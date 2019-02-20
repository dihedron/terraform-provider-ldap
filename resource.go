// Copyright 2018-present Andrea Funtò. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/hashicorp/terraform/helper/hashcode"
	"github.com/hashicorp/terraform/helper/schema"
	ldap "gopkg.in/ldap.v2"
)

// DescribeLDAPObject returns a description of the LDAPObject resource in Terraform
// internal schema.Resource struct.
func DescribeLDAPObject() *schema.Resource {
	return &schema.Resource{
		Create: CreateLDAPObject,
		Read:   ReadLDAPObject,
		Update: UpdateLDAPObject,
		Delete: DeleteLDAPObject,
		Exists: ExistsLDAPObject,

		Importer: &schema.ResourceImporter{
			State: ImportLDAPObject,
		},

		Schema: map[string]*schema.Schema{
			"dn": &schema.Schema{
				Type:        schema.TypeString,
				Description: "The Distinguished Name (DN) of the object, as the concatenation of its RDN (unique among siblings) and its parent's DN.",
				Required:    true,
				ForceNew:    true,
			},
			"object_classes": &schema.Schema{
				Type:        schema.TypeSet,
				Description: "The set of classes this object conforms to (e.g. organizationalUnit, inetOrgPerson).",
				Elem:        &schema.Schema{Type: schema.TypeString},
				Set:         schema.HashString,
				Required:    true,
			},
			"attributes": &schema.Schema{
				Type:        schema.TypeSet,
				Description: "The map of attributes of this object; each attribute can be multi-valued.",
				Set:         attributeHash,
				MinItems:    0,

				Elem: &schema.Schema{
					Type:        schema.TypeMap,
					Description: "The list of values for a given attribute.",
					MinItems:    1,
					MaxItems:    1,
					Elem: &schema.Schema{
						Type:        schema.TypeString,
						Description: "The individual value for the given attribute.",
					},
				},
				Optional: true,
			},
		},
	}
}

// CreateLDAPObject creates a new LDAP object on the bound LDAP server.
func CreateLDAPObject(d *schema.ResourceData, meta interface{}) error {
	provider := meta.(*LDAPProvider)
	conn, err := provider.Bind()
	if err != nil {
		log.Printf("[ERROR] - error getting connection to provider: %v", err)
		return err
	}
	log.Printf("[DEBUG] CreateLDAPObject - creating a new object as %q", d.Get("dn").(string))

	// parse an object from the resource data (HCL)
	object, _ := NewFromResourceData(d)

	// then use the data transfer object to prepare the LDAP insert statement
	request := ldap.NewAddRequest(object.DN)
	request.Attribute("objectClass", object.Classes)
	for name, values := range object.Attributes {
		request.Attribute(name, values)
	}

	// send the request
	err = conn.Add(request)
	if err != nil {
		log.Printf("[ERROR] CreateLDAPObject - error adding object %q to LDAP server: %v", object.DN, err)
		return err
	}

	log.Printf("[DEBUG] CreateLDAPObject - object %q added to LDAP server", object.DN)

	// all creation methods end up with a read request to read the object back
	// from the server and make sure it was properly created; this has the side
	// effect of reading back attributes that were not in the original request,
	// such as those computed on the server or those that have a default value;
	// in order to do so, the object's DN (the primary key) must be stored in
	// the satste so that the subsequent ReadLDAPObject know what to look for
	d.SetId(object.DN)
	return ReadLDAPObject(d, meta)
}

// ReadLDAPObject retrieves an object from the LDAP server, given its DN, and
// stores it in the local state.
func ReadLDAPObject(d *schema.ResourceData, meta interface{}) error {
	return readLDAPObject(d, meta, true)
}

// UpdateLDAPObject updates the remote version of an LDAP object according to
// the updated information available in the local .tf file.
func UpdateLDAPObject(d *schema.ResourceData, meta interface{}) error {
	provider := meta.(*LDAPProvider)
	conn, err := provider.Bind()
	if err != nil {
		log.Printf("[ERROR] - error getting connection to provider: %v", err)
		return err
	}
	log.Printf("[DEBUG] UpdateLDAPObject - performing update on object %q", d.Get("dn").(string))

	request := ldap.NewModifyRequest(d.Id())

	// handle objectClasses
	if d.HasChange("object_classes") {
		classes := []string{}
		for _, oc := range (d.Get("object_classes").(*schema.Set)).List() {
			classes = append(classes, oc.(string))
		}
		log.Printf("[DEBUG] ldap_object::update - updating classes of %q, new value: %v", d.Id(), classes)
		request.ReplaceAttributes = []ldap.PartialAttribute{
			ldap.PartialAttribute{
				Type: "objectClass",
				Vals: classes,
			},
		}
	}

	if d.HasChange("attributes") {

		o, n := d.GetChange("attributes")
		log.Printf("[DEBUG] ldap_object::update - \n%s", printAttributes("old attributes map", o))
		log.Printf("[DEBUG] ldap_object::update - \n%s", printAttributes("new attributes map", n))

		added, changed, removed := computeDeltas(o.(*schema.Set), n.(*schema.Set))
		if len(added) > 0 {
			log.Printf("[DEBUG] ldap_object::update - %d attributes added", len(added))
			request.AddAttributes = added
		}
		if len(changed) > 0 {
			log.Printf("[DEBUG] ldap_object::update - %d attributes changed", len(changed))
			if request.ReplaceAttributes == nil {
				request.ReplaceAttributes = changed
			} else {
				request.ReplaceAttributes = append(request.ReplaceAttributes, changed...)
			}
		}
		if len(removed) > 0 {
			log.Printf("[DEBUG] ldap_object::update - %d attributes removed", len(removed))
			request.DeleteAttributes = removed
		}
	}

	err = conn.Modify(request)
	if err != nil {
		log.Printf("[ERROR] ldap_object::update - error modifying LDAP object %q with values %v", d.Id(), err)
		return err
	}
	return ReadLDAPObject(d, meta)
}

func DeleteLDAPObject(d *schema.ResourceData, meta interface{}) error {
	provider := meta.(*LDAPProvider)
	conn, err := provider.Bind()
	if err != nil {
		log.Printf("[ERROR] DeleteLDAPObject - error getting connection to provider: %v", err)
		return err
	}

	dn := d.Get("dn").(string)
	log.Printf("[DEBUG] DeleteLDAPObject - removing object %q", dn)

	request := ldap.NewDelRequest(dn, nil)

	err = conn.Del(request)
	if err != nil {
		log.Printf("[ERROR] ldap_object::delete - error removing %q: %v", dn, err)
		return err
	}
	log.Printf("[DEBUG] ldap_object::delete - %q removed", dn)
	return nil
}

// ExistsLDAPObject checks if an object exists on the bound LDAP server.
func ExistsLDAPObject(d *schema.ResourceData, meta interface{}) (b bool, e error) {
	provider := meta.(*LDAPProvider)
	conn, err := provider.Bind()
	if err != nil {
		log.Printf("[ERROR] ExistsLDAPObject - error getting connection to provider: %v", err)
		return false, err
	}

	dn := d.Get("dn").(string)

	log.Printf("[DEBUG] ExistsLDAPObject - checking if object %q exists", dn)

	// search by primary key (that is, set the DN as base DN and use a "base
	// object" scope); no attributes are retrieved since we are only checking
	// for existence; all objects have an "objectClass" attribute, so the filter
	// is a "match all"
	request := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		nil,
		nil,
	)

	// var _ *ldap.SearchResult
	_, err = conn.Search(request)
	if err != nil {
		if err, ok := err.(*ldap.Error); ok {
			if err.ResultCode == 32 { // no such object
				log.Printf("[INFO] ExistsLDAPObject - lookup for %q returned no value: deleted on server?", dn)
				return false, nil
			}
		}
		log.Printf("[DEBUG] ExistsLDAPObject - lookup for %q returned an error: %v", dn, err)
		return false, err
	}

	log.Printf("[INFO] LDAPObjectExists - object %q exists", dn)
	return true, nil
}

// ImportLDAPObject imports an LDAP object, given its DN; it can also produce
// a .tf file fragment.
func ImportLDAPObject(d *schema.ResourceData, meta interface{}) (imported []*schema.ResourceData, err error) {
	d.Set("dn", d.Id())
	err = readLDAPObject(d, meta, false)
	if path := os.Getenv("TF_LDAP_IMPORTER_PATH"); path != "" {
		log.Printf("[DEBUG] ldap_object::import - dumping imported object to %q", path)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			// the export file does not exist
			if file, err := os.Create(path); err == nil {
				defer file.Close()
				id := d.Id()
				tokens := strings.Split(id, ",")
				if len(tokens) > 0 {
					tokens = strings.Split(tokens[0], "=")
					if len(tokens) >= 1 {
						id = tokens[1]
						//resource "ldap_object" "a123456" {
						file.WriteString(fmt.Sprintf("resource \"ldap_object\" %q {\n", id))
						//	dn = "uid=a123456,dc=example,dc=com"
						file.WriteString(fmt.Sprintf("  dn = %q\n", d.Id()))
						//  object_classes = ["inetOrgPerson", "posixAccount"]
						classes := []string{}
						for _, class := range d.Get("object_classes").(*schema.Set).List() {
							//classes[i] = fmt.Sprintf("\"%s\"", class)
							classes = append(classes, fmt.Sprintf("%q", class))
						}
						file.WriteString(fmt.Sprintf("  object_classes = [ %s ]\n", strings.Join(classes, ", ")))
						if attributes, ok := d.GetOk("attributes"); ok {
							attributes := attributes.(*schema.Set).List()
							if len(attributes) > 0 {
								//  attributes = [
								file.WriteString("  attributes = [\n")
								for _, attribute := range attributes {
									for name, value := range attribute.(map[string]interface{}) {
										//    { sn = "Doe" },
										file.WriteString(fmt.Sprintf("    { %s = %q },\n", name, value.(string)))
									}
								}
								// ]
								file.WriteString("  ]\n")
							}
						}
						file.WriteString("}\n")
					}
				}
			}
		}
	}
	imported = append(imported, d)
	return
}

func readLDAPObject(d *schema.ResourceData, meta interface{}, updateState bool) error {
	provider := meta.(*LDAPProvider)
	conn, err := provider.Bind()
	if err != nil {
		log.Printf("[ERROR] DeleteLDAPObject - error getting connection to provider: %v", err)
		return err
	}
	dn := d.Get("dn").(string)

	log.Printf("[DEBUG] ldap_object::read - looking for object %q", dn)

	// when searching by DN, you don't need to specify the base DN, a search
	// filter and a "subtree" scope: just put the DN (i.e. the primary key) as
	// the base DN with a "base object" scope, and the returned object will be
	// the entry, if it exists
	request := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectclass=*)",
		[]string{"*"},
		nil,
	)

	sr, err := conn.Search(request)
	if err != nil {
		if err, ok := err.(*ldap.Error); ok {
			if err.ResultCode == 32 && updateState { // no such object
				log.Printf("[WARN] ldap_object::read - object not found, removing %q from state because it no longer exists in LDAP", dn)
				d.SetId("")
				return nil
			}
		}
		log.Printf("[DEBUG] ldap_object::read - lookup for %q returned an error %v", dn, err)
		return err
	}

	log.Printf("[DEBUG] ldap_object::read - query for %q returned %v", dn, sr)

	d.SetId(dn)
	d.Set("object_classes", sr.Entries[0].GetAttributeValues("objectClass"))

	// now deal with attributes
	set := &schema.Set{
		F: attributeHash,
	}

	for _, attribute := range sr.Entries[0].Attributes {
		log.Printf("[DEBUG] ldap_object::read - treating attribute %q of %q (%d values: %v)", attribute.Name, dn, len(attribute.Values), attribute.Values)
		if attribute.Name == "objectClass" {
			// skip: we don't treat object classes as ordinary attributes
			log.Printf("[DEBUG] ldap_object::read - skipping attribute %q of %q", attribute.Name, dn)
			continue
		}
		// FIXME: testing if this fixes issue #1.
		if len(attribute.Values) == 1 {
			// we don't treat the RDN as an ordinary attribute
			a := fmt.Sprintf("%s=%s", attribute.Name, attribute.Values[0])
			if strings.HasPrefix(dn, a) {
				log.Printf("[DEBUG] ldap_object::read - skipping RDN %q of %q", a, dn)
				continue
			}
		}

		log.Printf("[DEBUG] ldap_object::read - adding attribute %q to %q (%d values)", attribute.Name, dn, len(attribute.Values))
		// now add each value as an individual entry into the object, because
		// we do not handle name => []values, and we have a set of maps each
		// holding a single entry name => value; multiple maps may share the
		// same key.
		for _, value := range attribute.Values {
			log.Printf("[DEBUG] ldap_object::read - for %q, setting %q => %q", dn, attribute.Name, value)
			set.Add(map[string]interface{}{
				attribute.Name: value,
			})
		}
	}

	if err := d.Set("attributes", set); err != nil {
		log.Printf("[WARN] ldap_object::read - error setting LDAP attributes for %q : %v", dn, err)
		return err
	}
	return nil
}

// LDAPObject is the internal representation of an LDAP object; it can be
// instantiated from an HCL definition or from a LDAP QUery, and provides
// methods to check for differences.
type LDAPObject struct {
	// DN is the unique identifies of an LDAP object (its Distingushed Name).
	DN string `json:"dn,omitempty" yaml:"dn,omitempy"`

	// Classes is an array of object classes.
	Classes []string `json:"classes,omitempty" yaml:"classes,omitempty"`

	// Attributes is the set of extra attributes; some of these might have been
	// calculated on the server.
	Attributes map[string][]string
}

// String returns a string representation of the given LDAPObject.
func (o *LDAPObject) String() string {
	result, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return fmt.Sprintf("{ \"dn\" = \"%s\" }", o.DN)
	}
	return string(result)
}

// NewFromResourceData retuns a new LDAPObject using the information available
// in the schema.ResourceData input, as parsed from the HCL manifest.
func NewFromResourceData(d *schema.ResourceData) (*LDAPObject, error) {

	log.Printf("[DEBUG] NewFromResourceData - populating object %q", d.Get("dn").(string))

	object := &LDAPObject{
		DN:         d.Get("dn").(string),
		Classes:    []string{},
		Attributes: map[string][]string{},
	}

	// retrieve classes from HCL
	for _, oc := range (d.Get("object_classes").(*schema.Set)).List() {
		log.Printf("[DEBUG] NewFromResourceData - object %q has class: %q", object.DN, oc.(string))
		object.Classes = append(object.Classes, oc.(string))
	}

	// if there is a non empty list of attributes, loop though it and create a
	// new map collecting attribute names and corresponding value(s); we need to
	// do this because we could not model the attributes as a map[string][]string
	// due to an apparent limitation in HCL; we have a []map[string]string, so
	// we loop through the list and accumulate values when they share the same
	// key, then we use these as attributes in the LDAP client.
	// FIXME: LDAP attribute names are case insensitive: check what happens when
	// the same attribute is given two values under names that only differ by case.
	if v, ok := d.GetOk("attributes"); ok {
		attributes := v.(*schema.Set).List()
		if len(attributes) > 0 {
			log.Printf("[DEBUG] NewFromResourceData - object %q has %d attributes", object.DN, len(attributes))
			for _, attribute := range attributes {
				log.Printf("[DEBUG] NewFromResourceData - %q has attribute of type %T", object.DN, attribute)
				// each map should only have one entry (see resource declaration)
				for name, value := range attribute.(map[string]interface{}) {
					log.Printf("[DEBUG] NewFromResourceData - %q has attribute[%v] => %v (%T)", object.DN, name, value, value)
					object.Attributes[name] = append(object.Attributes[name], value.(string))
				}
			}
		}
	}
	log.Printf("[DEBUG] NewFromResourceData - object:\n%s", object)
	return object, nil
}

// NewFromQuery returns an LDAPObject populated with information extracted
// from the given LDAP query result; if the query result contains more than one
// entry, or the entry does not have a DN attribute, an error is returned.
func NewFromQuery(result *ldap.SearchResult) (*LDAPObject, error) {

	if len(result.Entries) != 1 {
		msg := fmt.Sprintf("%d entries in search result, expected 1", len(result.Entries))
		log.Printf("[ERROR] NewFromQuery - error: %s", msg)
		return nil, errors.New(msg)
	}
	if len(result.Entries[0].GetAttributeValues("dn")) <= 0 {
		log.Printf("[ERROR] NewFromQuery - error: no 'DN' attribute in search result entry")
		return nil, errors.New("no 'DN' attribute in search result entry")
	}
	log.Printf("[DEBUG] NewFromQuery - populating object %q", result.Entries[0].GetAttributeValues("dn")[0])

	object := &LDAPObject{
		DN:         result.Entries[0].GetAttributeValues("dn")[0],
		Classes:    result.Entries[0].GetAttributeValues("objectClass"),
		Attributes: map[string][]string{},
	}

	for _, attribute := range result.Entries[0].Attributes {
		log.Printf("[DEBUG] NewFromQuery - treating attribute %q (%d values: %v)", attribute.Name, len(attribute.Values), attribute.Values)
		if strings.EqualFold(attribute.Name, "dn") || strings.EqualFold(attribute.Name, "objectClass") {
			// skip: we don't treat dn and object classes as ordinary attributes
			// since they're coped with separately
			log.Printf("[DEBUG] NewFromQuery - skipping attribute %q", attribute.Name)
			continue
		}

		log.Printf("[DEBUG] NewFromQuery - adding attribute %q => %v (%d values)", attribute.Name, attribute.Values, len(attribute.Values))
		object.Attributes[attribute.Name] = attribute.Values
	}
	log.Printf("[DEBUG] NewFromQuery - object:\n%s", object)
	return object, nil
}

// computes the hash of the map representing an attribute in the attributes set
func attributeHash(v interface{}) int {
	m := v.(map[string]interface{})
	var buffer bytes.Buffer
	buffer.WriteString("map {")
	for k, v := range m {
		buffer.WriteString(fmt.Sprintf("%q := %q;", k, v.(string)))
	}
	buffer.WriteRune('}')
	text := buffer.String()
	hash := hashcode.String(text)
	return hash
}

func printAttributes(prefix string, attributes interface{}) string {
	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("%s: {\n", prefix))
	if attributes, ok := attributes.(*schema.Set); ok {
		for _, attribute := range attributes.List() {
			for k, v := range attribute.(map[string]interface{}) {
				buffer.WriteString(fmt.Sprintf("    %q: %q\n", k, v.(string)))
			}
		}
		buffer.WriteRune('}')
	}
	return buffer.String()
}

func computeDeltas(os, ns *schema.Set) (added, changed, removed []ldap.PartialAttribute) {

	rk := NewSet() // names of removed attributes
	for _, v := range os.Difference(ns).List() {
		for k := range v.(map[string]interface{}) {
			rk.Add(k)
		}
	}

	ak := NewSet() // names of added attributes
	for _, v := range ns.Difference(os).List() {
		for k := range v.(map[string]interface{}) {
			ak.Add(k)
		}
	}

	kk := NewSet() // names of kept attributes
	for _, v := range ns.Intersection(os).List() {
		for k := range v.(map[string]interface{}) {
			kk.Add(k)
		}
	}

	ck := NewSet() // names of changed attributes

	// loop over remove attributes' names
	for _, k := range rk.List() {
		if !ak.Contains(k) && !kk.Contains(k) {
			// one value under this name has been removed, no other value has
			// been added back, and there is no further value under the same
			// name among those that were untouched; this means that it has
			// been dropped and must go among the RemovedAttributes
			log.Printf("[DEBUG} ldap_object::deltas - dropping attribute %q", k)
			removed = append(removed, ldap.PartialAttribute{
				Type: k,
				Vals: []string{},
			})
		} else {
			ck.Add(k)
		}
	}

	for _, k := range ak.List() {
		if !rk.Contains(k) && !kk.Contains(k) {
			// this is the first value under this name: no value is being
			// removed and no value is being kept; so we're adding this new
			// attribute to the LDAP object (AddedAttributes), getting all
			// the values under this name from the new set
			values := []string{}
			for _, m := range ns.List() {
				for mk, mv := range m.(map[string]interface{}) {
					if k == mk {
						values = append(values, mv.(string))
					}
				}
			}
			added = append(added, ldap.PartialAttribute{
				Type: k,
				Vals: values,
			})
			log.Printf("[DEBUG} ldap_object::deltas - adding new attribute %q with values %v", k, values)
		} else {
			ck.Add(k)
		}
	}

	// now loop over changed attributes and
	for _, k := range ck.List() {
		// the attributes in this set have been changed, in that a new value has
		// been added or removed and it was not the last/first one; so we're
		// adding this new attribute to the LDAP object (ModifiedAttributes),
		// getting all the values under this name from the new set
		values := []string{}
		for _, m := range ns.List() {
			for mk, mv := range m.(map[string]interface{}) {
				if k == mk {
					values = append(values, mv.(string))
				}
			}
		}
		changed = append(added, ldap.PartialAttribute{
			Type: k,
			Vals: values,
		})
		log.Printf("[DEBUG} ldap_object::deltas - changing attribute %q with values %v", k, values)
	}
	return
}
