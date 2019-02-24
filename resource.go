// Copyright 2018-present Andrea Funtò. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	ldap "gopkg.in/ldap.v2"
)

// DescribeLDAPObject returns a description of the LDAPObject resource in Terraform
// internal schema.Resource struct.
func DescribeLDAPObject() *schema.Resource {
	return &schema.Resource{
		Create: CreateResource,
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

// CreateResource creates a new LDAP object resource on the bound LDAP server.
func CreateResource(d *schema.ResourceData, meta interface{}) error {
	provider := meta.(*LDAPProvider)
	conn, err := provider.Bind()
	if err != nil {
		log.Printf("[ERROR] CreateResource - error getting connection to provider: %v", err)
		return err
	}
	log.Printf("[DEBUG] CreateResource - creating a new object as %q", d.Get("dn").(string))

	// read the object from HCL
	object := NewLDAPObject("")
	err = object.PopulateFromResourceData(d)
	if err != nil {
		log.Printf("[ERROR] CreateResource - error reading resource data from HCL: %v", err)
		return err
	}

	// then use the data transfer object to prepare the LDAP insert statement
	request, _ := object.ToLDAPAddRequest()

	// send the request
	err = conn.Add(request)
	if err != nil {
		log.Printf("[ERROR] CreateResource - error adding object %q to LDAP server: %v", object.DN, err)
		return err
	}

	log.Printf("[DEBUG] CreateResource - object %q added to LDAP server", object.DN)

	// all creation methods end up with a read request to read the object back
	// from the server and make sure it was properly created; this has the side
	// effect of reading back attributes that were not in the original request,
	// such as those computed on the server or those that have a default value;
	// in order to do so, the object's DN (the primary key) must be stored in
	// the state so that the subsequent ReadLDAPObject knows what to look for
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
		log.Printf("[DEBUG] UpdateLDAPObject - updating classes of %q, new value: %v", d.Id(), classes)
		request.ReplaceAttributes = []ldap.PartialAttribute{
			ldap.PartialAttribute{
				Type: "objectClass",
				Vals: classes,
			},
		}
	}

	if d.HasChange("attributes") {
		o, n := d.GetChange("attributes")
		log.Printf("[DEBUG] UpdateLDAPObject - \n%s", printAttributes("old attributes map", o))
		log.Printf("[DEBUG] UpdateLDAPObject - \n%s", printAttributes("new attributes map", n))

		added, changed, removed := computeDeltas(o.(*schema.Set), n.(*schema.Set))
		if len(added) > 0 {
			log.Printf("[DEBUG] UpdateLDAPObject - %d attributes added", len(added))
			request.AddAttributes = added
		}
		if len(changed) > 0 {
			log.Printf("[DEBUG] UpdateLDAPObject - %d attributes changed", len(changed))
			if request.ReplaceAttributes == nil {
				request.ReplaceAttributes = changed
			} else {
				request.ReplaceAttributes = append(request.ReplaceAttributes, changed...)
			}
		}
		if len(removed) > 0 {
			log.Printf("[DEBUG] UpdateLDAPObject - %d attributes removed", len(removed))
			request.DeleteAttributes = removed
		}
	}

	err = conn.Modify(request)
	if err != nil {
		log.Printf("[ERROR] UpdateLDAPObject - error modifying LDAP object %q with values %v", d.Id(), err)
		return err
	}
	return ReadLDAPObject(d, meta)
}

// DeleteLDAPObject deletes an object in the bound LDAP server given its DN.
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
func ImportLDAPObject(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	d.Set("dn", d.Id())
	err := readLDAPObject(d, meta, false)
	if err != nil {
		log.Printf("[ERROR] ImportLDAPObject - error reading object %q", d.Id())
		return nil, err
	}
	path := os.Getenv("TF_LDAP_IMPORTER_PATH")
	if path == "" {
		log.Printf("[ERROR] ImportLDAPObject - no path specified")
		return nil, err
	}
	if _, err := os.Stat(path); err == nil {
		log.Printf("[ERROR] ImportLDAPObject - %q exists already on disk", path)
		return nil, fmt.Errorf("object %q exists already on disk", path)
	}
	log.Printf("[DEBUG] ImportLDAPObject - dumping imported object to %q", path)

	file, err := os.Create(path)
	if err != nil {
		log.Printf("[ERROR] ImportLDAPObject - error creating file %q: %v", path, err)
		return nil, err
	}
	defer file.Close()
	log.Printf("[DEBUG] ImportLDAPObject - file %q open", path)

	var buffer bytes.Buffer
	id := d.Id()
	tokens := strings.Split(id, ",")
	if len(tokens) > 0 {
		tokens = strings.Split(tokens[0], "=")
		if len(tokens) >= 1 {
			id = tokens[1]
			//resource "ldap_object" "a123456" {
			buffer.WriteString(fmt.Sprintf("resource \"ldap_object\" %q {\n", id))
			//	dn = "uid=a123456,dc=example,dc=com"
			buffer.WriteString(fmt.Sprintf("  dn = %q\n", d.Id()))
			//  object_classes = ["inetOrgPerson", "posixAccount"]
			classes := []string{}
			for _, class := range d.Get("object_classes").(*schema.Set).List() {
				//classes[i] = fmt.Sprintf("\"%s\"", class)
				classes = append(classes, fmt.Sprintf("%q", class))
			}
			buffer.WriteString(fmt.Sprintf("  object_classes = [ %s ]\n", strings.Join(classes, ", ")))
			if attributes, ok := d.GetOk("attributes"); ok {
				attributes := attributes.(*schema.Set).List()
				if len(attributes) > 0 {
					//  attributes = [
					buffer.WriteString("  attributes = [\n")
					for _, attribute := range attributes {
						for name, value := range attribute.(map[string]interface{}) {
							//    { sn = "Doe" },
							buffer.WriteString(fmt.Sprintf("    { %s = %q },\n", name, value.(string)))
						}
					}
					// ]
					buffer.WriteString("  ]\n")
				}
			}
			buffer.WriteString("}\n")
		}
	}

	_, err = buffer.WriteTo(file)
	if err != nil {
		log.Printf("[DEBUG] ImportLDAPObject - error writing to file: %v", err)
	}
	return []*schema.ResourceData{d}, err
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

/*
func searchLDAPObject(dn string, meta interface{}, updateState bool) (*LDAPObject, error) {
	provider := meta.(*LDAPProvider)
	conn, err := provider.Bind()
	if err != nil {
		log.Printf("[ERROR] searchLDAPObject - error getting connection to provider: %v", err)
		return nil, err
	}

	log.Printf("[DEBUG] searchLDAPObject - looking for object %q", dn)

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
				log.Printf("[WARN] searchLDAPObject - object not found, removing %q from state because it no longer exists in LDAP", dn)
				return nil, nil
			}
		}
		log.Printf("[DEBUG] searchLDAPObject - lookup for %q returned an error %v", dn, err)
		return nil, err
	}

	log.Printf("[DEBUG] searchLDAPObject - query for %q returned %v", dn, sr)

	return NewFromLDAPResult(sr)

	// d.SetId(dn)
	// d.Set("object_classes", sr.Entries[0].GetAttributeValues("objectClass"))

	// // now deal with attributes
	// set := &schema.Set{
	// 	F: attributeHash,
	// }

	// for _, attribute := range sr.Entries[0].Attributes {
	// 	log.Printf("[DEBUG] ldap_object::read - treating attribute %q of %q (%d values: %v)", attribute.Name, dn, len(attribute.Values), attribute.Values)
	// 	if attribute.Name == "objectClass" {
	// 		// skip: we don't treat object classes as ordinary attributes
	// 		log.Printf("[DEBUG] ldap_object::read - skipping attribute %q of %q", attribute.Name, dn)
	// 		continue
	// 	}
	// 	// FIXME: testing if this fixes issue #1.
	// 	if len(attribute.Values) == 1 {
	// 		// we don't treat the RDN as an ordinary attribute
	// 		a := fmt.Sprintf("%s=%s", attribute.Name, attribute.Values[0])
	// 		if strings.HasPrefix(dn, a) {
	// 			log.Printf("[DEBUG] ldap_object::read - skipping RDN %q of %q", a, dn)
	// 			continue
	// 		}
	// 	}

	// 	log.Printf("[DEBUG] ldap_object::read - adding attribute %q to %q (%d values)", attribute.Name, dn, len(attribute.Values))
	// 	// now add each value as an individual entry into the object, because
	// 	// we do not handle name => []values, and we have a set of maps each
	// 	// holding a single entry name => value; multiple maps may share the
	// 	// same key.
	// 	for _, value := range attribute.Values {
	// 		log.Printf("[DEBUG] ldap_object::read - for %q, setting %q => %q", dn, attribute.Name, value)
	// 		set.Add(map[string]interface{}{
	// 			attribute.Name: value,
	// 		})
	// 	}
	// }

	// if err := d.Set("attributes", set); err != nil {
	// 	log.Printf("[WARN] ldap_object::read - error setting LDAP attributes for %q : %v", dn, err)
	// 	return err
	// }
	// return nil
}
*/
