package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	ldap "gopkg.in/ldap.v2"
)

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

// NewLDAPObject returns a new, partially or uninitialised LDAPObject.
func NewLDAPObject(dn string) *LDAPObject {
	return &LDAPObject{
		DN:         dn,
		Classes:    []string{},
		Attributes: map[string][]string{},
	}
}

// String returns a string representation of the given LDAPObject.
func (o *LDAPObject) String() string {
	result, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return fmt.Sprintf("{ \"dn\" = \"%s\" }", o.DN)
	}
	return string(result)
}

// PopulateFromResourceData populates the current LDAPObject using the information available
// in the schema.ResourceData input, as parsed from the HCL manifest.
func (o *LDAPObject) PopulateFromResourceData(d *schema.ResourceData) error {

	log.Printf("[DEBUG] PopulateFromResourceData - populating object %q", d.Get("dn").(string))

	// reset object state
	o.DN = d.Get("dn").(string)
	o.Classes = []string{}
	o.Attributes = map[string][]string{}

	// retrieve classes from HCL
	for _, oc := range (d.Get("object_classes").(*schema.Set)).List() {
		log.Printf("[DEBUG] PopulateFromResourceData - object %q has class: %q", o.DN, oc.(string))
		o.Classes = append(o.Classes, oc.(string))
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
			log.Printf("[DEBUG] PopulateFromResourceData - object %q has %d attributes", o.DN, len(attributes))
			for _, attribute := range attributes {
				log.Printf("[DEBUG] PopulateFromResourceData - %q has attribute of type %T", o.DN, attribute)
				// each map should only have one entry (see resource declaration)
				for name, value := range attribute.(map[string]interface{}) {
					log.Printf("[DEBUG] PopulateFromResourceData - %q has attribute[%v] => %v (%T)", o.DN, name, value, value)
					o.Attributes[name] = append(o.Attributes[name], value.(string))
				}
			}
		}
	}
	log.Printf("[DEBUG] PopulateFromResourceData - object:\n%s", o)
	return nil
}

// PopulateFromLDAPQuery runs an LDAP query against the given provider, then populates
// the current object with the datareturnd from the server. NOTE: the object must
// have the DN attribute set.
func (o *LDAPObject) PopulateFromLDAPQuery(provider *LDAPProvider) error {

	if o.DN == "" {
		log.Printf("[ERROR] PopulateFromLDAPQuery - object must have a valid DN")
		return fmt.Errorf("object must have a valid DN")
	}

	conn, err := provider.Bind()
	if err != nil {
		log.Printf("[ERROR] PopulateFromLDAPQuery - error getting connection to provider: %v", err)
		return err
	}

	log.Printf("[DEBUG] PopulateFromLDAPQuery - looking for object %q", o.DN)

	// when searching by DN, you don't need to specify the base DN, a search
	// filter and a "subtree" scope: just put the DN (i.e. the primary key) as
	// the base DN with a "base object" scope, and the returned object will be
	// the entry, if it exists
	request := ldap.NewSearchRequest(
		o.DN,
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
			if err.ResultCode == 32 { // no such object
				log.Printf("[WARN] PopulateFromLDAPQuery - object %q not found", o.DN)
				return fmt.Errorf(fmt.Sprintf("object %q not found", o.DN))
			}
		}
		log.Printf("[ERROR] PopulateFromLDAPQuery - lookup for %q returned an error %v", o.DN, err)
		return err
	}

	if len(sr.Entries) != 1 {
		msg := fmt.Sprintf("%d entries in search result, expected 1", len(sr.Entries))
		log.Printf("[ERROR] PopulateFromLDAPQuery - error: %s", msg)
		return errors.New(msg)
	}
	if len(sr.Entries[0].GetAttributeValues("dn")) <= 0 {
		log.Printf("[ERROR] PopulateFromLDAPQuery - error: no 'DN' attribute in search result entry")
		return errors.New("no 'DN' attribute in search result entry")
	}
	log.Printf("[DEBUG] PopulateFromLDAPQuery - populating object %q", sr.Entries[0].GetAttributeValues("dn")[0])

	o.DN = sr.Entries[0].GetAttributeValues("dn")[0]
	o.Classes = sr.Entries[0].GetAttributeValues("objectClass")
	o.Attributes = map[string][]string{}

	for _, attribute := range sr.Entries[0].Attributes {
		log.Printf("[DEBUG] PopulateFromLDAPQuery - treating attribute %q (%d values: %v)", attribute.Name, len(attribute.Values), attribute.Values)
		if strings.EqualFold(attribute.Name, "dn") || strings.EqualFold(attribute.Name, "objectClass") {
			// skip: we don't treat dn and object classes as ordinary attributes
			// since they're coped with separately
			log.Printf("[DEBUG] PopulateFromLDAPQuery - skipping attribute %q", attribute.Name)
			continue
		}

		log.Printf("[DEBUG] PopulateFromLDAPQuery - adding attribute %q => %v (%d values)", attribute.Name, attribute.Values, len(attribute.Values))
		o.Attributes[attribute.Name] = attribute.Values
	}
	log.Printf("[DEBUG] PopulateFromLDAPQuery - object:\n%s", o)
	return nil
}

func (o *LDAPObject) ToResourceData(d *schema.ResourceData) error {
	return nil
}

// ToLDAPAddRequest populates an LDAP add request with information taken from the
// current object.
func (o *LDAPObject) ToLDAPAddRequest() (*ldap.AddRequest, error) {
	// then use the data transfer object to prepare the LDAP insert statement
	request := ldap.NewAddRequest(o.DN)
	request.Attribute("objectClass", o.Classes)
	for name, values := range o.Attributes {
		request.Attribute(name, values)
	}
	return request, nil
}
