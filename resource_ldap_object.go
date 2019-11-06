package main

import (
	"bytes"
	"encoding/hex"
	"log"

	"crypto/md5"
	"fmt"
	"sort"
	"strings"

	"os"

	"github.com/hashicorp/terraform/helper/customdiff"
	"github.com/hashicorp/terraform/helper/hashcode"
	"github.com/hashicorp/terraform/helper/schema"
	ldap "gopkg.in/ldap.v2"
)

var (
	separatorList = "||"
	separatorMap  = "@@"
)

func resourceLDAPObject() *schema.Resource {
	return &schema.Resource{
		Create: resourceLDAPObjectCreate,
		Read:   resourceLDAPObjectRead,
		Update: resourceLDAPObjectUpdate,
		Delete: resourceLDAPObjectDelete,
		Exists: resourceLDAPObjectExists,

		Importer: &schema.ResourceImporter{
			State: resourceLDAPObjectImport,
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
				Computed:    true,
				Elem: &schema.Schema{
					Type:        schema.TypeMap,
					Description: "The list of values for a given attribute.",
					MinItems:    1,
					MaxItems:    1,
					Elem: &schema.Schema{
						Computed:    true,
						Type:        schema.TypeString,
						Description: "The individual value for the given attribute.",
					},
				},
				Optional: true,
			},
			"attributes_hash": &schema.Schema{
				Type:        schema.TypeString,
				Description: "This field represent an hash of the attribute list Map",
				Computed:    true,
			},
		},
		CustomizeDiff: customdiff.All(
			resourceLdapObjectCustomizeDiffFunc,
		),
	}
}

func resourceLDAPObjectImport(d *schema.ResourceData, meta interface{}) (imported []*schema.ResourceData, err error) {
	d.Set("dn", d.Id())
	err = readLDAPObjectImpl(d, meta, false)

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

func resourceLDAPObjectExists(d *schema.ResourceData, meta interface{}) (b bool, e error) {
	config := meta.(*Config)
	conn, err := config.initiateAndBind()
	if err != nil {
		return false, err
	}
	dn := d.Get("dn").(string)

	log.Printf("[DEBUG] ldap_object::exists - checking if %q exists", dn)

	// search by primary key (that is, set the DN as base DN and use a "base
	// object" scope); no attributes are retrieved since we are onòy checking
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

	var _ *ldap.SearchResult
	_, err = conn.Search(request)
	if err != nil {
		if err, ok := err.(*ldap.Error); ok {
			if err.ResultCode == 32 { // no such object
				log.Printf("[WARN] ldap_object::exists - lookup for %q returned no value: deleted on server?", dn)
				return false, nil
			}
		}
		log.Printf("[DEBUG] ldap_object::exists - lookup for %q returned an error %v", dn, err)
		return false, err
	}

	log.Printf("[DEBUG] ldap_object::exists - object %q exists", dn)
	return true, nil
}

func resourceLDAPObjectCreate(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	client, err := config.initiateAndBind()
	if err != nil {
		return err
	}

	dn := d.Get("dn").(string)

	log.Printf("[DEBUG] ldap_object::create - creating a new object under %q", dn)

	request := ldap.NewAddRequest(dn)

	// retrieve classe from HCL
	objectClasses := []string{}
	for _, oc := range (d.Get("object_classes").(*schema.Set)).List() {
		log.Printf("[DEBUG] ldap_object::create - object %q has class: %q", dn, oc.(string))
		objectClasses = append(objectClasses, oc.(string))
	}
	request.Attribute("objectClass", objectClasses)

	// if there is a non empty list of attributes, loop though it and
	// create a new map collecting attribute names and its value(s); we need to
	// do this because we could not model the attributes as a map[string][]string
	// due to an appareent limitation in HCL; we have a []map[string]string, so
	// we loop through the list and accumulate values when they share the same
	// key, then we use these as attributes in the LDAP client.

	md5HashAttributes := ""
	if v, ok := d.GetOk("attributes"); ok {
		attributes := v.(*schema.Set).List()
		if len(attributes) > 0 {
			log.Printf("[DEBUG] ldap_object::create - object %q has %d attributes", dn, len(attributes))
			m := make(map[string][]string)
			for _, attribute := range attributes {
				log.Printf("[DEBUG] ldap_object::create - %q has attribute of type %T", dn, attribute)
				// each map should only have one entry (see resource declaration)
				for name, value := range attribute.(map[string]interface{}) {
					log.Printf("[DEBUG] ldap_object::create - %q has attribute[%v] => %v (%T)", dn, name, value, value)
					m[name] = append(m[name], value.(string))
				}
			}
			// now loop through the map and add attributes with theys value(s)
			for name, values := range m {
				request.Attribute(name, values)
			}

			md5HashAttributes = convertAttributesListToString(attributes)

		}
	}

	err = client.Add(request)
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] ldap_object::create - object %q added to LDAP server", dn)

	if md5HashAttributes != "" {
		d.Set("attributes_hash", md5HashAttributes)
	}

	d.SetId(dn)
	return resourceLDAPObjectRead(d, meta)
}

func resourceLDAPObjectRead(d *schema.ResourceData, meta interface{}) error {
	return readLDAPObjectImpl(d, meta, true)
}

func resourceLDAPObjectUpdate(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	client, err := config.initiateAndBind()
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] ldap_object::update - performing update on %q", d.Id())

	request := ldap.NewModifyRequest(d.Id())

	modifyHash := false // it is used to check if the hash for attributes has changed
	var md5HashAttributes string

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

		storedMd5HashAttributes := d.Get("attributes_hash").(string)
		storedMd5HashAttributesMap := convertAttributesStringToMap(storedMd5HashAttributes)

		o, n := d.GetChange("attributes")
		log.Printf("[DEBUG] ldap_object::update - \n%s", printAttributes("old attributes map", o))
		log.Printf("[DEBUG] ldap_object::update - \n%s", printAttributes("new attributes map", n))

		added, changed, removed := computeDeltas(o.(*schema.Set), n.(*schema.Set))
		if len(added) > 0 {
			log.Printf("[DEBUG] ldap_object::update - %d attributes added", len(added))
			request.AddAttributes = added

			for _, ldapAttr := range added {
				values := ldapAttr.Vals
				sort.Strings(values)
				md5HashValue := GetMD5Hash(strings.Join(values, separatorMap))
				storedMd5HashAttributesMap[ldapAttr.Type] = md5HashValue
			}

		}
		if len(changed) > 0 {
			log.Printf("[DEBUG] ldap_object::update - %d attributes changed", len(changed))
			if request.ReplaceAttributes == nil {
				request.ReplaceAttributes = changed
			} else {
				request.ReplaceAttributes = append(request.ReplaceAttributes, changed...)
			}

			for _, ldapAttr := range changed {
				values := ldapAttr.Vals
				sort.Strings(values)
				md5HashValue := GetMD5Hash(strings.Join(values, separatorMap))
				storedMd5HashAttributesMap[ldapAttr.Type] = md5HashValue
			}

		}
		if len(removed) > 0 {
			log.Printf("[DEBUG] ldap_object::update - %d attributes removed", len(removed))
			request.DeleteAttributes = removed

			for _, ldapAttr := range removed {
				delete(storedMd5HashAttributesMap, ldapAttr.Type)
			}
		}
		md5HashAttributes = convertAttributesMapToString(storedMd5HashAttributesMap)
		modifyHash = true
	}

	err = client.Modify(request)
	if err != nil {
		log.Printf("[ERROR] ldap_object::update - error modifying LDAP object %q with values %v", d.Id(), err)
		return err
	}

	if modifyHash {
		d.Set("attributes_hash", md5HashAttributes)
	}

	return resourceLDAPObjectRead(d, meta)
}

func resourceLDAPObjectDelete(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	client, err := config.initiateAndBind()
	if err != nil {
		return err
	}
	dn := d.Get("dn").(string)

	log.Printf("[DEBUG] ldap_object::delete - removing %q", dn)

	request := ldap.NewDelRequest(dn, nil)

	err = client.Del(request)
	if err != nil {
		log.Printf("[ERROR] ldap_object::delete - error removing %q: %v", dn, err)
		return err
	}
	log.Printf("[DEBUG] ldap_object::delete - %q removed", dn)
	return nil
}

func readLDAPObjectImpl(d *schema.ResourceData, meta interface{}, updateState bool) error {
	config := meta.(*Config)
	client, err := config.initiateAndBind()
	if err != nil {
		return err
	}
	dn := d.Get("dn").(string)

	log.Printf("[DEBUG] ldap_object::read - looking for object %q", dn)

	// when searching by DN, you don't need t specify the base DN a search
	// filter a "subtree" scope: just put the DN (i.e. the primary key) as the
	// base DN with a "base object" scope, and the returned object will be the
	// entry, if it exists
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

	sr, err := client.Search(request)
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
				//continue
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

// the diff is calculated considering the "attributes" key and all its sub-attributes.
// the hash is calculated on each sub-attribute in order to to address the following scenarios:
// 1. The creation of object will trigger the update of a new attribute on the provider and the next update would skip it
//    (this would be solved by considering the hash on the general "attributes" key).
// 2. A change of an sub-attribute in the main.tf would trigger only the specific update (this is addressed by considering an
//	  hash on the subkey otherwise the change would show also the sub-attribute computed by the provider).
// 		Ao   |   An   |   As   |   Action
//      --------------------------------------------------------------------
//      ao  ==   an  ==   as  -->  None
//      bo  !=   bn  ==   bs  -->  None
//      co  ==   cn  !=   cs  -->  Force(cs = cn)
//      co  !=   cn  !=   cs  -->  Force(cs = cn); if cn=0 then delete(cs)
//
// Where:
//      Ao --> Set of attributes on local (old values - previous ones)
//      An --> Set of attributes on local (new values - proposed ones)
//      As --> Set of attributes on Server provider
func resourceLdapObjectCustomizeDiffFunc(diff *schema.ResourceDiff, meta interface{}) error {
	o, n := diff.GetChange("attributes")
	oList := o.(*schema.Set).List()
	nList := n.(*schema.Set).List()

	log.Printf("[DEBUG] Change %+v --> %+v", oList, nList)

	// Calculate Map for As
	AsAttributes, _ := readAttributes(meta, diff.Get("dn").(string))
	log.Printf("[DEBUG] As Attributes: %+v", AsAttributes)
	AsMd5HashAttributes := convertAttributesListToString(AsAttributes)
	AsMd5HashAttributesMap := convertAttributesStringToMap(AsMd5HashAttributes)
	log.Printf("[DEBUG] As Hash: %+v", AsMd5HashAttributesMap)

	// Calculate Map for An
	AnMd5HashAttributes := convertAttributesListToString(nList)
	AnMd5HashAttributesMap := convertAttributesStringToMap(AnMd5HashAttributes)
	log.Printf("[DEBUG] An Hash: %+v", AnMd5HashAttributesMap)

	// Calculate Map for Ao
	AoMd5HashAttributes := diff.Get("attributes_hash").(string)
	AoMd5HashAttributesMap := convertAttributesStringToMap(AoMd5HashAttributes)
	log.Printf("[DEBUG] Ao Hash: %+v", AoMd5HashAttributesMap)

	for _, k := range diff.GetChangedKeysPrefix("attributes") {
		if strings.HasSuffix(k, ".#") {
			k = strings.TrimSuffix(k, ".#")
		}
		log.Printf("[DEBUG] Subkey %v processing ...", k)
		if k == "attributes" {
			continue
		}
		if strings.HasSuffix(k, "%") {
			continue
		}

		ow, nw := diff.GetChange(k)
		log.Printf("[DEBUG] Subkey Change %+v --> %+v", nw, ow)
		if ow == nw {
			continue
		}

		if strings.Contains(k, ".") {
			keyList := strings.Split(k, ".")
			simpleKey := keyList[len(keyList)-1]

			log.Printf("[DEBUG] Subkey diff %v, %v", AnMd5HashAttributesMap[simpleKey], AsMd5HashAttributesMap[simpleKey])

			// An and As are aligned
			if AnMd5HashAttributesMap[simpleKey] == AsMd5HashAttributesMap[simpleKey] {
				log.Printf("[DEBUG] Subkey %v: clearing (Same value on server)", k)
				return diff.Clear(k)
			}

			// An and Ao do not manage an attribute that is managed on server As
			AnExists := true
			AoExists := true
			if _, ok := AnMd5HashAttributesMap[simpleKey]; !ok {
				AnExists = false
			}
			if _, ok := AoMd5HashAttributesMap[simpleKey]; !ok {
				AoExists = false
			}
			if !AnExists && !AoExists {
				log.Printf("[DEBUG] Subkey %v: clearing (The diff is on server but not locally managed)", k)
				return diff.Clear(k)
			}

			log.Printf("[DEBUG] Subkey %v: keeping", k)
		}

	}

	return nil
}

/*
GetMD5Hash it return the hash related to the input string

 * @param text string. The string to hash

@return string it represents the md5 hash
*/
func GetMD5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

/*
convertAttributesListToString

 * @param d *schema.ResourceData
 * @param attributes the resource attribute name

@return string it represents the maps in the form: var1@@hash(values1)||var2@@hash(values2)||...||varN@@hash(valuesN)
*/
func convertAttributesListToString(attributes []interface{}) string {
	hashAttributes := []string{}
	m := make(map[string][]string)
	for _, attribute := range attributes {
		// each map should only have one entry (see resource declaration)
		for name, value := range attribute.(map[string]interface{}) {
			m[name] = append(m[name], value.(string))
		}
	}
	// now loop through the map and convert the related values to an hash
	for name, values := range m {
		sort.Strings(values)
		md5HashValue := GetMD5Hash(strings.Join(values, separatorMap))
		stringHash := name + separatorMap + md5HashValue
		hashAttributes = append(hashAttributes, stringHash)
	}
	sort.Strings(hashAttributes)
	return strings.Join(hashAttributes, separatorList)
}

/*
convertAttributesMapToHash

 * @param attributes map[string]string. {var1: hash(values1), var2: hash(values2), ..., varN: hash(valuesN)}

@return string it represents the maps in the form: var1@@hash(values1)||var2@@hash(values2)||...||varN@@hash(valuesN)
*/
func convertAttributesMapToString(attributes map[string]string) string {
	hashAttributes := []string{}
	// now loop through the map and convert the related values to an hash
	for name, values := range attributes {
		stringHash := name + separatorMap + values
		hashAttributes = append(hashAttributes, stringHash)
	}
	//	}
	sort.Strings(hashAttributes)
	return strings.Join(hashAttributes, separatorList)
}

/*
convertAttributesStringToMap

 * @param string - attributesString in the form of var1@@hash(values1)||var2@@hash(values2)||...||varN@@hash(valuesN)

@return map[string]string in the form {var1: hash(values1), var2: hash(values2), ..., varN: hash(valuesN)}
*/
func convertAttributesStringToMap(attributesString string) map[string]string {

	storedMd5HashAttributesMap := map[string]string{}
	if attributesString != "" {
		storedMd5HashAttributesList := strings.Split(attributesString, separatorList)
		if storedMd5HashAttributesList != nil && len(storedMd5HashAttributesList) != 0 {
			for _, elem := range storedMd5HashAttributesList {
				mapValue := strings.Split(elem, separatorMap)
				storedMd5HashAttributesMap[mapValue[0]] = mapValue[1]
			}

		}
	}
	return storedMd5HashAttributesMap

}

func readAttributes(meta interface{}, dn string) ([]interface{}, error) {
	// now deal with attributes
	set := &schema.Set{
		F: attributeHash,
	}

	config := meta.(*Config)
	client, err := config.initiateAndBind()
	if err != nil {
		return nil, err
	}

	log.Printf("[DEBUG] ldap_object::read - looking for object %q", dn)

	// when searching by DN, you don't need t specify the base DN a search
	// filter a "subtree" scope: just put the DN (i.e. the primary key) as the
	// base DN with a "base object" scope, and the returned object will be the
	// entry, if it exists
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

	sr, err := client.Search(request)
	if err != nil {
		log.Printf("[DEBUG] ldap_object::read - lookup for %q returned an error %v", dn, err)
		return nil, err
	}

	log.Printf("[DEBUG] ldap_object::read - query for %q returned %v", dn, sr)

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
				//continue
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

	return set.List(), nil
}
