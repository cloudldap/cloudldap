package repo

import (
	"context"
	"log"
	"time"

	"github.com/cloudldap/cloudldap/auth"
	"github.com/cloudldap/cloudldap/schema"
	"github.com/cloudldap/cloudldap/util"
	"github.com/pkg/errors"
)

type Changelog struct {
	schema    *schema.SchemaRegistry
	dn        *schema.DN
	newDN     *schema.DN
	newEntry  map[string]*schema.SchemaValue
	oldEntry  map[string]*schema.SchemaValue
	changed   map[string]struct{}
	requester *schema.DN
	timestamp string
}

type ModOperation struct {
	Add     []string
	Replace []string
	Delete  []string
}

func (m *ModOperation) IsClear() bool {
	return !m.IsAdd() && !m.IsReplace() && !m.IsDelete()
}

func (m *ModOperation) IsAdd() bool {
	return len(m.Add) > 0
}

func (m *ModOperation) IsReplace() bool {
	return len(m.Replace) > 0
}

func (m *ModOperation) IsDelete() bool {
	return len(m.Delete) > 0
}

func NewChangelog(ctx context.Context, s *schema.SchemaRegistry, dn *schema.DN, attrsOrig AttrsOrig) (*Changelog, error) {
	changelog := &Changelog{
		schema:   s,
		dn:       dn,
		newEntry: map[string]*schema.SchemaValue{},
		oldEntry: map[string]*schema.SchemaValue{},
		changed:  map[string]struct{}{},
	}

	for k, v := range attrsOrig {
		sv, err := changelog.apply(k, v)
		if err != nil {
			return nil, err
		}
		// Record old entry for calculating diff
		changelog.oldEntry[sv.Name()] = sv.Clone()
	}

	session, err := auth.AuthSessionContext(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "Not authenticated")
	}

	changelog.requester = session.DN
	changelog.timestamp = time.Now().In(time.UTC).Format(schema.TIMESTAMP_FORMAT)

	return changelog, nil
}

func (c *Changelog) Requester() *schema.DN {
	return c.requester
}

func (c *Changelog) Timestamp() string {
	return c.timestamp
}

func (c *Changelog) DN() *schema.DN {
	return c.dn
}

func (c *Changelog) NewDN() *schema.DN {
	return c.newDN
}

func (c *Changelog) UpdateDN(newDN *schema.DN) {
	c.newDN = newDN
}

func (c *Changelog) DNNorm() string {
	return c.dn.DNNormStr()
}

func (c *Changelog) NewEntry() map[string]*schema.SchemaValue {
	return c.newEntry
}

func (c *Changelog) ToAttrsOrig() AttrsOrig {
	orig := make(map[string][]string, len(c.newEntry))
	for k, v := range c.newEntry {
		orig[k] = v.Orig()
	}
	return orig
}

func (c *Changelog) ToNewAttrsOrig() AttrsOrig {
	orig := c.ToAttrsOrig()

	// Creator, Modifiers
	// If migration mode is enabled, we use the specified values
	if v, ok := orig["creatorsName"]; ok {
		// Migration mode
		// It's already normlized
		creatorsDN, _ := schema.NormalizeDN(c.schema, v[0])
		orig["creatorsName"] = []string{creatorsDN.DNOrigEncodedStrWithoutSuffix(c.schema.SuffixDN)}
	} else {
		orig["creatorsName"] = []string{c.requester.DNOrigEncodedStrWithoutSuffix(c.schema.SuffixDN)}
	}
	// If migration mode is enabled, we use the specified values
	if v, ok := orig["modifiersName"]; ok {
		// Migration mode
		// It's already normlized
		modifiersDN, _ := schema.NormalizeDN(c.schema, v[0])
		orig["modifiersName"] = []string{modifiersDN.DNOrigEncodedStrWithoutSuffix(c.schema.SuffixDN)}
	} else {
		orig["modifiersName"] = orig["creatorsName"]
	}

	// Timestamp
	// If migration mode is enabled, we use the specified values
	if _, ok := orig["createTimestamp"]; ok {
		// Migration mode
		// It's already normlized
	} else {
		orig["createTimestamp"] = []string{c.timestamp}
	}

	// If migration mode is enabled, we use the specified values
	if _, ok := orig["modifyTimestamp"]; ok {
		// Migration mode
		// It's already normlized
	} else {
		orig["modifyTimestamp"] = []string{c.timestamp}
	}

	return orig
}

func (c *Changelog) ToDiff() map[string]*ModOperation {
	diff := map[string]*ModOperation{}

	for k, _ := range c.changed {
		nsv, ok := c.newEntry[k]
		if !ok || nsv.IsEmpty() {
			// Clear
			diff[k] = &ModOperation{}
			continue
		}

		osv, ok := c.oldEntry[nsv.Name()]
		if !ok || osv.IsEmpty() {
			diff[k] = &ModOperation{
				Replace: nsv.Orig(),
			}
		} else {
			add, replace, del := nsv.Diff(osv)
			if add == nil && len(replace) == 0 && del == nil {
				// Clear
				diff[k] = &ModOperation{}
				continue
			}

			if len(replace) > 0 {
				diff[k] = &ModOperation{
					Replace: replace,
				}
			} else if len(add) > 0 || len(del) > 0 {
				op := &ModOperation{}
				if len(add) > 0 {
					op.Add = add
				}
				if len(del) > 0 {
					op.Delete = del
				}
				diff[k] = op
			}
		}

	}
	return diff
}

func (c *Changelog) ToMemberOfDiff() (add []string, del []string) {
	a := util.NewStringSet()
	d := util.NewStringSet()

	for k, _ := range c.changed {
		// TODO
		at, _ := c.schema.AttributeType(k)
		if !at.IsAssociationAttribute() {
			continue
		}

		nsv, nsvOk := c.newEntry[k]
		osv, osvOk := c.oldEntry[k]
		if !nsvOk && !osvOk {
			continue
		} else if !nsvOk && osvOk {
			// Clear, it means old values are deleted values
			d.AddAll(osv.Orig()...)
			continue

		} else if nsvOk && !osvOk {
			// No old values, it means new values are added values
			a.AddAll(nsv.Orig()...)
		} else {
			add, replace, del := nsv.Diff(osv)
			if add == nil && len(replace) == 0 && del == nil {
				// Clear, it means old values are deleted values
				d.AddAll(osv.Orig()...)
				continue
			}

			if len(replace) > 0 {
				// No old values, it means new values are added values
				a.AddAll(nsv.Orig()...)
			} else if len(add) > 0 || len(del) > 0 {
				if len(add) > 0 {
					a.AddAll(add...)
				}
				if len(del) > 0 {
					d.AddAll(del...)
				}
			}
		}
	}

	add = a.Values()
	del = d.Values()

	return add, del
}

func (c *Changelog) apply(attrName string, attrValue []string) (*schema.SchemaValue, error) {
	sv, err := schema.NewSchemaValue(c.schema, attrName, attrValue)
	if err != nil {
		return nil, err
	}
	if err := c.addsv(sv); err != nil {
		return nil, err
	}

	// Don't Record changelog here

	return sv, nil
}

func (c *Changelog) record(value *schema.SchemaValue) {
	c.changed[value.Name()] = struct{}{}
}

func (c *Changelog) Add(sv *schema.SchemaValue) error {
	if sv.IsNoUserModificationWithMigrationDisabled() {
		return util.NewNoUserModificationAllowedConstraintViolation(sv.Name())
	}

	// Apply change
	// We can detect schema error here
	if err := c.addsv(sv); err != nil {
		return err
	}

	// Record
	c.record(sv)

	return nil
}

func (c *Changelog) AddWithouCheck(sv *schema.SchemaValue) error {
	// Apply change
	// We can detect schema error here
	if err := c.addsv(sv); err != nil {
		return err
	}

	// Record
	c.record(sv)

	return nil
}

func (c *Changelog) addsv(value *schema.SchemaValue) error {
	name := value.Name()

	current, ok := c.newEntry[name]
	if !ok {
		c.newEntry[name] = value
	} else {
		return current.Add(value)
	}
	return nil
}

func (c *Changelog) ObjectClassesNorm() ([]string, bool) {
	v, ok := c.newEntry["objectClass"]
	if !ok {
		return nil, false
	}
	if v.IsEmpty() {
		return nil, false
	}
	return v.NormStr(), true
}

// Replace with the value(s).
func (c *Changelog) Replace(sv *schema.SchemaValue) error {
	if sv.IsNoUserModificationWithMigrationDisabled() {
		return util.NewNoUserModificationAllowedConstraintViolation(sv.Name())
	}

	// Validate ObjectClass
	if sv.Name() == "objectClass" {
		// Normalized objectClasses are sorted
		stoc, ok := c.ObjectClassesNorm()
		if !ok {
			log.Printf("error: Unexpected entry. The entry doesn't have objectClass. Cancel the operation. dn_norm: %s", c.dn.DNNormStr())
			return util.NewOperationsError()
		}
		for i, v := range sv.Orig() {
			oc, ok := c.schema.ObjectClass(v)
			if !ok {
				// e.g.
				// ldap_modify: Invalid syntax (21)
				// additional info: objectClass: value #0 invalid per syntax
				return util.NewInvalidPerSyntax("objectClass", i)
			}

			if oc.Structural {
				// e.g.
				// ldap_modify: Cannot modify object class (69)
				//     additional info: structural object class modification from 'inetOrgPerson' to 'person' not allowed
				return util.NewObjectClassModsProhibited(stoc[0], oc.Name)
			}
		}
	}

	// Apply change
	// We can detect schema error here
	if err := c.replacesv(sv); err != nil {
		return err
	}

	// Record
	c.record(sv)

	return nil
}

func (c *Changelog) replacesv(value *schema.SchemaValue) error {
	name := value.Name()

	if value.IsEmpty() {
		delete(c.newEntry, name)
	} else {
		c.newEntry[name] = value
	}
	return nil
}

// Delete from current value(s) if the value matchs.
func (c *Changelog) Delete(sv *schema.SchemaValue) error {
	if sv.IsNoUserModificationWithMigrationDisabled() {
		return util.NewNoUserModificationAllowedConstraintViolation(sv.Name())
	}

	// Validate ObjectClass
	if sv.Name() == "objectClass" {
		// Normalized objectClasses are sorted
		stoc, ok := c.ObjectClassesNorm()
		if !ok {
			log.Printf("error: Unexpected entry. The entry doesn't have objectClass. Cancel the operation. dn_norm: %s", c.dn.DNNormStr())
			return util.NewOperationsError()
		}
		for i, v := range sv.Orig() {
			oc, ok := c.schema.ObjectClass(v)
			if !ok {
				// e.g.
				// ldap_modify: Invalid syntax (21)
				// additional info: objectClass: value #0 invalid per syntax
				return util.NewInvalidPerSyntax("objectClass", i)
			}

			if oc.Structural && stoc[0] == oc.Name {
				// e.g.
				// ldap_modify: Object class violation (65)
				//     additional info: no objectClass attribute
				return util.NewObjectClassViolation()
			}
		}
	}

	// Apply change
	if err := c.deletesv(sv); err != nil {
		return err
	}

	// Record
	c.record(sv)

	return nil
}

func (c *Changelog) deletesv(value *schema.SchemaValue) error {
	if value.IsEmpty() {
		return c.deleteAll(value.Schema())
	}

	current, ok := c.newEntry[value.Name()]
	if !ok {
		log.Printf("warn: Failed to modify/delete because of no attribute. dn: %s, attrName: %s", c.dn.DNNormStr(), value.Name())
		return util.NewNoSuchAttribute("modify/delete", value.Name())
	}

	err := current.Delete(value)
	if err != nil {
		return err
	}
	return nil
}

func (c *Changelog) deleteAll(s *schema.AttributeType) error {
	if !c.HasAttr(s.Name) {
		log.Printf("warn: Failed to modify/delete because of no attribute. dn: %s", c.dn.DNNormStr())
		return util.NewNoSuchAttribute("modify/delete", s.Name)
	}

	c.newEntry[s.Name].Clear()
	return nil
}

func (c *Changelog) HasAttr(attrName string) bool {
	s, ok := c.schema.AttributeType(attrName)
	if !ok {
		return false
	}

	sv, ok := c.newEntry[s.Name]
	if !ok {
		return false
	}

	return !sv.IsEmpty()
}

func (c *Changelog) Validate() error {
	// objectClass is required
	if !c.HasAttr("objectClass") {
		return util.NewObjectClassViolation()
	}

	// Validate RDN
	for k, v := range c.dn.RDN() {
		sv, ok := c.newEntry[k]

		// If no attributes for RDN, return NamingViolation error
		if !ok || sv.IsEmpty() {
			// Add attributes for RDN when adding case instead of error
			if len(c.oldEntry) == 0 {
				if _, err := c.apply(k, []string{v.Orig}); err != nil {
					return err
				}
			} else {
				return util.NewNamingViolation(k)
			}
			continue
		}

		// Although it has attributes for RDN, if it doesn't have same value of RDN,
		// return NamingViolation error for value
		if !sv.Contains(v.Norm) {
			// Add attributes for RDN when adding case instead of error
			if len(c.oldEntry) == 0 {
				if _, err := c.apply(k, []string{v.Orig}); err != nil {
					return err
				}
			} else {
				return util.NewNamingViolationForValue(k)
			}
		}
	}

	// Validate schema by objectClass
	ocs, ok := c.ObjectClassesNorm()
	if !ok {
		return util.NewObjectClassViolation()
	}
	if err := c.schema.ValidateObjectClass(ocs, c.newEntry); err != nil {
		return err
	}

	return nil
}
