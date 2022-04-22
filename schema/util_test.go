//go:build test

package schema

import (
	"reflect"
	"testing"

	"github.com/cloudldap/cloudldap/util"
)

func TestNormalize(t *testing.T) {
	testcases := []struct {
		Name     string
		Value    string
		Expected string
	}{
		{
			"cn",
			"abc",
			"abc",
		},
		{
			"cn",
			"aBc",
			"abc",
		},
		{
			"cn",
			"  a  B c  ",
			"a b c",
		},
		{
			"vendorName",
			"foobar",
			"foobar",
		},
		{
			"vendorName",
			"  f oo  Bar  ",
			"f oo Bar",
		},
	}

	sr := NewSchemaRegistry(&SchemaConfig{
		Suffix: "dc=example,dc=com",
	})

	for i, tc := range testcases {
		s, ok := sr.AttributeType(tc.Name)
		if !ok {
			t.Errorf("Unexpected error on %d:\n'%s' -> '%s' expected, got no schema\n", i, tc.Value, tc.Expected)
			continue
		}
		v, err := normalize(s, tc.Value, 0)
		if err != nil {
			t.Errorf("Unexpected error on %d:\nSchema: %v\n'%s' -> '%s' expected, got error %s\n", i, s, tc.Value, tc.Expected, err)
			continue
		}

		if v != tc.Expected {
			t.Errorf("Unexpected error on %d:\nSchema: %v\n'%s' -> %s' expected, got '%s'\n", i, s, tc.Value, tc.Expected, v)
			continue
		}
	}
}

func TestSortObjectClassesAndVerifyChain(t *testing.T) {
	testcases := []struct {
		ObjectClasses            []string
		Expected                 []string
		ExpectedChainVerifyError *util.LDAPError
	}{
		{
			[]string{"person"},
			[]string{"person"},
			nil,
		},
		{
			[]string{"person", "top", "inetOrgPerson", "organizationalPerson"},
			[]string{"inetOrgPerson", "organizationalPerson", "person", "top"},
			nil,
		},
		{
			[]string{"groupOfUniqueNames", "inetOrgPerson"},
			[]string{"groupOfUniqueNames", "inetOrgPerson"},
			util.NewObjectClassViolationInvalidStructualChain("groupOfUniqueNames", "inetOrgPerson"),
		},
		{
			[]string{"groupOfUniqueNames", "person", "inetOrgPerson"},
			[]string{"groupOfUniqueNames", "inetOrgPerson", "person"},
			util.NewObjectClassViolationInvalidStructualChain("groupOfUniqueNames", "inetOrgPerson"),
		},
		{
			[]string{"person", "inetOrgPerson", "groupOfUniqueNames"},
			[]string{"inetOrgPerson", "person", "groupOfUniqueNames"},
			util.NewObjectClassViolationInvalidStructualChain("inetOrgPerson", "groupOfUniqueNames"),
		},
		{
			[]string{"person", "groupOfUniqueNames", "inetOrgPerson"},
			[]string{"person", "groupOfUniqueNames", "inetOrgPerson"},
			util.NewObjectClassViolationInvalidStructualChain("person", "groupOfUniqueNames"),
		},
		{
			[]string{"posixAccount", "systemQuotas", "person", "inetOrgPerson"},
			[]string{"systemQuotas", "posixAccount", "inetOrgPerson", "person"},
			util.NewObjectClassViolationInvalidStructualChain("systemQuotas", "inetOrgPerson"),
		},
	}

	sr := NewSchemaRegistry(&SchemaConfig{
		Suffix: "dc=example,dc=com",
	})

	for i, tc := range testcases {

		objectClasses := []*ObjectClass{}
		for _, v := range tc.ObjectClasses {
			if oc, ok := sr.ObjectClass(v); ok {
				objectClasses = append(objectClasses, oc)
			}
		}

		if len(tc.Expected) != len(objectClasses) {
			t.Errorf("Unexpected error on %d:\nlen %d expected, got %d\n", i, len(tc.Expected), len(objectClasses))
			continue
		}

		sortObjectClasses(sr, objectClasses)

		for j, oc := range objectClasses {
			if tc.Expected[j] != oc.Name {
				t.Errorf("Unexpected error on %d:\n'%s' == '%s' expected, got not equals. %v\n", i, tc.Expected[j], oc.Name, objectClasses)
				continue
			}
		}

		err := verifyChainedObjectClasses(sr, objectClasses)
		if tc.ExpectedChainVerifyError == nil {
			if err != nil {
				t.Errorf("Unexpected error on %d:\n'nil expected, got %v\n", i, err)
				continue
			}
		} else {
			if tc.ExpectedChainVerifyError.Error() != err.Error() {
				t.Errorf("Unexpected error on %d:\n'%v expected, got %v\n", i, tc.ExpectedChainVerifyError, err)
				continue
			}
		}
	}
}

func TestDiffDN(t *testing.T) {
	sr := NewSchemaRegistry(&SchemaConfig{
		Suffix: "dc=example,dc=com",
	})

	parseDN := func(s ...string) []interface{} {
		rtn := make([]interface{}, len(s))
		for i, v := range s {
			dn, _ := ParseDN(sr, v)
			rtn[i] = dn
		}
		return rtn
	}

	testcases := []struct {
		a           []interface{}
		b           []interface{}
		AddExpected []interface{}
		DelExpected []interface{}
	}{
		{
			parseDN("cn=a," + sr.Config.Suffix),
			parseDN("cn=b," + sr.Config.Suffix),
			parseDN("cn=b," + sr.Config.Suffix),
			parseDN("cn=a," + sr.Config.Suffix),
		},
		{
			parseDN("cn=a,"+sr.Config.Suffix, "cn=b,"+sr.Config.Suffix),
			parseDN("cn=c,"+sr.Config.Suffix, "cn=d,"+sr.Config.Suffix),
			parseDN("cn=c,"+sr.Config.Suffix, "cn=d,"+sr.Config.Suffix),
			parseDN("cn=a,"+sr.Config.Suffix, "cn=b,"+sr.Config.Suffix),
		},
		{
			parseDN("cn=a,"+sr.Config.Suffix, "cn=b,"+sr.Config.Suffix),
			parseDN("cn=b,"+sr.Config.Suffix, "cn=c,"+sr.Config.Suffix),
			parseDN("cn=c," + sr.Config.Suffix),
			parseDN("cn=a," + sr.Config.Suffix),
		},
		{
			[]interface{}{},
			parseDN("cn=a," + sr.Config.Suffix),
			parseDN("cn=a," + sr.Config.Suffix),
			[]interface{}{},
		},
		{
			parseDN("cn=a," + sr.Config.Suffix),
			[]interface{}{},
			[]interface{}{},
			parseDN("cn=a," + sr.Config.Suffix),
		},
	}

	for i, tc := range testcases {
		add, del := diffDN(tc.a, tc.b)
		if !reflect.DeepEqual(add, tc.AddExpected) {
			t.Errorf("Unexpected error on %d:\nadd '%v' expected, got '%v'\n", i, tc.AddExpected, add)
			continue
		}
		if !reflect.DeepEqual(del, tc.DelExpected) {
			t.Errorf("Unexpected error on %d:\ndel '%v' expected, got '%v'\n", i, tc.DelExpected, del)
			continue
		}
	}
}
