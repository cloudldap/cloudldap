//go:build test

package repo

import (
	"context"
	"testing"

	"github.com/cloudldap/cloudldap/auth"
	"github.com/cloudldap/cloudldap/schema"
	"github.com/cloudldap/cloudldap/util"
)

func TestChangeLogAdd(t *testing.T) {
	testcases := []struct {
		ID            int
		DN            string
		Attrs         map[string][]string
		ExpectedError error
	}{
		{
			1,
			"cn=abc,ou=Users,dc=example,dc=com",
			map[string][]string{
				"cn": {"abc"},
				"sn": {"efg"},
			},
			util.NewObjectClassViolation(),
		},
		{
			2,
			"cn=abc,ou=Users,dc=example,dc=com",
			map[string][]string{
				"objectClass": {"inetOrgPerson"},
				"cn":          {"abc"},
			},
			util.NewObjectClassViolationRequiresAttribute("inetOrgPerson", "sn"),
		},
		{
			3,
			"cn=abc,ou=Users,dc=example,dc=com",
			map[string][]string{
				"objectClass": {"inetOrgPerson"},
				"cn":          {"abc"},
				"sn":          {"efg"},
				"displayName": {"hij"},
			},
			nil,
		},
		{
			4,
			"cn=abc,ou=Users,dc=example,dc=com",
			map[string][]string{
				"objectClass": {"person"},
				"cn":          {"abc"},
				"sn":          {"efg"},
				"displayName": {"hij"},
			},
			util.NewObjectClassViolationNotAllowed("displayName"),
		},
		{
			5,
			"cn=abc,ou=Users,dc=example,dc=com",
			map[string][]string{
				"objectClass": {"unknown"},
				"cn":          {"abc"},
			},
			util.NewInvalidPerSyntax("objectClass", 0),
		},
		{
			6,
			"cn=abc,ou=Users,dc=example,dc=com",
			map[string][]string{
				"objectClass": {"person", "unknown"},
				"cn":          {"abc"},
				"sn":          {"efg"},
			},
			util.NewInvalidPerSyntax("objectClass", 1),
		},
	}
	sr := schema.NewSchemaRegistry(&schema.SchemaConfig{
		CustomSchema:     []string{},
		MigrationEnabled: false,
	})

	requester, _ := schema.NormalizeDN(sr, "cn=manager")
	ctx := auth.SetSessionContext(context.Background(), &auth.AuthSession{
		DN: requester,
	})

	for _, tc := range testcases {
		dn, err := schema.ParseDN(sr, tc.DN)
		if err != nil {
			t.Errorf("Unexpected error on %d:\nParse DN: %s, got error [%v]\n", tc.ID, tc.DN, err)
			continue
		}

		empty := make(AttrsOrig)

		entry, err := NewChangelog(ctx, sr, dn, empty)
		if err != nil {
			t.Errorf("Unexpected error on %d:\n DN: %s, got error [%v]\n", tc.ID, tc.DN, err)
			continue
		}

		for k, v := range tc.Attrs {
			var sv *schema.SchemaValue
			sv, err = schema.NewSchemaValue(sr, k, v)
			if err != nil {
				break
			}

			err = entry.Add(sv)
			if err != nil {
				break
			}
		}
		if err != nil {
			if tc.ExpectedError.Error() != err.Error() {
				t.Errorf("Unexpected error on %d:\nError: [%v] expected, got error [%v]\n", tc.ID, tc.ExpectedError, err)
			}
			continue
		}

		err = entry.Validate()
		if tc.ExpectedError == nil {
			if err != nil {
				t.Errorf("Unexpected error on %d:\nError: [%v] expected, got error [%v]\n", tc.ID, tc.ExpectedError, err)
			}
			continue
		} else {
			if tc.ExpectedError.Error() != err.Error() {
				t.Errorf("Unexpected error on %d:\nError: [%v] expected, got error [%v]\n", tc.ID, tc.ExpectedError, err)
			}
		}
	}
}
