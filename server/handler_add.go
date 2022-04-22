package server

import (
	"log"

	"github.com/cloudldap/cloudldap/auth"
	"github.com/cloudldap/cloudldap/repo"
	"github.com/cloudldap/cloudldap/schema"
	"github.com/cloudldap/cloudldap/util"
	ldap "github.com/cloudldap/ldapserver"
	"github.com/google/uuid"
	"golang.org/x/xerrors"
)

func handleAdd(s *Server, w ldap.ResponseWriter, m *ldap.Message) {
	ctx := auth.SetSessionContext(m.Context(), auth.GetAuthSession(m))

	r := m.GetAddRequest()

	dn, err := s.NormalizeDN(string(r.Entry()))
	if err != nil {
		responseAddError(w, err)
		return
	}

	if !s.RequiredAuthz(m, AddOps, dn) {
		// TODO return errror message
		// ldap_add: Insufficient access (50)
		// additional info: no write access to parent
		responseAddError(w, util.NewInsufficientAccess())
		return
	}

	// Invalid suffix
	if !dn.Equal(s.Suffix) && !dn.IsSubOf(s.Suffix) {
		responseAddError(w, util.NewNoGlobalSuperiorKnowledge())
		return
	}

	log.Printf("debug: Start adding DN: %v", dn)

	attrOrig := make(repo.AttrsOrig)

	changelog, err := repo.NewChangelog(ctx, s.schemaRegistry, dn, attrOrig)
	if err != nil {
		responseAddError(w, err)
		return
	}

	for _, attr := range r.Attributes() {
		k := attr.Type_()
		attrName := string(k)

		values := make([]string, len(attr.Vals()))
		for i, v := range attr.Vals() {
			values[i] = string(v)
		}

		// Reject invalid attribute name here
		sv, err := schema.NewSchemaValue(s.schemaRegistry, attrName, values)
		if err != nil {
			responseAddError(w, err)
			return
		}

		err = changelog.Add(sv)
		if err != nil {
			responseAddError(w, err)
			return
		}
	}

	if !changelog.HasAttr("entryUUID") {
		sv, err := schema.NewSchemaValue(s.schemaRegistry, "entryUUID", []string{uuid.New().String()})
		if err != nil {
			responseAddError(w, err)
			return
		}
		if err := changelog.AddWithouCheck(sv); err != nil {
			responseAddError(w, err)
			return
		}
	}

	err = changelog.Validate()
	if err != nil {
		responseAddError(w, err)
		return
	}

	log.Printf("info: Adding entry: %s", r.Entry())

	i := 0
Retry:

	id, err := s.Repo().Insert(ctx, changelog)
	if err != nil {
		var retryError *util.RetryError
		if ok := xerrors.As(err, &retryError); ok {
			if i < maxRetry {
				i++
				log.Printf("warn: Detect consistency error. Do retry. try_count: %d", i)
				goto Retry
			}
			log.Printf("error: Give up to retry. try_count: %d", i)
		}

		responseAddError(w, err)
		return
	}

	log.Printf("debug: Added. Id: %d, DN: %v", id, dn)

	res := ldap.NewAddResponse(ldap.LDAPResultSuccess)
	w.Write(res)

	log.Printf("debug: End Adding entry: %s", r.Entry())
}

func responseAddError(w ldap.ResponseWriter, err error) {
	var ldapErr *util.LDAPError
	if ok := xerrors.As(err, &ldapErr); ok {
		log.Printf("warn: Add LDAP error. err: %+v", err)

		res := ldap.NewAddResponse(ldapErr.Code)
		if ldapErr.Msg != "" {
			res.SetDiagnosticMessage(ldapErr.Msg)
		}
		if ldapErr.MatchedDN != "" {
			res.SetMatchedDN(ldapErr.MatchedDN)
		}
		w.Write(res)
	} else {
		log.Printf("error: Add error. err: %+v", err)

		// TODO
		res := ldap.NewAddResponse(ldap.LDAPResultProtocolError)
		w.Write(res)
	}
}
