package server

import (
	"database/sql"
	"log"

	"github.com/cloudldap/cloudldap/auth"
	"github.com/cloudldap/cloudldap/repo"
	"github.com/cloudldap/cloudldap/schema"
	"github.com/cloudldap/cloudldap/util"
	ldap "github.com/cloudldap/ldapserver"
	"github.com/pkg/errors"
	"golang.org/x/xerrors"
)

func handleModify(s *Server, w ldap.ResponseWriter, m *ldap.Message) {
	ctx := auth.SetSessionContext(m.Context(), auth.GetAuthSession(m))

	r := m.GetModifyRequest()
	dn, err := s.NormalizeDN(string(r.Object()))

	if err != nil {
		log.Printf("warn: Invalid dn: %s, err: %s", r.Object(), err)

		// TODO return correct error
		res := ldap.NewModifyResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	if !s.RequiredAuthz(m, ModifyOps, dn) {
		responseModifyError(w, util.NewInsufficientAccess())
		return
	}

	log.Printf("info: Modify entry: %s", dn.DNNormStr())

	i := 0
Retry:

	err = s.Repo().Update(ctx, dn, func(attrsOrig repo.AttrsOrig) (*repo.Changelog, error) {

		changelog, err := repo.NewChangelog(ctx, s.schemaRegistry, dn, attrsOrig)
		if err != nil {
			return nil, err
		}

		// Apply the changes to changelog
		for _, change := range r.Changes() {
			modification := change.Modification()
			attrName := string(modification.Type_())

			log.Printf("Modify operation: %d, attribute: %s", change.Operation(), modification.Type_())

			var values []string
			for _, attributeValue := range modification.Vals() {
				values = append(values, string(attributeValue))
				log.Printf("--> value: %s", attributeValue)
			}

			// Reject invalid attribute name here
			sv, err := schema.NewSchemaValue(s.schemaRegistry, attrName, values)
			if err != nil {
				return nil, err
			}

			// Resolve association
			// DNOrigStr => int64
			if sv.IsAssociationAttribute() {
				if sv, err = s.Repo().Association(ctx, sv); err != nil {
					return nil, err
				}
			}

			switch change.Operation() {
			case ldap.ModifyRequestChangeOperationAdd:
				err = changelog.Add(sv)

			case ldap.ModifyRequestChangeOperationDelete:
				err = changelog.Delete(sv)

			case ldap.ModifyRequestChangeOperationReplace:
				err = changelog.Replace(sv)
			}

			if err != nil {
				return nil, err
			}
		}

		// Validate the entry by schema
		if err := changelog.Validate(); err != nil {
			return nil, errors.Wrap(err, "invalid schema")
		}

		return changelog, nil
	})

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

		if err == sql.ErrNoRows {
			responseModifyError(w, util.NewNoSuchObject())
			return
		}
		responseModifyError(w, errors.Wrapf(err, "Failed to modify the entry. dn: %s", dn.DNNormStr()))
		return
	}

	res := ldap.NewModifyResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func responseModifyError(w ldap.ResponseWriter, err error) {
	var ldapErr *util.LDAPError
	if ok := xerrors.As(err, &ldapErr); ok {
		log.Printf("warn: Modify LDAP error. err: %v", err)

		res := ldap.NewModifyResponse(ldapErr.Code)
		if ldapErr.Msg != "" {
			res.SetDiagnosticMessage(ldapErr.Msg)
		}
		w.Write(res)
	} else {
		log.Printf("error: Modify error. err: %+v", err)

		// TODO
		res := ldap.NewModifyResponse(ldap.LDAPResultProtocolError)
		w.Write(res)
	}
}
