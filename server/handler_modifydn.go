package server

import (
	"database/sql"
	"errors"
	"log"

	"github.com/cloudldap/cloudldap/auth"
	"github.com/cloudldap/cloudldap/repo"
	"github.com/cloudldap/cloudldap/schema"
	"github.com/cloudldap/cloudldap/util"
	ldap "github.com/cloudldap/ldapserver"
	"golang.org/x/xerrors"
)

func handleModifyDN(s *Server, w ldap.ResponseWriter, m *ldap.Message) {
	ctx := auth.SetSessionContext(m.Context(), auth.GetAuthSession(m))

	r := m.GetModifyDNRequest()
	dn, err := s.NormalizeDN(string(r.Entry()))

	if err != nil {
		log.Printf("warn: Invalid dn: %s err: %s", r.Entry(), err)

		// TODO return correct error
		responseModifyDNError(w, err)
		return
	}

	if !s.RequiredAuthz(m, ModRDNOps, dn) {
		responseModifyDNError(w, util.NewInsufficientAccess())
		return
	}

	newDN, oldRDN, hasChange, err := dn.ModifyRDN(s.schemaRegistry, string(r.NewRDN()), bool(r.DeleteOldRDN()))

	if err != nil {
		// TODO return correct error
		log.Printf("info: Invalid newrdn. dn: %s newrdn: %s err: %#v", dn.DNNormStr(), r.NewRDN(), err)
		responseModifyDNError(w, err)
		return
	}

	log.Printf("info: Modify DN entry: %s", dn.DNNormStr())

	if r.NewSuperior() != nil {
		sup := string(*r.NewSuperior())
		newParentDN, err := s.NormalizeDN(sup)
		if err != nil {
			// TODO return correct error
			responseModifyDNError(w, util.NewInvalidDNSyntax())
			return
		}

		newDN, err = newDN.Move(newParentDN)
		if err != nil {
			// TODO return correct error
			responseModifyDNError(w, util.NewInvalidDNSyntax())
			return
		}
	}

	i := 0
Retry:
	// Same level, change RDN only
	err = s.Repo().UpdateDN(ctx, dn, newDN, oldRDN, func(attrsOrig repo.AttrsOrig) (*repo.Changelog, error) {

		changelog, err := repo.NewChangelog(ctx, s.schemaRegistry, dn, attrsOrig)
		if err != nil {
			return nil, err
		}

		changelog.UpdateDN(newDN)

		if !hasChange {
			return changelog, nil
		}

		for k, v := range newDN.RDN() {
			nsv, err := schema.NewSchemaValue(s.schemaRegistry, k, []string{v.Orig})
			if err != nil {
				return nil, err
			}

			if old, ok := dn.RDN()[nsv.Name()]; ok {
				osv, err := schema.NewSchemaValue(s.schemaRegistry, nsv.Name(), []string{old.Orig})
				if err != nil {
					return nil, err
				}

				if bool(r.DeleteOldRDN()) {
					if err := changelog.Delete(osv); err != nil {
						return nil, err
					}
				}
				if err := changelog.Add(nsv); err != nil {
					// Same value might exists in the current entry as non-RDN
					var ldapErr *util.LDAPError
					if ok := errors.As(err, &ldapErr); ok {
						if !ldapErr.IsAttributeOrValueExists() {
							return nil, err
						}
					}
				}
				break
			}
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
		// TODO error code
		responseModifyDNError(w, err)
		return
	}

	res := ldap.NewModifyDNResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func responseModifyDNError(w ldap.ResponseWriter, err error) {
	var ldapErr *util.LDAPError
	if ok := xerrors.As(err, &ldapErr); ok {
		log.Printf("warn: ModifyDN LDAP error. err: %v", err)

		res := ldap.NewModifyDNResponse(ldapErr.Code)
		if ldapErr.Msg != "" {
			res.SetDiagnosticMessage(ldapErr.Msg)
		}
		w.Write(res)
	} else {
		log.Printf("error: ModifyDN error. err: %+v", err)

		// TODO
		res := ldap.NewModifyDNResponse(ldap.LDAPResultProtocolError)
		w.Write(res)
	}
}
