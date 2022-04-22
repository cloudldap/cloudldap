package server

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/cloudldap/cloudldap/auth"
	"github.com/cloudldap/cloudldap/repo"
	"github.com/cloudldap/cloudldap/schema"
	"github.com/cloudldap/cloudldap/util"
	ldap "github.com/cloudldap/ldapserver"
	"github.com/jsimonetti/pwscheme/ssha"
	"github.com/jsimonetti/pwscheme/ssha256"
	"github.com/jsimonetti/pwscheme/ssha512"
	"golang.org/x/xerrors"
)

func handleBind(s *Server, w ldap.ResponseWriter, m *ldap.Message) {
	ctx := auth.SetSessionContext(m.Context(), auth.GetAuthSession(m))

	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)

	if r.AuthenticationChoice() == "simple" {
		name := string(r.Name())
		input := string(r.AuthenticationSimple())

		dn, err := s.NormalizeDN(name)
		if err != nil {
			log.Printf("info: Bind failed - Invalid DN syntax. request_dn: %s err: %s", name, err)
			res.SetResultCode(ldap.LDAPResultInvalidDNSyntax)
			res.SetDiagnosticMessage("invalid DN")
			w.Write(res)
			return
		}

		// For rootdn
		if dn.Equal(s.GetRootDN()) {
			// TODO implement password policy for root user
			if ok := validateCred(ctx, s, input, s.GetRootPW()); !ok {
				log.Printf("info: Bind failed - Invalid credentials. dn_norm: %s", dn.DNNormStr())
				res.SetResultCode(ldap.LDAPResultInvalidCredentials)
				res.SetDiagnosticMessage("invalid credentials")
				w.Write(res)
				return
			}
			log.Printf("info: Bind ok. dn_norm: %s", dn.DNNormStr())

			saveAuthencatedDNAsRoot(m, dn)

			w.Write(res)
			return
		}

		// Anonymous
		if dn.IsAnonymous() {
			log.Printf("info: Bind anonymous user.")

			w.Write(res)
			return
		}

		log.Printf("info: Find bind user. DN: %s", dn.DNNormStr())

		err = s.Repo().Bind(ctx, dn, func(current *repo.FetchedCredential) error {
			// If the user doesn't have credentials, always return 'invalid credential'.
			if len(current.Credential) == 0 {
				log.Printf("info: Bind failed - Not found credentials. dn_norm: %s, err: %s", dn.DNNormStr(), err)
				return util.NewInvalidCredentials()
			}

			if isLocked(current) {
				log.Printf("info: Bind failed - Account locked. dn_norm: %s", dn.DNNormStr())
				return util.NewAccountLocked()
			}

			bindOK := validateCreds(ctx, s, input, current)

			if !bindOK {
				if current.PPolicy.ShouldLockout(current.PwdFailureCount) {
					log.Printf("info: Bind failed - Invalid credentials then locking now. dn_norm: %s", dn.DNNormStr())
					return util.NewAccountLocking()
				}

				log.Printf("info: Bind failed - Invalid credentials. dn_norm: %s", dn.DNNormStr())
				return util.NewInvalidCredentials()
			}

			saveAuthencatedDN(m, dn, current.MemberOf)

			return nil
		})

		// Bind failure
		if err != nil {
			var lerr *util.LDAPError
			if ok := xerrors.As(err, &lerr); ok {
				if !lerr.IsInvalidCredentials() {
					log.Printf("error: Bind failed - LDAP error. dn_norm: %s, err: %+v", dn.DNNormStr(), err)
				}

				res.SetResultCode(lerr.Code)
				res.SetDiagnosticMessage(lerr.Msg)
				w.Write(res)
				return
			} else {
				log.Printf("error: Bind failed - System error. dn_norm: %s, err: %+v", dn.DNNormStr(), err)
			}

			// Return system error
			res.SetResultCode(ldap.LDAPResultUnavailable)
			w.Write(res)
			return
		}

		// Bind success
		log.Printf("info: Bind ok. dn_norm: %s", dn.DNNormStr())

		w.Write(res)
		return

	} else {
		res.SetResultCode(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Authentication choice not supported")
	}

	w.Write(res)
}

// isLocked checks the account is locked if the lock is enabled in the password policy
func isLocked(cred *repo.FetchedCredential) bool {
	if cred.PPolicy.IsLockoutEnabled() {
		if !cred.PwdAccountLockedTime.IsZero() {
			if cred.PPolicy.LockoutDuration() == 0 {
				// Locked until unlocking by administrator?
				log.Println("Permanent locked")
				return true
			}
			cur := time.Now()
			unlockTime := cred.PwdAccountLockedTime.Add(time.Duration(cred.PPolicy.LockoutDuration()) * time.Second)
			if cur.Before(unlockTime) {
				// Temporarily locked
				log.Println("Temporarily locked")
				return true
			}
		}
	}
	return false
}

func validateCreds(ctx context.Context, s *Server, input string, cred *repo.FetchedCredential) bool {
	for _, v := range cred.Credential {
		if ok := validateCred(ctx, s, input, v); ok {
			return true
		}
	}
	return false
}

func validateCred(ctx context.Context, s *Server, input, cred string) bool {
	var ok bool
	var err error
	if len(cred) > 7 && string(cred[0:6]) == "{SSHA}" {
		ok, err = ssha.Validate(input, cred)

	} else if len(cred) > 10 && string(cred[0:9]) == "{SSHA256}" {
		ok, err = ssha256.Validate(input, cred)

	} else if len(cred) > 10 && string(cred[0:9]) == "{SSHA512}" {
		ok, err = ssha512.Validate(input, cred)

	} else if len(cred) > 7 && string(cred[0:6]) == "{SASL}" {
		ok, err = doPassThrough(ctx, s, input, cred[6:])
	} else {
		// Plain
		ok = input == cred
	}

	if err != nil {
		if err.Error() == "hash does not match password" {
			log.Printf("info: Invalid bindDN/credential. err: %+v", err)
		} else {
			log.Printf("error: Failed to authenticate. err: %+v", err)
		}
	}

	return ok
}

type InvalidCredentials struct {
	err error
}

func (i InvalidCredentials) Error() string {
	return i.err.Error()
}

func doPassThrough(ctx context.Context, s *Server, input, passThroughKey string) (bool, error) {
	log.Printf("Handle pass-through authentication: %s", passThroughKey)

	i := strings.LastIndex(passThroughKey, "@")
	if i == -1 {
		return false, xerrors.Errorf("Invalid stored credential. It isn't '<ID>@<DOMAIN>' format. cred: %s", passThroughKey)
	}

	uid := strings.TrimSpace(passThroughKey[:i])
	domain := strings.TrimSpace(passThroughKey[i+1:])

	if uid == "" || domain == "" {
		return false, xerrors.Errorf("Invalid stored credential. It isn't '<ID>@<DOMAIN>' format. cred: %s", passThroughKey)
	}

	if c, ok := s.config.PassThroughConfig.Get(domain); ok {
		return c.Authenticate(ctx, domain, uid, input)
	}

	// No pass-through client

	return false, xerrors.Errorf("Invalid domain. domain: %s, uid: %s", domain, uid)
}

func saveAuthencatedDNAsRoot(m *ldap.Message, dn *schema.DN) {
	session := auth.GetAuthSession(m)
	if session.DN != nil {
		log.Printf("info: Switching authenticated user: %s -> %s", session.DN.DNNormStr(), dn.DNNormStr())
	}
	session.DN = dn
	session.IsRoot = true
	log.Printf("Saved authenticated DN: %s", dn.DNNormStr())
}

func saveAuthencatedDN(m *ldap.Message, dn *schema.DN, groups []*schema.DN) {
	session := auth.GetAuthSession(m)
	if session.DN != nil {
		log.Printf("info: Switching authenticated user: %s -> %s", session.DN.DNNormStr(), dn.DNNormStr())
	}
	session.DN = dn
	session.Groups = groups
	session.IsRoot = false
	log.Printf("Saved authenticated DN: %s", dn.DNNormStr())
}
