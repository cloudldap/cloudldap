package auth

import (
	"context"

	"github.com/cloudldap/cloudldap/schema"
	ldap "github.com/cloudldap/ldapserver"
	"golang.org/x/xerrors"
)

const authContextKey string = "auth"

func SetSessionContext(ctx context.Context, authSession *AuthSession) context.Context {
	return context.WithValue(context.WithValue(ctx, authContextKey, authSession), schema.DNCacheContextKey, schema.NewDnCache())
}

func AuthSessionContext(ctx context.Context) (*AuthSession, error) {
	v := ctx.Value(authContextKey)

	session, ok := v.(*AuthSession)
	if !ok {
		return nil, xerrors.Errorf("No authSession in the context")
	}

	return session, nil
}

type AuthSession struct {
	DN     *schema.DN
	Groups []*schema.DN
	IsRoot bool
}

func (a *AuthSession) UserDNStr(s *schema.SchemaRegistry) string {
	return a.DN.DNOrigEncodedStrWithoutSuffix(s.SuffixDN)
}

func GetSession(m *ldap.Message) map[string]interface{} {
	store := m.Client.GetCustomData()
	if sessionMap, ok := store.(map[string]interface{}); ok {
		return sessionMap
	} else {
		sessionMap := map[string]interface{}{}
		m.Client.SetCustomData(sessionMap)
		return sessionMap
	}
}

func GetAuthSession(m *ldap.Message) *AuthSession {
	session := GetSession(m)
	if authSession, ok := session["auth"]; ok {
		return authSession.(*AuthSession)
	} else {
		authSession := &AuthSession{}
		session["auth"] = authSession
		return authSession
	}
}

func GetPageSession(m *ldap.Message) map[string]int32 {
	session := GetSession(m)
	if pageSession, ok := session["page"]; ok {
		return pageSession.(map[string]int32)
	} else {
		pageSession := map[string]int32{}
		session["page"] = pageSession
		return pageSession
	}
}
