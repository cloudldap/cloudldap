module github.com/cloudldap/cloudldap

go 1.18

require (
	github.com/cloudldap/goldap/message v0.0.0-20220624044827-7916bfae1b74
	github.com/cloudldap/ldapserver v0.0.0-00010101000000-000000000000
	github.com/comail/colog v0.0.0-20160416085026-fba8e7b1f46c
	github.com/go-ldap/ldap/v3 v3.4.3
	github.com/google/uuid v1.3.0
	github.com/jmoiron/sqlx v1.3.5
	github.com/jsimonetti/pwscheme v0.0.0-20220125093853-4d9895f5db73
	github.com/lib/pq v1.10.5
	github.com/pkg/errors v0.9.1
	github.com/restream/reindexer v3.5.0+incompatible
	golang.org/x/xerrors v0.0.0-20220411194840-2f41105eb62f
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d
)

require (
	github.com/Azure/go-ntlmssp v0.0.0-20211209120228-48547f28849e // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.4 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/iancoleman/orderedmap v0.2.0 // indirect
	github.com/stretchr/testify v1.7.1 // indirect
	golang.org/x/crypto v0.0.0-20220331220935-ae2d96664a29 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)

replace github.com/cloudldap/goldap/message => ../goldap/message

replace github.com/cloudldap/ldapserver => ../ldapserver
