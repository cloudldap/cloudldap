package schema

import (
	"strings"
)

const DNCacheContextKey = "dn"

type DNCache struct {
	Itoa  map[int64]*DN
	Itoao map[int64]string // id => dnOrig
	Atoi  map[string]int64
}

func NewDnCache() *DNCache {
	return &DNCache{
		Itoa:  make(map[int64]*DN),
		Itoao: make(map[int64]string),
		Atoi:  make(map[string]int64),
	}
}

type DN struct {
	RDNs     []*RelativeDN
	RDNIndex map[string]NormString
}

type NormString struct {
	Orig string
	Norm string
}

type RelativeDN struct {
	Attributes []*AttributeTypeAndValue
}

func (r *RelativeDN) OrigEncodedStr() string {
	var b strings.Builder
	b.Grow(128)
	for i, attr := range r.Attributes {
		if i > 0 {
			b.WriteString("+")
		}
		b.WriteString(attr.TypeOrig)
		b.WriteString("=")
		b.WriteString(attr.ValueOrigEncoded)
	}
	return b.String()
}

// encodeDN encodes special characters for response DN in search.
// Special characters: "+,;<>\#<space>
// See: https://www.ipa.go.jp/security/rfc/RFC4514EN.html
func encodeDN(str string) string {
	var b strings.Builder
	b.Grow(len(str) + 10)

	last := len(str) - 1

	for i := 0; i < len(str); i++ {
		char := str[i]

		switch {
		case i == 0 && char == ' ':
			b.WriteString("\\20")
		case i == last && char == ' ':
			b.WriteString("\\20")
		case char == '"':
			b.WriteString("\\22")
		case i == 0 && char == '#':
			b.WriteString("\\23")
		case char == '+':
			b.WriteString("\\2B")
		case char == ',':
			b.WriteString("\\2C")
		case char == ';':
			b.WriteString("\\3B")
		case char == '<':
			b.WriteString("\\3C")
		case char == '=':
			b.WriteString("\\3D")
		case char == '>':
			b.WriteString("\\3E")
		case char == '\\':
			b.WriteString("\\5C")
		default:
			b.WriteByte(char)
		}
	}
	return b.String()
}

func (r *RelativeDN) NormStr() string {
	var b strings.Builder
	b.Grow(128)
	for i, attr := range r.Attributes {
		if i > 0 {
			b.WriteString("+")
		}
		b.WriteString(attr.TypeNorm)
		b.WriteString("=")
		b.WriteString(attr.ValueNorm)
	}
	return b.String()
}

type AttributeTypeAndValue struct {
	// TypeOrig is the original attribute type
	TypeOrig string
	// TypeNorm is the normalized attribute type
	TypeNorm string
	// Value is the original attribute value
	ValueOrig string
	// Value is the encoded original attribute value
	ValueOrigEncoded string
	// Value is the normalized attribute value
	ValueNorm string
}

var anonymousDN = &DN{
	RDNs: nil,
}

func NormalizeDN(sr *SchemaRegistry, dn string) (*DN, error) {
	// Anonymous
	if dn == "" {
		return anonymousDN, nil
	}

	return ParseDN(sr, dn)
}

func (d *DN) DNNormStr() string {
	var b strings.Builder
	b.Grow(256)
	for i, rdn := range d.RDNs {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(rdn.NormStr())
	}
	return b.String()
}

func (d *DN) DNNormStrWithoutSuffix(suffix *DN) string {
	sRDNs := suffix.RDNs
	diff := len(d.RDNs) - len(sRDNs)

	var b strings.Builder
	b.Grow(256)
	for i, rdn := range d.RDNs {
		if i >= diff {
			break
		}
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(rdn.NormStr())
	}
	return b.String()
}

func (d *DN) DNOrigStr() string {
	var b strings.Builder
	b.Grow(256)
	for i, rdn := range d.RDNs {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(rdn.OrigEncodedStr())
	}
	return b.String()
}

func (d *DN) DNOrigEncodedStrWithoutSuffix(suffix *DN) string {
	sRDNs := suffix.RDNs
	diff := len(d.RDNs) - len(sRDNs)

	var b strings.Builder
	b.Grow(256)
	for i, rdn := range d.RDNs {
		if i >= diff {
			break
		}
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(rdn.OrigEncodedStr())
	}
	return b.String()
}

func (d *DN) RDNNormStr() string {
	var b strings.Builder
	b.Grow(128)
	for i, attr := range d.RDNs[0].Attributes {
		if i > 0 {
			b.WriteString("+")
		}
		b.WriteString(attr.TypeNorm)
		b.WriteString("=")
		b.WriteString(attr.ValueNorm)
	}
	return b.String()
}

func (d *DN) RDNOrigEncodedStr() string {
	var b strings.Builder
	b.Grow(128)
	for i, attr := range d.RDNs[0].Attributes {
		if i > 0 {
			b.WriteString("+")
		}
		b.WriteString(attr.TypeOrig)
		b.WriteString("=")
		b.WriteString(attr.ValueOrigEncoded)
	}
	return b.String()
}

func (d *DN) Equal(o *DN) bool {
	if d == nil {
		return o == nil
	}
	return len(d.RDNs) == len(o.RDNs) && d.DNNormStr() == o.DNNormStr()
}

// IsSubOf checks whether the arg DN is subset of self.
// Example:
//   self DN: ou=people,dc=exaple,dc=com
//   arg DN: dc=example,dc=com
// => true
func (d *DN) IsSubOf(o *DN) bool {
	if d == nil {
		return false
	}
	return len(d.RDNs) > len(o.RDNs) && strings.HasSuffix(d.DNNormStr(), o.DNNormStr())
}

func (d *DN) RDN() map[string]NormString {
	if len(d.RDNIndex) > 0 {
		return d.RDNIndex
	}

	// Check DC case
	if len(d.RDNs) == 0 {
		return map[string]NormString{}
	}

	m := make(map[string]NormString, len(d.RDNs[0].Attributes))

	for _, a := range d.RDNs[0].Attributes {
		m[a.TypeNorm] = NormString{
			Orig: a.ValueOrig,
			Norm: a.ValueNorm,
		}
	}

	d.RDNIndex = m

	return m
}

func (d *DN) ModifyRDN(sr *SchemaRegistry, newRDN string, deleteOld bool) (*DN, *RelativeDN, bool, error) {
	newDN, err := ParseDN(sr, newRDN)
	if err != nil {
		return nil, nil, false, err
	}

	// Clone and apply the change
	newRDNs := make([]*RelativeDN, len(d.RDNs))
	var oldRDN *RelativeDN
	hasChange := false
	for i, v := range d.RDNs {
		if i == 0 {
			if v.NormStr() != newDN.RDNNormStr() {
				hasChange = true
				if !deleteOld {
					oldRDN = v
				}
			}
			newRDNs[i] = newDN.RDNs[0]
		} else {
			newRDNs[i] = v
		}
	}

	return &DN{
		RDNs: newRDNs,
	}, oldRDN, hasChange, nil
}

func (d *DN) Move(newParentDN *DN) (*DN, error) {
	leaf := d.RDNs[0]

	// Clone and apply the change
	newRDNs := make([]*RelativeDN, len(newParentDN.RDNs)+1)
	newRDNs[0] = leaf
	for i, v := range newParentDN.RDNs {
		newRDNs[i+1] = v
	}

	return &DN{
		RDNs: newRDNs,
	}, nil
}

func (d *DN) ParentDN() *DN {
	if d.IsRoot() {
		return nil
	}

	return &DN{
		RDNs: d.RDNs[1:],
	}
}

func (d *DN) IsRoot() bool {
	return len(d.RDNs) == 1
}

func (d *DN) IsSuffix(suffix *DN) bool {
	return d.Equal(suffix)
}

func (d *DN) IsDC() bool {
	for _, attr := range d.RDNs[0].Attributes {
		if attr.TypeNorm == "dc" {
			return true
		}
	}
	return false
}

func (d *DN) IsAnonymous() bool {
	return len(d.RDNs) == 0
}

func (d *DN) Level() int {
	return len(d.RDNs)
}

func (d *DN) LevelWithoutSuffix(suffix *DN) int {
	sRDNs := suffix.RDNs
	return len(d.RDNs) - len(sRDNs)
}
