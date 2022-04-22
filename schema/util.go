package schema

import (
	"bytes"
	enchex "encoding/hex"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cloudldap/cloudldap/util"
	"github.com/google/uuid"
	"golang.org/x/xerrors"
	ber "gopkg.in/asn1-ber.v1"
)

const TIMESTAMP_FORMAT string = "20060102150405Z"
const TIMESTAMP_NANO_FORMAT string = "20060102150405.000000Z"

func hasDuplicate(s *AttributeType, arr []string) (int, bool) {
	m := make(map[string]int, len(arr))

	for i, v := range arr {
		// TODO Schema aware
		if j, ok := m[v]; ok {
			return j, true
		}
		m[v] = i
	}
	return -1, false
}

func mergeMultipleValues(s *AttributeType, vals []interface{}, jsonMap map[string]interface{}) error {
	if mv, ok := jsonMap[s.Name]; ok {
		if mvv, ok := mv.([]interface{}); ok {
			mvvMap := arrayToMap(mvv)

			for i, v := range vals {
				if _, ok := mvvMap[v]; ok {
					// Duplicate error
					return util.NewTypeOrValueExists("modify/add", s.Name, i)
				}
				mvv = append(mvv, v)
			}

			jsonMap[s.Name] = mvv
		} else {
			// Value in DB isn't array
			return fmt.Errorf("%s is not array.", s.Name)
		}
	} else {
		// New
		jsonMap[s.Name] = vals
	}
	return nil
}

func arrayToMap(arr []interface{}) map[interface{}]struct{} {
	// TODO schema aware
	m := map[interface{}]struct{}{}
	for _, v := range arr {
		m[v] = struct{}{}
	}
	return m
}

func diffDN(a, b []interface{}) ([]interface{}, []interface{}) {
	ma := make(map[string]*DN, len(a))
	for _, x := range a {
		dn, _ := x.(*DN)
		ma[dn.DNNormStr()] = dn
	}
	mb := make(map[string]*DN, len(b))
	for _, x := range b {
		dn, _ := x.(*DN)
		mb[dn.DNNormStr()] = dn
	}

	add := []interface{}{}
	del := []interface{}{}

	for k, dn := range mb {
		if _, ok := ma[k]; !ok {
			add = append(add, dn)
		}
	}
	for k, dn := range ma {
		if _, ok := mb[k]; !ok {
			del = append(del, dn)
		}
	}

	return add, del
}

// ParseDN returns a distinguishedName or an error.
// The function respects https://tools.ietf.org/html/rfc4514
// This function based on go-ldap/ldap/v3.
func ParseDN(sr *SchemaRegistry, str string) (*DN, error) {
	dn := new(DN)
	dn.RDNs = make([]*RelativeDN, 0)
	rdn := new(RelativeDN)
	rdn.Attributes = make([]*AttributeTypeAndValue, 0)
	buffer := bytes.Buffer{}
	attribute := new(AttributeTypeAndValue)
	escaping := false

	unescapedTrailingSpaces := 0
	stringTypeFromBuffer := func() string {
		s := buffer.String()
		s = s[0 : len(s)-unescapedTrailingSpaces]
		buffer.Reset()
		unescapedTrailingSpaces = 0
		return s
	}
	stringValueFromBuffer := func(t string) (string, string, error) {
		orig := stringTypeFromBuffer()

		sv, err := NewSchemaValue(sr, t, []string{orig})
		if err != nil {
			log.Printf("warn: Invalid DN syntax. dn_orig: %s err: %v", str, err)
			return "", "", util.NewInvalidDNSyntax()
		}

		return orig, sv.NormStr()[0], nil
	}

	for i := 0; i < len(str); i++ {
		char := str[i]
		switch {
		case escaping:
			unescapedTrailingSpaces = 0
			escaping = false
			switch char {
			case ' ', '"', '#', '+', ',', ';', '<', '=', '>', '\\':
				buffer.WriteByte(char)
				continue
			}
			// Not a special character, assume hex encoded octet
			if len(str) == i+1 {
				return nil, xerrors.New("got corrupted escaped character")
			}

			dst := []byte{0}
			n, err := enchex.Decode([]byte(dst), []byte(str[i:i+2]))
			if err != nil {
				return nil, fmt.Errorf("failed to decode escaped character: %s", err)
			} else if n != 1 {
				return nil, fmt.Errorf("expected 1 byte when un-escaping, got %d", n)
			}
			buffer.WriteByte(dst[0])
			i++
		case char == '\\':
			unescapedTrailingSpaces = 0
			escaping = true
		case char == '=':
			attribute.TypeOrig = stringTypeFromBuffer()
			attribute.TypeNorm = strings.ToLower(attribute.TypeOrig)
			// Special case: If the first character in the value is # the
			// following data is BER encoded so we can just fast forward
			// and decode.
			if len(str) > i+1 && str[i+1] == '#' {
				i += 2
				index := strings.IndexAny(str[i:], ",+")
				data := str
				if index > 0 {
					data = str[i : i+index]
				} else {
					data = str[i:]
				}
				rawBER, err := enchex.DecodeString(data)
				if err != nil {
					return nil, fmt.Errorf("failed to decode BER encoding: %s", err)
				}
				packet, err := ber.DecodePacketErr(rawBER)
				if err != nil {
					return nil, fmt.Errorf("failed to decode BER packet: %s", err)
				}
				buffer.WriteString(packet.Data.String())
				i += len(data) - 1
			}
		case char == ',' || char == '+':
			// We're done with this RDN or value, push it
			if len(attribute.TypeOrig) == 0 {
				return nil, errors.New("incomplete type, value pair")
			}
			orig, norm, err := stringValueFromBuffer(attribute.TypeNorm)
			if err != nil {
				return nil, xerrors.Errorf("failed to normalize dn: %w", err)
			}
			attribute.ValueOrig = orig
			attribute.ValueOrigEncoded = encodeDN(orig)
			attribute.ValueNorm = norm
			rdn.Attributes = append(rdn.Attributes, attribute)
			attribute = new(AttributeTypeAndValue)
			if char == ',' {
				dn.RDNs = append(dn.RDNs, rdn)
				rdn = new(RelativeDN)
				rdn.Attributes = make([]*AttributeTypeAndValue, 0)
			}
		case char == ' ' && buffer.Len() == 0:
			// ignore unescaped leading spaces
			continue
		default:
			if char == ' ' {
				// Track unescaped spaces in case they are trailing and we need to remove them
				unescapedTrailingSpaces++
			} else {
				// Reset if we see a non-space char
				unescapedTrailingSpaces = 0
			}
			buffer.WriteByte(char)
		}
	}
	if buffer.Len() > 0 {
		if len(attribute.TypeOrig) == 0 {
			return nil, errors.New("DN ended with incomplete type, value pair")
		}
		orig, norm, err := stringValueFromBuffer(attribute.TypeNorm)
		if err != nil {
			return nil, xerrors.Errorf("failed to normalize dn: %w", err)
		}
		attribute.ValueOrig = orig
		attribute.ValueOrigEncoded = encodeDN(orig)
		attribute.ValueNorm = norm
		rdn.Attributes = append(rdn.Attributes, attribute)
		dn.RDNs = append(dn.RDNs, rdn)
	}
	return dn, nil
}

func normalizeDistinguishedName(s *AttributeType, value string, index int) (*DN, error) {
	dn, err := NormalizeDN(s.schemaDef, value)
	if err != nil {
		return nil, util.NewInvalidPerSyntax(s.Name, index)
	}

	// Return original DN
	return dn, nil
}

func normalizeGeneralizedTime(s *AttributeType, value string, index int) (int64, error) {
	t, err := time.Parse(TIMESTAMP_FORMAT, value)
	if err != nil {
		return 0, util.NewInvalidPerSyntax(s.Name, index)
	}
	if s.IsNanoFormat() {
		return t.UnixNano(), nil
	} else {
		return t.Unix(), nil
	}
}

func normalizeBoolean(s *AttributeType, value string, index int) (string, error) {
	// The spec says Boolean = "TRUE" / "FALSE"
	// https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.3
	if value != "TRUE" && value != "FALSE" {
		return "", util.NewInvalidPerSyntax(s.Name, index)
	}
	return value, nil
}

func normalizeUUID(s *AttributeType, value string, index int) (string, error) {
	u, err := uuid.Parse(value)
	if err != nil {
		return "", util.NewInvalidPerSyntax(s.Name, index)
	}
	return u.String(), nil
}

func normalize(s *AttributeType, value string, index int) (interface{}, error) {
	switch s.Equality {
	case "caseExactMatch":
		return normalizeSpace(value), nil
	case "caseIgnoreMatch":
		return strings.ToLower(normalizeSpace(value)), nil
	case "distinguishedNameMatch":
		return normalizeDistinguishedName(s, value, index)
	case "caseExactIA5Match":
		return normalizeSpace(value), nil
	case "caseIgnoreIA5Match":
		return strings.ToLower(normalizeSpace(value)), nil
	case "generalizedTimeMatch":
		return normalizeGeneralizedTime(s, value, index)
	case "objectIdentifierMatch":
		return strings.ToLower(value), nil
	case "numericStringMatch":
		return removeAllSpace(value), nil
	case "integerMatch":
		i, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			// Invalid syntax (21)
			// additional info: pwdLockoutDuration: value #0 invalid per syntax
			return 0, util.NewInvalidPerSyntax(s.Name, index)
		}
		return i, nil
	case "booleanMatch":
		return normalizeBoolean(s, value, index)
	case "UUIDMatch":
		return normalizeUUID(s, value, index)
	case "uniqueMemberMatch":
		nv, err := normalizeDistinguishedName(s, value, index)
		if err != nil {
			// fallback
			return strings.ToLower(normalizeSpace(value)), nil
		}
		return nv, nil
	}

	switch s.Substr {
	case "caseExactSubstringsMatch":
		return normalizeSpace(value), nil
	case "caseIgnoreSubstringsMatch":
		return strings.ToLower(normalizeSpace(value)), nil
	case "caseExactIA5SubstringsMatch":
		return normalizeSpace(value), nil
	case "caseIgnoreIA5SubstringsMatch":
		return strings.ToLower(normalizeSpace(value)), nil
	}

	return value, nil
}

var SPACE_PATTERN = regexp.MustCompile(`\s+`)

func normalizeSpace(value string) string {
	str := SPACE_PATTERN.ReplaceAllString(value, " ")
	str = strings.Trim(str, " ")
	return str
}

func removeAllSpace(value string) string {
	str := SPACE_PATTERN.ReplaceAllString(value, "")
	return str
}
