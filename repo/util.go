package repo

import (
	"database/sql"
	"log"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/cloudldap/cloudldap/schema"
	"github.com/lib/pq"
)

//////////////////////////////////////////
// Utilities
//////////////////////////////////////////

func isNoResult(err error) bool {
	// see https://golang.org/pkg/database/sql/#pkg-variables
	return err == sql.ErrNoRows
}

func isDuplicateKeyError(err error) bool {
	// The error code is 23505.
	// see https://www.postgresql.org/docs/13/errcodes-appendix.html
	if err, ok := err.(*pq.Error); ok {
		return err.Code == pq.ErrorCode("23505")
	}
	return false
}

func isForeignKeyError(err error) bool {
	// The error code is 23503.
	// see https://www.postgresql.org/docs/13/errcodes-appendix.html
	if err, ok := err.(*pq.Error); ok {
		return err.Code == pq.ErrorCode("23503")
	}
	return false
}

func isDeadlockError(err error) bool {
	// The error code is 40P01.
	// see https://www.postgresql.org/docs/13/errcodes-appendix.html
	if err, ok := err.(*pq.Error); ok {
		return err.Code == pq.ErrorCode("40P01")
	}
	return false
}

func debugSQL(logLevel string, query string, params map[string]interface{}) {
	if logLevel == "debug" {
		var fname, method string
		var line int
		if pc, f, l, ok := runtime.Caller(2); ok {
			fname = filepath.Base(f)
			line = l
			method = runtime.FuncForPC(pc).Name()
		}

		log.Printf(`Exec SQL at %s:%d:%s
--
%s
%v
--`, fname, line, method, query, params)
	}
}

func errorSQL(err error, query string, params map[string]interface{}) {
	if err != nil {
		var fname, method string
		var line int
		if pc, f, l, ok := runtime.Caller(2); ok {
			fname = filepath.Base(f)
			line = l
			method = runtime.FuncForPC(pc).Name()
		}
		logLevel := "error"
		if isDuplicateKeyError(err) || isForeignKeyError(err) || isNoResult(err) || isDeadlockError(err) {
			logLevel = "info"
		}
		log.Printf(`%s: Failed to execute SQL at %s:%d:%s: err: %v
--
%s
%v
--`, logLevel, fname, line, method, err, query, params)
	}
}

func findSchema(sr *schema.SchemaRegistry, attrName string) (*schema.AttributeType, bool) {
	var s *schema.AttributeType
	s, ok := sr.AttributeType(attrName)
	if !ok {
		log.Printf("Unsupported filter attribute: %s", attrName)
		return nil, false
	}
	return s, true
}

func escapeRegex(s string) string {
	return regexp.QuoteMeta(s)
}

// escape escapes meta characters used in PostgreSQL jsonpath name.
// See https://www.postgresql.org/docs/12/datatype-json.html#DATATYPE-JSONPATH
func escapeName(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `[`, `\[`)
	s = strings.ReplaceAll(s, `*`, `\*`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	// s = strings.ReplaceAll(s, `'`, `''`) // Write two adjacent single quotes
	return s
}

// escapeValue escapes meta characters used in PostgreSQL jsonpath value.
// See https://www.postgresql.org/docs/12/datatype-json.html#DATATYPE-JSONPATH
func escapeValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	// s = strings.ReplaceAll(s, `'`, `''`) // Don't neet it when using prepared statement
	return s
}

func writeFalseJsonpath(attrName string, sb *strings.Builder) {
	sb.WriteString(`$."`)
	sb.WriteString(escapeName(attrName))
	sb.WriteString(`" == false`)
}

func writeFalse(sb *strings.Builder) {
	sb.WriteString(`FALSE`)
}
