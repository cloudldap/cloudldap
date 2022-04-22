package repo

import (
	"context"
	"log"
	"strings"

	"github.com/cloudldap/cloudldap/schema"
	"github.com/cloudldap/goldap/message"
	"github.com/restream/reindexer"
)

type FilterTranslator struct {
	tx *reindexer.Tx
	r  *DefaultRepository
}

func (t *FilterTranslator) translate(ctx context.Context, sr *schema.SchemaRegistry, packet message.Filter, q *reindexer.Query) (err error) {
	err = nil

	switch f := packet.(type) {
	case message.FilterAnd:
		q.OpenBracket()
		for _, child := range f {
			err = t.translate(ctx, sr, child, q)

			if err != nil {
				return
			}
			// Default is "AND"
		}
		q.CloseBracket()

	case message.FilterOr:
		q.OpenBracket()
		for i, child := range f {
			err = t.translate(ctx, sr, child, q)

			if err != nil {
				return
			}
			if i < len(f)-1 {
				q.Or()
			}
		}
		q.CloseBracket()

	case message.FilterNot:
		q.OpenBracket()
		q.Not()

		err = t.translate(ctx, sr, f.Filter, q)

		if err != nil {
			return
		}
		q.CloseBracket()

	case message.FilterSubstrings:
		q.OpenBracket()
		attrName := string(f.Type_())

		s, ok := sr.AttributeType(attrName)
		if !ok {
			// TODO check
			q.Where("dummy", reindexer.EQ, "dummy")
			return
		}

		var sb strings.Builder
		sb.Grow(64)

		for i, fs := range f.Substrings() {
			switch fsv := fs.(type) {
			case message.SubstringInitial:
				t.StartsWithMatch(s, q, string(fsv), i)
			case message.SubstringAny:
				if i > 0 {
					sb.WriteString(" && ")
				}
				t.AnyMatch(s, q, string(fsv), i)
			case message.SubstringFinal:
				t.EndsMatch(s, q, string(fsv), i)
			}
		}

		q.CloseBracket()

	case message.FilterEqualityMatch:
		q.OpenBracket()
		if s, ok := findSchema(sr, string(f.AttributeDesc())); ok {
			t.EqualityMatch(ctx, s, q, string(f.AssertionValue()))
		} else {
			// TODO check
			q.Where("dummy", reindexer.EQ, "dummy")
		}
		q.CloseBracket()

	case message.FilterGreaterOrEqual:
		q.OpenBracket()
		if s, ok := findSchema(sr, string(f.AttributeDesc())); ok {
			t.GreaterOrEqualMatch(ctx, s, q, string(f.AssertionValue()))
		} else {
			// TODO check
			q.Where("dummy", reindexer.EQ, "dummy")
		}
		q.CloseBracket()

	case message.FilterLessOrEqual:
		q.OpenBracket()
		if s, ok := findSchema(sr, string(f.AttributeDesc())); ok {
			t.LessOrEqualMatch(ctx, s, q, string(f.AssertionValue()))
		} else {
			// TODO check
			q.Where("dummy", reindexer.EQ, "dummy")
		}
		q.CloseBracket()

	case message.FilterPresent:
		q.OpenBracket()
		if s, ok := findSchema(sr, string(f)); ok {
			t.PresentMatch(ctx, s, q)
		} else {
			// TODO check
			q.Where("dummy", reindexer.EQ, string(f))
		}
		q.CloseBracket()

	case message.FilterApproxMatch:
		q.OpenBracket()
		if s, ok := findSchema(sr, string(f.AttributeDesc())); ok {
			t.ApproxMatch(ctx, s, q, string(f.AssertionValue()))
		} else {
			// TODO check
			q.Where("dummy", reindexer.EQ, "dummy")
		}
		q.CloseBracket()
	}

	return nil
}

func (t *FilterTranslator) StartsWithMatch(s *schema.AttributeType, q *reindexer.Query, val string, i int) {
	sv, err := schema.NewSchemaValue(s.Schema(), s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	if s.IsAssociationAttribute() || s.IsReverseAssociationAttribute() {
		log.Printf("Filter for association doesn't support substring initial")
		q.Where("dummy", reindexer.EQ, "dummy")
		return
	}

	// TODO check escape
	q.Where(t.Name(s), reindexer.LIKE, string(sv.NormStr()[0])+"%")
}

func (t *FilterTranslator) AnyMatch(s *schema.AttributeType, q *reindexer.Query, val string, i int) {
	sv, err := schema.NewSchemaValue(s.Schema(), s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	if s.IsAssociationAttribute() || s.IsReverseAssociationAttribute() {
		log.Printf("Filter for association doesn't support substring any")
		q.Where("dummy", reindexer.EQ, "dummy")
		return
	}

	// TODO check escape
	q.Where(t.Name(s), reindexer.LIKE, "%"+string(sv.NormStr()[0]))
}

func (t *FilterTranslator) EndsMatch(s *schema.AttributeType, q *reindexer.Query, val string, i int) {
	sv, err := schema.NewSchemaValue(s.Schema(), s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	if s.IsAssociationAttribute() || s.IsReverseAssociationAttribute() {
		log.Printf("Filter for association doesn't support substring final")
		q.Where("dummy", reindexer.EQ, "dummy")
		return
	}

	// TODO check escape
	q.Where(t.Name(s), reindexer.LIKE, "%"+string(sv.NormStr()[0])+"%")
}

func (t *FilterTranslator) EqualityMatch(ctx context.Context, s *schema.AttributeType, q *reindexer.Query, val string) {
	sv, err := schema.NewSchemaValue(s.Schema(), s.Name, []string{val})
	if err != nil {
		// TODO error no entry response
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s, err: %+v", s.Name, val, err)
		q.Where("dummy", reindexer.EQ, "dummy")
		return
	}

	if s.IsAssociationAttribute() || s.IsReverseAssociationAttribute() {
		reqDN, err := s.Schema().NormalizeDN(val)
		if err != nil {
			log.Printf("warn: Ignore filter due to invalid DN syntax of association. attrName: %s, value: %s, err: %+v", s.Name, val, err)
			q.Where("dummy", reindexer.EQ, "dummy")
			return
		}
		id, err := t.r.findEntryID(ctx, reqDN)
		if err != nil {
			// Not found case
			q.Where("dummy", reindexer.EQ, "dummy")
			return
		}
		q.WhereInt64(t.Name(s), reindexer.EQ, id)

	} else if s.IsObjectClass() {
		q.Where(t.Name(s), reindexer.ALLSET, sv.NormStr())
	} else {
		q.Where(t.Name(s), reindexer.EQ, sv.NormStr())
	}
}

func (t *FilterTranslator) GreaterOrEqualMatch(ctx context.Context, s *schema.AttributeType, q *reindexer.Query, val string) {
	sv, err := schema.NewSchemaValue(s.Schema(), s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	if s.IsAssociationAttribute() || s.IsReverseAssociationAttribute() {
		log.Printf("Filter for association doesn't support greater or equal")
		q.Where("dummy", reindexer.EQ, "dummy")
		return
	}
	if !s.IsNumberOrdering() {
		log.Printf("Not number ordering doesn't support reater or equal")
		q.Where("dummy", reindexer.EQ, "dummy")
		return
	}

	q.Where(t.Name(s), reindexer.GE, sv.Norm()[0])
}

func (t *FilterTranslator) LessOrEqualMatch(ctx context.Context, s *schema.AttributeType, q *reindexer.Query, val string) {
	sv, err := schema.NewSchemaValue(s.Schema(), s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	if s.IsAssociationAttribute() || s.IsReverseAssociationAttribute() {
		log.Printf("Filter for association doesn't support less or equal")
		q.Where("dummy", reindexer.EQ, "dummy")
		return
	}
	if !s.IsNumberOrdering() {
		log.Printf("Not number ordering doesn't support less or equal")
		q.Where("dummy", reindexer.EQ, "dummy")
		return
	}

	q.Where(t.Name(s), reindexer.LE, sv.Norm()[0])
}

func (t *FilterTranslator) PresentMatch(ctx context.Context, s *schema.AttributeType, q *reindexer.Query) {
	q.Not()
	q.Where(t.Name(s), reindexer.EMPTY, 0)
}

func (t *FilterTranslator) ApproxMatch(ctx context.Context, s *schema.AttributeType, q *reindexer.Query, val string) {
	sv, err := schema.NewSchemaValue(s.Schema(), s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	if s.IsAssociationAttribute() || s.IsReverseAssociationAttribute() {
		log.Printf("Filter for association doesn't support approx match")
		q.Where("dummy", reindexer.EQ, "dummy")
		return
	}

	q.Where(t.Name(s), reindexer.LIKE, "%"+sv.NormStr()[0]+"%")
}

func (t *FilterTranslator) Name(s *schema.AttributeType) string {
	return "attrsNorm." + s.Name
}
