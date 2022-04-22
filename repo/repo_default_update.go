package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/cloudldap/cloudldap/schema"
	"github.com/cloudldap/cloudldap/util"
	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"github.com/restream/reindexer"
)

// Update modifies the entry by specified change data.
// This is used for MOD operation.
func (r *DefaultRepository) Update(ctx context.Context, dn *schema.DN, callback func(attrsOrig AttrsOrig) (*Changelog, error)) error {
	reportError := func(err error) error {
		return errors.Wrapf(err, "dn_norm: %s", dn.DNNormStr())
	}

	var m *NotifyMessage

	err := r.withTx(ctx, func(cacheTx *reindexer.Tx, dbTx *sqlx.Tx) error {
		id, err := r.findEntryIDWithTx(ctx, cacheTx, dn)
		if err != nil {
			return reportError(err)
		}

		var dest DBEntry
		err = r.get(dbTx, lockEntryByIDForUpdate, &dest, map[string]interface{}{
			"id": id,
		})
		if err != nil {
			return reportError(err)
		}

		attrsOrigMap := make(AttrsOrig)
		if err := dest.AttrsOrig.Unmarshal(&attrsOrigMap); err != nil {
			return reportError(err)
		}

		changelog, err := callback(attrsOrigMap)
		if err != nil {
			return reportError(err)
		}

		m, err = r.internalUpdate(ctx, dbTx, id, dest.Version, changelog)
		if err != nil {
			return reportError(err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Handle own notify message now
	if err := r.OnUpdate(ctx, m); err != nil {
		return errors.Wrapf(err, "Failed to update cache DB for modifed entry. id: %d, dn_norm: %s", m.ID, dn.DNNormStr())
	}

	log.Printf("info: Modified. dn_norm: %s", dn.DNNormStr())

	return nil
}

func strToJSONText(s string) (types.JSONText, error) {
	return strArrayToJSONText([]string{s})
}

func strArrayToJSONText(s []string) (types.JSONText, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, errors.Wrap(err, "Unexpected json marshal error")
	}
	return types.JSONText(b), nil
}

func (r *DefaultRepository) internalUpdate(ctx context.Context, dbTx *sqlx.Tx, id, rev int64, changelog *Changelog) (*NotifyMessage, error) {
	reportError := func(err error) (*NotifyMessage, error) {
		return nil, errors.Wrapf(err, "dn_norm: %s", changelog.DNNorm())
	}

	mn, err := strToJSONText(changelog.Requester().DNOrigEncodedStrWithoutSuffix(r.schemaRegistry.SuffixDN))
	if err != nil {
		return reportError(err)
	}
	mt, err := strToJSONText(changelog.Timestamp())
	if err != nil {
		return reportError(err)
	}

	params := map[string]interface{}{
		"id":               id,
		"rev":              rev,
		"modifiers_name":   mn,
		"modify_timestamp": mt,
	}
	var obj []string

	if true {
		// Apply patch mode
		ops := changelog.ToDiff()

		obj = make([]string, len(ops))
		i := 0
		for k, v := range ops {
			key := `k` + strconv.Itoa(i)
			if v.IsReplace() {
				obj[i] = `'` + k + `', (:` + key + `)::::jsonb`
				jt, err := strArrayToJSONText(v.Replace)
				if err != nil {
					return reportError(err)
				}
				params[key] = jt

			} else if v.IsAdd() && !v.IsDelete() {
				obj[i] = `'` + k + `', COALESCE((attrs_orig->'` + k + `')::::jsonb, '[]'::::jsonb) || (:` + key + `)::::jsonb`
				jt, err := strArrayToJSONText(v.Add)
				if err != nil {
					return reportError(err)
				}
				params[key] = jt

			} else if !v.IsAdd() && v.IsDelete() {
				obj[i] = `'` + k + `', COALESCE((attrs_orig->'` + k + `')::::jsonb, '[]'::::jsonb) - (:` + key + `)::::text[]`
				params[key] = pq.StringArray(v.Delete)

			} else if v.IsAdd() && v.IsDelete() {
				addKey := "a" + key
				delKey := "d" + key
				obj[i] = `'` + k + `', (COALESCE((attrs_orig->'` + k + `')::::jsonb, '[]'::::jsonb) || (:` + addKey + `)::::jsonb) - (:` + delKey + `)::::text[]`
				jt, err := strArrayToJSONText(v.Add)
				if err != nil {
					return reportError(err)
				}
				params[addKey] = jt
				params[delKey] = pq.StringArray(v.Delete)

			} else if v.IsClear() {
				obj[i] = `'` + k + `', '[]'::::jsonb`
			}
			i++
		}
	} else {
		// Full replace mode
		attrsOrig := changelog.ToAttrsOrig()

		obj = make([]string, len(attrsOrig))
		i := 0
		for k, v := range attrsOrig {
			key := `k` + strconv.Itoa(i)
			obj[i] = `'` + k + `', (:` + key + `)::::text[]`
			params[key] = pq.StringArray(v)
			i++
		}
	}

	// No modification
	if len(obj) == 0 {
		return nil, nil
	}

	q := fmt.Sprintf(`

UPDATE
	entry
SET
	attrs_orig = attrs_orig::::jsonb || JSONB_BUILD_OBJECT(
		'modifiersName', (:modifiers_name)::::jsonb,
		'modifyTimestamp', (:modify_timestamp)::::jsonb,
		%s
	),
	rev = rev + 1
WHERE
	id = :id
	AND rev = :rev;
`, strings.Join(obj, ","))

	result, err := dbTx.NamedExecContext(ctx, q, params)
	if err != nil {
		return reportError(err)
	}

	updated, err := result.RowsAffected()
	if err != nil {
		return reportError(err)
	}

	if updated != 1 {
		return reportError(errors.New("Unexpected update result"))
	}

	// Association
	associationChanged := false
	add, del := changelog.ToMemberOfDiff()
	if len(add) > 0 || len(del) > 0 {
		associationChanged = true

		if err := r.addMemberOf(ctx, dbTx, add, id); err != nil {
			return reportError(err)
		}
		if err := r.deleteMemberOf(ctx, dbTx, del, id); err != nil {
			return reportError(err)
		}
	}

	// Notify
	m := &NotifyMessage{
		Issuer:      r.config.ServerID,
		ID:          id,
		Op:          NotifyMod,
		Rev:         rev + 1,
		Association: associationChanged,
	}
	err = r.notify(dbTx, m)
	if err != nil {
		return reportError(err)
	}

	return m, nil
}

// Association resolves the association related attributes in the attributes.
// This is used for MOD operation.
func (r *DefaultRepository) Association(ctx context.Context, sv *schema.SchemaValue) (*schema.SchemaValue, error) {
	ids, err, errIndex := r.dnStrArrayToIDStrArray(ctx, sv.Orig())
	if err != nil {
		if util.IsNoSuchObjectError(err) {
			return nil, util.NewInvalidPerSyntax(sv.Name(), errIndex)
		}
		return nil, errors.Wrapf(err, "Failed to resolve association. dn: %v", sv.Orig())
	}
	return schema.NewSchemaValue(r.schemaRegistry, sv.Name(), ids)
}
