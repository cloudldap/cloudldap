package repo

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/cloudldap/cloudldap/schema"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"github.com/restream/reindexer"
)

// UpdateRDN modifies the entry RDN by specified change data.
// This is used for MODRDN operation.
func (r *DefaultRepository) UpdateDN(ctx context.Context, oldDN, newDN *schema.DN, oldRDN *schema.RelativeDN,
	callback func(attrsOrig AttrsOrig) (*Changelog, error)) error {
	reportError := func(err error) error {
		return errors.Wrapf(err, "old_dn_norm: %s, new_dn_norm: %s", oldDN.DNNormStr(), newDN.DNNormStr())
	}

	var m *NotifyMessage

	err := r.withTx(ctx, func(cacheTx *reindexer.Tx, dbTx *sqlx.Tx) error {
		id, err := r.findEntryIDWithTx(ctx, cacheTx, oldDN)
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

		m, err = r.internalUpdateDN(ctx, dbTx, id, dest.Version, changelog)
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
		return reportError(err)
	}

	log.Printf("info: Modified. old_dn_norm: %s, new_dn_norm: %s", oldDN.DNNormStr(), newDN.DNNormStr())

	return nil
}

func (r *DefaultRepository) internalUpdateDN(ctx context.Context, dbTx *sqlx.Tx, id, rev int64, changelog *Changelog) (*NotifyMessage, error) {
	reportError := func(err error) (*NotifyMessage, error) {
		return nil, errors.Wrapf(err, "old_dn_norm: %s, new_dn_norm: %s", changelog.DN().DNNormStr(), changelog.NewDN().DNNormStr())
	}

	move := !changelog.DN().ParentDN().Equal(changelog.NewDN().ParentDN())

	dependant := []int64{}
	updateSubTree := false

	if move {
		type dbEntry struct {
			ID          int64         `db:"id"`
			Rev         int64         `db:"rev"`
			Path        pq.Int64Array `db:"path"`
			IsContainer bool          `db:"is_container"`
		}
		type dbNewParentEntry struct {
			dbEntry
			ParentPath pq.Int64Array `db:"parent_path"`
		}
		oldSubTree := []dbEntry{}
		var oldParent dbEntry
		entry := dbEntry{
			ID:          id,
			Rev:         rev,
			Path:        nil,
			IsContainer: false,
		}
		var newParent dbNewParentEntry

		// Step 1: Find the old parent ID from cached DB
		oldPID, err := r.findEntryID(ctx, changelog.DN().ParentDN())
		if err != nil {
			return reportError(err)
		}

		// Step 2: Lock the old parent entry and the sub containers with update lock mode
		rows, err := r.stmtQuery(ctx, dbTx, lockTreeByIDForMove, map[string]interface{}{
			"id":   oldPID,
			"path": pq.Array([]int64{id}),
		})
		if err != nil {
			return reportError(err)
		}
		for rows.Next() {
			var op dbEntry
			if err := rows.StructScan(&op); err != nil {
				return reportError(err)
			}
			if op.ID == oldPID {
				oldParent = op
			} else if op.ID == id {
				entry = op
			} else {
				oldSubTree = append(oldSubTree, op)
			}
		}

		// Step 3: Find the new parent ID from cached DB
		newPID, err := r.findEntryID(ctx, changelog.NewDN().ParentDN())
		if err != nil {
			return reportError(err)
		}

		// Step 4: Lock the new parent entry with update lock mode
		err = r.get(dbTx, lockEntryByIDForMove, &newParent, map[string]interface{}{
			"id": newPID,
		})
		if err != nil {
			return reportError(err)
		}

		// Step 5: Update path of the sub containers in the oldSubtree
		if len(oldSubTree) > 0 {
			var upsert []string
			for _, v := range oldSubTree {
				upsert = append(upsert, fmt.Sprintf(`(%d, %d, :path%d)`, v.ID, v.Rev, v.ID))
				fromIndex := 0
				for i, v := range v.Path {
					if v == entry.ID {
						fromIndex = i
						break
					}
				}

				newChildPath := append(newParent.Path, v.Path[fromIndex:]...)

				updated, err := r.execAffected(dbTx, updatePath, map[string]interface{}{
					"id":       v.ID,
					"rev":      v.Rev,
					"new_path": newChildPath,
				})
				if err != nil {
					return reportError(err)
				}
				if updated != int64(len(oldSubTree)) {
					return reportError(err)
				}
			}
			updateSubTree = true
		}

		// Step 6: Update new parent if no children before moving
		if !newParent.IsContainer {
			// No children, update parent now
			updated, err := r.execAffected(dbTx, updateContainer, map[string]interface{}{
				"id":           newParent.ID,
				"rev":          newParent.Rev,
				"path":         pq.Array(append(newParent.ParentPath, newParent.ID)),
				"is_container": true,
			})
			if err != nil {
				return reportError(err)
			}
			if updated != 1 {
				return reportError(err)
			}
			dependant = append(dependant, newParent.ID)
		}

		// Step 7: Now Moving. Update entry with new parent ID, also update path if it's container
		var updated int64
		if entry.IsContainer {
			updated, err = r.execAffected(dbTx, updateParentWithPath, map[string]interface{}{
				"id":            entry.ID,
				"rev":           entry.Rev,
				"new_parent_id": newParent.ID,
				"new_path":      pq.Array(append(newParent.ParentPath, newParent.ID, entry.ID)),
			})
		} else {
			updated, err = r.execAffected(dbTx, updateParent, map[string]interface{}{
				"id":            entry.ID,
				"rev":           entry.Rev,
				"new_parent_id": newParent.ID,
			})
		}
		if err != nil {
			return reportError(err)
		}
		if updated != 1 {
			return reportError(err)
		}

		// Step 8: Update old parent if no children after moving
		var dbChildEntry struct {
			ID  int64 `db:"id"`
			Rev int64 `db:"rev"`
		}
		err = r.get(dbTx, findChildByParentID, &dbChildEntry, map[string]interface{}{
			"parent_id": oldParent.ID,
		})
		if err != nil {
			if err != sql.ErrNoRows {
				return reportError(err)
			}
			// No children, update parent now
			updated, err := r.execAffected(dbTx, updateContainer, map[string]interface{}{
				"id":           oldParent.ID,
				"rev":          oldParent.Rev,
				"path":         nil,
				"is_container": false,
			})
			if err != nil {
				return reportError(err)
			}
			if updated != 1 {
				return reportError(err)
			}
			dependant = append(dependant, oldParent.ID)
		}
	}

	// Step 9: Update entry
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
		"rdn_norm":         changelog.NewDN().RDNNormStr(),
		"rdn_orig":         changelog.NewDN().RDNOrigEncodedStr(),
	}
	var obj []string

	// Apply patch
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

	objStr := ""
	if len(obj) > 0 {
		objStr = strings.Join(obj, ",") + ","
	}
	q := fmt.Sprintf(`
UPDATE
	entry
SET
	rdn_norm = :rdn_norm,
	rdn_orig = :rdn_orig,
	attrs_orig = attrs_orig::::jsonb || JSONB_BUILD_OBJECT(
		%s
		'modifiersName', (:modifiers_name)::::jsonb,
		'modifyTimestamp', (:modify_timestamp)::::jsonb
	),
	rev = rev + 1
WHERE
	id = :id
	AND rev = :rev;
`, objStr)

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

	// Notify
	m := &NotifyMessage{
		Issuer:      r.config.ServerID,
		ID:          id,
		Op:          NotifyMod,
		Rev:         rev + 1,
		Association: false,
		Dependant:   dependant,
		Sub:         updateSubTree,
	}
	err = r.notify(dbTx, m)
	if err != nil {
		return reportError(err)
	}

	return m, nil
}
