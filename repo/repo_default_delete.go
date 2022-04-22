package repo

import (
	"context"
	"database/sql"
	"log"

	"github.com/cloudldap/cloudldap/schema"
	"github.com/cloudldap/cloudldap/util"
	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"golang.org/x/xerrors"
)

// DeleteByDN deletes the entry by specified DN.
func (r *DefaultRepository) DeleteByDN(ctx context.Context, dn *schema.DN) error {
	var m *NotifyMessage

	// Insert DB
	err := withDBTx(ctx, r.db, func(tx *sqlx.Tx) error {
		var err error
		m, err = r.deleteInternal(ctx, tx, dn)
		return err
	})
	if err != nil {
		return err
	}

	// Handle own notify message now
	if err := r.OnUpdate(ctx, m); err != nil {
		return errors.Wrapf(err, "Failed to update cache DB for delete entry. id: %d, dn_norm: %s", m.ID, dn.DNNormStr())
	}

	log.Printf("info: Deleted. id: %d, dn_norm: %s", m.ID, dn.DNNormStr())

	return nil
}

func (r *DefaultRepository) deleteInternal(ctx context.Context, dbTx *sqlx.Tx, dn *schema.DN) (*NotifyMessage, error) {
	reportError := func(err error) (*NotifyMessage, error) {
		return nil, errors.Wrapf(err, "dn_norm: %s", dn.DNNormStr())
	}

	// Step 1: Find the entry path from cached DB
	path, err := r.findEntryPath(ctx, dn)
	if err != nil {
		return reportError(err)
	}

	isRoot := len(path) == 1

	var id int64
	if isRoot {
		id = path[0]
	} else {
		id = path[len(path)-1]
	}

	// Step 2: Lock the parent entry from DB
	var dbParentEntry struct {
		ID  int64 `db:"id"`
		Rev int64 `db:"rev"`
	}
	if !isRoot {
		err = r.get(dbTx, lockEntryByIDForDelete, &dbParentEntry, map[string]interface{}{
			"id": path[len(path)-2],
		})
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, util.NewNoSuchObject()
			}
			return reportError(err)
		}
	}

	// Step 3: Fetch the entry from DB
	var dbEntry struct {
		ID          int64          `db:"id"`
		Version     int64          `db:"rev"`
		Rev         int64          `db:"parent_id"`
		Path        pq.Int64Array  `db:"path"`
		IsContainer bool           `db:"is_container"`
		RDNNorm     string         `db:"rdn_norm"`
		RDNOrig     string         `db:"rdn_orig"`
		AttrsOrig   types.JSONText `db:"attrs_orig"`
	}
	err = r.get(dbTx, findEntryByID, &dbEntry, map[string]interface{}{
		"id": id,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, util.NewNoSuchObject()
		}
		return reportError(err)
	}

	// Step 4: Delete the entry from DB
	deleted, err := r.execAffected(dbTx, deleteByIDEntry, map[string]interface{}{
		"id": id,
	})
	if err != nil {
		// Not allowed error if the entry has children yet
		if isForeignKeyError(err) {
			return nil, util.NewNotAllowedOnNonLeaf()
		}
		return reportError(err)
	}

	if deleted != 1 {
		return nil, util.NewNoSuchObject()
	}

	// Step 5: Delete association
	// Update association if the deleted entry has association
	attrsOrigMap := map[string][]string{}

	if err := dbEntry.AttrsOrig.Unmarshal(&attrsOrigMap); err != nil {
		return reportError(err)
	}

	// Delete memberOf of the target entries
	mids := util.NewSetString()
	for _, v := range attrsOrigMap["member"] {
		mids.Add(v)
	}
	for _, v := range attrsOrigMap["uniqueMember"] {
		mids.Add(v)
	}
	if err := r.deleteMemberOf(ctx, dbTx, mids.List(), id); err != nil {
		return reportError(err)
	}

	// Delete member/uniqueMember of the target entries
	memids := attrsOrigMap["memberOf"]
	if len(memids) > 0 {

		q, args, err := sqlx.Named(`
UPDATE entry
SET
	attrs_orig = JSONB_SET(
		JSONB_SET(attrs_orig, ARRAY['member'], COALESCE((attrs_orig->'member')::::jsonb, '[]'::::jsonb) - :(member_of_id)::::text),
		ARRAY['uniqueMember'], COALESCE((attrs_orig->'uniqueMember')::::jsonb, '[]'::::jsonb) - :(member_of_id)::::text
	),
	rev = rev + 1
WHERE id IN (:id)
		`, map[string]interface{}{
			"member_of_id": id,
			"id":           memids,
		})
		if err != nil {
			return reportError(err)
		}

		q, args, err = sqlx.In(q, args...)
		if err != nil {
			return reportError(err)
		}

		q = dbTx.Rebind(q)

		result, err := dbTx.Exec(q, args...)
		if err != nil {
			return reportError(err)
		}
		updated, err := result.RowsAffected()
		if err != nil {
			return reportError(err)
		}

		if updated != int64(len(memids)) {
			log.Printf("warn: Detected inconsistency while removing member. dn_norm: %s", dn.DNNormStr())
			return nil, util.NewRetryError(err)
		}
	}

	// Step 6: Update parent if no children
	dep := []int64{}
	if !isRoot {
		var dbChildEntry struct {
			ID  int64 `db:"id"`
			Rev int64 `db:"rev"`
		}
		err := r.get(dbTx, findChildByParentID, &dbChildEntry, map[string]interface{}{
			"parent_id": dbParentEntry.ID,
		})
		if err != nil {
			if err != sql.ErrNoRows {
				return reportError(err)
			}
			// No children, update parent now
			updated, err := r.execAffected(dbTx, updateContainer, map[string]interface{}{
				"id":           dbParentEntry.ID,
				"rev":          dbParentEntry.Rev,
				"path":         nil,
				"is_container": false,
			})
			if err != nil {
				return reportError(err)
			}
			if updated != 1 {
				log.Printf("warn: Detected inconsistency while updating parent as container. parent: %v", dbParentEntry)
				return nil, util.NewRetryError(xerrors.Errorf("Detected inconsistency while updating parent as container. parent: %v", dbParentEntry))
			}
			dep = append(dep, dbParentEntry.ID)
		}
	}

	// Notify
	m := &NotifyMessage{
		Issuer:      r.serverID,
		ID:          dbEntry.ID,
		Op:          NotifyDel,
		Rev:         dbEntry.Version, // Deleted version
		Association: true,
		Dependant:   dep,
	}
	err = r.notify(dbTx, m)
	if err != nil {
		return reportError(err)
	}

	return m, nil
}
