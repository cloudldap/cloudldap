package repo

import (
	"context"
	"encoding/json"
	"log"

	"github.com/cloudldap/cloudldap/util"
	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
	"github.com/lib/pq"
	"github.com/pkg/errors"
)

// Insert creates the entry by specified entry data.
func (r *DefaultRepository) Insert(ctx context.Context, changelog *Changelog) (int64, error) {
	var m *NotifyMessage

	// Insert DB
	err := withDBTx(ctx, r.db, func(tx *sqlx.Tx) error {
		var err error

		if changelog.DN().IsSuffix(r.schemaRegistry.SuffixDN) {
			m, err = r.insertRootInternal(ctx, tx, changelog)
		} else {
			m, err = r.insertInternal(ctx, tx, changelog)
		}

		return err
	})
	if err != nil {
		return -1, err
	}

	// Handle own notify message now
	if err := r.OnUpdate(ctx, m); err != nil {
		return -1, errors.Wrapf(err, "Failed to update cache DB for added entry. id: %d, dn_norm: %s", m.ID, changelog.DNNorm())
	}

	log.Printf("info: Added. id: %d, dn_norm: %s", m.ID, changelog.DNNorm())

	return m.ID, nil
}

func (r *DefaultRepository) insertRootInternal(ctx context.Context, tx *sqlx.Tx, changelog *Changelog) (*NotifyMessage, error) {
	dn := changelog.DN()
	reportError := func(err error) (*NotifyMessage, error) {
		return nil, errors.Wrapf(err, "dn_norm: %s", dn.DNNormStr())
	}

	attrsOrig := changelog.ToNewAttrsOrig()
	bOrig, err := json.Marshal(attrsOrig)
	if err != nil {
		return reportError(err)
	}

	newEntry := &DBEntry{
		Version:     1,
		Path:        []int64{},
		IsContainer: false,
		RDNNorm:     changelog.DN().RDNNormStr(),
		RDNOrig:     changelog.DN().RDNOrigEncodedStr(),
		AttrsOrig:   types.JSONText(bOrig),
	}

	var newID int64
	err = r.get(tx, insertRootEntry, &newID, map[string]interface{}{
		"uuid":       attrsOrig["entryUUID"][0],
		"rdn_norm":   newEntry.RDNNorm,
		"rdn_orig":   newEntry.RDNOrig,
		"attrs_orig": newEntry.AttrsOrig,
	})
	if err != nil {
		if isDuplicateKeyError(err) {
			log.Printf("warn: The new root entry already exists. dn_norm: %s", changelog.DNNorm())
			return nil, util.NewAlreadyExists()
		}
		return reportError(err)
	}
	// Don't forget store generated new ID!!
	newEntry.ID = newID

	// Notify
	m := &NotifyMessage{
		Issuer:      r.config.ServerID,
		ID:          newID,
		Op:          NotifyAdd,
		Rev:         1,
		Association: false,
	}
	err = r.notify(tx, m)
	if err != nil {
		return reportError(err)
	}

	return m, nil
}

func (r *DefaultRepository) insertInternal(ctx context.Context, tx *sqlx.Tx, changelog *Changelog) (*NotifyMessage, error) {
	reportError := func(err error) (*NotifyMessage, error) {
		return nil, errors.Wrapf(err, "dn_norm: %s", changelog.DN().DNNormStr())
	}

	// Step 1: Find the parent ID from cached DB
	pid, err := r.findEntryID(ctx, changelog.DN().ParentDN())
	if err != nil {
		log.Printf("warn: No parent entry in cache but try to insert the sub. dn_norm: %s",
			changelog.DNNorm())
		return reportError(err)
	}

	// Step 2: Lock parent entry with share lock mode
	var p struct {
		ID          int64         `db:"id"`
		Version     int64         `db:"rev"`
		ParentID    int64         `db:"parent_id"`
		Path        pq.Int64Array `db:"path"`
		IsContainer bool          `db:"is_container"`
		ParentPath  pq.Int64Array `db:"parent_path"`
	}
	err = r.get(tx, lockEntryByIDForInsert, &p, map[string]interface{}{
		"id": pid,
	})
	if err != nil {
		log.Printf("warn: No parent entry but try to insert the sub. dn_norm: %s",
			changelog.DNNorm())
		return reportError(err)
	}

	// Step 3: Update parent entry if it's not conainer yet
	dep := []int64{}
	if !p.IsContainer {
		pids := append(p.ParentPath, p.ID)
		updated, err := r.execAffected(tx, updateContainer, map[string]interface{}{
			"id":           p.ID,
			"rev":          p.Version,
			"path":         pq.Array(pids),
			"is_container": true,
		})
		if err != nil {
			return reportError(err)
		}
		if updated != 1 {
			log.Printf("warn: Detected inconsistency while updating parent as container. parent: %v", p)
			return reportError(err)
		}
		dep = append(dep, p.ID)
	}

	// Step 4: Prepared insert entry
	tids := util.NewSetString()
	attrsOrig := changelog.ToNewAttrsOrig()
	convAssoc := func(name string) error {
		if m, ok := attrsOrig[name]; ok {
			mids, err, errIndex := r.dnStrArrayToIDStrArray(ctx, m)
			if err != nil {
				if util.IsNoSuchObjectError(err) {
					return util.NewInvalidPerSyntax(name, errIndex)
				}
				return err
			}
			attrsOrig[name] = mids
			tids.AddAll(mids)
		}
		return nil
	}
	if err := convAssoc("member"); err != nil {
		return reportError(err)
	}
	if err := convAssoc("uniqueMember"); err != nil {
		return reportError(err)
	}
	bOrig, err := json.Marshal(attrsOrig)
	if err != nil {
		return reportError(err)
	}
	newEntry := &DBEntry{
		Version:     1,
		ParentID:    pid,
		Path:        []int64{},
		IsContainer: false,
		RDNNorm:     changelog.DN().RDNNormStr(),
		RDNOrig:     changelog.DN().RDNOrigEncodedStr(),
		AttrsOrig:   types.JSONText(bOrig),
	}

	// Step 5: Insert entry
	var newID int64
	err = r.get(tx, insertEntry, &newID, map[string]interface{}{
		"uuid":       attrsOrig["entryUUID"][0],
		"parent_id":  newEntry.ParentID,
		"rdn_norm":   newEntry.RDNNorm,
		"rdn_orig":   newEntry.RDNOrig,
		"attrs_orig": newEntry.AttrsOrig,
	})
	if err != nil {
		if isDuplicateKeyError(err) {
			log.Printf("warn: The new entry already exists. parentId: %d, dn_norm: %s", pid, changelog.DNNorm())
			return nil, util.NewAlreadyExists()
		}
		return nil, errors.Wrapf(err, "Failed to insert entry. entry: %v", changelog)
	}
	// Don't forget store generated new ID!!
	newEntry.ID = newID

	// Step 6: Update association if it has association
	// If the inserted entry has association (e.g. member attribute), update memberOf attribute of the target entries.
	mids := tids.List()
	if err := r.addMemberOf(ctx, tx, mids, newID); err != nil {
		return reportError(err)
	}

	// Notify
	m := &NotifyMessage{
		Issuer:      r.config.ServerID,
		ID:          newID,
		Op:          NotifyAdd,
		Rev:         1,
		Association: len(mids) > 0,
		Dependant:   dep,
	}
	err = r.notify(tx, m)
	if err != nil {
		return reportError(err)
	}

	return m, nil
}
