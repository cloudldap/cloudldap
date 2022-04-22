package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/cloudldap/cloudldap/schema"
	"github.com/cloudldap/cloudldap/util"
	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"github.com/restream/reindexer"
	"golang.org/x/xerrors"
)

type DefaultRepository struct {
	*DBRepository
}

type DBEntry struct {
	ID           int64               `db:"id"`
	Version      int64               `db:"rev"`
	ParentID     int64               `db:"parent_id"`
	Path         pq.Int64Array       `db:"path"`
	IsContainer  bool                `db:"is_container"`
	RDNNorm      string              `db:"rdn_norm"`
	RDNOrig      string              `db:"rdn_orig"`
	AttrsOrig    types.JSONText      `db:"attrs_orig"`
	AttrsOrigMap map[string][]string `db:"-"` // for cache
	// RDB doesn't have normalized attributes
}
type DBAttrsNorm = map[string][]string

type CacheEntry struct {
	ID          int64   `reindex:"id,,pk" json:"id"`
	Version     int64   `reindex:"rev" json:"rev"`
	ParentID    int64   `reindex:"parentId" json:"parentId"`
	Path        []int64 `reindex:"path,tree" json:"path"`
	IsContainer bool    `reindex:"isContainer" json:"isContainer"`
	RDNNorm     string  `reindex:"rdnNorm" json:"rdnNorm"`
	RDNOrig     string  `reindex:"-" json:"rdnOrig"`
	AttrsNorm   struct {
		// Add index dynamically
	} `reindex:"attrsNorm" json:"attrsNorm"`
	AttrsOrig CacheAttrsOrig `reindex:"-" json:"attrsOrig"`
	Dummy     string         `reindex:"dummy" json:"-"`
}
type CacheAttrsOrig map[string][]string
type CacheAttrsNorm map[string][]interface{}

func (c CacheAttrsNorm) ValueStr(name string) []string {
	rtn := make([]string, len(c[name]))
	for i, v := range c[name] {
		rtn[i] = v.(string)
	}
	return rtn
}
func (c CacheAttrsNorm) ValueInt64(name string) []int64 {
	rtn := make([]int64, len(c[name]))
	for i, v := range c[name] {
		var err error
		rtn[i], err = v.(json.Number).Int64()
		if err != nil {
			panic(fmt.Sprintf("Unexpected normalized value type: %v", v))
		}
	}
	return rtn
}

var (
	// select
	findAll                     *sqlx.NamedStmt
	findEntryByID               *sqlx.NamedStmt
	findSubContainerByPath      *sqlx.NamedStmt
	shareLockEntryByIDForInsert *sqlx.NamedStmt
	lockEntryByIDForInsert      *sqlx.NamedStmt
	lockEntryByIDForUpdate      *sqlx.NamedStmt
	lockEntryByIDForMove        *sqlx.NamedStmt
	lockTreeByIDForMove         *sqlx.NamedStmt
	lockEntryByIDForDelete      *sqlx.NamedStmt
	findChildByParentID         *sqlx.NamedStmt

	// insert
	insertRootEntry *sqlx.NamedStmt
	insertEntry     *sqlx.NamedStmt

	// update
	updateContainer      *sqlx.NamedStmt
	updateParent         *sqlx.NamedStmt
	updateParentWithPath *sqlx.NamedStmt
	updatePath           *sqlx.NamedStmt
	addMemberOf          *sqlx.NamedStmt
	removeMember         *sqlx.NamedStmt

	// delete
	deleteByIDEntry *sqlx.NamedStmt

	// notify
	notifyStmt *sqlx.NamedStmt
)

func (r *DefaultRepository) Init() error {
	var err error
	db := r.db

	reportError := func(err error) (x error) {
		return errors.Wrap(err, "Failed to initialize DB")
	}

	_, err = db.Exec(`
CREATE EXTENSION if not exists pgcrypto;
CREATE TABLE IF NOT EXISTS entry (
	id BIGSERIAL PRIMARY KEY,
	uuid UUID NOT NULL,
	rev BIGINT NOT NULL,
	parent_id BIGINT NOT NULL,
	path BIGINT[],
	is_container BOOLEAN NOT NULL,
	rdn_norm TEXT NOT NULL,
	rdn_orig TEXT NOT NULL,
	attrs_orig JSONB NOT NULL,
	
	CONSTRAINT uniq_entry
		UNIQUE (parent_id, rdn_norm),
	CONSTRAINT uniq_uuid
		UNIQUE (uuid),
	CONSTRAINT fk_id
		FOREIGN KEY (parent_id)
		REFERENCES entry (id)
		ON DELETE RESTRICT ON UPDATE RESTRICT
);
`)
	if err != nil {
		return reportError(err)
	}

	// Insert root of root
	_, err = db.Exec(`
INSERT INTO entry VALUES (0, gen_random_uuid(), 1, 0, ARRAY []::BIGINT[], TRUE, 'dc=0', 'dc=0', '{"dc":["0"], "objectClass": ["dcObject"]}') ON CONFLICT DO NOTHING;
`)
	if err != nil {
		return reportError(err)
	}

	// DEBUG
	if false {
		_, err = db.Exec(`
INSERT INTO entry VALUES (2, gen_random_uuid(), 1, 1, ARRAY [1, 1], TRUE, 'ou=people', 'ou=people', '{"ou":["people"], "objectClass": ["organizationalUnit"]}') ON CONFLICT DO NOTHING;
INSERT INTO entry VALUES (3, gen_random_uuid(), 1, 1, ARRAY [1, 2], TRUE, 'ou=groups', 'ou=groups', '{"ou":["groups"], "objectClass": ["organizationalUnit"]}') ON CONFLICT DO NOTHING;
`)
		if err != nil {
			return reportError(err)
		}

		values := []string{}
		allUserIds := []string{}
		c := 3

		USER_SIZE := 100000
		for i := 1; i <= USER_SIZE; i++ {
			values = append(values, fmt.Sprintf(`(%d, gen_random_uuid(), 1, 2, NULL, FALSE, 'cn=user%d', 'CN=User%d', '{"CN":["User%d"], "userPassword": ["test"], "objectClass": ["inetOrgPerson"], "sn": ["user%d"], "memberOf": ["21003"]}')`, c, i, i, i, i))
			allUserIds = append(allUserIds, strconv.Itoa(c))
			c++
		}
		_, err = db.Exec(fmt.Sprintf(`INSERT INTO entry VALUES %s ON CONFLICT DO NOTHING;`, strings.Join(values, ",")))
		if err != nil {
			return reportError(err)
		}

		log.Printf("Finished user data")

		values = []string{}

		GROUP_SIZE := 20000
		for i := 1; i <= GROUP_SIZE; i++ {
			values = append(values, fmt.Sprintf(`(%d, gen_random_uuid(), 1, 3, NULL, FALSE, 'cn=group%d', 'cn=group%d', '{"cn":["group%d"], "objectClass": ["groupOfNames"]}')`, c, i, i, i))
			c++
		}
		_, err = db.Exec(fmt.Sprintf(`INSERT INTO entry VALUES %s ON CONFLICT DO NOTHING;`, strings.Join(values, ",")))
		if err != nil {
			return reportError(err)
		}

		// Big Group
		values = []string{}

		_, err = db.Exec(fmt.Sprintf(`INSERT INTO entry VALUES (%d, gen_random_uuid(), 1, 3, NULL, FALSE, 'cn=all-users', 'cn=all-users', '{"cn":["all-users"], "objectClass": ["groupOfNames"], "member": ["%s"] }') ON CONFLICT DO NOTHING;`, c, strings.Join(allUserIds, `","`)))
		if err != nil {
			return reportError(err)
		}

		_, err = db.Exec(`
SELECT SETVAL('entry_id_seq', (SELECT MAX(id) + 1 FROM entry));
`)
		if err != nil {
			return reportError(err)
		}

		// for _, userId := range allUserIds {
		// 	values = append(values, fmt.Sprintf(`('member', %d, %s)`, c, userId))
		// }
		// _, err = db.Exec(fmt.Sprintf(`INSERT INTO association VALUES %s ON CONFLICT DO NOTHING;`, strings.Join(values, ",")))
		// if err != nil {
		// 	return xerrors.Errorf("Failed to insert test association data: %w", err)
		// }

		log.Printf("Finished test data")
	}

	findAll, err = db.PrepareNamed(`
SELECT
	e.id, e.rev, e.parent_id, e.path, e.is_container, e.rdn_norm, e.rdn_orig, e.attrs_orig
FROM entry e
`)
	if err != nil {
		return reportError(err)
	}

	findEntryByID, err = db.PrepareNamed(`
SELECT
	e.id, e.rev, e.parent_id, e.path, e.is_container, e.rdn_norm, e.rdn_orig, e.attrs_orig
FROM entry e
WHERE
	e.id = :id
`)
	if err != nil {
		return reportError(err)
	}

	findSubContainerByPath, err = db.PrepareNamed(`
SELECT
	e.id, e.rev, e.parent_id, e.path, e.is_container, e.rdn_norm, e.rdn_orig, e.attrs_orig
FROM entry e
WHERE
	e.path @> :path
	AND e.id != :id
`)
	if err != nil {
		return reportError(err)
	}

	shareLockEntryByIDForInsert, err = db.PrepareNamed(`
SELECT
	e.id, e.rev, e.path, e.is_container,
	(SELECT path FROM entry WHERE id = e.parent_id FOR SHARE) as parent_path
FROM entry e
WHERE
	e.id = :id
FOR SHARE
`)
	if err != nil {
		return reportError(err)
	}

	lockEntryByIDForInsert, err = db.PrepareNamed(`
SELECT
	e.id, e.rev, e.path, e.is_container,
	(SELECT path FROM entry WHERE id = e.parent_id FOR UPDATE) as parent_path
FROM entry e
WHERE
	e.id = :id
FOR UPDATE
`)
	if err != nil {
		return reportError(err)
	}

	lockEntryByIDForUpdate, err = db.PrepareNamed(`
SELECT
	e.id, e.rev, e.path, e.is_container, e.rdn_norm, e.rdn_orig, e.attrs_orig
FROM entry e
WHERE
	e.id = :id
FOR UPDATE
`)
	if err != nil {
		return reportError(err)
	}

	lockTreeByIDForMove, err = db.PrepareNamed(`
SELECT
	e.id, e.rev, e.path, e.is_container
FROM entry e
WHERE
	e.id = :id
	OR e.path @> :path
FOR UPDATE
`)
	if err != nil {
		return reportError(err)
	}

	lockEntryByIDForMove, err = db.PrepareNamed(`
SELECT
	e.id, e.rev, e.path, e.is_container,
	(SELECT path FROM entry WHERE id = e.parent_id FOR UPDATE) as parent_path
FROM entry e
WHERE
	e.id = :id
FOR UPDATE
`)
	if err != nil {
		return reportError(err)
	}

	lockEntryByIDForDelete, err = db.PrepareNamed(`
SELECT
	e.id, e.rev
FROM entry e
WHERE
	e.id = :id
FOR UPDATE
`)
	if err != nil {
		return reportError(err)
	}

	findChildByParentID, err = db.PrepareNamed(`
SELECT
	e.id, e.rev
FROM entry e
WHERE
	e.parent_id = :parent_id
LIMIT 1
`)
	if err != nil {
		return reportError(err)
	}

	insertRootEntry, err = db.PrepareNamed(`
INSERT INTO entry (uuid, rev, parent_id, is_container, rdn_norm, rdn_orig, attrs_orig)
VALUES(:uuid, 1, 0, FALSE, :rdn_norm, :rdn_orig, :attrs_orig)
RETURNING id
	`)
	if err != nil {
		return reportError(err)
	}

	insertEntry, err = db.PrepareNamed(`
INSERT INTO entry (uuid, rev, parent_id, is_container, rdn_norm, rdn_orig, attrs_orig)
VALUES(:uuid, 1, :parent_id, FALSE, :rdn_norm, :rdn_orig, :attrs_orig)
RETURNING id
`)
	if err != nil {
		return reportError(err)
	}

	updateContainer, err = db.PrepareNamed(`
UPDATE
	entry
SET
	rev = rev + 1,
	path = :path,
	is_container = :is_container
WHERE
	id = :id
	AND rev = :rev
	AND is_container != :is_container
`)
	if err != nil {
		return reportError(err)
	}

	updateParent, err = db.PrepareNamed(`
UPDATE
	entry
SET
	parent_id = :new_parent_id
WHERE
	id = :id
	AND rev = :rev
`)
	if err != nil {
		return reportError(err)
	}

	updateParentWithPath, err = db.PrepareNamed(`
UPDATE
	entry
SET
	parent_id = :new_parent_id,
	path = :new_path
WHERE
	id = :id
	AND rev = :rev
`)
	if err != nil {
		return reportError(err)
	}

	updatePath, err = db.PrepareNamed(`
UPDATE
	entry
SET
	rev = rev +1,
	path = :new_path
WHERE
	id = :id
	AND rev = :rev
`)
	if err != nil {
		return reportError(err)
	}

	deleteByIDEntry, err = db.PrepareNamed(`
DELETE FROM entry
WHERE
	id = :id
`)
	if err != nil {
		return reportError(err)
	}

	addMemberOf, err = db.PrepareNamed(`
UPDATE
	entry
SET
	attrs_orig = JSONB_SET(attrs_orig, ARRAY['memberOf'], (attrs_orig->'memberOf') || :member_id),
	rev = rev + 1
WHERE
	id = :id
`)
	if err != nil {
		return reportError(err)
	}

	removeMember, err = db.PrepareNamed(`
UPDATE
	entry
SET	
	attrs_orig = JSONB_SET(attrs_orig, ARRAY['memberOf'], (attrs_orig->'memberOf') - (:member_id)::::text),
	rev = rev + 1
WHERE
	id = :id
`)
	if err != nil {
		return reportError(err)
	}

	notifyStmt, err = db.PrepareNamed(`
SELECT pg_notify(
	'entry_update',
	JSON_BUILD_OBJECT(
		'iss', (:iss)::::TEXT, 
		'id', (:id)::::BIGINT,
		'op', (:op)::::TEXT,
		'rev', (:rev)::::BIGINT,
		'asc', (:asc)::::BOOLEAN,
		'dep', (:dep)::::BIGINT[],
		'sub', (:sub)::::BOOLEAN
	)::::text
)
	`)
	if err != nil {
		return reportError(err)
	}

	// 	allStmt, err = db.PrepareNamed(`
	// SELECT
	//     e.id, e.parent_id, e.attrs_orig,
	//     member.member,
	//     uniqueMember.unique_member,
	//     memberOf.member_of
	// FROM entry e
	// -- member
	// LEFT JOIN LATERAL (
	//     SELECT ARRAY_AGG(a.member_id) as member FROM association a WHERE e.id = a.id AND a.name = 'member'
	// ) AS member ON TRUE
	// -- uniqueMember
	// LEFT JOIN LATERAL (
	//     SELECT ARRAY_AGG(a.member_id) as unique_member FROM association a WHERE e.id = a.id AND a.name = 'uniqueMember'
	// ) AS uniqueMember ON TRUE
	// -- memberOf
	// LEFT JOIN LATERAL (
	//     SELECT ARRAY_AGG(a.id) as member_of FROM association a WHERE e.id = a.member_id
	// ) AS memberOf ON TRUE
	// 	`)
	if err != nil {
		return reportError(err)
	}

	// indexer
	err = r.cacheDB.AddIndex("entries", reindexer.IndexDef{Name: "attrsNorm.objectClass", JSONPaths: []string{"attrsNorm.objectClass"}, IndexType: "hash", FieldType: "string", IsArray: true})
	if err != nil {
		return errors.Wrap(err, "Failed to initialize local index. name: objectClass")
	}
	for k, _ := range r.schemaRegistry.AttributeTypes {
		if isIndexedAttribute(k) {
			err = r.cacheDB.AddIndex("entries", reindexer.IndexDef{Name: "attrsNorm." + k, JSONPaths: []string{"attrsNorm." + k}, IndexType: "hash", FieldType: "string", IsArray: true})
			if err != nil {
				return errors.Wrapf(err, "Failed to initialize local index. name: %s", k)
			}
		}
		if isNumIndexedAttribute(k) {
			err = r.cacheDB.AddIndex("entries", reindexer.IndexDef{Name: "attrsNorm." + k, JSONPaths: []string{"attrsNorm." + k}, IndexType: "hash", FieldType: "int64", IsArray: true})
			if err != nil {
				return errors.Wrapf(err, "Failed to initialize local index. name: %s", k)
			}
		}
	}

	ctx := context.Background()
	if err := r.CacheAll(ctx); err != nil {
		return errors.Wrap(err, "Failed to initialize cache DB.")
	}

	return nil
}

func isIndexedAttribute(name string) bool {
	// TODO
	return name == "cn" ||
		name == "uid" ||
		name == "sn" ||
		name == "givenName" ||
		name == "ou"
}

func isNumIndexedAttribute(name string) bool {
	// TODO
	return name == "member" ||
		name == "uniqueMember" ||
		name == "memberOf"
}

func (r *DefaultRepository) RefreshCache(ctx context.Context) error {
	log.Printf("info: Clear all cache entries")
	if err := r.cacheDB.TruncateNamespace("entries"); err != nil {
		return errors.Wrapf(err, "Failed to truncate cache DB")
	}

	return r.CacheAll(ctx)
}

func (r *DefaultRepository) CacheAll(ctx context.Context) error {
	log.Printf("info: Starting cache all entries")
	first := time.Now()

	cacheTx, err := r.beginCacheTX()

	if err != nil {
		return xerrors.Errorf("Failed to begin cache DB transaction: %w", err)
	}

	tx, err := r.beginReadonly(ctx)
	if err != nil {
		return xerrors.Errorf("Failed to begin DB transaction: %w", err)
	}
	defer rollback(tx)

	log.Printf("info: Feching all entries")
	start := time.Now()

	rows, err := tx.NamedStmtContext(ctx, findAll).Queryx(map[string]interface{}{})
	if err != nil {
		return xerrors.Errorf("Failed to execute fetch all query: %w", err)
	}

	elapsed := time.Since(start)
	log.Printf("info: Executed fetch all entries: %v", elapsed)
	log.Printf("info: Caching all entries")
	start = time.Now()

	for rows.Next() {
		var dbEntry DBEntry
		err = rows.StructScan(&dbEntry)
		if err != nil {
			return errors.Wrap(err, "Unexpected struct scan error")
		}

		if err := r.CacheEntry(ctx, cacheTx, &dbEntry, true); err != nil {
			return errors.Wrap(err, "cache entry error")
		}
	}

	elapsed = time.Since(start)
	log.Printf("info: Cached all entries: %v", elapsed)

	if err := cacheTx.Commit(); err != nil {
		panic(err)
	}

	elapsed = time.Since(first)
	log.Printf("info: Cache commited: %v", elapsed)

	// start = time.Now()
	// if err := r.CacheAssociation(ctx, memberOfMap); err != nil {
	// 	return xerrors.Errorf("Unexpected cache association error. err: %w", err)
	// }
	// elapsed = time.Since(start)

	// log.Printf("info: Resolve association: %v", elapsed)

	// ################### TEST

	// start = time.Now()

	// query := r.cacheDB.Query("entries").
	// 	WhereInt64("path", reindexer.EQ, 0).
	// 	ReqTotal()
	// iterator := query.Exec()
	// // Iterator must be closed
	// defer iterator.Close()

	// for iterator.Next() {
	// 	// Get the next document and cast it to a pointer
	// 	elem := iterator.Object().(*CacheEntry)
	// 	fmt.Println(elem)
	// }
	// if err := iterator.Error(); err != nil {
	// 	panic(err)
	// }

	// elapsed = time.Since(start)

	// log.Printf("info: Got base DN: %v", elapsed)

	// ctx = context.WithValue(ctx, dnCacheContextKey, newDnCache())

	// start = time.Now()

	// query = r.cacheDB.Query("entries").
	// 	Sort("id", false).
	// 	WhereInt64("parentId", reindexer.EQ, 2).
	// 	WhereString("attrsNorm.objectClass", reindexer.EQ, "groupofnames").
	// 	// WhereInt64("attrsNorm.memberOf", reindexer.EQ, 21003).
	// 	// WhereString("attrsNorm.cn", reindexer.EQ, "user100").
	// 	WhereString("attrsNorm.cn", reindexer.EQ, "all-users").
	// 	Limit(500).
	// 	ReqTotal()

	// iterator = query.Exec()
	// // Iterator must be closed
	// defer iterator.Close()

	// fmt.Println("Found", iterator.TotalCount(), "total documents, first", iterator.Count(), "documents:")

	// var rtn []string
	// for iterator.Next() {
	// 	// Get the next document and cast it to a pointer
	// 	elem := iterator.Object().(*CacheEntry)
	// 	// fmt.Println(elem.ID)
	// 	if member, ok := elem.AttrsOrig["member"]; ok {
	// 		for _, ms := range member {
	// 			mid, _ := strconv.ParseInt(ms, 10, 64)
	// 			dn, _ := r.toDN(ctx, mid)
	// 			s := dn.DNNormStr()
	// 			rtn = append(rtn, s)
	// 		}
	// 	}
	// 	// rtn = append(rtn, elem.RDNOrig)
	// }
	// if err := iterator.Error(); err != nil {
	// 	panic(err)
	// }

	// elapsed = time.Since(start)

	// log.Printf("%v", rtn)
	// log.Printf("info: Got entry: %v", elapsed)

	return nil
}

func (r *DefaultRepository) CacheEntryByID(ctx context.Context, cacheTx *reindexer.Tx, dbTx *sqlx.Tx, id int64, assoc bool) error {
	// Fetch the latest entry from DB to cache it
	var dbEntry DBEntry
	err := r.get(dbTx, findEntryByID, &dbEntry, map[string]interface{}{
		"id": id,
	})
	if err != nil {
		return err
	}

	// Add/Update Cache
	err = r.CacheEntry(ctx, cacheTx, &dbEntry, false)
	if err != nil {
		return err
	}

	// Update association
	if assoc {
		// Collect memberOf, then cache them
		memberOf := util.NewInt64Set()
		// TODO configurable
		for _, name := range []string{"member", "uniqueMember"} {
			if v, ok := dbEntry.AttrsOrigMap[name]; ok {
				for _, vv := range v {
					i, err := strconv.ParseInt(vv, 10, 64)
					if err != nil {
						log.Printf("warn: The association value is not number, ignored. value: %s", vv)
						continue
					}
					memberOf.Add(i)
				}
			}
		}
		return r.CacheAssociation(ctx, cacheTx, dbTx, memberOf.Values())
	}
	return nil
}

func (r *DefaultRepository) CacheEntryBySubTree(ctx context.Context, cacheTx *reindexer.Tx, dbTx *sqlx.Tx, id int64) error {
	// Fetch the latest entry from DB to cache it
	rows, err := r.stmtQuery(ctx, dbTx, findSubContainerByPath, map[string]interface{}{
		"id":   id,
		"path": pq.Array([]int64{id}),
	})
	if err != nil {
		return errors.Wrapf(err, "Failed to fetch sub containers. id: %d", id)
	}
	for rows.Next() {
		var dbEntry DBEntry
		if err := rows.StructScan(&dbEntry); err != nil {
			return errors.Wrapf(err, "Unexpected struct scan. id: %d", id)
		}

		// Add/Update Cache
		err = r.CacheEntry(ctx, cacheTx, &dbEntry, false)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *DefaultRepository) CacheEntry(ctx context.Context, tx *reindexer.Tx, entry *DBEntry, ignoreParent bool) error {
	dbAttrsOrig := make(DBAttrsNorm)
	cacheAttrsNorm := make(map[string]interface{})

	if err := entry.AttrsOrig.Unmarshal(&dbAttrsOrig); err != nil {
		return xerrors.Errorf("Unexpected unmarshal error. raw: %v, err: %w", entry.AttrsOrig, err)
	}

	// Normalize attrs
	for k, v := range dbAttrsOrig {
		sv, err := schema.NewSchemaValue(r.schemaRegistry, k, v)
		if err != nil {
			return xerrors.Errorf("Unexpected schema error. name: %s, value: %v, err: %w", k, v, err)
		}
		err = sv.Normalize()
		if err != nil {
			return xerrors.Errorf("Unexpected normalization error. err: %w", err)
		}

		if isNumIndexedAttribute(sv.Name()) {
			cacheAttrsNorm[sv.Name()] = sv.Norm()
		} else {
			cacheAttrsNorm[sv.Name()] = sv.NormStr()
		}
	}

	// Normalize rdn
	// TODO: create NormalizeRDNStr()
	rdn, err := r.schemaRegistry.NormalizeDN(entry.RDNOrig)
	if err != nil {
		return xerrors.Errorf("Unexpected normalization rdn error. rdn: %s, err: %w", entry.RDNOrig, err)
	}

	jsonMap := make(map[string]interface{})
	jsonMap["id"] = entry.ID
	jsonMap["rev"] = entry.Version
	jsonMap["parentId"] = entry.ParentID
	jsonMap["path"] = entry.Path
	jsonMap["isContainer"] = entry.IsContainer
	jsonMap["rdnOrig"] = entry.RDNOrig
	jsonMap["rdnNorm"] = rdn.RDNNormStr()
	jsonMap["attrsOrig"] = dbAttrsOrig
	jsonMap["attrsNorm"] = cacheAttrsNorm
	entryJson, err := json.Marshal(jsonMap)
	if err != nil {
		return xerrors.Errorf("Unexpected schema error. err: %w", err)
	}

	// log.Printf("%v", string(entryJson))

	err = tx.Upsert(entryJson)
	if err != nil {
		return xerrors.Errorf("Failed to upsert into cacheDB. err: %w", err)
	}

	// cache
	entry.AttrsOrigMap = dbAttrsOrig

	return nil
}

func (r *DefaultRepository) CacheAssociation(ctx context.Context, cacheTx *reindexer.Tx, dbTx *sqlx.Tx, memberOf []int64) error {
	reportError := func(err error) error {
		return errors.Wrapf(err, "Failed to cache assoication. memberOf: %v", memberOf)
	}

	if len(memberOf) == 0 {
		return nil
	}

	// Fetch current memberOf from DB, then sync them to cache DB
	q, args, err := sqlx.Named(`
SELECT
e.id, e.rev, e.parent_id, e.rdn_norm, e.rdn_orig, e.attrs_orig
FROM entry e
WHERE
id IN (:id)
`, map[string]interface{}{
		"id": memberOf,
	})
	if err != nil {
		return reportError(err)
	}

	q, args, err = sqlx.In(q, args...)
	if err != nil {
		return reportError(err)
	}

	q = dbTx.Rebind(q)

	rows, err := dbTx.QueryxContext(ctx, q, args...)
	if err != nil {
		return reportError(err)
	}

	for rows.Next() {
		var dbdest DBEntry
		err = rows.StructScan(&dbdest)
		if err != nil {
			return reportError(err)
		}

		iter := cacheTx.Query().
			Select("rev").
			WhereInt64("id", reindexer.EQ, dbdest.ID).
			ExecToJsonCtx(ctx)
		if iter.Next() {
			// Exists in cache
			var cdest struct {
				Version int64 `json:"rev"`
			}
			if err := json.Unmarshal(iter.JSON(), &cdest); err != nil {
				return reportError(err)
			}
			if shouldVersionUpdated(dbdest.Version, cdest.Version) {
				// Update cache with the latest db record
				if err := r.CacheEntry(ctx, cacheTx, &dbdest, false); err != nil {
					return reportError(err)
				}
				continue
			}
			log.Printf("info: Already cached association with new version, ignore it. id: %d, cacheVersion: %d, dbVersion: %d",
				dbdest.ID, cdest.Version, dbdest.Version)
			continue
		}
		iter.Close()

		// Not in the cache yet, add it
		if err := r.CacheEntry(ctx, cacheTx, &dbdest, false); err != nil {
			return reportError(err)
		}
	}

	return nil
}

// Not used
func (r *DefaultRepository) findAttrsOrigByID(ctx context.Context, id int64) (CacheAttrsOrig, error) {
	iter := r.query().
		Select("attrsOrig").
		WhereInt64("id", reindexer.EQ, id).
		Limit(1).
		ExecToJson()
	defer iter.Close()

	if !iter.Next() {
		// Not found
		return nil, nil
	}

	result := struct {
		AttrsOrig CacheAttrsOrig `json:"attrsOrig"`
	}{}

	if err := json.Unmarshal(iter.JSON(), &result); err != nil {
		log.Printf("error: Unexpected unmarshal json error. err: %v", err)
		return nil, xerrors.Errorf("Unexpected unmarshal json error: %w", err)
	}

	return result.AttrsOrig, nil
}

func (r *DefaultRepository) findEntryID(ctx context.Context, dn *schema.DN) (int64, error) {
	return r.findEntryIDWithTx(ctx, nil, dn)
}

func (r *DefaultRepository) findEntryIDWithTx(ctx context.Context, cacheTx *reindexer.Tx, dn *schema.DN) (int64, error) {
	var rdnNorms []string

	if dn.IsSuffix(r.schemaRegistry.SuffixDN) {
		// To support multiple base DN
		rdnNorms = []string{dn.RDNNormStr()}
	} else {
		size := dn.LevelWithoutSuffix(r.schemaRegistry.SuffixDN) + 1
		rdnNorms = make([]string, size)

		for i := 0; i < size; i++ {
			rdnNorms[i] = dn.RDNNormStr()
			dn = dn.ParentDN()
		}
	}

	dnCache, _ := ctx.Value(schema.DNCacheContextKey).(*schema.DNCache)

	var id int64 = 0

	result := struct {
		ID int64 `json:"id"`
	}{}

	var dnNorm string

	for i := len(rdnNorms) - 1; i >= 0; i-- {
		if i == len(rdnNorms)-1 {
			dnNorm = rdnNorms[i]
		} else {
			dnNorm = rdnNorms[i] + "," + dnNorm
		}
		if cid, ok := dnCache.Atoi[dnNorm]; ok {
			// Cached
			id = cid
		} else {
			// Not cached
			var q *reindexer.Query
			if cacheTx == nil {
				q = r.query()
			} else {
				q = cacheTx.Query()
			}
			iter := q.
				Select("id").
				WhereInt64("parentId", reindexer.EQ, id).
				WhereString("rdnNorm", reindexer.EQ, rdnNorms[i]).
				Limit(1).
				ExecToJsonCtx(ctx)
			defer iter.Close()

			if !iter.Next() {
				// Not found
				return -1, util.NewNoSuchObject()
			}

			if err := json.Unmarshal(iter.JSON(), &result); err != nil {
				return -1, xerrors.Errorf("Failed to fetch by parentId = %d and rdnNorm = %s. err: %w", id, rdnNorms[i], err)
			}

			id = result.ID

			// Cache container DN
			// Don't cache entry which isn't container
			if i > 0 {
				dnCache.Atoi[dnNorm] = id
			}
		}
	}

	return id, nil
}

func (r *DefaultRepository) findEntryPath(ctx context.Context, dn *schema.DN) ([]int64, error) {
	var rdnNorms []string

	if dn.IsSuffix(r.schemaRegistry.SuffixDN) {
		// To support multiple base DN
		rdnNorms = []string{dn.RDNNormStr()}
	} else {
		size := dn.LevelWithoutSuffix(r.schemaRegistry.SuffixDN) + 1
		rdnNorms = make([]string, size)

		for i := 0; i < size; i++ {
			rdnNorms[i] = dn.RDNNormStr()
			dn = dn.ParentDN()
		}
	}

	var id int64 = 0
	ids := []int64{}

	dest := struct {
		ID int64 `json:"id"`
	}{}

	for i := len(rdnNorms) - 1; i >= 0; i-- {
		iter := r.query().
			Select("id").
			WhereInt64("parentId", reindexer.EQ, id).
			WhereString("rdnNorm", reindexer.EQ, rdnNorms[i]).
			Limit(1).
			ExecToJsonCtx(ctx)
		defer iter.Close()

		if iter.Error() != nil {
			return nil, errors.Wrap(iter.Error(), "findEntryPath")
		}

		if !iter.Next() {
			// Not found
			return nil, util.NewNoSuchObject()
		}

		if err := json.Unmarshal(iter.JSON(), &dest); err != nil {
			return nil, xerrors.Errorf("Failed to fetch by parentId = %d and rdnNorm = %s. err: %w", id, rdnNorms[i], err)
		}

		id = dest.ID
		ids = append(ids, id)
	}

	return ids, nil
}

func (r *DefaultRepository) dnStrArrayToIDStrArray(ctx context.Context, dn []string) ([]string, error, int) {
	ids := make([]string, len(dn))
	for i, v := range dn {
		d, err := r.schemaRegistry.NormalizeDN(v)
		if err != nil {
			return nil, err, i
		}

		id, err := r.findEntryID(ctx, d)
		if err != nil {
			if util.IsNoSuchObjectError(err) {
				return nil, err, i
			}
			return nil, err, i
		}

		ids[i] = strconv.FormatInt(id, 10)
	}
	return ids, nil, -1
}

func (r *DefaultRepository) addMemberOf(ctx context.Context, dbTx *sqlx.Tx, ids []string, id int64) error {
	reportError := func(err error) error {
		return errors.Wrapf(err, "Failed to add memberOf. memberOf: %d, ids: %v", id, ids)
	}

	if len(ids) == 0 {
		return nil
	}

	// Use COALESCE for non memberOf situation
	q, args, err := sqlx.Named(`
UPDATE entry
SET
	attrs_orig = JSONB_SET(attrs_orig, ARRAY['memberOf'], COALESCE((attrs_orig->'memberOf')::::jsonb, '[]'::::jsonb) || :member_id),
	rev = rev + 1
WHERE id IN (:id)
`, map[string]interface{}{
		"member_id": types.JSONText(fmt.Sprintf(`["%d"]`, id)),
		"id":        ids,
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

	if updated != int64(len(ids)) {
		return reportError(err)
	}

	return nil
}

func (r *DefaultRepository) deleteMemberOf(ctx context.Context, dbTx *sqlx.Tx, ids []string, id int64) error {
	reportError := func(err error) error {
		return errors.Wrapf(err, "Failed to delete memberOf. memberOf: %d, ids: %v", id, ids)
	}

	if len(ids) == 0 {
		return nil
	}

	q, args, err := sqlx.Named(`
UPDATE entry
SET
	attrs_orig = JSONB_SET(attrs_orig, ARRAY['memberOf'], COALESCE((attrs_orig->'memberOf')::::jsonb, '[]'::::jsonb) - (:member_id)::::text),
	rev = rev + 1
WHERE id IN (:id)
`, map[string]interface{}{
		"member_id": id,
		"id":        ids,
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

	if updated != int64(len(ids)) {
		log.Printf("warn: Detected inconsistency while removing memberOf. id: %d", id)
		return util.NewRetryError(err)
	}

	return nil
}

func (r *DefaultRepository) OnUpdate(ctx context.Context, m *NotifyMessage) error {
	if m == nil {
		return nil
	}

	cacheTx, err := r.beginCacheTX()
	if err != nil {
		return err
	}
	reportError := func(err error) error {
		cacheTx.Rollback()
		return errors.Wrapf(err, "message: %v", m)
	}

	dbTx, err := r.beginReadonly(ctx)
	if err != nil {
		return err
	}
	defer rollback(dbTx)

	iter := cacheTx.Query().
		Select("rev", "parentId").
		WhereInt64("id", reindexer.EQ, m.ID).
		ExecToJsonCtx(ctx)

	if iter.Error() != nil {
		return errors.Wrapf(err, "Failed to get from cache DB. id: %d", m.ID)
	}

	var doUpdate bool

	var dest struct {
		Version  int64 `json:"rev"`
		ParentID int64 `json:"parentId"`
	}
	if iter.Next() {
		// Exists in cache
		if err := json.Unmarshal(iter.JSON(), &dest); err != nil {
			iter.Close()
			return reportError(err)
		}
		if shouldVersionUpdated(m.Rev, dest.Version) {
			// Update cache with the latest db record
			doUpdate = true
		} else {
			if m.IsMod() {
				log.Printf("warn: Already cached with new version, ignore it. id: %d, cacheVersion: %d, dbVersion: %d",
					m.ID, dest.Version, m.Rev)
			}
		}
	} else {
		// Not found in cache
		doUpdate = true
	}
	iter.Close()

	if (m.IsAdd() || m.IsMod()) && doUpdate {
		err = r.CacheEntryByID(ctx, cacheTx, dbTx, m.ID, m.Association)
		if err != nil {
			return reportError(err)
		}
		log.Printf("Upsert cache DB, id: %d, version: %d", m.ID, m.Rev)

		for _, id := range m.Dependant {
			err = r.CacheEntryByID(ctx, cacheTx, dbTx, id, false)
			if err != nil {
				return reportError(err)
			}
			log.Printf("Upsert cache DB, id: %d, version: %d", m.ID, m.Rev)
		}

		if m.Sub {
			err = r.CacheEntryBySubTree(ctx, cacheTx, dbTx, m.ID)
			if err != nil {
				return reportError(err)
			}
		}

	} else if m.IsDel() {
		deleted, err := r.DeleteCacheEntry(ctx, cacheTx, dbTx, m.ID, dest.ParentID, true)
		if err != nil {
			return reportError(err)
		}
		if deleted == 1 {
			log.Printf("Delete cache DB, id: %d, version: %d", m.ID, m.Rev)
		} else {
			log.Printf("Not found cache DB for delete, id: %d, version: %d", m.ID, m.Rev)
		}

	} else {
		// Nothing to cache
		cacheTx.Rollback()
		return nil
	}

	// Commit
	err = cacheTx.Commit()
	if err != nil {
		return reportError(err)
	}

	return nil
}

func (r *DefaultRepository) DeleteCacheEntry(ctx context.Context, cacheTx *reindexer.Tx, dbTx *sqlx.Tx, id, parentId int64, acc bool) (int, error) {
	reportError := func(err error) (int, error) {
		return -1, errors.Wrapf(err, "Failed to delete cache. id: %d", id)
	}
	// Delete it from cache DB
	deleted, err := cacheTx.Query().
		WhereInt64("id", reindexer.EQ, id).
		DeleteCtx(ctx)
	if err != nil {
		return reportError(err)
	}

	// Update parent container
	_, found := cacheTx.Query().
		Select("id").
		WhereInt64("parentId", reindexer.EQ, parentId).
		GetJsonCtx(ctx)
	if !found {
		// Detected no children, change parent container
		cacheTx.Query().
			WhereInt64("id", reindexer.EQ, parentId).
			Set("isContainer", false).
			Set("path", []int64{}).
			ExecCtx(ctx)
	}

	if acc {
		iter := r.query().
			Select("attrsNorm.member", "attrsNorm.uniqueMember", "attrsNorm.memberOf").
			WhereInt64("id", reindexer.EQ, id).
			ExecToJsonCtx(ctx)
		defer iter.Close()

		if iter.Error() != nil {
			return reportError(err)
		}

		if iter.Next() {
			var dest struct {
				AttrsNorm struct {
					Member       []int64 `json:"member"`
					UniqueMember []int64 `json:"uniqueMember"`
					MemberOf     []int64 `json:"memberOf"`
				} `json:"attrsNorm"`
			}
			if err := json.Unmarshal(iter.JSON(), &dest); err != nil {
				return reportError(err)
			}

			v := append(dest.AttrsNorm.Member, append(dest.AttrsNorm.UniqueMember, dest.AttrsNorm.MemberOf...)...)

			// Collect target ids, then cache them
			tids := util.NewInt64Set()
			for _, id := range v {
				tids.Add(id)
			}

			if err := r.CacheAssociation(ctx, cacheTx, dbTx, tids.Values()); err != nil {
				return reportError(err)
			}
		}
	}

	return deleted, nil
}

func shouldVersionUpdated(dbVersion, cacheVersion int64) bool {
	return dbVersion < 0 && cacheVersion > 0 || dbVersion > cacheVersion
}

//////////////////////////////////////////
// Utilities
//////////////////////////////////////////

func (r *DefaultRepository) withTx(ctx context.Context, callback func(cacheTx *reindexer.Tx, dbTx *sqlx.Tx) error) error {
	cacheTx, err := r.cacheDB.BeginTx("entries")
	if err != nil {
		return errors.Wrap(err, "Failed to begin cache transaction")
	}

	dbTx, err := r.db.BeginTxx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return errors.Wrap(err, "Failed to begin DB transaction")
	}

	err = callback(cacheTx, dbTx)
	if err != nil {
		rollback(dbTx)
		rollbackCache(cacheTx)
		return errors.Wrap(err, "Cache and DB transaction are rollbacked")
	}

	if err := commit(dbTx); err != nil {
		rollbackCache(cacheTx)
		return errors.Wrap(err, "Cache and DB transaction are rollbacked")
	}
	if err := commitCache(cacheTx); err != nil {
		log.Printf("error: Detected transaction inconsistency between cache and DB")
		return errors.Wrap(err, "Only cache transaction is rollbacked")
	}
	return nil
}

func (r *DefaultRepository) query() *reindexer.Query {
	return r.cacheDB.Query("entries")
}

func (r *DefaultRepository) beginCacheTX() (*reindexer.Tx, error) {
	tx, err := r.cacheDB.BeginTx("entries")
	if err != nil {
		return nil, xerrors.Errorf("Failed to begin cache db transaction. err: %w", err)
	}
	return tx, nil
}

func (r *DefaultRepository) begin(ctx context.Context) (*sqlx.Tx, error) {
	tx, err := r.db.BeginTxx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	// TODO Configurable isolation level
	// tx, err := r.db.BeginTxx(ctx, &sql.TxOptions{
	// 	Isolation: sql.LevelSerializable,
	// })
	if err != nil {
		return nil, xerrors.Errorf("Failed to begin transaction. err: %w", err)
	}
	return tx, nil
}

func (r *DefaultRepository) beginReadonly(ctx context.Context) (*sqlx.Tx, error) {
	tx, err := r.db.BeginTxx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  true,
	})
	// TODO Configurable isolation level
	// tx, err := r.db.BeginTxx(ctx, &sql.TxOptions{
	// 	Isolation: sql.LevelSerializable,
	// 	ReadOnly:  true,
	// })
	if err != nil {
		return nil, xerrors.Errorf("Failed to begin transaction. err: %w", err)
	}
	return tx, nil
}

func (r *DefaultRepository) exec(tx *sqlx.Tx, stmt *sqlx.NamedStmt, params map[string]interface{}) (sql.Result, error) {
	debugSQL(r.config.LogLevel, stmt.QueryString, params)
	result, err := tx.NamedStmt(stmt).Exec(params)
	errorSQL(err, stmt.QueryString, params)
	if isForeignKeyError(err) {
		return nil, util.NewRetryError(err)
	}
	return result, err
}

func (r *DefaultRepository) execQuery(tx *sqlx.Tx, query string) (sql.Result, error) {
	debugSQL(r.config.LogLevel, query, nil)
	result, err := tx.Exec(query)
	errorSQL(err, query, nil)
	if isForeignKeyError(err) {
		return nil, util.NewRetryError(err)
	}
	return result, err
}

func (r *DefaultRepository) execQueryAffected(ctx context.Context, tx *sqlx.Tx, q string, params map[string]interface{}) (int64, error) {
	debugSQL(r.config.LogLevel, q, params)
	result, err := tx.NamedExecContext(ctx, q, params)
	errorSQL(err, q, params)
	if isDeadlockError(err) {
		return -1, util.NewRetryError(err)
	}
	if err != nil {
		return -1, err
	}
	i, err := result.RowsAffected()
	if err != nil {
		return -1, nil
	}
	return i, err
}

func (r *DefaultRepository) execAffected(tx *sqlx.Tx, stmt *sqlx.NamedStmt, params map[string]interface{}) (int64, error) {
	debugSQL(r.config.LogLevel, stmt.QueryString, params)
	result, err := tx.NamedStmt(stmt).Exec(params)
	errorSQL(err, stmt.QueryString, params)
	if isDeadlockError(err) {
		return -1, util.NewRetryError(err)
	}
	if err != nil {
		return -1, err
	}
	i, err := result.RowsAffected()
	if err != nil {
		return -1, nil
	}
	return i, err
}

func (r *DefaultRepository) stmtQuery(ctx context.Context, tx *sqlx.Tx, stmt *sqlx.NamedStmt, params map[string]interface{}) (*sqlx.Rows, error) {
	debugSQL(r.config.LogLevel, stmt.QueryString, params)
	rows, err := tx.NamedStmtContext(ctx, stmt).QueryxContext(ctx, params)
	errorSQL(err, stmt.QueryString, params)
	if isForeignKeyError(err) {
		return nil, util.NewRetryError(err)
	}
	return rows, err
}

func (r *DefaultRepository) namedQuery(tx *sqlx.Tx, query string, params map[string]interface{}) (*sqlx.Rows, error) {
	debugSQL(r.config.LogLevel, query, params)
	rows, err := tx.NamedQuery(query, params)
	errorSQL(err, query, params)
	if isForeignKeyError(err) {
		return nil, util.NewRetryError(err)
	}
	return rows, err
}

func (r *DefaultRepository) get(tx *sqlx.Tx, stmt *sqlx.NamedStmt, dest interface{}, params map[string]interface{}) error {
	debugSQL(r.config.LogLevel, stmt.QueryString, params)
	err := tx.NamedStmt(stmt).Get(dest, params)
	errorSQL(err, stmt.QueryString, params)
	if isForeignKeyError(err) {
		return util.NewRetryError(err)
	}
	return err
}

func (r *DefaultRepository) notify(tx *sqlx.Tx, m *NotifyMessage) error {
	_, err := r.exec(tx, notifyStmt, map[string]interface{}{
		"iss": m.Issuer,
		"id":  m.ID,
		"op":  m.Op,
		"rev": m.Rev,
		"asc": m.Association,
		"dep": pq.Array(m.Dependant),
		"sub": m.Sub,
	})
	return err
}
