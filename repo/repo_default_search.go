package repo

import (
	"context"
	"encoding/json"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/cloudldap/cloudldap/schema"
	"github.com/pkg/errors"
	"github.com/restream/reindexer"
	"golang.org/x/xerrors"
)

type FilterContext struct {
	context.Context
	tx *reindexer.Tx
	q  *reindexer.Query
}

// Search handles search request by filter.
// This is used for SEARCH operation.
func (r *DefaultRepository) Search(ctx context.Context, baseDN *schema.DN, option *SearchOption, handler func(entry *SearchEntry) error) (int32, int32, error) {
	reportError := func(err error) (int32, int32, error) {
		return 0, 0, errors.Wrapf(err, "dn_norm: %s, filter: %v", baseDN.DNNormStr(), option.Filter)
	}

	cacheTx, err := r.beginCacheTX()
	if err != nil {
		return reportError(err)
	}
	defer cacheTx.Rollback()

	path, err := r.findEntryPath(ctx, baseDN)
	if err != nil {
		// It's ok returning NoSuchObject error if no base DN
		return reportError(err)
	}
	baseDNID := path[len(path)-1]

	translator := FilterTranslator{
		tx: cacheTx,
		r:  r,
	}
	q := cacheTx.Query()
	if err := translator.translate(ctx, r.schemaRegistry, option.Filter, q); err != nil {
		return reportError(err)
	}

	switch option.Scope {
	// Base only
	case 0:
		q.WhereInt64("id", reindexer.EQ, baseDNID)
	// Childlen only
	case 1:
		q.WhereInt64("parentId", reindexer.EQ, baseDNID)
	// Base + Children including grandchildren
	case 2:
		pids, err := r.findChildContainerIDs(ctx, cacheTx, baseDNID)
		if err != nil {
			return reportError(err)
		}

		q.OpenBracket().
			WhereInt64("id", reindexer.EQ, baseDNID)
		if len(pids) > 0 {
			q.Or().
				WhereInt64("parentId", reindexer.EQ, pids...).
				CloseBracket()
		} else {
			q.CloseBracket()
		}
	// Children including grandchildren
	case 3:
		pids, err := r.findChildContainerIDs(ctx, cacheTx, baseDNID)
		if err != nil {
			return reportError(err)
		}
		if len(pids) > 0 {
			q.WhereInt64("parentId", reindexer.EQ, pids...)
		} else {
			q.Where("dummy", reindexer.EQ, "dummy")
		}
	}

	// Attributes
	if option.IsHasSubordinatesRequested {
		q.Select("isContainer")
	}

	iter := q.
		ReqTotal().
		Limit(int(option.PageSize)).
		Offset(int(option.Offset)).
		ExecCtx(ctx)
	defer iter.Close()

	if iter.Error() != nil {
		return reportError(iter.Error())
	}

	maxCnt := iter.TotalCount()
	cnt := iter.Count()

	// time.Sleep(10 * time.Second)

	for iter.Next() {
		dest, ok := iter.Object().(*CacheEntry)
		if !ok {
			return reportError(errors.Errorf("Unexpected type in the cache: %v", iter.Object()))
		}

		dnOrig, err := r.toDNOrigWithSuffixRDN(ctx, dest.ID)
		if err != nil {
			return reportError(err)
		}

		entry := NewSearchEntry(r.schemaRegistry, dnOrig, dest.AttrsOrig)

		if option.IsHasSubordinatesRequested {
			entry.AttrsOrig()["hasSubordinates"] = []string{strings.ToUpper(strconv.FormatBool(dest.IsContainer))}
		}
		if option.IsMemberOfRequested {
			m, err := r.toDNOrigs(ctx, cacheTx, entry.AttrsOrig()["memberOf"])
			if err != nil {
				return reportError(err)
			}
			entry.AttrsOrig()["memberOf"] = m
		}
		for _, v := range option.RequestedAssocation {
			m, err := r.toDNOrigs(ctx, cacheTx, entry.AttrsOrig()[v])
			if err != nil {
				return reportError(err)
			}
			entry.AttrsOrig()[v] = m
		}

		if err := handler(entry); err != nil {
			return reportError(err)
		}
	}

	return int32(maxCnt), int32(cnt), nil
}

type RDNCache struct {
	ID       int64  `json:"id"`
	ParentID int64  `json:"parentId"`
	RDNOrig  string `json:"rdnOrig"`
}

func (r *DefaultRepository) toDNOrigs(ctx context.Context, cacheTx *reindexer.Tx, ids []string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		log.Printf("info: toDNOrigs: %v", elapsed)
	}()

	var dest RDNCache

	start2 := time.Now()

	iter := cacheTx.Query().
		Select("id", "rdnOrig", "parentId").
		WhereString("id", reindexer.SET, ids...).
		ExecToJsonCtx(ctx)
	defer iter.Close()

	elapsed2 := time.Since(start2)
	log.Printf("info: query: %v", elapsed2)

	dns := []string{}

	for iter.Next() {
		if err := json.Unmarshal(iter.JSON(), &dest); err != nil {
			return nil, errors.Wrapf(err, "Unexpected json unmarshal error")
		}

		dn, err := r.toDNOrig(ctx, cacheTx, &dest)
		if err != nil {
			return nil, err
		}

		dns = append(dns, dn)
	}

	return dns, nil
}

func (r *DefaultRepository) toDNOrigWithSuffixRDN(ctx context.Context, id int64) (string, error) {
	dnCache, _ := ctx.Value(schema.DNCacheContextKey).(*schema.DNCache)

	var rdn []string
	var pid []int64

	result := struct {
		ParentID int64  `json:"parentId"`
		RDNOrig  string `json:"rdnOrig"`
	}{}

	for {
		iter := r.query().
			Select("parentId", "rdnOrig").
			WhereInt64("id", reindexer.EQ, id).
			Limit(1).
			ExecToJsonCtx(ctx)
		defer iter.Close()
		if iter.Error() != nil {
			return "", iter.Error()
		}

		if !iter.Next() {
			// Not found
			return "", nil
		}

		if err := json.Unmarshal(iter.JSON(), &result); err != nil {
			return "", xerrors.Errorf("Failed to fetch by id = %d. err: %w", id, err)
		}

		// It's Root, end loop
		if result.ParentID == 0 {
			// TODO Support multiple suffix
			rdn = append(rdn, r.schemaRegistry.Config.Suffix)
			break
		} else {
			rdn = append(rdn, result.RDNOrig)
		}

		if pdn, ok := dnCache.Itoao[result.ParentID]; ok {
			return strings.Join(rdn, ",") + "," + pdn, nil
		}

		id = result.ParentID
		pid = append(pid, id)
	}

	dn := strings.Join(rdn, ",")

	if len(pid) > 0 {
		parentId := pid[0]
		parentDN := strings.Join(rdn[1:], ",")

		// Cache Parent Container DN
		dnCache.Itoao[parentId] = parentDN
	}

	return dn, nil
}

func (r *DefaultRepository) toDNOrig(ctx context.Context, cacheTx *reindexer.Tx, rdn *RDNCache) (string, error) {
	// start := time.Now()
	// defer func() {
	// 	elapsed := time.Since(start)
	// 	log.Printf("debug: toDN: %v", elapsed)
	// }()

	dnCache, _ := ctx.Value(schema.DNCacheContextKey).(*schema.DNCache)
	// if v, ok := dnCache.itoa[id]; ok {
	// 	return v, nil
	// }

	rdns := []string{rdn.RDNOrig}
	pids := []int64{rdn.ParentID}

	dest := struct {
		ParentID int64  `json:"parentId"`
		RDNOrig  string `json:"rdnOrig"`
	}{}

	nextID := rdn.ParentID

	for {
		if pdn, ok := dnCache.Itoao[nextID]; ok {
			return strings.Join(rdns, ",") + "," + pdn, nil
		}

		iter := cacheTx.Query().
			Select("parentId", "rdnOrig").
			WhereInt64("id", reindexer.EQ, nextID).
			Limit(1).
			ExecToJsonCtx(ctx)
		defer iter.Close()

		if !iter.Next() {
			// Not found
			return "", errors.Errorf("Detected inconsistency. Not found entry. id: %d", nextID)
		}

		if err := json.Unmarshal(iter.JSON(), &dest); err != nil {
			return "", errors.Wrapf(err, "Failed to fetch by id = %d", nextID)
		}

		// It's Root, end loop
		if dest.ParentID == nextID {
			break
		}

		if dest.ParentID == 0 {
			// TODO Support multiple suffix
			rdns = append(rdns, r.schemaRegistry.Config.Suffix)
		} else {
			rdns = append(rdns, dest.RDNOrig)
		}
		nextID = dest.ParentID
		pids = append(pids, nextID)
	}

	dn := strings.Join(rdns, ",")

	if len(pids) > 0 {
		parentId := pids[0]

		// Cache Parent Container DNOrig
		dnCache.Itoao[parentId] = strings.Join(rdns[1:], ",")
	}

	return dn, nil
}

func (r *DefaultRepository) findChildContainerIDs(ctx context.Context, cacheTx *reindexer.Tx, id int64) ([]int64, error) {
	pids := []int64{}
	iter := cacheTx.Query().
		Select("id").
		WhereInt64("path", reindexer.SET, id).
		ExecToJsonCtx(ctx)
	defer iter.Close()
	for iter.Next() {
		var dest struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(iter.JSON(), &dest); err != nil {
			iter.Close()
			return nil, errors.Wrap(err, "Unexpected unmarshal error")
		}
		pids = append(pids, dest.ID)
	}
	return pids, nil
}
