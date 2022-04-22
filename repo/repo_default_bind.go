package repo

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/cloudldap/cloudldap/schema"
	"github.com/cloudldap/cloudldap/util"
	"github.com/restream/reindexer"
	"golang.org/x/xerrors"
)

// Bind fetches the current bind entry by specified DN. Then execute callback with the entry.
// The callback is expected checking the credential, account lock status and so on.
// This is used for BIND operation.
func (r *DefaultRepository) Bind(ctx context.Context, dn *schema.DN, callback func(current *FetchedCredential) error) error {
	id, err := r.findEntryID(ctx, dn)
	if err != nil {
		return util.NewInvalidCredentials()
	}

	jsonEntry, err := r.findAttrsNormByID(ctx, id)
	if err != nil {
		return util.NewInvalidCredentials()
	}

	var pwdAccountLockedTime time.Time

	if len(jsonEntry["pwdAccountLockedTime"]) > 0 {
		pwdAccountLockedTime, err = time.Parse(schema.TIMESTAMP_FORMAT, jsonEntry.ValueStr("pwdAccountLockedTime")[0])
		if err != nil {
			return xerrors.Errorf("Failed to parse pwdAccountLockedTime. dn_orig: %s, err: %w", dn.DNOrigStr(), err)
		}
	}

	var lastPwdFailureTime *time.Time
	var currentPwdFailureTime []*time.Time

	if len(jsonEntry["pwdFailureTime"]) > 0 {
		for _, v := range jsonEntry.ValueStr("pwdFailureTime") {
			t, err := time.Parse(schema.TIMESTAMP_NANO_FORMAT, v)
			if err != nil {
				return xerrors.Errorf("Failed to parse pwdFailureTime. dn_orig: %s, err: %w", dn.DNOrigStr(), err)
			}
			if lastPwdFailureTime == nil {
				lastPwdFailureTime = &t
			} else {
				if t.After(*lastPwdFailureTime) {
					lastPwdFailureTime = &t
				}
			}
			currentPwdFailureTime = append(currentPwdFailureTime, &t)
		}
	}

	// Fetch ppolicy
	ppolicy, err := r.FindPPolicyByDN(ctx, dn)
	if err != nil {
		return xerrors.Errorf("Failed to fetch ppolicy. dn_orig: %s, err: %w", dn.DNOrigStr(), err)
	}

	memberOf := []*schema.DN{}
	for _, v := range jsonEntry.ValueInt64("memberOf") {
		dn, _ := r.toDNWithSuffixRDN(ctx, v)
		if dn != nil {
			memberOf = append(memberOf, dn)
		}
	}

	fc := &FetchedCredential{
		ID:                   id,
		Credential:           jsonEntry.ValueStr("userPassword"),
		MemberOf:             memberOf,
		PPolicy:              ppolicy,
		PwdAccountLockedTime: &pwdAccountLockedTime,
		LastPwdFailureTime:   lastPwdFailureTime,
		PwdFailureCount:      len(jsonEntry["pwdFailureTime"]),
	}

	// Call the callback implemented bind logic
	callbackErr := callback(fc)

	// After bind, record the results into DB
	if callbackErr != nil {
		var lerr *util.LDAPError
		isLDAPError := xerrors.As(callbackErr, &lerr)
		if !isLDAPError || !lerr.IsInvalidCredentials() {
			return err
		}

		if lerr.IsAccountLocked() {
			log.Printf("Account is locked, dn_norm: %s", dn.DNNormStr())
			return callbackErr
		}

		if ppolicy.IsLockoutEnabled() {
			// ft := time.Now()

			// var ltn, lto types.JSONText

			// if lerr.IsAccountLocking() {
			// 	// Record pwdAccountLockedTime to lock it
			// 	ltn, lto = timeToJSONAttrs(TIMESTAMP_FORMAT, &ft)
			// } else {
			// 	// Clear pwdAccountLockedTime
			// 	ltn, lto = emptyJSONArray()
			// }

			// currentPwdFailureTime = append(currentPwdFailureTime, &ft)
			// over := len(currentPwdFailureTime) - fc.PPolicy.MaxFailure()
			// if over > 0 {
			// 	currentPwdFailureTime = currentPwdFailureTime[over:]
			// }
			// ftn, fto := timesToJSONAttrs(TIMESTAMP_NANO_FORMAT, currentPwdFailureTime)

			// Don't rollback, commit the transaction.
			// if _, err := r.exec(tx, updateAfterBindFailureByDN, map[string]interface{}{
			// 	"id":                dest.ID,
			// 	"lock_time_norm":    ltn,
			// 	"lock_time_orig":    lto,
			// 	"failure_time_norm": ftn,
			// 	"failure_time_orig": fto,
			// }); err != nil {
			// 	rollback(tx)
			// 	return xerrors.Errorf("Failed to update entry after bind failure. id: %d, err: %w", dest.ID, err)
			// }
		} else {
			log.Printf("Lockout is disabled, so don't record failure count")
		}
		return callbackErr
	} else {
		// Record authTimestamp, also remove pwdAccountLockedTime and pwdFailureTime
		// n, o := nowTimeToJSONAttrs(TIMESTAMP_FORMAT)

		// if _, err := r.exec(tx, updateAfterBindSuccessByDN, map[string]interface{}{
		// 	"id":                  dest.ID,
		// 	"auth_timestamp_norm": n,
		// 	"auth_timestamp_orig": o,
		// }); err != nil {
		// 	rollback(tx)
		// 	return xerrors.Errorf("Failed to update entry after bind success. id: %d, err: %w", dest.ID, err)
		// }
	}
	return nil
}

// FindPPolicyByDN returns the password policy entry by specified DN.
// This is used for password policy process.
func (r *DefaultRepository) FindPPolicyByDN(ctx context.Context, dn *schema.DN) (*schema.PPolicy, error) {
	// TODO: Support user specific ppolicy

	if r.schemaRegistry.DefaultPPolicyDN.IsAnonymous() {
		return schema.NewDefaultPPolicy(), nil
	}
	id, err := r.findEntryID(ctx, r.schemaRegistry.DefaultPPolicyDN)
	if err != nil {
		if util.IsNoSuchObjectError(err) {
			return schema.NewDefaultPPolicy(), nil
		}
		return nil, xerrors.Errorf("Failed to fetch ppolicy by dn = %s. err: %w", dn.DNNormStr(), err)
	}

	jsonEntry, err := r.findAttrsNormByID(ctx, id)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch ppolicy by dn = %s. err: %w", dn.DNNormStr(), err)
	}

	if jsonEntry == nil {
		// Not found case
		return nil, nil
	}

	ppolicy := &schema.PPolicy{
		PwdAttribute:       jsonEntry.ValueStr("pwdAttribute"),
		PwdLockout:         jsonEntry.ValueStr("PwdLockout"),
		PwdLockoutDuration: jsonEntry.ValueStr("PwdLockoutDuration"),
		PwdMaxFailure:      jsonEntry.ValueStr("PwdMaxFailure"),
	}

	return ppolicy, nil
}

func (r *DefaultRepository) toDNWithSuffixRDN(ctx context.Context, id int64) (*schema.DN, error) {
	// start := time.Now()
	// defer func() {
	// 	elapsed := time.Since(start)
	// 	log.Printf("debug: toDN: %v", elapsed)
	// }()

	dnCache, _ := ctx.Value(schema.DNCacheContextKey).(*schema.DNCache)
	// if v, ok := dnCache.itoa[id]; ok {
	// 	return v, nil
	// }

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
			return nil, iter.Error()
		}

		if !iter.Next() {
			// Not found
			return nil, nil
		}

		if err := json.Unmarshal(iter.JSON(), &result); err != nil {
			return nil, xerrors.Errorf("Failed to fetch by id = %d. err: %w", id, err)
		}

		rdn = append(rdn, result.RDNOrig)

		// It's Root, end loop
		if result.ParentID == 0 {
			break
		}

		if pdn, ok := dnCache.Itoa[result.ParentID]; ok {
			return r.schemaRegistry.NormalizeDN(strings.Join(rdn, ",") + "," + pdn.DNNormStr())
		}

		id = result.ParentID
		pid = append(pid, id)
	}

	dn, err := r.schemaRegistry.NormalizeDN(strings.Join(rdn, ","))
	if err != nil {
		return nil, err
	}

	if len(pid) > 0 {
		parentId := pid[0]

		// Cache Parent Container DN
		dnCache.Itoa[parentId] = dn.ParentDN()
	}

	return dn, nil
}

func (r *DefaultRepository) findAttrsNormByID(ctx context.Context, id int64) (CacheAttrsNorm, error) {
	iter := r.query().
		Select("attrsNorm").
		WhereInt64("id", reindexer.EQ, id).
		Limit(1).
		ExecToJson()
	defer iter.Close()

	if !iter.Next() {
		// Not found
		return nil, nil
	}

	log.Printf("findAttrsNormByID: %v", string(iter.JSON()))

	result := struct {
		AttrsNorm CacheAttrsNorm `json:"attrsNorm"`
	}{}

	d := json.NewDecoder(bytes.NewReader(iter.JSON()))
	d.UseNumber()
	if err := d.Decode(&result); err != nil {
		log.Printf("error: Unexpected unmarshal json error. err: %v", err)
		return nil, xerrors.Errorf("Unexpected unmarshal json error: %w", err)
	}

	return result.AttrsNorm, nil
}
