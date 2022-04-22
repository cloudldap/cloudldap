package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cloudldap/cloudldap/schema"
	"github.com/cloudldap/goldap/message"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"golang.org/x/xerrors"

	"github.com/restream/reindexer"
	// choose how the Reindexer binds to the app (in this case "builtin," which means link Reindexer as a static library)
	_ "github.com/restream/reindexer/bindings/builtin"
)

// For generic filter
type StmtCache struct {
	sm sync.Map
}

func (m *StmtCache) Get(key string) (*sqlx.NamedStmt, bool) {
	val, ok := m.sm.Load(key)
	if !ok {
		return nil, false
	}
	return val.(*sqlx.NamedStmt), true
}

func (m *StmtCache) Put(key string, value *sqlx.NamedStmt) {
	m.sm.Store(key, value)
}

type DBRepository struct {
	db             *sqlx.DB
	cacheDB        *reindexer.Reindexer
	schemaRegistry *schema.SchemaRegistry
	serverID       string
	config         *DBRepositoryConfig
}

type DBRepositoryConfig struct {
	DBHostName     string
	DBPort         int
	DBUser         string
	DBPassword     string
	DBSchema       string
	DBName         string
	DBMaxOpenConns int
	DBMaxIdleConns int
	ServerID       string
	LogLevel       string
}

func NewRepository(config *DBRepositoryConfig, sr *schema.SchemaRegistry) (Repository, error) {
	cacheDB := reindexer.NewReindex("builtin:///tmp/cloudldap")
	err := cacheDB.OpenNamespace("entries", reindexer.DefaultNamespaceOptions().NoStorage(), CacheEntry{})
	if err != nil {
		log.Fatalf("alert: Open cacheDB error. err: %v", err)
	}

	// Init DB Connection
	connInfo := fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=disable search_path=%s",
		config.DBHostName, config.DBPort, config.DBUser, config.DBName,
		config.DBPassword, config.DBSchema)
	db, err := sqlx.Connect("postgres", connInfo)
	if err != nil {
		log.Fatalf("alert: Connect error. host=%s, port=%d, user=%s, dbname=%s, error=%s",
			config.DBHostName, config.DBPort, config.DBUser, config.DBName, err)
	}
	db.SetMaxOpenConns(config.DBMaxOpenConns)
	db.SetMaxIdleConns(config.DBMaxIdleConns)
	// db.SetConnMaxLifetime(time.Hour)

	// TODO: Enable to switch another implementation
	repo := &DefaultRepository{
		DBRepository: &DBRepository{
			db:             db,
			cacheDB:        cacheDB,
			schemaRegistry: sr,
			config:         config,
		},
	}

	err = repo.Init()
	if err != nil {
		return nil, err
	}

	// Start listener
	reportErr := func(ev pq.ListenerEventType, err error) {
		if err != nil {
			log.Printf("alert: Failed to start listener: %s", err)
		}
	}
	minReconn := 10 * time.Second
	maxReconn := time.Minute
	listener := pq.NewListener(connInfo, minReconn, maxReconn, reportErr)
	err = listener.Listen("entry_update")
	if err != nil {
		log.Fatalf("alert: Failed to LISTEN to channel 'entry_update': %v", err)
	}

	log.Printf("info: Listening to notifications on channel 'entry_update'")

	go func() {
		timeout := 1 * time.Minute

		for {
			log.Println("Waiting for notification...")

			select {
			case n := <-listener.Notify:
				if n == nil {
					log.Printf("error: Invalid notify message: %v", n)
					continue
				}
				var m NotifyMessage
				err := json.Unmarshal([]byte(n.Extra), &m)
				if err != nil {
					log.Printf("error: Failed to parse '%s': %v", n.Extra, err)
					continue
				}
				log.Printf("debug: Received event: %v", m)

				if m.Issuer == config.ServerID {
					log.Printf("debug: Skip own message: %v", m)
					continue
				}

				if err := repo.OnUpdate(context.Background(), &m); err != nil {
					log.Printf("error: Error on update for '%s': %v", n.Extra, err)
				}

			case <-time.After(timeout):
				log.Printf("Received no events for %s, checking connection", timeout.String())
				go func() {
					_ = listener.Ping()
				}()
			}
		}
	}()

	return repo, nil
}

type Repository interface {
	// Init is called when initializing repository implementation.
	Init() error

	// Bind fetches the current bind entry by specified DN. Then execute callback with the entry.
	// The callback is expected checking the credential, account lock status and so on.
	// This is used for BIND operation.
	Bind(ctx context.Context, dn *schema.DN, callback func(current *FetchedCredential) error) error

	// FindPPolicyByDN returns the password policy entry by specified DN.
	// This is used for password policy process.
	FindPPolicyByDN(ctx context.Context, dn *schema.DN) (*schema.PPolicy, error)

	// Search handles search request by filter.
	// This is used for SEARCH operation.
	Search(ctx context.Context, baseDN *schema.DN, option *SearchOption, handler func(entry *SearchEntry) error) (int32, int32, error)

	// Update modifies the entry by specified change data.
	// This is used for MOD operation.
	Update(ctx context.Context, dn *schema.DN, callback func(attrsOrig AttrsOrig) (*Changelog, error)) error

	// Association resolves the association related attributes in the attributes.
	// This is used for MOD operation.
	Association(ctx context.Context, sv *schema.SchemaValue) (*schema.SchemaValue, error)

	// UpdateRDN modifies the entry DN by specified change data.
	// This is used for MODRDN operation.
	UpdateDN(ctx context.Context, oldDN, newDN *schema.DN, oldRDN *schema.RelativeDN, callback func(attrsOrig AttrsOrig) (*Changelog, error)) error

	// Insert creates the entry by specified entry data.
	Insert(ctx context.Context, entry *Changelog) (int64, error)

	// DeleteByDN deletes the entry by specified DN.
	DeleteByDN(ctx context.Context, dn *schema.DN) error

	OnUpdate(ctx context.Context, m *NotifyMessage) error
}

type AttrsOrig map[string][]string

type SearchOption struct {
	Scope                      int
	Filter                     message.Filter
	PageSize                   int32
	Offset                     int32
	RequestedAssocation        []string
	IsMemberOfRequested        bool
	IsHasSubordinatesRequested bool
}

type SearchEntry struct {
	schema    *schema.SchemaRegistry
	dnOrig    string
	attrsOrig CacheAttrsOrig
}

func NewSearchEntry(s *schema.SchemaRegistry, dnOrig string, attrsOrig CacheAttrsOrig) *SearchEntry {
	readEntry := &SearchEntry{
		schema:    s,
		dnOrig:    dnOrig,
		attrsOrig: attrsOrig,
	}
	return readEntry
}

func (s *SearchEntry) DNOrig() string {
	return s.dnOrig
}

func (s *SearchEntry) AttrsOrig() CacheAttrsOrig {
	return s.attrsOrig
}

func (s *SearchEntry) AttrOrig(attrName string) (string, []string, bool) {
	at, ok := s.schema.AttributeType(attrName)
	if !ok {
		return "", nil, false
	}

	v, ok := s.attrsOrig[at.Name]
	if !ok {
		return "", nil, false
	}
	return at.Name, v, true
}

func (s *SearchEntry) AttrsOrigWithoutOperationalAttrs() AttrsOrig {
	m := make(AttrsOrig)
	for k, v := range s.attrsOrig {
		if s, ok := s.schema.AttributeType(k); ok {
			if !s.IsOperationalAttribute() {
				m[k] = v
			}
		}
	}
	return m
}

func (s *SearchEntry) OperationalAttrsOrig() AttrsOrig {
	m := make(AttrsOrig)
	for k, v := range s.attrsOrig {
		if s, ok := s.schema.AttributeType(k); ok {
			if s.IsOperationalAttribute() {
				m[k] = v
			}
		}
	}
	return m
}

type FetchedDNOrig struct {
	ID     int64  `db:"id"`
	DNOrig string `db:"dn_orig"`
}

type FetchedCredential struct {
	ID int64
	// Credential
	Credential []string
	// DN of the MemberOf
	MemberOf []*schema.DN
	// PPolicy related to this entry
	PPolicy              *schema.PPolicy
	PwdAccountLockedTime *time.Time
	LastPwdFailureTime   *time.Time
	PwdFailureCount      int
}

type NotifyOp string

const (
	NotifyAdd    NotifyOp = "add"
	NotifyMod    NotifyOp = "mod"
	NotifyModRDN NotifyOp = "modrdn"
	NotifyDel    NotifyOp = "del"
)

type NotifyMessage struct {
	Issuer      string   `json:"iss"`
	ID          int64    `json:"id"`
	Op          NotifyOp `json:"op"`
	Rev         int64    `json:"rev"`
	Association bool     `json:"asc"`
	Dependant   []int64  `json:"dep"`
	Sub         bool     `json:"sub"`
}

func (n *NotifyMessage) IsAdd() bool {
	return n.Op == NotifyAdd
}

func (n *NotifyMessage) IsMod() bool {
	return n.Op == NotifyMod || n.Op == NotifyModRDN
}

func (n *NotifyMessage) IsDel() bool {
	return n.Op == NotifyDel
}

func withDBTx(ctx context.Context, db *sqlx.DB, callback func(dbTx *sqlx.Tx) error) error {
	tx, err := db.BeginTxx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return xerrors.Errorf("Failed to begin DB transaction. err: %w", err)
	}

	err = callback(tx)
	if err != nil {
		rollback(tx)
		return xerrors.Errorf("DB transaction is rollbacked. err: %w", err)
	}

	if err := commit(tx); err != nil {
		return xerrors.Errorf("Failed to commit DB transaction. err: %w", err)
	}

	return nil
}

func rollbackCache(tx *reindexer.Tx) {
	err := tx.Rollback()
	if err != nil {
		log.Printf("warn: Detect error when rollback cache, ignore it. err: %v", err)
	}
}

func commitCache(tx *reindexer.Tx) error {
	err := tx.Commit()
	if err != nil {
		log.Printf("warn: Detect error when commit cache, do rollback. err: %v", err)
		rollbackCache(tx)
	}
	return errors.Wrap(err, "Failed to commit cache")
}

func rollback(tx *sqlx.Tx) {
	err := tx.Rollback()
	if err != nil {
		log.Printf("warn: Detect error when rollback DB, ignore it. err: %v", err)
	}
}

func commit(tx *sqlx.Tx) error {
	err := tx.Commit()
	if err != nil {
		log.Printf("warn: Detect error when commit DB, do rollback. err: %v", err)
		rollback(tx)
	}
	return errors.Wrap(err, "Failed to commit DB")
}
