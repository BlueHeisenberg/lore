// Package store is lore's local SQLite store (modernc.org/sqlite, WAL):
// spaces, entries with FTS5 search, member docs, sync bookkeeping.
// Schema and canonical signing encoding are pinned by docs/IMPLEMENTATION.md.
package store

import (
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// Typed errors for the hard rules enforced at the store layer.
var (
	// ErrPersonalSpace: the personal space never accepts members.
	ErrPersonalSpace = errors.New("personal space cannot have members added")
	// ErrUserModel: profile/ and feedback/ entries never leave the personal space.
	ErrUserModel = errors.New("user-model entries (profile/, feedback/) cannot be copied out of the personal space")
	// ErrNotFound: entry or space does not exist.
	ErrNotFound = errors.New("not found")
	// ErrNoSigner: a write was attempted on a store opened without keys.
	ErrNoSigner = errors.New("store opened without a signer; writes unavailable")
)

// Signer carries the identity used to author local writes.
type Signer struct {
	AccountID  string // hex account signing pubkey
	DeviceID   string // hex device pubkey
	DevicePriv ed25519.PrivateKey
}

// Store wraps the SQLite database.
type Store struct {
	db     *sql.DB
	signer *Signer
}

const schemaVersion = 1

const schema = `
CREATE TABLE IF NOT EXISTS spaces(
  space_id TEXT PRIMARY KEY, kind TEXT CHECK(kind IN ('personal','shared')),
  name TEXT, project_ref TEXT, space_key BLOB,
  pinned INTEGER DEFAULT 0, created_at TEXT);
CREATE TABLE IF NOT EXISTS member_docs(
  space_id TEXT, version INTEGER, doc TEXT, sig TEXT, signer TEXT,
  PRIMARY KEY(space_id, version));
CREATE TABLE IF NOT EXISTS entries(
  entry_id TEXT PRIMARY KEY, space_id TEXT, domain TEXT, title TEXT, body TEXT,
  markers TEXT,
  confidence TEXT CHECK(confidence IN ('experimental','provisional','validated','hardened')),
  origin TEXT CHECK(origin IN ('evidence','directive','convention','constraint')),
  author_account TEXT, author_device TEXT,
  created_at TEXT, updated_at TEXT,
  version INTEGER,
  device_seq INTEGER,
  origin_device TEXT,
  signature TEXT,
  provenance TEXT,
  tombstone INTEGER DEFAULT 0);
CREATE VIRTUAL TABLE IF NOT EXISTS entry_fts USING fts5(title, body, domain, content=entries, content_rowid=rowid);
CREATE TRIGGER IF NOT EXISTS entries_ai AFTER INSERT ON entries BEGIN
  INSERT INTO entry_fts(rowid, title, body, domain) VALUES (new.rowid, new.title, new.body, new.domain);
END;
CREATE TRIGGER IF NOT EXISTS entries_ad AFTER DELETE ON entries BEGIN
  INSERT INTO entry_fts(entry_fts, rowid, title, body, domain) VALUES ('delete', old.rowid, old.title, old.body, old.domain);
END;
CREATE TRIGGER IF NOT EXISTS entries_au AFTER UPDATE ON entries BEGIN
  INSERT INTO entry_fts(entry_fts, rowid, title, body, domain) VALUES ('delete', old.rowid, old.title, old.body, old.domain);
  INSERT INTO entry_fts(rowid, title, body, domain) VALUES (new.rowid, new.title, new.body, new.domain);
END;
CREATE TABLE IF NOT EXISTS attachments(
  blob_hash TEXT, entry_id TEXT, filename TEXT, source TEXT, size INTEGER,
  PRIMARY KEY(blob_hash, entry_id));
CREATE TABLE IF NOT EXISTS peers(device_id TEXT PRIMARY KEY, account_pub TEXT, name TEXT,
  addr TEXT, static INTEGER DEFAULT 0, last_seen TEXT);
CREATE TABLE IF NOT EXISTS sync_state(space_id TEXT, device_id TEXT, max_seq INTEGER,
  PRIMARY KEY(space_id, device_id));
CREATE TABLE IF NOT EXISTS relay_state(space_id TEXT PRIMARY KEY, log_offset INTEGER);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
`

// Open opens (creating and migrating as needed) the lore database at path,
// in WAL mode. signer may be nil for read-only use; writes then fail with
// ErrNoSigner.
func Open(path string, signer *Signer) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + url.PathEscape(filepath.ToSlash(path)) +
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// modernc sqlite: serialize access through one connection.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, signer: signer}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT)`); err != nil {
		return err
	}
	var v int
	err := s.db.QueryRow(`SELECT CAST(v AS INTEGER) FROM kv WHERE k='schema_version'`).Scan(&v)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if v >= schemaVersion {
		return nil
	}
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate schema: %w", err)
	}
	_, err = s.db.Exec(`INSERT INTO kv(k,v) VALUES('schema_version',?)
		ON CONFLICT(k) DO UPDATE SET v=excluded.v`, fmt.Sprint(schemaVersion))
	return err
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// Space is the sharing unit; see docs/ARCHITECTURE.md.
type Space struct {
	SpaceID    string
	Kind       string // personal | shared
	Name       string
	ProjectRef string
	SpaceKey   []byte
	Pinned     bool
	CreatedAt  string
}

// CreateSpace inserts a new space. kind must be "personal" or "shared";
// only one personal space may exist. key is the 32-byte space_key
// (generate with internal/space.NewSpaceKey).
func (s *Store) CreateSpace(kind, name, projectRef string, key []byte) (Space, error) {
	if kind != "personal" && kind != "shared" {
		return Space{}, fmt.Errorf("invalid space kind %q", kind)
	}
	if kind == "personal" {
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM spaces WHERE kind='personal'`).Scan(&n); err != nil {
			return Space{}, err
		}
		if n > 0 {
			return Space{}, errors.New("personal space already exists")
		}
	}
	sp := Space{
		SpaceID:    uuid.NewString(),
		Kind:       kind,
		Name:       name,
		ProjectRef: projectRef,
		SpaceKey:   key,
		CreatedAt:  nowTS(),
	}
	_, err := s.db.Exec(`INSERT INTO spaces(space_id,kind,name,project_ref,space_key,pinned,created_at)
		VALUES(?,?,?,?,?,0,?)`,
		sp.SpaceID, sp.Kind, sp.Name, sp.ProjectRef, sp.SpaceKey, sp.CreatedAt)
	if err != nil {
		return Space{}, err
	}
	return sp, nil
}

func scanSpaces(rows *sql.Rows) ([]Space, error) {
	defer rows.Close()
	var out []Space
	for rows.Next() {
		var sp Space
		var ref sql.NullString
		var pinned int
		if err := rows.Scan(&sp.SpaceID, &sp.Kind, &sp.Name, &ref, &sp.SpaceKey, &pinned, &sp.CreatedAt); err != nil {
			return nil, err
		}
		sp.ProjectRef = ref.String
		sp.Pinned = pinned != 0
		out = append(out, sp)
	}
	return out, rows.Err()
}

const spaceCols = `space_id,kind,name,project_ref,space_key,pinned,created_at`

// ListSpaces returns all spaces, personal first, then by name.
func (s *Store) ListSpaces() ([]Space, error) {
	rows, err := s.db.Query(`SELECT ` + spaceCols + ` FROM spaces
		ORDER BY kind='personal' DESC, name`)
	if err != nil {
		return nil, err
	}
	return scanSpaces(rows)
}

func (s *Store) spaceWhere(where string, args ...any) (Space, error) {
	rows, err := s.db.Query(`SELECT `+spaceCols+` FROM spaces WHERE `+where, args...)
	if err != nil {
		return Space{}, err
	}
	sps, err := scanSpaces(rows)
	if err != nil {
		return Space{}, err
	}
	if len(sps) == 0 {
		return Space{}, ErrNotFound
	}
	return sps[0], nil
}

// GetSpace returns a space by id.
func (s *Store) GetSpace(spaceID string) (Space, error) {
	return s.spaceWhere(`space_id=?`, spaceID)
}

// SpaceByName returns a space by name.
func (s *Store) SpaceByName(name string) (Space, error) {
	return s.spaceWhere(`name=?`, name)
}

// SpaceByProjectRef returns the project space for a project_ref.
func (s *Store) SpaceByProjectRef(ref string) (Space, error) {
	return s.spaceWhere(`project_ref=?`, ref)
}

// PersonalSpace returns the (single) personal space.
func (s *Store) PersonalSpace() (Space, error) {
	return s.spaceWhere(`kind='personal'`)
}

// AddMember appends a signed member-list document to a shared space.
// Personal spaces refuse with ErrPersonalSpace — enforced here, not in the CLI.
func (s *Store) AddMember(spaceID, doc, sig, signer string) error {
	sp, err := s.GetSpace(spaceID)
	if err != nil {
		return err
	}
	if sp.Kind == "personal" {
		return ErrPersonalSpace
	}
	_, err = s.db.Exec(`INSERT INTO member_docs(space_id,version,doc,sig,signer)
		VALUES(?, COALESCE((SELECT MAX(version) FROM member_docs WHERE space_id=?),0)+1, ?,?,?)`,
		spaceID, spaceID, doc, sig, signer)
	return err
}

// userModelLayer reports whether a domain belongs to the non-shareable
// user-model layers (profile/, feedback/).
func userModelLayer(domain string) bool {
	layer, _, _ := strings.Cut(domain, "/")
	return layer == "profile" || layer == "feedback"
}

func nowTS() string { return tsNow() }
