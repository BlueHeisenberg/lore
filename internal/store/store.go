// Package store is lore's local SQLite store (modernc.org/sqlite, WAL):
// spaces, entries with FTS5 search, member docs, sync bookkeeping.
// Schema and canonical signing encoding are pinned by docs/IMPLEMENTATION.md.
package store

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/google/uuid"
	"modernc.org/sqlite"
)

// Typed errors for the hard rules enforced at the store layer.
var (
	// ErrPersonalSpace: the personal space never accepts members.
	ErrPersonalSpace = errors.New("personal space cannot have members added")
	// ErrUserModel: profile/ and feedback/ entries never leave the personal space.
	ErrUserModel = errors.New("user-model entries (profile/, feedback/) cannot be copied out of the personal space")
	// ErrNotFound: entry or space does not exist.
	ErrNotFound = errors.New("not found")
	// ErrSpaceNotFound: this store holds no such space. It wraps ErrNotFound
	// so callers that only care "missing" keep working, while callers that
	// must tell a missing space from a missing entry (a configuration fault
	// versus a missing record) can ask for it specifically.
	ErrSpaceNotFound = fmt.Errorf("space %w", ErrNotFound)
	// ErrSchemaTooNew: the database was written by a newer lore than this
	// build. Refused at Open rather than tolerated: migrate used to return
	// early for any v >= schemaVersion, so an older build would silently read
	// a newer schema's columns.
	ErrSchemaTooNew = errors.New("database schema is newer than this build")
	// ErrNoSigner: a write was attempted on a store opened without keys.
	ErrNoSigner = errors.New("store opened without a signer; writes unavailable")
	// ErrNotWriter: this account lacks the writer/owner role required to
	// author entries in the shared space (per its verified member list).
	ErrNotWriter = errors.New("this account is not a writer/owner of the space")
	// ErrWrongSpace: the entry exists, but not in the space the caller named.
	// Entry ids are global, so every operation that names both an id and a
	// space refuses the mismatch instead of acting on the other space.
	ErrWrongSpace = errors.New("entry is not in that space")
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
	if v > schemaVersion {
		return fmt.Errorf("%w: database is at v%d, this build understands v%d",
			ErrSchemaTooNew, v, schemaVersion)
	}
	if v == schemaVersion {
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

// IsBusy reports whether err is SQLite's "database is locked" (SQLITE_BUSY /
// SQLITE_LOCKED, extended codes masked off). Lives here because this package
// owns the driver: nothing above it should have to know which SQLite binding
// is in use to recognise contention.
//
// Contention is real and by design: `lore serve`, internal/syncproto's second
// connection and any CLI invocation open the same lore.db. WAL plus
// busy_timeout absorbs most of it, but a deferred transaction upgrading from
// read to write gets SQLITE_BUSY immediately — busy_timeout does not retry an
// upgrade.
func IsBusy(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code() & 0xff {
	case 5, 6: // SQLITE_BUSY, SQLITE_LOCKED
		return true
	}
	return false
}

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

// CreateSharedSpace creates a shared space end to end: a fresh space_key, the
// space row, and signed member-list v1 naming this store's signing account as
// sole owner, with its wrapped copy of the space_key inside.
//
// The two rows go in one transaction. A space row without member-list v1 is a
// space nobody can prove they own — it cannot be invited into (Evolve needs a
// previous doc) and everyone who holds it may write to it — so a half-applied
// creation is worse than no creation at all.
//
// accountEncPub and accountPriv are the account's X25519 encryption pubkey and
// its Ed25519 signing key. The owner is the signer's account, so a store can
// only create a space it owns; without a signer this is ErrNoSigner.
func (s *Store) CreateSharedSpace(name, projectRef, accountEncPub string, accountPriv ed25519.PrivateKey) (Space, error) {
	if s.signer == nil {
		return Space{}, ErrNoSigner
	}
	key, err := space.NewSpaceKey()
	if err != nil {
		return Space{}, err
	}
	wrapped, err := space.WrapSpaceKey(key, accountEncPub)
	if err != nil {
		return Space{}, err
	}
	sp := Space{
		SpaceID:    uuid.NewString(),
		Kind:       "shared",
		Name:       name,
		ProjectRef: projectRef,
		SpaceKey:   key,
		CreatedAt:  nowTS(),
	}
	doc, err := space.NewMemberDoc(sp.SpaceID, space.Member{
		AccountPub:      s.signer.AccountID,
		EncPub:          accountEncPub,
		Role:            space.RoleOwner,
		WrappedSpaceKey: wrapped,
	}, accountPriv)
	if err != nil {
		return Space{}, err
	}
	docJSON, err := doc.DocJSON()
	if err != nil {
		return Space{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Space{}, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO spaces(space_id,kind,name,project_ref,space_key,pinned,created_at)
		VALUES(?,?,?,?,?,0,?)`,
		sp.SpaceID, sp.Kind, sp.Name, sp.ProjectRef, sp.SpaceKey, sp.CreatedAt); err != nil {
		return Space{}, err
	}
	if _, err := tx.Exec(`INSERT INTO member_docs(space_id,version,doc,sig,signer) VALUES(?,1,?,?,?)`,
		sp.SpaceID, docJSON, doc.Sig, doc.SignedBy); err != nil {
		return Space{}, err
	}
	if err := tx.Commit(); err != nil {
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
		return Space{}, ErrSpaceNotFound
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

// AddMemberDoc appends a signed, versioned member doc built by internal/
// space. It enforces the personal-space refusal and that the doc's version
// is exactly the next one for the space (the chain rule needs contiguity).
func (s *Store) AddMemberDoc(spaceID string, d space.MemberDoc) error {
	sp, err := s.GetSpace(spaceID)
	if err != nil {
		return err
	}
	if sp.Kind == "personal" {
		return ErrPersonalSpace
	}
	if d.SpaceID != spaceID {
		return fmt.Errorf("member doc names space %s, expected %s", d.SpaceID, spaceID)
	}
	doc, err := d.DocJSON()
	if err != nil {
		return err
	}
	var maxV int64
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM member_docs WHERE space_id=?`,
		spaceID).Scan(&maxV); err != nil {
		return err
	}
	if d.Version != maxV+1 {
		return fmt.Errorf("member doc version %d, expected %d", d.Version, maxV+1)
	}
	_, err = s.db.Exec(`INSERT INTO member_docs(space_id,version,doc,sig,signer) VALUES(?,?,?,?,?)`,
		spaceID, d.Version, doc, d.Sig, d.SignedBy)
	return err
}

// RawMemberDocs returns the stored member-doc rows for a space, oldest first,
// in the shape internal/space's chain verification consumes.
func (s *Store) RawMemberDocs(spaceID string) ([]space.RawDoc, error) {
	rows, err := s.db.Query(`SELECT version, doc, sig FROM member_docs
		WHERE space_id=? ORDER BY version`, spaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []space.RawDoc
	for rows.Next() {
		var r space.RawDoc
		if err := rows.Scan(&r.Version, &r.Doc, &r.Sig); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LatestMemberDoc returns the newest VERIFIED member doc of a space
// (ok=false when the space has none, or none verify).
func (s *Store) LatestMemberDoc(spaceID string) (space.MemberDoc, bool, error) {
	raws, err := s.RawMemberDocs(spaceID)
	if err != nil {
		return space.MemberDoc{}, false, err
	}
	d, ok := space.LatestDoc(spaceID, raws)
	return d, ok, nil
}

// SetPinned marks/unmarks a space as pinned (pinned spaces join the default
// search scope).
func (s *Store) SetPinned(spaceID string, pinned bool) error {
	res, err := s.db.Exec(`UPDATE spaces SET pinned=? WHERE space_id=?`, boolInt(pinned), spaceID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// linksKey is the kv key holding a space's project links.
func linksKey(spaceID string) string { return "links:" + spaceID }

// Links returns the space ids linked from a space (retrieval hints only —
// callers must still filter to spaces actually present locally).
func (s *Store) Links(spaceID string) ([]string, error) {
	var v string
	err := s.db.QueryRow(`SELECT v FROM kv WHERE k=?`, linksKey(spaceID)).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	if err := json.Unmarshal([]byte(v), &out); err != nil {
		return nil, fmt.Errorf("links for %s: %w", spaceID, err)
	}
	return out, nil
}

// AddLink records that searches scoped to fromSpaceID should also consult
// toSpaceID. A link is a retrieval hint, never an access grant.
func (s *Store) AddLink(fromSpaceID, toSpaceID string) error {
	if fromSpaceID == toSpaceID {
		return errors.New("a space cannot link to itself")
	}
	if _, err := s.GetSpace(toSpaceID); err != nil {
		return fmt.Errorf("link target %s: %w", toSpaceID, err)
	}
	links, err := s.Links(fromSpaceID)
	if err != nil {
		return err
	}
	for _, l := range links {
		if l == toSpaceID {
			return nil // already linked
		}
	}
	links = append(links, toSpaceID)
	b, err := json.Marshal(links)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO kv(k,v) VALUES(?,?)
		ON CONFLICT(k) DO UPDATE SET v=excluded.v`, linksKey(fromSpaceID), string(b))
	return err
}

// userModelLayer reports whether a domain belongs to the non-shareable
// user-model layers (profile/, feedback/).
func userModelLayer(domain string) bool {
	layer, _, _ := strings.Cut(domain, "/")
	return layer == "profile" || layer == "feedback"
}

func nowTS() string { return tsNow() }
