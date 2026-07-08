// Package relay implements the lore relay server per docs/RELAY.md and
// docs/IMPLEMENTATION.md §Relay: a deliberately dumb host of OPAQUE
// client-encrypted state. Per blinded space id it keeps a compacted
// snapshot plus an append-only delta log; it never parses entry content,
// never sees space names, member lists, real space ids, or usable keys.
//
// State lives in $LORE_RELAY_DATA/relay.db (SQLite, modernc.org/sqlite,
// WAL) and blob files under $LORE_RELAY_DATA/data/<blinded_id>/
// (log/<seq> and snapshot).
package relay

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Typed errors surfaced by the store; handlers map them to HTTP statuses.
var (
	ErrNotFound      = errors.New("not found")
	ErrConflict      = errors.New("conflict")
	ErrForbidden     = errors.New("forbidden")
	ErrQuotaExceeded = errors.New("quota exceeded")
	ErrPlanPolicy    = errors.New("plan policy violation")
	ErrBadInput      = errors.New("bad input")
)

// blindedIDRe: blinded ids are HMAC outputs, hex or base64url on the wire.
// The id doubles as a directory name, so restrict strictly to a filesystem-
// and URL-safe alphabet. 8..128 chars covers hex-encoded HMAC-SHA256 (64).
var blindedIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)

// handleRe pins the handle grammar from the contract.
var handleRe = regexp.MustCompile(`^[a-z0-9-]{3,32}$`)

// pubKeyRe: account/device public keys travel as hex-encoded Ed25519 keys.
var pubKeyRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidBlindedID reports whether s is acceptable as a blinded space id.
func ValidBlindedID(s string) bool { return blindedIDRe.MatchString(s) }

// ValidHandle reports whether s is an acceptable handle.
func ValidHandle(s string) bool { return handleRe.MatchString(s) }

// ParsePub decodes a hex Ed25519 public key.
func ParsePub(s string) (ed25519.PublicKey, error) {
	if !pubKeyRe.MatchString(s) {
		return nil, fmt.Errorf("%w: public key must be 64 hex chars", ErrBadInput)
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid public key", ErrBadInput)
	}
	return ed25519.PublicKey(b), nil
}

// Store owns relay.db and the blob directory.
type Store struct {
	db      *sql.DB
	dataDir string // $LORE_RELAY_DATA

	// appendMu serializes seq assignment + blob writes per space so
	// seq = max+1 is race-free even across the SQL tx / file boundary.
	appendMu sync.Mutex
}

const schema = `
CREATE TABLE IF NOT EXISTS accounts(
  account_pub     TEXT PRIMARY KEY,
  handle          TEXT UNIQUE,
  plan            TEXT NOT NULL DEFAULT 'trial' CHECK(plan IN ('free','trial','paid')),
  keybox          BLOB,
  stripe_customer TEXT,
  created_at      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices(
  device_pub  TEXT PRIMARY KEY,
  account_pub TEXT NOT NULL REFERENCES accounts(account_pub),
  cert        TEXT,
  created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS spaces(
  blinded_id    TEXT PRIMARY KEY,
  owner_account TEXT NOT NULL REFERENCES accounts(account_pub),
  created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS space_access(
  blinded_id  TEXT NOT NULL REFERENCES spaces(blinded_id),
  account_pub TEXT NOT NULL,
  PRIMARY KEY(blinded_id, account_pub)
);
CREATE TABLE IF NOT EXISTS log_index(
  blinded_id TEXT NOT NULL,
  seq        INTEGER NOT NULL,
  size       INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(blinded_id, seq)
);
CREATE TABLE IF NOT EXISTS snapshots(
  blinded_id TEXT PRIMARY KEY,
  upto_seq   INTEGER NOT NULL,
  size       INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
-- Stored bytes per account: all log + snapshot blobs of spaces the account
-- OWNS (members' appends bill the owner) plus the account keybox.
CREATE VIEW IF NOT EXISTS account_usage AS
SELECT a.account_pub AS account_pub,
       COALESCE((SELECT SUM(l.size) FROM log_index l
                 JOIN spaces s ON s.blinded_id = l.blinded_id
                 WHERE s.owner_account = a.account_pub), 0)
     + COALESCE((SELECT SUM(sn.size) FROM snapshots sn
                 JOIN spaces s2 ON s2.blinded_id = sn.blinded_id
                 WHERE s2.owner_account = a.account_pub), 0)
     + COALESCE(LENGTH(a.keybox), 0) AS used_bytes
FROM accounts a;
`

// OpenStore opens (creating if needed) relay.db and the blob root under dataDir.
func OpenStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dataDir, "data"), 0o700); err != nil {
		return nil, fmt.Errorf("relay: create data dir: %w", err)
	}
	path := filepath.Join(dataDir, "relay.db")
	dsn := "file:" + url.PathEscape(filepath.ToSlash(path)) +
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("relay: open db: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("relay: apply schema: %w", err)
	}
	return &Store{db: db, dataDir: dataDir}, nil
}

// Close closes the database.
func (st *Store) Close() error { return st.db.Close() }

// DB exposes the handle for the admin subcommands.
func (st *Store) DB() *sql.DB { return st.db }

func (st *Store) spaceDir(blindedID string) string {
	return filepath.Join(st.dataDir, "data", blindedID)
}
func (st *Store) logPath(blindedID string, seq int64) string {
	return filepath.Join(st.spaceDir(blindedID), "log", fmt.Sprintf("%d", seq))
}
func (st *Store) snapshotPath(blindedID string) string {
	return filepath.Join(st.spaceDir(blindedID), "snapshot")
}

// --- accounts & devices ---

// Account is a row of accounts.
type Account struct {
	AccountPub     string
	Handle         string
	Plan           string
	StripeCustomer string
	CreatedAt      int64
}

// GetAccount returns ErrNotFound if the account does not exist.
func (st *Store) GetAccount(accountPub string) (*Account, error) {
	var a Account
	var handle, customer sql.NullString
	err := st.db.QueryRow(
		`SELECT account_pub, handle, plan, stripe_customer, created_at FROM accounts WHERE account_pub=?`,
		accountPub).Scan(&a.AccountPub, &handle, &a.Plan, &customer, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.Handle, a.StripeCustomer = handle.String, customer.String
	return &a, nil
}

// EnrollDevice registers device_pub under account_pub, creating the account
// (plan 'trial') on first contact. Idempotent for the same pairing; a
// device_pub already bound to a DIFFERENT account is a conflict.
func (st *Store) EnrollDevice(accountPub, devicePub, cert string) error {
	now := time.Now().Unix()
	tx, err := st.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`INSERT INTO accounts(account_pub, plan, created_at) VALUES(?, 'trial', ?)
		 ON CONFLICT(account_pub) DO NOTHING`, accountPub, now); err != nil {
		return err
	}
	var existing string
	err = tx.QueryRow(`SELECT account_pub FROM devices WHERE device_pub=?`, devicePub).Scan(&existing)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.Exec(
			`INSERT INTO devices(device_pub, account_pub, cert, created_at) VALUES(?,?,?,?)`,
			devicePub, accountPub, cert, now); err != nil {
			return err
		}
	case err != nil:
		return err
	case existing != accountPub:
		return fmt.Errorf("%w: device already enrolled under another account", ErrConflict)
	}
	return tx.Commit()
}

// DeviceAccount maps an enrolled device to its account. ErrNotFound if unknown.
func (st *Store) DeviceAccount(devicePub string) (string, error) {
	var acct string
	err := st.db.QueryRow(`SELECT account_pub FROM devices WHERE device_pub=?`, devicePub).Scan(&acct)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return acct, err
}

// ClaimHandle sets (or changes) the caller account's unique handle.
func (st *Store) ClaimHandle(accountPub, handle string) error {
	if !ValidHandle(handle) {
		return fmt.Errorf("%w: handle must match [a-z0-9-]{3,32}", ErrBadInput)
	}
	var owner string
	err := st.db.QueryRow(`SELECT account_pub FROM accounts WHERE handle=?`, handle).Scan(&owner)
	if err == nil && owner != accountPub {
		return fmt.Errorf("%w: handle already claimed", ErrConflict)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	res, err := st.db.Exec(`UPDATE accounts SET handle=? WHERE account_pub=?`, handle, accountPub)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AccountByHandle resolves a handle to its account_pub.
func (st *Store) AccountByHandle(handle string) (string, error) {
	var pub string
	err := st.db.QueryRow(`SELECT account_pub FROM accounts WHERE handle=?`, handle).Scan(&pub)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return pub, err
}

// PutKeybox stores the wrapped account key (opaque bytes).
func (st *Store) PutKeybox(accountPub string, keybox []byte) error {
	res, err := st.db.Exec(`UPDATE accounts SET keybox=? WHERE account_pub=?`, keybox, accountPub)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetKeybox returns the wrapped account key. ErrNotFound if absent/empty.
func (st *Store) GetKeybox(accountPub string) ([]byte, error) {
	var kb []byte
	err := st.db.QueryRow(`SELECT keybox FROM accounts WHERE account_pub=?`, accountPub).Scan(&kb)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && len(kb) == 0) {
		return nil, ErrNotFound
	}
	return kb, err
}

// SetPlan updates the account plan ('free'|'trial'|'paid').
func (st *Store) SetPlan(accountPub, plan string) error {
	if plan != "free" && plan != "trial" && plan != "paid" {
		return fmt.Errorf("%w: plan must be free|trial|paid", ErrBadInput)
	}
	res, err := st.db.Exec(`UPDATE accounts SET plan=? WHERE account_pub=?`, plan, accountPub)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPlanByCustomer updates the plan for the account bound to a Stripe
// customer id. Returns ErrNotFound if no account has that customer.
func (st *Store) SetPlanByCustomer(customer, plan string) error {
	res, err := st.db.Exec(`UPDATE accounts SET plan=? WHERE stripe_customer=?`, plan, customer)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetStripeCustomer binds a Stripe customer id to an account.
func (st *Store) SetStripeCustomer(accountPub, customer string) error {
	_, err := st.db.Exec(`UPDATE accounts SET stripe_customer=? WHERE account_pub=?`, customer, accountPub)
	return err
}

// --- spaces & access ---

// RegisterSpace creates a space owned by ownerAccount and grants the owner
// access. Idempotent for the same owner; owned by someone else = conflict.
func (st *Store) RegisterSpace(blindedID, ownerAccount string) error {
	tx, err := st.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var owner string
	err = tx.QueryRow(`SELECT owner_account FROM spaces WHERE blinded_id=?`, blindedID).Scan(&owner)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.Exec(`INSERT INTO spaces(blinded_id, owner_account, created_at) VALUES(?,?,?)`,
			blindedID, ownerAccount, time.Now().Unix()); err != nil {
			return err
		}
	case err != nil:
		return err
	case owner != ownerAccount:
		return fmt.Errorf("%w: space registered by another account", ErrConflict)
	}
	if _, err := tx.Exec(`INSERT INTO space_access(blinded_id, account_pub) VALUES(?,?)
		ON CONFLICT DO NOTHING`, blindedID, ownerAccount); err != nil {
		return err
	}
	return tx.Commit()
}

// SpaceOwner returns the owning account. ErrNotFound if the space is unknown.
func (st *Store) SpaceOwner(blindedID string) (string, error) {
	var owner string
	err := st.db.QueryRow(`SELECT owner_account FROM spaces WHERE blinded_id=?`, blindedID).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return owner, err
}

// HasAccess reports whether account may read/append the space.
func (st *Store) HasAccess(blindedID, accountPub string) (bool, error) {
	var one int
	err := st.db.QueryRow(`SELECT 1 FROM space_access WHERE blinded_id=? AND account_pub=?`,
		blindedID, accountPub).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// Grant gives accountPub read/append access. Idempotent.
func (st *Store) Grant(blindedID, accountPub string) error {
	_, err := st.db.Exec(`INSERT INTO space_access(blinded_id, account_pub) VALUES(?,?)
		ON CONFLICT DO NOTHING`, blindedID, accountPub)
	return err
}

// Revoke removes access. Revoking the owner is refused.
func (st *Store) Revoke(blindedID, accountPub string) error {
	owner, err := st.SpaceOwner(blindedID)
	if err != nil {
		return err
	}
	if accountPub == owner {
		return fmt.Errorf("%w: cannot revoke the owner", ErrForbidden)
	}
	_, err = st.db.Exec(`DELETE FROM space_access WHERE blinded_id=? AND account_pub=?`,
		blindedID, accountPub)
	return err
}

// --- log & snapshot ---

// LogEntry is one row of log_index plus its blob.
type LogEntry struct {
	Seq  int64
	Data []byte
}

// AppendLog stores an encrypted delta and returns its assigned seq (max+1).
func (st *Store) AppendLog(blindedID string, data []byte) (int64, error) {
	st.appendMu.Lock()
	defer st.appendMu.Unlock()

	tx, err := st.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var maxSeq sql.NullInt64
	// The log continues past the compacted snapshot, so max must consider both.
	if err := tx.QueryRow(`SELECT MAX(m) FROM (
			SELECT COALESCE(MAX(seq),0) AS m FROM log_index WHERE blinded_id=?
			UNION ALL
			SELECT COALESCE(upto_seq,0) FROM snapshots WHERE blinded_id=?)`,
		blindedID, blindedID).Scan(&maxSeq); err != nil {
		return 0, err
	}
	seq := maxSeq.Int64 + 1
	if _, err := tx.Exec(`INSERT INTO log_index(blinded_id, seq, size, created_at) VALUES(?,?,?,?)`,
		blindedID, seq, len(data), time.Now().Unix()); err != nil {
		return 0, err
	}
	dir := filepath.Join(st.spaceDir(blindedID), "log")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	if err := os.WriteFile(st.logPath(blindedID, seq), data, 0o600); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		os.Remove(st.logPath(blindedID, seq))
		return 0, err
	}
	return seq, nil
}

// ReadLog returns entries with seq >= from, oldest first, bounded by
// maxEntries and maxBytes (whichever hits first; always at least one row).
func (st *Store) ReadLog(blindedID string, from int64, maxEntries int, maxBytes int64) ([]LogEntry, error) {
	rows, err := st.db.Query(`SELECT seq, size FROM log_index WHERE blinded_id=? AND seq>=? ORDER BY seq LIMIT ?`,
		blindedID, from, maxEntries)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogEntry
	var total int64
	for rows.Next() {
		var seq, size int64
		if err := rows.Scan(&seq, &size); err != nil {
			return nil, err
		}
		if len(out) > 0 && total+size > maxBytes {
			break
		}
		data, err := os.ReadFile(st.logPath(blindedID, seq))
		if err != nil {
			return nil, fmt.Errorf("relay: log blob %s/%d: %w", blindedID, seq, err)
		}
		out = append(out, LogEntry{Seq: seq, Data: data})
		total += size
	}
	return out, rows.Err()
}

// GetSnapshot returns the snapshot blob and its upto_seq. ErrNotFound if none.
func (st *Store) GetSnapshot(blindedID string) ([]byte, int64, error) {
	var upto int64
	err := st.db.QueryRow(`SELECT upto_seq FROM snapshots WHERE blinded_id=?`, blindedID).Scan(&upto)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	data, err := os.ReadFile(st.snapshotPath(blindedID))
	if err != nil {
		return nil, 0, fmt.Errorf("relay: snapshot blob %s: %w", blindedID, err)
	}
	return data, upto, nil
}

// PutSnapshot stores a compacted snapshot covering seqs <= upto, then drops
// the folded log prefix (rows and blob files).
func (st *Store) PutSnapshot(blindedID string, upto int64, data []byte) error {
	st.appendMu.Lock()
	defer st.appendMu.Unlock()

	if err := os.MkdirAll(st.spaceDir(blindedID), 0o700); err != nil {
		return err
	}
	// Write blob first (atomic replace via temp file) so a crash between the
	// two steps leaves at worst a newer blob with older metadata.
	tmp := st.snapshotPath(blindedID) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, st.snapshotPath(blindedID)); err != nil {
		return err
	}
	tx, err := st.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO snapshots(blinded_id, upto_seq, size, created_at) VALUES(?,?,?,?)
		ON CONFLICT(blinded_id) DO UPDATE SET upto_seq=excluded.upto_seq, size=excluded.size, created_at=excluded.created_at`,
		blindedID, upto, len(data), time.Now().Unix()); err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT seq FROM log_index WHERE blinded_id=? AND seq<=?`, blindedID, upto)
	if err != nil {
		return err
	}
	var drop []int64
	for rows.Next() {
		var s int64
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return err
		}
		drop = append(drop, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM log_index WHERE blinded_id=? AND seq<=?`, blindedID, upto); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	for _, s := range drop {
		os.Remove(st.logPath(blindedID, s)) // best effort; row is gone
	}
	return nil
}

// UsedBytes returns the account's stored bytes per the account_usage view.
func (st *Store) UsedBytes(accountPub string) (int64, error) {
	var n int64
	err := st.db.QueryRow(`SELECT used_bytes FROM account_usage WHERE account_pub=?`, accountPub).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return n, err
}
