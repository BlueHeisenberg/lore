// Package lore is the embeddable Go API for a lore knowledge store: spaces,
// entries, full-text search, and the signed, syncing writes behind them.
//
// A Store is one lore home. Open exactly one per home per process.
//
// # What is and is not promised
//
// This package is lore's compatibility promise. Everything under internal/ is
// not: sync, signing, membership evolution, the relay, the database schema
// and the canonical encodings all change without notice, and no accessor to
// any of them will be added here. In particular there is no way to reach the
// *sql.DB, to construct or verify an entry signature, to read a space key, or
// to mutate a member list — each of those would freeze an internal format
// into a public contract.
//
// Init, CreateSpace and Serve are here; device enrolment, invites and join,
// backup and restore, and membership mutation are not, and an embedder still
// reaches those by running the CLI.
//
// Serve is the sync daemon, in this process. It is here for the same reason
// the other two are: an embedder that had to run the `lore` binary to move an
// entry between two homes was not embedding lore, it was supervising it. What
// it does not bring with it is the enrolment and invite handshakes that give
// two homes a space to sync in the first place — those still belong to a
// person at a CLI, and Serve only carries what such a person already agreed
// to share.
//
// This package used to say space creation was deliberately absent, on the
// argument that a space is made out of band by a person who chose a name and
// a sharing posture. The premise that changed is who that person is: an
// embedder creating a household member's own space in a wizard IS that person
// deciding, and forcing it to shell out to `lore space create` bought no
// deliberation — it bought a subprocess and a caller parsing prose to learn
// the new space's id. So creation moved in, and the argument survives in the
// signature rather than in the absence: CreateSpace takes a name and a kind
// and refuses to guess either, there is no get-or-create that lets a space
// appear because a lookup missed, and the personal space belongs to Init
// because there is exactly one.
//
// # Stability
//
// v0.x. Breaking changes are allowed on a minor bump until the surface has
// been exercised by two consumers in anger. Importing this package puts your
// work under lore's licence (BSL 1.1) — see LICENSE.
//
// # Concurrency
//
// Every method on *Store is safe to call from any number of goroutines. That
// is the whole promise: it does not say reads run in parallel, and they
// currently do not. Do not build a design that needs them to.
//
// One Store per home per process. Two Stores on one home fight over one
// write-ahead log for no gain.
//
// # Version skew on one home
//
// A lore home is shared: `lore serve`, the `lore` CLI and this library may be
// three differently-versioned builds on one lore.db. Two rules keep that
// honest. Open refuses a database written by a newer build (ErrSchemaTooNew)
// rather than misreading its columns. And the canonical signing encoding is
// frozen: it may never gain, lose or reorder a field without an explicit,
// entry-carried version, because a build that computes a different digest
// rejects everything the other build wrote and sync stops silently. See
// docs/IMPLEMENTATION.md §"Canonical signing encoding".
//
// # Context
//
// Every method that touches the database takes a context.Context. It is
// checked before the call and it bounds the internal retry of a contended
// write. It does not interrupt a SQLite statement already in flight: each one
// is a local, typically sub-millisecond operation, and a mid-commit
// cancellation is not something a caller should be able to cause.
package lore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/BlueHeisenberg/lore/internal/distill"
	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
)

// dbFile is the database's name inside a lore home.
const dbFile = "lore.db"

// Options configure a store. Home is the only required field.
type Options struct {
	// Home is the lore home directory: the one holding account.json,
	// device.json and lore.db. It is a parameter and never an environment
	// variable, so one process can hold several stores — one per member pod,
	// say. Use DefaultHome for the CLI convention (LORE_HOME or ~/.lore).
	Home string

	// ReadOnly opens the store without loading device keys. Reads work; every
	// write returns ErrReadOnly. For an inspector that must not be able to
	// author.
	ReadOnly bool

	// NotifyOnWrite runs lore's own post-write side effects after every
	// committed write, exactly as `lore mcp` does:
	//
	//   - poke the local sync daemon over its admin API if one is running
	//     (Home/daemon.json), so the write leaves this machine now rather
	//     than at the daemon's next poll — thirty seconds by default;
	//   - re-render the markdown mirror when Home/config.json sets mirror_dir
	//     and the write touched the personal space.
	//
	// Both are best-effort and their errors are ignored; both run
	// synchronously on the calling goroutine, and the daemon poke has a one
	// second timeout.
	//
	// Leave it off and nothing fails — writes simply arrive late on your
	// other devices, intermittently, and the mirror drifts. That is the
	// single easiest thing to lose when moving off `lore mcp`, so it is an
	// option you must say yes to rather than a detail you can forget.
	NotifyOnWrite bool
}

// Store is one lore home.
type Store struct {
	home          string
	st            *store.Store
	accountID     string
	deviceID      string
	readOnly      bool
	notifyOnWrite bool
	closed        atomic.Bool
}

// DefaultHome returns $LORE_HOME, or ~/.lore when it is unset. It is the CLI
// convention, offered for a consumer that wants to follow it; a library
// embedding lore should set Options.Home explicitly instead.
func DefaultHome() (string, error) {
	if h := os.Getenv("LORE_HOME"); h != "" {
		return h, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".lore"), nil
}

// Open opens the store at opts.Home, creating and migrating the database if
// needed, and (unless opts.ReadOnly) loads the device identity that signs
// writes.
//
// It returns ErrNoAccount when the home has never been initialised (`lore
// init`), and ErrSchemaTooNew when the database was written by a newer lore
// than this build.
func Open(opts Options) (*Store, error) {
	if opts.Home == "" {
		return nil, invalid("Options.Home is required")
	}
	s := &Store{home: opts.Home, readOnly: opts.ReadOnly, notifyOnWrite: opts.NotifyOnWrite}

	var signer *store.Signer
	if !opts.ReadOnly {
		account, device, err := loadIdentity(opts.Home)
		if err != nil {
			return nil, err
		}
		priv, err := device.PrivateKey()
		if err != nil {
			return nil, err
		}
		s.accountID, s.deviceID = account.AccountID(), device.DeviceID()
		signer = &store.Signer{AccountID: s.accountID, DeviceID: s.deviceID, DevicePriv: priv}
	}

	st, err := store.Open(filepath.Join(opts.Home, dbFile), signer)
	if err != nil {
		return nil, wrap(err)
	}
	s.st = st
	return s, nil
}

// loadIdentity loads and cross-checks the account and device keys under home.
func loadIdentity(home string) (*keys.Account, *keys.Device, error) {
	for _, f := range []string{keys.AccountFile, keys.DeviceFile} {
		if _, err := os.Stat(filepath.Join(home, f)); errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("%w: no %s in %s (run `lore init`)", ErrNoAccount, f, home)
		}
	}
	account, err := keys.LoadAccount(home)
	if err != nil {
		return nil, nil, err
	}
	device, err := keys.LoadDevice(home)
	if err != nil {
		return nil, nil, err
	}
	// The device certificate is what binds this device key to the account
	// whose name every write will carry; an unverified one is not an identity.
	if err := device.Cert.VerifyForAccount(account.AccountID()); err != nil {
		return nil, nil, err
	}
	return account, device, nil
}

// Identity is what Init created.
type Identity struct {
	AccountID       string // hex Ed25519 account signing key: this home's identity
	DeviceID        string // hex Ed25519 device key that signs this home's writes
	DeviceName      string // the name given, or the hostname when none was
	PersonalSpaceID string // the one personal space, created with the home

	// RecoveryCode is the account recovery code, in the clear, and this is
	// the only time lore will ever produce it: it is a KDF factor and is
	// stored nowhere.
	//
	// Ignore it if you do not want it. It protects nothing at this point —
	// nothing has been wrapped under it yet — so discarding it costs only a
	// later `lore recovery new` before relay signup or a backup, which mints
	// another and voids nothing. Show it to a human or drop it on the floor;
	// the one thing not to do is log it, because a home that HAS signed up
	// pairs this code with a passphrase to unwrap the account keys.
	RecoveryCode string
}

// Init creates a lore home at home: an account keypair, a device keypair
// certified by it, the database, and the personal space. deviceName defaults
// to the hostname, or "device" when even that is unavailable.
//
// It does not open the store — Open does, and only the caller knows whether
// it wants Options.NotifyOnWrite. Like Open it takes no context: it is
// construction, and its writes are a handful of local file and SQLite calls.
//
// The home must be empty of lore: no account.json, no device.json AND no
// lore.db. Any of the three is ErrAlreadyInitialised and nothing is written.
// The database counts because the weaker check is a silent data fault — a
// fresh account adopting an existing lore.db inherits entries signed by keys
// it does not have and a personal space it did not create, and the run that
// did it looks like a successful first boot.
//
// Init is all-or-nothing: every file it creates is one this call created, in
// a home it verified was empty, so any failure removes them again and leaves
// the home as it found it. That is what makes retrying safe.
func Init(home, deviceName string) (id Identity, err error) {
	if home == "" {
		return Identity{}, invalid("home is required")
	}
	for _, f := range []string{keys.AccountFile, keys.DeviceFile, dbFile} {
		switch _, serr := os.Stat(filepath.Join(home, f)); {
		case serr == nil:
			return Identity{}, fmt.Errorf("%w: %s already holds %s", ErrAlreadyInitialised, home, f)
		case !errors.Is(serr, os.ErrNotExist):
			return Identity{}, serr
		}
	}
	if deviceName == "" {
		if h, herr := os.Hostname(); herr == nil && h != "" {
			deviceName = h
		} else {
			deviceName = "device"
		}
	}
	account, err := keys.GenerateAccount()
	if err != nil {
		return Identity{}, err
	}
	device, err := keys.GenerateDevice(deviceName, account)
	if err != nil {
		return Identity{}, err
	}
	code, err := keys.NewRecoveryCode()
	if err != nil {
		return Identity{}, err
	}
	defer func() {
		if err != nil {
			for _, f := range []string{keys.AccountFile, keys.DeviceFile, dbFile, dbFile + "-wal", dbFile + "-shm"} {
				os.Remove(filepath.Join(home, f))
			}
		}
	}()
	if err = keys.SaveAccount(home, account); err != nil {
		return Identity{}, err
	}
	if err = keys.SaveDevice(home, device); err != nil {
		return Identity{}, err
	}
	if err = os.MkdirAll(filepath.Join(home, "blobs"), 0o700); err != nil {
		return Identity{}, err
	}
	// An empty config.json so mirror_dir is discoverable — and never a
	// default value: nothing in lore may point at a directory it does not
	// own. config.json is not part of the emptiness check (it carries no
	// identity and no data), so a pre-seeded one is left exactly as it is.
	cfg := filepath.Join(home, "config.json")
	if _, serr := os.Stat(cfg); errors.Is(serr, os.ErrNotExist) {
		if err = os.WriteFile(cfg, []byte("{\n  \"mirror_dir\": \"\"\n}\n"), 0o600); err != nil {
			return Identity{}, err
		}
	}
	priv, err := device.PrivateKey()
	if err != nil {
		return Identity{}, err
	}
	st, err := store.Open(filepath.Join(home, dbFile), &store.Signer{
		AccountID: account.AccountID(), DeviceID: device.DeviceID(), DevicePriv: priv,
	})
	if err != nil {
		return Identity{}, wrap(err)
	}
	defer st.Close()
	key, err := space.NewSpaceKey()
	if err != nil {
		return Identity{}, err
	}
	sp, err := st.CreateSpace("personal", "personal", "", key)
	if err != nil {
		return Identity{}, wrap(err)
	}
	return Identity{
		AccountID:       account.AccountID(),
		DeviceID:        device.DeviceID(),
		DeviceName:      deviceName,
		PersonalSpaceID: sp.SpaceID,
		RecoveryCode:    code,
	}, nil
}

// Close releases the database. Calls already in flight are not cancelled;
// calls after Close return ErrClosed. Close is idempotent.
func (s *Store) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	return s.st.Close()
}

// AccountID is the hex Ed25519 account key this store writes as, or "" on a
// read-only store.
func (s *Store) AccountID() string { return s.accountID }

// DeviceID is the hex Ed25519 device key that signs this store's writes, or
// "" on a read-only store.
func (s *Store) DeviceID() string { return s.deviceID }

// Home is the lore home this store was opened on.
func (s *Store) Home() string { return s.home }

// busyRetries is how many extra attempts a contended call gets on top of
// SQLite's own busy_timeout. Small on purpose: busy_timeout already waits
// seconds, and these retries exist for the one case it does not cover — a
// deferred transaction refused immediately while upgrading read to write,
// which happens when another process (lore serve, the CLI) is mid-write.
const busyRetries = 4

// do runs one store operation under the caller's context, retrying SQLite
// contention. A contended operation committed nothing, so replaying it is
// safe.
func (s *Store) do(ctx context.Context, fn func() error) error {
	if s.closed.Load() {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var err error
	for attempt := 0; ; attempt++ {
		if err = fn(); !store.IsBusy(err) || attempt >= busyRetries {
			return wrap(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(10<<attempt) * time.Millisecond):
		}
	}
}

// afterWrite runs the post-write side effects when the caller opted in.
func (s *Store) afterWrite(spaceID string) {
	if !s.notifyOnWrite {
		return
	}
	s.pokeDaemon()
	s.renderMirror(spaceID)
}

// pokeDaemon fires POST /admin/sync at the local daemon if daemon.json exists
// ({"port":N,"token":"s"}). Fire-and-forget: 1s timeout, errors ignored — the
// daemon is optional.
func (s *Store) pokeDaemon() {
	b, err := os.ReadFile(filepath.Join(s.home, "daemon.json"))
	if err != nil {
		return
	}
	var d struct {
		Port  int    `json:"port"`
		Token string `json:"token"`
	}
	if json.Unmarshal(b, &d) != nil || d.Port <= 0 {
		return
	}
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Post(fmt.Sprintf("http://127.0.0.1:%d/admin/sync?token=%s",
		d.Port, url.QueryEscape(d.Token)), "", nil)
	if err == nil {
		resp.Body.Close()
	}
}

// renderMirror re-renders the markdown mirror after a personal-space write,
// but only when config.json explicitly sets mirror_dir. Nothing in lore may
// default to a directory it does not own. Errors ignored.
func (s *Store) renderMirror(spaceID string) {
	personal, err := s.st.PersonalSpace()
	if err != nil || personal.SpaceID != spaceID {
		return
	}
	b, err := os.ReadFile(filepath.Join(s.home, "config.json"))
	if err != nil {
		return
	}
	var c struct {
		MirrorDir string `json:"mirror_dir"`
	}
	if json.Unmarshal(b, &c) != nil || c.MirrorDir == "" {
		return
	}
	_, _ = distill.Render(s.st, personal.SpaceID, c.MirrorDir)
}
