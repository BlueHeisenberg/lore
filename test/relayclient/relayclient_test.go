// Package relayclienttest runs the relay CLIENT end-to-end against the real
// relay server (internal/relay) on 127.0.0.1:0 with temp LORE_HOMEs and temp
// relay data dirs — no daemons, no real ~/.lore, tiny Argon2 params.
package relayclienttest

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BlueHeisenberg/lore/internal/daemon"
	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/relay"
	"github.com/BlueHeisenberg/lore/internal/relayclient"
	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
	"github.com/BlueHeisenberg/lore/internal/vault"
)

// tinyKDF keeps Argon2id fast in tests (vault records params in the
// envelope, so Open works regardless).
var tinyKDF = vault.KDFParams{Time: 1, MemoryKiB: 64, Threads: 1}

const testPass = "correct horse battery staple"

func startRelay(t *testing.T) (url, dataDir string) {
	t.Helper()
	dataDir = t.TempDir()
	srv, err := relay.NewServer(relay.Config{Addr: ":0", DataDir: dataDir, QuotaMB: 100}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.Close() })
	return ts.URL, dataDir
}

// initHome creates a fresh LORE_HOME: account, device, personal space.
// Returns the home dir and the recovery code.
func initHome(t *testing.T, deviceName string) (string, string) {
	t.Helper()
	home := t.TempDir()
	account, err := keys.GenerateAccount()
	if err != nil {
		t.Fatal(err)
	}
	device, err := keys.GenerateDevice(deviceName, account)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveAccount(home, account); err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveDevice(home, device); err != nil {
		t.Fatal(err)
	}
	code, err := keys.NewRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	st, _, _ := openHome(t, home)
	defer st.Close()
	key, err := space.NewSpaceKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSpace("personal", "personal", "", key); err != nil {
		t.Fatal(err)
	}
	return home, code
}

func openHome(t *testing.T, home string) (*store.Store, *keys.Account, *keys.Device) {
	t.Helper()
	account, err := keys.LoadAccount(home)
	if err != nil {
		t.Fatal(err)
	}
	device, err := keys.LoadDevice(home)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := device.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(home, "lore.db"), &store.Signer{
		AccountID: account.AccountID(), DeviceID: device.DeviceID(), DevicePriv: priv,
	})
	if err != nil {
		t.Fatal(err)
	}
	return st, account, device
}

func openDB(t *testing.T, home string) *sql.DB {
	t.Helper()
	db, err := syncproto.OpenDB(filepath.Join(home, "lore.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func putEntry(t *testing.T, home, title, body string) store.Entry {
	t.Helper()
	st, _, _ := openHome(t, home)
	defer st.Close()
	sp, err := st.PersonalSpace()
	if err != nil {
		t.Fatal(err)
	}
	e, err := st.PutEntry(store.PutParams{SpaceID: sp.SpaceID, Domain: "ops/deploy", Title: title, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// pushPersonal pushes the personal space's unpushed entries via the client
// primitives (what the daemon loop does each round).
func pushPersonal(t *testing.T, home, url string) (store.Space, *relayclient.Client) {
	t.Helper()
	st, _, device := openHome(t, home)
	defer st.Close()
	sp, err := st.PersonalSpace()
	if err != nil {
		t.Fatal(err)
	}
	c, err := relayclient.New(url, device)
	if err != nil {
		t.Fatal(err)
	}
	db := openDB(t, home)
	if _, err := relayclient.PushSpace(context.Background(), c, db, sp); err != nil {
		t.Fatalf("push: %v", err)
	}
	return sp, c
}

// TestSignupLoginE2E: home A signs up and pushes entries; a brand-new home B
// logs in with handle + passphrase + recovery code and gets everything —
// same account, same personal space id/key, entries decrypted and searchable.
func TestSignupLoginE2E(t *testing.T) {
	url, _ := startRelay(t)
	ctx := context.Background()
	homeA, code := initHome(t, "laptop")

	e1 := putEntry(t, homeA, "staging deploy", "always run migrations before deploying to staging")
	e2 := putEntry(t, homeA, "prod deploy", "prod deploys need two approvals")

	if err := relayclient.Signup(ctx, homeA, url, "alice", testPass, code, tinyKDF); err != nil {
		t.Fatalf("signup: %v", err)
	}
	if got := relayclient.RelayURL(homeA); got != url {
		t.Fatalf("relay_url persisted = %q, want %q", got, url)
	}
	spA, _ := pushPersonal(t, homeA, url)

	// Handle resolves to the account (open route).
	stA, accountA, _ := openHome(t, homeA)
	stA.Close()
	if pub, err := relayclient.ResolveHandle(ctx, url, "alice"); err != nil || pub != accountA.AccountID() {
		t.Fatalf("resolve handle = %q, %v; want %q", pub, err, accountA.AccountID())
	}

	// Fresh machine B: nothing but the three factors.
	homeB := t.TempDir()
	res, err := relayclient.Login(ctx, homeB, url, "alice", testPass, code, "desktop", tinyKDF)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if res.AccountID != accountA.AccountID() {
		t.Fatalf("login account = %s, want %s", res.AccountID, accountA.AccountID())
	}
	if res.Spaces != 1 || res.Entries != 2 {
		t.Fatalf("login result = %+v, want 1 space / 2 entries", res)
	}

	stB, accountB, deviceB := openHome(t, homeB)
	defer stB.Close()
	if accountB.AccountID() != accountA.AccountID() {
		t.Fatal("restored account key differs")
	}
	if deviceB.DeviceID() == "" || deviceB.Cert.VerifyForAccount(accountB.AccountID()) != nil {
		t.Fatal("device B cert must chain to the restored account")
	}
	spB, err := stB.PersonalSpace()
	if err != nil {
		t.Fatalf("personal space on B: %v", err)
	}
	if spB.SpaceID != spA.SpaceID || string(spB.SpaceKey) != string(spA.SpaceKey) {
		t.Fatal("personal space id/key not preserved through the keybox manifest")
	}
	for _, want := range []store.Entry{e1, e2} {
		got, err := stB.GetEntry(want.EntryID)
		if err != nil {
			t.Fatalf("entry %s missing on B: %v", want.EntryID, err)
		}
		if got.Body != want.Body || got.Signature != want.Signature {
			t.Fatalf("entry %s corrupted in transit", want.EntryID)
		}
	}
	// `lore search` works immediately.
	hits, err := stB.Search("migrations", store.SearchOpts{Limit: 8})
	if err != nil || len(hits) != 1 || hits[0].EntryID != e1.EntryID {
		t.Fatalf("search on B = %v, %v", hits, err)
	}

	// Login must refuse to clobber an existing account.
	if _, err := relayclient.Login(ctx, homeB, url, "alice", testPass, code, "again", tinyKDF); err == nil {
		t.Fatal("second login over existing account must fail")
	}
}

// TestTamperedDeltaRejected: flipping one byte of a stored log blob on the
// relay's disk must fail authenticated decryption on pull — offset does not
// advance, nothing is applied, no panic.
func TestTamperedDeltaRejected(t *testing.T) {
	url, dataDir := startRelay(t)
	ctx := context.Background()
	homeA, code := initHome(t, "laptop")
	putEntry(t, homeA, "first", "body one")
	if err := relayclient.Signup(ctx, homeA, url, "bob", testPass, code, tinyKDF); err != nil {
		t.Fatal(err)
	}
	spA, _ := pushPersonal(t, homeA, url) // seq 1

	homeB := t.TempDir()
	if _, err := relayclient.Login(ctx, homeB, url, "bob", testPass, code, "desktop", tinyKDF); err != nil {
		t.Fatal(err)
	}

	// A second delta, then corrupt it at rest.
	putEntry(t, homeA, "second", "body two")
	pushPersonal(t, homeA, url) // seq 2
	blinded := syncproto.BlindSpaceID(spA.SpaceKey, spA.SpaceID)
	blobPath := filepath.Join(dataDir, "data", blinded, "log", "2")
	blob, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("relay blob: %v", err)
	}
	blob[len(blob)/2] ^= 0x01
	if err := os.WriteFile(blobPath, blob, 0o600); err != nil {
		t.Fatal(err)
	}

	stB, accountB, deviceB := openHome(t, homeB)
	defer stB.Close()
	dbB := openDB(t, homeB)
	spB, err := stB.PersonalSpace()
	if err != nil {
		t.Fatal(err)
	}
	cB, err := relayclient.New(url, deviceB)
	if err != nil {
		t.Fatal(err)
	}
	offBefore, _ := relayclient.LogOffset(dbB, spB.SpaceID)
	applied, offAfter, err := relayclient.PullSpace(ctx, cB, stB, dbB, spB, accountB.AccountID(), 0)
	if err == nil {
		t.Fatal("pull of tampered delta must fail")
	}
	if applied != 0 || offAfter != offBefore {
		t.Fatalf("tampered delta partially applied: applied=%d off %d->%d", applied, offBefore, offAfter)
	}
	stored, _ := relayclient.LogOffset(dbB, spB.SpaceID)
	if stored != offBefore {
		t.Fatalf("offset advanced past tampered delta: %d -> %d", offBefore, stored)
	}
	if _, err := stB.GetEntry("nonexistent"); err == nil {
		t.Fatal("sanity: store must still answer queries after AEAD failure")
	}
}

// TestLongPollDelivery: a blocked log read wakes within 2s of a concurrent
// append and yields the decryptable delta.
func TestLongPollDelivery(t *testing.T) {
	url, _ := startRelay(t)
	ctx := context.Background()
	homeA, code := initHome(t, "laptop")
	if err := relayclient.Signup(ctx, homeA, url, "carol", testPass, code, tinyKDF); err != nil {
		t.Fatal(err)
	}
	st, _, device := openHome(t, homeA)
	defer st.Close()
	sp, err := st.PersonalSpace()
	if err != nil {
		t.Fatal(err)
	}
	c, err := relayclient.New(url, device)
	if err != nil {
		t.Fatal(err)
	}
	blinded := syncproto.BlindSpaceID(sp.SpaceKey, sp.SpaceID)

	type result struct {
		items   []relayclient.LogEntry
		elapsed time.Duration
		err     error
	}
	done := make(chan result, 1)
	go func() {
		start := time.Now()
		items, err := c.ReadLog(ctx, blinded, 1, 15*time.Second)
		done <- result{items, time.Since(start), err}
	}()

	time.Sleep(300 * time.Millisecond) // let the poller park server-side
	putEntry(t, homeA, "wake", "the long-poller must see this")
	db := openDB(t, homeA)
	if _, err := relayclient.PushSpace(ctx, c, db, sp); err != nil {
		t.Fatal(err)
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("long-poll read: %v", r.err)
		}
		if len(r.items) != 1 {
			t.Fatalf("long-poll items = %d, want 1", len(r.items))
		}
		if r.elapsed > 2*time.Second {
			t.Fatalf("long-poll took %v since read start, want < ~2s after append", r.elapsed)
		}
		d, err := relayclient.DecryptDelta(sp.SpaceKey, blinded, r.items[0].Data)
		if err != nil || len(d.Entries) != 1 || d.Entries[0].Title != "wake" {
			t.Fatalf("delta decrypt = %+v, %v", d, err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("long-poll never returned")
	}
}

// TestKeyboxVaultCompat pins relayclient's envelope/derivation to
// internal/vault's: envelopes sealed by either side must open on the other,
// and a wrap-key reseal (the daemon's secret-less refresh path) must still
// open with the original passphrase + recovery code via vault.Open.
func TestKeyboxVaultCompat(t *testing.T) {
	code, err := keys.NewRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	account, err := keys.GenerateAccount()
	if err != nil {
		t.Fatal(err)
	}
	payload := relayclient.KeyboxPayload{
		V: 1, CreatedAt: keys.Now(), Account: *account,
		Spaces: []syncproto.SpaceRecord{{SpaceID: "s1", Kind: "personal", Name: "personal",
			SpaceKey: make([]byte, 32), CreatedAt: keys.Now()}},
	}

	// relayclient seal -> vault open.
	wk, err := relayclient.DeriveWrapKey(testPass, code, tinyKDF)
	if err != nil {
		t.Fatal(err)
	}
	env, err := relayclient.SealKeyboxWithKey(payload, wk)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := vault.Open(env, testPass, code)
	if err != nil {
		t.Fatalf("vault.Open on relayclient envelope: %v", err)
	}
	var back relayclient.KeyboxPayload
	if err := json.Unmarshal(plain, &back); err != nil || back.Account.SignPub != account.SignPub {
		t.Fatalf("payload roundtrip: %v", err)
	}

	// vault seal -> relayclient open.
	raw, _ := json.Marshal(payload)
	env2, err := vault.Seal(raw, testPass, code, tinyKDF)
	if err != nil {
		t.Fatal(err)
	}
	got, err := relayclient.OpenKeybox(env2, testPass, code)
	if err != nil || got.Account.SignPub != account.SignPub || len(got.Spaces) != 1 {
		t.Fatalf("OpenKeybox on vault envelope: %+v, %v", got, err)
	}

	// Reseal with the SAME cached wrap key after a manifest change (what the
	// daemon does without secrets) — still opens with the two factors.
	payload.Spaces = append(payload.Spaces, syncproto.SpaceRecord{
		SpaceID: "s2", Kind: "shared", Name: "team", SpaceKey: make([]byte, 32), CreatedAt: keys.Now()})
	env3, err := relayclient.SealKeyboxWithKey(payload, wk)
	if err != nil {
		t.Fatal(err)
	}
	got3, err := relayclient.OpenKeybox(env3, testPass, code)
	if err != nil || len(got3.Spaces) != 2 {
		t.Fatalf("resealed keybox: %+v, %v", got3, err)
	}
	// Wrong factor fails.
	if _, err := relayclient.OpenKeybox(env3, "wrong", code); err == nil {
		t.Fatal("wrong passphrase must not open the keybox")
	}
}

// TestStartRelayDaemonLoop drives daemon.StartRelay on two homes of the same
// account: an entry written on A propagates to B through the relay within
// seconds, without any LAN daemons.
func TestStartRelayDaemonLoop(t *testing.T) {
	url, _ := startRelay(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// No relay_url configured -> StartRelay is a config-gated no-op.
	if rr, err := daemon.StartRelay(ctx, t.TempDir(), t.Logf); err != nil || rr != nil {
		t.Fatalf("StartRelay without relay_url = %v, %v; want nil, nil", rr, err)
	}

	homeA, code := initHome(t, "laptop")
	if err := relayclient.Signup(ctx, homeA, url, "dave", testPass, code, tinyKDF); err != nil {
		t.Fatal(err)
	}
	homeB := t.TempDir()
	if _, err := relayclient.Login(ctx, homeB, url, "dave", testPass, code, "desktop", tinyKDF); err != nil {
		t.Fatal(err)
	}

	// B's runner first (it will long-poll), then the entry, then A's runner
	// (its first round pushes).
	rb, err := daemon.StartRelay(ctx, homeB, t.Logf)
	if err != nil || rb == nil {
		t.Fatalf("StartRelay B: %v", err)
	}
	defer rb.Stop()

	e := putEntry(t, homeA, "relayed", "written on A, must appear on B via the relay")

	ra, err := daemon.StartRelay(ctx, homeA, t.Logf)
	if err != nil || ra == nil {
		t.Fatalf("StartRelay A: %v", err)
	}
	defer ra.Stop()

	stB, _, _ := openHome(t, homeB)
	defer stB.Close()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if got, err := stB.GetEntry(e.EntryID); err == nil {
			if got.Body != e.Body {
				t.Fatal("entry body corrupted through relay loop")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("entry never reached B; A status: %+v, B status: %+v", ra.Status(), rb.Status())
		}
		time.Sleep(200 * time.Millisecond)
	}

	stat := ra.Status()
	if stat.RelayURL != url || !stat.Enrolled || len(stat.Spaces) == 0 {
		t.Fatalf("runner status = %+v", stat)
	}
}
