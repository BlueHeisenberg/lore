// Package shared_test is the Phase 4 integration test: two ACCOUNTS (not
// two devices of one account), a topic space shared via the LAN invite
// flow, bidirectional shared-space sync, personal-space isolation, and
// reader-role write rejection on the receive path.
package shared_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BlueHeisenberg/agentmesh/pkg/identity"
	"github.com/BlueHeisenberg/agentmesh/pkg/transport"
	"github.com/BlueHeisenberg/lore/internal/daemon"
	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
	"github.com/google/uuid"
)

// initAccount creates a fresh account+device+personal space at home,
// like `lore init --yes-i-saved-it`.
func initAccount(t *testing.T, home, deviceName string) (*keys.Account, *keys.Device, store.Space) {
	t.Helper()
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
	st := openStore(t, home)
	key, err := space.NewSpaceKey()
	if err != nil {
		t.Fatal(err)
	}
	personal, err := st.CreateSpace("personal", "personal", "", key)
	if err != nil {
		t.Fatal(err)
	}
	return account, device, personal
}

func openStore(t *testing.T, home string) *store.Store {
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
	t.Cleanup(func() { st.Close() })
	return st
}

// createSharedSpace is `lore space create`'s creation path — the same
// internal call the CLI and the public lore.CreateSpace both make.
func createSharedSpace(t *testing.T, st *store.Store, account *keys.Account, name string) store.Space {
	t.Helper()
	signPriv, err := account.SigningKey()
	if err != nil {
		t.Fatal(err)
	}
	sp, err := st.CreateSharedSpace("", name, "", account.EncPub, signPriv)
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

// inviteJoin runs the full LAN invite flow over loopback (no mDNS) and
// returns the space as stored on the invitee side. It asserts both sides
// saw the same fingerprint words.
func inviteJoin(t *testing.T, inviterHome, inviteeHome string, sp store.Space, role string) daemon.JoinResult {
	t.Helper()
	var inviterWords, inviteeWords string
	inv, err := daemon.StartInviter(inviterHome, sp, role, false, false,
		func(words, acct, name string) bool { inviterWords = words; return true })
	if err != nil {
		t.Fatalf("StartInviter: %v", err)
	}
	defer inv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := daemon.Join(ctx, inviteeHome, inv.Code, fmt.Sprintf("127.0.0.1:%d", inv.Port),
		func(words, acct, name string) bool { inviteeWords = words; return true })
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	joined, err := inv.Wait(ctx)
	if err != nil {
		t.Fatalf("inviter Wait: %v", err)
	}
	if inviterWords == "" || inviterWords != inviteeWords {
		t.Fatalf("fingerprints differ: inviter %q invitee %q", inviterWords, inviteeWords)
	}
	if joined.Role != role || res.Role != role {
		t.Fatalf("roles: inviter granted %q, invitee sees %q, want %q", joined.Role, res.Role, role)
	}
	return res
}

func startDaemon(t *testing.T, home string) *daemon.Daemon {
	t.Helper()
	d, err := daemon.New(home, daemon.Options{
		NoMDNS:       true,
		SyncInterval: 2 * time.Second,
		Logf:         t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		d.Stop(ctx)
	})
	return d
}

// waitFor polls cond, poking the daemon between attempts, until it returns
// nil or the deadline passes (deterministic polling, no fixed sleeps).
func waitFor(t *testing.T, d *daemon.Daemon, deadline time.Duration, what string, cond func() error) {
	t.Helper()
	stop := time.Now().Add(deadline)
	var last error
	for time.Now().Before(stop) {
		if last = cond(); last == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		d.SyncNow(ctx)
		cancel()
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s: %v", what, last)
}

// loreClient builds an mTLS client with the given home's device identity,
// pinned to the target daemon's device id, plus the device-cert header value
// — everything needed to speak /lore/v1/* as that account.
func loreClient(t *testing.T, home, targetDeviceID string) (*http.Client, string) {
	t.Helper()
	device, err := keys.LoadDevice(home)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := device.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	var cert tls.Certificate
	cert, err = identity.FromPrivateKey(priv).TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	return transport.NewClient(cert).HTTPFor(targetDeviceID), syncproto.EncodeDeviceCert(device.Cert)
}

// postJSON POSTs a /lore/v1/* request with the device-cert header and
// returns the HTTP status plus raw body.
func postJSON(t *testing.T, httpc *http.Client, certHdr, url string, body any) (int, []byte) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(syncproto.DeviceCertHeader, certHdr)
	resp, err := httpc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, out
}

func TestSharedSpaceAcrossAccounts(t *testing.T) {
	homeA := filepath.Join(t.TempDir(), "a")
	homeB := filepath.Join(t.TempDir(), "b")
	acctA, devA, personalA := initAccount(t, homeA, "device-a")
	acctB, devB, _ := initAccount(t, homeB, "device-b")
	if acctA.AccountID() == acctB.AccountID() {
		t.Fatal("test accounts collided")
	}
	stA := openStore(t, homeA)
	stB := openStore(t, homeB)

	// A creates a topic space (member doc v1: A owner) and invites B as writer.
	team := createSharedSpace(t, stA, acctA, "team-tips")
	joinRes := inviteJoin(t, homeA, homeB, team, space.RoleWriter)
	if joinRes.Space.SpaceID != team.SpaceID {
		t.Fatalf("space id changed in transit: %s != %s", joinRes.Space.SpaceID, team.SpaceID)
	}
	if !bytes.Equal(joinRes.Space.SpaceKey, team.SpaceKey) {
		t.Fatal("invitee unwrapped a different space key")
	}
	spB, err := stB.SpaceByName("team-tips")
	if err != nil {
		t.Fatalf("space not stored on B: %v", err)
	}
	if doc, ok, _ := stB.LatestMemberDoc(spB.SpaceID); !ok {
		t.Fatal("B has no verified member doc")
	} else if doc.Version != 2 || !doc.CanWrite(acctB.AccountID()) || doc.Role(acctA.AccountID()) != space.RoleOwner {
		t.Fatalf("B's latest doc wrong: v%d roles A=%s B=%s", doc.Version,
			doc.Role(acctA.AccountID()), doc.Role(acctB.AccountID()))
	}

	// Daemons on loopback, static peers (no mDNS in CI).
	dA := startDaemon(t, homeA)
	dB := startDaemon(t, homeB)
	if _, err := daemon.AddStaticPeer(homeA, fmt.Sprintf("127.0.0.1:%d", dB.Port())); err != nil {
		t.Fatalf("A pins B: %v", err)
	}
	if _, err := daemon.AddStaticPeer(homeB, fmt.Sprintf("127.0.0.1:%d", dA.Port())); err != nil {
		t.Fatalf("B pins A: %v", err)
	}

	// A -> B through the shared space.
	fromA, err := stA.PutEntry(store.PutParams{
		SpaceID: team.SpaceID, Domain: "ops/ci", Title: "CI cache rule",
		Body: "cache go modules keyed by go.sum",
	})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, dA, 20*time.Second, "A's entry to reach B", func() error {
		got, err := stB.GetEntry(fromA.EntryID)
		if err != nil {
			return err
		}
		if got.Body != fromA.Body || got.Signature != fromA.Signature {
			return errors.New("entry content differs on B")
		}
		return nil
	})

	// B (writer) -> A.
	fromB, err := stB.PutEntry(store.PutParams{
		SpaceID: spB.SpaceID, Domain: "ops/ci", Title: "Flaky test tip",
		Body: "rerun with -count=1 before blaming the cache",
	})
	if err != nil {
		t.Fatalf("B is a writer, put must succeed: %v", err)
	}
	waitFor(t, dB, 20*time.Second, "B's entry to reach A", func() error {
		got, err := stA.GetEntry(fromB.EntryID)
		if err != nil {
			return err
		}
		if got.AuthorAccount != acctB.AccountID() {
			return errors.New("author mangled in transit")
		}
		return nil
	})

	// ---- Isolation: A's personal space must be invisible to B. ----
	secret, err := stA.PutEntry(store.PutParams{
		SpaceID: personalA.SpaceID, Domain: "profile/style", Title: "Private note",
		Body: "the user prefers terse answers",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Give sync rounds a chance to move everything else, then assert absence.
	waitFor(t, dA, 20*time.Second, "one more full round trip", func() error {
		_, err := stB.GetEntry(fromA.EntryID)
		return err
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	dA.SyncNow(ctx)
	cancel()
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	dB.SyncNow(ctx)
	cancel()
	if _, err := stB.GetEntry(secret.EntryID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("A's personal entry visible on B: %v", err)
	}
	entriesB, err := stB.Search("terse", store.SearchOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entriesB) != 0 {
		t.Fatalf("personal content leaked to B: %+v", entriesB)
	}

	// Wire probe: even a CORRECT personal blinded id (computed here from A's
	// own key material) must never be served to B's account — the daemon
	// excludes the personal space from the intersection for foreign accounts.
	personalBlind := syncproto.BlindSpaceID(personalA.SpaceKey, personalA.SpaceID)
	httpcB, certHdrB := loreClient(t, homeB, devA.DeviceID())
	status, body := postJSON(t, httpcB, certHdrB,
		fmt.Sprintf("https://127.0.0.1:%d/lore/v1/spaces", dA.Port()),
		syncproto.SpacesRequest{Blinded: []string{personalBlind}})
	if status != http.StatusOK {
		t.Fatalf("spaces probe: %d %s", status, body)
	}
	var inter syncproto.SpacesResponse
	if err := json.Unmarshal(body, &inter); err != nil {
		t.Fatal(err)
	}
	if len(inter.Blinded) != 0 {
		t.Fatalf("A served its personal blinded id to a foreign account: %v", inter.Blinded)
	}
	// And a direct sync attempt against it is refused outright.
	status, body = postJSON(t, httpcB, certHdrB,
		fmt.Sprintf("https://127.0.0.1:%d/lore/v1/sync", dA.Port()),
		syncproto.SyncRequest{BlindedSpaceID: personalBlind, VV: syncproto.VV{}})
	if status != http.StatusNotFound {
		t.Fatalf("personal-space sync probe: want 404, got %d %s", status, body)
	}

	// Same-account gate sanity: A's own device DOES get the personal space
	// in the intersection (proving the probe above failed on account, not id).
	httpcA, certHdrA := loreClient(t, homeA, devA.DeviceID())
	status, body = postJSON(t, httpcA, certHdrA,
		fmt.Sprintf("https://127.0.0.1:%d/lore/v1/spaces", dA.Port()),
		syncproto.SpacesRequest{Blinded: []string{personalBlind}})
	if status != http.StatusOK {
		t.Fatalf("self spaces probe: %d %s", status, body)
	}
	if err := json.Unmarshal(body, &inter); err != nil {
		t.Fatal(err)
	}
	if len(inter.Blinded) != 1 {
		t.Fatalf("own device should see the personal space, got %v", inter.Blinded)
	}

	// AddMember(-Doc) on the personal space refuses at the store layer.
	if err := stA.AddMember(personalA.SpaceID, "{}", "sig", "signer"); !errors.Is(err, store.ErrPersonalSpace) {
		t.Fatalf("AddMember on personal: want ErrPersonalSpace, got %v", err)
	}
	if err := stA.AddMemberDoc(personalA.SpaceID, space.MemberDoc{SpaceID: personalA.SpaceID, Version: 1}); !errors.Is(err, store.ErrPersonalSpace) {
		t.Fatalf("AddMemberDoc on personal: want ErrPersonalSpace, got %v", err)
	}

	// Copy-out refusal: profile/ never leaves the personal space, on every path.
	if _, err := stA.CopyEntry(secret.EntryID, team.SpaceID); !errors.Is(err, store.ErrUserModel) {
		t.Fatalf("CopyEntry of profile/ entry: want ErrUserModel, got %v", err)
	}
	// Copy-out of a shareable entry works and records provenance.
	ok2, err := stA.PutEntry(store.PutParams{
		SpaceID: personalA.SpaceID, Domain: "craft/testing", Title: "Table tests",
		Body: "prefer table tests for parsers",
	})
	if err != nil {
		t.Fatal(err)
	}
	copied, err := stA.CopyEntry(ok2.EntryID, team.SpaceID)
	if err != nil {
		t.Fatalf("copy-out of craft/ entry must succeed: %v", err)
	}
	if copied.Provenance == nil || copied.Provenance.SourceEntry != ok2.EntryID ||
		copied.Provenance.SourceSpace != personalA.SpaceID {
		t.Fatalf("copy lost provenance: %+v", copied.Provenance)
	}

	// ---- Reader role: B can receive but not write. ----
	zone := createSharedSpace(t, stA, acctA, "read-only-zone")
	zoneJoin := inviteJoin(t, homeA, homeB, zone, space.RoleReader)
	if zoneJoin.Role != space.RoleReader {
		t.Fatalf("join role = %q, want reader", zoneJoin.Role)
	}
	// Local write on B refuses (checked on write).
	if _, err := stB.PutEntry(store.PutParams{
		SpaceID: zone.SpaceID, Domain: "ops/x", Title: "nope", Body: "b writes",
	}); !errors.Is(err, store.ErrNotWriter) {
		t.Fatalf("reader local put: want ErrNotWriter, got %v", err)
	}
	// A's entries still flow to B (reader receives).
	zoneEntry, err := stA.PutEntry(store.PutParams{
		SpaceID: zone.SpaceID, Domain: "ops/x", Title: "Zone rule", Body: "read this",
	})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, dA, 20*time.Second, "zone entry to reach reader B", func() error {
		_, err := stB.GetEntry(zoneEntry.EntryID)
		return err
	})

	// Forged write: an entry SIGNED by B's device, pushed over the wire, is
	// rejected on apply at A (checked on sync-receive, not just locally).
	privB, err := devB.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
	forged := store.Entry{
		EntryID: uuid.NewString(), SpaceID: zone.SpaceID, Domain: "ops/x",
		Title: "forged", Body: "reader wrote this", Confidence: "provisional",
		Origin: "evidence", AuthorAccount: acctB.AccountID(), AuthorDevice: devB.DeviceID(),
		CreatedAt: now, UpdatedAt: now, Version: 1, DeviceSeq: 999,
		OriginDevice: devB.DeviceID(),
	}
	if err := store.SignEntry(&forged, privB); err != nil {
		t.Fatal(err)
	}
	zoneBlind := syncproto.BlindSpaceID(zone.SpaceKey, zone.SpaceID)
	status, body = postJSON(t, httpcB, certHdrB,
		fmt.Sprintf("https://127.0.0.1:%d/lore/v1/entries", dA.Port()),
		syncproto.EntriesRequest{BlindedSpaceID: zoneBlind, Entries: []store.Entry{forged}})
	if status == http.StatusOK {
		t.Fatalf("reader push accepted: %d %s", status, body)
	}
	if !strings.Contains(string(body), "reader") {
		t.Fatalf("rejection should name the reader role, got: %s", body)
	}
	if _, err := stA.GetEntry(forged.EntryID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("forged entry landed on A: %v", err)
	}

	// A NON-member account pushing into the zone is also rejected — this
	// simulates a leaked space key: C knows the blinded id but is in no
	// member doc.
	nonMemberHome := filepath.Join(t.TempDir(), "c")
	acctC, devC, _ := initAccount(t, nonMemberHome, "device-c")
	privC, err := devC.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	forgedC := forged
	forgedC.EntryID = uuid.NewString()
	forgedC.AuthorAccount = acctC.AccountID()
	forgedC.AuthorDevice = devC.DeviceID()
	forgedC.OriginDevice = devC.DeviceID()
	if err := store.SignEntry(&forgedC, privC); err != nil {
		t.Fatal(err)
	}
	httpcC, certHdrC := loreClient(t, nonMemberHome, devA.DeviceID())
	status, body = postJSON(t, httpcC, certHdrC,
		fmt.Sprintf("https://127.0.0.1:%d/lore/v1/entries", dA.Port()),
		syncproto.EntriesRequest{BlindedSpaceID: zoneBlind, Entries: []store.Entry{forgedC}})
	if status == http.StatusOK {
		t.Fatalf("non-member push accepted: %d %s", status, body)
	}
	if _, err := stA.GetEntry(forgedC.EntryID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("non-member entry landed on A: %v", err)
	}
}
