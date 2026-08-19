// Package sync_test is the Phase 3 integration test: two LORE_HOMEs, LAN
// enrollment (loopback, no mDNS), two daemons wired as static peers, and a
// full put -> sync -> delete -> tombstone-sync round trip.
package sync_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BlueHeisenberg/lore"
	"github.com/BlueHeisenberg/lore/internal/daemon"
	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
)

// initHome does what `lore init` does, minus prompts: account + device +
// personal space. Returns the personal space.
func initHome(t *testing.T, home, deviceName string) store.Space {
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
	sp, err := st.CreateSpace("personal", "personal", "", key)
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

// openStore opens a signing store handle on home (extra WAL connection
// alongside the daemon's own, same as the CLI does).
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

// waitFor polls cond until it returns nil or the deadline passes.
func waitFor(t *testing.T, d *daemon.Daemon, deadline time.Duration, what string, cond func() error) {
	t.Helper()
	stop := time.Now().Add(deadline)
	var last error
	for time.Now().Before(stop) {
		if last = cond(); last == nil {
			return
		}
		// keep rounds coming faster than the interval
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		d.SyncNow(ctx)
		cancel()
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s: %v", what, last)
}

func startDaemon(t *testing.T, home string) *daemon.Daemon {
	return startDaemonOpts(t, home, daemon.Options{})
}

func startDaemonOpts(t *testing.T, home string, opts daemon.Options) *daemon.Daemon {
	t.Helper()
	opts.NoMDNS = true
	if opts.SyncInterval == 0 {
		opts.SyncInterval = 2 * time.Second
	}
	opts.Logf = t.Logf
	d, err := daemon.New(home, opts)
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

// adminStatus fetches GET /admin/status from a running daemon.
func adminStatus(t *testing.T, d *daemon.Daemon) daemon.AdminStatus {
	t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d/admin/status?token=%s", d.AdminPort(), d.Token())
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin status: %s", resp.Status)
	}
	var st daemon.AdminStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

// putPeer writes a peers-table row straight into lore.db, which is exactly
// what the discovery and static-peer paths do — the row, not a stand-in for
// one. deviceID is a plausible-looking hex id nothing will ever answer to.
func putPeer(t *testing.T, home string, p syncproto.Peer) {
	t.Helper()
	db, err := syncproto.OpenDB(filepath.Join(home, "lore.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := syncproto.UpsertPeer(db, p); err != nil {
		t.Fatal(err)
	}
}

func peerIDs(t *testing.T, home string) map[string]bool {
	t.Helper()
	db, err := syncproto.OpenDB(filepath.Join(home, "lore.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	peers, err := syncproto.ListPeers(db)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, p := range peers {
		out[p.DeviceID] = true
	}
	return out
}

// TestStalePeersExpireAndStaticFailuresStillReport is the container case: a
// pod is recreated, its old address stays in the peers table, and every round
// reports it as a sync error forever until a real failure is invisible in the
// noise. A discovered peer nobody has seen must be forgotten and must not be
// called an error; a static one must survive and must still be reported.
func TestStalePeersExpireAndStaticFailuresStillReport(t *testing.T) {
	home := filepath.Join(t.TempDir(), "a")
	initHome(t, home, "device-a")

	acct, err := keys.LoadAccount(home)
	if err != nil {
		t.Fatal(err)
	}
	dead := "127.0.0.1:1" // nothing listens on port 1
	old := time.Now().UTC().Add(-2 * time.Hour).Format(keys.TimeFormat)
	const (
		ghostID  = "aaaa0000000000000000000000000000000000000000000000000000000000aa"
		freshID  = "bbbb0000000000000000000000000000000000000000000000000000000000bb"
		staticID = "cccc0000000000000000000000000000000000000000000000000000000000cc"
	)
	peer := func(id, name, seen string, static bool) syncproto.Peer {
		// Same account as this device: what every peer row from enrolment or
		// `lore peer add` looks like, and what makes the personal space
		// eligible for the intersection (so the round really is attempted).
		return syncproto.Peer{DeviceID: id, AccountPub: acct.AccountID(), Name: name,
			Addr: dead, Static: static, LastSeen: seen}
	}
	// A replaced pod: discovered once, never seen since.
	putPeer(t, home, peer(ghostID, "pod-old", old, false))
	// A discovered peer seen this minute but currently unreachable.
	putPeer(t, home, peer(freshID, "pod-new", keys.Now(), false))
	// A peer a person configured by hand. Never expired, always reported.
	putPeer(t, home, peer(staticID, "nas", old, true))

	d := startDaemonOpts(t, home, daemon.Options{PeerTTL: time.Hour})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d.SyncNow(ctx)

	got := peerIDs(t, home)
	if got[ghostID] {
		t.Errorf("stale discovered peer %s survived the round; peers = %v", ghostID[:8], got)
	}
	if !got[freshID] {
		t.Errorf("discovered peer seen within PeerTTL was expired; peers = %v", got)
	}
	if !got[staticID] {
		t.Errorf("static peer was expired; peers = %v", got)
	}

	st := adminStatus(t, d)
	joined := strings.Join(st.SyncErrs, "\n")
	if !strings.Contains(joined, staticID[:12]) {
		t.Errorf("static peer's failure must be reported; sync_errors = %q", joined)
	}
	for _, id := range []string{ghostID, freshID} {
		if strings.Contains(joined, id[:12]) {
			t.Errorf("unreachable discovered peer %s must not be reported as a sync error; sync_errors = %q",
				id[:8], joined)
		}
	}
}

// TestAdminStatusMembersAndSharedSpaces: /admin/status must be able to answer
// "is this space actually shared, and with whom" — the member count from the
// verified member list, and the spaces each peer turned out to hold.
func TestAdminStatusMembersAndSharedSpaces(t *testing.T) {
	homeA := filepath.Join(t.TempDir(), "a")
	homeB := filepath.Join(t.TempDir(), "b")
	personal := initHome(t, homeA, "device-a")

	// Enroll B so both homes hold the same personal space (id AND key — the
	// blinded intersection is over both).
	enrollee, err := daemon.StartEnrollee(homeB, "device-b", false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer enrollee.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := daemon.Approve(ctx, homeA, enrollee.Code,
		fmt.Sprintf("127.0.0.1:%d", enrollee.Port)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := enrollee.Wait(ctx); err != nil {
		t.Fatalf("enrollee: %v", err)
	}

	// A shared space A holds alone, with a real two-account member list built
	// through the signing chain — not a hand-written row.
	stA := openStore(t, homeA)
	key, err := space.NewSpaceKey()
	if err != nil {
		t.Fatal(err)
	}
	team, err := stA.CreateSpace("shared", "team", "", key)
	if err != nil {
		t.Fatal(err)
	}
	acctA, err := keys.LoadAccount(homeA)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := acctA.SigningKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := keys.GenerateAccount()
	if err != nil {
		t.Fatal(err)
	}
	member := func(a *keys.Account, role string) space.Member {
		wrapped, err := space.WrapSpaceKey(key, a.EncPub)
		if err != nil {
			t.Fatal(err)
		}
		return space.Member{AccountPub: a.AccountID(), EncPub: a.EncPub,
			Role: role, WrappedSpaceKey: wrapped}
	}
	v1, err := space.NewMemberDoc(team.SpaceID, member(acctA, space.RoleOwner), priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := stA.AddMemberDoc(team.SpaceID, v1); err != nil {
		t.Fatal(err)
	}
	v2, err := space.Evolve(v1, []space.Member{
		member(acctA, space.RoleOwner), member(other, space.RoleWriter),
	}, acctA.AccountID(), priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := stA.AddMemberDoc(team.SpaceID, v2); err != nil {
		t.Fatal(err)
	}

	dA := startDaemon(t, homeA)
	dB := startDaemon(t, homeB)
	if _, err := daemon.AddStaticPeer(homeA, fmt.Sprintf("127.0.0.1:%d", dB.Port())); err != nil {
		t.Fatalf("A pins B: %v", err)
	}

	var st daemon.AdminStatus
	waitFor(t, dA, 20*time.Second, "A to observe the space it shares with B", func() error {
		st = adminStatus(t, dA)
		for _, p := range st.Peers {
			if p.DeviceID == dB.DeviceID() && len(p.SharedSpaces) > 0 {
				return nil
			}
		}
		return fmt.Errorf("no shared spaces recorded yet: %+v", st.Peers)
	})

	for _, p := range st.Peers {
		if p.DeviceID != dB.DeviceID() {
			continue
		}
		if len(p.SharedSpaces) != 1 || p.SharedSpaces[0] != personal.SpaceID {
			t.Errorf("shared_spaces = %v; want just the personal space %s",
				p.SharedSpaces, personal.SpaceID)
		}
		// B was never given the team space; it must not appear.
		for _, id := range p.SharedSpaces {
			if id == team.SpaceID {
				t.Errorf("team space reported as shared with B, which never held it")
			}
		}
	}

	seen := map[string]int{}
	for _, sp := range st.Spaces {
		seen[sp.Name] = sp.Members
	}
	if n, ok := seen["team"]; !ok || n != 2 {
		t.Errorf("team members = %d (present=%v); want 2 from the verified member list", n, ok)
	}
	if n, ok := seen["personal"]; !ok || n != 0 {
		t.Errorf("personal members = %d (present=%v); want 0 — it has no member list", n, ok)
	}
}

func TestTwoDeviceEnrollAndSync(t *testing.T) {
	homeA := filepath.Join(t.TempDir(), "a")
	homeB := filepath.Join(t.TempDir(), "b")

	// Device A: fresh account.
	personal := initHome(t, homeA, "device-a")

	// Enroll device B from A over loopback (no mDNS in tests: explicit addr).
	enrollee, err := daemon.StartEnrollee(homeB, "device-b", false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer enrollee.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	newDev, err := daemon.Approve(ctx, homeA, enrollee.Code,
		fmt.Sprintf("127.0.0.1:%d", enrollee.Port))
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := enrollee.Wait(ctx); err != nil {
		t.Fatalf("enrollee: %v", err)
	}

	// B got the account and the personal space verbatim.
	devB, err := keys.LoadDevice(homeB)
	if err != nil {
		t.Fatal(err)
	}
	if devB.DeviceID() != newDev {
		t.Fatalf("approve returned %s, device.json has %s", newDev, devB.DeviceID())
	}
	acctA, _ := keys.LoadAccount(homeA)
	if err := devB.Cert.VerifyForAccount(acctA.AccountID()); err != nil {
		t.Fatalf("B's device cert must chain to A's account: %v", err)
	}
	stB := openStore(t, homeB)
	spB, err := stB.PersonalSpace()
	if err != nil {
		t.Fatalf("B personal space: %v", err)
	}
	if spB.SpaceID != personal.SpaceID {
		t.Fatalf("personal space id differs: A=%s B=%s", personal.SpaceID, spB.SpaceID)
	}

	// Start both daemons (static peers, no mDNS) and pin each other (TOFU).
	dA := startDaemon(t, homeA)
	dB := startDaemon(t, homeB)
	if _, err := daemon.AddStaticPeer(homeA, fmt.Sprintf("127.0.0.1:%d", dB.Port())); err != nil {
		t.Fatalf("A pins B: %v", err)
	}
	if _, err := daemon.AddStaticPeer(homeB, fmt.Sprintf("127.0.0.1:%d", dA.Port())); err != nil {
		t.Fatalf("B pins A: %v", err)
	}

	// Write on A -> appears on B.
	stA := openStore(t, homeA)
	entry, err := stA.PutEntry(store.PutParams{
		SpaceID: personal.SpaceID, Domain: "ops/deploy", Title: "Deploy rule",
		Body: "deploy only from main", Markers: []string{"[NON-NEGOTIABLE]"},
	})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, dA, 15*time.Second, "entry to reach B", func() error {
		got, err := stB.GetEntry(entry.EntryID)
		if err != nil {
			return err
		}
		if got.Body != entry.Body || got.Signature != entry.Signature {
			return errors.New("entry content differs on B")
		}
		return nil
	})

	// Delete on B -> tombstone appears on A.
	if _, err := stB.DeleteEntry(entry.SpaceID, entry.EntryID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, dB, 15*time.Second, "tombstone to reach A", func() error {
		got, err := stA.GetEntry(entry.EntryID)
		if err != nil {
			return err
		}
		if !got.Tombstone {
			return errors.New("not yet tombstoned on A")
		}
		return nil
	})
}

// TestOneSpaceIDInTwoUnrelatedStoresExchangesNothing is the safety argument
// for lore.CreateSpaceWithID, run rather than asserted in prose.
//
// Accepting an id from a caller means two stores that never met can end up
// holding "the same" space id — a setup wizard that writes one id into a
// configuration file read by several machines makes it a certainty rather
// than a 1-in-2^122 accident. The claim is that this is harmless because an
// id is not what peers match on: they intersect blinded ids, HMAC(space_key,
// "lore-blind" || space_id), and each store generated its own space key. Two
// such stores must therefore be unable to see each other's space at all.
//
// The second half is the control. Give B the space row verbatim, key
// included — which is what `lore join`, enrolment and restore each do — and
// the intersection lights up immediately. So the first half is two live
// daemons declining to recognise one another, not a test harness that was
// never wired up.
func TestOneSpaceIDInTwoUnrelatedStoresExchangesNothing(t *testing.T) {
	homeA := filepath.Join(t.TempDir(), "a")
	homeB := filepath.Join(t.TempDir(), "b")
	initHome(t, homeA, "device-a")
	initHome(t, homeB, "device-b")

	// One id, two unrelated accounts, each creating it for itself. This is
	// the isolated-household shape: the wizard minted the id, and the pod
	// that will hold the space creates it at that id on first boot.
	const shared = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	createAt := func(home, name string) store.Space {
		t.Helper()
		s, err := lore.Open(lore.Options{Home: home})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if _, err := s.CreateSpaceWithID(context.Background(), shared, name, lore.Shared); err != nil {
			t.Fatal(err)
		}
		st := openStore(t, home)
		sp, err := st.GetSpace(shared)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.PutEntry(store.PutParams{SpaceID: shared, Domain: "ops",
			Title: name + "'s note", Body: "written in " + name + "'s own store"}); err != nil {
			t.Fatal(err)
		}
		return sp
	}
	spA, spB := createAt(homeA, "david"), createAt(homeB, "jordan")

	if string(spA.SpaceKey) == string(spB.SpaceKey) {
		t.Fatal("two independent creations produced the same space key; the whole argument rests on them differing")
	}
	blindA := syncproto.BlindSpaceID(spA.SpaceKey, spA.SpaceID)
	if blindB := syncproto.BlindSpaceID(spB.SpaceKey, spB.SpaceID); blindA == blindB {
		t.Fatalf("one id in two stores produced one blinded id %s; they would intersect", blindA[:16])
	}

	dA := startDaemon(t, homeA)
	dB := startDaemon(t, homeB)
	if _, err := daemon.AddStaticPeer(homeA, fmt.Sprintf("127.0.0.1:%d", dB.Port())); err != nil {
		t.Fatalf("A pins B: %v", err)
	}
	if _, err := daemon.AddStaticPeer(homeB, fmt.Sprintf("127.0.0.1:%d", dA.Port())); err != nil {
		t.Fatalf("B pins A: %v", err)
	}

	// Rounds in both directions, and enough of them that "nothing crossed"
	// is not "nothing has happened yet": each peer must have been reached.
	waitFor(t, dA, 20*time.Second, "A to reach B at all", func() error {
		for _, p := range adminStatus(t, dA).Peers {
			if p.DeviceID == dB.DeviceID() && p.LastSeen != "" {
				return nil
			}
		}
		return errors.New("A has not completed a round against B yet")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dB.SyncNow(ctx)
	dA.SyncNow(ctx)

	stA, stB := openStore(t, homeA), openStore(t, homeB)
	for _, tc := range []struct {
		who string
		st  *store.Store
	}{{"A", stA}, {"B", stB}} {
		n, err := tc.st.CountEntries(shared)
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("%s holds %d entries in %s after syncing with a store that has the same id; want only its own",
				tc.who, n, shared)
		}
	}
	for _, p := range adminStatus(t, dA).Peers {
		if p.DeviceID == dB.DeviceID() && len(p.SharedSpaces) != 0 {
			t.Errorf("A reports sharing %v with B; one id and two keys must intersect in nothing", p.SharedSpaces)
		}
	}

	// The control: the space row verbatim, exactly as join/enrolment/restore
	// write it. Same id AND same key is what sharing a space means.
	db, err := syncproto.OpenDB(filepath.Join(homeB, "lore.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := syncproto.InsertSpaceRecord(db, syncproto.SpaceRecord{
		SpaceID: spA.SpaceID, Kind: spA.Kind, Name: spA.Name,
		SpaceKey: spA.SpaceKey, CreatedAt: spA.CreatedAt,
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, dA, 20*time.Second, "the intersection to find the space once the key matches", func() error {
		for _, p := range adminStatus(t, dA).Peers {
			if p.DeviceID == dB.DeviceID() && len(p.SharedSpaces) == 1 && p.SharedSpaces[0] == shared {
				return nil
			}
		}
		return errors.New("not yet")
	})
}
