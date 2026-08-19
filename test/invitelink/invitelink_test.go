// Package invitelinktest runs the async invite-link flow end-to-end against
// the real relay server (internal/relay) on 127.0.0.1:0 with temp
// LORE_HOMEs: owner A mints a bearer token, fresh account B (no signup, no
// keybox) redeems it, A's relay runner auto-admits the claim, and entries
// flow both ways through the relay. Also covers single-use exhaustion,
// expiry, revocation, and the personal-space guard.
package invitelinktest

import (
	"context"
	"database/sql"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
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

var tinyKDF = vault.KDFParams{Time: 1, MemoryKiB: 64, Threads: 1}

const testPass = "correct horse battery staple"

func startRelayServer(t *testing.T) string {
	t.Helper()
	srv, err := relay.NewServer(relay.Config{Addr: ":0", DataDir: t.TempDir(), QuotaMB: 100}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.Close() })
	return ts.URL
}

// initHome creates a fresh LORE_HOME (account, device, personal space) —
// `lore init --yes-i-saved-it`. Returns home and the recovery code.
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

func putEntry(t *testing.T, home, spaceID, title, body string) store.Entry {
	t.Helper()
	st, _, _ := openHome(t, home)
	defer st.Close()
	e, err := st.PutEntry(store.PutParams{SpaceID: spaceID, Domain: "ops/deploy", Title: title, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// waitForEntry polls a home's store until entryID appears (or fails the test).
func waitForEntry(t *testing.T, home, entryID, wantBody, what string, deadline time.Duration) {
	t.Helper()
	st, _, _ := openHome(t, home)
	defer st.Close()
	end := time.Now().Add(deadline)
	for {
		if e, err := st.GetEntry(entryID); err == nil {
			if e.Body != wantBody {
				t.Fatalf("%s: entry body corrupted in transit", what)
			}
			return
		}
		if time.Now().After(end) {
			t.Fatalf("%s: entry %s never arrived", what, entryID)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// mintOwnerInvite calls the exact function the CLI uses.
func mintOwnerInvite(t *testing.T, ctx context.Context, home string, sp store.Space,
	role string, expires time.Duration, uses int) string {
	t.Helper()
	st, _, _ := openHome(t, home)
	defer st.Close()
	tok, err := relayclient.MintInvite(ctx, home, st, sp, role, expires, uses)
	if err != nil {
		t.Fatalf("MintInvite: %v", err)
	}
	return tok.String()
}

// TestInviteLinkFullFlow: A (signed up) mints; B (fresh init, NO signup)
// joins with nothing but the token; A's runner admits; entries flow both
// ways; the single-use token cannot be redeemed twice.
func TestInviteLinkFullFlow(t *testing.T) {
	url := startRelayServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	homeA, code := initHome(t, "laptop")
	if err := relayclient.Signup(ctx, homeA, url, "alice", testPass, code, tinyKDF); err != nil {
		t.Fatalf("signup: %v", err)
	}
	stA, accountA, _ := openHome(t, homeA)
	team := createSharedSpace(t, stA, accountA, "team")
	stA.Close()
	shared := putEntry(t, homeA, team.SpaceID, "deploy ritual", "always run migrations before deploying")

	// Owner's daemon relay loop: registers spaces, pushes, and processes claims.
	ra, err := daemon.StartRelay(ctx, homeA, t.Logf)
	if err != nil || ra == nil {
		t.Fatalf("StartRelay A: %v", err)
	}
	defer ra.Stop()

	token := mintOwnerInvite(t, ctx, homeA, team, space.RoleWriter, 0, 1)
	if len(strings.Split(token, "-")) != 5 {
		t.Fatalf("token %q is not 4 words + number", token)
	}

	// B: fresh init only — no signup, no keybox, no relay config.
	homeB, _ := initHome(t, "desktop")
	res, err := relayclient.JoinInvite(ctx, homeB, url, token, 45*time.Second)
	if err != nil {
		t.Fatalf("JoinInvite: %v", err)
	}
	if res.Pending {
		t.Fatalf("join stayed pending with the owner's runner online: %+v", res)
	}
	if res.Role != space.RoleWriter || res.Members != 2 || res.SpaceName != "team" {
		t.Fatalf("join result = %+v", res)
	}
	if got := relayclient.RelayURL(homeB); got != url {
		t.Fatalf("join did not persist relay_url: %q", got)
	}

	// B's runner pulls the owner's entry through the relay.
	rb, err := daemon.StartRelay(ctx, homeB, t.Logf)
	if err != nil || rb == nil {
		t.Fatalf("StartRelay B: %v", err)
	}
	defer rb.Stop()
	waitForEntry(t, homeB, shared.EntryID, shared.Body, "A->B", 30*time.Second)

	// B writes back (writer role) and A receives it.
	stB, _, _ := openHome(t, homeB)
	spB, err := stB.GetSpace(team.SpaceID)
	stB.Close()
	if err != nil {
		t.Fatalf("space on B: %v", err)
	}
	if string(spB.SpaceKey) != string(team.SpaceKey) {
		t.Fatal("space key not preserved through the invite payload")
	}
	back := putEntry(t, homeB, team.SpaceID, "from B", "written by the invited account")
	waitForEntry(t, homeA, back.EntryID, back.Body, "B->A", 30*time.Second)

	// Single-use exhaustion: the processed invite is gone locally on A ...
	deadline := time.Now().Add(20 * time.Second)
	for {
		lis, err := relayclient.ListLocalInvites(openDB(t, homeA))
		if err != nil {
			t.Fatal(err)
		}
		if len(lis) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("used single-use invite still recorded locally: %+v", lis)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// ... and a third account cannot redeem the same token.
	homeC, _ := initHome(t, "third")
	if _, err := relayclient.JoinInvite(ctx, homeC, url, token, 2*time.Second); err == nil {
		t.Fatal("second redemption of a single-use token must fail")
	}
}

// TestInviteLinkPendingCompletes: B redeems while the owner's daemon is
// OFFLINE — join exits pending; once both runners come up, membership and
// entries complete without any rejoin.
func TestInviteLinkPendingCompletes(t *testing.T) {
	url := startRelayServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	homeA, code := initHome(t, "laptop")
	if err := relayclient.Signup(ctx, homeA, url, "bob", testPass, code, tinyKDF); err != nil {
		t.Fatal(err)
	}
	stA, accountA, _ := openHome(t, homeA)
	team := createSharedSpace(t, stA, accountA, "pending-team")
	stA.Close()
	e := putEntry(t, homeA, team.SpaceID, "seed", "entry waiting for the joiner")
	token := mintOwnerInvite(t, ctx, homeA, team, space.RoleReader, 0, 1)

	homeB, _ := initHome(t, "desktop")
	res, err := relayclient.JoinInvite(ctx, homeB, url, token, 2*time.Second) // owner offline: stays pending
	if err != nil {
		t.Fatalf("JoinInvite: %v", err)
	}
	if !res.Pending {
		t.Fatalf("join completed with no owner daemon running: %+v", res)
	}

	// Owner comes online and processes the parked claim; B's runner completes.
	ra, err := daemon.StartRelay(ctx, homeA, t.Logf)
	if err != nil || ra == nil {
		t.Fatalf("StartRelay A: %v", err)
	}
	defer ra.Stop()
	rb, err := daemon.StartRelay(ctx, homeB, t.Logf)
	if err != nil || rb == nil {
		t.Fatalf("StartRelay B: %v", err)
	}
	defer rb.Stop()

	waitForEntry(t, homeB, e.EntryID, e.Body, "pending join completion", 45*time.Second)

	// The member doc naming B (as reader) arrived through the relay.
	dbB := openDB(t, homeB)
	raws, err := syncproto.RawMemberDocs(dbB, team.SpaceID)
	if err != nil {
		t.Fatal(err)
	}
	_, accountB, _ := func() (*store.Store, *keys.Account, *keys.Device) {
		st, a, d := openHome(t, homeB)
		st.Close()
		return nil, a, d
	}()
	doc, ok := space.LatestDoc(team.SpaceID, raws)
	if !ok || doc.Role(accountB.AccountID()) != space.RoleReader {
		t.Fatalf("member doc on B: ok=%v role=%q", ok, doc.Role(accountB.AccountID()))
	}
}

// TestInviteLinkExpiry: a 1s-expiry invite (test knob: values below the 6h
// clamp pass through) cannot be redeemed after it lapses.
func TestInviteLinkExpiry(t *testing.T) {
	url := startRelayServer(t)
	ctx := context.Background()

	homeA, code := initHome(t, "laptop")
	if err := relayclient.Signup(ctx, homeA, url, "carol", testPass, code, tinyKDF); err != nil {
		t.Fatal(err)
	}
	stA, accountA, _ := openHome(t, homeA)
	team := createSharedSpace(t, stA, accountA, "shortlived")
	stA.Close()
	token := mintOwnerInvite(t, ctx, homeA, team, space.RoleWriter, time.Second, 1)

	time.Sleep(1200 * time.Millisecond)

	homeB, _ := initHome(t, "desktop")
	if _, err := relayclient.JoinInvite(ctx, homeB, url, token, time.Second); err == nil {
		t.Fatal("expired invite must not be redeemable")
	}
}

// TestInviteLinkRevoke: `lore space invites revoke` semantics — after the
// owner revokes, the token is dead.
func TestInviteLinkRevoke(t *testing.T) {
	url := startRelayServer(t)
	ctx := context.Background()

	homeA, code := initHome(t, "laptop")
	if err := relayclient.Signup(ctx, homeA, url, "dave", testPass, code, tinyKDF); err != nil {
		t.Fatal(err)
	}
	stA, accountA, _ := openHome(t, homeA)
	team := createSharedSpace(t, stA, accountA, "revocable")
	stA.Close()
	token := mintOwnerInvite(t, ctx, homeA, team, space.RoleWriter, 0, 5)

	// The invite is listed locally; revoke it by address prefix (CLI path).
	dbA := openDB(t, homeA)
	lis, err := relayclient.ListLocalInvites(dbA)
	if err != nil || len(lis) != 1 {
		t.Fatalf("local invites = %+v, %v", lis, err)
	}
	li, err := relayclient.FindLocalInvite(dbA, lis[0].Addr[:8])
	if err != nil {
		t.Fatal(err)
	}
	stA2, _, deviceA := openHome(t, homeA)
	stA2.Close()
	c, err := relayclient.New(url, deviceA)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeInvite(ctx, li.Addr); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := relayclient.DeleteLocalInvite(dbA, li.Addr); err != nil {
		t.Fatal(err)
	}

	homeB, _ := initHome(t, "desktop")
	if _, err := relayclient.JoinInvite(ctx, homeB, url, token, time.Second); err == nil {
		t.Fatal("revoked invite must not be redeemable")
	}
}

// TestInviteLinkPersonalSpaceGuard: minting for the personal space is
// refused client-side, and the store itself refuses members on it.
func TestInviteLinkPersonalSpaceGuard(t *testing.T) {
	url := startRelayServer(t)
	ctx := context.Background()

	homeA, code := initHome(t, "laptop")
	if err := relayclient.Signup(ctx, homeA, url, "erin", testPass, code, tinyKDF); err != nil {
		t.Fatal(err)
	}
	stA, accountA, _ := openHome(t, homeA)
	defer stA.Close()
	personal, err := stA.PersonalSpace()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := relayclient.MintInvite(ctx, homeA, stA, personal, space.RoleWriter, 0, 1); !errors.Is(err, store.ErrPersonalSpace) {
		t.Fatalf("MintInvite(personal) = %v, want ErrPersonalSpace", err)
	}

	// Store-level backstop, independent of the client guard.
	signPriv, err := accountA.SigningKey()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := space.NewMemberDoc(personal.SpaceID, space.Member{
		AccountPub: accountA.SignPub, EncPub: accountA.EncPub, Role: space.RoleOwner,
	}, signPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := stA.AddMemberDoc(personal.SpaceID, doc); !errors.Is(err, store.ErrPersonalSpace) {
		t.Fatalf("AddMemberDoc(personal) = %v, want ErrPersonalSpace", err)
	}
}
