package lore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// initHome runs the real Init in a temp dir and opens the store on it, which
// is what a consumer does and what the grant path needs: newHome above builds
// its identity by hand and is fine for spaces, but a grant crosses two whole
// homes and both have to be real.
func initHome(t *testing.T) (*Store, string) {
	t.Helper()
	home := t.TempDir()
	if _, err := Init(home, "granttest"); err != nil {
		t.Fatalf("Init: %v", err)
	}
	s, err := Open(Options{Home: home})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, home
}

// grantOne is the whole handshake in one call: owner admits member into
// spaceID and member applies it.
func grantOne(t *testing.T, owner *Store, spaceID string, member *Store, role Role) Space {
	t.Helper()
	id, err := member.PublicIdentity()
	if err != nil {
		t.Fatalf("PublicIdentity: %v", err)
	}
	blob, err := owner.GrantMembership(bg, spaceID, id, role)
	if err != nil {
		t.Fatalf("GrantMembership: %v", err)
	}
	sp, err := member.AcceptMembership(bg, blob)
	if err != nil {
		t.Fatalf("AcceptMembership: %v", err)
	}
	return sp
}

func TestGrantMembershipCarriesASpaceIntoASecondStore(t *testing.T) {
	owner, _ := initHome(t)
	member, _ := initHome(t)

	sp, err := owner.CreateSpace(bg, "household", Shared)
	if err != nil {
		t.Fatal(err)
	}

	// Before: the member's store has never heard of it. Locally present is
	// lore's membership check, so this is the failing state the grant fixes.
	if _, err := member.GetSpace(bg, sp.ID); !errors.Is(err, ErrSpaceNotFound) {
		t.Fatalf("member holds the space before any grant: %v", err)
	}

	got := grantOne(t, owner, sp.ID, member, Writer)
	if got.ID != sp.ID || got.Kind != Shared {
		t.Fatalf("accepted %+v, want the shared space %s", got, sp.ID)
	}
	if _, err := member.GetSpace(bg, sp.ID); err != nil {
		t.Fatalf("member does not hold the space after accepting: %v", err)
	}

	// A member is a writer, and the space key came with it: a write that the
	// member's own store accepts is a write signed under a key it could only
	// have unwrapped from the member document.
	can, err := member.CanWrite(bg, sp.ID)
	if err != nil || !can {
		t.Fatalf("CanWrite = %v, %v; want true", can, err)
	}
	if _, err := member.PutEntry(bg, PutParams{SpaceID: sp.ID, Domain: "test/grant", Title: "t", Body: "b"}); err != nil {
		t.Fatalf("member cannot write into the granted space: %v", err)
	}

	// Both member lists agree, on both sides.
	for _, s := range []*Store{owner, member} {
		ms, err := s.Members(bg, sp.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(ms) != 2 {
			t.Fatalf("member list has %d entries, want 2: %+v", len(ms), ms)
		}
	}
}

// TestGrantedSpaceSyncs is the point of the whole exercise: a granted space
// behaves exactly like a joined one, which means entries move.
func TestGrantedSpaceSyncs(t *testing.T) {
	owner, _ := initHome(t)
	member, _ := initHome(t)
	sp, err := owner.CreateSpace(bg, "household", Shared)
	if err != nil {
		t.Fatal(err)
	}
	grantOne(t, owner, sp.ID, member, Writer)

	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	// Loopback only: two stores in one process are already on each other's
	// loopback, and a 0.0.0.0 bind buys a firewall prompt and nothing else.
	for _, s := range []*Store{owner, member} {
		go s.Serve(ctx, ServeOptions{SyncInterval: 200 * time.Millisecond})
	}

	want, err := owner.PutEntry(bg, PutParams{SpaceID: sp.ID, Domain: "house/bins", Title: "bins", Body: "tuesday"})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := member.GetEntryIn(bg, sp.ID, want.ID); err == nil {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("the owner's entry never reached the granted member's store")
}

func TestGrantMembershipIsIdempotent(t *testing.T) {
	owner, _ := initHome(t)
	member, _ := initHome(t)
	sp, err := owner.CreateSpace(bg, "household", Shared)
	if err != nil {
		t.Fatal(err)
	}
	id, err := member.PublicIdentity()
	if err != nil {
		t.Fatal(err)
	}

	first, err := owner.GrantMembership(bg, sp.ID, id, Writer)
	if err != nil {
		t.Fatal(err)
	}
	second, err := owner.GrantMembership(bg, sp.ID, id, Writer)
	if err != nil {
		t.Fatalf("second grant for the same account: %v", err)
	}
	// The member list must not have grown a second entry for one account.
	ms, err := owner.Members(bg, sp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 {
		t.Fatalf("re-granting added a member: %+v", ms)
	}
	// Both blobs work, and applying twice is not an error either.
	for i, blob := range [][]byte{first, second, second} {
		if _, err := member.AcceptMembership(bg, blob); err != nil {
			t.Fatalf("AcceptMembership #%d: %v", i, err)
		}
	}

	// A second call may not silently re-role either: the recorded role wins.
	if _, err := owner.GrantMembership(bg, sp.ID, id, Reader); err != nil {
		t.Fatalf("re-grant with a different role: %v", err)
	}
	ms, _ = owner.Members(bg, sp.ID)
	for _, m := range ms {
		if m.AccountID == id.AccountID && m.Role != Writer {
			t.Fatalf("re-granting changed the recorded role to %q", m.Role)
		}
	}
}

// TestGrantAuthorityBoundary is the refusal suite: everything the two calls
// must not do, in one place, because "what it refuses" is the whole of the
// argument for exposing them at all.
func TestGrantAuthorityBoundary(t *testing.T) {
	owner, ownerHome := initHome(t)
	member, _ := initHome(t)
	stranger, _ := initHome(t)

	sp, err := owner.CreateSpace(bg, "household", Shared)
	if err != nil {
		t.Fatal(err)
	}
	memberID, err := member.PublicIdentity()
	if err != nil {
		t.Fatal(err)
	}
	strangerID, err := stranger.PublicIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ownerID, err := owner.PublicIdentity()
	if err != nil {
		t.Fatal(err)
	}
	personal, err := owner.PersonalSpace(bg)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("a store cannot grant a space it does not own", func(t *testing.T) {
		// The member is a *writer* after this, which is the interesting case:
		// it holds the space, it holds the key, and it still cannot admit
		// anybody, because it cannot sign the next member-list version.
		grantOne(t, owner, sp.ID, member, Writer)
		if _, err := member.GrantMembership(bg, sp.ID, strangerID, Writer); !errors.Is(err, ErrNotOwner) {
			t.Fatalf("a writer granted membership: %v", err)
		}
		if _, err := stranger.GetSpace(bg, sp.ID); !errors.Is(err, ErrSpaceNotFound) {
			t.Fatal("the stranger acquired the space anyway")
		}
	})

	t.Run("a grant is inert in a store it was not addressed to", func(t *testing.T) {
		blob, err := owner.GrantMembership(bg, sp.ID, memberID, Writer)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stranger.AcceptMembership(bg, blob); !errors.Is(err, ErrNotGranted) {
			t.Fatalf("a third store applied somebody else's grant: %v", err)
		}
		if _, err := stranger.GetSpace(bg, sp.ID); !errors.Is(err, ErrSpaceNotFound) {
			t.Fatal("the stranger holds the space after a refused grant")
		}
	})

	t.Run("a corrupt or empty grant is refused", func(t *testing.T) {
		if _, err := member.AcceptMembership(bg, nil); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("empty grant: %v", err)
		}
		if _, err := member.AcceptMembership(bg, []byte("not a sealed box")); !errors.Is(err, ErrNotGranted) {
			t.Fatalf("garbage grant: %v", err)
		}
	})

	t.Run("the personal space is not grantable", func(t *testing.T) {
		if _, err := owner.GrantMembership(bg, personal.ID, memberID, Writer); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("granted the personal space: %v", err)
		}
	})

	t.Run("ownership is not grantable", func(t *testing.T) {
		if _, err := owner.GrantMembership(bg, sp.ID, strangerID, Owner); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("granted ownership: %v", err)
		}
	})

	t.Run("an unbound encryption key is refused", func(t *testing.T) {
		// The stranger's account id paired with somebody else's encryption
		// key: the substitution the enc_pub signature exists to catch. Admit
		// it and the space key would be wrapped to a key its named account
		// does not hold.
		forged := PublicIdentity{
			AccountID: strangerID.AccountID,
			EncPub:    memberID.EncPub,
			EncPubSig: strangerID.EncPubSig,
		}
		if _, err := owner.GrantMembership(bg, sp.ID, forged, Writer); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("granted to an unbound encryption key: %v", err)
		}
	})

	t.Run("a store cannot grant to itself", func(t *testing.T) {
		if _, err := owner.GrantMembership(bg, sp.ID, ownerID, Writer); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("granted to its own account: %v", err)
		}
	})

	t.Run("an unknown space is not found", func(t *testing.T) {
		if _, err := owner.GrantMembership(bg, "3f2b4c8e-0000-4000-8000-000000000000", memberID, Writer); !errors.Is(err, ErrSpaceNotFound) {
			t.Fatalf("granted an absent space: %v", err)
		}
	})

	t.Run("a read-only store can neither grant nor accept nor identify", func(t *testing.T) {
		ro, err := Open(Options{Home: ownerHome, ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		defer ro.Close()
		if _, err := ro.PublicIdentity(); !errors.Is(err, ErrReadOnly) {
			t.Fatalf("PublicIdentity on a read-only store: %v", err)
		}
		if _, err := ro.GrantMembership(bg, sp.ID, strangerID, Writer); !errors.Is(err, ErrReadOnly) {
			t.Fatalf("GrantMembership on a read-only store: %v", err)
		}
		if _, err := ro.AcceptMembership(bg, []byte("x")); !errors.Is(err, ErrReadOnly) {
			t.Fatalf("AcceptMembership on a read-only store: %v", err)
		}
	})

	t.Run("a closed store refuses both", func(t *testing.T) {
		s, _ := initHome(t)
		s.Close()
		if _, err := s.PublicIdentity(); !errors.Is(err, ErrClosed) {
			t.Fatalf("PublicIdentity after Close: %v", err)
		}
		if _, err := s.GrantMembership(bg, sp.ID, strangerID, Writer); !errors.Is(err, ErrClosed) {
			t.Fatalf("GrantMembership after Close: %v", err)
		}
		if _, err := s.AcceptMembership(bg, []byte("x")); !errors.Is(err, ErrClosed) {
			t.Fatalf("AcceptMembership after Close: %v", err)
		}
	})
}

// TestGrantRefusesARekeyedAccount covers the one conflict that is neither a
// refusal nor a no-op: an account already in the list under another
// encryption key. Re-initialising a home produces exactly that if the account
// id were reused, and admitting it twice would leave a member list with two
// answers for one account.
func TestGrantRefusesARekeyedAccount(t *testing.T) {
	owner, _ := initHome(t)
	member, memberHome := initHome(t)
	sp, err := owner.CreateSpace(bg, "household", Shared)
	if err != nil {
		t.Fatal(err)
	}
	id, err := member.PublicIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.GrantMembership(bg, sp.ID, id, Writer); err != nil {
		t.Fatal(err)
	}

	// A second identity that keeps the account id and changes the encryption
	// key cannot be produced honestly — the signature would not verify — so
	// this asserts the refusal from the other side: the same account id with
	// another home's encryption key is rejected as unbound, before the
	// already-a-member branch is even reached.
	other, _ := initHome(t)
	otherID, err := other.PublicIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rekeyed := PublicIdentity{AccountID: id.AccountID, EncPub: otherID.EncPub, EncPubSig: id.EncPubSig}
	if _, err := owner.GrantMembership(bg, sp.ID, rekeyed, Writer); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("a re-keyed member was admitted: %v", err)
	}
	_ = memberHome
}

// TestPublicIdentityIsPublic asserts what the struct promises: three public
// values, none of which is a secret in the home.
func TestPublicIdentityIsPublic(t *testing.T) {
	s, home := initHome(t)
	id, err := s.PublicIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if id.AccountID != s.AccountID() {
		t.Fatalf("PublicIdentity().AccountID = %s, AccountID() = %s", id.AccountID, s.AccountID())
	}
	if id.EncPub == "" || id.EncPubSig == "" {
		t.Fatalf("PublicIdentity is incomplete: %+v", id)
	}
	// Nothing it reports may appear in account.json's private halves.
	b, err := os.ReadFile(filepath.Join(home, "account.json"))
	if err != nil {
		t.Fatal(err)
	}
	var priv struct {
		SignPriv string `json:"sign_priv"`
		EncPriv  string `json:"enc_priv"`
	}
	if err := json.Unmarshal(b, &priv); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{priv.SignPriv, priv.EncPriv} {
		if secret == "" {
			continue
		}
		for _, got := range []string{id.AccountID, id.EncPub, id.EncPubSig} {
			if strings.Contains(got, secret) {
				t.Fatal("PublicIdentity leaks a private key")
			}
		}
	}
}
