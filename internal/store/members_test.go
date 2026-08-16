package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/BlueHeisenberg/lore/internal/space"
	"golang.org/x/crypto/curve25519"
)

// signedDocFor builds member-doc v1 for a shared space where the store's
// signer is the owner, signed by a fresh account key whose pubkey doubles as
// the signer's account id.
func signedDocFor(t *testing.T, s *Store, sp Space) (space.MemberDoc, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scalar := make([]byte, 32)
	rand.Read(scalar)
	encPub, err := curve25519.X25519(scalar, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := space.WrapSpaceKey(sp.SpaceKey, hex.EncodeToString(encPub))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := space.NewMemberDoc(sp.SpaceID, space.Member{
		AccountPub: hex.EncodeToString(pub), EncPub: hex.EncodeToString(encPub),
		Role: space.RoleOwner, WrappedSpaceKey: wrapped,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return doc, priv, hex.EncodeToString(pub)
}

func TestAddMemberDocAndRoles(t *testing.T) {
	s, personal := testStore(t)
	key := make([]byte, 32)
	rand.Read(key)
	shared, err := s.CreateSpace("shared", "team", "", key)
	if err != nil {
		t.Fatal(err)
	}

	// Personal space refuses signed member docs, same as raw AddMember.
	if err := s.AddMemberDoc(personal.SpaceID, space.MemberDoc{SpaceID: personal.SpaceID, Version: 1}); !errors.Is(err, ErrPersonalSpace) {
		t.Fatalf("want ErrPersonalSpace, got %v", err)
	}

	// Entry written before the space had a member list (still writable then).
	early, err := s.PutEntry(PutParams{SpaceID: shared.SpaceID, Domain: "d/early", Title: "t", Body: "b"})
	if err != nil {
		t.Fatal(err)
	}

	doc, ownerPriv, ownerPub := signedDocFor(t, s, shared)
	if err := s.AddMemberDoc(shared.SpaceID, doc); err != nil {
		t.Fatal(err)
	}
	// Version contiguity enforced: v3 after v1 refuses.
	skip := doc
	skip.Version = 3
	if err := s.AddMemberDoc(shared.SpaceID, skip); err == nil {
		t.Fatal("version gap accepted")
	}
	// Wrong space id refuses.
	wrong := doc
	wrong.SpaceID = "elsewhere"
	if err := s.AddMemberDoc(shared.SpaceID, wrong); err == nil {
		t.Fatal("cross-space doc accepted")
	}

	latest, ok, err := s.LatestMemberDoc(shared.SpaceID)
	if err != nil || !ok {
		t.Fatalf("latest: ok=%v err=%v", ok, err)
	}
	if latest.Version != 1 || latest.Role(ownerPub) != space.RoleOwner {
		t.Fatalf("latest doc wrong: %+v", latest)
	}

	// Once a member doc exists, the store's local signer (a different
	// account: not in the doc) may no longer write into the space.
	if _, err := s.PutEntry(PutParams{SpaceID: shared.SpaceID, Domain: "d/x", Title: "t", Body: "b"}); !errors.Is(err, ErrNotWriter) {
		t.Fatalf("non-member local put: want ErrNotWriter, got %v", err)
	}
	// A tombstone is a write too: a non-writer may not delete either (the
	// sync receive path would reject the tombstone anyway).
	if _, err := s.DeleteEntry(shared.SpaceID, early.EntryID); !errors.Is(err, ErrNotWriter) {
		t.Fatalf("non-member local delete: want ErrNotWriter, got %v", err)
	}

	// Add the store's signer as writer (owner-signed v2): put succeeds again.
	me := space.Member{AccountPub: s.signer.AccountID, EncPub: latest.Members[0].EncPub,
		Role: space.RoleWriter, WrappedSpaceKey: latest.Members[0].WrappedSpaceKey}
	v2, err := space.Evolve(latest, append(latest.Members, me), ownerPub, ownerPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddMemberDoc(shared.SpaceID, v2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutEntry(PutParams{SpaceID: shared.SpaceID, Domain: "d/x", Title: "t", Body: "b"}); err != nil {
		t.Fatalf("writer local put: %v", err)
	}
}

func TestPinAndLinks(t *testing.T) {
	s, personal := testStore(t)
	key := make([]byte, 32)
	rand.Read(key)
	a, err := s.CreateSpace("shared", "space-a", "refA", key)
	if err != nil {
		t.Fatal(err)
	}
	key2 := make([]byte, 32)
	rand.Read(key2)
	b, err := s.CreateSpace("shared", "space-b", "", key2)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.SetPinned(b.SpaceID, true); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSpace(b.SpaceID)
	if err != nil || !got.Pinned {
		t.Fatalf("pin not persisted: %+v err=%v", got, err)
	}
	if err := s.SetPinned(b.SpaceID, false); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetSpace(b.SpaceID); got.Pinned {
		t.Fatal("unpin not persisted")
	}
	if err := s.SetPinned("nope", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pin of unknown space: want ErrNotFound, got %v", err)
	}

	// Links: idempotent, no self-links, target must exist locally.
	if err := s.AddLink(a.SpaceID, b.SpaceID); err != nil {
		t.Fatal(err)
	}
	if err := s.AddLink(a.SpaceID, b.SpaceID); err != nil {
		t.Fatal(err)
	}
	if err := s.AddLink(a.SpaceID, personal.SpaceID); err != nil {
		t.Fatal(err)
	}
	links, err := s.Links(a.SpaceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 2 || links[0] != b.SpaceID || links[1] != personal.SpaceID {
		t.Fatalf("links = %v", links)
	}
	if err := s.AddLink(a.SpaceID, a.SpaceID); err == nil {
		t.Fatal("self-link accepted")
	}
	if err := s.AddLink(a.SpaceID, "ghost"); err == nil {
		t.Fatal("link to unknown space accepted")
	}
	if links, _ := s.Links(b.SpaceID); links != nil {
		t.Fatalf("unlinked space has links: %v", links)
	}
}
