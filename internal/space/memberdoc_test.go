package space

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func curveBase(scalar []byte) ([]byte, error) {
	return curve25519.X25519(scalar, curve25519.Basepoint)
}

type party struct {
	signPub  string
	signPriv ed25519.PrivateKey
	encPub   string
	encPriv  string
}

func newParty(t *testing.T) party {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// X25519 pair via the same path keys uses (scalar + basepoint mult) —
	// generate with box helper semantics: random scalar, derive pub.
	var scalar [32]byte
	if _, err := rand.Read(scalar[:]); err != nil {
		t.Fatal(err)
	}
	encPub, err := curveBase(scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	return party{
		signPub:  hex.EncodeToString(pub),
		signPriv: priv,
		encPub:   hex.EncodeToString(encPub),
		encPriv:  hex.EncodeToString(scalar[:]),
	}
}

func memberOf(t *testing.T, p party, role string, spaceKey []byte) Member {
	t.Helper()
	wrapped, err := WrapSpaceKey(spaceKey, p.encPub)
	if err != nil {
		t.Fatal(err)
	}
	return Member{AccountPub: p.signPub, EncPub: p.encPub, Role: role, WrappedSpaceKey: wrapped}
}

func rawOf(t *testing.T, d MemberDoc) RawDoc {
	t.Helper()
	doc, err := d.DocJSON()
	if err != nil {
		t.Fatal(err)
	}
	return RawDoc{Version: d.Version, Doc: doc, Sig: d.Sig}
}

func TestWrapUnwrapSpaceKey(t *testing.T) {
	p := newParty(t)
	key, err := NewSpaceKey()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := WrapSpaceKey(key, p.encPub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapSpaceKey(wrapped, p.encPub, p.encPriv)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(key) {
		t.Fatal("unwrapped key differs")
	}
	// Wrong keypair must not open it.
	q := newParty(t)
	if _, err := UnwrapSpaceKey(wrapped, q.encPub, q.encPriv); err == nil {
		t.Fatal("foreign keypair opened the wrapped space key")
	}
}

func TestMemberDocChain(t *testing.T) {
	owner := newParty(t)
	writer := newParty(t)
	key, _ := NewSpaceKey()
	const spaceID = "sp-1"

	v1, err := NewMemberDoc(spaceID, memberOf(t, owner, RoleOwner, key), owner.signPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := v1.VerifySig(); err != nil {
		t.Fatal(err)
	}

	// Round-trip through the stored (doc, sig) representation.
	raw1 := rawOf(t, v1)
	parsed, err := ParseMemberDoc(raw1.Doc, raw1.Sig)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.VerifySig(); err != nil {
		t.Fatalf("parsed doc sig: %v", err)
	}

	// Owner evolves: adds a writer.
	v2, err := Evolve(v1, append(v1.Members, memberOf(t, writer, RoleWriter, key)), owner.signPub, owner.signPriv)
	if err != nil {
		t.Fatal(err)
	}
	docs := VerifiedDocs(spaceID, []RawDoc{rawOf(t, v2), raw1}) // out of order on purpose
	if len(docs) != 2 {
		t.Fatalf("verified %d docs, want 2", len(docs))
	}
	latest, ok := LatestDoc(spaceID, []RawDoc{raw1, rawOf(t, v2)})
	if !ok || latest.Version != 2 {
		t.Fatalf("latest = %+v ok=%v", latest, ok)
	}
	if !latest.CanWrite(writer.signPub) || !latest.CanWrite(owner.signPub) {
		t.Fatal("owner and writer must both be able to write")
	}

	// A NON-owner (the writer) signing v3 must be rejected.
	forged := MemberDoc{
		SpaceID: spaceID, Version: 3,
		Members:  append(v2.Members, Member{AccountPub: "evil", EncPub: "00", Role: RoleOwner}),
		SignedBy: writer.signPub,
	}
	if err := forged.Sign(writer.signPriv); err != nil {
		t.Fatal(err)
	}
	docs = VerifiedDocs(spaceID, []RawDoc{raw1, rawOf(t, v2), rawOf(t, forged)})
	if len(docs) != 2 {
		t.Fatalf("forged v3 accepted: chain length %d, want 2", len(docs))
	}

	// v1 signed by someone not listed as owner in it is rejected outright.
	stranger := newParty(t)
	badV1 := MemberDoc{
		SpaceID: spaceID, Version: 1,
		Members:  []Member{memberOf(t, owner, RoleOwner, key)},
		SignedBy: stranger.signPub,
	}
	if err := badV1.Sign(stranger.signPriv); err != nil {
		t.Fatal(err)
	}
	if got := VerifiedDocs(spaceID, []RawDoc{rawOf(t, badV1)}); len(got) != 0 {
		t.Fatalf("v1 with non-owner signer accepted: %d", len(got))
	}

	// Tampered doc body fails.
	tampered := raw1
	tampered.Doc = strings.Replace(tampered.Doc, RoleOwner, RoleReader, 1)
	if got := VerifiedDocs(spaceID, []RawDoc{tampered}); len(got) != 0 {
		t.Fatal("tampered doc accepted")
	}

	// Wrong space id fails.
	if got := VerifiedDocs("other-space", []RawDoc{raw1}); len(got) != 0 {
		t.Fatal("doc accepted for the wrong space")
	}

	// Version gap ends the chain.
	v4 := v2
	v4.Version = 4
	if err := v4.Sign(owner.signPriv); err != nil {
		t.Fatal(err)
	}
	docs = VerifiedDocs(spaceID, []RawDoc{raw1, rawOf(t, v4)})
	if len(docs) != 1 {
		t.Fatalf("version gap accepted: %d docs", len(docs))
	}
}

func TestEvolveRejectsNonOwnerSigner(t *testing.T) {
	owner, writer := newParty(t), newParty(t)
	key, _ := NewSpaceKey()
	v1, err := NewMemberDoc("sp", memberOf(t, owner, RoleOwner, key), owner.signPriv)
	if err != nil {
		t.Fatal(err)
	}
	v1.Members = append(v1.Members, memberOf(t, writer, RoleWriter, key))
	if _, err := Evolve(v1, v1.Members, writer.signPub, writer.signPriv); err == nil {
		t.Fatal("Evolve accepted a non-owner signer")
	}
}

func TestFingerprintWords(t *testing.T) {
	a, b := "aa11", "bb22"
	w1 := FingerprintWords(a, b)
	w2 := FingerprintWords(b, a)
	if w1 != w2 {
		t.Fatalf("fingerprint not symmetric: %s vs %s", w1, w2)
	}
	if parts := strings.Split(w1, "-"); len(parts) != 4 {
		t.Fatalf("want 4 words, got %q", w1)
	}
	if FingerprintWords(a, "cc33") == w1 {
		t.Fatal("different keys produced the same fingerprint")
	}
	// Wordlist sanity: all 256 filled and distinct.
	seen := map[string]bool{}
	for i, w := range fingerprintWords {
		if w == "" {
			t.Fatalf("wordlist[%d] empty", i)
		}
		if seen[w] {
			t.Fatalf("duplicate word %q", w)
		}
		seen[w] = true
	}
}
