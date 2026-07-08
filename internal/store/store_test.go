package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// A distinct "account" pubkey (any hex works for LWW tiebreaks).
	acct := make([]byte, ed25519.PublicKeySize)
	if _, err := rand.Read(acct); err != nil {
		t.Fatal(err)
	}
	return &Signer{
		AccountID:  hex.EncodeToString(acct),
		DeviceID:   hex.EncodeToString(pub),
		DevicePriv: priv,
	}
}

func testStore(t *testing.T) (*Store, Space) {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "lore.db"), testSigner(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	key := make([]byte, 32)
	rand.Read(key)
	personal, err := s.CreateSpace("personal", "personal", "", key)
	if err != nil {
		t.Fatal(err)
	}
	return s, personal
}

func TestCRUD(t *testing.T) {
	s, sp := testStore(t)
	e, err := s.PutEntry(PutParams{
		SpaceID: sp.SpaceID, Domain: "ops/deploy", Title: "Canary first",
		Body:    "Always deploy through canary.\n[NON-NEGOTIABLE]",
		Markers: []string{"[NON-NEGOTIABLE]"}, Confidence: "validated", Origin: "directive",
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.EntryID == "" || e.Version != 1 || e.DeviceSeq != 1 || e.Signature == "" {
		t.Fatalf("bad new entry: %+v", e)
	}
	got, err := s.GetEntry(e.EntryID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Title != "Canary first" || got.Confidence != "validated" || got.Markers[0] != "[NON-NEGOTIABLE]" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}

	// Update: version bumps, created_at stays, updated_at advances, seq advances.
	e2, err := s.PutEntry(PutParams{
		EntryID: e.EntryID, SpaceID: sp.SpaceID, Domain: "ops/deploy",
		Title: "Canary first", Body: "Canary, then 10% rollout.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if e2.Version != 2 || e2.CreatedAt != e.CreatedAt || e2.UpdatedAt <= e.UpdatedAt || e2.DeviceSeq != 2 {
		t.Fatalf("bad updated entry: %+v", e2)
	}

	// GetDomain / ListEntries.
	de, err := s.GetDomain("ops/deploy", nil)
	if err != nil || len(de) != 1 {
		t.Fatalf("GetDomain: %v %d", err, len(de))
	}
	le, err := s.ListEntries(sp.SpaceID)
	if err != nil || len(le) != 1 {
		t.Fatalf("ListEntries: %v %d", err, len(le))
	}

	// Tombstone delete: hidden from domain/list/search, still fetchable by id.
	if err := s.DeleteEntry(e.EntryID); err != nil {
		t.Fatal(err)
	}
	dead, err := s.GetEntry(e.EntryID)
	if err != nil || !dead.Tombstone || dead.Version != 3 {
		t.Fatalf("tombstone: %v %+v", err, dead)
	}
	if de, _ := s.GetDomain("ops/deploy", nil); len(de) != 0 {
		t.Fatal("tombstoned entry still in domain")
	}
	if res, _ := s.Search("canary", SearchOpts{}); len(res) != 0 {
		t.Fatal("tombstoned entry still searchable")
	}

	if _, err := s.GetEntry("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestValidation(t *testing.T) {
	s, sp := testStore(t)
	if _, err := s.PutEntry(PutParams{SpaceID: sp.SpaceID, Domain: "d", Title: "t", Confidence: "sure"}); err == nil {
		t.Fatal("invalid confidence accepted")
	}
	if _, err := s.PutEntry(PutParams{SpaceID: sp.SpaceID, Domain: "d", Title: "t", Origin: "vibes"}); err == nil {
		t.Fatal("invalid origin accepted")
	}
	e, err := s.PutEntry(PutParams{SpaceID: sp.SpaceID, Domain: "d", Title: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if e.Confidence != "provisional" || e.Origin != "evidence" {
		t.Fatalf("defaults wrong: %+v", e)
	}
}

func TestSearchFilters(t *testing.T) {
	s, sp := testStore(t)
	key := make([]byte, 32)
	rand.Read(key)
	shared, err := s.CreateSpace("shared", "godot-tips", "", key)
	if err != nil {
		t.Fatal(err)
	}
	put := func(space, domain, title, body, conf string, markers ...string) Entry {
		t.Helper()
		e, err := s.PutEntry(PutParams{SpaceID: space, Domain: domain, Title: title,
			Body: body, Confidence: conf, Markers: markers})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	put(sp.SpaceID, "ops/deploy", "Deploy dance", "canary rollout procedure for services", "validated", "[IMPORTANT]")
	put(sp.SpaceID, "craft/testing", "Test rigor", "canary values in table tests", "provisional")
	put(shared.SpaceID, "godot/physics", "Physics tick", "canary scenes for physics regressions", "experimental", "[CONTEXT]")

	all, err := s.Search("canary", SearchOpts{})
	if err != nil || len(all) != 3 {
		t.Fatalf("unfiltered: %v %d", err, len(all))
	}
	if all[0].Snippet == "" || !strings.Contains(all[0].Snippet, "[canary]") {
		t.Fatalf("snippet missing highlight: %q", all[0].Snippet)
	}

	bySpace, _ := s.Search("canary", SearchOpts{Spaces: []string{shared.SpaceID}})
	if len(bySpace) != 1 || bySpace[0].Domain != "godot/physics" {
		t.Fatalf("space filter: %+v", bySpace)
	}
	byDomain, _ := s.Search("canary", SearchOpts{Domain: "ops/deploy"})
	if len(byDomain) != 1 || byDomain[0].Title != "Deploy dance" {
		t.Fatalf("domain filter: %+v", byDomain)
	}
	byMarker, _ := s.Search("canary", SearchOpts{Marker: "IMPORTANT"})
	if len(byMarker) != 1 || byMarker[0].Title != "Deploy dance" {
		t.Fatalf("marker filter: %+v", byMarker)
	}
	byConf, _ := s.Search("canary", SearchOpts{Confidence: "experimental"})
	if len(byConf) != 1 || byConf[0].Title != "Physics tick" {
		t.Fatalf("confidence filter: %+v", byConf)
	}
	limited, _ := s.Search("canary", SearchOpts{Limit: 2})
	if len(limited) != 2 {
		t.Fatalf("limit: %d", len(limited))
	}
	if hits, _ := s.Search("zzzznothing", SearchOpts{}); len(hits) != 0 {
		t.Fatal("phantom hits")
	}
}

func TestLWWApplyRemote(t *testing.T) {
	s, sp := testStore(t)
	local, err := s.PutEntry(PutParams{SpaceID: sp.SpaceID, Domain: "ops/x", Title: "T", Body: "local"})
	if err != nil {
		t.Fatal(err)
	}

	remote := local
	remote.Body = "older remote"
	remote.AuthorAccount = "aaaa"
	remote.UpdatedAt = "2000-01-01T00:00:00.000000000Z"
	if applied, err := s.ApplyRemote(remote); err != nil || applied {
		t.Fatalf("older remote applied: %v %v", applied, err)
	}

	remote.Body = "newer remote"
	remote.UpdatedAt = "2999-01-01T00:00:00.000000000Z"
	if applied, err := s.ApplyRemote(remote); err != nil || !applied {
		t.Fatalf("newer remote rejected: %v %v", applied, err)
	}
	got, _ := s.GetEntry(local.EntryID)
	if got.Body != "newer remote" {
		t.Fatalf("LWW did not replace: %q", got.Body)
	}

	// Equal timestamp: higher author account wins; equal author loses (not strictly greater).
	tie := got
	tie.Body = "tie lower author"
	tie.AuthorAccount = "0000"
	if applied, _ := s.ApplyRemote(tie); applied {
		t.Fatal("lower author won a timestamp tie")
	}
	tie.Body = "tie higher author"
	tie.AuthorAccount = "ffff"
	if applied, _ := s.ApplyRemote(tie); !applied {
		t.Fatal("higher author lost a timestamp tie")
	}
	tie2, _ := s.GetEntry(local.EntryID)
	if tie2.Body != "tie higher author" {
		t.Fatalf("tiebreak body: %q", tie2.Body)
	}
	same := tie2
	same.Body = "identical clock+author"
	if applied, _ := s.ApplyRemote(same); applied {
		t.Fatal("equal (updated_at, author) must not win")
	}

	// Tombstones propagate identically.
	tomb := tie2
	tomb.Tombstone = true
	tomb.UpdatedAt = "3000-01-01T00:00:00.000000000Z"
	if applied, _ := s.ApplyRemote(tomb); !applied {
		t.Fatal("tombstone rejected")
	}
	if got, _ := s.GetEntry(local.EntryID); !got.Tombstone {
		t.Fatal("tombstone not applied")
	}

	// Brand-new remote entry inserts.
	fresh := local
	fresh.EntryID = "11111111-2222-3333-4444-555555555555"
	fresh.Body = "fresh"
	if applied, _ := s.ApplyRemote(fresh); !applied {
		t.Fatal("fresh remote entry rejected")
	}
}

func TestSigningRoundtrip(t *testing.T) {
	s, sp := testStore(t)
	e, err := s.PutEntry(PutParams{SpaceID: sp.SpaceID, Domain: "craft/go", Title: "Sig",
		Body: "body", Markers: []string{"[CONTEXT]"}})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetEntry(e.EntryID)
	if err := VerifyEntry(got, s.signer.DeviceID); err != nil {
		t.Fatalf("stored entry does not verify: %v", err)
	}
	got.Body = "tampered"
	if err := VerifyEntry(got, s.signer.DeviceID); err == nil {
		t.Fatal("tampered entry verified")
	}

	// Canonical encoding is deterministic and key-sorted.
	b1, _ := CanonicalBytes(e, nil)
	b2, _ := CanonicalBytes(e, nil)
	if string(b1) != string(b2) {
		t.Fatal("canonical encoding not deterministic")
	}
	if !strings.HasPrefix(string(b1), `{"attachments":`) || !strings.Contains(string(b1), `"version":`) {
		t.Fatalf("canonical encoding shape: %s", b1)
	}
}

func TestEnforcementRules(t *testing.T) {
	s, personal := testStore(t)
	key := make([]byte, 32)
	rand.Read(key)
	shared, err := s.CreateSpace("shared", "team", "", key)
	if err != nil {
		t.Fatal(err)
	}

	// Personal space refuses members.
	if err := s.AddMember(personal.SpaceID, "{}", "sig", "signer"); !errors.Is(err, ErrPersonalSpace) {
		t.Fatalf("want ErrPersonalSpace, got %v", err)
	}
	if err := s.AddMember(shared.SpaceID, "{}", "sig", "signer"); err != nil {
		t.Fatalf("shared AddMember: %v", err)
	}

	// profile/ and feedback/ refuse copy-out.
	for _, domain := range []string{"profile/trust", "feedback/frustration"} {
		e, err := s.PutEntry(PutParams{SpaceID: personal.SpaceID, Domain: domain, Title: "user model"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.CopyEntry(e.EntryID, shared.SpaceID); !errors.Is(err, ErrUserModel) {
			t.Fatalf("%s: want ErrUserModel, got %v", domain, err)
		}
	}

	// Other layers copy out with provenance; original stays.
	src, err := s.PutEntry(PutParams{SpaceID: personal.SpaceID, Domain: "craft/go", Title: "Table tests",
		Body: "prefer table tests", Confidence: "validated"})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := s.CopyEntry(src.EntryID, shared.SpaceID)
	if err != nil {
		t.Fatal(err)
	}
	if cp.EntryID == src.EntryID || cp.SpaceID != shared.SpaceID {
		t.Fatalf("copy identity: %+v", cp)
	}
	if cp.Provenance == nil || cp.Provenance.SourceEntry != src.EntryID || cp.Provenance.SourceSpace != personal.SpaceID {
		t.Fatalf("copy provenance: %+v", cp.Provenance)
	}
	if _, err := s.GetEntry(src.EntryID); err != nil {
		t.Fatal("original vanished after copy")
	}

	// Only one personal space.
	if _, err := s.CreateSpace("personal", "personal2", "", key); err == nil {
		t.Fatal("second personal space allowed")
	}
}
