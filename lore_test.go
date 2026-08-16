package lore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
	"golang.org/x/crypto/curve25519"

	_ "modernc.org/sqlite"
)

var bg = context.Background()

// newHome creates an initialised lore home in a temp dir with a personal
// space and the named shared spaces. Never the real ~/.lore.
func newHome(t *testing.T, shared ...string) string {
	t.Helper()
	home := t.TempDir()
	account, err := keys.GenerateAccount()
	if err != nil {
		t.Fatal(err)
	}
	device, err := keys.GenerateDevice("loretest", account)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveAccount(home, account); err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveDevice(home, device); err != nil {
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
	defer st.Close()
	mk := func(kind, name string) {
		key, err := space.NewSpaceKey()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.CreateSpace(kind, name, "", key); err != nil {
			t.Fatal(err)
		}
	}
	mk("personal", "personal")
	for _, n := range shared {
		mk("shared", n)
	}
	return home
}

// open opens a store on home and closes it at the end of the test.
func open(t *testing.T, home string, opts ...func(*Options)) *Store {
	t.Helper()
	o := Options{Home: home}
	for _, f := range opts {
		f(&o)
	}
	s, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func spaceID(t *testing.T, s *Store, name string) string {
	t.Helper()
	sp, err := s.SpaceByName(bg, name)
	if err != nil {
		t.Fatalf("space %q: %v", name, err)
	}
	return sp.ID
}

// ----------------------------------------------------------------------------
// Open
// ----------------------------------------------------------------------------

func TestOpenErrors(t *testing.T) {
	if _, err := Open(Options{}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("empty Home: want ErrInvalidArgument, got %v", err)
	}
	if _, err := Open(Options{Home: t.TempDir()}); !errors.Is(err, ErrNoAccount) {
		t.Errorf("uninitialised home: want ErrNoAccount, got %v", err)
	}
}

// TestOpenRefusesNewerSchema is the version-skew guard: two differently
// versioned lores share one LORE_HOME (an embedded library, `lore serve`, the
// CLI), and migrate used to return early for ANY v >= schemaVersion — so an
// older build read a newer schema's columns and said nothing.
func TestOpenRefusesNewerSchema(t *testing.T) {
	home := newHome(t)
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(home, "lore.db")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE kv SET v='99' WHERE k='schema_version'`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	_, err = Open(Options{Home: home})
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("want ErrSchemaTooNew, got %v", err)
	}
	// The message must say which versions, or an operator cannot act on it.
	if !strings.Contains(err.Error(), "v99") {
		t.Errorf("error should name the database version: %v", err)
	}
}

func TestReadOnlyStoreRefusesWrites(t *testing.T) {
	home := newHome(t)
	seedOne(t, home)

	s := open(t, home, func(o *Options) { o.ReadOnly = true })
	if s.AccountID() != "" || s.DeviceID() != "" {
		t.Error("a read-only store must not report an authoring identity")
	}
	sp := spaceID(t, s, "personal")
	if es, err := s.ListEntries(bg, sp); err != nil || len(es) != 1 {
		t.Fatalf("read-only store cannot read: %d entries, %v", len(es), err)
	}
	if _, err := s.PutEntry(bg, PutParams{SpaceID: sp, Domain: "d/x", Title: "t"}); !errors.Is(err, ErrReadOnly) {
		t.Errorf("put on read-only: want ErrReadOnly, got %v", err)
	}
	if _, _, err := s.DeleteEntry(bg, sp, "any"); !errors.Is(err, ErrReadOnly) {
		t.Errorf("delete on read-only: want ErrReadOnly, got %v", err)
	}
	if ok, err := s.CanWrite(bg, sp); ok || err != nil {
		t.Errorf("CanWrite on read-only = %v, %v; want false, nil", ok, err)
	}
}

func TestClosedAndCancelled(t *testing.T) {
	home := newHome(t)
	s := open(t, home)
	sp := spaceID(t, s, "personal")

	cancelled, cancel := context.WithCancel(bg)
	cancel()
	if _, err := s.ListEntries(cancelled, sp); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled ctx: want context.Canceled, got %v", err)
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close is not idempotent: %v", err)
	}
	if _, err := s.ListEntries(bg, sp); !errors.Is(err, ErrClosed) {
		t.Errorf("after Close: want ErrClosed, got %v", err)
	}
	if _, err := s.PutEntry(bg, PutParams{SpaceID: sp, Domain: "d/x", Title: "t"}); !errors.Is(err, ErrClosed) {
		t.Errorf("write after Close: want ErrClosed, got %v", err)
	}
}

// ----------------------------------------------------------------------------
// Entries
// ----------------------------------------------------------------------------

func seedOne(t *testing.T, home string) Entry {
	t.Helper()
	s, err := Open(Options{Home: home})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	sp := spaceID(t, s, "personal")
	e, err := s.PutEntry(bg, PutParams{
		SpaceID: sp, Domain: "ops/deploy", Title: "Canary first",
		Body: "Always deploy through canary before the fleet.",
		// deliberately un-normalised, to prove the write normalises
		Markers: []string{"important", " ", "[CONTEXT]"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestPutAndGet(t *testing.T) {
	home := newHome(t, "team")
	s := open(t, home)
	personal := spaceID(t, s, "personal")
	team := spaceID(t, s, "team")

	e, err := s.PutEntry(bg, PutParams{
		SpaceID: personal, Domain: "ops/deploy", Title: "Canary first",
		Body: "Always deploy through canary.", Markers: []string{"important"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Version != 1 || e.Confidence != Provisional || e.Origin != Evidence {
		t.Errorf("defaults wrong: %+v", e)
	}
	if got := strings.Join(e.Markers, " "); got != "[IMPORTANT]" {
		t.Errorf("markers not normalised on write: %q", got)
	}
	if e.AuthorAccount != s.AccountID() {
		t.Errorf("author = %q, want this store's account", e.AuthorAccount)
	}
	if _, err := e.CreatedAt.Time(); err != nil {
		t.Errorf("CreatedAt does not parse: %v", err)
	}

	got, err := s.GetEntry(bg, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Body != e.Body {
		t.Errorf("body round-trip: %q", got.Body)
	}

	// Space scoping: an id from one space cannot read out of another.
	if _, err := s.GetEntryIn(bg, personal, e.ID); err != nil {
		t.Errorf("GetEntryIn in the right space: %v", err)
	}
	if _, err := s.GetEntryIn(bg, team, e.ID); !errors.Is(err, ErrWrongSpace) {
		t.Errorf("GetEntryIn across spaces: want ErrWrongSpace, got %v", err)
	}
	if _, err := s.GetEntry(bg, "no-such-id"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown id: want ErrNotFound, got %v", err)
	}

	// A new version keeps created_at and bumps version.
	v2, err := s.PutEntry(bg, PutParams{
		ID: e.ID, SpaceID: personal, Domain: e.Domain, Title: e.Title, Body: "Canary, then fleet.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if v2.Version != 2 || v2.CreatedAt != e.CreatedAt || v2.UpdatedAt <= e.UpdatedAt {
		t.Errorf("v2 = %+v, v1 = %+v", v2, e)
	}
	// Writing a known id into the wrong space is refused, not moved.
	if _, err := s.PutEntry(bg, PutParams{ID: e.ID, SpaceID: team, Domain: "d/x", Title: "t"}); !errors.Is(err, ErrWrongSpace) {
		t.Errorf("cross-space update: want ErrWrongSpace, got %v", err)
	}
}

func TestPutValidation(t *testing.T) {
	s := open(t, newHome(t))
	sp := spaceID(t, s, "personal")
	for name, p := range map[string]PutParams{
		"no space":       {Domain: "d/x", Title: "t"},
		"no domain":      {SpaceID: sp, Title: "t"},
		"no title":       {SpaceID: sp, Domain: "d/x"},
		"bad confidence": {SpaceID: sp, Domain: "d/x", Title: "t", Confidence: "sure"},
		"bad origin":     {SpaceID: sp, Domain: "d/x", Title: "t", Origin: "vibes"},
	} {
		if _, err := s.PutEntry(bg, p); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: want ErrInvalidArgument, got %v", name, err)
		}
	}
	if _, err := s.PutEntry(bg, PutParams{SpaceID: "nope", Domain: "d/x", Title: "t"}); !errors.Is(err, ErrSpaceNotFound) {
		t.Errorf("unknown space: want ErrSpaceNotFound, got %v", err)
	}
}

func TestDeleteIsScopedAndIdempotent(t *testing.T) {
	home := newHome(t, "team")
	s := open(t, home)
	personal := spaceID(t, s, "personal")
	team := spaceID(t, s, "team")
	e := mustPut(t, s, personal, "ops/deploy", "Canary first", "Always deploy through canary.")

	if _, _, err := s.DeleteEntry(bg, team, e.ID); !errors.Is(err, ErrWrongSpace) {
		t.Fatalf("cross-space delete: want ErrWrongSpace, got %v", err)
	}
	if _, err := s.GetEntry(bg, e.ID); err != nil {
		t.Fatalf("cross-space delete removed the entry anyway: %v", err)
	}
	if _, _, err := s.DeleteEntry(bg, personal, "no-such-id"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: want ErrNotFound, got %v", err)
	}

	dead, deleted, err := s.DeleteEntry(bg, personal, e.ID)
	if err != nil || !deleted {
		t.Fatalf("delete: deleted=%v err=%v", deleted, err)
	}
	if dead.Version != e.Version+1 {
		t.Errorf("tombstone version = %d, want %d", dead.Version, e.Version+1)
	}
	// Gone from every read path.
	if _, err := s.GetEntry(bg, e.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted entry still readable: %v", err)
	}
	if es, _ := s.ListEntries(bg, personal); len(es) != 0 {
		t.Errorf("deleted entry still listed: %d", len(es))
	}
	if n, _ := s.CountEntries(bg, personal); n != 0 {
		t.Errorf("deleted entry still counted: %d", n)
	}
	if hits, _ := s.Search(bg, "canary", SearchOpts{}); len(hits) != 0 {
		t.Errorf("deleted entry still searchable: %d", len(hits))
	}
	if es, _ := s.GetDomain(bg, "ops/deploy", nil); len(es) != 0 {
		t.Errorf("deleted entry still in its domain: %d", len(es))
	}

	// Second delete: no error, nothing written, and it says so.
	again, deleted, err := s.DeleteEntry(bg, personal, e.ID)
	if err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if deleted {
		t.Error("second delete reported that it wrote a tombstone")
	}
	if again.Version != dead.Version || again.UpdatedAt != dead.UpdatedAt {
		t.Errorf("second delete wrote a new version: %+v vs %+v", again, dead)
	}
}

func TestCopyEntry(t *testing.T) {
	home := newHome(t, "team")
	s := open(t, home)
	personal := spaceID(t, s, "personal")
	team := spaceID(t, s, "team")
	e := mustPut(t, s, personal, "ops/deploy", "Canary first", "Always deploy through canary.")

	copied, err := s.CopyEntry(bg, e.ID, team)
	if err != nil {
		t.Fatal(err)
	}
	if copied.SpaceID != team || copied.ID == e.ID {
		t.Errorf("copy = %+v", copied)
	}
	if copied.Provenance == nil || copied.Provenance.SourceEntry != e.ID ||
		copied.Provenance.SourceSpace != personal {
		t.Errorf("provenance = %+v", copied.Provenance)
	}
	if _, err := copied.Provenance.CopiedAt.Time(); err != nil {
		t.Errorf("CopiedAt does not parse: %v", err)
	}
	// A copy, never a move.
	if _, err := s.GetEntryIn(bg, personal, e.ID); err != nil {
		t.Errorf("source gone after copy: %v", err)
	}
	// Copying into the space it is already in is a programming error.
	if _, err := s.CopyEntry(bg, e.ID, personal); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("self-copy: want ErrInvalidArgument, got %v", err)
	}

	// The user model never leaves the personal space, on any path.
	for _, domain := range []string{"profile/trust", "feedback/style"} {
		um := mustPut(t, s, personal, domain, "Private", "secret")
		if _, err := s.CopyEntry(bg, um.ID, team); !errors.Is(err, ErrUserModel) {
			t.Errorf("copy %s out: want ErrUserModel, got %v", domain, err)
		}
	}
	if es, _ := s.ListEntries(bg, team); len(es) != 1 {
		t.Errorf("user-model entry leaked into the shared space: %d entries", len(es))
	}
}

func mustPut(t *testing.T, s *Store, spaceID, domain, title, body string) Entry {
	t.Helper()
	e, err := s.PutEntry(bg, PutParams{SpaceID: spaceID, Domain: domain, Title: title, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// ----------------------------------------------------------------------------
// Search
// ----------------------------------------------------------------------------

// TestSearchReturnsWholeEntries pins the property the whole library exists
// for: a search hit is a COMPLETE entry, not an excerpt. Snippet is a
// separate field, and no consumer should ever reconstruct a body from it.
func TestSearchReturnsWholeEntries(t *testing.T) {
	home := newHome(t, "team")
	s := open(t, home)
	personal := spaceID(t, s, "personal")
	team := spaceID(t, s, "team")

	body := strings.Repeat("Deploys go through canary before the fleet. ", 20) + "TERMINATOR"
	e, err := s.PutEntry(bg, PutParams{
		SpaceID: personal, Domain: "ops/deploy", Title: "Canary first", Body: body,
		Markers: []string{"NON-NEGOTIABLE"}, Confidence: Validated, Origin: Constraint,
	})
	if err != nil {
		t.Fatal(err)
	}
	mustPut(t, s, team, "ops/deploy", "Team deploy", "Team deploys use blue-green canary.")

	hits, err := s.Search(bg, "canary", SearchOpts{Spaces: []string{personal}})
	if err != nil || len(hits) != 1 {
		t.Fatalf("search: %d hits, %v", len(hits), err)
	}
	h := hits[0]
	if h.Body != body {
		t.Errorf("search returned a truncated body: %d of %d bytes", len(h.Body), len(body))
	}
	if !strings.HasSuffix(h.Body, "TERMINATOR") {
		t.Error("search body is missing its tail")
	}
	if h.Snippet == "" || h.Snippet == h.Body {
		t.Errorf("snippet should be a separate, shorter fragment: %q", h.Snippet)
	}
	// Everything kenward used to say was unavailable from search.
	if h.ID != e.ID || h.CreatedAt == "" || h.UpdatedAt == "" || h.Version != 1 ||
		h.Origin != Constraint || h.Confidence != Validated ||
		strings.Join(h.Markers, "") != "[NON-NEGOTIABLE]" || h.AuthorAccount == "" {
		t.Errorf("search hit is missing metadata: %+v", h)
	}

	// Empty Spaces means every space, and that is a decision, not a default.
	if hits, _ := s.Search(bg, "canary", SearchOpts{}); len(hits) != 2 {
		t.Errorf("unscoped search should see both spaces, got %d", len(hits))
	}
	// Filters.
	if hits, _ := s.Search(bg, "canary", SearchOpts{Marker: "non-negotiable"}); len(hits) != 1 {
		t.Errorf("marker filter (unbracketed spelling) got %d", len(hits))
	}
	if hits, _ := s.Search(bg, "canary", SearchOpts{Marker: "[NON-NEGOTIABLE]"}); len(hits) != 1 {
		t.Errorf("marker filter (bracketed spelling) got %d", len(hits))
	}
	if hits, _ := s.Search(bg, "canary", SearchOpts{Confidence: Validated}); len(hits) != 1 {
		t.Errorf("confidence filter got %d", len(hits))
	}
	if _, err := s.Search(bg, "canary", SearchOpts{Confidence: "sure"}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("bad confidence: want ErrInvalidArgument, got %v", err)
	}
	if hits, _ := s.Search(bg, "canary", SearchOpts{Limit: 1}); len(hits) != 1 {
		t.Errorf("limit ignored: %d", len(hits))
	}
	// A query with no searchable words is empty, not an error.
	if hits, err := s.Search(bg, "  ,, ", SearchOpts{}); err != nil || len(hits) != 0 {
		t.Errorf("wordless query: %d hits, %v", len(hits), err)
	}
}

// TestTermsMatchesSearch keeps Terms honest: what it reports is what search
// actually requires, conjunctively.
func TestTermsMatchesSearch(t *testing.T) {
	s := open(t, newHome(t))
	sp := spaceID(t, s, "personal")
	mustPut(t, s, sp, "ops/boiler", "Boiler", "The boiler service code is 1234.")

	if got := strings.Join(Terms("Boiler, SERVICE!"), "|"); got != "boiler|service" {
		t.Errorf("Terms = %q", got)
	}
	// Every term must be present: one absent word excludes the answer.
	if hits, _ := s.Search(bg, "boiler service", SearchOpts{}); len(hits) != 1 {
		t.Errorf("conjunctive match failed: %d", len(hits))
	}
	if hits, _ := s.Search(bg, "what is the boiler service code", SearchOpts{}); len(hits) != 0 {
		t.Errorf("a sentence should not match: %d hits — Terms would have warned", len(hits))
	}
}

func TestNormalizeMarkers(t *testing.T) {
	got := NormalizeMarkers([]string{" context ", "", "  ", "non-negotiable", "[ALREADY]"})
	want := []string{"[CONTEXT]", "[NON-NEGOTIABLE]", "[ALREADY]"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("NormalizeMarkers = %v, want %v", got, want)
	}
	if NormalizeMarkers(nil) != nil {
		t.Error("NormalizeMarkers(nil) should be nil")
	}
}

// TestTimestampSameTickPadding covers the reason Timestamp is a string: two
// versions inside one clock tick get literal "0" characters appended so the
// later string sorts strictly greater, and that is no longer RFC3339.
func TestTimestampSameTickPadding(t *testing.T) {
	base := Timestamp("2026-08-16T10:11:12.123456789Z")
	want, err := base.Time()
	if err != nil {
		t.Fatal(err)
	}
	for _, pad := range []string{"0", "00", "000"} {
		got, err := Timestamp(string(base) + pad).Time()
		if err != nil {
			t.Fatalf("padded %q: %v", pad, err)
		}
		if !got.Equal(want) {
			t.Errorf("padded %q parsed to %v, want %v", pad, got, want)
		}
	}
	if _, err := Timestamp("").Time(); err == nil {
		t.Error("the zero Timestamp should be an error, not the zero time")
	}
}

// ----------------------------------------------------------------------------
// Spaces and membership
// ----------------------------------------------------------------------------

func TestSpaces(t *testing.T) {
	home := newHome(t, "team")
	s := open(t, home)

	sps, err := s.Spaces(bg)
	if err != nil || len(sps) != 2 {
		t.Fatalf("spaces: %d, %v", len(sps), err)
	}
	if sps[0].Kind != Personal {
		t.Errorf("personal should sort first, got %+v", sps[0])
	}
	personal, err := s.PersonalSpace(bg)
	if err != nil || personal.ID != sps[0].ID {
		t.Fatalf("PersonalSpace = %+v, %v", personal, err)
	}
	if got, err := s.GetSpace(bg, personal.ID); err != nil || got.Name != "personal" {
		t.Errorf("GetSpace = %+v, %v", got, err)
	}
	if _, err := s.GetSpace(bg, "nope"); !errors.Is(err, ErrSpaceNotFound) {
		t.Errorf("unknown space: want ErrSpaceNotFound, got %v", err)
	}
	if _, err := s.SpaceByName(bg, "nope"); !errors.Is(err, ErrSpaceNotFound) {
		t.Errorf("unknown name: want ErrSpaceNotFound, got %v", err)
	}
	// ErrSpaceNotFound must be distinguishable from a missing entry: it is a
	// configuration fault, and kenward's doctor branches on the difference.
	if errors.Is(ErrSpaceNotFound, ErrNotFound) || errors.Is(ErrNotFound, ErrSpaceNotFound) {
		t.Error("ErrSpaceNotFound and ErrNotFound must not satisfy each other")
	}

	// No member list yet: no members reported, and writing is allowed.
	team := spaceID(t, s, "team")
	for _, id := range []string{personal.ID, team} {
		if ms, err := s.Members(bg, id); err != nil || ms != nil {
			t.Errorf("Members(%s) = %v, %v; want nil, nil", id, ms, err)
		}
		if ok, err := s.CanWrite(bg, id); !ok || err != nil {
			t.Errorf("CanWrite(%s) = %v, %v; want true, nil", id, ok, err)
		}
	}
	if _, err := s.CanWrite(bg, "nope"); !errors.Is(err, ErrSpaceNotFound) {
		t.Errorf("CanWrite on unknown space: want ErrSpaceNotFound, got %v", err)
	}

	// Counting does not require loading bodies, and matches ListEntries.
	mustPut(t, s, team, "ops/a", "A", "body a")
	mustPut(t, s, team, "ops/b", "B", "body b")
	n, err := s.CountEntries(bg, team)
	es, _ := s.ListEntries(bg, team)
	if err != nil || n != 2 || n != len(es) {
		t.Errorf("CountEntries = %d (%v), ListEntries = %d", n, err, len(es))
	}
}

// TestMembersAndCanWrite drives the real member-doc machinery: once a shared
// space has a verified member list, Members reports it and a reader may not
// author into it.
func TestMembersAndCanWrite(t *testing.T) {
	home := newHome(t, "team")
	s := open(t, home)
	team := spaceID(t, s, "team")

	// An owner who is NOT this store, so this store is left a non-member.
	own := newOwner(t)
	own.install(t, home, "team")

	ms, err := s.Members(bg, team)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].AccountID != own.pub || ms[0].Role != Owner {
		t.Fatalf("members = %+v", ms)
	}
	if ok, err := s.CanWrite(bg, team); ok || err != nil {
		t.Errorf("CanWrite for a non-member = %v, %v; want false, nil", ok, err)
	}
	if _, err := s.PutEntry(bg, PutParams{SpaceID: team, Domain: "d/x", Title: "t"}); !errors.Is(err, ErrNotWriter) {
		t.Errorf("non-writer put: want ErrNotWriter, got %v", err)
	}

	// Add this store as a writer (owner-signed v2).
	own.install(t, home, "team", s.AccountID())
	if ok, err := s.CanWrite(bg, team); !ok || err != nil {
		t.Errorf("CanWrite after being granted writer = %v, %v", ok, err)
	}
	if ms, _ := s.Members(bg, team); len(ms) != 2 {
		t.Errorf("members after grant = %+v", ms)
	}
	if _, err := s.PutEntry(bg, PutParams{SpaceID: team, Domain: "d/x", Title: "t"}); err != nil {
		t.Errorf("writer put: %v", err)
	}
}

// owner is a signing identity that is not this store, used to build the
// member-list chain through the real internal/space machinery — a member list
// that never went through the chain rule is not a member list.
type owner struct {
	pub  string
	priv ed25519.PrivateKey
	enc  string
}

func newOwner(t *testing.T) owner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return owner{pub: hex.EncodeToString(pub), priv: priv, enc: newEncPub(t)}
}

func newEncPub(t *testing.T) string {
	t.Helper()
	scalar := make([]byte, 32)
	if _, err := rand.Read(scalar); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(scalar, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(pub)
}

// install appends the next member-doc version to a shared space: this owner
// plus the given accounts as writers.
func (o owner) install(t *testing.T, home, spaceName string, writers ...string) {
	t.Helper()
	withInternalStore(t, home, func(st *store.Store) {
		sp, err := st.SpaceByName(spaceName)
		if err != nil {
			t.Fatal(err)
		}
		wrap := func(enc string) string {
			w, err := space.WrapSpaceKey(sp.SpaceKey, enc)
			if err != nil {
				t.Fatal(err)
			}
			return w
		}
		ownerMember := space.Member{AccountPub: o.pub, EncPub: o.enc,
			Role: space.RoleOwner, WrappedSpaceKey: wrap(o.enc)}
		prev, ok, err := st.LatestMemberDoc(sp.SpaceID)
		if err != nil {
			t.Fatal(err)
		}
		var doc space.MemberDoc
		if !ok {
			doc, err = space.NewMemberDoc(sp.SpaceID, ownerMember, o.priv)
		} else {
			members := []space.Member{ownerMember}
			for _, w := range writers {
				enc := newEncPub(t)
				members = append(members, space.Member{AccountPub: w, EncPub: enc,
					Role: space.RoleWriter, WrappedSpaceKey: wrap(enc)})
			}
			doc, err = space.Evolve(prev, members, o.pub, o.priv)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := st.AddMemberDoc(sp.SpaceID, doc); err != nil {
			t.Fatal(err)
		}
	})
}

// withInternalStore opens the internal store on home for the things the
// public API deliberately cannot do (create spaces, evolve member lists, link
// spaces), and closes it again straight away.
func withInternalStore(t *testing.T, home string, fn func(*store.Store)) {
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
	defer st.Close()
	fn(st)
}

func TestLinksAreHintsNotGrants(t *testing.T) {
	home := newHome(t, "team")
	s := open(t, home)
	personal := spaceID(t, s, "personal")
	team := spaceID(t, s, "team")

	if ids, err := s.Links(bg, personal); err != nil || ids != nil {
		t.Fatalf("no links yet: %v, %v", ids, err)
	}
	withInternalStore(t, home, func(st *store.Store) {
		if err := st.AddLink(personal, team); err != nil {
			t.Fatal(err)
		}
	})
	ids, err := s.Links(bg, personal)
	if err != nil || len(ids) != 1 || ids[0] != team {
		t.Fatalf("links = %v, %v", ids, err)
	}
	// A link never widens a search on its own.
	mustPut(t, s, team, "ops/a", "Team fact", "canary in the team space")
	if hits, _ := s.Search(bg, "canary", SearchOpts{Spaces: []string{personal}}); len(hits) != 0 {
		t.Errorf("a link must not widen a scoped search: %d hits", len(hits))
	}
}

// ----------------------------------------------------------------------------
// Post-write side effects
// ----------------------------------------------------------------------------

// TestNotifyOnWrite covers the quiet failure: an embedded consumer that does
// not opt in gets writes that sit locally until the daemon's next poll, and
// nothing anywhere reports it.
func TestNotifyOnWrite(t *testing.T) {
	for _, on := range []bool{false, true} {
		t.Run(map[bool]string{false: "off", true: "on"}[on], func(t *testing.T) {
			home := newHome(t)
			hits := make(chan struct{}, 4)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/admin/sync" {
					hits <- struct{}{}
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer ts.Close()
			u, _ := url.Parse(ts.URL)
			write(t, filepath.Join(home, "daemon.json"), `{"port":`+u.Port()+`,"token":"t"}`)
			mirror := t.TempDir()
			write(t, filepath.Join(home, "config.json"),
				`{"mirror_dir":"`+strings.ReplaceAll(mirror, `\`, `\\`)+`"}`)

			s := open(t, home, func(o *Options) { o.NotifyOnWrite = on })
			mustPut(t, s, spaceID(t, s, "personal"), "ops/deploy", "Canary", "canary first")

			poked := len(hits) > 0
			_, mirrored := os.Stat(filepath.Join(mirror, "SPINE.md"))
			if poked != on {
				t.Errorf("NotifyOnWrite=%v: daemon poked = %v", on, poked)
			}
			if (mirrored == nil) != on {
				t.Errorf("NotifyOnWrite=%v: mirror rendered = %v", on, mirrored == nil)
			}
		})
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// ----------------------------------------------------------------------------
// Concurrency
// ----------------------------------------------------------------------------

// TestConcurrentUse exercises the one concurrency promise the package makes:
// every method is safe from any number of goroutines.
func TestConcurrentUse(t *testing.T) {
	home := newHome(t, "team")
	s := open(t, home)
	personal := spaceID(t, s, "personal")

	const n = 16
	errs := make(chan error, n*2)
	for i := 0; i < n; i++ {
		go func(i int) {
			_, err := s.PutEntry(bg, PutParams{
				SpaceID: personal, Domain: "ops/deploy", Title: "T", Body: "canary"})
			errs <- err
		}(i)
		go func() {
			_, err := s.Search(bg, "canary", SearchOpts{})
			errs <- err
		}()
	}
	deadline := time.After(30 * time.Second)
	for i := 0; i < n*2; i++ {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("concurrent call failed: %v", err)
			}
		case <-deadline:
			t.Fatal("concurrent calls did not finish")
		}
	}
	if got, _ := s.CountEntries(bg, personal); got != n {
		t.Errorf("wrote %d entries concurrently, store holds %d", n, got)
	}
}
