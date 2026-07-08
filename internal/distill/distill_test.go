package distill

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BlueHeisenberg/lore/internal/store"
)

func testStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(t.TempDir(), "lore.db"), &store.Signer{
		AccountID:  hex.EncodeToString(pub), // fine for tests
		DeviceID:   hex.EncodeToString(pub),
		DevicePriv: priv,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	key := make([]byte, 32)
	rand.Read(key)
	sp, err := s.CreateSpace("personal", "personal", "", key)
	if err != nil {
		t.Fatal(err)
	}
	return s, sp.SpaceID
}

const opsDeployMD = `# Deploy procedure

Always canary first, then 10% rollout. [NON-NEGOTIABLE]

- [CONTEXT] staging is different, direct deploy is fine there.
`

const craftGoMD = `---
confidence: hardened
staleness: 90d
---
# Go testing habits

Prefer table tests. [IMPORTANT] Never mock the filesystem, use t.TempDir.
`

const profileTrustMD = `Trusts quick iterations more than upfront design.
`

// writeFixture builds a small distill dir: two layers + profile + SPINE.
func writeFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"ops/deploy.md":      opsDeployMD,
		"craft/go.md":        craftGoMD,
		"profile/trust.md":   profileTrustMD,
		"SPINE.md":           "# SPINE\nstale hand-written index\n",
		"ops/notes.txt":      "not markdown, ignored",
		"README-toplevel.md": "top-level file, not a layer entry",
	}
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestScrapeMarkers(t *testing.T) {
	body := "x [CONTEXT] y [IMPORTANT] z [CONTEXT] [NON-NEGOTIABLE] [DEPRECATED] [CORRECTED] [DIRECTIVE] [UPDATED] [PROVISIONAL] [MADEUP]"
	got := ScrapeMarkers(body)
	want := []string{"[CONTEXT]", "[IMPORTANT]", "[NON-NEGOTIABLE]", "[DEPRECATED]", "[CORRECTED]", "[DIRECTIVE]", "[UPDATED]", "[PROVISIONAL]"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ScrapeMarkers = %v, want %v", got, want)
	}
	if ScrapeMarkers("no markers here") != nil {
		t.Fatal("want nil for marker-free body")
	}
}

func TestImportRenderRoundtrip(t *testing.T) {
	s, spaceID := testStore(t)
	src := writeFixture(t)

	res, err := Import(s, spaceID, src)
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 3 || res.Skipped != 0 {
		t.Fatalf("import counts: %+v", res)
	}

	// Domain, title, markers, confidence.
	deploy, err := s.GetDomain("ops/deploy", []string{spaceID})
	if err != nil || len(deploy) != 1 {
		t.Fatalf("ops/deploy: %v %d", err, len(deploy))
	}
	if deploy[0].Title != "Deploy procedure" || deploy[0].Confidence != "validated" {
		t.Fatalf("deploy entry: %+v", deploy[0])
	}
	if !reflect.DeepEqual(deploy[0].Markers, []string{"[NON-NEGOTIABLE]", "[CONTEXT]"}) {
		t.Fatalf("deploy markers: %v", deploy[0].Markers)
	}
	goEntry, _ := s.GetDomain("craft/go", []string{spaceID})
	if goEntry[0].Confidence != "hardened" { // from frontmatter
		t.Fatalf("frontmatter confidence: %+v", goEntry[0])
	}
	trust, _ := s.GetDomain("profile/trust", []string{spaceID})
	if trust[0].Title != "trust" { // no H1 -> filename
		t.Fatalf("fallback title: %q", trust[0].Title)
	}
	// SPINE.md itself must not be an entry.
	if hits, _ := s.Search("stale hand-written", store.SearchOpts{}); len(hits) != 0 {
		t.Fatal("SPINE.md was imported")
	}

	// Idempotent: nothing changed, nothing imported.
	res2, err := Import(s, spaceID, src)
	if err != nil || res2.Imported != 0 || res2.Skipped != 3 {
		t.Fatalf("reimport: %v %+v", err, res2)
	}

	// Changed file becomes a new version of the same entry.
	changed := opsDeployMD + "\nAddendum: rollback plan required.\n"
	if err := os.WriteFile(filepath.Join(src, "ops", "deploy.md"), []byte(changed), 0o644); err != nil {
		t.Fatal(err)
	}
	if res3, _ := Import(s, spaceID, src); res3.Imported != 1 {
		t.Fatalf("changed reimport: %+v", res3)
	}
	deploy2, _ := s.GetDomain("ops/deploy", []string{spaceID})
	if len(deploy2) != 1 || deploy2[0].EntryID != deploy[0].EntryID || deploy2[0].Version != 2 {
		t.Fatalf("changed file did not version the same entry: %+v", deploy2)
	}

	// Render to a fresh dir: byte-identical files modulo SPINE regeneration.
	dst := t.TempDir()
	if _, err := Render(s, spaceID, dst); err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]string{
		"ops/deploy.md":    changed,
		"craft/go.md":      craftGoMD,
		"profile/trust.md": profileTrustMD,
	} {
		got, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		if string(got) != want {
			t.Fatalf("%s not byte-identical after roundtrip:\n%q\nwant\n%q", rel, got, want)
		}
	}
	spine, err := os.ReadFile(filepath.Join(dst, SpineFile))
	if err != nil {
		t.Fatal(err)
	}
	ss := string(spine)
	for _, want := range []string{"## ops", "## craft", "## profile",
		"- [Deploy procedure](ops/deploy.md) — Always canary first"} {
		if !strings.Contains(ss, want) {
			t.Fatalf("SPINE missing %q:\n%s", want, ss)
		}
	}
	if n := strings.Count(ss, "\n"); n > 80 {
		t.Fatalf("SPINE over budget: %d lines", n)
	}
}

func TestLoopGuard(t *testing.T) {
	s, spaceID := testStore(t)
	src := writeFixture(t)
	if _, err := Import(s, spaceID, src); err != nil {
		t.Fatal(err)
	}
	rec, err := Render(s, spaceID, src)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(src, "ops", "deploy.md")
	content, _ := os.ReadFile(path)
	if !rec.IsSelfWrite(path, content) {
		t.Fatal("renderer output not recognized as self-write")
	}
	if rec.IsSelfWrite(path, append(content, []byte("external edit\n")...)) {
		t.Fatal("external edit misclassified as self-write")
	}
	if !rec.IsSelfWrite(filepath.Join(src, SpineFile), mustRead(t, filepath.Join(src, SpineFile))) {
		t.Fatal("SPINE render not recognized as self-write")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestWatchImportsExternalEditsAndSkipsSelfWrites(t *testing.T) {
	s, spaceID := testStore(t)
	src := writeFixture(t)
	if _, err := Import(s, spaceID, src); err != nil {
		t.Fatal(err)
	}
	rec, err := Render(s, spaceID, src)
	if err != nil {
		t.Fatal(err)
	}
	w, err := Watch(s, spaceID, src, rec, 150*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	// External edit -> imported as a new version after the debounce.
	path := filepath.Join(src, "ops", "deploy.md")
	edited := opsDeployMD + "\nExternal edit via /distill.\n"
	if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		es, _ := s.GetDomain("ops/deploy", []string{spaceID})
		if len(es) == 1 && es[0].Version == 2 && strings.Contains(es[0].Body, "External edit") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("watcher never imported external edit: %+v", es)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Renderer re-writing the same content must NOT create a version.
	rec2, err := Render(s, spaceID, src)
	if err != nil {
		t.Fatal(err)
	}
	_ = rec2
	time.Sleep(600 * time.Millisecond) // give any (wrong) import time to land
	es, _ := s.GetDomain("ops/deploy", []string{spaceID})
	if es[0].Version != 2 {
		t.Fatalf("render self-write caused an import loop: version %d", es[0].Version)
	}
}
