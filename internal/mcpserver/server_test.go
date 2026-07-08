package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
)

// newTestServer builds a Server over a temp LORE_HOME with fresh keys and a
// personal space. It never touches the real ~/.lore or ~/.claude/distill.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	home := t.TempDir()
	account, err := keys.GenerateAccount()
	if err != nil {
		t.Fatal(err)
	}
	device, err := keys.GenerateDevice("mcptest", account)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveAccount(home, account); err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveDevice(home, device); err != nil {
		t.Fatal(err)
	}
	s, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	key, err := space.NewSpaceKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.CreateSpace("personal", "personal", "", key); err != nil {
		t.Fatal(err)
	}
	return s
}

func mkSpace(t *testing.T, s *Server, name, projectRef string) store.Space {
	t.Helper()
	key, err := space.NewSpaceKey()
	if err != nil {
		t.Fatal(err)
	}
	sp, err := s.st.CreateSpace("shared", name, projectRef, key)
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

func seed(t *testing.T, s *Server, spaceID, domain, title, body string, markers []string, confidence string) store.Entry {
	t.Helper()
	e, err := s.st.PutEntry(store.PutParams{
		SpaceID: spaceID, Domain: domain, Title: title, Body: body,
		Markers: markers, Confidence: confidence,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

type handler func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error)

// call drives a tool handler directly and returns (text, isError).
func call(t *testing.T, h handler, args map[string]any) (string, bool) {
	t.Helper()
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = args
	res, err := h(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned protocol error: %v", err)
	}
	if len(res.Content) == 0 {
		t.Fatal("handler returned no content")
	}
	tc, ok := res.Content[0].(mcplib.TextContent)
	if !ok {
		t.Fatalf("content is %T, want TextContent", res.Content[0])
	}
	return tc.Text, res.IsError
}

// chdirNonGit moves the process CWD outside any git repo so the CWD project
// space never leaks into scoping.
func chdirNonGit(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
}

// ----------------------------------------------------------------------------
// lore_search
// ----------------------------------------------------------------------------

func TestSearchScopingAndFilters(t *testing.T) {
	chdirNonGit(t)
	s := newTestServer(t)
	personal, _ := s.st.PersonalSpace()
	team := mkSpace(t, s, "team", "")

	seed(t, s, personal.SpaceID, "ops/deploy", "Deploy procedure",
		"Deploys go through canary first.", []string{"[NON-NEGOTIABLE]"}, "validated")
	seed(t, s, personal.SpaceID, "craft/go-testing", "Table tests",
		"Prefer table-driven deploy-unrelated tests.", nil, "provisional")
	seed(t, s, team.SpaceID, "ops/deploy", "Team deploy",
		"Team deploys use blue-green.", nil, "provisional")

	// default scope: personal only (no CWD project space, team not pinned)
	text, isErr := call(t, s.handleSearch, map[string]any{"query": "deploy"})
	if isErr {
		t.Fatalf("search errored: %s", text)
	}
	if !strings.Contains(text, "Deploy procedure") {
		t.Errorf("default scope missing personal entry:\n%s", text)
	}
	if strings.Contains(text, "Team deploy") {
		t.Errorf("default scope leaked shared-space entry:\n%s", text)
	}

	// scope=all sees the shared space too
	text, _ = call(t, s.handleSearch, map[string]any{"query": "deploy", "scope": "all"})
	if !strings.Contains(text, "Team deploy") || !strings.Contains(text, "Deploy procedure") {
		t.Errorf("scope=all should see both spaces:\n%s", text)
	}

	// space param restricts to one space
	text, _ = call(t, s.handleSearch, map[string]any{"query": "deploy", "space": "team"})
	if !strings.Contains(text, "Team deploy") || strings.Contains(text, "Deploy procedure") {
		t.Errorf("space=team should only see the team entry:\n%s", text)
	}

	// marker filter
	text, _ = call(t, s.handleSearch, map[string]any{"query": "deploy", "scope": "all", "marker": "NON-NEGOTIABLE"})
	if !strings.Contains(text, "Deploy procedure") || strings.Contains(text, "Team deploy") {
		t.Errorf("marker filter wrong:\n%s", text)
	}

	// confidence filter
	text, _ = call(t, s.handleSearch, map[string]any{"query": "deploy", "scope": "all", "confidence": "validated"})
	if !strings.Contains(text, "Deploy procedure") || strings.Contains(text, "Team deploy") {
		t.Errorf("confidence filter wrong:\n%s", text)
	}

	// domain filter
	text, _ = call(t, s.handleSearch, map[string]any{"query": "deploy", "domain": "craft/go-testing"})
	if !strings.Contains(text, "Table tests") || strings.Contains(text, "Deploy procedure") {
		t.Errorf("domain filter wrong:\n%s", text)
	}

	// results carry id, space name, confidence, markers
	text, _ = call(t, s.handleSearch, map[string]any{"query": "canary"})
	if !strings.Contains(text, "space:personal") || !strings.Contains(text, "(validated)") ||
		!strings.Contains(text, "[NON-NEGOTIABLE]") {
		t.Errorf("compact result missing fields:\n%s", text)
	}

	// no results: a message, not an error
	text, isErr = call(t, s.handleSearch, map[string]any{"query": "zebra unicorn"})
	if isErr || !strings.Contains(text, "no results") {
		t.Errorf("empty search should be a friendly message, got isErr=%v:\n%s", isErr, text)
	}

	// missing query: error
	_, isErr = call(t, s.handleSearch, map[string]any{})
	if !isErr {
		t.Error("missing query should be a tool error")
	}

	// unknown space: error
	_, isErr = call(t, s.handleSearch, map[string]any{"query": "deploy", "space": "nope"})
	if !isErr {
		t.Error("unknown space should be a tool error")
	}
}

// ----------------------------------------------------------------------------
// lore_get
// ----------------------------------------------------------------------------

func TestGetByIDAndDomain(t *testing.T) {
	chdirNonGit(t)
	s := newTestServer(t)
	personal, _ := s.st.PersonalSpace()
	e := seed(t, s, personal.SpaceID, "ops/deploy", "Deploy procedure",
		"Deploys go through canary first.", []string{"[NON-NEGOTIABLE]"}, "validated")
	seed(t, s, personal.SpaceID, "ops/deploy", "Rollback",
		"Rollback is one command.", nil, "provisional")

	text, isErr := call(t, s.handleGet, map[string]any{"id": e.EntryID})
	if isErr {
		t.Fatalf("get by id errored: %s", text)
	}
	for _, want := range []string{"# Deploy procedure", e.EntryID, "canary first", "validated", "[NON-NEGOTIABLE]", "space personal"} {
		if !strings.Contains(text, want) {
			t.Errorf("get by id missing %q:\n%s", want, text)
		}
	}

	text, _ = call(t, s.handleGet, map[string]any{"domain": "ops/deploy"})
	if !strings.Contains(text, "Deploy procedure") || !strings.Contains(text, "Rollback") {
		t.Errorf("get by domain should return both entries:\n%s", text)
	}

	// exactly one of id/domain
	if _, isErr := call(t, s.handleGet, map[string]any{}); !isErr {
		t.Error("neither id nor domain should error")
	}
	if _, isErr := call(t, s.handleGet, map[string]any{"id": e.EntryID, "domain": "ops/deploy"}); !isErr {
		t.Error("both id and domain should error")
	}
	if _, isErr := call(t, s.handleGet, map[string]any{"id": "no-such-id"}); !isErr {
		t.Error("unknown id should error")
	}
}

// ----------------------------------------------------------------------------
// lore_put routing
// ----------------------------------------------------------------------------

func TestPutRouting(t *testing.T) {
	// Fake git project so the CWD resolves to a project space.
	projDir := t.TempDir()
	remote := "https://github.com/example/mcp-routing-proj.git"
	gitDir := filepath.Join(projDir, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := "[remote \"origin\"]\n\turl = " + remote + "\n"
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(projDir)

	s := newTestServer(t)
	personal, _ := s.st.PersonalSpace()
	proj := mkSpace(t, s, "mcp-routing-proj", space.ProjectRef(remote))

	put := func(args map[string]any) string {
		t.Helper()
		text, isErr := call(t, s.handlePut, args)
		if isErr {
			t.Fatalf("put errored: %s", text)
		}
		return text
	}

	// subject omitted (ambiguous) -> personal
	text := put(map[string]any{"title": "T1", "body": "b", "domain": "ops/a"})
	if !strings.Contains(text, `space "personal"`) {
		t.Errorf("ambiguous should land personal:\n%s", text)
	}

	// subject=user -> personal
	text = put(map[string]any{"title": "T2", "body": "b", "domain": "ops/b", "subject": "user"})
	if !strings.Contains(text, `space "personal"`) {
		t.Errorf("subject=user should land personal:\n%s", text)
	}

	// subject=codebase -> CWD project space
	text = put(map[string]any{"title": "T3", "body": "b", "domain": "ops/c", "subject": "codebase"})
	if !strings.Contains(text, `space "mcp-routing-proj"`) {
		t.Errorf("subject=codebase should land in the project space:\n%s", text)
	}
	if es, _ := s.st.ListEntries(proj.SpaceID); len(es) != 1 {
		t.Errorf("project space should hold 1 entry, has %d", len(es))
	}

	// explicit space overrides routing
	text = put(map[string]any{"title": "T4", "body": "b", "domain": "ops/d",
		"subject": "user", "space": "mcp-routing-proj"})
	if !strings.Contains(text, `space "mcp-routing-proj"`) {
		t.Errorf("explicit space should override subject:\n%s", text)
	}

	// defaults: provisional + evidence
	if !strings.Contains(text, "confidence provisional") || !strings.Contains(text, "origin evidence") {
		t.Errorf("defaults not applied:\n%s", text)
	}

	// markers normalized
	put(map[string]any{"title": "T5", "body": "b", "domain": "ops/e", "markers": "context, non-negotiable"})
	res, err := s.st.Search("T5", store.SearchOpts{})
	if err != nil || len(res) != 1 {
		t.Fatalf("seeded T5 not found: %v", err)
	}
	if got := strings.Join(res[0].Markers, " "); got != "[CONTEXT] [NON-NEGOTIABLE]" {
		t.Errorf("markers = %q", got)
	}

	// required params
	if _, isErr := call(t, s.handlePut, map[string]any{"title": "x", "domain": "d/x"}); !isErr {
		t.Error("missing body should error")
	}

	// subject=codebase with NO project space for CWD -> personal (safe side)
	t.Chdir(t.TempDir())
	text = put(map[string]any{"title": "T6", "body": "b", "domain": "ops/f", "subject": "codebase"})
	if !strings.Contains(text, `space "personal"`) {
		t.Errorf("codebase without project space should fall back to personal:\n%s", text)
	}
	_ = personal
}

// ----------------------------------------------------------------------------
// lore_spaces
// ----------------------------------------------------------------------------

func TestSpacesList(t *testing.T) {
	chdirNonGit(t)
	s := newTestServer(t)
	personal, _ := s.st.PersonalSpace()
	team := mkSpace(t, s, "team", "")
	seed(t, s, personal.SpaceID, "ops/a", "A", "body a", nil, "")
	seed(t, s, team.SpaceID, "ops/b", "B", "body b", nil, "")
	seed(t, s, team.SpaceID, "ops/c", "C", "body c", nil, "")

	text, isErr := call(t, s.handleSpaces, nil)
	if isErr {
		t.Fatalf("spaces errored: %s", text)
	}
	for _, want := range []string{
		"personal  kind:personal  members:1  entries:1",
		"team  kind:shared  members:1  entries:2",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("spaces output missing %q:\n%s", want, text)
		}
	}
}

// ----------------------------------------------------------------------------
// lore_share confirm flow + user-model refusal
// ----------------------------------------------------------------------------

func TestShareConfirmFlow(t *testing.T) {
	chdirNonGit(t)
	s := newTestServer(t)
	personal, _ := s.st.PersonalSpace()
	team := mkSpace(t, s, "team", "")
	e := seed(t, s, personal.SpaceID, "ops/deploy", "Deploy procedure",
		"Deploys go through canary first.", nil, "validated")

	// preview: full content, no copy yet
	text, isErr := call(t, s.handleShare, map[string]any{"entry_id": e.EntryID, "to_space": "team"})
	if isErr {
		t.Fatalf("preview errored: %s", text)
	}
	if !strings.Contains(text, "canary first") || !strings.Contains(text, "confirm:true") {
		t.Errorf("preview should show full content and ask for confirm:true:\n%s", text)
	}
	if es, _ := s.st.ListEntries(team.SpaceID); len(es) != 0 {
		t.Fatalf("preview must not copy; team has %d entries", len(es))
	}

	// confirm=true executes the copy with provenance
	text, isErr = call(t, s.handleShare, map[string]any{"entry_id": e.EntryID, "to_space": "team", "confirm": true})
	if isErr {
		t.Fatalf("confirm errored: %s", text)
	}
	es, _ := s.st.ListEntries(team.SpaceID)
	if len(es) != 1 {
		t.Fatalf("team should have 1 entry after confirm, has %d", len(es))
	}
	if es[0].Provenance == nil || es[0].Provenance.SourceEntry != e.EntryID {
		t.Errorf("copied entry missing provenance: %+v", es[0].Provenance)
	}
	if !strings.Contains(text, es[0].EntryID) {
		t.Errorf("confirm response should carry the new entry id:\n%s", text)
	}
	// source still in personal (copy, not move)
	if _, err := s.st.GetEntry(e.EntryID); err != nil {
		t.Errorf("source entry gone after share: %v", err)
	}

	// user-model entries refuse at preview AND confirm
	um := seed(t, s, personal.SpaceID, "profile/trust", "Trust map", "secret", nil, "")
	for _, confirm := range []bool{false, true} {
		text, isErr = call(t, s.handleShare, map[string]any{"entry_id": um.EntryID, "to_space": "team", "confirm": confirm})
		if !isErr || !strings.Contains(text, "never leave the personal space") {
			t.Errorf("user-model share (confirm=%v) should refuse clearly, got isErr=%v:\n%s", confirm, isErr, text)
		}
	}
	if es, _ := s.st.ListEntries(team.SpaceID); len(es) != 1 {
		t.Errorf("user-model entry leaked into team space")
	}

	// unknown entry / space
	if _, isErr := call(t, s.handleShare, map[string]any{"entry_id": "nope", "to_space": "team"}); !isErr {
		t.Error("unknown entry should error")
	}
	if _, isErr := call(t, s.handleShare, map[string]any{"entry_id": e.EntryID, "to_space": "nope"}); !isErr {
		t.Error("unknown space should error")
	}
}

// ----------------------------------------------------------------------------
// post-write side effects: daemon poke + distill re-render
// ----------------------------------------------------------------------------

func TestAfterWriteSideEffects(t *testing.T) {
	chdirNonGit(t)
	s := newTestServer(t)
	personal, _ := s.st.PersonalSpace()
	team := mkSpace(t, s, "team", "")

	// fake daemon admin API
	hits := make(chan string, 8)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/admin/sync" {
			hits <- r.URL.Query().Get("token")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	daemonJSON := `{"port":` + u.Port() + `,"token":"sekrit"}`
	if err := os.WriteFile(filepath.Join(s.home, "daemon.json"), []byte(daemonJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	// scratch distill mirror, explicitly configured — never the real one
	distillDir := t.TempDir()
	cfg := `{"distill_dir":` + string(mustJSON(t, distillDir)) + `}`
	if err := os.WriteFile(filepath.Join(s.home, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// personal write: pokes daemon AND renders distill
	text, isErr := call(t, s.handlePut, map[string]any{
		"title": "Canary rule", "body": "Deploys go through canary first.", "domain": "ops/deploy"})
	if isErr {
		t.Fatalf("put errored: %s", text)
	}
	select {
	case tok := <-hits:
		if tok != "sekrit" {
			t.Errorf("daemon poked with token %q", tok)
		}
	default:
		t.Error("daemon was not poked after personal write")
	}
	if _, err := os.Stat(filepath.Join(distillDir, "SPINE.md")); err != nil {
		t.Errorf("distill mirror not rendered after personal write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(distillDir, "ops", "deploy.md")); err != nil {
		t.Errorf("distill mirror missing domain file: %v", err)
	}

	// shared-space write: pokes daemon but does NOT re-render distill
	before := mtimeOf(t, filepath.Join(distillDir, "SPINE.md"))
	text, isErr = call(t, s.handlePut, map[string]any{
		"title": "Team fact", "body": "blue-green", "domain": "ops/deploy", "space": "team"})
	if isErr {
		t.Fatalf("put errored: %s", text)
	}
	select {
	case <-hits:
	default:
		t.Error("daemon was not poked after shared write")
	}
	if after := mtimeOf(t, filepath.Join(distillDir, "SPINE.md")); !after.Equal(before) {
		t.Error("distill mirror re-rendered for a non-personal write")
	}
	_ = personal
	_ = team
}

func mustJSON(t *testing.T, s string) []byte {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mtimeOf(t *testing.T, path string) time.Time {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.ModTime()
}
