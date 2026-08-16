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

	"github.com/BlueHeisenberg/lore"
	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
)

var ctx = context.Background()

// newTestServer builds a Server over a temp LORE_HOME with fresh keys and a
// personal space. It never touches the real ~/.lore or the real mirror dir.
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
	createSpace(t, home, "personal", "personal", "")
	s, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// createSpace makes a space directly through the internal store, because
// space creation is deliberately absent from lore's public API: spaces are
// made out of band by a person who chose a name and a sharing posture. The
// store is opened and closed around the one call so nothing else in the test
// shares a home with a second open store.
func createSpace(t *testing.T, home, kind, name, projectRef string) {
	t.Helper()
	withStore(t, home, func(st *store.Store) {
		key, err := space.NewSpaceKey()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.CreateSpace(kind, name, projectRef, key); err != nil {
			t.Fatal(err)
		}
	})
}

// withStore opens the internal store on home for the things the public API
// deliberately cannot do (create spaces, evolve member lists) and closes it
// again straight away.
func withStore(t *testing.T, home string, fn func(*store.Store)) {
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

func mkSpace(t *testing.T, s *Server, name, projectRef string) lore.Space {
	t.Helper()
	createSpace(t, s.lo.Home(), "shared", name, projectRef)
	sp, err := s.lo.SpaceByName(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

func seed(t *testing.T, s *Server, spaceID, domain, title, body string, markers []string, confidence lore.Confidence) lore.Entry {
	t.Helper()
	e, err := s.lo.PutEntry(ctx, lore.PutParams{
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
	personal, _ := s.lo.PersonalSpace(ctx)
	team := mkSpace(t, s, "team", "")

	seed(t, s, personal.ID, "ops/deploy", "Deploy procedure",
		"Deploys go through canary first.", []string{"[NON-NEGOTIABLE]"}, lore.Validated)
	seed(t, s, personal.ID, "craft/go-testing", "Table tests",
		"Prefer table-driven deploy-unrelated tests.", nil, lore.Provisional)
	seed(t, s, team.ID, "ops/deploy", "Team deploy",
		"Team deploys use blue-green.", nil, lore.Provisional)

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
	personal, _ := s.lo.PersonalSpace(ctx)
	e := seed(t, s, personal.ID, "ops/deploy", "Deploy procedure",
		"Deploys go through canary first.", []string{"[NON-NEGOTIABLE]"}, lore.Validated)
	seed(t, s, personal.ID, "ops/deploy", "Rollback",
		"Rollback is one command.", nil, lore.Provisional)

	text, isErr := call(t, s.handleGet, map[string]any{"id": e.ID})
	if isErr {
		t.Fatalf("get by id errored: %s", text)
	}
	for _, want := range []string{"# Deploy procedure", e.ID, "canary first", "validated", "[NON-NEGOTIABLE]", "space personal"} {
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
	if _, isErr := call(t, s.handleGet, map[string]any{"id": e.ID, "domain": "ops/deploy"}); !isErr {
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
	if n, _ := s.lo.CountEntries(ctx, proj.ID); n != 1 {
		t.Errorf("project space should hold 1 entry, has %d", n)
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
	res, err := s.lo.Search(ctx, "T5", lore.SearchOpts{})
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
}

// ----------------------------------------------------------------------------
// lore_spaces
// ----------------------------------------------------------------------------

func TestSpacesList(t *testing.T) {
	chdirNonGit(t)
	s := newTestServer(t)
	personal, _ := s.lo.PersonalSpace(ctx)
	team := mkSpace(t, s, "team", "")
	mkSpace(t, s, "solo", "")
	seed(t, s, personal.ID, "ops/a", "A", "body a", nil, "")
	seed(t, s, team.ID, "ops/b", "B", "body b", nil, "")
	seed(t, s, team.ID, "ops/c", "C", "body c", nil, "")
	// "is this actually shared, or a lone copy?" is the one thing a consumer
	// asks lore_spaces, so the count must come from the verified member list
	// and not from a local assumption. team has one, solo does not.
	installMemberList(t, s.lo.Home(), "team")

	text, isErr := call(t, s.handleSpaces, nil)
	if isErr {
		t.Fatalf("spaces errored: %s", text)
	}
	for _, want := range []string{
		"personal  kind:personal  members:1  entries:1",
		"team  kind:shared  members:2  entries:2",
		"solo  kind:shared  members:1  entries:0",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("spaces output missing %q:\n%s", want, text)
		}
	}
}

// installMemberList gives a shared space a two-account member list built
// through the real signing chain: v1 defines the owner, an owner-signed v2
// admits a writer. A list that never went through the chain rule is not a
// list, so nothing here is hand-written.
func installMemberList(t *testing.T, home, spaceName string) {
	t.Helper()
	owner, err := keys.GenerateAccount()
	if err != nil {
		t.Fatal(err)
	}
	guest, err := keys.GenerateAccount()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := owner.SigningKey()
	if err != nil {
		t.Fatal(err)
	}
	withStore(t, home, func(st *store.Store) {
		sp, err := st.SpaceByName(spaceName)
		if err != nil {
			t.Fatal(err)
		}
		member := func(a *keys.Account, role string) space.Member {
			wrapped, err := space.WrapSpaceKey(sp.SpaceKey, a.EncPub)
			if err != nil {
				t.Fatal(err)
			}
			return space.Member{AccountPub: a.AccountID(), EncPub: a.EncPub,
				Role: role, WrappedSpaceKey: wrapped}
		}
		v1, err := space.NewMemberDoc(sp.SpaceID, member(owner, space.RoleOwner), priv)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.AddMemberDoc(sp.SpaceID, v1); err != nil {
			t.Fatal(err)
		}
		v2, err := space.Evolve(v1, []space.Member{
			member(owner, space.RoleOwner), member(guest, space.RoleWriter),
		}, owner.AccountID(), priv)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.AddMemberDoc(sp.SpaceID, v2); err != nil {
			t.Fatal(err)
		}
	})
}

// ----------------------------------------------------------------------------
// lore_share confirm flow + user-model refusal
// ----------------------------------------------------------------------------

func TestShareConfirmFlow(t *testing.T) {
	chdirNonGit(t)
	s := newTestServer(t)
	personal, _ := s.lo.PersonalSpace(ctx)
	team := mkSpace(t, s, "team", "")
	e := seed(t, s, personal.ID, "ops/deploy", "Deploy procedure",
		"Deploys go through canary first.", nil, lore.Validated)

	// preview: full content, no copy yet
	text, isErr := call(t, s.handleShare, map[string]any{"entry_id": e.ID, "to_space": "team"})
	if isErr {
		t.Fatalf("preview errored: %s", text)
	}
	if !strings.Contains(text, "canary first") || !strings.Contains(text, "confirm:true") {
		t.Errorf("preview should show full content and ask for confirm:true:\n%s", text)
	}
	if es, _ := s.lo.ListEntries(ctx, team.ID); len(es) != 0 {
		t.Fatalf("preview must not copy; team has %d entries", len(es))
	}

	// confirm=true executes the copy with provenance
	text, isErr = call(t, s.handleShare, map[string]any{"entry_id": e.ID, "to_space": "team", "confirm": true})
	if isErr {
		t.Fatalf("confirm errored: %s", text)
	}
	es, _ := s.lo.ListEntries(ctx, team.ID)
	if len(es) != 1 {
		t.Fatalf("team should have 1 entry after confirm, has %d", len(es))
	}
	if es[0].Provenance == nil || es[0].Provenance.SourceEntry != e.ID {
		t.Errorf("copied entry missing provenance: %+v", es[0].Provenance)
	}
	if !strings.Contains(text, es[0].ID) {
		t.Errorf("confirm response should carry the new entry id:\n%s", text)
	}
	// source still in personal (copy, not move)
	if _, err := s.lo.GetEntry(ctx, e.ID); err != nil {
		t.Errorf("source entry gone after share: %v", err)
	}

	// user-model entries refuse at preview AND confirm
	um := seed(t, s, personal.ID, "profile/trust", "Trust map", "secret", nil, "")
	for _, confirm := range []bool{false, true} {
		text, isErr = call(t, s.handleShare, map[string]any{"entry_id": um.ID, "to_space": "team", "confirm": confirm})
		if !isErr || !strings.Contains(text, "never leave the personal space") {
			t.Errorf("user-model share (confirm=%v) should refuse clearly, got isErr=%v:\n%s", confirm, isErr, text)
		}
	}
	if es, _ := s.lo.ListEntries(ctx, team.ID); len(es) != 1 {
		t.Errorf("user-model entry leaked into team space")
	}

	// unknown entry / space
	if _, isErr := call(t, s.handleShare, map[string]any{"entry_id": "nope", "to_space": "team"}); !isErr {
		t.Error("unknown entry should error")
	}
	if _, isErr := call(t, s.handleShare, map[string]any{"entry_id": e.ID, "to_space": "nope"}); !isErr {
		t.Error("unknown space should error")
	}
}

// ----------------------------------------------------------------------------
// lore_delete
// ----------------------------------------------------------------------------

func TestDeleteToolScopingAndIdempotency(t *testing.T) {
	chdirNonGit(t)
	s := newTestServer(t)
	personal, _ := s.lo.PersonalSpace(ctx)
	mkSpace(t, s, "team", "")
	e := seed(t, s, personal.ID, "ops/deploy", "Deploy procedure",
		"Deploys go through canary first.", nil, lore.Validated)

	// space is required: an id alone must not delete anything.
	text, isErr := call(t, s.handleDelete, map[string]any{"id": e.ID})
	if !isErr || !strings.Contains(text, "required") {
		t.Errorf("missing space should be a tool error:\n%s", text)
	}

	// wrong space: refused, entry untouched.
	text, isErr = call(t, s.handleDelete, map[string]any{"id": e.ID, "space": "team"})
	if !isErr || !strings.Contains(text, "nothing was deleted") {
		t.Errorf("cross-space delete should refuse, got isErr=%v:\n%s", isErr, text)
	}
	if _, err := s.lo.GetEntry(ctx, e.ID); err != nil {
		t.Fatalf("cross-space delete tombstoned the entry: %v", err)
	}

	// unknown id, and unknown space.
	if _, isErr := call(t, s.handleDelete, map[string]any{"id": "no-such-id", "space": "personal"}); !isErr {
		t.Error("unknown id should be a tool error")
	}
	if _, isErr := call(t, s.handleDelete, map[string]any{"id": e.ID, "space": "nope"}); !isErr {
		t.Error("unknown space should be a tool error")
	}

	// the real delete reports what it removed.
	text, isErr = call(t, s.handleDelete, map[string]any{"id": e.ID, "space": "personal"})
	if isErr {
		t.Fatalf("delete errored: %s", text)
	}
	for _, want := range []string{"deleted " + e.ID, `"Deploy procedure"`, `space "personal"`, "tombstone v2"} {
		if !strings.Contains(text, want) {
			t.Errorf("delete response missing %q:\n%s", want, text)
		}
	}

	// gone from search and get.
	text, _ = call(t, s.handleSearch, map[string]any{"query": "canary", "scope": "all"})
	if !strings.Contains(text, "no results") {
		t.Errorf("deleted entry still in search:\n%s", text)
	}
	text, isErr = call(t, s.handleGet, map[string]any{"id": e.ID})
	if !isErr {
		t.Errorf("deleted entry still fetchable by id:\n%s", text)
	}
	text, _ = call(t, s.handleGet, map[string]any{"domain": "ops/deploy"})
	if !strings.Contains(text, "no entries in domain") {
		t.Errorf("deleted entry still in its domain:\n%s", text)
	}

	// second delete: safe no-op, and honest about it — still tombstone v2, so
	// nothing was written the second time.
	text, isErr = call(t, s.handleDelete, map[string]any{"id": e.ID, "space": "personal"})
	if isErr || !strings.Contains(text, "already deleted") {
		t.Errorf("second delete should be a no-op, got isErr=%v:\n%s", isErr, text)
	}
	if !strings.Contains(text, "tombstone v2") {
		t.Errorf("second delete wrote a new version:\n%s", text)
	}
}

// ----------------------------------------------------------------------------
// post-write side effects: daemon poke + mirror re-render
// ----------------------------------------------------------------------------

func TestAfterWriteSideEffects(t *testing.T) {
	chdirNonGit(t)
	s := newTestServer(t)
	mkSpace(t, s, "team", "")

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
	if err := os.WriteFile(filepath.Join(s.lo.Home(), "daemon.json"), []byte(daemonJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	// scratch mirror dir, explicitly configured — never the real one
	mirrorDir := t.TempDir()
	cfg := `{"mirror_dir":` + string(mustJSON(t, mirrorDir)) + `}`
	if err := os.WriteFile(filepath.Join(s.lo.Home(), "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// personal write: pokes daemon AND renders the mirror
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
	if _, err := os.Stat(filepath.Join(mirrorDir, "SPINE.md")); err != nil {
		t.Errorf("mirror not rendered after personal write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(mirrorDir, "ops", "deploy.md")); err != nil {
		t.Errorf("mirror missing domain file: %v", err)
	}

	// shared-space write: pokes daemon but does NOT re-render the mirror
	before := mtimeOf(t, filepath.Join(mirrorDir, "SPINE.md"))
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
	if after := mtimeOf(t, filepath.Join(mirrorDir, "SPINE.md")); !after.Equal(before) {
		t.Error("mirror re-rendered for a non-personal write")
	}
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
