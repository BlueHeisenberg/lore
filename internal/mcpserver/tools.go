package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/BlueHeisenberg/lore"
	"github.com/BlueHeisenberg/lore/internal/space"
)

// ----------------------------------------------------------------------------
// Arg helpers (mcp-go v0.20.x: Arguments is map[string]any)
// ----------------------------------------------------------------------------

func argString(req mcplib.CallToolRequest, key string) string {
	v, _ := req.Params.Arguments[key].(string)
	return strings.TrimSpace(v)
}

func argInt(req mcplib.CallToolRequest, key string, def int) int {
	if v, ok := req.Params.Arguments[key].(float64); ok {
		return int(v)
	}
	return def
}

func argBool(req mcplib.CallToolRequest, key string) bool {
	v, _ := req.Params.Arguments[key].(bool)
	return v
}

func textResult(s string) (*mcplib.CallToolResult, error) {
	return mcplib.NewToolResultText(s), nil
}

func errResult(format string, a ...any) (*mcplib.CallToolResult, error) {
	return mcplib.NewToolResultError(fmt.Sprintf(format, a...)), nil
}

// ----------------------------------------------------------------------------
// Shared lookups
// ----------------------------------------------------------------------------

// resolveSpace maps a space name or id (empty/"personal" = personal space).
func (s *Server) resolveSpace(ctx context.Context, arg string) (lore.Space, error) {
	if arg == "" || arg == "personal" {
		return s.lo.PersonalSpace(ctx)
	}
	if sp, err := s.lo.GetSpace(ctx, arg); err == nil {
		return sp, nil
	}
	return s.lo.SpaceByName(ctx, arg)
}

// cwdProjectSpace returns the project space for the process CWD, or zero
// Space if the CWD is not in a git project or no space exists for it.
func (s *Server) cwdProjectSpace(ctx context.Context) (lore.Space, bool) {
	cwd, err := os.Getwd()
	if err != nil {
		return lore.Space{}, false
	}
	ref, err := space.FindProjectRef(cwd)
	if err != nil {
		return lore.Space{}, false
	}
	sps, err := s.lo.Spaces(ctx)
	if err != nil {
		return lore.Space{}, false
	}
	for _, sp := range sps {
		if sp.ProjectRef == ref {
			return sp, true
		}
	}
	return lore.Space{}, false
}

// defaultScope is the retrieval default: personal + CWD project + pinned.
func (s *Server) defaultScope(ctx context.Context) []string {
	var ids []string
	if p, err := s.lo.PersonalSpace(ctx); err == nil {
		ids = append(ids, p.ID)
	}
	if sp, ok := s.cwdProjectSpace(ctx); ok {
		ids = append(ids, sp.ID)
	}
	if sps, err := s.lo.Spaces(ctx); err == nil {
		for _, sp := range sps {
			if sp.Pinned && !containsStr(ids, sp.ID) {
				ids = append(ids, sp.ID)
			}
		}
	}
	return ids
}

func containsStr(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func (s *Server) spaceNames(ctx context.Context) map[string]string {
	names := map[string]string{}
	if sps, err := s.lo.Spaces(ctx); err == nil {
		for _, sp := range sps {
			names[sp.ID] = sp.Name
		}
	}
	return names
}

// normalizeMarkers turns "context, non-negotiable" into ["[CONTEXT]","[NON-NEGOTIABLE]"].
// The CSV split is this tool's affordance; the normalisation rule itself is
// lore's, so it comes from lore.NormalizeMarkers rather than being restated.
func normalizeMarkers(csv string) []string {
	if csv == "" {
		return nil
	}
	return lore.NormalizeMarkers(strings.Split(csv, ","))
}

// userModelDomain mirrors the store's rule: profile/ and feedback/ layers
// are the user model and never leave the personal space. Duplicated here
// only to refuse at preview time, before anything is attempted; the store
// enforces it again (lore.ErrUserModel) and that is the enforcement.
func userModelDomain(domain string) bool {
	layer, _, _ := strings.Cut(domain, "/")
	return layer == "profile" || layer == "feedback"
}

// renderEntry writes the full entry: title, one metadata line, body.
func renderEntry(b *strings.Builder, e lore.Entry, spaceName string) {
	fmt.Fprintf(b, "# %s\n", e.Title)
	meta := fmt.Sprintf("id %s (v%d) | space %s | domain %s | %s | origin %s",
		e.ID, e.Version, spaceName, e.Domain, e.Confidence, e.Origin)
	if len(e.Markers) > 0 {
		meta += " | " + strings.Join(e.Markers, " ")
	}
	if e.Provenance != nil {
		meta += fmt.Sprintf(" | copied from %s", e.Provenance.SourceEntry)
	}
	meta += " | updated " + string(e.UpdatedAt)
	b.WriteString(meta + "\n")
	if body := strings.TrimRight(e.Body, "\n"); body != "" {
		b.WriteString("\n" + body + "\n")
	}
}

// ----------------------------------------------------------------------------
// lore_search
// ----------------------------------------------------------------------------

func (s *Server) handleSearch(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	query := argString(req, "query")
	if query == "" {
		return errResult("`query` is required")
	}
	scope := argString(req, "scope")
	spaceArg := argString(req, "space")

	var spaces []string
	switch {
	case spaceArg != "":
		sp, err := s.resolveSpace(ctx, spaceArg)
		if err != nil {
			return errResult("unknown space %q (try lore_spaces)", spaceArg)
		}
		spaces = []string{sp.ID}
	case scope == "all", scope == "all-mine":
		// no space filter: locally-present spaces are exactly the readable set
	case scope == "project":
		sp, ok := s.cwdProjectSpace(ctx)
		if !ok {
			return textResult("no results: the current directory has no project space (scope=project)")
		}
		spaces = []string{sp.ID}
	case scope == "linked":
		sp, ok := s.cwdProjectSpace(ctx)
		if !ok {
			return textResult("no results: the current directory has no project space (scope=linked)")
		}
		spaces = []string{sp.ID}
		if links, err := s.lo.Links(ctx, sp.ID); err == nil {
			for _, id := range links {
				// links are retrieval hints, never access grants: only spaces
				// we actually hold locally (i.e. are a member of) are queried
				if _, err := s.lo.GetSpace(ctx, id); err == nil && !containsStr(spaces, id) {
					spaces = append(spaces, id)
				}
			}
		}
	default:
		spaces = s.defaultScope(ctx)
	}

	results, err := s.lo.Search(ctx, query, lore.SearchOpts{
		Spaces:     spaces,
		Domain:     argString(req, "domain"),
		Marker:     argString(req, "marker"),
		Confidence: lore.Confidence(argString(req, "confidence")),
		Limit:      argInt(req, "limit", 8),
	})
	if err != nil {
		return errResult("search: %v", err)
	}
	if len(results) == 0 {
		return textResult(fmt.Sprintf("no results for %q — the store has nothing matching; do not assume, just proceed without it", query))
	}

	names := s.spaceNames(ctx)
	var b strings.Builder
	fmt.Fprintf(&b, "%d result(s) for %q (full entry: lore_get with the id)\n\n", len(results), query)
	for _, r := range results {
		markers := ""
		if len(r.Markers) > 0 {
			markers = " " + strings.Join(r.Markers, "")
		}
		fmt.Fprintf(&b, "%s  space:%s  domain:%s\n  %s (%s)%s\n  %s\n",
			r.ID, names[r.SpaceID], r.Domain,
			r.Title, r.Confidence, markers,
			strings.ReplaceAll(r.Snippet, "\n", " "))
	}
	return textResult(strings.TrimRight(b.String(), "\n"))
}

// ----------------------------------------------------------------------------
// lore_get
// ----------------------------------------------------------------------------

func (s *Server) handleGet(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	id := argString(req, "id")
	domain := argString(req, "domain")
	if (id == "") == (domain == "") {
		return errResult("pass exactly one of `id` or `domain`")
	}
	names := s.spaceNames(ctx)
	var b strings.Builder
	if id != "" {
		// A deleted entry is ErrNotFound like any other absent id: lore_get is
		// not space-scoped, so distinguishing "deleted" from "never existed"
		// would report across spaces the caller never named.
		e, err := s.lo.GetEntry(ctx, id)
		if errors.Is(err, lore.ErrNotFound) {
			return errResult("no entry with id %q", id)
		}
		if err != nil {
			return errResult("get: %v", err)
		}
		renderEntry(&b, e, names[e.SpaceID])
		return textResult(strings.TrimRight(b.String(), "\n"))
	}
	es, err := s.lo.GetDomain(ctx, domain, nil)
	if err != nil {
		return errResult("get domain: %v", err)
	}
	if len(es) == 0 {
		return textResult(fmt.Sprintf("no entries in domain %q", domain))
	}
	for i, e := range es {
		if i > 0 {
			b.WriteString("\n---\n\n")
		}
		renderEntry(&b, e, names[e.SpaceID])
	}
	return textResult(strings.TrimRight(b.String(), "\n"))
}

// ----------------------------------------------------------------------------
// lore_put
// ----------------------------------------------------------------------------

func (s *Server) handlePut(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	title := argString(req, "title")
	body := argString(req, "body")
	domain := argString(req, "domain")
	if title == "" || body == "" || domain == "" {
		return errResult("`title`, `body` and `domain` are required")
	}

	var target lore.Space
	if spaceArg := argString(req, "space"); spaceArg != "" {
		sp, err := s.resolveSpace(ctx, spaceArg)
		if err != nil {
			return errResult("unknown space %q (try lore_spaces)", spaceArg)
		}
		target = sp
	} else {
		// Capture routing: user -> personal, codebase -> CWD project space,
		// ambiguous (the default) -> personal.
		personal, err := s.lo.PersonalSpace(ctx)
		if err != nil {
			return errResult("no personal space (run `lore init`): %v", err)
		}
		subject := space.Subject(argString(req, "subject"))
		if subject == "" {
			subject = space.SubjectAmbiguous
		}
		projectID := ""
		if sp, ok := s.cwdProjectSpace(ctx); ok {
			projectID = sp.ID
		}
		targetID := space.RouteSpace(subject, personal.ID, projectID)
		if target, err = s.lo.GetSpace(ctx, targetID); err != nil {
			return errResult("routed space: %v", err)
		}
	}

	e, err := s.lo.PutEntry(ctx, lore.PutParams{
		ID:         argString(req, "id"),
		SpaceID:    target.ID,
		Domain:     domain,
		Title:      title,
		Body:       body,
		Markers:    normalizeMarkers(argString(req, "markers")),
		Confidence: lore.Confidence(argString(req, "confidence")), // zero: provisional
		Origin:     lore.Origin(argString(req, "origin")),         // zero: evidence
	})
	if err != nil {
		return errResult("put: %v", err)
	}
	return textResult(fmt.Sprintf("stored %s (v%d) in space %q — domain %s, confidence %s, origin %s",
		e.ID, e.Version, target.Name, e.Domain, e.Confidence, e.Origin))
}

// ----------------------------------------------------------------------------
// lore_delete
// ----------------------------------------------------------------------------

// handleDelete tombstones one entry. `space` is required and must match the
// entry's own space: entry ids are global (lore_get is not space-scoped), so
// an id alone is a capability to name any entry anywhere — requiring the
// space means a consumer holding an id from one space cannot delete out of
// another. No confirm dance: unlike lore_share, nothing crosses a privacy
// boundary here, and a model confirming with itself is not a safety property
// — the space match is the guard, and the caller's UI is the confirmation.
func (s *Server) handleDelete(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	id := argString(req, "id")
	spaceArg := argString(req, "space")
	if id == "" || spaceArg == "" {
		return errResult("`id` and `space` are required")
	}
	sp, err := s.resolveSpace(ctx, spaceArg)
	if err != nil {
		return errResult("unknown space %q (try lore_spaces)", spaceArg)
	}
	dead, deleted, err := s.lo.DeleteEntry(ctx, sp.ID, id)
	switch {
	case errors.Is(err, lore.ErrNotFound):
		return errResult("no entry with id %q — nothing was deleted", id)
	case errors.Is(err, lore.ErrWrongSpace):
		return errResult("entry %s is not in space %q — nothing was deleted (delete is space-scoped; pass the space the entry actually lives in)", id, sp.Name)
	case err != nil:
		return errResult("delete: %v", err)
	}
	if !deleted {
		return textResult(fmt.Sprintf("already deleted: %s (%q) in space %q, tombstone v%d — nothing to do",
			dead.ID, dead.Title, sp.Name, dead.Version))
	}
	return textResult(fmt.Sprintf("deleted %s (%q, domain %s) from space %q — signed tombstone v%d; it no longer appears in lore_search or lore_get, and the delete propagates to the other devices",
		dead.ID, dead.Title, dead.Domain, sp.Name, dead.Version))
}

// ----------------------------------------------------------------------------
// lore_spaces
// ----------------------------------------------------------------------------

func (s *Server) handleSpaces(ctx context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	sps, err := s.lo.Spaces(ctx)
	if err != nil {
		return errResult("spaces: %v", err)
	}
	var b strings.Builder
	for _, sp := range sps {
		n, _ := s.lo.CountEntries(ctx, sp.ID)
		// A space with no verified member list has exactly one member — this
		// account. Once one exists, report what it says.
		members := 1
		if ms, err := s.lo.Members(ctx, sp.ID); err == nil && len(ms) > 0 {
			members = len(ms)
		}
		extra := ""
		if sp.ProjectRef != "" {
			extra = "  project"
		}
		if sp.Pinned {
			extra += "  pinned"
		}
		fmt.Fprintf(&b, "%s  kind:%s  members:%d  entries:%d%s  id:%s\n",
			sp.Name, sp.Kind, members, n, extra, sp.ID)
	}
	if b.Len() == 0 {
		return textResult("no spaces (run `lore init`)")
	}
	return textResult(strings.TrimRight(b.String(), "\n"))
}

// ----------------------------------------------------------------------------
// lore_share
// ----------------------------------------------------------------------------

func (s *Server) handleShare(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	entryID := argString(req, "entry_id")
	toSpace := argString(req, "to_space")
	if entryID == "" || toSpace == "" {
		return errResult("`entry_id` and `to_space` are required")
	}
	target, err := s.resolveSpace(ctx, toSpace)
	if err != nil {
		return errResult("unknown space %q (try lore_spaces)", toSpace)
	}
	src, err := s.lo.GetEntry(ctx, entryID)
	if errors.Is(err, lore.ErrNotFound) {
		return errResult("no entry with id %q", entryID)
	}
	if err != nil {
		return errResult("get: %v", err)
	}
	if userModelDomain(src.Domain) {
		return errResult("refused: %q is a user-model entry (profile/, feedback/); those never leave the personal space", src.Domain)
	}
	names := s.spaceNames(ctx)

	if !argBool(req, "confirm") {
		var b strings.Builder
		fmt.Fprintf(&b, "REVIEW — this exact content would be COPIED into space %q:\n\n", target.Name)
		renderEntry(&b, src, names[src.SpaceID])
		b.WriteString("\nNothing was shared yet. Call lore_share again with confirm:true to execute the copy (it is a copy with provenance, never a move).")
		return textResult(b.String())
	}

	copied, err := s.lo.CopyEntry(ctx, entryID, target.ID)
	if errors.Is(err, lore.ErrUserModel) {
		return errResult("refused: user-model entries (profile/, feedback/) never leave the personal space")
	}
	if err != nil {
		return errResult("share: %v", err)
	}
	return textResult(fmt.Sprintf("copied: new entry %s in space %q (source %s kept in %q)",
		copied.ID, target.Name, src.ID, names[src.SpaceID]))
}
