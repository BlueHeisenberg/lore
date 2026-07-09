// Package mcpserver is lore's stdio MCP server: five tools over the local
// SQLite store, zero resources, zero prompts, zero per-turn injection.
// Contract: docs/IMPLEMENTATION.md (MCP section). It opens the store
// directly (WAL makes multi-process access safe); after writes it pokes the
// daemon's admin API if one is running and re-renders the distill mirror
// when the personal space changed.
package mcpserver

import (
	"fmt"
	"path/filepath"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/store"
)

// version reported in the MCP initialize handshake.
const version = "0.2.0"

// ServerInstructions is published to the client at initialize. Kept ≤6
// lines per contract: knowledge store, search before assuming, writes land
// personal/provisional by default.
const ServerInstructions = `lore is the user's persistent knowledge store (personal, project and shared spaces). Tools start with lore_.
Search before assuming: call lore_search early when a task touches prior work, conventions, decisions, or user preferences; lore_get fetches full entries.
lore_put stores new learnings; unless told otherwise they land in the personal space with confidence "provisional".
Nothing is injected into your context per turn — knowledge reaches you only through these tool calls.`

// Server holds the open store and the LORE_HOME it came from.
type Server struct {
	home string
	st   *store.Store
}

// Open loads the account and device keys under home (LORE_HOME), verifies
// the device certificate, and opens the store with a signer.
func Open(home string) (*Server, error) {
	account, err := keys.LoadAccount(home)
	if err != nil {
		return nil, fmt.Errorf("load account (run `lore init` first?): %w", err)
	}
	device, err := keys.LoadDevice(home)
	if err != nil {
		return nil, err
	}
	if err := device.Cert.VerifyForAccount(account.AccountID()); err != nil {
		return nil, err
	}
	priv, err := device.PrivateKey()
	if err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(home, "lore.db"), &store.Signer{
		AccountID:  account.AccountID(),
		DeviceID:   device.DeviceID(),
		DevicePriv: priv,
	})
	if err != nil {
		return nil, err
	}
	return &Server{home: home, st: st}, nil
}

// Close closes the underlying store.
func (s *Server) Close() error { return s.st.Close() }

// MCPServer builds the mark3labs MCP server with lore's five tools
// registered. No resources, no prompts.
func (s *Server) MCPServer() *server.MCPServer {
	m := server.NewMCPServer("lore", version,
		server.WithToolCapabilities(false),
		server.WithInstructions(ServerInstructions),
	)
	s.registerTools(m)
	return m
}

// Serve opens the store under home and serves MCP on stdio until the
// client disconnects. This is what `lore mcp` runs.
func Serve(home string) error {
	s, err := Open(home)
	if err != nil {
		return err
	}
	defer s.Close()
	return server.ServeStdio(s.MCPServer())
}

func (s *Server) registerTools(m *server.MCPServer) {
	m.AddTool(mcplib.NewTool("lore_search",
		mcplib.WithDescription(
			"Full-text search over the lore knowledge store. Returns compact results: "+
				"id, space, domain, title, snippet, confidence, markers. Default scope is "+
				"the personal space plus the current directory's project space plus pinned "+
				"spaces; scope=all searches every local space.",
		),
		mcplib.WithString("query", mcplib.Required(),
			mcplib.Description("Free-text search terms (matched against title, body, domain).")),
		mcplib.WithString("scope",
			mcplib.Description("default = personal + CWD project + pinned spaces; project = CWD project space only; linked = CWD project + its linked spaces (membership-filtered); all-mine/all = every local space."),
			mcplib.Enum("default", "project", "linked", "all-mine", "all")),
		mcplib.WithString("space",
			mcplib.Description("Restrict to one space by name or id (overrides scope).")),
		mcplib.WithString("domain",
			mcplib.Description("Filter by exact domain, e.g. ops/deploy.")),
		mcplib.WithString("marker",
			mcplib.Description("Filter by marker, e.g. IMPORTANT or [NON-NEGOTIABLE].")),
		mcplib.WithString("confidence",
			mcplib.Description("Filter by confidence."),
			mcplib.Enum("experimental", "provisional", "validated", "hardened")),
		mcplib.WithNumber("limit",
			mcplib.Description("Max results (default 8)."),
			mcplib.DefaultNumber(8)),
	), s.handleSearch)

	m.AddTool(mcplib.NewTool("lore_get",
		mcplib.WithDescription(
			"Fetch full knowledge entries. Pass exactly one of: id (one entry) or "+
				"domain (all live entries in that domain).",
		),
		mcplib.WithString("id",
			mcplib.Description("Entry id from lore_search.")),
		mcplib.WithString("domain",
			mcplib.Description("Domain, e.g. ops/deploy — returns every live entry in it.")),
	), s.handleGet)

	m.AddTool(mcplib.NewTool("lore_put",
		mcplib.WithDescription(
			"Store a learning in lore. When space is omitted it is routed by subject: "+
				"about the user -> personal; about the codebase -> the CWD's project "+
				"space; ambiguous -> personal. Returns the entry id and the space it "+
				"landed in. To update an existing entry, pass its id.",
		),
		mcplib.WithString("title", mcplib.Required(),
			mcplib.Description("Short entry title.")),
		mcplib.WithString("body", mcplib.Required(),
			mcplib.Description("Entry body: the principle first, the evidence after.")),
		mcplib.WithString("domain", mcplib.Required(),
			mcplib.Description("layer/name, e.g. ops/deploy or craft/go-testing.")),
		mcplib.WithString("space",
			mcplib.Description("Target space name or id (skips subject routing).")),
		mcplib.WithString("subject",
			mcplib.Description("What the learning is about, used for routing when space is omitted (default ambiguous -> personal)."),
			mcplib.Enum("user", "codebase", "ambiguous")),
		mcplib.WithString("markers",
			mcplib.Description("Comma-separated markers, e.g. CONTEXT,NON-NEGOTIABLE.")),
		mcplib.WithString("confidence",
			mcplib.Description("Default provisional."),
			mcplib.Enum("experimental", "provisional", "validated", "hardened")),
		mcplib.WithString("origin",
			mcplib.Description("Default evidence."),
			mcplib.Enum("evidence", "directive", "convention", "constraint")),
		mcplib.WithString("id",
			mcplib.Description("Existing entry id to write a new version of.")),
	), s.handlePut)

	m.AddTool(mcplib.NewTool("lore_spaces",
		mcplib.WithDescription("List lore spaces with kind, name, member count and entry count."),
	), s.handleSpaces)

	m.AddTool(mcplib.NewTool("lore_share",
		mcplib.WithDescription(
			"Copy an entry into another space (always a copy with provenance, never a "+
				"move). Call with confirm=false first: it returns the full content for "+
				"review; call again with confirm=true to execute. User-model entries "+
				"(profile/, feedback/) never leave the personal space.",
		),
		mcplib.WithString("entry_id", mcplib.Required(),
			mcplib.Description("Entry to copy.")),
		mcplib.WithString("to_space", mcplib.Required(),
			mcplib.Description("Destination space name or id.")),
		mcplib.WithBoolean("confirm",
			mcplib.Description("false = preview only; true = execute the copy."),
			mcplib.DefaultBool(false)),
	), s.handleShare)
}
