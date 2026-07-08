# lore — roadmap

Phases are ordered so each ships something usable on its own. Tier 3 (paid relay) comes last, only after the local product is proven.

## Phase 0 — prerequisites (in agentmesh)

- [x] agentmesh v0.6.0: hook shrunk to unread-count ping; MCP instructions trimmed (context diet).
- [ ] Extract `internal/discovery` and `internal/transport` to importable public packages (`pkg/discovery`, `pkg/transport`) in agentmesh, so lore can depend on them without forking.

## Phase 1 — local core

- [ ] Repo scaffold: Go module `github.com/BlueHeisenberg/lore`, CLI skeleton (`lore init|put|get|search|serve|mcp`).
- [ ] SQLite store (entries, spaces, FTS5 index).
- [ ] Account + device keys (`lore init` generates account key; device cert signing).
- [ ] distill adapter: import existing `~/.claude/distill/` into the `personal` space; render the space back to the directory; watch for `/distill` writes.
- [ ] Check aura-distill license (github.com/tomacco/aura-distill) before importing any code; format compatibility needs no permission.

**Exit criterion**: `lore search deployment` returns your distilled knowledge; `/distill` in Claude Code keeps working unchanged.

## Phase 2 — MCP server

- [ ] `lore mcp` (stdio MCP server, thin client to the local daemon over unix socket).
- [ ] Tools: `lore_search`, `lore_get`, `lore_put`, `lore_spaces`.
- [ ] Installer registration for the four harnesses (reuse agentmesh install.sh/install.ps1 patterns).
- [ ] Zero per-turn context injection — tools only.
- [ ] `/lore` skill: retrospective capture (distill-equivalent) writing via `lore_put`; tiered invocation policy per docs/DISTILL.md (reads always autonomous, single-fact capture inline, full retrospective suggest-by-default with `autocapture` opt-in).

**Exit criterion**: a Claude Code session on a fresh project answers from knowledge distilled in another project's session, via `lore_search`.

## Phase 3 — own-device sync (tiers 1–2)

- [ ] `lore serve` daemon (one per machine, launchd/systemd/startup task).
- [ ] mDNS discovery (`_lore._tcp`) + static peer list (`lore peer add <addr>` for VPN/Tailscale peers).
- [ ] Version-vector sync of the `personal` space over mTLS, LWW conflict resolution, tombstones.
- [ ] Device enrollment flow (`lore enroll` / `lore approve`).

**Exit criterion**: distill something on the desktop, `lore search` finds it on the laptop over Tailscale.

## Phase 4 — project lore, shared with others

- [ ] Project spaces: `lore project init` (binding from git remote URL), CWD-based scoping in `lore_search`, capture routing personal-vs-project.
- [ ] Signed member lists and roles (owner/writer/reader).
- [ ] Space content encryption (space_key wrapped per member account pubkey).
- [ ] `lore share` / invite flow (out-of-band pubkey exchange v1).
- [ ] First-contact UX: surface new-space invitations for explicit user approval.
- [ ] Enforce personal-space isolation: no members, no entry moves out.

**Exit criterion**: a collaborator's session reads a project-space entry you authored, and cannot read your personal lore.

## Phase 5 — relay service (paid)

- [ ] Coordination server: accounts (handle -> pubkey), device registry, NAT traversal, DERP-style relay.
- [ ] Client: `lore relay login`, automatic fallback direct -> relay.
- [ ] Billing: subscription + one month free trial; expired accounts lose relay only (local tiers keep working).
- [ ] Free tier: one project space shared with one collaborator relays for free, forever (the try-it-with-a-friend hook). Personal-lore relay sync and additional projects/collaborators are paid.
- [ ] Ops: deploy, monitoring, abuse limits.

**Exit criterion**: two machines on different networks, no VPN, sync within seconds of coming online.

## Open questions

- Group-key rotation on member removal (v1: manual space_key rotation; revisit).
- Multiple distill profiles (`~/.claude-<name>/distill`) → map to multiple spaces?
- Embeddings-based search behind `lore_search` (later; FTS5 first).
- Windows daemon story (Scheduled Task vs service).
