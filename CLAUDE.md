# lore — project instructions

Read `README.md`, `docs/ARCHITECTURE.md`, and `docs/ROADMAP.md` before doing anything; they are the source of truth for scope and design. The project is in design phase — no Go code exists yet.

## Ground rules

- **Git identity**: commit as `BlueHeisenberg <2033896+BlueHeisenberg@users.noreply.github.com>`. Never as BlueHeisenberg. `gh auth switch --user BlueHeisenberg` if needed.
- **Sibling project**: agentmesh (`../harnessP2P`, github.com/BlueHeisenberg/agentmesh) is the communication layer; lore is the knowledge layer. lore must *import* agentmesh's discovery/transport packages (to be extracted to `pkg/` there — Phase 0), never copy them.
- **Trust-model boundary**: agentmesh is ephemeral/anonymous; lore is persistent/identity-based. Do not blur this (e.g., no persistent identity features in agentmesh, no anonymous write paths in lore).
- **Context discipline**: the lore MCP server injects nothing per turn. Knowledge reaches the agent only via explicit tool calls or the distill startup convention.
- **distill compatibility**: the knowledge format is aura-distill's (SPINE.md + domain files + markers). Check aura-distill's license (github.com/tomacco/aura-distill) before importing code from it.
- Go 1.25, same toolchain and release approach as agentmesh (GoReleaser + GitHub Actions on tag push) when code starts.

## Current state (update this section as work progresses)

- Phase: 1 (local core) done. `internal/keys` (account/device keys, certs, recovery code), `internal/store` (SQLite WAL + FTS5, canonical signing, LWW ApplyRemote, enforcement rules), `internal/space` (project_ref, routing, space_key), `internal/distill` (import/render/watch with loop-guard), `cmd/lore` (init/put/get/search/spaces/status/distill). All unit tests green; e2e verified on Windows.
- Phase 0 done: agentmesh (D:\Projects\agentmesh, commit 4914c65, local) exposes pkg/discovery, pkg/transport, pkg/identity; lore consumes them via the go.mod replace directive.
- docs/IMPLEMENTATION.md is the binding build contract (schema, wire formats, crypto, CLI surface).
- Next: Phases 2 (MCP) and 3 (daemon/sync) in flight; then 4 (shared spaces), 5 (relay, local-only pending accounts — see SETUP-ACCOUNTS.md).
