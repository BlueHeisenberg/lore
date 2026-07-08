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

- Phase: design. Docs written, repo created (private).
- Next task: Phase 0 — extract `pkg/discovery` + `pkg/transport` in agentmesh, then Phase 1 scaffold per ROADMAP.md.
