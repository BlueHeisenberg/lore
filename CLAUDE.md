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

- **All phases 0–5 built and validated locally (2026-07-09).** Everything runs and is tested on this machine; only external accounts are pending (see SETUP-ACCOUNTS.md for the exact plug-in slots: Cloudflare domains/tunnel, home server, Stripe test keys, agentmesh push+tag to drop the go.mod replace).
- Phase 0: agentmesh (D:\Projects\agentmesh, local commit) exposes pkg/discovery, pkg/transport, pkg/identity; lore imports them via go.mod replace.
- Binaries: `cmd/lore` (CLI + daemon + MCP) and `cmd/lore-relay` (hosted-state relay). docs/IMPLEMENTATION.md is the binding contract.
- Validated end-to-end: `claude -p` drives lore_search/lore_put through `lore mcp` (test/mcp/E2E-NOTES.md); two-daemon LAN sync + enrollment (test/sync); shared spaces with signed member docs, LAN invites, isolation (test/shared); relay signup/fresh-device login/tamper rejection/long-poll (test/relayclient); full relay-only two-account demo incl. grant reconciliation and no-plaintext-on-relay check (scratchpad e2e-grand.sh, all checks passed).
- Safety rule (learned the hard way): nothing may default to the real `~/.claude/distill`; the mirror is opt-in via config.json distill_dir. Tests always use scratch LORE_HOMEs.
- Known v1 gaps: relay-based invites by handle (`lore invites` pending list) not built — invites are LAN/out-of-band; member removal = manual space_key rotation; member docs don't carry device certs (documented in syncproto/apply.go); GoReleaser/CI not set up.
