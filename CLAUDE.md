# lore — project instructions

Read `README.md`, `docs/IMPLEMENTATION.md` (the binding contract), `docs/ARCHITECTURE.md`
and `docs/ROADMAP.md` before changing anything.

## Ground rules

- **Git identity**: commit as `BlueHeisenberg <2033896+BlueHeisenberg@users.noreply.github.com>`.
  Never as the maintainer's work identity; `gh auth switch --user BlueHeisenberg` if needed.
- **This repository is public.** Nothing goes in it that would not be shown to a stranger:
  no third-party names, no LAN addresses, no personal or financial arrangements, no local
  filesystem paths, no credentials of any kind. Session notes belong outside the repo.
- **No `replace` directive in `go.mod`, ever.** A `replace` in a dependency's go.mod is
  ignored by the consuming module, so a local-path replace here breaks every importer at
  resolution time. agentmesh is pinned at a published tag.
- **Sibling project**: agentmesh (github.com/BlueHeisenberg/agentmesh) is the communication
  layer; lore is the knowledge layer. lore *imports* its `pkg/discovery`, `pkg/identity` and
  `pkg/transport`, never copies them.
- **Trust-model boundary**: agentmesh is ephemeral/anonymous; lore is persistent/identity-based.
  Do not blur this (no persistent identity in agentmesh, no anonymous write paths in lore).
- **Context discipline**: the lore MCP server injects nothing per turn. Knowledge reaches the
  agent only via explicit tool calls or the mirror startup convention.
- **distill compatibility**: the knowledge format is aura-distill's (SPINE.md + domain files +
  markers). Check aura-distill's licence (github.com/tomacco/aura-distill) before importing
  any code from it.
- Go 1.25, same toolchain and release approach as agentmesh (GoReleaser + GitHub Actions on
  tag push).

## The public API is a promise; internal/ is not

The root package (`package lore`) is lore's compatibility surface. Everything under
`internal/` — sync, signing, membership, the relay, the schema, the canonical encodings —
changes without notice and gains no exported accessor. Two rules follow:

- **`internal/mcpserver` is written against the public package only.** That is the standing
  design test: if `lore mcp` cannot be built on the public surface, no other consumer can
  either. Do not "temporarily" reach into `internal/store` from it.
- **The canonical signing encoding is frozen.** One LORE_HOME is shared by up to three
  differently-versioned builds that verify each other's signatures; a changed digest stops
  sync silently. `TestCanonicalEncodingIsFrozen` guards it — if it goes red the change is
  wrong, not the golden.

## Testing

Real stores in `t.TempDir()`, never a fake — this project has been bitten repeatedly by
doubles that could not fail the way SQLite fails. A new assertion is not done until it has
been shown to fail with the code reverted. Nothing may touch the real `~/.lore` or the real
mirror directory.

Full gate, all with `GOWORK=off`: `gofmt -l .`, `go vet ./...`, `go build ./...`,
`go test -count=1 ./...`.

## Current state

- Phases 0–5 built and validated: local core, MCP, daemon/sync/enroll/vault, shared spaces
  with signed member docs, LAN and relay invites, relay server with billing hooks.
- Public Go API at the module root; `internal/mcpserver` rewritten onto it; `cmd/lore` stays
  on `internal/` (init, space create, join, enroll, backup and serve need keys and the daemon).
- BSL 1.1, public repository, importable module. External accounts still pending — see
  SETUP-ACCOUNTS.md.
- Known gaps: relay-based invites by handle not built (invites are LAN/token); member removal
  is manual space_key rotation; member docs carry no device certs (documented in
  syncproto/apply.go); GoReleaser/CI not set up.
