# lore

**Shared knowledge for AI coding sessions — yours, your devices', your team's.**

lore is a knowledge store that AI coding assistants (Claude Code, Cursor, Codex CLI, Antigravity) read and write through MCP, and that Go programs can embed directly. Knowledge distilled in one session is available in every other session — on the same machine, on your other devices, and (if you choose) to teammates you share it with.

It is the sibling project of [agentmesh](https://github.com/BlueHeisenberg/agentmesh): agentmesh is the *communication* layer between live sessions (ephemeral, anonymous, message-passing); lore is the *knowledge* layer (persistent, identity-based, synced). lore reuses agentmesh's discovery and transport packages for LAN sync.

## The problem

Every AI session starts from zero. Session-retrospective systems fix this per-machine: sessions distill learnings into markdown files (a SPINE index + domain files) that future sessions read on startup. But that knowledge is trapped on one machine, in one user's home directory. Switch computers and it's gone. Want a teammate's agent to know what yours learned — no path for that at all.

## Two kinds of lore

**1. Personal lore — from you, for you.** Everything a retrospective captures about *you*: your profile, preferences, craft standards, operational habits, cross-project learnings. It syncs between your harness sessions (same machine), your devices on the local network, and — with the relay — your devices anywhere. Nobody else can be added to it. Your user model (`profile/`, `feedback/`) can never leave it; other personal entries can be *copied out* to a shared space, but only as an explicit, reviewed act.

**2. Shared lore — invite-based.** Two flavours of the same thing: **project spaces** bound to a repo (architecture decisions, constraints, gotchas, corrected conclusions about that codebase) and **topic spaces** bound to nothing ("godot-tips", "ble-security" — pure knowledge you share with someone).

When a session distills learnings, each one is routed: insights about the user go to personal lore, insights about the codebase go to that project's lore. Ambiguous ones default to personal (the safe side).

## What lore does

- **Stores knowledge entries** — markdown documents with metadata: domain, confidence, origin (evidence / directive / convention / constraint), markers (`[CONTEXT]`, `[NON-NEGOTIABLE]`, `[DEPRECATED]`, …). The format is distill-compatible; existing `~/.claude/distill/` content imports directly.
- **Organises entries into spaces** — one `personal` space plus project and topic spaces. Shared spaces carry a signed member list; only writers and owners can author into them.
- **Syncs across three tiers**:
  1. **Same machine / LAN** — automatic peer discovery via mDNS, mutual TLS (agentmesh transport).
  2. **Your devices anywhere** — works over any existing VPN (Tailscale, WireGuard); to lore it's just IP connectivity.
  3. **lore relay** — a hosted coordination + relay service so devices sync across networks with zero VPN setup. End-to-end encrypted: the relay is a dumb pipe and never sees plaintext knowledge.
- **Exposes MCP tools** — `lore_search`, `lore_get`, `lore_put`, `lore_delete`, `lore_spaces`, `lore_share` — so any harness reads and writes knowledge mid-session.
- **Keeps the distill flow working** — an opt-in mirror directory becomes a live markdown view of your `personal` space.

## Use it as a Go library

```go
import "github.com/BlueHeisenberg/lore"

st, err := lore.Open(lore.Options{Home: "/var/lib/app/lore", NotifyOnWrite: true})
if err != nil {
    return err
}
defer st.Close()

hits, err := st.Search(ctx, "canary deploy", lore.SearchOpts{Spaces: []string{spaceID}})
```

The root package is the compatibility promise: spaces, entries, full-text search, and the
signed, syncing writes behind them. A search hit is a **whole entry**, with the highlighted
snippet alongside it. Everything under `internal/` — sync, signing, membership, the relay,
the schema — is explicitly not promised and gains no exported accessor; there is no way to
reach the database, a space key, or the signing encoding.

The surface, the error contract and the reasoning behind each choice are in
[docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md) §Public Go API. It is v0.x: breaking changes
are allowed on a minor bump until two consumers have exercised it in anger.

**Importing lore puts your work under lore's licence.** See below.

## Identity model

One **account keypair** per user (Ed25519). Each device holds a **device key** signed by the account key. Space membership, entry authorship and sync auth all resolve to account public keys. No usernames, no central registry required for tiers 1–2; the relay adds discovery-by-handle later.

## Status

Built and validated locally end to end: local core, MCP server, sync daemon with LAN discovery and device enrolment, shared spaces with signed member documents, LAN and token invites, encrypted backup/restore, and the relay server. Not yet packaged for installation — no release binaries, no CI.

Known gaps: relay invites by handle are not built (invites are LAN or bearer token); removing a member means rotating the space key by hand; member documents do not carry device certificates.

Design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · knowledge-capture model: [docs/DISTILL.md](docs/DISTILL.md) · relay: [docs/RELAY.md](docs/RELAY.md) · the binding implementation contract: [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md).

## Licence

[Business Source License 1.1](LICENSE). In short: read it, fork it, modify it, and run it for
yourself, your household or your organisation — including in production, including embedded in
your own software. What is not granted is offering lore, or a derivative, to third parties as a
hosted or managed service; the relay server is exactly that and is not granted. On 2030-08-16
this version converts to Apache 2.0.

Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md). Issues are welcome; pull requests are
closed unmerged until a CLA exists, because sole copyright is what keeps the relicensing
promise above possible.
