# lore

**Shared knowledge for AI coding sessions — yours, your devices', your team's.**

lore is a knowledge store that AI coding assistants (Claude Code, Cursor, Codex CLI, Antigravity) read and write through MCP. Knowledge distilled in one session is available in every other session — on the same machine, on your other devices, and (if you choose) to teammates you share it with.

It is the sibling project of [agentmesh](https://github.com/BlueHeisenberg/agentmesh): agentmesh is the *communication* layer between live sessions (ephemeral, anonymous, message-passing); lore is the *knowledge* layer (persistent, identity-based, synced). lore reuses agentmesh's discovery and transport code for LAN sync.

## The problem

Every AI session starts from zero. Session-retrospective systems fix this per-machine: sessions distill learnings into markdown files (a SPINE index + domain files) that future sessions read on startup. But that knowledge is trapped on one machine, in one user's home directory. Switch computers and it's gone. Want a teammate's agent to know what yours learned — no path for that at all.

## Two kinds of lore

**1. Personal lore — from you, for you.** Everything distill captures about *you*: your profile, preferences, craft standards, operational habits, cross-project learnings. It syncs between your harness sessions (same machine), your devices on the local network, and — with the paid relay — your devices anywhere. Nobody else can be added to it. Your user model (profile/feedback) can never leave it; other personal entries can be *copied out* to a shared space, but only as an explicit, reviewed act.

**2. Shared lore — invite-based.** Two flavors of the same thing: **project spaces** bound to a repo (architecture decisions, constraints, gotchas, corrected conclusions about that codebase) and **topic spaces** bound to nothing ("godot-tips", "ble-security" — pure knowledge you share with someone). Sharing on the local network is free; sharing across networks goes through the paid relay — except **one shared space with one collaborator is free**, so trying lore with a friend costs nothing.

When a session distills learnings, each one is routed: insights about the user go to personal lore, insights about the codebase go to that project's lore. Ambiguous ones default to personal (the safe side).

## What lore does

- **Stores knowledge entries** — markdown documents with metadata: domain, confidence, origin (evidence / directive / convention / constraint), markers (`[CONTEXT]`, `[NON-NEGOTIABLE]`, `[DEPRECATED]`, …). The format is distill-compatible; existing `~/.claude/distill/` content imports directly.
- **Organizes entries into spaces** — one `personal` space (feature 1) plus one space per project (feature 2). Project spaces have a member list; only members can read or contribute.
- **Syncs across three tiers**:
  1. **Same machine / LAN** — automatic peer discovery via mDNS, mutual TLS (agentmesh transport).
  2. **Your devices anywhere** — works over any existing VPN (Tailscale, WireGuard); to lore it's just IP connectivity.
  3. **lore relay (paid, planned)** — a hosted coordination + relay service so devices sync across networks with zero VPN setup. End-to-end encrypted: the relay is a dumb pipe and never sees plaintext knowledge. One month free trial; one shared space with one collaborator stays free forever.
- **Exposes MCP tools** — `lore_search`, `lore_get`, `lore_put`, `lore_spaces` — so any harness reads/writes knowledge mid-session.
- **Keeps the distill flow working** — `~/.claude/distill/` becomes a live view of your `personal` space. `/distill` keeps writing files; lore syncs them.

## Identity model

One **account keypair** per user (Ed25519). Each device holds a **device key** signed by the account key. Space membership, entry authorship, and sync auth all resolve to account public keys. No usernames, no central registry required for tiers 1–2; the relay service adds discovery-by-handle later.

## Status

Design phase. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design, [docs/DISTILL.md](docs/DISTILL.md) for the knowledge-capture model and its aura-distill heritage, and [docs/ROADMAP.md](docs/ROADMAP.md) for the build plan.

## License

TBD (private while in design).
