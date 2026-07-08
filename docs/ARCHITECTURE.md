# lore — architecture

Design document. Everything here is pre-implementation and revisable.

## Design principles

1. **Persistent where agentmesh is ephemeral.** agentmesh generates a fresh identity per session and stores nothing. lore is the opposite by design: durable identity, durable storage, ACLs. This is why lore is a separate binary and repo — mixing the two trust models would poison both.
2. **Local-first.** Every read and write hits the local store; sync is background reconciliation. No tier requires a server. The relay is a convenience, never a dependency.
3. **The relay never sees plaintext.** Shared-space content is encrypted client-side per space. A compromised relay leaks metadata (who syncs with whom, when, sizes) but no knowledge.
4. **distill-compatible.** The on-disk knowledge format is the aura-distill format (SPINE.md index + domain markdown files + markers/confidence/origin). lore adds sync and sharing around it, not a new format. NOTE: check aura-distill's license before importing any of its *code*; the *format* is just markdown conventions.

## Identity

- **Account key**: Ed25519 keypair, generated once per user (`lore init`). Private key at `~/.lore/account.key` (0600). The public key IS the user identity.
- **Device key**: Ed25519 keypair per device, signed by the account key (a device certificate). Sync sessions authenticate with the device cert chain: peer proves "device D belonging to account A".
- **Enrolling a new device**: `lore enroll` on the new device prints a short-lived code/QR; `lore approve <code>` on an existing device signs the new device key. (v1 fallback: copy the account key manually.)
- **mTLS reuse**: transport-level auth extends agentmesh's cert-pinning model — TLS cert pinned to the *device* key, device key chains to the *account* key.

## Data model

**Entry** — the unit of knowledge:

```
entry_id      uuid (stable across edits)
space_id      which space it belongs to (exactly one)
domain        distill domain, e.g. "deployment", "godot-patterns"
title         short name
body          markdown (distill conventions: markers, principles)
markers       [CONTEXT] [UPDATED] [PROVISIONAL] [IMPORTANT] [NON-NEGOTIABLE]
              [DIRECTIVE] [CORRECTED] [DEPRECATED]
confidence    experimental | provisional | validated | hardened
origin        evidence | directive | convention | constraint
author        account pubkey
created_at / updated_at
version       monotonic int per entry
signature     author's device key over the canonical encoding
tombstone     bool (deletes propagate as tombstones)
```

**Space** — the sharing unit:

```
space_id      uuid
name          "personal", "team-backend", ...
members       list of (account_pubkey, role: owner|writer|reader)
space_key     symmetric key for content encryption (shared spaces only),
              distributed wrapped to each member's account pubkey
```

- Every user gets a `personal` space at init (members: just them; no content encryption needed until relay tier).
- **Layer → space rule (enforced)**: entries in the distill layers `profile/` and `feedback/` (the user model) are personal-space-only — the binary refuses to move or copy them to a shared space. `projects/`, `craft/`, `ops/` are shareable. See docs/DISTILL.md.
- Membership changes are signed by an owner. v1 keeps a simple signed member-list document; no fancy group-key rotation initially (rotate space_key manually on member removal).

**Store**: SQLite at `~/.lore/lore.db` (entries, spaces, peers, sync state). The distill directory is a *materialized view*: lore renders the `personal` space (and any space the user opts in) to `~/.claude/distill/` files, and watches that directory for writes made by `/distill`, importing changes back as entry versions. Conflict rule: last-writer-wins per entry by (updated_at, author pubkey) — good enough for v1; entries are append-mostly.

## Sync protocol

Append-only signed log per space, reconciled pairwise:

1. Devices exchange per-space version vectors (`account:device -> max seq seen`).
2. Each side streams entries the other is missing.
3. Receiver verifies signatures (entry author must be a space member with write role) and applies LWW.

Transport: mTLS 1.3 (same stack as agentmesh `internal/transport`, to be extracted to a public package). Discovery per tier:

| Tier | Discovery | Transport path |
|---|---|---|
| Same machine / LAN | mDNS `_lore._tcp` (agentmesh discovery pkg) | direct mTLS |
| Own devices over VPN | static peer list (`lore peer add 100.x.y.z`) or mDNS if the VPN carries multicast | direct mTLS |
| Relay (paid) | relay coordination server (device registry per account) | mTLS through relay tunnel; content additionally encrypted with space_key |

The lore daemon (`lore serve`) runs one process per *machine* (unlike agentmesh's per-session process) — launchd/systemd/startup task. Harness sessions talk to it via the MCP server, which is a thin client (`lore mcp`) connecting to the local daemon over a unix socket / named pipe.

## MCP surface

| Tool | Purpose |
|---|---|
| `lore_search` | full-text + domain/marker/confidence filtered search across readable spaces |
| `lore_get` | fetch entry (or whole domain file) by id/domain |
| `lore_put` | create or update an entry (defaults to `personal`) |
| `lore_spaces` | list spaces, members, sync status |
| `lore_share` | move/copy an entry to a shared space |

Context discipline (lesson from agentmesh): the MCP server injects **nothing** per turn. No hooks by default. Knowledge enters context only when the agent calls a tool, or via the existing distill startup convention (reading SPINE.md), which stays user-controlled in CLAUDE.md.

## Relay service (tier 3, last)

- Coordination server: account registration (handle -> account pubkey), device registry, space membership hints, NAT traversal (DERP-style relaying; direct connection upgrade when possible).
- Billing: subscription, one month free trial. Relay refuses sync for expired accounts; tiers 1–2 keep working forever (the free/local product is complete on its own).
- Server stack: Go, same transport code, stateless relay nodes + small control-plane DB.

## Non-goals (v1)

- No CRDT merge of entry bodies (LWW per entry).
- No web UI. CLI + MCP only.
- No knowledge-graph/embeddings search (FTS5 is enough to start; embeddings can come later behind the same `lore_search`).
- No cross-account discovery without the relay (members exchange pubkeys out of band).
