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
- **Recovery / fresh login with no device online**: `lore login` with passphrase + recovery code fetches the wrapped account key and encrypted state from the relay and decrypts locally (paid tier); free tier equivalent is `lore backup`/`lore restore` with a self-hosted encrypted archive. See docs/RELAY.md (Login & recovery).

## Onboarding — there is no signup

- **`lore init`** (free, local): generates the account keypair + this device's key, creates the `personal` space, prints the recovery code once. No email, no username, no server. The account IS the keypair. The recovery code MUST be confirmed by re-typing it before init completes (converts "yeah, next" into actually-saved); the CLI suggests a password manager and offers the recovery kit as a downloadable file.
- **Second device (free)**: `lore enroll` on the new device shows a short code/QR; `lore approve <code>` on an existing device signs the new device key and hands over wrapped space keys.
- **`lore signup`** (relay tier): pick a public handle (`@alice`), set a passphrase; client uploads the public key, handle→pubkey mapping, and the keybox. Email exists only inside Stripe for billing — the relay's crypto layer never sees it.

## Invites — sharing a space with someone

Sharing = obtaining the friend's account pubkey trustworthily; then the owner's device wraps the space_key to it and appends a newly signed member list to the space log. Three first-contact paths:

1. **Same LAN (free)** — pairing-style: `lore space invite <space>` prints a short-lived code; the friend runs `lore join <code>`; daemons find each other over mDNS, exchange pubkeys over mTLS, and **both sides confirm a short fingerprint** (word/emoji string) so a network MITM can't slip in.
2. **Remote via relay** — handles: `lore space invite <space> @bob` → relay resolves handle → invite lands in their pending list (daemon long-poll) → `lore invites` to accept. Optional Signal-style safety-number verification.
3. **Remote without relay** — invite file sent over any channel covers the key exchange, but syncing still needs a transport (LAN, user's own VPN, or relay), so this path converges on "bring your own Tailscale" or the relay free tier.

Invariants: invites are always explicitly accepted (first-contact approval); the owner assigns the role (reader/writer) at invite time; removal rotates the space_key (manual v1).
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
attachments   list of blob refs (see below), optional
```

**Attachment** — durable reference material carried by an entry (a source file, a design doc, a config worth reusing elsewhere). Content-addressed blob (sha256), stored and synced with the entry's space, with provenance:

```
blob_hash     sha256 of content
filename      original name
source        project ref + repo-relative path + commit (when taken from a repo)
size          bytes (soft cap ~1 MB v1; lore is not file sync)
```

Short excerpts belong inline in the entry body (it's markdown); attachments are for whole files. Attaching into a shared project space publishes the file to that space's members, so it is always an explicit user act — the agent may suggest, never attach unasked — and the CLI warns when content looks like a secret (.env, key material, tokens). For ephemeral session-to-session file transfer, agentmesh `mesh_share`/`mesh_fetch` remains the tool; lore attachments are for reference material that belongs with the knowledge.

**Space** — the sharing unit. Two kinds:

```
space_id      uuid
kind          personal | shared
name          "personal", "agentmesh", "godot-tips", ...
project_ref   optional (shared spaces): stable project identifier -
              normalized git remote URL hash, or explicit id. With it, the
              space is a PROJECT space (CWD scoping + capture routing);
              without it, a TOPIC space (pure knowledge sharing).
members       list of (account_pubkey, role: owner|writer|reader)
space_key     symmetric key for content encryption (shared spaces only),
              distributed wrapped to each member's account pubkey
```

- **`personal` (feature 1)** — created at init, exactly one, members: you. From your user, for your user: profile, feedback, craft, ops, cross-project learnings. Syncs across your own devices (LAN free, relay paid). The binary refuses to add members to it.
  - The user-model layers `profile/` and `feedback/` are **never shareable** — the binary refuses to copy or move them out, period.
  - Other personal entries (craft, ops, general learnings) can be **copied out** to a shared space: explicit user act, content shown for review before publishing, provenance kept, original stays personal. Never a move, never automatic.
- **`shared` (feature 2)** — invite-based knowledge sharing; LAN sync free, cross-network via relay (paid, except the free tier: one shared space with one collaborator). Two flavors:
  - **Project space** (`project_ref` set) — one per repo, created/joined via `lore project init`. Holds knowledge about that codebase: architecture decisions, constraints, gotchas, corrected conclusions.
  - **Topic space** (no `project_ref`) — knowledge around a subject rather than a repo: "godot-tips", "ble-security". Created via `lore space create <name>`. Same membership/sync/encryption rules; not tied to any working directory, searched when the user or agent opts in (`scope` param or per-space pin).
- **Routing rule (capture)**: when a session distills learnings, each entry is classified — about the user → `personal`; about the codebase → the CWD's project space; ambiguous → `personal` (safe side). See docs/DISTILL.md.
- **Scoping rule (retrieval)**: `lore_search` defaults to `personal` + the current project's space (detected from CWD); other project spaces are opt-in per query.
- **Cross-project sharing** — three explicit mechanisms, no implicit propagation (generic learnings already travel via personal lore):
  - *Entry copy*: `lore share entry --to <project>` copies an entry into another project space with provenance (source entry id, author). A copy, not a move; each space's copy evolves independently. The agent may suggest a copy during capture, never perform it unasked.
  - *Project links*: `lore project link <other>` makes searches in this project also query the linked one. A link is a retrieval hint, NEVER an access grant — it is evaluated per reader against their own memberships, so a collaborator without membership in the linked space sees nothing from it.
  - *Scope widening*: `lore_search` takes `scope: project|linked|all-mine` for one-off cross-project queries.
  - Non-goal (v1): parent/org/workspace spaces with inheritance — links + copies cover the need without group-membership semantics.
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
| `lore_get` | fetch entry (or whole domain file) by id/domain; `lore_get_attachment` for blobs |
| `lore_put` | create or update an entry (defaults to `personal`); may attach files with explicit user approval |
| `lore_spaces` | list spaces, members, sync status |
| `lore_share` | copy an entry (with attachments) to a project space — explicit user act |

Context discipline (lesson from agentmesh): the MCP server injects **nothing** per turn. No hooks by default. Knowledge enters context only when the agent calls a tool, or via the existing distill startup convention (reading SPINE.md), which stays user-controlled in CLAUDE.md.

## Relay service (tier 3, last)

The **encrypted home of your lore**: per space, the relay always holds full current state — compacted snapshot + append-only delta log, all encrypted client-side and author-signed. Log in on any device and everything is there; captures propagate device-to-device in seconds via long-poll. Devices are the source of truth (they hold the keys); the relay is the source of availability — it sees only pubkeys, sizes, and timing, never plaintext, space names, or real space IDs. Full design: docs/RELAY.md.

- Billing: subscription, one month free trial. Relay refuses sync for expired accounts; tiers 1–2 keep working forever (the free/local product is complete on its own).
- Server stack: one Go binary on one small VPS — HTTP API + SQLite + blobs on disk. Quotas enforce the free tier. QUIC hole-punching (relay as rendezvous only) is a later optimization, not a launch requirement.

## Non-goals (v1)

- No CRDT merge of entry bodies (LWW per entry).
- No web UI. CLI + MCP only.
- No knowledge-graph/embeddings search (FTS5 is enough to start; embeddings can come later behind the same `lore_search`).
- No cross-account discovery without the relay (members exchange pubkeys out of band).
