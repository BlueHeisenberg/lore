# lore — implementation contract

Binding contract for the build. Design rationale lives in ARCHITECTURE.md / RELAY.md / DISTILL.md; this file pins the concrete choices so parallel work stays coherent. Deviations require updating this file first.

## Toolchain & dependencies

- Go 1.25, module `github.com/BlueHeisenberg/lore`.
- `go.mod` has `replace github.com/BlueHeisenberg/agentmesh => D:\Projects\agentmesh` until Phase 0 is pushed/tagged (tracked in SETUP-ACCOUNTS.md).
- Dependencies (keep this list tight):
  - `modernc.org/sqlite` — pure Go, no cgo (Windows-friendly). WAL mode always.
  - `github.com/mark3labs/mcp-go` — same MCP library as agentmesh.
  - `github.com/BlueHeisenberg/agentmesh/pkg/{discovery,transport,identity}` — Phase 3+.
  - `golang.org/x/crypto` — chacha20poly1305 (XChaCha20), argon2, nacl/box.
  - `github.com/google/uuid`, `github.com/fsnotify/fsnotify`.
  - CLI: stdlib `flag` + subcommand dispatch (agentmesh idiom). No cobra.
- Tests: stdlib `testing`. Integration tests use `LORE_HOME` pointed at t.TempDir().

## Layout

```
cmd/lore/            CLI + daemon + MCP entry (one binary)
cmd/lore-relay/      relay server (separate binary)
internal/keys/       account + device keys, device certs, TLS cert bridge
internal/store/      SQLite store: entries, spaces, members, peers, sync state, FTS5
internal/space/      space ops: create, member lists, space_key wrap/unwrap, routing rules
internal/distill/    ~/.claude/distill/ import / render / watch
internal/mcpserver/  MCP stdio server
internal/daemon/     lore serve: admin API, sync engine, discovery, relay client
internal/syncproto/  version vectors, LWW, sync wire format (shared client/server)
internal/vault/      keybox crypto (Argon2id wrap), backup/restore archive
internal/relay/      relay server implementation (used by cmd/lore-relay)
internal/relayclient/ relay HTTP client (log append/read, snapshot, keybox, long-poll)
skill/lore/SKILL.md  the /lore skill (fresh text)
configs/             .env.example, cloudflared config, systemd unit, Windows task, install notes
```

## Paths & env

- `LORE_HOME` env overrides the data dir; default `~/.lore`.
- Files under LORE_HOME: `account.json`, `device.json`, `lore.db`, `blobs/`, `daemon.json` (port+token, written by the daemon, 0600), `config.json`.
- Distill mirror dir: `~/.claude/distill/` (overridable in config.json `distill_dir`).

## Identity & keys (internal/keys)

Account = two keypairs, generated at `lore init`:
- **Signing**: Ed25519. The account identity = hex of the signing pubkey (`account_id`).
- **Encryption**: X25519 (separate keypair — no Ed25519→X25519 conversion tricks). The encryption pubkey is signed by the account signing key.

`account.json` (0600): `{v:1, sign_priv, sign_pub, enc_priv, enc_pub, enc_pub_sig, created_at}` — hex fields.

Device = Ed25519 keypair + **device certificate** signed by the account signing key:
`device.json`: `{v:1, device_priv, device_pub, name, cert: {device_pub, account_pub, name, created_at, sig}}`.
`device_id` = hex of device pubkey.

TLS: self-signed Ed25519 cert on the **device** key, CN = device_id (agentmesh `pkg/identity` mechanism). Transport verifies the self-signed cert (pkg/transport); lore's app layer then verifies the peer's device cert chains to the expected account.

Recovery code: 10 Crockford-base32 groups of 4 (~50 bits x 4 = 160 bits entropy total), generated at init, shown once, re-type forced.

## Store schema (internal/store, SQLite)

```sql
CREATE TABLE spaces(
  space_id TEXT PRIMARY KEY, kind TEXT CHECK(kind IN ('personal','shared')),
  name TEXT, project_ref TEXT, space_key BLOB, -- plaintext locally; only leaves device wrapped/encrypted
  pinned INTEGER DEFAULT 0, created_at TEXT);
CREATE TABLE member_docs(  -- whole signed member-list document, versioned
  space_id TEXT, version INTEGER, doc TEXT, sig TEXT, signer TEXT,
  PRIMARY KEY(space_id, version));
CREATE TABLE entries(
  entry_id TEXT PRIMARY KEY, space_id TEXT, domain TEXT, title TEXT, body TEXT,
  markers TEXT,            -- JSON array
  confidence TEXT CHECK(confidence IN ('experimental','provisional','validated','hardened')),
  origin TEXT CHECK(origin IN ('evidence','directive','convention','constraint')),
  author_account TEXT, author_device TEXT,
  created_at TEXT, updated_at TEXT,
  version INTEGER,         -- per-entry monotonic
  device_seq INTEGER,      -- per (space, device) monotonic, for version vectors
  origin_device TEXT,      -- device that wrote this version
  signature TEXT,          -- device-key sig over canonical encoding
  tombstone INTEGER DEFAULT 0);
CREATE VIRTUAL TABLE entry_fts USING fts5(title, body, domain, content=entries, content_rowid=rowid);
CREATE TABLE attachments(
  blob_hash TEXT, entry_id TEXT, filename TEXT, source TEXT, size INTEGER,
  PRIMARY KEY(blob_hash, entry_id));  -- blob bytes at LORE_HOME/blobs/<hash>
CREATE TABLE peers(device_id TEXT PRIMARY KEY, account_pub TEXT, name TEXT,
  addr TEXT, static INTEGER DEFAULT 0, last_seen TEXT);
CREATE TABLE sync_state(space_id TEXT, device_id TEXT, max_seq INTEGER,
  PRIMARY KEY(space_id, device_id));
CREATE TABLE relay_state(space_id TEXT PRIMARY KEY, log_offset INTEGER);
CREATE TABLE kv(k TEXT PRIMARY KEY, v TEXT);
```

Canonical entry encoding for signing: JSON with keys sorted, no insignificant whitespace, fields: entry_id, space_id, domain, title, body, markers, confidence, origin, author_account, created_at, updated_at, version, device_seq, origin_device, tombstone, attachment hashes. Signature = Ed25519(device_priv, SHA-256(canonical)).

LWW: an incoming entry version wins iff (updated_at, author_account) > local's, compared lexicographically (RFC3339 timestamps). Tombstones propagate identically.

**Hard rules enforced in store/space layer** (return typed errors):
- personal space: `AddMember` refuses; entries with domain layer `profile/` or `feedback/` refuse copy-out (`ErrUserModel`).
- copy-out is always a *copy* with provenance in the new entry (`source_entry`, `source_space` in a `provenance` JSON column-in-markers? no — add `provenance TEXT` column to entries).
- writes into a shared space require author be a member with writer/owner role (checked on both write and sync-receive).

(add `provenance TEXT` to entries: JSON `{source_entry, source_space, copied_at}` or null.)

## Capture routing & retrieval scoping

- Routing (used by MCP `lore_put` default and the skill): subject=user → personal; subject=codebase → project space for CWD (`project_ref` = SHA-256 of normalized git remote URL, helper in internal/space); ambiguous → personal.
- `lore_search` default scope: personal + CWD's project space (+ pinned topic spaces). `scope` param: `project|linked|all-mine|all`.
- Project links: `links` stored in kv per space (`links:<space_id>` = JSON array of space_ids). Retrieval hint only — results filtered by reader's actual memberships (which locally is: spaces present in DB).

## Distill adapter (internal/distill)

- Import: parse `distill_dir` — every `layer/name.md` becomes one entry (entry per file, v1): domain = `layer/name`, title = first H1 or filename, body = whole file, markers scraped from body, confidence from frontmatter if present else `validated`, origin `evidence`. SPINE.md itself is NOT an entry (it's derived).
- Render: write the personal space back: one file per entry at `layer/name.md`, regenerate SPINE.md (grouped by layer, one line per entry, ≤80 lines, respecting existing "when to read" line if present in entry metadata... v1: title + first-line description from entry).
- Watch: fsnotify on distill_dir, 2s debounce, changed file → new entry version (author = this account/device). Loop-guard: renderer writes are recorded (path+mtime+hash) and skipped by the watcher.
- Round-trip test: import → render to temp dir → byte-identical modulo SPINE regeneration.

## CLI surface (cmd/lore)

```
lore init [--name]                 create account+device+personal space, print recovery code (forced re-type; --yes-i-saved-it for tests)
lore put --domain d --title t [--space s] [--markers ..] [--confidence ..] [--origin ..] [-|--body-file]
lore get <entry-id|domain>         print entry/domain
lore search <query> [--space|--scope|--domain|--marker|--confidence]
lore spaces                        list spaces + members + sync state
lore space create <name>           topic space
lore space invite <space> [@handle]  invite (LAN code v1; handle = relay)
lore join <code>                   accept LAN invite
lore invites                       list/accept pending relay invites
lore project init                  create/join project space for CWD git remote
lore project link <space>
lore share entry <id> --to <space>  copy-out with review (prints content, confirms)
lore serve                         daemon (foreground; --admin-port for tests)
lore mcp                           stdio MCP server
lore enroll / lore approve <code>  new-device flow (LAN)
lore peer add <host:port>          static peer
lore sync [--now]                  poke daemon
lore backup <file> / lore restore <file>
lore login / lore signup           relay account flows
lore passphrase reset
lore status                        identity, daemon, relay, spaces summary
```

Non-interactive flags for every prompt (tests + agents must be able to drive everything headlessly).

## Sync protocol (internal/syncproto, over agentmesh pkg/transport mTLS)

Routes served by the daemon (device-to-device):

```
GET  /lore/v1/hello                      {device_id, account_id, name, version}
POST /lore/v1/spaces                     body: [blinded_space_id...] -> intersection (blind = HMAC-SHA256(space_key, "lore-blind" || space_id))
POST /lore/v1/sync                       body: {blinded_space_id, vv: {device_id: max_seq}}
                                         resp: {vv, entries: [full entries the caller lacks], member_docs: [...]}
POST /lore/v1/entries                    body: {blinded_space_id, entries: [...]} (push direction)
POST /lore/v1/enroll                     enrollment handshake (code-gated)
POST /lore/v1/invite                     LAN invite handshake (code-gated, fingerprint confirm)
```

Receive path (both sync and relay apply): verify entry signature → verify author is member with write role (against latest verified member_doc) → LWW apply → bump sync_state. Personal-space sync additionally requires peer account == own account.

## Space crypto (internal/space + vault)

- space_key: 32 random bytes per space (personal included — uniform relay path).
- Wrap to member: `box.SealAnonymous(space_key, member_enc_pub)` (x/crypto/nacl/box), carried in the member_doc.
- Relay payload encryption: XChaCha20-Poly1305 with space_key, random 24-byte nonce, AAD = blinded_space_id. Delta plaintext = JSON `{entries: [...], member_docs: [...]}` — already author-signed before encryption.
- Keybox (relay + backup): account.json plaintext encrypted with XChaCha20-Poly1305 under key = Argon2id(passphrase || recovery_code, salt, t=3, m=64MiB, p=4). `lore backup` = keybox + all space_keys + full encrypted snapshot in one file.

## Relay (internal/relay, cmd/lore-relay) — per docs/RELAY.md

API exactly as RELAY.md protocol section. Additions pinned here:
- Auth: `POST /v1/challenge {device_pub}` → `{nonce}` (60s TTL); every authed request carries headers `X-Lore-Device`, `X-Lore-Nonce`, `X-Lore-Sig` = Ed25519 over `nonce || method || path || SHA256(body)`. Device must be enrolled (`POST /v1/devices`, self-serve: signed by account key).
- Storage: `relay.db` (SQLite: accounts, devices, spaces (blinded ids only), log index, quotas) + `data/<blinded_id>/log/<seq>` and `snapshot` files.
- Long-poll: `GET .../log?from=N&wait=25s`.
- Quotas: stored bytes per account (default 100 MB), free plan = 1 shared space + its log; enforced on append.
- Entitlements: `accounts.plan` (`free|paid|trial`). Set by: Stripe webhook (`/v1/stripe/webhook`, signature-verified, handles checkout.session.completed, customer.subscription.updated/deleted) OR `lore-relay admin set-plan <account> <plan>` for local testing. Stripe keys via env; unset = webhook 503, admin path only.
- Config env: `LORE_RELAY_ADDR` (:8480), `LORE_RELAY_DATA`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_ID`, `LORE_RELAY_QUOTA_MB`.

## MCP (internal/mcpserver)

Direct-DB mode (WAL makes multi-process safe); after writes, poke the daemon's admin API (`POST 127.0.0.1:<port>/admin/sync?token=`) if daemon.json exists — fire-and-forget. Tools:

| tool | params (JSON schema) |
|---|---|
| lore_search | query (req), scope, space, domain, marker, confidence, limit (default 8) → compact list: id, space, domain, title, snippet, confidence, markers |
| lore_get | id or domain (one req) → full entries |
| lore_put | title, body, domain (req); space (default routed), markers, confidence (default provisional), origin (default evidence) |
| lore_spaces | none → spaces, roles, member counts, sync state |
| lore_share | entry_id, to_space (req) → refuses profile/feedback; returns content preview + requires confirm=true param to execute |

Server instructions ≤ 6 lines. No resources, no prompts, zero per-turn injection.

## Testing bar

- Unit tests per package (store CRUD+FTS+LWW, keys roundtrip, canonical signing, distill roundtrip, space crypto wrap/unwrap, routing rules, blinding).
- Integration (in-repo, `go test ./test/...`): two LORE_HOMEs sync over localhost daemons (static peer, no mDNS dependency in CI); shared-space flow (invite→join→sync→isolation check); relay e2e (start relay on :0, two homes, login-from-scratch restore).
- E2E harness test: register MCP in a scratch Claude Code config, `claude -p` with prompts exercising lore_search/lore_put, assert on DB rows. Windows host runs the binary natively; WSL used for a "second machine" daemon when useful.
