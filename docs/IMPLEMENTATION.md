# lore — implementation contract

Binding contract for the build. Design rationale lives in ARCHITECTURE.md / RELAY.md / DISTILL.md; this file pins the concrete choices so parallel work stays coherent. Deviations require updating this file first.

## Toolchain & dependencies

- Go 1.25, module `github.com/BlueHeisenberg/lore`.
- `github.com/BlueHeisenberg/agentmesh` is pinned at a published tag (v0.7.0). **No `replace` directive may exist in this go.mod**: a `replace` in a dependency's go.mod is ignored by the consuming module, so any local-path replace here breaks every downstream importer at resolution time.
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
- Mirror dir: opt-in via config.json `mirror_dir` (suggested: `~/.claude/lore/`); the mirror renders the personal space as SPINE.md + domain files. An aura-distill directory is an import source (`lore mirror import --dir`), never a default target.

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

### Canonical signing encoding — FROZEN

JSON with keys sorted, no insignificant whitespace, exactly these sixteen fields
and no others: `attachments`, `author_account`, `body`, `confidence`, `created_at`,
`device_seq`, `domain`, `entry_id`, `markers`, `origin`, `origin_device`, `space_id`,
`title`, `tombstone`, `updated_at`, `version`. `markers` and `attachments` are `[]`
when empty, never `null`. Signature = Ed25519(device_priv, SHA-256(canonical)).

**This encoding may not change.** Not the field set, not the field names, not the
order, not the null handling. It was already a within-store contract; since lore
became an importable library it is a **cross-version** one, and that is a stronger
obligation than it has ever carried:

- One LORE_HOME is now shared by up to three independently-versioned builds — an
  embedded library inside a consumer, the operator's `lore serve`, and the `lore`
  CLI. They sign entries for each other.
- The receive path verifies every incoming entry's signature (§Sync protocol). A
  build that computes a different digest rejects **everything** the other build
  wrote, in both directions.
- The failure is silent. Nothing errors at the user; entries simply stop arriving
  between two of the user's own devices, and the store on each looks healthy.

Adding a field to a signed entry therefore requires an explicit, entry-carried
signature version — a new column, a new verification branch, and a migration —
never an edit to `canonicalEntry`. `TestCanonicalEncodingIsFrozen` in
`internal/store` pins the exact bytes so that an edit fails the build rather than
the fleet. If that test fails, the change is wrong; do not update the golden.

The same rule and the same reasoning apply to the member-doc canonical encoding
(`internal/space`), which authorizes writes.

### Schema versioning

`kv.schema_version` is the database's schema version; the build's is
`store.schemaVersion`. `migrate` compares them three ways: lower migrates, equal
returns, and **higher refuses with `ErrSchemaTooNew`** (`lore.ErrSchemaTooNew` at
the public boundary). Refusing is the point: it used to return early for any
`v >= schemaVersion`, so an older build opened a newer database and read columns
that may have moved.

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

- Import: parse the import dir (config `mirror_dir` or `--dir`) — every `layer/name.md` becomes one entry (entry per file, v1): domain = `layer/name`, title = first H1 or filename, body = whole file, markers scraped from body, confidence from frontmatter if present else `validated`, origin `evidence`. SPINE.md itself is NOT an entry (it's derived).
- Render: write the personal space back: one file per entry at `layer/name.md`, regenerate SPINE.md (grouped by layer, one line per entry, ≤80 lines, respecting existing "when to read" line if present in entry metadata... v1: title + first-line description from entry).
- Watch: fsnotify on mirror_dir, 2s debounce, changed file → new entry version (author = this account/device). Loop-guard: renderer writes are recorded (path+mtime+hash) and skipped by the watcher.
- Round-trip test: import → render to temp dir → byte-identical modulo SPINE regeneration.

## CLI surface (cmd/lore)

```
lore init [--name]                 create account+device+personal space (lore.Init), print recovery code (re-type to confirm AFTER creation; --yes-i-saved-it for tests)
lore put --domain d --title t [--space s] [--markers ..] [--confidence ..] [--origin ..] [-|--body-file]
lore get <entry-id|domain>         print entry/domain
lore search <query> [--space|--scope|--domain|--marker|--confidence]
lore spaces                        list spaces + members + sync state
lore space create <name>           topic space (lore.CreateSpace)
lore space invite <space> [@handle]  invite (LAN code v1; handle = relay)
lore join <code>                   accept LAN invite
lore invites                       list/accept pending relay invites
lore project init                  create/join project space for CWD git remote
lore project link <space>
lore share entry <id> --to <space>  copy-out with review (prints content, confirms)
lore delete entry <id> --space <s>  tombstone one entry (prints content, confirms; --yes for automation; --space required: ids are global)
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
POST /lore/v1/entries                    body: {blinded_space_id, entries: [...], member_docs: [...]} (push direction; docs travel with entries so a push-before-pull peer can verify membership — docs are always applied first)
POST /lore/v1/enroll                     enrollment handshake (code-gated)
POST /lore/v1/invite                     LAN invite handshake (code-gated, fingerprint confirm)
```

Receive path (both sync and relay apply): verify entry signature → verify author is member with write role (against latest verified member_doc) → LWW apply → bump sync_state. Personal-space sync additionally requires peer account == own account.

### Peer lifecycle — discovered peers expire, static peers do not

The two kinds of `peers` row fail differently and must be treated differently.

- **Discovered** (`static=0`): mDNS asserted this address and will assert it again when the machine is back. `last_seen` is refreshed on **every sighting in the mDNS registry**, not only when the address changed — being advertised is being seen, whether or not the sync that followed succeeded. A row not seen for `Options.PeerTTL` (default **1h**) is deleted. Forgetting costs nothing: rediscovery re-verifies the device cert chain from scratch.
- **Static** (`static=1`): a person typed it and nothing will rediscover it. Never expired.

Why it matters: on a container host a pod's address (and, on an ephemeral home, its device id) changes on every recreation, so without expiry a rolling update leaves the replaced pod in the table forever. Two consequences, both fixed here — the table grew without bound, and `/admin/status` reported every dead address as a sync error on every round until a real failure was invisible in the noise.

**A failed round is only a reported error when the peer is static or currently advertised.** A discovered peer that is no longer advertising is a dead address, not a fault; it is still attempted (mDNS may be off, or it may be reachable anyway) and it is still logged, but it does not reach `sync_errors`. `PeerTTL` is a knob because the right value is a property of the deployment: an hour is generous for a pod, and a household of machines that are usually off may want longer.

### Loopback admin API (`internal/daemon/admin.go`)

`daemon.json` (0600) publishes `{port, token, sync_port, device_id, pid}`. Two routes, both token-gated on 127.0.0.1:

```
POST /admin/sync      run one round now, block until it finishes
GET  /admin/status    {device_id, account_id, name, sync_port, last_sync,
                       sync_errors[], peers[], spaces[]}
                      peers[]:  the peers row (device_id, account_pub, name, addr,
                                static, last_seen) + shared_spaces[]
                      spaces[]: {space_id, kind, name, entries, members}
```

- `spaces[].members` is the size of the latest **verified** member list, or `0` when the space has none — the personal space always (membership there is between devices of one account, gated on the account key), a shared space until its first member doc arrives. `0` means "no member list", never "no members", and it is never a local guess. (`lore_spaces` over MCP reports `1` in the same situation instead, because its reader is a model being told how many accounts it can see, not a machine distinguishing absent from empty.)
- `peers[].shared_spaces` are the **local** space ids the last blinded intersection with that peer returned, sorted. Empty means "not established": no round has succeeded with that peer since the daemon started (there is no history across restarts), or the two genuinely share nothing. `last_seen` says how old the answer is. Together with `members`, this is what lets a consumer say "3 instances, 2 of them in this space" rather than only "reaches 3 instances".

**Disclosure.** To a process that reached loopback *and* read the token out of `daemon.json` — which is a process that can already open `lore.db` and therefore holds every space key, every entry and the device private key. Nothing on this endpoint is a new capability; it is a convenience over facts that caller could compute itself.

It does not weaken the blinded intersection. `POST /lore/v1/spaces` only ever answers an offer with a **subset of it**, so a device never learns of a space a peer holds and it does not — `shared_spaces` is structurally incapable of naming one. Blinded ids are translated back to local ids before publishing precisely because blinding is a *wire* encoding (keep the id off the network) and a loopback caller is not the network; publishing the blinded form instead would disclose exactly as much while being unusable to a consumer, since the public API deliberately exposes no space key to unblind with. No space key, wrapped key, member wrapping or entry body appears in the response.

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

### Invite links (internal/invite + relay routes)

Async bearer-token invites; the LAN handshake stays as the no-relay path (`lore space invite --lan`).

- **Token**: 4 words from an embedded BIP39 English list (2048 words) + 2-digit number, e.g. `maple-rocket-sunset-cactus-73` (~50.6 bits). Parsing is case/separator-insensitive, accepts unique 4-letter prefixes. From S = canonical string: `addr = hex(HMAC-SHA256(S,"lore-invite-addr"))[:32]`, XChaCha20-Poly1305 key = `HMAC-SHA256(S,"lore-invite-key")`, claim MAC = `HMAC-SHA256(S,"lore-invite-claim"||account_pub)`. Payload blobs use AAD=addr; claim blobs AAD=addr+"claim".
- **Trust model**: the token is a bearer capability — anyone holding it can join until expiry/exhaustion, so it must travel over a channel the owner trusts. Caps keep the blast radius small: expiry clamped to **6h** (default 6h), uses clamped to **10** (default **single-use**), ≤20 open invites per account. The relay hosts only ciphertext at an unguessable address: it never sees the secret, the space id/name, or keys. The owner's daemon verifies each claim (AEAD + token MAC + enc-key binding) before admitting.
- **Routes**: `POST /v1/invites` (authed; {addr, blob b64, expires_in_s, max_uses}, clamped) · `GET /v1/invites/{addr}` (open, 10/min/IP — possessing addr implies possessing the secret; 404 when expired/exhausted) · `POST /v1/invites/{addr}/claims` (authed; uses counts claims) · `GET /v1/invites/claims` (authed; pending claims on own invites) · `POST /v1/invites/{addr}/processed` + `DELETE /v1/invites/{addr}` (authed, owner). Expired rows swept alongside challenge traffic.
- **Flow**: `lore space invite <space>` (default when relay_url is set) mints the token, parks the encrypted `{space_id, space_key, kind/name/project_ref, role, owner keys}` payload, and records the secret locally (`lore space invites` lists/revokes). `lore join <token>` fetches+decrypts, stores the space, enrolls with the relay, parks its claim, and polls ~30s; if the owner's daemon is offline it exits pending and the daemons complete membership later. The owner's relay loop verifies claims, evolves the member doc (same admit path as the LAN invite), grants relay access, pushes a doc-only delta, and deletes used single-use invites.

## Public Go API (package `lore`, module root)

lore is an importable Go module under BSL 1.1. The root package is the **only**
compatibility promise; everything under `internal/` changes without notice, and
nothing there gains an exported accessor.

**Shape: a facade, not a move.** The root package holds its own `Entry`, `Space`
and `Member` structs and converts from `internal/store`'s. That costs a
conversion layer and a second struct to keep in step; it buys the one thing
discipline cannot: it is a compile error to publish `Space.SpaceKey` (a raw
32-byte symmetric key), `Entry.Signature`, `AuthorDevice`, `DeviceSeq` or
`OriginDevice`. Re-exporting the internal structs would have made every one of
those a promise.

**Surface** (26 methods, 5 package functions):

```
Open(Options) (*Store, error) · Init(home, deviceName string) (Identity, error)
DefaultHome() · NormalizeMarkers([]string) · Terms(string)

(*Store) Close/AccountID/DeviceID/Home
entries  PutEntry · GetEntry · GetEntryIn · DeleteEntry · ListEntries · CountEntries · GetDomain · CopyEntry
search   Search
spaces   CreateSpace · CreateSpaceWithID · Spaces · GetSpace · SpaceByName · PersonalSpace
         Members · CanWrite · Links
grants   PublicIdentity · GrantMembership(ctx, spaceID, PublicIdentity, Role) ([]byte, error)
         AcceptMembership(ctx, grant []byte) (Space, error)
sync     Serve(ctx, ServeOptions) — blocks until ctx is cancelled; reports readiness
         and its ephemeral ports through ServeOptions.Ready(ServeInfo)
```

**Decisions worth their line:**

- **`context.Context` first on every method that touches the DB.** It is checked
  before the call and bounds the busy retry; it does not interrupt a statement
  in flight. Taken even though the benefit today is small, because adding it
  after v1 is breaking and removing it never is.
- **`Options.Home`, never `LORE_HOME`.** The env read lives only in
  `DefaultHome`, which the CLI calls and an embedder does not — one process can
  then hold one store per member pod.
- **`Options.NotifyOnWrite`** turns on the post-write side effects `lore mcp`
  has always had: poke the daemon, re-render the mirror on a personal write.
  Off by default and opt-in rather than automatic, because the failure mode of
  forgetting it is silent — writes sit locally until the daemon's next poll.
- **Search returns whole entries** with `Snippet` alongside. It always did; the
  MCP text rendering was what discarded the body. Consumers must not model
  search results as excerpts.
- **Retry on `SQLITE_BUSY` lives in lore**, bounded by `busyRetries` and the
  caller's context, and exhausts to `ErrBusy`. Contention is by design — `lore
  serve`, `internal/syncproto`'s second connection and any CLI invocation share
  `lore.db` — and busy_timeout does not cover a deferred transaction's
  read→write upgrade.
- **`Init` creates a home; it does not open one.** Only the caller knows whether
  it wants `NotifyOnWrite`, so `Open` stays a separate call and `Init` returns no
  `*Store` — and therefore no question of who closes it on the error path. Like
  `Open` it takes no context: it is construction.
- **`Init` requires an empty home — no `account.json`, no `device.json` AND no
  `lore.db`** — and is `ErrAlreadyInitialised` otherwise. The database counts.
  The weaker check (keys only) lets a fresh account adopt an existing database:
  it inherits entries signed by keys it does not have and a personal space it
  did not create, and the run looks like a successful first boot. The two rules
  are load-bearing on each other — `Init` is all-or-nothing and removes what it
  wrote on any failure, which is only safe because every one of those files is
  one it created in a home it verified was empty.
- **`Identity.RecoveryCode` is returned, not required.** The code is a KDF factor
  for relay signup and backup, stored nowhere, so `Init` is the only place it
  can ever be produced — but at that moment it protects nothing, and discarding
  it costs a later `lore recovery new`. A consumer that does not want a secret
  (a member pod) ignores the field; one that does (the CLI) shows it. What
  changed: the CLI's re-type confirmation now happens after the home exists, so
  a mistyped confirmation costs a `lore recovery new` rather than the account.
- **`CreateSpace` returns the space, id included, and does the whole creation** —
  key, space row and signed member-list v1 naming the caller sole owner, in one
  transaction (`store.CreateSharedSpace`). A space row without v1 is one nobody
  can prove they own and nobody can be invited into; a caller that has to diff
  `lore spaces` to learn the new id is the failure this export exists to end.
  It is the one write not retried on `SQLITE_BUSY`: it is two statements, and
  replay is only safe for an operation that committed nothing.
- **The space argument survives in the signature, not in the absence.** This
  package used to refuse space creation on the grounds that a space is a
  person's decision — a name and a sharing posture chosen out of band. An
  embedder creating a member's own space in a wizard is that person; what
  shelling out bought was a subprocess and prose parsing, not deliberation. So
  `CreateSpace` takes a name and a kind and guesses neither, there is no
  get-or-create, a duplicate name is `ErrSpaceExists` rather than a silent
  second space, and the personal space belongs to `Init` because there is one.
- **`CreateSpaceWithID` creates a shared space at an id the caller already
  holds, idempotently.** It is for the embedder whose id is decided before the
  store exists: a setup wizard writes the id into a configuration file, and the
  process that will actually hold the space — a container on a volume nothing
  outside it can reach — boots later. Without it that process mints a second id
  and a human pastes it back over the first. A second call with the same id
  returns the existing space and writes nothing, which is what lets a pod call
  it unconditionally on every boot; `name` is not compared (a display name is
  never identity) and nothing is renamed, while the *kind* is compared and a
  mismatch is `ErrSpaceExists`, because a personal space rejects every foreign
  author and is not a substitute for the shared one that was asked for. The id
  must be canonical UUID text and is refused, never coerced — a primary key
  with two spellings is two rows.
- **`GrantMembership` / `AcceptMembership` admit one store into another
  store's space, without a person at either end.** The package used to expose
  no membership mutation at all, and the reason was right for the case it was
  written about: a space arrives in somebody's store because two people agreed
  to share, and `lore space invite` / `lore join` — a code read aloud, a
  fingerprint confirmed on both screens — is that agreement. What changed is
  the same premise `CreateSpace`'s did, who the person is. An embedder that
  provisioned BOTH stores, holds both homes and was told by an administrator to
  add a member is carrying out a decision already taken, not taking one; making
  it drive a code and a y/N prompt through two containers bought a subprocess,
  not deliberation.

  The two calls only compose in one direction, and that is the whole safety
  argument. `GrantMembership` runs on the owner's own home, needs its account
  signing key, and is `ErrNotOwner` unless that account owns the space in its
  latest verified member list. `AcceptMembership` runs on the grantee's own
  home, needs its account encryption key, and is `ErrNotGranted` unless the
  blob opens with it AND the verified chain inside names it. Neither reaches a
  second store or opens a socket. There is no pair of calls that joins an
  arbitrary space to an arbitrary account: to grant you must hold the owner's
  home, to accept you must hold the grantee's, and a caller holding both could
  read both stores anyway. `PublicIdentity` is the third piece and carries only
  what a sync hello already puts on the wire — account id, encryption key, and
  the signature binding them.

  Both are idempotent, which is what makes them usable from a supervisor that
  cannot know whether this is a first boot: re-granting an account already in
  the list re-seals the current chain and writes no new version, and re-applying
  a grant rewrites the same rows. `Owner` is not grantable and the personal
  space is not grantable, on any path. Removal is not offered and cannot be:
  every store that holds a space holds its key, and a key cannot be un-learned
  — retiring a member's access means retiring the space.

- **Accepting an id from outside is safe because an id is not what peers match
  on.** They intersect `BlindSpaceID(space_key, space_id)`, and the key is
  generated locally and never leaves the home, so two unrelated stores holding
  one id compute different blinded ids and recognise nothing of each other
  (`test/sync`'s `TestOneSpaceIDInTwoUnrelatedStoresExchangesNothing`, which
  proves it by then handing over the key and watching the intersection light
  up). The corollary is a rule for callers: do not create a space at an id you
  also expect to be invited into, because join, enrolment and restore all write
  a space row verbatim and would overwrite the local key.
- **`Serve` runs the sync daemon in the caller's process, on the caller's
  store.** Nothing else carries an entry from one home to another: a write is
  local, `NotifyOnWrite` only pokes a daemon that already exists, and until
  this export the only daemon was the `lore` binary. An embedder that had to
  install and supervise that binary to make two of its own homes converge was
  not embedding lore. It blocks until `ctx` is cancelled and returns `nil`
  when it shut down cleanly, so a supervisor can treat any non-nil return as a
  real failure to serve; per-peer and per-round failures are not fatal and
  reach `ServeOptions.Logf` and `/admin/status` instead. `ServeOptions.Ready`
  exists because the ports are ephemeral and a blocking call has nowhere else
  to report them.
- **One daemon, two constructors, one owner question.** `internal/daemon` is
  the only sync daemon in the module: `lore serve` builds it with
  `daemon.New`, which opens its own store and closes it again, and `Serve`
  builds it with `daemon.NewWithStore`, which runs on the store the caller
  opened and leaves it open. That is the entire seam. It also keeps the
  connection count where it was — the daemon's own `syncproto` connection plus
  one store — rather than adding a third to a home that already has an
  embedder's `Store` on it. The CLI was deliberately **not** rewritten onto
  `Serve`: it is the older and more used surface, and routing it through
  `lore.Open` would have changed the message `lore serve` prints on a home
  with no account. `cmd/lore/serve_test.go` guards the other direction — the
  CLI must not grow a daemon of its own — and `test/serve` syncs the two
  constructors against each other so neither can drift.
- **Two daemons on one home are allowed and untidy.** A consumer cannot stop a
  person running `lore serve` against the home it is already serving, so
  `Serve` documents the outcome rather than pretending to prevent it (it could
  not tell a live daemon from a stale `daemon.json` without racing). It is not
  a data hazard — one WAL, one busy retry, the same signed LWW entries — but
  the two bind different ports while advertising one device id, so a peer's
  recorded address flaps; the second to start owns `daemon.json`, so write
  pokes go only to it; and the first to stop removes `daemon.json`, after
  which pokes reach nobody and the survivor syncs on its interval alone.
  `TestTwoDaemonsOnOneHome` is that paragraph, executable.
- **Absent on purpose**: device enrolment, invites and join, backup/restore,
  membership mutation (`Evolve`), pinning, `project_ref` (resolving one
  reads `os.Getwd` and a git config), key material, the schema, `*sql.DB`,
  signing, capture routing and scope resolution. Sync is now present as
  `Serve`; what stays absent is everything that gives two homes a space to
  sync in the first place, which is a person's decision at a CLI.
- **Errors**: `ErrNotFound`, `ErrSpaceNotFound`, `ErrWrongSpace`, `ErrNotWriter`,
  `ErrUserModel`, `ErrInvalidArgument`, `ErrReadOnly`, `ErrClosed`,
  `ErrNoAccount`, `ErrAlreadyInitialised`, `ErrSpaceExists`, `ErrSchemaTooNew`,
  `ErrBusy`. Every returned error matches one of these or is the caller's own
  context error.
- **Concurrency**: every method is safe from any number of goroutines — and that
  is all that is promised. Not that reads run in parallel (they do not:
  `SetMaxOpenConns(1)`). One `Store` per home per process.

**`internal/mcpserver` is written against this package and nothing else**, and
`cmd/lore`'s `init` and `space create` are now wrappers over `lore.Init` and
`lore.CreateSpace`. That is the standing design test: if the CLI cannot be
written on the public surface, no other consumer can either, and the failure
shows up in this repo where it is cheap. It bit twice and both times the API
gave way — `Identity` carries `DeviceName` and `PersonalSpaceID` because the
CLI prints them, and the recovery-code confirmation moved after creation
because `Init` mints the code as part of creating the account.

The rest of `cmd/lore` stays on `internal/` — `join`, `enroll`, `backup`,
`serve`, `project init` (it needs `project_ref`) and `space pin` need keys,
member docs, the git remote or the daemon. `serve` stays there by choice
rather than by need, and the choice is above: its behaviour is a released
product's and is worth more than the symmetry. `project init` reaches the same
creation through `store.CreateSharedSpace`, which is the single implementation
the public API, the CLI and the integration tests all call.

## MCP (internal/mcpserver)

Built on the public `lore` package (`lore.Open` with `NotifyOnWrite: true`), so
after writes it pokes the daemon's admin API
(`POST 127.0.0.1:<port>/admin/sync?token=`) if daemon.json exists — fire-and-forget
— and re-renders the mirror on a personal-space write. Tools:

| tool | params (JSON schema) |
|---|---|
| lore_search | query (req), scope, space, domain, marker, confidence, limit (default 8) → compact list: id, space, domain, title, snippet, confidence, markers |
| lore_get | id or domain (one req) → full entries |
| lore_put | title, body, domain (req); space (default routed), markers, confidence (default provisional), origin (default evidence) |
| lore_delete | id, space (both req) → signed tombstone; refuses when the entry is not in that space (ids are global); already-deleted = no-op, not an error; no confirm param (the space match is the guard) |
| lore_spaces | none → spaces with kind, entry count and member count (the real count once a space has a verified member list; 1 — this account — before it has one) |
| lore_share | entry_id, to_space (req) → refuses profile/feedback; returns content preview + requires confirm=true param to execute |

Server instructions ≤ 6 lines. No resources, no prompts, zero per-turn injection.

## Testing bar

- Unit tests per package (store CRUD+FTS+LWW, keys roundtrip, canonical signing, distill roundtrip, space crypto wrap/unwrap, routing rules, blinding), plus the public API against a real store in `t.TempDir()`.
- **No test doubles for the store.** Tests use a real store in a temp dir, never a fake: this project has repeatedly been bitten by doubles that could not fail the way the real dependency fails. A new assertion is not done until it has been shown to fail with the code reverted.
- Nothing may touch the real `~/.lore` or the real mirror directory. Every test points `LORE_HOME`/`Options.Home` at `t.TempDir()`.
- Integration (in-repo, `go test ./test/...`): two LORE_HOMEs sync over localhost daemons (static peer, no mDNS dependency in CI); shared-space flow (invite→join→sync→isolation check); relay e2e (start relay on :0, two homes, login-from-scratch restore); peer lifecycle (a stale discovered row is forgotten and is not reported, a fresh one and a static one survive, the static one's failure still reports) and `/admin/status` membership + observed shared spaces.
- E2E harness test: register MCP in a scratch Claude Code config, `claude -p` with prompts exercising lore_search/lore_put, assert on DB rows. Windows host runs the binary natively; WSL used for a "second machine" daemon when useful.
