# lore — relay design (tier 3)

The relay is the **encrypted home of your lore**: per space, it always holds the complete current state — a compacted snapshot plus an append-only delta log — all encrypted client-side. Log in on any device and everything is there, instantly, regardless of whether any other device is online. It is never a tunnel, and it can never read what it hosts.

**Devices are the source of truth** (only they hold keys and can validate signatures); **the relay is the source of availability**.

## Why hosted-state log, not a tunnel or plain mailbox

1. The main product promise is "log in anywhere, all your lore is there" — that requires the relay to hold full state at all times, not just in-flight deltas. A Tailscale-style live tunnel delivers nothing when the other device is asleep; a pickup-and-delete mailbox delivers nothing to a brand-new device.
2. "Share instantly" falls out of the same mechanism: a capture on device A is appended to the space log immediately; devices B and C long-poll the log and apply within seconds.
3. Payloads are tiny (markdown entries in KBs; attachments capped at 1 MB) — stateless HTTPS on one small box covers thousands of users.

## The model

Per space, the relay stores:

- **Snapshot**: the full space state as of sequence N, encrypted with the space_key.
- **Delta log**: append-only encrypted entries N+1, N+2, … Each delta is a batch of entry versions, encrypted client-side (XChaCha20-Poly1305) and **author-signed before encryption**; receivers verify against the space's signed member list (held locally by every client).
- Devices track their own offset per log. Catch-up = read from your offset; fresh login = snapshot + tail. Shared spaces are the same log read by every member's devices — no per-recipient fan-out.
- **Compaction**: when the log grows past a threshold, a device folds it into a new snapshot (client-side, encrypted) and uploads it; the relay drops the folded prefix. Storage stays bounded.
- **Idempotence/ordering**: version vectors on the receiving side; duplicate or out-of-order application is harmless.

Account-level, the relay also stores the **wrapped account key**: encrypted under Argon2id(passphrase + recovery code). The recovery code is high-entropy, generated at `lore init`, shown once to be saved — it keeps the wrapped key uncrackable offline even if the relay's disk is stolen.

## Protocol

```
POST /v1/spaces/{blinded_id}/log            append a delta (member device, authenticated)
GET  /v1/spaces/{blinded_id}/log?from=N     read deltas from offset (long-poll supported)
GET  /v1/spaces/{blinded_id}/snapshot       fetch current snapshot
PUT  /v1/spaces/{blinded_id}/snapshot?upto=N  upload compacted snapshot (drops folded prefix)
POST /v1/devices                            enroll device under an account (signed by account key)
GET  /v1/account/keybox                     fetch wrapped account key (login)
GET  /v1/accounts/{handle}                  handle -> account pubkey (invite discovery, opt-in)
```

- **Auth**: signature challenge on the device key. No passwords, no bearer tokens at rest. Billing identity (Stripe email) is separate from crypto identity.
- **Blinded space IDs**: HMAC over space_id with the space_key, so the relay cannot correlate spaces across users.

## Login flows

- **Fresh device, nothing else online**: `lore login` → handle + passphrase + recovery code → fetch keybox, unwrap account key locally → enroll device key → pull snapshot + log tail per space → decrypt locally. Everything is there.
- **Another device is handy**: approve-from-existing-device (it signs the new device key and wraps space keys to it) — no recovery code typed.
- **Free/local users**: same durability self-hosted — `lore backup` exports the identical encrypted archive to a file (iCloud/Drive/private repo), `lore restore` imports it. LAN sync needs no relay at all.

## What the relay can and cannot do

| | |
|---|---|
| Relay sees | account/device pubkeys, blob sizes, timing, log offsets |
| Relay never sees | plaintext entries, space names, member lists, real space IDs, usable keys |
| Compromised relay can | delay or drop deltas, serve stale state (availability; detectable as version-vector gaps) |
| Compromised relay cannot | read, modify, or inject knowledge (E2E encryption + author signatures) |

Personal-space logs are only ever readable by the same account's devices; the space_key never leaves them. LAN sync is direct mTLS and never touches the relay; both paths converge on the same version-vector reconciliation.

## Server implementation (cheapest viable)

- **One Go binary, one box**: HTTP API + SQLite (device registry, log index, quotas) + log/snapshot blobs on local disk. TLS via the fronting proxy or Let's Encrypt.
- **Quotas**: per-account stored bytes (~100 MB — years of curated text) + monthly transfer; free tier enforced here (one shared space, one collaborator). Attachment cap bounds worst-case blob size.
- **Backups**: nightly SQLite + blob dir to Backblaze B2 (pennies). Losing the relay loses availability, not truth — devices re-upload state.
- **Scale path (only if needed)**: split stateless API nodes from storage, add regions. The protocol doesn't change because the relay was never trusted.
- **Later optimization**: QUIC hole-punching for direct device-to-device sync across NATs — cuts relay bandwidth, never a launch requirement.

## Hosting plan

The relay is one self-contained binary that doesn't trust its front door (payloads are E2E-encrypted, auth is signature-based), so hosting is interchangeable:

1. **Phase A — zero users, zero cost**: run on the home server behind a **Cloudflare Tunnel** (`cloudflared` makes an outbound connection; no open ports, origin IP never exposed; free tier). Cloudflare terminating TLS is acceptable *because of* the zero-knowledge design — the edge sees the same ciphertext + metadata the relay itself sees.
2. **Phase B — paying users**: move the same binary to a small VPS (Hetzner ARM ~€4/mo): rsync SQLite + blob dir, repoint DNS, keep Cloudflare in front. No code changes.
- Rejected: proxy-only VPS in front of the home server (if you're paying for a VPS, run the relay on it); serverless rearchitecture (Lambda/Firebase/Cloud Run — forks the storage/auth implementation and adds lock-in to save €4/mo). Oracle Always Free is a viable dev-relay alternative to home hosting, with known instance-reclamation risk.
- Implementation note: the relay must not care about client IPs (it doesn't — auth is cryptographic), so proxying changes nothing.

## Client behavior

The `lore serve` daemon writes every capture to local SQLite first, then appends the encrypted delta to the relay log immediately (paid tier) and/or syncs direct mTLS to LAN/VPN peers (free). Reads are always local — the daemon applies incoming deltas in the background, so `lore_search` never waits on the network. Long-poll on the log gives seconds-level propagation between devices; polling with jitter is the fallback.
