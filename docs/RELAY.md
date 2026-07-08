# lore — relay design (tier 3)

The relay is an **encrypted mailbox**, not a tunnel. Devices drop small encrypted sync deltas; other devices pick them up when they come online. No live connection relaying, no VPN semantics.

## Why mailbox, not DERP-style tunnel

1. Devices are rarely online simultaneously — store-and-forward syncs on next wake; a live tunnel would sync nothing.
2. Deltas are tiny (markdown entries in KBs; attachments capped at 1 MB) — no streaming needed.
3. Cost: a tunnel scales with held-open connections and relayed bandwidth; a mailbox is stateless HTTPS on a single small VPS.

## Protocol

```
POST /v1/mailbox/{recipient_device_id}     drop a blob (sender authenticated)
GET  /v1/mailbox                           list + fetch my pending blobs
DELETE /v1/mailbox/{blob_id}               ack after successful apply
POST /v1/devices                           enroll device under an account (signed by account key)
GET  /v1/accounts/{handle}                 handle -> account pubkey (invite discovery, opt-in)
```

- **Blob payload**: a batch of entry versions for one space, encrypted client-side with the space_key (XChaCha20-Poly1305), each entry **signed by the author's device key before encryption**. Receivers verify signatures against the space's signed member list (held locally by every client).
- **Addressing**: sender's daemon knows which member devices exist per space (from the signed member list + device registry lookups) and drops one blob per recipient device. Space IDs in relay requests are blinded (HMAC over space_id with space_key) so the relay cannot correlate spaces across users.
- **Auth**: signature challenge on the device key. No passwords, no bearer tokens at rest. Billing identity (Stripe email) is separate from crypto identity.
- **Retention**: blobs deleted on ack or after ~30 days. The mailbox is transport, not backup — full state lives on the devices and re-syncs from any of them.
- **Idempotence/ordering**: version vectors on the receiving side; duplicate or out-of-order blobs are harmless.

## What the relay can and cannot do

| | |
|---|---|
| Relay sees | account/device pubkeys, blob sizes, timing |
| Relay never sees | plaintext entries, space names, member lists, real space IDs |
| Compromised relay can | delay or drop deltas (availability; detectable as version-vector gaps) |
| Compromised relay cannot | read, modify, or inject knowledge (E2E encryption + author signatures) |

Personal-space blobs are only ever addressed to the same account's devices; the space_key never leaves them. LAN sync is direct mTLS and never touches the relay.

## Server implementation (cheapest viable)

- **One Go binary, one VPS** (Hetzner ARM, ~€4/mo): HTTP API + SQLite (device registry, mailbox index, quotas) + blobs on local disk. Let's Encrypt TLS. 20 TB included egress dwarfs KB-scale traffic.
- **Quotas**: per-account mailbox bytes + monthly transfer; free tier enforced here (one shared space, one collaborator). Attachment cap bounds worst-case blob size.
- **Backups**: nightly SQLite snapshot + blob dir to Backblaze B2 (pennies). Losing the relay entirely loses nothing durable — devices re-sync.
- **Scale path (only if needed)**: split stateless relay nodes from the control plane, add regions. The protocol doesn't change because the relay was never trusted and never held per-connection state.
- **Later optimization**: QUIC hole-punching for direct device-to-device sync across NATs, relay as rendezvous only — cuts relay bandwidth to near zero. Ships after the mailbox; the mailbox alone delivers the full UX.

## Client behavior

The `lore serve` daemon syncs opportunistically: direct mTLS to any peer device visible on LAN/VPN; relay mailbox poll (with jitter, ~minutes) plus an optional push hint (long-poll) when the user is on the paid tier. All paths converge on the same version-vector reconciliation - transport is interchangeable.
