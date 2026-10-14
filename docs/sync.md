# Sync & multi-device prototype (`.vaultsync`, format `vaultsync/0.1`)

Status: **file-based prototype** (packages are files you move by hand; no server, no network, no signing). Implements part of ADR 0008. Single owner, 2+ devices, no server,
no network code. Device A exports a file, the user moves it (USB, file sync, …), device B imports it.

> **Do not use multi-device sync with real data.** Packages are unsigned, there is no key sync, and redaction/shredding
> does not propagate to other devices. Until signing exists, `user:*` and approval events are quarantined (see Trust).

## Package format
One file. Line 1 is the **manifest** (canonical JSON). Lines 2..n are the **body** (JSONL, one event per line, sorted by `(hlc, id)`).

```json
{"format":"vaultsync/0.1","source_device":"dev-…","created_at":"…Z",
 "vector":{"<origin_device>/<replica_id>": max_replica_seq, …},   // everything the source holds
 "since":{…},                                                      // watermark used for --since-peer
 "event_count":N,"body_sha256":"<hex sha256 of body bytes>","signature":null}
```
Each body line is the event **exactly as it was on its origin device**: every `EVENT_HASH_FIELDS` column, `prev_hash`,
`hash`, `payload_ct` (base64 ciphertext or null), `parents` (`[[parent_id, rel], …]` from `event_parents`), `targets`,
plus `origin_device`. Forwarded events (A→B→C) are re-exported from the stored origin row, so C can still verify A's hash.

## Integrity
1. `sha256(body) == manifest.body_sha256`, and `event_count` matches. If either fails, the whole package is rejected.
2. For every event, recompute `event_hash(prev_hash, row)` (the same function as the local chain) and `content_hash`. Any mismatch rejects the package.
3. Events signed with the user key carry `sig` in the body line, because the origin hash binds the signature
   (`vault.event_hash`). The receiver uses it to recompute the hash **and verifies it** (see Trust → Quarantine).
   Accepted events are stored without a local `event_sigs` row, so doctor classifies them `remote-unsigned`
   (docs/adr/0011-signing-keys.md); the origin row with `sig` stays in `sync_imported` and is re-exported as is.
4. **Not built:** Ed25519 package signing (`signature` is always null). SHA-256 detects corruption. It does **not** authenticate the sender:
   anyone who can write the file can recompute both hashes. Until signing exists, "paired device" is a label the
   user asserts, not something the vault proves (see the threat model / draft v0.4 K-6).

## Merge semantics
* **Union by event id**. An event whose id is already present is counted as `duplicate` and skipped. Re-importing a package is a no-op (tested).
* **All-or-nothing:** all checks (hashes, skew, causal gaps) run before any write. The writes then go into one SQLite transaction (rollback on any error),
  followed by `rebuild()` and one audit row. `--dry-run` runs every check and returns the report. It creates nothing, not even the sync tables.
* **Causal gaps:** a `supersedes` parent that is neither local nor in the package rejects the package ("import the earlier package first").
* **HLC:** local `next_hlc()` already reads `max(hlc)` over the whole log. Once remote events land, the next local event
  gets `max(local, remote)+1`, which is the HLC receive rule. **Skew bound:** if any event's HLC is more than `VAULT_SYNC_MAX_SKEW_MS` (default 5 min)
  ahead of the receiver's wall clock, the **whole package is rejected** (no flag-and-accept mode yet). Without this check, one bad clock could drag
  every device's HLC into the future. Open (DDIA #5): the counter is 16 bits (4 hex) and has no overflow guard. The remote
  `replica_id` suffix is opaque and is not validated.
* **Hash chain (DDIA #6), choice made: chain-of-imports.** We keep the single linear local chain. Imported events get a *local* `prev_hash`/`hash`
  (so `verify_chains()` and the existing triggers are unchanged). The origin hash plus the full origin row are kept in `sync_imported`.
  Trade-off: the event's `hash` column differs per device, so identity across devices is `id` plus `origin_hash`.
  Per-device chains were rejected for now because they need an `events` schema change. Also, an origin device's chain cannot be
  re-verified end-to-end from a package, since its chain interleaves events it imported. Each event's hash is verified on its own.
* `replica_id='local'` is rewritten to the origin device id on import, so `(replica_id, replica_seq)` stays unique.
* **Watermarks:** after importing from S, `sync_peer_state(peer=S, origin, max_seq)` = S's vector. `sync-export --since-peer S` sends only
  events above that. This is the knowledge "S already has these", learned from S's own package. Exports are not acknowledged, so a lost
  package means doing a full export (always safe because import is idempotent).

## Conflicts (no LWW)
These go through the existing DAG. Concurrent `preference.set` events on two devices produce two heads, so `conflict=1`, as before. Concurrent
`event.corrected` on the same parent cannot happen locally (double-supersede is refused) but can happen after a merge.
`rebuild()` now detects such a fork and sets `conflict=1` on the root's preference/decision row. The value shown is still
whichever correction replays last, but the conflict flag keeps it out of the context pack until the user resolves it.

## Trust
**Quarantine (until package signing exists).** Held events go to `sync_quarantine` (origin row + reason) and are
**not** written to `events`: never projected, never verified, not re-exported. Re-import counts them as duplicates.
List with `vault sync-quarantine`. Rules, in order:
* Human-only types (`vault.SIGNED_TYPES`: approve/reject/revert/batch-approve/redact/shred/conflict.resolved, `key.*`,
  `attestation.recorded`) are applied **only** if the event's `sig` verifies (`signing._verify` over
  `signing.sig_message` of the origin row) against a **user** key that is registered on this vault
  (`signing.registered_keys`), not revoked at the event's HLC, the actor is `user:*`, and the origin device is paired.
  Otherwise the reason is one of: `unsigned human-only event`, `bad signature`, `unknown signing key <key_id> (no
  key.registered for it on this device)`, `revoked key`, `human-only event from a non-user actor`,
  `valid user signature but origin device is not paired`, `signature not verifiable here (cryptography not installed)`.
* `key.*` events are always held (`key registry sync needs vaultsync/0.2`): the receiver's registry is never changed by a package.
  To accept signed approvals, register the same user key on the receiver first (`vault keys init-user` with the same `VAULT_USER_KEY`).
* `user:*` content events (preference/decision/…) are not user-signed in #10, so they are always held (`unsigned user:* event`).
* Children of held events and payloads that fail schema validation are held too.
Agent/import events are applied and stay unverified/proposed.
The rules below describe the pre-quarantine paired-device behaviour, kept behind a test-only flag.

* An event keeps its original actor/trust only if its `origin_device` is this device or a **paired** device (`vault sync-pair`, human-only,
  stored in the existing `replicas` table). Agent events stay unverified/proposed regardless.
* `user:*` events from an **unknown** device are quarantined: actor becomes `import:sync-<device>`, trust becomes `unverified`, status becomes `proposed`
  (they need `vault approve`). Human-only types (approve/reject/revert/redact/shred/…) from an unknown device are skipped and reported.
* Content on the redaction blocklist is skipped. A package never resurrects redacted data.

## Integration with schemas, projections, backup
* **Upcasters / schema validation:** each incoming plaintext payload is upcast to the current version (`schemas.upcast`) and
  validated like `vault.append` does. Invalid payloads are quarantined (`reason = "schema invalid: …"`). Stored bytes and
  `schema_version` stay as on the origin (upcasting is read-time only). Newer-schema events are stored and kept out of
  projections by `rebuild()` (`unknown_version`). Encrypted payloads are not validated here (the receiver may lack the key).
* **Projections:** after a merge, `rebuild()` runs in full and refreshes the projection checkpoint. Imported events can sort
  before local ones, which `apply_incremental` refuses by design. Later local appends use the incremental path again.
* **Backup:** the `sync_*` tables live in vault.db, so `vault backup` includes them. keys.db is never included, as before.

## Encryption, keys, shredding
Encrypted fields travel as ciphertext (`payload_ct` plus `{"$enc": key_id}`) and are stored byte-identical on the receiver.
**Key sync is out of scope (planned).** As a result: (a) on a device without the subject key, such events project as `undecryptable` (unreadable,
never plaintext). (b) Crypto-shredding is **per device**: shredding on A destroys A's key only, and B's copy is protected only because B never had
the key. Once key sync exists, a `subject.shredded` event must propagate and destroy the key on every device.
Packages on disk are **not** encrypted (only the sensitive fields are). Treat `.vaultsync` files like the vault itself.

## CLI
```
vault device-id                                 # create/show stable device id (dev-<16 hex>)
vault sync-pair <device-id> --name laptop       # human-only: trust this device as the owner's
vault sync-export --out a.vaultsync [--since-peer <device-id>]
vault sync-import a.vaultsync [--dry-run]       # prints a JSON report (new/duplicate/quarantined/skipped)
vault sync-quarantine                           # JSON list of held events (id, origin device, type, actor, reason)
```
New tables (all `CREATE TABLE IF NOT EXISTS`, created lazily by sync): `sync_device`, `sync_imported`, `sync_quarantine`, `sync_packages`.
Reuses the reserved `replicas` and `sync_peer_state`. No existing table or trigger is changed.

## Not built (planned)
Ed25519 package/event signing and device keys. Package encryption (age/AEAD). Key sync and cross-device shredding.
Propagation of redaction to other devices (redact-copy on each device). A flag-instead-of-reject mode for skew. HLC counter overflow handling.
`conflict.resolved` UX for correction forks. Sync-folder automation and compression. Watermarks acknowledged by the receiver.
Partial import (it is all-or-nothing by design). `projection_hash` includes local `seq` (`decided_seq`), so it is **not** comparable across devices.
