# ADR 0016: Signed sync manifests, per-sender sequence numbers, standard HPKE key wrap

Status: Proposed (implemented on `feat/pre-real-data-hardening`; Security and Data Systems review requested)

Closes ADR 0013 deferred items **N2** (signed bundle sequence numbers) and **N3** (key wrap construction). Also signs
the manifest vector used for `sync_peer_state`.

## Context
* `vaultsync/0.1` packages were unsigned. The manifest `vector` fed `sync_peer_state` (incremental export
  watermarks), so an edited package could move a watermark.
* `vaultkeys/0.1` bundles were signed, but carried no sequence number. A receiver could not tell an old bundle
  from a new one, or notice two different bundles from the same sender claiming the same place in its history.
* The 0.1 DEK wrap was an HPKE-like construction built by hand from X25519, HKDF and AES-GCM. A standard
  construction with published test vectors is easier to review.

## Decision
### 1. Signed manifests (`vaultsync/0.2`)
The manifest has exactly the keys `format, source_device, created_at, seq, prev_package, vector, since, event_count,
body_sha256, signature`. The signature is Ed25519 by the active user key registered on the receiving vault, over
`"lattice-sync-manifest/v2\n" || canon(manifest without signature)`. Unknown or missing keys, an unknown key id, or a
bad signature refuse the whole package. A receiver without the user key registered refuses every package (fail
closed). Packages exported by the receiving device itself are refused.

`key.*` events are no longer exported: receivers never apply them, and each device registers the user key itself.

### 2. Per-sender sequence numbers (both formats)
Each device keeps one counter and the hash of its last artefact per stream (`vaultsync`, `vaultkeys`; table
`sync_seq_send`). Every package/bundle carries `seq` and `prev_package` / `prev_bundle` (the SHA-256 of the
previous artefact's signed message), inside the signature. The counter advances only after the file is written.

The receiver stores every accepted `(stream, sender, seq, hash, prev)` in the append-only `sync_seq_seen` and decides
(seqstate.py):

| Case | Result |
|---|---|
| same seq, same hash | duplicate (idempotent, nothing changes) |
| same seq, different hash | **fork**, refused |
| seq lower than the highest accepted | **rollback**, refused |
| seq = highest + 1 | `prev` must equal the highest accepted hash, else **fork**, refused |
| seq > highest + 1 (gap) | accepted; if `prev` names an accepted artefact other than the highest, **fork**, refused |
| first artefact from a sender | accepted (trust on first use; the signature still binds it) |

Gaps are expected and allowed: the counter is per sender, not per recipient, so artefacts sent to other devices, or
never delivered, leave gaps. Refusals are recorded in `sync_seq_refused` (ids, hashes, reasons; no content) and, for
key bundles, also in `sync_key_quarantine`. `--dry-run` imports check but record nothing.

**Restored sender.** A device restored from an old backup re-uses old numbers and its peers refuse its packages.
Recovery is a human decision: `vault sync-seq-advance --stream vaultsync|vaultkeys --to N` (TTY only) moves the counter
forward (never back) and clears the head, which the receiver treats as a gap. `vault sync-seq` shows the counters and
refusals.

### 3. Peer watermarks use the signed vector
`sync_peer_state` is updated from the signed `vector`, capped per origin replica at the highest sequence the receiver
actually holds, so a watermark never claims events that did not arrive.

### 4. Key wrap: RFC 9180 HPKE (`vaultkeys/0.2`)
Verified, not assumed: `cryptography.hazmat.primitives.hpke` exists in `cryptography` 49.x (the minimum pinned
version, CI job `min-cryptography`) and 50.x. Suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, base mode
(`Suite.encrypt/decrypt`, output `enc || ciphertext`, 80 bytes for a 32-byte DEK).

The library API has no AAD argument, so the binding moves into HPKE `info`:
`"lattice-key-wrap-hpke/v2\n" || SHA-256(canon({v, bundle_id, key_id, subject, event_ids, sender_device,
recipient_device, recipient_ka_fp, signer_key_id}))`. The hash keeps `info` short and fixed length. Info is bound into
the HPKE key schedule, so a wrap moved to another bundle, key, subject, event set, device or signer does not open.
Bundle entries are `{key_id, subject, event_ids, hpke_b64}`.

Test vectors (`test_hpke_vectors.py`): an independent reference implementation of HPKE base mode is checked against
RFC 9180 Appendix A.1, then cross-checked against the library in both directions, plus a fixed known-answer vector for
the exact suite and info layout. Runs on 49.x and 50.x.

### 5. Compatibility and migration
* `vaultsync/0.1` packages are refused with a message to re-export from the sender on this version.
* `vaultkeys/0.1` bundles are refused (and quarantined as legacy). Migration: update the sender, then
  `vault sync-keys export` again; the sender still holds every DEK. There is no opt-in to import 0.1: the format is a
  prototype that was never meant for real data.
* Signing domains changed (`lattice-key-bundle-sig/v2`), so 0.1 signatures cannot be reused for 0.2.

## Consequences
* Replayed, rolled-back or forked packages and bundles are refused and recorded, never applied.
* The sender device id is still not cryptographically authenticated (every device holds the same user key; ADR 0013
  N4). Sequence numbers detect inconsistent histories, not a holder of the user key acting as another device.
* First contact is trust on first use.
* Receivers need the user key registered before any import.

## Not in scope
Per-device signing keys, receiver acknowledgements, an import path for 0.1 artefacts.
