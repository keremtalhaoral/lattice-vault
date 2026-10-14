# ADR 0013: Sync key transport (DEKs between paired devices)

Status: Proposed (prototype on `feat/sync-key-transport`; Security and Data Systems review requested)

## Context
Encrypted fields travel in `vaultsync/0.1` packages as ciphertext only (AES-GCM, AAD `<event_id>|<key_id>`), so a
paired device can store but not read them (`undecryptable`). Roadmap step 1 is to move the per-subject data keys
(DEKs) to paired devices without ever moving the KEK, without plaintext DEKs on disk or on the wire, and without
weakening crypto-shredding or the quarantine model (ADR 0008, 0011, 0012).

## Decision
1. **Separate, versioned artifact.** DEKs travel in a `vaultkeys/0.1` bundle, a file next to the event package.
   `vaultsync/0.1` packages are unchanged and stay readable; an old peer simply never sees key material.
2. **Device key-agreement (KA) key.** Each device has an X25519 key (`vault sync-keys init`). The private key is
   stored in `keys.db` wrapped by that device's own KEK (AES-256-GCM, AAD `ka|<device_id>`); it is never exported,
   backed up separately or printed.
3. **Certificate.** `{v, device_id, ka_alg:"x25519", ka_pub_b64, user_key_id, created_at}` signed with Ed25519 by the
   active user key over `lattice-device-ka-cert/v1\n || canon(cert)`. Exact field set required. A receiver accepts a
   certificate (`vault sync-keys add-peer`) only if the signer is the **currently active** user key registered on
   its own vault and the device is paired and not revoked for key transport. A user-key rotation therefore
   invalidates all certificates; they must be re-issued (conservative; no certificate chain across rotations).
4. **Wrap (HPKE-style base mode, built from `cryptography` primitives).** Per DEK: fresh ephemeral X25519 key;
   `k = HKDF-SHA256(ikm = X25519(eph, recipient), salt = eph_pub || recipient_pub, info = "lattice-sync-key-transport/v1
   x25519-hkdf-sha256-aes256gcm")`; AES-256-GCM with a random 96-bit nonce (single use per derived key).
   An all-zero shared secret is refused. AAD = `lattice-key-wrap-aad/v1\n || canon({v, bundle_id, key_id, subject,
   event_ids, sender_device, recipient_device, recipient_ka_fp, signer_key_id})`. Because DEKs are per subject, the
   "event id" binding is the exact list of encrypted events the key is sent for. This is not RFC 9180 wire format;
   the library's HPKE API is not available at our minimum `cryptography>=42`.
5. **Everything signed.** The whole bundle (all metadata, the sender's certificate, every ephemeral key and ciphertext)
   is signed by the active user key over `lattice-key-bundle-sig/v1\n || canon(bundle without signature)`. The
   importer verifies the signature before reading any other field, then requires: recipient device and KA fingerprint
   are its own, the sender is paired, not revoked, not itself, and its certificate verifies for that device id.
6. **Import.** For each entry: exact field set; key not shredded here (no `subject.shredded` for it in the log and no
   destroyed row); every listed event exists here with that `enc_key_id` and subject; the wrap authenticates; the DEK
   opens the first listed event. The DEK is then **re-wrapped under the recipient's KEK** (existing `dek|<key_id>` AAD).
   A key id already present is a duplicate (idempotent). A subject that already has a different key is refused.
   keys.db rows are written in one transaction, then vault.db bookkeeping in one transaction; projections are rebuilt.
   A receiver that so far only holds imported ciphertext may create its first KEK on import (no local DEK can be orphaned).
7. **Fail closed / quarantine.** A bundle that fails any bundle-level check is refused as a whole; an entry that fails
   is skipped. Both are recorded in `sync_key_quarantine` (bundle hash, sender, key id, reason; never key material).
   Re-importing the same bundle later (e.g. after the events have been synced) re-evaluates it.
8. **Revocation / unpaired.** `export` refuses a recipient that is not paired, is revoked (`vault sync-keys
   revoke-peer`, append-only table) or has no valid certificate. `import` refuses bundles from such senders.
9. **Shredding.** Export skips keys that are destroyed, `pending_destroy` or named by a `subject.shredded` event.
   When a user-signed `subject.shredded` from a paired device is applied by `sync-import` (or released from quarantine),
   the receiver destroys its copy of that DEK immediately (no second grace period; the origin already had one), and an
   old bundle can never bring it back. A pending (not finalized) shred on the origin does not propagate.
10. **CLI.** `vault sync-keys init|cert|add-peer|revoke-peer|export|import|quarantine`; all but `quarantine` are
    human-only (TTY). Output contains ids and fingerprints only.

## Consequences / limits (deferred)
- Same-owner model only: every device must have the same user key registered (as for signed events today). Device
  Ed25519 keys, a pairing ceremony and key-registry sync remain `vaultsync/0.2` work.
- No forward secrecy against later compromise of a recipient's KA private key (static recipient key); the KA key is
  as strong as that device's KEK. KA key rotation = new `init` on a new device id (not implemented).
- `revoke-peer` is local and not synced; revocation is not retroactive (a bundle already imported stays imported).
- Bundle replay to the same recipient is harmless (idempotent); no sequence numbers yet.
- Shred propagation relies on the signed `subject.shredded` event reaching the receiver; full crypto-shredding across
  devices (pending shreds, cancellation, audit of remote destruction) is roadmap step 2.
