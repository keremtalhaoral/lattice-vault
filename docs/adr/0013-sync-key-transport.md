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
   it is built from long-stable primitives (minimum `cryptography>=49`); moving to RFC 9180 HPKE is possible later.
5. **Everything signed.** The whole bundle (all metadata, the sender's certificate, every ephemeral key and ciphertext)
   is signed by the active user key over `lattice-key-bundle-sig/v1\n || canon(bundle without signature)`. The
   importer verifies the signature before reading any other field, then requires: recipient device and KA fingerprint
   are its own, the sender is paired, not revoked, not itself, and its certificate verifies for that device id.
6. **Import.** For each entry: exact field set; key not shredded here (no `subject.shredded` for it in the log and no
   destroyed row); every listed event exists here with that `enc_key_id` and subject; the wrap authenticates; the DEK
   opens the first listed event. The DEK is then **re-wrapped under the recipient's KEK** (existing `dek|<key_id>` AAD).
   A key id already present is a duplicate (idempotent). A subject that already has a different key is refused.
   keys.db rows are written in one transaction, then vault.db bookkeeping in one transaction; projections are rebuilt.
   **KEK creation (review N7).** `_keystore` uses `vault.keystore` (which never creates a KEK when keys.db is missing
   but encrypted events exist), with exactly one documented exception: no keys.db AND every encrypted event in the log
   came in through sync, so no local DEK can be orphaned. Then a first KEK is created and an audit row
   `keystore_created_for_key_import` is written. In every other case the error is raised. `reconcile_shreds` warns on
   stderr when a synced shred is in the log but there is no keystore.
7. **Fail closed / quarantine.** A bundle that fails any bundle-level check is refused as a whole; an entry that fails
   is skipped. Both are recorded in `sync_key_quarantine` (bundle hash, sender, key id, reason; never key material).
   Re-importing the same bundle later (e.g. after the events have been synced) re-evaluates it.
8. **Revocation / unpaired.** `export` refuses a recipient that is not paired, is revoked (`vault sync-keys
   revoke-peer`, append-only table) or has no valid certificate. `import` refuses bundles that *name* such a sender.
   The sender device id is **not cryptographically authenticated**: the bundle and the sender certificate are signed
   by the user key, which every device holds, so any holder of the user key can claim any paired device id. A DEK is
   still only accepted if it opens the listed events and its key id is not already present. Device-level
   authentication needs per-device signing keys (vaultsync/0.2). `revoke-peer` is therefore **not** a protection
   against a compromised user key (e.g. a lost device): rotate the user key (`vault keys rotate`); signatures by the
   revoked key are then refused.
9. **Shredding.** Export skips keys that are destroyed, `pending_destroy` or named by a `subject.shredded` event.
   For a user-signed `subject.shredded` from another device that is in the log (applied by `sync-import` or released
   from quarantine):
   - **reads are refused at once**: `vault.shred_applies` treats the key as shredded for that subject even while a DEK
     copy still exists (payloads read as `redacted`);
   - the DEK is **not destroyed at once** (review M1): `reconcile_shreds` moves it to `pending_destroy` with the local
     grace period (`VAULT_SHRED_GRACE_DAYS`, default 7), and destroys it once the grace period is over, writing the same
     `redactions` row as a local shred. `vault shred-cancel` is refused for a key with a shred in the log;
   - before acting, the shred's `key_id` must belong to the event's subject in keys.db, and the event must re-verify
     as `remote-signed` (signing.classify) at that moment (review N1); otherwise it is recorded once in
     `sync_key_quarantine` and ignored;
   - a shred whose origin device is revoked for key transport is ignored (recorded once); its key stays readable.
   **Durability (review B1).** keys.db is a separate database, so the key update cannot share the vault.db transaction
   that applied the event. `reconcile_shreds` is idempotent and runs after every `sync-import` and quarantine
   release, **on every vault open** (`vault.connect`), and in `vault doctor`. Until it has run, reads are already
   refused. `doctor` reports an ERROR for a live `active` DEK with an applied shred, or for a `pending_destroy` DEK
   past its grace period, then reconciles, so **`vault doctor` is not read-only** in this case (use `vault verify` for a
   read-only check). Automatic reconcile audits as `system:sync-reconcile`, not as the user. A crash-injection test
   covers the window. Destroying the key (keys.db) and writing the `redactions` row (vault.db) cannot be one
   transaction (review L5); a missing row after a crash is written by the next reconcile (tested).
   `revoke-peer` and `shred-cancel` rebuild projections (review L4). An old bundle can never bring a
   shredded key back. Pending shreds and cancellations now propagate as well (ADR 0014).
10. **CLI.** `vault sync-keys init|cert|add-peer|revoke-peer|export|import|quarantine`; all but `quarantine` are
    human-only (TTY). Output contains ids and fingerprints only.

## Review items deferred (Data Systems review of #14)
- **N2: signed bundle sequence numbers.** Closed by ADR 0016 (signed per-sender sequence numbers for packages and
  bundles; replay, rollback and fork refused). Security sign-off pending.
- **N3: key wrap construction.** Closed by ADR 0016: vaultkeys/0.2 uses standard RFC 9180 HPKE from `cryptography`
  (with test vectors); vaultkeys/0.1 is refused. Security sign-off pending.
- **N4: signing key.** Bundles and certificates are signed by the user key, not by a device key. `sender_device` is
  only as authentic as the user key; see item 8. Device keys come with vaultsync/0.2.
- **N5: key-transport revocation is separate from pairing.** `revoke-peer` stops key transport and synced shreds
  from that device. The device stays paired for event sync (there is no unpair command yet).
- **N6: no release path for the key quarantine.** Re-import the bundle to re-evaluate it; each refusal adds a row and
  rows are never resolved. After a crash between the keys.db and vault.db steps of an import, the `sync_key_imports`
  bookkeeping row is missing; the key itself is present and a re-import reports it as a duplicate.
- **N7:** addressed in item 6 (the explicit, audited first-KEK case).
- **N9: over-hiding (safe direction).** Any applied `subject.shredded` in the log hides that subject's data for reads,
  even if it is later found invalid by reconcile (subject mismatch, failed re-verification) or its origin is revoked
  after the fact; reads return after `revoke-peer` (then `shred-cancel`). Never the leaking direction.
- **N10: opening needs write access.** `vault.connect` may write (shred reconcile on open: keys.db update, audit row
  as `system:sync-reconcile`); a read-only vault file or keys.db makes the reconcile fail with a warning (reads stay
  refused) until it can write.
- **N8: bundle metadata is in cleartext.** Subject ids, key ids and event ids are not encrypted, the same as in
  `.vaultsync` packages (docs/sync.md, SECURITY.md).

## Consequences / limits (deferred)
- Same-owner model only: every device must have the same user key registered (as for signed events today). Device
  Ed25519 keys, a pairing ceremony and key-registry sync remain `vaultsync/0.2` work.
- No forward secrecy against later compromise of a recipient's KA private key (static recipient key); the KA key is
  as strong as that device's KEK. KA key rotation = new `init` on a new device id (not implemented).
- `revoke-peer` is local and not synced; revocation is not retroactive (a bundle already imported stays imported).
- Bundle replay to the same recipient is harmless (idempotent); no sequence numbers yet.
- Shred propagation relies on the signed `subject.shredded` event reaching the receiver; full crypto-shredding across
  devices (pending shreds, cancellation, audit of remote destruction) is roadmap step 2.
