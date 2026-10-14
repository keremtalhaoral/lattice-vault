# ADR 0011: User signing key, signed human-only events, external anchor; device keys reserved for packages
- **Status:** Accepted (user key); Proposed (device keys / package signing)
- **Implementation:** User key, event signatures, anchor and open-time sampling implemented (`signing.py`,
  `vault.py`). Device keys, package signatures and key sync are **not implemented**.
- **Aligned with:** Data Systems draft `docs/design/multidevice-signing-keysync-draft.md` (branch
  `feat/sync-prototype`, not on main) and the signature contract agreed on 2026-10-14.

## Context
Human-only events (approve/reject/revert/redact/shred/import approval/conflict resolution) were protected only by
a TTY check and a SQLite trigger on `actor LIKE 'user:%'`. Any same-user process could write them. The hash chain
detected edits but not a full rewrite, and it could not detect truncation. Sync (ADR 0008, `docs/sync.md`) will later
need per-device keys to authenticate packages.

## Decision
1. **Two key roles, one namespace.** `key_id = "<role>/ed25519/<first 16 hex of sha256(raw pubkey)>"`, with role
   `user` or `device`.
   * **User key** (implemented): one Ed25519 key per human owner. It signs every human-only event and the external
     anchor. It is stored outside the DB in a PKCS8 PEM file (`VAULT_USER_KEY`, default
     `<config dir>/user_ed25519.key`, optional passphrase `VAULT_USER_KEY_PASSPHRASE`). The file is refused if it is a
     symlink or not a regular file, if its owner is not the euid, or if `mode & 0o077 != 0`. An OS-keychain backend
     is planned (`VAULT_USER_KEY_BACKEND=keychain` is a stub that errors). Agent-facing processes (MCP server,
     `vault propose`) never load it.
   * **Device keys** (reserved, not implemented): sign `.vaultsync` packages (`lattice-pkg-sig/v1`, reserved) and
     identify the sender. They never sign human-only events. A device key is registered with
     `key.registered{role:'device', device_id, certified_by:<user key_id>}`.
2. **Key registry = events.** `key.registered{key_id, alg, pubkey_b64, role, device_id?, certified_by}`. The first
   user key is self-signed (TOFU). `vault keys init-user` shows its fingerprint on the TTY for confirmation, and the
   anchor pins it. `key.rotated{old_key_id, new_key_id, new_key_sig}`: the event is signed by the old key and
   `new_key_sig` proves possession of the new key, so both keys sign (verification is implemented, there is no CLI yet).
   `key.revoked{key_id, effective_hlc, reason, compromised}`: signatures made before `effective_hlc` stay valid, and
   signatures at or after it are rejected. All of these are human-only (`actor LIKE 'user:%'`, trigger
   `events_signed_types_human`).
3. **Signature contract** (agreed with Data Systems):
   `"lattice-event-sig/v1\n" + canon({id, type, subject, payload_hash, actor, parents (sorted), hlc, origin_device, key_id})`.
   `payload_hash = sha256(payload_ct)` if ciphertext is present, otherwise `sha256(canon(payload))`. `canon` sorts
   keys, uses separators `(',',':')` and `ensure_ascii=False`, and rejects floats. `prev_hash`, `seq`, `trust` and
   status are deliberately **excluded**, because they differ per device after sync. `parents` is the sorted set of
   `event_parents.parent_id` (supersedes and targets). `origin_device` is the `events.replica_id` column (`'local'`
   for events written on this device), because the schema has no separate origin field. See the open items.
4. **Storage and chain binding.** `event_sigs(event_id, key_id, alg, sig)` is an append-only index. The event hash
   binds the signature: `hash = sha256(prev_hash "\n" canon(event) ["\n" sig])`. For unsigned rows this is
   byte-identical to the previous format, so existing chains verify unchanged (test
   `test_hash_v2_equals_v1_for_unsigned_rows`). Deleting or editing a signature breaks the event chain.
   Trigger `events_require_sig` refuses a local signed-type INSERT without a signature row once a key is registered.
5. **Legacy.** Human-only events before the first `key.registered` are classified `legacy-unsigned`. They are accepted
   and flagged by doctor. Old rows are never rewritten. `vault sign-legacy` (strict TTY, no test bypass) appends
   signed `attestation.recorded{target_event_ids[], statement}` events. The type is `attestation.recorded` because
   `events.type` must match `<a>.<b>`.
6. **External anchor.** After each append/audit commit, the events and audit heads plus the `key_id` are signed
   (`lattice-anchor-sig/v1`) and written atomically (0600) to `VAULT_ANCHOR_PATH` or
   `<config dir>/anchors/<sha256(db path)[:16]>.anchor.json`. On open, a DB behind the anchor or a hash mismatch is
   an error, and a missing anchor is a warning.

## Decisions (2026-10-14, Kerem / Lead Architect / Data Systems)
1. **Key rotation and recovery** come in a separate PR *before* the multi-device work: a rotation CLI (`key.rotated`,
   signed by both keys) and an offline recovery code. Not in this PR.
2. **Second anchor location.** The user can choose an optional second location (`VAULT_ANCHOR_PATH2`). Planned for
   the next PR, **not implemented** here.
3. **OS keychain backend** first, with the 0600 file as the fallback. Separate PR (today the keychain backend is a stub).
4. **Defaults stay** at `VAULT_FULL_VERIFY_DAYS=30` and `VAULT_VERIFY_SAMPLE_K=4` (segment 64).
5. **Sync alignment (agreed with Data Systems):**
   * The origin writes its real device id into `replica_id` at write time. Until that change lands, sync verifies
     user signatures against the stored `origin_row`.
   * Device keys are certified by the user key (`key.registered{role:'device', device_id, certified_by:<user key_id>}`).
   * Retroactive revocation happens only with `compromised:true`, plus a user signature and a human decision.
   * Anchors are kept per device and per origin chain (seq + head vector). This is Data Systems' PR 7.
   * Packages carry `key.*` events from `vaultsync/0.2` on. Until then, `remote-unsigned` means **quarantine**.
     Implementation gap in this PR: such events from *paired* devices are still accepted and only flagged by doctor.
     Unpaired-device signed types are skipped. The quarantine rule lands with the sync PR.

## What Data Systems must align on (open items, superseded where item 5 above decides)
- **origin_device.** Sync rewrites `replica_id='local'` to the origin device id on import (`sync.py`), which changes
  a field that is signed. The receiver must verify against the stored origin row (`sync_imported.origin_row`), or
  `'local'` must be replaced by the real device id at write time. Decide before package signing.
- **Imported human-only events** are stored unsigned locally and classified `remote-unsigned` (flagged, not
  rejected). Packages now carry `sig` so the origin hash verifies, but the signature itself is **not verified on
  import** yet. Needed: ship `key.registered` for the user key in packages and verify user signatures on import.
- **Device key certification.** Should device keys be certified by the user key (`certified_by`) or by an existing
  device (draft §3)? This ADR assumes the user key.
- **Revocation by HLC.** `effective_hlc` comparisons depend on sane clocks. The skew bound from `docs/sync.md`
  applies. Retroactive revocation for a compromised key (`compromised:true`) is not implemented (draft S4).
- **Anchor per device.** The anchor is local, per DB path, and it is not synced.
- **Redaction copies** keep the original signatures (the message excludes `prev_hash`). A redacted *signed-type*
  event would then fail verification. Rule for that case: re-sign, or attest.

## Consequences
New dependency on `cryptography` for any human-only write. A lost user key means no new human-only events until
rotation has a CLI. See SECURITY.md for the limits.
