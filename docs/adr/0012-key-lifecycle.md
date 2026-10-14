# ADR 0012: User key lifecycle (rotate, revoke, offline recovery code) and a second anchor

Status: Proposed (implemented on `feat/signing-completion`; Security review pending)

## Context
ADR 0011 defined `key.rotated` / `key.revoked` verification but no CLI, and decided on a rotation CLI, an offline
recovery code and an optional second anchor (`VAULT_ANCHOR_PATH2`) before any multi-device work.

## Decision
- **Rotate** (`vault keys rotate --new-key PATH`, TTY): new Ed25519 key written O_EXCL/0600 at PATH, then
  1. `key.registered{new, role:user, certified_by:old}` signed by the old key,
  2. `key.rotated{old,new,new_key_sig}` signed by the old key, `new_key_sig` by the new key (both keys prove possession),
  3. `key.revoked{old, effective_hlc = next HLC, compromised:false}` signed by the **new** key.
  Old signatures (HLC before `effective_hlc`) stay valid; the old key can no longer sign, certify, revoke or anchor.
  The anchor is rewritten with the new key. The user then points `VAULT_USER_KEY` at the new file.
- **Revoke** (`vault keys revoke KEY_ID --reason R`, TTY): signed by the local live user key; not retroactive;
  refuses to revoke the local key itself (use rotate). `compromised` is always `false` here: retroactive revocation
  needs the ADR 0011 human-decision flow and is deferred.
- **Recovery code** (`vault keys recovery-code`, TTY): 160 random bits shown once as base32 groups. The recovery
  Ed25519 key is `seed = SHA-256("lattice-recovery-seed/v1\n" || code bytes)`; only its public key is registered
  (`role: recovery`, certified by the user key). A new code revokes earlier recovery keys. 160 bits of entropy makes a
  password KDF unnecessary.
- **Recover** (`vault keys recover --new-key PATH`, code read from the TTY, never argv): the recovery key certifies a
  new user key, revokes every unrevoked user key (effective now), and the new key revokes the recovery key (one-time).
- **Role rules** (registry + classify + sign_row): only `user` keys sign ordinary human-only events and anchors; a
  `recovery` key may only sign `key.registered` (of a user key) and `key.revoked`; a certifier/revoker must be live at
  the event's HLC. A recovery-signed approval classifies as `wrong-role-key` (bad).
- **Second anchor**: if `VAULT_ANCHOR_PATH2` is set (for the `VAULT_DB` vault), every anchor write goes to both
  paths and open/doctor/verify check both. A missing second anchor (primary present) is a warning; a mismatch is an
  error. Anchors signed by a revoked or non-user key are errors.

## Consequences / limits
- Whoever holds the recovery code can take over signing (by design); store it offline, apart from the key file.
- An attacker holding the *old* key before rotation can still sign with it until the rotation is committed; events
  forged later with an old HLC would need DB write access and are caught only by the anchor/chain checks.
- Not done here: OS keychain backend, device keys / per-device signing, retroactive (`compromised:true`) revocation.
