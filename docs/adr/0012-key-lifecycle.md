# ADR 0012: User key lifecycle (rotate, revoke, offline recovery code) and a second anchor

Status: Proposed (implemented on `feat/signing-completion`; Security review pending)

## Context
ADR 0011 defined `key.rotated` / `key.revoked` verification but no CLI, and decided on a rotation CLI, an offline
recovery code and an optional second anchor (`VAULT_ANCHOR_PATH2`) before any multi-device work.

## Decision (revised after the Security review of #12)
- **One active user key.** The first user key is self-signed (TOFU; fingerprint confirmed on the TTY). A user key
  registered by the active user key is only *pending* and cannot sign until a dual-signed `key.rotated` activates it.
- **Rotate** (`vault keys rotate --new-key PATH`, TTY): `key.registered{new, certified_by:old}` (pending) +
  `key.rotated{old,new,new_key_sig}` signed by the old key, `new_key_sig` by the new key. The rotation activates the
  new key and revokes the old key **and, transitively, every non-recovery key it certified** (pending keys an attacker
  may have minted, device keys). The recovery key is **not** revoked by rotation: it dies only by self-revocation
  (old code) or by `recover`, so a thief who rotates with a stolen user key cannot disable the owner's recovery.
- **Revoke** (`vault keys revoke KEY_ID --reason R`, TTY): the active user key may revoke only device keys it
  certified. A recovery key may revoke only itself. The user key itself is replaced only via rotate/recover.
- **Recovery code** (`vault keys recovery-code`, TTY on stdin **and stdout**): 160 random bits shown once as base32
  groups; recovery key seed = `SHA-256("lattice-recovery-seed/v1\n" || code bytes)`; only the public key is stored.
  Registered by the active user key only while no recovery key is live. Replacing a live code
  (`--replace`) needs the OLD code: the old recovery key revokes itself first. A stolen user key alone therefore
  cannot swap or kill the owner's code. Trade-off: a lost code cannot be replaced while it is live (no path without
  the code); the vault keeps working with the user key.
- **Recover** (`vault keys recover --new-key PATH`, code from the TTY): the live recovery key registers a new user key;
  that one event atomically revokes every other user key, everything they certified, and the recovery key.
- **Revocation is bound to log position**: a revoked key's signature is valid only if the event's `seq < revoked_seq`
  **and** `hlc < revoked_hlc` (or it is the revoking event itself). HLCs are chosen by the signer, so back-dating
  alone no longer works; inserting below the revocation changes chain hashes, which the anchor (rewritten by the new
  key) detects. Sync: an event signed by a revoked key is quarantined whatever its HLC (human release only after
  0.2 provides pre-revocation evidence).
- **Role rules** (registry + classify + sign_row): only the active `user` key signs ordinary human-only events and
  anchors; pending keys never sign; a recovery-signed approval is `wrong-role-key`.
- **Second anchor**: if `VAULT_ANCHOR_PATH2` is set (for the `VAULT_DB` vault), every anchor write goes to both
  paths and open/doctor/verify check both. A missing second anchor (primary present) is a warning; a mismatch is an
  error. Anchors signed by a revoked or non-user key are errors.

## Consequences / limits
- Whoever holds the recovery code can take over signing (by design); store it offline, apart from the key file.
- An attacker holding the *old* key can sign until the rotation is committed. Retroactive (`compromised:true`)
  revocation is deferred.
- The default key file is unencrypted (0600); set `VAULT_USER_KEY_PASSPHRASE` to encrypt it. Prompting for a
  passphrase on rotate/recover is a follow-up.
- Anchors are written one after the other; if the second write fails the two disagree and open fails closed.
- Not done here: OS keychain backend, device keys / per-device signing, retroactive (`compromised:true`) revocation.
