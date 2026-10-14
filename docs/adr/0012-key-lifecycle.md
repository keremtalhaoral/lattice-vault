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
- **Recovery code**: 160 random bits shown once as base32 groups (TTY on stdin **and stdout**); recovery key seed =
  `SHA-256("lattice-recovery-seed/v1\n" || code bytes)`; only the public key is stored. **There is never a window
  without a live recovery key**, and a user key alone can never add one. The registry accepts a recovery
  `key.registered` only as the very next log event (same transaction) after one of:
  1. the first, self-signed user key (`vault keys init-user` creates the code in the same transaction),
  2. the live recovery key's self-revocation (`vault keys recovery-code --replace`, needs the OLD code; revoke +
     new registration in one transaction),
  3. a recovery-certified new user key (`vault keys recover`, which prints a fresh code in the same transaction),
  and only while no other recovery key is live. A recovery key is never revoked transitively (rotation keeps it).
  Trade-off: a lost live code cannot be replaced; the vault keeps working with the user key.
  **Migration:** vaults whose first key was registered before this rule have no recovery key and can never gain
  one; `doctor`/`verify` warn loudly. Re-initialise (`vault init` on a new path + import/restore of content) to get one.
- **Recover** (`vault keys recover --new-key PATH`, code from the TTY): the live recovery key registers a new user key;
  that one event atomically revokes every other user key, everything they certified, and the recovery key; the same
  transaction registers a fresh recovery key.
- **Revocation `effective_hlc`**: `"now"` (= the revocation's own HLC) or later; an earlier value is accepted only with
  `compromised:true` (Data Systems N1).
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
- **Root cause noted from the #13 review:** the event signature covers `event_parents` (targets are written there with
  `rel='target'`), while projections read `event_targets`, which is not signed. Every signed event is therefore only
  accepted if `event_targets` equals its signed `rel='target'` parents (`signing.targets_match`; status
  `targets-mismatch`, an error). The sync import/release path enforces the same rule (#13). Long term the target list
  should be part of the signed message (sig v2).
- Whoever holds the recovery code can take over signing (by design); store it offline, apart from the key file.
- An attacker holding the *old* key can sign until the rotation is committed. Retroactive (`compromised:true`)
  revocation is deferred.
- The default key file is unencrypted (0600); set `VAULT_USER_KEY_PASSPHRASE` to encrypt it. Prompting for a
  passphrase on rotate/recover is a follow-up.
- Anchors are written one after the other; if the second write fails the two disagree and open fails closed.
- Not done here: OS keychain backend, device keys / per-device signing, retroactive (`compromised:true`) revocation.
