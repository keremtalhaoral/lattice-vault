# Deferred from roadmap step 2: `vaultsync/0.2` package signing, key-registry sync, redaction-stable signatures

Status: design only, not implemented. Review needed from Security (crypto) and Data Systems (sync) before code.

## 1. `vaultsync/0.2` (signed packages + key registry sync)
- Manifest gains `signature = {key_id, alg:"ed25519", sig}` over `PKG_DOMAIN || canon(manifest without signature)`
  (`signing.PKG_DOMAIN` is already reserved). The signer is a **device key** (`key.registered` role `device`,
  certified by the user key, ADR 0011 §5), so the user key never has to live on every device.
- Replay: the receiver stores `(source_device, package seq)` and refuses a seq ≤ last seen (S8 in the multi-device draft).
- `key.*` events travel in the package and are applied first, in log order, through `signing.registered_keys`
  rules (certification chain rooted in the receiver's pinned first user key). Any key event that does not verify
  against that chain is quarantined as today. A receiver with no user key yet must pin the fingerprint on a TTY
  (TOFU), never implicitly.
- 0.1 packages remain readable with today's quarantine rules.
- Why deferred: needs device keys and a pairing ceremony (draft §4), which is per-device signing — out of scope
  for this PR and blocked on review. Today's mitigation: the receiver must already have the same user key
  (`vault keys init-user` with the same key file) and human-only events are verified per event.

## 2. Redacted signed events
Today a redact-copy replaces the payload of a signed-type event, so its signature fails in the copy (known limit).
Options:
- (a) **Redaction-stable digest**: sign `payload_hash` = SHA-256 over the canonical payload (already the case) and keep
  the original `payload_hash` in the redacted copy (`redactions` row, `orig_payload_hash`), so the signature verifies
  over (`id,type,subject,orig_payload_hash,…`) while the bytes are gone. Requires classify to accept the stored hash
  **only** when a valid, signed `event.redacted` targets the event.
- (b) Record the redaction as its own signed `event.redacted` and classify the target as `redacted-signed` (signature
  no longer checkable; trust moves to the signed redaction).
Proposal: (a) — keeps end-to-end verifiability and needs no new crypto; the signed `event.redacted` gates it.
Human-only event payloads are tiny (reasons) so this mostly matters for approvals with reasons.
Why deferred: it changes what `sig_message` binds for an existing contract (ADR 0011) and needs a Security sign-off.

## 3. Also deferred
- OS keychain backend (`VAULT_USER_KEY_BACKEND=keychain` stays a stub): platform-specific, needs packaging (step 6).
- Per-device signing / device keys: part of 0.2 above.
- Retroactive revocation (`compromised:true`): needs the ADR 0011 human-decision flow; today revocation is never
  retroactive. Known limit: an attacker holding an old key could back-date events below `effective_hlc`; they still
  need DB write access, and the chain + anchor checks detect rewrites of anchored history.
