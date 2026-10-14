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

## 2. Redacted signed events (decision after Security review: option 1, salted; deferred, not implemented)
Today a redact-copy replaces the payload of a signed-type event, so its signature fails in the copy (known limit).
- **Chosen: option 1 with a new signature contract `SIG_DOMAIN = b"lattice-event-sig/v2\n"`.** The signed message
  binds `payload_hash = SHA-256(salt || canon(payload))`, where `salt` is a 128-bit random value per event stored in
  the payload envelope. The redacted copy keeps `payload_hash` (in `redactions`, `orig_payload_hash`) but deletes the
  payload **and the salt**, so the stored hash is no longer a dictionary oracle for short, guessable human payloads
  (`{"reason":"ok"}`). Classify accepts the stored hash only when a valid, user-signed `event.redacted` targets the
  event; otherwise the event stays `bad-signature`.
- v1 events keep verifying under v1 (`SIG_DOMAIN` v1, unsalted). They cannot be redacted without failing their
  signature; a v2 re-attestation could cover them.
- Rejected: option 2 (the redaction event as the only proof) — trust in the target moves entirely to whoever signs
  the redaction. Also rejected: keeping unsalted SHA-256 (oracle). An alternative is to always encrypt human-event
  payloads and hash the ciphertext.
- Why deferred: it versions the ADR 0011 contract and touches every signed event; it needs its own PR + review.

## 3. Also deferred
- OS keychain backend (`VAULT_USER_KEY_BACKEND=keychain` stays a stub): platform-specific, needs packaging (step 6).
- Per-device signing / device keys: part of 0.2 above.
- Retroactive revocation (`compromised:true`): needs the ADR 0011 human-decision flow; today revocation is never
  retroactive. Back-dating with a revoked key is closed by binding revocation to log position (ADR 0012); legitimate
  events signed offline before a revocation but imported after it stay quarantined until 0.2 can prove they predate it.
