# ADR 0014: Crypto-shredding, complete and multi-device

Status: Proposed (prototype on `feat/crypto-shredding`, stacked on #14; Security and Data Systems review requested)

## Context
Local crypto-shredding existed (per-subject AES-256-GCM DEKs in keys.db, `vault shred --confirm` -> `pending_destroy`
with a grace period -> `shred-finalize`, `subject.shredded` event, `redactions` row). ADR 0013 added DEK transport and
made a synced `subject.shredded` effective on paired devices. Open gaps: a pending shred (and its cancellation) did
not propagate; the local steps were not crash-safe across vault.db and keys.db; `vault backup` copied derived
projection tables, which hold decrypted plaintext of sensitive fields, so a later shred could not reach that backup;
`verify`/`doctor` did not check the lifecycle.

## Decision
1. **The log is the source of truth; keys.db follows it.** Three user-signed `subject.*` events:
   `subject.shred_scheduled {key_id, grace_seconds}` (`shred --confirm`), `subject.shred_cancelled {key_id}`
   (`shred-cancel`), `subject.shredded {key_id}` (`shred-finalize`). They are signed like other human-only types
   (`SIGNED_TYPES`); the two new types are not added to the trigger SQL so existing vaults keep identical triggers
   (`check_triggers`), and agents can never write `subject.*` (agent API). Integer seconds, because signed canonical
   JSON refuses floats.
2. **Event first, then keys.db.** Each local operation writes its signed event, then changes keys.db (a separate
   database; one transaction is impossible), then writes the `redactions` row and VACUUMs. `shred-finalize`: checks
   (pending, grace over) -> `subject.shredded` (reads are refused from this point: `vault.shred_applies`) -> destroy
   the DEK (keys.db, secure_delete + VACUUM) -> `redactions` row -> projection rebuild -> VACUUM of vault.db.
3. **Reconcile (`shredding.reconcile`) makes keys.db match the log**, idempotently. It runs on vault open when
   something is due (cheap check against `shred_reconciled`), in `doctor`, after `sync-import`, after a quarantine
   release and after a key import. An event counts only if its key belongs to the event's subject in keys.db, it
   re-verifies now (local: valid signature or legacy; synced: `remote-signed`), its actor is `user:*`, and its origin
   is not revoked for key transport; otherwise it is noted once in `sync_key_quarantine` and ignored.
   Decision per key: a valid `subject.shredded` wins (local: destroy now, the user already finalized here; synced:
   `pending_destroy` with the LOCAL grace period, destroyed when it is over, ADR 0013); otherwise the latest valid
   schedule/cancel by `(hlc, id)` sets `pending_destroy` / `active`. A schedule alone is never finalized
   automatically: destruction always needs a `subject.shredded`.
4. **Pending shreds propagate.** A synced schedule puts the receiver's key into `pending_destroy` (local grace from
   the moment it is applied; data stays readable while pending, as on the origin); a synced cancel makes it active
   again. A cancel on any device propagates back (the owner's last signed decision by `(hlc, id)` wins).
   `shred-cancel` is refused once a valid `subject.shredded` is in the log.
5. **No plaintext after finalize.** Sensitive fields are stored as ciphertext in events and are never indexed (FTS5
   uses `text_norm`, which excludes them). Their decrypted values exist only in derived projection tables, which are
   rebuilt (now `redacted`) and the file VACUUMed with `secure_delete=ON` and `journal_mode=DELETE` (no WAL). keys.db
   gets the same. Snapshots (`pre-shred`) drop the derived tables (`SNAP_DROP`); **vault backups** now drop the projections and
   `url_cache` (keeping `review_queue` verdicts, see below) and VACUUM, so
   they hold only ciphertext; restore rebuilds projections. A test writes a canary into a sensitive field and scans
   every file in the vault directory (vault.db, keys.db, journals, snapshots) and a backup taken while pending.
6. **Backups.** Restore re-applies every `subject.shredded` in the restored log to keys.db (existing), then reconcile
   runs on open. A restored *old* vault backup learns later shreds by syncing from a device that has them.
   **Remaining risk (documented):** keys backups (`vault backup-keys`) taken before a shred still hold the KEK-wrapped
   DEK; together with the KEK (backup-kek) and an old vault backup they decrypt the subject. Delete them after a
   shred. A receiver keeps the wrapped DEK until its grace period ends (ADR 0013 N11).
7. **CLI.** `vault shred SUBJECT --preview | --confirm [--grace-days N]`: human-only TTY; `--confirm` explains the
   effect (counts, grace, plaintext fields not affected, devices follow) and asks to type the subject on a TTY;
   output gives the destroy time (UTC) and the next command. `shred-finalize` asks again and reminds to delete old
   keys backups. `shred-cancel` says paired devices follow.
8. **Verify / doctor.** `shredding.problems` (read-only, used by `vault verify` and `vault doctor`): ERROR for a live
   DEK with a valid shred in the log (active, or past grace), a scheduled key that is not pending, a cancelled key that
   is still pending, a destroyed key with no `redactions` row; WARNING for a past-grace pending key without a shred
   event (run `shred-finalize`) and for a destroyed key without a shred event (legacy / interrupted). `doctor` then
   reconciles (not read-only; `verify` is).

## Consequences / deferred
- Only fields written as `sensitive` are shredded; plaintext fields of the subject stay (use `vault redact`).
- Unlinked journal/snapshot files may remain on the filesystem/SSD below SQLite (`secure_delete` covers database
  pages, not the device). Full-disk encryption is the mitigation.
- Context Pack exports and other files the user wrote out are outside the vault and are not reached.
- **Triggers for the two new event types come with the next schema bump.** Until then, `events_signed_types_human`
  and `events_require_sig` do not cover `subject.shred_scheduled` / `subject.shred_cancelled`; the agent API refuses
  `subject.*`, and reconcile, classify and the sync quarantine ignore unsigned or non-user ones (tested).
- `review_queue` (human citation verdicts, not in the log) is kept in vault backups; entry rows hold only the stored
  payload (placeholders for sensitive fields), claim rows lose their text in backups. In the live vault, claim text a
  user queued from a context pack may contain decrypted values and is not removed by a shred (deferred).
- Concurrent schedule/cancel on two devices resolves by `(hlc, id)`; no human conflict prompt yet.
- A revoked origin's lifecycle events are ignored on receivers, but reads of a `subject.shredded` from it are refused
  until the device is revoked (ADR 0013 N9, safe direction).
- Restore re-applies all `subject.shredded` key ids in the log without the subject/revocation checks (over-destroys,
  safe direction).
