# `vault show`: event detail and correction chain

*Implemented* (`event_detail.py`).

    vault show <id | vault://event/<id> | unique id suffix (>= 6 chars)> [--json] [--tree]

Shows one event: id, type, subject/key, ts, hlc, actor (and import id), effective trust (and the recorded
trust), effective status (from `proj_status`), schema_version, hash and prev_hash, hash-chain verification of
the log prefix up to this event (plus the link to the next event and trigger check), payload, the review
history (proposed/created, approved, rejected, reverted, batch-approved, redacted: who, when) and audit rows.

**Correction history.** The `event_parents` `supersedes` DAG is walked both ways (ancestors and descendants);
the whole connected chain plus every meta event that targets a chain member (reviews, reverts) is printed
oldest -> newest in `(hlc, id)` order. The *effective head* is the active chain member with no active
superseding child; `effective payload` is the root payload with active `event.corrected` fields applied (same
rule as `rebuild`). `--tree` renders branches. Conflicts are flagged with `!! CONFLICT`: either more than one
head in the DAG (sync fork) or the existing projection conflict (`conflict=1` in `proj_preferences` /
`proj_decisions`, i.e. several live heads per `(subject, key)` / decision id).

**No plaintext leaks.** Payloads are never decrypted: encrypted fields print `[encrypted]`, redacted events
`[redacted]`, and any string matching the secret filter (`vault.find_secrets`) prints `[filtered:<pattern>]`.

**Read-only.** `vault.connect()` writes (journal-mode pragma, chmod, rebuild when projections are missing),
so `show` opens the file with SQLite `mode=ro` and never calls `connect()`. If projections are absent the
status is replayed in memory. Integrity problems are *reported* in `chain_verification`, not raised.

`--json` emits the same fields with sorted keys (`detail_version: "1"`); output is identical for a full id
and a suffix.
