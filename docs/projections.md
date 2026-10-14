# Projections: incremental apply + checkpoints

Review: DDIA review 2026-10-14, issue #2.

## How it works
- **One fold, two drivers.** `rebuild()` replays the whole log in `(hlc, id)` order. `apply_incremental()` applies only
  the event that was just appended, inside the same transaction as the insert. Both call the same pure pieces:
  `_status_step` (status transitions), `decrypt_payload`, `_apply` (projection rows) and `_flag_conflicts`.
  `rebuild()` is still the oracle: `vault rebuild`, and `vault doctor` compares the live projections against a fresh rebuild.
- **Fallback to a full rebuild** (after commit, same result as before this change) happens when an event cannot be
  applied safely on its own:
  - `event.corrected`, `event.reverted`, `event.redacted`, `subject.shredded`, `conflict.resolved` (these can rewrite
    effective payloads, supersede heads or the status of earlier events);
  - the event sorts before an existing event (HLC merge/sync case);
  - approval of a target that is not `preference.set`/`decision.made`/`learning.captured` (project/goal rows depend on
    order), or of a target that has supersede links or children;
  - a target that is not `proposed`, or a target payload that cannot be decrypted;
  - superseding a row whose conflict group is flagged (un-flagging needs the full fold) (forked-root flags set by the last rebuild are never cleared incrementally);
  - `proj_meta.last_seq` is not exactly `seq - 1`.
- **Projection checkpoint.** `proj_meta.last_seq` advances with every incremental apply. On open, a rebuild runs only
  when projections are missing or `last_seq != MAX(seq)`, for example after a crash between commit and fallback rebuild.
  `rebuild()` also writes `chain_checkpoint('projection', seq, projection_hash)`.
- **Chain checkpoint.** `chain_checkpoint('events'|'audit', verified_head_seq, hash)`. On open, `verify_chains_incremental`
  re-hashes the checkpoint row and verifies only the rows after it, then moves the checkpoint forward.
  `vault doctor` (and `vault doctor --full`) always verifies both chains from genesis.
- `rebuild()` runs in a single `BEGIN IMMEDIATE` transaction. If it fails part way, it rolls back and the old projections
  stay intact.
- In `rebuild()`, targets and parents now load in two queries instead of one query per event (N+1).

## Limitations
- If a row **below** the verified checkpoint is tampered with, the open-time check does not catch it. `vault doctor` catches it.
  The checkpoint lives in the same DB, so it is not a defense against someone who can rewrite the whole file.
  External head anchoring is review issue #6.
- The `projection_hash` in the checkpoint is refreshed on rebuild, not on every incremental apply, because hashing all
  projections each time is O(N).
- Corrections, reverts and approvals of order-dependent types still cost a full rebuild.
- `_flag_conflicts` still scans the preference and decision tables on each append.

## Benchmark (`python3 bench_append.py`)
Dev box, Python 3.13, journal_mode=DELETE. Each N runs in a fresh process. "Before" means origin/main.

| events | ms/append before → after | full rebuild ms before → after | open ms (checkpoint current) before → after | peak RSS MB | DB MB |
|---|---|---|---|---|---|
| 500 | 15.7 → 1.2 | 15 → 13 | 6.3 → 1.3 | 22 | 0.8 |
| 1k | 21.5 → 1.2 | 21 → 23 | 11.4 → 1.5 | 23 | 1.3 |
| 2k | 35.5 → 1.1 | 37 → 41 | 21.9 → 1.2 | 26 | 2.2 |
| 5k | 79.9 → 1.2 | 77 → 103 | 52.5 → 1.5 | 32 | 5.2 |
| 10k | 149.9 → 2.3 | 183 → 210 | 100 → 1.7 | 42 | 10.1 |
| 100k | 1696 → 3.6 | 1642 → 2335 | 973 → 1.7 | 234 | 101.6 |

Peak RSS and DB size are the same before and after. A full `rebuild()` is about 1.1–1.4× slower than before, because it
now computes `projection_hash` for the checkpoint and runs as one transaction. A rebuild only runs on fallback events
and in `vault rebuild`/`doctor`. The first open of a DB that has no chain checkpoint yet still verifies the whole chain.
After that, each append is mostly the commit fsync.
