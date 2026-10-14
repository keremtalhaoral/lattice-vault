# ADR 0004 (D-004): Storage model — append-only event log + projections
- **Status:** Accepted
- **Implementation:** Implemented

## Context
History must be complete and tamper-evident, and approvals/corrections must never destroy earlier state.

## Decision
`events` is the single source of truth (grow-only set). UPDATE and DELETE are forbidden by triggers on
`events`, `audit` and the other audit-like tables. Projections (`proj_*`) are derived and rebuilt
deterministically. Approval, rejection, revert and correction are separate events (`event.approved`,
`event.rejected`, `event.reverted`, `event.corrected`) linked via `event_targets` / `event_parents`
(no foreign keys). Events and audit rows are hash-chained and verified on open.
Journal mode is DELETE with `secure_delete=ON` (not WAL), `synchronous=FULL`, `busy_timeout=5000`
(re-confirmed 2026-10-14, see docs/backup-restore.md).

## Alternatives
Mutable rows with a status column; WAL mode (rejected for now: a `-wal` file can retain redacted pages).

## Consequences
Records cannot be removed by normal operations; revert/correction do not remove data. Secrets require the
redaction procedure (copy-to-new-file) or crypto-shredding (ADR 0007) — the only exception to "events are
never rewritten". The hash chain detects naive tampering but not a same-user rewrite or tail truncation.
