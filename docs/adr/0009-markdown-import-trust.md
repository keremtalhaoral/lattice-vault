# ADR 0009 (D-009): Markdown import trust rules
- **Status:** Accepted
- **Implementation:** Implemented

## Context
Existing notes are Markdown written by the owner and by bots; a signature line is easy to forge, and
imports must be repeatable and reversible.

## Decision
- `actor=import:markdown`; **every** imported event is `unverified` / `proposed`.
- "Verified" is derived only from a human `import.batch_approved` event covering lines the owner confirms
  from the dry-run's `owner_lines` list (`vault import-approve <id> --owner-lines …`).
- Owner = exact match of `VAULT_OWNER_NAME`; known bot names → bot; anything else → ambiguous. A bot line
  citing the owner as source counts as a bot line.
- `--dry-run` first; real runs are a single transaction with snapshot, per-file error codes and
  `revert-import`. Idempotency key = path + normalized content hash (line number is metadata only).
- Blocklisted (redacted) content is refused.

## Alternatives
Trusting owner signatures directly (rejected: forgeable).

## Consequences
Importing never makes anything verified without an explicit human step.
