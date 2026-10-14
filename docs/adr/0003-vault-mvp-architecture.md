# ADR 0003 (D-003): Vault MVP architecture
- **Status:** Accepted
- **Implementation:** Implemented (prototype 0.1.0)

## Context
A person's context is lost between chat tools and AI assistants. Needed: a single source of truth, full
history and auditability, human approval of agent writes, local-first operation ready for multiple replicas,
and a portable, size-budgeted context bundle. A plain Markdown folder edited by several writers was shown to
be prone to accidental overwrites.

## Decision
SQLite with an append-only event log as the source of truth plus derived projections (`vault rebuild`).
Ordering by `(hlc, id)` with UUIDv7 ids and a hybrid logical clock; wall-clock time is informational only.
Idempotent writes via unique `(actor, idempotency_key)`. Concurrent writes are recorded as conflicts; no
silent last-write-wins (for preferences/decisions; projects and goals still use last-write-wins — planned).
Details in ADRs 0004–0010.

## Alternatives
- Markdown files: structure and history cannot be enforced.
- Postgres / cloud database: operational burden; not local-first.

## Consequences
Risks and mitigations: secret leakage (filter, encryption, redaction), prompt injection (delimited Context
Packs, proposals only), projection bugs (deterministic rebuild, `vault doctor`), schema evolution
(versioned schema, migrate-by-copy), Turkish search (normalization), single-file loss (snapshots; user backups).
Open: authentication for a remote/HTTP MCP transport; Turkish stemming.
