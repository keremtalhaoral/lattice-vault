# Changelog
All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]
### Added
- `vault export-context`: MCP-fallback Context Pack (`lattice-context/v1`, Markdown + YAML front matter) of
  approved facts only, with `[encrypted]`/`[redacted]` placeholders, deterministic output, token budget and a
  `vault_update` template. See docs/context-pack.md. `vault pack` is unchanged.
- `vault show <id|suffix> [--json] [--tree]`: read-only event detail with review/audit history and the full
  correction/supersede chain (effective head, reverts, conflict flagging); never decrypts. See docs/event-detail.md.
- `vault backup --out DIR` (vault.db + sha256 manifest, never keys.db), separate human-only
  `vault backup-keys --out DIR2` (wrapped keys.db + manifest; refused in/around a vault backup dir), and
  `vault restore DIR --to PATH [--keys DIR2] [--force] [--allow-missing-keys]`: verifies hashes,
  integrity_check, triggers, hash chains and key coverage, re-applies logged shreds, renames atomically and
  rebuilds projections. A keys backup defeats later crypto-shredding (warned). `--no-keys` is a deprecated
  no-op. See docs/backup-restore.md.
### Changed
- `connect()` sets `busy_timeout=5000` and `synchronous=FULL`; journal mode stays DELETE (decision in
  docs/backup-restore.md).
- `vault doctor` reports `PRAGMA integrity_check`/`quick_check` and warns when the ops log is not writable.
### Fixed
- `vault doctor` in-memory rebuild could not find the vault's keystore (`''` vs `:memory:` key), so encrypted
  events could be reported as projection drift.

## [0.1.0-prototype] - 2026-10-14
First public prototype. **Not for production use.**
### Added
- Append-only SQLite event log (schema v2) with triggers, UUIDv7 ids, HLC ordering, parent/target link
  tables, derived projections, Turkish-normalized FTS5 search, and Context Pack export (spec 1.0.0).
- Human CLI: add, approve/reject, correct, revert, history, pending, search, pack, rebuild, doctor, migrate.
- Agent API and MCP stdio server with exactly 5 tools (`get_summary`, `search`, `export_context_pack`,
  `get_event`, `propose_event`); hashed per-agent tokens, server-assigned actor, 8 KB payload cap,
  secret filter, rate limit, audit.
- Markdown import with dry run, single-transaction commit, per-file error codes, batch approval of
  owner-signed lines, and revert-import.
- Secrets: pre-write secret filter, AES-256-GCM per-subject field encryption, two-step crypto-shredding
  with grace period, redact-to-new-file with persistent blocklist, pre-operation snapshots.
- Integrity: hash chains over events and audit, fail-loud verification on open, `vault doctor`.
- Human-only citation check (CLI) with SSRF hardening.
- Synthetic example vault (`examples/seed.py`), CI workflow, SECURITY.md.
### Security
- Citation-check tools are intentionally not exposed over MCP.
