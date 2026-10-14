# Changelog
All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]
### Added
- `vault export-context`: MCP-fallback Context Pack (`lattice-context/v1`, Markdown + YAML front matter) of
  approved facts only, with `[encrypted]`/`[redacted]` placeholders, deterministic output, token budget and a
  `vault_update` template. See docs/context-pack.md. `vault pack` is unchanged.

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
