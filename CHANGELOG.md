# Changelog
All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]
### Security
- Key lifecycle (docs/adr/0012-key-lifecycle.md): `vault keys rotate --new-key PATH`, `vault keys revoke`,
  `vault keys recovery-code` and `vault keys recover`. Recovery keys (role `recovery`) can only certify a new user key
  and revoke; revoked/non-user keys can no longer sign, certify or anchor. Optional second anchor `VAULT_ANCHOR_PATH2`.
  After Security review: one active user key (others pending until a dual-signed rotation), transitive revocation of
  non-recovery keys certified by a rotated/recovered key (the recovery key survives rotation), recovery-code replacement needs the old code, narrow revoke rights, and
  revocation bound to log position (`seq < revoked_seq` and `hlc < revoked_hlc`).
  Recovery keys are created only atomically with the first user key, `--replace` (old code) or `recover`; doctor
  warns when no recovery key is live; `keys show` lists it. Revocations cannot backdate without `compromised:true`.
  Signed events whose `event_targets` differ from their signed target parents are `targets-mismatch` (error).
- Human-only events are signed with a user Ed25519 key (`vault keys init-user`, `VAULT_USER_KEY`). Signatures are
  stored in `event_sigs` and bound into the event hash. New unsigned human-only events are refused. Older ones are
  flagged as `legacy-unsigned`, and `vault sign-legacy` re-attests them. See docs/adr/0011-signing-keys.md.
- A signed external anchor (chain heads + key_id) is written after each commit. A rollback, truncation or hash
  mismatch fails the open.
- Open also verifies K sampled segments below the checkpoint and nudges you to run `vault doctor` after 30 days.
- `VAULT_ALLOW_NONTTY` works only inside the test harness.
- Sync prototype: incoming human-only events (`vault.SIGNED_TYPES`) are applied only with a valid signature by a user
  key registered on the receiving vault (`signing.sig_message`/`registered_keys`) and from a paired device. Unsigned,
  forged, unknown-key, revoked-key, non-user-actor and `key.*` events, plus every `user:*` content event, are
  quarantined (`sync_quarantine` with a reason, not applied, idempotent); `vault sync-quarantine` lists them. This
  replaces the accept-and-flag `remote-unsigned` path for unverified events. Sync commands warn that multi-device use
  with real data is unsupported.
- `vault verify` and `vault doctor` also report signatures (signed / legacy / remote-unsigned), the key registry
  and the anchor. `restore` resets the anchor of the target path; a fresh signed anchor is written on its first commit.
- Restore drill 2026-10-14 fixes. `restore --keys` trial-decrypts with the target KEK (every live DEK + one
  event per key) and refuses on mismatch instead of exiting 0 with silently unreadable fields.
- `vault doctor` checks decryptability (DEKs unwrap; sampled events, or all with `--decrypt-all`).
- Restore without `--keys` is refused when unshredded encrypted events exist; `--allow-no-keys` overrides it on
  purpose and no longer auto-creates keys.db / a fresh KEK at the target.
- Restore errors for a corrupt vault.db no longer leak stored row text from SQLite messages.
- Read-only commands (`verify`, `doctor`, `history`, MCP, …) never create keys.db or a KEK. keys.db / KEK are
  created only by a sensitive write on a vault with no keystore and no encrypted events; a missing KEK for an
  existing keystore or existing encrypted events fails loudly instead of minting a new KEK.
- keys.db stores a KEK check value; restore verifies it, so a wrong KEK is caught even with no live keys. A keys
  backup with neither is restored with a `KEK NOT VERIFIED` warning (`kek_verified.tested: false`).
### Added
- `vault backup-kek --out DIR` (separate, explicit KEK backup; salt only in passphrase mode) and
  `restore --kek DIR`. A KEK is never bundled with `backup-keys`. See docs/backup-restore.md.
- `vault verify`: read-only full chain verify + projection hash vs a fresh rebuild.
- Event status `undecryptable` (missing key / wrong KEK), distinct from `redacted` (redacted or crypto-shredded).
- `doctor` reports `shredded_keys` separately from `events_with_missing_keys`, plus `checks.keystore`.
- Shredded subjects stay `redacted` (not `undecryptable`) even without keys.db, e.g. after `--allow-no-keys`.
### Changed
- README: CLI usage and file table synced with `backup-kek`, `restore --kek`, `verify`, `keys show`, `sync-quarantine` and the sync quarantine rules.
### Fixed
- Tests no longer leak temp dirs (`testutil.fresh` registers `shutil.rmtree` cleanup).
### Changed
- **Breaking (CLI):** a missing `VAULT_DB` is an error instead of silently creating an empty vault; create one
  with the new `vault init`. The MCP server never creates a vault.
- Projections are applied incrementally on append, inside the append transaction, through the same fold
  functions as `rebuild()`. Unsafe event shapes (corrections, reverts, redaction/shred, HLC merges, approval of
  order-dependent types) fall back to a full rebuild. Mean append time went from 21.5 to 1.2 ms at 1k events,
  150 to 2.3 ms at 10k and 1696 to 3.6 ms at 100k.
- Open verifies the hash chains incrementally from `chain_checkpoint` (verified head seq/hash), and skips the
  rebuild when `proj_meta.last_seq == MAX(seq)`. Open with a current checkpoint takes 1.2–1.7 ms at 1k–100k events,
  down from 11 ms to 973 ms. `vault doctor` (`--full`) still verifies from genesis.
- `rebuild()` runs in a single transaction, so a failure leaves the old projections intact. Link lookups during a
  rebuild are batched (no per-event N+1 queries). A full rebuild is about 1.1–1.4× slower, because it also
  checkpoints `projection_hash`. See docs/projections.md.
### Added
- Event schema registry + upcasters (`schemas.py`, docs/schema-evolution.md). Every emitted type has a
  current `schema_version` and a declarative validator. `append()` validates and stamps the version, and MCP
  `propose_event` refuses invalid payloads and unknown types with a `schema: …` error. Upcasters run in memory on
  read (rebuild, history, pack, export-context, show, `get_event`), and stored events are never rewritten.
  Events newer than the code are tolerated, excluded from projections (status `unknown_version`) and reported
  by `vault doctor`. The human CLI may still add unregistered types, with a warning.
- `bench_append.py` (append ms, rebuild time, open time, peak RSS, DB size) and `test_projections.py`
  (randomized incremental-vs-full equivalence, shuffled delivery, checkpoint + tail, atomic rebuild, tamper detection).
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
### Changed
- README: CLI usage and file table synced with `backup-kek`, `restore --kek`, `verify`, `keys show`, `sync-quarantine` and the sync quarantine rules.
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
