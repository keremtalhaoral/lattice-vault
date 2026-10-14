# Backup and restore

```sh
./vault backup --out ~/vault-backups/2026-10-14          # vault.db + manifest.json only (never keys.db)
./vault backup-keys --out /other/media/keys-2026-10-14   # keys.db (KEK-wrapped) + its own manifest, stored apart
./vault restore DIR --to /path/new/vault.db [--keys KEYS_DIR] [--force] [--allow-missing-keys]
./vault doctor                                           # includes PRAGMA integrity_check / quick_check
```

All three write commands are human-only (TTY gate, like `redact`/`migrate`). `--no-keys` on `backup` is
accepted as a deprecated no-op.

## Vault backup (`vault backup`)
- sqlite3 online backup API (page-consistent while the vault is open; `busy_timeout` 5 s). **Never includes
  keys.db**, so vault backups can be kept long-term / off-site without defeating crypto-shredding.
- Output dir 0700, must be empty, files 0600; refused if it equals, is inside, or contains a keys backup.
- `manifest.json` (`lattice-backup/v1`): sha256 of vault.db, event count, event + audit chain heads, schema
  version, `created_at` (UTC), tool version, `includes_keys: false`.

## Keys backup (`vault backup-keys`)
- Copies only keys.db (still KEK-wrapped) + `manifest.json` (`lattice-keys-backup/v1`: sha256, key ids with
  state). Refused if the target equals, is inside, or contains a vault backup dir (detected via manifest).
- **The KEK (`keys.kek` / `VAULT_PASSPHRASE` salt) is never backed up**; keep it separately.

> **Warning — crypto-shredding.** A keys backup can decrypt every subject that was not yet shredded when it
> was taken. Shredding later does not reach it. After a shred, delete (or re-take) older keys backups.

## Restore
1. Vault manifest format/schema check, sha256; with `--keys`, keys manifest sha256 and key-id list check.
2. Staged copy next to the target: `integrity_check` + `quick_check`, trigger check, full event + audit
   hash-chain verify, count / chain head equal to manifest.
3. With `--keys`: every `enc_key_id` in the log must exist in keys.db or belong to a `subject.shredded` event,
   else restore fails (`--allow-missing-keys` restores anyway and lists them). A KEK must be reachable for the
   target (keys.kek next to it, `VAULT_KEK_FILE`, or `VAULT_PASSPHRASE`), else restore refuses rather than
   letting a fresh KEK be auto-created. Keys come only from `--keys`.
4. Shreds recorded in the restored log are re-applied to the restored keys.db (wrapped DEK nulled).
5. Refuses existing target vault.db / keys.db without `--force`; atomic `os.replace` (same filesystem).
6. `connect()` re-verifies, projections rebuilt, `restore` audit row written; JSON report printed.

Limitation: restore only knows shreds that are *in the restored log*. Restoring a pre-shred vault backup with
a pre-shred keys backup brings the subject back as readable.

## Durability settings (decision)
`connect()` now sets `busy_timeout=5000` and `synchronous=FULL` (vault.db and keys.db). We **stay on
`journal_mode=DELETE`** (design §storage, ADR 0004): with DELETE, `synchronous=FULL` is the durable setting;
WAL+NORMAL would be faster but a `-wal` file can retain redacted/shredded pages, and backup/redaction would
need explicit `wal_checkpoint(TRUNCATE)` handling. Revisit with sync at scale. The backup API is
journal-mode agnostic, so switching later does not change the backup format.
