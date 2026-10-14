# Backup and restore

```sh
./vault backup --out ~/vault-backups/2026-10-14          # vault.db + keys.db (wrapped) + manifest.json
./vault backup --out DIR --no-keys                       # log only; keeps crypto-shredding effective
./vault restore DIR --to /path/new/vault.db [--force] [--allow-missing-keys]
./vault doctor                                           # now includes PRAGMA integrity_check / quick_check
```

Both commands are human-only (TTY gate, like `redact`/`migrate`).

## Backup
- Uses the sqlite3 online backup API (page-consistent while the vault is open; `busy_timeout` 5 s).
  vault.db and keys.db are copied one after the other, so a key created between the two copies may be in
  keys.db but not vault.db (harmless) — never the reverse in normal use, since keys are created before events.
- Output dir is created 0700 and must be empty; every file is 0600.
- `manifest.json` (`lattice-backup/v1`): sha256 of each file, event count, event + audit chain heads,
  schema version, `created_at` (UTC), tool version, `includes_keys`.
- keys.db stays KEK-wrapped. **The KEK (`keys.kek` / `VAULT_PASSPHRASE` salt) is never in a backup**;
  keep it separately (password manager / OS keychain). Without it the encrypted fields of a backup are unreadable.

> **Warning — crypto-shredding.** A backup that contains keys.db can decrypt every subject that was not yet
> shredded at backup time. Shredding a subject later does not reach existing backups. After a shred, delete
> (or re-take) older backups that include keys, or use `--no-keys` for long-lived/off-site copies.

## Restore
1. Manifest format/schema check, sha256 of every file.
2. Staged copy in a temp dir next to the target: `PRAGMA integrity_check` + `quick_check`, trigger check,
   full event + audit hash-chain verify, event count / chain head equal to manifest.
3. With keys: every `enc_key_id` in the log must exist in keys.db or belong to a `subject.shredded` event;
   otherwise restore fails (`--allow-missing-keys` restores anyway and lists them). A KEK must be reachable
   for the target (keys.kek next to it, `VAULT_KEK_FILE` or `VAULT_PASSPHRASE`), else restore refuses rather
   than letting a fresh KEK be auto-created.
4. Shreds recorded in the restored log are re-applied to the restored keys.db (wrapped DEK nulled).
5. Refuses existing target (vault.db or keys.db) without `--force`; `os.replace` (atomic, same filesystem).
6. `connect()` re-verifies, projections are rebuilt, a `restore` audit row is written; JSON report printed.

Limitation: restore only knows shreds that are *in the restored log*. Restoring a pre-shred backup brings
the subject back as readable; nothing in the backup can tell it otherwise.

## Durability settings (decision)
`connect()` now sets `busy_timeout=5000` and `synchronous=FULL` (vault.db and keys.db). We **stay on
`journal_mode=DELETE`** (design §storage, ADR 0004): with DELETE, `synchronous=FULL` is the durable setting;
WAL+NORMAL would be faster but a `-wal` file can retain redacted/shredded pages, and backup/redaction would
need explicit `wal_checkpoint(TRUNCATE)` handling. Revisit with sync at scale. The backup API is
journal-mode agnostic, so switching later does not change the backup format.
