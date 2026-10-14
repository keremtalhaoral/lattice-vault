# Backup and restore

```sh
./vault backup --out ~/vault-backups/2026-10-14          # vault.db + manifest.json only (never keys.db)
./vault backup-keys --out /other/media/keys-2026-10-14   # keys.db (KEK-wrapped) + its own manifest, stored apart
./vault backup-kek --out /third/place/kek-2026-10-14     # keys.kek (or passphrase salt) + manifest, stored apart from both
./vault restore DIR --to /path/new/vault.db [--keys KEYS_DIR [--kek KEK_DIR]] [--force]
                    [--allow-missing-keys] [--allow-no-keys]
./vault doctor [--decrypt-all]                           # integrity, chains, projections, key decryptability
./vault verify                                           # read-only: full chain verify + projection hash vs fresh rebuild
```

All four write commands (`backup`, `backup-keys`, `backup-kek`, `restore`) are human-only (TTY gate, like `redact`/`migrate`). `--no-keys` on `backup` is
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
- **The KEK is never part of a keys backup** (or a vault backup). Back it up with `vault backup-kek`.

## KEK backup (`vault backup-kek`) — decision
The 2026-10-14 restore drill copied `keys.kek` by hand because nothing backed it up. Bundling it into
`backup-keys` (even behind a flag) would put the wrapping key next to what it wraps: anyone holding that one
directory could decrypt every subject. Instead the KEK gets its **own explicit command and location**:
- `vault backup-kek --out DIR3` (human-only) writes `keys.kek` (file mode) or only `keys.kek.salt`
  (`VAULT_PASSPHRASE` mode: the passphrase itself is never written; keep it in your password manager) plus
  `manifest.json` (`lattice-kek-backup/v1`, sha256, kek id). Refused if DIR3 equals, is inside or contains a
  vault or keys backup; `backup` / `backup-keys` likewise refuse to write into or around a KEK backup.
- Keep the three backups on three separate media/locations (e.g. vault backups off-site, keys backup on an
  encrypted drive, KEK in a password manager / offline).
- `restore --keys K --kek DIR3` verifies the KEK manifest, installs it next to the target (0600) and then
  trial-decrypts as below. An existing *different* KEK at the target is never overwritten (not even with
  `--force`); move it away first. A salt backup only works with `VAULT_PASSPHRASE` set, and vice versa.

> **Warning — crypto-shredding.** A keys backup can decrypt every subject that was not yet shredded when it
> was taken. Shredding later does not reach it. After a shred, delete (or re-take) older keys backups.

## Restore
1. Vault manifest format/schema check, sha256; with `--keys`, keys manifest sha256 and key-id list check.
2. Staged copy next to the target: `integrity_check` + `quick_check`, trigger check, full event + audit
   hash-chain verify, count / chain head equal to manifest.
3. With `--keys`: every `enc_key_id` in the log must exist in keys.db or belong to a `subject.shredded` event,
   else restore fails (`--allow-missing-keys` restores anyway and lists them; it only covers *some* keys
   missing from a keys backup, never a restore without `--keys`). A KEK must be reachable for the target
   (keys.kek next to it, `VAULT_KEK_FILE`, `VAULT_PASSPHRASE`, or `--kek`), else restore refuses rather than
   letting a fresh KEK be auto-created. Keys come only from `--keys`.
   **KEK trial-decrypt:** every live (unshredded) DEK in the staged keys.db must unwrap with that KEK and one
   encrypted event per key must decrypt; otherwise restore fails with `KEK does not match the keys backup`
   and nothing is written. The report carries `kek_verified: {keys_checked, events_checked}`.
3b. Without `--keys`: if the log has encrypted events whose key was not shredded, restore **refuses** (rc 1).
   `--allow-no-keys` restores anyway on purpose: those events get status `undecryptable`, a warning is
   printed, and restore creates **no** keys.db / KEK at the target. (Any later command that opens the vault
   creates a fresh, empty keystore there; a later `restore --keys --force` into that dir is then rejected by
   the trial-decrypt until the right keys.kek is put in place.)
4. Shreds recorded in the restored log are re-applied to the restored keys.db (wrapped DEK nulled).
5. Refuses existing target vault.db / keys.db without `--force`; atomic `os.replace` (same filesystem).
6. `connect()` re-verifies, projections rebuilt, `restore` audit row written; JSON report printed.

## Doctor / verify
- `vault doctor` also unwraps every live DEK with the current KEK and decrypts one sampled event per key
  (`--decrypt-all`: every encrypted event). Failures are problems (exit 2): `checks.decrypt` gives counts only,
  never ids or plaintext. Keys referenced by a `subject.shredded` event or destroyed in keys.db count as
  `shredded_keys`, not `events_with_missing_keys`.
- `vault verify`: full event + audit hash-chain verify, chain head, `projection_hash` and whether it equals a
  fresh in-memory rebuild of the log (exit 2 on failure).
- Event status `undecryptable` (key missing, wrong KEK, ciphertext fails authentication) is distinct from
  `redacted` (redacted or crypto-shredded: data intentionally destroyed). `history` shows
  `{"undecryptable": true}`, context export / `show` print `[undecryptable]`.
- Restore errors on a corrupt vault.db never echo SQLite's message (it can quote stored row text).

Limitation: restore only knows shreds that are *in the restored log*. Restoring a pre-shred vault backup with
a pre-shred keys backup brings the subject back as readable.

## Durability settings (decision)
`connect()` now sets `busy_timeout=5000` and `synchronous=FULL` (vault.db and keys.db). We **stay on
`journal_mode=DELETE`** (design §storage, ADR 0004): with DELETE, `synchronous=FULL` is the durable setting;
WAL+NORMAL would be faster but a `-wal` file can retain redacted/shredded pages, and backup/redaction would
need explicit `wal_checkpoint(TRUNCATE)` handling. Revisit with sync at scale. The backup API is
journal-mode agnostic, so switching later does not change the backup format.
