# Lattice Vault (prototype)

> [!WARNING]
> **Prototype — do not use in production.** This is an experimental, single-user, local-only research
> prototype. Its on-disk format will change, and several security controls are *detection only* or *planned*.
> See [SECURITY.md](SECURITY.md) before storing anything you care about.
>
> **This project has not had an independent security audit.** The security controls described here are the
> authors' own design and tests, so treat them as unreviewed. Store real personal data only
> after you have completed a successful restore drill (`./vault backup` → `./vault restore … --to` a
> fresh path, verified; see [docs/backup-restore.md](docs/backup-restore.md)).

Lattice Vault is a local, append-only memory vault for one person that several AI assistants can read
and *propose* additions to over the [Model Context Protocol](https://modelcontextprotocol.io) (MCP).
A human approves everything that becomes "verified".

## Hızlı Başlangıç
- [docs/quickstart.md](docs/quickstart.md) — 2 dakikada kurulum ve ilk komutlar
- [docs/usage.md](docs/usage.md) — tam kullanım kılavuzu

## Why
Context about a person (preferences, decisions, projects, goals) gets scattered across chat tools and
AI assistants, and a shared Markdown folder is easy to overwrite by accident. The vault keeps:
- **one source of truth**: an append-only SQLite event log with full history, no UPDATE/DELETE;
- **human-in-the-loop**: agent writes are always `proposed` / `unverified` until a human approves them on the CLI;
- **portable context**: a budgeted, cited "Context Pack" that you can paste into any assistant;
- **local-first**: no server, no network code in the core.

## Architecture
```mermaid
flowchart LR
  subgraph Agents["AI clients (Claude Desktop, Cursor, ...)"]
    A1[MCP client]
  end
  subgraph Box["Your machine (single OS user)"]
    MCP["mcp_server.py<br/>stdio JSON-RPC<br/>5 tools"]
    API["agent_api.py<br/>token auth, filters,<br/>rate limit, audit"]
    CLI["vault CLI (vault.py)<br/>human-only: approve / reject /<br/>correct / redact / shred (TTY)"]
    DB[("vault.db<br/>events (append-only, hash-chained)<br/>audit · projections · FTS5")]
    KEYS[("keys.db<br/>per-subject AES-GCM keys")]
    IMP["importer.py<br/>Markdown import"]
    OPS["ops.py<br/>snapshot · redact · shred · doctor"]
  end
  A1 -- "stdio" --> MCP --> API --> DB
  CLI --> DB
  CLI --> IMP --> DB
  CLI --> OPS --> DB
  DB -. "sensitive fields" .-> KEYS
```

- `events` is the only source of truth. Triggers forbid UPDATE/DELETE and restrict human-only event types
  (approve, reject, revert, redact, shred, batch approval) to `user:*` actors.
- Projections (`proj_*`) and full-text search are derived and rebuilt deterministically in `(hlc, id)` order.
- Corrections, reverts and approvals are new events, not edits.
- IDs are UUIDv7 and ordering uses a hybrid logical clock (HLC).

Design details: [docs/design.md](docs/design.md). Decisions: [docs/adr/](docs/adr/).

## Files
| File | Purpose |
|---|---|
| `vault.py` / `vault` | core library + CLI |
| `agent_api.py` | the only agent write path (token auth, validation, secret filter, rate limit, audit) |
| `mcp_server.py` | MCP stdio server (5 tools) |
| `importer.py` | Markdown import (dry run, batch approval, revert) |
| `ops.py` | snapshots, migrate, redact-to-new-file, crypto-shredding lifecycle, `doctor` |
| `crypto_keys.py` | per-subject AES-256-GCM key store (needs `cryptography`) |
| `citation_check.py` | human-CLI-only check for unsupported claims (not exposed over MCP) |
| `obs.py` | allowlisted JSON-lines ops log (file only, never stdout) |
| `signing.py` | user Ed25519 key, signatures for human-only events, signed chain-head anchor |
| `sync.py` | file-based `.vaultsync` export/import with quarantine (experimental) |
| `backup.py` | `backup`, `backup-keys`, `backup-kek`, `restore` (manifest + trial-decrypt verification) |
| `schemas.py` | event payload schemas and upcasters |
| `context_export.py` | `export-context` (legacy `lattice-context/v1` via `--format 1`, docs/context-pack.md) |
| `context_pack.py` | `export-context` default format `context-pack/2` (ADR 0015) |
| `vault_update.py` | `import-update`: one `vault_update` block from AI output, lands unverified (ADR 0015) |
| `tokens.py` | token estimates (optional tiktoken, calibrated TR/EN heuristic) |
| `event_detail.py` | `show`: one event's detail and correction/supersede chain |
| `examples/seed.py` | creates a synthetic demo vault |

## Install
Python 3.11+. The core uses only the standard library (SQLite with FTS5 and JSON1).
```sh
git clone <repo-url> lattice-vault && cd lattice-vault
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt          # optional: cryptography, for encrypted fields / shredding
python -m unittest discover -p 'test_*.py'
python examples/seed.py ./demo-vault     # synthetic vault for a fictional user "Ada"
```

## CLI usage
Set `VAULT_DB` (default `./vault.db`). The human actor is `user:$VAULT_USER` (default `user:owner`).
Human-only commands require an interactive terminal.
```sh
export VAULT_DB=$HOME/.local/share/lattice-vault/vault.db
./vault init                     # once: create the vault (commands never auto-create a missing VAULT_DB)
./vault keys init-user           # once, after init: create + register your Ed25519 signing key and a one-time
                                 # recovery code (TTY, confirm fingerprint; write the code down offline)
./vault keys show                # registered signing key(s), roles, revocation
./vault keys recovery-code --replace   # replace the recovery code (asks for the OLD code)
./vault keys rotate --new-key PATH   # new key, old one revoked (old signatures stay valid); then set VAULT_USER_KEY=PATH
./vault keys revoke KEY_ID --reason ...   # e.g. a lost recovery code
./vault keys recover --new-key PATH  # lost key: reads the recovery code from the TTY

./vault add preference.set user:ada --key language --payload '{"value":"English"}'
./vault add decision.made decision:D-100 --payload '{"decision_id":"D-100","title":"Local-first","decision":"No cloud"}'
./vault add note.added user:ada --text 'bank note' --sensitive text   # encrypted field (per-subject key)
./vault search "local"
./vault pack --profile minimal           # Context Pack (minimal | full)
./vault pending                          # agent proposals waiting for review
./vault approve <event_id>               # or: reject <event_id> --reason ...
./vault correct <event_id> --field value --value "German" --reason "typo"   # append-only correction
./vault revert <event_id> --reason ...
./vault history user:ada

./vault import-markdown /path/to/notes --dry-run     # report only; nothing written
./vault import-markdown /path/to/notes               # one transaction, everything lands unverified
./vault import-approve <import_id> --owner-lines all # confirm owner-signed lines from the dry-run list
./vault revert-import <import_id>

./vault redact <event_id> --out redacted.db --reason ...   # copy-to-new-file; source left untouched
./vault shred user:ada --preview; ./vault shred user:ada --confirm --grace-days 7
./vault shred-cancel user:ada; ./vault shred-finalize user:ada
./vault doctor                           # triggers, hash chains, integrity_check, projection drift, keys, blocklist
./vault backup --out DIR                 # vault.db + manifest, never keys.db (docs/backup-restore.md)
./vault backup-keys --out DIR2           # keys.db only (wrapped); keep apart from vault backups
./vault backup-kek --out DIR3            # keys.kek (or passphrase salt) only; keep apart from DIR and DIR2
./vault restore DIR --to PATH [--keys DIR2] [--kek DIR3] [--force]  # verified restore drill
./vault verify                           # read-only: full chain + signatures + anchor, projections vs fresh rebuild
./vault sync-quarantine                  # synced events held back (unsigned/forged/unknown-key ...), see docs/sync.md
./vault migrate old.db new.db            # schema migration by copy
```
Run `./vault -h` and `./vault <command> -h` for all options.

## MCP usage
Tools (exactly 5): `get_summary`, `search`, `export_context_pack`, `get_event`, `propose_event`.
Resources: `vault://pack/{profile}`, `vault://event/{id}`, `vault://summary`. Protocol versions:
`2025-06-18` (preferred), `2025-03-26`, `2024-11-05`. There is no approve tool over MCP.

1. Register an agent; the token is printed **once** (only its SHA-256 hash is stored in `agents.json`, mode 0600):
   ```sh
   ./vault agent-add my-assistant
   ```
2. Save the token to a file only you can read (preferred over putting it in the client config):
   ```sh
   umask 077; printf '%s' '<TOKEN>' > ~/.config/lattice-vault/my-assistant.token
   ```
3. Configure the client.

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "lattice-vault": {
      "command": "python3",
      "args": ["/path/to/lattice-vault/mcp_server.py"],
      "env": {
        "VAULT_DB": "/path/to/vault.db",
        "VAULT_AGENT_TOKEN_FILE": "/path/to/my-assistant.token"
      }
    }
  }
}
```
**Cursor** (`.cursor/mcp.json` or `~/.cursor/mcp.json`):
```json
{
  "mcpServers": {
    "lattice-vault": {
      "command": "python3",
      "args": ["/path/to/lattice-vault/mcp_server.py"],
      "env": { "VAULT_DB": "/path/to/vault.db", "VAULT_AGENT_TOKEN_FILE": "/path/to/other-assistant.token" }
    }
  }
}
```
Use one agent (and one token) per client. `VAULT_AGENT_TOKEN` (the token itself in the env) also works but
is discouraged: client config files are often synced or shared, and environment variables are readable
via `/proc/<pid>/environ` by the same OS user. Never commit MCP client configs.

## Configuration
| Variable | Meaning |
|---|---|
| `VAULT_DB` | database path (default `./vault.db`) |
| `VAULT_USER` | local human actor name → `user:<name>` (default `owner`) |
| `VAULT_OWNER_NAME` | signature name treated as the owner during Markdown import (default `owner`) |
| `VAULT_AGENTS` | agent registry path (default `agents.json` next to the DB) |
| `VAULT_AGENT_TOKEN_FILE` / `VAULT_AGENT_TOKEN` | agent token for `mcp_server.py` / `vault propose` |
| `VAULT_KEYS_DB`, `VAULT_KEK_FILE`, `VAULT_PASSPHRASE` | key store, key-encryption key file, or passphrase (scrypt) |
| `VAULT_SHRED_GRACE_DAYS` | default shred grace period |
| `VAULT_LOG` | ops log path (JSON lines) |
| `VAULT_OFFLINE`, `VAULT_HTTP_TIMEOUT`, `VAULT_REVIEW_SAMPLE_PCT`, `VAULT_ROOT` | citation check |
| `VAULT_USER_KEY`, `VAULT_USER_KEY_PASSPHRASE` | user Ed25519 signing key (PKCS8 PEM, 0600; default `~/.config/lattice-vault/user_ed25519.key`); create with `vault keys init-user` |
| `VAULT_CONFIG_DIR` | config dir for the default key and anchors (default `$XDG_CONFIG_HOME/lattice-vault`) |
| `VAULT_ANCHOR_PATH2` | optional second anchor location (e.g. removable drive); written and checked in addition |
| `VAULT_ANCHOR_PATH` | external chain-head anchor for the `VAULT_DB` vault (default `<config dir>/anchors/<id>.anchor.json`) |
| `VAULT_VERIFY_SAMPLE_K`, `VAULT_VERIFY_SEGMENT`, `VAULT_FULL_VERIFY_DAYS` | open-time sampled verification (default 4 segments × 64 rows) and the "run doctor" nudge (default 30 days) |
| `VAULT_ALLOW_NONTTY` | **test harness only**: honoured only with `VAULT_TEST_HARNESS=1` and a `VAULT_USER_KEY` under the temp dir (set by `testutil.py`) |

## Status and limits
Implemented vs planned is tracked per decision in [docs/adr/](docs/adr/).

**Multi-device sync — experimental, CLI-only, file-based** (`sync.py`, [docs/sync.md](docs/sync.md)):
`./vault sync-pair` registers another device of the owner, `./vault sync-export --out FILE` writes new
events to a `.vaultsync` package, and `./vault sync-import FILE` verifies and merges one. You move the
package yourself; there is **no network transport and no automatic/background sync**. Per-device
signatures and key (`keys.db`/KEK) synchronization are **not built yet**, so do not rely on it for real
data across several devices. Incoming human-only events are applied only with a valid signature by a user key
already registered on the receiving vault; everything else (unsigned, forged, unknown-key, `key.*`, `user:*`
content, schema-invalid) is held in quarantine (`./vault sync-quarantine`); `./vault sync-quarantine --release`
re-verifies held events later (e.g. after the key is registered) and applies only those that now pass.

Human-only events (approve/reject/revert/redact/shred, …) are signed with a user Ed25519 key
(`./vault keys init-user`), and a signed external anchor of the chain heads is written after each commit; see
[SECURITY.md](SECURITY.md) for what this does and does not protect. Not built: network/automatic sync, per-device
(package) signing and key sync, OS-keychain key storage. Known limits are in
[SECURITY.md](SECURITY.md). Changes: [CHANGELOG.md](CHANGELOG.md).

## Türkçe özet
Lattice Vault, tek kullanıcılı, yerel, yalnız-ekleme (append-only) bir hafıza kasası prototipidir. AI
asistanlar MCP üzerinden okur ve yalnız *öneri* yazar; doğrulanmış içerik yalnız insan onayıyla oluşur.
Arama Türkçe karakter katlamalıdır (`ı/i`, `ş/s` …). **Prototiptir; üretimde kullanmayın.** Bağımsız bir güvenlik denetiminden **geçmemiştir**; gerçek kişisel veriyi
yalnızca başarılı bir geri yükleme tatbikatından (restore drill) sonra saklayın. Çok cihazlı senkronizasyon
deneysel, yalnızca CLI ve dosya tabanlıdır (`.vaultsync`); ağ/otomatik senkronizasyon yok, cihaz başına
imza ve anahtar senkronizasyonu henüz yok.

## License
Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

---

<sub>Lattice Labs · Created by Kerem Talha Oral · Licensed under Apache-2.0</sub>
