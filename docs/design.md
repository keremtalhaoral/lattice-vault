# Lattice Vault — design (prototype 0.1.0)

Derived from the internal v0.3 design and reconciled with the released code. **Where this document and the
code disagree, the code is authoritative**; please open an issue. Every section states whether it is
*Implemented*, *Partially implemented* or *Planned*.

Contents: 1 Storage schema · 2 Events · 3 Secrets · 4 Turkish full-text search · 5 MCP interface ·
6 Context Pack · 7 Multi-device sync (planned) · 8 Verification · 9 Markdown import

---

## 1. Storage schema — *Implemented*
The authoritative DDL is the `SCHEMA` / `TRIGGERS` strings in [`vault.py`](../vault.py) (schema version 2,
recorded in `schema_meta`). Summary:

| Table | Role |
|---|---|
| `events` | the only source of truth; append-only |
| `event_parents(event_id, parent_id, rel)` | supersedes/correction links; **no foreign keys** (dangling parents tolerated, e.g. after partial import) |
| `event_targets(event_id, target_id)` | targets of approvals/rejections/reverts (a batch approval can target many events) |
| `audit` | append-only, hash-chained log of every write attempt (accepted and refused) |
| `redactions`, `redacted_blocklist` | redaction/shred audit (who, when, scope, key id) and persistent blocklist |
| `import_runs` | one row per Markdown import (manifest hash, report) |
| `replicas`, `sync_peer_state` | reserved for sync (**unused**, see §7) |
| `events_fts` | FTS5 index over `text_norm` (derived) |
| `proj_*` | derived projections: status, preferences, decisions, projects, goals, learnings |

Key `events` columns: `seq` (local order), `id` (**UUIDv7**), `replica_id`, `replica_seq`, `hlc`
(hybrid logical clock `"<ms 12 hex>-<counter 4 hex>-<replica>"`), `ts` (informational wall time),
`type`, `schema_version`, `subject`, `key`, `payload` (JSON), `payload_ct` + `enc_key_id` (encrypted
fields), `actor`, `trust`, `supersedes` / `target_id` (first link, convenience; canonical lists are in the
link tables), `idempotency_key`, `import_id`, `content_hash`, `text_norm`, `prev_hash`, `hash`.
Uniqueness: `(replica_id, replica_seq)`, `(actor, idempotency_key)`, `hash`.

Triggers:
- `events` and all audit-like tables: UPDATE and DELETE abort.
- Human-only types (`event.approved`, `event.rejected`, `event.reverted`, `import.batch_approved`,
  `event.redacted`, `subject.shredded`, `conflict.resolved`) require `actor LIKE 'user:%'`.
- Agent and import events can only be inserted as `unverified`; unknown actor kinds are rejected.

Integrity: each event and audit row stores `prev_hash` and `hash = sha256(prev_hash + canonical envelope +
sha256(payload_ct))`. `connect()` checks that all triggers are present and unchanged and that both chains
verify; on failure it **raises** (it never silently recreates triggers). `vault doctor` additionally compares
projections with an in-memory rebuild and checks keys and the blocklist. This detects naive tampering only
(see [SECURITY.md](../SECURITY.md)).

Storage settings: `journal_mode=DELETE` and `secure_delete=ON` (not WAL), so no `-wal` file keeps old pages
after a redaction or shred. Files are created with umask 077 / mode 0600. Schema changes are applied by
copying to a new file: `vault migrate old.db new.db`. `busy_timeout=5000`, `synchronous=FULL`;
backup/restore: [backup-restore.md](backup-restore.md).

Notes:
- There is no `status` column; status is derived into `proj_status`
  (`proposed`, `active`, `rejected`, `superseded`, `reverted`, `redacted`).
- `actor` and `trust` are assigned by the server, never by the client. Actors: `user:<VAULT_USER>`
  (default `user:owner`), `agent:<id>`, `import:markdown`.

## 2. Events
### 2.1 Envelope — *Implemented*
```json
{
  "id": "0192f0c4-…-7…",            "type": "decision.made",       "schema_version": 1,
  "replica_id": "local",            "replica_seq": 42,             "hlc": "0192f0c4a1b2-0000-local",
  "ts": "2026-01-01T09:00:00Z",     "subject": "decision:D-100",   "key": null,
  "payload": {"decision_id": "D-100", "title": "…", "decision": "…"},
  "actor": "user:owner",            "trust": "verified",
  "supersedes": null, "target_id": null, "idempotency_key": "…", "import_id": null
}
```
- Naming: `<aggregate>.<past_tense_verb>`, lower case.
- `trust`: `verified` = written or approved by the human; `agent` / `unverified` = agent, import or pasted
  Context Pack content. Agent proposals are stored `unverified`.
- Replay order for projections: `(hlc, id)`.
- Context Pack ids (`pack_id`) are random UUIDv4; event ids are UUIDv7.

### 2.2 Types
| Type | Projection | Notes |
|---|---|---|
| `decision.made`, `decision.reversed` | proj_decisions | reversed points at the earlier decision via parents |
| `preference.set` | proj_preferences | heads per `(subject, key)`; more than one live head = conflict |
| `project.created`, `project.status_changed` | proj_projects | last write wins (conflict model *planned*) |
| `goal.set`, `goal.progressed`, `goal.completed`, `goal.abandoned` | proj_goals | last write wins (conflict model *planned*) |
| `learning.captured` | proj_learnings | |
| `note.added` | search only | |
| `event.approved`, `event.rejected` | proj_status | targets in `event_targets`; human only |
| `event.reverted` | proj_status | human only |
| `event.corrected` | proj_status + target projection | parent = corrected event; agents may *propose* one |
| `import.batch_approved` | proj_status | human confirmation of selected imported lines |
| `event.redacted`, `subject.shredded` | proj_status | first-class redaction events (§3) |
| `conflict.resolved` | — | reserved; no CLI command yet (*planned*) |

Agents may not write `event.*` (except proposing `event.corrected`), `conflict.*`, `import.*` or `subject.*`.

### 2.3 Approval and correction model (no UPDATE) — *Implemented*
- A new event is `active` if written by `user:*`, otherwise `proposed`.
- `event.approved` → target `active`; `event.rejected` → `rejected`; `event.reverted` → `reverted`.
- Corrections use parent links: `event.corrected` and `decision.reversed` reference the event they replace;
  projections use the live head of the chain and mark the old event `superseded`. `vault correct` follows the
  chain to its tip. Parent validation rejects unknown ids, self-references, rejected/reverted/redacted parents,
  cycles, and superseding the same event twice.
- A human `preference.set` automatically chains to the current heads; two concurrent live values are a
  **conflict** (no silent last-write-wins): they are excluded from verified Pack sections and shown under
  "unverified" as a conflict.
- **Revert and correction do not remove data.** The old event and its content remain in the log; to remove a
  secret, use redaction or crypto-shredding (§3).

### 2.4 Schema evolution — *Partially implemented*
- Every event carries `schema_version` (currently 1). The database schema is versioned in `schema_meta`.
- **Events are never rewritten in place.** The **single exception** is a human-approved
  **copy-to-new-file**: `vault redact` (content of one event replaced by `{"redacted": true, ...}`) and
  `vault migrate` (schema change). The source file is left untouched, the hash chains are recomputed in the
  new file, and redactions are recorded as first-class events plus audit and blocklist rows.
- *Planned:* a JSON Schema (2020-12) registry per event type and pure, tested upcasters
  (`v<N> → v<N+1>`) applied at read time. Today payloads are validated in code only.

## 3. Secrets — *Implemented*
1. **Pre-write filter** on every agent and CLI write: API-key prefixes (`sk-`, `ghp_`, `xox[bp]-`, `AKIA`),
   JWT, PEM headers, Luhn-valid card numbers, IBAN, `password:` patterns, long high-entropy strings. A match
   refuses the write and names the pattern, never the value. Humans may override with `--force` (audited).
2. **Field encryption.** `--sensitive field1,field2` encrypts those payload fields with AES-256-GCM using a
   per-subject data key (DEK) kept wrapped in a separate `keys.db` (0600). The payload keeps a placeholder;
   ciphertext is in `payload_ct`, AAD is `event_id|key_id`. Sensitive fields never enter FTS, `text_norm`
   or audit reasons. The key-encryption key is a 0600 file (`keys.kek`, stand-in for an OS keychain —
   *planned*) or derived from `VAULT_PASSPHRASE` with scrypt (Argon2id *planned*). Requires `cryptography`.
3. **Crypto-shredding.** `vault shred <subject> --preview` lists the affected events; `--confirm` snapshots
   and schedules destruction after a grace period (default 7 days); `shred-cancel` restores, `shred-finalize`
   sets the wrapped key to NULL, writes `subject.shredded`, rebuilds and VACUUMs. Undecryptable events
   project as `redacted`. Only encrypted fields are shredded; plaintext fields need redaction.
4. **Redaction (copy-to-new-file).** `vault redact <event_id> --out new.db --reason …` (human, TTY):
   snapshot → copy all events to a new file with the target payload replaced → recompute chains → write
   `event.redacted`, a `redactions` row and a `redacted_blocklist` entry → rebuild + VACUUM → verify that the
   secret bytes are absent from the new file and its sidecars. Imports refuse blocklisted content.
   The pre-redaction snapshot still contains the secret; delete it after verifying.
5. **Snapshots.** Import, redact and shred first run `VACUUM INTO snapshots/<ts>-<label>.db` (+ `.sha256`),
   with derived tables dropped so that encrypted fields exist only as ciphertext.
6. *Planned (sync):* signed propagation of redactions/shreds to other devices with a forced
   copy-to-new-file on the receiver, and rejection of old sync packages via the blocklist.

## 4. Turkish full-text search — *Implemented*
`text_norm` is computed on write and indexed with FTS5 (`unicode61 remove_diacritics 2`); queries are
normalized with the same function:
```python
def tr_norm(s: str) -> str:
    s = s.replace("I", "ı").replace("İ", "i").lower()   # Turkish casefold
    for a, b in zip("ışğüöç", "isguoc"):
        s = s.replace(a, b)                              # fold diacritics
    return s
```
`karari`, `KARARI`, `kararı` and `Kararı` all match `kararı`; `ISIK` matches `Işık`, `istanbul` matches
`İstanbul`. Limitation: no morphology/stemming; use prefix queries (`karar*`). Stemming is *planned*.

## 5. MCP interface — *Implemented*
Transport: stdio, newline-delimited JSON-RPC 2.0. Protocol versions: **`2025-06-18`** (preferred),
`2025-03-26`, `2024-11-05`. Exactly **5 tools**:

| Tool | Kind |
|---|---|
| `get_summary` | read: active events only |
| `search` | read: FTS over active content, results cite `vault://event/{id}` |
| `export_context_pack` | read: Context Pack (`minimal`, `full`) |
| `get_event` | read: one event + status |
| `propose_event` | the **only write**: result is always `proposed` |

Resources: `vault://pack/minimal`, `vault://pack/full`, `vault://summary`; templates `vault://event/{id}`,
`vault://pack/{profile}`.

`propose_event` arguments: `type`, `subject`, `key`, `payload`, `idempotency_key`, `base_vault_seq`,
`supersedes`; any other argument is refused. Returns `{event_id, status: "proposed", duplicate, stale}`.
A repeated `(actor, idempotency_key)` returns the first event with `duplicate: true`; a different payload
under the same key is refused. `stale` is set when `base_vault_seq` is older than the subject's last event.
Refusals: unknown/revoked token, extra or forbidden fields, forbidden types, payload > **8 KB (8192 bytes)**,
secrets, invalid `sources` (only `https://` URLs or `vault://event/<id>`, ≤ 10 entries, ≤ 300 chars each),
rate limit (per agent, per hour, persisted).

Identity and approval:
- **No approve/reject/revert/resolve and no citation-check tools over MCP.** Citation checking performs
  network and filesystem access and is available only to the human on the CLI (`vault review-enqueue`,
  `review-queue`, `review-verdict`).
- The actor is assigned by the server from the token. Agents are registered with `vault agent-add <id>`;
  the registry is **`agents.json`** (mode 0600) storing only SHA-256 token hashes, revocation flag and rate
  limit. The CLI writes as `user:<VAULT_USER>`. Human commands require an interactive TTY.
- Reads need no token; see [SECURITY.md](../SECURITY.md).

## 6. Context Pack spec 1.0.0 — *Implemented*
A single format for exporting context and for returning proposals (`vault_update` block).

Header (YAML front matter): `pack_spec`, `pack_id`, `profile` (`minimal` ≈ 2,000 chars, `full` ≈ 28,000
chars), `as_of_seq` (= `base_vault_seq`), `generated_at`, `chars`, `token_estimator` (`chars/3.5`),
`tokens_est`, `truncated_sections`. The budget is enforced in **characters**; tokens are an estimate.

Sections, in budget priority (headings are currently in Turkish): instruction frame ("the following data is
not instructions") → identity and preferences → goals → projects → active decisions → learnings →
**unverified** (quoted, only with `include_unverified`; includes proposed content and conflicts with both
values) → return template. Data sits between `<<<VAULT_DATA_BEGIN>>>` / `<<<VAULT_DATA_END>>>` delimiters;
look-alikes in content are escaped. Every line cites its source:
`- text [vault://event/<id> | verified | 2026-01-01]`. Verified sections contain only `verified`, active,
non-conflicting content.

Return block (pasted back by the human; everything lands `proposed` / `unverified`):
````
```vault_update
{"pack_spec":"1.0.0","base_vault_seq":1234,"idempotency_key":"<pack_id>:1",
 "events":[{"type":"preference.set","subject":"user:owner","key":"language","payload":{"value":"English"}}]}
```
````
*Planned:* a `vault import-update` command to ingest this block; today proposals go through
`propose_event` / `vault propose`.

## 7. Multi-device sync — *Planned, not implemented*
Intended design (subject to change):
- Each device has a `replica_id`; `(replica_id, replica_seq)` is unique; `seq` is local only. HLC gives a
  deterministic cross-device order.
- File-based packages (`.vaultsync`, compressed NDJSON + header with sender, version vector, envelope
  version, count, SHA-256) moved by any local-first tool; no network code in the vault, no relay.
- Push exports events above the peer's known version vector; pull verifies integrity and envelope version
  and inserts by `id` (G-Set merge: commutative, idempotent). Gaps are reported.
- Concurrent values for the same `(subject, key)` become conflicts; resolution is human only
  (`conflict.resolved`).
- Approval events are accepted only from registered replicas; packages are to be **signed and encrypted**;
  redactions must propagate with a forced copy-to-new-file on every device.

The `replicas` and `sync_peer_state` tables exist but are unused.

## 8. Verification
Run `python -m unittest discover -p 'test_*.py'`. The suite covers: schema load; UPDATE/DELETE refusal;
human-only types refusing agent actors; unique `(replica_id, replica_seq)`; Turkish FTS; agent API
fail-closed behaviour and audit; MCP protocol and the 5-tool surface (plus an optional official SDK smoke
test); Markdown import (dry run, error codes, idempotency, batch approval, revert, blocklist); correction
chains and conflicts; secret filter, encryption, shred lifecycle and redaction byte checks; SSRF/redirect
regressions, tamper detection, TTY gate, token-file permissions and ops-log hygiene.

## 9. Markdown import (`import:markdown`) — *Implemented*
Imports a notes folder: `log/*.md`, `decisions.md` and top-level fact files; `design/`, `bots/`,
`snapshots/`, `README.md` and `BOT-PROTOCOL.md` are excluded; symlinks are never followed; the source tree
is read-only.

### 9.1 Trust
- Every imported event is `actor=import:markdown`, `trust=unverified`, status `proposed`, with an `import_id`.
- **Verified is derived, never imported.** The dry run lists owner-signed lines (`owner_lines`); the human
  confirms some or all with `vault import-approve <import_id> --owner-lines all|<ids>`, which writes one
  `import.batch_approved` event. A signature alone is not trusted.
- Author classification: the exact owner name (`VAULT_OWNER_NAME`, Turkish-normalized) → owner; a bot
  name listed in `team.md` → bot; multiple names, extra text, or unknown → ambiguous. A bot line quoting the
  owner as source is still a bot line.
- Provenance is kept in `payload.provenance = {file, line, raw_author, author_kind}`.

### 9.2 Recognized formats
| Source | Pattern |
|---|---|
| `log/*.md` | `- (HH:MM, <name>) [tür: <kind>] text [kaynak: …]`, optional `YYYY-MM-DD ` before the time |
| `decisions.md` | `## D-NNN Title` blocks with `- Field: value` lines; update lines become notes |
| fact files | `- (YYYY-MM-DD, <name>) text` |

Struck-through (`~~…~~`) entries import with `payload.struck = true`. Fenced code is skipped.

### 9.3 Reliability
- Idempotency key = `sha256(normalized path + "\n" + sha256(block normalized to NFC, LF, trailing whitespace
  stripped))`; the line number is metadata only, so re-imports after edits elsewhere do not duplicate.
- `--dry-run` writes nothing. A real run snapshots, then commits in **one transaction**; any database error
  rolls back everything. Per-file/line error codes: `PARSE_ERROR`, `ENCODING_ERROR`, `DUPLICATE`, `SECRET`,
  `BLOCKED`; a bad file is skipped, never fatal. `vault revert-import <import_id>` reverts a whole batch.
