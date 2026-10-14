# ADR 0015: Context Pack v2 — measured token estimates, vault_update import, versioned output

Status: Proposed (implemented on `feat/context-pack-v2`; Security and Data Systems review requested)

## Context
`vault export-context` (lattice-context/v1) estimated tokens as chars/4, which badly under-counts Turkish text on
some tokenizers, so `--max-tokens` could be exceeded. AI answers carried a `vault_update` template in YAML that the
human had to retype into `vault propose`, one event at a time, with an agent token. Bullets did not say who wrote a
fact, and the format had no explicit marker for withheld (redacted/shredded) content. Shredded subjects' *plaintext*
fields (only sensitive fields are encrypted) were still exported.

## Decision
### 1. Token estimation (`tokens.py`)
* If the optional `tiktoken` package is installed, count with the real `o200k_base` and `cl100k_base` encodings and
  use the larger. Not a runtime dependency; falls back to the heuristic if encodings cannot load (offline).
* Otherwise a linear heuristic over six features (ASCII words / ASCII letters / non-ASCII words / non-ASCII letters /
  digits / punctuation), one coefficient set per encoding, default = the larger of the two (conservative).
* Coefficients were fitted on half of a synthetic, deterministic Turkish + English corpus (`tools/token_corpus.py`,
  120 samples: Turkish prose, English prose, mixed, pack-style bullets, YAML, ids/numbers; no personal data) and
  checked on the other half (held-out mean absolute error: 6.0 % vs o200k_base, 7.4 % vs cl100k_base). Reference
  counts are stored in `testdata/token_reference.json` so CI checks the error bounds without tiktoken;
  `tools/calibrate_tokens.py` re-measures (needs tiktoken).
* Budgets compare `budget_tokens()` = estimate × 1.15 (safety margin) against `--max-tokens`.
* Claude and Gemini tokenizers are not public in a form we can bundle; numbers here are *GPT-family estimates*. The
  header says so; the 15 % margin is a hedge, not a guarantee.

Measured on the whole corpus (signed mean / mean absolute / max absolute relative error, %):

| method | vs o200k_base (all) | vs cl100k_base (all) | Turkish prose vs o200k | Turkish prose vs cl100k |
|---|---|---|---|---|
| chars/4 (v1) | +3.2 / 30.9 / 100 | −10.2 / 41.0 / 100 | −9.4 / 9.4 / 20.0 | −37.6 / 37.6 / 43.9 |
| chars/3.5 (`vault pack`) | +17.8 / 34.2 / 127 | +2.5 / 40.5 / 127 | +3.4 / 5.2 / 13.9 | −28.8 / 28.8 / 36.8 |
| heuristic (o200k fit) | +2.7 / 6.0 / 21.1 | — | +2.6 / 6.5 / 17.1 | — |
| heuristic (cl100k fit) | — | +4.0 / 7.6 / 33.3 | — | +1.4 / 5.9 / 12.3 |
| heuristic default (max) | +24.4 / 24.6 / 73.2 | +4.1 / 7.5 / 33.3 | +47.4 (over) | +1.4 / 5.9 / 12.3 |

With the 15 % margin the default under-counts 0/120 samples for o200k_base and 3/120 for cl100k_base. The default
over-counts for o200k models by design (it must cover both). The corpus is synthetic with a limited vocabulary; real
text will differ, which is another reason for the margin.

### 2. `vault import-update` (`vault_update.py`)
* Input: AI output (file or stdin) containing **exactly one** fenced block tagged `vault_update` (```` ``` ```` or
  `~~~`, any fence length; the closing fence must match). The body is **strict JSON** (no YAML parser in stdlib):
  duplicate keys, NaN/Infinity, unknown top-level or entry fields are refused. Limits: 64 KiB block, 25 entries.
* Each entry: `type, subject, key?, payload, supersedes?, cites?`. Only content types are accepted
  (`IMPORT_TYPES`: preference, decision, goal, project, learning, note). `subject.*`, `key.*`, `event.*` (incl.
  approvals and corrections), `conflict.*`, `import.*`, `attestation.*` and every signed/human-only type are refused;
  subjects `event:*` / `key:*` too. Fields `actor, source, trust, status, approved` are refused anywhere.
* Same content rules as the agent API: per-type schema, `sources` restrictions, payload size, instruction-like text,
  secret filter (no `--force` on this path). `supersedes` / `cites` must be full ids; `supersedes` must exist.
* **Trust: content written by an AI is unverified.** Entries are appended with actor `agent:<name>` (default
  `agent:pasted-ai`, `--agent` to name the assistant) and trust `unverified` → status `proposed`. The user signing key
  is disabled for this command. Only the user's own signed `vault approve` makes an entry verified. What the human
  confirms at import is "stage these proposals", not "approve these facts".
* **Semi-automatic by default:** validate everything → preview (new / already imported / conflict, with the current
  preference value next to the proposed one) on stderr → confirmation typed on the controlling terminal
  (`/dev/tty`, so piping the AI output on stdin still works). No terminal → refused. `--dry-run` previews only.
  `--yes` skips the prompt (automatic mode); entries still land unverified, so it adds no trust.
* **Fail closed, atomic:** any invalid entry refuses the whole block; writes happen in one transaction, rolled back
  on any error. Refusals are audited (`import_update`), without echoing secret matches.
* **Idempotent:** each entry's idempotency key is `vu2:` + SHA-256 of its canonical (type, subject, key, payload,
  supersedes), scoped to the actor. Re-importing the same block (any order, any block key) writes nothing; same key
  with different stored content is a conflict and refuses the block.

### 3. Output format `context-pack/2` (`context_pack.py`)
* Default of `vault export-context`; `--format 1` keeps lattice-context/v1 byte-for-byte (except the shred rule below).
  The format is named in the first front-matter line, so consumers can branch on it.
* Front matter adds `counts {verified, unverified, withheld{...}}` and `token_estimate {method, tokens,
  safety_margin_percent, note}` (the stated estimate never under-states the pack itself; computed to a fixed point).
* Bullets: `- [V]|[U] <text> — ev:<last 8> · <date> · <author>[ · <status>][ · supersedes ev:<..>]`.
  `[V]` = approved by the user; `[U]` = not approved. Sections in fixed order Preferences, Goals, Projects,
  Decisions, Learnings, Notes, Other; items by (HLC, id). Infrastructure events (`key.*`, `attestation.*`,
  `subject.*`, `event.*`, `conflict.*`, `import.*`) never appear.
* Withheld items keep their marker and id but no text: `[redacted]`, `[undecryptable]`, `[shredded]` and
  `[shred pending]`. Any subject with an applied shred, or a scheduled one not cancelled, is withheld entirely —
  including non-sensitive plaintext fields and the subject name — in v1 and v2.
* Over budget: unverified items go first (oldest first, largest section first), then approved ones.
* The update template is one line of JSON with `"format": "vault_update/2"`.

### 4. Follow-ups after Security review
* **Agent read surfaces.** `agent_api.export_context_pack` (MCP tool and `vault://pack/*`) renders through
  `context_pack.export` instead of the projection-based `vault.pack`: sensitive fields stay `[encrypted]`,
  shred-affected subjects are withheld, `max_chars` is enforced (MCP minimum 2000). `get_summary`, `search` and
  `get_event` also omit subjects with a pending or applied shred. `vault pack` remains a human CLI command.
* **Shred withholding source of truth.** `context_export.shred_states` is the union (fail closed) of the keystore
  state (`pending_destroy`/`destroyed`), `shredding.plan()` decisions, and, for keys not held locally, the log in
  `(hlc, id)` order where only a cancel that passes `shredding._valid` counts.
* **Approved agent proposals** (status active, decided by a `user:` actor) count as approved facts in packs.
* **Import path:** revoked registered names refused; rate limit shared with `propose_event` (audit action
  `propose`, reason `via:import-update`); `key` without control characters; preview and messages strip C0/C1/bidi
  characters, never echo unknown field names/values, and filter secret patterns (`[filtered]`); preview shows
  `[encrypted]`/`[withheld]` for sensitive or shred-affected current values; `supersedes` only targets unverified
  proposals; deep nesting, huge integers and non-finite numbers are refused before preview.

## Consequences
* Packs are larger in the estimate (more conservative), so `--max-tokens` trims a little earlier, especially for
  Turkish text.
* Pasted AI updates no longer need an agent token, but they cannot do more than a token-holding agent: same rules,
  same unverified landing, narrower type allowlist.
* The MCP pack format changes from `pack_spec 1.0.0` to `context-pack/2`.

## Deferred
* Corrections (`event.corrected`) via import — refused for now; would need a preview of the corrected field.
* Real Claude/Gemini counts (no bundled tokenizer); a per-target-model margin.
* Calibration on real (consented, non-personal) text instead of the synthetic corpus.
* A YAML subset for hand-written blocks; JSON only for now.
