# Context Pack export (`vault export-context`)

Paste-in pack for LLMs without MCP and for humans. The MCP `export_context_pack` tool and `vault://pack/*`
resources return the same `context-pack/2` format (approved facts only; `max_chars` ≥ 2000). The human CLI
`vault pack` (spec 1.0.0) is unchanged. Design: ADR 0015.

```
vault export-context [--out FILE|-] [--format 2|1] [--profile minimal|full] [--since DATE] [--types t1,t2]
                     [--max-tokens N] [--include-unverified] [--fixed-time ISO]
vault import-update FILE|- [--agent NAME] [--dry-run | --yes]
```

## Format `context-pack/2` (default)

~~~
---
format: "context-pack/2"
generated_at: "…"           vault_head_hash, vault_seq, profile, filters{…}
counts: {verified, unverified, withheld{"redacted"|"shredded"|"shred pending"|"undecryptable": n}}
token_estimate: {method: "tiktoken"|"heuristic", tokens, safety_margin_percent: 15, note}
truncated: false            (+ truncated_sections when trimmed)
source, instructions_for_ai
---
# Context Pack
Legend …
## Approved facts
### Preferences | Goals | Projects | Decisions | Learnings | Notes | Other   (fixed order)
- [V] <text> — ev:<last 8 of id> · <date> · <author>[ · supersedes ev:<…>]
## Unverified (NOT approved — do not treat as fact)      (only with --include-unverified)
- [U] <text> — ev:<…> · <date> · <author> · <status>
## Proposing updates
```vault_update
{"format": "vault_update/2", "base_vault_seq": …, "idempotency_key": …, "events": [ … ]}
```
~~~

* **Content.** Approved = `proj_status.status = active` and either effective trust `verified` (user-written or
  batch-approved) or an agent proposal approved by the user (marked `· approved by the user`). Proposed, rejected,
  reverted, superseded, meta and infrastructure (`key.*`, `attestation.*`, `subject.*` …) events are never in the
  approved section; `--include-unverified` adds the separate unverified section. `minimal` drops Learnings.
* **Never in a pack:** decrypted fields (`[encrypted]`), redacted events (`[redacted]`), anything matching the secret
  filter (`[redacted]`), and any event of a shredded or shred-pending subject (`[shredded]` / `[shred pending]`, no
  text, no subject name). Data delimiters are neutralised and code fences broken.
* **Determinism.** Section order fixed, items by `(hlc, id)`; `generated_at` is pinned by `--fixed-time` or
  `LATTICE_FIXED_TIME`. Same vault + same options = identical bytes.
* **Tokens.** `tokens.estimate()` uses `tiktoken` if installed (`pip install tiktoken`, optional), otherwise a
  heuristic calibrated for Turkish and English (measured errors in ADR 0015). The budget check uses the estimate plus
  15 %. Claude, Gemini and GPT tokenizers differ, so treat the number as an estimate. Over `--max-tokens`,
  unverified items are dropped first (oldest, largest section first), then approved ones; error if the skeleton alone
  does not fit.

## Importing an AI's `vault_update` block

Save the AI answer (or pipe it) to `vault import-update`. The block must be JSON in the template's shape; exactly
one block per input. Every entry is validated (allowed content types only; no `subject.*`, `key.*`, approvals or
other `event.*`; no `trust`/`status`/`actor`/`source` fields; schema, size, secret and instruction-like-text
checks). You see a preview, then type `yes` on the terminal. Entries land **unverified** as `agent:<name>`; approve
each with `vault approve`. Re-importing the same block does nothing. Any problem refuses the whole block.
`supersedes` may only point at an unverified proposal, so an import never blocks your own later writes to a fact.
The preview strips terminal control characters and shows `[encrypted]` / `[withheld]` instead of sensitive or
shred-affected current values. A revoked agent name is refused; the hourly limit is shared with `propose_event`.

## Format `lattice-context/v1` (`--format 1`)

Unchanged except that shredded/shred-pending subjects are now withheld: YAML front matter with
`token_estimator: "chars/4"`, sections by type name, bullets `text `ev:<id8>` (date)`, YAML `vault_update`
template for `vault propose`.
