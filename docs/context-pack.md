# Context Pack export (`vault export-context`, format `lattice-context/v1`)

MCP-fallback for LLMs without MCP (ChatGPT/Gemini/DeepSeek paste-in) and for humans. Complements, and does not
replace, `vault pack` / MCP `export_context_pack` (spec 1.0.0), which are unchanged.

```
vault export-context [--out FILE|-] [--profile minimal|full] [--since DATE] [--types t1,t2]
                     [--max-tokens N] [--include-unverified] [--fixed-time ISO]
```

* **Content.** Only approved facts: `proj_status.status = active` and effective trust `verified` (incl. batch-approved
  imports). Proposed, rejected, reverted, superseded and meta events are never in the approved section.
  `--include-unverified` adds a separate, clearly labelled "Unverified (NOT approved)" section (active non-verified
  and proposed events; never rejected/reverted). `minimal` drops Learnings.
* **Secrets.** The exporter never decrypts. `{"$enc": key_id}` fields render as `[encrypted]`, redacted/blocklisted
  events as `[redacted]`, and every text passes the shared secret filter (`SECRET_PATTERNS` + Luhn cards) so
  `--force`-stored secrets render `[redacted]`. Data delimiters are neutralised (`vault.esc`) and code fences broken.
* **Corrections.** `event.corrected` chains are folded onto the root; the bullet shows the latest value, the latest
  correction's id and `supersedes <root id>`.
* **Format.** YAML front matter (`format, generated_at (UTC), vault_head_hash, vault_seq, event_count, filters,
  profile, source, token_estimator, truncated[_sections], instructions_for_ai`), hand-emitted with every string as an
  ASCII-escaped JSON double-quoted scalar (valid YAML, no PyYAML). Body: `# Context Pack`, sections per type, bullets
  `text `ev:<last 8 of id>` (date)`, then a ```` ```vault_update ```` template (same keys as `pack`'s return block,
  in YAML) that the human feeds to `vault propose`, landing as proposed/unverified.
* **Determinism.** Ordering is section name then `(hlc, id)`; `generated_at` is the only varying field and is pinned
  by `--fixed-time` or `LATTICE_FIXED_TIME`.
* **Budget.** tokens ≈ chars/4. Over `--max-tokens`, the oldest item of the currently largest section is dropped
  until it fits; counts appear under `truncated_sections`. Errors if even the skeleton does not fit.
