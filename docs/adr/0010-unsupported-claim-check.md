# ADR 0010 (D-010): Unsupported-claim (citation) check
- **Status:** Accepted
- **Implementation:** Partially implemented — human CLI only; not exposed over MCP

## Context
Claims written by agents should be traceable to a resolvable source, and a sample should be reviewed by a
human.

## Decision
An automatic citation check (each claim or agent record should cite `vault://event/<id>`, an `https://`
URL, or a file inside the vault root) plus a configurable sample (`VAULT_REVIEW_SAMPLE_PCT`, default 10%)
queued for human review. `https` sources are checked online: 404/410 or unreachable → flagged;
403/blocked/network error/redirect → human queue; `VAULT_OFFLINE=1` disables network access. Verdicts are
human only. Network checks allow only port 443 and public addresses after DNS resolution, never follow
redirects, and confine file references to the vault root.

## Alternatives
Exposing the check as MCP tools (rejected: gives agents an SSRF and filesystem-probing primitive).

## Consequences
Run via `vault review-enqueue`, `review-queue`, `review-verdict`. Residual risk: DNS rebinding between
validation and connection (see SECURITY.md).
