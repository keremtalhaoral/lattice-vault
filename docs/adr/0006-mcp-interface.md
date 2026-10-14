# ADR 0006 (D-006): MCP interface — reads plus a single proposal tool, no approval over MCP
- **Status:** Accepted
- **Implementation:** Implemented

## Context
AI clients need read access and a way to suggest additions, but must never be able to make anything
verified on their own.

## Decision
MCP over stdio (protocol `2025-06-18`, also accepting `2025-03-26` and `2024-11-05`) with exactly five tools:
`get_summary`, `search`, `export_context_pack`, `get_event` (reads) and `propose_event` (the only write;
result is always `proposed`). Resources expose Context Packs, the summary and single events. There are no
approve/reject/revert/resolve tools over MCP; those are human CLI commands requiring an interactive TTY.
The server assigns `actor` from the agent token; database triggers additionally require `user:*` for
human-only event types. Citation-check functionality (network and filesystem access) is **not** exposed
over MCP; it exists only as human CLI commands (`review-enqueue`, `review-queue`, `review-verdict`), so no
review-queue tool is reachable by agents.

## Alternatives
Exposing approval to trusted agents (rejected: prompt injection); exposing citation checks to agents
(rejected: unauthenticated SSRF and filesystem-probing surface).

## Consequences
Every agent contribution needs a human step. Reads are not authenticated (local single-user scope).
