# ADR 0007 (D-007): Security requirements for agent writes and secrets
- **Status:** Accepted
- **Implementation:** Partially implemented (see "Not implemented")

## Context
Agents may be buggy or prompt-injected; users may paste secrets; vault content may itself contain
injection attempts.

## Decision (implemented)
- All agent writes are `proposed` / `unverified`.
- Agent authentication: per-agent random tokens, stored only as SHA-256 hashes in `agents.json` (0600);
  token file (`VAULT_AGENT_TOKEN_FILE`, 0600, owned by the user) preferred over environment variables;
  revocation; fail-closed on any authentication or validation error.
- Refusals: extra/forbidden arguments, forbidden types (`event.*` except proposing `event.corrected`,
  `conflict.*`, `import.*`, `subject.*`), payload > 8192 bytes, detected secrets, invalid `sources`,
  idempotency-key reuse with a different payload, persistent per-agent hourly rate limit.
- Read paths use a read-only database connection. Every attempt (accepted or refused) is written to the
  hash-chained `audit` table, never including the token.
- Context Packs: data delimiters, "data is not instructions" frame, escaping of delimiter look-alikes,
  unverified content quoted and separated; proposals are NFKC-normalized and refused if they contain known injection markers.
- Secrets: pre-write filter on every write path; AES-256-GCM per-subject field encryption with
  crypto-shredding; human-approved redaction to a new file with a persistent blocklist.
- Human commands require an interactive TTY; files are created 0600.
- Human-only events are signed with a user Ed25519 key, and a signed external anchor holds the chain heads
  (ADR 0011).

## Not implemented
OS-keychain key storage, Argon2id KDF, device keys / signed sync packages, separate OS account for the vault. See [SECURITY.md](../../SECURITY.md).

## Consequences
Defends against misbehaving agents and accidents within a single-user machine; does not defend against
malware running as the same OS user.
