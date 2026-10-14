# Architecture Decision Records
Numbers match the project's internal decision log (D-003 … D-010); earlier numbers are internal and not published.

| ADR | Title | Decision status | Implementation |
|---|---|---|---|
| [0003](0003-vault-mvp-architecture.md) | Vault MVP architecture | Accepted | Implemented |
| [0004](0004-append-only-event-log.md) | Append-only event log + projections | Accepted | Implemented |
| [0005](0005-turkish-fts5-search.md) | Turkish-normalized FTS5 search | Accepted | Implemented (no stemming) |
| [0006](0006-mcp-interface.md) | MCP interface: reads + one proposal tool | Accepted | Implemented |
| [0007](0007-security-requirements.md) | Security requirements for agent writes and secrets | Accepted | Partially implemented |
| [0008](0008-multi-device-sync.md) | Multi-device sync via file packages | Proposed | Planned, not implemented |
| [0009](0009-markdown-import-trust.md) | Markdown import trust rules | Accepted | Implemented |
| [0010](0010-unsupported-claim-check.md) | Unsupported-claim (citation) check | Accepted | Partially implemented |
| [0011](0011-signing-keys.md) | User signing key, signed human-only events, external anchor; device keys reserved | Accepted (user key) / Proposed (device keys) | Partially implemented (no device keys / package signing) |
| [0012](0012-key-lifecycle.md) | User key rotation, revocation, offline recovery code, second anchor | Proposed | Implemented (review pending) |
| [0013](0013-sync-key-transport.md) | Sync key transport: certified X25519 device keys, signed DEK bundles | Proposed | Prototype (review pending) |
| [0014](0014-crypto-shredding.md) | Crypto-shredding lifecycle: signed schedule/cancel/shred events, reconcile, no plaintext after finalize | Proposed | Prototype (review pending) |
| [0015](0015-context-pack-v2.md) | Context Pack v2: measured token estimates, vault_update import (unverified), context-pack/2 format | Proposed | Implemented (review pending) |
| [0016](0016-signed-sequences-and-hpke.md) | Signed sync manifests, per-sender sequence numbers, RFC 9180 HPKE key wrap (vaultsync/0.2, vaultkeys/0.2) | Proposed | Implemented (review pending) |
