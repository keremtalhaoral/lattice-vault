# ADR 0008 (D-008): Multi-device sync via file-based packages
- **Status:** Proposed
- **Implementation:** Prototype on branch feat/sync-prototype (see docs/sync.md); signing, encryption, key sync planned

## Context
The vault should eventually be usable from a second device without running a server.

## Decision (proposed)
Version vectors plus grow-only-set merge. `.vaultsync` packages (compressed NDJSON with a header) are
written to a folder and moved by any local-first tool (file sync, USB, …); the vault itself contains no
network code. A relay service is rejected for now. Packages are to be encrypted and signed. Approval events
are accepted only from registered replicas. Redactions must propagate and force a copy-to-new-file on each
device; blocklisted content in old packages is refused.

## Alternatives
Self-hosted relay (lower latency, but requires hosting, authentication and TLS); cloud database.

## Consequences
Eventual consistency with delayed, reordered or duplicated delivery is tolerated by design. Until
implemented, the vault is single-device.
