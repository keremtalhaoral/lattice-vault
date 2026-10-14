# Schema evolution (event payloads)

Code: `schemas.py` (registry + validators + upcasters). Related: design §2.4, ADR 0004 (append-only log).

## Model
- `schemas.SCHEMAS[type] = Spec(version, fields, extra)` is the per-type registry. Fields are declared as
  `(types, required, max_len)` and are stdlib-only. `extra="allow"` (most domain types; importer metadata such as
  `provenance`, `tur` and `kaynak` rides along) or `"forbid"` (meta events). Payload cap: 64 KB.
- **Write:** `vault.append()` validates every *known* type against its current spec and stamps
  `schema_version = SCHEMAS[type].version`.
  - **Agents** (MCP `propose_event`, `vault propose`) get a `propose_event refused: schema: …` error for invalid
    payloads **and for unknown types**.
  - **Human CLI** (`vault add`) rejects invalid payloads for known types. Unknown types are *allowed*, with a
    stderr warning, and stored at v1 without per-type checks. Projections ignore them. Rationale: a human can
    record ad-hoc facts; once a type is registered, its v1 spec must accept what was stored.
- **Read:** `vault.read_upcast(e)` / `decrypt_payload()` apply `@upcaster(type, from_version)` functions
  `v1→v2→…→current` **in memory**. They are used by rebuild/projections, history, `pack`, `export-context`,
  `show` and MCP `get_event`. Stored rows, hashes and the chain are never touched.
- **Forward-compat:** an event with `schema_version` > the registry's version is *unknown-version*. Readers
  return its raw payload and never crash. `rebuild()` keeps it out of projections, with status `unknown_version`.
  `vault doctor` reports it (`checks.unknown_version_events`). Upgrading the code makes it readable again.

## Rules
1. **Additive, optional field:** no version bump and no upcaster. Old events simply lack the field.
2. **Rename, type change, new required field or semantic change:** bump `Spec.version` and add
   `@upcaster(type, old_version)`. Upcasters must be pure (`payload -> new payload`) and deterministic: no I/O, no
   clock, no mutation of their input.
3. **Never edit or rewrite old events** to "migrate" them. The only copy-to-new-file paths stay
   `vault redact` / `vault migrate` (human-approved).
4. **One test fixture per version.** For each type/version, keep a stored payload of that version in the tests
   and assert that it upcasts to the current shape and that rebuild stays deterministic.
5. Never remove an upcaster while events of that version can exist (including on sync peers).

## Limitations
- Meta events (approvals/reverts) with an unknown version still drive status, which comes from link tables and
  not from their payload.
- Sensitive fields are validated as plaintext before sealing. Upcasters see decrypted payloads, so a shredded
  event cannot be upcast; it stays redacted.
- Sync-imported rows keep the sender's `schema_version` and are not re-validated on import.
