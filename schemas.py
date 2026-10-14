"""Event-type registry: current schema_version + declarative payload validator per type, and upcasters.

Stdlib only. See docs/schema-evolution.md.

* SCHEMAS[type] = Spec(version, fields={name: (types, required, max_len)}, extra="allow"|"forbid")
* @upcaster(type, from_version) registers a pure function payload(v) -> payload(v+1).
* upcast(type, version, payload) applies the chain in memory; stored events are never rewritten.
* An event whose schema_version is newer than the registry knows is "unknown-version": readers must not crash,
  projections skip it, doctor reports it.
"""
import json

MAX_PAYLOAD_BYTES = 64 * 1024
MAX_STR = 20000          # default per-string cap for declared string fields
STR, NUM, BOOL, LIST, DICT, NONE = (str,), (int, float), (bool,), (list,), (dict,), (type(None),)
SCALAR = STR + NUM + BOOL + NONE


class SchemaError(ValueError):
    """Payload does not match the current schema for its event type (or the type is unknown)."""


class UnknownVersion(Exception):
    """Event schema_version is newer than this code knows."""


class Spec:
    def __init__(self, version=1, fields=None, extra="allow"):
        self.version, self.fields, self.extra = version, dict(fields or {}), extra


def F(types, required=False, max_len=None):
    return (tuple(types), required, max_len if max_len is not None else (MAX_STR if str in types else None))


PROV = F(DICT)          # importer provenance block
_TEXT = F(STR + NONE)
SCHEMAS = {
    # domain events
    "preference.set": Spec(1, {"value": F(SCALAR), "text": _TEXT, "key": F(STR, max_len=200), "provenance": PROV}),
    "decision.made": Spec(1, {"decision_id": F(STR, max_len=200), "title": F(STR + NONE, max_len=500),
                              "decision": _TEXT, "text": _TEXT, "context": _TEXT, "status_text": _TEXT,
                              "struck": F(BOOL), "provenance": PROV}),
    "decision.reversed": Spec(1, {"decision_id": F(STR, max_len=200), "reason": _TEXT, "text": _TEXT}),
    "project.created": Spec(1, {"project_id": F(STR, max_len=200), "title": F(STR + NONE, max_len=500),
                                "status": F(STR, max_len=50), "text": _TEXT}),
    "project.status_changed": Spec(1, {"project_id": F(STR, max_len=200), "status": F(STR, max_len=50),
                                       "title": F(STR + NONE, max_len=500), "text": _TEXT}),
    "goal.set": Spec(1, {"goal_id": F(STR, max_len=200), "title": F(STR + NONE, max_len=500),
                         "target": F(SCALAR), "text": _TEXT}),
    "goal.progressed": Spec(1, {"goal_id": F(STR, max_len=200), "progress": F(NUM + NONE), "text": _TEXT}),
    "goal.completed": Spec(1, {"goal_id": F(STR, max_len=200), "text": _TEXT}),
    "goal.abandoned": Spec(1, {"goal_id": F(STR, max_len=200), "reason": _TEXT, "text": _TEXT}),
    "learning.captured": Spec(1, {"text": _TEXT, "sources": F(LIST), "source": F(STR, max_len=2000)}),
    "note.added": Spec(1, {"text": _TEXT, "date": F(STR + NONE, max_len=40), "decision_id": F(STR, max_len=200),
                           "value": F(SCALAR), "tur": F(STR + NONE, max_len=50), "time": F(STR + NONE, max_len=10),
                           "kaynak": F(STR + NONE, max_len=500), "provenance": PROV}),
    # meta events (human-only except event.corrected proposals)
    "event.corrected": Spec(1, {"field": F(STR, True, 200), "new_value": F(SCALAR + LIST + DICT), "reason": _TEXT}),
    "event.approved": Spec(1, {"reason": _TEXT}, extra="forbid"),
    "event.rejected": Spec(1, {"reason": _TEXT}, extra="forbid"),
    "event.reverted": Spec(1, {"reason": _TEXT, "import_id": F(STR, max_len=200)}, extra="forbid"),
    "import.batch_approved": Spec(1, {"import_id": F(STR, True, 200), "confirmed_block_ids": F(LIST, True)}, extra="forbid"),
    "event.redacted": Spec(1, {"redaction_id": F(STR, True, 200), "reason": _TEXT}, extra="forbid"),
    "subject.shredded": Spec(1, {"key_id": F(STR, True, 200)}, extra="forbid"),
    # signing (signing.py, docs/adr/0011): human-only, signed with a user Ed25519 key
    "key.registered": Spec(1, {"key_id": F(STR, True, 200), "alg": F(STR, True, 20), "pubkey_b64": F(STR, True, 200),
                               "role": F(STR, True, 20), "device_id": F(STR + NONE, max_len=200),
                               "certified_by": F(STR, True, 200)}, extra="forbid"),
    "key.rotated": Spec(1, {"old_key_id": F(STR, True, 200), "new_key_id": F(STR, True, 200),
                            "new_key_sig": F(STR, True, 200)}, extra="forbid"),
    "key.revoked": Spec(1, {"key_id": F(STR, True, 200), "effective_hlc": F(STR, True, 200), "reason": _TEXT,
                            "compromised": F(BOOL, True)}, extra="forbid"),
    "attestation.recorded": Spec(1, {"target_event_ids": F(LIST, True), "statement": F(STR, True, 2000)}, extra="forbid"),
    "conflict.resolved": Spec(1, {"reason": _TEXT, "chosen": F(STR + NONE, max_len=200)}),
}

UPCASTERS = {}   # (type, from_version) -> fn


def upcaster(type_, from_version):
    def deco(fn):
        if (type_, from_version) in UPCASTERS:
            raise ValueError(f"duplicate upcaster {type_} v{from_version}")
        UPCASTERS[(type_, from_version)] = fn
        return fn
    return deco


def current_version(type_):
    s = SCHEMAS.get(type_)
    return s.version if s else 1


def is_known(type_):
    return type_ in SCHEMAS


def is_future(type_, version):
    return int(version or 1) > current_version(type_)


def upcast(type_, version, payload):
    """Return payload brought to the current version (a new dict; input untouched). Raises UnknownVersion."""
    v, cur = int(version or 1), current_version(type_)
    if v > cur:
        raise UnknownVersion(f"{type_} schema_version {v} > known {cur}")
    p = json.loads(json.dumps(payload))   # deep copy: upcasters must never mutate stored data
    while v < cur:
        fn = UPCASTERS.get((type_, v))
        if fn is None:
            raise UnknownVersion(f"no upcaster for {type_} v{v}->v{v + 1}")
        p = fn(p)
        if not isinstance(p, dict):
            raise TypeError(f"upcaster {type_} v{v} returned {type(p).__name__}")
        v += 1
    return p


def _tn(types):
    return "|".join(sorted({"null" if t is type(None) else t.__name__ for t in types}))


def validate(type_, payload, allow_unknown=False):
    """Raise SchemaError if payload is invalid for the current schema of type_. Sensitive placeholders
    ({"$enc": key_id}) are validated before sealing, so callers pass the plaintext payload."""
    if not isinstance(payload, dict):
        raise SchemaError("payload must be an object")
    size = len(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())
    if size > MAX_PAYLOAD_BYTES:
        raise SchemaError(f"payload {size} bytes > {MAX_PAYLOAD_BYTES}")
    spec = SCHEMAS.get(type_)
    if spec is None:
        if allow_unknown:
            return
        raise SchemaError(f"unknown event type {type_!r} (known: {', '.join(sorted(SCHEMAS))})")
    errs = []
    for name, (types, req, max_len) in spec.fields.items():
        if name not in payload:
            if req:
                errs.append(f"missing required field {name!r}")
            continue
        v = payload[name]
        if isinstance(v, bool) and bool not in types:   # bool is an int subclass; don't let it pass as a number
            errs.append(f"field {name!r} must be {_tn(types)}, got bool"); continue
        if not isinstance(v, types):
            errs.append(f"field {name!r} must be {_tn(types)}, got {_tn((type(v),))}"); continue
        if max_len and isinstance(v, str) and len(v) > max_len:
            errs.append(f"field {name!r} longer than {max_len} chars")
    if spec.extra == "forbid":
        extra = sorted(set(payload) - set(spec.fields))
        if extra:
            errs.append(f"unexpected field(s) {extra}")
    if errs:
        raise SchemaError(f"invalid {type_} v{spec.version} payload: " + "; ".join(errs))
