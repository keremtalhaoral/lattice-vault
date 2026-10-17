"""Import a `vault_update` block from pasted AI output (`vault import-update`). See ADR 0015.

Semi-automatic by default: parse -> strict validation of EVERY entry -> preview (diff against current state) ->
explicit confirmation on the terminal -> one atomic transaction. `--dry-run` only previews; `--yes` skips the prompt
(entries still land unverified). Fail closed: any invalid entry rejects the whole block, nothing is written.

Trust rule: the content was written by an AI, so every entry is stored with actor `agent:<name>` and trust
`unverified` (status proposed) -- exactly like the agent API. Only the user's own `vault approve` (signed) makes it
verified. Never importable: subject.*, key.*, event.*, conflict.*, import.*, attestation.* and every signed or
human-only type; only the content types in IMPORT_TYPES are accepted.

Idempotent: each entry's idempotency key is derived from its canonical content, so importing the same block twice
writes nothing the second time (reported as duplicates).
"""
import hashlib, json, re, sys, time

import vault, schemas, agent_api

IMPORT_TYPES = ("preference.set", "decision.made", "decision.reversed", "goal.set", "goal.progressed",
                "goal.completed", "goal.abandoned", "project.created", "project.status_changed",
                "learning.captured", "note.added")
NEVER_PREFIXES = ("subject.", "key.", "event.", "conflict.", "import.", "attestation.")
BLOCK_KEYS = {"format", "pack_spec", "base_vault_seq", "idempotency_key", "events"}
ENTRY_KEYS = {"type", "subject", "key", "payload", "supersedes", "cites"}
FORMATS = ("vault_update/2",)
MAX_BLOCK_BYTES = 65536
MAX_EVENTS = 25
DEFAULT_RATE = 20
FENCE = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})[ \t]*vault_update[ \t]*\r?$", re.M)
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
AGENT_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
VIA = "via:import-update"
CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]")
KEY_RX = re.compile(r"[^\s\x00-\x1f\x7f-\x9f]+(?: [^\s\x00-\x1f\x7f-\x9f]+)*")


def clean(text, n=160):
    """Terminal-safe one-line text: control/bidi/zero-width characters removed, secret patterns filtered."""
    s = " ".join(CONTROL.sub(" ", str(text)).split())
    if vault.find_secrets(s):
        return "[filtered]"
    s = vault.esc(s)
    return s if len(s) <= n else s[:n - 1] + "…"

assert not any(t.startswith(NEVER_PREFIXES) or t in vault.SIGNED_TYPES or t in vault.HUMAN_ONLY_TYPES
               or t in vault.META_TYPES for t in IMPORT_TYPES)


class UpdateRefused(ValueError):
    """Refused import. The message names the problem; it never echoes secret-pattern matches."""


def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise UpdateRefused("duplicate JSON key")
        d[k] = v
    return d


def _bad_const(c):
    raise UpdateRefused(f"non-finite number {c} not allowed")


def _finite(v):
    """Reject inf/nan anywhere (e.g. 1e999 parses to inf without going through parse_constant)."""
    import math
    if isinstance(v, float) and not math.isfinite(v):
        raise UpdateRefused("non-finite number not allowed")
    for x in (v.values() if isinstance(v, dict) else v if isinstance(v, list) else ()):
        _finite(x)


def extract_block(text):
    """Exactly one ```vault_update fenced block -> its body. Anything else (none, several, unclosed) is refused."""
    if not isinstance(text, str):
        raise UpdateRefused("input must be text")
    if len(text.encode("utf-8")) > 4 * MAX_BLOCK_BYTES:
        raise UpdateRefused("input too large")
    opens = list(FENCE.finditer(text))
    if not opens:
        raise UpdateRefused("no ```vault_update block found")
    if len(opens) > 1:
        raise UpdateRefused(f"{len(opens)} vault_update blocks found; exactly one is allowed")
    m = opens[0]
    fence = m.group(1)
    close = re.compile(r"^[ \t]{0,3}" + re.escape(fence[0]) + "{" + str(len(fence)) + r",}[ \t]*\r?$", re.M)
    c = close.search(text, m.end())
    if not c:
        raise UpdateRefused("vault_update block is not closed")
    body = text[m.end():c.start()].strip("\r\n")
    if len(body.encode("utf-8")) > MAX_BLOCK_BYTES:
        raise UpdateRefused(f"vault_update block larger than {MAX_BLOCK_BYTES} bytes")
    return body


def parse(text):
    """Text containing one block -> validated dict (structure only; content checks happen in validate())."""
    body = extract_block(text)
    try:
        doc = json.loads(body, object_pairs_hook=_no_dupes, parse_constant=_bad_const)
    except UpdateRefused:
        raise
    except json.JSONDecodeError as e:
        raise UpdateRefused(f"vault_update block is not valid JSON ({e.msg} at line {e.lineno})") from None
    except (ValueError, RecursionError):
        raise UpdateRefused("vault_update block is not valid JSON (too deep or number too large)") from None
    _finite(doc)
    if not isinstance(doc, dict):
        raise UpdateRefused("vault_update block must be a JSON object")
    extra = sorted(set(doc) - BLOCK_KEYS)
    if extra:
        raise UpdateRefused(f"{len(extra)} unknown top-level field(s); allowed: {', '.join(sorted(BLOCK_KEYS))}")
    if "format" in doc and doc["format"] not in FORMATS:
        raise UpdateRefused(f"unsupported format (supported: {', '.join(FORMATS)})")
    if "base_vault_seq" in doc and (type(doc["base_vault_seq"]) is not int or doc["base_vault_seq"] < 0):
        raise UpdateRefused("base_vault_seq must be a non-negative integer")
    if "idempotency_key" in doc and not (isinstance(doc["idempotency_key"], str) and 0 < len(doc["idempotency_key"]) <= 200):
        raise UpdateRefused("idempotency_key must be a non-empty string (max 200)")
    ev = doc.get("events")
    if not isinstance(ev, list) or not ev:
        raise UpdateRefused("events must be a non-empty list")
    if len(ev) > MAX_EVENTS:
        raise UpdateRefused(f"too many events ({len(ev)} > {MAX_EVENTS})")
    return doc


def _entry_key(e):
    canon = json.dumps({k: e.get(k) for k in ("type", "subject", "key", "payload", "supersedes")},
                       ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "vu2:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()[:40]


def validate(db, doc):
    """Every entry through the agent-API rules plus the import allowlist. Returns normalised entries or raises."""
    out = []
    for n, e in enumerate(doc["events"], 1):
        where = f"events[{n}]"
        if not isinstance(e, dict):
            raise UpdateRefused(f"{where}: must be an object")
        bad = sorted((set(e) | set(agent_api._keys(e.get("payload")))) & agent_api.FORBIDDEN_KEYS)
        if bad:
            raise UpdateRefused(f"{where}: forbidden field(s): {', '.join(bad)}")
        extra = sorted(set(e) - ENTRY_KEYS)
        if extra:
            raise UpdateRefused(f"{where}: {len(extra)} unknown field(s); allowed: {', '.join(sorted(ENTRY_KEYS))}")
        typ, subject, key, payload = e.get("type"), e.get("subject"), e.get("key"), e.get("payload")
        if not isinstance(typ, str) or not re.fullmatch(r"[a-z_]+\.[a-z_]+", typ):
            raise UpdateRefused(f"{where}: invalid type")
        if typ.startswith(NEVER_PREFIXES) or typ in vault.SIGNED_TYPES or typ not in IMPORT_TYPES:
            raise UpdateRefused(f"{where}: type {typ} cannot be imported (allowed: {', '.join(IMPORT_TYPES)})")
        if not (isinstance(subject, str) and 0 < len(subject) <= 200 and re.fullmatch(r"[^\s\x00-\x1f]+", subject)):
            raise UpdateRefused(f"{where}: subject must be a non-empty string without whitespace (max 200)")
        if subject.startswith(("event:", "key:")):
            raise UpdateRefused(f"{where}: subject {subject.split(':')[0]}:* is not allowed here")
        if key is not None and not (isinstance(key, str) and 0 < len(key) <= 200 and KEY_RX.fullmatch(key)):
            raise UpdateRefused(f"{where}: key must be a non-empty string without control characters (max 200)")
        if not isinstance(payload, dict):
            raise UpdateRefused(f"{where}: payload must be an object")
        sup = e.get("supersedes")
        if sup is not None and not (isinstance(sup, str) and UUID.fullmatch(sup)):
            raise UpdateRefused(f"{where}: supersedes must be a full event id")
        if sup is not None:
            r = db.execute("SELECT actor, trust FROM events WHERE id=?", (sup,)).fetchone()
            if not r:
                raise UpdateRefused(f"{where}: supersedes refers to an unknown event")
            st = db.execute("SELECT trust_eff, status FROM proj_status WHERE event_id=?", (sup,)).fetchone()
            if r["actor"].startswith("user:") or r["trust"] == "verified" or not st or st[0] == "verified":
                # an AI proposal must never block the user's own later writes (double-supersede rule)
                raise UpdateRefused(f"{where}: supersedes may only target an unverified proposal, not a verified or user fact")
            if st[1] != "proposed":   # approved/rejected/superseded: the user already decided on it (Security L4r)
                raise UpdateRefused(f"{where}: supersedes may only target a still-proposed event (status {st[1]!r})")
        cites = e.get("cites", [])
        if not isinstance(cites, list) or len(cites) > 20 or not all(isinstance(c, str) and UUID.fullmatch(c) for c in cites):
            raise UpdateRefused(f"{where}: cites must be a list of full event ids (max 20)")
        try:
            schemas.validate(typ, payload)
        except schemas.SchemaError as x:
            raise UpdateRefused(f"{where}: schema: {str(x)[:300]}") from None
        bad_src = agent_api._check_sources(payload)
        if bad_src:
            raise UpdateRefused(f"{where}: {bad_src}")
        size = len(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        if size > agent_api.MAX_PAYLOAD_BYTES:
            raise UpdateRefused(f"{where}: payload {size} bytes > {agent_api.MAX_PAYLOAD_BYTES}")
        text = agent_api.scan_text(f"{subject} {key or ''} {vault._flatten(payload)}")
        for rx in agent_api.INJECTION:
            if rx.search(text):
                raise UpdateRefused(f"{where}: refused: text looks like instructions to an AI, not data")
        if vault.find_secrets(text):
            raise UpdateRefused(f"{where}: refused: secret pattern detected (store secrets with `vault add --sensitive`)")
        ent = {"type": typ, "subject": subject, "key": key, "payload": payload, "supersedes": sup, "cites": cites}
        ent["idempotency_key"] = _entry_key(ent)
        out.append(ent)
    return out


_one_line = clean


def plan(db, entries, actor):
    """Annotate each entry: 'new' | 'duplicate' (already imported by this actor) | 'conflict'; plus 'current' text."""
    import context_export
    withheld = context_export.shred_states(db)
    seen = set()
    for e in entries:
        prev = db.execute("SELECT type, subject, payload FROM events WHERE actor=? AND idempotency_key=?",
                          (actor, e["idempotency_key"])).fetchone()
        if e["idempotency_key"] in seen:
            e["state"] = "duplicate"
        elif prev:
            same = prev["type"] == e["type"] and prev["subject"] == e["subject"] and json.loads(prev["payload"]) == e["payload"]
            e["state"] = "duplicate" if same else "conflict"
        else:
            e["state"] = "new"
        seen.add(e["idempotency_key"])
        e["current"] = None
        if e["type"] == "preference.set":
            k = e["key"] or e["payload"].get("key") or "_"
            r = db.execute("SELECT p.value, e.enc_key_id FROM proj_preferences p JOIN events e ON e.id=p.event_id "
                           "WHERE p.subject=? AND p.key=? ORDER BY p.event_id LIMIT 1", (e["subject"], k)).fetchone()
            if r is None:
                e["current"] = None
            elif e["subject"] in withheld:
                e["current"] = "[withheld]"
            elif r[1]:
                e["current"] = "[encrypted]"     # never print a decrypted sensitive value (no TTY needed here)
            else:
                e["current"] = r[0]
    return entries


def preview(entries, actor, stale=None):
    lines = [f"vault_update: {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}; all land as UNVERIFIED "
             f"proposals by {actor} (approve each later with `vault approve`)."]
    if stale:
        lines.append(f"note: block was written against vault_seq {stale[0]}, vault is now at {stale[1]}")
    for n, e in enumerate(entries, 1):
        tag = {"new": "+", "duplicate": "=", "conflict": "!"}[e["state"]]
        head = f"{tag} [{n}] {e['type']} {_one_line(e['subject'], 80)}" + (f" / {_one_line(e['key'], 60)}" if e["key"] else "")
        lines.append(head + {"duplicate": "  (already imported; skipped)", "conflict": "  (CONFLICT)", "new": ""}[e["state"]])
        if e["current"] is not None:
            lines.append(f"    - current: {_one_line(e['current'])}")
        lines.append(f"    + {_one_line(vault._flatten(e['payload']))}")
        if e["supersedes"]:
            lines.append(f"    supersedes {e['supersedes']} (an unverified proposal)")
    return "\n".join(lines) + "\n"


def _agent_limit(agent):
    """Registered agents (agents.json): refused if revoked, their own hourly limit applies. Unregistered names get
    the default limit. The rate counter is shared with the agent API (audit action 'propose')."""
    try:
        agents = agent_api._load_agents()
    except agent_api.Refused as x:
        raise UpdateRefused(str(x)) from None
    for a in agents:
        if a.get("id") == agent:
            if a.get("revoked"):
                raise UpdateRefused(f"agent:{agent} is revoked")
            return int(a.get("rate_limit_per_hour", DEFAULT_RATE))
    return DEFAULT_RATE


def import_update(db, text, agent="pasted-ai", confirm=None, dry_run=False, out=None):
    """Returns a result dict. `confirm(preview_text) -> bool` is called only when there is something new to write."""
    out = out or sys.stdout
    if not (isinstance(agent, str) and AGENT_NAME.fullmatch(agent)):
        raise UpdateRefused("agent name must match [a-z0-9][a-z0-9_-]*")
    actor = f"agent:{agent}"
    audit = lambda outcome, reason, eid=None: vault.audit(db, actor, "propose", outcome, f"{VIA}: {clean(reason, 200)}", eid)
    try:
        limit = _agent_limit(agent)
        doc = parse(text)
        entries = plan(db, validate(db, doc), actor)
    except UpdateRefused as x:
        audit("refused", str(x))
        raise
    seq = db.execute("SELECT COALESCE(MAX(seq),0) FROM events").fetchone()[0]
    base = doc.get("base_vault_seq")
    pv = preview(entries, actor, (base, seq) if isinstance(base, int) and base < seq else None)
    conflicts = [n for n, e in enumerate(entries, 1) if e["state"] == "conflict"]
    if conflicts:
        audit("refused", "idempotency conflict")
        raise UpdateRefused(f"entries {conflicts}: same idempotency key, different content; nothing imported")
    new = [e for e in entries if e["state"] == "new"]
    res = {"actor": actor, "new": len(new), "duplicates": len(entries) - len(new), "event_ids": [], "dry_run": dry_run}
    out.write(pv)
    if dry_run or not new:
        return res
    used = db.execute("SELECT count(*) FROM audit WHERE actor=? AND action='propose' AND outcome='accepted' AND epoch>?",
                      (actor, time.time() - agent_api.RATE_WINDOW_S)).fetchone()[0]
    if used + len(new) > limit:
        audit("refused", f"rate limit {limit}/h")
        raise UpdateRefused(f"rate limit for {actor}: {limit} proposals per hour ({used} used, {len(new)} new); nothing written")
    if confirm is None or not confirm(pv):
        audit("refused", "not confirmed by the user")
        raise UpdateRefused("import not confirmed; nothing written")
    try:
        for e in new:
            eid, dup = vault.append(db, e["type"], e["subject"], e["payload"], actor, "unverified", key=e["key"],
                                    supersedes=e["supersedes"], idempotency_key=e["idempotency_key"],
                                    strict_types=True, commit=False, _rebuild=False)
            res["event_ids"].append(eid)
        db.commit()
    except Exception as x:
        db.rollback()
        reason = "secret pattern detected" if isinstance(x, vault.SecretRefused) else str(x).split(";")[0][:160]
        audit("refused", reason)
        raise UpdateRefused(f"import failed, nothing written: {reason}") from None
    vault.rebuild(db)
    vault._after_commit(db)
    for eid in res["event_ids"]:
        audit("accepted", "ok", eid)
    return res


def tty_confirm(prompt_text):
    """Ask on the controlling terminal (works even when the block itself was piped in on stdin)."""
    try:
        with open("/dev/tty", "r+", encoding="utf-8") as t:
            t.write("Import these entries as UNVERIFIED proposals? Type 'yes' to continue: "); t.flush()
            return t.readline().strip().lower() == "yes"
    except OSError:
        raise vault.HumanRequired("`import-update` needs an interactive terminal to confirm (or --dry-run / --yes)")


def add_parser(sp):
    x = sp.add_parser("import-update", help="import one vault_update block from pasted AI output (lands unverified)")
    x.add_argument("file", help="file with the AI output, or - for stdin")
    x.add_argument("--agent", default="pasted-ai", help="name recorded as actor agent:<name> (default pasted-ai)")
    g = x.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true", help="validate and preview only")
    g.add_argument("--yes", action="store_true", help="skip the confirmation prompt (entries still land unverified)")


def run(db, args):
    if args.file == "-":
        text = sys.stdin.read(4 * MAX_BLOCK_BYTES + 1)
    else:
        with open(args.file, encoding="utf-8") as f:
            text = f.read(4 * MAX_BLOCK_BYTES + 1)
    confirm = (lambda _pv: True) if args.yes else tty_confirm
    res = import_update(db, text, args.agent, confirm=confirm, dry_run=args.dry_run, out=sys.stderr)
    print(json.dumps(res, ensure_ascii=False))
    return 0
