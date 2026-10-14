"""Agent-facing API (stand-in for the MCP server, design §6). Stdlib only.

Reads:  get_summary(token), export_context_pack(token, profile, max_chars)  -- read-only DB connection (mode=ro)
Write:  propose_event(token, args)  -- the single, narrow write path; always lands as proposed/unverified.
Tokens are never logged, echoed, or included in errors. Only sha256 hashes are stored (agents.json, mode 600).
"""
import hashlib, hmac, json, os, re, secrets, sqlite3, stat, time, unicodedata
import schemas, vault

MAX_PAYLOAD_BYTES = 8192
FORBIDDEN_KEYS = {"actor", "source", "trust", "status", "approved"}
ALLOWED_ARGS = {"type", "subject", "key", "payload", "idempotency_key", "base_vault_seq", "supersedes"}
AGENT_FORBIDDEN_TYPES = ("event.", "conflict.", "import.", "subject.")
AGENT_ALLOWED_META = ("event.corrected",)   # agents may PROPOSE corrections (land proposed); never approve/revert
SOURCE_FIELDS = ("sources", "source_id", "source_ids")   # 'source' itself stays forbidden
MAX_SOURCES = 10
RATE_WINDOW_S = 3600
ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e\u202a-\u202e\u2066-\u2069]")
INJECTION = [re.compile(p, re.I) for p in (
    r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules)", r"disregard\s+(all\s+)?(previous|prior)",
    r"\bsystem\s+prompt\b", r"you\s+are\s+now\b", r"<<<\s*vault_data", r"vault_data_(begin|end)",
    r"önceki\s+talimatlar", r"talimatlar[ıi]\s+(yok\s+say|unut)")]
# secret patterns live in vault.SECRET_PATTERNS / vault.find_secrets (shared with the human CLI path)


class Refused(Exception):
    """Raised for refused calls. Message never contains the token."""


def _agents_path():
    return os.environ.get("VAULT_AGENTS", os.path.join(os.path.dirname(os.path.abspath(os.environ.get("VAULT_DB", "./vault.db"))), "agents.json"))


def _db_path():
    return os.path.abspath(os.environ.get("VAULT_DB", "./vault.db"))


def _load_agents():
    p = _agents_path()
    if not os.path.exists(p):
        return []
    mode = stat.S_IMODE(os.stat(p).st_mode)
    if mode & 0o077:
        raise Refused(f"agents.json permissions {oct(mode)} too open; require 600")
    with open(p) as f:
        return json.load(f).get("agents", [])


def _save_agents(agents):
    p = _agents_path()
    fd = os.open(p + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"agents": agents}, f, indent=2)
    os.chmod(p + ".tmp", 0o600)
    os.replace(p + ".tmp", p)


def add_agent(agent_id, rate_limit=20):
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", agent_id):
        raise ValueError("agent id must match [a-z0-9][a-z0-9_-]*")
    agents = [a for a in _load_agents() if a["id"] != agent_id]
    token = "vt_" + secrets.token_urlsafe(32)
    agents.append({"id": agent_id, "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                   "revoked": False, "rate_limit_per_hour": rate_limit})
    _save_agents(agents)
    return token


def revoke_agent(agent_id):
    agents = _load_agents()
    for a in agents:
        if a["id"] == agent_id:
            a["revoked"] = True
    _save_agents(agents)


def authenticate(token):
    """Returns agent record or None. Constant-time compare against every stored hash."""
    if not token or not isinstance(token, str):
        return None, "missing token"
    h = hashlib.sha256(token.encode()).hexdigest()
    found = None
    for a in _load_agents():
        if hmac.compare_digest(h, a.get("token_sha256", "")):
            found = a
    if not found:
        return None, "unknown token"
    if found.get("revoked"):
        return None, f"agent:{found['id']} revoked"
    return found, "ok"


def _ro():
    db = sqlite3.connect(f"file:{_db_path()}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    return db


def _rw():
    return vault.connect(_db_path(), create=False)   # never auto-create a vault from the MCP side


def _audit(actor, outcome, reason, event_id=None):
    db = _rw()
    try:
        vault.audit(db, actor, "propose", outcome, reason, event_id)
    finally:
        db.close()


# ---------------- reads ----------------
def _withheld(db):
    """Subjects with an applied or pending crypto-shred: no plaintext of theirs on any agent read surface."""
    import context_export
    return context_export.shred_states(db)


def get_summary(token=None):
    """Canonical summary: active events only (proposed/unverified/rejected excluded). Reads allowed without auth."""
    db = _ro()
    try:
        rows = db.execute("""SELECT e.id, e.type, e.subject, e.payload, e.trust FROM events e JOIN proj_status s
                             ON s.event_id = e.id WHERE s.status='active' AND e.type NOT LIKE 'event.%' ORDER BY e.seq""").fetchall()
        as_of = db.execute("SELECT COALESCE(MAX(seq),0) FROM events").fetchone()[0]
        wh = _withheld(db)
        return {"as_of_seq": as_of, "items": [{"source": f"vault://event/{r['id']}", "type": r["type"], "subject": r["subject"],
                "text": vault.esc(vault._flatten(json.loads(r["payload"])))} for r in rows if r["subject"] not in wh]}
    finally:
        db.close()


def export_context_pack(token=None, profile="minimal", max_chars=None, include_unverified=False):
    """context-pack/2 (context_pack.export): sensitive fields stay `[encrypted]` (never decrypted for agents),
    redacted/shredded/shred-pending subjects are withheld, secret patterns filtered. ADR 0015."""
    import context_pack
    if max_chars is not None and (type(max_chars) is not int or max_chars <= 0):
        raise ValueError("max_chars must be a positive integer")
    db = _ro()
    try:
        return context_pack.export(db, profile, include_unverified=include_unverified, max_chars=max_chars)
    finally:
        db.close()


# ---------------- the single write path ----------------
def _keys(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _keys(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _keys(v)


def _check_sources(payload):
    """`sources`/`source_id(s)`: only https URLs or vault://event/<uuid>, at most 10, each <= 300 chars.
    (Security review K1: these fields used to drive network/file checks.)"""
    for k, v in payload.items() if isinstance(payload, dict) else []:
        if k not in SOURCE_FIELDS:
            continue
        vals = v if isinstance(v, list) else [v]
        if len(vals) > MAX_SOURCES:
            return f"too many {k} (max {MAX_SOURCES})"
        for x in vals:
            if not isinstance(x, str) or len(x) > 300 or not (
                    re.fullmatch(r"vault://event/[0-9a-fA-F-]{36}", x) or re.fullmatch(r"https://[A-Za-z0-9.-]+(:443)?(/[^\s]*)?", x)):
                return f"invalid {k}: only https URLs or vault://event/<id>"
    return None


def token_from_env():
    """Prefer VAULT_AGENT_TOKEN_FILE (must be 0600, owned by us) over VAULT_AGENT_TOKEN.
    Caveat: env vars stay readable in /proc/<pid>/environ for same-user processes even after os.environ.pop."""
    p = os.environ.get("VAULT_AGENT_TOKEN_FILE")
    if p:
        st = os.stat(p)
        if stat.S_IMODE(st.st_mode) & 0o077 or st.st_uid != os.getuid():
            raise Refused("VAULT_AGENT_TOKEN_FILE must be mode 600 and owned by the current user")
        with open(p) as f:
            return f.read().strip() or None
    return os.environ.get("VAULT_AGENT_TOKEN")


def scan_text(s):
    return ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", s))


def propose_event(token, args):
    agent, why = authenticate(token)
    if not agent:
        _audit("unauthenticated", "refused", why)
        raise Refused(f"propose_event refused: {why}")
    actor = f"agent:{agent['id']}"

    def refuse(reason):
        _audit(actor, "refused", reason)
        raise Refused(f"propose_event refused: {reason}")

    if not isinstance(args, dict):
        refuse("args must be an object")
    bad = sorted((set(args) | set(_keys(args.get("payload")))) & FORBIDDEN_KEYS)
    if bad:
        refuse(f"forbidden field(s): {', '.join(bad)}")
    extra = sorted(set(args) - ALLOWED_ARGS)
    if extra:
        refuse(f"unknown argument(s): {', '.join(extra)}")
    typ, subject, payload, ikey = args.get("type"), args.get("subject"), args.get("payload"), args.get("idempotency_key")
    if not (isinstance(typ, str) and re.fullmatch(r"[a-z_]+\.[a-z_]+", typ)):
        refuse("invalid type")
    if typ.startswith(AGENT_FORBIDDEN_TYPES) and typ not in AGENT_ALLOWED_META:
        refuse(f"type {typ} not allowed for agents")
    if not isinstance(subject, str) or not subject or not isinstance(payload, dict) or not isinstance(ikey, str) or not ikey:
        refuse("subject, payload (object) and idempotency_key are required")
    try:   # per-type schema (schemas.py); agents may not introduce unknown types
        schemas.validate(typ, payload)
    except schemas.SchemaError as e:
        refuse(f"schema: {str(e)[:300]}")
    bad_src = _check_sources(payload)
    if bad_src:
        refuse(bad_src)
    canon = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    size = len(canon.encode("utf-8"))
    if size > MAX_PAYLOAD_BYTES:
        refuse(f"payload {size} bytes > {MAX_PAYLOAD_BYTES}")
    text = scan_text(f"{subject} {args.get('key') or ''} {vault._flatten(payload)}")
    for rx in INJECTION:
        if rx.search(text):
            refuse(f"injection pattern: {rx.pattern}")
    if vault.find_secrets(text):
        refuse("secret pattern detected")
    db = _rw()
    try:
        prev = db.execute("SELECT id, payload, type, subject FROM events WHERE actor=? AND idempotency_key=?", (actor, ikey)).fetchone()
        if prev:
            if json.loads(prev["payload"]) == payload and prev["type"] == typ and prev["subject"] == subject:
                vault.audit(db, actor, "propose", "duplicate", "idempotent replay", prev["id"])
                return {"event_id": prev["id"], "status": "proposed", "duplicate": True}
            refuse("idempotency_key conflict: same key, different content")
        limit = int(agent.get("rate_limit_per_hour", 20))
        n = db.execute("SELECT count(*) FROM audit WHERE actor=? AND action='propose' AND outcome='accepted' AND epoch>?",
                       (actor, time.time() - RATE_WINDOW_S)).fetchone()[0]
        if n >= limit:
            refuse(f"rate limit {limit}/h exceeded")
        last = db.execute("SELECT COALESCE(MAX(seq),0) FROM events WHERE subject=?", (subject,)).fetchone()[0]
        try:
            eid, _ = vault.append(db, typ, subject, payload, actor, "unverified", key=args.get("key"),
                                  supersedes=args.get("supersedes"), idempotency_key=ikey, strict_types=True)
        except ValueError as e:   # supersedes validation, blocklist, secret filter
            refuse(str(e).split(";")[0][:160])
        vault.audit(db, actor, "propose", "accepted", "ok", eid)
        return {"event_id": eid, "status": "proposed", "duplicate": False,
                "stale": int(args.get("base_vault_seq") or 0) < last}
    finally:
        db.close()


def search(token=None, query="", type_=None, subject=None, limit=8):
    """FTS over active events only (proposed/unverified excluded)."""
    limit = max(1, min(int(limit or 8), 25))
    db = _ro()
    try:
        rows = vault.search(db, query, type_, subject, limit * 4)
        wh = _withheld(db)
        rows = [r for r in rows if r["subject"] not in wh]
        return [{"source": f"vault://event/{r['id']}", "type": r["type"], "subject": r["subject"],
                 "snippet": vault.esc(r["snip"]), "score": round(r["score"], 4)}
                for r in rows if r["status"] == "active"][:limit]
    finally:
        db.close()


def get_event(token=None, event_id=""):
    """Single event + status. Non-active events are returned only as status metadata, payload withheld."""
    db = _ro()
    try:
        r = db.execute("""SELECT e.*, s.status FROM events e LEFT JOIN proj_status s ON s.event_id=e.id
                          WHERE e.id=?""", (event_id,)).fetchone()
        if not r:
            raise Refused(f"unknown event")
        out = {"id": r["id"], "type": r["type"], "subject": r["subject"], "status": r["status"],
               "trust": r["trust"], "ts": r["ts"], "supersedes": r["supersedes"], "target_id": r["target_id"]}
        wh = _withheld(db)
        if r["subject"] in wh:
            out["payload"] = None
            out["note"] = f"subject {wh[r['subject']]}; content withheld"
        elif r["status"] == "active":
            out["payload"] = json.loads(vault.esc(vault.canon(vault.read_upcast(r))))
            if vault.is_unknown_version(r):
                out["unknown_version"] = r["schema_version"]
        else:
            out["payload"] = None
            out["note"] = "not active (proposed/rejected); content withheld until a human approves it"
        return out
    finally:
        db.close()
