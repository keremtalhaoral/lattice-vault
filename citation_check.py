#!/usr/bin/env python3
"""Unsupported-claim check (docs/adr/0010):
1) automatic citation check, 2) a configurable % sample queued for human review. Stdlib only."""
import hashlib, ipaddress, json, os, re, socket, time, urllib.error, urllib.parse, urllib.request

CITE_RE = re.compile(r"vault://event/([0-9a-fA-F-]{36})")
SOURCE_FIELDS = ("source", "sources", "source_id", "source_ids")
DEFAULT_SAMPLE_PCT = float(os.environ.get("VAULT_REVIEW_SAMPLE_PCT", "10"))

HTTP_TIMEOUT = float(os.environ.get("VAULT_HTTP_TIMEOUT", "5"))
CACHE_TTL_OK = 7 * 86400      # seconds a definite result (ok / flag) stays cached
CACHE_TTL_REVIEW = 3600       # uncertain results (403, timeout...) are retried sooner
OK, FLAG, REVIEW = "ok", "flag", "review"

URL_CACHE_SCHEMA = """
CREATE TABLE IF NOT EXISTS url_cache (url TEXT PRIMARY KEY, verdict TEXT NOT NULL, detail TEXT, checked_epoch REAL NOT NULL);
"""

QUEUE_SCHEMA = """
CREATE TABLE IF NOT EXISTS review_queue (
  item TEXT PRIMARY KEY,           -- event id or claim hash
  kind TEXT NOT NULL CHECK (kind IN ('entry','claim')),
  reason TEXT NOT NULL,            -- 'unsupported' | 'uncertain_source' | 'sample'
  text TEXT,
  queued_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  verdict TEXT CHECK (verdict IN ('supported','unsupported')),
  reviewer TEXT
);
"""


def _exists(db, eid):
    return db.execute("SELECT 1 FROM events WHERE id=?", (eid,)).fetchone() is not None


def offline():
    return os.environ.get("VAULT_OFFLINE", "").lower() in ("1", "true", "yes")


class UnsafeURL(ValueError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None   # never follow redirects: a 3xx is reported as its status code


_OPENER = urllib.request.build_opener(_NoRedirect)


def _ip_allowed(ip):
    ip = ipaddress.ip_address(ip)
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return ip.is_global and not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                                  or ip.is_reserved or ip.is_unspecified)


def validate_url(url):
    """https only, port 443, every resolved address must be public (checked AFTER DNS resolution)."""
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https":
        raise UnsafeURL("only https URLs are checked")
    if not u.hostname or u.username or u.password:
        raise UnsafeURL("invalid host")
    if u.port not in (None, 443):
        raise UnsafeURL("only port 443")
    try:
        infos = socket.getaddrinfo(u.hostname, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise
    addrs = {i[4][0] for i in infos}
    if not addrs or not all(_ip_allowed(a) for a in addrs):
        raise UnsafeURL("host resolves to a non-public address")
    return u


def _fetch(url, timeout):
    """Return HTTP status code. HEAD first, GET if HEAD is not allowed. Raises on network failure.
    Redirects are NOT followed. (Residual risk: DNS rebinding between validation and connect; documented.)"""
    validate_url(url)
    for method in ("HEAD", "GET"):
        req = urllib.request.Request(url, method=method, headers={"User-Agent": "lattice-vault-citation-check/0.1.0"})
        try:
            with _OPENER.open(req, timeout=timeout) as r:
                return r.status
        except urllib.error.HTTPError as e:
            if method == "HEAD" and e.code in (405, 501):
                continue
            return e.code
    return 405


def classify_status(code):
    if 200 <= code < 400:
        return OK
    if code in (404, 410):
        return FLAG
    return REVIEW  # 403/401/429/5xx/other: blocked or unclear -> human


def check_url(db, url):
    """(verdict, detail). Cached in url_cache. Offline mode: never auto-valid -> review, no network, no cache write."""
    if offline():
        return REVIEW, "offline mode: not checked"
    db.executescript(URL_CACHE_SCHEMA)
    row = db.execute("SELECT verdict, detail, checked_epoch FROM url_cache WHERE url=?", (url,)).fetchone()
    if row:
        ttl = CACHE_TTL_REVIEW if row[0] == REVIEW else CACHE_TTL_OK
        if time.time() - row[2] < ttl:
            return row[0], row[1]
    try:
        code = _fetch(url, HTTP_TIMEOUT)
        verdict, detail = classify_status(code), f"HTTP {code}"
        if 300 <= code < 400:
            verdict, detail = REVIEW, f"redirect HTTP {code} (not followed)"
    except UnsafeURL as e:
        return FLAG, f"unsafe url: {e}"
    except urllib.error.URLError as e:
        r = e.reason
        if isinstance(r, socket.gaierror) or isinstance(r, ConnectionRefusedError):
            verdict, detail = FLAG, f"unreachable: {type(r).__name__}"
        else:
            verdict, detail = REVIEW, f"network failure: {type(r).__name__}"
    except (socket.timeout, TimeoutError, OSError) as e:
        verdict, detail = REVIEW, f"network failure: {type(e).__name__}"
    db.execute("INSERT OR REPLACE INTO url_cache(url, verdict, detail, checked_epoch) VALUES(?,?,?,?)",
               (url, verdict, detail, time.time()))
    db.commit()
    return verdict, detail


def check_source(db, ref, base_dir=None):
    """(verdict, detail) for one source ref: ok | flag | review."""
    ref = str(ref).strip()
    m = CITE_RE.fullmatch(ref) or re.fullmatch(r"([0-9a-fA-F-]{36})", ref)
    if m:
        return (OK, "vault event") if _exists(db, m.group(1)) else (FLAG, "unknown vault event")
    if ref.startswith(("http://", "https://")):
        return check_url(db, ref)
    # Files: only relative paths confined to the vault root (VAULT_ROOT or base_dir). Absolute paths and
    # traversal are flagged WITHOUT touching the filesystem, so the result is not an existence oracle.
    root = base_dir or os.environ.get("VAULT_ROOT")
    if not root or not ref or os.path.isabs(ref) or ref.startswith("~"):
        return FLAG, "file ref not allowed"
    root_r = os.path.realpath(root)
    path = os.path.realpath(os.path.join(root_r, ref))
    if os.path.commonpath([root_r, path]) != root_r:
        return FLAG, "file ref not allowed"
    return (OK, "file") if os.path.isfile(path) else (FLAG, "missing file")


def resolve(db, ref, base_dir=None):
    return check_source(db, ref, base_dir)[0] == OK


def check_entries(db, base_dir=None):
    """Flag non-human entries (agent:/import:) whose payload has no resolvable source.
    Human (user:) entries are first-hand and are their own source."""
    flagged = []
    for r in db.execute("SELECT id, type, actor, payload FROM events WHERE actor NOT LIKE 'user:%' ORDER BY seq"):
        p = json.loads(r["payload"])
        refs = []
        for f in SOURCE_FIELDS:
            v = p.get(f)
            refs += v if isinstance(v, list) else ([v] if v else [])
        res = {x: check_source(db, x, base_dir) for x in refs}
        bad = [x for x, v in res.items() if v[0] == FLAG]
        unsure = [x for x, v in res.items() if v[0] == REVIEW]
        if not refs or bad:
            flagged.append({"id": r["id"], "type": r["type"], "actor": r["actor"], "action": FLAG,
                            "reason": "no source" if not refs else f"unresolvable: {bad}"})
        elif unsure:
            flagged.append({"id": r["id"], "type": r["type"], "actor": r["actor"], "action": REVIEW,
                            "reason": "uncertain source: " + "; ".join(f"{x} ({res[x][1]})" for x in unsure)})
    return flagged


def check_claims(db, text):
    """Each bullet line ('- ...') of an answer/pack is a claim; it must cite >=1 existing vault event."""
    flagged = []
    for ln in text.splitlines():
        s = ln.strip().lstrip(">").strip()
        if not s.startswith("- ") or s in ("- (kasada yok)", "- …(kesildi)"):
            continue
        ids = CITE_RE.findall(s)
        if not ids:
            flagged.append({"claim": s, "reason": "no citation"})
        elif not all(_exists(db, i) for i in ids):
            flagged.append({"claim": s, "reason": "unresolvable citation"})
    return flagged


def unsupported_rate(db, text):
    claims = [l for l in text.splitlines() if l.strip().lstrip(">").strip().startswith("- ")]
    return len(check_claims(db, text)) / len(claims) if claims else 0.0


def in_sample(item, pct):
    """Deterministic: same item always gets the same decision for a given pct."""
    h = int(hashlib.sha256(item.encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
    return h * 100 < pct


def queue_for_review(db, pct=None, text=None, base_dir=None):
    """Queue all flagged items + a pct% sample of the rest. Returns number newly queued."""
    pct = DEFAULT_SAMPLE_PCT if pct is None else pct
    if not 0 <= pct <= 100:
        raise ValueError("sample pct must be 0..100")
    db.executescript(QUEUE_SCHEMA)
    rows = []
    flagged = {f["id"]: f["action"] for f in check_entries(db, base_dir)}
    for r in db.execute("SELECT id, payload FROM events ORDER BY seq"):
        if r["id"] in flagged:
            rows.append((r["id"], "entry", "unsupported" if flagged[r["id"]] == FLAG else "uncertain_source", r["payload"]))
        elif in_sample(r["id"], pct):
            rows.append((r["id"], "entry", "sample", r["payload"]))
    if text:
        bad = {f["claim"] for f in check_claims(db, text)}
        for ln in text.splitlines():
            s = ln.strip().lstrip(">").strip()
            if not s.startswith("- "):
                continue
            cid = "claim:" + hashlib.sha256(s.encode()).hexdigest()[:16]
            if s in bad:
                rows.append((cid, "claim", "unsupported", s))
            elif in_sample(cid, pct):
                rows.append((cid, "claim", "sample", s))
    before = db.total_changes
    db.executemany("INSERT OR IGNORE INTO review_queue(item,kind,reason,text) VALUES(?,?,?,?)", rows)
    db.commit()
    return db.total_changes - before


def pending_reviews(db):
    db.executescript(QUEUE_SCHEMA)
    return [dict(r) for r in db.execute("SELECT * FROM review_queue WHERE verdict IS NULL ORDER BY queued_at, item")]


def record_verdict(db, item, verdict, reviewer=None):
    reviewer = reviewer or "user:" + (os.environ.get("VAULT_USER", "owner").strip() or "owner")
    if not reviewer.startswith("user:"):
        raise ValueError("review verdicts require a human reviewer")
    db.executescript(QUEUE_SCHEMA)
    cur = db.execute("UPDATE review_queue SET verdict=?, reviewer=? WHERE item=? AND verdict IS NULL",
                     (verdict, reviewer, item))
    db.commit()
    if not cur.rowcount:
        raise ValueError(f"no pending review item {item}")
