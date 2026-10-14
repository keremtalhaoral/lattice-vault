"""`vault show`: one event's detail plus its full correction/supersede chain (read-only).

Opens the database with SQLite `mode=ro` instead of `vault.connect()`: connect() issues
`PRAGMA journal_mode=DELETE`, chmods files and may run `rebuild()` (all writes). Integrity is checked with
the same `check_triggers` / `verify_chains` logic. Payloads are NEVER decrypted: encrypted fields render as
`[encrypted]`, redacted events as `[redacted]`, and strings matching the secret filter as `[filtered:<pattern>]`.
"""
import json, os, re, sqlite3
import vault

DETAIL_VERSION = "1"
MIN_SUFFIX = 6
TARGET_META = ("event.approved", "event.rejected", "event.reverted", "import.batch_approved", "event.redacted")


class LookupError_(ValueError):
    pass


def open_ro(path=None):
    path = path or os.environ.get("VAULT_DB", "./vault.db")
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        raise ValueError(f"{path}: no vault database")
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    v = db.execute("SELECT v FROM schema_meta WHERE k='schema_version'").fetchone() \
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='schema_meta'").fetchone() else None
    if not v or v[0] != vault.SCHEMA_VERSION:
        db.close()
        raise vault.TamperError(f"{path}: schema version {v[0] if v else '1'} != {vault.SCHEMA_VERSION}")
    return db


def resolve(db, ref):
    ref = ref.split("vault://event/", 1)[-1].strip().lower()
    if db.execute("SELECT 1 FROM events WHERE id=?", (ref,)).fetchone():
        return ref
    if len(ref) < MIN_SUFFIX:
        raise ValueError(f"id suffix must be at least {MIN_SUFFIX} characters")
    if not re.fullmatch(r"[0-9a-f-]+", ref):
        raise ValueError(f"unknown event {ref}")
    c = [r[0] for r in db.execute("SELECT id FROM events WHERE id LIKE ? ORDER BY hlc, id", ("%" + ref,))]
    if not c:
        raise ValueError(f"unknown event {ref}")
    if len(c) > 1:
        raise ValueError(f"ambiguous id suffix {ref}; candidates: {', '.join(c)}")
    return c[0]


def _statuses(db):
    """Effective status/trust: proj_status if the projection exists, else replayed in memory (no write)."""
    if db.execute("SELECT 1 FROM sqlite_master WHERE name='proj_status'").fetchone():
        return {r[0]: (r[1], r[2], r[3], r[4]) for r in db.execute("SELECT event_id,status,decided_by,decided_seq,trust_eff FROM proj_status")}
    st, te = vault.compute_status(db, db.execute("SELECT * FROM events ORDER BY hlc, id").fetchall())
    return {k: (a, b, c, te.get(k)) for k, (a, b, c) in st.items()}


def _scrub(v):
    if isinstance(v, dict):
        if set(v) == {"$enc"}:
            return "[encrypted]"
        return {k: _scrub(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_scrub(x) for x in v]
    if isinstance(v, str):
        hits = vault.find_secrets(v)
        return f"[filtered:{','.join(sorted(set(hits)))}]" if hits else v
    return v


def safe_payload(e, status=None):
    p = vault.read_upcast(e)
    if p.get("redacted") is True or status == "redacted":
        return "[redacted]"
    if status == "undecryptable":
        return "[undecryptable]"
    return _scrub(p)


def _chain_check(db, e):
    prev, out = vault.GENESIS, {"ok": True, "detail": "hash chain verified up to this event"}
    for r in db.execute("SELECT * FROM events WHERE seq<=? ORDER BY seq", (e["seq"],)):
        if r["prev_hash"] != prev or vault.event_hash(prev, r) != r["hash"]:
            return {"ok": False, "detail": f"event chain broken at seq {r['seq']}"}
        prev = r["hash"]
    nxt = db.execute("SELECT prev_hash FROM events WHERE seq>? ORDER BY seq LIMIT 1", (e["seq"],)).fetchone()
    if nxt and nxt[0] != e["hash"]:
        return {"ok": False, "detail": "next event does not link to this event's hash"}
    trig = vault.check_triggers(db)
    if trig:
        out = {"ok": False, "detail": "; ".join(trig)}
    return out


def _sup(db, eid, up=True):
    q = ("SELECT parent_id FROM event_parents WHERE event_id=? AND rel='supersedes'" if up else
         "SELECT event_id FROM event_parents WHERE parent_id=? AND rel='supersedes'")
    return sorted(r[0] for r in db.execute(q, (eid,)))


def _component(db, eid):
    seen, stack = set(), [eid]
    while stack:
        x = stack.pop()
        if x in seen:
            continue
        seen.add(x)
        stack += _sup(db, x, True) + _sup(db, x, False)
    return seen


def _ancestors(db, eid):
    out, stack = [], list(_sup(db, eid, True))
    while stack:
        x = stack.pop()
        if x not in out:
            out.append(x); stack += _sup(db, x, True)
    return out


def _descendants(db, eid):
    out, stack = [], list(_sup(db, eid, False))
    while stack:
        x = stack.pop()
        if x not in out:
            out.append(x); stack += _sup(db, x, False)
    return out


def _targeting(db, ids):
    if not ids:
        return []
    q = ",".join("?" * len(ids))
    return db.execute(f"""SELECT DISTINCT e.* , t.target_id tgt FROM event_targets t JOIN events e ON e.id=t.event_id
                          WHERE t.target_id IN ({q}) ORDER BY e.hlc, e.id""", list(ids)).fetchall()


def _ev(db, eid):
    return db.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()


def detail(db, ref):
    eid = resolve(db, ref)
    sts = _statuses(db)
    st = lambda i: sts.get(i, (None, None, None, None))
    e = _ev(db, eid)
    chain = _component(db, eid)
    order = sorted(chain, key=lambda i: (_ev(db, i)["hlc"], i))
    active = lambda i: st(i)[0] == "active"
    heads = [i for i in order if active(i) and not any(active(c) for c in _sup(db, i, False))]
    conflict_heads = list(heads) if len(heads) > 1 else []
    # projection-level conflicts (existing model: >1 live head per (subject,key) / decision_id)
    proj_conf = []
    if db.execute("SELECT 1 FROM sqlite_master WHERE name='proj_preferences'").fetchone():
        for i in order:
            for tbl, col in (("proj_preferences", "subject, key"), ("proj_decisions", "decision_id")):
                r = db.execute(f"SELECT {col} FROM {tbl} WHERE event_id=? AND conflict=1", (i,)).fetchone()
                if r:
                    where = " AND ".join(f"{c.strip()}=?" for c in col.split(","))
                    proj_conf += [x[0] for x in db.execute(f"SELECT event_id FROM {tbl} WHERE {where} AND conflict=1", list(r))]
    proj_conf = sorted(set(proj_conf))
    conflict = bool(conflict_heads) or len(proj_conf) > 1
    meta = _targeting(db, order)
    timeline = []
    for i in order:
        r = _ev(db, i)
        timeline.append({"id": i, "type": r["type"], "ts": r["ts"], "hlc": r["hlc"], "actor": r["actor"],
                         "status": st(i)[0], "supersedes": _sup(db, i, True), "head": i in heads and not conflict_heads,
                         "conflict_head": i in conflict_heads, "selected": i == eid,
                         "payload": safe_payload(r, st(i)[0])})
    for m in meta:
        timeline.append({"id": m["id"], "type": m["type"], "ts": m["ts"], "hlc": m["hlc"], "actor": m["actor"],
                         "status": st(m["id"])[0], "targets": [m["tgt"]], "head": False, "conflict_head": False,
                         "selected": False, "payload": safe_payload(m, st(m["id"])[0])})
    timeline.sort(key=lambda x: (x["hlc"], x["id"]))
    # effective payload of the chain root(s): stored payload + active corrections, never decrypted
    roots = [i for i in order if not set(_sup(db, i, True)) & chain]
    eff = None
    if len(roots) == 1:
        r0 = _ev(db, roots[0])
        eff = safe_payload(r0, st(roots[0])[0])
        if isinstance(eff, dict):
            for i in order:
                c = _ev(db, i)
                if c["type"] == "event.corrected" and active(i):
                    cp = safe_payload(c, st(i)[0])
                    if isinstance(cp, dict) and "field" in cp:
                        eff[cp["field"]] = cp.get("new_value")
    s = st(eid)
    review = [{"action": "proposed" if s[0] != "active" or not e["actor"].startswith("user:") else "created",
               "by": e["actor"], "at": e["ts"], "event_id": eid}]
    for m in meta:
        if m["tgt"] == eid:
            review.append({"action": {"event.approved": "approved", "event.rejected": "rejected", "event.reverted": "reverted",
                                      "import.batch_approved": "batch_approved", "event.redacted": "redacted"}.get(m["type"], m["type"]),
                           "by": m["actor"], "at": m["ts"], "event_id": m["id"]})
    audit = [dict(ts=a["ts"], actor=a["actor"], action=a["action"], outcome=a["outcome"], reason=_scrub(a["reason"]),
                  event_id=a["event_id"])
             for a in db.execute("SELECT * FROM audit WHERE event_id=? OR event_id IN (SELECT event_id FROM event_targets WHERE target_id=?) ORDER BY id",
                                 (eid, eid))]
    return {"detail_version": DETAIL_VERSION, "id": eid, "type": e["type"], "subject": e["subject"], "key": e["key"],
            "ts": e["ts"], "hlc": e["hlc"], "actor": e["actor"], "import_id": e["import_id"],
            "trust": s[3] or e["trust"], "trust_recorded": e["trust"], "status": s[0], "decided_by": s[1],
            "schema_version": e["schema_version"], "hash": e["hash"], "prev_hash": e["prev_hash"],
            "chain_verification": _chain_check(db, e), "encrypted": bool(e["enc_key_id"]),
            "payload": safe_payload(e, s[0]), "review": review, "audit": audit,
            "history": {"ancestors": _ancestors(db, eid), "descendants": _descendants(db, eid), "roots": roots,
                        "heads": heads, "effective_head": heads[0] if len(heads) == 1 else None,
                        "effective_payload": eff, "conflict": conflict, "conflict_heads": conflict_heads,
                        "projection_conflict_heads": proj_conf, "timeline": timeline}}


def _short(i):
    return i[-12:]


def _p(x):
    return x if isinstance(x, str) else json.dumps(x, ensure_ascii=False, sort_keys=True)


def render_text(d, tree=False):
    h = d["history"]
    cv = d["chain_verification"]
    L = [f"id:             {d['id']}", f"type:           {d['type']}", f"subject/key:    {d['subject']} / {d['key'] or '-'}",
         f"ts / hlc:       {d['ts']}  {d['hlc']}", f"actor:          {d['actor']}" + (f"  (import {d['import_id']})" if d["import_id"] else ""),
         f"trust:          {d['trust']}" + (f" (recorded {d['trust_recorded']})" if d['trust'] != d['trust_recorded'] else ""),
         f"status:         {d['status']}" + (f" (by {d['decided_by']})" if d["decided_by"] else ""),
         f"schema_version: {d['schema_version']}", f"hash:           {d['hash']}", f"prev_hash:      {d['prev_hash']}",
         f"chain:          {'OK' if cv['ok'] else 'FAILED'} - {cv['detail']}", f"payload:        {_p(d['payload'])}", "", "review:"]
    L += [f"  {r['at']}  {r['action']:<14} {r['by']}  ({_short(r['event_id'])})" for r in d["review"]]
    if d["audit"]:
        L += ["audit:"] + [f"  {a['ts']}  {a['action']} {a['outcome']}  {a['actor']}  {a['reason']}" for a in d["audit"]]
    L += ["", "correction history (oldest -> newest):"]
    if h["conflict"]:
        L.append(f"  !! CONFLICT: multiple live heads: {', '.join(h['conflict_heads'] or h['projection_conflict_heads'])}")
    elif h["effective_head"]:
        L.append(f"  effective head: {h['effective_head']}")
    else:
        L.append("  effective head: none (chain reverted/rejected or not yet approved)")
    if h["effective_payload"] is not None:
        L.append(f"  effective payload: {_p(h['effective_payload'])}")

    def line(t):
        mark = " <= HEAD" if t["head"] else (" <= CONFLICT HEAD" if t["conflict_head"] else "")
        sel = "*" if t["selected"] else " "
        rel = (f" supersedes {','.join(map(_short, t['supersedes']))}" if t.get("supersedes") else
               f" -> {','.join(map(_short, t['targets']))}" if t.get("targets") else "")
        return f"{sel} {t['ts']}  {_short(t['id'])}  {t['type']:<18} {t['status'] or '-':<9} {t['actor']}{rel}  {_p(t['payload'])}{mark}"
    if not tree:
        L += ["  " + line(t) for t in h["timeline"]]
    else:
        by = {t["id"]: t for t in h["timeline"]}
        kids = {}
        for t in h["timeline"]:
            for p in t.get("supersedes", []) + t.get("targets", []):
                kids.setdefault(p, []).append(t["id"])
        def walk(i, pre, last, top):
            L.append("  " + ("" if top else pre + ("└─ " if last else "├─ ")) + line(by[i]))
            ch = kids.get(i, [])
            for n, c in enumerate(ch):
                walk(c, pre + ("" if top else ("   " if last else "│  ")), n == len(ch) - 1, False)
        for r in h["roots"]:
            walk(r, "", True, True)
    L.append("  (* = selected event)")
    return "\n".join(L) + "\n"


def show(ref, as_json=False, tree=False, path=None):
    db = open_ro(path)
    try:
        d = detail(db, ref)
    finally:
        db.close()
    return json.dumps(d, ensure_ascii=False, indent=2, sort_keys=True) + "\n" if as_json else render_text(d, tree)
