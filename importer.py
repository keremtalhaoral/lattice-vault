"""Markdown import (docs/design.md §12, docs/adr/0009).

* Scope: log/*.md, decisions.md, and simple signed bullets in top-level fact files. design/ and bots/ are excluded,
  as are README.md / BOT-PROTOCOL.md (rules, not facts). Never follows symlinks. Read-only on the source tree.
* Every imported event: actor=import:markdown, trust=unverified, status proposed, import_id set.
  'verified' is DERIVED from the owner's `import.batch_approved` event, and only for lines the owner explicitly confirms
  from the dry-run's owner_lines list (an owner-name signature alone is not trusted).
* idempotency_key = sha256(norm_path + "\\n" + sha256(NFC, LF, trailing-whitespace-stripped block));
  the line number is metadata only.
* Errors are per file/line with codes PARSE_ERROR, ENCODING_ERROR, DUPLICATE, SECRET, BLOCKED; a bad file is skipped,
  never fatal. Commit is a single transaction: any DB error rolls back the whole import.
"""
import hashlib, json, os, re, time, unicodedata
import vault, obs

EXCLUDE_DIRS = {"design", "bots", "snapshots"}
EXCLUDE_FILES = {"README.md", "BOT-PROTOCOL.md"}
FACT_FILES = ("user-context.md", "current-work.md", "principles.md", "models.md", "product-ideas.md", "team.md")
TUR_MAP = {"tercih": "preference.set", "karar": "note.added", "iş": "note.added", "is": "note.added",
           "fikir": "note.added", "model": "note.added"}
LOG_RE = re.compile(r"^- \((?:\d{4}-\d{2}-\d{2} )?(\d{2}:\d{2}), ([^)]+)\)\s*(?:\[tür:\s*([^\]]+)\])?\s*(.*)$")
SIG_RE = re.compile(r"^- \((\d{4}-\d{2}-\d{2}), ([^)]+)\)\s*(.+)$")
KAYNAK_RE = re.compile(r"\[kaynak:\s*([^\]]*)\]\s*$")
DEC_HEAD_RE = re.compile(r"^## (D-\d{3})\s+(.*)$")
DEC_FIELD_RE = re.compile(r"^- ([^:]+):\s*(.*)$")


def norm_block(text):
    t = unicodedata.normalize("NFC", text).replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(l.rstrip() for l in t.split("\n")).strip("\n")


def bot_names(root):
    names = set()
    p = os.path.join(root, "team.md")
    if os.path.isfile(p) and not os.path.islink(p):
        for line in open(p, encoding="utf-8", errors="replace"):
            m = re.match(r"^\|\s*([^|]+?)\s*\|", line)
            if m and m.group(1) not in ("Bot", "---"):
                names.add(vault.tr_norm(m.group(1)))
    return names


def classify(name, bots):
    """owner | bot | ambiguous (single exact owner name only; extra text/multiple names -> ambiguous).
    The owner's signature name comes from VAULT_OWNER_NAME (default "owner")."""
    n = vault.tr_norm(name.strip())
    owner = vault.tr_norm(os.environ.get("VAULT_OWNER_NAME", "owner").strip())
    if n == owner:
        return "owner"
    if "/" in n or "," in n or "(" in n or owner in n:
        return "ambiguous"
    if n and any(n == b or n in b for b in bots):
        return "bot"
    return "ambiguous"


def _block(rel, line, author, kind, type_, subject, payload, key=None):
    text = norm_block(payload.get("text") or payload.get("decision") or "")
    raw = norm_block(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    chash = hashlib.sha256(raw.encode()).hexdigest()
    ikey = hashlib.sha256(f"{rel}\n{chash}".encode()).hexdigest()
    payload = dict(payload, provenance={"file": rel, "line": line, "raw_author": author, "author_kind": kind})
    return {"block_id": ikey[:12], "idempotency_key": ikey, "file": rel, "line": line, "author": author,
            "author_kind": kind, "type": type_, "subject": subject, "key": key, "payload": payload,
            "preview": text[:80]}


def parse_log(rel, lines, bots, errors):
    out = []
    for n, line in enumerate(lines, 1):
        if not line.startswith("- ("):
            continue
        m = LOG_RE.match(line.rstrip("\n"))
        if not m:
            errors.append({"file": rel, "line": n, "code": "PARSE_ERROR", "msg": "log line does not match '- (SS:DD, <ad>) ...'"})
            continue
        hhmm, name, tur, rest = m.groups()
        km = KAYNAK_RE.search(rest)
        text = rest[:km.start()].strip() if km else rest.strip()
        tur_n = (tur or "").strip().lower()
        type_ = TUR_MAP.get(tur_n, "note.added")
        payload = {"text": text, "tur": tur_n or None, "time": hhmm, "kaynak": km.group(1).strip() if km else None}
        subject = f"md:{rel}"
        key = None
        if type_ == "preference.set":
            key = "md:" + hashlib.sha256(text.encode()).hexdigest()[:8]; subject = vault.HUMAN; payload["value"] = text
        out.append(_block(rel, n, name, classify(name, bots), type_, subject, payload, key))
    return out


def parse_decisions(rel, lines, bots, errors):
    out, cur = [], None
    def flush():
        if not cur:
            return
        f = cur["fields"]
        who = f.get("tarih / karar veren", "")
        author = who.split("/", 1)[1].strip() if "/" in who else ""
        if not author:
            errors.append({"file": rel, "line": cur["line"], "code": "PARSE_ERROR", "msg": f"{cur['id']}: missing 'Karar veren'"})
        payload = {"decision_id": cur["id"], "title": cur["title"], "decision": f.get("karar", ""),
                   "context": f.get("bağlam"), "status_text": f.get("durum")}
        if cur.get("struck_fields"):
            payload["struck"] = True     # design §12.2: struck-through records import as struck (never verified-by-default)
        out.append(_block(rel, cur["line"], author or "?", classify(author, bots) if author else "ambiguous",
                          "decision.made", f"decision:{cur['id']}", payload))
        for ln, upd in cur["updates"]:
            m = re.match(r"^Güncelleme [^()]*\(([^)]+)\):\s*(.*)$", upd)
            name = m.group(1) if m else "?"
            out.append(_block(rel, ln, name, classify(name, bots) if m else "ambiguous", "note.added",
                              f"decision:{cur['id']}", {"text": m.group(2) if m else upd, "decision_id": cur["id"]}))
    in_fence = False
    for n, line in enumerate(lines, 1):
        s = line.rstrip("\n")
        if s.startswith("```"):
            in_fence = not in_fence; continue
        if in_fence:
            continue
        m = DEC_HEAD_RE.match(s)
        if m:
            flush(); cur = {"id": m.group(1), "title": m.group(2).strip(), "line": n, "fields": {}, "updates": []}; continue
        if cur and s.startswith("- Güncelleme"):
            cur["updates"].append((n, s[2:])); continue
        struck = s.startswith("- ~~") and s.rstrip().endswith("~~")
        if struck:
            s = "- " + s[4:].rstrip()[:-2]; cur and cur.setdefault("struck_fields", []).append(n)
        fm = DEC_FIELD_RE.match(s)
        if cur and fm:
            cur["fields"][fm.group(1).strip().lower()] = fm.group(2).strip()
    flush()
    return out


def parse_facts(rel, lines, bots, errors):
    out = []
    for n, line in enumerate(lines, 1):
        m = SIG_RE.match(line.rstrip("\n"))
        if m:
            date, name, text = m.groups()
            out.append(_block(rel, n, name, classify(name, bots), "note.added", f"md:{rel}", {"text": text.strip(), "date": date}))
    return out


def scan(root):
    """Parse the tree (read-only). Returns (blocks, errors, manifest)."""
    root = os.path.realpath(root)
    bots = bot_names(root)
    files = []
    logd = os.path.join(root, "log")
    if os.path.isdir(logd) and not os.path.islink(logd):
        files += [("log", os.path.join("log", f)) for f in sorted(os.listdir(logd)) if f.endswith(".md")]
    files.append(("decisions", "decisions.md"))
    files += [("facts", f) for f in FACT_FILES]
    blocks, errors, manifest = [], [], {}
    for kind, rel in files:
        p = os.path.join(root, rel)
        if not os.path.isfile(p) or os.path.islink(p) or rel.split(os.sep)[0] in EXCLUDE_DIRS or rel in EXCLUDE_FILES:
            continue
        data = open(p, "rb").read()
        manifest[rel] = hashlib.sha256(data).hexdigest()
        try:
            lines = data.decode("utf-8").splitlines(True)
        except UnicodeDecodeError as e:
            errors.append({"file": rel, "line": None, "code": "ENCODING_ERROR", "msg": f"not UTF-8 (byte {e.start}); file skipped"})
            continue
        fn = {"log": parse_log, "decisions": parse_decisions, "facts": parse_facts}[kind]
        try:
            blocks += fn(rel, lines, bots, errors)
        except Exception as e:  # a bad file is skipped, never fatal
            errors.append({"file": rel, "line": None, "code": "PARSE_ERROR", "msg": f"{type(e).__name__}; file skipped"})
    return blocks, errors, manifest


def plan(db, root):
    blocks, errors, manifest = scan(root)
    seen, items = set(), []
    for b in blocks:
        code = None
        if b["idempotency_key"] in seen:
            code = "DUPLICATE"
        elif db is not None and db.execute("SELECT 1 FROM redacted_blocklist WHERE content_hash=?",
                (vault.content_hash(b["type"], b["subject"], b["key"], b["payload"]),)).fetchone():
            code = "BLOCKED"
        elif db is not None and db.execute("SELECT 1 FROM events WHERE actor='import:markdown' AND idempotency_key=?",
                                           (b["idempotency_key"],)).fetchone():
            code = "DUPLICATE"
        elif vault.find_secrets(json.dumps(b["payload"], ensure_ascii=False)):
            code = "SECRET"
        seen.add(b["idempotency_key"])
        if code:
            errors.append({"file": b["file"], "line": b["line"], "code": code, "msg": b["block_id"]})
        else:
            items.append(b)
    mhash = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    counts = {"files": len(manifest), "blocks": len(blocks), "new": len(items)}
    for e in errors:
        counts[e["code"].lower()] = counts.get(e["code"].lower(), 0) + 1
    by_author = {}
    for b in items:
        by_author[b["author_kind"]] = by_author.get(b["author_kind"], 0) + 1
    return {"root": os.path.realpath(root), "manifest_sha256": mhash, "counts": counts, "by_author": by_author,
            "by_type": {t: sum(1 for b in items if b["type"] == t) for t in sorted({b["type"] for b in items})},
            "errors": errors,
            "owner_lines": [{"block_id": b["block_id"], "file": b["file"], "line": b["line"], "preview": b["preview"]}
                            for b in items if b["author_kind"] == "owner"],
            "items": items}


def run(db, root, dry_run=True):
    with obs.span("import", "dry_run" if dry_run else "commit") as st:
        rep = plan(db, root)
        if dry_run:
            st["count"] = rep["counts"]["new"]
            return {k: v for k, v in rep.items() if k != "items"}
        import ops
        snap = ops.snapshot(db, "pre-import") if db.execute("SELECT 1 FROM events LIMIT 1").fetchone() else (None, None)
        import_id = vault.uuid7()
        st_ids = {}
        try:
            for b in rep["items"]:
                eid, _ = vault.append(db, b["type"], b["subject"], b["payload"], "import:markdown", "unverified",
                                      key=b["key"], idempotency_key=b["idempotency_key"], import_id=import_id, commit=False)
                st_ids[b["block_id"]] = eid
            summary = {k: v for k, v in rep.items() if k != "items"}
            summary["import_id"] = import_id
            summary["owner_lines"] = [dict(k, event_id=st_ids[k["block_id"]]) for k in rep["owner_lines"]]
            db.execute("INSERT INTO import_runs(import_id, root, manifest_sha256, report) VALUES(?,?,?,?)",
                       (import_id, rep["root"], rep["manifest_sha256"], json.dumps(summary, ensure_ascii=False)))
            db.commit()
        except Exception:
            db.rollback()
            st["error_code"] = "ROLLBACK"
            raise
        vault.rebuild(db)
        vault.audit(db, "import:markdown", "import", "accepted", f"import {import_id}: {rep['counts']['new']} new")
        st["count"] = len(st_ids); summary["snapshot"] = snap[0]
        return summary


def approve(db, import_id, owner_lines, by=vault.HUMAN):
    r = db.execute("SELECT report FROM import_runs WHERE import_id=?", (import_id,)).fetchone()
    if not r:
        raise ValueError("unknown import_id")
    cands = {k["block_id"]: k["event_id"] for k in json.loads(r[0])["owner_lines"]}
    if owner_lines == "all":
        chosen = list(cands)
    else:
        chosen = [x.strip() for x in owner_lines.split(",") if x.strip()]
        bad = [x for x in chosen if x not in cands]
        if bad:
            raise ValueError(f"not in the dry-run owner_lines list: {bad}")
    targets = [cands[c] for c in chosen
               if (db.execute("SELECT status FROM proj_status WHERE event_id=?", (cands[c],)).fetchone() or [""])[0] == "proposed"]
    if not targets:
        raise ValueError("nothing to approve")
    eid = vault.append(db, "import.batch_approved", f"import:{import_id}", {"import_id": import_id, "confirmed_block_ids": chosen},
                       by, "verified", target_ids=targets)[0]
    vault.audit(db, by, "import_approve", "accepted", f"{len(targets)} owner line(s) confirmed", eid)
    return eid, len(targets)


def revert_import(db, import_id, by=vault.HUMAN, reason="revert-import"):
    ids = [r[0] for r in db.execute("""SELECT e.id FROM events e JOIN proj_status s ON s.event_id=e.id
                                       WHERE e.import_id=? AND s.status IN ('active','proposed') ORDER BY e.seq""", (import_id,))]
    if not ids:
        raise ValueError("nothing to revert for this import_id")
    eid = vault.append(db, "event.reverted", f"import:{import_id}", {"import_id": import_id, "reason": reason}, by, "verified",
                       target_ids=ids)[0]
    vault.audit(db, by, "revert_import", "accepted", f"{len(ids)} event(s) reverted", eid)
    return eid, len(ids)
