"""Operational procedures: snapshots, copy-to-new-file (redact / migrate), shred lifecycle, doctor.

The ONLY exception to "events are never rewritten" is the human-approved copy-to-new-file procedure
(`vault redact`, `vault migrate`): the source DB is never modified in place; a new file is written with the
redacted/migrated content and a fresh hash chain, and the redaction is recorded as a first-class event.
"""
import hashlib, json, os, re, shutil, sqlite3, tempfile, time
import vault, obs

SNAP_DROP = vault.PROJ_TABLES + ["review_queue", "url_cache"]   # derived/caches may hold plaintext of sensitive fields


def _sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 16), b""):
            h.update(b)
    return h.hexdigest()


def db_path(db):
    return db.execute("PRAGMA database_list").fetchone()[2]


def snapshot(db, label):
    """VACUUM INTO snapshots/<ts>-<label>.db, then strip derived tables (they hold decrypted plaintext) and write
    a .sha256 file. Encrypted fields stay ciphertext; keys.db is NEVER copied into a snapshot."""
    base = os.path.dirname(os.path.abspath(db_path(db)))
    d = os.path.join(base, "snapshots"); os.makedirs(d, mode=0o700, exist_ok=True)
    out = os.path.join(d, f"{time.strftime('%Y%m%dT%H%M%S')}-{int(time.time()*1000)%1000:03d}-{label}.db")
    db.execute("VACUUM INTO ?", (out,))
    s = sqlite3.connect(out)
    for t in SNAP_DROP:
        s.execute(f"DROP TABLE IF EXISTS {t}")
    s.commit(); s.execute("VACUUM"); s.close()
    os.chmod(out, 0o600)
    digest = _sha256_file(out)
    with open(out + ".sha256", "w") as f:
        f.write(f"{digest}  {os.path.basename(out)}\n")
    os.chmod(out + ".sha256", 0o600)
    obs.log(component="ops", op="snapshot", result="ok")
    return out, digest


def _copy(src, dst_path, transform_event=None, transform_audit=None):
    """Copy all log tables into a fresh schema-v2 DB, recomputing hash chains. Returns new connection."""
    if os.path.exists(dst_path):
        raise FileExistsError(dst_path)
    dst = vault.connect(dst_path)
    cols = [c[1] for c in dst.execute("PRAGMA table_info(events)") if c[1] not in ("seq", "recorded_at", "prev_hash", "hash")]
    prev = vault.GENESIS
    for r in src.execute("SELECT * FROM events ORDER BY seq"):
        row = {c: (r[c] if c in r.keys() else None) for c in cols}
        if transform_event:
            row = transform_event(row)
        row["prev_hash"] = prev; row["hash"] = vault.event_hash(prev, row); prev = row["hash"]
        ks = list(row)
        dst.execute(f"INSERT INTO events({','.join(ks)}) VALUES({','.join('?'*len(ks))})", [row[k] for k in ks])
    for t in ("event_parents", "event_targets", "redactions", "redacted_blocklist", "replicas"):
        if src.execute("SELECT 1 FROM sqlite_master WHERE name=?", (t,)).fetchone():
            rows = src.execute(f"SELECT * FROM {t}").fetchall()
            if rows:
                dst.executemany(f"INSERT INTO {t} VALUES({','.join('?'*len(rows[0]))})", [tuple(x) for x in rows])
    prev = vault.GENESIS
    for r in src.execute("SELECT * FROM audit ORDER BY id"):
        row = {k: r[k] for k in vault.AUDIT_HASH_FIELDS}
        if transform_audit:
            row = transform_audit(row)
        row["prev_hash"] = prev; row["hash"] = vault.audit_hash(prev, row); prev = row["hash"]
        dst.execute("INSERT INTO audit(ts,epoch,actor,action,outcome,reason,event_id,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?)",
                    [row[k] for k in ("ts", "epoch", "actor", "action", "outcome", "reason", "event_id", "prev_hash", "hash")])
    dst.commit()
    return dst


def migrate(old_path, new_path):
    """v0.3.x (schema 1) -> schema 2 by copy-to-new-file. lamport dropped, HLC derived from ts, hashes computed."""
    src = sqlite3.connect(old_path); src.row_factory = sqlite3.Row
    def tx(row):
        r = dict(row)
        ts = r.get("ts") or vault.now()
        ms = int(time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")) * 1000)
        r["hlc"] = f"{ms:012x}-{r.get('replica_seq') or 0:04x}-{r.get('replica_id') or 'local'}"
        p = json.loads(r["payload"])
        r["content_hash"] = vault.content_hash(r["type"], r["subject"], r.get("key"), p)
        r.setdefault("text_norm", "")
        return r
    with obs.span("ops", "migrate"):
        dst = _copy(src, new_path, tx)
        for r in src.execute("SELECT id, supersedes, target_id FROM events"):
            if r["supersedes"]:
                dst.execute("INSERT OR IGNORE INTO event_parents VALUES(?,?,'supersedes')", (r["id"], r["supersedes"]))
            if r["target_id"]:
                dst.execute("INSERT OR IGNORE INTO event_targets VALUES(?,?)", (r["id"], r["target_id"]))
        dst.commit(); vault.rebuild(dst)
    return dst


def _needles(payload):
    out = set()
    def walk(x):
        if isinstance(x, dict):
            for v in x.values(): walk(v)
        elif isinstance(x, list):
            for v in x: walk(v)
        elif isinstance(x, str) and len(x) >= 4:
            out.add(x)
    walk(payload)
    return out


def file_bytes_contain(path, needles):
    """Return needles found in the DB file or any sidecar (-journal/-wal/-shm), incl. FTS pages; checks raw + tr_norm."""
    found = set()
    for p in (path, path + "-journal", path + "-wal", path + "-shm"):
        if os.path.exists(p):
            data = open(p, "rb").read()
            for n in needles:
                # whole string (raw + Turkish-folded) and its long tokens (FTS stores single tokens)
                variants = {n, vault.tr_norm(n)} | {t for t in re.findall(r"\w+", vault.tr_norm(n)) if len(t) >= 8}
                if any(v.encode() in data for v in variants if len(v) >= 4):
                    found.add(n)
    return sorted(found)


def redact(db, event_id, out_path, reason, approved_by=vault.HUMAN, take_snapshot=True):
    """Human-only redact + copy to new file. Source untouched (except an audit line). Returns report dict."""
    src_path = db_path(db)
    e = db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
    if not e:
        raise ValueError("unknown event")
    original = vault.decrypt_payload(db, e) or {}
    # strings unique to this event's content (provenance and values shared with other events are not "the secret")
    others = set()
    for r in db.execute("SELECT * FROM events WHERE id<>?", (event_id,)):
        others |= _needles({k: v for k, v in (vault.decrypt_payload(db, r) or {}).items()})
        others |= {r["subject"], r["key"] or ""}
        others |= set(r["text_norm"].split())
    needles = {n for n in _needles({k: v for k, v in original.items() if k != "provenance"})
               if n not in others and vault.tr_norm(n) not in others and n not in (e["subject"], e["type"], e["key"])}
    head = (db.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone() or [vault.GENESIS])[0]
    snap = snapshot(db, "pre-redact") if take_snapshot else (None, None)
    with obs.span("ops", "redact") as st:
        rid = f"r_{int(time.time()*1000)}"
        def tx(row):
            if row["id"] == event_id:
                row = dict(row); row["payload"] = vault.canon({"redacted": True, "redaction_id": rid})
                row["payload_ct"] = None; row["enc_key_id"] = None; row["text_norm"] = ""
            return row
        def tx_audit(row):
            if row["event_id"] == event_id:
                row = dict(row); row["reason"] = "[redacted]"
            return row
        dst = _copy(db, out_path, tx, tx_audit)
        dst.execute("INSERT INTO redactions(kind,scope,key_id,approved_by,reason,source_head_hash) VALUES('redact_copy',?,?,?,?,?)",
                    (f"event:{event_id}", e["enc_key_id"], approved_by, reason, head))
        dst.execute("INSERT OR IGNORE INTO redacted_blocklist(event_id, content_hash) VALUES(?,?)", (event_id, e["content_hash"]))
        dst.commit()
        vault.append(dst, "event.redacted", f"event:{event_id}", {"redaction_id": rid, "reason": reason}, approved_by,
                     "verified", target_ids=[event_id])
        vault.audit(dst, approved_by, "redact", "accepted", f"redaction {rid}", event_id)
        dst.execute("VACUUM"); dst.close()
        vault.audit(db, approved_by, "redact", "accepted", f"redacted copy written ({rid})", event_id)
        os.chmod(out_path, 0o600)
        leaks = file_bytes_contain(out_path, needles)
        st["error_code"] = "LEAK" if leaks else None
    return {"out": out_path, "redaction_id": rid, "verified_absent": not leaks, "leaked_count": len(leaks),
            "checked_strings": len(needles), "snapshot": snap[0],
            "warning": "the pre-redact snapshot still contains the redacted data; delete it after verifying the new file" if snap[0] else None}


def shred_preview(db, subject):
    enc = db.execute("SELECT count(*) FROM events WHERE subject=? AND enc_key_id IS NOT NULL", (subject,)).fetchone()[0]
    plain = db.execute("SELECT count(*) FROM events WHERE subject=? AND enc_key_id IS NULL", (subject,)).fetchone()[0]
    info = vault.keystore(db).info(subject)
    return {"subject": subject, "encrypted_events": enc, "plaintext_events": plain, "key": info,
            "note": "plaintext (non-sensitive) fields are NOT removed by shredding; use `vault redact` for those"}


def shred_confirm(db, subject, grace_days, by=vault.HUMAN):
    snap = snapshot(db, "pre-shred")
    with obs.span("ops", "shred_schedule"):
        info = vault.keystore(db).schedule_destroy(subject, grace_days, by)
        vault.audit(db, by, "shred_schedule", "accepted", f"key {info['key_id']} pending destroy ({grace_days}d)")
    return {"key": info, "snapshot": snap[0]}


def shred_cancel(db, subject, by=vault.HUMAN):
    vault.keystore(db).cancel(subject)
    vault.audit(db, by, "shred_cancel", "accepted", "pending destroy cancelled")


def shred_finalize(db, subject, by=vault.HUMAN):
    with obs.span("ops", "shred_finalize"):
        kid = vault.keystore(db).finalize(subject)
        db.execute("INSERT INTO redactions(kind,scope,key_id,approved_by,reason) VALUES('shred',?,?,?,?)",
                   (f"subject:{subject}", kid, by, "crypto-shred"))
        db.commit()
        vault.append(db, "subject.shredded", subject, {"key_id": kid}, by, "verified")   # first-class event; rebuilds
        vault.audit(db, by, "shred_finalize", "accepted", f"key {kid} destroyed")
        db.execute("VACUUM")
    return kid


def _projection_pair(db):
    """(stored projection_hash, hash of a fresh in-memory rebuild of the log). Read-only for db."""
    mem = sqlite3.connect(":memory:"); mem.row_factory = sqlite3.Row
    db.backup(mem)
    before = vault.projection_hash(db)
    ks = vault._KEYSTORE.get(db_path(db))
    if ks is None and db.execute("SELECT 1 FROM events WHERE enc_key_id IS NOT NULL LIMIT 1").fetchone():
        try:
            ks = vault.keystore(db)       # load the vault's own keystore so the in-memory rebuild decrypts the same way
        except Exception:
            ks = None
    mem_keys = (":memory:", "")          # PRAGMA database_list reports '' for an in-memory DB
    try:
        if ks is not None:
            for k in mem_keys:
                vault._KEYSTORE[k] = ks
        vault.rebuild(mem)
        after = vault.projection_hash(mem)
    finally:
        for k in mem_keys:
            vault._KEYSTORE.pop(k, None)
    return before, after


def verify(db):
    """`vault verify`: full event + audit hash-chain verify and projection hash vs a fresh rebuild. No writes."""
    problems = vault.check_triggers(db) + vault.verify_chains(db)
    before, after = _projection_pair(db)
    if before != after:
        problems.append("projections differ from a fresh rebuild of the log")
    n = db.execute("SELECT count(*) FROM events").fetchone()[0]
    head = (db.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone() or [vault.GENESIS])[0]
    return {"ok": not problems, "problems": problems, "event_count": n, "chain_head": head,
            "projection_hash": before, "projection_matches_log": before == after}


def doctor(db, decrypt_all=False):
    """Append-only integrity, projection vs log, orphan keys, shredded-but-still-readable, key decryptability
    (every live DEK unwrapped with the KEK; one sampled event per key, or every encrypted event with decrypt_all).
    Returns {ok, problems, checks}."""
    problems = vault.check_triggers(db) + vault.verify_chains(db)
    checks = {"triggers_and_chains": not problems}
    ic = [r[0] for r in db.execute("PRAGMA integrity_check")]
    qc = [r[0] for r in db.execute("PRAGMA quick_check")]
    checks["integrity_check"] = ic[0] if ic == ["ok"] else ic[:5]
    checks["quick_check"] = qc[0] if qc == ["ok"] else qc[:5]
    if ic != ["ok"] or qc != ["ok"]:
        problems.append("sqlite integrity_check/quick_check failed")
    before, after = _projection_pair(db)
    checks["projection_matches_log"] = before == after
    if before != after:
        problems.append("projections differ from a fresh rebuild of the log")
    enc_ids = {r[0] for r in db.execute("SELECT DISTINCT enc_key_id FROM events WHERE enc_key_id IS NOT NULL")}
    keys = []
    checks["keystore"] = "absent"
    try:
        keys = vault.keystore(db).all_keys()      # never creates keys.db / a KEK (read path)
        checks["keystore"] = "ok"
    except Exception as e:
        import crypto_keys
        if not isinstance(e, crypto_keys.KeystoreMissing) or "no KEK" in str(e):
            checks["keystore"] = "unavailable"
            problems.append(f"keystore unavailable: {type(e).__name__}" + (" (KEK missing)" if "no KEK" in str(e) else ""))
        # plain "no keys.db": unshredded encrypted events are reported below as missing keys
    key_ids = {k["key_id"] for k in keys}
    shredded_log = set()
    for r in db.execute("SELECT payload FROM events WHERE type='subject.shredded'"):
        try:
            kid = json.loads(r[0]).get("key_id")
        except (ValueError, AttributeError):
            kid = None
        if kid:
            shredded_log.add(kid)
    destroyed = {k["key_id"] for k in keys if not k["has_dek"]}
    orphans = sorted(key_ids - enc_ids)
    missing = sorted(enc_ids - key_ids - shredded_log)
    checks["orphan_keys"] = orphans; checks["events_with_missing_keys"] = len(missing)
    checks["shredded_keys"] = len((enc_ids & shredded_log) | (enc_ids & destroyed))
    if missing:
        problems.append(f"{len(missing)} key id(s) referenced by events are missing from keys.db")
    dec = {"keys_checked": 0, "events_checked": 0, "bad_keys": [], "bad_events": [], "mode": "all" if decrypt_all else "sample"}
    if keys:
        try:
            import crypto_keys
            ks = vault.keystore(db)
            dec.update(crypto_keys.trial_decrypt(ks.db, db, ks.kek, None if decrypt_all else 1))
        except Exception as e:
            problems.append(f"decrypt check failed: {type(e).__name__}")
    checks["decrypt"] = {"mode": dec["mode"], "keys_checked": dec["keys_checked"], "events_checked": dec["events_checked"],
                         "undecryptable_keys": len(dec["bad_keys"]), "undecryptable_events": len(dec["bad_events"])}
    if dec["bad_keys"]:
        problems.append(f"{len(dec['bad_keys'])} key(s) cannot be unwrapped with the current KEK (wrong keys.kek / "
                        f"VAULT_PASSPHRASE?): encrypted fields are undecryptable")
    if dec["bad_events"]:
        problems.append(f"{len(dec['bad_events'])} encrypted event(s) fail to decrypt")
    readable = 0
    for k in keys:
        if not k["has_dek"]:
            for r in db.execute("SELECT * FROM events WHERE enc_key_id=?", (k["key_id"],)):
                if vault.decrypt_payload(db, r) is not None:
                    readable += 1
                st = db.execute("SELECT status FROM proj_status WHERE event_id=?", (r["id"],)).fetchone()
                if st and st[0] not in ("redacted",) and r["type"] not in vault.META_TYPES:
                    readable += 1
    checks["shredded_but_readable"] = readable
    if readable:
        problems.append(f"{readable} shredded event(s) still readable or not marked redacted")
    blocked = db.execute("""SELECT count(*) FROM events e JOIN redacted_blocklist b ON b.event_id=e.id
                            WHERE json_extract(e.payload,'$.redacted') IS NOT 1""").fetchone()[0]
    checks["blocklisted_but_present"] = blocked
    if blocked:
        problems.append(f"{blocked} blocklisted event(s) still carry content")
    warnings = []
    lp = obs._path()
    try:
        fd = os.open(lp, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600); os.close(fd)
        checks["ops_log_writable"] = True
    except OSError as e:
        checks["ops_log_writable"] = False
        warnings.append(f"ops log {lp} is not writable ({type(e).__name__}); obs.log() drops records silently")
    # forward-compat (docs/schema-evolution.md): events written by a newer schema than this code knows
    unknown = [r["id"] for r in db.execute("SELECT id, type, schema_version FROM events ORDER BY seq")
               if vault.is_unknown_version(r)]
    checks["unknown_version_events"] = len(unknown)
    if unknown:
        problems.append(f"{len(unknown)} event(s) have a schema_version newer than this code; excluded from "
                        f"projections until upgrade (first: {unknown[0]})")
    return {"ok": not problems, "problems": problems, "warnings": warnings, "checks": checks}
