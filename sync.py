"""File-based multi-device sync prototype (`.vaultsync` packages). See docs/sync.md.

Package = line 1: manifest JSON; lines 2..n: body JSONL (one origin event per line, sorted by (hlc, id)).
No network code. Additive schema only (CREATE TABLE IF NOT EXISTS); existing tables/triggers untouched.
"""
import base64, hashlib, json, os, secrets, time
import vault

FORMAT = "vaultsync/0.1"
MAX_SKEW_MS = int(os.environ.get("VAULT_SYNC_MAX_SKEW_MS", str(5 * 60 * 1000)))   # remote HLC may be ≤ 5 min ahead

SCHEMA = """
CREATE TABLE IF NOT EXISTS sync_device (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sync_imported (            -- chain-of-imports record: origin row + origin hash per event
  event_id TEXT PRIMARY KEY, origin_device TEXT NOT NULL, origin_hash TEXT NOT NULL,
  origin_row TEXT NOT NULL CHECK (json_valid(origin_row)), package_sha256 TEXT NOT NULL,
  quarantined INTEGER NOT NULL DEFAULT 0,
  at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE TABLE IF NOT EXISTS sync_quarantine (          -- held, NOT in events: never projected, never verified (no signing yet)
  event_id TEXT PRIMARY KEY, origin_device TEXT NOT NULL, type TEXT NOT NULL, actor TEXT NOT NULL,
  origin_row TEXT NOT NULL CHECK (json_valid(origin_row)), package_sha256 TEXT NOT NULL, reason TEXT NOT NULL,
  at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE TABLE IF NOT EXISTS sync_packages (
  body_sha256 TEXT PRIMARY KEY, source_device TEXT NOT NULL, report TEXT NOT NULL CHECK (json_valid(report)),
  at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
"""


class SyncError(ValueError):
    pass


UNSUPPORTED_WARNING = ("WARNING: multi-device sync is an unsigned prototype. Do not use it with real data: no package signing, "
                       "no key sync, no redaction/shred propagation. user:* and approval events are quarantined, not applied.")


def _quarantine_reason(e, parents_held):
    """Until package signing exists, nothing that could carry the owner's authority is applied from a package."""
    if e["actor"].startswith("user:"):
        return "unsigned user:* event"
    if e["type"] in vault.HUMAN_ONLY_TYPES:
        return "unsigned approval/human-only event"
    if any(p in parents_held for p, _ in e["parents"]):
        return "parent quarantined"
    return None


def quarantined(db):
    if not _has(db, "sync_quarantine"):
        return []
    return [dict(r) for r in db.execute(
        "SELECT event_id, origin_device, type, actor, reason, package_sha256, at FROM sync_quarantine ORDER BY at, event_id")]


def _has(db, name):
    return db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (name,)).fetchone() is not None


def ensure_schema(db):
    db.executescript(SCHEMA)


def device_id(db, create=True):
    """Stable per-vault device id (dev-<16 hex>), created on first use."""
    if _has(db, "sync_device"):
        r = db.execute("SELECT v FROM sync_device WHERE k='device_id'").fetchone()
        if r:
            return r[0]
    if not create:
        return None
    ensure_schema(db)
    d = "dev-" + secrets.token_hex(8)
    db.execute("INSERT INTO sync_device VALUES('device_id', ?)", (d,)); db.commit()
    return d


def pair(db, dev, name, actor=vault.HUMAN):
    """Register a device of the same owner (human-only at the CLI). Uses the existing `replicas` table."""
    ensure_schema(db)
    db.execute("INSERT OR IGNORE INTO replicas(replica_id, device_name, added_by) VALUES(?,?,?)", (dev, name, actor))
    db.commit()


def _hlc_ms(h):
    return int(h[:12], 16)


def _origin_rows(db, me):
    """Every event as it looked on its origin device: (origin_device, origin_row dict, parents list)."""
    imp = {}
    if _has(db, "sync_imported"):
        imp = {r[0]: (r[1], json.loads(r[2])) for r in db.execute("SELECT event_id, origin_device, origin_row FROM sync_imported")}
    out = []
    for r in db.execute("SELECT * FROM events ORDER BY hlc, id"):
        if r["id"] in imp:
            dev, row = imp[r["id"]]
        else:
            dev = me
            row = {k: r[k] for k in vault.EVENT_HASH_FIELDS + ("prev_hash", "hash")}
            row["payload_ct"] = base64.b64encode(r["payload_ct"]).decode() if r["payload_ct"] else None
            row["parents"] = [[p[0], p[1]] for p in db.execute(
                "SELECT parent_id, rel FROM event_parents WHERE event_id=? ORDER BY rel, parent_id", (r["id"],))]
            row["targets"] = [t[0] for t in db.execute("SELECT target_id FROM event_targets WHERE event_id=? ORDER BY target_id", (r["id"],))]
            sg = db.execute("SELECT key_id, alg, sig FROM event_sigs WHERE event_id=?", (r["id"],)).fetchone() \
                if _has(db, "event_sigs") else None
            if sg:   # the origin hash binds the signature (vault.event_hash v2); the receiver needs it to verify the hash.
                row["sig"] = {"key_id": sg[0], "alg": sg[1], "sig": sg[2]}   # NOT verified on import yet (ADR 0011)
        out.append((dev, row))
    return out


def _vkey(dev, row):
    return f"{dev}/{row['replica_id']}"     # a device may host several local replica_ids (e.g. 'local')


def export(db, out_path, since_peer=None):
    me = device_id(db)
    known = {}
    if since_peer:
        known = {r[0]: r[1] for r in db.execute("SELECT origin_replica, max_replica_seq FROM sync_peer_state WHERE peer_replica_id=?", (since_peer,))}
    vector, lines = {}, []
    for dev, row in _origin_rows(db, me):
        k = _vkey(dev, row)
        vector[k] = max(vector.get(k, 0), row["replica_seq"])
        if row["replica_seq"] > known.get(k, 0):
            lines.append(vault.canon({"origin_device": dev, **row}))
    body = ("\n".join(lines) + "\n" if lines else "").encode()
    manifest = {"format": FORMAT, "source_device": me, "created_at": vault.now(), "vector": vector,
                "since": known, "event_count": len(lines), "body_sha256": hashlib.sha256(body).hexdigest(),
                "signature": None}
    tmp = out_path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(vault.canon(manifest).encode() + b"\n" + body)
    os.replace(tmp, out_path)
    return manifest


def _parse(path):
    raw = open(path, "rb").read()
    head, _, body = raw.partition(b"\n")
    try:
        m = json.loads(head)
    except ValueError:
        raise SyncError("not a .vaultsync package (bad manifest)")
    if m.get("format") != FORMAT:
        raise SyncError(f"unsupported package format {m.get('format')!r}")
    if hashlib.sha256(body).hexdigest() != m.get("body_sha256"):
        raise SyncError("body sha256 mismatch: package corrupted or tampered")
    evs = [json.loads(l) for l in body.decode().splitlines() if l.strip()]
    if len(evs) != m.get("event_count"):
        raise SyncError("event_count mismatch")
    return m, evs


def _verify_event(e):
    row = dict(e)
    row["payload_ct"] = base64.b64decode(e["payload_ct"]) if e.get("payload_ct") else None
    row["_sig"] = (e.get("sig") or {}).get("sig")
    if vault.event_hash(e["prev_hash"], row) != e["hash"]:
        raise SyncError(f"event {e['id']}: hash mismatch (tampered)")
    if vault.content_hash(e["type"], e["subject"], e["key"], json.loads(e["payload"])) != e["content_hash"]:
        raise SyncError(f"event {e['id']}: content_hash mismatch")
    return row


def import_package(db, path, dry_run=False, now_ms=None, _trust_unsigned=False):
    """Verify then merge a package. All-or-nothing; idempotent (union by event id).

    user:* and human-only (approval/revert/redact/shred/...) events are stored in `sync_quarantine` and not applied,
    because packages are unsigned. `_trust_unsigned` restores the old paired-device behaviour; tests only, no CLI/env."""
    m, evs = _parse(path)
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    me = device_id(db, create=not dry_run)
    paired = {r[0] for r in db.execute("SELECT replica_id FROM replicas")} | {me}
    have = {r[0] for r in db.execute("SELECT id FROM events")}
    held = {r[0] for r in db.execute("SELECT event_id FROM sync_quarantine")} if _has(db, "sync_quarantine") else set()
    rep = {"source_device": m["source_device"], "events": len(evs), "new": 0, "duplicate": 0, "quarantined": 0,
           "skipped": [], "dry_run": dry_run}
    todo, skew = [], []
    for e in sorted(evs, key=lambda x: (x["hlc"], x["id"])):
        row = _verify_event(e)
        if _hlc_ms(e["hlc"]) > now_ms + MAX_SKEW_MS:
            skew.append(e["id"])
        if e["id"] in have or e["id"] in held:
            rep["duplicate"] += 1; continue
        todo.append((e, row))
    hold = []
    if not _trust_unsigned:
        rest = []
        for e, row in todo:   # (hlc, id) order, so a parent is classified before its children
            why = _quarantine_reason(e, held)
            if why:
                held.add(e["id"]); hold.append((e, why))
            else:
                rest.append((e, row))
        todo = rest
    if skew:
        raise SyncError(f"clock skew: {len(skew)} event(s) have HLC > now + {MAX_SKEW_MS} ms (first {skew[0]}); package rejected")
    ids_in = have | {e["id"] for e, _ in todo}
    for e, _ in todo:
        missing = [p for p, rel in e["parents"] if rel == "supersedes" and p not in ids_in]
        if missing:
            raise SyncError(f"event {e['id']}: missing parent {missing[0]} (causal gap; import the earlier package first)")
    blocked = {r[0] for r in db.execute("SELECT content_hash FROM redacted_blocklist")} | \
              {r[0] for r in db.execute("SELECT event_id FROM redacted_blocklist")}
    plan = []
    for e, row in todo:
        if e["content_hash"] in blocked or e["id"] in blocked:
            rep["skipped"].append({"id": e["id"], "reason": "redaction blocklist"}); continue
        local = dict(row); local.pop("_sig", None)   # local copy is stored without the origin signature (remote-unsigned)
        local["replica_id"] = e["origin_device"] if row["replica_id"] == "local" else row["replica_id"]
        quarantine = e["origin_device"] not in paired and e["actor"].startswith("user:")
        if quarantine:
            if e["type"] in vault.SIGNED_TYPES:
                rep["skipped"].append({"id": e["id"], "reason": "human-only event from unpaired device"}); continue
            local["actor"], local["trust"] = f"import:sync-{e['origin_device']}", "unverified"
            rep["quarantined"] += 1
        plan.append((e, local, quarantine))
    rep["new"] = len(plan)
    if not _trust_unsigned:
        rep["quarantined"] = len(hold)
    if dry_run:
        return rep
    ensure_schema(db)
    try:
        prev = (db.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone() or [vault.GENESIS])[0]
        for e, local, q in plan:
            p_ = {k: v for k, v in json.loads(local["payload"]).items()}
            local["text_norm"] = "" if local["enc_key_id"] else vault.tr_norm(
                f"{local['type']} {local['subject']} {vault._flatten({k: v for k, v in p_.items() if k != 'provenance'})}")
            local["prev_hash"] = prev
            local["hash"] = prev = vault.event_hash(prev, local)
            cols = list(vault.EVENT_HASH_FIELDS) + ["payload_ct", "text_norm", "prev_hash", "hash"]
            db.execute(f"INSERT INTO events({','.join(cols)}) VALUES({','.join('?' * len(cols))})", [local[c] for c in cols])
            for pid, rel in e["parents"]:
                db.execute("INSERT OR IGNORE INTO event_parents VALUES(?,?,?)", (e["id"], pid, rel))
            for t in e.get("targets", []):
                db.execute("INSERT OR IGNORE INTO event_targets VALUES(?,?)", (e["id"], t))
            orig = {k: v for k, v in e.items() if k != "origin_device"}
            db.execute("INSERT INTO sync_imported(event_id, origin_device, origin_hash, origin_row, package_sha256, quarantined) "
                       "VALUES(?,?,?,?,?,?)", (e["id"], e["origin_device"], e["hash"], vault.canon(orig), m["body_sha256"], int(q)))
        for e, why in hold:
            orig = {k: v for k, v in e.items() if k != "origin_device"}
            db.execute("INSERT OR IGNORE INTO sync_quarantine(event_id, origin_device, type, actor, origin_row, package_sha256, reason) "
                       "VALUES(?,?,?,?,?,?,?)", (e["id"], e["origin_device"], e["type"], e["actor"], vault.canon(orig),
                                                 m["body_sha256"], why))
        # the source device holds everything in its vector -> watermark for `--since-peer <source>`
        for k, v in m["vector"].items():
            db.execute("""INSERT INTO sync_peer_state VALUES(?,?,?) ON CONFLICT(peer_replica_id, origin_replica)
                          DO UPDATE SET max_replica_seq=max(max_replica_seq, excluded.max_replica_seq)""", (m["source_device"], k, v))
        db.execute("INSERT OR IGNORE INTO sync_packages(body_sha256, source_device, report) VALUES(?,?,?)",
                   (m["body_sha256"], m["source_device"], json.dumps(rep)))
        db.commit()
    except Exception:
        db.rollback(); raise
    vault.rebuild(db)
    vault.audit(db, vault.HUMAN, "sync_import", "accepted" if plan else "duplicate",
                f"{len(plan)} new, {rep['duplicate']} dup, {rep['quarantined']} quarantined from {m['source_device']}")
    return rep
