"""Crypto-shredding lifecycle across devices (docs/adr/0014-crypto-shredding.md).

The log is the source of truth; keys.db follows it. Three user-signed event types (all `subject.*`, never writable
by agents):
  subject.shred_scheduled {key_id, grace_seconds}   `vault shred SUBJECT --confirm`  -> key pending_destroy
  subject.shred_cancelled {key_id}               `vault shred-cancel SUBJECT`     -> key active again
  subject.shredded        {key_id}               `vault shred-finalize SUBJECT`   -> key destroyed
Every local operation writes its signed event FIRST and then changes keys.db (a separate database, so the two can
never share a transaction). `reconcile` makes keys.db match the log and is idempotent: it runs on vault open (when
something is due), in doctor, after sync-import and after a quarantine release, so an interrupted operation (local or
synced) is completed by the next run. Reads of a key named by an applied `subject.shredded` are refused at once
(vault.shred_applies), whatever keys.db says.

An event counts only if: its key belongs to the event's subject in keys.db; it re-verifies now (local: a valid
signature; synced: `remote-signed`); its origin device is not revoked for key transport. Otherwise it is noted once in
`sync_key_quarantine` and ignored. Decision per key: a valid `subject.shredded` wins; otherwise the latest valid
scheduled/cancelled event by (hlc, id). Synced schedules and shreds use the LOCAL grace period from the moment they
are applied (ADR 0013 M1); a local `subject.shredded` (the user already finalized here) destroys at once.
Reconcile never finalizes a mere schedule: destruction needs a `subject.shredded` (local `shred-finalize` or synced).
"""
import json, os, sys, time
import vault

SCHEDULED, CANCELLED, SHREDDED = "subject.shred_scheduled", "subject.shred_cancelled", "subject.shredded"
LIFECYCLE = (SCHEDULED, CANCELLED, SHREDDED)
SYSTEM_ACTOR = "system:sync-reconcile"   # automatic reconcile is not a human action (audit actor)

SCHEMA = """
CREATE TABLE IF NOT EXISTS shred_reconciled (   -- lifecycle events whose effect is final here (skip on open)
  event_id TEXT PRIMARY KEY, outcome TEXT NOT NULL, due REAL,          -- due: epoch when it needs another look
  at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
"""


def grace_days():
    return float(os.environ.get("VAULT_SHRED_GRACE_DAYS", "7"))


def _has(db, t):
    return db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (t,)).fetchone() is not None


def lifecycle_events(db):
    """[(id, type, subject, key_id, origin_device|None, hlc, actor, payload)] in (hlc, id) order."""
    imp = _has(db, "sync_imported")
    q = (f"SELECT e.id, e.type, e.subject, e.payload, {'i.origin_device' if imp else 'NULL'}, e.hlc, e.actor FROM events e "
         + ("LEFT JOIN sync_imported i ON i.event_id=e.id " if imp else "")
         + f"WHERE e.type IN ({','.join('?' * len(LIFECYCLE))}) ORDER BY e.hlc, e.id")
    out = []
    for eid, t, subj, payload, origin, hlc, actor in db.execute(q, LIFECYCLE):
        try:
            p = json.loads(payload)
            kid = p.get("key_id") if isinstance(p, dict) else None
        except ValueError:
            p, kid = {}, None
        out.append((eid, t, subj, kid if isinstance(kid, str) else None, origin, hlc, actor, p))
    return out


def needs_reconcile(db, now=None):
    """Cheap check for vault open: any lifecycle event not final here, or one whose due time has come."""
    if not db.execute(f"SELECT 1 FROM events WHERE type IN ({','.join('?' * len(LIFECYCLE))}) LIMIT 1", LIFECYCLE).fetchone():
        return False
    if not _has(db, "shred_reconciled"):
        return True
    now = now if now is not None else time.time()
    return db.execute(f"""SELECT 1 FROM events e LEFT JOIN shred_reconciled r ON r.event_id=e.id
                          WHERE e.type IN ({','.join('?' * len(LIFECYCLE))}) AND (r.event_id IS NULL OR
                          (r.due IS NOT NULL AND r.due <= ?)) LIMIT 1""", (*LIFECYCLE, now)).fetchone() is not None


def _revoked(db):
    return {r[0] for r in db.execute("SELECT device_id FROM sync_ka_revoked")} if _has(db, "sync_ka_revoked") else set()


def _note_once(db, eid, kid, origin, why):
    import key_transport as kt
    kt.ensure_schema(db)
    if db.execute("INSERT OR IGNORE INTO sync_shred_handled(event_id, key_id, action) VALUES(?,?,?)",
                  (eid, kid, "ignored: " + why)).rowcount:
        kt._q(db, "-", origin, kid, f"{why}: ignored")


def _valid(db, ev, ks_subject, revoked, cls):
    """None if the event may act on its key, else the reason it is ignored."""
    eid, t, subj, kid, origin, hlc, actor, p = ev
    if origin is not None and origin in revoked:
        return "lifecycle event from a device revoked for key transport"
    if ks_subject != subj:
        return "lifecycle event names a key of another subject"
    if not actor.startswith("user:"):
        return "lifecycle event from a non-user actor"
    import signing
    if signing.HAVE_CRYPTO:
        if not cls:
            cls.update(signing.classify(db))
        st = (cls.get(eid) or (None, None))[1]
        ok = ("remote-signed",) if origin is not None else ("signed", "legacy-unsigned", "legacy-attested")
        if st not in ok:
            return f"lifecycle event does not re-verify ({st})"
    return None


def _record_args(db, ev):
    eid, t, subj, kid, origin, hlc, actor, p = ev
    signer = actor if actor.startswith("user:") else vault.HUMAN
    reason = "crypto-shred" if origin is None else f"crypto-shred (synced from {origin}; applied by {SYSTEM_ACTOR})"
    return (f"subject:{subj}", kid, signer, reason)


def _ensure_record(db, ev):
    if not db.execute("SELECT 1 FROM redactions WHERE kind='shred' AND key_id=?", (ev[3],)).fetchone():
        db.execute("INSERT INTO redactions(kind,scope,key_id,approved_by,reason) VALUES('shred',?,?,?,?)", _record_args(db, ev))
        return True
    return False


def plan(db, ks, now=None):
    """Decide per key from the log. Returns ({key_id: (decision, event)}, ignored[(event, reason)]). Read-only."""
    now = now if now is not None else time.time()
    rows = {r[0]: r[1] for r in ks.db.execute("SELECT key_id, subject FROM subject_keys")}
    revoked, cls, dec, ignored = _revoked(db), {}, {}, []
    shred = {}
    for ev in lifecycle_events(db):
        kid = ev[3]
        if kid is None or kid not in rows:
            continue
        why = _valid(db, ev, rows[kid], revoked, cls)
        if why:
            ignored.append((ev, why)); continue
        if ev[1] == SHREDDED:
            if kid not in shred or (ev[4] is None and shred[kid][4] is not None):   # a local shred wins
                shred[kid] = ev
        else:
            dec[kid] = ("schedule" if ev[1] == SCHEDULED else "cancel", ev)        # latest by (hlc, id)
    for kid, ev in shred.items():
        dec[kid] = ("destroy-now" if ev[4] is None else "destroy-after-grace", ev)
    return dec, ignored


def reconcile(db, now=None):
    """Make keys.db follow the log (see module doc). Returns {"pending", "destroyed", "cancelled", "records"}."""
    rep = {"pending": [], "destroyed": [], "cancelled": [], "records": []}
    import crypto_keys
    if not crypto_keys.HAVE_CRYPTO or not db.execute(
            f"SELECT 1 FROM events WHERE type IN ({','.join('?' * len(LIFECYCLE))}) LIMIT 1", LIFECYCLE).fetchone():
        return rep
    db.executescript(SCHEMA)
    try:
        ks = vault.keystore(db)
    except (crypto_keys.KeystoreMissing, FileNotFoundError):
        # no keys here: nothing to destroy. Mark the events seen so open stays quiet; a later key import runs a full
        # reconcile (plan() always reads the whole log), and import refuses keys named by a shred.
        for ev in lifecycle_events(db):
            db.execute("INSERT OR IGNORE INTO shred_reconciled(event_id, outcome) VALUES(?, 'no keystore')", (ev[0],))
        db.commit()
        return rep
    now = now if now is not None else time.time()
    dec, ignored = plan(db, ks, now)
    state = {r[0]: (r[1], r[2], r[3], r[4]) for r in ks.db.execute(
        "SELECT key_id, subject, state, destroy_after, wrapped_dek IS NOT NULL FROM subject_keys")}
    done = {}   # event_id -> (outcome, due)
    try:
        for ev, why in ignored:
            _note_once(db, ev[0], ev[3], ev[4], why); done[ev[0]] = ("ignored", None)
        for kid, (d, ev) in dec.items():
            subj, st, after, live = state[kid]
            if d == "destroy-now" or (d == "destroy-after-grace" and live and st == "pending_destroy"
                                      and after is not None and after <= now):
                if live:
                    ks.destroy(kid); rep["destroyed"].append(kid)
                if _ensure_record(db, ev):
                    rep["records"].append(kid)
                done[ev[0]] = ("destroyed", None)
            elif d == "destroy-after-grace":
                if not live:
                    if _ensure_record(db, ev):
                        rep["records"].append(kid)
                    done[ev[0]] = ("destroyed", None); continue
                if st == "active":
                    after = now + grace_days() * 86400
                    ks.set_pending(kid, after, f"sync:{ev[4]}"); rep["pending"].append(kid)
                done[ev[0]] = ("pending", after)
            elif d == "schedule":
                if live and st == "active":
                    g = ev[7].get("grace_seconds") if isinstance(ev[7], dict) else None
                    if ev[4] is None and isinstance(g, int) and not isinstance(g, bool) and g >= 0:   # local: the grace the user chose
                        after = int(ev[5][:12], 16) / 1000 + g
                    else:                                                       # synced: local grace from now
                        after = now + grace_days() * 86400
                    ks.set_pending(kid, after, vault.HUMAN if ev[4] is None else f"sync:{ev[4]}")
                    rep["pending"].append(kid)
                done[ev[0]] = ("scheduled", None)
            elif d == "cancel":
                if live and st == "pending_destroy":
                    ks.set_active(kid); rep["cancelled"].append(kid)
                done[ev[0]] = ("cancelled", None)
        # superseded lifecycle events (an older schedule/cancel) are final too
        for ev in lifecycle_events(db):
            done.setdefault(ev[0], ("superseded" if ev[3] in state else "no local key", None))
        for eid, (outcome, due) in done.items():
            db.execute("INSERT INTO shred_reconciled(event_id, outcome, due) VALUES(?,?,?) ON CONFLICT(event_id) "
                       "DO UPDATE SET outcome=excluded.outcome, due=excluded.due", (eid, outcome, due))
        db.commit()
    except Exception:
        db.rollback(); raise
    if rep["destroyed"] or rep["pending"] or rep["cancelled"] or rep["records"]:
        if rep["destroyed"]:
            db.execute("VACUUM")
        vault.rebuild(db)
        vault.audit(db, SYSTEM_ACTOR, "shred_reconciled", "accepted",
                    f"{len(rep['pending'])} pending, {len(rep['destroyed'])} destroyed, {len(rep['cancelled'])} cancelled, "
                    f"{len(rep['records'])} record(s) written")
    return rep


def problems(db, now=None):
    """Read-only shred invariants for verify/doctor. Returns (errors, warnings); ids only."""
    import crypto_keys
    errs, warns = [], []
    if not crypto_keys.HAVE_CRYPTO:
        return errs, warns
    try:
        ks = vault.keystore(db)
    except Exception:
        return errs, warns
    now = now if now is not None else time.time()
    dec, _ = plan(db, ks, now)
    state = {r[0]: (r[1], r[2], r[3], r[4]) for r in ks.db.execute(
        "SELECT key_id, subject, state, destroy_after, wrapped_dek IS NOT NULL FROM subject_keys")}
    for kid, (d, ev) in dec.items():
        subj, st, after, live = state[kid]
        if d in ("destroy-now", "destroy-after-grace"):
            if live and (d == "destroy-now" or st == "active"):
                errs.append(f"key {kid}: live usable DEK although subject.shredded {ev[0]} is in the log")
            elif live and after is not None and after <= now:
                errs.append(f"key {kid}: grace period over but DEK not destroyed (subject.shredded {ev[0]})")
            elif not live and not db.execute("SELECT 1 FROM redactions WHERE kind='shred' AND key_id=?", (kid,)).fetchone():
                errs.append(f"key {kid}: destroyed but no redactions record")
        elif d == "schedule" and live and st == "active":
            errs.append(f"key {kid}: shred scheduled ({ev[0]}) but key is not pending_destroy")
        elif d == "cancel" and live and st == "pending_destroy":
            errs.append(f"key {kid}: shred cancelled ({ev[0]}) but key is still pending_destroy")
    shredded_log = {k for k, (d, _) in dec.items() if d.startswith("destroy")}
    for kid, (subj, st, after, live) in state.items():
        if not live and kid not in shredded_log and not vault._shredded_in_log(db, kid):
            warns.append(f"key {kid}: destroyed in keys.db without a subject.shredded in the log (legacy or interrupted)")
        if live and st == "pending_destroy" and after is not None and after <= now and kid not in shredded_log:
            warns.append(f"key {kid}: grace period over; run `vault shred-finalize` for its subject (or shred-cancel)")
    return errs, warns
