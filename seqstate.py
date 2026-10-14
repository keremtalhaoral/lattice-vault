"""Signed, monotonic per-sender sequence numbers for sync packages and key bundles (ADR 0016).

Streams: "vaultsync" (event packages) and "vaultkeys" (DEK bundles). Each sending device keeps one counter and the
hash of its last artefact per stream; both go into the artefact and are covered by the user signature. A receiver
records every (stream, sender, seq, hash, prev) it accepted and decides:

* same seq, same hash            -> duplicate (idempotent re-import, nothing changes)
* same seq, other hash           -> fork (refused)
* seq below the highest accepted -> rollback/replay (refused)
* seq == highest + 1             -> prev MUST equal the hash of the highest accepted one, else fork (refused)
* seq >  highest + 1 (a gap)     -> accepted: the counter is per sender, not per recipient, so artefacts that went to
                                    other peers (or were never delivered) leave gaps. If prev names an artefact this
                                    receiver accepted, it must be the highest one (else the sender branched: fork).
* first artefact from a sender   -> accepted with any seq (trust on first use; the signature still binds it).
Refusals are recorded in sync_seq_refused (ids, hashes and reasons only). A sender restored from an old backup
re-uses old numbers and is refused (rollback) until it advances its counter (`vault sync-seq-advance`).
"""
import hashlib

SCHEMA = """
CREATE TABLE IF NOT EXISTS sync_seq_send (stream TEXT PRIMARY KEY, seq INTEGER NOT NULL, head TEXT);
CREATE TABLE IF NOT EXISTS sync_seq_seen (
  stream TEXT NOT NULL, sender TEXT NOT NULL, seq INTEGER NOT NULL, hash TEXT NOT NULL, prev TEXT,
  at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), PRIMARY KEY (stream, sender, seq));
CREATE TABLE IF NOT EXISTS sync_seq_refused (
  id INTEGER PRIMARY KEY AUTOINCREMENT, stream TEXT NOT NULL, sender TEXT, seq INTEGER, hash TEXT, reason TEXT NOT NULL,
  at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE TRIGGER IF NOT EXISTS sync_seq_seen_no_update BEFORE UPDATE ON sync_seq_seen BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER IF NOT EXISTS sync_seq_seen_no_delete BEFORE DELETE ON sync_seq_seen BEGIN SELECT RAISE(ABORT,'append-only'); END;
"""
STREAMS = ("vaultsync", "vaultkeys")


class SeqError(ValueError):
    pass


def ensure(db):
    db.executescript(SCHEMA)


def digest(msg: bytes) -> str:
    return hashlib.sha256(msg).hexdigest()


def next_send(db, stream):
    """(seq, prev_hash) for the next artefact. Nothing is stored until commit_send()."""
    assert stream in STREAMS
    ensure(db)
    r = db.execute("SELECT seq, head FROM sync_seq_send WHERE stream=?", (stream,)).fetchone()
    return (r[0] + 1, r[1]) if r else (1, None)


def commit_send(db, stream, seq, h):
    db.execute("INSERT INTO sync_seq_send(stream, seq, head) VALUES(?,?,?) ON CONFLICT(stream) DO UPDATE SET "
               "seq=excluded.seq, head=excluded.head WHERE excluded.seq > sync_seq_send.seq", (stream, seq, h))


def advance(db, stream, to):
    """Human recovery after restoring a sender from an old backup: jump the counter forward (never back)."""
    ensure(db)
    cur = next_send(db, stream)[0] - 1
    if not isinstance(to, int) or to <= cur:
        raise SeqError(f"{stream}: new counter must be greater than the current one ({cur})")
    db.execute("INSERT INTO sync_seq_send(stream, seq, head) VALUES(?,?,NULL) ON CONFLICT(stream) DO UPDATE SET "
               "seq=excluded.seq, head=NULL", (stream, to))
    db.commit()
    return to


def check(db, stream, sender, seq, h, prev):
    """'new' | 'duplicate', or raise SeqError(reason). Read-only."""
    if type(seq) is not int or seq < 1:
        raise SeqError("sequence number missing or invalid")
    if prev is not None and not (isinstance(prev, str) and len(prev) == 64):
        raise SeqError("prev hash invalid")
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='sync_seq_seen'").fetchone():
        return "new"   # nothing accepted yet (and a dry run must not create tables)
    same = db.execute("SELECT hash FROM sync_seq_seen WHERE stream=? AND sender=? AND seq=?", (stream, sender, seq)).fetchone()
    if same:
        if same[0] == h:
            return "duplicate"
        raise SeqError(f"fork: sequence {seq} from {sender} was already accepted with different content")
    top = db.execute("SELECT seq, hash FROM sync_seq_seen WHERE stream=? AND sender=? ORDER BY seq DESC LIMIT 1",
                     (stream, sender)).fetchone()
    if top is None:
        return "new"
    if seq < top[0]:
        raise SeqError(f"rollback: sequence {seq} from {sender} is older than the last accepted ({top[0]})")
    if seq == top[0] + 1:
        if prev != top[1]:
            raise SeqError(f"fork: sequence {seq} from {sender} does not continue the last accepted artefact")
        return "new"
    known = db.execute("SELECT seq FROM sync_seq_seen WHERE stream=? AND sender=? AND hash=?", (stream, sender, prev)).fetchone() \
        if prev else None
    if known and known[0] != top[0]:
        raise SeqError(f"fork: sequence {seq} from {sender} branches from an earlier artefact ({known[0]})")
    return "new"


def record(db, stream, sender, seq, h, prev):
    db.execute("INSERT OR IGNORE INTO sync_seq_seen(stream, sender, seq, hash, prev) VALUES(?,?,?,?,?)",
               (stream, sender, seq, h, prev))


def refuse(db, stream, sender, seq, h, reason):
    ensure(db)
    db.execute("INSERT INTO sync_seq_refused(stream, sender, seq, hash, reason) VALUES(?,?,?,?,?)",
               (stream, sender if isinstance(sender, str) else None, seq if type(seq) is int else None,
                h, str(reason)[:300]))
    db.commit()


def refused(db):
    ensure(db)
    return [dict(r) for r in db.execute("SELECT stream, sender, seq, hash, reason, at FROM sync_seq_refused ORDER BY id")]
