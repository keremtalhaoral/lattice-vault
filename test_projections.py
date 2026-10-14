"""Incremental projections + checkpoints: incremental state == full fold, transactional rebuild, tamper detection."""
import os, random, sqlite3, unittest
from unittest import mock
from testutil import fresh, HAVE_CRYPTO
import vault, ops

H = vault.HUMAN
TABLES = [t for t in vault.PROJ_TABLES if t != "proj_meta"]


def state(db, drop_seq=False):
    out = {}
    for t in TABLES:
        rows = [tuple(r) for r in db.execute(f"SELECT * FROM {t}")]
        if drop_seq and t == "proj_status":
            rows = [r[:3] + r[4:] for r in rows]   # decided_seq depends on arrival order (seq), not semantics
        out[t] = sorted(rows, key=repr)
    return out


def ids(db, where):
    return [r[0] for r in db.execute(f"SELECT e.id FROM events e JOIN proj_status s ON s.event_id=e.id WHERE {where} ORDER BY e.seq")]


def random_op(db, rng, crypto):
    subj = rng.choice(["user:owner", "proj:a", "proj:b"]); key = rng.choice(["dil", "tema"])
    k = rng.randrange(12)
    try:
        if k == 0:
            vault.append(db, "preference.set", subj, {"key": key, "value": f"v{rng.randrange(99)}"}, H, "verified")
        elif k == 1:
            t = rng.choice(["preference.set", "decision.made", "learning.captured", "goal.set", "project.created"])
            vault.append(db, t, subj, {"key": key, "value": "a", "text": f"p{rng.randrange(99)}"}, "agent:bot", "unverified")
        elif k == 2:
            vault.append(db, "decision.made", f"d{rng.randrange(3)}", {"text": f"dec{rng.randrange(99)}"}, H, "verified")
        elif k == 3:
            vault.append(db, rng.choice(["learning.captured", "goal.set", "project.created"]), f"g{rng.randrange(3)}",
                         {"text": f"x{rng.randrange(99)}"}, H, "verified")
        elif k == 4:
            vault.append(db, "goal.progressed", f"g{rng.randrange(3)}", {"progress": rng.random()}, H, "verified")
        elif k in (5, 6):
            p = ids(db, "s.status='proposed'")
            if p:
                vault.review(db, rng.choice(p), rng.choice(["approve", "reject"]))
        elif k == 7:
            p = ids(db, "s.status='proposed'")
            if p:
                vault.append(db, "import.batch_approved", f"batch:{len(p)}", {}, H, "verified", target_ids=p[:2])
        elif k == 8:
            a = ids(db, "s.status='active' AND e.type IN ('preference.set','event.corrected')")
            if a:
                vault.append(db, "event.corrected", "event:x", {"field": "value", "new_value": f"c{rng.randrange(99)}"},
                             H, "verified", supersedes=rng.choice(a))
        elif k == 9:
            a = ids(db, "s.status='active' AND e.type NOT IN ('event.approved','event.rejected','event.reverted','import.batch_approved')")
            if a:
                t = rng.choice(a)
                vault.append(db, "event.reverted", f"event:{t}", {}, H, "verified", target_ids=[t])
        elif k == 10:
            vault.append(db, "decision.reversed", f"d{rng.randrange(3)}", {"text": "undo"}, H, "verified")
        elif k == 11 and crypto:
            vault.append(db, "preference.set", subj, {"key": key, "value": "secret"}, H, "verified", sensitive=["value"])
    except ValueError:
        pass   # refused by validation (e.g. double supersede): no event written


class IncrementalEquivalenceTest(unittest.TestCase):
    def setUp(self):
        fresh(self)

    def test_randomized_incremental_equals_full_rebuild(self):
        calls = {"n": 0}; real = vault.rebuild
        def counting(db):
            calls["n"] += 1; return real(db)
        appends = 0
        for seed in range(12):
            fresh(self); rng = random.Random(seed)
            with mock.patch.object(vault, "rebuild", counting):
                for i in range(40):
                    random_op(self.db, rng, HAVE_CRYPTO); appends += 1
                    if i % 8 == 7 or i == 39:
                        inc = state(self.db); real(self.db)
                        self.assertEqual(inc, state(self.db), f"seed {seed} op {i}")
        self.assertLess(calls["n"], appends / 2, "most appends should take the incremental path")

    def test_checkpoint_plus_remaining_equals_full_fold(self):
        rng = random.Random(99)
        for _ in range(30):
            random_op(self.db, rng, False)
        vault.rebuild(self.db)                      # checkpoint
        for _ in range(30):
            random_op(self.db, rng, False)          # remaining, applied incrementally / with fallbacks
        inc = state(self.db); vault.rebuild(self.db)
        self.assertEqual(inc, state(self.db))

    def test_shuffled_delivery_same_hlc_order(self):
        rng = random.Random(7)
        for _ in range(50):
            random_op(self.db, rng, False)
        vault.rebuild(self.db); want = state(self.db, drop_seq=True)
        rows = [dict(r) for r in self.db.execute("SELECT * FROM events ORDER BY seq")]
        par = self.db.execute("SELECT * FROM event_parents").fetchall()
        tgt = self.db.execute("SELECT * FROM event_targets").fetchall()
        sigs = self.db.execute("SELECT event_id, key_id, alg, sig FROM event_sigs").fetchall()
        sigmap = {x[0]: x[3] for x in sigs}
        for trial in range(3):
            order = rows[:]; random.Random(trial).shuffle(order)
            b = vault.connect(os.path.join(self.d, f"b{trial}.db"))
            b.executemany("INSERT INTO event_sigs VALUES(?,?,?,?)", [tuple(x) for x in sigs])   # signatures travel with rows
            prev = vault.GENESIS
            for r in order:   # arrival order differs from HLC order (e.g. sync); hash chain follows arrival
                r = dict(r); r.pop("seq"); r["prev_hash"] = prev; r["_sig"] = sigmap.get(r["id"])
                r["hash"] = prev = vault.event_hash(prev, r); r.pop("_sig")
                b.execute(f"INSERT INTO events({','.join(r)}) VALUES({','.join('?' * len(r))})", list(r.values()))
                for p in par:
                    if p["event_id"] == r["id"]:
                        b.execute("INSERT INTO event_parents VALUES(?,?,?)", tuple(p))
                for t in tgt:
                    if t["event_id"] == r["id"]:
                        b.execute("INSERT INTO event_targets VALUES(?,?)", tuple(t))
                if not vault.apply_incremental(b, r["id"]):   # same path as append()
                    b.commit(); vault.rebuild(b)
                b.commit()
            self.assertEqual(want, state(b, drop_seq=True), f"trial {trial}")
            b.close()


class RebuildAndCheckpointTest(unittest.TestCase):
    def setUp(self):
        fresh(self)
        for i in range(10):
            vault.append(self.db, "preference.set", "user:owner", {"key": f"k{i}", "value": f"v{i}"}, H, "verified")

    def raw(self):
        r = sqlite3.connect(self.dbp); r.row_factory = sqlite3.Row; return r

    def test_rebuild_is_atomic(self):
        before = state(self.db); n = {"i": 0}; real = vault._apply
        def boom(*a):
            n["i"] += 1
            if n["i"] == 3:
                raise RuntimeError("crash mid-rebuild")
            return real(*a)
        with mock.patch.object(vault, "_apply", boom):
            with self.assertRaises(RuntimeError):
                vault.rebuild(self.db)
        self.assertEqual(before, state(self.db))
        self.assertEqual(vault._proj_last_seq(self.db), 10)

    def test_open_skips_rebuild_when_checkpoint_current(self):
        self.db.close()
        with mock.patch.object(vault, "rebuild") as rb:
            vault.connect(self.dbp).close()
        rb.assert_not_called()
        r = self.raw(); r.execute("UPDATE proj_meta SET last_seq=5"); r.commit(); r.close()
        with mock.patch.object(vault, "rebuild") as rb:
            vault.connect(self.dbp).close()
        rb.assert_called_once()

    def _tamper(self, seq):
        r = self.raw()
        r.execute("DROP TRIGGER events_no_update")
        r.execute("UPDATE events SET payload=json_set(payload,'$.value','EVIL') WHERE seq=?", (seq,))
        r.execute(vault.TRIGGERS["events_no_update"]); r.commit(); r.close()

    def test_tamper_old_event_detected_by_doctor_full(self):
        os.environ["VAULT_VERIFY_SAMPLE_K"] = "0"; self.addCleanup(os.environ.pop, "VAULT_VERIFY_SAMPLE_K")  # no sampling
        self.db.close(); vault.connect(self.dbp).close()      # checkpoint at seq 10
        self._tamper(2)
        db = vault.connect(self.dbp)                          # below checkpoint: open-time check does not cover it
        rep = ops.doctor(db); db.close()
        self.assertFalse(rep["ok"])
        self.assertTrue(any("event chain broken at seq 2" in p for p in rep["problems"]))

    def test_tamper_in_unverified_range_detected_on_open(self):
        self.db.close(); vault.connect(self.dbp).close()      # checkpoint at seq 10
        db = vault.connect(self.dbp)
        for i in range(5):
            vault.append(db, "learning.captured", "x", {"text": f"t{i}"}, H, "verified")
        db.close()                                            # seq 11..15 not yet verified
        self._tamper(12)
        with self.assertRaisesRegex(vault.TamperError, "event chain broken at seq 12"):
            vault.connect(self.dbp)

    def test_tampered_checkpoint_row_detected(self):
        os.environ["VAULT_VERIFY_SAMPLE_K"] = "0"; self.addCleanup(os.environ.pop, "VAULT_VERIFY_SAMPLE_K")
        self.db.close(); vault.connect(self.dbp).close()
        self._tamper(10)
        with self.assertRaisesRegex(vault.TamperError, "checkpoint mismatch"):
            vault.connect(self.dbp)


if __name__ == "__main__":
    unittest.main()
