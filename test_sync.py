import json, os, subprocess, sys, tempfile, time, unittest
from unittest import mock
os.environ.setdefault("VAULT_ALLOW_NONTTY", "1")
import vault, sync, signing
from testutil import HAVE_CRYPTO

HERE = os.path.dirname(os.path.abspath(__file__))
U = "user:owner"


class SyncTest(unittest.TestCase):
    def setUp(self):
        for k in ("VAULT_KEYS_DB", "VAULT_KEK_FILE", "VAULT_PASSPHRASE", "VAULT_AGENTS"):
            os.environ.pop(k, None)
        vault._KEYSTORE.clear()
        self.d = tempfile.mkdtemp()
        self.A, self.B = self.mk("a"), self.mk("b")
        self.da, self.db_ = sync.device_id(self.A), sync.device_id(self.B)
        sync.pair(self.A, self.db_, "B"); sync.pair(self.B, self.da, "A")

    def imp(self, db, path, **kw):   # pre-quarantine semantics (paired user:* trusted) for the merge/conflict mechanics tests
        return sync.import_package(db, path, _trust_unsigned=True, **kw)

    def mk(self, n):
        os.makedirs(os.path.join(self.d, n))
        db = vault.connect(os.path.join(self.d, n, "v.db")); self.addCleanup(db.close); return db

    def pkg(self, src, name="p.vaultsync", **kw):
        p = os.path.join(self.d, name); sync.export(src, p, **kw); return p

    def sem(self, db):   # projection_hash includes local seq (decided_seq), so compare the semantic content instead
        return [list(r) for r in db.execute("SELECT event_id, status, decided_by FROM proj_status ORDER BY 1")] + \
               [list(r) for r in db.execute("SELECT * FROM proj_preferences ORDER BY 1,2,4")]

    def count(self, db):
        return db.execute("SELECT count(*) FROM events").fetchone()[0]

    def pref(self, db, key="dil"):
        return sorted(tuple(r) for r in db.execute("SELECT value, conflict FROM proj_preferences WHERE key=?", (key,)))

    def test_round_trip_both_ways_and_chains_valid(self):
        vault.append(self.A, "preference.set", U, {"key": "dil", "value": "Türkçe"}, U, "verified")
        vault.append(self.A, "learning.captured", "x", {"text": "merhaba"}, "agent:bot", "unverified")
        r = self.imp(self.B, self.pkg(self.A))
        self.assertEqual((r["new"], r["duplicate"], r["quarantined"]), (2, 0, 0))
        self.assertEqual(self.pref(self.B), [("Türkçe", 0)])
        vault.append(self.B, "goal.set", "goal:g", {"title": "koş"}, U, "verified")
        r = self.imp(self.A, self.pkg(self.B, "b.vaultsync"))
        self.assertEqual((r["new"], r["duplicate"]), (1, 2))
        self.assertEqual(self.sem(self.A), self.sem(self.B))
        for db in (self.A, self.B):
            self.assertEqual(vault.verify_chains(db), []); self.assertEqual(vault.check_triggers(db), [])
        # reopen with full integrity verification
        vault.connect(os.path.join(self.d, "b", "v.db")).close()

    def test_reimport_is_noop_and_since_peer(self):
        vault.append(self.A, "preference.set", U, {"key": "dil", "value": "Türkçe"}, U, "verified")
        p = self.pkg(self.A)
        self.imp(self.B, p); n = self.count(self.B); h = vault.projection_hash(self.B)
        r = self.imp(self.B, p)
        self.assertEqual((r["new"], r["duplicate"]), (0, 1)); self.assertEqual(self.count(self.B), n)
        self.assertEqual(vault.projection_hash(self.B), h)
        # B already holds A's events -> incremental export from B to A carries nothing A sent
        m = sync.export(self.B, os.path.join(self.d, "inc"), since_peer=self.da)
        self.assertEqual(m["event_count"], 0)

    def test_tampered_body_rejected(self):
        vault.append(self.A, "preference.set", U, {"key": "dil", "value": "Türkçe"}, U, "verified")
        p = self.pkg(self.A); raw = open(p, encoding="utf-8").read()
        open(p, "w", encoding="utf-8").write(raw.replace("Türkçe", "Almanca"))
        with self.assertRaisesRegex(sync.SyncError, "sha256"):
            self.imp(self.B, p)
        # attacker also fixes the body sha256 -> per-event hash still catches it
        head, body = raw.split("\n", 1); body = body.replace("Türkçe", "Almanca")
        m = json.loads(head); import hashlib; m["body_sha256"] = hashlib.sha256(body.encode()).hexdigest()
        open(p, "w", encoding="utf-8").write(json.dumps(m) + "\n" + body)
        with self.assertRaisesRegex(sync.SyncError, "hash mismatch"):
            self.imp(self.B, p)
        self.assertEqual(self.count(self.B), 0)

    def test_hlc_receive_advances_local_clock(self):
        real = time.time
        with mock.patch.object(vault.time, "time", lambda: real() + 120):   # A's clock 2 min ahead (within bound)
            vault.append(self.A, "learning.captured", "x", {"text": "a"}, U, "verified")
        remote = self.A.execute("SELECT hlc FROM events").fetchone()[0]
        self.imp(self.B, self.pkg(self.A))
        eid = vault.append(self.B, "learning.captured", "y", {"text": "b"}, U, "verified")[0]
        local = self.B.execute("SELECT hlc FROM events WHERE id=?", (eid,)).fetchone()[0]
        self.assertGreater(local[:17], remote[:17])

    def test_clock_skew_beyond_bound_rejected(self):
        vault.append(self.A, "learning.captured", "x", {"text": "a"}, U, "verified")
        p = self.pkg(self.A)
        with self.assertRaisesRegex(sync.SyncError, "clock skew"):
            self.imp(self.B, p, now_ms=int(time.time() * 1000) - 10 * 60 * 1000)
        self.assertEqual(self.count(self.B), 0)

    def test_concurrent_corrections_flag_conflict_not_lww(self):
        base = vault.append(self.A, "preference.set", U, {"key": "dil", "value": "Türkçe"}, U, "verified")[0]
        self.imp(self.B, self.pkg(self.A))
        corr = lambda db, v: vault.append(db, "event.corrected", f"event:{base}", {"field": "value", "new_value": v,
                                          "reason": "t"}, U, "verified", supersedes=base)
        corr(self.A, "İngilizce"); corr(self.B, "Almanca")
        self.imp(self.B, self.pkg(self.A, "a2", since_peer=self.db_))
        self.imp(self.A, self.pkg(self.B, "b2", since_peer=self.da))
        for db in (self.A, self.B):
            rows = self.pref(db)
            self.assertEqual(len(rows), 1); self.assertEqual(rows[0][1], 1, "fork must be flagged as conflict")
        self.assertEqual(self.sem(self.A), self.sem(self.B))

    def test_concurrent_preference_sets_flag_conflict(self):
        base = vault.append(self.A, "preference.set", U, {"key": "dil", "value": "Türkçe"}, U, "verified")[0]
        self.imp(self.B, self.pkg(self.A))
        vault.append(self.A, "preference.set", U, {"key": "dil", "value": "X"}, U, "verified")
        vault.append(self.B, "preference.set", U, {"key": "dil", "value": "Y"}, U, "verified")
        self.imp(self.B, self.pkg(self.A, "a2"))
        self.assertEqual(self.pref(self.B), [("X", 1), ("Y", 1)])

    def test_unknown_device_events_land_unverified(self):
        C = self.mk("c")
        vault.append(C, "preference.set", U, {"key": "dil", "value": "Klingonca"}, U, "verified")
        vault.append(C, "event.approved", "event:x", {}, U, "verified")
        r = self.imp(self.B, self.pkg(C, "c.vaultsync"))
        # skipped: the approval AND C's user + recovery key.registered (signed human-only types, unpaired device)
        self.assertEqual((r["new"], r["quarantined"], len(r["skipped"])), (1, 1, 3))
        e = self.B.execute("SELECT e.actor, e.trust, s.status FROM events e JOIN proj_status s ON s.event_id=e.id").fetchone()
        self.assertTrue(e[0].startswith("import:sync-")); self.assertEqual((e[1], e[2]), ("unverified", "proposed"))
        self.assertEqual(self.pref(self.B), [])   # not in the active projection until approved

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_encrypted_fields_stay_ciphertext(self):
        eid = vault.append(self.A, "learning.captured", "user:owner", {"text": "not", "pin": "4711-gizli"}, U, "verified",
                           sensitive=["pin"])[0]
        p = self.pkg(self.A)
        self.assertNotIn("4711-gizli", open(p, encoding="utf-8").read())
        self.imp(self.B, p)
        a = self.A.execute("SELECT payload, payload_ct FROM events WHERE id=?", (eid,)).fetchone()
        b = self.B.execute("SELECT payload, payload_ct FROM events WHERE id=?", (eid,)).fetchone()
        self.assertEqual(tuple(a), tuple(b))
        st = self.B.execute("SELECT status FROM proj_status WHERE event_id=?", (eid,)).fetchone()[0]
        self.assertEqual(st, "undecryptable")   # B has no key (key sync is planned) -> unreadable, never plaintext

    def test_dry_run_writes_nothing(self):
        vault.append(self.A, "preference.set", U, {"key": "dil", "value": "Türkçe"}, U, "verified")
        p = self.pkg(self.A); path = os.path.join(self.d, "b", "v.db")
        before = open(path, "rb").read()
        r = self.imp(self.B, p, dry_run=True)
        self.assertEqual(r["new"], 1); self.assertEqual(open(path, "rb").read(), before)

    def test_cli(self):
        env = {**os.environ, "VAULT_DB": os.path.join(self.d, "a", "v.db")}
        run = lambda *a, db=None: subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), *a], capture_output=True,
                                                 text=True, env={**env, **({"VAULT_DB": db} if db else {})})
        self.assertEqual(run("device-id").stdout.strip(), self.da)
        vault.append(self.A, "learning.captured", "x", {"text": "a"}, U, "verified")
        out = os.path.join(self.d, "cli.vaultsync")
        r = run("sync-export", "--out", out); self.assertEqual(r.returncode, 0, r.stderr)
        bdb = os.path.join(self.d, "b", "v.db")
        r = run("sync-import", out, "--dry-run", db=bdb); self.assertEqual(json.loads(r.stdout)["quarantined"], 1)
        r = run("sync-import", out, db=bdb); self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Do not use it with real data", r.stderr)
        r = run("sync-import", out, db=bdb); self.assertEqual((json.loads(r.stdout)["new"], json.loads(r.stdout)["duplicate"]), (0, 1))
        q = json.loads(run("sync-quarantine", db=bdb).stdout)
        self.assertEqual([(x["actor"], x["reason"]) for x in q], [(U, "unsigned user:* event")])
        self.assertIn("not for real data", run("--help").stdout)

    # ---- consensus block: unsigned user:* / approval events are quarantined, never applied ----
    def held(self, db):
        return {r["event_id"]: r["reason"] for r in sync.quarantined(db)}

    def test_user_events_quarantined_not_applied(self):
        eid = vault.append(self.A, "preference.set", U, {"key": "dil", "value": "Türkçe"}, U, "verified")[0]
        r = sync.import_package(self.B, self.pkg(self.A))
        self.assertEqual((r["new"], r["quarantined"]), (0, 1))
        self.assertEqual(self.count(self.B), 0); self.assertEqual(self.pref(self.B), [])
        self.assertEqual(self.held(self.B), {eid: "unsigned user:* event"})
        self.assertIsNone(self.B.execute("SELECT 1 FROM proj_status WHERE event_id=?", (eid,)).fetchone())
        self.assertEqual(vault.verify_chains(self.B), [])

    def test_quarantine_reimport_idempotent(self):
        vault.append(self.A, "preference.set", U, {"key": "dil", "value": "Türkçe"}, U, "verified")
        p = self.pkg(self.A)
        sync.import_package(self.B, p); h = vault.projection_hash(self.B)
        r = sync.import_package(self.B, p)
        self.assertEqual((r["new"], r["quarantined"], r["duplicate"]), (0, 0, 1))
        self.assertEqual(len(sync.quarantined(self.B)), 1); self.assertEqual(vault.projection_hash(self.B), h)

    def test_agent_events_still_sync(self):
        a = vault.append(self.A, "learning.captured", "x", {"text": "merhaba"}, "agent:bot", "unverified")[0]
        u = vault.append(self.A, "learning.captured", "y", {"text": "sahte"}, U, "verified")[0]
        r = sync.import_package(self.B, self.pkg(self.A))
        self.assertEqual((r["new"], r["quarantined"]), (1, 1))
        row = self.B.execute("SELECT e.actor, e.trust, s.status FROM events e JOIN proj_status s ON s.event_id=e.id").fetchall()
        self.assertEqual([tuple(x) for x in row], [("agent:bot", "unverified", "proposed")])
        self.assertEqual(set(self.held(self.B)), {u}); self.assertNotIn(a, self.held(self.B))

    def test_forged_approval_does_not_change_projection(self):
        a = vault.append(self.A, "learning.captured", "x", {"text": "ajan"}, "agent:bot", "unverified")[0]
        sync.import_package(self.B, self.pkg(self.A)); before = self.sem(self.B)
        self.assertEqual(self.B.execute("SELECT status FROM proj_status WHERE event_id=?", (a,)).fetchone()[0], "proposed")
        vault.review(self.A, a, "approve", actor=U)
        r = sync.import_package(self.B, self.pkg(self.A, "a2", since_peer=self.db_))
        self.assertEqual((r["new"], r["quarantined"]), (0, 3))   # A's user + recovery key.registered + the approval
        self.assertEqual(self.sem(self.B), before)
        self.assertEqual(sorted(v.split(" (")[0] for v in self.held(self.B).values()),
                         ["key.* events are not applied via sync"] * 2 + ["unknown signing key " + signing.try_user_key()[1]])

    def test_approval_type_quarantined_regardless_of_actor(self):
        # a forged batch approval claiming a non-user actor (inserted around the human-only trigger, as a package writer could)
        a = vault.append(self.A, "learning.captured", "x", {"text": "ajan"}, "agent:bot", "unverified")[0]
        p = self.pkg(self.A)
        self.forge(p, lambda e: e.update(id="forged-1", type="import.batch_approved", actor="agent:bot", parents=[],
                                         targets=[a], payload=vault.canon({"batch_id": "b", "target_ids": [a]})))
        sync.import_package(self.B, self.pkg(self.A, "orig"))
        r = sync.import_package(self.B, p)
        self.assertEqual((r["new"], r["quarantined"]), (0, 1))
        self.assertEqual(self.held(self.B), {"forged-1": "human-only event from a non-user actor"})
        self.assertEqual(self.B.execute("SELECT status FROM proj_status WHERE event_id=?", (a,)).fetchone()[0], "proposed")

    def forge(self, p, mutate):
        """Rewrite one package event the way a package writer could (fixing hashes), bypassing write-path checks."""
        import hashlib
        lines = open(p, encoding="utf-8").read().splitlines()
        e = json.loads(lines[1]); mutate(e)
        e["content_hash"] = vault.content_hash(e["type"], e["subject"], e["key"], json.loads(e["payload"]))
        row = dict(e); row["payload_ct"] = None; e["hash"] = vault.event_hash(e["prev_hash"], row)
        body = (vault.canon(e) + "\n").encode()
        m = json.loads(lines[0]); m.update(event_count=1, body_sha256=hashlib.sha256(body).hexdigest())
        with open(p, "wb") as f:
            f.write(vault.canon(m).encode() + b"\n" + body)
        return e["id"]

    def test_schema_invalid_payload_quarantined(self):
        vault.append(self.A, "preference.set", "s", {"key": "dil", "value": "ok"}, "agent:bot", "unverified")
        p = self.pkg(self.A)
        eid = self.forge(p, lambda e: e.update(payload=vault.canon({"key": "dil", "value": {"nested": 1}})))
        r = sync.import_package(self.B, p)
        self.assertEqual((r["new"], r["quarantined"]), (0, 1)); self.assertEqual(self.count(self.B), 0)
        self.assertTrue(self.held(self.B)[eid].startswith("schema invalid"))

    def test_older_schema_event_upcast_on_import(self):
        from test_schemas import patched, V3, DEMO_UPS
        eid = vault.append(self.A, "preference.set", "s", {"key": "dil", "val": "Türkçe"}, "agent:bot", "unverified")[0]
        p = self.pkg(self.A)
        with patched("preference.set", V3, DEMO_UPS):   # receiver runs newer code: v1 -> v3 via upcasters
            r = sync.import_package(self.B, p)
            self.assertEqual((r["new"], r["quarantined"]), (1, 0))
            e = self.B.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
            self.assertEqual((e["schema_version"], json.loads(e["payload"])["val"]), (1, "Türkçe"))   # stored bytes untouched
            self.assertEqual(vault.read_upcast(e)["value"], "Türkçe")

    def test_projection_consistent_after_merge_then_local_append(self):
        vault.append(self.A, "learning.captured", "x", {"text": "a"}, "agent:bot", "unverified")
        sync.import_package(self.B, self.pkg(self.A))
        vault.append(self.B, "learning.captured", "y", {"text": "b"}, U, "verified")   # incremental path on B
        h = vault.projection_hash(self.B); vault.rebuild(self.B)
        self.assertEqual(vault.projection_hash(self.B), h)
        self.assertEqual(vault.verify_chains(self.B), [])

    # ---- #10 integration: user signatures on incoming human-only events ----
    def approval_pkg(self, name="ap"):
        a = vault.append(self.A, "learning.captured", "x", {"text": "ajan"}, "agent:bot", "unverified")[0]
        ap = vault.review(self.A, a, "approve", actor=U)
        return a, ap, self.pkg(self.A, name)

    def rewrite(self, p, eid, mutate):
        """Mutate one event in a package and re-seal hashes (sig is bound into event_hash v2)."""
        import hashlib
        lines = open(p, encoding="utf-8").read().splitlines(); out = []
        for l in lines[1:]:
            e = json.loads(l)
            if e["id"] == eid:
                mutate(e)
                e["content_hash"] = vault.content_hash(e["type"], e["subject"], e["key"], json.loads(e["payload"]))
                row = dict(e); row["payload_ct"] = None; row["_sig"] = (e.get("sig") or {}).get("sig")
                e["hash"] = vault.event_hash(e["prev_hash"], row)
            out.append(vault.canon(e))
        body = ("\n".join(out) + "\n").encode()
        m = json.loads(lines[0]); m.update(event_count=len(out), body_sha256=hashlib.sha256(body).hexdigest())
        with open(p, "wb") as f:
            f.write(vault.canon(m).encode() + b"\n" + body)

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_valid_user_signature_applied(self):
        signing.register_user_key(self.B)                  # receiver knows the same user key (key.registered on B)
        a, ap, p = self.approval_pkg()
        r = sync.import_package(self.B, p)
        self.assertEqual((r["new"], r["quarantined"]), (2, 2))   # agent event + approval; A's two key.registered held
        self.assertEqual(self.B.execute("SELECT status FROM proj_status WHERE event_id=?", (a,)).fetchone()[0], "active")
        self.assertNotIn(ap, self.held(self.B))
        self.assertEqual(signing.classify(self.B)[ap][1], "remote-signed")   # origin signature re-verified from origin_row
        r = sync.import_package(self.B, p)                  # idempotent
        self.assertEqual((r["new"], r["quarantined"], r["duplicate"]), (0, 0, 4))
        self.assertEqual(len(sync.quarantined(self.B)), 2)

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_signed_but_key_not_registered_on_receiver_quarantined(self):
        a, ap, p = self.approval_pkg()
        sync.import_package(self.B, p)
        self.assertTrue(self.held(self.B)[ap].startswith("unknown signing key user/ed25519/"))
        self.assertEqual(self.B.execute("SELECT status FROM proj_status WHERE event_id=?", (a,)).fetchone()[0], "proposed")

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_forged_or_stripped_signature_quarantined(self):
        signing.register_user_key(self.B)
        a, ap, p = self.approval_pkg()
        good = open(p, "rb").read()
        def flip(e):
            s = signing.unb64(e["sig"]["sig"]); e["sig"]["sig"] = signing.b64(bytes([s[0] ^ 1]) + s[1:])
        for mutate, why in ((flip, "bad signature"), (lambda e: e.pop("sig"), "unsigned human-only event"),
                            (lambda e: e.update(subject="event:other"), "bad signature")):
            with open(p, "wb") as f:
                f.write(good)
            self.rewrite(p, ap, mutate)
            C = self.mk(f"c{why[:3]}{id(mutate)}"); sync.pair(C, self.da, "A"); signing.register_user_key(C)
            r = sync.import_package(C, p)
            self.assertEqual(self.held(C).get(ap), why)
            self.assertEqual(C.execute("SELECT status FROM proj_status WHERE event_id=?", (a,)).fetchone()[0], "proposed")
            r2 = sync.import_package(C, p)
            self.assertEqual((r2["new"], r2["quarantined"]), (0, 0))

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_valid_signature_from_unpaired_device_quarantined(self):
        C = self.mk("c"); signing.register_user_key(C)
        a, ap, p = self.approval_pkg()
        sync.import_package(C, p)
        self.assertEqual(self.held(C)[ap], "valid user signature but origin device is not paired")

    # ---- step 2: re-verifiable quarantine release, remote-signed, retryable cursor ----
    def st(self, db, eid):
        return db.execute("SELECT status FROM proj_status WHERE event_id=?", (eid,)).fetchone()[0]

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_release_after_key_registered(self):
        a, ap, p = self.approval_pkg()
        sync.import_package(self.B, p)
        self.assertIn(ap, self.held(self.B))
        r = sync.release_quarantined(self.B)                       # key still unknown: nothing released
        self.assertEqual(r["released"], []); self.assertIn(ap, r["still_held"])
        signing.register_user_key(self.B)
        r = sync.release_quarantined(self.B, dry_run=True)
        self.assertEqual(r["released"], [ap]); self.assertEqual(self.st(self.B, a), "proposed")
        r = sync.release_quarantined(self.B)
        self.assertEqual(r["released"], [ap])
        self.assertTrue(any(v.startswith("key.* events") for v in r["still_held"].values()))   # A's key.registered stays held
        self.assertEqual(self.st(self.B, a), "active")
        self.assertNotIn(ap, self.held(self.B))
        self.assertEqual(signing.classify(self.B)[ap][1], "remote-signed")
        self.assertEqual(vault.verify_chains(self.B), [])
        with self.assertRaises(sync.SyncError):                     # already released
            sync.release_quarantined(self.B, [ap])
        r = sync.import_package(self.B, p)                          # re-import stays a no-op
        self.assertEqual(r["new"], 0)

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_release_never_applies_unverified(self):
        signing.register_user_key(self.B)
        a, ap, p = self.approval_pkg()
        self.rewrite(p, ap, lambda e: e.pop("sig"))
        sync.import_package(self.B, p)
        r = sync.release_quarantined(self.B, [ap])
        self.assertEqual(r["released"], []); self.assertEqual(r["still_held"][ap], "unsigned human-only event")
        self.assertEqual(self.st(self.B, a), "proposed")

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_release_requires_paired_device(self):
        C = self.mk("c"); signing.register_user_key(C)
        a, ap, p = self.approval_pkg()
        sync.import_package(C, p)
        self.assertEqual(sync.release_quarantined(C, [ap])["released"], [])
        sync.pair(C, self.da, "A")
        self.assertEqual(sync.release_quarantined(C, [ap])["released"], [ap])

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_reimport_reports_still_quarantined(self):
        a, ap, p = self.approval_pkg()
        sync.import_package(self.B, p)
        r = sync.import_package(self.B, self.pkg(self.A, "again"))
        self.assertGreaterEqual(r.get("still_quarantined", 0), 1)

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_remote_signed_bound_to_local_row(self):
        signing.register_user_key(self.B)
        a, ap, p = self.approval_pkg()
        sync.import_package(self.B, p)
        self.assertEqual(signing.classify(self.B)[ap][1], "remote-signed")
        import ops
        self.assertFalse(any("remote" in w for w in ops.doctor(self.B).get("warnings", [])))
        # origin_row is not hash-chained: editing it must not make a different event pass
        orig = json.loads(self.B.execute("SELECT origin_row FROM sync_imported WHERE event_id=?", (ap,)).fetchone()[0])
        orig["subject"] = "event:other"
        self.B.execute("UPDATE sync_imported SET origin_row=? WHERE event_id=?", (vault.canon(orig), ap))
        self.assertEqual(signing.classify(self.B)[ap][1], "remote-mismatch")
        self.assertIn("remote-mismatch", signing.BAD)


    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_cli_release(self):
        a, ap, p = self.approval_pkg()
        sync.import_package(self.B, p); signing.register_user_key(self.B); self.B.commit()
        env = {**os.environ, "VAULT_DB": os.path.join(self.d, "b", "v.db")}
        run = lambda *x: subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), *x], capture_output=True, text=True, env=env)
        r = run("sync-quarantine", "--release", "--dry-run"); self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["released"], [ap])
        r = run("sync-quarantine", "--release", ap); self.assertEqual(r.returncode, 0, r.stderr)
        r = run("sync-quarantine"); self.assertNotIn(ap, r.stdout)


if __name__ == "__main__":
    unittest.main()
