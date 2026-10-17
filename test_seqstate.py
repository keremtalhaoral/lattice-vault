"""Signed per-sender sequence numbers for vaultsync/0.2 packages and vaultkeys/0.2 bundles (ADR 0016)."""
import json, os, shutil, sqlite3, subprocess, sys, tempfile, unittest
os.environ.setdefault("VAULT_ALLOW_NONTTY", "1")
import testutil  # noqa: F401
import vault, sync, signing, seqstate
from testutil import HAVE_CRYPTO
from test_sync import resign

HERE = os.path.dirname(os.path.abspath(__file__))
BOT = "agent:bot"
H = lambda c: c * 64


class SeqRulesTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:"); seqstate.ensure(self.db)

    def acc(self, seq, h, prev):
        st = seqstate.check(self.db, "vaultsync", "dev-x", seq, h, prev)
        seqstate.record(self.db, "vaultsync", "dev-x", seq, h, prev); return st

    def test_rules(self):
        self.assertEqual(self.acc(1, H("a"), None), "new")
        self.assertEqual(self.acc(2, H("b"), H("a")), "new")
        self.assertEqual(seqstate.check(self.db, "vaultsync", "dev-x", 2, H("b"), H("a")), "duplicate")      # replay of same
        for seq, h, prev, why in [(2, H("c"), H("a"), "fork"),             # same seq, other content
                                  (1, H("d"), None, "fork"),
                                  (3, H("e"), H("a"), "fork"),             # next seq must continue the head
                                  (5, H("f"), H("a"), "fork"),             # gap branching from an older artefact
                                  (0, H("g"), None, "invalid"), ("3", H("g"), H("b"), "invalid"),
                                  (3, H("g"), "zz", "invalid")]:
            with self.assertRaisesRegex(seqstate.SeqError, why):
                seqstate.check(self.db, "vaultsync", "dev-x", seq, h, prev)
        self.assertEqual(self.acc(5, H("h"), H("b")), "new")             # documented gap
        self.assertEqual(self.acc(9, H("i"), None), "new")               # gap, prev unknown here
        with self.assertRaisesRegex(seqstate.SeqError, "rollback"):
            seqstate.check(self.db, "vaultsync", "dev-x", 6, H("j"), H("h"))
        # streams and senders are independent
        self.assertEqual(seqstate.check(self.db, "vaultkeys", "dev-x", 1, H("k"), None), "new")
        self.assertEqual(seqstate.check(self.db, "vaultsync", "dev-y", 1, H("k"), None), "new")
        with self.assertRaises(sqlite3.DatabaseError):
            self.db.execute("DELETE FROM sync_seq_seen")

    def test_advance_only_forward(self):
        self.assertEqual(seqstate.next_send(self.db, "vaultkeys"), (1, None))
        seqstate.commit_send(self.db, "vaultkeys", 4, H("a"))
        self.assertEqual(seqstate.next_send(self.db, "vaultkeys"), (5, H("a")))
        with self.assertRaises(seqstate.SeqError):
            seqstate.advance(self.db, "vaultkeys", 3)
        seqstate.advance(self.db, "vaultkeys", 50)
        self.assertEqual(seqstate.next_send(self.db, "vaultkeys"), (51, None))


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class SyncSeqTest(unittest.TestCase):
    def setUp(self):
        for k in ("VAULT_KEYS_DB", "VAULT_KEK_FILE", "VAULT_PASSPHRASE", "VAULT_AGENTS"):
            os.environ.pop(k, None)
        vault._KEYSTORE.clear(); self.addCleanup(vault._KEYSTORE.clear)
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.A, self.B = self.mk("a"), self.mk("b")
        self.da, self.db_ = sync.device_id(self.A), sync.device_id(self.B)
        sync.pair(self.A, self.db_, "B"); sync.pair(self.B, self.da, "A")
        for x in (self.A, self.B):
            signing.register_user_key(x)
        self.n = 0

    def mk(self, n):
        os.makedirs(os.path.join(self.d, n))
        db = vault.connect(os.path.join(self.d, n, "v.db")); self.addCleanup(db.close); return db

    def pkg(self, src=None, **kw):
        self.n += 1; p = os.path.join(self.d, f"{self.n}.vaultsync"); sync.export(src or self.A, p, **kw); return p

    def ev(self, t="x"):
        vault.append(self.A, "learning.captured", "s", {"text": t}, BOT, "unverified")

    def manifest(self, p):
        return json.loads(open(p, "rb").read().split(b"\n", 1)[0])

    def rewrite(self, p, mutate):
        raw = open(p, "rb").read(); head, body = raw.split(b"\n", 1)
        m = json.loads(head); mutate(m); open(p, "wb").write(resign(m, self.A) + b"\n" + body); return p

    def test_sequence_signed_and_monotonic(self):
        self.ev(); p1 = self.pkg(); self.ev("y"); p2 = self.pkg()
        m1, m2 = self.manifest(p1), self.manifest(p2)
        self.assertEqual((m1["seq"], m2["seq"]), (1, 2))
        self.assertEqual(m2["prev_package"], seqstate.digest(sync._manifest_msg(m1)))
        self.assertEqual(sync.import_package(self.B, p2)["seq_state"], "new")
        self.assertEqual(sync.import_package(self.B, p2)["seq_state"], "duplicate")   # replay: idempotent, no change
        with self.assertRaisesRegex(sync.SyncError, "rollback"):      # an older package after a newer one
            sync.import_package(self.B, p1)
        self.ev("z"); p3 = self.pkg()
        self.assertEqual(sync.import_package(self.B, p3)["seq_state"], "new")
        self.rewrite(p3, lambda m: m.__setitem__("created_at", "2020-01-01T00:00:00Z"))
        with self.assertRaisesRegex(sync.SyncError, "fork"):          # same number, different signed content
            sync.import_package(self.B, p3)

    def test_unsigned_seq_change_refused(self):
        self.ev(); p = self.pkg()
        raw = open(p, "rb").read(); head, body = raw.split(b"\n", 1); m = json.loads(head); m["seq"] = 7
        open(p, "wb").write(vault.canon(m).encode() + b"\n" + body)
        with self.assertRaisesRegex(sync.SyncError, "signature"):
            sync.import_package(self.B, p)
        m = json.loads(head); m["vector"] = {k: v + 100 for k, v in m["vector"].items()}   # L3: vector is signed too
        open(p, "wb").write(vault.canon(m).encode() + b"\n" + body)
        with self.assertRaisesRegex(sync.SyncError, "signature"):
            sync.import_package(self.B, p)

    def test_fork_refused_and_recorded(self):
        self.ev(); p1 = self.pkg(); sync.import_package(self.B, p1)
        self.ev("y"); p2 = self.pkg()
        self.rewrite(p2, lambda m: m.__setitem__("prev_package", None))
        with self.assertRaisesRegex(sync.SyncError, "fork"):
            sync.import_package(self.B, p2)
        self.assertEqual([r["reason"][:4] for r in seqstate.refused(self.B)], ["fork"])
        n = self.B.execute("SELECT count(*) FROM events").fetchone()[0]
        with self.assertRaisesRegex(sync.SyncError, "fork"):
            sync.import_package(self.B, p2, dry_run=True)
        self.assertEqual(self.B.execute("SELECT count(*) FROM events").fetchone()[0], n)
        self.assertEqual(len(seqstate.refused(self.B)), 1)            # dry run records nothing

    def test_gap_allowed(self):
        self.ev(); self.pkg(); self.ev("y"); p2 = self.pkg()          # package 1 never delivered to B
        self.assertEqual(sync.import_package(self.B, p2)["seq_state"], "new")

    def test_restored_sender_refused_until_advanced(self):
        self.ev(); p1 = self.pkg(); sync.import_package(self.B, p1)
        self.ev("y"); sync.import_package(self.B, self.pkg())
        # model a sender restored from a backup taken before package 2: its counter is back at 1
        self.A.execute("UPDATE sync_seq_send SET seq=1 WHERE stream='vaultsync'"); self.A.commit()
        self.ev("z")
        with self.assertRaisesRegex(sync.SyncError, "fork"):
            sync.import_package(self.B, self.pkg())
        seqstate.advance(self.A, "vaultsync", 100)
        self.assertEqual(sync.import_package(self.B, self.pkg())["seq_state"], "new")

    def test_legacy_package_refused(self):
        self.ev(); p = self.pkg()
        self.rewrite(p, lambda m: m.__setitem__("format", "vaultsync/0.1"))
        with self.assertRaisesRegex(sync.SyncError, "re-export"):
            sync.import_package(self.B, p)

    def test_peer_watermark_capped_by_local_rows(self):
        self.ev(); p = self.pkg()
        self.rewrite(p, lambda m: m.__setitem__("vector", {k: v + 1000 for k, v in m["vector"].items()}))
        sync.import_package(self.B, p)
        for _, held in self.B.execute("SELECT origin_replica, max_replica_seq FROM sync_peer_state"):
            self.assertLess(held, 1000)

    def test_cli_seq_advance(self):
        env = {**os.environ, "VAULT_DB": os.path.join(self.d, "a", "v.db")}
        run = lambda *a: subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), *a], capture_output=True, text=True, env=env)
        r = run("sync-seq-advance", "--stream", "vaultkeys", "--to", "10"); self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), {"stream": "vaultkeys", "seq": 10})
        self.assertNotEqual(run("sync-seq-advance", "--stream", "vaultkeys", "--to", "5").returncode, 0)
        self.assertEqual(json.loads(run("sync-seq").stdout)["send"], {"vaultkeys": 10})
        r = subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), "sync-seq-advance", "--stream", "vaultsync",
                            "--to", "20"], capture_output=True, text=True, env={**env, "VAULT_ALLOW_NONTTY": ""}, stdin=subprocess.DEVNULL)
        self.assertNotEqual(r.returncode, 0)                           # human-only


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class KeySeqTest(unittest.TestCase):
    def setUp(self):
        import key_transport as kt
        self.kt = kt
        for k in ("VAULT_KEYS_DB", "VAULT_KEK_FILE", "VAULT_PASSPHRASE", "VAULT_AGENTS"):
            os.environ.pop(k, None)
        vault._KEYSTORE.clear(); self.addCleanup(vault._KEYSTORE.clear)
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.A, self.B = SyncSeqTest.mk(self, "a"), SyncSeqTest.mk(self, "b")
        self.da, self.db_ = sync.device_id(self.A), sync.device_id(self.B)
        for x in (self.A, self.B):
            signing.register_user_key(x)
        sync.pair(self.A, self.db_, "B"); sync.pair(self.B, self.da, "A")
        vault.append(self.A, "learning.captured", "person:t", {"text": "t", "pin": "synthetic"}, BOT, "unverified", sensitive=["pin"])
        p = os.path.join(self.d, "e.vaultsync"); sync.export(self.A, p); sync.import_package(self.B, p)
        kt.add_peer(self.A, kt.make_cert(self.B)); kt.add_peer(self.B, kt.make_cert(self.A))
        self.n = 0

    def bundle(self):
        self.n += 1; p = os.path.join(self.d, f"{self.n}.vaultkeys"); self.kt.export_keys(self.A, self.db_, p); return p

    def resign(self, p, mutate):
        b = json.load(open(p)); mutate(b)
        priv, kid = signing._current_user_key(self.A)
        b["signature"] = {"key_id": kid, "alg": "ed25519", "sig": self.kt._b64(priv.sign(self.kt._bundle_msg(b)))}
        open(p, "w").write(vault.canon(b)); return p

    def test_bundle_seq_replay_rollback_fork(self):
        kt = self.kt
        p1, p2 = self.bundle(), self.bundle()
        b1, b2 = json.load(open(p1)), json.load(open(p2))
        self.assertEqual((b1["seq"], b2["seq"]), (1, 2))
        self.assertEqual(b2["prev_bundle"], seqstate.digest(kt._bundle_msg(b1)))
        self.assertEqual(kt.import_keys(self.B, p2)["seq_state"], "new")
        self.assertEqual(kt.import_keys(self.B, p2)["seq_state"], "duplicate")
        with self.assertRaisesRegex(kt.KeyTransportError, "rollback"):
            kt.import_keys(self.B, p1)
        p3 = self.resign(self.bundle(), lambda b: b.__setitem__("prev_bundle", None))
        with self.assertRaisesRegex(kt.KeyTransportError, "fork"):
            kt.import_keys(self.B, p3)
        self.assertEqual([r["stream"] for r in seqstate.refused(self.B)], ["vaultkeys", "vaultkeys"])

    def test_unsigned_seq_tamper_refused(self):
        kt = self.kt
        p = self.bundle(); b = json.load(open(p)); b["seq"] = 99; open(p, "w").write(vault.canon(b))
        with self.assertRaisesRegex(kt.KeyTransportError, "bad bundle signature"):
            kt.import_keys(self.B, p)

    def test_legacy_bundle_refused(self):
        kt = self.kt
        p = self.resign(self.bundle(), lambda b: b.__setitem__("format", "vaultkeys/0.1"))
        with self.assertRaisesRegex(kt.KeyTransportError, "re-export"):
            kt.import_keys(self.B, p)
        self.assertIn("legacy", kt.quarantined(self.B)[-1]["reason"])


if __name__ == "__main__":
    unittest.main()
