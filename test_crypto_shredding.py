"""Crypto-shredding lifecycle, local and multi-device (docs/adr/0014-crypto-shredding.md)."""
import glob, json, os, subprocess, sys, time, unittest
from unittest import mock
os.environ.setdefault("VAULT_ALLOW_NONTTY", "1")
import testutil  # noqa: F401
import vault, sync, signing
from testutil import HAVE_CRYPTO
if HAVE_CRYPTO:
    import key_transport as kt, crypto_keys, ops, backup, shredding
    import test_key_transport as _tkt

HERE = os.path.dirname(os.path.abspath(__file__))
CANARY = "KANARYA-7f3e9q"
SUBJ = "person:ayse"
LATER = 30 * 86400


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class CryptoShreddingTest(_tkt.KeyTransportTest if HAVE_CRYPTO else unittest.TestCase):
    def canary_event(self, db=None):
        db = db or self.A
        # a sensitive field in a projected type (preferences keep the decrypted value in proj_preferences)
        return vault.append(db, "preference.set", SUBJ, {"key": "pin", "value": CANARY}, "user:owner", "verified",
                            sensitive=["value"])[0]

    def files_with(self, root, needle=CANARY):
        hits = []
        for f in glob.glob(os.path.join(root, "**"), recursive=True):
            if os.path.isfile(f) and needle.encode() in open(f, "rb").read():
                hits.append(os.path.relpath(f, root))
        return hits

    def state(self, db, subj=SUBJ):
        return vault.keystore(db).info(subj)["state"]

    def finalize_now(self, db, subj=SUBJ):
        return ops.shred_finalize(db, subj, now=time.time() + LATER)

    # ------------------------------------------------------------------ local
    def test_no_plaintext_left_anywhere_after_finalize(self):
        eid = self.canary_event()
        a = os.path.join(self.d, "a")
        self.assertTrue(self.files_with(a))                       # sanity: the projection holds the decrypted value
        fts = self.A.execute("SELECT count(*) FROM events_fts WHERE events_fts MATCH ?", (CANARY.lower().split("-")[0],)).fetchone()[0]
        self.assertEqual(fts, 0)                                  # sensitive fields are never indexed
        r = ops.shred_confirm(self.A, SUBJ, 7)
        self.assertEqual(self.files_with(os.path.dirname(r["snapshot"])), [])   # pre-shred snapshot: ciphertext only
        bk = os.path.join(self.d, "bk"); backup.backup(self.A, bk)
        self.assertEqual(self.files_with(bk), [])                 # vault backups never hold derived plaintext
        self.finalize_now(self.A)
        self.assertEqual(self.files_with(a), [])                  # vault.db, keys.db, journals, snapshots, free pages
        self.assertEqual(self.payload(self.A, eid), (None, "redacted"))
        self.assertTrue(ops.doctor(self.A)["ok"]); self.assertTrue(ops.verify(self.A)["ok"])

    def test_schedule_emits_signed_event_and_cli_ux(self):
        self.canary_event()
        env = dict(os.environ, VAULT_DB=os.path.join(self.d, "a", "v.db"))
        run = lambda *a: subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), *a], capture_output=True,
                                        text=True, env=env, cwd=HERE)
        r = run("shred", SUBJ, "--confirm", "--grace-days", "3")
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertIn("grace period", r.stderr); self.assertIn("NOT affected", r.stderr)
        out = json.loads(r.stdout); self.assertIn("destroy_after_utc", out); self.assertIn("shred-finalize", out["next"])
        r = run("shred-finalize", SUBJ)
        self.assertEqual(r.returncode, 1); self.assertIn("grace period not over", r.stderr)
        r = run("shred", SUBJ, "--confirm")
        self.assertEqual(r.returncode, 1); self.assertIn("already pending", r.stderr)
        vault._KEYSTORE.clear()
        ev = self.A.execute("SELECT id FROM events WHERE type='subject.shred_scheduled'").fetchone()[0]
        self.assertEqual(signing.classify(self.A)[ev][1], "signed")
        r = run("shred-cancel", SUBJ); self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.A.execute("SELECT count(*) FROM events WHERE type='subject.shred_cancelled'").fetchone()[0], 1)

    def test_crash_after_shredded_event_completed_on_open(self):
        eid = self.canary_event()
        ops.shred_confirm(self.A, SUBJ, 0); time.sleep(0.01)
        with mock.patch.object(crypto_keys.KeyStore, "finalize", side_effect=RuntimeError("crash")):
            with self.assertRaises(RuntimeError):
                ops.shred_finalize(self.A, SUBJ)
        self.assertEqual(self.payload(self.A, eid), (None, "redacted"))     # refused at once
        self.assertTrue(ops.verify(self.A)["problems"])                     # verify reports, read-only
        self.assertEqual(self.state(self.A), "pending_destroy")
        vault._KEYSTORE.clear()
        db2 = vault.connect(os.path.join(self.d, "a", "v.db")); self.addCleanup(db2.close)
        self.assertEqual(self.state(db2), "destroyed")
        self.assertEqual(db2.execute("SELECT count(*) FROM redactions WHERE kind='shred'").fetchone()[0], 1)
        self.assertTrue(ops.doctor(db2)["ok"])
        self.assertEqual(self.files_with(os.path.join(self.d, "a")), [])

    def test_crash_after_scheduled_event_completed_on_open(self):
        self.canary_event()
        with mock.patch.object(crypto_keys.KeyStore, "schedule_destroy", side_effect=RuntimeError("crash")):
            with self.assertRaises(RuntimeError):
                ops.shred_confirm(self.A, SUBJ, 2)
        self.assertEqual(self.state(self.A), "active")
        self.assertEqual(len(ops.verify(self.A)["problems"]), 1)
        vault._KEYSTORE.clear()
        db2 = vault.connect(os.path.join(self.d, "a", "v.db")); self.addCleanup(db2.close)
        i = vault.keystore(db2).info(SUBJ)
        self.assertEqual(i["state"], "pending_destroy"); self.assertGreater(i["destroy_after"], time.time() + 86400)

    def test_unsigned_or_agent_lifecycle_event_ignored(self):
        eid = self.canary_event()
        kid = vault.keystore(self.A).info(SUBJ)["key_id"]
        vault.append(self.A, "subject.shred_scheduled", SUBJ, {"key_id": kid, "grace_seconds": 0}, "agent:bot", "unverified")
        shredding.reconcile(self.A)
        self.assertEqual(self.state(self.A), "active")
        self.assertEqual(self.payload(self.A, eid)[0]["value"], CANARY)

    # ------------------------------------------------------------------ multi-device
    def two(self):   # agent content syncs without a user signature; the sensitive field is encrypted the same way
        eid = vault.append(self.A, "learning.captured", SUBJ, {"text": "not", "value": CANARY}, "agent:bot", "unverified",
                           sensitive=["value"])[0]
        self.sync_events(self.A, self.B); self.ready()
        kt.import_keys(self.B, self.bundle())
        self.assertEqual(self.payload(self.B, eid)[0]["value"], CANARY)
        return eid

    def test_pending_shred_and_cancel_propagate(self):
        eid = self.two()
        ops.shred_confirm(self.A, SUBJ, 7)
        r = self.sync_events(self.A, self.B)
        self.assertEqual(len(r["pending_destroy_keys"]), 1)
        self.assertEqual(self.state(self.B), "pending_destroy")
        self.assertEqual(self.payload(self.B, eid)[0]["value"], CANARY)       # still readable while pending
        ops.shred_cancel(self.A, SUBJ)
        self.sync_events(self.A, self.B)
        self.assertEqual(self.state(self.B), "active")
        self.assertTrue(ops.doctor(self.B)["ok"])

    def test_finalized_shred_propagates_and_leaves_no_plaintext(self):
        eid = self.two()
        ops.shred_confirm(self.A, SUBJ, 0); time.sleep(0.01); ops.shred_finalize(self.A, SUBJ)
        self.sync_events(self.A, self.B)
        self.assertEqual(self.state(self.B), "pending_destroy")
        self.assertEqual(self.payload(self.B, eid), (None, "redacted"))
        shredding.reconcile(self.B, now=time.time() + LATER)
        self.assertEqual(self.state(self.B), "destroyed")
        vault.rebuild(self.B); self.B.execute("VACUUM")
        self.assertEqual(self.files_with(os.path.join(self.d, "b")), [])
        d = ops.doctor(self.B); self.assertTrue(d["ok"], d["problems"])
        self.assertEqual(self.files_with(os.path.join(self.d, "a")), [])

    def test_cancel_on_receiver_propagates_back(self):
        self.two()
        ops.shred_confirm(self.A, SUBJ, 7); self.sync_events(self.A, self.B)
        ops.shred_cancel(self.B, SUBJ)                                         # the owner undoes it on the other device
        self.assertEqual(self.state(self.B), "active")
        self.sync_events(self.B, self.A)
        self.assertEqual(self.state(self.A), "active")

    def test_schedule_from_revoked_origin_ignored(self):
        eid = self.two()
        kt.revoke_peer(self.B, self.da, "lost device")
        ops.shred_confirm(self.A, SUBJ, 0); self.sync_events(self.A, self.B)
        self.assertEqual(self.state(self.B), "active")
        self.assertTrue(any("revoked" in q["reason"] for q in kt.quarantined(self.B)))
        self.assertEqual(self.payload(self.B, eid)[0]["value"], CANARY)

    # ------------------------------------------------------------------ backups
    def test_restore_old_vault_backup_with_newer_log_via_sync(self):
        """An old vault backup has no shred event; syncing from a device that has it shreds the restored copy."""
        eid = self.two()
        bk = os.path.join(self.d, "bk-old"); backup.backup(self.B, bk)
        ops.shred_confirm(self.A, SUBJ, 0); time.sleep(0.01); ops.shred_finalize(self.A, SUBJ)
        self.sync_events(self.A, self.B)
        shredding.reconcile(self.B, now=time.time() + LATER)
        to = os.path.join(self.d, "b2", "v.db"); os.makedirs(os.path.dirname(to))
        os.environ["VAULT_KEYS_DB"] = os.path.join(self.d, "b", "keys.db"); os.environ["VAULT_KEK_FILE"] = os.path.join(self.d, "b", "keys.kek")
        self.addCleanup(os.environ.pop, "VAULT_KEYS_DB", None); self.addCleanup(os.environ.pop, "VAULT_KEK_FILE", None)
        backup.restore(bk, to, allow_no_keys=True)
        vault._KEYSTORE.clear()
        r = vault.connect(to); self.addCleanup(r.close)
        self.assertEqual(self.payload(r, eid), (None, "redacted"))       # the current keys.db no longer has the DEK


if HAVE_CRYPTO:   # reuse the two-device fixture, not the key-transport tests themselves
    for _n in [n for n in dir(_tkt.KeyTransportTest) if n.startswith("test_")]:
        setattr(CryptoShreddingTest, _n, None)


if __name__ == "__main__":
    unittest.main()
