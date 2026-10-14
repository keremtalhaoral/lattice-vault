"""Backup / restore drill (docs/backup-restore.md)."""
import json, os, shutil, sqlite3, stat, subprocess, sys, unittest
from testutil import fresh, user, status, HAVE_CRYPTO
import vault, ops, backup

HERE = os.path.dirname(os.path.abspath(__file__))
SECRET = "Gizli-Not-QWV4412-test"  # synthetic test fixture; gitleaks:allow


def head(db):
    return db.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()[0]


def rehash(bk, name):
    mp = os.path.join(bk, "manifest.json"); man = json.load(open(mp))
    man["files"][name]["sha256"] = ops._sha256_file(os.path.join(bk, name)); json.dump(man, open(mp, "w"))


class BackupRestoreTest(unittest.TestCase):
    def setUp(self):
        fresh(self)
        self.e1 = user(self.db, "preference.set", "user:owner", {"key": "dil", "value": "Türkçe"})
        self.e2 = user(self.db, "note.added", "proje:x", {"text": "ilk not"})
        self.bk = os.path.join(self.d, "bk")
        self.to = os.path.join(self.d, "restored", "vault.db")

    def test_round_trip_projections_and_chain_head(self):
        m = backup.backup(self.db, self.bk, include_keys=False)["manifest"]
        self.assertEqual(m["event_count"], 2); self.assertEqual(m["chain_head"], head(self.db))
        self.assertEqual(stat.S_IMODE(os.stat(self.bk).st_mode), 0o700)
        for f in os.listdir(self.bk):
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.bk, f)).st_mode), 0o600, f)
        self.assertEqual(set(m["files"]), {"vault.db"}); self.assertFalse(os.path.exists(os.path.join(self.bk, "keys.db")))
        ph = vault.projection_hash(self.db)
        r = backup.restore(self.bk, self.to)
        self.assertEqual(r["integrity_check"], "ok"); self.assertEqual(r["projection_hash"], ph)
        nd = vault.connect(self.to); self.addCleanup(nd.close)
        self.assertEqual(head(nd), m["chain_head"]); self.assertEqual(vault.projection_hash(nd), ph)
        self.assertEqual(status(nd, self.e1), "active")

    def test_tampered_backup_rejected(self):
        backup.backup(self.db, self.bk, include_keys=False)
        c = sqlite3.connect(os.path.join(self.bk, "vault.db")); c.execute("PRAGMA user_version=7"); c.commit(); c.close()
        with self.assertRaisesRegex(backup.BackupError, "sha256"):
            backup.restore(self.bk, self.to)
        self.assertFalse(os.path.exists(self.to))
        # attacker also rewrites the manifest: chain/trigger verification still rejects an altered event
        bk2 = os.path.join(self.d, "bk2"); backup.backup(self.db, bk2, include_keys=False)
        c = sqlite3.connect(os.path.join(bk2, "vault.db"))
        for (n,) in c.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall():
            c.execute(f"DROP TRIGGER {n}")
        c.execute("UPDATE events SET subject='evil' WHERE seq=1"); c.commit(); c.close()
        rehash(bk2, "vault.db")
        with self.assertRaises(backup.BackupError):
            backup.restore(bk2, self.to)
        self.assertFalse(os.path.exists(self.to))

    def test_refuses_overwrite_without_force(self):
        backup.backup(self.db, self.bk, include_keys=False)
        backup.restore(self.bk, self.to)
        with self.assertRaises(FileExistsError):
            backup.restore(self.bk, self.to)
        self.assertEqual(backup.restore(self.bk, self.to, force=True)["event_count"], 2)
        with self.assertRaises(FileExistsError):
            backup.backup(self.db, self.bk)          # non-empty out dir

    def test_doctor_reports_integrity_and_pragmas(self):
        d = ops.doctor(self.db)
        self.assertEqual(d["checks"]["integrity_check"], "ok"); self.assertEqual(d["checks"]["quick_check"], "ok")
        self.assertTrue(d["checks"]["ops_log_writable"])
        self.assertEqual(self.db.execute("PRAGMA busy_timeout").fetchone()[0], vault.BUSY_TIMEOUT_MS)
        self.assertEqual(self.db.execute("PRAGMA synchronous").fetchone()[0], 2)   # FULL

    def test_doctor_warns_unwritable_ops_log(self):
        os.environ["VAULT_LOG"] = os.path.join(self.d, "nope", "ops.jsonl")
        d = ops.doctor(self.db)
        self.assertFalse(d["checks"]["ops_log_writable"]); self.assertTrue(d["warnings"])

    def test_cli_restore_drill(self):
        env = dict(os.environ)
        run = lambda *a: subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), *a], capture_output=True,
                                        text=True, env=env, timeout=120)
        r = run("backup", "--out", self.bk, "--no-keys"); self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["event_count"], 2)
        r = run("restore", self.bk, "--to", self.to); self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["quick_check"], "ok")
        r = run("restore", self.bk, "--to", self.to); self.assertEqual(r.returncode, 1); self.assertIn("--force", r.stderr)
        env["VAULT_DB"] = self.to
        r = run("doctor"); self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(json.loads(r.stdout)["checks"]["integrity_check"], "ok")


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class EncryptedBackupTest(unittest.TestCase):
    def setUp(self):
        fresh(self)
        os.environ["VAULT_KEK_FILE"] = os.path.join(self.d, "keys.kek")   # KEK kept separately from the backup
        self.addCleanup(os.environ.pop, "VAULT_KEK_FILE", None)
        self.e = vault.append(self.db, "note.added", "user:owner", {"text": "acik", "secret": SECRET}, "user:owner",
                              "verified", sensitive=["secret"])[0]
        self.e2 = vault.append(self.db, "note.added", "kisi:b", {"text": "b", "secret": "ikinci-gizli"}, "user:owner",
                               "verified", sensitive=["secret"])[0]
        self.bk = os.path.join(self.d, "bk"); self.to = os.path.join(self.d, "r", "vault.db")

    def _open(self, path=None):
        vault._KEYSTORE.clear()
        nd = vault.connect(path or self.to); self.addCleanup(nd.close)
        return nd, (lambda eid: vault.decrypt_payload(nd, nd.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()))

    def test_keys_included_readable_and_wrapped(self):
        rep = backup.backup(self.db, self.bk)
        self.assertIn("keys.db", rep["manifest"]["files"]); self.assertIn("shredded AFTER", rep["warning"])
        self.assertFalse(any("kek" in f for f in os.listdir(self.bk)))
        dek = vault.keystore(self.db).dek_for("user:owner")[1]
        self.assertNotIn(dek, open(os.path.join(self.bk, "keys.db"), "rb").read())     # wrapped only
        self.assertNotIn(SECRET.encode(), open(os.path.join(self.bk, "vault.db"), "rb").read())
        backup.restore(self.bk, self.to)
        nd, dec = self._open()
        self.assertEqual(dec(self.e)["secret"], SECRET)

    def test_no_keys_backup_unreadable(self):
        backup.backup(self.db, self.bk, include_keys=False)
        self.assertTrue(backup.restore(self.bk, self.to)["warnings"])
        nd, dec = self._open()
        self.assertIsNone(dec(self.e))

    def test_missing_keys_rejected_unless_allowed(self):
        backup.backup(self.db, self.bk)
        c = sqlite3.connect(os.path.join(self.bk, "keys.db")); c.execute("DELETE FROM subject_keys WHERE subject='kisi:b'")
        c.commit(); c.close(); rehash(self.bk, "keys.db")
        with self.assertRaisesRegex(backup.BackupError, "missing"):
            backup.restore(self.bk, self.to)
        self.assertFalse(os.path.exists(self.to))
        rep = backup.restore(self.bk, self.to, allow_missing_keys=True)
        self.assertEqual(len(rep["missing_keys"]), 1); self.assertTrue(rep["warnings"])

    def test_restore_reapplies_shred_in_log(self):
        backup.backup(self.db, self.bk)                     # keys.db from before the shred ...
        ops.shred_confirm(self.db, "user:owner", 0); ops.shred_finalize(self.db, "user:owner")
        bk2 = os.path.join(self.d, "bk2"); backup.backup(self.db, bk2)
        shutil.copyfile(os.path.join(self.bk, "keys.db"), os.path.join(bk2, "keys.db")); rehash(bk2, "keys.db")
        rep = backup.restore(bk2, self.to)                  # ... paired with a log that records the shred
        self.assertEqual(rep["shreds_reapplied"], 1)
        nd, dec = self._open()
        self.assertIsNone(dec(self.e)); self.assertEqual(status(nd, self.e), "redacted")
        self.assertEqual(dec(self.e2)["secret"], "ikinci-gizli")
        self.assertTrue(ops.doctor(nd)["ok"])

    def test_drill_backup_shred_restore(self):
        old = os.path.join(self.d, "bk-old"); backup.backup(self.db, old)
        ops.shred_confirm(self.db, "user:owner", 0); ops.shred_finalize(self.db, "user:owner")
        live_ph = vault.projection_hash(self.db)
        new = os.path.join(self.d, "bk-new"); backup.backup(self.db, new)
        self.assertEqual(backup.restore(new, self.to)["projection_hash"], live_ph)
        nd, dec = self._open()
        d = ops.doctor(nd); self.assertTrue(d["ok"], d)
        self.assertEqual(vault.projection_hash(nd), live_ph)
        self.assertIsNone(dec(self.e)); self.assertEqual(status(nd, self.e), "redacted")
        self.assertEqual(dec(self.e2)["secret"], "ikinci-gizli")
        # documented limitation: the pre-shred backup (log + keys) still decrypts the shredded subject
        od, odec = self._open(os.path.join(self.d, "r-old", "vault.db")) if backup.restore(old, os.path.join(self.d, "r-old", "vault.db")) else None
        self.assertEqual(odec(self.e)["secret"], SECRET)

    def test_refuses_keys_restore_without_kek(self):
        backup.backup(self.db, self.bk)
        os.environ.pop("VAULT_KEK_FILE")
        with self.assertRaisesRegex(backup.BackupError, "KEK"):
            backup.restore(self.bk, self.to)
        self.assertFalse(os.path.exists(self.to))


if __name__ == "__main__":
    unittest.main()
