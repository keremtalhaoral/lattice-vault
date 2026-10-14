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
        m = backup.backup(self.db, self.bk)["manifest"]
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
        backup.backup(self.db, self.bk)
        c = sqlite3.connect(os.path.join(self.bk, "vault.db")); c.execute("PRAGMA user_version=7"); c.commit(); c.close()
        with self.assertRaisesRegex(backup.BackupError, "sha256"):
            backup.restore(self.bk, self.to)
        self.assertFalse(os.path.exists(self.to))
        # attacker also rewrites the manifest: chain/trigger verification still rejects an altered event
        bk2 = os.path.join(self.d, "bk2"); backup.backup(self.db, bk2)
        c = sqlite3.connect(os.path.join(bk2, "vault.db"))
        for (n,) in c.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall():
            c.execute(f"DROP TRIGGER {n}")
        c.execute("UPDATE events SET subject='evil' WHERE seq=1"); c.commit(); c.close()
        rehash(bk2, "vault.db")
        with self.assertRaises(backup.BackupError):
            backup.restore(bk2, self.to)
        self.assertFalse(os.path.exists(self.to))

    def test_refuses_overwrite_without_force(self):
        backup.backup(self.db, self.bk)
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

    def full(self, name):
        bk, kd = os.path.join(self.d, name), os.path.join(self.d, name + "-keys")
        backup.backup(self.db, bk); backup.backup_keys(self.db, kd)
        return bk, kd

    def test_default_backup_has_no_keys(self):
        m = backup.backup(self.db, self.bk)["manifest"]
        self.assertFalse(m["includes_keys"]); self.assertEqual(set(m["files"]), {"vault.db"})
        self.assertEqual(sorted(os.listdir(self.bk)), ["manifest.json", "vault.db"])
        with self.assertRaises(backup.BackupError):
            backup.backup(self.db, os.path.join(self.d, "x"), include_keys=True)

    def test_backup_keys_separate_and_wrapped(self):
        bk, kd = self.full("b")
        rep = backup.backup_keys(self.db, os.path.join(self.d, "k2"))
        self.assertIn("shredded AFTER", rep["warning"]); self.assertEqual(len(rep["manifest"]["keys"]), 2)
        self.assertEqual(sorted(os.listdir(kd)), ["keys.db", "manifest.json"])
        self.assertEqual(stat.S_IMODE(os.stat(kd).st_mode), 0o700)
        dek = vault.keystore(self.db).dek_for("user:owner")[1]
        self.assertNotIn(dek, open(os.path.join(kd, "keys.db"), "rb").read())     # wrapped only
        self.assertNotIn(SECRET.encode(), open(os.path.join(bk, "vault.db"), "rb").read())
        backup.restore(bk, self.to, keys_dir=kd)
        nd, dec = self._open()
        self.assertEqual(dec(self.e)["secret"], SECRET)

    def test_backup_keys_overlap_refused(self):
        backup.backup(self.db, self.bk)
        for target in (self.bk, os.path.join(self.bk, "keys"), self.d):          # same, inside, contains
            with self.subTest(target=target):
                with self.assertRaisesRegex(backup.BackupError, "overlaps"):
                    backup.backup_keys(self.db, target)
        kd = os.path.join(self.d, "kk"); backup.backup_keys(self.db, kd)
        with self.assertRaisesRegex(backup.BackupError, "overlaps"):
            backup.backup(self.db, os.path.join(kd, "v"))
        with self.assertRaisesRegex(backup.BackupError, "not a keys backup"):
            backup.restore(self.bk, self.to, keys_dir=self.bk)

    def test_no_keys_restore_refused_when_encrypted(self):
        backup.backup(self.db, self.bk)
        with self.assertRaisesRegex(backup.BackupError, "--allow-no-keys"):
            backup.restore(self.bk, self.to)
        self.assertFalse(os.path.exists(self.to))

    def test_no_keys_restore_override_undecryptable_no_kek_created(self):
        backup.backup(self.db, self.bk)
        os.environ.pop("VAULT_KEK_FILE", None); os.environ.pop("VAULT_KEYS_DB", None)
        self.assertTrue(backup.restore(self.bk, self.to, allow_no_keys=True)["warnings"])
        tdir = os.path.dirname(self.to)
        self.assertNotIn("keys.db", os.listdir(tdir)); self.assertNotIn("keys.kek", os.listdir(tdir))
        c = sqlite3.connect(self.to)
        self.assertEqual(c.execute("SELECT status FROM proj_status WHERE event_id=?", (self.e,)).fetchone()[0], "undecryptable")
        c.close()

    def test_missing_keys_rejected_unless_allowed(self):
        bk, kd = self.full("b")
        c = sqlite3.connect(os.path.join(kd, "keys.db")); c.execute("DELETE FROM subject_keys WHERE subject='kisi:b'")
        c.commit(); c.close(); rehash(kd, "keys.db")
        mp = os.path.join(kd, "manifest.json"); man = json.load(open(mp))
        man["keys"] = [k for k in man["keys"] if k["key_id"] != vault.keystore(self.db).info("kisi:b")["key_id"]]
        json.dump(man, open(mp, "w"))
        with self.assertRaisesRegex(backup.BackupError, "missing"):
            backup.restore(bk, self.to, keys_dir=kd)
        self.assertFalse(os.path.exists(self.to))
        rep = backup.restore(bk, self.to, allow_missing_keys=True, keys_dir=kd)
        self.assertEqual(len(rep["missing_keys"]), 1); self.assertTrue(rep["warnings"])

    def test_restore_reapplies_shred_in_log(self):
        _, old_keys = self.full("b")                         # keys.db from before the shred ...
        ops.shred_confirm(self.db, "user:owner", 0); ops.shred_finalize(self.db, "user:owner")
        bk2 = os.path.join(self.d, "bk2"); backup.backup(self.db, bk2)
        rep = backup.restore(bk2, self.to, keys_dir=old_keys)   # ... paired with a log that records the shred
        self.assertEqual(rep["shreds_reapplied"], 1)
        nd, dec = self._open()
        self.assertIsNone(dec(self.e)); self.assertEqual(status(nd, self.e), "redacted")
        self.assertEqual(dec(self.e2)["secret"], "ikinci-gizli")
        self.assertTrue(ops.doctor(nd)["ok"])

    def test_drill_backup_shred_restore(self):
        old, old_keys = self.full("old")
        ops.shred_confirm(self.db, "user:owner", 0); ops.shred_finalize(self.db, "user:owner")
        live_ph = vault.projection_hash(self.db)
        new, new_keys = self.full("new")
        self.assertEqual(backup.restore(new, self.to, keys_dir=new_keys)["projection_hash"], live_ph)
        nd, dec = self._open()
        d = ops.doctor(nd); self.assertTrue(d["ok"], d)
        self.assertEqual(vault.projection_hash(nd), live_ph)
        self.assertIsNone(dec(self.e)); self.assertEqual(status(nd, self.e), "redacted")
        self.assertEqual(dec(self.e2)["secret"], "ikinci-gizli")
        # documented limitation: the pre-shred vault + keys backups still decrypt the shredded subject
        op = os.path.join(self.d, "r-old", "vault.db"); backup.restore(old, op, keys_dir=old_keys)
        od, odec = self._open(op)
        self.assertEqual(odec(self.e)["secret"], SECRET)

    def test_cli_backup_keys_and_restore(self):
        env = dict(os.environ)
        run = lambda *a: subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), *a], capture_output=True,
                                        text=True, env=env, timeout=120)
        self.db.close()
        kd = os.path.join(self.d, "kd")
        r = run("backup", "--out", self.bk, "--no-keys"); self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("deprecated", r.stderr); self.assertFalse(json.loads(r.stdout)["includes_keys"])
        r = run("backup-keys", "--out", self.bk); self.assertEqual(r.returncode, 1); self.assertIn("overlaps", r.stderr)
        r = run("backup-keys", "--out", kd); self.assertEqual(r.returncode, 0, r.stderr); self.assertIn("WARNING", r.stderr)
        r = run("restore", self.bk, "--to", self.to, "--keys", kd); self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(json.loads(r.stdout)["keys_restored"])
        self.db = vault.connect(self.dbp)
        nd, dec = self._open()
        self.assertEqual(dec(self.e)["secret"], SECRET)

    def test_refuses_keys_restore_without_kek(self):
        bk, kd = self.full("b")
        os.environ.pop("VAULT_KEK_FILE")
        with self.assertRaisesRegex(backup.BackupError, "KEK"):
            backup.restore(bk, self.to, keys_dir=kd)
        self.assertFalse(os.path.exists(self.to))


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class RestoreKeyVerificationTest(unittest.TestCase):
    """Restore drill 2026-10-14 regressions: wrong KEK, keyless restore, undecryptable state, doctor decrypt check."""
    def setUp(self):
        fresh(self)
        os.environ["VAULT_KEK_FILE"] = os.path.join(self.d, "keys.kek")
        self.addCleanup(os.environ.pop, "VAULT_KEK_FILE", None)
        self.e = vault.append(self.db, "note.added", "user:owner", {"text": "acik", "secret": SECRET}, "user:owner",
                              "verified", sensitive=["secret"])[0]
        self.e2 = vault.append(self.db, "note.added", "kisi:b", {"text": "b", "secret": "ikinci-gizli"}, "user:owner",
                               "verified", sensitive=["secret"])[0]
        self.bk = os.path.join(self.d, "bk"); self.kd = os.path.join(self.d, "keys")
        backup.backup(self.db, self.bk); backup.backup_keys(self.db, self.kd)
        self.tdir = os.path.join(self.d, "r"); self.to = os.path.join(self.tdir, "vault.db")
        os.environ.pop("VAULT_KEK_FILE")          # restore target uses its own keys.kek next to vault.db

    def _wrong_kek(self):
        os.makedirs(self.tdir, mode=0o700, exist_ok=True)
        fd = os.open(os.path.join(self.tdir, "keys.kek"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, os.urandom(32)); os.close(fd)

    def _good_kek(self):
        os.makedirs(self.tdir, mode=0o700, exist_ok=True)
        shutil.copy(os.path.join(self.d, "keys.kek"), os.path.join(self.tdir, "keys.kek"))
        os.chmod(os.path.join(self.tdir, "keys.kek"), 0o600)

    def test_wrong_kek_rejected(self):
        self._wrong_kek()
        with self.assertRaisesRegex(backup.BackupError, "KEK does not match"):
            backup.restore(self.bk, self.to, keys_dir=self.kd)
        self.assertEqual(os.listdir(self.tdir), ["keys.kek"])            # nothing restored, no staging left

    def test_wrong_kek_rejected_even_with_force_over_existing(self):
        self._wrong_kek()
        backup.restore(self.bk, self.to, allow_no_keys=True)              # keyless restore first (drill path)
        with self.assertRaisesRegex(backup.BackupError, "KEK does not match"):
            backup.restore(self.bk, self.to, force=True, keys_dir=self.kd)

    def test_right_kek_reports_verification(self):
        self._good_kek()
        rep = backup.restore(self.bk, self.to, keys_dir=self.kd)
        self.assertEqual(rep["kek_verified"], {"keys_checked": 2, "events_checked": 2, "check_value": "ok", "tested": True})
        self.assertFalse(rep["warnings"])

    def test_kek_backup_separate_and_restorable(self):
        os.environ["VAULT_KEK_FILE"] = os.path.join(self.d, "keys.kek")
        kekd = os.path.join(self.d, "kek")
        rep = backup.backup_kek(self.db, kekd)
        self.assertIn("apart", rep["warning"]); self.assertEqual(sorted(os.listdir(kekd)), ["keys.kek", "manifest.json"])
        for target in (self.kd, os.path.join(self.bk, "x")):
            with self.assertRaisesRegex(backup.BackupError, "overlaps"):
                backup.backup_kek(self.db, target)
        with self.assertRaisesRegex(backup.BackupError, "overlaps"):
            backup.backup_keys(self.db, os.path.join(kekd, "k"))
        self.assertNotIn("keys.kek", os.listdir(self.kd))                 # keys backup never carries the KEK
        os.environ.pop("VAULT_KEK_FILE")
        rep = backup.restore(self.bk, self.to, keys_dir=self.kd, kek_dir=kekd)
        self.assertTrue(rep["kek_installed"])
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.tdir, "keys.kek")).st_mode), 0o600)
        vault._KEYSTORE.clear(); nd = vault.connect(self.to); self.addCleanup(nd.close)
        self.assertEqual(vault.decrypt_payload(nd, nd.execute("SELECT * FROM events WHERE id=?", (self.e,)).fetchone())["secret"], SECRET)
        self.assertTrue(ops.doctor(nd)["ok"])

    def test_kek_never_overwritten(self):
        os.environ["VAULT_KEK_FILE"] = os.path.join(self.d, "keys.kek")
        kekd = os.path.join(self.d, "kek"); backup.backup_kek(self.db, kekd); os.environ.pop("VAULT_KEK_FILE")
        self._wrong_kek()
        with self.assertRaisesRegex(backup.BackupError, "different KEK already exists"):
            backup.restore(self.bk, self.to, keys_dir=self.kd, kek_dir=kekd, force=True)

    def test_doctor_detects_undecryptable_and_state(self):
        self._good_kek()
        backup.restore(self.bk, self.to, keys_dir=self.kd)
        os.chmod(os.path.join(self.tdir, "keys.kek"), 0o600)
        with open(os.path.join(self.tdir, "keys.kek"), "wb") as f:      # KEK swapped after restore
            f.write(os.urandom(32))
        vault._KEYSTORE.clear(); nd = vault.connect(self.to); self.addCleanup(nd.close)
        vault.rebuild(nd)
        self.assertEqual(status(nd, self.e), "undecryptable")              # not 'redacted'
        rep = ops.doctor(nd)
        self.assertFalse(rep["ok"]); self.assertEqual(rep["checks"]["decrypt"]["undecryptable_keys"], 2)
        self.assertTrue(any("cannot be unwrapped" in p for p in rep["problems"]))
        self.assertEqual(ops.doctor(nd, decrypt_all=True)["checks"]["decrypt"]["mode"], "all")

    def test_doctor_full_decrypt_mode(self):
        self._good_kek()
        backup.restore(self.bk, self.to, keys_dir=self.kd)
        vault._KEYSTORE.clear(); nd = vault.connect(self.to); self.addCleanup(nd.close)
        self.assertTrue(ops.doctor(nd, decrypt_all=True)["ok"])
        self.assertEqual(ops.doctor(nd, decrypt_all=True)["checks"]["decrypt"]["events_checked"], 2)

    def test_shredded_vs_missing_in_doctor(self):
        os.environ["VAULT_KEK_FILE"] = os.path.join(self.d, "keys.kek")
        ops.shred_confirm(self.db, "kisi:b", 0); ops.shred_finalize(self.db, "kisi:b")
        rep = ops.doctor(self.db)
        self.assertTrue(rep["ok"], rep["problems"])
        self.assertEqual(rep["checks"]["shredded_keys"], 1); self.assertEqual(rep["checks"]["events_with_missing_keys"], 0)
        self.assertEqual(status(self.db, self.e2), "redacted")              # crypto-shredded stays 'redacted'
        c = vault.keystore(self.db).db; c.execute("DELETE FROM subject_keys WHERE subject='user:owner'"); c.commit()
        rep = ops.doctor(self.db)
        self.assertEqual(rep["checks"]["events_with_missing_keys"], 1); self.assertEqual(rep["checks"]["shredded_keys"], 1)
        vault.rebuild(self.db); self.assertEqual(status(self.db, self.e), "undecryptable")

    def test_corrupt_row_error_sanitized(self):
        bad = os.path.join(self.d, "bad"); shutil.copytree(self.bk, bad)
        p = os.path.join(bad, "vault.db"); b = bytearray(open(p, "rb").read())
        i = b.find(b'"acik"'); self.assertGreater(i, 0); b[i + 1] = 0xFF; open(p, "wb").write(b); rehash(bad, "vault.db")
        with self.assertRaises(backup.BackupError) as cm:
            backup.restore(bad, self.to, keys_dir=self.kd)
        self.assertNotIn("cik", str(cm.exception))

    def test_verify_command(self):
        rep = ops.verify(self.db)
        self.assertTrue(rep["ok"]); self.assertEqual(rep["projection_hash"], vault.projection_hash(self.db))


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class ReliabilityFollowupTest(unittest.TestCase):
    """PR #8 re-verification items R1-R4."""
    def setUp(self):
        fresh(self)
        self.e = vault.append(self.db, "note.added", "user:owner", {"text": "acik", "secret": SECRET}, "user:owner",
                              "verified", sensitive=["secret"])[0]
        self.e2 = vault.append(self.db, "note.added", "kisi:b", {"text": "b", "secret": "ikinci-gizli"}, "user:owner",
                               "verified", sensitive=["secret"])[0]
        self.tdir = os.path.join(self.d, "r"); self.to = os.path.join(self.tdir, "vault.db")

    def _cli(self, *args, db=None):
        env = dict(os.environ, VAULT_DB=db or self.to, VAULT_ALLOW_NONTTY="1")
        return subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), *args], capture_output=True, text=True, env=env)

    def test_r1_read_only_commands_never_create_keystore(self):
        bk = os.path.join(self.d, "bk"); backup.backup(self.db, bk)
        backup.restore(bk, self.to, allow_no_keys=True)
        for cmd in (["verify"], ["doctor"], ["history", "user:owner"], ["search", "acik"]):
            with self.subTest(cmd=cmd):
                self._cli(*cmd)
                self.assertEqual(sorted(f for f in os.listdir(self.tdir) if f.startswith("keys")), [])
        vault._KEYSTORE.clear(); nd = vault.connect(self.to); self.addCleanup(nd.close)
        self.assertEqual(status(nd, self.e), "undecryptable")
        rep = ops.doctor(nd)
        self.assertFalse(rep["ok"]); self.assertEqual(rep["checks"]["events_with_missing_keys"], 2)
        self.assertEqual(os.listdir(self.tdir).count("keys.kek"), 0)

    def test_r1_write_with_encrypted_events_but_no_kek_fails_loudly(self):
        bk = os.path.join(self.d, "bk"); backup.backup(self.db, bk)
        backup.restore(bk, self.to, allow_no_keys=True)
        vault._KEYSTORE.clear(); nd = vault.connect(self.to); self.addCleanup(nd.close)
        import crypto_keys
        with self.assertRaisesRegex(crypto_keys.KeystoreMissing, "refusing to create a new KEK"):
            vault.append(nd, "note.added", "user:owner", {"text": "t", "secret": "x"}, "user:owner", "verified", sensitive=["secret"])
        self.assertNotIn("keys.kek", os.listdir(self.tdir))

    def test_r1_keys_db_without_kek_fails_loudly(self):
        os.remove(os.path.join(self.d, "keys.kek")); vault._KEYSTORE.clear()
        import crypto_keys
        with self.assertRaisesRegex(crypto_keys.KeystoreMissing, "no KEK"):
            vault.keystore(self.db)
        with self.assertRaisesRegex(crypto_keys.KeystoreMissing, "no KEK"):
            vault.keystore(self.db, create=True)
        self.assertNotIn("keys.kek", os.listdir(self.d))
        rep = ops.doctor(self.db); self.assertFalse(rep["ok"]); self.assertEqual(rep["checks"]["keystore"], "unavailable")

    def test_r1_plain_vault_creates_keystore_only_on_sensitive_write(self):
        d = os.path.join(self.d, "plain"); os.makedirs(d); p = os.path.join(d, "v.db")
        os.environ.pop("VAULT_KEK_FILE", None)
        nd = vault.connect(p); self.addCleanup(nd.close)
        vault.append(nd, "note.added", "x:y", {"text": "plain"}, "user:owner", "verified")
        self.assertTrue(ops.doctor(nd)["ok"]); ops.verify(nd)
        self.assertEqual(sorted(os.listdir(d)), ["v.db"])
        vault.append(nd, "note.added", "x:y", {"text": "t", "secret": "s"}, "user:owner", "verified", sensitive=["secret"])
        self.assertIn("keys.kek", os.listdir(d)); self.assertIn("keys.db", os.listdir(d))

    def test_r2_kek_untested_warned_and_check_value_catches_wrong_kek(self):
        ops.shred_confirm(self.db, "user:owner", 0); ops.shred_finalize(self.db, "user:owner")
        ops.shred_confirm(self.db, "kisi:b", 0); ops.shred_finalize(self.db, "kisi:b")   # no live DEKs left
        bk, kd = os.path.join(self.d, "bk"), os.path.join(self.d, "kd")
        backup.backup(self.db, bk); backup.backup_keys(self.db, kd)
        os.makedirs(self.tdir, mode=0o700)
        fd = os.open(os.path.join(self.tdir, "keys.kek"), os.O_WRONLY | os.O_CREAT, 0o600); os.write(fd, os.urandom(32)); os.close(fd)
        with self.assertRaisesRegex(backup.BackupError, "check value"):      # wrong KEK caught with 0 live keys
            backup.restore(bk, self.to, keys_dir=kd)
        shutil.copy(os.path.join(self.d, "keys.kek"), os.path.join(self.tdir, "keys.kek"))
        rep = backup.restore(bk, self.to, keys_dir=kd)
        self.assertEqual(rep["kek_verified"]["keys_checked"], 0); self.assertEqual(rep["kek_verified"]["check_value"], "ok")
        self.assertTrue(rep["kek_verified"]["tested"])
        # legacy keys.db without a check value and no live keys -> explicit "not verified" warning
        c = sqlite3.connect(os.path.join(kd, "keys.db")); c.execute("DROP TABLE kek_check"); c.commit(); c.close()
        rehash(kd, "keys.db")
        rep = backup.restore(bk, self.to, keys_dir=kd, force=True)
        self.assertFalse(rep["kek_verified"]["tested"])
        self.assertTrue(any("KEK NOT VERIFIED" in w for w in rep["warnings"]))

    def test_r3_keyless_restore_shredded_stays_redacted(self):
        ops.shred_confirm(self.db, "kisi:b", 0); ops.shred_finalize(self.db, "kisi:b")
        bk = os.path.join(self.d, "bk"); backup.backup(self.db, bk)
        backup.restore(bk, self.to, allow_no_keys=True)
        vault._KEYSTORE.clear(); nd = vault.connect(self.to); self.addCleanup(nd.close)
        self.assertEqual(status(nd, self.e2), "redacted")
        self.assertEqual(status(nd, self.e), "undecryptable")
        rep = ops.doctor(nd)
        self.assertEqual(rep["checks"]["shredded_keys"], 1); self.assertEqual(rep["checks"]["events_with_missing_keys"], 1)

    def test_r4_missing_vault_db_not_auto_created(self):
        missing = os.path.join(self.d, "typo", "vault.db"); os.makedirs(os.path.dirname(missing))
        for cmd in (["verify"], ["doctor"], ["search", "x"], ["add", "note.added", "x:y", "--text", "hi"]):
            with self.subTest(cmd=cmd):
                r = self._cli(*cmd, db=missing)
                self.assertEqual(r.returncode, 1, r.stderr); self.assertIn("vault init", r.stderr)
                self.assertNotIn("Traceback", r.stderr); self.assertFalse(os.path.exists(missing))
        os.environ["VAULT_DB"] = missing
        with self.assertRaises(vault.VaultNotFound):
            vault.connect()
        r = self._cli("init", db=missing); self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(missing))
        self.assertEqual(self._cli("init", db=missing).returncode, 1)       # never re-inits an existing vault
        self.assertEqual(self._cli("add", "note.added", "x:y", "--text", "hi", db=missing).returncode, 0)
