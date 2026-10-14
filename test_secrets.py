import glob, json, os, sqlite3, subprocess, sys, unittest
from testutil import fresh, user, status, all_bytes, HAVE_CRYPTO
import vault, ops

HERE = os.path.dirname(os.path.abspath(__file__))
SECRET = "Hesap-Sifresi-ZQX7731-gizli"  # plaintext marker we grep for; gitleaks:allow (synthetic test fixture)
TOKEN_LIKE = "ghp_abcdefghijklmnopqrstuvwxyz0123"  # gitleaks:allow (synthetic test fixture)


class SecretFilterTest(unittest.TestCase):
    def setUp(self):
        fresh(self)

    def test_cli_add_refuses_secret_unless_force(self):
        run = lambda *a: subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), *a], capture_output=True, text=True)
        r = run("add", "note.added", "x", "--text", f"token {TOKEN_LIKE}")
        self.assertEqual(r.returncode, 1); self.assertIn("github_token", r.stderr); self.assertNotIn(TOKEN_LIKE, r.stderr)
        for txt in ("şifre: hunter2xx", "kart 4111 1111 1111 1111", "IBAN TR33 0006 1005 1978 6457 8413 26"):
            self.assertTrue(vault.find_secrets(txt), txt)
        r = run("add", "note.added", "x", "--text", f"token {TOKEN_LIKE}", "--force")
        self.assertEqual(r.returncode, 0, r.stderr)
        db = vault.connect(self.dbp)
        self.assertIn("add_force", [x[0] for x in db.execute("SELECT action FROM audit")])
        self.assertFalse(any(TOKEN_LIKE in (x[0] or "") for x in db.execute("SELECT reason FROM audit")))

    def test_redact_copy_removes_secret_from_new_file_and_fts(self):
        keep = user(self.db, "note.added", "x", {"text": "normal not"})
        bad = vault.append(self.db, "note.added", "x", {"text": f"yanlışlıkla {SECRET} yazıldı"}, "user:owner", "verified", force=True)[0]
        vault.audit(self.db, "user:owner", "note", "accepted", "ref", bad)
        self.assertEqual(len(vault.search(self.db, "ZQX7731")), 1)
        out = os.path.join(self.d, "clean.db")
        rep = ops.redact(self.db, bad, out, "secret leak")
        self.assertTrue(rep["verified_absent"]); self.assertGreater(rep["checked_strings"], 0)
        data = all_bytes(out)
        for needle in (SECRET, vault.tr_norm(SECRET), "zqx7731"):
            self.assertNotIn(needle.encode(), data)
        self.assertFalse(glob.glob(out + "-wal") or glob.glob(out + "-journal"))
        nd = vault.connect(out)
        self.assertEqual(vault.search(nd, "ZQX7731"), [])
        self.assertEqual(status(nd, keep), "active"); self.assertEqual(status(nd, bad), "redacted")
        red = nd.execute("SELECT kind, scope, approved_by, reason, at FROM redactions").fetchone()
        self.assertEqual((red[0], red[1], red[2]), ("redact_copy", f"event:{bad}", "user:owner")); self.assertTrue(red[4])
        self.assertTrue(nd.execute("SELECT 1 FROM events WHERE type='event.redacted'").fetchone())
        self.assertTrue(nd.execute("SELECT 1 FROM redacted_blocklist WHERE event_id=?", (bad,)).fetchone())
        self.assertTrue(ops.doctor(nd)["ok"], ops.doctor(nd))
        self.assertIn(SECRET.encode(), all_bytes(self.dbp))      # source untouched (only exception: copy-to-new-file)
        self.assertTrue(rep["warning"])                          # pre-redact snapshot keeps data -> documented warning

    def test_redact_is_human_only_cli(self):
        bad = vault.append(self.db, "note.added", "x", {"text": SECRET}, "user:owner", "verified", force=True)[0]
        env = {k: v for k, v in os.environ.items() if k != "VAULT_ALLOW_NONTTY"}
        r = subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), "redact", bad, "--out", os.path.join(self.d, "o.db"),
                            "--reason", "x"], capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL)
        self.assertEqual(r.returncode, 1); self.assertIn("interactive terminal", r.stderr)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed (run with .venv-sdk/bin/python)")
class ShredTest(unittest.TestCase):
    def setUp(self):
        fresh(self)
        self.e = vault.append(self.db, "preference.set", "user:owner", {"key": "saglik", "value": SECRET},
                              "user:owner", "verified", sensitive=["value"])[0]
        self.other = user(self.db, "preference.set", "user:owner", {"key": "dil", "value": "Türkçe"})

    def test_encrypted_at_rest_not_in_fts(self):
        row = self.db.execute("SELECT payload, payload_ct, enc_key_id, text_norm FROM events WHERE id=?", (self.e,)).fetchone()
        self.assertNotIn(SECRET, row[0]); self.assertIn("$enc", row[0]); self.assertTrue(row[1]); self.assertNotIn("zqx", row[3])
        self.assertEqual(vault.search(self.db, "ZQX7731"), [])
        self.assertIn(SECRET, [r[0] for r in self.db.execute("SELECT value FROM proj_preferences")])  # derived view decrypts
        for p in ("keys.db", "keys.kek", "v.db"):
            self.assertEqual(oct(os.stat(os.path.join(self.d, p)).st_mode & 0o777), "0o600", p)
        # AAD binds ciphertext to the event: moving it to another event id fails
        ks = vault.keystore(self.db)
        with self.assertRaises(Exception):
            ks.open(row[2], self.other, row[1])

    def test_snapshot_holds_only_ciphertext(self):
        snap, _ = ops.snapshot(self.db, "t")
        self.assertNotIn(SECRET.encode(), open(snap, "rb").read())
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(snap), "keys.db")))

    def test_shred_preview_confirm_cancel_finalize(self):
        pv = ops.shred_preview(self.db, "user:owner")
        self.assertEqual(pv["encrypted_events"], 1); self.assertEqual(pv["plaintext_events"], 1)
        ops.shred_confirm(self.db, "user:owner", grace_days=7)
        with self.assertRaisesRegex(ValueError, "grace"):
            ops.shred_finalize(self.db, "user:owner")
        ops.shred_cancel(self.db, "user:owner")                  # cancel within grace
        vault.rebuild(self.db)
        self.assertEqual(status(self.db, self.e), "active")
        ops.shred_confirm(self.db, "user:owner", grace_days=0)   # grace 0 -> finalize allowed now
        kid = ops.shred_finalize(self.db, "user:owner")
        self.assertTrue(kid)
        self.assertEqual(status(self.db, self.e), "redacted")    # rebuild doesn't crash; shows redacted
        self.assertEqual(status(self.db, self.other), "active")
        vault.rebuild(self.db); self.assertEqual(status(self.db, self.e), "redacted")
        self.assertNotIn(SECRET.encode(), all_bytes(self.dbp))
        self.assertNotIn(SECRET.encode(), all_bytes(os.path.join(self.d, "keys.db")))
        self.assertIsNone(vault.keystore(self.db).db.execute("SELECT wrapped_dek FROM subject_keys").fetchone()[0])
        self.assertTrue(self.db.execute("SELECT 1 FROM events WHERE type='subject.shredded'").fetchone())
        r = self.db.execute("SELECT kind, scope, key_id, approved_by, at FROM redactions").fetchone()
        self.assertEqual((r[0], r[1], r[2], r[3]), ("shred", "subject:user:owner", kid, "user:owner"))
        d = ops.doctor(self.db); self.assertTrue(d["ok"], d)
        self.assertEqual(vault.verify_chains(self.db), [])        # chain over ciphertext survives the shred
        h = vault.get_history(self.db, "user:owner")
        self.assertEqual([x["payload"] for x in h if x["id"] == self.e], [{"redacted": True}])


if __name__ == "__main__":
    unittest.main()
