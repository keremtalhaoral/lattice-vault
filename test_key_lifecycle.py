"""Key rotation, revocation, offline recovery code, second anchor (docs/adr/0012-key-lifecycle.md)."""
import json, os, subprocess, sys, unittest
from unittest import mock
import testutil
from testutil import fresh, agent, status, HAVE_CRYPTO
import vault, signing, ops

HERE = os.path.dirname(os.path.abspath(__file__))
H = "user:owner"


def rj(p):
    with open(p) as f:
        return json.load(f)


def approve_one(db, text):
    p = agent(db, "note.added", "x", {"text": text}); vault.review(db, p, "approve"); return p


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class Rotation(unittest.TestCase):
    def setUp(self):
        fresh(self)
        self.p1 = approve_one(self.db, "before")
        self.old = signing.load_user_key()[1]
        self.newp = os.path.join(self.d, "new.key")

    def test_rotate_keeps_old_signatures_and_switches_signer(self):
        old, new = signing.rotate_user_key(self.db, self.newp)
        self.assertEqual(old, self.old)
        keys, probs = signing.registered_keys(self.db)
        self.assertEqual(probs, [])
        self.assertIsNotNone(keys[old]["revoked_hlc"]); self.assertIsNone(keys[new]["revoked_hlc"])
        cls = signing.classify(self.db)
        self.assertTrue(all(st == "signed" for _, st in cls.values()), cls)    # old approvals + key events stay valid
        with self.assertRaisesRegex(signing.SignatureError, "revoked"):       # old key can no longer sign
            approve_one(self.db, "with old key")
        self.db.rollback()
        with mock.patch.dict(os.environ, {"VAULT_USER_KEY": self.newp}):
            p2 = approve_one(self.db, "with new key")
            self.assertEqual(status(self.db, p2), "active")
            rep = ops.verify(self.db)
            self.assertTrue(rep["ok"], rep)
        self.assertEqual(rj(signing.anchor_path(self.dbp))["key_id"], new)

    def test_rotate_refuses_existing_path_and_same_path(self):
        open(self.newp, "w").close()
        with self.assertRaises(FileExistsError):
            signing.rotate_user_key(self.db, self.newp)
        with self.assertRaisesRegex(signing.SignatureError, "new path"):
            signing.rotate_user_key(self.db, signing.key_path())

    def test_old_key_signing_after_revocation_is_flagged(self):
        signing.rotate_user_key(self.db, self.newp)
        old_priv = signing.load_user_key()
        row = self.db.execute("SELECT * FROM events WHERE id=?", (self.p1,)).fetchone()
        # an attacker holding the old key file forges a post-revocation registration: the registry rejects it
        _, probs = signing.registered_keys(self.db)
        self.assertEqual(probs, [])
        with self.assertRaises(signing.SignatureError):
            signing._append_signed(self.db, old_priv, "key.registered", "key:x",
                                   {"key_id": "user/ed25519/0000000000000000", "alg": "ed25519", "role": "user",
                                    "pubkey_b64": "AA==", "certified_by": old_priv[1]}, H)
        self.db.rollback()

    def test_revoked_key_anchor_rejected(self):
        signing.rotate_user_key(self.db, self.newp)
        old = signing.load_user_key()
        self.assertIsNone(signing.write_anchor(self.db, key=old))           # never anchors with a revoked key
        body = {"v": 1, "db": os.path.abspath(self.dbp), "events": {"seq": 0, "hash": None},
                "audit": {"id": 0, "hash": None}, "key_id": old[1], "written_at": "x"}
        body["sig"] = signing.b64(old[0].sign(signing.ANCHOR_DOMAIN + signing.canon(body).encode()))
        signing._write_atomic(signing.anchor_path(self.dbp), body)
        errs, _ = signing.check_anchor(self.db)
        self.assertTrue(any("revoked" in e for e in errs), errs)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class Revoke(unittest.TestCase):
    def setUp(self):
        fresh(self); approve_one(self.db, "a")

    def test_cannot_revoke_self_or_unknown(self):
        me = signing.load_user_key()[1]
        with self.assertRaisesRegex(signing.SignatureError, "rotate"):
            signing.revoke_key(self.db, me, "x")
        with self.assertRaisesRegex(signing.SignatureError, "not a registered"):
            signing.revoke_key(self.db, "user/ed25519/ffffffffffffffff", "x")

    def test_revoke_recovery_key(self):
        _, rk = signing.new_recovery_code(self.db)
        signing.revoke_key(self.db, rk, "lost paper")
        keys, probs = signing.registered_keys(self.db)
        self.assertEqual(probs, []); self.assertIsNotNone(keys[rk]["revoked_hlc"])


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class Recovery(unittest.TestCase):
    def setUp(self):
        fresh(self); self.p1 = approve_one(self.db, "a")
        self.newp = os.path.join(self.d, "recovered.key")

    def test_code_stored_only_as_public_key(self):
        code, rk = signing.new_recovery_code(self.db)
        self.assertTrue(rk.startswith("recovery/ed25519/"))
        self.db.commit()
        blob = testutil.all_bytes(self.dbp)
        self.assertNotIn(code.encode(), blob); self.assertNotIn(code.replace("-", "").encode(), blob)

    def test_new_code_revokes_previous(self):
        _, r1 = signing.new_recovery_code(self.db)
        _, r2 = signing.new_recovery_code(self.db)
        keys = signing.registered_keys(self.db)[0]
        self.assertIsNotNone(keys[r1]["revoked_hlc"]); self.assertIsNone(keys[r2]["revoked_hlc"])

    def test_recover_lost_key(self):
        code, rk = signing.new_recovery_code(self.db)
        old = signing.load_user_key()[1]
        new = signing.recover_with_code(self.db, code.lower(), self.newp)   # case/dash tolerant
        keys, probs = signing.registered_keys(self.db)
        self.assertEqual(probs, [])
        self.assertIsNotNone(keys[old]["revoked_hlc"]); self.assertIsNotNone(keys[rk]["revoked_hlc"])
        self.assertIsNone(keys[new]["revoked_hlc"])
        self.assertTrue(all(st == "signed" for _, st in signing.classify(self.db).values()))
        with self.assertRaisesRegex(signing.SignatureError, "unused recovery key"):   # one-time
            signing.recover_with_code(self.db, code, os.path.join(self.d, "again.key"))
        with mock.patch.dict(os.environ, {"VAULT_USER_KEY": self.newp}):
            self.assertEqual(status(self.db, approve_one(self.db, "after")), "active")
            self.assertTrue(ops.verify(self.db)["ok"])

    def test_wrong_code_refused(self):
        signing.new_recovery_code(self.db)
        with self.assertRaisesRegex(signing.SignatureError, "recovery"):
            signing.recover_with_code(self.db, "AAAA-" * 7 + "AAAA", self.newp)
        self.assertFalse(os.path.exists(self.newp))
        with self.assertRaisesRegex(signing.SignatureError, "malformed"):
            signing.recover_with_code(self.db, "not-a-code", self.newp)

    def test_recovery_key_cannot_sign_approvals(self):
        code, rk = signing.new_recovery_code(self.db)
        rec = signing._priv_kid(signing._recovery_priv(code), "recovery")
        p = agent(self.db, "note.added", "x", {"text": "b"})
        with self.assertRaisesRegex(signing.SignatureError, "may only sign"):
            signing._append_signed(self.db, rec, "event.approved", f"event:{p}", {"reason": "x"}, H)
        self.db.rollback()


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class SecondAnchor(unittest.TestCase):
    def setUp(self):
        fresh(self)
        self.a2 = os.path.join(self.d, "second", "anchor2.json")
        self.env = mock.patch.dict(os.environ, {"VAULT_ANCHOR_PATH2": self.a2}); self.env.start()
        self.addCleanup(self.env.stop)
        approve_one(self.db, "a")

    def test_written_and_checked(self):
        self.assertTrue(os.path.exists(self.a2))
        self.assertEqual(signing.check_anchor(self.db), ([], []))
        body = rj(self.a2); body["events"]["hash"] = "0" * 64
        with open(self.a2, "w") as f:
            json.dump(body, f)
        errs, _ = signing.check_anchor(self.db)
        self.assertTrue(errs)

    def test_missing_second_is_warning(self):
        os.remove(self.a2)
        errs, warns = signing.check_anchor(self.db)
        self.assertEqual(errs, []); self.assertTrue(any("VAULT_ANCHOR_PATH2" in w for w in warns))


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class Cli(unittest.TestCase):
    def test_cli_rotate_recovery_recover(self):
        fresh(self); self.db.close()
        env = {**os.environ, "VAULT_USER_KEY": os.path.join(self.d, "u.key")}
        run = lambda *a, inp=None: subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), *a],
                                                  capture_output=True, text=True, env=env, input=inp)
        self.assertEqual(run("keys", "init-user").returncode, 0)
        r = run("keys", "rotate"); self.assertEqual(r.returncode, 1); self.assertIn("--new-key", r.stderr)
        r = run("keys", "rotate", "--new-key", os.path.join(self.d, "u2.key")); self.assertEqual(r.returncode, 0, r.stderr)
        env["VAULT_USER_KEY"] = os.path.join(self.d, "u2.key")
        r = run("keys", "recovery-code"); self.assertEqual(r.returncode, 0, r.stderr)
        code = r.stdout.strip().splitlines()[-1].strip()
        r = run("keys", "recover", "--new-key", os.path.join(self.d, "u3.key"), inp=code + "\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        env["VAULT_USER_KEY"] = os.path.join(self.d, "u3.key")
        r = run("keys", "show"); self.assertEqual(r.returncode, 0, r.stderr)
        shown = json.loads(r.stdout); self.assertEqual(shown["problems"], [])
        self.assertEqual(sum(1 for k in shown["keys"].values() if k["revoked_hlc"] is None), 1)
        r = run("verify"); self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
