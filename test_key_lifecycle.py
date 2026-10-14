"""Key rotation, revocation, offline recovery code, second anchor (docs/adr/0012-key-lifecycle.md)."""
import json, os, subprocess, sys, unittest
from unittest import mock
import testutil
from testutil import fresh, agent, status, HAVE_CRYPTO
import vault, signing, ops

HERE = os.path.dirname(os.path.abspath(__file__))
H = "user:owner"


def init_code(db):
    """The recovery code created atomically with the first user key (harness: testutil.recovery_code)."""
    rk = next(k for k, v in signing.registered_keys(db)[0].items() if v["role"] == "recovery" and v["revoked_seq"] is None)
    return testutil.recovery_code(db), rk


def code_after(out, marker):
    lines = out.splitlines()
    return lines[next(i for i, l in enumerate(lines) if marker in l) + 1].strip()


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

    def test_user_key_cannot_revoke_recovery_key(self):
        # Security B3: the user key may revoke only device keys it certified
        _, rk = init_code(self.db)
        with self.assertRaisesRegex(signing.SignatureError, "only revoke device keys"):
            signing.revoke_key(self.db, rk, "x")
        signing._revoke(self.db, signing._current_user_key(self.db), rk, "forced", H)   # bypass the library check
        keys, probs = signing.registered_keys(self.db)
        self.assertIsNone(keys[rk]["revoked_seq"]); self.assertTrue(probs)          # registry rejects it

    def test_revoke_device_key(self):
        import cryptography.hazmat.primitives.asymmetric.ed25519 as ed
        me = signing._current_user_key(self.db)
        dk = signing._register(self.db, me, ed.Ed25519PrivateKey.generate(), "device", H)
        signing.revoke_key(self.db, dk, "lost laptop")
        keys, probs = signing.registered_keys(self.db)
        self.assertEqual(probs, []); self.assertIsNotNone(keys[dk]["revoked_seq"])


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class Recovery(unittest.TestCase):
    def setUp(self):
        fresh(self); self.p1 = approve_one(self.db, "a")
        self.newp = os.path.join(self.d, "recovered.key")

    def test_code_stored_only_as_public_key(self):
        code, rk = init_code(self.db)
        self.assertTrue(rk.startswith("recovery/ed25519/"))
        self.db.commit()
        blob = testutil.all_bytes(self.dbp)
        self.assertNotIn(code.encode(), blob); self.assertNotIn(code.replace("-", "").encode(), blob)

    def test_replacing_code_needs_old_code(self):
        # Security B2: a stolen user key alone cannot replace the owner's recovery code
        c1, r1 = init_code(self.db)
        with self.assertRaisesRegex(signing.SignatureError, "needs the old code"):
            signing.new_recovery_code(self.db)
        with self.assertRaisesRegex(signing.SignatureError, "does not match"):
            signing.new_recovery_code(self.db, old_code="AAAA-" * 7 + "AAAA")
        _, r2 = signing.new_recovery_code(self.db, old_code=c1)
        keys, probs = signing.registered_keys(self.db)
        self.assertEqual(probs, [])
        self.assertIsNotNone(keys[r1]["revoked_seq"]); self.assertIsNone(keys[r2]["revoked_seq"])
        # a second recovery key registered by the user key while one is live is rejected by the registry
        import cryptography.hazmat.primitives.asymmetric.ed25519 as ed
        signing._register(self.db, signing._current_user_key(self.db), ed.Ed25519PrivateKey.generate(), "recovery", H)
        self.assertTrue(signing.registered_keys(self.db)[1])

    def test_recovery_key_cannot_only_revoke_users(self):
        # Security B3: recovery may revoke only itself; user keys are revoked only atomically by `recover`
        code, rk = init_code(self.db)
        rec = signing._priv_kid(signing._recovery_priv(code), "recovery")
        me = signing.load_user_key()[1]
        signing._revoke(self.db, rec, me, "dos", H)
        keys, probs = signing.registered_keys(self.db)
        self.assertTrue(keys[me]["active"]); self.assertTrue(probs)

    def test_recover_lost_key(self):
        code, rk = init_code(self.db)
        old = signing.load_user_key()[1]
        new, _ = signing.recover_with_code(self.db, code.lower(), self.newp)   # case/dash tolerant
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
        with self.assertRaisesRegex(signing.SignatureError, "recovery"):
            signing.recover_with_code(self.db, "AAAA-" * 7 + "AAAA", self.newp)
        self.assertFalse(os.path.exists(self.newp))
        with self.assertRaisesRegex(signing.SignatureError, "malformed"):
            signing.recover_with_code(self.db, "not-a-code", self.newp)

    def test_recovery_key_cannot_sign_approvals(self):
        code, rk = init_code(self.db)
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
        r = run("keys", "init-user"); self.assertEqual(r.returncode, 0, r.stderr)
        code = code_after(r.stdout, "RECOVERY CODE")                     # created with the first key (ADR 0012)
        r = run("keys", "show"); self.assertIsNotNone(json.loads(r.stdout)["live_recovery_key"]["seq"])
        r = run("keys", "rotate"); self.assertEqual(r.returncode, 1); self.assertIn("--new-key", r.stderr)
        r = run("keys", "rotate", "--new-key", os.path.join(self.d, "u2.key")); self.assertEqual(r.returncode, 0, r.stderr)
        env["VAULT_USER_KEY"] = os.path.join(self.d, "u2.key")
        r = run("keys", "recovery-code"); self.assertEqual(r.returncode, 1); self.assertIn("old code", r.stderr)
        r = run("keys", "recover", "--new-key", os.path.join(self.d, "u3.key"), inp=code + "\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        c2 = code_after(r.stdout, "NEW RECOVERY CODE")
        env["VAULT_USER_KEY"] = os.path.join(self.d, "u3.key")
        r = run("keys", "show"); self.assertEqual(r.returncode, 0, r.stderr)
        shown = json.loads(r.stdout); self.assertEqual(shown["problems"], [])
        self.assertEqual(sum(1 for k in shown["keys"].values() if k["revoked_hlc"] is None), 2)   # user + recovery
        r = run("verify"); self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = run("keys", "recovery-code", "--replace", inp=c2 + "\n"); self.assertEqual(r.returncode, 0, r.stderr)

    def test_recovery_code_refuses_non_tty_stdout(self):
        fresh(self); self.db.close()
        env = {k: v for k, v in os.environ.items() if k != "VAULT_TEST_HARNESS"}
        r = subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), "keys", "recovery-code"],
                           capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL)
        self.assertEqual(r.returncode, 1); self.assertNotIn("RECOVERY CODE", r.stdout)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class SecurityReview(unittest.TestCase):
    """Security review of #12: B1 single active user key, transitive revocation; (a) seq-bound revocation."""
    def setUp(self):
        fresh(self); self.p1 = approve_one(self.db, "a")
        self.me = signing._current_user_key(self.db)

    def test_stolen_key_cannot_mint_active_user_key(self):
        import cryptography.hazmat.primitives.asymmetric.ed25519 as ed
        evil = ed.Ed25519PrivateKey.generate()
        ek = signing._register(self.db, self.me, evil, "user", H)       # attacker with the user key, before rotation
        keys = signing.registered_keys(self.db)[0]
        self.assertFalse(keys[ek]["active"])                            # pending: not usable without key.rotated
        p = agent(self.db, "note.added", "x", {"text": "b"})
        with self.assertRaisesRegex(signing.SignatureError, "pending"):
            signing._append_signed(self.db, (evil, ek), "event.approved", f"event:{p}", {"reason": "x"}, H)
        self.db.rollback()
        code, rk = init_code(self.db)
        signing.rotate_user_key(self.db, os.path.join(self.d, "n.key"))  # owner rotates
        keys, probs = signing.registered_keys(self.db)
        self.assertEqual(probs, [])
        self.assertIsNotNone(keys[ek]["revoked_seq"])                   # transitively revoked with the old key
        self.assertIsNone(keys[rk]["revoked_seq"])                      # recovery key survives rotation
        self.assertEqual(sum(1 for k in keys.values() if k["role"] == "user" and k["active"]), 1)

    def test_stolen_key_rotation_keeps_owner_recovery(self):
        """Security re-review B1 (PoC test_stolen_key_rotation_kills_owner_recovery): a thief rotating with the stolen
        user key must not kill the owner's offline recovery code; the owner recovers and the thief's key dies."""
        code, rk = init_code(self.db)
        _, evil = signing.rotate_user_key(self.db, os.path.join(self.d, "evil.key"))
        self.assertIsNone(signing.registered_keys(self.db)[0][rk]["revoked_seq"])
        new, _ = signing.recover_with_code(self.db, code, os.path.join(self.d, "owner.key"))
        keys, probs = signing.registered_keys(self.db)
        self.assertEqual(probs, [])
        self.assertIsNotNone(keys[evil]["revoked_seq"]); self.assertIsNotNone(keys[rk]["revoked_seq"])
        self.assertEqual([k for k, v in keys.items() if v["role"] == "user" and v["active"]], [new])

    def test_rotation_needs_pending_key_certified_by_signer(self):
        import cryptography.hazmat.primitives.asymmetric.ed25519 as ed
        other = ed.Ed25519PrivateKey.generate()
        ok_ = signing.key_id_for(signing.pub_raw(other))
        signing._append_signed(self.db, self.me, "key.rotated", f"key:{ok_}", {"old_key_id": self.me[1], "new_key_id": ok_,
                               "new_key_sig": signing.b64(other.sign(signing.rotation_message(self.me[1], ok_)))}, H)
        keys, probs = signing.registered_keys(self.db)
        self.assertTrue(probs); self.assertTrue(keys[self.me[1]]["active"])

    def test_recover_revokes_all_user_keys_and_their_certs(self):
        import cryptography.hazmat.primitives.asymmetric.ed25519 as ed
        dk = signing._register(self.db, self.me, ed.Ed25519PrivateKey.generate(), "device", H)
        code, rk = init_code(self.db)
        new, _ = signing.recover_with_code(self.db, code, os.path.join(self.d, "r.key"))
        keys, probs = signing.registered_keys(self.db)
        self.assertEqual(probs, [])
        for k in (self.me[1], dk, rk):
            self.assertIsNotNone(keys[k]["revoked_seq"], k)
        self.assertTrue(keys[new]["active"])

    def test_backdated_signature_after_revocation_rejected(self):
        """(a): a revoked key signs an event with an HLC before the revocation and appends it later: revoked-key."""
        old = self.me
        signing.rotate_user_key(self.db, os.path.join(self.d, "n.key"))
        p = agent(self.db, "note.added", "x", {"text": "late"})
        rot_hlc = self.db.execute("SELECT hlc FROM events WHERE type='key.rotated'").fetchone()[0]
        early = f"{int(rot_hlc[:12], 16) - 1000:012x}-0000-local"
        with mock.patch.object(vault, "next_hlc", lambda db, rep: early), \
                mock.patch.object(signing, "sign_row", lambda db, row, parents: (old[1], signing.b64(
                    old[0].sign(signing.sig_message(row, parents, old[1]))))):
            ap = vault.append(self.db, "event.approved", f"event:{p}", {"reason": "x"}, H, "verified", target_id=p)[0]
        cls = signing.classify(self.db); st = cls[ap][1]
        self.assertEqual(st, "revoked-key"); self.assertIn(st, signing.BAD)
        self.assertTrue(all(v == "signed" for k, (_, v) in cls.items() if k != ap))   # genuinely earlier ones stay valid


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class RecoveryWindow(unittest.TestCase):
    """Security re-review @ c604b44 (HIGH): no window in which a stolen user key can add a recovery key."""
    def setUp(self):
        fresh(self)

    def legacy_vault_without_recovery(self):
        testutil.AUTO_REGISTER = False; self.addCleanup(setattr, testutil, "AUTO_REGISTER", True)
        priv, kid = signing.load_user_key()
        pub = signing.pub_raw(priv)
        vault.append(self.db, "key.registered", f"key:{kid}", {"key_id": kid, "alg": "ed25519", "role": "user",
                     "pubkey_b64": signing.b64(pub), "certified_by": kid}, H, "verified")
        approve_one(self.db, "x")
        return priv, kid

    def test_poc_thief_cannot_register_recovery(self):
        """PoC test_thief_registered_recovery_survives_owner_rotation, ported: on a vault with NO recovery key the
        thief (stolen user key) cannot register one, neither via the API nor by writing the event directly."""
        me = self.legacy_vault_without_recovery()
        with self.assertRaisesRegex(signing.SignatureError, "old code"):
            signing.new_recovery_code(self.db)
        import cryptography.hazmat.primitives.asymmetric.ed25519 as ed
        thief = ed.Ed25519PrivateKey.generate()
        trk = signing._register(self.db, me, thief, "recovery", H)
        keys, probs = signing.registered_keys(self.db)
        self.assertNotIn(trk, keys); self.assertTrue(any("not allowed" in x for x in probs))
        code = signing._new_code()   # even a well-formed code for that key is useless
        with self.assertRaises(signing.SignatureError):
            signing.recover_with_code(self.db, code, os.path.join(self.d, "thief.key"))
        rep = ops.doctor(self.db)
        self.assertTrue(any("NO LIVE RECOVERY KEY" in w for w in rep.get("warnings", []) + rep.get("problems", [])), rep)

    def test_init_user_registers_recovery_atomically(self):
        approve_one(self.db, "a")
        keys = signing.registered_keys(self.db)[0]
        user = [v for v in keys.values() if v["role"] == "user"][0]
        rec = [v for v in keys.values() if v["role"] == "recovery"]
        self.assertEqual(len(rec), 1); self.assertEqual(rec[0]["seq"], user["seq"] + 1)
        self.assertFalse(any("NO LIVE RECOVERY" in w for w in ops.doctor(self.db).get("warnings", [])))

    def test_init_user_failure_registers_nothing(self):
        testutil.AUTO_REGISTER = False; self.addCleanup(setattr, testutil, "AUTO_REGISTER", True)
        with mock.patch.object(signing, "_register", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                signing.register_user_key(self.db)
        self.assertIsNone(signing.epoch_seq(self.db))

    def test_replace_is_atomic(self):
        approve_one(self.db, "a")
        code, rk = init_code(self.db)
        with mock.patch.object(signing, "_register", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                signing.new_recovery_code(self.db, old_code=code)
        keys = signing.registered_keys(self.db)[0]
        self.assertIsNone(keys[rk]["revoked_seq"])                      # old code still live
        new, nk = signing.new_recovery_code(self.db, old_code=code)
        keys, probs = signing.registered_keys(self.db)
        self.assertEqual(probs, []); self.assertIsNotNone(keys[rk]["revoked_seq"]); self.assertIsNone(keys[nk]["revoked_seq"])
        self.assertEqual(keys[nk]["seq"], keys[rk]["revoked_seq"] + 1)

    def test_recover_creates_fresh_recovery(self):
        approve_one(self.db, "a")
        code, rk = init_code(self.db)
        new, code2 = signing.recover_with_code(self.db, code, os.path.join(self.d, "r.key"))
        keys, probs = signing.registered_keys(self.db)
        self.assertEqual(probs, [])
        live = [k for k, v in keys.items() if v["role"] == "recovery" and v["revoked_seq"] is None]
        self.assertEqual(len(live), 1); self.assertNotEqual(live[0], rk)
        with mock.patch.dict(os.environ, {"VAULT_USER_KEY": os.path.join(self.d, "r.key")}):
            self.assertEqual(signing.new_recovery_code(self.db, old_code=code2)[1] in signing.registered_keys(self.db)[0], True)

    def test_backdated_revocation_needs_compromised(self):
        """Data Systems N1: a user-signed key.revoked may not backdate effective_hlc unless compromised:true."""
        import cryptography.hazmat.primitives.asymmetric.ed25519 as ed
        approve_one(self.db, "a")
        me = signing._current_user_key(self.db)
        dk = signing._register(self.db, me, ed.Ed25519PrivateKey.generate(), "device", H)
        signing._append_signed(self.db, me, "key.revoked", f"key:{dk}", {"key_id": dk, "effective_hlc": "000000000000-0000-local",
                               "reason": "backdated", "compromised": False}, H)
        keys, probs = signing.registered_keys(self.db)
        self.assertIsNone(keys[dk]["revoked_seq"]); self.assertTrue(probs)

    def test_l1_legacy_first_key_as_last_event(self):
        """Security L1 (PoC poc12-578 test_legacy_first_user_is_last_event): adjacency alone is not enough; the first
        user key event must name the recovery key (signed recovery_key_id). Legacy first-key events have none."""
        testutil.AUTO_REGISTER = False; self.addCleanup(setattr, testutil, "AUTO_REGISTER", True)
        priv, kid = signing.load_user_key()
        vault.append(self.db, "key.registered", f"key:{kid}", {"key_id": kid, "alg": "ed25519", "role": "user",
                     "pubkey_b64": signing.b64(signing.pub_raw(priv)), "certified_by": kid}, H, "verified")
        import cryptography.hazmat.primitives.asymmetric.ed25519 as ed
        trk = signing._register(self.db, (priv, kid), ed.Ed25519PrivateKey.generate(), "recovery", H)
        keys, probs = signing.registered_keys(self.db)
        self.assertNotIn(trk, keys); self.assertTrue(probs)

    def test_l1_recovery_must_match_signed_id(self):
        approve_one(self.db, "a")
        code, rk = init_code(self.db)
        import cryptography.hazmat.primitives.asymmetric.ed25519 as ed
        rec = signing._priv_kid(signing._recovery_priv(code), "recovery")
        me = signing._current_user_key(self.db)
        # self-revoke naming recovery key R2, then registering a different key R3: rejected
        r2 = signing.key_id_for(signing.pub_raw(ed.Ed25519PrivateKey.generate()), "recovery")
        signing._revoke(self.db, rec, rk, "x", H, recovery_key_id=r2)
        r3 = signing._register(self.db, me, ed.Ed25519PrivateKey.generate(), "recovery", H)
        keys, probs = signing.registered_keys(self.db)
        self.assertNotIn(r3, keys); self.assertTrue(probs)

    def test_recover_rollback_removes_key_file(self):
        approve_one(self.db, "a")
        code, rk = init_code(self.db)
        newp = os.path.join(self.d, "r.key")
        real = signing._register
        calls = []
        def flaky(*a, **kw):
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeError("boom")
            return real(*a, **kw)
        with mock.patch.object(signing, "_register", flaky):
            with self.assertRaises(RuntimeError):
                signing.recover_with_code(self.db, code, newp)
        self.assertFalse(os.path.exists(newp))
        self.assertIsNone(signing.registered_keys(self.db)[0][rk]["revoked_seq"])   # nothing committed

    def test_anchor_skip_warns_after_rotation(self):
        import io
        approve_one(self.db, "a")
        err = io.StringIO()
        with mock.patch.object(signing, "write_anchor", return_value=None), mock.patch("sys.stderr", err):
            signing.rotate_user_key(self.db, os.path.join(self.d, "n.key"))
        self.assertIn("anchor NOT refreshed", err.getvalue())


if __name__ == "__main__":
    unittest.main()
