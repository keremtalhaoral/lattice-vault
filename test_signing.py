"""Signed approvals, external anchor, open-time sampled verification (SECURITY.md, docs/adr/0011)."""
import base64, hashlib, json, os, random, shutil, sqlite3, stat, subprocess, sys, tempfile, time, unittest
from unittest import mock
import testutil
from testutil import fresh, user, agent, status, HAVE_CRYPTO
import vault, signing, ops

HERE = os.path.dirname(os.path.abspath(__file__))
H = "user:owner"


def raw(path):
    r = sqlite3.connect(path); r.row_factory = sqlite3.Row; return r


def drop_triggers(r, *names):
    for n in names:
        r.execute(f"DROP TRIGGER {n}")


def restore_triggers(r, *names):
    for n in names:
        r.execute({**vault.TRIGGERS, **vault.SIG_TRIGGERS}[n])


def insert_forged(path, typ, target, key_id=None, sig=None):
    """Attacker without the private key: append a correctly hash-chained row (+ optional signature row)."""
    r = raw(path)
    prev = r.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()[0]
    eid = vault.uuid7()
    row = {"id": eid, "replica_id": "local", "replica_seq": 9999, "hlc": "ffffffffffff-0000-local", "ts": vault.now(),
           "type": typ, "schema_version": 1, "subject": f"event:{target}", "key": None, "payload": "{}", "payload_ct": None,
           "enc_key_id": None, "actor": H, "trust": "verified", "supersedes": None, "target_id": target,
           "idempotency_key": None, "import_id": None, "content_hash": "c" * 64, "text_norm": "", "prev_hash": prev}
    row["_sig"] = sig
    row["hash"] = vault.event_hash(prev, row); row.pop("_sig")
    drop_triggers(r, "events_require_sig")
    if sig:
        r.execute("INSERT INTO event_sigs VALUES(?,?,?,?)", (eid, key_id, "ed25519", sig))
    r.execute(f"INSERT INTO events({','.join(row)}) VALUES({','.join('?' * len(row))})", list(row.values()))
    r.execute("INSERT INTO event_targets VALUES(?,?)", (eid, target))
    r.execute("INSERT INTO event_parents VALUES(?,?,'target')", (eid, target))
    restore_triggers(r, "events_require_sig"); r.commit(); r.close()
    return eid


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class SignedApprovals(unittest.TestCase):
    def setUp(self):
        fresh(self)
        self.p = agent(self.db, "note.added", "x", {"text": "proposal"})

    def test_approval_is_signed_and_bound_into_hash(self):
        a = vault.review(self.db, self.p, "approve")
        s = self.db.execute("SELECT key_id, alg FROM event_sigs WHERE event_id=?", (a,)).fetchone()
        self.assertEqual(s["alg"], "ed25519"); self.assertTrue(s["key_id"].startswith("user/ed25519/"))
        self.assertEqual(signing.classify(self.db)[a][1], "signed")
        rep = ops.doctor(self.db); self.assertTrue(rep["ok"], rep["problems"])

    def test_signature_message_contract(self):
        a = vault.review(self.db, self.p, "approve")
        e = self.db.execute("SELECT * FROM events WHERE id=?", (a,)).fetchone()
        kid = self.db.execute("SELECT key_id FROM event_sigs WHERE event_id=?", (a,)).fetchone()[0]
        msg = signing.sig_message(e, [self.p], kid)
        self.assertTrue(msg.startswith(b"lattice-event-sig/v1\n"))
        body = json.loads(msg.split(b"\n", 1)[1])
        self.assertEqual(set(body), {"id", "type", "subject", "payload_hash", "actor", "parents", "hlc", "origin_device", "key_id"})
        self.assertEqual(body["payload_hash"], hashlib.sha256(b"{}").hexdigest())
        with self.assertRaises(signing.SignatureError):
            signing.canon({"x": 1.5})   # floats rejected in the signed canonical form

    def test_forged_signature_detected_on_open_and_doctor(self):
        kid = self.db.execute("SELECT json_extract(payload,'$.key_id') FROM events WHERE type='key.registered'").fetchone()
        vault.review(self.db, self.p, "approve")          # make sure signing is enabled
        q = agent(self.db, "note.added", "y", {"text": "p2"})
        self.db.close()
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        bogus = base64.b64encode(Ed25519PrivateKey.generate().sign(b"anything")).decode()
        reg = vault.connect(self.dbp).execute("SELECT key_id FROM event_sigs LIMIT 1").fetchone()[0]
        insert_forged(self.dbp, "event.approved", q, key_id=reg, sig=bogus)
        with self.assertRaisesRegex(vault.TamperError, "signature check failed .*bad-signature"):
            vault.connect(self.dbp)
        rep = ops.doctor(vault.connect(self.dbp, verify=False))
        self.assertFalse(rep["ok"]); self.assertTrue(any("signature verification" in p for p in rep["problems"]))

    def test_signed_encrypted_event_verifies_when_undecryptable(self):
        """payload_hash covers payload_ct, so a signature stays valid when the key is missing (payload_state
        'undecryptable') or shredded; integrity and decryptability are reported separately."""
        eid, _ = vault.append(self.db, "conflict.resolved", "subject:s", {"reason": "r", "note": "geheim"}, H, "verified",
                              sensitive=["note"])
        e = self.db.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
        self.assertIsNotNone(e["payload_ct"])
        self.db.close(); vault._KEYSTORE.clear()
        for f in ("keys.db", "keys.kek"):
            p = os.path.join(self.d, f)
            if os.path.exists(p):
                os.rename(p, p + ".away")
        db = vault.connect(self.dbp)
        self.assertEqual(vault.payload_state(db, db.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone())[1], "undecryptable")
        self.assertEqual(signing.classify(db)[eid][1], "signed")
        db.close()

    def test_forged_key_id_detected(self):
        vault.review(self.db, self.p, "approve")
        q = agent(self.db, "note.added", "y", {"text": "p2"}); self.db.close()
        insert_forged(self.dbp, "event.approved", q, key_id="user/ed25519/deadbeefdeadbeef", sig=base64.b64encode(b"x" * 64).decode())
        with self.assertRaisesRegex(vault.TamperError, "unknown-key"):
            vault.connect(self.dbp)

    def test_unsigned_new_approval_rejected(self):
        vault.review(self.db, self.p, "approve")
        q = agent(self.db, "note.added", "y", {"text": "p2"})
        # 1) no usable key -> append refuses
        with mock.patch.dict(os.environ, {"VAULT_USER_KEY": os.path.join(self.d, "missing.key")}):
            with self.assertRaisesRegex(signing.SignatureError, "no user signing key"):
                vault.review(self.db, q, "approve")
        # 2) raw INSERT without a signature row -> trigger refuses
        r = raw(self.dbp)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "unsigned human-only event refused"):
            r.execute("INSERT INTO events(id,replica_id,replica_seq,hlc,ts,type,subject,payload,actor,trust,content_hash,prev_hash,hash) "
                      "VALUES('f','local',99,'fff','t','event.approved','e','{}','user:owner','verified','c','p','h')")
        r.close(); self.db.close()
        # 3) trigger bypassed, correct hash chain, no signature -> open refuses
        insert_forged(self.dbp, "event.approved", q)
        with self.assertRaisesRegex(vault.TamperError, "unsigned human-only event at seq"):
            vault.connect(self.dbp)

    def test_deleted_signature_breaks_hash_chain(self):
        a = vault.review(self.db, self.p, "approve"); self.db.close()
        r = raw(self.dbp); drop_triggers(r, "event_sigs_no_delete")
        r.execute("DELETE FROM event_sigs WHERE event_id=?", (a,)); restore_triggers(r, "event_sigs_no_delete"); r.commit(); r.close()
        with self.assertRaisesRegex(vault.TamperError, "event chain broken"):
            vault.connect(self.dbp)

    def test_hash_v2_equals_v1_for_unsigned_rows(self):
        e = self.db.execute("SELECT * FROM events WHERE id=?", (self.p,)).fetchone()
        ct = e["payload_ct"]
        body = vault.canon([e[f] for f in vault.EVENT_HASH_FIELDS] + [hashlib.sha256(ct).hexdigest() if ct else ""])
        v1 = hashlib.sha256(f"{e['prev_hash']}\n{body}".encode()).hexdigest()   # format before this change
        self.assertEqual(v1, e["hash"]); self.assertEqual(vault.event_hash(e["prev_hash"], dict(e)), v1)
        self.assertNotEqual(vault.event_hash(e["prev_hash"], {**dict(e), "_sig": "AAAA"}), v1)

    def test_agent_cannot_write_key_or_attestation_events(self):
        for t in ("key.registered", "key.revoked", "attestation.recorded"):
            with self.subTest(t=t), self.assertRaises(sqlite3.DatabaseError):
                self.db.execute("INSERT INTO events(id,replica_id,replica_seq,hlc,ts,type,subject,payload,actor,trust,content_hash,prev_hash,hash) "
                                f"VALUES('{t}','local',98,'f','t','{t}','e','{{}}','agent:x','unverified','c','p','h{t}')")

    def test_revoked_key_cannot_sign_after_effective_hlc(self):
        a = vault.review(self.db, self.p, "approve")
        kid = self.db.execute("SELECT key_id FROM event_sigs WHERE event_id=?", (a,)).fetchone()[0]
        hlc = vault.next_hlc(self.db, "local")
        vault.append(self.db, "key.revoked", f"key:{kid}", {"key_id": kid, "effective_hlc": hlc, "reason": "test",
                                                             "compromised": False}, H, "verified")
        self.assertEqual(signing.classify(self.db)[a][1], "signed")   # signatures made before revocation stay valid
        q = agent(self.db, "note.added", "y", {"text": "p2"})
        with self.assertRaisesRegex(signing.SignatureError, "revoked"):
            vault.review(self.db, q, "approve")


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class LegacyUpcast(unittest.TestCase):
    def setUp(self):
        fresh(self); testutil.AUTO_REGISTER = False; self.addCleanup(setattr, testutil, "AUTO_REGISTER", True)
        p = agent(self.db, "note.added", "x", {"text": "old proposal"})
        with mock.patch.object(vault, "SIGNED_TYPES", ()):          # simulate the pre-signing code
            self.old = vault.review(self.db, p, "approve")
        self.assertIsNone(self.db.execute("SELECT 1 FROM event_sigs").fetchone())
        signing.register_user_key(self.db)                          # upgrade: `vault keys init-user`

    def test_legacy_flagged_not_rejected(self):
        self.db.close(); db = vault.connect(self.dbp)                # accepted on open
        self.assertEqual(signing.classify(db)[self.old][1], "legacy-unsigned")
        rep = ops.doctor(db)
        self.assertTrue(rep["ok"], rep["problems"]); self.assertEqual(rep["checks"]["signatures"].get("legacy-unsigned"), 1)
        self.assertTrue(any("legacy-unsigned" in w for w in rep["warnings"]))

    def test_sign_legacy_attests_without_rewriting(self):
        before = self.db.execute("SELECT hash FROM events WHERE id=?", (self.old,)).fetchone()[0]
        self.assertEqual(signing.sign_legacy(self.db, lambda items: False), [])      # declined -> nothing
        ids = signing.sign_legacy(self.db, lambda items: len(items) == 1)
        self.assertEqual(len(ids), 1)
        self.assertEqual(self.db.execute("SELECT hash FROM events WHERE id=?", (self.old,)).fetchone()[0], before)
        self.assertEqual(signing.classify(self.db)[self.old][1], "legacy-attested")
        rep = ops.doctor(self.db); self.assertTrue(rep["ok"]); self.assertFalse(any("legacy" in w for w in rep["warnings"]))

    def test_sign_legacy_cli_requires_tty_even_in_harness(self):
        r = subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), "sign-legacy"], capture_output=True, text=True,
                           env=os.environ, stdin=subprocess.DEVNULL)
        self.assertEqual(r.returncode, 1); self.assertIn("interactive terminal", r.stderr)

    def test_dropped_sig_tables_after_registration_detected(self):
        self.db.close(); r = raw(self.dbp)
        for n in vault.SIG_TRIGGERS:
            r.execute(f"DROP TRIGGER {n}")
        r.execute("DROP TABLE event_sigs"); r.commit(); r.close()
        with self.assertRaisesRegex(vault.TamperError, "signing tables are missing"):
            vault.connect(self.dbp)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class Anchor(unittest.TestCase):
    def setUp(self):
        fresh(self)
        self.p = agent(self.db, "note.added", "x", {"text": "a"})
        vault.review(self.db, self.p, "approve")
        self.anchor = signing.anchor_path(self.dbp)

    def test_anchor_written_0600_signed(self):
        self.assertTrue(os.path.exists(self.anchor))
        self.assertEqual(stat.S_IMODE(os.stat(self.anchor).st_mode), 0o600)
        a = json.load(open(self.anchor))
        self.assertEqual(a["events"]["seq"], self.db.execute("SELECT MAX(seq) FROM events").fetchone()[0])
        self.assertEqual(a["audit"]["id"], self.db.execute("SELECT MAX(id) FROM audit").fetchone()[0])
        self.assertTrue(a["key_id"].startswith("user/ed25519/"))

    def test_env_anchor_path(self):
        p = os.path.join(self.d, "custom.anchor")
        with mock.patch.dict(os.environ, {"VAULT_ANCHOR_PATH": p}):
            vault.audit(self.db, H, "x", "accepted", "r")
            self.assertTrue(os.path.exists(p))

    def test_rollback_detected(self):
        self.db.close()
        snap = os.path.join(self.d, "old.db"); shutil.copy(self.dbp, snap)
        db = vault.connect(self.dbp); agent(db, "note.added", "y", {"text": "newer"}); vault.audit(db, H, "a", "accepted", "r"); db.close()
        shutil.copy(snap, self.dbp)                                    # roll the DB back, anchor stays
        with self.assertRaisesRegex(vault.TamperError, "behind the external anchor"):
            vault.connect(self.dbp)

    def test_tail_truncation_detected(self):
        agent(self.db, "note.added", "y", {"text": "t"}); vault.audit(self.db, H, "a", "accepted", "r"); self.db.close()
        r = raw(self.dbp); r.execute("DROP TRIGGER audit_no_delete")
        r.execute("DELETE FROM audit WHERE id=(SELECT MAX(id) FROM audit)"); r.execute(vault.TRIGGERS["audit_no_delete"]); r.commit(); r.close()
        with self.assertRaisesRegex(vault.TamperError, "audit is behind the external anchor"):
            vault.connect(self.dbp)

    def test_mismatched_hash_detected(self):
        self.db.close(); os.remove(self.dbp)
        db = vault.connect(self.dbp)                                    # a different history at the same path
        for i in range(5):
            agent(db, "note.added", "z", {"text": f"other {i}"})
        db.close()
        with self.assertRaisesRegex(vault.TamperError, "does not match the external anchor"):
            vault.connect(self.dbp)

    def test_forged_anchor_rejected(self):
        a = json.load(open(self.anchor)); a["events"]["seq"] = 1
        json.dump(a, open(self.anchor, "w"))
        self.db.close()
        with self.assertRaisesRegex(vault.TamperError, "anchor signature invalid"):
            vault.connect(self.dbp)

    def test_missing_anchor_is_warning(self):
        self.db.close(); os.remove(self.anchor)
        db = vault.connect(self.dbp)
        self.assertTrue(any("no external anchor" in w for w in vault.OPEN_WARNINGS[os.path.abspath(self.dbp)]))
        db.close()

    def test_verify_reports_signatures_and_anchor(self):
        rep = ops.verify(self.db)
        self.assertTrue(rep["ok"], rep["problems"]); self.assertEqual(rep["anchor"], "ok")
        self.assertGreaterEqual(rep["signatures"].get("signed", 0), 2)        # key.registered + approval
        os.remove(self.anchor)
        rep = ops.verify(self.db)
        self.assertTrue(any("no external anchor" in w for w in rep["warnings"]))

    def test_restore_resets_anchor(self):
        import backup
        bk, to = os.path.join(self.d, "bk"), os.path.join(self.d, "restored.db")
        backup.backup(self.db, bk)
        vault.audit(self.db, H, "later", "accepted", "after backup")
        backup.restore(bk, to)
        db = vault.connect(to)                                           # fresh anchor for the restored path; no rollback error
        self.assertTrue(os.path.exists(signing.anchor_path(to))); self.assertEqual(ops.verify(db)["anchor"], "ok"); db.close()

    def test_known_limit_rollback_of_both_files_undetected(self):
        """KNOWN LIMIT (documented): rolling back the DB AND the anchor together is not detected."""
        self.db.close()
        snap, asnap = os.path.join(self.d, "old.db"), os.path.join(self.d, "old.anchor")
        shutil.copy(self.dbp, snap); shutil.copy(self.anchor, asnap)
        db = vault.connect(self.dbp); agent(db, "note.added", "y", {"text": "newer"}); db.close()
        shutil.copy(snap, self.dbp); shutil.copy(asnap, self.anchor)
        vault.connect(self.dbp).close()                                 # opens fine: undetected

    def test_agent_process_never_loads_user_key(self):
        with mock.patch.object(signing, "USER_KEY_DISABLED", True):
            with self.assertRaises(signing.SignatureError):
                signing.load_user_key()
            self.assertIsNone(signing.write_anchor(self.db))


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class OpenTimeSampling(unittest.TestCase):
    N = 300

    def setUp(self):
        fresh(self)
        for i in range(self.N):
            vault.append(self.db, "learning.captured", "x", {"text": f"t{i}"}, H, "verified", _rebuild=False)
        self.db.close(); vault.connect(self.dbp).close()                # checkpoint at head
        self.addCleanup(os.environ.pop, "VAULT_VERIFY_SAMPLE_K", None)

    def tamper(self, seq):
        r = raw(self.dbp); r.execute("DROP TRIGGER events_no_update")
        r.execute("UPDATE events SET payload=json_set(payload,'$.text','EVIL') WHERE seq=?", (seq,))
        r.execute(vault.TRIGGERS["events_no_update"]); r.commit(); r.close()

    def test_mid_chain_tamper_caught_by_sampled_segment(self):
        self.tamper(100)
        os.environ["VAULT_VERIFY_SAMPLE_K"] = "1"
        with mock.patch.object(vault, "_RNG", random.Random(0)), \
             mock.patch.object(vault._RNG.__class__, "sample", lambda self, pop, k: [1]):   # segment 65..128
            with self.assertRaisesRegex(vault.TamperError, "event chain broken at seq 100 \\(sampled segment\\)"):
                vault.connect(self.dbp)

    def test_tail_tamper_caught_by_checkpoint_check(self):
        db = vault.connect(self.dbp); vault.append(db, "learning.captured", "x", {"text": "new"}, H, "verified"); db.close()
        self.tamper(self.N + 1)
        os.environ["VAULT_VERIFY_SAMPLE_K"] = "0"
        with self.assertRaisesRegex(vault.TamperError, f"event chain broken at seq {self.N + 1}"):
            vault.connect(self.dbp)

    def test_known_limit_unsampled_tamper_not_caught_on_open(self):
        """KNOWN LIMIT (documented): a row below the checkpoint outside the K sampled segments is NOT caught at open;
        only `vault doctor` (full verify) finds it."""
        self.tamper(100)
        os.environ["VAULT_VERIFY_SAMPLE_K"] = "1"
        with mock.patch.object(vault, "_RNG", random.Random(0)), \
             mock.patch.object(vault._RNG.__class__, "sample", lambda self, pop, k: [3]):   # segment 193..256
            db = vault.connect(self.dbp)                                # opens: not detected
        rep = ops.doctor(db)
        self.assertFalse(rep["ok"]); self.assertTrue(any("event chain broken at seq 100" in p for p in rep["problems"]))

    def test_last_full_verify_nudge(self):
        db = vault.connect(self.dbp); vault.set_last_full_verify(db, time.time() - 40 * 86400); db.close()
        db = vault.connect(self.dbp)
        self.assertTrue(any("run `vault doctor`" in w for w in vault.OPEN_WARNINGS[os.path.abspath(self.dbp)]))
        self.assertTrue(ops.doctor(db)["ok"]); db.close()
        vault.connect(self.dbp).close()
        self.assertFalse(any("vault doctor" in w for w in vault.OPEN_WARNINGS[os.path.abspath(self.dbp)]))


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class KeyFileAndTTY(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def test_key_file_mode_symlink_and_passphrase(self):
        kp = os.path.join(self.d, "k.pem")
        signing.generate_user_key(kp)
        self.assertEqual(stat.S_IMODE(os.stat(kp).st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            signing.generate_user_key(kp)                               # never overwrites
        os.chmod(kp, 0o640); signing._CACHE.clear()
        with self.assertRaisesRegex(signing.SignatureError, "0600"):
            signing.load_user_key(kp)
        os.chmod(kp, 0o600); ln = os.path.join(self.d, "link.pem"); os.symlink(kp, ln)
        with self.assertRaisesRegex(signing.SignatureError, "regular file"):
            signing.load_user_key(ln)
        pp = os.path.join(self.d, "pp.pem")
        with mock.patch.dict(os.environ, {"VAULT_USER_KEY_PASSPHRASE": "correct horse"}):
            signing.generate_user_key(pp); signing._CACHE.clear()
            self.assertTrue(signing.load_user_key(pp)[1].startswith("user/ed25519/"))
        signing._CACHE.clear()
        with self.assertRaises(signing.SignatureError):
            signing.load_user_key(pp)                                   # no passphrase -> refused
        self.assertIn("BEGIN ENCRYPTED PRIVATE KEY", open(pp).read())

    def test_keychain_backend_is_a_documented_stub(self):
        with mock.patch.dict(os.environ, {"VAULT_USER_KEY_BACKEND": "keychain"}):
            with self.assertRaisesRegex(signing.SignatureError, "planned"):
                signing.load_user_key()

    def test_nontty_bypass_only_in_harness(self):
        self.assertTrue(vault._nontty_allowed())
        with mock.patch.dict(os.environ, {"VAULT_TEST_HARNESS": "0"}):
            self.assertFalse(vault._nontty_allowed())
        with mock.patch.dict(os.environ, {"VAULT_USER_KEY": os.path.expanduser("~/.config/lattice-vault/user_ed25519.key")}):
            self.assertFalse(vault._nontty_allowed())
        env = {k: v for k, v in os.environ.items() if k != "VAULT_TEST_HARNESS"}
        r = subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), "keys", "init-user"], capture_output=True,
                           text=True, env=env, stdin=subprocess.DEVNULL)
        self.assertEqual(r.returncode, 1); self.assertIn("interactive terminal", r.stderr)

    def test_cli_keys_init_user(self):
        env = {**os.environ, "VAULT_DB": os.path.join(self.d, "v.db"), "VAULT_USER_KEY": os.path.join(self.d, "u.key")}
        run = lambda *a: subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), *a], capture_output=True, text=True, env=env)
        r = run("keys", "init-user")                                   # before `vault init`: refused, nothing created
        self.assertEqual(r.returncode, 1); self.assertIn("vault init", r.stderr)
        self.assertFalse(os.path.exists(env["VAULT_USER_KEY"]))
        self.assertEqual(run("init").returncode, 0)
        r = run("search", "x"); self.assertEqual(r.returncode, 0, r.stderr)   # read-only: no key file, no anchor
        r = run("keys", "show"); self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(env["VAULT_USER_KEY"]))
        self.assertFalse(os.path.exists(os.path.join(os.environ["VAULT_CONFIG_DIR"], "anchors",
                         hashlib.sha256(os.path.abspath(env["VAULT_DB"]).encode()).hexdigest()[:16] + ".anchor.json")))
        r = run("keys", "init-user"); self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("fingerprint", r.stdout); self.assertIn("registered in this vault", r.stdout)
        r = run("keys", "init-user"); self.assertIn("already registered", r.stdout)
        r = run("keys", "show"); self.assertEqual(json.loads(r.stdout)["problems"], [])


if __name__ == "__main__":
    unittest.main()
