"""Sync key transport (ADR 0013): device KA certificates, signed vaultkeys bundles, shred propagation."""
import json, os, shutil, subprocess, sys, tempfile, time, unittest
os.environ.setdefault("VAULT_ALLOW_NONTTY", "1")
import testutil  # noqa: F401  (test harness: user key under a temp dir)
import vault, sync, signing
from testutil import HAVE_CRYPTO
if HAVE_CRYPTO:
    import key_transport as kt, crypto_keys, ops

HERE = os.path.dirname(os.path.abspath(__file__))
BOT = "agent:bot"


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class KeyTransportTest(unittest.TestCase):
    def setUp(self):
        for k in ("VAULT_KEYS_DB", "VAULT_KEK_FILE", "VAULT_PASSPHRASE", "VAULT_AGENTS"):
            os.environ.pop(k, None)
        vault._KEYSTORE.clear()
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.addCleanup(vault._KEYSTORE.clear)
        self.A, self.B, self.C = self.mk("a"), self.mk("b"), self.mk("c")
        self.da, self.db_, self.dc = (sync.device_id(x) for x in (self.A, self.B, self.C))
        for x in (self.A, self.B, self.C):
            signing.register_user_key(x)          # same owner: the same user key is registered on every device
        sync.pair(self.A, self.db_, "B"); sync.pair(self.B, self.da, "A")
        self.n = 0

    def mk(self, n):
        os.makedirs(os.path.join(self.d, n))
        db = vault.connect(os.path.join(self.d, n, "v.db")); self.addCleanup(db.close); return db

    def path(self, name):
        self.n += 1; return os.path.join(self.d, f"{self.n}-{name}")

    def secret(self, db=None, subject="person:ayse", pin="4711-gizli"):
        return vault.append(db or self.A, "learning.captured", subject, {"text": "not", "pin": pin}, BOT, "unverified",
                            sensitive=["pin"])[0]

    def sync_events(self, src, dst):
        p = self.path("p.vaultsync"); sync.export(src, p); return sync.import_package(dst, p)

    def peer(self, a, b):
        """b learns a's certified KA key."""
        return kt.add_peer(b, kt.make_cert(a))

    def ready(self):
        self.peer(self.B, self.A); self.peer(self.A, self.B)

    def bundle(self, src=None, to=None, **kw):
        p = self.path("k.vaultkeys"); kt.export_keys(src or self.A, to or self.db_, p, **kw); return p

    def payload(self, db, eid):
        e = db.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
        return vault.payload_state(db, e)

    def resign(self, p, mutate):
        b = json.load(open(p)); mutate(b)
        priv, kid = signing._current_user_key(self.A)
        b["signature"] = {"key_id": kid, "alg": "ed25519", "sig": kt._b64(priv.sign(kt._bundle_msg(b)))}
        open(p, "w").write(vault.canon(b)); return p

    # -------------------------------------------------------------- end to end
    def test_e2e_paired_device_decrypts(self):
        eid = self.secret()
        self.sync_events(self.A, self.B)
        self.assertEqual(self.payload(self.B, eid), (None, "undecryptable"))
        self.ready()
        p = self.bundle()
        raw = open(p).read()
        self.assertNotIn("4711-gizli", raw)
        kek = open(os.path.join(self.d, "a", "keys.kek"), "rb").read()
        self.assertNotIn(kt._b64(kek), raw)
        dek = vault.keystore(self.A).dek_by_id(json.loads(raw)["entries"][0]["key_id"])
        self.assertNotIn(kt._b64(dek), raw); self.assertNotIn(dek.hex(), raw)
        r = kt.import_keys(self.B, p)
        self.assertEqual((len(r["imported"]), r["quarantined"]), (1, {}))
        self.assertEqual(self.payload(self.B, eid)[0]["pin"], "4711-gizli")
        self.assertEqual(self.B.execute("SELECT status FROM proj_status WHERE event_id=?", (eid,)).fetchone()[0], "proposed")   # readable now (was undecryptable)
        # re-wrapped under B's own KEK: B's KEK opens it, A's does not
        ksb = vault.keystore(self.B); kid = r["imported"][0]
        blob = ksb.db.execute("SELECT wrapped_dek FROM subject_keys WHERE key_id=?", (kid,)).fetchone()[0]
        self.assertEqual(crypto_keys.unwrap_dek(ksb.kek, kid, blob), dek)
        with self.assertRaises(Exception):
            crypto_keys.unwrap_dek(kek, kid, blob)
        self.assertEqual(kt.import_keys(self.B, p)["duplicate"], [kid])   # idempotent
        for db in (self.A, self.B):
            self.assertEqual(vault.verify_chains(db), []); self.assertEqual(vault.check_triggers(db), [])

    def test_unpaired_device_gets_nothing(self):
        self.secret(); self.ready()
        with self.assertRaisesRegex(kt.KeyTransportError, "not paired"):
            kt.export_keys(self.A, self.dc, self.path("x"))
        with self.assertRaisesRegex(kt.KeyTransportError, "not paired"):
            kt.add_peer(self.A, kt.make_cert(self.C))
        # a bundle for B is useless to C (other recipient / KA key) and quarantined there
        p = self.bundle()
        sync.pair(self.C, self.da, "A")
        with self.assertRaisesRegex(kt.KeyTransportError, "(no key-agreement key|another device)"):
            kt.import_keys(self.C, p)
        kt.init_device_key(self.C)
        with self.assertRaisesRegex(kt.KeyTransportError, "another device"):
            kt.import_keys(self.C, p)
        self.assertTrue(kt.quarantined(self.C)[0]["reason"].startswith("bundle refused"))

    def test_revoked_device_gets_nothing_and_cannot_send(self):
        self.secret(); self.ready()
        p = self.bundle(); self.sync_events(self.A, self.B)
        kt.revoke_peer(self.A, self.db_, "lost phone")
        with self.assertRaisesRegex(kt.KeyTransportError, "revoked"):
            kt.export_keys(self.A, self.db_, self.path("x"))
        with self.assertRaises(Exception):
            self.A.execute("DELETE FROM sync_ka_revoked")
        # B revokes A: an older bundle from A is refused
        kt.revoke_peer(self.B, self.da, "test")
        with self.assertRaisesRegex(kt.KeyTransportError, "revoked"):
            kt.import_keys(self.B, p)

    def test_tampered_wrap_quarantined(self):
        eid = self.secret(); self.sync_events(self.A, self.B); self.ready()
        p = self.bundle(); b = json.load(open(p))
        ct = bytearray(kt._unb64(b["entries"][0]["ct_b64"])); ct[-1] ^= 1
        b["entries"][0]["ct_b64"] = kt._b64(bytes(ct)); open(p, "w").write(vault.canon(b))
        with self.assertRaisesRegex(kt.KeyTransportError, "bad bundle signature"):   # unsigned change: whole bundle refused
            kt.import_keys(self.B, p)
        self.resign(p, lambda b: None)                  # validly signed but the wrap does not authenticate
        r = kt.import_keys(self.B, p)
        self.assertEqual(r["imported"], []); self.assertIn("does not authenticate", list(r["quarantined"].values())[0])
        self.assertEqual(self.payload(self.B, eid), (None, "undecryptable"))
        # AAD binding: moving a wrap to another subject / event set fails
        p2 = self.bundle()
        self.resign(p2, lambda b: b["entries"][0].__setitem__("subject", "person:other"))
        self.assertTrue(kt.import_keys(self.B, p2)["quarantined"])
        q = [r["reason"] for r in kt.quarantined(self.B)]
        self.assertEqual(len(q), 3)
        self.assertNotIn("4711", json.dumps(kt.quarantined(self.B)))

    def test_bundle_signed_by_unknown_key_refused(self):
        self.secret(); self.sync_events(self.A, self.B); self.ready()
        p = self.bundle(); b = json.load(open(p))
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        k = Ed25519PrivateKey.generate()
        b["signature"] = {"key_id": "user/ed25519/0000000000000000", "alg": "ed25519", "sig": kt._b64(k.sign(kt._bundle_msg(b)))}
        open(p, "w").write(vault.canon(b))
        with self.assertRaisesRegex(kt.KeyTransportError, "bad bundle signature"):
            kt.import_keys(self.B, p)
        open(p, "w").write("not json")
        with self.assertRaisesRegex(kt.KeyTransportError, "malformed"):
            kt.import_keys(self.B, p)

    def test_forged_cert_refused(self):
        c = kt.make_cert(self.B); c["cert"]["ka_pub_b64"] = kt._b64(os.urandom(32))
        with self.assertRaisesRegex(kt.KeyTransportError, "not signed"):
            kt.add_peer(self.A, c)
        c = kt.make_cert(self.B); c["cert"]["extra"] = 1
        with self.assertRaisesRegex(kt.KeyTransportError, "unsupported"):
            kt.add_peer(self.A, c)

    def test_key_for_unknown_events_quarantined(self):
        self.secret(); self.ready()               # events not synced to B yet
        r = kt.import_keys(self.B, self.bundle())
        self.assertIn("sync the events first", list(r["quarantined"].values())[0])

    def test_shredded_key_not_transported_and_shred_propagates(self):
        e1 = self.secret(subject="person:ayse"); e2 = self.secret(subject="person:can", pin="9999-gizli")
        self.sync_events(self.A, self.B); self.ready()
        r = kt.import_keys(self.B, self.bundle())
        self.assertEqual(len(r["imported"]), 2)
        ops.shred_confirm(self.A, "person:ayse", 0); time.sleep(0.01)
        kid = ops.shred_finalize(self.A, "person:ayse")
        p = self.path("k"); s = kt.export_keys(self.A, self.db_, p)
        self.assertEqual(s["keys"], 1); self.assertEqual(s["skipped"][0]["key_id"], kid)
        self.assertNotIn(kid, open(p).read().split('"entries"')[1])
        r = self.sync_events(self.A, self.B)          # signed subject.shredded from a paired device is applied
        self.assertEqual(r["destroyed_keys"], [kid])
        self.assertEqual(self.payload(self.B, e1), (None, "redacted"))
        self.assertEqual(self.payload(self.B, e2)[0]["pin"], "9999-gizli")
        ksb = vault.keystore(self.B)
        self.assertIsNone(ksb.db.execute("SELECT wrapped_dek FROM subject_keys WHERE key_id=?", (kid,)).fetchone()[0])

    def test_shredded_key_never_reimported(self):
        self.secret(); self.sync_events(self.A, self.B); self.ready()
        old = self.bundle()                        # made before the shred
        ops.shred_confirm(self.A, "person:ayse", 0); time.sleep(0.01); ops.shred_finalize(self.A, "person:ayse")
        self.sync_events(self.A, self.B)
        r = kt.import_keys(self.B, old)
        self.assertEqual(r["imported"], []); self.assertIn("shredded", list(r["quarantined"].values())[0])

    def test_rotation_invalidates_certificates(self):
        self.secret(); self.ready()
        signing.rotate_user_key(self.A, os.path.join(self.d, "new.key"))
        with self.assertRaisesRegex(Exception, "(not the active user key|no valid key-agreement certificate)"):
            kt.export_keys(self.A, self.db_, self.path("x"))

    def test_ka_private_key_wrapped_not_plain(self):
        pub = kt.init_device_key(self.A)
        self.assertEqual(kt.init_device_key(self.A), pub)
        priv, p2 = kt._device_priv(self.A); self.assertEqual(p2, pub)
        from cryptography.hazmat.primitives import serialization as s
        raw = priv.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
        self.assertNotIn(raw, open(os.path.join(self.d, "a", "keys.db"), "rb").read())
        self.assertNotIn(raw, open(os.path.join(self.d, "a", "v.db"), "rb").read())

    def test_receiver_without_keystore_can_import(self):
        eid = self.secret(); self.sync_events(self.A, self.B)
        self.assertFalse(os.path.exists(os.path.join(self.d, "b", "keys.db")))
        self.ready()
        kt.import_keys(self.B, self.bundle())
        self.assertEqual(self.payload(self.B, eid)[0]["pin"], "4711-gizli")

    def test_cli_round_trip(self):
        eid = self.secret(); self.sync_events(self.A, self.B)
        env = dict(os.environ)
        def run(dbdir, *a):
            e = dict(env, VAULT_DB=os.path.join(self.d, dbdir, "v.db"))
            return subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), "sync-keys", *a],
                                  capture_output=True, text=True, env=e, cwd=HERE)
        ca, cb = self.path("a.cert"), self.path("b.cert")
        self.assertEqual(run("a", "cert", "--out", ca).returncode, 0)
        r = run("b", "cert", "--out", cb); self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(run("a", "add-peer", cb).returncode, 0)
        self.assertEqual(run("b", "add-peer", ca).returncode, 0)
        out = self.path("k")
        r = run("a", "export", "--to", self.db_, "--out", out); self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("ct_b64", r.stdout)
        r = run("b", "import", out); self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(json.loads(r.stdout)["imported"]), 1)
        vault._KEYSTORE.clear()
        self.assertEqual(self.payload(self.B, eid)[0]["pin"], "4711-gizli")
        r = run("c", "export", "--to", self.da, "--out", self.path("z"))
        self.assertEqual(r.returncode, 1); self.assertIn("not paired", r.stderr)


if __name__ == "__main__":
    unittest.main()
