import hashlib, json, os, subprocess, sys, unittest
from unittest import mock
from testutil import fresh, user, agent, status, HAVE_CRYPTO
import vault, event_detail as ed

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE_KEY = "sk-" + "Q" * 8 + "testonlynotreal" + "9" * 4   # matches openai_key pattern; synthetic


def run(*a):
    return subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), *a], capture_output=True, text=True,
                          env=dict(os.environ))


class EventDetailTest(unittest.TestCase):
    def setUp(self):
        fresh(self)
        self.base = user(self.db, "preference.set", "user:owner", {"key": "dil", "value": "Türkçe"})

    def correct(self, target, value):
        return vault.append(self.db, "event.corrected", f"event:{self.base}", {"field": "value", "new_value": value,
                            "reason": "t"}, "user:owner", "verified", supersedes=target)[0]

    def show(self, ref):
        db = ed.open_ro(self.dbp)
        try:
            return ed.detail(db, ref)
        finally:
            db.close()

    def test_full_id_and_suffix(self):
        self.assertEqual(self.show(self.base)["id"], self.base)
        self.assertEqual(self.show(self.base[-8:])["id"], self.base)
        self.assertEqual(self.show(f"vault://event/{self.base}")["id"], self.base)
        with self.assertRaisesRegex(ValueError, "at least 6"):
            self.show(self.base[-4:])

    def test_ambiguous_suffix(self):
        other = user(self.db, "note.added", "n", {"text": "n"})
        db = ed.open_ro(self.dbp)
        try:   # real UUIDv7 suffix collisions are improbable; feed resolve() a DB whose LIKE matches two ids
            class TwoMatches:
                def execute(s, q, a=()):
                    return iter([(self.base,), (other,)]) if "LIKE" in q else db.execute(q, a)
            with self.assertRaisesRegex(ValueError, f"ambiguous id suffix abcdef; candidates: {self.base}, {other}"):
                ed.resolve(TwoMatches(), "abcdef")
        finally:
            db.close()

    def test_unknown(self):
        with self.assertRaisesRegex(ValueError, "unknown"):
            self.show("00000000-0000-7000-8000-000000000000")
        r = run("show", "ffffffffffff")
        self.assertEqual(r.returncode, 1); self.assertIn("unknown event", r.stderr)

    def test_two_corrections_head(self):
        c1 = self.correct(self.base, "A"); c2 = self.correct(c1, "B")
        for ref in (self.base, c1, c2):
            h = self.show(ref)["history"]
            self.assertEqual(h["effective_head"], c2); self.assertFalse(h["conflict"])
            self.assertEqual(h["effective_payload"]["value"], "B")
            self.assertEqual([t["id"] for t in h["timeline"]], [self.base, c1, c2])
        d = self.show(c1)["history"]
        self.assertEqual(d["ancestors"], [self.base]); self.assertEqual(d["descendants"], [c2])
        out = ed.show(self.base, path=self.dbp)
        self.assertIn(f"effective head: {c2}", out); self.assertEqual(out.count("<= HEAD"), 1)
        self.assertIn("<= HEAD", [l for l in out.splitlines() if c2[-12:] in l and "event.corrected" in l][0])
        self.assertIn("└─", ed.show(self.base, tree=True, path=self.dbp))

    def test_revert_marks_reverted(self):
        c1 = self.correct(self.base, "A")
        rv = vault.append(self.db, "event.reverted", f"event:{c1}", {"reason": "x"}, "user:owner", "verified", target_ids=[c1])[0]
        d = self.show(c1)
        self.assertEqual(d["status"], "reverted")
        self.assertIn("reverted", [r["action"] for r in d["review"]])
        h = d["history"]
        self.assertEqual(h["effective_head"], self.base); self.assertEqual(h["effective_payload"]["value"], "Türkçe")
        self.assertIn(rv, [t["id"] for t in h["timeline"]])

    def test_review_history(self):
        p = agent(self.db, "learning.captured", "user:owner", {"text": "x"})
        self.assertEqual(self.show(p)["status"], "proposed")
        vault.review(self.db, p, "approve")
        d = self.show(p)
        self.assertEqual(d["status"], "active")
        self.assertEqual([(r["action"], r["by"]) for r in d["review"]], [("proposed", "agent:bot"), ("approved", "user:owner")])
        self.assertTrue(any(a["action"] == "approve" for a in d["audit"]))

    def test_conflict_projection_two_heads(self):
        a = agent(self.db, "preference.set", "user:owner", {"value": "x"}, key="renk")
        b = agent(self.db, "preference.set", "user:owner", {"value": "y"}, key="renk")
        vault.review(self.db, [a, b], "approve")
        h = self.show(a)["history"]
        self.assertTrue(h["conflict"]); self.assertEqual(h["projection_conflict_heads"], sorted([a, b]))
        self.assertIn("CONFLICT", ed.show(a, path=self.dbp))

    def test_conflict_dag_two_heads(self):
        c1 = self.correct(self.base, "A")
        with mock.patch.object(vault, "validate_parents", lambda *a: None):   # simulates a sync fork
            c2 = self.correct(self.base, "B")
        h = self.show(self.base)["history"]
        self.assertTrue(h["conflict"]); self.assertIsNone(h["effective_head"])
        self.assertEqual(sorted(h["conflict_heads"]), sorted([c1, c2]))
        self.assertIn("!! CONFLICT", ed.show(self.base, tree=True, path=self.dbp))

    def test_secret_filtered_and_redacted(self):
        bad = vault.append(self.db, "note.added", "x", {"text": f"key {FAKE_KEY}"}, "user:owner", "verified", force=True)[0]
        for out in (ed.show(bad, path=self.dbp), ed.show(bad, as_json=True, path=self.dbp)):
            self.assertNotIn(FAKE_KEY, out); self.assertIn("[filtered:openai_key]", out)
        import ops
        newp = os.path.join(self.d, "clean.db")
        ops.redact(self.db, bad, newp, "leak")
        for out in (ed.show(bad, path=newp), ed.show(bad, as_json=True, path=newp)):
            self.assertNotIn(FAKE_KEY, out); self.assertIn("[redacted]", out)

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_encrypted_never_decrypted(self):
        e = vault.append(self.db, "note.added", "x", {"text": "t", "pin": "ZZTOPSECRET42"}, "user:owner", "verified",
                         sensitive=["pin"])[0]
        with mock.patch.object(vault, "decrypt_payload", side_effect=AssertionError("decrypt called")):
            for out in (ed.show(e, path=self.dbp), ed.show(e, as_json=True, path=self.dbp)):
                self.assertNotIn("ZZTOPSECRET42", out); self.assertIn("[encrypted]", out)

    def test_json_stable(self):
        c1 = self.correct(self.base, "A")
        r1 = run("show", self.base, "--json"); r2 = run("show", self.base[-10:], "--json")
        self.assertEqual(r1.returncode, 0, r1.stderr); self.assertEqual(r1.stdout, r2.stdout)
        d = json.loads(r1.stdout)
        self.assertEqual(sorted(d), sorted(["detail_version", "id", "type", "subject", "key", "ts", "hlc", "actor", "import_id",
                         "trust", "trust_recorded", "status", "decided_by", "schema_version", "hash", "prev_hash",
                         "chain_verification", "encrypted", "payload", "review", "audit", "history"]))
        self.assertTrue(d["chain_verification"]["ok"]); self.assertEqual(d["history"]["effective_head"], c1)

    def test_read_only(self):
        self.correct(self.base, "A"); self.db.close()
        def h():
            with open(self.dbp, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest(), os.stat(self.dbp).st_mtime_ns
        before = h()
        for args in (("show", self.base), ("show", self.base, "--json"), ("show", self.base, "--tree")):
            self.assertEqual(run(*args).returncode, 0)
        self.assertEqual(h(), before); self.assertFalse(os.path.exists(self.dbp + "-journal"))
        self.db = vault.connect(self.dbp)


if __name__ == "__main__":
    unittest.main()
