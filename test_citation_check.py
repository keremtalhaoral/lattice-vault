import testutil  # noqa: F401  test harness: harness key, config dir, TTY bypass (SECURITY.md)
import json, os, tempfile, unittest
import vault, citation_check as cc


class CitationCheckTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.db = vault.connect(os.path.join(self.d, "v.db"))
        self.u, _ = vault.append(self.db, "decision.made", "decision:D-003", {"decision_id": "D-003", "title": "V", "decision": "ok"}, "user:owner", "verified")

    def agent(self, payload):
        return vault.append(self.db, "learning.noted", "topic:x", payload, "agent:a1", "unverified")[0]

    def test_entries_flagged_without_resolvable_source(self):
        good = self.agent({"text": "a", "source": f"vault://event/{self.u}"})
        none = self.agent({"text": "b"})
        bad = self.agent({"text": "c", "sources": ["vault://event/00000000-0000-0000-0000-000000000000"]})
        open(os.path.join(self.d, "f.md"), "w").close()
        fileok = self.agent({"text": "d", "source": "f.md"})
        ids = {f["id"] for f in cc.check_entries(self.db, self.d)}
        self.assertEqual(ids, {none, bad}); self.assertNotIn(self.u, ids); self.assertNotIn(good, ids); self.assertNotIn(fileok, ids)

    def test_claims_in_pack_are_supported(self):
        self.assertEqual(cc.check_claims(self.db, vault.pack(self.db)), [])

    def test_claims_flagged(self):
        txt = (f"- cited [vault://event/{self.u}]\n- no cite here\n"
               "- ghost [vault://event/00000000-0000-0000-0000-000000000000]\nnot a claim")
        reasons = [f["reason"] for f in cc.check_claims(self.db, txt)]
        self.assertEqual(reasons, ["no citation", "unresolvable citation"])
        self.assertAlmostEqual(cc.unsupported_rate(self.db, txt), 2 / 3)

    def test_sampling_rate_and_determinism(self):
        items = [f"e{i}" for i in range(2000)]
        n = sum(cc.in_sample(i, 10) for i in items)
        self.assertTrue(150 < n < 250, n)
        self.assertEqual([cc.in_sample(i, 10) for i in items], [cc.in_sample(i, 10) for i in items])
        self.assertFalse(any(cc.in_sample(i, 0) for i in items)); self.assertTrue(all(cc.in_sample(i, 100) for i in items))

    def test_queue_and_verdict(self):
        bad = self.agent({"text": "b"})
        self.assertEqual(cc.queue_for_review(self.db, pct=0, text="- uncited"), 2)
        self.assertEqual(cc.queue_for_review(self.db, pct=0, text="- uncited"), 0)  # idempotent
        self.assertEqual(cc.queue_for_review(self.db, pct=100), 1)  # the human entry joins via sample
        items = {r["item"]: r["reason"] for r in cc.pending_reviews(self.db)}
        self.assertEqual(items[bad], "unsupported"); self.assertEqual(items[self.u], "sample")
        with self.assertRaises(ValueError): cc.record_verdict(self.db, bad, "supported", reviewer="agent:a1")
        cc.record_verdict(self.db, bad, "unsupported")
        self.assertNotIn(bad, {r["item"] for r in cc.pending_reviews(self.db)})
        with self.assertRaises(ValueError): cc.queue_for_review(self.db, pct=150)

    def test_events_untouched(self):
        n = self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        cc.queue_for_review(self.db, pct=100)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0], n)


if __name__ == "__main__":
    unittest.main()
