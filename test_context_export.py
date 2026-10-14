import os, re, unittest
import testutil as tu
import vault, context_export as ce

FT = "2026-01-01T00:00:00Z"


def front(out):
    assert out.startswith("---\n")
    end = out.index("\n---\n", 4)
    fm = {}
    for ln in out[4:end].splitlines():
        if ln and not ln.startswith(" "):
            k, _, v = ln.partition(":"); fm[k] = v.strip()
    return fm, out[end + 5:]


class ContextExportTest(unittest.TestCase):
    def setUp(self):
        db = tu.fresh(self)
        self.pref = tu.user(db, "preference.set", "user:a", {"value": "tea"}, key="drink")
        self.dec = tu.user(db, "decision.made", "decision:D-1", {"decision_id": "D-1", "title": "Ship", "decision": "ship it"})
        self.prop = tu.agent(db, "learning.captured", "user:a", {"text": "PROPOSED_FACT"})
        self.rej = tu.agent(db, "learning.captured", "user:a", {"text": "REJECTED_FACT"})
        vault.review(db, self.rej, "reject")
        self.rev = tu.user(db, "learning.captured", "user:a", {"text": "REVERTED_FACT"})
        vault.append(db, "event.reverted", f"event:{self.rev}", {"reason": "x"}, "user:owner", "verified", target_ids=[self.rev])
        self.old = tu.user(db, "learning.captured", "user:a", {"text": "OLD_LEARNING"})
        self.corr = tu.user(db, "event.corrected", f"event:{self.old}", {"field": "text", "new_value": "NEW_LEARNING",
                                                                          "reason": "fix"}, supersedes=self.old)

    def out(self, **kw):
        return ce.export_context(self.db, fixed_time=FT, **kw)

    def test_approved_only_by_default(self):
        o = self.out()
        self.assertIn("tea", o); self.assertIn("ship it", o)
        for bad in ("PROPOSED_FACT", "REJECTED_FACT", "REVERTED_FACT", "OLD_LEARNING", "## Unverified"):
            self.assertNotIn(bad, o)

    def test_correction_latest_with_supersedes(self):
        o = self.out()
        self.assertRegex(o, r"NEW_LEARNING `ev:%s` \(.*\) — supersedes `ev:%s`" % (self.corr[-8:], self.old[-8:]))

    def test_include_unverified_labelled(self):
        o = self.out(include_unverified=True)
        unv = o[o.index("## Unverified"):]
        self.assertIn("[UNVERIFIED proposed/unverified] PROPOSED_FACT", unv)
        self.assertNotIn("PROPOSED_FACT", o[:o.index("## Unverified")])
        self.assertNotIn("REJECTED_FACT", o); self.assertNotIn("REVERTED_FACT", o)

    @unittest.skipUnless(tu.HAVE_CRYPTO, "cryptography not installed")
    def test_encrypted_never_leaks(self):
        tu.user(self.db, "preference.set", "user:a", {"value": "PLAINSECRET123"}, key="pin", sensitive=["value"])
        o = self.out(include_unverified=True)
        self.assertNotIn("PLAINSECRET123", o); self.assertIn("pin: [encrypted]", o)

    def test_secret_pattern_and_redacted_never_leak(self):
        tok = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1"
        tu.user(self.db, "learning.captured", "user:a", {"text": f"token {tok}"}, force=True)
        o = self.out()
        self.assertNotIn(tok, o); self.assertIn("token [redacted]", o)

    def test_front_matter_structure(self):
        o = self.out(types=["preference.set"], max_tokens=5000)
        fm, body = front(o)
        for k in ("format", "generated_at", "vault_head_hash", "event_count", "filters", "profile", "source",
                  "instructions_for_ai"):
            self.assertIn(k, fm)
        self.assertEqual(fm["format"], "lattice-context/v1"); self.assertEqual(fm["generated_at"], f'"{FT}"')
        head = self.db.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()[0]
        self.assertEqual(fm["vault_head_hash"], f'"{head}"'); self.assertEqual(fm["event_count"], "1")
        self.assertTrue(body.lstrip().startswith("# Context Pack")); self.assertNotIn("ship it", body)

    def test_deterministic(self):
        self.assertEqual(self.out(include_unverified=True), self.out(include_unverified=True))
        os.environ["LATTICE_FIXED_TIME"] = FT; self.addCleanup(os.environ.pop, "LATTICE_FIXED_TIME", None)
        self.assertEqual(ce.export_context(self.db), self.out())

    def test_max_tokens_truncation(self):
        for i in range(30):
            tu.user(self.db, "learning.captured", "user:a", {"text": f"fact number {i:02d} " + "x" * 40})
        full = self.out()
        o = self.out(max_tokens=len(full) // 4 - 200)
        self.assertLessEqual(len(o) / 4, len(full) // 4 - 200)
        fm, _ = front(o)
        self.assertEqual(fm["truncated"], "true"); self.assertIn('"Learnings":', o)
        self.assertNotIn("fact number 00", o); self.assertIn("fact number 29", o)
        with self.assertRaises(ValueError):
            self.out(max_tokens=10)

    def test_vault_update_block_and_cli(self):
        p = os.path.join(self.d, "ctx.md")
        self.assertEqual(vault.main(["export-context", "--out", p, "--fixed-time", FT]), 0)
        o = open(p, encoding="utf-8").read()
        self.assertEqual(o, self.out())
        m = re.search(r"```vault_update\n(.*?)```", o, re.S)
        self.assertTrue(m); self.assertIn("events:", m.group(1)); self.assertIn("idempotency_key:", m.group(1))


if __name__ == "__main__":
    unittest.main()
