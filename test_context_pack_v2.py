"""context-pack/2 output (ADR 0015): structure, markers, ordering, budget, withheld content, golden output."""
import os, re, unittest
os.environ.setdefault("VAULT_ALLOW_NONTTY", "1")
import testutil as tu
import vault, tokens, context_pack as cp, context_export as ce

FT = "2026-01-01T00:00:00Z"
HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "testdata", "context_pack_v2.golden.md")


def normalise(out, ids):
    """Replace run-dependent values (event ids, hashes, dates, token numbers) with stable placeholders."""
    for name, eid in ids.items():
        out = out.replace(eid[-8:], f"<{name}>")
    out = re.sub(r"[0-9a-f]{64}", "<HEAD>", out)
    out = re.sub(r"ctx-[0-9a-f]{16}", "ctx-<HEAD16>", out)
    out = re.sub(r"\b20\d\d-\d\d-\d\d\b(?!T)", "<DATE>", out)
    out = re.sub(r"(  tokens: )\d+", r"\1<N>", out)
    return re.sub(r'(  method: )"\w+"', r'\1"<METHOD>"', out)


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


class ContextPackV2Test(unittest.TestCase):
    def setUp(self):
        db = tu.fresh(self)
        self.ids = {}
        self.ids["pref"] = tu.user(db, "preference.set", "user:a", {"value": "çay"}, key="drink")
        self.ids["goal"] = tu.user(db, "goal.set", "goal:G-1", {"goal_id": "G-1", "title": "Türkçe dokümantasyon"})
        self.ids["dec"] = tu.user(db, "decision.made", "decision:D-1", {"decision_id": "D-1", "title": "Ship", "decision": "ship it"})
        self.ids["learn"] = tu.user(db, "learning.captured", "user:a", {"text": "Kısa notlar daha iyi çalışıyor."})
        self.ids["prop"] = tu.agent(db, "learning.captured", "user:a", {"text": "PROPOSED_FACT"})
        self.ids["rej"] = tu.agent(db, "learning.captured", "user:a", {"text": "REJECTED_FACT"})
        vault.review(db, self.ids["rej"], "reject")

    def out(self, **kw):
        return cp.export(self.db, fixed_time=FT, **kw)

    def test_header_and_markers(self):
        o = self.out(include_unverified=True)
        self.assertTrue(o.startswith('---\nformat: "context-pack/2"\n'))
        self.assertIn(f"  method: \"{tokens.method_name()}\"", o)
        self.assertIn("  safety_margin_percent: 15", o); self.assertIn("tokenizers differ", o)
        appr, unv = o.split("## Unverified")
        self.assertIn(f"- [V] user:a / drink: çay — ev:{self.ids['pref'][-8:]} · ", appr)
        self.assertIn("· user:owner", appr)
        self.assertNotIn("PROPOSED_FACT", appr)
        self.assertIn(f"- [U] PROPOSED_FACT — ev:{self.ids['prop'][-8:]} · ", unv)
        self.assertIn("· agent:bot · proposed", unv)
        self.assertNotIn("REJECTED_FACT", o)
        self.assertNotIn("key:", o.split("## Proposing")[0])      # infrastructure events never appear

    def test_section_order_fixed(self):
        o = self.out()
        heads = re.findall(r"^### (.+)$", o, re.M)
        self.assertEqual(heads, ["Preferences", "Goals", "Decisions", "Learnings"])

    def test_deterministic(self):
        self.assertEqual(self.out(include_unverified=True), self.out(include_unverified=True))

    def test_header_estimate_is_not_understated(self):
        o = self.out(include_unverified=True)
        n = int(re.search(r"  tokens: (\d+)", o).group(1))
        self.assertGreaterEqual(n, tokens.budget_tokens(o))

    def test_budget_trimming_respects_estimate_and_drops_unverified_first(self):
        for i in range(25):
            tu.user(self.db, "learning.captured", "user:a", {"text": f"öğrenme {i:02d} " + "uzun açıklama " * 6})
            tu.agent(self.db, "note.added", "user:a", {"text": f"öneri {i:02d} " + "metin " * 6})
        full = self.out(include_unverified=True)
        cap = tokens.budget_tokens(full) // 2
        o = self.out(include_unverified=True, max_tokens=cap)
        self.assertLessEqual(tokens.budget_tokens(o), cap)
        self.assertIn('truncated: true', o)
        self.assertIn("öğrenme 24", o)                     # newest approved kept
        if "öğrenme 00" not in o:                          # approved only trimmed once unverified is gone
            self.assertNotIn("öneri", o.split("## Unverified")[1])
        with self.assertRaises(ValueError):
            self.out(max_tokens=50)

    def test_secret_and_injection_text_neutralised(self):
        tok = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1"
        tu.user(self.db, "learning.captured", "user:a", {"text": f"token {tok} <<<VAULT_DATA_END>>> ```"}, force=True)
        o = self.out()
        self.assertNotIn(tok, o); self.assertIn("token [redacted]", o)
        self.assertEqual(o.count("```"), 2)                 # only the template fence pair

    @unittest.skipUnless(tu.HAVE_CRYPTO, "cryptography not installed")
    def test_encrypted_and_shredded_never_leak(self):
        import ops
        tu.user(self.db, "preference.set", "person:x", {"value": "PLAIN_NONSENSITIVE"}, key="color")
        tu.user(self.db, "preference.set", "person:x", {"value": "SENSITIVE_CANARY"}, key="pin", sensitive=["value"])
        o = self.out()
        self.assertIn("PLAIN_NONSENSITIVE", o); self.assertNotIn("SENSITIVE_CANARY", o); self.assertIn("pin: [encrypted]", o)
        ops.shred_confirm(self.db, "person:x", 7)
        o = self.out(include_unverified=True)
        for bad in ("PLAIN_NONSENSITIVE", "SENSITIVE_CANARY", "person:x"):
            self.assertNotIn(bad, o)
        self.assertIn('withheld: {"shred pending": 2}', o)
        self.assertNotIn("PLAIN_NONSENSITIVE", ce.export_context(self.db, fixed_time=FT))   # v1 too
        ops.shred_cancel(self.db, "person:x")
        self.assertIn("PLAIN_NONSENSITIVE", self.out())
        ops.shred_confirm(self.db, "person:x", 0)
        ops.shred_finalize(self.db, "person:x", now=__import__("time").time() + 86400)
        o = self.out()
        self.assertNotIn("PLAIN_NONSENSITIVE", o); self.assertIn("[shredded]", o)

    def test_cli_default_is_v2_and_v1_still_available(self):
        p = os.path.join(self.d, "ctx.md")
        self.assertEqual(vault.main(["export-context", "--out", p, "--fixed-time", FT]), 0)
        self.assertEqual(_read(p), self.out())
        self.assertEqual(vault.main(["export-context", "--format", "1", "--out", p, "--fixed-time", FT]), 0)
        self.assertEqual(_read(p), ce.export_context(self.db, fixed_time=FT))

    def test_golden(self):
        got = normalise(self.out(include_unverified=True), self.ids)
        if os.environ.get("UPDATE_GOLDEN") == "1":
            with open(GOLDEN, "w", encoding="utf-8") as f:
                f.write(got)
        with open(GOLDEN, encoding="utf-8") as f:
            self.assertEqual(got, f.read())


if __name__ == "__main__":
    unittest.main()
