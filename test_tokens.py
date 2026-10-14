"""Token estimation calibration (ADR 0015). Reference counts were measured with tiktoken on the synthetic corpus in
tools/token_corpus.py and stored in testdata/token_reference.json (refresh: tools/calibrate_tokens.py --write)."""
import json, os, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "tools"))
import tokens
from token_corpus import samples

REF = json.load(open(os.path.join(HERE, "testdata", "token_reference.json"), encoding="utf-8"))


def rows():
    s = samples()
    assert len(s) == len(REF["counts"])
    out = []
    for (cat, text), r in zip(s, REF["counts"]):
        assert cat == r["cat"], (cat, r["cat"])
        out.append(dict(r, text=text))
    return out


class TokenCalibrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = rows()
        cls.rep = tokens.error_report(cls.rows, REF["encodings"])

    def test_corpus_is_deterministic_and_bilingual(self):
        self.assertEqual(samples(), samples())
        cats = {r["cat"] for r in self.rows}
        self.assertTrue({"tr_prose", "en_prose", "mixed"} <= cats)
        self.assertTrue(any(ch in r["text"] for r in self.rows for ch in "ğışçöüİ"))

    def test_heuristic_error_bounds(self):
        # measured (see ADR 0015): heuristic-o200k vs o200k MAE 6.0%, heuristic-cl100k vs cl100k MAE 7.6%
        for m, enc, mae, mx in (("heuristic-o200k", "o200k_base", 8, 25), ("heuristic-cl100k", "cl100k_base", 10, 35)):
            r = self.rep[f"{m} vs {enc}"]
            self.assertLessEqual(r["ALL"]["mae"], mae, r)
            self.assertLessEqual(r["ALL"]["max"], mx, r)
            self.assertLessEqual(r["tr_prose"]["mae"], mae, r)

    def test_heuristic_beats_chars4_on_turkish(self):
        for enc in REF["encodings"]:
            h = self.rep[f"heuristic vs {enc}"]["tr_prose"]
            self.assertGreaterEqual(h["mean"], -2, h)          # never materially under-estimates Turkish
        self.assertLess(self.rep["chars4 vs cl100k_base"]["tr_prose"]["mean"], -30)   # the v1 estimator did

    def test_budget_with_margin_covers_both_gpt_encodings(self):
        # the default (max of both fits) + 15% margin should cover nearly every sample of both encodings
        under = sum(1 for r in self.rows for enc in REF["encodings"]
                    if int(tokens.METHODS["heuristic"](r["text"]) * (1 + tokens.DEFAULT_MARGIN) + 0.999) < r[enc])
        self.assertLessEqual(under / (2 * len(self.rows)), 0.03)

    def test_edge_cases(self):
        self.assertEqual(tokens.estimate(""), 0); self.assertEqual(tokens.estimate(None), 0)
        self.assertGreater(tokens.estimate("ş"), 0)
        self.assertGreaterEqual(tokens.budget_tokens("hello world"), tokens.estimate("hello world"))
        self.assertGreater(tokens.heuristic("x" * 10000), 0)

    @unittest.skipUnless(tokens.tiktoken_available(), "tiktoken not installed (optional)")
    def test_reference_counts_match_installed_tiktoken(self):
        import tiktoken
        for enc in REF["encodings"]:
            e = tiktoken.get_encoding(enc)
            for r in self.rows[:20]:
                self.assertEqual(len(e.encode(r["text"])), r[enc])


if __name__ == "__main__":
    unittest.main()
