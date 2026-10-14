import os as _os; _os.environ.setdefault("VAULT_ALLOW_NONTTY", "1")  # test-only TTY bypass
import json, os, socket, tempfile, unittest, urllib.error
from unittest import mock
import vault, agent_api, citation_check as cc
from test_mcp_server import Base


class UrlCheckTest(unittest.TestCase):
    def setUp(self):
        os.environ.pop("VAULT_OFFLINE", None)
        self.db = vault.connect(os.path.join(tempfile.mkdtemp(), "v.db"))

    def agent(self, src):
        return vault.append(self.db, "learning.noted", "t:x", {"text": "a", "source": src}, "agent:a1", "unverified")[0]

    def run_with(self, fetch):
        with mock.patch.object(cc, "_fetch", side_effect=fetch) as m:
            return {f["id"]: f for f in cc.check_entries(self.db)}, m

    def test_status_mapping(self):
        codes = {"https://ok.example/": 200, "https://redir.example/": 301, "https://gone.example/": 410,
                 "https://nf.example/": 404, "https://blk.example/": 403, "https://err.example/": 503}
        ids = {u: self.agent(u) for u in codes}
        res, _ = self.run_with(lambda u, t: codes[u])
        self.assertNotIn(ids["https://ok.example/"], res)
        self.assertEqual(res[ids["https://redir.example/"]]["action"], "review")  # redirects not followed (sec review K1)
        for u in ("https://gone.example/", "https://nf.example/"):
            self.assertEqual(res[ids[u]]["action"], "flag")
        for u in ("https://blk.example/", "https://err.example/"):
            self.assertEqual(res[ids[u]]["action"], "review")

    def test_network_failures(self):
        a = self.agent("https://nodns.example/"); b = self.agent("https://slow.example/")
        def f(u, t):
            if "nodns" in u: raise urllib.error.URLError(socket.gaierror(-2, "Name not known"))
            raise urllib.error.URLError(socket.timeout("timed out"))
        res, _ = self.run_with(f)
        self.assertEqual(res[a]["action"], "flag"); self.assertEqual(res[b]["action"], "review")

    def test_cache(self):
        self.agent("https://ok.example/"); self.agent("https://ok.example/")
        _, m = self.run_with(lambda u, t: 200)
        self.assertEqual(m.call_count, 1)
        _, m2 = self.run_with(lambda u, t: 404)
        self.assertEqual(m2.call_count, 0)  # cached ok
        self.db.execute("UPDATE url_cache SET checked_epoch = checked_epoch - 8*86400"); self.db.commit()
        res, m3 = self.run_with(lambda u, t: 404)
        self.assertEqual(m3.call_count, 1); self.assertEqual({f["action"] for f in res.values()}, {"flag"})

    def test_offline_never_auto_valid(self):
        a = self.agent("https://ok.example/")
        with mock.patch.dict(os.environ, {"VAULT_OFFLINE": "1"}):
            res, m = self.run_with(lambda u, t: 200)
            self.assertEqual(m.call_count, 0); self.assertEqual(res[a]["action"], "review")
            cc.queue_for_review(self.db, pct=0)
        self.assertEqual({r["item"]: r["reason"] for r in cc.pending_reviews(self.db)}, {a: "uncertain_source"})

    def test_owner_unflagged_but_sampled_at_default_10pct(self):
        self.assertEqual(cc.DEFAULT_SAMPLE_PCT, 10.0)
        ids = [vault.append(self.db, "note.added", "t:k", {"text": str(i)}, "user:owner", "verified")[0] for i in range(300)]
        self.assertEqual(cc.check_entries(self.db), [])
        cc.queue_for_review(self.db)
        n = len(cc.pending_reviews(self.db)); self.assertTrue(10 < n < 60, n)
        self.assertTrue(all(r["reason"] == "sample" for r in cc.pending_reviews(self.db)))


class McpCitationTest(Base):
    def setUp(self):
        os.environ["VAULT_OFFLINE"] = "1"; super().setUp()

    def tearDown(self):
        super().tearDown(); os.environ.pop("VAULT_OFFLINE", None)

    def j(self, r):
        return json.loads(r["content"][0]["text"])

    def test_citation_tools_not_exposed_over_mcp(self):
        """Security review K1 (2026-10-14): citation tools removed from MCP; human CLI only."""
        for tok in (None, "__default__"):
            s = self.server(token=tok); s.init()
            names = {t["name"] for t in s.req("tools/list")["result"]["tools"]}
            for n in ("run_citation_check", "enqueue_review", "list_review_queue", "record_review_verdict"):
                self.assertNotIn(n, names)
                self.assertEqual(s.req("tools/call", {"name": n, "arguments": {"target": "entries"}})["error"]["code"], -32602)


if __name__ == "__main__":
    unittest.main()
