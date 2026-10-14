import os as _os; _os.environ.setdefault("VAULT_ALLOW_NONTTY", "1")  # test-only TTY bypass
import json, os, subprocess, sys, tempfile, unittest
import vault, agent_api

HERE = os.path.dirname(os.path.abspath(__file__))
SDK_PY = os.path.join(HERE, ".venv-sdk", "bin", "python")


class MCP:
    def __init__(self, env):
        self.p = subprocess.Popen([sys.executable, os.path.join(HERE, "mcp_server.py")], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, bufsize=1)
        self.n = 0

    def raw(self, line):
        self.p.stdin.write(line + "\n"); self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def req(self, method, params=None):
        self.n += 1
        return self.raw(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}}))

    def note(self, method):
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n"); self.p.stdin.flush()

    def init(self):
        r = self.req("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}})
        self.note("notifications/initialized")
        return r

    def call(self, name, args=None):
        return self.req("tools/call", {"name": name, "arguments": args or {}})["result"]

    def close(self):
        self.p.stdin.close(); err = self.p.stderr.read(); self.p.wait(5); self.p.stdout.close(); self.p.stderr.close()
        return err


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.dbp = os.path.join(self.tmp, "v.db"); self.agp = os.path.join(self.tmp, "agents.json")
        os.environ["VAULT_DB"] = self.dbp; os.environ["VAULT_AGENTS"] = self.agp
        db = vault.connect(self.dbp)
        vault.append(db, "decision.made", "decision:D-003", {"decision_id": "D-003", "title": "Vault", "decision": "Mimari kararı alındı"},
                     "user:owner", "verified")
        db.close()
        self.tok = agent_api.add_agent("beta", rate_limit=100)
        self.servers = []

    def server(self, token="__default__"):
        env = {k: v for k, v in os.environ.items() if k != "VAULT_AGENT_TOKEN"}
        tok = self.tok if token == "__default__" else token
        if tok is not None:
            env["VAULT_AGENT_TOKEN"] = tok
        s = MCP(env); self.servers.append(s); return s

    def tearDown(self):
        for s in self.servers:
            if s.p.poll() is None:
                err = s.close()
                self.assertNotIn(self.tok, err)


class TestProtocol(Base):
    def test_initialize_handshake(self):
        s = self.server(); r = s.init()
        self.assertEqual(r["result"]["protocolVersion"], "2025-06-18")
        self.assertIn("tools", r["result"]["capabilities"])
        self.assertEqual(r["result"]["serverInfo"]["name"], "lattice-vault")
        self.assertEqual(s.req("ping")["result"], {})
        err = s.close()
        self.assertIn("identity=agent:beta", err); self.assertNotIn(self.tok, err)

    def test_tools_list_exactly_five(self):
        s = self.server(); s.init()
        tools = s.req("tools/list")["result"]["tools"]
        self.assertEqual(sorted(t["name"] for t in tools),
                         ["export_context_pack", "get_event", "get_summary", "propose_event", "search"])
        for t in tools:
            self.assertEqual(t["inputSchema"]["type"], "object")
        self.assertFalse(any("approve" in t["name"] or "reject" in t["name"] for t in tools))
        r = s.req("tools/call", {"name": "approve", "arguments": {"id": "x"}})
        self.assertIn("error", r)

    def test_malformed_json_and_unknown_method(self):
        s = self.server(); s.init()
        r = s.raw("{not json"); self.assertEqual(r["error"]["code"], -32700); self.assertIsNone(r["id"])
        r = s.raw('{"jsonrpc":"2.0","id":7}'); self.assertEqual(r["error"]["code"], -32600)
        r = s.req("does/not_exist"); self.assertEqual(r["error"]["code"], -32601)
        self.assertEqual(s.req("ping")["result"], {})       # survived
        self.assertIsNone(s.p.poll())

    def test_resources(self):
        s = self.server(); s.init()
        uris = [r["uri"] for r in s.req("resources/list")["result"]["resources"]]
        self.assertIn("vault://pack/minimal", uris)
        txt = s.req("resources/read", {"uri": "vault://pack/minimal"})["result"]["contents"][0]["text"]
        self.assertIn("pack_spec: 1.0.0", txt)
        eid = json.loads(s.call("search", {"query": "karari"})["content"][0]["text"])[0]["source"]
        ev = json.loads(s.req("resources/read", {"uri": eid})["result"]["contents"][0]["text"])
        self.assertEqual(ev["status"], "active")
        self.assertEqual(s.req("resources/read", {"uri": "vault://nope"})["error"]["code"], -32002)


class TestTools(Base):
    def test_each_tool(self):
        s = self.server(); s.init()
        r = s.call("get_summary"); self.assertFalse(r["isError"]); self.assertEqual(r["content"][0]["type"], "text")
        self.assertIn("kararı", r["content"][0]["text"])
        r = s.call("search", {"query": "KARARI"}); hits = json.loads(r["content"][0]["text"])
        self.assertEqual(len(hits), 1); eid = hits[0]["source"]
        r = s.call("export_context_pack", {"profile": "minimal", "max_chars": 2000}); self.assertFalse(r["isError"])
        self.assertLessEqual(len(r["content"][0]["text"]), 2000)
        r = s.call("get_event", {"id": eid}); self.assertEqual(json.loads(r["content"][0]["text"])["payload"]["decision_id"], "D-003")
        r = s.call("propose_event", {"type": "note.added", "subject": "x", "payload": {"text": "merhaba"}, "idempotency_key": "a"})
        self.assertFalse(r["isError"], r); self.assertEqual(json.loads(r["content"][0]["text"])["status"], "proposed")
        r = s.call("get_event", {"id": "nope"}); self.assertTrue(r["isError"])

    def test_propose_hidden_until_cli_approve(self):
        s = self.server(); s.init()
        r = s.call("propose_event", {"type": "preference.set", "subject": "user:owner", "key": "kahve",
                                     "payload": {"value": "TURKKAHVESI"}, "idempotency_key": "p1", "base_vault_seq": 1})
        eid = json.loads(r["content"][0]["text"])["event_id"]
        for tool, args in (("export_context_pack", {"profile": "full"}), ("get_summary", {}), ("search", {"query": "turkkahvesi"})):
            self.assertNotIn("TURKKAHVESI", s.call(tool, args)["content"][0]["text"], tool)
        ev = json.loads(s.call("get_event", {"id": eid})["content"][0]["text"])
        self.assertEqual(ev["status"], "proposed"); self.assertIsNone(ev["payload"])
        cli = subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), "approve", eid], capture_output=True, text=True)
        self.assertEqual(cli.returncode, 0, cli.stderr)
        self.assertIn("TURKKAHVESI", s.call("export_context_pack", {"profile": "full"})["content"][0]["text"])
        self.assertIn("TURKKAHVESI", s.call("get_summary")["content"][0]["text"])

    def test_forbidden_fields_via_mcp(self):
        s = self.server(); s.init()
        for i, k in enumerate(sorted(agent_api.FORBIDDEN_KEYS)):
            for args in ({"type": "note.added", "subject": "x", "payload": {"text": "a"}, "idempotency_key": f"f{i}", k: "v"},
                         {"type": "note.added", "subject": "x", "payload": {"text": "a", k: "v"}, "idempotency_key": f"g{i}"}):
                r = s.call("propose_event", args)
                self.assertTrue(r["isError"]); self.assertIn("forbidden", r["content"][0]["text"])
        r = s.call("propose_event", {"type": "event.approved", "subject": "x", "payload": {}, "idempotency_key": "z"})
        self.assertTrue(r["isError"])
        n = vault.connect(self.dbp).execute("SELECT count(*) FROM events").fetchone()[0]
        self.assertEqual(n, 1)

    def test_no_token_reads_ok_propose_refused(self):
        for tok in (None, "", "vt_bogus"):
            with self.subTest(tok=tok):
                s = self.server(token=tok); s.init()
                self.assertFalse(s.call("get_summary")["isError"])
                self.assertFalse(s.call("search", {"query": "karari"})["isError"])
                r = s.call("propose_event", {"type": "note.added", "subject": "x", "payload": {"text": "a"}, "idempotency_key": "n"})
                self.assertTrue(r["isError"]); self.assertIn("refused", r["content"][0]["text"])
                self.assertNotIn("vt_bogus", r["content"][0]["text"])
                err = s.close(); self.assertIn("writes refused", err); self.assertNotIn("vt_bogus", err)


@unittest.skipUnless(os.path.exists(SDK_PY), "mcp SDK venv (.venv-sdk) not installed")
class TestSDKSmoke(Base):
    def test_official_sdk_stdio_client(self):
        code = r'''
import asyncio, json, os, sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
async def main():
    params = StdioServerParameters(command=sys.argv[1], args=[sys.argv[2]], env=dict(os.environ))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            init = await s.initialize()
            tools = await s.list_tools()
            res = await s.call_tool("search", {"query": "karari"})
            prop = await s.call_tool("propose_event", {"type": "note.added", "subject": "x", "payload": {"text": "sdk"}, "idempotency_key": "sdk1"})
            rl = await s.list_resources()
            g = lambda o, a, b: getattr(o, a) if hasattr(o, a) else getattr(o, b)
            print(json.dumps({"proto": g(init, "protocol_version", "protocolVersion"), "tools": sorted(t.name for t in tools.tools),
                              "search_err": g(res, "is_error", "isError"), "search": res.content[0].text,
                              "prop_err": g(prop, "is_error", "isError"), "prop": prop.content[0].text, "resources": len(rl.resources)}))
asyncio.run(main())
'''
        env = {**os.environ, "VAULT_AGENT_TOKEN": self.tok}
        r = subprocess.run([SDK_PY, "-c", code, sys.executable, os.path.join(HERE, "mcp_server.py")],
                           capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        out = json.loads(r.stdout.strip().splitlines()[-1])
        print("\nSDK smoke:", {k: out[k] for k in ("proto", "tools", "search_err", "prop_err", "resources")}, file=sys.stderr)
        self.assertEqual(len(out["tools"]), 5); self.assertFalse(out["search_err"]); self.assertIn("D-003", out["search"])
        self.assertFalse(out["prop_err"]); self.assertIn('"proposed"', out["prop"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
