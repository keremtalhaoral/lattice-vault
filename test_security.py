"""Security regression tests (SSRF in citation check, tampering detection, TTY gate, token file, ops log)."""
import http.server, json, os, socket, sqlite3, stat, subprocess, sys, threading, unittest
from unittest import mock
from testutil import fresh, user, agent, status
import vault, agent_api, citation_check as cc, ops

HERE = os.path.dirname(os.path.abspath(__file__))


class _H(http.server.BaseHTTPRequestHandler):
    hits = []
    def do_HEAD(self):
        _H.hits.append(self.path)
        self.send_response(302); self.send_header("Location", "http://127.0.0.1:1/admin"); self.end_headers()
    do_GET = do_HEAD
    def log_message(self, *a): pass


class K1CitationSSRF(unittest.TestCase):
    def setUp(self):
        fresh(self); os.environ.pop("VAULT_OFFLINE", None)
        self.srv = http.server.HTTPServer(("127.0.0.1", 0), _H); _H.hits = []
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)
        self.port = self.srv.server_address[1]

    def test_poc_loopback_and_files_not_probed(self):
        # PoC from the report: agent-supplied loopback URL + absolute paths
        e = agent(self.db, "learning.noted", "t", {"text": "a", "sources": [f"http://127.0.0.1:{self.port}/admin/internal",
                                                                          "/etc/shadow", "/nonexistent/secret"]})
        res = cc.check_entries(self.db, base_dir=self.d)
        self.assertEqual(_H.hits, [])                                     # no request reached the loopback server
        reasons = [r["reason"] for r in res if r["id"] == e]
        self.assertTrue(reasons)
        self.assertEqual(cc.check_source(self.db, "/etc/shadow", self.d), cc.check_source(self.db, "/nonexistent/secret", self.d))
        self.assertEqual(cc.check_source(self.db, "../../etc/passwd", self.d)[1], "file ref not allowed")

    def test_url_validation(self):
        for u in (f"http://127.0.0.1:{self.port}/", "https://127.0.0.1/", "https://localhost/", "https://10.0.0.5/",
                  "https://169.254.169.254/latest/meta-data/", "https://[::1]/", "https://example.com:8443/", "ftp://x/",
                  "https://user:pw@example.com/"):
            with self.subTest(u=u):
                with self.assertRaises((cc.UnsafeURL, socket.gaierror)):
                    cc.validate_url(u)

    def test_redirects_not_followed(self):
        import urllib.request
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/r", method="HEAD")
        with self.assertRaises(urllib.error.HTTPError) as cm:     # 302 surfaces as status, Location not fetched
            cc._OPENER.open(req, timeout=3)
        self.assertEqual(cm.exception.code, 302); self.assertEqual(_H.hits, ["/r"])

    def test_sources_field_validated_in_proposals(self):
        os.environ["VAULT_AGENTS"] = os.path.join(self.d, "agents.json")
        tok = agent_api.add_agent("a", rate_limit=100)
        bad = [[f"http://127.0.0.1:{self.port}/admin"], ["/etc/shadow"], ["file:///etc/passwd"], ["https://x/"] * 11, [{"u": 1}]]
        for i, s in enumerate(bad):
            with self.subTest(s=str(s)[:40]):
                with self.assertRaisesRegex(agent_api.Refused, "sources"):
                    agent_api.propose_event(tok, {"type": "note.added", "subject": "x", "payload": {"text": "t", "sources": s},
                                                  "idempotency_key": f"s{i}"})
        ok = agent_api.propose_event(tok, {"type": "note.added", "subject": "x", "idempotency_key": "okk",
                                           "payload": {"text": "t", "sources": ["https://example.com/a", f"vault://event/{'0'*8}-0000-7000-8000-{'0'*12}"]}})
        self.assertEqual(ok["status"], "proposed")
        with self.assertRaisesRegex(agent_api.Refused, "source_id"):
            agent_api.propose_event(tok, {"type": "note.added", "subject": "x", "payload": {"text": "t", "source_id": "/etc/x"},
                                          "idempotency_key": "s99"})


class Y1Integrity(unittest.TestCase):
    def setUp(self):
        fresh(self)
        self.e = user(self.db, "preference.set", "user:owner", {"key": "dil", "value": "Türkçe"})
        vault.audit(self.db, "user:owner", "x", "accepted", "r")
        self.db.close()

    def raw(self):
        return sqlite3.connect(self.dbp)

    def test_file_modes(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.dbp).st_mode), 0o600)
        self.assertEqual(os.umask(0o077), 0o077)

    def test_dropped_trigger_fails_loudly_and_is_not_recreated(self):
        r = self.raw(); r.execute("DROP TRIGGER events_no_update"); r.commit(); r.close()
        with self.assertRaisesRegex(vault.TamperError, "missing trigger events_no_update"):
            vault.connect(self.dbp)
        r = self.raw()
        self.assertIsNone(r.execute("SELECT 1 FROM sqlite_master WHERE name='events_no_update'").fetchone())

    def test_poc_tamper_detected_even_if_triggers_restored(self):
        r = self.raw()
        r.execute("DROP TRIGGER events_no_update")
        r.execute("UPDATE events SET payload=json_set(payload,'$.value','Esperanto')")
        r.execute(vault.TRIGGERS["events_no_update"]); r.commit(); r.close()
        with self.assertRaisesRegex(vault.TamperError, "event chain broken"):
            vault.connect(self.dbp)

    def test_forged_human_row_detected(self):
        r = self.raw()
        r.execute("INSERT INTO events(id,replica_id,replica_seq,hlc,ts,type,subject,payload,actor,trust,content_hash,prev_hash,hash) "
                  "VALUES('f','local',99,'fff','t','decision.made','d','{}','user:owner','verified','c','bogus','bogus2')")
        r.commit(); r.close()
        with self.assertRaisesRegex(vault.TamperError, "chain"):
            vault.connect(self.dbp)

    def test_audit_deletion_detected(self):
        db = vault.connect(self.dbp); vault.audit(db, "user:owner", "y", "accepted", "r2"); db.close()
        r = self.raw(); r.execute("DROP TRIGGER audit_no_delete"); r.execute("DELETE FROM audit WHERE id=1")
        r.execute(vault.TRIGGERS["audit_no_delete"]); r.commit(); r.close()
        with self.assertRaisesRegex(vault.TamperError, "audit chain broken"):
            vault.connect(self.dbp)
        # Known limit (documented): truncating the WHOLE tail/table leaves a valid shorter chain -> needs an
        # external anchor (keychain HMAC of the head), planned next.

    def test_doctor_clean_on_healthy_db(self):
        db = vault.connect(self.dbp)
        rep = ops.doctor(db)
        self.assertTrue(rep["ok"], rep)
        self.assertTrue(rep["checks"]["projection_matches_log"])

    def test_doctor_detects_projection_drift(self):
        db = vault.connect(self.dbp)
        db.execute("UPDATE proj_preferences SET value='Esperanto'"); db.commit()
        rep = ops.doctor(db)
        self.assertFalse(rep["ok"]); self.assertIn("projections differ", " ".join(rep["problems"]))

    def test_journal_mode_delete_not_wal(self):
        db = vault.connect(self.dbp)
        self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "delete")
        self.assertEqual(db.execute("PRAGMA secure_delete").fetchone()[0], 1)


class Y2HumanTTY(unittest.TestCase):
    def setUp(self):
        fresh(self); self.e = agent(self.db, "note.added", "x", {"text": "t"})

    def test_approve_refused_without_tty(self):
        env = {k: v for k, v in os.environ.items() if k != "VAULT_ALLOW_NONTTY"}
        for cmd in (["approve", self.e], ["reject", self.e], ["add", "note.added", "x", "--text", "y"], ["revert", self.e, "--reason", "r"]):
            r = subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), *cmd], capture_output=True, text=True,
                               env=env, stdin=subprocess.DEVNULL)
            self.assertEqual(r.returncode, 1, cmd); self.assertIn("interactive terminal", r.stderr)
        self.assertEqual(status(vault.connect(self.dbp), self.e), "proposed")


class Y3TokenFile(unittest.TestCase):
    def setUp(self):
        fresh(self); os.environ["VAULT_AGENTS"] = os.path.join(self.d, "agents.json")
        self.tok = agent_api.add_agent("filebot", rate_limit=100)
        self.tf = os.path.join(self.d, "token")
        with open(self.tf, "w") as f:
            f.write(self.tok + "\n")
        os.chmod(self.tf, 0o600)

    def tearDown(self):
        os.environ.pop("VAULT_AGENT_TOKEN_FILE", None); os.environ.pop("VAULT_AGENT_TOKEN", None)

    def test_token_file_preferred_and_mode_enforced(self):
        os.environ["VAULT_AGENT_TOKEN_FILE"] = self.tf; os.environ["VAULT_AGENT_TOKEN"] = "vt_wrong"
        self.assertEqual(agent_api.token_from_env(), self.tok)
        os.chmod(self.tf, 0o644)
        with self.assertRaisesRegex(agent_api.Refused, "600"):
            agent_api.token_from_env()

    def test_mcp_server_uses_token_file(self):
        env = {**os.environ, "VAULT_AGENT_TOKEN_FILE": self.tf}; env.pop("VAULT_AGENT_TOKEN", None)
        p = subprocess.run([sys.executable, os.path.join(HERE, "mcp_server.py")], capture_output=True, text=True, env=env, timeout=20,
                           input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}) + "\n")
        self.assertIn("identity=agent:filebot", p.stderr); self.assertNotIn(self.tok, p.stderr + p.stdout)


class ObservabilityTest(unittest.TestCase):
    def test_ops_log_is_json_file_without_content(self):
        fresh(self)
        import importer
        root = os.path.join(self.d, "vault"); os.makedirs(os.path.join(root, "log"))
        open(os.path.join(root, "log", "2026-10-14.md"), "w").write("- (05:00, Ada) [tür: fikir] GIZLIICERIK satırı\n")
        importer.run(self.db, root, dry_run=False)
        ops.doctor(self.db)
        lines = [json.loads(l) for l in open(os.environ["VAULT_LOG"])]
        self.assertTrue(any(l["component"] == "import" and l["op"] == "commit" and "duration_ms" in l for l in lines))
        self.assertTrue(all(set(l) <= {"ts", "component", "op", "request_id", "import_id", "duration_ms", "result", "error_code", "count"}
                            for l in lines))
        self.assertNotIn("GIZLIICERIK", open(os.environ["VAULT_LOG"]).read())
        self.assertEqual(stat.S_IMODE(os.stat(os.environ["VAULT_LOG"]).st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
