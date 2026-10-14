"""Schema registry, write-path validation, upcasters on read, forward-compat (docs/schema-evolution.md)."""
import contextlib, io, os, re, unittest
from testutil import fresh, user, agent, status
import vault, schemas, agent_api, ops, event_detail, context_export
from test_mcp_server import Base as MCPBase

HERE = os.path.dirname(os.path.abspath(__file__))
EMITTERS = ("vault.py", "importer.py", "ops.py", "sync.py", "agent_api.py", "context_export.py", "event_detail.py")

# one payload per type, shaped exactly like the code that emits it
SAMPLES = {
    "preference.set": {"value": "koyu"},
    "decision.made": {"decision_id": "D-1", "title": "t", "decision": "d", "context": None, "status_text": None,
                      "struck": True, "provenance": {"file": "decisions.md", "line": 1}},
    "decision.reversed": {"decision_id": "D-1"},
    "project.created": {"project_id": "p", "title": "P", "status": "active"},
    "project.status_changed": {"project_id": "p", "status": "done"},
    "goal.set": {"goal_id": "g", "title": "G", "target": 10},
    "goal.progressed": {"goal_id": "g", "progress": 0.5},
    "goal.completed": {"goal_id": "g"}, "goal.abandoned": {"goal_id": "g"},
    "learning.captured": {"text": "x", "sources": ["https://example.org"]},
    "note.added": {"text": "x", "tur": "tercih", "time": "10:00", "kaynak": None, "value": "x", "date": "2026-01-01"},
    "event.corrected": {"field": "value", "new_value": "acik", "reason": "typo"},
    "event.approved": {"reason": "ok"}, "event.rejected": {},
    "event.reverted": {"import_id": "i", "reason": "r"},
    "import.batch_approved": {"import_id": "i", "confirmed_block_ids": ["b1"]},
    "event.redacted": {"redaction_id": "r", "reason": "x"},
    "subject.shredded": {"key_id": "k"},
    "conflict.resolved": {"reason": "x"},
}


@contextlib.contextmanager
def patched(type_, spec, ups=None):
    """Temporarily replace a type's registry entry (+ upcasters). Test-only."""
    old, old_ups = schemas.SCHEMAS.get(type_), dict(schemas.UPCASTERS)
    schemas.SCHEMAS[type_] = spec
    schemas.UPCASTERS.update(ups or {})
    try:
        yield
    finally:
        schemas.UPCASTERS.clear(); schemas.UPCASTERS.update(old_ups)
        if old is None:
            schemas.SCHEMAS.pop(type_, None)
        else:
            schemas.SCHEMAS[type_] = old


# demo upcasters (TEST ONLY): preference.set v1 {"val"} -> v2 {"setting"} -> v3 {"value"}
def _v1_v2(p):
    p = dict(p); p["setting"] = p.pop("val", None); return p


def _v2_v3(p):
    p = dict(p); p["value"] = p.pop("setting", None); return p


V3 = schemas.Spec(3, {"value": schemas.F(schemas.SCALAR)})
DEMO_UPS = {("preference.set", 1): _v1_v2, ("preference.set", 2): _v2_v3}


def _read(f):
    with open(os.path.join(HERE, f), encoding="utf-8") as fh:
        return fh.read()


class Registry(unittest.TestCase):
    def test_every_emitted_type_registered_and_sample_validates(self):
        found = set()
        for f in EMITTERS:
            found |= set(re.findall(r'"((?:preference|decision|project|goal|learning|note|event|import|subject|conflict)\.[a-z_]+)"',
                                    _read(f)))
        self.assertTrue(found)
        self.assertEqual(sorted(found - set(schemas.SCHEMAS)), [])
        self.assertEqual(set(SAMPLES), set(schemas.SCHEMAS))
        for t, p in SAMPLES.items():
            schemas.validate(t, p)
            self.assertEqual(schemas.current_version(t), 1)   # no production bumps in this change

    def test_invalid_payloads(self):
        bad = [("event.corrected", {"new_value": 1}), ("subject.shredded", {"key_id": "k", "x": 1}),
               ("goal.progressed", {"progress": "half"}), ("goal.progressed", {"progress": True}),
               ("decision.made", {"decision_id": "x" * 201}), ("note.added", {"text": "x" * 70000}),
               ("nope.unknown", {})]
        for t, p in bad:
            with self.assertRaises(schemas.SchemaError, msg=t):
                schemas.validate(t, p)
        schemas.validate("nope.unknown", {}, allow_unknown=True)

    def test_upcast_is_pure_and_errors_on_gap_or_future(self):
        with patched("preference.set", V3, DEMO_UPS):
            src = {"val": "dark", "keep": 1}
            self.assertEqual(schemas.upcast("preference.set", 1, src), {"value": "dark", "keep": 1})
            self.assertEqual(src, {"val": "dark", "keep": 1})
            with self.assertRaises(schemas.UnknownVersion):
                schemas.upcast("preference.set", 4, src)
        with patched("goal.set", schemas.Spec(2)), self.assertRaises(schemas.UnknownVersion):
            schemas.upcast("goal.set", 1, {})


class WritePath(unittest.TestCase):
    def setUp(self):
        fresh(self)

    def test_append_stamps_registry_version_and_validates(self):
        eid = user(self.db, "preference.set", "user:owner", {"value": "x"}, key="k")
        self.assertEqual(self.db.execute("SELECT schema_version FROM events WHERE id=?", (eid,)).fetchone()[0], 1)
        with patched("goal.set", schemas.Spec(2)):
            g = user(self.db, "goal.set", "goal:a", {"title": "A"})
        self.assertEqual(self.db.execute("SELECT schema_version FROM events WHERE id=?", (g,)).fetchone()[0], 2)
        n = self.db.execute("SELECT count(*) FROM events").fetchone()[0]
        with self.assertRaises(schemas.SchemaError):
            user(self.db, "goal.progressed", "goal:a", {"progress": "lots"})
        with self.assertRaises(schemas.SchemaError):   # agents included, at the library level
            agent(self.db, "event.corrected", "event:x", {"new_value": 1}, supersedes=eid)
        self.assertEqual(self.db.execute("SELECT count(*) FROM events").fetchone()[0], n)

    def test_cli_rejects_invalid_and_warns_on_unknown(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = vault.main(["add", "goal.progressed", "goal:a", "--payload", '{"progress": "lots"}'])
        self.assertEqual(rc, 1)
        self.assertIn("field 'progress' must be", err.getvalue())
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = vault.main(["add", "habit.tracked", "user:owner", "--text", "kosu"])
        self.assertEqual(rc, 0)
        self.assertIn("not a registered event type", err.getvalue())


class MCPWrite(MCPBase):
    def test_agent_api_rejects_invalid_and_unknown(self):
        args = {"type": "goal.progressed", "subject": "goal:a", "payload": {"progress": "lots"}, "idempotency_key": "k1"}
        with self.assertRaisesRegex(agent_api.Refused, r"schema: invalid goal.progressed v1 payload: field 'progress'"):
            agent_api.propose_event(self.tok, args)
        with self.assertRaisesRegex(agent_api.Refused, r"unknown event type 'habit.tracked'"):
            agent_api.propose_event(self.tok, dict(args, type="habit.tracked", payload={"text": "x"}, idempotency_key="k2"))
        ok = agent_api.propose_event(self.tok, dict(args, payload={"progress": 0.3}, idempotency_key="k3"))
        self.assertEqual(ok["status"], "proposed")

    def test_mcp_propose_event_returns_clear_error(self):
        s = self.server(); s.init()
        r = s.call("propose_event", {"type": "event.corrected", "subject": "event:x", "payload": {"new_value": 1},
                                     "idempotency_key": "m1"})
        self.assertTrue(r.get("isError"))
        self.assertIn("missing required field 'field'", r["content"][0]["text"])


class ReadPath(unittest.TestCase):
    def setUp(self):
        fresh(self)

    def _old_event(self):
        """A preference.set written at v1 with the 'old' shape {"val": ...}."""
        return user(self.db, "preference.set", "user:owner", {"val": "dark"}, key="theme")

    def _snap(self):
        return [tuple(r) for r in self.db.execute("SELECT * FROM events ORDER BY seq")]

    def test_chain_applied_on_rebuild_show_export_and_deterministic(self):
        eid = self._old_event()
        before = self._snap()
        with patched("preference.set", V3, DEMO_UPS):
            vault.rebuild(self.db); h1 = vault.projection_hash(self.db)
            vault.rebuild(self.db); h2 = vault.projection_hash(self.db)
            self.assertEqual(h1, h2)
            v = self.db.execute("SELECT value FROM proj_preferences WHERE event_id=?", (eid,)).fetchone()[0]
            self.assertEqual(v, "dark")
            self.assertIn("dark", vault.pack(self.db))
            row = self.db.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
            self.assertEqual(vault.decrypt_payload(self.db, row), {"value": "dark"})
            self.assertEqual(event_detail.safe_payload(row), {"value": "dark"})
            self.assertEqual(vault.get_history(self.db, "user:owner")[0]["payload"], {"value": "dark"})
            self.assertIn("dark", context_export.export_context(self.db))
            self.assertEqual(ops.doctor(self.db)["problems"], [])
        # stored bytes + hashes untouched (append-only), chain still verifies
        self.assertEqual(self._snap(), before)
        self.assertEqual(vault.verify_chains(self.db), [])

    def test_newer_version_tolerated_excluded_and_reported(self):
        ok = user(self.db, "preference.set", "user:owner", {"value": "a"}, key="k1")
        with patched("preference.set", schemas.Spec(9)):          # simulate a newer writer
            fut = user(self.db, "preference.set", "user:owner", {"value_v9": {"x": 1}}, key="k2")
        vault.rebuild(self.db)                                     # back on code that knows only v1
        self.assertEqual(status(self.db, fut), "unknown_version")
        self.assertEqual(status(self.db, ok), "active")
        keys = [r[0] for r in self.db.execute("SELECT key FROM proj_preferences")]
        self.assertEqual(keys, ["k1"])
        rep = ops.doctor(self.db)
        self.assertEqual(rep["checks"]["unknown_version_events"], 1)
        self.assertTrue(any("schema_version newer" in p for p in rep["problems"]))
        row = self.db.execute("SELECT * FROM events WHERE id=?", (fut,)).fetchone()
        self.assertEqual(vault.decrypt_payload(self.db, row), {"value_v9": {"x": 1}})   # no crash, raw payload
        self.assertTrue(vault.is_unknown_version(row))
        vault.pack(self.db)
        self.assertEqual(vault.verify_chains(self.db), [])
        self.db.close(); self.db = vault.connect(self.dbp)        # reopen verifies chains
        self.assertEqual(vault.verify_chains(self.db), [])


if __name__ == "__main__":
    unittest.main()
