import json, os, sqlite3, subprocess, sys, unittest
from testutil import fresh, user, agent, status
import vault

HERE = os.path.dirname(os.path.abspath(__file__))


def pref(db, subject="user:owner", key="dil"):
    return [r[0] for r in db.execute("SELECT value FROM proj_preferences WHERE subject=? AND key=?", (subject, key))]


class CorrectionTest(unittest.TestCase):
    def setUp(self):
        fresh(self)
        self.base = user(self.db, "preference.set", "user:owner", {"key": "dil", "value": "Türkçe"})

    def correct(self, target, value, actor="user:owner"):
        trust = "verified" if actor.startswith("user:") else "unverified"
        return vault.append(self.db, "event.corrected", f"event:{self.base}", {"field": "value", "new_value": value,
                            "reason": "test"}, actor, trust, supersedes=target)[0]

    def test_correction_chain_and_history(self):
        c1 = self.correct(self.base, "İngilizce")
        self.assertEqual(pref(self.db), ["İngilizce"])
        c2 = self.correct(c1, "Almanca")                      # correction of a correction
        self.assertEqual(pref(self.db), ["Almanca"])
        h = vault.get_history(self.db, "user:owner")
        self.assertEqual([x["id"] for x in h], [self.base, c1, c2])
        self.assertEqual(h[1]["supersedes"], [self.base]); self.assertEqual(h[2]["supersedes"], [c1])

    def test_revert_of_correction_restores_original(self):
        c1 = self.correct(self.base, "İngilizce")
        vault.append(self.db, "event.reverted", f"event:{c1}", {"reason": "yanlış"}, "user:owner", "verified", target_ids=[c1])
        self.assertEqual(status(self.db, c1), "reverted")
        self.assertEqual(pref(self.db), ["Türkçe"])
        # after the revert, a new correction may supersede the base again
        self.correct(self.base, "Fransızca")
        self.assertEqual(pref(self.db), ["Fransızca"])

    def test_double_supersede_cycle_self_unknown_rejected(self):
        self.correct(self.base, "İngilizce")
        with self.assertRaisesRegex(ValueError, "double supersede"):
            self.correct(self.base, "Almanca")
        with self.assertRaisesRegex(ValueError, "unknown"):
            self.correct("00000000-0000-7000-8000-000000000000", "x")
        with self.assertRaisesRegex(ValueError, "itself|cycle"):
            vault.validate_parents(self.db, self.base, [self.base])
        with self.assertRaisesRegex(ValueError, "cycle"):
            # an existing ancestor re-declared as superseding its own descendant
            c1 = self.db.execute("SELECT event_id FROM event_parents WHERE parent_id=?", (self.base,)).fetchone()[0]
            vault.validate_parents(self.db, self.base, [c1])
        self.db.rollback()
        with self.assertRaisesRegex(ValueError, "requires supersedes"):
            vault.append(self.db, "event.corrected", "x", {"field": "value", "new_value": 1}, "user:owner", "verified")

    def test_rebuild_deterministic_with_chains(self):
        c1 = self.correct(self.base, "A"); c2 = self.correct(c1, "B")
        vault.append(self.db, "event.reverted", "r", {}, "user:owner", "verified", target_ids=[c2])
        d = user(self.db, "decision.made", "decision:D-9", {"decision_id": "D-9", "title": "t", "decision": "x"})
        user(self.db, "decision.reversed", "decision:D-9", {"decision_id": "D-9"}, supersedes=d)
        h1 = vault.projection_hash(self.db)
        for _ in range(3):
            vault.rebuild(self.db); self.assertEqual(vault.projection_hash(self.db), h1)
        self.assertEqual(pref(self.db), ["A"])
        self.assertEqual(self.db.execute("SELECT count(*) FROM proj_decisions").fetchone()[0], 0)

    def test_agent_correction_is_only_a_proposal(self):
        c = self.correct(self.base, "Esperanto", actor="agent:bot")
        self.assertEqual(status(self.db, c), "proposed"); self.assertEqual(pref(self.db), ["Türkçe"])
        vault.review(self.db, c, "approve")
        self.assertEqual(pref(self.db), ["Esperanto"])
        with self.assertRaises(sqlite3.DatabaseError):
            vault.append(self.db, "event.reverted", "x", {}, "agent:bot", "unverified", target_ids=[c])

    def test_mcp_agent_can_propose_correction_not_revert(self):
        import agent_api
        os.environ["VAULT_AGENTS"] = os.path.join(self.d, "agents.json")
        tok = agent_api.add_agent("bot", rate_limit=100)
        r = agent_api.propose_event(tok, {"type": "event.corrected", "subject": f"event:{self.base}", "supersedes": self.base,
                                          "payload": {"field": "value", "new_value": "Kürtçe"}, "idempotency_key": "c1"})
        self.assertEqual(r["status"], "proposed")
        with self.assertRaisesRegex(agent_api.Refused, "not allowed"):
            agent_api.propose_event(tok, {"type": "event.reverted", "subject": "x", "payload": {}, "idempotency_key": "c2"})
        with self.assertRaisesRegex(agent_api.Refused, "unknown event"):
            agent_api.propose_event(tok, {"type": "event.corrected", "subject": "x", "supersedes": "nope",
                                          "payload": {"field": "value", "new_value": 1}, "idempotency_key": "c3"})

    def test_cli_correct_follows_chain_tip_and_revert(self):
        env = {**os.environ}
        run = lambda *a: subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), *a], capture_output=True, text=True, env=env)
        r = run("correct", self.base, "--field", "value", "--value", "A", "--reason", "x"); self.assertEqual(r.returncode, 0, r.stderr)
        r = run("correct", self.base, "--field", "value", "--value", "B", "--reason", "y"); self.assertEqual(r.returncode, 0, r.stderr)
        c2 = r.stdout.strip()
        r = run("revert", c2, "--reason", "z"); self.assertEqual(r.returncode, 0, r.stderr)
        r = run("history", "user:owner"); h = json.loads(r.stdout)
        self.assertEqual([x["status"] for x in h if x["type"] == "event.corrected"], ["active", "reverted"])
        db = vault.connect(self.dbp); self.assertEqual(pref(db), ["A"]); db.close()

    def test_preference_conflict_flagged_not_lww(self):
        a = agent(self.db, "preference.set", "user:owner", {"key": "dil", "value": "Esperanto"})   # no supersedes
        vault.review(self.db, a, "approve")
        rows = self.db.execute("SELECT value, conflict FROM proj_preferences WHERE key='dil' ORDER BY value").fetchall()
        self.assertEqual([tuple(r) for r in rows], [("Esperanto", 1), ("Türkçe", 1)])
        p = vault.pack(self.db, "full")
        self.assertNotIn("Esperanto", p.split("Kimlik ve tercihler")[1].split("## 2.")[0])
        self.assertIn("ÇAKIŞMA", vault.pack(self.db, "full", include_unverified=True))


if __name__ == "__main__":
    unittest.main()
