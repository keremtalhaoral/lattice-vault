import testutil  # noqa: F401  test harness: harness key, config dir, TTY bypass (SECURITY.md)
import io, os, sqlite3, subprocess, sys, tempfile, unittest
from contextlib import redirect_stdout
import vault, signing

HERE = os.path.dirname(os.path.abspath(__file__))

class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.path = os.path.join(self.tmp, "v.db")
        os.environ["VAULT_DB"] = self.path
        self.db = vault.connect(self.path)
        signing.register_user_key(self.db)   # as `vault keys init-user`; the CLI subprocesses sign with the harness key
    def cli(self, *args):
        r = subprocess.run([sys.executable, os.path.join(HERE, "vault.py"), *args], capture_output=True, text=True,
                           env={**os.environ, "VAULT_DB": self.path})
        return r.returncode, r.stdout, r.stderr
    def user(self, t, s, p, **kw): return vault.append(self.db, t, s, p, "user:owner", "verified", **kw)[0]
    def agent(self, t, s, p, **kw): return vault.append(self.db, t, s, p, "agent:alpha", "unverified", **kw)[0]

class T(Base):
    def test_turkish_search(self):
        self.user("decision.made", "decision:D-003", {"decision_id": "D-003", "title": "Vault", "decision": "Mimari kararı alındı"})
        self.user("learning.captured", "user:owner", {"text": "Işık sabah verimliliği artırıyor"})
        for q in ("karari", "KARARI", "kararı"):
            self.assertEqual(len(vault.search(self.db, q)), 1, q)
        self.assertEqual(len(vault.search(self.db, "ISIK")), 1)
        self.assertEqual(len(vault.search(self.db, "karari", type_="learning.captured")), 0)
        self.assertEqual(len(vault.search(self.db, "isik", subject="user:owner")), 1)

    def test_agent_proposed_hidden_until_approved(self):
        eid = self.agent("preference.set", "user:owner", {"key": "dil", "value": "Esperanto"})
        st = self.db.execute("SELECT status FROM proj_status WHERE event_id=?", (eid,)).fetchone()[0]
        self.assertEqual(st, "proposed")
        self.assertEqual(self.db.execute("SELECT count(*) FROM proj_preferences").fetchone()[0], 0)
        self.assertNotIn("Esperanto", vault.pack(self.db))   # default pack excludes unverified
        p = vault.pack(self.db, include_unverified=True)
        main, unverified = p.split(". Doğrulanmamış\n", 1)[0], p.split("## 6. Doğrulanmamış", 1)[1]
        self.assertNotIn("Esperanto", main); self.assertIn("> - ", unverified); self.assertIn("Esperanto", unverified)
        rc, out, err = self.cli("approve", eid)
        self.assertEqual(rc, 0, err)
        db = vault.connect(self.path)
        self.assertEqual(db.execute("SELECT value FROM proj_preferences").fetchone()[0], "Esperanto")
        p = vault.pack(db)
        self.assertIn("Esperanto", p.split(". Doğrulanmamış\n", 1)[0])
        rc, _, err = self.cli("approve", eid)   # double approve rejected
        self.assertEqual(rc, 1)

    def test_reject_stays_out(self):
        eid = self.agent("goal.set", "goal:g1", {"goal_id": "g1", "title": "Maraton"})
        rc, _, err = self.cli("reject", eid, "--reason", "yanlış"); self.assertEqual(rc, 0, err)
        db = vault.connect(self.path)
        self.assertEqual(db.execute("SELECT count(*) FROM proj_goals").fetchone()[0], 0)
        self.assertNotIn("Maraton", vault.pack(db))
        rc, out, _ = self.cli("pending"); self.assertEqual(out.strip(), "")

    def test_agent_actor_approve_blocked(self):
        eid = self.agent("preference.set", "user:owner", {"key": "k", "value": "v"})
        with self.assertRaisesRegex(sqlite3.DatabaseError, "human actor"):
            vault.append(self.db, "event.approved", f"event:{eid}", {}, "agent:alpha", "unverified", target_id=eid)
        with self.assertRaisesRegex(sqlite3.DatabaseError, "human actor"):
            vault.append(self.db, "event.approved", f"event:{eid}", {}, "agent:alpha", "unverified", target_id=eid, idempotency_key="z")
        with self.assertRaisesRegex(sqlite3.DatabaseError, "unverified"):
            vault.review(self.db, eid, "approve", actor="agent:alpha")
        rc, _, err = self.cli("add", "event.approved", "x", "--text", "hi", "--source", "agent:evil")
        self.assertNotEqual(rc, 0); self.assertIn("human path", err)

    def test_rebuild_deterministic(self):
        self.user("preference.set", "user:owner", {"key": "dil", "value": "Türkçe"})
        self.user("goal.set", "goal:g1", {"goal_id": "g1", "title": "Vault MVP"})
        self.user("goal.progressed", "goal:g1", {"goal_id": "g1", "progress": 0.3})
        e = self.agent("project.created", "project:vault", {"title": "Vault"}); vault.review(self.db, e, "approve")
        h1 = vault.projection_hash(self.db); vault.rebuild(self.db); h2 = vault.projection_hash(self.db)
        rc, out, _ = self.cli("rebuild")
        self.assertEqual(h1, h2); self.assertIn(h1, out)

    def test_update_delete_blocked(self):
        self.user("note.added", "x", {"text": "a"})
        with self.assertRaisesRegex(sqlite3.DatabaseError, "UPDATE forbidden"):
            self.db.execute("UPDATE events SET payload='{}'")
        with self.assertRaisesRegex(sqlite3.DatabaseError, "DELETE forbidden"):
            self.db.execute("DELETE FROM events")

    def test_idempotency(self):
        a, d1 = vault.append(self.db, "note.added", "x", {"text": "a"}, "agent:c", "unverified", idempotency_key="k1")
        b, d2 = vault.append(self.db, "note.added", "x", {"text": "a"}, "agent:c", "unverified", idempotency_key="k1")
        self.assertEqual(a, b); self.assertFalse(d1); self.assertTrue(d2)
        self.assertEqual(self.db.execute("SELECT count(*) FROM events WHERE type<>'key.registered'").fetchone()[0], 1)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO events(id,replica_id,replica_seq,hlc,ts,type,subject,payload,actor,trust,idempotency_key,content_hash,prev_hash,hash) "
                            "VALUES('z','local',99,'99','t','note.added','x','{}','agent:c','unverified','k1','c','p','h')")

    def test_pack_size_cap(self):
        for i in range(200):
            self.user("learning.captured", "user:owner", {"text": f"Öğrenim numarası {i} " + "x" * 50})
        for cap in (1500, 3000, 6000):
            p = vault.pack(self.db, "full", cap)
            self.assertLessEqual(len(p), cap)
            self.assertIn(f"chars: {len(p)}", p)
            self.assertIn('"Öğrenimler"', p.split("---")[1])
            self.assertIn("```vault_update", p)
        self.assertLessEqual(len(vault.pack(self.db, "minimal")), 2000)

if __name__ == "__main__":
    unittest.main(verbosity=2)


class VaultUserTest(unittest.TestCase):
    def test_vault_user_sets_human_actor(self):
        import subprocess, sys, tempfile
        d = tempfile.mkdtemp(); env = dict(os.environ, VAULT_DB=os.path.join(d, "v.db"), VAULT_USER="ada")
        self.addCleanup(__import__("shutil").rmtree, d, True)
        here = os.path.dirname(os.path.abspath(__file__))
        subprocess.run([sys.executable, os.path.join(here, "vault.py"), "init"], check=True, capture_output=True, env=env)
        r = subprocess.run([sys.executable, os.path.join(here, "vault.py"), "add", "note.added", "x", "--text", "hi"],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        db = vault.connect(env["VAULT_DB"])
        self.assertEqual(db.execute("SELECT actor FROM events").fetchone()[0], "user:ada")
