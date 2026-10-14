import json, os, shutil, sqlite3, tempfile, unittest
from unittest import mock
from testutil import fresh, status, all_bytes, HAVE_CRYPTO
import vault, importer, ops
os.environ.setdefault("VAULT_OWNER_NAME", "Ada")

LOG = """# Log 2026-10-14
- (04:45, Archive Bot) Vault iskeleti oluşturuldu.
- (05:00, Ada) [tür: tercih] Türkçe yanıt istiyorum. [kaynak: Ada]
- (05:10, Design Bot) [tür: karar] Tasarım yazıldı. [kaynak: Ada, 2026-10-14]
- (05:20, Ada) [tür: fikir] Bahçe projesi için sulama planı.
- (bozuk satır
- (05:30, Ada) [tür: fikir] Bahçe projesi için sulama planı.
"""
DEC = """# Kararlar (ADR)
Format:
```
## D-NNN Başlık
- Tarih / Karar veren:
```

## D-001 Örnek karar
- Tarih / Karar veren: 2026-10-14 / Ada
- Karar: Haftalık plan pazartesi yapılır.
- Durum: aktif

## D-003 Vault MVP
- Tarih / Karar veren: 2026-10-14 / Design Bot / onaylayan: Ada
- Karar: SQLite + olay günlüğü.
- Durum: onaylandı
- Güncelleme 2026-10-14 (Ada): v0.3.1 onaylandı.
"""
TEAM = "| Bot | Sorumluluk |\n|---|---|\n| Archive Bot | x |\n| Design Bot | y |\n"


def make_vault(root):
    os.makedirs(os.path.join(root, "log")); os.makedirs(os.path.join(root, "design")); os.makedirs(os.path.join(root, "bots"))
    open(os.path.join(root, "log", "2026-10-14.md"), "w").write(LOG)
    open(os.path.join(root, "log", "2026-10-13.md"), "wb").write(b"- (01:00, Ada) \xff\xfe bozuk kodlama\n")
    open(os.path.join(root, "decisions.md"), "w").write(DEC)
    open(os.path.join(root, "team.md"), "w").write(TEAM)
    open(os.path.join(root, "design", "x.md"), "w").write("- (05:00, Ada) design should be excluded\n")
    open(os.path.join(root, "bots", "y.md"), "w").write("- (05:00, Ada) bots excluded\n")
    open(os.path.join(root, "user-context.md"), "w").write("- (2026-10-14, Archive Bot) Türkçe tercih ediyor.\n")


class ImportTest(unittest.TestCase):
    def setUp(self):
        fresh(self); self.root = os.path.join(self.d, "vault"); make_vault(self.root)

    def test_dry_run_report(self):
        rep = importer.run(self.db, self.root, dry_run=True)
        codes = {(e["code"], e["file"]) for e in rep["errors"]}
        self.assertIn(("PARSE_ERROR", "log/2026-10-14.md"), codes)
        self.assertIn(("ENCODING_ERROR", "log/2026-10-13.md"), codes)          # bad file skipped, not fatal
        self.assertEqual(self.db.execute("SELECT count(*) FROM events").fetchone()[0], 0)   # dry-run writes nothing
        kl = {k["preview"][:12] for k in rep["owner_lines"]}
        self.assertTrue(any("Türkçe" in k for k in kl)); self.assertTrue(any("Haftalık" in k for k in kl))
        self.assertFalse(any("design" in str(e) or "bots excluded" in str(e) for e in rep["owner_lines"]))
        # D-003 ('Design Bot / onaylayan: Ada') and bot lines quoting [kaynak: Ada] are NOT owner lines
        self.assertFalse(any("SQLite" in k["preview"] for k in rep["owner_lines"]))
        self.assertFalse(any("Tasarım yazıldı" in k["preview"] for k in rep["owner_lines"]))
        self.assertEqual(rep["by_type"].get("preference.set"), 1)

    def test_commit_idempotent_and_line_independent(self):
        r1 = importer.run(self.db, self.root, dry_run=False)
        n = self.db.execute("SELECT count(*) FROM events WHERE import_id=?", (r1["import_id"],)).fetchone()[0]
        self.assertEqual(n, r1["counts"]["new"]); self.assertGreater(n, 5)
        rows = self.db.execute("SELECT e.trust, s.status, e.actor FROM events e JOIN proj_status s ON s.event_id=e.id "
                               "WHERE e.import_id=?", (r1["import_id"],)).fetchall()
        self.assertTrue(all(r[0] == "unverified" and r[1] == "proposed" and r[2] == "import:markdown" for r in rows))
        p = os.path.join(self.root, "log", "2026-10-14.md")
        open(p, "w").write("- (04:00, Archive Bot) yeni üst satır\n" + LOG.replace("\n", "  \r\n"))   # shift lines + CRLF + trailing ws
        r2 = importer.run(self.db, self.root, dry_run=False)
        self.assertEqual(r2["counts"]["new"], 1)                    # only the genuinely new line
        self.assertGreaterEqual(r2["counts"].get("duplicate", 0), n - 1)

    def test_import_approve_confirms_only_listed_owner_lines(self):
        r = importer.run(self.db, self.root, dry_run=False)
        ids = [k["block_id"] for k in r["owner_lines"]]
        with self.assertRaisesRegex(ValueError, "not in the dry-run"):
            importer.approve(self.db, r["import_id"], "deadbeef0000")
        importer.approve(self.db, r["import_id"], ids[0])
        first = next(k["event_id"] for k in r["owner_lines"] if k["block_id"] == ids[0])
        other = [k["event_id"] for k in r["owner_lines"] if k["block_id"] != ids[0]]
        self.assertEqual(status(self.db, first), "active")
        self.assertEqual(self.db.execute("SELECT trust_eff FROM proj_status WHERE event_id=?", (first,)).fetchone()[0], "verified")
        self.assertTrue(all(status(self.db, o) == "proposed" for o in other))
        # events themselves stay unverified; 'verified' is derived
        self.assertEqual(self.db.execute("SELECT trust FROM events WHERE id=?", (first,)).fetchone()[0], "unverified")
        with self.assertRaises(sqlite3.DatabaseError):   # only a human can batch-approve
            vault.append(self.db, "import.batch_approved", "x", {}, "import:markdown", "unverified", target_ids=[first])

    def test_partial_import_rolls_back(self):
        real = vault.append; calls = {"n": 0}
        def flaky(*a, **k):
            calls["n"] += 1
            if calls["n"] == 3:
                raise sqlite3.OperationalError("disk I/O error (injected)")
            return real(*a, **k)
        with mock.patch.object(vault, "append", side_effect=flaky):
            with self.assertRaises(sqlite3.OperationalError):
                importer.run(self.db, self.root, dry_run=False)
        self.assertEqual(self.db.execute("SELECT count(*) FROM events").fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT count(*) FROM import_runs").fetchone()[0], 0)
        self.assertEqual(vault.verify_chains(self.db), [])
        r = importer.run(self.db, self.root, dry_run=False)          # clean retry works
        self.assertGreater(r["counts"]["new"], 5)

    def test_revert_import(self):
        r = importer.run(self.db, self.root, dry_run=False)
        importer.approve(self.db, r["import_id"], "all")
        eid, n = importer.revert_import(self.db, r["import_id"])
        self.assertEqual(n, r["counts"]["new"])
        st = {s for (s,) in self.db.execute("SELECT s.status FROM events e JOIN proj_status s ON s.event_id=e.id WHERE e.import_id=?",
                                            (r["import_id"],))}
        self.assertEqual(st, {"reverted"})
        self.assertNotIn("Türkçe yanıt", vault.pack(self.db, "full"))
        with self.assertRaises(sqlite3.DatabaseError):
            vault.append(self.db, "event.reverted", "x", {}, "agent:bot", "unverified", target_ids=[eid])

    def test_snapshot_before_import(self):
        vault.append(self.db, "note.added", "x", {"text": "önce"}, "user:owner", "verified")
        r = importer.run(self.db, self.root, dry_run=False)
        self.assertTrue(r["snapshot"] and os.path.exists(r["snapshot"]))
        self.assertEqual(oct(os.stat(r["snapshot"]).st_mode & 0o777), "0o600")
        digest = open(r["snapshot"] + ".sha256").read().split()[0]
        self.assertEqual(digest, ops._sha256_file(r["snapshot"]))

    def test_blocklist_refuses_resurrection(self):
        r = importer.run(self.db, self.root, dry_run=False)
        target = self.db.execute("SELECT id FROM events WHERE json_extract(payload,'$.text') LIKE 'Türkçe yanıt%'").fetchone()[0]
        newp = os.path.join(self.d, "red.db")
        rep = ops.redact(self.db, target, newp, "test", take_snapshot=False)
        self.assertTrue(rep["verified_absent"])
        nd = vault.connect(newp)
        r2 = importer.run(nd, self.root, dry_run=True)
        self.assertIn("BLOCKED", {e["code"] for e in r2["errors"]})
        with self.assertRaisesRegex(ValueError, "blocklist"):
            e = self.db.execute("SELECT * FROM events WHERE id=?", (target,)).fetchone()
            vault.append(nd, e["type"], e["subject"], json.loads(e["payload"]), "user:owner", "verified", key=e["key"])
        self.assertNotIn(b"T\xc3\xbcrk\xc3\xa7e yan\xc4\xb1t", all_bytes(newp))


if __name__ == "__main__":
    unittest.main()
