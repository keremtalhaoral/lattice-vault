#!/usr/bin/env python3
"""Create a synthetic demo vault for a fictional user, Ada. All data here is made up.

Usage:  python3 examples/seed.py [OUT_DIR]      (default: ./demo-vault, must not exist)
Then:   VAULT_DB=OUT_DIR/vault.db python3 vault.py pack --profile full
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

out = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "demo-vault")
if os.path.exists(out):
    sys.exit(f"refusing to overwrite existing path: {out}")
os.makedirs(out, mode=0o700)
os.environ["VAULT_DB"] = os.path.join(out, "vault.db")
os.environ["VAULT_AGENTS"] = os.path.join(out, "agents.json")
os.environ["VAULT_LOG"] = os.path.join(out, "vault-ops.jsonl")

import vault, agent_api  # noqa: E402

db = vault.connect(os.environ["VAULT_DB"])
U = ("user:owner", "verified")


def user(t, s, p, **kw):
    return vault.append(db, t, s, p, *U, **kw)[0]


# Preferences, decisions, projects, goals, learnings (all fictional)
lang = user("preference.set", "user:ada", {"value": "English, concise answers"}, key="language")
user("preference.set", "user:ada", {"value": "metric units"}, key="units")
user("decision.made", "decision:D-100", {"decision_id": "D-100", "title": "Use a local-first notes app",
                                          "decision": "Notes stay on Ada's laptop; no cloud sync for now."})
user("decision.made", "decision:D-101", {"decision_id": "D-101", "title": "Weekly review on Sundays",
                                          "decision": "Ada reviews open projects every Sunday evening."})
user("project.created", "project:garden", {"project_id": "garden", "title": "Balcony herb garden", "status": "active"})
user("project.created", "project:bike", {"project_id": "bike", "title": "Restore old bicycle", "status": "paused"})
user("goal.set", "goal:run-5k", {"goal_id": "run-5k", "title": "Run 5 km without stopping", "target": "2026-12-31"})
user("learning.captured", "user:ada", {"text": "Basil needs at least six hours of sun."})

# Correction: Ada changes her language preference (append-only; the old value stays in history)
corr = user("event.corrected", f"event:{lang}", {"field": "value", "new_value": "English, detailed answers",
                                                 "reason": "changed my mind"}, supersedes=lang)

# An AI agent proposes something through the same path the MCP server uses (lands 'proposed'/'unverified')
token = agent_api.add_agent("demo-assistant", rate_limit=100)
db.close()
res = agent_api.propose_event(token, {"type": "learning.captured", "subject": "user:ada",
                                      "payload": {"text": "Ada prefers morning runs.",
                                                  "sources": ["https://example.com/ada-running-log"]},
                                      "idempotency_key": "demo-1"})
db = vault.connect(os.environ["VAULT_DB"]); vault.rebuild(db)
n = db.execute("SELECT count(*) FROM events").fetchone()[0]
print(json.dumps({"vault": out, "events": n, "correction": corr, "agent_proposal": res}, indent=2))
print("The demo agent token was NOT saved. Create your own with `vault agent-add <id>`.", file=sys.stderr)
