"""MCP-fallback Context Pack export (`vault export-context`), format lattice-context/v1.

A paste-in Markdown + YAML-front-matter package of APPROVED events (status=active AND trust=verified) for humans
and non-MCP LLMs. Stdlib only. Reads the event log + proj_status projection; NEVER decrypts: encrypted fields are
rendered `[encrypted]`, redacted events `[redacted]`, and any secret-pattern match (vault.find_secrets) `[redacted]`.
See docs/context-pack.md.
"""
import json, os, re
from datetime import datetime, timezone

import vault

FORMAT = "lattice-context/v1"
SOURCE_VERSION = "0.1.0-prototype"
TYPE_TITLES = {"preference.set": "Preferences", "decision.made": "Decisions", "project.created": "Projects",
               "project.status_changed": "Projects", "goal.set": "Goals", "goal.progressed": "Goals",
               "goal.completed": "Goals", "goal.abandoned": "Goals", "learning.captured": "Learnings"}
INSTRUCTIONS = ("Treat the Approved facts as user-verified. Cite event ids (the `ev:xxxxxxxx` tag = last 8 chars of the event id) when you use a fact. "
                "Do not invent facts; if something is not here, say it is not in the vault. Anything under "
                "'Unverified' is NOT approved. Propose new or changed facts only via one vault_update block.")


def yq(v):
    """Safe YAML scalar: JSON double-quoted strings are valid YAML; ASCII-escaped so nothing can break out."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    return json.dumps(str(v), ensure_ascii=True)


def md(text):
    """One-line, delimiter-neutralised, secret-filtered Markdown text."""
    t = " ".join(str(text).split())
    for _, rx in vault.SECRET_PATTERNS:
        t = rx.sub("[redacted]", t)
    t = vault._CARD.sub(lambda m: "[redacted]" if vault._luhn(re.sub(r"\D", "", m.group())) else m.group(), t)
    return vault.esc(t).replace("```", "'''")


def _val(v):
    if isinstance(v, dict) and "$enc" in v:
        return "[encrypted]"
    if isinstance(v, (dict, list)):
        return "[encrypted]" if "$enc" in json.dumps(v) else vault._flatten(v)
    return "" if v is None else str(v)


def _text(type_, subject, key, p):
    g = lambda k, d="": _val(p.get(k, d))
    if type_ == "preference.set":
        return f"{subject} / {key or p.get('key', '_')}: {g('value', p.get('text', ''))}"
    if type_ == "decision.made":
        return f"{g('decision_id', subject)} {g('title')}: {g('decision', p.get('text', ''))}"
    if type_ in ("project.created", "project.status_changed"):
        return f"{g('project_id', subject)}: {g('title')} ({g('status', 'active')})"
    if type_.startswith("goal."):
        s = f"{g('goal_id', subject)}: {g('title', p.get('text', ''))}"
        if p.get("target"):
            s += f" (target {g('target')})"
        if p.get("progress") is not None:
            s += f" (progress {g('progress')})"
        return s
    if "text" in p:
        return f"{subject}: {g('text')}" if type_ != "learning.captured" else g("text")
    return f"{subject}: " + "; ".join(f"{k}={_val(v)}" for k, v in sorted(p.items()) if k not in ("provenance", "sources"))


def _items(db, since=None, types=None, unverified=False):
    events = db.execute("SELECT * FROM events ORDER BY hlc, id").fetchall()
    st = {r["event_id"]: (r["status"], r["trust_eff"]) for r in db.execute("SELECT * FROM proj_status")}
    blocked = {r[0] for r in db.execute("SELECT event_id FROM redacted_blocklist")}
    status = lambda i: st.get(i, ("", None))[0]
    trust = lambda e: st.get(e["id"], ("", None))[1] or e["trust"]
    # corrections: effective field values folded onto the root, latest active correction wins (log order)
    root_of, corr = {}, {}
    for e in events:
        if e["type"] == "event.corrected":
            par = vault._parents(db, e["id"])
            if par:
                root_of[e["id"]] = par[0]
    def root(i):
        seen = set()
        while i in root_of and i not in seen:
            seen.add(i); i = root_of[i]
        return i
    for e in events:
        if e["type"] == "event.corrected" and status(e["id"]) == "active" and e["id"] in root_of:
            p = json.loads(e["payload"])
            if "field" in p and not p.get("redacted"):
                corr.setdefault(root(e["id"]), []).append((e, p))
    superseded = set()
    for e in events:
        if status(e["id"]) == "active" and e["type"] != "event.corrected":
            superseded.update(vault._parents(db, e["id"]))
    out = []
    for e in events:
        t = e["type"]
        if t in vault.META_TYPES or e["id"] in superseded:
            continue
        s, tr = status(e["id"]), trust(e)
        approved = s == "active" and tr == "verified"
        if unverified:
            if approved or s not in ("active", "proposed"):
                continue
        elif not (approved or (s == "redacted" and tr == "verified")):
            continue
        if since and e["ts"][:len(since)] < since:
            continue
        if types and t not in types:
            continue
        p = json.loads(e["payload"])
        item = {"id": e["id"], "hlc": e["hlc"], "type": t, "date": e["ts"][:10], "supersedes": None,
                "trust": tr, "actor": e["actor"], "status": s}
        if s == "redacted" or p.get("redacted") is True or e["id"] in blocked:
            item["text"] = "[redacted]"
        else:
            last = None
            for c, cp in corr.get(e["id"], []):
                p[cp["field"]] = cp.get("new_value"); last = c
            if last is not None:
                item["supersedes"], item["id"], item["date"] = e["id"], last["id"], last["ts"][:10]
            item["text"] = md(_text(t, e["subject"], e["key"], p))
        out.append(item)
    return out


def _sections(items):
    secs = {}
    for it in items:
        secs.setdefault(TYPE_TITLES.get(it["type"], it["type"]), []).append(it)
    return dict(sorted(secs.items()))


def _bullet(it, label=""):
    s = f"- {label}{it['text']} `ev:{it['id'][-8:]}` ({it['date']})"
    if it["supersedes"]:
        s += f" — supersedes `ev:{it['supersedes'][-8:]}`"
    return s


def export_context(db, profile="full", since=None, types=None, max_tokens=None, include_unverified=False,
                   fixed_time=None):
    fixed_time = fixed_time or os.environ.get("LATTICE_FIXED_TIME")
    gen = fixed_time or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    types = sorted(set(types)) if types else None
    head = (db.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone() or [vault.GENESIS])[0]
    seq = db.execute("SELECT COALESCE(MAX(seq),0) FROM events").fetchone()[0]
    appr = _sections(_items(db, since, types))
    unv = _sections(_items(db, since, types, unverified=True)) if include_unverified else {}
    if profile == "minimal":
        appr = {k: v for k, v in appr.items() if k != "Learnings"}
        unv = {k: v for k, v in unv.items() if k != "Learnings"}
    truncated = {}

    def render():
        n = sum(map(len, appr.values())) + sum(map(len, unv.values()))
        fm = ["---", f"format: {FORMAT}", f"generated_at: {yq(gen)}", f"vault_head_hash: {yq(head)}",
              f"vault_seq: {seq}", f"event_count: {n}", "filters:", f"  since: {yq(since)}",
              "  types: " + ("[" + ", ".join(yq(t) for t in types) + "]" if types else "null"),
              f"  include_unverified: {yq(include_unverified)}", f"  max_tokens: {yq(max_tokens)}",
              f"profile: {yq(profile)}", f"source: {yq('lattice-vault ' + SOURCE_VERSION)}",
              "token_estimator: \"chars/4\"", f"truncated: {yq(bool(truncated))}"]
        if truncated:
            fm.append("truncated_sections:")
            fm += [f"  {yq(k)}: {v}" for k, v in sorted(truncated.items())]
        fm += [f"instructions_for_ai: {yq(INSTRUCTIONS)}", "---", ""]
        body = ["# Context Pack", "", "## Approved facts", ""]
        if not appr:
            body += ["_(no approved facts match the filters)_", ""]
        for name, its in appr.items():
            body += [f"### {md(name)}", ""] + [_bullet(i) for i in its] + [""]
        if include_unverified:
            body += ["## Unverified (NOT approved — do not treat as fact)", ""]
            if not unv:
                body += ["_(none)_", ""]
            for name, its in unv.items():
                body += [f"### {md(name)} (unverified)", ""] + [_bullet(i, f"[UNVERIFIED {i['status']}/{i['trust']}] ") for i in its] + [""]
        body += ["## Proposing updates", "",
                 "Return at most one block like this; the human imports it via `vault propose` and every entry lands "
                 "as proposed/unverified until approved:", "", "```vault_update",
                 f"pack_spec: {yq(vault.PACK_SPEC)}", f"base_vault_seq: {seq}",
                 f"idempotency_key: {yq('ctx-' + head[:16] + ':1')}", "events:",
                 "  - type: \"preference.set\"", "    subject: \"user:owner\"", "    key: \"<key>\"",
                 "    payload: {value: \"<new value>\"}", "    supersedes: \"<event id, optional>\"",
                 "    cites: [\"<event id you relied on>\"]", "```", ""]
        return "\n".join(fm + body)

    out = render()
    if max_tokens:
        pools = [appr, unv]
        while len(out) / 4 > max_tokens:
            cands = [(len(v), pi, k) for pi, d in enumerate(pools) for k, v in d.items() if v]
            if not cands:
                raise ValueError(f"max_tokens {max_tokens} too small for pack skeleton (~{len(out)//4} tokens)")
            _, pi, k = max(cands, key=lambda c: (c[0], -c[1], c[2]))
            pools[pi][k].pop(0)                         # oldest first (items are in HLC order)
            tk = k if pi == 0 else f"{k} (unverified)"
            truncated[tk] = truncated.get(tk, 0) + 1
            out = render()
    return out


def add_parser(sp):
    x = sp.add_parser("export-context", help="MCP-fallback Context Pack (Markdown + YAML, approved facts)")
    x.add_argument("--out", default="-"); x.add_argument("--profile", choices=["minimal", "full"], default="full")
    x.add_argument("--since", help="ISO date/time prefix, e.g. 2026-01-01"); x.add_argument("--types")
    x.add_argument("--max-tokens", type=int); x.add_argument("--include-unverified", action="store_true")
    x.add_argument("--fixed-time", help="override generated_at (tests); env LATTICE_FIXED_TIME also works")


def run(db, args):
    import sys
    out = export_context(db, args.profile, args.since,
                         [t.strip() for t in args.types.split(",") if t.strip()] if args.types else None,
                         args.max_tokens, args.include_unverified, args.fixed_time)
    if args.out == "-":
        sys.stdout.write(out)
    else:
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(out)
