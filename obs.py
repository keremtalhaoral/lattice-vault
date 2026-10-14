"""Structured JSON ops log (never stdout: stdout is the MCP stdio channel). No content, no key material."""
import json, os, time, uuid
from contextlib import contextmanager

ALLOWED = {"ts", "component", "op", "request_id", "import_id", "duration_ms", "result", "error_code", "count"}


def _path():
    p = os.environ.get("VAULT_LOG")
    if p:
        return p
    return os.path.join(os.path.dirname(os.path.abspath(os.environ.get("VAULT_DB", "./vault.db"))), "vault-ops.jsonl")


def log(**fields):
    rec = {k: v for k, v in fields.items() if k in ALLOWED and v is not None}   # allowlist: nothing else can leak
    rec.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    try:
        fd = os.open(_path(), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass  # logging must never break the vault


@contextmanager
def span(component, op, **ids):
    t0 = time.monotonic(); rec = {"component": component, "op": op, "request_id": ids.get("request_id") or uuid.uuid4().hex[:12],
                                  "import_id": ids.get("import_id")}
    state = {"result": "ok", "error_code": None, "count": None}
    try:
        yield state
    except Exception as e:
        state["result"] = "error"; state["error_code"] = state.get("error_code") or type(e).__name__
        raise
    finally:
        log(**rec, **state, duration_ms=round((time.monotonic() - t0) * 1000, 2))
