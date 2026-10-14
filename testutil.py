import os, sqlite3, tempfile
os.environ.setdefault("VAULT_ALLOW_NONTTY", "1")
import vault

try:
    import crypto_keys
    HAVE_CRYPTO = crypto_keys.HAVE_CRYPTO
except Exception:
    HAVE_CRYPTO = False


def fresh(test):
    d = tempfile.mkdtemp()
    os.environ["VAULT_DB"] = os.path.join(d, "v.db")
    os.environ["VAULT_LOG"] = os.path.join(d, "ops.jsonl")
    for k in ("VAULT_KEYS_DB", "VAULT_KEK_FILE", "VAULT_PASSPHRASE", "VAULT_AGENTS"):
        os.environ.pop(k, None)
    vault._KEYSTORE.clear()
    test.d = d; test.dbp = os.environ["VAULT_DB"]
    test.db = vault.connect(test.dbp)
    test.addCleanup(lambda: test.db.close())
    return test.db


def user(db, t, s, p, **kw):
    return vault.append(db, t, s, p, "user:owner", "verified", **kw)[0]


def agent(db, t, s, p, **kw):
    return vault.append(db, t, s, p, "agent:bot", "unverified", **kw)[0]


def status(db, eid):
    r = db.execute("SELECT status FROM proj_status WHERE event_id=?", (eid,)).fetchone()
    return r[0] if r else None


def all_bytes(path):
    out = b""
    for p in (path, path + "-journal", path + "-wal", path + "-shm"):
        if os.path.exists(p):
            out += open(p, "rb").read()
    return out
