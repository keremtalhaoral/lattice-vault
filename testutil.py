import os, shutil, sqlite3, tempfile
# ---- test harness (see SECURITY.md "Test harness") ----
# VAULT_ALLOW_NONTTY is honoured only together with VAULT_TEST_HARNESS=1 and a VAULT_USER_KEY under the temp dir.
_HARNESS = tempfile.mkdtemp(prefix="vault-harness-")
os.environ["VAULT_TEST_HARNESS"] = "1"
os.environ.setdefault("VAULT_ALLOW_NONTTY", "1")
os.environ["VAULT_CONFIG_DIR"] = os.path.join(_HARNESS, "config")       # anchors land here, never in ~/.config
os.environ["VAULT_USER_KEY"] = os.path.join(_HARNESS, "user_ed25519.key")
os.environ.pop("VAULT_ANCHOR_PATH", None); os.environ.pop("VAULT_USER_KEY_PASSPHRASE", None)
import vault, signing
if signing.HAVE_CRYPTO:
    signing.generate_user_key(os.environ["VAULT_USER_KEY"])

_append = vault.append
AUTO_REGISTER = True


def _harness_append(db, type_, subject, payload, actor, trust, *a, **kw):
    """Harness only: the first signed (human-only) append in a test vault registers the harness user key first,
    as `vault keys init-user` would. Vaults that never write human-only events get no extra rows."""
    if (AUTO_REGISTER and signing.HAVE_CRYPTO and type_ in vault.SIGNED_TYPES and type_ not in signing.KEY_TYPES
            and actor.startswith("user:")):
        vault.ensure_sig_schema(db)
        if signing.epoch_seq(db) is None:
            signing.register_user_key(db)
    return _append(db, type_, subject, payload, actor, trust, *a, **kw)


vault.append = _harness_append

try:
    import crypto_keys
    HAVE_CRYPTO = crypto_keys.HAVE_CRYPTO
except Exception:
    HAVE_CRYPTO = False


def fresh(test):
    d = tempfile.mkdtemp()
    test.addCleanup(shutil.rmtree, d, ignore_errors=True)   # registered first -> runs after db.close()
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
