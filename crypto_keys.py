"""Per-subject data keys for crypto-shredding (design §4.3; security review 'Crypto-shredding MVP').

* keys.db: separate SQLite file, mode 0600, journal_mode=DELETE, secure_delete=ON. Never snapshotted with vault.db.
* DEK: AES-256-GCM per subject, wrapped by a KEK (AES-GCM, AAD 'dek|<key_id>'). wrapped_dek NULL = shredded.
* Event ciphertext: AES-GCM, AAD = '<event_id>|<key_id>' -> ciphertext cannot be moved to another event.
* KEK source (placeholder for the OS keychain, which is the target): VAULT_KEK_FILE (0600, 32 raw bytes, auto-created)
  or VAULT_PASSPHRASE -> scrypt(n=2**17, r=8, p=1). Argon2id is preferred but this `cryptography` build (venv) is
  used via scrypt for portability; switch to Argon2id when available (noted in README).
Requires the `cryptography` package (installed in .venv-sdk). Without it, encryption/shredding raise CryptoUnavailable;
nothing silently falls back to plaintext.
"""
import hashlib, json, os, sqlite3, stat, time

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False


class CryptoUnavailable(RuntimeError):
    pass


class Shredded(PermissionError):
    pass


SCHEMA = """
CREATE TABLE IF NOT EXISTS subject_keys(
  key_id TEXT PRIMARY KEY, subject TEXT UNIQUE NOT NULL,
  wrapped_dek BLOB,                       -- NULL = shredded (destroyed)
  kek_id TEXT NOT NULL, created_at TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active','pending_destroy','destroyed')),
  destroy_after REAL, shredded_at TEXT, requested_by TEXT);
"""


def _need():
    if not HAVE_CRYPTO:
        raise CryptoUnavailable("`cryptography` not installed; run with .venv-sdk/bin/python")


def _secure_file(p):
    if os.path.exists(p):
        os.chmod(p, 0o600)


class KeyStore:
    def __init__(self, vault_db_path):
        _need()
        base = os.path.dirname(os.path.abspath(vault_db_path))
        self.path = os.environ.get("VAULT_KEYS_DB", os.path.join(base, "keys.db"))
        self.kek_path = os.environ.get("VAULT_KEK_FILE", os.path.join(base, "keys.kek"))
        self.db = sqlite3.connect(self.path)
        _secure_file(self.path)
        self.db.execute("PRAGMA journal_mode=DELETE"); self.db.execute("PRAGMA secure_delete=ON")
        self.db.executescript(SCHEMA)
        self.kek, self.kek_id = self._kek()

    def _kek(self):
        pw = os.environ.get("VAULT_PASSPHRASE")
        if pw:
            salt_p = self.kek_path + ".salt"
            if not os.path.exists(salt_p):
                fd = os.open(salt_p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.write(fd, os.urandom(16)); os.close(fd)
            salt = open(salt_p, "rb").read()
            return Scrypt(salt=salt, length=32, n=2 ** 17, r=8, p=1).derive(pw.encode()), "kek-scrypt-v1"
        if not os.path.exists(self.kek_path):
            fd = os.open(self.kek_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.write(fd, AESGCM.generate_key(256)); os.close(fd)
        mode = stat.S_IMODE(os.stat(self.kek_path).st_mode)
        if mode & 0o077:
            raise PermissionError(f"KEK file permissions {oct(mode)} too open; require 600")
        return open(self.kek_path, "rb").read(), "kek-file-v1"

    def close(self):
        self.db.close()

    # -- keys
    def dek_for(self, subject, create=True):
        r = self.db.execute("SELECT key_id, wrapped_dek FROM subject_keys WHERE subject=?", (subject,)).fetchone()
        if r:
            if r[1] is None:
                raise Shredded(f"subject shredded (key {r[0]})")
            return r[0], self._unwrap(r[1], r[0])
        if not create:
            raise KeyError(subject)
        kid = "k_" + hashlib.sha256(os.urandom(16)).hexdigest()[:24]
        dek = AESGCM.generate_key(256)
        self.db.execute("INSERT INTO subject_keys(key_id,subject,wrapped_dek,kek_id,created_at) VALUES(?,?,?,?,?)",
                        (kid, subject, self._wrap(dek, kid), self.kek_id, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
        self.db.commit()
        return kid, dek

    def dek_by_id(self, kid):
        r = self.db.execute("SELECT wrapped_dek FROM subject_keys WHERE key_id=?", (kid,)).fetchone()
        if not r:
            raise KeyError(kid)
        if r[0] is None:
            raise Shredded(kid)
        return self._unwrap(r[0], kid)

    def _wrap(self, dek, kid):
        n = os.urandom(12); return n + AESGCM(self.kek).encrypt(n, dek, b"dek|" + kid.encode())

    def _unwrap(self, blob, kid):
        return AESGCM(self.kek).decrypt(blob[:12], blob[12:], b"dek|" + kid.encode())

    # -- payload
    def seal(self, subject, event_id, fields):
        kid, dek = self.dek_for(subject)
        n = os.urandom(12)
        ct = n + AESGCM(dek).encrypt(n, json.dumps(fields, ensure_ascii=False, sort_keys=True).encode(), f"{event_id}|{kid}".encode())
        return kid, ct

    def open(self, kid, event_id, ct):
        dek = self.dek_by_id(kid)
        return json.loads(AESGCM(dek).decrypt(ct[:12], ct[12:], f"{event_id}|{kid}".encode()))

    # -- shredding lifecycle
    def info(self, subject):
        r = self.db.execute("SELECT key_id, state, destroy_after, shredded_at FROM subject_keys WHERE subject=?", (subject,)).fetchone()
        return dict(zip(("key_id", "state", "destroy_after", "shredded_at"), r)) if r else None

    def schedule_destroy(self, subject, grace_days, requested_by):
        i = self.info(subject)
        if not i:
            raise KeyError(f"no key for subject {subject}")
        if i["state"] == "destroyed":
            raise Shredded("already destroyed")
        self.db.execute("UPDATE subject_keys SET state='pending_destroy', destroy_after=?, requested_by=? WHERE subject=?",
                        (time.time() + grace_days * 86400, requested_by, subject)); self.db.commit()
        return self.info(subject)

    def cancel(self, subject):
        i = self.info(subject)
        if not i or i["state"] != "pending_destroy":
            raise ValueError("no pending shred for this subject")
        self.db.execute("UPDATE subject_keys SET state='active', destroy_after=NULL, requested_by=NULL WHERE subject=?", (subject,))
        self.db.commit()

    def finalize(self, subject, now=None):
        i = self.info(subject)
        if not i or i["state"] != "pending_destroy":
            raise ValueError("no pending shred for this subject (run `vault shred <subject> --confirm` first)")
        if (now or time.time()) < i["destroy_after"]:
            raise ValueError("grace period not over yet")
        self.db.execute("UPDATE subject_keys SET wrapped_dek=NULL, state='destroyed', shredded_at=? WHERE subject=?",
                        (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), subject)); self.db.commit()
        self.db.execute("VACUUM")
        return i["key_id"]

    def all_keys(self):
        return [dict(zip(("key_id", "subject", "state", "has_dek"), r)) for r in
                self.db.execute("SELECT key_id, subject, state, wrapped_dek IS NOT NULL FROM subject_keys")]
