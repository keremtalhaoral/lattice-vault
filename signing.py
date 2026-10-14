"""Ed25519 user signatures for human-only events, and the external chain-head anchor.

See SECURITY.md ("Signed approvals", "External anchor") and docs/adr/0011-signing-keys.md.

* The user private key lives OUTSIDE the vault DB in a 0600 file (VAULT_USER_KEY, default
  <config dir>/user_ed25519.key). An OS-keychain backend is planned (VAULT_USER_KEY_BACKEND=keychain is a stub).
* Public keys are registered in the `user_keys` table (append-only triggers) plus an audit row (hash-chained).
* Signatures live in `event_sigs` (append-only) and cover a canonical encoding of the event (see sig_message).
* After each append/audit commit the chain heads are written, signed, to an anchor file outside the DB.
"""
import base64, hashlib, json, os, stat, sys, tempfile, time

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    HAVE_CRYPTO = False

SIG_DOMAIN = b"lattice-event-sig/v1\n"
ANCHOR_DOMAIN = b"lattice-anchor-sig/v1\n"
PKG_DOMAIN = b"lattice-pkg-sig/v1\n"          # reserved for .vaultsync package signatures (not implemented)
ATTEST_TYPE = "attestation.recorded"          # 'attestation' alone fails the events.type CHECK ('<a>.<b>')
KEY_TYPES = ("key.registered", "key.rotated", "key.revoked")
RECOVERY_DOMAIN = b"lattice-recovery-seed/v1\n"
KEY_ROLES = ("user", "recovery", "device")

# Set by agent-facing processes (MCP server, `vault propose`): never load the user private key there.
USER_KEY_DISABLED = False


class SignatureError(RuntimeError):
    """Missing/invalid user key or signature."""


def _need():
    if not HAVE_CRYPTO:
        raise SignatureError("signed approvals need the `cryptography` package (pip install -r requirements.txt)")


def b64(b):
    return base64.b64encode(b).decode()


def unb64(s):
    return base64.b64decode(s.encode(), validate=True)


def _nofloat(o):
    if isinstance(o, float):
        raise SignatureError("floats are not allowed in signed canonical JSON")
    if isinstance(o, dict):
        for v in o.values(): _nofloat(v)
    elif isinstance(o, list):
        for v in o: _nofloat(v)


def canon(obj):
    """Signature canonical form: sorted keys, (',',':'), ensure_ascii=False, floats rejected."""
    _nofloat(obj)
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def config_dir():
    if os.environ.get("VAULT_CONFIG_DIR"):
        return os.environ["VAULT_CONFIG_DIR"]
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "lattice-vault")


def key_path():
    return os.environ.get("VAULT_USER_KEY") or os.path.join(config_dir(), "user_ed25519.key")


def fingerprint(pub):
    return hashlib.sha256(pub).hexdigest()


def key_id_for(pub_raw, role="user"):
    """key_id namespace: '<role>/ed25519/<first 16 hex of sha256(raw public key)>', role 'user' or 'device'."""
    return f"{role}/ed25519/{fingerprint(pub_raw)[:16]}"


def pub_raw(priv):
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _backend():
    b = os.environ.get("VAULT_USER_KEY_BACKEND", "file")
    if b == "keychain":
        raise SignatureError("VAULT_USER_KEY_BACKEND=keychain is planned, not implemented; use the 0600 key file")
    if b != "file":
        raise SignatureError(f"unknown VAULT_USER_KEY_BACKEND {b!r}")


def generate_user_key(path=None):
    """Create a new Ed25519 key in a new 0600 file (O_EXCL: never overwrites). Returns (path, key_id)."""
    _need(); _backend()
    path = path or key_path()
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, mode=0o700, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    pw = os.environ.get("VAULT_USER_KEY_PASSPHRASE")
    enc = serialization.BestAvailableEncryption(pw.encode()) if pw else serialization.NoEncryption()
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem); f.flush(); os.fsync(f.fileno())
    _CACHE.pop(os.path.abspath(path), None)
    return path, key_id_for(pub_raw(priv))


_CACHE = {}


def load_user_key(path=None):
    """Load the private key. The file must be a regular file owned by us with no group/other permission bits."""
    _need(); _backend()
    if USER_KEY_DISABLED:
        raise SignatureError("user key is not available in agent-facing processes")
    path = os.path.abspath(path or key_path())
    if path in _CACHE:
        return _CACHE[path]
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise SignatureError(f"no user signing key at {path}; run `vault keys init-user`") from None
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise SignatureError(f"{path} must be a regular file owned by you with mode 0600")
    with open(path, "rb") as f:
        pw = os.environ.get("VAULT_USER_KEY_PASSPHRASE")
        try:
            priv = serialization.load_pem_private_key(f.read(), password=pw.encode() if pw else None)
        except (TypeError, ValueError) as e:
            raise SignatureError(f"cannot load {path}: {e}") from None
    if not isinstance(priv, Ed25519PrivateKey):
        raise SignatureError(f"{path} is not an Ed25519 key")
    _CACHE[path] = (priv, key_id_for(pub_raw(priv)))
    return _CACHE[path]


def try_user_key():
    try:
        return load_user_key()
    except SignatureError:
        return None


def _verify(pub_b64, sig_b64, msg):
    try:
        Ed25519PublicKey.from_public_bytes(unb64(pub_b64)).verify(unb64(sig_b64), msg)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ---------- key registry (events: key.registered / key.rotated / key.revoked) ----------
def _sig_rows(db, where="", args=()):
    return db.execute("SELECT e.*, s.key_id AS skid, s.sig AS ssig, s.alg AS salg FROM events e "
                      f"LEFT JOIN event_sigs s ON s.event_id=e.id {where}", args)


def _parents_all(db, eid):
    return sorted({r[0] for r in db.execute("SELECT parent_id FROM event_parents WHERE event_id=?", (eid,))})


def payload_hash(row):
    ct = row["payload_ct"]
    if ct:
        return hashlib.sha256(ct).hexdigest()
    return hashlib.sha256(canon(json.loads(row["payload"])).encode()).hexdigest()


def sig_message(row, parents, key_id):
    """Contract agreed with Data Systems (docs/adr/0011). origin_device = the events.replica_id column ('local' for
    events written here; sync rewrites it to the origin device id on import, see ADR open items). hlc = events.hlc."""
    body = {"id": row["id"], "type": row["type"], "subject": row["subject"], "payload_hash": payload_hash(row),
            "actor": row["actor"], "parents": sorted(parents), "hlc": row["hlc"], "origin_device": row["replica_id"],
            "key_id": key_id}
    return SIG_DOMAIN + canon(body).encode()


def registered_keys(db):
    """Replay key events in log order. Returns ({key_id: info}, problems).
    info = {pub, role, seq, certified_by, active, revoked_hlc, revoked_seq, revoked_by}. Rules (docs/adr/0012):
    * at most ONE active user key. The first user key is self-signed (TOFU, fingerprint confirmed on the TTY).
      A further user key is only *pending* when registered by the active user key, and becomes active through a
      dual-signed key.rotated, which atomically revokes the old key; or it is registered by the live recovery key
      (recover), which atomically revokes every user key and the recovery key itself.
    * a recovery key is registered by the active user key only while no recovery key is live (replacing one needs the
      old recovery key's self-revocation, i.e. the old code).
    * key.revoked: the active user key may revoke device keys it certified (and its predecessor); a recovery key may
      revoke only itself. Any revocation also revokes, transitively, every live key certified by the revoked key.
    * a revoked key's signature is valid only on events with seq < revoked_seq AND hlc < revoked_hlc (or on the
      revoking event itself), see _sig_valid."""
    import vault
    vault.ensure_sig_schema(db)
    keys, problems = {}, []

    def revoke(kid, r, hlc, keep=()):
        k = keys[kid]
        if k["revoked_seq"] is None:
            k.update(revoked_hlc=hlc, revoked_seq=r["seq"], revoked_by=r["id"], active=False)
        for c, ck in keys.items():
            if ck["certified_by"] == kid and c != kid and c not in keep and ck["revoked_seq"] is None:
                revoke(c, r, hlc, keep)

    def active_user():
        return next((kid for kid, k in keys.items() if k["role"] == "user" and k["active"]), None)

    for r in _sig_rows(db, f"WHERE e.type IN ({','.join('?' * len(KEY_TYPES))}) ORDER BY e.seq", KEY_TYPES):
        p = json.loads(r["payload"])
        signer = r["skid"]
        sk = keys.get(signer)

        def ok(k):
            return bool(HAVE_CRYPTO and r["ssig"] and k and _sig_valid(k, r)
                        and _verify(k["pub"], r["ssig"], sig_message(r, _parents_all(db, r["id"]), signer)))
        if r["type"] == "key.registered":
            kid, pub, role = p.get("key_id"), p.get("pubkey_b64", ""), p.get("role", "user")
            try:
                good_id = key_id_for(unb64(pub), role) == kid
            except Exception:
                good_id = False
            if not good_id or p.get("alg") != "ed25519" or role not in KEY_ROLES or kid in keys:
                problems.append(f"key.registered at seq {r['seq']} is malformed or a duplicate"); continue
            info = {"pub": pub, "role": role, "seq": r["seq"], "certified_by": p.get("certified_by"), "active": True,
                    "revoked_hlc": None, "revoked_seq": None, "revoked_by": None, "device_id": p.get("device_id")}
            if signer != p.get("certified_by"):
                problems.append(f"key.registered at seq {r['seq']}: signer is not the certifier"); continue
            if not keys and role == "user":
                if signer != kid or not (HAVE_CRYPTO and r["ssig"] and _verify(pub, r["ssig"], sig_message(
                        r, _parents_all(db, r["id"]), signer))):
                    problems.append(f"key.registered for {kid} at seq {r['seq']} has an invalid self-signature"); continue
                keys[kid] = info; continue
            if not ok(sk):
                problems.append(f"key.registered for {kid} at seq {r['seq']} has an invalid signature/certification"); continue
            if role == "user" and sk["role"] == "user" and signer == active_user():
                info["active"] = False                     # pending until a dual-signed key.rotated
                keys[kid] = info
            elif role == "user" and sk["role"] == "recovery" and sk["active"]:
                keys[kid] = info                           # recover: atomic takeover by the recovery key
                for u, uk in list(keys.items()):
                    if uk["role"] == "user" and u != kid and uk["revoked_seq"] is None:
                        revoke(u, r, r["hlc"], keep=(kid,))
                revoke(signer, r, r["hlc"], keep=(kid,))
            elif role == "recovery" and signer == active_user() and not any(
                    k["role"] == "recovery" and k["revoked_seq"] is None for k in keys.values()):
                keys[kid] = info
            elif role == "device" and signer == active_user():
                keys[kid] = info
            else:
                problems.append(f"key.registered for {kid} ({role}) at seq {r['seq']} is not allowed by the key rules")
        elif r["type"] == "key.rotated":
            old, new = keys.get(p.get("old_key_id")), keys.get(p.get("new_key_id"))
            if not (old and new and signer == p.get("old_key_id") and signer == active_user() and ok(old)
                    and new["role"] == "user" and not new["active"] and new["revoked_seq"] is None
                    and new["certified_by"] == signer and p.get("new_key_sig")
                    and _verify(new["pub"], p["new_key_sig"], rotation_message(p["old_key_id"], p["new_key_id"]))):
                problems.append(f"key.rotated at seq {r['seq']} is not valid (dual signature / pending new key)"); continue
            new["active"] = True
            revoke(p["old_key_id"], r, r["hlc"], keep=(p["new_key_id"],))
        elif r["type"] == "key.revoked":
            tk = keys.get(p.get("key_id"))
            allowed = tk and tk["revoked_seq"] is None and ok(sk) and (
                (sk["role"] == "recovery" and p["key_id"] == signer) or
                (sk["role"] == "user" and signer == active_user() and tk["role"] == "device" and tk["certified_by"] == signer))
            if not allowed:
                problems.append(f"key.revoked at seq {r['seq']} is not allowed or has an invalid signature"); continue
            revoke(p["key_id"], r, min(p.get("effective_hlc") or r["hlc"], r["hlc"]))
    return keys, problems


def _sig_valid(k, row):
    """May key `k` have signed event `row`? Active keys: yes. Pending keys: never. Revoked keys: only before the
    revocation in BOTH log position and HLC (HLC alone is chosen by the signer), or on the revoking event itself."""
    if k["revoked_seq"] is None:
        return k["active"]
    if row["id"] == k["revoked_by"]:
        return True
    return row["seq"] < k["revoked_seq"] and row["hlc"] < k["revoked_hlc"]


def rotation_message(old_kid, new_kid):
    return SIG_DOMAIN + canon({"rotate": {"old_key_id": old_kid, "new_key_id": new_kid}}).encode()


def epoch_seq(db):
    """Seq of the first key.registered event. Human-only events before it are legacy. None = signing not enabled."""
    import vault
    vault.ensure_sig_schema(db)
    r = db.execute("SELECT MIN(seq) FROM events WHERE type='key.registered'").fetchone()
    return r[0] if r else None


def local_key_registered(db, kid):
    return db.execute("SELECT 1 FROM events WHERE type='key.registered' AND json_extract(payload,'$.key_id')=?", (kid,)).fetchone()


def register_user_key(db, actor=None, confirm=None):
    """Register the local user key with a self-signed key.registered event (first key only). `confirm(fingerprint)`
    must return True (the CLI shows the fingerprint on the TTY). Returns (key_id, created)."""
    import vault
    priv, kid = load_user_key()
    vault.ensure_sig_schema(db)
    if local_key_registered(db, kid):
        return kid, False
    if db.execute("SELECT 1 FROM events WHERE type='key.registered'").fetchone():
        raise SignatureError("a different user key is already registered in this vault; rotation (key.rotated, signed by "
                             "both keys) has no CLI yet (docs/adr/0011-signing-keys.md)")
    pub = pub_raw(priv)
    if confirm is not None and not confirm(fingerprint(pub)):
        raise SignatureError("fingerprint not confirmed; nothing registered")
    eid, _ = vault.append(db, "key.registered", f"key:{kid}", {"key_id": kid, "alg": "ed25519", "pubkey_b64": b64(pub),
                          "role": "user", "certified_by": kid}, actor or vault.HUMAN, "verified")
    vault.audit(db, actor or vault.HUMAN, "key_register", "accepted", f"user key {kid} registered", eid)
    return kid, True


# (priv, key_id) override used only inside rotate_user_key / recover_with_code; never set from the environment.
_SIGNER = None


def sign_row(db, row, parents):
    """Sign a new event row with the local user key. The key must be registered (or this is its own key.registered)."""
    priv, kid = _SIGNER or load_user_key()
    if row["type"] == "key.registered":
        p = json.loads(row["payload"])
        if p.get("certified_by") != kid:
            raise SignatureError("key.registered must be signed by its certifying key (the local user key)")
    if row["type"] == "key.registered" and p.get("key_id") == kid:
        pass                                  # self-signed first registration (register_user_key)
    elif not local_key_registered(db, kid):
        raise SignatureError(f"user key {kid} is not registered in this vault; run `vault keys init-user`")
    else:
        k = registered_keys(db)[0].get(kid)
        if not k or k["revoked_seq"] is not None or not k["active"]:
            raise SignatureError(f"key {kid} is revoked, pending or invalid in this vault (after `vault keys rotate`, point "
                                 "VAULT_USER_KEY at the new key file)")
        if k["role"] != "user" and row["type"] not in ("key.registered", "key.revoked"):
            raise SignatureError(f"{k['role']} key {kid} may only sign key.registered / key.revoked")
    return kid, b64(priv.sign(sig_message(row, parents, kid)))


def _attested(db, keys):
    out = set()
    for r in _sig_rows(db, "WHERE e.type=?", (ATTEST_TYPE,)):
        k = keys.get(r["skid"])
        if k and r["ssig"] and _verify(k["pub"], r["ssig"], sig_message(r, _parents_all(db, r["id"]), r["skid"])):
            out.update(json.loads(r["payload"]).get("target_event_ids", []))
    return out


def classify(db, ranges=None, keys=None):
    """{event_id: (seq, status)} for signed-type events; status in signed | bad-signature | unknown-key |
    revoked-key | legacy-unsigned | legacy-attested | remote-unsigned | unsigned."""
    import vault
    if keys is None:
        keys, _ = registered_keys(db)
    ep = epoch_seq(db)
    w = f"WHERE e.type IN ({','.join('?' * len(vault.SIGNED_TYPES))})"
    if ranges is None:
        it = _sig_rows(db, w + " ORDER BY e.seq", vault.SIGNED_TYPES)
    else:
        it = (r for lo, hi in ranges for r in _sig_rows(db, w + " AND e.seq BETWEEN ? AND ? ORDER BY e.seq",
                                                         (*vault.SIGNED_TYPES, lo, hi)))
    has_sync = db.execute("SELECT 1 FROM sqlite_master WHERE name='sync_imported'").fetchone()
    att, out = None, {}
    for r in it:
        if r["skid"] is not None:
            k = keys.get(r["skid"])
            if r["type"] == "key.registered" and r["skid"] == json.loads(r["payload"]).get("key_id") and r["skid"] in keys:
                k = keys[r["skid"]]
            if not k:
                st = "unknown-key"
            elif not HAVE_CRYPTO:
                st = "signed"
            elif not _verify(k["pub"], r["ssig"], sig_message(r, _parents_all(db, r["id"]), r["skid"])):
                st = "bad-signature"
            elif not _sig_valid(k, r):
                st = "revoked-key" if k["revoked_seq"] is not None else "unknown-key"   # pending keys never sign
            elif k["role"] != "user" and r["type"] not in ("key.registered", "key.revoked"):
                st = "wrong-role-key"
            else:
                st = "signed"
        elif ep is None or r["seq"] < ep:
            if att is None:
                att = _attested(db, keys)
            st = "legacy-attested" if r["id"] in att else "legacy-unsigned"
        elif r["replica_id"] != "local" and has_sync and db.execute(
                "SELECT 1 FROM sync_imported WHERE event_id=?", (r["id"],)).fetchone():
            st = "remote-unsigned"
        else:
            st = "unsigned"
        out[r["id"]] = (r["seq"], st)
    return out


BAD = ("bad-signature", "unknown-key", "revoked-key", "wrong-role-key", "unsigned")


def unsigned_after_epoch(db):
    """Cheap whole-log SQL check: signed-type events after the epoch with no signature (sync imports excepted)."""
    import vault
    ep = epoch_seq(db)
    if ep is None:
        return []
    has_sync = db.execute("SELECT 1 FROM sqlite_master WHERE name='sync_imported'").fetchone()
    rows = db.execute(f"""SELECT e.seq, e.id, e.replica_id FROM events e LEFT JOIN event_sigs s ON s.event_id=e.id
        WHERE s.event_id IS NULL AND e.seq >= ? AND e.type IN ({','.join('?' * len(vault.SIGNED_TYPES))})""",
                      (ep, *vault.SIGNED_TYPES)).fetchall()
    return [r["seq"] for r in rows if not (r["replica_id"] != "local" and has_sync and db.execute(
        "SELECT 1 FROM sync_imported WHERE event_id=?", (r["id"],)).fetchone())]


def registry_problems(db):
    keys, problems = registered_keys(db)
    n_audit = db.execute("SELECT count(*) FROM audit WHERE action='key_register'").fetchone()[0]
    if n_audit and not keys:
        problems.append("audit records a user key registration but no valid key.registered event exists")
    return keys, problems


def summarize(cls):
    out = {}
    for _, st in cls.values():
        out[st] = out.get(st, 0) + 1
    return out


def sign_legacy(db, confirm, actor=None, chunk=200):
    """Re-attest legacy-unsigned human-only events with NEW signed attestation.recorded events (old rows untouched).
    `confirm([(seq, id, type)]) -> bool` asks the human (CLI: TTY only). Returns the new event ids."""
    import vault
    legacy = sorted((seq, eid) for eid, (seq, st) in classify(db).items() if st == "legacy-unsigned")
    if not legacy:
        return []
    info = [(s_, e, db.execute("SELECT type FROM events WHERE id=?", (e,)).fetchone()[0]) for s_, e in legacy]
    if not confirm(info):
        return []
    out = []
    for i in range(0, len(legacy), chunk):
        part = [e for _, e in legacy[i:i + chunk]]
        eid, _ = vault.append(db, ATTEST_TYPE, "attestation:legacy",
                              {"target_event_ids": part,
                               "statement": "I re-attest these previously unsigned human-only events as mine."},
                              actor or vault.HUMAN, "verified")
        vault.audit(db, actor or vault.HUMAN, "sign_legacy", "accepted", f"re-attested {len(part)} legacy event(s)", eid)
        out.append(eid)
    return out


# ---------- rotation, revocation, offline recovery code (docs/adr/0012-key-lifecycle.md) ----------
def _append_signed(db, signer, type_, subject, payload, actor):
    """Append one key.* event signed by `signer` (priv, key_id) instead of the VAULT_USER_KEY file."""
    import vault
    global _SIGNER
    prev, _SIGNER = _SIGNER, signer
    try:
        return vault.append(db, type_, subject, payload, actor, "verified")[0]
    finally:
        _SIGNER = prev


def _priv_kid(priv, role="user"):
    return priv, key_id_for(pub_raw(priv), role)


def _register(db, signer, priv, role, actor):
    kid = key_id_for(pub_raw(priv), role)
    _append_signed(db, signer, "key.registered", f"key:{kid}", {"key_id": kid, "alg": "ed25519", "role": role,
                   "pubkey_b64": b64(pub_raw(priv)), "certified_by": signer[1]}, actor)
    return kid


def _revoke(db, signer, kid, reason, actor):
    import vault
    eff = vault.next_hlc(db, "local")   # signatures by `kid` from now on are invalid; earlier ones stay valid
    return _append_signed(db, signer, "key.revoked", f"key:{kid}", {"key_id": kid, "effective_hlc": eff,
                          "reason": reason, "compromised": False}, actor)


def _current_user_key(db):
    priv, kid = load_user_key()
    k = registered_keys(db)[0].get(kid)
    if not k or k["role"] != "user" or not k["active"]:
        raise SignatureError(f"local key {kid} is not the active user key of this vault")
    return priv, kid


def rotate_user_key(db, new_path, actor=None):
    """key.registered(new, pending, certified by old) + key.rotated (signed by old, new_key_sig by new). The rotation
    activates the new key and revokes the old one plus every key it certified (e.g. the recovery key: create a new
    recovery code afterwards). The new key is written to `new_path` (O_EXCL). Returns (old_kid, new_kid)."""
    import vault
    actor = actor or vault.HUMAN
    old = _current_user_key(db)
    if os.path.abspath(new_path) == os.path.abspath(key_path()):
        raise SignatureError("--new-key must be a new path, not the current VAULT_USER_KEY")
    generate_user_key(new_path)
    new = load_user_key(new_path)
    _register(db, old, new[0], "user", actor)
    _append_signed(db, old, "key.rotated", f"key:{new[1]}", {"old_key_id": old[1], "new_key_id": new[1],
                   "new_key_sig": b64(new[0].sign(rotation_message(old[1], new[1])))}, actor)
    vault.audit(db, actor, "key_rotate", "accepted", f"user key {old[1]} rotated to {new[1]}")
    write_anchor(db, key=new)
    return old[1], new[1]


def revoke_key(db, kid, reason, actor=None):
    """Revoke a device key certified by the active user key. Not retroactive. (Recovery keys are replaced with the old
    code via new_recovery_code; the user key itself is replaced via rotate.)"""
    import vault
    actor = actor or vault.HUMAN
    me = _current_user_key(db)
    keys = registered_keys(db)[0]
    if kid == me[1]:
        raise SignatureError("refusing to revoke the local key itself; use `vault keys rotate`")
    if kid not in keys or keys[kid]["revoked_seq"] is not None:
        raise SignatureError(f"{kid} is not a registered, unrevoked key")
    if keys[kid]["role"] != "device" or keys[kid]["certified_by"] != me[1]:
        raise SignatureError("the user key may only revoke device keys it certified; replace a recovery code with "
                             "`vault keys recovery-code --replace` (needs the old code) or `vault keys rotate`")
    eid = _revoke(db, me, kid, reason, actor)
    vault.audit(db, actor, "key_revoke", "accepted", f"key {kid} revoked", eid)
    return eid


def _recovery_priv(code):
    norm = "".join(ch for ch in code.upper() if ch.isalnum())
    try:
        raw = base64.b32decode(norm)
    except Exception:
        raise SignatureError("malformed recovery code") from None
    if len(raw) != 20:
        raise SignatureError("malformed recovery code")
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(RECOVERY_DOMAIN + raw).digest())


def new_recovery_code(db, actor=None, old_code=None):
    """Register a one-time offline recovery key (role 'recovery', certified by the active user key). Returns the code
    (160 random bits, base32, shown ONCE; only the public key is stored). If a recovery key is live, `old_code` is
    required: the old recovery key revokes itself, so a stolen user key alone cannot replace the owner's code."""
    import vault
    _need()
    actor = actor or vault.HUMAN
    me = _current_user_key(db)
    live = [kid for kid, k in registered_keys(db)[0].items() if k["role"] == "recovery" and k["revoked_seq"] is None]
    if live:
        if not old_code:
            raise SignatureError("a recovery code already exists; replacing it needs the old code (--replace), or "
                                 "rotate the user key first (rotation revokes the old recovery key)")
        rec = _priv_kid(_recovery_priv(old_code), "recovery")
        if rec[1] not in live:
            raise SignatureError("old recovery code does not match the live recovery key")
        _revoke(db, rec, rec[1], "replaced by a new recovery code", actor)
    raw = os.urandom(20)
    code = base64.b32encode(raw).decode()
    code = "-".join(code[i:i + 4] for i in range(0, len(code), 4))
    kid = _register(db, me, _recovery_priv(code), "recovery", actor)
    vault.audit(db, actor, "key_recovery_code", "accepted", f"recovery key {kid} registered")
    write_anchor(db)
    return code, kid


def recover_with_code(db, code, new_path, actor=None):
    """Lost user key: the recovery key registers a NEW user key (written to new_path). That single event atomically
    revokes every other user key, the keys they certified, and the recovery key itself (one-time)."""
    import vault
    _need()
    actor = actor or vault.HUMAN
    rec = _priv_kid(_recovery_priv(code), "recovery")
    k = registered_keys(db)[0].get(rec[1])
    if not k or k["role"] != "recovery" or k["revoked_seq"] is not None:
        raise SignatureError("recovery code does not match a registered, unused recovery key")
    generate_user_key(new_path)
    new = load_user_key(new_path)
    _register(db, rec, new[0], "user", actor)
    vault.audit(db, actor, "key_recover", "accepted", f"recovered: new user key {new[1]}")
    write_anchor(db, key=new)
    return new[1]


# ---------- external anchor ----------
def anchor_path(db_path):
    db_path = os.path.abspath(db_path)
    env_db = os.environ.get("VAULT_DB")
    if os.environ.get("VAULT_ANCHOR_PATH") and env_db and os.path.abspath(env_db) == db_path:
        return os.environ["VAULT_ANCHOR_PATH"]
    return os.path.join(config_dir(), "anchors", hashlib.sha256(db_path.encode()).hexdigest()[:16] + ".anchor.json")


def anchor_paths(db_path):
    """Primary anchor plus the optional, user-chosen second location VAULT_ANCHOR_PATH2 (same VAULT_DB rule)."""
    out = [anchor_path(db_path)]
    env_db = os.environ.get("VAULT_DB")
    p2 = os.environ.get("VAULT_ANCHOR_PATH2")
    if p2 and env_db and os.path.abspath(env_db) == os.path.abspath(db_path) and os.path.abspath(p2) != os.path.abspath(out[0]):
        out.append(p2)
    return out


def _heads(db):
    e = db.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
    a = db.execute("SELECT id, hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    return {"seq": e[0], "hash": e[1]} if e else {"seq": 0, "hash": None}, {"id": a[0], "hash": a[1]} if a else {"id": 0, "hash": None}


def _db_path(db):
    return db.execute("PRAGMA database_list").fetchone()[2]


def write_anchor(db, key=None):
    """Write the signed chain heads atomically (0600) next to the config dir. Silently skipped when the user key is not
    available in this process (e.g. the MCP server) or not registered in this vault. Returns the path or None."""
    p = _db_path(db)
    if not p or not HAVE_CRYPTO:
        return None
    k = key or try_user_key()
    if not k:
        return None
    priv, kid = k
    try:
        rk = registered_keys(db)[0].get(kid)
        if not rk or rk["role"] != "user" or not rk["active"]:
            return None    # unregistered, revoked (rotated away) or non-user key: never anchors
    except Exception:
        return None
    ev, au = _heads(db)
    body = {"v": 1, "db": os.path.abspath(p), "events": ev, "audit": au, "key_id": kid,
            "written_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    body["sig"] = b64(priv.sign(ANCHOR_DOMAIN + canon(body).encode()))
    paths = anchor_paths(p)
    for path in paths:
        _write_atomic(path, body)
    return paths[0]


def _write_atomic(path, body):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".anchor.", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(body, sort_keys=True)); f.flush(); os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        try:
            dfd = os.open(d, os.O_RDONLY); os.fsync(dfd); os.close(dfd)
        except OSError:
            pass
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def remove_anchor(db_path):
    """Human-approved reset (restore of an older backup is an intentional rollback)."""
    for p in anchor_paths(db_path):
        if os.path.exists(p):
            os.remove(p)


def check_anchor(db, keys=None):
    """Returns (errors, warnings)."""
    p = _db_path(db)
    if not p:
        return [], []
    if keys is None:
        keys, _ = registered_keys(db)
    errors, warnings = [], []
    for i, path in enumerate(anchor_paths(p)):
        e, w = _check_one_anchor(db, p, path, keys)
        if i and w and not e and os.path.exists(anchor_paths(p)[0]):
            w = [f"VAULT_ANCHOR_PATH2 is set but {path} is missing (it will be written on the next commit)"]
        errors += e; warnings += w
    return errors, warnings


def _check_one_anchor(db, p, path, keys):
    if not os.path.exists(path):
        return [], [f"no external anchor at {path} (first open, or the anchor was deleted); truncation/rollback "
                    "cannot be detected until one is written"]
    try:
        with open(path) as f:
            a = json.load(f)
        sig = a.pop("sig")
    except (OSError, ValueError, KeyError) as e:
        return [f"anchor {path} unreadable ({type(e).__name__})"], []
    k = keys.get(a.get("key_id"))
    pub = None
    local = try_user_key() if not USER_KEY_DISABLED else None
    if local and local[1] == a.get("key_id"):
        pub = b64(pub_raw(local[0]))
    elif k:
        pub = k["pub"]
    errors = []
    if not pub:
        return [f"anchor signed by key {a.get('key_id')} which is not registered in this vault"], []
    if HAVE_CRYPTO and not _verify(pub, sig, ANCHOR_DOMAIN + canon(a).encode()):
        return ["anchor signature invalid"], []
    if k and (k["role"] != "user" or not k["active"]):
        return [f"anchor {path} is signed by a revoked or non-user key {a.get('key_id')}"], []
    if a.get("db") != os.path.abspath(p):
        errors.append(f"anchor belongs to {a.get('db')}, not this vault")
    for table, key, h in (("events", "seq", a.get("events", {})), ("audit", "id", a.get("audit", {}))):
        n = h.get(key) or 0
        if not n:
            continue
        mx = db.execute(f"SELECT COALESCE(MAX({key}),0) FROM {table}").fetchone()[0]
        if mx < n:
            errors.append(f"{table} is behind the external anchor ({key} {mx} < {n}): truncation or rollback")
            continue
        r = db.execute(f"SELECT hash FROM {table} WHERE {key}=?", (n,)).fetchone()
        if not r or r[0] != h.get("hash"):
            errors.append(f"{table} hash at {key} {n} does not match the external anchor")
    return errors, []
