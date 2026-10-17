"""Sync key transport PROTOTYPE (roadmap step 1, docs/adr/0013-sync-key-transport.md).

Moves per-subject DEKs (never the KEK, never plaintext DEKs) from one paired device to another in a separate,
versioned `vaultkeys/0.2` bundle next to the `vaultsync/0.2` event packages (ADR 0016).

* Each device has an X25519 key-agreement (KA) key. The private key is stored in keys.db, wrapped by that device's
  KEK (AES-GCM, AAD 'ka|<device_id>'); it never leaves the device and is never printed.
* A device KA certificate binds {device_id, X25519 public key} and is signed by the active user Ed25519 key
  (CERT_DOMAIN). A peer certificate is accepted only for a paired, not locally revoked device and only while the
  signing user key is the active user key registered on THIS vault.
* Per DEK: standard RFC 9180 HPKE, base mode, suite DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM
  (`cryptography.hazmat.primitives.hpke`, present in every supported `cryptography` version). The library API has no
  AAD argument, so the binding (format, bundle id, key id, subject, encrypted event ids, sender and recipient device
  ids, recipient KA fingerprint, signing key id) goes into the HPKE `info` as WRAP_INFO_DOMAIN || SHA-256(binding).
* The whole bundle (including every ciphertext, the sender sequence number and the previous bundle hash) is signed by
  the user key (BUNDLE_DOMAIN). No unsigned field is used. The receiver enforces per-sender monotonic sequence numbers
  (seqstate.py, stream "vaultkeys"): replays, rollbacks and forks are refused.
* vaultkeys/0.1 bundles (hand-built HPKE-style wrap, no sequence numbers) are refused; re-export from the sender.
* The recipient re-wraps each DEK under its own KEK. Shredded or pending-destroy keys are never sent and never
  accepted; a synced, applied `subject.shredded` puts the local copy into pending_destroy with the local grace
  period (apply_remote_shreds), unless its origin is revoked for key transport.
* The sender device id is NOT cryptographically authenticated: every device holding the user key can sign a
  certificate for any device id. Device-level authentication needs per-device signing keys (future work).
* Anything that does not verify is recorded in `sync_key_quarantine` (ids and reasons only, no key material) and
  not imported (fail closed).
"""
import base64, hashlib, json, os, secrets, sys, time
import seqstate, signing, vault

FORMAT = "vaultkeys/0.2"
LEGACY_FORMATS = ("vaultkeys/0.1",)
CERT_V = "lattice-device-ka-cert/v1"
CERT_DOMAIN = b"lattice-device-ka-cert/v1\n"
BUNDLE_DOMAIN = b"lattice-key-bundle-sig/v2\n"
WRAP_INFO_DOMAIN = b"lattice-key-wrap-hpke/v2\n"
MAX_BUNDLE_BYTES = 16 * 1024 * 1024
from shredding import SYSTEM_ACTOR, grace_days as shred_grace_days   # noqa: E402,F401

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hpke, serialization
    HPKE_SUITE = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM)
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False

SCHEMA = """
CREATE TABLE IF NOT EXISTS sync_ka_peers (            -- verified peer KA certificates (public data only)
  device_id TEXT NOT NULL, ka_fp TEXT NOT NULL, cert TEXT NOT NULL CHECK (json_valid(cert)),
  added_by TEXT NOT NULL, at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  PRIMARY KEY (device_id, ka_fp));
CREATE TABLE IF NOT EXISTS sync_ka_revoked (          -- a revoked device never receives or sends keys again
  device_id TEXT PRIMARY KEY, reason TEXT NOT NULL, revoked_by TEXT NOT NULL,
  at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE TABLE IF NOT EXISTS sync_key_quarantine (      -- ids and reasons only; never key material
  id INTEGER PRIMARY KEY AUTOINCREMENT, bundle_sha256 TEXT NOT NULL, sender_device TEXT, key_id TEXT,
  reason TEXT NOT NULL, at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE TABLE IF NOT EXISTS sync_key_imports (
  bundle_sha256 TEXT NOT NULL, key_id TEXT NOT NULL, sender_device TEXT NOT NULL,
  at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), PRIMARY KEY (bundle_sha256, key_id));
CREATE TABLE IF NOT EXISTS sync_shred_handled (       -- synced shreds that were ignored (noted once each)
  event_id TEXT PRIMARY KEY, key_id TEXT, action TEXT NOT NULL,
  at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE TRIGGER IF NOT EXISTS sync_ka_peers_no_update BEFORE UPDATE ON sync_ka_peers BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER IF NOT EXISTS sync_ka_peers_no_delete BEFORE DELETE ON sync_ka_peers BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER IF NOT EXISTS sync_ka_revoked_no_update BEFORE UPDATE ON sync_ka_revoked BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER IF NOT EXISTS sync_ka_revoked_no_delete BEFORE DELETE ON sync_ka_revoked BEGIN SELECT RAISE(ABORT,'append-only'); END;
"""
KS_SCHEMA = """
CREATE TABLE IF NOT EXISTS device_ka (device_id TEXT PRIMARY KEY, pub BLOB NOT NULL, priv_wrapped BLOB NOT NULL,
  kek_id TEXT NOT NULL, created_at TEXT NOT NULL);
"""


class KeyTransportError(ValueError):
    pass


class SeqRefused(KeyTransportError):
    """Signed bundle refused by the per-sender sequence check (replay, rollback, fork)."""


def _need():
    if not HAVE_CRYPTO:
        raise KeyTransportError("key transport needs the `cryptography` package")


def _b64(b):
    return base64.b64encode(b).decode()


def _unb64(s):
    if not isinstance(s, str):
        raise KeyTransportError("expected base64 string")
    try:
        return base64.b64decode(s.encode(), validate=True)
    except Exception:
        raise KeyTransportError("bad base64") from None


def ka_fp(pub):
    return hashlib.sha256(pub).hexdigest()


def ensure_schema(db):
    db.executescript(SCHEMA)


def _paired(db):
    import sync
    return {r[0] for r in db.execute("SELECT replica_id FROM replicas")}


def _revoked(db):
    ensure_schema(db)
    return {r[0] for r in db.execute("SELECT device_id FROM sync_ka_revoked")}


def _keystore(db):
    """Keystore for key transport. A device that so far only holds *imported* ciphertext may create its own KEK:
    it has no local DEK that a fresh KEK could orphan (vault.keystore refuses that case for local data)."""
    import crypto_keys
    try:
        ks = vault.keystore(db, create=True)
    except crypto_keys.KeystoreMissing:
        path = db.execute("PRAGMA database_list").fetchone()[2]
        base = os.path.dirname(os.path.abspath(path))
        if os.path.exists(os.environ.get("VAULT_KEYS_DB", os.path.join(base, "keys.db"))):
            raise
        local_enc = db.execute("SELECT 1 FROM events WHERE enc_key_id IS NOT NULL AND id NOT IN "
                               "(SELECT event_id FROM sync_imported) LIMIT 1").fetchone() \
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='sync_imported'").fetchone() else True
        if local_enc:
            raise
        # The ONE documented case (ADR 0013 §6, review N7) where a KEK is created although encrypted events exist:
        # no keys.db, and every encrypted event came in through sync (no local DEK can be orphaned). Audited.
        ks = vault._KEYSTORE[path] = crypto_keys.KeyStore(path, create=True, has_encrypted_events=False)
        vault.audit(db, vault.HUMAN, "keystore_created_for_key_import", "accepted",
                    "first KEK created on this device for imported ciphertext only")
    ks.db.executescript(KS_SCHEMA)
    return ks


# ---------------------------------------------------------------- device KA key + certificate
def _ka_aad(dev):
    return b"ka|" + dev.encode()


def init_device_key(db):
    """Create this device's X25519 KA key (idempotent). Returns the public key bytes. Private key: KEK-wrapped in keys.db."""
    _need()
    import sync
    dev = sync.device_id(db)
    ks = _keystore(db)
    r = ks.db.execute("SELECT pub FROM device_ka WHERE device_id=?", (dev,)).fetchone()
    if r:
        return r[0]
    priv = X25519PrivateKey.generate()
    raw = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    n = os.urandom(12)
    ks.db.execute("INSERT INTO device_ka(device_id, pub, priv_wrapped, kek_id, created_at) VALUES(?,?,?,?,?)",
                  (dev, pub, n + AESGCM(ks.kek).encrypt(n, raw, _ka_aad(dev)), ks.kek_id,
                   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
    ks.db.commit()
    return pub


def _device_priv(db):
    import sync
    dev = sync.device_id(db, create=False)
    ks = _keystore(db)
    r = ks.db.execute("SELECT pub, priv_wrapped FROM device_ka WHERE device_id=?", (dev,)).fetchone() if dev else None
    if not r:
        raise KeyTransportError("this device has no key-agreement key; run `vault sync-keys init`")
    raw = AESGCM(ks.kek).decrypt(r[1][:12], r[1][12:], _ka_aad(dev))
    return X25519PrivateKey.from_private_bytes(raw), r[0]


def _cert_msg(cert):
    return CERT_DOMAIN + signing.canon(cert).encode()


def make_cert(db):
    """This device's KA certificate, signed by the active user key: {"cert": {...}, "sig": {...}} (public data)."""
    _need()
    import sync
    pub = init_device_key(db)
    priv, kid = signing._current_user_key(db)
    cert = {"v": CERT_V, "device_id": sync.device_id(db), "ka_alg": "x25519", "ka_pub_b64": _b64(pub),
            "user_key_id": kid, "created_at": vault.now()}
    return {"cert": cert, "sig": {"key_id": kid, "alg": "ed25519", "sig": _b64(priv.sign(_cert_msg(cert)))}}


def _active_user_pub(db, kid, keys=None):
    keys = keys if keys is not None else signing.registered_keys(db)[0]
    k = keys.get(kid)
    if not k or k["role"] != "user" or not k["active"] or k["revoked_seq"] is not None:
        return None
    return k["pub"]


def verify_cert(db, c, expect_device=None, keys=None):
    """Return the 32-byte X25519 public key of a valid certificate, else raise KeyTransportError (fail closed)."""
    _need()
    if not isinstance(c, dict) or set(c) != {"cert", "sig"} or not isinstance(c["cert"], dict) or not isinstance(c["sig"], dict):
        raise KeyTransportError("malformed certificate")
    cert, sg = c["cert"], c["sig"]
    if set(cert) != {"v", "device_id", "ka_alg", "ka_pub_b64", "user_key_id", "created_at"} or cert["v"] != CERT_V \
            or cert["ka_alg"] != "x25519":
        raise KeyTransportError("unsupported certificate version or algorithm")
    if sg.get("alg") != "ed25519" or sg.get("key_id") != cert["user_key_id"]:
        raise KeyTransportError("certificate signature key does not match the certified user key")
    pub = _active_user_pub(db, cert["user_key_id"], keys)
    if not pub or not isinstance(sg.get("sig"), str) or not signing._verify(pub, sg["sig"], _cert_msg(cert)):
        raise KeyTransportError("certificate not signed by the active user key of this vault")
    if expect_device is not None and cert["device_id"] != expect_device:
        raise KeyTransportError("certificate is for another device")
    ka = _unb64(cert["ka_pub_b64"])
    if len(ka) != 32:
        raise KeyTransportError("bad X25519 public key")
    return ka


def add_peer(db, c, actor=vault.HUMAN):
    """Store a verified KA certificate of a paired, non-revoked device. Returns (device_id, ka fingerprint)."""
    ensure_schema(db)
    ka = verify_cert(db, c)
    dev = c["cert"]["device_id"]
    if dev not in _paired(db):
        raise KeyTransportError(f"device {dev} is not paired (`vault sync-pair` first)")
    if dev in _revoked(db):
        raise KeyTransportError(f"device {dev} is revoked for key transport")
    fp = ka_fp(ka)
    db.execute("INSERT OR IGNORE INTO sync_ka_peers(device_id, ka_fp, cert, added_by) VALUES(?,?,?,?)",
               (dev, fp, signing.canon(c), actor))
    db.commit()
    vault.audit(db, actor, "sync_keys_add_peer", "accepted", f"KA certificate {fp[:16]} for {dev}")
    return dev, fp


def revoke_peer(db, dev, reason, actor=vault.HUMAN):
    ensure_schema(db)
    db.execute("INSERT OR IGNORE INTO sync_ka_revoked(device_id, reason, revoked_by) VALUES(?,?,?)", (dev, reason, actor))
    db.commit()
    vault.rebuild(db)   # shreds from this device stop applying (vault.shred_applies): projections must follow (L4)
    vault.audit(db, actor, "sync_keys_revoke_peer", "accepted", f"{dev} revoked for key transport")


def _peer_ka(db, dev, keys=None):
    """X25519 public key of a usable peer, else raise. Usable = paired, not revoked, certificate still valid now
    (signed by the CURRENT active user key; certificates die with a rotation and must be re-issued)."""
    ensure_schema(db)
    if dev not in _paired(db):
        raise KeyTransportError(f"device {dev} is not paired")
    if dev in _revoked(db):
        raise KeyTransportError(f"device {dev} is revoked for key transport")
    for (cert,) in db.execute("SELECT cert FROM sync_ka_peers WHERE device_id=? ORDER BY at DESC", (dev,)):
        try:
            return verify_cert(db, json.loads(cert), expect_device=dev, keys=keys)
        except KeyTransportError:
            continue
    raise KeyTransportError(f"no valid key-agreement certificate for {dev} (`vault sync-keys add-peer`)")


# ---------------------------------------------------------------- wrap / unwrap
def _binding(bundle_id, key_id, subject, event_ids, sender, recipient, rfp, signer):
    """HPKE info for one wrapped DEK: a domain plus the SHA-256 of the canonical binding (fixed length)."""
    return WRAP_INFO_DOMAIN + hashlib.sha256(signing.canon({
        "v": FORMAT, "bundle_id": bundle_id, "key_id": key_id, "subject": subject, "event_ids": event_ids,
        "sender_device": sender, "recipient_device": recipient, "recipient_ka_fp": rfp,
        "signer_key_id": signer}).encode()).digest()


def wrap_dek(dek, rcpt_pub, info):
    """RFC 9180 HPKE base mode SealBase: returns enc (32 bytes) || ciphertext."""
    return HPKE_SUITE.encrypt(dek, X25519PublicKey.from_public_bytes(rcpt_pub), info=info)


def unwrap_dek(priv, blob, info):
    return HPKE_SUITE.decrypt(blob, priv, info=info)


# ---------------------------------------------------------------- export
def _bundle_msg(b):
    return BUNDLE_DOMAIN + signing.canon({k: v for k, v in b.items() if k != "signature"}).encode()


def _shredded_ids(db):
    return {json.loads(r[0]).get("key_id") for r in db.execute("SELECT payload FROM events WHERE type='subject.shredded'")}


def export_keys(db, recipient, out_path, subjects=None):
    """Write a signed vaultkeys/0.2 bundle with every live DEK used by an encrypted event in the log, wrapped to
    `recipient`'s certified KA key. Shredded / pending-destroy keys are skipped. Returns a summary (no secrets)."""
    _need()
    import sync
    me = sync.device_id(db)
    priv, signer = signing._current_user_key(db)
    rcpt = _peer_ka(db, recipient)
    my_cert = make_cert(db)
    rfp, bundle_id = ka_fp(rcpt), "kb_" + secrets.token_hex(16)
    ks = _keystore(db)
    shredded = _shredded_ids(db)
    evs = {}
    for eid, kid, subj in db.execute("SELECT id, enc_key_id, subject FROM events WHERE enc_key_id IS NOT NULL ORDER BY id"):
        evs.setdefault(kid, []).append(eid)
    entries, skipped = [], []
    for kid, subj, blob, state in ks.db.execute("SELECT key_id, subject, wrapped_dek, state FROM subject_keys ORDER BY key_id"):
        if kid not in evs or (subjects and subj not in subjects):
            continue
        if blob is None or state != "active" or kid in shredded:
            skipped.append({"key_id": kid, "reason": "shredded or pending destroy"}); continue
        dek = ks.dek_by_id(kid)
        info = _binding(bundle_id, kid, subj, evs[kid], me, recipient, rfp, signer)
        entries.append({"key_id": kid, "subject": subj, "event_ids": evs[kid], "hpke_b64": _b64(wrap_dek(dek, rcpt, info))})
    seq, prev = seqstate.next_send(db, "vaultkeys")
    b = {"format": FORMAT, "bundle_id": bundle_id, "created_at": vault.now(), "sender_device": me, "seq": seq,
         "prev_bundle": prev, "recipient_device": recipient, "recipient_ka_fp": rfp, "sender_cert": my_cert,
         "entries": entries}
    msg = _bundle_msg(b)
    b["signature"] = {"key_id": signer, "alg": "ed25519", "sig": _b64(priv.sign(msg))}
    raw = (vault.canon(b) + "\n").encode()
    tmp = out_path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, out_path)
    seqstate.commit_send(db, "vaultkeys", seq, seqstate.digest(msg)); db.commit()
    vault.audit(db, vault.HUMAN, "sync_keys_export", "accepted", f"{len(entries)} key(s) to {recipient}")
    return {"format": FORMAT, "bundle_id": bundle_id, "seq": seq, "recipient_device": recipient, "keys": len(entries),
            "skipped": skipped, "bundle_sha256": hashlib.sha256(raw).hexdigest()}


# ---------------------------------------------------------------- import
def _q(db, sha, sender, kid, why):
    db.execute("INSERT INTO sync_key_quarantine(bundle_sha256, sender_device, key_id, reason) VALUES(?,?,?,?)",
               (sha, sender, kid, why))


def quarantined(db):
    ensure_schema(db)
    return [dict(r) for r in db.execute("SELECT bundle_sha256, sender_device, key_id, reason, at FROM sync_key_quarantine ORDER BY id")]


def _check_bundle(db, b, me, my_pub, keys):
    """Bundle-level checks. Returns the sender's verified cert pub; raises KeyTransportError (whole bundle refused)."""
    want = {"format", "bundle_id", "created_at", "sender_device", "seq", "prev_bundle", "recipient_device",
            "recipient_ka_fp", "sender_cert", "entries", "signature"}
    if isinstance(b, dict) and b.get("format") in LEGACY_FORMATS:
        raise KeyTransportError(f"legacy bundle format {b['format']!r} is no longer accepted; re-export it from the "
                                f"sending device with this version ({FORMAT})")
    if not isinstance(b, dict) or set(b) != want:
        raise KeyTransportError("malformed bundle")
    if b["format"] != FORMAT:
        raise KeyTransportError(f"unsupported bundle format {b['format']!r}")
    sg = b["signature"]
    if not isinstance(sg, dict) or sg.get("alg") != "ed25519" or not isinstance(sg.get("sig"), str):
        raise KeyTransportError("unsigned or malformed bundle signature")
    pub = _active_user_pub(db, sg.get("key_id"), keys)
    if not pub or not signing._verify(pub, sg["sig"], _bundle_msg(b)):
        raise KeyTransportError("bad bundle signature (not the active user key of this vault)")
    # everything below is covered by the verified signature
    if b["recipient_device"] != me or b["recipient_ka_fp"] != ka_fp(my_pub):
        raise KeyTransportError("bundle is addressed to another device or key-agreement key")
    snd = b["sender_device"]
    if snd == me or snd not in _paired(db):
        raise KeyTransportError(f"sender device {snd} is not paired")
    if snd in _revoked(db):
        raise KeyTransportError(f"sender device {snd} is revoked for key transport")
    verify_cert(db, b["sender_cert"], expect_device=snd, keys=keys)
    if not isinstance(b["entries"], list):
        raise KeyTransportError("malformed entries")
    try:
        return seqstate.check(db, "vaultkeys", snd, b["seq"], seqstate.digest(_bundle_msg(b)), b["prev_bundle"])
    except seqstate.SeqError as x:
        raise SeqRefused(str(x)) from None


def import_keys(db, path, actor=vault.HUMAN):
    """Verify a vaultkeys bundle and re-wrap its DEKs under this device's KEK. Bundle-level failures refuse the whole
    bundle; entry-level failures quarantine that entry. Writes are atomic per database. Returns a report (ids only)."""
    _need()
    import sync
    ensure_schema(db); seqstate.ensure(db)
    if os.path.getsize(path) > MAX_BUNDLE_BYTES:
        raise KeyTransportError("bundle too large")
    raw = open(path, "rb").read()
    sha = hashlib.sha256(raw).hexdigest()
    me = sync.device_id(db)
    try:
        b = json.loads(raw)
    except ValueError:
        b = None
    priv, my_pub = _device_priv(db)
    keys = signing.registered_keys(db)[0]
    try:
        seq_state = _check_bundle(db, b, me, my_pub, keys)
    except KeyTransportError as x:
        snd0 = b.get("sender_device") if isinstance(b, dict) else None
        _q(db, sha, snd0 if isinstance(snd0, str) else None, None, f"bundle refused: {x}")
        if isinstance(x, SeqRefused):
            seqstate.refuse(db, "vaultkeys", snd0, b.get("seq"), seqstate.digest(_bundle_msg(b)), x)
        db.commit()
        vault.audit(db, actor, "sync_keys_import", "refused", f"bundle {sha[:16]} refused")
        raise
    snd, signer, bid = b["sender_device"], b["signature"]["key_id"], b["bundle_id"]
    ks = _keystore(db)
    shredded = _shredded_ids(db)
    local = {r[0]: (r[1], r[2], r[3]) for r in ks.db.execute("SELECT key_id, subject, wrapped_dek, state FROM subject_keys")}
    local_subj = {v[0]: k for k, v in local.items()}
    mh = seqstate.digest(_bundle_msg(b))
    rep = {"bundle_sha256": sha, "sender_device": snd, "seq": b["seq"], "seq_state": seq_state, "imported": [], "duplicate": [], "quarantined": {}}
    plan, seen = [], set()
    for e in b["entries"]:
        kid = e.get("key_id") if isinstance(e, dict) else None
        try:
            if not isinstance(e, dict) or set(e) != {"key_id", "subject", "event_ids", "hpke_b64"} \
                    or not isinstance(kid, str) or not isinstance(e["subject"], str) or not isinstance(e["event_ids"], list) \
                    or not e["event_ids"] or not all(isinstance(i, str) for i in e["event_ids"]):
                raise KeyTransportError("malformed entry")
            if kid in seen:
                raise KeyTransportError("duplicate key id in bundle")
            seen.add(kid)
            if kid in shredded or (kid in local and (local[kid][1] is None or local[kid][2] == "destroyed")):
                raise KeyTransportError("key is shredded on this device")
            for eid in e["event_ids"]:   # the key must belong to events we hold, under the same key id and subject
                r = db.execute("SELECT enc_key_id, subject FROM events WHERE id=?", (eid,)).fetchone()
                if not r or r[0] != kid or r[1] != e["subject"]:
                    raise KeyTransportError("key does not match the encrypted events held here (sync the events first)")
            info = _binding(bid, kid, e["subject"], e["event_ids"], snd, me, ka_fp(my_pub), signer)
            blob = _unb64(e["hpke_b64"])
            if len(blob) != 32 + 32 + 16:
                raise KeyTransportError("malformed wrap")
            try:
                dek = unwrap_dek(priv, blob, info)
            except KeyTransportError:
                raise
            except Exception:
                raise KeyTransportError("wrap does not authenticate") from None
            if len(dek) != 32:
                raise KeyTransportError("bad DEK length")
            ct0 = db.execute("SELECT id, payload_ct FROM events WHERE id=?", (e["event_ids"][0],)).fetchone()
            try:   # the DEK must actually open the event it is sent for
                import crypto_keys
                crypto_keys.open_event(dek, kid, ct0[0], ct0[1])
            except Exception:
                raise KeyTransportError("DEK does not decrypt its event") from None
            if kid in local:
                rep["duplicate"].append(kid); continue
            if e["subject"] in local_subj:
                raise KeyTransportError("subject already has a different key on this device")
            plan.append((kid, e["subject"], dek))
        except KeyTransportError as x:
            rep["quarantined"][kid if isinstance(kid, str) else "?"] = str(x)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:   # keys.db first (one transaction), then vault.db bookkeeping (one transaction)
        for kid, subj, dek in plan:
            ks.db.execute("INSERT INTO subject_keys(key_id,subject,wrapped_dek,kek_id,created_at) VALUES(?,?,?,?,?)",
                          (kid, subj, ks._wrap(dek, kid), ks.kek_id, now))
        ks.db.commit()
    except Exception:
        ks.db.rollback(); raise
    try:
        for kid, why in rep["quarantined"].items():
            _q(db, sha, snd, kid, why)
        for kid, _, _ in plan:
            db.execute("INSERT OR IGNORE INTO sync_key_imports(bundle_sha256, key_id, sender_device) VALUES(?,?,?)", (sha, kid, snd))
        seqstate.record(db, "vaultkeys", snd, b["seq"], mh, b["prev_bundle"])
        db.commit()
    except Exception:
        db.rollback(); raise
    rep["imported"] = [k for k, _, _ in plan]
    if plan:
        import shredding
        shredding.reconcile(db)   # an imported key may already be scheduled for shredding in the log
        vault.rebuild(db)
    vault.audit(db, actor, "sync_keys_import", "accepted" if plan else "duplicate",
                f"{len(plan)} key(s) from {snd}, {len(rep['quarantined'])} quarantined")
    return rep


# ---------------------------------------------------------------- shred propagation
def shred_problems(db):
    """Compatibility wrapper (ADR 0013): shred invariant errors, see shredding.problems."""
    import shredding
    return shredding.problems(db)[0]


def reconcile_shreds(db, now=None):
    """Compatibility wrapper (ADR 0013): see shredding.reconcile (now covers local and synced lifecycle events)."""
    import shredding
    return shredding.reconcile(db, now=now)


def apply_remote_shreds(db):
    """Compatibility wrapper used by sync.py: reconcile and return the key ids newly put into pending_destroy."""
    import shredding
    return shredding.reconcile(db)["pending"]
