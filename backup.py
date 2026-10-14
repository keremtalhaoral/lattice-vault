"""Backup / restore drill (docs/backup-restore.md).

`vault backup --out DIR`: consistent online copy of vault.db ONLY (never keys.db) via the sqlite3 backup API,
plus manifest.json. `vault backup-keys --out DIR2`: separate copy of keys.db (still KEK-wrapped) with its own
manifest; refused inside/around a vault backup dir so the two are stored apart. `vault restore DIR --to PATH [--keys DIR2] [--force]`: verify manifest hashes,
PRAGMA integrity_check, triggers and full hash chains on a staged copy, atomically rename into place, re-apply
shreds recorded in the restored log, rebuild projections.

The KEK is never part of a vault or keys backup. `vault backup-kek --out DIR3` makes an explicit, separate KEK
backup (keys.kek, or only the salt in VAULT_PASSPHRASE mode); `restore --kek DIR3` installs it. With --keys,
restore trial-decrypts with the target KEK and refuses on mismatch.
"""
import json, os, shutil, sqlite3, tempfile
from datetime import datetime, timezone
import vault, obs
from ops import _sha256_file

FORMAT = "lattice-backup/v1"
TOOL_VERSION = "0.1.0-prototype"
KEYS_FORMAT = "lattice-keys-backup/v1"
KEK_FORMAT = "lattice-kek-backup/v1"
KEK_WARNING = ("this KEK backup unlocks every keys backup. Store it apart from BOTH vault and keys backups "
               "(different medium / password manager / offline), never next to keys.db.")
KEYS_WARNING = ("this keys backup contains keys.db: any subject shredded AFTER this backup stays decryptable from it. "
                "Store it apart from vault backups and delete old key backups after a shred.")


class BackupError(ValueError):
    pass


def _sqlite_copy(src_path, dst_path):
    src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True)
    src.execute("PRAGMA busy_timeout=5000")
    fd = os.open(dst_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.close(fd)
    dst = sqlite3.connect(dst_path)
    try:
        src.backup(dst)            # online, page-consistent snapshot; holds a read lock per step
        dst.execute("PRAGMA journal_mode=DELETE")
    finally:
        dst.close(); src.close()
    os.chmod(dst_path, 0o600)


def integrity(conn):
    return {"integrity_check": [r[0] for r in conn.execute("PRAGMA integrity_check")],
            "quick_check": [r[0] for r in conn.execute("PRAGMA quick_check")]}


def _ok(res):
    return res["integrity_check"] == ["ok"] and res["quick_check"] == ["ok"]


def _manifest_format(d):
    p = os.path.join(d, "manifest.json")
    try:
        with open(p) as f:
            return json.load(f).get("format")
    except (OSError, ValueError, AttributeError):
        return None


def _near_backup(out_dir, fmt):
    """Return a dir holding a `fmt` manifest that equals, contains or is inside out_dir, else None."""
    out = os.path.realpath(out_dir)
    d = out
    while True:                                   # out_dir itself and its ancestors
        if _manifest_format(d) == fmt:
            return d
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    if os.path.isdir(out):                        # descendants
        for root, _dirs, files in os.walk(out):
            if "manifest.json" in files and _manifest_format(root) == fmt:
                return root
    return None


def _prepare_out(out_dir, other_fmt, what):
    near = None
    for fmt in (other_fmt if isinstance(other_fmt, tuple) else (other_fmt,)):
        near = near or _near_backup(out_dir, fmt)
    if near:
        raise BackupError(f"{what} output {out_dir} overlaps backup dir {near}; keep vault and key backups in separate locations")
    if os.path.exists(out_dir) and os.listdir(out_dir):
        raise FileExistsError(f"{out_dir} exists and is not empty")
    os.makedirs(out_dir, mode=0o700, exist_ok=True); os.chmod(out_dir, 0o700)


def _write_manifest(out_dir, man):
    fd = os.open(os.path.join(out_dir, "manifest.json"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(man, f, indent=2, sort_keys=True); f.write("\n")


def backup_keys(db, out_dir):
    """Copy keys.db only (KEK-wrapped) + manifest with key ids. Human-only CLI: `vault backup-keys`."""
    _prepare_out(out_dir, (FORMAT, KEK_FORMAT), "backup-keys")
    with obs.span("ops", "backup_keys"):
        ks = vault.keystore(db); ks.db.commit()      # keystore's own path (honours VAULT_KEYS_DB)
        kp = os.path.join(out_dir, "keys.db")
        _sqlite_copy(ks.path, kp)
        c = sqlite3.connect(kp)
        keys = [{"key_id": r[0], "state": r[1], "has_dek": bool(r[2])}
                for r in c.execute("SELECT key_id, state, wrapped_dek IS NOT NULL FROM subject_keys ORDER BY key_id")]
        c.close()
        man = {"format": KEYS_FORMAT, "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "tool_version": TOOL_VERSION, "kek_included": False, "keys": keys,
               "files": {"keys.db": {"sha256": _sha256_file(kp)}}}
        _write_manifest(out_dir, man)
        vault.audit(db, vault.HUMAN, "backup_keys", "accepted", f"keys backup written ({len(keys)} keys)")
    return {"out": out_dir, "manifest": man, "warning": KEYS_WARNING}


def verify_keys(keys_dir):
    mp = os.path.join(keys_dir, "manifest.json")
    if _manifest_format(keys_dir) != KEYS_FORMAT:
        raise BackupError(f"{keys_dir}: not a keys backup (manifest format must be {KEYS_FORMAT})")
    with open(mp) as f:
        man = json.load(f)
    if set(man.get("files", {})) != {"keys.db"}:
        raise BackupError("keys manifest must list exactly keys.db")
    p = os.path.join(keys_dir, "keys.db")
    if not os.path.exists(p) or _sha256_file(p) != man["files"]["keys.db"]["sha256"]:
        raise BackupError("keys.db: missing or sha256 mismatch (tampered or corrupt)")
    c = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    try:
        ids = sorted(r[0] for r in c.execute("SELECT key_id FROM subject_keys"))
    finally:
        c.close()
    if ids != sorted(k["key_id"] for k in man.get("keys", [])):
        raise BackupError("keys.db key ids differ from its manifest")
    return man


def backup_kek(db, out_dir):
    """Explicit, separate KEK backup (`vault backup-kek --out DIR3`, human-only). File mode: copies keys.kek.
    Passphrase mode: copies only the scrypt salt (the passphrase itself is never written anywhere).
    Refused if DIR3 equals, is inside or contains a vault or keys backup."""
    import crypto_keys
    _prepare_out(out_dir, (FORMAT, KEYS_FORMAT), "backup-kek")
    with obs.span("ops", "backup_kek"):
        ks = vault.keystore(db)
        src = crypto_keys.kek_paths(ks.kek_path)
        name = "keys.kek.salt" if src.endswith(".salt") else "keys.kek"
        dst = os.path.join(out_dir, name)
        fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with open(src, "rb") as f, os.fdopen(fd, "wb") as o:
            o.write(f.read())
        man = {"format": KEK_FORMAT, "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "tool_version": TOOL_VERSION, "kek_id": ks.kek_id, "passphrase_included": False,
               "files": {name: {"sha256": _sha256_file(dst)}}}
        _write_manifest(out_dir, man)
        vault.audit(db, vault.HUMAN, "backup_kek", "accepted", f"KEK backup written ({ks.kek_id})")
    return {"out": out_dir, "manifest": man, "warning": KEK_WARNING}


def verify_kek(kek_dir):
    if _manifest_format(kek_dir) != KEK_FORMAT:
        raise BackupError(f"{kek_dir}: not a KEK backup (manifest format must be {KEK_FORMAT})")
    with open(os.path.join(kek_dir, "manifest.json")) as f:
        man = json.load(f)
    files = man.get("files", {})
    if len(files) != 1 or next(iter(files)) not in ("keys.kek", "keys.kek.salt"):
        raise BackupError("KEK manifest must list exactly keys.kek or keys.kek.salt")
    name = next(iter(files))
    p = os.path.join(kek_dir, name)
    if not os.path.exists(p) or _sha256_file(p) != files[name]["sha256"]:
        raise BackupError(f"{name}: missing or sha256 mismatch (tampered or corrupt)")
    return man, name


def backup(db, out_dir, include_keys=False):
    if include_keys:
        raise BackupError("vault backups never include keys.db; use `vault backup-keys --out DIR2` (separate location)")
    src = os.path.abspath(db.execute("PRAGMA database_list").fetchone()[2])
    _prepare_out(out_dir, (KEYS_FORMAT, KEK_FORMAT), "backup")
    with obs.span("ops", "backup"):
        db.commit()
        vpath = os.path.join(out_dir, "vault.db")
        _sqlite_copy(src, vpath)
        files = {"vault.db": _sha256_file(vpath)}
        c = sqlite3.connect(vpath)
        n = c.execute("SELECT count(*) FROM events").fetchone()[0]
        head = (c.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone() or [vault.GENESIS])[0]
        ahead = (c.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone() or [vault.GENESIS])[0]
        schema = c.execute("SELECT v FROM schema_meta WHERE k='schema_version'").fetchone()[0]
        c.close()
        man = {"format": FORMAT, "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "tool_version": TOOL_VERSION, "schema_version": schema, "event_count": n, "chain_head": head,
               "audit_head": ahead, "includes_keys": False, "kek_included": False,
               "files": {k: {"sha256": v} for k, v in files.items()}}
        _write_manifest(out_dir, man)
        vault.audit(db, vault.HUMAN, "backup", "accepted", f"backup written ({n} events, no keys)")
    return {"out": out_dir, "manifest": man, "warning": None}


def verify(backup_dir):
    """Verify manifest + files. Returns (manifest, report). Raises BackupError on any mismatch."""
    mp = os.path.join(backup_dir, "manifest.json")
    if not os.path.exists(mp):
        raise BackupError("manifest.json missing")
    with open(mp) as f:
        man = json.load(f)
    if man.get("format") != FORMAT:
        raise BackupError(f"unknown backup format {man.get('format')!r}")
    if man.get("schema_version") != vault.SCHEMA_VERSION:
        raise BackupError(f"schema {man.get('schema_version')} != {vault.SCHEMA_VERSION}; restore with a matching version, then migrate")
    if "vault.db" not in man.get("files", {}):
        raise BackupError("manifest lists no vault.db")
    for name, meta in man["files"].items():
        if name != "vault.db":
            raise BackupError(f"unexpected file in manifest: {name}")
        p = os.path.join(backup_dir, name)
        if not os.path.exists(p):
            raise BackupError(f"{name} missing")
        if _sha256_file(p) != meta["sha256"]:
            raise BackupError(f"{name}: sha256 mismatch (tampered or corrupt)")
    return man


def _check_copy(path, man):
    try:
        return _check_copy_inner(path, man)
    except sqlite3.Error as e:
        # never echo sqlite's message: it can quote stored row text (e.g. "Could not decode ... with text '...'")
        raise BackupError(f"vault.db is corrupt or unreadable ({type(e).__name__}); backup rejected") from None


def _check_copy_inner(path, man):
    c = sqlite3.connect(path); c.row_factory = sqlite3.Row
    try:
        integ = integrity(c)
        if not _ok(integ):
            raise BackupError(f"integrity_check failed: {integ['integrity_check'][:3]}")
        problems = vault.check_triggers(c) + vault.verify_chains(c)
        if problems:
            raise BackupError("; ".join(problems))
        n = c.execute("SELECT count(*) FROM events").fetchone()[0]
        head = (c.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone() or [vault.GENESIS])[0]
        if n != man["event_count"] or head != man["chain_head"]:
            raise BackupError("event count / chain head differ from manifest")
        return integ
    finally:
        c.close()


def _kek_path(tdir):
    return os.environ.get("VAULT_KEK_FILE", os.path.join(tdir, "keys.kek"))


def _kek_available(tdir):
    if os.environ.get("VAULT_PASSPHRASE"):
        return os.path.exists(_kek_path(tdir) + ".salt")
    return os.path.exists(_kek_path(tdir))


class _NoKeyStore:
    """Stand-in keystore for a keyless restore: every encrypted field is undecryptable, and no keys.db / KEK
    is created next to the restored vault."""
    def open(self, *a):
        raise KeyError("no keys restored")

    def close(self):
        pass


def restore(backup_dir, to_path, force=False, allow_missing_keys=False, keys_dir=None, allow_no_keys=False, kek_dir=None):
    """allow_missing_keys: --keys given but some referenced key ids are absent -> restore anyway (listed).
    allow_no_keys: no --keys although the log has encrypted events -> restore anyway; those fields stay
    'undecryptable' and no keys.db / KEK is created. kek_dir: KEK backup from `vault backup-kek`, installed
    next to the target when no KEK is reachable there. With --keys the KEK is always trial-verified."""
    import crypto_keys
    man = verify(backup_dir)
    if keys_dir is not None:
        verify_keys(keys_dir)
    kek_src = None
    if kek_dir is not None:
        if keys_dir is None:
            raise BackupError("--kek needs --keys (a KEK alone decrypts nothing)")
        _kman, kname = verify_kek(kek_dir)
        if (kname == "keys.kek.salt") != bool(os.environ.get("VAULT_PASSPHRASE")):
            raise BackupError("KEK backup mode does not match this environment (salt backups need VAULT_PASSPHRASE; "
                              "keys.kek backups must be used without it)")
        kek_src = os.path.join(kek_dir, kname)
    to_path = os.path.abspath(to_path)
    tdir = os.path.dirname(to_path)
    keys_target = os.path.join(tdir, "keys.db")
    has_keys = keys_dir is not None
    if not force:
        for p in [to_path] + ([keys_target] if has_keys else []):
            if os.path.exists(p):
                raise FileExistsError(f"{p} exists; pass --force to overwrite")
    kek_install = None
    if kek_src is not None:
        kek_install = crypto_keys.kek_paths(_kek_path(tdir))
        if os.path.exists(kek_install):
            if open(kek_install, "rb").read() != open(kek_src, "rb").read():
                raise BackupError(f"a different KEK already exists at {kek_install}; move it away first "
                                  "(it is never overwritten, not even with --force)")
            kek_install = None
    if has_keys and kek_install is None and not _kek_available(tdir):
        raise BackupError("--keys given but no KEK is reachable for the target (copy the original keys.kek next "
                          "to it, or set VAULT_KEK_FILE / VAULT_PASSPHRASE); refusing so a fresh KEK is not auto-created")
    os.makedirs(tdir, mode=0o700, exist_ok=True)
    stage = tempfile.mkdtemp(prefix=".restore-", dir=tdir)       # same filesystem -> os.replace is atomic
    try:
        sv = os.path.join(stage, "vault.db")
        shutil.copyfile(os.path.join(backup_dir, "vault.db"), sv); os.chmod(sv, 0o600)
        if _sha256_file(sv) != man["files"]["vault.db"]["sha256"]:
            raise BackupError("vault.db changed while staging")
        integ = _check_copy(sv, man)
        sk = None
        if has_keys:
            sk = os.path.join(stage, "keys.db")
            shutil.copyfile(os.path.join(keys_dir, "keys.db"), sk); os.chmod(sk, 0o600)
            kc = sqlite3.connect(sk)
            ki = integrity(kc); kc.close()
            if not _ok(ki):
                raise BackupError("keys.db integrity_check failed")
            # trial-decrypt: the KEK must unwrap every live DEK, and one event per key must open (drill finding 1)
            kek_file = kek_src if kek_src is not None else _kek_path(tdir)
            try:
                kek, _ = crypto_keys.read_kek(kek_file[:-5] if kek_file.endswith(".salt") else kek_file)
            except (OSError, ValueError) as e:
                raise BackupError(f"KEK for the target cannot be read ({type(e).__name__}: {e})") from None
            kc = sqlite3.connect(sk); vc = sqlite3.connect(sv)
            try:
                trial = crypto_keys.trial_decrypt(kc, vc, kek, 1)
            finally:
                kc.close(); vc.close()
            if trial["bad_keys"] or trial["bad_events"]:
                raise BackupError(f"KEK does not match the keys backup: {len(trial['bad_keys'])} of {trial['keys_checked']} key(s) "
                                  f"cannot be unwrapped, {len(trial['bad_events'])} sampled event(s) fail to decrypt. "
                                  "Use the keys.kek / VAULT_PASSPHRASE that was in use when the keys backup was taken.")
        # re-apply shreds recorded in the restored log (key ids from subject.shredded events)
        c = sqlite3.connect(sv)
        shredded = [json.loads(r[0]).get("key_id") for r in c.execute("SELECT payload FROM events WHERE type='subject.shredded'")]
        c.close()
        c = sqlite3.connect(sv)
        enc_ids = {r[0] for r in c.execute("SELECT DISTINCT enc_key_id FROM events WHERE enc_key_id IS NOT NULL")}
        c.close()
        missing = []
        live_enc = enc_ids - set(shredded)
        if not has_keys and live_enc and not allow_no_keys:
            raise BackupError(f"backup has encrypted events ({len(live_enc)} unshredded key id(s)) but no --keys was given; restoring "
                              "would leave them undecryptable. Pass --keys KEYS_DIR, or --allow-no-keys to restore without "
                              "them on purpose")
        if sk:
            kc = sqlite3.connect(sk)
            have = {r[0] for r in kc.execute("SELECT key_id FROM subject_keys")}
            kc.close()
            missing = sorted(enc_ids - have - set(shredded))
            if missing and not allow_missing_keys:
                raise BackupError(f"keys.db does not match the vault: {len(missing)} key id(s) referenced by encrypted events "
                                  f"are missing ({', '.join(missing[:5])}); pass --allow-missing-keys to restore anyway")
        reapplied = 0
        if sk:
            kc = sqlite3.connect(sk); kc.execute("PRAGMA secure_delete=ON")
            for kid in filter(None, shredded):
                reapplied += kc.execute("""UPDATE subject_keys SET wrapped_dek=NULL, state='destroyed',
                    shredded_at=COALESCE(shredded_at, strftime('%Y-%m-%dT%H:%M:%SZ','now')) WHERE key_id=? AND wrapped_dek IS NOT NULL""",
                                        (kid,)).rowcount
            kc.commit()
            if reapplied:
                kc.execute("VACUUM")
            kc.close()
        for p in (to_path + "-journal", to_path + "-wal", to_path + "-shm"):
            if os.path.exists(p):
                os.remove(p)
        if kek_install is not None:
            fd = os.open(kek_install, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with open(kek_src, "rb") as f, os.fdopen(fd, "wb") as o:
                o.write(f.read())
        if sk:
            os.replace(sk, keys_target)
        os.replace(sv, to_path)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    vault._KEYSTORE.pop(to_path, None)
    if not has_keys:
        vault._KEYSTORE[to_path] = _NoKeyStore()   # never auto-create keys.db / a fresh KEK on a keyless restore
    try:
        db = vault.connect(to_path)          # verifies triggers + chains again
    except BaseException:
        vault._KEYSTORE.pop(to_path, None); raise
    try:
        vault.rebuild(db)
        vault.audit(db, vault.HUMAN, "restore", "accepted", f"restored from backup {man['created_at']} ({man['event_count']} events)")
        ph = vault.projection_hash(db)
    finally:
        db.close()
        if not has_keys:
            vault._KEYSTORE.pop(to_path, None)
    warnings = []
    if missing:
        warnings.append(f"MISSING KEYS: {len(missing)} key id(s) absent from keys.db; those fields are unreadable")
    if not has_keys and live_enc:
        warnings.append("restored without --keys (--allow-no-keys): encrypted fields are undecryptable until a keys "
                        "backup and its KEK are restored")
    return {"restored": to_path, "keys_restored": has_keys, "event_count": man["event_count"], "chain_head": man["chain_head"],
            "integrity_check": integ["integrity_check"][0], "quick_check": integ["quick_check"][0],
            "shreds_reapplied": reapplied, "kek_installed": kek_install is not None,
            "kek_verified": {"keys_checked": trial["keys_checked"], "events_checked": trial["events_checked"]} if has_keys else None, "missing_keys": missing, "projection_hash": ph, "warnings": warnings}
