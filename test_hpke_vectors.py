"""RFC 9180 HPKE test vectors for the vaultkeys/0.2 DEK wrap (ADR 0016).

A small independent reference implementation of HPKE base mode (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-GCM)
is checked against RFC 9180 Appendix A.1 and then cross-checked against the `cryptography` HPKE module that
key_transport.py uses, in both directions, plus a fixed known-answer vector for the exact suite and info layout.
"""
import hashlib, hmac, unittest
from testutil import HAVE_CRYPTO
if HAVE_CRYPTO:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import serialization
    import key_transport as kt

H = bytes.fromhex


def _extract(salt, ikm):
    return hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()


def _expand(prk, info, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest(); out += t; i += 1
    return out[:n]


def _lx(sid, label, ikm, salt=b""):
    return _extract(salt, b"HPKE-v1" + sid + label + ikm)


def _le(sid, prk, label, info, n):
    return _expand(prk, n.to_bytes(2, "big") + b"HPKE-v1" + sid + label + info, n)


def _raw_pub(k):
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def ref_setup(skE, pkR, info, nk, aead_id):
    """RFC 9180 SetupBaseS with a fixed ephemeral key. Returns (enc, key, base_nonce)."""
    kem_sid = b"KEM" + (0x0020).to_bytes(2, "big")
    e = X25519PrivateKey.from_private_bytes(skE)
    enc = _raw_pub(e)
    dh = e.exchange(X25519PublicKey.from_public_bytes(pkR))
    shared = _le(kem_sid, _lx(kem_sid, b"eae_prk", dh), b"shared_secret", enc + pkR, 32)
    sid = b"HPKE" + (0x0020).to_bytes(2, "big") + (0x0001).to_bytes(2, "big") + aead_id.to_bytes(2, "big")
    ctx = b"\x00" + _lx(sid, b"psk_id_hash", b"") + _lx(sid, b"info_hash", info)
    secret = _lx(sid, b"secret", b"", salt=shared)
    return enc, _le(sid, secret, b"key", ctx, nk), _le(sid, secret, b"base_nonce", ctx, 12)


def ref_seal(skE, pkR, info, pt, aad=b"", nk=32, aead_id=0x0002):
    enc, key, nonce = ref_setup(skE, pkR, info, nk, aead_id)
    return enc + AESGCM(key).encrypt(nonce, pt, aad)


def ref_open(skR, blob, info, aad=b"", nk=32, aead_id=0x0002):
    enc, ct = blob[:32], blob[32:]
    r = X25519PrivateKey.from_private_bytes(skR)
    dh = r.exchange(X25519PublicKey.from_public_bytes(enc))
    kem_sid = b"KEM" + (0x0020).to_bytes(2, "big")
    shared = _le(kem_sid, _lx(kem_sid, b"eae_prk", dh), b"shared_secret", enc + _raw_pub(r), 32)
    sid = b"HPKE" + (0x0020).to_bytes(2, "big") + (0x0001).to_bytes(2, "big") + aead_id.to_bytes(2, "big")
    ctx = b"\x00" + _lx(sid, b"psk_id_hash", b"") + _lx(sid, b"info_hash", info)
    secret = _lx(sid, b"secret", b"", salt=shared)
    return AESGCM(_le(sid, secret, b"key", ctx, nk)).decrypt(_le(sid, secret, b"base_nonce", ctx, 12), ct, aad)


# RFC 9180 Appendix A.1 (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM), base mode, sequence 0
A1 = dict(info=H("4f6465206f6e2061204772656369616e2055726e"),
          skEm=H("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"),
          enc=H("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"),
          skRm=H("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"),
          pkRm=H("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"),
          key=H("4531685d41d65f03dc48f6b8302c05b0"), base_nonce=H("56d890e5accaaf011cff4b7d"),
          pt=H("4265617574792069732074727574682c20747275746820626561757479"), aad=H("436f756e742d30"),
          ct=H("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"))

# Fixed known-answer vector for the vaultkeys/0.2 suite (AES-256-GCM) and info layout (domain || SHA-256(binding)).
KAT_SKE = bytes(range(1, 33))
KAT_SKR = bytes(range(33, 65))
KAT_DEK = bytes(range(100, 132))
KAT_BINDING = ("kb_00", "sk_00", "person:test", ["e1"], "dev-a", "dev-b", "0" * 64, "user/ed25519/00")


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class HpkeVectorTest(unittest.TestCase):
    def test_reference_matches_rfc9180_a1(self):
        enc, key, nonce = ref_setup(A1["skEm"], A1["pkRm"], A1["info"], 16, 0x0001)
        self.assertEqual((enc, key, nonce), (A1["enc"], A1["key"], A1["base_nonce"]))
        blob = ref_seal(A1["skEm"], A1["pkRm"], A1["info"], A1["pt"], A1["aad"], 16, 0x0001)
        self.assertEqual(blob, A1["enc"] + A1["ct"])
        self.assertEqual(ref_open(A1["skRm"], blob, A1["info"], A1["aad"], 16, 0x0001), A1["pt"])

    def test_library_opens_reference_ciphertext(self):
        pkR = _raw_pub(X25519PrivateKey.from_private_bytes(KAT_SKR))
        info = kt._binding(*KAT_BINDING)
        blob = ref_seal(KAT_SKE, pkR, info, KAT_DEK)
        self.assertEqual(kt.unwrap_dek(X25519PrivateKey.from_private_bytes(KAT_SKR), blob, info), KAT_DEK)
        # RFC A.1 suite too, empty aad (the library API has none)
        from cryptography.hazmat.primitives import hpke
        s128 = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_128_GCM)
        b2 = ref_seal(A1["skEm"], A1["pkRm"], A1["info"], A1["pt"], b"", 16, 0x0001)
        self.assertEqual(s128.decrypt(b2, X25519PrivateKey.from_private_bytes(A1["skRm"]), info=A1["info"]), A1["pt"])

    def test_reference_opens_library_ciphertext(self):
        r = X25519PrivateKey.from_private_bytes(KAT_SKR)
        info = kt._binding(*KAT_BINDING)
        blob = kt.wrap_dek(KAT_DEK, _raw_pub(r), info)
        self.assertEqual(len(blob), 32 + 32 + 16)
        self.assertEqual(ref_open(KAT_SKR, blob, info), KAT_DEK)
        with self.assertRaises(Exception):   # info is bound: another binding does not open
            kt.unwrap_dek(r, blob, kt._binding("kb_01", *KAT_BINDING[1:]))

    def test_fixed_kat(self):
        pkR = _raw_pub(X25519PrivateKey.from_private_bytes(KAT_SKR))
        info = kt._binding(*KAT_BINDING)
        self.assertEqual(info[:len(kt.WRAP_INFO_DOMAIN)], kt.WRAP_INFO_DOMAIN)
        self.assertEqual(hashlib.sha256(ref_seal(KAT_SKE, pkR, info, KAT_DEK)).hexdigest(), KAT_PINNED)


KAT_PINNED = "bf9bd3c1801a6863a571bd9fd54a3c1846e50393a92dc52b6ef1e011a29de926"   # SHA-256 of enc || ct

if __name__ == "__main__":
    unittest.main()
