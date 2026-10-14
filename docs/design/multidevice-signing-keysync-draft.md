# Çok cihaz: cihaz başına Ed25519 imza + anahtar senkronizasyonu (TASLAK)

Durum: **taslak, uygulanmadı.** Sahip: W-006 Sync (Data Systems). Tarih: 2026-10-14. Dayanak: `sync.py` (quarantine,
`vaultsync/0.1`), `docs/sync.md`, `crypto_keys.py`, `ops.py`, v0.4 taslağı `/workspace/lattice-vault/design/vaultsync-import-v0.4-draft.md`
§4.3–4.4, güvenlik incelemesi `/workspace/vault-sec-review/REPORT.md` Y2/Y4 ve "Sync (.vaultsync) etkisi".
Bu belge bir hedef tasarımdır; buradaki tablo/olay adları henüz kodda yoktur (aksi belirtilmedikçe).

## 0. Security Engineer'ın mevcut işi (kontrol edildi)
- `grep -i "ed25519|x25519|signature|sign"` repo + `/workspace` üzerinde: **imzalı onay kodu yok.**
  - `wt-security` worktree'si `feat/signed-approvals` dalında ama `a57e9ec` (main) ile aynı; ek commit, stash veya değişiklik yok.
  - Mevcut referanslar yalnız plan: `vault.py` `require_human_tty` docstring'i ("real fix is Ed25519-signed approvals"),
    `SECURITY.md` "Known limitations", `docs/adr/0007-security-requirements.md` "Not implemented",
    `REPORT.md` Y2 (insan anahtarıyla onay imzası) ve Y4 (cihaz Ed25519 anahtarı, `replicas`'ta public key, imzasız `user:*` reddi).
  - Paket manifestinde `"signature": null` alanı var (`sync.py` `export`). `events` tablosunda imza kolonu yok
    (`vault.EVENT_HASH_FIELDS`).
- Sonuç: bu taslak Y2/Y4 ile ve v0.4 §4.4 iki katmanlı imza ile uyumlu kurulmuştur. Uzlaşılması gereken arayüz noktaları §9'da.

## 1. Hedefler / hedef dışı
Hedef: (a) bir paketten gelen `user:*` ve onay türü olaylar yalnız geçerli imzalı ise uygulanır, (b) şifreli alanlar
anahtarı olan her eşleşmiş cihazda okunur, (c) shred ve redaksiyon diğer cihazlara imzalı olay olarak yayılır.
Hedef dışı: ağ/sunucu, gerçek zamanlı sync, aynı OS kullanıcısındaki kötü amaçlı yazılıma karşı tam koruma
(ADR 0007 "Consequences" ile aynı sınır).

## 2. Cihaz anahtarları
- Her cihaz ilk `vault device-id` / `sync-pair` anında iki anahtar çifti üretir: **Ed25519** (imza) ve **X25519** (anahtar sarma).
  `cryptography` paketi zaten bağımlılık (`crypto_keys.py`).
- Özel anahtarlar **keys.db'de değil**, ayrı `device_keys` deposunda: hedef OS keychain; ara çözüm 0600 dosya,
  KEK ile sarılı (`crypto_keys.py` KEK mekanizması). Yedeğe girmez (backup politikası: keys.db/anahtarlar vault.db yedeğinde yok).
- `device_id` = `dev-` + Ed25519 public key'in SHA-256'sının ilk 16 hex'i (şu an rastgele; geçiş: mevcut id korunur,
  registry olayı public key'i bağlar).
- İnsan onay anahtarı (Y2): ayrı bir "human key" mi, yoksa cihaz Ed25519 anahtarı + TTY/OS onayı mı? → **Açık soru S1**.

## 3. Cihaz kaydı = olaylar (registry as events)
- Yeni türler (insan-only, `HUMAN_ONLY_TYPES`'a eklenir): `device.added {device_id, name, ed25519_pub, x25519_pub}`,
  `device.revoked {device_id, reason, effective_hlc}`, `device.keys_rotated {device_id, ed25519_pub, x25519_pub}`.
- `replicas` tablosu bu olaylardan türetilen bir **projeksiyon** olur (`proj_devices`); `sync-pair` doğrudan INSERT yerine
  `device.added` yazar. Yeni şema `schemas.SCHEMAS`'a kayıt + upcaster kuralları (docs/schema-evolution.md) geçerli.
- Her registry olayı, kayıtlı ve iptal edilmemiş **mevcut** bir cihazın imzasını taşır (v0.4 §4.4 son madde). İlk cihaz
  kendi `device.added` olayını kendi anahtarıyla imzalar (güven kökü = ilk cihaz).

## 4. Eşleştirme töreni (pairing ceremony)
1. Yeni cihaz B: anahtarları üretir, `vault sync-pair --offer` → B'nin public key'leri + nonce içeren bir dosya / QR.
2. Güvenilir cihaz A (TTY'li insan): `vault sync-pair --accept <offer>` → iki tarafta da gösterilen **kısa doğrulama kodu**
   (ör. SHA-256(A_pub‖B_pub‖nonce) → 6 kelime/8 hane) elle karşılaştırılır. Eşleşmezse iptal.
3. A, `device.added(B)` olayını imzalar; mevcut veri anahtarlarını (DEK) B'nin X25519 anahtarına sarar (§7) ve
   ilk paketi üretir. B ilk paketi doğrularken A'nın public key'ini offer/accept sırasında elle onaylanmış olarak kabul eder.
- Ajan yolu yok: `sync-pair` `HUMAN_CMDS`'te kalır (bugün de öyle, `vault.py`).

## 5. İptal (revocation)
- `device.revoked` imzalı ve insan onaylı. `effective_hlc`'den **sonra** o cihazın imzaladığı olaylar quarantine'e gider
  (`reason="revoked device"`); öncekiler geçerli kalır (iptal geriye dönük değildir; ele geçirme şüphesinde
  "geriye dönük" mod → **Açık soru S4**).
- İptal sonrası **zorunlu DEK rotasyonu** (§7.3): iptal edilen cihaz yeni yazılan şifreli alanları okuyamaz. Eski
  ciphertext'e karşı koruma yok (cihaz zaten DEK'i görmüştü) → belgelenir.
- Kayıp cihaz senaryosu §8.

## 6. İmza kapsamı ve içe alırken doğrulama
### 6.1 Olay imzası (her olay, oluşturan cihaz; aktarıcı yeniden imzalamaz — v0.4 §4.4/2)
- İmzalanan mesaj: `"lattice-event-sig/v1\n" + canon({event_hash_fields..., "content_hash", "origin_device"})`.
  Yani `vault.EVENT_HASH_FIELDS` (payload, `enc_key_id`, `content_hash` dahil) + origin cihaz. `prev_hash`/`hash`
  **dahil değil**: zincir yereldir ve içe alırken yeniden hesaplanır (`sync.import_package`).
- Şifreli alanlar: imza `payload` (yer tutucular) + `content_hash` üzerindedir. `payload_ct`'nin bütünlüğü AES-GCM
  (AAD `event_id|key_id`, `crypto_keys.py`) ile korunur. `payload_ct`'nin SHA-256'sı da imzaya eklensin mi → **S2**.
- Saklama: yeni tablo `event_signatures(event_id PK, device_id, alg, sig)`; `events` şemasına ve hash alanlarına dokunulmaz
  (additive şema kuralı, `sync.py` docstring). İmza kolonu `events`'e mi girmeli → **S3**.
### 6.2 Paket imzası
- Manifest'teki `signature` = Ed25519( `"lattice-pkg-sig/v1\n" + canon(manifest - signature)` ); manifest `body_sha256`'yı
  içerdiği için gövde de kapsanır. Paket imzası **gönderen** cihazı doğrular (taşıma bütünlüğü + replay için `created_at`,
  vektör); olay imzası **yazarı** doğrular. İkisi de zorunlu.
- İleride `age` şifrelemesi (v0.4 §4.3): imza şifreli dosyanın değil, düz manifest+gövdenin üzerinde (sign-then-encrypt).
### 6.3 İçe alma algoritması (mevcut `import_package` sırasına eklenir)
1. Paket imzası: `source_device` kayıtlı, iptal edilmemiş ve imza geçerli değilse **tüm paket reddedilir** (`SyncError`).
2. Her olay: hash/content_hash (bugünkü `_verify_event`) → imza (`origin_device`'ın o olayın HLC'sindeki geçerli anahtarı).
3. Sınıflandırma: `user:*` veya `HUMAN_ONLY_TYPES` veya registry türü → imza geçerliyse **uygula**, değilse **quarantine**
   (`reason="unsigned"|"bad signature"|"revoked device"`). Ajan/import olayları imzasız da uygulanır ama
   `unverified/proposed` kalır (bugünkü kural).
4. Şema/upcaster kontrolü (bugünkü `_schema_problem`), ebeveyn quarantine'deyse çocuk da quarantine (bugünkü kural).
5. Tam `rebuild()` (bugünkü davranış; `apply_incremental` sıra dışı olayları reddeder).
- Registry olayları paket içinde önce işlenir (HLC sırasıyla), böylece aynı paketteki yeni cihaz anahtarı tanınır; ama
  yalnız zaten güvenilir bir cihazın imzasıyla.

## 7. Anahtar senkronizasyonu
### 7.1 Model
- Bugün: DEK'ler subject başına, KEK ile sarılı, keys.db'de (`crypto_keys.py subject_keys`); diğer cihaza hiç gitmez,
  bu yüzden B'de şifreli alanlar `redacted` görünür (`test_sync.test_encrypted_fields_stay_ciphertext`).
- Hedef (REPORT.md "Sync etkisi" seçenek 1): paket bir **anahtar bölümü** taşır: her `key_id` için
  `wrap_x25519(DEK, alıcı_x25519_pub)` (X25519 ECDH efemeral + HKDF-SHA256 + AES-256-GCM, AAD `"dek|<key_id>|<alıcı device_id>"`;
  ya da `age` alıcısı — v0.4 §4.3 ile uyum → **S5**). Alıcı açar ve kendi KEK'iyle yeniden sarıp keys.db'ye koyar.
- Anahtar bölümü olay **değil**, paketin imzalı ek kısmıdır (event log'a DEK girmez; shred'den sonra log'da DEK izi kalmaz).
### 7.2 Tombstone ve diriltme yasağı
- `subject_keys.state='destroyed'` / `shredded_at` kalıcı tombstone. Gelen paket aynı `key_id` için DEK getirirse
  **reddedilir** (REPORT.md: `INSERT OR IGNORE` DEK'i diriltmemeli).
### 7.3 Rotasyon
- Tetikleyiciler: cihaz iptali, insan isteği, periyodik. Yeni `key_id` (subject başına birden çok anahtar: aktif + eski
  okunur). `key.rotated {subject, old_key_id, new_key_id}` imzalı insan olayı. Eski ciphertext yeniden şifrelenmez
  (append-only); okuma için eski DEK tutulur, shred hepsini yok eder.
  Not: bugün `subject_keys.subject UNIQUE` → çoklu anahtar için şema değişikliği gerekir (keys.db, ayrı migration).
### 7.4 Shred yayılımı
- Bugün `ops.shred_finalize` yerel DEK'i yok eder ve `subject.shredded {key_id}` (`HUMAN_ONLY_TYPES`) yazar; bu olay şu an
  sync'te **quarantine'e gider** (imzasız). Hedef: imzalı `subject.shredded` geçerliyse alıcı cihaz kendi DEK'ini **grace
  süresi olmadan** yok eder (`crypto_keys.finalize` eşdeğeri) ve tombstone yazar.
- Garanti sınırı: yayılım **en iyi çaba**; olayı hiç almayan cihazda veri okunur kalır (REPORT.md). UI "bu cihazda silindi"
  + "N cihaz henüz onaylamadı" göstermeli (consensus Content/Brand: "deleted on this device" scope). Alındı onayı için
  `sync_peer_state` watermark'ı kullanılabilir.
- Sahte tombstone = veri imhası/DoS → imza zorunlu (REPORT.md).
### 7.5 Redaksiyon yayılımı
- Bugün `ops.redact` yeni dosyaya kopya + `redacted_blocklist` + `event.redacted`; blocklist pakette taşınmaz, yalnız alıcının
  yerel blocklist'i paket içeriğini atlatır (`sync.import_package`).
- Hedef: imzalı `event.redacted {target, content_hash}` geçerliyse alıcı aynı redact-copy prosedürünü çalıştırır
  (insan onayı ile mi otomatik mi → **S6**) ve blocklist'e ekler; böylece eski paketler içeriği geri getiremez.
  Export, blocklist'teki olayları ve onların quarantine kopyalarını göndermez.

## 8. Kayıp cihaz kurtarma
- Kalan bir güvenilir cihazdan: `device.revoked(kayıp)` → DEK rotasyonu → yeni cihazla eşleştirme töreni (§4).
- **Tek cihaz kaldıysa ve o da kayıpsa:** veri = son vault.db yedeği; DEK'ler = ayrı `backup-keys` (main'de var,
  `docs/backup-restore.md`). İsteğe bağlı "kurtarma alıcısı" (parola/kâğıt, v0.4 §4.3 son madde) — Kerem kararı.
- Kayıp cihazın imzaladığı, iptalden önce yayılmamış olaylar kaybolur (kabul edilen risk).

## 9. Quarantine'in serbest bırakılması
- Bugünkü `sync_quarantine` satırları origin satırını aynen saklar (`origin_row`, `package_sha256`, `reason`).
- `vault sync-quarantine --release [--event ID]` (insan-only): her satır için §6.3 adım 2–4 yeniden çalışır; **imza
  doğrulanırsa** olay normal içe alma yolundan `events`'e yazılır, satır `released_at` ile işaretlenir (silinmez — audit).
  Doğrulanmazsa yerinde kalır. Ebeveyni serbest kalan çocuklar aynı geçişte yeniden değerlendirilir.
- İmzası olmayan eski (bugünkü 0.1 paketlerinden) satırlar **asla** otomatik serbest kalmaz. Tek tek insan kararı
  (`vault approve` benzeri, yerel imzayla yeniden yazma) mümkün mü → **S7**.
- Format: imzalı paketler `vaultsync/0.2`; 0.1 paketleri okunur ama her `user:*`/onay olayı quarantine'e gider (bugünkü davranış).

## 10. Security Engineer ile uzlaşılacak arayüz noktaları
1. İmza mesaj formatı (domain-separation önekleri, canon JSON = `vault.canon`) ve alg tanımlayıcısı.
2. Olay imzasının nerede saklandığı (`event_signatures` vs `events` kolonu) ve hash alanlarına girip girmediği.
3. İnsan onay imzası ile cihaz imzasının ilişkisi (tek anahtar mı, iki imza mı).
4. Özel anahtar deposu (OS keychain API, dosya fallback, KEK) ve yedek politikası.
5. `device.*`, `key.rotated` olay şemaları + `HUMAN_ONLY_TYPES`/trigger güncellemesi.
6. DEK sarma yöntemi (`age` vs X25519+HKDF+AES-GCM) ve AAD.
7. Doğrulama hatası davranışı: paket reddi vs olay quarantine (bu taslak: paket imzası → red, olay imzası → quarantine).

## 11. Security Engineer için açık sorular
- **S1** İnsan onayı: ayrı human key (OS keychain/biometric) mı, cihaz anahtarı + TTY mi? Onay olayında iki imza mı?
- **S2** Olay imzası `payload_ct` SHA-256'yı da kapsamalı mı (AES-GCM AAD yeterli mi)?
- **S3** İmza `events` içinde mi (hash zincirine girer) yoksa yan tabloda mı?
- **S4** Ele geçirilmiş cihazda geriye dönük iptal (belirli HLC'den önceki imzaları da quarantine) gerekli mi?
- **S5** DEK sarma: `age` (v0.4 §4.3) mı elle X25519/HKDF/AES-GCM mi?
- **S6** Redaksiyon yayılımı alıcı cihazda otomatik mi, insan onayı mı?
- **S7** İmzasız eski quarantine satırları insan tarafından yerel imzayla "benimsenebilir" mi, yoksa yalnız silinebilir mi?
- **S8** Replay: eski ama geçerli imzalı paket (ör. iptal öncesi) — `created_at`/vektör penceresi yeterli mi?
- **S9** İlk cihaz güven kökü: kurtarma alıcısı/kâğıt yedek parmak izi gerekli mi?
