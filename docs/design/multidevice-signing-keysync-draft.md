# Çok cihaz: Ed25519 imza + anahtar senkronizasyonu (TASLAK v2)

Durum: **taslak, uygulanmadı.** Sahip: W-006 Sync (Data Systems). Tarih: 2026-10-14.
v2: Security Engineer'ın S1–S9 yanıtları karar olarak işlendi (**Security ile mutabık** etiketli). Tek açık uyuşmazlık §6.1'de.
Dayanak: `sync.py` (quarantine, `vaultsync/0.1`), `docs/sync.md`, `crypto_keys.py`, `ops.py`, v0.4 taslağı
`/workspace/lattice-vault/design/vaultsync-import-v0.4-draft.md` §4.3–4.4, güvenlik incelemesi `/workspace/vault-sec-review/REPORT.md` Y2/Y4.
Buradaki tablo/olay adları henüz kodda yoktur (aksi belirtilmedikçe).

## 0. Mevcut durum (kontrol edildi)
- Repo ve `/workspace` içinde imzalı onay **kodu yok**; `wt-security` (`feat/signed-approvals`) main (`a57e9ec`) ile aynı.
  Plan referansları: `vault.py` `require_human_tty` docstring'i, `SECURITY.md` "Known limitations", ADR 0007, REPORT.md Y2/Y4.
- Paket manifestinde `"signature": null` (`sync.py` `export`); `events` tablosunda imza yok (`vault.EVENT_HASH_FIELDS`).
- **`origin_device` paket gövdesinden okunuyor** (Security notu: `origin/main` `sync.py:166-167`). main'de güven kararı buna
  bağlıydı: `origin_device` eşleşmiş bir cihaz id'si yazılırsa `user:*` olay (onaylar dahil) verified kalıyordu.
  Bu dalda `801cd57` (quarantine) **güven kararını** bu alandan ayırdı: varsayılan yolda her `user:*` ve `HUMAN_ONLY_TYPES`
  olayı `origin_device` ne olursa olsun quarantine'e gider (`sync._quarantine_reason`; test: `test_user_events_quarantined_not_applied`,
  `test_forged_approval_does_not_change_projection`). Eşleşmiş-cihaz kontrolü yalnız test bayrağı `_trust_unsigned=True` ile çalışır.
  **Kapanmayan kısım:** `origin_device` (ve manifest `source_device`) hâlâ kimlik doğrulamasız; ajan olaylarında yerel
  `replica_id`'yi, `sync_imported`/`sync_quarantine` kayıtlarını ve vektör/watermark anahtarlarını (`_vkey`) belirliyor. Yani
  sahte atıf ve watermark kaydırma mümkün, yetki yükseltme değil. Asıl çözüm §6 (imzalı manifest + olay imzası).

## 1. Hedefler / hedef dışı
Hedef: (a) paketten gelen `user:*` ve insan-only olaylar yalnız geçerli **kullanıcı imzasıyla** uygulanır, (b) şifreli alanlar
anahtarı olan her eşleşmiş cihazda okunur, (c) shred/redaksiyon imzalı olay olarak yayılır.
Hedef dışı: ağ/sunucu, gerçek zamanlı sync, aynı OS kullanıcısındaki kötü amaçlı yazılıma tam koruma (ADR 0007).

## 2. Anahtarlar — Security ile mutabık (S1, S5)
- **Kullanıcı (insan) anahtarı:** ayrı Ed25519 anahtarı; 0600 dosya veya `VAULT_USER_KEY`, sonra OS keychain.
  İnsan-only olayları imzalar (approve/reject/revert/redact/shred ve §3 kayıt olayları). Onay başına **tek kullanıcı imzası**.
- **Cihaz anahtarları:** her cihazda Ed25519 (paketleri imzalar: taşıma/köken) + **age X25519 kimliği** (DEK sarma alıcısı).
- **Katmanlar ayrı:** paket üzerindeki cihaz imzası ≠ olay üzerindeki kullanıcı imzası. TTY yalnız UX koruması, kimlik doğrulama değil.
- Özel anahtarlar keys.db'de ve vault.db yedeğinde yok (main backup politikası).

## 3. Kayıt olayları (registry as events) — Security ile mutabık (S1, S4)
- `key.registered {key_id, kind: user|device-sign|device-age, pub, device_id?, name?}` — **kullanıcı anahtarıyla imzalı**.
  Kullanıcı pubkey'i ile cihaz anahtarları bu olayla çapraz sertifikalanır; yeni cihaz anahtarı yalnız kullanıcı imzasıyla eklenir.
- `key.revoked {key_id, effective_hlc, reason, compromised?: bool}` — kullanıcı imzalı.
- `replicas` bu olaylardan türetilen projeksiyon olur; `sync-pair` doğrudan INSERT yerine `key.registered` yazar.
  Yeni türler `schemas.SCHEMAS` + `HUMAN_ONLY_TYPES`'a eklenir.

## 4. Eşleştirme töreni
1. Yeni cihaz B anahtarlarını üretir; `vault sync-pair --offer` → pubkey'ler + nonce (dosya/QR).
2. A'da insan (TTY) `vault sync-pair --accept <offer>`; iki ekranda kısa doğrulama kodu (SHA-256(A_pub‖B_pub‖nonce)) karşılaştırılır.
3. A, B için `key.registered` olaylarını **kullanıcı anahtarıyla** imzalar, DEK'leri B'nin age alıcısına sarar (§7), ilk paketi üretir.
- Kâğıt **parmak izi** yalnız doğrulama içindir (S9, §8).

## 5. İptal — Security ile mutabık (S4)
- Geriye dönük iptal **yok**. `key.revoked`: `effective_hlc` öncesi imzalar geçerli, sonrası **reddedilir** (quarantine, `reason="revoked key"`).
- Ele geçirme: `compromised=true` + geriye tarihli `effective_hlc`, yalnız kullanıcı imzası + insan kararıyla.
- İptal sonrası DEK rotasyonu (§7.3). Eski ciphertext'i görmüş cihaza karşı koruma yok (belgelenir).

## 6. İmza kapsamı ve doğrulama
### 6.1 Olay imzası — Security ile mutabık (S2, S3), **bir uyuşmazlık açık**
- İmzalanan kanonik biçim (S2): `(id, type, subject, payload | sha256(payload_ct), actor, parents, prev_hash, key_id)`,
  `vault.canon` ile, domain öneki `"lattice-event-sig/v1\n"`. Şifreli olayda ciphertext hash'i imzalanır; shred sonrası
  ciphertext değişmediği için doğrulama bozulmaz.
- Saklama (S3): yan tablo `event_sigs(event_id, key_id, alg, sig)`. Hash zinciri imzayı kapsamalı (ya da olay hash'i imzayı
  içermeli) ki imza sessizce silinemesin.
- **Açık uyuşmazlık — `prev_hash`:** Security imza kapsamına `prev_hash` koyuyor. Ama `prev_hash` cihaza yereldir:
  `sync.import_package` gelen olayı alıcının zincirine ekler ve `prev_hash`/`hash`'i yeniden hesaplar, yani senkronlanan
  bir olayın `prev_hash`'i her cihazda farklıdır ve alıcıda yerel `prev_hash` üzerinden doğrulama başarısız olur.
  **Öneri:** imzaya köken cihazdaki değer girsin, adı `origin_prev_hash`; alıcı bunu `sync_imported.origin_row`'da
  (bugün zaten köken satırı saklanıyor) veya `event_sigs` yanında saklar ve doğrulamayı ona göre yapar; yerel `prev_hash`
  imzaya girmez, yerel zincir bütünlüğü S3 kuralıyla korunur. **Security'ye soru:** `origin_prev_hash` kabul mü, yoksa
  `prev_hash`'in imzaya girmesinin başka bir amacı var mı (ör. köken zincirinde konum/kesme tespiti)?
### 6.2 Paket imzası ve replay — Security ile mutabık (S8)
- İmzalı manifest: `package_id, source_device, seq` (cihaz başına monoton), `base_vector`, `head_vector`, `body_sha256`;
  cihaz Ed25519 anahtarıyla, domain öneki `"lattice-pkg-sig/v1\n"`.
- Alıcı cihaz başına son kabul edilen `seq`'i saklar, `<=` olanı reddeder. Olay id'siyle birleşim tekrar olayları zararsız kılar;
  redaksiyon/iptal tekrarları blocklist ve iptal durumuna karşı kontrol edilir.
- İleride `age` paket şifrelemesi: sign-then-encrypt (imza düz manifest+gövde üzerinde).
### 6.3 İçe alma algoritması (bugünkü `import_package` sırasına eklenir)
1. Manifest imzası + `seq` kontrolü; başarısızsa **paket reddi** (`SyncError`). `source_device`/`origin_device` artık imzayla bağlı.
2. Her olay: bugünkü hash/content_hash (`_verify_event`) → `event_sigs` imzası (anahtar o HLC'de iptal edilmemiş olmalı).
3. `user:*` / `HUMAN_ONLY_TYPES` / `key.*`: geçerli **kullanıcı imzası** varsa uygula, yoksa quarantine
   (`unsigned|bad signature|revoked key`). Ajan/import olayları imzasız da uygulanır, `unverified/proposed` kalır.
4. Şema/upcaster kontrolü ve ebeveyn-quarantine kuralı (bugünkü `_schema_problem`).
5. Tam `rebuild()` (bugünkü davranış).

## 7. Anahtar senkronizasyonu
### 7.1 Model — Security ile mutabık (S5)
- Bugün DEK'ler cihaz dışına çıkmıyor (`crypto_keys.py subject_keys`), B'de şifreli alanlar `redacted` görünüyor
  (`test_sync.test_encrypted_fields_stay_ciphertext`).
- Hedef: paket, imzalı bir **anahtar bölümü** taşır: her `key_id` için DEK, alıcı cihazın **age** alıcısına sarılı.
  Alıcı açar, kendi KEK'iyle yeniden sarar. DEK event log'a girmez.
### 7.2 Tombstone
- `subject_keys` `destroyed`/`shredded_at` kalıcı tombstone; aynı `key_id` için gelen DEK reddedilir (REPORT.md).
### 7.3 Rotasyon
- Tetikleyici: iptal, insan isteği, periyodik. `key.rotated {subject, old_key_id, new_key_id}` kullanıcı imzalı.
  Eski ciphertext yeniden şifrelenmez; eski DEK okuma için tutulur, shred hepsini yok eder.
  Not: `subject_keys.subject UNIQUE` → çoklu anahtar için keys.db migration gerekir.
### 7.4 Shred yayılımı
- Bugün `ops.shred_finalize` yerel DEK'i yok eder + `subject.shredded {key_id}` yazar; sync'te bu olay şu an quarantine'e gider.
- Hedef: kullanıcı imzalı `subject.shredded`, eşleşmiş ve iptal edilmemiş cihazdan geliyorsa alıcı DEK'ini hemen yok eder,
  tombstone yazar. Yayılım **en iyi çaba**; UI "bu cihazda silindi" + bekleyen cihazları göstermeli.
### 7.5 Redaksiyon yayılımı — Security ile mutabık (S6)
- **Otomatik** yalnız: kullanıcı imzalı ve eşleşmiş, iptal edilmemiş cihazdan. Alıcı `ops.redact` eşdeğerini çalıştırır, blocklist'e ekler.
- İmzasız → quarantine + kullanıcıya gösterilir. Export blocklist'teki olayları göndermez.

## 8. Kurtarma — Security ile mutabık (S9)
- **Kâğıt kurtarma kodu:** çevrimdışı age kurtarma alıcısı; her DEK sarımına eklenir → tüm cihazlar kaybolsa da anahtar kurtarma.
- **Kâğıt parmak izi:** yalnız doğrulama (kullanıcı pubkey'i / ilk cihaz), kurtarma için değil.
- Kayıp cihaz: kalan cihazdan `key.revoked` → rotasyon → yeni cihazla tören. Tek cihaz da kayıpsa: vault.db yedeği + ayrı
  `backup-keys` (main, `docs/backup-restore.md`) + kurtarma kodu.

## 9. Quarantine'in serbest bırakılması — Security ile mutabık (S7)
- `sync_quarantine` satırları köken satırını aynen saklar (`origin_row`, `package_sha256`, `reason`); bu satır **hiç değişmez**.
- İmzalı olarak gelmiş satırlar: `vault sync-quarantine --release` §6.3 adım 2–4'ü yeniden çalıştırır, geçerse `events`'e yazar.
- İmzasız eski (0.1) satırlar: yeni **`attestation`** olayı ile benimsenir — kullanıcı anahtarıyla imzalı, TTY'de, önce
  `--dry-run` listesi, tek veya toplu. `attestation {target_event_ids[], quarantine_origin_sha256[]}` (alan adları taslak).
- 0.2 (imzalı) paket formatı; 0.1 paketleri okunur ama `user:*`/onay olayları quarantine'e gider (bugünkü davranış).

## 10. Uzlaşılacak uygulama ayrıntıları (karar değil, sözleşme)
1. `vault.canon` = imza kanonik JSON'u; domain önekleri `lattice-event-sig/v1`, `lattice-pkg-sig/v1`; `alg="ed25519"`.
2. `event_sigs`'in hash zincirine bağlanma şekli (ayrı zincirli tablo mı, olay hash'ine sig mi) — S3 ikisini de kabul ediyor.
3. `key.*`, `attestation`, `key.rotated` olay şemaları ve trigger güncellemesi.
4. `VAULT_USER_KEY` dosya formatı ve izin kontrolü (0600, sahiplik).

## 11. Açık soru (Security Engineer)
- **§6.1 `prev_hash`:** imzaya yerel `prev_hash` yerine köken cihazdaki `origin_prev_hash` girsin mi? (S1–S9'un geri kalanı kapandı.)
