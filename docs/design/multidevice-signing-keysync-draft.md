# Çok cihaz: Ed25519 imza + anahtar senkronizasyonu (final v3 — Security ile mutabık)

Durum: **Security ile mutabık, final v3. Tasarım kesin, kod henüz yok.** Sahip: W-006 Sync (Data Systems). Tarih: 2026-10-14.
v2: S1–S9 kararları işlendi. v3: `prev_hash` uyuşmazlığı kapandı (§6.1), sözleşme ayrıntıları kesinleşti (§10),
uygulama notu (§11) ve PR planı (§12) eklendi. **Açık soru yok.**
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

## 3. Kayıt olayları (registry as events) — Security ile mutabık, final v3
Şemalar §10.3'te. Özet: `key.registered` (kullanıcı imzalı; ilk kullanıcı anahtarı kendini imzalar, parmak izi TTY'de
onaylanır), `key.rotated` (eski ve yeni anahtarın ikisi de imzalar), `key.revoked` (kullanıcı imzalı), `attestation`
(kullanıcı imzalı). Kullanıcı pubkey'i ile cihaz anahtarları `key.registered.certified_by` ile çapraz sertifikalanır.
`replicas` bu olaylardan türetilen projeksiyon olur; `sync-pair` doğrudan INSERT yerine `key.registered` yazar.

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
### 6.1 Olay imzası — Security ile mutabık, final v3
- İmzalanan nesne (bayt kuralları §10.1):
  `canon({domain:"lattice-event-sig/v1", id, type, subject, payload_hash, actor, parents (sıralı), hlc, origin_device, key_id})`.
  `payload_hash` = `payload_ct` varsa onun SHA-256'sı, yoksa `canon(payload)`'ın SHA-256'sı. Shred sonrası ciphertext
  değişmediği için doğrulama bozulmaz.
- **Kapsam dışı:** `prev_hash`, `seq`, `trust`/`status` (hepsi cihaza yerel veya türetilmiş).
- `prev_hash` uyuşmazlığı **kapandı**: `prev_hash` imzadan çıkarıldı, `origin_prev_hash` önerisi reddedildi. Nedensel bağ
  `parents` ile, köken zincirindeki kesme ise imzalı manifestteki `seq` + `head_vector` ve anchor imzası
  (`lattice-anchor-sig/v1`) ile yakalanır.
- `origin_device` artık imzanın içinde: §0'daki kimliksiz `origin_device` sorunu olay düzeyinde de kapanır.
- Saklama: `event_sigs(event_id, key_id, alg, sig)` yalnız indeks/yan tablo; bütünlük §10.2'deki olay hash'inden gelir.

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
- Tetikleyici: iptal, insan isteği, periyodik. `dek.rotated {subject, old_key_id, new_key_id}` kullanıcı imzalı (bkz. §10.3 isim notu).
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
  `--dry-run` listesi, tek veya toplu. `attestation {target_event_ids[], statement}` (şema §10.3).
- 0.2 (imzalı) paket formatı; 0.1 paketleri okunur ama `user:*`/onay olayları quarantine'e gider (bugünkü davranış).

## 10. Sözleşme ayrıntıları — Security ile mutabık, final v3
### 10.1 Domain'ler ve imzalanan baytlar
- Domain'ler: `lattice-event-sig/v1`, `lattice-pkg-sig/v1`, `lattice-anchor-sig/v1`. `alg="ed25519"`.
- İmzalanan baytlar = UTF-8(`domain + "\n" + canon(nesne)`).
- `canon` = anahtarlar sıralı, ayraçlar `(",", ":")`, `ensure_ascii=False`, **float yasak** (float içeren nesne imzalanmaz/reddedilir).
  Not (kontrol edildi): bugünkü `vault.canon` (`vault.py:189`) sıralama/ayraç/`ensure_ascii` kuralına uyuyor ama **float'ı reddetmiyor** (`canon({'a':1.5})` → `{"a":1.5}`); imza için ayrı, float reddeden bir `canon_sig` gerekir (PR 1).
### 10.2 Olay hash'i imzayı içerir
- `hash = H(prev_hash || canon(olay) || sig_bytes)`; imza yoksa `sig_bytes` boş. `event_sigs` yalnız indeks; bir imzayı
  silmek veya değiştirmek hash uyuşmazlığı verir.
### 10.3 Olay şemaları
- `key.registered {key_id, alg, pubkey_b64, role: "user"|"device", device_id?, certified_by}` — kullanıcı imzalı;
  ilk kullanıcı anahtarı kendini imzalar, parmak izi TTY'de onaylanır.
- `key.rotated {old_key_id, new_key_id}` — eski ve yeni anahtarın **ikisi de** imzalar.
- `key.revoked {key_id, effective_hlc, reason, compromised: bool}` — kullanıcı imzalı.
- `attestation {target_event_ids[], statement}` — kullanıcı imzalı.
- Trigger: bu türler insan-only; **imzasız INSERT reddedilir**; `actor LIKE 'user:%'`.
- İsim çakışması: §7.3'teki DEK rotasyonu bu yüzden `dek.rotated {subject, old_key_id, new_key_id}` adını alır (imza anahtarı rotasyonu = `key.rotated`).
### 10.4 `VAULT_USER_KEY`
- PKCS8 PEM; isteğe bağlı parola (`BestAvailableEncryption`). Açarken: düzenli dosya (symlink değil), sahibi = euid,
  `mode & 0o077 == 0`; aksi halde **reddet**.

## 11. Uygulama notu: imzalı hash ve sync içe alma / quarantine
- Bugün `sync.import_package` gelen olayın köken hash'ini `_verify_event` ile (köken `prev_hash` üzerinden) doğrular, sonra
  yerel zincire eklerken `prev_hash`/`hash`'i `vault.event_hash(prev, local)` ile **yeniden hesaplar**. §10.2 sonrası:
  1. Paket her olay için `sig` (ve `key_id`, `alg`) taşımalı; köken hash doğrulaması `sig_bytes`'ı da katmalı, yoksa her imzalı olay "tampered" görünür.
  2. Yerel yeniden hesaplama **aynı `sig_bytes`'ı** katmalı (`H(yerel_prev || canon(olay) || sig)`); imza alıcıda yeniden üretilmez, aynen taşınır. `event_sigs` satırı aynı transaction'da yazılır.
  3. İmza doğrulaması (§6.1) yerel hash'ten bağımsızdır (prev_hash kapsam dışı), bu yüzden zincir yeniden kurulsa da geçerli kalır.
  4. `sync_quarantine` satırları `events`'e girmediği için yerel hash etkilenmez; `origin_row` imzayı da saklamalı ki serbest bırakmada (§9) olay imzasıyla birlikte eklenebilsin. 0.1 satırlarında imza yok → yalnız `attestation` yolu.
  5. Mevcut olaylar (imzasız) için `sig_bytes` boş: hash formülü geriye uyumlu, eski zincirler `verify_chains`'ten geçmeye devam eder (test edilmeli).
  6. `event_sigs` için yeni tablo + `vault.event_hash` imza değişikliği tüm yazma yollarını etkiler (`append`, `ops.redact` kopya, `backup` doğrulaması, `sync`).

## 12. Uygulama planı (sıralı PR'lar)
Bağımlılık: PR 1–2 Security (`wt-security`, `feat/signed-approvals`; şu an main ile aynı, commit yok). PR 3+ W-006, PR 2'ye bağlı.
1. **[Security] Kullanıcı anahtarı + kanonik imza çekirdeği:** `VAULT_USER_KEY` yükleme (§10.4), `canon` float yasağı, `sign/verify(domain, obj)` (§10.1).
2. **[Security] İmzalı olay hash'i + `event_sigs` + trigger'lar:** §10.2 hash formülü (geriye uyumlu), `key.*`/`attestation` şemaları ve insan-only/imzasız-red trigger'ı (§10.3), imzalı approve/reject/revert/redact/shred.
3. **[W-006] Cihaz anahtarları + registry projeksiyonu + eşleştirme töreni:** cihaz Ed25519 + age kimliği, `key.registered`/`key.revoked` → `replicas`, `sync-pair --offer/--accept` (§2–§5).
4. **[W-006] `vaultsync/0.2` imzalı paket:** imzalı manifest (`package_id, seq, base/head_vector`), seq replay reddi, olay `sig` taşıma, §11 içe alma değişiklikleri, imzalı `user:*` olayların uygulanması (§6).
5. **[W-006] Quarantine serbest bırakma + `attestation`:** `sync-quarantine --release`, dry-run + TTY ile `attestation` (§9).
6. **[W-006 + Security] Anahtar senkronizasyonu:** age ile DEK sarma, tombstone, `dek.rotated`, shred/redaksiyon yayılımı (§7), kurtarma kodu (§8).
7. **[Security] Anchor:** `lattice-anchor-sig/v1` ile zincir başı anchor'ı (kesme tespiti, §6.1).

Açık soru yok (S1–S9 ve `prev_hash` kapandı).
