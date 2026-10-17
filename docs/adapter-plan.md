# Adapter Katmanı Planı

Amaç: Kurulumdan sonra ekstra iş olmasın. AI’lar vault’u otomatik okusun / güncelle sin. Onay hâlâ kullanıcıda.

## Öncelik sırası

1. **Context Pack Watcher** (şimdi)
2. **MCP Adapter** (sonra)
3. Kural bazlı otomatik onay — **şimdilik yok**

## 1. Context Pack Watcher

**Ne yapar**
- Vault değişince (yeni onaylı olay) otomatik Context Pack üretir.
- Kullanıcıya “şu pack’i yapıştır” bildirimi verir veya dosyaya yazar.
- MCP’siz modeller (ChatGPT, Gemini, DeepSeek) için hemen fayda sağlar.

**Dosyalar**
- `adapters/context_pack_watcher.py`
- CLI: `python vault.py watch-pack --out pack.md --notify`

**Davranış**
- `export-context` çağrısını izler.
- Değişiklik olunca `pack.md` günceller.
- İsteğe bağlı bildirim (terminal / dosya).

## 2. MCP Adapter (sonraki adım)

**Ne yapar**
- Claude vb. MCP istemcileri için arka plan yardımcısı.
- Otomatik `get_summary` / `search` çağrılarını kolaylaştırır.
- Yeni bilgi geldiğinde `propose_event` önerir (onay yine CLI’de).

## 3. Kural bazlı onay

Şimdilik **yapılmayacak**. Onay her zaman insan.

## Güvenlik notu

Adapter’lar yazma yapmaz. Sadece okur ve önerir.  
Tüm kalıcı değişiklikler hâlâ `vault approve` ile olur.
