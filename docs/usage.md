# Lattice Vault — Kullanım Kılavuzu

Local-first, AI-agnostic kişisel bilgi vault’u.  
Tüm olaylar append-only log’da tutulur, sen onaylamadan “aktif” sayılmaz.

## 1. Kurulum

```sh
git clone https://github.com/keremtalhaoral/lattice-vault
cd lattice-vault
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Önerilen ortam değişkenleri:

```sh
export VAULT_DB="$HOME/lattice/vault.db"
export VAULT_USER_KEY="$HOME/.config/lattice-vault/user.key"
mkdir -p "$(dirname "$VAULT_DB")" "$(dirname "$VAULT_USER_KEY")"
```

## 2. İlk kurulum

```sh
python vault.py init
python vault.py keys init-user
```

- `yes` de.
- Recovery code’u **offline** (kağıt / şifre yöneticisi) sakla. Bir daha gösterilmez.

## 3. Günlük kullanım

### Olay ekle

```sh
python vault.py add note.added person:kerem \
  --payload '{"text":"Bugün hokey antrenmanı vardı"}' \
  --sensitive note
```

### Onayla

```sh
python vault.py approve <event-id>
```

### Göster / geçmiş

```sh
python vault.py show <event-id>
python vault.py history person:kerem
python vault.py history --type note.added
```

### Ara

```sh
python vault.py search "hokey"
```

## 4. Context Pack (AI’lara vermek için)

```sh
python vault.py export-context --out pack.md --max-tokens 4000
```

Çıktıyı Claude / ChatGPT / Gemini / DeepSeek’e yapıştır.

## 5. Sync (çoklu cihaz)

```sh
# Kaynak cihaz
python vault.py sync-export --out vault.vaultsync

# Hedef cihaz
python vault.py sync-import vault.vaultsync
```

## 6. Yedekleme ve geri yükleme

Üç ayrı yerde tut:

```sh
python vault.py backup --out /media/usb1/vault-bk
python vault.py backup-keys --out /media/usb2/keys-bk
python vault.py backup-kek --out /media/usb3/kek-bk
```

Geri yükleme:

```sh
python vault.py restore /media/usb1/vault-bk \
  --to "$HOME/lattice/vault.db" \
  --keys /media/usb2/keys-bk \
  --kek /media/usb3/kek-bk
```

## 7. Sağlık ve bütünlük

```sh
python vault.py doctor
python vault.py verify
```

## 8. MCP (Claude Desktop vb.)

```sh
python vault.py mcp
```

## 9. Dikkat edilmesi gerekenler

- Gerçek veriye geçmeden önce sentetik veriyle geri yükleme provası yap.
- Recovery code ve kullanıcı anahtarını offline yedekle.
- `VAULT_ALLOW_NONTTY` asla açık bırakma.
- Hassas alanlar için `--sensitive` kullan.
- KEK, keys ve vault yedeklerini **ayrı** yerlerde tut.

## 10. Yardım

```sh
python vault.py --help
python vault.py add --help
```

Daha fazla: `SECURITY.md`, `roadmap.md`
