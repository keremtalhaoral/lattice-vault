# Hızlı Başlangıç

## Kurulum

```sh
git clone https://github.com/keremtalhaoral/lattice-vault
cd lattice-vault
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## İlk vault

```sh
export VAULT_DB="$HOME/lattice/vault.db"
mkdir -p "$HOME/lattice"
python vault.py init
python vault.py keys init-user
```

## Günlük komutlar

```sh
python vault.py add note.added person:kerem --payload '{"text":"Merhaba"}'
python vault.py export-context --out pack.md --max-tokens 4000
python vault.py doctor
```

Detaylı kullanım: [docs/usage.md](docs/usage.md)  
Güvenlik: [SECURITY.md](SECURITY.md)
