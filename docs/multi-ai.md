# Multi-AI Kullanım Örnekleri

Lattice Vault’u farklı AI’larla nasıl kullanırsın.

## Claude (MCP — önerilen)

1. Agent ekle:
   ```sh
   python vault.py agent-add claude
   ```
2. Token’ı kaydet:
   ```sh
   umask 077; printf '%s' 'TOKEN' > ~/.config/lattice-vault/claude.token
   ```
3. `claude_desktop_config.json`:
   ```json
   {
     "mcpServers": {
       "lattice-vault": {
         "command": "python3",
         "args": ["/path/to/lattice-vault/mcp_server.py"],
         "env": {
           "VAULT_DB": "/path/to/vault.db",
           "VAULT_AGENT_TOKEN_FILE": "/path/to/claude.token"
         }
       }
     }
   }
   ```

Claude artık `get_summary`, `search`, `export_context_pack`, `propose_event` kullanabilir.  
Yazdıkları “öneri” olarak gelir, sen CLI’den onaylarsın.

## ChatGPT / Gemini / DeepSeek (Context Pack)

```sh
python vault.py export-context --out pack.md --max-tokens 4000
```

`pack.md` içeriğini sohbetin başına yapıştır.

Örnek prompt:
```
Aşağıdaki Context Pack benim güncel kişisel vault’umdur. 
Buna göre cevap ver. Yeni bilgi önerirsen vault_update bloğu kullan.

<pack içeriği>
```

## Grok / diğer MCP destekleyenler

Claude ile aynı yapı. Sadece config dosyası farklı olabilir.

## Kural

- MCP varsa → araçlarla oku / öner.
- MCP yoksa → Context Pack yapıştır.
- Onay her zaman senin (CLI).
