#!/usr/bin/env python3
"""Context Pack Watcher — vault değişince otomatik pack üretir.

MCP'siz modeller (ChatGPT, Gemini, DeepSeek) için.
Yazma yapmaz. Sadece okur ve pack.md günceller.
"""
import argparse, os, sys, time
import vault

def generate_pack(db, out_path, max_tokens=4000):
    import context_export
    class Args:
        out = out_path
        max_tokens = max_tokens
        format = 2
        include_unverified = False
    context_export.run(db, Args)
    print(f"pack updated → {out_path}", file=sys.stderr)

def main():
    p = argparse.ArgumentParser(description="Watch vault and refresh Context Pack")
    p.add_argument("--out", default="pack.md", help="output file")
    p.add_argument("--max-tokens", type=int, default=4000)
    p.add_argument("--interval", type=float, default=2.0, help="seconds between checks")
    p.add_argument("--once", action="store_true", help="generate once and exit")
    args = p.parse_args()

    db_path = os.environ.get("VAULT_DB")
    if not db_path:
        print("VAULT_DB not set", file=sys.stderr)
        sys.exit(1)

    db = vault.connect(db_path)
    last_seq = -1

    while True:
        seq = db.execute("SELECT COALESCE(MAX(seq),0) FROM events").fetchone()[0]
        if seq != last_seq:
            generate_pack(db, args.out, args.max_tokens)
            last_seq = seq
        if args.once:
            break
        time.sleep(args.interval)

if __name__ == "__main__":
    main()
