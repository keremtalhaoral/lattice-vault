"""Measure token-estimate error against real tokenizers (needs `pip install tiktoken`; not a runtime dependency).

python tools/calibrate_tokens.py            # print error table per method / category
python tools/calibrate_tokens.py --write    # refresh testdata/token_reference.json (reference counts)
"""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import tiktoken
import tokens
from token_corpus import samples

ENCS = ("o200k_base", "cl100k_base")
ref = {n: tiktoken.get_encoding(n) for n in ENCS}
rows = [{"cat": c, "text": t, **{n: len(ref[n].encode(t)) for n in ENCS}} for c, t in samples()]
if "--write" in sys.argv:
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "testdata", "token_reference.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"tiktoken": tiktoken.__version__, "encodings": list(ENCS),
                   "counts": [{"cat": r["cat"], **{n: r[n] for n in ENCS}} for r in rows]}, f, indent=0, ensure_ascii=False)
        f.write("\n")
print(json.dumps(tokens.error_report(rows, ENCS), indent=1))
