"""Token estimation for context packs (ADR 0015).

Token counts depend on the model: GPT (o200k_base / cl100k_base), Claude and Gemini all use different tokenizers,
so every number here is an *estimate*. Budgets are enforced on `budget_tokens()`, which adds a safety margin.

* If the optional `tiktoken` package is installed, `estimate()` counts with the real o200k_base / cl100k_base
  encodings (and takes the larger of the two).
* Otherwise a calibrated heuristic is used. Its coefficients were fitted with tools/calibrate_tokens.py on a
  synthetic Turkish + English corpus (tools/token_corpus.py) and are checked in CI against stored reference counts
  (testdata/token_reference.json). Turkish words (agglutinative, non-ASCII letters) cost noticeably more tokens
  than English ones, which plain chars/4 badly underestimates.
"""
import math
import re

DEFAULT_MARGIN = 0.15
_PIECES = re.compile(r"[^\W\d_]+|\d+|\S", re.UNICODE)

# (ascii_word, ascii_letter, nonascii_word, nonascii_letter, digit, punct) -- fitted, see module docstring
COEFFS = {
    "o200k": (0.53, 0.09, 1.77, 0.15, 0.75, 0.75),
    "cl100k": (0.20, 0.15, 1.83, 0.33, 0.81, 0.78),
}

try:  # optional
    import tiktoken as _tiktoken
except Exception:  # pragma: no cover - depends on environment
    _tiktoken = None
_ENC = {}


def features(text):
    aw = al = nw = nl = dg = pu = 0
    for m in _PIECES.findall(text or ""):
        if m[0].isdigit():
            dg += len(m)
        elif m[0].isalpha():
            if m.isascii():
                aw += 1; al += len(m)
            else:
                nw += 1; nl += len(m)
        else:
            pu += 1
    return (aw, al, nw, nl, dg, pu)


def heuristic(text, model="o200k"):
    f = features(text)
    return int(math.ceil(sum(a * b for a, b in zip(COEFFS[model], f))))


def tiktoken_available():
    return _tiktoken is not None


def _tk(text, name):
    if name not in _ENC:
        _ENC[name] = _tiktoken.get_encoding(name)
    return len(_ENC[name].encode(text or "", disallowed_special=()))


METHODS = {
    "chars4": lambda t: int(math.ceil(len(t or "") / 4)),
    "chars3.5": lambda t: int(math.ceil(len(t or "") / 3.5)),
    "heuristic-o200k": lambda t: heuristic(t, "o200k"),
    "heuristic-cl100k": lambda t: heuristic(t, "cl100k"),
    "heuristic": lambda t: max(heuristic(t, "o200k"), heuristic(t, "cl100k")),
}


def method_name():
    return "tiktoken" if tiktoken_available() else "heuristic"


def estimate(text):
    """Best available estimate (conservative: larger of the GPT-family encodings), without margin."""
    if not text:
        return 0
    if tiktoken_available():
        try:
            return max(_tk(text, "o200k_base"), _tk(text, "cl100k_base"))
        except Exception:  # encoding files unavailable offline -> heuristic
            pass
    return METHODS["heuristic"](text)


def budget_tokens(text, margin=DEFAULT_MARGIN):
    """Estimate with safety margin; this is what budget trimming compares against max_tokens."""
    return int(math.ceil(estimate(text) * (1 + margin)))


def error_report(rows, encodings):
    """rows: [{'cat','text', <enc>: true_count}] -> signed mean / mean-abs / max-abs relative error (%) per method."""
    out = {}
    for m, fn in METHODS.items():
        for enc in encodings:
            per = {}
            for r in rows:
                e = (fn(r["text"]) - r[enc]) / r[enc]
                for k in ("ALL", r["cat"]):
                    per.setdefault(k, []).append(e)
            out[f"{m} vs {enc}"] = {k: {"mean": round(100 * sum(v) / len(v), 1),
                                        "mae": round(100 * sum(map(abs, v)) / len(v), 1),
                                        "max": round(100 * max(map(abs, v)), 1)} for k, v in sorted(per.items())}
    return out
