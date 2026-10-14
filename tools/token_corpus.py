"""Synthetic Turkish + English calibration corpus for token estimation (no personal data; generic phrases only).

Deterministic: `samples()` always returns the same list. Used by tools/calibrate_tokens.py (needs tiktoken) and by
test_tokens.py (reference counts stored in testdata/token_reference.json).
"""
import random

TR_WORDS = ("bugün yarın sabah akşam toplantı proje hedef karar öğrenme tercih çalışma ekip müşteri rapor sunum "
            "güncelleme süreç değişiklik doğrulama onay belge kayıt özet sonuç öneri planlama haftalık aylık yıllık "
            "geliştirme test yayın sürüm güvenlik şifreleme anahtar cihaz eşitleme yedekleme geri yükleme kullanıcı "
            "ayar bildirim zamanlama öncelik görev tamamlandı başladı ertelendi iptal edildi çok önemli şimdilik "
            "değerlendirme İstanbul Ankara İzmir ılık güneşli yağmurlu öğleden sonra çarşamba perşembe cumartesi "
            "kitap okumak yürüyüş spor beslenme uyku düzeni alışkanlık değiştirmek istiyorum düşünüyorum gerekiyor "
            "çünkü fakat ancak ayrıca böylece özellikle genellikle şöyle böyle hiç her zaman").split()
TR_SUFFIX = ("", "", "", "ler", "lar", "de", "da", "den", "dan", "e", "a", "i", "ı", "ü", "u", "nin", "nın", "imiz",
             "ımız", "leri", "ları", "ında", "inde", "dır", "dir", "mış", "miş", "ecek", "acak", "iyor", "ıyor")
EN_WORDS = ("today tomorrow morning evening meeting project goal decision learning preference work team customer "
            "report presentation update process change verification approval document record summary result "
            "proposal planning weekly monthly yearly development test release version security encryption key "
            "device sync backup restore user setting notification schedule priority task completed started "
            "postponed cancelled very important for now evaluation reading walking sports nutrition sleep habit "
            "change want think need because but however also therefore especially usually always never the a of "
            "and to in is that it for with as on be this by").split()
PUNCT = (".", ",", ":", ";", "!", "?", " -", " (", ")")


def _sentence(r, words, n, suffix=False):
    out = []
    for _ in range(n):
        w = r.choice(words)
        if suffix and r.random() < 0.5:
            w += r.choice(TR_SUFFIX)
        out.append(w)
    s = " ".join(out)
    return s[0].upper() + s[1:] + r.choice((".", ".", "!", "?"))


def _id(r):
    return "".join(r.choice("0123456789abcdef") for _ in range(8))


def samples():
    r = random.Random(20261015)
    out = []
    for i in range(30):
        out.append(("tr_prose", " ".join(_sentence(r, TR_WORDS, r.randint(5, 14), True) for _ in range(r.randint(1, 4)))))
    for i in range(30):
        out.append(("en_prose", " ".join(_sentence(r, EN_WORDS, r.randint(5, 14)) for _ in range(r.randint(1, 4)))))
    for i in range(20):
        out.append(("mixed", _sentence(r, TR_WORDS, r.randint(4, 9), True) + " " + _sentence(r, EN_WORDS, r.randint(4, 9))))
    for i in range(20):
        lang = TR_WORDS if i % 2 == 0 else EN_WORDS
        lines = [f"- {_sentence(r, lang, r.randint(3, 10), lang is TR_WORDS)} `ev:{_id(r)}` (2026-{r.randint(1,12):02d}-{r.randint(1,28):02d})"
                 for _ in range(r.randint(2, 8))]
        out.append(("pack_bullets_" + ("tr" if lang is TR_WORDS else "en"), "\n".join(lines)))
    for i in range(10):
        out.append(("yaml", "\n".join(f"{r.choice(EN_WORDS)}_{r.choice(EN_WORDS)}: \"{_sentence(r, TR_WORDS, r.randint(2, 6), True)}\""
                                      for _ in range(r.randint(3, 8)))))
    for i in range(10):
        out.append(("ids_numbers", " ".join(r.choice((_id(r), str(r.randint(0, 99999)), f"{r.randint(1,31)}.{r.randint(1,12)}.2026",
                                                      f"%{r.randint(1,100)}")) for _ in range(r.randint(5, 20)))))
    return out
