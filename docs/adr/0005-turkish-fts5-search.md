# ADR 0005 (D-005): Turkish-normalized full-text search (FTS5)
- **Status:** Accepted
- **Implementation:** Implemented; stemming planned

## Context
Content is largely Turkish; users type queries with or without Turkish characters and with mixed case
(`I/ı`, `İ/i`).

## Decision
Text is folded with a Turkish-aware casefold plus diacritic folding into a `text_norm` column on write;
FTS5 (`unicode61 remove_diacritics 2`) indexes that column; queries are folded with the same function.
Sensitive (encrypted) fields are never written to `text_norm`.

## Alternatives
ICU tokenizer (not available in stock SQLite builds); external search engine (not local-first/simple).

## Consequences
Accent- and case-insensitive matching works; no morphological analysis — prefix queries (`karar*`) are
recommended until a stemmer is added.
