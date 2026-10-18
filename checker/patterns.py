"""Weak-pattern detection: dictionary words, repeats, sequences, leetspeak, years.

All functions are pure: they take strings and return values. Nothing is
written, logged, or sent anywhere. The only I/O is a one-time READ of the
bundled common-password list.
"""
import re
from functools import lru_cache
from pathlib import Path

_WORDLIST = Path(__file__).with_name("common_passwords.txt")

# Common character substitutions. '1' and '!' are ambiguous (i or l),
# so we try both variants.
_LEET_BASE = {"@": "a", "4": "a", "0": "o", "3": "e", "$": "s",
              "5": "s", "7": "t", "+": "t", "8": "b", "9": "g"}
_LEET_VARIANTS = ({"1": "i", "!": "i"}, {"1": "l", "!": "l"})

SEQUENCE_SOURCES = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890",
)
MIN_SEQUENCE = 4
MIN_SUBSTRING_WORD = 5

_REPEAT_RE = re.compile(r"(.)\1{2,}")
_YEAR_RE = re.compile(r"(?:19|20)\d{2}")


@lru_cache(maxsize=1)
def common_passwords() -> frozenset:
    """Load the common-password list (read-only) into a set for O(1) lookup."""
    with open(_WORDLIST, "r", encoding="utf-8", errors="ignore") as fh:
        return frozenset(line.strip().lower() for line in fh if line.strip())


@lru_cache(maxsize=1)
def _long_words() -> tuple:
    """Alphabetic common words long enough to be meaningful as substrings."""
    return tuple(sorted(
        (w for w in common_passwords() if w.isalpha() and len(w) >= MIN_SUBSTRING_WORD),
        key=len, reverse=True))


def normalize_leet(password: str) -> list:
    """Return lowercase de-leetspeaked variants of the password."""
    base = password.lower()
    out = []
    for variant in _LEET_VARIANTS:
        table = str.maketrans({**_LEET_BASE, **variant})
        norm = base.translate(table)
        if norm not in out:
            out.append(norm)
    return out


def find_repeats(password: str) -> list:
    """Runs of 3+ identical characters, e.g. 'aaa', '111'."""
    return [m.group(0) for m in _REPEAT_RE.finditer(password)]


def find_sequences(password: str) -> list:
    """Alphabetic, numeric, and keyboard-row runs (forwards or backwards)."""
    pw = password.lower()
    sources = SEQUENCE_SOURCES + tuple(s[::-1] for s in SEQUENCE_SOURCES)
    found, i = [], 0
    while i <= len(pw) - MIN_SEQUENCE:
        best = ""
        for src in sources:
            j = i + MIN_SEQUENCE
            if pw[i:j] in src:
                while j < len(pw) and pw[i:j + 1] in src:
                    j += 1
                if j - i > len(best):
                    best = pw[i:j]
        if best:
            found.append(best)
            i += len(best)
        else:
            i += 1
    return found


def find_years(password: str) -> list:
    """Four-digit years 1900-2099, which are very guessable."""
    return _YEAR_RE.findall(password)


def _strip_edges(s: str) -> str:
    """Remove leading/trailing digits and symbols ('password123!' -> 'password')."""
    return re.sub(r"^[^a-z]+|[^a-z]+$", "", s)


def find_dictionary_matches(password: str) -> list:
    """Return dicts: {'word', 'exact', 'disguised'}.

    exact     - the whole password (ignoring leading/trailing digits/symbols)
                is itself a known common password.
    disguised - the match only appears after leetspeak normalisation.
    """
    words = common_passwords()
    raw = password.lower()
    raw_forms = {raw, _strip_edges(raw)}
    candidates = normalize_leet(password)
    matches = {}

    def record(word, exact, disguised):
        prev = matches.get(word)
        if prev is None or (prev["disguised"] and not disguised):
            matches[word] = {"word": word, "exact": exact, "disguised": disguised}

    # Whole-password matches.
    for form in raw_forms:
        if form and form in words:
            record(form, True, False)
    for cand in candidates:
        for form in (cand, _strip_edges(cand)):
            if form and form in words:
                record(form, True, form not in raw_forms)

    # Embedded words (e.g. 'MySummerHoliday' contains 'summer').
    if not any(m["exact"] for m in matches.values()):
        for cand in candidates:
            for word in _long_words():
                if word in cand:
                    record(word, False, word not in raw)
                    break
    return list(matches.values())
