"""Scoring engine. Takes a password string, returns an Analysis.

PRIVACY: the password is used only inside analyze() and is never stored in
the result, logged, written to disk, or sent over a network.
"""
from dataclasses import dataclass, field

from . import entropy, patterns

# Penalties (in bits) subtracted from the effective entropy.
PENALTY_DICTIONARY_WORD = 25
PENALTY_REPEAT = 8
PENALTY_REPEAT_MAX = 16
PENALTY_SEQUENCE = 10
PENALTY_SEQUENCE_MAX = 20
PENALTY_YEAR = 5
EXACT_COMMON_CAP = 10  # a known common password is capped at 10 bits

# Rating thresholds on final bits.
WEAK_MAX = 40
MODERATE_MAX = 60
STRONG_MAX = 80

GUESSES_PER_SECOND = 1e10  # offline attack against a fast hash


@dataclass(frozen=True)
class Finding:
    kind: str     # dictionary | leetspeak | repeat | sequence | year
    detail: str


@dataclass(frozen=True)
class Analysis:
    """Result of an analysis. Deliberately contains NO copy of the password."""
    score: int
    rating: str
    length: int
    pool_size: int
    pool_entropy: float
    shannon_per_char: float
    shannon_entropy: float
    effective_bits: float
    final_bits: float
    crack_time: str
    findings: tuple = field(default_factory=tuple)
    suggestions: tuple = field(default_factory=tuple)

    def has(self, kind: str) -> bool:
        return any(f.kind == kind for f in self.findings)


def rate(bits: float) -> str:
    if bits < WEAK_MAX:
        return "Weak"
    if bits < MODERATE_MAX:
        return "Moderate"
    if bits < STRONG_MAX:
        return "Strong"
    return "Very Strong"


def crack_time(bits: float) -> str:
    """Average-case time to brute-force: 2^(bits-1) / guesses-per-second."""
    seconds = (2 ** max(bits - 1, 0)) / GUESSES_PER_SECOND
    if seconds < 1:
        return "instantly"
    units = [("year", 31_557_600), ("day", 86_400), ("hour", 3_600),
             ("minute", 60), ("second", 1)]
    if seconds >= 31_557_600 * 1e9:
        return "billions of years or more"
    for name, size in units:
        if seconds >= size:
            n = seconds / size
            n_txt = f"{n:,.0f}" if n >= 10 else f"{n:.1f}"
            return f"~{n_txt} {name}{'' if n_txt in ('1', '1.0') else 's'}"
    return "instantly"


def analyze(password: str) -> Analysis:
    if not isinstance(password, str):
        raise TypeError("password must be a string")  # never echo the value

    length = len(password)
    pool = entropy.pool_size(password)
    p_ent = entropy.pool_entropy(password)
    s_pc = entropy.shannon_per_char(password)
    s_tot = entropy.shannon_total(password)
    bits = entropy.effective_entropy(password)

    findings, suggestions = [], []

    # --- dictionary / leetspeak ---
    matches = patterns.find_dictionary_matches(password)
    exact = [m for m in matches if m["exact"]]
    for m in matches:
        if m["disguised"]:
            findings.append(Finding(
                "leetspeak",
                f"Contains the common word '{m['word']}' disguised with character substitutions"))
        else:
            findings.append(Finding(
                "dictionary", f"Contains the common word/password '{m['word']}'"))
    if exact:
        bits = min(bits, EXACT_COMMON_CAP)
    elif matches:
        bits -= PENALTY_DICTIONARY_WORD

    # --- repeats ---
    repeats = patterns.find_repeats(password)
    for r in repeats:
        findings.append(Finding("repeat", f"Repeated characters: '{r}'"))
    bits -= min(PENALTY_REPEAT * len(repeats), PENALTY_REPEAT_MAX)

    # --- sequences ---
    seqs = patterns.find_sequences(password)
    for s in seqs:
        findings.append(Finding("sequence", f"Predictable sequence: '{s}'"))
    bits -= min(PENALTY_SEQUENCE * len(seqs), PENALTY_SEQUENCE_MAX)

    # --- years ---
    years = patterns.find_years(password)
    for y in years:
        findings.append(Finding("year", f"Looks like a year: '{y}'"))
    if years:
        bits -= PENALTY_YEAR

    bits = max(bits, 0.0)
    rating = rate(bits)
    score = min(100, round(bits / STRONG_MAX * 100))

    # --- suggestions ---
    if length == 0:
        suggestions.append("Enter a password to analyze.")
    else:
        if length < 12:
            suggestions.append("Increase length to at least 14 characters; "
                               "consider a passphrase of 4+ random words.")
        if not any(c.islower() for c in password):
            suggestions.append("Add lowercase letters.")
        if not any(c.isupper() for c in password):
            suggestions.append("Add uppercase letters.")
        if not any(c.isdigit() for c in password):
            suggestions.append("Add numbers.")
        if not any(not c.isalnum() for c in password):
            suggestions.append("Add special characters (e.g. ! # $ %).")
        if exact:
            suggestions.append("This is a well-known password; attackers try these first. "
                               "Choose something completely different.")
        elif matches:
            suggestions.append("Avoid dictionary words, even with substitutions like "
                               "'@' for 'a' - attackers apply those rules automatically.")
        if repeats:
            suggestions.append("Avoid repeated characters like 'aaa' or '111'.")
        if seqs:
            suggestions.append("Avoid sequences like '1234', 'abcd' or 'qwerty'.")
        if years:
            suggestions.append("Avoid years and dates; they are easy to guess.")
        if length >= 8 and s_pc < 2.5 and not repeats:
            suggestions.append("Use more distinct characters; many characters are reused.")
        if rating in ("Strong", "Very Strong") and not findings:
            suggestions.append("Looks good. Use a unique password per account and a password manager.")

    return Analysis(
        score=score, rating=rating, length=length, pool_size=pool,
        pool_entropy=round(p_ent, 2), shannon_per_char=round(s_pc, 3),
        shannon_entropy=round(s_tot, 2), effective_bits=round(min(p_ent, s_tot), 2),
        final_bits=round(bits, 2), crack_time=crack_time(bits),
        findings=tuple(findings), suggestions=tuple(suggestions),
    )
