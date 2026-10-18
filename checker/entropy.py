"""Entropy calculations. Pure math: no I/O of any kind."""
import math
import string
from collections import Counter

LOWER = 26
UPPER = 26
DIGITS = 10
SYMBOLS = len(string.punctuation) + 1  # 32 punctuation chars + space = 33
OTHER_UNICODE = 100  # rough allowance for non-ASCII characters


def pool_size(password: str) -> int:
    """Size R of the character pool implied by the classes present."""
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += LOWER
    if any(c in string.ascii_uppercase for c in password):
        size += UPPER
    if any(c in string.digits for c in password):
        size += DIGITS
    if any(c in string.punctuation or c == " " for c in password):
        size += SYMBOLS
    if any(ord(c) > 127 for c in password):
        size += OTHER_UNICODE
    return size


def pool_entropy(password: str) -> float:
    """E = L * log2(R): theoretical search-space size in bits."""
    if not password:
        return 0.0
    return len(password) * math.log2(pool_size(password))


def shannon_per_char(password: str) -> float:
    """H = -sum(p_i * log2(p_i)): bits per character from symbol frequencies."""
    if not password:
        return 0.0
    n = len(password)
    h = -sum((c / n) * math.log2(c / n) for c in Counter(password).values())
    return h + 0.0  # normalise -0.0


def shannon_total(password: str) -> float:
    """Shannon entropy per character multiplied by length (total bits)."""
    return shannon_per_char(password) * len(password)


def effective_entropy(password: str) -> float:
    """Conservative estimate: the lower of pool-based and Shannon totals.

    Pool entropy assumes uniformly random characters; Shannon entropy reveals
    when the actual characters are repetitive. Taking the minimum prevents
    'aaaaaaaaaaaaaaaa' from being credited for its length.
    """
    return min(pool_entropy(password), shannon_total(password))
