"""Password strength estimate.

zxcvbn finds the guessable parts of a password (dictionary words, dates,
keyboard patterns, sequences, l33t substitutions). For the parts it can only
brute-force, zxcvbn assumes 10 possibilities per character, which badly
underrates truly random passwords. We keep zxcvbn's estimate for the patterns
and use the real character-set size for the brute-force parts, capped at a
pure brute-force estimate for the whole password.
"""

from __future__ import annotations

import math
import string
from dataclasses import dataclass
from functools import lru_cache

from zxcvbn import zxcvbn

LABELS = ["Terrible", "Weak", "Fair", "Good", "Very Good", "Excellent", "Fantastic"]
# Lower bound (bits) for each label after "Terrible".
THRESHOLDS = [25, 35, 50, 65, 80, 100]
MAX_ANALYZED = 72  # zxcvbn refuses longer inputs (and gets slow)


@dataclass(frozen=True)
class Strength:
    bits: float
    level: int  # index into LABELS

    @property
    def label(self) -> str:
        return LABELS[self.level]


def _charset_size(text: str) -> int:
    size = 0
    if any(c in string.ascii_lowercase for c in text):
        size += 26
    if any(c in string.ascii_uppercase for c in text):
        size += 26
    if any(c in string.digits for c in text):
        size += 10
    if any(c in string.punctuation or c == " " for c in text):
        size += 33
    if any(ord(c) > 127 for c in text):
        size += 100
    return max(size, 1)


def _level(bits: float) -> int:
    return sum(1 for t in THRESHOLDS if bits >= t)


@lru_cache(maxsize=8192)
def estimate(password: str) -> Strength:
    if not password:
        return Strength(0.0, 0)
    sample = password[:MAX_ANALYZED]
    result = zxcvbn(sample)
    bits = 0.0
    for match in result["sequence"]:
        token = match["token"]
        if match["pattern"] == "bruteforce":
            bits += len(token) * math.log2(_charset_size(token))
        else:
            bits += math.log2(max(float(match["guesses"]), 1.0))
    bits = min(bits, len(sample) * math.log2(_charset_size(sample)))
    return Strength(bits, _level(bits))


def is_weak(password: str) -> bool:
    """Watchtower's "weak password" rule: Fair or worse."""
    return estimate(password).level <= 2


def clear_cache() -> None:
    """Forget cached passwords (called when the vault locks)."""
    estimate.cache_clear()


def estimate_master(password: str) -> Strength:
    """Rate a master password the way the KDF will see it (NFKC-normalized)."""
    import unicodedata

    return estimate(unicodedata.normalize("NFKC", password))
