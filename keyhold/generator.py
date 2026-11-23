"""Password, passphrase and PIN generation using the OS CSPRNG (``secrets``)."""

from __future__ import annotations

import math
import secrets
import string
from functools import lru_cache
from pathlib import Path

# Symbols accepted by nearly every site. Quotes, backslash, backtick, spaces and
# angle brackets are left out because many forms reject or mangle them.
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/~"
AMBIGUOUS = "Il1O0o"
WORDLIST_PATH = Path(__file__).with_name("eff_large_wordlist.txt")


def alphabet(digits: bool = True, symbols: bool = True, avoid_ambiguous: bool = False) -> str:
    chars = string.ascii_lowercase + string.ascii_uppercase
    if digits:
        chars += string.digits
    if symbols:
        chars += SYMBOLS
    if avoid_ambiguous:
        chars = "".join(c for c in chars if c not in AMBIGUOUS)
    return chars


def random_password(length: int = 20, digits: bool = True, symbols: bool = True,
                    avoid_ambiguous: bool = False) -> str:
    """Uniformly random password containing at least one of each enabled class.

    Rejection sampling keeps the result uniform over all valid passwords.
    """
    if not 4 <= length <= 100:
        raise ValueError("length must be between 4 and 100")
    chars = alphabet(digits, symbols, avoid_ambiguous)
    classes = [string.ascii_lowercase, string.ascii_uppercase]
    if digits:
        classes.append(string.digits)
    if symbols:
        classes.append(SYMBOLS)
    while True:
        candidate = "".join(secrets.choice(chars) for _ in range(length))
        if all(any(c in cls for c in candidate) for cls in classes):
            return candidate


@lru_cache(maxsize=1)
def wordlist() -> tuple[str, ...]:
    """EFF large diceware wordlist (7,776 words, CC BY 3.0 US)."""
    words = tuple(w for w in WORDLIST_PATH.read_text(encoding="ascii").split() if w)
    if len(words) != 7776:
        raise RuntimeError("the bundled wordlist is damaged")
    return words


def passphrase(words: int = 4, separator: str = "-", capitalize: bool = True,
               include_number: bool = False) -> str:
    if not 3 <= words <= 12:
        raise ValueError("a passphrase needs 3 to 12 words")
    chosen = [secrets.choice(wordlist()) for _ in range(words)]
    if capitalize:
        chosen = [w[0].upper() + w[1:] for w in chosen]
    if include_number:
        i = secrets.randbelow(words)
        chosen[i] = chosen[i] + str(secrets.randbelow(10))
    return separator.join(chosen)


def pin(length: int = 6) -> str:
    if not 4 <= length <= 12:
        raise ValueError("a PIN needs 4 to 12 digits")
    return "".join(secrets.choice(string.digits) for _ in range(length))


def entropy_bits(mode: str, length: int = 20, digits: bool = True, symbols: bool = True,
                 avoid_ambiguous: bool = False, words: int = 4, include_number: bool = False,
                 **_ignored) -> float:
    """Entropy of the *generator settings* (not of a particular output)."""
    if mode == "random":
        return length * math.log2(len(alphabet(digits, symbols, avoid_ambiguous)))
    if mode == "words":
        bits = words * math.log2(len(wordlist()))
        if include_number:
            bits += math.log2(10 * words)
        return bits
    if mode == "pin":
        return length * math.log2(10)
    raise ValueError(f"unknown mode {mode!r}")


def generate(settings: dict) -> str:
    mode = settings.get("mode", "random")
    if mode == "random":
        return random_password(
            length=int(settings.get("length", 20)),
            digits=bool(settings.get("digits", True)),
            symbols=bool(settings.get("symbols", True)),
            avoid_ambiguous=bool(settings.get("avoid_ambiguous", False)),
        )
    if mode == "words":
        return passphrase(
            words=int(settings.get("words", 4)),
            separator=str(settings.get("separator", "-")),
            capitalize=bool(settings.get("capitalize", True)),
            include_number=bool(settings.get("include_number", False)),
        )
    if mode == "pin":
        return pin(length=int(settings.get("length", 6)))
    raise ValueError(f"unknown mode {mode!r}")
