import math
import string

import pytest

from keyhold import generator, strength


def test_random_password_has_requested_length_and_every_class():
    for _ in range(200):
        pw = generator.random_password(length=12, digits=True, symbols=True)
        assert len(pw) == 12
        assert any(c.islower() for c in pw)
        assert any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw)
        assert any(c in generator.SYMBOLS for c in pw)


def test_random_password_respects_disabled_classes():
    for _ in range(200):
        pw = generator.random_password(length=30, digits=False, symbols=False)
        assert all(c in string.ascii_letters for c in pw)


def test_avoid_ambiguous_characters():
    for _ in range(200):
        pw = generator.random_password(length=40, avoid_ambiguous=True)
        assert not set(pw) & set(generator.AMBIGUOUS)


def test_random_password_uses_the_whole_alphabet():
    seen = set()
    for _ in range(2000):
        seen.update(generator.random_password(length=20))
    assert seen == set(generator.alphabet(digits=True, symbols=True))


@pytest.mark.parametrize("length", [0, 3, 101])
def test_random_password_length_bounds(length):
    with pytest.raises(ValueError):
        generator.random_password(length=length)


def test_passphrase_words_come_from_the_wordlist():
    words = set(generator.wordlist())
    assert len(words) == 7776
    phrase = generator.passphrase(words=5, separator=".", capitalize=False)
    parts = phrase.split(".")
    # A few EFF words contain hyphens but never dots, so splitting on "." is exact.
    assert len(parts) == 5
    assert all(p in words for p in parts)


def test_passphrase_capitalize_and_number():
    phrase = generator.passphrase(words=4, separator=" ", capitalize=True, include_number=True)
    parts = phrase.split(" ")
    assert len(parts) == 4
    assert all(p[0].isupper() for p in parts)
    assert sum(c.isdigit() for c in phrase) == 1


@pytest.mark.parametrize("n", [2, 13])
def test_passphrase_word_bounds(n):
    with pytest.raises(ValueError):
        generator.passphrase(words=n)


def test_pin_is_digits():
    pin = generator.pin(length=8)
    assert len(pin) == 8 and pin.isdigit()
    with pytest.raises(ValueError):
        generator.pin(length=3)


def test_entropy_bits():
    size = len(generator.alphabet(digits=True, symbols=True))
    assert generator.entropy_bits("random", length=20, digits=True, symbols=True) == pytest.approx(20 * math.log2(size))
    assert generator.entropy_bits("words", words=4) == pytest.approx(4 * math.log2(7776))
    assert generator.entropy_bits("pin", length=6) == pytest.approx(6 * math.log2(10))


def test_generate_from_settings_dict():
    pw = generator.generate({"mode": "random", "length": 24, "digits": True, "symbols": False})
    assert len(pw) == 24
    phrase = generator.generate({"mode": "words", "words": 3, "separator": "-", "capitalize": False})
    assert len(phrase.split("-")) >= 3


# --- strength ---------------------------------------------------------------

def test_strength_labels_are_ordered():
    assert strength.LABELS == ["Terrible", "Weak", "Fair", "Good", "Very Good", "Excellent", "Fantastic"]


def test_empty_and_common_passwords_are_terrible():
    assert strength.estimate("").label == "Terrible"
    assert strength.estimate("password").label == "Terrible"
    assert strength.estimate("123456").label == "Terrible"


def test_dictionary_based_passwords_are_weak():
    for pw in ("Summer2024!", "P@ssw0rd2024", "iloveyou123", "Qwerty!234"):
        assert strength.estimate(pw).level <= 2, pw


def test_generated_random_password_is_fantastic():
    for _ in range(5):
        assert strength.estimate(generator.random_password(length=20)).label == "Fantastic"


def test_six_word_passphrase_is_at_least_good():
    assert strength.estimate(generator.passphrase(words=6)).level >= 3


def test_is_weak_matches_fair_or_below():
    assert strength.is_weak("password1")
    assert not strength.is_weak(generator.random_password(length=20))


def test_very_long_input_is_fast_and_bounded():
    s = strength.estimate("a" * 5000)
    assert s.level <= 1


def test_clear_cache_forgets_passwords():
    strength.estimate("cached secret")
    assert strength.estimate.cache_info().currsize > 0
    strength.clear_cache()
    assert strength.estimate.cache_info().currsize == 0


def test_master_password_is_rated_after_normalization():
    fullwidth = "ｐａｓｓｗｏｒｄ１２３４５６"  # NFKC -> "password123456"
    assert strength.estimate_master(fullwidth).level == strength.estimate("password123456").level
    assert strength.estimate_master(fullwidth).level <= 1
