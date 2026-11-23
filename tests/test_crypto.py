import json

import pytest

from keyhold import crypto
from keyhold.crypto import CorruptVaultError, KdfCost, WrongPasswordError

# Tiny Argon2 cost so the suite stays fast. Production uses crypto.DEFAULT_COST.
FAST = KdfCost(memory_kib=1024, iterations=1, lanes=1)


def make(password="correct horse", plaintext=b'{"items": []}'):
    key = crypto.new_vault_key(password, cost=FAST)
    return key, crypto.seal(key, plaintext)


def test_unseal_returns_the_sealed_plaintext():
    _, blob = make(plaintext=b"secret data")
    key, plaintext = crypto.unseal(blob, "correct horse")
    assert plaintext == b"secret data"
    assert isinstance(key, crypto.VaultKey)


def test_wrong_password_is_rejected():
    _, blob = make()
    with pytest.raises(WrongPasswordError):
        crypto.unseal(blob, "Correct horse")


def test_tampered_payload_is_reported_as_corrupt_not_wrong_password():
    _, blob = make()
    doc = json.loads(blob)
    ct = bytearray(crypto.b64d(doc["data"]["ct"]))
    ct[0] ^= 0x01
    doc["data"]["ct"] = crypto.b64e(bytes(ct))
    with pytest.raises(CorruptVaultError):
        crypto.unseal(json.dumps(doc).encode(), "correct horse")


def test_tampered_header_cannot_be_opened():
    _, blob = make()
    doc = json.loads(blob)
    doc["kdf"]["iterations"] = 2
    with pytest.raises(WrongPasswordError):
        crypto.unseal(json.dumps(doc).encode(), "correct horse")


def test_every_seal_uses_a_fresh_nonce():
    key, first = make()
    second = crypto.seal(key, b'{"items": []}')
    a, b = json.loads(first), json.loads(second)
    assert a["data"]["nonce"] != b["data"]["nonce"]
    assert a["data"]["ct"] != b["data"]["ct"]


def test_resealing_with_the_unlocked_key_still_opens_with_the_password():
    _, blob = make()
    key, _ = crypto.unseal(blob, "correct horse")
    blob2 = crypto.seal(key, b"updated")
    assert crypto.unseal(blob2, "correct horse")[1] == b"updated"


def test_unicode_password_is_normalized():
    composed = "café secret"
    decomposed = "café secret"
    _, blob = make(password=composed)
    assert crypto.unseal(blob, decomposed)[1] == b'{"items": []}'


def test_garbage_input_is_corrupt():
    for junk in (b"", b"not json", b"{}", b'{"format": "something-else"}', b"[1,2]"):
        with pytest.raises(CorruptVaultError):
            crypto.unseal(junk, "x")


def test_absurd_kdf_parameters_are_rejected_before_deriving():
    _, blob = make()
    doc = json.loads(blob)
    doc["kdf"]["memory_kib"] = 64 * 1024 * 1024  # 64 GiB
    with pytest.raises(CorruptVaultError):
        crypto.unseal(json.dumps(doc).encode(), "correct horse")


def test_rekey_changes_password_and_key():
    key, _ = make()
    old_bytes = bytes(key.key)
    new_key = crypto.rekey("new password", cost=FAST)
    blob = crypto.seal(new_key, b"data")
    assert bytes(new_key.key) != old_bytes
    assert crypto.unseal(blob, "new password")[1] == b"data"
    with pytest.raises(WrongPasswordError):
        crypto.unseal(blob, "correct horse")


def test_check_password():
    key, _ = make()
    assert crypto.check_password(key, "correct horse")
    assert not crypto.check_password(key, "wrong")


def test_wipe_zeroes_key_material():
    key, _ = make()
    key.wipe()
    assert key.key == bytearray(len(key.key))
    with pytest.raises(ValueError):
        crypto.seal(key, b"x")


def test_default_cost_is_strong():
    assert crypto.DEFAULT_COST.memory_kib >= 256 * 1024
    assert crypto.DEFAULT_COST.iterations >= 3


def test_kdf_caps_reject_expensive_parameters_without_deriving():
    _, blob = make()
    for field, value in (("memory_kib", 2 * 1024 * 1024), ("iterations", 17), ("lanes", 9)):
        doc = json.loads(blob)
        doc["kdf"][field] = value
        with pytest.raises(CorruptVaultError):
            crypto.unseal(json.dumps(doc).encode(), "correct horse")


def test_open_with_key_reads_blobs_sealed_with_the_same_key_only():
    key, blob = make(plaintext=b"pending")
    assert crypto.open_with_key(blob, key) == b"pending"
    other, _ = make()
    with pytest.raises(CorruptVaultError):
        crypto.open_with_key(blob, other)
