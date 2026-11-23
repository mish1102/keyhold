"""Vault encryption.

Key hierarchy:

    master password --Argon2id(salt, cost)--> key-encryption key (KEK, 32 bytes)
    KEK --ChaCha20-Poly1305--> wraps a random 32-byte vault key
    vault key --ChaCha20-Poly1305--> encrypts the vault JSON

The file header (format, version, cipher and KDF parameters) is bound to both
ciphertexts as associated data, so editing it makes the vault fail to open.
Every seal uses a fresh random nonce. Changing the master password generates a
new salt *and* a new vault key (see ``rekey``).

On-disk format (UTF-8 JSON):

    {"format": "keyhold-vault", "version": 1, "cipher": "chacha20-poly1305",
     "kdf": {"name": "argon2id", "salt": b64, "memory_kib": int,
             "iterations": int, "lanes": int},
     "key":  {"nonce": b64, "ct": b64},
     "data": {"nonce": b64, "ct": b64}}
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
import unicodedata
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

FORMAT = "keyhold-vault"
VERSION = 1
CIPHER = "chacha20-poly1305"
KEY_LEN = 32
NONCE_LEN = 12
SALT_LEN = 16

# Upper bounds accepted when *opening* a file, so a crafted vault cannot make
# us allocate absurd memory or spin for minutes before failing.
MAX_MEMORY_KIB = 1024 * 1024  # 1 GiB
MAX_ITERATIONS = 16
MAX_LANES = 8


class WrongPasswordError(Exception):
    """The master password did not unlock the vault key."""


class CorruptVaultError(Exception):
    """The file is not a Keyhold vault, or its contents were damaged."""


@dataclass(frozen=True)
class KdfCost:
    memory_kib: int
    iterations: int
    lanes: int


# ~1.4 s on a modern laptop CPU. Unlocking is the only time we pay it.
DEFAULT_COST = KdfCost(memory_kib=256 * 1024, iterations=3, lanes=4)


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def _normalize(password: str) -> bytes:
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def _derive(password: str, salt: bytes, cost: KdfCost) -> bytearray:
    kdf = Argon2id(
        salt=salt,
        length=KEY_LEN,
        iterations=cost.iterations,
        lanes=cost.lanes,
        memory_cost=cost.memory_kib,
    )
    return bytearray(kdf.derive(_normalize(password)))


def _zero(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


class VaultKey:
    """Unlocked key material for one vault. Call ``wipe()`` when locking."""

    def __init__(self, header: dict, key: bytearray, wrapped: dict):
        self.header = header
        self.key = key
        self.wrapped = wrapped
        self._wiped = False

    @property
    def cost(self) -> KdfCost:
        k = self.header["kdf"]
        return KdfCost(k["memory_kib"], k["iterations"], k["lanes"])

    def wipe(self) -> None:
        _zero(self.key)
        self._wiped = True

    @property
    def wiped(self) -> bool:
        return self._wiped


def _header(salt: bytes, cost: KdfCost) -> dict:
    return {
        "format": FORMAT,
        "version": VERSION,
        "cipher": CIPHER,
        "kdf": {
            "name": "argon2id",
            "salt": b64e(salt),
            "memory_kib": cost.memory_kib,
            "iterations": cost.iterations,
            "lanes": cost.lanes,
        },
    }


def _aad(header: dict, purpose: bytes) -> bytes:
    canonical = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    return canonical + b"|" + purpose


def new_vault_key(password: str, cost: KdfCost = DEFAULT_COST) -> VaultKey:
    """Create fresh key material protected by ``password``."""
    salt = os.urandom(SALT_LEN)
    header = _header(salt, cost)
    kek = _derive(password, salt, cost)
    try:
        key = bytearray(os.urandom(KEY_LEN))
        nonce = os.urandom(NONCE_LEN)
        ct = ChaCha20Poly1305(bytes(kek)).encrypt(nonce, bytes(key), _aad(header, b"key"))
    finally:
        _zero(kek)
    return VaultKey(header, key, {"nonce": b64e(nonce), "ct": b64e(ct)})


# Changing the master password: new salt, new KEK, new vault key.
rekey = new_vault_key


def seal(vault_key: VaultKey, plaintext: bytes) -> bytes:
    """Encrypt ``plaintext`` into the complete vault file bytes."""
    if vault_key.wiped:
        raise ValueError("vault key has been wiped (vault is locked)")
    nonce = os.urandom(NONCE_LEN)
    ct = ChaCha20Poly1305(bytes(vault_key.key)).encrypt(
        nonce, plaintext, _aad(vault_key.header, b"data")
    )
    doc = dict(vault_key.header)
    doc["key"] = vault_key.wrapped
    doc["data"] = {"nonce": b64e(nonce), "ct": b64e(ct)}
    return json.dumps(doc, indent=1).encode("utf-8")


def _parse(data: bytes) -> tuple[dict, KdfCost, bytes, dict, dict]:
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CorruptVaultError("not a Keyhold vault file") from exc
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise CorruptVaultError("not a Keyhold vault file")
    if doc.get("version") != VERSION or doc.get("cipher") != CIPHER:
        raise CorruptVaultError("unsupported vault version")
    try:
        kdf = doc["kdf"]
        if kdf["name"] != "argon2id":
            raise CorruptVaultError("unsupported key derivation")
        cost = KdfCost(int(kdf["memory_kib"]), int(kdf["iterations"]), int(kdf["lanes"]))
        salt = b64d(kdf["salt"])
        wrapped = {"nonce": doc["key"]["nonce"], "ct": doc["key"]["ct"]}
        payload = {"nonce": doc["data"]["nonce"], "ct": doc["data"]["ct"]}
        for part in (wrapped, payload):
            if len(b64d(part["nonce"])) != NONCE_LEN:
                raise CorruptVaultError("bad nonce")
            b64d(part["ct"])
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        if isinstance(exc, CorruptVaultError):
            raise
        raise CorruptVaultError("vault header is damaged") from exc
    if not (1 <= cost.lanes <= MAX_LANES and 1 <= cost.iterations <= MAX_ITERATIONS):
        raise CorruptVaultError("unreasonable key derivation parameters")
    if not (8 * cost.lanes <= cost.memory_kib <= MAX_MEMORY_KIB) or len(salt) < 8:
        raise CorruptVaultError("unreasonable key derivation parameters")
    header = _header(salt, cost)
    return header, cost, salt, wrapped, payload


def unseal(data: bytes, password: str) -> tuple[VaultKey, bytes]:
    """Open vault file bytes. Returns the unlocked key and the plaintext."""
    header, cost, salt, wrapped, payload = _parse(data)
    kek = _derive(password, salt, cost)
    try:
        key = bytearray(
            ChaCha20Poly1305(bytes(kek)).decrypt(
                b64d(wrapped["nonce"]), b64d(wrapped["ct"]), _aad(header, b"key")
            )
        )
    except InvalidTag as exc:
        raise WrongPasswordError("incorrect master password") from exc
    finally:
        _zero(kek)
    if len(key) != KEY_LEN:
        raise CorruptVaultError("vault key has the wrong length")
    try:
        plaintext = ChaCha20Poly1305(bytes(key)).decrypt(
            b64d(payload["nonce"]), b64d(payload["ct"]), _aad(header, b"data")
        )
    except InvalidTag as exc:
        _zero(key)
        raise CorruptVaultError("vault contents are damaged") from exc
    return VaultKey(header, key, wrapped), plaintext


def open_with_key(data: bytes, vault_key: VaultKey) -> bytes:
    """Decrypt a blob sealed earlier with this same unlocked key (no KDF run)."""
    header, _cost, _salt, wrapped, payload = _parse(data)
    if header != vault_key.header or wrapped != vault_key.wrapped or vault_key.wiped:
        raise CorruptVaultError("sealed with a different key")
    try:
        return ChaCha20Poly1305(bytes(vault_key.key)).decrypt(
            b64d(payload["nonce"]), b64d(payload["ct"]), _aad(header, b"data")
        )
    except InvalidTag as exc:
        raise CorruptVaultError("damaged") from exc


def check_password(vault_key: VaultKey, password: str) -> bool:
    """True if ``password`` unwraps this vault's key (used to confirm actions)."""
    k = vault_key.header["kdf"]
    kek = _derive(password, b64d(k["salt"]), vault_key.cost)
    try:
        candidate = ChaCha20Poly1305(bytes(kek)).decrypt(
            b64d(vault_key.wrapped["nonce"]),
            b64d(vault_key.wrapped["ct"]),
            _aad(vault_key.header, b"key"),
        )
    except InvalidTag:
        return False
    finally:
        _zero(kek)
    return hmac.compare_digest(candidate, bytes(vault_key.key))
