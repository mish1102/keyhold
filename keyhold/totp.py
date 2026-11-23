"""Time-based one-time passwords (RFC 6238)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse

ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


@dataclass(frozen=True)
class OtpSpec:
    secret: bytes
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"
    issuer: str = ""
    account: str = ""


def _b32decode(text: str) -> bytes:
    cleaned = "".join(text.split()).replace("-", "").upper().rstrip("=")
    if not cleaned:
        raise ValueError("the secret is empty")
    cleaned += "=" * (-len(cleaned) % 8)
    try:
        secret = base64.b32decode(cleaned)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("the secret isn't valid Base32 (letters A–Z and digits 2–7)") from exc
    if not secret:
        raise ValueError("the secret is empty")
    return secret


def parse(value: str) -> OtpSpec:
    """Parse an ``otpauth://totp/...`` URI or a bare Base32 secret."""
    value = (value or "").strip()
    if not value:
        raise ValueError("no one-time password secret")
    if not value.lower().startswith("otpauth://"):
        return OtpSpec(_b32decode(value))

    url = urlparse(value)
    if url.netloc.lower() != "totp":
        raise ValueError("only time-based (TOTP) codes are supported")
    params = {k.lower(): v[0] for k, v in parse_qs(url.query).items()}
    if "secret" not in params:
        raise ValueError("the otpauth link has no secret")
    label = unquote(url.path.lstrip("/"))
    issuer = params.get("issuer", "")
    account = label
    if ":" in label:
        label_issuer, account = label.split(":", 1)
        issuer = issuer or label_issuer
    algorithm = params.get("algorithm", "SHA1").upper()
    if algorithm not in ALGORITHMS:
        raise ValueError(f"unsupported algorithm {algorithm}")
    try:
        digits = int(params.get("digits", 6))
        period = int(params.get("period", 30))
    except ValueError as exc:
        raise ValueError("digits and period must be numbers") from exc
    if not 6 <= digits <= 10:
        raise ValueError("codes must have 6 to 10 digits")
    if not 1 <= period <= 3600:
        raise ValueError("the period must be between 1 and 3600 seconds")
    return OtpSpec(_b32decode(params["secret"]), digits, period, algorithm, issuer.strip(), account.strip())


def code(spec: OtpSpec, at: float) -> str:
    counter = int(at // spec.period)
    digest = hmac.new(spec.secret, struct.pack(">Q", counter), ALGORITHMS[spec.algorithm]).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10 ** spec.digits).zfill(spec.digits)


def seconds_remaining(spec: OtpSpec, at: float) -> int:
    return spec.period - int(at % spec.period)


def format_code(text: str) -> str:
    if len(text) == 6:
        return f"{text[:3]} {text[3:]}"
    return f"{text[:4]} {text[4:]}"
