"""Downloads for Watchtower's online checks. Only used when the user turns
online checks on in Preferences.

What leaves this computer:
* Pwned Passwords (api.pwnedpasswords.com): the first 5 hex characters of
  each password's SHA-1 hash (k-anonymity). Responses are padded so their
  size doesn't reveal anything either. Passwords and full hashes never leave.
* Breach list (haveibeenpwned.com) and 2FA directory (api.2fa.directory): the
  full public lists are downloaded. Nothing about your items is sent.
"""

from __future__ import annotations

import json
import urllib.request
from collections import defaultdict
from typing import Callable, Iterable

from .watchtower import sha1_hex

PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"
TOTP_DIRECTORY_URL = "https://api.2fa.directory/v3/totp.json"
USER_AGENT = "Keyhold-Password-Manager"
TIMEOUT = 20

Fetch = Callable[..., bytes]


def http_get(url: str, headers: dict | None = None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 (fixed https URLs)
        return resp.read(50 * 1024 * 1024)


def pwned_check(passwords: Iterable[str], fetch: Fetch = http_get) -> dict[str, int]:
    """Map SHA-1 (upper hex) -> breach count for every distinct password."""
    by_prefix: dict[str, set[str]] = defaultdict(set)
    for pw in passwords:
        if pw:
            h = sha1_hex(pw)
            by_prefix[h[:5]].add(h)
    result: dict[str, int] = {}
    for prefix, hashes in by_prefix.items():
        body = fetch(PWNED_RANGE_URL.format(prefix=prefix), headers={"Add-Padding": "true"})
        found = {}
        for line in body.decode("ascii", "replace").splitlines():
            suffix, _, count = line.strip().partition(":")
            if suffix and count.isdigit() and int(count) > 0:
                found[prefix + suffix.upper()] = int(count)
        for h in hashes:
            result[h] = found.get(h, 0)
    return result


def parse_breaches(raw: bytes) -> list[dict]:
    out = []
    for b in json.loads(raw):
        if b.get("IsFabricated") or b.get("IsSpamList"):
            continue
        domain = (b.get("Domain") or "").strip().lower()
        if domain and b.get("BreachDate"):
            out.append({"name": b.get("Name", domain), "domain": domain, "date": b["BreachDate"]})
    return out


def parse_2fa_directory(raw: bytes) -> list[str]:
    domains = set()
    for entry in json.loads(raw):
        if not isinstance(entry, list) or len(entry) != 2 or not isinstance(entry[1], dict):
            continue
        info = entry[1]
        for d in [info.get("domain", "")] + list(info.get("additional-domains", [])):
            if isinstance(d, str) and d.strip():
                domains.add(d.strip().lower())
    return sorted(domains)


def refresh(passwords: list[str], previous: dict, fetch: Fetch = http_get,
            now: float = 0.0) -> tuple[dict, list[str]]:
    """Run every online check. A source that fails keeps its previous data."""
    cache = dict(previous or {})
    errors = []
    try:
        cache["pwned"] = pwned_check(passwords, fetch)
    except Exception as exc:  # network, HTTP or parse errors
        errors.append(f"Couldn't check passwords against Pwned Passwords: {exc}")
    try:
        cache["breaches"] = parse_breaches(fetch(BREACHES_URL))
    except Exception as exc:
        errors.append(f"Couldn't download the breach list from Have I Been Pwned: {exc}")
    try:
        cache["totp_domains"] = parse_2fa_directory(fetch(TOTP_DIRECTORY_URL))
    except Exception as exc:
        errors.append(f"Couldn't download the 2FA Directory list: {exc}")
    cache["updated"] = now
    return cache, errors
