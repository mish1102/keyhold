"""Watchtower: security checks over the vault's items.

Offline checks (always on): weak, reused, unsecured websites, expiring.
Checks that need downloaded data (only when the user enables online checks;
see ``watchtower_online``): vulnerable passwords, compromised logins, inactive 2FA.
"""

from __future__ import annotations

import calendar
import hashlib
import ipaddress
import re
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse

from . import strength
from .model import Item

KEYS = ["compromised", "vulnerable", "reused", "weak", "unsecured", "inactive_2fa", "expiring"]
TITLES = {
    "compromised": "Compromised Logins",
    "vulnerable": "Vulnerable Passwords",
    "reused": "Reused Passwords",
    "weak": "Weak Passwords",
    "unsecured": "Unsecured Websites",
    "inactive_2fa": "Inactive 2FA",
    "expiring": "Expiring",
}
ICONS = {
    "compromised": "dialog-warning-symbolic",
    "vulnerable": "security-low-symbolic",
    "reused": "edit-copy-symbolic",
    "weak": "security-medium-symbolic",
    "unsecured": "channel-insecure-symbolic",
    "inactive_2fa": "keyhold-2fa-symbolic",
    "expiring": "alarm-symbolic",
}
ADVICE = {
    "compromised": "This website reported a data breach after you last changed this password. Change it now.",
    "vulnerable": "This password appears in known data breaches, so attackers will try it. Change it.",
    "reused": "This password is used for more than one item. If one site leaks it, the others are exposed.",
    "weak": "This password is easy to guess. Generate a stronger one.",
    "unsecured": "This website address uses http://, so your password can be read on the network. Use https:// if the site supports it.",
    "inactive_2fa": "This website supports one-time codes (2FA). Turn 2FA on there and save the code here.",
    "expiring": "This item has expired or expires within 30 days.",
}
ONLINE_KEYS = {"compromised", "vulnerable", "inactive_2fa"}
EXPIRY_WINDOW = 30 * 86400
_LOCAL_SUFFIXES = (".local", ".lan", ".home", ".home.arpa", ".internal", ".localdomain")


def host_of(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    if "://" not in url:
        url = "https://" + url
    try:
        host = (urlparse(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def _domain_match(host: str, domains: set[str]) -> bool:
    if not host:
        return False
    parts = host.split(".")
    return any(".".join(parts[i:]) in domains for i in range(len(parts) - 1))


def _is_local(host: str) -> bool:
    if host == "localhost" or host.endswith(_LOCAL_SUFFIXES) or "." not in host:
        return True
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _end_of_month(month: int, year: int) -> float:
    last = calendar.monthrange(year, month)[1]
    return datetime(year, month, last, 23, 59, 59).timestamp()


def parse_month_year(text: str) -> tuple[int, int] | None:
    text = text.strip()
    m = re.fullmatch(r"(\d{1,2})\s*/\s*(\d{2}|\d{4})", text)
    if m:
        month, year = int(m.group(1)), int(m.group(2))
        year += 2000 if year < 100 else 0
    else:
        m = re.fullmatch(r"(\d{4})-(\d{1,2})(?:-\d{1,2})?", text)
        if not m:
            return None
        year, month = int(m.group(1)), int(m.group(2))
    return (month, year) if 1 <= month <= 12 and 1900 <= year <= 9999 else None


def _expiry(item: Item) -> float | None:
    for f in item.fields:
        if f.kind in ("monthyear", "date") and "expir" in f.label.lower() and f.value.strip():
            parsed = parse_month_year(f.value)
            if parsed:
                try:
                    return _end_of_month(*parsed)
                except (ValueError, OverflowError, OSError):
                    return None
    return None


def _breach_ts(date: str) -> float | None:
    try:
        return datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


def sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def analyze(items: list[Item], now: float, online: dict | None = None) -> dict[str, set[str]]:
    online = online or {}
    report: dict[str, set[str]] = {k: set() for k in KEYS}
    active = [i for i in items if i.trashed_at is None]

    by_password: dict[str, list[str]] = defaultdict(list)
    pwned = online.get("pwned", {})
    for item in active:
        pw = item.password
        if not pw:
            continue
        by_password[pw].append(item.id)
        if strength.is_weak(pw):
            report["weak"].add(item.id)
        if pwned.get(sha1_hex(pw), 0) > 0:
            report["vulnerable"].add(item.id)
    for ids in by_password.values():
        if len(ids) > 1:
            report["reused"].update(ids)

    totp_domains = set(online.get("totp_domains", []))
    breaches = defaultdict(list)
    for b in online.get("breaches", []):
        ts = _breach_ts(b.get("date", ""))
        if ts is not None and b.get("domain"):
            breaches[b["domain"]].append(ts)

    for item in active:
        expiry = _expiry(item)
        if expiry is not None and expiry < now + EXPIRY_WINDOW:
            report["expiring"].add(item.id)
        if item.category != "login":
            continue
        hosts = [host_of(u) for u in item.websites]
        for url, host in zip(item.websites, hosts):
            if url.strip().lower().startswith("http://") and host and not _is_local(host):
                report["unsecured"].add(item.id)
        if totp_domains and not item.totp.strip() and any(_domain_match(h, totp_domains) for h in hosts):
            report["inactive_2fa"].add(item.id)
        if breaches and item.password:
            last_change = item.password_changed or item.created
            for h in hosts:
                parts = h.split(".")
                candidates = {".".join(parts[i:]) for i in range(len(parts) - 1)}
                if any(ts > last_change for d in candidates for ts in breaches.get(d, [])):
                    report["compromised"].add(item.id)
    return report


def counts(report: dict[str, set[str]]) -> dict[str, int]:
    return {k: len(report.get(k, ())) for k in KEYS}


def reasons(report: dict[str, set[str]], item_id: str) -> list[str]:
    return [k for k in KEYS if item_id in report.get(k, ())]
