import hashlib
import json
from datetime import datetime

from keyhold import model, watchtower, watchtower_online
from keyhold.generator import random_password

NOW = datetime(2026, 6, 15, 12, 0).timestamp()


def login(title, password="", websites=(), totp="", created=1.0, changed=None):
    item = model.new_item("login", vault_id="v", now=created)
    item.title = title
    item.field("password").value = password
    item.field("totp").value = totp
    item.fields = [f for f in item.fields if f.purpose != "website"]
    for w in websites:
        item.fields.append(model.Field.new("website", "url", w, "website"))
    item.password_changed = changed
    return item


def card(title, expiry):
    item = model.new_item("credit_card", vault_id="v", now=1.0)
    item.title = title
    next(f for f in item.fields if f.label == "expiry date").value = expiry
    return item


def test_weak_and_reused():
    strong = random_password(24)
    items = [login("a", "password1"), login("b", strong), login("c", strong), login("d", random_password(24))]
    report = watchtower.analyze(items, NOW)
    assert report["weak"] == {items[0].id}
    assert report["reused"] == {items[1].id, items[2].id}


def test_trashed_items_and_empty_passwords_are_ignored():
    strong = random_password(24)
    a, b, c = login("a", strong), login("b", strong), login("c", "")
    b.trashed_at = 5.0
    report = watchtower.analyze([a, b, c], NOW)
    assert report["reused"] == set()
    assert report["weak"] == set()


def test_unsecured_websites_skip_local_addresses():
    items = [
        login("plain", "x", ["http://shop.example.com/login"]),
        login("tls", "x", ["https://bank.example.com"]),
        login("router", "x", ["http://192.168.1.1"]),
        login("local", "x", ["http://localhost:8080", "http://nas.local"]),
        login("noscheme", "x", ["example.org"]),
    ]
    assert watchtower.analyze(items, NOW)["unsecured"] == {items[0].id}


def test_expiring_cards_within_30_days_or_expired():
    items = [card("expired", "01/2026"), card("this month", "06/2026"), card("later", "12/2027"), card("bad", "garbage")]
    assert watchtower.analyze(items, NOW)["expiring"] == {items[0].id, items[1].id}


def test_online_checks_are_empty_without_online_data():
    items = [login("a", "password1", ["https://adobe.com"])]
    report = watchtower.analyze(items, NOW)
    for key in ("vulnerable", "compromised", "inactive_2fa"):
        assert report[key] == set()


def test_vulnerable_passwords_use_sha1_counts():
    items = [login("a", "hunter2"), login("b", random_password(24))]
    sha = hashlib.sha1(b"hunter2").hexdigest().upper()
    report = watchtower.analyze(items, NOW, {"pwned": {sha: 17}})
    assert report["vulnerable"] == {items[0].id}


def test_inactive_2fa_matches_domains_and_subdomains_without_totp():
    items = [
        login("g", "x", ["https://accounts.google.com/signin"]),
        login("g2", "x", ["https://mail.google.com"], totp="JBSWY3DPEHPK3PXP"),
        login("other", "x", ["https://notgoogle.com"]),
        login("www", "x", ["https://www.github.com"]),
    ]
    report = watchtower.analyze(items, NOW, {"totp_domains": ["google.com", "github.com"]})
    assert report["inactive_2fa"] == {items[0].id, items[3].id}


def test_compromised_when_breach_is_newer_than_last_password_change():
    breach_ts_date = "2026-03-01"
    before = datetime(2026, 1, 1).timestamp()
    after = datetime(2026, 4, 1).timestamp()
    items = [
        login("old pw", "x", ["https://login.adobe.com"], created=before),
        login("changed since", "x", ["https://adobe.com"], created=before, changed=after),
        login("unrelated", "x", ["https://example.com"], created=before),
    ]
    online = {"breaches": [{"name": "Adobe", "domain": "adobe.com", "date": breach_ts_date}]}
    assert watchtower.analyze(items, NOW, online)["compromised"] == {items[0].id}


def test_counts_and_reasons():
    items = [login("a", "password1")]
    report = watchtower.analyze(items, NOW)
    assert watchtower.counts(report)["weak"] == 1
    assert "weak" in watchtower.reasons(report, items[0].id)


# --- online fetching (no real network) ------------------------------------

def test_pwned_check_sends_only_five_char_prefixes_and_ignores_padding():
    sha = hashlib.sha1(b"hunter2").hexdigest().upper()
    requested = []

    def fake_fetch(url, headers=None):
        requested.append((url, headers))
        assert url.startswith("https://api.pwnedpasswords.com/range/")
        prefix = url.rsplit("/", 1)[1]
        assert len(prefix) == 5
        if prefix == sha[:5]:
            return f"{sha[5:]}:42\r\n0000000000000000000000000000000000A:0\r\n".encode()
        return b"0000000000000000000000000000000000B:0\r\n"

    result = watchtower_online.pwned_check(["hunter2", "hunter2", "other-pass"], fetch=fake_fetch)
    assert result[sha] == 42
    assert hashlib.sha1(b"other-pass").hexdigest().upper() not in result or result[hashlib.sha1(b"other-pass").hexdigest().upper()] == 0
    assert len(requested) == 2  # one request per distinct prefix
    assert all(h.get("Add-Padding") == "true" for _, h in requested)


def test_parse_breaches_skips_fabricated_and_domainless():
    raw = json.dumps([
        {"Name": "Adobe", "Domain": "Adobe.com", "BreachDate": "2013-10-04", "IsFabricated": False, "IsSpamList": False},
        {"Name": "Fake", "Domain": "fake.com", "BreachDate": "2020-01-01", "IsFabricated": True, "IsSpamList": False},
        {"Name": "Combo", "Domain": "", "BreachDate": "2019-01-01", "IsFabricated": False, "IsSpamList": False},
    ]).encode()
    assert watchtower_online.parse_breaches(raw) == [{"name": "Adobe", "domain": "adobe.com", "date": "2013-10-04"}]


def test_parse_2fa_directory_collects_domains():
    raw = json.dumps([
        ["Google", {"domain": "google.com", "additional-domains": ["youtube.com"], "tfa": ["totp"]}],
        ["GitHub", {"domain": "github.com", "tfa": ["totp", "u2f"]}],
    ]).encode()
    assert watchtower_online.parse_2fa_directory(raw) == ["github.com", "google.com", "youtube.com"]


def test_refresh_reports_errors_without_losing_other_results():
    def fetch(url, headers=None):
        if "2fa.directory" in url:
            raise OSError("network down")
        if "haveibeenpwned" in url:
            return json.dumps([{"Name": "A", "Domain": "a.com", "BreachDate": "2020-01-01"}]).encode()
        return b""

    cache, errors = watchtower_online.refresh(["pw"], previous={"totp_domains": ["kept.com"]}, fetch=fetch, now=NOW)
    assert cache["breaches"][0]["domain"] == "a.com"
    assert cache["totp_domains"] == ["kept.com"]  # previous data kept when a source fails
    assert len(errors) == 1 and "2FA" in errors[0]
    assert cache["updated"] == NOW


def test_impossible_expiry_values_are_ignored_not_crashing():
    items = []
    for value in ("0000-12", "0000-01-01", "00/0000", "13/2026", "99999-01", "12/99999"):
        c = card(value, "01/2030")
        next(f for f in c.fields if f.label == "expiry date").value = value
        items.append(c)
    assert watchtower.analyze(items, NOW)["expiring"] == set()
