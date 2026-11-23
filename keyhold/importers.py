"""Import items from other password managers, and export Keyhold items as CSV.

``import_file`` recognises the format from the file's contents, not its name:

* CSV exports from Chrome/Edge/Brave, Firefox, Safari, Bitwarden, 1Password,
  KeePassXC, LastPass and Keyhold itself, plus any other CSV file that has a
  recognisable username or password column;
* Bitwarden unencrypted JSON exports;
* 1Password ``.1pux`` exports.

Guiding rule: non-empty source data is never dropped silently. Anything that
has no natural home in a Keyhold item becomes an extra field, and anything
that cannot be represented at all is reported in ``ImportResult.warnings``.
Malformed input raises ``ImportFormatError`` rather than importing a guess.
"""

from __future__ import annotations

import codecs
import csv
import dataclasses
import io
import json
import math
import pathlib
import re
import zipfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from keyhold.model import CATEGORIES, FIELD_KINDS, Field, Item, new_item

__all__ = ["ImportFormatError", "ImportResult", "import_file", "export_csv"]


class ImportFormatError(Exception):
    """The file can't be imported. ``str(error)`` is a message meant for the user."""


@dataclasses.dataclass
class ImportResult:
    items: list[Item]
    source: str  # human name of the detected format, e.g. "Chrome CSV"
    warnings: list[str] = dataclasses.field(default_factory=list)


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


# Real exports are a few MB at most. These caps stop a huge or malicious file
# (e.g. a zip bomb posing as .1pux) from exhausting memory.
MAX_IMPORT_BYTES = 64 * 1024 * 1024
MAX_EXPORT_DATA_BYTES = 256 * 1024 * 1024
MAX_TIMESTAMP = 253402300799.0  # 9999-12-31


def import_file(path: pathlib.Path, vault_id: str, now: float) -> ImportResult:
    """Read an export file and return new items for ``vault_id``.

    Raises ``ImportFormatError`` (with a user-facing message) when the file
    can't be read or isn't a supported export.
    """
    path = pathlib.Path(path)
    try:
        if path.stat().st_size > MAX_IMPORT_BYTES:
            raise ImportFormatError(f"“{path.name}” is too large to be a password export "
                                    f"(over {MAX_IMPORT_BYTES // (1024 * 1024)} MB).")
        data = path.read_bytes()
    except OSError as exc:
        raise ImportFormatError(f"Couldn't read “{path.name}”: {exc.strerror or exc}.") from None
    if not data.strip():
        raise ImportFormatError(f"“{path.name}” is empty.")
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return _import_zip(data, vault_id, now)
    text = _decode(data)
    if text.lstrip().startswith(("{", "[")):
        return _import_json(text, vault_id, now)
    return _import_csv(text, vault_id, now)


def _decode(data: bytes) -> str:
    encoding = "utf-16" if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)) else "utf-8-sig"
    try:
        text = data.decode(encoding)
    except UnicodeDecodeError:
        raise ImportFormatError(
            "This file isn't a supported export: it isn't UTF-8 text. If it is a CSV file that was "
            "re-saved by a spreadsheet program, export it again from your password manager "
            "(or save it as “CSV UTF-8”) and import that file."
        ) from None
    text = text.lstrip("﻿")
    if "\x00" in text:
        raise ImportFormatError("This file contains binary data and isn't a supported export.")
    return text


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------

_PURPOSE_DEFAULTS = {
    "username": ("username", "text"),
    "password": ("password", "concealed"),
    "totp": ("one-time password", "totp"),
    "website": ("website", "url"),
}

_SECRET_LABEL = re.compile(
    r"\b(pass(word|wd|phrase|code)?|pwd|pins?|secret|cvv2?|cvc|security code|token|answer|ssn|"
    r"(private|secret|api|access|recovery|license|product|encryption)[ _-]?key)\b",
    re.IGNORECASE,
)
_URL_VALUE = re.compile(r"(?i)https?://\S+")
_EMAIL_VALUE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_MONTHYEAR_VALUE = re.compile(r"(0[1-9]|1[0-2])/\d{4}")
_DATE_VALUE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _str(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value) -> list:
    return value if isinstance(value, list) else []


def _is_empty(value) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _clean_text(text: str) -> str:
    """Normalise Windows / old Mac line breaks (for notes and multi-line text, never secrets)."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _truthy(value) -> bool:
    return _str(value).strip().lower() in {"1", "true", "yes", "y", "x", "t", "on", "✓", "checked"}


def _dedupe(values) -> list[str]:
    out: list[str] = []
    for v in values:
        v = v.strip()
        if v and v not in out:
            out.append(v)
    return out


def _guess_kind(label: str, value: str, *, secret_hint: bool = True) -> str:
    """Pick a field kind for untyped source data (unknown CSV columns, custom fields)."""
    if secret_hint and _SECRET_LABEL.search(label):
        return "concealed"
    v = value.strip()
    if v.lower().startswith("otpauth://"):
        return "totp"
    if "\n" in v:
        return "multiline"
    if _URL_VALUE.fullmatch(v):
        return "url"
    if _EMAIL_VALUE.fullmatch(v):
        return "email"
    return "text"


def _words(key: str) -> str:
    """``passportNumber`` -> ``passport number``."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", key).replace("_", " ").lower()


def _extra(item: Item, label: str, kind: str, value: str) -> Field:
    """Append a non-template field."""
    if kind not in FIELD_KINDS:
        kind = "text"
    if kind == "text" and "\n" in value:
        kind = "multiline"
    if kind == "multiline":
        value = _clean_text(value)
    f = Field.new(label or "field", kind, value)
    item.fields.append(f)
    return f


def _put(item: Item, purpose: str, value: str, *, label: str | None = None, kind: str | None = None,
         keep_purpose: bool = False) -> None:
    """Store a username/password/totp/website value.

    Fills the item's first empty field with that purpose. Otherwise appends a
    new field (keeping source order): extra websites keep the "website" purpose
    (so ``Item.websites`` lists them); other values become plain extra fields
    unless ``keep_purpose`` is set (used when re-importing Keyhold's own export).
    """
    if value == "":
        return
    same = [f for f in item.fields if f.purpose == purpose]
    for f in same:
        if f.value == "":
            f.value = value
            return
    default_label, default_kind = _PURPOSE_DEFAULTS.get(purpose, (purpose, "text"))
    kind = kind if kind in FIELD_KINDS else default_kind
    if keep_purpose or (purpose == "website" and same):
        item.fields.append(Field.new(label or default_label, kind, value, purpose))
    else:
        _extra(item, label or default_label, kind, value)


def _fill_template(item: Item, label: str, value: str) -> bool:
    """Put ``value`` into the empty template field called ``label``; False if there is none."""
    want = label.lower()
    for f in item.fields:
        if f.purpose is None and f.value == "" and f.label.lower() == want:
            if f.kind == "monthyear" and not _MONTHYEAR_VALUE.fullmatch(value):
                return False
            if f.kind == "date" and not _DATE_VALUE.fullmatch(value):
                return False
            f.value = value
            return True
    return False


def _template_or_extra(item: Item, label: str, value: str, kind: str = "text") -> None:
    if value != "" and not _fill_template(item, label, value):
        _extra(item, label, kind, value)


def _flatten(item: Item, obj: dict) -> None:
    """Keep every non-empty value of ``obj`` as an extra field (used for data without a mapping)."""
    for key, val in obj.items():
        if _is_empty(val) or isinstance(val, bool):
            continue
        label = _words(str(key))
        text = _str(val)
        _extra(item, label, _guess_kind(label, text), text)


def _hostname(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    try:
        host = urlsplit(url if "://" in url else "//" + url).hostname or ""
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def _derive_title(item: Item) -> str:
    for f in item.fields:
        if (f.purpose == "website" or f.kind == "url") and f.value.strip():
            host = _hostname(f.value)
            if host:
                return host
    for f in item.fields:
        if (f.purpose == "username" or f.label.lower() == "username") and f.value.strip():
            return f.value.strip()
    return "Untitled"


def _finish(item: Item, now: float, created: float | None = None, modified: float | None = None) -> Item:
    if created is None:
        created = modified
    if modified is None:
        modified = created
    item.created = created if created is not None else now
    item.modified = modified if modified is not None else now
    item.title = item.title.strip() or _derive_title(item)
    return item


def _parse_time(value, unit: str = "auto") -> float | None:
    """Epoch seconds from epoch s/ms numbers or ISO-8601 text; None if unknown or unreadable."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        num = float(value)
    else:
        text = str(value).strip()
        if not text:
            return None
        try:
            num = float(text)
        except ValueError:
            try:
                dt = datetime.fromisoformat(text)
            except ValueError:
                return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
    if not math.isfinite(num) or num <= 0:
        return None
    if unit == "ms" or (unit == "auto" and num > 1e11):  # 1e11 s is year 5138; 1e11 ms is 1973
        num /= 1000.0
    if num > MAX_TIMESTAMP:
        return None
    return num


def _password_history(entries, value_key: str, time_key: str, now: float) -> list[dict]:
    history = []
    for entry in _list(entries):
        if isinstance(entry, dict) and _str(entry.get(value_key)) != "":
            history.append({"value": _str(entry.get(value_key)),
                            "replaced_at": _parse_time(entry.get(time_key)) or now})
    history.sort(key=lambda h: h["replaced_at"], reverse=True)
    return history


def _address(street_lines, city: str, state: str, postal: str, country: str) -> str:
    lines = [s for s in street_lines if s]
    region = " ".join(p for p in (state, postal) if p)
    locality = ", ".join(p for p in (city, region) if p)
    if locality:
        lines.append(locality)
    if country:
        lines.append(country)
    return "\n".join(lines)


def _month_year(month, year) -> str | None:
    """("3", "2027") -> "03/2027"; None if either part is missing or invalid."""
    m, y = _str(month).strip(), _str(year).strip()
    if len(y) == 2 and y.isdigit():
        y = "20" + y
    if not (m.isdigit() and y.isdigit() and len(y) == 4 and 1 <= int(m) <= 12):
        return None
    return f"{int(m):02d}/{y}"


def _n(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


@dataclasses.dataclass
class _Report:
    """Things worth telling the user about, collected while importing."""

    empty_rows: int = 0
    ragged_rows: int = 0
    bad_dates_kept: int = 0
    bad_dates: int = 0
    skipped_entries: int = 0
    linked_fields: int = 0
    recycle_bin: int = 0
    damaged_fields: int = 0
    unsupported: Counter = dataclasses.field(default_factory=Counter)  # type name -> count
    unknown_types: Counter = dataclasses.field(default_factory=Counter)  # Bitwarden CSV type -> count
    bad_categories: Counter = dataclasses.field(default_factory=Counter)  # Keyhold CSV category -> count
    kept_as_fields: Counter = dataclasses.field(default_factory=Counter)  # what -> count
    attachments: list = dataclasses.field(default_factory=list)  # (item title, file name)

    def warnings(self, items: list[Item]) -> list[str]:
        out = []
        if self.empty_rows:
            out.append(f"Skipped {_n(self.empty_rows, 'empty row')}.")
        if self.ragged_rows:
            out.append(
                f"{_n(self.ragged_rows, 'row')} didn't have the same number of columns as the header row; "
                "please check those items (any extra values were kept as “Column N” fields)."
            )
        if self.skipped_entries:
            out.append(f"Skipped {_n(self.skipped_entries, 'entry', 'entries')} that weren't items.")
        if self.bad_dates_kept:
            out.append(
                f"{_n(self.bad_dates_kept, 'date')} couldn't be read; the text was kept in a field and the "
                "import time was used instead."
            )
        if self.bad_dates:
            out.append(f"{_n(self.bad_dates, 'date')} couldn't be read; the import time was used instead.")
        if self.unsupported:
            detail = ", ".join(f"{name} ({count})" for name, count in sorted(self.unsupported.items()))
            out.append(
                f"Imported {_n(sum(self.unsupported.values()), 'item')} as secure notes because Keyhold has no "
                f"matching category (all their data was kept in fields): {detail}."
            )
        if self.unknown_types:
            detail = ", ".join(f"“{name}” ({count})" for name, count in sorted(self.unknown_types.items()))
            out.append(f"Imported {_n(sum(self.unknown_types.values()), 'row')} with an unknown type as logins: {detail}.")
        if self.bad_categories:
            detail = ", ".join(f"“{name}” ({count})" for name, count in sorted(self.bad_categories.items()))
            out.append(
                f"Imported {_n(sum(self.bad_categories.values()), 'item')} with an unknown category as secure notes: "
                f"{detail}."
            )
        if self.attachments:
            files = ", ".join(f"{name} (in “{title}”)" for title, name in self.attachments)
            out.append(
                f"Keyhold can't store file attachments, so {_n(len(self.attachments), 'file')} "
                f"{'was' if len(self.attachments) == 1 else 'were'} not imported; the file names were kept in an "
                f"“attachment” field: {files}."
            )
        if self.kept_as_fields:
            detail = ", ".join(f"{name} ({count})" for name, count in sorted(self.kept_as_fields.items()))
            out.append(f"Some data has no direct equivalent in Keyhold and was kept in extra fields: {detail}.")
        if self.linked_fields:
            out.append(
                f"Skipped {_n(self.linked_fields, 'linked custom field')} (they have no value of their own; "
                "they only point at another field of the same item)."
            )
        if self.recycle_bin:
            out.append(
                f"{_n(self.recycle_bin, 'item')} came from the KeePassXC Recycle Bin; "
                "they were imported with the tag “Recycle Bin”."
            )
        if self.damaged_fields:
            out.append(
                f"{_n(self.damaged_fields, 'item')} had an unreadable “Fields” column; its text was kept "
                "in a field named “Fields”."
            )
        if not items:
            out.append("No items were found in this file.")
        return out


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

_NOISE_COLUMNS = {"guid", "httprealm", "formactionorigin", "icon", "reprompt", "timelastused"}
_KEYHOLD_COLUMNS = ["Category", "Title", "Url", "Username", "Password", "OTPAuth", "Favorite", "Tags", "Notes", "Fields"]


@dataclasses.dataclass(frozen=True)
class _CsvFormat:
    source: str
    columns: dict  # normalised header -> role
    time_unit: str = "auto"


# Roles: title, url, urls (comma separated), lp_url (LastPass: "http://sn" marks a secure note),
# username, password, totp, notes, tags, folder, group (KeePassXC path), favorite, archived,
# bw_type, bw_fields ("name: value" lines), created, modified, pw_changed.
_CHROME = _CsvFormat("Chrome CSV", {
    "name": "title", "url": "url", "username": "username", "password": "password", "note": "notes"})
_FIREFOX = _CsvFormat("Firefox CSV", {
    "url": "url", "username": "username", "password": "password",
    "timecreated": "created", "timepasswordchanged": "pw_changed"}, time_unit="ms")
_SAFARI = _CsvFormat("Safari CSV", {
    "title": "title", "url": "url", "username": "username", "password": "password", "notes": "notes",
    "otpauth": "totp"})
_BITWARDEN = _CsvFormat("Bitwarden CSV", {
    "folder": "folder", "favorite": "favorite", "type": "bw_type", "name": "title", "notes": "notes",
    "fields": "bw_fields", "login_uri": "urls", "login_username": "username", "login_password": "password",
    "login_totp": "totp", "collections": "tags"})
_ONEPASSWORD = _CsvFormat("1Password CSV", {
    "title": "title", "url": "url", "username": "username", "password": "password", "otpauth": "totp",
    "favorite": "favorite", "archived": "archived", "tags": "tags", "notes": "notes"})
_KEEPASSXC = _CsvFormat("KeePassXC CSV", {
    "group": "group", "title": "title", "username": "username", "password": "password", "url": "url",
    "notes": "notes", "totp": "totp", "last modified": "modified", "created": "created", "tags": "tags"})
_LASTPASS = _CsvFormat("LastPass CSV", {
    "url": "lp_url", "username": "username", "password": "password", "totp": "totp", "extra": "notes",
    "name": "title", "grouping": "folder", "fav": "favorite"})

# Generic CSV: role -> accepted header names (lower case, non-alphanumerics removed), best first.
_SYNONYMS = {
    "title": ("title", "name", "account", "accountname", "entry", "entryname", "itemname", "service",
              "servicename", "sitename", "displayname"),
    "url": ("url", "uri", "website", "websiteurl", "loginurl", "loginuri", "site", "siteurl", "webaddress",
            "link", "hostname", "host", "origin", "domain"),
    "username": ("username", "user", "userid", "login", "loginname", "loginusername", "email", "emailaddress",
                 "mail"),
    "password": ("password", "pass", "passwd", "pwd", "passphrase", "loginpassword"),
    "totp": ("totp", "otp", "otpauth", "otpsecret", "totpsecret", "otpurl", "onetimepassword", "2fa",
             "twofactor", "mfa", "logintotp", "authenticator"),
    "notes": ("notes", "note", "notesplain", "comments", "comment", "extra", "description", "memo", "remarks"),
    "tags": ("tags", "tag", "labels"),
    "folder": ("folder", "group", "grouping", "collection", "path"),
    "favorite": ("favorite", "favourite", "fav", "starred", "isfavorite"),
    "created": ("created", "createdat", "creationdate", "datecreated", "creationtime", "createtime",
                "timecreated"),
    "modified": ("modified", "lastmodified", "modifiedat", "updated", "updatedat", "revisiondate",
                 "datemodified", "lastupdated", "modificationtime", "modifytime"),
}


def _norm(header: str) -> str:
    return header.replace("﻿", "").strip().lower()


def _squash(header: str) -> str:
    return re.sub(r"[^a-z0-9]", "", _norm(header))


_KNOWN_COLUMNS = (
    {_squash(name) for fmt in (_CHROME, _FIREFOX, _SAFARI, _BITWARDEN, _ONEPASSWORD, _KEEPASSXC, _LASTPASS)
     for name in fmt.columns}
    | {syn for synonyms in _SYNONYMS.values() for syn in synonyms}
    | {_squash(c) for c in _KEYHOLD_COLUMNS}
    | {_squash(c) for c in _NOISE_COLUMNS}
)


def _guess_delimiter(first_line: str) -> str:
    best, best_score = ",", 0
    for delimiter in (",", ";", "\t"):
        try:
            cells = next(csv.reader([first_line], delimiter=delimiter), [])
        except csv.Error:
            continue
        score = sum(1 for c in cells if _squash(c) in _KNOWN_COLUMNS) if len(cells) > 1 else 0
        if score > best_score:
            best, best_score = delimiter, score
    return best


def _read_csv(text: str) -> list[list[str]]:
    first, *rest = re.split(r"\r\n|\r|\n", text, maxsplit=1)
    first = first.strip()
    if len(first) == 5 and first.lower().startswith("sep="):  # Excel's delimiter hint line
        delimiter, text = first[4], (rest[0] if rest else "")
    else:
        delimiter = _guess_delimiter(first)
    old_limit = csv.field_size_limit()
    csv.field_size_limit(max(old_limit, 64 * 1024 * 1024))  # long notes must not abort the import
    reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True)
    try:
        return list(reader)
    except csv.Error as exc:
        raise ImportFormatError(
            f"The CSV file is malformed near line {reader.line_num} ({exc}), so nothing was imported. "
            "A quote character may be missing; please export the file again."
        ) from None
    finally:
        csv.field_size_limit(old_limit)


def _detect_csv_format(names: set[str]) -> _CsvFormat | None:
    if names & {"login_uri", "login_username", "login_password"}:
        return _BITWARDEN
    if {"grouping", "extra"} <= names:
        return _LASTPASS
    if {"group", "title", "username", "password"} <= names:
        return _KEEPASSXC
    if {"username", "password"} <= names and names & {"timepasswordchanged", "httprealm", "formactionorigin",
                                                       "timecreated"}:
        return _FIREFOX
    if {"title", "username", "password"} <= names and ("archived" in names or {"otpauth", "tags"} <= names):
        return _ONEPASSWORD
    if {"title", "url", "username", "password", "otpauth"} <= names:
        return _SAFARI
    if {"name", "url", "username", "password"} <= names:
        return _CHROME
    return None


def _generic_format(header: list[str]) -> _CsvFormat:
    names = [_norm(h) for h in header]
    squashed = [_squash(h) for h in header]
    mapping: dict[str, str] = {}
    for role, synonyms in _SYNONYMS.items():
        for syn in synonyms:
            idx = next((i for i, s in enumerate(squashed) if s == syn and names[i] not in mapping), None)
            if idx is not None:
                mapping[names[idx]] = role
                break
    if not {"username", "password"} & set(mapping.values()):
        shown = ", ".join(f"“{h.strip()[:40]}”" for h in header[:12] if h.strip())
        more = "…" if len(header) > 12 else ""
        raise ImportFormatError(
            "This file isn't a recognised export. Keyhold can import CSV files with at least a username or "
            f"password column, Bitwarden JSON and 1Password .1pux files. Columns found: {shown or 'none'}{more}."
        )
    return _CsvFormat("Generic CSV", mapping)


def _column_roles(names: list[str], mapping: dict) -> list[str | None]:
    roles: list[str | None] = []
    used = set()
    for name in names:
        role = mapping.get(name)
        if role is None and name in _NOISE_COLUMNS:
            role = "ignore"
        elif role is not None:
            if role in used:
                role = None  # a duplicate column: keep it as an extra field
            else:
                used.add(role)
        roles.append(role)
    return roles


def _column_label(header: list[str], idx: int) -> str:
    if idx < len(header) and header[idx].strip():
        return header[idx].replace("﻿", "").strip()
    return f"Column {idx + 1}"


def _import_csv(text: str, vault_id: str, now: float) -> ImportResult:
    rows = _read_csv(text)
    while rows and not any(cell.strip() for cell in rows[0]):
        rows.pop(0)
    if not rows:
        raise ImportFormatError("The file is empty.")
    header, body = rows[0], rows[1:]
    names = [_norm(h) for h in header]
    if {"category", "title", "otpauth", "fields"} <= set(names):
        return _import_keyhold_csv(header, names, body, vault_id, now)
    fmt = _detect_csv_format(set(names)) or _generic_format(header)
    roles = _column_roles(names, fmt.columns)
    report = _Report()

    group_root = None
    if "group" in roles:
        gi = roles.index("group")
        tops = {row[gi].strip().split("/")[0] for row in body if gi < len(row) and row[gi].strip()}
        if len(tops) == 1:
            group_root = tops.pop()

    items = []
    for row in body:
        meaningful = [c for i, c in enumerate(row) if (roles[i] if i < len(roles) else None) != "ignore"]
        if not any(c.strip() for c in meaningful):
            report.empty_rows += 1
            continue
        if len(row) != len(header):
            report.ragged_rows += 1
        items.append(_csv_row_to_item(fmt, header, roles, row, group_root, vault_id, now, report))
    return ImportResult(items, fmt.source, report.warnings(items))


def _csv_row_to_item(fmt: _CsvFormat, header: list[str], roles: list, row: list[str], group_root: str | None,
                     vault_id: str, now: float, report: _Report) -> Item:
    vals: dict[str, tuple[str, str]] = {}  # role -> (column label, cell)
    extra: list[tuple[str, str]] = []
    for i, cell in enumerate(row):
        role = roles[i] if i < len(roles) else None
        if role == "ignore":
            continue
        if role is None:
            if cell.strip():
                extra.append((_column_label(header, i), cell))
            continue
        vals[role] = (_column_label(header, i), cell)

    def get(role: str) -> str:
        return vals.get(role, ("", ""))[1]

    category = "login"
    is_lastpass_note = get("lp_url").strip().lower().rstrip("/") == "http://sn"
    if is_lastpass_note:
        category = "secure_note"
    bw_type = get("bw_type").strip().lower()
    if bw_type == "note":
        category = "secure_note"
    elif bw_type not in ("", "login"):
        report.unknown_types[get("bw_type").strip()] += 1
        extra.append((vals["bw_type"][0], get("bw_type")))

    item = new_item(category, vault_id, now)
    item.title = get("title").strip()
    _put(item, "username", get("username"))
    _put(item, "password", get("password"))
    urls = [get("url")] + get("urls").split(",")
    if not is_lastpass_note:
        urls.append(get("lp_url"))
    for url in urls:
        _put(item, "website", url.strip())
    _put(item, "totp", get("totp").strip())
    item.notes = _clean_text(get("notes"))
    item.favorite = _truthy(get("favorite"))

    tags = re.split(r"[,;]", get("tags"))
    tags.append(get("folder"))
    group = get("group").strip()
    if group:
        if group == "Root" or group == group_root:
            group = ""
        elif group_root and group.startswith(group_root + "/"):
            group = group[len(group_root) + 1:]
        elif group.startswith("Root/"):
            group = group[len("Root/"):]
        if group.split("/")[0] == "Recycle Bin":
            report.recycle_bin += 1
        tags.append(group)
    if _truthy(get("archived")):
        tags.append("archived")
    item.tags = _dedupe(tags)

    for name, val in _parse_bitwarden_fields(get("bw_fields")):
        _extra(item, name, _guess_kind(name, val), val)

    times: dict[str, float] = {}
    for role in ("created", "modified", "pw_changed"):
        label, raw = vals.get(role, ("", ""))
        if raw.strip() in ("", "0"):
            continue
        parsed = _parse_time(raw, fmt.time_unit)
        if parsed is None:
            report.bad_dates_kept += 1
            extra.append((label, raw))
        else:
            times[role] = parsed
    item.password_changed = times.get("pw_changed")

    for label, val in extra:
        _extra(item, label, _guess_kind(label, val), val)
    return _finish(item, now, times.get("created"), times.get("modified", times.get("pw_changed")))


def _parse_bitwarden_fields(text: str) -> list[tuple[str, str]]:
    """Bitwarden CSV custom fields: one "name: value" per line; other lines continue the previous value."""
    fields: list[list[str]] = []
    for line in _clean_text(text).strip("\n").split("\n"):
        if ": " in line:
            name, val = line.split(": ", 1)
            fields.append([name.strip() or "field", val])
        elif fields:
            fields[-1][1] += "\n" + line
        elif line.strip():
            fields.append(["field", line])
    return [(name, val) for name, val in fields]


# -- Keyhold's own CSV -----------------------------------------------------


def export_csv(items: list[Item]) -> str:
    """CSV text of all non-trashed items, in a layout ``import_file`` reads back ("Keyhold CSV").

    Url/Username/Password/OTPAuth hold the first field with that purpose; every
    other field (including extra websites) is listed in the Fields column as
    JSON ``{"label", "kind", "value"}`` objects, plus ``"purpose"`` for purpose fields.
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_KEYHOLD_COLUMNS)
    for item in items:
        if item.trashed_at is not None:
            continue
        primary: dict[str, Field] = {}
        for f in item.fields:
            if f.purpose in _PURPOSE_DEFAULTS and f.purpose not in primary:
                primary[f.purpose] = f
        others = []
        for f in item.fields:
            if any(f is p for p in primary.values()):
                continue
            entry = {"label": f.label, "kind": f.kind, "value": f.value}
            if f.purpose:
                entry["purpose"] = f.purpose
            others.append(entry)

        def first(purpose: str) -> str:
            return primary[purpose].value if purpose in primary else ""

        writer.writerow([
            item.category, item.title, first("website"), first("username"), first("password"), first("totp"),
            "true" if item.favorite else "false", ", ".join(item.tags), item.notes,
            json.dumps(others, ensure_ascii=False) if others else "",
        ])
    return buf.getvalue()


def _import_keyhold_csv(header: list[str], names: list[str], body: list[list[str]], vault_id: str,
                        now: float) -> ImportResult:
    known = {c.lower() for c in _KEYHOLD_COLUMNS}
    index = {n: names.index(n) for n in known if n in names}
    report = _Report()
    items = []
    for row in body:
        if not any(cell.strip() for cell in row):
            report.empty_rows += 1
            continue
        if len(row) != len(header):
            report.ragged_rows += 1

        def get(name: str) -> str:
            i = index.get(name)
            return row[i] if i is not None and i < len(row) else ""

        category = get("category").strip().lower()
        if category not in CATEGORIES:
            report.bad_categories[get("category").strip()] += 1
            category = "secure_note"
        item = new_item(category, vault_id, now)
        template_ids = {f.id for f in item.fields}
        item.title = get("title").strip()
        for column, purpose in (("url", "website"), ("username", "username"), ("password", "password"),
                                ("otpauth", "totp")):
            _put(item, purpose, get(column), keep_purpose=True)
        item.favorite = _truthy(get("favorite"))
        item.tags = _dedupe(get("tags").split(","))
        item.notes = _clean_text(get("notes"))

        raw_fields = get("fields")
        if raw_fields.strip():
            try:
                entries = json.loads(raw_fields)
                if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
                    raise ValueError("not a list of objects")
            except (ValueError, RecursionError):
                report.damaged_fields += 1
                item.fields.append(Field.new("Fields", "concealed", raw_fields))
                entries = []
            consumed: set[str] = set()
            for entry in entries:
                label, kind, val = _str(entry.get("label")), entry.get("kind"), _str(entry.get("value"))
                kind = kind if kind in FIELD_KINDS else "text"
                purpose = entry.get("purpose")
                if isinstance(purpose, str) and purpose:
                    _put(item, purpose, val, label=label, kind=kind, keep_purpose=True)
                    continue
                target = next((f for f in item.fields if f.id in template_ids and f.id not in consumed
                               and f.purpose is None and f.label == label), None)
                if target is not None:
                    target.value, target.kind = val, kind
                    consumed.add(target.id)
                else:
                    item.fields.append(Field.new(label, kind, val))

        for i, cell in enumerate(row):
            if (names[i] if i < len(names) else None) not in known and cell.strip():
                label = _column_label(header, i)
                _extra(item, label, _guess_kind(label, cell), cell)
        items.append(_finish(item, now))
    return ImportResult(items, "Keyhold CSV", report.warnings(items))


# ---------------------------------------------------------------------------
# JSON (Bitwarden)
# ---------------------------------------------------------------------------


def _import_json(text: str, vault_id: str, now: float) -> ImportResult:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ImportFormatError(
            f"This looks like a JSON file but it couldn't be read (problem at line {exc.lineno}); "
            "it may be incomplete or damaged."
        ) from None
    except RecursionError:
        raise ImportFormatError("This JSON file is too deeply nested to be an export.") from None
    if isinstance(doc, dict) and doc.get("encrypted") is True:
        raise ImportFormatError(
            "This Bitwarden export is encrypted, so Keyhold can't read it. In Bitwarden, export your vault "
            "again choosing the unencrypted “.json” format (not “.json (Encrypted)”), import that file, and "
            "then delete it."
        )
    if isinstance(doc, dict) and isinstance(doc.get("items"), list) and (
        "encrypted" in doc or "folders" in doc or "collections" in doc
    ):
        return _import_bitwarden(doc, vault_id, now)
    raise ImportFormatError(
        "This JSON file isn't a recognised export. Keyhold can import unencrypted Bitwarden JSON exports."
    )


_BW_CATEGORIES = {1: "login", 2: "secure_note", 3: "credit_card", 4: "identity"}
_BW_TYPE_NAMES = {5: "SSH Key"}
_BW_LOGIN_KEYS = {"username", "password", "totp", "uris", "passwordRevisionDate", "fido2Credentials",
                  "autofillOnPageLoad"}
_BW_CARD_KEYS = {"cardholderName", "brand", "number", "code", "expMonth", "expYear"}
_BW_IDENTITY_TEMPLATE = {"firstName": "first name", "lastName": "last name", "email": "email", "phone": "phone",
                         "company": "company"}
_BW_IDENTITY_EXTRAS = {"title": ("title", "text"), "middleName": ("middle name", "text"),
                       "ssn": ("social security number", "concealed"), "username": ("username", "text"),
                       "passportNumber": ("passport number", "concealed"),
                       "licenseNumber": ("license number", "concealed")}
_BW_ADDRESS_KEYS = {"address1", "address2", "address3", "city", "state", "postalCode", "country"}


def _import_bitwarden(doc: dict, vault_id: str, now: float) -> ImportResult:
    names = {}
    for key in ("folders", "collections"):
        for entry in _list(doc.get(key)):
            if isinstance(entry, dict) and _str(entry.get("id")) and _str(entry.get("name")).strip():
                names[_str(entry["id"])] = _str(entry["name"]).strip()
    report = _Report()
    items = []
    for raw in doc["items"]:
        if not isinstance(raw, dict):
            report.skipped_entries += 1
            continue
        items.append(_bitwarden_item(raw, names, vault_id, now, report))
    return ImportResult(items, "Bitwarden JSON", report.warnings(items))


def _bitwarden_item(raw: dict, folder_names: dict, vault_id: str, now: float, report: _Report) -> Item:
    item_type = raw.get("type")
    category = _BW_CATEGORIES.get(item_type) if isinstance(item_type, int) else None
    if category is None:
        category = "secure_note"
        known_name = _BW_TYPE_NAMES.get(item_type) if isinstance(item_type, int) else None
        report.unsupported[known_name or f"Bitwarden type {_str(item_type)}"] += 1
    item = new_item(category, vault_id, now)
    item.title = _str(raw.get("name")).strip()
    item.notes = _clean_text(_str(raw.get("notes")))
    item.favorite = raw.get("favorite") is True

    tags = [folder_names.get(_str(raw.get("folderId")), "")]
    tags += [folder_names.get(_str(cid), "") for cid in _list(raw.get("collectionIds"))]
    if raw.get("archivedDate"):
        tags.append("archived")
    item.tags = _dedupe(tags)

    if category == "login":
        _bitwarden_login(item, _dict(raw.get("login")), report)
    elif category == "credit_card":
        _bitwarden_card(item, _dict(raw.get("card")))
    elif category == "identity":
        _bitwarden_identity(item, _dict(raw.get("identity")))
    elif item_type != 2:  # unknown type: keep whatever data it carries
        for key, sub in raw.items():
            if isinstance(sub, dict) and key != "secureNote":
                _flatten(item, sub)

    for f in _list(raw.get("fields")):
        if not isinstance(f, dict):
            continue
        name, val = _str(f.get("name")).strip(), _str(f.get("value"))
        if f.get("type") == 3:  # linked: a pointer to another field, no value of its own
            report.linked_fields += 1
            continue
        if not name and val == "":
            continue
        kind = "concealed" if f.get("type") == 1 else _guess_kind(name, val, secret_hint=False)
        _extra(item, name, kind, val)

    item.password_history = _password_history(raw.get("passwordHistory"), "password", "lastUsedDate", now)
    created, modified = _bitwarden_time(raw.get("creationDate"), report), _bitwarden_time(raw.get("revisionDate"), report)
    return _finish(item, now, created, modified)


def _bitwarden_time(value, report: _Report) -> float | None:
    parsed = _parse_time(value)
    if parsed is None and not _is_empty(value):
        report.bad_dates += 1
    return parsed


def _bitwarden_login(item: Item, login: dict, report: _Report) -> None:
    _put(item, "username", _str(login.get("username")))
    _put(item, "password", _str(login.get("password")))
    _put(item, "totp", _str(login.get("totp")).strip())
    for uri in _list(login.get("uris")):
        _put(item, "website", _str(uri.get("uri") if isinstance(uri, dict) else uri).strip())
    item.password_changed = _parse_time(login.get("passwordRevisionDate"))
    for credential in _list(login.get("fido2Credentials")):
        if not _is_empty(credential):
            _extra(item, "passkey", "concealed", _str(credential))
            report.kept_as_fields["passkey"] += 1
    _flatten(item, {k: v for k, v in login.items() if k not in _BW_LOGIN_KEYS})


def _bitwarden_card(item: Item, card: dict) -> None:
    _template_or_extra(item, "cardholder name", _str(card.get("cardholderName")).strip())
    _template_or_extra(item, "type", _str(card.get("brand")).strip())
    _template_or_extra(item, "number", _str(card.get("number")).strip(), "concealed")
    _template_or_extra(item, "verification number", _str(card.get("code")).strip(), "concealed")
    expiry = _month_year(card.get("expMonth"), card.get("expYear"))
    if not (expiry and _fill_template(item, "expiry date", expiry)):
        for key, label in (("expMonth", "expiry month"), ("expYear", "expiry year")):
            if _str(card.get(key)).strip():
                _extra(item, label, "text", _str(card.get(key)).strip())
    _flatten(item, {k: v for k, v in card.items() if k not in _BW_CARD_KEYS})


def _bitwarden_identity(item: Item, ident: dict) -> None:
    def get(key: str) -> str:
        return _str(ident.get(key)).strip()

    for key, label in _BW_IDENTITY_TEMPLATE.items():
        kind = "email" if key == "email" else "phone" if key == "phone" else "text"
        _template_or_extra(item, label, get(key), kind)
    address = _address([get("address1"), get("address2"), get("address3")], get("city"), get("state"),
                       get("postalCode"), get("country"))
    _template_or_extra(item, "address", address, "multiline")
    for key, (label, kind) in _BW_IDENTITY_EXTRAS.items():
        if get(key):
            _extra(item, label, kind, get(key))
    handled = set(_BW_IDENTITY_TEMPLATE) | set(_BW_IDENTITY_EXTRAS) | _BW_ADDRESS_KEYS
    _flatten(item, {k: v for k, v in ident.items() if k not in handled})


# ---------------------------------------------------------------------------
# 1Password .1pux
# ---------------------------------------------------------------------------


def _import_zip(data: bytes, vault_id: str, now: float) -> ImportResult:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            if "export.data" not in zf.namelist():
                raise ImportFormatError(
                    "This zip file isn't a 1Password export (.1pux): it has no “export.data” inside."
                )
            if zf.getinfo("export.data").file_size > MAX_EXPORT_DATA_BYTES:
                raise ImportFormatError("This .1pux file's contents are too large to import.")
            with zf.open("export.data") as fh:  # don't trust the size header alone
                raw = fh.read(MAX_EXPORT_DATA_BYTES + 1)
            if len(raw) > MAX_EXPORT_DATA_BYTES:
                raise ImportFormatError("This .1pux file's contents are too large to import.")
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, EOFError, RuntimeError, NotImplementedError,
            ValueError) as exc:
        raise ImportFormatError(f"This zip / .1pux file is damaged or unsupported ({exc}).") from None
    try:
        doc = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ImportFormatError("This 1Password export is damaged: its “export.data” isn't valid JSON.") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("accounts"), list):
        raise ImportFormatError("This 1Password export is damaged: it has no accounts in it.")
    return _import_1pux(doc, vault_id, now)


_1P_CATEGORIES = {"001": "login", "002": "credit_card", "003": "secure_note", "004": "identity",
                  "005": "password", "101": "bank_account"}
_1P_CATEGORY_NAMES = {
    "006": "Document", "100": "Software License", "102": "Database", "103": "Driver License",
    "104": "Outdoor License", "105": "Membership", "106": "Passport", "107": "Reward Program",
    "108": "Social Security Number", "109": "Wireless Router", "110": "Server", "111": "Email Account",
    "112": "API Credential", "113": "Medical Record", "114": "SSH Key", "115": "Crypto Wallet",
}
# 1Password section field ids (lower case) -> Keyhold template labels.
_1P_TEMPLATE_IDS = {
    "credit_card": {"cardholder": "cardholder name", "type": "type", "ccnum": "number",
                    "cvv": "verification number", "expiry": "expiry date", "validfrom": "valid from",
                    "pin": "PIN"},
    "identity": {"firstname": "first name", "lastname": "last name", "birthdate": "birth date", "email": "email",
                 "defphone": "phone", "address": "address", "company": "company", "jobtitle": "job title"},
    "bank_account": {"bankname": "bank name", "owner": "name on account", "accounttype": "type",
                     "accountno": "account number", "routingno": "routing number", "swift": "SWIFT / IBAN",
                     "iban": "SWIFT / IBAN", "telephonepin": "PIN"},
}
_1P_CARD_TYPES = {"mc": "Mastercard", "visa": "Visa", "amex": "American Express", "diners": "Diners Club",
                  "carteblanche": "Carte Blanche", "discover": "Discover", "jcb": "JCB", "maestro": "Maestro",
                  "visaelectron": "Visa Electron", "laser": "Laser", "unionpay": "UnionPay"}
_1P_SIMPLE_KINDS = {"concealed": "concealed", "totp": "totp", "url": "url", "phone": "phone", "menu": "text",
                    "gender": "text", "reference": "text", "creditCardNumber": "concealed"}
# details keys that are handled, or are form metadata rather than user data.
_1P_DETAIL_KEYS = {"loginFields", "notesPlain", "sections", "passwordHistory", "password", "documentAttributes",
                   "htmlForm"}


def _import_1pux(doc: dict, vault_id: str, now: float) -> ImportResult:
    vaults = [v for account in doc["accounts"] if isinstance(account, dict)
              for v in _list(account.get("vaults")) if isinstance(v, dict)]
    tag_vaults = len(vaults) > 1
    report = _Report()
    items = []
    for vault in vaults:
        vault_name = _str(_dict(vault.get("attrs")).get("name")).strip() if tag_vaults else ""
        for raw in _list(vault.get("items")):
            if not isinstance(raw, dict):
                report.skipped_entries += 1
                continue
            items.append(_1pux_item(raw, vault_name, vault_id, now, report))
    return ImportResult(items, "1Password (1PUX)", report.warnings(items))


def _1pux_item(raw: dict, vault_name: str, vault_id: str, now: float, report: _Report) -> Item:
    category_uuid = _str(raw.get("categoryUuid"))
    category = _1P_CATEGORIES.get(category_uuid)
    if category is None:
        category = "secure_note"
        report.unsupported[_1P_CATEGORY_NAMES.get(category_uuid, f"1Password category {category_uuid}")] += 1
    item = new_item(category, vault_id, now)
    overview, details = _dict(raw.get("overview")), _dict(raw.get("details"))
    item.title = _str(overview.get("title")).strip()

    urls: list[tuple[str, str]] = []
    if _str(overview.get("url")).strip():
        urls.append((_str(overview.get("url")).strip(), ""))
    for entry in _list(overview.get("urls")):
        url = _str(_dict(entry).get("url")).strip()
        if url and url not in [u for u, _ in urls]:
            urls.append((url, _str(_dict(entry).get("label")).strip()))
    for url, label in urls:
        _put(item, "website", url, label=label or None)

    for login_field in _list(details.get("loginFields")):
        login_field = _dict(login_field)
        val = _str(login_field.get("value"))
        if val == "":
            continue
        designation = login_field.get("designation")
        if designation in ("username", "password"):
            _put(item, designation, val)
        else:
            kind = {"P": "concealed", "E": "email"}.get(_str(login_field.get("fieldType")), "text")
            label = _str(login_field.get("name")).strip() or _str(login_field.get("id")).strip()
            _extra(item, label, kind, val)
    _put(item, "password", _str(details.get("password")))
    item.notes = _clean_text(_str(details.get("notesPlain")))

    for section in _list(details.get("sections")):
        section = _dict(section)
        section_title = _str(section.get("title")).strip()
        for fld in _list(section.get("fields")):
            if isinstance(fld, dict):
                _1pux_section_field(item, category, section_title, fld, report)

    document = _dict(details.get("documentAttributes"))
    if _str(document.get("fileName")).strip():
        _1pux_attachment(item, _str(document.get("fileName")).strip(), report)
    for key, val in details.items():
        if key not in _1P_DETAIL_KEYS and not _is_empty(val):
            _extra(item, _words(key), "concealed", _str(val))
            report.kept_as_fields[f"1Password “{key}” data"] += 1

    item.password_history = _password_history(details.get("passwordHistory"), "value", "time", now)
    tags = [t for t in _list(overview.get("tags")) if isinstance(t, str)]
    tags.append(vault_name)
    state = _str(raw.get("state")).strip().lower()
    if state and state != "active":
        tags.append(state)  # "archived": imported as an active item, tagged so it can be found
    item.tags = _dedupe(tags)
    try:
        item.favorite = int(raw.get("favIndex") or 0) > 0
    except (TypeError, ValueError):
        item.favorite = False
    return _finish(item, now, _parse_time(raw.get("createdAt")), _parse_time(raw.get("updatedAt")))


def _1pux_attachment(item: Item, file_name: str, report: _Report) -> None:
    _extra(item, "attachment", "text", file_name)
    report.attachments.append((item.title or "untitled item", file_name))


def _1pux_section_field(item: Item, category: str, section_title: str, fld: dict, report: _Report) -> None:
    title = _str(fld.get("title")).strip()
    field_id = _str(fld.get("id")).strip()
    label = title or field_id or section_title or "field"
    value = fld.get("value")
    if not isinstance(value, dict):
        if not _is_empty(value):
            _extra(item, label, "text", _str(value))
        return
    template = _1P_TEMPLATE_IDS.get(category, {})
    template_label = template.get(field_id.lower())
    if template_label is None:
        template_label = next((t for t in template.values() if t.lower() == title.lower()), None)
    for value_type, raw in value.items():
        if value_type == "file":
            name = _str(_dict(raw).get("fileName")).strip() or _str(raw)
            if name:
                _1pux_attachment(item, name, report)
            continue
        for sub_label, kind, text in _1pux_decode(value_type, raw):
            if text == "":
                continue
            if sub_label is None and kind == "totp":
                _put(item, "totp", text, label=label)
            elif sub_label is None and template_label and _fill_template(item, template_label, text):
                pass
            else:
                _extra(item, sub_label or label, kind, text)


def _1pux_decode(value_type: str, raw) -> list[tuple[str | None, str, str]]:
    """A 1PUX field value as (label override, kind, text) parts; usually exactly one part."""
    if _is_empty(raw):
        return []
    if value_type == "string":
        return [(None, "text", _str(raw))]
    if value_type in _1P_SIMPLE_KINDS and not isinstance(raw, (dict, list)):
        return [(None, _1P_SIMPLE_KINDS[value_type], _str(raw))]
    if value_type == "email":
        return [(None, "email", _str(_dict(raw).get("email_address")) if isinstance(raw, dict) else _str(raw))]
    if value_type == "creditCardType" and not isinstance(raw, (dict, list)):
        return [(None, "text", _1P_CARD_TYPES.get(_str(raw).strip().lower(), _str(raw)))]
    if value_type == "date":
        if isinstance(raw, str) and _DATE_VALUE.fullmatch(raw.strip()):
            return [(None, "date", raw.strip())]
        try:
            day = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=float(raw))
            return [(None, "date", day.date().isoformat())]
        except (TypeError, ValueError, OverflowError):
            return [(None, "text", _str(raw))]
    if value_type == "monthYear":
        text = _str(raw).strip()
        if text.isdigit() and int(text) == 0:
            return []
        expiry = _month_year(text[4:], text[:4]) if text.isdigit() and len(text) == 6 else None
        return [(None, "monthyear", expiry)] if expiry else [(None, "text", text)]
    if value_type == "address" and isinstance(raw, dict):
        known = ("street", "city", "state", "zip", "country")
        get = {k: _str(raw.get(k)).strip() for k in known}
        text = _address([get["street"]], get["city"], get["state"], get["zip"], get["country"])
        rest = [_str(v) for k, v in raw.items() if k not in known and not _is_empty(v)]
        return [(None, "multiline", "\n".join([text] + rest).strip("\n"))]
    if value_type == "sshKey" and isinstance(raw, dict):
        meta = _dict(raw.get("metadata"))
        return [(None, "concealed", _str(raw.get("privateKey") or meta.get("privateKey"))),
                ("public key", "text", _str(meta.get("publicKey"))),
                ("fingerprint", "text", _str(meta.get("fingerprint")))]
    # An unknown (or unexpectedly shaped) value: keep its text / JSON form.
    return [(None, "text", _str(raw))]
