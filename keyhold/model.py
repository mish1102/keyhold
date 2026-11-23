"""Vault contents: vaults, items, fields and settings.

Everything here is plain data that is serialized to JSON and then encrypted as
a whole by ``keyhold.crypto``. Nothing in this module touches the disk.
"""

from __future__ import annotations

import copy
import uuid
from dataclasses import asdict, dataclass, field

DATA_VERSION = 1

# Field kinds the UI knows how to show and edit.
FIELD_KINDS = ("text", "concealed", "totp", "url", "email", "phone", "date", "monthyear", "multiline")


def _uid() -> str:
    return uuid.uuid4().hex


MAX_TIMESTAMP = 253402300799.0  # 9999-12-31


def _timestamp(value, default=None):
    """A sane epoch timestamp, or ``default`` for missing/impossible values."""
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return default
    if ts != ts or not 0 <= ts <= MAX_TIMESTAMP:  # NaN or out of range
        return default
    return ts


@dataclass
class Field:
    id: str
    label: str
    kind: str = "text"
    value: str = ""
    purpose: str | None = None  # "username", "password", "totp", "website" or None

    @classmethod
    def new(cls, label: str, kind: str = "text", value: str = "", purpose: str | None = None) -> "Field":
        if kind not in FIELD_KINDS:
            raise ValueError(f"unknown field kind {kind!r}")
        return cls(id=_uid(), label=label, kind=kind, value=value, purpose=purpose)

    @property
    def secret(self) -> bool:
        return self.kind in ("concealed", "totp")

    @classmethod
    def from_dict(cls, d: dict) -> "Field":
        kind = d.get("kind", "text")
        return cls(
            id=d.get("id") or _uid(),
            label=d.get("label", ""),
            kind=kind if kind in FIELD_KINDS else "text",
            value=str(d.get("value", "")),
            purpose=d.get("purpose"),
        )


@dataclass(frozen=True)
class Category:
    id: str
    label: str
    plural: str
    icon: str  # icon name from the system (Adwaita) icon theme
    template: tuple  # (label, kind, purpose) tuples


CATEGORIES: dict[str, Category] = {
    c.id: c
    for c in (
        Category(
            "login", "Login", "Logins", "dialog-password-symbolic",
            (("username", "text", "username"), ("password", "concealed", "password"),
             ("one-time password", "totp", "totp"), ("website", "url", "website")),
        ),
        Category(
            "secure_note", "Secure Note", "Secure Notes", "accessories-text-editor-symbolic", (),
        ),
        Category(
            "credit_card", "Credit Card", "Credit Cards", "auth-smartcard-symbolic",
            (("cardholder name", "text", None), ("type", "text", None), ("number", "concealed", None),
             ("verification number", "concealed", None), ("expiry date", "monthyear", None),
             ("valid from", "monthyear", None), ("PIN", "concealed", None)),
        ),
        Category(
            "identity", "Identity", "Identities", "avatar-default-symbolic",
            (("first name", "text", None), ("last name", "text", None), ("birth date", "date", None),
             ("email", "email", None), ("phone", "phone", None), ("address", "multiline", None),
             ("company", "text", None), ("job title", "text", None)),
        ),
        Category(
            "password", "Password", "Passwords", "channel-secure-symbolic",
            (("password", "concealed", "password"),),
        ),
        Category(
            "bank_account", "Bank Account", "Bank Accounts", "keyhold-bank-symbolic",
            (("bank name", "text", None), ("name on account", "text", None), ("type", "text", None),
             ("account number", "concealed", None), ("routing number", "text", None),
             ("SWIFT / IBAN", "text", None), ("PIN", "concealed", None)),
        ),
    )
}


@dataclass
class Vault:
    id: str
    name: str

    @classmethod
    def from_dict(cls, d: dict) -> "Vault":
        return cls(id=d["id"], name=d.get("name", "Vault"))


@dataclass
class Item:
    id: str
    category: str
    vault_id: str
    title: str = ""
    fields: list[Field] = field(default_factory=list)
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    favorite: bool = False
    created: float = 0.0
    modified: float = 0.0
    password_changed: float | None = None
    password_history: list[dict] = field(default_factory=list)
    trashed_at: float | None = None

    # -- purpose accessors -------------------------------------------------
    def field(self, purpose: str) -> Field | None:
        return next((f for f in self.fields if f.purpose == purpose), None)

    def _value(self, purpose: str) -> str:
        f = self.field(purpose)
        return f.value if f else ""

    @property
    def username(self) -> str:
        return self._value("username")

    @property
    def password(self) -> str:
        return self._value("password")

    @property
    def totp(self) -> str:
        return self._value("totp")

    @property
    def websites(self) -> list[str]:
        return [f.value for f in self.fields if f.purpose == "website" and f.value.strip()]

    @property
    def subtitle(self) -> str:
        """Second line shown in the item list."""
        if self.username:
            return self.username
        if self.category == "credit_card":
            number = next((f.value for f in self.fields if f.label == "number"), "")
            digits = "".join(ch for ch in number if ch.isdigit())
            return f"•••• {digits[-4:]}" if len(digits) >= 4 else ""
        if self.category == "identity":
            first = next((f.value for f in self.fields if f.label == "first name"), "")
            last = next((f.value for f in self.fields if f.label == "last name"), "")
            return f"{first} {last}".strip()
        if self.category == "secure_note":
            return self.notes.strip().splitlines()[0][:60] if self.notes.strip() else ""
        return ""

    def copy(self) -> "Item":
        return copy.deepcopy(self)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Item":
        category = d.get("category", "secure_note")
        return cls(
            id=d.get("id") or _uid(),
            category=category if category in CATEGORIES else "secure_note",
            vault_id=d.get("vault_id", ""),
            title=d.get("title", ""),
            fields=[Field.from_dict(f) for f in d.get("fields", [])],
            notes=d.get("notes", ""),
            tags=[str(t) for t in d.get("tags", [])],
            favorite=bool(d.get("favorite", False)),
            created=_timestamp(d.get("created"), 0.0),
            modified=_timestamp(d.get("modified"), 0.0),
            password_changed=_timestamp(d.get("password_changed")),
            password_history=[h for h in d.get("password_history", [])
                              if isinstance(h, dict) and isinstance(h.get("value"), str)],
            trashed_at=_timestamp(d.get("trashed_at")),
        )


def new_item(category: str, vault_id: str, now: float) -> Item:
    cat = CATEGORIES[category]
    fields = [Field.new(label, kind, "", purpose) for label, kind, purpose in cat.template]
    return Item(id=_uid(), category=category, vault_id=vault_id, fields=fields, created=now, modified=now)


def apply_edit(old: Item, new: Item, now: float) -> Item:
    """Return ``new`` stamped with modification time and password history."""
    result = new.copy()
    result.modified = now
    if old.password != result.password:
        result.password_changed = now
        if old.password:
            result.password_history = [{"value": old.password, "replaced_at": now}] + list(
                old.password_history
            )
    return result


DEFAULT_SETTINGS = {
    "auto_lock_minutes": 10,
    "lock_on_screen_lock": True,
    "clipboard_clear_seconds": 90,
    "online_checks": False,
    "theme": "dark",  # "dark", "light" or "system"
    "sort": "title",  # "title", "modified" or "created"
    "generator": {"mode": "random", "length": 20, "digits": True, "symbols": True,
                  "words": 4, "separator": "-", "capitalize": True},
}


@dataclass
class VaultData:
    vaults: list[Vault]
    items: list[Item]
    settings: dict
    watchtower: dict  # cached results of online checks (stays encrypted)
    version: int = DATA_VERSION

    @classmethod
    def new(cls) -> "VaultData":
        return cls(
            vaults=[Vault(id=_uid(), name="Personal")],
            items=[],
            settings=copy.deepcopy(DEFAULT_SETTINGS),
            watchtower={},
        )

    # -- queries -----------------------------------------------------------
    def get(self, item_id: str) -> Item | None:
        return next((i for i in self.items if i.id == item_id), None)

    def vault(self, vault_id: str) -> Vault | None:
        return next((v for v in self.vaults if v.id == vault_id), None)

    def active_items(self) -> list[Item]:
        return [i for i in self.items if i.trashed_at is None]

    def all_tags(self) -> list[str]:
        tags = {t for i in self.active_items() for t in i.tags if t.strip()}
        return sorted(tags, key=lambda t: (t.lower(), t))

    # -- mutations ---------------------------------------------------------
    def add_item(self, item: Item) -> None:
        self.items.append(item)

    def replace_item(self, item: Item) -> None:
        for idx, existing in enumerate(self.items):
            if existing.id == item.id:
                self.items[idx] = item
                return
        raise KeyError(item.id)

    def trash(self, item_id: str, now: float) -> None:
        self.get(item_id).trashed_at = now

    def restore(self, item_id: str) -> None:
        self.get(item_id).trashed_at = None

    def purge(self, item_id: str) -> None:
        self.items = [i for i in self.items if i.id != item_id]

    def add_vault(self, name: str) -> Vault:
        vault = Vault(id=_uid(), name=name)
        self.vaults.append(vault)
        return vault

    # -- serialization -----------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "vaults": [asdict(v) for v in self.vaults],
            "items": [i.to_dict() for i in self.items],
            "settings": self.settings,
            "watchtower": self.watchtower,
        }

    def to_json(self) -> str:
        import json

        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_dict(cls, d: dict) -> "VaultData":
        settings = copy.deepcopy(DEFAULT_SETTINGS)
        settings.update(d.get("settings", {}))
        vaults = [Vault.from_dict(v) for v in d.get("vaults", [])] or [Vault(id=_uid(), name="Personal")]
        return cls(
            vaults=vaults,
            items=[Item.from_dict(i) for i in d.get("items", [])],
            settings=settings,
            watchtower=dict(d.get("watchtower", {})),
            version=int(d.get("version", DATA_VERSION)),
        )

    @classmethod
    def from_json(cls, text: str) -> "VaultData":
        import json

        return cls.from_dict(json.loads(text))
