"""Choosing, searching, sorting and grouping items for the item list."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta

from .model import CATEGORIES, Item, VaultData


@dataclass(frozen=True)
class View:
    kind: str  # "all", "favorites", "category", "tag", "watchtower", "trash"
    value: str | None = None
    vault_id: str | None = None  # None = all vaults


def display_title(item: Item) -> str:
    return item.title.strip() or "Untitled"


def _haystack(item: Item) -> str:
    parts = [item.title, " ".join(item.tags), CATEGORIES[item.category].label]
    parts += [f.value for f in item.fields if not f.secret]
    return " ".join(parts).lower()


def matches(item: Item, query: str) -> bool:
    tokens = query.lower().split()
    if not tokens:
        return True
    hay = _haystack(item)
    return all(t in hay for t in tokens)


def _sort_key(sort: str):
    if sort == "modified":
        return lambda i: (-i.modified, display_title(i).casefold())
    if sort == "created":
        return lambda i: (-i.created, display_title(i).casefold())
    return lambda i: (display_title(i).casefold(), i.id)


def select(data: VaultData, view: View, query: str = "", sort: str = "title",
           report: dict[str, set[str]] | None = None) -> list[Item]:
    if view.kind == "trash":
        pool = [i for i in data.items if i.trashed_at is not None]
    else:
        pool = data.active_items()
    if view.vault_id:
        pool = [i for i in pool if i.vault_id == view.vault_id]
    if view.kind == "favorites":
        pool = [i for i in pool if i.favorite]
    elif view.kind == "category":
        pool = [i for i in pool if i.category == view.value]
    elif view.kind == "tag":
        pool = [i for i in pool if view.value in i.tags]
    elif view.kind == "watchtower":
        ids = (report or {}).get(view.value, set())
        pool = [i for i in pool if i.id in ids]
    pool = [i for i in pool if matches(i, query)]
    return sorted(pool, key=_sort_key(sort))


def format_time(ts: float | None) -> str:
    if not ts:
        return "—"
    try:
        return datetime.fromtimestamp(ts).strftime("%b %-d, %Y at %-I:%M %p")
    except (ValueError, OverflowError, OSError):
        return "—"


def _period(ts: float, now: datetime) -> str:
    try:
        when = datetime.fromtimestamp(ts)
    except (ValueError, OverflowError, OSError):
        return "Unknown Date"
    today = now.date()
    if when.date() == today:
        return "Today"
    if when.date() == today - timedelta(days=1):
        return "Yesterday"
    if when.date() > today - timedelta(days=7):
        return "This Week"
    if (when.year, when.month) == (now.year, now.month):
        return "This Month"
    return when.strftime("%B %Y")


def group(items: list[Item], sort: str, now: float | None = None) -> list[tuple[str, list[Item]]]:
    """Split an already sorted list into (header, items) sections."""
    now_dt = datetime.fromtimestamp(now) if now is not None else datetime.now()
    groups: list[tuple[str, list[Item]]] = []
    for item in items:
        if sort in ("modified", "created"):
            header = _period(item.modified if sort == "modified" else item.created, now_dt)
        else:
            first = display_title(item)[:1].upper()
            header = first if first.isalpha() else "#"
        if groups and groups[-1][0] == header:
            groups[-1][1].append(item)
        else:
            groups.append((header, [item]))
    return groups


def counts(data: VaultData, vault_id: str | None = None) -> dict:
    active = [i for i in data.active_items() if not vault_id or i.vault_id == vault_id]
    trashed = [i for i in data.items if i.trashed_at is not None and (not vault_id or i.vault_id == vault_id)]
    return {
        "all": len(active),
        "favorites": sum(1 for i in active if i.favorite),
        "category": Counter(i.category for i in active),
        "tag": Counter(t for i in active for t in i.tags),
        "trash": len(trashed),
    }
