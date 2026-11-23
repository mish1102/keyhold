"""Left pane: views, Watchtower, categories, tags and trash."""

from __future__ import annotations

from gi.repository import GObject, Gtk

from .. import watchtower
from ..listing import View
from ..model import CATEGORIES
from .widgets import section_header


class SidebarRow(Gtk.ListBoxRow):
    def __init__(self, view: View | None, icon: str, title: str, count: int | None = None, alert=False):
        super().__init__()
        self.view = view
        box = Gtk.Box(spacing=10, margin_top=5, margin_bottom=5, margin_start=6, margin_end=6)
        image = Gtk.Image.new_from_icon_name(icon)
        box.append(image)
        box.append(Gtk.Label(label=title, xalign=0, hexpand=True, ellipsize=3))
        if count:
            badge = Gtk.Label(label=str(count), css_classes=["kh-count"], valign=Gtk.Align.CENTER)
            if alert:
                badge.add_css_class("kh-alert")
            box.append(badge)
        self.set_child(box)


class HeaderRow(Gtk.ListBoxRow):
    def __init__(self, text: str):
        super().__init__(selectable=False, activatable=False, focusable=False)
        self.view = None
        self.set_child(section_header(text))


class Sidebar(Gtk.Box):
    __gsignals__ = {"view-selected": (GObject.SignalFlags.RUN_FIRST, None, (object,))}

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.listbox = Gtk.ListBox(css_classes=["navigation-sidebar"])
        self.listbox.connect("row-selected", self._on_selected)
        scroller = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
        scroller.set_child(self.listbox)
        self.append(scroller)
        self.current = View("all")
        self._suppress = False

    def _key(self, view: View | None):
        return (view.kind, view.value) if view else None

    def rebuild(self, counts: dict, report_counts: dict, online_enabled: bool, tags: list[str],
                vault_id: str | None):
        self._suppress = True
        self.listbox.remove_all()
        rows = []

        def add(row):
            self.listbox.append(row)
            rows.append(row)

        add(SidebarRow(View("all", vault_id=vault_id), "view-grid-symbolic", "All Items", counts["all"]))
        add(SidebarRow(View("favorites", vault_id=vault_id), "starred-symbolic", "Favorites", counts["favorites"]))

        add(HeaderRow("Watchtower"))
        for key in watchtower.KEYS:
            if key in watchtower.ONLINE_KEYS and not online_enabled:
                count = None
            else:
                count = report_counts.get(key, 0)
            add(SidebarRow(View("watchtower", key, vault_id), watchtower.ICONS[key], watchtower.TITLES[key],
                           count, alert=bool(count) and key in ("compromised", "vulnerable")))

        add(HeaderRow("Categories"))
        for cat_id, cat in CATEGORIES.items():
            n = counts["category"].get(cat_id, 0)
            if n:
                add(SidebarRow(View("category", cat_id, vault_id), cat.icon, cat.plural, n))

        if tags:
            add(HeaderRow("Tags"))
            for tag in tags:
                n = counts["tag"].get(tag, 0)
                if n:
                    add(SidebarRow(View("tag", tag, vault_id), "keyhold-tag-symbolic", tag, n))

        add(HeaderRow(""))
        add(SidebarRow(View("trash", vault_id=vault_id), "user-trash-symbolic", "Trash", counts["trash"]))

        # Re-select the current view if it still exists, else All Items.
        target = next((r for r in rows if r.view and self._key(r.view) == self._key(self.current)), rows[0])
        self._suppress = False
        self.current = None
        self.listbox.select_row(target)
        if self.current is None:  # select_row didn't emit (already selected)
            self.current = target.view
            self.emit("view-selected", target.view)

    def _on_selected(self, _listbox, row):
        if self._suppress or row is None or row.view is None:
            return
        self.current = row.view
        self.emit("view-selected", row.view)
