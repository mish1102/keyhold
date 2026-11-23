"""Middle pane: the searchable, grouped item list."""

from __future__ import annotations

from gi.repository import GObject, Gtk

from .. import listing
from ..listing import display_title
from .widgets import ItemIcon

SORT_LABELS = {"title": "Title", "modified": "Date Modified", "created": "Date Created"}


class ItemRow(Gtk.ListBoxRow):
    def __init__(self, item, header: str):
        super().__init__()
        self.item_id = item.id
        self.header = header
        box = Gtk.Box(spacing=10, css_classes=["kh-item-row"])
        icon_overlay = Gtk.Overlay()
        icon_overlay.set_child(ItemIcon(item, 32))
        if item.favorite:
            star = Gtk.Image.new_from_icon_name("starred-symbolic")
            star.set_pixel_size(11)
            star.set_halign(Gtk.Align.END)
            star.set_valign(Gtk.Align.END)
            star.add_css_class("kh-fav-badge")
            icon_overlay.add_overlay(star)
        box.append(icon_overlay)
        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER, hexpand=True)
        text.append(Gtk.Label(label=display_title(item), xalign=0, ellipsize=3, css_classes=["kh-item-title"]))
        subtitle = item.subtitle
        if subtitle:
            text.append(Gtk.Label(label=subtitle, xalign=0, ellipsize=3, css_classes=["kh-subtitle"]))
        box.append(text)
        self.set_child(box)


class ItemList(Gtk.Box):
    __gsignals__ = {
        "item-selected": (GObject.SignalFlags.RUN_FIRST, None, (object,)),
        "sort-changed": (GObject.SignalFlags.RUN_FIRST, None, (str,)),
    }

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.sort = "title"
        sort_bar = Gtk.Box(halign=Gtk.Align.CENTER, margin_top=4, margin_bottom=4)
        self.sort_button = Gtk.MenuButton(css_classes=["flat", "kh-sort-bar"], always_show_arrow=True)
        menu = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, margin_top=6, margin_bottom=6)
        group = None
        self._sort_checks = {}
        for key, label in SORT_LABELS.items():
            check = Gtk.CheckButton(label=label)
            if group:
                check.set_group(group)
            group = group or check
            check.connect("toggled", self._on_sort_toggled, key)
            menu.append(check)
            self._sort_checks[key] = check
        pop = Gtk.Popover(child=menu)
        self.sort_button.set_popover(pop)
        sort_bar.append(self.sort_button)
        self.append(sort_bar)

        self.listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.listbox.set_header_func(self._header_func)
        self.listbox.connect("row-selected", self._on_row_selected)
        self.placeholder = Gtk.Label(css_classes=["dim-label"], wrap=True, margin_top=40,
                                     margin_start=20, margin_end=20, justify=Gtk.Justification.CENTER)
        self.listbox.set_placeholder(self.placeholder)
        self.scroller = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
        self.scroller.set_child(self.listbox)
        self.append(self.scroller)
        self.selected_id = None
        self._suppress = False

    def set_sort(self, sort: str):
        self.sort = sort if sort in SORT_LABELS else "title"
        self._suppress = True
        self._sort_checks[self.sort].set_active(True)
        self._suppress = False

    def _on_sort_toggled(self, check, key):
        if check.get_active() and not self._suppress and key != self.sort:
            self.sort = key
            self.sort_button.popdown()
            self.emit("sort-changed", key)

    def _header_func(self, row, before):
        if before is None or before.header != row.header:
            row.set_header(Gtk.Label(label=row.header, xalign=0, css_classes=["kh-letter-header"]))
        else:
            row.set_header(None)

    def populate(self, items, empty_text: str, keep_selection: bool = True, select_first: bool = True):
        self._suppress = True
        self.listbox.remove_all()
        self.placeholder.set_text(empty_text)
        rows = []
        for header, group in listing.group(items, self.sort):
            for item in group:
                row = ItemRow(item, header)
                self.listbox.append(row)
                rows.append(row)
        n = len(items)
        self.sort_button.set_label(f"{n} item{'s' if n != 1 else ''} sorted by {SORT_LABELS[self.sort]}")
        target = None
        if keep_selection and self.selected_id:
            target = next((r for r in rows if r.item_id == self.selected_id), None)
        if target is None and select_first and rows:
            target = rows[0]
        self._suppress = False
        self._suppress = True
        if target:
            self.listbox.select_row(target)
        self._suppress = False
        self.selected_id = target.item_id if target else None
        self.emit("item-selected", self.selected_id)

    def select_id(self, item_id: str):
        for row in self._rows():
            if row.item_id == item_id:
                self.listbox.select_row(row)
                return True
        return False

    def _rows(self):
        child = self.listbox.get_first_child()
        while child:
            if isinstance(child, ItemRow):
                yield child
            child = child.get_next_sibling()

    def _on_row_selected(self, _lb, row):
        if self._suppress:
            return
        self.selected_id = row.item_id if row else None
        self.emit("item-selected", self.selected_id)

    def focus_list(self):
        row = self.listbox.get_selected_row()
        (row or self.listbox).grab_focus()
