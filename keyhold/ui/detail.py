"""Right pane: item details (view mode) and the item editor (edit mode)."""

from __future__ import annotations

from gi.repository import Adw, Gtk, Pango

from .. import totp, watchtower
from ..listing import display_title
from ..model import CATEGORIES, FIELD_KINDS, Field, Item
from .generator_popover import GeneratorPopover
from .widgets import ItemIcon, StrengthLabel, TotpDisplay, format_time

MASK = "••••••••••"
KIND_LABELS = {
    "text": "Text", "concealed": "Password / hidden", "url": "Website address", "email": "Email",
    "phone": "Phone", "date": "Date", "monthyear": "Month / year", "totp": "One-time password",
    "multiline": "Multi-line text",
}


def _flat_button(icon: str, tooltip: str, callback) -> Gtk.Button:
    b = Gtk.Button(icon_name=icon, tooltip_text=tooltip, valign=Gtk.Align.CENTER, css_classes=["flat", "circular"])
    b.connect("clicked", lambda *_: callback())
    return b


class DetailPane(Gtk.Box):
    """Builds the detail page (header bar + body) for the selected item."""

    def __init__(self, ctx):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.ctx = ctx
        self.item: Item | None = None
        self.editor: ItemEditor | None = None

        self.toolbar = Adw.ToolbarView()
        self.header = Adw.HeaderBar(show_title=False)
        self.toolbar.add_top_bar(self.header)
        self.append(self.toolbar)
        self.toolbar.set_vexpand(True)

        # View-mode header widgets
        self.edit_button = Gtk.Button(label="Edit", tooltip_text="Edit (Ctrl+E)")
        self.edit_button.connect("clicked", lambda *_: self.start_edit())
        self.fav_button = Gtk.ToggleButton(icon_name="non-starred-symbolic", tooltip_text="Favorite")
        self._fav_handler = self.fav_button.connect("toggled", self._on_fav_toggled)
        self.more_button = Gtk.MenuButton(icon_name="view-more-symbolic", tooltip_text="More")
        self.more_button.set_popover(self._more_popover())
        # Edit-mode header widgets
        self.cancel_button = Gtk.Button(label="Cancel")
        self.cancel_button.connect("clicked", lambda *_: self.cancel_edit())
        self.save_button = Gtk.Button(label="Save", css_classes=["suggested-action"], tooltip_text="Save (Ctrl+S)")
        self.save_button.connect("clicked", lambda *_: self.save_edit())

        self.header.pack_start(self.edit_button)
        self.header.pack_start(self.cancel_button)
        self.header.pack_end(self.more_button)
        self.header.pack_end(self.fav_button)
        self.header.pack_end(self.save_button)

        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE, transition_duration=120)
        self.empty = Adw.StatusPage(icon_name="channel-secure-symbolic", title="No item selected")
        self.stack.add_named(self.empty, "empty")
        self.view_scroller = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
        self.stack.add_named(self.view_scroller, "view")
        self.edit_scroller = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
        self.stack.add_named(self.edit_scroller, "edit")
        self.toolbar.set_content(self.stack)
        self._set_mode("empty")

    # -- modes ---------------------------------------------------------------
    @property
    def editing(self) -> bool:
        return self.editor is not None

    def _set_mode(self, mode: str):
        viewing = mode == "view"
        trashed = bool(self.item and self.item.trashed_at)
        self.edit_button.set_visible(viewing and not trashed)
        self.fav_button.set_visible(viewing and not trashed)
        self.more_button.set_visible(viewing)
        self.cancel_button.set_visible(mode == "edit")
        self.save_button.set_visible(mode == "edit")
        self.stack.set_visible_child_name(mode)

    def show_item(self, item: Item | None, empty_text: str = "No item selected"):
        if self.editing:
            return
        if item is None:
            self.item = None
            self.view_scroller.set_child(None)
            self.empty.set_title(empty_text)
            self._set_mode("empty")
            return
        try:
            view = self._build_view(item)
        except Exception:  # damaged data must not leave the pane showing another item
            import traceback

            traceback.print_exc()
            self.item = None
            self.view_scroller.set_child(None)
            self.empty.set_title("This item can't be displayed")
            self._set_mode("empty")
            return
        self.item = item
        self.fav_button.handler_block(self._fav_handler)
        self.fav_button.set_active(item.favorite)
        self.fav_button.set_icon_name("starred-symbolic" if item.favorite else "non-starred-symbolic")
        self.fav_button.handler_unblock(self._fav_handler)
        self.view_scroller.set_child(view)
        self._set_mode("view")

    def clear(self):
        """Drop every widget that showed vault data (used when locking)."""
        self.editor = None
        self.item = None
        self.view_scroller.set_child(None)
        self.edit_scroller.set_child(None)
        self.empty.set_title("No item selected")
        self._set_mode("empty")

    def start_edit(self, item: Item | None = None, is_new: bool = False):
        if self.editing:
            return  # never replace an editor that may hold unsaved input
        target = item or self.item
        if target is None or target.trashed_at:
            return
        self.item = target
        self.editor = ItemEditor(self.ctx, target, is_new)
        self.edit_scroller.set_child(self.editor)
        self._set_mode("edit")
        self.ctx.set_editing(True)
        self.editor.focus_first()

    def cancel_edit(self):
        if not self.editor:
            return
        was_new = self.editor.is_new
        self.editor = None
        self.edit_scroller.set_child(None)
        self.ctx.set_editing(False)
        if was_new:
            self.item = None
            self.ctx.refresh(select_id=None)
        else:
            self.show_item(self.ctx.data.get(self.item.id))

    def save_edit(self):
        if not self.editor:
            return
        new_item = self.editor.collect()
        if new_item is None:
            return  # validation message already shown
        if self.ctx.commit_item(new_item, is_new=self.editor.is_new):
            self.editor = None
            self.edit_scroller.set_child(None)
            self.ctx.set_editing(False)
            self.ctx.refresh(select_id=new_item.id)
        else:
            self.editor._error("Couldn't save this item (see the message at the top of the window). "
                               "Your changes are still here; try again once that's fixed.")

    def _on_fav_toggled(self, button):
        if self.item:
            self.ctx.set_favorite(self.item.id, button.get_active())

    def _more_popover(self) -> Gtk.Popover:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, margin_top=6, margin_bottom=6, margin_start=6, margin_end=6)
        pop = Gtk.Popover(child=box)

        def add(label, callback, css=None):
            b = Gtk.Button(label=label, css_classes=["flat"] + ([css] if css else []))
            b.get_child().set_xalign(0)
            b.connect("clicked", lambda *_: (pop.popdown(), callback()))
            box.append(b)
            return b

        self._dup_btn = add("Duplicate", lambda: self.item and self.ctx.duplicate(self.item.id))
        self._trash_btn = add("Move to Trash", lambda: self.item and self.ctx.trash(self.item.id), "destructive-action")
        self._restore_btn = add("Restore", lambda: self.item and self.ctx.restore(self.item.id))
        self._purge_btn = add("Delete Permanently…", lambda: self.item and self.ctx.purge(self.item.id),
                              "destructive-action")

        def on_show(*_):
            trashed = bool(self.item and self.item.trashed_at)
            self._dup_btn.set_visible(not trashed)
            self._trash_btn.set_visible(not trashed)
            self._restore_btn.set_visible(trashed)
            self._purge_btn.set_visible(trashed)

        pop.connect("show", on_show)
        return pop

    # -- view mode -----------------------------------------------------------
    def _build_view(self, item: Item) -> Gtk.Widget:
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18, margin_top=24, margin_bottom=32,
                        margin_start=24, margin_end=24)
        clamp = Adw.Clamp(maximum_size=620, child=outer)

        head = Gtk.Box(spacing=16)
        head.append(ItemIcon(item, 64))
        title_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER, spacing=2)
        title = Gtk.Label(label=display_title(item), xalign=0, wrap=True, css_classes=["kh-detail-title"])
        title_box.append(title)
        vault = self.ctx.data.vault(item.vault_id)
        crumbs = f"{vault.name if vault else 'Vault'}  ›  {CATEGORIES[item.category].label}"
        title_box.append(Gtk.Label(label=crumbs, xalign=0, css_classes=["kh-breadcrumb"]))
        head.append(title_box)
        outer.append(head)

        if item.trashed_at:
            outer.append(self._trash_banner(item))
        for key in watchtower.reasons(self.ctx.report, item.id):
            outer.append(self._alert(watchtower.ICONS[key], watchtower.TITLES[key], watchtower.ADVICE[key]))

        main_fields = [f for f in item.fields if f.value.strip() and f.purpose != "website"]
        if main_fields:
            outer.append(self._card([self._field_row(f) for f in main_fields]))

        for url in item.websites:
            outer.append(self._website(url))

        if item.notes.strip():
            notes = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            notes.append(Gtk.Label(label="notes", xalign=0, css_classes=["kh-meta-label"]))
            notes.append(Gtk.Label(label=item.notes, xalign=0, wrap=True, selectable=True,
                                   wrap_mode=Pango.WrapMode.WORD_CHAR, css_classes=["kh-field-value"]))
            outer.append(notes)

        if item.tags:
            tags = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, column_spacing=6, row_spacing=6,
                               max_children_per_line=20)
            for t in item.tags:
                tags.append(Gtk.Label(label=t, css_classes=["kh-tag"]))
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            box.append(Gtk.Label(label="tags", xalign=0, css_classes=["kh-meta-label"]))
            box.append(tags)
            outer.append(box)

        if item.password_history:
            outer.append(self._history(item))

        meta = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, margin_top=6)
        for label, ts in (("last modified", item.modified), ("created", item.created)):
            meta.append(Gtk.Label(label=label, xalign=0, css_classes=["kh-meta-label"]))
            meta.append(Gtk.Label(label=format_time(ts), xalign=0, css_classes=["kh-meta-value"], margin_bottom=6))
        outer.append(meta)
        return clamp

    def _alert(self, icon, title, text, css=None) -> Gtk.Widget:
        box = Gtk.Box(spacing=12, css_classes=["kh-alert-box"] + ([css] if css else []))
        box.append(Gtk.Image(icon_name=icon, valign=Gtk.Align.START, margin_top=2))
        text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
        text_box.append(Gtk.Label(label=title, xalign=0, css_classes=["heading"]))
        text_box.append(Gtk.Label(label=text, xalign=0, wrap=True))
        box.append(text_box)
        return box

    def _trash_banner(self, item) -> Gtk.Widget:
        box = self._alert("user-trash-symbolic", "In the Trash",
                          f"Moved to the Trash {format_time(item.trashed_at)}.", "kh-trash")
        buttons = Gtk.Box(spacing=6, valign=Gtk.Align.CENTER)
        restore = Gtk.Button(label="Restore")
        restore.connect("clicked", lambda *_: self.ctx.restore(item.id))
        purge = Gtk.Button(label="Delete…", css_classes=["destructive-action"])
        purge.connect("clicked", lambda *_: self.ctx.purge(item.id))
        buttons.append(restore)
        buttons.append(purge)
        box.append(buttons)
        return box

    def _card(self, rows: list[Gtk.Widget]) -> Gtk.Widget:
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, css_classes=["kh-card"])
        for i, row in enumerate(rows):
            if i:
                card.append(Gtk.Separator(css_classes=["kh-field-sep"]))
            card.append(row)
        return card

    def _row_shell(self, label: str, value_widget: Gtk.Widget, actions: list[Gtk.Widget], on_click=None):
        row = Gtk.Box(spacing=8, css_classes=["kh-field"])
        col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
        col.append(Gtk.Label(label=label, xalign=0, css_classes=["kh-field-label"]))
        col.append(value_widget)
        row.append(col)
        for a in actions:
            row.append(a)
        if on_click:
            click = Gtk.GestureClick()
            click.connect("released", lambda g, n, x, y: on_click())
            col.add_controller(click)
            col.set_cursor_from_name("pointer")
            col.set_tooltip_text("Click to copy")
        return row

    def _field_row(self, f: Field) -> Gtk.Widget:
        label = f.label
        if f.kind == "totp":
            display = TotpDisplay(f.value)
            if display.spec is None:
                return self._row_shell(label, display, [])
            copy = lambda: self.ctx.copy(display.current_code(), "One-time password")  # noqa: E731
            return self._row_shell(label, display, [_flat_button("edit-copy-symbolic", "Copy code", copy)], copy)

        if f.kind == "concealed":
            value = Gtk.Label(label=MASK, xalign=0, css_classes=["kh-field-value"], wrap=True,
                              wrap_mode=Pango.WrapMode.CHAR)
            reveal = Gtk.ToggleButton(icon_name="view-reveal-symbolic", tooltip_text="Reveal",
                                      valign=Gtk.Align.CENTER, css_classes=["flat", "circular"])

            def on_reveal(btn, v=value, secret=f.value):
                shown = btn.get_active()
                v.set_text(secret if shown else MASK)
                if shown:
                    v.add_css_class("kh-mono")
                else:
                    v.remove_css_class("kh-mono")
                btn.set_icon_name("view-conceal-symbolic" if shown else "view-reveal-symbolic")

            reveal.connect("toggled", on_reveal)
            copy = lambda v=f.value, name=label: self.ctx.copy(v, name.capitalize())  # noqa: E731
            actions = []
            if f.purpose == "password":
                meter = StrengthLabel()
                meter.set_password(f.value)
                actions.append(meter)
            actions += [reveal, _flat_button("edit-copy-symbolic", "Copy", copy)]
            return self._row_shell(label, value, actions, copy)

        value = Gtk.Label(label=f.value, xalign=0, wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR,
                          css_classes=["kh-field-value"], selectable=f.kind == "multiline")
        copy = lambda v=f.value, name=label: self.ctx.copy(v, name.capitalize(), secret=False)  # noqa: E731
        actions = [_flat_button("edit-copy-symbolic", "Copy", copy)]
        if f.kind == "url":
            actions.insert(0, _flat_button("web-browser-symbolic", "Open in browser", lambda u=f.value: self.ctx.open_url(u)))
        return self._row_shell(label, value, actions, copy if f.kind != "multiline" else None)

    def _website(self, url: str) -> Gtk.Widget:
        box = Gtk.Box(spacing=8)
        col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
        col.append(Gtk.Label(label="website", xalign=0, css_classes=["kh-meta-label"]))
        link = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END, tooltip_text=url)
        link.set_markup(f'<span foreground="#62a0ea">{_escape(url)}</span>')
        click = Gtk.GestureClick()
        click.connect("released", lambda *_: self.ctx.open_url(url))
        link.add_controller(click)
        link.set_cursor_from_name("pointer")
        col.append(link)
        box.append(col)
        box.append(_flat_button("web-browser-symbolic", "Open in browser", lambda: self.ctx.open_url(url)))
        box.append(_flat_button("edit-copy-symbolic", "Copy", lambda: self.ctx.copy(url, "Website", secret=False)))
        return box

    def _history(self, item: Item) -> Gtk.Widget:
        group = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
        n = len(item.password_history)
        exp = Adw.ExpanderRow(title="Password history",
                              subtitle=f"{n} previous password{'s' if n != 1 else ''}")
        for entry in item.password_history:
            row = Adw.ActionRow(title=MASK, subtitle=f"Replaced {format_time(entry.get('replaced_at'))}")
            reveal = Gtk.ToggleButton(icon_name="view-reveal-symbolic", valign=Gtk.Align.CENTER,
                                      css_classes=["flat", "circular"], tooltip_text="Reveal")
            reveal.connect("toggled", lambda b, r=row, v=entry["value"]: r.set_title(_escape(v) if b.get_active() else MASK))
            row.add_suffix(reveal)
            row.add_suffix(_flat_button("edit-copy-symbolic", "Copy",
                                        lambda v=entry["value"]: self.ctx.copy(v, "Old password")))
            exp.add_row(row)
        group.append(exp)
        return group


def _escape(text: str) -> str:
    from gi.repository import GLib

    return GLib.markup_escape_text(text)


class ItemEditor(Gtk.Box):
    def __init__(self, ctx, item: Item, is_new: bool):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.ctx = ctx
        self.is_new = is_new
        self.original = item
        self.work = item.copy()
        self.getters: list = []
        self.outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18, margin_top=24, margin_bottom=32,
                             margin_start=24, margin_end=24)
        self.append(Adw.Clamp(maximum_size=620, child=self.outer))
        self._build()

    # Rebuilding keeps typed values: sync widgets -> working copy first.
    def _sync(self):
        for getter in self.getters:
            getter()

    def _rebuild(self):
        self._sync()
        child = self.outer.get_first_child()
        while child:
            nxt = child.get_next_sibling()
            self.outer.remove(child)
            child = nxt
        self._build()

    def _build(self):
        self.getters = []
        w = self.work
        cat = CATEGORIES[w.category]
        heading = Gtk.Label(label=("New " if self.is_new else "Edit ") + cat.label, xalign=0,
                            css_classes=["title-2"])
        self.outer.append(heading)

        top = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
        self.title_row = Adw.EntryRow(title="title", text=w.title, use_markup=False)
        top.append(self.title_row)
        self.getters.append(lambda: setattr(w, "title", self.title_row.get_text().strip()))
        vaults = self.ctx.data.vaults
        if len(vaults) > 1:
            combo = Adw.ComboRow(title="vault", model=Gtk.StringList.new([v.name for v in vaults]))
            ids = [v.id for v in vaults]
            combo.set_selected(ids.index(w.vault_id) if w.vault_id in ids else 0)
            top.append(combo)
            self.getters.append(lambda: setattr(w, "vault_id", ids[combo.get_selected()]))
        self.outer.append(top)

        fields_box = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
        for f in w.fields:
            if f.purpose != "website":
                fields_box.append(self._field_editor(f))
        if fields_box.get_first_child():
            self.outer.append(fields_box)

        if w.category == "login" or w.websites or any(f.purpose == "website" for f in w.fields):
            sites = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
            for f in w.fields:
                if f.purpose == "website":
                    sites.append(self._field_editor(f))
            self.outer.append(sites)

        buttons = Gtk.Box(spacing=8)
        if w.category == "login":
            add_site = Gtk.Button(label="Add Website", css_classes=["flat"])
            add_site.connect("clicked", lambda *_: self._add_field(Field.new("website", "url", "", "website")))
            buttons.append(add_site)
        add_field = Gtk.MenuButton(label="Add Field", css_classes=["flat"])
        add_field.set_popover(self._add_field_popover())
        buttons.append(add_field)
        self.outer.append(buttons)

        notes_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        notes_box.append(Gtk.Label(label="notes", xalign=0, css_classes=["kh-meta-label"]))
        notes_view = Gtk.TextView(wrap_mode=Gtk.WrapMode.WORD_CHAR, top_margin=8, bottom_margin=8,
                                  left_margin=10, right_margin=10, css_classes=["card"])
        notes_view.set_size_request(-1, 110)
        notes_view.get_buffer().set_text(w.notes)
        notes_box.append(notes_view)
        self.outer.append(notes_box)

        def get_notes():
            buf = notes_view.get_buffer()
            w.notes = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)

        self.getters.append(get_notes)

        tags = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
        tags_row = Adw.EntryRow(title="tags (separate with commas)", text=", ".join(w.tags), use_markup=False)
        tags.append(tags_row)
        self.getters.append(lambda: setattr(w, "tags", _split_tags(tags_row.get_text())))
        self.outer.append(tags)

        self.error = Gtk.Label(css_classes=["error"], xalign=0, wrap=True, visible=False)
        self.outer.append(self.error)

    def _remove_button(self, f: Field) -> Gtk.Button:
        def remove():
            self._sync()
            self.work.fields = [x for x in self.work.fields if x.id != f.id]
            self._rebuild()

        return _flat_button("user-trash-symbolic", "Remove field", remove)

    def _field_editor(self, f: Field) -> Gtk.Widget:
        removable = f.purpose not in ("username", "password")
        if f.kind == "multiline":
            row = Gtk.ListBoxRow(activatable=False)
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, margin_top=8, margin_bottom=8,
                          margin_start=12, margin_end=12)
            head = Gtk.Box()
            head.append(Gtk.Label(label=f.label, xalign=0, hexpand=True, css_classes=["kh-field-label"]))
            if removable:
                head.append(self._remove_button(f))
            box.append(head)
            view = Gtk.TextView(wrap_mode=Gtk.WrapMode.WORD_CHAR)
            view.set_size_request(-1, 60)
            view.get_buffer().set_text(f.value)
            box.append(view)
            row.set_child(box)

            def get():
                buf = view.get_buffer()
                f.value = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)

            self.getters.append(get)
            return row

        if f.kind == "concealed":
            row = Adw.PasswordEntryRow(title=f.label, text=f.value, use_markup=False)
            if f.purpose == "password" or "password" in f.label.lower() or f.label.upper() == "PIN":
                meter = StrengthLabel()
                meter.set_password(f.value)
                row.add_suffix(meter)
                row.connect("changed", lambda r: meter.set_password(r.get_text()))
                gen_button = Gtk.MenuButton(icon_name="dialog-password-symbolic", tooltip_text="Generate password",
                                            valign=Gtk.Align.CENTER, css_classes=["flat"])
                gen_button.set_popover(GeneratorPopover(
                    self.ctx.generator_settings, self.ctx.save_generator_settings,
                    lambda v: self.ctx.copy(v, "Generated password"),
                    lambda v, r=row: r.set_text(v)))
                row.add_suffix(gen_button)
        else:
            row = Adw.EntryRow(title=f.label if f.kind != "totp" else f"{f.label} (secret or otpauth:// link)",
                               text=f.value, use_markup=False)
            purposes = {"email": Gtk.InputPurpose.EMAIL, "phone": Gtk.InputPurpose.PHONE,
                        "url": Gtk.InputPurpose.URL}
            if f.kind in purposes:
                row.set_input_purpose(purposes[f.kind])
            if f.kind == "totp":
                row.connect("changed", self._validate_totp)
                self._validate_totp(row)
            if f.kind == "monthyear":
                row.set_title(f"{f.label} (MM/YYYY)")
            if f.kind == "date":
                row.set_title(f"{f.label} (YYYY-MM-DD)")
        if removable:
            row.add_suffix(self._remove_button(f))
        self.getters.append(lambda: setattr(f, "value", row.get_text().strip() if f.kind != "concealed" else row.get_text()))
        return row

    def _validate_totp(self, row):
        text = row.get_text().strip()
        ok = True
        if text:
            try:
                totp.parse(text)
            except ValueError:
                ok = False
        if ok:
            row.remove_css_class("error")
        else:
            row.add_css_class("error")

    def _add_field(self, field: Field):
        self._sync()
        self.work.fields.append(field)
        self._rebuild()

    def _add_field_popover(self) -> Gtk.Popover:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_top=10, margin_bottom=10,
                      margin_start=10, margin_end=10)
        pop = Gtk.Popover(child=box)
        name = Gtk.Entry(placeholder_text="Field name, e.g. Recovery codes")
        box.append(name)
        kinds = [k for k in FIELD_KINDS]
        dropdown = Gtk.DropDown(model=Gtk.StringList.new([KIND_LABELS[k] for k in kinds]))
        box.append(dropdown)
        add = Gtk.Button(label="Add", css_classes=["suggested-action"])
        box.append(add)

        def do_add(*_):
            kind = kinds[dropdown.get_selected()]
            label = name.get_text().strip() or KIND_LABELS[kind].lower()
            purpose = None
            if kind == "totp" and not any(f.purpose == "totp" for f in self.work.fields):
                purpose = "totp"
            pop.popdown()
            name.set_text("")
            self._add_field(Field.new(label, kind, "", purpose))

        add.connect("clicked", do_add)
        name.connect("activate", do_add)
        return pop

    def focus_first(self):
        self.title_row.grab_focus()

    def draft(self) -> dict:
        """Current editor contents, unvalidated (kept across a lock)."""
        self._sync()
        return {"item": self.work.to_dict(), "is_new": self.is_new}

    def collect(self) -> Item | None:
        self._sync()
        w = self.work.copy()
        from ..watchtower import parse_month_year

        for f in w.fields:
            if f.kind == "totp" and f.value.strip():
                try:
                    totp.parse(f.value)
                except ValueError as exc:
                    self._error(f"The one-time password secret isn't valid: {exc}.")
                    return None
            if f.kind == "monthyear" and f.value.strip() and not parse_month_year(f.value):
                self._error(f"“{f.label}” should look like 08/2027.")
                return None
            if f.kind == "date" and f.value.strip() and not _valid_date(f.value):
                self._error(f"“{f.label}” should look like 2027-08-31.")
                return None
        if not w.title:
            # Like most managers: fall back to the website's name or the category.
            from ..watchtower import host_of

            host = host_of(w.websites[0]) if w.websites else ""
            w.title = host or CATEGORIES[w.category].label
        # Drop empty extra websites (keep the first website field for logins).
        seen_site = False
        kept = []
        for f in w.fields:
            if f.purpose == "website":
                if f.value.strip() or not seen_site:
                    kept.append(f)
                seen_site = True
            else:
                kept.append(f)
        w.fields = kept
        return w

    def _error(self, text):
        self.error.set_text(text)
        self.error.set_visible(True)


def _valid_date(text: str) -> bool:
    from datetime import datetime

    try:
        return 1900 <= datetime.strptime(text.strip(), "%Y-%m-%d").year <= 9999
    except ValueError:
        return False


def _split_tags(text: str) -> list[str]:
    out = []
    for t in text.replace(";", ",").split(","):
        t = t.strip()
        if t and t not in out:
            out.append(t)
    return out
