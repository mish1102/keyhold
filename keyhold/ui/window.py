"""Main window: lock screens plus the three-pane vault view."""

from __future__ import annotations

import os
import time
from pathlib import Path

from gi.repository import Adw, Gio, GLib, GObject, Gtk

from .. import APP_NAME, listing, model, strength, watchtower, watchtower_online
from ..listing import View
from ..model import CATEGORIES
from ..store import SaveError, atomic_write
from . import config
from .clipboard import SecureClipboard
from .detail import DetailPane
from .generator_popover import GeneratorPanel
from .itemlist import ItemList
from .lockscreen import CreatePage, UnlockPage, run_in_thread
from .sidebar import Sidebar

ONLINE_REFRESH_SECONDS = 24 * 3600


def _scrub(widget: Gtk.Widget) -> None:
    """Blank every text entry and generated-password preview inside ``widget``."""
    child = widget.get_first_child()
    while child is not None:
        if isinstance(child, Gtk.Editable):
            child.set_text("")
        elif isinstance(child, Gtk.Label) and child.has_css_class("kh-mono-preview"):
            child.set_text("")
        _scrub(child)
        child = child.get_next_sibling()


from ..system import clock as _clock  # noqa: E402  (keeps counting during sleep)
from ..system import shortcut_label  # noqa: E402


class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app, store):
        super().__init__(application=app, title=APP_NAME)
        cfg = config.load()
        self.set_default_size(cfg.get("width", 1180), cfg.get("height", 760))
        self.set_size_request(360, 480)
        self.store = store
        self.session = None
        self.report: dict[str, set[str]] = {k: set() for k in watchtower.KEYS}
        self.vault_filter: str | None = None
        self.current_view = View("all")
        self.last_activity = _clock()
        self.dialogs: list[Adw.Dialog] = []
        self.clipboard = SecureClipboard(self.get_display(), self._clipboard_seconds)
        self._online_running = False

        self.toasts = Adw.ToastOverlay()
        self.set_content(self.toasts)
        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        self.toasts.set_child(self.stack)
        self.create_page = CreatePage(store, self._on_unlocked)
        self.unlock_page = UnlockPage(store, self._on_unlocked)
        self.stack.add_named(self.create_page, "create")
        self.stack.add_named(self.unlock_page, "unlock")
        self.stack.add_named(self._build_main(), "main")
        self._install_actions(app)
        self._install_activity_tracking()
        self.show_lock_screen()
        self.connect("close-request", self._on_close_request)

    # ------------------------------------------------------------------ layout
    def _build_main(self) -> Gtk.Widget:
        # Sidebar pane
        self.sidebar = Sidebar()
        self.sidebar.connect("view-selected", self._on_view_selected)
        side_tb = Adw.ToolbarView(css_classes=["kh-sidebar-pane"])
        side_header = Adw.HeaderBar(show_title=False)
        self.vault_button = Gtk.MenuButton(css_classes=["flat"], tooltip_text="Switch vault")
        self.vault_button.set_popover(Gtk.Popover())
        self.vault_button.get_popover().connect("show", self._fill_vault_popover)
        side_header.pack_start(self.vault_button)
        menu_button = Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=self._main_menu(),
                                     tooltip_text="Main menu", primary=True)
        side_header.pack_end(menu_button)
        lock_button = Gtk.Button(icon_name="system-lock-screen-symbolic", tooltip_text=f"Lock ({shortcut_label('Ctrl+L')})",
                                 action_name="win.lock")
        side_header.pack_end(lock_button)
        side_tb.add_top_bar(side_header)
        side_tb.set_content(self.sidebar)

        # Item list pane
        self.itemlist = ItemList()
        self.itemlist.connect("item-selected", self._on_item_selected)
        self.itemlist.connect("sort-changed", self._on_sort_changed)
        list_tb = Adw.ToolbarView(css_classes=["kh-list-pane"])
        list_header = Adw.HeaderBar()
        self.sidebar_toggle = Gtk.ToggleButton(icon_name="sidebar-show-symbolic", tooltip_text="Show sidebar",
                                               visible=False)
        list_header.pack_start(self.sidebar_toggle)
        self.search = Gtk.SearchEntry(placeholder_text=f"Search {APP_NAME}", hexpand=True)
        self.search.connect("search-changed", lambda *_: self.populate_list())
        self.search.connect("activate", lambda *_: self.itemlist.focus_list())
        self.search.connect("stop-search", lambda *_: self.search.set_text(""))
        list_header.set_title_widget(self.search)
        self.add_button = Gtk.MenuButton(icon_name="list-add-symbolic", tooltip_text=f"New item ({shortcut_label('Ctrl+N')})",
                                         menu_model=self._new_item_menu())
        list_header.pack_end(self.add_button)
        list_tb.add_top_bar(list_header)
        list_tb.set_content(self.itemlist)
        list_page = Adw.NavigationPage(title="Items", child=list_tb)

        # Detail pane
        self.detail = DetailPane(self)
        detail_page = Adw.NavigationPage(title="Item", child=self.detail)

        self.inner_split = Adw.NavigationSplitView(sidebar=list_page, content=detail_page,
                                                   min_sidebar_width=280, max_sidebar_width=360,
                                                   sidebar_width_fraction=0.34)
        self.outer_split = Adw.OverlaySplitView(sidebar=side_tb, content=self.inner_split,
                                                min_sidebar_width=220, max_sidebar_width=280)
        self.outer_split.bind_property("collapsed", self.sidebar_toggle, "visible",
                                       GObject.BindingFlags.SYNC_CREATE)
        self.outer_split.bind_property("show-sidebar", self.sidebar_toggle, "active",
                                       GObject.BindingFlags.SYNC_CREATE | GObject.BindingFlags.BIDIRECTIONAL)

        self.save_banner = Adw.Banner(button_label="Try Again")
        self.save_banner.connect("button-clicked", lambda *_: self.save())
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        main_box.append(self.save_banner)
        self.outer_split.set_vexpand(True)
        main_box.append(self.outer_split)

        for condition, target, prop in (("max-width: 860sp", self.outer_split, "collapsed"),
                                        ("max-width: 560sp", self.inner_split, "collapsed")):
            bp = Adw.Breakpoint.new(Adw.BreakpointCondition.parse(condition))
            bp.add_setter(target, prop, True)
            self.add_breakpoint(bp)
        return main_box

    def _main_menu(self) -> Gio.Menu:
        menu = Gio.Menu()
        section = Gio.Menu()
        section.append("Password Generator", "win.generator")
        section.append("Import…", "win.import")
        export = Gio.Menu()
        export.append("Encrypted Backup…", "win.export-encrypted")
        export.append("Unencrypted CSV…", "win.export-csv")
        section.append_submenu("Export", export)
        menu.append_section(None, section)
        section2 = Gio.Menu()
        section2.append("Preferences", "win.preferences")
        section2.append("Keyboard Shortcuts", "win.shortcuts")
        section2.append(f"About {APP_NAME}", "win.about")
        menu.append_section(None, section2)
        section3 = Gio.Menu()
        section3.append("Lock", "win.lock")
        menu.append_section(None, section3)
        return menu

    def _new_item_menu(self) -> Gio.Menu:
        menu = Gio.Menu()
        for cat_id, cat in CATEGORIES.items():
            item = Gio.MenuItem.new(cat.label, None)
            item.set_action_and_target_value("win.new-item", GLib.Variant.new_string(cat_id))
            menu.append_item(item)
        return menu

    # ----------------------------------------------------------------- actions
    def _install_actions(self, app):
        def add(name, callback, accels=(), param=None):
            action = Gio.SimpleAction.new(name, param)
            action.connect("activate", callback)
            self.add_action(action)
            if accels:
                app.set_accels_for_action(f"win.{name}" + ("::login" if name == "new-item" else ""), list(accels))
            return action

        self.unlocked_actions = [
            add("lock", lambda *_: self.lock(), ["<Primary>l"]),
            add("search", lambda *_: self.search.grab_focus(), ["<Primary>f"]),
            add("new-item", lambda _a, p: self.new_item(p.get_string()), ["<Primary>n"], GLib.VariantType.new("s")),
            add("edit", lambda *_: self.detail.start_edit(), ["<Primary>e"]),
            add("save", lambda *_: self.detail.save_edit(), ["<Primary>s"]),
            add("generator", lambda *_: self.show_generator(), ["<Primary>g"]),
            add("preferences", lambda *_: self.show_preferences(), ["<Primary>comma"]),
            add("import", lambda *_: self.import_file()),
            add("export-encrypted", lambda *_: self.export_encrypted()),
            add("export-csv", lambda *_: self.export_csv()),
        ]
        add("shortcuts", lambda *_: self.show_shortcuts(), ["<Primary>question"])
        add("about", lambda *_: self.show_about())
        self.edit_actions = [a for a in self.unlocked_actions if a.get_name() in ("new-item", "edit", "import")]

        # Copying secrets is bound with a ShortcutController instead of window
        # actions: GTK exports window actions on the session D-Bus, where any
        # other program could trigger them.
        shortcuts = Gtk.ShortcutController(scope=Gtk.ShortcutScope.GLOBAL)
        for trigger, what in (("<Primary><Shift>c", "password"), ("<Primary><Shift>u", "username"),
                              ("<Primary><Shift>o", "totp")):
            shortcuts.add_shortcut(Gtk.Shortcut.new(
                Gtk.ShortcutTrigger.parse_string(trigger),
                Gtk.CallbackAction.new(lambda _w, _args, w=what: (self._copy_selected(w), True)[1])))
        self.add_controller(shortcuts)

    def _set_actions_enabled(self, enabled: bool):
        for a in self.unlocked_actions:
            a.set_enabled(enabled)

    def _install_activity_tracking(self):
        def bump(*_):
            if self.is_active():
                self.last_activity = _clock()
            return False

        key = Gtk.EventControllerKey(propagation_phase=Gtk.PropagationPhase.CAPTURE)
        key.connect("key-pressed", bump)
        click = Gtk.GestureClick(propagation_phase=Gtk.PropagationPhase.CAPTURE, button=0)
        click.connect("pressed", bump)
        motion = Gtk.EventControllerMotion(propagation_phase=Gtk.PropagationPhase.CAPTURE)
        motion.connect("motion", bump)
        scroll = Gtk.EventControllerScroll(propagation_phase=Gtk.PropagationPhase.CAPTURE,
                                           flags=Gtk.EventControllerScrollFlags.BOTH_AXES)
        scroll.connect("scroll", bump)
        for c in (key, click, motion, scroll):
            self.add_controller(c)
        GLib.timeout_add_seconds(10, self._check_idle)

    def _check_idle(self):
        try:
            if self.session and not self.session.locked:
                minutes = int(self.data.settings.get("auto_lock_minutes", 10))
                if minutes > 0 and _clock() - self.last_activity > minutes * 60:
                    self.lock()
        except Exception:  # never let an error stop the auto-lock timer
            import traceback

            traceback.print_exc()
        return True

    # ------------------------------------------------------------ lock/unlock
    @property
    def data(self) -> model.VaultData:
        return self.session.data

    def show_lock_screen(self):
        self._set_actions_enabled(False)
        if self.store.exists():
            self.unlock_page.reset()
            self.stack.set_visible_child_name("unlock")
            GLib.idle_add(lambda: self.unlock_page.focus() and False)
        else:
            self.stack.set_visible_child_name("create")
            GLib.idle_add(lambda: self.create_page.focus() and False)

    def _on_unlocked(self, session):
        self.session = session
        self.last_activity = _clock()
        self.itemlist.set_sort(self.data.settings.get("sort", "title"))
        self.vault_filter = None
        self.current_view = View("all")
        self.sidebar.current = View("all")
        self.itemlist.selected_id = None
        self.search.set_text("")
        self._set_actions_enabled(True)
        self.stack.set_visible_child_name("main")
        self.refresh()
        GLib.idle_add(lambda: self.itemlist.focus_list() and False)
        self._restore_recovered(session.recovered)
        self._maybe_refresh_online()

    def _restore_recovered(self, recovered):
        if not recovered:
            return
        if recovered.get("data"):
            if self.save(quiet=True):
                self.toast("Saved the changes that couldn't be saved before Keyhold locked", 5)
            self.refresh()
        draft = recovered.get("draft")
        if draft and draft.get("item"):
            try:
                item = model.Item.from_dict(draft["item"])
            except (KeyError, TypeError, ValueError):
                return
            is_new = bool(draft.get("is_new"))
            if not is_new and self.data.get(item.id) is None:
                is_new = True  # the original was deleted meanwhile
            if is_new and self.data.vault(item.vault_id) is None:
                item.vault_id = self._default_vault_id()
            if not is_new:
                self.itemlist.selected_id = item.id
                self.refresh()
            self.detail.start_edit(item, is_new=is_new)
            self.toast("Restored the edit you were making when Keyhold locked", 5)

    def lock(self):
        if not self.session or self.session.locked:
            return
        self._close_all_dialogs()
        if self.detail.editing:
            self.session.set_draft(self.detail.editor.draft())
            self.detail.editor = None
            self.set_editing(False)
        if self.session.dirty:
            try:
                self.session.save()  # last chance; otherwise kept encrypted in memory
            except SaveError:
                pass
        self.clipboard.clear()
        self.session.lock()
        self.detail.clear()
        strength.clear_cache()
        self.report = {k: set() for k in watchtower.KEYS}
        self.detail.item = None
        self.detail.show_item(None)
        self.itemlist.populate([], "")
        self.sidebar.listbox.remove_all()
        self.search.set_text("")
        self.save_banner.set_revealed(False)
        self.show_lock_screen()

    def _close_all_dialogs(self):
        """Close every dialog. Their text is wiped first, so nothing secret is
        visible even during the closing animation."""
        dialogs = list(self.dialogs)
        visible = self.get_visible_dialog()
        if visible is not None and visible not in dialogs:
            dialogs.append(visible)
        for d in dialogs:
            _scrub(d)
            d.force_close()
        self.dialogs.clear()

    def shutdown(self):
        self.clipboard.clear()
        if self.session and not self.session.locked:
            self.session.lock()
        strength.clear_cache()

    def _on_close_request(self, *_):
        config.update(width=self.get_width(), height=self.get_height())
        if getattr(self, "_close_confirmed", False) or not self.session or self.session.locked:
            return False
        editing = self.detail.editing
        if not editing and self.session.dirty and self.save(quiet=True):
            return False
        if not editing and not self.session.dirty:
            return False
        body = ("You're editing an item that hasn't been saved." if editing else
                "Your latest changes couldn't be saved (see the message at the top of the window).")
        dialog = Adw.AlertDialog(heading="Quit without saving?", body=body + " Quitting will discard them.")
        dialog.add_response("cancel", "Keep Working")
        if editing:
            dialog.add_response("save", "Save and Quit")
            dialog.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
        dialog.add_response("discard", "Discard and Quit")
        dialog.set_response_appearance("discard", Adw.ResponseAppearance.DESTRUCTIVE)

        def on_response(_d, response):
            if response == "save":
                self.detail.save_edit()
                if self.detail.editing:
                    return  # save failed; the editor shows why
            if response in ("save", "discard"):
                self._close_confirmed = True
                self.close()

        dialog.connect("response", on_response)
        self._present(dialog)
        return True

    # ---------------------------------------------------------------- context
    def _clipboard_seconds(self) -> int:
        if self.session and not self.session.locked:
            return int(self.data.settings.get("clipboard_clear_seconds", 90))
        return 90

    def toast(self, text: str, timeout: int = 3):
        self.toasts.add_toast(Adw.Toast(title=GLib.markup_escape_text(text), timeout=timeout))

    def copy(self, text: str, what: str, secret: bool = True):
        if not text:
            return
        seconds = self.clipboard.copy(text, secret=secret)
        suffix = f" · clears in {seconds} s" if seconds else ""
        self.toast(f"{what} copied{suffix}")

    def open_url(self, url: str):
        url = url.strip()
        if "://" not in url:
            url = "https://" + url
        if not url.lower().startswith(("https://", "http://")):
            self.toast("Only web addresses (http/https) can be opened.")
            return
        Gtk.UriLauncher.new(url).launch(self, None, None)

    def set_editing(self, editing: bool):
        for w in (self.sidebar, self.itemlist, self.search, self.add_button, self.vault_button):
            w.set_sensitive(not editing)
        for a in self.edit_actions:
            a.set_enabled(not editing and bool(self.session) and not self.session.locked)

    def generator_settings(self) -> dict:
        return dict(self.data.settings.get("generator", {}))

    def save_generator_settings(self, settings: dict):
        self.data.settings["generator"] = settings
        self.save(quiet=True)

    def save(self, quiet: bool = False) -> bool:
        try:
            self.session.save()
        except SaveError as exc:
            self.save_banner.set_title(str(exc))
            self.save_banner.set_revealed(True)
            return False
        if self.save_banner.get_revealed():
            self.save_banner.set_revealed(False)
            if not quiet:
                self.toast("All changes saved")
        return True

    # ------------------------------------------------------------- refreshing
    def refresh(self, select_id: str | None = "__keep__"):
        if select_id != "__keep__":
            self.itemlist.selected_id = select_id
        online = self.data.watchtower if self.data.settings.get("online_checks") else None
        self.report = watchtower.analyze(self.data.items, time.time(), online)
        self._update_vault_button()
        counts = listing.counts(self.data, self.vault_filter)
        self.sidebar.rebuild(counts, watchtower.counts(self.report), bool(online),
                             self.data.all_tags(), self.vault_filter)
        if select_id not in ("__keep__", None) and self.itemlist.selected_id != select_id:
            # The item isn't in the current view: jump to All Items.
            self.itemlist.selected_id = select_id
            self.sidebar.current = View("all", vault_id=self.vault_filter)
            self.sidebar.rebuild(counts, watchtower.counts(self.report), bool(online),
                                 self.data.all_tags(), self.vault_filter)

    def _on_view_selected(self, _sidebar, view: View):
        self.current_view = view
        self.populate_list()

    def populate_list(self):
        if not self.session or self.session.locked:
            return
        view = View(self.current_view.kind, self.current_view.value, self.vault_filter)
        query = self.search.get_text()
        items = listing.select(self.data, view, query, self.itemlist.sort, self.report)
        if query:
            empty = f"No items match “{query}”."
        elif view.kind == "watchtower" and view.value in watchtower.ONLINE_KEYS and not self.data.settings.get("online_checks"):
            empty = "Turn on online checks in Preferences to look for these problems."
        elif view.kind == "watchtower":
            empty = "Nothing to fix here."
        elif view.kind == "trash":
            empty = "The Trash is empty."
        elif not self.data.active_items():
            empty = "Your vault is empty.\nClick + to add your first item, or import from another password manager."
        else:
            empty = "No items here."
        self.itemlist.populate(items, empty)

    def _on_item_selected(self, _list, item_id):
        item = self.data.get(item_id) if (item_id and self.session and not self.session.locked) else None
        self.detail.show_item(item)

    def _on_sort_changed(self, _list, sort):
        self.data.settings["sort"] = sort
        self.save(quiet=True)
        self.populate_list()

    # ------------------------------------------------------------ item changes
    def _default_vault_id(self) -> str:
        return self.vault_filter or self.data.vaults[0].id

    def new_item(self, category: str):
        if not self.session or self.session.locked or self.detail.editing:
            return
        item = model.new_item(category, self._default_vault_id(), time.time())
        if category == "login":
            pw = item.field("password")
            from .. import generator

            pw.value = generator.generate(self.generator_settings() or {"mode": "random"})
        self.detail.start_edit(item, is_new=True)

    def commit_item(self, item: model.Item, is_new: bool) -> bool:
        now = time.time()
        old = None if is_new else self.data.get(item.id)
        if is_new or old is None:
            item.created = item.modified = now
            if item.password:
                item.password_changed = now
            self.data.add_item(item)
        else:
            self.data.replace_item(model.apply_edit(old, item, now))
        if self.save():
            return True
        # Roll back so what's in memory matches the file; the editor stays open.
        if old is None:
            self.data.purge(item.id)
        else:
            self.data.replace_item(old)
        return False

    def set_favorite(self, item_id: str, favorite: bool):
        item = self.data.get(item_id)
        if item and item.favorite != favorite:
            item.favorite = favorite
            self.save()
            self.refresh()

    def duplicate(self, item_id: str):
        src = self.data.get(item_id)
        if not src:
            return
        now = time.time()
        clone = src.copy()
        clone.id = model._uid()
        clone.title = f"{listing.display_title(src)} copy"
        clone.created = clone.modified = now
        clone.password_history = []
        clone.favorite = False
        self.data.add_item(clone)
        self.save()
        self.refresh(select_id=clone.id)
        self.toast("Item duplicated")

    def trash(self, item_id: str):
        self.data.trash(item_id, time.time())
        self.save()
        self.refresh(select_id=None)
        self.toast("Moved to the Trash")

    def restore(self, item_id: str):
        self.data.restore(item_id)
        self.save()
        self.refresh(select_id=item_id)
        self.toast("Item restored")

    def purge(self, item_id: str):
        item = self.data.get(item_id)
        if not item:
            return
        dialog = Adw.AlertDialog(heading="Delete permanently?",
                                 body=f"“{listing.display_title(item)}” will be deleted. This can't be undone.")
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("delete", "Delete")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)

        def on_response(_d, response):
            if response == "delete":
                self.data.purge(item_id)
                self.save()
                self.refresh(select_id=None)

        dialog.connect("response", on_response)
        self._present(dialog)

    def _copy_selected(self, what: str):
        item = self.detail.item
        if not item or self.detail.editing:
            return
        if what == "password":
            self.copy(item.password, "Password")
        elif what == "username":
            self.copy(item.username, "Username", secret=False)
        elif what == "totp" and item.totp:
            from .. import totp

            try:
                self.copy(totp.code(totp.parse(item.totp), time.time()), "One-time password")
            except ValueError:
                self.toast("This item's one-time password secret isn't valid.")

    # ------------------------------------------------------------------ vaults
    def _update_vault_button(self):
        name = "All Vaults" if not self.vault_filter else self.data.vault(self.vault_filter).name
        n = len(self.data.vaults)
        box = Gtk.Box(spacing=8)
        icon = Gtk.Image.new_from_icon_name("folder-symbolic" if self.vault_filter else "view-app-grid-symbolic")
        box.append(icon)
        labels = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        labels.append(Gtk.Label(label=name, xalign=0, css_classes=["heading"], ellipsize=3, max_width_chars=16))
        labels.append(Gtk.Label(label=f"{n} Vault{'s' if n != 1 else ''}", xalign=0, css_classes=["caption", "dim-label"]))
        box.append(labels)
        self.vault_button.set_child(box)

    def _fill_vault_popover(self, popover):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, margin_top=6, margin_bottom=6, margin_start=6, margin_end=6)

        def choose(vault_id):
            popover.popdown()
            self.vault_filter = vault_id
            self.sidebar.current = View(self.current_view.kind, self.current_view.value, vault_id)
            self.refresh()

        def add(label, callback, icon=None, checked=False):
            row = Gtk.Box(spacing=8)
            if icon:
                row.append(Gtk.Image.new_from_icon_name(icon))
            row.append(Gtk.Label(label=label, xalign=0, hexpand=True))
            if checked:
                row.append(Gtk.Image.new_from_icon_name("object-select-symbolic"))
            b = Gtk.Button(child=row, css_classes=["flat"])
            b.connect("clicked", lambda *_: callback())
            box.append(b)

        add("All Vaults", lambda: choose(None), "view-app-grid-symbolic", self.vault_filter is None)
        for v in self.data.vaults:
            add(v.name, lambda vid=v.id: choose(vid), "folder-symbolic", self.vault_filter == v.id)
        box.append(Gtk.Separator(margin_top=4, margin_bottom=4))
        add("New Vault…", lambda: (popover.popdown(), self._new_vault()), "list-add-symbolic")
        if self.vault_filter:
            add("Rename Vault…", lambda: (popover.popdown(), self._rename_vault(self.vault_filter)), "document-edit-symbolic")
            add("Delete Vault…", lambda: (popover.popdown(), self._delete_vault(self.vault_filter)), "user-trash-symbolic")
        popover.set_child(box)

    def _ask_text(self, heading, body, initial, confirm_label, callback):
        dialog = Adw.AlertDialog(heading=heading, body=body)
        entry = Gtk.Entry(text=initial, activates_default=True)
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("ok", confirm_label)
        dialog.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("ok")

        def on_response(_d, response):
            if response == "ok" and entry.get_text().strip():
                callback(entry.get_text().strip())

        dialog.connect("response", on_response)
        self._present(dialog)
        entry.grab_focus()

    def _new_vault(self):
        def create(name):
            vault = self.data.add_vault(name)
            self.save()
            self.vault_filter = vault.id
            self.refresh()
            self.toast(f"Created vault “{name}”")

        self._ask_text("New Vault", "Vaults let you keep groups of items apart, e.g. Personal and Work.",
                       "", "Create", create)

    def _rename_vault(self, vault_id):
        vault = self.data.vault(vault_id)

        def rename(name):
            vault.name = name
            self.save()
            self.refresh()

        self._ask_text("Rename Vault", "", vault.name, "Rename", rename)

    def _delete_vault(self, vault_id):
        vault = self.data.vault(vault_id)
        in_use = [i for i in self.data.items if i.vault_id == vault_id]
        if in_use:
            self.toast("Move or delete this vault's items (including the Trash) before deleting it.", 5)
            return
        if len(self.data.vaults) == 1:
            self.toast("You need at least one vault.")
            return
        dialog = Adw.AlertDialog(heading=f"Delete “{vault.name}”?", body="The vault is empty.")
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("delete", "Delete")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)

        def on_response(_d, response):
            if response == "delete":
                self.data.vaults = [v for v in self.data.vaults if v.id != vault_id]
                self.vault_filter = None
                self.save()
                self.refresh()

        dialog.connect("response", on_response)
        self._present(dialog)

    # --------------------------------------------------------------- dialogs
    def _present(self, dialog: Adw.Dialog):
        self.dialogs.append(dialog)
        dialog.connect("closed", lambda d: d in self.dialogs and self.dialogs.remove(d))
        dialog.present(self)

    def show_generator(self):
        if not self.session or self.session.locked:
            return
        dialog = Adw.Dialog(title="Password Generator", content_width=400)
        tb = Adw.ToolbarView()
        tb.add_top_bar(Adw.HeaderBar())
        tb.set_content(GeneratorPanel(self.generator_settings(), self.save_generator_settings,
                                      lambda v: (self.copy(v, "Generated password"), dialog.close())))
        dialog.set_child(tb)
        self._present(dialog)

    def show_preferences(self):
        from .preferences import PreferencesDialog

        self._present(PreferencesDialog(self))

    def show_about(self):
        about = Adw.AboutDialog(application_name=APP_NAME, application_icon="io.github.keyhold.Keyhold",
                                version=__import__("keyhold").__version__,
                                comments="A local, encrypted password manager.",
                                license_type=Gtk.License.MIT_X11)
        about.add_credit_section("Passphrase wordlist", ["EFF Large Wordlist (CC BY 3.0 US) https://www.eff.org/dice"])
        self._present(about)

    def show_shortcuts(self):
        rows = [
            ("Ctrl+F", "Search"), ("Ctrl+N", "New login"), ("Ctrl+E", "Edit item"), ("Ctrl+S", "Save item"),
            ("Ctrl+Shift+C", "Copy password"), ("Ctrl+Shift+U", "Copy username"),
            ("Ctrl+Shift+O", "Copy one-time password"), ("Ctrl+G", "Password generator"),
            ("Ctrl+,", "Preferences"), ("Ctrl+L", "Lock"), ("Ctrl+Q", "Quit"),
        ]
        dialog = Adw.Dialog(title="Keyboard Shortcuts", content_width=380)
        tb = Adw.ToolbarView()
        tb.add_top_bar(Adw.HeaderBar())
        lb = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"],
                         margin_top=12, margin_bottom=18, margin_start=18, margin_end=18)
        for keys, what in rows:
            r = Adw.ActionRow(title=what)
            r.add_suffix(Gtk.Label(label=shortcut_label(keys), css_classes=["dim-label", "monospace"]))
            lb.append(r)
        tb.set_content(lb)
        dialog.set_child(tb)
        self._present(dialog)

    # ----------------------------------------------------------- import/export
    def import_file(self):
        dialog = Gtk.FileDialog(title="Import Passwords")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        f = Gtk.FileFilter(name="Password exports (CSV, 1PUX, Bitwarden JSON)")
        for pattern in ("*.csv", "*.CSV", "*.1pux", "*.json"):
            f.add_pattern(pattern)
        filters.append(f)
        dialog.set_filters(filters)

        def on_open(d, result):
            try:
                gfile = d.open_finish(result)
            except GLib.Error:
                return
            self._confirm_import(Path(gfile.get_path()))

        dialog.open(self, None, on_open)

    def _confirm_import(self, path: Path):
        from .. import importers

        vault_id = self._default_vault_id()
        session = self.session

        def done(result, error):
            if session is not self.session or session.locked:
                return  # locked while parsing: drop the results
            if isinstance(error, importers.ImportFormatError):
                self._alert("Can't import this file", str(error))
            elif error is not None:
                self._alert("Can't read this file", str(error))
            else:
                self._ask_import(path, result)

        run_in_thread(lambda: importers.import_file(path, vault_id, time.time()), done)

    def _ask_import(self, path: Path, result):
        if not result.items:
            self._alert("Nothing to import", "The file doesn't contain any items.")
            return
        vault = self.data.vault(self._default_vault_id())
        body = f"{len(result.items)} items from {result.source} will be added to “{vault.name}”."
        if result.warnings:
            body += "\n\n" + "\n".join(f"• {w}" for w in result.warnings[:8])
        dialog = Adw.AlertDialog(heading="Import Items?", body=body)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("import", "Import")
        dialog.set_response_appearance("import", Adw.ResponseAppearance.SUGGESTED)

        def on_response(_d, response):
            if response != "import":
                return
            for item in result.items:
                self.data.add_item(item)
            saved = self.save()
            self.refresh()
            if saved:
                self.toast(f"Imported {len(result.items)} items")
                self._offer_delete_export(path)

        dialog.connect("response", on_response)
        self._present(dialog)

    def _offer_delete_export(self, path: Path):
        dialog = Adw.AlertDialog(
            heading="Delete the export file?",
            body=f"{path.name} contains your passwords without encryption. Now that they're safely in "
                 f"{APP_NAME}, you should delete it (and empty your system trash if you moved it there).")
        dialog.add_response("keep", "Keep File")
        dialog.add_response("delete", "Delete File")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)

        def on_response(_d, response):
            if response == "delete":
                try:
                    os.remove(path)
                    self.toast("Export file deleted")
                except OSError as exc:
                    self._alert("Couldn't delete the file", str(exc))

        dialog.connect("response", on_response)
        self._present(dialog)

    def _alert(self, heading, body):
        dialog = Adw.AlertDialog(heading=heading, body=body)
        dialog.add_response("ok", "OK")
        self._present(dialog)

    def _save_dialog(self, title, name, callback):
        dialog = Gtk.FileDialog(title=title, initial_name=name)

        def on_save(d, result):
            try:
                gfile = d.save_finish(result)
            except GLib.Error:
                return
            callback(Path(gfile.get_path()))

        dialog.save(self, None, on_save)

    def export_encrypted(self):
        name = f"keyhold-backup-{time.strftime('%Y-%m-%d')}.keyhold"

        def write(path):
            try:
                self.session.export_encrypted(path)
            except SaveError as exc:
                self._alert("Backup failed", str(exc))
                return
            self.toast("Encrypted backup saved. It opens with your current master password.", 5)

        self._save_dialog("Save Encrypted Backup", name, write)

    def export_csv(self):
        dialog = Adw.AlertDialog(
            heading="Export without encryption?",
            body="The CSV file will contain all your passwords in plain text. Anyone who can read the file "
                 "can read your passwords. Enter your master password to continue.")
        entry = Gtk.PasswordEntry(show_peek_icon=True, activates_default=True)
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("export", "Export")
        dialog.set_response_appearance("export", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("export")

        def on_response(_d, response):
            if response != "export":
                return
            password = entry.get_text()

            def done(ok, error):
                if error or not ok:
                    self._alert("Incorrect password", "The CSV export was cancelled.")
                    return
                self._save_dialog("Export CSV", "keyhold-export.csv", self._write_csv)

            run_in_thread(lambda: self.session.check_password(password), done)

        dialog.connect("response", on_response)
        self._present(dialog)
        entry.grab_focus()

    def _write_csv(self, path: Path):
        from .. import importers

        text = importers.export_csv(self.data.items)
        try:
            atomic_write(path, text.encode("utf-8"))
        except OSError as exc:
            self._alert("Export failed", str(exc))
            return
        self.toast("Exported. Delete the CSV file as soon as you're done with it.", 6)

    # ----------------------------------------------------------- online checks
    def _maybe_refresh_online(self, force: bool = False):
        if not self.session or self.session.locked or self._online_running:
            return
        if not self.data.settings.get("online_checks"):
            return
        last = self.data.watchtower.get("updated", 0)
        if not force and time.time() - last < ONLINE_REFRESH_SECONDS:
            return
        self._online_running = True
        passwords = [i.password for i in self.data.active_items() if i.password]
        previous = dict(self.data.watchtower)
        session = self.session

        def work():
            return watchtower_online.refresh(passwords, previous, fetch=watchtower_online.http_get,
                                             now=time.time())

        def done(result, error):
            self._online_running = False
            if session is not self.session or session.locked:
                return  # locked meanwhile: drop results
            if error:
                self.toast(f"Online checks failed: {error}", 5)
                return
            cache, errors = result
            self.data.watchtower = cache
            self.save(quiet=True)
            self.refresh()
            if errors:
                self.toast(errors[0], 6)
            elif force:
                self.toast("Online checks complete")

        run_in_thread(work, done)

    def refresh_online_now(self):
        self._maybe_refresh_online(force=True)
