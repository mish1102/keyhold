"""First-run (create vault) and unlock screens."""

from __future__ import annotations

import threading

from gi.repository import Adw, GLib, Gtk

from .. import APP_NAME, generator, strength
from ..crypto import CorruptVaultError, WrongPasswordError
from ..store import VaultBusyError
from .widgets import StrengthLabel

MIN_MASTER_LEVEL = 2  # "Fair" (>= 50 bits) or better


def display_path(path) -> str:
    """Show paths under the home folder as ~/..."""
    from pathlib import Path

    path, home = Path(path), Path.home()
    try:
        return "~/" + str(path.relative_to(home))
    except ValueError:
        return str(path)


def run_in_thread(work, done):
    """Run ``work()`` off the main loop, then ``done(result, error)`` on it."""

    def runner():
        try:
            result, error = work(), None
        except Exception as exc:  # reported to the UI
            result, error = None, exc
        GLib.idle_add(lambda: done(result, error) and False)

    threading.Thread(target=runner, daemon=True).start()


def _page(child: Gtk.Widget) -> Gtk.Widget:
    toolbar = Adw.ToolbarView()
    header = Adw.HeaderBar(show_title=False)
    header.add_css_class("flat")
    toolbar.add_top_bar(header)
    scroller = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
    clamp = Adw.Clamp(maximum_size=420, child=child, valign=Gtk.Align.CENTER, margin_top=24,
                      margin_bottom=48, margin_start=16, margin_end=16)
    scroller.set_child(clamp)
    toolbar.set_content(scroller)
    return toolbar


def _hero(icon: str, title: str, subtitle: str) -> Gtk.Box:
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
    img = Gtk.Image.new_from_icon_name(icon)
    img.set_pixel_size(72)
    img.add_css_class("dim-label")
    box.append(img)
    box.append(Gtk.Label(label=title, css_classes=["kh-lock-title"], wrap=True, justify=Gtk.Justification.CENTER))
    sub = Gtk.Label(label=subtitle, wrap=True, justify=Gtk.Justification.CENTER, css_classes=["dim-label"])
    box.append(sub)
    return box


class UnlockPage(Gtk.Box):
    def __init__(self, store, on_unlocked):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.store = store
        self.on_unlocked = on_unlocked
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=22)
        content.append(_hero("system-lock-screen-symbolic", f"{APP_NAME} is locked",
                             "Enter your master password to unlock your vault."))
        group = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
        self.entry = Adw.PasswordEntryRow(title="Master password")
        self.entry.connect("entry-activated", lambda *_: self.unlock())
        self.entry.connect("changed", lambda *_: self.error.set_visible(False))
        group.append(self.entry)
        content.append(group)
        self.error = Gtk.Label(css_classes=["error"], wrap=True, visible=False)
        content.append(self.error)
        self.button = Gtk.Button(css_classes=["suggested-action", "pill"], halign=Gtk.Align.CENTER)
        btn_box = Gtk.Box(spacing=8, halign=Gtk.Align.CENTER)
        self.spinner = Gtk.Spinner(visible=False)
        btn_box.append(self.spinner)
        btn_box.append(Gtk.Label(label="Unlock"))
        self.button.set_child(btn_box)
        self.button.set_size_request(180, -1)
        self.button.connect("clicked", lambda *_: self.unlock())
        content.append(self.button)
        path = Gtk.Label(label=display_path(store.path), css_classes=["caption", "dim-label"], wrap=True,
                         wrap_mode=2, selectable=True, justify=Gtk.Justification.CENTER)
        content.append(path)
        self.append(_page(content))

    def focus(self):
        self.entry.grab_focus()

    def reset(self):
        self.entry.set_text("")
        self.error.set_visible(False)
        self._busy(False)

    def _busy(self, busy: bool):
        self.spinner.set_visible(busy)
        self.spinner.set_spinning(busy)
        self.button.set_sensitive(not busy)
        self.entry.set_sensitive(not busy)

    def unlock(self):
        password = self.entry.get_text()
        if not password:
            self._show_error("Enter your master password.")
            return
        self._busy(True)

        def done(session, error):
            self._busy(False)
            if error is None:
                self.entry.set_text("")
                self.on_unlocked(session)
                return
            if isinstance(error, WrongPasswordError):
                self._show_error("That password is incorrect. Check Caps Lock and try again.")
            elif isinstance(error, VaultBusyError):
                self._show_error(str(error))
            elif isinstance(error, CorruptVaultError):
                self._show_error(f"The vault file can't be read ({error}). Your backups are in "
                                 f"{self.store.backup_dir}.")
            else:
                self._show_error(f"Couldn't open the vault: {error}")
            self.entry.grab_focus()

        def work():
            session = self.store.unlock(password)
            # Warm the strength cache here (off the UI thread) so Watchtower's
            # first pass doesn't freeze the window on large vaults.
            for item in session.data.active_items():
                if item.password:
                    strength.estimate(item.password)
            return session

        run_in_thread(work, done)

    def _show_error(self, text):
        self.error.set_text(text)
        self.error.set_visible(True)


class CreatePage(Gtk.Box):
    def __init__(self, store, on_created):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.store = store
        self.on_created = on_created
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        content.append(_hero("channel-secure-symbolic", f"Welcome to {APP_NAME}",
                             "Choose a master password. It encrypts everything in your vault and is "
                             "the only password you'll need to remember."))
        group = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
        self.pw = Adw.PasswordEntryRow(title="Master password")
        self.pw.connect("changed", self._update)
        self.confirm = Adw.PasswordEntryRow(title="Confirm master password")
        self.confirm.connect("changed", self._update)
        self.confirm.connect("entry-activated", lambda *_: self.create())
        group.append(self.pw)
        group.append(self.confirm)
        content.append(group)

        meter = Gtk.Box(spacing=8)
        self.level = Gtk.LevelBar(min_value=0, max_value=6, hexpand=True, valign=Gtk.Align.CENTER)
        self.level.set_mode(Gtk.LevelBarMode.DISCRETE)
        for name, value in (("low", 2), ("high", 4), ("full", 6)):
            self.level.add_offset_value(name, value)
        self.strength = StrengthLabel()
        meter.append(self.level)
        meter.append(self.strength)
        content.append(meter)

        suggest = Gtk.Button(label="Suggest a memorable password", css_classes=["flat"], halign=Gtk.Align.START)
        suggest.connect("clicked", self._suggest)
        content.append(suggest)
        self.suggestion = Gtk.Label(xalign=0, wrap=True, selectable=True, visible=False,
                                    css_classes=["kh-mono-preview"])
        content.append(self.suggestion)

        warn = Gtk.Label(
            label="If you forget your master password, your data can't be recovered by anyone. "
                  "Write it down and keep it somewhere safe.",
            wrap=True, xalign=0, css_classes=["kh-alert-box"])
        content.append(warn)
        self.hint = Gtk.Label(wrap=True, xalign=0, css_classes=["caption", "dim-label"])
        content.append(self.hint)
        self.button = Gtk.Button(css_classes=["suggested-action", "pill"], halign=Gtk.Align.CENTER, sensitive=False)
        btn_box = Gtk.Box(spacing=8, halign=Gtk.Align.CENTER)
        self.spinner = Gtk.Spinner(visible=False)
        btn_box.append(self.spinner)
        btn_box.append(Gtk.Label(label="Create Vault"))
        self.button.set_child(btn_box)
        self.button.set_size_request(180, -1)
        self.button.connect("clicked", lambda *_: self.create())
        content.append(self.button)
        self.append(_page(content))
        self._update()

    def focus(self):
        self.pw.grab_focus()

    def _suggest(self, *_):
        phrase = generator.passphrase(words=5, separator="-", capitalize=True, include_number=True)
        self.suggestion.set_text(phrase)
        self.suggestion.set_visible(True)
        self.pw.set_text(phrase)
        self.confirm.set_text("")
        self.confirm.grab_focus()

    def _ready(self) -> bool:
        pw = self.pw.get_text()
        return bool(pw) and strength.estimate_master(pw).level >= MIN_MASTER_LEVEL and pw == self.confirm.get_text()

    def _update(self, *_):
        pw = self.pw.get_text()
        s = strength.estimate_master(pw)
        self.level.set_value(s.level + 1 if pw else 0)
        self.strength.set_level(s.level, s.label)
        self.strength.set_visible(bool(pw))
        if not pw:
            self.hint.set_text("Use at least four random words, or let Keyhold suggest some.")
        elif s.level < MIN_MASTER_LEVEL:
            self.hint.set_text("This password is too easy to guess. Make it longer or use more words.")
        elif self.confirm.get_text() and self.confirm.get_text() != pw:
            self.hint.set_text("The passwords don't match.")
        elif not self.confirm.get_text():
            self.hint.set_text("Type it again to confirm.")
        else:
            self.hint.set_text("")
        self.button.set_sensitive(self._ready())

    def create(self):
        if not self._ready():
            return
        password = self.pw.get_text()
        self.button.set_sensitive(False)
        self.spinner.set_visible(True)
        self.spinner.set_spinning(True)

        def done(session, error):
            self.spinner.set_visible(False)
            self.spinner.set_spinning(False)
            if error:
                self.hint.set_text(f"Couldn't create the vault: {error}")
                self.button.set_sensitive(True)
                return
            self.pw.set_text("")
            self.confirm.set_text("")
            self.suggestion.set_text("")
            self.suggestion.set_visible(False)
            self.on_created(session)

        run_in_thread(lambda: self.store.create(password), done)
