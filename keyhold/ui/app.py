"""Application object: single instance, styling, screen-lock and sleep hooks."""

from __future__ import annotations

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, Gtk  # noqa: E402

from .. import APP_ID, APP_NAME  # noqa: E402
from ..store import VaultStore, default_vault_path  # noqa: E402
from . import config  # noqa: E402
from .preferences import apply_theme  # noqa: E402
from .window import MainWindow  # noqa: E402


class KeyholdApp(Adw.Application):
    def __init__(self, store: VaultStore | None = None):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.store = store or VaultStore(default_vault_path())
        self.window: MainWindow | None = None
        self._subscriptions = []
        self.connect("activate", self._on_activate)
        self.connect("startup", self._on_startup)
        self.connect("shutdown", self._on_shutdown)

    def _on_startup(self, *_):
        Gtk.Window.set_default_icon_name(APP_ID)
        apply_theme(config.load().get("theme", "dark"))
        css = Gtk.CssProvider()
        css.load_from_path(str(Path(__file__).with_name("style.css")))
        Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), css,
                                                  Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        icons = Path(__file__).resolve().parents[2] / "data" / "icons"
        if icons.is_dir():
            Gtk.IconTheme.get_for_display(Gdk.Display.get_default()).add_search_path(str(icons))
        quit_action = Gio.SimpleAction.new("quit", None)
        quit_action.connect("activate", lambda *_: self.window.close() if self.window else self.quit())
        self.add_action(quit_action)
        self.set_accels_for_action("app.quit", ["<Ctrl>q"])
        self._watch_screen_lock()

    def _on_activate(self, *_):
        if self.window is None:
            self.window = MainWindow(self, self.store)
        self.window.present()

    def _on_shutdown(self, *_):
        if self.window:
            self.window.shutdown()

    # Lock when the session's screen locks or the machine is about to sleep.
    def _watch_screen_lock(self):
        def lock_if_enabled(*_args):
            win = self.window
            if win and win.session and not win.session.locked:
                if win.data.settings.get("lock_on_screen_lock", True):
                    win.lock()

        def on_screensaver(_conn, _sender, _path, _iface, _signal, params):
            if params.unpack()[0]:
                lock_if_enabled()

        def on_sleep(_conn, _sender, _path, _iface, _signal, params):
            if params.unpack()[0]:
                lock_if_enabled()

        try:
            session_bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
            for iface, path in (("org.gnome.ScreenSaver", "/org/gnome/ScreenSaver"),
                                ("org.freedesktop.ScreenSaver", "/org/freedesktop/ScreenSaver")):
                self._subscriptions.append(session_bus.signal_subscribe(
                    None, iface, "ActiveChanged", path, None, Gio.DBusSignalFlags.NONE, on_screensaver))
        except Exception:  # no session bus (e.g. headless)
            pass
        try:
            system_bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
            self._subscriptions.append(system_bus.signal_subscribe(
                "org.freedesktop.login1", "org.freedesktop.login1.Manager", "PrepareForSleep",
                "/org/freedesktop/login1", None, Gio.DBusSignalFlags.NONE, on_sleep))
            # logind's Lock signal on any session object ("loginctl lock-session").
            self._subscriptions.append(system_bus.signal_subscribe(
                "org.freedesktop.login1", "org.freedesktop.login1.Session", "Lock", None, None,
                Gio.DBusSignalFlags.NONE, lock_if_enabled))
        except Exception:
            pass


def main(argv=None) -> int:
    import sys

    Gtk.Window.set_default_icon_name(APP_ID)
    from gi.repository import GLib

    GLib.set_application_name(APP_NAME)
    app = KeyholdApp()
    return app.run(argv if argv is not None else sys.argv)
