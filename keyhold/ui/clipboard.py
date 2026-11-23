"""Copying secrets: mark them as sensitive and clear them after a timeout."""

from __future__ import annotations

from gi.repository import Gdk, GLib, GObject

# Clipboard managers (KDE Klipper, GPaste, CopyQ, ...) skip history for
# content offered with this MIME type set to "secret".
SECRET_HINT_MIME = "x-kde-passwordManagerHint"


class SecureClipboard:
    def __init__(self, display: Gdk.Display, clear_after_seconds=lambda: 90):
        self.clipboard = display.get_clipboard()
        self.clear_after_seconds = clear_after_seconds
        self._timer = None
        self._provider = None

    def copy(self, text: str, secret: bool = True) -> int:
        """Copy ``text``. Returns the number of seconds until it is cleared (0 = never)."""
        providers = [Gdk.ContentProvider.new_for_value(GObject.Value(str, text))]
        if secret:
            providers.append(
                Gdk.ContentProvider.new_for_bytes(SECRET_HINT_MIME, GLib.Bytes.new(b"secret"))
            )
        self._provider = Gdk.ContentProvider.new_union(providers)
        self.clipboard.set_content(self._provider)
        self._cancel_timer()
        seconds = int(self.clear_after_seconds()) if secret else 0
        if seconds > 0:
            self._timer = GLib.timeout_add_seconds(seconds, self._on_timeout)
        return seconds

    def _cancel_timer(self):
        if self._timer is not None:
            GLib.source_remove(self._timer)
            self._timer = None

    def _on_timeout(self):
        self._timer = None
        self.clear()
        return False

    def holds_our_copy(self) -> bool:
        return self._provider is not None and self.clipboard.get_content() is self._provider

    def clear(self) -> None:
        """Empty the clipboard, but only if it still holds exactly what we put
        there (never something the user copied afterwards)."""
        self._cancel_timer()
        if self.holds_our_copy():
            self.clipboard.set_content(None)
        self._provider = None
