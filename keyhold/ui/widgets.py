"""Small reusable widgets."""

from __future__ import annotations

import math
import time
import zlib

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Gsk", "4.0")
gi.require_version("Graphene", "1.0")
from gi.repository import Gdk, GLib, Graphene, Gsk, Gtk, Pango  # noqa: E402

from .. import strength, totp  # noqa: E402
from ..model import CATEGORIES, Item  # noqa: E402
from ..listing import display_title  # noqa: E402


class ItemIcon(Gtk.Box):
    """Colored rounded square with the item's initial (logins) or category icon."""

    def __init__(self, item: Item | None = None, size: int = 32):
        super().__init__(halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER, hexpand=False, vexpand=False)
        self.size = size
        self.set_size_request(size, size)
        self.add_css_class("kh-icon")
        if size >= 48:
            self.add_css_class("kh-large")
        self._color_class = None
        self._child = None
        if item:
            self.set_item(item)

    def set_item(self, item: Item) -> None:
        title = display_title(item)
        index = zlib.crc32(title.lower().encode()) % 10
        if self._color_class:
            self.remove_css_class(self._color_class)
        self._color_class = f"kh-icon-{index}"
        self.add_css_class(self._color_class)
        if self._child:
            self.remove(self._child)
        if item.category in ("login", "password") and title[:1].isalnum():
            label = Gtk.Label(label=title[:1].upper(), hexpand=True, halign=Gtk.Align.CENTER)
            px = int(self.size * 0.5)
            label.set_markup(f'<span size="{px * 1024}">{GLib.markup_escape_text(title[:1].upper())}</span>')
            self._child = label
        else:
            image = Gtk.Image.new_from_icon_name(CATEGORIES[item.category].icon)
            image.set_pixel_size(int(self.size * 0.55))
            image.set_hexpand(True)
            self._child = image
        self.append(self._child)


class Ring(Gtk.Widget):
    """A circular progress ring drawn with GSK paths (no cairo needed)."""

    def __init__(self, size: int = 14, show_text: bool = False):
        super().__init__(valign=Gtk.Align.CENTER, halign=Gtk.Align.CENTER)
        self.size = size
        self.fraction = 1.0
        self.text = ""
        self.alert = False
        self.show_text = show_text

    def set_progress(self, fraction: float, text: str = "", alert: bool = False):
        self.fraction = max(0.0, min(1.0, fraction))
        self.text = text
        self.alert = alert
        self.queue_draw()

    def do_measure(self, orientation, for_size):
        return self.size, self.size, -1, -1

    def do_snapshot(self, snapshot):
        w, h = self.get_width(), self.get_height()
        cx, cy = w / 2, h / 2
        r = min(w, h) / 2 - 1.5
        color = self.get_color()
        if self.alert:
            color = Gdk.RGBA()
            color.parse("#e01b24")
        faint = color.copy()
        faint.alpha = 0.25
        stroke = Gsk.Stroke.new(2.0 if self.size < 18 else 2.2)
        stroke.set_line_cap(Gsk.LineCap.ROUND)

        circle = Gsk.PathBuilder.new()
        circle.add_circle(Graphene.Point().init(cx, cy), r)
        snapshot.append_stroke(circle.to_path(), stroke, faint)

        if self.fraction > 0:
            arc = Gsk.PathBuilder.new()
            if self.fraction >= 0.999:
                arc.add_circle(Graphene.Point().init(cx, cy), r)
            else:
                theta = 2 * math.pi * self.fraction
                arc.move_to(cx, cy - r)
                arc.svg_arc_to(r, r, 0, theta > math.pi, True,
                               cx + r * math.sin(theta), cy - r * math.cos(theta))
            snapshot.append_stroke(arc.to_path(), stroke, color)

        if self.show_text and self.text:
            layout = self.create_pango_layout(self.text)
            desc = Pango.FontDescription.from_string("Sans Bold 6.5")
            layout.set_font_description(desc)
            _ink, logical = layout.get_pixel_extents()
            snapshot.save()
            snapshot.translate(Graphene.Point().init(cx - logical.width / 2, cy - logical.height / 2))
            snapshot.append_layout(layout, color)
            snapshot.restore()


class StrengthLabel(Gtk.Box):
    """Strength word plus a small colored ring, e.g. "Fantastic ◯"."""

    def __init__(self):
        super().__init__(spacing=6, valign=Gtk.Align.CENTER)
        self.label = Gtk.Label(css_classes=["caption-heading"])
        self.ring = Ring(14)
        self.append(self.label)
        self.append(self.ring)
        self._css = None

    def set_password(self, password: str) -> None:
        self.set_visible(bool(password))
        if not password:
            return
        s = strength.estimate(password)
        self.set_level(s.level, s.label)

    def set_level(self, level: int, text: str) -> None:
        self.label.set_text(text)
        if self._css:
            self.remove_css_class(self._css)
        self._css = f"kh-strength-{level}"
        self.add_css_class(self._css)
        self.ring.set_progress((level + 1) / len(strength.LABELS))


class Countdown(Ring):
    """Ring that empties as the one-time code's period runs out."""

    def __init__(self):
        super().__init__(20, show_text=True)

    def update(self, remaining: int, period: int) -> None:
        self.set_progress(remaining / period, str(remaining), alert=remaining <= 5)


class TotpDisplay(Gtk.Box):
    """Live one-time code with a countdown. Stops ticking when unrealized."""

    def __init__(self, value: str):
        super().__init__(spacing=10, valign=Gtk.Align.CENTER)
        self.code_label = Gtk.Label(xalign=0, css_classes=["kh-totp-code"], selectable=False)
        self.countdown = Countdown()
        self.append(self.code_label)
        self.append(self.countdown)
        self._timer = None
        self.error = None
        try:
            self.spec = totp.parse(value)
        except ValueError as exc:
            self.spec = None
            self.error = str(exc)
            self.code_label.set_text("invalid secret")
            self.code_label.add_css_class("error")
            self.countdown.set_visible(False)
            return
        self._tick()
        self.connect("map", lambda *_: self._start())
        self.connect("unmap", lambda *_: self._stop())

    def current_code(self) -> str:
        return totp.code(self.spec, time.time()) if self.spec else ""

    def _start(self):
        if self._timer is None:
            self._timer = GLib.timeout_add(500, self._tick)

    def _stop(self):
        if self._timer is not None:
            GLib.source_remove(self._timer)
            self._timer = None

    def _tick(self):
        now = time.time()
        self.code_label.set_text(totp.format_code(totp.code(self.spec, now)))
        self.countdown.update(totp.seconds_remaining(self.spec, now), self.spec.period)
        return True


def section_header(text: str) -> Gtk.Label:
    return Gtk.Label(label=text.upper(), xalign=0, css_classes=["kh-section-header"])


from ..listing import format_time  # noqa: E402,F401  (re-exported for the UI)
