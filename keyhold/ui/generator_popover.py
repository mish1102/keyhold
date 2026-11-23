"""Password generator popover (header bar and password fields)."""

from __future__ import annotations

from gi.repository import Adw, Gtk

from .. import generator, strength

SEPARATORS = [("-", "Hyphen  -"), (".", "Period  ."), ("_", "Underscore  _"), (" ", "Space"), (",", "Comma  ,")]


class GeneratorPanel(Gtk.Box):
    def __init__(self, settings: dict, on_settings_changed, on_copy, on_use=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12,
                         margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
        self.set_size_request(360, -1)
        self.settings = dict(settings)
        self.on_settings_changed = on_settings_changed
        self.on_copy = on_copy
        self.on_use = on_use
        self._building = True

        # Preview
        preview_box = Gtk.Box(spacing=6)
        self.preview = Gtk.Label(xalign=0, hexpand=True, wrap=True, wrap_mode=2, selectable=False,
                                 css_classes=["kh-mono-preview"])
        regen = Gtk.Button(icon_name="view-refresh-symbolic", valign=Gtk.Align.CENTER,
                           tooltip_text="Generate another", css_classes=["flat"])
        regen.connect("clicked", lambda *_: self.regenerate())
        preview_box.append(self.preview)
        preview_box.append(regen)
        self.append(preview_box)

        self.strength_label = Gtk.Label(xalign=0, css_classes=["caption"])
        self.append(self.strength_label)

        # Mode switcher
        modes = Gtk.Box(css_classes=["linked"], halign=Gtk.Align.CENTER)
        self.mode_buttons = {}
        group = None
        for mode, label in (("random", "Random"), ("words", "Memorable"), ("pin", "PIN")):
            b = Gtk.ToggleButton(label=label)
            if group:
                b.set_group(group)
            group = group or b
            b.connect("toggled", self._on_mode_toggled, mode)
            modes.append(b)
            self.mode_buttons[mode] = b
        self.append(modes)

        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
        self.length_row = Adw.SpinRow.new_with_range(4, 100, 1)
        self.length_row.set_title("Characters")
        self.length_row.connect("notify::value", self._changed)
        self.digits_row = Adw.SwitchRow(title="Numbers")
        self.digits_row.connect("notify::active", self._changed)
        self.symbols_row = Adw.SwitchRow(title="Symbols")
        self.symbols_row.connect("notify::active", self._changed)
        self.ambiguous_row = Adw.SwitchRow(title="Avoid look-alikes", subtitle="Leave out I l 1 O 0 o")
        self.ambiguous_row.connect("notify::active", self._changed)
        self.words_row = Adw.SpinRow.new_with_range(3, 12, 1)
        self.words_row.set_title("Words")
        self.words_row.connect("notify::value", self._changed)
        self.sep_row = Adw.ComboRow(title="Separator", model=Gtk.StringList.new([s[1] for s in SEPARATORS]))
        self.sep_row.connect("notify::selected", self._changed)
        self.cap_row = Adw.SwitchRow(title="Capitalize")
        self.cap_row.connect("notify::active", self._changed)
        self.num_row = Adw.SwitchRow(title="Add a number")
        self.num_row.connect("notify::active", self._changed)
        self.pin_row = Adw.SpinRow.new_with_range(4, 12, 1)
        self.pin_row.set_title("Digits")
        self.pin_row.connect("notify::value", self._changed)
        for r in (self.length_row, self.digits_row, self.symbols_row, self.ambiguous_row, self.words_row,
                  self.sep_row, self.cap_row, self.num_row, self.pin_row):
            rows.append(r)
        self.append(rows)

        buttons = Gtk.Box(spacing=8, halign=Gtk.Align.END)
        copy = Gtk.Button(label="Copy")
        copy.connect("clicked", lambda *_: self.on_copy(self.value))
        buttons.append(copy)
        if on_use:
            use = Gtk.Button(label="Use Password", css_classes=["suggested-action"])
            use.connect("clicked", lambda *_: self.on_use(self.value))
            buttons.append(use)
        self.append(buttons)

        self._load(settings)
        self._building = False
        self.regenerate()

    def _load(self, s: dict):
        mode = s.get("mode", "random")
        self.length_row.set_value(s.get("length", 20) if mode != "pin" else 20)
        self.digits_row.set_active(s.get("digits", True))
        self.symbols_row.set_active(s.get("symbols", True))
        self.ambiguous_row.set_active(s.get("avoid_ambiguous", False))
        self.words_row.set_value(s.get("words", 4))
        seps = [x[0] for x in SEPARATORS]
        self.sep_row.set_selected(seps.index(s.get("separator", "-")) if s.get("separator", "-") in seps else 0)
        self.cap_row.set_active(s.get("capitalize", True))
        self.num_row.set_active(s.get("include_number", False))
        self.pin_row.set_value(s.get("pin_length", 6))
        self.mode = mode
        self.mode_buttons[mode].set_active(True)
        self._sync_visibility()

    def _collect(self) -> dict:
        return {
            "mode": self.mode,
            "length": int(self.length_row.get_value()),
            "digits": self.digits_row.get_active(),
            "symbols": self.symbols_row.get_active(),
            "avoid_ambiguous": self.ambiguous_row.get_active(),
            "words": int(self.words_row.get_value()),
            "separator": SEPARATORS[self.sep_row.get_selected()][0],
            "capitalize": self.cap_row.get_active(),
            "include_number": self.num_row.get_active(),
            "pin_length": int(self.pin_row.get_value()),
        }

    def _sync_visibility(self):
        m = self.mode
        for r in (self.length_row, self.digits_row, self.symbols_row, self.ambiguous_row):
            r.set_visible(m == "random")
        for r in (self.words_row, self.sep_row, self.cap_row, self.num_row):
            r.set_visible(m == "words")
        self.pin_row.set_visible(m == "pin")

    def _on_mode_toggled(self, button, mode):
        if button.get_active():
            self.mode = mode
            self._sync_visibility()
            self._changed()

    def _changed(self, *_):
        if self._building:
            return
        self.settings = self._collect()
        self.on_settings_changed(self.settings)
        self.regenerate()

    def regenerate(self):
        s = self._collect()
        gen = dict(s)
        if s["mode"] == "pin":
            gen["length"] = s["pin_length"]
        self.value = generator.generate(gen)
        self.preview.set_text(self.value)
        bits = generator.entropy_bits(**gen)
        level = sum(1 for t in strength.THRESHOLDS if bits >= t)
        self.strength_label.set_text(f"{strength.LABELS[level]} · {bits:.0f} bits of entropy")


class GeneratorPopover(Gtk.Popover):
    def __init__(self, settings_getter, on_settings_changed, on_copy, on_use=None):
        super().__init__()
        self.settings_getter = settings_getter
        self.on_settings_changed = on_settings_changed
        self.on_copy = on_copy
        self.on_use = on_use
        self.connect("show", self._rebuild)

    def _rebuild(self, *_):
        def use(value):
            self.popdown()
            self.on_use(value)

        def copy(value):
            self.popdown()
            self.on_copy(value)

        self.set_child(GeneratorPanel(self.settings_getter(), self.on_settings_changed, copy,
                                      use if self.on_use else None))
