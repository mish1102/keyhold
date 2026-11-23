"""Drive the real app with a throwaway demo vault and save PNG screenshots.

Run headless (doesn't open windows on your desktop):

    gtk4-broadwayd :7 &
    GDK_BACKEND=broadway BROADWAY_DISPLAY=:7 .venv/bin/python tools/screenshot.py OUTDIR

Uses a temporary data directory and a fast KDF; never touches your real vault.
"""

from __future__ import annotations

import os
import sys
import tempfile
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
TMP = tempfile.mkdtemp(prefix="keyhold-shot-")
os.environ["KEYHOLD_DATA_DIR"] = TMP

import gi  # noqa: E402

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Gsk", "4.0")
gi.require_version("Graphene", "1.0")
from gi.repository import Gio, GLib, Graphene, Gsk, Gtk  # noqa: E402

import demo_data  # noqa: E402
from keyhold.crypto import KdfCost  # noqa: E402
from keyhold.store import VaultStore  # noqa: E402
from keyhold.ui.app import KeyholdApp  # noqa: E402

FAST = KdfCost(memory_kib=1024, iterations=1, lanes=1)
PASSWORD = "demo master password 42"
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "screenshots")
OUT.mkdir(parents=True, exist_ok=True)
SCENES = sys.argv[2].split(",") if len(sys.argv) > 2 else None


def snap(widget, name: str, overlay: Gtk.Widget | None = None) -> bool:
    """Save the widget's last rendered frame (plus an optional dialog drawn on
    top). Returns False if nothing has been drawn yet."""
    from gi.repository import Adw, Gdk

    w, h = widget.get_width(), widget.get_height()
    nodes = []
    for layer in ([widget] if overlay is None else [widget.get_content(), overlay]):
        inner = Gtk.Snapshot()
        Gtk.WidgetPaintable.new(layer).snapshot(inner, layer.get_width(), layer.get_height())
        node = inner.to_node()
        if node is None:
            layer.queue_draw()
            return False
        nodes.append(node)
    snapshot = Gtk.Snapshot()
    # The window paints its own background; the content we capture doesn't.
    bg = Gdk.RGBA()
    bg.parse("#242424" if Adw.StyleManager.get_default().get_dark() else "#fafafa")
    snapshot.append_color(bg, Graphene.Rect().init(0, 0, w, h))
    for node in nodes:
        snapshot.append_node(node)
    node = snapshot.to_node()
    renderer = Gsk.CairoRenderer()
    renderer.realize_for_display(widget.get_display())
    try:
        texture = renderer.render_texture(node, Graphene.Rect().init(0, 0, w, h))
    finally:
        renderer.unrealize()
    texture.save_to_png(str(OUT / f"{name}.png"))
    print("saved", OUT / f"{name}.png")
    return True


def main():
    import json

    width, height = (int(x) for x in os.environ.get("SHOT_SIZE", "1180x760").split("x"))
    (Path(TMP) / "config.json").write_text(json.dumps(
        {"width": width, "height": height, "theme": os.environ.get("SHOT_THEME", "dark")}))
    store = VaultStore(Path(TMP) / "vault.keyhold", cost=FAST)
    session = store.create(PASSWORD)
    demo_data.populate(session.data)
    session.save()
    session.lock()

    app = KeyholdApp(store=store)
    def headless_settings(*_):
        settings = Gtk.Settings.get_default()
        settings.set_property("gtk-enable-animations", False)
        settings.set_property("gtk-xft-dpi", 96 * 1024)  # broadway reports -1

    app.connect("startup", headless_settings)
    app.set_flags(Gio.ApplicationFlags.NON_UNIQUE)
    steps = []

    def win():
        return app.window

    def step(fn, delay=400):
        steps.append((fn, delay))

    def run_steps():
        if not steps:
            app.quit()
            return False
        fn, delay = steps[0]
        try:
            result = fn()
            if result is False and getattr(fn, "_tries", 0) < 15:
                fn._tries = getattr(fn, "_tries", 0) + 1
                GLib.timeout_add(250, run_steps)
                return False
            steps.pop(0)
        except Exception:
            traceback.print_exc()
            app.quit()
            return False
        GLib.timeout_add(delay, run_steps)
        return False

    def select_title(title):
        for row in win().itemlist._rows():
            item = win().data.get(row.item_id)
            if item.title == title:
                win().itemlist.listbox.select_row(row)
                return
        raise AssertionError(f"no item {title}")

    def want(scene):
        return SCENES is None or scene in SCENES

    step(lambda: None, 600)
    if want("lock"):
        step(lambda: snap(win(), "01-lock"))
    step(lambda: (win().unlock_page.entry.set_text(PASSWORD), win().unlock_page.unlock()), 900)
    step(lambda: select_title("Evernote"), 600)

    def sizes():
        w = win()
        print("window", w.get_width(), w.get_height(), "sidebar", w.outer_split.get_sidebar().get_width(),
              "list", w.inner_split.get_sidebar().get_width(), "detail", w.inner_split.get_content().get_width(),
              "outer collapsed", w.outer_split.get_collapsed(), "inner collapsed", w.inner_split.get_collapsed(),
              "min", w.outer_split.get_min_sidebar_width(), w.inner_split.get_min_sidebar_width(),
              "frac", w.outer_split.get_sidebar_width_fraction(), w.inner_split.get_sidebar_width_fraction(),
              "dpi", Gtk.Settings.get_default().get_property("gtk-xft-dpi"))

    step(sizes, 100)
    if want("main"):
        step(lambda: snap(win(), "02-main-evernote"))
    if want("watchtower"):
        step(lambda: select_title("Forums"), 500)
        step(lambda: snap(win(), "03-weak-unsecured"))
    if want("card"):
        step(lambda: select_title("Visa Platinum"), 500)
        step(lambda: snap(win(), "04-card"))
    if want("edit"):
        step(lambda: select_title("Evernote"), 400)
        step(lambda: win().detail.start_edit(), 600)
        step(lambda: snap(win(), "05-edit"))
        step(lambda: win().detail.cancel_edit(), 400)
    if want("search"):
        step(lambda: win().search.set_text("alex.rivera@"), 700)
        step(lambda: snap(win(), "06-search"))
        step(lambda: win().search.set_text(""), 500)
    if want("generator"):
        step(lambda: win().show_generator(), 700)
        step(lambda: snap(win(), "07-generator", win().dialogs[-1]))
        step(lambda: win().dialogs[-1].force_close(), 400)
    if want("prefs"):
        step(lambda: win().show_preferences(), 700)
        step(lambda: snap(win(), "08-preferences", win().dialogs[-1]))
        step(lambda: win().dialogs[-1].force_close(), 400)
    step(lambda: win().lock(), 500)
    if want("lock"):
        step(lambda: snap(win(), "11-locked-again"))

    def on_activate(*_):
        GLib.timeout_add(800, run_steps)

    app.connect_after("activate", on_activate)
    app.run([sys.argv[0]])


if __name__ == "__main__":
    main()
