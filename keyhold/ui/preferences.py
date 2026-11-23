"""Preferences dialog."""

from __future__ import annotations

import time

from gi.repository import Adw, Gtk

from .. import strength
from .lockscreen import MIN_MASTER_LEVEL, run_in_thread
from .widgets import StrengthLabel, format_time
from . import config

AUTO_LOCK = [(1, "1 minute"), (2, "2 minutes"), (5, "5 minutes"), (10, "10 minutes"), (30, "30 minutes"),
             (60, "1 hour"), (240, "4 hours")]
CLIPBOARD = [(30, "30 seconds"), (60, "1 minute"), (90, "90 seconds"), (120, "2 minutes"), (300, "5 minutes")]
THEMES = [("dark", "Dark"), ("light", "Light"), ("system", "Follow system")]


def apply_theme(theme: str):
    schemes = {"dark": Adw.ColorScheme.FORCE_DARK, "light": Adw.ColorScheme.FORCE_LIGHT,
               "system": Adw.ColorScheme.DEFAULT}
    Adw.StyleManager.get_default().set_color_scheme(schemes.get(theme, Adw.ColorScheme.FORCE_DARK))


def _combo(title, subtitle, options, current, on_change):
    row = Adw.ComboRow(title=title, subtitle=subtitle, model=Gtk.StringList.new([o[1] for o in options]))
    values = [o[0] for o in options]
    row.set_selected(values.index(current) if current in values else 0)
    row.connect("notify::selected", lambda r, _p: on_change(values[r.get_selected()]))
    return row


class PreferencesDialog(Adw.PreferencesDialog):
    def __init__(self, win):
        super().__init__(title="Preferences")
        self.win = win
        s = win.data.settings

        def setting(key):
            def set_value(value):
                win.data.settings[key] = value
                win.save(quiet=True)
            return set_value

        # --- Security
        page = Adw.PreferencesPage(title="Security", icon_name="channel-secure-symbolic")
        lock = Adw.PreferencesGroup(title="Locking")
        lock.add(_combo("Lock after inactivity", "Keyhold locks itself when you haven't used it for this long.",
                        AUTO_LOCK, s.get("auto_lock_minutes", 10), setting("auto_lock_minutes")))
        screen = Adw.SwitchRow(title="Lock when the screen locks or the computer sleeps",
                               active=s.get("lock_on_screen_lock", True))
        screen.connect("notify::active", lambda r, _p: setting("lock_on_screen_lock")(r.get_active()))
        lock.add(screen)
        page.add(lock)
        clip = Adw.PreferencesGroup(title="Clipboard")
        clip.add(_combo("Clear copied passwords after", "Only cleared if the clipboard still holds what Keyhold copied.",
                        CLIPBOARD, s.get("clipboard_clear_seconds", 90), setting("clipboard_clear_seconds")))
        page.add(clip)
        master = Adw.PreferencesGroup(title="Master password")
        change = Adw.ActionRow(title="Change master password", activatable=True)
        change.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
        change.connect("activated", lambda *_: self._change_password())
        master.add(change)
        page.add(master)
        self.add(page)

        # --- Watchtower
        wt = Adw.PreferencesPage(title="Watchtower", icon_name="security-high-symbolic")
        group = Adw.PreferencesGroup(
            title="Online checks",
            description=(
                "Finds passwords that appeared in data breaches, websites that were breached after you last "
                "changed your password, and websites that support one-time codes.\n\n"
                "Only the first 5 characters of each password's SHA-1 hash are sent to Have I Been Pwned "
                "(they can't work out your password from that). The breach list and the 2FA Directory list "
                "are downloaded whole, so nothing about your websites is sent. Results are stored inside "
                "your encrypted vault."))
        online = Adw.SwitchRow(title="Check passwords and websites online", active=s.get("online_checks", False))
        group.add(online)
        self.last = Adw.ActionRow(title="Last checked", subtitle=self._last_checked())
        check_now = Gtk.Button(label="Check Now", valign=Gtk.Align.CENTER)
        check_now.connect("clicked", lambda *_: (win.refresh_online_now(), self.last.set_subtitle("Checking…")))
        self.last.add_suffix(check_now)
        group.add(self.last)

        def on_online(row, _p):
            setting("online_checks")(row.get_active())
            check_now.set_sensitive(row.get_active())
            win.refresh()
            if row.get_active():
                win.refresh_online_now()
                self.last.set_subtitle("Checking…")

        online.connect("notify::active", on_online)
        check_now.set_sensitive(online.get_active())
        wt.add(group)
        self.add(wt)

        # --- Appearance
        look = Adw.PreferencesPage(title="Appearance", icon_name="applications-graphics-symbolic")
        g = Adw.PreferencesGroup()
        cfg_theme = config.load().get("theme", "dark")

        def on_theme(value):
            config.update(theme=value)
            apply_theme(value)

        g.add(_combo("Style", None, THEMES, cfg_theme, on_theme))
        look.add(g)
        self.add(look)

        # --- Vault
        vault = Adw.PreferencesPage(title="Vault", icon_name="drive-harddisk-symbolic")
        g = Adw.PreferencesGroup(title="Location")
        loc = Adw.ActionRow(title="Vault file", subtitle=str(win.store.path), subtitle_selectable=True, use_markup=False)
        g.add(loc)
        backups = Adw.ActionRow(title="Automatic backups", subtitle=f"{win.store.backup_dir}\n"
                                f"The {win.store.max_backups} most recent versions are kept, still encrypted.",
                                subtitle_selectable=True, use_markup=False)
        g.add(backups)
        vault.add(g)
        g2 = Adw.PreferencesGroup(title="Move your data")
        for title, action in (("Import from another password manager…", "win.import"),
                              ("Export encrypted backup…", "win.export-encrypted"),
                              ("Export unencrypted CSV…", "win.export-csv")):
            row = Adw.ActionRow(title=title, activatable=True)
            row.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
            row.connect("activated", lambda _r, a=action: (self.close(), win.activate_action(a, None)))
            g2.add(row)
        vault.add(g2)
        self.add(vault)

    def _last_checked(self):
        ts = self.win.data.watchtower.get("updated")
        return format_time(ts) if ts else "Never"

    def _change_password(self):
        dialog = Adw.Dialog(title="Change Master Password", content_width=420)
        tb = Adw.ToolbarView()
        header = Adw.HeaderBar(show_end_title_buttons=False, show_start_title_buttons=False)
        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda *_: dialog.close())
        apply = Gtk.Button(label="Change", css_classes=["suggested-action"], sensitive=False)
        header.pack_start(cancel)
        header.pack_end(apply)
        tb.add_top_bar(header)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14, margin_top=12, margin_bottom=18,
                      margin_start=18, margin_end=18)
        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
        current = Adw.PasswordEntryRow(title="Current master password")
        new = Adw.PasswordEntryRow(title="New master password")
        confirm = Adw.PasswordEntryRow(title="Confirm new master password")
        meter = StrengthLabel()
        new.add_suffix(meter)
        for r in (current, new, confirm):
            rows.append(r)
        box.append(rows)
        delete_old = Gtk.CheckButton(
            label="Remove older backups once you've unlocked with the new password\n"
                  "(they still open with the old one)", active=True)
        box.append(delete_old)
        status = Gtk.Label(wrap=True, xalign=0, css_classes=["dim-label"])
        box.append(status)
        tb.set_content(box)
        dialog.set_child(tb)

        def update(*_):
            pw = new.get_text()
            rating = strength.estimate_master(pw)
            meter.set_level(rating.level, rating.label)
            meter.set_visible(bool(pw))
            ok = bool(current.get_text()) and pw == confirm.get_text() and rating.level >= MIN_MASTER_LEVEL \
                and pw != current.get_text()
            if pw and rating.level < MIN_MASTER_LEVEL:
                status.set_text("The new password is too easy to guess.")
            elif confirm.get_text() and pw != confirm.get_text():
                status.set_text("The new passwords don't match.")
            else:
                status.set_text("")
            apply.set_sensitive(ok)

        for r in (current, new, confirm):
            r.connect("changed", update)

        def do_change(*_):
            if not apply.get_sensitive():
                return
            apply.set_sensitive(False)
            status.set_text("Re-encrypting your vault…")
            session = self.win.session
            cur, pw, purge = current.get_text(), new.get_text(), delete_old.get_active()

            def work():
                # Only the slow, side-effect-free part runs off the main thread.
                if not session.check_password(cur):
                    return None
                return session.prepare_password_change(pw)

            def done(new_key, error):
                if session is not self.win.session or session.locked:
                    if new_key:
                        new_key.wipe()
                    return  # locked meanwhile: nothing was changed
                if error:
                    update()
                    status.set_text(f"Couldn't change the password: {error}")
                    return
                if new_key is None:
                    update()
                    status.set_text("The current password is incorrect.")
                    return
                try:
                    session.apply_password_change(new_key, delete_old_backups=purge)
                except Exception as exc:
                    update()
                    status.set_text(f"The password was NOT changed: {exc}")
                    return
                dialog.close()
                self.win.toast("Master password changed")

            run_in_thread(work, done)

        apply.connect("clicked", do_change)
        confirm.connect("entry-activated", do_change)
        self.win._present(dialog)
        current.grab_focus()
