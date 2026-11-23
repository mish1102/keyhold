"""End-to-end smoke test of the GTK app against a throwaway vault.

    gtk4-broadwayd :7 &
    GDK_BACKEND=broadway BROADWAY_DISPLAY=:7 .venv/bin/python tools/smoke.py

Drives the real window (not mocks) and checks what reaches the encrypted file
on disk after each step. Exits non-zero on the first failure.
"""

from __future__ import annotations

import hashlib
import os
import stat
import sys
import tempfile
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
TMP = Path(tempfile.mkdtemp(prefix="keyhold-smoke-"))
os.environ["KEYHOLD_DATA_DIR"] = str(TMP / "data")

import gi  # noqa: E402

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk  # noqa: E402

from keyhold import model, watchtower_online  # noqa: E402
from keyhold.crypto import KdfCost  # noqa: E402
from keyhold.store import VaultStore  # noqa: E402
from keyhold.ui.app import KeyholdApp  # noqa: E402

FAST = KdfCost(memory_kib=1024, iterations=1, lanes=1)
MASTER = "correct-horse-battery-staple-42"
NEW_MASTER = "Another-Long-Master-Passphrase-77"
store = VaultStore(TMP / "data" / "vault.keyhold", cost=FAST)
app = KeyholdApp(store=store)
app.set_flags(Gio.ApplicationFlags.NON_UNIQUE)
failures = []
checks = 0


def check(cond, what):
    global checks
    checks += 1
    if not cond:
        raise AssertionError(what)


def disk(password=None):
    """Open the vault file independently, as a second reader would."""
    return VaultStore(store.path, cost=FAST).unlock(password or current_password[0], take_lock=False).data


current_password = [MASTER]


def wait(cond, timeout=10.0):
    ctx = GLib.MainContext.default()
    end = time.time() + timeout
    while time.time() < end:
        while ctx.pending():
            ctx.iteration(False)
        if cond():
            return True
        time.sleep(0.02)
    return False


def pump(seconds=0.2):
    wait(lambda: False, seconds)


def rows_of(widget, cls):
    out = []
    child = widget.get_first_child()
    while child:
        if isinstance(child, cls):
            out.append(child)
        out.extend(rows_of(child, cls))
        child = child.get_next_sibling()
    return out


def entry_row(editor, title_prefix):
    for r in rows_of(editor, Adw.EntryRow):
        if r.get_title().startswith(title_prefix):
            return r
    raise AssertionError(f"no entry row {title_prefix!r}")


def respond(win, response):
    dialog = win.dialogs[-1]
    dialog.emit("response", response)
    dialog.force_close()
    pump()


def scenario(win):
    # 1. First run: create vault through the create page.
    check(win.stack.get_visible_child_name() == "create", "fresh start shows the create page")
    win.create_page.pw.set_text("weak")
    win.create_page.confirm.set_text("weak")
    check(not win.create_page.button.get_sensitive(), "weak master password is refused")
    win.create_page.pw.set_text(MASTER)
    win.create_page.confirm.set_text(MASTER)
    check(win.create_page.button.get_sensitive(), "strong matching master password enables Create")
    win.create_page.create()
    check(wait(lambda: win.stack.get_visible_child_name() == "main"), "vault created and unlocked")
    check(stat.S_IMODE(os.stat(store.path).st_mode) == 0o600, "vault file is 0600")

    # 2. New login through the editor.
    win.new_item("login")
    ed = win.detail.editor
    check(ed is not None and ed.is_new, "editor opened for new login")
    ed.title_row.set_text("Bank of Example")
    entry_row(ed, "username").set_text("alex@example.com")
    pw_row = rows_of(ed, Adw.PasswordEntryRow)[0]
    check(len(pw_row.get_text()) >= 16, "new login gets a generated password")
    pw_row.set_text("first-Password-123!")
    entry_row(ed, "website").set_text("https://bank.example.com")
    entry_row(ed, "one-time password").set_text("not valid base32 !!!")
    win.detail.save_edit()
    check(win.detail.editing, "invalid TOTP secret blocks saving")
    entry_row(ed, "one-time password").set_text("JBSWY3DPEHPK3PXP")
    win.detail.save_edit()
    check(not win.detail.editing, "save closes editor")
    item = next(i for i in disk().items if i.title == "Bank of Example")
    check(item.username == "alex@example.com" and item.password == "first-Password-123!", "login saved to disk")
    check(item.totp == "JBSWY3DPEHPK3PXP", "TOTP secret saved")
    check(win.detail.item.id == item.id, "new item selected after save")

    # 3. Edit password -> history.
    win.detail.start_edit()
    rows_of(win.detail.editor, Adw.PasswordEntryRow)[0].set_text("second-Password-456!")
    win.detail.save_edit()
    item = disk().get(item.id)
    check(item.password == "second-Password-456!", "edited password saved")
    check([h["value"] for h in item.password_history] == ["first-Password-123!"], "password history kept")

    # 4. Cancel edit discards changes.
    win.detail.start_edit()
    win.detail.editor.title_row.set_text("SHOULD NOT SAVE")
    win.detail.cancel_edit()
    check(disk().get(item.id).title == "Bank of Example", "cancel discards edits")

    # 5. Favorite, duplicate, trash, restore, purge.
    win.set_favorite(item.id, True)
    check(disk().get(item.id).favorite, "favorite saved")
    win.duplicate(item.id)
    copies = [i for i in disk().items if i.title == "Bank of Example copy"]
    check(len(copies) == 1 and copies[0].password_history == [], "duplicate created without history")
    win.trash(copies[0].id)
    check(disk().get(copies[0].id).trashed_at is not None, "trash saved")
    win.restore(copies[0].id)
    check(disk().get(copies[0].id).trashed_at is None, "restore saved")
    win.purge(copies[0].id)
    respond(win, "delete")
    check(disk().get(copies[0].id) is None, "purge removes item from disk")

    # 6. Search and sort.
    win.search.set_text("bank.example")
    pump(0.4)
    check([r.item_id for r in win.itemlist._rows()] == [item.id], "search finds by website")
    win.search.set_text("zzzz-nothing")
    pump(0.4)
    check(list(win.itemlist._rows()) == [], "search with no match is empty")
    win.search.set_text("")
    pump(0.4)
    win.itemlist._sort_checks["modified"].set_active(True)
    pump()
    check(disk().settings["sort"] == "modified", "sort preference saved")

    # 7. Vaults.
    win._new_vault()
    win.dialogs[-1].get_extra_child().set_text("Work")
    respond(win, "ok")
    check([v.name for v in disk().vaults] == ["Personal", "Work"], "new vault saved")
    check(win.vault_filter is not None, "switched to new vault")
    win.new_item("secure_note")
    win.detail.editor.title_row.set_text("Work note")
    win.detail.save_edit()
    note = next(i for i in disk().items if i.title == "Work note")
    check(note.vault_id == win.vault_filter, "item created in the selected vault")
    win.vault_filter = None
    win.refresh()

    # 8. Clipboard: copy marks content local, clear empties it.
    win.copy("secret-value", "Password")
    check(win.clipboard.holds_our_copy(), "copy put our content on the clipboard")
    formats = win.clipboard.clipboard.get_formats()
    check(formats.contain_mime_type("x-kde-passwordManagerHint"), "clipboard marked as secret for managers")
    win.clipboard.clear()
    check(win.clipboard.clipboard.get_content() is None, "clipboard cleared")
    win.copy("user-visible", "Password")
    win.clipboard.clipboard.set_content(Gdk.ContentProvider.new_for_value(GObject.Value(str, "user copy")))
    win.clipboard.clear()
    check(win.clipboard.clipboard.get_content() is not None, "clear never wipes something copied afterwards")

    # 9. Lock / unlock.
    win.copy("another-secret", "Password")
    win.lock()
    check(win.session.locked and win.stack.get_visible_child_name() == "unlock", "locked")
    check(win.clipboard.clipboard.get_content() is None, "locking clears our clipboard content")
    check(list(win.itemlist._rows()) == [] and win.detail.item is None, "no item data left in widgets")
    win.unlock_page.entry.set_text("wrong password")
    win.unlock_page.unlock()
    check(wait(lambda: win.unlock_page.error.get_visible()), "wrong password shows an error")
    win.unlock_page.entry.set_text(MASTER)
    win.unlock_page.unlock()
    check(wait(lambda: win.stack.get_visible_child_name() == "main"), "unlocked again")

    # 10. Auto-lock after inactivity.
    win.data.settings["auto_lock_minutes"] = 1
    win.last_activity = time.monotonic() - 120
    win._check_idle()
    check(win.session.locked, "auto-lock after idle")
    win.unlock_page.entry.set_text(MASTER)
    win.unlock_page.unlock()
    check(wait(lambda: win.stack.get_visible_child_name() == "main"), "unlocked after auto-lock")

    # 11. Encrypted export and CSV export.
    backup = TMP / "backup.keyhold"
    win.session.export_encrypted(backup)
    check(VaultStore(backup, cost=FAST).unlock(MASTER, take_lock=False).data.get(item.id) is not None,
          "encrypted backup opens")
    csv_path = TMP / "export.csv"
    win._write_csv(csv_path)
    check(stat.S_IMODE(os.stat(csv_path).st_mode) == 0o600, "CSV export is 0600")
    check("second-Password-456!" in csv_path.read_text(), "CSV contains the password")

    # 12. Import (re-import the CSV), then delete the plaintext file.
    before = len(disk().items)
    win._confirm_import(csv_path)
    check(wait(lambda: bool(win.dialogs)), "import confirmation shown")
    respond(win, "import")
    check(len(disk().items) > before, "import added items")
    respond(win, "delete")
    check(not csv_path.exists(), "export file deleted after import")

    # 13. Online checks with a fake network.
    sha = hashlib.sha1(b"second-Password-456!").hexdigest().upper()

    def fake_get(url, headers=None):
        if "pwnedpasswords" in url:
            return f"{sha[5:]}:3\r\n".encode() if url.endswith(sha[:5]) else b""
        if "haveibeenpwned" in url:
            return b'[{"Name":"Example","Domain":"example.com","BreachDate":"2099-01-01"}]'
        return b'[["Bank", {"domain": "bank.example.com", "tfa": ["totp"]}]]'

    watchtower_online.http_get = fake_get  # no real network in the smoke test
    win.data.settings["online_checks"] = True
    win.refresh_online_now()
    check(wait(lambda: bool(win.data.watchtower.get("updated"))), "online refresh finished")
    check(item.id in win.report["vulnerable"], "pwned password flagged as vulnerable")
    check(item.id in win.report["compromised"], "breach newer than password change flagged")
    check(disk().watchtower.get("pwned", {}).get(sha) == 3, "online results stored encrypted in the vault")

    # 14. Change master password through the dialog.
    win.show_preferences()
    pump()
    prefs = win.dialogs[-1]
    old_backups = list(store.backups())
    prefs._change_password()
    pump()
    cp = win.dialogs[-1]
    rows = rows_of(cp, Adw.PasswordEntryRow)
    rows[0].set_text(MASTER)
    rows[1].set_text(NEW_MASTER)
    rows[2].set_text(NEW_MASTER)
    pump()
    change_btn = next(b for b in rows_of(cp, Gtk.Button) if b.get_label() == "Change")
    check(change_btn.get_sensitive(), "change button enabled for a valid new password")
    change_btn.emit("clicked")

    def opens_with_new():
        try:
            disk(NEW_MASTER)
            return True
        except Exception:
            return False

    # (Broadway never runs dialog close animations, so check the outcome
    # rather than waiting for the dialog to disappear.)
    check(wait(opens_with_new), "password change applied")
    cp.force_close()
    pump()
    current_password[0] = NEW_MASTER
    check(disk(NEW_MASTER).get(item.id) is not None, "vault opens with the new master password")
    check(all(b.exists() for b in old_backups), "old-password backups kept until the new password is used")
    # Lock with Preferences and the password dialog open: their text is wiped
    # and they're closed. (Broadway can't finish close animations, so we check
    # the wipe and the close request rather than the unmapping.)
    win.show_preferences()
    pump()
    win.dialogs[-1]._change_password()
    pump()
    open_cp = win.dialogs[-1]
    cp_rows = rows_of(open_cp, Adw.PasswordEntryRow)
    cp_rows[0].set_text("typed secret")
    win.show_generator()
    pump()
    gen_preview = next(l for l in rows_of(win.dialogs[-1], Gtk.Label) if l.has_css_class("kh-mono-preview"))
    check(bool(gen_preview.get_text()), "generator shows a password")
    win.lock()
    check(all(r.get_text() == "" for r in cp_rows), "lock wipes password fields in open dialogs")
    check(gen_preview.get_text() == "", "lock wipes generated password preview")
    check(win.dialogs == [], "lock closes all dialogs")
    check(win.detail.view_scroller.get_child() is None and win.detail.edit_scroller.get_child() is None,
          "lock drops item widgets")
    win.unlock_page.entry.set_text(NEW_MASTER)
    win.unlock_page.unlock()
    check(wait(lambda: win.stack.get_visible_child_name() == "main"), "unlocked with new password")
    check(not any(b.exists() for b in old_backups), "old-password backups removed after unlocking with the new one")

    # 14b. Ctrl+E while creating an item must not wipe the editor.
    win.new_item("login")
    win.detail.editor.title_row.set_text("Keep me")
    win.activate_action("win.edit", None)
    check(win.detail.editor.title_row.get_text() == "Keep me", "edit shortcut ignored while editing")
    win.detail.save_edit()
    check(any(i.title == "Keep me" for i in disk().items), "item saved after the ignored shortcut")

    # 14c. A failed save keeps the editor open and the vault unchanged.
    import keyhold.store as store_mod

    real_replace = store_mod.os.replace

    def full_disk(*a, **k):
        raise OSError(28, "No space left on device")

    win.new_item("login")
    win.detail.editor.title_row.set_text("Retry me")
    store_mod.os.replace = full_disk
    try:
        win.detail.save_edit()
    finally:
        store_mod.os.replace = real_replace
    check(win.detail.editing and win.detail.editor.error.get_visible(), "failed save keeps the editor open")
    check(not any(i.title == "Retry me" for i in win.data.items), "failed new item rolled back in memory")
    win.detail.save_edit()
    check(any(i.title == "Retry me" for i in disk().items), "retry after failure saves")

    # 14d. Locking mid-edit keeps the draft (encrypted) and restores it.
    win.detail.start_edit()
    win.detail.editor.title_row.set_text("Draft title")
    win.lock()
    check(store.pending is not None, "draft sealed in memory on lock")
    win.unlock_page.entry.set_text(NEW_MASTER)
    win.unlock_page.unlock()
    check(wait(lambda: win.stack.get_visible_child_name() == "main"), "unlocked after draft lock")
    check(win.detail.editing and win.detail.editor.title_row.get_text() == "Draft title", "draft restored")
    win.detail.save_edit()
    check(any(i.title == "Draft title" for i in disk().items), "restored draft saves")

    # 14e. Unsaved (failed) changes survive a lock and are saved after unlock.
    target = next(i for i in win.data.items if i.title == "Draft title")
    store_mod.os.replace = full_disk
    try:
        win.set_favorite(target.id, not target.favorite)
        win.lock()  # its own retry also fails
    finally:
        store_mod.os.replace = real_replace
    want_fav = not disk().get(target.id).favorite
    win.unlock_page.entry.set_text(NEW_MASTER)
    win.unlock_page.unlock()
    check(wait(lambda: win.stack.get_visible_child_name() == "main"), "unlocked after failed save")
    check(disk().get(target.id).favorite == want_fav, "changes from before the lock were recovered and saved")

    # 14f. Damaged dates don't break the main view.
    bad = next(i for i in win.data.items if i.category == "login")
    bad.fields.append(model.Field.new("expiry date", "monthyear", "0000-12"))
    bad.modified = 1e300
    win.refresh()
    check(len(list(win.sidebar.listbox)) > 0 and len(list(win.itemlist._rows())) > 0,
          "sidebar and list still render with damaged dates")
    win.detail.show_item(bad)
    check(win.detail.item is bad, "damaged item still displays")
    bad.fields.pop()
    bad.modified = time.time()
    win.save()

    # 14g. Secret-copying shortcuts aren't exported as (D-Bus reachable) actions.
    check(win.lookup_action("copy-password") is None, "copy-password is not a window action")

    # 14h. Closing while editing asks first.
    win.new_item("secure_note")
    check(win._on_close_request() is True, "close with an open editor asks to confirm")
    respond(win, "cancel")
    check(win.get_visible() and win.detail.editing, "keep working leaves everything open")
    win.detail.cancel_edit()

    # 15. Save failure keeps working state and shows the banner.
    store_mod.os.replace = full_disk
    try:
        win.set_favorite(item.id, False)
    finally:
        store_mod.os.replace = real_replace
    check(win.save_banner.get_revealed(), "save failure shows banner")
    check(disk().get(item.id).favorite is True, "failed save left the file untouched")
    win.save()
    check(not win.save_banner.get_revealed() and disk().get(item.id).favorite is False, "retry saves")
    win.lock()


def on_activate(*_):
    def run():
        win = app.window
        try:
            scenario(win)
            print(f"SMOKE OK: {checks} checks passed")
        except Exception:
            traceback.print_exc()
            failures.append(1)
            print(f"SMOKE FAILED after {checks} checks")
        app.quit()
        return False

    GLib.timeout_add(500, run)


def headless_settings(*_):
    settings = Gtk.Settings.get_default()
    settings.set_property("gtk-xft-dpi", 96 * 1024)  # broadway reports -1
    settings.set_property("gtk-enable-animations", False)  # broadway draws frames rarely


app.connect("startup", headless_settings)
app.connect_after("activate", on_activate)
app.run([sys.argv[0]])
sys.exit(1 if failures else 0)
