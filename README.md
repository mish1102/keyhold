# Keyhold

A password manager for Linux that keeps your vault on your own computer, encrypted.
It has a three-pane layout: vaults and Watchtower on the left, items in the middle, details on the right.
It is built with GTK 4 and libadwaita.

Keyhold has no account, no cloud and no sync. Nothing leaves your computer unless you
turn on Watchtower's online checks (see below).

## Install and run

```sh
./install.sh            # adds "Keyhold" to your app menu and a `keyhold` command
keyhold
```

`./install.sh --uninstall` removes the launcher, menu entry and icon. Your vault stays where it is.

To run without installing: `./install.sh` first sets up `.venv`; then `.venv/bin/python -I -m keyhold`.

It requires `python3-gi`, `gir1.2-gtk-4.0` and `gir1.2-adw-1` (already present on Ubuntu 24.04 with GNOME).

## Features

- **Item types:** logins, passwords, secure notes, credit cards, identities and bank accounts.
- **Organizing:** multiple vaults, favorites, tags and a Trash with restore.
- **Fields:** custom fields of any type, and multiple websites per login.
- **Password history:** every password change keeps the old value.
- **One-time codes:** live codes with a countdown. Paste the secret or an `otpauth://` link.
- **Password generator:** random, memorable words (EFF wordlist) or PIN. A strength rating is shown everywhere.
- **Watchtower** lists:
  - weak, reused and unsecured (`http://`) logins
  - cards that are expiring or have expired
  - with online checks on: compromised logins, vulnerable passwords and inactive 2FA
- **Import** from Chrome/Edge/Brave, Firefox, Safari, Bitwarden (CSV or unencrypted JSON),
  1Password (CSV or `.1pux`), KeePassXC, LastPass and generic CSV. After importing, Keyhold
  offers to delete the unencrypted export file.
- **Export** an encrypted backup, or plain CSV (asks for your master password first).

## Keyboard shortcuts

| Keys | Action |
| --- | --- |
| Ctrl+F | Search |
| Ctrl+N | New login (the + menu has the other types) |
| Ctrl+E / Ctrl+S | Edit / save the selected item |
| Ctrl+Shift+C / U / O | Copy password / username / one-time code |
| Ctrl+G | Password generator |
| Ctrl+L | Lock |
| Ctrl+, | Preferences |

## Where your data lives

| What | Where |
| --- | --- |
| Vault (encrypted) | `~/.local/share/keyhold/vault.keyhold` |
| Automatic backups (encrypted) | `~/.local/share/keyhold/backups/` (the 10 most recent, plus one per day for 30 days) |
| Theme and window size (not secret) | `~/.config/keyhold/config.json` |

The first save after each unlock copies the previous vault into `backups/`. A backup opens
with the master password that was in use when it was made.

When you change your master password:
- Keyhold first backs up the vault under the old password.
- Then it writes the new file and checks that it reads back correctly.
- The backups that still open with the old password are removed only after you've unlocked
  once with the new password. If you mistype the new password the same way twice, you can
  still get back in.

**Keep your own copy too:** use *Export → Encrypted Backup…* now and then, and store the
file off this computer (USB drive, another machine).

## Security design

- **Key derivation:** Argon2id (256 MiB, 3 iterations, 4 lanes) turns your master password
  into a key-encryption key. Unlocking takes about 1.5 s; that cost is what slows down
  anyone trying to guess your password from a stolen vault file.
- **Encryption:** a random 256-bit vault key, wrapped by that key, encrypts the whole vault with
  ChaCha20-Poly1305. Every save uses a fresh random nonce. The header (format, KDF settings)
  is authenticated, so tampering makes the file refuse to open instead of opening weakened.
- **Saving:** writes are atomic (temp file + fsync + rename). A crash or a full disk can't
  damage the existing vault; Keyhold shows a "not saved" banner with a retry button.
- **File access:** files are created `0600` in a `0700` folder. An exclusive lock stops two
  copies of Keyhold from writing the same vault.
- **Locking:**
  - Keyhold locks after inactivity (default 10 minutes, counting time asleep), when the
    screen locks, and before the computer sleeps.
  - Locking wipes and closes any open dialogs.
  - An edit you were in the middle of, or a change that couldn't be saved, is kept
    encrypted in memory and restored when you unlock.
  - Quitting with unsaved work asks first.
- **Clipboard:** copied secrets are cleared after 90 seconds, but only if the clipboard still
  holds what Keyhold put there. They are marked `x-kde-passwordManagerHint: secret`, so
  clipboard managers that honor the hint (Klipper, CopyQ, GPaste) don't keep them in their history.
- **Process hardening:**
  - Core dumps are disabled and the process is marked non-dumpable, which blocks same-user
    debuggers from reading its memory.
  - The launcher runs Python in isolated mode (`-I`), so nothing from the current folder,
    `PYTHONPATH` or `~/.local` can load into it.
  - Copy shortcuts aren't exposed as window actions, which other programs could trigger over D-Bus.
  - Imports are limited in size (64 MB, and 256 MB unpacked for `.1pux`).
- **Online checks (off by default):**
  - Only the first 5 characters of each password's SHA-1 hash are sent to Have I Been Pwned,
    which uses k-anonymity, with padded responses.
  - The breach list and the 2FA Directory list are downloaded whole, so nothing about your sites is sent.
  - Results are stored inside the encrypted vault.

### Limitations, honestly

- **No sync, no browser autofill, no mobile app.** You copy and paste, or use the shortcuts above.
- **Secrets in memory:** Python can't reliably wipe them, so decrypted values can stay in
  process memory until Keyhold exits. Lock or quit when you step away from an unlocked computer.
  The vault key itself is zeroed on lock.
- **Swap and disk encryption:** that memory can be written to swap. On a computer without
  full-disk encryption (or at least encrypted swap), someone who takes the disk could find
  passwords in the swap file, or in deleted export files, without needing your master password.
  Turn on full-disk encryption if you can.
- **No recovery:** if you forget your master password, your data can't be recovered. That's the
  point of the encryption.
- **Not audited:** this is new software that no outside security firm has reviewed. Keep an
  encrypted backup, and keep your old password manager until you trust this one.
- **CSV export:** values are written exactly as stored. Avoid opening it in a spreadsheet app, which may
  run cells starting with `=` as formulas. Delete it when you're done.

## Development

```sh
.venv/bin/python -m pytest                      # unit tests
gtk4-broadwayd :7 &                             # headless display for the UI checks
GDK_BACKEND=broadway BROADWAY_DISPLAY=:7 .venv/bin/python tools/smoke.py       # end-to-end UI test
GDK_BACKEND=broadway BROADWAY_DISPLAY=:7 .venv/bin/python tools/screenshot.py screenshots
```

Both tools use a throwaway vault in a temp folder and never touch your real one.

### Layout

- `keyhold/crypto.py`: key derivation, key wrapping, file format
- `keyhold/store.py`: atomic saves, backups, locking, password change
- `keyhold/model.py`: items, fields, categories, vaults, settings
- `keyhold/listing.py`: filtering, search, sorting, grouping
- `keyhold/totp.py`: one-time codes (RFC 6238)
- `keyhold/generator.py`: generator (plus `eff_large_wordlist.txt`)
- `keyhold/strength.py`: strength meter
- `keyhold/watchtower.py`, `keyhold/watchtower_online.py`: security checks
- `keyhold/importers.py`: import and CSV export
- `keyhold/ui/`: GTK interface

## Credits

Passphrase words come from the [EFF Large Wordlist](https://www.eff.org/dice) (CC BY 3.0 US).
Breach data comes from [Have I Been Pwned](https://haveibeenpwned.com), and 2FA support data from
[2FA Directory](https://2fa.directory). Both are used only when online checks are turned on.
