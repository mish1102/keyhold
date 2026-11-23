#!/bin/sh
# Install Keyhold for the current user: a launcher in ~/.local/bin, a menu
# entry and an icon. Your vault is NOT touched. Run ./install.sh --uninstall
# to remove the launcher, menu entry and icon (the vault stays where it is).
set -eu

DIR=$(cd "$(dirname "$0")" && pwd)
APP_ID=io.github.keyhold.Keyhold
BIN="$HOME/.local/bin/keyhold"
DESKTOP="$HOME/.local/share/applications/$APP_ID.desktop"
ICON="$HOME/.local/share/icons/hicolor/scalable/apps/$APP_ID.svg"

if [ "${1:-}" = "--uninstall" ]; then
    rm -f "$BIN" "$DESKTOP" "$ICON"
    echo "Removed the launcher, menu entry and icon."
    echo "Your vault is still in ${XDG_DATA_HOME:-$HOME/.local/share}/keyhold"
    exit 0
fi

python3 -c 'import gi; gi.require_version("Gtk", "4.0"); gi.require_version("Adw", "1")' 2>/dev/null || {
    echo "Keyhold needs GTK 4 and libadwaita for Python:"
    echo "  sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1"
    exit 1
}

if [ ! -x "$DIR/.venv/bin/python" ]; then
    python3 -m venv --system-site-packages "$DIR/.venv"
fi
"$DIR/.venv/bin/pip" install --quiet --ignore-installed "cryptography>=46,<47" "zxcvbn==4.5.0"

# Make the package importable from the venv without copying it.
SITE=$("$DIR/.venv/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
echo "$DIR" > "$SITE/keyhold-src.pth"

mkdir -p "$(dirname "$BIN")" "$(dirname "$DESKTOP")" "$(dirname "$ICON")"
cat > "$BIN" <<EOF
#!/bin/sh
# -I (isolated): ignore the current directory, PYTHONPATH and ~/.local packages,
# so only Keyhold and its pinned venv libraries can load.
exec "$DIR/.venv/bin/python" -I -m keyhold "\$@"
EOF
chmod 755 "$BIN"

cp "$DIR/data/icons/hicolor/scalable/apps/$APP_ID.svg" "$ICON"
cat > "$DESKTOP" <<EOF
[Desktop Entry]
Type=Application
Name=Keyhold
GenericName=Password Manager
Comment=Keep your passwords in a local encrypted vault
Exec=$BIN
Icon=$APP_ID
Terminal=false
Categories=Utility;Security;GTK;
Keywords=password;vault;login;2fa;totp;
StartupNotify=true
EOF
update-desktop-database "$HOME/.local/share/applications" >/dev/null 2>&1 || true
gtk-update-icon-cache -q "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true

echo "Installed. Start Keyhold from your app menu or run: keyhold"
