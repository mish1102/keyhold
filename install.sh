#!/bin/sh
# Install Keyhold for the current user. Your vault is NOT touched.
#
#   Linux: a `keyhold` command in ~/.local/bin, an app-menu entry and an icon.
#   macOS: ~/Applications/Keyhold.app and a `keyhold` command in ~/.local/bin.
#
# ./install.sh --uninstall removes those again (the vault stays where it is).
set -eu

DIR=$(cd "$(dirname "$0")" && pwd)
APP_ID=io.github.keyhold.Keyhold
BIN="$HOME/.local/bin/keyhold"
OS=$(uname -s)

if [ "$OS" = "Darwin" ]; then
    MAC_APP="$HOME/Applications/Keyhold.app"
    if [ "${1:-}" = "--uninstall" ]; then
        rm -f "$BIN"
        rm -rf "$MAC_APP"
        echo "Removed Keyhold.app and the keyhold command."
        echo "Your vault is still in $HOME/Library/Application Support/Keyhold"
        exit 0
    fi
    command -v brew >/dev/null 2>&1 || {
        echo "Keyhold on macOS needs Homebrew (https://brew.sh). Install it, then run:"
        echo "  brew install python gtk4 libadwaita pygobject3 adwaita-icon-theme librsvg"
        exit 1
    }
    # Use Homebrew's Python: it's the one Homebrew's PyGObject is built for.
    PY="$(brew --prefix)/bin/python3"
    GTK_HINT="brew install python gtk4 libadwaita pygobject3 adwaita-icon-theme librsvg"
else
    DESKTOP="$HOME/.local/share/applications/$APP_ID.desktop"
    ICON="$HOME/.local/share/icons/hicolor/scalable/apps/$APP_ID.svg"
    if [ "${1:-}" = "--uninstall" ]; then
        rm -f "$BIN" "$DESKTOP" "$ICON"
        echo "Removed the launcher, menu entry and icon."
        echo "Your vault is still in ${XDG_DATA_HOME:-$HOME/.local/share}/keyhold"
        exit 0
    fi
    PY=python3
    GTK_HINT="sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1"
fi

"$PY" -c 'import sys; assert sys.version_info >= (3, 12)' 2>/dev/null || {
    echo "Keyhold needs Python 3.12 or newer ($PY is older or missing)."
    exit 1
}
"$PY" -c 'import gi; gi.require_version("Gtk", "4.0"); gi.require_version("Adw", "1")' 2>/dev/null || {
    echo "Keyhold needs GTK 4 and libadwaita for Python:"
    echo "  $GTK_HINT"
    exit 1
}

if [ ! -x "$DIR/.venv/bin/python" ]; then
    "$PY" -m venv --system-site-packages "$DIR/.venv"
fi
"$DIR/.venv/bin/pip" install --quiet --ignore-installed "cryptography>=46,<47" "zxcvbn==4.5.0"

# Make the package importable from the venv without copying it.
SITE=$("$DIR/.venv/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
echo "$DIR" > "$SITE/keyhold-src.pth"

mkdir -p "$(dirname "$BIN")"
cat > "$BIN" <<EOF
#!/bin/sh
# -I (isolated): ignore the current directory, PYTHONPATH and ~/.local packages,
# so only Keyhold and its pinned venv libraries can load.
exec "$DIR/.venv/bin/python" -I -m keyhold "\$@"
EOF
chmod 755 "$BIN"

if [ "$OS" = "Darwin" ]; then
    rm -rf "$MAC_APP"
    mkdir -p "$MAC_APP/Contents/MacOS" "$MAC_APP/Contents/Resources"
    cat > "$MAC_APP/Contents/MacOS/Keyhold" <<EOF
#!/bin/sh
exec "$DIR/.venv/bin/python" -I -m keyhold "\$@"
EOF
    chmod 755 "$MAC_APP/Contents/MacOS/Keyhold"
    cat > "$MAC_APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Keyhold</string>
    <key>CFBundleDisplayName</key><string>Keyhold</string>
    <key>CFBundleIdentifier</key><string>$APP_ID</string>
    <key>CFBundleExecutable</key><string>Keyhold</string>
    <key>CFBundleIconFile</key><string>Keyhold</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>0.1.0</string>
    <key>LSMinimumSystemVersion</key><string>11.0</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF
    # App icon from the SVG (needs librsvg's rsvg-convert; iconutil ships with macOS).
    if command -v rsvg-convert >/dev/null 2>&1 && command -v iconutil >/dev/null 2>&1; then
        SET=$(mktemp -d)/Keyhold.iconset
        mkdir -p "$SET"
        for size in 16 32 128 256 512; do
            rsvg-convert -w $size -h $size "$DIR/data/icons/hicolor/scalable/apps/$APP_ID.svg" -o "$SET/icon_${size}x${size}.png"
            rsvg-convert -w $((size * 2)) -h $((size * 2)) "$DIR/data/icons/hicolor/scalable/apps/$APP_ID.svg" -o "$SET/icon_${size}x${size}@2x.png"
        done
        iconutil -c icns "$SET" -o "$MAC_APP/Contents/Resources/Keyhold.icns" || true
        rm -rf "$(dirname "$SET")"
    fi
    echo "Installed. Open Keyhold from Spotlight, Launchpad or ~/Applications,"
    echo "or run: $BIN"
    exit 0
fi

mkdir -p "$(dirname "$DESKTOP")" "$(dirname "$ICON")"
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
