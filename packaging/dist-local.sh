#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DESKTOP_DIR="$ROOT_DIR/apps/desktop"
DIST_ROOT=${DIST_ROOT:-"$ROOT_DIR/dist"}
VERSION=${VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT_DIR/Cargo.toml" | head -n 1)}
ARCH=${ARCH:-$(uname -m)}
DIST_NAME=${DIST_NAME:-"oc-oxide-${VERSION}-linux-${ARCH}"}
STAGE_DIR="$DIST_ROOT/$DIST_NAME"

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  (cd "$ROOT_DIR" && cargo build --release -p oc-oxide-daemon -p ocx)
  (cd "$DESKTOP_DIR" && npm run tauri -- build --no-bundle)
fi

rm -rf "$STAGE_DIR"
mkdir -p \
  "$STAGE_DIR/bin" \
  "$STAGE_DIR/lib" \
  "$STAGE_DIR/libexec/oc-oxide" \
  "$STAGE_DIR/share/applications" \
  "$STAGE_DIR/share/icons/hicolor/256x256/apps" \
  "$STAGE_DIR/share/polkit-1/actions" \
  "$STAGE_DIR/systemd"

copy_binary() {
  src=$1
  dest=$2
  if [ ! -x "$src" ]; then
    printf 'missing executable: %s\n' "$src" >&2
    exit 1
  fi
  cp "$src" "$dest"
  chmod 0755 "$dest"
}

copy_binary "$ROOT_DIR/target/release/oc-oxide-desktop" "$STAGE_DIR/libexec/oc-oxide/oc-oxide-desktop"
copy_binary "$ROOT_DIR/target/release/oc-oxide-daemon" "$STAGE_DIR/libexec/oc-oxide/oc-oxide-daemon"
copy_binary "$ROOT_DIR/target/release/ocx" "$STAGE_DIR/libexec/oc-oxide/ocx"
install -m 0755 "$ROOT_DIR/packaging/linux/oc-oxide-update.sh" \
  "$STAGE_DIR/libexec/oc-oxide/oc-oxide-update"

openconnect_lib=$(find "$ROOT_DIR/target/release/build" -path '*/openconnect-install/lib/libopenconnect.so*' -type f 2>/dev/null | sort | tail -n 1)
if [ -z "$openconnect_lib" ]; then
  printf 'missing vendored libopenconnect release build output\n' >&2
  exit 1
fi
openconnect_lib_dir=$(dirname "$openconnect_lib")
cp -P "$openconnect_lib_dir"/libopenconnect.so* "$STAGE_DIR/lib/"

make_wrapper() {
  name=$1
  target=$2
  cat > "$STAGE_DIR/bin/$name" <<EOF
#!/bin/sh
APP_DIR=\$(CDPATH= cd -- "\$(dirname -- "\$0")/.." && pwd)
export LD_LIBRARY_PATH="\$APP_DIR/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
exec "\$APP_DIR/libexec/oc-oxide/$target" "\$@"
EOF
  chmod 0755 "$STAGE_DIR/bin/$name"
}

make_wrapper oc-oxide oc-oxide-desktop
make_wrapper oc-oxide-daemon oc-oxide-daemon
make_wrapper ocx ocx

cp "$ROOT_DIR/packaging/systemd/oc-oxide-daemon.service" "$STAGE_DIR/systemd/"
cp "$ROOT_DIR/packaging/polkit/com.github.fudanglp.oc-oxide.policy" \
  "$STAGE_DIR/share/polkit-1/actions/"
cp "$ROOT_DIR/apps/desktop/src-tauri/icons/256x256.png" \
  "$STAGE_DIR/share/icons/hicolor/256x256/apps/oc-oxide.png"

cat > "$STAGE_DIR/share/applications/oc-oxide.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=oc-oxide
Comment=OpenConnect desktop helper
Exec=oc-oxide
Icon=oc-oxide
Terminal=false
Categories=Network;Security;
EOF

cat > "$STAGE_DIR/INSTALL.md" <<'EOF'
# oc-oxide local dist

This archive is a local Linux distribution layout for testing.

## Manual install

```sh
sudo ./install.sh
```

The installer copies:

- `bin/` wrappers to `/usr/local/bin`
- `libexec/oc-oxide/` binaries to `/usr/local/libexec/oc-oxide`
- `uninstall.sh` to `/usr/local/libexec/oc-oxide/uninstall.sh`
- `lib/libopenconnect.so*` to `/usr/local/lib`
- the desktop entry and icon to `/usr/local/share`
- the polkit action to `/usr/local/share/polkit-1/actions`
- the systemd unit to `/etc/systemd/system`
- an enabled, idle `oc-oxide-daemon.service`

The packaged daemon reads profiles from `/etc/oc-oxide/profiles`.

## Manual uninstall

```sh
sudo /usr/local/libexec/oc-oxide/uninstall.sh
```

You can also run `sudo ./uninstall.sh` from the extracted archive. The
uninstaller stops and disables `oc-oxide-daemon.service`, removes installed
program files, reloads systemd, and leaves user profiles, keyring entries, and
system profiles under `/etc/oc-oxide` in place.
EOF

cp "$ROOT_DIR/packaging/linux/install.sh" "$STAGE_DIR/install.sh" 2>/dev/null || true
if [ ! -f "$STAGE_DIR/install.sh" ]; then
  cat > "$STAGE_DIR/install.sh" <<'EOF'
#!/bin/sh
set -eu
PREFIX=${PREFIX:-/usr/local}
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

install -d "$PREFIX/bin" "$PREFIX/lib" "$PREFIX/libexec/oc-oxide" \
  "$PREFIX/share/applications" "$PREFIX/share/icons/hicolor/256x256/apps"
install -m 0755 "$ROOT_DIR/bin/oc-oxide" "$PREFIX/bin/oc-oxide"
install -m 0755 "$ROOT_DIR/bin/oc-oxide-daemon" "$PREFIX/bin/oc-oxide-daemon"
install -m 0755 "$ROOT_DIR/bin/ocx" "$PREFIX/bin/ocx"
install -m 0755 "$ROOT_DIR/libexec/oc-oxide/oc-oxide-desktop" "$PREFIX/libexec/oc-oxide/oc-oxide-desktop"
install -m 0755 "$ROOT_DIR/libexec/oc-oxide/oc-oxide-daemon" "$PREFIX/libexec/oc-oxide/oc-oxide-daemon"
install -m 0755 "$ROOT_DIR/libexec/oc-oxide/ocx" "$PREFIX/libexec/oc-oxide/ocx"
cp -P "$ROOT_DIR"/lib/libopenconnect.so* "$PREFIX/lib/"
install -m 0644 "$ROOT_DIR/share/applications/oc-oxide.desktop" "$PREFIX/share/applications/oc-oxide.desktop"
install -m 0644 "$ROOT_DIR/share/icons/hicolor/256x256/apps/oc-oxide.png" "$PREFIX/share/icons/hicolor/256x256/apps/oc-oxide.png"

if [ -d /etc/systemd/system ]; then
  install -m 0644 "$ROOT_DIR/systemd/oc-oxide-daemon.service" /etc/systemd/system/oc-oxide-daemon.service
  systemctl daemon-reload || true
fi
EOF
fi
chmod 0755 "$STAGE_DIR/install.sh"
cp "$ROOT_DIR/packaging/linux/uninstall.sh" "$STAGE_DIR/uninstall.sh"
chmod 0755 "$STAGE_DIR/uninstall.sh"
find "$STAGE_DIR" -type d -exec chmod 0755 {} \;

(cd "$STAGE_DIR" && find INSTALL.md install.sh uninstall.sh bin lib libexec share systemd -type f -exec sha256sum {} \; | sort > SHA256SUMS)

printf '%s\n' "$STAGE_DIR"
