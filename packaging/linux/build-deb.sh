#!/bin/sh
set -eu

if ! command -v dpkg-deb >/dev/null 2>&1; then
  printf 'dpkg-deb is required to build the Debian package\n' >&2
  exit 1
fi

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DIST_ROOT=${DIST_ROOT:-"$ROOT_DIR/dist"}
VERSION=${VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT_DIR/Cargo.toml" | head -n 1)}
ARCH=${ARCH:-$(uname -m)}
DIST_NAME=${DIST_NAME:-"oc-oxide-${VERSION}-linux-${ARCH}"}

case "$ARCH" in
  x86_64) DEB_ARCH=amd64 ;;
  aarch64|arm64) DEB_ARCH=arm64 ;;
  *) DEB_ARCH="$ARCH" ;;
esac

"$ROOT_DIR/packaging/dist-local.sh"

STAGE_DIR="$DIST_ROOT/$DIST_NAME"
DEB_WORK="$ROOT_DIR/target/package/deb"
DEB_ROOT="$DEB_WORK/oc-oxide_${VERSION}_${DEB_ARCH}"
DEB_OUT="$DIST_ROOT/oc-oxide_${VERSION}_${DEB_ARCH}.deb"

rm -rf "$DEB_ROOT"
mkdir -p \
  "$DEB_ROOT/DEBIAN" \
  "$DEB_ROOT/etc/oc-oxide/profiles" \
  "$DEB_ROOT/usr/bin" \
  "$DEB_ROOT/usr/lib" \
  "$DEB_ROOT/usr/libexec/oc-oxide" \
  "$DEB_ROOT/usr/share/applications" \
  "$DEB_ROOT/usr/share/doc/oc-oxide" \
  "$DEB_ROOT/usr/share/icons/hicolor/256x256/apps" \
  "$DEB_ROOT/usr/share/polkit-1/actions" \
  "$DEB_ROOT/usr/lib/systemd/system"

cp "$STAGE_DIR/bin/oc-oxide" "$DEB_ROOT/usr/bin/"
cp "$STAGE_DIR/bin/oc-oxide-daemon" "$DEB_ROOT/usr/bin/"
cp "$STAGE_DIR/bin/ocx" "$DEB_ROOT/usr/bin/"
cp "$STAGE_DIR/libexec/oc-oxide/"* "$DEB_ROOT/usr/libexec/oc-oxide/"
cp -P "$STAGE_DIR"/lib/libopenconnect.so* "$DEB_ROOT/usr/lib/"
cp "$STAGE_DIR/share/applications/oc-oxide.desktop" "$DEB_ROOT/usr/share/applications/"
cp "$STAGE_DIR/share/icons/hicolor/256x256/apps/oc-oxide.png" \
  "$DEB_ROOT/usr/share/icons/hicolor/256x256/apps/"
cp "$STAGE_DIR/share/polkit-1/actions/com.github.fudanglp.oc-oxide.policy" \
  "$DEB_ROOT/usr/share/polkit-1/actions/"
cp "$STAGE_DIR/INSTALL.md" "$DEB_ROOT/usr/share/doc/oc-oxide/INSTALL.md"
sed 's#/usr/local/bin#/usr/bin#g' "$STAGE_DIR/systemd/oc-oxide-daemon.service" \
  > "$DEB_ROOT/usr/lib/systemd/system/oc-oxide-daemon.service"

cat > "$DEB_ROOT/DEBIAN/control" <<EOF
Package: oc-oxide
Version: $VERSION
Section: net
Priority: optional
Architecture: $DEB_ARCH
Maintainer: oc-oxide contributors <noreply@example.invalid>
Depends: libc6, libssl3 | libssl1.1, libgtk-3-0, libwebkit2gtk-4.1-0 | libwebkit2gtk-4.0-37, libayatana-appindicator3-1, librsvg2-2, systemd
Description: OpenConnect desktop helper
 oc-oxide is a Rust/Tauri OpenConnect helper with a privileged daemon,
 desktop control surface, and GitHub private-repository profile sync.
EOF

cat > "$DEB_ROOT/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
case "${1:-}" in
  configure)
    chmod 0755 /etc/oc-oxide || true
    chmod 0750 /etc/oc-oxide/profiles || true
    if command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload || true
      systemctl enable oc-oxide-daemon.service || true
      systemctl restart oc-oxide-daemon.service || true
    fi
    if command -v update-desktop-database >/dev/null 2>&1; then
      update-desktop-database /usr/share/applications || true
    fi
    ;;
esac
exit 0
EOF

cat > "$DEB_ROOT/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
case "${1:-}" in
  remove|deconfigure)
    if command -v systemctl >/dev/null 2>&1; then
      systemctl stop oc-oxide-daemon.service || true
      systemctl disable oc-oxide-daemon.service || true
    fi
    ;;
esac
exit 0
EOF

cat > "$DEB_ROOT/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
case "${1:-}" in
  remove|purge|upgrade|failed-upgrade|abort-install|abort-upgrade|disappear)
    if command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload || true
      systemctl reset-failed oc-oxide-daemon.service || true
    fi
    if command -v update-desktop-database >/dev/null 2>&1; then
      update-desktop-database /usr/share/applications || true
    fi
    ;;
esac

case "${1:-}" in
  purge)
    rmdir /etc/oc-oxide/profiles 2>/dev/null || true
    rmdir /etc/oc-oxide 2>/dev/null || true
    ;;
esac
exit 0
EOF

chmod 0755 "$DEB_ROOT/DEBIAN/postinst" "$DEB_ROOT/DEBIAN/prerm" "$DEB_ROOT/DEBIAN/postrm"
find "$DEB_ROOT" -type d -exec chmod 0755 {} \;
chmod 0750 "$DEB_ROOT/etc/oc-oxide/profiles"
find "$DEB_ROOT/usr/bin" "$DEB_ROOT/usr/libexec/oc-oxide" -type f -exec chmod 0755 {} \;
find "$DEB_ROOT/usr/share" "$DEB_ROOT/usr/lib/systemd/system" -type f -exec chmod 0644 {} \;

rm -f "$DEB_OUT" "$DEB_OUT.sha256"
dpkg-deb --build --root-owner-group "$DEB_ROOT" "$DEB_OUT"
(cd "$DIST_ROOT" && sha256sum "$(basename "$DEB_OUT")" > "$(basename "$DEB_OUT").sha256")
rm -rf "$DEB_WORK"

printf '%s\n' "$DEB_OUT"
