#!/bin/sh
set -eu

PREFIX=${PREFIX:-/usr/local}
SYSTEMD_DIR=${SYSTEMD_DIR:-/etc/systemd/system}
SKIP_SYSTEMD=${SKIP_SYSTEMD:-0}
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DESKTOP_ID="com.github.fudanglp.oc-oxide"

install -d \
  "$PREFIX/bin" \
  "$PREFIX/lib" \
  "$PREFIX/libexec/oc-oxide" \
  "$PREFIX/share/applications" \
  "$PREFIX/share/icons/hicolor/32x32/apps" \
  "$PREFIX/share/icons/hicolor/128x128/apps" \
  "$PREFIX/share/icons/hicolor/256x256/apps" \
  "$PREFIX/share/icons/hicolor/512x512/apps" \
  "$PREFIX/share/polkit-1/actions"

install -m 0755 "$ROOT_DIR/bin/oc-oxide" "$PREFIX/bin/oc-oxide"
install -m 0755 "$ROOT_DIR/bin/oc-oxide-daemon" "$PREFIX/bin/oc-oxide-daemon"
install -m 0755 "$ROOT_DIR/bin/ocx" "$PREFIX/bin/ocx"
install -m 0755 "$ROOT_DIR/libexec/oc-oxide/oc-oxide-desktop" "$PREFIX/libexec/oc-oxide/oc-oxide-desktop"
install -m 0755 "$ROOT_DIR/libexec/oc-oxide/oc-oxide-daemon" "$PREFIX/libexec/oc-oxide/oc-oxide-daemon"
install -m 0755 "$ROOT_DIR/libexec/oc-oxide/ocx" "$PREFIX/libexec/oc-oxide/ocx"
install -m 0755 "$ROOT_DIR/libexec/oc-oxide/oc-oxide-update" "$PREFIX/libexec/oc-oxide/oc-oxide-update"
install -m 0755 "$ROOT_DIR/uninstall.sh" "$PREFIX/libexec/oc-oxide/uninstall.sh"
cp -P "$ROOT_DIR"/lib/libopenconnect.so* "$PREFIX/lib/"
install -m 0644 "$ROOT_DIR/share/applications/${DESKTOP_ID}.desktop" \
  "$PREFIX/share/applications/${DESKTOP_ID}.desktop"
for size in 32 128 256 512; do
  install -m 0644 "$ROOT_DIR/share/icons/hicolor/${size}x${size}/apps/${DESKTOP_ID}.png" \
    "$PREFIX/share/icons/hicolor/${size}x${size}/apps/${DESKTOP_ID}.png"
done
install -m 0644 "$ROOT_DIR/share/polkit-1/actions/com.github.fudanglp.oc-oxide.policy" \
  "$PREFIX/share/polkit-1/actions/com.github.fudanglp.oc-oxide.policy"

if [ "$SKIP_SYSTEMD" != "1" ] && [ -d "$SYSTEMD_DIR" ]; then
  install -d /etc/oc-oxide/profiles "$SYSTEMD_DIR"
  chmod 0755 /etc/oc-oxide
  chmod 0750 /etc/oc-oxide/profiles
  install -m 0644 "$ROOT_DIR/systemd/oc-oxide-daemon.service" "$SYSTEMD_DIR/oc-oxide-daemon.service"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable oc-oxide-daemon.service || true
    systemctl restart oc-oxide-daemon.service || true
  fi
fi

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$PREFIX/share/applications" || true
fi

if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -q -t -f "$PREFIX/share/icons/hicolor" || true
fi
