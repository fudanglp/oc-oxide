#!/bin/sh
set -eu

PREFIX=${PREFIX:-/usr/local}
SYSTEMD_DIR=${SYSTEMD_DIR:-/etc/systemd/system}
SKIP_SYSTEMD=${SKIP_SYSTEMD:-0}

if [ "$SKIP_SYSTEMD" != "1" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl stop oc-oxide-daemon.service || true
  systemctl disable oc-oxide-daemon.service || true
fi

rm -f "$PREFIX/bin/oc-oxide" \
  "$PREFIX/bin/oc-oxide-daemon" \
  "$PREFIX/bin/ocx" \
  "$PREFIX/share/applications/oc-oxide.desktop" \
  "$PREFIX/share/icons/hicolor/256x256/apps/oc-oxide.png" \
  "$PREFIX/share/polkit-1/actions/com.github.fudanglp.oc-oxide.policy"

rm -f "$PREFIX/libexec/oc-oxide/oc-oxide-desktop" \
  "$PREFIX/libexec/oc-oxide/oc-oxide-daemon" \
  "$PREFIX/libexec/oc-oxide/ocx" \
  "$PREFIX/libexec/oc-oxide/oc-oxide-update" \
  "$PREFIX/libexec/oc-oxide/uninstall.sh"

rm -f "$PREFIX/lib/libopenconnect.so" \
  "$PREFIX/lib/libopenconnect.so.5" \
  "$PREFIX/lib/libopenconnect.so.5.11.0"

rmdir "$PREFIX/libexec/oc-oxide" 2>/dev/null || true

if [ "$SKIP_SYSTEMD" != "1" ] && [ -f "$SYSTEMD_DIR/oc-oxide-daemon.service" ]; then
  rm -f "$SYSTEMD_DIR/oc-oxide-daemon.service"
fi

if [ "$SKIP_SYSTEMD" != "1" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  systemctl reset-failed oc-oxide-daemon.service || true
fi

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$PREFIX/share/applications" || true
fi

cat <<'EOF'
oc-oxide removed.

User profiles, keyring entries, and system profiles under /etc/oc-oxide are
left in place. Remove them manually only if you no longer need them.
EOF
