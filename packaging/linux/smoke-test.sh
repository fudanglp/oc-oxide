#!/bin/sh
# Run as root in a disposable Ubuntu build/test environment. Never connects VPN.
set -eu
package=$(realpath "${1:?usage: smoke-test.sh PACKAGE.deb}")
apt-get install -y "$package"
for binary in /usr/libexec/oc-oxide/oc-oxide-desktop /usr/libexec/oc-oxide/oc-oxide-daemon /usr/libexec/oc-oxide/ocx /usr/lib/libopenconnect.so; do
  result=$(LD_LIBRARY_PATH=/usr/lib ldd "$binary")
  if printf '%s\n' "$result" | grep -q 'not found'; then
    printf '%s\n' "$result" >&2
    exit 1
  fi
done
/usr/bin/ocx help >/dev/null
socket_dir=$(mktemp -d)
OC_OXIDE_DAEMON_SOCKET="$socket_dir/daemon.sock" /usr/bin/oc-oxide-daemon serve > "$socket_dir/daemon.log" 2>&1 &
daemon_pid=$!
cleanup() {
  kill "$daemon_pid" 2>/dev/null || true
  wait "$daemon_pid" 2>/dev/null || true
  rm -rf "$socket_dir"
}
trap cleanup EXIT INT TERM
attempt=0
while [ ! -S "$socket_dir/daemon.sock" ]; do
  if ! kill -0 "$daemon_pid" 2>/dev/null || [ "$attempt" -ge 20 ]; then
    cat "$socket_dir/daemon.log" >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  sleep 0.5
done
printf 'Daemon started and created its socket.\n'
