#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DIST_ROOT=${DIST_ROOT:-"$ROOT_DIR/dist"}
VERSION=${VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT_DIR/Cargo.toml" | head -n 1)}
ARCH=${ARCH:-$(uname -m)}
DIST_NAME=${DIST_NAME:-"oc-oxide-${VERSION}-linux-${ARCH}"}
TARBALL="$DIST_ROOT/${DIST_NAME}.tar.gz"

"$ROOT_DIR/packaging/dist-local.sh"

if [ ! -d "$DIST_ROOT/$DIST_NAME" ]; then
  printf 'missing dist directory: %s\n' "$DIST_ROOT/$DIST_NAME" >&2
  exit 1
fi

rm -f "$TARBALL" "$TARBALL.sha256"
tar -C "$DIST_ROOT" -czf "$TARBALL" "$DIST_NAME"
(cd "$DIST_ROOT" && sha256sum "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256")

printf '%s\n' "$TARBALL"
