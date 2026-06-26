#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION_FILE=${VERSION_FILE:-"$ROOT_DIR/version.yml"}
CARGO=${CARGO:-cargo}
NPM=${NPM:-npm}

VERSION=$(
  sed -nE 's/^[[:space:]]*version:[[:space:]]*"?([0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?)"?[[:space:]]*$/\1/p' "$VERSION_FILE" |
    head -n 1
)

if [ -z "$VERSION" ]; then
  printf '%s\n' "sync-version: missing or invalid version in $VERSION_FILE" >&2
  exit 1
fi

case "$VERSION" in
  *[!0-9A-Za-z.+-]* | *..* | .* | *.)
    printf '%s\n' "sync-version: invalid version: $VERSION" >&2
    exit 1
    ;;
esac

export VERSION

perl -0pi -e 's/(\[workspace\.package\]\s*version = ")[^"]+(")/$1$ENV{VERSION}$2/s' \
  "$ROOT_DIR/Cargo.toml"

perl -0pi -e 's/("version"\s*:\s*")[^"]+(")/$1$ENV{VERSION}$2/' \
  "$ROOT_DIR/apps/desktop/src-tauri/tauri.conf.json"

(cd "$ROOT_DIR/apps/desktop" && "$NPM" version "$VERSION" --no-git-tag-version --allow-same-version)
(cd "$ROOT_DIR" && "$CARGO" update --workspace)

printf 'sync-version: %s\n' "$VERSION"
