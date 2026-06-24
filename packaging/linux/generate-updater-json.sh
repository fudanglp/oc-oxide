#!/bin/sh
set -eu

if ! command -v python3 >/dev/null 2>&1; then
  printf 'python3 is required to generate latest.json\n' >&2
  exit 1
fi

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DIST_ROOT=${DIST_ROOT:-"$ROOT_DIR/dist"}
VERSION=${VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT_DIR/Cargo.toml" | head -n 1)}
ARCH=${ARCH:-$(uname -m)}
TARGET=${TAURI_UPDATE_TARGET:-}
ASSET_URL=${TAURI_UPDATE_URL:-}
SIGNATURE=${TAURI_UPDATE_SIGNATURE:-}
SIGNATURE_FILE=${TAURI_UPDATE_SIGNATURE_FILE:-}
NOTES=${TAURI_UPDATE_NOTES:-"oc-oxide $VERSION"}
OUT=${OUT:-"$DIST_ROOT/latest.json"}

case "$ARCH" in
  x86_64) default_target=linux-x86_64 ;;
  aarch64|arm64) default_target=linux-aarch64 ;;
  *) default_target="linux-$ARCH" ;;
esac

if [ -z "$TARGET" ]; then
  TARGET="$default_target"
fi

if [ -z "$ASSET_URL" ]; then
  printf 'TAURI_UPDATE_URL is required\n' >&2
  exit 1
fi

if [ -n "$SIGNATURE_FILE" ]; then
  if [ ! -f "$SIGNATURE_FILE" ]; then
    printf 'missing TAURI_UPDATE_SIGNATURE_FILE: %s\n' "$SIGNATURE_FILE" >&2
    exit 1
  fi
  SIGNATURE=$(tr -d '\n\r' < "$SIGNATURE_FILE")
fi

if [ -z "$SIGNATURE" ]; then
  printf 'TAURI_UPDATE_SIGNATURE or TAURI_UPDATE_SIGNATURE_FILE is required\n' >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"
VERSION="$VERSION" TARGET="$TARGET" ASSET_URL="$ASSET_URL" SIGNATURE="$SIGNATURE" NOTES="$NOTES" OUT="$OUT" \
python3 - <<'PY'
import datetime
import json
import os

payload = {
    "version": os.environ["VERSION"],
    "notes": os.environ["NOTES"],
    "pub_date": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "platforms": {
        os.environ["TARGET"]: {
            "signature": os.environ["SIGNATURE"],
            "url": os.environ["ASSET_URL"],
        }
    },
}

with open(os.environ["OUT"], "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2)
    handle.write("\n")
PY

printf '%s\n' "$OUT"
