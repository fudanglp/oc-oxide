#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
usage: oc-oxide-update install --manifest PATH

Installs a previously downloaded oc-oxide update artifact. Downloading and
primary verification are done by the desktop app; this wrapper performs final
root-side validation before installing.
EOF
}

die() {
  printf '%s\n' "$*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

json_string() {
  key=$1
  sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$MANIFEST" | head -n 1
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ "$(id -u)" != "0" ]; then
  die "oc-oxide-update must run as root"
fi

if [ "${1:-}" != "install" ]; then
  usage >&2
  exit 2
fi
shift

MANIFEST=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --manifest)
      MANIFEST=${2:-}
      [ -n "$MANIFEST" ] || die "missing value for --manifest"
      shift 2
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[ -n "$MANIFEST" ] || die "--manifest is required"
[ -f "$MANIFEST" ] || die "manifest is missing: $MANIFEST"

VERSION=$(json_string version)
METHOD=$(json_string method)
ARTIFACT=$(json_string artifact)
SHA256_FILE=$(json_string sha256)
EXPECTED_SHA256=$(json_string expectedSha256)

[ -n "$VERSION" ] || die "manifest is missing version"
[ -n "$METHOD" ] || die "manifest is missing method"
[ -n "$ARTIFACT" ] || die "manifest is missing artifact"
[ -n "$SHA256_FILE" ] || die "manifest is missing sha256"
[ -n "$EXPECTED_SHA256" ] || die "manifest is missing expectedSha256"

case "$VERSION" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) die "invalid update version: $VERSION" ;;
esac

case "$ARTIFACT" in
  /*) ;;
  *) die "artifact path must be absolute" ;;
esac

case "$SHA256_FILE" in
  /*) ;;
  *) die "sha256 path must be absolute" ;;
esac

[ -f "$ARTIFACT" ] || die "artifact is missing: $ARTIFACT"
[ -f "$SHA256_FILE" ] || die "sha256 file is missing: $SHA256_FILE"

case "$EXPECTED_SHA256" in
  *[!0123456789abcdefABCDEF]*)
    die "expectedSha256 must be hex"
    ;;
esac

if [ "${#EXPECTED_SHA256}" -ne 64 ]; then
  die "expectedSha256 must be 64 hex characters"
fi

ARCH=$(uname -m)
case "$ARCH" in
  x86_64)
    LINUX_ARCH=x86_64
    DEB_ARCH=amd64
    ;;
  aarch64|arm64)
    LINUX_ARCH=aarch64
    DEB_ARCH=arm64
    ;;
  *)
    die "unsupported architecture: $ARCH"
    ;;
esac

ARTIFACT_VERSION=${VERSION#v}
case "$METHOD" in
  deb)
    EXPECTED_NAME="oc-oxide_${ARTIFACT_VERSION}_${DEB_ARCH}.deb"
    ;;
  tarball)
    EXPECTED_NAME="oc-oxide-${ARTIFACT_VERSION}-linux-${LINUX_ARCH}.tar.gz"
    ;;
  *)
    die "invalid update method: $METHOD"
    ;;
esac

ARTIFACT_NAME=$(basename "$ARTIFACT")
SHA256_NAME=$(basename "$SHA256_FILE")
[ "$ARTIFACT_NAME" = "$EXPECTED_NAME" ] || die "unexpected artifact name: $ARTIFACT_NAME"
[ "$SHA256_NAME" = "$EXPECTED_NAME.sha256" ] || die "unexpected sha256 name: $SHA256_NAME"

FILE_SHA=$(awk 'NR == 1 { print $1 }' "$SHA256_FILE")
[ "$FILE_SHA" = "$EXPECTED_SHA256" ] || die "manifest checksum does not match sha256 file"

FILE_NAME=$(awk 'NR == 1 { print $2 }' "$SHA256_FILE" | sed 's/^\*//')
if [ -n "$FILE_NAME" ] && [ "$FILE_NAME" != "$EXPECTED_NAME" ]; then
  die "sha256 file describes $FILE_NAME, expected $EXPECTED_NAME"
fi

need sha256sum
ACTUAL_SHA=$(sha256sum "$ARTIFACT" | awk '{ print $1 }')
[ "$ACTUAL_SHA" = "$EXPECTED_SHA256" ] || die "artifact checksum mismatch"

case "$METHOD" in
  deb)
    need apt
    printf '%s\n' "status: installing-deb"
    apt install -y "$ARTIFACT"
    ;;
  tarball)
    need tar
    TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/oc-oxide-update.XXXXXX")
    cleanup() {
      rm -rf "$TMPDIR"
    }
    trap cleanup EXIT INT TERM
    printf '%s\n' "status: installing-tarball"
    tar -xzf "$ARTIFACT" -C "$TMPDIR"
    INSTALL_DIR="$TMPDIR/oc-oxide-${ARTIFACT_VERSION}-linux-${LINUX_ARCH}"
    [ -x "$INSTALL_DIR/install.sh" ] || die "tarball installer is missing"
    "$INSTALL_DIR/install.sh"
    ;;
esac

printf '%s\n' "status: done"
