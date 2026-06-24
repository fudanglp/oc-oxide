#!/bin/sh
set -eu

REPO=${OC_OXIDE_REPO:-fudanglp/oc-oxide}
VERSION=${OC_OXIDE_VERSION:-}
METHOD=${OC_OXIDE_INSTALL_METHOD:-auto}
DRY_RUN=0

usage() {
  cat <<'EOF'
usage: install-release.sh [--version vX.Y.Z] [--method auto|deb|tarball] [--dry-run]

Downloads an oc-oxide release artifact from GitHub Releases, verifies its
.sha256 file, and installs it through the Debian package or tarball installer.

Environment:
  OC_OXIDE_VERSION         Release tag, for example v0.1.1
  OC_OXIDE_INSTALL_METHOD  auto, deb, or tarball
  OC_OXIDE_REPO            GitHub repo, default fudanglp/oc-oxide
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      VERSION=${2:-}
      if [ -z "$VERSION" ]; then
        printf 'missing value for --version\n' >&2
        exit 2
      fi
      shift 2
      ;;
    --method)
      METHOD=${2:-}
      if [ -z "$METHOD" ]; then
        printf 'missing value for --method\n' >&2
        exit 2
      fi
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$METHOD" in
  auto|deb|tarball) ;;
  *)
    printf 'invalid --method %s; expected auto, deb, or tarball\n' "$METHOD" >&2
    exit 2
    ;;
esac

if [ "$(uname -s)" != "Linux" ]; then
  printf 'oc-oxide release installer currently supports Linux only\n' >&2
  exit 1
fi

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s is required\n' "$1" >&2
    exit 1
  fi
}

fetch() {
  url=$1
  dest=${2:-}
  if command -v curl >/dev/null 2>&1; then
    if [ -n "$dest" ]; then
      curl -fL --proto '=https' --tlsv1.2 -o "$dest" "$url"
    else
      curl -fsSL --proto '=https' --tlsv1.2 "$url"
    fi
  elif command -v wget >/dev/null 2>&1; then
    if [ -n "$dest" ]; then
      wget -O "$dest" "$url"
    else
      wget -qO- "$url"
    fi
  else
    printf 'curl or wget is required\n' >&2
    exit 1
  fi
}

if [ -z "$VERSION" ]; then
  latest_json=$(fetch "https://api.github.com/repos/$REPO/releases/latest")
  VERSION=$(printf '%s\n' "$latest_json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
  if [ -z "$VERSION" ]; then
    printf 'could not resolve latest release tag for %s\n' "$REPO" >&2
    exit 1
  fi
fi

case "$VERSION" in
  v*)
    RELEASE_TAG=$VERSION
    ARTIFACT_VERSION=${VERSION#v}
    ;;
  *)
    RELEASE_TAG="v$VERSION"
    ARTIFACT_VERSION=$VERSION
    ;;
esac

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
    printf 'unsupported architecture: %s\n' "$ARCH" >&2
    exit 1
    ;;
esac

if [ "$METHOD" = "auto" ]; then
  if command -v apt >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
    METHOD=deb
  else
    METHOD=tarball
  fi
fi

BASE_URL="https://github.com/$REPO/releases/download/$RELEASE_TAG"
TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/oc-oxide-install.XXXXXX")
cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

if [ "$(id -u)" -eq 0 ]; then
  SUDO=
else
  need sudo
  SUDO=sudo
fi

download_checked() {
  name=$1
  url="$BASE_URL/$name"
  checksum_url="$url.sha256"

  printf 'Downloading %s\n' "$url"
  fetch "$url" "$TMPDIR/$name"
  printf 'Downloading %s\n' "$checksum_url"
  fetch "$checksum_url" "$TMPDIR/$name.sha256"

  (cd "$TMPDIR" && sha256sum -c "$name.sha256")
}

make_apt_readable() {
  artifact=$1
  # apt reads local .deb files through the _apt sandbox user when possible.
  # mktemp creates a private 0700 directory, so make only this transient
  # download directory and verified artifacts readable to avoid a noisy apt
  # fallback-to-root notice.
  chmod 0755 "$TMPDIR"
  chmod 0644 "$artifact" "$artifact.sha256"
}

run_or_print() {
  if [ "$DRY_RUN" = "1" ]; then
    printf '+'
    for arg in "$@"; do
      printf ' %s' "$arg"
    done
    printf '\n'
  else
    "$@"
  fi
}

case "$METHOD" in
  deb)
    need sha256sum
    name="oc-oxide_${ARTIFACT_VERSION}_${DEB_ARCH}.deb"
    download_checked "$name"
    if [ "$DRY_RUN" = "1" ]; then
      printf 'Would install Debian package: %s\n' "$TMPDIR/$name"
    else
      make_apt_readable "$TMPDIR/$name"
    fi
    run_or_print $SUDO apt install "$TMPDIR/$name"
    ;;
  tarball)
    need sha256sum
    need tar
    name="oc-oxide-${ARTIFACT_VERSION}-linux-${LINUX_ARCH}.tar.gz"
    download_checked "$name"
    if [ "$DRY_RUN" = "1" ]; then
      printf 'Would extract and run tarball installer from: %s\n' "$TMPDIR/$name"
      run_or_print $SUDO "$TMPDIR/oc-oxide-${ARTIFACT_VERSION}-linux-${LINUX_ARCH}/install.sh"
      exit 0
    fi
    run_or_print tar -xzf "$TMPDIR/$name" -C "$TMPDIR"
    install_dir="$TMPDIR/oc-oxide-${ARTIFACT_VERSION}-linux-${LINUX_ARCH}"
    if [ ! -x "$install_dir/install.sh" ]; then
      printf 'missing tarball installer: %s/install.sh\n' "$install_dir" >&2
      exit 1
    fi
    run_or_print $SUDO "$install_dir/install.sh"
    ;;
esac

cat <<EOF

oc-oxide $RELEASE_TAG installed.

Try:
  oc-oxide
  systemctl status oc-oxide-daemon.service --no-pager
EOF
