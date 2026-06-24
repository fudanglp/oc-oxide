#!/bin/sh
set -eu

if ! command -v gpg >/dev/null 2>&1; then
  printf 'gpg is required to sign release artifacts\n' >&2
  exit 1
fi

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DIST_ROOT=${DIST_ROOT:-"$ROOT_DIR/dist"}
SIGNING_KEY=${SIGNING_KEY:-}

if [ "$#" -gt 0 ]; then
  artifacts="$*"
else
  artifacts=$(find "$DIST_ROOT" -maxdepth 1 -type f \( \
    -name 'oc-oxide-*.tar.gz' -o \
    -name 'oc-oxide-*.tar.gz.sha256' -o \
    -name 'oc-oxide-apt-repo.tar.gz' -o \
    -name 'oc-oxide-apt-repo.tar.gz.sha256' -o \
    -name 'oc-oxide_*.deb' -o \
    -name 'oc-oxide_*.deb.sha256' -o \
    -name 'install.sh' -o \
    -name 'install.sh.sha256' -o \
    -name 'latest.json' \
  \) | sort)
fi

if [ -z "$artifacts" ]; then
  printf 'no release artifacts found in %s\n' "$DIST_ROOT" >&2
  exit 1
fi

for artifact in $artifacts; do
  if [ ! -f "$artifact" ]; then
    printf 'missing artifact: %s\n' "$artifact" >&2
    exit 1
  fi

  rm -f "$artifact.asc"
  if [ -n "$SIGNING_KEY" ]; then
    gpg --batch --yes --local-user "$SIGNING_KEY" --armor --detach-sign "$artifact"
  else
    gpg --batch --yes --armor --detach-sign "$artifact"
  fi
  printf '%s.asc\n' "$artifact"
done
