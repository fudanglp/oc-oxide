#!/bin/sh
set -eu

if ! command -v dpkg-scanpackages >/dev/null 2>&1; then
  printf 'dpkg-scanpackages is required; install dpkg-dev\n' >&2
  exit 1
fi

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DIST_ROOT=${DIST_ROOT:-"$ROOT_DIR/dist"}
REPO_DIR=${REPO_DIR:-"$DIST_ROOT/apt"}
SUITE=${SUITE:-stable}
COMPONENT=${COMPONENT:-main}
ORIGIN=${ORIGIN:-oc-oxide}
LABEL=${LABEL:-oc-oxide}
ARCH=${DEB_ARCH:-}
SIGNING_KEY=${SIGNING_KEY:-}

deb=$(find "$DIST_ROOT" -maxdepth 1 -type f -name 'oc-oxide_*.deb' | sort | tail -n 1)
if [ -z "$deb" ]; then
  printf 'missing Debian package in %s\n' "$DIST_ROOT" >&2
  exit 1
fi

if [ -z "$ARCH" ]; then
  ARCH=$(dpkg-deb --field "$deb" Architecture)
fi

pool_dir="$REPO_DIR/pool/$COMPONENT/o/oc-oxide"
binary_dir="$REPO_DIR/dists/$SUITE/$COMPONENT/binary-$ARCH"
release_file="$REPO_DIR/dists/$SUITE/Release"

rm -rf "$REPO_DIR"
mkdir -p "$pool_dir" "$binary_dir"
cp "$deb" "$pool_dir/"

(
  cd "$REPO_DIR"
  dpkg-scanpackages --arch "$ARCH" "pool/$COMPONENT" /dev/null > "dists/$SUITE/$COMPONENT/binary-$ARCH/Packages"
)
gzip -9c "$binary_dir/Packages" > "$binary_dir/Packages.gz"

packages_rel="$COMPONENT/binary-$ARCH/Packages"
packages_gz_rel="$COMPONENT/binary-$ARCH/Packages.gz"
packages_file="$binary_dir/Packages"
packages_gz_file="$binary_dir/Packages.gz"

packages_md5=$(md5sum "$packages_file" | awk '{print $1}')
packages_gz_md5=$(md5sum "$packages_gz_file" | awk '{print $1}')
packages_sha256=$(sha256sum "$packages_file" | awk '{print $1}')
packages_gz_sha256=$(sha256sum "$packages_gz_file" | awk '{print $1}')
packages_size=$(wc -c < "$packages_file" | tr -d ' ')
packages_gz_size=$(wc -c < "$packages_gz_file" | tr -d ' ')

cat > "$release_file" <<EOF
Origin: $ORIGIN
Label: $LABEL
Suite: $SUITE
Codename: $SUITE
Architectures: $ARCH
Components: $COMPONENT
Date: $(date -Ru)
MD5Sum:
 $packages_md5 $packages_size $packages_rel
 $packages_gz_md5 $packages_gz_size $packages_gz_rel
SHA256:
 $packages_sha256 $packages_size $packages_rel
 $packages_gz_sha256 $packages_gz_size $packages_gz_rel
EOF

if [ -n "$SIGNING_KEY" ]; then
  if ! command -v gpg >/dev/null 2>&1; then
    printf 'gpg is required to sign apt repository metadata\n' >&2
    exit 1
  fi
  gpg --batch --yes --local-user "$SIGNING_KEY" --clearsign \
    --output "$REPO_DIR/dists/$SUITE/InRelease" "$release_file"
  gpg --batch --yes --local-user "$SIGNING_KEY" --armor --detach-sign \
    --output "$REPO_DIR/dists/$SUITE/Release.gpg" "$release_file"
fi

printf '%s\n' "$REPO_DIR"
