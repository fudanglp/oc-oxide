#!/bin/sh
# Sourced by the build scripts. Ubuntu 24.04 keeps the legacy asset names;
# Ubuntu 26.04 needs its own ABI-specific artifacts.
BUILD_OS=$( . /etc/os-release; printf '%s:%s' "${ID:-}" "${VERSION_ID:-}" )
PLATFORM_SUFFIX=
DEB_VERSION_SUFFIX=
case "$BUILD_OS" in
  ubuntu:24.04) ;;
  ubuntu:26.04)
    PLATFORM_SUFFIX=-ubuntu26.04
    DEB_VERSION_SUFFIX=+ubuntu26.04
    ;;
  ubuntu:*)
    printf 'Unsupported Ubuntu release: %s (expected 24.04 or 26.04)\n' "$BUILD_OS" >&2
    exit 1
    ;;
esac
