#!/usr/bin/env bash
#
# vendor-hash.sh - Compute SHA256 of the vendored-crates tarball.
#
# The output is the hex digest suitable for pasting into
# depends/packages/vendored_crates.mk as `$(package)_sha256_hash`.
#
# Usage:
#   ./vendor-hash.sh                                  # defaults to 1.1.1 tarball
#   ./vendor-hash.sh depends/sources/other.tar.gz     # explicit path
#   KRGN_VERSION=1.2.0 ./vendor-hash.sh

set -euo pipefail

KRGN_VERSION="${KRGN_VERSION:-1.1.1}"
KRGN_SRC="${KRGN_SRC:-$(pwd)}"
DEFAULT_PATH="${KRGN_SRC}/depends/sources/vendored-crates-${KRGN_VERSION}.tar.gz"

TARBALL="${1:-${DEFAULT_PATH}}"

if [[ ! -f "${TARBALL}" ]]; then
    echo "error: tarball not found: ${TARBALL}" >&2
    echo "hint:  run ./download-crates.sh first" >&2
    exit 1
fi

if ! command -v sha256sum >/dev/null 2>&1; then
    # macOS fallback
    if command -v shasum >/dev/null 2>&1; then
        HASH="$(shasum -a 256 "${TARBALL}" | awk '{print $1}')"
    else
        echo "error: neither sha256sum nor shasum available" >&2
        exit 1
    fi
else
    HASH="$(sha256sum "${TARBALL}" | awk '{print $1}')"
fi

# Human-readable summary on stderr, bare hash on stdout for pipeline use.
{
    echo "tarball: ${TARBALL}"
    SIZE="$(stat -c '%s' "${TARBALL}" 2>/dev/null || stat -f '%z' "${TARBALL}")"
    echo "size:    ${SIZE} bytes"
    echo "sha256:  ${HASH}"
    echo
    echo "Paste into depends/packages/vendored_crates.mk:"
    echo "    \$(package)_sha256_hash=${HASH}"
} >&2

echo "${HASH}"
