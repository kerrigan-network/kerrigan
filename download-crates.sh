#!/usr/bin/env bash
#
# download-crates.sh - Produce a reproducible vendored-crates tarball for Kerrigan.
#
# Runs `cargo vendor` against the repo's pinned Cargo.toml/Cargo.lock, then packs
# the resulting `vendor/` tree into a byte-identical tarball suitable for
# consumption by the depends/ build system.
#
# Output:
#   depends/sources/vendored-crates-<KRGN_VERSION>.tar.gz
#
# Reproducibility is achieved by:
#   * fixing file ownership  (uid/gid 0, uname/gname root)
#   * fixing mtime           (SOURCE_DATE_EPOCH, defaults to 0 = 1970-01-01)
#   * sorting entries        (--sort=name, or an explicit sorted file list)
#   * clamping mtimes        (--clamp-mtime)
#   * forcing locale         (LC_ALL=C)
#   * gzip without timestamp (gzip -n)
#
# Usage:
#   ./download-crates.sh                 # vendors from ./Cargo.toml
#   KRGN_SRC=/path/to/kerrigan ./download-crates.sh
#   SOURCE_DATE_EPOCH=1700000000 ./download-crates.sh

set -euo pipefail

KRGN_VERSION="${KRGN_VERSION:-1.1.1}"
KRGN_SRC="${KRGN_SRC:-$(pwd)}"
OUT_DIR="${OUT_DIR:-${KRGN_SRC}/depends/sources}"
OUT_NAME="vendored-crates-${KRGN_VERSION}.tar.gz"
OUT_PATH="${OUT_DIR}/${OUT_NAME}"

# Pin timestamps for reproducibility. Override via env if desired.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
export LC_ALL=C
export TZ=UTC

# Sanity: we need a Cargo.toml and Cargo.lock at KRGN_SRC
if [[ ! -f "${KRGN_SRC}/Cargo.toml" ]]; then
    echo "error: ${KRGN_SRC}/Cargo.toml not found" >&2
    exit 1
fi
if [[ ! -f "${KRGN_SRC}/Cargo.lock" ]]; then
    echo "error: ${KRGN_SRC}/Cargo.lock not found (must be pre-generated and checked in)" >&2
    exit 1
fi

# Cargo must be on PATH
if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo not found on PATH. Install rust 1.81.0 via rustup." >&2
    exit 1
fi

mkdir -p "${OUT_DIR}"

# Work in a clean scratch directory so we never mutate the repo's own vendor/.
SCRATCH="$(mktemp -d -t krgn-vendor.XXXXXXXX)"
trap 'rm -rf "${SCRATCH}"' EXIT

echo "==> Vendoring crates from ${KRGN_SRC} into ${SCRATCH}/vendor"
cp "${KRGN_SRC}/Cargo.toml" "${SCRATCH}/Cargo.toml"
cp "${KRGN_SRC}/Cargo.lock" "${SCRATCH}/Cargo.lock"

# The [lib] path = src/rust/src/lib.rs must exist for cargo to accept the manifest.
# We create a minimal stub that satisfies parsing; cargo vendor does not compile it.
mkdir -p "${SCRATCH}/src/rust/src"
: > "${SCRATCH}/src/rust/src/lib.rs"

pushd "${SCRATCH}" >/dev/null
cargo vendor --locked --versioned-dirs vendor >/dev/null
popd >/dev/null

echo "==> Packing ${SCRATCH}/vendor into ${OUT_PATH}"

# Build a sorted, deterministic file list and feed it to tar with --no-recursion.
# This is the surest way to guarantee byte-identical archives across filesystems
# that may otherwise return directory entries in arbitrary order.
LIST="${SCRATCH}/filelist.txt"
( cd "${SCRATCH}" && find vendor -print0 | LC_ALL=C sort -z | tr '\0' '\n' > "${LIST}" )

# Normalize mtimes on the tree (belt-and-suspenders with --mtime below).
find "${SCRATCH}/vendor" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

tar \
    --create \
    --file - \
    --directory "${SCRATCH}" \
    --no-recursion \
    --owner=0 --group=0 --numeric-owner \
    --mtime="@${SOURCE_DATE_EPOCH}" \
    --clamp-mtime \
    --mode='go-w,a+rX' \
    --format=ustar \
    --files-from "${LIST}" \
    | gzip -n -9 > "${OUT_PATH}.tmp"

mv "${OUT_PATH}.tmp" "${OUT_PATH}"

echo "==> Wrote ${OUT_PATH}"
ls -l "${OUT_PATH}"
sha256sum "${OUT_PATH}"
