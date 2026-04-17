#!/usr/bin/env bash
# Kerrigan Core build driver. Installs build tools, then defers everything
# else (boost, libsodium, gmp, sqlite, zmq, rust, cxxbridge, ...) to the
# depends/ system so builds are reproducible from pinned sources.
#
# Usage:
#   ./build.sh                  # headless daemon + cli
#   ./build.sh --clean          # wipe build tree and depends prefix first
#   ./build.sh --online-rust    # allow cargo to hit crates.io (not for release)
#   ./build.sh --jobs N         # cap parallel jobs (positive integer)
#
# Requires: sudo on first run to install build tools.

set -euo pipefail
export LC_ALL=C

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { printf '%b[INFO]%b %s\n'  "$GREEN"  "$NC" "$*"; }
warn()  { printf '%b[WARN]%b %s\n'  "$YELLOW" "$NC" "$*"; }
error() { printf '%b[ERROR]%b %s\n' "$RED"    "$NC" "$*" >&2; exit 1; }

# Validate that --jobs got a positive integer. Rejects 0, negatives, and
# non-numeric input (previously accepted silently, then make/depends failed
# many minutes into the build with a confusing message).
validate_jobs() {
    case "$1" in
        ''|*[!0-9]*) error "--jobs requires a positive integer (got: '$1')" ;;
    esac
    [ "$1" -gt 0 ] || error "--jobs must be greater than zero (got: '$1')"
}

CLEAN=0
ONLINE_RUST=0
JOBS=$(nproc 2>/dev/null || echo 2)

while [ $# -gt 0 ]; do
    case "$1" in
        --clean)        CLEAN=1 ;;
        --online-rust)  ONLINE_RUST=1 ;;
        --jobs)         shift; JOBS="${1:?--jobs requires N}"; validate_jobs "$JOBS" ;;
        --jobs=*)       JOBS="${1#*=}"; validate_jobs "$JOBS" ;;
        -h|--help)
            sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) error "Unknown option: $1 (use --help)" ;;
    esac
    shift
done

SRCDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SRCDIR"

[ -f configure.ac ] || error "Run from the Kerrigan source tree (configure.ac missing)"
[ -d depends ]      || error "depends/ directory missing"

# --- Pre-flight tool check ------------------------------------------------
# Fail fast if a required host tool is missing instead of discovering it
# 45 minutes into the depends/ build. install_tools() below covers the
# common distros; this guard catches custom setups and warn() distros.
preflight() {
    local missing=()
    for tool in make autoconf automake libtool pkg-config curl python3 gcc g++ patch; do
        command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        error "Missing required host tools: ${missing[*]}. Install them and re-run."
    fi
}

# --- Detect distro --------------------------------------------------------
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="${ID:-unknown}"
else
    error "Cannot detect distro (no /etc/os-release)"
fi
info "Distro: ${PRETTY_NAME:-$DISTRO}"

# --- Install build tools only (NO libraries) ------------------------------
# depends/ builds boost, libsodium, gmp, sqlite, zmq, miniupnpc, natpmp,
# berkeley-db, qt, rust, cxxbridge from pinned sources. We only need the
# toolchain and autotools on the host.
install_tools() {
    case "$DISTRO" in
        ubuntu|debian|linuxmint|pop)
            sudo apt-get update -qq
            sudo apt-get install -y \
                build-essential git cmake curl pkg-config \
                autoconf automake libtool libtool-bin bsdmainutils \
                python3 ca-certificates patch
            ;;
        fedora|rocky|almalinux|rhel|centos)
            sudo dnf install -y \
                gcc gcc-c++ make git cmake curl pkgconf-pkg-config \
                autoconf automake libtool \
                python3 ca-certificates which patch
            ;;
        arch|manjaro|endeavouros)
            sudo pacman -Sy --needed --noconfirm \
                base-devel git cmake curl pkgconf \
                autoconf automake libtool \
                python ca-certificates patch
            ;;
        *)
            warn "Unknown distro '$DISTRO'. Install manually: build-essential, git,"
            warn "cmake, curl, pkg-config, autoconf, automake, libtool, bsdmainutils, python3, patch."
            ;;
    esac
}

info "Installing build tools (libraries come from depends/)"
install_tools

info "Checking host toolchain"
preflight

# --- Vendor Rust crates on first run --------------------------------------
# depends/sources/vendored-crates-<version>.tar.gz is shipped in release
# tarballs but not in a fresh git clone. Regenerate it before depends/ runs
# so the offline build has something to unpack.
shopt -s nullglob
vendored=(depends/sources/vendored-crates-*.tar.gz)
shopt -u nullglob
if [ ${#vendored[@]} -eq 0 ]; then
    info "Vendoring Rust crates (first run only)"
    [ -x ./download-crates.sh ] || error "download-crates.sh missing or not executable"
    ./download-crates.sh
fi

# --- Clean -----------------------------------------------------------------
HOST="$(./depends/config.guess)"
PREFIX="$SRCDIR/depends/$HOST"

if [ "$CLEAN" -eq 1 ]; then
    info "Cleaning build tree and depends prefix"
    make clean 2>/dev/null || true
    make distclean 2>/dev/null || true
    rm -rf "$PREFIX" "$SRCDIR/depends/work" "$SRCDIR/depends/built"
fi

# --- autogen ---------------------------------------------------------------
if [ ! -f configure ] || [ configure.ac -nt configure ]; then
    info "Running autogen.sh"
    ./autogen.sh
fi

# --- depends (boost, libsodium, rust, cxxbridge, everything) ---------------
info "Building depends for $HOST (this includes Rust 1.81 toolchain, first run ~45min)"
make -C depends HOST="$HOST" -j"$JOBS"

[ -f "$PREFIX/share/config.site" ] || error "depends build did not produce config.site at $PREFIX"

# --- configure -------------------------------------------------------------
CONFIGURE_FLAGS=(--prefix="$PREFIX" --disable-tests --disable-bench)
if [ "$ONLINE_RUST" -eq 1 ]; then
    CONFIGURE_FLAGS+=(--enable-online-rust)
else
    CONFIGURE_FLAGS+=(--disable-online-rust)
fi

info "Configuring: ${CONFIGURE_FLAGS[*]}"
CONFIG_SITE="$PREFIX/share/config.site" ./configure "${CONFIGURE_FLAGS[@]}"

# --- build -----------------------------------------------------------------
info "Building Kerrigan Core with $JOBS jobs"
make -j"$JOBS"

# --- report ----------------------------------------------------------------
echo
info "Build complete. Binaries:"
for bin in src/kerrigand src/kerrigan-cli src/kerrigan-tx src/kerrigan-util src/kerrigan-wallet src/qt/kerrigan-qt; do
    [ -f "$bin" ] && printf '  %s\n' "$SRCDIR/$bin"
done
