#!/usr/bin/env bash
# Kerrigan Core release builder. Produces signed-ready tarballs/zips for
# linux-x64, linux-arm64, and windows-x64.
#
# Everything (boost, libsodium, rust, cxxbridge, qt, ...) comes from depends/.
# Host only needs cross-compilers and Docker (for the Windows build).
#
# Usage:
#   ./build-release.sh                          # all three targets
#   ./build-release.sh linux-x64                # one target
#   ./build-release.sh linux-x64 linux-arm64    # multiple
#   VERSION=1.1.1 ./build-release.sh            # override version
#
# Output: release/kerrigan-<version>-<host>.{tar.gz,zip}

set -euo pipefail
export LC_ALL=C

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { printf '%b[INFO]%b %s\n'  "$GREEN"  "$NC" "$*"; }
warn()  { printf '%b[WARN]%b %s\n'  "$YELLOW" "$NC" "$*"; }
error() { printf '%b[ERROR]%b %s\n' "$RED"    "$NC" "$*" >&2; exit 1; }

SRCDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SRCDIR"

[ -f configure.ac ] || error "Run from the Kerrigan source tree"

# Pull version from configure.ac unless overridden.
if [ -z "${VERSION:-}" ]; then
    MAJ=$(grep -oE 'CLIENT_VERSION_MAJOR, *[0-9]+' configure.ac | grep -oE '[0-9]+')
    MIN=$(grep -oE 'CLIENT_VERSION_MINOR, *[0-9]+' configure.ac | grep -oE '[0-9]+')
    BLD=$(grep -oE 'CLIENT_VERSION_BUILD, *[0-9]+' configure.ac | grep -oE '[0-9]+')
    VERSION="${MAJ}.${MIN}.${BLD}"
fi
[ -n "$VERSION" ] || error "Could not determine VERSION"

RELEASE="$SRCDIR/release"
mkdir -p "$RELEASE"

JOBS=$(nproc 2>/dev/null || echo 2)
TARGETS=("$@")
[ "${#TARGETS[@]}" -eq 0 ] && TARGETS=(linux-x64 linux-arm64 windows-x64)

info "Kerrigan Core $VERSION release build"
info "Targets: ${TARGETS[*]}"
info "Output:  $RELEASE"

# --- Host toolchain (cross compilers and docker) --------------------------
install_host_tools() {
    [ -f /etc/os-release ] || error "Cannot detect distro"
    local ID
    ID="$( . /etc/os-release; echo "$ID" )"
    case "${ID:-}" in
        ubuntu|debian|linuxmint|pop)
            sudo apt-get update -qq
            sudo apt-get install -y \
                build-essential git cmake curl pkg-config \
                autoconf automake libtool bsdmainutils python3 \
                g++-aarch64-linux-gnu binutils-aarch64-linux-gnu \
                docker.io zip
            ;;
        *)
            warn "Automatic host setup only handles Debian/Ubuntu. Install manually:"
            warn "  build-essential, g++-aarch64-linux-gnu, binutils-aarch64-linux-gnu,"
            warn "  docker, zip, autoconf, automake, libtool, cmake, pkg-config, python3."
            ;;
    esac
}

want_target() {
    local t="$1"
    for x in "${TARGETS[@]}"; do [ "$x" = "$t" ] && return 0; done
    return 1
}

need() { command -v "$1" >/dev/null || error "Missing tool: $1"; }

# --- depends build for a HOST triple --------------------------------------
build_depends() {
    local host="$1"
    info "depends/ build for $host"
    make -C depends HOST="$host" -j"$JOBS"
    [ -f "depends/$host/share/config.site" ] \
        || error "depends build did not produce $host/share/config.site"
}

# --- Linux build (native or aarch64 cross) --------------------------------
build_linux() {
    local host="$1" tag="$2" strip_cmd="$3" configure_host="$4"
    local prefix="$SRCDIR/depends/$host"
    local outdir="$RELEASE/kerrigan-$VERSION-$tag"

    build_depends "$host"

    info "configure + build for $tag"
    make clean 2>/dev/null || true
    ./autogen.sh

    # Strip build-tree paths from DWARF debug strings and Rust source refs so
    # binaries do not leak the operator's home directory. Remaps $SRCDIR -> /build
    # and cargo home -> /cargo in every compiled object.
    local remap="-ffile-prefix-map=$SRCDIR=/build -fmacro-prefix-map=$SRCDIR=/build -fdebug-prefix-map=$SRCDIR=/build"
    export CFLAGS="${CFLAGS:-} $remap"
    export CXXFLAGS="${CXXFLAGS:-} $remap"
    export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$SRCDIR=/build --remap-path-prefix=$HOME/.cargo=/cargo"

    CONFIG_SITE="$prefix/share/config.site" ./configure \
        --prefix="$prefix" \
        --disable-tests --disable-bench \
        --disable-online-rust \
        ${configure_host:+--host="$configure_host"}
    make -j"$JOBS"

    test -f src/kerrigand     || error "kerrigand missing for $tag"
    test -f src/qt/kerrigan-qt || error "kerrigan-qt missing for $tag"

    rm -rf "$outdir"
    mkdir -p "$outdir/bin"
    cp src/kerrigand src/kerrigan-cli src/kerrigan-tx \
       src/kerrigan-wallet src/kerrigan-util \
       src/qt/kerrigan-qt "$outdir/bin/"

    "$strip_cmd" --strip-unneeded "$outdir/bin/"*

    # Sanitize qt_prfxpath: Qt embeds the host_prefix path (built into binaries
    # at qmake time, not affected by --remap-path-prefix). Rewrite the source
    # directory portion to /build so binaries do not leak the operator home dir.
    python3 -c "
import os, sys
src = sys.argv[1].encode()
bindir = sys.argv[2]
new = b'/build'
pad = b'\\0' * (len(src) - len(new))
for name in os.listdir(bindir):
    p = os.path.join(bindir, name)
    with open(p, 'rb') as f: data = f.read()
    if src in data:
        with open(p, 'wb') as f: f.write(data.replace(src, new + pad))
" "$SRCDIR" "$outdir/bin"

    ( cd "$RELEASE" && tar -czf "kerrigan-$VERSION-$tag.tar.gz" "kerrigan-$VERSION-$tag/" )
    info "Produced $RELEASE/kerrigan-$VERSION-$tag.tar.gz"
}

# --- Windows build (Docker Ubuntu 24.04 for C++20 mingw) ------------------
build_windows() {
    need docker
    local host="x86_64-w64-mingw32"
    local tag="win64"

    build_depends "$host"

    info "Windows build inside ubuntu:24.04 container"
    local src="$SRCDIR" rel="$RELEASE" ver="$VERSION"

    docker run --rm --network host \
        -v "$src:$src" \
        -v "$rel:$rel" \
        -e SRC="$src" -e RELEASE="$rel" -e VERSION="$ver" -e JOBS="$JOBS" \
        ubuntu:24.04 bash -euxc '
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y build-essential git cmake curl pkg-config \
                autoconf automake libtool bsdmainutils python3 \
                g++-mingw-w64-x86-64-posix nsis zip
            cd "$SRC"
            make clean 2>/dev/null || true
            ./autogen.sh

            # Strip build-tree paths from DWARF debug strings and Rust source refs
            REMAP="-ffile-prefix-map=$SRC=/build -fmacro-prefix-map=$SRC=/build -fdebug-prefix-map=$SRC=/build"
            export CFLAGS="${CFLAGS:-} $REMAP"
            export CXXFLAGS="${CXXFLAGS:-} $REMAP"
            export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$SRC=/build --remap-path-prefix=$HOME/.cargo=/cargo"

            CONFIG_SITE="$SRC/depends/x86_64-w64-mingw32/share/config.site" ./configure \
                --prefix=/ \
                --disable-bench \
                --disable-online-rust \
                --without-libs
            make -j"$JOBS"

            # Strip in place first so install/copy steps inherit the strip.
            for b in src/kerrigand.exe src/kerrigan-cli.exe src/kerrigan-tx.exe \
                     src/kerrigan-wallet.exe src/kerrigan-util.exe \
                     src/qt/kerrigan-qt.exe; do
                test -f "$b" || { echo "missing $b"; exit 1; }
            done
            x86_64-w64-mingw32-strip src/kerrigand.exe src/kerrigan-cli.exe \
                src/kerrigan-tx.exe src/kerrigan-wallet.exe \
                src/kerrigan-util.exe src/qt/kerrigan-qt.exe

            # Sanitize qt_prfxpath: Qt embeds host_prefix at qmake time as a
            # string literal in kerrigan-qt.exe. Not reachable by
            # --remap-path-prefix / -ffile-prefix-map. Run on src/ in place
            # so BOTH the zip (cp from src/) and the NSIS installer
            # (make deploy install-strips src/ -> ./release/, then NSIS
            # bundles from there) get sanitized binaries.
            cat > /tmp/sanitize_qtprfx.py <<"PYEOF"
import os, sys
src_path = sys.argv[1].encode()
new = b"/build"
pad = b"\0" * (len(src_path) - len(new))
for f in sys.argv[2:]:
    with open(f, "rb") as fh: data = fh.read()
    if src_path in data:
        with open(f, "wb") as fh: fh.write(data.replace(src_path, new + pad))
        print("sanitized: " + f)
    else:
        print("clean (no match): " + f)
PYEOF
            python3 /tmp/sanitize_qtprfx.py "$SRC" \
                src/kerrigand.exe src/kerrigan-cli.exe src/kerrigan-tx.exe \
                src/kerrigan-wallet.exe src/kerrigan-util.exe \
                src/qt/kerrigan-qt.exe

            out="$RELEASE/kerrigan-$VERSION-win64"
            rm -rf "$out"
            mkdir -p "$out"
            for b in kerrigand.exe kerrigan-cli.exe kerrigan-tx.exe \
                     kerrigan-wallet.exe kerrigan-util.exe; do
                cp "src/$b" "$out/"
            done
            cp src/qt/kerrigan-qt.exe "$out/"

            cd "$RELEASE"
            zip -r "kerrigan-$VERSION-win64.zip" "kerrigan-$VERSION-win64/"

            cd "$SRC"
            make deploy
            test -f "kerrigan-$VERSION-win64-setup.exe" || { echo "missing installer"; exit 1; }
            mv "kerrigan-$VERSION-win64-setup.exe" "$RELEASE/"
        '
    info "Produced $RELEASE/kerrigan-$VERSION-win64.zip"
}

# --- Run -------------------------------------------------------------------
install_host_tools

if want_target linux-x64; then
    build_linux "x86_64-pc-linux-gnu" "x86_64-linux-gnu" "strip" ""
fi

if want_target linux-arm64; then
    need aarch64-linux-gnu-strip
    build_linux "aarch64-linux-gnu" "aarch64-linux-gnu" "aarch64-linux-gnu-strip" "aarch64-linux-gnu"
fi

if want_target windows-x64; then
    build_windows
fi

echo
info "Artifacts:"
( cd "$RELEASE" && ls -lh *.tar.gz *.zip 2>/dev/null || true )
( cd "$RELEASE" && sha256sum *.tar.gz *.zip 2>/dev/null || true )
