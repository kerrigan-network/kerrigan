RELEASE BUILD NOTES
====================

How to build Kerrigan Core release binaries for Linux x86_64, Linux ARM64,
Windows x64, and macOS ARM64. Qt GUI is included on every platform.

Qt 5.15.18 is pulled automatically by the depends system.

Output files
---------------

```
kerrigan-1.0.4-x86_64-linux-gnu.tar.gz
kerrigan-1.0.4-aarch64-linux-gnu.tar.gz
kerrigan-1.0.4-win64.zip
kerrigan-1.0.4-win64-setup.exe
kerrigan-1.0.4-arm64-apple-darwin.tar.gz      (GitHub Actions)
kerrigan-1.0.4-arm64-apple-darwin.dmg         (GitHub Actions)
```

Host prerequisites (Ubuntu 22.04+)
-----------------------------------

One-time setup on the build host:

```sh
apt update
apt install -y build-essential libtool autotools-dev automake pkg-config \
    bsdmainutils python3 curl git cmake \
    g++-aarch64-linux-gnu binutils-aarch64-linux-gnu \
    g++-mingw-w64-x86-64-posix mingw-w64-x86-64-dev \
    nsis zip docker.io
```

Rust toolchain (needed for Sapling zk-SNARK support):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
rustup target add x86_64-pc-windows-gnu aarch64-unknown-linux-gnu
cargo install cxxbridge-cmd --version 1.0.186
```

Verify:

```sh
rustc --version       # >= 1.81
cxxbridge --version   # 1.0.186
```

Note: Ubuntu 22.04 ships mingw GCC 10, which does not support C++20. Windows
builds must run inside a Docker Ubuntu 24.04 container (see Windows section).

Build depends
-------------

Each target takes roughly 45 minutes on 12 cores. Results are cached.

```sh
git clone https://github.com/kerrigan-network/kerrigan.git
cd kerrigan/depends

make HOST=x86_64-pc-linux-gnu -j$(nproc)
make HOST=aarch64-linux-gnu -j$(nproc)
make HOST=x86_64-w64-mingw32 -j$(nproc)

cd ..
```

Verify each target has `config.site` and Qt:

```sh
ls depends/x86_64-pc-linux-gnu/share/config.site
ls depends/x86_64-pc-linux-gnu/lib/libQt5Core*
ls depends/aarch64-linux-gnu/share/config.site
ls depends/aarch64-linux-gnu/lib/libQt5Core*
ls depends/x86_64-w64-mingw32/share/config.site
ls depends/x86_64-w64-mingw32/lib/libQt5Core*
```

If the Qt download fails, drop the archives into `depends/sources/` manually:

```
https://download.qt.io/archive/qt/5.15/5.15.18/submodules/qtbase-everywhere-opensource-src-5.15.18.tar.xz
https://download.qt.io/archive/qt/5.15/5.15.18/submodules/qttranslations-everywhere-opensource-src-5.15.18.tar.xz
https://download.qt.io/archive/qt/5.15/5.15.18/submodules/qttools-everywhere-opensource-src-5.15.18.tar.xz
```

If gmp fails, check that `depends/packages/gmp.mk` points at
`gmplib.org/download/gmp` (the GNU mirror is unreliable).

Linux x86_64
------------

```sh
VERSION="1.0.4"
RELEASE="$(pwd)/release"
mkdir -p $RELEASE

source ~/.cargo/env
make clean 2>/dev/null || true
./autogen.sh
./configure --prefix=$PWD/depends/x86_64-pc-linux-gnu \
    --disable-tests --disable-bench
make -j$(nproc)

test -f src/qt/kerrigan-qt || { echo "ERROR: kerrigan-qt not built"; exit 1; }

mkdir -p $RELEASE/kerrigan-$VERSION-x86_64-linux-gnu/bin
cp src/kerrigand src/kerrigan-cli src/kerrigan-tx src/kerrigan-wallet src/kerrigan-util \
   src/qt/kerrigan-qt \
   $RELEASE/kerrigan-$VERSION-x86_64-linux-gnu/bin/
strip --strip-unneeded $RELEASE/kerrigan-$VERSION-x86_64-linux-gnu/bin/*
cd $RELEASE
tar -czvf kerrigan-$VERSION-x86_64-linux-gnu.tar.gz kerrigan-$VERSION-x86_64-linux-gnu/
cd ..
```

Use `strip --strip-unneeded`, not plain `strip`. Plain strip destroys PIE
binaries and leaves you with 0-byte files.

Linux ARM64 (cross-compile)
---------------------------

```sh
source ~/.cargo/env
make clean 2>/dev/null || true
./autogen.sh
./configure --prefix=$PWD/depends/aarch64-linux-gnu \
    --disable-tests --disable-bench \
    --host=aarch64-linux-gnu
make -j$(nproc)

test -f src/qt/kerrigan-qt || { echo "ERROR: kerrigan-qt not built"; exit 1; }

mkdir -p $RELEASE/kerrigan-$VERSION-aarch64-linux-gnu/bin
cp src/kerrigand src/kerrigan-cli src/kerrigan-tx src/kerrigan-wallet src/kerrigan-util \
   src/qt/kerrigan-qt \
   $RELEASE/kerrigan-$VERSION-aarch64-linux-gnu/bin/
aarch64-linux-gnu-strip --strip-unneeded $RELEASE/kerrigan-$VERSION-aarch64-linux-gnu/bin/*
cd $RELEASE
tar -czvf kerrigan-$VERSION-aarch64-linux-gnu.tar.gz kerrigan-$VERSION-aarch64-linux-gnu/
cd ..
```

Windows x64 (Docker)
--------------------

Ubuntu 22.04 mingw is GCC 10 (no C++20). Use Docker Ubuntu 24.04 which ships
GCC 13+. The depends must already be compiled on the host (see "Build
depends"); Docker only compiles the project itself.

The volume mount path inside the container must match the host path, because
the depends system bakes absolute paths into its pkg-config `.pc` files.

```sh
SRC=$(pwd)
RELEASE=$(pwd)/release

docker run --rm \
  -v ${SRC}:${SRC} \
  -v ${RELEASE}:${RELEASE} \
  -e SRC=${SRC} \
  -e RELEASE=${RELEASE} \
  ubuntu:24.04 bash -c '
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y build-essential libtool autotools-dev automake pkg-config \
    g++-mingw-w64-x86-64-posix nsis zip curl python3 bsdmainutils cmake

curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source /root/.cargo/env
rustup target add x86_64-pc-windows-gnu
cargo install cxxbridge-cmd --version 1.0.186

cd ${SRC}
make clean 2>/dev/null || true
./autogen.sh
CONFIG_SITE=${SRC}/depends/x86_64-w64-mingw32/share/config.site ./configure \
    --prefix=/ \
    --disable-tests --disable-bench \
    --without-libs
make -j$(nproc)

for bin in kerrigand.exe kerrigan-cli.exe kerrigan-tx.exe kerrigan-wallet.exe kerrigan-util.exe; do
    test -f "src/${bin}" || { echo "ERROR: src/${bin} missing"; exit 1; }
done
test -f src/qt/kerrigan-qt.exe || { echo "ERROR: kerrigan-qt.exe missing"; exit 1; }

VERSION="1.0.4"
RELEASE_DIR="kerrigan-${VERSION}-win64"
rm -rf ${RELEASE}/${RELEASE_DIR}
mkdir -p ${RELEASE}/${RELEASE_DIR}
cp src/kerrigand.exe src/kerrigan-cli.exe src/kerrigan-tx.exe \
   src/kerrigan-wallet.exe src/kerrigan-util.exe \
   src/qt/kerrigan-qt.exe \
   ${RELEASE}/${RELEASE_DIR}/
x86_64-w64-mingw32-strip ${RELEASE}/${RELEASE_DIR}/*.exe

cd ${RELEASE}
zip -r ${RELEASE_DIR}.zip ${RELEASE_DIR}/

cp ${SRC}/share/pixmaps/kerrigan.ico ${RELEASE}/kerrigan.ico

cat > ${RELEASE}/kerrigan-setup.nsi << NSIS_EOF
!include "MUI2.nsh"

Name "Kerrigan Core"
OutFile "kerrigan-${VERSION}-win64-setup.exe"
InstallDir "\$PROGRAMFILES64\\Kerrigan"
RequestExecutionLevel admin

!define MUI_ICON "kerrigan.ico"
!define MUI_UNICON "kerrigan.ico"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "Install"
    SetOutPath "\$INSTDIR"
    File "${RELEASE_DIR}\\kerrigand.exe"
    File "${RELEASE_DIR}\\kerrigan-cli.exe"
    File "${RELEASE_DIR}\\kerrigan-qt.exe"
    File "${RELEASE_DIR}\\kerrigan-tx.exe"
    File "${RELEASE_DIR}\\kerrigan-wallet.exe"
    File "${RELEASE_DIR}\\kerrigan-util.exe"
    File "kerrigan.ico"

    WriteUninstaller "\$INSTDIR\\uninstall.exe"

    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Kerrigan" "DisplayName" "Kerrigan Core"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Kerrigan" "UninstallString" "\$INSTDIR\\uninstall.exe"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Kerrigan" "DisplayIcon" "\$INSTDIR\\kerrigan.ico"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Kerrigan" "DisplayVersion" "${VERSION}"

    CreateDirectory "\$SMPROGRAMS\\Kerrigan"
    CreateShortcut "\$SMPROGRAMS\\Kerrigan\\Kerrigan Core.lnk" "\$INSTDIR\\kerrigan-qt.exe" "" "\$INSTDIR\\kerrigan.ico"
    CreateShortcut "\$SMPROGRAMS\\Kerrigan\\Uninstall.lnk" "\$INSTDIR\\uninstall.exe"
    CreateShortcut "\$DESKTOP\\Kerrigan Core.lnk" "\$INSTDIR\\kerrigan-qt.exe" "" "\$INSTDIR\\kerrigan.ico"
SectionEnd

Section "Uninstall"
    Delete "\$INSTDIR\\*.exe"
    Delete "\$INSTDIR\\kerrigan.ico"
    Delete "\$SMPROGRAMS\\Kerrigan\\*.lnk"
    RMDir "\$SMPROGRAMS\\Kerrigan"
    Delete "\$DESKTOP\\Kerrigan Core.lnk"
    DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Kerrigan"
    RMDir "\$INSTDIR"
SectionEnd
NSIS_EOF

makensis kerrigan-setup.nsi

ls -lh ${RELEASE}/${RELEASE_DIR}.zip ${RELEASE}/kerrigan-${VERSION}-win64-setup.exe
'
```

macOS ARM64 (GitHub Actions)
----------------------------

Workflow file: `.github/workflows/build.yml`. Produces a tar.gz (binaries) and
a DMG (Qt app bundle).

Configure flags used by the workflow:

```
--without-libs            # skip libkerriganconsensus (progpow linker issue)
--disable-tests --disable-bench
ARFLAGS="cr"              # Xcode 16+ compatibility
```

Build flag:

```
RANLIB="ranlib -no_warning_for_no_symbols"    # Xcode 16+ compatibility
```

Triggers:

- Push a tag matching `v*` (e.g. `git tag v1.0.4 && git push --tags`)
- Or manually: Actions > "Build Kerrigan macOS" > Run workflow > main

Artifacts appear in the run summary once the job finishes (roughly 20 minutes
with warm caches). SHA256 checksums are printed in the build logs.

Verify
------

```sh
cd release
ls -lh *.tar.gz *.zip *.exe
sha256sum *.tar.gz *.zip *.exe

tar tzf kerrigan-1.0.4-x86_64-linux-gnu.tar.gz | grep qt
tar tzf kerrigan-1.0.4-aarch64-linux-gnu.tar.gz | grep qt
unzip -l kerrigan-1.0.4-win64.zip | grep qt
```

Smoke test
----------

Run on a separate datadir so nothing conflicts with a live node:

```sh
mkdir -p /tmp/kerrigan-test
src/kerrigand -datadir=/tmp/kerrigan-test -port=17120 -rpcport=17121 \
    -printtoconsole 2>&1 | head -100

src/kerrigan-cli -datadir=/tmp/kerrigan-test -rpcport=17121 getblockchaininfo
```

Gotchas
-------

- `strip --strip-unneeded` on Linux. Plain `strip` ruins PIE binaries.
- Windows builds need Docker Ubuntu 24.04 (C++20). Host depends still compile
  fine on 22.04.
- Windows and macOS need `--without-libs` to skip libkerriganconsensus.
  Linux builds don't need it and the flag has no effect on the final binaries.
- macOS on Xcode 16+ needs `ARFLAGS="cr"` and `RANLIB="ranlib -no_warning_for_no_symbols"`,
  otherwise relic objects with no symbols trigger fatal warnings.
- `depends/packages/gmp.mk` must use `gmplib.org/download/gmp`. The GNU mirror
  drops connections.
- Version lives in `configure.ac` (`CLIENT_VERSION_MAJOR/MINOR/BUILD`). After
  bumping it, re-run `./autogen.sh && ./configure`.
- Rust + cxxbridge must be in PATH before `./configure`. Run
  `source ~/.cargo/env` in every fresh shell.
- The Windows depends must be built on the host before launching Docker.
  Docker just compiles the project. Verify with
  `ls depends/x86_64-w64-mingw32/share/config.site`.
- Docker volume mounts must use the same path inside and outside the
  container. `-v /path:/path`, not `-v /path:/src`. The depends `.pc` files
  have absolute paths baked in and pkg-config will fail otherwise.
- Qt is built by the depends by default. If it's missing, make sure you
  didn't build with `NO_QT=1`.

Credits
-------

Release build pipeline contributed by biigbang0001.
