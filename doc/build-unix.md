UNIX BUILD NOTES
====================
Some notes on how to build Kerrigan Core on Unix.

(For BSD specific instructions, see `build-*bsd.md` in this directory.)

Kerrigan 1.1.1 uses the `depends/` system to build every runtime library from
pinned source. The host OS only needs build tools; no Boost, libsodium, gmp,
sqlite, zmq, miniupnpc, natpmp, libevent, Qt, or Berkeley DB -dev packages are
required. Rust 1.81.0 is staged by `depends/` automatically.

To Build
---------------------

```sh
make -C depends -j$(nproc)
./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site \
    ./configure --prefix=$PWD/depends/x86_64-pc-linux-gnu
make # use "-j N" for N parallel jobs
```

The `depends/` build takes roughly 45 minutes on 12 cores for a cold build.
Subsequent builds are cached in `depends/built/`.

Binaries live under `src/` after `make` completes. The `--prefix` above
points at the per-triple depends/ directory so `pkg-config` / `config.site`
stay self-consistent; `make install` is **not** intended for a system
install from this prefix. To install into a system location, re-configure
with a real prefix (e.g. `--prefix=/usr/local`) and then `sudo make install`.
Never pass `--prefix=/` -- it would place binaries into `/bin`, `/etc`, `/share`.

## Memory Requirements

C++ compilers are memory-hungry. It is recommended to have at least 1.5 GB of
memory available when compiling Kerrigan Core. On systems with less, gcc can be
tuned to conserve memory with additional CXXFLAGS:

```sh
./configure CXXFLAGS="--param ggc-min-expand=1 --param ggc-min-heapsize=32768"
```

## Linux Distribution Specific Instructions

### Ubuntu & Debian

Kerrigan 1.1.1 has no runtime library `-dev` requirements. Only build tools
are needed:

```sh
sudo apt-get install build-essential git cmake curl pkg-config \
    autoconf automake libtool libtool-bin bsdmainutils python3
```

GCC 11+ or Clang 16+ is required (C++20). Ubuntu 22.04 ships GCC 11, which is
sufficient. Ubuntu 20.04 ships GCC 9 -- add `ppa:ubuntu-toolchain-r/test` and
install `g++-12`. Debian 11 ships GCC 10 -- use backports for GCC 12. See
[build-pool-operator.md](build-pool-operator.md) for per-distro instructions.

Cross-compilation adds:

```sh
# Linux aarch64
sudo apt-get install g++-aarch64-linux-gnu binutils-aarch64-linux-gnu
# Windows x86_64
sudo apt-get install g++-mingw-w64-x86-64-posix mingw-w64-x86-64-dev nsis zip
```

### Fedora

```sh
sudo dnf install gcc-c++ libtool make autoconf automake cmake curl git \
    pkgconf python3
```

Fedora 40+ ships GCC 14, which is sufficient.

### Arch Linux

```sh
sudo pacman --sync --needed base-devel git cmake curl pkgconf autoconf \
    automake libtool python
```

## The `depends/` Flow

`depends/` builds every C/C++ library, the Rust toolchain, and the vendored
crate tarball into a per-triple prefix at `depends/<triple>/`. The main
Kerrigan build reads that prefix via `config.site`.

Supported host triples:

```
x86_64-pc-linux-gnu
aarch64-linux-gnu
x86_64-w64-mingw32
x86_64-apple-darwin
aarch64-apple-darwin
```

Build `depends/` for the target you want, then point `./configure` at the
resulting `config.site`:

```sh
# Native Linux x86_64
make -C depends -j$(nproc)
./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site \
    ./configure --prefix=$PWD/depends/x86_64-pc-linux-gnu
make -j$(nproc)

# Cross-compile to aarch64
make -C depends HOST=aarch64-linux-gnu -j$(nproc)
./autogen.sh
CONFIG_SITE=$PWD/depends/aarch64-linux-gnu/share/config.site \
    ./configure --prefix=$PWD/depends/aarch64-linux-gnu
make -j$(nproc)
```

`config.site` sets `RUSTC`, `CARGO`, `CXXBRIDGE`, `RUST_TARGET`, and
`RUST_VENDORED_SOURCES` so the Kerrigan build uses the staged toolchain, not
whatever happens to be on `PATH`.

See [build-reproducibility.md](build-reproducibility.md) for the design.

## Rust Toolchain

Rust 1.81.0 is pinned in `depends/packages/native_rust.mk` and staged into
`depends/<triple>/native/bin/` during `make -C depends`. The main build
prepends that directory to `PATH` via `config.site`.

Manual `rustup` install is no longer required for release builds. A
`rust-toolchain.toml` in the repo root pins 1.81.0 for standalone `cargo`
invocations (editor rust-analyzer, ad-hoc `cargo check`).

cxxbridge 1.0.186 is staged by `depends/packages/native_cxxbridge.mk` at the
same time and needs no manual `cargo install` step.

## Online vs Offline Rust Builds

`configure` accepts `--enable-online-rust` / `--disable-online-rust` with an
`auto` default.

- `auto` (default): if `RUST_VENDORED_SOURCES` is set by `config.site` (the
  `depends/` path), build offline. Otherwise (standalone dev tree without
  `depends/`), build online and pull crates from crates.io.
- `--enable-online-rust`: force online. `cargo build` contacts crates.io. Used
  when iterating on `Cargo.toml` without needing a reproducible build.
- `--disable-online-rust`: force offline. Requires `depends/` to have staged
  the vendored-crates tarball. Production reproducible path.

Offline mode stamps `.cargo/config.toml` with:

```
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "<staged vendor/>"
```

and runs `cargo build --locked --offline`. Zero network calls after
`depends/` completes.

## Rebuilding the Vendored Crates Tarball

The vendored crates tarball (`depends/sources/vendored-crates-1.1.1.tar.gz`)
is produced from `Cargo.toml` + `Cargo.lock` and checked into the release
sources. Rebuilding requires a network-enabled host with `cargo 1.81.0`:

```sh
./download-crates.sh           # writes depends/sources/vendored-crates-1.1.1.tar.gz
./vendor-hash.sh               # prints SHA256 for depends/packages/vendored_crates.mk
```

`download-crates.sh` runs `cargo vendor --locked --versioned-dirs` and packs
the result with fixed uid/gid, fixed mtime (`SOURCE_DATE_EPOCH=0`), sorted
file list, and `gzip -n`. Two back-to-back runs on the same host produce
byte-identical tarballs. Paste the `vendor-hash.sh` output into
`depends/packages/vendored_crates.mk` at `$(package)_sha256_hash=`.

After regenerating, commit `Cargo.lock`, `depends/sources/vendored-crates-1.1.1.tar.gz`,
and the hash bump to `vendored_crates.mk` in a single change so the build
stays self-consistent.

## GUI

The Qt 5.15.18 stack is built by `depends/` on all platforms. No distro Qt
packages are consulted. `./configure` picks up `kerrigan-qt` automatically.

To build headless:

```sh
./configure --without-gui
```

## Disable-wallet Mode

When running a P2P node only:

```sh
./configure --disable-wallet
```

Mining with `getblocktemplate` still works in this mode.

## Additional Configure Flags

```sh
./configure --help
```

## Arch Linux Command-Line Build

```sh
sudo pacman --sync --needed base-devel git cmake curl pkgconf autoconf \
    automake libtool python
git clone https://github.com/kerrigan-network/kerrigan.git
cd kerrigan
make -C depends -j$(nproc)
./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site \
    ./configure --prefix=$PWD/depends/x86_64-pc-linux-gnu --without-gui
make -j$(nproc)
./src/kerrigand --version
```

If you need legacy Berkeley DB wallet compatibility (BDB 4.8), build it
through `depends/`. The legacy wallet is enabled by default; pass
`--without-bdb` to skip it. See [build-pool-operator.md](build-pool-operator.md)
for a manual BDB 4.8 build recipe that bypasses depends.
