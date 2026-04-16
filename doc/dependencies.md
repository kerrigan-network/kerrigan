# Dependencies

Every dependency listed here is built from source via `depends/` with a
pinned version and SHA256. Release binaries have zero distro-package library
dependencies beyond glibc and the kernel.

"Runtime" is whether the library is linked dynamically into the release
binary. Everything in Kerrigan 1.1.1 release tarballs is statically linked
except glibc.

"Stability" is an operational call: how often this package is expected to
need a version bump.

- **stable**: pinned version is expected to survive multi-year cadence
  without a CVE or platform compatibility break.
- **cutting-edge**: expected to need version bumps on annual or faster
  cadence (security churn, LLVM cadence, Apple SDK churn).

## Host Build Tools

These live on the build host, not in `depends/`, and are not shipped.

| Dependency | Minimum required | Stability |
| --- | --- | --- |
| [Autoconf](https://www.gnu.org/software/autoconf/) | 2.69 | stable |
| [Automake](https://www.gnu.org/software/automake/) | 1.13 | stable |
| [Clang](https://clang.llvm.org) | 16.0 | cutting-edge |
| [GCC](https://gcc.gnu.org) | 11.1 | cutting-edge |
| [Python](https://www.python.org) (scripts, tests) | 3.10 | stable |
| [CMake](https://cmake.org) (Rust build scripts) | 3.16 | stable |
| [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/) | 0.29 | stable |

The Rust toolchain is staged by `depends/`, not from the host. See
`depends/packages/native_rust.mk`.

## Built via `depends/`

Every package below is built from pinned source in the `depends/` tree. The
main Kerrigan build consumes these via `depends/<triple>/share/config.site`.

### Rust Toolchain

| Dependency | Package file | Version | Stability |
| --- | --- | --- | --- |
| Rust compiler + rust-std | `depends/packages/native_rust.mk` | 1.81.0 | cutting-edge |
| cxxbridge (C++/Rust FFI) | `depends/packages/native_cxxbridge.mk` | 1.0.186 | cutting-edge |
| cxx.h header | `depends/packages/rustcxx.mk` | 1.0.186 | cutting-edge |
| Vendored crates tarball | `depends/packages/vendored_crates.mk` | 1.1.1 | cutting-edge |

Rust cadence means 1.81.0 will likely be bumped during each Kerrigan
release cycle. Update procedure is in
[build-reproducibility.md](build-reproducibility.md).

### Required C/C++ Libraries

| Dependency | Package file | Version | Stability | Runtime |
| --- | --- | --- | --- | --- |
| [Boost](../depends/packages/boost.mk) | `boost.mk` | 1.81.0 | stable | No |
| [libevent](../depends/packages/libevent.mk) | `libevent.mk` | 2.1.12-stable | stable | No |
| [libsodium](../depends/packages/libsodium.mk) | `libsodium.mk` | 1.0.20 | stable | No |
| [libbacktrace](../depends/packages/backtrace.mk) | `backtrace.mk` | commit `b9e4006` | stable | No |
| glibc (host) | N/A | 2.31+ | stable | Yes |

### Optional

| Dependency | Package file | Version | Stability | Runtime |
| --- | --- | --- | --- | --- |
| [libgmp](../depends/packages/gmp.mk) | `gmp.mk` | 6.3.0 | stable | No |

### GUI

| Dependency | Package file | Version | Stability | Runtime |
| --- | --- | --- | --- | --- |
| [Qt](../depends/packages/qt.mk) | `qt.mk` | 5.15.18 | cutting-edge | No |
| [Fontconfig](../depends/packages/fontconfig.mk) | `fontconfig.mk` | 2.12.6 | stable | Yes |
| [FreeType](../depends/packages/freetype.mk) | `freetype.mk` | 2.11.0 | stable | Yes |
| [expat](../depends/packages/expat.mk) | `expat.mk` | 2.4.8 | stable | No |
| [libxcb](../depends/packages/libxcb.mk) | `libxcb.mk` | 1.14 | stable | No |
| [libxcb-util](../depends/packages/libxcb_util.mk) | `libxcb_util.mk` | (vendored set) | stable | No |
| [libxkbcommon](../depends/packages/libxkbcommon.mk) | `libxkbcommon.mk` | 0.8.4 | stable | No |
| [xcb-proto](../depends/packages/xcb_proto.mk) | `xcb_proto.mk` | 1.15.2 | stable | No |
| [qrencode](../depends/packages/qrencode.mk) | `qrencode.mk` | 4.1.1 | stable | No |

Qt 5.15 is LTS. A jump to Qt 6 will be a deliberate major-version change,
not incremental.

### Networking

| Dependency | Package file | Version | Stability | Runtime |
| --- | --- | --- | --- | --- |
| [libnatpmp](../depends/packages/libnatpmp.mk) | `libnatpmp.mk` | commit `07004b9` | stable | No |
| [MiniUPnPc](../depends/packages/miniupnpc.mk) | `miniupnpc.mk` | 2.2.2 | stable | No |

### Notifications

| Dependency | Package file | Version | Stability | Runtime |
| --- | --- | --- | --- | --- |
| [ZeroMQ](../depends/packages/zeromq.mk) | `zeromq.mk` | 4.3.5 | stable | No |

### Wallet

| Dependency | Package file | Version | Stability | Runtime |
| --- | --- | --- | --- | --- |
| [Berkeley DB](../depends/packages/bdb.mk) (legacy wallet) | `bdb.mk` | 4.8.30 | stable | No |
| [SQLite](../depends/packages/sqlite.mk) | `sqlite.mk` | 3.38.5 | stable | No |

Berkeley DB 4.8 is locked to 4.8.30 for on-disk wallet compatibility with
historical Bitcoin/Dash releases. This pin will not change; see
[build-unix.md](build-unix.md) Berkeley DB note.

### Tracing (optional)

| Dependency | Package file | Version | Stability | Runtime |
| --- | --- | --- | --- | --- |
| [systemtap](../depends/packages/systemtap.mk) | `systemtap.mk` | 4.8 | stable | No |

### Multiprocess (optional, IPC between kerrigand subprocesses)

| Dependency | Package file | Version | Stability | Runtime |
| --- | --- | --- | --- | --- |
| [libmultiprocess](../depends/packages/libmultiprocess.mk) | `libmultiprocess.mk` | commit `abe254b` | stable | No |
| [Cap'n Proto](../depends/packages/capnp.mk) | `capnp.mk` | 1.3.0 | stable | No |

## Version-Bump Cadence

Cutting-edge packages (the ones most likely to need attention):

- **Rust toolchain** (`native_rust.mk`, `native_cxxbridge.mk`, `rustcxx.mk`):
  Rust releases every 6 weeks. cxxbridge follows cxx crate releases. Expect
  to bump both once or twice per Kerrigan release.
- **Vendored crates** (`vendored_crates.mk`): Every crate update forces a
  rebuild of the vendored tarball via `./download-crates.sh`.
- **Qt** (`qt.mk`): Qt 5.15 LTS receives patch releases. Bump on security
  advisory or Qt 6 migration.
- **Host compilers** (GCC, Clang): tracked by Bitcoin Core. Kerrigan
  follows.

Stable packages (Boost, libevent, libsodium, gmp, sqlite, zeromq,
miniupnpc, libnatpmp, libbacktrace, Berkeley DB) are expected to hold for
multiple Kerrigan releases without change. Bump only on CVE or platform
compatibility break.

## Change Procedure

See [build-reproducibility.md](build-reproducibility.md) "How to Add a New
Dependency" for the full process. One-line summary: pin exactly, regenerate
the vendored crates tarball, verify offline build, commit everything
together.
