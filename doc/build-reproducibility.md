REPRODUCIBLE BUILDS
====================

Two independent builds of the same Kerrigan source tree, on hosts with
matching compiler versions, produce release binaries with identical SHA256.
This document explains the design, how to verify it, how to audit the
pinned SHA256 values, and how to add a new dependency without breaking it.

What Reproducibility Means Here
-------------------------------

A reproducible build is one where:

- Given the same source tree (same git tag),
- and the same `depends/` pins,
- on two different machines with matching host-compiler versions,
- the release archive (`kerrigan-1.1.1-<triple>.tar.gz` or `.zip`) has an
  identical SHA256.

Reproducibility lets third parties verify that a signed release binary was
built from the published source, with no tampering by the build maintainer.

What reproducibility does NOT mean:

- It does not mean every host produces the same output. A Fedora host with
  GCC 14 and an Ubuntu host with GCC 11 will produce different binaries;
  that is expected.
- It does not guarantee security. A compromised source tree or pinned
  tarball will reproduce a compromised binary consistently.

Scope
-----

Reproducibility is verified on the following triples:

```
x86_64-pc-linux-gnu      Ubuntu 22.04 host, GCC 11.4
aarch64-linux-gnu        Ubuntu 22.04 host, cross-GCC 11.4
x86_64-w64-mingw32       Docker Ubuntu 24.04, mingw GCC 13
x86_64-apple-darwin      GitHub Actions macos-13 runner
aarch64-apple-darwin     GitHub Actions macos-14 runner
```

Linux and Windows builds are reproducible across arbitrary hosts that match
the compiler pin. macOS reproducibility is only asserted across identical
GitHub Actions runner images, because Apple codesigning and linker behaviour
vary between Xcode point releases.

Why We Pin Everything
---------------------

Every input to the build is pinned to an exact version and SHA256:

- **Rust toolchain**: `depends/packages/native_rust.mk` pins Rust 1.81.0 and
  the SHA256 of every upstream tarball (`rust-<ver>-<triple>.tar.gz` and
  `rust-std-<ver>-<triple>.tar.gz`). Both the native compiler for the build
  host and the cross-compile `rust-std` for each target are pinned.
- **cxxbridge**: `depends/packages/native_cxxbridge.mk` pins cxx 1.0.186
  (matches `cxx = "=1.0.186"` in `Cargo.toml`). The cxxbridge-cmd build
  uses its own vendored Cargo.lock checked in at
  `depends/patches/native_cxxbridge/Cargo.lock`.
- **Rust crates**: `Cargo.toml` uses exact pins (`"=0.14.0"` not `"0.14"`).
  `Cargo.lock` is checked in. The vendored tarball at
  `depends/sources/vendored-crates-1.1.1.tar.gz` is the complete transitive
  closure of crates.io dependencies, verified against
  `depends/packages/vendored_crates.mk`'s SHA256.
- **C/C++ libraries**: Every depends package pins version and SHA256 (Boost
  1.81.0, libevent 2.1.12, libsodium 1.0.20, gmp 6.3.0, sqlite 3.38.5,
  zeromq 4.3.5, miniupnpc 2.2.2, libnatpmp commit 07004b9, libbacktrace
  commit b9e4006, Qt 5.15.18, Berkeley DB 4.8.30).

An unpinned dependency is a reproducibility bug. If `cargo update` can
change what you ship, your build is not reproducible.

How to Verify Two Builds Produce Identical Binaries
---------------------------------------------------

Reference procedure for Linux x86_64. Host-A and Host-B must have the same
Ubuntu point release (or any two hosts with the same `gcc --version` and
`ld --version` output).

### On Host A

```sh
git clone https://github.com/kerrigan-network/kerrigan.git
cd kerrigan
git checkout v1.1.1
rm -rf depends/built depends/work depends/x86_64-pc-linux-gnu
make -C depends HOST=x86_64-pc-linux-gnu -j$(nproc)
./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site ./configure \
    --prefix=/ --disable-tests --disable-bench
make -j$(nproc)
sha256sum src/kerrigand src/kerrigan-cli src/qt/kerrigan-qt
```

### On Host B

Same commands. Compare the three SHA256 values. They must match.

### What To Do When They Don't

If the SHAs differ, the most common causes, in order of likelihood:

1. Different compiler point release. Confirm `gcc --version` matches to the
   patch level. `11.4.0` and `11.4.1` can produce different output.
2. Different `SOURCE_DATE_EPOCH`. Check `env | grep SOURCE_DATE_EPOCH`. If
   set on one host and not the other, the build stamps different timestamps.
3. Build path leaked into a binary. Grep the mismatched binary for the
   absolute build path (`strings src/kerrigand | grep /home`). Any hit is a
   reproducibility bug in that specific compilation unit.
4. A depends package ran a build script that hit the network. `unshare -n
   make` should still succeed; if it fails, that package needs its
   `$(package)_fetch_cmds` tightened.

How to Audit the Pinned SHA256 Values
-------------------------------------

`contrib/devtools/update-rust-hashes.sh` refreshes the Rust toolchain
hashes against `static.rust-lang.org`:

```sh
cd kerrigan
./contrib/devtools/update-rust-hashes.sh
git diff depends/packages/native_rust.mk
```

The script uses `curl -fsSL` (fails hard on HTTP error, follows redirects)
so a 404 cannot silently turn an HTML error page into a bogus hash. It
updates both native-compiler tarballs (`rust-<ver>-<triple>.tar.gz`) and
cross-compile sysroots (`rust-std-<ver>-<triple>.tar.gz`) for:

```
aarch64-unknown-linux-gnu
x86_64-apple-darwin
x86_64-unknown-linux-gnu
x86_64-unknown-freebsd
aarch64-apple-darwin
x86_64-pc-windows-gnu
```

For other depends packages, the SHA256 lives in the package's `.mk` file
next to the version pin. To audit manually:

```sh
# Example: audit boost 1.81.0
URL=$(grep -E '^\$\(package\)_download_path' depends/packages/boost.mk)
FILE=$(grep -E '^\$\(package\)_file_name' depends/packages/boost.mk)
curl -fsSL "<download_path>/<file_name>" | sha256sum
# Compare with $(package)_sha256_hash in depends/packages/boost.mk
```

To audit the vendored crates tarball:

```sh
./vendor-hash.sh    # prints SHA256 of depends/sources/vendored-crates-1.1.1.tar.gz
grep sha256_hash depends/packages/vendored_crates.mk
```

The two values must match.

How to Add a New Dependency
---------------------------

Kerrigan minimises its dependency footprint. Adding a new crate or C library
is a deliberate act. Process:

1. **Justify it.** Prefer extending a crate already in `Cargo.toml` over
   pulling a new one. Prefer a 100-line C implementation over a
   multi-hundred-line C dependency.
2. **Vet the source.** For a crate, check crates.io for download count,
   publishing history, and dependent count. Skim the source for
   obvious smells (build.rs reaching out to the network, proc-macros
   calling `include_str!` on system files, etc.).
3. **Pin it exactly.** `"=0.14.0"` in `Cargo.toml`, never `"0.14"`. For a
   C library, add a new `depends/packages/<name>.mk` with an exact version
   and a SHA256 verified against the upstream release page.
4. **Regenerate the vendored crates tarball:**

   ```sh
   ./download-crates.sh
   ./vendor-hash.sh    # paste output into depends/packages/vendored_crates.mk
   ```

5. **Verify offline build works:**

   ```sh
   make -C depends -j$(nproc)
   ./autogen.sh
   CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site \
       ./configure --disable-online-rust
   sudo unshare -n -- bash -c 'make -j$(nproc)'
   ```

   `unshare -n` disables network namespace. If the build tries to reach the
   network, it fails. An offline-capable build is the passing condition.
6. **Commit everything in one change.** `Cargo.toml`, `Cargo.lock`,
   `depends/sources/vendored-crates-1.1.1.tar.gz`, and the hash bump in
   `depends/packages/vendored_crates.mk` all land together. A partial
   commit leaves the tree inconsistent and breaks reproducibility for
   whoever pulls between the two commits.

Supply Chain Considerations
---------------------------

What happens if an upstream crate is compromised and a malicious version
is published after our pin?

- **crates.io yanks:** A yank removes the crate from default resolution but
  leaves it reachable by exact pin. Our exact pins in `Cargo.toml` plus
  `cargo --locked` keep the compromised version out of a cold resolve, but
  an older checkout that already pinned the bad version continues to build
  it. This is why `Cargo.lock` is checked in.
- **Silent upstream version swap:** crates.io does not allow overwriting
  a published version, so an attacker cannot silently swap `0.14.0` for a
  malicious `0.14.0`. They must publish `0.14.1`. Our pin to `=0.14.0`
  blocks that.
- **Compromised maintainer publishing a new minor:** If we use `"0.14"` the
  attacker's `0.14.1` lands on next `cargo update`. If we use `"=0.14.0"`
  we ignore it. This is why every direct dependency is an exact pin.
- **Compromised upstream source git repo:** Irrelevant until someone
  publishes a new version on crates.io. Kerrigan resolves only from
  crates.io (via the vendored tarball), not from git.
- **Compromised build host:** Out of scope for reproducibility. Defence in
  depth: multiple maintainers perform independent builds from signed source
  tags and compare SHA256 before publishing signed binaries.
- **Compromised release signing key:** Out of scope for this document;
  handled by the release signing policy (separate airgapped keys, multiple
  signers).

If a crate IS compromised after we pin it, the response is:

1. Identify the affected crate and version.
2. Identify the last known-good version. If the pin is already older than
   the compromise, we are unaffected for builds from that commit forward,
   but existing signed binaries are compromised.
3. Update `Cargo.toml` to a known-good version (usually newer, sometimes
   older), regenerate `Cargo.lock` and the vendored tarball, cut a new
   release.
4. Publish an advisory with SHA256 hashes of the compromised binaries so
   users can identify them.

Files That Make Reproducibility Work
------------------------------------

```
depends/packages/native_rust.mk          Rust 1.81.0 + all triples + SHA256
depends/packages/native_cxxbridge.mk     cxx 1.0.186 + SHA256
depends/packages/rustcxx.mk              Pinned cxx.h header stage
depends/packages/vendored_crates.mk      Vendored tarball + SHA256
depends/sources/vendored-crates-1.1.1.tar.gz   The tarball itself
depends/patches/native_cxxbridge/Cargo.lock    Pin for cxxbridge-cmd build
Cargo.toml                               Exact pins for every direct crate
Cargo.lock                               Full transitive resolution
.cargo/config.toml.offline               Offline mode template
rust-toolchain.toml                      1.81.0 for standalone cargo
contrib/devtools/update-rust-hashes.sh   Audit helper for Rust SHA256s
download-crates.sh                       Reproducible vendored-tarball builder
vendor-hash.sh                           SHA256 computation for the tarball
```

Any change to any of these files must keep the tree self-consistent. A
`Cargo.lock` that doesn't match `Cargo.toml`, or a vendored tarball whose
SHA256 doesn't match `vendored_crates.mk`, breaks the build on the next
clean checkout.
