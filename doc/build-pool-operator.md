# Building Kerrigan for Pool Operators

Quick-start guide for building `kerrigand` (headless daemon) from source on
common Linux distributions. Optimized for pool operators who need a working
daemon -- no GUI, no wallet, no tests.

Kerrigan 1.1.1 uses the `depends/` system to build every runtime library
(boost, libsodium, gmp, sqlite, zmq, miniupnpc, natpmp, libevent, berkeley-db,
qt) from pinned sources, plus the Rust 1.81 toolchain and cxxbridge. **No
distro `-dev` packages are required at runtime.** The host only needs a
toolchain and autotools.

## Supported Platforms

| Distro | GCC | Status | Notes |
|--------|-----|--------|-------|
| Ubuntu 24.04 | 13.2 | Native | Default target, fully tested |
| Ubuntu 22.04 | 11.4 | Native | Supported |
| Ubuntu 20.04 | 9.4 | **Needs PPA** | GCC 9 too old (need 11+), use `ppa:ubuntu-toolchain-r/test` |
| Debian 12 | 12.2 | Native | Supported |
| Debian 11 | 10.2 | **Needs backports** | GCC 10 too old, install `gcc-12` from backports |
| Fedora 38+ | 13+ | Native | Supported |
| Rocky / Alma 9 | 11.4 | Native | Supported |
| Arch Linux | Latest | Native | Supported |

## Requirements

- **GCC 11.1+** or **Clang 16+** (C++20 support mandatory)
- Build tools: `make`, `autoconf`, `automake`, `libtool`, `pkg-config`,
  `curl`, `python3`, `patch`
- ~2 GB RAM for compilation (Rust / bellman is the peak)
- ~6 GB disk for the full depends tree plus build artefacts
- ~45 min for the first build on 12 cores; incremental builds are fast

Rust, cxxbridge, and every C/C++ library come from `depends/` -- do **not**
install rustup, cargo, or cxxbridge manually on the host.

## One-Liner Install (Ubuntu 22.04 / 24.04)

```bash
sudo apt update && \
sudo apt install -y build-essential git cmake curl pkg-config \
  autoconf automake libtool bsdmainutils python3 ca-certificates patch && \
git clone https://github.com/kerrigan-network/kerrigan.git && \
cd kerrigan && \
./build.sh
```

`build.sh` installs the toolchain (sudo on first run), regenerates the Rust
vendor tarball if missing, builds `depends/` and then Kerrigan. Binaries
land under `src/`.

## Step-by-Step Instructions

### 1. Install Host Tools

Only the compiler toolchain and autotools are needed. The distro library
packages (`libboost-dev`, `libsodium-dev`, etc.) are **not** required and
should not be installed for a reproducible build -- `depends/` brings its
own pinned versions.

#### Ubuntu 24.04 (Noble) / 22.04 (Jammy)
```bash
sudo apt update
sudo apt install -y build-essential git cmake curl pkg-config \
  autoconf automake libtool bsdmainutils python3 ca-certificates patch
```

#### Ubuntu 20.04 (Focal) -- Needs newer GCC
```bash
sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
sudo apt update
sudo apt install -y gcc-12 g++-12 build-essential git cmake curl pkg-config \
  autoconf automake libtool bsdmainutils python3 ca-certificates patch

sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-12 100
sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-12 100
```

#### Debian 12 (Bookworm)
```bash
sudo apt update
sudo apt install -y build-essential git cmake curl pkg-config \
  autoconf automake libtool bsdmainutils python3 ca-certificates patch
```

#### Debian 11 (Bullseye) -- Needs newer GCC
```bash
echo "deb http://deb.debian.org/debian bullseye-backports main" | \
  sudo tee /etc/apt/sources.list.d/backports.list
sudo apt update
sudo apt install -y -t bullseye-backports gcc-12 g++-12
sudo apt install -y build-essential git cmake curl pkg-config \
  autoconf automake libtool bsdmainutils python3 ca-certificates patch

sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-12 100
sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-12 100
```

#### Fedora 38+
```bash
sudo dnf install -y gcc gcc-c++ make git cmake curl pkgconf-pkg-config \
  autoconf automake libtool python3 ca-certificates which patch
```

#### Rocky / AlmaLinux 9
```bash
sudo dnf install -y gcc-toolset-12 make git cmake curl pkgconf-pkg-config \
  autoconf automake libtool python3 ca-certificates which patch

# Enable the newer toolchain for this shell
scl enable gcc-toolset-12 bash
```

#### Arch Linux
```bash
sudo pacman -Sy --needed --noconfirm base-devel git cmake curl pkgconf \
  autoconf automake libtool python ca-certificates patch
```

### 2. Clone and Build

```bash
git clone https://github.com/kerrigan-network/kerrigan.git
cd kerrigan

# build.sh handles everything: tool check, vendor tarball, depends, configure, make
./build.sh

# Daemon and CLI end up at:
ls -la src/kerrigand src/kerrigan-cli
```

Flags:

```
./build.sh --clean          # wipe depends/ and rebuild from scratch
./build.sh --online-rust    # let cargo hit crates.io (dev only, not reproducible)
./build.sh --jobs N         # cap parallel jobs (low-RAM hosts, positive integer)
```

The first build downloads source tarballs for every dependency into
`depends/sources/` and takes roughly 45 minutes on 12 cores. Subsequent
builds reuse `depends/built/` and are fast.

### 3. Manual Build (Alternative)

If you need more control than `build.sh` offers:

```bash
# Vendor Rust crates from Cargo.toml + Cargo.lock (first run only; skip if
# depends/sources/vendored-crates-*.tar.gz already exists)
./download-crates.sh

# Build every dependency under depends/<triple>/
make -C depends -j$(nproc)

# Generate configure, then configure against the depends prefix
./autogen.sh
HOST=$(./depends/config.guess)
CONFIG_SITE=$PWD/depends/$HOST/share/config.site ./configure \
  --prefix=$PWD/depends/$HOST \
  --without-gui \
  --disable-wallet \
  --disable-tests \
  --disable-bench \
  --disable-online-rust

make -j$(nproc)
```

Do not pass `--prefix=/`. The Kerrigan build expects `$prefix` to be the
`depends/<triple>/` directory; pointing it at `/` and running `make install`
would dump files into `/bin`, `/etc`, `/share`.

## Common Build Errors

### `ERROR: cmake not installed`
`build.sh` runs a pre-flight tool check. If the apt / dnf / pacman install
step was skipped (or your distro is not recognised), install the missing
tools and re-run.

### `--disable-online-rust was specified but vendored sources are not available`
`configure` refuses to build offline without a vendored-crates tarball. Run
`./download-crates.sh` (requires network access to crates.io once), or re-run
`./build.sh` which invokes it automatically on a fresh clone.

### `C++20 support not found`
Your compiler is too old. Need GCC 11+ or Clang 16+. See the distro table
above for the right PPA / backport channel.

### `make -C depends` stalls or fails on gmp
A GNU mirror hiccup. Re-run `./build.sh` -- curl retries on the next run.
You can also drop the source tarball into `depends/sources/` manually and
restart.

### Rust compilation runs out of memory
Rust (and bellman in particular) peaks around 2 GB. On low-memory hosts,
add swap and cap parallelism:

```bash
sudo fallocate -l 4G /swap && sudo chmod 600 /swap && \
  sudo mkswap /swap && sudo swapon /swap
./build.sh --jobs 2
```

### `configure: error: Rust toolchain not found`
You have a stale `depends/` from before v1.1.1. Clean and rebuild:
```bash
./build.sh --clean
```

## Pool Daemon Configuration

After building, see [pool-integration.md](pool-integration.md) for:
- `rpcalgoport` configuration (per-algo RPC ports)
- `pooladdress` setup (coinbase recipient)
- Miningcore / S-NOMP integration
- Troubleshooting mining issues

## Verifying Your Build

```bash
# Check version
./src/kerrigand --version

# Quick test: start on mainnet, sync headers
./src/kerrigand -printtoconsole -datadir=/tmp/kerrigan-test

# Test RPC
./src/kerrigan-cli -rpcuser=pool -rpcpassword=test getblockchaininfo
```
