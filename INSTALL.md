Kerrigan Core Install
=====================

Binary install
--------------

Official tagged releases ship pre-built tarballs and a Windows installer at
https://github.com/kerrigan-network/kerrigan/releases. v1.1.1 is still in
development; binary downloads and `SHA256SUMS` files will appear on the
release page after v1.1.1 is tagged. Until then, install from source (below)
or grab the most recent tagged release (currently v1.0.5):

```sh
tar xzf kerrigan-1.0.5-x86_64-linux-gnu.tar.gz
cd kerrigan-1.0.5-x86_64-linux-gnu/bin
./kerrigand -daemon
./kerrigan-cli getblockchaininfo
```

Windows users: download `kerrigan-1.0.5-win64-setup.exe` and run it.

When a release publishes a `SHA256SUMS` file, verify every tarball against
it before running anything. Pool operators and validators should also check
the detached PGP signature.

Build from source
-----------------

```sh
git clone https://github.com/kerrigan-network/kerrigan.git
cd kerrigan
./build.sh
```

`build.sh` installs the build tools it needs (sudo on first run), vendors
the Rust crates on first run, then compiles every library (boost, libsodium,
gmp, sqlite, zmq, miniupnpc, natpmp, berkeley-db, rust 1.81, cxxbridge, qt)
from pinned sources under `depends/`. No system libraries are consumed.
First build takes roughly 45 minutes on 12 cores; incremental builds are fast.

Flags:

```
./build.sh --clean          # wipe depends/ and rebuild from scratch
./build.sh --online-rust    # let cargo hit crates.io (dev only, not reproducible)
./build.sh --jobs N         # cap parallel jobs, positive integer only
```

Binaries land in `src/kerrigand`, `src/kerrigan-cli`, `src/kerrigan-tx`, etc.
Release builds for multiple targets use `./build-release.sh`
(see `doc/build-release.md`).

Note on `make install`
----------------------

`build.sh` configures with `--prefix=$PWD/depends/<triple>` so that headers
and pkg-config files point at the staged dependency tree. **Do not run
`sudo make install` after a `build.sh` run** -- it would copy binaries into
the depends/ prefix, not a system location. If you want a system install:

```sh
# After build.sh completes, re-configure with a system prefix and install.
./configure --prefix=/usr/local --disable-tests --disable-bench
sudo make install
```

Passing `--prefix=/` is not supported and will place binaries in `/bin`,
`/etc`, `/share` on `make install`.

Troubleshooting
---------------

**`make -C depends` stalls or fails on gmp.**
Network hiccup on a GNU mirror. Re-run `./build.sh` or drop the archive
into `depends/sources/` manually. See `doc/build-release.md` Gotchas.

**Rust build runs out of RAM.**
Bellman needs roughly 2 GB. Add swap or pass `--jobs 2`:

```sh
sudo fallocate -l 4G /swap && sudo mkswap /swap && sudo swapon /swap
./build.sh --jobs 2
```

**`configure: error: Rust toolchain not found`.**
You have a stale `depends/` from before v1.1.1. Run `./build.sh --clean`.
The Rust toolchain now comes from `depends/packages/native_rust.mk`; it is
not installed on the host.

**`--disable-online-rust was specified but vendored sources are not available`.**
`configure` refuses to build offline without a vendored-crates tarball.
Run `./download-crates.sh` once (needs crates.io access), or re-run
`./build.sh` which invokes it automatically on a fresh clone.

**Unsupported distro / `apt-get: command not found`.**
Install these build tools manually, then re-run `./build.sh`:
build-essential (or gcc/g++ + make), git, cmake, curl, pkg-config,
autoconf, automake, libtool, bsdmainutils, python3, patch.
Do not install boost/libsodium/gmp/sqlite/zmq from the distro. `depends/`
builds pinned versions of all of them.

Getting Started
---------------

After `build.sh` finishes, the daemon and CLI live in `src/`:

```sh
ls src/kerrigand src/kerrigan-cli
```

Run the daemon in the foreground once to seed a default data directory:

```sh
mkdir -p ~/.kerrigan
cat > ~/.kerrigan/kerrigan.conf <<'CONF'
# Minimal kerrigan.conf for a local node. Pick a strong rpcpassword.
rpcuser=kerrigan
rpcpassword=change_me_before_production_use
rpcport=9998
server=1
daemon=0
txindex=1
CONF

./src/kerrigand -printtoconsole
```

In a second terminal, verify RPC works:

```sh
./src/kerrigan-cli getblockchaininfo
./src/kerrigan-cli getpeerinfo
```

**Wallet**: the headless daemon ships with a built-in wallet. Create one
with:

```sh
./src/kerrigan-cli createwallet "main"
./src/kerrigan-cli -rpcwallet=main getnewaddress
```

For a GUI wallet instead, build with the default `configure` flags (not
`--without-gui --disable-wallet`) and run `src/qt/kerrigan-qt`.

**Network peers**: the node picks up DNS seeds automatically. Connectivity
usually settles within a minute or two. If the node has no inbound peers
after 5 minutes, check that TCP/9999 (mainnet) or TCP/19999 (testnet) is
reachable, or add explicit `addnode=<ip>:9999` lines in `kerrigan.conf`.

**Running as a service**: once the config works, daemonise it:

```sh
./src/kerrigand -daemon
./src/kerrigan-cli stop    # graceful shutdown
```

For long-running pool / validator deployments, use a systemd unit pointing
at the binary. Sample unit files ship under `contrib/init/` in the source
tree.
