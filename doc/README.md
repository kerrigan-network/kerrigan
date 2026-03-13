Kerrigan
==========

This is the official reference wallet for Dash digital currency and comprises the backbone of the Dash peer-to-peer network. You can [download Kerrigan](https://www.kerrigan.network/downloads/) or [build it yourself](#building) using the guides below.

Running
---------------------
The following are some helpful notes on how to run Kerrigan on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/kerrigan-qt` (GUI) or
- `bin/kerrigand` (headless)

### Windows

Unpack the files into a directory, and then run kerrigan-qt.exe.

### macOS

Drag Kerrigan to your applications folder, and then run Kerrigan.

### Need Help?

* See the [Dash documentation](https://docs.kerrigan.network)
for help and more information.
* Ask for help on [Dash Discord](http://staydashy.com)
* Ask for help on the [Dash Forum](https://kerrigan.network/forum)

Building
---------------------
The following are developer notes on how to build Kerrigan on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [NetBSD Build Notes](build-netbsd.md)
- [Android Build Notes](build-android.md)

Development
---------------------
The Kerrigan repo's [root README](/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Productivity Notes](productivity.md)
- [Release Notes](release-notes.md)
- [Release Process](release-process.md)
- Source Code Documentation ***TODO***
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [JSON-RPC Interface](JSON-RPC-interface.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Shared Libraries](shared-libraries.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)
- [Internal Design Docs](design/)

### Resources
* See the [Kerrigan Developer Documentation](https://kerrigan.network/)
  for technical specifications and implementation details.
* Discuss on the [Kerrigan Discord](https://discord.gg/V9P3UDjkFu)

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [kerrigan.conf Configuration File](dash-conf.md)
- [CJDNS Support](cjdns.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [I2P Support](i2p.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [Managing Wallets](managing-wallets.md)
- [Multisig Tutorial](multisig-tutorial.md)
- [P2P bad ports definition and list](p2p-bad-ports.md)
- [PSBT support](psbt.md)
- [Reduce Memory](reduce-memory.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Transaction Relay Policy](policy/README.md)
- [ZMQ](zmq.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).
