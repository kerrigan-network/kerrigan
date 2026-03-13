Repository Tools
---------------------

### [Developer tools](/contrib/devtools) ###
Specific tools for developers working on this repository.
Contains the script `github-merge.py` for merging GitHub pull requests securely and signing them using GPG.

### [Verify-Commits](/contrib/verify-commits) ###
Tool to verify that every merge commit was signed by a developer using the above `github-merge.py` script.

### [Linearize](/contrib/linearize) ###
Construct a linear, no-fork, best version of the blockchain.

### [Qos](/contrib/qos) ###
A Linux bash script that will set up traffic control (tc) to limit the outgoing bandwidth for connections to the Kerrigan network. This means one can have an always-on kerrigand instance running, and another local kerrigand/kerrigan-qt instance which connects to this node and receives blocks from it.

### [Seeds](/contrib/seeds) ###
Utility to generate the pnSeed[] array that is compiled into the client.

Build Tools and Keys
---------------------

### [Debian](/contrib/debian) ###
Contains files used to package kerrigand/kerrigan-qt
for Debian-based Linux systems. If you compile kerrigand/kerrigan-qt yourself, there are some useful files here.

### [Builder keys](/contrib/builder-keys)
PGP keys used for signing Kerrigan [release](/doc/release-process.md) results.

### [MacDeploy](/contrib/macdeploy) ###
Scripts and notes for Mac builds.

Test and Verify Tools
---------------------

### [TestGen](/contrib/testgen) ###
Utilities to generate test vectors for the data-driven Kerrigan tests.

### [Verify-Binaries](/contrib/verify-binaries) ###
This script attempts to download and verify the signature file SHA256SUMS.asc from bitcoin.org.
