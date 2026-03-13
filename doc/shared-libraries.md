Shared Libraries
================

## kerriganconsensus

The purpose of this library is to make the verification functionality that is critical to Kerrigan's consensus available to other applications, e.g. to language bindings.

### API

The interface is defined in the C header `bitcoinconsensus.h` located in  `src/script/bitcoinconsensus.h`.

#### Version

`kerriganconsensus_version` returns an `unsigned int` with the API version *(currently at an experimental `0`)*.

#### Script Validation

`kerriganconsensus_verify_script` returns an `int` with the status of the verification. It will be `1` if the input script correctly spends the previous output `scriptPubKey`.

##### Parameters
- `const unsigned char *scriptPubKey` - The previous output script that encumbers spending.
- `unsigned int scriptPubKeyLen` - The number of bytes for the `scriptPubKey`.
- `const unsigned char *txTo` - The transaction with the input that is spending the previous output.
- `unsigned int txToLen` - The number of bytes for the `txTo`.
- `unsigned int nIn` - The index of the input in `txTo` that spends the `scriptPubKey`.
- `unsigned int flags` - The script validation flags *(see below)*.
- `kerriganconsensus_error* err` - Will have the error/success code for the operation *(see below)*.

##### Script Flags
- `kerriganconsensus_SCRIPT_FLAGS_VERIFY_NONE`
- `kerriganconsensus_SCRIPT_FLAGS_VERIFY_P2SH` - Evaluate P2SH ([BIP16](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki)) subscripts
- `kerriganconsensus_SCRIPT_FLAGS_VERIFY_DERSIG` - Enforce strict DER ([BIP66](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki)) compliance
- `kerriganconsensus_SCRIPT_FLAGS_VERIFY_NULLDUMMY` - Enforce NULLDUMMY ([BIP147](https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki))
- `kerriganconsensus_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY` - Enable CHECKLOCKTIMEVERIFY ([BIP65](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki))
- `kerriganconsensus_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY` - Enable CHECKSEQUENCEVERIFY ([BIP112](https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki))

##### Errors
- `kerriganconsensus_ERR_OK` - No errors with input parameters *(see the return value of `kerriganconsensus_verify_script` for the verification status)*
- `kerriganconsensus_ERR_TX_INDEX` - An invalid index for `txTo`
- `kerriganconsensus_ERR_TX_SIZE_MISMATCH` - `txToLen` did not match with the size of `txTo`
- `kerriganconsensus_ERR_DESERIALIZE` - An error deserializing `txTo`
- `kerriganconsensus_ERR_INVALID_FLAGS` - Script verification `flags` are invalid (i.e. not part of the libconsensus interface)
