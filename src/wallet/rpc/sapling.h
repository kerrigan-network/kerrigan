// Copyright (c) 2024 The Kerrigan developers
// Distributed under the MIT software license.

#ifndef KERRIGAN_WALLET_RPC_SAPLING_H
#define KERRIGAN_WALLET_RPC_SAPLING_H

#include <rpc/util.h>

namespace wallet {

RPCHelpMan z_getnewaddress();
RPCHelpMan z_getbalance();
RPCHelpMan z_listunspent();
RPCHelpMan z_sendmany();
RPCHelpMan z_listaddresses();
RPCHelpMan z_exportkey();
RPCHelpMan z_importkey();
RPCHelpMan z_exportviewingkey();
RPCHelpMan z_importviewingkey();
RPCHelpMan z_rebuildsaplingwitnesses();

} // namespace wallet

#endif // KERRIGAN_WALLET_RPC_SAPLING_H
