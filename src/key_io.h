// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KEY_IO_H
#define BITCOIN_KEY_IO_H

#include <key.h>
#include <pubkey.h>
#include <sapling/sapling_address.h>
#include <script/standard.h>

#include <string>

class CChainParams;

CKey DecodeSecret(const std::string& str);
std::string EncodeSecret(const CKey& key);

CExtKey DecodeExtKey(const std::string& str);
std::string EncodeExtKey(const CExtKey& extkey);
CExtPubKey DecodeExtPubKey(const std::string& str);
std::string EncodeExtPubKey(const CExtPubKey& extpubkey);

std::string EncodeDestination(const CTxDestination& dest);
CTxDestination DecodeDestination(const std::string& str);
CTxDestination DecodeDestination(const std::string& str, std::string& error_msg);
bool IsValidDestinationString(const std::string& str);
bool IsValidDestinationString(const std::string& str, const CChainParams& params);

/** Encode a Sapling payment address as Bech32m with the network-specific HRP. */
std::string EncodeSaplingAddress(const sapling::SaplingPaymentAddress& addr);
/** Decode a Bech32m Sapling payment address. Returns false if invalid. */
bool DecodeSaplingAddress(const std::string& str, sapling::SaplingPaymentAddress& addr);
/** Check if a string is a valid Sapling address for the current network. */
bool IsValidSaplingAddress(const std::string& str);

#endif // BITCOIN_KEY_IO_H
