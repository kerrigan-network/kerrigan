// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_AMOUNT_H
#define BITCOIN_CONSENSUS_AMOUNT_H

#include <cstdint>

/** Amount in satoshis (Can be negative) */
typedef int64_t CAmount;

/** The amount of satoshis in one BTC. */
static constexpr CAmount COIN = 100000000;

/** No amount larger than this (in satoshi) is valid.
 *
 * This is a consensus-critical sanity check. Any output or transaction total
 * exceeding this value is rejected. Must be >= the theoretical max supply.
 *
 * Kerrigan: 25 COIN initial subsidy, halving every 1,051,200 blocks, 64
 * halvings, max supply ~52,560,000 KRGN.
 * */
static constexpr CAmount MAX_MONEY = 52560000 * COIN;
inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }

#endif // BITCOIN_CONSENSUS_AMOUNT_H
