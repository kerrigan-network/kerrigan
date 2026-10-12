// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_SAPLING_SEND_H
#define BITCOIN_WALLET_SAPLING_SEND_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wallet {
class CWallet;

/**
 * The funds a shielded send spends: the wallet's transparent coins or its
 * Sapling notes, from any of its addresses.
 */
struct SaplingSendSource {
    //! Spend Sapling notes (true) or transparent coins (false).
    bool shielded{false};
    //! Transparent source: spend exactly these coins. Empty: choose from all spendable coins.
    std::vector<COutPoint> coins;
    //! Shielded source: spend exactly these notes (note commitments). Empty: choose from all spendable notes.
    std::vector<uint256> notes;
    //! Transparent source: where the change goes. CNoDestination: a new change address.
    CTxDestination change_dest{CNoDestination{}};
};

struct SaplingSendRecipient {
    std::string address;
    CAmount amount{0};
    //! Memo bytes (at most 512, zero-padded on send). Shielded recipients only.
    std::vector<uint8_t> memo;
    //! Pay the fee out of this amount (split evenly between such recipients).
    bool subtract_fee{false};
};

/** A Sapling note the wallet can spend. */
struct SaplingSpendableNote {
    uint256 cmu;
    uint256 txid;
    int output_index{-1};
    CAmount value{0};
    std::string address;
    //! Received on an internal (ZIP 316) change address.
    bool is_change{false};
    int depth{0};
    int64_t time{0};
};

/** Inputs of a planned send that come from one address. */
struct SaplingSendInputGroup {
    std::string address;
    //! Internal (ZIP 316) shielded change address.
    bool is_change{false};
    size_t count{0};
    CAmount value{0};
};

/** The inputs, fee and change a shielded send will use. */
struct SaplingSendPlan {
    std::vector<COutPoint> coins;
    std::vector<uint256> notes;
    //! Inputs grouped by address, largest first.
    std::vector<SaplingSendInputGroup> sources;
    CAmount input_total{0};
    CAmount fee{0};
    CAmount change{0};
    //! Recipient amounts after subtracting the fee, in recipient order.
    std::vector<CAmount> amounts;
};

/** Notes with at least @p minconf confirmations that the wallet holds the spending key for. */
std::vector<SaplingSpendableNote> ListSpendableSaplingNotes(const CWallet& wallet, int minconf);

/**
 * Choose the inputs and compute the fee and change for a shielded send
 * (t->z, z->z or z->t). Nothing is reserved. Without an explicit selection,
 * the largest coins or notes are used first.
 *
 * @throws std::runtime_error with a user-facing message.
 */
SaplingSendPlan PlanSaplingSend(CWallet& wallet, const SaplingSendSource& source,
                                const std::vector<SaplingSendRecipient>& recipients,
                                int minconf, std::optional<CAmount> fee = std::nullopt);

/**
 * Plan, prove, sign and commit a shielded send. Shielded change goes to an
 * internal address of the key that owns the largest spent note; transparent
 * change goes to @p source.change_dest or a new change address.
 * Generating the proofs is slow; cs_wallet is released meanwhile.
 *
 * @return the txid.
 * @throws std::runtime_error with a user-facing message.
 */
std::string SendSapling(CWallet& wallet, const SaplingSendSource& source,
                        const std::vector<SaplingSendRecipient>& recipients,
                        int minconf, std::optional<CAmount> fee = std::nullopt);
} // namespace wallet

#endif // BITCOIN_WALLET_SAPLING_SEND_H
