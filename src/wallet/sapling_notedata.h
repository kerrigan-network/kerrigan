// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license.

#ifndef KERRIGAN_WALLET_SAPLING_NOTEDATA_H
#define KERRIGAN_WALLET_SAPLING_NOTEDATA_H

#include <consensus/amount.h>
#include <sapling/sapling_address.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <vector>

namespace wallet {

/**
 * Data tracked per received Sapling note.
 *
 * Each SaplingNoteData represents one OutputDescription that wallet's IVK
 * successfully decrypted.  Notes are keyed by nullifier in the parent map.
 *
 * Persistence: stored in wallet DB (task #1). Until that lands, the parent
 * map lives in memory in SaplingKeyManager.
 */
struct SaplingNoteData {
    /** Which incoming viewing key decrypted this note. */
    sapling::SaplingIncomingViewingKey ivk;

    /** Diversified payment address this note was sent to. */
    sapling::SaplingPaymentAddress recipient;

    /** Note value in satoshis. */
    CAmount value{0};

    /** Note randomness seed (rseed, 32 bytes, ZIP 212). */
    std::array<uint8_t, 32> rseed{};

    /**
     * Sapling nullifier (32 bytes).
     * Derived from nk + note position; used to detect when the note is spent.
     * Populated after the commitment tree position is known.
     */
    uint256 nullifier;

    /** Memo field (512 bytes, zero-padded). */
    std::array<uint8_t, 512> memo{};

    // -- Location ---------------------------------------------------------

    /** Transaction that created this note. */
    uint256 txid;

    /** Index of the OutputDescription within the SaplingTxPayload. */
    int outputIndex{-1};

    /** Block height at which this note was confirmed (-1 if mempool). */
    int blockHeight{-1};

    // -- Merkle witness ---------------------------------------------------

    /**
     * Position of this note's commitment in the global Sapling Merkle tree.
     * Set when the note is first confirmed; -1 if unknown.
     * Required for nullifier derivation and witness updates.
     */
    int64_t treePosition{-1};

    /**
     * Serialized incremental witness (from Rust SaplingWitness).
     * Updated per block with new commitments. When spending, deserialize
     * and call witness_path() to get the 1065-byte Merkle proof.
     * Empty if the note has not been witnessed yet.
     */
    std::vector<uint8_t> witnessData;

    // -- Spend tracking ---------------------------------------------------

    /** True once a SpendDescription with this nullifier is confirmed. */
    bool isSpent{false};

    /** Txid that spent this note (zero if unspent). */
    uint256 spendingTxid;

    // -- Serialization ----------------------------------------------------

    SERIALIZE_METHODS(SaplingNoteData, obj) {
        READWRITE(Span{obj.ivk.key});
        READWRITE(Span{obj.recipient.d});
        READWRITE(Span{obj.recipient.pk_d});
        READWRITE(obj.value);
        READWRITE(Span{obj.rseed});
        READWRITE(obj.nullifier);
        READWRITE(Span{obj.memo});
        READWRITE(obj.txid);
        READWRITE(obj.outputIndex);
        READWRITE(obj.blockHeight);
        READWRITE(obj.treePosition);
        READWRITE(obj.witnessData);
        READWRITE(obj.isSpent);
        READWRITE(obj.spendingTxid);
    }
};

} // namespace wallet

#endif // KERRIGAN_WALLET_SAPLING_NOTEDATA_H
