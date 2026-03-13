// Copyright (c) 2024 The Kerrigan developers
// Distributed under the MIT software license.

#ifndef KERRIGAN_SAPLING_TRANSACTION_BUILDER_H
#define KERRIGAN_SAPLING_TRANSACTION_BUILDER_H

#include <consensus/params.h>
#include <primitives/transaction.h>
#include <sapling/sapling_address.h>
#include <sapling/sapling_tx_payload.h>
#include <script/script.h>

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

/**
 * SaplingTransactionBuilder: constructs a complete shielded transaction.
 *
 * Wraps the Rust SaplingBuilder FFI to provide a C++ interface for building
 * t->z, z->z, and z->t transactions.
 *
 * Usage:
 *   1. Construct with consensus params + block height + tree anchor
 *   2. Call AddTransparentInput / AddTransparentOutput for transparent side
 *   3. Call AddSaplingSpend for each shielded note being consumed
 *   4. Call AddSaplingOutput for each shielded note being created
 *   5. Call Build() which returns a signed CMutableTransaction on success
 *
 * The returned transaction has:
 *   nType = TRANSACTION_SAPLING
 *   vExtraPayload = serialized SaplingTxPayload
 *
 * Build() may only be called once per builder instance.
 */
class SaplingTransactionBuilder
{
public:
    /**
     * Construct a builder for a Sapling transaction at the given height.
     *
     * Uses "regtest" network parameters (LocalNetwork with Kerrigan's
     * SaplingHeight).  Suitable for testing and regtest.
     *
     * @param params   Consensus parameters (provides SaplingHeight).
     * @param nHeight  Block height at which the transaction will confirm.
     * @param anchor   32-byte Sapling commitment tree root (from best chain tip).
     *                 Obtain via CSaplingState::GetTreeRoot(nHeight - 1, root).
     */
    SaplingTransactionBuilder(const Consensus::Params& params,
                              int nHeight,
                              const std::array<uint8_t, 32>& anchor);

    /**
     * Construct a builder with an explicit network ID string.
     *
     * @param networkIDStr  Chain network ID: "main", "test", or "regtest"
     *                      (devnet is treated like regtest).
     *                      Use Params().NetworkIDString() to obtain this.
     */
    SaplingTransactionBuilder(const Consensus::Params& params,
                              int nHeight,
                              const std::array<uint8_t, 32>& anchor,
                              const std::string& networkIDStr);

    ~SaplingTransactionBuilder();

    // Non-copyable; move allowed.
    SaplingTransactionBuilder(const SaplingTransactionBuilder&) = delete;
    SaplingTransactionBuilder& operator=(const SaplingTransactionBuilder&) = delete;
    SaplingTransactionBuilder(SaplingTransactionBuilder&&) noexcept;

    /**
     * Add a transparent input (for t->z transactions).
     *
     * @param outpoint     The UTXO being spent.
     * @param scriptPubKey The scriptPubKey of that UTXO.
     * @param value        Value in satoshis.
     */
    void AddTransparentInput(const COutPoint& outpoint,
                             const CScript& scriptPubKey,
                             CAmount value);

    /**
     * Add a transparent output (for z->t transactions).
     *
     * @param scriptPubKey  Locking script for the output.
     * @param value         Value in satoshis.
     */
    void AddTransparentOutput(const CScript& scriptPubKey, CAmount value);

    /**
     * Add a shielded spend (consumes a previously received note).
     *
     * @param extsk        169-byte ZIP-32 Extended Spending Key.
     * @param recipient    43-byte payment address of the note being spent.
     * @param value        Note value in satoshis.
     * @param rcm          32-byte note randomness (rcm from wallet DB).
     * @param merkle_path  1065-byte incremental Merkle witness path.
     *
     * @return true on success; false if the Rust builder rejects the spend.
     */
    bool AddSaplingSpend(const sapling::SaplingExtendedSpendingKey& extsk,
                         const std::array<uint8_t, 43>& recipient,
                         uint64_t value,
                         const std::array<uint8_t, 32>& rcm,
                         const std::array<uint8_t, 1065>& merkle_path);

    /**
     * Add a shielded output (creates a new note for the recipient).
     *
     * @param ovk    32-byte Outgoing Viewing Key (for sender-side recovery).
     * @param to     43-byte payment address of the recipient.
     * @param value  Value in satoshis.
     * @param memo   Optional memo (up to 512 bytes; zero-padded to 512).
     *
     * @return true on success; false if the Rust builder rejects the output.
     */
    bool AddSaplingOutput(const std::array<uint8_t, 32>& ovk,
                          const std::array<uint8_t, 43>& to,
                          uint64_t value,
                          const std::vector<uint8_t>& memo = {});

    /**
     * Add a shielded output with no OVK (privacy-preserving for external recipients).
     *
     * The sender will NOT be able to decrypt this output's outCiphertext after
     * sending, which prevents an FVK compromise from revealing recipient details.
     * Use this for all non-change outputs in z-to-z transactions.
     *
     * @param to     43-byte payment address of the recipient.
     * @param value  Value in satoshis.
     * @param memo   Optional memo (up to 512 bytes; zero-padded to 512).
     *
     * @return true on success; false if the Rust builder rejects the output.
     */
    bool AddSaplingOutputNoOvk(const std::array<uint8_t, 43>& to,
                               uint64_t value,
                               const std::vector<uint8_t>& memo = {});

    /**
     * Build the complete signed Sapling transaction.
     *
     * Steps:
     *   1. build_bundle() generates Groth16 proofs (slow).
     *   2. Assembles CMutableTransaction with transparent ins/outs.
     *   3. Computes Sapling sighash (ComputeSaplingSighash).
     *   4. apply_bundle_signatures() adds spend-auth + binding signatures.
     *   5. Extracts spend/output descriptions into SaplingTxPayload.
     *   6. SetTxPayload into vExtraPayload.
     *
     * Returns std::nullopt if:
     *   - Sapling is not active at nHeight
     *   - No shielded actions were added
     *   - Rust builder fails (proof generation or signing error)
     *
     * @param error  If non-null, receives a human-readable error on failure.
     */
    std::optional<CMutableTransaction> Build(std::string* error = nullptr);

private:
    // Pimpl: hides rust::Box<::sapling::Builder> from this header.
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

#endif // KERRIGAN_SAPLING_TRANSACTION_BUILDER_H
