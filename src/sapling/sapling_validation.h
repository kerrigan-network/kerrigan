// Copyright (c) 2024 The Kerrigan developers
// Distributed under the MIT software license.

#ifndef KERRIGAN_SAPLING_VALIDATION_H
#define KERRIGAN_SAPLING_VALIDATION_H

#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <sapling/sapling_tx_payload.h>

namespace sapling {

/**
 * Check Sapling-specific consensus rules for a transaction.
 *
 * Validates payload structure, activation gating, bounds, AND
 * Groth16 proofs + binding/spend-auth signatures via the Rust FFI.
 */
bool CheckSaplingTx(const CTransaction& tx,
                    const Consensus::Params& consensusParams,
                    int nHeight,
                    TxValidationState& state,
                    bool check_sigs = true);

/**
 * Verify all Sapling Groth16 proofs and signatures in a transaction.
 *
 * Creates a Sapling Verifier via Rust FFI, checks each spend and output
 * proof, and performs the final binding signature check.
 *
 * Requires Sapling parameters to be loaded (init_sapling_params called).
 * Returns false with state set if params not loaded or any proof is invalid.
 */
bool VerifySaplingProofs(const CTransaction& tx,
                         const SaplingTxPayload& payload,
                         TxValidationState& state);

/**
 * Compute the sighash for a Sapling transaction.
 *
 * Hashes all transaction data (transparent + shielded) EXCEPT the
 * spend authorization signatures and binding signature. This is the
 * value signed by those signatures.
 */
uint256 ComputeSaplingSighash(const CTransaction& tx,
                              const SaplingTxPayload& payload);

inline bool IsSaplingActive(const Consensus::Params& params, int nHeight) {
    return nHeight >= params.SaplingHeight;
}

inline unsigned int GetMaxExtraPayloadSize(const Consensus::Params& params, int nHeight) {
    if (IsSaplingActive(params, nHeight)) {
        return MAX_SAPLING_TX_EXTRA_PAYLOAD;
    }
    return MAX_TX_EXTRA_PAYLOAD;
}

} // namespace sapling

#endif // KERRIGAN_SAPLING_VALIDATION_H
