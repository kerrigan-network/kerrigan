// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KERRIGAN_HMP_PARAMS_H
#define KERRIGAN_HMP_PARAMS_H

#include <cstdint>
#include <vector>

class uint256;

/**
 * C++ wrappers for Rust Groth16 proof functions (via CXX FFI).
 *
 * The actual circuit and proving system lives in Rust (bellman + bls12_381).
 * These functions call through the CXX bridge to create and verify proofs.
 */
namespace hmp_proof {

/** Initialize Groth16 parameters (trusted setup). Call once at startup. */
bool InitParams();

/** Check if Groth16 parameters are initialized. */
bool IsInitialized();

/**
 * Create a Groth16 participation proof.
 *
 * @param sk_bytes         32 bytes of secret key material
 * @param block_hash       block being sealed
 * @param chain_state_hash hash of chain state at signing time
 * @return 192-byte proof, or empty vector on failure
 */
std::vector<uint8_t> CreateProof(const uint8_t sk_bytes[32],
                                  const uint8_t block_hash[32],
                                  const uint8_t chain_state_hash[32]);

/**
 * Verify a Groth16 participation proof.
 *
 * @param proof      serialized proof (192 bytes)
 * @param block_hash block that was sealed (public input)
 * @param commitment commitment value (public input)
 * @return true if valid
 */
bool VerifyProof(const std::vector<uint8_t>& proof,
                  const uint8_t block_hash[32],
                  const uint8_t commitment[32]);

/**
 * Compute commitment for given inputs.
 *
 * @param sk_bytes         32 bytes of secret key material
 * @param block_hash       block being sealed
 * @param chain_state_hash chain state hash
 * @param out              32-byte commitment output
 * @return true on success
 */
bool ComputeCommitment(const uint8_t sk_bytes[32],
                        const uint8_t block_hash[32],
                        const uint8_t chain_state_hash[32],
                        uint8_t out[32]);

} // namespace hmp_proof

#endif // KERRIGAN_HMP_PARAMS_H
