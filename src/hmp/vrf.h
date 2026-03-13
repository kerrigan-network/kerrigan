// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KERRIGAN_HMP_VRF_H
#define KERRIGAN_HMP_VRF_H

#include <bls/bls.h>
#include <uint256.h>

/**
 * BLS-VRF committee selection for Hivemind Protocol (Layer 4).
 *
 * VRF output = BLS::Sign(sk, H("HMP-VRF" || blockHash))
 * Selection: H(VRF_output) mod 1000 < effective_threshold
 * Threshold weighted by tier: Elder 3×, New 1×
 *
 * The VRF is deterministic: all nodes can verify who was selected
 * for any given block without knowing the signer's secret key.
 */

/** Base selection threshold (per mille). Default 200 = 20% base selection rate. */
static constexpr int HMP_VRF_BASE_THRESHOLD = 200;

/** Tier multipliers for VRF selection probability */
static constexpr int HMP_VRF_ELDER_MULTIPLIER = 3;
static constexpr int HMP_VRF_NEW_MULTIPLIER = 1;

/** Compute the domain-separated VRF input hash.
 *  @param blockHash     hash of the block being sealed
 *  @param prevSealHash  hash of the previous block's assembled seal (or previous
 *                       block hash if no seal exists). Mixing in previous-seal
 *                       entropy makes VRF selection resistant to nonce grinding.
 */
uint256 ComputeVRFInput(const uint256& blockHash, const uint256& prevSealHash);

/** Compute VRF proof (BLS signature over domain-separated input) */
CBLSSignature ComputeVRF(const CBLSSecretKey& sk, const uint256& blockHash, const uint256& prevSealHash);

/** Verify a VRF proof against a public key and block hash */
bool VerifyVRF(const CBLSPublicKey& pk, const uint256& blockHash, const uint256& prevSealHash, const CBLSSignature& vrfProof);

/** Derive the VRF output hash (deterministic, used for committee selection) */
uint256 VRFOutputHash(const CBLSSignature& vrfProof);

/**
 * Check if a VRF output selects this signer for committee duty.
 *
 * @param vrfHash        the VRF output hash (from VRFOutputHash)
 * @param tierMultiplier weight multiplier (Elder=3, New=1)
 * @param baseThreshold  base selection threshold (per mille, default 200)
 * @return true if selected for this round
 */
bool IsVRFSelected(const uint256& vrfHash, int tierMultiplier, int baseThreshold = HMP_VRF_BASE_THRESHOLD);

/**
 * Get the tier multiplier for VRF selection.
 * Elder = 3x (60% selection rate), New = 1x (20% selection rate)
 */
int GetVRFTierMultiplier(int tier);

#endif // KERRIGAN_HMP_VRF_H
