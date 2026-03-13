// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KERRIGAN_HMP_NEGATIVE_PROOF_H
#define KERRIGAN_HMP_NEGATIVE_PROOF_H

#include <cstdint>
#include <vector>

class CBLSPublicKey;
class CHMPPrivilegeTracker;

/**
 * Evaluate Elder absence and mannequin presence in a block's seal.
 * Detects attacker chains missing known Elders or filled with unknown signers (PRD SS4.7.4).
 * @return multiplier in basis points (10000 = neutral, >10000 = bonus, <10000 = penalty)
 */
uint64_t EvaluateNegativeProof(const std::vector<CBLSPublicKey>& signerPubKeys,
                                const std::vector<uint8_t>& signerAlgos,
                                int blockAlgo,
                                const CHMPPrivilegeTracker* privilege);

#endif // KERRIGAN_HMP_NEGATIVE_PROOF_H
