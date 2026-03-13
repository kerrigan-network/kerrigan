// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hmp/negative_proof.h>

#include <bls/bls.h>
#include <hmp/chain_weight.h>
#include <hmp/privilege.h>

#include <algorithm>
#include <set>

uint64_t EvaluateNegativeProof(const std::vector<CBLSPublicKey>& signerPubKeys,
                                const std::vector<uint8_t>& signerAlgos,
                                int blockAlgo,
                                const CHMPPrivilegeTracker* privilege)
{
    if (!privilege) return 10000; // no penalty

    auto elders = privilege->GetElderSet(blockAlgo);
    if (elders.empty()) return 10000; // no Elders to check against

    size_t elderCount = elders.size();

    int requiredPct = GetRequiredAgreement(static_cast<int>(elderCount));
    if (requiredPct == 0) return 10000; // pure PoW mode (0 Elders)

    // Full penalty ladder for all Elder counts.

    // Build privileged set across all algos for mannequin detection
    std::set<CBLSPublicKey> allPrivileged;
    for (int a = 0; a < NUM_ALGOS; a++) {
        auto privSet = privilege->GetPrivilegedSet(a);
        allPrivileged.insert(privSet.begin(), privSet.end());
    }

    // Same-algo signers only.
    size_t present = 0;
    for (const auto& elder : elders) {
        for (size_t i = 0; i < signerPubKeys.size(); i++) {
            if (signerPubKeys[i] == elder &&
                i < signerAlgos.size() &&
                signerAlgos[i] == static_cast<uint8_t>(blockAlgo)) {
                present++;
                break;
            }
        }
    }

    // Mannequin detection (PRD SS4.7.4): count unknown signers
    // A signer not in any privilege set is a "mannequin" (a stranger nobody recognizes)
    size_t unknownSigners = 0;
    for (const auto& signer : signerPubKeys) {
        if (!allPrivileged.count(signer)) {
            unknownSigners++;
        }
    }

    // Integer bps to avoid float non-determinism.
    uint64_t presentBps = (static_cast<uint64_t>(present) * 10000) / static_cast<uint64_t>(elders.size());
    uint64_t requiredBps = static_cast<uint64_t>(requiredPct) * 100;

    uint64_t unknownBps = 0;
    if (!signerPubKeys.empty()) {
        unknownBps = (static_cast<uint64_t>(unknownSigners) * 10000) / static_cast<uint64_t>(signerPubKeys.size());
    }

    // Mannequin penalty: if majority of signers are unknown (>50%), heavy penalty
    // A room full of strangers is as suspicious as a room missing known faces
    if (unknownBps > 5000) {
        return 1000; // 0.1x severe penalty
    }

    // If enough Elders present, check mannequin ratio for lighter penalty
    if (requiredBps == 0 || presentBps >= requiredBps) {
        if (unknownBps > 3000 && elderCount >= 4) {
            uint64_t mannequinPenalty = 10000 - unknownBps;
            return std::max(mannequinPenalty, uint64_t{5000});
        }
        return 10000; // no penalty
    }

    // Proportional penalty ladder:
    // presentBps < 5000 (under half Elders)  -> 0.1x severe penalty
    // presentBps 5000..requiredBps           -> scale 5000..10000 bps
    if (presentBps < 5000) {
        return 1000; // 0.1x penalty (severe, truly absent)
    }

    // Linear interpolation: 5000 bps present -> 5000 weight, requiredBps -> 10000
    uint64_t range = requiredBps - 5000;
    if (range == 0) return 10000; // shouldn't happen but guard
    uint64_t above = presentBps - 5000;
    uint64_t penalty = 5000 + (above * 5000) / range;
    return std::min(penalty, uint64_t{10000});
}
