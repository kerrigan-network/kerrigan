// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hmp/chain_weight.h>

#include <bls/bls.h>
#include <logging.h>
#include <primitives/block.h>
#include <hmp/privilege.h>

#include <algorithm>
#include <set>

// PRD v3 Section 7.2: Elder agreement threshold table (per-algo Elder count).
// 0-1 Elders fall back to pure PoW; 2+ Elders require agreement,
// relaxing from 100% toward supermajority as the set grows.
int GetRequiredAgreement(int totalElders)
{
    if (totalElders <= 1) return 0;   // 0-1 Elders: pure PoW, no HMP
    if (totalElders <= 2) return 100; // 2 Elders: require both present
    if (totalElders == 3) return 66;  // 2 of 3 (floor so ceil(3*66/100)=2)
    if (totalElders <= 5) return 75;  // 3 of 4, 4 of 5
    return 80; // 6+: supermajority
}

uint64_t ComputeSealMultiplier(const std::vector<CBLSPublicKey>& signerPubKeys,
                                const std::vector<uint8_t>& signerAlgos,
                                int blockAlgo,
                                const CHMPPrivilegeTracker* privilege)
{
    if (!privilege || signerPubKeys.empty()) {
        return 10000;
    }

    if (signerPubKeys.size() != signerAlgos.size()) {
        LogPrintf("HMP: signers/algos size mismatch (%zu vs %zu)\n",
                  signerPubKeys.size(), signerAlgos.size());
        return 10000; // neutral weight
    }

    size_t totalElders = 0;
    for (int a = 0; a < NUM_ALGOS; a++) {
        totalElders += privilege->GetElderSet(a).size();
    }

    if (totalElders == 0) {
        return 10000;
    }

    // Pure PoW mode when 0-1 Elders per algo (whitepaper Section 6.6).
    auto elderSet = privilege->GetElderSet(blockAlgo);
    size_t elderCount = elderSet.size();
    if (elderCount <= 1) {
        return 10000;
    }

    // Cross-algo signers excluded.
    std::set<CBLSPublicKey> elderLookup(elderSet.begin(), elderSet.end());
    size_t eldersPresent = 0;
    for (size_t i = 0; i < signerPubKeys.size(); i++) {
        if (elderLookup.count(signerPubKeys[i]) && signerAlgos[i] == static_cast<uint8_t>(blockAlgo)) {
            eldersPresent++;
        }
    }

    // Determine required agreement threshold using per-algo Elder count.
    // GetRequiredAgreement was being called with cross-algo totalElders but applied
    // to single-algo elderCount, producing an inconsistent threshold.
    int requiredPct = GetRequiredAgreement(static_cast<int>(elderCount));
    // requiredCount = ceil(elderCount * requiredPct / 100)
    size_t requiredCount = (elderCount * static_cast<size_t>(requiredPct) + 99) / 100;
    if (requiredCount == 0) requiredCount = 1; // at least 1 if we have Elders

    // Tier multipliers: ELDER=5x, VETERAN=4x, JOURNEYMAN=3x, APPRENTICE=2x, NOVICE=1x

    uint64_t baseMult;

    if (eldersPresent >= elderCount) {
        // Ratio of Elders present to total Elders for the algo.
        baseMult = 15000 + (static_cast<uint64_t>(eldersPresent) * 3000) / elderCount;
        baseMult = std::min(baseMult, uint64_t{18000});
    } else if (eldersPresent >= requiredCount) {
        // Interpolate 12000..15000 based on how far above threshold
        // ratio: (present - required) / (total - required), range 0..1
        size_t above = eldersPresent - requiredCount;
        size_t range = elderCount - requiredCount;
        if (range == 0) {
            baseMult = 15000; // threshold == total, so meeting threshold is full
        } else {
            baseMult = 12000 + (above * 3000) / range;
        }
    } else {
        baseMult = 10000;
    }

    // Cross-algorithm bonus (PRD Section 4.8)
    // Only ELDER-tier signers count. +500 bps per additional algo beyond the
    // block's own algo, capped at +1500 bps (all 4 algos represented).
    std::set<uint8_t> elderAlgos;
    for (size_t i = 0; i < signerPubKeys.size(); i++) {
        if (privilege->GetTier(signerPubKeys[i], signerAlgos[i]) >= HMPPrivilegeTier::ELDER) {
            elderAlgos.insert(signerAlgos[i]);
        }
    }
    elderAlgos.erase(static_cast<uint8_t>(blockAlgo));
    uint64_t crossAlgoBonus = std::min<uint64_t>(elderAlgos.size() * 500, 1500);

    return baseMult + crossAlgoBonus;
}
