// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2014-2025 The DigiByte Core developers (Hivemind)
// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

static inline unsigned int PowLimit(const Consensus::Params& params)
{
    return UintToArith256(params.powLimit).GetCompact();
}

unsigned int PowLimitForAlgo(const Consensus::Params& params, int algo)
{
    if (algo >= 0 && algo < NUM_ALGOS) {
        return UintToArith256(params.powLimitAlgo[algo]).GetCompact();
    }
    return PowLimit(params);
}

// Return the effective powLimit for an algo, applying the tighter difficulty
// floor when the chain has passed the activation height (#851).
static unsigned int EffectivePowLimitForAlgo(const Consensus::Params& params, int algo, int nHeight)
{
    if (params.nDiffFloorHeight > 0 && nHeight >= params.nDiffFloorHeight &&
        algo >= 0 && algo < NUM_ALGOS) {
        return UintToArith256(params.powLimitFloorAlgo[algo]).GetCompact();
    }
    return PowLimitForAlgo(params, algo);
}

// Walk chain backward to find the last block mined by the given algorithm.
// maxDepth limits the search to avoid walking the entire chain on long chains
// (default 240 covers ~8 hours of blocks across all algos at 120s spacing).
const CBlockIndex* GetLastBlockIndexForAlgo(const CBlockIndex* pindex, const Consensus::Params& params, int algo, int maxDepth)
{
    int depth = 0;
    for (; pindex && depth < maxDepth; pindex = pindex->pprev, ++depth) {
        if (pindex->GetAlgo() != algo)
            continue;
        // Skip special min-difficulty testnet blocks
        if (params.fPowAllowMinDifficultyBlocks &&
            pindex->pprev &&
            pindex->nTime > pindex->pprev->nTime + params.nPowTargetSpacing * 2) {
            continue;
        }
        return pindex;
    }
    return nullptr;
}

// Hivemind per-algo DAA (DigiByte-derived). See #382 for time-warp analysis.
unsigned int Hivemind(const CBlockIndex* pindexLast, const Consensus::Params& params, int algo, int gapThresholdOverride)
{
    const int nAveragingInterval = 10;
    const int64_t nMaxAdjustDown = 16; // percent
    const int64_t nMaxAdjustUp = 8;    // percent

    // Per-algo target spacing = overall target * NUM_ALGOS
    const int64_t nAlgoTargetSpacing = params.nPowTargetSpacing * NUM_ALGOS;
    const int64_t nAveragingTargetTimespan = nAveragingInterval * nAlgoTargetSpacing;

    const int64_t nMinActualTimespan = nAveragingTargetTimespan * (100 - nMaxAdjustUp) / 100;
    const int64_t nMaxActualTimespan = nAveragingTargetTimespan * (100 + nMaxAdjustDown) / 100;

    // Go back nAveragingInterval * NUM_ALGOS blocks (covers enough blocks for any algo)
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < NUM_ALGOS * nAveragingInterval; i++) {
        pindexFirst = pindexFirst->pprev;
    }

    const int nNextHeight = pindexLast->nHeight + 1; // height of the block being mined

    const CBlockIndex* pindexPrevAlgo = GetLastBlockIndexForAlgo(pindexLast, params, algo);
    if (pindexPrevAlgo == nullptr || pindexFirst == nullptr) {
        // Not enough history, use per-algo difficulty floor calibrated to
        // minimum available hardware (prevents chain flooding at genesis)
        return EffectivePowLimitForAlgo(params, algo, nNextHeight);
    }

    // #524: If no block for this algo has been mined in a very long time,
    // the stored difficulty is stale and may be unreachable. Reset to
    // powLimit so the algo can recover.
    //
    // Pre-nDiffFloorHeight: 240 blocks (4*10*6) -- ~80 hours at 2min blocks
    // when only one algo is mining. Too slow under hashrate volatility.
    // Post-nDiffFloorHeight: 40 blocks (4*10*1) -- ~1.3 hours. Equals one
    // full averaging window (NUM_ALGOS * nAveragingInterval), the minimum
    // safe value before the DAA oscillates. See #970.
    const int nGapThreshold = (gapThresholdOverride > 0)
        ? gapThresholdOverride
        : (nNextHeight >= params.nDiffFloorHeight && params.nDiffFloorHeight > 0)
            ? NUM_ALGOS * nAveragingInterval       // 40 blocks post-activation
            : NUM_ALGOS * nAveragingInterval * 6;  // 240 blocks pre-activation
    int algoGap = pindexLast->nHeight - pindexPrevAlgo->nHeight;
    if (algoGap >= nGapThreshold) {
        return EffectivePowLimitForAlgo(params, algo, nNextHeight);
    }

    // Use medians to prevent time-warp attacks
    int64_t nActualTimespan = pindexLast->GetMedianTimePast() - pindexFirst->GetMedianTimePast();
    nActualTimespan = nAveragingTargetTimespan + (nActualTimespan - nAveragingTargetTimespan) / 4;

    if (nActualTimespan < nMinActualTimespan)
        nActualTimespan = nMinActualTimespan;
    if (nActualTimespan > nMaxActualTimespan)
        nActualTimespan = nMaxActualTimespan;

    // Global retarget
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexPrevAlgo->nBits);
    // Clamp before multiplication to prevent uint256 overflow with easy powLimits
    arith_uint256 bnOverflowGuard;
    bnOverflowGuard.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    bnOverflowGuard /= nActualTimespan;
    if (bnNew > bnOverflowGuard) bnNew = bnOverflowGuard;
    bnNew *= nActualTimespan;
    bnNew /= nAveragingTargetTimespan;

    // Per-algo retarget: if this algo's blocks are under/over-represented, adjust
    // DigiByte uses 4%. 10% is too aggressive and causes oscillation between algos.
    const int nLocalTargetAdjustment = 4; // percent (matches DigiByte V4)
    int nAdjustments = pindexPrevAlgo->nHeight + NUM_ALGOS - 1 - pindexLast->nHeight;

    // Cap iterations to prevent O(N^2) bignum work during deep reorgs.
    const int nMaxLocalAdjustments = 100;
    if (nAdjustments > nMaxLocalAdjustments) nAdjustments = nMaxLocalAdjustments;
    if (nAdjustments < -nMaxLocalAdjustments) nAdjustments = -nMaxLocalAdjustments;

    if (nAdjustments > 0) {
        for (int i = 0; i < nAdjustments; i++) {
            bnNew *= 100;
            bnNew /= (100 + nLocalTargetAdjustment);
        }
    } else if (nAdjustments < 0) {
        for (int i = 0; i < -nAdjustments; i++) {
            bnNew *= (100 + nLocalTargetAdjustment);
            bnNew /= 100;
            if (bnNew > UintToArith256(params.powLimitAlgo[algo])) {
                bnNew = UintToArith256(params.powLimitAlgo[algo]);
                break;
            }
        }
    }

    if (bnNew > UintToArith256(params.powLimitAlgo[algo])) {
        bnNew = UintToArith256(params.powLimitAlgo[algo]);
    }

    // Height-activated difficulty floor (#851): clamp DAA output to
    // hardware-calibrated floor after activation height.
    // Use nNextHeight (the block being mined), not tip height (#876).
    if (params.nDiffFloorHeight > 0 && nNextHeight >= params.nDiffFloorHeight &&
        algo >= 0 && algo < NUM_ALGOS) {
        const arith_uint256 bnFloor = UintToArith256(params.powLimitFloorAlgo[algo]);
        if (bnNew > bnFloor) {
            bnNew = bnFloor;
        }
    }

    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, int algo)
{
    // Genesis block: use per-algo floor
    if (pindexLast == nullptr)
        return PowLimitForAlgo(params, algo);

    if (params.fPowAllowMinDifficultyBlocks) {
        // Testnet: allow min difficulty if block is delayed
        if (pblock->nTime > pindexLast->nTime + params.nPowTargetSpacing * 2)
            return EffectivePowLimitForAlgo(params, algo, pindexLast->nHeight + 1);
    }

    if (params.fPowNoRetargeting)
        return PowLimitForAlgo(params, algo);

    return Hivemind(pindexLast, params, algo);
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params, int algo)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Use per-algo powLimit when algo is valid, otherwise fall back to global powLimit
    const uint256& limit = (algo >= 0 && algo < NUM_ALGOS) ? params.powLimitAlgo[algo] : params.powLimit;

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(limit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
