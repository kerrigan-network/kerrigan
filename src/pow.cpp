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

#include <algorithm>
#include <vector>

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
    const int nNextHeight = pindexLast->nHeight + 1; // height of the block being mined
    const bool fDaaRetargetFix = params.IsDaaRetargetFixActive(nNextHeight);

    const int nAveragingInterval = 10;
    const int64_t nMaxAdjustDown = 16; // percent
    // Pre-fix the ease cap (+8%) is tighter than the tighten cap (-16%), so under
    // rising/switching hashrate difficulty rides low and blocks run fast. The fix
    // makes the clamp symmetric at +-16%.
    const int64_t nMaxAdjustUp = fDaaRetargetFix ? 16 : 8; // percent

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
        const unsigned int nResetLimit = EffectivePowLimitForAlgo(params, algo, nNextHeight);
        if (!fDaaRetargetFix) {
            return nResetLimit;
        }
        // Bounded reset: ease the last difficulty by 4x per missed round (one
        // round = NUM_ALGOS blocks the stalled algo did not produce) rather than
        // jumping straight to the floor, so a long stall does not seed an
        // instant-block burst when the algo resumes. Capped at the floor, so it
        // can never ease further than the legacy reset.
        arith_uint256 bnEased;
        bnEased.SetCompact(pindexPrevAlgo->nBits);
        arith_uint256 bnLimit;
        bnLimit.SetCompact(nResetLimit);
        const int nSteps = 1 + (algoGap - nGapThreshold) / NUM_ALGOS;
        for (int i = 0; i < nSteps && bnEased < bnLimit; i++) {
            // If another 4x would reach or pass the floor, settle at the floor.
            // This also stops bnEased <<= 2 from wrapping past 256 bits when the
            // floor target is itself near 2^254 (which would emit nBits 0).
            if (bnEased > (bnLimit >> 2)) {
                bnEased = bnLimit;
                break;
            }
            bnEased <<= 2; // 4x easier per step
        }
        if (bnEased > bnLimit) bnEased = bnLimit;
        return bnEased.GetCompact();
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

// Per-algo LWMA-1 difficulty retarget (zawy12), v1.3.1 anti-hop DAA.
//
// Each algo retargets on its OWN last-N same-algo blocks, fully decoupled from the
// other algos' timing. This removes the two defects that let profit-hopping
// multipools stall the chain under the legacy Hivemind DAA:
//   (1) the 40-block ALL-ALGO averaging window -- a burst-then-abandon on one algo
//       contaminated the shared window so the DAA read "fast" and tightened even
//       while the chain was objectively slow; and
//   (2) the per-algo "rebalance" count term -- pinned a +12.5%/block ratchet on
//       whichever algo was left carrying the chain (sole survivor).
// Both are dropped here: LWMA measures each algo against its own spacing.
//
// Validated by a byte-exact port of the legacy DAA plus a stochastic multi-algo
// simulation across steady / burst-then-abandon / continuous-hop / sole-survivor /
// legit-hashrate-step / timestamp-attack scenarios. Config (N=60, T=480s, solvetime
// clamp [-5T,+6T], weighted-sum floor k/20) is the simulated optimum.
unsigned int LwmaPerAlgo(const CBlockIndex* pindexLast, const Consensus::Params& params, int algo)
{
    const int nNextHeight = pindexLast->nHeight + 1;
    const int64_t T = (int64_t)params.nPowTargetSpacing * NUM_ALGOS; // per-algo spacing = 480s
    const int N = 60;                                                 // averaging window (same-algo blocks)

    // Collect up to N+1 most-recent same-algo blocks (newest first). Bounded walk so a
    // very sparse algo cannot force a full-chain scan.
    std::vector<const CBlockIndex*> a;
    a.reserve(N + 1);
    const int maxDepth = (N + 1) * NUM_ALGOS * 8;
    int depth = 0;
    for (const CBlockIndex* p = pindexLast;
         p != nullptr && (int)a.size() < N + 1 && depth < maxDepth;
         p = p->pprev, ++depth) {
        if (p->GetAlgo() == algo) a.push_back(p);
    }

    // Bootstrap: need at least two same-algo blocks for one solvetime. On the v1.3.1
    // fork this never fires (pre-fork history holds > N same-algo blocks); it only
    // matters on a fresh chain.
    if (a.size() < 2) {
        return EffectivePowLimitForAlgo(params, algo, nNextHeight);
    }

    // Progressive window: use all available same-algo history, up to N.
    const int Neff = std::min<int>(N, (int)a.size() - 1);
    const int64_t k = (int64_t)Neff * (Neff + 1) / 2 * T;

    // a[0] = newest ... a[Neff] = oldest of the window. Iterate oldest->newest so the
    // linear weight i (1..Neff) gives the most recent block the highest weight.
    int64_t weightedSolvetimes = 0;
    arith_uint256 sumTarget;
    for (int i = 1; i <= Neff; ++i) {
        const CBlockIndex* cur  = a[Neff - i];       // i-th oldest block in the window
        const CBlockIndex* prev = a[Neff - i + 1];   // its same-algo predecessor
        int64_t st = (int64_t)cur->GetBlockTime() - (int64_t)prev->GetBlockTime();
        if (st > 6 * T)  st = 6 * T;                  // cap high outliers (timestamp attack)
        if (st < -5 * T) st = -5 * T;                 // bound out-of-order timestamps
        weightedSolvetimes += st * i;
        arith_uint256 tcur;
        tcur.SetCompact(cur->nBits);
        sumTarget += tcur;
    }

    // Anti-timewarp: never let the weighted solvetime collapse (would spike difficulty).
    if (weightedSolvetimes < k / 20) weightedSolvetimes = k / 20;

    // next_target = avg(target over window) * weightedSolvetimes / k.
    // Divide before the multiply to stay within 256 bits for the easiest algos; the
    // dropped low bits are far below compact-nBits precision (checked vs the oracle).
    arith_uint256 bnNew = sumTarget;
    bnNew /= (uint32_t)Neff;                 // average target over the window
    bnNew /= (uint32_t)k;                    // pre-divide by k (overflow-safe)
    bnNew *= (uint32_t)weightedSolvetimes;   // apply weighted solvetimes

    // Cap at the per-algo powLimit, then the tighter hardware floor (post nDiffFloorHeight).
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimitAlgo[algo]);
    if (bnNew > bnPowLimit) bnNew = bnPowLimit;
    if (params.nDiffFloorHeight > 0 && nNextHeight >= params.nDiffFloorHeight &&
        algo >= 0 && algo < NUM_ALGOS) {
        const arith_uint256 bnFloor = UintToArith256(params.powLimitFloorAlgo[algo]);
        if (bnNew > bnFloor) bnNew = bnFloor;
    }
    if (bnNew == arith_uint256(0)) bnNew = UintToArith256(params.powLimitFloorAlgo[algo]);
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

    // v1.3.1 anti-hop hard fork: per-algo LWMA replaces the Hivemind all-algo window
    // + rebalance term. Bit-identical to Hivemind below the activation height.
    if (params.IsDaaLwmaActive(pindexLast->nHeight + 1))
        return LwmaPerAlgo(pindexLast, params, algo);

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
