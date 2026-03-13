// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2014-2025 The DigiByte Core developers (multi-algo, Hivemind)
// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KERRIGAN_POW_H
#define KERRIGAN_POW_H

#include <consensus/params.h>

#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class uint256;

/** Get the next required work (difficulty) for a given algorithm */
unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&, int algo);

/** Hivemind difficulty adjustment for per-algo retargeting */
unsigned int Hivemind(const CBlockIndex* pindexLast, const Consensus::Params& params, int algo);

/** Walk chain backward to find the last block mined by the given algorithm.
 *  maxDepth limits the search to avoid walking the entire chain (default 240). */
const CBlockIndex* GetLastBlockIndexForAlgo(const CBlockIndex* pindex, const Consensus::Params& params, int algo, int maxDepth = 240);

/** Get the per-algorithm PoW limit (minimum difficulty / maximum target floor) */
unsigned int PowLimitForAlgo(const Consensus::Params& params, int algo);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits.
 *  When algo is valid (0-3), checks against params.powLimitAlgo[algo] instead of the
 *  global powLimit. Default algo=-1 uses the global powLimit for backward compatibility. */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&, int algo = -1);

#endif // KERRIGAN_POW_H
