// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KERRIGAN_HMP_PRIVILEGE_H
#define KERRIGAN_HMP_PRIVILEGE_H

#include <bls/bls.h>
#include <primitives/block.h>
#include <sync.h>
#include <uint256.h>

#include <deque>
#include <map>
#include <memory>
#include <set>
#include <vector>

class CBlockIndex;

namespace Consensus { struct Params; }

/** Privilege tiers for Hivemind Protocol participants */
enum class HMPPrivilegeTier {
    UNKNOWN,  // in warmup or no history
    NEW,      // completed warmup, participating, not yet Elder
    ELDER,    // participated in sealing + solved >= 1 block within window
};

/** Per-miner privilege record within the sliding window */
struct CPrivilegeRecord {
    int blocks_solved{0};          // number of blocks solved in window
    int seal_participations{0};    // seal signatures contributed in window
    int first_seen_height{-1};     // height where first seen
    int last_active_height{-1};    // most recent activity

    bool operator==(const CPrivilegeRecord& o) const {
        return blocks_solved == o.blocks_solved &&
               seal_participations == o.seal_participations &&
               first_seen_height == o.first_seen_height &&
               last_active_height == o.last_active_height;
    }
};

/** Entry in the sliding window recording one block's HMP data */
struct CHMPWindowEntry {
    int height;
    int algo;
    CBLSPublicKey minerPubKey;
    std::vector<CBLSPublicKey> sealSigners; // who signed the seal in this block
    std::vector<uint8_t> signerAlgos;       // each signer's declared algo
};

/** Lightweight entry for extended lookback (dominance catch). Tracks only solver identity. */
struct CHMPExtendedEntry {
    int height;
    int algo;
    CBLSPublicKey minerPubKey;
};

/**
 * CHMPPrivilegeTracker -- 100-block sliding window tracking per-algo privilege.
 *
 * Fed by ConnectBlock/DisconnectBlock. Maintains per-algo maps of
 * CBLSPublicKey -> CPrivilegeRecord for tier classification.
 *
 * Thread safety: all public methods acquire cs internally.
 */
class CHMPPrivilegeTracker
{
private:
    mutable RecursiveMutex cs;

    int m_windowSize;   // from consensus params (default 100)
    int m_warmupBlocks; // from consensus params (default 10)
    int m_minBlocksSolved; // from consensus params (default 1)
    int m_dominanceCatchFloor; // min unique pools per algo (default 6)
    int m_extendedWindowSize;  // max extended lookback (default 1000)

    // Sliding window of recent blocks (privilege computation)
    std::deque<CHMPWindowEntry> m_window GUARDED_BY(cs);

    // Extended window for dominance catch (lightweight, up to 1000 blocks)
    std::deque<CHMPExtendedEntry> m_extendedWindow GUARDED_BY(cs);

    // Per-algo privilege records: algo_id -> (pubkey -> record)
    std::map<CBLSPublicKey, CPrivilegeRecord> m_records[NUM_ALGOS] GUARDED_BY(cs);

    void RebuildFromWindow() EXCLUSIVE_LOCKS_REQUIRED(cs);

    /** Get the last N unique block solvers per algo from the extended window.
     *  Used for dominance catch: when normal Elder set is below floor. */
    std::vector<CBLSPublicKey> GetExtendedSolvers(int algo, int count) const EXCLUSIVE_LOCKS_REQUIRED(cs);

public:
    CHMPPrivilegeTracker() : m_windowSize(100), m_warmupBlocks(10), m_minBlocksSolved(1),
                             m_dominanceCatchFloor(6), m_extendedWindowSize(1000) {}

    explicit CHMPPrivilegeTracker(const Consensus::Params& params);

    /** Called when a new block is connected. Updates privilege records.
     *  signerAlgos: each signer's declared algo. Seal participation is recorded
     *  under the signer's own algo, not the block algo. */
    void BlockConnected(int height, int algo, const CBLSPublicKey& minerPubKey,
                        const std::vector<CBLSPublicKey>& sealSigners,
                        const std::vector<uint8_t>& signerAlgos = {});

    /** Called when a block is disconnected (reorg). Pops from window. */
    void BlockDisconnected(int height);

    /** Get the privilege tier for a pubkey on a given algo */
    HMPPrivilegeTier GetTier(const CBLSPublicKey& pubkey, int algo) const;

    /** Get effective weight with 25% dominance cap. Returns weight in basis points (0-2500). */
    uint32_t GetEffectiveWeight(const CBLSPublicKey& pubkey, int algo) const;

    /** Get all Elder pubkeys for a given algo */
    std::vector<CBLSPublicKey> GetElderSet(int algo) const;

    /** Get all pubkeys with tier >= NEW for a given algo */
    std::vector<CBLSPublicKey> GetPrivilegedSet(int algo) const;

    /** Get total number of privileged participants across all algos (unique pubkeys) */
    size_t GetTotalPrivilegedCount() const;

    /** Get the privilege record for a pubkey on a given algo (for RPC) */
    CPrivilegeRecord GetRecord(const CBLSPublicKey& pubkey, int algo) const;

    int GetTipHeight() const;

    /** Clear all privilege data (windows + records). Called when SPORK_25_HMP_ENABLED
     *  transitions from disabled to enabled, to prevent stale pre-toggle data from
     *  creating inaccurate Elder windows. */
    void Clear();
};

extern std::unique_ptr<CHMPPrivilegeTracker> g_hmp_privilege;

#endif // KERRIGAN_HMP_PRIVILEGE_H
