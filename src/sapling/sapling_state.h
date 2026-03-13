// Copyright (c) 2024 The Kerrigan developers
// Distributed under the MIT software license.

#ifndef KERRIGAN_SAPLING_STATE_H
#define KERRIGAN_SAPLING_STATE_H

#include <consensus/amount.h>
#include <dbwrapper.h>
#include <sync.h>
#include <uint256.h>

#include <map>
#include <set>
#include <vector>

class CBlock;
class CBlockIndex;
class CCoinsViewCache;

namespace Consensus {
struct Params;
} // namespace Consensus

namespace sapling {

/**
 * Sapling consensus state: nullifier set + commitment tree roots.
 *
 * Uses its own LevelDB directory (sapling/) separate from chainstate.
 * Follows the EvoDB pattern: per-block atomic writes, undo on disconnect.
 *
 * LevelDB key structure:
 *   'N' + uint256 nullifier  -> int32_t height  (nullifier spend set)
 *   'Z' + int32_t height     -> uint256 root    (commitment tree root per block)
 *   'B'                      -> uint256 hash    (best block hash)
 *   'V'                      -> int64_t pool    (cumulative Sapling value pool, ZIP-209)
 */
class CSaplingState
{
public:
    // LevelDB key prefixes (public for key wrapper structs)
    static constexpr uint8_t DB_NULLIFIER  = 'N';
    static constexpr uint8_t DB_TREE_ROOT  = 'Z';
    static constexpr uint8_t DB_TREE_DATA  = 'T';  // serialized frontier per height
    static constexpr uint8_t DB_BEST_BLOCK = 'B';
    static constexpr uint8_t DB_VALUE_POOL = 'V';  // cumulative Sapling value pool (ZIP-209)

private:
    mutable Mutex cs;
    std::unique_ptr<CDBWrapper> db;

    // Reverse index: anchor value -> set of block heights, for O(1) IsValidAnchor lookup.
    // Multiple heights per root because carry-forward blocks reuse the same root (#667).
    // Populated by ProcessBlock and cleared by UndoBlock.
    // Loaded from DB on construction via RebuildAnchorIndex().
    std::map<uint256, std::set<int>> m_anchor_heights GUARDED_BY(cs);

    // Deferred commit: ProcessBlock builds the batch, CommitBlock writes it.
    std::unique_ptr<CDBBatch> m_pendingBatch GUARDED_BY(cs);
    uint256 m_pendingTreeRoot GUARDED_BY(cs);
    int m_pendingHeight GUARDED_BY(cs){-1};

    // Cached height of the most recent block that stored frontier data.
    // Avoids O(N) backward chain walk for carry-forward (#545).
    int m_lastFrontierHeight GUARDED_BY(cs){-1};

    // ZIP-209: cumulative Sapling value pool balance.
    // Tracks total value in the shielded pool across the chain.
    // valueBalance > 0 means value leaving the pool (z->t), so we subtract.
    // valueBalance < 0 means value entering the pool (t->z), so we add.
    // Reject any block that would make this go negative.
    CAmount m_nSaplingValuePool GUARDED_BY(cs){0};
    CAmount m_pendingValuePoolDelta GUARDED_BY(cs){0};

    /**
     * Rebuild the in-memory anchor index by scanning all stored tree roots.
     * Called once during construction.
     */
    void RebuildAnchorIndex() EXCLUSIVE_LOCKS_REQUIRED(cs);

public:
    CSaplingState() = delete;
    CSaplingState(const CSaplingState&) = delete;
    CSaplingState& operator=(const CSaplingState&) = delete;

    explicit CSaplingState(const fs::path& db_path, size_t nCacheSize, bool fMemory = false, bool fWipe = false);
    ~CSaplingState();

    bool HasNullifier(const uint256& nullifier) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Check a set of nullifiers against both the DB and each other.
     * Returns false and populates bad_nf if any duplicate is found.
     */
    bool CheckNullifiers(const std::vector<uint256>& nullifiers, uint256& bad_nf) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    bool AddNullifiers(const std::vector<uint256>& nullifiers, int nHeight) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Remove nullifiers that were added at the given block height.
     * Verifies each nullifier's stored height matches before erasing.
     */
    bool RemoveNullifiers(const std::vector<uint256>& nullifiers, int nHeight) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    bool WriteTreeRoot(int nHeight, const uint256& root) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    bool GetTreeRoot(int nHeight, uint256& root) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    bool EraseTreeRoot(int nHeight) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Get the serialized commitment tree frontier at a given block height.
     * Returns false if no data is stored for that height.
     */
    bool GetFrontierData(int nHeight, std::vector<uint8_t>& data) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Check if an anchor (tree root) is valid, matches any historical root.
     */
    bool IsValidAnchor(const uint256& anchor) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    bool VerifyBestBlock(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Get the DB's stored best block hash (for crash-recovery tolerance).
     */
    uint256 GetBestBlock() const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Get the current cumulative Sapling value pool balance (ZIP-209).
     */
    CAmount GetValuePool() const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Get the height of the highest block committed to SaplingDB.
     * Returns -1 if no blocks have been committed.
     */
    int GetBestBlockHeight() const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Process all Sapling transactions in a block.
     *
     * Called from ProcessSpecialTxsInBlock (before UTXO updates).
     *  1. Extract nullifiers from all Sapling txs
     *  2. Check for double-spends (against DB + within block)
     *  3. Build DB batch (nullifiers, tree root, frontier, best block)
     *
     * When fJustCheck=false, the batch is held in m_pendingBatch and must
     * be committed by calling CommitBlock() after all ConnectBlock checks
     * pass. This avoids persisting state that must be unwound if later
     * validation (e.g. masternode payments) fails.
     *
     * @param fJustCheck  If true, validate only; no batch is built
     * @return true if all Sapling txs are valid
     */
    bool ProcessBlock(const CBlock& block, const CBlockIndex* pindex,
                      const Consensus::Params& params, bool fJustCheck) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Commit the pending Sapling state batch built by ProcessBlock.
     *
     * Called from ConnectBlock after all consensus checks pass.
     * No-op if no pending batch exists (e.g. block had no Sapling txs,
     * or ProcessBlock was called with fJustCheck=true).
     *
     * @return true on success
     */
    bool CommitBlock() EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Discard the pending batch without writing to DB.
     * Called when ConnectBlock fails after ProcessBlock to prevent
     * a stale batch from lingering.
     */
    void DiscardPendingBatch() EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * Undo Sapling state changes for a disconnected block.
     *
     * Called from UndoSpecialTxsInBlock (before UTXO undo).
     *  1. Remove nullifiers added by this block's Sapling txs
     *  2. Erase tree root for this height
     */
    bool UndoBlock(const CBlock& block, const CBlockIndex* pindex,
                   const Consensus::Params& params) EXCLUSIVE_LOCKS_REQUIRED(!cs);
};

} // namespace sapling

#endif // KERRIGAN_SAPLING_STATE_H
