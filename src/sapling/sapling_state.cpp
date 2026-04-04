// Copyright (c) 2024 The Kerrigan developers
// Distributed under the MIT software license.

#include <sapling/sapling_state.h>

#include <chain.h>
#include <consensus/params.h>
#include <evo/specialtx.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <rust/bridge.h>
#include <sapling/sapling_tx_payload.h>
#include <sapling/sapling_validation.h>
#include <logging.h>
#include <limits>

#include <set>

namespace sapling {

// LevelDB key wrappers
namespace {

struct NullifierKey {
    uint8_t prefix;
    uint256 nullifier;
    explicit NullifierKey(const uint256& nf) : prefix(CSaplingState::DB_NULLIFIER), nullifier(nf) {}
    SERIALIZE_METHODS(NullifierKey, obj) { READWRITE(obj.prefix, obj.nullifier); }
};

struct TreeRootKey {
    uint8_t prefix;
    int32_t height;
    explicit TreeRootKey(int h) : prefix(CSaplingState::DB_TREE_ROOT), height(h) {}
    SERIALIZE_METHODS(TreeRootKey, obj) { READWRITE(obj.prefix, obj.height); }
};

struct TreeDataKey {
    uint8_t prefix;
    int32_t height;
    explicit TreeDataKey(int h) : prefix(CSaplingState::DB_TREE_DATA), height(h) {}
    SERIALIZE_METHODS(TreeDataKey, obj) { READWRITE(obj.prefix, obj.height); }
};

/**
 * Extract all nullifiers, note commitments, and total value balance from
 * Sapling txs in a block. Pure function, no DB access, no side effects.
 *
 * valueBalance semantics:
 *   positive = value leaving the shielded pool (z->t unshielding)
 *   negative = value entering the shielded pool (t->z shielding)
 */
bool CollectSaplingData(const CBlock& block,
                        std::vector<uint256>& nullifiers,
                        std::vector<uint256>& commitments,
                        CAmount& valueBalanceTotal)
{
    valueBalanceTotal = 0;
    for (const auto& tx : block.vtx) {
        if (tx->nType != TRANSACTION_SAPLING) continue;

        auto payloadOpt = GetTxPayload<SaplingTxPayload>(tx->vExtraPayload);
        if (!payloadOpt) {
            LogPrintf("ERROR: CollectSaplingData: failed to parse Sapling payload in tx %s\n",
                      tx->GetHash().ToString());
            return false;
        }
        const auto& payload = *payloadOpt;

        for (const auto& spend : payload.vSpendDescriptions) {
            uint256 nf;
            std::memcpy(nf.begin(), spend.nullifier.data(), 32);
            nullifiers.push_back(nf);
        }

        for (const auto& output : payload.vOutputDescriptions) {
            uint256 cmu;
            std::memcpy(cmu.begin(), output.cmu.data(), 32);
            commitments.push_back(cmu);
        }

        // Prevent signed overflow (#R9).
        if ((payload.valueBalance > 0 && valueBalanceTotal > std::numeric_limits<CAmount>::max() - payload.valueBalance) ||
            (payload.valueBalance < 0 && valueBalanceTotal < std::numeric_limits<CAmount>::min() - payload.valueBalance)) {
            LogPrintf("ERROR: CollectSaplingData: valueBalance addition overflow in tx %s\n",
                      tx->GetHash().ToString());
            return false;
        }
        valueBalanceTotal += payload.valueBalance;
        if (valueBalanceTotal < -MAX_MONEY || valueBalanceTotal > MAX_MONEY) {
            LogPrintf("ERROR: CollectSaplingData: cumulative valueBalance overflow (%lld) in tx %s\n",
                      valueBalanceTotal, tx->GetHash().ToString());
            return false;
        }
    }
    return true;
}

} // namespace

CSaplingState::CSaplingState(const fs::path& db_path, size_t nCacheSize, bool fMemory, bool fWipe)
    : db(std::make_unique<CDBWrapper>(db_path, nCacheSize, fMemory, fWipe, true))
{
    LOCK(cs);
    RebuildAnchorIndex();

    // Load cumulative Sapling value pool balance (ZIP-209)
    int64_t storedPool{0};
    if (db->Read(DB_VALUE_POOL, storedPool)) {
        m_nSaplingValuePool = storedPool;
        LogPrint(BCLog::SAPLING, "CSaplingState: loaded value pool balance: %lld\n", m_nSaplingValuePool);
    }
}

void CSaplingState::RebuildAnchorIndex()
{
    std::unique_ptr<CDBIterator> pcursor(db->NewIterator());
    pcursor->Seek(TreeRootKey(0));
    while (pcursor->Valid()) {
        std::pair<uint8_t, int32_t> key;
        if (pcursor->GetKey(key) && key.first == DB_TREE_ROOT) {
            uint256 root;
            if (pcursor->GetValue(root)) {
                int h = static_cast<int>(key.second);
                m_anchor_heights[root].insert(h);  // #667: multiple heights per root
                if (h > m_lastFrontierHeight) m_lastFrontierHeight = h;
            }
            pcursor->Next();
        } else {
            break;
        }
    }
    LogPrint(BCLog::SAPLING, "CSaplingState: loaded %u anchors into reverse index\n", m_anchor_heights.size());
}

CSaplingState::~CSaplingState() = default;

bool CSaplingState::HasNullifier(const uint256& nullifier) const
{
    LOCK(cs);
    int32_t height;
    return db->Read(NullifierKey(nullifier), height);
}

bool CSaplingState::CheckNullifiers(const std::vector<uint256>& nullifiers, uint256& bad_nf) const
{
    LOCK(cs);
    std::set<uint256> seen;
    for (const auto& nf : nullifiers) {
        if (!seen.insert(nf).second) {
            bad_nf = nf;
            return false;
        }
    }
    for (const auto& nf : nullifiers) {
        int32_t height;
        if (db->Read(NullifierKey(nf), height)) {
            bad_nf = nf;
            return false;
        }
    }
    return true;
}

bool CSaplingState::AddNullifiers(const std::vector<uint256>& nullifiers, int nHeight)
{
    LOCK(cs);
    CDBBatch batch(*db);
    int32_t h = static_cast<int32_t>(nHeight);
    for (const auto& nf : nullifiers) {
        batch.Write(NullifierKey(nf), h);
    }
    return db->WriteBatch(batch);
}

bool CSaplingState::RemoveNullifiers(const std::vector<uint256>& nullifiers, int nHeight)
{
    LOCK(cs);
    CDBBatch batch(*db);
    int32_t expectedHeight = static_cast<int32_t>(nHeight);
    for (const auto& nf : nullifiers) {
        // Verify the nullifier belongs to this height before erasing
        int32_t storedHeight;
        if (db->Read(NullifierKey(nf), storedHeight)) {
            if (storedHeight != expectedHeight) {
                LogPrintf("ERROR: CSaplingState::RemoveNullifiers: nullifier %s stored at height %d, expected %d\n",
                          nf.ToString(), storedHeight, expectedHeight);
                return false;
            }
            batch.Erase(NullifierKey(nf));
        } else {
            LogPrintf("WARN: CSaplingState::RemoveNullifiers: nullifier %s not found at height %d\n",
                      nf.ToString(), nHeight);
            // Not fatal, could happen on restart after partial write
        }
    }
    return db->WriteBatch(batch);
}

bool CSaplingState::WriteTreeRoot(int nHeight, const uint256& root)
{
    LOCK(cs);
    return db->Write(TreeRootKey(nHeight), root);
}

bool CSaplingState::GetTreeRoot(int nHeight, uint256& root) const
{
    LOCK(cs);
    return db->Read(TreeRootKey(nHeight), root);
}

bool CSaplingState::EraseTreeRoot(int nHeight)
{
    LOCK(cs);
    CDBBatch batch(*db);
    batch.Erase(TreeRootKey(nHeight));
    return db->WriteBatch(batch);
}

bool CSaplingState::GetFrontierData(int nHeight, std::vector<uint8_t>& data) const
{
    LOCK(cs);
    return db->Read(TreeDataKey(nHeight), data);
}

bool CSaplingState::IsValidAnchor(const uint256& anchor) const
{
    LOCK(cs);
    // Null anchors are invalid. Output-only txs have no spends and
    // never call this.
    if (anchor.IsNull()) {
        return false;
    }
    // O(1) lookup via the in-memory reverse index (populated at construction
    // and maintained by ProcessBlock / UndoBlock).
    return m_anchor_heights.count(anchor) > 0;
}

bool CSaplingState::VerifyBestBlock(const uint256& hash) const
{
    LOCK(cs);
    uint256 stored;
    if (!db->Read(DB_BEST_BLOCK, stored)) {
        // No Sapling state written yet (e.g. first block after activation,
        // or genesis block which bypasses ConnectBlock). Fresh state is
        // always considered consistent.
        return true;
    }
    return stored == hash;
}

uint256 CSaplingState::GetBestBlock() const
{
    LOCK(cs);
    uint256 stored;
    db->Read(DB_BEST_BLOCK, stored);
    return stored;
}

CAmount CSaplingState::GetValuePool() const
{
    LOCK(cs);
    return m_nSaplingValuePool;
}

int CSaplingState::GetBestBlockHeight() const
{
    LOCK(cs);
    return m_lastFrontierHeight;
}

bool CSaplingState::ProcessBlock(const CBlock& block, const CBlockIndex* pindex,
                                 const Consensus::Params& params, bool fJustCheck)
{
    if (!IsSaplingActive(params, pindex->nHeight)) {
        return true;
    }

    // Idempotency: if SaplingDB already committed this block or a later one
    // (crash after SaplingDB flush but before CoinsTip flush), skip processing.
    // This allows ReplayBlocks rollforward to succeed without reindex.
    {
        LOCK(cs);
        if (m_lastFrontierHeight >= pindex->nHeight) {
            LogPrintf("CSaplingState::ProcessBlock: skipping block %d (SaplingDB at height %d)\n",
                      pindex->nHeight, m_lastFrontierHeight);
            return true;
        }
    }

    // Discard any stale pending batch from a previous failed ConnectBlock.
    {
        LOCK(cs);
        if (m_pendingBatch) {
            m_pendingBatch.reset();
            m_pendingHeight = -1;
            m_pendingTreeRoot.SetNull();
            m_pendingValuePoolDelta = 0;
        }
    }

    std::vector<uint256> nullifiers;
    std::vector<uint256> commitments;
    CAmount blockValueBalance{0};
    if (!CollectSaplingData(block, nullifiers, commitments, blockValueBalance)) {
        return false;
    }

    if (nullifiers.empty() && commitments.empty()) {
        // Carry forward frontier.
        if (!fJustCheck) {
            LOCK(cs);
            m_pendingBatch = std::make_unique<CDBBatch>(*db);

            // Carry forward the most recent frontier and root using cached
            // height for O(1) lookup instead of backward chain walk.
            if (m_lastFrontierHeight >= 0) {
                std::vector<uint8_t> prevData;
                if (db->Read(TreeDataKey(m_lastFrontierHeight), prevData)) {
                    m_pendingBatch->Write(TreeDataKey(pindex->nHeight), prevData);
                }

                uint256 prevRoot;
                if (db->Read(TreeRootKey(m_lastFrontierHeight), prevRoot)) {
                    m_pendingBatch->Write(TreeRootKey(pindex->nHeight), prevRoot);
                    m_pendingTreeRoot = prevRoot;
                }
            } else {
                // First Sapling-active block with no txs: write empty tree
                // root so the carry-forward chain has a starting point and
                // m_lastFrontierHeight can be recovered from DB on restart.
                auto emptyFrontier = sapling::tree::new_sapling_frontier();
                auto rootArr = sapling::tree::frontier_root(*emptyFrontier);
                uint256 emptyRoot;
                std::memcpy(emptyRoot.begin(), rootArr.data(), 32);
                m_pendingBatch->Write(TreeRootKey(pindex->nHeight), emptyRoot);
                m_pendingTreeRoot = emptyRoot;

                auto serialized = sapling::tree::frontier_serialize(*emptyFrontier);
                std::vector<uint8_t> treeData(serialized.begin(), serialized.end());
                m_pendingBatch->Write(TreeDataKey(pindex->nHeight), treeData);
            }

            m_pendingBatch->Write(DB_BEST_BLOCK, pindex->GetBlockHash());
            m_pendingHeight = pindex->nHeight;
            m_pendingValuePoolDelta = 0;
        }
        return true;
    }

    LOCK(cs);

    // ZIP-209: reject blocks making value pool negative.
    CAmount poolDelta = -blockValueBalance;
    if (m_nSaplingValuePool + poolDelta < 0) {
        LogPrintf("ERROR: CSaplingState::ProcessBlock: block at height %d would make Sapling value pool negative "
                  "(current: %lld, delta: %lld)\n",
                  pindex->nHeight, m_nSaplingValuePool, poolDelta);
        return false;
    }

    // Check nullifiers for double-spends: within-block + against DB
    {
        std::set<uint256> seen;
        for (const auto& nf : nullifiers) {
            if (!seen.insert(nf).second) {
                LogPrintf("ERROR: CSaplingState::ProcessBlock: duplicate nullifier %s in block at height %d\n",
                          nf.ToString(), pindex->nHeight);
                return false;
            }
        }
        for (const auto& nf : nullifiers) {
            int32_t height;
            if (db->Read(NullifierKey(nf), height)) {
                LogPrintf("ERROR: CSaplingState::ProcessBlock: double-spend nullifier %s (first at height %d) at height %d\n",
                          nf.ToString(), height, pindex->nHeight);
                return false;
            }
        }
    }

    if (fJustCheck) {
        return true;
    }

    m_pendingValuePoolDelta = poolDelta;

    m_pendingBatch = std::make_unique<CDBBatch>(*db);
    int32_t h = static_cast<int32_t>(pindex->nHeight);

    for (const auto& nf : nullifiers) {
        m_pendingBatch->Write(NullifierKey(nf), h);
    }

    // Update the incremental Merkle tree with new note commitments.
    // Load the frontier from the cached last-written height.
    bool frontierCorrupted = false;
    auto frontier = [&]() -> rust::Box<sapling::tree::SaplingFrontier> {
        if (m_lastFrontierHeight >= 0) {
            std::vector<uint8_t> prevData;
            if (db->Read(TreeDataKey(m_lastFrontierHeight), prevData)) {
                rust::Slice<const uint8_t> slice(prevData.data(), prevData.size());
                try {
                    return sapling::tree::frontier_deserialize(slice);
                } catch (const std::exception& e) {
                    LogPrintf("ERROR: CSaplingState::ProcessBlock: corrupted frontier at height %d: %s (reindex required)\n",
                              m_lastFrontierHeight, e.what());
                    frontierCorrupted = true;
                }
            }
        }
        return sapling::tree::new_sapling_frontier();
    }();

    if (frontierCorrupted) {
        m_pendingBatch.reset();
        return false;
    }

    // Cross-check frontier root against stored anchor
    if (m_lastFrontierHeight >= 0) {
        uint256 storedRoot;
        if (db->Read(TreeRootKey(m_lastFrontierHeight), storedRoot)) {
            auto frontierRootArr = sapling::tree::frontier_root(*frontier);
            uint256 frontierRoot;
            std::memcpy(frontierRoot.begin(), frontierRootArr.data(), 32);
            if (frontierRoot != storedRoot) {
                LogPrintf("ERROR: CSaplingState::ProcessBlock: frontier/root mismatch at height %d "
                          "(frontier root=%s, stored root=%s). Reindex required.\n",
                          m_lastFrontierHeight, frontierRoot.ToString(), storedRoot.ToString());
                m_pendingBatch.reset();
                return false;
            }
        }
    }

    for (const auto& cmu : commitments) {
        std::array<uint8_t, 32> cmu_arr;
        std::memcpy(cmu_arr.data(), cmu.begin(), 32);
        try {
            sapling::tree::frontier_append(*frontier, cmu_arr);
        } catch (const std::exception& e) {
            LogPrintf("ERROR: CSaplingState::ProcessBlock: failed to append commitment: %s\n", e.what());
            m_pendingBatch.reset();
            return false;
        }
    }

    uint256 treeRoot;
    {
        auto root_arr = sapling::tree::frontier_root(*frontier);
        std::memcpy(treeRoot.begin(), root_arr.data(), 32);
        m_pendingBatch->Write(TreeRootKey(pindex->nHeight), treeRoot);
    }

    {
        auto serialized = sapling::tree::frontier_serialize(*frontier);
        std::vector<uint8_t> treeData(serialized.begin(), serialized.end());
        m_pendingBatch->Write(TreeDataKey(pindex->nHeight), treeData);
    }

    m_pendingBatch->Write(DB_BEST_BLOCK, pindex->GetBlockHash());

    // ZIP-209: write updated value pool to batch
    int64_t newPool = m_nSaplingValuePool + m_pendingValuePoolDelta;
    m_pendingBatch->Write(DB_VALUE_POOL, newPool);

    m_pendingTreeRoot = treeRoot;
    m_pendingHeight = pindex->nHeight;

    return true;
}

bool CSaplingState::CommitBlock()
{
    LOCK(cs);

    if (!m_pendingBatch) {
        return true; // nothing to commit (fJustCheck, or no Sapling-active block)
    }

    if (!db->WriteBatch(*m_pendingBatch, /*fSync=*/true)) {
        LogPrintf("ERROR: CSaplingState::CommitBlock: failed to write batch at height %d\n",
                  m_pendingHeight);
        m_pendingBatch.reset();
        return false;
    }

    // Update in-memory anchor reverse index (only if we stored a tree root).
    // Insert height into the set; same root may appear at multiple heights
    // due to carry-forward blocks with no Sapling data.
    if (!m_pendingTreeRoot.IsNull()) {
        m_anchor_heights[m_pendingTreeRoot].insert(m_pendingHeight);
    }

    // Update frontier height cache
    if (m_pendingHeight > m_lastFrontierHeight) {
        m_lastFrontierHeight = m_pendingHeight;
    }

    // ZIP-209: apply pending value pool delta to in-memory state
    m_nSaplingValuePool += m_pendingValuePoolDelta;

    m_pendingBatch.reset();
    m_pendingHeight = -1;
    m_pendingTreeRoot.SetNull();
    m_pendingValuePoolDelta = 0;

    return true;
}

void CSaplingState::DiscardPendingBatch()
{
    LOCK(cs);
    m_pendingBatch.reset();
    m_pendingHeight = -1;
    m_pendingTreeRoot.SetNull();
    m_pendingValuePoolDelta = 0;
}

bool CSaplingState::UndoBlock(const CBlock& block, const CBlockIndex* pindex,
                              const Consensus::Params& params)
{
    if (!IsSaplingActive(params, pindex->nHeight)) {
        return true;
    }

    std::vector<uint256> nullifiers;
    std::vector<uint256> commitments;
    CAmount blockValueBalance{0};
    if (!CollectSaplingData(block, nullifiers, commitments, blockValueBalance)) {
        return false;
    }

    if (nullifiers.empty() && commitments.empty()) {
        // No Sapling data in this block, but we may have carried-forward
        // frontier/root data (see ProcessBlock carry-forward logic).  Erase
        // those and update best block to previous.
        LOCK(cs);
        CDBBatch batch(*db);

        // Read the carried-forward root before erasing so we can remove
        // it from the in-memory reverse index after the batch succeeds.
        uint256 erasedRoot;
        bool hasRoot = db->Read(TreeRootKey(pindex->nHeight), erasedRoot);

        batch.Erase(TreeRootKey(pindex->nHeight));
        batch.Erase(TreeDataKey(pindex->nHeight));

        if (pindex->pprev) {
            batch.Write(DB_BEST_BLOCK, pindex->pprev->GetBlockHash());
        }
        if (!db->WriteBatch(batch, /*fSync=*/true)) {
            LogPrintf("ERROR: CSaplingState::UndoBlock: failed to update best block at height %d\n",
                      pindex->nHeight);
            return false;
        }

        // Update in-memory anchor reverse index (#667: remove only this height).
        if (hasRoot) {
            auto ait = m_anchor_heights.find(erasedRoot);
            if (ait != m_anchor_heights.end()) {
                ait->second.erase(pindex->nHeight);
                if (ait->second.empty()) {
                    m_anchor_heights.erase(ait);
                }
            }
        }

        // Recompute frontier height cache if we undid the tip
        if (pindex->nHeight >= m_lastFrontierHeight) {
            m_lastFrontierHeight = -1;
            for (const auto& [root, heights] : m_anchor_heights) {
                for (int h : heights) {
                    if (h > m_lastFrontierHeight) m_lastFrontierHeight = h;
                }
            }
        }

        return true;
    }

    LOCK(cs);

    CDBBatch batch(*db);
    int32_t expectedHeight = static_cast<int32_t>(pindex->nHeight);

    for (const auto& nf : nullifiers) {
        int32_t storedHeight;
        if (db->Read(NullifierKey(nf), storedHeight)) {
            if (storedHeight != expectedHeight) {
                LogPrintf("ERROR: CSaplingState::UndoBlock: nullifier %s stored at height %d, expected %d\n",
                          nf.ToString(), storedHeight, expectedHeight);
                return false;
            }
            batch.Erase(NullifierKey(nf));
        } else {
            LogPrintf("WARN: CSaplingState::UndoBlock: nullifier %s not found at height %d\n",
                      nf.ToString(), pindex->nHeight);
        }
    }

    // Read the tree root before erasing, so we can remove it from the
    // in-memory reverse index after the batch succeeds.
    uint256 erasedRoot;
    bool hasRoot = db->Read(TreeRootKey(pindex->nHeight), erasedRoot);

    batch.Erase(TreeRootKey(pindex->nHeight));
    batch.Erase(TreeDataKey(pindex->nHeight));

    if (pindex->pprev) {
        batch.Write(DB_BEST_BLOCK, pindex->pprev->GetBlockHash());
    }

    // ZIP-209: reverse the value pool delta for this block.
    // On connect: poolDelta = -blockValueBalance (added to pool)
    // On disconnect: reverse it by adding blockValueBalance back
    CAmount undoDelta = blockValueBalance; // reverse of -blockValueBalance
    int64_t newPool = m_nSaplingValuePool + undoDelta;
    if (newPool < 0) {
        LogPrintf("ERROR: SaplingState: value pool went negative during disconnect at height %d\n", pindex->nHeight);
        return false;
    }
    batch.Write(DB_VALUE_POOL, newPool);

    if (!db->WriteBatch(batch, /*fSync=*/true)) {
        LogPrintf("ERROR: CSaplingState::UndoBlock: failed to write batch at height %d\n",
                  pindex->nHeight);
        return false;
    }

    // Update in-memory anchor reverse index (#667: remove only this height).
    if (hasRoot) {
        auto ait = m_anchor_heights.find(erasedRoot);
        if (ait != m_anchor_heights.end()) {
            ait->second.erase(pindex->nHeight);
            if (ait->second.empty()) {
                m_anchor_heights.erase(ait);
            }
        }
    }

    // Recompute frontier height cache if we undid the tip
    if (pindex->nHeight >= m_lastFrontierHeight) {
        m_lastFrontierHeight = -1;
        for (const auto& [root, heights] : m_anchor_heights) {
            for (int h : heights) {
                if (h > m_lastFrontierHeight) m_lastFrontierHeight = h;
            }
        }
    }

    // ZIP-209: apply value pool undo to in-memory state
    m_nSaplingValuePool = newPool;

    return true;
}

} // namespace sapling
