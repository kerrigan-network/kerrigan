// Copyright (c) 2024-2025 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/chainhelper.h>

#include <chainparams.h>

#include <chainlock/chainlock.h>
#include <evo/creditpool.h>
#include <evo/mnhftx.h>
#include <evo/specialtxman.h>
#include <instantsend/instantsend.h>
#include <instantsend/lock.h>
#include <masternode/payments.h>
#include <sapling/sapling_init.h>
#include <sapling/sapling_state.h>

// Global pointer for the anchor callback (set during init, cleared on shutdown).
static sapling::CSaplingState* g_sapling_state_ptr = nullptr;

static bool AnchorCallbackImpl(int nHeight, uint256& root)
{
    if (!g_sapling_state_ptr) return false;
    return g_sapling_state_ptr->GetTreeRoot(nHeight, root);
}

static bool FrontierCallbackImpl(int nHeight, std::vector<uint8_t>& data)
{
    if (!g_sapling_state_ptr) return false;
    return g_sapling_state_ptr->GetFrontierData(nHeight, data);
}

static bool ValidAnchorCallbackImpl(const uint256& anchor)
{
    if (!g_sapling_state_ptr) return false;
    return g_sapling_state_ptr->IsValidAnchor(anchor);
}

CChainstateHelper::CChainstateHelper(CEvoDB& evodb, CDeterministicMNManager& dmnman, CGovernanceManager& govman,
                                     llmq::CInstantSendManager& isman, llmq::CQuorumBlockProcessor& qblockman,
                                     llmq::CQuorumSnapshotManager& qsnapman, const ChainstateManager& chainman,
                                     const Consensus::Params& consensus_params, const CMasternodeSync& mn_sync,
                                     const CSporkManager& sporkman, const chainlock::Chainlocks& chainlocks,
                                     const llmq::CQuorumManager& qman,
                                     const fs::path& data_dir, bool fWipe) :
    isman{isman},
    credit_pool_manager{std::make_unique<CCreditPoolManager>(evodb, chainman)},
    m_chainlocks{chainlocks},
    ehf_manager{std::make_unique<CMNHFManager>(evodb, chainman, qman)},
    mn_payments{std::make_unique<CMNPaymentsProcessor>(dmnman, govman, chainman, consensus_params, mn_sync, sporkman)},
    sapling_state{std::make_unique<sapling::CSaplingState>(data_dir / "sapling", 1 << 20 /* 1 MiB cache */, false, fWipe)},
    special_tx{std::make_unique<CSpecialTxProcessor>(*credit_pool_manager, dmnman, *ehf_manager, qblockman, qsnapman,
                                                     chainman, consensus_params, chainlocks, qman, *sapling_state)}
{
    // Register the anchor callback so wallet RPCs can retrieve tree roots
    // without a direct link dependency on LevelDB.
    g_sapling_state_ptr = sapling_state.get();
    sapling::SetAnchorCallback(&AnchorCallbackImpl);
    sapling::SetFrontierCallback(&FrontierCallbackImpl);
    sapling::SetValidAnchorCallback(&ValidAnchorCallbackImpl);
}

CChainstateHelper::~CChainstateHelper()
{
    g_sapling_state_ptr = nullptr;
    sapling::SetAnchorCallback(nullptr);
    sapling::SetFrontierCallback(nullptr);
    sapling::SetValidAnchorCallback(nullptr);
}

/** Passthrough functions to chainlock::Chainlocks */
bool CChainstateHelper::HasConflictingChainLock(int nHeight, const uint256& blockHash) const
{
    return m_chainlocks.HasConflictingChainLock(nHeight, blockHash);
}

bool CChainstateHelper::HasChainLock(int nHeight, const uint256& blockHash) const
{
    return m_chainlocks.HasChainLock(nHeight, blockHash);
}

int32_t CChainstateHelper::GetBestChainLockHeight() const { return m_chainlocks.GetBestChainLockHeight(); }

/** Passthrough functions to CCreditPoolManager */
CCreditPool CChainstateHelper::GetCreditPool(const CBlockIndex* const pindex)
{
    return credit_pool_manager->GetCreditPool(pindex);
}

/** Passthrough functions to CInstantSendManager */
std::optional<std::pair</*islock_hash=*/uint256, /*txid=*/uint256>> CChainstateHelper::ConflictingISLockIfAny(
    const CTransaction& tx) const
{
    const auto islock = isman.GetConflictingLock(tx);
    if (!islock) return std::nullopt;
    return std::make_pair(::SerializeHash(*islock), islock->txid);
}

bool CChainstateHelper::IsInstantSendWaitingForTx(const uint256& hash) const { return isman.IsWaitingForTx(hash); }

bool CChainstateHelper::RemoveConflictingISLockByTx(const CTransaction& tx)
{
    const auto islock = isman.GetConflictingLock(tx);
    if (!islock) return false;
    isman.RemoveConflictingLock(::SerializeHash(*islock), *islock);
    return true;
}

bool CChainstateHelper::ShouldInstantSendRejectConflicts() const { return isman.RejectConflictingBlocks(); }

std::unordered_map<uint8_t, int> CChainstateHelper::GetSignalsStage(const CBlockIndex* const pindexPrev)
{
    return ehf_manager->GetSignalsStage(pindexPrev);
}
