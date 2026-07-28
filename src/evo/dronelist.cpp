// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/dronelist.h>

#include <chain.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <evo/evodb.h>
#include <evo/inference_wire.h>
#include <evo/specialtx.h>
#include <key_io.h>
#include <logging.h>
#include <primitives/block.h>
#include <script/standard.h>
#include <spork.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <univalue.h>

#include <algorithm>

static const std::string DB_DRONE_LIST_SNAPSHOT = "drn_S1";
static const std::string DB_DRONE_LIST_DIFF = "drn_D1";

UniValue CDroneEntry::ToJson() const
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("blsPubKeyHash", blsPubKeyHash.ToString());
    CTxDestination dest;
    if (ExtractDestination(payoutScript, dest)) {
        obj.pushKV("payoutAddress", EncodeDestination(dest));
    }
    obj.pushKV("payoutScript", HexStr(payoutScript));
    obj.pushKV("collateralHash", collateralOutpoint.hash.ToString());
    obj.pushKV("collateralIndex", static_cast<int64_t>(collateralOutpoint.n));
    obj.pushKV("irohNodeId", irohNodeId.ToString());
    obj.pushKV("hardwareClass", nHardwareClass);
    obj.pushKV("modelTier", nModelTier);
    obj.pushKV("registeredHeight", nRegisteredHeight);
    obj.pushKV("lastSeenHeight", nLastSeenHeight);
    obj.pushKV("lastPaidHeight", nLastPaidHeight);
    return obj;
}

void CDroneList::AddDrone(const CDroneEntry& entry)
{
    auto [it, inserted] = droneMap.emplace(entry.blsPubKeyHash, entry);
    if (!inserted) {
        throw std::runtime_error(strprintf("%s: can't add a duplicate drone %s", __func__,
                                           entry.blsPubKeyHash.ToString()));
    }
    if (!collateralIndex.emplace(entry.collateralOutpoint, entry.blsPubKeyHash).second) {
        droneMap.erase(it);
        throw std::runtime_error(strprintf("%s: can't add a drone %s with a duplicate collateral %s", __func__,
                                           entry.blsPubKeyHash.ToString(), entry.collateralOutpoint.ToStringShort()));
    }
}

void CDroneList::UpdateDrone(const CDroneEntry& entry)
{
    auto it = droneMap.find(entry.blsPubKeyHash);
    if (it == droneMap.end()) {
        throw std::runtime_error(strprintf("%s: can't update a non-existent drone %s", __func__,
                                           entry.blsPubKeyHash.ToString()));
    }
    // Payout script + collateral are immutable per pkh (anti-hijack); an
    // update may only touch the height bookkeeping.
    if (it->second.collateralOutpoint != entry.collateralOutpoint || it->second.payoutScript != entry.payoutScript) {
        throw std::runtime_error(strprintf("%s: attempt to mutate immutable fields of drone %s", __func__,
                                           entry.blsPubKeyHash.ToString()));
    }
    it->second = entry;
}

void CDroneList::RemoveDrone(const uint160& pubKeyHash)
{
    auto it = droneMap.find(pubKeyHash);
    if (it == droneMap.end()) {
        throw std::runtime_error(strprintf("%s: can't remove a non-existent drone %s", __func__,
                                           pubKeyHash.ToString()));
    }
    collateralIndex.erase(it->second.collateralOutpoint);
    droneMap.erase(it);
}

bool CDroneList::IsEligible(const CDroneEntry& entry, int nBlockHeight, const Consensus::Params& params) const
{
    // Liveness: last authenticated signal must be within nDroneMaxAge blocks.
    // nRegisteredHeight < nBlockHeight and collateral-unspent hold inherently
    // for every entry of a prev-block list (see header).
    if (params.nDroneMaxAge > 0 && nBlockHeight - entry.nLastSeenHeight > params.nDroneMaxAge) {
        return false;
    }
    return true;
}

namespace {

int EffectiveLastPaidHeight(const CDroneEntry& entry)
{
    // Never-paid drones queue by registration height, the same fallback as
    // CompareByLastPaid_GetHeight in deterministicmns.cpp.
    return entry.nLastPaidHeight == 0 ? entry.nRegisteredHeight : entry.nLastPaidHeight;
}

bool CompareDronesByLastPaid(const CDroneEntry& a, const CDroneEntry& b)
{
    const int ah = EffectiveLastPaidHeight(a);
    const int bh = EffectiveLastPaidHeight(b);
    if (ah == bh) {
        return a.blsPubKeyHash < b.blsPubKeyHash;
    }
    return ah < bh;
}

} // anonymous namespace

const CDroneEntry* CDroneList::GetPayee(int nBlockHeight, const Consensus::Params& params) const
{
    // TODO(model-tier): stride-frequency weighting by nModelTier activates in
    // a LATER milestone, gated on a tier-attestation/slash scheme that does
    // not exist yet. Until then payee selection is deliberately tier-neutral
    // pure round-robin -- do not consult nModelTier here.
    const CDroneEntry* best = nullptr;
    for (const auto& [pkh, entry] : droneMap) {
        if (!IsEligible(entry, nBlockHeight, params)) continue;
        if (best == nullptr || CompareDronesByLastPaid(entry, *best)) {
            best = &entry;
        }
    }
    return best;
}

std::vector<const CDroneEntry*> CDroneList::GetProjectedPayees(int nBlockHeight, const Consensus::Params& params, size_t nCount) const
{
    std::vector<const CDroneEntry*> result;
    result.reserve(droneMap.size());
    for (const auto& [pkh, entry] : droneMap) {
        if (IsEligible(entry, nBlockHeight, params)) {
            result.push_back(&entry);
        }
    }
    std::sort(result.begin(), result.end(), [](const CDroneEntry* a, const CDroneEntry* b) {
        return CompareDronesByLastPaid(*a, *b);
    });
    if (result.size() > nCount) {
        result.resize(nCount);
    }
    return result;
}

CDroneListDiff CDroneList::BuildDiff(const CDroneList& to) const
{
    CDroneListDiff diff;
    for (const auto& [pkh, toEntry] : to.droneMap) {
        auto it = droneMap.find(pkh);
        if (it == droneMap.end()) {
            diff.addedDrones.push_back(toEntry);
        } else if (it->second != toEntry) {
            if (it->second.collateralOutpoint != toEntry.collateralOutpoint ||
                it->second.payoutScript != toEntry.payoutScript) {
                // A collateral spend + re-registration of the same pkh inside
                // one block replaces the immutable fields; encode it as
                // remove+add so ApplyDiff replay never mutates immutables.
                diff.removedDrones.emplace(pkh);
                diff.addedDrones.push_back(toEntry);
            } else {
                diff.updatedDrones.emplace(pkh, toEntry);
            }
        }
    }
    for (const auto& [pkh, fromEntry] : droneMap) {
        if (to.droneMap.count(pkh) == 0) {
            diff.removedDrones.emplace(pkh);
        }
    }
    return diff;
}

void CDroneList::ApplyDiff(gsl::not_null<const CBlockIndex*> pindex, const CDroneListDiff& diff)
{
    blockHash = pindex->GetBlockHash();
    nHeight = pindex->nHeight;

    for (const auto& pkh : diff.removedDrones) {
        RemoveDrone(pkh);
    }
    for (const auto& [pkh, entry] : diff.updatedDrones) {
        UpdateDrone(entry);
    }
    for (const auto& entry : diff.addedDrones) {
        AddDrone(entry);
    }
}

void CDroneListManager::BuildListFromBlock(const CDroneList& prevList, const CBlock& block, int nHeight,
                                           const Consensus::Params& params, CDroneList& newListRet)
{
    CDroneList newList = prevList;
    newList.SetBlockHash(uint256()); // final block hash is set by the caller
    newList.SetHeight(nHeight);

    // (1) Payee bookkeeping. The payee of THIS block was selected from the
    // previous block's list, exactly as GetBlockTxOuts did when the coinbase
    // was built/validated (IsBlockPayeeValid enforces the coinbase actually
    // pays it), so bump its last-paid height before applying this block's
    // registrations -- a registration in block H first affects the payee of
    // H+1, never its own block.
    if (const CDroneEntry* payee = prevList.GetPayee(nHeight, params)) {
        CDroneEntry entry = *payee;
        entry.nLastPaidHeight = nHeight;
        newList.UpdateDrone(entry);
    }

    for (const auto& ptr_tx : block.vtx) {
        const CTransaction& tx = *ptr_tx;
        if (tx.IsCoinBase()) continue;

        // (2) Collateral spends: spending the bond outpoint deregisters the
        // drone (bond recovery). Processed per-TX before the TX's own
        // payload so a single TX can spend an old bond and re-register.
        for (const auto& txin : tx.vin) {
            if (const CDroneEntry* spent = newList.GetDroneByCollateral(txin.prevout)) {
                LogPrint(BCLog::MNPAYMENTS, "CDroneListManager::%s -- drone %s deregistered (collateral %s spent) at height %d\n",
                         __func__, spent->blsPubKeyHash.ToString(), txin.prevout.ToStringShort(), nHeight);
                newList.RemoveDrone(spent->blsPubKeyHash);
            }
        }

        // (3) Registration / heartbeat. Payload shape and the BLS key-ownership
        // signature were already enforced as TX validity by CheckDroneRegTx
        // (a block containing a malformed or unsigned registration never gets
        // here), so an undecodable payload is a hard internal error.
        if (!tx.IsSpecialTxVersion() || tx.nType != TRANSACTION_DRONE_REGISTER) continue;
        const auto opt_reg = GetTxPayload<CDroneRegTx>(tx);
        if (!opt_reg) {
            throw std::runtime_error(strprintf("%s: undecodable CDroneRegTx payload in checked block (tx %s)",
                                               __func__, tx.GetHash().ToString()));
        }

        if (const CDroneEntry* existing = newList.GetDrone(opt_reg->blsPubKeyHash)) {
            // Heartbeat: the consensus-verified payload signature proves the
            // key holder issued it; bump liveness only. Payout script /
            // collateral / hardware class / model tier are NEVER updated
            // here -- immutability is what makes rebinding a live
            // registration impossible.
            CDroneEntry entry = *existing;
            entry.nLastSeenHeight = nHeight;
            newList.UpdateDrone(entry);
            LogPrint(BCLog::MNPAYMENTS, "CDroneListManager::%s -- drone %s heartbeat at height %d (tx %s)\n",
                     __func__, existing->blsPubKeyHash.ToString(), nHeight, tx.GetHash().ToString());
        } else {
            // New registration. CheckDroneRegTx validated the bond output and
            // payout script against the PREVIOUS block's list; if the entry
            // was instead removed EARLIER IN THIS BLOCK (collateral spend in
            // this or a prior TX), the TX was validated on the heartbeat path
            // and its collateral fields were not checked. Re-check them here
            // and treat an unusable shape as a deterministic no-op -- never a
            // block-invalidity reason at this stage.
            if (params.nDroneCollateralAmount <= 0) continue;
            if (opt_reg->nCollateralIndex >= tx.vout.size()) continue;
            if (tx.vout[opt_reg->nCollateralIndex].nValue != params.nDroneCollateralAmount) continue;
            if (!IsValidDronePayoutScript(opt_reg->scriptPayout)) continue;

            CDroneEntry entry;
            entry.blsPubKeyHash = opt_reg->blsPubKeyHash;
            entry.payoutScript = opt_reg->scriptPayout;
            entry.collateralOutpoint = COutPoint(tx.GetHash(), opt_reg->nCollateralIndex);
            entry.irohNodeId = opt_reg->irohNodeId;
            entry.nHardwareClass = opt_reg->nHardwareClass;
            entry.nModelTier = opt_reg->nModelTier;
            entry.nRegisteredHeight = nHeight;
            entry.nLastSeenHeight = nHeight;
            entry.nLastPaidHeight = 0;
            newList.AddDrone(entry);
            LogPrint(BCLog::MNPAYMENTS, "CDroneListManager::%s -- drone %s registered at height %d (collateral %s)\n",
                     __func__, entry.blsPubKeyHash.ToString(), nHeight, entry.collateralOutpoint.ToStringShort());
        }
    }

    newListRet = std::move(newList);
}

bool CDroneListManager::ProcessBlock(const CBlock& block, gsl::not_null<const CBlockIndex*> pindex,
                                     const Consensus::Params& params, BlockValidationState& state)
{
    AssertLockHeld(::cs_main);

    // The list starts empty at the fork height; nothing is tracked before it.
    if (!params.IsDronePayoutActive(pindex->nHeight)) {
        return true;
    }

    try {
        LOCK(cs);

        const CDroneList oldList = GetListForBlockInternal(pindex->pprev, params);
        CDroneList newList;
        BuildListFromBlock(oldList, block, pindex->nHeight, params, newList);
        newList.SetBlockHash(pindex->GetBlockHash());

        CDroneListDiff diff = oldList.BuildDiff(newList);

        // A diff is written for EVERY post-activation block (even an empty
        // one): GetListForBlockInternal treats "no diff on disk" as the
        // pre-activation empty baseline, so gaps would corrupt the walk.
        m_evoDb.Write(std::make_pair(DB_DRONE_LIST_DIFF, newList.GetBlockHash()), diff);
        if ((pindex->nHeight % m_nSnapshotPeriod) == 0) {
            m_evoDb.Write(std::make_pair(DB_DRONE_LIST_SNAPSHOT, newList.GetBlockHash()), newList);
            LogPrint(BCLog::MNPAYMENTS, "CDroneListManager::%s -- wrote snapshot. nHeight=%d, drones=%d\n",
                     __func__, pindex->nHeight, (int)newList.GetAllDroneCount());
        }

        diff.nHeight = pindex->nHeight;
        droneListDiffsCache.emplace(pindex->GetBlockHash(), diff);
        droneListsCache.emplace(newList.GetBlockHash(), newList);
        CleanupCache(pindex->nHeight);
    } catch (const std::exception& e) {
        LogPrintf("CDroneListManager::%s -- internal error: %s\n", __func__, e.what());
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "failed-drone-block");
    }

    return true;
}

bool CDroneListManager::UndoBlock(gsl::not_null<const CBlockIndex*> pindex, const Consensus::Params& params)
{
    if (!params.IsDronePayoutActive(pindex->nHeight)) {
        return true;
    }

    LOCK(cs);
    // Cache eviction is all that is needed: lists are rebuilt by forward
    // replay from the nearest snapshot, so a later reconnect (or a query for
    // any still-active ancestor) recomputes exact state at any reorg depth.
    // The on-disk diff keyed by this block's hash becomes unreachable and is
    // simply overwritten if the block ever reconnects.
    droneListsCache.erase(pindex->GetBlockHash());
    droneListDiffsCache.erase(pindex->GetBlockHash());
    return true;
}

CDroneList CDroneListManager::GetListForBlockInternal(gsl::not_null<const CBlockIndex*> pindex,
                                                      const Consensus::Params& params)
{
    AssertLockHeld(cs);

    if (!params.IsDronePayoutActive(pindex->nHeight)) {
        // Pre-activation: the list is empty by definition (registrations
        // mined before the fork are deliberately ignored, see class header).
        return CDroneList(pindex->GetBlockHash(), pindex->nHeight);
    }

    CDroneList snapshot;
    std::list<const CBlockIndex*> listDiffIndexes;

    const CBlockIndex* pindexWalk = pindex;
    while (true) {
        if (!params.IsDronePayoutActive(pindexWalk->nHeight)) {
            // Walked below the fork: empty baseline.
            snapshot = CDroneList(pindexWalk->GetBlockHash(), pindexWalk->nHeight);
            break;
        }

        auto itLists = droneListsCache.find(pindexWalk->GetBlockHash());
        if (itLists != droneListsCache.end()) {
            snapshot = itLists->second;
            break;
        }

        if (m_evoDb.Read(std::make_pair(DB_DRONE_LIST_SNAPSHOT, pindexWalk->GetBlockHash()), snapshot)) {
            droneListsCache.emplace(pindexWalk->GetBlockHash(), snapshot);
            break;
        }

        auto itDiffs = droneListDiffsCache.find(pindexWalk->GetBlockHash());
        if (itDiffs != droneListDiffsCache.end()) {
            listDiffIndexes.emplace_front(pindexWalk);
            pindexWalk = pindexWalk->pprev;
            continue;
        }

        CDroneListDiff diff;
        if (!m_evoDb.Read(std::make_pair(DB_DRONE_LIST_DIFF, pindexWalk->GetBlockHash()), diff)) {
            // No snapshot and no diff for a post-activation block: it has not
            // been processed (should not happen for a connected ancestor --
            // evoDb consistency is guarded at init like the MN list's).
            // Treat as the empty baseline rather than crash.
            LogPrintf("CDroneListManager::%s -- WARNING: no drone list data for block %s at height %d, using empty baseline\n",
                      __func__, pindexWalk->GetBlockHash().ToString(), pindexWalk->nHeight);
            snapshot = CDroneList(pindexWalk->GetBlockHash(), pindexWalk->nHeight);
            break;
        }

        diff.nHeight = pindexWalk->nHeight;
        droneListDiffsCache.emplace(pindexWalk->GetBlockHash(), std::move(diff));
        listDiffIndexes.emplace_front(pindexWalk);
        pindexWalk = pindexWalk->pprev;
    }

    for (const auto& diffIndex : listDiffIndexes) {
        const auto& diff = droneListDiffsCache.at(diffIndex->GetBlockHash());
        snapshot.ApplyDiff(diffIndex, diff);
    }

    return snapshot;
}

void CDroneListManager::CleanupCache(int nHeight)
{
    AssertLockHeld(cs);

    for (auto it = droneListsCache.begin(); it != droneListsCache.end();) {
        if (it->second.GetHeight() < nHeight - m_nCacheKeepBlocks) {
            it = droneListsCache.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = droneListDiffsCache.begin(); it != droneListDiffsCache.end();) {
        if (it->second.nHeight >= 0 && it->second.nHeight < nHeight - m_nCacheKeepBlocks) {
            it = droneListDiffsCache.erase(it);
        } else {
            ++it;
        }
    }
}

bool IsDronePayoutEffective(const Consensus::Params& params, int nHeight)
{
    // Height floor first: the spork can never activate the fork inside
    // already-mined pre-floor history. Full rationale (lockstep gates,
    // reindex safety, enable-once) at the declaration in dronelist.h.
    if (!params.IsDronePayoutActive(nHeight)) {
        return false;
    }
    // Null g_sporkman (early init, some unit-test setups) == spork off:
    // fail closed to the byte-identical pre-fork escrow behaviour.
    return g_sporkman != nullptr && g_sporkman->IsSporkActive(SPORK_26_DRONE_PAYOUT_ENABLED);
}
