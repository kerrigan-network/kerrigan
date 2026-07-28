// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EVO_DRONELIST_H
#define BITCOIN_EVO_DRONELIST_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <saltedhasher.h>
#include <script/script.h>
#include <serialize.h>
#include <sync.h>
#include <threadsafety.h>
#include <uint256.h>

#include <gsl/pointers.h>

#include <map>
#include <set>

class BlockValidationState;
class CBlock;
class CBlockIndex;
class CEvoDB;
class UniValue;
namespace Consensus { struct Params; }

extern RecursiveMutex cs_main; // NOLINT(readability-redundant-declaration)

/**
 * DETERMINISTIC INFERENCE-DRONE LIST (v1.3.0, nDronePayoutHeight fork).
 *
 * Consensus-side registry of inference drones built from on-chain
 * TRANSACTION_DRONE_REGISTER special transactions (CDroneRegTx,
 * evo/inference_wire.h). From nDronePayoutHeight the
 * 40% growth-escrow coinbase slot pays the round-robin payee of this list
 * (masternode/payments.cpp::GetBlockTxOuts); every node recomputes the payee
 * from chain state alone and a coinbase paying anyone else is bad-cb-payee.
 *
 * This is a deliberately small clone of the CDeterministicMNManager storage
 * skeleton (per-block diffs + periodic snapshots in CEvoDB, forward-replay
 * from the nearest snapshot for historical lists, cache-eviction undo) with a
 * far simpler state machine: no PoSe, no operator keys, no IP registry, no
 * quorum interaction.
 *
 * Registration: a TRANSACTION_DRONE_REGISTER special transaction whose
 * extraPayload (CDroneRegTx, evo/inference_wire.h) carries the drone's full
 * 96-byte BLS min_sig pubkey, the payout script, the bond output index and a
 * BLS signature proving ownership of the key whose HASH160 the list is keyed
 * by. The bond output (tx.vout[nCollateralIndex], exact value
 * nDroneCollateralAmount) is the collateral -- spending it deregisters the
 * drone. Payload shape and signature are enforced as TX validity by
 * CheckDroneRegTx (specialtxman.cpp) at mempool acceptance and inside
 * ProcessSpecialTxsInBlock, exactly like the ProTx family: a malformed or
 * unsigned registration invalidates its block (bad-drone-reg-*), it is never
 * silently skipped. Only exotic same-block remove-then-re-register orderings
 * fall back to a deterministic no-op here (see BuildListFromBlock).
 *
 * Heartbeat: a TRANSACTION_DRONE_REGISTER for an already-registered pubkey
 * hash bumps the drone's last-seen height. It is authenticated by the same
 * consensus-verified BLS payload signature (only the key holder can produce
 * one), so no bond output is required on heartbeats. Payout script,
 * collateral and hardware class are immutable per pubkey hash -- a second
 * registration for a live pkh can only ever be a heartbeat; combined with the
 * ownership signature this makes registration hijack impossible (a squatter
 * can neither sign for a victim's pkh nor rebind a registered one).
 *
 * The list starts EMPTY at nDronePayoutHeight; pre-fork registrations are
 * impossible by construction (CheckDroneRegTx rejects the TX type below the
 * fork height, matching v1.2.x nodes' unknown-type rejection).
 */
class CDroneEntry
{
public:
    /** List key: HASH160 of the drone's 96-byte BLS min_sig pubkey. */
    uint160 blsPubKeyHash;
    /** Immutable coinbase payout script (the bond output's scriptPubKey). */
    CScript payoutScript;
    /** The bond UTXO; spending it deregisters the drone. Immutable. */
    COutPoint collateralOutpoint;
    /** Iroh node id from the registration payload. Informational only. */
    uint256 irohNodeId;
    /** Hardware class byte, stored raw (any value accepted; informational). */
    uint8_t nHardwareClass{0};
    /** Model-capability tier (0=simple, 1=standard, 2=complex, 3=frontier)
     *  from the consensus-validated registration payload (CheckDroneRegTx
     *  rejects values > 3, so stored state is always canonical). Stored-state
     *  only for now: payout selection is tier-neutral until the
     *  stride-frequency weighting milestone. Immutable per pkh, like
     *  nHardwareClass. */
    uint8_t nModelTier{0};
    /** Height of the (post-activation) registration that created this entry. */
    int nRegisteredHeight{0};
    /** Height of the last authenticated liveness signal (registration or heartbeat). */
    int nLastSeenHeight{0};
    /** Height this drone last received the 40% coinbase slot; 0 = never paid. */
    int nLastPaidHeight{0};

    SERIALIZE_METHODS(CDroneEntry, obj)
    {
        READWRITE(obj.blsPubKeyHash, obj.payoutScript, obj.collateralOutpoint, obj.irohNodeId,
                  obj.nHardwareClass, obj.nModelTier, obj.nRegisteredHeight, obj.nLastSeenHeight,
                  obj.nLastPaidHeight);
    }

    friend bool operator==(const CDroneEntry& a, const CDroneEntry& b)
    {
        return a.blsPubKeyHash == b.blsPubKeyHash &&
               a.payoutScript == b.payoutScript &&
               a.collateralOutpoint == b.collateralOutpoint &&
               a.irohNodeId == b.irohNodeId &&
               a.nHardwareClass == b.nHardwareClass &&
               a.nModelTier == b.nModelTier &&
               a.nRegisteredHeight == b.nRegisteredHeight &&
               a.nLastSeenHeight == b.nLastSeenHeight &&
               a.nLastPaidHeight == b.nLastPaidHeight;
    }
    friend bool operator!=(const CDroneEntry& a, const CDroneEntry& b) { return !(a == b); }

    [[nodiscard]] UniValue ToJson() const;
};

class CDroneListDiff;

class CDroneList
{
public:
    // Belt-and-braces deserialization bound; the real-world list is tiny
    // (one bonded registration per entry).
    static constexpr size_t MAX_DRONE_LIST_ENTRIES = 100000;

private:
    uint256 blockHash;
    int nHeight{-1};
    // Ordered map => deterministic iteration => deterministic payee tie-break.
    std::map<uint160, CDroneEntry> droneMap;
    // Derived O(log n) input-spend lookup; rebuilt on deserialize, never serialized.
    std::map<COutPoint, uint160> collateralIndex;

public:
    CDroneList() = default;
    explicit CDroneList(const uint256& _blockHash, int _nHeight) :
        blockHash(_blockHash), nHeight(_nHeight) {}

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << blockHash;
        s << nHeight;
        WriteCompactSize(s, droneMap.size());
        for (const auto& [pkh, entry] : droneMap) {
            s << entry;
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        droneMap.clear();
        collateralIndex.clear();
        s >> blockHash;
        s >> nHeight;
        size_t nSize = ReadCompactSize(s);
        if (nSize > MAX_DRONE_LIST_ENTRIES) {
            throw std::ios_base::failure("CDroneList::droneMap size exceeds limit");
        }
        for (size_t i = 0; i < nSize; i++) {
            CDroneEntry entry;
            s >> entry;
            AddDrone(entry);
        }
    }

    [[nodiscard]] const uint256& GetBlockHash() const { return blockHash; }
    void SetBlockHash(const uint256& _blockHash) { blockHash = _blockHash; }
    [[nodiscard]] int GetHeight() const { return nHeight; }
    void SetHeight(int _height) { nHeight = _height; }
    [[nodiscard]] size_t GetAllDroneCount() const { return droneMap.size(); }

    [[nodiscard]] const CDroneEntry* GetDrone(const uint160& pubKeyHash) const
    {
        auto it = droneMap.find(pubKeyHash);
        return it != droneMap.end() ? &it->second : nullptr;
    }
    [[nodiscard]] const CDroneEntry* GetDroneByCollateral(const COutPoint& outpoint) const
    {
        auto it = collateralIndex.find(outpoint);
        return it != collateralIndex.end() ? GetDrone(it->second) : nullptr;
    }
    [[nodiscard]] bool HasDrone(const uint160& pubKeyHash) const { return droneMap.count(pubKeyHash) != 0; }

    void AddDrone(const CDroneEntry& entry);
    /** Replace an existing entry. The collateral outpoint is immutable per
     *  entry so the collateral index needs no fixup. */
    void UpdateDrone(const CDroneEntry& entry);
    void RemoveDrone(const uint160& pubKeyHash);

    template <typename Callback>
    void ForEachDrone(Callback&& cb) const
    {
        for (const auto& [pkh, entry] : droneMap) {
            cb(entry);
        }
    }

    /**
     * CONSENSUS: eligibility of an entry for the payout of block nBlockHeight,
     * evaluated against the list at nBlockHeight - 1:
     *   - liveness: nBlockHeight - nLastSeenHeight <= nDroneMaxAge (if gated);
     *   - registered before nBlockHeight: inherent (a prev-block list can only
     *     contain entries registered at <= nBlockHeight - 1);
     *   - collateral unspent: enforced structurally by removal-on-spend.
     */
    [[nodiscard]] bool IsEligible(const CDroneEntry& entry, int nBlockHeight, const Consensus::Params& params) const;

    /**
     * CONSENSUS: round-robin payee for block nBlockHeight -- the minimum over
     * eligible entries by (effective last-paid height, blsPubKeyHash), where a
     * never-paid entry's effective height is its registration height (same
     * fallback as CDeterministicMNList::CompareByLastPaid). Returns nullptr if
     * no drone is eligible (callers then use the escrow-or-burn fallback).
     * The returned pointer is into this list; do not hold it past mutation.
     */
    [[nodiscard]] const CDroneEntry* GetPayee(int nBlockHeight, const Consensus::Params& params) const;

    /** Next nCount projected payees, in payment order (RPC convenience). */
    [[nodiscard]] std::vector<const CDroneEntry*> GetProjectedPayees(int nBlockHeight, const Consensus::Params& params, size_t nCount) const;

    [[nodiscard]] CDroneListDiff BuildDiff(const CDroneList& to) const;
    void ApplyDiff(gsl::not_null<const CBlockIndex*> pindex, const CDroneListDiff& diff);

    friend bool operator==(const CDroneList& a, const CDroneList& b)
    {
        return a.blockHash == b.blockHash && a.nHeight == b.nHeight && a.droneMap == b.droneMap;
    }
};

class CDroneListDiff
{
public:
    /** Memory-only (set when loaded/applied), mirroring CDeterministicMNListDiff. */
    int nHeight{-1};

    std::vector<CDroneEntry> addedDrones;
    std::map<uint160, CDroneEntry> updatedDrones; // full new entry (the struct is small; no bitmask sub-diffs)
    std::set<uint160> removedDrones;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        WriteCompactSize(s, addedDrones.size());
        for (const auto& e : addedDrones) s << e;
        WriteCompactSize(s, updatedDrones.size());
        for (const auto& [pkh, e] : updatedDrones) s << e;
        WriteCompactSize(s, removedDrones.size());
        for (const auto& pkh : removedDrones) s << pkh;
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        addedDrones.clear();
        updatedDrones.clear();
        removedDrones.clear();

        size_t nAdded = ReadCompactSize(s);
        if (nAdded > CDroneList::MAX_DRONE_LIST_ENTRIES) {
            throw std::ios_base::failure("CDroneListDiff::addedDrones size exceeds limit");
        }
        for (size_t i = 0; i < nAdded; i++) {
            CDroneEntry e;
            s >> e;
            addedDrones.push_back(std::move(e));
        }
        size_t nUpdated = ReadCompactSize(s);
        if (nUpdated > CDroneList::MAX_DRONE_LIST_ENTRIES) {
            throw std::ios_base::failure("CDroneListDiff::updatedDrones size exceeds limit");
        }
        for (size_t i = 0; i < nUpdated; i++) {
            CDroneEntry e;
            s >> e;
            const uint160 key = e.blsPubKeyHash;
            updatedDrones.emplace(key, std::move(e));
        }
        size_t nRemoved = ReadCompactSize(s);
        if (nRemoved > CDroneList::MAX_DRONE_LIST_ENTRIES) {
            throw std::ios_base::failure("CDroneListDiff::removedDrones size exceeds limit");
        }
        for (size_t i = 0; i < nRemoved; i++) {
            uint160 pkh;
            s >> pkh;
            removedDrones.emplace(pkh);
        }
    }

    [[nodiscard]] bool HasChanges() const
    {
        return !addedDrones.empty() || !updatedDrones.empty() || !removedDrones.empty();
    }
};

class CDroneListManager
{
public:
    static constexpr int DISK_SNAPSHOT_PERIOD = 576; // once per nominal day, same as CDeterministicMNManager

private:
    Mutex cs;
    CEvoDB& m_evoDb;
    // Snapshot cadence. NOT consensus (snapshots are a purely local storage
    // layout; any period rebuilds the identical lists) -- overridable on
    // REGTEST ONLY via -dronesnapshotperiod so tests can exercise the
    // snapshot-write / snapshot-read / forward-replay path without mining
    // 576-block spans. Mainnet/testnet/devnet always use
    // DISK_SNAPSHOT_PERIOD (the override is gated in chainhelper.cpp).
    const int m_nSnapshotPeriod;
    // Keep recent lists/diffs cached long enough for typical reorg depths and
    // repeated GetListForBlock() calls near the tip; everything older is
    // rebuildable from disk snapshots + diffs. Scales with the snapshot
    // period so short-period regtest runs exercise the disk walk in-session.
    const int m_nCacheKeepBlocks;

    Uint256HashMap<CDroneList> droneListsCache GUARDED_BY(cs);
    Uint256HashMap<CDroneListDiff> droneListDiffsCache GUARDED_BY(cs);

public:
    CDroneListManager() = delete;
    CDroneListManager(const CDroneListManager&) = delete;
    CDroneListManager& operator=(const CDroneListManager&) = delete;
    explicit CDroneListManager(CEvoDB& evoDb, int nSnapshotPeriod = DISK_SNAPSHOT_PERIOD) :
        m_evoDb{evoDb},
        m_nSnapshotPeriod{nSnapshotPeriod > 0 ? nSnapshotPeriod : DISK_SNAPSHOT_PERIOD},
        m_nCacheKeepBlocks{2 * m_nSnapshotPeriod} {}

    /**
     * Apply block pindex to the drone list and persist the per-block diff
     * (plus a full snapshot every m_nSnapshotPeriod blocks). Invoked from
     * CSpecialTxProcessor::ProcessSpecialTxsInBlock next to the deterministic
     * MN list hook, under cs_main; every CDroneRegTx in the block has already
     * passed CheckDroneRegTx (payload shape + BLS ownership signature) by the
     * time this runs. No-op before nDronePayoutHeight.
     */
    bool ProcessBlock(const CBlock& block, gsl::not_null<const CBlockIndex*> pindex,
                      const Consensus::Params& params, BlockValidationState& state)
        EXCLUSIVE_LOCKS_REQUIRED(!cs, ::cs_main);

    /**
     * Undo block pindex. Like CDeterministicMNManager::UndoBlock this only
     * evicts the block's cached list/diff: historical lists are always
     * rebuilt by forward-replay from the nearest snapshot, so undo is exact
     * at ARBITRARY depth (stored diffs keyed by a disconnected block's hash
     * are unreachable from the active chain and harmless).
     */
    bool UndoBlock(gsl::not_null<const CBlockIndex*> pindex, const Consensus::Params& params) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /** Drone list as of (i.e. AFTER connecting) block pindex. Empty list for
     *  any pre-activation block. */
    CDroneList GetListForBlock(gsl::not_null<const CBlockIndex*> pindex, const Consensus::Params& params)
        EXCLUSIVE_LOCKS_REQUIRED(!cs)
    {
        LOCK(cs);
        return GetListForBlockInternal(pindex, params);
    }

    /**
     * CONSENSUS: pure list-transition function -- build the drone list that
     * results from connecting `block` at height nHeight on top of prevList.
     * Assumes every TRANSACTION_DRONE_REGISTER in the block passed
     * CheckDroneRegTx (which verified the BLS ownership signature and -- for
     * fresh registrations as of the previous block's list -- the bond output
     * and payout script). Static and index-free so unit tests can exercise it
     * without an evoDb or a chainstate.
     */
    static void BuildListFromBlock(const CDroneList& prevList, const CBlock& block, int nHeight,
                                   const Consensus::Params& params, CDroneList& newListRet);

private:
    CDroneList GetListForBlockInternal(gsl::not_null<const CBlockIndex*> pindex, const Consensus::Params& params)
        EXCLUSIVE_LOCKS_REQUIRED(cs);
    void CleanupCache(int nHeight) EXCLUSIVE_LOCKS_REQUIRED(cs);
};

/**
 * CONSENSUS: is the drone-payout fork IN EFFECT for a block at nHeight?
 *
 *   effective := params.IsDronePayoutActive(nHeight)              // hard height floor
 *                && SPORK_26_DRONE_PAYOUT_ENABLED is active       // operator cutover
 *
 * This is the ONE predicate behind all three consensus gates of the fork,
 * which must move in lockstep or the chain splits:
 *   1. the drone-vs-escrow coinbase branch (masternode/payments.cpp,
 *      GetBlockTxOuts -- miner template AND block validation);
 *   2. TRANSACTION_DRONE_REGISTER acceptance in ContextualCheckTransaction
 *      (validation.cpp, "bad-txns-type");
 *   3. CheckDroneRegTx's activation gate (evo/specialtxman.cpp,
 *      "bad-drone-reg-height").
 *
 * WHY REGISTRATION IS SPORK-GATED TOO (reindex safety): IsSporkActive
 * compares the spork value against GetAdjustedTime(), so during IBD/reindex
 * it evaluates to the CURRENT spork state uniformly across ALL historical
 * blocks. Reindex safety therefore requires that no TRANSACTION_DRONE_REGISTER
 * ever confirmed while the spork was off: if one had, a node reindexing after
 * the operator flips the spork on would see the payout gate as active for
 * those escrow-era blocks, expect a drone payee, and reject the historically
 * escrow-paying coinbase (bad-cb-payee) -- chain split. Gating registration
 * acceptance (gates 2 and 3) on this same predicate closes that window: while
 * the spork is off no type-11 tx can confirm, the drone list stays empty
 * above the height floor, and gate 1 deterministically falls back to the
 * byte-identical escrow/burn branch for every spork-off block.
 *
 * ENABLE-ONCE: by the same argument in reverse, once the spork is on and real
 * registrations have confirmed, turning it OFF would reject those confirmed
 * type-11 txs (and the drone-paying coinbases) on reindex/IBD. Operators must
 * treat the flip as one-way. The nDronePayoutHeight floor stays a hard
 * minimum so the spork can never activate the fork inside already-mined
 * pre-floor history. Known, accepted cost: brief tip-only enforcement
 * ambiguity around the ON flip itself (adjusted-time skew + spork message
 * propagation), the standard Dash enable-spork trade-off.
 *
 * The raw height-only Consensus::Params::IsDronePayoutActive remains for
 * deterministic bookkeeping that must NOT depend on current spork state
 * (CDroneListManager's per-block diff/snapshot storage: a diff is written for
 * every post-floor block regardless of the spork, so the on-disk walk is
 * identical whether the blocks were first connected live, spork-off, or
 * re-validated later with the spork on).
 *
 * Defined in dronelist.cpp (Consensus::Params must not depend on the global
 * g_sporkman, so the spork term cannot live in consensus/params.h). A null
 * g_sporkman evaluates as spork-off (fail-closed to pre-fork behaviour).
 */
[[nodiscard]] bool IsDronePayoutEffective(const Consensus::Params& params, int nHeight);

#endif // BITCOIN_EVO_DRONELIST_H
