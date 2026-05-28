// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Outpoint / address blacklist ("freeze list").
//
// PURPOSE
// -------
// A surgical, opt-in, file-driven mechanism for a cooperating node operator to
// refuse to *mine* or *relay* transactions that spend a specific set of
// transparent outputs (or any output paying a specific script). It exists to
// let cooperating pools collectively deny confirmation to a known theft's
// onward spends -- including any transparent->Sapling shield -- without
// rewriting history or affecting any other transaction.
//
// This is a DEFENSIVE, REVERSIBLE control. It freezes *spends of named coins*;
// it never moves, seizes, or redirects funds, and it touches no key material.
//
// TWO INDEPENDENT LAYERS (see outpoint_blacklist.cpp and the call sites):
//   * Layer 1 (relay/policy)  -- mempool reject + block-template exclusion.
//     Non-consensus. Default OFF. An un-configured node behaves exactly as
//     stock. Enabled per node via -blacklistoutpoints / -blacklistaddr. Causes
//     NO chain split: a node simply declines to relay/mine the spend. If a
//     supermajority of hashpower runs it, the spend never confirms.
//   * Layer 2 (consensus)     -- block containing a blacklisted-outpoint spend
//     is invalid, from an activation height onward. Default OFF, gated behind
//     its OWN flag (-blacklistconsensus) AND an activation height. This is a
//     HARD FORK if not universally adopted; it must ship with a checkpoint and
//     coordinated upgrade. Documented but NOT enabled by default.
//
// REVERSIBILITY
// -------------
// The list is plain text loaded at startup. Removing an entry (or the option)
// and restarting un-freezes the coin. No on-disk consensus state is created by
// Layer 1. Layer 2's invalidity is purely a function of the running binary's
// configured list + flag + height, so lifting it is a config/release change.
//
// THREAD SAFETY
// -------------
// The singleton is loaded ONCE at startup (before networking/validation
// threads start) and thereafter treated as read-only / immutable. Lookups are
// therefore lock-free and safe to call from validation and mining threads
// concurrently. If runtime mutation is ever added, add a lock first.

#ifndef BITCOIN_POLICY_OUTPOINT_BLACKLIST_H
#define BITCOIN_POLICY_OUTPOINT_BLACKLIST_H

#include <fs.h>                     // fs::path
#include <primitives/transaction.h> // COutPoint
#include <script/script.h>          // CScript
#include <uint256.h>                // uint256 (TaintSet anchor hash / seed txids)

#include <cstddef>
#include <set>
#include <string>
#include <vector>

/**
 * Immutable freeze list of outpoints and scripts.
 *
 * Time complexity: O(log n) per lookup (std::set / red-black tree). n is the
 * number of frozen entries -- expected to be tiny (tens), so this is never a
 * hot-path concern even though it is consulted per-input during block connect.
 *
 * Memory: one CScript per frozen address + one COutPoint per frozen outpoint.
 */
class OutpointBlacklist
{
public:
    OutpointBlacklist() = default;

    /** True if any entry is loaded (i.e. the freeze is active for this node). */
    bool IsActive() const { return !outpoints_.empty() || !scripts_.empty(); }

    std::size_t OutpointCount() const { return outpoints_.size(); }
    std::size_t ScriptCount() const { return scripts_.size(); }

    /** Add a single outpoint (txid:vout) to the freeze set. Cold path. */
    void AddOutpoint(const COutPoint& outpoint) { outpoints_.insert(outpoint); }

    /** Add a script (scriptPubKey of a frozen address) to the freeze set. Cold path. */
    void AddScript(const CScript& script) { scripts_.insert(script); }

    /** Exact outpoint match. Lock-free; safe on validation/mining threads. */
    bool ContainsOutpoint(const COutPoint& outpoint) const
    {
        return outpoints_.find(outpoint) != outpoints_.end();
    }

    /** Frozen-script match (for coins already swept to a named address). */
    bool ContainsScript(const CScript& script) const
    {
        return !scripts_.empty() && scripts_.find(script) != scripts_.end();
    }

    /**
     * @brief Seed the list from a file of "txid:vout" and/or address lines.
     *
     * Format (one entry per line):
     *   - "<64-hex-txid>:<vout>"  -> frozen outpoint
     *   - "<address>"             -> frozen script (scriptPubKey of the address)
     *   - lines starting with '#' and blank lines are ignored
     *   - inline "# comment" after an entry is ignored
     *
     * Address decoding uses the active CChainParams (Params()), so the file is
     * network-specific. Invalid lines are logged and skipped (fail-soft: a typo
     * never aborts startup, but it IS reported so the operator can fix it).
     *
     * @param path    Path to the blacklist file.
     * @param[out] errors  Human-readable messages for any skipped lines.
     * @return Number of entries successfully loaded.
     *
     * Cold path (startup only). Not thread-safe with concurrent lookups; call
     * before validation/mining threads start.
     */
    std::size_t LoadFromFile(const fs::path& path, std::vector<std::string>& errors);

    /**
     * @brief Add a single address string (decoded against active params).
     * @return true on success; on failure pushes a message into @p errors.
     */
    bool AddAddressString(const std::string& address, std::vector<std::string>& errors);

    /**
     * @brief Add a single "txid:vout" string.
     * @return true on success; on failure pushes a message into @p errors.
     */
    bool AddOutpointString(const std::string& token, std::vector<std::string>& errors);

private:
    std::set<COutPoint> outpoints_;
    std::set<CScript> scripts_;
};

/**
 * Process-wide singleton. Populated at startup from -blacklistoutpoints /
 * -blacklistaddr (see init.cpp::InitOutpointBlacklist), then read-only.
 */
extern OutpointBlacklist g_outpoint_blacklist;

/**
 * True if Layer 2 (consensus invalidity of blacklisted spends) is enabled on
 * this node. Default false. Set once at startup from -blacklistconsensus and is
 * only meaningful when the active-chain height has reached the activation
 * height (see init.cpp / the ConnectBlock call site). Read-only after startup.
 */
extern bool g_outpoint_blacklist_consensus;

/**
 * Activation height for Layer 2. Blocks at height >= this value are subject to
 * the consensus rule when g_outpoint_blacklist_consensus is true. Default 0
 * means "from genesis" but Layer 2 stays off unless its flag is set. Set once
 * at startup. Read-only after startup.
 */
extern int g_outpoint_blacklist_consensus_height;

// ===========================================================================
//  DETERMINISTIC TAINT-ROOT FREEZE  (incident 2026-05)
// ===========================================================================
//
// PURPOSE
// -------
// The OutpointBlacklist above is a *manually curated* list: an operator must
// enumerate every outpoint/address to freeze. Against a peel/fan-out launderer
// that splits coins across an unbounded number of fresh addresses, a static
// list is always one hop behind. The TaintSet closes that gap by computing the
// frozen set *by descent* from a fixed seed, deterministically, so that every
// honest node on the same canonical chain arrives at a bit-identical set with
// no per-operator configuration.
//
// SEED (the "taint root"), fixed at compile time -- see the constants below:
//   * Drain script: the P2PKH scriptPubKey the thief swept funds to. ANY output
//     paying this script at/after the theft block is a seed taint.
//   * Seed txids: the theft transaction (and any consolidation siblings). ALL
//     outputs of a seed txid are seed taints. (Belt-and-suspenders to the drain
//     script: even if a seed tx pays a different script, its outputs are tainted.)
//
// PROPAGATION RULE (deterministic, conservative -- over-freeze, never under):
//   A transaction is TAINTED if ANY of its inputs spends a tainted outpoint, OR
//   any of its outputs pays the seed script, OR its txid is a seed txid. If a
//   transaction is tainted, ALL of its outputs become tainted outpoints.
//
// COMPUTATION MODEL -- "backfill-to-H then static":
//   A per-network activation height H (Consensus::Params::nFreezeActivationHeight)
//   gates the whole mechanism. When the active chain first reaches height H, each
//   node walks its OWN canonical chain from nFreezeRootHeight up to and including
//   H, applying the propagation rule in block order, building the tainted COutPoint
//   set as of H. From H onward the set is STATIC: because a spend of a tainted
//   outpoint is rejected at/after H, the thief cannot move tainted coins, so the
//   set never needs to grow. Membership is then a simple O(log n) set lookup.
//
// DETERMINISM ARGUMENT (this is consensus-critical):
//   The computed set is a pure function of (canonical blocks [root..H], seed
//   constants). It depends on NOTHING else. Specifically:
//     1. Block iteration is by strictly increasing height over the ACTIVE chain
//        index (CChain::operator[]), so every node walks the same blocks in the
//        same order.
//     2. Within a block, transactions are visited in vtx order -- the canonical
//        order committed by the merkle root -- identical on every node.
//     3. Within a transaction, inputs and outputs are visited in serialized
//        order. Output index n is the canonical vout index.
//     4. The working/result containers are std::set<COutPoint>, whose iteration
//        is the total order defined by COutPoint::operator< (uint256::Compare,
//        a byte-wise comparison). No std::unordered_*; no hash-order dependence.
//     5. No floating point, no locale-dependent ops, no wall-clock, no RNG.
//   Therefore two honest nodes with the same canonical chain compute identical
//   sets. A divergence here would split the honest coalition, so the algorithm
//   is intentionally restricted to canonical, ordered, integer-only operations.
//
// REORG SAFETY:
//   The set is cached together with the block hash AT height H on the chain it
//   was computed from (computed_anchor_hash_). Membership is only trusted while
//   the active chain's block at H still hashes to that anchor. If a reorg changes
//   the block at H (or anywhere in [root..H]), the cache is invalidated and the
//   set is recomputed from scratch off the new canonical chain -- never mutated
//   incrementally across disconnects. Because H is chosen comfortably above the
//   tip at deploy time, the [root..H] window is buried and stable in practice;
//   the recompute path exists for correctness, not for the common case.
//
// GATING / DEFAULT-INERT:
//   nFreezeActivationHeight == 0 (or a tip below H) means the mechanism is fully
//   inert: a stock node with no config and tip < H is byte-identical to upstream.
//   The consensus reject only bites at/after H. The Layer-1 OutpointBlacklist
//   (-blacklistoutpoints / -blacklistaddr) is independent and keeps working.
//
// THREAD SAFETY:
//   The TaintSet is mutated only under cs_main (lazy compute / reorg recompute
//   happen on the validation thread inside ConnectBlock, which holds cs_main).
//   The block-template path (miner) also holds cs_main when it queries. Callers
//   MUST hold cs_main. This is asserted in the implementation.

/**
 * Compile-time seed for the deterministic taint freeze (incident 2026-05).
 *
 * These are FIXED and identical on every node: they are the consensus seed, not
 * operator configuration. Changing them changes the computed frozen set and is a
 * consensus change requiring a coordinated upgrade.
 */
namespace freeze_seed {
/** Drain address scriptPubKey, hex (P2PKH for KAezrjvRyUpd8Nwvshv9eLvZDWL46hLExd,
 *  hash160 25cc2352fd7ad476659aa18203967a6e2073adc98). Any output paying this
 *  script at/after the root height is a seed taint. */
constexpr char DRAIN_SCRIPT_HEX[] =
    "76a91425cc2352fd7ad476659aa18203967a6e2073adc988ac";

/** Seed txids: the theft tx and any consolidation siblings. ALL outputs of these
 *  txids are seed taints regardless of script. One 64-hex string per entry. */
constexpr const char* SEED_TXIDS[] = {
    // Theft transaction (block 54351).
    "53c99ba469c2955e6f8db21c4c0e8fa1fee4a78a693e27cb1cda2ed44d77d093",
};
} // namespace freeze_seed

/**
 * Deterministically-computed frozen outpoint set, built by descent from a fixed
 * seed (see the block comment above). Sibling to OutpointBlacklist: that class
 * is a manual list, this one is a computed closure.
 *
 * Lifetime: a single process-wide instance (g_taint_set). Computed lazily under
 * cs_main and cached; recomputed on a reorg that crosses the activation height.
 */
class TaintSet
{
public:
    TaintSet() = default;

    /** True once a set has been computed and not invalidated. */
    bool IsComputed() const { return computed_; }

    /** Number of tainted outpoints (0 if not yet computed). Diagnostic. */
    std::size_t Size() const { return tainted_.size(); }

    /** Activation height H this set was computed for (-1 if never). Diagnostic. */
    int ComputedHeight() const { return computed_height_; }

    /** Anchor block hash at height H the set was computed against. Diagnostic. */
    const uint256& ComputedAnchorHash() const { return computed_anchor_hash_; }

    /**
     * @brief Membership test: is @p outpoint frozen?
     *
     * Pure O(log n) lookup. The caller is responsible for having computed the set
     * (the validation/miner call sites compute-or-recompute first). Returns false
     * if the set has not been computed.
     *
     * Caller MUST hold cs_main (the set may be racing a reorg recompute otherwise).
     */
    bool Contains(const COutPoint& outpoint) const
    {
        return computed_ && tainted_.find(outpoint) != tainted_.end();
    }

    /** Read-only view of the computed set (for tests / diagnostics). */
    const std::set<COutPoint>& Outpoints() const { return tainted_; }

    /**
     * @brief Drop any computed state. Next compute starts from scratch.
     * Called on reorg invalidation. Caller MUST hold cs_main.
     */
    void Reset()
    {
        tainted_.clear();
        computed_ = false;
        computed_height_ = -1;
        computed_anchor_hash_.SetNull();
    }

    /**
     * @brief Adopt a freshly-computed set + its activation height + anchor hash.
     *
     * Used by the production chain-walk (CChainState::EnsureTaintSetComputed) to
     * publish a recomputed set, and by unit tests to inject a synthetic one.
     * Replaces any prior contents atomically from the caller's view. Caller MUST
     * hold cs_main (or be single-threaded, as in unit tests).
     */
    void Adopt(std::set<COutPoint> outpoints, int height, const uint256& anchor)
    {
        tainted_ = std::move(outpoints);
        computed_ = true;
        computed_height_ = height;
        computed_anchor_hash_ = anchor;
    }

    /**
     * @brief Apply the propagation rule for a single transaction against the
     *        current working set, returning whether the tx is tainted.
     *
     * Deterministic and side-effect-free except for inserting this tx's outputs
     * into @p working when the tx is tainted. Exposed as a free-standing static
     * so the walk loop AND the unit tests exercise the exact same logic.
     *
     * @param txid        Transaction id (used for the seed-txid rule + outpoints).
     * @param vin_prevouts Ordered input prevouts (for the "spends a tainted
     *                     outpoint" rule).
     * @param vout_scripts Ordered output scriptPubKeys (for the seed-script rule
     *                     and to know how many outpoints to taint).
     * @param seed_script The drain scriptPubKey (seed).
     * @param seed_txids  The set of seed txids.
     * @param[in,out] working The evolving tainted-outpoint set; this tx's outputs
     *                        are inserted iff the tx is tainted.
     * @return true iff the transaction is tainted.
     */
    static bool ApplyTxRule(const uint256& txid,
                            const std::vector<COutPoint>& vin_prevouts,
                            const std::vector<CScript>& vout_scripts,
                            const CScript& seed_script,
                            const std::set<uint256>& seed_txids,
                            std::set<COutPoint>& working);

private:
    std::set<COutPoint> tainted_;
    bool computed_ = false;
    int computed_height_ = -1;
    uint256 computed_anchor_hash_;
};

/**
 * Process-wide deterministic taint set. Computed lazily under cs_main at/after
 * the activation height; recomputed on a reorg crossing it. See TaintSet docs.
 */
extern TaintSet g_taint_set;

#endif // BITCOIN_POLICY_OUTPOINT_BLACKLIST_H
