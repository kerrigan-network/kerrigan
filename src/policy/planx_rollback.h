// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// ============================================================================
//  PLAN X -- CONTINGENCY ROLLBACK  (incident 2026-05)
// ============================================================================
//
// RECOVERY-RELEASE (PRODUCTION) BUILD -- community vote passed; the block hashes,
// rotated treasury/spork keys, recovery destination, and compromised set below
// are FINAL. Mainnet candidate pending the full-depth staging reorg proof + human
// review. Still default-inert until -activaterollback is passed.
//
// PURPOSE
// -------
// This module is the *armed-but-safed* contingency response to the 2026-05
// theft. It implements three coordinated consensus controls that, TOGETHER,
// let the network roll back to a pre-theft anchor, re-mine the missing blocks
// WITHOUT the theft transaction, and durably prevent the theft from ever being
// re-included -- while constraining the drained coins so that even with stolen
// keys the attacker can only ever move them to a fresh treasury address ("7b").
//
// It is DEFAULT-INERT IN AN UNFINALIZED BUILD and OFF MAINNET: with null block
// hashes / an empty compiled set, or on any network where consensus.nRollbackHeight
// is 0, every code path here is a no-op and the binary behaves exactly as upstream.
// In this release the block hashes are the FINAL real values (the community vote
// passed) and the recovery destination is a fresh treasury script, so the
// VALIDITY rules are LIVE on mainnet for every node running this build, with no
// launch flag required. The separate -activaterollback flag additionally performs
// the one-time in-process reorg on an already-synced node; the startup interlock
// (init.cpp) refuses that action while any rotated treasury slot / recovery script
// is still the placeholder sentinel.
//
// NOTE (recovery-release build): the treasury / recovery scripts baked into this
// build are the PRODUCTION rotated key sets (Set-A escrow+devfund/7b, Set-B
// founders/7a, Set-C spork; see chainparams.cpp + recovery-pubkeys.md). The
// interlock still guards against activating with any slot left at the placeholder
// sentinel, and additionally cross-checks recovery == devfund == escrow.
//
// CONSENSUS VALIDITY vs. THE ACTION FLAG
// --------------------------------------
// The consensus VALIDITY rules in this module -- the header-level disallow,
// descendant and checkpoint pins, and the recovery spend restriction -- are
// driven by COMPILED, PER-NETWORK STATE (the baked block hashes, the compiled
// compromised set, and consensus.nRollbackHeight / rollbackAnchorHash), NOT by a
// launch flag. Every node running this release therefore enforces IDENTICAL block
// validity: a fresh sync, or a "delete the block and chainstate databases and
// re-sync", converges on the recovered chain without an operator having to set any
// flag. These rules are mainnet-scoped by construction (nRollbackHeight is 0 on
// every other network, and the compiled addresses decode only under mainnet
// parameters) and inert in an unfinalized build (null hashes / empty set).
//
// The -activaterollback launch flag (g_activate_rollback, default false) gates
// ONLY the operational, one-time IN-PROCESS REORG performed at startup on an
// already-synced node (ActivatePlanXRollbackReorg in init.cpp), and the startup
// interlock that refuses to perform that reorg while any rotated treasury slot or
// the recovery destination is still the placeholder sentinel.
//
// Adopting this release is, by construction, a HARD FORK: a node that enforces
// these rules rejects the disallowed chain that a non-enforcing (un-upgraded) node
// accepts, so the release MUST be adopted by the network majority or the chain
// will split. This is the same posture as the existing Layer-2 -blacklistconsensus
// rule (see outpoint_blacklist.h) and is documented here so no one mistakes it for
// a soft, per-node preference. It is not.
//
// THE THREE CONTROLS
// ------------------
//   (1) CHECKPOINT PIN -- consensus.nRollbackHeight / rollbackAnchorHash.
//       The block at nRollbackHeight (54350 = theft block 54351 minus one) is the
//       required ancestor of the canonical chain. On mainnet (nRollbackHeight > 0)
//       with the anchor hash finalized (non-zero), a chain that does not contain
//       that exact block at that height is rejected. This pins the re-mined chain
//       to the last honest block before the theft. A matching hardcoded checkpoint
//       is added in chainparams.cpp in the same release.
//
//   (2) DISALLOW THE ATTACK BLOCK -- DEFAULT_DISALLOWED_BLOCKHASH.
//       The theft block (placeholder all-zero; human fills the real block-54351
//       hash) is rejected outright, AND any block whose ancestry includes it is
//       rejected. This is what makes the rollback DURABLE: it is not enough to
//       prefer the re-mined chain by work; we must make the theft chain
//       permanently invalid so it can never be re-organized back in, no matter
//       how much hashpower an attacker brings. Enforced in the header-acceptance
//       path (block hash match) and the ancestry path (pprev chain contains the
//       disallowed hash) -- see IsDisallowedBlockHash / the AcceptBlock site.
//
//   (3) ONLY-TO-7B SPEND RESTRICTION -- g_compromised_recovery_set +
//       DEFAULT_RECOVERY_SCRIPT_7B.
//       A curated set of compromised outpoints/scripts (the theft tx inputs and
//       the drained addresses). RULE: a transaction that spends ANY output in this
//       set is INVALID unless EVERY non-change output pays the recovery script (the
//       fresh "7b" treasury). "Change" means an output that itself pays back into
//       the compromised set (so a partial sweep that leaves a remainder in a
//       compromised wallet is still legal, as long as the moved portion goes to
//       7b). Effect: after the rollback the drained coins sit back in the
//       compromised wallets; an attacker holding the stolen keys can only ever push
//       them to 7b, while the legitimate holders of the real keys sweep them to 7b
//       at leisure. Modeled on the growth-escrow guard: mempool PreChecks reject +
//       ConnectBlock reject.
//
// RELATIONSHIP TO THE EXISTING FREEZE (outpoint_blacklist.h)
// ----------------------------------------------------------
// The deterministic taint freeze freezes spends of tainted coins (they cannot
// move at all). PLAN X is the heavier, rollback-coupled response: it rewinds to
// before the theft, bans the theft block, and -- instead of fully freezing --
// channels the recovered coins to a single safe destination. The two are
// independent and separately gated; PLAN X does not modify the freeze.
//
// THREAD SAFETY
// -------------
// g_activate_rollback, the constants, and g_compromised_recovery_set are set
// ONCE at startup (before networking/validation threads start) and thereafter
// read-only. Lookups are lock-free and safe from validation/mining threads.
// If runtime mutation is ever added, add a lock first.

#ifndef BITCOIN_POLICY_PLANX_ROLLBACK_H
#define BITCOIN_POLICY_PLANX_ROLLBACK_H

#include <consensus/amount.h>        // CAmount, COIN
#include <primitives/transaction.h> // COutPoint, CTransaction
#include <script/script.h>          // CScript
#include <uint256.h>                // uint256, uint160

#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <vector>

class CCoinsViewCache;

// ===========================================================================
//  Compile-time constants -- FINALIZED for the recovery release (production)
// ===========================================================================
namespace planx {

/**
 * Required-ancestor (checkpoint pin) height: the last honest block before the
 * theft (theft block 54351 minus one). FINAL.
 */
constexpr int DEFAULT_ROLLBACK_HEIGHT = 54350;

/**
 * Hash of the block at DEFAULT_ROLLBACK_HEIGHT on the canonical (pre-theft)
 * chain. This is the FINAL, real block-54350 hash (the last honest block before
 * the theft); baked in at recovery-release assembly. On mainnet (where
 * consensus.nRollbackHeight > 0) the checkpoint-pin rule requires the chain to
 * contain exactly this block at DEFAULT_ROLLBACK_HEIGHT. A null (all-zero) value
 * would be treated as "not finalized -> inert"; this value is non-null, so the
 * pin is live on mainnet.
 *
 * FINAL VALUE (community vote passed) -- this hash is not a placeholder.
 */
constexpr char DEFAULT_ROLLBACK_ANCHOR_HASH[] =
    "35bdbd05e21cd0e9321b9406683efe77b52c32ae50dbbf9444bef20d55ce7aee";

/**
 * Hash of the theft block (height 54351). This is the FINAL, real block-54351
 * hash; baked in at recovery-release assembly. On mainnet (where the header
 * enforcement is active), this block AND any block whose ancestry includes it are
 * rejected -- this is what pins the re-mined chain and makes the rollback durable.
 * A null value would be treated as "not finalized -> inert"; this value is
 * non-null, so the disallow rule is live on mainnet.
 *
 * FINAL VALUE (community vote passed) -- this hash is not a placeholder.
 */
constexpr char DEFAULT_DISALLOWED_BLOCKHASH[] =
    "00000000000002a24a4f88a39fe12bc5fd895c571af884d7eae5bfe21a0429a9";

/**
 * The fresh treasury "7b" recovery scriptPubKey, hex (the serialized P2SH
 * scriptPubKey "a914<hash160(redeemScript)>87" of the fresh Set-A multisig that
 * the rotated devFundPaymentScript / growthEscrowScript also use). When the gate
 * is on and the compromised set is non-empty, the only-to-7b rule requires every
 * non-change output of a compromised-coin spend to pay exactly this script. An
 * empty value would be treated as "not finalized -> inert"; this value is
 * non-empty.
 *
 * ============================================================================
 *  PRODUCTION KEYSET (recovery rotation, incident 2026-05)
 * ----------------------------------------------------------------------------
 *  The value below is the P2SH scriptPubKey of the production Set-D 2-of-3
 *  multisig (address 7XRanBZwu6RNPPyPzPmFkrPntUwrseHdbc, hash160 3705ba...),
 *  derived offline via `createmultisig 2 [D1,D2,D3]` over Set-D (canonical
 *  redeemScript, key order per recovery-pubkeys.md). Equals
 *  consensus.devFundPaymentScript; explicitly NOT growthEscrowScript (the
 *  Set-A 7g script a9149835c3ef...87), which would subject recovery to the
 *  escrow lock.
 *
 *  Set-D redeemScript:
 *    522102127f6236da2f3b8292e1e340df703a2c1589d48cec7b3419d8c99c3193befa97
 *    210249c8aaf5465cf233354009d907179b4bc8a55f5809d9f5a0fb706e8537160ecd
 *    21026b20a3200b07d1691bd4575c83e5e0d1d67324908c3c65d6771e56cd3c51292853ae
 * ============================================================================
 */
constexpr char DEFAULT_RECOVERY_SCRIPT_7B[] =
    "a9143705ba0547a9d275c2cb6e6fa9d665061aa95fa687"; // Set-D P2SH (7XRanBZwu6RNPPyPzPmFkrPntUwrseHdbc)

// v1.2.1/v1.2.2 recovery destination (Set-A 7g). Accepted as a legitimate
// recovery output only for blocks STRICTLY below RECOVERY_V2_ACTIVATION_HEIGHT;
// at/above, only DEFAULT_RECOVERY_SCRIPT_7B is valid. Keeps the two existing
// historical sweeps (h=54361, 54364) valid without allowing future sweeps to
// land at the consensus-locked growth-escrow address.
constexpr char LEGACY_RECOVERY_SCRIPT_V1[] =
    "a9149835c3ef5977c827045edb682d113761856deb5887"; // Set-A P2SH (7gHTsab3...)
// Kept at 54500 to preserve consensus parity with v1.2.3/v1.2.4. Pushing the
// gate forward in v1.2.5 would silently accept blocks at heights 54500-NEW_GATE
// that v1.2.3/v1.2.4 reject, causing a release-boundary chain split. The chain
// is already past 54500 on every healthy v1.2.3+ node, so no forward "exposure
// window" exists to widen.
constexpr int  RECOVERY_V2_ACTIVATION_HEIGHT = 54500;

/**
 * Placeholder sentinel scriptPubKey (hex). A rotated treasury slot or the
 * recovery script that still equals this exact byte string is, by definition,
 * UNFINALIZED. The InitPlanXRollback interlock (see init.cpp) refuses to start
 * under -activaterollback if any consulted slot equals this sentinel (or is an
 * empty/all-zero placeholder), so the binary can never activate the rollback
 * while pointing recovery at an unfinalized address.
 *
 * The sentinel is a deliberately-unspendable P2SH-shaped script whose hash160 is
 * all-0xEE ("EE" == "rEplacE mE"): valid script encoding (so it parses), but it
 * corresponds to no real, controllable address. It is NEVER a legitimate target.
 *
 *   OP_HASH160 <20 bytes 0xEE> OP_EQUAL  ==  a914 eeee...ee 87
 */
constexpr char PLACEHOLDER_SENTINEL_SCRIPT[] =
    "a914eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee87";

/**
 * Claim-back OP_RETURN marker magic ("KRCP" = Kerrigan Recovery Claim Pubkey).
 *
 * When a masternode operator sweeps a compromised collateral to the recovery
 * destination via the unlockmasternode RPC, the tx may carry one OP_RETURN
 * output whose payload is:
 *
 *   <MAGIC:4> <operator-pubkey-hash:20> <nonce:8>
 *
 * Total payload: 32 bytes (well within MAX_OP_RETURN_RELAY=83). The marker is
 * NOT consensus -- the only-to-7b rule treats every IsUnspendable() output as a
 * marker and ignores it. The marker exists so an off-chain governance process
 * can later identify the operator that swept a given collateral and disburse
 * replacement value from the devfund (Set-D) under proposal review.
 *
 * The operator pubkey hash is HASH160 of a pubkey they control (passed to the
 * RPC, or generated by the wallet and returned in the result). Pubkey hash
 * (not the full pubkey) is used to keep the payload short -- the operator
 * proves ownership at claim time by presenting the pubkey + a signature over
 * a governance-supplied challenge. The 8-byte nonce separates multiple
 * collateral sweeps by the same operator so each claim has a distinct on-chain
 * marker.
 *
 * Magic in transmission order is 'K','R','C','P' (0x4b,0x52,0x43,0x50).
 */
constexpr uint32_t RECOVERY_CLAIM_MARKER_MAGIC = 0x4b524350; // "KRCP"
constexpr std::size_t RECOVERY_CLAIM_PUBKEYHASH_LEN = 20;
constexpr std::size_t RECOVERY_CLAIM_NONCE_LEN = 8;
constexpr std::size_t RECOVERY_CLAIM_PAYLOAD_LEN = 4 + RECOVERY_CLAIM_PUBKEYHASH_LEN + RECOVERY_CLAIM_NONCE_LEN;

/**
 * Maximum fee a compromised-coin sweep may leave behind.
 *
 * The only-to-7b rule constrains a compromised-coin spend's DESTINATIONS, but a
 * destination-only filter still leaks value via the FEE: an attacker spends a
 * large compromised input, pays a dust output to 7b, and burns the remainder as
 * fee to a (self-mined / colluding) miner. To close that leak, a compromised-coin
 * spend must channel essentially the ENTIRE protected value to the 7b recovery
 * script: the value paid to 7b must be at least (sum of compromised input value)
 * minus this tiny tolerance. The tolerance only exists to allow a realistic
 * relay/mining fee on the sweep itself; it is deliberately small (a full sweep
 * cannot bleed more than this to fee).
 *
 * 0.001 KRGN. CAmount is in satoshis (1 KRGN == COIN).
 */
constexpr CAmount MAX_RECOVERY_FEE = COIN / 1000; // 0.001 KRGN (100000 sat)

/**
 * Seed members of the compromised recovery set, as "txid:vout" strings.
 *
 * The drained coins are covered by the compromised-ADDRESS list below
 * (SEED_COMPROMISED_ADDRESSES): a script-based entry covers any UTXO paying a
 * compromised address (now or later), which is strictly broader than the exact
 * pre-theft outpoints and survives any re-derivation of those outpoints after the
 * rollback. This outpoint list is therefore left empty for the recovery release.
 * The set is defined entirely by these compiled constants; there are no per-node
 * (operator-supplied) additions, so consensus validity is identical on every node.
 *
 * INCIDENT FACTS (provenance):
 *   - Theft consolidation txs (block 54351), all paying the drain address
 *     KAezrjvRyUpd8Nwvshv9eLvZDWL46hLExd:
 *       53c99ba469c2955e6f8db21c4c0e8fa1fee4a78a693e27cb1cda2ed44d77d093 (bulk)
 *       4b43d090400b7bb14aff154d62f27946028041a956526ce0c05c4fa3064e88fe
 *       a910ee0e5e73ffff947471403c8f0eb2a698c5067cf0d127ff528b6ef7654284
 *       0b93a4d4190830e4cc37b8f231dbe5bd0f7f2914d0050772572b3352833059fd
 *     Their inputs are the 48 drained addresses below. After the rollback to block
 *     54350 those coins sit back in the compromised wallets and are constrained by
 *     only-to-7b via the address (script) match.
 */
constexpr const char* SEED_COMPROMISED_OUTPOINTS[] = {
    // (empty -- coverage is via SEED_COMPROMISED_ADDRESSES; see provenance above)
};

/**
 * The compromised (drained) addresses (50 entries). The first 48 are the input
 * addresses of the 4 theft consolidation txs in block 54351 (incident 2026-05);
 * the last 2 are the OLD pre-rotation treasury P2SH addresses whose 2-of-3 key
 * sets are likewise compromised. At startup InitPlanXRollback decodes each to its
 * scriptPubKey and seeds g_compromised_recovery_set (matched via ContainsScript),
 * unconditionally, since the spend restriction is consensus validity. A spend that
 * touches any of these is valid ONLY if it sweeps fully-transparently to the Set-D
 * recovery script (only-to-7b -- the post-v1.2.3 destination is the Set-D devfund
 * P2SH 7XRanBZwu6RNPPyPzPmFkrPntUwrseHdbc, a9143705ba...87). Every input of those
 * 4 txs is the affected operator's own coin, so there is no innocent-party input
 * in this set.
 *
 * Most entries are P2PKH ('K'-prefix) wallet addresses; the last two are the OLD
 * (pre-rotation) treasury P2SH ('7'-prefix) addresses whose 2-of-3 key sets are
 * also compromised. The Set-D RECOVERY destination
 * (7XRanBZwu6RNPPyPzPmFkrPntUwrseHdbc, P2SH a9143705ba...87) is the rotated FRESH
 * script and is NOT a member of this set (verified at finalization; the
 * InitPlanXRollback interlock fails closed if it ever were). The Set-A
 * destination 7gHTsab3... / a9149835c3ef...87 is the LEGACY recovery target used
 * by v1.2.1/v1.2.2 sweeps below RECOVERY_V2_ACTIVATION_HEIGHT; it is consensus-
 * locked as growthEscrowScript and is NOT the current recovery destination.
 */
constexpr const char* SEED_COMPROMISED_ADDRESSES[] = {
    "K7qS3cmteTYfCTeefwCoTCAtJ7hb3zFFdt", "K8CEQAKusgVhXrvNj1mE1rp1nbEHguoumT",
    "K8pe8RxTVZoYj22Z6hyMqaVoxLccr18EQp", "K9A8TYFikmyExVSXfGF7ERH63PfRVWku3k",
    "K9qu3EWnRzjvQrQEKqZ38xhQF6WGGLitQw", "K9ycM8RoLmE85zpC83XHHkyCqoLGyStCsC",
    "KAKxAvoDDrrKSzBD3n5rgY6ZSVRbHzhB7v", "KAcizcVPMaVeb27G6QNYhGaMYT6UNhHy5o",
    "KAfq16P6iBHPtGWpPkEYb2ackXaPiE7sfp", "KALVbP4SZw1btvZFAZ5TojMgMTcpRmUs8j",
    "KB9tj8kP3WLBn3ys6bRbhKrpRLHWvzoMfV", "KBbzU3cP2hYGc1U1x5hnDF9UC8Z9XsMDQs",
    "KBvGd7bYytn4ed23sswtSKez1sH4Zemowo", "KCywQVkpkUM8a3o9dSqmPbR6m7TDvc6kUX",
    "KDgeDwnnkvedoZQdPLH5EHcD2emfCknRof", "KDiwbpsvR6LqNh6b1RSfXF3i3pBV2kwU8h",
    "KDx3JbSbRDANZQNDomWWvFSvF32QCYyYSF", "KFK9ZrD2fFeMf9iWNAVS1iQuYAXrRxEbUZ",
    "KG1LXs17qyeNzfjkxiVYLdjpD5ogn65t14", "KGKEQFKfHKZQLwEQcwNHDvBYrv1mBU6Zgh",
    "KGj5r6dTbNwjsnmfavFVwsR2yh73fVj5hA", "KH9AkBHBfZMJKGzxBTR3qcHNyMoiFrNWfW",
    "KHd1eJfUWnYKS6HpAuKA252eoHgwMGCPMy", "KHnTNGwPiMN1Ys4KpcmHrTtgjSJUbsbioL",
    "KJ5gPFhmR6672ZhyVWqMGZGWYY8LjxECkn", "KJMrhzRksKkCDugdW8XeHKaPpqZHzwWywa",
    "KJUdeuBNbd8hD9in8FF1GfaDHjNqayKTYC", "KJcLnd9AShj5QuR3XBHGh2M1q7Cdev4def",
    "KK5XkQzPjafGLf7LPebS8Dh97eMC8azFvt", "KMQVittEhSjiGcgznS1QfDwmRiYrzkSxCU",
    "KN2VDChSoamXNe74eDpS73BrExfqHmLkTG", "KNA3TcQNZLbXFvSR3g5QhqPJtu1UbLCWhU",
    "KNNJHkYGUQpA82iFTxTFp2ntqw7EoQ41p3", "KNinGd6io7Mnqw2qwNGk6p8oTcQsAGbfaA",
    "KNpkgVMkTjGMKRPHgjotAwiST65d25XGM1", "KR9wFLRH71a7vHdWSCUgKUa5jWG5mfGqxf",
    "KRhQnCgwnWkXAqscyACdtxvtTUrcTueTJd", "KRmMjr7dL7aHNc6btKrF2KgYXr1kEPbWur",
    "KSAA3VEXms8HCug4rKadBYUBGJ2hzkELcH", "KSBLDwEFszkJEddktZxDvJMt15oYshzjeB",
    "KScKFbdELTzwib8zBMufhjZNySMtn4K8Kv", "KU1ByXazkFjuynhnue8cWsL8rZnpYDB1r6",
    "KUJTHn42WsDhhK5QApC4Fyji2EhBJCp3fB", "KURcTPweLSGwKGmiRvzaAZsGfgbNzH8mou",
    "KVyASajCNPdM9BYzi3nzRk2b93R1Gf9y67", "KW9bwdmkuYL31Mv6fhZ1BkydEF8y12JV4F",
    "KWAbe7kKwJmJ4Q93wH5jHAd4hh5vNASq5R", "KWLyBeUZNPyAHLfWiqC9JZ66NBvc7WkGHr",
    // OLD (pre-rotation) treasury addresses whose 2-of-3 keys are also
    // compromised. Adding them constrains any spend that touches the restored OLD
    // founders/devfund coins under the only-to-7b sweep rule. Verified against
    // release-v1.2.0-freeze:src/chainparams.cpp (the pre-rotation founders/devfund
    // scripts) and the "PRIOR (COMPROMISED) VALUES" comment block in chainparams:
    //   OLD founders (7a) 7aP2bhZGE6mT6Ae7DhPAbWz54gZahCqHP8 -> P2SH a914577268b060369798d215b6f278efb2cd72fa773487
    //   OLD devfund  (7b) 7bMQKKigBdndVPqitNQuzUXPMVcTqjWHP5 -> P2SH a914621bd4ef835272a795b46babe03a1f5559e0b51e87
    // Neither equals the rotated Set-D recovery destination (a9143705ba...87),
    // so the InitPlanXRollback self-lock interlock still passes.
    "7aP2bhZGE6mT6Ae7DhPAbWz54gZahCqHP8", // OLD founders (7a) 2-of-3 P2SH
    "7bMQKKigBdndVPqitNQuzUXPMVcTqjWHP5", // OLD devfund  (7b) 2-of-3 P2SH
};

} // namespace planx

// ===========================================================================
//  Compromised recovery set (the only-to-7b constraint's membership source)
// ===========================================================================

/**
 * Immutable set of compromised outpoints and compromised scriptPubKeys.
 *
 * A transaction "touches" the compromised set if it spends an outpoint in the
 * set, OR spends a coin whose scriptPubKey is in the set. Such a transaction is
 * subject to the only-to-7b restriction.
 *
 * Time complexity: O(log n) per membership test (std::set). n is tiny (the
 * theft's inputs + a handful of drained addresses), so this is never a hot path
 * concern even though it is consulted per-input during block connect.
 */
class CompromisedRecoverySet
{
public:
    CompromisedRecoverySet() = default;

    /** True if any entry is loaded. */
    bool IsActive() const { return !outpoints_.empty() || !scripts_.empty(); }

    std::size_t OutpointCount() const { return outpoints_.size(); }
    std::size_t ScriptCount() const { return scripts_.size(); }

    /** Add a compromised outpoint (txid:vout). Cold path (startup only). */
    void AddOutpoint(const COutPoint& outpoint) { outpoints_.insert(outpoint); }

    /** Add a compromised scriptPubKey (a drained address). Cold path. */
    void AddScript(const CScript& script) { scripts_.insert(script); }

    /** Exact outpoint match. Lock-free; safe on validation/mining threads. */
    bool ContainsOutpoint(const COutPoint& outpoint) const
    {
        return outpoints_.find(outpoint) != outpoints_.end();
    }

    /** Compromised-script match. */
    bool ContainsScript(const CScript& script) const
    {
        return !scripts_.empty() && scripts_.find(script) != scripts_.end();
    }

    /** Read-only views (tests / diagnostics). */
    const std::set<COutPoint>& Outpoints() const { return outpoints_; }
    const std::set<CScript>& Scripts() const { return scripts_; }

private:
    std::set<COutPoint> outpoints_;
    std::set<CScript> scripts_;
};

// ===========================================================================
//  Process-wide state (set ONCE at startup, then read-only)
// ===========================================================================

/**
 * The PLAN X action flag. False by default. Set once at startup from
 * -activaterollback. It gates ONLY the one-time in-process reorg and the startup
 * interlock, NOT consensus validity (the validity rules are driven by the compiled
 * per-network state below and in chainparams). Read-only after startup.
 */
extern bool g_activate_rollback;

/**
 * The compromised recovery set, populated UNCONDITIONALLY at startup from
 * planx::SEED_COMPROMISED_ADDRESSES / SEED_COMPROMISED_OUTPOINTS plus any
 * operator-supplied entries, because the only-to-7b rule is consensus validity and
 * must not depend on a launch flag. Empty (and the rule inert) off mainnet, since
 * the seed addresses decode only under mainnet parameters. Read-only after startup.
 */
extern CompromisedRecoverySet g_compromised_recovery_set;

// ===========================================================================
//  Pure predicates (consensus core -- exercised directly by unit tests)
// ===========================================================================

/**
 * @brief The compiled disallowed block hash, or a null uint256 if the
 *        placeholder is still all-zero (i.e. the rule is inert).
 *
 * Pure; no global state. Returns uint256() (null) for the zero placeholder so
 * callers can cheaply test IsNull() to mean "rule not finalized -> inert".
 */
uint256 PlanXDisallowedBlockHash();

/**
 * @brief The compiled required-ancestor (checkpoint pin) hash, or null if the
 *        placeholder is still all-zero (rule inert).
 */
uint256 PlanXRollbackAnchorHash();

/**
 * @brief The recovery "7b" scriptPubKey, or an empty CScript if the placeholder
 *        is still empty (rule inert).
 */
CScript PlanXRecoveryScript();

/**
 * @brief The placeholder-sentinel scriptPubKey (planx::PLACEHOLDER_SENTINEL_SCRIPT).
 *
 * Returned as a parsed CScript so callers (the InitPlanXRollback interlock and
 * its unit test) can compare a candidate slot against it directly. Pure; O(1).
 */
CScript PlanXPlaceholderSentinelScript();

/**
 * @brief Is @p script an UNFINALIZED placeholder for a rotated treasury / the
 *        recovery destination?
 *
 * True if @p script is empty OR equals the placeholder sentinel
 * (PlanXPlaceholderSentinelScript()). Used by the startup interlock to refuse to
 * activate the rollback while any consulted slot is unfinalized. Pure; O(1).
 */
bool PlanXScriptIsPlaceholder(const CScript& script);

/**
 * @brief Is @p hash the disallowed (theft) block hash?
 *
 * Returns false when the disallowed-hash placeholder is still all-zero (an
 * unfinalized build). Driven by the compiled hash, independent of the action flag;
 * the caller is mainnet-scoped. Pure; O(1).
 */
bool PlanXIsDisallowedBlockHash(const uint256& hash);

/**
 * Result of classifying a transaction's relationship to the Sapling shielded
 * pool.
 *
 * All fields are derived purely from the transaction's own bytes (its nType and
 * deserialized Sapling payload). Default-constructed value (all zero/false)
 * describes a pure-transparent transaction.
 */
struct ShieldedDirection {
    /** True iff the tx is nType == TRANSACTION_SAPLING with a well-formed payload. */
    bool is_sapling{false};
    /** Number of shielded spends (notes leaving the pool -- the OUT direction). */
    std::size_t spends{0};
    /** Number of shielded outputs (notes entering the pool -- the IN direction). */
    std::size_t outputs{0};
    /** Net value balance: > 0 = value leaves pool (z->t); < 0 = value enters (t->z). */
    CAmount value_balance{0};

    /** OUT direction: the tx spends shielded notes (the airtight exit predicate). */
    bool SpendsShielded() const { return spends > 0; }

    /** Strict z->t: spends shielded notes AND net value leaves the pool. */
    bool UnshieldsValue() const { return spends > 0 && value_balance > 0; }
};

/**
 * @brief Classify @p tx with respect to the Sapling shielded pool.
 *
 * Pure function. For a non-Sapling tx, returns a default-constructed result
 * (is_sapling == false, everything else zero). For a Sapling tx whose payload
 * fails to deserialize, returns is_sapling == false as well (a malformed payload
 * is rejected elsewhere by the normal Sapling validation; this function declines
 * to classify it rather than guess). For a well-formed Sapling tx, fills in the
 * spend/output counts and value balance from SaplingTxPayload.
 *
 * Lives here (not under a separate freeze header) because its only production
 * caller is PlanXTxHasShieldedComponent below and its only test caller is the
 * planx test suite. Pure; thread-safe (no shared state); O(1) plus one payload
 * parse.
 */
ShieldedDirection ClassifyShieldedDirection(const CTransaction& tx);

/**
 * @brief Does @p tx carry ANY Sapling shielded component?
 *
 * Reuses the canonical Sapling-payload classifier above
 * (ClassifyShieldedDirection), so this is bit-for-bit consistent with how the
 * rest of consensus parses the payload. A tx "has a shielded component" iff it
 * is a well-formed TRANSACTION_SAPLING tx with any shielded spend OR any
 * shielded output OR a non-zero valueBalance (i.e. it moves value across the
 * transparent<->shielded boundary, or churns notes inside the pool). A
 * pure-transparent tx (and a Sapling tx with an unparseable payload, which is
 * rejected elsewhere) returns false.
 *
 * This is the predicate that closes the t->z shield bypass: a compromised-coin
 * spend that shields value into the Sapling pool has an empty (or marker-only)
 * vout, so the destination-only loop would never see a forbidden output. Treating
 * any shielded component on a compromised-touching tx as forbidden forces the
 * recovered coins to move ONLY via a fully-transparent sweep to 7b.
 *
 * Pure; never throws. O(1) plus one payload parse.
 */
bool PlanXTxHasShieldedComponent(const CTransaction& tx);

/**
 * @brief The only-to-7b predicate -- the heart of control (3).
 *
 * Given a transaction and the UTXO view it spends from, decide whether the tx is
 * VALID under the only-to-7b restriction. The decision:
 *
 *   1. If the recovery set is empty (which is also the rule's mainnet scoping), or
 *      the recovery script is unfinalized (empty/placeholder) -> ALWAYS VALID (rule
 *      inert); returns true. Independent of the action flag.
 *   2. Determine whether the tx TOUCHES the compromised set (spends a
 *      compromised outpoint, or a coin paying a compromised script). If it does
 *      NOT touch the set -> VALID (the rule ignores non-compromised spends).
 *   3. If it DOES touch the set, the tx is VALID iff ALL of the following hold
 *      (a compromised coin may move ONLY via a full, fully-transparent sweep to
 *      7b):
 *        (3a) the tx has NO Sapling shielded component
 *             (PlanXTxHasShieldedComponent == false). A t->z shield (empty vout,
 *             value carried in the Sapling payload) would otherwise slip past the
 *             destination loop; shielding a compromised coin is forbidden.
 *        (3b) no change-back: EVERY non-marker output pays exactly the recovery
 *             "7b" script. Paying back into the compromised set is NOT permitted --
 *             a "change" allowance would let an attacker holding all the keys
 *             shuffle value among the compromised addresses indefinitely, so a full
 *             sweep to 7b is forced. OP_RETURN / provably-unspendable outputs
 *             (markers) are still ignored.
 *        (3c) fee bound: the value paid to the 7b script is at least
 *             (sum of compromised input value) - planx::MAX_RECOVERY_FEE. This
 *             kills the fee-bleed leak (dust to 7b + large fee captured via a
 *             self-mined block).
 *      Any violation -> INVALID.
 *
 * This function is PURE w.r.t. its inputs (it reads only @p tx, @p view, and the
 * startup-fixed globals/constants) and is the single source of truth shared by
 * the mempool PreChecks site, the ConnectBlock site, and the unit tests.
 *
 * @param tx     The transaction to test.
 * @param view   The UTXO view providing the spent coins' scriptPubKeys.
 * @param[out] reason  On a VALID==false return, set to a short reject reason
 *                     token (may be nullptr if the caller does not need it).
 * @param nHeight  Height of the block being validated (ConnectBlock) or
 *                 tip-height + 1 (mempool PreChecks). Below the chainparams
 *                 nPlanXRecoveryActivationHeight the rule is inert (returns
 *                 true) so historical pre-activation blocks replay during
 *                 fresh IBD. 0 disables the height gate (unit-test path only;
 *                 all production callers thread the real height).
 * @return true if the tx is permitted under the only-to-7b restriction.
 *
 * Caller MUST hold cs_main when @p view is the live chainstate view (it is read
 * during validation). Pure/safe for unit tests with a standalone view.
 */
bool PlanXOnlyToRecoveryAllowed(const CTransaction& tx,
                                const CCoinsViewCache& view,
                                const char** reason,
                                int nHeight);

/**
 * @brief Build a claim-back marker scriptPubKey for the unlockmasternode RPC.
 *
 * Returns OP_RETURN <RECOVERY_CLAIM_MARKER_MAGIC LE> <pubkey-hash> <nonce>.
 * The resulting script is provably unspendable (IsUnspendable() == true) so it
 * is ignored by the only-to-7b destination loop. Pure; no globals consulted.
 *
 * @param operator_pubkey_hash  HASH160 of an operator-controlled pubkey.
 * @param nonce                 8 random bytes that separate multiple sweeps
 *                              by the same operator.
 * @return The OP_RETURN scriptPubKey, or an empty CScript if the nonce length
 *         is wrong (defensive; the caller's nonce vector is always 8 bytes).
 */
CScript PlanXBuildClaimBackMarker(const uint160& operator_pubkey_hash,
                                  const std::vector<unsigned char>& nonce);

/**
 * @brief Parsed claim-back marker payload.
 */
struct ClaimBackMarker {
    uint160 pubkey_hash;
    std::vector<unsigned char> nonce; // exactly RECOVERY_CLAIM_NONCE_LEN bytes
};

/**
 * @brief Parse a candidate scriptPubKey as a claim-back marker.
 *
 * Returns std::nullopt if @p script is not OP_RETURN with a payload of exactly
 * RECOVERY_CLAIM_PAYLOAD_LEN bytes starting with RECOVERY_CLAIM_MARKER_MAGIC
 * (little-endian). Pure; intended for off-chain governance tooling and tests.
 */
std::optional<ClaimBackMarker> PlanXParseClaimBackMarker(const CScript& script);

#endif // BITCOIN_POLICY_PLANX_ROLLBACK_H
