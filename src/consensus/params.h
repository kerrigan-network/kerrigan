// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Copyright (c) 2014-2025 The Dash Core developers
// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KERRIGAN_CONSENSUS_PARAMS_H
#define KERRIGAN_CONSENSUS_PARAMS_H

#include <consensus/amount.h>
#include <uint256.h>
#include <llmq/params.h>

#include <limits>
#include <vector>

namespace Consensus {

/**
 * A buried deployment is one where the height of the activation has been hardcoded into
 * the client implementation long after the consensus change has activated. See BIP 90.
 */
enum BuriedDeployment : int16_t {
    // buried deployments get negative values to avoid overlap with DeploymentPos
    DEPLOYMENT_HEIGHTINCB = std::numeric_limits<int16_t>::min(),
    DEPLOYMENT_DERSIG,
    DEPLOYMENT_CLTV,
    DEPLOYMENT_BIP147,
    DEPLOYMENT_CSV,
    DEPLOYMENT_DIP0001,
    DEPLOYMENT_DIP0003,
    DEPLOYMENT_DIP0008,
    DEPLOYMENT_DIP0020,
    DEPLOYMENT_DIP0024,
    DEPLOYMENT_BRR,
    DEPLOYMENT_V19,
    DEPLOYMENT_V20,
    DEPLOYMENT_MN_RR,
    DEPLOYMENT_WITHDRAWALS,
    DEPLOYMENT_SAPLING,
    DEPLOYMENT_HMP,
};
constexpr bool ValidDeployment(BuriedDeployment dep) { return dep <= DEPLOYMENT_HMP; }

enum DeploymentPos : uint16_t {
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_V24,         // Deployment of doubling withdrawal limit, extended addresses
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in deploymentinfo.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};
constexpr bool ValidDeployment(DeploymentPos dep) { return dep < MAX_VERSION_BITS_DEPLOYMENTS; }

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit{28};
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime{NEVER_ACTIVE};
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout{NEVER_ACTIVE};
    /** If lock in occurs, delay activation until at least this block
     *  height.  Note that activation will only occur on a retarget
     *  boundary.
     */
    int min_activation_height{0};
    /** The number of past blocks (including the block under consideration) to be taken into account for locking in a fork. */
    int64_t nWindowSize{0};
    /** A starting number of blocks, in the range of 1..nWindowSize, which must signal for a fork in order to lock it in. */
    int64_t nThresholdStart{0};
    /** A minimum number of blocks, in the range of 1..nWindowSize, which must signal for a fork in order to lock it in. */
    int64_t nThresholdMin{0};
    /** A coefficient which adjusts the speed a required number of signaling blocks is decreasing from nThresholdStart to nThresholdMin at with each period. */
    int64_t nFalloffCoeff{0};
    /** This value is used for forks activated by masternodes.
      * false means it is a regular fork, no masternodes confirmation is needed.
      * true means that a signalling of masternodes is expected first to determine a height when miners signals are matter.
      */
    bool useEHF{false};

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;

    /** Special value for nStartTime indicating that the deployment is never active.
     *  This is useful for integrating the code changes for a new feature
     *  prior to deploying it on some or all networks. */
    static constexpr int64_t NEVER_ACTIVE = -2;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    uint256 hashDevnetGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Block height at which masternode payments begin */
    int nMasternodePaymentsStartBlock;
    int nMasternodePaymentsIncreaseBlock;
    int nMasternodePaymentsIncreasePeriod; // in blocks
    int nInstantSendConfirmationsRequired; // in blocks
    int nInstantSendKeepLock; // in blocks
    int nBudgetPaymentsStartBlock;
    int nBudgetPaymentsCycleBlocks;
    int nBudgetPaymentsWindowBlocks;
    int nSuperblockStartBlock;
    uint256 nSuperblockStartHash;
    int nSuperblockCycle; // in blocks
    int nSuperblockMaturityWindow; // in blocks
    int nGovernanceMinQuorum; // Min absolute vote count to trigger an action
    int nGovernanceFilterElements;
    int nMasternodeMinimumConfirmations;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    // Deployment of BIP147 (NULLDUMMY)
    int BIP147Height;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Block height at which DIP0001 becomes active */
    int DIP0001Height;
    /** Block height at which DIP0002 and DIP0003 (txv3 and deterministic MN lists) becomes active */
    int DIP0003Height;
    /** Block height at which DIP0003 becomes enforced */
    int DIP0003EnforcementHeight;
    uint256 DIP0003EnforcementHash;
    /** Block height at which DIP0008 becomes active */
    int DIP0008Height;
    /** Block height at which BRR (Block Reward Reallocation) becomes active */
    int BRRHeight;
    /** Block height at which DIP0020, DIP0021 and LLMQ_100_67 quorums become active */
    int DIP0020Height;
    /** Block height at which DIP0024 (Quorum Rotation) and decreased governance proposal fee becomes active */
    int DIP0024Height;
    /** Block height at which the first DIP0024 quorum was mined */
    int DIP0024QuorumsHeight;
    /** Block height at which V19 (Basic BLS and BroodNodes) becomes active */
    int V19Height;
    /** Block height at which V20 (Deployment of EHF, LLMQ Randomness Beacon) becomes active */
    int V20Height;
    /** Block height at which MN_RR (Deployment of Masternode Reward Location Reallocation) becomes active */
    int MN_RRHeight;
    /** Block height at which WITHDRAWALS (Deployment of quorum fix and higher limits for withdrawals) becomes active */
    int WithdrawalsHeight;
    /** Block height at which Sapling (zk-SNARK shielded transactions) becomes active */
    int SaplingHeight;
    /** Block height at which SaplingDB consistency checks become hard rejections.
     *  Below this height, mismatches are logged but tolerated (pre-v8 compat). */
    int nSaplingStrictnessHeight{0};
    /** Block height at which Hivemind Protocol becomes active */
    int HMPHeight;
    /** 4-stage HMP bootstrap activation heights.
     * Stage 1 (< nHMPStage2Height): Pure PoW, no HMP processing at all.
     * Stage 2 (< nHMPStage3Height): Commitments Open, pubkey commits accepted/stored.
     * Stage 3 (< nHMPStage4Height): Soft Seal, sealing begins with positive-only weights.
     * Stage 4 (>= nHMPStage4Height): Full HMP, complete weight ladder + negative proofs.
     * SPORK_25_HMP_ENABLED remains the emergency kill switch: if disabled, fall back
     * to Stage 1 (pure PoW) regardless of height. */
    int nHMPStage2Height{0};           // commitments open
    int nHMPStage3Height{0};           // soft seal begins
    int nHMPStage4Height{0};           // full HMP (negative proofs enabled)
    int nHMPWarmupBlocks{10};          // warmup before participation
    int nHMPPrivilegeWindow{100};      // lookback for Elder status
    int nHMPMinBlocksSolved{1};        // min blocks to solve for Elder
    int nHMPSigningWindowMs{5000};     // 5s signing window
    int nHMPGracePeriodMs{15000};      // 15s total grace
    int nHMPSealTrailingDepth{2};      // seal for N in N+2
    int nHMPDominanceCatchFloor{6};    // min unique pools per algo in privileged set
    int nHMPDominanceCatchMaxLookback{1000}; // max extended lookback for dominance catch (~33hr)
    int nHMPCommitmentOffset{0};       // Phase 1 pubkey commitment offset (0=disabled, ~10 when enabled)
    int nHMPMandatoryProofHeight{0};   // Height after which empty zkProofs are rejected (0=never enforce)
    /** v1.2.0 hard-fork activation height for the bundled HMP corrections.
     *  When height >= nHMPSealAlgoFixHeight (and the field is > 0) two coupled
     *  changes take effect together:
     *    1. ConnectBlock passes the SEALED block's algo (pAncestor->GetAlgo()) to
     *       ComputeSealMultiplier and EvaluateNegativeProof, instead of the
     *       enclosing block's algo. Pre-fix this filtered Elder signers against
     *       the wrong algo and capped seal_weight at 1000-1999.
     *    2. The Elder-tier threshold (blocks_solved) is recalibrated via
     *       GetEffectiveMinBlocksSolved() to allow Elders to form under the
     *       observed multi-pool / multi-algo distribution.
     *  0 = never activate (safe default). Set per-network in chainparams.cpp.
     *  See doc/release-notes-v1.2.0.md for the full rationale. */
    int nHMPSealAlgoFixHeight{0};
    /** v1.2.6 hard-fork activation height for the prevSealHash harmonization.
     *  When height >= nPrevSealHashFixHeight (and the field is > 0), ConnectBlock
     *  stops feeding the in-memory m_assembledSeals cache into the seal session's
     *  prevSealHash. Both ConnectBlock and RollforwardBlock instead pass
     *  block.hashPrevBlock unconditionally, so the VRF input is identical on a
     *  fresh-restart node and a long-running node at the same height.
     *  Pre-fix, ConnectBlock hashed the assembled-seal bytes if the cache was hot
     *  and fell back to hashPrevBlock otherwise; RollforwardBlock always used
     *  hashPrevBlock. Because m_assembledSeals does not survive a daemon restart,
     *  the two paths could disagree, causing seal shares to be rejected as
     *  REJECTED_INVALID by AddSealShare after restart. This is share-level, not
     *  block-level: blocks are never rejected by this path. The operational
     *  effect is seal weight collapsing toward the neutral 10000 baseline for
     *  the restart window, demoting HMP to inert and reverting chain ranking
     *  to raw PoW until the cache repopulates.
     *  0 = never activate (safe default). Set per-network in chainparams.cpp. */
    int nPrevSealHashFixHeight{0};

    /** Hard-fork activation height for deterministic seal weighting.
     *  When height >= nHMPDeterministicSealHeight (and the field is > 0),
     *  ConnectBlock computes nSealWeight from HMP state that is canonical for
     *  the block's parent rather than from the live incremental trackers. The
     *  privilege/commitment trackers mutate incrementally on connect/disconnect,
     *  and the disconnect path is not the inverse of connect (front-evicted
     *  window entries are not restored), so the same block reached via different
     *  reorg histories could be assigned a different nSealWeight, diverging the
     *  persisted nChainSealWork between nodes. Post-activation, ConnectBlock
     *  rebuilds the trackers from disk to the parent when they are not already
     *  anchored there, and credits the privilege window from the raw on-chain
     *  seal signers so the incremental and rebuilt states agree bit-for-bit.
     *  nSealWeight then depends only on the chain up to the block, not on the
     *  order blocks were connected. Like the other HMP fixes this is consensus
     *  and gated. Convergence holds once the rebuild lookback
     *  (nHMPDominanceCatchMaxLookback + nHMPPrivilegeWindow) lies entirely above
     *  the activation height; while the window straddles activation a rebuilt
     *  node still credits pre-activation heights from the filtered set, so
     *  schedule the activation at least that many blocks into Stage 4 and treat
     *  the straddle span as a soak window. Participating nodes must run
     *  unpruned (a rebuild that cannot read a block in the lookback halts).
     *  0 = never activate (safe default). Set per-network in chainparams.cpp. */
    int nHMPDeterministicSealHeight{0};

    /** Whether deterministic seal weighting is active at a given height. */
    bool IsDeterministicSealActive(int height) const
    {
        return nHMPDeterministicSealHeight > 0 && height >= nHMPDeterministicSealHeight;
    }

    /** Hard-fork activation height for the DAA retarget symmetry fix.
     *  The Hivemind retarget clamps difficulty falls to -13.8% but rises to
     *  only +8.7% per interval (nMaxAdjustDown=16 vs nMaxAdjustUp=8). Under
     *  profit-switching hashrate the tighten clamp binds far more often than
     *  the ease clamp, so difficulty rides below equilibrium and blocks run
     *  ~15% fast (mainnet measured ~102s vs 120s). The stale-algo gap reset
     *  also jumps straight to the hardware floor, seeding instant-block bursts.
     *  When height >= nDaaRetargetFixHeight (and the field is > 0) the retarget
     *  uses a symmetric +-16% clamp and eases a stalled algo by 4x per missed
     *  averaging window (capped at the floor) instead of resetting to it.
     *  Consensus: every node must switch at the same height.
     *  0 = never activate (safe default). Set per-network in chainparams.cpp. */
    int nDaaRetargetFixHeight{0};

    /** Whether the DAA retarget symmetry fix is active at a given height. */
    bool IsDaaRetargetFixActive(int height) const
    {
        return nDaaRetargetFixHeight > 0 && height >= nDaaRetargetFixHeight;
    }

    /** Hard-fork activation height for the per-algo LWMA difficulty retarget (v1.3.1).
     *  The Hivemind DAA (nDaaRetargetFixHeight) still retargets each algo off a
     *  40-block ALL-ALGO averaging window plus a per-algo "rebalance" count term.
     *  Both are exploited by profit-hopping multipools: a burst-then-abandon on
     *  one algo contaminates the shared window (the DAA reads "fast" and tightens)
     *  while the count term pins a +12.5%/block ratchet on whichever algo is left
     *  carrying the chain -- difficulty strands high, blocks stall, until the burst
     *  ages out ~40 blocks later (hours, at the resulting slow rate). Reproduced by
     *  a byte-exact port of the live DAA and simulated across steady/burst-abandon/
     *  continuous-hop/timestamp-attack scenarios (see the v1.3.1 DAA sim).
     *  From this height each algo retargets independently with a zawy12 LWMA-1 over
     *  its own last-60 same-algo blocks (per-algo target spacing = nPowTargetSpacing
     *  * NUM_ALGOS = 480s), decoupling the algos entirely and eliminating both the
     *  window contamination and the sole-survivor ratchet. Below this height the
     *  retarget is bit-identical to the Hivemind path, so pre-fork block validity is
     *  unchanged; behaviour only diverges at the flag day.
     *  Consensus: every node must switch at the same height.
     *  0 = never activate (safe default). Set per-network in chainparams.cpp. */
    int nDaaLwmaHeight{0};

    /** Whether the per-algo LWMA retarget is active at a given height. */
    bool IsDaaLwmaActive(int height) const
    {
        return nDaaLwmaHeight > 0 && height >= nDaaLwmaHeight;
    }

    /** Hard-fork activation height for the LLMQ_60_60 small-network quorum.
     *  The Dash-inherited quorum roles (ChainLocks on LLMQ_400_60, EHF on
     *  LLMQ_400_85, InstantSend on the DIP0024-rotated LLMQ_60_75) can never
     *  form on a network with fewer than several hundred masternodes, so no
     *  quorum of those types has ever existed on Kerrigan mainnet. From this
     *  height LLMQ_60_60 DKGs are enabled (see ChainstateManager::
     *  IsQuorumTypeEnabled) and the type takes over the ChainLocks,
     *  InstantSend and EHF roles. Because no LLMQ_60_60 quorum can exist
     *  below this height, pre-fork block validity (CbTx bestCLSignature,
     *  MnEHF special txs, mined commitments) is bit-identical to older
     *  releases; behaviour only diverges at/after the flag day, which is
     *  shared with the other v1.3.0 hard forks.
     *  0 = never activate (safe default). Set per-network in chainparams.cpp. */
    int nLLMQ6060Height{0};

    /** Hard-fork activation height for inference-drone coinbase payouts.
     *  At/after this height the 40% growth-escrow coinbase slot is paid to a
     *  registered, bonded, recently-alive inference drone, selected round-robin
     *  by last-paid height from the deterministic drone list built from
     *  on-chain OP_RETURN 0x01 registrations (see evo/dronelist.h). With zero
     *  eligible drones the slot falls back to the exact pre-fork behaviour
     *  (escrow accumulation before nGrowthEscrowEndHeight, OP_RETURN burn
     *  after), so fork-day behaviour is byte-identical until the first bonded
     *  registration confirms. The drone list itself starts empty at this
     *  height: registrations mined before activation are ignored by consensus.
     *  0 = never activate (safe default). Set per-network in chainparams.cpp. */
    int nDronePayoutHeight{0};

    /** Whether drone coinbase payouts are active at a given height. */
    bool IsDronePayoutActive(int height) const
    {
        return nDronePayoutHeight > 0 && height >= nDronePayoutHeight;
    }

    /** Exact value of the bond output a drone registration TX must carry for
     *  consensus to admit it into the drone list. The bond output's
     *  scriptPubKey becomes the drone's payout script and its outpoint is the
     *  collateral: spending it deregisters the drone (same collateral pattern
     *  as deterministic masternodes). Zero or multiple outputs matching this
     *  exact value make the TX not-a-registration (never block-invalid).
     *  RETUNABLE AT RELEASE CUT: size to ~3-6 months of a single drone's
     *  expected payout at launch drone count so sybil identities tie up more
     *  capital than they can extract (v1 payee selection is capital-gated,
     *  not service-gated). 0 = registrations never admitted. */
    CAmount nDroneCollateralAmount{0};

    /** Maximum age, in blocks, of a drone's last authenticated liveness
     *  signal (registration or heartbeat re-registration whose inputs spend
     *  from the drone's payout script) before the drone becomes ineligible
     *  for coinbase payouts. Drones fall out of rotation silently and return
     *  on their next authenticated heartbeat; the entry itself is only
     *  removed when the collateral is spent. 0 = no liveness gating. */
    int nDroneMaxAge{0};

    int nHMPBroodDemotionDuration{1000}; // blocks to stay demoted after equivocation (~33hr)
    int nHMPBroodChainWeightBonus{300};  // bps bonus per BROOD signer's algo in seal multiplier
    static constexpr int MAX_COMMITMENTS_PER_BLOCK = 16;

    /** Effective Elder-tier blocks_solved threshold at a given chain height.
     *  Pre-v1.2.0 (height < nHMPSealAlgoFixHeight, or fix never scheduled):
     *  returns nHMPMinBlocksSolved (legacy bug-compatible value).
     *  Post-v1.2.0: returns 3, the recalibrated threshold that lets Elders form
     *  under realistic multi-algo distribution.
     *  Both call sites in privilege.cpp (GetTier, GetElderSet) MUST use this
     *  helper so the two queries stay in lockstep across the activation. */
    int GetEffectiveMinBlocksSolved(int height) const
    {
        if (nHMPSealAlgoFixHeight > 0 && height >= nHMPSealAlgoFixHeight) {
            return 3;
        }
        return nHMPMinBlocksSolved;
    }

    /** Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV and DIP activations. */
    int MinBIP9WarningHeight;
    /**
     * Minimum blocks including miner confirmation of the total of nMinerConfirmationWindow blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Default BIP9Deployment::nThresholdStart value for deployments where it's not specified and for unknown deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    // Default BIP9Deployment::nWindowSize value for deployments where it's not specified and for unknown deployments.
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /**
     * Proof of work parameters
     *
     * Kerrigan uses 4 mining algorithms (X11, KawPoW, Equihash(200,9),
     * Equihash(192,7)) with per-algo Hivemind difficulty adjustment.
     *
     * nPowTargetSpacing is the overall block target (120s). Each algorithm
     * independently targets nPowTargetSpacing * NUM_ALGOS (480s), so the
     * combined output of all algorithms yields one block every 120s.
     *
     */
    uint256 powLimit;
    /** Per-algorithm difficulty floors (minimum difficulty / maximum target).
     * Calibrated to cheapest available hardware so 1 unit produces ~1 block/480s:
     *   X11:             Antminer D3 (15 GH/s)    = target ~2^213
     *   KawPoW:          GTX 1080 (18 MH/s)       = target ~2^224
     *   Equihash(200,9): Z9 Mini (17.5 kSol/s)    = target ~2^233
     *   Equihash(192,7): GTX 1080 (30 Sol/s)      = target ~2^244
     * powLimit is set to the easiest per-algo floor for CheckProofOfWork().
     * Set all entries to powLimit on test networks (no per-algo floors).
     */
    uint256 powLimitAlgo[4 /* NUM_ALGOS */];
    /** Height-activated per-algo difficulty floor (#851).
     * After nDiffFloorHeight, the DAA output is clamped to powLimitFloorAlgo[]
     * instead of the permissive powLimitAlgo[]. This allows testnet to start
     * with easy powLimits for CPU mining but switch to hardware-calibrated
     * floors once real miners connect. nDiffFloorHeight=0 disables floors.
     * Mainnet activates at block 14000, testnet at block 2260.
     * Also lowers the algo-gap recovery threshold from 240 to 40 blocks. */
    int nDiffFloorHeight{0};
    /** Height at which the tighter 40-block algo-gap threshold activates.
     * Before this height, the legacy 240-block threshold is used. */
    int nGapThresholdHeight{0};
    uint256 powLimitFloorAlgo[4 /* NUM_ALGOS */];
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;  // 120 seconds (overall block target)
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    /** The best chain should have at least this much work */
    uint256 nMinimumChainWork;
    /** By default assume that the signatures in ancestors of this block are valid */
    uint256 defaultAssumeValid;

    /**
     * Kerrigan coinbase split addresses (serialized CScripts).
     * Set in chainparams.cpp per network.
     *
     * Split: 20% miner, 5% founders, 15% dev, 20% masternodes, 40% growth escrow.
     */
    std::vector<unsigned char> foundersPaymentScript;   // 5% to founders
    std::vector<unsigned char> devFundPaymentScript;     // 15% to dev fund
    std::vector<unsigned char> growthEscrowScript;       // 40% consensus-locked growth escrow (burns at nGrowthEscrowEndHeight)

    /**
     * Legacy (superseded) growth-escrow scriptPubKeys (serialized CScripts).
     *
     * INCIDENT 2026-05 (P-8 fix). When the growth-escrow keys are rotated to a
     * fresh script (growthEscrowScript above), any coins still sitting at a PRIOR
     * escrow script would otherwise stop matching the single-script consensus lock
     * -- the governance gate would never fire and the old balance would become
     * spendable with just the old (compromised) keys. To keep those coins
     * consensus-locked AND governance-gated, every superseded escrow script is
     * recorded here. The mempool relay check and the ConnectBlock consensus check
     * treat a coin paying growthEscrowScript OR any entry in this list as an
     * escrow input, routing it through the same CheckGovernanceEscrowSpend gate.
     *
     * A governance-approved release may sweep EITHER the current or a legacy escrow
     * script (enabling a later old->new consolidation), so the gate matches the
     * approved payout against whichever script the inputs actually came from.
     *
     * Mainnet seeds the pre-rotation escrow P2SH; testnet/devnet/regtest are empty
     * (default-inert: with no legacy scripts the behaviour is byte-identical to a
     * single-script lock).
     */
    std::vector<std::vector<unsigned char>> legacyEscrowScripts;

    /**
     * True iff `spk` (a serialized scriptPubKey) is an escrow-locked script: the
     * current growthEscrowScript OR any superseded legacyEscrowScripts entry. Empty
     * scripts never match (an unconfigured escrow lock is inert). Used by both the
     * mempool relay lock and the ConnectBlock consensus lock so the two sites stay
     * in lockstep over the full escrow script set.
     *
     * @return true if `spk` is a current or legacy escrow scriptPubKey.
     */
    bool IsGrowthEscrowScript(const std::vector<unsigned char>& spk) const
    {
        if (spk.empty()) return false;
        if (!growthEscrowScript.empty() && spk == growthEscrowScript) return true;
        for (const auto& legacy : legacyEscrowScripts) {
            if (!legacy.empty() && spk == legacy) return true;
        }
        return false;
    }

    /**
     * Legacy (superseded) devfund + founders payment scripts. A historical block
     * paying ANY entry here (at the expected amount) satisfies the treasury
     * validation, in addition to the current devFundPaymentScript /
     * foundersPaymentScript. This is the same legacy-script pattern as
     * legacyEscrowScripts and lets the binary validate blocks mined under prior
     * treasury rotations without forking. Empty == single-script only (default).
     */
    std::vector<std::vector<unsigned char>> legacyDevFundScripts;
    std::vector<std::vector<unsigned char>> legacyFoundersPaymentScripts;

    bool IsDevFundScript(const std::vector<unsigned char>& spk) const
    {
        if (spk.empty()) return false;
        if (!devFundPaymentScript.empty() && spk == devFundPaymentScript) return true;
        for (const auto& legacy : legacyDevFundScripts) {
            if (!legacy.empty() && spk == legacy) return true;
        }
        return false;
    }

    bool IsFoundersPaymentScript(const std::vector<unsigned char>& spk) const
    {
        if (spk.empty()) return false;
        if (!foundersPaymentScript.empty() && spk == foundersPaymentScript) return true;
        for (const auto& legacy : legacyFoundersPaymentScripts) {
            if (!legacy.empty() && spk == legacy) return true;
        }
        return false;
    }

    /**
     * Growth escrow sunset height. After this block, the 40% coinbase allocation
     * burns via OP_RETURN instead of entering the escrow. Existing escrow UTXOs stay
     * consensus-locked (governance-gated), and -- at/after nEscrowBurnHeight -- become
     * burnable to OP_RETURN via the keyless value-conserving carve-out (they can be
     * DESTROYED but never redirected to a spendable address). Set to 0 to disable.
     */
    int nGrowthEscrowEndHeight{0};

    /**
     * Growth-escrow BURN activation height. At/after this block a transaction may
     * spend growth-escrow coins (current growthEscrowScript OR any legacyEscrowScripts
     * entry, via IsGrowthEscrowScript) WITHOUT a signature and WITHOUT a governance
     * proposal, but ONLY if it is a "pure escrow burn": every input is an escrow coin,
     * every output is OP_RETURN, and the output value equals the input value (zero fee).
     * Such a tx can therefore only DESTROY escrow value -- it can never redirect it to a
     * spendable address, and no value can leak to the miner as fees -- so bypassing the
     * signature + governance checks is safe (see IsPureEscrowBurn in validation.cpp).
     * This lets the accumulated escrow be permanently burned to OP_RETURN even though the
     * governance-release path is unusable and the rotated pre-Plan-X keys are gone. 0 =
     * disabled (escrow stays governance-gated, no burn carve-out).
     */
    int nEscrowBurnHeight{0};

    /**
     * DETERMINISTIC TAINT-ROOT FREEZE (incident 2026-05).
     *
     * nFreezeActivationHeight (H): the consensus activation height for the
     * deterministic taint freeze. At/after H, a block that spends a tainted
     * outpoint is INVALID. When the active chain first reaches H, each node walks
     * its OWN canonical chain from nFreezeRootHeight up to H, applies the
     * propagation rule (seed = drain script + seed txids, see
     * policy/outpoint_blacklist.h), and builds a bit-identical frozen set.
     *
     * 0 == DISABLED: the mechanism is fully inert and the node is byte-identical
     * to upstream. This is the default so every network that does not explicitly
     * opt in keeps stock behaviour.
     *
     * nFreezeRootHeight: the earliest block the walk inspects (the theft block).
     * Outputs paying the drain script or belonging to a seed txid only count as
     * seed taint at/after this height. Ignored when nFreezeActivationHeight == 0.
     *
     * H is per-network (mainnet finalised before tag, devnet/regtest = 1 so tests
     * can exercise it, testnet = a far-future placeholder). H MUST be chosen
     * comfortably above the tip at deploy time so the [root..H] window is buried
     * and stable; see the reorg-safety note in policy/outpoint_blacklist.h.
     */
    int nFreezeActivationHeight{0};
    int nFreezeRootHeight{0};

    /**
     * PLAN X -- CONTINGENCY ROLLBACK (incident 2026-05). See
     * policy/planx_rollback.h for the full design.
     *
     * PENDING COMMUNITY VOTE -- do not deploy without vote + finalized
     * hashes/address.
     *
     * These per-network params mirror the compile-time PLAN X constants so a
     * network can carry the required-ancestor (checkpoint pin) height/hash in
     * its chainparams alongside the hardcoded checkpoint. They are ONLY consulted
     * when the -activaterollback gate is on (g_activate_rollback). With the gate
     * off and these left at their defaults (height 0 / null hash) the rollback is
     * fully inert and the node is byte-identical to upstream.
     *
     * nRollbackHeight: required-ancestor height (the last honest block before the
     *   theft; placeholder 54350). 0 == disabled.
     * rollbackAnchorHash: hash of the canonical block at nRollbackHeight. Null ==
     *   not finalized (rule inert; a null anchor is never enforced).
     * rollbackDisallowedHash: hash of the theft block (nRollbackHeight + 1). The
     *   header acceptance path rejects this block and any block descending from it.
     *   Per-network so the disallow/descendant pins never consult another network's
     *   value; null == not finalized (rule inert).
     */
    int nRollbackHeight{0};
    uint256 rollbackAnchorHash;
    uint256 rollbackDisallowedHash;

    /**
     * PLAN X recovery-spend activation height. The only-to-7b consensus rule
     * (PlanXOnlyToRecoveryAllowed in policy/planx_rollback.h) is enforced only
     * for blocks at height >= this value. Below this height the rule is inert,
     * so historical pre-rollback blocks that contain legitimate spends from
     * addresses later added to the compromised set still validate cleanly on a
     * fresh IBD. 0 == disabled (rule never fires; default off-mainnet).
     *
     * On mainnet this matches planx::RECOVERY_V2_ACTIVATION_HEIGHT (54500):
     * pinned at 54500 since v1.2.3 to preserve cross-release consensus parity.
     * The pre-activation legacy allowlist keeps the historical Set-A sweeps at
     * h=54361/54364 valid; at/above 54500 only the Set-D destination is
     * accepted for compromised-coin spends.
     */
    int nPlanXRecoveryActivationHeight{0};

    /**
     * Operator-side deprecation height (v1.2.5). The daemon refuses to extend
     * the chain at or above this height and initiates a clean shutdown;
     * ~15,000 blocks before, the GUI warning banner is set on every tip update
     * and the daemon writes a log line every 100 blocks. Forces the network
     * onto a current release rather than letting
     * stragglers hold a stale codebase view. This is NOT consensus -- newer
     * daemons happily mine past this height. v1.2.5 deprecates itself.
     * 0 == disabled (default off-mainnet; default for any release without an
     * intended deprecation cycle).
     */
    int nDeprecationHeight{0};

    /**
     * Legacy devfund + founders sunset height. Below this height, a coinbase
     * that pays devfund/founders to ANY entry in legacyDevFundScripts /
     * legacyFoundersPaymentScripts satisfies the treasury check (preserves
     * historical block validity across the v1.0/1.1 -> v1.2 rotation). At or
     * above this height, ONLY the current devFundPaymentScript /
     * foundersPaymentScript are accepted; any block paying a legacy address is
     * bad-cb-payee. The growth-escrow legacy list is NOT subject to this gate
     * (a legitimate consolidation may still be needed via governance).
     * 0 == disabled (legacy fallback always active; default off-mainnet).
     */
    int nLegacyDevfundSunsetHeight{0};

    /**
     * nEscrowUnlockHeight (H_unlock): the earliest block height at which an escrow
     * release (a spend of growthEscrowScript or any legacyEscrowScripts entry) may
     * be valid. A block that contains an escrow-release spend at a height STRICTLY
     * BELOW this value is consensus-invalid on every node, unconditionally -- no
     * governance lookup, no IBD branch. This forbids any escrow movement during the
     * PLAN X recovery re-mine window, where governance state cannot be verified at
     * mining time. 0 == disabled (no unlock floor; pre-incident behaviour).
     */
    int nEscrowUnlockHeight{0};

    /** these parameters are only used on devnet and can be configured from the outside */
    int nMinimumDifficultyBlocks{0};
    int nHighSubsidyBlocks{0};
    int nHighSubsidyFactor{1};

    std::vector<LLMQParams> llmqs;
    LLMQType llmqTypeChainLocks;
    LLMQType llmqTypeDIP0024InstantSend{LLMQType::LLMQ_NONE};
    LLMQType llmqTypePlatform{LLMQType::LLMQ_NONE};
    LLMQType llmqTypeMnhf{LLMQType::LLMQ_NONE};

    int DeploymentHeight(BuriedDeployment dep) const
    {
        switch (dep) {
        case DEPLOYMENT_HEIGHTINCB:
            return BIP34Height;
        case DEPLOYMENT_DERSIG:
            return BIP66Height;
        case DEPLOYMENT_CLTV:
            return BIP65Height;
        case DEPLOYMENT_BIP147:
            return BIP147Height;
        case DEPLOYMENT_CSV:
            return CSVHeight;
        case DEPLOYMENT_DIP0001:
            return DIP0001Height;
        case DEPLOYMENT_DIP0003:
            return DIP0003Height;
        case DEPLOYMENT_DIP0008:
            return DIP0008Height;
        case DEPLOYMENT_DIP0020:
            return DIP0020Height;
        case DEPLOYMENT_DIP0024:
            return DIP0024Height;
        case DEPLOYMENT_BRR:
            return BRRHeight;
        case DEPLOYMENT_V19:
            return V19Height;
        case DEPLOYMENT_V20:
            return V20Height;
        case DEPLOYMENT_MN_RR:
            return MN_RRHeight;
        case DEPLOYMENT_WITHDRAWALS:
            return WithdrawalsHeight;
        case DEPLOYMENT_SAPLING:
            return SaplingHeight;
        case DEPLOYMENT_HMP:
            return HMPHeight;
        } // no default case, so the compiler can warn about missing cases
        return std::numeric_limits<int>::max();
    }
};

} // namespace Consensus

#endif // KERRIGAN_CONSENSUS_PARAMS_H
