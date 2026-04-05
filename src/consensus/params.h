// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Copyright (c) 2014-2025 The Dash Core developers
// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KERRIGAN_CONSENSUS_PARAMS_H
#define KERRIGAN_CONSENSUS_PARAMS_H

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
    int nHMPBroodDemotionDuration{1000}; // blocks to stay demoted after equivocation (~33hr)
    int nHMPBroodChainWeightBonus{300};  // bps bonus per BROOD signer's algo in seal multiplier
    static constexpr int MAX_COMMITMENTS_PER_BLOCK = 16;
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
     * Growth escrow sunset height. After this block, the 40% coinbase allocation
     * burns via OP_RETURN instead of entering the escrow. Existing escrow UTXOs
     * become permanently unspendable. Set to 0 to disable (no sunset).
     */
    int nGrowthEscrowEndHeight{0};

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
