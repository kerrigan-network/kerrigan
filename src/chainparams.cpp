// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Copyright (c) 2014-2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <crypto/ripemd160.h>
#include <crypto/sha256.h>
#include <deploymentinfo.h>
#include <llmq/params.h>
#include <script/script.h>
#include <util/ranges.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/underlying.h>
#include <versionbits.h>

#include <arith_uint256.h>

#include <assert.h>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateDevNetGenesisBlock(const uint256 &prevBlockHash, const std::string& devNetName, uint32_t nTime, uint32_t nNonce, uint32_t nBits, const CAmount& genesisReward)
{
    assert(!devNetName.empty());

    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    // put height (BIP34) and devnet name into coinbase
    txNew.vin[0].scriptSig = CScript() << 1 << std::vector<unsigned char>(devNetName.begin(), devNetName.end());
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = CScript() << OP_RETURN;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = 4;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock = prevBlockHash;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the Kerrigan genesis block.
 *
 * Timestamp: Reuters 27/Feb/2026 GPU miners bridge to decentralized AI inference
 * Output: P2PKH to KKZcodg9Dpe82JyhPRRoMdd5ypXrS3cCM6
 * Reward: 25 COIN
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Reuters 27/Feb/2026 GPU miners bridge to decentralized AI inference";
    // P2PKH output to KKZcodg9Dpe82JyhPRRoMdd5ypXrS3cCM6
    const CScript genesisOutputScript = CScript() << OP_DUP << OP_HASH160 << ParseHex("8780c7e4553d942f9239bf5f60d09dae1c5ffd46") << OP_EQUALVERIFY << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

static CBlock FindDevNetGenesisBlock(const CBlock &prevBlock, const CAmount& reward)
{
    std::string devNetName = gArgs.GetDevNetName();
    assert(!devNetName.empty());

    CBlock block = CreateDevNetGenesisBlock(prevBlock.GetHash(), devNetName, prevBlock.nTime + 1, 0, prevBlock.nBits, reward);

    arith_uint256 bnTarget;
    bnTarget.SetCompact(block.nBits);

    for (uint32_t nNonce = 0; nNonce < UINT32_MAX; nNonce++) {
        block.nNonce = nNonce;

        uint256 hash = block.GetHash();
        if (UintToArith256(hash) <= bnTarget)
            return block;
    }

    // This is very unlikely to happen as we start the devnet with a very low difficulty. In many cases even the first
    // iteration of the above loop will give a result already
    error("FindDevNetGenesisBlock: could not find devnet genesis block for %s", devNetName);
    assert(false);
}

/**
 * Build a P2PKH treasury script from a 20-byte pubkey hash.
 * Returns the serialized script bytes for storage in Consensus::Params.
 */
static std::vector<unsigned char> BuildTreasuryScript(const std::string& pubKeyHashHex)
{
    auto parsed = TryParseHex<uint8_t>(pubKeyHashHex);
    assert(parsed && parsed->size() == 20); // Exactly 20-byte pubkey hash required
    CScript script = CScript() << OP_DUP << OP_HASH160 << *parsed << OP_EQUALVERIFY << OP_CHECKSIG;
    return std::vector<unsigned char>(script.begin(), script.end());
}

/**
 * Build a P2SH treasury script from a hex-encoded redeemScript.
 * Used for 2-of-3 multisig treasury addresses.
 */
static std::vector<unsigned char> BuildP2SHTreasuryScript(const std::string& redeemScriptHex)
{
    auto parsed = TryParseHex<uint8_t>(redeemScriptHex);
    assert(parsed && !parsed->empty());
    // P2SH: OP_HASH160 <hash160(redeemScript)> OP_EQUAL
    uint256 sha;
    CSHA256().Write(parsed->data(), parsed->size()).Finalize(sha.begin());
    std::vector<uint8_t> hash160(20);
    CRIPEMD160().Write(sha.begin(), 32).Finalize(hash160.data());
    CScript script = CScript() << OP_HASH160 << hash160 << OP_EQUAL;
    return std::vector<unsigned char>(script.begin(), script.end());
}


bool CChainParams::IsValidMNActivation(int nBit, int64_t timePast) const
{
    assert(nBit < VERSIONBITS_NUM_BITS);

    for (int index = 0; index < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++index) {
        if (consensus.vDeployments[index].bit == nBit) {
            auto& deployment = consensus.vDeployments[index];
            if (timePast > deployment.nTimeout || timePast < deployment.nStartTime) {
                LogPrintf("%s: activation by bit=%d deployment='%s' is out of time range start=%lld timeout=%lld\n", __func__, nBit, VersionBitsDeploymentInfo[Consensus::DeploymentPos(index)].name, deployment.nStartTime, deployment.nTimeout);
                continue;
            }
            if (!deployment.useEHF) {
                LogPrintf("%s: trying to set MnEHF for non-masternode activation fork bit=%d\n", __func__, nBit);
                return false;
            }
            LogPrintf("%s: set MnEHF for bit=%d is valid\n", __func__, nBit);
            return true;
        }
    }
    LogPrintf("%s: WARNING: unknown MnEHF fork bit=%d\n", __func__, nBit);
    return true;
}

void CChainParams::AddLLMQ(Consensus::LLMQType llmqType)
{
    assert(!GetLLMQ(llmqType).has_value());
    for (const auto& llmq_param : Consensus::available_llmqs) {
        if (llmq_param.type == llmqType) {
            consensus.llmqs.push_back(llmq_param);
            return;
        }
    }
    error("CChainParams::%s: unknown LLMQ type %d", __func__, static_cast<uint8_t>(llmqType));
    assert(false);
}

std::optional<Consensus::LLMQParams> CChainParams::GetLLMQ(Consensus::LLMQType llmqType) const
{
    for (const auto& llmq_param : consensus.llmqs) {
        if (llmq_param.type == llmqType) {
            return std::make_optional(llmq_param);
        }
    }
    return std::nullopt;
}

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;
        consensus.nSubsidyHalvingInterval = 1051200; // ~4 years at 120s blocks (25 COIN halving)
        consensus.nMasternodePaymentsStartBlock = 1; // Treasury payments from block 1
        consensus.nMasternodePaymentsIncreaseBlock = 2100000000; // Effectively never (Kerrigan uses fixed 50/50 miner/MN split)
        consensus.nMasternodePaymentsIncreasePeriod = 1; // Unused
        consensus.nInstantSendConfirmationsRequired = 6;
        consensus.nInstantSendKeepLock = 24;
        consensus.nBudgetPaymentsStartBlock = 2100000000; // Effectively never (no Kerrigan budget system)
        consensus.nBudgetPaymentsCycleBlocks = 16616;
        consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nSuperblockStartBlock = 2100000000; // Effectively never (no superblocks)
        consensus.nSuperblockStartHash = uint256();
        consensus.nSuperblockCycle = 16616;
        consensus.nSuperblockMaturityWindow = 1662;
        consensus.nGovernanceMinQuorum = 10;
        consensus.nGovernanceFilterElements = 20000;
        consensus.nMasternodeMinimumConfirmations = 15;
        // All BIPs/DIPs active from genesis (new chain, no legacy blocks)
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.BIP147Height = 0;
        consensus.CSVHeight = 0;
        // DIP/version heights start at 2: genesis skips EvoDB, block 1 establishes
        // EvoDB state, DIPs activate at block 2 when EvoDB is consistent.
        consensus.DIP0001Height = 2;
        consensus.DIP0003Height = 2;
        consensus.DIP0003EnforcementHeight = 2;
        consensus.DIP0003EnforcementHash = uint256();
        consensus.DIP0008Height = 2;
        consensus.BRRHeight = 2;
        consensus.DIP0020Height = 2;
        consensus.DIP0024Height = 2;
        consensus.DIP0024QuorumsHeight = 2;
        consensus.V19Height = 2;
        consensus.V20Height = 2;
        consensus.MN_RRHeight = 2100000000; // Effectively never (no MN reward reallocation in Kerrigan)
        consensus.WithdrawalsHeight = 2100000000; // Effectively never
        consensus.SaplingHeight = 500; // Sapling activates after ~16 hours of mining (500 blocks * 120s)
        consensus.nSaplingStrictnessHeight = 15500; // Tolerate pre-v8 SaplingDB mismatches below this height
        consensus.HMPHeight = 100; // Hivemind HMP Stage 2 (commitments) at block 100
        // 4-stage HMP bootstrap:
        // Stage 1 (< 100): Pure PoW, no HMP processing (pre-activation)
        // Stage 2 (100-299): Commitments open, miners register identities
        // Stage 3 (300-499): Soft seal, positive-only weight (no penalties)
        // Stage 4 (500+): Full HMP with negative proofs
        consensus.nHMPStage2Height = 100;  // commitments open (after coinbase maturity)
        consensus.nHMPStage3Height = 300;  // soft seal begins (~200 blocks for commitment buildup)
        consensus.nHMPStage4Height = 500;  // full HMP (~16 hours, negative proofs active)
        consensus.nHMPCommitmentOffset = 10; // Phase 1: 10-block pubkey commitment maturity
        consensus.nHMPMinBlocksSolved = 10; // Anti-Sybil: 10 blocks to reach Elder tier
        // Mandatory zk-SNARK proof height: 0 = never enforce.
        // Groth16 proofs are Phase 2 (post-launch hard fork). Proofs are accepted
        // but never required until Phase 2 activates via a future hard fork.
        consensus.nHMPMandatoryProofHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        // Per-algo genesis powLimits — permissive targets for chain bootstrapping.
        // These are intentionally easy so the first miner on each algo can produce blocks.
        // After nDiffFloorHeight, the tighter powLimitFloorAlgo[] values take over.
        // Formula: floor_target = 2^256 / (hashrate_H_per_s * 480)
        consensus.powLimitAlgo[ALGO_X11]          = uint256S("00000ffff0000000000000000000000000000000000000000000000000000000"); // genesis nBits=0x1e0ffff0
        consensus.powLimitAlgo[ALGO_KAWPOW]       = uint256S("0000000100000000000000000000000000000000000000000000000000000000"); // ~2^224
        consensus.powLimitAlgo[ALGO_EQUIHASH_200] = uint256S("0000020000000000000000000000000000000000000000000000000000000000"); // ~2^233
        consensus.powLimitAlgo[ALGO_EQUIHASH_192] = uint256S("0010000000000000000000000000000000000000000000000000000000000000"); // ~2^244
        // Global powLimit = easiest per-algo floor (for CheckProofOfWork range validation)
        consensus.powLimit = consensus.powLimitAlgo[ALGO_EQUIHASH_192];

        // Height-activated difficulty floor: after nDiffFloorHeight, the DAA output
        // is clamped to hardware-calibrated floors instead of the permissive genesis
        // powLimitAlgo[]. Prevents flash-mining after hashrate drops (incident at
        // block 10879 where X11 diff dropped to 0.0002 and ~500 blocks were mined
        // in 30 minutes). Floors calibrated so 1 unit of minimum hardware for each
        // algo produces ~1 block per 480s (per-algo target spacing).
        consensus.nDiffFloorHeight = 14000;
        consensus.powLimitFloorAlgo[ALGO_X11]          = uint256S("0000000000271700000000000000000000000000000000000000000000000000"); // Antminer D3, 15 GH/s
        consensus.powLimitFloorAlgo[ALGO_KAWPOW]       = uint256S("000000007f420000000000000000000000000000000000000000000000000000"); // GTX 1080, 18 MH/s
        consensus.powLimitFloorAlgo[ALGO_EQUIHASH_200] = uint256S("0000020000000000000000000000000000000000000000000000000000000000"); // ~17.5 kSol/s (same as genesis cap — already tight for Z9 Mini)
        consensus.powLimitFloorAlgo[ALGO_EQUIHASH_192] = uint256S("00048d1000000000000000000000000000000000000000000000000000000000"); // GTX 1080, 30 Sol/s
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Kerrigan: 1 day
        consensus.nPowTargetSpacing = 120; // Kerrigan: 2 minutes
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // BIP9 signaling window
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_V24].bit = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE; // Kerrigan does not use V24
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nWindowSize = 4032;
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nThresholdStart = 3226;     // 80% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nThresholdMin = 2420;       // 60% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nFalloffCoeff = 5;          // this corresponds to 10 periods
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].useEHF = true;

        // Verify no BIP9 deployment uses bits 8-11 (reserved for algo encoding)
        for (int i = 0; i < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
            int bit = consensus.vDeployments[i].bit;
            if (bit >= 8 && bit <= 11) {
                throw std::runtime_error(strprintf("BIP9 deployment %d uses bit %d which collides with algo encoding", i, bit));
            }
        }

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        // Fund addresses: 2-of-3 P2SH multisig for security
        // founders (5%):        7aP2bhZGE6mT6Ae7DhPAbWz54gZahCqHP8 (2-of-3)
        // devfund (15%):        7bMQKKigBdndVPqitNQuzUXPMVcTqjWHP5 (2-of-3)
        // growth escrow (40%):  7TrJoc8f9AD32D225cV63CcdibhLyRXiP3 (2-of-3, consensus-locked)
        consensus.foundersPaymentScript = BuildP2SHTreasuryScript(
            "5221035d9b548bdfe19f60e351a65a7b97a5752dd1063247ca204cc10663696e79fad2"
            "210385a58f276109b9bfb16e68da9ba1262f8f75c86ebc1ae543c130459fc715a049"
            "21031feba692dd7ec8cfad6558b15240097d085f356d81cfc7675cb47815c51d077053ae");
        consensus.devFundPaymentScript = BuildP2SHTreasuryScript(
            "5221024dd90cdbcf689fee2292677df1a632ea389a626e8f11b1af6e0afac1db897282"
            "2102204507581c8864c2d7ba124c14d131b972644956b04c8e6922e34c523c56e9ea"
            "210289473d7b9bc4af599e99ced0fa74805f1492b6930a4eac1f2384126ade33024653ae");
        consensus.growthEscrowScript = BuildP2SHTreasuryScript(
            "522103261171e2b23bf1d194df2c7a5d1d538c32b8f89663e44dd120f81d6c2247c4a5"
            "210389c01e16affdc212dad4041fdcb541bb16cbc70228b6073243ee8139bb6d1a28"
            "210208fcb17aa95588e3f37da5aa6513ecb8cca193249c67af7997a416993b6bbe8e53ae");
        consensus.nGrowthEscrowEndHeight = 262800; // ~12 months, 40% burns via OP_RETURN after this

        // "KRGN" Kerrigan mainnet network magic
        pchMessageStart[0] = 0x4b; // K
        pchMessageStart[1] = 0x52; // R
        pchMessageStart[2] = 0x47; // G
        pchMessageStart[3] = 0x4e; // N
        nDefaultPort = 7120;
        nDefaultPlatformP2PPort = 7121;
        nDefaultPlatformHTTPPort = 7122;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlock(1773446400, 1338121, 0x1e0ffff0, 1, 25 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000444f8dbee14c599ac723b35cc8021b12d48d092c7ac67d45f6d8a0b9c32"));
        assert(genesis.hashMerkleRoot == uint256S("0x0a4c26b182f334bbc42f1e3761fce27a7c12874937cc0d0bf5399e65a3c194b8"));

        vSeeds.emplace_back("seed1.kerrigan.network");
        vSeeds.emplace_back("seed2.kerrigan.network");
        vSeeds.emplace_back("seed3.kerrigan.network");
        vSeeds.emplace_back("seed4.kerrigan.network");

        // Kerrigan addresses start with 'K'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 45);
        // Kerrigan script addresses start with '7'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 16);
        // Kerrigan private keys
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 204);
        // Kerrigan BIP32 pubkeys start with 'xpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        // Kerrigan BIP32 prvkeys start with 'xprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        // Kerrigan BIP44 coin type (unregistered range, avoids NEO collision at 888)
        nExtCoinType = 99888;

        // Sapling shielded address Bech32m HRP
        strSaplingHRP = "ks";

        vFixedSeeds.assign(chainparams_seed_main, chainparams_seed_main + sizeof(chainparams_seed_main));

        // long living quorum params
        AddLLMQ(Consensus::LLMQType::LLMQ_50_60);
        AddLLMQ(Consensus::LLMQType::LLMQ_60_75);
        AddLLMQ(Consensus::LLMQType::LLMQ_400_60);
        AddLLMQ(Consensus::LLMQType::LLMQ_400_85);
        AddLLMQ(Consensus::LLMQType::LLMQ_100_67);
        consensus.llmqTypeChainLocks = Consensus::LLMQType::LLMQ_400_60;
        consensus.llmqTypeDIP0024InstantSend = Consensus::LLMQType::LLMQ_60_75;
        consensus.llmqTypePlatform = Consensus::LLMQType::LLMQ_100_67;
        consensus.llmqTypeMnhf = Consensus::LLMQType::LLMQ_400_85;

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fRequireRoutableExternalIP = true;
        m_is_test_chain = false;
        fAllowMultipleAddressesFromGroup = false;
        nLLMQConnectionRetryTimeout = 60;
        m_is_mockable_chain = false;

        nPoolMinParticipants = 3;
        nPoolMaxParticipants = 20;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour

        vSporkAddresses = {"KRnfZa6oT2hwLybJWVqgZ3TDPYB579deVr",
                           "K8ENPxi1XejZ6cAEGe8jq6eD7NABkzeZaE",
                           "KUi71L87dCrq2FLgXVUmzMfgCfaj3nGnSp"};
        nMinSporkKeys = 2; // 2-of-3 spork key threshold

        nCreditPoolPeriodBlocks = 576;

        checkpointData = {
            {
                {0, uint256S("0x00000444f8dbee14c599ac723b35cc8021b12d48d092c7ac67d45f6d8a0b9c32")},
            }
        };

        m_assumeutxo_data = MapAssumeutxo{};

        chainTxData = ChainTxData{
                0,
                0,
                0
        };

        // DIP activation ordering assertions (must hold for consensus correctness)
        assert(consensus.V20Height >= consensus.DIP0003Height);
        assert(consensus.MN_RRHeight >= consensus.V20Height);
        assert(consensus.DIP0003EnforcementHeight >= consensus.DIP0003Height);
    }
};

/**
 * Testnet (v3): public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = CBaseChainParams::TESTNET;
        consensus.nSubsidyHalvingInterval = 1051200;
        consensus.nMasternodePaymentsStartBlock = 1;
        consensus.nMasternodePaymentsIncreaseBlock = 2100000000;
        consensus.nMasternodePaymentsIncreasePeriod = 1;
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 2100000000;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nSuperblockStartBlock = 2100000000;
        consensus.nSuperblockStartHash = uint256();
        consensus.nSuperblockCycle = 24;
        consensus.nSuperblockMaturityWindow = 8;
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        // BIPs active from genesis, DIPs from height 2 (same pattern as devnet:
        // genesis skips EvoDB, block 1 establishes EvoDB, DIPs activate at block 2)
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.BIP147Height = 0;
        consensus.CSVHeight = 0;
        consensus.DIP0001Height = 2;
        consensus.DIP0003Height = 2;
        consensus.DIP0003EnforcementHeight = 2;
        consensus.DIP0003EnforcementHash = uint256();
        consensus.DIP0008Height = 2;
        consensus.BRRHeight = 2;
        consensus.DIP0020Height = 2;
        consensus.DIP0024Height = 2;
        consensus.DIP0024QuorumsHeight = 2;
        consensus.V19Height = 2;
        consensus.V20Height = 2;
        consensus.MN_RRHeight = 2100000000;
        consensus.WithdrawalsHeight = 2100000000;
        consensus.SaplingHeight = 100; // Sapling active early on testnet
        consensus.nSaplingStrictnessHeight = 15500;
        consensus.HMPHeight = 20; // Hivemind HMP Stage 2 at block 20
        // 4-stage HMP bootstrap:
        consensus.nHMPStage2Height = 20;   // commitments open (faster for testing)
        consensus.nHMPStage3Height = 100;  // soft seal begins
        consensus.nHMPStage4Height = 200;  // full HMP with negative proofs
        consensus.nHMPCommitmentOffset = 10; // Phase 1: 10-block pubkey commitment maturity
        // Mandatory zk-SNARK proof height: 0 = never enforce.
        // Groth16 proofs are Phase 2 (post-launch hard fork).
        consensus.nHMPMandatoryProofHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        // Testnet powLimit: ~uint256(0) >> 1, very easy for CPU mining all algos.
        // Equihash BLAKE2b PoW hash varies per solution; with ~2^254 target, ~30% of
        // solutions pass, giving fast Equihash mining. Genesis nBits (0x2000ffff) is
        // below this limit and remains valid.
        consensus.powLimit = uint256S("7fffff0000000000000000000000000000000000000000000000000000000000");
        // No per-algo floors on testnet; all algos use global powLimit for CPU mining
        for (int i = 0; i < NUM_ALGOS; i++) consensus.powLimitAlgo[i] = consensus.powLimit;
        // Height-activated difficulty floor: after nDiffFloorHeight, DAA output
        // is clamped to per-algo floors. Testnet floors recalibrated for CPU
        // mining (mainnet uses harder values).
        consensus.nDiffFloorHeight = 2260;
        consensus.powLimitFloorAlgo[ALGO_X11]          = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");  // ~2^236, testnet CPU-minable
        consensus.powLimitFloorAlgo[ALGO_KAWPOW]       = uint256S("000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");  // ~2^244, testnet CPU-minable
        consensus.powLimitFloorAlgo[ALGO_EQUIHASH_200] = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");  // ~2^241, testnet CPU-minable
        consensus.powLimitFloorAlgo[ALGO_EQUIHASH_192] = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");  // ~2^252, testnet CPU-minable
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Kerrigan: 1 day
        consensus.nPowTargetSpacing = 120; // Kerrigan: 2 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // BIP9 signaling window
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_V24].bit = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE; // Kerrigan does not use V24
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nThresholdStart = 80;       // 80% of 100
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nThresholdMin = 60;         // 60% of 100
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nFalloffCoeff = 5;          // this corresponds to 10 periods
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].useEHF = true;

        // Verify no BIP9 deployment uses bits 8-11 (reserved for algo encoding)
        for (int i = 0; i < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
            int bit = consensus.vDeployments[i].bit;
            if (bit >= 8 && bit <= 11) {
                throw std::runtime_error(strprintf("BIP9 deployment %d uses bit %d which collides with algo encoding", i, bit));
            }
        }

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        // Test-only treasury hashes, NOT real wallets, testnet funds have no value
        // Derived from sha256("kerrigan-testnet-{role}-test-only")[:40]
        consensus.foundersPaymentScript = BuildTreasuryScript("7d07fca94d3bc5a2229f8f201babb44e82f46d5d");
        consensus.devFundPaymentScript = BuildTreasuryScript("6b642237272cd37fd77de4b299579f8850b8cd09");
        consensus.growthEscrowScript = BuildTreasuryScript("62401dcf73aa0e06c91f44add1e5c24d96ae07ac");
        consensus.nGrowthEscrowEndHeight = 262800; // Same sunset as mainnet

        // "krgt" - Kerrigan testnet network magic
        pchMessageStart[0] = 0x6b; // k
        pchMessageStart[1] = 0x72; // r
        pchMessageStart[2] = 0x67; // g
        pchMessageStart[3] = 0x74; // t
        nDefaultPort = 17120;
        nDefaultPlatformP2PPort = 17121;
        nDefaultPlatformHTTPPort = 17122;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        // Testnet: past timestamp (2025-02-28), easy powLimit for CPU mining all algos
        // Uses original P2PK output script to preserve existing testnet chain.
        {
            const char* pszTimestamp = "Reuters 27/Feb/2026 GPU miners bridge to decentralized AI inference";
            const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
            genesis = CreateGenesisBlock(pszTimestamp, genesisOutputScript, 1740700800, 118, 0x2000ffff, 1, 25 * COIN);
        }
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0013e791b16aa0491287b31d15c788d867a11d11031dac96842021d2213deb28"));
        assert(genesis.hashMerkleRoot == uint256S("0x2deb2fe357303593e3c1e842fd4722e824629c6b99b8171549ec932a733d8dda"));

        vFixedSeeds.assign(chainparams_seed_test, chainparams_seed_test + sizeof(chainparams_seed_test));
        vSeeds.clear();

        // Testnet Kerrigan addresses start with 'k'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 107);
        // Testnet Kerrigan script addresses start with '8' or '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);
        // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 239);
        // Testnet Kerrigan BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        // Testnet Kerrigan BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // Testnet Kerrigan BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        // Sapling shielded address Bech32m HRP
        strSaplingHRP = "ktestsapling";

        // long living quorum params
        AddLLMQ(Consensus::LLMQType::LLMQ_50_60);
        AddLLMQ(Consensus::LLMQType::LLMQ_60_75);
        AddLLMQ(Consensus::LLMQType::LLMQ_400_60);
        AddLLMQ(Consensus::LLMQType::LLMQ_400_85);
        AddLLMQ(Consensus::LLMQType::LLMQ_100_67);
        AddLLMQ(Consensus::LLMQType::LLMQ_25_67);
        consensus.llmqTypeChainLocks = Consensus::LLMQType::LLMQ_50_60;
        consensus.llmqTypeDIP0024InstantSend = Consensus::LLMQType::LLMQ_60_75;
        consensus.llmqTypePlatform = Consensus::LLMQType::LLMQ_25_67;
        consensus.llmqTypeMnhf = Consensus::LLMQType::LLMQ_50_60;

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fRequireRoutableExternalIP = true;
        m_is_test_chain = true;
        fAllowMultipleAddressesFromGroup = false;
        nLLMQConnectionRetryTimeout = 60;
        m_is_mockable_chain = false;

        nPoolMinParticipants = 2;
        nPoolMaxParticipants = 20;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        vSporkAddresses = {"kFYkX1txwxVZZMnXeqSvJ9hYJmhxnjBWXd"};
        nMinSporkKeys = 1;

        nCreditPoolPeriodBlocks = 576;

        checkpointData = {
            {
                {0, uint256S("0x0013e791b16aa0491287b31d15c788d867a11d11031dac96842021d2213deb28")},
            }
        };

        m_assumeutxo_data = MapAssumeutxo{};

        chainTxData = ChainTxData{
                0,
                0,
                0
        };

        // DIP activation ordering assertions (must hold for consensus correctness)
        assert(consensus.V20Height >= consensus.DIP0003Height);
        assert(consensus.MN_RRHeight >= consensus.V20Height);
        assert(consensus.DIP0003EnforcementHeight >= consensus.DIP0003Height);
    }
};

/**
 * Devnet: The Development network intended for developers use.
 */
class CDevNetParams : public CChainParams {
public:
    explicit CDevNetParams(const ArgsManager& args) {
        strNetworkID = CBaseChainParams::DEVNET;
        consensus.nSubsidyHalvingInterval = 1051200;
        consensus.nMasternodePaymentsStartBlock = 1;
        consensus.nMasternodePaymentsIncreaseBlock = 2100000000;
        consensus.nMasternodePaymentsIncreasePeriod = 1;
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 4100;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nSuperblockStartBlock = 2100000000; // Disabled, Kerrigan does not use governance superblocks
        consensus.nSuperblockStartHash = uint256(); // do not check this on devnet
        consensus.nSuperblockCycle = 24;
        consensus.nSuperblockMaturityWindow = 8;
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.BIP34Height = 1;   // BIP34 activated immediately on devnet
        consensus.BIP65Height = 1;   // BIP65 activated immediately on devnet
        consensus.BIP66Height = 1;   // BIP66 activated immediately on devnet
        consensus.BIP147Height = 1;  // BIP147 activated immediately on devnet
        consensus.CSVHeight = 1;     // BIP68 activated immediately on devnet
        consensus.DIP0001Height = 2; // DIP0001 activated immediately on devnet
        consensus.DIP0003Height = 2; // DIP0003 activated immediately on devnet
        consensus.DIP0003EnforcementHeight = 2; // DIP0003 activated immediately on devnet
        consensus.DIP0003EnforcementHash = uint256();
        consensus.DIP0008Height = 2; // DIP0008 activated immediately on devnet
        consensus.BRRHeight = 2;     // BRR (realloc) activated immediately on devnet
        consensus.DIP0020Height = 2; // DIP0020 activated immediately on devnet
        consensus.DIP0024Height = 2; // DIP0024 activated immediately on devnet
        consensus.DIP0024QuorumsHeight = 2; // DIP0024 activated immediately on devnet
        consensus.V19Height = 2;     // V19 activated immediately on devnet
        consensus.V20Height = 2;     // V20 activated immediately on devnet
        consensus.MN_RRHeight = 2;   // MN_RR activated immediately on devnet
        consensus.WithdrawalsHeight = 2;   // withdrawals activated immediately on devnet
        consensus.SaplingHeight = 2;       // Sapling activated immediately on devnet
        consensus.nSaplingStrictnessHeight = 0; // Strict from genesis on devnet
        consensus.HMPHeight = 2;            // Hivemind HMP Stage 2 at block 2
        // 4-stage HMP bootstrap:
        consensus.nHMPStage2Height = 2;    // commitments open early on devnet
        consensus.nHMPStage3Height = 5;    // soft seal begins
        consensus.nHMPStage4Height = 10;   // full HMP with negative proofs
        consensus.nHMPCommitmentOffset = 10; // Phase 1: 10-block pubkey commitment maturity
        // Mandatory zk-SNARK proof height: 0 = never enforce.
        // Groth16 proofs are Phase 2 (post-launch hard fork).
        consensus.nHMPMandatoryProofHeight = 0;
        consensus.MinBIP9WarningHeight = 2 + 2016; // withdrawals activation height + miner confirmation window
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 1
        // No per-algo floors on devnet; all algos use global powLimit
        for (int i = 0; i < NUM_ALGOS; i++) consensus.powLimitAlgo[i] = consensus.powLimit;
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Kerrigan: 1 day
        consensus.nPowTargetSpacing = 120; // Kerrigan: 2 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // BIP9 signaling window
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_V24].bit = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nStartTime = 1751328000;    // July 1, 2025
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nWindowSize = 120;
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nThresholdStart = 96;       // 80% of 120
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nThresholdMin = 72;         // 60% of 120
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nFalloffCoeff = 5;          // this corresponds to 10 periods
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].useEHF = true;

        // Verify no BIP9 deployment uses bits 8-11 (reserved for algo encoding)
        for (int i = 0; i < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
            int bit = consensus.vDeployments[i].bit;
            if (bit >= 8 && bit <= 11) {
                throw std::runtime_error(strprintf("BIP9 deployment %d uses bit %d which collides with algo encoding", i, bit));
            }
        }

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        // "krgn-devnet" magic - sha256("krgn-devnet")[0:4] = 0x1d 0x54 0x3b 0x94
        // Distinct from mainnet (KRGN=0x4b52474e), testnet (krgt), and regtest (krgr).
        pchMessageStart[0] = 0x1d;
        pchMessageStart[1] = 0x54;
        pchMessageStart[2] = 0x3b;
        pchMessageStart[3] = 0x94;
        nDefaultPort = 37120; // 7120 + 30000 (Kerrigan devnet)
        nDefaultPlatformP2PPort = 22100;
        nDefaultPlatformHTTPPort = 22101;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        // Test-only treasury hashes, NOT real wallets, devnet funds have no value
        // Derived from sha256("kerrigan-devnet-{role}-test-only")[:40]
        consensus.foundersPaymentScript = BuildTreasuryScript("7503984d5714574884102529492a4d3b46900cd7");
        consensus.devFundPaymentScript = BuildTreasuryScript("a39764ebef30eb2dfce24d626784b88ee053e3b7");
        consensus.growthEscrowScript = BuildTreasuryScript("0df05cdab550e3dff3d2ec86f0a6e5cda72efccb");
        consensus.nGrowthEscrowEndHeight = 262800;

        UpdateDevnetSubsidyAndDiffParametersFromArgs(args);
        genesis = CreateGenesisBlock(1773446400, 1, 0x207fffff, 1, 25 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        // Devnet genesis hash validated at startup (easy difficulty, nonce=1 always works)

        devnetGenesis = FindDevNetGenesisBlock(genesis, 25 * COIN);
        consensus.hashDevnetGenesisBlock = devnetGenesis.GetHash();

        vFixedSeeds.clear();
        vSeeds.clear();

        // Devnet Kerrigan addresses start with 'y'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,140);
        // Devnet Kerrigan script addresses start with '8' or '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);
        // Devnet private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Devnet Kerrigan BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        // Devnet Kerrigan BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // Devnet Kerrigan BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        // Sapling shielded address Bech32m HRP
        strSaplingHRP = "kdevsapling";

        // long living quorum params
        AddLLMQ(Consensus::LLMQType::LLMQ_50_60);
        AddLLMQ(Consensus::LLMQType::LLMQ_60_75);
        AddLLMQ(Consensus::LLMQType::LLMQ_400_60);
        AddLLMQ(Consensus::LLMQType::LLMQ_400_85);
        AddLLMQ(Consensus::LLMQType::LLMQ_100_67);
        AddLLMQ(Consensus::LLMQType::LLMQ_DEVNET);
        AddLLMQ(Consensus::LLMQType::LLMQ_DEVNET_DIP0024);
        AddLLMQ(Consensus::LLMQType::LLMQ_DEVNET_PLATFORM);
        consensus.llmqTypeChainLocks = Consensus::LLMQType::LLMQ_DEVNET;
        consensus.llmqTypeDIP0024InstantSend = Consensus::LLMQType::LLMQ_DEVNET_DIP0024;
        consensus.llmqTypePlatform = Consensus::LLMQType::LLMQ_DEVNET_PLATFORM;
        consensus.llmqTypeMnhf = Consensus::LLMQType::LLMQ_DEVNET;

        UpdateDevnetLLMQChainLocksFromArgs(args);
        UpdateDevnetLLMQInstantSendDIP0024FromArgs(args);
        UpdateDevnetLLMQPlatformFromArgs(args);
        UpdateDevnetLLMQMnhfFromArgs(args);
        UpdateLLMQDevnetParametersFromArgs(args);
        UpdateDevnetPowTargetSpacingFromArgs(args);

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fRequireRoutableExternalIP = true;
        m_is_test_chain = true;
        fAllowMultipleAddressesFromGroup = true;
        nLLMQConnectionRetryTimeout = 60;
        m_is_mockable_chain = false;

        nPoolMinParticipants = 2;
        nPoolMaxParticipants = 20;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        // Test-only devnet spork address, NOT a real wallet key.
        // Derived from sha256/ripemd160("kerrigan-devnet-spork-test-only") with version byte 140 ('y' prefix).
        vSporkAddresses = {"yUSMHqGhi86Y3YADVEddwumYpbZKYYMZZi"};
        nMinSporkKeys = 1;


        nCreditPoolPeriodBlocks = 576;

        checkpointData = (CCheckpointData) {
            {
                {0, uint256S("0x4b2eb93d5339f7ab42caca1c9cfcfd7ffd489d2909e67727715bcc64223cd06a")},
            }
        };

        chainTxData = ChainTxData{
            devnetGenesis.GetBlockTime(), // * UNIX timestamp of devnet genesis block
            2,                            // * we only have 2 coinbase transactions when a devnet is started up
            0.01                          // * estimated number of transactions per second
        };
    }

    /**
     * Allows modifying the subsidy and difficulty devnet parameters.
     */
    void UpdateDevnetSubsidyAndDiffParameters(int nMinimumDifficultyBlocks, int nHighSubsidyBlocks, int nHighSubsidyFactor)
    {
        consensus.nMinimumDifficultyBlocks = nMinimumDifficultyBlocks;
        consensus.nHighSubsidyBlocks = nHighSubsidyBlocks;
        consensus.nHighSubsidyFactor = nHighSubsidyFactor;
    }
    void UpdateDevnetSubsidyAndDiffParametersFromArgs(const ArgsManager& args);

    /**
     * Allows modifying the LLMQ type for ChainLocks.
     */
    void UpdateDevnetLLMQChainLocks(Consensus::LLMQType llmqType)
    {
        consensus.llmqTypeChainLocks = llmqType;
    }
    void UpdateDevnetLLMQChainLocksFromArgs(const ArgsManager& args);

    /**
     * Allows modifying the LLMQ type for InstantSend (DIP0024).
     */
    void UpdateDevnetLLMQDIP0024InstantSend(Consensus::LLMQType llmqType)
    {
        consensus.llmqTypeDIP0024InstantSend = llmqType;
    }

    /**
     * Allows modifying the LLMQ type for Platform.
     */
    void UpdateDevnetLLMQPlatform(Consensus::LLMQType llmqType)
    {
        consensus.llmqTypePlatform = llmqType;
    }

    /**
     * Allows modifying the LLMQ type for Mnhf.
     */
    void UpdateDevnetLLMQMnhf(Consensus::LLMQType llmqType)
    {
        consensus.llmqTypeMnhf = llmqType;
    }

    /**
     * Allows modifying PowTargetSpacing
     */
    void UpdateDevnetPowTargetSpacing(int64_t nPowTargetSpacing)
    {
        consensus.nPowTargetSpacing = nPowTargetSpacing;
    }

    /**
     * Allows modifying parameters of the devnet LLMQ
     */
    void UpdateLLMQDevnetParameters(int size, int threshold)
    {
        auto params = ranges::find_if(consensus.llmqs, [](const auto& llmq){ return llmq.type == Consensus::LLMQType::LLMQ_DEVNET;});
        assert(params != consensus.llmqs.end());
        params->size = size;
        params->minSize = threshold;
        params->threshold = threshold;
        params->dkgBadVotesThreshold = threshold;
    }
    void UpdateLLMQDevnetParametersFromArgs(const ArgsManager& args);
    void UpdateDevnetLLMQInstantSendFromArgs(const ArgsManager& args);
    void UpdateDevnetLLMQInstantSendDIP0024FromArgs(const ArgsManager& args);
    void UpdateDevnetLLMQPlatformFromArgs(const ArgsManager& args);
    void UpdateDevnetLLMQMnhfFromArgs(const ArgsManager& args);
    void UpdateDevnetPowTargetSpacingFromArgs(const ArgsManager& args);
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID =  CBaseChainParams::REGTEST;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMasternodePaymentsStartBlock = 1;
        consensus.nMasternodePaymentsIncreaseBlock = 2100000000;
        consensus.nMasternodePaymentsIncreasePeriod = 1;
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 1000;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nSuperblockStartBlock = 1500;
        consensus.nSuperblockStartHash = uint256(); // do not check this on regtest
        consensus.nSuperblockCycle = 20;
        consensus.nSuperblockMaturityWindow = 10;
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 100;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.BIP34Height = 1;   // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;   // Always active unless overridden
        consensus.BIP66Height = 1;   // Always active unless overridden
        consensus.BIP147Height = 0;  // Always active unless overridden
        consensus.CSVHeight = 1;     // Always active unless overridden
        consensus.DIP0001Height = 1; // Always active unless overridden
        consensus.DIP0003Height = 432; // Always active for KerriganTestFramework in functional tests (see dip3params)
                                       // For unit tests and for BitcoinTestFramework is disabled due to missing quorum commitment for blocks created by helpers such as create_blocks
        consensus.DIP0003EnforcementHeight = 500;
        consensus.DIP0003EnforcementHash = uint256();
        consensus.DIP0008Height = 1; // Always active unless overridden
        consensus.BRRHeight = 1;     // Always active unless overridden
        consensus.DIP0020Height = 1; // Always active unless overridden
        consensus.DIP0024Height = 1; // Always have dip0024 quorums unless overridden
        consensus.DIP0024QuorumsHeight = 1; // Always have dip0024 quorums unless overridden
        consensus.V19Height = 1; // Always active unless overridden
        consensus.V20Height = consensus.DIP0003Height; // Active not earlier than dip0003. Functional tests (KerriganTestFramework) uses height 100 (same as coinbase maturity)
        consensus.MN_RRHeight = consensus.V20Height; // MN_RR does not really have effect before v20 activation
        consensus.WithdrawalsHeight = 600;
        consensus.SaplingHeight = 0; // Sapling active from genesis on regtest
        consensus.nSaplingStrictnessHeight = 0; // Strict from genesis on regtest
        consensus.HMPHeight = 0;    // Hivemind HMP active from genesis on regtest
        // 4-stage HMP bootstrap: all active immediately for unit tests
        consensus.nHMPStage2Height = 0;
        consensus.nHMPStage3Height = 0;
        consensus.nHMPStage4Height = 0;
        consensus.nHMPCommitmentOffset = 10; // Phase 1: 10-block pubkey commitment maturity
        // Mandatory zk-SNARK proof height: 0 = never enforce.
        // Groth16 proofs are Phase 2 (post-launch hard fork).
        consensus.nHMPMandatoryProofHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 1
        // No per-algo floors on regtest; all algos use global powLimit
        for (int i = 0; i < NUM_ALGOS; i++) consensus.powLimitAlgo[i] = consensus.powLimit;
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Kerrigan: 1 day
        consensus.nPowTargetSpacing = 120; // Kerrigan: 2 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_V24].bit = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nWindowSize = 250;
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nThresholdStart = 250 / 5 * 4;     // 80% of window size
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nThresholdMin = 250 / 5 * 3;       // 60% of window size
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].nFalloffCoeff = 5;                 // this corresponds to 10 periods
        consensus.vDeployments[Consensus::DEPLOYMENT_V24].useEHF = true;

        // Verify no BIP9 deployment uses bits 8-11 (reserved for algo encoding)
        for (int i = 0; i < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
            int bit = consensus.vDeployments[i].bit;
            if (bit >= 8 && bit <= 11) {
                throw std::runtime_error(strprintf("BIP9 deployment %d uses bit %d which collides with algo encoding", i, bit));
            }
        }

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        // "krgr" - Kerrigan regtest network magic
        pchMessageStart[0] = 0x6b; // k
        pchMessageStart[1] = 0x72; // r
        pchMessageStart[2] = 0x67; // g
        pchMessageStart[3] = 0x72; // r
        nDefaultPort = 27120;
        nDefaultPlatformP2PPort = 27121;
        nDefaultPlatformHTTPPort = 27122;
        nPruneAfterHeight = args.GetBoolArg("-fastprune", false) ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        // Test-only treasury hashes, NOT real wallets, regtest funds have no value
        // Derived from sha256("kerrigan-regtest-{role}-test-only")[:40]
        consensus.foundersPaymentScript = BuildTreasuryScript("fd264480b44878cdf763c9cf4daa354bbb87a4e8");
        consensus.devFundPaymentScript = BuildTreasuryScript("5d9f2310a8602b46e6e93c8277a8c9e8ea7c7ee6");
        consensus.growthEscrowScript = BuildTreasuryScript("b0841b8f59f554fb92c7951ed9f890faba8e8f89");
        consensus.nGrowthEscrowEndHeight = 500; // Short for regtest

        UpdateActivationParametersFromArgs(args);
        UpdateDIP3ParametersFromArgs(args);
        UpdateBudgetParametersFromArgs(args);

        genesis = CreateGenesisBlock(1773446400, 1, 0x207fffff, 1, 25 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        vFixedSeeds.clear();
        vSeeds.clear();

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        fRequireRoutableExternalIP = false;
        m_is_test_chain = true;
        fAllowMultipleAddressesFromGroup = true;
        nLLMQConnectionRetryTimeout = 1; // must be lower then the LLMQ signing session timeout so that tests have control over failing behavior
        m_is_mockable_chain = true;

        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        nPoolMinParticipants = 2;
        nPoolMaxParticipants = 20;

        vSporkAddresses = {"kSN8WQ66mTWeWBvqGWMSQ3dWv2itCLf4i1"};
        nMinSporkKeys = 1;

        nCreditPoolPeriodBlocks = 100;

        // No checkpoint for regtest, genesis hash is parameter-dependent
        checkpointData = {};

        m_assumeutxo_data = MapAssumeutxo{};

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        // Regtest Kerrigan addresses start with 'k'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 107);
        // Regtest Kerrigan script addresses start with '8' or '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);
        // Regtest private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 239);
        // Regtest Kerrigan BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        // Regtest Kerrigan BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // Regtest Kerrigan BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        // Sapling shielded address Bech32m HRP
        strSaplingHRP = "kregsapling";

        // long living quorum params
        AddLLMQ(Consensus::LLMQType::LLMQ_TEST);
        AddLLMQ(Consensus::LLMQType::LLMQ_TEST_INSTANTSEND);
        AddLLMQ(Consensus::LLMQType::LLMQ_TEST_V17);
        AddLLMQ(Consensus::LLMQType::LLMQ_TEST_DIP0024);
        AddLLMQ(Consensus::LLMQType::LLMQ_TEST_PLATFORM);
        consensus.llmqTypeChainLocks = Consensus::LLMQType::LLMQ_TEST;
        consensus.llmqTypeDIP0024InstantSend = Consensus::LLMQType::LLMQ_TEST_DIP0024;
        consensus.llmqTypePlatform = Consensus::LLMQType::LLMQ_TEST_PLATFORM;
        consensus.llmqTypeMnhf = Consensus::LLMQType::LLMQ_TEST;

        UpdateLLMQTestParametersFromArgs(args, Consensus::LLMQType::LLMQ_TEST);
        UpdateLLMQTestParametersFromArgs(args, Consensus::LLMQType::LLMQ_TEST_INSTANTSEND);
        UpdateLLMQTestParametersFromArgs(args, Consensus::LLMQType::LLMQ_TEST_PLATFORM);
        UpdateLLMQInstantSendDIP0024FromArgs(args);
        // V20 features for CbTx (credit pool, CL) have no meaning without masternodes
        assert(consensus.V20Height >= consensus.DIP0003Height);
        // MN_RR reallocate part of reward to CreditPool which exits since V20
        assert(consensus.MN_RRHeight >= consensus.V20Height);
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout, int min_activation_height, int64_t nWindowSize, int64_t nThresholdStart, int64_t nThresholdMin, int64_t nFalloffCoeff, int64_t nUseEHF)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
        consensus.vDeployments[d].min_activation_height = min_activation_height;
        if (nWindowSize != -1) {
            consensus.vDeployments[d].nWindowSize = nWindowSize;
        }
        if (nThresholdStart != -1) {
            consensus.vDeployments[d].nThresholdStart = nThresholdStart;
        }
        if (nThresholdMin != -1) {
            consensus.vDeployments[d].nThresholdMin = nThresholdMin;
        }
        if (nFalloffCoeff != -1) {
            consensus.vDeployments[d].nFalloffCoeff = nFalloffCoeff;
        }
        if (nUseEHF != -1) {
            consensus.vDeployments[d].useEHF = nUseEHF > 0;
        }
    }
    void UpdateActivationParametersFromArgs(const ArgsManager& args);

    /**
     * Allows modifying the DIP3 activation and enforcement height
     */
    void UpdateDIP3Parameters(int nActivationHeight, int nEnforcementHeight)
    {
        consensus.DIP0003Height = nActivationHeight;
        consensus.DIP0003EnforcementHeight = nEnforcementHeight;
    }
    void UpdateDIP3ParametersFromArgs(const ArgsManager& args);

    /**
     * Allows modifying the budget regtest parameters.
     */
    void UpdateBudgetParameters(int nMasternodePaymentsStartBlock, int nBudgetPaymentsStartBlock, int nSuperblockStartBlock)
    {
        consensus.nMasternodePaymentsStartBlock = nMasternodePaymentsStartBlock;
        consensus.nBudgetPaymentsStartBlock = nBudgetPaymentsStartBlock;
        consensus.nSuperblockStartBlock = nSuperblockStartBlock;
    }
    void UpdateBudgetParametersFromArgs(const ArgsManager& args);

    /**
     * Allows modifying parameters of the test LLMQ
     */
    void UpdateLLMQTestParameters(int size, int threshold, const Consensus::LLMQType llmqType)
    {
        auto params = ranges::find_if(consensus.llmqs, [llmqType](const auto& llmq){ return llmq.type == llmqType;});
        assert(params != consensus.llmqs.end());
        params->size = size;
        params->minSize = threshold;
        params->threshold = threshold;
        params->dkgBadVotesThreshold = threshold;
    }

    /**
     * Allows modifying the LLMQ type for InstantSend (DIP0024).
     */
    void UpdateLLMQDIP0024InstantSend(Consensus::LLMQType llmqType)
    {
        consensus.llmqTypeDIP0024InstantSend = llmqType;
    }

    void UpdateLLMQTestParametersFromArgs(const ArgsManager& args, const Consensus::LLMQType llmqType);
    void UpdateLLMQInstantSendDIP0024FromArgs(const ArgsManager& args);
};

static void MaybeUpdateHeights(const ArgsManager& args, Consensus::Params& consensus)
{
    for (const std::string& arg : args.GetArgs("-testactivationheight")) {
        const auto found{arg.find('@')};
        if (found == std::string::npos) {
            throw std::runtime_error(strprintf("Invalid format (%s) for -testactivationheight=name@height.", arg));
        }
        const auto name{arg.substr(0, found)};
        const auto value{arg.substr(found + 1)};
        int32_t height;
        if (!ParseInt32(value, &height) || height < 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%s) for -testactivationheight=name@height.", arg));
        }
        if (name == "bip147") {
            consensus.BIP147Height = int{height};
        } else if (name == "bip34") {
            consensus.BIP34Height = int{height};
        } else if (name == "dersig") {
            consensus.BIP66Height = int{height};
        } else if (name == "cltv") {
            consensus.BIP65Height = int{height};
        } else if (name == "csv") {
            consensus.CSVHeight = int{height};
        } else if (name == "brr") {
            consensus.BRRHeight = int{height};
        } else if (name == "dip0001") {
            consensus.DIP0001Height = int{height};
        } else if (name == "dip0008") {
            consensus.DIP0008Height = int{height};
        } else if (name == "dip0024") {
            consensus.DIP0024Height = int{height};
            consensus.DIP0024QuorumsHeight = int{height};
        } else if (name == "v19") {
            consensus.V19Height = int{height};
        } else if (name == "v20") {
            consensus.V20Height = int{height};
        } else if (name == "mn_rr") {
            consensus.MN_RRHeight = int{height};
        } else if (name == "sapling") {
            consensus.SaplingHeight = int{height};
        } else if (name == "hmp") {
            consensus.HMPHeight = int{height};
            consensus.nHMPStage2Height = int{height};
            consensus.nHMPStage3Height = int{height} + 200;
            consensus.nHMPStage4Height = int{height} + 400;
        } else if (name == "withdrawals") {
            consensus.WithdrawalsHeight = int{height};
        } else {
            throw std::runtime_error(strprintf("Invalid name (%s) for -testactivationheight=name@height.", arg));
        }
    }
}

void CRegTestParams::UpdateActivationParametersFromArgs(const ArgsManager& args)
{
    MaybeUpdateHeights(args, consensus);

    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams = SplitString(strDeployment, ':');
        if (vDeploymentParams.size() != 3 && vDeploymentParams.size() != 4 && vDeploymentParams.size() != 6 && vDeploymentParams.size() != 9) {
            throw std::runtime_error("Version bits parameters malformed, expecting "
                    "<deployment>:<start>:<end> or "
                    "<deployment>:<start>:<end>:<min_activation_height> or "
                    "<deployment>:<start>:<end>:<min_activation_height>:<window>:<threshold> or "
                    "<deployment>:<start>:<end>:<min_activation_height>:<window>:<thresholdstart>:<thresholdmin>:<falloffcoeff>:<useehf>");
        }
        int64_t nStartTime, nTimeout, nWindowSize = -1, nThresholdStart = -1, nThresholdMin = -1, nFalloffCoeff = -1, nUseEHF = -1;
        int min_activation_height = 0;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        if (vDeploymentParams.size() >= 4 && !ParseInt32(vDeploymentParams[3], &min_activation_height)) {
            throw std::runtime_error(strprintf("Invalid min_activation_height (%s)", vDeploymentParams[3]));
        }
        if (vDeploymentParams.size() >= 6) {
            if (!ParseInt64(vDeploymentParams[4], &nWindowSize)) {
                throw std::runtime_error(strprintf("Invalid nWindowSize (%s)", vDeploymentParams[4]));
            }
            if (!ParseInt64(vDeploymentParams[5], &nThresholdStart)) {
                throw std::runtime_error(strprintf("Invalid nThresholdStart (%s)", vDeploymentParams[5]));
            }
        }
        if (vDeploymentParams.size() == 9) {
            if (!ParseInt64(vDeploymentParams[6], &nThresholdMin)) {
                throw std::runtime_error(strprintf("Invalid nThresholdMin (%s)", vDeploymentParams[6]));
            }
            if (!ParseInt64(vDeploymentParams[7], &nFalloffCoeff)) {
                throw std::runtime_error(strprintf("Invalid nFalloffCoeff (%s)", vDeploymentParams[7]));
            }
            if (!ParseInt64(vDeploymentParams[8], &nUseEHF)) {
                throw std::runtime_error(strprintf("Invalid nUseEHF (%s)", vDeploymentParams[8]));
            }
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout, min_activation_height, nWindowSize, nThresholdStart, nThresholdMin, nFalloffCoeff, nUseEHF);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld, min_activation_height=%ld, window=%ld, thresholdstart=%ld, thresholdmin=%ld, falloffcoeff=%ld, useehf=%ld\n",
                          vDeploymentParams[0], nStartTime, nTimeout, min_activation_height, nWindowSize, nThresholdStart, nThresholdMin, nFalloffCoeff, nUseEHF);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

void CRegTestParams::UpdateDIP3ParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-dip3params")) return;

    std::string strParams = args.GetArg("-dip3params", "");
    std::vector<std::string> vParams = SplitString(strParams, ':');
    if (vParams.size() != 2) {
        throw std::runtime_error("DIP3 parameters malformed, expecting <activation>:<enforcement>");
    }
    int nDIP3ActivationHeight, nDIP3EnforcementHeight;
    if (!ParseInt32(vParams[0], &nDIP3ActivationHeight)) {
        throw std::runtime_error(strprintf("Invalid activation height (%s)", vParams[0]));
    }
    if (!ParseInt32(vParams[1], &nDIP3EnforcementHeight)) {
        throw std::runtime_error(strprintf("Invalid enforcement height (%s)", vParams[1]));
    }
    LogPrintf("Setting DIP3 parameters to activation=%ld, enforcement=%ld\n", nDIP3ActivationHeight, nDIP3EnforcementHeight);
    UpdateDIP3Parameters(nDIP3ActivationHeight, nDIP3EnforcementHeight);
}

void CRegTestParams::UpdateBudgetParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-budgetparams")) return;

    std::string strParams = args.GetArg("-budgetparams", "");
    std::vector<std::string> vParams = SplitString(strParams, ':');
    if (vParams.size() != 3) {
        throw std::runtime_error("Budget parameters malformed, expecting <masternode>:<budget>:<superblock>");
    }
    int nMasternodePaymentsStartBlock, nBudgetPaymentsStartBlock, nSuperblockStartBlock;
    if (!ParseInt32(vParams[0], &nMasternodePaymentsStartBlock)) {
        throw std::runtime_error(strprintf("Invalid masternode start height (%s)", vParams[0]));
    }
    if (!ParseInt32(vParams[1], &nBudgetPaymentsStartBlock)) {
        throw std::runtime_error(strprintf("Invalid budget start block (%s)", vParams[1]));
    }
    if (!ParseInt32(vParams[2], &nSuperblockStartBlock)) {
        throw std::runtime_error(strprintf("Invalid superblock start height (%s)", vParams[2]));
    }
    LogPrintf("Setting budget parameters to masternode=%ld, budget=%ld, superblock=%ld\n", nMasternodePaymentsStartBlock, nBudgetPaymentsStartBlock, nSuperblockStartBlock);
    UpdateBudgetParameters(nMasternodePaymentsStartBlock, nBudgetPaymentsStartBlock, nSuperblockStartBlock);
}

void CRegTestParams::UpdateLLMQTestParametersFromArgs(const ArgsManager& args, const Consensus::LLMQType llmqType)
{
    assert(llmqType == Consensus::LLMQType::LLMQ_TEST || llmqType == Consensus::LLMQType::LLMQ_TEST_INSTANTSEND || llmqType == Consensus::LLMQType::LLMQ_TEST_PLATFORM);

    std::string cmd_param{"-llmqtestparams"}, llmq_name{"LLMQ_TEST"};
    if (llmqType == Consensus::LLMQType::LLMQ_TEST_INSTANTSEND) {
        cmd_param = "-llmqtestinstantsendparams";
        llmq_name = "LLMQ_TEST_INSTANTSEND";
    }
    if (llmqType == Consensus::LLMQType::LLMQ_TEST_PLATFORM) {
        cmd_param = "-llmqtestplatformparams";
        llmq_name = "LLMQ_TEST_PLATFORM";
    }

    if (!args.IsArgSet(cmd_param)) return;

    std::string strParams = args.GetArg(cmd_param, "");
    std::vector<std::string> vParams = SplitString(strParams, ':');
    if (vParams.size() != 2) {
        throw std::runtime_error(strprintf("%s parameters malformed, expecting <size>:<threshold>", llmq_name));
    }
    int size, threshold;
    if (!ParseInt32(vParams[0], &size)) {
        throw std::runtime_error(strprintf("Invalid %s size (%s)", llmq_name, vParams[0]));
    }
    if (!ParseInt32(vParams[1], &threshold)) {
        throw std::runtime_error(strprintf("Invalid %s threshold (%s)", llmq_name, vParams[1]));
    }
    LogPrintf("Setting %s parameters to size=%ld, threshold=%ld\n", llmq_name, size, threshold);
    UpdateLLMQTestParameters(size, threshold, llmqType);
}

void CRegTestParams::UpdateLLMQInstantSendDIP0024FromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-llmqtestinstantsenddip0024")) return;

    const auto& llmq_params_opt = GetLLMQ(consensus.llmqTypeDIP0024InstantSend);
    assert(llmq_params_opt.has_value());

    std::string strLLMQType = gArgs.GetArg("-llmqtestinstantsenddip0024", std::string(llmq_params_opt->name));

    Consensus::LLMQType llmqType = Consensus::LLMQType::LLMQ_NONE;
    for (const auto& params : consensus.llmqs) {
        if (params.name == strLLMQType) {
            llmqType = params.type;
        }
    }
    if (llmqType == Consensus::LLMQType::LLMQ_NONE) {
        throw std::runtime_error("Invalid LLMQ type specified for -llmqtestinstantsenddip0024.");
    }
    LogPrintf("Setting llmqtestinstantsenddip0024 to %ld\n", ToUnderlying(llmqType));
    UpdateLLMQDIP0024InstantSend(llmqType);
}

void CDevNetParams::UpdateDevnetSubsidyAndDiffParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-minimumdifficultyblocks") && !args.IsArgSet("-highsubsidyblocks") && !args.IsArgSet("-highsubsidyfactor")) return;

    int nMinimumDifficultyBlocks = gArgs.GetIntArg("-minimumdifficultyblocks", consensus.nMinimumDifficultyBlocks);
    int nHighSubsidyBlocks = gArgs.GetIntArg("-highsubsidyblocks", consensus.nHighSubsidyBlocks);
    int nHighSubsidyFactor = gArgs.GetIntArg("-highsubsidyfactor", consensus.nHighSubsidyFactor);
    LogPrintf("Setting minimumdifficultyblocks=%ld, highsubsidyblocks=%ld, highsubsidyfactor=%ld\n", nMinimumDifficultyBlocks, nHighSubsidyBlocks, nHighSubsidyFactor);
    UpdateDevnetSubsidyAndDiffParameters(nMinimumDifficultyBlocks, nHighSubsidyBlocks, nHighSubsidyFactor);
}

void CDevNetParams::UpdateDevnetLLMQChainLocksFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-llmqchainlocks")) return;

    const auto& llmq_params_opt = GetLLMQ(consensus.llmqTypeChainLocks);
    assert(llmq_params_opt.has_value());

    std::string strLLMQType = gArgs.GetArg("-llmqchainlocks", std::string(llmq_params_opt->name));

    Consensus::LLMQType llmqType = Consensus::LLMQType::LLMQ_NONE;
    for (const auto& params : consensus.llmqs) {
        if (params.name == strLLMQType) {
            if (params.useRotation) {
                throw std::runtime_error("LLMQ type specified for -llmqchainlocks must NOT use rotation");
            }
            llmqType = params.type;
        }
    }
    if (llmqType == Consensus::LLMQType::LLMQ_NONE) {
        throw std::runtime_error("Invalid LLMQ type specified for -llmqchainlocks.");
    }
    LogPrintf("Setting llmqchainlocks to size=%ld\n", static_cast<uint8_t>(llmqType));
    UpdateDevnetLLMQChainLocks(llmqType);
}

void CDevNetParams::UpdateDevnetLLMQInstantSendDIP0024FromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-llmqinstantsenddip0024")) return;

    const auto& llmq_params_opt = GetLLMQ(consensus.llmqTypeDIP0024InstantSend);
    assert(llmq_params_opt.has_value());

    std::string strLLMQType = gArgs.GetArg("-llmqinstantsenddip0024", std::string(llmq_params_opt->name));

    Consensus::LLMQType llmqType = Consensus::LLMQType::LLMQ_NONE;
    for (const auto& params : consensus.llmqs) {
        if (params.name == strLLMQType) {
            if (!params.useRotation) {
                throw std::runtime_error("LLMQ type specified for -llmqinstantsenddip0024 must use rotation");
            }
            llmqType = params.type;
        }
    }
    if (llmqType == Consensus::LLMQType::LLMQ_NONE) {
        throw std::runtime_error("Invalid LLMQ type specified for -llmqinstantsenddip0024.");
    }
    LogPrintf("Setting llmqinstantsenddip0024 to size=%ld\n", static_cast<uint8_t>(llmqType));
    UpdateDevnetLLMQDIP0024InstantSend(llmqType);
}

void CDevNetParams::UpdateDevnetLLMQPlatformFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-llmqplatform")) return;

    const auto& llmq_params_opt = GetLLMQ(consensus.llmqTypePlatform);
    assert(llmq_params_opt.has_value());

    std::string strLLMQType = gArgs.GetArg("-llmqplatform", std::string(llmq_params_opt->name));

    Consensus::LLMQType llmqType = Consensus::LLMQType::LLMQ_NONE;
    for (const auto& params : consensus.llmqs) {
        if (params.name == strLLMQType) {
            llmqType = params.type;
        }
    }
    if (llmqType == Consensus::LLMQType::LLMQ_NONE) {
        throw std::runtime_error("Invalid LLMQ type specified for -llmqplatform.");
    }
    LogPrintf("Setting llmqplatform to size=%ld\n", static_cast<uint8_t>(llmqType));
    UpdateDevnetLLMQPlatform(llmqType);
}

void CDevNetParams::UpdateDevnetLLMQMnhfFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-llmqmnhf")) return;

    const auto& llmq_params_opt = GetLLMQ(consensus.llmqTypeMnhf);
    assert(llmq_params_opt.has_value());

    std::string strLLMQType = gArgs.GetArg("-llmqmnhf", std::string(llmq_params_opt->name));

    Consensus::LLMQType llmqType = Consensus::LLMQType::LLMQ_NONE;
    for (const auto& params : consensus.llmqs) {
        if (params.name == strLLMQType) {
            llmqType = params.type;
        }
    }
    if (llmqType == Consensus::LLMQType::LLMQ_NONE) {
        throw std::runtime_error("Invalid LLMQ type specified for -llmqmnhf.");
    }
    LogPrintf("Setting llmqmnhf to size=%ld\n", static_cast<uint8_t>(llmqType));
    UpdateDevnetLLMQMnhf(llmqType);
}

void CDevNetParams::UpdateDevnetPowTargetSpacingFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-powtargetspacing")) return;

    std::string strPowTargetSpacing = gArgs.GetArg("-powtargetspacing", "");

    int64_t powTargetSpacing;
    if (!ParseInt64(strPowTargetSpacing, &powTargetSpacing)) {
        throw std::runtime_error(strprintf("Invalid parsing of powTargetSpacing (%s)", strPowTargetSpacing));
    }

    if (powTargetSpacing < 1) {
        throw std::runtime_error(strprintf("Invalid value of powTargetSpacing (%s)", strPowTargetSpacing));
    }

    LogPrintf("Setting powTargetSpacing to %ld\n", powTargetSpacing);
    UpdateDevnetPowTargetSpacing(powTargetSpacing);
}

void CDevNetParams::UpdateLLMQDevnetParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-llmqdevnetparams")) return;

    std::string strParams = args.GetArg("-llmqdevnetparams", "");
    std::vector<std::string> vParams = SplitString(strParams, ':');
    if (vParams.size() != 2) {
        throw std::runtime_error("LLMQ_DEVNET parameters malformed, expecting <size>:<threshold>");
    }
    int size, threshold;
    if (!ParseInt32(vParams[0], &size)) {
        throw std::runtime_error(strprintf("Invalid LLMQ_DEVNET size (%s)", vParams[0]));
    }
    if (!ParseInt32(vParams[1], &threshold)) {
        throw std::runtime_error(strprintf("Invalid LLMQ_DEVNET threshold (%s)", vParams[1]));
    }
    LogPrintf("Setting LLMQ_DEVNET parameters to size=%ld, threshold=%ld\n", size, threshold);
    UpdateLLMQDevnetParameters(size, threshold);
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN) {
        return std::unique_ptr<CChainParams>(new CMainParams());
    } else if (chain == CBaseChainParams::TESTNET) {
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    } else if (chain == CBaseChainParams::DEVNET) {
        return std::unique_ptr<CChainParams>(new CDevNetParams(args));
    } else if (chain == CBaseChainParams::REGTEST) {
        return std::unique_ptr<CChainParams>(new CRegTestParams(args));
    }
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(gArgs, network);
}

void SetupChainParamsOptions(ArgsManager& argsman)
{
    SetupChainParamsBaseOptions(argsman);

    argsman.AddArg("-budgetparams=<masternode>:<budget>:<superblock>", "Override masternode, budget and superblock start heights (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-dip3params=<activation>:<enforcement>", "Override DIP3 activation and enforcement heights (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-highsubsidyblocks=<n>", "The number of blocks with a higher than normal subsidy to mine at the start of a chain. Block after that height will have fixed subsidy base. (default: 0, devnet-only)", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-highsubsidyfactor=<n>", "The factor to multiply the normal block subsidy by while in the highsubsidyblocks window of a chain (default: 1, devnet-only)", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-llmqchainlocks=<quorum name>", "Override the default LLMQ type used for ChainLocks. Allows using ChainLocks with smaller LLMQs. (default: llmq_devnet, devnet-only)", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-llmqdevnetparams=<size>:<threshold>", "Override the default LLMQ size for the LLMQ_DEVNET quorum (devnet-only)", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-llmqinstantsenddip0024=<quorum name>", "Override the default LLMQ type used for InstantSendDIP0024. (default: llmq_devnet_dip0024, devnet-only)", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-llmqplatform=<quorum name>", "Override the default LLMQ type used for Platform. (default: llmq_devnet_platform, devnet-only)", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-llmqmnhf=<quorum name>", "Override the default LLMQ type used for EHF. (default: llmq_devnet, devnet-only)", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-llmqtestinstantsenddip0024=<quorum name>", "Override the default LLMQ type used for InstantSendDIP0024. Used mainly to test Platform. (default: llmq_test_dip0024, regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-llmqtestinstantsendparams=<size>:<threshold>", "Override the default LLMQ size for the LLMQ_TEST_INSTANTSEND quorums (default: 3:2, regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-llmqtestparams=<size>:<threshold>", "Override the default LLMQ size for the LLMQ_TEST quorum (default: 3:2, regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-llmqtestplatformparams=<size>:<threshold>", "Override the default LLMQ size for the LLMQ_TEST_PLATFORM quorum (default: 3:2, regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-minimumdifficultyblocks=<n>", "The number of blocks that can be mined with the minimum difficulty at the start of a chain (default: 0, devnet-only)", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-powtargetspacing=<n>", "Override the default PowTargetSpacing value in seconds (default: 120s, devnet-only)", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-testactivationheight=name@height.", "Set the activation height of 'name' (bip147, bip34, dersig, cltv, csv, brr, dip0001, dip0008, dip0024, v19, v20, mn_rr, sapling). (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-vbparams=<deployment>:<start>:<end>(:min_activation_height(:<window>:<threshold/thresholdstart>(:<thresholdmin>:<falloffcoeff>:<mnactivation>)))",
                 "Use given start/end times and min_activation_height for specified version bits deployment (regtest-only). "
                 "Specifying window, threshold/thresholdstart, thresholdmin, falloffcoeff and mnactivation is optional.", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
}
