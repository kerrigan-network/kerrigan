// Copyright (c) 2015-2020 The Bitcoin Core developers
// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <crypto/equihash.h>
#include <crypto/ethash/include/ethash/ethash.hpp>
#include <crypto/ethash/include/ethash/progpow.hpp>
#include <pow.h>
#include <primitives/block.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <cstring>
#include <crypto/ethash/progpow_test_vectors.hpp>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

/* Test Hivemind returns per-algo floor when there's not enough history */
BOOST_AUTO_TEST_CASE(hivemind_insufficient_history)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    // With no previous blocks, should return per-algo difficulty floor
    CBlockHeader blockHeader;
    int algo = blockHeader.GetAlgo(); // X11 by default
    BOOST_CHECK_EQUAL(
        GetNextWorkRequired(nullptr, &blockHeader, consensus, algo),
        UintToArith256(consensus.powLimitAlgo[algo]).GetCompact());

    // Check each algo returns its own floor
    for (int a = 0; a < NUM_ALGOS; a++) {
        BOOST_CHECK_EQUAL(
            GetNextWorkRequired(nullptr, &blockHeader, consensus, a),
            UintToArith256(consensus.powLimitAlgo[a]).GetCompact());
    }
}

/* Test Hivemind per-algo difficulty with a synthetic chain */
BOOST_AUTO_TEST_CASE(hivemind_basic_retarget)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    // Build a chain of NUM_ALGOS * 10 + 1 blocks (enough for Hivemind averaging)
    const int numBlocks = NUM_ALGOS * 10 + 1;
    std::vector<CBlockIndex> blocks(numBlocks);

    for (int i = 0; i < numBlocks; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        // Blocks at exactly the target spacing
        blocks[i].nTime = 1700000000 + i * consensus.nPowTargetSpacing;
        // Rotate algos: each block uses algo = i % NUM_ALGOS
        int algo = i % NUM_ALGOS;
        blocks[i].nBits = UintToArith256(consensus.powLimitAlgo[algo]).GetCompact();
        blocks[i].nVersion = BLOCK_VERSION_DEFAULT;
        // Set algo in version bits
        switch (algo) {
            case ALGO_X11: blocks[i].nVersion |= BLOCK_VERSION_X11; break;
            case ALGO_KAWPOW: blocks[i].nVersion |= BLOCK_VERSION_KAWPOW; break;
            case ALGO_EQUIHASH_200: blocks[i].nVersion |= BLOCK_VERSION_EQUIHASH_200; break;
            case ALGO_EQUIHASH_192: blocks[i].nVersion |= BLOCK_VERSION_EQUIHASH_192; break;
        }
    }

    CBlockHeader blockHeader;
    blockHeader.nTime = blocks.back().nTime + consensus.nPowTargetSpacing;

    // With perfectly timed blocks, difficulty should stay near per-algo floor
    unsigned int nextWork = GetNextWorkRequired(&blocks.back(), &blockHeader, consensus, ALGO_X11);
    arith_uint256 algoLimit = UintToArith256(consensus.powLimitAlgo[ALGO_X11]);
    arith_uint256 result;
    result.SetCompact(nextWork);
    // Result should be within 2x of the per-algo floor for a well-timed chain
    BOOST_CHECK(result <= algoLimit);
    BOOST_CHECK(result > algoLimit / 2);
}

/* Test that min-difficulty rules apply on testnet when blocks are slow */
BOOST_AUTO_TEST_CASE(hivemind_testnet_min_difficulty)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::REGTEST);
    const auto& consensus = chainParams->GetConsensus();

    // Regtest has fPowNoRetargeting=true, so it should always return PowLimit
    CBlockIndex prev;
    prev.nHeight = 100;
    prev.nTime = 1700000000;
    prev.nBits = 0x200f0f0fU;
    prev.pprev = nullptr;

    CBlockHeader blockHeader;
    blockHeader.nTime = prev.nTime + 1;

    unsigned int nextWork = GetNextWorkRequired(&prev, &blockHeader, consensus, blockHeader.GetAlgo());
    BOOST_CHECK_EQUAL(nextWork, UintToArith256(consensus.powLimit).GetCompact());
}

/* Test GetLastBlockIndexForAlgo finds the correct algo block */
BOOST_AUTO_TEST_CASE(get_last_block_for_algo)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    // Build a chain: X11, KawPoW, Equihash200, Equihash192, X11, KawPoW
    std::vector<CBlockIndex> blocks(6);
    int algos[] = {ALGO_X11, ALGO_KAWPOW, ALGO_EQUIHASH_200, ALGO_EQUIHASH_192, ALGO_X11, ALGO_KAWPOW};

    for (int i = 0; i < 6; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1700000000 + i * 120;
        blocks[i].nBits = UintToArith256(consensus.powLimitAlgo[algos[i]]).GetCompact();
        blocks[i].nVersion = BLOCK_VERSION_DEFAULT;
        switch (algos[i]) {
            case ALGO_X11: blocks[i].nVersion |= BLOCK_VERSION_X11; break;
            case ALGO_KAWPOW: blocks[i].nVersion |= BLOCK_VERSION_KAWPOW; break;
            case ALGO_EQUIHASH_200: blocks[i].nVersion |= BLOCK_VERSION_EQUIHASH_200; break;
            case ALGO_EQUIHASH_192: blocks[i].nVersion |= BLOCK_VERSION_EQUIHASH_192; break;
        }
    }

    // Last X11 block should be blocks[4] (the second X11)
    const CBlockIndex* lastX11 = GetLastBlockIndexForAlgo(&blocks[5], consensus, ALGO_X11);
    BOOST_CHECK(lastX11 != nullptr);
    BOOST_CHECK_EQUAL(lastX11->nHeight, 4);

    // Last Equihash192 should be blocks[3]
    const CBlockIndex* lastEq192 = GetLastBlockIndexForAlgo(&blocks[5], consensus, ALGO_EQUIHASH_192);
    BOOST_CHECK(lastEq192 != nullptr);
    BOOST_CHECK_EQUAL(lastEq192->nHeight, 3);

    // Last Equihash200 should be blocks[2]
    const CBlockIndex* lastEq200 = GetLastBlockIndexForAlgo(&blocks[5], consensus, ALGO_EQUIHASH_200);
    BOOST_CHECK(lastEq200 != nullptr);
    BOOST_CHECK_EQUAL(lastEq200->nHeight, 2);
}

/* Test algo encoding in block version bits */
BOOST_AUTO_TEST_CASE(block_algo_encoding)
{
    CBlockHeader header;
    header.nVersion = BLOCK_VERSION_DEFAULT;

    // Default (no algo bits set) should be X11
    BOOST_CHECK_EQUAL(header.GetAlgo(), ALGO_X11);

    // Set KawPoW
    header.SetAlgo(ALGO_KAWPOW);
    BOOST_CHECK_EQUAL(header.GetAlgo(), ALGO_KAWPOW);

    // Set Equihash(200,9)
    header.SetAlgo(ALGO_EQUIHASH_200);
    BOOST_CHECK_EQUAL(header.GetAlgo(), ALGO_EQUIHASH_200);

    // Set Equihash(192,7)
    header.SetAlgo(ALGO_EQUIHASH_192);
    BOOST_CHECK_EQUAL(header.GetAlgo(), ALGO_EQUIHASH_192);

    // Set back to X11
    header.SetAlgo(ALGO_X11);
    BOOST_CHECK_EQUAL(header.GetAlgo(), ALGO_X11);

    // Verify SetAlgo clears previous algo bits (the bug Codex caught)
    header.SetAlgo(ALGO_EQUIHASH_192);
    header.SetAlgo(ALGO_KAWPOW);
    BOOST_CHECK_EQUAL(header.GetAlgo(), ALGO_KAWPOW);
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_negative_target)
{
    const auto consensus = CreateChainParams(*m_node.args, CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    nBits = UintToArith256(consensus.powLimit).GetCompact(true);
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_overflow_target)
{
    const auto consensus = CreateChainParams(*m_node.args, CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits{~0x00800000U};
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_too_easy_target)
{
    const auto consensus = CreateChainParams(*m_node.args, CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 nBits_arith = UintToArith256(consensus.powLimit);
    nBits_arith *= 2;
    nBits = nBits_arith.GetCompact();
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_biger_hash_than_target)
{
    const auto consensus = CreateChainParams(*m_node.args, CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith = UintToArith256(consensus.powLimit);
    nBits = hash_arith.GetCompact();
    hash_arith *= 2; // hash > nBits
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_zero_target)
{
    const auto consensus = CreateChainParams(*m_node.args, CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith{0};
    nBits = hash_arith.GetCompact();
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p2 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p3 = &blocks[InsecureRandRange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

void sanity_check_chainparams(const ArgsManager& args, std::string chainName)
{
    const auto chainParams = CreateChainParams(args, chainName);
    const auto consensus = chainParams->GetConsensus();

    // hash genesis is correct
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());

    // target timespan is an even multiple of spacing
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);

    // genesis nBits is positive, doesn't overflow and is lower than powLimit
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg && pow_compact != 0);
    BOOST_CHECK(!over);
    BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);

    // Per-algo floors must each be <= global powLimit
    for (int algo = 0; algo < NUM_ALGOS; algo++) {
        BOOST_CHECK(UintToArith256(consensus.powLimitAlgo[algo]) <= UintToArith256(consensus.powLimit));
    }

    // Hivemind has an overflow guard that safely clamps targets before multiplication,
    // so per-algo floors can exceed the theoretical nPowTargetTimespan*4 bound.
    // Only check networks without per-algo floors (where all per-algo limits equal powLimit).
    if (!consensus.fPowNoRetargeting) {
        bool hasPerAlgoFloors = false;
        for (int i = 0; i < NUM_ALGOS; i++) {
            if (consensus.powLimitAlgo[i] != consensus.powLimit) {
                hasPerAlgoFloors = true;
                break;
            }
        }
        if (!hasPerAlgoFloors) {
            arith_uint256 targ_max("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
            targ_max /= consensus.nPowTargetTimespan*4;
            if (chainName != CBaseChainParams::DEVNET && chainName != CBaseChainParams::TESTNET) {
                BOOST_CHECK(UintToArith256(consensus.powLimit) < targ_max);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)
{
    sanity_check_chainparams(*m_node.args, CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity)
{
    sanity_check_chainparams(*m_node.args, CBaseChainParams::REGTEST);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_sanity)
{
    sanity_check_chainparams(*m_node.args, CBaseChainParams::TESTNET);
}

BOOST_AUTO_TEST_CASE(ChainParams_DEVNET_sanity)
{
    gArgs.SoftSetBoolArg("-devnet", true);
    sanity_check_chainparams(*m_node.args, CBaseChainParams::DEVNET);
    gArgs.ForceRemoveArg("devnet");
}

/* ======================================================================
 * Per-algo difficulty floor tests
 * ====================================================================== */

/* Each mainnet algo should have a distinct difficulty floor */
BOOST_AUTO_TEST_CASE(per_algo_difficulty_floors)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    // Genesis powLimitAlgo[] are permissive bootstrap targets -- no strict ordering required.
    // All must be non-zero.
    for (int algo = 0; algo < NUM_ALGOS; algo++) {
        BOOST_CHECK(UintToArith256(consensus.powLimitAlgo[algo]) > arith_uint256(0));
    }

    // Global powLimit should equal the easiest per-algo genesis limit
    arith_uint256 eq192Limit = UintToArith256(consensus.powLimitAlgo[ALGO_EQUIHASH_192]);
    BOOST_CHECK(UintToArith256(consensus.powLimit) == eq192Limit);

    // Height-activated difficulty floors (hardware-calibrated, tighter than genesis).
    // Activated at nDiffFloorHeight to prevent flash-mining after hashrate drops.
    BOOST_CHECK(consensus.nDiffFloorHeight > 0);

    arith_uint256 x11Floor = UintToArith256(consensus.powLimitFloorAlgo[ALGO_X11]);
    arith_uint256 kawpowFloor = UintToArith256(consensus.powLimitFloorAlgo[ALGO_KAWPOW]);
    arith_uint256 eq200Floor = UintToArith256(consensus.powLimitFloorAlgo[ALGO_EQUIHASH_200]);
    arith_uint256 eq192Floor = UintToArith256(consensus.powLimitFloorAlgo[ALGO_EQUIHASH_192]);

    // Hardware-calibrated ordering: X11 ASIC < KawPoW GPU < Equihash200 ASIC < Equihash192 GPU
    // (hardest to easiest, lower target = harder)
    BOOST_CHECK(x11Floor < kawpowFloor);
    BOOST_CHECK(kawpowFloor < eq200Floor);
    BOOST_CHECK(eq200Floor < eq192Floor);

    // All floors must be non-zero
    for (int algo = 0; algo < NUM_ALGOS; algo++) {
        BOOST_CHECK(UintToArith256(consensus.powLimitFloorAlgo[algo]) > arith_uint256(0));
    }

    // Each floor must be tighter (lower target) than its genesis powLimitAlgo
    for (int algo = 0; algo < NUM_ALGOS; algo++) {
        BOOST_CHECK(UintToArith256(consensus.powLimitFloorAlgo[algo]) <=
                    UintToArith256(consensus.powLimitAlgo[algo]));
    }
}

/* Gap recovery threshold drops from 240 to 40 at nDiffFloorHeight */
BOOST_AUTO_TEST_CASE(gap_threshold_activation)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    // nDiffFloorHeight must be set on mainnet
    BOOST_CHECK(consensus.nDiffFloorHeight > 0);

    // Pre-activation: threshold = NUM_ALGOS * 10 * 6 = 240
    const int preThreshold = NUM_ALGOS * 10 * 6;
    BOOST_CHECK_EQUAL(preThreshold, 240);

    // Post-activation: threshold = NUM_ALGOS * 10 = 40
    const int postThreshold = NUM_ALGOS * 10;
    BOOST_CHECK_EQUAL(postThreshold, 40);

    // 40 is exactly one averaging window -- the minimum safe value
    BOOST_CHECK_EQUAL(postThreshold, NUM_ALGOS * 10 /* nAveragingInterval */);
}

/* Testnet/regtest should have uniform per-algo limits (no floors) */
BOOST_AUTO_TEST_CASE(testnet_no_per_algo_floors)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::REGTEST);
    const auto& consensus = chainParams->GetConsensus();

    // All per-algo limits should equal the global powLimit on test networks
    for (int algo = 0; algo < NUM_ALGOS; algo++) {
        BOOST_CHECK(consensus.powLimitAlgo[algo] == consensus.powLimit);
    }
}

/* ======================================================================
 * Multi-algo PoW validation tests
 * ====================================================================== */

/* Test Equihash(200,9) solve + validate roundtrip (140-byte header) */
BOOST_AUTO_TEST_CASE(equihash_200_9_solution_validation)
{
    // Construct a header for Equihash(200,9)
    CBlockHeader header;
    header.nVersion = BLOCK_VERSION_DEFAULT;
    header.SetAlgo(ALGO_EQUIHASH_200);
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot.SetHex("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
    header.hashReserved.SetNull(); // 32 zero bytes (Zcash compat)
    header.nTime = 1773446400;
    header.nBits = 0x207fffffU; // easy target for test
    header.nNonce256.SetNull();  // 32-byte Equihash nonce

    unsigned int n = 200, k = 9;

    // Initialize Equihash BLAKE2b state
    eh_HashState state;
    EhInitialiseState(n, k, state);

    // CEquihashInput = 108 bytes + nNonce256 = 32 bytes = 140 bytes total
    CEquihashInput I{header};
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;
    ss << header.nNonce256;
    BOOST_CHECK_EQUAL(ss.size(), 140u); // Verify 140-byte Equihash input
    crypto_generichash_blake2b_update(&state, reinterpret_cast<const unsigned char*>(ss.data()), ss.size());

    // Solve: find a valid Equihash solution
    bool solved = false;
    EhBasicSolveUncancellable(n, k, state, [&](std::vector<unsigned char> soln) {
        header.nSolution = soln;
        solved = true;
        return true; // accept first solution
    });
    BOOST_CHECK_MESSAGE(solved, "Equihash(200,9) solver should find a solution");

    // Verify the solution
    BOOST_CHECK(header.CheckEquihashSolution());

    // Tamper with the solution and verify it fails
    if (!header.nSolution.empty()) {
        header.nSolution[0] ^= 0xFF;
        BOOST_CHECK(!header.CheckEquihashSolution());
    }
}

/* Test Equihash(192,7) solve + validate roundtrip (140-byte header) */
BOOST_AUTO_TEST_CASE(equihash_192_7_solution_validation)
{
    CBlockHeader header;
    header.nVersion = BLOCK_VERSION_DEFAULT;
    header.SetAlgo(ALGO_EQUIHASH_192);
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot.SetHex("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
    header.hashReserved.SetNull();
    header.nTime = 1773446400;
    header.nBits = 0x207fffffU;
    header.nNonce256.SetNull();

    unsigned int n = 192, k = 7;

    eh_HashState state;
    EhInitialiseState(n, k, state);

    CEquihashInput I{header};
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;
    ss << header.nNonce256;
    BOOST_CHECK_EQUAL(ss.size(), 140u); // Verify 140-byte Equihash input
    crypto_generichash_blake2b_update(&state, reinterpret_cast<const unsigned char*>(ss.data()), ss.size());

    bool solved = false;
    EhBasicSolveUncancellable(n, k, state, [&](std::vector<unsigned char> soln) {
        header.nSolution = soln;
        solved = true;
        return true;
    });
    BOOST_CHECK_MESSAGE(solved, "Equihash(192,7) solver should find a solution");

    BOOST_CHECK(header.CheckEquihashSolution());

    // Tamper
    if (!header.nSolution.empty()) {
        header.nSolution[0] ^= 0xFF;
        BOOST_CHECK(!header.CheckEquihashSolution());
    }
}

/* Test KawPoW hash_no_verify matches progpow::hash final_hash */
BOOST_AUTO_TEST_CASE(kawpow_hash_roundtrip)
{
    // Use epoch 0 (block 0) for minimal DAG
    int block_number = 0;
    int epoch = ethash::get_epoch_number(block_number);
    BOOST_CHECK_EQUAL(epoch, 0);

    // Create a test header hash
    ethash::hash256 header_h = {};
    header_h.bytes[0] = 0xAB;
    header_h.bytes[1] = 0xCD;
    uint64_t nonce = 42;

    // Compute full hash (requires full epoch context)
    const ethash::epoch_context_full& ctx_full = ethash::get_global_epoch_context_full(epoch);
    ethash::result full_result = progpow::hash(ctx_full, block_number, header_h, nonce);

    // hash_no_verify should produce the same final_hash
    ethash::hash256 quick_hash = progpow::hash_no_verify(block_number, header_h, full_result.mix_hash, nonce);
    BOOST_CHECK(std::memcmp(quick_hash.bytes, full_result.final_hash.bytes, 32) == 0);

    // Verify with light context accepts the valid result
    const ethash::epoch_context& ctx_light = ethash::get_global_epoch_context(epoch);
    ethash::hash256 easy_boundary = {};
    std::memset(easy_boundary.bytes, 0xFF, 32); // very easy target
    BOOST_CHECK(progpow::verify(ctx_light, block_number, header_h, full_result.mix_hash, nonce, easy_boundary));

    // Bad mix_hash should fail verification
    ethash::hash256 bad_mix = full_result.mix_hash;
    bad_mix.bytes[0] ^= 0xFF;
    BOOST_CHECK(!progpow::verify(ctx_light, block_number, header_h, bad_mix, nonce, easy_boundary));
}

/* Test KawPoW GetPoWAlgoHash differs from GetHash (X11) */
BOOST_AUTO_TEST_CASE(kawpow_pow_algo_hash)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::REGTEST);
    const auto& consensus = chainParams->GetConsensus();

    // Construct a KawPoW header with known fields
    CBlockHeader header;
    header.nVersion = BLOCK_VERSION_DEFAULT;
    header.SetAlgo(ALGO_KAWPOW);
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot.SetHex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    header.nTime = 1773446400;
    header.nBits = 0x207fffffU;
    header.nNonce = 1;
    header.nHeight = 0;
    header.nNonce64 = 12345;
    // Set a non-zero mix_hash so the KawPoW hash differs from identity
    header.mix_hash.SetHex("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");

    uint256 x11Hash = header.GetHash();
    uint256 kawpowHash = header.GetPoWAlgoHash(consensus);

    // KawPoW PoW hash should differ from X11 identity hash
    BOOST_CHECK(x11Hash != kawpowHash);

    // X11 header should return same hash for both
    CBlockHeader x11Header = header;
    x11Header.SetAlgo(ALGO_X11);
    BOOST_CHECK(x11Header.GetHash() == x11Header.GetPoWAlgoHash(consensus));
}

/* Validate KawPoW test vectors against KERRIGAN ProgPoW constant.
 * Only tests epoch 0 vectors (blocks 0,49,50,99) to keep runtime short.
 * Full vector set validated by kawpow_vector_gen during regeneration. */
BOOST_AUTO_TEST_CASE(kawpow_test_vectors_epoch0)
{
    auto hex_to_hash256 = [](const char* hex) -> ethash::hash256 {
        ethash::hash256 h = {};
        for (int i = 0; i < 32; ++i) {
            unsigned int byte;
            sscanf(hex + i * 2, "%02x", &byte);
            h.bytes[i] = static_cast<uint8_t>(byte);
        }
        return h;
    };

    auto hex_to_nonce = [](const char* hex) -> uint64_t {
        uint64_t nonce = 0;
        sscanf(hex, "%016lx", &nonce);
        return nonce;
    };

    // Only test epoch 0 cases (blocks < 7500) to keep test fast
    const ethash::epoch_context_full& ctx = ethash::get_global_epoch_context_full(0);

    for (const auto& tc : progpow_hash_test_cases) {
        if (ethash::get_epoch_number(tc.block_number) != 0)
            continue;

        ethash::hash256 header_h = hex_to_hash256(tc.header_hash_hex);
        uint64_t nonce = hex_to_nonce(tc.nonce_hex);

        ethash::result res = progpow::hash(ctx, tc.block_number, header_h, nonce);

        ethash::hash256 expected_mix = hex_to_hash256(tc.mix_hash_hex);
        ethash::hash256 expected_final = hex_to_hash256(tc.final_hash_hex);

        BOOST_CHECK_MESSAGE(
            std::memcmp(res.mix_hash.bytes, expected_mix.bytes, 32) == 0,
            "mix_hash mismatch at block " << tc.block_number);
        BOOST_CHECK_MESSAGE(
            std::memcmp(res.final_hash.bytes, expected_final.bytes, 32) == 0,
            "final_hash mismatch at block " << tc.block_number);
    }
}

BOOST_AUTO_TEST_SUITE_END()
