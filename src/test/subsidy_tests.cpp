// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(subsidy_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(block_subsidy_kerrigan)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    // nPrevBits is unused in Kerrigan but required by the API
    uint32_t nPrevBits = 0x1e0ffff0;
    CAmount nSubsidy;

    // Block 1 (nPrevHeight=0): full 25 COIN
    nSubsidy = GetBlockSubsidyInner(nPrevBits, 0, consensus, false);
    BOOST_CHECK_EQUAL(nSubsidy, 25 * COIN);

    // Block 1000: still 25 COIN (no halving yet)
    nSubsidy = GetBlockSubsidyInner(nPrevBits, 999, consensus, false);
    BOOST_CHECK_EQUAL(nSubsidy, 25 * COIN);

    // Last block before first halving (nPrevHeight = halving_interval - 1)
    nSubsidy = GetBlockSubsidyInner(nPrevBits, consensus.nSubsidyHalvingInterval - 1, consensus, false);
    BOOST_CHECK_EQUAL(nSubsidy, 25 * COIN);

    // First block of second era (nPrevHeight = halving_interval)
    nSubsidy = GetBlockSubsidyInner(nPrevBits, consensus.nSubsidyHalvingInterval, consensus, false);
    BOOST_CHECK_EQUAL(nSubsidy, 1250000000LL); // 12.5 COIN

    // Second halving
    nSubsidy = GetBlockSubsidyInner(nPrevBits, consensus.nSubsidyHalvingInterval * 2, consensus, false);
    BOOST_CHECK_EQUAL(nSubsidy, 625000000LL); // 6.25 COIN

    // Third halving
    nSubsidy = GetBlockSubsidyInner(nPrevBits, consensus.nSubsidyHalvingInterval * 3, consensus, false);
    BOOST_CHECK_EQUAL(nSubsidy, 312500000LL); // 3.125 COIN

    // fV20Active has no effect (API compat only)
    nSubsidy = GetBlockSubsidyInner(nPrevBits, 0, consensus, true);
    BOOST_CHECK_EQUAL(nSubsidy, 25 * COIN);

    // After 64 halvings: subsidy is 0
    nSubsidy = GetBlockSubsidyInner(nPrevBits, consensus.nSubsidyHalvingInterval * 64, consensus, false);
    BOOST_CHECK_EQUAL(nSubsidy, 0);
}

BOOST_AUTO_TEST_CASE(superblock_subsidy_zero)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    // Kerrigan has no superblock subsidy
    BOOST_CHECK_EQUAL(GetSuperblockSubsidyInner(0x1e0ffff0, 0, consensus, false), 0);
    BOOST_CHECK_EQUAL(GetSuperblockSubsidyInner(0x1e0ffff0, 100000, consensus, true), 0);
}

BOOST_AUTO_TEST_CASE(masternode_payment_20pct)
{
    // Masternode payment should be 20% of block value
    CAmount blockValue = 25 * COIN;
    CAmount mnPayment = GetMasternodePayment(100, blockValue, false);
    BOOST_CHECK_EQUAL(mnPayment, 5 * COIN); // 20% of 25 = 5

    // With fees
    blockValue = 25 * COIN + 1000000; // 25 COIN + 0.01 COIN fees
    mnPayment = GetMasternodePayment(100, blockValue, false);
    BOOST_CHECK_EQUAL(mnPayment, blockValue / 5);
}

BOOST_AUTO_TEST_SUITE_END()
