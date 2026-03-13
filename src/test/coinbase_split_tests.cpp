// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/amount.h>
#include <evo/chainhelper.h>
#include <masternode/payments.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(coinbase_split_tests, BasicTestingSetup)

/**
 * Kerrigan coinbase split verification:
 *   20% miner, 20% masternode, 5% founders, 15% dev, 40% growth escrow
 */
BOOST_AUTO_TEST_CASE(coinbase_split_percentages)
{
    // Block reward: 25 COIN = 2,500,000,000 satoshis
    CAmount blockReward = 25 * COIN;

    // Masternode: 20%
    CAmount mnPayment = GetMasternodePayment(1, blockReward, false);
    BOOST_CHECK_EQUAL(mnPayment, 500000000LL); // 5 COIN

    // Verify percentages via integer math (matching payments.cpp)
    CAmount escrowReward = blockReward * 40 / 100;
    CAmount devReward = blockReward * 15 / 100;
    CAmount foundersReward = blockReward * 5 / 100;

    BOOST_CHECK_EQUAL(escrowReward, 1000000000LL);      // 10 COIN (40%)
    BOOST_CHECK_EQUAL(devReward, 375000000LL);       // 3.75 COIN (15%)
    BOOST_CHECK_EQUAL(foundersReward, 125000000LL);  // 1.25 COIN (5%)

    // Miner gets remainder: 20%
    CAmount minerReward = blockReward - mnPayment - escrowReward - devReward - foundersReward;
    BOOST_CHECK_EQUAL(minerReward, 500000000LL); // 5 COIN

    // Total must equal block reward
    BOOST_CHECK_EQUAL(mnPayment + escrowReward + devReward + foundersReward + minerReward, blockReward);
}

BOOST_AUTO_TEST_CASE(coinbase_split_with_fees)
{
    // Block reward with transaction fees
    CAmount blockSubsidy = 25 * COIN;
    CAmount fees = 50000000LL; // 0.5 COIN in fees
    CAmount totalReward = blockSubsidy + fees;

    CAmount mnPayment = GetMasternodePayment(1, totalReward, false);
    CAmount escrowReward = totalReward * 40 / 100;
    CAmount devReward = totalReward * 15 / 100;
    CAmount foundersReward = totalReward * 5 / 100;
    CAmount minerReward = totalReward - mnPayment - escrowReward - devReward - foundersReward;

    // All 5 pieces sum to total
    BOOST_CHECK_EQUAL(mnPayment + escrowReward + devReward + foundersReward + minerReward, totalReward);

    // Each piece is proportional
    BOOST_CHECK_EQUAL(mnPayment, totalReward / 5);
    BOOST_CHECK_EQUAL(escrowReward, totalReward * 40 / 100);
}

BOOST_AUTO_TEST_CASE(coinbase_split_after_halving)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    // After first halving: 12.5 COIN
    CAmount blockReward = GetBlockSubsidyInner(0, consensus.nSubsidyHalvingInterval, consensus, false);
    BOOST_CHECK_EQUAL(blockReward, 1250000000LL);

    CAmount mnPayment = GetMasternodePayment(consensus.nSubsidyHalvingInterval + 1, blockReward, false);
    CAmount escrowReward = blockReward * 40 / 100;
    CAmount devReward = blockReward * 15 / 100;
    CAmount foundersReward = blockReward * 5 / 100;
    CAmount minerReward = blockReward - mnPayment - escrowReward - devReward - foundersReward;

    BOOST_CHECK_EQUAL(mnPayment, 250000000LL);      // 2.5 COIN
    BOOST_CHECK_EQUAL(escrowReward, 500000000LL);        // 5.0 COIN
    BOOST_CHECK_EQUAL(devReward, 187500000LL);       // 1.875 COIN
    BOOST_CHECK_EQUAL(foundersReward, 62500000LL);   // 0.625 COIN
    BOOST_CHECK_EQUAL(minerReward, 250000000LL);     // 2.5 COIN

    // Total must equal block reward
    BOOST_CHECK_EQUAL(mnPayment + escrowReward + devReward + foundersReward + minerReward, blockReward);
}

BOOST_AUTO_TEST_SUITE_END()

// ============================================================================
// Integration tests using CMNPaymentsProcessor through the real chain helper.
// RegTestingSetup provides full chain initialization with treasury scripts.
// ============================================================================

BOOST_FIXTURE_TEST_SUITE(coinbase_split_integration_tests, RegTestingSetup)

// Helper: build a coinbase tx with the full block reward in vout[0] (miner)
static CMutableTransaction MakeCoinbaseTx(CAmount totalReward)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vout.resize(1);
    tx.vout[0].nValue = totalReward;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return tx;
}

BOOST_AUTO_TEST_CASE(fill_block_payments_builds_correct_outputs)
{
    // FillBlockPayments should add 3 treasury outputs (AI, dev, founders)
    // and reduce the miner's vout[0] accordingly.
    // With no masternodes registered, MN share stays with miner.
    const CAmount blockSubsidy = 25 * COIN;
    const CAmount feeReward = 0;
    const CAmount totalReward = blockSubsidy + feeReward;

    CMutableTransaction coinbaseTx = MakeCoinbaseTx(totalReward);
    std::vector<CTxOut> voutMN, voutSuperblock;

    CBlockIndex* pindexPrev = m_node.chainman->ActiveTip();
    BOOST_REQUIRE(pindexPrev != nullptr);

    m_node.chain_helper->mn_payments->FillBlockPayments(
        coinbaseTx, pindexPrev, blockSubsidy, feeReward, voutMN, voutSuperblock);

    // 3 treasury outputs: AI (40%), dev (15%), founders (5%)
    // No MN output since none are registered
    BOOST_CHECK_EQUAL(voutMN.size(), 3U);

    // Sum of treasury outputs
    CAmount treasuryTotal = 0;
    for (const auto& out : voutMN) {
        treasuryTotal += out.nValue;
    }
    CAmount expectedTreasury = totalReward * 40 / 100 + totalReward * 15 / 100 + totalReward * 5 / 100;
    BOOST_CHECK_EQUAL(treasuryTotal, expectedTreasury);

    // Miner gets remainder (20% base + 20% MN share since no MNs)
    BOOST_CHECK_EQUAL(coinbaseTx.vout[0].nValue, totalReward - treasuryTotal);

    // Total coinbase value must equal total reward
    CAmount coinbaseTotal = coinbaseTx.vout[0].nValue;
    for (size_t i = 1; i < coinbaseTx.vout.size(); ++i) {
        coinbaseTotal += coinbaseTx.vout[i].nValue;
    }
    BOOST_CHECK_EQUAL(coinbaseTotal, totalReward);
}

BOOST_AUTO_TEST_CASE(is_block_payee_valid_accepts_correct_coinbase)
{
    const CAmount blockSubsidy = 25 * COIN;
    const CAmount feeReward = 0;

    CMutableTransaction coinbaseTx = MakeCoinbaseTx(blockSubsidy + feeReward);
    std::vector<CTxOut> voutMN, voutSuperblock;

    CBlockIndex* pindexPrev = m_node.chainman->ActiveTip();
    m_node.chain_helper->mn_payments->FillBlockPayments(
        coinbaseTx, pindexPrev, blockSubsidy, feeReward, voutMN, voutSuperblock);

    CTransaction tx(coinbaseTx);
    BOOST_CHECK(m_node.chain_helper->mn_payments->IsBlockPayeeValid(
        tx, pindexPrev, blockSubsidy, feeReward, /*check_superblock=*/false));
}

BOOST_AUTO_TEST_CASE(is_block_payee_valid_rejects_missing_treasury)
{
    const CAmount blockSubsidy = 25 * COIN;
    const CAmount feeReward = 0;

    CMutableTransaction coinbaseTx = MakeCoinbaseTx(blockSubsidy + feeReward);
    std::vector<CTxOut> voutMN, voutSuperblock;

    CBlockIndex* pindexPrev = m_node.chainman->ActiveTip();
    m_node.chain_helper->mn_payments->FillBlockPayments(
        coinbaseTx, pindexPrev, blockSubsidy, feeReward, voutMN, voutSuperblock);

    // Remove the last treasury output (founders 5%)
    coinbaseTx.vout.pop_back();

    CTransaction tx(coinbaseTx);
    BOOST_CHECK(!m_node.chain_helper->mn_payments->IsBlockPayeeValid(
        tx, pindexPrev, blockSubsidy, feeReward, /*check_superblock=*/false));
}

BOOST_AUTO_TEST_CASE(is_block_payee_valid_rejects_wrong_amount)
{
    const CAmount blockSubsidy = 25 * COIN;
    const CAmount feeReward = 0;

    CMutableTransaction coinbaseTx = MakeCoinbaseTx(blockSubsidy + feeReward);
    std::vector<CTxOut> voutMN, voutSuperblock;

    CBlockIndex* pindexPrev = m_node.chainman->ActiveTip();
    m_node.chain_helper->mn_payments->FillBlockPayments(
        coinbaseTx, pindexPrev, blockSubsidy, feeReward, voutMN, voutSuperblock);

    // Tamper with growth escrow output (index 1 = first treasury output after miner)
    BOOST_REQUIRE(coinbaseTx.vout.size() >= 2);
    coinbaseTx.vout[1].nValue -= 1; // off by 1 satoshi

    CTransaction tx(coinbaseTx);
    BOOST_CHECK(!m_node.chain_helper->mn_payments->IsBlockPayeeValid(
        tx, pindexPrev, blockSubsidy, feeReward, /*check_superblock=*/false));
}

BOOST_AUTO_TEST_CASE(rounding_odd_fee_amounts)
{
    // Odd fee that doesn't divide evenly by 100, verify no satoshis are lost
    const CAmount blockSubsidy = 25 * COIN;
    const CAmount feeReward = 33333333LL; // intentionally not divisible by 100
    const CAmount totalReward = blockSubsidy + feeReward;

    CMutableTransaction coinbaseTx = MakeCoinbaseTx(totalReward);
    std::vector<CTxOut> voutMN, voutSuperblock;

    CBlockIndex* pindexPrev = m_node.chainman->ActiveTip();
    m_node.chain_helper->mn_payments->FillBlockPayments(
        coinbaseTx, pindexPrev, blockSubsidy, feeReward, voutMN, voutSuperblock);

    // Total coinbase must equal total reward (no satoshis lost or created)
    CAmount coinbaseTotal = 0;
    for (const auto& out : coinbaseTx.vout) {
        coinbaseTotal += out.nValue;
    }
    BOOST_CHECK_EQUAL(coinbaseTotal, totalReward);

    // Each treasury output must be non-negative
    for (const auto& out : voutMN) {
        BOOST_CHECK_GE(out.nValue, 0);
    }

    // Miner must get at least their 20% share (actually gets 40% with no MNs)
    BOOST_CHECK_GT(coinbaseTx.vout[0].nValue, 0);
}

BOOST_AUTO_TEST_CASE(no_masternode_scenario)
{
    // With no masternodes registered, MN 20% share stays with miner.
    // Miner should receive 40% (own 20% + MN 20%) of total reward.
    const CAmount blockSubsidy = 25 * COIN;
    const CAmount feeReward = 0;
    const CAmount totalReward = blockSubsidy + feeReward;

    CMutableTransaction coinbaseTx = MakeCoinbaseTx(totalReward);
    std::vector<CTxOut> voutMN, voutSuperblock;

    CBlockIndex* pindexPrev = m_node.chainman->ActiveTip();
    m_node.chain_helper->mn_payments->FillBlockPayments(
        coinbaseTx, pindexPrev, blockSubsidy, feeReward, voutMN, voutSuperblock);

    // No MN output should be present in treasury outputs
    // Treasury = AI(40%) + dev(15%) + founders(5%) = 60%
    CAmount treasuryTotal = 0;
    for (const auto& out : voutMN) {
        treasuryTotal += out.nValue;
    }
    BOOST_CHECK_EQUAL(treasuryTotal, totalReward * 60 / 100);

    // Miner gets remaining 40% (own 20% + MN 20%)
    BOOST_CHECK_EQUAL(coinbaseTx.vout[0].nValue, totalReward * 40 / 100);
}

BOOST_AUTO_TEST_CASE(fill_then_validate_consistency)
{
    // FillBlockPayments and IsBlockPayeeValid must agree:
    // a coinbase built by Fill must always pass validation.
    const CAmount blockSubsidy = 25 * COIN;

    // Test with several fee levels
    for (CAmount fee : {CAmount{0}, CAmount{1}, CAmount{50000000LL}, CAmount{999999999LL}}) {
        CMutableTransaction coinbaseTx = MakeCoinbaseTx(blockSubsidy + fee);
        std::vector<CTxOut> voutMN, voutSuperblock;

        CBlockIndex* pindexPrev = m_node.chainman->ActiveTip();
        m_node.chain_helper->mn_payments->FillBlockPayments(
            coinbaseTx, pindexPrev, blockSubsidy, fee, voutMN, voutSuperblock);

        CTransaction tx(coinbaseTx);
        BOOST_CHECK_MESSAGE(
            m_node.chain_helper->mn_payments->IsBlockPayeeValid(
                tx, pindexPrev, blockSubsidy, fee, /*check_superblock=*/false),
            strprintf("Fill->Validate failed for fee=%lld", fee));
    }
}

BOOST_AUTO_TEST_CASE(post_halving_integration)
{
    // Verify the full pipeline works with halved subsidy (12.5 COIN)
    const auto& consensus = Params().GetConsensus();
    CAmount halvedSubsidy = GetBlockSubsidyInner(0, consensus.nSubsidyHalvingInterval, consensus, false);
    BOOST_CHECK_EQUAL(halvedSubsidy, 1250000000LL); // 12.5 COIN

    const CAmount feeReward = 10000000LL; // 0.1 COIN
    const CAmount totalReward = halvedSubsidy + feeReward;

    CMutableTransaction coinbaseTx = MakeCoinbaseTx(totalReward);
    std::vector<CTxOut> voutMN, voutSuperblock;

    CBlockIndex* pindexPrev = m_node.chainman->ActiveTip();
    m_node.chain_helper->mn_payments->FillBlockPayments(
        coinbaseTx, pindexPrev, halvedSubsidy, feeReward, voutMN, voutSuperblock);

    // Validate the built coinbase passes
    CTransaction tx(coinbaseTx);
    BOOST_CHECK(m_node.chain_helper->mn_payments->IsBlockPayeeValid(
        tx, pindexPrev, halvedSubsidy, feeReward, /*check_superblock=*/false));

    // Verify total equals reward
    CAmount coinbaseTotal = 0;
    for (const auto& out : coinbaseTx.vout) {
        coinbaseTotal += out.nValue;
    }
    BOOST_CHECK_EQUAL(coinbaseTotal, totalReward);

    // Verify treasury proportions on halved amount
    CAmount expectedAI = totalReward * 40 / 100;
    CAmount expectedDev = totalReward * 15 / 100;
    CAmount expectedFounders = totalReward * 5 / 100;

    // Treasury outputs are indices 1, 2, 3 (AI, dev, founders)
    BOOST_REQUIRE(coinbaseTx.vout.size() >= 4);
    BOOST_CHECK_EQUAL(coinbaseTx.vout[1].nValue, expectedAI);
    BOOST_CHECK_EQUAL(coinbaseTx.vout[2].nValue, expectedDev);
    BOOST_CHECK_EQUAL(coinbaseTx.vout[3].nValue, expectedFounders);
}

BOOST_AUTO_TEST_SUITE_END()
