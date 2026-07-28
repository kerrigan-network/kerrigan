// Copyright (c) 2022-2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>

#include <chainparams.h>
#include <llmq/options.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

using node::NodeContext;

/* TODO: rename this file and test to llmq_options_test */
BOOST_AUTO_TEST_SUITE(evo_utils_tests)

void Test(NodeContext& node)
{
    using namespace llmq;
    auto tip = node.chainman->ActiveTip();
    const auto& consensus_params = Params().GetConsensus();
    // Kerrigan mainnet assigns the ChainLocks/InstantSend/EHF roles to the
    // height-gated LLMQ_60_60 small-network quorum; below nLLMQ6060Height that
    // type is disabled regardless of the DIP0024 flags (at the test tip the
    // gate has not been reached, so the expectation is false on mainnet).
    const bool fLLMQ6060Enabled{consensus_params.nLLMQ6060Height > 0 &&
                                tip->nHeight + 1 >= consensus_params.nLLMQ6060Height};
    auto expected = [&](Consensus::LLMQType llmqType, bool legacy_expected) {
        return llmqType == Consensus::LLMQType::LLMQ_60_60 ? fLLMQ6060Enabled : legacy_expected;
    };
    BOOST_CHECK_EQUAL(node.chainman->IsQuorumTypeEnabled(consensus_params.llmqTypeDIP0024InstantSend, tip,
                                                         /*optDIP0024IsActive=*/false, /*optHaveDIP0024Quorums=*/false),
                      expected(consensus_params.llmqTypeDIP0024InstantSend, false));
    BOOST_CHECK_EQUAL(node.chainman->IsQuorumTypeEnabled(consensus_params.llmqTypeDIP0024InstantSend, tip,
                                                         /*optDIP0024IsActive=*/true, /*optHaveDIP0024Quorums=*/false),
                      expected(consensus_params.llmqTypeDIP0024InstantSend, true));
    BOOST_CHECK_EQUAL(node.chainman->IsQuorumTypeEnabled(consensus_params.llmqTypeDIP0024InstantSend, tip,
                                                         /*optDIP0024IsActive=*/true, /*optHaveDIP0024Quorums=*/true),
                      expected(consensus_params.llmqTypeDIP0024InstantSend, true));
    BOOST_CHECK_EQUAL(node.chainman->IsQuorumTypeEnabled(consensus_params.llmqTypeChainLocks, tip,
                                                         /*optDIP0024IsActive=*/false, /*optHaveDIP0024Quorums=*/false),
                      expected(consensus_params.llmqTypeChainLocks, true));
    BOOST_CHECK_EQUAL(node.chainman->IsQuorumTypeEnabled(consensus_params.llmqTypeChainLocks, tip,
                                                         /*optDIP0024IsActive=*/true, /*optHaveDIP0024Quorums=*/false),
                      expected(consensus_params.llmqTypeChainLocks, true));
    BOOST_CHECK_EQUAL(node.chainman->IsQuorumTypeEnabled(consensus_params.llmqTypeChainLocks, tip,
                                                         /*optDIP0024IsActive=*/true, /*optHaveDIP0024Quorums=*/true),
                      expected(consensus_params.llmqTypeChainLocks, true));
    BOOST_CHECK_EQUAL(node.chainman->IsQuorumTypeEnabled(consensus_params.llmqTypePlatform, tip,
                                                         /*optDIP0024IsActive=*/false, /*optHaveDIP0024Quorums=*/false),
                      Params().IsTestChain());
    BOOST_CHECK_EQUAL(node.chainman->IsQuorumTypeEnabled(consensus_params.llmqTypePlatform, tip,
                                                         /*optDIP0024IsActive=*/true, /*optHaveDIP0024Quorums=*/false),
                      Params().IsTestChain());
    BOOST_CHECK_EQUAL(node.chainman->IsQuorumTypeEnabled(consensus_params.llmqTypePlatform, tip,
                                                         /*optDIP0024IsActive=*/true, /*optHaveDIP0024Quorums=*/true),
                      Params().IsTestChain());
    BOOST_CHECK_EQUAL(node.chainman->IsQuorumTypeEnabled(consensus_params.llmqTypeMnhf, tip,
                                                         /*optDIP0024IsActive=*/false, /*optHaveDIP0024Quorums=*/false),
                      expected(consensus_params.llmqTypeMnhf, true));
    BOOST_CHECK_EQUAL(node.chainman->IsQuorumTypeEnabled(consensus_params.llmqTypeMnhf, tip,
                                                         /*optDIP0024IsActive=*/true, /*optHaveDIP0024Quorums=*/false),
                      expected(consensus_params.llmqTypeMnhf, true));
    BOOST_CHECK_EQUAL(node.chainman->IsQuorumTypeEnabled(consensus_params.llmqTypeMnhf, tip,
                                                         /*optDIP0024IsActive=*/true, /*optHaveDIP0024Quorums=*/true),
                      expected(consensus_params.llmqTypeMnhf, true));
}

BOOST_FIXTURE_TEST_CASE(utils_IsQuorumTypeEnabled_tests_regtest, RegTestingSetup)
{
    Test(m_node);
}

BOOST_FIXTURE_TEST_CASE(utils_IsQuorumTypeEnabled_tests_mainnet, TestingSetup)
{
    Test(m_node);
}

BOOST_AUTO_TEST_SUITE_END()
