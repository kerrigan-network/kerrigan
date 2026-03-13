// Copyright (c) 2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/llmq_tests.h>
#include <test/util/setup_common.h>

#include <consensus/params.h>
#include <llmq/params.h>
#include <llmq/utils.h>
#include <netaddress.h>
#include <random.h>

#include <boost/test/unit_test.hpp>

#include <map>
#include <set>

using namespace llmq;
using namespace llmq::testutils;

BOOST_FIXTURE_TEST_SUITE(llmq_utils_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(trivially_passes) { BOOST_CHECK(true); }

BOOST_AUTO_TEST_CASE(deterministic_outbound_connection_test)
{
    uint256 proTxHash1 = GetTestQuorumHash(1);
    uint256 proTxHash2 = GetTestQuorumHash(2);

    uint256 conn1a = llmq::utils::DeterministicOutboundConnection(proTxHash1, proTxHash2);
    uint256 conn1b = llmq::utils::DeterministicOutboundConnection(proTxHash1, proTxHash2);
    BOOST_CHECK(conn1a == conn1b);
    BOOST_CHECK(conn1a == proTxHash1 || conn1a == proTxHash2);

    // Commutative: the function deterministically selects which node initiates
    uint256 conn2 = llmq::utils::DeterministicOutboundConnection(proTxHash2, proTxHash1);
    BOOST_CHECK(conn1a == conn2);

    BOOST_CHECK(llmq::utils::DeterministicOutboundConnection(proTxHash1, proTxHash2) ==
                llmq::utils::DeterministicOutboundConnection(proTxHash2, proTxHash1));
}

BOOST_AUTO_TEST_CASE(deterministic_outbound_connection_edge_cases_test)
{
    uint256 nullHash;
    uint256 validHash = GetTestQuorumHash(1);

    uint256 conn1 = llmq::utils::DeterministicOutboundConnection(nullHash, validHash);
    uint256 conn2 = llmq::utils::DeterministicOutboundConnection(validHash, nullHash);
    uint256 conn3 = llmq::utils::DeterministicOutboundConnection(nullHash, nullHash);

    BOOST_CHECK(conn1 == nullHash || conn1 == validHash);
    BOOST_CHECK(conn2 == nullHash || conn2 == validHash);
    BOOST_CHECK(conn1 == conn2);
    BOOST_CHECK(conn3 == nullHash);

    uint256 sameHash = GetTestQuorumHash(42);
    uint256 connSame = llmq::utils::DeterministicOutboundConnection(sameHash, sameHash);
    BOOST_CHECK(connSame == sameHash);
    BOOST_CHECK(!connSame.IsNull());
}

BOOST_AUTO_TEST_CASE(deterministic_connection_symmetry_test)
{
    uint256 proTxHash1 = GetTestQuorumHash(1);
    uint256 proTxHash2 = GetTestQuorumHash(2);
    uint256 proTxHash3 = GetTestQuorumHash(3);

    uint256 conn12 = llmq::utils::DeterministicOutboundConnection(proTxHash1, proTxHash2);
    uint256 conn21 = llmq::utils::DeterministicOutboundConnection(proTxHash2, proTxHash1);
    uint256 conn13 = llmq::utils::DeterministicOutboundConnection(proTxHash1, proTxHash3);
    uint256 conn31 = llmq::utils::DeterministicOutboundConnection(proTxHash3, proTxHash1);
    uint256 conn23 = llmq::utils::DeterministicOutboundConnection(proTxHash2, proTxHash3);
    uint256 conn32 = llmq::utils::DeterministicOutboundConnection(proTxHash3, proTxHash2);

    BOOST_CHECK(conn12 == conn21);
    BOOST_CHECK(conn13 == conn31);
    BOOST_CHECK(conn23 == conn32);

    BOOST_CHECK(conn12 == proTxHash1 || conn12 == proTxHash2);
    BOOST_CHECK(conn13 == proTxHash1 || conn13 == proTxHash3);
    BOOST_CHECK(conn23 == proTxHash2 || conn23 == proTxHash3);

    std::set<uint256> uniqueResults;
    uniqueResults.insert(conn12);
    uniqueResults.insert(conn13);
    uniqueResults.insert(conn23);
    BOOST_CHECK(uniqueResults.size() >= 2 && uniqueResults.size() <= 3);
}

BOOST_AUTO_TEST_SUITE_END()
