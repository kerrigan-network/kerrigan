// Copyright (c) 2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/llmq_tests.h>
#include <test/util/setup_common.h>

#include <streams.h>
#include <univalue.h>

#include <llmq/params.h>
#include <llmq/snapshot.h>

#include <boost/test/unit_test.hpp>

#include <vector>

using namespace llmq;
using namespace llmq::testutils;

BOOST_FIXTURE_TEST_SUITE(llmq_snapshot_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(quorum_snapshot_construction_test)
{
    CQuorumSnapshot snapshot1;
    BOOST_CHECK(snapshot1.activeQuorumMembers.empty());
    BOOST_CHECK_EQUAL(snapshot1.mnSkipListMode, SnapshotSkipMode::MODE_NO_SKIPPING);
    BOOST_CHECK(snapshot1.mnSkipList.empty());

    std::vector<bool> activeMembers = {true, false, true, true, false};
    auto skipMode = SnapshotSkipMode::MODE_SKIPPING_ENTRIES;
    std::vector<int> skipList = {1, 3, 5, 7};

    CQuorumSnapshot snapshot2(activeMembers, skipMode, skipList);
    BOOST_CHECK(snapshot2.activeQuorumMembers == activeMembers);
    BOOST_CHECK_EQUAL(snapshot2.mnSkipListMode, skipMode);
    BOOST_CHECK(snapshot2.mnSkipList == skipList);

    std::vector<bool> activeMembersCopy = activeMembers;
    std::vector<int> skipListCopy = skipList;
    CQuorumSnapshot snapshot3(std::move(activeMembersCopy), skipMode, std::move(skipListCopy));
    BOOST_CHECK(snapshot3.activeQuorumMembers == activeMembers);
    BOOST_CHECK_EQUAL(snapshot3.mnSkipListMode, skipMode);
    BOOST_CHECK(snapshot3.mnSkipList == skipList);
}

BOOST_AUTO_TEST_CASE(quorum_snapshot_serialization_test)
{
    std::vector<bool> activeMembers = CreateBitVector(10, {0, 2, 4, 6, 8});
    auto skipMode = SnapshotSkipMode::MODE_SKIPPING_ENTRIES;
    std::vector<int> skipList = {10, 20, 30};

    CQuorumSnapshot snapshot(activeMembers, skipMode, skipList);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << snapshot;

    CQuorumSnapshot deserialized;
    ss >> deserialized;

    BOOST_CHECK(deserialized.activeQuorumMembers == snapshot.activeQuorumMembers);
    BOOST_CHECK_EQUAL(deserialized.mnSkipListMode, snapshot.mnSkipListMode);
    BOOST_CHECK(deserialized.mnSkipList == snapshot.mnSkipList);
}

BOOST_AUTO_TEST_CASE(quorum_snapshot_skip_modes_test)
{
    constexpr std::array<SnapshotSkipMode, 4> skipModes{
        SnapshotSkipMode::MODE_NO_SKIPPING,
        SnapshotSkipMode::MODE_SKIPPING_ENTRIES,
        SnapshotSkipMode::MODE_NO_SKIPPING_ENTRIES,
        SnapshotSkipMode::MODE_ALL_SKIPPED
    };

    for (auto mode : skipModes) {
        CQuorumSnapshot snapshot({true, false, true}, mode, {1, 2, 3});

        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << snapshot;

        CQuorumSnapshot deserialized;
        ss >> deserialized;

        BOOST_CHECK_EQUAL(deserialized.mnSkipListMode, mode);
    }
}

BOOST_AUTO_TEST_CASE(quorum_snapshot_large_data_test)
{
    std::vector<bool> largeActiveMembers(400);
    for (size_t i = 0; i < largeActiveMembers.size(); i++) {
        largeActiveMembers[i] = (i % 3 != 0);
    }

    std::vector<int> largeSkipList;
    for (int i = 0; i < 100; i++) {
        largeSkipList.push_back(i * 4);
    }

    CQuorumSnapshot snapshot(largeActiveMembers, SnapshotSkipMode::MODE_SKIPPING_ENTRIES, largeSkipList);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << snapshot;
    CQuorumSnapshot deserialized;
    ss >> deserialized;
    BOOST_CHECK_EQUAL(deserialized.activeQuorumMembers.size(), 400);
    BOOST_CHECK_EQUAL(deserialized.mnSkipList.size(), 100);
}

BOOST_AUTO_TEST_CASE(quorum_snapshot_empty_data_test)
{
    CQuorumSnapshot emptySnapshot({}, SnapshotSkipMode::MODE_NO_SKIPPING, {});
    BOOST_CHECK(TestSerializationRoundtrip(emptySnapshot));

    CQuorumSnapshot snapshot1({}, SnapshotSkipMode::MODE_SKIPPING_ENTRIES, {1, 2, 3});
    BOOST_CHECK(TestSerializationRoundtrip(snapshot1));

    CQuorumSnapshot snapshot2({true, false, true}, SnapshotSkipMode::MODE_NO_SKIPPING, {});
    BOOST_CHECK(TestSerializationRoundtrip(snapshot2));
}

BOOST_AUTO_TEST_CASE(quorum_snapshot_bit_serialization_test)
{
    CQuorumSnapshot snapshot1({true}, SnapshotSkipMode::MODE_NO_SKIPPING, {});
    BOOST_CHECK(TestSerializationRoundtrip(snapshot1));

    CQuorumSnapshot snapshot8(std::vector<bool>(8, true), SnapshotSkipMode::MODE_NO_SKIPPING, {});
    BOOST_CHECK(TestSerializationRoundtrip(snapshot8));

    CQuorumSnapshot snapshot9(std::vector<bool>(9, false), SnapshotSkipMode::MODE_NO_SKIPPING, {});
    snapshot9.activeQuorumMembers[8] = true; // Set last bit
    BOOST_CHECK(TestSerializationRoundtrip(snapshot9));

    std::vector<bool> alternating(16);
    for (size_t i = 0; i < alternating.size(); i++) {
        alternating[i] = (i % 2 == 0);
    }
    CQuorumSnapshot snapshotAlt(alternating, SnapshotSkipMode::MODE_NO_SKIPPING, {});
    BOOST_CHECK(TestSerializationRoundtrip(snapshotAlt));
}

BOOST_AUTO_TEST_CASE(quorum_rotation_info_construction_test)
{
    CQuorumRotationInfo rotInfo;

    BOOST_CHECK(!rotInfo.extraShare);
    BOOST_CHECK(!rotInfo.cycleHMinus4C.has_value());
    BOOST_CHECK(rotInfo.lastCommitmentPerIndex.empty());
    BOOST_CHECK(rotInfo.quorumSnapshotList.empty());
    BOOST_CHECK(rotInfo.mnListDiffList.empty());
}

BOOST_AUTO_TEST_CASE(get_quorum_rotation_info_serialization_test)
{
    CGetQuorumRotationInfo getInfo;

    getInfo.baseBlockHashes = {GetTestBlockHash(1), GetTestBlockHash(2), GetTestBlockHash(3)};
    getInfo.blockRequestHash = GetTestBlockHash(100);
    getInfo.extraShare = true;

    BOOST_CHECK(TestSerializationRoundtrip(getInfo));

    CGetQuorumRotationInfo emptyInfo;
    emptyInfo.blockRequestHash = GetTestBlockHash(200);
    emptyInfo.extraShare = false;

    BOOST_CHECK(TestSerializationRoundtrip(emptyInfo));
}

BOOST_AUTO_TEST_CASE(quorum_rotation_info_serialization_test)
{
    CQuorumRotationInfo rotInfo;

    rotInfo.cycleHMinusC.m_snap = CQuorumSnapshot({true, false, true}, SnapshotSkipMode::MODE_SKIPPING_ENTRIES, {1, 2});
    rotInfo.cycleHMinus2C.m_snap = CQuorumSnapshot({false, true, false}, SnapshotSkipMode::MODE_NO_SKIPPING, {});
    rotInfo.cycleHMinus3C.m_snap = CQuorumSnapshot({true, true, false}, SnapshotSkipMode::MODE_ALL_SKIPPED, {3});

    rotInfo.extraShare = false;
    BOOST_CHECK(TestSerializationRoundtrip(rotInfo));

    rotInfo.extraShare = true;
    BOOST_CHECK(TestSerializationRoundtrip(rotInfo));

    llmq::CycleData extra_cycle;
    extra_cycle.m_snap = CQuorumSnapshot({false, false, true}, SnapshotSkipMode::MODE_SKIPPING_ENTRIES, {4, 5, 6});
    rotInfo.cycleHMinus4C = extra_cycle;
    BOOST_CHECK(TestSerializationRoundtrip(rotInfo));

    CFinalCommitment commitment{GetLLMQParams(Consensus::LLMQType::LLMQ_TEST), uint256::ONE};
    rotInfo.lastCommitmentPerIndex.push_back(commitment);
    rotInfo.quorumSnapshotList.push_back(
        CQuorumSnapshot({false, false, true}, SnapshotSkipMode::MODE_SKIPPING_ENTRIES, {7, 8}));
    BOOST_CHECK(TestSerializationRoundtrip(rotInfo));
}

BOOST_AUTO_TEST_CASE(quorum_snapshot_json_test)
{
    std::vector<bool> activeMembers = {true, false, true, true, false, false, true};
    auto skipMode = SnapshotSkipMode::MODE_SKIPPING_ENTRIES;
    std::vector<int> skipList = {10, 20, 30, 40};

    CQuorumSnapshot snapshot(activeMembers, skipMode, skipList);

    UniValue json = snapshot.ToJson();

    BOOST_CHECK(json.isObject());
    BOOST_CHECK(json.exists("activeQuorumMembers"));
    BOOST_CHECK(json.exists("mnSkipListMode"));
    BOOST_CHECK(json.exists("mnSkipList"));

    BOOST_CHECK(json["mnSkipList"].isArray());
    BOOST_CHECK_EQUAL(json["mnSkipList"].size(), skipList.size());
}

BOOST_AUTO_TEST_CASE(quorum_snapshot_malformed_data_test)
{
    CQuorumSnapshot snapshot({true, false, true}, SnapshotSkipMode::MODE_SKIPPING_ENTRIES, {1, 2, 3});

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << snapshot;

    std::string data = ss.str();
    for (size_t truncateAt = 1; truncateAt < data.size(); truncateAt += 5) {
        CDataStream truncated(std::vector<unsigned char>(data.begin(), data.begin() + truncateAt), SER_NETWORK,
                              PROTOCOL_VERSION);

        CQuorumSnapshot deserialized;
        try {
            truncated >> deserialized;
            // If no exception, it might be a valid partial deserialization
            // (though unlikely for complex structures)
        } catch (const std::exception&) {
            // Expected for most truncation points
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
