// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Unit tests for the deterministic taint-root freeze (incident 2026-05).
//
// These exercise the PURE propagation + membership logic (TaintSet::ApplyTxRule
// and TaintSet::Contains) using synthetic transactions, mirroring what the
// production chain walk (CChainState::EnsureTaintSetComputed) does block by
// block. This is the consensus-critical core: if the rule and membership are
// correct and deterministic here, the chain walk (which only adds canonical
// block iteration around this exact rule) is correct by construction.
//
// What is proven:
//   1. Propagation by descent: seed -> A -> B (fan-out B1,B2) all tainted.
//   2. A spend of a tainted outpoint is detected/rejected (membership test).
//   3. A clean, unrelated coin is NOT tainted (no false positive) and spends fine.
//   4. Determinism: building the set twice from the same inputs is bit-identical.
//
// Verification gap (documented): these tests do not stand up a live regtest
// chain through ProcessNewBlock; they test the rule + membership directly. The
// chain walk is a thin canonical-iteration wrapper around ApplyTxRule, verified
// separately by syntax/compile. See F-taint-freeze-impl.md.

#include <policy/outpoint_blacklist.h>

#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <set>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

//! The real incident drain script, built from the deployed constant.
CScript DrainScript()
{
    const auto b = ParseHex(freeze_seed::DRAIN_SCRIPT_HEX);
    return CScript(b.begin(), b.end());
}

//! A distinct, unrelated P2PKH script (NOT the drain script).
CScript CleanScript()
{
    // OP_DUP OP_HASH160 <20 bytes of 0xAB> OP_EQUALVERIFY OP_CHECKSIG
    std::vector<unsigned char> h160(20, 0xAB);
    return CScript() << OP_DUP << OP_HASH160 << h160 << OP_EQUALVERIFY << OP_CHECKSIG;
}

//! Deterministic synthetic txid from a small integer (distinct per id).
uint256 TxId(unsigned id)
{
    // Encode id into the low bytes of an otherwise-zero 32-byte value. Distinct
    // ids yield distinct, totally-ordered txids -- enough for the rule's needs.
    std::vector<unsigned char> raw(32, 0x00);
    raw[0] = static_cast<unsigned char>(id & 0xFF);
    raw[1] = static_cast<unsigned char>((id >> 8) & 0xFF);
    uint256 out;
    std::copy(raw.begin(), raw.end(), out.begin());
    return out;
}

//! Convenience: run ApplyTxRule for a tx with the given inputs/output-scripts.
bool Apply(const uint256& txid,
           const std::vector<COutPoint>& vin,
           const std::vector<CScript>& vout,
           std::set<COutPoint>& working)
{
    static const CScript seed_script = DrainScript();
    static const std::set<uint256> seed_txids = [] {
        std::set<uint256> s;
        for (const char* h : freeze_seed::SEED_TXIDS) s.insert(uint256S(h));
        return s;
    }();
    return TaintSet::ApplyTxRule(txid, vin, vout, seed_script, seed_txids, working);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(freeze_tests, BasicTestingSetup)

// 1. Propagation: a coin paying the drain script seeds the taint; spending it to
//    A taints all of A's outputs; A spending to B with a fan-out (B1,B2) taints
//    all of B's outputs. Verify seed, A, B1, B2 are all in the frozen set.
BOOST_AUTO_TEST_CASE(propagation_descent_and_fanout)
{
    std::set<COutPoint> frozen;

    // SEED tx: output 0 pays the drain script (the theft sweep). This makes the
    // seed tx tainted and taints ALL its outputs (0 and 1).
    const uint256 seedTx = TxId(1);
    {
        const std::vector<COutPoint> vin{COutPoint(TxId(100), 0)}; // arbitrary clean funding
        const std::vector<CScript> vout{DrainScript(), CleanScript()};
        BOOST_CHECK(Apply(seedTx, vin, vout, frozen));
    }
    BOOST_CHECK(frozen.count(COutPoint(seedTx, 0)) == 1);
    BOOST_CHECK(frozen.count(COutPoint(seedTx, 1)) == 1);

    // Tx A spends seedTx:0 (a tainted outpoint). A is tainted by descent; both of
    // A's outputs become tainted -- even though neither pays the drain script.
    const uint256 txA = TxId(2);
    {
        const std::vector<COutPoint> vin{COutPoint(seedTx, 0)};
        const std::vector<CScript> vout{CleanScript(), CleanScript()};
        BOOST_CHECK(Apply(txA, vin, vout, frozen));
    }
    BOOST_CHECK(frozen.count(COutPoint(txA, 0)) == 1);
    BOOST_CHECK(frozen.count(COutPoint(txA, 1)) == 1);

    // Tx B spends txA:0 and fans out to B1, B2 (two outputs). B is tainted by
    // descent; both B1 and B2 become tainted outpoints.
    const uint256 txB = TxId(3);
    {
        const std::vector<COutPoint> vin{COutPoint(txA, 0)};
        const std::vector<CScript> vout{CleanScript(), CleanScript()};
        BOOST_CHECK(Apply(txB, vin, vout, frozen));
    }
    const COutPoint B1(txB, 0);
    const COutPoint B2(txB, 1);
    BOOST_CHECK(frozen.count(B1) == 1);
    BOOST_CHECK(frozen.count(B2) == 1);

    // The whole descent chain is frozen: seed, A, B1, B2.
    BOOST_CHECK(frozen.count(COutPoint(seedTx, 0)) == 1);
    BOOST_CHECK(frozen.count(COutPoint(txA, 0)) == 1);
    BOOST_CHECK(frozen.count(B1) == 1);
    BOOST_CHECK(frozen.count(B2) == 1);
}

// Seed-by-txid rule: a tx whose id is a seed txid is tainted regardless of its
// scripts, and all its outputs become tainted.
BOOST_AUTO_TEST_CASE(seed_txid_taints_all_outputs)
{
    std::set<COutPoint> frozen;
    const uint256 theft = uint256S(freeze_seed::SEED_TXIDS[0]);
    const std::vector<COutPoint> vin{COutPoint(TxId(200), 0)};
    const std::vector<CScript> vout{CleanScript(), CleanScript(), CleanScript()};
    BOOST_CHECK(Apply(theft, vin, vout, frozen));
    BOOST_CHECK(frozen.count(COutPoint(theft, 0)) == 1);
    BOOST_CHECK(frozen.count(COutPoint(theft, 1)) == 1);
    BOOST_CHECK(frozen.count(COutPoint(theft, 2)) == 1);
}

// 2. A spend of a tainted outpoint is detected by TaintSet::Contains (the exact
//    membership the ConnectBlock / mempool reject uses). Build the frozen set
//    via Adopt and verify a tx spending it is caught.
BOOST_AUTO_TEST_CASE(tainted_spend_is_detected)
{
    std::set<COutPoint> frozen;
    const uint256 seedTx = TxId(1);
    Apply(seedTx, {COutPoint(TxId(100), 0)}, {DrainScript()}, frozen);

    TaintSet ts;
    ts.Adopt(frozen, /*height=*/1, /*anchor=*/uint256S("0x01"));
    BOOST_CHECK(ts.IsComputed());

    // A tx spending the tainted seed output: at least one input is frozen.
    const std::vector<COutPoint> spend_vin{COutPoint(seedTx, 0)};
    bool spends_frozen = false;
    for (const auto& prevout : spend_vin) {
        if (ts.Contains(prevout)) { spends_frozen = true; break; }
    }
    BOOST_CHECK(spends_frozen); // would be rejected by ConnectBlock / PreChecks
}

// 3. A completely unrelated clean coin is NOT tainted (no false positive) and a
//    spend of it passes the membership test.
BOOST_AUTO_TEST_CASE(clean_coin_not_tainted)
{
    std::set<COutPoint> frozen;
    // Seed something unrelated so the set is non-empty.
    const uint256 seedTx = TxId(1);
    Apply(seedTx, {COutPoint(TxId(100), 0)}, {DrainScript()}, frozen);

    // A clean tx funded by a clean coin, paying clean scripts: NOT tainted, and
    // its outputs are NOT added to the set.
    const uint256 cleanTx = TxId(50);
    const std::vector<COutPoint> vin{COutPoint(TxId(900), 0)};
    const std::vector<CScript> vout{CleanScript(), CleanScript()};
    BOOST_CHECK(!Apply(cleanTx, vin, vout, frozen));
    BOOST_CHECK(frozen.count(COutPoint(cleanTx, 0)) == 0);
    BOOST_CHECK(frozen.count(COutPoint(cleanTx, 1)) == 0);

    TaintSet ts;
    ts.Adopt(frozen, 1, uint256S("0x01"));
    // Spending the clean coin: membership test is false -> would NOT be rejected.
    BOOST_CHECK(!ts.Contains(COutPoint(cleanTx, 0)));
    BOOST_CHECK(!ts.Contains(COutPoint(TxId(900), 0)));
}

// 4. Determinism: building the set twice from the same ordered inputs yields a
//    bit-identical set (same membership AND same iteration order).
BOOST_AUTO_TEST_CASE(determinism_identical_sets)
{
    auto build = []() {
        std::set<COutPoint> frozen;
        const uint256 seedTx = TxId(1);
        Apply(seedTx, {COutPoint(TxId(100), 0)}, {DrainScript(), CleanScript()}, frozen);
        Apply(TxId(2), {COutPoint(seedTx, 0)}, {CleanScript(), CleanScript()}, frozen);
        Apply(TxId(3), {COutPoint(TxId(2), 0)}, {CleanScript(), CleanScript()}, frozen);
        // A clean tx that must NOT taint anything.
        Apply(TxId(50), {COutPoint(TxId(900), 0)}, {CleanScript()}, frozen);
        return frozen;
    };

    const std::set<COutPoint> a = build();
    const std::set<COutPoint> b = build();

    BOOST_CHECK_EQUAL(a.size(), b.size());
    BOOST_CHECK(a == b); // std::set::operator== compares ordered contents

    // Element-by-element, in iteration order (the order ConnectBlock observes).
    auto ia = a.begin();
    auto ib = b.begin();
    for (; ia != a.end() && ib != b.end(); ++ia, ++ib) {
        BOOST_CHECK(*ia == *ib);
    }
    BOOST_CHECK(ia == a.end());
    BOOST_CHECK(ib == b.end());
}

// Order-independence of input processing within a tx: the boolean taint result
// does not depend on which tainted input is encountered first.
BOOST_AUTO_TEST_CASE(determinism_input_order_irrelevant)
{
    std::set<COutPoint> frozen;
    const uint256 seedTx = TxId(1);
    Apply(seedTx, {COutPoint(TxId(100), 0)}, {DrainScript()}, frozen);

    // Tx with the tainted input first vs last -> identical taint outcome.
    std::set<COutPoint> w1 = frozen;
    std::set<COutPoint> w2 = frozen;
    const bool r1 = Apply(TxId(2),
                          {COutPoint(seedTx, 0), COutPoint(TxId(999), 0)},
                          {CleanScript()}, w1);
    const bool r2 = Apply(TxId(2),
                          {COutPoint(TxId(999), 0), COutPoint(seedTx, 0)},
                          {CleanScript()}, w2);
    BOOST_CHECK(r1);
    BOOST_CHECK(r2);
    BOOST_CHECK(w1 == w2);
}

BOOST_AUTO_TEST_SUITE_END()
