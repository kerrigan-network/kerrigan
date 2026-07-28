// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/dronelist.h>

#include <chain.h>
#include <chainparams.h>
#include <clientversion.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <evo/evodb.h>
#include <evo/inference_wire.h>
#include <evo/specialtx.h>
#include <evo/specialtxman.h>
#include <hash.h>
#include <key.h>
#include <key_io.h>
#include <primitives/block.h>
#include <script/script.h>
#include <script/standard.h>
#include <spork.h>
#include <streams.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/system.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <deque>

namespace {

struct RegTestDroneSetup : public BasicTestingSetup {
    RegTestDroneSetup() :
        BasicTestingSetup(CBaseChainParams::REGTEST) {}
};

/** Full TestingSetup (chainman etc.) for the CheckDroneRegTx-level test. */
struct RegTestDroneChainSetup : public TestingSetup {
    RegTestDroneChainSetup() :
        TestingSetup(CBaseChainParams::REGTEST) {}
};

uint160 Pkh(uint8_t b)
{
    return uint160(std::vector<unsigned char>(20, b));
}

CScript PayoutScript(uint8_t b)
{
    return CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, b) << OP_EQUALVERIFY << OP_CHECKSIG;
}

CDroneEntry MakeEntry(uint8_t keyByte, int nRegisteredHeight)
{
    CDroneEntry entry;
    entry.blsPubKeyHash = Pkh(keyByte);
    entry.payoutScript = PayoutScript(keyByte);
    entry.collateralOutpoint = COutPoint(uint256S(strprintf("%02x", keyByte)), 1);
    entry.irohNodeId = uint256S(strprintf("%02x%02x", keyByte, keyByte));
    entry.nHardwareClass = 0x03;
    entry.nModelTier = 0x02;
    entry.nRegisteredHeight = nRegisteredHeight;
    entry.nLastSeenHeight = nRegisteredHeight;
    entry.nLastPaidHeight = 0;
    return entry;
}

CDroneRegTx MakePayload(uint8_t keyByte, uint32_t nCollateralIndex, uint8_t hwClass = 0x00,
                        uint8_t modelTier = 0x02)
{
    // NOTE: unit tests exercise the list TRANSITION, which by design trusts
    // that CheckDroneRegTx already validated pubkey/pkh consistency and the
    // BLS signature -- so dummy key material is fine here. The signature and
    // commitment checks themselves are covered by inference_wire_tests
    // (golden vectors) and the functional test.
    CDroneRegTx ptx;
    ptx.blsPubKeyHash = Pkh(keyByte);
    ptx.vchBlsPubKey.assign(CDroneRegTx::BLS_PUBKEY_SIZE, keyByte);
    ptx.irohNodeId = uint256S(strprintf("%02x%02x", keyByte, keyByte));
    ptx.nHardwareClass = hwClass;
    ptx.nModelTier = modelTier;
    ptx.nCollateralIndex = nCollateralIndex;
    ptx.scriptPayout = PayoutScript(keyByte);
    ptx.inputsHash = uint256::ONE;
    ptx.vchSig.assign(CDroneRegTx::BLS_SIGNATURE_SIZE, 0x01);
    return ptx;
}

/** Consensus-shaped registration TX: special tx with a CDroneRegTx payload
 *  and the bond output at vout[1]. */
CMutableTransaction MakeRegistrationTx(uint8_t keyByte, CAmount bondValue, const COutPoint& fundingOutpoint,
                                       uint8_t hwClass = 0x00, uint32_t nCollateralIndex = 1,
                                       uint8_t modelTier = 0x02)
{
    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.nType = TRANSACTION_DRONE_REGISTER;
    tx.vin.emplace_back(fundingOutpoint);
    tx.vout.emplace_back(1 * COIN, PayoutScript(0xEE)); // change-style output at index 0
    tx.vout.emplace_back(bondValue, PayoutScript(keyByte));
    SetTxPayload(tx, MakePayload(keyByte, nCollateralIndex, hwClass, modelTier));
    return tx;
}

CBlock MakeBlock(const std::vector<CMutableTransaction>& txs)
{
    CBlock block;
    for (const auto& tx : txs) {
        block.vtx.push_back(MakeTransactionRef(tx));
    }
    return block;
}

CDroneList BuildFrom(const CDroneList& prev, const CBlock& block, int nHeight, const Consensus::Params& params)
{
    CDroneList out;
    CDroneListManager::BuildListFromBlock(prev, block, nHeight, params, out);
    return out;
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(drone_list_tests, RegTestDroneSetup)

BOOST_AUTO_TEST_CASE(payee_selection_ordering)
{
    const auto& params = Params().GetConsensus();
    BOOST_REQUIRE(params.nDronePayoutHeight > 0); // regtest arms the fork by default

    const int H = params.nDronePayoutHeight + 10;

    CDroneList list(uint256::ONE, H - 1);
    BOOST_CHECK(list.GetPayee(H, params) == nullptr); // empty list -> fallback

    // Never-paid drones queue by registration height...
    auto a = MakeEntry(0x02, H - 5); // registered later but SMALLER pkh
    auto b = MakeEntry(0x01, H - 6); // registered earlier
    a.nLastSeenHeight = H - 1;
    b.nLastSeenHeight = H - 1;
    list.AddDrone(a);
    list.AddDrone(b);
    BOOST_REQUIRE(list.GetPayee(H, params) != nullptr);
    BOOST_CHECK(list.GetPayee(H, params)->blsPubKeyHash == b.blsPubKeyHash);

    // ...with the pubkey-hash tie-break when registered in the same block.
    CDroneList tied(uint256::ONE, H - 1);
    auto t1 = MakeEntry(0x07, H - 5);
    auto t2 = MakeEntry(0x03, H - 5);
    t1.nLastSeenHeight = t2.nLastSeenHeight = H - 1;
    tied.AddDrone(t1);
    tied.AddDrone(t2);
    BOOST_CHECK(tied.GetPayee(H, params)->blsPubKeyHash == t2.blsPubKeyHash);

    // Paid drones go to the back of the queue: round-robin.
    auto paid = *list.GetPayee(H, params);
    paid.nLastPaidHeight = H;
    list.UpdateDrone(paid);
    BOOST_CHECK(list.GetPayee(H + 1, params)->blsPubKeyHash == a.blsPubKeyHash);

    const auto projected = list.GetProjectedPayees(H + 1, params, 10);
    BOOST_REQUIRE_EQUAL(projected.size(), 2U);
    BOOST_CHECK(projected[0]->blsPubKeyHash == a.blsPubKeyHash);
    BOOST_CHECK(projected[1]->blsPubKeyHash == b.blsPubKeyHash);
}

BOOST_AUTO_TEST_CASE(eligibility_heartbeat_max_age)
{
    const auto& params = Params().GetConsensus();
    BOOST_REQUIRE(params.nDroneMaxAge > 0);

    const int H = params.nDronePayoutHeight + 100;
    CDroneList list(uint256::ONE, H - 1);
    auto a = MakeEntry(0x01, H - 50);
    a.nLastSeenHeight = H - params.nDroneMaxAge; // exactly at the boundary: still eligible
    list.AddDrone(a);
    BOOST_CHECK(list.IsEligible(a, H, params));
    BOOST_CHECK(list.GetPayee(H, params) != nullptr);

    // One block past the max age: ineligible, payee falls back to none.
    a.nLastSeenHeight = H - params.nDroneMaxAge - 1;
    list.UpdateDrone(a);
    BOOST_CHECK(!list.IsEligible(a, H, params));
    BOOST_CHECK(list.GetPayee(H, params) == nullptr);
}

BOOST_AUTO_TEST_CASE(diff_and_serialization_roundtrip)
{
    CDroneList from(uint256::ONE, 250);
    auto a = MakeEntry(0x01, 210);
    auto b = MakeEntry(0x02, 220);
    from.AddDrone(a);
    from.AddDrone(b);

    CDroneList to = from;
    to.SetHeight(251);
    auto a2 = a;
    a2.nLastPaidHeight = 251;   // update
    to.UpdateDrone(a2);
    to.RemoveDrone(b.blsPubKeyHash); // removal
    auto c = MakeEntry(0x03, 251);   // addition
    c.nModelTier = 0x03;             // distinct tier: must survive both paths
    to.AddDrone(c);

    CDroneListDiff diff = from.BuildDiff(to);
    BOOST_CHECK(diff.HasChanges());
    BOOST_CHECK_EQUAL(diff.addedDrones.size(), 1U);
    BOOST_CHECK_EQUAL(diff.updatedDrones.size(), 1U);
    BOOST_CHECK_EQUAL(diff.removedDrones.size(), 1U);

    // Diff survives a serialization round-trip.
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << diff;
    CDroneListDiff diff2;
    ss >> diff2;
    BOOST_CHECK(diff2.HasChanges());
    BOOST_CHECK(diff2.addedDrones == diff.addedDrones);
    BOOST_CHECK(diff2.updatedDrones == diff.updatedDrones);
    BOOST_CHECK(diff2.removedDrones == diff.removedDrones);

    // An empty diff has no changes (written for every post-activation block).
    BOOST_CHECK(!from.BuildDiff(from).HasChanges());

    // List snapshot round-trip, including the derived collateral index.
    CDataStream ss2(SER_DISK, CLIENT_VERSION);
    ss2 << to;
    CDroneList to2;
    ss2 >> to2;
    BOOST_CHECK(to2 == to);
    BOOST_REQUIRE(to2.GetDroneByCollateral(c.collateralOutpoint) != nullptr);
    BOOST_CHECK(to2.GetDroneByCollateral(c.collateralOutpoint)->blsPubKeyHash == c.blsPubKeyHash);
    BOOST_CHECK(to2.GetDroneByCollateral(b.collateralOutpoint) == nullptr);

    // The model tier rides both storage paths identically: the per-entry
    // serializer (EvoDB snapshot, checked via to2 above) and the diff path
    // (added/updated entries embed full CDroneEntry structs).
    BOOST_REQUIRE(to2.GetDrone(a2.blsPubKeyHash) != nullptr);
    BOOST_CHECK_EQUAL(int{to2.GetDrone(a2.blsPubKeyHash)->nModelTier}, 0x02);
    BOOST_CHECK_EQUAL(int{to2.GetDrone(c.blsPubKeyHash)->nModelTier}, 0x03);
    BOOST_REQUIRE_EQUAL(diff2.addedDrones.size(), 1U);
    BOOST_CHECK_EQUAL(int{diff2.addedDrones[0].nModelTier}, 0x03);
}

BOOST_AUTO_TEST_CASE(build_list_registration_shapes)
{
    const auto& params = Params().GetConsensus();
    const int H = params.nDronePayoutHeight + 1;
    const CDroneList prev(uint256::ONE, H - 1);

    // Valid consensus shape: registered, payout script from the payload,
    // collateral = (txid, nCollateralIndex).
    {
        auto tx = MakeRegistrationTx(0x01, params.nDroneCollateralAmount, COutPoint(uint256::ONE, 0));
        const CDroneList out = BuildFrom(prev, MakeBlock({tx}), H, params);
        BOOST_REQUIRE_EQUAL(out.GetAllDroneCount(), 1U);
        const CDroneEntry* e = out.GetDrone(Pkh(0x01));
        BOOST_REQUIRE(e != nullptr);
        BOOST_CHECK(e->payoutScript == PayoutScript(0x01));
        BOOST_CHECK(e->collateralOutpoint == COutPoint(tx.GetHash(), 1));
        BOOST_CHECK_EQUAL(int{e->nModelTier}, 0x02); // tier from the payload
        BOOST_CHECK_EQUAL(e->nRegisteredHeight, H);
        BOOST_CHECK_EQUAL(e->nLastSeenHeight, H);
        BOOST_CHECK_EQUAL(e->nLastPaidHeight, 0);
    }

    // The explicit collateral index disambiguates equal-value outputs: an
    // extra output with the bond value changes nothing.
    {
        auto tx = MakeRegistrationTx(0x02, params.nDroneCollateralAmount, COutPoint(uint256::ONE, 0));
        tx.vout.emplace_back(params.nDroneCollateralAmount, PayoutScript(0x33));
        const CDroneList out = BuildFrom(prev, MakeBlock({tx}), H, params);
        BOOST_REQUIRE_EQUAL(out.GetAllDroneCount(), 1U);
        BOOST_CHECK(out.GetDrone(Pkh(0x02))->collateralOutpoint == COutPoint(tx.GetHash(), 1));
    }

    // Same-block-remove edge fallbacks (CheckDroneRegTx would reject these as
    // fresh registrations; BuildListFromBlock treats them as no-ops):
    // wrong bond value at the index...
    {
        auto tx = MakeRegistrationTx(0x03, params.nDroneCollateralAmount - 1, COutPoint(uint256::ONE, 0));
        BOOST_CHECK_EQUAL(BuildFrom(prev, MakeBlock({tx}), H, params).GetAllDroneCount(), 0U);
    }
    // ...collateral index out of range...
    {
        auto tx = MakeRegistrationTx(0x04, params.nDroneCollateralAmount, COutPoint(uint256::ONE, 0),
                                     /*hwClass=*/0x00, /*nCollateralIndex=*/7);
        BOOST_CHECK_EQUAL(BuildFrom(prev, MakeBlock({tx}), H, params).GetAllDroneCount(), 0U);
    }
    // ...unusable payout script.
    {
        auto tx = MakeRegistrationTx(0x05, params.nDroneCollateralAmount, COutPoint(uint256::ONE, 0));
        CDroneRegTx ptx = MakePayload(0x05, 1);
        ptx.scriptPayout = CScript() << OP_RETURN;
        SetTxPayload(tx, ptx);
        BOOST_CHECK_EQUAL(BuildFrom(prev, MakeBlock({tx}), H, params).GetAllDroneCount(), 0U);
    }

    // Non-special transactions (including old-style OP_RETURN payloads) are
    // completely ignored by the transition.
    {
        CMutableTransaction tx;
        tx.vin.emplace_back(COutPoint(uint256::ONE, 0));
        std::vector<unsigned char> oldPayload(54, 0x01);
        tx.vout.emplace_back(0, CScript() << OP_RETURN << oldPayload);
        tx.vout.emplace_back(params.nDroneCollateralAmount, PayoutScript(0x06));
        BOOST_CHECK_EQUAL(BuildFrom(prev, MakeBlock({tx}), H, params).GetAllDroneCount(), 0U);
    }

    // Unknown hardware-class byte is ACCEPTED and stored raw (consensus must
    // not gate on the swarm's enum).
    {
        auto tx = MakeRegistrationTx(0x07, params.nDroneCollateralAmount, COutPoint(uint256::ONE, 0),
                                     /*hwClass=*/0x2A);
        const CDroneList out = BuildFrom(prev, MakeBlock({tx}), H, params);
        BOOST_REQUIRE_EQUAL(out.GetAllDroneCount(), 1U);
        BOOST_CHECK_EQUAL(int{out.GetDrone(Pkh(0x07))->nHardwareClass}, 0x2A);
    }

    // Every canonical model tier (0..3) is stored exactly as registered.
    // (CheckDroneRegTx rejects > MAX_MODEL_TIER before the transition runs,
    // so the list only ever sees canonical values.)
    for (uint8_t tier = 0; tier <= CDroneRegTx::MAX_MODEL_TIER; tier++) {
        auto tx = MakeRegistrationTx(0x10 + tier, params.nDroneCollateralAmount, COutPoint(uint256::ONE, 0),
                                     /*hwClass=*/0x00, /*nCollateralIndex=*/1, /*modelTier=*/tier);
        const CDroneList out = BuildFrom(prev, MakeBlock({tx}), H, params);
        BOOST_REQUIRE_EQUAL(out.GetAllDroneCount(), 1U);
        BOOST_CHECK_EQUAL(int{out.GetDrone(Pkh(0x10 + tier))->nModelTier}, int{tier});
    }
}

BOOST_AUTO_TEST_CASE(build_list_collateral_spend_deregisters)
{
    const auto& params = Params().GetConsensus();
    const int H = params.nDronePayoutHeight + 5;

    CDroneList prev(uint256::ONE, H - 1);
    auto a = MakeEntry(0x01, H - 3);
    a.nLastSeenHeight = H - 1;
    prev.AddDrone(a);

    // Any TX spending the bond outpoint removes the entry.
    CMutableTransaction spend;
    spend.vin.emplace_back(a.collateralOutpoint);
    spend.vout.emplace_back(50 * COIN, PayoutScript(0x99));

    const CDroneList out = BuildFrom(prev, MakeBlock({spend}), H, params);
    BOOST_CHECK_EQUAL(out.GetAllDroneCount(), 0U);
    BOOST_CHECK(out.GetDroneByCollateral(a.collateralOutpoint) == nullptr);
}

BOOST_AUTO_TEST_CASE(build_list_heartbeat_and_immutability)
{
    const auto& params = Params().GetConsensus();
    const int H = params.nDronePayoutHeight + 5;

    CDroneList prev(uint256::ONE, H - 1);
    auto a = MakeEntry(0x01, H - 4);
    a.nLastSeenHeight = H - 4;
    prev.AddDrone(a);

    // A second registration payload for a live pkh is a heartbeat: it bumps
    // the last-seen height ONLY. A different bond output / payout script /
    // hardware class in the heartbeat TX must not rebind anything
    // (immutability; the BLS signature authenticating the heartbeat was
    // consensus-verified before the transition runs).
    auto hb = MakeRegistrationTx(0x01, params.nDroneCollateralAmount, COutPoint(uint256S("aa"), 0),
                                 /*hwClass=*/0x05);
    CDroneRegTx hbPayload = MakePayload(0x01, 1, /*hwClass=*/0x05, /*modelTier=*/0x01);
    hbPayload.scriptPayout = PayoutScript(0x66); // rebind attempt
    SetTxPayload(hb, hbPayload);

    const CDroneList out = BuildFrom(prev, MakeBlock({hb}), H, params);
    const CDroneEntry* e = out.GetDrone(a.blsPubKeyHash);
    BOOST_REQUIRE(e != nullptr);
    BOOST_CHECK_EQUAL(e->nLastSeenHeight, H);                         // bumped
    BOOST_CHECK(e->payoutScript == a.payoutScript);                   // immutable
    BOOST_CHECK(e->collateralOutpoint == a.collateralOutpoint);       // immutable
    BOOST_CHECK_EQUAL(int{e->nHardwareClass}, int{a.nHardwareClass}); // immutable
    BOOST_CHECK_EQUAL(int{e->nModelTier}, int{a.nModelTier});         // immutable
}

BOOST_AUTO_TEST_CASE(same_block_reregistration_diff_replay)
{
    // A single TX may spend a drone's bond AND carry a fresh registration for
    // the same pkh with a new bond: deregister + re-register in one block.
    // The per-block diff must replay this exactly (remove+add, never an
    // immutable-field mutation).
    const auto& params = Params().GetConsensus();
    const int H = params.nDronePayoutHeight + 5;

    CDroneList prev(uint256::ONE, H - 1);
    auto a = MakeEntry(0x01, H - 3);
    a.nLastSeenHeight = H - 1;
    prev.AddDrone(a);

    CMutableTransaction rereg = MakeRegistrationTx(0x01, params.nDroneCollateralAmount, a.collateralOutpoint);
    const CDroneList out = BuildFrom(prev, MakeBlock({rereg}), H, params);
    const CDroneEntry* e = out.GetDrone(a.blsPubKeyHash);
    BOOST_REQUIRE(e != nullptr);
    BOOST_CHECK(e->collateralOutpoint == COutPoint(rereg.GetHash(), 1)); // new bond
    BOOST_CHECK_EQUAL(e->nRegisteredHeight, H);

    // Diff replay reproduces the exact same list.
    CDroneListDiff diff = prev.BuildDiff(out);
    BOOST_CHECK_EQUAL(diff.removedDrones.size(), 1U);
    BOOST_CHECK_EQUAL(diff.addedDrones.size(), 1U);
    BOOST_CHECK_EQUAL(diff.updatedDrones.size(), 0U);
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << diff;
    CDroneListDiff diff2;
    ss >> diff2;
    CDroneList replayed = prev;
    CBlockIndex index;
    index.nHeight = H;
    index.phashBlock = &uint256::ONE;
    replayed.ApplyDiff(&index, diff2);
    replayed.SetBlockHash(out.GetBlockHash());
    replayed.SetHeight(out.GetHeight());
    BOOST_CHECK(replayed == out);
}

BOOST_AUTO_TEST_CASE(build_list_payee_last_paid_bump)
{
    const auto& params = Params().GetConsensus();
    const int H = params.nDronePayoutHeight + 5;

    CDroneList prev(uint256::ONE, H - 1);
    auto a = MakeEntry(0x01, H - 4);
    auto b = MakeEntry(0x02, H - 4);
    a.nLastSeenHeight = b.nLastSeenHeight = H - 1;
    prev.AddDrone(a);
    prev.AddDrone(b);

    // Empty block: the only state transition is the payee's last-paid bump,
    // which must select exactly what GetPayee selected for this height.
    const CDroneEntry* expected = prev.GetPayee(H, params);
    BOOST_REQUIRE(expected != nullptr);
    BOOST_CHECK(expected->blsPubKeyHash == a.blsPubKeyHash); // pkh tie-break

    const CDroneList afterH = BuildFrom(prev, MakeBlock({}), H, params);
    BOOST_CHECK_EQUAL(afterH.GetDrone(a.blsPubKeyHash)->nLastPaidHeight, H);
    BOOST_CHECK_EQUAL(afterH.GetDrone(b.blsPubKeyHash)->nLastPaidHeight, 0);

    // Next block rotates to B, then back to A: strict alternation.
    BOOST_CHECK(afterH.GetPayee(H + 1, params)->blsPubKeyHash == b.blsPubKeyHash);
    const CDroneList afterH1 = BuildFrom(afterH, MakeBlock({}), H + 1, params);
    BOOST_CHECK_EQUAL(afterH1.GetDrone(b.blsPubKeyHash)->nLastPaidHeight, H + 1);
    BOOST_CHECK(afterH1.GetPayee(H + 2, params)->blsPubKeyHash == a.blsPubKeyHash);
}

/**
 * Manager-level snapshot/replay coverage (review finding M1): exercises the
 * evoDb-backed diff-write + snapshot-write path of ProcessBlock, and the
 * cache-miss walk of GetListForBlock (snapshot read + forward diff replay)
 * with a fresh manager whose caches are empty -- the exact route a restarted
 * or reindexing node takes. Uses a small snapshot period (the same knob the
 * functional test drives via -dronesnapshotperiod) and a synthetic chain.
 */
BOOST_AUTO_TEST_CASE(manager_snapshot_walk_and_undo)
{
    const auto& params = Params().GetConsensus();
    const int nFork = params.nDronePayoutHeight; // 200 on regtest
    constexpr int SNAPSHOT_PERIOD = 5;
    const int nStart = nFork - 3;
    const int nTip = nFork + 22; // crosses snapshot heights 200, 205, ..., 220

    // Synthetic chain nStart..nTip (stable storage for hashes + indexes).
    std::deque<uint256> hashes;
    std::deque<CBlockIndex> indexes;
    CBlockIndex* pprev{nullptr};
    for (int h = nStart; h <= nTip; h++) {
        hashes.push_back(uint256S(strprintf("%06x", h)));
        indexes.emplace_back();
        CBlockIndex& idx = indexes.back();
        idx.nHeight = h;
        idx.phashBlock = &hashes.back();
        idx.pprev = pprev;
        pprev = &idx;
    }
    auto IndexAt = [&](int h) -> CBlockIndex* { return &indexes.at(h - nStart); };

    CEvoDB evoDb(util::DbWrapperParams{.path = gArgs.GetDataDirNet() / "drone_evodb_test", .memory = true, .wipe = true});
    CDroneListManager mgr(evoDb, SNAPSHOT_PERIOD);

    // Blocks: register A at fork+2, B at fork+7 (between snapshots),
    // heartbeat A at fork+13, deregister B at fork+17. Everything else empty.
    const CAmount bond = params.nDroneCollateralAmount;
    std::map<int, CBlock> blocks;
    const auto txA = MakeRegistrationTx(0x0A, bond, COutPoint(uint256S("f00d"), 0));
    const auto txB = MakeRegistrationTx(0x0B, bond, COutPoint(uint256S("f00e"), 0));
    blocks[nFork + 2] = MakeBlock({txA});
    blocks[nFork + 7] = MakeBlock({txB});
    auto hbA = MakeRegistrationTx(0x0A, bond, COutPoint(uint256S("f00f"), 0));
    blocks[nFork + 13] = MakeBlock({hbA});
    CMutableTransaction spendB;
    spendB.vin.emplace_back(COutPoint(txB.GetHash(), 1));
    spendB.vout.emplace_back(bond - 10000, PayoutScript(0x77));
    blocks[nFork + 17] = MakeBlock({spendB});

    {
        LOCK(cs_main);
        for (int h = nFork; h <= nTip; h++) {
            BlockValidationState state;
            const CBlock block = blocks.count(h) ? blocks[h] : MakeBlock({});
            BOOST_REQUIRE_MESSAGE(mgr.ProcessBlock(block, IndexAt(h), params, state),
                                  strprintf("ProcessBlock failed at height %d: %s", h, state.ToString()));
        }
    }

    // Snapshots must exist exactly at the period multiples.
    for (int h = nFork; h <= nTip; h++) {
        const bool expectSnap = (h % SNAPSHOT_PERIOD) == 0;
        BOOST_CHECK_MESSAGE(
            evoDb.Exists(std::make_pair(std::string("drn_S1"), IndexAt(h)->GetBlockHash())) == expectSnap,
            strprintf("unexpected snapshot presence at height %d", h));
    }

    // Reference lists from the live (fully cached) manager.
    std::map<int, CDroneList> reference;
    for (int h = nStart; h <= nTip; h++) {
        reference.emplace(h, mgr.GetListForBlock(IndexAt(h), params));
    }
    BOOST_CHECK_EQUAL(reference.at(nTip).GetAllDroneCount(), 1U); // B deregistered
    BOOST_REQUIRE(reference.at(nTip).GetDrone(Pkh(0x0A)) != nullptr);
    BOOST_CHECK_EQUAL(reference.at(nTip).GetDrone(Pkh(0x0A))->nLastSeenHeight, nFork + 13);

    // A FRESH manager on the same evoDb has empty caches: every query walks
    // disk -- nearest snapshot first, then forward diff replay. Lists must be
    // identical at every height (this is the restart / historical-query
    // route, and any divergence here is the M1 chainsplit scenario).
    {
        CDroneListManager fresh(evoDb, SNAPSHOT_PERIOD);
        for (int h = nStart; h <= nTip; h++) {
            const CDroneList walked = fresh.GetListForBlock(IndexAt(h), params);
            BOOST_CHECK_MESSAGE(walked == reference.at(h),
                                strprintf("fresh-manager walk diverges at height %d", h));
            const CDroneEntry* pw = walked.GetPayee(h + 1, params);
            const CDroneEntry* pr = reference.at(h).GetPayee(h + 1, params);
            BOOST_CHECK_MESSAGE((pw == nullptr) == (pr == nullptr) &&
                                    (pw == nullptr || pw->blsPubKeyHash == pr->blsPubKeyHash),
                                strprintf("payee diverges at height %d", h));
        }
    }

    // Undo back through a snapshot boundary, then reconnect: state and payees
    // must replay identically (reorg rewind + replay at the manager level).
    {
        LOCK(cs_main);
        for (int h = nTip; h > nFork + 14; h--) { // rewinds through snapshots 220 and 215
            BOOST_REQUIRE(mgr.UndoBlock(IndexAt(h), params));
        }
        for (int h = nFork + 15; h <= nTip; h++) {
            BlockValidationState state;
            const CBlock block = blocks.count(h) ? blocks[h] : MakeBlock({});
            BOOST_REQUIRE(mgr.ProcessBlock(block, IndexAt(h), params, state));
        }
    }
    for (int h = nStart; h <= nTip; h++) {
        BOOST_CHECK_MESSAGE(mgr.GetListForBlock(IndexAt(h), params) == reference.at(h),
                            strprintf("post-undo/replay list diverges at height %d", h));
    }
}

BOOST_AUTO_TEST_CASE(drone_payout_effective_spork_gate)
{
    // IsDronePayoutEffective = height floor (nDronePayoutHeight) AND
    // SPORK_26_DRONE_PAYOUT_ENABLED. See dronelist.h for why the two terms
    // must gate registration and payout in lockstep (reindex safety).
    const auto& params = Params().GetConsensus();
    BOOST_REQUIRE(params.nDronePayoutHeight > 0);
    const int nFloor = params.nDronePayoutHeight;

    const CSporkManager* const prev_sporkman = g_sporkman;

    // No spork manager at all (early init / bare test setups): fail closed,
    // even far above the floor. The raw height-only predicate is unaffected.
    g_sporkman = nullptr;
    BOOST_CHECK(params.IsDronePayoutActive(nFloor));
    BOOST_CHECK(!IsDronePayoutEffective(params, nFloor));
    BOOST_CHECK(!IsDronePayoutEffective(params, nFloor + 100000));

    // Live spork manager with the DEFAULT spork value: OFF (4070908800ULL).
    CSporkManager sporkman;
    CKey sporkKey;
    sporkKey.MakeNewKey(false);
    BOOST_REQUIRE(sporkman.SetSporkAddress(EncodeDestination(PKHash(sporkKey.GetPubKey()))));
    BOOST_REQUIRE(sporkman.SetMinSporkKeys(1));
    BOOST_REQUIRE(sporkman.SetPrivKey(EncodeSecret(sporkKey)));
    g_sporkman = &sporkman;

    BOOST_CHECK(!sporkman.IsSporkActive(SPORK_26_DRONE_PAYOUT_ENABLED));
    BOOST_CHECK(!IsDronePayoutEffective(params, nFloor));
    BOOST_CHECK(!IsDronePayoutEffective(params, nFloor + 100000));

    // Operator flips the spork ON (value 0 == active immediately).
    BOOST_REQUIRE(sporkman.UpdateSpork(SPORK_26_DRONE_PAYOUT_ENABLED, 0).has_value());
    BOOST_CHECK(sporkman.IsSporkActive(SPORK_26_DRONE_PAYOUT_ENABLED));
    // ...but the height floor stays a hard minimum: the spork can never
    // activate the fork inside pre-floor history.
    BOOST_CHECK(!IsDronePayoutEffective(params, nFloor - 1));
    BOOST_CHECK(!IsDronePayoutEffective(params, 0));
    BOOST_CHECK(IsDronePayoutEffective(params, nFloor));
    BOOST_CHECK(IsDronePayoutEffective(params, nFloor + 100000));

    g_sporkman = prev_sporkman;
}

/**
 * CheckDroneRegTx model-tier consensus rule: fully-signed registrations with
 * nModelTier 0..MAX_MODEL_TIER are accepted, anything above is rejected with
 * "bad-drone-reg-tier" -- even with a perfectly valid BLS signature (the tier
 * byte is INSIDE the signed payload, so the signer vouched for it; the range
 * rule is what keeps stored list state canonical). Also pins that the tier
 * check sits inside the IsDronePayoutEffective gate: with the spork off the
 * TX fails "bad-drone-reg-height" first, keeping all drone-reg gates in
 * lockstep (reindex safety).
 */
BOOST_FIXTURE_TEST_CASE(check_drone_reg_tx_model_tier, RegTestDroneChainSetup)
{
    const auto& params = Params().GetConsensus();
    BOOST_REQUIRE(m_node.chainman);
    const ChainstateManager& chainman = *m_node.chainman;

    // Spork 26 ON (same recipe as drone_payout_effective_spork_gate).
    const CSporkManager* const prev_sporkman = g_sporkman;
    CSporkManager sporkman;
    CKey sporkKey;
    sporkKey.MakeNewKey(false);
    BOOST_REQUIRE(sporkman.SetSporkAddress(EncodeDestination(PKHash(sporkKey.GetPubKey()))));
    BOOST_REQUIRE(sporkman.SetMinSporkKeys(1));
    BOOST_REQUIRE(sporkman.SetPrivKey(EncodeSecret(sporkKey)));
    BOOST_REQUIRE(sporkman.UpdateSpork(SPORK_26_DRONE_PAYOUT_ENABLED, 0).has_value());
    g_sporkman = &sporkman;

    CEvoDB evoDb(util::DbWrapperParams{.path = gArgs.GetDataDirNet() / "drone_evodb_tier_test", .memory = true, .wipe = true});
    CDroneListManager droneman(evoDb);

    // Synthetic post-fork pindexPrev (the drone list walk falls back to the
    // empty baseline, so every payload below is a FRESH registration).
    const uint256 prevHash = uint256::ONE;
    CBlockIndex prevIndex;
    prevIndex.nHeight = params.nDronePayoutHeight + 5;
    prevIndex.phashBlock = &prevHash;

    // Real drone BLS key so check_sigs=true exercises the full path.
    std::vector<unsigned char> secret(32, 0x00);
    secret[31] = 0x2a;
    std::vector<unsigned char> pubkey;
    BOOST_REQUIRE(DroneBLS::PublicKeyFromSecret(secret, pubkey));

    const auto MakeSignedRegTx = [&](uint8_t modelTier) {
        CMutableTransaction tx;
        tx.nVersion = 3;
        tx.nType = TRANSACTION_DRONE_REGISTER;
        tx.vin.emplace_back(COutPoint(uint256::ONE, 0));
        tx.vout.emplace_back(params.nDroneCollateralAmount, PayoutScript(0x11)); // bond at index 0
        CDroneRegTx ptx;
        ptx.blsPubKeyHash = Hash160(pubkey);
        ptx.vchBlsPubKey = pubkey;
        ptx.irohNodeId = uint256::ONE;
        ptx.nHardwareClass = 0x03;
        ptx.nModelTier = modelTier;
        ptx.nCollateralIndex = 0;
        ptx.scriptPayout = PayoutScript(0x11);
        ptx.inputsHash = CalcTxInputsHash(CTransaction(tx));
        BOOST_REQUIRE(DroneBLS::SignMinSig(secret, ::SerializeHash(ptx), ptx.vchSig));
        SetTxPayload(tx, ptx);
        return CTransaction(tx);
    };

    LOCK(cs_main);

    // Canonical tiers 0..3: accepted.
    for (uint8_t tier = 0; tier <= CDroneRegTx::MAX_MODEL_TIER; tier++) {
        TxValidationState state;
        BOOST_CHECK_MESSAGE(
            CheckDroneRegTx(MakeSignedRegTx(tier), &prevIndex, droneman, chainman, state, /*check_sigs=*/true),
            strprintf("tier %d rejected: %s", tier, state.GetRejectReason()));
    }

    // Out-of-range tiers: rejected with the dedicated reason, despite the
    // valid signature.
    for (const uint8_t tier : {uint8_t{4}, uint8_t{5}, uint8_t{0xFF}}) {
        TxValidationState state;
        BOOST_CHECK(!CheckDroneRegTx(MakeSignedRegTx(tier), &prevIndex, droneman, chainman, state,
                                     /*check_sigs=*/true));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-drone-reg-tier");
    }

    // Spork off: the shared activation gate fires FIRST, for valid and
    // invalid tiers alike (lockstep with the other drone-reg gates).
    BOOST_REQUIRE(sporkman.UpdateSpork(SPORK_26_DRONE_PAYOUT_ENABLED, 4070908800ULL /*OFF*/).has_value());
    for (const uint8_t tier : {uint8_t{0}, uint8_t{4}}) {
        TxValidationState state;
        BOOST_CHECK(!CheckDroneRegTx(MakeSignedRegTx(tier), &prevIndex, droneman, chainman, state,
                                     /*check_sigs=*/true));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-drone-reg-height");
    }

    g_sporkman = prev_sporkman;
}

BOOST_AUTO_TEST_SUITE_END()
