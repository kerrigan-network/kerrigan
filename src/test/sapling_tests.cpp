// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coins.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <evo/specialtx.h>
#include <key_io.h>
#include <primitives/transaction.h>
#include <rust/bridge.h>
#include <sapling/sapling_address.h>
#include <sapling/sapling_state.h>
#include <sapling/sapling_tx_payload.h>
#include <sapling/sapling_validation.h>
#include <streams.h>
#include <blockencodings.h>
#include <consensus/merkle.h>
#include <test/util/setup_common.h>

#include <cstring>

#include <boost/test/unit_test.hpp>

// Forward declarations for spec.rs bridge functions (no header generated for this bridge).
namespace sapling::spec {
std::array<uint8_t, 32> tree_uncommitted() noexcept;
std::array<uint8_t, 32> merkle_hash(size_t depth, const std::array<uint8_t, 32>& lhs, const std::array<uint8_t, 32>& rhs) noexcept;
} // namespace sapling::spec

BOOST_FIXTURE_TEST_SUITE(sapling_tests, BasicTestingSetup)

// Serialization round-trip tests

BOOST_AUTO_TEST_CASE(sapling_spend_description_roundtrip)
{
    SaplingSpendDescription sd;
    // Fill with non-zero test data
    sd.cv.fill(0x11);
    sd.anchor.fill(0x22);
    sd.nullifier.fill(0x33);
    sd.rk.fill(0x44);
    sd.zkproof.fill(0x55);
    sd.spendAuthSig.fill(0x66);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << sd;

    SaplingSpendDescription sd2;
    ss >> sd2;

    BOOST_CHECK(sd.cv == sd2.cv);
    BOOST_CHECK(sd.anchor == sd2.anchor);
    BOOST_CHECK(sd.nullifier == sd2.nullifier);
    BOOST_CHECK(sd.rk == sd2.rk);
    BOOST_CHECK(sd.zkproof == sd2.zkproof);
    BOOST_CHECK(sd.spendAuthSig == sd2.spendAuthSig);
}

BOOST_AUTO_TEST_CASE(sapling_output_description_roundtrip)
{
    SaplingOutputDescription od;
    od.cv.fill(0xAA);
    od.cmu.fill(0xBB);
    od.ephemeralKey.fill(0xCC);
    od.encCiphertext.fill(0xDD);
    od.outCiphertext.fill(0xEE);
    od.zkproof.fill(0xFF);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << od;

    SaplingOutputDescription od2;
    ss >> od2;

    BOOST_CHECK(od.cv == od2.cv);
    BOOST_CHECK(od.cmu == od2.cmu);
    BOOST_CHECK(od.ephemeralKey == od2.ephemeralKey);
    BOOST_CHECK(od.encCiphertext == od2.encCiphertext);
    BOOST_CHECK(od.outCiphertext == od2.outCiphertext);
    BOOST_CHECK(od.zkproof == od2.zkproof);
}

BOOST_AUTO_TEST_CASE(sapling_tx_payload_roundtrip)
{
    SaplingTxPayload payload;
    payload.nVersion = SAPLING_PAYLOAD_VERSION;
    payload.valueBalance = -12345678;
    payload.bindingSig.fill(0x77);

    // Add a spend
    SaplingSpendDescription sd;
    sd.cv.fill(0x01);
    sd.anchor.fill(0x02);
    sd.nullifier.fill(0x03);
    sd.rk.fill(0x04);
    sd.zkproof.fill(0x05);
    sd.spendAuthSig.fill(0x06);
    payload.vSpendDescriptions.push_back(sd);

    // Add two outputs
    SaplingOutputDescription od;
    od.cv.fill(0x0A);
    od.cmu.fill(0x0B);
    od.ephemeralKey.fill(0x0C);
    od.encCiphertext.fill(0x0D);
    od.outCiphertext.fill(0x0E);
    od.zkproof.fill(0x0F);
    payload.vOutputDescriptions.push_back(od);

    od.cv.fill(0x1A);
    od.cmu.fill(0x1B);
    payload.vOutputDescriptions.push_back(od);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;

    SaplingTxPayload payload2;
    ss >> payload2;

    BOOST_CHECK_EQUAL(payload2.nVersion, SAPLING_PAYLOAD_VERSION);
    BOOST_CHECK_EQUAL(payload2.valueBalance, -12345678);
    BOOST_CHECK(payload2.bindingSig == payload.bindingSig);
    BOOST_CHECK_EQUAL(payload2.vSpendDescriptions.size(), 1U);
    BOOST_CHECK_EQUAL(payload2.vOutputDescriptions.size(), 2U);
    BOOST_CHECK(payload2.vSpendDescriptions[0].nullifier == sd.nullifier);
    BOOST_CHECK(payload2.vOutputDescriptions[0].cmu[0] == 0x0B);
    BOOST_CHECK(payload2.vOutputDescriptions[1].cmu[0] == 0x1B);
}

BOOST_AUTO_TEST_CASE(sapling_payload_empty_roundtrip)
{
    // Empty payload (no spends, no outputs), still valid wire format
    SaplingTxPayload payload;
    payload.nVersion = SAPLING_PAYLOAD_VERSION;
    payload.valueBalance = 0;
    payload.bindingSig.fill(0x00);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;

    SaplingTxPayload payload2;
    ss >> payload2;

    BOOST_CHECK_EQUAL(payload2.nVersion, SAPLING_PAYLOAD_VERSION);
    BOOST_CHECK_EQUAL(payload2.valueBalance, 0);
    BOOST_CHECK_EQUAL(payload2.GetSpendsCount(), 0U);
    BOOST_CHECK_EQUAL(payload2.GetOutputsCount(), 0U);
    BOOST_CHECK(!payload2.HasShieldedActions());
}

// GetTxPayload integration

BOOST_AUTO_TEST_CASE(sapling_get_tx_payload)
{
    // Build a SaplingTxPayload, serialize into vExtraPayload, recover via GetTxPayload
    SaplingTxPayload payload;
    payload.nVersion = SAPLING_PAYLOAD_VERSION;
    payload.valueBalance = 50000000; // 0.5 KRGN entering transparent pool

    SaplingOutputDescription od;
    od.cv.fill(0xAB);
    od.cmu.fill(0xCD);
    od.ephemeralKey.fill(0xEF);
    od.encCiphertext.fill(0x12);
    od.outCiphertext.fill(0x34);
    od.zkproof.fill(0x56);
    payload.vOutputDescriptions.push_back(od);
    payload.bindingSig.fill(0x99);

    // Serialize to bytes (simulating vExtraPayload)
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;
    std::vector<uint8_t> extraPayload(ss.size());
    std::memcpy(extraPayload.data(), ss.data(), ss.size());

    // Recover
    auto opt = GetTxPayload<SaplingTxPayload>(extraPayload);
    BOOST_REQUIRE(opt.has_value());
    BOOST_CHECK_EQUAL(opt->nVersion, SAPLING_PAYLOAD_VERSION);
    BOOST_CHECK_EQUAL(opt->valueBalance, 50000000);
    BOOST_CHECK_EQUAL(opt->GetSpendsCount(), 0U);
    BOOST_CHECK_EQUAL(opt->GetOutputsCount(), 1U);
    BOOST_CHECK(opt->vOutputDescriptions[0].cv[0] == 0xAB);
}

// Transaction structure tests

BOOST_AUTO_TEST_CASE(sapling_transaction_type)
{
    // Verify TRANSACTION_SAPLING is 10
    BOOST_CHECK_EQUAL(TRANSACTION_SAPLING, 10);
}

BOOST_AUTO_TEST_CASE(sapling_tx_allows_empty_vin_vout)
{
    // A pure z->z Sapling tx has no transparent inputs or outputs.
    // CheckTransaction should allow empty vin/vout for TRANSACTION_SAPLING.
    CMutableTransaction mtx;
    mtx.nVersion = 3;
    mtx.nType = TRANSACTION_SAPLING;
    // No vin, no vout: normally rejected, but allowed for Sapling

    // Build a minimal payload
    SaplingTxPayload payload;
    payload.nVersion = SAPLING_PAYLOAD_VERSION;
    payload.valueBalance = 0;
    payload.bindingSig.fill(0x00);

    SaplingOutputDescription od;
    od.cv.fill(0x01);
    od.cmu.fill(0x02);
    od.ephemeralKey.fill(0x03);
    od.encCiphertext.fill(0x04);
    od.outCiphertext.fill(0x05);
    od.zkproof.fill(0x06);
    payload.vOutputDescriptions.push_back(od);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;
    mtx.vExtraPayload.resize(ss.size());
    std::memcpy(mtx.vExtraPayload.data(), ss.data(), ss.size());

    CTransaction tx(mtx);
    TxValidationState state;
    BOOST_CHECK(CheckTransaction(tx, state));
}

BOOST_AUTO_TEST_CASE(sapling_tx_payload_size_limit)
{
    // MAX_SAPLING_TX_EXTRA_PAYLOAD = 150000. Verify rejection for oversized.
    CMutableTransaction mtx;
    mtx.nVersion = 3;
    mtx.nType = TRANSACTION_SAPLING;
    mtx.vExtraPayload.resize(150001, 0x00); // 1 byte over limit

    // Need at least a coinbase-like input to avoid "bad-txns-vin-empty"
    // (Actually for TRANSACTION_SAPLING empty vin is allowed, but we need
    //  the payload check to fire)
    CTransaction tx(mtx);
    TxValidationState state;
    bool result = CheckTransaction(tx, state);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-payload-oversize");
}

BOOST_AUTO_TEST_CASE(sapling_tx_normal_payload_size_ok)
{
    // A normally-sized Sapling payload should pass the size check
    CMutableTransaction mtx;
    mtx.nVersion = 3;
    mtx.nType = TRANSACTION_SAPLING;

    SaplingTxPayload payload;
    payload.nVersion = SAPLING_PAYLOAD_VERSION;
    payload.valueBalance = 0;
    payload.bindingSig.fill(0x00);

    // Add 10 outputs (~9.5KB, well under 150KB)
    for (int i = 0; i < 10; i++) {
        SaplingOutputDescription od;
        od.cv.fill(i);
        od.cmu.fill(i + 1);
        od.ephemeralKey.fill(i + 2);
        od.encCiphertext.fill(i + 3);
        od.outCiphertext.fill(i + 4);
        od.zkproof.fill(i + 5);
        payload.vOutputDescriptions.push_back(od);
    }

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;
    mtx.vExtraPayload.resize(ss.size());
    std::memcpy(mtx.vExtraPayload.data(), ss.data(), ss.size());

    CTransaction tx(mtx);
    TxValidationState state;
    BOOST_CHECK(CheckTransaction(tx, state));
}

// ToJson test

BOOST_AUTO_TEST_CASE(sapling_payload_to_json)
{
    SaplingTxPayload payload;
    payload.nVersion = SAPLING_PAYLOAD_VERSION;
    payload.valueBalance = 100000000; // 1 KRGN

    SaplingSpendDescription sd;
    sd.cv.fill(0x11);
    sd.anchor.fill(0x22);
    sd.nullifier.fill(0x33);
    sd.rk.fill(0x44);
    sd.zkproof.fill(0x55);
    sd.spendAuthSig.fill(0x66);
    payload.vSpendDescriptions.push_back(sd);

    SaplingOutputDescription od;
    od.cv.fill(0xAA);
    od.cmu.fill(0xBB);
    od.ephemeralKey.fill(0xCC);
    od.encCiphertext.fill(0xDD);
    od.outCiphertext.fill(0xEE);
    od.zkproof.fill(0xFF);
    payload.vOutputDescriptions.push_back(od);

    payload.bindingSig.fill(0x88);

    UniValue json = payload.ToJson();
    BOOST_CHECK_EQUAL(json["version"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(json["spends"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(json["outputs"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(json["valueBalance"].getValStr(), "1.00000000"); // 1 KRGN in coin units
    BOOST_CHECK_EQUAL(json["valueBalanceSat"].getInt<int64_t>(), 100000000);
    BOOST_CHECK(json["vSpendDescriptions"].isArray());
    BOOST_CHECK(json["vOutputDescriptions"].isArray());
    BOOST_CHECK_EQUAL(json["vSpendDescriptions"].size(), 1U);
    BOOST_CHECK_EQUAL(json["vOutputDescriptions"].size(), 1U);

    // Verify nullifier hex encoding
    const UniValue& spend0 = json["vSpendDescriptions"][0];
    std::string expectedNullifier(64, '3'); // 32 bytes of 0x33
    BOOST_CHECK_EQUAL(spend0["nullifier"].get_str(), expectedNullifier);
}

// Address encoding/decoding tests

BOOST_AUTO_TEST_CASE(sapling_address_roundtrip)
{
    sapling::SaplingPaymentAddress addr;
    // Fill with known test data
    for (int i = 0; i < 11; i++) addr.d[i] = static_cast<uint8_t>(i + 1);
    for (int i = 0; i < 32; i++) addr.pk_d[i] = static_cast<uint8_t>(0x80 + i);

    std::string encoded = EncodeSaplingAddress(addr);

    // Should start with the network HRP + "1" separator
    const std::string& hrp = Params().SaplingHRP();
    BOOST_CHECK(encoded.substr(0, hrp.size() + 1) == hrp + "1");

    // Decode it back
    sapling::SaplingPaymentAddress addr2;
    BOOST_CHECK(DecodeSaplingAddress(encoded, addr2));
    BOOST_CHECK(addr == addr2);
}

BOOST_AUTO_TEST_CASE(sapling_address_invalid)
{
    sapling::SaplingPaymentAddress addr;

    // Empty string
    BOOST_CHECK(!DecodeSaplingAddress("", addr));

    // Wrong HRP (mainnet when we're on regtest)
    BOOST_CHECK(!DecodeSaplingAddress("ks1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqrp9kw8", addr));

    // Random garbage
    BOOST_CHECK(!DecodeSaplingAddress("notavalidaddress", addr));

    // Valid check
    BOOST_CHECK(!IsValidSaplingAddress("garbage"));
}

BOOST_AUTO_TEST_CASE(sapling_address_all_zeros)
{
    // Edge case: all-zero address
    sapling::SaplingPaymentAddress addr;
    addr.d.fill(0x00);
    addr.pk_d.fill(0x00);

    std::string encoded = EncodeSaplingAddress(addr);
    BOOST_CHECK(!encoded.empty());

    sapling::SaplingPaymentAddress addr2;
    BOOST_CHECK(DecodeSaplingAddress(encoded, addr2));
    BOOST_CHECK(addr == addr2);
}

BOOST_AUTO_TEST_CASE(sapling_address_all_ff)
{
    // Edge case: all-0xFF address
    sapling::SaplingPaymentAddress addr;
    addr.d.fill(0xFF);
    addr.pk_d.fill(0xFF);

    std::string encoded = EncodeSaplingAddress(addr);
    BOOST_CHECK(!encoded.empty());

    sapling::SaplingPaymentAddress addr2;
    BOOST_CHECK(DecodeSaplingAddress(encoded, addr2));
    BOOST_CHECK(addr == addr2);
}

// Sapling state tests

BOOST_AUTO_TEST_CASE(sapling_state_nullifier_tracking)
{
    // Test CSaplingState nullifier add/check/remove
    fs::path test_dir = m_args.GetDataDirNet() / "sapling_test";
    sapling::CSaplingState state(test_dir, 1 << 16);

    uint256 nf1, nf2, nf3;
    std::memset(nf1.begin(), 0xAA, 32);
    std::memset(nf2.begin(), 0xBB, 32);
    std::memset(nf3.begin(), 0xCC, 32);

    // Initially empty
    BOOST_CHECK(!state.HasNullifier(nf1));
    BOOST_CHECK(!state.HasNullifier(nf2));

    // Add nullifiers at height 100
    std::vector<uint256> nfs = {nf1, nf2};
    state.AddNullifiers(nfs, 100);

    BOOST_CHECK(state.HasNullifier(nf1));
    BOOST_CHECK(state.HasNullifier(nf2));
    BOOST_CHECK(!state.HasNullifier(nf3));

    // CheckNullifiers should detect known nullifiers
    uint256 bad_nf;
    BOOST_CHECK(!state.CheckNullifiers({nf1}, bad_nf)); // false = conflict
    BOOST_CHECK(bad_nf == nf1);
    BOOST_CHECK(!state.CheckNullifiers({nf2}, bad_nf));
    BOOST_CHECK(bad_nf == nf2);
    BOOST_CHECK(state.CheckNullifiers({nf3}, bad_nf));  // true = no conflict

    // Remove at correct height
    state.RemoveNullifiers(nfs, 100);
    BOOST_CHECK(!state.HasNullifier(nf1));
    BOOST_CHECK(!state.HasNullifier(nf2));
}

BOOST_AUTO_TEST_CASE(sapling_state_tree_root)
{
    fs::path test_dir = m_args.GetDataDirNet() / "sapling_tree_test";
    sapling::CSaplingState state(test_dir, 1 << 16);

    uint256 root1;
    root1.SetHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    uint256 root2;
    root2.SetHex("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");

    // Initially no tree root
    uint256 retrieved;
    BOOST_CHECK(!state.GetTreeRoot(100, retrieved));

    // Write tree root
    state.WriteTreeRoot(100, root1);
    BOOST_CHECK(state.GetTreeRoot(100, retrieved));
    BOOST_CHECK(retrieved == root1);

    // Different height
    state.WriteTreeRoot(200, root2);
    BOOST_CHECK(state.GetTreeRoot(200, retrieved));
    BOOST_CHECK(retrieved == root2);

    // Original still there
    BOOST_CHECK(state.GetTreeRoot(100, retrieved));
    BOOST_CHECK(retrieved == root1);

    // Erase
    state.EraseTreeRoot(100);
    BOOST_CHECK(!state.GetTreeRoot(100, retrieved));
    BOOST_CHECK(state.GetTreeRoot(200, retrieved)); // 200 still there
}

BOOST_AUTO_TEST_CASE(sapling_state_within_block_duplicate)
{
    // CheckNullifiers should detect duplicates within the same set
    fs::path test_dir = m_args.GetDataDirNet() / "sapling_dup_test";
    sapling::CSaplingState state(test_dir, 1 << 16);

    uint256 nf1;
    std::memset(nf1.begin(), 0xDD, 32);

    // Two identical nullifiers in one block, should be rejected
    uint256 bad_nf;
    BOOST_CHECK(!state.CheckNullifiers({nf1, nf1}, bad_nf));
    BOOST_CHECK(bad_nf == nf1);
}

BOOST_AUTO_TEST_SUITE(sapling_consensus_tests)

namespace {

/** Serialize a SaplingTxPayload into the vExtraPayload of a mutable tx. */
static void AttachSaplingPayload(CMutableTransaction& mtx, const SaplingTxPayload& payload)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;
    mtx.vExtraPayload.resize(ss.size());
    std::memcpy(mtx.vExtraPayload.data(), ss.data(), ss.size());
}

/** Build a Sapling tx that spends a single UTXO worth `inputAmount`, produces
 *  one transparent output worth `outputAmount`, and carries `valueBalance`. */
static CTransaction MakeSaplingSpendTx(CCoinsViewCache& coins,
                                       CAmount inputAmount,
                                       CAmount outputAmount,
                                       CAmount valueBalance)
{
    // Create a funding output and plant it in the UTXO set.
    uint256 fundingTxid;
    fundingTxid.SetHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    COutPoint fundingOutpoint(fundingTxid, 0);

    CTxOut fundingOut;
    fundingOut.nValue = inputAmount;
    fundingOut.scriptPubKey.resize(4);

    coins.AddCoin(fundingOutpoint, Coin(std::move(fundingOut), /*nHeight=*/1, /*fCoinBase=*/false), /*possible_overwrite=*/true);

    // Build the spending tx.
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::SPECIAL_VERSION;
    mtx.nType = TRANSACTION_SAPLING;

    mtx.vin.resize(1);
    mtx.vin[0].prevout = fundingOutpoint;

    if (outputAmount > 0) {
        mtx.vout.resize(1);
        mtx.vout[0].nValue = outputAmount;
        mtx.vout[0].scriptPubKey.resize(4);
    }

    SaplingTxPayload payload;
    payload.nVersion = SAPLING_PAYLOAD_VERSION;
    payload.valueBalance = valueBalance;
    payload.bindingSig.fill(0x00);

    AttachSaplingPayload(mtx, payload);

    return CTransaction(mtx);
}

} // anonymous namespace

BOOST_AUTO_TEST_CASE(checktxinputs_positive_value_balance)
{
    // Positive valueBalance: shielded value entering the transparent pool (z-to-t).
    // 1 KRGN transparent input + 0.5 KRGN from shielded = 1.5 KRGN effective input.
    // 1.4 KRGN transparent output => fee should be 0.1 KRGN.
    const CAmount inputAmount = 100000000;   // 1 KRGN
    const CAmount valueBalance = 50000000;   // +0.5 KRGN (shielded -> transparent)
    const CAmount outputAmount = 140000000;  // 1.4 KRGN
    const CAmount expectedFee = inputAmount + valueBalance - outputAmount; // 0.1 KRGN

    CCoinsView base;
    CCoinsViewCache coins(&base);

    CTransaction tx = MakeSaplingSpendTx(coins, inputAmount, outputAmount, valueBalance);

    TxValidationState state;
    CAmount txfee{-1};
    BOOST_CHECK(Consensus::CheckTxInputs(tx, state, coins, /*nSpendHeight=*/100, txfee));
    BOOST_CHECK_EQUAL(txfee, expectedFee);
}

BOOST_AUTO_TEST_CASE(checktxinputs_negative_value_balance)
{
    // Negative valueBalance: transparent value entering the shielded pool (t-to-z).
    // 2 KRGN transparent input, 0.5 KRGN shielded (valueBalance = -0.5).
    // Effective input = 2 - 0.5 = 1.5 KRGN. Output = 1.4 KRGN. Fee = 0.1 KRGN.
    const CAmount inputAmount = 200000000;    // 2 KRGN
    const CAmount valueBalance = -50000000;   // -0.5 KRGN (transparent -> shielded)
    const CAmount outputAmount = 140000000;   // 1.4 KRGN
    const CAmount expectedFee = inputAmount + valueBalance - outputAmount; // 0.1 KRGN

    CCoinsView base;
    CCoinsViewCache coins(&base);

    CTransaction tx = MakeSaplingSpendTx(coins, inputAmount, outputAmount, valueBalance);

    TxValidationState state;
    CAmount txfee{-1};
    BOOST_CHECK(Consensus::CheckTxInputs(tx, state, coins, /*nSpendHeight=*/100, txfee));
    BOOST_CHECK_EQUAL(txfee, expectedFee);
}

BOOST_AUTO_TEST_CASE(checktxinputs_insufficient_for_shielding)
{
    // Negative valueBalance exceeds transparent nValueIn, making effectiveValueIn negative.
    // 0.3 KRGN input with -0.5 KRGN valueBalance = -0.2 KRGN effective input.
    // CheckTxInputs must reject this.
    const CAmount inputAmount = 30000000;     // 0.3 KRGN
    const CAmount valueBalance = -50000000;   // -0.5 KRGN (transparent -> shielded)
    const CAmount outputAmount = 10000000;    // 0.1 KRGN (irrelevant, fails before this check)

    CCoinsView base;
    CCoinsViewCache coins(&base);

    CTransaction tx = MakeSaplingSpendTx(coins, inputAmount, outputAmount, valueBalance);

    TxValidationState state;
    CAmount txfee{-1};
    BOOST_CHECK(!Consensus::CheckTxInputs(tx, state, coins, /*nSpendHeight=*/100, txfee));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-inputvalues-outofrange");
}

BOOST_AUTO_TEST_SUITE_END() // sapling_consensus_tests

// Sighash commitment tests
// Verify ComputeSaplingSighash commits to every shielded field.
// Changing any field must produce a different hash.

namespace {

/** Build a reference transaction + payload for sighash tests. */
static std::pair<CTransaction, SaplingTxPayload> MakeSighashFixture()
{
    CMutableTransaction mtx;
    mtx.nVersion  = CTransaction::SPECIAL_VERSION;
    mtx.nType     = TRANSACTION_SAPLING;
    mtx.nLockTime = 0;

    // One transparent input and output so prevout/sequence/output hashes are non-trivial
    mtx.vin.resize(1);
    mtx.vin[0].prevout.hash = uint256S("abcdef");
    mtx.vin[0].prevout.n = 0;
    mtx.vout.resize(1);
    mtx.vout[0].nValue  = 1000000;
    mtx.vout[0].scriptPubKey.resize(4);

    SaplingTxPayload payload;
    payload.nVersion     = SAPLING_PAYLOAD_VERSION;
    payload.valueBalance = 50000;
    payload.bindingSig.fill(0x88);

    SaplingSpendDescription sd;
    sd.cv.fill(0x11); sd.anchor.fill(0x22); sd.nullifier.fill(0x33);
    sd.rk.fill(0x44); sd.zkproof.fill(0x55); sd.spendAuthSig.fill(0x66);
    payload.vSpendDescriptions.push_back(sd);

    SaplingOutputDescription od;
    od.cv.fill(0xAA); od.cmu.fill(0xBB); od.ephemeralKey.fill(0xCC);
    od.encCiphertext.fill(0xDD); od.outCiphertext.fill(0xEE); od.zkproof.fill(0xFF);
    payload.vOutputDescriptions.push_back(od);

    return {CTransaction(mtx), payload};
}

} // anonymous namespace

BOOST_AUTO_TEST_CASE(sighash_commits_to_spend_cv)
{
    auto [tx, payload] = MakeSighashFixture();
    uint256 base = sapling::ComputeSaplingSighash(tx, payload);

    SaplingTxPayload modified = payload;
    modified.vSpendDescriptions[0].cv.fill(0x99);
    BOOST_CHECK(sapling::ComputeSaplingSighash(tx, modified) != base);
}

BOOST_AUTO_TEST_CASE(sighash_commits_to_spend_anchor)
{
    auto [tx, payload] = MakeSighashFixture();
    uint256 base = sapling::ComputeSaplingSighash(tx, payload);

    SaplingTxPayload modified = payload;
    modified.vSpendDescriptions[0].anchor.fill(0x99);
    BOOST_CHECK(sapling::ComputeSaplingSighash(tx, modified) != base);
}

BOOST_AUTO_TEST_CASE(sighash_commits_to_spend_nullifier)
{
    auto [tx, payload] = MakeSighashFixture();
    uint256 base = sapling::ComputeSaplingSighash(tx, payload);

    SaplingTxPayload modified = payload;
    modified.vSpendDescriptions[0].nullifier.fill(0x99);
    BOOST_CHECK(sapling::ComputeSaplingSighash(tx, modified) != base);
}

BOOST_AUTO_TEST_CASE(sighash_commits_to_spend_rk)
{
    auto [tx, payload] = MakeSighashFixture();
    uint256 base = sapling::ComputeSaplingSighash(tx, payload);

    SaplingTxPayload modified = payload;
    modified.vSpendDescriptions[0].rk.fill(0x99);
    BOOST_CHECK(sapling::ComputeSaplingSighash(tx, modified) != base);
}

BOOST_AUTO_TEST_CASE(sighash_commits_to_spend_zkproof)
{
    auto [tx, payload] = MakeSighashFixture();
    uint256 base = sapling::ComputeSaplingSighash(tx, payload);

    SaplingTxPayload modified = payload;
    modified.vSpendDescriptions[0].zkproof.fill(0x99);
    BOOST_CHECK(sapling::ComputeSaplingSighash(tx, modified) != base);
}

BOOST_AUTO_TEST_CASE(sighash_excludes_spend_auth_sig)
{
    // spendAuthSig is the value BEING signed, it must NOT affect the sighash
    auto [tx, payload] = MakeSighashFixture();
    uint256 base = sapling::ComputeSaplingSighash(tx, payload);

    SaplingTxPayload modified = payload;
    modified.vSpendDescriptions[0].spendAuthSig.fill(0x99);
    BOOST_CHECK(sapling::ComputeSaplingSighash(tx, modified) == base);
}

BOOST_AUTO_TEST_CASE(sighash_commits_to_output_cv)
{
    auto [tx, payload] = MakeSighashFixture();
    uint256 base = sapling::ComputeSaplingSighash(tx, payload);

    SaplingTxPayload modified = payload;
    modified.vOutputDescriptions[0].cv.fill(0x99);
    BOOST_CHECK(sapling::ComputeSaplingSighash(tx, modified) != base);
}

BOOST_AUTO_TEST_CASE(sighash_commits_to_output_cmu)
{
    auto [tx, payload] = MakeSighashFixture();
    uint256 base = sapling::ComputeSaplingSighash(tx, payload);

    SaplingTxPayload modified = payload;
    modified.vOutputDescriptions[0].cmu.fill(0x99);
    BOOST_CHECK(sapling::ComputeSaplingSighash(tx, modified) != base);
}

BOOST_AUTO_TEST_CASE(sighash_commits_to_output_ephemeral_key)
{
    auto [tx, payload] = MakeSighashFixture();
    uint256 base = sapling::ComputeSaplingSighash(tx, payload);

    SaplingTxPayload modified = payload;
    modified.vOutputDescriptions[0].ephemeralKey.fill(0x99);
    BOOST_CHECK(sapling::ComputeSaplingSighash(tx, modified) != base);
}

BOOST_AUTO_TEST_CASE(sighash_commits_to_output_enc_ciphertext)
{
    auto [tx, payload] = MakeSighashFixture();
    uint256 base = sapling::ComputeSaplingSighash(tx, payload);

    SaplingTxPayload modified = payload;
    modified.vOutputDescriptions[0].encCiphertext.fill(0x99);
    BOOST_CHECK(sapling::ComputeSaplingSighash(tx, modified) != base);
}

BOOST_AUTO_TEST_CASE(sighash_commits_to_output_out_ciphertext)
{
    auto [tx, payload] = MakeSighashFixture();
    uint256 base = sapling::ComputeSaplingSighash(tx, payload);

    SaplingTxPayload modified = payload;
    modified.vOutputDescriptions[0].outCiphertext.fill(0x99);
    BOOST_CHECK(sapling::ComputeSaplingSighash(tx, modified) != base);
}

BOOST_AUTO_TEST_CASE(sighash_commits_to_output_zkproof)
{
    auto [tx, payload] = MakeSighashFixture();
    uint256 base = sapling::ComputeSaplingSighash(tx, payload);

    SaplingTxPayload modified = payload;
    modified.vOutputDescriptions[0].zkproof.fill(0x99);
    BOOST_CHECK(sapling::ComputeSaplingSighash(tx, modified) != base);
}

BOOST_AUTO_TEST_CASE(sighash_commits_to_value_balance)
{
    auto [tx, payload] = MakeSighashFixture();
    uint256 base = sapling::ComputeSaplingSighash(tx, payload);

    SaplingTxPayload modified = payload;
    modified.valueBalance = 99999;
    BOOST_CHECK(sapling::ComputeSaplingSighash(tx, modified) != base);
}

BOOST_AUTO_TEST_CASE(sighash_commits_to_payload_version)
{
    auto [tx, payload] = MakeSighashFixture();
    uint256 base = sapling::ComputeSaplingSighash(tx, payload);

    SaplingTxPayload modified = payload;
    modified.nVersion = 99;
    BOOST_CHECK(sapling::ComputeSaplingSighash(tx, modified) != base);
}

BOOST_AUTO_TEST_CASE(sighash_excludes_binding_sig)
{
    // bindingSig is verified against the sighash, it must NOT affect it
    auto [tx, payload] = MakeSighashFixture();
    uint256 base = sapling::ComputeSaplingSighash(tx, payload);

    SaplingTxPayload modified = payload;
    modified.bindingSig.fill(0x99);
    BOOST_CHECK(sapling::ComputeSaplingSighash(tx, modified) == base);
}

BOOST_AUTO_TEST_CASE(sighash_commits_to_spend_count)
{
    // Adding a spend must change the hash
    auto [tx, payload] = MakeSighashFixture();
    uint256 base = sapling::ComputeSaplingSighash(tx, payload);

    SaplingTxPayload modified = payload;
    SaplingSpendDescription sd2;
    sd2.cv.fill(0x77); sd2.anchor.fill(0x78); sd2.nullifier.fill(0x79);
    sd2.rk.fill(0x7A); sd2.zkproof.fill(0x7B); sd2.spendAuthSig.fill(0x7C);
    modified.vSpendDescriptions.push_back(sd2);
    BOOST_CHECK(sapling::ComputeSaplingSighash(tx, modified) != base);
}

BOOST_AUTO_TEST_CASE(sighash_commits_to_output_count)
{
    // Adding an output must change the hash
    auto [tx, payload] = MakeSighashFixture();
    uint256 base = sapling::ComputeSaplingSighash(tx, payload);

    SaplingTxPayload modified = payload;
    SaplingOutputDescription od2;
    od2.cv.fill(0x77); od2.cmu.fill(0x78); od2.ephemeralKey.fill(0x79);
    od2.encCiphertext.fill(0x7A); od2.outCiphertext.fill(0x7B); od2.zkproof.fill(0x7C);
    modified.vOutputDescriptions.push_back(od2);
    BOOST_CHECK(sapling::ComputeSaplingSighash(tx, modified) != base);
}

BOOST_AUTO_TEST_CASE(sighash_deterministic)
{
    // Same inputs must produce the same hash
    auto [tx, payload] = MakeSighashFixture();
    uint256 h1 = sapling::ComputeSaplingSighash(tx, payload);
    uint256 h2 = sapling::ComputeSaplingSighash(tx, payload);
    BOOST_CHECK(h1 == h2);
}

// Merkle tree tests

BOOST_AUTO_TEST_SUITE(merkle_tree_tests)

BOOST_AUTO_TEST_CASE(frontier_empty_root)
{
    // An empty frontier should produce the empty-tree root (all-zeros path).
    auto frontier = sapling::tree::new_sapling_frontier();
    auto root = sapling::tree::frontier_root(*frontier);
    BOOST_CHECK_EQUAL(sapling::tree::frontier_size(*frontier), 0u);
    // Empty tree root should be the Sapling "uncommitted" root (not all zeros).
    // Just verify it's deterministic: two empty frontiers produce the same root.
    auto frontier2 = sapling::tree::new_sapling_frontier();
    auto root2 = sapling::tree::frontier_root(*frontier2);
    BOOST_CHECK(root == root2);
}

BOOST_AUTO_TEST_CASE(frontier_append_changes_root)
{
    auto frontier = sapling::tree::new_sapling_frontier();
    auto emptyRoot = sapling::tree::frontier_root(*frontier);

    // Generate a valid non-trivial note commitment using Pedersen hash.
    // merkle_hash(0, uncommitted, uncommitted) produces a valid, non-empty Node.
    auto uncommitted = sapling::spec::tree_uncommitted();
    auto testCmu = sapling::spec::merkle_hash(0, uncommitted, uncommitted);

    sapling::tree::frontier_append(*frontier, testCmu);
    BOOST_CHECK_EQUAL(sapling::tree::frontier_size(*frontier), 1u);

    auto oneRoot = sapling::tree::frontier_root(*frontier);
    // Root should change after appending a non-empty leaf.
    BOOST_CHECK(oneRoot != emptyRoot);

    // Append another leaf, root should change again.
    sapling::tree::frontier_append(*frontier, testCmu);
    BOOST_CHECK_EQUAL(sapling::tree::frontier_size(*frontier), 2u);
    auto twoRoot = sapling::tree::frontier_root(*frontier);
    BOOST_CHECK(twoRoot != oneRoot);
}

BOOST_AUTO_TEST_CASE(frontier_serialize_roundtrip)
{
    auto frontier = sapling::tree::new_sapling_frontier();
    auto uncommitted = sapling::spec::tree_uncommitted();
    auto testCmu = sapling::spec::merkle_hash(0, uncommitted, uncommitted);

    // Append some leaves
    for (int i = 0; i < 5; i++) {
        sapling::tree::frontier_append(*frontier, testCmu);
    }

    auto root_before = sapling::tree::frontier_root(*frontier);
    auto size_before = sapling::tree::frontier_size(*frontier);

    // Serialize
    auto data = sapling::tree::frontier_serialize(*frontier);
    BOOST_CHECK(!data.empty());

    // Deserialize
    rust::Slice<const uint8_t> slice(data.data(), data.size());
    auto frontier2 = sapling::tree::frontier_deserialize(slice);

    auto root_after = sapling::tree::frontier_root(*frontier2);
    auto size_after = sapling::tree::frontier_size(*frontier2);

    BOOST_CHECK(root_before == root_after);
    BOOST_CHECK_EQUAL(size_before, size_after);
}

BOOST_AUTO_TEST_CASE(witness_path_roundtrip)
{
    auto frontier = sapling::tree::new_sapling_frontier();
    auto uncommitted = sapling::spec::tree_uncommitted();
    auto testCmu = sapling::spec::merkle_hash(0, uncommitted, uncommitted);

    // Append a leaf, this is the note we'll witness.
    sapling::tree::frontier_append(*frontier, testCmu);

    // Create witness for the note we just appended.
    auto witness = sapling::tree::witness_from_frontier(*frontier);
    BOOST_CHECK_EQUAL(sapling::tree::witness_position(*witness), 0u);

    // The witness root should match the frontier root.
    auto frontierRoot = sapling::tree::frontier_root(*frontier);
    auto witnessRoot = sapling::tree::witness_root(*witness);
    BOOST_CHECK(frontierRoot == witnessRoot);

    // Append more leaves to both frontier and witness.
    for (int i = 0; i < 10; i++) {
        sapling::tree::frontier_append(*frontier, testCmu);
        sapling::tree::witness_append(*witness, testCmu);
    }

    // Roots should still match.
    frontierRoot = sapling::tree::frontier_root(*frontier);
    witnessRoot = sapling::tree::witness_root(*witness);
    BOOST_CHECK(frontierRoot == witnessRoot);

    // Get the 1065-byte Merkle path.
    auto path = sapling::tree::witness_path(*witness);
    // First byte should be depth = 32.
    BOOST_CHECK_EQUAL(path[0], 32);
    // Last 8 bytes are position (0) as u64 LE.
    uint64_t pos = 0;
    std::memcpy(&pos, &path[1057], 8);
    BOOST_CHECK_EQUAL(pos, 0u);
}

BOOST_AUTO_TEST_CASE(witness_serialize_roundtrip)
{
    auto frontier = sapling::tree::new_sapling_frontier();
    auto uncommitted = sapling::spec::tree_uncommitted();
    auto testCmu = sapling::spec::merkle_hash(0, uncommitted, uncommitted);

    sapling::tree::frontier_append(*frontier, testCmu);
    auto witness = sapling::tree::witness_from_frontier(*frontier);

    // Append a few more leaves to the witness
    for (int i = 0; i < 3; i++) {
        sapling::tree::frontier_append(*frontier, testCmu);
        sapling::tree::witness_append(*witness, testCmu);
    }

    auto root_before = sapling::tree::witness_root(*witness);
    auto pos_before = sapling::tree::witness_position(*witness);

    // Serialize
    auto data = sapling::tree::witness_serialize(*witness);
    BOOST_CHECK(!data.empty());

    // Deserialize
    rust::Slice<const uint8_t> slice(data.data(), data.size());
    auto witness2 = sapling::tree::witness_deserialize(slice);

    auto root_after = sapling::tree::witness_root(*witness2);
    auto pos_after = sapling::tree::witness_position(*witness2);

    BOOST_CHECK(root_before == root_after);
    BOOST_CHECK_EQUAL(pos_before, pos_after);

    // Paths should be identical.
    auto path1 = sapling::tree::witness_path(*witness);
    auto path2 = sapling::tree::witness_path(*witness2);
    BOOST_CHECK(path1 == path2);
}

BOOST_AUTO_TEST_CASE(multiple_witnesses_independent)
{
    auto frontier = sapling::tree::new_sapling_frontier();
    auto uncommitted = sapling::spec::tree_uncommitted();
    auto testCmu = sapling::spec::merkle_hash(0, uncommitted, uncommitted);

    // Append first leaf and create witness for it.
    sapling::tree::frontier_append(*frontier, testCmu);
    auto wit0 = sapling::tree::witness_from_frontier(*frontier);

    // Append second leaf and create witness for it.
    sapling::tree::frontier_append(*frontier, testCmu);
    sapling::tree::witness_append(*wit0, testCmu);
    auto wit1 = sapling::tree::witness_from_frontier(*frontier);

    // Witnesses are at different positions.
    BOOST_CHECK_EQUAL(sapling::tree::witness_position(*wit0), 0u);
    BOOST_CHECK_EQUAL(sapling::tree::witness_position(*wit1), 1u);

    // Both should produce the same root.
    auto root0 = sapling::tree::witness_root(*wit0);
    auto root1 = sapling::tree::witness_root(*wit1);
    BOOST_CHECK(root0 == root1);
}

BOOST_AUTO_TEST_SUITE_END() // merkle_tree_tests

// Fee calculation tests

BOOST_AUTO_TEST_CASE(sapling_fee_calculation)
{
    // BASE=10000, PER_SPEND=5000, PER_OUTPUT=5000
    BOOST_CHECK_EQUAL(CalculateSaplingFee(0, 0), 10000);   // base only
    BOOST_CHECK_EQUAL(CalculateSaplingFee(0, 1), 15000);   // base + 1 output
    BOOST_CHECK_EQUAL(CalculateSaplingFee(1, 1), 20000);   // base + 1 spend + 1 output
    BOOST_CHECK_EQUAL(CalculateSaplingFee(1, 2), 25000);   // base + 1 spend + 2 outputs
    BOOST_CHECK_EQUAL(CalculateSaplingFee(2, 3), 35000);   // base + 2 spends + 3 outputs
}

// Compact block relay roundtrip test

BOOST_AUTO_TEST_CASE(sapling_compact_block_roundtrip)
{
    // Build a Sapling tx and verify compact block short IDs work
    CMutableTransaction mtx;
    mtx.nVersion = 3;
    mtx.nType = TRANSACTION_SAPLING;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.hash = uint256S("abcd");
    mtx.vin[0].prevout.n = 0;
    mtx.vin[0].scriptSig.resize(4);

    // Build a Sapling payload with 1 spend + 1 output
    SaplingTxPayload payload;
    payload.nVersion = SAPLING_PAYLOAD_VERSION;
    payload.valueBalance = 100000;
    payload.bindingSig.fill(0x88);

    SaplingSpendDescription sd;
    sd.cv.fill(0x11); sd.anchor.fill(0x22); sd.nullifier.fill(0x33);
    sd.rk.fill(0x44); sd.zkproof.fill(0x55); sd.spendAuthSig.fill(0x66);
    payload.vSpendDescriptions.push_back(sd);

    SaplingOutputDescription od;
    od.cv.fill(0xAA); od.cmu.fill(0xBB); od.ephemeralKey.fill(0xCC);
    od.encCiphertext.fill(0xDD); od.outCiphertext.fill(0xEE); od.zkproof.fill(0xFF);
    payload.vOutputDescriptions.push_back(od);

    CDataStream payloadStream(SER_NETWORK, PROTOCOL_VERSION);
    payloadStream << payload;
    mtx.vExtraPayload.resize(payloadStream.size());
    std::memcpy(mtx.vExtraPayload.data(), payloadStream.data(), payloadStream.size());

    CTransactionRef saplingTx = MakeTransactionRef(std::move(mtx));
    uint256 origHash = saplingTx->GetHash();

    // Build a block containing a coinbase + the Sapling tx
    CBlock block;
    block.nVersion = 42;
    block.hashPrevBlock = uint256S("1234");
    block.nBits = 0x207fffff;

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].scriptSig.resize(10);
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = 25 * COIN;
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
    block.vtx.push_back(saplingTx);

    bool mutated;
    block.hashMerkleRoot = BlockMerkleRoot(block, &mutated);
    BOOST_CHECK(!mutated);

    // Construct compact block representation
    CBlockHeaderAndShortTxIDs shortIDs{block};
    BOOST_CHECK_EQUAL(shortIDs.BlockTxCount(), 2U);

    // Short ID for the Sapling tx should be non-zero (computed from tx hash)
    uint64_t sid = shortIDs.GetShortID(origHash);
    BOOST_CHECK(sid != 0);

    // Serialize and deserialize the compact block
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << shortIDs;

    CBlockHeaderAndShortTxIDs shortIDs2;
    stream >> shortIDs2;

    BOOST_CHECK_EQUAL(shortIDs2.BlockTxCount(), 2U);
    // The same short ID should be reproducible after deserialization
    BOOST_CHECK_EQUAL(shortIDs2.GetShortID(origHash), sid);

    // Verify the tx hash is preserved through full block serialization roundtrip
    CDataStream blockStream(SER_NETWORK, PROTOCOL_VERSION);
    blockStream << block;

    CBlock block2;
    blockStream >> block2;

    BOOST_CHECK_EQUAL(block2.vtx.size(), 2U);
    BOOST_CHECK(block2.vtx[1]->GetHash() == origHash);
    BOOST_CHECK_EQUAL(block2.vtx[1]->nType, TRANSACTION_SAPLING);
}

BOOST_AUTO_TEST_SUITE_END() // sapling_tests
