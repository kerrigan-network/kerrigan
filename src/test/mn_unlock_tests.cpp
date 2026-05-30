// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Unit tests for the unlockmasternode RPC building blocks (v1.2.5).
//
// The RPC itself (rpc/masternode.cpp::unlockmasternode) needs a wallet, a live
// chainstate, and the broadcast pipeline; we don't stand up that fixture here.
// Instead we test the pieces unlockmasternode composes:
//
//   1. PlanXBuildClaimBackMarker + PlanXParseClaimBackMarker round-trip.
//      The marker MUST be IsUnspendable() so the only-to-7b rule ignores it,
//      and the parsed payload MUST recover the operator pubkey hash + nonce
//      byte-for-byte. Malformed candidates MUST parse to std::nullopt.
//
//   2. A hand-built compromised-coin unlock tx (recovery output + OP_RETURN
//      claim marker) MUST be accepted by PlanXOnlyToRecoveryAllowed when the
//      gate is armed.
//
//   3. A hand-built non-compromised collateral unlock tx (paying an arbitrary
//      destination) MUST NOT be flagged by PlanXOnlyToRecoveryAllowed (case 1
//      and case 3 sanity: a fresh `protx register` collateral is not in the
//      compromised set, so it is not false-flagged).
//
// These exercise the SAME pure predicate the mempool / ConnectBlock sites call,
// so passing here means the RPC's constructed transactions will pass consensus
// (modulo signature + fee bound, which are RPC-side concerns).

#include <policy/planx_rollback.h>

#include <coins.h>
#include <consensus/amount.h>           // CAmount, COIN
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cstdint>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

constexpr CAmount kRegularCollateral = 10000 * COIN;

CScript ScriptOf(unsigned char b)
{
    std::vector<unsigned char> h160(20, b);
    return CScript() << OP_DUP << OP_HASH160 << h160 << OP_EQUALVERIFY << OP_CHECKSIG;
}

const CScript& RecoveryScript()
{
    static const CScript s = PlanXRecoveryScript();
    return s;
}

const CScript& CompromisedScript()
{
    static const CScript s = ScriptOf(0xC0);
    return s;
}

const CScript& CleanCollateralScript()
{
    static const CScript s = ScriptOf(0x77);
    return s;
}

uint256 TxId(unsigned id)
{
    uint256 out;
    out.begin()[0] = static_cast<unsigned char>(id & 0xFF);
    out.begin()[1] = static_cast<unsigned char>((id >> 8) & 0xFF);
    return out;
}

COutPoint AddValuedCoin(CCoinsViewCache& view, const uint256& txid, uint32_t n,
                        const CScript& spk, CAmount value)
{
    COutPoint op(txid, n);
    CTxOut txout(value, spk);
    view.AddCoin(op, Coin(std::move(txout), /*nHeight=*/1, /*fCoinBase=*/false),
                 /*possible_overwrite=*/false);
    return op;
}

uint160 PubkeyHashOf(unsigned char b)
{
    std::vector<unsigned char> bytes(planx::RECOVERY_CLAIM_PUBKEYHASH_LEN, b);
    uint160 h;
    std::copy(bytes.begin(), bytes.end(), h.begin());
    return h;
}

std::vector<unsigned char> NonceOf(unsigned char b)
{
    return std::vector<unsigned char>(planx::RECOVERY_CLAIM_NONCE_LEN, b);
}

// RAII: seed the compromised set with one script, restore on exit.
struct ArmGuard {
    explicit ArmGuard(const CScript& s)
    {
        g_compromised_recovery_set = CompromisedRecoverySet();
        g_compromised_recovery_set.AddScript(s);
    }
    ~ArmGuard() { g_compromised_recovery_set = CompromisedRecoverySet(); }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(mn_unlock_tests, BasicTestingSetup)

// (1a) Claim-back marker round-trip: build a marker, parse it back, recover
//      the pubkey hash + nonce bit-for-bit. Marker MUST be IsUnspendable so
//      the only-to-7b destination loop ignores it.
BOOST_AUTO_TEST_CASE(claim_marker_roundtrip)
{
    const uint160 pkh = PubkeyHashOf(0xAB);
    const std::vector<unsigned char> nonce = NonceOf(0x42);
    const CScript marker = PlanXBuildClaimBackMarker(pkh, nonce);

    BOOST_REQUIRE(!marker.empty());
    BOOST_CHECK(marker.IsUnspendable());

    auto parsed = PlanXParseClaimBackMarker(marker);
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK(parsed->pubkey_hash == pkh);
    BOOST_CHECK(parsed->nonce == nonce);
}

// (1b) Magic appears in transmission order K,R,C,P at the first 4 bytes of the
//      pushed payload, so an off-chain parser scanning raw script bytes can
//      identify our marker by string match.
BOOST_AUTO_TEST_CASE(claim_marker_magic_byte_order)
{
    const CScript marker = PlanXBuildClaimBackMarker(PubkeyHashOf(0x00), NonceOf(0x00));
    // CScript serialization: OP_RETURN (0x6a) | push opcode (0x20 for 32) |
    // payload[32]. First 4 payload bytes must be 'K','R','C','P'.
    BOOST_REQUIRE(marker.size() >= 6);
    BOOST_CHECK_EQUAL(marker[0], OP_RETURN);
    BOOST_CHECK_EQUAL(marker[1], static_cast<unsigned char>(planx::RECOVERY_CLAIM_PAYLOAD_LEN));
    BOOST_CHECK_EQUAL(marker[2], 'K');
    BOOST_CHECK_EQUAL(marker[3], 'R');
    BOOST_CHECK_EQUAL(marker[4], 'C');
    BOOST_CHECK_EQUAL(marker[5], 'P');
}

// (1c) Wrong nonce length -> empty script (defensive). The RPC always passes 8
//      bytes; this exercises the guard.
BOOST_AUTO_TEST_CASE(claim_marker_wrong_nonce_len)
{
    BOOST_CHECK(PlanXBuildClaimBackMarker(PubkeyHashOf(0x01), std::vector<unsigned char>(7, 0)).empty());
    BOOST_CHECK(PlanXBuildClaimBackMarker(PubkeyHashOf(0x01), std::vector<unsigned char>(9, 0)).empty());
    BOOST_CHECK(PlanXBuildClaimBackMarker(PubkeyHashOf(0x01), {}).empty());
}

// (1d) Parsing rejects non-OP_RETURN, wrong-length payloads, wrong magic, and
//      OP_RETURN with trailing bytes.
BOOST_AUTO_TEST_CASE(claim_marker_parse_rejections)
{
    // Plain OP_RETURN with no payload.
    BOOST_CHECK(!PlanXParseClaimBackMarker(CScript() << OP_RETURN).has_value());
    // P2PKH-shaped (no OP_RETURN at all).
    BOOST_CHECK(!PlanXParseClaimBackMarker(ScriptOf(0x11)).has_value());
    // Correct length, wrong magic.
    {
        std::vector<unsigned char> bad(planx::RECOVERY_CLAIM_PAYLOAD_LEN, 0);
        bad[0] = 'X'; bad[1] = 'X'; bad[2] = 'X'; bad[3] = 'X';
        const CScript s = CScript() << OP_RETURN << bad;
        BOOST_CHECK(!PlanXParseClaimBackMarker(s).has_value());
    }
    // Correct magic, wrong length (too short).
    {
        std::vector<unsigned char> bad(16, 0);
        bad[0] = 'K'; bad[1] = 'R'; bad[2] = 'C'; bad[3] = 'P';
        const CScript s = CScript() << OP_RETURN << bad;
        BOOST_CHECK(!PlanXParseClaimBackMarker(s).has_value());
    }
    // OP_RETURN with marker followed by extra bytes (not what we built).
    {
        const CScript good = PlanXBuildClaimBackMarker(PubkeyHashOf(0x55), NonceOf(0x77));
        CScript with_tail = good;
        with_tail << OP_TRUE;
        BOOST_CHECK(!PlanXParseClaimBackMarker(with_tail).has_value());
    }
}

// (2) Case 2 shape: a compromised-coin spend with output[0] = recovery, output[1]
//     = claim-back OP_RETURN marker. MUST be accepted by the only-to-7b rule.
//     We use a value slightly under (collateral - MAX_RECOVERY_FEE) to also
//     exercise the fee-bound branch (3c).
BOOST_AUTO_TEST_CASE(case2_unlock_tx_accepted_by_predicate)
{
    ArmGuard arm(CompromisedScript());
    BOOST_REQUIRE(!RecoveryScript().empty()); // recovery finalized in this build

    CCoinsView base;
    CCoinsViewCache view(&base);
    const COutPoint op = AddValuedCoin(view, TxId(10), 0,
                                       CompromisedScript(), kRegularCollateral);

    // Mirror what unlockmasternode constructs in case 2.
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    CTxIn in;
    in.prevout = op;
    in.nSequence = CTxIn::MAX_SEQUENCE_NONFINAL;
    mtx.vin.push_back(in);
    const CAmount fee = 10000; // matches UNLOCK_FIXED_FEE
    mtx.vout.emplace_back(kRegularCollateral - fee, RecoveryScript());
    mtx.vout.emplace_back(/*nValue=*/0,
                          PlanXBuildClaimBackMarker(PubkeyHashOf(0xCC), NonceOf(0x11)));

    const char* reason = nullptr;
    BOOST_CHECK(PlanXOnlyToRecoveryAllowed(CTransaction(mtx), view, &reason,
                                           /*nHeight=*/planx::RECOVERY_V2_ACTIVATION_HEIGHT + 1));
    BOOST_CHECK(reason == nullptr);
}

// (2b) If the operator omits the recovery output (e.g. a buggy caller), the
//      predicate MUST reject -- the marker alone is unspendable and pays
//      nothing to recovery.
BOOST_AUTO_TEST_CASE(case2_marker_only_rejected)
{
    ArmGuard arm(CompromisedScript());

    CCoinsView base;
    CCoinsViewCache view(&base);
    const COutPoint op = AddValuedCoin(view, TxId(11), 0,
                                       CompromisedScript(), kRegularCollateral);

    CMutableTransaction mtx;
    mtx.vin.emplace_back();
    mtx.vin.back().prevout = op;
    mtx.vout.emplace_back(/*nValue=*/0,
                          PlanXBuildClaimBackMarker(PubkeyHashOf(0xDD), NonceOf(0x22)));

    const char* reason = nullptr;
    BOOST_CHECK(!PlanXOnlyToRecoveryAllowed(CTransaction(mtx), view, &reason,
                                            /*nHeight=*/planx::RECOVERY_V2_ACTIVATION_HEIGHT + 1));
    BOOST_REQUIRE(reason != nullptr);
    BOOST_CHECK_EQUAL(std::string(reason), "planx-recovery-fee-too-high");
}

// (3) Case 1 shape: non-compromised collateral, spend to an arbitrary
//     destination. The compromised set is armed with a DIFFERENT script, so
//     the predicate must short-circuit on "tx does not touch the set" and
//     ALLOW the spend regardless of where the outputs go.
BOOST_AUTO_TEST_CASE(case1_non_compromised_collateral_allowed)
{
    ArmGuard arm(CompromisedScript()); // arms with 0xC0, NOT the clean script

    CCoinsView base;
    CCoinsViewCache view(&base);
    const COutPoint op = AddValuedCoin(view, TxId(20), 0,
                                       CleanCollateralScript(), kRegularCollateral);

    // Pays to some arbitrary clean address (operator's chosen destination).
    CMutableTransaction mtx;
    mtx.vin.emplace_back();
    mtx.vin.back().prevout = op;
    mtx.vout.emplace_back(kRegularCollateral - 10000, ScriptOf(0xAB));

    const char* reason = nullptr;
    BOOST_CHECK(PlanXOnlyToRecoveryAllowed(CTransaction(mtx), view, &reason,
                                           /*nHeight=*/planx::RECOVERY_V2_ACTIVATION_HEIGHT + 1));
    BOOST_CHECK(reason == nullptr);
}

// (3b) Case 3 sanity (fresh `protx register` collateral): a freshly-funded
//      collateral cannot be in the compromised set (the set is closed at build
//      time on mainnet, empty everywhere else). Modelled here by arming the set
//      with a DIFFERENT script and asserting the new collateral spend is not
//      flagged. This is the property the spec asks us to verify; if it ever
//      fails the registration RPC is broken under Plan-X.
BOOST_AUTO_TEST_CASE(case3_fresh_registration_not_false_flagged)
{
    ArmGuard arm(CompromisedScript());

    CCoinsView base;
    CCoinsViewCache view(&base);
    // Fresh script the operator just funded for `protx register`.
    const CScript fresh_register_script = ScriptOf(0x33);
    const COutPoint op = AddValuedCoin(view, TxId(30), 0,
                                       fresh_register_script, kRegularCollateral);

    // Mirror the shape a protx register fund tx ends up with: the collateral
    // output sits at vout[0] of a tx that may have other outputs (payout etc).
    CMutableTransaction mtx;
    mtx.vin.emplace_back();
    mtx.vin.back().prevout = op;
    mtx.vout.emplace_back(kRegularCollateral, fresh_register_script); // collateral
    mtx.vout.emplace_back(/*nValue=*/0, CScript() << OP_RETURN);      // ProTx marker

    const char* reason = nullptr;
    BOOST_CHECK(PlanXOnlyToRecoveryAllowed(CTransaction(mtx), view, &reason,
                                           /*nHeight=*/planx::RECOVERY_V2_ACTIVATION_HEIGHT + 1));
    BOOST_CHECK(reason == nullptr);
}

BOOST_AUTO_TEST_SUITE_END()
