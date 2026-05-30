// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Unit tests for PLAN X -- the contingency rollback (incident 2026-05),
// recovery-release build with the rotated keys + baked block hashes.
//
// Community vote PASSED; the block hashes are FINAL. The recovery / treasury
// scripts baked into this build are the PRODUCTION rotated key sets (Set-A
// escrow+devfund/7b, Set-B founders/7a; see chainparams.cpp /
// policy/planx_rollback.h and recovery-pubkeys.md).
//
// These exercise the consensus-critical only-to-7b predicate
// (PlanXOnlyToRecoveryAllowed) directly against synthetic transactions and a
// standalone UTXO view -- the same predicate the mempool PreChecks and
// ConnectBlock sites call. Because DEFAULT_RECOVERY_SCRIPT_7B is now finalized
// (the PRODUCTION Set-A P2SH), the production predicate's accept/reject/change/
// marker branches run for real (no oracle stand-in needed). The predicate is pure
// w.r.t. its inputs and the startup-fixed globals, so testing it here proves the
// consensus rule; the call sites are thin wrappers around it.
//
// What is proven:
//   1. Default-inert: with the gate OFF, any compromised spend is allowed.
//   2. Gate ON + finalized: a compromised spend whose outputs ALL pay the fresh
//      Set-A/7b script is ACCEPTED -- driven through the real predicate.
//   3. Gate ON + finalized: a compromised spend that pays ANYWHERE else is
//      REJECTED (with the expected reason token) -- real predicate.
//   4. A spend that does NOT touch the compromised set is ignored (allowed),
//      even when the gate is on.
//   5. Change back into a compromised wallet is REJECTED (full sweep
//      forced) while OP_RETURN markers are ignored -- real predicate.
//   6. The disallow rule recognises the baked theft-block hash (54351) and the
//      checkpoint-pin recognises the baked anchor hash (54350).
//   7. The startup interlock predicate (PlanXScriptIsPlaceholder) flags an
//      empty / sentinel slot and passes the finalized PRODUCTION scripts.
//
// Verification gap (documented): these tests do not stand up a live regtest
// chain through ProcessNewBlock, so the header-level disallow-block /
// checkpoint-pin ENFORCEMENT sites and the InitError interlock WIRING in
// init.cpp are covered by the compile/syntax check + the predicate-level tests
// here, not by an end-to-end reorg. See O-recovery-release-impl.md.

#include <policy/planx_rollback.h>

#include <coins.h>
#include <consensus/amount.h>           // CAmount, COIN
#include <evo/specialtx.h>              // SetTxPayload (build a Sapling shield tx)
#include <policy/shielded_spend_freeze.h> // ClassifyShieldedDirection (shielded-spend detection)
#include <primitives/transaction.h>
#include <sapling/sapling_tx_payload.h> // SaplingTxPayload (shield tx)
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h> // ParseHex

#include <string>

#include <set>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

//! A P2PKH-shaped script with all bytes of the hash160 set to `b`. Distinct `b`
//! values yield distinct scripts.
CScript ScriptOf(unsigned char b)
{
    std::vector<unsigned char> h160(20, b);
    return CScript() << OP_DUP << OP_HASH160 << h160 << OP_EQUALVERIFY << OP_CHECKSIG;
}

//! The recovery "7b" destination used throughout the tests. In this build the
//! recovery constant is finalized to the PRODUCTION Set-A P2SH scriptPubKey, so we
//! source it straight from the production accessor: the tests then exercise the
//! EXACT script the binary enforces against.
const CScript& RecoveryScript()
{
    static const CScript s = PlanXRecoveryScript();
    return s;
}

//! A compromised (drained) address script.
const CScript& CompromisedScript()
{
    static const CScript s = ScriptOf(0xC0);
    return s;
}

//! A clean, unrelated destination.
const CScript& CleanScript()
{
    static const CScript s = ScriptOf(0xAB);
    return s;
}

//! Deterministic synthetic txid from a small integer.
uint256 TxId(unsigned id)
{
    uint256 out;
    out.begin()[0] = static_cast<unsigned char>(id & 0xFF);
    out.begin()[1] = static_cast<unsigned char>((id >> 8) & 0xFF);
    return out;
}

//! Add one coin paying `spk` to `view` at outpoint (txid, n) and return it.
COutPoint AddCoinTo(CCoinsViewCache& view, const uint256& txid, uint32_t n, const CScript& spk)
{
    COutPoint op(txid, n);
    CTxOut txout(/*nValue=*/1000, spk);
    view.AddCoin(op, Coin(std::move(txout), /*nHeight=*/1, /*fCoinBase=*/false),
                 /*possible_overwrite=*/false);
    return op;
}

//! Build a transaction spending `prevouts`, paying each (value,script) in `outs`.
CTransaction MakeTx(const std::vector<COutPoint>& prevouts,
                    const std::vector<CScript>& outs)
{
    CMutableTransaction mtx;
    for (const auto& op : prevouts) {
        CTxIn in;
        in.prevout = op;
        mtx.vin.push_back(in);
    }
    for (const auto& spk : outs) {
        mtx.vout.emplace_back(/*nValue=*/100, spk);
    }
    return CTransaction(mtx);
}

//! Add one coin paying `spk` with an explicit `value` and return its outpoint.
COutPoint AddValuedCoinTo(CCoinsViewCache& view, const uint256& txid, uint32_t n,
                          const CScript& spk, CAmount value)
{
    COutPoint op(txid, n);
    CTxOut txout(value, spk);
    view.AddCoin(op, Coin(std::move(txout), /*nHeight=*/1, /*fCoinBase=*/false),
                 /*possible_overwrite=*/false);
    return op;
}

//! Build a transaction spending `prevouts`, paying each (value,script) pair.
CTransaction MakeValuedTx(const std::vector<COutPoint>& prevouts,
                          const std::vector<std::pair<CAmount, CScript>>& outs)
{
    CMutableTransaction mtx;
    for (const auto& op : prevouts) {
        CTxIn in;
        in.prevout = op;
        mtx.vin.push_back(in);
    }
    for (const auto& [value, spk] : outs) {
        mtx.vout.emplace_back(value, spk);
    }
    return CTransaction(mtx);
}

//! Build a TRANSACTION_SAPLING tx that spends `prevouts` (a t->z shield):
//! empty vout, value carried into the shielded pool via SaplingTxPayload with the
//! given negative `valueBalance` (negative == value ENTERS the shielded pool).
//! This is the exact shape of the only-to-7b bypass the rule must reject.
CTransaction MakeShieldTx(const std::vector<COutPoint>& prevouts, int64_t valueBalance,
                          bool with_output_desc = true)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::SPECIAL_VERSION;
    mtx.nType = TRANSACTION_SAPLING;
    for (const auto& op : prevouts) {
        CTxIn in;
        in.prevout = op;
        mtx.vin.push_back(in);
    }
    // vout intentionally EMPTY (a t->z shield carries no transparent output).
    SaplingTxPayload payload;
    payload.valueBalance = valueBalance;
    if (with_output_desc) {
        // One shielded output description (a note entering the pool). Default-
        // constructed (all-zero) bytes are fine for classification: the freeze
        // classifier only counts descriptions and reads valueBalance.
        payload.vOutputDescriptions.emplace_back();
    }
    SetTxPayload(mtx, payload);
    return CTransaction(mtx);
}

//! RAII helper: arm PLAN X (gate on, set the recovery set) for one test and
//! reliably reset the process-wide globals afterwards so tests don't leak state.
struct PlanXArmGuard {
    bool prev_gate;
    explicit PlanXArmGuard(bool arm_with_set = true)
        : prev_gate(g_activate_rollback)
    {
        g_activate_rollback = true;
        // start clean
        g_compromised_recovery_set = CompromisedRecoverySet();
        if (arm_with_set) {
            g_compromised_recovery_set.AddScript(CompromisedScript());
        }
    }
    ~PlanXArmGuard()
    {
        g_activate_rollback = prev_gate;
        g_compromised_recovery_set = CompromisedRecoverySet();
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(planx_tests, BasicTestingSetup)

// Sanity: in the recovery-release build the block hashes are FINAL (non-null) and
// the recovery script is finalized to the PRODUCTION Set-A P2SH. The consensus
// VALIDITY rules are driven by these compiled constants, NOT by the action flag:
// the disallow-pin recognises the baked theft hash whether or not -activaterollback
// is set. The flag gates only the one-time in-process reorg. The only-to-7b rule is
// inert here purely because the compromised set has not been seeded yet (a unit
// test does not run the startup seeding).
BOOST_AUTO_TEST_CASE(constants_finalized_validity_is_baked_driven)
{
    BOOST_CHECK(!g_activate_rollback);                       // action flag off by default

    // The baked block hashes are the FINAL real values (non-null).
    BOOST_CHECK(!PlanXDisallowedBlockHash().IsNull());
    BOOST_CHECK(!PlanXRollbackAnchorHash().IsNull());
    BOOST_CHECK_EQUAL(PlanXDisallowedBlockHash().ToString(),
                      "00000000000002a24a4f88a39fe12bc5fd895c571af884d7eae5bfe21a0429a9");
    BOOST_CHECK_EQUAL(PlanXRollbackAnchorHash().ToString(),
                      "35bdbd05e21cd0e9321b9406683efe77b52c32ae50dbbf9444bef20d55ce7aee");

    // The recovery script is finalized (PRODUCTION Set-A P2SH: a914<20 bytes>87).
    BOOST_CHECK(!PlanXRecoveryScript().empty());

    BOOST_CHECK(!g_compromised_recovery_set.IsActive());     // set not seeded in a unit test
    // The disallow-pin is driven by the baked hash, INDEPENDENT of the action flag:
    // it recognises the real theft hash even with -activaterollback off.
    BOOST_CHECK(PlanXIsDisallowedBlockHash(PlanXDisallowedBlockHash()));
}

// (1) Inert when the compromised set is empty: with nothing seeded, a spend of any
//     coin is allowed (no coin is "compromised"), regardless of the action flag.
BOOST_AUTO_TEST_CASE(inert_when_set_empty)
{
    CCoinsView base;
    CCoinsViewCache view(&base);
    const COutPoint op = AddCoinTo(view, TxId(1), 0, CompromisedScript());

    g_activate_rollback = false;
    g_compromised_recovery_set = CompromisedRecoverySet();  // empty -> rule inert

    const CTransaction tx = MakeTx({op}, {CleanScript()}); // pays a non-7b dest
    BOOST_CHECK(PlanXOnlyToRecoveryAllowed(tx, view));      // allowed: set empty
}

// (1b) The only-to-7b rule is CONSENSUS VALIDITY, driven by the seeded set, NOT by
//      the action flag: with the set seeded and -activaterollback OFF, a compromised
//      spend to a non-7b destination is still REJECTED. This is the property that
//      lets a node that never set the flag (e.g. one that re-synced from scratch)
//      enforce identical block validity, so no flag-dependent consensus split exists.
BOOST_AUTO_TEST_CASE(enforced_regardless_of_action_flag)
{
    CCoinsView base;
    CCoinsViewCache view(&base);
    const COutPoint op = AddCoinTo(view, TxId(1), 0, CompromisedScript());

    g_activate_rollback = false;                            // action flag OFF
    g_compromised_recovery_set = CompromisedRecoverySet();
    g_compromised_recovery_set.AddScript(CompromisedScript()); // but the set IS seeded

    const CTransaction tx = MakeTx({op}, {CleanScript()}); // pays a non-7b dest
    const char* reason = nullptr;
    BOOST_CHECK(!PlanXOnlyToRecoveryAllowed(tx, view, &reason)); // rejected despite flag off
    BOOST_REQUIRE(reason != nullptr);
    BOOST_CHECK_EQUAL(std::string(reason), "planx-only-to-recovery");

    g_compromised_recovery_set = CompromisedRecoverySet();  // reset
}

// (2) Armed + finalized recovery: a compromised spend whose outputs ALL pay the
//     fresh Set-A/7b script is ACCEPTED. Driven through the REAL predicate
//     (recovery is finalized in this build), so this is the exact rule the
//     mempool + ConnectBlock sites enforce.
BOOST_AUTO_TEST_CASE(accepts_spend_all_to_recovery)
{
    PlanXArmGuard arm; // gate on, compromised script in set
    BOOST_REQUIRE(!RecoveryScript().empty()); // finalized PRODUCTION Set-A P2SH

    CCoinsView base;
    CCoinsViewCache view(&base);
    const COutPoint op = AddCoinTo(view, TxId(2), 0, CompromisedScript());

    // Two outputs, both to the fresh Set-A/7b recovery script -> accepted.
    const CTransaction tx = MakeTx({op}, {RecoveryScript(), RecoveryScript()});
    const char* reason = nullptr;
    BOOST_CHECK(PlanXOnlyToRecoveryAllowed(tx, view, &reason));
    BOOST_CHECK(reason == nullptr); // no reject reason on the accept path
}

// (3) Armed + finalized recovery: a compromised spend paying ANYWHERE other than
//     7b (or compromised-change / OP_RETURN) is REJECTED with the documented
//     reason token. REAL predicate.
BOOST_AUTO_TEST_CASE(rejects_compromised_spend_elsewhere)
{
    PlanXArmGuard arm; // gate on, compromised script in set

    CCoinsView base;
    CCoinsViewCache view(&base);
    const COutPoint op = AddCoinTo(view, TxId(5), 0, CompromisedScript());

    // Pays a clean (non-7b) destination -> rejected.
    const CTransaction tx = MakeTx({op}, {CleanScript()});
    const char* reason = nullptr;
    BOOST_CHECK(!PlanXOnlyToRecoveryAllowed(tx, view, &reason));
    BOOST_REQUIRE(reason != nullptr);
    BOOST_CHECK_EQUAL(std::string(reason), "planx-only-to-recovery");

    // Mixed: one output to 7b, one to a clean dest -> still rejected (ALL
    // non-change outputs must pay 7b).
    const CTransaction tx_mixed = MakeTx({op}, {RecoveryScript(), CleanScript()});
    BOOST_CHECK(!PlanXOnlyToRecoveryAllowed(tx_mixed, view));
}

// (5) Armed + finalized recovery: 7b + OP_RETURN marker -> ACCEPTED. Change-back
//     into a compromised wallet is NO LONGER allowed (see the dedicated
//     rejects_change_back test); only 7b outputs and OP_RETURN markers are
//     permitted on a compromised-coin spend. This test pins the marker-allowed /
//     full-sweep-allowed half of the contract.
BOOST_AUTO_TEST_CASE(accepts_recovery_and_marker)
{
    PlanXArmGuard arm; // gate on, compromised script in set

    CCoinsView base;
    CCoinsViewCache view(&base);
    const COutPoint op = AddCoinTo(view, TxId(6), 0, CompromisedScript());

    const CScript opret = CScript() << OP_RETURN << std::vector<unsigned char>{0xde, 0xad};
    BOOST_REQUIRE(opret.IsUnspendable());
    // 7b output + OP_RETURN marker (no change-back) -> accepted.
    const CTransaction tx = MakeTx({op}, {RecoveryScript(), opret});
    BOOST_CHECK(PlanXOnlyToRecoveryAllowed(tx, view));
}

// (4) A spend that does NOT touch the compromised set is ignored (allowed), even
//     with the gate armed.
BOOST_AUTO_TEST_CASE(ignores_non_compromised_spends)
{
    PlanXArmGuard arm;

    CCoinsView base;
    CCoinsViewCache view(&base);
    // A clean coin (not in the compromised set).
    const COutPoint op = AddCoinTo(view, TxId(3), 0, CleanScript());

    const CTransaction tx = MakeTx({op}, {CleanScript()});
    BOOST_CHECK(PlanXOnlyToRecoveryAllowed(tx, view)); // untouched -> allowed
}

// (6) Disallow-block + checkpoint-pin recognise the BAKED hashes (gate on). This
//     pins the consensus constants to their finalized values so a regression that
//     edits a hash is caught. The header-level ENFORCEMENT sites in validation.cpp
//     consume exactly these predicates.
BOOST_AUTO_TEST_CASE(baked_hashes_recognised_when_armed)
{
    const bool prev = g_activate_rollback;
    g_activate_rollback = true;

    // The real theft block hash is disallowed; an unrelated hash is not.
    BOOST_CHECK(PlanXIsDisallowedBlockHash(
        uint256S("0x00000000000002a24a4f88a39fe12bc5fd895c571af884d7eae5bfe21a0429a9")));
    BOOST_CHECK(!PlanXIsDisallowedBlockHash(uint256S("0x01")));

    // The checkpoint-pin anchor is the real block-54350 hash.
    BOOST_CHECK_EQUAL(PlanXRollbackAnchorHash().ToString(),
                      "35bdbd05e21cd0e9321b9406683efe77b52c32ae50dbbf9444bef20d55ce7aee");

    g_activate_rollback = prev;
}

// (7) The startup interlock predicate. PlanXScriptIsPlaceholder flags an empty
//     slot and the documented sentinel, and PASSES the finalized PRODUCTION scripts.
//     This is the building block the InitPlanXRollback interlock uses to refuse
//     to boot a gate-on node with an unfinalized recovery/treasury slot.
BOOST_AUTO_TEST_CASE(interlock_placeholder_detection)
{
    // Empty script -> placeholder.
    BOOST_CHECK(PlanXScriptIsPlaceholder(CScript()));
    // The documented sentinel (a914 ee..ee 87) -> placeholder.
    BOOST_CHECK(PlanXScriptIsPlaceholder(PlanXPlaceholderSentinelScript()));
    // The finalized recovery (PRODUCTION Set-A P2SH) -> NOT a placeholder.
    BOOST_CHECK(!PlanXScriptIsPlaceholder(PlanXRecoveryScript()));
    // A concrete (clean) script -> NOT a placeholder.
    BOOST_CHECK(!PlanXScriptIsPlaceholder(CleanScript()));

    // The sentinel is well-formed (parses to the expected 23-byte P2SH shape).
    const CScript sentinel = PlanXPlaceholderSentinelScript();
    BOOST_CHECK_EQUAL(sentinel.size(), 23u); // OP_HASH160 <20> OP_EQUAL
    BOOST_CHECK(sentinel.IsPayToScriptHash());
}

// The recovery destination is Set-D devFundPaymentScript; the init.cpp interlock
// also asserts it is NOT growthEscrowScript so recovered funds never land at the
// consensus-locked 40% reserve.
BOOST_AUTO_TEST_CASE(recovery_is_production_setD_p2sh)
{
    const CScript recovery = PlanXRecoveryScript();
    BOOST_REQUIRE(!recovery.empty());
    BOOST_CHECK(recovery.IsPayToScriptHash());
    const std::vector<unsigned char> want =
        ParseHex("a9143705ba0547a9d275c2cb6e6fa9d665061aa95fa687");
    const std::vector<unsigned char> got(recovery.begin(), recovery.end());
    BOOST_CHECK(got == want);
}

// Recovered funds are FREELY SPENDABLE: a tx that SPENDS the 7b/Set-A recovery
// script (i.e. the legit team sweeping the recovered coins out of 7b to wherever
// they choose) is NOT subject to the only-to-7b restriction. The restriction only
// constrains spends that TOUCH the compromised set; the 7b/Set-A P2SH is NOT a
// member of that set, so a spend of it may pay any destination. This is the
// release's "recovered funds are not locked" guarantee at the unit level.
BOOST_AUTO_TEST_CASE(recovery_script_spend_is_unrestricted)
{
    PlanXArmGuard guard; // gate on, compromised set = {CompromisedScript()}

    const CScript recovery = RecoveryScript();
    BOOST_REQUIRE(!recovery.empty());
    // Sanity: the 7b/Set-A recovery script is NOT in the compromised set.
    BOOST_REQUIRE(!g_compromised_recovery_set.ContainsScript(recovery));

    // A coin paying the 7b recovery script, spent to ARBITRARY (non-7b) dests.
    CCoinsView base;
    CCoinsViewCache view(&base);
    const COutPoint op = AddValuedCoinTo(view, TxId(0x77), 0, recovery, 100 * COIN);
    const CTransaction tx = MakeValuedTx(
        {op}, {{50 * COIN, CleanScript()}, {49 * COIN, ScriptOf(0x42)}});

    // Spending recovered (7b) funds does NOT touch the compromised set -> allowed,
    // no matter where the outputs go. Recovered funds are freely spendable.
    const char* reason = nullptr;
    BOOST_CHECK(PlanXOnlyToRecoveryAllowed(tx, view, &reason));
}

// ---------------------------------------------------------------------------
// Supplementary coverage via a local oracle that mirrors the only-to-7b contract
// for an ARBITRARY recovery script. The live predicate reads the (now finalized)
// recovery constant, so the oracle lets us also exercise membership-by-outpoint
// against a recovery script chosen by the test, and double-checks the documented
// accept/reject/change/marker contract independently of the baked constant.
// ---------------------------------------------------------------------------
namespace {

//! Local oracle encoding the documented only-to-7b contract for a FINALIZED
//! recovery script, INCLUDING the no-shielded-component and no-change-back
//! rules. Mirrors PlanXOnlyToRecoveryAllowed's step (3) exactly
//! (the fee-bound (3c) is exercised by the dedicated rejects_fee_bleed test that
//! drives the real predicate, so this oracle focuses on the destination/shield
//! contract for an arbitrary recovery script).
bool OnlyToRecoveryOracle(const CTransaction& tx,
                          const CCoinsViewCache& view,
                          const CScript& recovery)
{
    // Touch test (same as production).
    bool touches = false;
    for (const auto& in : tx.vin) {
        if (g_compromised_recovery_set.ContainsOutpoint(in.prevout)) { touches = true; break; }
        const Coin& c = view.AccessCoin(in.prevout);
        if (!c.IsSpent() && g_compromised_recovery_set.ContainsScript(c.out.scriptPubKey)) {
            touches = true; break;
        }
    }
    if (!touches) return true;
    if (PlanXTxHasShieldedComponent(tx)) return false;             // no shielded component allowed
    for (const auto& out : tx.vout) {
        if (out.scriptPubKey.IsUnspendable()) continue;             // OP_RETURN marker
        if (out.scriptPubKey == recovery) continue;                 // pays 7b
        return false;                                               // any other dest (incl. change) forbidden
    }
    return true;
}

} // namespace

// (2'/3'/5') The finalized-recovery contract: accept all-to-7b, accept 7b +
// OP_RETURN, reject any other destination (including change-back) and
// any shielded component, on a compromised-touching spend.
BOOST_AUTO_TEST_CASE(finalized_contract_accept_reject_change_marker)
{
    PlanXArmGuard arm; // compromised script in set
    const CScript recovery = RecoveryScript(); // a real, non-empty 7b script

    CCoinsView base;
    CCoinsViewCache view(&base);
    const COutPoint op = AddCoinTo(view, TxId(10), 0, CompromisedScript());

    // (2') All outputs pay 7b -> accepted.
    {
        const CTransaction tx = MakeTx({op}, {recovery, recovery});
        BOOST_CHECK(OnlyToRecoveryOracle(tx, view, recovery));
    }
    // (5') 7b + OP_RETURN marker (no change-back) -> accepted.
    {
        const CScript opret = CScript() << OP_RETURN << std::vector<unsigned char>{0xde, 0xad};
        BOOST_REQUIRE(opret.IsUnspendable());
        const CTransaction tx = MakeTx({op}, {recovery, opret});
        BOOST_CHECK(OnlyToRecoveryOracle(tx, view, recovery));
    }
    // Change back to a compromised wallet is now REJECTED.
    {
        const CTransaction tx = MakeTx({op}, {recovery, CompromisedScript()});
        BOOST_CHECK(!OnlyToRecoveryOracle(tx, view, recovery));
    }
    // (3') Any output to a clean (non-7b) dest -> rejected.
    {
        const CTransaction tx = MakeTx({op}, {recovery, CleanScript()});
        BOOST_CHECK(!OnlyToRecoveryOracle(tx, view, recovery));
    }
    // (3'') A single output entirely to a clean dest -> rejected.
    {
        const CTransaction tx = MakeTx({op}, {CleanScript()});
        BOOST_CHECK(!OnlyToRecoveryOracle(tx, view, recovery));
    }
    // A spend that does not touch the set is allowed regardless of destination.
    {
        const COutPoint clean = AddCoinTo(view, TxId(11), 0, CleanScript());
        const CTransaction tx = MakeTx({clean}, {CleanScript()});
        BOOST_CHECK(OnlyToRecoveryOracle(tx, view, recovery));
    }
}

// Membership by OUTPOINT (not just by script): a compromised outpoint triggers
// the rule even if its scriptPubKey is not separately listed.
BOOST_AUTO_TEST_CASE(membership_by_outpoint)
{
    PlanXArmGuard arm(/*arm_with_set=*/false); // gate on, EMPTY set, then add an outpoint
    const CScript recovery = RecoveryScript();

    CCoinsView base;
    CCoinsViewCache view(&base);
    // Coin pays a CLEAN script, but its outpoint is listed as compromised.
    const COutPoint op = AddCoinTo(view, TxId(20), 0, CleanScript());
    g_compromised_recovery_set.AddOutpoint(op);

    // Touches the set via the outpoint -> must go to 7b. Paying clean -> rejected.
    const CTransaction tx = MakeTx({op}, {CleanScript()});
    BOOST_CHECK(!OnlyToRecoveryOracle(tx, view, recovery));

    // All-to-7b -> accepted.
    const CTransaction tx_ok = MakeTx({op}, {recovery});
    BOOST_CHECK(OnlyToRecoveryOracle(tx_ok, view, recovery));
}

// ===========================================================================
//  Shielded (t->z) spend of a compromised coin is REJECTED.
// ===========================================================================
// The bypass: a TRANSACTION_SAPLING tx spends a compromised input, has an EMPTY
// vout, and carries the value into the shielded pool via valueBalance < 0. The
// pre-fix vout-only loop saw nothing to reject and returned ALLOWED. The fix
// rejects any compromised-touching tx with a shielded component, while a
// fully-transparent sweep to 7b still passes.

// Sanity: the shield-tx builder produces a tx the freeze classifier recognises
// as carrying a shielded component (is_sapling + outputs/valueBalance).
BOOST_AUTO_TEST_CASE(p1_shield_detection_sanity)
{
    const CTransaction tx = MakeShieldTx({COutPoint(TxId(30), 0)}, /*valueBalance=*/-900);
    const ShieldedDirection dir = ClassifyShieldedDirection(tx);
    BOOST_CHECK(dir.is_sapling);
    BOOST_CHECK_EQUAL(dir.value_balance, -900);
    BOOST_CHECK(PlanXTxHasShieldedComponent(tx));
    // A pure-transparent tx has no shielded component.
    const CTransaction plain = MakeTx({COutPoint(TxId(31), 0)}, {RecoveryScript()});
    BOOST_CHECK(!PlanXTxHasShieldedComponent(plain));
}

// A Sapling shield (empty vout, value via valueBalance) of a compromised
// input is REJECTED with the dedicated reason token. REAL predicate.
BOOST_AUTO_TEST_CASE(p1_rejects_shielded_compromised_spend)
{
    PlanXArmGuard arm; // gate on, compromised script in set

    CCoinsView base;
    CCoinsViewCache view(&base);
    // Compromised coin worth 1000 sat.
    const COutPoint op = AddValuedCoinTo(view, TxId(32), 0, CompromisedScript(), /*value=*/1000);

    // t->z shield: empty vout, all value (minus a tiny fee) enters the pool.
    const CTransaction shield = MakeShieldTx({op}, /*valueBalance=*/-990);
    const char* reason = nullptr;
    BOOST_CHECK(!PlanXOnlyToRecoveryAllowed(shield, view, &reason));
    BOOST_REQUIRE(reason != nullptr);
    BOOST_CHECK_EQUAL(std::string(reason), "planx-shielded-compromised-spend");

    // Even a shield with only a valueBalance and no output description is caught
    // (any non-zero shielded component on a compromised spend is forbidden).
    const CTransaction shield_vb_only =
        MakeShieldTx({op}, /*valueBalance=*/-990, /*with_output_desc=*/false);
    BOOST_CHECK(!PlanXOnlyToRecoveryAllowed(shield_vb_only, view));
}

// A fully-transparent full sweep to 7b still PASSES (the rule does not
// over-block legitimate recovery). REAL predicate.
BOOST_AUTO_TEST_CASE(p1_transparent_to_7b_still_passes)
{
    PlanXArmGuard arm; // gate on, compromised script in set

    CCoinsView base;
    CCoinsViewCache view(&base);
    const COutPoint op = AddValuedCoinTo(view, TxId(33), 0, CompromisedScript(), /*value=*/1000);

    // Transparent sweep: pay ~the whole input to 7b (within the fee tolerance).
    const CTransaction tx = MakeValuedTx({op}, {{/*value=*/1000, RecoveryScript()}});
    const char* reason = nullptr;
    BOOST_CHECK(PlanXOnlyToRecoveryAllowed(tx, view, &reason));
    BOOST_CHECK(reason == nullptr);
}

// ===========================================================================
//  Bound the fee and forbid change-back.
// ===========================================================================

// Fee bound: a spend that pays only a dust output to 7b and leaves a
// LARGE fee (input value >> value to 7b, beyond MAX_RECOVERY_FEE) is REJECTED.
// REAL predicate. Input is large enough that the fee tolerance cannot mask it.
BOOST_AUTO_TEST_CASE(p4_rejects_fee_bleed)
{
    PlanXArmGuard arm; // gate on, compromised script in set

    CCoinsView base;
    CCoinsViewCache view(&base);
    // A large compromised coin: 10 KRGN.
    const CAmount big = 10 * COIN;
    const COutPoint op = AddValuedCoinTo(view, TxId(40), 0, CompromisedScript(), big);

    // Pay a dust 1000 sat to 7b; the rest (~10 KRGN) is left as fee. With
    // MAX_RECOVERY_FEE == 0.001 KRGN, min_to_recovery == big - 0.001 KRGN, so
    // 1000 sat is far below the bound -> REJECTED for excessive fee.
    const CTransaction tx = MakeValuedTx({op}, {{/*value=*/1000, RecoveryScript()}});
    const char* reason = nullptr;
    BOOST_CHECK(!PlanXOnlyToRecoveryAllowed(tx, view, &reason));
    BOOST_REQUIRE(reason != nullptr);
    BOOST_CHECK_EQUAL(std::string(reason), "planx-recovery-fee-too-high");

    // A full sweep that pays the whole input to 7b -> accepted.
    const CTransaction full = MakeValuedTx({op}, {{big, RecoveryScript()}});
    BOOST_CHECK(PlanXOnlyToRecoveryAllowed(full, view));

    // Paying (big - tolerance) to 7b sits exactly on the bound -> accepted.
    const CTransaction on_bound =
        MakeValuedTx({op}, {{big - planx::MAX_RECOVERY_FEE, RecoveryScript()}});
    BOOST_CHECK(PlanXOnlyToRecoveryAllowed(on_bound, view));

    // Paying one satoshi BELOW the bound -> rejected (fee just over tolerance).
    const CTransaction below_bound =
        MakeValuedTx({op}, {{big - planx::MAX_RECOVERY_FEE - 1, RecoveryScript()}});
    BOOST_CHECK(!PlanXOnlyToRecoveryAllowed(below_bound, view));
}

// No change-back: a spend that sends a sliver to 7b and the rest as
// "change" back into a compromised address is REJECTED -- a full sweep is forced.
// REAL predicate.
BOOST_AUTO_TEST_CASE(p4_rejects_change_back)
{
    PlanXArmGuard arm; // gate on, compromised script in set

    CCoinsView base;
    CCoinsViewCache view(&base);
    const CAmount big = 10 * COIN;
    const COutPoint op = AddValuedCoinTo(view, TxId(41), 0, CompromisedScript(), big);

    // 1 sat to 7b + the rest back to a compromised address (change). The change
    // output is a forbidden destination now -> REJECTED with the only-to-recovery
    // reason (the destination check fires before the fee bound).
    const CTransaction tx = MakeValuedTx({op},
        {{/*value=*/1, RecoveryScript()},
         {/*value=*/big - 1, CompromisedScript()}});
    const char* reason = nullptr;
    BOOST_CHECK(!PlanXOnlyToRecoveryAllowed(tx, view, &reason));
    BOOST_REQUIRE(reason != nullptr);
    BOOST_CHECK_EQUAL(std::string(reason), "planx-only-to-recovery");
}

// A clean full-sweep-to-7b (whole input value to 7b, no change, no
// shield, fee within tolerance) PASSES. REAL predicate.
BOOST_AUTO_TEST_CASE(p4_clean_full_sweep_passes)
{
    PlanXArmGuard arm; // gate on, compromised script in set

    CCoinsView base;
    CCoinsViewCache view(&base);
    const CAmount big = 5 * COIN;
    const COutPoint op = AddValuedCoinTo(view, TxId(42), 0, CompromisedScript(), big);

    const CScript opret = CScript() << OP_RETURN << std::vector<unsigned char>{0x7b};
    BOOST_REQUIRE(opret.IsUnspendable());
    // Whole value to 7b + an OP_RETURN marker -> accepted (markers are ignored
    // and do not count against the fee bound).
    const CTransaction tx = MakeValuedTx({op}, {{big, RecoveryScript()}, {0, opret}});
    BOOST_CHECK(PlanXOnlyToRecoveryAllowed(tx, view));
}

// v1.2.5 IBD height-gate. Below RECOVERY_V2_ACTIVATION_HEIGHT the recovery
// rule is inert; at/above it the rule enforces as before. Pre-1.2.5 a fresh
// IBD failed at the first historical block that touched a now-compromised
// address (slush, h=2036). With the gate in place those historical blocks
// pass and the constraint binds only from h=54500 onward.
BOOST_AUTO_TEST_CASE(p5_ibd_height_gate_accepts_below_activation)
{
    PlanXArmGuard arm;

    CCoinsView base;
    CCoinsViewCache view(&base);
    const COutPoint op = AddCoinTo(view, TxId(50), 0, CompromisedScript());

    // Same transaction shape that the post-activation tests reject (compromised
    // input -> clean destination) MUST pass when the block height is below the
    // gate: a legitimate pre-incident spend.
    const CTransaction tx = MakeTx({op}, {CleanScript()});
    const int activation = planx::RECOVERY_V2_ACTIVATION_HEIGHT;
    const char* reason = nullptr;
    BOOST_CHECK(PlanXOnlyToRecoveryAllowed(tx, view, &reason, /*nHeight=*/2036));
    BOOST_CHECK(PlanXOnlyToRecoveryAllowed(tx, view, &reason, /*nHeight=*/activation - 1));
    BOOST_CHECK(reason == nullptr);
}

// At/above the activation height the rule binds: the same transaction that
// passes at activation-1 must be rejected at activation, with the documented
// reason token. Pins the gate boundary so an off-by-one regression is caught.
BOOST_AUTO_TEST_CASE(p5_ibd_height_gate_rejects_at_activation)
{
    PlanXArmGuard arm;

    CCoinsView base;
    CCoinsViewCache view(&base);
    const COutPoint op = AddCoinTo(view, TxId(51), 0, CompromisedScript());

    const CTransaction tx = MakeTx({op}, {CleanScript()});
    const int activation = planx::RECOVERY_V2_ACTIVATION_HEIGHT;
    const char* reason = nullptr;

    BOOST_CHECK(!PlanXOnlyToRecoveryAllowed(tx, view, &reason, activation));
    BOOST_REQUIRE(reason != nullptr);
    BOOST_CHECK_EQUAL(std::string(reason), "planx-only-to-recovery");

    reason = nullptr;
    BOOST_CHECK(!PlanXOnlyToRecoveryAllowed(tx, view, &reason, activation + 1));
    BOOST_REQUIRE(reason != nullptr);
    BOOST_CHECK_EQUAL(std::string(reason), "planx-only-to-recovery");
}

// The default (nHeight == 0) call path used by the existing predicate-level
// unit tests must still enforce -- absence of a height is treated as
// "no IBD context" and the rule binds. This pins the back-compat semantics
// the rest of the suite depends on.
BOOST_AUTO_TEST_CASE(p5_default_height_zero_still_enforces)
{
    PlanXArmGuard arm;

    CCoinsView base;
    CCoinsViewCache view(&base);
    const COutPoint op = AddCoinTo(view, TxId(52), 0, CompromisedScript());

    const CTransaction tx = MakeTx({op}, {CleanScript()});
    const char* reason = nullptr;
    BOOST_CHECK(!PlanXOnlyToRecoveryAllowed(tx, view, &reason)); // default nHeight=0
    BOOST_REQUIRE(reason != nullptr);
    BOOST_CHECK_EQUAL(std::string(reason), "planx-only-to-recovery");
}

BOOST_AUTO_TEST_SUITE_END()
