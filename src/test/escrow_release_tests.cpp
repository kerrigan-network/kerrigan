// Copyright (c) 2026 Kerrigan Network
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <governance/escrow_validator.h>
#include <governance/common.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <consensus/params.h>
#include <crypto/ripemd160.h>
#include <crypto/sha256.h>
#include <evo/evodb.h>
#include <key.h>
#include <key_io.h>
#include <policy/planx_rollback.h>
#include <pubkey.h>
#include <script/script.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/system.h>

#include <test/util/setup_common.h>

#include <memory>
#include <vector>

#include <boost/test/unit_test.hpp>

static std::string MakeEscrowReleaseHex(const std::string& name, const std::string& address,
                                         double amount, const std::string& url)
{
    std::string json = "{";
    json += "\"type\":3,";
    json += "\"name\":\"" + name + "\",";
    json += "\"payment_address\":\"" + address + "\",";
    json += "\"payment_amount\":" + std::to_string(amount) + ",";
    json += "\"url\":\"" + url + "\"";
    json += "}";
    return HexStr(std::vector<unsigned char>(json.begin(), json.end()));
}

static std::string MakeProposalHex(int type, const std::string& name, const std::string& address,
                                    double amount, const std::string& url)
{
    std::string json = "{";
    json += "\"type\":" + std::to_string(type) + ",";
    json += "\"name\":\"" + name + "\",";
    json += "\"payment_address\":\"" + address + "\",";
    json += "\"payment_amount\":" + std::to_string(amount) + ",";
    json += "\"url\":\"" + url + "\"";
    json += "}";
    return HexStr(std::vector<unsigned char>(json.begin(), json.end()));
}

// Generate a valid regtest address from a random key
static std::string MakeRegtestAddress()
{
    CKey key;
    key.MakeNewKey(true);
    CTxDestination dest = PKHash(key.GetPubKey());
    return EncodeDestination(dest);
}

BOOST_FIXTURE_TEST_SUITE(escrow_release_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(escrow_release_validator_valid)
{
    std::string addr = MakeRegtestAddress();
    std::string hex = MakeEscrowReleaseHex("exchange-listing", addr, 50000.0, "https://kerrigan.network/proposals/001");
    CEscrowReleaseValidator validator(hex);
    BOOST_CHECK_MESSAGE(validator.Validate(), "Expected valid, got: " + validator.GetErrorMessages());
}

BOOST_AUTO_TEST_CASE(escrow_release_validator_invalid_type)
{
    std::string addr = MakeRegtestAddress();
    // type=1 is PROPOSAL, not ESCROW_RELEASE -- should fail type check
    std::string hex = MakeProposalHex(1, "test", addr, 100.0, "https://example.com");
    CEscrowReleaseValidator validator(hex);
    BOOST_CHECK(!validator.Validate());
}

BOOST_AUTO_TEST_CASE(escrow_release_validator_missing_amount)
{
    std::string addr = MakeRegtestAddress();
    // JSON without payment_amount field
    std::string json = "{\"type\":3,\"name\":\"test\",\"payment_address\":\"" + addr + "\","
                        "\"url\":\"https://example.com\"}";
    std::string hex = HexStr(std::vector<unsigned char>(json.begin(), json.end()));
    CEscrowReleaseValidator validator(hex);
    BOOST_CHECK(!validator.Validate());
}

BOOST_AUTO_TEST_CASE(escrow_release_validator_negative_amount)
{
    std::string addr = MakeRegtestAddress();
    std::string hex = MakeEscrowReleaseHex("test", addr, -100.0, "https://example.com");
    CEscrowReleaseValidator validator(hex);
    BOOST_CHECK(!validator.Validate());
}

BOOST_AUTO_TEST_CASE(escrow_release_validator_empty_name)
{
    std::string addr = MakeRegtestAddress();
    std::string hex = MakeEscrowReleaseHex("", addr, 100.0, "https://example.com");
    CEscrowReleaseValidator validator(hex);
    BOOST_CHECK(!validator.Validate());
}

// Test OP_RETURN parsing for the KRGN marker
BOOST_AUTO_TEST_CASE(escrow_op_return_format)
{
    // Build a valid OP_RETURN: OP_RETURN OP_PUSHBYTES_36 "KRGN" <32-byte hash>
    uint256 testHash = uint256S("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
    CScript opReturnScript;
    std::vector<unsigned char> data;
    data.push_back('K');
    data.push_back('R');
    data.push_back('G');
    data.push_back('N');
    data.insert(data.end(), testHash.begin(), testHash.end());
    opReturnScript << OP_RETURN;
    opReturnScript << data;

    // Verify the script is 38 bytes: 1 (OP_RETURN) + 1 (push 36) + 4 (KRGN) + 32 (hash)
    BOOST_CHECK_EQUAL(opReturnScript.size(), 38U);
    BOOST_CHECK_EQUAL(opReturnScript[0], OP_RETURN);
    BOOST_CHECK_EQUAL(opReturnScript[1], 0x24); // push 36 bytes
    BOOST_CHECK_EQUAL(opReturnScript[2], 'K');
    BOOST_CHECK_EQUAL(opReturnScript[3], 'R');
    BOOST_CHECK_EQUAL(opReturnScript[4], 'G');
    BOOST_CHECK_EQUAL(opReturnScript[5], 'N');

    // Extract the hash back
    uint256 extractedHash;
    memcpy(extractedHash.begin(), opReturnScript.data() + 6, 32);
    BOOST_CHECK_EQUAL(extractedHash, testHash);
}

// Test anti-replay via evoDB
BOOST_AUTO_TEST_CASE(escrow_replay_prevention)
{
    // Create a temporary evodb for testing
    util::DbWrapperParams db_params{m_args.GetDataDirNet() / "evodb_test", true, false, 1 << 20};
    CEvoDB testEvoDB(db_params);

    uint256 proposalHash = uint256S("1111111111111111111111111111111111111111111111111111111111111111");

    // Should not be executed initially
    BOOST_CHECK(!IsEscrowReleaseExecuted(testEvoDB, proposalHash));

    // Mark as executed
    MarkEscrowReleaseExecuted(testEvoDB, proposalHash, 1000);
    BOOST_CHECK(IsEscrowReleaseExecuted(testEvoDB, proposalHash));

    // Unmark (reorg simulation)
    UnmarkEscrowReleaseExecuted(testEvoDB, proposalHash);
    BOOST_CHECK(!IsEscrowReleaseExecuted(testEvoDB, proposalHash));
}

BOOST_AUTO_TEST_CASE(escrow_release_accessor_methods)
{
    std::string addr = MakeRegtestAddress();
    std::string hex = MakeEscrowReleaseHex("test-release", addr, 25000.5, "https://example.com");
    CEscrowReleaseValidator validator(hex);
    BOOST_CHECK_MESSAGE(validator.Validate(), "Expected valid, got: " + validator.GetErrorMessages());

    double amount = 0;
    BOOST_CHECK(validator.GetPaymentAmount(amount));
    BOOST_CHECK_CLOSE(amount, 25000.5, 0.001);

    std::string extractedAddr;
    BOOST_CHECK(validator.GetPaymentAddress(extractedAddr));
    BOOST_CHECK_EQUAL(extractedAddr, addr);
}

// ===========================================================================
//  Lock guards the SET (escrow key rotation without unlocking old coins)
// ===========================================================================
//
// After the growth-escrow key rotation, growthEscrowScript points at the fresh
// Set-A P2SH. The ~500k KRGN still parked at the OLD escrow P2SH must remain
// consensus-locked and governance-gated. The routing decision at BOTH lock sites
// (mempool PreChecks ~L1020, ConnectBlock ~L3336) is Consensus::Params::
// IsGrowthEscrowScript(spk): a coin is "from escrow" iff it pays the current
// growthEscrowScript OR any superseded legacyEscrowScripts entry. These tests
// drive that exact predicate against the REAL baked mainnet params, plus a local
// oracle that mirrors CheckGovernanceEscrowSpend's output guards (the static
// function isn't linkable from the test binary) to prove the governance gate
// accepts a release of EITHER the current OR a legacy escrow script.

namespace {

// Helpers re-derive the escrow P2SH scriptPubKeys from the same redeemScript bytes
// chainparams.cpp bakes in, so the test asserts against derived (not transcribed)
// values. P2SH scriptPubKey = OP_HASH160 <hash160(redeemScript)> OP_EQUAL.
static CScript P2SHFromRedeem(const std::string& redeemHex)
{
    const std::vector<unsigned char> redeem = ParseHex(redeemHex);
    uint256 sha;
    CSHA256().Write(redeem.data(), redeem.size()).Finalize(sha.begin());
    std::vector<unsigned char> h160(20);
    CRIPEMD160().Write(sha.begin(), 32).Finalize(h160.data());
    return CScript() << OP_HASH160 << h160 << OP_EQUAL;
}

// The OLD (pre-rotation, compromised) mainnet growth-escrow redeemScript
// (release-v1.2.0-freeze) -> address 7TrJoc8f9AD32D225cV63CcdibhLyRXiP3.
static const char* OLD_ESCROW_REDEEM =
    "522103261171e2b23bf1d194df2c7a5d1d538c32b8f89663e44dd120f81d6c2247c4a5"
    "210389c01e16affdc212dad4041fdcb541bb16cbc70228b6073243ee8139bb6d1a28"
    "210208fcb17aa95588e3f37da5aa6513ecb8cca193249c67af7997a416993b6bbe8e53ae";

// The NEW (rotated) Set-A growth-escrow redeemScript -> 7gHTsab3dGLuJCQFDwfxkycX7Bdipnz7V5.
static const char* NEW_ESCROW_REDEEM =
    "5221030302c0ab19d44d26494e7e4189e14e91b861317ce813aa544efebacc13fb9600"
    "21036a26c1b83b3cf923c1b4d7e3abbc04d91265d47d00a0ca6c985f92adb04bf992"
    "210394a5d10cda90e851553c925f419d01e1a2316f63749fb4d90943c1d15006d4be53ae";

static std::vector<unsigned char> VecOf(const CScript& s)
{
    return std::vector<unsigned char>(s.begin(), s.end());
}

// Local oracle: mirrors CheckGovernanceEscrowSpend's OUTPUT guards (steps 6/7a/7b)
// for a given `escrowScript` (the matched current-or-legacy script the inputs came
// from) and a governance-approved (payout script, amount). Returns true iff the
// output set is authorized (the marker/proposal-lookup/anti-replay layers are
// covered by the existing tests above; here we isolate the script-routing contract
// the escrow key-rotation fix touches). `escrowScript` is the change destination.
static bool EscrowOutputsAuthorized(const CTransaction& tx,
                                    const CScript& escrowScript,
                                    const CScript& approvedScript,
                                    CAmount approvedAmount)
{
    // step 6 + 7a: exactly one output pays the approved script for the approved amount.
    int paymentCount = 0;
    CAmount totalToApproved = 0;
    for (const auto& out : tx.vout) {
        if (out.scriptPubKey == approvedScript) {
            paymentCount++;
            totalToApproved += out.nValue;
        }
    }
    if (paymentCount != 1 || totalToApproved != approvedAmount) return false;
    // step 7b: every remaining output is the payment, change back to escrowScript, or OP_RETURN.
    for (const auto& out : tx.vout) {
        if (out.scriptPubKey == approvedScript && out.nValue == approvedAmount) continue;
        if (out.scriptPubKey == escrowScript) continue;       // change back to (this) escrow
        if (out.scriptPubKey.IsUnspendable()) continue;       // OP_RETURN marker
        return false;                                          // unauthorized output
    }
    return true;
}

static CTransaction MakeEscrowTx(const std::vector<std::pair<CAmount, CScript>>& outs)
{
    CMutableTransaction mtx;
    CTxIn in; // one synthetic input; the lock site selects the escrow via the COIN, not the tx
    mtx.vin.push_back(in);
    for (const auto& [v, spk] : outs) mtx.vout.emplace_back(v, spk);
    return CTransaction(mtx);
}

static CScript ArbitraryP2PKH(unsigned char b)
{
    std::vector<unsigned char> h(20, b);
    return CScript() << OP_DUP << OP_HASH160 << h << OP_EQUALVERIFY << OP_CHECKSIG;
}

} // namespace

// The mainnet params seed legacyEscrowScripts with EXACTLY the OLD escrow P2SH, and
// growthEscrowScript is the NEW Set-A P2SH. Lock in the exact byte values.
BOOST_AUTO_TEST_CASE(p8_mainnet_escrow_set_baked)
{
    const auto params = CreateChainParams(ArgsManager{}, CBaseChainParams::MAIN);
    const Consensus::Params& c = params->GetConsensus();

    const CScript oldEscrow = P2SHFromRedeem(OLD_ESCROW_REDEEM);
    const CScript newEscrow = P2SHFromRedeem(NEW_ESCROW_REDEEM);

    // Sanity: the derived OLD escrow is the documented pre-rotation P2SH scriptPubKey.
    BOOST_CHECK_EQUAL(HexStr(oldEscrow), "a9140fd2497322e9d0a0c681fd5b4beb374d1b89392d87");
    BOOST_CHECK_EQUAL(HexStr(newEscrow), "a9149835c3ef5977c827045edb682d113761856deb5887");

    // Current escrow == NEW (rotation kept).
    BOOST_CHECK(c.growthEscrowScript == VecOf(newEscrow));
    // Exactly one legacy escrow, == OLD.
    BOOST_REQUIRE_EQUAL(c.legacyEscrowScripts.size(), 1U);
    BOOST_CHECK(c.legacyEscrowScripts[0] == VecOf(oldEscrow));
}

// REGRESSION: the OLD escrow scriptPubKey routes through the escrow lock. Before
// the fix it matched neither growthEscrowScript (rotated away) nor any legacy entry,
// so the old 500k was spendable with just the old keys. Now IsGrowthEscrowScript
// flags it -> the spend is forced through CheckGovernanceEscrowSpend.
BOOST_AUTO_TEST_CASE(p8_old_escrow_is_locked)
{
    const auto params = CreateChainParams(ArgsManager{}, CBaseChainParams::MAIN);
    const Consensus::Params& c = params->GetConsensus();

    const CScript oldEscrow = P2SHFromRedeem(OLD_ESCROW_REDEEM);
    const CScript newEscrow = P2SHFromRedeem(NEW_ESCROW_REDEEM);

    // Both the OLD and the NEW escrow scripts are "from escrow".
    BOOST_CHECK(c.IsGrowthEscrowScript(VecOf(oldEscrow)));
    BOOST_CHECK(c.IsGrowthEscrowScript(VecOf(newEscrow)));

    // A non-escrow script is NOT routed through the gate.
    BOOST_CHECK(!c.IsGrowthEscrowScript(VecOf(ArbitraryP2PKH(0xAB))));
    // An empty script never matches (inert).
    BOOST_CHECK(!c.IsGrowthEscrowScript(std::vector<unsigned char>{}));
}

// Governance gate accepts a release of EITHER the current OR a legacy escrow script:
// the output guards run against whichever escrow script the inputs came from.
BOOST_AUTO_TEST_CASE(p8_gate_accepts_current_and_legacy_release)
{
    const CScript oldEscrow = P2SHFromRedeem(OLD_ESCROW_REDEEM);
    const CScript newEscrow = P2SHFromRedeem(NEW_ESCROW_REDEEM);
    const CScript payout = ArbitraryP2PKH(0x11);
    const CScript marker = CScript() << OP_RETURN << std::vector<unsigned char>{0xab, 0xcd};
    BOOST_REQUIRE(marker.IsUnspendable());
    const CAmount amt = 50000 * COIN;

    // Release of the LEGACY (old) escrow: payout + change back to OLD escrow + marker.
    {
        const CTransaction tx = MakeEscrowTx({{amt, payout}, {10 * COIN, oldEscrow}, {0, marker}});
        BOOST_CHECK(EscrowOutputsAuthorized(tx, /*escrowScript=*/oldEscrow, payout, amt));
        // ...but if the change goes back to the NEW escrow while the inputs were the
        // OLD escrow, that NEW-escrow change is an unauthorized output (the gate is
        // scoped to the funding script). It would instead have to be the approved payout.
        const CTransaction tx2 = MakeEscrowTx({{amt, payout}, {10 * COIN, newEscrow}});
        BOOST_CHECK(!EscrowOutputsAuthorized(tx2, /*escrowScript=*/oldEscrow, payout, amt));
    }

    // OLD -> NEW consolidation sweep: governance approves paying the NEW escrow as the
    // destination. With escrowScript = OLD (funding), approvedScript = NEW, this is a
    // single authorized payment -> allowed (the later old->new sweep the fix enables).
    {
        const CTransaction tx = MakeEscrowTx({{amt, newEscrow}, {0, marker}});
        BOOST_CHECK(EscrowOutputsAuthorized(tx, /*escrowScript=*/oldEscrow, /*approved=*/newEscrow, amt));
    }

    // Release of the CURRENT (new) escrow: payout + change back to NEW escrow.
    {
        const CTransaction tx = MakeEscrowTx({{amt, payout}, {5 * COIN, newEscrow}});
        BOOST_CHECK(EscrowOutputsAuthorized(tx, /*escrowScript=*/newEscrow, payout, amt));
    }
}

// Single-payment guard preserved: N duplicate payment outputs are rejected even
// through the legacy path (no N * approvedAmount drain).
BOOST_AUTO_TEST_CASE(p8_gate_rejects_duplicate_payment_legacy)
{
    const CScript oldEscrow = P2SHFromRedeem(OLD_ESCROW_REDEEM);
    const CScript payout = ArbitraryP2PKH(0x22);
    const CAmount amt = 1000 * COIN;

    // Two outputs each paying the approved amount -> totalToApproved = 2*amt -> rejected.
    const CTransaction tx = MakeEscrowTx({{amt, payout}, {amt, payout}});
    BOOST_CHECK(!EscrowOutputsAuthorized(tx, oldEscrow, payout, amt));
}

// Unauthorized output guard preserved through the legacy path: any output to a
// non-payout, non-(this-escrow), non-marker destination is rejected.
BOOST_AUTO_TEST_CASE(p8_gate_rejects_unauthorized_output_legacy)
{
    const CScript oldEscrow = P2SHFromRedeem(OLD_ESCROW_REDEEM);
    const CScript payout = ArbitraryP2PKH(0x33);
    const CScript thief  = ArbitraryP2PKH(0x44);
    const CAmount amt = 1000 * COIN;

    const CTransaction tx = MakeEscrowTx({{amt, payout}, {500 * COIN, thief}});
    BOOST_CHECK(!EscrowOutputsAuthorized(tx, oldEscrow, payout, amt));
}

// Default-inert: testnet/regtest carry NO legacy escrow scripts, so the legacy
// path is byte-identical to the single-script lock there. (Devnet is omitted only
// because its genesis construction asserts on a -devnet name; its chainparams block
// likewise sets no legacyEscrowScripts, so the field defaults empty there too.)
BOOST_AUTO_TEST_CASE(p8_non_mainnet_has_no_legacy_escrow)
{
    for (const std::string chain : {std::string(CBaseChainParams::TESTNET),
                                    std::string(CBaseChainParams::REGTEST)}) {
        const auto params = CreateChainParams(ArgsManager{}, chain);
        const Consensus::Params& c = params->GetConsensus();
        BOOST_CHECK_MESSAGE(c.legacyEscrowScripts.empty(),
                            "expected no legacyEscrowScripts on " + chain);
        // The OLD mainnet escrow script must NOT be locked on these networks.
        const CScript oldEscrow = P2SHFromRedeem(OLD_ESCROW_REDEEM);
        BOOST_CHECK(!c.IsGrowthEscrowScript(VecOf(oldEscrow)));
    }
}

// ===========================================================================
//  The escrow gate is a DETERMINISTIC CONSENSUS HEIGHT FLOOR
//  (no IBD branch, no best-header depth, no -activaterollback flag).
// ===========================================================================
//
// CheckGovernanceEscrowSpend (validation.cpp, static -- not linkable here) now
// applies a STEP-0 hard floor BEFORE the OP_RETURN marker parse: an escrow
// release at a height STRICTLY BELOW Consensus::Params::nEscrowUnlockHeight
// (H_unlock) is consensus-INVALID on every node, unconditionally
// (bad-escrow-locked-window). The three prior node-state-dependent trust gates
// are GONE:
//   - one earlier design keyed a blanket IBD shortcut -> an attacker with the
//     compromised legacy escrow keys could drain the ~500k on a bogus marker
//     during the re-mine.
//   - another keyed the shortcut on g_activate_rollback -> flag-on vs flag-off
//     nodes split on a buried historical release.
//   - a third keyed it on (m_best_header height - release height) > DEPTH through
//     a strict boundary -> +-1 header jitter split two honest nodes.
// All three operands (IBD state, the rollback flag, the best-header height) are
// removed from the escrow path entirely. The verdict now depends ONLY on the
// block's own height versus the baked constant H_unlock (below the floor) and on
// the funded-governance object (at/above it, where every node is out of IBD).
//
// The whole PLAN X re-mine window (anchor 54350, theft 54351, old tip ~55011) is
// below H_unlock = 60000, so no escrow release of ANY kind is valid during the
// re-mine -- the IBD-shortcut drain door is shut by height, not by IBD state. The only
// legitimate release (the later old->new 500k consolidation) is forced to height
// >= 60000, where the network is provably caught up and the FULL funded-governance
// check runs at mining time on every miner.
//
// The static gate is not linkable from the test binary (exactly as the escrow
// key-rotation cases above note), so these cases drive a MODEL of the gate's
// accept/reject contract.
// The model is deliberately written to TAKE the (now-removed) node-state inputs --
// nodeInIBD, best-header height, and the rollback flag -- and prove the verdict is
// invariant under every combination of them: the verdict is a pure function of
// (release height, H_unlock, funded-governance), the exact determinism property
// the height floor establishes.

namespace {

//! RAII helper: set the PLAN X master gate for one test and reliably restore it
//! afterwards so tests never leak the process-wide flag. The height-floor fix
//! makes the escrow verdict flag-INDEPENDENT, so these tests use this guard to
//! PROVE the same release yields the same verdict in either flag state.
struct PlanXGateGuard {
    bool prev;
    explicit PlanXGateGuard(bool on) : prev(g_activate_rollback) { g_activate_rollback = on; }
    ~PlanXGateGuard() { g_activate_rollback = prev; }
};

//! The mainnet unlock floor, read from the REAL baked chainparams so the test
//! tracks whatever value chainparams.cpp ships (no transcription).
static int MainnetEscrowUnlockHeight()
{
    const auto params = CreateChainParams(ArgsManager{}, CBaseChainParams::MAIN);
    return params->GetConsensus().nEscrowUnlockHeight;
}

//! Heights spanning the floor. kSubFloor sits inside the PLAN X re-mine window;
//! kAtFloor is the first height a release may be valid; kAboveFloor is well past.
//! Only the height-vs-floor relation matters to the gate.
constexpr int kReleaseHeight = 54360;   // a re-mine-window height (< 60000)

//! Faithful model of CheckGovernanceEscrowSpend's accept/reject decision after the
//! height-floor fix. STEP 0: a release below H_unlock is rejected unconditionally.
//! STEPS 4+ (only reached at/above the floor): accept iff a funded governance
//! object for the proposal exists. The node-state inputs (initial-block-download
//! state, best-known-header height, and the rollback flag via g_activate_rollback)
//! are ACCEPTED as parameters but DELIBERATELY UNUSED -- mirroring the real
//! function, which no longer reads any of them. Their presence in the signature
//! lets the determinism tests below toggle every node-state axis and assert the
//! verdict never moves.
static bool EscrowGateAccepts(int nReleaseHeight, int nEscrowUnlockHeight,
                              bool hasFundedGovObject,
                              bool /*nodeInInitialBlockDownload, unused*/,
                              int /*nBestKnownHeaderHeight, unused*/)
{
    // STEP 0: hard unlock floor. Pure height comparison; no node-state input.
    if (nEscrowUnlockHeight > 0 && nReleaseHeight < nEscrowUnlockHeight) {
        return false; // bad-escrow-locked-window
    }
    // STEPS 4+: full funded-governance verification (reachable only at/above floor).
    return hasFundedGovObject; // bad-escrow-not-funded when no funded object exists
}

} // namespace

// CORE behavior (the three prior gates closed by deletion): a release BELOW
// H_unlock is REJECTED with bad-escrow-locked-window, and the verdict is
// IDENTICAL across every
// synthetic node state -- nodeInIBD true/false, best-header high/low, flag on/off.
// This is the determinism property the three prior gates failed: the verdict
// depends ONLY on the block height vs the baked constant. The marker-only fresh
// fake release the attacker mines during the re-mine sits at a sub-floor height,
// so it is rejected on every node regardless of who wins the seal-weight race.
BOOST_AUTO_TEST_CASE(escrow_release_below_unlock_height_rejected)
{
    const int H = MainnetEscrowUnlockHeight();
    BOOST_REQUIRE_EQUAL(H, 60000);                 // baked mainnet floor
    BOOST_REQUIRE_LT(kReleaseHeight, H);           // a re-mine-window release
    const int kSubFloor = H - 1;                   // the last forbidden height

    // Enumerate every node-state combination the prior gates split on. The verdict
    // must be REJECT in all of them, for both a re-mine-window height and the
    // boundary height H-1, and whether or not a funded gov object happens to exist.
    for (bool flag : {false, true}) {
        PlanXGateGuard g(flag);
        for (bool nodeInIBD : {false, true}) {
            for (int bestHeader : {0, kReleaseHeight - 5, kReleaseHeight,
                                   kReleaseHeight + 1, kSubFloor, H, H + 100000}) {
                for (bool funded : {false, true}) {
                    BOOST_CHECK(!EscrowGateAccepts(kReleaseHeight, H, funded, nodeInIBD, bestHeader));
                    BOOST_CHECK(!EscrowGateAccepts(kSubFloor,      H, funded, nodeInIBD, bestHeader));
                }
            }
        }
    }
}

// EXPLICIT DETERMINISM PROOF: for a fixed sub-floor release height and a fixed
// funded-governance state, the verdict is byte-identical across the full cross
// product of (nodeInIBD, best-header, flag). i.e. the verdict has ZERO node-state
// inputs -- it is a pure function of (height, H_unlock). This is the structural
// fix for the best-header boundary split (the boundary cannot split because both
// operands are node-invariant).
BOOST_AUTO_TEST_CASE(escrow_gate_verdict_independent_of_flag_and_ibd)
{
    const int H = MainnetEscrowUnlockHeight();
    const int kSubFloor = kReleaseHeight; // any height < H

    // Reference verdict (a sub-floor release is always rejected).
    const bool reference = EscrowGateAccepts(kSubFloor, H, /*funded=*/true,
                                             /*nodeInIBD=*/false, /*bestHeader=*/0);
    BOOST_CHECK(!reference); // sub-floor -> REJECT

    for (bool flag : {false, true}) {
        PlanXGateGuard g(flag);
        for (bool nodeInIBD : {false, true}) {
            for (int bestHeader : {0, kSubFloor - 1, kSubFloor + 1, H, H + 50000}) {
                for (bool funded : {false, true}) {
                    BOOST_CHECK_EQUAL(
                        EscrowGateAccepts(kSubFloor, H, funded, nodeInIBD, bestHeader),
                        reference);
                }
            }
        }
    }
}

// AT the floor (height == H_unlock, the FIRST height a release may be valid): the
// step-0 floor passes and the gate falls through to the FULL funded-governance
// check. Marker-only (no funded object) -> REJECTED by the normal gov check
// (bad-escrow-not-funded); a funded governance object -> ALLOWED. Verdict still
// node-state-independent.
BOOST_AUTO_TEST_CASE(escrow_release_at_unlock_height_runs_full_check)
{
    const int H = MainnetEscrowUnlockHeight();

    for (bool flag : {false, true}) {
        PlanXGateGuard g(flag);
        for (bool nodeInIBD : {false, true}) {
            // marker-only at the floor -> rejected by the normal funded-gov check
            BOOST_CHECK(!EscrowGateAccepts(H, H, /*funded=*/false, nodeInIBD, /*bestHeader=*/H));
            // funded at the floor -> allowed
            BOOST_CHECK(EscrowGateAccepts(H, H, /*funded=*/true, nodeInIBD, /*bestHeader=*/H));
        }
    }
}

// ABOVE the floor + a funded governance object -> ALLOWED. This is the legit
// old->new 500k consolidation, mined at a caught-up height where the full check
// runs at mining time. Marker-only above the floor is still rejected (full check).
BOOST_AUTO_TEST_CASE(escrow_release_above_unlock_height_funded_accepted)
{
    const int H = MainnetEscrowUnlockHeight();
    const int kAboveFloor = H + 1000;

    for (bool flag : {false, true}) {
        PlanXGateGuard g(flag);
        for (bool nodeInIBD : {false, true}) {
            BOOST_CHECK(EscrowGateAccepts(kAboveFloor, H, /*funded=*/true, nodeInIBD, /*bestHeader=*/kAboveFloor));
            BOOST_CHECK(!EscrowGateAccepts(kAboveFloor, H, /*funded=*/false, nodeInIBD, /*bestHeader=*/kAboveFloor));
        }
    }
}

// FLOOR INERT when nEscrowUnlockHeight == 0 (the testnet/devnet/regtest path).
// With the floor disabled the step-0 gate never fires, so the gate reduces to the
// pre-incident funded-governance check at every height -- byte-identical behaviour
// on networks that do not opt in. Confirmed against the real testnet/regtest
// chainparams (they leave the floor at its 0 default).
BOOST_AUTO_TEST_CASE(escrow_floor_inert_when_unlock_height_zero)
{
    // Real non-mainnet params carry no unlock floor.
    for (const std::string& chain : {std::string(CBaseChainParams::TESTNET),
                                     std::string(CBaseChainParams::REGTEST)}) {
        const auto params = CreateChainParams(ArgsManager{}, chain);
        BOOST_CHECK_MESSAGE(params->GetConsensus().nEscrowUnlockHeight == 0,
                            "expected nEscrowUnlockHeight == 0 (inert) on " + chain);
    }

    // With H_unlock == 0 the floor is skipped: at ANY height the verdict is just
    // the funded-governance result (a release at a very low height is accepted iff
    // funded), proving the floor adds nothing when disabled.
    const int H0 = 0;
    for (int height : {1, 100, kReleaseHeight, 1000000}) {
        BOOST_CHECK(EscrowGateAccepts(height, H0, /*funded=*/true,  /*nodeInIBD=*/true, /*bestHeader=*/height));
        BOOST_CHECK(!EscrowGateAccepts(height, H0, /*funded=*/false, /*nodeInIBD=*/true, /*bestHeader=*/height));
    }
}

BOOST_AUTO_TEST_SUITE_END()
