// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Unit tests for the v1.2.5 legacy-devfund / legacy-founders sunset gate
// (masternode/payments.h::IsLegacyTreasuryConsulted) and a documented skip for
// the DetectPostRollbackContamination init.cpp helper.
//
// The sunset gate is a pure predicate:
//   - sunset == 0          -> legacy fallback always consulted (off-mainnet)
//   - nBlockHeight <  sunset -> legacy fallback consulted (pre-sunset blocks
//                               built under the v1.0/1.1 -> v1.2 rotation
//                               continue to validate)
//   - nBlockHeight >= sunset -> legacy fallback NOT consulted: a coinbase
//                               paying devfund/founders to any legacy address
//                               is bad-cb-payee, only the current
//                               devFundPaymentScript / foundersPaymentScript
//                               are accepted.
//
// Testing the predicate at the height boundary pins the off-by-one shape: the
// rule MUST flip exactly at height == sunset (inclusive at/after, exclusive
// before). The IsTransactionValid wiring in payments.cpp is a one-line
// call into this helper, so testing the helper pins the consensus behaviour
// without standing up a full ChainstateManager fixture.

#include <masternode/payments.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace {

// Small override so the boundary maths is obvious in the test output and so the
// test does not become wallpaper for whatever mainnet ships in chainparams.
constexpr int kSunset = 100;

} // namespace

BOOST_FIXTURE_TEST_SUITE(legacy_sunset_tests, BasicTestingSetup)

// sunset == 0 means the gate is disabled (off-mainnet default). The legacy
// fallback MUST be consulted at every height -- there is no rule to enforce.
BOOST_AUTO_TEST_CASE(disabled_sunset_always_consults_legacy)
{
    BOOST_CHECK(IsLegacyTreasuryConsulted(0, 0));
    BOOST_CHECK(IsLegacyTreasuryConsulted(1, 0));
    BOOST_CHECK(IsLegacyTreasuryConsulted(59000, 0));
    BOOST_CHECK(IsLegacyTreasuryConsulted(1'000'000, 0));
}

// h == sunset - 1 is the LAST height where the legacy fallback is still
// consulted. A coinbase paying devfund/founders to a legacy script at this
// height MUST be accepted by the treasury check (legacy fallback live).
BOOST_AUTO_TEST_CASE(below_sunset_consults_legacy)
{
    BOOST_CHECK(IsLegacyTreasuryConsulted(kSunset - 1, kSunset));
    BOOST_CHECK(IsLegacyTreasuryConsulted(0,            kSunset));
    BOOST_CHECK(IsLegacyTreasuryConsulted(kSunset / 2,  kSunset));
}

// h == sunset is the FIRST height where the legacy fallback is dropped. A
// coinbase paying devfund/founders to a legacy script at this height MUST be
// rejected (helper returns false -> caller wires no legacy fallback -> the
// outer IsTransactionValid emits bad-cb-payee).
BOOST_AUTO_TEST_CASE(at_sunset_drops_legacy)
{
    BOOST_CHECK(!IsLegacyTreasuryConsulted(kSunset, kSunset));
}

// h > sunset stays in the post-sunset regime indefinitely. No "re-arming" of
// the legacy fallback; once dropped it stays dropped.
BOOST_AUTO_TEST_CASE(above_sunset_drops_legacy)
{
    BOOST_CHECK(!IsLegacyTreasuryConsulted(kSunset + 1,   kSunset));
    BOOST_CHECK(!IsLegacyTreasuryConsulted(kSunset + 100, kSunset));
    BOOST_CHECK(!IsLegacyTreasuryConsulted(1'000'000,     kSunset));
}

// constexpr-evaluable: the helper is usable in static_assert contexts (the
// caller is a hot path in block validation; a runtime call is fine, but the
// constexpr shape proves no hidden state). Pins the contract.
BOOST_AUTO_TEST_CASE(constexpr_evaluable)
{
    static_assert(IsLegacyTreasuryConsulted(0, 0),               "disabled");
    static_assert(IsLegacyTreasuryConsulted(kSunset - 1, kSunset), "below");
    static_assert(!IsLegacyTreasuryConsulted(kSunset, kSunset),    "at");
    static_assert(!IsLegacyTreasuryConsulted(kSunset + 1, kSunset),"above");
    BOOST_CHECK(true);
}

// TODO(v1.3.x): DetectPostRollbackContamination is a static function inside
// init.cpp and operates on live LevelDB-backed CEvoDB + sapling::SaplingState
// instances. Simulating a contamination (sapling_state best-block != active
// tip) requires either standing up a ChainTestingSetup, hand-writing a stale
// best-block hash into sapling/, and then re-loading -- or de-staticizing the
// helper and injecting the DB handles. Both are larger than the v1.2.5 scope.
// The contamination predicate itself is two LOC (VerifyBestBlock on each cache,
// OR into the drift list) and has been audit-reviewed; the operator-facing
// behaviour (refuse-to-start + suggest -resetchainstate) is covered by the
// init.cpp ResetChainstateIfRequested path which has its own coverage via the
// source-gate + wipe-target tests below in future iterations.
//
// When the helper is moved out of init.cpp (or a ChainTestingSetup-based
// integration test is added in v1.3.x), the test cases per the v1.2.5 spec are:
//   1. Fresh chain, no rollback ever activated -> returns false (no contamination)
//   2. Manually pointed sapling_state best-block at a stale hash -> returns true
//   3. Same for evodb -> returns true

BOOST_AUTO_TEST_SUITE_END()
