// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key_io.h>
#include <random.h>
#include <rust/bridge.h>
#include <sapling/sapling_address.h>
#include <sapling/sapling_tx_payload.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <wallet/sapling_keymanager.h>
#include <wallet/sapling_send.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <optional>
#include <stdexcept>
#include <string>

namespace wallet {
namespace {

struct SaplingSendSetup : public TestChain100Setup {
    std::unique_ptr<CWallet> wallet;
    sapling::SaplingPaymentAddress external1, internal1, external2;
    int note_index{0};

    SaplingSendSetup()
    {
        CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
        wallet = CreateSyncedWallet(*m_node.chain, m_node.chainman->ActiveChain(), m_args, coinbaseKey);

        auto& km = wallet->GetSaplingKeyManager();
        const sapling::SaplingExtendedSpendingKey sk1 = MakeKey(1), sk2 = MakeKey(2);
        BOOST_REQUIRE(km.AddSpendingKey(sk1));
        external1 = AddressOf(sk1, /*internal=*/false);
        internal1 = AddressOf(sk1, /*internal=*/true);
        BOOST_REQUIRE(km.AddSpendingKey(sk2));
        external2 = AddressOf(sk2, /*internal=*/false);
    }

    static sapling::SaplingExtendedSpendingKey MakeKey(uint8_t seed_byte)
    {
        std::array<uint8_t, 32> seed;
        seed.fill(seed_byte);
        sapling::SaplingExtendedSpendingKey sk;
        sk.key = sapling::zip32::xsk_master(rust::Slice<const uint8_t>(seed.data(), seed.size()));
        return sk;
    }

    // The default address of the key's external or internal (ZIP 316) FVK
    static sapling::SaplingPaymentAddress AddressOf(const sapling::SaplingExtendedSpendingKey& sk, bool internal)
    {
        auto fvk = sapling::zip32::xsk_to_fvk(sk.key);
        auto dk = sapling::zip32::xsk_to_dk(sk.key);
        if (internal) {
            auto derived = sapling::zip32::derive_internal_fvk(fvk, dk);
            fvk = derived.fvk;
            dk = derived.dk;
        }
        const auto bytes = sapling::zip32::fvk_default_address(fvk, dk);
        sapling::SaplingPaymentAddress addr;
        std::copy(bytes.begin(), bytes.begin() + 11, addr.d.begin());
        std::copy(bytes.begin() + 11, bytes.end(), addr.pk_d.begin());
        return addr;
    }

    uint256 AddNote(const sapling::SaplingPaymentAddress& to, CAmount value, int height, bool spent = false)
    {
        auto& km = wallet->GetSaplingKeyManager();
        SaplingNoteData nd;
        nd.ivk = *km.GetIvk(to);
        nd.recipient = to;
        nd.value = value;
        nd.txid = InsecureRand256();
        nd.outputIndex = note_index++;
        nd.nullifier = InsecureRand256();
        nd.blockHeight = height;
        nd.witnessData = {1}; // planning does not read the witness
        nd.isSpent = spent;
        const uint256 cmu = InsecureRand256();
        km.LoadNote(cmu, nd);
        return cmu;
    }

    int TipHeight()
    {
        LOCK(wallet->cs_wallet);
        return wallet->GetLastBlockHeight();
    }

    static SaplingSendRecipient To(const sapling::SaplingPaymentAddress& addr, CAmount amount, bool subtract_fee = false)
    {
        SaplingSendRecipient r;
        r.address = EncodeSaplingAddress(addr);
        r.amount = amount;
        r.subtract_fee = subtract_fee;
        return r;
    }

    SaplingSendRecipient ToTransparent(CAmount amount)
    {
        SaplingSendRecipient r;
        r.address = EncodeDestination(PKHash(coinbaseKey.GetPubKey()));
        r.amount = amount;
        return r;
    }
};

bool HasMessage(const std::runtime_error& e, const std::string& text)
{
    return std::string{e.what()}.find(text) != std::string::npos;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(sapling_send_tests, SaplingSendSetup)

BOOST_AUTO_TEST_CASE(list_spendable_notes)
{
    const int tip = TipHeight();
    const uint256 a = AddNote(external1, 3 * COIN, tip);
    const uint256 change = AddNote(internal1, 2 * COIN, tip - 5);
    AddNote(external2, 1 * COIN, -1);                      // unconfirmed
    AddNote(external2, 4 * COIN, tip - 1, /*spent=*/true); // spent

    auto notes = ListSpendableSaplingNotes(*wallet, /*minconf=*/1);
    BOOST_REQUIRE_EQUAL(notes.size(), 2U);
    std::sort(notes.begin(), notes.end(), [](const auto& x, const auto& y) { return x.value > y.value; });
    BOOST_CHECK(notes[0].cmu == a);
    BOOST_CHECK(!notes[0].is_change);
    BOOST_CHECK_EQUAL(notes[0].depth, 1);
    BOOST_CHECK_EQUAL(notes[0].address, EncodeSaplingAddress(external1));
    BOOST_CHECK(notes[1].cmu == change);
    BOOST_CHECK(notes[1].is_change);
    BOOST_CHECK_EQUAL(notes[1].depth, 6);

    // minconf
    BOOST_CHECK_EQUAL(ListSpendableSaplingNotes(*wallet, /*minconf=*/2).size(), 1U);
}

BOOST_AUTO_TEST_CASE(plan_combines_notes_from_several_addresses)
{
    const int tip = TipHeight();
    const uint256 n3 = AddNote(external1, 3 * COIN, tip);
    const uint256 n2 = AddNote(internal1, 2 * COIN, tip);
    const uint256 n1 = AddNote(external2, 1 * COIN, tip);

    SaplingSendSource source;
    source.shielded = true;

    // 4 KRGN needs the two largest notes, on two different addresses
    auto plan = PlanSaplingSend(*wallet, source, {To(external2, 4 * COIN)}, /*minconf=*/1);
    BOOST_CHECK_EQUAL(plan.notes.size(), 2U);
    BOOST_CHECK(plan.notes[0] == n3);
    BOOST_CHECK(plan.notes[1] == n2);
    BOOST_CHECK(plan.coins.empty());
    BOOST_CHECK_EQUAL(plan.fee, CalculateSaplingFee(2, 2)); // recipient + change
    BOOST_CHECK_EQUAL(plan.input_total, 5 * COIN);
    BOOST_CHECK_EQUAL(plan.change, 5 * COIN - 4 * COIN - plan.fee);
    BOOST_REQUIRE_EQUAL(plan.amounts.size(), 1U);
    BOOST_CHECK_EQUAL(plan.amounts[0], 4 * COIN);
    BOOST_REQUIRE_EQUAL(plan.sources.size(), 2U);
    BOOST_CHECK_EQUAL(plan.sources[0].address, EncodeSaplingAddress(external1));
    BOOST_CHECK(!plan.sources[0].is_change);
    BOOST_CHECK_EQUAL(plan.sources[1].address, EncodeSaplingAddress(internal1));
    BOOST_CHECK(plan.sources[1].is_change);

    // Every note, across both spending keys
    plan = PlanSaplingSend(*wallet, source, {To(external2, 5 * COIN + COIN / 2)}, /*minconf=*/1);
    BOOST_CHECK_EQUAL(plan.notes.size(), 3U);
    BOOST_CHECK(plan.notes[2] == n1);
    BOOST_CHECK_EQUAL(plan.fee, CalculateSaplingFee(3, 2));

    // More than the shielded balance
    BOOST_CHECK_EXCEPTION(PlanSaplingSend(*wallet, source, {To(external2, 6 * COIN)}, 1), std::runtime_error,
                          [](const std::runtime_error& e) { return HasMessage(e, "Insufficient shielded funds"); });
}

BOOST_AUTO_TEST_CASE(plan_selected_notes)
{
    const int tip = TipHeight();
    AddNote(external1, 3 * COIN, tip);
    const uint256 n1 = AddNote(external2, 1 * COIN, tip);

    SaplingSendSource source;
    source.shielded = true;
    source.notes = {n1};

    // Only the selected note is used, even though a larger one exists
    auto plan = PlanSaplingSend(*wallet, source, {To(external1, COIN / 2)}, 1);
    BOOST_REQUIRE_EQUAL(plan.notes.size(), 1U);
    BOOST_CHECK(plan.notes[0] == n1);
    BOOST_CHECK_EQUAL(plan.change, COIN / 2 - CalculateSaplingFee(1, 2));

    BOOST_CHECK_EXCEPTION(PlanSaplingSend(*wallet, source, {To(external1, 2 * COIN)}, 1), std::runtime_error,
                          [](const std::runtime_error& e) { return HasMessage(e, "selected shielded inputs"); });

    // A selected note that cannot be spent
    source.notes = {n1, AddNote(external1, 1 * COIN, tip, /*spent=*/true)};
    BOOST_CHECK_EXCEPTION(PlanSaplingSend(*wallet, source, {To(external1, COIN / 2)}, 1), std::runtime_error,
                          [](const std::runtime_error& e) { return HasMessage(e, "can no longer be spent"); });
}

BOOST_AUTO_TEST_CASE(plan_subtract_fee_and_fee_convergence)
{
    const int tip = TipHeight();
    AddNote(external1, 3 * COIN, tip);
    AddNote(external2, 1 * COIN, tip);

    SaplingSendSource source;
    source.shielded = true;

    // Send everything: the fee comes out of the amount, no change
    auto plan = PlanSaplingSend(*wallet, source, {To(external2, 4 * COIN, /*subtract_fee=*/true)}, 1);
    BOOST_CHECK_EQUAL(plan.notes.size(), 2U);
    BOOST_CHECK_EQUAL(plan.change, 0);
    BOOST_CHECK_EQUAL(plan.fee, CalculateSaplingFee(2, 2));
    BOOST_CHECK_EQUAL(plan.amounts[0], 4 * COIN - plan.fee);

    // Fee split between two recipients; the first pays the remainder
    const CAmount fee = CalculateSaplingFee(2, 2);
    plan = PlanSaplingSend(*wallet, source, {To(external2, 2 * COIN, true), ToTransparent(2 * COIN)}, 1);
    BOOST_CHECK_EQUAL(plan.fee, fee);
    BOOST_CHECK_EQUAL(plan.amounts[0], 2 * COIN - fee);
    BOOST_CHECK_EQUAL(plan.amounts[1], 2 * COIN);

    // Exactly one note's worth needs one spend; one satoshi more needs a
    // second spend, which raises the fee
    plan = PlanSaplingSend(*wallet, source, {To(external2, 3 * COIN - CalculateSaplingFee(1, 2))}, 1);
    BOOST_CHECK_EQUAL(plan.notes.size(), 1U);
    BOOST_CHECK_EQUAL(plan.change, 0);
    BOOST_CHECK_EQUAL(plan.fee, CalculateSaplingFee(1, 2));
    plan = PlanSaplingSend(*wallet, source, {To(external2, 3 * COIN - CalculateSaplingFee(1, 2) + 1)}, 1);
    BOOST_CHECK_EQUAL(plan.notes.size(), 2U);
    BOOST_CHECK_EQUAL(plan.fee, CalculateSaplingFee(2, 2));

    // Two shielded recipients and an amount where the fee with a change output
    // leaves no change, while the fee without one would leave change: the plan
    // must settle on the higher fee and no change, never on a fee too low for
    // the outputs it creates
    const CAmount fee_with_change = CalculateSaplingFee(1, 3);
    plan = PlanSaplingSend(*wallet, source, {To(external2, COIN), To(external1, 2 * COIN - fee_with_change)}, 1);
    BOOST_CHECK_EQUAL(plan.notes.size(), 1U);
    BOOST_CHECK_EQUAL(plan.change, 0);
    BOOST_CHECK_EQUAL(plan.fee, fee_with_change);
    BOOST_CHECK_EQUAL(plan.input_total, plan.amounts[0] + plan.amounts[1] + plan.fee);
}

BOOST_AUTO_TEST_CASE(plan_transparent_source)
{
    SaplingSendSource source; // transparent, automatic selection
    auto plan = PlanSaplingSend(*wallet, source, {To(external1, COIN)}, 1);
    BOOST_CHECK(!plan.coins.empty());
    BOOST_CHECK(plan.notes.empty());
    BOOST_CHECK_EQUAL(plan.fee + plan.change + COIN, plan.input_total);
    BOOST_CHECK_EQUAL(plan.fee, CalculateSaplingFee(0, 2));
    BOOST_REQUIRE_EQUAL(plan.sources.size(), 1U);
    BOOST_CHECK_EQUAL(plan.sources[0].address, EncodeDestination(PKHash(coinbaseKey.GetPubKey())));

    // Selected coins only
    source.coins = plan.coins;
    BOOST_CHECK(PlanSaplingSend(*wallet, source, {To(external1, COIN)}, 1).coins == plan.coins);
    source.coins.emplace_back(InsecureRand256(), 0);
    BOOST_CHECK_EXCEPTION(PlanSaplingSend(*wallet, source, {To(external1, COIN)}, 1), std::runtime_error,
                          [](const std::runtime_error& e) { return HasMessage(e, "can no longer be spent"); });

    // t->t is not a shielded transaction
    BOOST_CHECK_EXCEPTION(PlanSaplingSend(*wallet, SaplingSendSource{}, {ToTransparent(COIN)}, 1), std::runtime_error,
                          [](const std::runtime_error& e) { return HasMessage(e, "needs a shielded source or recipient"); });
}

BOOST_AUTO_TEST_CASE(plan_rejects_invalid_recipients)
{
    AddNote(external1, 3 * COIN, TipHeight());
    SaplingSendSource source;
    source.shielded = true;

    auto memo_to_transparent = ToTransparent(COIN);
    memo_to_transparent.memo = {'h', 'i'};
    BOOST_CHECK_EXCEPTION(PlanSaplingSend(*wallet, source, {memo_to_transparent}, 1), std::runtime_error,
                          [](const std::runtime_error& e) { return HasMessage(e, "Memo can only be sent to shielded addresses"); });

    auto long_memo = To(external2, COIN);
    long_memo.memo.assign(513, 'x');
    BOOST_CHECK_EXCEPTION(PlanSaplingSend(*wallet, source, {long_memo}, 1), std::runtime_error,
                          [](const std::runtime_error& e) { return HasMessage(e, "Memo too long"); });

    BOOST_CHECK_EXCEPTION(PlanSaplingSend(*wallet, source, {}, 1), std::runtime_error,
                          [](const std::runtime_error& e) { return HasMessage(e, "No recipients"); });

    // The fee cannot exceed the subtracting recipient's amount
    BOOST_CHECK_EXCEPTION(PlanSaplingSend(*wallet, source, {To(external2, 1000, /*subtract_fee=*/true)}, 1), std::runtime_error,
                          [](const std::runtime_error& e) { return HasMessage(e, "too small to pay the fee"); });
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
