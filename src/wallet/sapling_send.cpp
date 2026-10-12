// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/sapling_send.h>

#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <logging.h>
#include <policy/policy.h>
#include <random.h>
#include <rust/bridge.h>
#include <sapling/sapling_address.h>
#include <sapling/sapling_init.h>
#include <sapling/sapling_transaction_builder.h>
#include <sapling/sapling_tx_payload.h>
#include <serialize.h>
#include <support/cleanse.h>
#include <tinyformat.h>
#include <util/moneystr.h>
#include <wallet/coincontrol.h>
#include <wallet/sapling_keymanager.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>

namespace wallet {
namespace {

// On-wire sizes, for the transaction size estimate.
constexpr size_t SPEND_DESCRIPTION_SIZE = 384;
constexpr size_t OUTPUT_DESCRIPTION_SIZE = 948;
constexpr size_t TRANSPARENT_INPUT_SIZE = 148;
constexpr size_t TRANSPARENT_OUTPUT_SIZE = 34;
constexpr size_t SAPLING_TX_OVERHEAD = 120;

struct ParsedRecipient {
    bool shielded{false};
    sapling::SaplingPaymentAddress sapling_addr;
    CTxDestination dest{CNoDestination{}};
};

std::array<uint8_t, 43> AddressBytes(const sapling::SaplingPaymentAddress& addr)
{
    std::array<uint8_t, 43> bytes;
    std::copy(addr.d.begin(), addr.d.end(), bytes.begin());
    std::copy(addr.pk_d.begin(), addr.pk_d.end(), bytes.begin() + 11);
    return bytes;
}

struct Candidate {
    CAmount value{0};
    std::string address;
    bool is_change{false};
    COutPoint outpoint;
    uint256 cmu;
};

std::vector<ParsedRecipient> ParseRecipients(const std::vector<SaplingSendRecipient>& recipients, CAmount& total)
{
    if (recipients.empty()) {
        throw std::runtime_error("No recipients specified");
    }
    std::vector<ParsedRecipient> parsed;
    total = 0;
    for (const auto& r : recipients) {
        ParsedRecipient p;
        if (r.amount <= 0 || !MoneyRange(r.amount)) {
            throw std::runtime_error("Invalid recipient amount");
        }
        p.shielded = DecodeSaplingAddress(r.address, p.sapling_addr);
        if (!p.shielded) {
            p.dest = DecodeDestination(r.address);
            if (!IsValidDestination(p.dest)) {
                throw std::runtime_error("Invalid recipient address: " + r.address);
            }
        }
        if (!r.memo.empty()) {
            if (!p.shielded) {
                throw std::runtime_error("Memo can only be sent to shielded addresses");
            }
            if (r.memo.size() > 512) {
                throw std::runtime_error("Memo too long (max 512 bytes)");
            }
        }
        if (r.amount > MAX_MONEY - total) {
            throw std::runtime_error("Total send amount out of range");
        }
        total += r.amount;
        parsed.push_back(std::move(p));
    }
    return parsed;
}

} // namespace

std::vector<SaplingSpendableNote> ListSpendableSaplingNotes(const CWallet& wallet, int minconf)
{
    LOCK(wallet.cs_wallet);
    const auto& km = wallet.GetSaplingKeyManager();
    const int tip_height = wallet.GetLastBlockHeight();
    const auto internal_ivks = km.GetInternalIvks();

    std::vector<SaplingSpendableNote> result;
    for (const auto& [cmu, nd] : km.GetUnspentNotesWithKeys()) {
        if (!km.CanSpend(nd.recipient)) continue;
        const int depth = tip_height - nd.blockHeight + 1;
        if (depth < minconf) continue;

        SaplingSpendableNote note;
        note.cmu = cmu;
        note.txid = nd.txid;
        note.output_index = nd.outputIndex;
        note.value = nd.value;
        note.address = EncodeSaplingAddress(nd.recipient);
        auto ivk = km.GetIvk(nd.recipient);
        note.is_change = ivk && internal_ivks.count(*ivk);
        note.depth = depth;
        auto it = wallet.mapWallet.find(nd.txid);
        if (it != wallet.mapWallet.end()) note.time = it->second.GetTxTime();
        result.push_back(std::move(note));
    }
    return result;
}

SaplingSendPlan PlanSaplingSend(CWallet& wallet, const SaplingSendSource& source,
                                const std::vector<SaplingSendRecipient>& recipients,
                                int minconf, std::optional<CAmount> fee)
{
    LOCK(wallet.cs_wallet);

    if (minconf < 0) {
        throw std::runtime_error("minconf must be non-negative");
    }
    if (fee && (*fee <= 0 || !MoneyRange(*fee))) {
        throw std::runtime_error("Fee must be positive");
    }

    CAmount total_send{0};
    const auto parsed = ParseRecipients(recipients, total_send);
    size_t n_shielded_outputs{0};
    size_t n_transparent_outputs{0};
    size_t n_subtract{0};
    for (size_t i = 0; i < parsed.size(); ++i) {
        (parsed[i].shielded ? n_shielded_outputs : n_transparent_outputs)++;
        if (recipients[i].subtract_fee) n_subtract++;
    }
    if (!source.shielded && n_shielded_outputs == 0) {
        throw std::runtime_error("A shielded transaction needs a shielded source or recipient; send transparent coins to transparent addresses with a regular transaction");
    }

    // Candidate inputs, largest first
    std::vector<Candidate> candidates;
    const bool explicit_selection = source.shielded ? !source.notes.empty() : !source.coins.empty();
    if (source.shielded) {
        std::set<uint256> wanted(source.notes.begin(), source.notes.end());
        for (const auto& note : ListSpendableSaplingNotes(wallet, minconf)) {
            if (explicit_selection && !wanted.erase(note.cmu)) continue;
            Candidate c;
            c.value = note.value;
            c.address = note.address;
            c.is_change = note.is_change;
            c.cmu = note.cmu;
            candidates.push_back(std::move(c));
        }
        if (!wanted.empty()) {
            throw std::runtime_error(strprintf("%d selected note(s) can no longer be spent (already spent, in use by another transaction, or not confirmed)", wanted.size()));
        }
    } else {
        std::set<COutPoint> wanted(source.coins.begin(), source.coins.end());
        CCoinControl coin_control;
        coin_control.m_min_depth = minconf;
        for (const COutput& coin : AvailableCoins(wallet, &coin_control).all()) {
            if (explicit_selection && !wanted.erase(coin.outpoint)) continue;
            Candidate c;
            c.value = coin.txout.nValue;
            CTxDestination dest;
            if (ExtractDestination(coin.txout.scriptPubKey, dest)) c.address = EncodeDestination(dest);
            c.outpoint = coin.outpoint;
            candidates.push_back(std::move(c));
        }
        if (!wanted.empty()) {
            throw std::runtime_error(strprintf("%d selected coin(s) can no longer be spent (already spent, locked, or not confirmed)", wanted.size()));
        }
    }
    std::sort(candidates.begin(), candidates.end(), [](const Candidate& a, const Candidate& b) {
        if (a.value != b.value) return a.value > b.value;
        if (a.cmu != b.cmu) return a.cmu < b.cmu;
        return a.outpoint < b.outpoint;
    });

    CAmount available{0};
    for (const auto& c : candidates) {
        if (!MoneyRange(available + c.value)) throw std::runtime_error("Balance out of range");
        available += c.value;
    }

    // Sapling fee: per spend and per shielded output (at least 2 outputs,
    // the builder pads). Transparent inputs and outputs are not charged.
    auto calc_fee = [&](size_t n_inputs, bool shielded_change) -> CAmount {
        if (fee) return *fee;
        const size_t n_outputs = n_shielded_outputs + (shielded_change ? 1 : 0);
        return CalculateSaplingFee(source.shielded ? n_inputs : 0, std::max<size_t>(2, n_outputs));
    };

    // Pick inputs until the fee stops growing: the fee depends on the number
    // of spends and on whether there is a change output. The fee only ever
    // grows, starting from the smallest possible one; otherwise an exact
    // amount could flip between "change output" and "no change output"
    // forever. The fee each pass needs is at most the one selected for, so
    // the final fee always covers the final selection. This terminates
    // because the fee is bounded by spending every candidate.
    size_t n_inputs{0};
    CAmount selected{0};
    CAmount tx_fee = calc_fee(source.shielded ? 1 : 0, /*shielded_change=*/false);
    while (true) {
        const CAmount target = total_send + (n_subtract ? 0 : tx_fee);
        n_inputs = 0;
        selected = 0;
        for (const auto& c : candidates) {
            if (!explicit_selection && selected >= target) break;
            selected += c.value;
            n_inputs++;
        }
        if (selected < target) {
            const std::string pool = source.shielded ? "shielded" : "transparent";
            if (explicit_selection) {
                throw std::runtime_error(strprintf("The selected %s inputs (%s) do not cover the amount plus fee (%s)",
                    pool, FormatMoney(selected), FormatMoney(target)));
            }
            throw std::runtime_error(strprintf("Insufficient %s funds: %s available, %s needed including the fee",
                pool, FormatMoney(available), FormatMoney(target)));
        }
        const bool has_change = selected > target;
        const CAmount needed_fee = calc_fee(n_inputs, source.shielded && has_change);
        if (needed_fee <= tx_fee) break;
        tx_fee = needed_fee;
    }

    SaplingSendPlan plan;
    plan.input_total = selected;
    plan.change = selected - total_send - (n_subtract ? 0 : tx_fee);
    plan.fee = tx_fee;

    // Recipient amounts after the fee, Bitcoin style: split evenly, the
    // first subtracting recipient also pays the remainder.
    plan.amounts.reserve(recipients.size());
    bool first_subtract = true;
    for (size_t i = 0; i < recipients.size(); ++i) {
        CAmount amount = recipients[i].amount;
        if (recipients[i].subtract_fee) {
            amount -= tx_fee / static_cast<CAmount>(n_subtract);
            if (first_subtract) {
                amount -= tx_fee % static_cast<CAmount>(n_subtract);
                first_subtract = false;
            }
            if (amount <= 0) {
                throw std::runtime_error(strprintf("The amount for %s is too small to pay the fee", recipients[i].address));
            }
        }
        if (!parsed[i].shielded && IsDust(CTxOut(amount, GetScriptForDestination(parsed[i].dest)), wallet.chain().relayDustFee())) {
            throw std::runtime_error(strprintf("The amount for %s is too small (dust)", recipients[i].address));
        }
        plan.amounts.push_back(amount);
    }

    // Transparent change too small to relay goes to the fee instead
    bool transparent_change = !source.shielded && plan.change > 0;
    if (transparent_change && IsDust(CTxOut(plan.change, CScript() << std::vector<unsigned char>(24, 0)), wallet.chain().relayDustFee())) {
        plan.fee += plan.change;
        plan.change = 0;
        transparent_change = false;
    }
    if (plan.fee > wallet.m_default_max_tx_fee) {
        throw std::runtime_error(strprintf("Fee (%s) exceeds the wallet maximum (%s)", FormatMoney(plan.fee), FormatMoney(wallet.m_default_max_tx_fee)));
    }

    const size_t n_spends = source.shielded ? n_inputs : 0;
    const size_t n_outputs = std::max<size_t>(2, n_shielded_outputs + (source.shielded && plan.change > 0 ? 1 : 0));
    const size_t estimated_size = SAPLING_TX_OVERHEAD
        + (source.shielded ? 0 : n_inputs) * TRANSPARENT_INPUT_SIZE
        + (n_transparent_outputs + (transparent_change ? 1 : 0)) * TRANSPARENT_OUTPUT_SIZE
        + n_spends * SPEND_DESCRIPTION_SIZE
        + n_outputs * OUTPUT_DESCRIPTION_SIZE;
    if (estimated_size > MAX_SAPLING_TX_EXTRA_PAYLOAD) {
        throw std::runtime_error(strprintf("The transaction would need %d inputs and be too large; send a smaller amount or select fewer inputs", n_inputs));
    }

    std::map<std::string, SaplingSendInputGroup> groups;
    for (size_t i = 0; i < n_inputs; ++i) {
        const auto& c = candidates[i];
        if (source.shielded) {
            plan.notes.push_back(c.cmu);
        } else {
            plan.coins.push_back(c.outpoint);
        }
        auto& group = groups[c.address];
        group.address = c.address;
        group.is_change = c.is_change;
        group.count++;
        group.value += c.value;
    }
    for (auto& [address, group] : groups) plan.sources.push_back(std::move(group));
    std::sort(plan.sources.begin(), plan.sources.end(), [](const SaplingSendInputGroup& a, const SaplingSendInputGroup& b) {
        if (a.value != b.value) return a.value > b.value;
        return a.address < b.address;
    });
    return plan;
}

std::string SendSapling(CWallet& wallet, const SaplingSendSource& source,
                        const std::vector<SaplingSendRecipient>& recipients,
                        int minconf, std::optional<CAmount> fee)
{
    // Broadcasting a Sapling spend reveals its nullifiers; wait until the
    // wallet has seen every block that may spend our notes.
    if (wallet.chain().isInitialBlockDownload()) {
        throw std::runtime_error("Cannot send while in initial block download. Wait for sync to complete.");
    }
    wallet.BlockUntilSyncedToCurrentChain();

    WAIT_LOCK(wallet.cs_wallet, wallet_lock);
    if (wallet.IsLocked()) {
        throw std::runtime_error("Wallet is locked");
    }
    if (!sapling::IsSaplingInitialized()) {
        throw std::runtime_error("Sapling parameters not loaded");
    }

    const SaplingSendPlan plan = PlanSaplingSend(wallet, source, recipients, minconf, fee);
    CAmount total_send{0};
    const auto parsed = ParseRecipients(recipients, total_send);
    auto& km = wallet.GetSaplingKeyManager();

    const auto& chainparams = Params();
    const int tip_height = wallet.GetLastBlockHeight();
    std::array<uint8_t, 32> anchor{};
    {
        uint256 anchor_hash;
        if (sapling::GetBestAnchor(tip_height, anchor_hash)) {
            std::copy(anchor_hash.begin(), anchor_hash.end(), anchor.begin());
        }
    }
    SaplingTransactionBuilder builder(chainparams.GetConsensus(), tip_height + 1, anchor, chainparams.NetworkIDString());

    // Notes and coins are held for this transaction while cs_wallet is
    // released for proof generation, and released again on every exit.
    // Declared after wallet_lock, so it runs while the lock is held.
    struct InputHold {
        CWallet& wallet;
        SaplingKeyManager& km;
        std::set<uint256> notes;
        std::vector<COutPoint> coins;
        ~InputHold()
        {
            AssertLockHeld(wallet.cs_wallet);
            if (!notes.empty()) km.UnreserveNotes(notes);
            for (const auto& op : coins) wallet.UnlockCoin(op);
        }
    } hold{wallet, km, {}, {}};

    std::optional<sapling::SaplingPaymentAddress> pending_change_addr;
    std::optional<sapling::SaplingIncomingViewingKey> pending_change_ivk;
    ReserveDestination reserve_change(&wallet);

    if (source.shielded) {
        std::map<uint256, SaplingNoteData> unspent;
        for (auto& [cmu, nd] : km.GetUnspentNotesWithKeys()) unspent.emplace(cmu, std::move(nd));

        // Spending keys of the notes, wiped when this scope ends
        struct SpendingKeys {
            std::map<sapling::SaplingPaymentAddress, sapling::SaplingExtendedSpendingKey> map;
            ~SpendingKeys()
            {
                for (auto& [addr, sk] : map) memory_cleanse(sk.key.data(), sk.key.size());
            }
        } keys;
        for (const uint256& cmu : plan.notes) {
            auto it = unspent.find(cmu);
            if (it == unspent.end()) throw std::runtime_error("A selected note is no longer spendable");
            const SaplingNoteData& note = it->second;

            auto key_it = keys.map.find(note.recipient);
            if (key_it == keys.map.end()) {
                auto sk = km.GetSpendingKey(note.recipient);
                if (!sk) throw std::runtime_error("Spending key not found for " + EncodeSaplingAddress(note.recipient));
                key_it = keys.map.emplace(note.recipient, *sk).first;
                memory_cleanse(sk->key.data(), sk->key.size());
            }

            if (note.witnessData.empty()) {
                throw std::runtime_error("Note has no Merkle witness");
            }
            std::array<uint8_t, 1065> merkle_path;
            try {
                rust::Slice<const uint8_t> witness_slice(note.witnessData.data(), note.witnessData.size());
                auto witness = sapling::tree::witness_deserialize(witness_slice);
                auto path = sapling::tree::witness_path(*witness);
                if (path.size() != merkle_path.size()) {
                    throw std::runtime_error("unexpected Merkle path size");
                }
                std::copy(path.begin(), path.end(), merkle_path.begin());
            } catch (const std::exception& e) {
                throw std::runtime_error(strprintf("Corrupt Merkle witness for note in tx %s: %s", note.txid.GetHex(), e.what()));
            }

            if (!builder.AddSaplingSpend(key_it->second, AddressBytes(note.recipient), note.value, note.rseed, merkle_path)) {
                throw std::runtime_error("Failed to add Sapling spend");
            }
            hold.notes.insert(cmu);
        }
        km.ReserveNotes(hold.notes);

        if (plan.change > 0) {
            // Change goes to an internal address of the key that owns the
            // largest spent note. For an external source key this is its
            // ZIP 316 internal key; an internal source key is reused as is,
            // since an internal-of-internal key would not be tracked.
            const auto& change_source = unspent.at(plan.notes.front()).recipient;
            auto fvk = km.GetFvk(change_source);
            auto dk = km.GetDk(change_source);
            auto source_ivk = km.GetIvk(change_source);
            if (!fvk || !dk || !source_ivk) {
                throw std::runtime_error("Cannot derive change address");
            }
            std::array<uint8_t, 96> source_fvk_bytes;
            std::copy(fvk->ak.begin(), fvk->ak.end(), source_fvk_bytes.begin());
            std::copy(fvk->nk.begin(), fvk->nk.end(), source_fvk_bytes.begin() + 32);
            std::copy(fvk->ovk.begin(), fvk->ovk.end(), source_fvk_bytes.begin() + 64);

            std::array<uint8_t, 96> change_fvk_bytes = source_fvk_bytes;
            std::array<uint8_t, 32> change_dk_bytes = *dk;
            if (!km.GetInternalIvks().count(*source_ivk)) {
                auto derived = sapling::zip32::derive_internal_fvk(source_fvk_bytes, *dk);
                change_fvk_bytes = derived.fvk;
                change_dk_bytes = derived.dk;
            }
            std::array<uint8_t, 11> j_start{};
            GetStrongRandBytes(Span{j_start.data(), 8});
            const auto found = sapling::zip32::find_address(change_fvk_bytes, change_dk_bytes, j_start);

            // Encrypt the change to the change key's OVK so the wallet can
            // recover it from the transaction.
            std::array<uint8_t, 32> change_ovk;
            std::copy(change_fvk_bytes.begin() + 64, change_fvk_bytes.end(), change_ovk.begin());
            if (!builder.AddSaplingOutput(change_ovk, found.addr, plan.change)) {
                throw std::runtime_error("Failed to add shielded change output");
            }

            sapling::SaplingPaymentAddress change_addr;
            std::copy(found.addr.begin(), found.addr.begin() + 11, change_addr.d.begin());
            std::copy(found.addr.begin() + 11, found.addr.end(), change_addr.pk_d.begin());
            sapling::SaplingIncomingViewingKey change_ivk;
            change_ivk.key = sapling::zip32::fvk_to_ivk(change_fvk_bytes);
            pending_change_addr = change_addr;
            pending_change_ivk = change_ivk;
        }
    } else {
        for (const COutPoint& outpoint : plan.coins) {
            const CWalletTx* wtx = wallet.GetWalletTx(outpoint.hash);
            if (!wtx || outpoint.n >= wtx->tx->vout.size()) {
                throw std::runtime_error("A selected coin is no longer spendable");
            }
            const CTxOut& txout = wtx->tx->vout[outpoint.n];
            builder.AddTransparentInput(outpoint, txout.scriptPubKey, txout.nValue);
            wallet.LockCoin(outpoint);
            hold.coins.push_back(outpoint);
        }
        if (plan.change > 0) {
            CTxDestination change_dest = source.change_dest;
            if (!IsValidDestination(change_dest)) {
                auto reserved = reserve_change.GetReservedDestination(true);
                if (!reserved) {
                    throw std::runtime_error("Transaction needs a change address, but we can't generate it: " + util::ErrorString(reserved).original);
                }
                change_dest = *reserved;
            }
            builder.AddTransparentOutput(GetScriptForDestination(change_dest), plan.change);
        }
    }

    for (size_t i = 0; i < parsed.size(); ++i) {
        if (parsed[i].shielded) {
            // No OVK: the sender cannot decrypt payments to others afterwards
            if (!builder.AddSaplingOutputNoOvk(AddressBytes(parsed[i].sapling_addr), plan.amounts[i], recipients[i].memo)) {
                throw std::runtime_error("Failed to add shielded output");
            }
        } else {
            builder.AddTransparentOutput(GetScriptForDestination(parsed[i].dest), plan.amounts[i]);
        }
    }

    // Groth16 proof generation takes seconds; do it without cs_wallet.
    std::optional<CMutableTransaction> mtx;
    std::string build_error;
    {
        REVERSE_LOCK(wallet_lock);
        try {
            mtx = builder.Build(&build_error);
        } catch (const std::exception& e) {
            build_error = e.what();
        }
    }
    if (!mtx) {
        throw std::runtime_error("Failed to build Sapling transaction: " + build_error);
    }
    if (wallet.GetLastBlockHeight() != tip_height) {
        throw std::runtime_error("Chain tip changed during proof generation, anchor may be stale, please retry");
    }
    if (wallet.IsLocked()) {
        throw std::runtime_error("Wallet was locked during proof generation");
    }
    if (!mtx->vin.empty() && !wallet.SignTransaction(*mtx)) {
        throw std::runtime_error("Failed to sign transparent inputs");
    }

    CTransactionRef tx = MakeTransactionRef(std::move(*mtx));
    TxValidationState state;
    if (!CheckTransaction(*tx, state)) {
        throw std::runtime_error("Transaction validation failed: " + state.ToString());
    }
    const unsigned int max_size = tx->nType == TRANSACTION_SAPLING ? MAX_SAPLING_TX_EXTRA_PAYLOAD : MAX_STANDARD_TX_SIZE;
    if (GetSerializeSize(*tx) > max_size) {
        throw std::runtime_error("Transaction too large");
    }

    wallet.CommitTransaction(tx, {}, {});
    reserve_change.KeepDestination();

    // Register the internal change address now that the transaction is
    // committed. If this fails, LoadNote recovers it on the next load.
    if (pending_change_addr && pending_change_ivk) {
        WalletBatch batch(wallet.GetDatabase());
        if (!km.RegisterDiversifiedAddress(*pending_change_addr, *pending_change_ivk, &batch)) {
            LogPrintf("SendSapling: failed to register internal change address (funds still spendable after next restart via LoadNote self-heal)\n");
        }
    }
    return tx->GetHash().GetHex();
}
} // namespace wallet
