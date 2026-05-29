// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/shielded_spend_freeze.h>

#include <evo/specialtx.h>             // GetTxPayload<>
#include <primitives/transaction.h>    // CTransaction, TRANSACTION_SAPLING
#include <sapling/sapling_tx_payload.h> // SaplingTxPayload

// Process-wide Layer-1 opt-in flag. Defined once here; declared extern in header.
bool g_freeze_shielded_spends = false;

ShieldedDirection ClassifyShieldedDirection(const CTransaction& tx)
{
    ShieldedDirection out; // default: pure-transparent (is_sapling == false)

    // Only special-version Sapling transactions carry a shielded payload. A
    // non-Sapling tx (transparent payments, masternode special txs, etc.) has no
    // shielded spends by construction.
    if (!tx.IsSpecialTxVersion() || tx.nType != TRANSACTION_SAPLING) {
        return out;
    }

    // Deserialize the shielded payload using the SAME canonical helper the rest of
    // consensus uses (consensus/tx_verify.cpp, sapling/sapling_state.cpp), so this
    // classification is bit-for-bit consistent with how the payload is parsed
    // everywhere else. We call the single-argument (raw-bytes) overload directly on
    // vExtraPayload: we have already verified nType == TRANSACTION_SAPLING above, so
    // the type-checking tx-overload would be redundant (and a std::vector argument
    // would in fact bind to the wrong overload). Returns nullopt on a malformed
    // payload rather than throwing.
    const std::optional<SaplingTxPayload> payload =
        GetTxPayload<SaplingTxPayload>(tx.vExtraPayload);
    if (!payload) {
        // Malformed payload: decline to classify. The normal Sapling validation
        // path rejects an unparseable payload ("bad-sapling-payload"); we do not
        // second-guess it here, and we do not treat "unparseable" as "frozen"
        // (that would diverge from the parse-failure handling elsewhere).
        return out;
    }

    out.is_sapling = true;
    out.spends = payload->GetSpendsCount();
    out.outputs = payload->GetOutputsCount();
    out.value_balance = payload->valueBalance;
    return out;
}

bool IsFrozenShieldedSpend(const CTransaction& tx)
{
    // OUT-direction predicate: the tx spends shielded notes. A note can only ever
    // leave the pool via a spend, so freezing every shielded spend is the airtight
    // closure of the z->t exit (and additionally blocks z->z churn). t->z shield-IN
    // (spends == 0) and pure-transparent txs are not frozen.
    return ClassifyShieldedDirection(tx).SpendsShielded();
}
