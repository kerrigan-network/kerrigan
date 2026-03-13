// Copyright (c) 2024 The Kerrigan developers
// Distributed under the MIT software license.

#include <sapling/sapling_validation.h>
#include <sapling/sapling_init.h>
#include <consensus/amount.h>
#include <evo/specialtx.h>
#include <hash.h>
#include <rust/bridge.h>
#include <span.h>

#include <cstring>
#include <set>

namespace sapling {

uint256 ComputeSaplingSighash(const CTransaction& tx,
                              const SaplingTxPayload& payload)
{
    // Stable sighash that commits to both transparent and shielded data.
    // Hashes prevouts + sequences + outputs separately to avoid scriptSig
    // dependency (ZIP 243 / BIP 143 style).
    //
    // Format:
    //   nVersion | hashPrevouts | hashSequence | hashOutputs | nLockTime
    //   | nType | payloadVersion | hashShieldedSpends | hashShieldedOutputs
    //   | valueBalance
    //
    // hashShieldedSpends:  SHA256d of all spend descriptions (cv|anchor|nullifier|rk|zkproof)
    // hashShieldedOutputs: SHA256d of all output descriptions (cv|cmu|ephKey|encCT|outCT|zkproof)
    //
    // This MUST match the builder in sapling_transaction_builder.cpp.
    CHashWriter hw(SER_GETHASH, 0);
    hw << tx.nVersion;
    {
        CHashWriter hp(SER_GETHASH, 0);
        for (const auto& in : tx.vin) {
            hp << in.prevout;
        }
        hw << hp.GetHash();
    }
    {
        CHashWriter hs(SER_GETHASH, 0);
        for (const auto& in : tx.vin) {
            hs << in.nSequence;
        }
        hw << hs.GetHash();
    }
    {
        CHashWriter ho(SER_GETHASH, 0);
        for (const auto& out : tx.vout) {
            ho << out;
        }
        hw << ho.GetHash();
    }
    hw << tx.nLockTime;

    // Shielded data commitment (ZIP 243 style)
    hw << tx.nType;
    hw << payload.nVersion;
    {
        // hashShieldedSpends: hash each spend's (cv|anchor|nullifier|rk|zkproof)
        // excludes spendAuthSig which is the value being signed
        CHashWriter hss(SER_GETHASH, 0);
        for (const auto& spend : payload.vSpendDescriptions) {
            hss.write(MakeByteSpan(spend.cv));
            hss.write(MakeByteSpan(spend.anchor));
            hss.write(MakeByteSpan(spend.nullifier));
            hss.write(MakeByteSpan(spend.rk));
            hss.write(MakeByteSpan(spend.zkproof));
        }
        hw << hss.GetHash();
    }
    {
        // hashShieldedOutputs: hash each output's full description
        CHashWriter hso(SER_GETHASH, 0);
        for (const auto& output : payload.vOutputDescriptions) {
            hso.write(MakeByteSpan(output.cv));
            hso.write(MakeByteSpan(output.cmu));
            hso.write(MakeByteSpan(output.ephemeralKey));
            hso.write(MakeByteSpan(output.encCiphertext));
            hso.write(MakeByteSpan(output.outCiphertext));
            hso.write(MakeByteSpan(output.zkproof));
        }
        hw << hso.GetHash();
    }
    hw << payload.valueBalance;

    return hw.GetHash();
}

bool VerifySaplingProofs(const CTransaction& tx,
                         const SaplingTxPayload& payload,
                         TxValidationState& state)
{
    if (!IsSaplingInitialized()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "sapling-params-not-loaded",
                             "Sapling proof verification requires loaded parameters");
    }

    uint256 sighash = ComputeSaplingSighash(tx, payload);
    std::array<uint8_t, 32> sighash_arr;
    std::memcpy(sighash_arr.data(), sighash.begin(), 32);

    auto verifier = ::sapling::init_verifier();

    for (size_t i = 0; i < payload.vSpendDescriptions.size(); ++i) {
        const auto& spend = payload.vSpendDescriptions[i];
        if (!verifier->check_spend(
                spend.cv,
                spend.anchor,
                spend.nullifier,
                spend.rk,
                spend.zkproof,
                spend.spendAuthSig,
                sighash_arr)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "bad-sapling-spend-proof",
                                 strprintf("Invalid Sapling spend proof at index %u", i));
        }
    }

    for (size_t i = 0; i < payload.vOutputDescriptions.size(); ++i) {
        const auto& output = payload.vOutputDescriptions[i];
        if (!verifier->check_output(
                output.cv,
                output.cmu,
                output.ephemeralKey,
                output.zkproof)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "bad-sapling-output-proof",
                                 strprintf("Invalid Sapling output proof at index %u", i));
        }
    }

    if (!verifier->final_check(
            payload.valueBalance,
            payload.bindingSig,
            sighash_arr)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "bad-sapling-binding-sig",
                             "Invalid Sapling binding signature");
    }

    return true;
}

bool CheckSaplingTx(const CTransaction& tx,
                    const Consensus::Params& consensusParams,
                    int nHeight,
                    TxValidationState& state,
                    bool check_sigs)
{
    if (tx.nType != TRANSACTION_SAPLING) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-sapling-type");
    }

    if (!IsSaplingActive(consensusParams, nHeight)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-sapling-not-active");
    }

    if (!tx.HasExtraPayloadField()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-sapling-no-payload");
    }

    auto payloadOpt = GetTxPayload<SaplingTxPayload>(tx.vExtraPayload);
    if (!payloadOpt) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-sapling-payload");
    }
    const auto& payload = *payloadOpt;

    if (payload.nVersion != SAPLING_PAYLOAD_VERSION) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-sapling-version");
    }

    if (!payload.HasShieldedActions()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-sapling-empty");
    }

    if (payload.vSpendDescriptions.size() > 500) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-sapling-spends-count");
    }
    if (payload.vOutputDescriptions.size() > 500) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-sapling-outputs-count");
    }

    if (tx.vExtraPayload.size() > MAX_SAPLING_TX_EXTRA_PAYLOAD) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-sapling-payload-size");
    }

    // Check for duplicate nullifiers within this transaction (#616).
    // A tx that spends the same note twice is always invalid. Catching it
    // here (before expensive proof verification) prevents such txs from
    // entering the mempool. The consensus-level check in sapling_state.cpp
    // remains as a belt-and-suspenders defence at block-connect time.
    {
        std::set<uint256> txNullifiers;
        for (const auto& spend : payload.vSpendDescriptions) {
            uint256 nf;
            std::memcpy(nf.begin(), spend.nullifier.data(), 32);
            if (!txNullifiers.insert(nf).second) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                     "bad-sapling-duplicate-nullifier",
                                     "Duplicate nullifier within single transaction");
            }
        }
    }

    // valueBalance must be in valid monetary range to prevent signed overflow in pool
    // accounting and to ensure the binding signature commitment is meaningful.
    // This check runs even with check_sigs=false (e.g. -assumevalid IBD).
    // NOTE: valueBalance can be legitimately negative for t->z shielding.
    // Use symmetric range check instead of MoneyRange (which rejects negatives).
    if (payload.valueBalance < -MAX_MONEY || payload.valueBalance > MAX_MONEY) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-sapling-value-balance");
    }

    // Verify each spend's anchor is a valid historical commitment tree root.
    // An unrecognized anchor means the spend references a tree state we have
    // never seen, which makes the spend unprovable and the tx invalid.
    // Output-only txs have no spends so this loop is a no-op for them.
    for (size_t i = 0; i < payload.vSpendDescriptions.size(); ++i) {
        uint256 anchor;
        std::memcpy(anchor.begin(), payload.vSpendDescriptions[i].anchor.data(), 32);
        if (anchor.IsNull()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "bad-sapling-anchor-null",
                                 strprintf("Spend %u has null anchor", i));
        }
        if (!IsValidSaplingAnchor(anchor)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "bad-sapling-anchor",
                                 strprintf("Spend %u references unknown Sapling anchor %s", i, anchor.ToString()));
        }
    }

    // Verify Groth16 proofs and signatures via Rust FFI.
    // During IBD with assumevalid, check_sigs is false and we skip the
    // expensive (~10-40ms each) Groth16 proof verification.
    if (check_sigs && !VerifySaplingProofs(tx, payload, state)) {
        return false; // state already set by VerifySaplingProofs
    }

    return true;
}

} // namespace sapling
