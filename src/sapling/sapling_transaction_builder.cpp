// Copyright (c) 2024 The Kerrigan developers
// Distributed under the MIT software license.

#include <sapling/sapling_transaction_builder.h>

#include <evo/specialtx.h>
#include <hash.h>
#include <logging.h>
#include <rust/bridge.h>
#include <sapling/sapling_validation.h>
#include <span.h>

#include <cassert>
#include <cstring>

// Pimpl

struct SaplingTransactionBuilder::Impl {
    const Consensus::Params& params;
    int nHeight;
    std::array<uint8_t, 32> anchor;

    std::vector<CTxIn>  vin;
    std::vector<CTxOut> vout;

    rust::Box<::sapling::Builder> rust_builder;

    size_t num_spends{0};
    size_t num_outputs{0};

    Impl(const Consensus::Params& p,
         int h,
         const std::array<uint8_t, 32>& anch,
         rust::Box<::sapling::Builder> builder)
        : params(p), nHeight(h), anchor(anch),
          rust_builder(std::move(builder))
    {}
};

// Internal helpers

/**
 * Build a Rust consensus::Network object from a chainparams network ID string.
 *
 * Mainnet and testnet use the Zcash standard crypto parameters (the Sapling
 * circuits are identical).  Regtest and devnet use LocalNetwork with the
 * Kerrigan SaplingHeight so the builder accepts our custom activation height.
 */
static rust::Box<::consensus::Network>
MakeRustNetwork(const std::string& networkIDStr, int saplingHeight)
{
    // Pass -1 for unused heights (Rust converts negative to None).
    if (networkIDStr == "main") {
        return ::consensus::network("main", -1,-1,-1,-1,-1,-1,-1,-1);
    }
    if (networkIDStr == "test") {
        return ::consensus::network("test", -1,-1,-1,-1,-1,-1,-1,-1);
    }
    // Regtest / devnet: supply our Sapling activation height.
    return ::consensus::network("regtest",
                                /*overwinter=*/-1,
                                /*sapling=*/saplingHeight,
                                /*blossom=*/-1,
                                /*heartwood=*/-1,
                                /*canopy=*/-1,
                                /*nu5=*/-1,
                                /*nu6=*/-1,
                                /*nu6_1=*/-1);
}

// Constructor / Destructor

SaplingTransactionBuilder::SaplingTransactionBuilder(
    const Consensus::Params& params,
    int nHeight,
    const std::array<uint8_t, 32>& anchor)
    : SaplingTransactionBuilder(params, nHeight, anchor, "regtest")
{}

SaplingTransactionBuilder::SaplingTransactionBuilder(
    const Consensus::Params& params,
    int nHeight,
    const std::array<uint8_t, 32>& anchor,
    const std::string& networkIDStr)
{
    auto rustNetwork = MakeRustNetwork(networkIDStr, params.SaplingHeight);
    auto rustBuilder = ::sapling::new_builder(
        *rustNetwork,
        static_cast<uint32_t>(nHeight),
        anchor,
        /*coinbase=*/false);

    m_impl = std::make_unique<Impl>(params, nHeight, anchor, std::move(rustBuilder));
}

SaplingTransactionBuilder::~SaplingTransactionBuilder() = default;

SaplingTransactionBuilder::SaplingTransactionBuilder(
    SaplingTransactionBuilder&&) noexcept = default;

// Transparent inputs / outputs

void SaplingTransactionBuilder::AddTransparentInput(
    const COutPoint& outpoint,
    const CScript& /*scriptPubKey*/,
    CAmount value)
{
    assert(m_impl && "Build() already called");
    m_impl->vin.emplace_back(outpoint);
}

void SaplingTransactionBuilder::AddTransparentOutput(
    const CScript& scriptPubKey,
    CAmount value)
{
    assert(m_impl && "Build() already called");
    m_impl->vout.emplace_back(value, scriptPubKey);
}

// Shielded spends / outputs

bool SaplingTransactionBuilder::AddSaplingSpend(
    const sapling::SaplingExtendedSpendingKey& extsk,
    const std::array<uint8_t, 43>& recipient,
    uint64_t value,
    const std::array<uint8_t, 32>& rcm,
    const std::array<uint8_t, 1065>& merkle_path)
{
    assert(m_impl && "Build() already called");
    try {
        rust::Slice<const uint8_t> extsk_slice(extsk.key.data(), extsk.key.size());
        m_impl->rust_builder->add_spend(extsk_slice, recipient, value, rcm, merkle_path);
        ++m_impl->num_spends;
        return true;
    } catch (const std::exception& e) {
        LogPrintf("%s: add_spend error: %s\n", __func__, e.what());
        return false;
    }
}

bool SaplingTransactionBuilder::AddSaplingOutput(
    const std::array<uint8_t, 32>& ovk,
    const std::array<uint8_t, 43>& to,
    uint64_t value,
    const std::vector<uint8_t>& memo)
{
    assert(m_impl && "Build() already called");

    std::array<uint8_t, 512> memo_arr{};
    std::memcpy(memo_arr.data(), memo.data(), std::min(memo.size(), size_t{512}));

    try {
        m_impl->rust_builder->add_recipient(ovk, to, value, memo_arr);
        ++m_impl->num_outputs;
        return true;
    } catch (const std::exception& e) {
        LogPrintf("%s: add_recipient error: %s\n", __func__, e.what());
        return false;
    }
}

bool SaplingTransactionBuilder::AddSaplingOutputNoOvk(
    const std::array<uint8_t, 43>& to,
    uint64_t value,
    const std::vector<uint8_t>& memo)
{
    assert(m_impl && "Build() already called");

    std::array<uint8_t, 512> memo_arr{};
    std::memcpy(memo_arr.data(), memo.data(), std::min(memo.size(), size_t{512}));

    try {
        m_impl->rust_builder->add_recipient_no_ovk(to, value, memo_arr);
        ++m_impl->num_outputs;
        return true;
    } catch (const std::exception& e) {
        LogPrintf("%s: add_recipient_no_ovk error: %s\n", __func__, e.what());
        return false;
    }
}

// Build

std::optional<CMutableTransaction> SaplingTransactionBuilder::Build(std::string* error)
{
    if (!m_impl) {
        if (error) *error = "Build() already called on this builder";
        return std::nullopt;
    }

    if (!sapling::IsSaplingActive(m_impl->params, m_impl->nHeight)) {
        if (error) *error = "Sapling not active at height " + std::to_string(m_impl->nHeight);
        m_impl.reset();
        return std::nullopt;
    }

    if (m_impl->num_spends == 0 && m_impl->num_outputs == 0) {
        if (error) *error = "No shielded spends or outputs";
        m_impl.reset();
        return std::nullopt;
    }

    // Generate Groth16 proofs
    std::optional<rust::Box<::sapling::UnauthorizedBundle>> unauth;
    try {
        unauth.emplace(::sapling::build_bundle(std::move(m_impl->rust_builder)));
    } catch (const std::exception& e) {
        if (error) *error = std::string("build_bundle: ") + e.what();
        m_impl.reset();
        return std::nullopt;
    }

    CMutableTransaction mtx;
    mtx.nVersion  = CTransaction::SPECIAL_VERSION;  // 3
    mtx.nType     = TRANSACTION_SAPLING;
    mtx.nLockTime = 0;
    mtx.vin  = m_impl->vin;
    mtx.vout = m_impl->vout;

    // Uses a stable hash that commits to both transparent and shielded data.
    // Hashes prevouts + sequences + outputs separately to avoid scriptSig
    // dependency (ZIP 243 / BIP 143 style).
    //
    // Format:
    //   nVersion | hashPrevouts | hashSequence | hashOutputs | nLockTime
    //   | nType | payloadVersion | hashShieldedSpends | hashShieldedOutputs
    //   | valueBalance
    //
    // This MUST match ComputeSaplingSighash() in sapling_validation.cpp.
    CHashWriter hw(SER_GETHASH, 0);
    hw << mtx.nVersion;
    {
        CHashWriter hp(SER_GETHASH, 0);
        for (const auto& in : mtx.vin) {
            hp << in.prevout;
        }
        hw << hp.GetHash();
    }
    {
        CHashWriter hs(SER_GETHASH, 0);
        for (const auto& in : mtx.vin) {
            hs << in.nSequence;
        }
        hw << hs.GetHash();
    }
    {
        CHashWriter ho(SER_GETHASH, 0);
        for (const auto& out : mtx.vout) {
            ho << out;
        }
        hw << ho.GetHash();
    }
    hw << mtx.nLockTime;

    // Shielded data commitment (ZIP 243 style), data from unauthorized bundle
    hw << mtx.nType;
    hw << SAPLING_PAYLOAD_VERSION;
    try {
        {
            // hashShieldedSpends: cv|anchor|nullifier|rk|zkproof per spend (no auth sig)
            CHashWriter hss(SER_GETHASH, 0);
            const size_t nSpends = (*unauth)->num_spends();
            for (size_t si = 0; si < nSpends; ++si) {
                auto cv      = (*unauth)->spend_cv(si);
                auto anchor  = (*unauth)->spend_anchor(si);
                auto nf      = (*unauth)->spend_nullifier(si);
                auto rk      = (*unauth)->spend_rk(si);
                auto zkproof = (*unauth)->spend_zkproof(si);
                hss.write(MakeByteSpan(cv));
                hss.write(MakeByteSpan(anchor));
                hss.write(MakeByteSpan(nf));
                hss.write(MakeByteSpan(rk));
                hss.write(MakeByteSpan(zkproof));
            }
            hw << hss.GetHash();
        }
        {
            // hashShieldedOutputs: cv|cmu|ephKey|encCT|outCT|zkproof per output
            CHashWriter hso(SER_GETHASH, 0);
            const size_t nOutputs = (*unauth)->num_outputs();
            for (size_t oi = 0; oi < nOutputs; ++oi) {
                auto cv      = (*unauth)->output_cv(oi);
                auto cmu     = (*unauth)->output_cmu(oi);
                auto ephKey  = (*unauth)->output_ephemeral_key(oi);
                auto encCT   = (*unauth)->output_enc_ciphertext(oi);
                auto outCT   = (*unauth)->output_out_ciphertext(oi);
                auto zkproof = (*unauth)->output_zkproof(oi);
                hso.write(MakeByteSpan(cv));
                hso.write(MakeByteSpan(cmu));
                hso.write(MakeByteSpan(ephKey));
                hso.write(MakeByteSpan(encCT));
                hso.write(MakeByteSpan(outCT));
                hso.write(MakeByteSpan(zkproof));
            }
            hw << hso.GetHash();
        }
    } catch (const std::exception& e) {
        if (error) *error = std::string("sighash_shielded: ") + e.what();
        m_impl.reset();
        return std::nullopt;
    }
    hw << (*unauth)->value_balance_zat();

    uint256 sighash_u256 = hw.GetHash();

    std::array<uint8_t, 32> sighash_arr;
    std::memcpy(sighash_arr.data(), sighash_u256.begin(), 32);

    std::optional<rust::Box<::sapling::Bundle>> auth;
    try {
        auth.emplace(::sapling::apply_bundle_signatures(std::move(*unauth), sighash_arr));
    } catch (const std::exception& e) {
        if (error) *error = std::string("apply_bundle_signatures: ") + e.what();
        m_impl.reset();
        return std::nullopt;
    }

    SaplingTxPayload payload;
    payload.nVersion     = SAPLING_PAYLOAD_VERSION;
    payload.valueBalance = (*auth)->value_balance_zat();
    try {
        payload.bindingSig = (*auth)->binding_sig();
    } catch (const std::exception& e) {
        if (error) *error = std::string("binding_sig: ") + e.what();
        m_impl.reset();
        return std::nullopt;
    }

    auto spends  = (*auth)->spends();
    auto outputs = (*auth)->outputs();

    payload.vSpendDescriptions.reserve(spends.size());
    for (const auto& sp : spends) {
        SaplingSpendDescription sd;
        sd.cv           = sp.cv();
        sd.anchor       = sp.anchor();
        sd.nullifier    = sp.nullifier();
        sd.rk           = sp.rk();
        sd.zkproof      = sp.zkproof();
        sd.spendAuthSig = sp.spend_auth_sig();
        payload.vSpendDescriptions.push_back(sd);
    }

    payload.vOutputDescriptions.reserve(outputs.size());
    for (const auto& op : outputs) {
        SaplingOutputDescription od;
        od.cv            = op.cv();
        od.cmu           = op.cmu();
        od.ephemeralKey  = op.ephemeral_key();
        od.encCiphertext = op.enc_ciphertext();
        od.outCiphertext = op.out_ciphertext();
        od.zkproof       = op.zkproof();
        payload.vOutputDescriptions.push_back(od);
    }

    SetTxPayload(mtx, payload);

    m_impl.reset();
    return mtx;
}
