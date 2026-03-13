// Copyright (c) 2024 The Kerrigan developers
// Distributed under the MIT software license.

#ifndef KERRIGAN_SAPLING_TX_PAYLOAD_H
#define KERRIGAN_SAPLING_TX_PAYLOAD_H

#include <consensus/amount.h>
#include <core_io.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <array>
#include <cstdint>
#include <vector>

/** Serialize/Unserialize helpers for fixed-size std::array<uint8_t, N> */
template <typename Stream, size_t N>
void SerializeFixedArray(Stream& s, const std::array<uint8_t, N>& a) {
    s.write(MakeByteSpan(a));
}
template <typename Stream, size_t N>
void UnserializeFixedArray(Stream& s, std::array<uint8_t, N>& a) {
    s.read(MakeWritableByteSpan(a));
}

/**
 * Sapling shielded transaction payload.
 *
 * Serialized into CTransaction::vExtraPayload when nType == TRANSACTION_SAPLING.
 * This is the on-wire/on-disk format before the Rust Sapling library parses it.
 *
 * Wire format:
 *   uint16_t nVersion (payload version, currently 1)
 *   compactSize nSpends
 *   SpendDescription[nSpends]
 *   compactSize nOutputs
 *   OutputDescription[nOutputs]
 *   int64_t valueBalance (net value entering transparent pool)
 *   byte[64] bindingSig (binding signature)
 */

static constexpr uint16_t SAPLING_PAYLOAD_VERSION = 1;

/**
 * Sapling fee policy.
 * Shielded operations are more expensive due to proof generation overhead
 * and larger transaction sizes.
 *
 * Base: 10000 satoshis (0.0001 KRGN)
 * Per spend: 5000 satoshis (0.00005 KRGN)
 * Per output: 5000 satoshis (0.00005 KRGN)
 *
 * Example: 1 spend + 2 outputs = 10000 + 5000 + 10000 = 25000 sat (0.00025 KRGN)
 */
static constexpr int64_t SAPLING_BASE_FEE = 10000;
static constexpr int64_t SAPLING_PER_SPEND_FEE = 5000;
static constexpr int64_t SAPLING_PER_OUTPUT_FEE = 5000;

inline int64_t CalculateSaplingFee(size_t nSpends, size_t nOutputs)
{
    return SAPLING_BASE_FEE
         + static_cast<int64_t>(nSpends) * SAPLING_PER_SPEND_FEE
         + static_cast<int64_t>(nOutputs) * SAPLING_PER_OUTPUT_FEE;
}

/** A single Sapling spend description (on wire). */
struct SaplingSpendDescription {
    std::array<uint8_t, 32> cv;               // value commitment
    std::array<uint8_t, 32> anchor;           // Merkle tree anchor
    std::array<uint8_t, 32> nullifier;        // nullifier
    std::array<uint8_t, 32> rk;               // randomized public key
    std::array<uint8_t, 192> zkproof;         // Groth16 proof
    std::array<uint8_t, 64> spendAuthSig;     // spend authorization signature

    template <typename Stream>
    void Serialize(Stream& s) const {
        SerializeFixedArray(s, cv);
        SerializeFixedArray(s, anchor);
        SerializeFixedArray(s, nullifier);
        SerializeFixedArray(s, rk);
        SerializeFixedArray(s, zkproof);
        SerializeFixedArray(s, spendAuthSig);
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        UnserializeFixedArray(s, cv);
        UnserializeFixedArray(s, anchor);
        UnserializeFixedArray(s, nullifier);
        UnserializeFixedArray(s, rk);
        UnserializeFixedArray(s, zkproof);
        UnserializeFixedArray(s, spendAuthSig);
    }
};

/** A single Sapling output description (on wire). */
struct SaplingOutputDescription {
    std::array<uint8_t, 32> cv;               // value commitment
    std::array<uint8_t, 32> cmu;              // note commitment
    std::array<uint8_t, 32> ephemeralKey;     // ephemeral public key
    std::array<uint8_t, 580> encCiphertext;   // encrypted note
    std::array<uint8_t, 80> outCiphertext;    // encrypted outgoing info
    std::array<uint8_t, 192> zkproof;         // Groth16 proof

    template <typename Stream>
    void Serialize(Stream& s) const {
        SerializeFixedArray(s, cv);
        SerializeFixedArray(s, cmu);
        SerializeFixedArray(s, ephemeralKey);
        SerializeFixedArray(s, encCiphertext);
        SerializeFixedArray(s, outCiphertext);
        SerializeFixedArray(s, zkproof);
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        UnserializeFixedArray(s, cv);
        UnserializeFixedArray(s, cmu);
        UnserializeFixedArray(s, ephemeralKey);
        UnserializeFixedArray(s, encCiphertext);
        UnserializeFixedArray(s, outCiphertext);
        UnserializeFixedArray(s, zkproof);
    }
};

/**
 * SaplingTxPayload: lives inside vExtraPayload for TRANSACTION_SAPLING.
 *
 * Follows the same GetTxPayload<T> / SetTxPayload pattern as other
 * Kerrigan special transaction payloads in src/evo/specialtx.h.
 */
struct SaplingTxPayload {
    static constexpr auto SPECIALTX_TYPE = 10; // TRANSACTION_SAPLING

    uint16_t nVersion{SAPLING_PAYLOAD_VERSION};
    std::vector<SaplingSpendDescription> vSpendDescriptions;
    std::vector<SaplingOutputDescription> vOutputDescriptions;
    int64_t valueBalance{0};    // net value: positive = value enters transparent pool
    std::array<uint8_t, 64> bindingSig{};

    template <typename Stream>
    void Serialize(Stream& s) const {
        ::Serialize(s, nVersion);
        assert(vSpendDescriptions.size() <= 500);
        assert(vOutputDescriptions.size() <= 500);
        ::Serialize(s, vSpendDescriptions);
        ::Serialize(s, vOutputDescriptions);
        ::Serialize(s, valueBalance);
        SerializeFixedArray(s, bindingSig);
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        ::Unserialize(s, nVersion);
        // Bounded deserialization: match consensus limit of 500 each to reject
        // oversized payloads at the wire level before validation (#542)
        ::Unserialize(s, Using<LimitedVectorFormatter<500>>(vSpendDescriptions));
        ::Unserialize(s, Using<LimitedVectorFormatter<500>>(vOutputDescriptions));
        ::Unserialize(s, valueBalance);
        UnserializeFixedArray(s, bindingSig);
    }

    size_t GetSpendsCount() const { return vSpendDescriptions.size(); }
    size_t GetOutputsCount() const { return vOutputDescriptions.size(); }

    bool HasShieldedActions() const {
        return !vSpendDescriptions.empty() || !vOutputDescriptions.empty();
    }

    [[nodiscard]] UniValue ToJson() const {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("version", nVersion);
        obj.pushKV("spends", static_cast<int64_t>(vSpendDescriptions.size()));
        obj.pushKV("outputs", static_cast<int64_t>(vOutputDescriptions.size()));
        obj.pushKV("valueBalance", ValueFromAmount(valueBalance));
        obj.pushKV("valueBalanceSat", valueBalance);
        obj.pushKV("bindingSig", HexStr(bindingSig));

        UniValue spends(UniValue::VARR);
        for (const auto& sd : vSpendDescriptions) {
            UniValue s(UniValue::VOBJ);
            s.pushKV("cv", HexStr(sd.cv));
            s.pushKV("anchor", HexStr(sd.anchor));
            s.pushKV("nullifier", HexStr(sd.nullifier));
            s.pushKV("rk", HexStr(sd.rk));
            s.pushKV("proof", HexStr(sd.zkproof));
            s.pushKV("spendAuthSig", HexStr(sd.spendAuthSig));
            spends.push_back(s);
        }
        obj.pushKV("vSpendDescriptions", spends);

        UniValue outputs(UniValue::VARR);
        for (const auto& od : vOutputDescriptions) {
            UniValue o(UniValue::VOBJ);
            o.pushKV("cv", HexStr(od.cv));
            o.pushKV("cmu", HexStr(od.cmu));
            o.pushKV("ephemeralKey", HexStr(od.ephemeralKey));
            o.pushKV("encCiphertext", HexStr(od.encCiphertext));
            o.pushKV("outCiphertext", HexStr(od.outCiphertext));
            o.pushKV("proof", HexStr(od.zkproof));
            outputs.push_back(o);
        }
        obj.pushKV("vOutputDescriptions", outputs);

        return obj;
    }
};

#endif // KERRIGAN_SAPLING_TX_PAYLOAD_H
