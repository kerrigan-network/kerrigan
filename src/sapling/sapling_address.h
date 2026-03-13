// Copyright (c) 2024 The Kerrigan developers
// Distributed under the MIT software license.

#ifndef KERRIGAN_SAPLING_ADDRESS_H
#define KERRIGAN_SAPLING_ADDRESS_H

#include <array>
#include <cstdint>
#include <string>

namespace sapling {

/**
 * Sapling payment address: diversifier (11 bytes) + pk_d (32 bytes).
 *
 * Encoded as Bech32m with HRP:
 *   mainnet:  "ks"
 *   testnet:  "ktestsapling"
 *   regtest:  "kregsapling"
 */
struct SaplingPaymentAddress {
    std::array<uint8_t, 11> d;   // diversifier
    std::array<uint8_t, 32> pk_d; // diversified transmission key

    bool operator==(const SaplingPaymentAddress& other) const {
        return d == other.d && pk_d == other.pk_d;
    }
    bool operator!=(const SaplingPaymentAddress& other) const {
        return !(*this == other);
    }
    bool operator<(const SaplingPaymentAddress& other) const {
        if (d != other.d) return d < other.d;
        return pk_d < other.pk_d;
    }
};

/**
 * Sapling incoming viewing key (ivk): 32 bytes.
 * Used to detect notes addressed to us without the spending key.
 */
struct SaplingIncomingViewingKey {
    std::array<uint8_t, 32> key;

    bool operator==(const SaplingIncomingViewingKey& other) const { return key == other.key; }
    bool operator<(const SaplingIncomingViewingKey& other) const { return key < other.key; }
};

/**
 * Sapling full viewing key: ak (32) + nk (32) + ovk (32).
 * Can derive ivk and detect owned notes, but cannot spend.
 */
struct SaplingFullViewingKey {
    std::array<uint8_t, 32> ak;  // authorizing key (spend)
    std::array<uint8_t, 32> nk;  // nullifier key
    std::array<uint8_t, 32> ovk; // outgoing viewing key
};

/**
 * Sapling extended spending key: 169 bytes (ZIP 32).
 * Full key material for spending + viewing + address generation.
 */
struct SaplingExtendedSpendingKey {
    std::array<uint8_t, 169> key;
};

/**
 * Sapling extended full viewing key: ZIP 32 hierarchical viewing key.
 */
struct SaplingExtendedFullViewingKey {
    std::array<uint8_t, 169> key;
};

} // namespace sapling

#endif // KERRIGAN_SAPLING_ADDRESS_H
