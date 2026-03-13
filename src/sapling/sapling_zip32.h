// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license.
//
// C++ declarations for the Sapling ZIP 32 key derivation functions
// implemented in Rust (src/rust/src/sapling/zip32.rs) and exposed
// through the CXX bridge (src/rust/src/bridge.rs).
//
// These declarations match the CXX-generated symbols exactly.
// They are provided as a standalone header so that C++ callers
// can use ZIP 32 functions without pulling in the full bridge.h
// (which requires streams.h types that may not be available in
// all translation units).

#ifndef KERRIGAN_SAPLING_ZIP32_H
#define KERRIGAN_SAPLING_ZIP32_H

#include <array>
#include <cstdint>

namespace sapling {
namespace zip32 {

struct Zip32Fvk {
    std::array<uint8_t, 96> fvk;
    std::array<uint8_t, 32> dk;
};

struct Zip32Address {
    std::array<uint8_t, 11> j;
    std::array<uint8_t, 43> addr;
};

// Extract FVK (96 bytes: ak || nk || ovk) from serialized ExtSK (169 bytes).
// Throws rust::Error if the ExtSK bytes are invalid.
std::array<uint8_t, 96> xsk_to_fvk(const std::array<uint8_t, 169>& xsk);

// Extract DK (32 bytes) from serialized ExtSK (169 bytes).
// Pure byte slice, never fails.
std::array<uint8_t, 32> xsk_to_dk(const std::array<uint8_t, 169>& xsk) noexcept;

// Extract IVK (32 bytes) from serialized ExtSK (169 bytes).
// Throws rust::Error if the ExtSK bytes are invalid.
std::array<uint8_t, 32> xsk_to_ivk(const std::array<uint8_t, 169>& xsk);

// Derive default payment address (43 bytes: d(11) || pk_d(32)) from ExtSK.
// Throws rust::Error if the ExtSK bytes are invalid.
std::array<uint8_t, 43> xsk_to_default_address(const std::array<uint8_t, 169>& xsk);

// Find next valid diversified address at or above diversifier index j.
// Throws rust::Error if no valid diversifier exists at or above j.
Zip32Address find_address(const std::array<uint8_t, 96>& fvk, std::array<uint8_t, 32> dk, std::array<uint8_t, 11> j);

// Derive IVK (32 bytes) from 96-byte FVK (ak || nk || ovk).
// Throws rust::Error if the FVK bytes are invalid.
std::array<uint8_t, 32> fvk_to_ivk(const std::array<uint8_t, 96>& fvk);

// Derive default payment address from FVK + DK.
// Throws rust::Error if the FVK bytes are invalid or no diversifier is found.
std::array<uint8_t, 43> fvk_default_address(const std::array<uint8_t, 96>& fvk, std::array<uint8_t, 32> dk);

} // namespace zip32
} // namespace sapling

#endif // KERRIGAN_SAPLING_ZIP32_H
