// Copyright (c) 2024 The Kerrigan developers
// Distributed under the MIT software license.

#ifndef KERRIGAN_SAPLING_INIT_H
#define KERRIGAN_SAPLING_INIT_H

#include <fs.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

namespace sapling {

/**
 * Load Sapling zk-SNARK parameters from spend and output param files.
 *
 * Calls into the Rust FFI which verifies file integrity (size + BLAKE2b
 * hash) before deserializing. Returns false on failure and logs the reason.
 */
bool InitSaplingParams(const fs::path& spend_path, const fs::path& output_path);

/**
 * Returns true if Sapling parameters have been successfully loaded.
 */
bool IsSaplingInitialized();

/**
 * Register a callback for retrieving the Sapling commitment tree root.
 * Called once during node init after CSaplingState is constructed.
 * The callback takes (nHeight, &root) and returns true if root was found.
 */
using AnchorCallback = bool(*)(int nHeight, uint256& root);
void SetAnchorCallback(AnchorCallback cb);

/**
 * Register a callback for validating a Sapling anchor (Merkle root).
 * The callback takes a root value and returns true if it is a valid
 * historical commitment tree root.
 */
using ValidAnchorCallback = bool(*)(const uint256& anchor);
void SetValidAnchorCallback(ValidAnchorCallback cb);

/**
 * Check if the given value is a valid historical Sapling commitment tree root.
 * Returns false if no callback is registered (e.g. during IBD before init).
 */
bool IsValidSaplingAnchor(const uint256& anchor);

/**
 * Get the Sapling anchor (commitment tree root) for a given block height.
 * Returns false if no callback is registered or the height has no root.
 */
bool GetBestAnchor(int nHeight, uint256& anchor);

/**
 * Register a callback for retrieving the serialized commitment tree frontier.
 * Used by the wallet to create incremental witnesses for owned notes.
 * The callback takes (nHeight, &data) and returns true if data was found.
 */
using FrontierCallback = bool(*)(int nHeight, std::vector<uint8_t>& data);
void SetFrontierCallback(FrontierCallback cb);

/**
 * Get the serialized Sapling commitment tree frontier at a given block height.
 * Returns false if no callback is registered or the height has no frontier.
 */
bool GetFrontierData(int nHeight, std::vector<uint8_t>& data);

} // namespace sapling

#endif // KERRIGAN_SAPLING_INIT_H
