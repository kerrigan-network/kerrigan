// Copyright (c) 2024 The Kerrigan developers
// Distributed under the MIT software license.

#ifndef KERRIGAN_SAPLING_CACHE_H
#define KERRIGAN_SAPLING_CACHE_H

#include <cuckoocache.h>
#include <util/hasher.h>
#include <rust/cxx.h>

#include <array>
#include <cstring>
#include <memory>
#include <shared_mutex>
#include <string>

namespace libkerrigan {

/**
 * Bundle validity cache for Sapling proof/signature verification results.
 *
 * Uses the same CuckooCache pattern as the signature cache (sigcache.cpp).
 * Entries are 32-byte BLAKE2b hashes already, so we can extract uint32_t
 * hash values directly (same as SignatureCacheHasher).
 */
class BundleValidityCache {
private:
    struct CacheHasher {
        template <uint8_t hash_select>
        uint32_t operator()(const uint256& key) const {
            static_assert(hash_select < 8, "CacheHasher only has 8 hashes available.");
            uint32_t u;
            std::memcpy(&u, key.begin() + 4 * hash_select, 4);
            return u;
        }
    };

    mutable std::shared_mutex cs_cache;
    CuckooCache::cache<uint256, CacheHasher> cache;

public:
    BundleValidityCache(size_t bytes) {
        cache.setup_bytes(bytes);
    }

    void insert(std::array<unsigned char, 32> entry) {
        uint256 key;
        std::memcpy(key.begin(), entry.data(), 32);
        std::unique_lock lock(cs_cache);
        cache.insert(key);
    }

    bool contains(const std::array<unsigned char, 32>& entry, bool erase) const {
        uint256 key;
        std::memcpy(key.begin(), entry.data(), 32);
        std::shared_lock lock(cs_cache);
        return cache.contains(key, erase);
    }
};

inline std::unique_ptr<BundleValidityCache> NewBundleValidityCache(
    rust::Str /*kind*/, size_t bytes)
{
    return std::make_unique<BundleValidityCache>(bytes);
}

} // namespace libkerrigan

#endif // KERRIGAN_SAPLING_CACHE_H
