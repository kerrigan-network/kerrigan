// Copyright (c) 2024 The Kerrigan developers
// Adapted from Zcash's bundlecache.rs
// Distributed under the MIT software license.

use std::{
    convert::TryInto,
    sync::{OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use rand_core::{OsRng, RngCore};

use crate::bridge::ffi;

pub(crate) struct CacheEntry([u8; 32]);

pub(crate) enum CacheEntries {
    Storing(Vec<CacheEntry>),
    NotStoring,
}

impl CacheEntries {
    pub(crate) fn new(cache_store: bool) -> Self {
        if cache_store {
            CacheEntries::Storing(vec![])
        } else {
            CacheEntries::NotStoring
        }
    }
}

pub(crate) struct BundleValidityCache {
    hasher: blake2b_simd::State,
    cache: cxx::UniquePtr<ffi::BundleValidityCache>,
}

// Safety: BundleValidityCache is only accessed through a RwLock, which
// provides the necessary synchronization. The UniquePtr<ffi::BundleValidityCache>
// is only used through pin_mut() (write) or contains() (read), both guarded
// by the RwLock's read/write guards.
unsafe impl Send for BundleValidityCache {}
unsafe impl Sync for BundleValidityCache {}

impl BundleValidityCache {
    fn new(kind: &'static str, personalization: &[u8; 16], cache_bytes: usize) -> Self {
        let mut hasher = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(personalization)
            .to_state();

        // Per-instance nonce for deterministic but unique cache entries.
        let mut nonce = [0; 32];
        OsRng.fill_bytes(&mut nonce);
        hasher.update(&nonce);

        Self {
            hasher,
            cache: ffi::NewBundleValidityCache(kind, cache_bytes),
        }
    }

    pub(crate) fn compute_entry(
        &self,
        bundle_commitment: &[u8; 32],
        bundle_authorizing_commitment: &[u8; 32],
        sighash: &[u8; 32],
    ) -> CacheEntry {
        self.hasher
            .clone()
            .update(bundle_commitment)
            .update(bundle_authorizing_commitment)
            .update(sighash)
            .finalize()
            .as_bytes()
            .try_into()
            .map(CacheEntry)
            .expect("BLAKE2b configured with hash length of 32 so conversion cannot fail")
    }

    pub(crate) fn insert(&mut self, queued_entries: CacheEntries) {
        if let CacheEntries::Storing(cache_entries) = queued_entries {
            for cache_entry in cache_entries {
                self.cache.pin_mut().insert(cache_entry.0);
            }
        }
    }

    pub(crate) fn contains(&self, entry: CacheEntry, queued_entries: &mut CacheEntries) -> bool {
        if self
            .cache
            .contains(&entry.0, matches!(queued_entries, CacheEntries::NotStoring))
        {
            true
        } else {
            if let CacheEntries::Storing(cache_entries) = queued_entries {
                cache_entries.push(entry);
            }
            false
        }
    }
}

static SAPLING_BUNDLE_VALIDITY_CACHE: OnceLock<RwLock<BundleValidityCache>> = OnceLock::new();

pub(crate) fn init(cache_bytes: usize) {
    SAPLING_BUNDLE_VALIDITY_CACHE.get_or_init(|| {
        RwLock::new(BundleValidityCache::new(
            "Sapling",
            b"KrrgnSaplCache\0\0", // Kerrigan-specific personalization
            cache_bytes,
        ))
    });
}

pub(crate) fn sapling_bundle_validity_cache() -> RwLockReadGuard<'static, BundleValidityCache> {
    SAPLING_BUNDLE_VALIDITY_CACHE
        .get()
        .expect("bundlecache::init() must be called before validation")
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) fn sapling_bundle_validity_cache_mut() -> RwLockWriteGuard<'static, BundleValidityCache>
{
    SAPLING_BUNDLE_VALIDITY_CACHE
        .get()
        .expect("bundlecache::init() must be called before validation")
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
