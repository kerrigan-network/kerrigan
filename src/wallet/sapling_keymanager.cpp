// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license.

#include <wallet/sapling_keymanager.h>

#include <consensus/amount.h>
#include <evo/specialtx.h>
#include <primitives/block.h>
#include <sapling/sapling_init.h>
#include <sapling/sapling_tx_payload.h>
// bridge.h is the authoritative source for zip32 structs/functions. Include it
// before sapling_zip32.h would be included transitively to avoid redefinition.
// sapling_zip32.h is intentionally omitted here; bridge.h provides a superset.
#include <rust/bridge.h>
#include <rust/spec.h>
#include <wallet/crypter.h>
#include <wallet/walletdb.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cstring>
#include <string>

namespace wallet {

bool SaplingKeyManager::AddFvkInternal(const sapling::SaplingFullViewingKey& fvk,
                                       const std::array<uint8_t, 32>& dk,
                                       const sapling::SaplingIncomingViewingKey& ivk)
{
    // Store FVK and DK keyed by IVK
    mapIvkToFvk[ivk] = fvk;
    mapIvkToDk[ivk] = dk;

    // Derive the FVK as a contiguous 96-byte array for the Rust FFI
    std::array<uint8_t, 96> fvk_bytes;
    std::copy(fvk.ak.begin(), fvk.ak.end(), fvk_bytes.begin());
    std::copy(fvk.nk.begin(), fvk.nk.end(), fvk_bytes.begin() + 32);
    std::copy(fvk.ovk.begin(), fvk.ovk.end(), fvk_bytes.begin() + 64);

    // Derive the default payment address via Rust FFI
    std::array<uint8_t, 43> addr_bytes;
    try {
        addr_bytes = sapling::zip32::fvk_default_address(fvk_bytes, dk);
    } catch (const std::exception& e) {
        LogPrintf("SaplingKeyManager::AddFvkInternal: fvk_default_address failed: %s\n", e.what());
        return false;
    }

    sapling::SaplingPaymentAddress addr;
    std::copy(addr_bytes.begin(), addr_bytes.begin() + 11, addr.d.begin());
    std::copy(addr_bytes.begin() + 11, addr_bytes.end(), addr.pk_d.begin());

    // Register the address
    mapIvkToAddresses[ivk].insert(addr);
    mapAddressToIvk[addr] = ivk;

    return true;
}

bool SaplingKeyManager::AddSpendingKey(const sapling::SaplingExtendedSpendingKey& sk)
{
    LOCK(cs);

    // Extract FVK (96 bytes), DK (32 bytes), IVK (32 bytes) from the ExtSK via Rust FFI
    std::array<uint8_t, 96> fvk_bytes;
    std::array<uint8_t, 32> ivk_bytes;
    try {
        fvk_bytes = sapling::zip32::xsk_to_fvk(sk.key);
        ivk_bytes = sapling::zip32::xsk_to_ivk(sk.key);
    } catch (const std::exception& e) {
        LogPrintf("SaplingKeyManager::AddSpendingKey: invalid ExtSK: %s\n", e.what());
        return false;
    }
    std::array<uint8_t, 32> dk_bytes;
    try {
        dk_bytes = sapling::zip32::xsk_to_dk(sk.key);
    } catch (const std::exception& e) {
        LogPrintf("SaplingKeyManager::AddSpendingKey: xsk_to_dk failed: %s\n", e.what());
        return false;
    }

    // Build C++ key structs
    sapling::SaplingFullViewingKey fvk;
    std::copy(fvk_bytes.begin(), fvk_bytes.begin() + 32, fvk.ak.begin());
    std::copy(fvk_bytes.begin() + 32, fvk_bytes.begin() + 64, fvk.nk.begin());
    std::copy(fvk_bytes.begin() + 64, fvk_bytes.end(), fvk.ovk.begin());

    sapling::SaplingIncomingViewingKey ivk;
    ivk.key = ivk_bytes;

    // Register FVK, DK, default address
    if (!AddFvkInternal(fvk, dk_bytes, ivk)) {
        return false;
    }

    // Store the ExtSK and mark this IVK as spendable
    mapIvkToExtSk[ivk] = sk;
    setSpendableIvks.insert(ivk);

    // Also register the internal FVK so the wallet can detect change notes
    // sent to internal addresses (ZIP 316 unlinkable change).
    try {
        auto internalResult = sapling::zip32::derive_internal_fvk(fvk_bytes, dk_bytes);
        auto internal_ivk_bytes = sapling::zip32::fvk_to_ivk(internalResult.fvk);

        sapling::SaplingFullViewingKey internalFvk;
        std::copy(internalResult.fvk.begin(), internalResult.fvk.begin() + 32, internalFvk.ak.begin());
        std::copy(internalResult.fvk.begin() + 32, internalResult.fvk.begin() + 64, internalFvk.nk.begin());
        std::copy(internalResult.fvk.begin() + 64, internalResult.fvk.end(), internalFvk.ovk.begin());

        sapling::SaplingIncomingViewingKey internalIvk;
        internalIvk.key = internal_ivk_bytes;

        // Register the internal FVK so ScanSaplingOutputs can detect change
        AddFvkInternal(internalFvk, internalResult.dk, internalIvk);

        // Derive the internal ExtSK so the wallet can spend internal notes.
        // The builder's add_spend() derives the FVK from the ExtSK, so we
        // need the internal ExtSK (not the external one) for internal notes.
        auto internalXskBytes = sapling::zip32::xsk_derive_internal(sk.key);
        sapling::SaplingExtendedSpendingKey internalSk;
        internalSk.key = internalXskBytes;

        mapIvkToExtSk[internalIvk] = internalSk;
        setSpendableIvks.insert(internalIvk);
    } catch (const std::exception& e) {
        LogPrintf("SaplingKeyManager: failed to derive internal FVK: %s (non-fatal)\n", e.what());
    }

    // First spending key becomes the default for GenerateNewAddress
    if (!defaultIvk.has_value()) {
        defaultIvk = ivk;
    }

    LogPrint(BCLog::SAPLING, "SaplingKeyManager: added spending key, %d address(es) total\n",
              mapAddressToIvk.size());
    return true;
}

bool SaplingKeyManager::AddViewingKey(const sapling::SaplingFullViewingKey& fvk, const std::array<uint8_t, 32>& dk)
{
    LOCK(cs);

    // Derive IVK from FVK via Rust FFI
    std::array<uint8_t, 96> fvk_bytes;
    std::copy(fvk.ak.begin(), fvk.ak.end(), fvk_bytes.begin());
    std::copy(fvk.nk.begin(), fvk.nk.end(), fvk_bytes.begin() + 32);
    std::copy(fvk.ovk.begin(), fvk.ovk.end(), fvk_bytes.begin() + 64);

    std::array<uint8_t, 32> ivk_bytes;
    try {
        ivk_bytes = sapling::zip32::fvk_to_ivk(fvk_bytes);
    } catch (const std::exception& e) {
        LogPrintf("SaplingKeyManager::AddViewingKey: invalid FVK: %s\n", e.what());
        return false;
    }

    sapling::SaplingIncomingViewingKey ivk;
    ivk.key = ivk_bytes;

    // Register FVK, DK, default address (but NOT as spendable)
    if (!AddFvkInternal(fvk, dk, ivk)) {
        return false;
    }

    LogPrint(BCLog::SAPLING, "SaplingKeyManager: added viewing key (watch-only), %d address(es) total\n",
              mapAddressToIvk.size());
    return true;
}

std::optional<sapling::SaplingPaymentAddress> SaplingKeyManager::GenerateNewAddress()
{
    LOCK(cs);

    if (!defaultIvk.has_value()) {
        LogPrintf("SaplingKeyManager: no default spending key, cannot generate address\n");
        return std::nullopt;
    }

    const auto& ivk = defaultIvk.value();

    // Look up the FVK and DK for the default key
    auto fvkIt = mapIvkToFvk.find(ivk);
    auto dkIt = mapIvkToDk.find(ivk);
    if (fvkIt == mapIvkToFvk.end() || dkIt == mapIvkToDk.end()) {
        LogPrintf("SaplingKeyManager::%s -- FVK or DK not found for default IVK\n", __func__);
        return std::nullopt;
    }

    const auto& fvk = fvkIt->second;
    const auto& dk = dkIt->second;

    // Build 96-byte FVK for FFI
    std::array<uint8_t, 96> fvk_bytes;
    std::copy(fvk.ak.begin(), fvk.ak.end(), fvk_bytes.begin());
    std::copy(fvk.nk.begin(), fvk.nk.end(), fvk_bytes.begin() + 32);
    std::copy(fvk.ovk.begin(), fvk.ovk.end(), fvk_bytes.begin() + 64);

    // Encode current diversifier index as 11-byte little-endian
    std::array<uint8_t, 11> j{};
    uint64_t idx = nDiversifierIndex;
    for (int i = 0; i < 8 && i < 11; ++i) {
        j[i] = static_cast<uint8_t>(idx & 0xff);
        idx >>= 8;
    }

    // Find the next valid diversified address via Rust FFI
    sapling::zip32::Zip32Address result;
    try {
        result = sapling::zip32::find_address(fvk_bytes, dk, j);
    } catch (const std::exception& e) {
        LogPrintf("SaplingKeyManager: find_address failed: %s\n", e.what());
        return std::nullopt;
    }

    // Build the payment address from the result
    sapling::SaplingPaymentAddress addr;
    std::copy(result.addr.begin(), result.addr.begin() + 11, addr.d.begin());
    std::copy(result.addr.begin() + 11, result.addr.end(), addr.pk_d.begin());

    // Update the diversifier index to one past the returned index
    uint64_t returned_idx = 0;
    for (int i = 7; i >= 0; --i) {
        returned_idx = (returned_idx << 8) | result.j[i];
    }
    nDiversifierIndex = returned_idx + 1;

    // Register the new address
    mapIvkToAddresses[ivk].insert(addr);
    mapAddressToIvk[addr] = ivk;

    return addr;
}

bool SaplingKeyManager::HaveAddress(const sapling::SaplingPaymentAddress& addr) const
{
    LOCK(cs);
    return mapAddressToIvk.count(addr) > 0;
}

bool SaplingKeyManager::CanSpend(const sapling::SaplingPaymentAddress& addr) const
{
    LOCK(cs);
    auto it = mapAddressToIvk.find(addr);
    if (it == mapAddressToIvk.end()) return false;
    return setSpendableIvks.count(it->second) > 0;
}

std::optional<sapling::SaplingIncomingViewingKey> SaplingKeyManager::GetIvk(const sapling::SaplingPaymentAddress& addr) const
{
    LOCK(cs);
    auto it = mapAddressToIvk.find(addr);
    if (it == mapAddressToIvk.end()) return std::nullopt;
    return it->second;
}

std::optional<sapling::SaplingExtendedSpendingKey> SaplingKeyManager::GetSpendingKey(const sapling::SaplingPaymentAddress& addr) const
{
    LOCK(cs);
    auto ivkIt = mapAddressToIvk.find(addr);
    if (ivkIt == mapAddressToIvk.end()) return std::nullopt;
    auto skIt = mapIvkToExtSk.find(ivkIt->second);
    if (skIt == mapIvkToExtSk.end()) return std::nullopt;
    return skIt->second;
}

std::optional<sapling::SaplingFullViewingKey> SaplingKeyManager::GetFvk(const sapling::SaplingPaymentAddress& addr) const
{
    LOCK(cs);
    auto ivkIt = mapAddressToIvk.find(addr);
    if (ivkIt == mapAddressToIvk.end()) return std::nullopt;
    auto fvkIt = mapIvkToFvk.find(ivkIt->second);
    if (fvkIt == mapIvkToFvk.end()) return std::nullopt;
    return fvkIt->second;
}

std::optional<std::array<uint8_t, 32>> SaplingKeyManager::GetDk(const sapling::SaplingPaymentAddress& addr) const
{
    LOCK(cs);
    auto ivkIt = mapAddressToIvk.find(addr);
    if (ivkIt == mapAddressToIvk.end()) return std::nullopt;
    auto dkIt = mapIvkToDk.find(ivkIt->second);
    if (dkIt == mapIvkToDk.end()) return std::nullopt;
    return dkIt->second;
}

std::vector<sapling::SaplingPaymentAddress> SaplingKeyManager::GetAllAddresses() const
{
    LOCK(cs);
    std::vector<sapling::SaplingPaymentAddress> result;
    result.reserve(mapAddressToIvk.size());
    for (const auto& [addr, ivk] : mapAddressToIvk) {
        result.push_back(addr);
    }
    return result;
}

std::vector<sapling::SaplingIncomingViewingKey> SaplingKeyManager::GetAllIvks() const
{
    LOCK(cs);
    std::vector<sapling::SaplingIncomingViewingKey> result;
    result.reserve(mapIvkToAddresses.size());
    for (const auto& [ivk, addrs] : mapIvkToAddresses) {
        result.push_back(ivk);
    }
    return result;
}

bool SaplingKeyManager::HaveIvk(const sapling::SaplingIncomingViewingKey& ivk) const
{
    LOCK(cs);
    return mapIvkToFvk.count(ivk) > 0;
}

bool SaplingKeyManager::IsEmpty() const
{
    LOCK(cs);
    return mapIvkToAddresses.empty();
}

size_t SaplingKeyManager::GetSpendableKeyCount() const
{
    LOCK(cs);
    return setSpendableIvks.size();
}

size_t SaplingKeyManager::GetNoteCount() const
{
    LOCK(cs);
    return mapSaplingNotes.size();
}

int SaplingKeyManager::ValidateConsistency() const
{
    LOCK(cs);
    int nIssues = 0;

    // For each spending key, verify the corresponding FVK exists and matches
    for (const auto& [ivk, sk] : mapIvkToExtSk) {
        // FVK record must exist for this IVK
        auto fvk_it = mapIvkToFvk.find(ivk);
        if (fvk_it == mapIvkToFvk.end()) {
            LogPrintf("WARNING: Sapling spending key has no FVK record (IVK=%s). "
                      "Shielded balance may not display correctly.\n",
                      HexStr(ivk.key));
            ++nIssues;
            continue;
        }

        // Re-derive FVK from spending key and compare to stored FVK
        try {
            auto derived_fvk_bytes = sapling::zip32::xsk_to_fvk(sk.key);
            const sapling::SaplingFullViewingKey& stored_fvk = fvk_it->second;
            bool mismatch = false;
            if (!std::equal(derived_fvk_bytes.begin(), derived_fvk_bytes.begin() + 32, stored_fvk.ak.begin())) mismatch = true;
            if (!std::equal(derived_fvk_bytes.begin() + 32, derived_fvk_bytes.begin() + 64, stored_fvk.nk.begin())) mismatch = true;
            if (!std::equal(derived_fvk_bytes.begin() + 64, derived_fvk_bytes.end(), stored_fvk.ovk.begin())) mismatch = true;

            if (mismatch) {
                LogPrintf("WARNING: Sapling FVK does not match spending key derivation (IVK=%s). "
                          "Stored FVK may be corrupted. Shielded transactions may fail.\n",
                          HexStr(ivk.key));
                ++nIssues;
            }
        } catch (const std::exception& e) {
            LogPrintf("WARNING: Failed to re-derive Sapling FVK from spending key (IVK=%s): %s\n",
                      HexStr(ivk.key), e.what());
            ++nIssues;
        }
    }

    // Every FVK should have at least one associated address
    for (const auto& [ivk, fvk] : mapIvkToFvk) {
        auto addr_it = mapIvkToAddresses.find(ivk);
        if (addr_it == mapIvkToAddresses.end() || addr_it->second.empty()) {
            LogPrintf("WARNING: Sapling FVK has no associated addresses (IVK=%s). "
                      "Address generation may have failed.\n",
                      HexStr(ivk.key));
            ++nIssues;
        }
    }

    if (nIssues > 0) {
        LogPrintf("Sapling key consistency check found %d issue(s)\n", nIssues);
    }

    return nIssues;
}

// DB load helpers

bool SaplingKeyManager::LoadSpendingKey(const sapling::SaplingIncomingViewingKey& ivk,
                                        const sapling::SaplingExtendedSpendingKey& sk)
{
    LOCK(cs);
    mapIvkToExtSk[ivk] = sk;
    setSpendableIvks.insert(ivk);
    if (!defaultIvk.has_value()) {
        defaultIvk = ivk;
    }
    return true;
}

bool SaplingKeyManager::LoadViewingKey(const sapling::SaplingIncomingViewingKey& ivk,
                                       const sapling::SaplingFullViewingKey& fvk,
                                       const std::array<uint8_t, 32>& dk)
{
    LOCK(cs);
    mapIvkToFvk[ivk] = fvk;
    mapIvkToDk[ivk] = dk;
    // Ensure the IVK appears in the address map so GetAllIvks() includes it
    mapIvkToAddresses.emplace(ivk, std::set<sapling::SaplingPaymentAddress>{});
    return true;
}

void SaplingKeyManager::LoadAddress(const sapling::SaplingPaymentAddress& addr,
                                    const sapling::SaplingIncomingViewingKey& ivk)
{
    LOCK(cs);
    mapIvkToAddresses[ivk].insert(addr);
    mapAddressToIvk[addr] = ivk;
}

void SaplingKeyManager::LoadCryptedSpendingKey(const sapling::SaplingIncomingViewingKey& ivk,
                                               const std::vector<unsigned char>& vchCryptedSecret)
{
    LOCK(cs);
    mapIvkToCryptedExtSk[ivk] = vchCryptedSecret;
    setSpendableIvks.insert(ivk);
    fUseCrypto = true;
    if (!defaultIvk.has_value()) {
        defaultIvk = ivk;
    }
}

void SaplingKeyManager::LoadDiversifierIndex(uint64_t index)
{
    LOCK(cs);
    if (index > nDiversifierIndex) {
        nDiversifierIndex = index;
    }
}

bool SaplingKeyManager::EncryptKeys(const CKeyingMaterial& vMasterKey, WalletBatch& batch)
{
    LOCK(cs);
    if (fUseCrypto) {
        LogPrintf("SaplingKeyManager::%s -- keys already encrypted\n", __func__);
        return false; // already encrypted
    }
    // Collect IVKs first to avoid iterator invalidation.
    std::vector<sapling::SaplingIncomingViewingKey> ivksToEncrypt;
    ivksToEncrypt.reserve(mapIvkToExtSk.size());
    for (const auto& [ivk, sk] : mapIvkToExtSk) {
        ivksToEncrypt.push_back(ivk);
    }
    for (const auto& ivk : ivksToEncrypt) {
        auto it = mapIvkToExtSk.find(ivk);
        if (it == mapIvkToExtSk.end()) continue;
        CKeyingMaterial skMaterial(it->second.key.begin(), it->second.key.end());
        uint256 ivk_hash;
        std::copy(ivk.key.begin(), ivk.key.end(), ivk_hash.begin());
        std::vector<unsigned char> vchCryptedSecret;
        if (!EncryptSecret(vMasterKey, skMaterial, ivk_hash, vchCryptedSecret)) {
            LogPrintf("SaplingKeyManager::%s -- EncryptSecret failed\n", __func__);
            return false;
        }
        mapIvkToCryptedExtSk[ivk] = vchCryptedSecret;
        if (!batch.WriteCryptedSaplingSpendingKey(ivk, vchCryptedSecret)) {
            LogPrintf("SaplingKeyManager::%s -- WriteCryptedSaplingSpendingKey failed\n", __func__);
            return false;
        }
        // Cleanse plaintext immediately after encryption
        memory_cleanse(it->second.key.data(), it->second.key.size());
        mapIvkToExtSk.erase(it);
    }
    fUseCrypto = true;
    return true;
}

bool SaplingKeyManager::Unlock(const CKeyingMaterial& vMasterKey)
{
    LOCK(cs);
    if (!fUseCrypto) {
        return true; // unencrypted wallet, nothing to do
    }
    for (const auto& [ivk, vchCryptedSecret] : mapIvkToCryptedExtSk) {
        uint256 ivk_hash;
        std::copy(ivk.key.begin(), ivk.key.end(), ivk_hash.begin());
        CKeyingMaterial skMaterial;
        if (!DecryptSecret(vMasterKey, vchCryptedSecret, ivk_hash, skMaterial)) {
            LogPrintf("SaplingKeyManager::%s -- DecryptSecret failed\n", __func__);
            return false;
        }
        if (skMaterial.size() != 169) {
            LogPrintf("SaplingKeyManager::%s -- decrypted key has wrong size %u (expected 169)\n", __func__, skMaterial.size());
            return false;
        }
        sapling::SaplingExtendedSpendingKey sk;
        std::copy(skMaterial.begin(), skMaterial.end(), sk.key.begin());

        // Verify the decrypted spending key corresponds to the stored IVK.
        // Without this check, a corrupted or tampered encrypted key blob
        // could silently load an unrelated spending key under the wrong IVK,
        // leading to incorrect spend authorization or balance display.
        try {
            auto derivedIvkBytes = sapling::zip32::xsk_to_ivk(sk.key);
            if (derivedIvkBytes != ivk.key) {
                LogPrintf("ERROR: SaplingKeyManager::%s -- decrypted spending key does not match stored IVK\n", __func__);
                return false;
            }
        } catch (const std::exception& e) {
            LogPrintf("ERROR: SaplingKeyManager::%s -- failed to derive IVK from decrypted key: %s\n", __func__, e.what());
            return false;
        }

        mapIvkToExtSk[ivk] = sk;
    }
    return true;
}

void SaplingKeyManager::Lock()
{
    LOCK(cs);
    for (auto& [ivk, sk] : mapIvkToExtSk) {
        memory_cleanse(sk.key.data(), sk.key.size());
    }
    mapIvkToExtSk.clear();
}

bool SaplingKeyManager::IsCrypto() const
{
    LOCK(cs);
    return fUseCrypto;
}

void SaplingKeyManager::LoadNote(const uint256& cmu, const SaplingNoteData& nd)
{
    if (!MoneyRange(nd.value)) {
        LogPrintf("WARNING: SaplingKeyManager::LoadNote: note %s has invalid value %lld, skipping\n",
                  cmu.ToString(), nd.value);
        return;
    }
    LOCK(cs);
    mapSaplingNotes[cmu] = nd;
}

// DB persistence hooks

bool SaplingKeyManager::AddSpendingKeyWithDB(WalletBatch& batch, const sapling::SaplingExtendedSpendingKey& sk,
                                             const CKeyingMaterial* vMasterKey)
{
    // AddSpendingKey() derives ivk via FFI; we need the IVK to write the record.
    // So we call AddSpendingKey first (which populates mapIvkToExtSk), then look it up.
    if (!AddSpendingKey(sk)) {
        return false;
    }

    // Derive the internal ExtSK so we can identify the internal IVK entry
    std::array<uint8_t, 169> internalXskBytes{};
    bool haveInternal = false;
    try {
        internalXskBytes = sapling::zip32::xsk_derive_internal(sk.key);
        haveInternal = true;
    } catch (const std::exception&) {}

    // Persist both external and internal key records
    LOCK(cs);
    std::vector<sapling::SaplingIncomingViewingKey> toErase; // plaintext IVKs to remove after encrypt
    for (const auto& [ivk, stored_sk] : mapIvkToExtSk) {
        bool isExternal = (stored_sk.key == sk.key);
        bool isInternal = haveInternal && (stored_sk.key == internalXskBytes);
        if (!isExternal && !isInternal) continue;

        auto fvkIt = mapIvkToFvk.find(ivk);
        auto dkIt = mapIvkToDk.find(ivk);
        if (fvkIt == mapIvkToFvk.end() || dkIt == mapIvkToDk.end()) {
            if (isExternal) return false;
            continue; // skip internal if missing (shouldn't happen)
        }

        // If the wallet is encrypted, write the encrypted key blob instead of plaintext.
        // The master key is held in memory (decrypted) while the wallet is unlocked.
        if (fUseCrypto) {
            if (!vMasterKey) {
                LogPrintf("ERROR: SaplingKeyManager::%s -- encrypted wallet but no master key provided\n", __func__);
                return false;
            }
            CKeyingMaterial skMaterial(stored_sk.key.begin(), stored_sk.key.end());
            uint256 ivk_hash;
            std::copy(ivk.key.begin(), ivk.key.end(), ivk_hash.begin());
            std::vector<unsigned char> vchCryptedSecret;
            if (!EncryptSecret(*vMasterKey, skMaterial, ivk_hash, vchCryptedSecret)) {
                LogPrintf("ERROR: SaplingKeyManager::%s -- EncryptSecret failed\n", __func__);
                return false;
            }
            mapIvkToCryptedExtSk[ivk] = vchCryptedSecret;
            // Mark for plaintext removal after the loop (can't erase while iterating)
            toErase.push_back(ivk);
            if (!batch.WriteCryptedSaplingSpendingKey(ivk, vchCryptedSecret)) {
                LogPrintf("ERROR: SaplingKeyManager::%s -- WriteCryptedSaplingSpendingKey failed\n", __func__);
                return false;
            }
        } else {
            if (!batch.WriteSaplingExtendedSpendingKey(ivk, stored_sk)) return false;
        }

        if (!batch.WriteSaplingFullViewingKey(ivk, fvkIt->second, dkIt->second)) return false;
        // Write all addresses derived for this ivk
        auto addrIt = mapIvkToAddresses.find(ivk);
        if (addrIt != mapIvkToAddresses.end()) {
            for (const auto& addr : addrIt->second) {
                if (!batch.WriteSaplingPaymentAddress(addr, ivk)) return false;
            }
        }
    }
    // Remove plaintext keys after loop to avoid iterator invalidation
    for (const auto& ivk : toErase) {
        auto it = mapIvkToExtSk.find(ivk);
        if (it != mapIvkToExtSk.end()) {
            memory_cleanse(it->second.key.data(), it->second.key.size());
            mapIvkToExtSk.erase(it);
        }
    }
    return true;
}

bool SaplingKeyManager::AddViewingKeyWithDB(WalletBatch& batch, const sapling::SaplingFullViewingKey& fvk, const std::array<uint8_t, 32>& dk)
{
    if (!AddViewingKey(fvk, dk)) {
        return false;
    }
    // Derive IVK from FVK to look up the stored record
    std::array<uint8_t, 96> fvk_bytes;
    std::copy(fvk.ak.begin(), fvk.ak.end(), fvk_bytes.begin());
    std::copy(fvk.nk.begin(), fvk.nk.end(), fvk_bytes.begin() + 32);
    std::copy(fvk.ovk.begin(), fvk.ovk.end(), fvk_bytes.begin() + 64);
    std::array<uint8_t, 32> ivk_bytes;
    try {
        ivk_bytes = sapling::zip32::fvk_to_ivk(fvk_bytes);
    } catch (const std::exception& e) {
        LogPrintf("SaplingKeyManager::AddViewingKeyWithDB: invalid FVK: %s\n", e.what());
        return false;
    }

    sapling::SaplingIncomingViewingKey ivk;
    ivk.key = ivk_bytes;

    LOCK(cs);
    if (!batch.WriteSaplingFullViewingKey(ivk, fvk, dk)) return false;
    auto addrIt = mapIvkToAddresses.find(ivk);
    if (addrIt != mapIvkToAddresses.end()) {
        for (const auto& addr : addrIt->second) {
            if (!batch.WriteSaplingPaymentAddress(addr, ivk)) return false;
        }
    }
    return true;
}

bool SaplingKeyManager::WriteAddressToDB(WalletBatch& batch, const sapling::SaplingPaymentAddress& addr)
{
    LOCK(cs);
    auto it = mapAddressToIvk.find(addr);
    if (it == mapAddressToIvk.end()) {
        return false;
    }
    return batch.WriteSaplingPaymentAddress(addr, it->second);
}

bool SaplingKeyManager::WriteDiversifierIndexToDB(WalletBatch& batch)
{
    LOCK(cs);
    if (!defaultIvk.has_value()) {
        return true; // nothing to persist
    }
    // Key the diversifier index by the hash of the default IVK bytes
    uint256 seed_hash;
    std::copy(defaultIvk.value().key.begin(), defaultIvk.value().key.end(), seed_hash.begin());
    return batch.WriteSaplingDiversifierIndex(seed_hash, nDiversifierIndex);
}

// Note tracking

/**
 * Build a consensus::Network Rust object for note decryption FFI calls.
 * Uses the same convention as SaplingTransactionBuilder::MakeRustNetwork.
 */
static rust::Box<::consensus::Network> MakeNoteDecryptionNetwork(
    const std::string& networkIDStr, int saplingHeight)
{
    if (networkIDStr == "main")
        return ::consensus::network("main", -1, -1, -1, -1, -1, -1, -1, -1);
    if (networkIDStr == "test")
        return ::consensus::network("test", -1, -1, -1, -1, -1, -1, -1, -1);
    return ::consensus::network("regtest",
        /*overwinter=*/-1, /*sapling=*/saplingHeight,
        /*blossom=*/-1, /*heartwood=*/-1, /*canopy=*/-1,
        /*nu5=*/-1, /*nu6=*/-1, /*nu6_1=*/-1);
}

void SaplingKeyManager::ScanSaplingOutputs(const CTransaction& tx,
                                            const SaplingTxPayload& payload,
                                            int blockHeight,
                                            const std::string& networkIDStr,
                                            int saplingHeight,
                                            WalletBatch* batch)
{
    if (payload.vOutputDescriptions.empty()) return;

    // Snapshot IVKs without holding cs during FFI calls (which can be slow).
    std::vector<sapling::SaplingIncomingViewingKey> ivks;
    {
        LOCK(cs);
        if (mapIvkToAddresses.empty()) return;
        ivks.reserve(mapIvkToAddresses.size());
        for (const auto& [ivk, _] : mapIvkToAddresses) {
            ivks.push_back(ivk);
        }
    }

    auto rustNetwork = MakeNoteDecryptionNetwork(networkIDStr, saplingHeight);
    const uint32_t height = blockHeight >= 0 ? static_cast<uint32_t>(blockHeight) : 0u;
    const uint256 txid = tx.GetHash();

    for (int outIdx = 0; outIdx < static_cast<int>(payload.vOutputDescriptions.size()); ++outIdx) {
        const SaplingOutputDescription& od = payload.vOutputDescriptions[outIdx];

        // Build the SaplingShieldedOutput struct expected by the Rust FFI.
        ::wallet::SaplingShieldedOutput ffi_output;
        ffi_output.cv             = od.cv;
        ffi_output.cmu            = od.cmu;
        ffi_output.ephemeral_key  = od.ephemeralKey;
        ffi_output.enc_ciphertext = od.encCiphertext;
        ffi_output.out_ciphertext = od.outCiphertext;

        // Use cmu as a unique per-output key (one commitment per output).
        uint256 noteKey;
        std::copy(od.cmu.begin(), od.cmu.end(), noteKey.begin());

        // Check if already recorded. Handle re-confirmation of rewound notes.
        {
            LOCK(cs);
            auto existIt = mapSaplingNotes.find(noteKey);
            if (existIt != mapSaplingNotes.end()) {
                if (existIt->second.blockHeight == -1 && blockHeight >= 0) {
                    // Re-confirmation after reorg: update height but preserve
                    // spend state; the spending tx may still be valid.
                    existIt->second.blockHeight = blockHeight;
                    if (batch) batch->WriteSaplingNote(noteKey, existIt->second);
                    LogPrint(BCLog::SAPLING, "SaplingKeyManager: re-confirmed note %s at height %d\n",
                              noteKey.ToString(), blockHeight);
                }
                continue;
            }
        }

        for (const auto& ivk : ivks) {
            try {
                auto decrypted = ::wallet::try_sapling_note_decryption(
                    *rustNetwork,
                    height,
                    ivk.key,
                    ffi_output);

                // Decryption succeeded, build the note record.
                SaplingNoteData nd;
                nd.ivk         = ivk;
                nd.value       = static_cast<CAmount>(decrypted->note_value());
                if (!MoneyRange(nd.value)) {
                    LogPrint(BCLog::SAPLING, "SaplingKeyManager: ignoring note with out-of-range value %lld in txid=%s outIdx=%d\n",
                              nd.value, txid.GetHex(), outIdx);
                    continue;
                }
                nd.rseed       = decrypted->note_rseed();
                nd.txid        = txid;
                nd.outputIndex = outIdx;
                nd.blockHeight = blockHeight;

                // Build recipient payment address from diversifier + pk_d.
                auto d    = decrypted->recipient_d();
                auto pk_d = decrypted->recipient_pk_d();
                std::copy(d.begin(), d.end(), nd.recipient.d.begin());
                std::copy(pk_d.begin(), pk_d.end(), nd.recipient.pk_d.begin());

                nd.memo = decrypted->memo();

                // The Sapling nullifier requires the commitment tree position,
                // only known once the note is confirmed in a block.  Leave
                // nd.nullifier as all-zeros for now; spend detection uses the
                // SpendDescription nullifier field directly.

                CAmount noteValue = nd.value;
                LOCK(cs);
                if (mapSaplingNotes.count(noteKey) == 0) {
                    mapSaplingNotes[noteKey] = std::move(nd);
                    if (batch) batch->WriteSaplingNote(noteKey, mapSaplingNotes[noteKey]);
                    LogPrint(BCLog::SAPLING, "SaplingKeyManager: received note txid=%s outIdx=%d value=%lld sat\n",
                              txid.GetHex(), outIdx, noteValue);
                }

                // Each output decrypts by exactly one IVK.
                break;
            } catch (const std::exception&) {
                // Not for this IVK, try the next one.
                continue;
            }
        }
    }
}

void SaplingKeyManager::ScanSaplingSpends(const CTransaction& tx,
                                           const SaplingTxPayload& payload,
                                           WalletBatch* batch)
{
    if (payload.vSpendDescriptions.empty()) return;

    const uint256 spendingTxid = tx.GetHash();

    LOCK(cs);
    for (const auto& spend : payload.vSpendDescriptions) {
        // The spend's nullifier is 32 bytes; convert to uint256 for map lookup.
        uint256 nf;
        std::copy(spend.nullifier.begin(), spend.nullifier.end(), nf.begin());

        // Search all stored notes for a matching nullifier.
        for (auto& [key, nd] : mapSaplingNotes) {
            if (!nd.isSpent && nd.nullifier == nf && !nf.IsNull()) {
                nd.isSpent       = true;
                nd.spendingTxid  = spendingTxid;
                if (batch) batch->WriteSaplingNote(key, nd);
                LogPrint(BCLog::SAPLING, "SaplingKeyManager: note spent txid=%s by %s\n",
                          nd.txid.GetHex(), spendingTxid.GetHex());
                break;
            }
        }
    }
}

void SaplingKeyManager::UpdateWitnesses(int blockHeight, const std::vector<uint256>& blockCmus,
                                        WalletBatch* batch)
{
    LOCK(cs);
    if (blockCmus.empty() || mapSaplingNotes.empty()) return;

    // Load the frontier from the previous block.
    // Fail-closed: if frontier data is corrupt, skip witness update entirely
    // rather than proceeding with empty frontier which would corrupt witness paths.
    auto frontier = [&]() -> std::optional<rust::Box<sapling::tree::SaplingFrontier>> {
        std::vector<uint8_t> frontierData;
        if (blockHeight > 0 && sapling::GetFrontierData(blockHeight - 1, frontierData)) {
            rust::Slice<const uint8_t> slice(frontierData.data(), frontierData.size());
            try {
                return sapling::tree::frontier_deserialize(slice);
            } catch (const std::exception& e) {
                LogPrintf("ERROR: SaplingKeyManager::UpdateWitnesses: corrupt frontier at height %d: %s, skipping witness update (rescan required)\n",
                          blockHeight - 1, e.what());
                return std::nullopt;
            }
        }
        // No previous block or no frontier stored; fresh frontier is correct for genesis/early blocks
        return sapling::tree::new_sapling_frontier();
    }();
    if (!frontier.has_value()) return;

    // Deserialize all existing unspent witnesses into memory for batch update.
    struct LiveWitness {
        uint256 noteKey;
        rust::Box<sapling::tree::SaplingWitness> witness;
        LiveWitness(uint256 k, rust::Box<sapling::tree::SaplingWitness> w)
            : noteKey(std::move(k)), witness(std::move(w)) {}
    };
    std::vector<LiveWitness> liveWitnesses;
    for (auto& [key, nd] : mapSaplingNotes) {
        if (nd.isSpent || nd.witnessData.empty()) continue;
        rust::Slice<const uint8_t> slice(nd.witnessData.data(), nd.witnessData.size());
        try {
            liveWitnesses.emplace_back(key, sapling::tree::witness_deserialize(slice));
        } catch (const std::exception& e) {
            LogPrintf("WARN: Failed to deserialize witness for note %s, clearing for resync: %s\n", key.ToString(), e.what());
            nd.witnessData.clear();
            if (batch) batch->WriteSaplingNote(key, nd);
        }
    }

    // Process each commitment in block order.
    for (const auto& cmu : blockCmus) {
        std::array<uint8_t, 32> cmu_arr;
        std::memcpy(cmu_arr.data(), cmu.begin(), 32);

        // Update all existing witnesses with this new leaf.
        bool witnessUpdateFailed = false;
        for (auto& lw : liveWitnesses) {
            try {
                sapling::tree::witness_append(*lw.witness, cmu_arr);
            } catch (const std::exception& e) {
                LogPrintf("ERROR: Failed to update witness for note %s, clearing all witnesses for resync: %s\n",
                          lw.noteKey.ToString(), e.what());
                witnessUpdateFailed = true;
                break;
            }
        }
        if (witnessUpdateFailed) {
            // Clear all live witnesses to prevent persisting corrupted state
            for (auto& lw : liveWitnesses) {
                auto it = mapSaplingNotes.find(lw.noteKey);
                if (it != mapSaplingNotes.end()) {
                    it->second.witnessData.clear();
                    if (batch) batch->WriteSaplingNote(lw.noteKey, it->second);
                }
            }
            return;
        }

        // Append to frontier.
        try {
            sapling::tree::frontier_append(**frontier, cmu_arr);
        } catch (const std::exception& e) {
            LogPrintf("ERROR: SaplingKeyManager::UpdateWitnesses: failed to append: %s\n", e.what());
            return;
        }

        // If this cmu corresponds to an owned note without a witness, create one.
        auto it = mapSaplingNotes.find(cmu);
        if (it != mapSaplingNotes.end() && it->second.witnessData.empty() && !it->second.isSpent) {
            try {
                auto newWit = sapling::tree::witness_from_frontier(**frontier);
                uint64_t pos = sapling::tree::witness_position(*newWit);
                it->second.treePosition = static_cast<int64_t>(pos);
                liveWitnesses.emplace_back(cmu, std::move(newWit));

                // Derive the nullifier now that we know the position.
                auto fvkIt = mapIvkToFvk.find(it->second.ivk);
                if (fvkIt != mapIvkToFvk.end()) {
                    auto nf_arr = sapling::spec::compute_nf(
                        it->second.recipient.d,
                        it->second.recipient.pk_d,
                        static_cast<uint64_t>(it->second.value),
                        it->second.rseed,
                        fvkIt->second.nk,
                        pos);
                    std::copy(nf_arr.begin(), nf_arr.end(), it->second.nullifier.begin());
                    LogPrint(BCLog::SAPLING, "SaplingKeyManager: note %s nullifier=%s position=%lld\n",
                              cmu.ToString(), it->second.nullifier.GetHex(), pos);
                }

                LogPrint(BCLog::SAPLING, "SaplingKeyManager: created witness for note %s at position %lld\n",
                          cmu.ToString(), it->second.treePosition);
            } catch (const std::exception& e) {
                LogPrintf("WARN: Failed to create witness for note %s: %s\n", cmu.ToString(), e.what());
            }
        }
    }

    // Serialize all witnesses back to note data and persist.
    for (auto& lw : liveWitnesses) {
        auto it = mapSaplingNotes.find(lw.noteKey);
        if (it != mapSaplingNotes.end()) {
            auto data = sapling::tree::witness_serialize(*lw.witness);
            it->second.witnessData.assign(data.begin(), data.end());
            if (batch) batch->WriteSaplingNote(lw.noteKey, it->second);
        }
    }
}

CAmount SaplingKeyManager::GetSaplingBalance() const
{
    LOCK(cs);
    CAmount total = 0;
    for (const auto& [key, nd] : mapSaplingNotes) {
        // Also require witnessData; notes with cleared witnesses (post-reorg) are unspendable
        if (!nd.isSpent && nd.blockHeight >= 0 && !nd.witnessData.empty() && !m_reservedNotes.count(key)) {
            if (!MoneyRange(total + nd.value)) {
                LogPrintf("WARNING: Sapling balance overflow, capping at MAX_MONEY\n");
                return MAX_MONEY;
            }
            total += nd.value;
        }
    }
    return total;
}

CAmount SaplingKeyManager::GetSaplingBalance(const sapling::SaplingPaymentAddress& addr) const
{
    LOCK(cs);
    CAmount total = 0;
    for (const auto& [key, nd] : mapSaplingNotes) {
        if (!nd.isSpent && nd.blockHeight >= 0 && !nd.witnessData.empty() && nd.recipient == addr && !m_reservedNotes.count(key)) {
            if (!MoneyRange(total + nd.value)) {
                LogPrintf("WARNING: Sapling balance overflow, capping at MAX_MONEY\n");
                return MAX_MONEY;
            }
            total += nd.value;
        }
    }
    return total;
}

void SaplingKeyManager::ReserveNotes(const std::set<uint256>& cmus)
{
    LOCK(cs);
    m_reservedNotes.insert(cmus.begin(), cmus.end());
}

void SaplingKeyManager::UnreserveNotes(const std::set<uint256>& cmus)
{
    LOCK(cs);
    for (const auto& cmu : cmus) {
        m_reservedNotes.erase(cmu);
    }
}

void SaplingKeyManager::ReserveNotesByNullifier(const std::set<uint256>& nullifiers)
{
    LOCK(cs);
    for (const auto& [cmu, nd] : mapSaplingNotes) {
        if (nullifiers.count(nd.nullifier)) {
            m_reservedNotes.insert(cmu);
        }
    }
}

void SaplingKeyManager::UnreserveNotesByNullifier(const std::set<uint256>& nullifiers)
{
    LOCK(cs);
    for (const auto& [cmu, nd] : mapSaplingNotes) {
        if (nullifiers.count(nd.nullifier)) {
            m_reservedNotes.erase(cmu);
        }
    }
}

std::vector<std::pair<uint256, SaplingNoteData>> SaplingKeyManager::GetAllNotes() const
{
    LOCK(cs);
    std::vector<std::pair<uint256, SaplingNoteData>> result;
    result.reserve(mapSaplingNotes.size());
    for (const auto& [key, nd] : mapSaplingNotes) {
        result.emplace_back(key, nd);
    }
    return result;
}

std::vector<SaplingNoteData> SaplingKeyManager::GetUnspentNotes() const
{
    LOCK(cs);
    std::vector<SaplingNoteData> result;
    for (const auto& [key, nd] : mapSaplingNotes) {
        // Exclude notes with empty witnessData (cleared after reorg)
        if (!nd.isSpent && nd.blockHeight >= 0 && !nd.witnessData.empty() && !m_reservedNotes.count(key)) {
            result.push_back(nd);
        }
    }
    return result;
}

std::vector<SaplingNoteData> SaplingKeyManager::GetUnspentNotes(const sapling::SaplingPaymentAddress& addr) const
{
    LOCK(cs);
    std::vector<SaplingNoteData> result;
    for (const auto& [key, nd] : mapSaplingNotes) {
        if (!nd.isSpent && nd.blockHeight >= 0 && !nd.witnessData.empty() && nd.recipient == addr && !m_reservedNotes.count(key)) {
            result.push_back(nd);
        }
    }
    return result;
}

std::vector<std::pair<uint256, SaplingNoteData>> SaplingKeyManager::GetUnspentNotesWithKeys(const sapling::SaplingPaymentAddress& addr) const
{
    LOCK(cs);
    std::vector<std::pair<uint256, SaplingNoteData>> result;
    for (const auto& [key, nd] : mapSaplingNotes) {
        if (!nd.isSpent && nd.blockHeight >= 0 && !nd.witnessData.empty() && nd.recipient == addr && !m_reservedNotes.count(key)) {
            result.emplace_back(key, nd);
        }
    }
    return result;
}

void SaplingKeyManager::ZapNotesByTxid(const std::set<uint256>& txids, WalletBatch* batch)
{
    LOCK(cs);
    for (auto it = mapSaplingNotes.begin(); it != mapSaplingNotes.end();) {
        if (txids.count(it->second.txid)) {
            LogPrint(BCLog::SAPLING, "SaplingKeyManager::ZapNotesByTxid: erasing note %s (txid %s)\n",
                      it->first.ToString(), it->second.txid.ToString());
            if (batch) batch->EraseSaplingNote(it->first);  // Persist to DB
            it = mapSaplingNotes.erase(it);
        } else {
            // Also clear spend state if the spending tx was zapped
            if (it->second.isSpent && txids.count(it->second.spendingTxid)) {
                LogPrint(BCLog::SAPLING, "SaplingKeyManager::ZapNotesByTxid: unspending note %s (spendingTxid %s)\n",
                          it->first.ToString(), it->second.spendingTxid.ToString());
                it->second.isSpent = false;
                it->second.spendingTxid.SetNull();
                if (batch) batch->WriteSaplingNote(it->first, it->second);  // Persist to DB
            }
            ++it;
        }
    }
}

std::optional<int> SaplingKeyManager::ClearWitnessesForRebuild(WalletBatch* batch)
{
    LOCK(cs);
    std::optional<int> minHeight;
    for (auto& [key, nd] : mapSaplingNotes) {
        if (nd.isSpent || nd.blockHeight < 0) continue;
        if (!minHeight || nd.blockHeight < *minHeight) minHeight = nd.blockHeight;
        // Wipe witness + position; nullifier is preserved since it is only a
        // function of (fvk.nk, recipient, value, rseed, position) and position
        // will be reassigned when UpdateWitnesses hits this cmu again.
        nd.witnessData.clear();
        nd.treePosition = -1;
        if (batch) batch->WriteSaplingNote(key, nd);
    }
    return minHeight;
}

std::vector<SaplingKeyManager::StaleWitnessReport>
SaplingKeyManager::DetectStaleWitnesses(int walletTipHeight) const
{
    LOCK(cs);
    std::vector<StaleWitnessReport> stale;
    if (mapSaplingNotes.empty()) return stale;

    // Resolve the expected witness root once. Every unspent witness is
    // appended in lockstep with the wallet's block processing, so all
    // currently-healthy witnesses should yield this same root.
    std::optional<uint256> expectedTipRoot;
    if (walletTipHeight >= 0) {
        uint256 anchor;
        if (sapling::GetBestAnchor(walletTipHeight, anchor)) {
            expectedTipRoot = anchor;
        }
        // If the anchor isn't available (SaplingDB not yet caught up for
        // that height), we silently skip the root comparison and only
        // report deserialize failures. The caller is expected to retry
        // once the node is fully synced.
    }

    for (const auto& [key, nd] : mapSaplingNotes) {
        // Skip notes that are spent or still unconfirmed; we only validate
        // the witnesses we would actually use to spend.
        if (nd.isSpent || nd.blockHeight < 0) continue;

        // A confirmed unspent note with no witness is by definition stale;
        // the rebuild path will repopulate it when replaying blocks.
        if (nd.witnessData.empty()) {
            stale.push_back({key, nd.blockHeight, "empty witness data"});
            continue;
        }

        // Deserialize the witness and recompute its Merkle root. If either
        // step throws, the on-disk bytes are unusable and the witness must
        // be rebuilt from scratch.
        uint256 witnessRoot;
        try {
            rust::Slice<const uint8_t> slice(nd.witnessData.data(), nd.witnessData.size());
            auto witness = sapling::tree::witness_deserialize(slice);
            auto rootArr = sapling::tree::witness_root(*witness);
            std::memcpy(witnessRoot.begin(), rootArr.data(), 32);
        } catch (const std::exception& e) {
            stale.push_back({key, nd.blockHeight,
                strprintf("witness_deserialize/root threw: %s", e.what())});
            continue;
        }

        if (!expectedTipRoot) continue;  // no reference to compare against

        if (witnessRoot != *expectedTipRoot) {
            stale.push_back({key, nd.blockHeight,
                strprintf("root mismatch at tip %d: witness=%s db=%s",
                          walletTipHeight,
                          witnessRoot.GetHex().substr(0, 16),
                          expectedTipRoot->GetHex().substr(0, 16))});
        }
    }

    return stale;
}

void SaplingKeyManager::RewindBlock(int height, const CBlock& block, WalletBatch* batch)
{
    LOCK(cs);
    if (mapSaplingNotes.empty()) return;

    // Collect all nullifiers revealed by spends in this block.
    std::set<uint256> blockNullifiers;
    std::set<uint256> blockTxids;
    for (const auto& ptx : block.vtx) {
        if (ptx->nType != TRANSACTION_SAPLING) continue;
        auto payload = GetTxPayload<SaplingTxPayload>(*ptx, /*assert_type=*/false);
        if (!payload) continue;
        blockTxids.insert(ptx->GetHash());
        for (const auto& spend : payload->vSpendDescriptions) {
            uint256 nf;
            std::copy(spend.nullifier.begin(), spend.nullifier.end(), nf.begin());
            blockNullifiers.insert(nf);
        }
    }

    // Undo spends: notes whose spendingTxid is in this block.
    for (auto& [key, nd] : mapSaplingNotes) {
        if (nd.isSpent && blockTxids.count(nd.spendingTxid)) {
            nd.isSpent = false;
            nd.spendingTxid.SetNull();
            if (batch) batch->WriteSaplingNote(key, nd);
            LogPrint(BCLog::SAPLING, "SaplingKeyManager::RewindBlock: unspent note %s (height %d)\n",
                      key.ToString(), height);
        }
    }

    // Revert outputs confirmed at this height.
    for (auto& [key, nd] : mapSaplingNotes) {
        if (nd.blockHeight == height) {
            nd.blockHeight = -1;
            nd.treePosition = -1;
            nd.nullifier.SetNull();
            nd.witnessData.clear();
            if (batch) batch->WriteSaplingNote(key, nd);
            LogPrint(BCLog::SAPLING, "SaplingKeyManager::RewindBlock: reverted note %s from height %d\n",
                      key.ToString(), height);
        }
    }

    // Clear witness data for notes at or above the disconnected height.
    // Witnesses reference tree state that is now stale.
    // Notes confirmed below this height retain valid witnesses.
    // NOTE: do NOT clear the nullifier for pre-existing notes; they may still be
    // spent in a future block after the reorg and ScanSaplingSpends() relies on
    // nd.nullifier being non-null to match spend descriptions.
    for (auto& [key, nd] : mapSaplingNotes) {
        if (nd.blockHeight >= height && !nd.witnessData.empty()) {
            nd.witnessData.clear();
            nd.treePosition = -1;
            if (batch) batch->WriteSaplingNote(key, nd);
            LogPrint(BCLog::SAPLING, "SaplingKeyManager::RewindBlock: cleared witness for note %s (height %d)\n",
                      key.ToString(), nd.blockHeight);
        }
    }
}

} // namespace wallet
