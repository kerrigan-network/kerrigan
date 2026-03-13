// Copyright (c) 2018-2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bls/bls_ies.h>

#include <hash.h>
#include <random.h>

#include <crypto/aes.h>
#include <crypto/hmac_sha256.h>
#include <support/cleanse.h>

#include <cstring>

/** Size of the HMAC-SHA256 authentication tag appended to ciphertext. */
static constexpr size_t BLS_IES_MAC_SIZE = 32;

static bool EncryptBlob(const void* in, size_t inSize, std::vector<unsigned char>& out, const void* symKey, const void* iv)
{
    // Encrypt: AES-256-CBC
    std::vector<unsigned char> ciphertext(inSize);
    AES256CBCEncrypt enc(reinterpret_cast<const unsigned char*>(symKey), reinterpret_cast<const unsigned char*>(iv), false);
    int w = enc.Encrypt(reinterpret_cast<const unsigned char*>(in), int(inSize), ciphertext.data());
    if (w != int(inSize)) {
        return false;
    }

    // Authenticate: HMAC-SHA256 over ciphertext using symKey
    unsigned char mac[BLS_IES_MAC_SIZE];
    CHMAC_SHA256(reinterpret_cast<const unsigned char*>(symKey), 32)
        .Write(ciphertext.data(), ciphertext.size())
        .Finalize(mac);

    // Output = ciphertext || MAC
    out.resize(inSize + BLS_IES_MAC_SIZE);
    std::memcpy(out.data(), ciphertext.data(), inSize);
    std::memcpy(out.data() + inSize, mac, BLS_IES_MAC_SIZE);

    memory_cleanse(mac, BLS_IES_MAC_SIZE);
    return true;
}

template <typename Out>
static bool DecryptBlob(const void* in, size_t inSize, Out& out, const void* symKey, const void* iv)
{
    // inSize includes the trailing MAC
    if (inSize < BLS_IES_MAC_SIZE) {
        return false;
    }
    const size_t ciphertextSize = inSize - BLS_IES_MAC_SIZE;
    const auto* inBytes = reinterpret_cast<const unsigned char*>(in);

    // Verify HMAC-SHA256 before decrypting (authenticate-then-decrypt)
    unsigned char expectedMac[BLS_IES_MAC_SIZE];
    CHMAC_SHA256(reinterpret_cast<const unsigned char*>(symKey), 32)
        .Write(inBytes, ciphertextSize)
        .Finalize(expectedMac);

    // Constant-time comparison to prevent timing side-channels
    const unsigned char* receivedMac = inBytes + ciphertextSize;
    unsigned int diff = 0;
    for (size_t i = 0; i < BLS_IES_MAC_SIZE; i++) {
        diff |= expectedMac[i] ^ receivedMac[i];
    }
    memory_cleanse(expectedMac, BLS_IES_MAC_SIZE);
    if (diff != 0) {
        return false;
    }

    // Decrypt the ciphertext (MAC verified)
    out.resize(ciphertextSize);
    AES256CBCDecrypt dec(reinterpret_cast<const unsigned char*>(symKey), reinterpret_cast<const unsigned char*>(iv), false);
    int w = dec.Decrypt(inBytes, int(ciphertextSize), reinterpret_cast<unsigned char*>(out.data()));
    return w == (int)ciphertextSize;
}

uint256 CBLSIESEncryptedBlob::GetIV(size_t idx) const
{
    uint256 iv = ivSeed;
    for (size_t i = 0; i < idx; i++) {
        iv = ::SerializeHash(iv);
    }
    return iv;
}

bool CBLSIESEncryptedBlob::Decrypt(size_t idx, const CBLSSecretKey& secretKey, CDataStream& decryptedDataRet) const
{
    CBLSPublicKey pk;
    if (!pk.DHKeyExchange(secretKey, ephemeralPubKey)) {
        return false;
    }

    std::vector<unsigned char> symKey = pk.ToByteVector(false);
    symKey.resize(32);

    uint256 iv = GetIV(idx);
    bool ret = DecryptBlob(data.data(), data.size(), decryptedDataRet, symKey.data(), iv.begin());
    memory_cleanse(symKey.data(), symKey.size());
    return ret;
}

bool CBLSIESEncryptedBlob::IsValid() const
{
    return ephemeralPubKey.IsValid() && !data.empty() && !ivSeed.IsNull();
}

void CBLSIESMultiRecipientBlobs::InitEncrypt(size_t count)
{
    ephemeralSecretKey.MakeNewKey();
    ephemeralPubKey = ephemeralSecretKey.GetPublicKey();
    GetStrongRandBytes({ivSeed.begin(), ivSeed.size()});

    uint256 iv = ivSeed;
    ivVector.resize(count);
    blobs.resize(count);
    for (size_t i = 0; i < count; i++) {
        ivVector[i] = iv;
        iv = ::SerializeHash(iv);
    }
}

bool CBLSIESMultiRecipientBlobs::Encrypt(size_t idx, const CBLSPublicKey& recipient, const Blob& blob)
{
    assert(idx < blobs.size());

    CBLSPublicKey pk;
    if (!pk.DHKeyExchange(ephemeralSecretKey, recipient)) {
        return false;
    }

    std::vector<uint8_t> symKey = pk.ToByteVector(false);
    symKey.resize(32);

    bool ret = EncryptBlob(blob.data(), blob.size(), blobs[idx], symKey.data(), ivVector[idx].begin());
    memory_cleanse(symKey.data(), symKey.size());
    return ret;
}

bool CBLSIESMultiRecipientBlobs::Decrypt(size_t idx, const CBLSSecretKey& sk, Blob& blobRet) const
{
    if (idx >= blobs.size()) {
        return false;
    }

    CBLSPublicKey pk;
    if (!pk.DHKeyExchange(sk, ephemeralPubKey)) {
        return false;
    }

    std::vector<uint8_t> symKey = pk.ToByteVector(false);
    symKey.resize(32);

    uint256 iv = ivSeed;
    for (size_t i = 0; i < idx; i++) {
        iv = ::SerializeHash(iv);
    }

    bool ret = DecryptBlob(blobs[idx].data(), blobs[idx].size(), blobRet, symKey.data(), iv.begin());
    memory_cleanse(symKey.data(), symKey.size());
    return ret;
}
