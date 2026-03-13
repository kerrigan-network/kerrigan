// Copyright (c) 2014-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key_io.h>

#include <base58.h>
#include <bech32.h>
#include <chainparams.h>
#include <sapling/sapling_address.h>

#include <algorithm>
#include <assert.h>
#include <string.h>

namespace {
class DestinationEncoder
{
private:
    const CChainParams& m_params;

public:
    explicit DestinationEncoder(const CChainParams& params) : m_params(params) {}

    std::string operator()(const PKHash& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const ScriptHash& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const CNoDestination& no) const { return {}; }
};

CTxDestination DecodeDestination(const std::string& str, const CChainParams& params, std::string& error_str)
{
    std::vector<unsigned char> data;
    uint160 hash;
    error_str = "";
    if (DecodeBase58Check(str, data, 21)) {
        // base58-encoded Kerrigan addresses.
        // Public-key-hash-addresses have version 76 (or 140 testnet).
        // The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
        const std::vector<unsigned char>& pubkey_prefix = params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        if (data.size() == hash.size() + pubkey_prefix.size() && std::equal(pubkey_prefix.begin(), pubkey_prefix.end(), data.begin())) {
            std::copy(data.begin() + pubkey_prefix.size(), data.end(), hash.begin());
            return PKHash(hash);
        }
        // Script-hash-addresses have version 16 (or 19 testnet).
        // The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
        const std::vector<unsigned char>& script_prefix = params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        if (data.size() == hash.size() + script_prefix.size() && std::equal(script_prefix.begin(), script_prefix.end(), data.begin())) {
            std::copy(data.begin() + script_prefix.size(), data.end(), hash.begin());
            return ScriptHash(hash);
        }

        // Set potential error message.
        error_str = "Invalid prefix for Base58-encoded address";
    }
    // Set error message if address can't be interpreted as Base58.
    if (error_str.empty()) error_str = "Invalid address format";

    return CNoDestination();
}
} // namespace

CKey DecodeSecret(const std::string& str)
{
    CKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data, 34)) {
        const std::vector<unsigned char>& privkey_prefix = Params().Base58Prefix(CChainParams::SECRET_KEY);
        if ((data.size() == 32 + privkey_prefix.size() || (data.size() == 33 + privkey_prefix.size() && data.back() == 1)) &&
            std::equal(privkey_prefix.begin(), privkey_prefix.end(), data.begin())) {
            bool compressed = data.size() == 33 + privkey_prefix.size();
            key.Set(data.begin() + privkey_prefix.size(), data.begin() + privkey_prefix.size() + 32, compressed);
        }
    }
    if (!data.empty()) {
        memory_cleanse(data.data(), data.size());
    }
    return key;
}

std::string EncodeSecret(const CKey& key)
{
    assert(key.IsValid());
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::SECRET_KEY);
    data.insert(data.end(), key.begin(), key.end());
    if (key.IsCompressed()) {
        data.push_back(1);
    }
    std::string ret = EncodeBase58Check(data);
    memory_cleanse(data.data(), data.size());
    return ret;
}

CExtPubKey DecodeExtPubKey(const std::string& str)
{
    CExtPubKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data, 78)) {
        const std::vector<unsigned char>& prefix = Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY);
        if (data.size() == BIP32_EXTKEY_SIZE + prefix.size() && std::equal(prefix.begin(), prefix.end(), data.begin())) {
            key.Decode(data.data() + prefix.size());
        }
    }
    return key;
}

std::string EncodeExtPubKey(const CExtPubKey& key)
{
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY);
    size_t size = data.size();
    data.resize(size + BIP32_EXTKEY_SIZE);
    key.Encode(data.data() + size);
    std::string ret = EncodeBase58Check(data);
    return ret;
}

CExtKey DecodeExtKey(const std::string& str)
{
    CExtKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data, 78)) {
        const std::vector<unsigned char>& prefix = Params().Base58Prefix(CChainParams::EXT_SECRET_KEY);
        if (data.size() == BIP32_EXTKEY_SIZE + prefix.size() && std::equal(prefix.begin(), prefix.end(), data.begin())) {
            key.Decode(data.data() + prefix.size());
        }
    }
    return key;
}

std::string EncodeExtKey(const CExtKey& key)
{
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::EXT_SECRET_KEY);
    size_t size = data.size();
    data.resize(size + BIP32_EXTKEY_SIZE);
    key.Encode(data.data() + size);
    std::string ret = EncodeBase58Check(data);
    if (!data.empty()) {
        memory_cleanse(data.data(), data.size());
    }
    return ret;
}

std::string EncodeDestination(const CTxDestination& dest)
{
    return std::visit(DestinationEncoder(Params()), dest);
}

CTxDestination DecodeDestination(const std::string& str, std::string& error_msg)
{
    return DecodeDestination(str, Params(), error_msg);
}

CTxDestination DecodeDestination(const std::string& str)
{
    std::string error_msg;
    return DecodeDestination(str, error_msg);
}

bool IsValidDestinationString(const std::string& str, const CChainParams& params)
{
    std::string error_msg;
    return IsValidDestination(DecodeDestination(str, params, error_msg));
}

bool IsValidDestinationString(const std::string& str)
{
    return IsValidDestinationString(str, Params());
}

// Sapling address encoding/decoding

/** Sapling payment address: 11 bytes diversifier + 32 bytes pk_d = 43 bytes raw. */
static constexpr size_t SAPLING_ADDR_RAW_SIZE = 11 + 32;

/** Expected 5-bit group count for 43 raw bytes: ceil(43*8/5) = 69 */
static constexpr size_t SAPLING_ADDR_5BIT_SIZE = 69;

std::string EncodeSaplingAddress(const sapling::SaplingPaymentAddress& addr)
{
    const std::string& hrp = Params().SaplingHRP();

    // Concatenate diversifier (11) + pk_d (32) = 43 bytes
    std::vector<uint8_t> raw(SAPLING_ADDR_RAW_SIZE);
    std::copy(addr.d.begin(), addr.d.end(), raw.begin());
    std::copy(addr.pk_d.begin(), addr.pk_d.end(), raw.begin() + 11);

    // Convert 8-bit data to 5-bit groups for Bech32m (unsigned accumulator to avoid UB)
    std::vector<uint8_t> data;
    data.reserve(SAPLING_ADDR_5BIT_SIZE);
    uint32_t acc = 0;
    int bits = 0;
    for (uint8_t byte : raw) {
        acc = (acc << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            data.push_back((acc >> bits) & 0x1f);
        }
    }
    if (bits > 0) {
        data.push_back((acc << (5 - bits)) & 0x1f);
    }

    return bech32::Encode(bech32::Encoding::BECH32M, hrp, data);
}

bool DecodeSaplingAddress(const std::string& str, sapling::SaplingPaymentAddress& addr)
{
    const auto dec = bech32::Decode(str);
    if (dec.encoding != bech32::Encoding::BECH32M) return false;

    // Check HRP matches current network
    const std::string& hrp = Params().SaplingHRP();
    if (dec.hrp != hrp) return false;

    // Early reject: unexpected 5-bit data length (should be exactly 69 for 43 raw bytes)
    if (dec.data.size() != SAPLING_ADDR_5BIT_SIZE) return false;

    // Convert 5-bit to 8-bit (unsigned accumulator to avoid UB)
    std::vector<uint8_t> raw;
    raw.reserve(SAPLING_ADDR_RAW_SIZE);
    uint32_t acc = 0;
    int bits = 0;
    for (uint8_t val : dec.data) {
        if (val >= 32) return false; // invalid 5-bit value
        acc = (acc << 5) | val;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            raw.push_back((acc >> bits) & 0xff);
        }
    }
    // Check padding bits are zero
    if (bits > 4) return false;
    if (bits > 0 && ((acc << (8 - bits)) & 0xff) != 0) return false;

    if (raw.size() != SAPLING_ADDR_RAW_SIZE) return false;

    std::copy(raw.begin(), raw.begin() + 11, addr.d.begin());
    std::copy(raw.begin() + 11, raw.begin() + 43, addr.pk_d.begin());
    return true;
}

bool IsValidSaplingAddress(const std::string& str)
{
    sapling::SaplingPaymentAddress addr;
    return DecodeSaplingAddress(str, addr);
}
