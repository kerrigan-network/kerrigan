// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2014-2025 The DigiByte Core developers (multi-algo)
// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <crypto/equihash.h>
#include <crypto/ethash/include/ethash/progpow.hpp>
#include <hash.h>
#include <hash_x11.h>
#include <streams.h>
#include <logging.h>
#include <tinyformat.h>

int CBlockHeader::GetAlgo() const
{
    switch (nVersion & BLOCK_VERSION_ALGO) {
        case BLOCK_VERSION_X11:          return ALGO_X11;
        case BLOCK_VERSION_KAWPOW:       return ALGO_KAWPOW;
        case BLOCK_VERSION_EQUIHASH_200: return ALGO_EQUIHASH_200;
        case BLOCK_VERSION_EQUIHASH_192: return ALGO_EQUIHASH_192;
    }
    LogPrintf("WARNING: CBlockHeader::GetAlgo(): unmapped algo bits 0x%03x in nVersion=0x%08x\n",
              nVersion & BLOCK_VERSION_ALGO, nVersion);
    return ALGO_INVALID;
}

std::string GetAlgoName(int algo)
{
    switch (algo) {
        case ALGO_X11:          return "x11";
        case ALGO_KAWPOW:       return "kawpow";
        case ALGO_EQUIHASH_200: return "equihash200";
        case ALGO_EQUIHASH_192: return "equihash192";
        default:                return "unknown";
    }
}

int GetAlgoByName(const std::string& strAlgo, int fallback)
{
    if (strAlgo == "x11")          return ALGO_X11;
    if (strAlgo == "kawpow")       return ALGO_KAWPOW;
    if (strAlgo == "equihash200")  return ALGO_EQUIHASH_200;
    if (strAlgo == "equihash192")  return ALGO_EQUIHASH_192;
    return fallback;
}

uint256 CBlockHeader::GetHash() const
{
    // Block identity hash (X11). Extended fields (nSolution, KawPoW mix_hash)
    // are NOT included.
    CDataStream ss(SER_GETHASH, PROTOCOL_VERSION);
    int algo = GetAlgo();
    if (algo == ALGO_EQUIHASH_200 || algo == ALGO_EQUIHASH_192) {
        // Equihash: 140-byte header (Zcash-compatible)
        // version(4) + prevhash(32) + merkleroot(32) + reserved(32) + time(4) + bits(4) + nonce256(32)
        ss << nVersion << hashPrevBlock << hashMerkleRoot << hashReserved << nTime << nBits << nNonce256;
    } else {
        // X11/KawPoW: standard 80-byte header
        ss << nVersion << hashPrevBlock << hashMerkleRoot << nTime << nBits << nNonce;
    }
    return HashX11((const char *)ss.data(), (const char *)ss.data() + ss.size());
}

bool CBlockHeader::CheckEquihashSolution() const
{
    int algo = GetAlgo();
    unsigned int n, k;
    if (algo == ALGO_EQUIHASH_200) {
        n = 200; k = 9;
    } else if (algo == ALGO_EQUIHASH_192) {
        n = 192; k = 7;
    } else {
        return false; // not an Equihash block
    }

    // Initialize Equihash hash state
    eh_HashState state;
    EhInitialiseState(n, k, state);

    // Serialize header without nonce and solution (CEquihashInput = 108 bytes)
    // then append 32-byte nonce for 140 bytes total (Zcash-compatible)
    CEquihashInput I{*this};
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;
    ss << nNonce256;

    // Feed serialized header into BLAKE2b state
    crypto_generichash_blake2b_update(&state, reinterpret_cast<const unsigned char*>(ss.data()), ss.size());

    // Validate the solution
    bool isValid;
    EhIsValidSolution(n, k, state, nSolution, isValid);
    return isValid;
}

uint256 CBlockHeader::GetPoWAlgoHash(const Consensus::Params& params) const
{
    switch (GetAlgo()) {
        case ALGO_X11:
            return GetHash(); // X11 is the default
        case ALGO_KAWPOW:
        {
            // KawPoW PoW hash: cheap Keccak-only final hash from (height, header_hash, mix_hash, nonce64).
            // No epoch context needed; hash_no_verify just recomputes the final Keccak.
            //
            // Byte order: ethash::hash256 is big-endian (bytes[0]=MSB), uint256 is little-endian
            // (begin()=LSB). We must reverse bytes at every conversion boundary.
            // ProgPoW seed hash: sha256d of the 80-byte header (RVN standard).
            // GetHash() returns X11 which no KawPoW miner uses. (#804, #801)
            ethash::hash256 header_h;
            static_assert(sizeof(header_h.bytes) == sizeof(uint256));
            CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
            hw << nVersion << hashPrevBlock << hashMerkleRoot << nTime << nBits << nNonce;
            uint256 hdrHash = hw.GetHash();
            for (int i = 0; i < 32; ++i)
                header_h.bytes[i] = *(hdrHash.begin() + 31 - i);

            ethash::hash256 mix_h;
            for (int i = 0; i < 32; ++i)
                mix_h.bytes[i] = *(mix_hash.begin() + 31 - i);

            ethash::hash256 result = progpow::hash_no_verify(
                static_cast<int>(nHeight), header_h, mix_h, nNonce64);

            uint256 ret;
            for (int i = 0; i < 32; ++i)
                *(ret.begin() + i) = result.bytes[31 - i];
            return ret;
        }
        case ALGO_EQUIHASH_200:
        case ALGO_EQUIHASH_192:
        {
            // Equihash PoW hash: SHA256D of the full serialized header
            // including the solution. Using SHA256D for pool software
            // compatibility (miniZ, lolMiner, Miningcore, S-NOMP all use
            // SHA256D for share difficulty validation). The Equihash
            // solution validity is checked separately via CheckEquihashSolution().
            CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
            ss << *this; // base header + nSolution
            return ss.GetHash();
        }
        default:
            return GetHash();
    }
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

static void MarkVersionAsMostRecent(std::list<int32_t>& last_unique_versions, std::list<int32_t>::const_iterator version_it)
{
    if (version_it != last_unique_versions.cbegin()) {
        // Move the found version to the front of the list
        last_unique_versions.splice(last_unique_versions.begin(), last_unique_versions, version_it, std::next(version_it));
    }
}

static void SaveVersionAsMostRecent(std::list<int32_t>& last_unique_versions, const int32_t version)
{
    last_unique_versions.push_front(version);

    // Always keep the last 7 unique versions
    constexpr std::size_t max_backwards_look_ups = 7;
    if (last_unique_versions.size() > max_backwards_look_ups) {
        // Evict the oldest version
        last_unique_versions.pop_back();
    }
}

void CompressibleBlockHeader::Compress(const std::vector<CompressibleBlockHeader>& previous_blocks, std::list<int32_t>& last_unique_versions)
{
    // Set algo-specific field flags before any early return.  The deserializer
    // uses these flags (not GetAlgo()) to decide which extended fields follow,
    // avoiding stream corruption when nVersion is compressed.
    int algo = GetAlgo();
    if (algo == ALGO_EQUIHASH_200 || algo == ALGO_EQUIHASH_192) {
        bit_field.MarkAsUncompressed(CompressedHeaderBitField::Flag::HAS_EQUIHASH_FIELDS);
    } else if (algo == ALGO_KAWPOW) {
        bit_field.MarkAsUncompressed(CompressedHeaderBitField::Flag::HAS_KAWPOW_FIELDS);
    }

    if (previous_blocks.empty()) {
        // Previous block not available, we have to send the block completely uncompressed
        SaveVersionAsMostRecent(last_unique_versions, nVersion);
        return;
    }

    // Try to compress version
    const auto version_it = std::find(last_unique_versions.cbegin(), last_unique_versions.cend(), nVersion);
    if (version_it != last_unique_versions.cend()) {
        // Version is found in the last 7 unique blocks.
        bit_field.SetVersionOffset(static_cast<uint8_t>(std::distance(last_unique_versions.cbegin(), version_it) + 1));

        // Mark the version as the most recent one
        MarkVersionAsMostRecent(last_unique_versions, version_it);
    } else {
        // Save the version as the most recent one
        SaveVersionAsMostRecent(last_unique_versions, nVersion);
    }

    // Previous block is available
    const auto& last_block = previous_blocks.back();
    bit_field.MarkAsCompressed(CompressedHeaderBitField::Flag::PREV_BLOCK_HASH);

    // Compute compressed time diff
    const int64_t time_diff = nTime - last_block.nTime;
    if (time_diff <= std::numeric_limits<int16_t>::max() && time_diff >= std::numeric_limits<int16_t>::min()) {
        time_offset = static_cast<int16_t>(time_diff);
        bit_field.MarkAsCompressed(CompressedHeaderBitField::Flag::TIMESTAMP);
    }

    // If n_bits matches previous block, it can be compressed (not sent at all)
    if (nBits == last_block.nBits) {
        bit_field.MarkAsCompressed(CompressedHeaderBitField::Flag::NBITS);
    }
}

bool CompressibleBlockHeader::Uncompress(const std::vector<CBlockHeader>& previous_blocks, std::list<int32_t>& last_unique_versions)
{
    if (previous_blocks.empty()) {
        // First block in chain is always uncompressed
        SaveVersionAsMostRecent(last_unique_versions, nVersion);
        return true;
    }

    // We have the previous block
    const auto& last_block = previous_blocks.back();

    // Uncompress version
    if (bit_field.IsVersionCompressed()) {
        const auto version_offset = bit_field.GetVersionOffset();
        if (version_offset == 0 || version_offset > last_unique_versions.size()) {
            // Malformed message: version_offset references a slot that doesn't exist.
            // Return false so the caller can misbehave-score / reject the peer.
            return false;
        }
        auto version_it = last_unique_versions.begin();
        std::advance(version_it, version_offset - 1);
        nVersion = *version_it;
        MarkVersionAsMostRecent(last_unique_versions, version_it);
    } else {
        // Save the version as the most recent one
        SaveVersionAsMostRecent(last_unique_versions, nVersion);
    }

    // Uncompress prev block hash
    if (bit_field.IsCompressed(CompressedHeaderBitField::Flag::PREV_BLOCK_HASH)) {
        hashPrevBlock = last_block.GetHash();
    }

    // Uncompress timestamp
    if (bit_field.IsCompressed(CompressedHeaderBitField::Flag::TIMESTAMP)) {
        nTime = last_block.nTime + time_offset;
    }

    // Uncompress n_bits
    if (bit_field.IsCompressed(CompressedHeaderBitField::Flag::NBITS)) {
        nBits = last_block.nBits;
    }

    return true;
}
