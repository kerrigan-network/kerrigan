// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Copyright (c) 2014-2025 The DigiByte Core developers (multi-algo)
// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KERRIGAN_PRIMITIVES_BLOCK_H
#define KERRIGAN_PRIMITIVES_BLOCK_H

#include <list>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>
#include <cstddef>
#include <cassert>
#include <stdexcept>
#include <string>
#include <type_traits>

namespace Consensus { struct Params; }

// Mining algorithm identifiers
enum {
    ALGO_INVALID      = -1,
    ALGO_X11          = 0,
    ALGO_KAWPOW       = 1,
    ALGO_EQUIHASH_200 = 2,  // Equihash<200,9>
    ALGO_EQUIHASH_192 = 3,  // Equihash<192,7>
    NUM_ALGOS         = 4,
};

// Algorithm encoding in block version (bits 8-11, DigiByte pattern)
enum {
    BLOCK_VERSION_DEFAULT        = 2,
    BLOCK_VERSION_ALGO           = (15 << 8),       // mask: 0x0F00
    BLOCK_VERSION_X11            = (0 << 8),
    BLOCK_VERSION_KAWPOW         = (2 << 8),
    BLOCK_VERSION_EQUIHASH_200   = (4 << 8),
    BLOCK_VERSION_EQUIHASH_192   = (6 << 8),
};

std::string GetAlgoName(int algo);
int GetAlgoByName(const std::string& strAlgo, int fallback);

inline int GetVersionForAlgo(int algo)
{
    switch (algo) {
        case ALGO_X11:          return BLOCK_VERSION_X11;
        case ALGO_KAWPOW:       return BLOCK_VERSION_KAWPOW;
        case ALGO_EQUIHASH_200: return BLOCK_VERSION_EQUIHASH_200;
        case ALGO_EQUIHASH_192: return BLOCK_VERSION_EQUIHASH_192;
        default: throw std::invalid_argument("GetVersionForAlgo: unknown algo");
    }
}

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // Common header fields (all algos)
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    // Equihash-specific fields (ALGO_EQUIHASH_200, ALGO_EQUIHASH_192)
    uint256 hashReserved;                     // 32 zero bytes (Zcash compat: Sapling root position)
    uint256 nNonce256;                        // 32-byte Equihash mining nonce
    std::vector<unsigned char> nSolution;

    // KawPoW-specific fields (ALGO_KAWPOW)
    uint32_t nHeight{0};
    uint64_t nNonce64{0};
    uint256 mix_hash;

    CBlockHeader()
    {
        SetNull();
    }

    SERIALIZE_METHODS(CBlockHeader, obj)
    {
        READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot);
        int algo = obj.GetAlgo();
        if (algo == ALGO_EQUIHASH_200 || algo == ALGO_EQUIHASH_192) {
            READWRITE(obj.hashReserved, obj.nTime, obj.nBits, obj.nNonce256);
            READWRITE(LIMITED_VECTOR(obj.nSolution, 1400));
        } else {
            READWRITE(obj.nTime, obj.nBits, obj.nNonce);
            if (algo == ALGO_KAWPOW) {
                READWRITE(obj.nHeight, obj.nNonce64, obj.mix_hash);
            }
        }
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        hashReserved.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        nNonce256.SetNull();
        nSolution.clear();
        nHeight = 0;
        nNonce64 = 0;
        mix_hash.SetNull();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    // Multi-algo support (DigiByte pattern)
    inline void SetAlgo(int algo)
    {
        nVersion = (nVersion & ~BLOCK_VERSION_ALGO) | GetVersionForAlgo(algo);
    }

    int GetAlgo() const;

    uint256 GetHash() const;

    uint256 GetPoWAlgoHash(const Consensus::Params& params) const;

    /** Check whether the Equihash solution in this block is valid */
    bool CheckEquihashSolution() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};

class CompressedHeaderBitField
{
    std::byte bit_field{0};

public:
    enum class Flag : std::underlying_type_t<std::byte> {
        VERSION_BIT_0 = (1 << 0),
        VERSION_BIT_1 = (1 << 1),
        VERSION_BIT_2 = (1 << 2),
        PREV_BLOCK_HASH = (1 << 3),
        TIMESTAMP = (1 << 4),
        NBITS = (1 << 5),
        HAS_EQUIHASH_FIELDS = (1 << 6),  // nSolution follows in stream
        HAS_KAWPOW_FIELDS = (1 << 7),    // nHeight, nNonce64, mix_hash follow
    };

    inline bool IsCompressed(Flag flag) const
    {
        return (bit_field & to_byte(flag)) == to_byte(0);
    }

    inline void MarkAsUncompressed(Flag flag)
    {
        bit_field |= to_byte(flag);
    }

    inline void MarkAsCompressed(Flag flag)
    {
        bit_field &= ~to_byte(flag);
    }

    inline bool IsVersionCompressed() const
    {
        return GetVersionOffset() != 0;
    }

    inline void SetVersionOffset(uint8_t version)
    {
        bit_field &= ~VERSION_BIT_MASK;
        bit_field |= to_byte(version) & VERSION_BIT_MASK;
    }

    inline uint8_t GetVersionOffset() const
    {
        return to_uint8(bit_field & VERSION_BIT_MASK);
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, to_uint8(bit_field));
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint8_t new_bit_field_value;
        ::Unserialize(s, new_bit_field_value);
        bit_field = to_byte(new_bit_field_value);
    }

private:
    static constexpr uint8_t to_uint8(const std::byte value)
    {
        return std::to_integer<uint8_t>(value);
    }

    static constexpr std::byte to_byte(const uint8_t value)
    {
        return std::byte{value};
    }

    static constexpr std::byte to_byte(const Flag flag)
    {
        return static_cast<std::byte>(flag);
    }

    static constexpr std::byte VERSION_BIT_MASK = static_cast<std::byte>(Flag::VERSION_BIT_0) | static_cast<std::byte>(Flag::VERSION_BIT_1) | static_cast<std::byte>(Flag::VERSION_BIT_2);
};

struct CompressibleBlockHeader : CBlockHeader {
    CompressedHeaderBitField bit_field;
    int16_t time_offset{0};

    CompressibleBlockHeader() = default;

    explicit CompressibleBlockHeader(CBlockHeader&& block_header)
    {
        *static_cast<CBlockHeader*>(this) = std::move(block_header);

        // When we create this from a block header, mark everything as uncompressed
        bit_field.SetVersionOffset(0);
        bit_field.MarkAsUncompressed(CompressedHeaderBitField::Flag::PREV_BLOCK_HASH);
        bit_field.MarkAsUncompressed(CompressedHeaderBitField::Flag::TIMESTAMP);
        bit_field.MarkAsUncompressed(CompressedHeaderBitField::Flag::NBITS);

        // Set algo-specific field flags so the serializer includes extended
        // fields (Equihash solution, KawPoW nonce/mix_hash) even when
        // Compress() is not called (e.g. the first header in a GETHEADERS2
        // response).  Without these flags the receiver sees zero-initialized
        // KawPoW/Equihash data and rejects the header as invalid.
        int algo = GetAlgo();
        if (algo == ALGO_EQUIHASH_200 || algo == ALGO_EQUIHASH_192) {
            bit_field.MarkAsUncompressed(CompressedHeaderBitField::Flag::HAS_EQUIHASH_FIELDS);
        } else if (algo == ALGO_KAWPOW) {
            bit_field.MarkAsUncompressed(CompressedHeaderBitField::Flag::HAS_KAWPOW_FIELDS);
        }
    }

    SERIALIZE_METHODS(CompressibleBlockHeader, obj)
    {
        READWRITE(obj.bit_field);
        if (!obj.bit_field.IsVersionCompressed()) {
            READWRITE(obj.nVersion);
        }
        if (!obj.bit_field.IsCompressed(CompressedHeaderBitField::Flag::PREV_BLOCK_HASH)) {
            READWRITE(obj.hashPrevBlock);
        }
        READWRITE(obj.hashMerkleRoot);
        // Algo-specific extended fields use explicit bit_field flags so
        // deserialization works even when nVersion is compressed (GetAlgo()
        // would return X11 default, skipping these fields and corrupting
        // the stream for all subsequent headers).
        bool has_equihash = !obj.bit_field.IsCompressed(CompressedHeaderBitField::Flag::HAS_EQUIHASH_FIELDS);
        bool has_kawpow = !obj.bit_field.IsCompressed(CompressedHeaderBitField::Flag::HAS_KAWPOW_FIELDS);
        if (has_equihash && has_kawpow) {
            throw std::ios_base::failure("contradictory algo flags in CompressibleBlockHeader");
        }
        if (!obj.bit_field.IsVersionCompressed()) {
            int algo = obj.GetAlgo();
            bool expect_equihash = (algo == ALGO_EQUIHASH_200 || algo == ALGO_EQUIHASH_192);
            bool expect_kawpow = (algo == ALGO_KAWPOW);
            if (has_equihash != expect_equihash || has_kawpow != expect_kawpow) {
                throw std::ios_base::failure("algo flags inconsistent with nVersion");
            }
        }
        if (has_equihash) {
            // Equihash: hashReserved before nTime (Zcash 140-byte compat)
            READWRITE(obj.hashReserved);
        }
        if (!obj.bit_field.IsCompressed(CompressedHeaderBitField::Flag::TIMESTAMP)) {
            READWRITE(obj.nTime);
        } else {
            READWRITE(obj.time_offset);
        }
        if (!obj.bit_field.IsCompressed(CompressedHeaderBitField::Flag::NBITS)) {
            READWRITE(obj.nBits);
        }
        if (has_equihash) {
            // Equihash: 32-byte nonce instead of 4-byte
            READWRITE(obj.nNonce256);
            READWRITE(LIMITED_VECTOR(obj.nSolution, 1400));
        } else {
            READWRITE(obj.nNonce);
            if (has_kawpow) {
                READWRITE(obj.nHeight, obj.nNonce64, obj.mix_hash);
            }
        }
    }

    void Compress(const std::vector<CompressibleBlockHeader>& previous_blocks, std::list<int32_t>& last_unique_versions);

    // Returns false if version_offset in the compressed header is out of range.
    // Callers must reject the message and misbehave-score the peer on false.
    [[nodiscard]] bool Uncompress(const std::vector<CBlockHeader>& previous_blocks, std::list<int32_t>& last_unique_versions);
};

class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    SERIALIZE_METHODS(CBlock, obj)
    {
        READWRITEAS(CBlockHeader, obj);
        READWRITE(obj.vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.hashReserved   = hashReserved;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.nNonce256      = nNonce256;
        block.nSolution      = nSolution;
        block.nHeight        = nHeight;
        block.nNonce64       = nNonce64;
        block.mix_hash       = mix_hash;
        return block;
    }

    std::string ToString() const;
};


/**
 * Custom serializer for CBlockHeader that omits the nonce and solution, for use
 * as input to Equihash. The Equihash solver/verifier hashes the header without
 * the nonce and solution, then uses that hash state to generate/verify the solution.
 */
class CEquihashInput : private CBlockHeader
{
public:
    CEquihashInput(const CBlockHeader &header)
    {
        CBlockHeader::SetNull();
        *static_cast<CBlockHeader*>(this) = header;
    }

    SERIALIZE_METHODS(CEquihashInput, obj)
    {
        // 108 bytes: version(4) + prevhash(32) + merkleroot(32) + reserved(32) + time(4) + bits(4)
        // Combined with the 32-byte nNonce256 appended by the caller, this produces
        // the 140-byte Equihash input expected by standard Zcash miners and pools.
        READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.hashReserved, obj.nTime, obj.nBits);
    }
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    explicit CBlockLocator(const std::vector<uint256>& vHaveIn) : vHave(vHaveIn) {}

    SERIALIZE_METHODS(CBlockLocator, obj)
    {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(obj.vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // KERRIGAN_PRIMITIVES_BLOCK_H
