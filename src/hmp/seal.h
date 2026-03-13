// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KERRIGAN_HMP_SEAL_H
#define KERRIGAN_HMP_SEAL_H

#include <bls/bls.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <string_view>
#include <vector>

/** Domain separation tag for HMP seal BLS signatures. */
inline constexpr std::string_view HMP_SEAL_DOMAIN_TAG{"KRGN-HMP-SEAL-V1"};

/** Maximum signers per assembled seal (DoS protection). */
inline constexpr size_t MAX_SEAL_SIGNERS{200};

/**
 * CSealShare -- individual signature share from one daemon for Hivemind sealing.
 *
 * When a new block is found, eligible daemons sign H(domain || blockHash || signerPubKey || algoId)
 * and broadcast their share. The domain tag "KRGN-HMP-SEAL-V1" prevents cross-context
 * BLS signature replay. Per-signer message binding prevents rogue key attacks
 * on BLS aggregate signatures, and including algoId binds the signerAlgos vector
 * to the BLS aggregate. The next block's miner collects shares and assembles
 * them into a seal.
 */
class CSealShare
{
public:
    uint256 blockHash;              // block being sealed
    CBLSPublicKey signerPubKey;     // who signed
    CBLSSignature signature;        // BLS sig over H(blockHash || signerPubKey || algoId)
    uint8_t algoId{0};              // signer's algo privilege domain
    int64_t nTimestamp{0};          // when signed

    // VRF + zk proof fields
    CBLSSignature vrfProof;         // VRF proof for committee selection
    std::vector<uint8_t> zkProof;   // Groth16 participation proof (192 bytes)
    uint256 commitment;             // public input to zk circuit

    SERIALIZE_METHODS(CSealShare, obj)
    {
        READWRITE(obj.blockHash, obj.signerPubKey, obj.signature, obj.algoId, obj.nTimestamp,
                  obj.vrfProof, LIMITED_VECTOR(obj.zkProof, 256), obj.commitment);
    }

    uint256 GetHash() const;

    bool operator==(const CSealShare& other) const
    {
        return blockHash == other.blockHash && signerPubKey == other.signerPubKey;
    }
};

/**
 * CAssembledSeal -- aggregated threshold signature from multiple daemons.
 *
 * The assembling miner collects enough shares, aggregates them using
 * BLS aggregate, and embeds the result in CCbTx v4.
 */
class CAssembledSeal
{
public:
    uint256 blockHash;                          // block that was sealed
    CBLSSignature aggregatedSig;                // BLS aggregate of all shares
    std::vector<CBLSPublicKey> signers;          // who contributed
    std::vector<uint8_t> signerAlgos;            // per-signer algo domain

    SERIALIZE_METHODS(CAssembledSeal, obj)
    {
        READWRITE(obj.blockHash, obj.aggregatedSig, LIMITED_VECTOR(obj.signers, MAX_SEAL_SIGNERS), LIMITED_VECTOR(obj.signerAlgos, MAX_SEAL_SIGNERS));
    }

    bool IsNull() const { return blockHash.IsNull(); }

    /** Verify the assembled seal using VerifyInsecureAggregated with per-signer messages. */
    bool Verify() const;
};

#endif // KERRIGAN_HMP_SEAL_H
