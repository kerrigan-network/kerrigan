// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hmp/seal.h>

#include <hash.h>
#include <logging.h>

#include <set>

uint256 CSealShare::GetHash() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << HMP_SEAL_DOMAIN_TAG << blockHash << signerPubKey << algoId;
    return ss.GetHash();
}

bool CAssembledSeal::Verify() const
{
    if (blockHash.IsNull() || signers.empty() || !aggregatedSig.IsValid()) {
        return false;
    }

    if (signers.size() != signerAlgos.size()) {
        return false;
    }

    // Reject duplicate signers; each pubkey must be unique
    std::set<CBLSPublicKey> seen;
    for (const auto& pk : signers) {
        if (!seen.insert(pk).second) return false;
    }

    // DoS protection: cap signer count
    if (signers.size() > MAX_SEAL_SIGNERS) {
        LogPrintf("HMP: seal verify rejected -- too many signers (%zu)\n", signers.size());
        return false;
    }

    // Each signer signs H(blockHash || signerPubKey || algoId) to prevent rogue key
    // attacks and bind signerAlgos to the BLS signature.
    std::vector<CBLSPublicKey> pks(signers.begin(), signers.end());
    std::vector<uint256> msgHashes;
    msgHashes.reserve(signers.size());
    for (size_t i = 0; i < signers.size(); i++) {
        CHashWriter hw(SER_GETHASH, 0);
        hw << HMP_SEAL_DOMAIN_TAG << blockHash << signers[i] << signerAlgos[i];
        msgHashes.push_back(hw.GetHash());
    }

    return aggregatedSig.VerifyInsecureAggregated(Span<CBLSPublicKey>(pks), Span<uint256>(msgHashes), false /* basic scheme */);
}
