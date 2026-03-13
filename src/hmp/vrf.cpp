// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hmp/vrf.h>

#include <hash.h>
#include <hmp/privilege.h>
#include <crypto/common.h>

#include <cstring>

uint256 ComputeVRFInput(const uint256& blockHash, const uint256& prevSealHash)
{
    CHashWriter hasher(SER_GETHASH, 0);
    // Domain separator prevents cross-protocol signature reuse
    const std::string domain = "HMP-VRF";
    hasher.write(MakeByteSpan(domain));
    hasher << blockHash;
    // Mix in previous block's seal hash to prevent nonce grinding.
    // The miner controls blockHash via nonce grinding, but cannot influence
    // the previous block's seal which was assembled by other participants.
    hasher << prevSealHash;
    return hasher.GetHash();
}

CBLSSignature ComputeVRF(const CBLSSecretKey& sk, const uint256& blockHash, const uint256& prevSealHash)
{
    uint256 vrfInput = ComputeVRFInput(blockHash, prevSealHash);
    return sk.Sign(vrfInput, false /* not legacy scheme */);
}

bool VerifyVRF(const CBLSPublicKey& pk, const uint256& blockHash, const uint256& prevSealHash, const CBLSSignature& vrfProof)
{
    if (!pk.IsValid() || !vrfProof.IsValid()) return false;
    uint256 vrfInput = ComputeVRFInput(blockHash, prevSealHash);
    return vrfProof.VerifyInsecure(pk, vrfInput, false /* basic scheme */);
}

uint256 VRFOutputHash(const CBLSSignature& vrfProof)
{
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << vrfProof;
    return hasher.GetHash();
}

bool IsVRFSelected(const uint256& vrfHash, int tierMultiplier, int baseThreshold)
{
    // Use first 8 bytes of VRF hash for selection (64-bit)
    uint64_t val = ReadLE64(vrfHash.begin());

    int effectiveThreshold = baseThreshold * tierMultiplier;
    if (effectiveThreshold > 1000) effectiveThreshold = 1000;

    return (val % 1000) < static_cast<uint64_t>(effectiveThreshold);
}

int GetVRFTierMultiplier(int tier)
{
    switch (static_cast<HMPPrivilegeTier>(tier)) {
    case HMPPrivilegeTier::ELDER:
        return HMP_VRF_ELDER_MULTIPLIER;
    case HMPPrivilegeTier::NEW:
        return HMP_VRF_NEW_MULTIPLIER;
    case HMPPrivilegeTier::UNKNOWN:
    default:
        return 0; // not eligible
    }
}
