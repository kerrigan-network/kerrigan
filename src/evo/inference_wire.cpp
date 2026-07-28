// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/inference_wire.h>

#include <hash.h>
#include <key_io.h>
#include <script/standard.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <dashbls/bls.hpp>
#include <dashbls/elements.hpp>
#include <dashbls/privatekey.hpp>

#include <univalue.h>

#include <cstring>

std::string CDroneRegTx::ToString() const
{
    CTxDestination dest;
    std::string payee = "unknown";
    if (ExtractDestination(scriptPayout, dest)) {
        payee = EncodeDestination(dest);
    }
    return strprintf("CDroneRegTx(nVersion=%d, blsPubKeyHash=%s, irohNodeId=%s, nHardwareClass=%d, "
                     "nModelTier=%d, nCollateralIndex=%u, scriptPayout=%s)",
                     nVersion, blsPubKeyHash.ToString(), irohNodeId.ToString(), nHardwareClass,
                     nModelTier, nCollateralIndex, payee);
}

// NOTE: CDroneRegTx::ToJson lives in evo/core_write.cpp (libbitcoin_common)
// with the other special-payload ToJson implementations, so wallet/tx tools
// that link core_write can decode the payload without libbitcoin_node.

bool IsValidDronePayoutScript(const CScript& script)
{
    if (script.size() == 0 || script.size() > 40) return false;
    if (script[0] == OP_RETURN) return false;
    return true;
}

namespace DroneBLS {

namespace {

/** Compressed BLS12-381 point header bits: 0x80 = compressed, 0x40 = infinity.
 *  The identity element verifies trivially against any message (both pairings
 *  degenerate to 1), so it must be rejected outright for pubkeys AND sigs. */
bool IsInfinityEncoding(const std::vector<unsigned char>& vch)
{
    return !vch.empty() && (vch[0] & 0x40) != 0;
}

std::vector<uint8_t> MsgBytes(const uint256& msgHash)
{
    return std::vector<uint8_t>(msgHash.begin(), msgHash.end());
}

constexpr int DstLen()
{
    return int{sizeof(DRONE_REG_BLS_DST)} - 1; // strip the NUL terminator
}

} // anonymous namespace

bool VerifyMinSig(const std::vector<unsigned char>& vchPubKey,
                  const uint256& msgHash,
                  const std::vector<unsigned char>& vchSig)
{
    if (vchPubKey.size() != CDroneRegTx::BLS_PUBKEY_SIZE ||
        vchSig.size() != CDroneRegTx::BLS_SIGNATURE_SIZE) {
        return false;
    }
    if (IsInfinityEncoding(vchPubKey) || IsInfinityEncoding(vchSig)) {
        return false;
    }
    try {
        // FromBytes performs the on-curve + subgroup checks (throws on
        // failure), matching blst's verify(pk_validate=true, sig_groupcheck=true).
        const bls::G2Element pk = bls::G2Element::FromByteVector(std::vector<uint8_t>(vchPubKey.begin(), vchPubKey.end()));
        const bls::G1Element sig = bls::G1Element::FromByteVector(std::vector<uint8_t>(vchSig.begin(), vchSig.end()));
        const bls::G1Element msgPoint = bls::G1Element::FromMessage(
            MsgBytes(msgHash), reinterpret_cast<const uint8_t*>(DRONE_REG_BLS_DST), DstLen());
        // Core min_sig verification equation: e(sig, g2) == e(H(m), pk).
        return sig.Pair(bls::G2Element::Generator()) == msgPoint.Pair(pk);
    } catch (const std::exception&) {
        return false;
    }
}

bool SignMinSig(const std::vector<unsigned char>& vchSecret,
                const uint256& msgHash,
                std::vector<unsigned char>& vchSigRet)
{
    if (vchSecret.size() != 32) return false;
    try {
        const bls::PrivateKey sk = bls::PrivateKey::FromByteVector(
            std::vector<uint8_t>(vchSecret.begin(), vchSecret.end()), /*modOrder=*/true);
        if (sk.IsZero()) return false;
        const bls::G1Element msgPoint = bls::G1Element::FromMessage(
            MsgBytes(msgHash), reinterpret_cast<const uint8_t*>(DRONE_REG_BLS_DST), DstLen());
        const bls::G1Element sig = sk * msgPoint;
        const std::vector<uint8_t> ser = sig.Serialize();
        vchSigRet.assign(ser.begin(), ser.end());
        return vchSigRet.size() == CDroneRegTx::BLS_SIGNATURE_SIZE;
    } catch (const std::exception&) {
        return false;
    }
}

bool PublicKeyFromSecret(const std::vector<unsigned char>& vchSecret,
                         std::vector<unsigned char>& vchPubKeyRet)
{
    if (vchSecret.size() != 32) return false;
    try {
        const bls::PrivateKey sk = bls::PrivateKey::FromByteVector(
            std::vector<uint8_t>(vchSecret.begin(), vchSecret.end()), /*modOrder=*/true);
        if (sk.IsZero()) return false;
        const std::vector<uint8_t> ser = sk.GetG2Element().Serialize();
        vchPubKeyRet.assign(ser.begin(), ser.end());
        return vchPubKeyRet.size() == CDroneRegTx::BLS_PUBKEY_SIZE;
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace DroneBLS
