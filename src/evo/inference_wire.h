// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EVO_INFERENCE_WIRE_H
#define BITCOIN_EVO_INFERENCE_WIRE_H

#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

class UniValue;

/**
 * DRONE REGISTRATION SPECIAL TRANSACTION (v1.3.0, nDronePayoutHeight fork).
 *
 * Consensus wire format for registering an inference drone with the
 * deterministic drone list (evo/dronelist.h). The registration is carried in a
 * Dash-style special-transaction extraPayload (nVersion = 3,
 * nType = TRANSACTION_DRONE_REGISTER) rather than an OP_RETURN: the payload
 * carries the drone's FULL 96-byte BLS min_sig public key plus a BLS signature
 * proving the registrant controls that key, which cannot fit Bitcoin's
 * 80-byte OP_RETURN standard-relay cap (96 + 48 > 80).
 *
 * This REPLACES the earlier OP_RETURN 0x01 registration outright (the fork is
 * not live; no drone ever registered under the OP_RETURN consensus rules).
 * The swarm's 0x03 rep-update OP_RETURN path is unrelated and unchanged.
 *
 * NOTE FOR THE SWARM STACK (cross-repo follow-up, NOT part of this daemon
 * change): kerrigan-sdk/sdk/src/inference/register_tx.rs still builds the old
 * OP_RETURN 0x01 form and krgn-coordinator/src/scanner.rs still scans for it.
 * Both must be updated to this special-tx format before drones can register
 * under the fork rules. The golden vectors in
 * src/test/data/drone_wire_vectors.json pin the exact bytes (payload
 * serialization, signed message and blst min_sig signatures) the Rust side
 * must reproduce.
 *
 * BLS scheme: the drone identity key is a BLS12-381 *min_sig* key (public key
 * in G2, 96 bytes compressed; signature in G1, 48 bytes compressed) -- the
 * scheme the swarm uses so 48-byte aggregate signatures fit rep-update
 * OP_RETURNs. This is the OPPOSITE group assignment from the daemon's
 * masternode BLS (dashbls min_pk: 48-byte G1 pubkeys, 96-byte G2 sigs), so
 * CBLSPublicKey/CBLSSignature CANNOT be used here; DroneBLS below implements
 * min_sig core sign/verify from dashbls G1/G2/pairing primitives.
 *
 * Signed message (consensus, pinned by the golden vectors):
 *     msgHash = SHA256d( payload serialized WITHOUT vchSig )
 * i.e. exactly ::SerializeHash(CDroneRegTx) -- the SER_GETHASH serialization
 * below omits vchSig, mirroring CProRegTx. The signature is
 *     vchSig = blst min_sig Sign(secretKey, msg = the 32 msgHash bytes,
 *                                DST = DRONE_REG_BLS_DST, aug = "")
 * Because the payload includes the payout script, the collateral output index
 * and inputsHash (hash of all input prevouts, CalcTxInputsHash), the signature
 * binds the BLS key to THIS registration: it cannot be replayed onto a
 * different funding TX or rebound to a different payout/bond, which is what
 * closes the pkh-squatting hole (review finding M2) -- a registration for a
 * bls_pubkey_hash is only valid if its issuer controls the matching key.
 *
 * Exact payload byte layout, v1 (all integers little-endian; vectors and
 * scripts are Bitcoin CompactSize-length-prefixed):
 *     u16              nVersion            (= 1)
 *     20B              blsPubKeyHash       (uint160 raw; MUST equal
 *                                           HASH160(vchBlsPubKey))
 *     1B + 96B         vchBlsPubKey        (CompactSize 0x60 + G2 compressed)
 *     32B              irohNodeId          (uint256 raw)
 *     1B               nHardwareClass      (stored raw; ANY value accepted --
 *                                           consensus must not gate on the
 *                                           swarm's enum, see dronelist.h)
 *     1B               nModelTier          (capability tier 0..3; consensus
 *                                           REJECTS values > 3,
 *                                           "bad-drone-reg-tier")
 *     u32              nCollateralIndex    (bond output index in this TX)
 *     1B + nB          scriptPayout        (CScript, CompactSize-prefixed)
 *     32B              inputsHash          (CalcTxInputsHash of this TX)
 *     1B + 48B         vchSig              (CompactSize 0x30 + G1 compressed;
 *                                           OMITTED under SER_GETHASH)
 */
class CDroneRegTx
{
public:
    static constexpr auto SPECIALTX_TYPE = TRANSACTION_DRONE_REGISTER;
    static constexpr uint16_t CURRENT_VERSION = 1;

    static constexpr size_t BLS_PUBKEY_SIZE = 96; // min_sig: pubkey in G2
    static constexpr size_t BLS_SIGNATURE_SIZE = 48; // min_sig: signature in G1

    /** Highest valid model-capability tier (see nModelTier). */
    static constexpr uint8_t MAX_MODEL_TIER = 3;

    uint16_t nVersion{CURRENT_VERSION};
    /** Committed HASH160 of vchBlsPubKey -- the drone-list key, kept explicit
     *  for continuity with the swarm's hash-committed identity (rep updates,
     *  /v1/models). Consensus asserts HASH160(vchBlsPubKey) == blsPubKeyHash. */
    uint160 blsPubKeyHash;
    /** Full 96-byte BLS12-381 min_sig public key (compressed G2). */
    std::vector<unsigned char> vchBlsPubKey;
    /** Iroh (QUIC transport) node id; informational only for consensus. */
    uint256 irohNodeId;
    /** Hardware class byte, stored raw (any value accepted). */
    uint8_t nHardwareClass{0};
    /** Model-capability tier: 0=simple, 1=standard, 2=complex, 3=frontier.
     *  Consensus-validated (0..3, "bad-drone-reg-tier") and BLS-signed (inside
     *  the SER_GETHASH portion). Stored state only for now -- payout selection
     *  stays tier-neutral round-robin until the stride-frequency weighting
     *  milestone (gated on a tier-attestation scheme). */
    uint8_t nModelTier{0};
    /** Index of the bond output in this TX: nValue must equal
     *  consensus.nDroneCollateralAmount exactly; spending it deregisters. */
    uint32_t nCollateralIndex{0};
    /** Immutable coinbase payout script for this drone. */
    CScript scriptPayout;
    /** Hash of all input prevouts (CalcTxInputsHash); replay protection. */
    uint256 inputsHash;
    /** 48-byte BLS min_sig signature over ::SerializeHash(*this). */
    std::vector<unsigned char> vchSig;

    SERIALIZE_METHODS(CDroneRegTx, obj)
    {
        READWRITE(obj.nVersion);
        if (obj.nVersion == 0 || obj.nVersion > CURRENT_VERSION) {
            // unknown version, bail out early (mirrors CProRegTx)
            return;
        }
        READWRITE(obj.blsPubKeyHash,
                  LIMITED_VECTOR(obj.vchBlsPubKey, BLS_PUBKEY_SIZE),
                  obj.irohNodeId,
                  obj.nHardwareClass,
                  obj.nModelTier,
                  obj.nCollateralIndex,
                  obj.scriptPayout,
                  obj.inputsHash);
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(LIMITED_VECTOR(obj.vchSig, BLS_SIGNATURE_SIZE));
        }
    }

    std::string ToString() const;
    [[nodiscard]] UniValue ToJson() const;
};

/** Payout-script constraints for a drone registration: must be
 *  spendable-looking and small enough to sit in a coinbase without grief --
 *  non-empty, not an OP_RETURN, at most 40 bytes (covers
 *  P2PKH/P2SH/witness-program shapes). Consensus (CheckDroneRegTx). */
bool IsValidDronePayoutScript(const CScript& script);

/**
 * BLS12-381 min_sig helpers for the drone registration proof, built from
 * dashbls G1/G2/pairing primitives (hash-to-G1 via relic's IETF
 * hash_to_curve; the same construction blst implements). Compatibility with
 * the Rust reference (blst::min_sig) is pinned by blst-generated golden
 * vectors in src/test/data/drone_wire_vectors.json.
 */
namespace DroneBLS {

/** Domain separation tag for drone-registration signatures. Deliberately
 *  distinct from the swarm's rep-update DST (…_RO_KRGN_V1_) so a registration
 *  signature can never double as protocol evidence and vice versa. */
static constexpr char DRONE_REG_BLS_DST[] = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_KRGN_REG_V1_";

/**
 * Core min_sig verification: e(sig, g2) == e(H_G1(msg, DST), pk).
 * pubkey = 96-byte compressed G2, sig = 48-byte compressed G1, msgHash = the
 * 32-byte signed message (fed to hash-to-curve as the message, NOT as a
 * point). Returns false for wrong sizes, points not on curve / not in the
 * subgroup, and for the identity (infinity) pubkey or signature -- accepting
 * infinity would allow trivial forgeries.
 */
bool VerifyMinSig(const std::vector<unsigned char>& vchPubKey,
                  const uint256& msgHash,
                  const std::vector<unsigned char>& vchSig);

/** min_sig signing: sig = sk * H_G1(msg, DST). Secret is a 32-byte big-endian
 *  scalar (reduced mod the group order). Test/RPC support only -- consensus
 *  never signs. Returns false on a bad secret. */
bool SignMinSig(const std::vector<unsigned char>& vchSecret,
                const uint256& msgHash,
                std::vector<unsigned char>& vchSigRet);

/** Derive the 96-byte min_sig (G2) public key for a 32-byte secret. Matches
 *  blst min_sig sk_to_pk. Test/RPC support only. */
bool PublicKeyFromSecret(const std::vector<unsigned char>& vchSecret,
                         std::vector<unsigned char>& vchPubKeyRet);

} // namespace DroneBLS

#endif // BITCOIN_EVO_INFERENCE_WIRE_H
