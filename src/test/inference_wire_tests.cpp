// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/inference_wire.h>

#include <evo/specialtx.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <util/strencodings.h>
#include <version.h>

#include <test/data/drone_wire_vectors.json.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

/**
 * The golden vectors in test/data/drone_wire_vectors.json pin the CDroneRegTx
 * consensus wire format (payload serialization, the exact signed message and
 * BLS min_sig signature acceptance):
 *   - payload bytes were produced by the serialization spec in
 *     evo/inference_wire.h and are ROUND-TRIPPED byte-for-byte below, so any
 *     change to the C++ serializer fails this suite;
 *   - signatures were produced by Rust blst 0.3.16 min_sig (the swarm's
 *     library/scheme), so this suite also pins dashbls-verify <-> blst-sign
 *     cross-stack compatibility (hash-to-G1, DST, message definition).
 * If this suite fails after touching evo/inference_wire.{h,cpp} you have
 * changed consensus acceptance -- that is a hard fork, not a cleanup.
 *
 * The Rust SDK's register_tx.rs / the coordinator scanner have NOT yet been
 * updated to this format; these vectors are the reference they must match.
 */
BOOST_FIXTURE_TEST_SUITE(inference_wire_tests, BasicTestingSetup)

namespace {

std::optional<CDroneRegTx> DecodePayload(const std::vector<unsigned char>& payload)
{
    return GetTxPayload<CDroneRegTx>(payload);
}

std::vector<unsigned char> EncodePayload(const CDroneRegTx& ptx)
{
    CDataStream ds(SER_NETWORK, PROTOCOL_VERSION);
    ds << ptx;
    return std::vector<unsigned char>(UCharCast(ds.data()), UCharCast(ds.data()) + ds.size());
}

} // anonymous namespace

BOOST_AUTO_TEST_CASE(golden_vectors)
{
    UniValue vectors = read_json(std::string(json_tests::drone_wire_vectors,
                                             json_tests::drone_wire_vectors + sizeof(json_tests::drone_wire_vectors)));
    BOOST_CHECK(vectors.size() > 0);

    size_t nChecked{0};
    for (size_t i = 0; i < vectors.size(); i++) {
        const UniValue& test = vectors[i];
        if (!test.exists("name")) continue; // leading comment entry
        const std::string name = test["name"].get_str();
        const auto payloadBytes = ParseHex(test["payload"].get_str());

        const auto opt_ptx = DecodePayload(payloadBytes);
        BOOST_CHECK_MESSAGE(opt_ptx.has_value() == test["valid_payload"].get_bool(),
                            name + ": payload deserialization acceptance diverges from the pinned vectors");
        if (!opt_ptx) {
            nChecked++;
            continue;
        }

        BOOST_CHECK_MESSAGE(int{opt_ptx->nVersion} == test["version"].getInt<int>(),
                            name + ": version mismatch");
        const bool version_ok = opt_ptx->nVersion != 0 && opt_ptx->nVersion <= CDroneRegTx::CURRENT_VERSION;
        BOOST_CHECK_MESSAGE(version_ok == test["version_ok"].get_bool(), name + ": version acceptance diverges");
        if (!version_ok) {
            nChecked++;
            continue;
        }

        // Round-trip: re-serializing must reproduce the vector bytes exactly.
        // This is what pins the vectors to the C++ consensus serializer.
        BOOST_CHECK_MESSAGE(EncodePayload(*opt_ptx) == payloadBytes,
                            name + ": re-serialization is not byte-identical to the vector");

        // Field decode.
        BOOST_CHECK_EQUAL(HexStr(opt_ptx->blsPubKeyHash), test["bls_pubkey_hash"].get_str());
        BOOST_CHECK_EQUAL(HexStr(opt_ptx->vchBlsPubKey), test["bls_pubkey"].get_str());
        BOOST_CHECK_EQUAL(HexStr(opt_ptx->irohNodeId), test["iroh_node_id"].get_str());
        BOOST_CHECK_EQUAL(int{opt_ptx->nHardwareClass}, test["hardware_class"].getInt<int>());
        BOOST_CHECK_EQUAL(int{opt_ptx->nModelTier}, test["model_tier"].getInt<int>());
        BOOST_CHECK_EQUAL(opt_ptx->nCollateralIndex, uint32_t(test["collateral_index"].getInt<int>()));
        BOOST_CHECK_EQUAL(HexStr(opt_ptx->scriptPayout), test["script_payout"].get_str());
        BOOST_CHECK_EQUAL(HexStr(opt_ptx->inputsHash), test["inputs_hash"].get_str());

        // Pubkey size + committed-hash consistency (the consensus checks in
        // CheckDroneRegTx).
        const bool pubkey_size_ok = opt_ptx->vchBlsPubKey.size() == CDroneRegTx::BLS_PUBKEY_SIZE;
        BOOST_CHECK_MESSAGE(pubkey_size_ok == test["pubkey_size_ok"].get_bool(),
                            name + ": pubkey size acceptance diverges");
        const bool pkh_matches = Hash160(opt_ptx->vchBlsPubKey) == opt_ptx->blsPubKeyHash;
        BOOST_CHECK_MESSAGE(pkh_matches == test["pkh_matches"].get_bool(),
                            name + ": HASH160(pubkey) commitment check diverges");

        // Model-tier range rule (the CheckDroneRegTx "bad-drone-reg-tier"
        // consensus check): the WIRE decodes any raw byte, acceptance is
        // 0..MAX_MODEL_TIER.
        const bool tier_ok = opt_ptx->nModelTier <= CDroneRegTx::MAX_MODEL_TIER;
        BOOST_CHECK_MESSAGE(tier_ok == test["tier_ok"].get_bool(),
                            name + ": model-tier range acceptance diverges");

        // The signed message: SHA256d of the payload without vchSig, i.e.
        // exactly ::SerializeHash. Pinned so the Rust follow-up reproduces it.
        const uint256 msgHash = ::SerializeHash(*opt_ptx);
        BOOST_CHECK_EQUAL(HexStr(msgHash), test["msg_hash"].get_str());
        BOOST_CHECK_EQUAL(HexStr(opt_ptx->vchSig), test["signature"].get_str());

        // Cross-stack signature acceptance: blst-produced signatures verified
        // by the dashbls-based min_sig verifier.
        const bool sig_valid = DroneBLS::VerifyMinSig(opt_ptx->vchBlsPubKey, msgHash, opt_ptx->vchSig);
        BOOST_CHECK_MESSAGE(sig_valid == test["sig_valid"].get_bool(),
                            name + ": BLS min_sig acceptance diverges from the blst reference");
        nChecked++;
    }
    BOOST_CHECK_EQUAL(nChecked, 15U);
}

BOOST_AUTO_TEST_CASE(minsig_sign_verify_roundtrip)
{
    // The daemon-side signer (droneblssign RPC / test support) must produce
    // signatures its own consensus verifier accepts, for the same DST +
    // message definition the golden vectors pin against blst.
    std::vector<unsigned char> secret(32, 0x00);
    secret[31] = 0x2a;

    std::vector<unsigned char> pubkey;
    BOOST_REQUIRE(DroneBLS::PublicKeyFromSecret(secret, pubkey));
    BOOST_CHECK_EQUAL(pubkey.size(), CDroneRegTx::BLS_PUBKEY_SIZE);

    const uint256 msgHash = ::SerializeHash(std::string("kerrigan drone sign/verify roundtrip"));
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(DroneBLS::SignMinSig(secret, msgHash, sig));
    BOOST_CHECK_EQUAL(sig.size(), CDroneRegTx::BLS_SIGNATURE_SIZE);

    BOOST_CHECK(DroneBLS::VerifyMinSig(pubkey, msgHash, sig));

    // Wrong message.
    const uint256 otherHash = ::SerializeHash(std::string("some other message"));
    BOOST_CHECK(!DroneBLS::VerifyMinSig(pubkey, otherHash, sig));

    // Wrong key.
    std::vector<unsigned char> secret2(32, 0x00);
    secret2[31] = 0x2b;
    std::vector<unsigned char> pubkey2;
    BOOST_REQUIRE(DroneBLS::PublicKeyFromSecret(secret2, pubkey2));
    BOOST_CHECK(!DroneBLS::VerifyMinSig(pubkey2, msgHash, sig));

    // Zero secret is rejected.
    std::vector<unsigned char> zeroSecret(32, 0x00);
    std::vector<unsigned char> dummy;
    BOOST_CHECK(!DroneBLS::SignMinSig(zeroSecret, msgHash, dummy));
    BOOST_CHECK(!DroneBLS::PublicKeyFromSecret(zeroSecret, dummy));
}

BOOST_AUTO_TEST_CASE(payout_script_constraints)
{
    BOOST_CHECK(!IsValidDronePayoutScript(CScript()));
    BOOST_CHECK(!IsValidDronePayoutScript(CScript() << OP_RETURN));
    BOOST_CHECK(!IsValidDronePayoutScript(CScript() << OP_RETURN << std::vector<unsigned char>(10, 0x01)));
    // 41-byte script (1 push opcode + 40 data bytes): too large.
    BOOST_CHECK(!IsValidDronePayoutScript(CScript() << std::vector<unsigned char>(40, 0x01)));
    // 40 bytes exactly: allowed.
    BOOST_CHECK(IsValidDronePayoutScript(CScript() << std::vector<unsigned char>(39, 0x01)));
    // Standard P2PKH (25 bytes) is fine.
    BOOST_CHECK(IsValidDronePayoutScript(CScript() << OP_DUP << OP_HASH160
                                                   << std::vector<unsigned char>(20, 0x01)
                                                   << OP_EQUALVERIFY << OP_CHECKSIG));
}

BOOST_AUTO_TEST_SUITE_END()
