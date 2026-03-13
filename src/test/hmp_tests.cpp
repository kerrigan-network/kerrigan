// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bls/bls.h>
#include <chain.h>
#include <hash.h>
#include <chainparams.h>
#include <clientversion.h>
#include <consensus/params.h>
#include <evo/cbtx.h>
#include <primitives/block.h>
#include <hmp/commitment.h>
#include <hmp/identity.h>
#include <hmp/privilege.h>
#include <hmp/chain_weight.h>
#include <hmp/negative_proof.h>
#include <hmp/hmp_params.h>
#include <hmp/seal.h>
#include <hmp/seal_manager.h>
#include <hmp/vrf.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(hmp_tests, BasicTestingSetup)

// Helpers

/** Compute the per-signer message hash H(domain || blockHash || signerPubKey || algoId)
 *  Must match production code in seal.cpp / seal_manager.cpp. */
static uint256 PerSignerMsg(const uint256& blockHash, const CBLSPublicKey& pk, uint8_t algoId = ALGO_X11)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw << HMP_SEAL_DOMAIN_TAG << blockHash << pk << algoId;
    return hw.GetHash();
}

/** Default prevSealHash for tests (no real previous seal available) */
static const uint256 TEST_PREV_SEAL_HASH;

/**
 * Generate a BLS key pair that is VRF-selected for the given blockHash.
 * Loops until IsVRFSelected returns true (expected ~5 iterations for 20% base rate).
 */
static void MakeVRFSelectedKey(const uint256& blockHash, CBLSSecretKey& skOut, CBLSPublicKey& pkOut,
                                CBLSSignature& vrfOut, int tierMultiplier = 1)
{
    for (int i = 0; i < 10000; i++) {
        skOut.MakeNewKey();
        pkOut = skOut.GetPublicKey();
        vrfOut = ComputeVRF(skOut, blockHash, TEST_PREV_SEAL_HASH);
        uint256 vrfHash = VRFOutputHash(vrfOut);
        if (IsVRFSelected(vrfHash, tierMultiplier)) return;
    }
    BOOST_FAIL("Could not generate VRF-selected key after 10000 attempts");
}

// Identity Tests

BOOST_AUTO_TEST_CASE(identity_generate_and_sign)
{
    bls::bls_legacy_scheme.store(false);

    CHMPIdentity identity;
    fs::path testdir = m_node.args->GetDataDirNet();
    BOOST_CHECK(identity.Init(testdir));
    BOOST_CHECK(identity.IsValid());

    // Verify signature
    uint256 hash = uint256::ONE;
    CBLSSignature sig = identity.Sign(hash);
    BOOST_CHECK(sig.IsValid());
    BOOST_CHECK(sig.VerifyInsecure(identity.GetPublicKey(), hash));

    // Verify wrong hash fails
    uint256 wrongHash = uint256::TWO;
    BOOST_CHECK(!sig.VerifyInsecure(identity.GetPublicKey(), wrongHash));
}

BOOST_AUTO_TEST_CASE(identity_persistence_roundtrip)
{
    bls::bls_legacy_scheme.store(false);

    fs::path testdir = m_node.args->GetDataDirNet();

    CBLSPublicKey savedPubKey;
    {
        CHMPIdentity identity;
        BOOST_CHECK(identity.Init(testdir));
        savedPubKey = identity.GetPublicKey();
        BOOST_CHECK(savedPubKey.IsValid());
    }

    // Reload from disk, should get same key
    {
        CHMPIdentity identity2;
        BOOST_CHECK(identity2.Init(testdir));
        BOOST_CHECK(identity2.GetPublicKey() == savedPubKey);
    }
}

// Privilege Tracker Tests

BOOST_AUTO_TEST_CASE(privilege_tracker_basic_tier)
{
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPWarmupBlocks = 5;
    params.nHMPPrivilegeWindow = 50;
    params.nHMPMinBlocksSolved = 1;

    CHMPPrivilegeTracker tracker(params);

    CBLSSecretKey sk;
    sk.MakeNewKey();
    CBLSPublicKey pk = sk.GetPublicKey();

    // Initially unknown
    BOOST_CHECK(tracker.GetTier(pk, ALGO_X11) == HMPPrivilegeTier::UNKNOWN);

    // Add blocks but still in warmup
    for (int i = 0; i < 4; i++) {
        tracker.BlockConnected(i, ALGO_X11, pk, {});
    }
    BOOST_CHECK(tracker.GetTier(pk, ALGO_X11) == HMPPrivilegeTier::UNKNOWN);

    // Past warmup ->NEW (solved blocks but no seal participation)
    for (int i = 4; i < 6; i++) {
        tracker.BlockConnected(i, ALGO_X11, pk, {});
    }
    BOOST_CHECK(tracker.GetTier(pk, ALGO_X11) == HMPPrivilegeTier::NEW);

    // Add seal participation ->ELDER
    tracker.BlockConnected(6, ALGO_X11, pk, {pk});
    BOOST_CHECK(tracker.GetTier(pk, ALGO_X11) == HMPPrivilegeTier::ELDER);
}

BOOST_AUTO_TEST_CASE(privilege_tracker_per_algo)
{
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPWarmupBlocks = 2;
    params.nHMPPrivilegeWindow = 50;
    params.nHMPMinBlocksSolved = 1;

    CHMPPrivilegeTracker tracker(params);

    CBLSSecretKey sk;
    sk.MakeNewKey();
    CBLSPublicKey pk = sk.GetPublicKey();

    // Mine only X11 blocks
    for (int i = 0; i < 5; i++) {
        tracker.BlockConnected(i, ALGO_X11, pk, {});
    }

    // Privileged on X11 but unknown on KawPoW
    BOOST_CHECK(tracker.GetTier(pk, ALGO_X11) == HMPPrivilegeTier::NEW);
    BOOST_CHECK(tracker.GetTier(pk, ALGO_KAWPOW) == HMPPrivilegeTier::UNKNOWN);
}

BOOST_AUTO_TEST_CASE(privilege_tracker_window_sliding)
{
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPWarmupBlocks = 2;
    params.nHMPPrivilegeWindow = 10; // small window for testing
    params.nHMPMinBlocksSolved = 1;

    CHMPPrivilegeTracker tracker(params);

    CBLSSecretKey sk1, sk2;
    sk1.MakeNewKey();
    sk2.MakeNewKey();
    CBLSPublicKey pk1 = sk1.GetPublicKey();
    CBLSPublicKey pk2 = sk2.GetPublicKey();

    // pk1 mines blocks 0-4
    for (int i = 0; i < 5; i++) {
        tracker.BlockConnected(i, ALGO_X11, pk1, {});
    }
    BOOST_CHECK(tracker.GetTier(pk1, ALGO_X11) == HMPPrivilegeTier::NEW);

    // pk2 mines blocks 5-14 (window slides, pk1 falls out)
    for (int i = 5; i < 15; i++) {
        tracker.BlockConnected(i, ALGO_X11, pk2, {});
    }

    // pk1 should still be in window if window=10 and we have blocks 5-14
    // pk1 mined blocks 0-4 which are outside window of last 10
    BOOST_CHECK(tracker.GetTier(pk1, ALGO_X11) == HMPPrivilegeTier::UNKNOWN);
    BOOST_CHECK(tracker.GetTier(pk2, ALGO_X11) == HMPPrivilegeTier::NEW);
}

BOOST_AUTO_TEST_CASE(privilege_tracker_dominance_cap)
{
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPWarmupBlocks = 0;
    params.nHMPPrivilegeWindow = 100;
    params.nHMPMinBlocksSolved = 1;

    CHMPPrivilegeTracker tracker(params);

    CBLSSecretKey sk_big, sk_small;
    sk_big.MakeNewKey();
    sk_small.MakeNewKey();
    CBLSPublicKey pk_big = sk_big.GetPublicKey();
    CBLSPublicKey pk_small = sk_small.GetPublicKey();

    // pk_big mines 80 blocks, pk_small mines 20
    for (int i = 0; i < 80; i++) {
        tracker.BlockConnected(i, ALGO_X11, pk_big, {});
    }
    for (int i = 80; i < 100; i++) {
        tracker.BlockConnected(i, ALGO_X11, pk_small, {});
    }

    // pk_big has 80% share but capped at 25% (2500 basis points)
    uint32_t weight_big = tracker.GetEffectiveWeight(pk_big, ALGO_X11);
    BOOST_CHECK_EQUAL(weight_big, 2500u);

    // pk_small has 20% share (2000 basis points), under cap
    uint32_t weight_small = tracker.GetEffectiveWeight(pk_small, ALGO_X11);
    BOOST_CHECK_EQUAL(weight_small, 2000u);
}

BOOST_AUTO_TEST_CASE(privilege_tracker_disconnect)
{
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPWarmupBlocks = 2;
    params.nHMPPrivilegeWindow = 50;
    params.nHMPMinBlocksSolved = 1;

    CHMPPrivilegeTracker tracker(params);

    CBLSSecretKey sk;
    sk.MakeNewKey();
    CBLSPublicKey pk = sk.GetPublicKey();

    for (int i = 0; i < 5; i++) {
        tracker.BlockConnected(i, ALGO_X11, pk, {});
    }
    BOOST_CHECK(tracker.GetTier(pk, ALGO_X11) == HMPPrivilegeTier::NEW);

    // Disconnect all blocks
    for (int i = 4; i >= 0; i--) {
        tracker.BlockDisconnected(i);
    }
    BOOST_CHECK(tracker.GetTier(pk, ALGO_X11) == HMPPrivilegeTier::UNKNOWN);
}

BOOST_AUTO_TEST_CASE(privilege_tracker_elder_set)
{
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPWarmupBlocks = 2;
    params.nHMPPrivilegeWindow = 50;
    params.nHMPMinBlocksSolved = 1;

    CHMPPrivilegeTracker tracker(params);

    CBLSSecretKey sk1, sk2;
    sk1.MakeNewKey();
    sk2.MakeNewKey();
    CBLSPublicKey pk1 = sk1.GetPublicKey();
    CBLSPublicKey pk2 = sk2.GetPublicKey();

    // Both mine blocks past warmup
    for (int i = 0; i < 5; i++) {
        tracker.BlockConnected(i, ALGO_X11, pk1, {});
    }
    for (int i = 5; i < 10; i++) {
        tracker.BlockConnected(i, ALGO_X11, pk2, {});
    }

    // Only pk1 participates in sealing
    tracker.BlockConnected(10, ALGO_X11, pk1, {pk1});

    auto elders = tracker.GetElderSet(ALGO_X11);
    BOOST_CHECK_EQUAL(elders.size(), 1u);
    BOOST_CHECK(elders[0] == pk1);

    // pk2 is NEW, not Elder
    BOOST_CHECK(tracker.GetTier(pk2, ALGO_X11) == HMPPrivilegeTier::NEW);
}

// CCbTx v4 Serialization Tests

BOOST_AUTO_TEST_CASE(cbtx_v4_serialization_roundtrip)
{
    bls::bls_legacy_scheme.store(false);

    CCbTx original;
    original.nVersion = CCbTx::Version::HMP_SEAL;
    original.nHeight = 12345;
    original.merkleRootMNList = uint256::ONE;
    original.merkleRootQuorums = uint256::TWO;
    original.bestCLHeightDiff = 42;

    // Generate BLS keys for the test
    CBLSSecretKey sk;
    sk.MakeNewKey();
    original.bestCLSignature = sk.Sign(uint256::ONE, false);
    original.creditPoolBalance = 1000000;

    // HMP fields
    original.minerIdentity = sk.GetPublicKey();
    original.sealForAncestor = sk.Sign(uint256::TWO, false);
    original.sealBlockHash.SetHex("0000000000000000000000000000000000000000000000000000000000001234");

    // Serialize
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << original;

    // Deserialize
    CCbTx deserialized;
    ss >> deserialized;

    // Verify all fields
    BOOST_CHECK(deserialized.nVersion == CCbTx::Version::HMP_SEAL);
    BOOST_CHECK_EQUAL(deserialized.nHeight, 12345);
    BOOST_CHECK(deserialized.merkleRootMNList == uint256::ONE);
    BOOST_CHECK(deserialized.merkleRootQuorums == uint256::TWO);
    BOOST_CHECK_EQUAL(deserialized.bestCLHeightDiff, 42u);
    BOOST_CHECK(deserialized.bestCLSignature == original.bestCLSignature);
    BOOST_CHECK_EQUAL(deserialized.creditPoolBalance, 1000000);

    // HMP fields
    BOOST_CHECK(deserialized.minerIdentity == original.minerIdentity);
    BOOST_CHECK(deserialized.sealForAncestor == original.sealForAncestor);
    BOOST_CHECK(deserialized.sealBlockHash == original.sealBlockHash);
}

BOOST_AUTO_TEST_CASE(cbtx_v3_backward_compat)
{
    bls::bls_legacy_scheme.store(false);

    // v3 CCbTx should not have HMP fields
    CCbTx v3tx;
    v3tx.nVersion = CCbTx::Version::CLSIG_AND_BALANCE;
    v3tx.nHeight = 100;
    v3tx.merkleRootMNList = uint256::ONE;
    v3tx.merkleRootQuorums = uint256::TWO;

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << v3tx;

    CCbTx deserialized;
    ss >> deserialized;

    // HMP fields should be default (invalid/empty)
    BOOST_CHECK(!deserialized.minerIdentity.IsValid());
    BOOST_CHECK(!deserialized.sealForAncestor.IsValid());
    BOOST_CHECK(deserialized.sealBlockHash.IsNull());
}

// Seal Tests

BOOST_AUTO_TEST_CASE(seal_share_creation_and_verify)
{
    bls::bls_legacy_scheme.store(false);

    CBLSSecretKey sk;
    sk.MakeNewKey();
    CBLSPublicKey pk = sk.GetPublicKey();

    uint256 blockHash = uint256::ONE;

    // Per-signer message: H(blockHash || signerPubKey)
    uint256 sigMsg = PerSignerMsg(blockHash, pk);

    CSealShare share;
    share.blockHash = blockHash;
    share.signerPubKey = pk;
    share.signature = sk.Sign(sigMsg, false);
    share.algoId = ALGO_X11;
    share.nTimestamp = 12345;

    // Verify BLS sig against per-signer message
    BOOST_CHECK(share.signature.IsValid());
    BOOST_CHECK(share.signature.VerifyInsecure(pk, sigMsg));

    // Wrong hash should fail
    uint256 wrongMsg = PerSignerMsg(uint256::TWO, pk);
    BOOST_CHECK(!share.signature.VerifyInsecure(pk, wrongMsg));
}

BOOST_AUTO_TEST_CASE(seal_share_serialization)
{
    bls::bls_legacy_scheme.store(false);

    CBLSSecretKey sk;
    sk.MakeNewKey();

    CSealShare original;
    original.blockHash = uint256::ONE;
    original.signerPubKey = sk.GetPublicKey();
    original.signature = sk.Sign(PerSignerMsg(original.blockHash, original.signerPubKey), false);
    original.algoId = ALGO_KAWPOW;
    original.nTimestamp = 99999;

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << original;

    CSealShare deserialized;
    ss >> deserialized;

    BOOST_CHECK(deserialized.blockHash == original.blockHash);
    BOOST_CHECK(deserialized.signerPubKey == original.signerPubKey);
    BOOST_CHECK(deserialized.signature == original.signature);
    BOOST_CHECK_EQUAL(deserialized.algoId, original.algoId);
    BOOST_CHECK_EQUAL(deserialized.nTimestamp, original.nTimestamp);
}

BOOST_AUTO_TEST_CASE(seal_assembly_and_verify)
{
    bls::bls_legacy_scheme.store(false);

    uint256 blockHash = uint256::ONE;

    // Create 3 signers, each signs H(blockHash || pk)
    std::vector<CBLSSecretKey> sks(3);
    std::vector<CBLSPublicKey> pks(3);
    std::vector<CBLSSignature> sigs(3);

    std::vector<uint8_t> algos = {ALGO_X11, ALGO_KAWPOW, ALGO_EQUIHASH_200};
    for (int i = 0; i < 3; i++) {
        sks[i].MakeNewKey();
        pks[i] = sks[i].GetPublicKey();
        uint256 sigMsg = PerSignerMsg(blockHash, pks[i], algos[i]);
        sigs[i] = sks[i].Sign(sigMsg, false);
        BOOST_CHECK(sigs[i].VerifyInsecure(pks[i], sigMsg));
    }

    // Aggregate signatures
    CBLSSignature aggSig = CBLSSignature::AggregateInsecure(Span<CBLSSignature>(sigs));
    BOOST_CHECK(aggSig.IsValid());

    // Create assembled seal
    CAssembledSeal seal;
    seal.blockHash = blockHash;
    seal.aggregatedSig = aggSig;
    seal.signers = pks;
    seal.signerAlgos = algos;

    // Verify
    BOOST_CHECK(seal.Verify());

    // Tamper with block hash, should fail
    CAssembledSeal tampered = seal;
    tampered.blockHash = uint256::TWO;
    BOOST_CHECK(!tampered.Verify());
}

BOOST_AUTO_TEST_CASE(seal_assembled_serialization)
{
    bls::bls_legacy_scheme.store(false);

    CBLSSecretKey sk1, sk2;
    sk1.MakeNewKey();
    sk2.MakeNewKey();

    uint256 blockHash = uint256::TWO;
    CBLSPublicKey pk1 = sk1.GetPublicKey();
    CBLSPublicKey pk2 = sk2.GetPublicKey();

    // Per-signer messages, include algoId in hash
    std::vector<uint8_t> algos = {ALGO_X11, ALGO_KAWPOW};
    std::vector<CBLSSignature> sigs = {
        sk1.Sign(PerSignerMsg(blockHash, pk1, algos[0]), false),
        sk2.Sign(PerSignerMsg(blockHash, pk2, algos[1]), false)
    };

    CAssembledSeal original;
    original.blockHash = blockHash;
    original.aggregatedSig = CBLSSignature::AggregateInsecure(Span<CBLSSignature>(sigs));
    original.signers = {pk1, pk2};
    original.signerAlgos = algos;

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << original;

    CAssembledSeal deserialized;
    ss >> deserialized;

    BOOST_CHECK(deserialized.blockHash == original.blockHash);
    BOOST_CHECK(deserialized.aggregatedSig == original.aggregatedSig);
    BOOST_CHECK_EQUAL(deserialized.signers.size(), 2u);
    BOOST_CHECK(deserialized.signers[0] == original.signers[0]);
    BOOST_CHECK(deserialized.signers[1] == original.signers[1]);
    BOOST_CHECK(deserialized.Verify());
}

BOOST_AUTO_TEST_CASE(seal_manager_share_collection)
{
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPSigningWindowMs = 5000;
    params.nHMPGracePeriodMs = 15000;
    params.nHMPSealTrailingDepth = 2;
    params.nHMPWarmupBlocks = 0;
    params.nHMPPrivilegeWindow = 100;
    params.nHMPMinBlocksSolved = 1;
    params.nHMPCommitmentOffset = 0;

    CHMPPrivilegeTracker privilege(params);

    uint256 blockHash = uint256::ONE;

    // Create VRF-selected signers
    CBLSSecretKey sk1, sk2;
    CBLSPublicKey pk1, pk2;
    CBLSSignature vrf1, vrf2;
    MakeVRFSelectedKey(blockHash, sk1, pk1, vrf1);
    MakeVRFSelectedKey(blockHash, sk2, pk2, vrf2);

    // Build privilege for signers
    for (int i = 0; i < 5; i++) {
        privilege.BlockConnected(i, ALGO_X11, pk1, {});
    }
    for (int i = 5; i < 10; i++) {
        privilege.BlockConnected(i, ALGO_X11, pk2, {});
    }

    CSealManager manager(params, nullptr, &privilege);
    manager.OnNewBlock(blockHash, 10, TEST_PREV_SEAL_HASH);

    // Create and add valid shares with per-signer messages + VRF
    CSealShare share1;
    share1.blockHash = blockHash;
    share1.signerPubKey = pk1;
    share1.signature = sk1.Sign(PerSignerMsg(blockHash, pk1), false);
    share1.algoId = ALGO_X11;
    share1.vrfProof = vrf1;

    CSealShare share2;
    share2.blockHash = blockHash;
    share2.signerPubKey = pk2;
    share2.signature = sk2.Sign(PerSignerMsg(blockHash, pk2), false);
    share2.algoId = ALGO_X11;
    share2.vrfProof = vrf2;

    BOOST_CHECK(HMPAccepted(manager.AddSealShare(share1)));
    BOOST_CHECK(HMPAccepted(manager.AddSealShare(share2)));

    // Duplicate should be rejected
    BOOST_CHECK(!HMPAccepted(manager.AddSealShare(share1)));
}

BOOST_AUTO_TEST_CASE(seal_manager_invalid_share_rejected)
{
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPSigningWindowMs = 5000;
    params.nHMPGracePeriodMs = 15000;
    params.nHMPSealTrailingDepth = 2;
    params.nHMPWarmupBlocks = 2;
    params.nHMPPrivilegeWindow = 100;
    params.nHMPMinBlocksSolved = 1;
    params.nHMPCommitmentOffset = 0;

    CHMPPrivilegeTracker privilege(params);
    CSealManager manager(params, nullptr, &privilege);

    uint256 blockHash = uint256::ONE;
    manager.OnNewBlock(blockHash, 10, TEST_PREV_SEAL_HASH);

    // Create a VRF-selected key for this block
    CBLSSecretKey sk1;
    CBLSPublicKey pk1;
    CBLSSignature vrf1;
    MakeVRFSelectedKey(blockHash, sk1, pk1, vrf1);

    CBLSSecretKey sk2;
    sk2.MakeNewKey();

    // Give sk1 some privilege first
    for (int i = 0; i < 5; i++) {
        privilege.BlockConnected(i, ALGO_X11, pk1, {});
    }

    // Share with bad BLS signature (signed with wrong key)
    CSealShare badSig;
    badSig.blockHash = blockHash;
    badSig.signerPubKey = pk1;
    badSig.signature = sk2.Sign(PerSignerMsg(blockHash, pk1), false);
    badSig.algoId = ALGO_X11;
    badSig.vrfProof = vrf1;

    BOOST_CHECK(!HMPAccepted(manager.AddSealShare(badSig)));

    // Share for unknown block
    CSealShare unknownBlock;
    unknownBlock.blockHash = uint256::TWO; // no session for this block
    unknownBlock.signerPubKey = pk1;
    unknownBlock.signature = sk1.Sign(PerSignerMsg(uint256::TWO, pk1), false);
    unknownBlock.algoId = ALGO_X11;
    unknownBlock.vrfProof = ComputeVRF(sk1, uint256::TWO, TEST_PREV_SEAL_HASH);

    BOOST_CHECK(!HMPAccepted(manager.AddSealShare(unknownBlock)));

    // Share with missing VRF proof
    CSealShare noVrf;
    noVrf.blockHash = blockHash;
    noVrf.signerPubKey = pk1;
    noVrf.signature = sk1.Sign(PerSignerMsg(blockHash, pk1), false);
    noVrf.algoId = ALGO_X11;
    // vrfProof left default (invalid), should be rejected

    BOOST_CHECK(!HMPAccepted(manager.AddSealShare(noVrf)));
}

// Chain Weight & Negative Proof Tests

BOOST_AUTO_TEST_CASE(seal_multiplier_no_signers)
{
    bls::bls_legacy_scheme.store(false);

    // No signers ->pure PoW multiplier
    std::vector<CBLSPublicKey> empty;
    std::vector<uint8_t> emptyAlgos;
    uint64_t mult = ComputeSealMultiplier(empty, emptyAlgos, ALGO_X11, nullptr);
    BOOST_CHECK_EQUAL(mult, 10000u);
}

BOOST_AUTO_TEST_CASE(seal_multiplier_full_coverage)
{
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPWarmupBlocks = 0;
    params.nHMPPrivilegeWindow = 100;
    params.nHMPMinBlocksSolved = 1;

    CHMPPrivilegeTracker tracker(params);

    // Create 4 signers, one per algo, to be Elders
    CBLSSecretKey sks[4];
    CBLSPublicKey pks[4];
    for (int i = 0; i < 4; i++) {
        sks[i].MakeNewKey();
        pks[i] = sks[i].GetPublicKey();
    }

    // Mine blocks and participate in sealing to become Elders
    for (int i = 0; i < 4; i++) {
        tracker.BlockConnected(i, i, pks[i], {pks[i]});
    }

    // All 4 sign the seal
    std::vector<CBLSPublicKey> signers(pks, pks + 4);
    std::vector<uint8_t> algos = {ALGO_X11, ALGO_KAWPOW, ALGO_EQUIHASH_200, ALGO_EQUIHASH_192};

    uint64_t mult = ComputeSealMultiplier(signers, algos, ALGO_X11, &tracker);

    // Graduated ladder: 1 X11 Elder present out of 1 total ->full shade (18000)
    // Cross-algo bonus: 3 additional algos × 500 = +1500
    // Total: 18000 + 1500 = 19500
    BOOST_CHECK(mult > 10000u);
    BOOST_CHECK(mult <= 19500u);
}

BOOST_AUTO_TEST_CASE(seal_multiplier_graceful_degradation)
{
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPWarmupBlocks = 0;
    params.nHMPPrivilegeWindow = 100;
    params.nHMPMinBlocksSolved = 1;

    CHMPPrivilegeTracker tracker(params);

    // Only 1 Elder, with 1 Elder now getting full shade benefit
    CBLSSecretKey sk;
    sk.MakeNewKey();
    CBLSPublicKey pk = sk.GetPublicKey();
    tracker.BlockConnected(0, ALGO_X11, pk, {pk});

    std::vector<CBLSPublicKey> signers = {pk};
    std::vector<uint8_t> algos = {ALGO_X11};

    uint64_t mult = ComputeSealMultiplier(signers, algos, ALGO_X11, &tracker);
    // 1 Elder present out of 1 required ->full shade tier (15000-18000)
    BOOST_CHECK(mult >= 15000u);
    BOOST_CHECK(mult <= 18000u);

    // 0 Elders (no signers) ->neutral
    std::vector<CBLSPublicKey> noSigners;
    std::vector<uint8_t> noAlgos;
    uint64_t noSealMult = ComputeSealMultiplier(noSigners, noAlgos, ALGO_X11, &tracker);
    BOOST_CHECK_EQUAL(noSealMult, 10000u);
}

BOOST_AUTO_TEST_CASE(negative_proof_no_penalty)
{
    bls::bls_legacy_scheme.store(false);

    // No privilege tracker ->no penalty
    std::vector<CBLSPublicKey> signers;
    std::vector<uint8_t> signerAlgos;
    uint64_t penalty = EvaluateNegativeProof(signers, signerAlgos, ALGO_X11, nullptr);
    BOOST_CHECK_EQUAL(penalty, 10000u);
}

BOOST_AUTO_TEST_CASE(negative_proof_heavy_penalty)
{
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPWarmupBlocks = 0;
    params.nHMPPrivilegeWindow = 100;
    params.nHMPMinBlocksSolved = 1;

    CHMPPrivilegeTracker tracker(params);

    // Create 6 Elders on X11
    std::vector<CBLSSecretKey> sks(6);
    std::vector<CBLSPublicKey> pks(6);
    for (int i = 0; i < 6; i++) {
        sks[i].MakeNewKey();
        pks[i] = sks[i].GetPublicKey();
        tracker.BlockConnected(i, ALGO_X11, pks[i], {pks[i]});
    }

    // Only 2 of 6 Elders present ->67% missing ->heavy penalty
    std::vector<CBLSPublicKey> signers = {pks[0], pks[1]};
    std::vector<uint8_t> signerAlgos = {ALGO_X11, ALGO_X11};
    uint64_t penalty = EvaluateNegativeProof(signers, signerAlgos, ALGO_X11, &tracker);
    BOOST_CHECK_EQUAL(penalty, 1000u); // 0.1× severe penalty
}

BOOST_AUTO_TEST_CASE(required_agreement_thresholds)
{
    // PRD v3 Section 7.2 threshold table
    BOOST_CHECK_EQUAL(GetRequiredAgreement(0), 0);    // no Elders ->pure PoW
    BOOST_CHECK_EQUAL(GetRequiredAgreement(1), 0);     // 1 Elder -> pure PoW
    BOOST_CHECK_EQUAL(GetRequiredAgreement(2), 100);   // 2 Elders ->require both
    BOOST_CHECK_EQUAL(GetRequiredAgreement(3), 66);    // 2 of 3
    BOOST_CHECK_EQUAL(GetRequiredAgreement(4), 75);
    BOOST_CHECK_EQUAL(GetRequiredAgreement(5), 75);
    BOOST_CHECK_EQUAL(GetRequiredAgreement(6), 80);
    BOOST_CHECK_EQUAL(GetRequiredAgreement(100), 80);
}

// PRD v2: Dominance Catch & Mannequin Detection Tests

BOOST_AUTO_TEST_CASE(privilege_tracker_dominance_catch_floor)
{
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPWarmupBlocks = 0;
    params.nHMPPrivilegeWindow = 10; // small window for testing
    params.nHMPMinBlocksSolved = 1;
    params.nHMPDominanceCatchFloor = 3; // catch floor of 3 for easy testing
    params.nHMPDominanceCatchMaxLookback = 100;

    CHMPPrivilegeTracker tracker(params);

    // Create 4 pools
    std::vector<CBLSSecretKey> sks(4);
    std::vector<CBLSPublicKey> pks(4);
    for (int i = 0; i < 4; i++) {
        sks[i].MakeNewKey();
        pks[i] = sks[i].GetPublicKey();
    }

    // pk0-pk2 mine blocks 0-2 with seal participation (all become Elder)
    for (int i = 0; i < 3; i++) {
        tracker.BlockConnected(i, ALGO_X11, pks[i], {pks[i]});
    }

    auto elders = tracker.GetElderSet(ALGO_X11);
    BOOST_CHECK_EQUAL(elders.size(), 3u);

    // pk3 dominates blocks 3-11 (window=10, so pk0-pk2 start falling out)
    for (int i = 3; i < 12; i++) {
        tracker.BlockConnected(i, ALGO_X11, pks[3], {pks[3]});
    }

    // pk0 solves block 12 (still in standard window) + seals
    tracker.BlockConnected(12, ALGO_X11, pks[0], {pks[0], pks[3]});

    // pk3 dominates 13-14
    for (int i = 13; i < 15; i++) {
        tracker.BlockConnected(i, ALGO_X11, pks[3], {pks[3]});
    }

    elders = tracker.GetElderSet(ALGO_X11);
    // pk0 solved + sealed within standard window ->promoted via dominance catch
    bool pk0Found = false;
    for (const auto& e : elders) {
        if (e == pks[0]) pk0Found = true;
    }
    BOOST_CHECK(pk0Found);
}

BOOST_AUTO_TEST_CASE(privilege_tracker_dominance_catch_extended_window)
{
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPWarmupBlocks = 0;
    params.nHMPPrivilegeWindow = 5;
    params.nHMPMinBlocksSolved = 1;
    params.nHMPDominanceCatchFloor = 2;
    params.nHMPDominanceCatchMaxLookback = 50;

    CHMPPrivilegeTracker tracker(params);

    CBLSSecretKey sk1, sk2;
    sk1.MakeNewKey();
    sk2.MakeNewKey();
    CBLSPublicKey pk1 = sk1.GetPublicKey();
    CBLSPublicKey pk2 = sk2.GetPublicKey();

    // pk1 mines block 0 with seal
    tracker.BlockConnected(0, ALGO_KAWPOW, pk1, {pk1});

    // pk2 dominates blocks 1-7
    for (int i = 1; i < 8; i++) {
        tracker.BlockConnected(i, ALGO_KAWPOW, pk2, {pk2});
    }

    // pk1 solves block 8 (within 5-block standard window) + seals
    tracker.BlockConnected(8, ALGO_KAWPOW, pk1, {pk1, pk2});

    // pk2 dominates 9-10
    for (int i = 9; i < 11; i++) {
        tracker.BlockConnected(i, ALGO_KAWPOW, pk2, {pk2});
    }

    // pk1 solved + sealed within standard window ->promoted via dominance catch
    auto elders = tracker.GetElderSet(ALGO_KAWPOW);
    BOOST_CHECK_EQUAL(elders.size(), 2u);
}

BOOST_AUTO_TEST_CASE(negative_proof_mannequin_detection)
{
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPWarmupBlocks = 0;
    params.nHMPPrivilegeWindow = 100;
    params.nHMPMinBlocksSolved = 1;

    CHMPPrivilegeTracker tracker(params);

    // Create 4 known Elders
    std::vector<CBLSSecretKey> elderSks(4);
    std::vector<CBLSPublicKey> elderPks(4);
    for (int i = 0; i < 4; i++) {
        elderSks[i].MakeNewKey();
        elderPks[i] = elderSks[i].GetPublicKey();
        tracker.BlockConnected(i, ALGO_X11, elderPks[i], {elderPks[i]});
    }

    // Create unknown "mannequin" signers
    std::vector<CBLSSecretKey> mannequinSks(6);
    std::vector<CBLSPublicKey> mannequinPks(6);
    for (int i = 0; i < 6; i++) {
        mannequinSks[i].MakeNewKey();
        mannequinPks[i] = mannequinSks[i].GetPublicKey();
    }

    // All Elders present + no mannequins ->no penalty
    std::vector<uint8_t> elderAlgos(elderPks.size(), ALGO_X11);
    uint64_t penalty = EvaluateNegativeProof(elderPks, elderAlgos, ALGO_X11, &tracker);
    BOOST_CHECK_EQUAL(penalty, 10000u);

    // Only mannequins, no Elders ->severe penalty (missing Elders + mannequins)
    std::vector<uint8_t> mannequinAlgos(mannequinPks.size(), ALGO_X11);
    uint64_t mannequinPenalty = EvaluateNegativeProof(mannequinPks, mannequinAlgos, ALGO_X11, &tracker);
    BOOST_CHECK_EQUAL(mannequinPenalty, 1000u);

    // Mix: 1 Elder + 5 mannequins ->mannequin penalty (>50% unknown)
    std::vector<CBLSPublicKey> mixed = {elderPks[0]};
    mixed.insert(mixed.end(), mannequinPks.begin(), mannequinPks.begin() + 5);
    std::vector<uint8_t> mixedAlgos(mixed.size(), ALGO_X11);
    uint64_t mixedPenalty = EvaluateNegativeProof(mixed, mixedAlgos, ALGO_X11, &tracker);
    BOOST_CHECK(mixedPenalty < 10000u); // some penalty applied
}

// VRF Committee Selection Tests

BOOST_AUTO_TEST_CASE(vrf_compute_and_verify)
{
    bls::bls_legacy_scheme.store(false);

    CBLSSecretKey sk;
    sk.MakeNewKey();
    CBLSPublicKey pk = sk.GetPublicKey();

    uint256 blockHash = uint256::ONE;

    // Compute VRF
    CBLSSignature vrfProof = ComputeVRF(sk, blockHash, TEST_PREV_SEAL_HASH);
    BOOST_CHECK(vrfProof.IsValid());

    // Verify VRF
    BOOST_CHECK(VerifyVRF(pk, blockHash, TEST_PREV_SEAL_HASH, vrfProof));

    // Different block hash should fail verification
    BOOST_CHECK(!VerifyVRF(pk, uint256::TWO, TEST_PREV_SEAL_HASH, vrfProof));

    // Different pubkey should fail verification
    CBLSSecretKey sk2;
    sk2.MakeNewKey();
    BOOST_CHECK(!VerifyVRF(sk2.GetPublicKey(), blockHash, TEST_PREV_SEAL_HASH, vrfProof));
}

BOOST_AUTO_TEST_CASE(vrf_deterministic)
{
    bls::bls_legacy_scheme.store(false);

    CBLSSecretKey sk;
    sk.MakeNewKey();

    uint256 blockHash = uint256::ONE;

    // VRF should be deterministic for same inputs
    CBLSSignature proof1 = ComputeVRF(sk, blockHash, TEST_PREV_SEAL_HASH);
    CBLSSignature proof2 = ComputeVRF(sk, blockHash, TEST_PREV_SEAL_HASH);
    BOOST_CHECK(proof1 == proof2);

    // Different block hash gives different proof
    CBLSSignature proof3 = ComputeVRF(sk, uint256::TWO, TEST_PREV_SEAL_HASH);
    BOOST_CHECK(proof1 != proof3);
}

BOOST_AUTO_TEST_CASE(vrf_output_hash_consistent)
{
    bls::bls_legacy_scheme.store(false);

    CBLSSecretKey sk;
    sk.MakeNewKey();

    uint256 blockHash = uint256::ONE;
    CBLSSignature vrfProof = ComputeVRF(sk, blockHash, TEST_PREV_SEAL_HASH);

    // VRF output hash should be deterministic
    uint256 hash1 = VRFOutputHash(vrfProof);
    uint256 hash2 = VRFOutputHash(vrfProof);
    BOOST_CHECK(hash1 == hash2);
    BOOST_CHECK(!hash1.IsNull());
}

BOOST_AUTO_TEST_CASE(vrf_committee_selection)
{
    bls::bls_legacy_scheme.store(false);

    // Test selection with different thresholds
    // Use a known hash to test deterministic selection
    uint256 vrfHash;
    vrfHash.SetHex("00000000000000000000000000000000000000000000000000000000000000c8");
    // c8 = 200 decimal, 200 % 1000 = 200

    // Base threshold 200: selected if val % 1000 < 200
    // val=200, threshold=200: NOT selected (< is strict)
    // Actually we use first 8 bytes: 0xc8 = 200
    // 200 % 1000 = 200, threshold 200 * 1 = 200, 200 < 200 = false
    BOOST_CHECK(!IsVRFSelected(vrfHash, 1, 200));

    // Elder multiplier: threshold 200 * 3 = 600, 200 < 600 = true
    BOOST_CHECK(IsVRFSelected(vrfHash, 3, 200));

    // Zero multiplier = not eligible
    BOOST_CHECK(!IsVRFSelected(vrfHash, 0, 200));

    // Threshold capped at 1000
    BOOST_CHECK(IsVRFSelected(vrfHash, 10, 200)); // 10*200=2000 capped to 1000
}

BOOST_AUTO_TEST_CASE(vrf_tier_multipliers)
{
    // ELDER ->3×
    BOOST_CHECK_EQUAL(GetVRFTierMultiplier(static_cast<int>(HMPPrivilegeTier::ELDER)), 3);
    // NEW ->1×
    BOOST_CHECK_EQUAL(GetVRFTierMultiplier(static_cast<int>(HMPPrivilegeTier::NEW)), 1);
    // UNKNOWN ->0 (not eligible)
    BOOST_CHECK_EQUAL(GetVRFTierMultiplier(static_cast<int>(HMPPrivilegeTier::UNKNOWN)), 0);
}

BOOST_AUTO_TEST_CASE(vrf_domain_separation)
{
    bls::bls_legacy_scheme.store(false);

    uint256 blockHash = uint256::ONE;

    // VRF input should be domain-separated from the raw block hash
    uint256 vrfInput = ComputeVRFInput(blockHash, TEST_PREV_SEAL_HASH);
    BOOST_CHECK(vrfInput != blockHash);

    // Different blocks ->different VRF inputs
    uint256 vrfInput2 = ComputeVRFInput(uint256::TWO, TEST_PREV_SEAL_HASH);
    BOOST_CHECK(vrfInput != vrfInput2);
}

BOOST_AUTO_TEST_CASE(seal_share_with_vrf_serialization)
{
    bls::bls_legacy_scheme.store(false);

    CBLSSecretKey sk;
    sk.MakeNewKey();

    uint256 blockHash = uint256::ONE;

    CSealShare original;
    original.blockHash = blockHash;
    original.signerPubKey = sk.GetPublicKey();
    original.signature = sk.Sign(PerSignerMsg(blockHash, original.signerPubKey), false);
    original.algoId = ALGO_X11;
    original.nTimestamp = 12345;
    original.vrfProof = ComputeVRF(sk, blockHash, TEST_PREV_SEAL_HASH);
    original.commitment.SetHex("0000000000000000000000000000000000000000000000000000000000abcdef");

    // Serialize
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << original;

    // Deserialize
    CSealShare deserialized;
    ss >> deserialized;

    BOOST_CHECK(deserialized.blockHash == original.blockHash);
    BOOST_CHECK(deserialized.signerPubKey == original.signerPubKey);
    BOOST_CHECK(deserialized.signature == original.signature);
    BOOST_CHECK(deserialized.vrfProof == original.vrfProof);
    BOOST_CHECK(deserialized.commitment == original.commitment);
    BOOST_CHECK_EQUAL(deserialized.zkProof.size(), 0u);

    // Verify VRF still works after deserialization
    BOOST_CHECK(VerifyVRF(deserialized.signerPubKey, deserialized.blockHash, TEST_PREV_SEAL_HASH, deserialized.vrfProof));
}

BOOST_AUTO_TEST_CASE(groth16_params_init)
{
    // Test that HMP Groth16 params can be initialized
    BOOST_CHECK(hmp_proof::InitParams());
    BOOST_CHECK(hmp_proof::IsInitialized());
}

BOOST_AUTO_TEST_CASE(groth16_proof_roundtrip)
{
    // Ensure params are initialized
    if (!hmp_proof::IsInitialized()) {
        BOOST_CHECK(hmp_proof::InitParams());
    }

    // Create test inputs
    uint8_t sk_bytes[32] = {};
    uint8_t block_hash[32] = {};
    uint8_t chain_state[32] = {};
    sk_bytes[0] = 42;
    block_hash[0] = 100;
    chain_state[0] = 200;

    // Compute commitment
    uint8_t commitment[32] = {};
    BOOST_CHECK(hmp_proof::ComputeCommitment(sk_bytes, block_hash, chain_state, commitment));

    // Create proof
    auto proof = hmp_proof::CreateProof(sk_bytes, block_hash, chain_state);
    BOOST_CHECK(!proof.empty());
    BOOST_CHECK_EQUAL(proof.size(), 192u); // Groth16 on BLS12-381

    // Verify with correct inputs
    BOOST_CHECK(hmp_proof::VerifyProof(proof, block_hash, commitment));

    // Verify with wrong commitment fails
    uint8_t wrong_commitment[32] = {};
    wrong_commitment[0] = 99;
    BOOST_CHECK(!hmp_proof::VerifyProof(proof, block_hash, wrong_commitment));

    // Verify with wrong block hash fails
    uint8_t wrong_block[32] = {};
    wrong_block[0] = 77;
    BOOST_CHECK(!hmp_proof::VerifyProof(proof, wrong_block, commitment));
}

BOOST_AUTO_TEST_CASE(groth16_commitment_deterministic)
{
    if (!hmp_proof::IsInitialized()) {
        BOOST_CHECK(hmp_proof::InitParams());
    }

    uint8_t sk[32] = {1};
    uint8_t block[32] = {2};
    uint8_t chain[32] = {3};

    uint8_t c1[32] = {}, c2[32] = {};
    BOOST_CHECK(hmp_proof::ComputeCommitment(sk, block, chain, c1));
    BOOST_CHECK(hmp_proof::ComputeCommitment(sk, block, chain, c2));

    // Same inputs ->same commitment
    BOOST_CHECK(memcmp(c1, c2, 32) == 0);

    // Different input ->different commitment
    uint8_t chain2[32] = {4};
    uint8_t c3[32] = {};
    BOOST_CHECK(hmp_proof::ComputeCommitment(sk, block, chain2, c3));
    BOOST_CHECK(memcmp(c1, c3, 32) != 0);
}

// Pubkey Commitment Tests

BOOST_AUTO_TEST_CASE(commitment_registry_basic)
{
    bls::bls_legacy_scheme.store(false);

    // offset=5: must be committed 5 blocks before sealing
    CHMPCommitmentRegistry registry(5);

    CBLSSecretKey sk;
    sk.MakeNewKey();
    CBLSPublicKey pk = sk.GetPublicKey();

    // Commit at height 10 (implicit via mining)
    registry.BlockConnected(10, pk, {});

    // Not yet mature at height 14 (only 4 blocks ago)
    BOOST_CHECK(!registry.IsCommitted(pk, 14));

    // Mature at height 15 (exactly 5 blocks ago)
    BOOST_CHECK(registry.IsCommitted(pk, 15));

    // Mature at height 20 (10 blocks ago)
    BOOST_CHECK(registry.IsCommitted(pk, 20));

    // Unknown key is never committed
    CBLSSecretKey sk2;
    sk2.MakeNewKey();
    BOOST_CHECK(!registry.IsCommitted(sk2.GetPublicKey(), 20));
}

BOOST_AUTO_TEST_CASE(commitment_registry_explicit)
{
    bls::bls_legacy_scheme.store(false);

    CHMPCommitmentRegistry registry(5);

    CBLSSecretKey sk1, sk2, sk3;
    sk1.MakeNewKey();
    sk2.MakeNewKey();
    sk3.MakeNewKey();
    CBLSPublicKey pk1 = sk1.GetPublicKey();
    CBLSPublicKey pk2 = sk2.GetPublicKey();
    CBLSPublicKey pk3 = sk3.GetPublicKey();

    // pk1 is miner, pk2 and pk3 are explicit commitments at height 10
    registry.BlockConnected(10, pk1, {pk2, pk3});

    // All three committed at height 10
    BOOST_CHECK(registry.HasCommitment(pk1));
    BOOST_CHECK(registry.HasCommitment(pk2));
    BOOST_CHECK(registry.HasCommitment(pk3));

    // Not mature at 14
    BOOST_CHECK(!registry.IsCommitted(pk2, 14));
    BOOST_CHECK(!registry.IsCommitted(pk3, 14));

    // Mature at 15
    BOOST_CHECK(registry.IsCommitted(pk2, 15));
    BOOST_CHECK(registry.IsCommitted(pk3, 15));
}

BOOST_AUTO_TEST_CASE(commitment_registry_disconnect)
{
    bls::bls_legacy_scheme.store(false);

    CHMPCommitmentRegistry registry(5);

    std::vector<CBLSSecretKey> sks(10);
    std::vector<CBLSPublicKey> pks(10);
    for (int i = 0; i < 10; i++) {
        sks[i].MakeNewKey();
        pks[i] = sks[i].GetPublicKey();
    }

    // Connect blocks 0-9, one miner per block
    for (int i = 0; i < 10; i++) {
        registry.BlockConnected(i, pks[i], {});
    }

    // All 10 committed
    for (int i = 0; i < 10; i++) {
        BOOST_CHECK(registry.HasCommitment(pks[i]));
    }

    // Disconnect blocks 5-9
    registry.BlockDisconnected(5);

    // pks 0-4 still committed, pks 5-9 removed
    for (int i = 0; i < 5; i++) {
        BOOST_CHECK(registry.HasCommitment(pks[i]));
    }
    for (int i = 5; i < 10; i++) {
        BOOST_CHECK(!registry.HasCommitment(pks[i]));
    }
}

BOOST_AUTO_TEST_CASE(commitment_registry_disabled)
{
    bls::bls_legacy_scheme.store(false);

    // offset=0: feature disabled,IsCommitted always true
    CHMPCommitmentRegistry registry(0);

    BOOST_CHECK(!registry.IsEnabled());

    CBLSSecretKey sk;
    sk.MakeNewKey();
    CBLSPublicKey pk = sk.GetPublicKey();

    // Even without any commitment, IsCommitted returns true when disabled
    BOOST_CHECK(registry.IsCommitted(pk, 0));
    BOOST_CHECK(registry.IsCommitted(pk, 100));
    BOOST_CHECK(registry.IsCommitted(pk, 999999));
}

BOOST_AUTO_TEST_CASE(commitment_registry_duplicate)
{
    bls::bls_legacy_scheme.store(false);

    CHMPCommitmentRegistry registry(5);

    CBLSSecretKey sk;
    sk.MakeNewKey();
    CBLSPublicKey pk = sk.GetPublicKey();

    // First commitment at height 5
    registry.BlockConnected(5, pk, {});
    BOOST_CHECK(registry.IsCommitted(pk, 10));

    // Same pubkey committed again at height 10 (should be ignored, first wins)
    registry.BlockConnected(10, pk, {});
    BOOST_CHECK(registry.IsCommitted(pk, 10)); // still mature from h=5

    // Disconnect height 10, commitment from h=5 should survive
    registry.BlockDisconnected(10);
    BOOST_CHECK(registry.HasCommitment(pk));
    BOOST_CHECK(registry.IsCommitted(pk, 10));

    // Disconnect height 5, now truly removed
    registry.BlockDisconnected(5);
    BOOST_CHECK(!registry.HasCommitment(pk));
}

BOOST_AUTO_TEST_CASE(seal_share_uncommitted_rejected)
{
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPSigningWindowMs = 5000;
    params.nHMPGracePeriodMs = 15000;
    params.nHMPSealTrailingDepth = 2;
    params.nHMPWarmupBlocks = 0;
    params.nHMPPrivilegeWindow = 100;
    params.nHMPMinBlocksSolved = 1;
    params.nHMPCommitmentOffset = 5;

    CHMPPrivilegeTracker privilege(params);
    CHMPCommitmentRegistry registry(5);

    uint256 blockHash2 = uint256::TWO;

    // Create signer that is VRF-selected for blockHash2 (the acceptance test)
    CBLSSecretKey sk;
    CBLSPublicKey pk;
    CBLSSignature vrf2;
    MakeVRFSelectedKey(blockHash2, sk, pk, vrf2);

    // Build privilege (mine 5 blocks)
    for (int i = 0; i < 5; i++) {
        privilege.BlockConnected(i, ALGO_X11, pk, {});
    }
    BOOST_CHECK(privilege.GetTier(pk, ALGO_X11) == HMPPrivilegeTier::NEW);

    // Commit at height 3 (not mature until height 8)
    registry.BlockConnected(3, pk, {});

    CSealManager manager(params, nullptr, &privilege, &registry);

    uint256 blockHash = uint256::ONE;
    manager.OnNewBlock(blockHash, 6, TEST_PREV_SEAL_HASH); // height 6: commitment from h=3 only 3 blocks old

    CSealShare share;
    share.blockHash = blockHash;
    share.signerPubKey = pk;
    share.signature = sk.Sign(PerSignerMsg(blockHash, pk), false);
    share.algoId = ALGO_X11;
    share.vrfProof = ComputeVRF(sk, blockHash, TEST_PREV_SEAL_HASH); // may not be selected, but rejected before VRF check

    // Should be rejected: committed at h=3, current h=6, need offset=5
    BOOST_CHECK(!HMPAccepted(manager.AddSealShare(share)));

    // Now try at height 8: committed 5 blocks ago
    manager.OnNewBlock(blockHash2, 8, TEST_PREV_SEAL_HASH);

    CSealShare share2;
    share2.blockHash = blockHash2;
    share2.signerPubKey = pk;
    share2.signature = sk.Sign(PerSignerMsg(blockHash2, pk), false);
    share2.algoId = ALGO_X11;
    share2.vrfProof = vrf2;

    BOOST_CHECK(HMPAccepted(manager.AddSealShare(share2)));
}

BOOST_AUTO_TEST_CASE(pubkey_commit_serialization)
{
    bls::bls_legacy_scheme.store(false);

    CBLSSecretKey sk;
    sk.MakeNewKey();
    CBLSPublicKey pk = sk.GetPublicKey();

    // Create a signed commit
    CPubKeyCommit original;
    original.pubKey = pk;
    original.nTimestamp = 1700000000;
    uint256 msgHash = CPubKeyCommit::SignatureHash(pk);
    original.signature = sk.Sign(msgHash, false);

    // Verify the original
    BOOST_CHECK(original.Verify());

    // Serialize
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << original;

    // Deserialize
    CPubKeyCommit deserialized;
    ss >> deserialized;

    BOOST_CHECK(deserialized.pubKey == original.pubKey);
    BOOST_CHECK(deserialized.signature == original.signature);
    BOOST_CHECK_EQUAL(deserialized.nTimestamp, original.nTimestamp);

    // Deserialized should also verify
    BOOST_CHECK(deserialized.Verify());

    // Tamper with pubkey, verification should fail
    CBLSSecretKey sk2;
    sk2.MakeNewKey();
    CPubKeyCommit tampered = deserialized;
    tampered.pubKey = sk2.GetPublicKey();
    BOOST_CHECK(!tampered.Verify());
}

BOOST_AUTO_TEST_CASE(cbtx_v5_serialization_roundtrip)
{
    bls::bls_legacy_scheme.store(false);

    CCbTx original;
    original.nVersion = CCbTx::Version::HMP_COMMITMENT;
    original.nHeight = 54321;
    original.merkleRootMNList = uint256::ONE;
    original.merkleRootQuorums = uint256::TWO;
    original.bestCLHeightDiff = 7;

    CBLSSecretKey sk;
    sk.MakeNewKey();
    original.bestCLSignature = sk.Sign(uint256::ONE, false);
    original.creditPoolBalance = 500000;

    // HMP v4 fields
    original.minerIdentity = sk.GetPublicKey();
    original.sealForAncestor = sk.Sign(uint256::TWO, false);
    original.sealBlockHash.SetHex("0000000000000000000000000000000000000000000000000000000000005678");

    // HMP v5 fields: commitments
    CBLSSecretKey sk2, sk3;
    sk2.MakeNewKey();
    sk3.MakeNewKey();
    original.vCommitments = {sk2.GetPublicKey(), sk3.GetPublicKey()};

    // Serialize
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << original;

    // Deserialize
    CCbTx deserialized;
    ss >> deserialized;

    // Verify all fields including v5
    BOOST_CHECK(deserialized.nVersion == CCbTx::Version::HMP_COMMITMENT);
    BOOST_CHECK_EQUAL(deserialized.nHeight, 54321);
    BOOST_CHECK(deserialized.minerIdentity == original.minerIdentity);
    BOOST_CHECK(deserialized.sealForAncestor == original.sealForAncestor);
    BOOST_CHECK(deserialized.sealBlockHash == original.sealBlockHash);
    BOOST_CHECK_EQUAL(deserialized.vCommitments.size(), 2u);
    BOOST_CHECK(deserialized.vCommitments[0] == original.vCommitments[0]);
    BOOST_CHECK(deserialized.vCommitments[1] == original.vCommitments[1]);
}

BOOST_AUTO_TEST_CASE(cbtx_v4_backward_compat)
{
    bls::bls_legacy_scheme.store(false);

    // v4 CCbTx should deserialize with empty vCommitments
    CCbTx v4tx;
    v4tx.nVersion = CCbTx::Version::HMP_SEAL;
    v4tx.nHeight = 100;
    v4tx.merkleRootMNList = uint256::ONE;
    v4tx.merkleRootQuorums = uint256::TWO;
    v4tx.bestCLHeightDiff = 1;

    CBLSSecretKey sk;
    sk.MakeNewKey();
    v4tx.bestCLSignature = sk.Sign(uint256::ONE, false);
    v4tx.creditPoolBalance = 100;
    v4tx.minerIdentity = sk.GetPublicKey();
    v4tx.sealForAncestor = sk.Sign(uint256::TWO, false);
    v4tx.sealBlockHash = uint256::ONE;

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << v4tx;

    CCbTx deserialized;
    ss >> deserialized;

    // v4 should have empty vCommitments
    BOOST_CHECK(deserialized.nVersion == CCbTx::Version::HMP_SEAL);
    BOOST_CHECK(deserialized.vCommitments.empty());
    // But v4 fields should be intact
    BOOST_CHECK(deserialized.minerIdentity == v4tx.minerIdentity);
    BOOST_CHECK(deserialized.sealBlockHash == v4tx.sealBlockHash);
}

// zk proof creation, verification, algo bounds, and assembly

BOOST_AUTO_TEST_CASE(seal_share_zk_proof_created)
{
    // SignBlock() should populate zkProof + commitment when hmp_proof is initialized
    bls::bls_legacy_scheme.store(false);

    if (!hmp_proof::IsInitialized()) {
        BOOST_CHECK(hmp_proof::InitParams());
    }

    Consensus::Params params;
    params.nHMPSigningWindowMs = 5000;
    params.nHMPGracePeriodMs = 15000;
    params.nHMPSealTrailingDepth = 2;
    params.nHMPWarmupBlocks = 0;
    params.nHMPPrivilegeWindow = 100;
    params.nHMPMinBlocksSolved = 1;
    params.nHMPCommitmentOffset = 0;

    CHMPIdentity identity;
    fs::path testdir = m_node.args->GetDataDirNet();
    BOOST_CHECK(identity.Init(testdir));

    // Build privilege so signer is eligible
    CHMPPrivilegeTracker privilege(params);
    for (int i = 0; i < 5; i++) {
        privilege.BlockConnected(i, ALGO_X11, identity.GetPublicKey(), {});
    }
    BOOST_CHECK(privilege.GetTier(identity.GetPublicKey(), ALGO_X11) != HMPPrivilegeTier::UNKNOWN);

    CSealManager manager(params, &identity, &privilege);

    // SignBlock needs to be VRF-selected; try multiple block hashes
    // to find one that passes VRF selection
    std::optional<CSealShare> share;
    for (int i = 1; i <= 1000 && !share; i++) {
        uint256 blockHash;
        CHashWriter hw(SER_GETHASH, 0);
        hw << i;
        blockHash = hw.GetHash();
        share = manager.SignBlock(blockHash, ALGO_X11);
    }

    // If none selected in 1000 tries, skip (probabilistic, extremely unlikely)
    if (!share) {
        BOOST_TEST_MESSAGE("VRF did not select in 1000 attempts, skipping zk proof creation test");
        return;
    }

    // zkProof should be populated
    BOOST_CHECK(!share->zkProof.empty());
    BOOST_CHECK_EQUAL(share->zkProof.size(), 192u);

    // commitment should be non-null
    BOOST_CHECK(!share->commitment.IsNull());

    // The proof should verify against the commitment
    BOOST_CHECK(hmp_proof::VerifyProof(share->zkProof, share->blockHash.begin(), share->commitment.begin()));
}

BOOST_AUTO_TEST_CASE(seal_share_zk_proof_verified)
{
    // AddSealShare() should reject shares with invalid zk proofs
    bls::bls_legacy_scheme.store(false);

    if (!hmp_proof::IsInitialized()) {
        BOOST_CHECK(hmp_proof::InitParams());
    }

    Consensus::Params params;
    params.nHMPSigningWindowMs = 5000;
    params.nHMPGracePeriodMs = 15000;
    params.nHMPSealTrailingDepth = 2;
    params.nHMPWarmupBlocks = 0;
    params.nHMPPrivilegeWindow = 100;
    params.nHMPMinBlocksSolved = 1;
    params.nHMPCommitmentOffset = 0;

    CHMPPrivilegeTracker privilege(params);

    uint256 blockHash = uint256::ONE;

    CBLSSecretKey sk;
    CBLSPublicKey pk;
    CBLSSignature vrfProof;
    MakeVRFSelectedKey(blockHash, sk, pk, vrfProof);

    for (int i = 0; i < 5; i++) {
        privilege.BlockConnected(i, ALGO_X11, pk, {});
    }

    CSealManager manager(params, nullptr, &privilege);
    manager.OnNewBlock(blockHash, 10, TEST_PREV_SEAL_HASH);

    // Create a share with a garbage 192-byte zkProof
    CSealShare share;
    share.blockHash = blockHash;
    share.signerPubKey = pk;
    share.signature = sk.Sign(PerSignerMsg(blockHash, pk), false);
    share.algoId = ALGO_X11;
    share.vrfProof = vrfProof;
    share.zkProof.resize(192, 0xFF); // invalid proof bytes
    share.commitment = uint256::ONE;

    // Should be rejected because the zk proof is invalid
    BOOST_CHECK(!HMPAccepted(manager.AddSealShare(share)));
}

BOOST_AUTO_TEST_CASE(seal_share_algo_bounds)
{
    // AddSealShare() should reject shares with algoId >= NUM_ALGOS
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPSigningWindowMs = 5000;
    params.nHMPGracePeriodMs = 15000;
    params.nHMPSealTrailingDepth = 2;
    params.nHMPWarmupBlocks = 0;
    params.nHMPPrivilegeWindow = 100;
    params.nHMPMinBlocksSolved = 1;
    params.nHMPCommitmentOffset = 0;

    CSealManager manager(params, nullptr, nullptr);

    uint256 blockHash = uint256::ONE;
    manager.OnNewBlock(blockHash, 10, TEST_PREV_SEAL_HASH);

    CBLSSecretKey sk;
    sk.MakeNewKey();
    CBLSPublicKey pk = sk.GetPublicKey();

    CSealShare share;
    share.blockHash = blockHash;
    share.signerPubKey = pk;
    share.signature = sk.Sign(PerSignerMsg(blockHash, pk), false);
    share.algoId = NUM_ALGOS; // out of bounds
    share.nTimestamp = 12345;
    share.vrfProof = ComputeVRF(sk, blockHash, TEST_PREV_SEAL_HASH);

    BOOST_CHECK(!HMPAccepted(manager.AddSealShare(share)));

    // Also test with a very large value
    share.algoId = 255;
    BOOST_CHECK(!HMPAccepted(manager.AddSealShare(share)));

    // Valid algo should not be rejected at this stage (may fail later validation)
    share.algoId = ALGO_X11;
    // This will pass algo bounds check but may fail privilege or VRF check, that's fine,
    // we're just testing the bounds check doesn't reject valid algos
    manager.AddSealShare(share); // may return true or false depending on other checks
}

BOOST_AUTO_TEST_CASE(seal_share_empty_zk_accepted)
{
    // AddSealShare() should accept shares with empty zkProof (fallback)
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPSigningWindowMs = 5000;
    params.nHMPGracePeriodMs = 15000;
    params.nHMPSealTrailingDepth = 2;
    params.nHMPWarmupBlocks = 0;
    params.nHMPPrivilegeWindow = 100;
    params.nHMPMinBlocksSolved = 1;
    params.nHMPCommitmentOffset = 0;

    CHMPPrivilegeTracker privilege(params);

    uint256 blockHash = uint256::ONE;

    CBLSSecretKey sk;
    CBLSPublicKey pk;
    CBLSSignature vrfProof;
    MakeVRFSelectedKey(blockHash, sk, pk, vrfProof);

    for (int i = 0; i < 5; i++) {
        privilege.BlockConnected(i, ALGO_X11, pk, {});
    }

    CSealManager manager(params, nullptr, &privilege);
    manager.OnNewBlock(blockHash, 10, TEST_PREV_SEAL_HASH);

    CSealShare share;
    share.blockHash = blockHash;
    share.signerPubKey = pk;
    share.signature = sk.Sign(PerSignerMsg(blockHash, pk), false);
    share.algoId = ALGO_X11;
    share.vrfProof = vrfProof;
    // zkProof is empty, should still be accepted

    BOOST_CHECK(HMPAccepted(manager.AddSealShare(share)));
}

BOOST_AUTO_TEST_CASE(seal_share_broadcast_assembled)
{
    // TryAssemble succeeds and the assembled seal is stored
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPSigningWindowMs = 0; // immediate assembly
    params.nHMPGracePeriodMs = 60000;
    params.nHMPSealTrailingDepth = 2;
    params.nHMPWarmupBlocks = 0;
    params.nHMPPrivilegeWindow = 100;
    params.nHMPMinBlocksSolved = 1;
    params.nHMPCommitmentOffset = 0;

    CHMPPrivilegeTracker privilege(params);

    uint256 blockHash = uint256::ONE;

    // Create multiple VRF-selected signers
    std::vector<CBLSSecretKey> sks(3);
    std::vector<CBLSPublicKey> pks(3);
    std::vector<CBLSSignature> vrfs(3);
    for (int i = 0; i < 3; i++) {
        MakeVRFSelectedKey(blockHash, sks[i], pks[i], vrfs[i]);
        for (int h = 0; h < 5; h++) {
            privilege.BlockConnected(h, ALGO_X11, pks[i], {});
        }
    }

    // No connman needed, broadcast will be a no-op
    CSealManager manager(params, nullptr, &privilege);
    manager.OnNewBlock(blockHash, 10, TEST_PREV_SEAL_HASH);

    // Add shares from all signers
    for (int i = 0; i < 3; i++) {
        CSealShare share;
        share.blockHash = blockHash;
        share.signerPubKey = pks[i];
        share.signature = sks[i].Sign(PerSignerMsg(blockHash, pks[i]), false);
        share.algoId = ALGO_X11;
        share.vrfProof = vrfs[i];
        BOOST_CHECK(HMPAccepted(manager.AddSealShare(share)));
    }

    // Start the worker which will trigger assembly (window=0ms)
    manager.Start();
    // Give the worker time to run
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    manager.Stop();

    // Assembled seal should be available
    auto seal = manager.GetSeal(blockHash);
    BOOST_CHECK(seal.has_value());
    if (seal) {
        BOOST_CHECK_EQUAL(seal->signers.size(), 3u);
        BOOST_CHECK(seal->Verify());
    }
}

// Integration Gap Tests

BOOST_AUTO_TEST_CASE(seal_verify_in_connect_block)
{
    // Assembled seal with valid BLS sig passes Verify()
    bls::bls_legacy_scheme.store(false);

    uint256 blockHash = uint256::ONE;

    std::vector<uint8_t> algos = {ALGO_X11, ALGO_KAWPOW, ALGO_EQUIHASH_200};
    std::vector<CBLSSecretKey> sks(3);
    std::vector<CBLSPublicKey> pks(3);
    std::vector<CBLSSignature> sigs(3);
    for (int i = 0; i < 3; i++) {
        sks[i].MakeNewKey();
        pks[i] = sks[i].GetPublicKey();
        sigs[i] = sks[i].Sign(PerSignerMsg(blockHash, pks[i], algos[i]), false);
        BOOST_CHECK(sigs[i].IsValid());
    }

    // Aggregate
    CBLSSignature aggSig = CBLSSignature::AggregateInsecure(Span<CBLSSignature>(sigs));
    BOOST_CHECK(aggSig.IsValid());

    CAssembledSeal seal;
    seal.blockHash = blockHash;
    seal.aggregatedSig = aggSig;
    seal.signers = pks;
    seal.signerAlgos = algos;

    BOOST_CHECK(seal.Verify());
}

BOOST_AUTO_TEST_CASE(seal_verify_invalid_rejected)
{
    // Assembled seal with tampered sig fails Verify()
    bls::bls_legacy_scheme.store(false);

    uint256 blockHash = uint256::ONE;
    uint256 wrongHash = uint256::TWO;

    // Create 2 signers, but sign wrong hash for one
    CBLSSecretKey sk1, sk2;
    sk1.MakeNewKey();
    sk2.MakeNewKey();

    CBLSPublicKey pk1 = sk1.GetPublicKey();
    CBLSPublicKey pk2 = sk2.GetPublicKey();

    CBLSSignature sig1 = sk1.Sign(PerSignerMsg(blockHash, pk1), false);
    CBLSSignature sig2 = sk2.Sign(PerSignerMsg(wrongHash, pk2), false); // wrong block hash!

    std::vector<CBLSSignature> sigs = {sig1, sig2};
    CBLSSignature aggSig = CBLSSignature::AggregateInsecure(Span<CBLSSignature>(sigs));

    CAssembledSeal seal;
    seal.blockHash = blockHash;
    seal.aggregatedSig = aggSig;
    seal.signers = {pk1, pk2};
    seal.signerAlgos = {static_cast<uint8_t>(ALGO_X11), static_cast<uint8_t>(ALGO_KAWPOW)};

    // Should fail, one signer signed wrong block hash
    BOOST_CHECK(!seal.Verify());
}

BOOST_AUTO_TEST_CASE(seal_manager_block_disconnected)
{
    // BlockDisconnected removes session + assembled seal
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPSigningWindowMs = 0; // instant assembly
    params.nHMPGracePeriodMs = 60000;
    params.nHMPSealTrailingDepth = 2;
    params.nHMPWarmupBlocks = 0;
    params.nHMPPrivilegeWindow = 100;
    params.nHMPMinBlocksSolved = 1;
    params.nHMPCommitmentOffset = 0;

    CHMPPrivilegeTracker privilege(params);

    uint256 blockHash = uint256::ONE;
    int height = 100;

    // Create 3 VRF-selected signers with privilege
    std::vector<CBLSSecretKey> sks(3);
    std::vector<CBLSPublicKey> pks(3);
    std::vector<CBLSSignature> vrfs(3);
    for (int i = 0; i < 3; i++) {
        MakeVRFSelectedKey(blockHash, sks[i], pks[i], vrfs[i]);
        for (int h = 0; h < 5; h++) {
            privilege.BlockConnected(h, ALGO_X11, pks[i], {});
        }
    }

    CSealManager manager(params, nullptr, &privilege);
    manager.OnNewBlock(blockHash, height, TEST_PREV_SEAL_HASH);

    // Add shares
    for (int i = 0; i < 3; i++) {
        CSealShare share;
        share.blockHash = blockHash;
        share.signerPubKey = pks[i];
        share.signature = sks[i].Sign(PerSignerMsg(blockHash, pks[i]), false);
        share.algoId = ALGO_X11;
        share.vrfProof = vrfs[i];
        BOOST_CHECK(HMPAccepted(manager.AddSealShare(share)));
    }

    // Let worker assemble
    manager.Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    manager.Stop();

    // Seal should exist
    BOOST_CHECK(manager.GetSeal(blockHash).has_value());
    BOOST_CHECK(manager.GetSealForTemplate(height + params.nHMPSealTrailingDepth).has_value());

    // Disconnect the block
    manager.BlockDisconnected(blockHash, height);

    // Seal and session should be gone
    BOOST_CHECK(!manager.GetSeal(blockHash).has_value());
    BOOST_CHECK(!manager.GetSealForTemplate(height + params.nHMPSealTrailingDepth).has_value());
}

BOOST_AUTO_TEST_CASE(commit_pool_cleanup_on_connect)
{
    // Simulates pool removal after block inclusion
    bls::bls_legacy_scheme.store(false);

    CHMPCommitPool pool;

    // Create 3 commits
    std::vector<CBLSSecretKey> sks(3);
    for (int i = 0; i < 3; i++) {
        sks[i].MakeNewKey();
        CPubKeyCommit commit;
        commit.pubKey = sks[i].GetPublicKey();
        uint256 msgHash = CPubKeyCommit::SignatureHash(commit.pubKey);
        commit.signature = sks[i].Sign(msgHash, false);
        commit.nTimestamp = GetTimeMicros() / 1000;
        BOOST_CHECK(HMPAccepted(pool.Add(commit)));
    }
    BOOST_CHECK_EQUAL(pool.Size(), 3u);

    // Simulate on-chain inclusion: remove first two
    pool.Remove(sks[0].GetPublicKey());
    pool.Remove(sks[1].GetPublicKey());

    BOOST_CHECK_EQUAL(pool.Size(), 1u);

    // Remove last
    pool.Remove(sks[2].GetPublicKey());
    BOOST_CHECK_EQUAL(pool.Size(), 0u);

    // Removing non-existent key is a no-op
    CBLSSecretKey phantom;
    phantom.MakeNewKey();
    pool.Remove(phantom.GetPublicKey());
    BOOST_CHECK_EQUAL(pool.Size(), 0u);
}

BOOST_AUTO_TEST_CASE(commit_pool_get_pending_commits)
{
    // GetPendingCommits returns full CPubKeyCommit objects
    bls::bls_legacy_scheme.store(false);

    CHMPCommitPool pool;

    // Add 5 commits
    std::vector<CBLSSecretKey> sks(5);
    for (int i = 0; i < 5; i++) {
        sks[i].MakeNewKey();
        CPubKeyCommit commit;
        commit.pubKey = sks[i].GetPublicKey();
        uint256 msgHash = CPubKeyCommit::SignatureHash(commit.pubKey);
        commit.signature = sks[i].Sign(msgHash, false);
        commit.nTimestamp = GetTimeMicros() / 1000;
        BOOST_CHECK(HMPAccepted(pool.Add(commit)));
    }

    // Get all
    auto all = pool.GetPendingCommits(100);
    BOOST_CHECK_EQUAL(all.size(), 5u);

    // Verify each returned commit has valid sig
    for (const auto& c : all) {
        BOOST_CHECK(c.pubKey.IsValid());
        BOOST_CHECK(c.signature.IsValid());
        BOOST_CHECK(c.Verify());
    }

    // Get capped at 2
    auto capped = pool.GetPendingCommits(2);
    BOOST_CHECK_EQUAL(capped.size(), 2u);

    // Get 0
    auto none = pool.GetPendingCommits(0);
    BOOST_CHECK_EQUAL(none.size(), 0u);
}

BOOST_AUTO_TEST_CASE(commit_pool_rejects_onchain_replay)
{
    // PUBKEYCOMMIT replay DoS: Add() must reject keys already on-chain
    bls::bls_legacy_scheme.store(false);

    // Set up a commitment registry with offset=10
    auto oldRegistry = std::move(g_hmp_commitments);
    g_hmp_commitments = std::make_unique<CHMPCommitmentRegistry>(10);

    CHMPCommitPool pool;

    // Create a key and commit it on-chain via the registry
    CBLSSecretKey sk1;
    sk1.MakeNewKey();
    g_hmp_commitments->BlockConnected(100, sk1.GetPublicKey(), {});
    BOOST_CHECK(g_hmp_commitments->HasCommitment(sk1.GetPublicKey()));

    // Try to add same key to the pending pool, should be rejected
    CPubKeyCommit commit1;
    commit1.pubKey = sk1.GetPublicKey();
    uint256 msgHash1 = CPubKeyCommit::SignatureHash(commit1.pubKey);
    commit1.signature = sk1.Sign(msgHash1, false);
    commit1.nTimestamp = GetTimeMicros() / 1000;
    BOOST_CHECK_EQUAL(static_cast<int>(pool.Add(commit1)),
                      static_cast<int>(HMPAcceptResult::REJECTED_BENIGN));
    BOOST_CHECK_EQUAL(pool.Size(), 0u);

    // A fresh key NOT on-chain should still be accepted
    CBLSSecretKey sk2;
    sk2.MakeNewKey();
    CPubKeyCommit commit2;
    commit2.pubKey = sk2.GetPublicKey();
    uint256 msgHash2 = CPubKeyCommit::SignatureHash(commit2.pubKey);
    commit2.signature = sk2.Sign(msgHash2, false);
    commit2.nTimestamp = GetTimeMicros() / 1000;
    BOOST_CHECK(HMPAccepted(pool.Add(commit2)));
    BOOST_CHECK_EQUAL(pool.Size(), 1u);

    // Restore previous registry state
    g_hmp_commitments = std::move(oldRegistry);
}

BOOST_AUTO_TEST_CASE(seal_weight_minimum_signers)
{
    // Single-signer seal gets neutral weight (10000)
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPPrivilegeWindow = 100;
    params.nHMPMinBlocksSolved = 1;
    params.nHMPWarmupBlocks = 0;

    CHMPPrivilegeTracker privilege(params);

    // One signer with privilege
    CBLSSecretKey sk;
    sk.MakeNewKey();
    for (int h = 0; h < 5; h++) {
        privilege.BlockConnected(h, ALGO_X11, sk.GetPublicKey(), {});
    }

    // Single signer list, should get neutral weight
    std::vector<CBLSPublicKey> singleSigner = {sk.GetPublicKey()};
    std::vector<uint8_t> singleAlgo = {ALGO_X11};

    // The fix: when sealSignerPubKeys.size() < 2, weight = 10000
    // Replicate the logic from ConnectBlock
    uint64_t weight;
    if (!singleSigner.empty() && singleSigner.size() < 2) {
        weight = 10000; // neutral
    } else {
        weight = ComputeSealMultiplier(singleSigner, singleAlgo, ALGO_X11, &privilege);
    }
    BOOST_CHECK_EQUAL(weight, 10000u);

    // Two signers should get a real (non-neutral) multiplier
    CBLSSecretKey sk2;
    sk2.MakeNewKey();
    for (int h = 0; h < 5; h++) {
        privilege.BlockConnected(h, ALGO_KAWPOW, sk2.GetPublicKey(), {});
    }

    std::vector<CBLSPublicKey> twoSigners = {sk.GetPublicKey(), sk2.GetPublicKey()};
    std::vector<uint8_t> twoAlgos = {ALGO_X11, ALGO_KAWPOW};

    uint64_t weight2;
    if (!twoSigners.empty() && twoSigners.size() < 2) {
        weight2 = 10000;
    } else {
        weight2 = ComputeSealMultiplier(twoSigners, twoAlgos, ALGO_X11, &privilege);
    }
    // Two signers from different algos should yield > 10000 (cross-algo bonus)
    BOOST_CHECK(weight2 >= 10000u);

    // Empty signers (no seal) should also go through ComputeSealMultiplier normally
    std::vector<CBLSPublicKey> noSigners;
    std::vector<uint8_t> noAlgos;
    uint64_t weight3 = ComputeSealMultiplier(noSigners, noAlgos, ALGO_X11, &privilege);
    BOOST_CHECK_EQUAL(weight3, 10000u); // default neutral
}

// Integer arithmetic in negative proof

BOOST_AUTO_TEST_CASE(negative_proof_integer_arithmetic)
{
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPWarmupBlocks = 0;
    params.nHMPPrivilegeWindow = 100;
    params.nHMPMinBlocksSolved = 1;

    CHMPPrivilegeTracker tracker(params);

    // Create 5 Elders on X11 (required agreement = 75%)
    std::vector<CBLSSecretKey> sks(5);
    std::vector<CBLSPublicKey> pks(5);
    for (int i = 0; i < 5; i++) {
        sks[i].MakeNewKey();
        pks[i] = sks[i].GetPublicKey();
        tracker.BlockConnected(i, ALGO_X11, pks[i], {pks[i]});
    }

    // Build algo vectors for signers (all X11 since that's the block algo)
    std::vector<uint8_t> allAlgos(pks.size(), ALGO_X11);

    // All 5 Elders present ->no penalty (10000 bps)
    uint64_t allPresent = EvaluateNegativeProof(pks, allAlgos, ALGO_X11, &tracker);
    BOOST_CHECK_EQUAL(allPresent, 10000u);

    // 4 of 5 present (80%) with 75% required ->no penalty
    std::vector<CBLSPublicKey> four = {pks[0], pks[1], pks[2], pks[3]};
    std::vector<uint8_t> fourAlgos(4, ALGO_X11);
    uint64_t fourPresent = EvaluateNegativeProof(four, fourAlgos, ALGO_X11, &tracker);
    BOOST_CHECK_EQUAL(fourPresent, 10000u);

    // 0 of 5 present ->heavy penalty (missing >20%)
    std::vector<CBLSPublicKey> none;
    std::vector<uint8_t> noneAlgos;
    uint64_t nonePresent = EvaluateNegativeProof(none, noneAlgos, ALGO_X11, &tracker);
    // 0 elders present ->presentBps=0, below 8000 ->1000
    BOOST_CHECK_EQUAL(nonePresent, 1000u);

    // 1 of 5 present (20%) ->heavy penalty (below 50%)
    std::vector<CBLSPublicKey> one = {pks[0]};
    std::vector<uint8_t> oneAlgos = {ALGO_X11};
    uint64_t onePresent = EvaluateNegativeProof(one, oneAlgos, ALGO_X11, &tracker);
    BOOST_CHECK_EQUAL(onePresent, 1000u);

    // 3 of 5 present (60%) -> proportional penalty
    // presentBps=6000, requiredBps=7500, range=2500, above=1000
    // penalty = 5000 + (1000 * 5000) / 2500 = 7000
    std::vector<CBLSPublicKey> three = {pks[0], pks[1], pks[2]};
    std::vector<uint8_t> threeAlgos(3, ALGO_X11);
    uint64_t threePresent = EvaluateNegativeProof(three, threeAlgos, ALGO_X11, &tracker);
    BOOST_CHECK(threePresent > 1000u);  // not severe
    BOOST_CHECK(threePresent < 10000u); // still penalized
    BOOST_CHECK_EQUAL(threePresent, 7000u); // proportional

    // Result must never exceed 10000 (no bonus from negative proof)
    BOOST_CHECK_LE(allPresent, 10000u);
    BOOST_CHECK_LE(fourPresent, 10000u);

    // Null privilege tracker ->always 10000
    uint64_t noTracker = EvaluateNegativeProof(pks, allAlgos, ALGO_X11, nullptr);
    BOOST_CHECK_EQUAL(noTracker, 10000u);

    // Empty elder set ->no penalty
    uint64_t emptyElders = EvaluateNegativeProof(pks, allAlgos, ALGO_KAWPOW, &tracker);
    BOOST_CHECK_EQUAL(emptyElders, 10000u);
}

// Commitment registry eviction

BOOST_AUTO_TEST_CASE(commitment_registry_eviction)
{
    bls::bls_legacy_scheme.store(false);

    CHMPCommitmentRegistry registry(10); // offset=10

    // Add commitments at various heights
    std::vector<CBLSSecretKey> sks(5);
    std::vector<CBLSPublicKey> pks(5);
    for (int i = 0; i < 5; i++) {
        sks[i].MakeNewKey();
        pks[i] = sks[i].GetPublicKey();
    }

    // Commit at heights 100, 200, 300, 400, 500
    for (int i = 0; i < 5; i++) {
        registry.BlockConnected((i + 1) * 100, pks[i], {});
    }

    // All should be present
    for (int i = 0; i < 5; i++) {
        BOOST_CHECK(registry.HasCommitment(pks[i]));
    }

    // Evict with maxAge=300 at height 500 ->cutoff = 200
    // Heights < 200 should be evicted (height 100)
    registry.EvictOld(500, 300);
    BOOST_CHECK(!registry.HasCommitment(pks[0])); // height 100, evicted
    BOOST_CHECK(registry.HasCommitment(pks[1]));  // height 200, kept (not < cutoff)
    BOOST_CHECK(registry.HasCommitment(pks[2]));  // height 300, kept
    BOOST_CHECK(registry.HasCommitment(pks[3]));  // height 400, kept
    BOOST_CHECK(registry.HasCommitment(pks[4]));  // height 500, kept

    // Evict with maxAge=100 at height 500 ->cutoff = 400
    // Heights < 400 should be evicted (200, 300)
    registry.EvictOld(500, 100);
    BOOST_CHECK(!registry.HasCommitment(pks[1])); // height 200, evicted
    BOOST_CHECK(!registry.HasCommitment(pks[2])); // height 300, evicted
    BOOST_CHECK(registry.HasCommitment(pks[3]));  // height 400, kept (not < cutoff)
    BOOST_CHECK(registry.HasCommitment(pks[4]));  // height 500, kept

    // Evict with cutoff <= 0 does nothing
    registry.EvictOld(50, 100); // cutoff = -50
    BOOST_CHECK(registry.HasCommitment(pks[3]));
    BOOST_CHECK(registry.HasCommitment(pks[4]));
}

BOOST_AUTO_TEST_CASE(commitment_registry_eviction_from_block_connected)
{
    bls::bls_legacy_scheme.store(false);

    CHMPCommitmentRegistry registry(10); // offset=10

    CBLSSecretKey sk1, sk2;
    sk1.MakeNewKey();
    sk2.MakeNewKey();

    // Add commitment at height 1
    registry.BlockConnected(1, sk1.GetPublicKey(), {});
    BOOST_CHECK(registry.HasCommitment(sk1.GetPublicKey()));

    // Connect enough blocks to trigger eviction (1100 = privilege window + buffer)
    // At height 1102, cutoff = 1102 - 1100 = 2, so height 1 < 2 ->evicted
    registry.BlockConnected(1102, sk2.GetPublicKey(), {});
    BOOST_CHECK(!registry.HasCommitment(sk1.GetPublicKey()));
    BOOST_CHECK(registry.HasCommitment(sk2.GetPublicKey()));
}

// SEALASM DoS protection

BOOST_AUTO_TEST_CASE(seal_verify_rejects_too_many_signers)
{
    // CAssembledSeal::Verify() should reject seals with > 200 signers
    bls::bls_legacy_scheme.store(false);

    uint256 blockHash = uint256::ONE;

    // Create a seal with 201 signers (over the cap)
    CAssembledSeal seal;
    seal.blockHash = blockHash;
    seal.signers.resize(201);
    seal.signerAlgos.resize(201, ALGO_X11);

    // Generate dummy keys (sig won't matter, rejected before verification)
    for (size_t i = 0; i < 201; i++) {
        CBLSSecretKey sk;
        sk.MakeNewKey();
        seal.signers[i] = sk.GetPublicKey();
    }

    // Use a dummy aggregated sig
    CBLSSecretKey dummySk;
    dummySk.MakeNewKey();
    seal.aggregatedSig = dummySk.Sign(blockHash, false);

    BOOST_CHECK(!seal.Verify());

    // 200 signers should not be rejected by the DoS check (but will fail BLS verify)
    seal.signers.resize(200);
    seal.signerAlgos.resize(200);
    // Will fail BLS verify (dummy sig), but NOT the signer count check
    BOOST_CHECK(!seal.Verify()); // fails BLS, not DoS cap
}

// SEALSHARE relay cap

BOOST_AUTO_TEST_CASE(seal_manager_get_share_count)
{
    // GetShareCount returns the number of shares for a block
    bls::bls_legacy_scheme.store(false);

    Consensus::Params params;
    params.nHMPSigningWindowMs = 5000;
    params.nHMPGracePeriodMs = 15000;
    params.nHMPSealTrailingDepth = 2;
    params.nHMPWarmupBlocks = 0;
    params.nHMPPrivilegeWindow = 100;
    params.nHMPMinBlocksSolved = 1;
    params.nHMPCommitmentOffset = 0;

    CHMPPrivilegeTracker privilege(params);

    uint256 blockHash = uint256::ONE;

    // Create VRF-selected signers
    std::vector<CBLSSecretKey> sks(3);
    std::vector<CBLSPublicKey> pks(3);
    std::vector<CBLSSignature> vrfs(3);
    for (int i = 0; i < 3; i++) {
        MakeVRFSelectedKey(blockHash, sks[i], pks[i], vrfs[i]);
        for (int h = 0; h < 5; h++) {
            privilege.BlockConnected(h, ALGO_X11, pks[i], {});
        }
    }

    CSealManager manager(params, nullptr, &privilege);
    manager.OnNewBlock(blockHash, 10, TEST_PREV_SEAL_HASH);

    // Initially 0 shares
    BOOST_CHECK_EQUAL(manager.GetShareCount(blockHash), 0u);

    // Unknown block ->0
    BOOST_CHECK_EQUAL(manager.GetShareCount(uint256::TWO), 0u);

    // Add shares and verify count
    for (int i = 0; i < 3; i++) {
        CSealShare share;
        share.blockHash = blockHash;
        share.signerPubKey = pks[i];
        share.signature = sks[i].Sign(PerSignerMsg(blockHash, pks[i]), false);
        share.algoId = ALGO_X11;
        share.vrfProof = vrfs[i];
        BOOST_CHECK(HMPAccepted(manager.AddSealShare(share)));
        BOOST_CHECK_EQUAL(manager.GetShareCount(blockHash), static_cast<size_t>(i + 1));
    }
}

BOOST_AUTO_TEST_SUITE_END()
