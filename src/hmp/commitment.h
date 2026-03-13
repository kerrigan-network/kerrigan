// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KERRIGAN_HMP_COMMITMENT_H
#define KERRIGAN_HMP_COMMITMENT_H

#include <bls/bls.h>
#include <consensus/params.h>
#include <serialize.h>
#include <sync.h>

#include <map>
#include <memory>
#include <vector>

/** Result of adding an HMP P2P message (seal share, assembled seal, commit).
 *  ACCEPTED: message was valid and stored.
 *  REJECTED_BENIGN: rejected for non-malicious reasons (dedup, timing, pool full, etc.).
 *  REJECTED_INVALID: rejected for cryptographic invalidity (bad BLS sig, bad VRF proof). */
enum class HMPAcceptResult { REJECTED_INVALID = 0, REJECTED_BENIGN, ACCEPTED };

/** Helper for test assertions and boolean contexts */
inline bool HMPAccepted(HMPAcceptResult r) { return r == HMPAcceptResult::ACCEPTED; }

/**
 * CPubKeyCommit -- P2P message payload for Phase 1 pubkey commitment.
 *
 * Pools broadcast this to commit their BLS public key before sealing.
 * Signature over H("HMP-COMMIT" || pubkey) proves key ownership.
 */
class CPubKeyCommit
{
public:
    CBLSPublicKey pubKey;
    CBLSSignature signature;
    int64_t nTimestamp{0};

    SERIALIZE_METHODS(CPubKeyCommit, obj)
    {
        READWRITE(obj.pubKey, obj.signature, obj.nTimestamp);
    }

    /** Verify the self-signature proving key ownership */
    bool Verify() const;

    /** Compute the hash that must be signed: H("HMP-COMMIT" || pubkey) */
    static uint256 SignatureHash(const CBLSPublicKey& pk);
};

/**
 * CHMPCommitmentRegistry -- tracks on-chain pubkey commitments.
 *
 * A signer must be committed at least nHMPCommitmentOffset blocks before
 * they can participate in sealing. When offset=0 the check is disabled.
 */
class CHMPCommitmentRegistry
{
private:
    mutable RecursiveMutex cs;

    int m_offset;          // nHMPCommitmentOffset from consensus params
    int m_evictionWindow;  // nHMPDominanceCatchMaxLookback + buffer

    // pubkey -> first committed height
    std::map<CBLSPublicKey, int> m_commitments GUARDED_BY(cs);

    // reverse index: height -> pubkeys first committed at that height
    std::map<int, std::vector<CBLSPublicKey>> m_heightIndex GUARDED_BY(cs);

public:
    explicit CHMPCommitmentRegistry(int offset, int evictionWindow = 1100)
        : m_offset(offset), m_evictionWindow(evictionWindow) {}

    /** Record commitments from a connected block */
    void BlockConnected(int height, const CBLSPublicKey& minerPubKey,
                        const std::vector<CBLSPublicKey>& explicitCommitments);

    /** Remove commitments first seen at >= height (for reorg) */
    void BlockDisconnected(int height);

    /** Check if pubkey is committed and mature at the given height */
    bool IsCommitted(const CBLSPublicKey& pubkey, int atHeight) const;

    bool IsEnabled() const { return m_offset > 0; }
    int GetOffset() const { return m_offset; }
    bool HasCommitment(const CBLSPublicKey& pubkey) const;

    /** Evict commitments older than maxAge blocks */
    void EvictOld(int currentHeight, int maxAge);
};

/**
 * CHMPCommitPool -- in-memory pool of pending pubkey commitments.
 *
 * Collects PUBKEYCOMMIT messages from P2P; template builders pull
 * from here to embed in CCbTx v5.
 */
class CHMPCommitPool
{
private:
    mutable RecursiveMutex cs;

    static constexpr size_t MAX_PENDING = 256;
    static constexpr int64_t COMMIT_TTL_SECS = 3600; // 1-hour TTL for pool entries

    std::map<CBLSPublicKey, CPubKeyCommit> m_pending GUARDED_BY(cs);

public:
    /** Add a verified commit to the pool. */
    HMPAcceptResult Add(const CPubKeyCommit& commit);

    /** Add a commit during reorg without verifying its BLS signature. */
    HMPAcceptResult AddFromReorg(const CPubKeyCommit& commit);

    /** Get up to maxCount pending commits not yet on-chain */
    std::vector<CBLSPublicKey> GetForTemplate(size_t maxCount,
                                               const CHMPCommitmentRegistry& registry) const;

    /** Remove a pubkey from the pending pool (after it's on-chain) */
    void Remove(const CBLSPublicKey& pubkey);

    /** Get up to maxCount full pending CPubKeyCommit objects */
    std::vector<CPubKeyCommit> GetPendingCommits(size_t maxCount) const;

    size_t Size() const;
};

extern std::unique_ptr<CHMPCommitmentRegistry> g_hmp_commitments;
extern std::unique_ptr<CHMPCommitPool> g_hmp_commit_pool;

#endif // KERRIGAN_HMP_COMMITMENT_H
