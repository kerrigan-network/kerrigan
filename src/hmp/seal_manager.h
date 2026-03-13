// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KERRIGAN_HMP_SEAL_MANAGER_H
#define KERRIGAN_HMP_SEAL_MANAGER_H

#include <hmp/seal.h>
#include <hmp/privilege.h>
#include <hmp/identity.h>
#include <hmp/commitment.h>
#include <consensus/params.h>
#include <sync.h>
#include <uint256.h>

#include <atomic>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <thread>
#include <vector>

class CConnman;

/**
 * CSealManager -- orchestrates the Hivemind sealing protocol.
 *
 * When a new block is found, eligible daemons broadcast BLS signature
 * shares. The next block's miner assembles them into a seal embedded
 * in CCbTx v4. This class manages the collection, validation, and
 * assembly of seal shares.
 *
 * Architecture follows the CSigSharesManager pattern from llmq/signing_shares.h.
 */
class CSealManager
{
private:
    mutable RecursiveMutex cs;

    // Configuration from consensus params
    int m_signingWindowMs;
    int m_gracePeriodMs;
    int m_sealTrailingDepth;
    int m_mandatoryProofHeight;  // height after which empty zkProofs are rejected

    // References to other HMP components
    CHMPIdentity* m_identity;
    CHMPPrivilegeTracker* m_privilege;
    CHMPCommitmentRegistry* m_commitments;
    CConnman* m_connman{nullptr};

    // Per-block share collection
    struct CSealSession {
        uint256 blockHash;
        int blockHeight{0};
        int64_t startTime{0};       // when collection started (ms)
        uint256 prevSealHash;       // anti-grinding VRF entropy from previous seal
        std::map<CBLSPublicKey, CSealShare> shares;  // dedup by signer
        bool assembled{false};
    };

    // Active sessions indexed by block hash
    std::map<uint256, CSealSession> m_sessions GUARDED_BY(cs);

    // Assembled seals indexed by block hash
    std::map<uint256, CAssembledSeal> m_assembledSeals GUARDED_BY(cs);

    // Insertion-order tracking for age-based eviction of assembled seals
    std::deque<uint256> m_sealInsertionOrder GUARDED_BY(cs);

    // Height-to-block-hash mapping for GetSealForTemplate
    std::map<int, uint256> m_heightToHash GUARDED_BY(cs);

    // Equivocation detection: track which block hash we signed at each height
    mutable std::map<int, uint256> m_signedBlocks GUARDED_BY(cs);

    // Worker thread
    std::thread m_thread;
    std::atomic<bool> m_shutdown{false};

    void WorkerThread();

    /** Try to assemble a seal from collected shares.
     *  On success, populates relayOut for broadcast outside the lock. */
    bool TryAssemble(CSealSession& session, std::optional<std::pair<CAssembledSeal, int>>& relayOut) EXCLUSIVE_LOCKS_REQUIRED(cs);

    /** Clean up old sessions past grace period */
    void CleanupStaleSessions() EXCLUSIVE_LOCKS_REQUIRED(cs);

public:
    CSealManager(const Consensus::Params& params, CHMPIdentity* identity, CHMPPrivilegeTracker* privilege,
                 CHMPCommitmentRegistry* commitments = nullptr);
    ~CSealManager();

    void Start();
    void Stop();

    /** Called when a new block is connected. Start collecting shares for it.
     *  @param prevSealHash  hash of previous block's assembled seal (or prev block hash
     *                       if no seal exists), used as VRF anti-grinding entropy */
    void OnNewBlock(const uint256& blockHash, int height, const uint256& prevSealHash);

    /** Add an incoming seal share (from P2P). */
    HMPAcceptResult AddSealShare(const CSealShare& share);

    /** Get the assembled seal for use in a block template at the given height.
     *  Returns the seal for block at (height - nHMPSealTrailingDepth). */
    std::optional<CAssembledSeal> GetSealForTemplate(int height) const;

    /** Get the assembled seal for a specific block hash */
    std::optional<CAssembledSeal> GetSeal(const uint256& blockHash) const;

    /** Sign the given block if this daemon is eligible */
    std::optional<CSealShare> SignBlock(const uint256& blockHash, int algo) const;

    /** Store an assembled seal received from P2P (catch-up).
     */
    HMPAcceptResult AddAssembledSeal(const CAssembledSeal& seal, int height);

    void SetConnman(CConnman* connman) { m_connman = connman; }

    /** Broadcast a seal share to all connected peers */
    void BroadcastShare(const CSealShare& share);

    /** Remove session and assembled seal for a disconnected block (reorg) */
    void BlockDisconnected(const uint256& blockHash, int height);

    /** Get the number of shares collected for a block (for relay cap) */
    size_t GetShareCount(const uint256& blockHash) const;
};

extern std::unique_ptr<CSealManager> g_seal_manager;

#endif // KERRIGAN_HMP_SEAL_MANAGER_H
