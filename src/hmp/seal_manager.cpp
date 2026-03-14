// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hmp/seal_manager.h>

#include <hash.h>
#include <logging.h>
#include <hmp/hmp_params.h>
#include <hmp/vrf.h>
#include <net.h>
#include <netmessagemaker.h>
#include <protocol.h>
#include <support/cleanse.h>
#include <util/time.h>

#include <algorithm>

std::unique_ptr<CSealManager> g_seal_manager;

CSealManager::CSealManager(const Consensus::Params& params, CHMPIdentity* identity, CHMPPrivilegeTracker* privilege,
                           CHMPCommitmentRegistry* commitments)
    : m_signingWindowMs(params.nHMPSigningWindowMs),
      m_gracePeriodMs(params.nHMPGracePeriodMs),
      m_sealTrailingDepth(params.nHMPSealTrailingDepth),
      m_mandatoryProofHeight(params.nHMPMandatoryProofHeight),
      m_identity(identity),
      m_privilege(privilege),
      m_commitments(commitments)
{
}

CSealManager::~CSealManager()
{
    Stop();
}

void CSealManager::Start()
{
    m_shutdown = false;
    m_thread = std::thread(&CSealManager::WorkerThread, this);
}

void CSealManager::Stop()
{
    m_shutdown = true;
    if (m_thread.joinable()) {
        m_thread.join();
    }
}

void CSealManager::WorkerThread()
{
    LogPrintf("HMP: seal manager worker thread started\n");
    while (!m_shutdown) {
        // Collect pending relays under lock, broadcast outside
        std::vector<std::pair<CAssembledSeal, int>> relays;
        {
            LOCK(cs);
            int64_t now = GetTimeMicros() / 1000;

            for (auto& [hash, session] : m_sessions) {
                if (session.assembled) continue;

                int64_t elapsed = now - session.startTime;

                // Try assembly after signing window closes
                if (elapsed >= m_signingWindowMs) {
                    std::optional<std::pair<CAssembledSeal, int>> relayOut;
                    TryAssemble(session, relayOut);
                    if (relayOut) {
                        relays.push_back(*relayOut);
                    }
                }
            }

            CleanupStaleSessions();
        }

        // Broadcast assembled seals outside the lock
        if (m_connman) {
            for (const auto& [seal, height] : relays) {
                const CNetMsgMaker msgMaker(PROTOCOL_VERSION);
                m_connman->ForEachNode([&](CNode* pnode) {
                    m_connman->PushMessage(pnode, msgMaker.Make(NetMsgType::SEALASM, seal, height));
                });
                LogPrint(BCLog::NET, "HMP: broadcast assembled seal for block %s height %d\n",
                         seal.blockHash.ToString().substr(0, 16), height);
            }
        }

        if (!m_shutdown) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
    LogPrintf("HMP: seal manager worker thread stopped\n");
}

bool CSealManager::TryAssemble(CSealSession& session, std::optional<std::pair<CAssembledSeal, int>>& relayOut)
{
    AssertLockHeld(cs);

    if (session.shares.empty()) return false;

    std::vector<CBLSSignature> sigs;
    std::vector<CBLSPublicKey> pubkeys;
    std::vector<uint8_t> algos;

    for (const auto& [pk, share] : session.shares) {
        if (share.signature.IsValid() && pk.IsValid()) {
            sigs.push_back(share.signature);
            pubkeys.push_back(pk);
            algos.push_back(share.algoId);
        }
    }

    if (sigs.empty()) return false;

    CBLSSignature aggSig = CBLSSignature::AggregateInsecure(Span<CBLSSignature>(sigs));
    if (!aggSig.IsValid()) {
        LogPrintf("HMP: seal assembly failed, aggregate sig invalid for block %s\n",
                  session.blockHash.ToString().substr(0, 16));
        return false;
    }

    CAssembledSeal seal;
    seal.blockHash = session.blockHash;
    seal.aggregatedSig = aggSig;
    seal.signers = pubkeys;
    seal.signerAlgos = algos;

    if (!seal.Verify()) {
        LogPrintf("HMP: assembled seal failed verification for block %s\n",
                  session.blockHash.ToString().substr(0, 16));
        return false;
    }

    m_assembledSeals[session.blockHash] = seal;
    m_sealInsertionOrder.push_back(session.blockHash);
    session.assembled = true;

    // Capture relay data under lock; broadcast after releasing
    CAssembledSeal sealToRelay = seal;
    int heightToRelay = session.blockHeight;

    LogPrintf("HMP: assembled seal for block %s with %zu signers\n",
              session.blockHash.ToString().substr(0, 16), pubkeys.size());

    relayOut = std::make_pair(sealToRelay, heightToRelay);

    return true;
}

void CSealManager::CleanupStaleSessions()
{
    AssertLockHeld(cs);

    int64_t now = GetTimeMicros() / 1000;
    auto it = m_sessions.begin();
    while (it != m_sessions.end()) {
        int64_t elapsed = now - it->second.startTime;
        if (elapsed > m_gracePeriodMs && it->second.assembled) {
            it = m_sessions.erase(it);
        } else if (elapsed > m_gracePeriodMs * 2) {
            // Force cleanup of very old unassembled sessions
            it = m_sessions.erase(it);
        } else {
            ++it;
        }
    }

    while (m_assembledSeals.size() > 20) {
        auto oldest = m_sealInsertionOrder.front();
        m_sealInsertionOrder.pop_front();
        m_assembledSeals.erase(oldest);
    }

    // Keep only last 20 height mappings
    while (m_heightToHash.size() > 20) {
        m_heightToHash.erase(m_heightToHash.begin());
    }
}

void CSealManager::OnNewBlock(const uint256& blockHash, int height, const uint256& prevSealHash)
{
    LOCK(cs);

    if (m_sessions.count(blockHash)) return;

    CSealSession session;
    session.blockHash = blockHash;
    session.blockHeight = height;
    session.startTime = GetTimeMicros() / 1000;
    session.prevSealHash = prevSealHash;

    m_sessions[blockHash] = session;
    m_heightToHash[height] = blockHash;

    LogPrintf("HMP: started seal collection for block %s at height %d\n",
              blockHash.ToString().substr(0, 16), height);
}

HMPAcceptResult CSealManager::AddSealShare(const CSealShare& share)
{
    uint256 sessionPrevSealHash;
    int sessionBlockHeight = 0;
    {
        LOCK(cs);

        // Bounds-check algo ID
        if (share.algoId >= NUM_ALGOS) {
            LogPrintf("HMP: rejecting share with out-of-bounds algoId=%d\n", share.algoId);
            return HMPAcceptResult::REJECTED_INVALID;
        }

        auto it = m_sessions.find(share.blockHash);
        if (it == m_sessions.end()) {
            LogPrint(BCLog::NET, "HMP: ignoring share for unknown block %s\n",
                     share.blockHash.ToString().substr(0, 16));
            return HMPAcceptResult::REJECTED_BENIGN;
        }

        auto& session = it->second;
        if (session.assembled) {
            return HMPAcceptResult::REJECTED_BENIGN;
        }

        int64_t now = GetTimeMicros() / 1000; // milliseconds
        int64_t elapsed = now - session.startTime;
        if (elapsed > m_signingWindowMs + 2000) { // 2s network tolerance
            LogPrint(BCLog::NET, "HMP: rejecting late seal share (elapsed=%dms, window=%dms)\n",
                     elapsed, m_signingWindowMs);
            return HMPAcceptResult::REJECTED_BENIGN;
        }

        if (session.shares.count(share.signerPubKey)) {
            return HMPAcceptResult::REJECTED_BENIGN;
        }

        if (session.shares.size() >= MAX_SEAL_SIGNERS) {
            LogPrint(BCLog::NET, "HMP: Session at height %d reached max shares (%zu)\n", session.blockHeight, MAX_SEAL_SIGNERS);
            return HMPAcceptResult::REJECTED_BENIGN;
        }

        sessionPrevSealHash = session.prevSealHash;
        sessionBlockHeight = session.blockHeight;
    }

    // Crypto verification outside lock (privilege/commitment have own locks).
    CHashWriter hw(SER_GETHASH, 0);
    hw << HMP_SEAL_DOMAIN_TAG << share.blockHash << share.signerPubKey << share.algoId;
    uint256 sigMsg = hw.GetHash();
    if (!share.signature.VerifyInsecure(share.signerPubKey, sigMsg, false /* basic scheme */)) {
        LogPrintf("HMP: rejecting share with invalid BLS sig from %s\n",
                  share.signerPubKey.ToString().substr(0, 16));
        return HMPAcceptResult::REJECTED_INVALID;
    }

    HMPPrivilegeTier tier = HMPPrivilegeTier::NEW;

    if (m_privilege) {
        tier = m_privilege->GetTier(share.signerPubKey, share.algoId);
        if (tier == HMPPrivilegeTier::UNKNOWN) {
            LogPrint(BCLog::NET, "HMP: rejecting share from unknown-tier signer %s\n",
                     share.signerPubKey.ToString().substr(0, 16));
            return HMPAcceptResult::REJECTED_BENIGN;
        }
    }

    if (m_commitments && m_commitments->IsEnabled() &&
        !m_commitments->IsCommitted(share.signerPubKey, sessionBlockHeight)) {
        LogPrint(BCLog::NET, "HMP: rejecting share from uncommitted signer %s at height %d\n",
                 share.signerPubKey.ToString().substr(0, 16), sessionBlockHeight);
        return HMPAcceptResult::REJECTED_BENIGN;
    }

    if (!share.vrfProof.IsValid()) {
        LogPrintf("HMP: rejecting share with missing VRF proof from %s\n",
                  share.signerPubKey.ToString().substr(0, 16));
        return HMPAcceptResult::REJECTED_INVALID;
    }
    if (!VerifyVRF(share.signerPubKey, share.blockHash, sessionPrevSealHash, share.vrfProof)) {
        LogPrintf("HMP: rejecting share with invalid VRF proof from %s\n",
                  share.signerPubKey.ToString().substr(0, 16));
        return HMPAcceptResult::REJECTED_INVALID;
    }

    uint256 vrfHash = VRFOutputHash(share.vrfProof);
    int multiplier = GetVRFTierMultiplier(static_cast<int>(tier));
    if (!IsVRFSelected(vrfHash, multiplier)) {
        LogPrint(BCLog::NET, "HMP: rejecting share, signer not VRF-selected for block %s\n",
                 share.blockHash.ToString().substr(0, 16));
        return HMPAcceptResult::REJECTED_BENIGN;
    }

    // Empty zkProof accepted until nHMPMandatoryProofHeight
    if (!share.zkProof.empty()) {
        if (share.zkProof.size() != 192) {
            LogPrintf("HMP: rejecting share with malformed zkProof (size=%zu) from %s\n",
                      share.zkProof.size(), share.signerPubKey.ToString().substr(0, 16));
            return HMPAcceptResult::REJECTED_INVALID;
        }
        if (!hmp_proof::IsInitialized()) {
            // Reject unverifiable proofs; don't relay what we can't validate
            LogPrintf("HMP: rejecting share with zkProof (params not initialized) from %s\n",
                      share.signerPubKey.ToString().substr(0, 16));
            return HMPAcceptResult::REJECTED_BENIGN;
        } else if (!hmp_proof::VerifyProof(share.zkProof, share.blockHash.begin(), share.commitment.begin())) {
            LogPrintf("HMP: rejecting share with invalid zkProof from %s\n",
                      share.signerPubKey.ToString().substr(0, 16));
            return HMPAcceptResult::REJECTED_INVALID;
        }
    } else if (m_mandatoryProofHeight > 0 && sessionBlockHeight >= m_mandatoryProofHeight) {
        LogPrintf("HMP: rejecting share with empty zkProof at height %d (mandatory after %d) from %s\n",
                  sessionBlockHeight, m_mandatoryProofHeight,
                  share.signerPubKey.ToString().substr(0, 16));
        return HMPAcceptResult::REJECTED_BENIGN;
    }

    // Re-acquire lock, re-validate, insert
    {
        LOCK(cs);

        auto it = m_sessions.find(share.blockHash);
        if (it == m_sessions.end()) return HMPAcceptResult::REJECTED_BENIGN;

        auto& session = it->second;
        if (session.assembled) return HMPAcceptResult::REJECTED_BENIGN;
        if (session.shares.count(share.signerPubKey)) return HMPAcceptResult::REJECTED_BENIGN;

        if (session.shares.size() >= MAX_SEAL_SIGNERS) return HMPAcceptResult::REJECTED_BENIGN;

        session.shares[share.signerPubKey] = share;
        LogPrint(BCLog::NET, "HMP: accepted share for block %s from %s (total: %zu)\n",
                 share.blockHash.ToString().substr(0, 16),
                 share.signerPubKey.ToString().substr(0, 16),
                 session.shares.size());
    }

    return HMPAcceptResult::ACCEPTED;
}

std::optional<CAssembledSeal> CSealManager::GetSealForTemplate(int height) const
{
    LOCK(cs);

    int targetHeight = height - m_sealTrailingDepth;
    auto heightIt = m_heightToHash.find(targetHeight);
    if (heightIt == m_heightToHash.end()) {
        return std::nullopt;
    }

    auto sealIt = m_assembledSeals.find(heightIt->second);
    if (sealIt == m_assembledSeals.end()) {
        return std::nullopt;
    }

    return sealIt->second;
}

std::optional<CAssembledSeal> CSealManager::GetSeal(const uint256& blockHash) const
{
    LOCK(cs);

    auto it = m_assembledSeals.find(blockHash);
    if (it == m_assembledSeals.end()) {
        return std::nullopt;
    }

    return it->second;
}

std::optional<CSealShare> CSealManager::SignBlock(const uint256& blockHash, int algo) const
{
    SignAttempt attempt;
    attempt.algo = algo;
    attempt.timestamp = GetTimeMicros() / 1000;

    if (!m_identity || !m_identity->IsValid()) {
        attempt.failReason = "identity_invalid";
        LOCK(cs);
        m_signAttempts.push_back(attempt);
        while (m_signAttempts.size() > MAX_SIGN_ATTEMPTS) m_signAttempts.pop_front();
        return std::nullopt;
    }
    attempt.identityValid = true;

    // Capture session state under a single lock window. prevSealHash is captured
    // here and equivocation intent is pre-registered so there is no TOCTOU gap
    // between check and write.
    uint256 prevSealHash;
    {
        LOCK(cs);

        // Equivocation detection: refuse to sign a different block at a height
        // we've already signed. Look up height from active sessions, falling back
        // to the height-to-hash reverse index so equivocation checks survive
        // session cleanup.
        int height = -1;
        for (const auto& [hash, session] : m_sessions) {
            if (hash == blockHash) {
                height = session.blockHeight;
                break;
            }
        }
        if (height < 0) {
            for (const auto& [h, hash] : m_heightToHash) {
                if (hash == blockHash) {
                    height = h;
                    break;
                }
            }
        }
        attempt.height = height;

        if (height >= 0) {
            auto it = m_signedBlocks.find(height);
            if (it != m_signedBlocks.end() && it->second != blockHash) {
                LogPrintf("HMP: EQUIVOCATION PREVENTED -- already signed block %s at height %d, refusing to sign %s\n",
                          it->second.ToString().substr(0, 16), height, blockHash.ToString().substr(0, 16));
                attempt.equivocationBlocked = true;
                attempt.failReason = "equivocation";
                m_signAttempts.push_back(attempt);
                while (m_signAttempts.size() > MAX_SIGN_ATTEMPTS) m_signAttempts.pop_front();
                return std::nullopt;
            }
        }

        if (!m_signedBlocks.empty() && height > 100) {
            auto pruneIt = m_signedBlocks.begin();
            while (pruneIt != m_signedBlocks.end() && pruneIt->first < height - 100) {
                pruneIt = m_signedBlocks.erase(pruneIt);
            }
        }

        // Pre-register equivocation intent under the same lock. If signing
        // fails below and returns std::nullopt, the stale record
        // is harmlessly conservative (prevents re-signing same height) and
        // gets pruned after 100 blocks.
        if (height >= 0) {
            m_signedBlocks[height] = blockHash;
        }

        // Also capture prevSealHash while holding the lock: avoids a second
        // lock window and eliminates the session-eviction race entirely.
        for (const auto& [hash, session] : m_sessions) {
            if (hash == blockHash) {
                prevSealHash = session.prevSealHash;
                break;
            }
        }
    }

    // Check eligibility
    HMPPrivilegeTier tier = HMPPrivilegeTier::NEW; // default if no tracker
    if (m_privilege) {
        tier = m_privilege->GetTier(m_identity->GetPublicKey(), algo);
        attempt.tier = static_cast<int>(tier);
        LogPrintf("HMP: SignBlock tier=%d for identity=%s algo=%d block=%s\n",
                  static_cast<int>(tier),
                  m_identity->GetPublicKey().ToString().substr(0, 16),
                  algo, blockHash.ToString().substr(0, 16));
        if (tier == HMPPrivilegeTier::UNKNOWN) {
            attempt.failReason = "unknown_tier";
            LOCK(cs);
            m_signAttempts.push_back(attempt);
            while (m_signAttempts.size() > MAX_SIGN_ATTEMPTS) m_signAttempts.pop_front();
            return std::nullopt; // Not eligible
        }
    }

    // Check commitment
    if (m_commitments && m_commitments->IsEnabled()) {
        attempt.committed = m_commitments->IsCommitted(m_identity->GetPublicKey(), attempt.height);
        if (!attempt.committed) {
            LogPrintf("HMP: SignBlock identity not committed at height %d\n", attempt.height);
            // Don't abort here - commitment is checked in AddSealShare.
            // But log it for diagnostics.
        }
    } else {
        attempt.committed = true; // commitments disabled, always committed
    }

    // Compute VRF and check selection
    CBLSSignature vrfProof = m_identity->SignVRF(blockHash, prevSealHash);
    if (!vrfProof.IsValid()) {
        LogPrintf("HMP: SignBlock VRF proof invalid for block %s\n",
                  blockHash.ToString().substr(0, 16));
        attempt.failReason = "vrf_invalid";
        LOCK(cs);
        m_signAttempts.push_back(attempt);
        while (m_signAttempts.size() > MAX_SIGN_ATTEMPTS) m_signAttempts.pop_front();
        return std::nullopt;
    }
    attempt.vrfValid = true;

    uint256 vrfHash = VRFOutputHash(vrfProof);
    int multiplier = GetVRFTierMultiplier(static_cast<int>(tier));
    if (!IsVRFSelected(vrfHash, multiplier)) {
        LogPrintf("HMP: not VRF-selected for block %s (tier=%d mult=%d)\n",
                 blockHash.ToString().substr(0, 16), static_cast<int>(tier), multiplier);
        attempt.failReason = "vrf_not_selected";
        LOCK(cs);
        m_signAttempts.push_back(attempt);
        while (m_signAttempts.size() > MAX_SIGN_ATTEMPTS) m_signAttempts.pop_front();
        return std::nullopt; // Not selected for this round
    }
    attempt.vrfSelected = true;

    LogPrintf("HMP: VRF SELECTED for block %s (tier=%d) -- producing seal share\n",
              blockHash.ToString().substr(0, 16), static_cast<int>(tier));

    CSealShare share;
    share.blockHash = blockHash;
    share.signerPubKey = m_identity->GetPublicKey();

    // Sign H(domain || blockHash || signerPubKey || algoId) to prevent rogue key attacks,
    // bind algoId to the BLS signature, and domain-separate from other BLS contexts.
    share.algoId = static_cast<uint8_t>(algo);
    CHashWriter hw(SER_GETHASH, 0);
    hw << HMP_SEAL_DOMAIN_TAG << blockHash << m_identity->GetPublicKey() << share.algoId;
    uint256 sigMsg = hw.GetHash();
    share.signature = m_identity->Sign(sigMsg);
    share.nTimestamp = GetTimeMicros() / 1000;
    share.vrfProof = vrfProof;

    // Create zk-SNARK proof if Groth16 params are initialized AND proofs are mandatory.
    // When nHMPMandatoryProofHeight == 0 (or current height is below it), empty proofs
    // are accepted by AddSealShare, so skip the expensive proof creation entirely.
    // This also avoids a scalar round-trip bug in VerifyProof (#1082).
    bool proofsMandatory = m_mandatoryProofHeight > 0 && attempt.height >= m_mandatoryProofHeight;
    if (proofsMandatory && hmp_proof::IsInitialized()) {
        uint8_t sk_bytes[32] = {};
        if (m_identity->GetSecretKeyBytes(sk_bytes)) {
            // Bind proof to this block (block_hash) AND to the chain state (prevSealHash).
            // prevSealHash commits to the prior block's seal, which transitively commits
            // to all prior chain state, giving genuine fork discrimination.
            share.zkProof = hmp_proof::CreateProof(sk_bytes, blockHash.begin(), prevSealHash.begin());

            if (!share.zkProof.empty()) {
                uint8_t commit_out[32] = {};
                if (hmp_proof::ComputeCommitment(sk_bytes, blockHash.begin(), prevSealHash.begin(), commit_out)) {
                    std::memcpy(share.commitment.begin(), commit_out, 32);
                }
            }

            memory_cleanse(sk_bytes, 32);
        }
    }

    if (!share.signature.IsValid()) {
        attempt.failReason = "signature_invalid";
        LOCK(cs);
        m_signAttempts.push_back(attempt);
        while (m_signAttempts.size() > MAX_SIGN_ATTEMPTS) m_signAttempts.pop_front();
        return std::nullopt;
    }

    attempt.shareAccepted = true;
    attempt.failReason = "success";
    {
        LOCK(cs);
        m_signAttempts.push_back(attempt);
        while (m_signAttempts.size() > MAX_SIGN_ATTEMPTS) m_signAttempts.pop_front();
    }

    return share;
}

std::vector<CSealManager::SignAttempt> CSealManager::GetSignAttempts() const
{
    LOCK(cs);
    return {m_signAttempts.begin(), m_signAttempts.end()};
}

std::vector<CSealManager::SessionInfo> CSealManager::GetActiveSessions() const
{
    LOCK(cs);
    std::vector<SessionInfo> result;
    for (const auto& [hash, session] : m_sessions) {
        SessionInfo info;
        info.blockHash = hash;
        info.height = session.blockHeight;
        info.shareCount = session.shares.size();
        info.assembled = session.assembled;
        result.push_back(info);
    }
    return result;
}

HMPAcceptResult CSealManager::AddAssembledSeal(const CAssembledSeal& seal, int height)
{
    {
        LOCK(cs);
        if (seal.IsNull()) return HMPAcceptResult::REJECTED_BENIGN;

        // Allow replacement if new seal has more signers
        auto existingByHash = m_assembledSeals.find(seal.blockHash);
        if (existingByHash != m_assembledSeals.end() &&
            existingByHash->second.signers.size() >= seal.signers.size()) {
            return HMPAcceptResult::ACCEPTED;  // already have equal or better
        }
    }

    // Verify outside lock
    if (seal.signers.size() > MAX_SEAL_SIGNERS) return HMPAcceptResult::REJECTED_INVALID;

    std::set<CBLSPublicKey> uniqueSigners(seal.signers.begin(), seal.signers.end());
    if (uniqueSigners.size() != seal.signers.size()) {
        LogPrint(BCLog::NET, "HMP: rejecting assembled seal with %zu duplicate signers\n",
                 seal.signers.size() - uniqueSigners.size());
        return HMPAcceptResult::REJECTED_INVALID;
    }

    if (!seal.Verify()) return HMPAcceptResult::REJECTED_INVALID;

    // Re-acquire lock, commit
    {
        LOCK(cs);

        // Allow replacement only if new seal is strictly better
        auto existingByHash = m_assembledSeals.find(seal.blockHash);
        if (existingByHash != m_assembledSeals.end() &&
            existingByHash->second.signers.size() >= seal.signers.size()) {
            return HMPAcceptResult::ACCEPTED;  // already have equal or better
        }

        // Don't overwrite an existing seal at the same height with fewer signers
        auto existingIt = m_heightToHash.find(height);
        if (existingIt != m_heightToHash.end() && existingIt->second != seal.blockHash) {
            auto existingSeal = m_assembledSeals.find(existingIt->second);
            if (existingSeal != m_assembledSeals.end() &&
                existingSeal->second.signers.size() >= seal.signers.size()) {
                return HMPAcceptResult::REJECTED_BENIGN;
            }
            // New seal is better, remove the old one
            m_assembledSeals.erase(existingIt->second);
            m_sealInsertionOrder.erase(
                std::remove(m_sealInsertionOrder.begin(), m_sealInsertionOrder.end(), existingIt->second),
                m_sealInsertionOrder.end());
        }

        m_assembledSeals[seal.blockHash] = seal;
        m_heightToHash[height] = seal.blockHash;

        // Remove stale deque entry before pushing new one (same-hash replacement)
        m_sealInsertionOrder.erase(
            std::remove(m_sealInsertionOrder.begin(), m_sealInsertionOrder.end(), seal.blockHash),
            m_sealInsertionOrder.end());
        m_sealInsertionOrder.push_back(seal.blockHash);

        // Evict oldest if over capacity
        while (m_assembledSeals.size() > 20) {
            auto oldest = m_sealInsertionOrder.front();
            m_sealInsertionOrder.pop_front();
            // Remove corresponding heightToHash entry
            for (auto it = m_heightToHash.begin(); it != m_heightToHash.end(); ++it) {
                if (it->second == oldest) {
                    m_heightToHash.erase(it);
                    break;
                }
            }
            m_assembledSeals.erase(oldest);
        }
    }

    return HMPAcceptResult::ACCEPTED;
}

void CSealManager::BroadcastShare(const CSealShare& share)
{
    if (!m_connman) return;

    const CNetMsgMaker msgMaker(PROTOCOL_VERSION);
    m_connman->ForEachNode([&](CNode* pnode) {
        m_connman->PushMessage(pnode, msgMaker.Make(NetMsgType::SEALSHARE, share));
    });
    LogPrint(BCLog::NET, "HMP: broadcast seal share for block %s\n",
             share.blockHash.ToString().substr(0, 16));
}

void CSealManager::BlockDisconnected(const uint256& blockHash, int height)
{
    LOCK(cs);

    m_sessions.erase(blockHash);
    m_assembledSeals.erase(blockHash);
    m_sealInsertionOrder.erase(
        std::remove(m_sealInsertionOrder.begin(), m_sealInsertionOrder.end(), blockHash),
        m_sealInsertionOrder.end());
    m_heightToHash.erase(height);
    m_signedBlocks.erase(height);

    LogPrint(BCLog::NET, "HMP: seal manager disconnect block %s height %d\n",
             blockHash.ToString().substr(0, 16), height);
}

size_t CSealManager::GetShareCount(const uint256& blockHash) const
{
    LOCK(cs);
    auto it = m_sessions.find(blockHash);
    if (it == m_sessions.end()) return 0;
    return it->second.shares.size();
}

