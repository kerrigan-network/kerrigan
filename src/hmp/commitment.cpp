// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hmp/commitment.h>

#include <hash.h>
#include <logging.h>
#include <util/time.h>

#include <algorithm>

std::unique_ptr<CHMPCommitmentRegistry> g_hmp_commitments;
std::unique_ptr<CHMPCommitPool> g_hmp_commit_pool;

// CPubKeyCommit

uint256 CPubKeyCommit::SignatureHash(const CBLSPublicKey& pk)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw << std::string("HMP-COMMIT");
    hw << pk;
    return hw.GetHash();
}

bool CPubKeyCommit::Verify() const
{
    if (!pubKey.IsValid() || !signature.IsValid()) return false;
    uint256 msgHash = SignatureHash(pubKey);
    return signature.VerifyInsecure(pubKey, msgHash, false /* basic scheme */);
}

// CHMPCommitmentRegistry

void CHMPCommitmentRegistry::BlockConnected(int height, const CBLSPublicKey& minerPubKey,
                                             const std::vector<CBLSPublicKey>& explicitCommitments)
{
    LOCK(cs);

    // Implicit commitment: mining a block commits your pubkey
    if (minerPubKey.IsValid() && m_commitments.find(minerPubKey) == m_commitments.end()) {
        m_commitments[minerPubKey] = height;
        m_heightIndex[height].push_back(minerPubKey);
        LogPrint(BCLog::NET, "HMP: implicit commitment for miner %s at height %d\n",
                 minerPubKey.ToString().substr(0, 16), height);
    }

    // Explicit commitments from CCbTx v5
    for (const auto& pk : explicitCommitments) {
        if (!pk.IsValid()) continue;
        if (m_commitments.find(pk) != m_commitments.end()) continue; // already committed
        m_commitments[pk] = height;
        m_heightIndex[height].push_back(pk);
        LogPrint(BCLog::NET, "HMP: explicit commitment for %s at height %d\n",
                 pk.ToString().substr(0, 16), height);
    }

    // Evict commitments older than privilege window + offset.
    // Only evict after the registry has enough history to avoid premature pruning
    // during IBD when blocks are replayed rapidly.
    if (height > m_evictionWindow) {
        EvictOld(height, m_evictionWindow);
    }
}

void CHMPCommitmentRegistry::BlockDisconnected(int height)
{
    LOCK(cs);

    auto it = m_heightIndex.lower_bound(height);
    while (it != m_heightIndex.end()) {
        for (const auto& pk : it->second) {
            auto cit = m_commitments.find(pk);
            if (cit != m_commitments.end() && cit->second >= height) {
                m_commitments.erase(cit);
            }
        }
        it = m_heightIndex.erase(it);
    }
}

bool CHMPCommitmentRegistry::IsCommitted(const CBLSPublicKey& pubkey, int atHeight) const
{
    LOCK(cs);

    // If offset is 0, feature is disabled; everyone is "committed"
    if (m_offset == 0) return true;

    auto it = m_commitments.find(pubkey);
    if (it == m_commitments.end()) return false;

    // Must be committed at least m_offset blocks ago
    return (atHeight - it->second) >= m_offset;
}

bool CHMPCommitmentRegistry::HasCommitment(const CBLSPublicKey& pubkey) const
{
    LOCK(cs);
    return m_commitments.count(pubkey) > 0;
}

void CHMPCommitmentRegistry::EvictOld(int currentHeight, int maxAge)
{
    LOCK(cs);
    int cutoff = currentHeight - maxAge;
    if (cutoff <= 0) return;
    auto it = m_heightIndex.begin();
    while (it != m_heightIndex.end() && it->first < cutoff) {
        for (const auto& pk : it->second) {
            m_commitments.erase(pk);
        }
        it = m_heightIndex.erase(it);
    }
}

// CHMPCommitPool

HMPAcceptResult CHMPCommitPool::Add(const CPubKeyCommit& commit)
{
    // Cheap structural checks before expensive BLS verification (#1068)
    if (!commit.pubKey.IsValid() || !commit.signature.IsValid())
        return HMPAcceptResult::REJECTED_INVALID;

    if (g_hmp_commitments && g_hmp_commitments->HasCommitment(commit.pubKey))
        return HMPAcceptResult::REJECTED_BENIGN;

    {
        LOCK(cs);
        if (m_pending.count(commit.pubKey)) return HMPAcceptResult::REJECTED_BENIGN;
        if (m_pending.size() >= MAX_PENDING) return HMPAcceptResult::REJECTED_BENIGN;
    }

    // BLS verification outside lock (expensive)
    if (!commit.Verify()) {
        LogPrint(BCLog::NET, "HMP: rejecting commit with invalid signature from %s\n",
                 commit.pubKey.ToString().substr(0, 16));
        return HMPAcceptResult::REJECTED_INVALID;
    }

    // Under lock: dedup + state mutation (re-check after verify window)
    LOCK(cs);
    if (m_pending.count(commit.pubKey)) return HMPAcceptResult::REJECTED_BENIGN;

    int64_t nNow = GetTime<std::chrono::seconds>().count();
    for (auto it = m_pending.begin(); it != m_pending.end(); ) {
        if (it->second.nTimestamp < nNow - COMMIT_TTL_SECS * 2) {
            it = m_pending.erase(it);
        } else if ((nNow - it->second.nTimestamp) > COMMIT_TTL_SECS) {
            it = m_pending.erase(it);
        } else {
            ++it;
        }
    }
    if (commit.nTimestamp > nNow + 300) return HMPAcceptResult::REJECTED_BENIGN;

    if (m_pending.size() >= MAX_PENDING) return HMPAcceptResult::REJECTED_BENIGN;

    m_pending[commit.pubKey] = commit;
    LogPrint(BCLog::NET, "HMP: added pending commit from %s (pool size: %zu)\n",
             commit.pubKey.ToString().substr(0, 16), m_pending.size());
    return HMPAcceptResult::ACCEPTED;
}

HMPAcceptResult CHMPCommitPool::AddFromReorg(const CPubKeyCommit& commit)
{
    LOCK(cs);

    if (m_pending.count(commit.pubKey)) return HMPAcceptResult::REJECTED_BENIGN;

    // Cap pool size
    if (m_pending.size() >= MAX_PENDING) return HMPAcceptResult::REJECTED_BENIGN;

    m_pending[commit.pubKey] = commit;
    LogPrint(BCLog::NET, "HMP: restored commit from reorg for %s (pool size: %zu)\n",
             commit.pubKey.ToString().substr(0, 16), m_pending.size());
    return HMPAcceptResult::ACCEPTED;
}

std::vector<CBLSPublicKey> CHMPCommitPool::GetForTemplate(size_t maxCount,
                                                            const CHMPCommitmentRegistry& registry) const
{
    LOCK(cs);

    std::vector<CBLSPublicKey> result;
    result.reserve(std::min(maxCount, m_pending.size()));

    for (const auto& [pk, commit] : m_pending) {
        if (result.size() >= maxCount) break;
        // Skip reorg-restored entries with no BLS signature (#1074)
        if (!commit.signature.IsValid()) continue;
        if (!registry.HasCommitment(pk)) {
            result.push_back(pk);
        }
    }

    return result;
}

void CHMPCommitPool::Remove(const CBLSPublicKey& pubkey)
{
    LOCK(cs);
    m_pending.erase(pubkey);
}

std::vector<CPubKeyCommit> CHMPCommitPool::GetPendingCommits(size_t maxCount) const
{
    LOCK(cs);

    std::vector<CPubKeyCommit> result;
    result.reserve(std::min(maxCount, m_pending.size()));

    for (const auto& [pk, commit] : m_pending) {
        if (result.size() >= maxCount) break;
        if (!commit.signature.IsValid()) continue; // skip reorg-restored entries
        result.push_back(commit);
    }

    return result;
}

size_t CHMPCommitPool::Size() const
{
    LOCK(cs);
    return m_pending.size();
}
