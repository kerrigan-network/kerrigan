// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hmp/privilege.h>

#include <consensus/params.h>
#include <logging.h>

#include <algorithm>
#include <set>

CHMPPrivilegeTracker::CHMPPrivilegeTracker(const Consensus::Params& params)
    : m_windowSize(params.nHMPPrivilegeWindow),
      m_warmupBlocks(params.nHMPWarmupBlocks),
      m_minBlocksSolved(params.nHMPMinBlocksSolved),
      m_dominanceCatchFloor(params.nHMPDominanceCatchFloor),
      m_extendedWindowSize(params.nHMPDominanceCatchMaxLookback)
{
}

void CHMPPrivilegeTracker::RebuildFromWindow()
{
    AssertLockHeld(cs);

    for (int a = 0; a < NUM_ALGOS; a++) {
        m_records[a].clear();
    }

    for (const auto& entry : m_window) {
        if (entry.algo >= 0 && entry.algo < NUM_ALGOS && entry.minerPubKey.IsValid()) {
            auto& rec = m_records[entry.algo][entry.minerPubKey];
            rec.blocks_solved++;
            rec.last_active_height = entry.height;
            if (rec.first_seen_height < 0 || entry.height < rec.first_seen_height) {
                rec.first_seen_height = entry.height;
            }
        }

        for (size_t si = 0; si < entry.sealSigners.size(); si++) {
            const auto& signer = entry.sealSigners[si];
            if (!signer.IsValid()) continue;
            // Seal participation: record under the signer's declared algo
            int signerAlgo = (si < entry.signerAlgos.size()) ? static_cast<int>(entry.signerAlgos[si]) : entry.algo;
            if (signerAlgo >= 0 && signerAlgo < NUM_ALGOS) {
                auto& rec = m_records[signerAlgo][signer];
                rec.seal_participations++;
                rec.last_active_height = std::max(rec.last_active_height, entry.height);
                if (rec.first_seen_height < 0) {
                    rec.first_seen_height = entry.height;
                }
            }
        }
    }
}

void CHMPPrivilegeTracker::BlockConnected(int height, int algo, const CBLSPublicKey& minerPubKey,
                                          const std::vector<CBLSPublicKey>& sealSigners,
                                          const std::vector<uint8_t>& signerAlgos)
{
    LOCK(cs);

    CHMPWindowEntry entry;
    entry.height = height;
    entry.algo = algo;
    entry.minerPubKey = minerPubKey;
    entry.sealSigners = sealSigners;
    entry.signerAlgos = signerAlgos;
    m_window.push_back(std::move(entry));

    // Add to extended window (dominance catch, lightweight, solver identity only)
    if (minerPubKey.IsValid()) {
        CHMPExtendedEntry ext;
        ext.height = height;
        ext.algo = algo;
        ext.minerPubKey = minerPubKey;
        m_extendedWindow.push_back(std::move(ext));
        while (static_cast<int>(m_extendedWindow.size()) > m_extendedWindowSize) {
            m_extendedWindow.pop_front();
        }
    }

    // Trim window to size and track if entries were evicted
    bool evicted = false;
    while (static_cast<int>(m_window.size()) > m_windowSize) {
        m_window.pop_front();
        evicted = true;
    }

    if (evicted) {
        // Records may contain stale entries from evicted window slots, rebuild
        RebuildFromWindow();
    } else {
        // Safe to do incremental update (no entries were evicted)
        if (algo >= 0 && algo < NUM_ALGOS && minerPubKey.IsValid()) {
            auto& rec = m_records[algo][minerPubKey];
            rec.blocks_solved++;
            rec.last_active_height = height;
            if (rec.first_seen_height < 0) {
                rec.first_seen_height = height;
            }
        }

        for (size_t si = 0; si < sealSigners.size(); si++) {
            const auto& signer = sealSigners[si];
            if (!signer.IsValid()) continue;
            // Seal participation: record under the signer's declared algo
            int signerAlgo = (si < signerAlgos.size()) ? static_cast<int>(signerAlgos[si]) : algo;
            if (signerAlgo >= 0 && signerAlgo < NUM_ALGOS) {
                auto& rec = m_records[signerAlgo][signer];
                rec.seal_participations++;
                rec.last_active_height = std::max(rec.last_active_height, height);
                if (rec.first_seen_height < 0) {
                    rec.first_seen_height = height;
                }
            }
        }
    }
}

void CHMPPrivilegeTracker::BlockDisconnected(int height)
{
    LOCK(cs);

    while (!m_window.empty() && m_window.back().height >= height) {
        m_window.pop_back();
    }

    while (!m_extendedWindow.empty() && m_extendedWindow.back().height >= height) {
        m_extendedWindow.pop_back();
    }

    RebuildFromWindow();
}

HMPPrivilegeTier CHMPPrivilegeTracker::GetTier(const CBLSPublicKey& pubkey, int algo) const
{
    LOCK(cs);

    if (algo < 0 || algo >= NUM_ALGOS) return HMPPrivilegeTier::UNKNOWN;

    auto it = m_records[algo].find(pubkey);
    if (it == m_records[algo].end()) return HMPPrivilegeTier::UNKNOWN;

    const auto& rec = it->second;
    int currentHeight = GetTipHeight();

    // Check warmup: must have been seen for at least m_warmupBlocks
    if (rec.first_seen_height < 0 || (currentHeight - rec.first_seen_height) < m_warmupBlocks) {
        return HMPPrivilegeTier::UNKNOWN;
    }

    // Elder: solved >= m_minBlocksSolved AND has seal participation
    if (rec.blocks_solved >= m_minBlocksSolved && rec.seal_participations > 0) {
        return HMPPrivilegeTier::ELDER;
    }

    // New: past warmup period
    return HMPPrivilegeTier::NEW;
}

// TODO: wire into ComputeSealMultiplier
uint32_t CHMPPrivilegeTracker::GetEffectiveWeight(const CBLSPublicKey& pubkey, int algo) const
{
    LOCK(cs);

    if (algo < 0 || algo >= NUM_ALGOS) return 0;

    auto it = m_records[algo].find(pubkey);
    if (it == m_records[algo].end()) return 0;

    // Total weight is sum of all blocks solved in this algo
    uint32_t totalWeight = 0;
    for (const auto& [pk, rec] : m_records[algo]) {
        totalWeight += rec.blocks_solved;
    }

    if (totalWeight == 0) return 0;

    uint32_t myWeight = it->second.blocks_solved;

    // Express as basis points (0-10000)
    uint32_t bps = (myWeight * 10000) / totalWeight;

    // Cap at 25% (2500 basis points)
    return std::min(bps, uint32_t{2500});
}

std::vector<CBLSPublicKey> CHMPPrivilegeTracker::GetExtendedSolvers(int algo, int count) const
{
    AssertLockHeld(cs);

    // Walk the extended window backwards to find the last N unique solvers for this algo
    std::vector<CBLSPublicKey> solvers;
    std::set<CBLSPublicKey> seen;

    for (auto it = m_extendedWindow.rbegin(); it != m_extendedWindow.rend(); ++it) {
        if (it->algo != algo) continue;
        if (!it->minerPubKey.IsValid()) continue;
        if (seen.count(it->minerPubKey)) continue;

        seen.insert(it->minerPubKey);
        solvers.push_back(it->minerPubKey);
        if (static_cast<int>(solvers.size()) >= count) break;
    }
    return solvers;
}

std::vector<CBLSPublicKey> CHMPPrivilegeTracker::GetElderSet(int algo) const
{
    LOCK(cs);

    std::vector<CBLSPublicKey> result;
    if (algo < 0 || algo >= NUM_ALGOS) return result;

    int currentHeight = m_window.empty() ? -1 : m_window.back().height;

    // Normal Elders: solved + sealed within the standard window
    std::set<CBLSPublicKey> elderSet;
    for (const auto& [pubkey, rec] : m_records[algo]) {
        if (rec.first_seen_height >= 0 &&
            (currentHeight - rec.first_seen_height) >= m_warmupBlocks &&
            rec.blocks_solved >= m_minBlocksSolved &&
            rec.seal_participations > 0) {
            result.push_back(pubkey);
            elderSet.insert(pubkey);
        }
    }

    // Dominance catch (PRD §4.6.3): if fewer than floor, extend by including
    // recent unique solvers from the extended window who also have seal
    // participation in the standard window. Search broadly to find enough
    // qualified candidates since some may lack current seal participation.
    if (static_cast<int>(result.size()) < m_dominanceCatchFloor && m_dominanceCatchFloor > 0) {
        // Get all unique solvers from extended window (generous limit)
        auto extSolvers = GetExtendedSolvers(algo, m_extendedWindowSize);
        for (const auto& pk : extSolvers) {
            if (elderSet.count(pk)) continue; // already an Elder

            // Check if this pool has both seal participation AND minimum blocks solved
            // in the standard window. seal_participations alone is insufficient:
            // a signing-only Sybil that mined one block in the extended window can
            // accumulate seal_participations without recent mining activity.
            auto it = m_records[algo].find(pk);
            if (it != m_records[algo].end() &&
                it->second.first_seen_height >= 0 &&
                (currentHeight - it->second.first_seen_height) >= m_warmupBlocks &&
                it->second.seal_participations > 0 &&
                it->second.blocks_solved >= 1) {
                result.push_back(pk);
                elderSet.insert(pk);
            }

            if (static_cast<int>(result.size()) >= m_dominanceCatchFloor) break;
        }
    }

    return result;
}

std::vector<CBLSPublicKey> CHMPPrivilegeTracker::GetPrivilegedSet(int algo) const
{
    LOCK(cs);

    std::vector<CBLSPublicKey> result;
    if (algo < 0 || algo >= NUM_ALGOS) return result;

    int currentHeight = m_window.empty() ? -1 : m_window.back().height;

    for (const auto& [pubkey, rec] : m_records[algo]) {
        if (rec.first_seen_height >= 0 &&
            (currentHeight - rec.first_seen_height) >= m_warmupBlocks) {
            result.push_back(pubkey);
        }
    }
    return result;
}

size_t CHMPPrivilegeTracker::GetTotalPrivilegedCount() const
{
    LOCK(cs);

    std::set<CBLSPublicKey> unique;
    int currentHeight = m_window.empty() ? -1 : m_window.back().height;

    for (int a = 0; a < NUM_ALGOS; a++) {
        for (const auto& [pubkey, rec] : m_records[a]) {
            if (rec.first_seen_height >= 0 &&
                (currentHeight - rec.first_seen_height) >= m_warmupBlocks) {
                unique.insert(pubkey);
            }
        }
    }
    return unique.size();
}

CPrivilegeRecord CHMPPrivilegeTracker::GetRecord(const CBLSPublicKey& pubkey, int algo) const
{
    LOCK(cs);

    if (algo >= 0 && algo < NUM_ALGOS) {
        auto it = m_records[algo].find(pubkey);
        if (it != m_records[algo].end()) {
            return it->second;
        }
    }
    return CPrivilegeRecord{};
}

int CHMPPrivilegeTracker::GetTipHeight() const
{
    LOCK(cs);
    if (m_window.empty()) return -1;
    return m_window.back().height;
}

void CHMPPrivilegeTracker::Clear()
{
    LOCK(cs);
    m_window.clear();
    m_extendedWindow.clear();
    for (int a = 0; a < NUM_ALGOS; a++) {
        m_records[a].clear();
    }
    LogPrintf("HMP: privilege tracker cleared (spork toggle reset)\n");
}
