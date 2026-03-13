// Copyright (c) 2014-2025 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <flat-database.h>
#include <netfulfilledman.h>
#include <shutdown.h>

CNetFulfilledRequestManager::CNetFulfilledRequestManager() :
    // Bumped magic string; serialization format changed from CService to CNetAddr keys
    m_db{std::make_unique<db_type>("netfulfilled.dat", "magicFulfilledCache2")}
{
}

CNetFulfilledRequestManager::~CNetFulfilledRequestManager()
{
    if (!is_valid) return;
    m_db->Store(*this);
}

bool CNetFulfilledRequestManager::LoadCache(bool load_cache)
{
    assert(m_db != nullptr);
    is_valid = load_cache ? m_db->Load(*this) : m_db->Store(*this);
    if (is_valid && load_cache) {
        CheckAndRemove();
    }
    return is_valid;
}

void CNetFulfilledRequestManager::AddFulfilledRequest(const CNetAddr& addr, const std::string& strRequest)
{
    LOCK(cs_mapFulfilledRequests);
    // Cap per-peer entries to match the deserialization limit (#838).
    // Evict the soonest-expiring entry when full so critical throttle keys
    // (e.g. governance per-object) always get tracked (#884).
    static constexpr size_t MAX_REQUESTS_PER_PEER = 100;
    auto& inner = mapFulfilledRequests[addr];
    if (inner.size() >= MAX_REQUESTS_PER_PEER && inner.find(strRequest) == inner.end()) {
        auto earliest = inner.begin();
        for (auto it = inner.begin(); it != inner.end(); ++it) {
            if (it->second < earliest->second) {
                earliest = it;
            }
        }
        inner.erase(earliest);
    }
    inner[strRequest] = GetTime() + Params().FulfilledRequestExpireTime();
}

bool CNetFulfilledRequestManager::HasFulfilledRequest(const CNetAddr& addr, const std::string& strRequest)
{
    LOCK(cs_mapFulfilledRequests);
    fulfilledreqmap_t::iterator it = mapFulfilledRequests.find(addr);

    return  it != mapFulfilledRequests.end() &&
            it->second.find(strRequest) != it->second.end() &&
            it->second[strRequest] > GetTime();
}

void CNetFulfilledRequestManager::RemoveAllFulfilledRequests(const CNetAddr& addr)
{
    LOCK(cs_mapFulfilledRequests);
    fulfilledreqmap_t::iterator it = mapFulfilledRequests.find(addr);

    if (it != mapFulfilledRequests.end()) {
        mapFulfilledRequests.erase(it++);
    }
}

void CNetFulfilledRequestManager::CheckAndRemove()
{
    LOCK(cs_mapFulfilledRequests);

    int64_t now = GetTime();
    fulfilledreqmap_t::iterator it = mapFulfilledRequests.begin();

    while(it != mapFulfilledRequests.end()) {
        fulfilledreqmapentry_t::iterator it_entry = it->second.begin();
        while(it_entry != it->second.end()) {
            if(now > it_entry->second) {
                it->second.erase(it_entry++);
            } else {
                ++it_entry;
            }
        }
        if(it->second.size() == 0) {
            mapFulfilledRequests.erase(it++);
        } else {
            ++it;
        }
    }
}

void NetFulfilledRequestStore::Clear()
{
    LOCK(cs_mapFulfilledRequests);
    mapFulfilledRequests.clear();
}

std::string NetFulfilledRequestStore::ToString() const
{
    return strprintf("Nodes with fulfilled requests: %d", mapFulfilledRequests.size());
}

void CNetFulfilledRequestManager::DoMaintenance()
{
    if (ShutdownRequested()) return;

    CheckAndRemove();
}
