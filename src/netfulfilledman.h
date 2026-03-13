// Copyright (c) 2014-2025 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETFULFILLEDMAN_H
#define BITCOIN_NETFULFILLEDMAN_H

#include <netaddress.h>
#include <serialize.h>
#include <sync.h>

#include <memory>

template<typename T>
class CFlatDB;
class CNetFulfilledRequestManager;

class NetFulfilledRequestStore
{
protected:
    typedef std::map<std::string, int64_t> fulfilledreqmapentry_t;
    // #765/#776: Keyed by CNetAddr (IP only), not CService (IP+port).
    // Prevents bypass via source-port churn.
    typedef std::map<CNetAddr, fulfilledreqmapentry_t> fulfilledreqmap_t;

protected:
    //keep track of what node has/was asked for and when
    fulfilledreqmap_t mapFulfilledRequests;
    mutable RecursiveMutex cs_mapFulfilledRequests;

public:
    SERIALIZE_METHODS(NetFulfilledRequestStore, obj)
    {
        LOCK(obj.cs_mapFulfilledRequests);
        READWRITE(obj.mapFulfilledRequests);
        SER_READ(obj, {
            // Reject corrupt cache: bound outer map (tracked peers) and
            // inner maps (request types per peer) (#829).
            static constexpr size_t MAX_FULFILLED_PEERS = 50000;
            static constexpr size_t MAX_REQUESTS_PER_PEER = 100;
            if (obj.mapFulfilledRequests.size() > MAX_FULFILLED_PEERS) {
                throw std::ios_base::failure("NetFulfilledRequestStore peer count exceeds safety limit");
            }
            for (const auto& [addr, reqmap] : obj.mapFulfilledRequests) {
                if (reqmap.size() > MAX_REQUESTS_PER_PEER) {
                    throw std::ios_base::failure("NetFulfilledRequestStore per-peer request count exceeds safety limit");
                }
            }
        });
    }

    void Clear();

    std::string ToString() const;
};

// Fulfilled requests are used to prevent nodes from asking for the same data on sync
// and from being banned for doing so too often.
class CNetFulfilledRequestManager : public NetFulfilledRequestStore
{
private:
    using db_type = CFlatDB<NetFulfilledRequestStore>;

private:
    const std::unique_ptr<db_type> m_db;
    bool is_valid{false};

public:
    CNetFulfilledRequestManager(const CNetFulfilledRequestManager&) = delete;
    CNetFulfilledRequestManager& operator=(const CNetFulfilledRequestManager&) = delete;
    CNetFulfilledRequestManager();
    ~CNetFulfilledRequestManager();

    bool LoadCache(bool load_cache);

    bool IsValid() const { return is_valid; }
    void CheckAndRemove();

    void AddFulfilledRequest(const CNetAddr& addr, const std::string& strRequest);
    bool HasFulfilledRequest(const CNetAddr& addr, const std::string& strRequest);

    void RemoveAllFulfilledRequests(const CNetAddr& addr);

    void DoMaintenance();
};

#endif // BITCOIN_NETFULFILLEDMAN_H
