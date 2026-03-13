// Copyright (c) 2014-2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <spork.h>

#include <chainparams.h>
#include <flat-database.h>
#include <key_io.h>
#include <logging.h>
#include <messagesigner.h>
#include <net.h>
#include <netmessagemaker.h>
#include <protocol.h>
#include <script/standard.h>
#include <timedata.h>
#include <util/message.h> // for MESSAGE_MAGIC
#include <util/ranges.h>
#include <util/string.h>

#include <string>

const CSporkManager* g_sporkman{nullptr};

const std::string SporkStore::SERIALIZATION_VERSION_STRING = "CSporkManager-Version-2";

std::optional<SporkValue> CSporkManager::SporkValueIfActive(SporkId nSporkID) const
{
    AssertLockHeld(cs);

    if (!mapSporksActive.count(nSporkID)) return std::nullopt;

    {
        LOCK(cs_cache);
        if (auto it = mapSporksCachedValues.find(nSporkID); it != mapSporksCachedValues.end()) {
            return {it->second};
        }
    }

    // calc how many values we have and how many signers vote for every value
    std::unordered_map<SporkValue, int> mapValueCounts;
    for (const auto& [_, spork] : mapSporksActive.at(nSporkID)) {
        mapValueCounts[spork.nValue]++;
        if (mapValueCounts.at(spork.nValue) >= nMinSporkKeys) {
            // nMinSporkKeys is always more than the half of the max spork keys number,
            // so there is only one such value and we can stop here
            {
                LOCK(cs_cache);
                mapSporksCachedValues[nSporkID] = spork.nValue;
            }
            return {spork.nValue};
        }
    }

    return std::nullopt;
}

void SporkStore::Clear()
{
    LOCK(cs);
    mapSporksActive.clear();
    mapSporksByHash.clear();
    // sporkPubKeyID and sporkPrivKey should be set in init.cpp,
    // we should not alter them here.
}

CSporkManager::CSporkManager() :
    m_db{std::make_unique<db_type>("sporks.dat", "magicSporkCache")}
{
}

CSporkManager::~CSporkManager()
{
    if (!is_valid) return;
    m_db->Store(*this);
}

bool CSporkManager::LoadCache()
{
    assert(m_db != nullptr);
    is_valid = m_db->Load(*this);
    if (is_valid) {
        CheckAndRemove();
    }
    return is_valid;
}

void CSporkManager::CheckAndRemove()
{
    LOCK(cs);

    if (setSporkPubKeyIDs.empty()) return;

    for (auto itActive = mapSporksActive.begin(); itActive != mapSporksActive.end();) {
        auto itSignerPair = itActive->second.begin();
        while (itSignerPair != itActive->second.end()) {
            bool fHasValidSig = setSporkPubKeyIDs.find(itSignerPair->first) != setSporkPubKeyIDs.end() &&
                                itSignerPair->second.CheckSignature(itSignerPair->first);
            if (!fHasValidSig) {
                mapSporksByHash.erase(itSignerPair->second.GetHash());
                itActive->second.erase(itSignerPair++);
                continue;
            }
            ++itSignerPair;
        }
        if (itActive->second.empty()) {
            mapSporksActive.erase(itActive++);
            continue;
        }
        ++itActive;
    }

    for (auto itByHash = mapSporksByHash.begin(); itByHash != mapSporksByHash.end();) {
        bool found = false;
        for (const auto& signer : setSporkPubKeyIDs) {
            if (itByHash->second.CheckSignature(signer)) {
                found = true;
                break;
            }
        }
        if (!found) {
            mapSporksByHash.erase(itByHash++);
            continue;
        }
        ++itByHash;
    }
}

MessageProcessingResult CSporkManager::ProcessMessage(CNode& peer, CConnman& connman, std::string_view msg_type, CDataStream& vRecv)
{
    if (msg_type == NetMsgType::SPORK) {
        return ProcessSpork(peer.GetId(), vRecv);
    } else if (msg_type == NetMsgType::GETSPORKS) {
        ProcessGetSporks(peer, connman);
    }
    return {};
}

MessageProcessingResult CSporkManager::ProcessSpork(NodeId from, CDataStream& vRecv)
{
    CSporkMessage spork;
    vRecv >> spork;

    uint256 hash = spork.GetHash();

    MessageProcessingResult ret{};
    ret.m_to_erase = CInv{MSG_SPORK, hash};

    // Validate spork ID against known definitions
    bool knownSpork = false;
    for (const auto& def : sporkDefs) {
        if (def.sporkId == spork.nSporkID) {
            knownSpork = true;
            break;
        }
    }
    if (!knownSpork) {
        LogPrint(BCLog::SPORK, "CSporkManager::ProcessSpork -- Unknown spork ID %d from peer=%d\n", spork.nSporkID, from);
        ret.m_error = MisbehavingError{100};
        return ret;
    }

    if (spork.nTimeSigned > GetAdjustedTime() + 2 * 60 * 60) {
        LogPrint(BCLog::SPORK, "CSporkManager::ProcessSpork -- ERROR: too far into the future\n");
        ret.m_error = MisbehavingError{100};
        return ret;
    }

    auto opt_keyIDSigner = spork.GetSignerKeyID();

    if (opt_keyIDSigner == std::nullopt || WITH_LOCK(cs, return !setSporkPubKeyIDs.count(*opt_keyIDSigner))) {
        LogPrint(BCLog::SPORK, "CSporkManager::ProcessSpork -- ERROR: invalid signature\n");
        ret.m_error = MisbehavingError{100};
        return ret;
    }

    std::string strLogMsg{strprintf("SPORK -- hash: %s id: %d value: %10d peer=%d", hash.ToString(), spork.nSporkID,
                                    spork.nValue, from)};
    auto keyIDSigner = *opt_keyIDSigner;

    {
        LOCK(cs); // make sure to not lock this together with cs_main
        if (mapSporksActive.count(spork.nSporkID)) {
            if (mapSporksActive[spork.nSporkID].count(keyIDSigner)) {
                if (mapSporksActive[spork.nSporkID][keyIDSigner].nTimeSigned >= spork.nTimeSigned) {
                    LogPrint(BCLog::SPORK, "%s seen\n", strLogMsg);
                    return ret;
                } else {
                    LogPrintf("%s updated\n", strLogMsg);
                }
            } else {
                LogPrintf("%s new signer\n", strLogMsg);
            }
        } else {
            LogPrintf("%s new\n", strLogMsg);
        }

        // Remove stale entry from hash map before adding new one
        if (mapSporksActive.count(spork.nSporkID) && mapSporksActive[spork.nSporkID].count(keyIDSigner)) {
            mapSporksByHash.erase(mapSporksActive[spork.nSporkID][keyIDSigner].GetHash());
        }
        mapSporksByHash[hash] = spork;
        mapSporksActive[spork.nSporkID][keyIDSigner] = spork;
        // Clear cached values on new spork being processed
        {
            LOCK(cs_cache);
            mapSporksCachedActive.erase(spork.nSporkID);
            mapSporksCachedValues.erase(spork.nSporkID);
        }
    }

    ret.m_inventory.emplace_back(MSG_SPORK, hash);
    return ret;
}

void CSporkManager::ProcessGetSporks(CNode& peer, CConnman& connman)
{
    // Rate-limit getsporks to prevent peers from spamming spork responses
    {
        static Mutex cs_spork_ratelimit;
        static std::map<NodeId, int64_t> mapLastSporkRequest GUARDED_BY(cs_spork_ratelimit);
        LOCK(cs_spork_ratelimit);
        int64_t now = GetAdjustedTime();
        // Clean up stale rate limit entries (older than 60 seconds) to prevent unbounded growth
        for (auto it = mapLastSporkRequest.begin(); it != mapLastSporkRequest.end(); ) {
            if (now - it->second > 60) {
                it = mapLastSporkRequest.erase(it);
            } else {
                ++it;
            }
        }
        auto& last = mapLastSporkRequest[peer.GetId()];
        if (now - last < 5) {
            LogPrint(BCLog::SPORK, "CSporkManager::%s -- rate limiting getsporks from peer=%d\n", __func__, peer.GetId());
            return;
        }
        last = now;
    }

    LOCK(cs); // make sure to not lock this together with cs_main
    for (const auto& pair : mapSporksActive) {
        for (const auto& signerSporkPair : pair.second) {
            connman.PushMessage(&peer, CNetMsgMaker(peer.GetCommonVersion()).Make(NetMsgType::SPORK, signerSporkPair.second));
        }
    }
}


std::optional<CInv> CSporkManager::UpdateSpork(SporkId nSporkID, SporkValue nValue)
{
    CSporkMessage spork(nSporkID, nValue, GetAdjustedTime());

    LOCK(cs);

    if (!spork.Sign(sporkPrivKey)) {
        LogPrintf("CSporkManager::%s -- ERROR: signing failed for spork %d\n", __func__, nSporkID);
        return std::nullopt;
    }

    auto opt_keyIDSigner = spork.GetSignerKeyID();
    if (opt_keyIDSigner == std::nullopt || !setSporkPubKeyIDs.count(*opt_keyIDSigner)) {
        LogPrintf("CSporkManager::UpdateSpork: failed to find keyid for private key\n");
        return std::nullopt;
    }

    LogPrintf("CSporkManager::%s -- signed %d %s\n", __func__, nSporkID, spork.GetHash().ToString());

    // Remove stale entry from hash map before adding new one
    if (mapSporksActive.count(nSporkID) && mapSporksActive[nSporkID].count(*opt_keyIDSigner)) {
        mapSporksByHash.erase(mapSporksActive[nSporkID][*opt_keyIDSigner].GetHash());
    }
    mapSporksByHash[spork.GetHash()] = spork;
    mapSporksActive[nSporkID][*opt_keyIDSigner] = spork;
    // Clear cached values on new spork being processed

    LOCK(cs_cache);
    mapSporksCachedActive.erase(spork.nSporkID);
    mapSporksCachedValues.erase(spork.nSporkID);


    CInv inv(MSG_SPORK, spork.GetHash());
    return inv;
}

bool CSporkManager::IsSporkActive(SporkId nSporkID) const
{
    // If nSporkID is cached, and the cached value is true, then return early true
    {
        LOCK(cs_cache);
        if (auto it = mapSporksCachedActive.find(nSporkID); it != mapSporksCachedActive.end() && it->second) {
            return true;
        }
    }

    SporkValue nSporkValue = GetSporkValue(nSporkID);
    // Get time is somewhat costly it looks like
    bool ret = nSporkValue < GetAdjustedTime();
    // Only cache true values
    if (ret) {
        LOCK(cs_cache);
        mapSporksCachedActive[nSporkID] = ret;
    }
    return ret;
}

SporkValue CSporkManager::GetSporkValue(SporkId nSporkID) const
{
    // Harden all sporks on Mainnet (except SPORK_25_HMP_ENABLED which
    // must remain a runtime kill switch even on mainnet).
    if (!Params().IsTestChain()) {
        switch (nSporkID) {
            case SPORK_21_QUORUM_ALL_CONNECTED:
                return 1;
            case SPORK_25_HMP_ENABLED:
                break; // fall through to normal spork lookup
            // IS/CL must stay OFF at genesis; LLMQ needs masternodes registered first.
            // Superblocks OFF at genesis, no governance without meaningful MN participation.
            // Return 4070908800 (far-future disabled sentinel) so IsSporkActive() returns false.
            case SPORK_2_INSTANTSEND_ENABLED:
            case SPORK_3_INSTANTSEND_BLOCK_FILTERING:
            case SPORK_9_SUPERBLOCKS_ENABLED:
            case SPORK_17_QUORUM_DKG_ENABLED:
            case SPORK_19_CHAINLOCKS_ENABLED:
            case SPORK_23_QUORUM_POSE:
                return 4070908800ULL;
            default:
                // Fall through to normal spork lookup instead of
                // returning 0, which would force unknown sporks active.
                break;
        }
    }

    LOCK(cs);

    if (auto opt_sporkValue = SporkValueIfActive(nSporkID)) {
        return *opt_sporkValue;
    }


    if (auto optSpork = ranges::find_if_opt(sporkDefs,
                                            [&nSporkID](const auto& sporkDef){return sporkDef.sporkId == nSporkID;})) {
        return optSpork->defaultValue;
    } else {
        // Unknown spork IDs return far-future sentinel (fail-closed).
        // Previously returned -1, which IsSporkActive treated as active since -1 < GetAdjustedTime().
        LogPrint(BCLog::SPORK, "CSporkManager::GetSporkValue -- Unknown Spork ID %d\n", nSporkID);
        return 4070908800ULL;
    }
}

SporkId CSporkManager::GetSporkIDByName(std::string_view strName)
{
    if (auto optSpork = ranges::find_if_opt(sporkDefs,
                                            [&strName](const auto& sporkDef){return sporkDef.name == strName;})) {
        return optSpork->sporkId;
    }

    LogPrint(BCLog::SPORK, "CSporkManager::GetSporkIDByName -- Unknown Spork name '%s'\n", strName);
    return SPORK_INVALID;
}

std::optional<CSporkMessage> CSporkManager::GetSporkByHash(const uint256& hash) const
{
    LOCK(cs);

    if (const auto it = mapSporksByHash.find(hash); it != mapSporksByHash.end())
        return {it->second};

    return std::nullopt;
}

bool CSporkManager::SetSporkAddress(const std::string& strAddress)
{
    LOCK(cs);
    CTxDestination dest = DecodeDestination(strAddress);
    const PKHash* pkhash = std::get_if<PKHash>(&dest);
    if (!pkhash) {
        LogPrintf("CSporkManager::SetSporkAddress -- Failed to parse spork address\n");
        return false;
    }
    setSporkPubKeyIDs.insert(ToKeyID(*pkhash));
    return true;
}

bool CSporkManager::SetMinSporkKeys(int minSporkKeys)
{
    LOCK(cs);
    int maxKeysNumber = setSporkPubKeyIDs.size();
    // Allow 0/0 when no spork keys are configured (spork system disabled)
    if (minSporkKeys == 0 && maxKeysNumber == 0) {
        nMinSporkKeys = 0;
        return true;
    }
    if ((minSporkKeys <= maxKeysNumber / 2) || (minSporkKeys > maxKeysNumber)) {
        LogPrintf("CSporkManager::SetMinSporkKeys -- Invalid min spork signers number: %d\n", minSporkKeys);
        return false;
    }
    nMinSporkKeys = minSporkKeys;
    return true;
}

bool CSporkManager::SetPrivKey(const std::string& strPrivKey)
{
    CKey key;
    CPubKey pubKey;
    if (!CMessageSigner::GetKeysFromSecret(strPrivKey, key, pubKey)) {
        LogPrintf("CSporkManager::SetPrivKey -- Failed to parse private key\n");
        return false;
    }

    LOCK(cs);
    if (setSporkPubKeyIDs.find(pubKey.GetID()) == setSporkPubKeyIDs.end()) {
        LogPrintf("CSporkManager::SetPrivKey -- New private key does not belong to spork addresses\n");
        return false;
    }

    if (!CSporkMessage().Sign(key)) {
        LogPrintf("CSporkManager::SetPrivKey -- Test signing failed\n");
        return false;
    }

    // Test signing successful, proceed
    LogPrintf("CSporkManager::SetPrivKey -- Successfully initialized as spork signer\n");
    sporkPrivKey = key;
    return true;
}

std::string SporkStore::ToString() const
{
    LOCK(cs);
    return strprintf("Sporks: %llu", mapSporksActive.size());
}

uint256 CSporkMessage::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CSporkMessage::GetSignatureHash() const
{
    CHashWriter s(SER_GETHASH, 0);
    s << nSporkID;
    s << nValue;
    s << nTimeSigned;
    return s.GetHash();
}

bool CSporkMessage::Sign(const CKey& key)
{
    if (!key.IsValid()) {
        LogPrintf("CSporkMessage::Sign -- signing key is not valid\n");
        return false;
    }

    CKeyID pubKeyId = key.GetPubKey().GetID();
    std::string strError;
    std::string strMessage = ToString(nSporkID) + ToString(nValue) + ToString(nTimeSigned);

    if (!CMessageSigner::SignMessage(strMessage, vchSig, key)) {
        LogPrintf("CSporkMessage::Sign -- SignMessage() failed\n");
        return false;
    }

    if (!CMessageSigner::VerifyMessage(pubKeyId, vchSig, strMessage, strError)) {
        LogPrintf("CSporkMessage::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CSporkMessage::CheckSignature(const CKeyID& pubKeyId) const
{
    std::string strError;
    std::string strMessage = ToString(nSporkID) + ToString(nValue) + ToString(nTimeSigned);

    if (!CMessageSigner::VerifyMessage(pubKeyId, vchSig, strMessage, strError)) {
        LogPrint(BCLog::SPORK, "CSporkMessage::CheckSignature -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

std::optional<CKeyID> CSporkMessage::GetSignerKeyID() const
{
    CPubKey pubkeyFromSig;
    std::string strMessage = ToString(nSporkID) + ToString(nValue) + ToString(nTimeSigned);
    CHashWriter ss(SER_GETHASH, 0);
    ss << MESSAGE_MAGIC;
    ss << strMessage;
    if (!pubkeyFromSig.RecoverCompact(ss.GetHash(), vchSig)) {
        return std::nullopt;
    }

    return {pubkeyFromSig.GetID()};
}
