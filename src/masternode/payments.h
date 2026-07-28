// Copyright (c) 2014-2024 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MASTERNODE_PAYMENTS_H
#define BITCOIN_MASTERNODE_PAYMENTS_H

#include <consensus/amount.h>

#include <string>
#include <vector>

class CBlock;
class CBlockIndex;
class CDeterministicMNManager;
class CDroneListManager;
class CGovernanceManager;
class ChainstateManager;
class CMasternodeSync;
class CTransaction;
class CSporkManager;
class CTxOut;

struct CMutableTransaction;

namespace Consensus { struct Params; }

/**
 * This helper returns amount that should be reallocated to platform
 * It is calculated based on total amount of masternode rewards (not block reward)
 */
CAmount PlatformShare(const CAmount masternodeReward);

/**
 * v1.2.5 legacy-devfund/founders sunset gate.
 *
 * Returns true when the legacy fallback scripts for devfund/founders should be
 * consulted at @p nBlockHeight, given the network's configured sunset height
 * @p nSunsetHeight (Consensus::Params::nLegacyDevfundSunsetHeight). The rule:
 *   - sunset == 0          -> disabled (legacy always consulted; off-mainnet)
 *   - nBlockHeight <  sunset -> consult legacy fallback (pre-sunset behaviour)
 *   - nBlockHeight >= sunset -> do NOT consult legacy fallback; coinbase paying
 *                               devfund/founders to a legacy address is
 *                               bad-cb-payee.
 * Pure helper exposed for unit tests so the boundary is pinned with a small
 * fixture and no full ChainstateManager spin-up.
 */
constexpr bool IsLegacyTreasuryConsulted(int nBlockHeight, int nSunsetHeight) noexcept
{
    return nSunsetHeight == 0 || nBlockHeight < nSunsetHeight;
}

class CMNPaymentsProcessor
{
private:
    CDeterministicMNManager& m_dmnman;
    CDroneListManager& m_droneman;
    CGovernanceManager& m_govman;
    const ChainstateManager& m_chainman;
    const Consensus::Params& m_consensus_params;
    const CMasternodeSync& m_mn_sync;
    const CSporkManager& m_sporkman;

private:
    [[nodiscard]] bool GetBlockTxOuts(const CBlockIndex* pindexPrev, const CAmount blockSubsidy, const CAmount feeReward,
                                      std::vector<CTxOut>& voutMasternodePaymentsRet);
    [[nodiscard]] bool GetMasternodeTxOuts(const CBlockIndex* pindexPrev, const CAmount blockSubsidy, const CAmount feeReward,
                                      std::vector<CTxOut>& voutMasternodePaymentsRet);
    [[nodiscard]] bool IsTransactionValid(const CTransaction& txNew, const CBlockIndex* pindexPrev, const CAmount blockSubsidy,
                                          const CAmount feeReward);
    [[nodiscard]] bool IsOldBudgetBlockValueValid(const CBlock& block, const int nBlockHeight, const CAmount blockReward, std::string& strErrorRet);

public:
    explicit CMNPaymentsProcessor(CDeterministicMNManager& dmnman, CDroneListManager& droneman, CGovernanceManager& govman,
                                  const ChainstateManager& chainman, const Consensus::Params& consensus_params,
                                  const CMasternodeSync& mn_sync, const CSporkManager& sporkman) :
        m_dmnman{dmnman}, m_droneman{droneman}, m_govman{govman}, m_chainman{chainman}, m_consensus_params{consensus_params},
        m_mn_sync{mn_sync}, m_sporkman{sporkman} {}

    bool IsBlockValueValid(const CBlock& block, const int nBlockHeight, const CAmount blockReward, std::string& strErrorRet, const bool check_superblock);
    bool IsBlockPayeeValid(const CTransaction& txNew, const CBlockIndex* pindexPrev, const CAmount blockSubsidy, const CAmount feeReward, const bool check_superblock);
    void FillBlockPayments(CMutableTransaction& txNew, const CBlockIndex* pindexPrev, const CAmount blockSubsidy, const CAmount feeReward,
                           std::vector<CTxOut>& voutMasternodePaymentsRet, std::vector<CTxOut>& voutSuperblockPaymentsRet);
};

#endif // BITCOIN_MASTERNODE_PAYMENTS_H
