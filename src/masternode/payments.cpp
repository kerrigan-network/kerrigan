// Copyright (c) 2014-2025 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <masternode/payments.h>

#include <chain.h>
#include <consensus/amount.h>
#include <deploymentstatus.h>
#include <evo/deterministicmns.h>
#include <governance/classes.h>
#include <governance/governance.h>
#include <key_io.h>
#include <logging.h>
#include <masternode/sync.h>
#include <primitives/block.h>
#include <script/standard.h>
#include <tinyformat.h>
#include <util/ranges.h>
#include <validation.h>

#include <cassert>
#include <string>

CAmount PlatformShare(const CAmount reward)
{
    // Retained for compilation compatibility with creditpool.cpp (gated behind MN_RR deployment)
    const CAmount platformReward = reward * 375 / 1000;
    bool ok = MoneyRange(platformReward);
    assert(ok);
    return platformReward;
}

/**
 * Kerrigan 5-way coinbase split:
 *   20% miner (implicit, what's left after subtracting all outputs)
 *   20% masternode (selected from deterministic MN list)
 *    5% founders (hardcoded address)
 *   15% dev fund (hardcoded address)
 *   40% growth escrow (consensus-locked, burns after nGrowthEscrowEndHeight)
 *
 * If no masternodes are registered yet, the MN 20% stays with the miner.
 */
[[nodiscard]] bool CMNPaymentsProcessor::GetBlockTxOuts(const CBlockIndex* pindexPrev, const CAmount blockSubsidy, const CAmount feeReward,
                                                        std::vector<CTxOut>& voutMasternodePaymentsRet)
{
    voutMasternodePaymentsRet.clear();

    const int nBlockHeight = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;
    const CAmount totalReward = blockSubsidy + feeReward;

    // Growth escrow: 40% -- consensus-locked until governance vote, burns after sunset
    CAmount escrowReward = totalReward * 40 / 100;
    if (m_consensus_params.nGrowthEscrowEndHeight > 0 && nBlockHeight > m_consensus_params.nGrowthEscrowEndHeight) {
        // After escrow sunset: 40% burns via OP_RETURN (provably unspendable)
        CScript burnScript = CScript() << OP_RETURN;
        voutMasternodePaymentsRet.emplace_back(escrowReward, burnScript);
    } else {
        // Escrow accumulation: coins are consensus-locked (see CheckGrowthEscrowSpend)
        CScript escrowScript(m_consensus_params.growthEscrowScript.begin(),
                             m_consensus_params.growthEscrowScript.end());
        voutMasternodePaymentsRet.emplace_back(escrowReward, escrowScript);
    }

    // Masternode: 20% (if any MNs registered)
    CAmount mnReward = GetMasternodePayment(nBlockHeight, totalReward, /*fV20Active=*/false);
    const auto mnList = m_dmnman.GetListForBlock(pindexPrev);
    if (mnList.GetCounts().enabled() > 0) {
        const auto dmnPayee = mnList.GetMNPayee(pindexPrev);
        if (dmnPayee) {
            CAmount operatorReward = 0;
            if (dmnPayee->nOperatorReward != 0 && dmnPayee->pdmnState->scriptOperatorPayout != CScript()) {
                operatorReward = (mnReward * dmnPayee->nOperatorReward) / 10000;
                mnReward -= operatorReward;
            }
            if (mnReward > 0) {
                voutMasternodePaymentsRet.emplace_back(mnReward, dmnPayee->pdmnState->scriptPayout);
            }
            if (operatorReward > 0) {
                voutMasternodePaymentsRet.emplace_back(operatorReward, dmnPayee->pdmnState->scriptOperatorPayout);
            }
        }
    } else {
        LogPrint(BCLog::MNPAYMENTS, "CMNPaymentsProcessor::%s -- No masternodes registered, MN share stays with miner\n", __func__);
    }

    // Dev fund: 15%
    CAmount devReward = totalReward * 15 / 100;
    CScript devScript(m_consensus_params.devFundPaymentScript.begin(),
                      m_consensus_params.devFundPaymentScript.end());
    voutMasternodePaymentsRet.emplace_back(devReward, devScript);

    // Founders: 5%
    CAmount foundersReward = totalReward * 5 / 100;
    CScript foundersScript(m_consensus_params.foundersPaymentScript.begin(),
                           m_consensus_params.foundersPaymentScript.end());
    voutMasternodePaymentsRet.emplace_back(foundersReward, foundersScript);

    LogPrint(BCLog::MNPAYMENTS, "CMNPaymentsProcessor::%s -- height=%d total=%lld escrow=%lld mn=%lld dev=%lld founders=%lld\n",
             __func__, nBlockHeight, totalReward, escrowReward, mnReward, devReward, foundersReward);
    return true;
}

/**
 * Get treasury payment tx outputs for coinbase.
 */
[[nodiscard]] bool CMNPaymentsProcessor::GetMasternodeTxOuts(const CBlockIndex* pindexPrev, const CAmount blockSubsidy, const CAmount feeReward,
                                                             std::vector<CTxOut>& voutMasternodePaymentsRet)
{
    voutMasternodePaymentsRet.clear();

    if (!GetBlockTxOuts(pindexPrev, blockSubsidy, feeReward, voutMasternodePaymentsRet)) {
        LogPrintf("CMNPaymentsProcessor::%s -- ERROR Failed to build treasury output\n", __func__);
        return false;
    }

    return true;
}

[[nodiscard]] bool CMNPaymentsProcessor::IsTransactionValid(const CTransaction& txNew, const CBlockIndex* pindexPrev, const CAmount blockSubsidy,
                                                            const CAmount feeReward)
{
    const int nBlockHeight = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;

    std::vector<CTxOut> voutTreasuryPayments;
    if (!GetBlockTxOuts(pindexPrev, blockSubsidy, feeReward, voutTreasuryPayments)) {
        LogPrintf("CMNPaymentsProcessor::%s -- ERROR! Failed to get treasury outputs for height %d\n", __func__, nBlockHeight);
        return false; // reject block on treasury computation failure
    }

    // #756: Use index-erasure to prevent a single coinbase output from satisfying
    // two identical required payments (e.g. if MN payout matches a treasury script+amount).
    std::vector<CTxOut> remaining(txNew.vout.begin(), txNew.vout.end());
    for (const auto& txout : voutTreasuryPayments) {
        auto it = std::find(remaining.begin(), remaining.end(), txout);
        if (it == remaining.end()) {
            LogPrintf("CMNPaymentsProcessor::%s -- ERROR! Missing treasury payment amount=%lld at height %d\n",
                      __func__, txout.nValue, nBlockHeight);
            return false;
        }
        remaining.erase(it);
    }
    return true;
}

[[nodiscard]] bool CMNPaymentsProcessor::IsOldBudgetBlockValueValid(const CBlock& block, const int nBlockHeight, const CAmount blockReward, std::string& strErrorRet)
{
    // Kerrigan has no old budget system, just check block reward limit
    if (block.vtx[0]->GetValueOut() > blockReward) {
        strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d)",
                                nBlockHeight, block.vtx[0]->GetValueOut(), blockReward);
        return false;
    }
    return true;
}

/**
 * Kerrigan: simple block value check, coinbase must not exceed block reward.
 * No superblock logic.
 */
bool CMNPaymentsProcessor::IsBlockValueValid(const CBlock& block, const int nBlockHeight, const CAmount blockReward, std::string& strErrorRet, const bool check_superblock)
{
    strErrorRet = "";
    if (block.vtx[0]->GetValueOut() > blockReward) {
        strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward",
                                nBlockHeight, block.vtx[0]->GetValueOut(), blockReward);
        return false;
    }
    return true;
}

bool CMNPaymentsProcessor::IsBlockPayeeValid(const CTransaction& txNew, const CBlockIndex* pindexPrev, const CAmount blockSubsidy, const CAmount feeReward, const bool check_superblock)
{
    if (IsTransactionValid(txNew, pindexPrev, blockSubsidy, feeReward)) {
        return true;
    }

    const int nBlockHeight = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;
    LogPrintf("CMNPaymentsProcessor::%s -- ERROR! Invalid treasury payment at height %d\n", __func__, nBlockHeight);
    return false;
}

void CMNPaymentsProcessor::FillBlockPayments(CMutableTransaction& txNew, const CBlockIndex* pindexPrev, const CAmount blockSubsidy, const CAmount feeReward,
                                             std::vector<CTxOut>& voutMasternodePaymentsRet, std::vector<CTxOut>& voutSuperblockPaymentsRet)
{
    int nBlockHeight = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;

    if (!GetMasternodeTxOuts(pindexPrev, blockSubsidy, feeReward, voutMasternodePaymentsRet)) {
        LogPrint(BCLog::MNPAYMENTS, "CMNPaymentsProcessor::%s -- Failed to build treasury output at height %d\n", __func__, nBlockHeight);
        return;
    }

    // Pre-check: verify miner reward is sufficient for all payments
    CAmount totalPayments = 0;
    for (const auto& txout : voutMasternodePaymentsRet) {
        totalPayments += txout.nValue;
    }
    if (txNew.vout[0].nValue < totalPayments) {
        LogPrintf("ERROR: FillBlockPayments: miner reward insufficient at height %d (reward=%lld, payments=%lld)\n",
                  nBlockHeight, txNew.vout[0].nValue, totalPayments);
        return;
    }

    // Now safe to subtract and append outputs
    for (const auto& txout : voutMasternodePaymentsRet) {
        txNew.vout[0].nValue -= txout.nValue;
        txNew.vout.push_back(txout);
    }

    LogPrint(BCLog::MNPAYMENTS, "CMNPaymentsProcessor::%s -- nBlockHeight %d blockReward %lld treasuryPayment %lld minerReward %lld\n",
             __func__, nBlockHeight, blockSubsidy + feeReward,
             voutMasternodePaymentsRet.empty() ? 0 : voutMasternodePaymentsRet[0].nValue,
             txNew.vout[0].nValue);
}
