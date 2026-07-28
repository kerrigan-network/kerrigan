// Copyright (c) 2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/specialtx_filter.h>

#include <evo/assetlocktx.h>
#include <evo/inference_wire.h>
#include <evo/providertx.h>
#include <evo/specialtx.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <span.h>
#include <streams.h>

// Add a script to the filter if non-empty
static void AddScriptElement(const CScript& script, const std::function<void(Span<const unsigned char>)>& addElement)
{
    if (!script.empty()) {
        addElement(MakeUCharSpan(script));
    }
}

// Add a hash/key to the filter
template <typename T>
static void AddHashElement(const T& hash, const std::function<void(Span<const unsigned char>)>& addElement)
{
    addElement(MakeUCharSpan(hash));
}

// Note: Keep this in sync with
// CBloomFilter::CheckSpecialTransactionMatchesAndUpdate in
// src/common/bloom.cpp. If you add or remove fields for a special
// transaction type here, update the bloom filter routine accordingly
// (and vice versa) to avoid compact-filter vs bloom-filter divergence.
void ExtractSpecialTxFilterElements(const CTransaction& tx, const std::function<void(Span<const unsigned char>)>& addElement)
{
    if (!tx.HasExtraPayloadField()) {
        return; // not a special transaction
    }

    switch (tx.nType) {
    case TRANSACTION_PROVIDER_REGISTER: {
        if (const auto opt_proTx = GetTxPayload<CProRegTx>(tx)) {
            CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
            stream << opt_proTx->collateralOutpoint;
            addElement(MakeUCharSpan(stream));

            AddHashElement(opt_proTx->keyIDOwner, addElement);
            AddHashElement(opt_proTx->keyIDVoting, addElement);
            AddScriptElement(opt_proTx->scriptPayout, addElement);
        }
        break;
    }
    case TRANSACTION_PROVIDER_UPDATE_SERVICE: {
        if (const auto opt_proTx = GetTxPayload<CProUpServTx>(tx)) {
            AddHashElement(opt_proTx->proTxHash, addElement);
            AddScriptElement(opt_proTx->scriptOperatorPayout, addElement);
        }
        break;
    }
    case TRANSACTION_PROVIDER_UPDATE_REGISTRAR: {
        if (const auto opt_proTx = GetTxPayload<CProUpRegTx>(tx)) {
            AddHashElement(opt_proTx->proTxHash, addElement);
            AddHashElement(opt_proTx->keyIDVoting, addElement);
            AddScriptElement(opt_proTx->scriptPayout, addElement);
        }
        break;
    }
    case TRANSACTION_PROVIDER_UPDATE_REVOKE: {
        if (const auto opt_proTx = GetTxPayload<CProUpRevTx>(tx)) {
            AddHashElement(opt_proTx->proTxHash, addElement);
        }
        break;
    }
    case TRANSACTION_ASSET_LOCK: {
        // Asset Lock transactions have special outputs (creditOutputs) that should be included
        if (const auto opt_assetlockTx = GetTxPayload<CAssetLockPayload>(tx)) {
            const auto& extraOuts = opt_assetlockTx->getCreditOutputs();
            for (const CTxOut& txout : extraOuts) {
                const CScript& script = txout.scriptPubKey;
                // Exclude OP_RETURN outputs as they are not spendable
                if (!script.empty() && script[0] != OP_RETURN) {
                    AddScriptElement(script, addElement);
                }
            }
        }
        break;
    }
    case TRANSACTION_DRONE_REGISTER: {
        if (const auto opt_droneTx = GetTxPayload<CDroneRegTx>(tx)) {
            AddHashElement(opt_droneTx->blsPubKeyHash, addElement);
            AddScriptElement(opt_droneTx->scriptPayout, addElement);
        }
        break;
    }
    case TRANSACTION_SAPLING:
        // Intentionally empty: shielded transaction data should not
        // be extractable via compact block filters (privacy preservation)
        break;
    case TRANSACTION_ASSET_UNLOCK:
    case TRANSACTION_COINBASE:
    case TRANSACTION_QUORUM_COMMITMENT:
    case TRANSACTION_MNHF_SIGNAL:
        // No additional special fields needed for these transaction types
        // Their standard outputs are already included in the base filter
        break;
    } // no default case, so the compiler can warn about missing cases
}
