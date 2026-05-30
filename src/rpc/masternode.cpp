// Copyright (c) 2014-2025 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <active/context.h>
#include <active/masternode.h>
#include <evo/assetlocktx.h>
#include <evo/chainhelper.h>
#include <evo/deterministicmns.h>
#include <governance/governance.h>
#include <masternode/payments.h>
#include <rpc/evo_util.h>

#include <chainparams.h>
#include <coins.h>
#include <core_io.h>
#include <hash.h>
#include <index/txindex.h>
#include <key_io.h>
#include <net.h>
#include <netbase.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/transaction.h>
#include <policy/planx_rollback.h>
#include <pubkey.h>
#include <random.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/standard.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/rpc/util.h>

#ifdef ENABLE_WALLET
#include <wallet/spend.h>
#include <wallet/wallet.h>
#endif // ENABLE_WALLET

#include <univalue.h>

using node::GetTransaction;
using node::NodeContext;
using node::ReadBlockFromDisk;
#ifdef ENABLE_WALLET
using wallet::CCoinControl;
using wallet::CoinType;
using wallet::CWallet;
using wallet::GetWalletForJSONRPCRequest;
#endif // ENABLE_WALLET

static RPCHelpMan masternode_connect()
{
    return RPCHelpMan{"masternode connect",
        "Connect to given masternode\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address of the masternode to connect"},
            {"v2transport", RPCArg::Type::BOOL, RPCArg::DefaultHint{"set by -v2transport"}, "Attempt to connect using BIP324 v2 transport protocol"},
        },
        RPCResult{
            RPCResult::Type::STR, "status", "Returns 'successfully connected' if successful"
        },
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string strAddress = request.params[0].get_str();

    std::optional<CService> addr{Lookup(strAddress, 0, false)};
    if (!addr.has_value()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Incorrect masternode address %s", strAddress));
    }

    const NodeContext& node = EnsureAnyNodeContext(request.context);
    CConnman& connman = EnsureConnman(node);

    bool node_v2transport = connman.GetLocalServices() & NODE_P2P_V2;
    bool use_v2transport = request.params[1].isNull() ? node_v2transport : ParseBoolV(request.params[1], "v2transport");

    if (use_v2transport && !node_v2transport) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Error: Adding v2transport connections requires -v2transport init flag to be set.");
    }

    connman.OpenMasternodeConnection(CAddress(addr.value(), NODE_NETWORK), use_v2transport);
    if (!connman.IsConnected(CAddress(addr.value(), NODE_NETWORK), CConnman::AllNodes)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Couldn't connect to masternode %s", strAddress));
    }

    return "successfully connected";
},
    };
}

static RPCHelpMan masternode_count()
{
    return RPCHelpMan{"masternode count",
        "Get information about number of masternodes.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "total", "Total number of Masternodes"},
                {RPCResult::Type::NUM, "enabled", "Number of enabled Masternodes"},
                {RPCResult::Type::OBJ, "details", "Breakdown of masternodes by type",
                    {
                        {RPCResult::Type::OBJ, "regular", "Details for regular masternodes",
                            {
                                {RPCResult::Type::NUM, "total", "Total number of regular Masternodes"},
                                {RPCResult::Type::NUM, "enabled", "Number of enabled regular Masternodes"}
                        }},
                        {RPCResult::Type::OBJ, "evo", "Details for BroodNodes",
                            {
                                {RPCResult::Type::NUM, "total", "Total number of BroodNodes"},
                                {RPCResult::Type::NUM, "enabled", "Number of enabled BroodNodes"}
                        }},
                    }}
            }
        },
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const NodeContext& node = EnsureAnyNodeContext(request.context);

    const auto counts{node.dmnman->GetListAtChainTip().GetCounts()};

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("total", counts.total());
    obj.pushKV("enabled", counts.enabled());

    UniValue evoObj(UniValue::VOBJ);
    evoObj.pushKV("total", counts.m_total_evo);
    evoObj.pushKV("enabled", counts.m_valid_evo);

    UniValue regularObj(UniValue::VOBJ);
    regularObj.pushKV("total", counts.m_total_mn);
    regularObj.pushKV("enabled", counts.m_valid_mn);

    UniValue detailedObj(UniValue::VOBJ);
    detailedObj.pushKV("regular", regularObj);
    detailedObj.pushKV("evo", evoObj);
    obj.pushKV("details", detailedObj);

    return obj;
},
    };
}

#ifdef ENABLE_WALLET
static RPCHelpMan masternode_outputs()
{
    return RPCHelpMan{"masternode outputs",
        "Print masternode compatible outputs\n",
        {},
        RPCResult {
            RPCResult::Type::ARR, "", "A list of outpoints that can be/are used as masternode collaterals",
            {
                {RPCResult::Type::STR, "", "A (potential) masternode collateral"},
            }},
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return UniValue::VNULL;

    // Find possible candidates
    CCoinControl coin_control(CoinType::ONLY_MASTERNODE_COLLATERAL);

    UniValue outputsArr(UniValue::VARR);
    for (const auto& out : WITH_LOCK(wallet->cs_wallet, return AvailableCoinsListUnspent(*wallet, &coin_control).all())) {
        outputsArr.push_back(out.outpoint.ToStringShort());
    }

    return outputsArr;
},
    };
}

namespace {

// ---------------------------------------------------------------------------
//  unlockmasternode helpers (Plan-X recovery path)
// ---------------------------------------------------------------------------

// Conservative fee for the unlock sweep. A 1-in / 1-or-2-out P2PKH or P2SH
// transparent tx is well under 400 bytes; 10000 sat is ~25 sat/byte for the
// largest realistic shape (P2SH 2-of-3 input + recovery output + OP_RETURN
// marker), comfortably above default min-relay (1 sat/byte) and well under the
// only-to-7b fee bound (planx::MAX_RECOVERY_FEE == 100000 sat). Kept fixed
// rather than estimated so the RPC has no dependency on fee estimation data.
constexpr CAmount UNLOCK_FIXED_FEE = 10000; // 0.0001 KRGN

// Parse an outpoint string in either "txid:vout" (spec / human friendly) or
// "txid-vout" (matches COutPoint::ToStringShort, which is what masternode
// outputs prints). Throws JSONRPCError on a malformed input.
COutPoint ParseOutpointArg(const std::string& s)
{
    auto sep = s.find_first_of(":-");
    if (sep == std::string::npos || sep == 0 || sep + 1 >= s.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "collateral_outpoint must be \"txid:vout\" or \"txid-vout\"");
    }
    const std::string txid_str = s.substr(0, sep);
    const std::string n_str = s.substr(sep + 1);
    if (txid_str.size() != 64 || !IsHex(txid_str)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "collateral_outpoint txid must be 64 hex chars");
    }
    uint256 hash = uint256S(txid_str);
    int32_t n = 0;
    if (!ParseInt32(n_str, &n) || n < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "collateral_outpoint vout must be a non-negative integer");
    }
    return COutPoint(hash, static_cast<uint32_t>(n));
}

// Resolve the operator claim-back pubkey hash for case 2. If the user passed
// `claim_back_pubkey` as a hex-encoded compressed/uncompressed pubkey, parse it
// and HASH160 it. Otherwise (and only when ENABLE_WALLET), ask the wallet for a
// fresh receive destination, extract its CKeyID, and return that hash + the
// fresh address (for the RPC response).
struct ClaimBackKey
{
    uint160 pubkey_hash{};
    std::string source_pubkey_hex;   // empty if generated by wallet
    std::string generated_address;   // empty if user supplied a pubkey
};

#ifdef ENABLE_WALLET
ClaimBackKey ResolveClaimBackKey(CWallet& wallet, const UniValue& arg)
{
    ClaimBackKey out;
    if (!arg.isNull() && !arg.get_str().empty()) {
        const std::string hex = arg.get_str();
        if (!IsHex(hex)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "claim_back_pubkey must be hex (compressed or uncompressed pubkey)");
        }
        const std::vector<unsigned char> bytes = ParseHex(hex);
        CPubKey pubkey(bytes.begin(), bytes.end());
        if (!pubkey.IsFullyValid()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "claim_back_pubkey is not a valid secp256k1 pubkey");
        }
        out.pubkey_hash = pubkey.GetID();
        out.source_pubkey_hex = hex;
        return out;
    }
    // Generate a fresh wallet address. The CKeyID of that address is the
    // pubkey hash; we hand both back to the operator so they can later prove
    // ownership by signing with the corresponding key.
    auto dest_or_err = wallet.GetNewDestination("planx-claim-back");
    if (!dest_or_err) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT,
                           "no claim_back_pubkey supplied and wallet cannot derive one: "
                           + util::ErrorString(dest_or_err).original);
    }
    const CTxDestination& dest = *dest_or_err;
    const PKHash* pkh = std::get_if<PKHash>(&dest);
    if (pkh == nullptr) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "wallet returned a non-P2PKH destination; supply claim_back_pubkey explicitly");
    }
    out.pubkey_hash = ToKeyID(*pkh);
    out.generated_address = EncodeDestination(dest);
    return out;
}
#endif // ENABLE_WALLET

// Look up the coin that backs `outpoint` in the chainstate UTXO view. Returns
// the spent-script + value, or throws if the outpoint is unknown / already
// spent. cs_main must be held by the caller.
struct ResolvedCoin {
    CScript script_pub_key;
    CAmount value{0};
};

ResolvedCoin LookupCollateralCoin(const ChainstateManager& chainman, const COutPoint& outpoint)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();
    const Coin& coin = view.AccessCoin(outpoint);
    if (coin.IsSpent()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("collateral outpoint %s is unknown or already spent",
                                     outpoint.ToStringShort()));
    }
    ResolvedCoin r;
    r.script_pub_key = coin.out.scriptPubKey;
    r.value = coin.out.nValue;
    return r;
}

} // namespace

static RPCHelpMan unlockmasternode()
{
    return RPCHelpMan{"unlockmasternode",
        "\nConstruct, sign and broadcast a transaction that spends a masternode\n"
        "collateral, routing it correctly under the Plan-X recovery rules.\n"
        "\n"
        "Three cases are handled automatically based on whether the collateral\n"
        "script is in the compromised recovery set:\n"
        "\n"
        "  1. Non-compromised collateral: sweeps to `destination` (or a fresh\n"
        "     wallet change address if omitted). The masternode is deregistered\n"
        "     at the consensus layer when the collateral is spent.\n"
        "  2. Compromised collateral (in the Plan-X recovery set): sweeps to the\n"
        "     baked recovery destination and emits an OP_RETURN claim-back marker\n"
        "     containing HASH160(claim_back_pubkey). The marker is consensus-\n"
        "     invisible (ignored by the only-to-7b rule) but is parseable later\n"
        "     by off-chain governance tooling for replacement-claim disbursement.\n"
        "  3. (Verified, no code path): a fresh `protx register` collateral is\n"
        "     not in the compromised set and is therefore not affected.\n"
        "\n"
        "Locktime is set to the current chain tip height (anti-fee-sniping).\n"
        + wallet::HELP_REQUIRING_PASSPHRASE,
        {
            {"collateral_outpoint", RPCArg::Type::STR, RPCArg::Optional::NO,
                "The collateral outpoint as \"txid:vout\" or \"txid-vout\"."},
            {"destination", RPCArg::Type::STR, RPCArg::Default{""},
                "Destination address for case 1. Ignored for compromised collateral.\n"
                "If omitted in case 1, a fresh wallet change address is used."},
            {"claim_back_pubkey", RPCArg::Type::STR, RPCArg::Default{""},
                "For case 2 only. Hex-encoded secp256k1 pubkey the operator controls.\n"
                "If omitted, the wallet derives a fresh receive address and the\n"
                "resulting pubkey hash + address are returned in the response."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "case", "1 for clean exit, 2 for recovery sweep."},
                {RPCResult::Type::STR_HEX, "txid", "The broadcast transaction id."},
                {RPCResult::Type::STR_HEX, "hex", "The serialized signed transaction."},
                {RPCResult::Type::STR_HEX, "claim_back_marker", /*optional=*/true,
                    "HASH160 hex (40 chars) of the operator pubkey embedded in the\n"
                    "OP_RETURN marker. Case 2 only."},
                {RPCResult::Type::STR, "claim_back_address", /*optional=*/true,
                    "Address corresponding to a wallet-generated claim_back_pubkey,\n"
                    "if one was generated. Case 2 only."},
                {RPCResult::Type::ARR, "warnings", "Any operator-relevant notes.",
                    {
                        {RPCResult::Type::STR, "", ""},
                    }},
            }
        },
        RPCExamples{
            HelpExampleCli("unlockmasternode", "\"abcd...:1\" \"kE...payout-address\"")
            + HelpExampleCli("unlockmasternode", "\"abcd...:1\" \"\" \"02ab...pubkey\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return UniValue::VNULL;
    EnsureWalletIsUnlocked(*wallet);

    const NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);

    const COutPoint outpoint = ParseOutpointArg(request.params[0].get_str());

    // Snapshot the spent script + value + chain tip height under cs_main.
    ResolvedCoin spent;
    int tip_height = 0;
    {
        LOCK(::cs_main);
        spent = LookupCollateralCoin(chainman, outpoint);
        if (chainman.ActiveChain().Tip() != nullptr) {
            tip_height = chainman.ActiveChain().Tip()->nHeight;
        }
    }

    // Sanity: the collateral value should match a known MN collateral. Not
    // strictly required (the only-to-7b predicate doesn't care), but warns the
    // operator early if they pointed the RPC at a non-collateral output.
    UniValue warnings(UniValue::VARR);
    if (!dmn_types::IsCollateralAmount(spent.value)) {
        warnings.push_back(strprintf(
            "outpoint value (%d.%08d KRGN) is not a recognised MN collateral amount",
            spent.value / COIN, spent.value % COIN));
    }
    // And nudge the operator if their collateral is in the active MN list, so
    // they know spending it will trigger deregistration.
    auto dmn = CHECK_NONFATAL(node.dmnman)->GetListAtChainTip().GetMNByCollateral(outpoint);
    if (dmn) {
        warnings.push_back(strprintf(
            "spending this collateral will deregister masternode %s",
            dmn->proTxHash.ToString()));
    }

    // Classify the case by whether the collateral script is in the compromised
    // recovery set. The set is mainnet-scoped (empty off mainnet) so on regtest
    // / testnet this RPC always takes the case-1 path.
    const bool is_compromised = g_compromised_recovery_set.IsActive() &&
                                g_compromised_recovery_set.ContainsScript(spent.script_pub_key);

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.nLockTime = static_cast<uint32_t>(std::max(0, tip_height));

    CTxIn in;
    in.prevout = outpoint;
    // Use a sequence below the final marker so nLockTime is honoured by relay.
    in.nSequence = CTxIn::MAX_SEQUENCE_NONFINAL;
    mtx.vin.push_back(in);

    UniValue result(UniValue::VOBJ);

    if (is_compromised) {
        // CASE 2 -- compromised collateral. Forced sweep to the recovery
        // destination; the only-to-7b predicate (PlanXOnlyToRecoveryAllowed)
        // requires value_to_recovery >= compromised_value - MAX_RECOVERY_FEE,
        // every non-marker output to equal the recovery script, and no Sapling
        // payload. We satisfy all three by hand here.
        if (!request.params[1].isNull() && !request.params[1].get_str().empty()) {
            warnings.push_back(
                "destination is ignored for a compromised collateral; sweep must go to the recovery script");
        }
        const CScript recovery = PlanXRecoveryScript();
        if (PlanXScriptIsPlaceholder(recovery)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "recovery destination is unfinalized on this build");
        }
        const CAmount to_recovery = spent.value - UNLOCK_FIXED_FEE;
        if (to_recovery < spent.value - planx::MAX_RECOVERY_FEE) {
            // Defensive: UNLOCK_FIXED_FEE is well under MAX_RECOVERY_FEE, but
            // if the constant is ever raised above the rule's tolerance the
            // resulting tx would be rejected. Catch it locally.
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "internal fee exceeds planx::MAX_RECOVERY_FEE; tx would be rejected");
        }

        ClaimBackKey ck = ResolveClaimBackKey(*wallet, request.params[2]);
        std::vector<unsigned char> nonce(planx::RECOVERY_CLAIM_NONCE_LEN, 0);
        GetRandBytes(nonce);
        const CScript marker = PlanXBuildClaimBackMarker(ck.pubkey_hash, nonce);
        if (marker.empty() || !marker.IsUnspendable()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "failed to build claim-back OP_RETURN marker");
        }

        mtx.vout.emplace_back(to_recovery, recovery);
        mtx.vout.emplace_back(/*nValue=*/0, marker);

        result.pushKV("case", 2);
        result.pushKV("claim_back_marker", HexStr(ck.pubkey_hash));
        if (!ck.generated_address.empty()) {
            result.pushKV("claim_back_address", ck.generated_address);
        }
    } else {
        // CASE 1 -- non-compromised collateral. Sweep to operator's chosen
        // destination, or a fresh wallet change address if none given. No
        // OP_RETURN marker; the only-to-7b rule does not apply here (the
        // predicate short-circuits on a non-compromised input).
        CTxDestination dest;
        const std::string dest_arg = request.params[1].isNull() ? std::string() : request.params[1].get_str();
        if (!dest_arg.empty()) {
            dest = DecodeDestination(dest_arg);
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                   std::string("Invalid Kerrigan address: ") + dest_arg);
            }
        } else {
            auto dest_or_err = wallet->GetNewChangeDestination();
            if (!dest_or_err) {
                throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT,
                                   "no destination supplied and wallet cannot derive a change address: "
                                   + util::ErrorString(dest_or_err).original);
            }
            dest = *dest_or_err;
        }
        const CScript payout = GetScriptForDestination(dest);
        const CAmount to_payout = spent.value - UNLOCK_FIXED_FEE;
        if (to_payout <= 0) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "collateral value too small to cover unlock fee");
        }
        mtx.vout.emplace_back(to_payout, payout);

        // Defensive cross-check: even though we believe `spent` is not in the
        // compromised set, run the predicate on the constructed tx. If for any
        // reason the rule would still fire (e.g. a future broadening of the
        // recovery set on this build), refuse to broadcast a tx that would be
        // false-flagged so the operator notices.
        {
            LOCK(::cs_main);
            const CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();
            const char* reason = nullptr;
            if (!PlanXOnlyToRecoveryAllowed(CTransaction(mtx), view, &reason,
                                            std::max(0, tip_height) + 1)) {
                throw JSONRPCError(RPC_VERIFY_REJECTED,
                                   strprintf("unlock would be rejected by Plan-X rule (%s); "
                                             "collateral may be in the recovery set after all",
                                             reason ? reason : "unknown"));
            }
        }

        result.pushKV("case", 1);
    }

    // Sign with the wallet. Requires the wallet to own the keys for the
    // collateral script; in practice a MN operator's wallet does.
    {
        LOCK(wallet->cs_wallet);
        if (!wallet->SignTransaction(mtx)) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                               "wallet could not sign the unlock transaction "
                               "(missing keys for the collateral script?)");
        }
    }

    CTransactionRef tx_ref = MakeTransactionRef(std::move(mtx));
    bilingual_str broadcast_err;
    const TransactionError terr = BroadcastTransaction(
        const_cast<NodeContext&>(node), tx_ref, broadcast_err,
        /*max_tx_fee=*/wallet->m_default_max_tx_fee,
        /*relay=*/true, /*wait_callback=*/true);
    if (terr != TransactionError::OK) {
        throw JSONRPCTransactionError(terr, broadcast_err.original);
    }

    result.pushKV("txid", tx_ref->GetHash().ToString());
    result.pushKV("hex", EncodeHexTx(*tx_ref));
    result.pushKV("warnings", warnings);
    return result;
},
    };
}

#endif // ENABLE_WALLET

static RPCHelpMan masternode_status()
{
    return RPCHelpMan{"masternode status",
        "Print masternode status information\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                GetRpcResult("outpoint"),
                GetRpcResult("service"),
                GetRpcResult("proTxHash", /*optional=*/true),
                GetRpcResult("type_str", /*optional=*/true, /*override_name=*/"type"),
                GetRpcResult("collateralHash", /*optional=*/true),
                GetRpcResult("collateralIndex", /*optional=*/true),
                CDeterministicMNState::GetJsonHelp(/*key=*/"dmnState", /*optional=*/true),
                {RPCResult::Type::STR, "state", "Masternode state (e.g. READY, POSE_BANNED, WAITING_FOR_PROTX)"},
            }
        },
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const NodeContext& node = EnsureAnyNodeContext(request.context);

    if (!node.active_ctx) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "This node does not run an active masternode.");
    }
    const auto& mn_activeman{*node.active_ctx->nodeman};

    UniValue mnObj(UniValue::VOBJ);
    mnObj.pushKV("outpoint", mn_activeman.GetOutPoint().ToStringShort());
    mnObj.pushKV("service", mn_activeman.GetService().ToStringAddrPort());
    auto dmn = CHECK_NONFATAL(node.dmnman)->GetListAtChainTip().GetMN(mn_activeman.GetProTxHash());
    if (dmn) {
        mnObj.pushKV("proTxHash", dmn->proTxHash.ToString());
        mnObj.pushKV("type", std::string(GetMnType(dmn->nType).description));
        mnObj.pushKV("collateralHash", dmn->collateralOutpoint.hash.ToString());
        mnObj.pushKV("collateralIndex", dmn->collateralOutpoint.n);
        mnObj.pushKV("dmnState", dmn->pdmnState->ToJson(dmn->nType));
    }
    // "status" removed in v1.1 -- was a human-friendly duplicate of "state".
    // Pool software and monitoring tools use "state" (machine-readable enum).
    mnObj.pushKV("state", mn_activeman.GetStateString());

    return mnObj;
},
    };
}

static std::string GetRequiredPaymentsString(CGovernanceManager& govman, const CDeterministicMNList& tip_mn_list, int nBlockHeight, const CDeterministicMNCPtr &payee)
{
    std::string strPayments = "Unknown";
    if (payee) {
        CTxDestination dest;
        if (!ExtractDestination(payee->pdmnState->scriptPayout, dest)) {
            NONFATAL_UNREACHABLE();
        }
        strPayments = EncodeDestination(dest);
        if (payee->nOperatorReward != 0 && payee->pdmnState->scriptOperatorPayout != CScript()) {
            if (!ExtractDestination(payee->pdmnState->scriptOperatorPayout, dest)) {
                NONFATAL_UNREACHABLE();
            }
            strPayments += ", " + EncodeDestination(dest);
        }
    }
    if (govman.IsSuperblockTriggered(tip_mn_list, nBlockHeight)) {
        std::vector<CTxOut> voutSuperblock;
        if (!govman.GetSuperblockPayments(tip_mn_list, nBlockHeight, voutSuperblock)) {
            return strPayments + ", error";
        }
        std::string strSBPayees = "Unknown";
        for (const auto& txout : voutSuperblock) {
            CTxDestination dest;
            ExtractDestination(txout.scriptPubKey, dest);
            if (strSBPayees != "Unknown") {
                strSBPayees += ", " + EncodeDestination(dest);
            } else {
                strSBPayees = EncodeDestination(dest);
            }
        }
        strPayments += ", " + strSBPayees;
    }
    return strPayments;
}

static RPCHelpMan masternode_winners()
{
    return RPCHelpMan{"masternode winners",
        "Print list of masternode winners\n",
        {
            {"count", RPCArg::Type::NUM, RPCArg::Default{10}, "number of last winners to return"},
            {"filter", RPCArg::Type::STR, RPCArg::Default{""}, "filter for returned winners"},
        },
        RPCResult{
            RPCResult::Type::OBJ_DYN, "", "Keys are block heights (as strings); values describe the payees for that height",
            {
                {RPCResult::Type::STR, "payee", "Payee for the height"}
            }
        },
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const NodeContext& node = EnsureAnyNodeContext(request.context);
    const ChainstateManager& chainman = EnsureChainman(node);
    const CBlockIndex* pindexTip{nullptr};
    {
        LOCK(::cs_main);
        pindexTip = chainman.ActiveChain().Tip();
        if (!pindexTip) return UniValue::VNULL;
    }

    int nCount = 10;
    std::string strFilter;

    if (!request.params[0].isNull()) {
        nCount = request.params[0].getInt<int>();
    }

    // Clamp count to [1, 200] to prevent negative/huge values
    constexpr int kMaxWinnersCount = 200;
    if (nCount < 1 || nCount > kMaxWinnersCount) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("count out of range [1, %d]", kMaxWinnersCount));
    }

    if (!request.params[1].isNull()) {
        strFilter = request.params[1].get_str();
    }

    UniValue obj(UniValue::VOBJ);

    int nChainTipHeight = pindexTip->nHeight;
    int nStartHeight = std::max(nChainTipHeight - nCount, 1);

    const auto tip_mn_list = CHECK_NONFATAL(node.dmnman)->GetListAtChainTip();
    for (int h = nStartHeight; h <= nChainTipHeight; h++) {
        if (h < 1) continue; // Guard against GetAncestor(-1) at genesis
        const CBlockIndex* pIndex = pindexTip->GetAncestor(h - 1);
        if (!pIndex) continue;
        auto payee = node.dmnman->GetListForBlock(pIndex).GetMNPayee(pIndex);
        if (payee) {
            std::string strPayments = GetRequiredPaymentsString(*CHECK_NONFATAL(node.govman), tip_mn_list, h, payee);
            if (!strFilter.empty() && strPayments.find(strFilter) == std::string::npos) continue;
            obj.pushKV(strprintf("%d", h), strPayments);
        }
    }

    auto projection = node.dmnman->GetListForBlock(pindexTip).GetProjectedMNPayees(pindexTip, /*nCount=*/20);
    for (size_t i = 0; i < projection.size(); i++) {
        int h = nChainTipHeight + 1 + i;
        std::string strPayments = GetRequiredPaymentsString(*node.govman, tip_mn_list, h, projection[i]);
        if (!strFilter.empty() && strPayments.find(strFilter) == std::string::npos) continue;
        obj.pushKV(strprintf("%d", h), strPayments);
    }

    return obj;
},
    };
}

static RPCHelpMan masternode_payments()
{
    return RPCHelpMan{"masternode payments",
        "\nReturns an array of deterministic masternodes and their payments for the specified block\n",
        {
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"tip"}, "The hash of the starting block"},
            {"count", RPCArg::Type::NUM, RPCArg::Default{1}, "The number of blocks to return. Will return <count> previous blocks if <count> is negative. Both 1 and -1 correspond to the chain tip."},
        },
        RPCResult {
            RPCResult::Type::ARR, "", "Blocks",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::NUM, "height", "The height of the block"},
                    {RPCResult::Type::STR_HEX, "blockhash", "The hash of the block"},
                    {RPCResult::Type::NUM, "amount", "Amount received in this block by all masternodes"},
                    {RPCResult::Type::ARR, "masternodes", "Masternodes that received payments in this block",
                    {
                        {RPCResult::Type::STR_HEX, "proTxHash", "The hash of the corresponding ProRegTx"},
                        {RPCResult::Type::NUM, "amount", "Amount received by this masternode"},
                        {RPCResult::Type::ARR, "payees", "Payees who received a share of this payment",
                        {
                            {RPCResult::Type::STR, "address", "Payee address"},
                            {RPCResult::Type::STR_HEX, "script", "Payee scriptPubKey"},
                            {RPCResult::Type::NUM, "amount", "Amount received by this payee"},
                        }},
                    }},
                }},
            },
        },
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const NodeContext& node = EnsureAnyNodeContext(request.context);
    const ChainstateManager& chainman = EnsureChainman(node);

    const CBlockIndex* pindex{nullptr};

    if (g_txindex) {
        g_txindex->BlockUntilSyncedToCurrentChain();
    }

    if (request.params[0].isNull()) {
        LOCK(::cs_main);
        pindex = chainman.ActiveChain().Tip();
    } else {
        LOCK(::cs_main);
        uint256 blockHash(ParseHashV(request.params[0], "blockhash"));
        pindex = chainman.m_blockman.LookupBlockIndex(blockHash);
        if (pindex == nullptr) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    int64_t nCount = request.params.size() > 1 ? ParseInt64V(request.params[1], "count") : 1;

    // Clamp count to [1, 200] to prevent INT64_MIN UB and unbounded loop
    constexpr int64_t kMaxPaymentsCount = 200;
    if (nCount == INT64_MIN || std::abs(nCount) > kMaxPaymentsCount) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("count out of range [-%d, %d]", kMaxPaymentsCount, kMaxPaymentsCount));
    }

    // A temporary vector which is used to sort results properly (there is no "reverse" in/for UniValue)
    std::vector<UniValue> vecPayments;

    CHECK_NONFATAL(node.chain_helper);
    CHECK_NONFATAL(node.dmnman);
    // Obtain mempool reference once before the loop (not every block iteration)
    const CTxMemPool& mempool = EnsureAnyMemPool(request.context);
    while (vecPayments.size() < uint64_t(std::abs(nCount)) && pindex != nullptr) {
        CBlock block;
        if (!ReadBlockFromDisk(block, pindex, Params().GetConsensus())) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
        }

        // Note: we have to actually calculate block reward from scratch instead of simply querying coinbase vout
        // because miners might collect less coins than they potentially could and this would break our calculations.
        CAmount nBlockFees{0};
        for (const auto& tx : block.vtx) {
            if (tx->IsCoinBase()) {
                continue;
            }
            if (tx->IsPlatformTransfer()) {
                auto payload = GetTxPayload<CAssetUnlockPayload>(*tx);
                CHECK_NONFATAL(payload);
                nBlockFees += payload->getFee();
                continue;
            }

            CAmount nValueIn{0};
            for (const auto& txin : tx->vin) {
                uint256 blockHashTmp;
                CTransactionRef txPrev = GetTransaction(/* block_index */ nullptr, &mempool, txin.prevout.hash, Params().GetConsensus(), blockHashTmp);
                if (!txPrev) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR,
                        strprintf("Previous transaction %s not found. Requires -txindex.",
                                  txin.prevout.hash.ToString()));
                }
                if (txin.prevout.n >= txPrev->vout.size()) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR,
                        strprintf("Output index %u out of range for tx %s",
                                  txin.prevout.n, txin.prevout.hash.ToString()));
                }
                nValueIn += txPrev->vout[txin.prevout.n].nValue;
            }
            nBlockFees += nValueIn - tx->GetValueOut();
        }

        std::vector<CTxOut> voutMasternodePayments, voutDummy;
        CMutableTransaction dummyTx;
        CAmount blockSubsidy = GetBlockSubsidy(pindex, Params().GetConsensus());
        // FillBlockPayments expects vout[0] initialized with the block reward
        // (it subtracts treasury shares from it). Without this, vout[0] goes negative.
        dummyTx.vout.resize(1);
        dummyTx.vout[0].nValue = blockSubsidy;
        // pindex->pprev is null at genesis block, guard before use
        if (pindex->pprev) {
            node.chain_helper->mn_payments->FillBlockPayments(dummyTx, pindex->pprev, blockSubsidy, nBlockFees, voutMasternodePayments, voutDummy);
        }

        UniValue blockObj(UniValue::VOBJ);
        CAmount payedPerBlock{0};

        UniValue masternodeArr(UniValue::VARR);
        UniValue protxObj(UniValue::VOBJ);
        UniValue payeesArr(UniValue::VARR);
        CAmount payedPerMasternode{0};

        for (const auto& txout : voutMasternodePayments) {
            UniValue obj(UniValue::VOBJ);
            CTxDestination dest;
            ExtractDestination(txout.scriptPubKey, dest);
            obj.pushKV("address", EncodeDestination(dest));
            obj.pushKV("script", HexStr(txout.scriptPubKey));
            obj.pushKV("amount", txout.nValue);
            payedPerMasternode += txout.nValue;
            payeesArr.push_back(obj);
        }

        // NOTE: we use _previous_ block to find a payee for the current one
        // pindex->pprev is null at genesis, guard before use
        const auto dmnPayee = pindex->pprev
            ? node.dmnman->GetListForBlock(pindex->pprev).GetMNPayee(pindex->pprev)
            : nullptr;
        protxObj.pushKV("proTxHash", dmnPayee == nullptr ? "" : dmnPayee->proTxHash.ToString());
        protxObj.pushKV("amount", payedPerMasternode);
        protxObj.pushKV("payees", payeesArr);
        payedPerBlock += payedPerMasternode;
        masternodeArr.push_back(protxObj);

        blockObj.pushKV("height", pindex->nHeight);
        blockObj.pushKV("blockhash", pindex->GetBlockHash().ToString());
        blockObj.pushKV("amount", payedPerBlock);
        blockObj.pushKV("masternodes", masternodeArr);
        vecPayments.push_back(blockObj);

        if (nCount > 0) {
            LOCK(::cs_main);
            pindex = chainman.ActiveChain().Next(pindex);
        } else {
            pindex = pindex->pprev;
        }
    }

    if (nCount < 0) {
        std::reverse(vecPayments.begin(), vecPayments.end());
    }

    UniValue paymentsArr(UniValue::VARR);
    for (const auto& payment : vecPayments) {
        paymentsArr.push_back(payment);
    }

    return paymentsArr;
},
    };
}

static RPCHelpMan masternode_help()
{
    return RPCHelpMan{"masternode",
        "Set of commands to execute masternode related actions\n"
        "\nAvailable commands:\n"
        "  count        - Get information about number of masternodes\n"
#ifdef ENABLE_WALLET
        "  outputs      - Print masternode compatible outputs\n"
#endif // ENABLE_WALLET
        "  status       - Print masternode status information\n"
        "  list         - Print list of all known masternodes (see masternodelist for more info)\n"
        "  payments     - Return information about masternode payments in a mined block\n"
        "  winners      - Print list of masternode winners\n",
        {
            {"command", RPCArg::Type::STR, RPCArg::Optional::NO, "The command to execute"},
        },
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    throw JSONRPCError(RPC_INVALID_PARAMETER, "Must be a valid command");
},
    };
}

static RPCHelpMan masternodelist_helper(bool is_composite)
{
    // We need both composite and non-composite options because we support
    // both options 'masternodelist' and 'masternode list'
    return RPCHelpMan{is_composite ? "masternode list" : "masternodelist",
        "Get a list of masternodes in different modes. This call is identical to 'masternode list' call.\n"
        "Available modes:\n"
        "  addr           - Print ip address associated with a masternode (can be additionally filtered, partial match)\n"
        "  recent         - Print info in JSON format for active and recently banned masternodes (can be additionally filtered, partial match)\n"
        "  evo            - Print info in JSON format for BroodNodes only\n"
        "  full           - Print info in format 'status payee lastpaidtime lastpaidblock IP'\n"
        "                   (can be additionally filtered, partial match)\n"
        "  info           - Print info in format 'status payee IP'\n"
        "                   (can be additionally filtered, partial match)\n"
        "  json           - Print info in JSON format (can be additionally filtered, partial match)\n"
        "  lastpaidblock  - Print the last block height a node was paid on the network\n"
        "  lastpaidtime   - Print the last time a node was paid on the network\n"
        "  owneraddress   - Print the masternode owner Kerrigan address\n"
        "  payee          - Print the masternode payout Kerrigan address (can be additionally filtered,\n"
        "                   partial match)\n"
        "  pubKeyOperator - Print the masternode operator public key\n"
        "  status         - Print masternode status: ENABLED / POSE_BANNED\n"
        "                   (can be additionally filtered, partial match)\n"
        "  votingaddress  - Print the masternode voting Kerrigan address\n",
        {
            {"mode", RPCArg::Type::STR, RPCArg::DefaultHint{"json"}, "The mode to run list in"},
            {"filter", RPCArg::Type::STR, RPCArg::Default{""}, "Filter results. Partial match by outpoint by default in all modes, additional matches in some modes are also available"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "<outpoint>", "", {
                RPCResult{"for mode = addr", RPCResult::Type::STR, "<address>", "Flattened list of all addresses registered to masternode"},
                RPCResult{"for mode = full", RPCResult::Type::STR, "<info>", "Flattened list of a masternode's status, payee address, last paid block's timestamp, height and service addresses"},
                RPCResult{"for mode = info", RPCResult::Type::STR, "<info>", "Flattened list of a masternode's status, payee address and service addresses"},
                RPCResult{"for mode = evo, json or recent", RPCResult::Type::OBJ, "", "", {
                    GetRpcResult("proTxHash"),
                    GetRpcResult("service", /*optional=*/false, /*override_name=*/"address"),
                    GetRpcResult("addresses"),
                    GetRpcResult("payoutAddress", /*optional=*/false, /*override_name=*/"payee"),
                    {RPCResult::Type::STR, "status", "Masternode status (human-readable string)"},
                    GetRpcResult("type_str", /*optional=*/false, /*override_name=*/"type"),
                    GetRpcResult("platformNodeID", /*optional=*/true),
                    GetRpcResult("platformP2PPort", /*optional=*/true),
                    GetRpcResult("platformHTTPPort", /*optional=*/true),
                    GetRpcResult("PoSePenalty", /*optional=*/false, /*override_name=*/"pospenaltyscore"),
                    GetRpcResult("consecutivePayments"),
                    {RPCResult::Type::NUM, "lastpaidtime", "Timestamp of block the masternode was last paid"},
                    GetRpcResult("lastPaidHeight", /*optional=*/false, /*override_name=*/"lastpaidblock"),
                    GetRpcResult("ownerAddress", /*optional=*/false, /*override_name=*/"owneraddress"),
                    GetRpcResult("votingAddress", /*optional=*/false, /*override_name=*/"votingaddress"),
                    GetRpcResult("collateralAddress", /*optional=*/false, /*override_name=*/"collateraladdress"),
                    GetRpcResult("pubKeyOperator", /*optional=*/false, /*override_name=*/"pubkeyoperator"),
                }},
                RPCResult{"for mode = lastpaidblock", RPCResult::Type::NUM, "<height>", "Height masternode was last paid"},
                RPCResult{"for mode = lastpaidtime", RPCResult::Type::NUM, "<time>", "Timestamp of block the masternode was last paid"},
                RPCResult{"for mode = payee", RPCResult::Type::STR, "<addr>", "Kerrigan address used for masternode reward payments"},
                RPCResult{"for mode = owneraddress", RPCResult::Type::STR, "<addr>", "Kerrigan address used for payee updates and proposal voting"},
                RPCResult{"for mode = pubkeyoperator", RPCResult::Type::STR, "<addr>", "BLS public key used for operator signing"},
                RPCResult{"for mode = status", RPCResult::Type::STR, "<status>", "Masternode status (human-readable string)"},
                RPCResult{"for mode = votingaddress", RPCResult::Type::STR, "<addr>", "Kerrigan address used for voting"},
            }
        },
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string strMode = "json";
    std::string strFilter;

    if (!request.params[0].isNull()) strMode = request.params[0].get_str();
    if (!request.params[1].isNull()) strFilter = request.params[1].get_str();

    strMode = ToLower(strMode);

    if (
                strMode != "addr" && strMode != "full" && strMode != "info" && strMode != "json" &&
                strMode != "owneraddress" && strMode != "votingaddress" &&
                strMode != "lastpaidtime" && strMode != "lastpaidblock" &&
                strMode != "payee" && strMode != "pubkeyoperator" &&
                strMode != "status" && strMode != "recent" && strMode != "evo")
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode. Use: addr, full, info, json, owneraddress, votingaddress, lastpaidtime, lastpaidblock, payee, pubkeyoperator, status, recent, evo");
    }

    const NodeContext& node = EnsureAnyNodeContext(request.context);
    const ChainstateManager& chainman = EnsureChainman(node);

    UniValue obj(UniValue::VOBJ);

    const auto mnList = CHECK_NONFATAL(node.dmnman)->GetListAtChainTip();
    const auto dmnToStatus = [&](const auto& dmn) {
        if (dmn.pdmnState->IsBanned()) {
            return "POSE_BANNED";
        }
        return "ENABLED";
    };
    const auto dmnToLastPaidTime = [&](const auto& dmn) {
        if (dmn.pdmnState->nLastPaidHeight == 0) {
            return (int)0;
        }

        LOCK(::cs_main);
        const CBlockIndex* pindex = chainman.ActiveChain()[dmn.pdmnState->nLastPaidHeight];
        return (int)pindex->nTime;
    };

    const bool showRecentMnsOnly = strMode == "recent";
    const bool showEvoOnly = strMode == "evo";
    const int tipHeight = WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip()->nHeight);
    mnList.ForEachMN(/*onlyValid=*/false, [&](const auto& dmn) {
        if (showRecentMnsOnly && dmn.pdmnState->IsBanned()) {
            if (tipHeight - dmn.pdmnState->GetBannedHeight() > Params().GetConsensus().nSuperblockCycle) {
                return;
            }
        }
        if (showEvoOnly && dmn.nType != MnType::Evo) {
            return;
        }

        std::string strOutpoint = dmn.collateralOutpoint.ToStringShort();
        Coin coin;
        std::string collateralAddressStr = "UNKNOWN";
        if (GetUTXOCoin(chainman.ActiveChainstate(), dmn.collateralOutpoint, coin)) {
            CTxDestination collateralDest;
            if (ExtractDestination(coin.out.scriptPubKey, collateralDest)) {
                collateralAddressStr = EncodeDestination(collateralDest);
            }
        }

        CScript payeeScript = dmn.pdmnState->scriptPayout;
        CTxDestination payeeDest;
        std::string payeeStr = "UNKNOWN";
        if (ExtractDestination(payeeScript, payeeDest)) {
            payeeStr = EncodeDestination(payeeDest);
        }

        std::string strAddress{};
        if (strMode == "addr" || strMode == "full" || strMode == "info" || strMode == "json" || strMode == "recent" ||
            strMode == "evo") {
            for (const auto& entry : dmn.pdmnState->netInfo->GetEntries()) {
                strAddress += entry.ToStringAddrPort() + " ";
            }
            if (!strAddress.empty()) strAddress.pop_back(); // Remove trailing space
        }

        if (strMode == "addr") {
            if (!strFilter.empty() && strAddress.find(strFilter) == std::string::npos &&
                strOutpoint.find(strFilter) == std::string::npos)
                return;
            obj.pushKV(strOutpoint, strAddress);
        } else if (strMode == "full") {
            std::string strFull = strprintf("%s %d %s %s %s %s",
                                    PadString(dmnToStatus(dmn), 18),
                                    dmn.pdmnState->nPoSePenalty,
                                    payeeStr,
                                    PadString(ToString(dmnToLastPaidTime(dmn)), 10),
                                    PadString(ToString(dmn.pdmnState->nLastPaidHeight), 6),
                                    strAddress);
            if (!strFilter.empty() && strFull.find(strFilter) == std::string::npos &&
                strOutpoint.find(strFilter) == std::string::npos)
                return;
            obj.pushKV(strOutpoint, strFull);
        } else if (strMode == "info") {
            std::string strInfo = strprintf("%s %d %s %s",
                                    PadString(dmnToStatus(dmn), 18),
                                    dmn.pdmnState->nPoSePenalty,
                                    payeeStr,
                                    strAddress);
            if (!strFilter.empty() && strInfo.find(strFilter) == std::string::npos &&
                strOutpoint.find(strFilter) == std::string::npos)
                return;
            obj.pushKV(strOutpoint, strInfo);
        } else if (strMode == "json" || strMode == "recent" || strMode == "evo") {
            std::string strInfo = strprintf("%s %s %s %s %d %d %d %s %s %s %s",
                                    dmn.proTxHash.ToString(),
                                    strAddress,
                                    payeeStr,
                                    dmnToStatus(dmn),
                                    dmn.pdmnState->nPoSePenalty,
                                    dmnToLastPaidTime(dmn),
                                    dmn.pdmnState->nLastPaidHeight,
                                    EncodeDestination(PKHash(dmn.pdmnState->keyIDOwner)),
                                    EncodeDestination(PKHash(dmn.pdmnState->keyIDVoting)),
                                    collateralAddressStr,
                                    dmn.pdmnState->pubKeyOperator.ToString());
            if (!strFilter.empty() && strInfo.find(strFilter) == std::string::npos &&
                strOutpoint.find(strFilter) == std::string::npos)
                return;
            UniValue objMN(UniValue::VOBJ);
            objMN.pushKV("proTxHash", dmn.proTxHash.ToString());
            objMN.pushKV("address", dmn.pdmnState->netInfo->GetPrimary().ToStringAddrPort());
            objMN.pushKV("addresses", GetNetInfoWithLegacyFields(*dmn.pdmnState, dmn.nType));
            objMN.pushKV("payee", payeeStr);
            objMN.pushKV("status", dmnToStatus(dmn));
            objMN.pushKV("type", std::string(GetMnType(dmn.nType).description));
            if (dmn.nType == MnType::Evo) {
                objMN.pushKV("platformNodeID", dmn.pdmnState->platformNodeID.ToString());
                objMN.pushKV("platformP2PPort", GetPlatformPort</*is_p2p=*/true>(*dmn.pdmnState));
                objMN.pushKV("platformHTTPPort", GetPlatformPort</*is_p2p=*/false>(*dmn.pdmnState));
            }
            objMN.pushKV("pospenaltyscore", dmn.pdmnState->nPoSePenalty);
            objMN.pushKV("consecutivePayments", dmn.pdmnState->nConsecutivePayments);
            objMN.pushKV("lastpaidtime", dmnToLastPaidTime(dmn));
            objMN.pushKV("lastpaidblock", dmn.pdmnState->nLastPaidHeight);
            objMN.pushKV("owneraddress", EncodeDestination(PKHash(dmn.pdmnState->keyIDOwner)));
            objMN.pushKV("votingaddress", EncodeDestination(PKHash(dmn.pdmnState->keyIDVoting)));
            objMN.pushKV("collateraladdress", collateralAddressStr);
            objMN.pushKV("pubkeyoperator", dmn.pdmnState->pubKeyOperator.ToString());
            obj.pushKV(strOutpoint, objMN);
        } else if (strMode == "lastpaidblock") {
            if (!strFilter.empty() && strOutpoint.find(strFilter) == std::string::npos) return;
            obj.pushKV(strOutpoint, dmn.pdmnState->nLastPaidHeight);
        } else if (strMode == "lastpaidtime") {
            if (!strFilter.empty() && strOutpoint.find(strFilter) == std::string::npos) return;
            obj.pushKV(strOutpoint, dmnToLastPaidTime(dmn));
        } else if (strMode == "payee") {
            if (!strFilter.empty() && payeeStr.find(strFilter) == std::string::npos &&
                strOutpoint.find(strFilter) == std::string::npos)
                return;
            obj.pushKV(strOutpoint, payeeStr);
        } else if (strMode == "owneraddress") {
            if (!strFilter.empty() && strOutpoint.find(strFilter) == std::string::npos) return;
            obj.pushKV(strOutpoint, EncodeDestination(PKHash(dmn.pdmnState->keyIDOwner)));
        } else if (strMode == "pubkeyoperator") {
            if (!strFilter.empty() && strOutpoint.find(strFilter) == std::string::npos) return;
            obj.pushKV(strOutpoint, dmn.pdmnState->pubKeyOperator.ToString());
        } else if (strMode == "status") {
            std::string strStatus = dmnToStatus(dmn);
            if (!strFilter.empty() && strStatus.find(strFilter) == std::string::npos &&
                strOutpoint.find(strFilter) == std::string::npos)
                return;
            obj.pushKV(strOutpoint, strStatus);
        } else if (strMode == "votingaddress") {
            if (!strFilter.empty() && strOutpoint.find(strFilter) == std::string::npos) return;
            obj.pushKV(strOutpoint, EncodeDestination(PKHash(dmn.pdmnState->keyIDVoting)));
        }
    });

    return obj;
},
    };
}

static RPCHelpMan masternodelist()
{
    return masternodelist_helper(false);
}

static RPCHelpMan masternodelist_composite()
{
    return masternodelist_helper(true);
}

#ifdef ENABLE_WALLET
Span<const CRPCCommand> GetWalletMasternodeRPCCommands()
{
    static const CRPCCommand commands[]{
        {"kerrigan", &masternode_outputs},
        {"kerrigan", &unlockmasternode},
    };
    return commands;
}
#endif // ENABLE_WALLET

void RegisterMasternodeRPCCommands(CRPCTable &t)
{
    static const CRPCCommand commands[]{
        {"kerrigan", &masternode_help},
        {"kerrigan", &masternodelist_composite},
        {"kerrigan", &masternodelist},
        {"kerrigan", &masternode_connect},
        {"kerrigan", &masternode_count},
        {"kerrigan", &masternode_status},
        {"kerrigan", &masternode_payments},
        {"kerrigan", &masternode_winners},
    };
    for (const auto& command : commands) {
        t.appendCommand(command.name, &command);
    }
}
