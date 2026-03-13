// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <deploymentstatus.h>
#include <node/context.h>
#include <primitives/block.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <hmp/identity.h>
#include <hmp/privilege.h>
#include <univalue.h>
#include <validation.h>

static const char* TierToString(HMPPrivilegeTier tier)
{
    switch (tier) {
    case HMPPrivilegeTier::ELDER: return "elder";
    case HMPPrivilegeTier::NEW: return "new";
    case HMPPrivilegeTier::UNKNOWN: return "unknown";
    }
    return "unknown";
}

static RPCHelpMan gethmpinfo()
{
    return RPCHelpMan{"gethmpinfo",
        "Returns information about this daemon's Hivemind Protocol state.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "active", "whether HMP is active at current height"},
                {RPCResult::Type::NUM, "activation_height", "HMP activation height"},
                {RPCResult::Type::NUM, "stage", "current HMP bootstrap stage (1-4)"},
                {RPCResult::Type::NUM, "stage2_height", "height at which Stage 2 (commitments) opens"},
                {RPCResult::Type::NUM, "stage3_height", "height at which Stage 3 (soft seal) begins"},
                {RPCResult::Type::NUM, "stage4_height", "height at which Stage 4 (full HMP) activates"},
                {RPCResult::Type::STR_HEX, "identity", "this daemon's HMP public key"},
                {RPCResult::Type::STR, "tier_x11", "privilege tier for X11"},
                {RPCResult::Type::STR, "tier_kawpow", "privilege tier for KawPoW"},
                {RPCResult::Type::STR, "tier_equihash200", "privilege tier for Equihash<200,9>"},
                {RPCResult::Type::STR, "tier_equihash192", "privilege tier for Equihash<192,7>"},
                {RPCResult::Type::NUM, "privileged_count", "total unique privileged participants"},
                {RPCResult::Type::NUM, "window_height", "current privilege window tip height"},
            }
        },
        RPCExamples{
            HelpExampleCli("gethmpinfo", "")
            + HelpExampleRpc("gethmpinfo", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const auto& consensus = Params().GetConsensus();
            ChainstateManager& chainman = EnsureAnyChainman(request.context);

            UniValue result(UniValue::VOBJ);

            int currentHeight;
            {
                LOCK(cs_main);
                currentHeight = chainman.ActiveChain().Height();
            }

            bool active = currentHeight >= consensus.HMPHeight;
            result.pushKV("active", active);
            result.pushKV("activation_height", consensus.HMPHeight);

            // Report 4-stage bootstrap status (#410)
            int stage;
            if (currentHeight < consensus.nHMPStage2Height) {
                stage = 1;
            } else if (currentHeight < consensus.nHMPStage3Height) {
                stage = 2;
            } else if (currentHeight < consensus.nHMPStage4Height) {
                stage = 3;
            } else {
                stage = 4;
            }
            result.pushKV("stage", stage);
            result.pushKV("stage2_height", consensus.nHMPStage2Height);
            result.pushKV("stage3_height", consensus.nHMPStage3Height);
            result.pushKV("stage4_height", consensus.nHMPStage4Height);

            if (g_hmp_identity && g_hmp_identity->IsValid()) {
                result.pushKV("identity", g_hmp_identity->GetPublicKey().ToString());
            } else {
                result.pushKV("identity", "not_initialized");
            }

            if (g_hmp_privilege) {
                const auto& pk = g_hmp_identity ? g_hmp_identity->GetPublicKey() : CBLSPublicKey();
                result.pushKV("tier_x11", TierToString(g_hmp_privilege->GetTier(pk, ALGO_X11)));
                result.pushKV("tier_kawpow", TierToString(g_hmp_privilege->GetTier(pk, ALGO_KAWPOW)));
                result.pushKV("tier_equihash200", TierToString(g_hmp_privilege->GetTier(pk, ALGO_EQUIHASH_200)));
                result.pushKV("tier_equihash192", TierToString(g_hmp_privilege->GetTier(pk, ALGO_EQUIHASH_192)));
                result.pushKV("privileged_count", (uint64_t)g_hmp_privilege->GetTotalPrivilegedCount());
                result.pushKV("window_height", g_hmp_privilege->GetTipHeight());
            }

            return result;
        }
    };
}

static RPCHelpMan gethmpprivilegedset()
{
    return RPCHelpMan{"gethmpprivilegedset",
        "Returns the current privileged set for all mining algorithms.\n",
        {
            {"algo", RPCArg::Type::STR, RPCArg::Default{"all"}, "Filter by algorithm: x11, kawpow, equihash200, equihash192, or all"},
        },
        RPCResult{
            RPCResult::Type::OBJ_DYN, "", "keyed by algo name (x11, kawpow, equihash200, equihash192)",
            {
                {RPCResult::Type::ARR, "algo_name", "privileged set for this algorithm",
                    {{RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "pubkey", "BLS public key"},
                            {RPCResult::Type::STR, "tier", "privilege tier (UNKNOWN, NEW, ELDER)"},
                            {RPCResult::Type::NUM, "blocks_solved", "blocks solved in window"},
                            {RPCResult::Type::NUM, "seal_participations", "seal signatures in window"},
                        }
                    }}
                },
            }
        },
        RPCExamples{
            HelpExampleCli("gethmpprivilegedset", "")
            + HelpExampleCli("gethmpprivilegedset", "kawpow")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!g_hmp_privilege) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "HMP privilege tracker not initialized");
            }

            std::string algoFilter = "all";
            if (!request.params[0].isNull()) {
                algoFilter = request.params[0].get_str();
            }

            if (algoFilter != "all" && algoFilter != "x11" && algoFilter != "kawpow" &&
                algoFilter != "equihash200" && algoFilter != "equihash192") {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Invalid algo filter. Use: all, x11, kawpow, equihash200, equihash192");
            }

            // #535: Hold cs_main for a consistent snapshot across all algo queries
            LOCK(cs_main);

            UniValue result(UniValue::VOBJ);

            auto addAlgoSet = [&](const std::string& name, int algo) {
                UniValue arr(UniValue::VARR);
                auto privileged = g_hmp_privilege->GetPrivilegedSet(algo);
                for (const auto& pk : privileged) {
                    UniValue entry(UniValue::VOBJ);
                    entry.pushKV("pubkey", pk.ToString());
                    entry.pushKV("tier", TierToString(g_hmp_privilege->GetTier(pk, algo)));
                    auto rec = g_hmp_privilege->GetRecord(pk, algo);
                    entry.pushKV("blocks_solved", rec.blocks_solved);
                    entry.pushKV("seal_participations", rec.seal_participations);
                    arr.push_back(entry);
                }
                result.pushKV(name, arr);
            };

            if (algoFilter == "all" || algoFilter == "x11") addAlgoSet("x11", ALGO_X11);
            if (algoFilter == "all" || algoFilter == "kawpow") addAlgoSet("kawpow", ALGO_KAWPOW);
            if (algoFilter == "all" || algoFilter == "equihash200") addAlgoSet("equihash200", ALGO_EQUIHASH_200);
            if (algoFilter == "all" || algoFilter == "equihash192") addAlgoSet("equihash192", ALGO_EQUIHASH_192);

            return result;
        }
    };
}

static RPCHelpMan getsealstatus()
{
    return RPCHelpMan{"getsealstatus",
        "Returns Hivemind seal information for a given block.\n",
        {
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash to query seal status for"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "blockhash", "the queried block hash"},
                {RPCResult::Type::NUM, "height", "block height"},
                {RPCResult::Type::NUM, "seal_weight", "seal quality in basis points (10000 = no seal, >10000 = sealed)"},
                {RPCResult::Type::BOOL, "has_seal", "whether this block has a seal bonus (seal_weight > 10000)"},
                {RPCResult::Type::STR, "miner_identity", "miner's HMP pubkey from CCbTx, or \"none\""},
            }
        },
        RPCExamples{
            HelpExampleCli("getsealstatus", "\"00000000000000001234...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            ChainstateManager& chainman = EnsureAnyChainman(request.context);

            uint256 hash(ParseHashV(request.params[0], "blockhash"));

            UniValue result(UniValue::VOBJ);

            // #516: Hold cs_main while reading CBlockIndex fields
            LOCK(cs_main);
            const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
            if (!pindex) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
            }

            result.pushKV("blockhash", pindex->GetBlockHash().GetHex());
            result.pushKV("height", pindex->nHeight);
            result.pushKV("seal_weight", pindex->nSealWeight);
            result.pushKV("has_seal", pindex->nSealWeight > 10000);
            result.pushKV("miner_identity", pindex->hmpMinerPubKey.IsValid() ? pindex->hmpMinerPubKey.ToString() : "none");

            return result;
        }
    };
}

void RegisterHMPRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"hmp", &gethmpinfo},
        {"hmp", &gethmpprivilegedset},
        {"hmp", &getsealstatus},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
