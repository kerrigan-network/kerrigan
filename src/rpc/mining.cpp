// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Copyright (c) 2014-2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <crypto/equihash.h>
#include <crypto/ethash/include/ethash/ethash.hpp>
#include <crypto/ethash/include/ethash/progpow.hpp>
#include <deploymentinfo.h>
#include <deploymentstatus.h>
#include <httpserver.h> // g_rpc_algo_ports
#include <key_io.h>
#include <llmq/blockprocessor.h>
#include <llmq/context.h>
#include <evo/evodb.h>
#include <net.h>
#include <node/context.h>
#include <node/miner.h>
#include <governance/governance.h>
#include <pow.h>
#include <rpc/blockchain.h>
#include <rpc/mining.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <shutdown.h>
#include <spork.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/system.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <warnings.h>

#include <governance/classes.h>
#include <governance/governance.h>
#include <masternode/sync.h>

#include <memory>
#include <stdint.h>

using node::BlockAssembler;
using node::CBlockTemplate;
using node::NodeContext;
using node::UpdateTime;

/**
 * Parse an algo name from a UniValue parameter and validate it.
 * Returns a valid algo index in [0, NUM_ALGOS).
 * @param param   The RPC parameter (may be null, in which case defaultAlgo is used).
 * @param defaultAlgo  Fallback algorithm name when param is null (default: "x11").
 * @throws JSONRPCError if the algorithm name is unrecognized.
 */
static int ParseAlgoParam(const UniValue& param, const std::string& defaultAlgo = "x11")
{
    std::string strAlgo = param.isNull() ? defaultAlgo : param.get_str();
    int algo = GetAlgoByName(strAlgo, -1);
    if (algo < 0 || algo >= NUM_ALGOS) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "Invalid algorithm. Use: x11, kawpow, equihash200, equihash192");
    }
    return algo;
}

/**
 * Return average network hashes per second based on the last 'lookup' blocks,
 * or from the last difficulty change if 'lookup' is nonpositive.
 * If 'height' is nonnegative, compute the estimate at the time when a given block was found.
 */
static UniValue GetNetworkHashPS(int lookup, int height, const CChain& active_chain) {
    const CBlockIndex* pb = active_chain.Tip();

    if (height >= 0 && height < active_chain.Height()) {
        pb = active_chain[height];
    }

    if (pb == nullptr || !pb->nHeight)
        return 0;

    // If lookup is -1, then use blocks since last difficulty change.
    if (lookup <= 0)
        lookup = pb->nHeight % Params().GetConsensus().DifficultyAdjustmentInterval() + 1;

    // If lookup is larger than chain, then set it to chain length.
    if (lookup > pb->nHeight)
        lookup = pb->nHeight;

    const CBlockIndex* pb0 = pb;
    int64_t minTime = pb0->GetBlockTime();
    int64_t maxTime = minTime;
    for (int i = 0; i < lookup; i++) {
        pb0 = pb0->pprev;
        int64_t time = pb0->GetBlockTime();
        minTime = std::min(time, minTime);
        maxTime = std::max(time, maxTime);
    }

    // In case there's a situation where minTime == maxTime, we don't want a divide by zero exception.
    if (minTime == maxTime)
        return 0;

    arith_uint256 workDiff = pb->nChainWork - pb0->nChainWork;
    int64_t timeDiff = maxTime - minTime;

    return workDiff.getdouble() / timeDiff;
}

/** Return average network hashes per second for a specific mining algorithm. */
static double GetNetworkHashPSForAlgo(int lookup, int height, const CChain& active_chain, int algo)
{
    const CBlockIndex* pb = active_chain.Tip();
    if (height >= 0 && height < active_chain.Height())
        pb = active_chain[height];
    if (!pb || !pb->nHeight) return 0;
    if (lookup <= 0) lookup = 120; // ~16 hours per-algo on a 4-algo chain

    // Walk backward collecting blocks that match this algo,
    // summing per-algo work (not nChainWork which includes all algos).
    const CBlockIndex* pAlgoTip = nullptr;
    const CBlockIndex* pAlgoOldest = nullptr;
    int algoCount = 0;
    arith_uint256 algoWork = 0;

    for (const CBlockIndex* pi = pb; pi && pi->nHeight > 0; pi = pi->pprev) {
        if (pi->GetAlgo() != algo) continue;
        if (!pAlgoTip) pAlgoTip = pi;
        algoWork += GetBlockProof(*pi);
        pAlgoOldest = pi;
        algoCount++;
        if (algoCount >= lookup) break;
    }

    if (algoCount < 2 || !pAlgoTip || !pAlgoOldest) return 0;

    int64_t timeDiff = pAlgoTip->GetBlockTime() - pAlgoOldest->GetBlockTime();
    if (timeDiff <= 0) return 0;

    return algoWork.getdouble() / timeDiff;
}

static RPCHelpMan getnetworkhashps()
{
    return RPCHelpMan{"getnetworkhashps",
                "\nReturns the estimated network hashes per second based on the last n blocks.\n"
                "Pass in [blocks] to override # of blocks, -1 specifies since last difficulty change.\n"
                "Pass in [height] to estimate the network speed at the time when a certain block was found.\n"
                "Pass in [algo] to get the estimate for a specific mining algorithm only.\n",
                {
                    {"nblocks", RPCArg::Type::NUM, RPCArg::Default{120}, "The number of blocks, or -1 for blocks since last difficulty change. Defaults to 480 when algo is specified."},
                    {"height", RPCArg::Type::NUM, RPCArg::Default{-1}, "To estimate at the time of the given height."},
                    {"algo", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Mining algorithm: x11, kawpow, equihash200, equihash192. Omit for combined hashrate."},
                },
                RPCResult{
                    RPCResult::Type::NUM, "", "Hashes per second estimated"},
                RPCExamples{
                    HelpExampleCli("getnetworkhashps", "")
            + HelpExampleCli("getnetworkhashps", "480 -1 \"kawpow\"")
            + HelpExampleRpc("getnetworkhashps", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);

    // If algo is specified, use the per-algo estimator with a larger default lookback
    // (480 algo-specific blocks, ~64 hours per algo on a 4-algo chain) to reduce
    // variance that causes pool hashrate to appear >100% of network.
    if (!request.params[2].isNull()) {
        int algo = GetAlgoByName(request.params[2].get_str(), -1);
        if (algo < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown algorithm: " + request.params[2].get_str());
        int lookup = !request.params[0].isNull() ? request.params[0].getInt<int>() : 480;
        int height = !request.params[1].isNull() ? request.params[1].getInt<int>() : -1;
        return GetNetworkHashPSForAlgo(lookup, height, chainman.ActiveChain(), algo);
    }

    return GetNetworkHashPS(!request.params[0].isNull() ? request.params[0].getInt<int>() : 120, !request.params[1].isNull() ? request.params[1].getInt<int>() : -1, chainman.ActiveChain());
},
    };
}

#if ENABLE_MINER
static bool GenerateBlock(ChainstateManager& chainman, CBlock& block, uint64_t& max_tries, uint256& block_hash)
{
    block_hash.SetNull();
    block.hashMerkleRoot = BlockMerkleRoot(block);

    const CChainParams& chainparams(Params());
    const Consensus::Params& consensus = chainparams.GetConsensus();
    int algo = block.GetAlgo();

    switch (algo) {
        case ALGO_X11:
        {
            while (max_tries > 0 && block.nNonce < std::numeric_limits<uint32_t>::max() &&
                   !CheckProofOfWork(block.GetHash(), block.nBits, consensus, block.GetAlgo()) && !ShutdownRequested()) {
                ++block.nNonce;
                --max_tries;
            }
            if (max_tries == 0 || ShutdownRequested()) return false;
            if (block.nNonce == std::numeric_limits<uint32_t>::max()) return true; // exhausted, no solution
            break;
        }

        case ALGO_KAWPOW:
        {
            int height = static_cast<int>(block.nHeight);
            int epoch_number = ethash::get_epoch_number(height);
            const ethash::epoch_context_full& ctx = ethash::get_global_epoch_context_full(epoch_number);

            // ProgPoW seed hash: sha256d of 80-byte header (RVN standard). (#801)
            ethash::hash256 header_h;
            CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
            hw << block.nVersion << block.hashPrevBlock << block.hashMerkleRoot
               << block.nTime << block.nBits << block.nNonce;
            uint256 hdrHash = hw.GetHash();
            // ethash is big-endian, uint256 is little-endian; reverse bytes
            for (int i = 0; i < 32; ++i)
                header_h.bytes[i] = *(hdrHash.begin() + 31 - i);

            arith_uint256 bnTarget;
            bnTarget.SetCompact(block.nBits);
            ethash::hash256 boundary;
            uint256 boundaryU256 = ArithToUint256(bnTarget);
            // ethash uses big-endian (bytes[0]=MSB), uint256 is little-endian (begin()=LSB)
            // Reverse bytes so the boundary comparison in progpow::search is correct
            for (int i = 0; i < 32; ++i)
                boundary.bytes[i] = *(boundaryU256.begin() + 31 - i);

            uint64_t start_nonce = 0;
            while (max_tries > 0 && !ShutdownRequested()) {
                size_t iterations = std::min(max_tries, static_cast<uint64_t>(1024));
                ethash::search_result sr = progpow::search(ctx, height, header_h, boundary, start_nonce, iterations);
                max_tries -= iterations;
                if (sr.solution_found) {
                    block.nNonce64 = sr.nonce;
                    // Reverse bytes: ethash big-endian to uint256 little-endian
                    for (int i = 0; i < 32; ++i)
                        *(block.mix_hash.begin() + i) = sr.mix_hash.bytes[31 - i];
                    break;
                }
                start_nonce += iterations;
            }
            if (max_tries == 0 || ShutdownRequested()) return false;
            break;
        }

        case ALGO_EQUIHASH_200:
        case ALGO_EQUIHASH_192:
        {
            unsigned int n, k;
            if (algo == ALGO_EQUIHASH_200) { n = 200; k = 9; }
            else { n = 192; k = 7; }

            bool found = false;
            while (max_tries > 0 && !found && !ShutdownRequested()) {
                --max_tries;

                eh_HashState state;
                EhInitialiseState(n, k, state);

                // CEquihashInput = 108 bytes + nNonce256 = 32 bytes = 140 bytes total
                CEquihashInput I{block};
                CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                ss << I;
                ss << block.nNonce256;
                crypto_generichash_blake2b_update(&state, reinterpret_cast<const unsigned char*>(ss.data()), ss.size());

                EhBasicSolveUncancellable(n, k, state, [&](std::vector<unsigned char> soln) {
                    block.nSolution = soln;
                    if (CheckProofOfWork(block.GetPoWAlgoHash(consensus), block.nBits, consensus, block.GetAlgo())) {
                        found = true;
                        return true; // stop solving
                    }
                    return false; // keep looking
                });

                if (!found) {
                    // Increment 32-byte nonce (little-endian byte-level increment)
                    for (int i = 0; i < 32; ++i) {
                        if (++*(block.nNonce256.begin() + i) != 0)
                            break;
                    }
                }
            }
            if (max_tries == 0 || ShutdownRequested()) return false;
            break;
        }

        default:
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Unknown mining algorithm");
    }

    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(block);
    if (!chainman.ProcessNewBlock(shared_pblock, true, nullptr)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNewBlock, block not accepted");
    }

    block_hash = block.GetHash();
    return true;
}

static UniValue generateBlocks(ChainstateManager& chainman, const NodeContext& node, const CTxMemPool& mempool, const CScript& coinbase_script,
                               int nGenerate, uint64_t nMaxTries, int algo = ALGO_X11)
{
    EnsureLLMQContext(node);

    UniValue blockHashes(UniValue::VARR);
    while (nGenerate > 0 && !ShutdownRequested()) {
        std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(chainman.ActiveChainstate(), node, &mempool, Params()).CreateNewBlock(coinbase_script));
        if (!pblocktemplate.get())
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");
        CBlock *pblock = &pblocktemplate->block;

        pblock->SetAlgo(algo);
        {
            LOCK(cs_main);
            const CBlockIndex* pindexPrev = chainman.ActiveChain().Tip();
            pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, Params().GetConsensus(), algo);
            // For KawPoW, set nHeight (needed for epoch context) under the
            // same lock so nBits and nHeight are consistent with the same tip.
            if (algo == ALGO_KAWPOW) {
                pblock->nHeight = pindexPrev->nHeight + 1;
            }
        }

        uint256 block_hash;
        if (!GenerateBlock(chainman, *pblock, nMaxTries, block_hash)) {
            break;
        }

        if (!block_hash.IsNull()) {
            --nGenerate;
            blockHashes.push_back(block_hash.GetHex());
        }
    }
    return blockHashes;
}

static bool getScriptFromDescriptor(const std::string& descriptor, CScript& script, std::string& error)
{
    FlatSigningProvider key_provider;
    const auto desc = Parse(descriptor, key_provider, error, /* require_checksum = */ false);
    if (desc) {
        if (desc->IsRange()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Ranged descriptor not accepted. Maybe pass through deriveaddresses first?");
        }

        FlatSigningProvider provider;
        std::vector<CScript> scripts;
        if (!desc->Expand(0, key_provider, scripts, provider)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot derive script without private keys");
        }

        // Combo descriptors can have 2 or 4 scripts, so we can't just check scripts.size() == 1
        CHECK_NONFATAL(scripts.size() > 0 && scripts.size() <= 4);

        if (scripts.size() == 1) {
            script = scripts.at(0);
        } else if (scripts.size() == 4) {
            // For uncompressed keys, take the 3rd script, since it is p2wpkh
            script = scripts.at(2);
        } else {
            // Else take the 2nd script, since it is p2pkh
            script = scripts.at(1);
        }

        return true;
    } else {
        return false;
    }
}

static RPCHelpMan generatetodescriptor()
{
    return RPCHelpMan{
        "generatetodescriptor",
        "Mine to a specified descriptor and return the block hashes.",
        {
            {"num_blocks", RPCArg::Type::NUM, RPCArg::Optional::NO, "How many blocks are generated."},
            {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "The descriptor to send the newly generated coins to."},
            {"maxtries", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_MAX_TRIES}, "How many iterations to try."},
            {"algo", RPCArg::Type::STR, RPCArg::Default{"x11"}, "Mining algorithm: x11, kawpow, equihash200, equihash192"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
                {
                        {RPCResult::Type::STR_HEX, "blockhashes", "hashes of blocks generated"},
                }
        },
        RPCExamples{
            "\nGenerate 11 blocks to mydesc\n" + HelpExampleCli("generatetodescriptor", "11 \"mydesc\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const int num_blocks{request.params[0].getInt<int>()};
    const int64_t raw_tries = request.params[2].isNull() ? (int64_t)DEFAULT_MAX_TRIES : request.params[2].getInt<int64_t>();
    if (raw_tries < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "maxtries must be non-negative");
    const uint64_t max_tries = static_cast<uint64_t>(raw_tries);

    // Parse algo parameter
    int algo = ParseAlgoParam(request.params[3]);

    CScript coinbase_script;
    std::string error;
    if (!getScriptFromDescriptor(request.params[1].get_str(), coinbase_script, error)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
    }

    const NodeContext& node = EnsureAnyNodeContext(request.context);
    const CTxMemPool& mempool = EnsureMemPool(node);
    ChainstateManager& chainman = EnsureChainman(node);

    return generateBlocks(chainman, node, mempool, coinbase_script, num_blocks, max_tries, algo);
},
    };
}

static RPCHelpMan generatetoaddress()
{
    return RPCHelpMan{"generatetoaddress",
        "\nMine to a specified address and return the block hashes.\n",
         {
             {"nblocks", RPCArg::Type::NUM, RPCArg::Optional::NO, "How many blocks are generated."},
             {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to send the newly generated coins to."},
             {"maxtries", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_MAX_TRIES}, "How many iterations to try."},
             {"algo", RPCArg::Type::STR, RPCArg::Default{"x11"}, "Mining algorithm: x11, kawpow, equihash200, equihash192"},
         },
         RPCResult{
             RPCResult::Type::ARR, "", "hashes of blocks generated",
             {
                 {RPCResult::Type::STR_HEX, "", "blockhash"},
             }},
         RPCExamples{
            "\nGenerate 11 blocks to myaddress\n"
            + HelpExampleCli("generatetoaddress", "11 \"myaddress\"")
            + "\nGenerate 1 KawPoW block\n"
            + HelpExampleCli("generatetoaddress", "1 \"myaddress\" 1000000 \"kawpow\"")
            + "If you are using the " PACKAGE_NAME " wallet, you can get a new address to send the newly generated coins to with:\n"
            + HelpExampleCli("getnewaddress", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const int num_blocks{request.params[0].getInt<int>()};
    const int64_t raw_tries = request.params[2].isNull() ? (int64_t)DEFAULT_MAX_TRIES : request.params[2].getInt<int64_t>();
    if (raw_tries < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "maxtries must be non-negative");
    const uint64_t max_tries = static_cast<uint64_t>(raw_tries);

    CTxDestination destination = DecodeDestination(request.params[1].get_str());
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
    }

    // Parse algo parameter
    int algo = ParseAlgoParam(request.params[3]);

    const NodeContext& node = EnsureAnyNodeContext(request.context);
    const CTxMemPool& mempool = EnsureMemPool(node);
    ChainstateManager& chainman = EnsureChainman(node);

    CScript coinbase_script = GetScriptForDestination(destination);

    return generateBlocks(chainman, node, mempool, coinbase_script, num_blocks, max_tries, algo);
},
    };
}

static RPCHelpMan generateblock()
{
    return RPCHelpMan{"generateblock",
        "Mine a set of ordered transactions to a specified address or descriptor and return the block hash.",
        {
            {"output", RPCArg::Type::STR, RPCArg::Optional::NO, "The address or descriptor to send the newly generated coins to."},
            {"transactions", RPCArg::Type::ARR, RPCArg::Optional::NO, "An array of hex strings which are either txids or raw transactions.\n"
                "Txids must reference transactions currently in the mempool.\n"
                "All transactions must be valid and in valid order, otherwise the block will be rejected.",
                {
                    {"rawtx/txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""},
                },
            },
            {"algo", RPCArg::Type::STR, RPCArg::Default{"x11"}, "Mining algorithm: x11, kawpow, equihash200, equihash192"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hash", "hash of generated block"},
            }
        },
        RPCExamples{
            "\nGenerate a block to myaddress, with txs rawtx and mempool_txid\n"
            + HelpExampleCli("generateblock", R"("myaddress" '["rawtx", "mempool_txid"]')")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto address_or_descriptor = request.params[0].get_str();
    CScript coinbase_script;
    std::string error;

    if (!getScriptFromDescriptor(address_or_descriptor, coinbase_script, error)) {
        const auto destination = DecodeDestination(address_or_descriptor);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address or descriptor");
        }

        coinbase_script = GetScriptForDestination(destination);
    }

    // Parse algo parameter
    int algo = ParseAlgoParam(request.params[2]);

    const NodeContext& node = EnsureAnyNodeContext(request.context);
    const CTxMemPool& mempool = EnsureMemPool(node);

    std::vector<CTransactionRef> txs;
    const auto raw_txs_or_txids = request.params[1].get_array();
    for (size_t i = 0; i < raw_txs_or_txids.size(); i++) {
        const auto str(raw_txs_or_txids[i].get_str());

        uint256 hash;
        CMutableTransaction mtx;
        if (ParseHashStr(str, hash)) {

            const auto tx = mempool.get(hash);
            if (!tx) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Transaction %s not in mempool.", str));
            }

            txs.emplace_back(tx);

        } else if (DecodeHexTx(mtx, str)) {
            txs.push_back(MakeTransactionRef(std::move(mtx)));

        } else {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Transaction decode failed for %s. Make sure the tx has at least one input.", str));
        }
    }

    const CChainParams& chainparams(Params());

    ChainstateManager& chainman = EnsureChainman(node);
    CChainState& active_chainstate = chainman.ActiveChainstate();

    CBlock block;
    {
        LOCK(cs_main);

        std::unique_ptr<CBlockTemplate> blocktemplate(BlockAssembler(active_chainstate, node, nullptr, chainparams).CreateNewBlock(coinbase_script));
        if (!blocktemplate) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");
        }
        block = blocktemplate->block;
    }

    block.SetAlgo(algo);
    {
        LOCK(cs_main);
        const CBlockIndex* pindexPrev = chainman.ActiveChain().Tip();
        block.nBits = GetNextWorkRequired(pindexPrev, &block, Params().GetConsensus(), algo);
        if (algo == ALGO_KAWPOW) {
            block.nHeight = pindexPrev->nHeight + 1;
        }
    }

    // 1 coinbase + could have a few quorum commitments
    CHECK_NONFATAL(block.vtx.size() >= 1);

    // Add transactions
    block.vtx.insert(block.vtx.end(), txs.begin(), txs.end());

    {
        LOCK(cs_main);

        BlockValidationState state;
        if (!TestBlockValidity(state, *CHECK_NONFATAL(node.chainlocks), *CHECK_NONFATAL(node.evodb), chainparams, active_chainstate,
                               block, chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock), false, false)) {
            throw JSONRPCError(RPC_VERIFY_ERROR, strprintf("TestBlockValidity failed: %s", state.GetRejectReason()));
        }
    }

    uint256 block_hash;
    uint64_t max_tries{DEFAULT_MAX_TRIES};

    if (!GenerateBlock(chainman, block, max_tries, block_hash) || block_hash.IsNull()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Failed to make block.");
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("hash", block_hash.GetHex());
    return obj;
},
    };
}
#else
static RPCHelpMan generatetoaddress()
{
    return RPCHelpMan{"generatetoaddress", "This call is not available because RPC miner isn't compiled", {}, {}, RPCExamples{""}, [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "This call is not available because RPC miner isn't compiled");
    }};
}

static RPCHelpMan generatetodescriptor()
{
    return RPCHelpMan{"generatetodescriptor", "This call is not available because RPC miner isn't compiled", {}, {}, RPCExamples{""}, [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "This call is not available because RPC miner isn't compiled");
    }};
}
static RPCHelpMan generateblock()
{
    return RPCHelpMan{"generateblock", "This call is not available because RPC miner isn't compiled", {}, {}, RPCExamples{""}, [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "This call is not available because RPC miner isn't compiled");
    }};
}
#endif // ENABLE_MINER

static RPCHelpMan getmininginfo()
{
    return RPCHelpMan{"getmininginfo",
                "\nReturns a json object containing mining-related information.",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "blocks", "The current block"},
                        {RPCResult::Type::NUM, "currentblocksize", /*optional=*/true, "The block size of the last assembled block (only present if a block was ever assembled)"},
                        {RPCResult::Type::NUM, "currentblocktx", /*optional=*/true, "The number of block transactions of the last assembled block (only present if a block was ever assembled)"},
                        {RPCResult::Type::NUM, "difficulty", "The current difficulty (algo-specific on rpcalgoport)"},
                        {RPCResult::Type::STR, "algo", /*optional=*/true, "The mining algorithm (present on rpcalgoport)"},
                        {RPCResult::Type::NUM, "networkhashps", "The network hashes per second (algo-specific on rpcalgoport)"},
                        {RPCResult::Type::OBJ, "difficulties", "Per-algorithm difficulty",
                        {
                            {RPCResult::Type::NUM, "x11", "X11 difficulty"},
                            {RPCResult::Type::NUM, "kawpow", "KawPoW difficulty"},
                            {RPCResult::Type::NUM, "equihash200", "Equihash(200,9) difficulty"},
                            {RPCResult::Type::NUM, "equihash192", "Equihash(192,7) difficulty"},
                        }},
                        {RPCResult::Type::OBJ, "networkhashps_per_algo", "Per-algorithm network hashes per second",
                        {
                            {RPCResult::Type::NUM, "x11", "X11 network hashrate"},
                            {RPCResult::Type::NUM, "kawpow", "KawPoW network hashrate"},
                            {RPCResult::Type::NUM, "equihash200", "Equihash(200,9) network hashrate"},
                            {RPCResult::Type::NUM, "equihash192", "Equihash(192,7) network hashrate"},
                        }},
                        {RPCResult::Type::NUM, "pooledtx", "The size of the mempool"},
                        {RPCResult::Type::STR, "chain", "current network name (main, test, devnet, regtest)"},
                        {RPCResult::Type::STR, "warnings", "any network and blockchain warnings"},
                    }},
                RPCExamples{
                    HelpExampleCli("getmininginfo", "")
            + HelpExampleRpc("getmininginfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{

    const NodeContext& node = EnsureAnyNodeContext(request.context);

    ChainstateManager& chainman = EnsureChainman(node);
    LOCK(cs_main);

    const CTxMemPool& mempool = EnsureMemPool(node);
    const CChain& active_chain = chainman.ActiveChain();

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("blocks",           active_chain.Height());
    if (BlockAssembler::m_last_block_size) obj.pushKV("currentblocksize", *BlockAssembler::m_last_block_size);
    if (BlockAssembler::m_last_block_num_txs) obj.pushKV("currentblocktx", *BlockAssembler::m_last_block_num_txs);

    // Scalar "difficulty" and "networkhashps" are for backward compat with
    // single-algo tools. Per-algo breakdowns are in "difficulties" and
    // "networkhashps_per_algo". On algo-specific RPC ports, the scalars
    // report that algo's values; otherwise they report the chain tip.
    auto algoPortIt = g_rpc_algo_ports.find(request.localPort);
    int algoSelected = -1;
    if (algoPortIt != g_rpc_algo_ports.end()) {
        algoSelected = algoPortIt->second;
    } else {
        std::string powalgo = gArgs.GetArg("-powalgo", "");
        if (!powalgo.empty()) {
            int a = GetAlgoByName(powalgo, -1);
            if (a >= 0 && a < NUM_ALGOS) algoSelected = a;
        }
    }
    if (algoSelected >= 0) {
        const CBlockIndex* pindexAlgo = GetLastBlockIndexForAlgo(active_chain.Tip(), chainman.GetConsensus(), algoSelected);
        if (pindexAlgo) {
            obj.pushKV("difficulty", (double)GetDifficulty(pindexAlgo));
        } else {
            obj.pushKV("difficulty", (double)GetDifficulty(active_chain.Tip()));
        }
        obj.pushKV("algo", GetAlgoName(algoSelected));
    } else {
        obj.pushKV("difficulty", (double)GetDifficulty(active_chain.Tip()));
    }

    // On algo-specific RPC ports or with -powalgo set, return algo-specific networkhashps
    if (algoSelected >= 0) {
        obj.pushKV("networkhashps", GetNetworkHashPSForAlgo(120, -1, active_chain, algoSelected));
    } else {
        obj.pushKV("networkhashps", getnetworkhashps().HandleRequest(request));
    }

    // 120-block per-algo lookback (~16 hours on a 4-algo chain).
    UniValue difficulties(UniValue::VOBJ);
    UniValue hashrates(UniValue::VOBJ);
    const Consensus::Params& consensusParams = chainman.GetConsensus();
    for (int a = 0; a < NUM_ALGOS; a++) {
        std::string name = GetAlgoName(a);
        const CBlockIndex* pAlgo = GetLastBlockIndexForAlgo(active_chain.Tip(), consensusParams, a);
        difficulties.pushKV(name, pAlgo ? (double)GetDifficulty(pAlgo) : 0.0);
        hashrates.pushKV(name, GetNetworkHashPSForAlgo(120, -1, active_chain, a));
    }
    obj.pushKV("difficulties", difficulties);
    obj.pushKV("networkhashps_per_algo", hashrates);

    obj.pushKV("pooledtx",         (uint64_t)mempool.size());
    obj.pushKV("chain",            Params().NetworkIDString());
    obj.pushKV("warnings",         GetWarnings(false).original);
    return obj;
},
    };
}


// NOTE: Unlike wallet RPC (which use BTC values), mining RPCs follow GBT (BIP 22) in using satoshi amounts
static RPCHelpMan prioritisetransaction()
{
    return RPCHelpMan{"prioritisetransaction",
        "Accepts the transaction into mined blocks at a higher (or lower) priority\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id."},
            {"fee_delta", RPCArg::Type::NUM, RPCArg::Optional::NO, "The fee value (in satoshis) to add (or subtract, if negative).\n"
    "                  Note, that this value is not a fee rate. It is a value to modify absolute fee of the TX.\n"
    "                  The fee is not actually paid, only the algorithm for selecting transactions into a block\n"
    "                  considers the transaction as it would have paid a higher (or lower) fee."},
        },
        RPCResult{
            RPCResult::Type::BOOL, "", "Returns true"},
        RPCExamples{
            HelpExampleCli("prioritisetransaction", "\"txid\" 10000")
    + HelpExampleRpc("prioritisetransaction", "\"txid\", 10000")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue

{
    LOCK(cs_main);

    uint256 hash(ParseHashV(request.params[0].get_str(), "txid"));
    CAmount nAmount = request.params[1].getInt<int64_t>();

    EnsureAnyMemPool(request.context).PrioritiseTransaction(hash, nAmount);
    return true;
},
    };
}


// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const BlockValidationState& state)
{
    if (state.IsValid())
        return UniValue::VNULL;

    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, state.ToString());
    if (state.IsInvalid())
    {
        std::string strRejectReason = state.GetRejectReason();
        if (strRejectReason.empty())
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?";
}

static std::string gbt_vb_name(const Consensus::DeploymentPos pos) {
    const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
    std::string s = vbinfo.name;
    if (!vbinfo.gbt_force) {
        s.insert(s.begin(), '!');
    }
    return s;
}

static RPCHelpMan getblocktemplate()
{
    return RPCHelpMan{"getblocktemplate",
        "\nIf the request parameters include a 'mode' key, that is used to explicitly select between the default 'template' request or a 'proposal'.\n"
        "It returns data needed to construct a block to work on.\n"
        "For full specification, see BIPs 22, 23, and 9:\n"
        "    https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki\n"
        "    https://github.com/bitcoin/bips/blob/master/bip-0023.mediawiki\n"
        "    https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki#getblocktemplate_changes\n",
        {
            {"template_request", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "Format of the template",
                {
                    {"mode", RPCArg::Type::STR, /* treat as named arg */ RPCArg::Optional::OMITTED_NAMED_ARG, "This must be set to \"template\", \"proposal\" (see BIP 23), or omitted"},
                    {"capabilities", RPCArg::Type::ARR, /* treat as named arg */ RPCArg::Optional::OMITTED_NAMED_ARG, "A list of strings",
                        {
                            {"str", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "client side supported feature, 'longpoll', 'coinbasevalue', 'proposal', 'serverlist', 'workid'"},
                        },
                        },
                    {"rules", RPCArg::Type::ARR, RPCArg::Optional::NO, "A list of strings",
                        {
                            {"str", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "client side supported softfork deployment"},
                        },
                        },
                    {"algo", RPCArg::Type::STR, RPCArg::Default{"x11"}, "Mining algorithm: x11, kawpow, equihash200, equihash192"},
                    {"pooladdress", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, "Pool payout address. When provided, coinbasetxn is included for all algos with this address in vout[0]."},
                },
                "\"template_request\""},
        },
        {
            RPCResult{"If the proposal was accepted with mode=='proposal'", RPCResult::Type::NONE, "", ""},
            RPCResult{"If the proposal was not accepted with mode=='proposal'", RPCResult::Type::STR, "", "According to BIP22"},
            RPCResult{"Otherwise", RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::ARR, "capabilities", "specific client side supported features",
                    {
                        {RPCResult::Type::STR, "", "capability"},
                    }},
                {RPCResult::Type::NUM, "version", "The preferred block version"},
                {RPCResult::Type::ARR, "rules", "specific block rules that are to be enforced",
                {
                    {RPCResult::Type::STR, "", "name of a rule the client must understand to some extent; see BIP 9 for format"},
                }},
                {RPCResult::Type::OBJ_DYN, "vbavailable", "set of pending, supported versionbit (BIP 9) softfork deployments",
                {
                    {RPCResult::Type::NUM, "rulename", "identifies the bit number as indicating acceptance and readiness for the named softfork rule"},
                }},
                {RPCResult::Type::NUM, "vbrequired", "bit mask of versionbits the server requires set in submissions"},
                {RPCResult::Type::STR, "previousblockhash", "The hash of current highest block"},
                {RPCResult::Type::ARR, "transactions", "contents of non-coinbase transactions that should be included in the next block",
                {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "data", "transaction data encoded in hexadecimal (byte-for-byte)"},
                        {RPCResult::Type::STR_HEX, "hash", "transaction hash encoded in little-endian hexadecimal"},
                        {RPCResult::Type::ARR, "depends", "array of numbers",
                        {
                            {RPCResult::Type::NUM, "", "transactions before this one (by 1-based index in 'transactions' list) that must be present in the final block if this one is"},
                        }},
                        {RPCResult::Type::NUM, "fee", "difference in value between transaction inputs and outputs (in satoshis); for coinbase transactions, this is a negative Number of the total collected block fees (ie, not including the block subsidy); if key is not present, fee is unknown and clients MUST NOT assume there isn't one"},
                        {RPCResult::Type::NUM, "sigops", "total number of SigOps, as counted for purposes of block limits; if key is not present, sigop count is unknown and clients MUST NOT assume there aren't any"},
                    }},
                }},
                {RPCResult::Type::OBJ_DYN, "coinbaseaux", "data that should be included in the coinbase's scriptSig content",
                {
                    {RPCResult::Type::STR_HEX, "key", "values must be in the coinbase (keys may be ignored)"},
                }},
                {RPCResult::Type::NUM, "coinbasevalue", "total value of all coinbase outputs (block reward + fees, in satoshis)"},
                {RPCResult::Type::NUM, "coinbasevalue_miner", "miner's share of the coinbase (vout[0], in satoshis)"},
                {RPCResult::Type::OBJ, "coinbasetxn", /*optional=*/true, "pre-built coinbase transaction (present for equihash algos, or when pooladdress is set)",
                    {
                        {RPCResult::Type::STR_HEX, "data", "serialized coinbase transaction in hex"},
                    }},
                {RPCResult::Type::STR, "longpollid", "an id to include with a request to longpoll on an update to this template"},
                {RPCResult::Type::STR, "target", "The hash target"},
                {RPCResult::Type::NUM_TIME, "mintime", "The minimum timestamp appropriate for the next block time, expressed in " + UNIX_EPOCH_TIME},
                {RPCResult::Type::ARR, "mutable", "list of ways the block template may be changed",
                {
                    {RPCResult::Type::STR, "value", "A way the block template may be changed, e.g. 'time', 'transactions', 'prevblock'"},
                }},
                {RPCResult::Type::STR_HEX, "noncerange", "A range of valid nonces"},
                {RPCResult::Type::NUM, "sigoplimit", "limit of sigops in blocks"},
                {RPCResult::Type::NUM, "sizelimit", "limit of block size"},
                {RPCResult::Type::NUM_TIME, "curtime", "current timestamp in " + UNIX_EPOCH_TIME},
                {RPCResult::Type::STR, "bits", "compressed target of next block"},
                {RPCResult::Type::STR, "previousbits", "compressed target of current highest block"},
                {RPCResult::Type::NUM, "height", "The height of the next block"},
                {RPCResult::Type::STR, "algo", "mining algorithm for this template (x11, kawpow, equihash200, equihash192)"},
                {RPCResult::Type::STR_HEX, "finalsaplingroothash", /*optional=*/true, "Sapling root hash (equihash algos only)"},
                {RPCResult::Type::NUM, "equihash_n", /*optional=*/true, "Equihash N parameter (equihash algos only)"},
                {RPCResult::Type::NUM, "equihash_k", /*optional=*/true, "Equihash K parameter (equihash algos only)"},
                {RPCResult::Type::STR, "personalization", /*optional=*/true, "Equihash personalization string (equihash algos only)"},
                {RPCResult::Type::STR_HEX, "header_hex", /*optional=*/true, "140-byte serialized header for equihash (equihash algos only)"},
                {RPCResult::Type::STR_HEX, "headerhash", /*optional=*/true, "header hash for KawPoW mining (kawpow only)"},
                {RPCResult::Type::STR_HEX, "seedhash", /*optional=*/true, "epoch seed hash for KawPoW (kawpow only)"},
                {RPCResult::Type::ARR, "masternode", "required masternode/treasury payments that must be included in the next block",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "payee", /*optional=*/true, "payee address (omitted for OP_RETURN burn outputs)"},
                                {RPCResult::Type::STR_HEX, "script", "payee scriptPubKey"},
                                {RPCResult::Type::NUM, "amount", "required amount to pay"},
                            }},
                    }},
                {RPCResult::Type::BOOL, "masternode_payments_started", "true, if masternode payments started"},
                {RPCResult::Type::STR_HEX, "coinbase_payload", "coinbase transaction payload data encoded in hexadecimal"},
                {RPCResult::Type::STR, "blockhash_algorithm", "algorithm used for block identity hashes (always x11)"},
                {RPCResult::Type::STR_HEX, "template_hash", "X11 identity hash of this block template"},
            }},
        },
        RPCExamples{
            HelpExampleCli("getblocktemplate", "")
    + HelpExampleCli("getblocktemplate", "'{\"rules\": [\"segwit\"], \"algo\": \"kawpow\"}'")
    + HelpExampleRpc("getblocktemplate", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const NodeContext& node = EnsureAnyNodeContext(request.context);

    ChainstateManager& chainman = EnsureChainman(node);
    LOCK(cs_main);

    std::string strMode = "template";
    UniValue lpval = NullUniValue;
    std::set<std::string> setClientRules;
    std::set<std::string> setClientCaps;
    CChainState& active_chainstate = chainman.ActiveChainstate();
    CChain& active_chain = active_chainstate.m_chain;
    if (!request.params[0].isNull())
    {
        const UniValue& oparam = request.params[0].get_obj();
        const UniValue& modeval = oparam.find_value("mode");
        if (modeval.isStr())
            strMode = modeval.get_str();
        else if (modeval.isNull())
        {
            /* Do nothing */
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
        lpval = oparam.find_value("longpollid");

        if (strMode == "proposal")
        {
            const UniValue& dataval = oparam.find_value("data");
            if (!dataval.isStr())
                throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

            CBlock block;
            if (!DecodeHexBlk(block, dataval.get_str()))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

            uint256 hash = block.GetHash();
            const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
            if (pindex) {
                if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                    return "duplicate";
                if (pindex->nStatus & BLOCK_FAILED_MASK)
                    return "duplicate-invalid";
                return "duplicate-inconclusive";
            }

            CBlockIndex* const pindexPrev = active_chain.Tip();
            // TestBlockValidity only supports blocks built on the current Tip
            if (block.hashPrevBlock != pindexPrev->GetBlockHash())
                return "inconclusive-not-best-prevblk";
            BlockValidationState state;
            TestBlockValidity(state, *CHECK_NONFATAL(node.chainlocks), *CHECK_NONFATAL(node.evodb), Params(), active_chainstate,
                              block, pindexPrev, false, true);
            return BIP22ValidationResult(state);
        }

        const UniValue& aClientRules = oparam.find_value("rules");
        if (aClientRules.isArray()) {
            for (unsigned int i = 0; i < aClientRules.size(); ++i) {
                const UniValue& v = aClientRules[i];
                setClientRules.insert(v.get_str());
            }
        }

        // Parse client capabilities (BIP22), used to gate optional fields like coinbasetxn
        const UniValue& aClientCaps = oparam.find_value("capabilities");
        if (aClientCaps.isArray()) {
            for (unsigned int i = 0; i < aClientCaps.size(); ++i) {
                setClientCaps.insert(aClientCaps[i].get_str());
            }
        }
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    // Parse algo: per-algo RPC port takes priority, then template_request param,
    // then -powalgo config fallback. Lets operators run one daemon per algo
    // without per-call algo dispatch by setting -powalgo in kerrigan.conf.
    int algo = GetAlgoByName(gArgs.GetArg("-powalgo", "x11"), ALGO_X11);
    if (algo < 0 || algo >= NUM_ALGOS) algo = ALGO_X11;
    auto algoPortIt = g_rpc_algo_ports.find(request.localPort);
    if (algoPortIt != g_rpc_algo_ports.end()) {
        algo = algoPortIt->second;
    } else if (!request.params[0].isNull()) {
        const UniValue& algoVal = request.params[0].get_obj().find_value("algo");
        if (algoVal.isStr()) {
            algo = ParseAlgoParam(algoVal);
        }
    }

    // Parse pooladdress: when provided, coinbasetxn is included for all algos
    // and the pool's payout output uses this address instead of OP_TRUE. (#871)
    CScript poolScript;
    bool hasPoolAddress = false;
    if (!request.params[0].isNull()) {
        const UniValue& poolVal = request.params[0].get_obj().find_value("pooladdress");
        if (poolVal.isStr()) {
            CTxDestination poolDest = DecodeDestination(poolVal.get_str());
            if (!IsValidDestination(poolDest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid pooladdress");
            }
            poolScript = GetScriptForDestination(poolDest);
            hasPoolAddress = true;
        }
    }

    const CConnman& connman = EnsureConnman(node);

    if (!Params().IsTestChain()) {
        // Allow mining without peers when the chain tip is the genesis block,
        // so the first miner on a new chain can produce block 1.
        if (active_chain.Height() > 0 && connman.GetNodeCount(ConnectionDirection::Both) == 0) {
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, PACKAGE_NAME " is not connected!");
        }

        if (active_chainstate.IsInitialBlockDownload()) {
            throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, PACKAGE_NAME " is in initial sync and waiting for blocks...");
        }
    }

    // Next block is a superblock and we need governance info to correctly construct it
    CHECK_NONFATAL(node.sporkman);
    if (AreSuperblocksEnabled(*node.sporkman)
        && !node.mn_sync->IsSynced()
        && CSuperblock::IsValidBlockHeight(active_chain.Height() + 1))
            throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, PACKAGE_NAME " is syncing with network...");

    static std::map<int, unsigned int> nTransactionsUpdatedLastMap; // per-algo (#939)
    const CTxMemPool& mempool = EnsureMemPool(node);

    if (!lpval.isNull())
    {
        // Wait to respond until either the best block changes, OR a minute has passed and there are more transactions
        uint256 hashWatchedChain;
        std::chrono::steady_clock::time_point checktxtime;
        unsigned int nTransactionsUpdatedLastLP;

        if (lpval.isStr())
        {
            // Format: <hashBestChain><nTransactionsUpdatedLast>
            const std::string& lpstr = lpval.get_str();

            hashWatchedChain = ParseHashV(lpstr.substr(0, 64), "longpollid");
            nTransactionsUpdatedLastLP = LocaleIndependentAtoi<int64_t>(lpstr.substr(64));
        }
        else
        {
            // NOTE: Spec does not specify behaviour for non-string longpollid, but this makes testing easier
            hashWatchedChain = active_chain.Tip()->GetBlockHash();
            nTransactionsUpdatedLastLP = nTransactionsUpdatedLastMap[algo];
        }

        // Release lock while waiting
        LEAVE_CRITICAL_SECTION(cs_main);
        {
            checktxtime = std::chrono::steady_clock::now() + std::chrono::minutes(1);

            WAIT_LOCK(g_best_block_mutex, lock);
            while (g_best_block == hashWatchedChain && IsRPCRunning())
            {
                if (g_best_block_cv.wait_until(lock, checktxtime) == std::cv_status::timeout)
                {
                    // Timeout: Check transactions for update
                    // without holding the mempool lock to avoid deadlocks
                    if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastLP)
                        break;
                    checktxtime += std::chrono::seconds(10);
                }
            }
        }
        ENTER_CRITICAL_SECTION(cs_main);

        if (!IsRPCRunning())
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Shutting down");
        // TODO: Maybe recheck connections/IBD and (if something wrong) send an expires-immediately template to stop miners?
    }

    const Consensus::Params& consensusParams = Params().GetConsensus();

    // Per-algo template cache (#916): each algo gets its own cached template
    // to avoid cross-algo contamination when pools query multiple algos.
    static std::map<int, CBlockIndex*> pindexPrevMap;
    static std::map<int, int64_t> nStartMap;
    static std::map<int, std::unique_ptr<CBlockTemplate>> pblockTemplateMap;
    static std::map<int, CScript> lastCoinbaseScriptMap;
    CScript scriptCoinbase = hasPoolAddress ? poolScript : (CScript() << OP_TRUE);
    if (pindexPrevMap[algo] != active_chain.Tip() ||
        lastCoinbaseScriptMap[algo] != scriptCoinbase ||
        (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastMap[algo] && GetTime() - nStartMap[algo] > 5))
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrevMap[algo] = nullptr;

        // Snapshot tip before CreateNewBlock to avoid races
        nTransactionsUpdatedLastMap[algo] = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrevNew = active_chain.Tip();
        nStartMap[algo] = GetTime();

        // Create new block; use pool's address when provided, OP_TRUE otherwise
        EnsureLLMQContext(node);
        pblockTemplateMap[algo] = BlockAssembler(active_chainstate, node, &mempool, Params()).CreateNewBlock(scriptCoinbase);
        if (!pblockTemplateMap[algo])
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");

        // Need to update only after we know CreateNewBlock succeeded
        pindexPrevMap[algo] = pindexPrevNew;
        lastCoinbaseScriptMap[algo] = scriptCoinbase;
    }
    CHECK_NONFATAL(pindexPrevMap[algo]);
    CBlockIndex* pindexPrev = pindexPrevMap[algo];
    CBlock* pblock = &pblockTemplateMap[algo]->block; // pointer for convenience

    // Set the requested mining algorithm and recompute per-algo difficulty
    pblock->SetAlgo(algo);
    pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams, algo);

    // For KawPoW, set nHeight (needed for epoch context by miners)
    if (algo == ALGO_KAWPOW) {
        pblock->nHeight = pindexPrev->nHeight + 1;
    }

    // Update nTime
    UpdateTime(pblock, consensusParams, pindexPrev);
    pblock->nNonce = 0;
    pblock->nNonce256.SetNull();

    UniValue aCaps(UniValue::VARR); aCaps.push_back("proposal");

    UniValue transactions(UniValue::VARR);
    std::map<uint256, int64_t> setTxIndex;
    int i = 0;
    for (const auto& it : pblock->vtx) {
        const CTransaction& tx = *it;
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase())
            continue;

        UniValue entry(UniValue::VOBJ);

        entry.pushKV("data", EncodeHexTx(tx));

        entry.pushKV("hash", txHash.GetHex());

        UniValue deps(UniValue::VARR);
        for (const CTxIn &in : tx.vin)
        {
            if (setTxIndex.count(in.prevout.hash))
                deps.push_back(setTxIndex[in.prevout.hash]);
        }
        entry.pushKV("depends", deps);

        int index_in_template = i - 1;
        entry.pushKV("fee", pblockTemplateMap[algo]->vTxFees[index_in_template]);
        entry.pushKV("sigops", pblockTemplateMap[algo]->vTxSigOps[index_in_template]);

        transactions.push_back(entry);
    }

    UniValue aux(UniValue::VOBJ);

    arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);

    UniValue aMutable(UniValue::VARR);
    aMutable.push_back("time");
    aMutable.push_back("transactions");
    aMutable.push_back("prevblock");

    UniValue result(UniValue::VOBJ);
    result.pushKV("capabilities", aCaps);

    UniValue aRules(UniValue::VARR);
    aRules.push_back("csv");
    UniValue vbavailable(UniValue::VOBJ);
    for (int j = 0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
        Consensus::DeploymentPos pos = Consensus::DeploymentPos(j);
        ThresholdState state = chainman.m_versionbitscache.State(pindexPrev, consensusParams, pos);
        switch (state) {
            case ThresholdState::DEFINED:
            case ThresholdState::FAILED:
                // Not exposed to GBT at all
                break;
            case ThresholdState::LOCKED_IN:
                // Ensure bit is set in block version
                pblock->nVersion |= chainman.m_versionbitscache.Mask(consensusParams, pos);
                [[fallthrough]];
            case ThresholdState::STARTED:
            {
                const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
                vbavailable.pushKV(gbt_vb_name(pos), consensusParams.vDeployments[pos].bit);
                if (setClientRules.find(vbinfo.name) == setClientRules.end()) {
                    if (!vbinfo.gbt_force) {
                        // If the client doesn't support this, don't indicate it in the [default] version
                        pblock->nVersion &= ~chainman.m_versionbitscache.Mask(consensusParams, pos);
                    }
                }
                break;
            }
            case ThresholdState::ACTIVE:
            {
                // Add to rules only
                const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
                aRules.push_back(gbt_vb_name(pos));
                if (setClientRules.find(vbinfo.name) == setClientRules.end()) {
                    // Not supported by the client; make sure it's safe to proceed
                    if (!vbinfo.gbt_force) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Support for '%s' rule requires explicit client support", vbinfo.name));
                    }
                }
                break;
            }
        }
    }
    result.pushKV("version", pblock->nVersion);
    result.pushKV("rules", aRules);
    result.pushKV("vbavailable", vbavailable);
    result.pushKV("vbrequired", int(0));

    const bool fDIP0001Active_context{DeploymentActiveAfter(pindexPrev, consensusParams, Consensus::DEPLOYMENT_DIP0001)};
    result.pushKV("previousblockhash", pblock->hashPrevBlock.GetHex());
    result.pushKV("transactions", transactions);
    result.pushKV("coinbaseaux", aux);
    // coinbasetxn mode: equihash always, others when pooladdress set or client requests (#871, #874)
    int cbAlgo = pblock->GetAlgo();
    bool isEquihash = IsEquihash(cbAlgo);
    bool hasCoinbaseTxn = isEquihash || hasPoolAddress || setClientCaps.count("coinbasetxn");

    // BIP 22: total value of all coinbase outputs (block reward + fees)
    result.pushKV("coinbasevalue", (int64_t)pblock->vtx[0]->GetValueOut());
    // Pool's share (vout[0]) for pool software that uses coinbasevalue for payout accounting
    result.pushKV("coinbasevalue_miner", (int64_t)pblock->vtx[0]->vout[0].nValue);

    // Emit pre-built coinbase when in coinbasetxn mode (#874)
    if (hasCoinbaseTxn) {
        UniValue coinbasetxnObj(UniValue::VOBJ);
        coinbasetxnObj.pushKV("data", EncodeHexTx(*pblock->vtx[0]));
        result.pushKV("coinbasetxn", coinbasetxnObj);
    }
    result.pushKV("longpollid", active_chain.Tip()->GetBlockHash().GetHex() + ToString(nTransactionsUpdatedLastMap[algo]));
    result.pushKV("target", hashTarget.GetHex());
    result.pushKV("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1);
    result.pushKV("mutable", aMutable);
    // BIP 22 noncerange is the valid range for nHeader.nNonce during GBT.
    // Standard is 16 hex chars (uint64) regardless of algo, matching zcashd
    // and Zero. Equihash miners use the full 256-bit nonce on the wire, but
    // GBT advertises the 32-bit header nonce range.
    result.pushKV("noncerange", "00000000ffffffff");
    result.pushKV("sigoplimit", (int64_t)MaxBlockSigOps(fDIP0001Active_context));
    result.pushKV("sizelimit", (int64_t)MaxBlockSize(fDIP0001Active_context));
    result.pushKV("curtime", pblock->GetBlockTime());
    result.pushKV("bits", strprintf("%08x", pblock->nBits));
    result.pushKV("previousbits", strprintf("%08x", pblockTemplateMap[algo]->nPrevBits));
    result.pushKV("height", (int64_t)(pindexPrev->nHeight+1));

    result.pushKV("algo", GetAlgoName(algo));

    // Equihash fields for Zcash-compatible pool software (#788)
    if (isEquihash) {
        result.pushKV("finalsaplingroothash", pblock->hashReserved.GetHex());

        // N,K parameters + personalization string (#802)
        if (cbAlgo == ALGO_EQUIHASH_200) {
            result.pushKV("equihash_n", 200);
            result.pushKV("equihash_k", 9);
            result.pushKV("personalization", "ZcashPoW");
        } else {
            result.pushKV("equihash_n", 192);
            result.pushKV("equihash_k", 7);
            result.pushKV("personalization", "kerrigan");
        }

        // 140-byte header: CEquihashInput(108) + nNonce256(32) (#794)
        CEquihashInput I{*pblock};
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << I;
        ss << pblock->nNonce256;
        result.pushKV("header_hex", HexStr(ss));
    }

    // KawPoW: header hash + epoch seed hash (RVN-standard field names)
    if (cbAlgo == ALGO_KAWPOW) {
        CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
        hw << pblock->nVersion << pblock->hashPrevBlock << pblock->hashMerkleRoot
           << pblock->nTime << pblock->nBits << pblock->nNonce;
        result.pushKV("headerhash", hw.GetHash().GetHex());

        int height = pindexPrev->nHeight + 1;
        auto epoch = ethash::get_epoch_number(height);
        auto seed = ethash::calculate_epoch_seed(epoch);
        uint256 seedU256;
        // ethash is big-endian, uint256 is little-endian; reverse bytes
        for (int i = 0; i < 32; ++i)
            *(seedU256.begin() + i) = seed.bytes[31 - i];
        result.pushKV("seedhash", seedU256.GetHex());
    }

    UniValue masternodeObj(UniValue::VARR);
    for (const auto& txout : pblockTemplateMap[algo]->voutMasternodePayments) {
        UniValue obj(UniValue::VOBJ);

        CTxDestination dest;
        if (ExtractDestination(txout.scriptPubKey, dest)) {
            obj.pushKV("payee", EncodeDestination(dest));
        } else {
            // OP_RETURN burn outputs (post escrow-sunset) and other non-standard
            // scripts have no address representation; omit payee so pool software
            // does not receive an empty string that breaks validateaddress calls.
        }
        obj.pushKV("script", HexStr(txout.scriptPubKey));
        obj.pushKV("amount", txout.nValue);
        masternodeObj.push_back(obj);
    }

    result.pushKV("masternode", masternodeObj);
    result.pushKV("masternode_payments_started", pindexPrev->nHeight + 1 > consensusParams.nMasternodePaymentsStartBlock);
    // Removed in v1.1: masternode_payments_enforced (always true),
    // superblock/superblocks_started/superblocks_enabled (nSuperblockStartBlock=2100000000).

    result.pushKV("coinbase_payload", HexStr(pblock->vtx[0]->vExtraPayload));

    // Kerrigan uses X11 for block identity hashes regardless of mining algo (#875)
    result.pushKV("blockhash_algorithm", "x11");

    // X11 identity hash of this template for post-submitblock lookups
    result.pushKV("template_hash", pblock->GetHash().GetHex());

    return result;
},
    };
}

class submitblock_StateCatcher final : public CValidationInterface
{
public:
    uint256 hash;
    bool found{false};
    BlockValidationState state;

    explicit submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), state() {}

protected:
    void BlockChecked(const CBlock& block, const BlockValidationState& stateIn) override {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    }
};

static RPCHelpMan submitblock()
{
    // We allow 2 arguments for compliance with BIP22. Argument 2 is ignored.
    return RPCHelpMan{"submitblock",
        "\nAttempts to submit new block to network.\n"
        "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n",
        {
            {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded block data to submit"},
            {"dummy", RPCArg::Type::STR, RPCArg::DefaultHint{"ignored"}, "dummy value, for compatibility with BIP22. This value is ignored."},
        },
        {
            RPCResult{"If the block was accepted", RPCResult::Type::NONE, "", ""},
            RPCResult{"Otherwise", RPCResult::Type::STR, "", "According to BIP22"},
        },
        RPCExamples{
            HelpExampleCli("submitblock", "\"mydata\"")
    + HelpExampleRpc("submitblock", "\"mydata\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
    CBlock& block = *blockptr;
    const std::string& hexdata = request.params[0].get_str();
    if (!DecodeHexBlk(block, hexdata)) {
        LogPrintf("submitblock: decode failed, hex length=%zu, first 40 hex chars: %s\n",
                  hexdata.size(), hexdata.substr(0, 40));
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    LogPrintf("submitblock: algo=%d nVersion=0x%08x nBits=0x%08x nTime=%u hash=%s hexlen=%zu vtx=%zu\n",
              block.GetAlgo(), block.nVersion, block.nBits, block.nTime,
              block.GetHash().ToString(), hexdata.size(), block.vtx.size());

    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block does not start with a coinbase");
    }

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    uint256 hash = block.GetHash();
    {
        LOCK(cs_main);
        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (pindex) {
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
                return "duplicate";
            }
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                return "duplicate-invalid";
            }
        }
    }

    bool new_block;
    auto sc = std::make_shared<submitblock_StateCatcher>(block.GetHash());
    RegisterSharedValidationInterface(sc);
    bool accepted = chainman.ProcessNewBlock(blockptr, /*force_processing=*/true, /*new_block=*/&new_block);
    UnregisterSharedValidationInterface(sc);
    if (!new_block && accepted) {
        return "duplicate";
    }
    if (!sc->found) {
        return "inconclusive";
    }
    return BIP22ValidationResult(sc->state);
},
    };
}

static RPCHelpMan submitheader()
{
    return RPCHelpMan{"submitheader",
                "\nDecode the given hexdata as a header and submit it as a candidate chain tip if valid."
                "\nThrows when the header is invalid.\n",
                {
                    {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded block header data"},
                },
                RPCResult{
                    RPCResult::Type::NONE, "", "None"},
                RPCExamples{
                    HelpExampleCli("submitheader", "\"aabbcc\"") +
                    HelpExampleRpc("submitheader", "\"aabbcc\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    CBlockHeader h;
    if (!DecodeHexBlockHeader(h, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block header decode failed");
    }
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        if (!chainman.m_blockman.LookupBlockIndex(h.hashPrevBlock)) {
            throw JSONRPCError(RPC_VERIFY_ERROR, "Must submit previous header (" + h.hashPrevBlock.GetHex() + ") first");
        }
    }

    BlockValidationState state;
    chainman.ProcessNewBlockHeaders({h}, state);
    if (state.IsValid()) return UniValue::VNULL;
    if (state.IsError()) {
        throw JSONRPCError(RPC_VERIFY_ERROR, state.ToString());
    }
    throw JSONRPCError(RPC_VERIFY_ERROR, state.GetRejectReason());
},
    };
}

static RPCHelpMan getblocksubsidy()
{
    return RPCHelpMan{"getblocksubsidy",
        "\nReturns the block subsidy breakdown for a given height.\n"
        "If height is not provided, uses the next block height.\n",
        {
            {"height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED_NAMED_ARG, "Block height (default: tip + 1)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_AMOUNT, "miner", "miner's portion in KRGN (20%)"},
                {RPCResult::Type::STR_AMOUNT, "masternode", "masternode portion in KRGN (20%)"},
                {RPCResult::Type::STR_AMOUNT, "growthescrow", "growth escrow portion in KRGN (40%, burns via OP_RETURN after escrow sunset)"},
                {RPCResult::Type::BOOL, "escrow_sunset", "true if escrow has sunset (40% burns via OP_RETURN instead of accumulating)"},
                {RPCResult::Type::STR_AMOUNT, "devfund", "dev fund portion in KRGN (15%)"},
                {RPCResult::Type::STR_AMOUNT, "founders", "founders portion in KRGN (5%)"},
            }},
        RPCExamples{
            HelpExampleCli("getblocksubsidy", "")
    + HelpExampleCli("getblocksubsidy", "1000")
    + HelpExampleRpc("getblocksubsidy", "1000")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const Consensus::Params& consensus = chainman.GetConsensus();

    int nHeight;
    {
        LOCK(cs_main);
        nHeight = chainman.ActiveChain().Height() + 1;
    }
    if (!request.params[0].isNull()) {
        nHeight = request.params[0].getInt<int>();
        if (nHeight < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
        }
    }

    // nPrevHeight = nHeight - 1 for GetBlockSubsidyInner
    int nPrevHeight = std::max(0, nHeight - 1);
    CAmount nSubsidy = GetBlockSubsidyInner(0, nPrevHeight, consensus, false);

    // Match the 5-way split from CMNPaymentsProcessor::GetBlockTxOuts (masternode/payments.cpp).
    // Note: GetBlockTxOuts uses (blockSubsidy + feeReward) as the base; this RPC
    // reports the subsidy-only split (fees are unpredictable for a future height).
    CAmount escrowReward = nSubsidy * 40 / 100;
    CAmount mnReward = GetMasternodePayment(nHeight, nSubsidy, /*fV20Active=*/false);
    CAmount devReward = nSubsidy * 15 / 100;
    CAmount foundersReward = nSubsidy * 5 / 100;
    CAmount minerReward = nSubsidy - escrowReward - mnReward - devReward - foundersReward;

    // Escrow sunset: after nGrowthEscrowEndHeight, the 40% burns via OP_RETURN
    // instead of accumulating. The amount is the same; the destination changes.
    bool fEscrowSunset = (consensus.nGrowthEscrowEndHeight > 0 && nHeight > consensus.nGrowthEscrowEndHeight);

    UniValue result(UniValue::VOBJ);
    result.pushKV("miner", ValueFromAmount(minerReward));
    result.pushKV("masternode", ValueFromAmount(mnReward));
    result.pushKV("growthescrow", ValueFromAmount(escrowReward));
    result.pushKV("escrow_sunset", fEscrowSunset);
    result.pushKV("devfund", ValueFromAmount(devReward));
    result.pushKV("founders", ValueFromAmount(foundersReward));
    return result;
},
    };
}

void RegisterMiningRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"mining", &getnetworkhashps},
        {"mining", &getmininginfo},
        {"mining", &prioritisetransaction},
        {"mining", &getblocktemplate},
        {"mining", &getblocksubsidy},
        {"mining", &submitblock},
        {"mining", &submitheader},
        {"hidden", &generatetoaddress},
        {"hidden", &generatetodescriptor},
        {"hidden", &generateblock},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
