// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Copyright (c) 2014-2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <init.h>

#include <addrman.h>
#include <banman.h>
#include <base58.h>
#include <blockfilter.h>
#include <chain.h>
#include <chainparams.h>
#include <context.h>
#include <consensus/amount.h>
#include <deploymentstatus.h>
#include <fs.h>
#include <hash.h>
#include <httpserver.h>
#include <httprpc.h>
#include <chainlock/chainlock.h>
#include <chainlock/handler.h>
#include <init/common.h>
#include <interfaces/chain.h>
#include <index/blockfilterindex.h>
#include <index/coinstatsindex.h>
#include <index/txindex.h>
#include <interfaces/init.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <kernel/coinstats.h>
#include <mapport.h>
#include <node/miner.h>
#include <net.h>
#include <net_permissions.h>
#include <net_processing.h>
#include <netbase.h>
#include <netgroup.h>
#include <node/blockstorage.h>
#include <node/caches.h>
#include <node/chainstate.h>
#include <node/context.h>
#include <node/interface_ui.h>
#include <node/sync_manager.h>
#include <node/txreconciliation.h>
#include <policy/feerate.h>
#include <policy/fees.h>
#include <key_io.h>
#include <policy/outpoint_blacklist.h>
#include <policy/planx_rollback.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <rpc/blockchain.h>
#include <rpc/register.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <scheduler.h>
#include <script/sigcache.h>
#include <script/standard.h>
#include <shutdown.h>
#include <sync.h>
#include <timedata.h>
#include <torcontrol.h>
#include <txdb.h>
#include <txmempool.h>
#include <util/asmap.h>
#include <util/error.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/syserror.h>
#include <util/system.h>
#include <util/thread.h>
#include <util/threadnames.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <walletinitinterface.h>
#ifdef ENABLE_WALLET
#include <wallet/wallet.h>
#endif

#include <active/context.h>
#include <active/masternode.h>
#include <bls/bls.h>
#include <dsnotificationinterface.h>
#include <evo/chainhelper.h>
#include <evo/deterministicmns.h>
#include <evo/evodb.h>
#include <evo/specialtxman.h>
#include <flat-database.h>
#include <governance/governance.h>
#include <governance/net_governance.h>
#include <instantsend/instantsend.h>
#include <instantsend/net_instantsend.h>
#include <llmq/context.h>
#include <llmq/dkgsessionmgr.h>
#include <llmq/net_signing.h>
#include <llmq/options.h>
#include <llmq/observer/context.h>
#include <masternode/meta.h>
#include <masternode/sync.h>
#include <masternode/utils.h>
#include <messagesigner.h>
#include <netfulfilledman.h>
#include <sapling/sapling_init.h>
#include <sapling/sapling_state.h>
#include <hmp/brood_lookup.h>
#include <hmp/commitment.h>
#include <hmp/identity.h>
#include <hmp/privilege.h>
#include <hmp/hmp_params.h>
#include <hmp/seal_manager.h>
#include <spork.h>
#include <stats/client.h>


#include <crypto/sha256.h>

#include <algorithm>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <functional>
#include <set>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#ifndef WIN32
#include <cerrno>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <boost/signals2/signal.hpp>

#if ENABLE_ZMQ
#include <zmq/zmqabstractnotifier.h>
#include <zmq/zmqnotificationinterface.h>
#include <zmq/zmqrpc.h>
#endif

using kernel::CoinStatsHashType;

using node::CacheSizes;
using node::CalculateCacheSizes;
using node::ChainstateLoadingError;
using node::ChainstateLoadVerifyError;
using node::KerriganChainstateSetupClose;
using node::DEFAULT_ADDRESSINDEX;
using node::DEFAULT_PRINTPRIORITY;
using node::DEFAULT_SPENTINDEX;
using node::DEFAULT_STOPAFTERBLOCKIMPORT;
using node::DEFAULT_TIMESTAMPINDEX;
using node::LoadChainstate;
using node::NodeContext;
using node::ThreadImport;
using node::VerifyLoadedChainstate;
using node::fAddressIndex;
using node::fPruneMode;
using node::fReindex;
using node::fSpentIndex;
using node::fTimestampIndex;
using node::nPruneTarget;
#ifdef ENABLE_WALLET
using wallet::DEFAULT_DISABLE_WALLET;
#endif // ENABLE_WALLET

// HMP global instances
std::unique_ptr<CHMPIdentity> g_hmp_identity;
std::unique_ptr<CHMPPrivilegeTracker> g_hmp_privilege;
static std::unique_ptr<CBroodNodeLookup> g_brood_lookup;

/** Compute SHA256 of a file and return hex string. */
static std::string FileSHA256(const fs::path& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "";
    CSHA256 hasher;
    char buf[65536];
    while (f.read(buf, sizeof(buf)) || f.gcount() > 0) {
        hasher.Write(reinterpret_cast<const unsigned char*>(buf), f.gcount());
    }
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(hash);
    return HexStr(Span<unsigned char>(hash, CSHA256::OUTPUT_SIZE));
}

/** Download a Sapling parameter file from a list of URLs. Returns true on success. */
static bool DownloadSaplingParam(const std::string& filename, const fs::path& dest, const std::string& expected_sha256)
{
    // If file already exists with correct hash, skip
    if (fs::exists(dest) && fs::file_size(dest) > 0) {
        if (FileSHA256(dest) == expected_sha256) return true;
        LogPrintf("Sapling: %s exists but hash mismatch, re-downloading\n", filename);
        fs::remove(dest);
    }

    const std::vector<std::string> urls = {
        "https://download.z.cash/downloads/" + filename,
        "https://seed1.kerrigan.network/params/" + filename,
    };

    fs::create_directories(dest.parent_path());

    for (const auto& url : urls) {
        LogPrintf("Sapling: Downloading %s from %s ...\n", filename, url);
        int ret = -1;
#ifdef WIN32
        // Use CreateProcessA instead of system() to avoid shell-injection via dest path.
        // Build PowerShell arguments as a proper argv-style command line.
        {
            std::string destStr = fs::PathToString(dest);
            // Double-quote the URL and path to handle spaces; escape embedded single quotes
            // in the PowerShell script by doubling them.
            std::string safeUrl = url;  // URLs are hardcoded constants, no escaping needed
            std::string safeDest = destStr;
            // Replace single quotes with doubled single quotes for PowerShell string literals
            for (std::string::size_type pos = 0; (pos = safeDest.find('\'', pos)) != std::string::npos; pos += 2) {
                safeDest.replace(pos, 1, "''");
            }
            // Also escape double-quotes to prevent breaking out of the outer PowerShell quoting
            for (size_t pos = safeDest.find('"'); pos != std::string::npos; pos = safeDest.find('"', pos + 2))
                safeDest.replace(pos, 1, "\\\"");
            std::string psScript =
                "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; "
                "(New-Object System.Net.WebClient).DownloadFile('" + safeUrl + "', '" + safeDest + "')";

            std::string cmdLine = "powershell.exe -NoProfile -Command \"" + psScript + "\"";

            STARTUPINFOA si = {};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
            si.hStdOutput = INVALID_HANDLE_VALUE;
            si.hStdError = INVALID_HANDLE_VALUE;
            PROCESS_INFORMATION pi = {};

            if (CreateProcessA(nullptr, cmdLine.data(), nullptr, nullptr, FALSE,
                               CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                WaitForSingleObject(pi.hProcess, INFINITE);
                DWORD exitCode = 1;
                GetExitCodeProcess(pi.hProcess, &exitCode);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                ret = static_cast<int>(exitCode);
            }
        }
#else
        // Use fork/execvp instead of system() to avoid shell injection via dest path
        auto tryExec = [](const std::vector<std::string>& args) -> int {
            pid_t pid = fork();
            if (pid == -1) return -1;
            if (pid == 0) {
                // Child: redirect stdout/stderr to /dev/null
                int devnull = open("/dev/null", O_WRONLY);
                if (devnull >= 0) { dup2(devnull, STDOUT_FILENO); dup2(devnull, STDERR_FILENO); close(devnull); }
                std::vector<const char*> argv;
                for (const auto& a : args) argv.push_back(a.c_str());
                argv.push_back(nullptr);
                execvp(argv[0], const_cast<char* const*>(argv.data()));
                _exit(127);
            }
            int status = 0;
            waitpid(pid, &status, 0);
            return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        };
        std::string destStr = fs::PathToString(dest);
        ret = tryExec({"curl", "-#", "-L", "-o", destStr, url});
        if (ret != 0) ret = tryExec({"wget", "--show-progress", "-q", "-O", destStr, url});
#endif
        if (ret == 0 && fs::exists(dest) && fs::file_size(dest) > 1000) {
            std::string actual_hash = FileSHA256(dest);
            if (actual_hash == expected_sha256) {
                LogPrintf("Sapling: %s downloaded and verified (%d bytes)\n", filename, fs::file_size(dest));
                return true;
            }
            LogPrintf("Sapling: Hash mismatch for %s (got %s, expected %s). Trying next mirror.\n",
                      filename, actual_hash, expected_sha256);
            fs::remove(dest);
        }
    }
    return false;
}

/** Get the default Sapling params directory. Uses ~/.zcash-params convention. */
static fs::path GetDefaultSaplingDir()
{
#ifdef WIN32
    const char* pszAppData = getenv("APPDATA");
    if (pszAppData && strlen(pszAppData) > 0) {
        return fs::path(pszAppData) / "ZcashParams";
    }
    const char* pszUserProfile = getenv("USERPROFILE");
    if (pszUserProfile && strlen(pszUserProfile) > 0) {
        return fs::path(pszUserProfile) / ".zcash-params";
    }
    return fs::path("C:\\") / "ZcashParams";
#else
    const char* pszHome = getenv("HOME");
    fs::path home = (pszHome && strlen(pszHome) > 0) ? fs::path(pszHome) : fs::path("/tmp");
    return home / ".zcash-params";
#endif
}

static constexpr bool DEFAULT_PROXYRANDOMIZE{true};
static constexpr bool DEFAULT_REST_ENABLE{false};
static constexpr bool DEFAULT_I2P_ACCEPT_INCOMING{true};

#ifdef WIN32
// Win32 LevelDB doesn't use filedescriptors, and the ones used for
// accessing block files don't count towards the fd_set size limit
// anyway.
#define MIN_CORE_FILEDESCRIPTORS 0
#else
#define MIN_CORE_FILEDESCRIPTORS 150
#endif

static const char* DEFAULT_ASMAP_FILENAME="ip_asn.map";
/**
 * The PID file facilities.
 */
static const char* BITCOIN_PID_FILENAME = "kerrigand.pid";

static fs::path GetPidFile(const ArgsManager& args)
{
    return AbsPathForConfigVal(args.GetPathArg("-pid", BITCOIN_PID_FILENAME));
}

[[nodiscard]] static bool CreatePidFile(const ArgsManager& args)
{
    std::ofstream file{GetPidFile(args)};
    if (file) {
#ifdef WIN32
        tfm::format(file, "%d\n", GetCurrentProcessId());
#else
        tfm::format(file, "%d\n", getpid());
#endif
        return true;
    } else {
        return InitError(strprintf(_("Unable to create the PID file '%s': %s"), fs::PathToString(GetPidFile(args)), SysErrorString(errno)));
    }
}

//////////////////////////////////////////////////////////////////////////////
//
// Shutdown
//

//
// Thread management and startup/shutdown:
//
// The network-processing threads are all part of a thread group
// created by AppInit() or the Qt main() function.
//
// A clean exit happens when StartShutdown() or the SIGTERM
// signal handler sets ShutdownRequested(), which makes main thread's
// WaitForShutdown() interrupts the thread group.
// And then, WaitForShutdown() makes all other on-going threads
// in the thread group join the main thread.
// Shutdown() is then called to clean up database connections, and stop other
// threads that should only be stopped after the main network-processing
// threads have exited.
//
// Shutdown for Qt is very similar, only it uses a QTimer to detect
// ShutdownRequested() getting set, and then does the normal Qt
// shutdown thing.
//

#if HAVE_SYSTEM
static void ShutdownNotify(const ArgsManager& args)
{
    std::vector<std::thread> threads;
    for (const auto& cmd : args.GetArgs("-shutdownnotify")) {
        threads.emplace_back(runCommand, cmd);
    }
    for (auto& t : threads) {
        t.join();
    }
}
#endif

void Interrupt(NodeContext& node)
{
#if HAVE_SYSTEM
    ShutdownNotify(*node.args);
#endif
    InterruptHTTPServer();
    InterruptHTTPRPC();
    InterruptRPC();
    InterruptREST();
    InterruptTorControl();
    if (node.peerman) {
        node.peerman->InterruptHandlers();
    }
    InterruptMapPort();
    if (node.connman)
        node.connman->Interrupt();
    if (g_txindex) {
        g_txindex->Interrupt();
    }
    ForEachBlockFilterIndex([](BlockFilterIndex& index) { index.Interrupt(); });
    if (g_coin_stats_index) {
        g_coin_stats_index->Interrupt();
    }
}

/** Preparing steps before shutting down or restarting the wallet */
void PrepareShutdown(NodeContext& node)
{
    static Mutex g_shutdown_mutex;
    LOCK(g_shutdown_mutex);
    LogPrintf("%s: In progress...\n", __func__);
    Assert(node.args);

    /// Note: Shutdown() must be able to handle cases in which initialization failed part of the way,
    /// for example if the data directory was found to be locked.
    /// Be sure that anything that writes files or flushes caches only does this if the respective
    /// module was initialized.
    util::ThreadRename("shutoff");
    if (node.mempool) node.mempool->AddTransactionsUpdated(1);

    StopHTTPRPC();
    StopREST();
    StopRPC();
    StopHTTPServer();

    if (node.observer_ctx) node.observer_ctx->Stop();
    if (node.active_ctx) node.active_ctx->Stop();
    if (node.clhandler) node.clhandler->Stop();
    if (node.peerman) node.peerman->StopHandlers();


    for (const auto& client : node.chain_clients) {
        client->flush();
    }
    StopMapPort();

    // Because these depend on each-other, we make sure that neither can be
    // using the other before destroying them.
    if (node.clhandler) UnregisterValidationInterface(node.clhandler.get());
    if (node.peerman) UnregisterValidationInterface(node.peerman.get());

    if (node.connman) node.connman->Stop();

    StopTorControl();

    // After everything has been shut down, but before things get flushed, stop the
    // CScheduler/checkqueue, threadGroup and load block thread.
    if (node.scheduler) node.scheduler->stop();
    if (node.chainman && node.chainman->m_load_block.joinable()) node.chainman->m_load_block.join();
    StopScriptCheckWorkerThreads();

    // Stop seal manager AFTER m_load_block joins and script check workers stop.
    // The load_block thread may still be calling ConnectBlock which uses g_seal_manager.
    if (g_seal_manager) {
        g_seal_manager->Stop();
        g_seal_manager.reset();
    }

    // After there are no more peers/RPC left to give us new data which may generate
    // CValidationInterface callbacks, flush them...
    GetMainSignals().FlushBackgroundCallbacks();

    // After the threads that potentially access these pointers have been stopped,
    // destruct and reset all to nullptr.
    node.peerman.reset();
    node.connman.reset();
    node.banman.reset();
    node.addrman.reset();
    node.netgroupman.reset();
    ::g_stats_client.reset();

    if (node.mempool && node.mempool->IsLoaded() && node.args->GetBoolArg("-persistmempool", DEFAULT_PERSIST_MEMPOOL)) {
        DumpMempool(*node.mempool);
    }

    // Drop transactions we were still watching, and record fee estimations.
    if (node.fee_estimator) node.fee_estimator->Flush();

    // FlushStateToDisk generates a ChainStateFlushed callback, which we should avoid missing
    if (node.chainman) {
        LOCK(cs_main);
        for (CChainState* chainstate : node.chainman->GetAll()) {
            if (chainstate->CanFlushToDisk()) {
                chainstate->ForceFlushStateToDisk();
            }
        }
    }

    // After there are no more peers/RPC left to give us new data which may generate
    // CValidationInterface callbacks, flush them...
    GetMainSignals().FlushBackgroundCallbacks();

    if (node.observer_ctx) {
        UnregisterValidationInterface(node.observer_ctx.get());
    }

    if (node.active_ctx) {
        UnregisterValidationInterface(node.active_ctx.get());
    }

    if (g_ds_notification_interface) {
        UnregisterValidationInterface(g_ds_notification_interface.get());
        g_ds_notification_interface.reset();
    }

    // After all scheduled tasks have been flushed, destroy pointers
    // and reset all to nullptr.
    node.observer_ctx.reset();
    node.active_ctx.reset();
    node.mn_sync.reset();
    g_sporkman = nullptr;
    node.sporkman.reset();
    node.govman.reset();
    node.netfulfilledman.reset();
    node.mn_metaman.reset();

    // Stop and delete all indexes only after flushing background callbacks.
    if (g_txindex) {
        g_txindex->Stop();
        g_txindex.reset();
    }
    if (g_coin_stats_index) {
        g_coin_stats_index->Stop();
        g_coin_stats_index.reset();
    }
    ForEachBlockFilterIndex([](BlockFilterIndex& index) { index.Stop(); });
    DestroyAllBlockFilterIndexes();

    // Any future callbacks will be dropped. This should absolutely be safe - if
    // missing a callback results in an unrecoverable situation, unclean shutdown
    // would too. The only reason to do the above flushes is to let the wallet catch
    // up with our current chain to avoid any strange pruning edge cases and make
    // next startup faster by avoiding rescan.

    if (node.chainman) {
        LOCK(cs_main);
        for (CChainState* chainstate : node.chainman->GetAll()) {
            if (chainstate->CanFlushToDisk()) {
                chainstate->ForceFlushStateToDisk();
                chainstate->ResetCoinsViews();
            }
        }
        KerriganChainstateSetupClose(node.chain_helper, node.dmnman, node.llmq_ctx,
                                 Assert(node.mempool.get()));
        node.evodb.reset();
    }
    for (const auto& client : node.chain_clients) {
        client->stop();
    }

#if ENABLE_ZMQ
    if (g_zmq_notification_interface) {
        UnregisterValidationInterface(g_zmq_notification_interface.get());
        g_zmq_notification_interface.reset();
    }
#endif

    node.chain_clients.clear();

    UnregisterAllValidationInterfaces();
    GetMainSignals().UnregisterBackgroundSignalScheduler();

    // We need to manually release our directory locks if we are expected to restart
    // because the replacement instance will start before this instance stops and the
    // global context won't be torn down in time to release the locks automatically.
    if (RestartRequested()) {
        ReleaseDirectoryLocks();
    }
}

/**
* Shutdown is split into 2 parts:
* Part 1: shut down everything but the main wallet instance (done in PrepareShutdown() )
* Part 2: delete wallet instance
*
* PrepareShutdown is always called (it's idempotent via a mutex), even on
* the restart path where it may have been called once already.
*/
void Shutdown(NodeContext& node)
{
    // Shutdown part 1: always flush + stop threads first.
    // PrepareShutdown is idempotent (uses a mutex), so it's safe to call
    // even on the restart path where it was already called once.
    PrepareShutdown(node);
    // Shutdown part 2: clean up HMP and wallet instances.
    // Reset brood_lookup before privilege (privilege holds raw pointer to it).
    g_brood_lookup.reset();
    g_hmp_commit_pool.reset();
    g_hmp_commitments.reset();
    g_hmp_identity.reset();
    g_hmp_privilege.reset();
    init::UnsetGlobals();
    node.mempool.reset();
    node.fee_estimator.reset();
    node.chainman.reset();
    node.scheduler.reset();

    try {
        if (!fs::remove(GetPidFile(*node.args))) {
            LogPrintf("%s: Unable to remove PID file: File does not exist\n", __func__);
        }
    } catch (const fs::filesystem_error& e) {
        LogPrintf("%s: Unable to remove PID file: %s\n", __func__, fsbridge::get_filesystem_error_message(e));
    }

    LogPrintf("%s: done\n", __func__);
}

/**
 * Signal handlers are very limited in what they are allowed to do.
 * The execution context the handler is invoked in is not guaranteed,
 * so we restrict handler operations to just touching variables:
 */
#ifndef WIN32
static void HandleSIGTERM(int)
{
    StartShutdown();
}

static void HandleSIGHUP(int)
{
    LogInstance().m_reopen_file = true;
}
#else
static BOOL WINAPI consoleCtrlHandler(DWORD dwCtrlType)
{
    StartShutdown();
    Sleep(INFINITE);
    return true;
}
#endif

#ifndef WIN32
static void registerSignalHandler(int signal, void(*handler)(int))
{
    struct sigaction sa;
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(signal, &sa, nullptr);
}
#endif

static boost::signals2::connection rpc_notify_block_change_connection;
static void OnRPCStarted()
{
    rpc_notify_block_change_connection = uiInterface.NotifyBlockTip_connect(std::bind(RPCNotifyBlockChange, std::placeholders::_2));
}

static void OnRPCStopped()
{
    rpc_notify_block_change_connection.disconnect();
    RPCNotifyBlockChange(nullptr);
    g_best_block_cv.notify_all();
    LogPrint(BCLog::RPC, "RPC stopped.\n");
}

void SetupServerArgs(ArgsManager& argsman)
{
    SetupHelpOptions(argsman);
    argsman.AddArg("-help-debug", "Print help message with debugging options and exit", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);

    init::AddLoggingArgs(argsman);

    const auto defaultBaseParams = CreateBaseChainParams(CBaseChainParams::MAIN);
    const auto testnetBaseParams = CreateBaseChainParams(CBaseChainParams::TESTNET);
    const auto devnetBaseParams = CreateBaseChainParams(CBaseChainParams::DEVNET);
    const auto regtestBaseParams = CreateBaseChainParams(CBaseChainParams::REGTEST);
    const auto defaultChainParams = CreateChainParams(argsman, CBaseChainParams::MAIN);
    const auto testnetChainParams = CreateChainParams(argsman, CBaseChainParams::TESTNET);
    const auto devnetChainParams = CreateChainParams(argsman, CBaseChainParams::DEVNET);
    const auto regtestChainParams = CreateChainParams(argsman, CBaseChainParams::REGTEST);

    // Hidden Options
    std::vector<std::string> hidden_args = {"-dbcrashratio", "-forcecompactdb", "-printcrashinfo",
        // GUI args. These will be overwritten by SetupUIArgs for the GUI
        "-choosedatadir", "-lang=<lang>", "-min", "-resetguisettings", "-splash", "-uiplatform"};


    // Set all of the args and their help
    // When adding new options to the categories, please keep and ensure alphabetical ordering.
#if HAVE_SYSTEM
    argsman.AddArg("-alertnotify=<cmd>", "Execute command when an alert is raised (%s in cmd is replaced by message)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
#endif
    argsman.AddArg("-assumevalid=<hex>", strprintf("If this block is in the chain assume that it and its ancestors are valid and potentially skip their script verification (0 to verify all, default: %s, testnet: %s, devnet: %s)", defaultChainParams->GetConsensus().defaultAssumeValid.GetHex(), testnetChainParams->GetConsensus().defaultAssumeValid.GetHex(), devnetChainParams->GetConsensus().defaultAssumeValid.GetHex()), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    // --- Outpoint blacklist ("freeze list") -----------------------------------
    // Opt-in Layer 1 (relay/policy), default OFF. An un-configured node behaves
    // exactly as stock. INDEPENDENT of the deterministic Layer 2 taint freeze
    // (which is gated by the per-network nFreezeActivationHeight consensus param,
    // not by these flags). See policy/outpoint_blacklist.h.
    argsman.AddArg("-blacklistoutpoints=<file>",
                   "Path to a freeze list file. Each line is either \"<txid>:<vout>\" (an outpoint to freeze) "
                   "or an address (freeze any output paying it); blank lines and '#' comments are ignored. "
                   "When set, this node refuses to relay (mempool) or mine (block template) any transaction "
                   "that spends a listed outpoint/address. Relay/policy only (Layer 1) -- causes no chain split. "
                   "Default: not set (feature disabled). Reversible: remove the entry/option and restart.",
                   ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-blacklistaddr=<address>",
                   "Freeze a single address (repeatable). Equivalent to one address line in -blacklistoutpoints. "
                   "Relay/policy only (Layer 1). Default: not set.",
                   ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-blacklistconsensus",
                   "EXPERT/HARD-FORK: also enforce the manual freeze list as a CONSENSUS rule (Layer 2) -- blocks "
                   "containing a frozen-outpoint spend become invalid at/after -blacklistactivationheight. "
                   "This SPLITS the chain unless universally adopted and MUST be paired with a checkpoint. "
                   "Independent of the deterministic taint freeze. Default: 0 (disabled).",
                   ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-blacklistactivationheight=<n>",
                   "Activation height for the Layer 2 manual freeze rule (only meaningful with "
                   "-blacklistconsensus). Default: 0.",
                   ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    // --- PLAN X: contingency rollback (incident 2026-05) -----------------------
    // Recovery release: community vote passed; hashes/keys/compromised set are
    // finalized. EXPERT / HARD-FORK gate, default OFF. When off, the node is
    // byte-identical to upstream. See policy/planx_rollback.h.
    argsman.AddArg("-activaterollback",
                   "EXPERT/HARD-FORK: perform the contingency rollback's one-time in-process reorg at "
                   "startup (incident 2026-05). The three coupled CONSENSUS rules -- (1) pin the chain to "
                   "the required pre-theft ancestor, (2) permanently disallow the theft block and any chain "
                   "containing it, (3) restrict spends of the compromised coins so they may only move to "
                   "the fresh recovery treasury -- are ALWAYS enforced on mainnet by this release, with or "
                   "without this flag. This flag only makes an already-synced node reorg immediately to the "
                   "pre-theft anchor instead of waiting for the recovered chain to overtake by work; "
                   "coalition miners need it to re-mine. Default: 0 (disabled).",
                   ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-blocksdir=<dir>", "Specify directory to hold blocks subdirectory for *.dat files (default: <datadir>)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-fastprune", "Use smaller block files and lower minimum prune height for testing purposes", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-tinyblk", "Use smaller block files for testing purposes", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
#if HAVE_SYSTEM
    argsman.AddArg("-blocknotify=<cmd>", "Execute command when the best block changes (%s in cmd is replaced by block hash)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
#endif
    argsman.AddArg("-blockreconstructionextratxn=<n>", strprintf("Extra transactions to keep in memory for compact block reconstructions (default: %u)", DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-blocksonly", strprintf("Whether to reject transactions from network peers. Automatic broadcast and rebroadcast of any transactions from inbound peers is disabled, unless the peer has the 'forcerelay' permission. RPC transactions are not affected. (default: %u)", DEFAULT_BLOCKSONLY), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
#if HAVE_SYSTEM
    argsman.AddArg("-chainlocknotify=<cmd>", "Execute command when the best chainlock changes (%s in cmd is replaced by chainlocked block hash)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
#endif
    argsman.AddArg("-coinstatsindex", strprintf("Maintain coinstats index used by the gettxoutsetinfo RPC (default: %u)", DEFAULT_COINSTATSINDEX), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-conf=<file>", strprintf("Specify path to read-only configuration file. Relative paths will be prefixed by datadir location (only useable from command line, not configuration file) (default: %s)", BITCOIN_CONF_FILENAME), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-datadir=<dir>", "Specify data directory", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-dbbatchsize", strprintf("Maximum database write batch size in bytes (default: %u)", nDefaultDbBatchSize), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::OPTIONS);
    argsman.AddArg("-dbcache=<n>", strprintf("Maximum database cache size <n> MiB (%d to %d, default: %d). In addition, unused mempool memory is shared for this cache (see -maxmempool).", nMinDbCache, nMaxDbCache, nDefaultDbCache), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-includeconf=<file>", "Specify additional configuration file, relative to the -datadir path (only useable from configuration file, not command line)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-loadblock=<file>", "Imports blocks from external file on startup", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-maxmempool=<n>", strprintf("Keep the transaction memory pool below <n> megabytes (default: %u)", DEFAULT_MAX_MEMPOOL_SIZE), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-maxorphantxsize=<n>", strprintf("Maximum total size of all orphan transactions in megabytes (default: %u)", DEFAULT_MAX_ORPHAN_TRANSACTIONS_SIZE), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-maxrecsigsage=<n>", strprintf("Number of seconds to keep LLMQ recovery sigs (default: %u)", llmq::DEFAULT_MAX_RECOVERED_SIGS_AGE), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-mempoolexpiry=<n>", strprintf("Do not keep transactions in the mempool longer than <n> hours (default: %u)", DEFAULT_MEMPOOL_EXPIRY), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-minimumchainwork=<hex>", strprintf("Minimum work assumed to exist on a valid chain in hex (default: %s, testnet: %s, devnet: %s)", defaultChainParams->GetConsensus().nMinimumChainWork.GetHex(), testnetChainParams->GetConsensus().nMinimumChainWork.GetHex(), devnetChainParams->GetConsensus().nMinimumChainWork.GetHex()), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::OPTIONS);
    argsman.AddArg("-par=<n>", strprintf("Set the number of script verification threads (%u to %d, 0 = auto, <0 = leave that many cores free, default: %d)",
        -GetNumCores(), MAX_SCRIPTCHECK_THREADS, DEFAULT_SCRIPTCHECK_THREADS), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-parbls=<n>", strprintf("Set the number of BLS verification threads (%u to %d, 0 = auto, <0 = leave that many cores free, default: %d)",
        -GetNumCores(), llmq::MAX_BLSCHECK_THREADS, llmq::DEFAULT_BLSCHECK_THREADS), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-persistmempool", strprintf("Whether to save the mempool on shutdown and load on restart (default: %u)", DEFAULT_PERSIST_MEMPOOL), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-pid=<file>", strprintf("Specify pid file. Relative paths will be prefixed by a net-specific datadir location. (default: %s)", BITCOIN_PID_FILENAME), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-saplingparamdir=<dir>", "Specify directory containing Sapling zk-SNARK parameter files (sapling-spend.params and sapling-output.params). (default: ~/.zcash-params/)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-prune=<n>", strprintf("Reduce storage requirements by enabling pruning (deleting) of old blocks. This allows the pruneblockchain RPC to be called to delete specific blocks, and enables automatic pruning of old blocks if a target size in MiB is provided. This mode is incompatible with -txindex, -rescan and -disablegovernance=false. "
            "Warning: Reverting this setting requires re-downloading the entire blockchain. "
            "(default: 0 = disable pruning blocks, 1 = allow manual pruning via RPC, >%u = automatically prune block files to stay under the specified target size in MiB)", MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-settings=<file>", strprintf("Specify path to dynamic settings data file. Can be disabled with -nosettings. File is written at runtime and not meant to be edited by users (use %s instead for custom settings). Relative paths will be prefixed by datadir location. (default: %s)", BITCOIN_CONF_FILENAME, BITCOIN_SETTINGS_FILENAME), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-syncmempool", strprintf("Sync mempool from other nodes on start (default: %u)", DEFAULT_SYNC_MEMPOOL), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
#if HAVE_SYSTEM
    argsman.AddArg("-startupnotify=<cmd>", "Execute command on startup.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-shutdownnotify=<cmd>", "Execute command immediately before beginning shutdown. The need for shutdown may be urgent, so be careful not to delay it long (if the command doesn't require interaction with the server, consider having it fork into the background).", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
#endif
    argsman.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

    argsman.AddArg("-addressindex", strprintf("Maintain a full address index, used to query for the balance, txids and unspent outputs for addresses (default: %u)", DEFAULT_ADDRESSINDEX), ArgsManager::ALLOW_ANY, OptionsCategory::INDEXING);
    argsman.AddArg("-reindex", "Rebuild chain state and block index from the blk*.dat files on disk. This will also rebuild active optional indexes.", ArgsManager::ALLOW_ANY, OptionsCategory::INDEXING);
    argsman.AddArg("-reindex-chainstate", "Rebuild chain state from the currently indexed blocks. When in pruning mode or if blocks on disk might be corrupted, use full -reindex instead. Deactivate all optional indexes before running this.", ArgsManager::ALLOW_ANY, OptionsCategory::INDEXING);
    argsman.AddArg("-resetchainstate",
                   "DESTRUCTIVE: wipe ALL on-disk chain state (blocks, chainstate, sapling, "
                   "evodb, llmq, indexes, peer/mempool/governance/spork dat files, debug.log) and "
                   "then start a fresh IBD from peers. Preserves kerrigan.conf, wallet.dat, all "
                   "named wallet directories, wallets/, backups/, settings.json. Operator-explicit "
                   "recovery flag for post-Plan-X-rollback contamination -- see policy/planx_rollback.h. "
                   "Default off; never auto-enabled.",
                   ArgsManager::ALLOW_ANY, OptionsCategory::INDEXING);
    argsman.AddArg("-spentindex", strprintf("Maintain a full spent index, used to query the spending txid and input index for an outpoint (default: %u)", DEFAULT_SPENTINDEX), ArgsManager::ALLOW_ANY, OptionsCategory::INDEXING);
    argsman.AddArg("-timestampindex", strprintf("Maintain a timestamp index for block hashes, used to query blocks hashes by a range of timestamps (default: %u)", DEFAULT_TIMESTAMPINDEX), ArgsManager::ALLOW_ANY, OptionsCategory::INDEXING);
    argsman.AddArg("-txindex", strprintf("Maintain a full transaction index, used by the getrawtransaction rpc call (default: %u)", DEFAULT_TXINDEX), ArgsManager::ALLOW_ANY, OptionsCategory::INDEXING);
    argsman.AddArg("-blockfilterindex=<type>",
                 strprintf("Maintain an index of compact filters by block (default: %s, values: %s).", DEFAULT_BLOCKFILTERINDEX, ListBlockFilterTypes()) +
                 " If <type> is not supplied or if <type> = 1, indexes for all known types are enabled." +
                 " Automatically enabled for masternodes with value 'basic'.",
                 ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

    argsman.AddArg("-asmap=<file>", strprintf("Specify asn mapping used for bucketing of the peers (default: %s). Relative paths will be prefixed by the net-specific datadir location.", DEFAULT_ASMAP_FILENAME), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-addnode=<ip>", strprintf("Add a node to connect to and attempt to keep the connection open (see the addnode RPC help for more info). This option can be specified multiple times to add multiple nodes; connections are limited to %u at a time and are counted separately from the -maxconnections limit.", MAX_ADDNODE_CONNECTIONS), ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::CONNECTION);
    argsman.AddArg("-allowprivatenet", strprintf("Allow RFC1918 addresses to be relayed and connected to (default: %u)", DEFAULT_ALLOWPRIVATENET), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-bantime=<n>", strprintf("Default duration (in seconds) of manually configured bans (default: %u)", DEFAULT_MISBEHAVING_BANTIME), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-bind=<addr>[:<port>][=onion]", strprintf("Bind to given address and always listen on it (default: 0.0.0.0). Use [host]:port notation for IPv6. Append =onion to tag any incoming connections to that address and port as incoming Tor connections (default: 127.0.0.1:%u=onion, testnet: 127.0.0.1:%u=onion, devnet: 127.0.0.1:%u=onion, regtest: 127.0.0.1:%u=onion)", defaultBaseParams->OnionServiceTargetPort(), testnetBaseParams->OnionServiceTargetPort(), devnetBaseParams->OnionServiceTargetPort(), regtestBaseParams->OnionServiceTargetPort()), ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::CONNECTION);
    argsman.AddArg("-cjdnsreachable", "If set, then this host is configured for CJDNS (connecting to fc00::/8 addresses would lead us to the CJDNS network, see doc/cjdns.md) (default: 0)", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-connect=<ip>", "Connect only to the specified node; -noconnect disables automatic connections (the rules for this peer are the same as for -addnode). This option can be specified multiple times to connect to multiple nodes.", ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::CONNECTION);
    argsman.AddArg("-discover", "Discover own IP addresses (default: 1 when listening and no -externalip or -proxy)", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-dns", strprintf("Allow DNS lookups for -addnode, -seednode and -connect (default: %u)", DEFAULT_NAME_LOOKUP), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-dnsseed", strprintf("Query for peer addresses via DNS lookup, if low on addresses (default: %u unless -connect used or -maxconnections=0)", DEFAULT_DNSSEED), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-externalip=<ip>", "Specify your own public address", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-fixedseeds", strprintf("Allow fixed seeds if DNS seeds don't provide peers (default: %u)", DEFAULT_FIXEDSEEDS), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-forcednsseed", strprintf("Always query for peer addresses via DNS lookup (default: %u)", DEFAULT_FORCEDNSSEED), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-listen", strprintf("Accept connections from outside (default: %u if no -proxy, -connect or -maxconnections=0)", DEFAULT_LISTEN), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-listenonion", strprintf("Automatically create Tor onion service (default: %d)", DEFAULT_LISTEN_ONION), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-maxconnections=<n>", strprintf("Maintain at most <n> connections to peers (temporary service connections excluded) (default: %u). This limit does not apply to connections manually added via -addnode or the addnode RPC, which have a separate limit of %u.", DEFAULT_MAX_PEER_CONNECTIONS, MAX_ADDNODE_CONNECTIONS), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-maxreceivebuffer=<n>", strprintf("Maximum per-connection receive buffer, <n>*1000 bytes (default: %u)", DEFAULT_MAXRECEIVEBUFFER), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-maxsendbuffer=<n>", strprintf("Maximum per-connection memory usage for the send buffer, <n>*1000 bytes (default: %u)", DEFAULT_MAXSENDBUFFER), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-maxtimeadjustment", strprintf("Maximum allowed median peer time offset adjustment. Local perspective of time may be influenced by outbound peers forward or backward by this amount (default: %u seconds).", DEFAULT_MAX_TIME_ADJUSTMENT), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-maxuploadtarget=<n>", strprintf("Tries to keep outbound traffic under the given target per 24h. Limit does not apply to peers with 'download' permission or blocks created within past week. 0 = no limit (default: %s). Optional suffix units [k|K|m|M|g|G|t|T] (default: M). Lowercase is 1000 base while uppercase is 1024 base", DEFAULT_MAX_UPLOAD_TARGET), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
#if HAVE_SOCKADDR_UN
    argsman.AddArg("-onion=<ip:port|path>", "Use separate SOCKS5 proxy to reach peers via Tor onion services, set -noonion to disable (default: -proxy). May be a local file path prefixed with 'unix:'.", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
#else
    argsman.AddArg("-onion=<ip:port>", "Use separate SOCKS5 proxy to reach peers via Tor onion services, set -noonion to disable (default: -proxy)", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
#endif
    argsman.AddArg("-i2psam=<ip:port>", "I2P SAM proxy to reach I2P peers and accept I2P connections (default: none)", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-i2pacceptincoming", strprintf("Whether to accept inbound I2P connections (default: %i). Ignored if -i2psam is not set. Listening for inbound I2P connections is done through the SAM proxy, not by binding to a local address and port.", DEFAULT_I2P_ACCEPT_INCOMING), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-onlynet=<net>", "Make automatic outbound connections only to network <net> (" + Join(GetNetworkNames(), ", ") + "). Inbound and manual connections are not affected by this option. It can be specified multiple times to allow multiple networks.", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-v2transport", strprintf("Support v2 transport (default: %u)", DEFAULT_V2_TRANSPORT), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-peerblockfilters", strprintf("Serve compact block filters to peers per BIP 157 (default: %u, automatically enabled for masternodes)", DEFAULT_PEERBLOCKFILTERS), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-peerbloomfilters", strprintf("Support filtering of blocks and transaction with bloom filters (default: %u)", DEFAULT_PEERBLOOMFILTERS), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-txreconciliation", strprintf("Enable transaction reconciliations per BIP 330 (default: %d)", DEFAULT_TXRECONCILIATION_ENABLE), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CONNECTION);
    argsman.AddArg("-peertimeout=<n>", strprintf("Specify a p2p connection timeout delay in seconds. After connecting to a peer, wait this amount of time before considering disconnection based on inactivity (minimum: 1, default: %d)", DEFAULT_PEER_CONNECT_TIMEOUT), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    // TODO: remove the sentence "Nodes not using ... incoming connections." once the changes from
    // https://github.com/bitcoin/bitcoin/pull/23542 have become widespread.
    argsman.AddArg("-port=<port>", strprintf("Listen for connections on <port>. Nodes not using the default ports (default: %u, testnet: %u, devnet: %u, regtest: %u) are unlikely to get incoming connections. Not relevant for I2P (see doc/i2p.md).", defaultChainParams->GetDefaultPort(), testnetChainParams->GetDefaultPort(), devnetChainParams->GetDefaultPort(), regtestChainParams->GetDefaultPort()), ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::CONNECTION);
#if HAVE_SOCKADDR_UN
    argsman.AddArg("-proxy=<ip:port|path>", "Connect through SOCKS5 proxy, set -noproxy to disable (default: disabled). May be a local file path prefixed with 'unix:' if the proxy supports it.", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_ELISION, OptionsCategory::CONNECTION);
#else
    argsman.AddArg("-proxy=<ip:port>", "Connect through SOCKS5 proxy, set -noproxy to disable (default: disabled)", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_ELISION, OptionsCategory::CONNECTION);
#endif
    argsman.AddArg("-proxyrandomize", strprintf("Randomize credentials for every proxy connection. This enables Tor stream isolation (default: %u)", DEFAULT_PROXYRANDOMIZE), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-seednode=<ip>", "Connect to a node to retrieve peer addresses, and disconnect. This option can be specified multiple times to connect to multiple nodes.", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-socketevents=<mode>", "Socket events mode, which must be one of 'select', 'poll', 'epoll' or 'kqueue', depending on your system (default: Linux - 'epoll', FreeBSD/Apple - 'kqueue', Windows - 'select')", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-networkactive", "Enable all P2P network activity (default: 1). Can be changed by the setnetworkactive RPC command", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-timeout=<n>", strprintf("Specify socket connection timeout in milliseconds. If an initial attempt to connect is unsuccessful after this amount of time, drop it (minimum: 1, default: %d)", DEFAULT_CONNECT_TIMEOUT), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-torcontrol=<ip>:<port>", strprintf("Tor control host and port to use if onion listening enabled (default: %s). If no port is specified, the default port of %i will be used.", DEFAULT_TOR_CONTROL, DEFAULT_TOR_CONTROL_PORT), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-torpassword=<pass>", "Tor control port password (default: empty)", ArgsManager::ALLOW_ANY | ArgsManager::SENSITIVE, OptionsCategory::CONNECTION);
#ifdef USE_UPNP
    argsman.AddArg("-upnp", strprintf("Use UPnP to map the listening port (default: %u)", DEFAULT_UPNP), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
#else
    hidden_args.emplace_back("-upnp");
#endif
#ifdef USE_NATPMP
    argsman.AddArg("-natpmp", strprintf("Use NAT-PMP to map the listening port (default: %u)", DEFAULT_NATPMP), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
#else
    hidden_args.emplace_back("-natpmp");
#endif // USE_NATPMP
    argsman.AddArg("-whitebind=<[permissions@]addr>", "Bind to the given address and add permission flags to the peers connecting to it. "
        "Use [host]:port notation for IPv6. Allowed permissions: " + Join(NET_PERMISSIONS_DOC, ", ") + ". "
        "Specify multiple permissions separated by commas (default: download,noban,mempool,relay). Can be specified multiple times.", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);

    argsman.AddArg("-whitelist=<[permissions@]IP address or network>", "Add permission flags to the peers connecting from the given IP address (e.g. 1.2.3.4) or "
        "CIDR-notated network (e.g. 1.2.3.0/24). Uses the same permissions as "
        "-whitebind. Can be specified multiple times." , ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);

    g_wallet_init_interface.AddWalletOptions(argsman);

#if ENABLE_ZMQ
    argsman.AddArg("-zmqpubhashblock=<address>", "Enable publish hash block in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubhashchainlock=<address>", "Enable publish hash block (locked via ChainLocks) in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubhashgovernanceobject=<address>", "Enable publish hash of governance objects (like proposals) in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubhashgovernancevote=<address>", "Enable publish hash of governance votes in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubhashinstantsenddoublespend=<address>", "Enable publish transaction hashes of attempted InstantSend double spend in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubhashrecoveredsig=<address>", "Enable publish message hash of recovered signatures (recovered by LLMQs) in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubhashtx=<address>", "Enable publish hash transaction in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubhashtxlock=<address>", "Enable publish hash transaction (locked via InstantSend) in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawblock=<address>", "Enable publish raw block in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawchainlock=<address>", "Enable publish raw block (locked via ChainLocks) in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawchainlocksig=<address>", "Enable publish raw block (locked via ChainLocks) and CLSIG message in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawgovernancevote=<address>", "Enable publish raw governance objects (like proposals) in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawgovernanceobject=<address>", "Enable publish raw governance votes in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawinstantsenddoublespend=<address>", "Enable publish raw transactions of attempted InstantSend double spend in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawrecoveredsig=<address>", "Enable publish raw recovered signatures (recovered by LLMQs) in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawtx=<address>", "Enable publish raw transaction in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawtxlock=<address>", "Enable publish raw transaction (locked via InstantSend) in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawtxlocksig=<address>", "Enable publish raw transaction (locked via InstantSend) and ISLOCK in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubsequence=<address>", "Enable publish hash block and tx sequence in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubhashblockhwm=<n>", strprintf("Set publish hash block outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubhashchainlockhwm=<n>", strprintf("Set publish hash chain lock outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubhashgovernanceobjecthwm=<n>", strprintf("Set publish hash governance object outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubhashgovernancevotehwm=<n>", strprintf("Set publish hash governance vote outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubhashinstantsenddoublespendhwm=<n>", strprintf("Set publish hash InstantSend double spend outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubhashrecoveredsighwm=<n>", strprintf("Set publish hash recovered signature outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubhashtxhwm=<n>", strprintf("Set publish hash transaction outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubhashtxlockhwm=<n>", strprintf("Set publish hash transaction lock outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawblockhwm=<n>", strprintf("Set publish raw block outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawchainlockhwm=<n>", strprintf("Set publish raw chain lock outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawchainlocksighwm=<n>", strprintf("Set publish raw chain lock signature outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawgovernanceobjecthwm=<n>", strprintf("Set publish raw governance object outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawgovernancevotehwm=<n>", strprintf("Set publish raw governance vote outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawinstantsenddoublespendhwm=<n>", strprintf("Set publish raw InstantSend double spend outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawrecoveredsighwm=<n>", strprintf("Set publish raw recovered signature outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawtxhwm=<n>", strprintf("Set publish raw transaction outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawtxlockhwm=<n>", strprintf("Set publish raw transaction lock outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawtxlocksighwm=<n>", strprintf("Set publish raw transaction lock signature outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubsequencehwm=<n>", strprintf("Set publish hash sequence message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
#else
    hidden_args.emplace_back("-zmqpubhashblock=<address>");
    hidden_args.emplace_back("-zmqpubhashchainlock=<address>");
    hidden_args.emplace_back("-zmqpubhashgovernanceobject=<address>");
    hidden_args.emplace_back("-zmqpubhashgovernancevote=<address>");
    hidden_args.emplace_back("-zmqpubhashinstantsenddoublespend=<address>");
    hidden_args.emplace_back("-zmqpubhashrecoveredsig=<address>");
    hidden_args.emplace_back("-zmqpubhashtx=<address>");
    hidden_args.emplace_back("-zmqpubhashtxlock=<address>");
    hidden_args.emplace_back("-zmqpubrawblock=<address>");
    hidden_args.emplace_back("-zmqpubrawchainlock=<address>");
    hidden_args.emplace_back("-zmqpubrawchainlocksig=<address>");
    hidden_args.emplace_back("-zmqpubrawgovernancevote=<address>");
    hidden_args.emplace_back("-zmqpubrawgovernanceobject=<address>");
    hidden_args.emplace_back("-zmqpubrawinstantsenddoublespend=<address>");
    hidden_args.emplace_back("-zmqpubrawrecoveredsig=<address>");
    hidden_args.emplace_back("-zmqpubrawtx=<address>");
    hidden_args.emplace_back("-zmqpubrawtxlock=<address>");
    hidden_args.emplace_back("-zmqpubrawtxlocksig=<address>");
    hidden_args.emplace_back("-zmqpubsequence=<n>");
    hidden_args.emplace_back("-zmqpubhashblockhwm=<n>");
    hidden_args.emplace_back("-zmqpubhashchainlockhwm=<n>");
    hidden_args.emplace_back("-zmqpubhashgovernanceobjecthwm=<n>");
    hidden_args.emplace_back("-zmqpubhashgovernancevotehwm=<n>");
    hidden_args.emplace_back("-zmqpubhashinstantsenddoublespendhwm=<n>");
    hidden_args.emplace_back("-zmqpubhashrecoveredsighwm=<n>");
    hidden_args.emplace_back("-zmqpubhashtxhwm=<n>");
    hidden_args.emplace_back("-zmqpubhashtxlockhwm=<n>");
    hidden_args.emplace_back("-zmqpubrawblockhwm=<n>");
    hidden_args.emplace_back("-zmqpubrawchainlockhwm=<n>");
    hidden_args.emplace_back("-zmqpubrawchainlocksighwm=<n>");
    hidden_args.emplace_back("-zmqpubrawgovernanceobjecthwm=<n>");
    hidden_args.emplace_back("-zmqpubrawgovernancevotehwm=<n>");
    hidden_args.emplace_back("-zmqpubrawinstantsenddoublespendhwm=<n>");
    hidden_args.emplace_back("-zmqpubrawrecoveredsighwm=<n>");
    hidden_args.emplace_back("-zmqpubrawtxhwm=<n>");
    hidden_args.emplace_back("-zmqpubrawtxlockhwm=<n>");
    hidden_args.emplace_back("-zmqpubrawtxlocksighwm=<n>");
    hidden_args.emplace_back("-zmqpubsequencehwm=<n>");
#endif

    argsman.AddArg("-checkblockindex", strprintf("Do a consistency check for the block tree, and  occasionally. (default: %u, regtest: %u)", defaultChainParams->DefaultConsistencyChecks(), regtestChainParams->DefaultConsistencyChecks()), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-checkblocks=<n>", strprintf("How many blocks to check at startup (default: %u, 0 = all)", DEFAULT_CHECKBLOCKS), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-checklevel=<n>", strprintf("How thorough the block verification of -checkblocks is: %s (0-4, default: %u)", Join(CHECKLEVEL_DOC, ", "), DEFAULT_CHECKLEVEL), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-checkaddrman=<n>", strprintf("Run addrman consistency checks every <n> operations. Use 0 to disable. (default: %u)", DEFAULT_ADDRMAN_CONSISTENCY_CHECKS), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-checkmempool=<n>", strprintf("Run mempool consistency checks every <n> transactions. Use 0 to disable. (default: %u, regtest: %u)", defaultChainParams->DefaultConsistencyChecks(), regtestChainParams->DefaultConsistencyChecks()), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-checkpoints", strprintf("Enable rejection of any forks from the known historical chain until block %s (default: %u)", defaultChainParams->Checkpoints().GetHeight(), DEFAULT_CHECKPOINTS_ENABLED), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-deprecatedrpc=<method>", "Allows deprecated RPC method(s) to be used", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-forceevodbrepair", "Force evodb masternode list diff verification and repair on startup, even if already repaired (default: 0)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-limitancestorcount=<n>", strprintf("Do not accept transactions if number of in-mempool ancestors is <n> or more (default: %u)", DEFAULT_ANCESTOR_LIMIT), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-limitancestorsize=<n>", strprintf("Do not accept transactions whose size with all in-mempool ancestors exceeds <n> kilobytes (default: %u)", DEFAULT_ANCESTOR_SIZE_LIMIT), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-limitdescendantcount=<n>", strprintf("Do not accept transactions if any ancestor would have <n> or more in-mempool descendants (default: %u)", DEFAULT_DESCENDANT_LIMIT), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-limitdescendantsize=<n>", strprintf("Do not accept transactions if any ancestor would have more than <n> kilobytes of in-mempool descendants (default: %u).", DEFAULT_DESCENDANT_SIZE_LIMIT), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-stopafterblockimport", strprintf("Stop running after importing blocks from disk (default: %u)", DEFAULT_STOPAFTERBLOCKIMPORT), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-stopatheight", strprintf("Stop running after reaching the given height in the main chain (default: %u)", DEFAULT_STOPATHEIGHT), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-watchquorums=<n>", strprintf("Watch and validate quorum communication (default: %u)", llmq::DEFAULT_WATCH_QUORUMS), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-capturemessages", "Capture all P2P messages to disk", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-disablegovernance", strprintf("Disable governance validation (0-1, default: %u)", 0), ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-maxsigcachesize=<n>", strprintf("Limit sum of signature cache and script execution cache sizes to <n> MiB (default: %u)", DEFAULT_MAX_SIG_CACHE_SIZE), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-maxtipage=<n>", strprintf("Maximum tip age in seconds to consider node in initial block download (default: %u)", DEFAULT_MAX_TIP_AGE), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-mocktime=<n>", "Replace actual time with " + UNIX_EPOCH_TIME + " (default: 0)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-minsporkkeys=<n>", "Overrides minimum spork signers to change spork value. Only useful for regtest and devnet. Using this on mainnet or testnet will ban you.", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-printpriority", strprintf("Log transaction fee per kB when mining blocks (default: %u)", DEFAULT_PRINTPRIORITY), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-pushversion", "Protocol version to report to other nodes", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-sporkaddr=<address>", "Override spork address. Only useful for regtest and devnet. Using this on mainnet or testnet will ban you.", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-sporkkey=<privatekey>", "Set the private key to be used for signing spork messages.", ArgsManager::ALLOW_ANY | ArgsManager::SENSITIVE, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-uacomment=<cmt>", "Append comment to the user agent string", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);

    SetupChainParamsOptions(argsman);

    argsman.AddArg("-llmq-data-recovery=<n>", strprintf("Enable automated quorum data recovery (default: %u)", llmq::DEFAULT_ENABLE_QUORUM_DATA_RECOVERY), ArgsManager::ALLOW_ANY, OptionsCategory::MASTERNODE);
    argsman.AddArg("-llmq-qvvec-sync=<quorum_name>:<mode>", strprintf("Defines from which LLMQ type the masternode should sync quorum verification vectors. Can be used multiple times with different LLMQ types. <mode>: %d (sync always from all quorums of the type defined by <quorum_name>), %d (sync from all quorums of the type defined by <quorum_name> if a member of any of the quorums)", (int32_t)llmq::QvvecSyncMode::Always, (int32_t)llmq::QvvecSyncMode::OnlyIfTypeMember), ArgsManager::ALLOW_ANY, OptionsCategory::MASTERNODE);
    argsman.AddArg("-masternodeblsprivkey=<hex>", "Set the masternode BLS private key and enable the client to act as a masternode", ArgsManager::ALLOW_ANY | ArgsManager::SENSITIVE, OptionsCategory::MASTERNODE);
    argsman.AddArg("-deprecated-platform-user=<user>", "Set the username for the \"platform user\", a restricted user intended to be used by Kerrigan Platform, to the specified username.", ArgsManager::ALLOW_ANY, OptionsCategory::MASTERNODE);

    argsman.AddArg("-acceptnonstdtxn", strprintf("Relay and mine \"non-standard\" transactions (%sdefault: %u)", "testnet/regtest only; ", !testnetChainParams->RequireStandard()), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-dustrelayfee=<amt>", strprintf("Fee rate (in %s/kB) used to define dust, the value of an output such that it will cost more than its value in fees at this fee rate to spend it. (default: %s)", CURRENCY_UNIT, FormatMoney(DUST_RELAY_TX_FEE)), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-incrementalrelayfee=<amt>", strprintf("Fee rate (in %s/kB) used to define cost of relay, used for mempool limiting. (default: %s)", CURRENCY_UNIT, FormatMoney(DEFAULT_INCREMENTAL_RELAY_FEE)), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-bytespersigop", strprintf("Equivalent bytes per sigop in transactions for relay and mining (default: %u)", DEFAULT_BYTES_PER_SIGOP), ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-datacarrier", strprintf("Relay and mine data carrier transactions (default: %u)", DEFAULT_ACCEPT_DATACARRIER), ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-datacarriersize", strprintf("Maximum size of data in data carrier transactions we relay and mine (default: %u)", MAX_OP_RETURN_RELAY), ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-permitbaremultisig", strprintf("Relay non-P2SH multisig (default: %u)", DEFAULT_PERMIT_BAREMULTISIG), ArgsManager::ALLOW_ANY,
                   OptionsCategory::NODE_RELAY);
    argsman.AddArg("-minrelaytxfee=<amt>", strprintf("Fees (in %s/kB) smaller than this are considered zero fee for relaying, mining and transaction creation (default: %s)",
        CURRENCY_UNIT, FormatMoney(DEFAULT_MIN_RELAY_TX_FEE)), ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-whitelistforcerelay", strprintf("Add 'forcerelay' permission to whitelisted inbound peers with default permissions. This will relay transactions even if the transactions were already in the mempool. (default: %d)", DEFAULT_WHITELISTFORCERELAY), ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-whitelistrelay", strprintf("Add 'relay' permission to whitelisted inbound peers with default permissions. This will accept relayed transactions even when not relaying transactions (default: %d)", DEFAULT_WHITELISTRELAY), ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);

    argsman.AddArg("-blockmaxsize=<n>", strprintf("Set maximum block size in bytes (default: %d)", DEFAULT_BLOCK_MAX_SIZE), ArgsManager::ALLOW_ANY, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-blockmintxfee=<amt>", strprintf("Set lowest fee rate (in %s/kB) for transactions to be included in block creation. (default: %s)", CURRENCY_UNIT, FormatMoney(DEFAULT_BLOCK_MIN_TX_FEE)), ArgsManager::ALLOW_ANY, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-blockversion=<n>", "Override block version to test forking scenarios", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::BLOCK_CREATION);

    argsman.AddArg("-rest", strprintf("Accept public REST requests (default: %u)", DEFAULT_REST_ENABLE), ArgsManager::ALLOW_ANY, OptionsCategory::RPC);
    argsman.AddArg("-rpcallowip=<ip>", "Allow JSON-RPC connections from specified source. Valid values for <ip> are a single IP (e.g. 1.2.3.4), a network/netmask (e.g. 1.2.3.4/255.255.255.0), a network/CIDR (e.g. 1.2.3.4/24), all ipv4 (0.0.0.0/0), or all ipv6 (::/0). This option can be specified multiple times", ArgsManager::ALLOW_ANY, OptionsCategory::RPC);
    argsman.AddArg("-rpcauth=<userpw>", "Username and HMAC-SHA-256 hashed password for JSON-RPC connections. The field <userpw> comes in the format: <USERNAME>:<SALT>$<HASH>. A canonical python script is included in share/rpcuser. The client then connects normally using the rpcuser=<USERNAME>/rpcpassword=<PASSWORD> pair of arguments. This option can be specified multiple times", ArgsManager::ALLOW_ANY | ArgsManager::SENSITIVE, OptionsCategory::RPC);
    argsman.AddArg("-rpcbind=<addr>[:port]", "Bind to given address to listen for JSON-RPC connections. Do not expose the RPC server to untrusted networks such as the public internet! This option is ignored unless -rpcallowip is also passed. Port is optional and overrides -rpcport. Use [host]:port notation for IPv6. This option can be specified multiple times (default: 127.0.0.1 and ::1 i.e., localhost, or if -rpcallowip has been specified, 0.0.0.0 and :: i.e., all addresses)", ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::RPC);
    argsman.AddArg("-rpcdoccheck", strprintf("Throw a non-fatal error at runtime if the documentation for an RPC is incorrect (default: %u)", DEFAULT_RPC_DOC_CHECK), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::RPC);
    argsman.AddArg("-rpccookiefile=<loc>", "Location of the auth cookie. Relative paths will be prefixed by a net-specific datadir location. (default: data dir)", ArgsManager::ALLOW_ANY, OptionsCategory::RPC);
    argsman.AddArg("-rpcexternaluser=<users>", "List of comma-separated usernames for JSON-RPC external connections", ArgsManager::ALLOW_ANY | ArgsManager::SENSITIVE, OptionsCategory::RPC);
    argsman.AddArg("-rpcexternalworkqueue=<n>", strprintf("Set the depth of the work queue to service external RPC calls (default: %d)", DEFAULT_HTTP_WORKQUEUE), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::RPC);
    argsman.AddArg("-rpcpassword=<pw>", "Password for JSON-RPC connections", ArgsManager::ALLOW_ANY | ArgsManager::SENSITIVE, OptionsCategory::RPC);
    argsman.AddArg("-rpcport=<port>", strprintf("Listen for JSON-RPC connections on <port> (default: %u, testnet: %u, devnet: %u, regtest: %u)", defaultBaseParams->RPCPort(), testnetBaseParams->RPCPort(), devnetBaseParams->RPCPort(), regtestBaseParams->RPCPort()), ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::RPC);
    argsman.AddArg("-rpcalgoport=<algo:port>", "Bind an additional RPC listener for a specific mining algorithm. "
        "Requests arriving on this port will use the specified algorithm for getblocktemplate "
        "without needing the \"algo\" parameter. Can be specified multiple times. "
        "Mnemonic port convention: x11:1100 kawpow:5700 equihash200:2009 equihash192:1927. "
        "Example: -rpcalgoport=equihash192:1927 -rpcalgoport=equihash200:2009 -rpcalgoport=kawpow:5700 -rpcalgoport=x11:1100", ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::RPC);
    argsman.AddArg("-powalgo=<algo>", "Default mining algorithm for RPC calls that do not specify one and are not received on a -rpcalgoport listener. Valid values: x11, kawpow, equihash200, equihash192. Default: x11.", ArgsManager::ALLOW_ANY, OptionsCategory::RPC);
    argsman.AddArg("-mineraddress=<addr>", "If set, getblocktemplate uses this address for the coinbase miner payout when no pooladdress GBT parameter is provided. Avoids wallet keypool exhaustion for pool software that calls GBT continuously. Address must be a valid transparent Kerrigan address.", ArgsManager::ALLOW_ANY, OptionsCategory::RPC);
    argsman.AddArg("-hashrateavgblocks=<n>", "Number of per-algo blocks to average for network hashrate estimates in "
        "getmininginfo and getnetworkhashps. Higher values reduce variance, lower values respond faster. "
        "(default: 23, ~3 hours per algo on a 4-algo chain with 120s target)", ArgsManager::ALLOW_ANY, OptionsCategory::RPC);
    argsman.AddArg("-rpcservertimeout=<n>", strprintf("Timeout during HTTP requests (default: %d)", DEFAULT_HTTP_SERVER_TIMEOUT), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::RPC);
    argsman.AddArg("-rpcthreads=<n>", strprintf("Set the number of threads to service RPC calls (default: %d)", DEFAULT_HTTP_THREADS), ArgsManager::ALLOW_ANY, OptionsCategory::RPC);
    argsman.AddArg("-rpcuser=<user>", "Username for JSON-RPC connections", ArgsManager::ALLOW_ANY | ArgsManager::SENSITIVE, OptionsCategory::RPC);
    argsman.AddArg("-rpcwhitelist=<whitelist>", "Set a whitelist to filter incoming RPC calls for a specific user. The field <whitelist> comes in the format: <USERNAME>:<rpc 1>,<rpc 2>,...,<rpc n>. If multiple whitelists are set for a given user, they are set-intersected. See -rpcwhitelistdefault documentation for information on default whitelist behavior.", ArgsManager::ALLOW_ANY, OptionsCategory::RPC);
    argsman.AddArg("-rpcwhitelistdefault", "Sets default behavior for rpc whitelisting. Unless rpcwhitelistdefault is set to 0, if any -rpcwhitelist is set, the rpc server acts as if all rpc users are subject to empty-unless-otherwise-specified whitelists. If rpcwhitelistdefault is set to 1 and no -rpcwhitelist is set, rpc server acts as if all rpc users are subject to empty whitelists.", ArgsManager::ALLOW_ANY, OptionsCategory::RPC);
    argsman.AddArg("-rpcworkqueue=<n>", strprintf("Set the depth of the work queue to service RPC calls (default: %d)", DEFAULT_HTTP_WORKQUEUE), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::RPC);
    argsman.AddArg("-server", "Accept command line and JSON-RPC commands", ArgsManager::ALLOW_ANY, OptionsCategory::RPC);

    argsman.AddArg("-statsbatchsize=<bytes>", strprintf("Specify the size of each batch of stats messages (default: %d)", DEFAULT_STATSD_BATCH_SIZE), ArgsManager::ALLOW_ANY, OptionsCategory::STATSD);
    argsman.AddArg("-statsduration=<ms>", strprintf("Specify the number of milliseconds between stats messages (default: %d)", DEFAULT_STATSD_DURATION), ArgsManager::ALLOW_ANY, OptionsCategory::STATSD);
    argsman.AddArg("-statshost=<ip>", strprintf("Specify statsd host (default: %s)", DEFAULT_STATSD_HOST), ArgsManager::ALLOW_ANY, OptionsCategory::STATSD);
    hidden_args.emplace_back("-statsport");
    argsman.AddArg("-statsperiod=<seconds>", strprintf("Specify the number of seconds between periodic measurements (default: %d)", DEFAULT_STATSD_PERIOD), ArgsManager::ALLOW_ANY, OptionsCategory::STATSD);
    argsman.AddArg("-statsprefix=<string>", strprintf("Specify an optional string prepended to every stats key (default: %s)", DEFAULT_STATSD_PREFIX), ArgsManager::ALLOW_ANY, OptionsCategory::STATSD);
    argsman.AddArg("-statssuffix=<string>", strprintf("Specify an optional string appended to every stats key (default: %s)", DEFAULT_STATSD_SUFFIX), ArgsManager::ALLOW_ANY, OptionsCategory::STATSD);
#if HAVE_DECL_FORK
    argsman.AddArg("-daemon", strprintf("Run in the background as a daemon and accept commands (default: %d)", DEFAULT_DAEMON), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-daemonwait", strprintf("Wait for initialization to be finished before exiting. This implies -daemon (default: %d)", DEFAULT_DAEMONWAIT), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
#else
    hidden_args.emplace_back("-daemon");
    hidden_args.emplace_back("-daemonwait");
#endif

    // Add the hidden options
    argsman.AddHiddenArgs(hidden_args);
}

static bool fHaveGenesis = false;
static GlobalMutex g_genesis_wait_mutex;
static std::condition_variable g_genesis_wait_cv;

static void BlockNotifyGenesisWait(const CBlockIndex* pBlockIndex)
{
    if (pBlockIndex != nullptr) {
        {
            LOCK(g_genesis_wait_mutex);
            fHaveGenesis = true;
        }
        g_genesis_wait_cv.notify_all();
    }
}

#if HAVE_SYSTEM
static void StartupNotify(const ArgsManager& args)
{
    std::string cmd = args.GetArg("-startupnotify", "");
    if (!cmd.empty()) {
        std::thread t(runCommand, cmd);
        t.detach(); // thread runs free
    }
}
#endif

static void PeriodicStats(NodeContext& node)
{
    assert(::g_stats_client->active());
    const ArgsManager& args = *Assert(node.args);
    ChainstateManager& chainman = *Assert(node.chainman);
    const CTxMemPool& mempool = *Assert(node.mempool);
    const llmq::CInstantSendManager& isman = *Assert(node.llmq_ctx->isman);
    chainman.ActiveChainstate().ForceFlushStateToDisk();
    const auto maybe_stats = WITH_LOCK(::cs_main, return GetUTXOStats(&chainman.ActiveChainstate().CoinsDB(), chainman.m_blockman, /*hash_type=*/CoinStatsHashType::NONE, node.rpc_interruption_point, chainman.ActiveChain().Tip(), /*index_requested=*/true));
    if (maybe_stats.has_value()) {
        ::g_stats_client->gauge("utxoset.tx", maybe_stats->nTransactions, 1.0f);
        ::g_stats_client->gauge("utxoset.txOutputs", maybe_stats->nTransactionOutputs, 1.0f);
        ::g_stats_client->gauge("utxoset.dbSizeBytes", maybe_stats->nDiskSize, 1.0f);
        ::g_stats_client->gauge("utxoset.blockHeight", maybe_stats->nHeight, 1.0f);
        if (maybe_stats->total_amount.has_value()) {
            ::g_stats_client->gauge("utxoset.totalAmount", (double)maybe_stats->total_amount.value() / (double)COIN, 1.0f);
        }
    } else {
        // something went wrong
        LogPrintf("%s: GetUTXOStats failed\n", __func__);
    }

    CBlockIndex *tip;
    {
        LOCK(cs_main);
        tip = chainman.ActiveChain().Tip();
    }
    if (!tip) return; // Chain not yet loaded (pre-genesis)

    double nNetworkHashPS = [&]() {
        // Short version of GetNetworkHashPS(120, -1);
        CBlockIndex *pindex = tip;
        int64_t minTime = pindex->GetBlockTime();
        int64_t maxTime = minTime;
        for (int i = 0; i < 120 && pindex->pprev != nullptr; i++) {
            pindex = pindex->pprev;
            int64_t time = pindex->GetBlockTime();
            minTime = std::min(time, minTime);
            maxTime = std::max(time, maxTime);
        }
        if (minTime == maxTime) return 0.0;
        arith_uint256 workDiff = tip->nChainWork - pindex->nChainWork;
        int64_t timeDiff = maxTime - minTime;
        return workDiff.getdouble() / timeDiff;
    }();

    if (nNetworkHashPS > 0.0) {
        ::g_stats_client->gaugeDouble("network.hashesPerSecond", nNetworkHashPS);
        ::g_stats_client->gaugeDouble("network.terahashesPerSecond", nNetworkHashPS / 1e12);
        ::g_stats_client->gaugeDouble("network.petahashesPerSecond", nNetworkHashPS / 1e15);
        ::g_stats_client->gaugeDouble("network.exahashesPerSecond", nNetworkHashPS / 1e18);
    }
    ::g_stats_client->gaugeDouble("network.difficulty", (double)GetDifficulty(tip));

    ::g_stats_client->gauge("transactions.txCacheSize", WITH_LOCK(cs_main, return chainman.ActiveChainstate().CoinsTip().GetCacheSize()), 1.0f);
    ::g_stats_client->gauge("transactions.totalTransactions", tip->nChainTx, 1.0f);

    {
        LOCK(mempool.cs);
        ::g_stats_client->gauge("transactions.mempool.totalTransactions", mempool.size(), 1.0f);
        ::g_stats_client->gauge("transactions.mempool.totalTxBytes", (int64_t) mempool.GetTotalTxSize(), 1.0f);
        ::g_stats_client->gauge("transactions.mempool.memoryUsageBytes", (int64_t) mempool.DynamicMemoryUsage(), 1.0f);
        ::g_stats_client->gauge("transactions.mempool.minFeePerKb", mempool.GetMinFee(args.GetIntArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000).GetFeePerK(), 1.0f);
    }
    ::g_stats_client->gauge("transactions.mempool.lockedTransactions", isman.GetInstantSendLockCount(), 1.0f);
}

static bool AppInitServers(NodeContext& node)
{
    const ArgsManager& args = *Assert(node.args);
    RPCServer::OnStarted(&OnRPCStarted);
    RPCServer::OnStopped(&OnRPCStopped);
    if (!InitHTTPServer())
        return false;
    StartRPC();
    node.rpc_interruption_point = RpcInterruptionPoint;
    if (!StartHTTPRPC(node))
        return false;
    if (args.GetBoolArg("-rest", DEFAULT_REST_ENABLE)) StartREST(node);
    StartHTTPServer();
    return true;
}

// Parameter interaction based on rules
void InitParameterInteraction(ArgsManager& args)
{
    // when specifying an explicit binding address, you want to listen on it
    // even when -connect or -proxy is specified
    if (args.IsArgSet("-bind")) {
        if (args.SoftSetBoolArg("-listen", true))
            LogPrintf("%s: parameter interaction: -bind set -> setting -listen=1\n", __func__);
    }
    if (args.IsArgSet("-whitebind")) {
        if (args.SoftSetBoolArg("-listen", true))
            LogPrintf("%s: parameter interaction: -whitebind set -> setting -listen=1\n", __func__);
    }

    if (args.IsArgSet("-connect") || args.GetIntArg("-maxconnections", DEFAULT_MAX_PEER_CONNECTIONS) <= 0) {
        // when only connecting to trusted nodes, do not seed via DNS, or listen by default
        if (args.SoftSetBoolArg("-dnsseed", false))
            LogPrintf("%s: parameter interaction: -connect or -maxconnections=0 set -> setting -dnsseed=0\n", __func__);
        if (args.SoftSetBoolArg("-listen", false))
            LogPrintf("%s: parameter interaction: -connect or -maxconnections=0 set -> setting -listen=0\n", __func__);
    }

    std::string proxy_arg = args.GetArg("-proxy", "");
    if (proxy_arg != "" && proxy_arg != "0") {
        // to protect privacy, do not listen by default if a default proxy server is specified
        if (args.SoftSetBoolArg("-listen", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -listen=0\n", __func__);
        // to protect privacy, do not map ports when a proxy is set. The user may still specify -listen=1
        // to listen locally, so don't rely on this happening through -listen below.
        if (args.SoftSetBoolArg("-upnp", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -upnp=0\n", __func__);
        if (args.SoftSetBoolArg("-natpmp", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -natpmp=0\n", __func__);
        // to protect privacy, do not discover addresses by default
        if (args.SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -discover=0\n", __func__);
    }

    if (!args.GetBoolArg("-listen", DEFAULT_LISTEN)) {
        // do not map ports or try to retrieve public IP when not listening (pointless)
        if (args.SoftSetBoolArg("-upnp", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -upnp=0\n", __func__);
        if (args.SoftSetBoolArg("-natpmp", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -natpmp=0\n", __func__);
        if (args.SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -discover=0\n", __func__);
        if (args.SoftSetBoolArg("-listenonion", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -listenonion=0\n", __func__);
        if (args.SoftSetBoolArg("-i2pacceptincoming", false)) {
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -i2pacceptincoming=0\n", __func__);
        }
    }

    if (args.IsArgSet("-externalip")) {
        // if an explicit public IP is specified, do not try to find others
        if (args.SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -externalip set -> setting -discover=0\n", __func__);
    }

    // disable whitelistrelay in blocksonly mode
    if (args.GetBoolArg("-blocksonly", DEFAULT_BLOCKSONLY)) {
        if (args.SoftSetBoolArg("-whitelistrelay", false))
            LogPrintf("%s: parameter interaction: -blocksonly=1 -> setting -whitelistrelay=0\n", __func__);
    }

    // Forcing relay from whitelisted hosts implies we will accept relays from them in the first place.
    if (args.GetBoolArg("-whitelistforcerelay", DEFAULT_WHITELISTFORCERELAY)) {
        if (args.SoftSetBoolArg("-whitelistrelay", true))
            LogPrintf("%s: parameter interaction: -whitelistforcerelay=1 -> setting -whitelistrelay=1\n", __func__);
    }

    if (args.IsArgSet("-onlynet")) {
        const auto onlynets = args.GetArgs("-onlynet");
        bool clearnet_reachable = std::any_of(onlynets.begin(), onlynets.end(), [](const auto& net) {
            const auto n = ParseNetwork(net);
            return n == NET_IPV4 || n == NET_IPV6;
        });
        if (!clearnet_reachable && args.SoftSetBoolArg("-dnsseed", false)) {
            LogPrintf("%s: parameter interaction: -onlynet excludes IPv4 and IPv6 -> setting -dnsseed=0\n", __func__);
        }
    }

    int64_t nPruneArg = args.GetIntArg("-prune", 0);
    if (nPruneArg > 0) {
        if (args.SoftSetBoolArg("-disablegovernance", true)) {
            LogPrintf("%s: parameter interaction: -prune=%d -> setting -disablegovernance=true\n", __func__, nPruneArg);
        }
        if (args.SoftSetBoolArg("-txindex", false)) {
            LogPrintf("%s: parameter interaction: -prune=%d -> setting -txindex=false\n", __func__, nPruneArg);
        }
    }

    // Make sure additional indexes are recalculated correctly in VerifyDB
    // (we must reconnect blocks whenever we disconnect them for these indexes to work)
    bool fAdditionalIndexes =
        args.GetBoolArg("-addressindex", DEFAULT_ADDRESSINDEX) ||
        args.GetBoolArg("-spentindex", DEFAULT_SPENTINDEX) ||
        args.GetBoolArg("-timestampindex", DEFAULT_TIMESTAMPINDEX);

    if (fAdditionalIndexes && args.GetIntArg("-checklevel", DEFAULT_CHECKLEVEL) < 4) {
        args.ForceSetArg("-checklevel", "4");
        LogPrintf("%s: parameter interaction: additional indexes -> setting -checklevel=4\n", __func__);
    }

    if (args.IsArgSet("-masternodeblsprivkey")) {
        if (args.SoftSetBoolArg("-disablewallet", true)) {
            LogPrintf("%s: parameter interaction: -masternodeblsprivkey set -> setting -disablewallet=1\n", __func__);
        }
        // Enable block filters for masternodes to improve network services
        if (args.SoftSetBoolArg("-peerblockfilters", true)) {
            LogPrintf("%s: parameter interaction: -masternodeblsprivkey set -> setting -peerblockfilters=1\n", __func__);
        }
        if (args.SoftSetArg("-blockfilterindex", "basic")) {
            LogPrintf("%s: parameter interaction: -masternodeblsprivkey set -> setting -blockfilterindex=basic\n", __func__);
        }
    }
}

/**
 * Initialize global loggers.
 *
 * Note that this is called very early in the process lifetime, so you should be
 * careful about what global state you rely on here.
 */
void InitLogging(const ArgsManager& args)
{
    init::SetLoggingOptions(args);
    init::LogPackageVersion();
}

namespace { // Variables internal to initialization process only

int nMaxConnections;
int nUserMaxConnections;
int nFD;
ServiceFlags nLocalServices = ServiceFlags(NODE_NETWORK_LIMITED);
int64_t peer_connect_timeout;
std::set<BlockFilterType> g_enabled_filter_types;

} // namespace

[[noreturn]] static void new_handler_terminate()
{
    // Rather than throwing std::bad-alloc if allocation fails, terminate
    // immediately to (try to) avoid chain corruption.
    // Since LogPrintf may itself allocate memory, set the handler directly
    // to terminate first.
    std::set_new_handler(std::terminate);
    LogPrintf("Error: Out of memory. Terminating.\n");

    // The log was successful, terminate now.
    std::terminate();
};

bool AppInitBasicSetup(const ArgsManager& args)
{
    // ********************************************************* Step 1: setup
#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, 0));
    // Disable confusing "helpful" text message on abort, Ctrl-C
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifdef WIN32
    // Enable heap terminate-on-corruption
    HeapSetInformation(nullptr, HeapEnableTerminationOnCorruption, nullptr, 0);
#endif
    if (!InitShutdownState()) {
        return InitError(Untranslated("Initializing wait-for-shutdown state failed."));
    }

    if (!SetupNetworking()) {
        return InitError(Untranslated("Initializing networking failed."));
    }

#ifndef WIN32
    // Clean shutdown on SIGTERM
    registerSignalHandler(SIGTERM, HandleSIGTERM);
    registerSignalHandler(SIGINT, HandleSIGTERM);

    // Reopen debug.log on SIGHUP
    registerSignalHandler(SIGHUP, HandleSIGHUP);

    // Ignore SIGPIPE, otherwise it will bring the daemon down if the client closes unexpectedly
    signal(SIGPIPE, SIG_IGN);
#else
    SetConsoleCtrlHandler(consoleCtrlHandler, true);
#endif

    std::set_new_handler(new_handler_terminate);

    return true;
}

bool AppInitParameterInteraction(const ArgsManager& args)
{
    const CChainParams& chainparams = Params();
    // ********************************************************* Step 2: parameter interactions

    // also see: InitParameterInteraction()

    // Error if network-specific options (-addnode, -connect, etc) are
    // specified in default section of config file, but not overridden
    // on the command line or in this network's section of the config file.
    std::string network = args.GetChainName();
    bilingual_str errors;
    for (const auto& arg : args.GetUnsuitableSectionOnlyArgs()) {
        errors += strprintf(_("Config setting for %s only applied on %s network when in [%s] section.") + Untranslated("\n"), arg, network, network);
    }

    if (!errors.empty()) {
        return InitError(errors);
    }

    // Warn if unrecognized section name are present in the config file.
    bilingual_str warnings;
    for (const auto& section : args.GetUnrecognizedSections()) {
        warnings += strprintf(Untranslated("%s:%i ") + _("Section [%s] is not recognized.") + Untranslated("\n"), section.m_file, section.m_line, section.m_name);
    }

    if (!warnings.empty()) {
        InitWarning(warnings);
    }

    if (!fs::is_directory(gArgs.GetBlocksDirPath())) {
        return InitError(strprintf(_("Specified blocks directory \"%s\" does not exist."), args.GetArg("-blocksdir", "")));
    }

    // parse and validate enabled filter types
    std::string blockfilterindex_value = args.GetArg("-blockfilterindex", DEFAULT_BLOCKFILTERINDEX);
    if (blockfilterindex_value == "" || blockfilterindex_value == "1") {
        g_enabled_filter_types = AllBlockFilterTypes();
    } else if (blockfilterindex_value != "0") {
        const std::vector<std::string> names = args.GetArgs("-blockfilterindex");
        for (const auto& name : names) {
            BlockFilterType filter_type;
            if (!BlockFilterTypeByName(name, filter_type)) {
                return InitError(strprintf(_("Unknown -blockfilterindex value %s."), name));
            }
            g_enabled_filter_types.insert(filter_type);
        }
    }

    // Signal NODE_P2P_V2 if BIP324 v2 transport is enabled.
    if (args.GetBoolArg("-v2transport", DEFAULT_V2_TRANSPORT)) {
        nLocalServices = ServiceFlags(nLocalServices | NODE_P2P_V2);
    }

    // Signal NODE_COMPACT_FILTERS if peerblockfilters and basic filters index are both enabled.
    if (args.GetBoolArg("-peerblockfilters", DEFAULT_PEERBLOCKFILTERS)) {
        if (g_enabled_filter_types.count(BlockFilterType::BASIC_FILTER) != 1) {
            return InitError(_("Cannot set -peerblockfilters without -blockfilterindex."));
        }

        nLocalServices = ServiceFlags(nLocalServices | NODE_COMPACT_FILTERS);
    }

    if (args.GetIntArg("-prune", 0)) {
        if (args.GetBoolArg("-txindex", DEFAULT_TXINDEX))
            return InitError(_("Prune mode is incompatible with -txindex."));
        if (args.GetBoolArg("-addressindex", DEFAULT_ADDRESSINDEX))
            return InitError(_("Prune mode is incompatible with -addressindex."));
        if (args.GetBoolArg("-spentindex", DEFAULT_SPENTINDEX))
            return InitError(_("Prune mode is incompatible with -spentindex."));
        if (args.GetBoolArg("-timestampindex", DEFAULT_TIMESTAMPINDEX))
            return InitError(_("Prune mode is incompatible with -timestampindex."));
        if (args.GetBoolArg("-reindex-chainstate", false)) {
            return InitError(_("Prune mode is incompatible with -reindex-chainstate. Use full -reindex instead."));
        }
        if (!args.GetBoolArg("-disablegovernance", !DEFAULT_GOVERNANCE_ENABLE)) {
            return InitError(_("Prune mode is incompatible with -disablegovernance=false."));
        }
    }

    if (args.IsArgSet("-devnet")) {
        // Require setting of ports when running devnet
        if (args.GetBoolArg("-listen", DEFAULT_LISTEN) && !args.IsArgSet("-port")) {
            return InitError(_("-port must be specified when -devnet and -listen are specified"));
        }
        if (args.GetBoolArg("-server", false) && !args.IsArgSet("-rpcport")) {
            return InitError(_("-rpcport must be specified when -devnet and -server are specified"));
        }
        if (args.GetArgs("-devnet").size() > 1) {
            return InitError(_("-devnet can only be specified once"));
        }
    }

    fAllowPrivateNet = args.GetBoolArg("-allowprivatenet", DEFAULT_ALLOWPRIVATENET);

    // If -forcednsseed is set to true, ensure -dnsseed has not been set to false
    if (args.GetBoolArg("-forcednsseed", DEFAULT_FORCEDNSSEED) && !args.GetBoolArg("-dnsseed", DEFAULT_DNSSEED)){
        return InitError(_("Cannot set -forcednsseed to true when setting -dnsseed to false."));
    }

    // -bind and -whitebind can't be set when not listening
    size_t nUserBind = args.GetArgs("-bind").size() + args.GetArgs("-whitebind").size();
    if (nUserBind != 0 && !args.GetBoolArg("-listen", DEFAULT_LISTEN)) {
        return InitError(Untranslated("Cannot set -bind or -whitebind together with -listen=0"));
    }

    // if listen=0, then disallow listenonion=1
    if (!args.GetBoolArg("-listen", DEFAULT_LISTEN) && args.GetBoolArg("-listenonion", DEFAULT_LISTEN_ONION)) {
        return InitError(Untranslated("Cannot set -listen=0 together with -listenonion=1"));
    }

    // Make sure enough file descriptors are available
    int nBind = std::max(nUserBind, size_t(1));
    nUserMaxConnections = args.GetIntArg("-maxconnections", DEFAULT_MAX_PEER_CONNECTIONS);
    nMaxConnections = std::max(nUserMaxConnections, 0);

    nFD = RaiseFileDescriptorLimit(nMaxConnections + MIN_CORE_FILEDESCRIPTORS + MAX_ADDNODE_CONNECTIONS + nBind + NUM_FDS_MESSAGE_CAPTURE);

#ifdef USE_POLL
    int fd_max = nFD;
#else
    int fd_max = FD_SETSIZE;
#endif
    // Trim requested connection counts, to fit into system limitations
    // <int> in std::min<int>(...) to work around FreeBSD compilation issue described in #2695
    nMaxConnections = std::max(std::min<int>(nMaxConnections, fd_max - nBind - MIN_CORE_FILEDESCRIPTORS - MAX_ADDNODE_CONNECTIONS - NUM_FDS_MESSAGE_CAPTURE), 0);
    if (nFD < MIN_CORE_FILEDESCRIPTORS)
        return InitError(_("Not enough file descriptors available."));
    nMaxConnections = std::min(nFD - MIN_CORE_FILEDESCRIPTORS - MAX_ADDNODE_CONNECTIONS - NUM_FDS_MESSAGE_CAPTURE, nMaxConnections);

    if (nMaxConnections < nUserMaxConnections)
        InitWarning(strprintf(_("Reducing -maxconnections from %d to %d, because of system limitations."), nUserMaxConnections, nMaxConnections));

    // ********************************************************* Step 3: parameter-to-internal-flags
    init::SetLoggingCategories(args);
    init::SetLoggingLevel(args);

    fCheckBlockIndex = args.GetBoolArg("-checkblockindex", chainparams.DefaultConsistencyChecks());
    fCheckpointsEnabled = args.GetBoolArg("-checkpoints", DEFAULT_CHECKPOINTS_ENABLED);

    hashAssumeValid = uint256S(args.GetArg("-assumevalid", chainparams.GetConsensus().defaultAssumeValid.GetHex()));
    if (!hashAssumeValid.IsNull())
        LogPrintf("Assuming ancestors of block %s have valid signatures.\n", hashAssumeValid.GetHex());
    else
        LogPrintf("Validating signatures for all blocks.\n");

    if (args.IsArgSet("-minimumchainwork")) {
        const std::string minChainWorkStr = args.GetArg("-minimumchainwork", "");
        if (!IsHexNumber(minChainWorkStr)) {
            return InitError(strprintf(Untranslated("Invalid non-hex (%s) minimum chain work value specified"), minChainWorkStr));
        }
        nMinimumChainWork = UintToArith256(uint256S(minChainWorkStr));
    } else {
        nMinimumChainWork = UintToArith256(chainparams.GetConsensus().nMinimumChainWork);
    }
    LogPrintf("Setting nMinimumChainWork=%s\n", nMinimumChainWork.GetHex());
    if (nMinimumChainWork < UintToArith256(chainparams.GetConsensus().nMinimumChainWork)) {
        LogPrintf("Warning: nMinimumChainWork set below default value of %s\n", chainparams.GetConsensus().nMinimumChainWork.GetHex());
    }

    // mempool limits
    int64_t nMempoolSizeMax = args.GetIntArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    int64_t nMempoolSizeMin = args.GetIntArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT) * 1000 * 40;
    if (nMempoolSizeMax < 0 || nMempoolSizeMax < nMempoolSizeMin)
        return InitError(strprintf(_("-maxmempool must be at least %d MB"), std::ceil(nMempoolSizeMin / 1000000.0)));
    // incremental relay fee sets the amount the mempool min fee increases above the feerate of txs evicted due to mempool limiting.
    if (args.IsArgSet("-incrementalrelayfee")) {
        if (std::optional<CAmount> inc_relay_fee = ParseMoney(args.GetArg("-incrementalrelayfee", ""))) {
            ::incrementalRelayFee = CFeeRate{inc_relay_fee.value()};
        } else {
            return InitError(AmountErrMsg("incrementalrelayfee", args.GetArg("-incrementalrelayfee", "")));
        }
    }

    // block pruning; get the amount of disk space (in MiB) to allot for block & undo files
    int64_t nPruneArg = args.GetIntArg("-prune", 0);
    if (nPruneArg < 0) {
        return InitError(_("Prune cannot be configured with a negative value."));
    }
    nPruneTarget = (uint64_t) nPruneArg * 1024 * 1024;
    if (nPruneArg == 1) {  // manual pruning: -prune=1
        LogPrintf("Block pruning enabled.  Use RPC call pruneblockchain(height) to manually prune block and undo files.\n");
        nPruneTarget = std::numeric_limits<uint64_t>::max();
        fPruneMode = true;
    } else if (nPruneTarget) {
        if (args.GetBoolArg("-regtest", false)) {
            // we use 1MB blocks to test this on regtest
            if (nPruneTarget < 550 * 1024 * 1024) {
                return InitError(strprintf(_("Prune configured below the minimum of %d MiB.  Please use a higher number."), 550));
            }
        } else {
            if (nPruneTarget < MIN_DISK_SPACE_FOR_BLOCK_FILES) {
                return InitError(strprintf(_("Prune configured below the minimum of %d MiB.  Please use a higher number."), MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024));
            }
        }
        LogPrintf("Prune configured to target %u MiB on disk for block and undo files.\n", nPruneTarget / 1024 / 1024);
        fPruneMode = true;
    }

    nConnectTimeout = args.GetIntArg("-timeout", DEFAULT_CONNECT_TIMEOUT);
    if (nConnectTimeout <= 0) {
        nConnectTimeout = DEFAULT_CONNECT_TIMEOUT;
    }

    peer_connect_timeout = args.GetIntArg("-peertimeout", DEFAULT_PEER_CONNECT_TIMEOUT);
    if (peer_connect_timeout <= 0) {
        return InitError(Untranslated("peertimeout must be a positive integer."));
    }

    if (args.IsArgSet("-minrelaytxfee")) {
        if (std::optional<CAmount> min_relay_fee = ParseMoney(args.GetArg("-minrelaytxfee", ""))) {
            // High fee check is done afterward in CWallet::Create()
            ::minRelayTxFee = CFeeRate{min_relay_fee.value()};
        } else {
            return InitError(AmountErrMsg("minrelaytxfee", args.GetArg("-minrelaytxfee", "")));
        }
    } else if (incrementalRelayFee > ::minRelayTxFee) {
        // Allow only setting incrementalRelayFee to control both
        ::minRelayTxFee = incrementalRelayFee;
        LogPrintf("Increasing minrelaytxfee to %s to match incrementalrelayfee\n",::minRelayTxFee.ToString());
    }

    // Sanity check argument for min fee for including tx in block
    // TODO: Harmonize which arguments need sanity checking and where that happens
    if (args.IsArgSet("-blockmintxfee")) {
        if (!ParseMoney(args.GetArg("-blockmintxfee", ""))) {
            return InitError(AmountErrMsg("blockmintxfee", args.GetArg("-blockmintxfee", "")));
        }
    }

    // Feerate used to define dust.  Shouldn't be changed lightly as old
    // implementations may inadvertently create non-standard transactions
    if (args.IsArgSet("-dustrelayfee")) {
        if (std::optional<CAmount> parsed = ParseMoney(args.GetArg("-dustrelayfee", ""))) {
            dustRelayFee = CFeeRate{parsed.value()};
        } else {
            return InitError(AmountErrMsg("dustrelayfee", args.GetArg("-dustrelayfee", "")));
        }
    }

    fRequireStandard = !args.GetBoolArg("-acceptnonstdtxn", !chainparams.RequireStandard());
    if (!chainparams.IsTestChain() && !fRequireStandard) {
        return InitError(strprintf(Untranslated("acceptnonstdtxn is not currently supported for %s chain"), chainparams.NetworkIDString()));
    }
    nBytesPerSigOp = args.GetIntArg("-bytespersigop", nBytesPerSigOp);

    if (!g_wallet_init_interface.ParameterInteraction()) return false;

    fIsBareMultisigStd = args.GetBoolArg("-permitbaremultisig", DEFAULT_PERMIT_BAREMULTISIG);
    fAcceptDatacarrier = args.GetBoolArg("-datacarrier", DEFAULT_ACCEPT_DATACARRIER);
    nMaxDatacarrierBytes = args.GetIntArg("-datacarriersize", nMaxDatacarrierBytes);

    // Option to startup with mocktime set (used for regression testing):
    SetMockTime(args.GetIntArg("-mocktime", 0)); // SetMockTime(0) is a no-op

    if (args.GetBoolArg("-peerbloomfilters", DEFAULT_PEERBLOOMFILTERS))
        nLocalServices = ServiceFlags(nLocalServices | NODE_BLOOM);

    nMaxTipAge = args.GetIntArg("-maxtipage", DEFAULT_MAX_TIP_AGE);

    if (args.GetBoolArg("-reindex-chainstate", false)) {
        // indexes that must be deactivated to prevent index corruption, see #24630
        if (args.GetBoolArg("-coinstatsindex", DEFAULT_COINSTATSINDEX)) {
            return InitError(_("-reindex-chainstate option is not compatible with -coinstatsindex. Please temporarily disable coinstatsindex while using -reindex-chainstate, or replace -reindex-chainstate with -reindex to fully rebuild all indexes."));
        }
        if (g_enabled_filter_types.count(BlockFilterType::BASIC_FILTER)) {
            return InitError(_("-reindex-chainstate option is not compatible with -blockfilterindex. Please temporarily disable blockfilterindex while using -reindex-chainstate, or replace -reindex-chainstate with -reindex to fully rebuild all indexes."));
        }
        if (args.GetBoolArg("-txindex", DEFAULT_TXINDEX)) {
            return InitError(_("-reindex-chainstate option is not compatible with -txindex. Please temporarily disable txindex while using -reindex-chainstate, or replace -reindex-chainstate with -reindex to fully rebuild all indexes."));
        }
    }

    try {
        const bool fQuorumVvecRequestsEnabled{llmq::GetEnabledQuorumVvecSyncEntries(args).size() > 0};
        if (!args.GetBoolArg("-llmq-data-recovery", llmq::DEFAULT_ENABLE_QUORUM_DATA_RECOVERY) && fQuorumVvecRequestsEnabled) {
            InitWarning(Untranslated("-llmq-qvvec-sync set but recovery is disabled due to -llmq-data-recovery=0"));
        }
    } catch (const std::invalid_argument& e) {
        return InitError(Untranslated(e.what()));
    }

    if (args.IsArgSet("-masternodeblsprivkey")) {
        if (!args.GetBoolArg("-listen", DEFAULT_LISTEN) && Params().RequireRoutableExternalIP()) {
            return InitError(Untranslated("Masternode must accept connections from outside, set -listen=1"));
        }
        if (!args.GetBoolArg("-txindex", DEFAULT_TXINDEX)) {
            return InitError(Untranslated("Masternode must have transaction index enabled, set -txindex=1"));
        }
        if (!args.GetBoolArg("-peerbloomfilters", DEFAULT_PEERBLOOMFILTERS)) {
            return InitError(Untranslated("Masternode must have bloom filters enabled, set -peerbloomfilters=1"));
        }
        if (args.GetIntArg("-prune", 0) > 0) {
            return InitError(Untranslated("Masternode must have no pruning enabled, set -prune=0"));
        }
        if (args.GetIntArg("-maxconnections", DEFAULT_MAX_PEER_CONNECTIONS) < DEFAULT_MAX_PEER_CONNECTIONS) {
            return InitError(strprintf(Untranslated("Masternode must be able to handle at least %d connections, set -maxconnections=%d"), DEFAULT_MAX_PEER_CONNECTIONS, DEFAULT_MAX_PEER_CONNECTIONS));
        }
        if (args.GetBoolArg("-disablegovernance", !DEFAULT_GOVERNANCE_ENABLE)) {
            return InitError(_("You can not disable governance validation on a masternode."));
        }
    }

    if (args.GetBoolArg("-disablegovernance", !DEFAULT_GOVERNANCE_ENABLE)) {
        InitWarning(_("You are starting with governance validation disabled.") +
            (fPruneMode ?
                Untranslated(" ") + _("This is expected because you are running a pruned node.") :
                Untranslated("")));
    }

    return true;
}

static bool LockDataDirectory(bool probeOnly)
{
    // Make sure only a single Kerrigan process is using the data directory.
    const fs::path& datadir = gArgs.GetDataDirNet();
    if (!DirIsWritable(datadir)) {
        return InitError(strprintf(_("Cannot write to data directory '%s'; check permissions."), fs::PathToString(datadir)));
    }
    if (!LockDirectory(datadir, ".lock", probeOnly)) {
        return InitError(strprintf(_("Cannot obtain a lock on data directory %s. %s is probably already running."), fs::PathToString(datadir), PACKAGE_NAME));
    }
    return true;
}

bool AppInitSanityChecks()
{
    // ********************************************************* Step 4: sanity checks

    init::SetGlobals();

    if (!init::SanityChecks()) {
        return InitError(strprintf(_("Initialization sanity check failed. %s is shutting down."), PACKAGE_NAME));
    }

    // Probe the data directory lock to give an early error message, if possible
    // We cannot hold the data directory lock here, as the forking for daemon() hasn't yet happened,
    // and a fork will cause weird behavior to it.
    return LockDataDirectory(true);
}

bool AppInitLockDataDirectory()
{
    // After daemonization get the data directory lock again and hold on to it until exit
    // This creates a slight window for a race condition to happen, however this condition is harmless: it
    // will at most make us exit without printing a message to console.
    if (!LockDataDirectory(false)) {
        // Detailed error printed inside LockDataDirectory
        return false;
    }
    return true;
}

bool AppInitInterfaces(NodeContext& node)
{
    node.chain = node.init->makeChain();
    return true;
}

/**
 * Populate the process-wide MANUAL outpoint blacklist (Layer 1 + optional Layer
 * 2) from configuration.
 *
 * Reads -blacklistoutpoints (a file), -blacklistaddr (repeatable address), and
 * the Layer 2 flags -blacklistconsensus / -blacklistactivationheight. Decodes
 * addresses against the already-selected network params, so it must run after
 * SelectParams() and after logging has started, but before any networking or
 * validation thread is launched (the list is treated as immutable thereafter).
 *
 * NOTE: This configures only the MANUAL freeze list. The deterministic taint
 * freeze (g_taint_set) needs NO configuration -- it is seeded from compile-time
 * constants and computed lazily under cs_main once the active chain reaches the
 * per-network activation height. See policy/outpoint_blacklist.h.
 *
 * Fail-soft on malformed individual entries (logged + skipped) so a typo does
 * not abort the node, but a hard error (e.g. an unreadable file the operator
 * explicitly pointed at) returns false via InitError.
 *
 * Cold path (startup only).
 */
static bool InitOutpointBlacklist(const ArgsManager& args)
{
    std::vector<std::string> errors;
    std::size_t loaded = 0;

    if (args.IsArgSet("-blacklistoutpoints")) {
        const fs::path path = args.GetPathArg("-blacklistoutpoints");
        const std::size_t n = g_outpoint_blacklist.LoadFromFile(path, errors);
        if (n == 0 && !errors.empty()) {
            // Distinguish "file unreadable" (hard error) from "all lines bad".
            // LoadFromFile pushes a single "could not open" message in the
            // unreadable case; treat that as fatal so a misconfigured path is loud.
            for (const auto& e : errors) {
                if (e.rfind("could not open blacklist file:", 0) == 0) {
                    return InitError(Untranslated("Outpoint blacklist: " + e));
                }
            }
        }
        loaded += n;
    }

    // -blacklistaddr may be specified multiple times.
    for (const std::string& addr : args.GetArgs("-blacklistaddr")) {
        if (g_outpoint_blacklist.AddAddressString(addr, errors)) ++loaded;
    }

    for (const std::string& e : errors) {
        LogPrintf("Outpoint blacklist: WARNING: skipped invalid entry: %s\n", e);
    }

    // Layer 2 (consensus) wiring for the MANUAL list. OFF unless explicitly enabled.
    g_outpoint_blacklist_consensus = args.GetBoolArg("-blacklistconsensus", false);
    g_outpoint_blacklist_consensus_height =
        static_cast<int>(args.GetIntArg("-blacklistactivationheight", 0));

    if (g_outpoint_blacklist.IsActive()) {
        LogPrintf("Outpoint blacklist ACTIVE (Layer 1 relay/policy): %u outpoint(s), %u script(s) frozen.\n",
                  static_cast<unsigned>(g_outpoint_blacklist.OutpointCount()),
                  static_cast<unsigned>(g_outpoint_blacklist.ScriptCount()));
        if (g_outpoint_blacklist_consensus) {
            LogPrintf("Outpoint blacklist: Layer 2 CONSENSUS rule ENABLED from height %d. "
                      "WARNING: this is a hard fork; it splits the chain unless universally "
                      "adopted and should be paired with a checkpoint.\n",
                      g_outpoint_blacklist_consensus_height);
        }
    } else if (g_outpoint_blacklist_consensus) {
        LogPrintf("Outpoint blacklist: -blacklistconsensus set but freeze list is empty; rule is inert.\n");
    }

    return true;
}

/**
 * -resetchainstate: wipe ALL on-disk chain-derived state, then let normal startup
 * rebuild it from scratch via fresh IBD.
 *
 * Operator-explicit, never default. Used to recover from corrupted derived caches
 * (sapling tree / evodb / llmq / governance / sporks / indexes) left behind by a
 * v1.2.3+ Plan-X in-process rollback on a node that held pre-rollback derived
 * state. See policy/planx_rollback.h and the post-rollback contamination detection
 * helper below.
 *
 * REMOVED (chain + network + ephemeral runtime state):
 *   blocks/ (honors -blocksdir), chainstate/, sapling/, evodb/, llmq/, indexes/
 *   mempool.dat, peers.dat, banlist.json, banlist.dat, anchors.dat,
 *   netfulfilled.dat, mncache.dat, governance.dat, sporks.dat, hmp_identity.dat
 *   debug.log, fee_estimates.dat
 *
 * PRESERVED (operator data; never touched):
 *   kerrigan.conf, wallet.dat, wallets/, <walletname>/ subdirs, backups/,
 *   settings.json, the PID lockfile and the datadir .lock are intentionally
 *   left alone (held by the running process).
 *
 * Runs once at startup BEFORE logging is open so the wipe of debug.log is safe.
 * A second LogPrintf confirmation is emitted from RecordResetChainstate() after
 * StartLogging() opens the new debug.log, so the wipe is visible on disk even
 * when stderr is closed (e.g. -daemon).
 *
 * REFUSAL: -resetchainstate is honored ONLY when provided on the command line.
 * A `resetchainstate=1` line in kerrigan.conf is the same footgun class as
 * historical `reindex=1`: forget to remove it, every restart wipes state. We
 * refuse to act on the conf-file source and ask the operator to pass the flag
 * on the command line. Cold path.
 */
static bool g_resetchainstate_fired = false; // true if a wipe ran this boot

static bool ResetChainstateIfRequested(const ArgsManager& args, const fs::path& datadir)
{
    if (!args.GetBoolArg("-resetchainstate", false)) {
        return true;
    }

    // SOURCE GATE: only honor when the flag was on the command line. A
    // resetchainstate=1 line in kerrigan.conf would wipe on EVERY restart --
    // the operator forgets the line, loses peers.dat + state every boot. Same
    // class as Bitcoin Core's historical reindex=1 footgun, worse because we
    // also drop network state. GetCommandLineArgs() returns the CLI map only.
    {
        const auto cli = args.GetCommandLineArgs();
        if (cli.find("resetchainstate") == cli.end()) {
            return InitError(Untranslated(
                "-resetchainstate was set in kerrigan.conf (or settings.json), not on "
                "the command line. This flag is one-shot and destructive: leaving it "
                "in a config file would wipe chain state on every restart. Remove the "
                "line from the config and pass -resetchainstate on the command line "
                "for a single boot."));
        }
    }

    // Loud stderr notice: the daemon log is about to be wiped, so without this
    // line the operator has no on-screen record that the destructive flag fired.
    // (Under -daemon stderr is also gone after fork; the post-StartLogging
    // LogPrintf in RecordResetChainstate() records the wipe in the new log.)
    tfm::format(std::cerr,
        "WARNING: -resetchainstate provided; wiping all on-disk chain-derived state in %s\n"
        "         (kerrigan.conf, wallets, and backups are preserved).\n",
        fs::PathToString(datadir));

    // Resolve the blocks directory the same way the rest of the daemon does
    // (ArgsManager::GetBlocksDirPath): honors -blocksdir + appends the network
    // subdir + "blocks". Without this we'd wipe chainstate but leave an
    // external blocks/ tree behind, producing inconsistent state on next boot.
    // When -blocksdir is unset, this resolves to <datadir>/blocks (the same
    // path the old code used). Side effect: GetBlocksDirPath() creates the dir
    // if missing; for a first-boot reset that just makes an empty dir we
    // immediately remove_all. Returns an empty path if -blocksdir points at a
    // non-directory; refuse to wipe in that case so the operator sees the
    // problem rather than a silent no-op.
    const fs::path blocks_path = args.GetBlocksDirPath();
    if (blocks_path.empty()) {
        return InitError(Untranslated(
            "-resetchainstate: could not resolve the blocks directory "
            "(check -blocksdir points at an existing directory)."));
    }

    // Directory trees to remove wholesale. fs::remove_all is std::filesystem's
    // (no-throw, ec overload); missing paths return 0 with no error set.
    struct WipeTarget { const char* label; fs::path path; };
    const WipeTarget kSubdirsToWipe[] = {
        {"blocks",     blocks_path},
        {"chainstate", datadir / "chainstate"},
        {"sapling",    datadir / "sapling"},
        {"evodb",      datadir / "evodb"},
        {"llmq",       datadir / "llmq"},
        {"indexes",    datadir / "indexes"},
    };
    for (const auto& target : kSubdirsToWipe) {
        std::error_code ec;
        const auto removed = fs::remove_all(target.path, ec);
        if (ec) {
            return InitError(Untranslated(strprintf(
                "-resetchainstate: failed to remove %s: %s",
                fs::PathToString(target.path), ec.message())));
        }
        if (removed > 0) {
            tfm::format(std::cerr, "  removed %s (%llu entries)\n",
                        fs::PathToString(target.path),
                        static_cast<unsigned long long>(removed));
        }
    }

    // Individual files to remove. dat caches, peer state, mempool, and the
    // existing debug.log so the post-reset boot starts a fresh log. banlist.dat
    // is the legacy Bitcoin Core 19.x ban file (superseded by banlist.json);
    // include it so a long-lived datadir does not accumulate stale ban state.
    static const char* const kFilesToWipe[] = {
        "mempool.dat", "peers.dat", "banlist.json", "banlist.dat",
        "anchors.dat", "netfulfilled.dat",
        "mncache.dat", "governance.dat", "sporks.dat",
        "hmp_identity.dat", "fee_estimates.dat",
        "debug.log",
    };
    for (const char* name : kFilesToWipe) {
        const fs::path p = datadir / name;
        std::error_code ec;
        const bool was_present = fs::remove(p, ec);
        if (ec) {
            return InitError(Untranslated(strprintf(
                "-resetchainstate: failed to remove %s: %s",
                fs::PathToString(p), ec.message())));
        }
        if (was_present) {
            tfm::format(std::cerr, "  removed %s\n", fs::PathToString(p));
        }
    }

    tfm::format(std::cerr,
        "-resetchainstate: wipe complete. Daemon will continue startup and begin "
        "a fresh sync from peers.\n");
    g_resetchainstate_fired = true;
    return true;
}

/**
 * Post-StartLogging confirmation that the wipe ran. Recorded into the freshly-
 * opened debug.log so the wipe is visible on disk even when stderr is gone
 * (the -daemon case closes stdout/stderr before this point). The flag is
 * passed only on the command line by construction (see the source-gate above).
 */
static void RecordResetChainstate()
{
    if (!g_resetchainstate_fired) {
        return;
    }
    LogPrintf("WARNING: -resetchainstate executed at startup; chain-derived state "
              "was wiped (blocks, chainstate, sapling, evodb, llmq, indexes, peers, "
              "mempool, banlists). Fresh IBD will follow. -resetchainstate is "
              "ONE-SHOT: pass on the command line only, never persist in the "
              "config file (it would wipe on every restart).\n");
}

/**
 * Detect a post-Plan-X-rollback derived-cache mismatch and refuse to start if
 * one is found.
 *
 * Background: the v1.2.3 Plan-X in-process rollback (ActivatePlanXRollbackReorg)
 * disconnects blocks via the same path as the invalidateblock RPC, which unwinds
 * UTXO and triggers UndoBlock on the sapling/evodb tracks. On a node whose
 * derived caches had already advanced past the disallowed block under a prior
 * code path, the rollback can leave those caches pointing at a best-block that
 * no longer exists on the active chain. The node looks healthy locally but
 * produces blocks that reference anchors (sapling) or MN list snapshots that
 * clean peers cannot reproduce, and the chain silently splits.
 *
 * Conservative detection (no half-revert risk): after LoadChainstate has set the
 * active tip, ask each derived-cache subsystem whether its stored best-block
 * matches the active tip. If either disagrees, the cache is contaminated; we
 * refuse to start and point the operator at -resetchainstate. For NEW Plan-X
 * activations going forward the same check fires before the reorg runs, so an
 * activation that would leave the node contaminated is also stopped here.
 *
 * Inert when the Plan-X rollback rule itself is inert (no compromised set, off
 * mainnet) or when the active chain is empty (a fresh -resetchainstate boot).
 *
 * Must run after LoadChainstate (so the active tip and the derived-cache
 * subsystems are live) and before ActivatePlanXRollbackReorg / networking
 * (so a contaminated node never relays or extends a divergent chain).
 *
 * Note on LLMQ caches (quorumdb/recsigdb/isdb/dkgdb): NOT checked here. They
 * unwind via BlockDisconnected events through the validation interface and do
 * not maintain a per-cache best-block cursor of the same shape as sapling and
 * evodb, so there is no equivalent VerifyBestBlock contract to assert against.
 *
 * Cold path; runs once.
 */
static bool DetectPostRollbackContamination(const NodeContext& node)
{
    if (!g_compromised_recovery_set.IsActive()) {
        return true; // off mainnet / rule inert -> no contamination possible
    }
    if (node.chainman == nullptr || node.chain_helper == nullptr || node.evodb == nullptr) {
        return true; // pre-load state; nothing to check
    }

    uint256 tip_hash;
    int tip_height = -1;
    {
        LOCK(cs_main);
        const CBlockIndex* tip = node.chainman->ActiveChain().Tip();
        if (tip == nullptr) {
            return true; // empty chain (post-reset / fresh datadir) -> nothing to check
        }
        tip_hash = tip->GetBlockHash();
        tip_height = tip->nHeight;
    }

    std::vector<std::string> drifts;

    // Sapling state: separate LevelDB at <datadir>/sapling. Stores its own
    // best-block hash that should equal the active tip exactly.
    if (node.chain_helper->sapling_state) {
        if (!node.chain_helper->sapling_state->VerifyBestBlock(tip_hash)) {
            drifts.emplace_back("sapling commitment tree (sapling/)");
        }
    }

    // EvoDB: deterministic MN list, special-tx caches. Same best-block contract.
    if (!node.evodb->VerifyBestBlock(tip_hash)) {
        drifts.emplace_back("evo state / deterministic MN list (evodb/)");
    }

    if (drifts.empty()) {
        return true;
    }

    std::string joined;
    for (const std::string& d : drifts) joined += "\n  - " + d;
    return InitError(Untranslated(strprintf(
        "FATAL: corrupted post-Plan-X-rollback state detected. The following derived "
        "caches disagree with the active chain tip %s (height %d):%s\n"
        "Run kerrigand with -resetchainstate to wipe chain-derived state and rebuild "
        "from peers (wallets and config are preserved); or use -reindex for less "
        "downtime if you trust the on-disk blocks/ contents. See "
        "policy/planx_rollback.h.",
        tip_hash.ToString(), tip_height, joined)));
}

/**
 * PLAN X -- CONTINGENCY ROLLBACK (incident 2026-05). Seed the compromised recovery
 * set from the compile-time, per-network seed constants, and read the
 * -activaterollback flag (which gates only the in-process reorg, not validity).
 * See policy/planx_rollback.h.
 *
 * Recovery release: community vote passed; the rotated keys, block hashes, and the
 * compromised set are finalized (production).
 *
 * The compromised set is seeded UNCONDITIONALLY from the compiled seed constants,
 * because the recovery spend restriction is consensus validity and must not depend
 * on a launch flag. There are NO operator-supplied set extensions: validity has no
 * per-node inputs. The set is empty (and the rule inert) off mainnet, since the
 * compiled addresses decode only under mainnet parameters; the disallow-block and
 * checkpoint-pin rules likewise stay inert while their per-network hashes are zero.
 *
 * When -activaterollback IS set, the startup interlock additionally refuses to boot
 * if any rotated treasury slot / recovery destination is still a placeholder, and
 * the one-time in-process reorg is performed (ActivatePlanXRollbackReorg).
 *
 * Must run after SelectParams() + logging start and before any networking /
 * validation thread (the set is treated as immutable thereafter). Cold path.
 */
static bool InitPlanXRollback(const ArgsManager& args)
{
    // The contingency rollback's consensus VALIDITY rules -- the header-level
    // disallow / descendant / checkpoint pins (validation.cpp, scoped by the
    // per-network consensus.nRollbackHeight) and the recovery spend restriction
    // (scoped by the compromised set below being non-empty) -- are driven by
    // compiled, per-network state, NOT by -activaterollback. Seeding the
    // compromised set here UNCONDITIONALLY is what lets a node that has not passed
    // -activaterollback still enforce identical block validity, so that a fresh
    // sync (or a "delete the block and chainstate databases and re-sync")
    // converges on the recovered chain without depending on a launch flag.
    //
    // Mainnet-scoped by construction: the seed entries are mainnet addresses that
    // decode only under mainnet parameters, so on every other network (and on a
    // build with an empty seed list) the set stays empty and the recovery spend
    // restriction is inert -- matching the header pins, which are inert wherever
    // consensus.nRollbackHeight == 0.
    //
    // -activaterollback now gates ONLY the operational in-process reorg
    // (ActivatePlanXRollbackReorg) and the activation interlock further below.
    {
        std::vector<std::string> seed_errors;

        for (const char* token : planx::SEED_COMPROMISED_OUTPOINTS) {
            const std::string s = TrimString(std::string(token));
            if (s.empty()) continue;
            const std::size_t colon = s.rfind(':');
            if (colon == std::string::npos) {
                seed_errors.emplace_back("rollback seed outpoint missing ':vout': " + s);
                continue;
            }
            const std::string txidHex = TrimString(s.substr(0, colon));
            const std::string voutStr = TrimString(s.substr(colon + 1));
            uint32_t vout = 0;
            if (txidHex.size() != 64 || !IsHex(txidHex) || !ParseUInt32(voutStr, &vout)) {
                seed_errors.emplace_back("rollback seed outpoint invalid: " + s);
                continue;
            }
            g_compromised_recovery_set.AddOutpoint(COutPoint(uint256S(txidHex), vout));
        }

        // Decode each compromised address to its scriptPubKey and match it via
        // ContainsScript, covering any output that pays a compromised address once
        // the rollback restores it. An address that does not decode under the
        // active network's parameters is skipped (expected off mainnet).
        for (const char* token : planx::SEED_COMPROMISED_ADDRESSES) {
            const std::string addr = TrimString(std::string(token));
            if (addr.empty()) continue;
            const CTxDestination dest = DecodeDestination(addr);
            if (!IsValidDestination(dest)) {
                seed_errors.emplace_back("rollback seed address invalid for this network: " + addr);
                continue;
            }
            const CScript script = GetScriptForDestination(dest);
            if (script.empty()) {
                seed_errors.emplace_back("rollback seed address produced empty script: " + addr);
                continue;
            }
            g_compromised_recovery_set.AddScript(script);
        }

        for (const std::string& e : seed_errors) {
            LogPrintf("Contingency rollback: skipped invalid compiled seed entry: %s\n", e);
        }

        // Build invariant: the recovery destination must never itself be a member
        // of the compromised set, or a sweep to it would be a forbidden re-entry
        // and the recovered funds would be locked by the very rule meant to free
        // them. Fail closed on any build that violates this.
        const CScript recovery = PlanXRecoveryScript();
        if (!recovery.empty() && g_compromised_recovery_set.ContainsScript(recovery)) {
            return InitError(Untranslated(
                "Contingency rollback: the recovery destination is itself in the "
                "compromised set -- recovered funds would be permanently locked. "
                "Refusing to start. Re-derive the recovery destination so that it is "
                "not one of the compromised addresses."));
        }
    }

    // -activaterollback gates only the in-process reorg ACTION + the interlock.
    g_activate_rollback = args.GetBoolArg("-activaterollback", false);
    if (!g_activate_rollback) {
        // Consensus validity is already armed above from compiled state; we simply
        // do not perform the in-process reorg. Fork choice alone still rejects the
        // disallowed chain and converges a fresh sync on the recovered chain.
        if (g_compromised_recovery_set.IsActive() && !PlanXRecoveryScript().empty()) {
            LogPrintf("Contingency rollback: consensus rules armed from compiled state; "
                      "-activaterollback not set, so no in-process reorg is performed.\n");
        }
        return true;
    }

    // -----------------------------------------------------------------------
    // INTERLOCK (incident 2026-05 key rotation). The gate is ON. Before doing
    // ANYTHING, refuse to start if the rollback is not fully finalized -- i.e. if
    // recovery would point at an unfinalized/placeholder address, or the baked
    // block hashes are still null. This makes it structurally impossible for a
    // shipped binary to ACTIVATE the rollback while pointing the only-to-7b
    // recovery at a placeholder. The interlock checks:
    //
    //   (a) the recovery "7b" script is finalized (not empty / not the sentinel);
    //   (b) every rotated treasury slot (founders/7a, devfund/7b, growth-escrow)
    //       is finalized (not empty / not the sentinel);
    //   (c) recovery == devFundPaymentScript and recovery != growthEscrowScript
    //       (the latter would put recovered coins under the escrow gate);
    //   (d) the checkpoint-pin anchor hash and the disallowed-block hash are both
    //       finalized (non-null). With the gate on, a null hash would silently
    //       disable that control; we require them present so an activated node
    //       cannot run a half-armed rollback.
    //
    // The placeholder sentinel is documented in policy/planx_rollback.h
    // (PLACEHOLDER_SENTINEL_SCRIPT = a P2SH whose hash160 is all-0xEE). The baked
    // hashes and the rotated PRODUCTION treasury/recovery scripts in this build are
    // concrete (not the sentinel), so this interlock PASSES in the recovery-release
    // build; it fires only if a slot is left/returned to a placeholder.
    {
        const Consensus::Params& cons = Params().GetConsensus();
        const CScript recovery = PlanXRecoveryScript();
        auto as_script = [](const std::vector<unsigned char>& v) {
            return CScript(v.begin(), v.end());
        };
        const CScript founders = as_script(cons.foundersPaymentScript);
        const CScript devfund  = as_script(cons.devFundPaymentScript);
        const CScript escrow   = as_script(cons.growthEscrowScript);

        std::vector<std::string> faults;
        if (PlanXScriptIsPlaceholder(recovery)) {
            faults.emplace_back("recovery-script (7b) is empty/placeholder");
        }
        if (PlanXScriptIsPlaceholder(founders)) {
            faults.emplace_back("foundersPaymentScript (7a) is empty/placeholder");
        }
        if (PlanXScriptIsPlaceholder(devfund)) {
            faults.emplace_back("devFundPaymentScript (7b) is empty/placeholder");
        }
        if (PlanXScriptIsPlaceholder(escrow)) {
            faults.emplace_back("growthEscrowScript is empty/placeholder");
        }
        if (!PlanXScriptIsPlaceholder(recovery) && !PlanXScriptIsPlaceholder(devfund) &&
            recovery != devfund) {
            faults.emplace_back("recovery-script does not match devFundPaymentScript");
        }
        if (!PlanXScriptIsPlaceholder(recovery) && !PlanXScriptIsPlaceholder(escrow) &&
            recovery == escrow) {
            faults.emplace_back("recovery-script equals growthEscrowScript");
        }
        if (PlanXRollbackAnchorHash().IsNull() || cons.rollbackAnchorHash.IsNull()) {
            faults.emplace_back("rollback anchor hash (checkpoint pin) is null/unfinalized");
        }
        if (cons.rollbackDisallowedHash.IsNull()) {
            faults.emplace_back("disallowed (theft) block hash is null/unfinalized");
        }

        if (!faults.empty()) {
            std::string joined;
            for (const std::string& f : faults) {
                joined += "\n  - " + f;
            }
            return InitError(Untranslated(strprintf(
                "PLAN X interlock: -activaterollback was set but the rollback is NOT finalized; "
                "refusing to start so recovery cannot point at a placeholder/unfinalized address. "
                "Finalize the rotated treasury scripts + recovery destination + block hashes "
                "before activating. Faults:%s", joined)));
        }
    }

    // The compromised set is fully defined by the compiled, per-network seed
    // (seeded unconditionally above, with the recovery-not-in-set self-lock already
    // enforced there). There are NO per-node consensus inputs: validity does not
    // depend on any launch argument, so two nodes always agree on which coins are
    // subject to the recovery spend restriction.

    LogPrintf("PLAN X CONTINGENCY ROLLBACK ACTIVATED (-activaterollback). "
              "WARNING: this is a HARD FORK; it splits the chain unless universally adopted "
              "and MUST be paired with the release checkpoint + finalized hashes/address.\n");
    LogPrintf("PLAN X: compromised recovery set: %u outpoint(s), %u script(s); "
              "disallowed-block %s; checkpoint-pin %s; recovery-script %s.\n",
              static_cast<unsigned>(g_compromised_recovery_set.OutpointCount()),
              static_cast<unsigned>(g_compromised_recovery_set.ScriptCount()),
              Params().GetConsensus().rollbackDisallowedHash.IsNull() ? "UNFINALIZED(inert)" : "set",
              PlanXRollbackAnchorHash().IsNull() ? "UNFINALIZED(inert)" : "set",
              PlanXRecoveryScript().empty() ? "UNFINALIZED(inert)" : "set");
    if (!g_compromised_recovery_set.IsActive() || PlanXRecoveryScript().empty()) {
        LogPrintf("PLAN X: only-to-7b spend restriction is INERT (seed list empty and/or recovery "
                  "script unfinalized). Finalize before relying on the rollback.\n");
    }
    return true;
}

/**
 * Self-effecting rollback on an ALREADY-SYNCED running node.
 *
 * The header-level disallow/pin rules in ContextualCheckBlockHeader only run for
 * NEW (not-yet-indexed) headers, so a node already at a tip that includes the
 * theft block never rolls itself back -- it keeps building on the theft chain.
 * This step closes that gap: when the -activaterollback gate is on and the active
 * chain CONTAINS the disallowed (theft) block, it programmatically invalidates
 * that block via the SAME path the `invalidateblock` RPC uses
 * (CChainState::InvalidateBlock + ActivateBestChain), forcing an in-process reorg
 * back to the pre-theft anchor (height DEFAULT_ROLLBACK_HEIGHT). The existing
 * header-level disallow rule then PINS the chain so the theft block can never be
 * reconnected.
 *
 * P-7 (Q-p7-sapling-unwind-test.md) PROVED that this running-node in-process reorg
 * unwinds the Sapling shielded pool cleanly (no AbortNode). We deliberately do NOT
 * use offline reindex / ReplayBlocks (that path lands in the armed crash-recovery
 * SaplingDB-inconsistency guard and can AbortNode).
 *
 * ACTIVATION MODEL: activation = the coalition restarts the binary with
 * -activaterollback at one coordinated UTC time. Because every coalition node
 * runs this step on startup, they all reorg to the same anchor; the population
 * then splits cleanly into coalition (rolled back + pinned) vs non-upgraded (still
 * on the theft chain), which is the P-3 split bounded to exactly that boundary.
 *
 * GUARDS (fail-safe): does nothing unless the gate is on AND the disallowed hash
 * is finalized AND the block is present AND it is on the ACTIVE chain. If any
 * guard is not met (e.g. a freshly re-synced node that already rejected the theft
 * header, or a node already at/below the anchor), this is a logged no-op.
 *
 * Must run AFTER chainstate load (the block index + active chain must exist) and
 * BEFORE networking starts (so the node does not relay/extend the theft chain
 * before rolling back). Cold path; runs once.
 *
 * @return true on success or a no-op; false only if the forced reorg itself fails
 *         (in which case startup aborts via InitError rather than silently running
 *         on the un-rolled-back chain).
 */
static bool ActivatePlanXRollbackReorg(ChainstateManager& chainman)
{
    if (!g_activate_rollback) {
        return true; // gate off -> inert
    }
    // Use the per-network disallowed hash (the same value the consensus disallow-pin
    // enforces), so the reorg action and validity agree on a single source of truth.
    const uint256 disallowed = chainman.GetConsensus().rollbackDisallowedHash;
    if (disallowed.IsNull()) {
        return true; // disallowed hash unfinalized -> nothing to invalidate
    }

    // Look up the disallowed block index and verify it is on the active chain,
    // under cs_main. We then release the lock before invalidating, exactly as the
    // invalidateblock RPC does (InvalidateBlock/ActivateBestChain take cs_main
    // themselves).
    CBlockIndex* pblockindex = nullptr;
    {
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(disallowed);
        if (pblockindex == nullptr) {
            LogPrintf("PLAN X: disallowed (theft) block %s is NOT in the block index; "
                      "no in-process rollback needed (node never saw it / already below the anchor).\n",
                      disallowed.ToString());
            return true;
        }
        if (!chainman.ActiveChain().Contains(pblockindex)) {
            LogPrintf("PLAN X: disallowed (theft) block %s is present but NOT on the active chain; "
                      "no in-process rollback needed (already reorged away / on a different chain).\n",
                      disallowed.ToString());
            return true;
        }
        // Sanity: the theft block sits at the anchor height + 1. Log loudly if the
        // height does not match the expected slot (we still proceed -- the hash is
        // the authoritative identifier -- but this surfaces a misconfiguration).
        const int expected_height = planx::DEFAULT_ROLLBACK_HEIGHT + 1;
        if (pblockindex->nHeight != expected_height) {
            LogPrintf("PLAN X: WARNING: disallowed block %s is at height %d, expected %d "
                      "(anchor %d + 1). Proceeding by hash.\n",
                      disallowed.ToString(), pblockindex->nHeight, expected_height,
                      planx::DEFAULT_ROLLBACK_HEIGHT);
        }
        LogPrintf("PLAN X: FORCING IN-PROCESS ROLLBACK. Active chain contains the disallowed (theft) "
                  "block %s at height %d. Invalidating it to reorg back to the pre-theft anchor at "
                  "height %d. This is the running-node reorg proven clean by the P-7 Sapling-unwind "
                  "test; the header-level disallow rule then pins the chain.\n",
                  disallowed.ToString(), pblockindex->nHeight, planx::DEFAULT_ROLLBACK_HEIGHT);
    }

    // Same call sequence as the invalidateblock RPC (src/rpc/blockchain.cpp).
    BlockValidationState state;
    CChainState& active_chainstate = chainman.ActiveChainstate();
    active_chainstate.InvalidateBlock(state, pblockindex);
    if (state.IsValid()) {
        active_chainstate.ActivateBestChain(state);
    }
    if (!state.IsValid()) {
        return InitError(Untranslated(strprintf(
            "PLAN X: forced rollback of the disallowed (theft) block %s FAILED: %s. Refusing to start "
            "on the un-rolled-back chain.", disallowed.ToString(), state.ToString())));
    }

    // Ensure validation-interface subscribers (wallet, indexes) observe all the
    // BlockDisconnected events before we proceed, mirroring the RPC.
    SyncWithValidationInterfaceQueue();

    // Report the new tip. With the disallow rule active, the theft block is now
    // BLOCK_FAILED_VALID and the anchor is the new active tip.
    {
        LOCK(cs_main);
        const CBlockIndex* tip = chainman.ActiveChain().Tip();
        LogPrintf("PLAN X: rollback reorg complete. Active tip is now %s at height %d "
                  "(target anchor height %d).\n",
                  tip ? tip->GetBlockHash().ToString() : "null",
                  tip ? tip->nHeight : -1, planx::DEFAULT_ROLLBACK_HEIGHT);
    }
    return true;
}

bool AppInitMain(NodeContext& node, interfaces::BlockAndHeaderTipInfo* tip_info)
{
    const ArgsManager& args = *Assert(node.args);
    const CChainParams& chainparams = Params();

    auto opt_max_upload = ParseByteUnits(args.GetArg("-maxuploadtarget", DEFAULT_MAX_UPLOAD_TARGET), ByteUnit::M);
    if (!opt_max_upload) {
        return InitError(strprintf(_("Unable to parse -maxuploadtarget: '%s'"), args.GetArg("-maxuploadtarget", "")));
    }

    // ********************************************************* Step 4a: application initialization
    if (!CreatePidFile(args)) {
        // Detailed error printed inside CreatePidFile().
        return false;
    }

    // -resetchainstate: destructive wipe of chain-derived state. Runs BEFORE
    // logging is opened so the old debug.log can be removed cleanly; the rest
    // of startup behaves as if a fresh datadir was provided. Operator-explicit
    // recovery path for post-Plan-X-rollback contamination -- never default.
    // See policy/planx_rollback.h and ResetChainstateIfRequested above.
    if (!ResetChainstateIfRequested(args, gArgs.GetDataDirNet())) {
        return false; // InitError already reported the cause.
    }

    if (!init::StartLogging(args)) {
        // Detailed error printed inside StartLogging().
        return false;
    }

    // -resetchainstate confirmation in the new debug.log. Under -daemon the
    // pre-logging stderr notice is lost when stdout/stderr are closed at fork;
    // this is the on-disk record that the destructive flag fired this boot.
    RecordResetChainstate();

    LogPrintf("Using at most %i automatic connections (%i file descriptors available)\n", nMaxConnections, nFD);

    // Warn about relative -datadir path.
    if (args.IsArgSet("-datadir") && !args.GetPathArg("-datadir").is_absolute()) {
        LogPrintf("Warning: relative datadir option '%s' specified, which will be interpreted relative to the " /* Continued */
                  "current working directory '%s'. This is fragile, because if Kerrigan is started in the future "
                  "from a different location, it will be unable to locate the current data files. There could "
                  "also be data loss if Kerrigan is started while in a temporary directory.\n",
                  args.GetArg("-datadir", ""), fs::PathToString(fs::current_path()));
    }

    // Load the optional MANUAL outpoint/address freeze list (default OFF). Must
    // be done after params selection + logging start and before networking /
    // validation threads spin up, since the list is treated as immutable
    // afterwards. (The deterministic taint freeze needs no loader here.)
    if (!InitOutpointBlacklist(args)) {
        return false; // InitError already reported the cause.
    }

    // PLAN X contingency rollback (incident 2026-05). Default OFF. Same lifecycle
    // constraints as the freeze list above (after params + logging, before
    // networking/validation threads). See policy/planx_rollback.h.
    if (!InitPlanXRollback(args)) {
        return false; // InitError already reported the cause.
    }

    InitSignatureCache();
    InitScriptExecutionCache();

    int script_threads = args.GetIntArg("-par", DEFAULT_SCRIPTCHECK_THREADS);
    if (script_threads <= 0) {
        // -par=0 means autodetect (number of cores - 1 script threads)
        // -par=-n means "leave n cores free" (number of cores - n - 1 script threads)
        script_threads += GetNumCores();
    }

    // Subtract 1 because the main thread counts towards the par threads
    script_threads = std::max(script_threads - 1, 0);

    // Number of script-checking threads <= MAX_SCRIPTCHECK_THREADS
    script_threads = std::min(script_threads, MAX_SCRIPTCHECK_THREADS);

    LogPrintf("Script verification uses %d additional threads\n", script_threads);
    if (script_threads >= 1) {
        g_parallel_script_checks = true;
        StartScriptCheckWorkerThreads(script_threads);
    }

    assert(!node.scheduler);
    node.scheduler = std::make_unique<CScheduler>();

    // Start the lightweight task scheduler thread
    node.scheduler->m_service_thread = std::thread(util::TraceThread, "scheduler", [&] { node.scheduler->serviceQueue(); });

    // Gather some entropy once per minute.
    node.scheduler->scheduleEvery([]{
        RandAddPeriodic();
    }, std::chrono::minutes{1});

    GetMainSignals().RegisterBackgroundSignalScheduler(*node.scheduler);

    // Create client interfaces for wallets that are supposed to be loaded
    // according to -wallet and -disablewallet options. This only constructs
    // the interfaces, it doesn't load wallet data. Wallets actually get loaded
    // when load() and start() interface methods are called below.
    g_wallet_init_interface.Construct(node);
    uiInterface.InitWallet();

    /* Register RPC commands regardless of -server setting so they will be
     * available in the GUI RPC console even if external calls are disabled.
     */
    RegisterAllCoreRPCCommands(tableRPC);
    for (const auto& client : node.chain_clients) {
        client->registerRpcs();
    }
#ifdef ENABLE_WALLET
    // Register non-core wallet-only RPC commands. These are commands that
    // aren't a part of the wallet library but heavily rely on wallet logic.
    // TODO: Move them to chain client interfaces so they can be called
    //       with registerRpcs()
    if (!args.GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET)) {
        for (const auto& commands : {
            GetWalletEvoRPCCommands(),
            GetWalletGovernanceRPCCommands(),
            GetWalletMasternodeRPCCommands(),
        }) {
            node.wallet_loader->registerOtherRpcs(commands);
        }
    }
#endif // ENABLE_WALLET

#if ENABLE_ZMQ
    RegisterZMQRPCCommands(tableRPC);
#endif

    /* Start the RPC server already.  It will be started in "warmup" mode
     * and not really process calls already (but it will signify connections
     * that the server is there and will be ready later).  Warmup mode will
     * be disabled when initialisation is finished.
     */
    if (args.GetBoolArg("-server", false)) {
        uiInterface.InitMessage_connect(SetRPCWarmupStatus);
        if (!AppInitServers(node))
            return InitError(_("Unable to start HTTP server. See debug log for details."));
    }

    // ********************************************************* Step 5: verify wallet database integrity

    g_wallet_init_interface.InitAutoBackup();
    for (const auto& client : node.chain_clients) {
        if (!client->verify()) {
            return false;
        }
    }

    // ********************************************************* Step 6: network initialization
    // Note that we absolutely cannot open any actual connections
    // until the very end ("start node") as the UTXO/block state
    // is not yet setup and may end up being set up twice if we
    // need to reindex later.

    fListen = args.GetBoolArg("-listen", DEFAULT_LISTEN);
    fDiscover = args.GetBoolArg("-discover", true);
    const bool ignores_incoming_txs{args.GetBoolArg("-blocksonly", DEFAULT_BLOCKSONLY)};

    {

        // Read asmap file if configured
        std::vector<bool> asmap;
        if (args.IsArgSet("-asmap")) {
            fs::path asmap_path = args.GetPathArg("-asmap", DEFAULT_ASMAP_FILENAME);
            if (!asmap_path.is_absolute()) {
                asmap_path = gArgs.GetDataDirNet() / asmap_path;
            }
            if (!fs::exists(asmap_path)) {
                InitError(strprintf(_("Could not find asmap file %s"), fs::quoted(fs::PathToString(asmap_path))));
                return false;
            }
            asmap = DecodeAsmap(asmap_path);
            if (asmap.size() == 0) {
                InitError(strprintf(_("Could not parse asmap file %s"), fs::quoted(fs::PathToString(asmap_path))));
                return false;
            }
            const uint256 asmap_version = (HashWriter{} << asmap).GetHash();
            LogPrintf("Using asmap version %s for IP bucketing\n", asmap_version.ToString());
        } else {
            LogPrintf("Using /16 prefix for IP bucketing\n");
        }

        // Initialize netgroup manager
        assert(!node.netgroupman);
        node.netgroupman = std::make_unique<NetGroupManager>(std::move(asmap));

        // Initialize addrman
        assert(!node.addrman);
        uiInterface.InitMessage(_("Loading P2P addresses…").translated);
        if (const auto error{LoadAddrman(*node.netgroupman, args, node.addrman)}) {
            return InitError(*error);
        }
    }

    std::string sem_str = args.GetArg("-socketevents", DEFAULT_SOCKETEVENTS);
    ::g_socket_events_mode = SEMFromString(sem_str);
    if (::g_socket_events_mode == SocketEventsMode::Unknown) {
        return InitError(strprintf(_("Invalid -socketevents ('%s') specified. Only these modes are supported: %s"), sem_str, GetSupportedSocketEventsStr()));
    }

    // We need to initialize g_stats_client early as currently, g_stats_client is called
    // regardless of whether transmitting stats are desirable or not and if
    // g_stats_client isn't present when that attempt is made, the client will crash.
    {
        auto stats_client = StatsdClient::make(args);
        if (!stats_client) {
            return InitError(_("Cannot init Statsd client") + Untranslated(" (") + util::ErrorString(stats_client) + Untranslated(")"));
        }
        ::g_stats_client = std::move(*stats_client);
    }

    assert(!node.banman);
    node.banman = std::make_unique<BanMan>(gArgs.GetDataDirNet() / "banlist", &uiInterface, args.GetIntArg("-bantime", DEFAULT_MISBEHAVING_BANTIME));
    assert(!node.connman);
    node.connman = std::make_unique<CConnman>(GetRand<uint64_t>(),
                                              GetRand<uint64_t>(),
                                              *node.addrman, *node.netgroupman, args.GetBoolArg("-networkactive", true));

    assert(!node.fee_estimator);
    // Don't initialize fee estimation with old data if we don't relay transactions,
    // as they would never get updated.
    if (!ignores_incoming_txs) node.fee_estimator = std::make_unique<CBlockPolicyEstimator>();

    assert(!node.mn_metaman);
    node.mn_metaman = std::make_unique<CMasternodeMetaMan>();

    assert(!node.netfulfilledman);
    node.netfulfilledman = std::make_unique<CNetFulfilledRequestManager>();

    const bool is_governance_enabled{!args.GetBoolArg("-disablegovernance", !DEFAULT_GOVERNANCE_ENABLE)};

    assert(!node.sporkman);
    node.sporkman = std::make_unique<CSporkManager>();
    g_sporkman = node.sporkman.get();
    node.chainlocks = std::make_unique<chainlock::Chainlocks>(*node.sporkman);

    std::vector<std::string> vSporkAddresses;
    if (args.IsArgSet("-sporkaddr")) {
        if (!chainparams.IsTestChain() && !chainparams.IsMockableChain()) {
            return InitError(strprintf(_("-sporkaddr is only valid on test networks")));
        }
        vSporkAddresses = args.GetArgs("-sporkaddr");
    } else {
        vSporkAddresses = Params().SporkAddresses();
    }
    for (const auto& address: vSporkAddresses) {
        if (!node.sporkman->SetSporkAddress(address)) {
            return InitError(_("Invalid spork address specified with -sporkaddr"));
        }
    }

    int minsporkkeys = args.GetIntArg("-minsporkkeys", Params().MinSporkKeys());
    if (args.IsArgSet("-minsporkkeys")) {
        if (!chainparams.IsTestChain() && !chainparams.IsMockableChain()) {
            return InitError(strprintf(_("-minsporkkeys is only valid on test networks")));
        }
    }
    if (!node.sporkman->SetMinSporkKeys(minsporkkeys)) {
        return InitError(_("Invalid minimum number of spork signers specified with -minsporkkeys"));
    }


    if (args.IsArgSet("-sporkkey")) { // spork priv key
        if (!node.sporkman->SetPrivKey(args.GetArg("-sporkkey", ""))) {
            return InitError(_("Unable to sign spork message, wrong key?"));
        }
    }

    // Check port numbers
    for (const std::string port_option : {
        "-port",
        "-rpcport",
    }) {
        if (args.IsArgSet(port_option)) {
            const std::string port = args.GetArg(port_option, "");
            uint16_t n;
            if (!ParseUInt16(port, &n) || n == 0) {
                return InitError(InvalidPortErrMsg(port_option, port));
            }
        }
    }

    for ([[maybe_unused]] const auto& [arg, unix] : std::vector<std::pair<std::string, bool>>{
        // arg name                 UNIX socket support
        {"-i2psam",                             false},
        {"-onion",                               true},
        {"-proxy",                               true},
        {"-rpcbind",                            false},
        {"-torcontrol",                         false},
        {"-whitebind",                          false},
        {"-zmqpubhashblock",                     true},
        {"-zmqpubhashchainlock",                 true},
        {"-zmqpubhashgovernanceobject",          true},
        {"-zmqpubhashgovernancevote",            true},
        {"-zmqpubhashinstantsenddoublespend",    true},
        {"-zmqpubhashrecoveredsig",              true},
        {"-zmqpubhashtx",                        true},
        {"-zmqpubhashtxlock",                    true},
        {"-zmqpubrawblock",                      true},
        {"-zmqpubrawchainlock",                  true},
        {"-zmqpubrawchainlocksig",               true},
        {"-zmqpubrawgovernancevote",             true},
        {"-zmqpubrawgovernanceobject",           true},
        {"-zmqpubrawinstantsenddoublespend",     true},
        {"-zmqpubrawrecoveredsig",               true},
        {"-zmqpubrawtx",                         true},
        {"-zmqpubrawtxlock",                     true},
        {"-zmqpubrawtxlocksig",                  true},
        {"-zmqpubsequence",                      true},
    }) {
        for (const std::string& socket_addr : args.GetArgs(arg)) {
            std::string host_out;
            uint16_t port_out{0};
            if (!SplitHostPort(socket_addr, port_out, host_out)) {
#if HAVE_SOCKADDR_UN
                // Allow unix domain sockets for some options e.g. unix:/some/file/path
                if (!unix || socket_addr.find(ADDR_PREFIX_UNIX) != 0) {
                    return InitError(InvalidPortErrMsg(arg, socket_addr));
                }
#else
                return InitError(InvalidPortErrMsg(arg, socket_addr));
#endif
            }
        }
    }

    for (const std::string& socket_addr : args.GetArgs("-bind")) {
        std::string host_out;
        uint16_t port_out{0};
        std::string bind_socket_addr = socket_addr.substr(0, socket_addr.rfind('='));
        if (!SplitHostPort(bind_socket_addr, port_out, host_out)) {
            return InitError(InvalidPortErrMsg("-bind", socket_addr));
        }
    }

    // sanitize comments per BIP-0014, format user agent and check total size
    std::vector<std::string> uacomments;

    if (chainparams.NetworkIDString() == CBaseChainParams::DEVNET) {
        // Add devnet name to user agent. This allows to disconnect nodes immediately if they don't belong to our own devnet
        uacomments.push_back(strprintf("devnet.%s", args.GetDevNetName()));
    }

    for (const std::string& cmt : args.GetArgs("-uacomment")) {
        if (cmt != SanitizeString(cmt, SAFE_CHARS_UA_COMMENT))
            return InitError(strprintf(_("User Agent comment (%s) contains unsafe characters."), cmt));
        uacomments.push_back(cmt);
    }
    strSubVersion = FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, uacomments);
    if (strSubVersion.size() > MAX_SUBVERSION_LENGTH) {
        return InitError(strprintf(_("Total length of network version string (%i) exceeds maximum length (%i). Reduce the number or size of uacomments."),
            strSubVersion.size(), MAX_SUBVERSION_LENGTH));
    }

    if (args.IsArgSet("-onlynet")) {
        g_reachable_nets.RemoveAll();
        for (const std::string& snet : args.GetArgs("-onlynet")) {
            enum Network net = ParseNetwork(snet);
            if (net == NET_UNROUTABLE)
                return InitError(strprintf(_("Unknown network specified in -onlynet: '%s'"), snet));
            g_reachable_nets.Add(net);
        }
    }

    if (!args.IsArgSet("-cjdnsreachable")) {
        if (args.IsArgSet("-onlynet") && g_reachable_nets.Contains(NET_CJDNS)) {
            return InitError(
                _("Outbound connections restricted to CJDNS (-onlynet=cjdns) but "
                  "-cjdnsreachable is not provided"));
        }
        g_reachable_nets.Remove(NET_CJDNS);
    }
    // Now g_reachable_nets.Contains(NET_CJDNS) is true if:
    // 1. -cjdnsreachable is given and
    // 2.1. -onlynet is not given or
    // 2.2. -onlynet=cjdns is given

    // Requesting DNS seeds entails connecting to IPv4/IPv6, which -onlynet options may prohibit:
    // If -dnsseed=1 is explicitly specified, abort. If it's left unspecified by the user, we skip
    // the DNS seeds by adjusting -dnsseed in InitParameterInteraction.
    if (args.GetBoolArg("-dnsseed", DEFAULT_DNSSEED) == true && !g_reachable_nets.Contains(NET_IPV4) && !g_reachable_nets.Contains(NET_IPV6)) {
        return InitError(strprintf(_("Incompatible options: -dnsseed=1 was explicitly specified, but -onlynet forbids connections to IPv4/IPv6")));
    };

    // Check for host lookup allowed before parsing any network related parameters
    fNameLookup = args.GetBoolArg("-dns", DEFAULT_NAME_LOOKUP);

    Proxy onion_proxy;

    bool proxyRandomize = args.GetBoolArg("-proxyrandomize", DEFAULT_PROXYRANDOMIZE);
    // -proxy sets a proxy for all outgoing network traffic
    // -noproxy (or -proxy=0) as well as the empty string can be used to not set a proxy, this is the default
    std::string proxyArg = args.GetArg("-proxy", "");
    if (proxyArg != "" && proxyArg != "0") {
        Proxy addrProxy;
        if (IsUnixSocketPath(proxyArg)) {
            addrProxy = Proxy(proxyArg, proxyRandomize);
        } else {
            const std::optional<CService> proxyAddr{Lookup(proxyArg, 9050, fNameLookup)};
            if (!proxyAddr.has_value()) {
                return InitError(strprintf(_("Invalid -proxy address or hostname: '%s'"), proxyArg));
            }

            addrProxy = Proxy(proxyAddr.value(), proxyRandomize);
        }

        if (!addrProxy.IsValid())
            return InitError(strprintf(_("Invalid -proxy address or hostname: '%s'"), proxyArg));

        SetProxy(NET_IPV4, addrProxy);
        SetProxy(NET_IPV6, addrProxy);
        SetProxy(NET_CJDNS, addrProxy);
        SetNameProxy(addrProxy);
        onion_proxy = addrProxy;
    }

    const bool onlynet_used_with_onion{args.IsArgSet("-onlynet") && g_reachable_nets.Contains(NET_ONION)};

    // -onion can be used to set only a proxy for .onion, or override normal proxy for .onion addresses
    // -noonion (or -onion=0) disables connecting to .onion entirely
    // An empty string is used to not override the onion proxy (in which case it defaults to -proxy set above, or none)
    std::string onionArg = args.GetArg("-onion", "");
    if (onionArg != "") {
        if (onionArg == "0") { // Handle -noonion/-onion=0
            onion_proxy = Proxy{};
            if (onlynet_used_with_onion) {
                return InitError(
                    _("Outbound connections restricted to Tor (-onlynet=onion) but the proxy for "
                      "reaching the Tor network is explicitly forbidden: -onion=0"));
            }
        } else {
            if (IsUnixSocketPath(onionArg)) {
                onion_proxy = Proxy(onionArg, proxyRandomize);
            } else {
                const std::optional<CService> addr{Lookup(onionArg, 9050, fNameLookup)};
                if (!addr.has_value() || !addr->IsValid()) {
                    return InitError(strprintf(_("Invalid -onion address or hostname: '%s'"), onionArg));
                }

                onion_proxy = Proxy(addr.value(), proxyRandomize);
            }
        }
    }

    if (onion_proxy.IsValid()) {
        SetProxy(NET_ONION, onion_proxy);
    } else {
        // If -listenonion is set, then we will (try to) connect to the Tor control port
        // later from the torcontrol thread and may retrieve the onion proxy from there.
        const bool listenonion_disabled{!args.GetBoolArg("-listenonion", DEFAULT_LISTEN_ONION)};
        if (onlynet_used_with_onion && listenonion_disabled) {
            return InitError(
                _("Outbound connections restricted to Tor (-onlynet=onion) but the proxy for "
                  "reaching the Tor network is not provided: none of -proxy, -onion or "
                  "-listenonion is given"));
        }
        g_reachable_nets.Remove(NET_ONION);
    }

    for (const std::string& strAddr : args.GetArgs("-externalip")) {
        const std::optional<CService> addrLocal{Lookup(strAddr, GetListenPort(), fNameLookup)};
        if (addrLocal.has_value() && addrLocal->IsValid())
            AddLocal(addrLocal.value(), LOCAL_MANUAL);
        else
            return InitError(ResolveErrMsg("externalip", strAddr));
    }

#if ENABLE_ZMQ
    g_zmq_notification_interface = CZMQNotificationInterface::Create();

    if (g_zmq_notification_interface) {
        RegisterValidationInterface(g_zmq_notification_interface.get());
    }
#endif

    // ********************************************************* Step 7a: Load sporks

    if (!node.sporkman->LoadCache()) {
        auto file_path = fs::PathToString(gArgs.GetDataDirNet() / "sporks.dat");
        return InitError(strprintf(_("Failed to load sporks cache from %s"), file_path));
    }

    // ********************************************************* Step 7a2: Load Sapling parameters
    {
        const std::string SPEND_SHA256 = "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13";
        const std::string OUTPUT_SHA256 = "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4";

        fs::path sapling_dir;
        if (args.IsArgSet("-saplingparamdir")) {
            sapling_dir = args.GetPathArg("-saplingparamdir");
        } else {
            sapling_dir = GetDefaultSaplingDir();
        }

        fs::path spend_path = sapling_dir / "sapling-spend.params";
        fs::path output_path = sapling_dir / "sapling-output.params";

        // Auto-download if missing
        if (!fs::exists(spend_path) || !fs::exists(output_path)) {
            LogPrintf("Sapling parameters not found in %s, downloading automatically...\n", fs::PathToString(sapling_dir));
            uiInterface.InitMessage(_("Downloading Sapling parameters (one-time, ~50 MB)...").translated);

            if (!fs::exists(spend_path)) {
                if (!DownloadSaplingParam("sapling-spend.params", spend_path, SPEND_SHA256)) {
                    return InitError(strprintf(_("Failed to download sapling-spend.params. "
                                                "Check your internet connection, or manually place the file in %s. "
                                                "You can also use -saplingparamdir= to specify a custom location."),
                                               fs::PathToString(sapling_dir)));
                }
            }
            if (!fs::exists(output_path)) {
                if (!DownloadSaplingParam("sapling-output.params", output_path, OUTPUT_SHA256)) {
                    return InitError(strprintf(_("Failed to download sapling-output.params. "
                                                "Check your internet connection, or manually place the file in %s. "
                                                "You can also use -saplingparamdir= to specify a custom location."),
                                               fs::PathToString(sapling_dir)));
                }
            }
        }

        LogPrintf("Loading Sapling parameters from %s\n", fs::PathToString(sapling_dir));
        if (!sapling::InitSaplingParams(spend_path, output_path)) {
            return InitError(strprintf(_("Failed to load Sapling parameters from %s. "
                                        "The files may be corrupt. Delete them and restart to re-download."),
                                       fs::PathToString(sapling_dir)));
        }
        LogPrintf("Sapling: activation height=%d\n", chainparams.GetConsensus().SaplingHeight);
    }

    // ********************************************************* Step 7a2: Initialize HMP identity + Groth16 params
    {
        g_hmp_identity = std::make_unique<CHMPIdentity>();
        if (!g_hmp_identity->Init(gArgs.GetDataDirNet())) {
            LogPrintf("HMP: WARNING: failed to initialize HMP identity. Seal signing disabled.\n");
            g_hmp_identity.reset();
        } else {
            LogPrintf("HMP: identity initialized, activation height=%d (stages: S2=%d, S3=%d, S4=%d)\n",
                      chainparams.GetConsensus().HMPHeight,
                      chainparams.GetConsensus().nHMPStage2Height,
                      chainparams.GetConsensus().nHMPStage3Height,
                      chainparams.GetConsensus().nHMPStage4Height);
        }
        g_hmp_privilege = std::make_unique<CHMPPrivilegeTracker>(chainparams.GetConsensus());
        g_hmp_commitments = std::make_unique<CHMPCommitmentRegistry>(
            chainparams.GetConsensus().nHMPCommitmentOffset,
            chainparams.GetConsensus().nHMPDominanceCatchMaxLookback + chainparams.GetConsensus().nHMPPrivilegeWindow);
        g_hmp_commit_pool = std::make_unique<CHMPCommitPool>();
        g_seal_manager = std::make_unique<CSealManager>(chainparams.GetConsensus(),
                                                         g_hmp_identity.get(),
                                                         g_hmp_privilege.get(),
                                                         g_hmp_commitments.get());
        g_seal_manager->SetConnman(node.connman.get());
        // g_seal_manager->Start() is deferred until after RebuildHMPState()
        // so that privilege/commitment trackers are populated first.
        if (chainparams.GetConsensus().nHMPCommitmentOffset > 0) {
            LogPrintf("HMP: commitment offset=%d blocks\n", chainparams.GetConsensus().nHMPCommitmentOffset);
            // Auto-commit own pubkey to the pool so it gets embedded + relayed.
            // SPORK_25_HMP_ENABLED gates commitment broadcasting.
            // At startup g_sporkman may not be set yet (sporks load later), so
            // also check for null.  If the spork is inactive or the pointer is
            // not yet available, defer the self-commit; it will be re-attempted
            // on each outbound VERACK anyway (net_processing.cpp).
            if (g_hmp_identity && g_hmp_identity->IsValid() && g_hmp_commit_pool
                && (!g_sporkman || g_sporkman->IsSporkActive(SPORK_25_HMP_ENABLED))) {
                CPubKeyCommit selfCommit;
                selfCommit.pubKey = g_hmp_identity->GetPublicKey();
                selfCommit.nTimestamp = GetTime();
                uint256 msgHash = CPubKeyCommit::SignatureHash(selfCommit.pubKey);
                selfCommit.signature = g_hmp_identity->Sign(msgHash);
                if (selfCommit.Verify() && g_hmp_commit_pool->Add(selfCommit) == HMPAcceptResult::ACCEPTED) {
                    LogPrintf("HMP: queued own pubkey commitment for broadcast\n");
                }
            }
        }

        // Initialize HMP Groth16 participation proof parameters
        if (!hmp_proof::InitParams()) {
            LogPrintf("HMP: WARNING: Groth16 param init failed. zk proofs disabled.\n");
        }
    }

    // ********************************************************* Step 7b: load block chain

    fReindex = args.GetBoolArg("-reindex", false);
    bool fReindexChainState = args.GetBoolArg("-reindex-chainstate", false);

    // cache size calculations
    CacheSizes cache_sizes = CalculateCacheSizes(args, g_enabled_filter_types.size());

    int64_t nMempoolSizeMax = args.GetIntArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    LogPrintf("Cache configuration:\n");
    LogPrintf("* Using %.1f MiB for block index database\n", cache_sizes.block_tree_db * (1.0 / 1024 / 1024));
    if (args.GetBoolArg("-txindex", DEFAULT_TXINDEX)) {
        LogPrintf("* Using %.1f MiB for transaction index database\n", cache_sizes.tx_index * (1.0 / 1024 / 1024));
    }
    for (BlockFilterType filter_type : g_enabled_filter_types) {
        LogPrintf("* Using %.1f MiB for %s block filter index database\n",
                  cache_sizes.filter_index * (1.0 / 1024 / 1024), BlockFilterTypeName(filter_type));
    }
    LogPrintf("* Using %.1f MiB for chain state database\n", cache_sizes.coins_db * (1.0 / 1024 / 1024));
    LogPrintf("* Using %.1f MiB for in-memory UTXO set (plus up to %.1f MiB of unused mempool space)\n", cache_sizes.coins * (1.0 / 1024 / 1024), nMempoolSizeMax * (1.0 / 1024 / 1024));

    assert(!node.mempool);
    assert(!node.chainman);
    assert(!node.govman);
    assert(!node.mn_sync);
    const int mempool_check_ratio = std::clamp<int>(args.GetIntArg("-checkmempool", chainparams.DefaultConsistencyChecks() ? 1 : 0), 0, 1000000);

    for (bool fLoaded = false; !fLoaded && !ShutdownRequested();) {
        node.mempool = std::make_unique<CTxMemPool>(node.fee_estimator.get(), mempool_check_ratio);

        node.chainman = std::make_unique<ChainstateManager>(chainparams);
        ChainstateManager& chainman = *node.chainman;

        /**
         * The manager needs to be constructed regardless of whether governance
         * validation is needed or not.
         *
         * Instead, we decide whether to initialize its database based on whether we
         * need it or not further down and then query if the database is initialized
         * to check if validation is enabled.
         */
        node.mn_sync = std::make_unique<CMasternodeSync>(std::make_unique<NodeSyncNotifierImpl>(*node.connman, *node.netfulfilledman));

        node.govman = std::make_unique<CGovernanceManager>(*node.mn_metaman, *node.chainman, node.dmnman, *node.mn_sync);

        const bool fReset = fReindex;
        bilingual_str strLoadError;

        uiInterface.InitMessage(_("Loading block index…").translated);
        const auto load_block_index_start_time{SteadyClock::now()};
        std::optional<ChainstateLoadingError> maybe_load_error;
        try {
            maybe_load_error = LoadChainstate(fReset,
                                              chainman,
                                              *node.govman,
                                              *node.mn_metaman,
                                              *node.mn_sync,
                                              *node.sporkman,
                                              *node.chainlocks,
                                              node.chain_helper,
                                              node.dmnman,
                                              node.evodb,
                                              node.llmq_ctx,
                                              Assert(node.mempool.get()),
                                              args.GetDataDirNet(),
                                              fPruneMode,
                                              args.GetBoolArg("-addressindex", DEFAULT_ADDRESSINDEX),
                                              args.GetBoolArg("-spentindex", DEFAULT_SPENTINDEX),
                                              args.GetBoolArg("-timestampindex", DEFAULT_TIMESTAMPINDEX),
                                              chainparams.GetConsensus(),
                                              fReindexChainState,
                                              cache_sizes.block_tree_db,
                                              cache_sizes.coins_db,
                                              cache_sizes.coins,
                                              /*block_tree_db_in_memory=*/false,
                                              /*coins_db_in_memory=*/false,
                                              /*kerrigan_dbs_in_memory=*/false,
                                              /*bls_threads=*/[&args]() -> int8_t {
                                                  int8_t threads = args.GetIntArg("-parbls", llmq::DEFAULT_BLSCHECK_THREADS);
                                                  if (threads <= 0) {
                                                      // -parbls=0 means autodetect (number of cores - 1 validator threads)
                                                      // -parbls=-n means "leave n cores free" (number of cores - n - 1 validator threads)
                                                      threads += GetNumCores();
                                                  }
                                                  // Subtract 1 because the main thread counts towards the par threads
                                                  return std::clamp<int8_t>(threads - 1, 0, llmq::MAX_BLSCHECK_THREADS);
                                              }(),
                                              args.GetIntArg("-maxrecsigsage", llmq::DEFAULT_MAX_RECOVERED_SIGS_AGE),
                                              /*shutdown_requested=*/ShutdownRequested,
                                              /*coins_error_cb=*/[]() {
                                                  uiInterface.ThreadSafeMessageBox(
                                                      _("Error reading from database, shutting down."),
                                                      "", CClientUIInterface::MSG_ERROR);
                                              });
        } catch (const std::exception& e) {
            LogPrintf("%s\n", e.what());
            maybe_load_error = ChainstateLoadingError::ERROR_GENERIC_BLOCKDB_OPEN_FAILED;
        }
        if (maybe_load_error.has_value()) {
            switch (maybe_load_error.value()) {
            case ChainstateLoadingError::ERROR_LOADING_BLOCK_DB:
                strLoadError = _("Error loading block database");
                break;
            case ChainstateLoadingError::ERROR_BAD_GENESIS_BLOCK:
                // If the loaded chain has a wrong genesis, bail out immediately
                // (we're likely using a testnet datadir, or the other way around).
                return InitError(_("Incorrect or no genesis block found. Wrong datadir for network?"));
            case ChainstateLoadingError::ERROR_BAD_DEVNET_GENESIS_BLOCK:
                return InitError(_("Incorrect or no devnet genesis block found. Wrong datadir for devnet specified?"));
            case ChainstateLoadingError::ERROR_ADDRIDX_NEEDS_REINDEX:
                strLoadError = _("You need to rebuild the database using -reindex to enable -addressindex");
                break;
            case ChainstateLoadingError::ERROR_SPENTIDX_NEEDS_REINDEX:
                strLoadError = _("You need to rebuild the database using -reindex to enable -spentindex");
                break;
            case ChainstateLoadingError::ERROR_TIMEIDX_NEEDS_REINDEX:
                strLoadError = _("You need to rebuild the database using -reindex to enable -timestampindex");
                break;
            case ChainstateLoadingError::ERROR_PRUNED_NEEDS_REINDEX:
                strLoadError = _("You need to rebuild the database using -reindex to go back to unpruned mode.  This will redownload the entire blockchain");
                break;
            case ChainstateLoadingError::ERROR_LOAD_GENESIS_BLOCK_FAILED:
                strLoadError = _("Error initializing block database");
                break;
            case ChainstateLoadingError::ERROR_CHAINSTATE_UPGRADE_FAILED:
                return InitError(_("Unsupported chainstate database format found. "
                                   "Please restart with -reindex-chainstate. This will "
                                   "rebuild the chainstate database."));
            case ChainstateLoadingError::ERROR_REPLAYBLOCKS_FAILED:
                strLoadError = _("Unable to replay blocks. You will need to rebuild the database using -reindex-chainstate.");
                break;
            case ChainstateLoadingError::ERROR_LOADCHAINTIP_FAILED:
                strLoadError = _("Error initializing block database");
                break;
            case ChainstateLoadingError::ERROR_GENERIC_BLOCKDB_OPEN_FAILED:
                strLoadError = _("Error opening block database");
                break;
            case ChainstateLoadingError::ERROR_COMMITING_EVO_DB:
                strLoadError = _("Failed to commit Evo database");
                break;
            case ChainstateLoadingError::ERROR_UPGRADING_EVO_DB:
                strLoadError = _("Failed to upgrade Evo database");
                break;
            case ChainstateLoadingError::ERROR_UPGRADING_SIGNALS_DB:
                strLoadError = _("Error upgrading evo database for EHF");
                break;
            case ChainstateLoadingError::SHUTDOWN_PROBED:
                break;
            }
        } else {
            LogPrintf("%s: address index %s\n", __func__, fAddressIndex ? "enabled" : "disabled");
            LogPrintf("%s: timestamp index %s\n", __func__, fTimestampIndex ? "enabled" : "disabled");
            LogPrintf("%s: spent index %s\n", __func__, fSpentIndex ? "enabled" : "disabled");

            std::optional<ChainstateLoadVerifyError> maybe_verify_error;
            try {
                uiInterface.InitMessage(_("Verifying blocks…").translated);
                auto check_blocks = args.GetIntArg("-checkblocks", DEFAULT_CHECKBLOCKS);
                if (chainman.m_blockman.m_have_pruned && check_blocks > MIN_BLOCKS_TO_KEEP) {
                    LogWarning("pruned datadir may not have more than %d blocks; only checking available blocks\n",
                                      MIN_BLOCKS_TO_KEEP);
                }
                maybe_verify_error = VerifyLoadedChainstate(chainman,
                                                            *Assert(node.evodb.get()),
                                                            fReset,
                                                            fReindexChainState,
                                                            chainparams.GetConsensus(),
                                                            check_blocks,
                                                            args.GetIntArg("-checklevel", DEFAULT_CHECKLEVEL),
                                                            /*get_unix_time_seconds=*/static_cast<int64_t(*)()>(GetTime),
                                                            [](bool bls_state) {
                                                                LogPrintf("%s: bls_legacy_scheme=%d\n", __func__, bls_state);
                                                            });
            } catch (const std::exception& e) {
                LogPrintf("%s\n", e.what());
                maybe_verify_error = ChainstateLoadVerifyError::ERROR_GENERIC_FAILURE;
            }
            if (maybe_verify_error.has_value()) {
                switch (maybe_verify_error.value()) {
                case ChainstateLoadVerifyError::ERROR_BLOCK_FROM_FUTURE:
                    strLoadError = _("The block database contains a block which appears to be from the future. "
                                     "This may be due to your computer's date and time being set incorrectly. "
                                     "Only rebuild the block database if you are sure that your computer's date and time are correct");
                    break;
                case ChainstateLoadVerifyError::ERROR_CORRUPTED_BLOCK_DB:
                    strLoadError = _("Corrupted block database detected");
                    break;
                case ChainstateLoadVerifyError::ERROR_EVO_DB_SANITY_FAILED:
                    strLoadError = _("Error initializing block database");
                    break;
                case ChainstateLoadVerifyError::ERROR_GENERIC_FAILURE:
                    strLoadError = _("Error opening block database");
                    break;
                }
            } else {
                fLoaded = true;
                LogPrintf(" block index %15dms\n", Ticks<std::chrono::milliseconds>(SteadyClock::now() - load_block_index_start_time));
            }
        }

        if (!fLoaded && !ShutdownRequested()) {
            // first suggest a reindex
            if (!fReset) {
                bool fRet = uiInterface.ThreadSafeQuestion(
                    strLoadError + Untranslated(".\n\n") + _("Do you want to rebuild the block database now?"),
                    strLoadError.original + ".\nPlease restart with -reindex or -reindex-chainstate to recover.",
                    "", CClientUIInterface::MSG_ERROR | CClientUIInterface::BTN_ABORT);
                if (fRet) {
                    fReindex = true;
                    AbortShutdown();
                } else {
                    LogPrintf("Aborted block database rebuild. Exiting.\n");
                    return false;
                }
            } else {
                return InitError(strLoadError);
            }
        }
    }

    // As LoadBlockIndex can take several minutes, it's possible the user
    // requested to kill the GUI during the last operation. If so, exit.
    // As the program has not fully started yet, Shutdown() is possibly overkill.
    if (ShutdownRequested()) {
        LogPrintf("Shutdown requested. Exiting.\n");
        return false;
    }

    ChainstateManager& chainman = *Assert(node.chainman);

    // PLAN X: refuse to start if the derived caches (sapling tree, evodb)
    // disagree with the active chain tip. Catches the v1.2.3 in-process-rollback
    // contamination class BEFORE we extend the chain or run another reorg on
    // top of stale state. Operator recovery is -resetchainstate. See
    // DetectPostRollbackContamination + policy/planx_rollback.h.
    if (!DetectPostRollbackContamination(node)) {
        return false; // InitError already reported the cause.
    }

    // PLAN X: force the in-process rollback reorg on an already-synced
    // node BEFORE rebuilding HMP state and BEFORE networking, so all downstream
    // state (HMP trackers, peer relay) reflects the rolled-back chain. Default
    // no-op (gate off / theft block absent / not on the active chain). See
    // ActivatePlanXRollbackReorg + policy/planx_rollback.h.
    if (!ActivatePlanXRollbackReorg(chainman)) {
        return false; // InitError already reported the cause.
    }

    // Wire BroodNode lookup into HMP privilege tracker (requires dmnman from LoadChainstate)
    if (g_hmp_privilege && node.dmnman) {
        g_brood_lookup = std::make_unique<CBroodNodeLookup>(*node.dmnman);
        g_hmp_privilege->SetMasternodeLookup(g_brood_lookup.get());
        LogPrintf("HMP: BroodNode lookup initialized (BROOD tier enabled)\n");
    }

    // Rebuild HMP in-memory tracker state from the active chain.
    // Must happen after LoadChainstate (chain tip is set) and before accepting
    // new blocks so that commitment/privilege trackers are populated.
    if (g_hmp_privilege || g_hmp_commitments) {
        LOCK(::cs_main);
        if (!chainman.ActiveChainstate().RebuildHMPState()) {
            return InitError(_("Unable to rebuild HMP seal state from disk. This node is over-pruned or has a corrupt block for deterministic seal weighting; reindex or run without pruning."));
        }
    }

    if (g_seal_manager) {
        g_seal_manager->Start();
    }

    node.clhandler = std::make_unique<chainlock::ChainlockHandler>(*node.chainlocks, chainman, *node.mempool, *node.mn_sync);
    RegisterValidationInterface(node.clhandler.get());

    assert(!node.peerman);
    node.peerman = PeerManager::make(chainparams, *node.connman, *node.addrman, node.banman.get(),
                                     chainman, *node.mempool, *node.mn_metaman, *node.mn_sync,
                                     *node.govman, *node.sporkman, *node.chainlocks, *node.clhandler, node.active_ctx, node.dmnman,
                                     node.llmq_ctx, node.observer_ctx, ignores_incoming_txs);
    RegisterValidationInterface(node.peerman.get());

    g_ds_notification_interface = std::make_unique<CDSNotificationInterface>(
        *node.connman, *node.mn_sync, *node.govman, chainman, node.dmnman, node.llmq_ctx
    );
    RegisterValidationInterface(g_ds_notification_interface.get());

    // ********************************************************* Step 7c: Setup masternode mode or watch-only mode
    assert(!node.active_ctx);
    assert(!node.observer_ctx);

    const bool quorums_recovery = args.GetBoolArg("-llmq-data-recovery", llmq::DEFAULT_ENABLE_QUORUM_DATA_RECOVERY);
    const bool quorums_watch = args.GetBoolArg("-watchquorums", llmq::DEFAULT_WATCH_QUORUMS);
    const llmq::QvvecSyncModeMap sync_map{llmq::GetEnabledQuorumVvecSyncEntries(args)};
    const util::DbWrapperParams kerrigan_db_params{.path = args.GetDataDirNet(), .memory = false, .wipe = (fReindex || fReindexChainState)};
    if (const auto operator_sk_str = args.GetArg("-masternodeblsprivkey", ""); !operator_sk_str.empty()) {
        const CBLSSecretKey operator_sk{ParseHex(operator_sk_str)};
        if (!operator_sk.IsValid()) {
            return InitError(_("Invalid masternodeblsprivkey. Please see documentation."));
        }
        // Will init later in ThreadImport
        node.active_ctx = std::make_unique<ActiveContext>(*node.llmq_ctx->bls_worker, chainman, *node.connman, *node.dmnman, *node.govman, *node.mn_metaman,
                                                          *node.sporkman, *node.chainlocks, *node.mempool, *node.clhandler, *node.llmq_ctx->isman,
                                                          *node.llmq_ctx->quorum_block_processor, *node.llmq_ctx->qman, *node.llmq_ctx->qsnapman, *node.llmq_ctx->sigman,
                                                          *node.mn_sync, operator_sk, sync_map, kerrigan_db_params, quorums_recovery, quorums_watch);
        RegisterValidationInterface(node.active_ctx.get());
    } else if (quorums_watch) {
        node.observer_ctx = std::make_unique<llmq::ObserverContext>(*node.llmq_ctx->bls_worker, *node.connman, *node.dmnman, *node.mn_metaman, *node.mn_sync,
                                                                    *node.llmq_ctx->quorum_block_processor, *node.llmq_ctx->qman, *node.llmq_ctx->qsnapman,
                                                                    chainman, *node.sporkman, sync_map, kerrigan_db_params, quorums_recovery);
        RegisterValidationInterface(node.observer_ctx.get());
    }

    // ********************************************************* Step 7d: Setup other Kerrigan services

    node.peerman->AddExtraHandler(std::make_unique<NetInstantSend>(node.peerman.get(), *node.llmq_ctx->isman, *node.llmq_ctx->qman, chainman.ActiveChainstate()));
    node.peerman->AddExtraHandler(std::make_unique<llmq::NetSigning>(node.peerman.get(), *node.llmq_ctx->sigman, node.active_ctx ? node.active_ctx->shareman.get() : nullptr, *node.sporkman));

    bool fLoadCacheFiles = !(fReindex || fReindexChainState) && (chainman.ActiveChain().Tip() != nullptr);

    if (!node.netfulfilledman->LoadCache(fLoadCacheFiles)) {
        auto file_path = fs::PathToString(gArgs.GetDataDirNet() / "netfulfilled.dat");
        if (fLoadCacheFiles) {
            return InitError(strprintf(_("Failed to load fulfilled requests cache from %s"), file_path));
        }
        return InitError(strprintf(_("Failed to clear fulfilled requests cache at %s"), file_path));
    }

    if (!node.mn_metaman->LoadCache(fLoadCacheFiles)) {
        auto file_path = fs::PathToString(gArgs.GetDataDirNet() / "mncache.dat");
        if (fLoadCacheFiles) {
            return InitError(strprintf(_("Failed to load masternode cache from %s"), file_path));
        }
        return InitError(strprintf(_("Failed to clear masternode cache at %s"), file_path));
    }

    if (is_governance_enabled) {
        if (!node.govman->LoadCache(fLoadCacheFiles)) {
            auto file_path = fs::PathToString(gArgs.GetDataDirNet() / "governance.dat");
            if (fLoadCacheFiles) {
                return InitError(strprintf(_("Failed to load governance cache from %s"), file_path));
            }
            return InitError(strprintf(_("Failed to clear governance cache at %s"), file_path));
        }
        node.peerman->AddExtraHandler(std::make_unique<NetGovernance>(node.peerman.get(), *node.govman, *node.mn_sync, *node.netfulfilledman, *node.connman));
    }
    node.peerman->AddExtraHandler(std::make_unique<SyncManager>(node.peerman.get(), *node.govman, *node.mn_sync, *node.connman, *node.netfulfilledman));

    // ********************************************************* Step 8: start indexers
    if (args.GetBoolArg("-txindex", DEFAULT_TXINDEX)) {
        g_txindex = std::make_unique<TxIndex>(cache_sizes.tx_index, false, fReindex);
        if (!g_txindex->Start(chainman.ActiveChainstate())) {
            return false;
        }
    }

    for (const auto& filter_type : g_enabled_filter_types) {
        InitBlockFilterIndex(filter_type, cache_sizes.filter_index, false, fReindex);
        if (!GetBlockFilterIndex(filter_type)->Start(chainman.ActiveChainstate())) {
            return false;
        }
    }

    if (args.GetBoolArg("-coinstatsindex", DEFAULT_COINSTATSINDEX)) {
        g_coin_stats_index = std::make_unique<CoinStatsIndex>(/* cache size */ 0, false, fReindex);
        if (!g_coin_stats_index->Start(chainman.ActiveChainstate())) {
            return false;
        }
    }

    // ********************************************************* Step 9: load wallet
    for (const auto& client : node.chain_clients) {
        if (!client->load()) {
            return false;
        }
    }

    // As InitLoadWallet can take several minutes, it's possible the user
    // requested to kill the GUI during the last operation. If so, exit.
    if (ShutdownRequested())
    {
        LogPrintf("Shutdown requested. Exiting.\n");
        return false;
    }
    // ********************************************************* Step 10: data directory maintenance

    // if pruning, perform the initial blockstore prune
    // after any wallet rescanning has taken place.
    if (fPruneMode) {
        if (!fReindex) {
            LOCK(cs_main);
            for (CChainState* chainstate : chainman.GetAll()) {
                uiInterface.InitMessage(_("Pruning blockstore…").translated);
                chainstate->PruneAndFlush();
            }
        }
    } else {
        LogPrintf("Setting NODE_NETWORK on non-prune mode\n");
        nLocalServices = ServiceFlags(nLocalServices | NODE_NETWORK);
    }

    // As PruneAndFlush can take several minutes, it's possible the user
    // requested to kill the GUI during the last operation. If so, exit.
    if (ShutdownRequested())
    {
        LogPrintf("Shutdown requested. Exiting.\n");
        return false;
    }

    // ********************************************************* Step 10a: schedule Kerrigan-specific tasks

    node.peerman->StartHandlers();
    node.clhandler->Start();
    if (node.observer_ctx) node.observer_ctx->Start();

    node.scheduler->scheduleEvery(std::bind(&CNetFulfilledRequestManager::DoMaintenance, std::ref(*node.netfulfilledman)), std::chrono::minutes{1});
    node.scheduler->scheduleEvery(std::bind(&CMasternodeUtils::DoMaintenance, std::ref(*node.connman), std::ref(*node.dmnman), std::ref(*node.mn_sync)), std::chrono::minutes{1});
    node.scheduler->scheduleEvery(std::bind(&CDeterministicMNManager::DoMaintenance, std::ref(*node.dmnman)), std::chrono::seconds{10});
    node.peerman->ScheduleHandlers(*node.scheduler);

    if (node.active_ctx) {
        node.active_ctx->Start(*node.connman, *node.peerman);
        node.scheduler->scheduleEvery(std::bind(&llmq::CDKGSessionManager::CleanupOldContributions, std::ref(*node.active_ctx->qdkgsman)), std::chrono::hours{1});
    }

    if (::g_stats_client->active()) {
        int nStatsPeriod = std::min(std::max((int)args.GetIntArg("-statsperiod", DEFAULT_STATSD_PERIOD), MIN_STATSD_PERIOD), MAX_STATSD_PERIOD);
        node.scheduler->scheduleEvery(std::bind(&PeriodicStats, std::ref(node)), std::chrono::seconds{nStatsPeriod});
    }

    // ********************************************************* Step 11: import blocks

    if (!CheckDiskSpace(gArgs.GetDataDirNet())) {
        InitError(strprintf(_("Error: Disk space is low for %s"), fs::quoted(fs::PathToString(gArgs.GetDataDirNet()))));
        return false;
    }
    if (!CheckDiskSpace(gArgs.GetBlocksDirPath())) {
        InitError(strprintf(_("Error: Disk space is low for %s"), fs::quoted(fs::PathToString(gArgs.GetBlocksDirPath()))));
        return false;
    }

    int chain_active_height = WITH_LOCK(cs_main, return chainman.ActiveChain().Height());

    // On first startup, warn on low block storage space
    if (!fReindex && !fReindexChainState && chain_active_height <= 1) {
        uint64_t additional_bytes_needed = fPruneMode ? nPruneTarget
            : chainparams.AssumedBlockchainSize() * 1024 * 1024 * 1024;

        if (!CheckDiskSpace(args.GetBlocksDirPath(), additional_bytes_needed)) {
            InitWarning(strprintf(_(
                    "Disk space for %s may not accommodate the block files. " \
                    "Approximately %u GB of data will be stored in this directory."
                ),
                fs::quoted(fs::PathToString(args.GetBlocksDirPath())),
                chainparams.AssumedBlockchainSize()
            ));
        }
    }

    // Either install a handler to notify us when genesis activates, or set fHaveGenesis directly.
    // No locking, as this happens before any background thread is started.
    boost::signals2::connection block_notify_genesis_wait_connection;
    if (chainman.ActiveChain().Tip() == nullptr) {
        block_notify_genesis_wait_connection = uiInterface.NotifyBlockTip_connect(std::bind(BlockNotifyGenesisWait, std::placeholders::_2));
    } else {
        fHaveGenesis = true;
    }

#if HAVE_SYSTEM
    const std::string block_notify = args.GetArg("-blocknotify", "");
    if (!block_notify.empty()) {
        uiInterface.NotifyBlockTip_connect([block_notify](SynchronizationState sync_state, const CBlockIndex* pBlockIndex) {
            if (sync_state != SynchronizationState::POST_INIT || !pBlockIndex) return;
            std::string command = block_notify;
            ReplaceAll(command, "%s", pBlockIndex->GetBlockHash().GetHex());
            std::thread t(runCommand, command);
            t.detach(); // thread runs free
        });
    }
    const std::string chainlock_notify = args.GetArg("-chainlocknotify", "");
    if (!chainlock_notify.empty()) {
        uiInterface.NotifyChainLock_connect([chainlock_notify](const std::string& bestChainLockHash, int bestChainLockHeight) {
            std::string command = chainlock_notify;
            ReplaceAll(command, "%s", bestChainLockHash);
            std::thread t(runCommand, command);
            t.detach(); // thread runs free
        });
    }
#endif

    std::vector<fs::path> vImportFiles;
    for (const std::string& strFile : args.GetArgs("-loadblock")) {
        vImportFiles.push_back(fs::PathFromString(strFile));
    }

    chainman.m_load_block = std::thread(&util::TraceThread, "loadblk", [=, &args, &chainman, &node] {
        ThreadImport(chainman, vImportFiles, args);

        // force UpdatedBlockTip to initialize nCachedBlockHeight for DS, MN payments and budgets
        // but don't call it directly to prevent triggering of other listeners like zmq etc.
        // GetMainSignals().UpdatedBlockTip(::ChainActive().Tip());
        g_ds_notification_interface->InitializeCurrentBlockTip();

        {
            // Get all UTXOs for each MN collateral in one go so that we can fill coin cache early
            // and reduce further locking overhead for cs_main in other parts of code including GUI
            LogPrintf("Filling coin cache with masternode UTXOs...\n");
            LOCK(cs_main);
            const auto start{SteadyClock::now()};
            const auto mnList{node.dmnman->GetListAtChainTip()};
            mnList.ForEachMN(/*onlyValid=*/false, [&](const auto& dmn) {
                Coin coin;
                GetUTXOCoin(chainman.ActiveChainstate(), dmn.collateralOutpoint, coin);
            });
            LogPrintf("Filling coin cache with masternode UTXOs: done in %dms\n", Ticks<std::chrono::milliseconds>(SteadyClock::now() - start));
        }

        if (fReindex || fReindexChainState) {
            LogPrintf("Skipping evodb repair during reindex\n");
            node.dmnman->CompleteRepair();  // Mark as repaired since we're rebuilding fresh
        } else if (node.dmnman->IsRepaired() && !args.GetBoolArg("-forceevodbrepair", false)) {
            LogPrintf("Masternode list diffs are already repaired\n");
        } else {
            const CBlockIndex* start_index;
            const CBlockIndex* stop_index;
            {
                LOCK(cs_main);
                const auto& consensus_params = Params().GetConsensus();
                start_index = chainman.ActiveChain()[consensus_params.DIP0003Height];
                stop_index = chainman.ActiveChain().Tip();
            }

            if (start_index && stop_index && start_index->nHeight < stop_index->nHeight) {
                LogPrintf("Verifying and repairing masternode list diffs...\n");
                const auto start{SteadyClock::now()};
                // Create a callback that wraps CSpecialTxProcessor::BuildNewListFromBlock
                auto build_list_func = [&node](const CBlock& block, const CBlockIndex* const pindexPrev,
                                                       const CDeterministicMNList& prevList, const CCoinsViewCache& view,
                                                       bool debugLogs, BlockValidationState& state,
                                                       CDeterministicMNList& mnListRet) -> bool {
                    return node.chain_helper->special_tx->RebuildListFromBlock(block, pindexPrev, prevList, view, debugLogs, state, mnListRet);
                };
                auto result = node.dmnman->RecalculateAndRepairDiffs(start_index, stop_index, chainman, build_list_func, true);

                if (!result.verification_errors.empty()) {
                    LogPrintf("WARNING: Verification errors:\n%s\n", Join(result.verification_errors, "\n"));
                }

                if (!result.repair_errors.empty()) {
                    // Critical errors occurred - reindex required
                    LogPrintf("Failed to repair masternode list diffs. Database corruption detected. " /* Continued */
                              "Please restart with -reindex to rebuild the database.\n"
                              "Errors:\n%s\n",
                              Join(result.repair_errors, "\n"));
                    StartShutdown();
                    return;
                }
                node.dmnman->CompleteRepair();
                LogPrintf("Successfully repaired %d masternode list diffs, verified %d snapshots in %ds\n",
                          result.diffs_recalculated, result.snapshots_verified,
                          Ticks<std::chrono::seconds>(SteadyClock::now() - start));
            }
        }

        if (node.active_ctx) {
            node.active_ctx->nodeman->Init(chainman.ActiveTip());
        }
    });
#ifdef ENABLE_WALLET
    if (!args.GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET)) {
        g_wallet_init_interface.AutoLockMasternodeCollaterals(*node.wallet_loader);
    }
#endif // ENABLE_WALLET

    // Wait for genesis block to be processed
    {
        WAIT_LOCK(g_genesis_wait_mutex, lock);
        // We previously could hang here if StartShutdown() is called prior to
        // ThreadImport getting started, so instead we just wait on a timer to
        // check ShutdownRequested() regularly.
        while (!fHaveGenesis && !ShutdownRequested()) {
            g_genesis_wait_cv.wait_for(lock, std::chrono::milliseconds(500));
        }
        block_notify_genesis_wait_connection.disconnect();
    }

    // As importing blocks can take several minutes, it's possible the user
    // requested to kill the GUI during one of the last operations. If so, exit.
    if (ShutdownRequested()) {
        LogPrintf("Shutdown requested. Exiting.\n");
        return false;
    }

    // ********************************************************* Step 12: start node

    //// debug print
    {
        LOCK(cs_main);
        LogPrintf("block tree size = %u\n", chainman.BlockIndex().size());
        chain_active_height = chainman.ActiveChain().Height();
        if (tip_info) {
            tip_info->block_height = chain_active_height;
            tip_info->block_time = chainman.ActiveChain().Tip() ? chainman.ActiveChain().Tip()->GetBlockTime() : Params().GenesisBlock().GetBlockTime();
            tip_info->block_hash = chainman.ActiveChain().Tip() ? chainman.ActiveChain().Tip()->GetBlockHash() : Params().GenesisBlock().GetHash();
            tip_info->verification_progress = GuessVerificationProgress(Params().TxData(), chainman.ActiveChain().Tip());
        }
        if (tip_info && chainman.m_best_header) {
            tip_info->header_height = chainman.m_best_header->nHeight;
            tip_info->header_time = chainman.m_best_header->GetBlockTime();
        }
    }
    LogPrintf("nBestHeight = %d\n", chain_active_height);
    if (node.peerman) node.peerman->SetBestHeight(chain_active_height);

    // Map ports with UPnP or NAT-PMP.
    StartMapPort(args.GetBoolArg("-upnp", DEFAULT_UPNP), args.GetBoolArg("-natpmp", DEFAULT_NATPMP));

    CConnman::Options connOptions;
    connOptions.nLocalServices = nLocalServices;
    connOptions.nMaxConnections = nMaxConnections;
    connOptions.m_max_outbound_full_relay = std::min(MAX_OUTBOUND_FULL_RELAY_CONNECTIONS, connOptions.nMaxConnections);
    connOptions.m_max_outbound_block_relay = std::min(MAX_BLOCK_RELAY_ONLY_CONNECTIONS, connOptions.nMaxConnections-connOptions.m_max_outbound_full_relay);
    connOptions.m_max_outbound_onion = std::min(MAX_DESIRED_ONION_CONNECTIONS, connOptions.nMaxConnections / 2);
    connOptions.nMaxAddnode = MAX_ADDNODE_CONNECTIONS;
    connOptions.nMaxFeeler = MAX_FEELER_CONNECTIONS;
    connOptions.uiInterface = &uiInterface;
    connOptions.m_banman = node.banman.get();
    connOptions.m_msgproc = node.peerman.get();
    connOptions.nSendBufferMaxSize = 1000 * args.GetIntArg("-maxsendbuffer", DEFAULT_MAXSENDBUFFER);
    connOptions.nReceiveFloodSize = 1000 * args.GetIntArg("-maxreceivebuffer", DEFAULT_MAXRECEIVEBUFFER);
    connOptions.m_added_nodes = args.GetArgs("-addnode");
    // Kerrigan: always add seed nodes so the wallet connects even without DNS seeder
    if (!args.IsArgSet("-connect")) {
        connOptions.m_added_nodes.push_back("seed1.kerrigan.network");
        connOptions.m_added_nodes.push_back("seed2.kerrigan.network");
        connOptions.m_added_nodes.push_back("seed3.kerrigan.network");
        connOptions.m_added_nodes.push_back("seed4.kerrigan.network");
    }
    connOptions.nMaxOutboundLimit = *opt_max_upload;
    connOptions.m_peer_connect_timeout = peer_connect_timeout;
    connOptions.socketEventsMode = ::g_socket_events_mode;
    connOptions.m_active_masternode = node.active_ctx != nullptr;

    // Port to bind to if `-bind=addr` is provided without a `:port` suffix.
    const uint16_t default_bind_port =
        static_cast<uint16_t>(args.GetIntArg("-port", Params().GetDefaultPort()));

    const auto BadPortWarning = [](const char* prefix, uint16_t port) {
        return strprintf(_("%s request to listen on port %u. This port is considered \"bad\" and "
                           "thus it is unlikely that any peer will connect to it. See "
                           "doc/p2p-bad-ports.md for details and a full list."),
                         prefix,
                         port);
    };

    for (const std::string& bind_arg : args.GetArgs("-bind")) {
        std::optional<CService> bind_addr;
        const size_t index = bind_arg.rfind('=');
        if (index == std::string::npos) {
            bind_addr = Lookup(bind_arg, default_bind_port, /*fAllowLookup=*/false);
            if (bind_addr.has_value()) {
                connOptions.vBinds.push_back(bind_addr.value());
                if (IsBadPort(bind_addr.value().GetPort())) {
                    InitWarning(BadPortWarning("-bind", bind_addr.value().GetPort()));
                }
                continue;
            }
        } else {
            const std::string network_type = bind_arg.substr(index + 1);
            if (network_type == "onion") {
                const std::string truncated_bind_arg = bind_arg.substr(0, index);
                bind_addr = Lookup(truncated_bind_arg, BaseParams().OnionServiceTargetPort(), false);
                if (bind_addr.has_value()) {
                    connOptions.onion_binds.push_back(bind_addr.value());
                    continue;
                }
            }
        }
        return InitError(ResolveErrMsg("bind", bind_arg));
    }

    for (const std::string& strBind : args.GetArgs("-whitebind")) {
        NetWhitebindPermissions whitebind;
        bilingual_str error;
        if (!NetWhitebindPermissions::TryParse(strBind, whitebind, error)) return InitError(error);
        connOptions.vWhiteBinds.push_back(whitebind);
    }

    // If the user did not specify -bind= or -whitebind= then we bind
    // on any address - 0.0.0.0 (IPv4) and :: (IPv6).
    connOptions.bind_on_any = args.GetArgs("-bind").empty() && args.GetArgs("-whitebind").empty();

    // Emit a warning if a bad port is given to -port= but only if -bind and -whitebind are not
    // given, because if they are, then -port= is ignored.
    if (connOptions.bind_on_any && args.IsArgSet("-port")) {
        const uint16_t port_arg = args.GetIntArg("-port", 0);
        if (IsBadPort(port_arg)) {
            InitWarning(BadPortWarning("-port", port_arg));
        }
    }

    CService onion_service_target;
    if (!connOptions.onion_binds.empty()) {
        onion_service_target = connOptions.onion_binds.front();
    } else {
        onion_service_target = DefaultOnionServiceTarget();
        connOptions.onion_binds.push_back(onion_service_target);
    }

    if (args.GetBoolArg("-listenonion", DEFAULT_LISTEN_ONION)) {
        if (connOptions.onion_binds.size() > 1) {
            InitWarning(strprintf(_("More than one onion bind address is provided. Using %s "
                                    "for the automatically created Tor onion service."),
                                  onion_service_target.ToStringAddrPort()));
        }
        StartTorControl(onion_service_target);
    }

    if (connOptions.bind_on_any) {
        // Only add all IP addresses of the machine if we would be listening on
        // any address - 0.0.0.0 (IPv4) and :: (IPv6).
        Discover();
    }

    for (const auto& net : args.GetArgs("-whitelist")) {
        NetWhitelistPermissions subnet;
        bilingual_str error;
        if (!NetWhitelistPermissions::TryParse(net, subnet, error)) return InitError(error);
        connOptions.vWhitelistedRange.push_back(subnet);
    }

    connOptions.vSeedNodes = args.GetArgs("-seednode");

    // Initiate outbound connections unless connect=0
    connOptions.m_use_addrman_outgoing = !args.IsArgSet("-connect");
    if (!connOptions.m_use_addrman_outgoing) {
        const auto connect = args.GetArgs("-connect");
        if (connect.size() != 1 || connect[0] != "0") {
            connOptions.m_specified_outgoing = connect;
        }
        if (!connOptions.m_specified_outgoing.empty() && !connOptions.vSeedNodes.empty()) {
            LogPrintf("-seednode is ignored when -connect is used\n");
        }

        if (args.IsArgSet("-dnsseed") && args.GetBoolArg("-dnsseed", DEFAULT_DNSSEED) && args.IsArgSet("-proxy")) {
            LogPrintf("-dnsseed is ignored when -connect is used and -proxy is specified\n");
        }
    }

    const std::string& i2psam_arg = args.GetArg("-i2psam", "");
    if (!i2psam_arg.empty()) {
        const std::optional<CService> addr{Lookup(i2psam_arg, 7656, fNameLookup)};
        if (!addr.has_value() || !addr->IsValid()) {
            return InitError(strprintf(_("Invalid -i2psam address or hostname: '%s'"), i2psam_arg));
        }
        SetProxy(NET_I2P, Proxy{addr.value()});
    } else {
        if (args.IsArgSet("-onlynet") && g_reachable_nets.Contains(NET_I2P)) {
            return InitError(
                _("Outbound connections restricted to i2p (-onlynet=i2p) but "
                  "-i2psam is not provided"));
        }
        g_reachable_nets.Remove(NET_I2P);
    }

    connOptions.m_i2p_accept_incoming = args.GetBoolArg("-i2pacceptincoming", DEFAULT_I2P_ACCEPT_INCOMING);

    if (!node.connman->Start(*node.dmnman, *node.mn_metaman, *node.mn_sync, *node.scheduler, connOptions)) {
        return false;
    }

    // ********************************************************* Step 13: finished

    // At this point, the RPC is "started", but still in warmup, which means it
    // cannot yet be called. Before we make it callable, we need to make sure
    // that the RPC's view of the best block is valid and consistent with
    // ChainstateManager's ActiveTip.
    //
    // If we do not do this, RPC's view of the best block will be height=0 and
    // hash=0x0. This will lead to erroroneous responses for things like
    // waitforblockheight.
    RPCNotifyBlockChange(chainman.ActiveTip());
    SetRPCWarmupFinished();

    uiInterface.InitMessage(_("Done loading").translated);

    for (const auto& client : node.chain_clients) {
        client->start(*node.scheduler);
    }

    BanMan* banman = node.banman.get();
    node.scheduler->scheduleEvery([banman]{
        banman->DumpBanlist();
    }, DUMP_BANS_INTERVAL);

    if (node.peerman) node.peerman->StartScheduledTasks(*node.scheduler);

#if HAVE_SYSTEM
    StartupNotify(args);
#endif

    return true;
}
