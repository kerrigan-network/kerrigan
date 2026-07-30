// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <recovery/recovery.h>

#include <addrman.h>
#include <chainparams.h>
#include <evo/chainhelper.h>
#include <evo/evodb.h>
#include <deploymentstatus.h>
#include <logging.h>
#include <masternode/sync.h>
#include <net.h>
#include <net_processing.h>
#include <netbase.h>
#include <node/context.h>
#include <random.h>
#include <rpc/server.h>
#include <sapling/sapling_state.h>
#include <sapling/sapling_validation.h>
#include <scheduler.h>
#include <shutdown.h>
#include <univalue.h>
#include <util/system.h>
#include <util/time.h>
#include <validation.h>

#include <algorithm>
#include <fstream>

namespace recovery {

std::atomic<bool> g_quarantined{false};
std::unique_ptr<RecoveryManager> g_recovery;

// ---------------------------------------------------------------------------
// File names (all in the network datadir ROOT, deliberately outside every
// wiped directory, 6.6)
// ---------------------------------------------------------------------------
static const char* const REPAIR_MARKER_FILENAME = "repair_marker.json";
static const char* const REPAIR_MARKER_DONE_FILENAME = "repair_marker.done.json";
static const char* const RECOVERY_LEDGER_FILENAME = "recovery_ledger.json";
static const char* const NODE_ABORT_FILENAME = "node_abort.json";
static const char* const WIPE_TMP_PREFIX = "repair_wipe_tmp.";

// Guard windows (6.6). Attempt guard: 3 per rolling 6 h; wipe-rate guard:
// 2 completed wipes per rolling 7 days.
static constexpr int REPAIR_ATTEMPTS_MAX{3};
static constexpr int64_t REPAIR_ATTEMPT_WINDOW_SECS{6 * 60 * 60};
static constexpr int REPAIR_WIPES_MAX{2};
static constexpr int64_t REPAIR_WIPE_WINDOW_SECS{7 * 24 * 60 * 60};
static constexpr int64_t CONFIRM_TOKEN_TTL_SECS{5 * 60};

// Auto-engine cadence (2.2/3). Interval math uses GetTime() (mocktime-aware
// on regtest) so functional tests can compress the windows.
static constexpr int64_t ROTATION_MIN_INTERVAL_SECS{10 * 60};
static constexpr int64_t LINK_PROBE_BACKOFF_SECS{5 * 60};
static constexpr int64_t PEER_SILENCE_HORIZON_SECS{5 * 60};
static constexpr int64_t STALL_EVICTION_SUPPRESSION_SECS{5 * 60};
static constexpr int LADDER_CYCLES_MAX{3};
static constexpr int64_t LADDER_CYCLE_WINDOW_SECS{6 * 60 * 60};
static constexpr int ISOLATION_HYSTERESIS_TICKS{2};
static constexpr int L2_FAILURES_BEFORE_L3{2};
static constexpr int FULL_CYCLES_BEFORE_ECLIPSE{2};
// N2 heuristic: an addrman this large that still yields nothing is
// eclipse-suspect rather than merely empty (3.4).
static constexpr size_t ECLIPSE_ADDRMAN_FLOOR{50};

// ---------------------------------------------------------------------------
// id tables (7.1: stable snake_case wire ids, no display English)
// ---------------------------------------------------------------------------
const char* DaemonModeToString(DaemonMode mode)
{
    switch (mode) {
    case DaemonMode::STARTING: return "starting";
    case DaemonMode::SYNCING: return "syncing";
    case DaemonMode::NORMAL: return "normal";
    case DaemonMode::DEGRADED: return "degraded";
    case DaemonMode::QUARANTINED: return "quarantined";
    case DaemonMode::CRIPPLED_WAIT: return "crippled_wait";
    case DaemonMode::REPAIR_ARMED: return "repair_armed";
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

const char* FindingCodeToString(FindingCode code)
{
    switch (code) {
    case FindingCode::NET_LOCAL_LINK_DOWN: return "NET_LOCAL_LINK_DOWN";
    case FindingCode::NET_ISOLATED: return "NET_ISOLATED";
    case FindingCode::NET_ECLIPSE_SUSPECT: return "NET_ECLIPSE_SUSPECT";
    case FindingCode::TIP_STALLED_NETWORK: return "TIP_STALLED_NETWORK";
    case FindingCode::TIP_STALLED_NONNETWORK: return "TIP_STALLED_NONNETWORK";
    case FindingCode::DRIFT_EVODB: return "DRIFT_EVODB";
    case FindingCode::DRIFT_SAPLING: return "DRIFT_SAPLING";
    case FindingCode::WITNESS_STALE: return "WITNESS_STALE";
    case FindingCode::REPAIR_RATE_LIMITED: return "REPAIR_RATE_LIMITED";
    case FindingCode::CHAINSTATE_LOAD_FAILED: return "CHAINSTATE_LOAD_FAILED";
    case FindingCode::NODE_ABORTED: return "NODE_ABORTED";
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

const char* RecommendedActionToString(RecommendedAction action)
{
    switch (action) {
    case RecommendedAction::ACTION_NONE: return "ACTION_NONE";
    case RecommendedAction::ACTION_WAIT_AUTO: return "ACTION_WAIT_AUTO";
    case RecommendedAction::ACTION_GUIDED_NETWORK_REPAIR: return "ACTION_GUIDED_NETWORK_REPAIR";
    case RecommendedAction::ACTION_GUIDED_REPAIR: return "ACTION_GUIDED_REPAIR";
    case RecommendedAction::ACTION_DIAGNOSE_SUPPORT: return "ACTION_DIAGNOSE_SUPPORT";
    case RecommendedAction::ACTION_CHECK_DISK: return "ACTION_CHECK_DISK";
    case RecommendedAction::ACTION_MANAGE_NODE_ELSEWHERE: return "ACTION_MANAGE_NODE_ELSEWHERE";
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

const char* RepairPhaseToString(RepairPhase phase)
{
    switch (phase) {
    case RepairPhase::NONE: return "none";
    case RepairPhase::ARMED: return "armed";
    case RepairPhase::SHUTTING_DOWN: return "shutting_down";
    case RepairPhase::WIPING: return "wiping";
    case RepairPhase::BOOTSTRAPPING: return "bootstrapping";
    case RepairPhase::SYNCING: return "syncing";
    case RepairPhase::REBUILDING_WITNESSES: return "rebuilding_witnesses";
    case RepairPhase::VERIFYING: return "verifying";
    case RepairPhase::DONE: return "done";
    case RepairPhase::FAILED: return "failed";
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

// ---------------------------------------------------------------------------
// Small JSON-file helpers (ledger / marker / abort record). All best-effort
// and crash-safe: writes go to a temp file, FileCommit, then RenameOver.
// ---------------------------------------------------------------------------
static std::optional<UniValue> ReadJsonFile(const fs::path& path)
{
    if (!fs::exists(path)) return std::nullopt;
    std::ifstream file{path};
    if (!file.is_open()) return std::nullopt;
    std::string contents{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    UniValue json;
    if (!json.read(contents) || !json.isObject()) {
        LogPrintf("recovery: ignoring unparseable %s\n", fs::PathToString(path));
        return std::nullopt;
    }
    return json;
}

static bool WriteJsonFile(const fs::path& path, const UniValue& json)
{
    fs::path tmp = path;
    tmp += ".tmp";
    {
        std::ofstream file{tmp, std::ios::trunc};
        if (!file.is_open()) return false;
        file << json.write(/*prettyIndent=*/2) << "\n";
        if (!file.good()) return false;
    }
    if (FILE* f = fsbridge::fopen(tmp, "ab")) {
        FileCommit(f);
        fclose(f);
    }
    return RenameOver(tmp, path);
}

static fs::path LedgerPath() { return gArgs.GetDataDirNet() / RECOVERY_LEDGER_FILENAME; }
static fs::path MarkerPath() { return gArgs.GetDataDirNet() / REPAIR_MARKER_FILENAME; }
static fs::path MarkerDonePath() { return gArgs.GetDataDirNet() / REPAIR_MARKER_DONE_FILENAME; }

static UniValue ReadLedger()
{
    if (auto json = ReadJsonFile(LedgerPath())) return *json;
    UniValue ledger(UniValue::VOBJ);
    ledger.pushKV("version", 1);
    ledger.pushKV("attempts", UniValue{UniValue::VARR});
    ledger.pushKV("wipes", UniValue{UniValue::VARR});
    ledger.pushKV("repair_state", "idle");
    return ledger;
}

static void WriteLedger(const UniValue& ledger)
{
    if (!WriteJsonFile(LedgerPath(), ledger)) {
        LogPrintf("recovery: WARNING: failed to persist %s\n", fs::PathToString(LedgerPath()));
    }
}

static int CountLedgerEntriesInWindow(const UniValue& ledger, const std::string& key, int64_t window_secs, int64_t now)
{
    int count{0};
    const UniValue& arr = ledger[key];
    if (!arr.isArray()) return 0;
    for (size_t i = 0; i < arr.size(); ++i) {
        const UniValue& ts = arr[i]["ts"];
        if (ts.isNum() && now - ts.getInt<int64_t>() <= window_secs) ++count;
    }
    return count;
}

static void SetLedgerRepairState(const std::string& state)
{
    UniValue ledger = ReadLedger();
    UniValue out(UniValue::VOBJ);
    for (const auto& key : ledger.getKeys()) {
        if (key != "repair_state" && key != "repair_state_ts") out.pushKV(key, ledger[key]);
    }
    out.pushKV("repair_state", state);
    out.pushKV("repair_state_ts", GetTime());
    WriteLedger(out);
}

// ---------------------------------------------------------------------------
// Wipe plan (6.1): what a full repair removes and what it always preserves.
// Mirrors the -resetchainstate list minus network/log state; peers.dat +
// anchors.dat are added only for network-class findings or scope:"network".
// ---------------------------------------------------------------------------
static std::vector<std::string> FullWipeDirs()
{
    return {"blocks", "chainstate", "sapling", "evodb", "llmq", "indexes"};
}

static std::vector<std::string> WipeFiles(bool include_network_state)
{
    std::vector<std::string> files{"mempool.dat"};
    if (include_network_state) {
        files.emplace_back("peers.dat");
        files.emplace_back("anchors.dat");
    }
    return files;
}

static std::vector<std::string> PreservedLabels()
{
    // labels only; front-ends map to copy. The wallet is preserved but
    // Sapling note witnesses are rebuilt after resync (6.4) -- surfaced via
    // the rebuilding_witnesses phase, never hidden.
    return {"wallet", "config", "masternode_operator_keys", "recovery_ledger", "logs"};
}

//! Resolve a wipe label to its absolute path. "blocks" honors -blocksdir the
//! same way -resetchainstate does (ArgsManager::GetBlocksDirPath).
static fs::path ResolveWipePath(const std::string& label)
{
    if (label == "blocks") return gArgs.GetBlocksDirPath();
    return gArgs.GetDataDirNet() / fs::PathFromString(label);
}

static int64_t DirSizeEstimate(const fs::path& path)
{
    int64_t total{0};
    std::error_code ec;
    if (!fs::exists(path)) return 0;
    if (fs::is_regular_file(path, ec)) {
        return static_cast<int64_t>(fs::file_size(path, ec));
    }
    for (auto it = fs::recursive_directory_iterator(path, fs::directory_options::skip_permission_denied, ec);
         !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
        std::error_code fec;
        if (fs::is_regular_file(it->path(), fec) && !fec) {
            total += static_cast<int64_t>(fs::file_size(it->path(), fec));
        }
    }
    return total;
}

// ---------------------------------------------------------------------------
// Marker-driven wipe (6.2). Rename-then-unlink: phase 1 renames every target
// to a tombstone (O(1), so the datadir reaches the bootstrap-triggering state
// immediately), phase 2 consumes the marker by rename (the journal commit
// point), phase 3 reclaims the tombstones. A crash at any point is resumed by
// RunStartupRepairTasks(): marker still present -> redo phase 1 (idempotent);
// marker consumed but tombstones left -> phase 3 sweep only.
// ---------------------------------------------------------------------------
static void SweepWipeTombstones()
{
    const std::vector<fs::path> parents{gArgs.GetDataDirNet(), fs::path{gArgs.GetBlocksDirPath().parent_path()}};
    for (const fs::path& parent : parents) {
        if (!fs::exists(parent)) continue;
        std::error_code ec;
        for (auto it = fs::directory_iterator(parent, ec); !ec && it != fs::directory_iterator(); it.increment(ec)) {
            const std::string name = fs::PathToString(it->path().filename());
            if (name.rfind(WIPE_TMP_PREFIX, 0) == 0) {
                std::error_code rec;
                fs::remove_all(it->path(), rec);
                LogPrintf("recovery: reclaimed wipe tombstone %s%s\n", fs::PathToString(it->path()),
                          rec ? strprintf(" (error: %s)", rec.message()) : "");
            }
        }
    }
}

//! Execute the wipe described by the marker at `marker_path`. Returns true if
//! the marker was consumed (renamed to done).
static bool ExecuteMarkerWipe(const fs::path& marker_path)
{
    const auto marker = ReadJsonFile(marker_path);
    if (!marker) return false;

    std::vector<std::string> targets;
    const UniValue& dirs = (*marker)["wipe_dirs"];
    const UniValue& files = (*marker)["wipe_files"];
    if (dirs.isArray()) for (size_t i = 0; i < dirs.size(); ++i) targets.push_back(dirs[i].get_str());
    if (files.isArray()) for (size_t i = 0; i < files.size(); ++i) targets.push_back(files[i].get_str());

    const std::string scope = (*marker)["scope"].isStr() ? (*marker)["scope"].get_str() : "full";
    LogPrintf("recovery: executing %s repair wipe (%d targets) from %s\n",
              scope, targets.size(), fs::PathToString(marker_path));

    // Phase 1: rename targets to tombstones (idempotent on resume).
    for (const std::string& label : targets) {
        const fs::path src = ResolveWipePath(label);
        if (!fs::exists(src)) continue;
        const fs::path dst = src.parent_path() / fs::PathFromString(WIPE_TMP_PREFIX + label);
        std::error_code rmec;
        fs::remove_all(dst, rmec); // stale tombstone from an interrupted run
        std::error_code rnec;
        fs::rename(src, dst, rnec);
        if (rnec) {
            // Fall back to direct removal (e.g. cross-device -blocksdir edge).
            std::error_code dec;
            fs::remove_all(src, dec);
            LogPrintf("recovery: wipe %s: rename failed (%s), removed directly%s\n", label,
                      rnec.message(), dec ? strprintf(" (error: %s)", dec.message()) : "");
        } else {
            LogPrintf("recovery: wipe %s -> tombstone\n", label);
        }
    }

    // Phase 2: consume the marker by rename -- the journal commit point.
    if (!RenameOver(marker_path, MarkerDonePath())) {
        LogPrintf("recovery: WARNING: failed to consume repair marker %s\n", fs::PathToString(marker_path));
        return false;
    }

    // Record the completed wipe in the ledger (wipe-rate guard input, 6.6.2).
    {
        UniValue ledger = ReadLedger();
        UniValue wipe(UniValue::VOBJ);
        wipe.pushKV("ts", GetTime());
        wipe.pushKV("scope", scope);
        UniValue wipes = ledger["wipes"];
        if (!wipes.isArray()) wipes = UniValue{UniValue::VARR};
        wipes.push_back(wipe);
        UniValue out(UniValue::VOBJ);
        for (const auto& key : ledger.getKeys()) {
            if (key != "wipes" && key != "repair_state" && key != "repair_state_ts") out.pushKV(key, ledger[key]);
        }
        out.pushKV("wipes", wipes);
        out.pushKV("repair_state", scope == "network" ? "idle" : "wiped");
        out.pushKV("repair_state_ts", GetTime());
        WriteLedger(out);
    }

    // Phase 3: reclaim tombstones (interruptible; resumed by the startup sweep).
    SweepWipeTombstones();
    LogPrintf("recovery: repair wipe complete (scope=%s)\n", scope);
    return true;
}

void ExecuteShutdownWipe()
{
    const fs::path marker = MarkerPath();
    if (!fs::exists(marker)) return;
    LogPrintf("recovery: repair marker present at shutdown; wiping chain-derived state now "
              "(wallet, config, and the recovery ledger are preserved)\n");
    ExecuteMarkerWipe(marker);
}

bool RunStartupRepairTasks()
{
    const fs::path marker = MarkerPath();
    if (fs::exists(marker)) {
        // Crash mid-wipe, or armed on a daemon that was killed instead of
        // stopped: finish the wipe before any DB is opened (6.2.3).
        LogPrintf("recovery: repair marker found at startup; completing wipe before init\n");
        ExecuteMarkerWipe(marker);
    }
    // Consume a done-marker from the previous shutdown (state continues in
    // the ledger's repair_state).
    if (fs::exists(MarkerDonePath())) {
        std::error_code dec;
        fs::remove(MarkerDonePath(), dec);
    }
    SweepWipeTombstones();
    return true;
}

// ---------------------------------------------------------------------------
// AbortNode reason persistence (C2): lets the NEXT start surface NODE_ABORTED
// with ACTION_CHECK_DISK for disk-class failures. Best-effort by design --
// the disk may be the thing that is failing.
// ---------------------------------------------------------------------------
void RecordAbortReason(const std::string& reason)
{
    try {
        UniValue json(UniValue::VOBJ);
        json.pushKV("reason", reason);
        json.pushKV("ts", GetTime());
        WriteJsonFile(gArgs.GetDataDirNet() / NODE_ABORT_FILENAME, json);
    } catch (...) {
        // Swallow everything: AbortNode must never throw through here.
    }
}

static bool AbortReasonIsDiskClass(const std::string& reason)
{
    for (const char* needle : {"Disk space", "Failed to write", "Failed to commit", "Failed to delete",
                               "System error", "Corrupt block", "flushing"}) {
        if (reason.find(needle) != std::string::npos) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// RecoveryManager
// ---------------------------------------------------------------------------

struct RecoveryManager::Signals {
    bool attached{false};
    int64_t now{0};
    size_t outbound{0};
    size_t inbound{0};
    size_t total{0};
    bool any_recent_recv{false};
    size_t silent_outbounds{0};
    int best_peer_height{-1};
    size_t addrman_size{0};
    int tip_height{-1};
    int64_t tip_time{0};
    uint256 tip_hash;
    bool have_tip{false};
    bool ibd{true};
    int64_t expected_spacing{120};
    int competing_higher_work_tips{0};
    bool drift_check_ran{false};
    bool drift_ok{true};
};

RecoveryManager::RecoveryManager()
{
    LOCK(m_mutex);
    // The auto engine is meaningless when the operator has deliberately
    // pinned connectivity (-connect, which stops ThreadOpenConnections from
    // refilling outbound slots at all) or disabled networking
    // (-networkactive=0): rotation and re-seed cannot help, and raising
    // NET_ISOLATED for an intentionally isolated node is noise. An explicit
    // -selfheal=1 overrides the inference (used by the regtest suite, which
    // sets connect=0 in every datadir). The diagnosis engine and the RPC
    // contract stay live either way.
    const bool selfheal_arg = gArgs.GetBoolArg("-selfheal", true);
    const bool connectivity_pinned = gArgs.IsArgSet("-connect") || !gArgs.GetBoolArg("-networkactive", true);
    m_selfheal_enabled = selfheal_arg && (gArgs.IsArgSet("-selfheal") || !connectivity_pinned);

    // Resume repair-phase tracking across the restart (6.3): the ledger's
    // repair_state survives the wipe because it lives in the datadir root.
    const UniValue ledger = ReadLedger();
    const std::string repair_state = ledger["repair_state"].isStr() ? ledger["repair_state"].get_str() : "idle";
    if (repair_state == "wiped" || repair_state == "syncing" || repair_state == "rebuilding_witnesses" ||
        repair_state == "verifying") {
        m_repair_in_flight = true;
        m_repair_phase = RepairPhase::SYNCING;
        LogPrintf("recovery: resuming repair tracking (ledger state: %s)\n", repair_state);
    } else if (repair_state == "failed") {
        m_repair_phase = RepairPhase::FAILED;
    }

    // Surface a previous run's AbortNode (C2 -> ACTION_CHECK_DISK).
    const fs::path abort_path = gArgs.GetDataDirNet() / NODE_ABORT_FILENAME;
    if (auto abort_json = ReadJsonFile(abort_path)) {
        const std::string reason = (*abort_json)["reason"].isStr() ? (*abort_json)["reason"].get_str() : "";
        Finding f;
        f.code = FindingCode::NODE_ABORTED;
        f.since = (*abort_json)["ts"].isNum() ? (*abort_json)["ts"].getInt<int64_t>() : GetTime();
        f.evidence_str.emplace_back("abort_reason", reason);
        f.evidence_num.emplace_back("disk_class", AbortReasonIsDiskClass(reason) ? 1 : 0);
        f.debug_detail = "previous run aborted: " + reason;
        m_findings.push_back(std::move(f));
        std::error_code ec;
        fs::remove(abort_path, ec);
    }

    // Initial (pre-attach) snapshot so warmup RPC has something to serve.
    Signals sig;
    sig.now = GetTime();
    PublishSnapshot(sig);
}

RecoveryManager::~RecoveryManager() = default;

void RecoveryManager::AttachNode(node::NodeContext& node)
{
    LOCK(m_mutex);
    m_node = &node;
    m_connman = node.connman.get();
    m_peerman = node.peerman.get();
    m_chainman = node.chainman.get();
    m_mn_sync = node.mn_sync.get();
    m_scheduler = node.scheduler.get();
}

void RecoveryManager::DetachNode()
{
    LOCK(m_mutex);
    m_node = nullptr;
    m_connman = nullptr;
    m_peerman = nullptr;
    m_chainman = nullptr;
    m_mn_sync = nullptr;
    m_scheduler = nullptr;
}

void RecoveryManager::SetInitComplete()
{
    Signals sig;
    sig.now = GetTime();
    LOCK(m_mutex);
    m_init_complete = true;
    m_last_tip_advance_time = sig.now;
    // Startup diagnosis that did NOT stop init (e.g. the operator chose
    // -reindex from the startup question) must not leave the node reporting
    // crippled_wait forever.
    if (m_mode == DaemonMode::CRIPPLED_WAIT) {
        m_mode = DaemonMode::STARTING;
        m_startup_diagnosis = false;
    }
    PublishSnapshot(sig);
}

void RecoveryManager::NoteBuiltinStallEviction()
{
    m_last_builtin_stall_eviction.store(GetTime(), std::memory_order_release);
}

void RecoveryManager::UpsertFinding(FindingCode code, Finding&& f)
{
    AssertLockHeld(m_mutex);
    for (auto& existing : m_findings) {
        if (existing.code == code) {
            f.since = existing.since; // keep the original onset time
            existing = std::move(f);
            return;
        }
    }
    LogPrintf("recovery: finding raised: %s\n", FindingCodeToString(code));
    m_findings.push_back(std::move(f));
}

void RecoveryManager::ClearFinding(FindingCode code)
{
    AssertLockHeld(m_mutex);
    const size_t before = m_findings.size();
    m_findings.erase(std::remove_if(m_findings.begin(), m_findings.end(),
                                    [code](const Finding& f) { return f.code == code; }),
                     m_findings.end());
    if (m_findings.size() != before) {
        LogPrintf("recovery: finding cleared: %s\n", FindingCodeToString(code));
    }
}

bool RecoveryManager::HasFinding(FindingCode code) const
{
    AssertLockHeld(m_mutex);
    return std::any_of(m_findings.begin(), m_findings.end(),
                       [code](const Finding& f) { return f.code == code; });
}

void RecoveryManager::EnterQuarantine(QuarantineReason reason, const std::string& debug_detail)
{
    const int64_t now = GetTime();
    // NOTE: callers hold cs_main (validation drift sites). Everything below
    // must therefore avoid any lock that can be held while waiting on
    // cs_main; m_mutex is never held across a cs_main acquisition
    // (see SchedulerTick), so this is safe.
    LOCK(m_mutex);

    FindingCode code;
    switch (reason) {
    case QuarantineReason::DRIFT_EVODB_DISCONNECT:
    case QuarantineReason::DRIFT_EVODB_CONNECT:
        code = FindingCode::DRIFT_EVODB;
        break;
    case QuarantineReason::DRIFT_SAPLING_DISCONNECT:
        code = FindingCode::DRIFT_SAPLING;
        break;
    case QuarantineReason::STARTUP_DRIFT:
        code = FindingCode::DRIFT_EVODB; // refined by debug_detail/evidence
        break;
    case QuarantineReason::STARTUP_LOAD_FAILED:
        code = FindingCode::CHAINSTATE_LOAD_FAILED;
        break;
    } // no default case, so the compiler can warn about missing cases

    // STARTUP_DRIFT does not know which cache drifted; the caller encodes it
    // in the detail string (which is also what the operator sees in the log).
    if (reason == QuarantineReason::STARTUP_DRIFT &&
        (debug_detail.find("sapling") != std::string::npos ||
         debug_detail.find("Sapling") != std::string::npos)) {
        code = FindingCode::DRIFT_SAPLING;
    }

    Finding f;
    f.code = code;
    f.since = now;
    f.debug_detail = debug_detail;
    UpsertFinding(code, std::move(f));

    if (!m_init_complete) {
        // 5.3: startup drift -> crippled_wait. Init parks with RPC (the
        // warmup-callable subset) serving diagnosis; no quarantine levers to
        // pull because networking/duties never started.
        m_startup_diagnosis = true;
        m_mode = DaemonMode::CRIPPLED_WAIT;
        LogPrintf("recovery: startup diagnosis recorded (%s); crippled_wait pending: %s\n",
                  FindingCodeToString(code), debug_detail);
        Signals sig;
        sig.now = now;
        PublishSnapshot(sig);
        return;
    }

    if (g_quarantined.exchange(true, std::memory_order_acq_rel)) {
        return; // already quarantined; one-way for the process lifetime (5.2)
    }
    m_mode = DaemonMode::QUARANTINED;
    LogPrintf("*** recovery: ENTERING QUARANTINE (%s): %s -- networking, mining, masternode/LLMQ "
              "duties and HMP signing are disabled; RPC diagnosis stays available "
              "(getrecoverystatus)\n",
              FindingCodeToString(code), debug_detail);

    // Networking off (5.2.1). Deferred to the scheduler thread: the caller
    // holds cs_main and CConnman::SetNetworkActive touches net/mn-sync state
    // whose lock order with cs_main we must not assume.
    if (m_scheduler && m_connman) {
        CConnman* connman = m_connman;
        CMasternodeSync* mn_sync = m_mn_sync;
        m_scheduler->scheduleFromNow([connman, mn_sync] {
            connman->SetNetworkActive(false, mn_sync);
            LogPrintf("recovery: quarantine: networking disabled\n");
        }, std::chrono::milliseconds{0});
    }

    Signals sig;
    sig.now = now;
    PublishSnapshot(sig);
}

void RecoveryManager::RecordStartupLoadFailure(const std::string& load_error_id, const std::string& debug_detail)
{
    LOCK(m_mutex);
    Finding f;
    f.code = FindingCode::CHAINSTATE_LOAD_FAILED;
    f.since = GetTime();
    f.evidence_str.emplace_back("load_error", load_error_id);
    f.debug_detail = debug_detail;
    UpsertFinding(FindingCode::CHAINSTATE_LOAD_FAILED, std::move(f));
    m_startup_diagnosis = true;
    m_mode = DaemonMode::CRIPPLED_WAIT;
    Signals sig;
    sig.now = GetTime();
    PublishSnapshot(sig);
}

bool RecoveryManager::StartupDiagnosisPending() const
{
    LOCK(m_mutex);
    return m_startup_diagnosis;
}

//! Set once RunCrippledWait() returns; read after the manager is destroyed,
//! so it deliberately lives outside RecoveryManager.
static std::atomic<bool> g_crippled_wait_released{false};

bool CrippledWaitWasReleased()
{
    return g_crippled_wait_released.load(std::memory_order_acquire);
}

void RecoveryManager::RunCrippledWait()
{
    {
        LOCK(m_mutex);
        m_mode = DaemonMode::CRIPPLED_WAIT;
        Signals sig;
        sig.now = GetTime();
        PublishSnapshot(sig);
    }
    // Keep the (warmup-gated) RPC message honest for clients that have not
    // adopted the recovery contract; the id is machine-mapped by front-ends.
    SetRPCWarmupStatus("crippled_wait");
    LogPrintf("recovery: entering crippled_wait -- chainstate unusable; getrecoverystatus/"
              "repairnode remain callable; send `repairnode` with shutdown:true (headless) or "
              "stop the node to proceed\n");
    while (!ShutdownRequested()) {
        UninterruptibleSleep(std::chrono::milliseconds{200});
    }
    g_crippled_wait_released.store(true, std::memory_order_release);
    LogPrintf("recovery: crippled_wait released by shutdown request\n");
}

// ---- signal collection (never holds m_mutex across cs_main) ----

RecoveryManager::Signals RecoveryManager::CollectSignals()
{
    Signals sig;
    sig.now = GetTime();

    CConnman* connman{nullptr};
    PeerManager* peerman{nullptr};
    ChainstateManager* chainman{nullptr};
    node::NodeContext* node{nullptr};
    bool want_drift_check{false};
    {
        LOCK(m_mutex);
        connman = m_connman;
        peerman = m_peerman;
        chainman = m_chainman;
        node = m_node;
        want_drift_check = m_repair_in_flight && m_repair_phase == RepairPhase::VERIFYING;
    }
    if (!connman || !chainman) return sig;
    sig.attached = true;

    // Peer-layer signals.
    sig.outbound = connman->GetNodeCount(ConnectionDirection::Out);
    sig.inbound = connman->GetNodeCount(ConnectionDirection::In);
    sig.total = sig.outbound + sig.inbound;
    {
        std::vector<CNodeStats> vstats;
        connman->GetNodeStats(vstats);
        for (const CNodeStats& stats : vstats) {
            if (sig.now - stats.m_last_recv.count() <= PEER_SILENCE_HORIZON_SECS) {
                sig.any_recent_recv = true;
            } else if (!stats.fInbound) {
                ++sig.silent_outbounds;
            }
            if (peerman) {
                CNodeStateStats state_stats;
                if (peerman->GetNodeStateStats(stats.nodeid, state_stats)) {
                    sig.best_peer_height = std::max(sig.best_peer_height, state_stats.nSyncHeight);
                }
            }
        }
    }
    if (node && node->addrman) sig.addrman_size = node->addrman->Size();

    // Chain signals (cs_main; m_mutex NOT held).
    {
        LOCK(cs_main);
        const CBlockIndex* tip = chainman->ActiveTip();
        if (tip) {
            sig.have_tip = true;
            sig.tip_height = tip->nHeight;
            sig.tip_time = tip->GetBlockTime();
            sig.tip_hash = tip->GetBlockHash();

            // Observed-cadence spacing (2.2): rolling median of the last 20
            // inter-block intervals, clamped to [30 s, 600 s].
            std::vector<int64_t> intervals;
            const CBlockIndex* walk = tip;
            for (int i = 0; i < 20 && walk->pprev; ++i, walk = walk->pprev) {
                intervals.push_back(std::max<int64_t>(0, walk->GetBlockTime() - walk->pprev->GetBlockTime()));
            }
            if (!intervals.empty()) {
                std::sort(intervals.begin(), intervals.end());
                sig.expected_spacing = std::clamp<int64_t>(intervals[intervals.size() / 2], 30, 600);
            }

            // T2 evidence: competing tips with more work than the active tip
            // flagged invalid / headers-only. Only walked when the tip is
            // already old enough to matter (cold path).
            const int64_t stall_floor = std::max<int64_t>(60 * 60, 30 * sig.expected_spacing);
            if (sig.now - sig.tip_time > stall_floor / 2) {
                for (const auto& [hash, index] : chainman->BlockIndex()) {
                    if (index.nChainWork > tip->nChainWork &&
                        (index.nStatus & BLOCK_FAILED_MASK || !(index.nStatus & BLOCK_HAVE_DATA))) {
                        ++sig.competing_higher_work_tips;
                    }
                }
            }
        }
        sig.ibd = chainman->ActiveChainstate().IsInitialBlockDownload();
    }

    // Repair verification drift re-check (5.4 semantics mirrored: EvoDB
    // missing key == inconsistent but only when DIP3 is active; SaplingDB
    // missing key == fresh == consistent).
    if (want_drift_check && node && sig.have_tip) {
        sig.drift_check_ran = true;
        LOCK(cs_main);
        const CBlockIndex* tip = chainman->ActiveTip();
        if (tip) {
            if (node->evodb &&
                DeploymentActiveAt(*tip, Params().GetConsensus(), Consensus::DEPLOYMENT_DIP0003) &&
                !node->evodb->VerifyBestBlock(tip->GetBlockHash())) {
                sig.drift_ok = false;
            }
            if (node->chain_helper && node->chain_helper->sapling_state &&
                sapling::IsSaplingActive(Params().GetConsensus(), tip->nHeight) &&
                !node->chain_helper->sapling_state->VerifyBestBlock(tip->GetBlockHash())) {
                sig.drift_ok = false;
            }
        }
    }

    return sig;
}

// ---- classification (1: N1/N2/T1/T2 taxonomy) ----

void RecoveryManager::Classify(const Signals& sig)
{
    AssertLockHeld(m_mutex);
    if (!sig.attached || !m_init_complete) return;

    // Tip-advance tracking.
    if (sig.tip_height > m_last_tip_height) {
        const bool was_isolated = HasFinding(FindingCode::NET_ISOLATED) ||
                                  HasFinding(FindingCode::NET_ECLIPSE_SUSPECT) ||
                                  HasFinding(FindingCode::TIP_STALLED_NETWORK);
        m_last_tip_height = sig.tip_height;
        m_last_tip_advance_time = sig.now;
        // A tip advance with live peers is the "successful reconnection" that
        // resets the ladder and its loop guard (3.5).
        if (sig.total > 0) {
            ClearFinding(FindingCode::NET_ISOLATED);
            ClearFinding(FindingCode::NET_LOCAL_LINK_DOWN);
            ClearFinding(FindingCode::NET_ECLIPSE_SUSPECT);
            ClearFinding(FindingCode::TIP_STALLED_NETWORK);
            ClearFinding(FindingCode::TIP_STALLED_NONNETWORK);
            if (was_isolated || m_ladder_stage != 0 || m_ladder_parked) {
                LogPrintf("recovery: tip advancing with %d peer(s); auto-engine reset\n", sig.total);
            }
            m_ladder_stage = 0;
            m_l2_failures = 0;
            m_full_cycles = 0;
            m_cycles_used = 0;
            m_ladder_parked = false;
            m_zero_peer_ticks = 0;
        }
    }
    m_expected_spacing = sig.expected_spacing;

    // N1/N2: isolation (with hysteresis). Skipped entirely when the auto
    // engine is disabled or connectivity is operator-pinned -- see the
    // m_selfheal_enabled derivation in the constructor.
    if (sig.total == 0 && m_selfheal_enabled) {
        ++m_zero_peer_ticks;
        if (m_zero_peer_ticks >= ISOLATION_HYSTERESIS_TICKS && !HasFinding(FindingCode::NET_ISOLATED)) {
            Finding f;
            f.code = FindingCode::NET_ISOLATED;
            f.since = sig.now;
            f.evidence_num.emplace_back("outbound", 0);
            f.evidence_num.emplace_back("inbound", 0);
            f.evidence_num.emplace_back("addrman_size", static_cast<int64_t>(sig.addrman_size));
            f.debug_detail = "zero peer connections";
            UpsertFinding(FindingCode::NET_ISOLATED, std::move(f));
        }
    } else {
        m_zero_peer_ticks = 0;
        if (HasFinding(FindingCode::NET_ISOLATED) && sig.any_recent_recv) {
            // Peers back and talking; full recovery is declared on tip
            // advance above, but the isolation finding itself clears now.
            ClearFinding(FindingCode::NET_ISOLATED);
            ClearFinding(FindingCode::NET_LOCAL_LINK_DOWN);
        }
    }

    // T1/T2: stalled tip (skip during IBD; cadence-relative thresholds, 2.2).
    if (!sig.ibd && sig.have_tip) {
        const int64_t tip_age = sig.now - sig.tip_time;
        const int64_t stalled_after = std::max<int64_t>(60 * 60, 30 * sig.expected_spacing);
        if (tip_age > stalled_after && sig.total > 0) {
            const bool network_attributable = sig.best_peer_height > sig.tip_height &&
                                              sig.competing_higher_work_tips == 0;
            Finding f;
            f.since = sig.now;
            f.evidence_num.emplace_back("tip_height", sig.tip_height);
            f.evidence_num.emplace_back("tip_age_secs", tip_age);
            f.evidence_num.emplace_back("expected_spacing_secs", sig.expected_spacing);
            f.evidence_num.emplace_back("best_peer_height", sig.best_peer_height);
            f.evidence_num.emplace_back("competing_higher_work_tips", sig.competing_higher_work_tips);
            f.evidence_str.emplace_back("tip_hash", sig.tip_hash.ToString());
            if (network_attributable) {
                f.code = FindingCode::TIP_STALLED_NETWORK;
                f.debug_detail = "peers advertise more work; blocks not arriving";
                ClearFinding(FindingCode::TIP_STALLED_NONNETWORK);
                UpsertFinding(FindingCode::TIP_STALLED_NETWORK, std::move(f));
            } else {
                // T2 (4.2): possible network-wide halt or a higher-work chain
                // we rejected. Diagnose and surface ONLY -- no block-level
                // action is ever taken or offered automatically.
                f.code = FindingCode::TIP_STALLED_NONNETWORK;
                f.debug_detail = "no peer advertises more work than our tip, or a higher-work "
                                 "competing tip exists in the local index; automatic block-level "
                                 "action is intentionally not taken";
                ClearFinding(FindingCode::TIP_STALLED_NETWORK);
                UpsertFinding(FindingCode::TIP_STALLED_NONNETWORK, std::move(f));
            }
        } else if (tip_age <= stalled_after) {
            ClearFinding(FindingCode::TIP_STALLED_NETWORK);
            ClearFinding(FindingCode::TIP_STALLED_NONNETWORK);
        }
    }
}

// ---- auto engine (3): decisions made under m_mutex, actuation by the tick
// after the lock is dropped ----

enum class LadderAction { NONE, PROBE, ROTATE, RESEED };

void RecoveryManager::SchedulerTick()
{
    if (IsQuarantined()) {
        // Diagnosis stays fresh in quarantine, but the auto engine must not
        // fight the quarantine's networking-off state.
        Signals sig = CollectSignals();
        LOCK(m_mutex);
        PublishSnapshot(sig);
        return;
    }

    Signals sig = CollectSignals();

    LadderAction action{LadderAction::NONE};
    std::string rotate_reason;
    {
        LOCK(m_mutex);
        if (!sig.attached || !m_init_complete) {
            PublishSnapshot(sig);
            return;
        }
        Classify(sig);
        AdvanceRepairPhases(sig);

        const bool isolated = HasFinding(FindingCode::NET_ISOLATED);
        const bool t1 = HasFinding(FindingCode::TIP_STALLED_NETWORK);

        if (m_selfheal_enabled && isolated && !m_ladder_parked) {
            // 3.5 loop guard: at most 3 full cycles per rolling 6 h window.
            if (m_cycle_window_start == 0 || sig.now - m_cycle_window_start > LADDER_CYCLE_WINDOW_SECS) {
                m_cycle_window_start = sig.now;
                m_cycles_used = 0;
            }
            switch (m_ladder_stage) {
            case 0: // enter the ladder
                if (m_cycles_used >= LADDER_CYCLES_MAX) {
                    m_ladder_parked = true;
                    LogPrintf("recovery: isolation ladder exhausted (%d cycles / 6h); parked in "
                              "degraded mode pending user action\n", m_cycles_used);
                } else {
                    ++m_cycles_used;
                    m_ladder_stage = 1;
                    action = LadderAction::PROBE;
                    LogPrintf("recovery: isolation ladder cycle %d: L1 local-link triage\n", m_cycles_used);
                }
                break;
            case 1: // L1 outcome is applied by the actuation block below
                if (sig.now >= m_next_link_probe_time) action = LadderAction::PROBE;
                break;
            case 2: // L2: outbound rotation; refill is ThreadOpenConnections'
                if (sig.now - m_last_rotation_time >= ROTATION_MIN_INTERVAL_SECS) {
                    if (m_l2_failures >= L2_FAILURES_BEFORE_L3) {
                        m_ladder_stage = 3;
                        action = LadderAction::RESEED;
                        LogPrintf("recovery: L2 yielded no tip-advancing peer twice; escalating to "
                                  "L3 re-seed\n");
                    } else {
                        ++m_l2_failures;
                        action = LadderAction::ROTATE;
                        rotate_reason = "L2 outbound rotation";
                    }
                }
                break;
            case 3: // L3 done; wait, then either recycle or declare N2
                if (sig.now - m_last_rotation_time >= ROTATION_MIN_INTERVAL_SECS) {
                    ++m_full_cycles;
                    if (m_full_cycles >= FULL_CYCLES_BEFORE_ECLIPSE && sig.addrman_size >= ECLIPSE_ADDRMAN_FLOOR) {
                        // 3.4: populated-but-eclipsed -- no safe automatic
                        // lever exists. Park and route to guided.
                        Finding f;
                        f.code = FindingCode::NET_ECLIPSE_SUSPECT;
                        f.since = sig.now;
                        f.evidence_num.emplace_back("addrman_size", static_cast<int64_t>(sig.addrman_size));
                        f.evidence_num.emplace_back("full_cycles", m_full_cycles);
                        f.debug_detail = "addrman populated but no connection advances the tip; "
                                         "no safe automatic lever for suspected eclipse";
                        UpsertFinding(FindingCode::NET_ECLIPSE_SUSPECT, std::move(f));
                        m_ladder_parked = true;
                    } else {
                        m_ladder_stage = 0; // recycle (bounded by the loop guard)
                        m_l2_failures = 0;
                    }
                }
                break;
            }
        } else if (m_selfheal_enabled && t1 && action == LadderAction::NONE) {
            // 4.1 T1: reconnection ONLY, with anti-double-eviction rules
            // (2.2): stand down for 5 minutes after the built-in stall
            // eviction fired, and respect the rotation cap.
            const int64_t last_builtin = m_last_builtin_stall_eviction.load(std::memory_order_acquire);
            if (sig.now - last_builtin >= STALL_EVICTION_SUPPRESSION_SECS &&
                sig.now - m_last_rotation_time >= ROTATION_MIN_INTERVAL_SECS) {
                action = LadderAction::ROTATE;
                rotate_reason = "T1 stalled-tip rotation";
            }
        }

        if (HasFinding(FindingCode::TIP_STALLED_NONNETWORK)) {
            // 4.2 T2: diagnosis only. Logged so the regtest suite can assert
            // the absence of any block-level actuator.
            LogPrint(BCLog::VALIDATION, "recovery: T2 non-network stall diagnosed; surfacing only, "
                                        "no automatic block-level action\n");
        }

        if (action == LadderAction::ROTATE || action == LadderAction::RESEED) {
            m_last_rotation_time = sig.now;
        }
        PublishSnapshot(sig);
    }

    // ---- actuation (no m_mutex held; uses only verified-effective levers) ----
    CConnman* connman;
    {
        LOCK(m_mutex);
        connman = m_connman;
    }
    if (!connman) return;

    switch (action) {
    case LadderAction::NONE:
        break;
    case LadderAction::PROBE: {
        const bool link_ok = ProbeLocalLink();
        LOCK(m_mutex);
        m_next_link_probe_time = GetTime() + LINK_PROBE_BACKOFF_SECS;
        if (link_ok) {
            ClearFinding(FindingCode::NET_LOCAL_LINK_DOWN);
            if (m_ladder_stage == 1) {
                m_ladder_stage = 2;
                LogPrintf("recovery: L1 link probe ok; advancing to L2 rotation\n");
            }
        } else {
            // 3.1: both probes failed -- our link is down; no peer action can
            // help. Surface and re-probe on backoff.
            Finding f;
            f.code = FindingCode::NET_LOCAL_LINK_DOWN;
            f.since = GetTime();
            f.debug_detail = "DNS seed resolution and TCP dial to fixed seeds both failed";
            UpsertFinding(FindingCode::NET_LOCAL_LINK_DOWN, std::move(f));
        }
        break;
    }
    case LadderAction::ROTATE: {
        LOCK(m_mutex);
        RotateOutbounds(rotate_reason);
        break;
    }
    case LadderAction::RESEED: {
        // 3.3 L3: AddAddrFetch across ALL DNS seeds (one ADDR_FETCH peer and
        // one getaddr response each -- the honest yield) + direct fixed-seed
        // injection into addrman, bypassing the one-shot empty-addrman gate.
        // The discouragement filter is never touched.
        size_t dns_count{0};
        for (const std::string& seed : Params().DNSSeeds()) {
            connman->AddAddrFetch(seed);
            ++dns_count;
        }
        const size_t fixed_count = connman->InjectFixedSeeds();
        LogPrintf("recovery: L3 re-seed: %d dns seed fetches queued, %d fixed seeds injected\n",
                  dns_count, fixed_count);
        LOCK(m_mutex);
        RotateOutbounds("L3 post-reseed rotation");
        break;
    }
    } // no default case, so the compiler can warn about missing cases
}

bool RecoveryManager::ProbeLocalLink() const
{
    // 3.1 L1: distinguish "our link is down" from "the peers are gone".
    // Nothing to probe against on chains without seeds (regtest): treat the
    // link as usable so the ladder proceeds.
    const auto& dns_seeds = Params().DNSSeeds();
    std::vector<CAddress> fixed;
    {
        // ConvertSeeds equivalent lives behind CConnman; keep the probe
        // independent of connman by only using chainparams data here.
    }
    bool have_target{false};
    // DNS resolve up to two seed names.
    for (size_t i = 0; i < dns_seeds.size() && i < 2; ++i) {
        have_target = true;
        const std::vector<CNetAddr> addrs = LookupHost(dns_seeds[i], /*nMaxSolutions=*/4, /*fAllowLookup=*/true);
        if (!addrs.empty()) return true;
    }
    // TCP-dial the first resolvable seed name on the default port.
    for (size_t i = 0; i < dns_seeds.size() && i < 2; ++i) {
        const std::vector<CNetAddr> addrs = LookupHost(dns_seeds[i], 1, true);
        if (addrs.empty()) continue;
        have_target = true;
        const CService dest{addrs[0], Params().GetDefaultPort()};
        if (ConnectDirectly(dest, /*manual_connection=*/false)) return true;
    }
    return !have_target;
}

void RecoveryManager::RotateOutbounds(const std::string& why)
{
    AssertLockHeld(m_mutex);
    if (!m_connman) return;
    // 3.2 L2: plain CConnman disconnection only -- never Misbehaving. At most
    // half the outbound set when any outbounds are still alive; manual
    // (operator-configured) and verified-masternode connections are left
    // alone. ThreadOpenConnections refills the freed slots from addrman, and
    // each NEW connection performs a fresh addr exchange (the per-connection
    // getaddr guard) -- the only mechanism that actually harvests gossip.
    std::vector<CNodeStats> vstats;
    m_connman->GetNodeStats(vstats);
    const int64_t now = GetTime();

    std::vector<std::pair<int64_t, NodeId>> candidates; // (last_recv, id) stalest first
    size_t outbound_alive{0};
    for (const CNodeStats& stats : vstats) {
        if (stats.fInbound) continue;
        if (stats.m_conn_type == ConnectionType::MANUAL || stats.m_masternode_connection) continue;
        ++outbound_alive;
        candidates.emplace_back(stats.m_last_recv.count(), stats.nodeid);
    }
    if (candidates.empty()) {
        LogPrintf("recovery: %s: no rotatable outbound peers (refill left to connman)\n", why);
        return;
    }
    std::sort(candidates.begin(), candidates.end());

    size_t budget = candidates.size();
    const bool any_alive = std::any_of(vstats.begin(), vstats.end(), [now](const CNodeStats& s) {
        return now - s.m_last_recv.count() <= PEER_SILENCE_HORIZON_SECS;
    });
    if (any_alive) budget = std::max<size_t>(1, candidates.size() / 2);

    size_t dropped{0};
    for (const auto& [last_recv, id] : candidates) {
        if (dropped >= budget) break;
        if (m_connman->DisconnectNode(id)) ++dropped;
    }
    LogPrintf("recovery: %s: rotated %d of %d outbound peer(s)\n", why, dropped, outbound_alive);
}

// ---- repair phase machine (6.3) ----

void RecoveryManager::AdvanceRepairPhases(const Signals& sig)
{
    AssertLockHeld(m_mutex);
    if (!m_repair_in_flight) return;

    if (sig.ibd) {
        if (m_repair_phase != RepairPhase::SYNCING) {
            m_repair_phase = RepairPhase::SYNCING;
            SetLedgerRepairState("syncing");
        }
        return;
    }

    // Post-IBD: the explicit Sapling witness stage (6.4). The wallet is
    // preserved, not untouched: per-note witnesses were built against the
    // pre-wipe chain and must be rebuilt before shielded funds are spendable.
    WalletWitnessStatus wit;
    if (const auto query = GetWalletWitnessQuery()) wit = query();
    if (wit.have_wallet) {
        if (!m_witness_stage_triggered) {
            m_witness_stage_triggered = true;
            if (const auto trigger = GetWalletWitnessTrigger()) {
                // Forces detection + rebuild even under
                // -noautorebuildsaplingwitnesses (6.4.b).
                trigger();
            }
            m_repair_phase = RepairPhase::REBUILDING_WITNESSES;
            SetLedgerRepairState("rebuilding_witnesses");
            return;
        }
        if (wit.rebuild_active || wit.check_pending) {
            if (m_repair_phase != RepairPhase::REBUILDING_WITNESSES) {
                m_repair_phase = RepairPhase::REBUILDING_WITNESSES;
                SetLedgerRepairState("rebuilding_witnesses");
            }
            return;
        }
    }

    if (m_repair_phase != RepairPhase::VERIFYING && m_repair_phase != RepairPhase::DONE) {
        m_repair_phase = RepairPhase::VERIFYING;
        m_verify_start_height = sig.tip_height;
        SetLedgerRepairState("verifying");
        return;
    }

    if (m_repair_phase == RepairPhase::VERIFYING) {
        // Verified health: drift re-check clean AND the tip advanced since
        // verification began AND no active findings. Only then do the guard
        // counters reset (6.6: "counter resets only on verified health").
        const bool drift_clean = !sig.drift_check_ran || sig.drift_ok;
        const bool tip_advanced = sig.tip_height > m_verify_start_height;
        if (drift_clean && tip_advanced && m_findings.empty()) {
            m_repair_phase = RepairPhase::DONE;
            m_repair_in_flight = false;
            UniValue ledger = ReadLedger();
            UniValue out(UniValue::VOBJ);
            for (const auto& key : ledger.getKeys()) {
                if (key != "attempts" && key != "repair_state" && key != "repair_state_ts" &&
                    key != "health_verified_ts") {
                    out.pushKV(key, ledger[key]);
                }
            }
            out.pushKV("attempts", UniValue{UniValue::VARR}); // verified health -> reset
            out.pushKV("repair_state", "done");
            out.pushKV("repair_state_ts", sig.now);
            out.pushKV("health_verified_ts", sig.now);
            WriteLedger(out);
            LogPrintf("recovery: repair complete and health verified at height %d; attempt "
                      "counters reset\n", sig.tip_height);
        } else if (sig.drift_check_ran && !sig.drift_ok) {
            m_repair_phase = RepairPhase::FAILED;
            m_repair_in_flight = false;
            SetLedgerRepairState("failed");
            LogPrintf("recovery: repair FAILED verification: consistency drift re-detected after "
                      "resync\n");
        }
    }
}

// ---- repairnode (7.3) ----

RepairPlan RecoveryManager::RepairDryRun(const std::string& scope)
{
    RepairPlan plan;
    const int64_t now = GetTime();
    const bool network_scope = scope == "network";

    bool network_class{false};
    {
        LOCK(m_mutex);
        network_class = HasFinding(FindingCode::NET_ECLIPSE_SUSPECT) ||
                        HasFinding(FindingCode::NET_ISOLATED) ||
                        HasFinding(FindingCode::NET_LOCAL_LINK_DOWN);
    }

    if (network_scope) {
        plan.wipe_files = {"peers.dat", "anchors.dat"};
    } else {
        plan.wipe_dirs = FullWipeDirs();
        plan.wipe_files = WipeFiles(/*include_network_state=*/network_class);
    }
    plan.preserved = PreservedLabels();
    for (const std::string& label : plan.wipe_dirs) plan.bytes_total_est += DirSizeEstimate(ResolveWipePath(label));
    for (const std::string& label : plan.wipe_files) plan.bytes_total_est += DirSizeEstimate(ResolveWipePath(label));

    const UniValue ledger = ReadLedger();
    plan.attempts_used = CountLedgerEntriesInWindow(ledger, "attempts", REPAIR_ATTEMPT_WINDOW_SECS, now);
    plan.wipes_in_window = CountLedgerEntriesInWindow(ledger, "wipes", REPAIR_WIPE_WINDOW_SECS, now);
    plan.rate_limited = !network_scope && plan.wipes_in_window >= REPAIR_WIPES_MAX;

    const std::string token = GetRandHash().ToString().substr(0, 32);
    {
        LOCK(m_mutex);
        m_confirm_token = token;
        m_confirm_token_expiry = now + CONFIRM_TOKEN_TTL_SECS;
        m_confirm_token_scope = network_scope ? "network" : "full";
        m_plan_bytes_est = plan.bytes_total_est;
    }
    plan.confirm_token = token;
    return plan;
}

ArmResult RecoveryManager::RepairArm(const std::string& confirm_token, const std::string& scope,
                                     bool override_rate_limit)
{
    const int64_t now = GetTime();
    const bool network_scope = scope == "network";

    {
        LOCK(m_mutex);
        if (m_repair_phase == RepairPhase::ARMED) return ArmResult::ALREADY_ARMED;
        if (confirm_token.empty() || confirm_token != m_confirm_token || now > m_confirm_token_expiry ||
            scope != m_confirm_token_scope) {
            return ArmResult::BAD_TOKEN;
        }
        m_confirm_token.clear(); // one-time
    }

    UniValue ledger = ReadLedger();
    const int attempts = CountLedgerEntriesInWindow(ledger, "attempts", REPAIR_ATTEMPT_WINDOW_SECS, now);
    const int wipes = CountLedgerEntriesInWindow(ledger, "wipes", REPAIR_WIPE_WINDOW_SECS, now);
    if (attempts >= REPAIR_ATTEMPTS_MAX) {
        LOCK(m_mutex);
        m_repair_phase = RepairPhase::FAILED;
        SetLedgerRepairState("failed");
        Signals sig;
        sig.now = now;
        PublishSnapshot(sig);
        return ArmResult::ATTEMPTS_EXHAUSTED;
    }
    if (!network_scope && wipes >= REPAIR_WIPES_MAX && !override_rate_limit) {
        // 6.6.2: the node keeps re-corrupting -- almost certainly failing
        // hardware. Refuse; front-ends render check-your-disk guidance.
        LOCK(m_mutex);
        Finding f;
        f.code = FindingCode::REPAIR_RATE_LIMITED;
        f.since = now;
        f.evidence_num.emplace_back("wipes_in_window", wipes);
        f.evidence_num.emplace_back("wipes_max", REPAIR_WIPES_MAX);
        const UniValue& warr = ledger["wipes"];
        if (warr.isArray()) {
            for (size_t i = 0; i < warr.size(); ++i) {
                if (warr[i]["ts"].isNum()) {
                    f.evidence_num.emplace_back(strprintf("wipe_ts_%d", i), warr[i]["ts"].getInt<int64_t>());
                }
            }
        }
        f.debug_detail = "wipe-rate guard: 2 completed wipes within 7 days";
        UpsertFinding(FindingCode::REPAIR_RATE_LIMITED, std::move(f));
        // Republish immediately: the very next getrecoverystatus must carry
        // the refusal, without waiting for the diagnosis tick.
        Signals sig;
        sig.now = now;
        PublishSnapshot(sig);
        return ArmResult::RATE_LIMITED;
    }

    // Determine the wipe list now (network-class findings pull peers.dat +
    // anchors.dat into a full wipe, 6.1).
    bool network_class{false};
    std::string reason{"user_requested"};
    {
        LOCK(m_mutex);
        network_class = HasFinding(FindingCode::NET_ECLIPSE_SUSPECT) ||
                        HasFinding(FindingCode::NET_ISOLATED) ||
                        HasFinding(FindingCode::NET_LOCAL_LINK_DOWN);
        for (const Finding& f : m_findings) {
            if (f.code == FindingCode::DRIFT_EVODB || f.code == FindingCode::DRIFT_SAPLING ||
                f.code == FindingCode::CHAINSTATE_LOAD_FAILED) {
                reason = FindingCodeToString(f.code);
                break;
            }
        }
    }

    // Arm: atomically write the marker (6.2.1). The wipe itself runs at
    // shutdown, after every DB is flushed and closed.
    UniValue marker(UniValue::VOBJ);
    marker.pushKV("version", 1);
    marker.pushKV("armed_ts", now);
    marker.pushKV("scope", network_scope ? "network" : "full");
    marker.pushKV("reason", reason);
    marker.pushKV("override_rate_limit", override_rate_limit);
    UniValue jdirs(UniValue::VARR);
    UniValue jfiles(UniValue::VARR);
    if (network_scope) {
        for (const auto& fname : {"peers.dat", "anchors.dat"}) jfiles.push_back(fname);
    } else {
        for (const std::string& d : FullWipeDirs()) jdirs.push_back(d);
        for (const std::string& fname : WipeFiles(network_class)) jfiles.push_back(fname);
    }
    marker.pushKV("wipe_dirs", jdirs);
    marker.pushKV("wipe_files", jfiles);
    if (!WriteJsonFile(MarkerPath(), marker)) {
        LogPrintf("recovery: ERROR: failed to write repair marker\n");
        return ArmResult::BAD_TOKEN;
    }

    // Ledger: record the attempt (+ any override, which is always ledgered).
    {
        UniValue attempt(UniValue::VOBJ);
        attempt.pushKV("ts", now);
        attempt.pushKV("scope", network_scope ? "network" : "full");
        attempt.pushKV("reason", reason);
        attempt.pushKV("override_rate_limit", override_rate_limit);
        UniValue attempts_arr = ledger["attempts"];
        if (!attempts_arr.isArray()) attempts_arr = UniValue{UniValue::VARR};
        attempts_arr.push_back(attempt);
        UniValue out(UniValue::VOBJ);
        for (const auto& key : ledger.getKeys()) {
            if (key != "attempts" && key != "repair_state" && key != "repair_state_ts") out.pushKV(key, ledger[key]);
        }
        out.pushKV("attempts", attempts_arr);
        out.pushKV("repair_state", "armed");
        out.pushKV("repair_state_ts", now);
        WriteLedger(out);
    }

    {
        LOCK(m_mutex);
        m_repair_phase = RepairPhase::ARMED;
        ClearFinding(FindingCode::REPAIR_RATE_LIMITED);
        Signals sig;
        sig.now = now;
        PublishSnapshot(sig);
    }
    LogPrintf("recovery: repair ARMED (scope=%s, reason=%s); wipe executes at shutdown\n",
              network_scope ? "network" : "full", reason);
    return ArmResult::ARMED;
}

// ---- snapshot publication ----

void RecoveryManager::PublishSnapshot(const Signals& sig)
{
    AssertLockHeld(m_mutex);
    StatusSnapshot snap;

    // daemon_mode discriminator (7.4).
    if (IsQuarantined()) {
        snap.daemon_mode = DaemonMode::QUARANTINED;
    } else if (m_mode == DaemonMode::CRIPPLED_WAIT) {
        snap.daemon_mode = DaemonMode::CRIPPLED_WAIT;
    } else if (m_repair_phase == RepairPhase::ARMED) {
        snap.daemon_mode = DaemonMode::REPAIR_ARMED;
    } else if (!m_init_complete) {
        snap.daemon_mode = DaemonMode::STARTING;
    } else if (sig.attached && sig.ibd) {
        snap.daemon_mode = DaemonMode::SYNCING;
    } else if (!m_findings.empty() || m_ladder_parked) {
        snap.daemon_mode = DaemonMode::DEGRADED;
    } else {
        snap.daemon_mode = DaemonMode::NORMAL;
    }

    snap.findings = m_findings;

    // recommended_action: highest-priority applicable id.
    snap.recommended_action = RecommendedAction::ACTION_NONE;
    if (HasFinding(FindingCode::DRIFT_EVODB) || HasFinding(FindingCode::DRIFT_SAPLING) ||
        HasFinding(FindingCode::CHAINSTATE_LOAD_FAILED)) {
        snap.recommended_action = RecommendedAction::ACTION_GUIDED_REPAIR;
    } else if (HasFinding(FindingCode::REPAIR_RATE_LIMITED)) {
        snap.recommended_action = RecommendedAction::ACTION_CHECK_DISK;
    } else if (HasFinding(FindingCode::NODE_ABORTED)) {
        snap.recommended_action = RecommendedAction::ACTION_CHECK_DISK;
    } else if (HasFinding(FindingCode::NET_ECLIPSE_SUSPECT)) {
        snap.recommended_action = RecommendedAction::ACTION_GUIDED_NETWORK_REPAIR;
    } else if (HasFinding(FindingCode::NET_LOCAL_LINK_DOWN)) {
        snap.recommended_action = RecommendedAction::ACTION_DIAGNOSE_SUPPORT;
    } else if (HasFinding(FindingCode::TIP_STALLED_NONNETWORK)) {
        snap.recommended_action = RecommendedAction::ACTION_DIAGNOSE_SUPPORT;
    } else if (m_ladder_parked) {
        snap.recommended_action = RecommendedAction::ACTION_GUIDED_NETWORK_REPAIR;
    } else if (HasFinding(FindingCode::NET_ISOLATED) || HasFinding(FindingCode::TIP_STALLED_NETWORK)) {
        snap.recommended_action = RecommendedAction::ACTION_WAIT_AUTO;
    }

    snap.ladder_stage = m_ladder_stage;
    snap.cycles_used = m_cycles_used;
    snap.cycles_max = LADDER_CYCLES_MAX;
    snap.window_resets = m_cycle_window_start > 0 ? m_cycle_window_start + LADDER_CYCLE_WINDOW_SECS : 0;

    snap.height = std::max(sig.tip_height, 0);
    snap.target_height = std::max({sig.best_peer_height, sig.tip_height, 0});
    snap.progress = snap.target_height > 0 ? std::min(1.0, double(snap.height) / snap.target_height) : 0.0;
    snap.tip_age_secs = sig.have_tip ? std::max<int64_t>(0, sig.now - sig.tip_time) : 0;
    snap.expected_spacing_secs = sig.expected_spacing;

    snap.repair_phase = m_repair_phase;
    snap.bytes_total_est = m_plan_bytes_est;
    snap.bytes_wiped = (m_repair_in_flight || m_repair_phase == RepairPhase::DONE) ? m_plan_bytes_est : 0;
    // Witness counts are not currently exposed by the wallet; reported as 0
    // (unknown) rather than fabricated. eta_secs stays null unless cheap.
    snap.witnesses_rebuilt = 0;
    snap.witnesses_total = 0;
    snap.eta_secs = std::nullopt;

    const UniValue ledger = ReadLedger();
    snap.attempts_used = CountLedgerEntriesInWindow(ledger, "attempts", REPAIR_ATTEMPT_WINDOW_SECS, sig.now);
    snap.attempts_max = REPAIR_ATTEMPTS_MAX;
    snap.wipes_in_window = CountLedgerEntriesInWindow(ledger, "wipes", REPAIR_WIPE_WINDOW_SECS, sig.now);
    snap.wipes_max = REPAIR_WIPES_MAX;

    m_snapshot = std::move(snap);
}

StatusSnapshot RecoveryManager::GetStatusSnapshot() const
{
    LOCK(m_mutex);
    return m_snapshot;
}

// ---------------------------------------------------------------------------
// Free-function fan-in
// ---------------------------------------------------------------------------

void EnterQuarantine(QuarantineReason reason, const std::string& debug_detail)
{
    if (g_recovery) {
        g_recovery->EnterQuarantine(reason, debug_detail);
        return;
    }
    // Manager not constructed (very early init or teardown): still flip the
    // duty gate so nothing acts on drifted state, and leave a log trail.
    g_quarantined.store(true, std::memory_order_release);
    LogPrintf("*** recovery: quarantine requested before/after manager lifetime: %s\n", debug_detail);
}

void NoteBuiltinStallEviction()
{
    if (g_recovery) g_recovery->NoteBuiltinStallEviction();
}

bool StartupDriftCheck(node::NodeContext& node)
{
    if (!node.chainman) return true;
    uint256 tip_hash;
    int tip_height{-1};
    bool dip3_active{false};
    {
        LOCK(cs_main);
        const CBlockIndex* tip = node.chainman->ActiveTip();
        if (!tip) return true; // fresh/post-wipe datadir: nothing to check
        tip_hash = tip->GetBlockHash();
        tip_height = tip->nHeight;
        dip3_active = DeploymentActiveAt(*tip, Params().GetConsensus(), Consensus::DEPLOYMENT_DIP0003);
    }

    // 5.4: EvoDB reports a MISSING best-block key as inconsistent, and the
    // check only applies once DIP3 is active -- mirror both.
    if (dip3_active && node.evodb && !node.evodb->VerifyBestBlock(tip_hash)) {
        EnterQuarantine(QuarantineReason::STARTUP_DRIFT,
                        strprintf("startup: EvoDB best-block disagrees with active tip %s (height %d)",
                                  tip_hash.ToString(), tip_height));
        return false;
    }
    // 5.4: SaplingDB defines a missing key as fresh/consistent
    // (VerifyBestBlock returns true), so no false positive is possible here
    // for a fresh post-activation node.
    if (node.chain_helper && node.chain_helper->sapling_state &&
        sapling::IsSaplingActive(Params().GetConsensus(), tip_height) &&
        !node.chain_helper->sapling_state->VerifyBestBlock(tip_hash)) {
        EnterQuarantine(QuarantineReason::STARTUP_DRIFT,
                        strprintf("startup: SaplingDB best-block disagrees with active tip %s (height %d) [sapling]",
                                  tip_hash.ToString(), tip_height));
        return false;
    }
    return true;
}

} // namespace recovery
