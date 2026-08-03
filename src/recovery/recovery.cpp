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
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <thread>

namespace recovery {

std::atomic<bool> g_quarantined{false};
std::unique_ptr<RecoveryManager> g_recovery;

//! GUI-build guard for `repairnode {shutdown:true}` (7.3/8.2). Set once by
//! kerrigan-qt before its RPC server can execute commands; never set by
//! headless kerrigand.
static std::atomic<bool> g_repair_shutdown_rejected{false};

void SetRepairShutdownRejected()
{
    g_repair_shutdown_rejected.store(true, std::memory_order_release);
}

bool IsRepairShutdownRejected()
{
    return g_repair_shutdown_rejected.load(std::memory_order_acquire);
}

//! PARK-VS-EXIT frontend split. Default false => headless kerrigand EXITS on a
//! fault; kerrigan-qt's GuiMain sets it true => the GUI node PARKS so the wallet
//! can offer a one-click Repair. A hidden -parkonfault arg can also set it true
//! (regression tests exercising the park path under the headless binary).
static std::atomic<bool> g_park_on_fault{false};
//! Latched when a headless RUNTIME fault took the AbortNode path after startup
//! had already succeeded; read in bitcoind.cpp to force a non-zero exit code.
static std::atomic<bool> g_headless_fault_exit{false};

void SetParkOnFault(bool park)
{
    g_park_on_fault.store(park, std::memory_order_release);
}

bool ParkOnFault()
{
    return g_park_on_fault.load(std::memory_order_acquire);
}

bool HeadlessFaultExitRequested()
{
    return g_headless_fault_exit.load(std::memory_order_acquire);
}

void NoteHeadlessFaultShutdown(const std::string& condition, const std::string& detail)
{
    // Engage the B3 serving gates synchronously (IsQuarantined() => true) so a
    // quarantined-class responder cannot serve drifted state during the brief
    // window before shutdown completes. Deliberately does NOT persist a
    // quarantine sentinel: a headless node does not park across restarts; the
    // underlying on-disk fault (if any) re-triggers the headless exit until an
    // operator repairs. Idempotent for the process lifetime.
    if (g_headless_fault_exit.exchange(true, std::memory_order_acq_rel)) {
        return; // already shutting down for a headless fault
    }
    g_quarantined.store(true, std::memory_order_release);
    // So the NEXT start can surface NODE_ABORTED / ACTION_CHECK_DISK.
    RecordAbortReason(detail);

    // Distinct, greppable diagnostic to the log AND stderr, naming the
    // condition and the recovery route, so systemd/monitoring see a real
    // failure rather than a clean shutdown.
    LogPrintf("*** recovery: HEADLESS FAULT EXIT (%s): %s | recovery route: the chainstate is "
              "inconsistent and must be rebuilt -- use the Kerrigan desktop wallet's one-click "
              "Repair, or `kerrigan-cli repair` (guided wipe + resync), or restart with "
              "-resetchainstate | the node is going DOWN with a NON-ZERO exit (NOT parked) so "
              "systemd/monitoring sees the failure\n",
              condition, detail);
    fprintf(stderr,
            "Error: recovery: HEADLESS FAULT EXIT (%s): %s\n"
            "The chainstate is inconsistent and must be rebuilt. Recover with the Kerrigan "
            "desktop wallet's one-click Repair, or run `kerrigan-cli repair` (guided wipe + "
            "resync), or restart with -resetchainstate.\n"
            "This headless node is exiting with a non-zero status (it did NOT park); a parked, "
            "repairable node is offered only under the desktop wallet.\n",
            condition.c_str(), detail.c_str());

    // Original fatal AbortNode semantics: SetMiscWarning + AbortError +
    // StartShutdown (controlled shutdown). Combined with the latched
    // HeadlessFaultExitRequested() above, the process exits non-zero.
    AbortNode(detail);
}

// ---------------------------------------------------------------------------
// File names (all in the network datadir ROOT, deliberately outside every
// wiped directory, 6.6)
// ---------------------------------------------------------------------------
static const char* const REPAIR_MARKER_FILENAME = "repair_marker.json";
static const char* const REPAIR_MARKER_DONE_FILENAME = "repair_marker.done.json";
static const char* const REPAIR_MARKER_REJECTED_FILENAME = "repair_marker.rejected.json";
static const char* const RECOVERY_LEDGER_FILENAME = "recovery_ledger.json";
static const char* const NODE_ABORT_FILENAME = "node_abort.json";
static const char* const QUARANTINE_SENTINEL_FILENAME = "quarantine_state.json";
static const char* const WIPE_TMP_PREFIX = "repair_wipe_tmp.";

//! A marker found at STARTUP whose wipe has not begun (no tombstones) is
//! executed only if it was armed recently. Restored backups, copied datadirs
//! and long-forgotten arms must not silently wipe months later.
static constexpr int64_t REPAIR_MARKER_MAX_AGE_SECS{24 * 60 * 60};
static constexpr int64_t REPAIR_MARKER_MAX_FUTURE_SKEW_SECS{60 * 60};

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
static fs::path MarkerRejectedPath() { return gArgs.GetDataDirNet() / REPAIR_MARKER_REJECTED_FILENAME; }
static fs::path QuarantineSentinelPath() { return gArgs.GetDataDirNet() / QUARANTINE_SENTINEL_FILENAME; }

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

// ---------------------------------------------------------------------------
// Wipe-target whitelist + containment (B1). The executor deletes ONLY a
// hard-coded, closed set of chain-derived basenames -- exactly the
// -resetchainstate set plus the three network/mempool files -- resolved
// strictly as direct children of the datadir (blocks: of -blocksdir's
// parent, mirroring GetBlocksDirPath). Marker content can never name an
// arbitrary path: labels are validated against this whitelist, resolution is
// re-derived from trusted configuration, and the resolved target is
// containment- and symlink-checked before anything is touched. Any
// validation failure aborts the WHOLE repair, fail-closed, with no removal.
// ---------------------------------------------------------------------------
static bool IsWhitelistedWipeDir(const std::string& label)
{
    static const std::vector<std::string> kDirs{"blocks", "chainstate", "sapling", "evodb", "llmq", "indexes"};
    return std::find(kDirs.begin(), kDirs.end(), label) != kDirs.end();
}

static bool IsWhitelistedWipeFile(const std::string& label)
{
    static const std::vector<std::string> kFiles{"mempool.dat", "peers.dat", "anchors.dat"};
    return std::find(kFiles.begin(), kFiles.end(), label) != kFiles.end();
}

static bool IsWhitelistedWipeLabel(const std::string& label)
{
    // Belt-and-suspenders: whitelist entries are plain basenames, but reject
    // separators / traversal / absolute forms explicitly anyway.
    if (label.empty() || label.find('/') != std::string::npos || label.find('\\') != std::string::npos ||
        label.find("..") != std::string::npos || label.front() == '/') {
        return false;
    }
    return IsWhitelistedWipeDir(label) || IsWhitelistedWipeFile(label);
}

//! Resolve a WHITELISTED wipe label to its absolute path. "blocks" honors
//! -blocksdir the same way -resetchainstate does (ArgsManager::GetBlocksDirPath).
//! Callers MUST have validated the label first (IsWhitelistedWipeLabel).
static fs::path ResolveWipePath(const std::string& label)
{
    if (label == "blocks") return gArgs.GetBlocksDirPath();
    return gArgs.GetDataDirNet() / fs::PathFromString(label);
}

//! The directory a wipe label's resolved path must be a DIRECT child of.
static fs::path ExpectedWipeParent(const std::string& label)
{
    if (label == "blocks") return gArgs.GetBlocksDirPath().parent_path();
    return gArgs.GetDataDirNet();
}

//! Containment check: the canonicalized parent of the resolved target must
//! equal the canonicalized expected parent, and the target itself must not
//! be a symlink (renaming/removing a link would strand or leak the real
//! data, and a planted link could redirect the wipe).
static bool WipeTargetIsSafe(const std::string& label, const fs::path& resolved, std::string& why)
{
    std::error_code ec;
    if (fs::is_symlink(fs::symlink_status(resolved, ec))) {
        why = strprintf("target %s is a symlink", fs::PathToString(resolved));
        return false;
    }
    std::error_code ec1, ec2;
    const std::filesystem::path canon_target = std::filesystem::weakly_canonical(resolved, ec1);
    const std::filesystem::path canon_parent = std::filesystem::weakly_canonical(ExpectedWipeParent(label), ec2);
    if (ec1 || ec2) {
        why = strprintf("cannot canonicalize %s (%s)", fs::PathToString(resolved),
                        (ec1 ? ec1 : ec2).message());
        return false;
    }
    if (canon_target.parent_path() != canon_parent) {
        why = strprintf("resolved target %s is not a direct child of %s",
                        canon_target.string(), canon_parent.string());
        return false;
    }
    if (canon_target.filename().string() != label) {
        why = strprintf("resolved basename %s does not match label %s",
                        canon_target.filename().string(), label);
        return false;
    }
    return true;
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

//! Any interrupted-wipe tombstone present? Used to distinguish "wipe already
//! began (must be finished)" from "armed but never started" at startup, which
//! in turn decides whether the marker staleness cutoff applies. Because that
//! makes this a security-relevant signal (NF-5: a bypass of the 24 h cutoff),
//! a tombstone counts as proof-of-in-progress ONLY when its name is exactly
//! `<prefix><whitelisted-label>` -- the only names THIS code ever creates. An
//! arbitrary attacker-plantable `repair_wipe_tmp.<anything>` no longer defeats
//! the staleness cutoff.
static bool AnyWipeTombstonePresent()
{
    const std::vector<fs::path> parents{gArgs.GetDataDirNet(), fs::path{gArgs.GetBlocksDirPath().parent_path()}};
    for (const fs::path& parent : parents) {
        if (!fs::exists(parent)) continue;
        std::error_code ec;
        for (auto it = fs::directory_iterator(parent, ec); !ec && it != fs::directory_iterator(); it.increment(ec)) {
            const std::string name = fs::PathToString(it->path().filename());
            if (name.rfind(WIPE_TMP_PREFIX, 0) != 0) continue;
            const std::string label = name.substr(std::string(WIPE_TMP_PREFIX).size());
            if (IsWhitelistedWipeLabel(label)) return true;
        }
    }
    return false;
}

//! Fail-closed marker rejection: NOTHING is removed; the marker is
//! quarantined by rename (so a bad marker is not re-honoured on every start)
//! and the repair is surfaced as failed.
static void RejectMarker(const fs::path& marker_path, const std::string& why)
{
    LogPrintf("recovery: ERROR: REFUSING repair wipe from %s: %s. No data was removed; the marker "
              "has been quarantined to %s and the repair is recorded as failed. Re-run `repairnode` "
              "to arm a fresh, validated repair.\n",
              fs::PathToString(marker_path), why, fs::PathToString(MarkerRejectedPath()));
    if (!RenameOver(marker_path, MarkerRejectedPath())) {
        // Even the rename failed; delete rather than leave an execute-me file.
        std::error_code ec;
        fs::remove(marker_path, ec);
    }
    SetLedgerRepairState("failed");
}

//! Execute the wipe described by the marker at `marker_path`. Returns true if
//! the marker was consumed (renamed to done) and the wipe ran. `at_startup`
//! selects the stricter startup rules (marker staleness).
//!
//! B1 hard rule: the wipe set is validated against the hard-coded whitelist
//! and containment checks BEFORE anything is touched; one bad target aborts
//! the whole repair with no removal at all.
static bool ExecuteMarkerWipe(const fs::path& marker_path, bool at_startup)
{
    const auto marker = ReadJsonFile(marker_path);
    if (!marker) {
        RejectMarker(marker_path, "marker is unreadable or not a JSON object");
        return false;
    }

    // Schema/version validation: refuse foreign or future marker formats.
    const UniValue& version = (*marker)["version"];
    if (!version.isNum() || version.getInt<int>() != 1) {
        RejectMarker(marker_path, "unsupported marker version");
        return false;
    }
    const std::string scope = (*marker)["scope"].isStr() ? (*marker)["scope"].get_str() : "";
    if (scope != "full" && scope != "network") {
        RejectMarker(marker_path, strprintf("unknown scope '%s'", scope));
        return false;
    }

    // Staleness (startup only, and only when the wipe has not already begun;
    // a crash mid-wipe MUST be finished regardless of age). A marker armed
    // >24 h ago -- restored backups, copied datadirs, long-forgotten arms --
    // is refused rather than silently destroying chain state.
    if (at_startup && !AnyWipeTombstonePresent()) {
        const UniValue& armed_ts = (*marker)["armed_ts"];
        const int64_t now = GetTime();
        if (!armed_ts.isNum()) {
            RejectMarker(marker_path, "marker carries no armed_ts");
            return false;
        }
        const int64_t age = now - armed_ts.getInt<int64_t>();
        if (age > REPAIR_MARKER_MAX_AGE_SECS || age < -REPAIR_MARKER_MAX_FUTURE_SKEW_SECS) {
            RejectMarker(marker_path, strprintf("marker is stale (armed %d seconds ago; limit %d)",
                                                age, REPAIR_MARKER_MAX_AGE_SECS));
            return false;
        }
    }

    // The EXECUTED wipe set is derived from the hard-coded whitelist plus
    // the marker's scope -- never from marker-supplied paths. The marker's
    // wipe_dirs/wipe_files arrays (written for transparency/debugging) are
    // still validated: any non-whitelisted entry means the marker was not
    // written by this code and the whole repair is refused.
    for (const auto* key : {"wipe_dirs", "wipe_files"}) {
        const UniValue& arr = (*marker)[key];
        if (arr.isNull()) continue;
        if (!arr.isArray()) {
            RejectMarker(marker_path, strprintf("%s is not an array", key));
            return false;
        }
        for (size_t i = 0; i < arr.size(); ++i) {
            if (!arr[i].isStr() || !IsWhitelistedWipeLabel(arr[i].get_str())) {
                RejectMarker(marker_path,
                             strprintf("%s entry '%s' is not in the hard-coded wipe whitelist",
                                       key, arr[i].isStr() ? arr[i].get_str() : "<non-string>"));
                return false;
            }
        }
    }

    std::vector<std::string> dir_targets;
    std::vector<std::string> file_targets;
    if (scope == "network") {
        file_targets = {"peers.dat", "anchors.dat"};
    } else {
        dir_targets = FullWipeDirs();
        bool include_network_state = (*marker)["include_network_state"].isBool() &&
                                     (*marker)["include_network_state"].get_bool();
        // Back-compat with markers that predate include_network_state: their
        // (whitelist-validated) wipe_files list carries the intent.
        const UniValue& files = (*marker)["wipe_files"];
        if (!include_network_state && files.isArray()) {
            for (size_t i = 0; i < files.size(); ++i) {
                if (files[i].isStr() && files[i].get_str() == "peers.dat") include_network_state = true;
            }
        }
        file_targets = WipeFiles(include_network_state);
    }
    std::vector<std::string> targets{dir_targets};
    targets.insert(targets.end(), file_targets.begin(), file_targets.end());

    // Validate EVERY existing target (containment + symlink) before touching
    // ANY of them: one bad target aborts the whole repair, fail closed.
    for (const std::string& label : targets) {
        const fs::path src = ResolveWipePath(label);
        std::error_code ec;
        const bool present = std::filesystem::exists(std::filesystem::symlink_status(src, ec));
        if (!present) continue;
        std::string why;
        if (!WipeTargetIsSafe(label, src, why)) {
            RejectMarker(marker_path, why);
            return false;
        }
    }

    LogPrintf("recovery: executing %s repair wipe (%d whitelisted targets) from %s\n",
              scope, targets.size(), fs::PathToString(marker_path));

    // Phase 1: rename targets to tombstones (idempotent on resume). Track
    // whether EVERY intended target actually left its live path: a wipe that
    // could not remove a target must NOT be reported as success (NF-4).
    bool all_removed = true;
    for (const std::string& label : targets) {
        const fs::path src = ResolveWipePath(label);
        if (!fs::exists(src)) continue;
        const fs::path dst = src.parent_path() / fs::PathFromString(WIPE_TMP_PREFIX + label);
        std::error_code rmec;
        fs::remove_all(dst, rmec); // stale tombstone from an interrupted run
        std::error_code rnec;
        fs::rename(src, dst, rnec);
        if (rnec) {
            // Fall back to direct removal (e.g. cross-device -blocksdir
            // edge). Safe here: the target passed the whitelist, containment
            // and symlink checks above.
            std::error_code dec;
            fs::remove_all(src, dec);
            LogPrintf("recovery: wipe %s: rename failed (%s), removed directly%s\n", label,
                      rnec.message(), dec ? strprintf(" (error: %s)", dec.message()) : "");
        } else {
            LogPrintf("recovery: wipe %s -> tombstone\n", label);
        }
        // Verify the live path is actually gone. rename-to-tombstone or a
        // successful direct remove both clear it; a permission/sharing/immutable
        // failure leaves it present -- the drifted DB survives and we must fail
        // closed rather than lie about it.
        std::error_code chkec;
        if (std::filesystem::exists(std::filesystem::symlink_status(src, chkec))) {
            all_removed = false;
            LogPrintf("recovery: ERROR: wipe target %s could NOT be removed and is still present\n",
                      fs::PathToString(src));
        }
    }

    // NF-4 fail-closed: if ANY intended target could not be removed, the repair
    // did NOT complete. Do NOT consume the marker, do NOT ledger a completed
    // wipe, do NOT reset the attempt counter, and do NOT clear the quarantine
    // sentinel. Surface REPAIR_FAILED and keep the node quarantined so the
    // operator fixes the underlying cause (disk/permission/mount) and retries,
    // rather than believing the corruption is gone. The marker is intentionally
    // left in place: with tombstones now present the wipe is treated as
    // in-progress, so the next start retries the removal (idempotent) instead
    // of being refused as stale.
    if (!all_removed) {
        LogPrintf("recovery: REPAIR_FAILED: one or more wipe targets could not be removed; the "
                  "repair is NOT complete, the quarantine sentinel is retained, and the node stays "
                  "quarantined. Fix the underlying disk/permission fault and re-run the repair.\n");
        SetLedgerRepairState("failed");
        return false;
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

    // A full wipe removes the drifted chain-derived state itself, so the
    // persisted quarantine (B2) is resolved by construction: clear the
    // sentinel so the resynced node is not re-quarantined at next start.
    if (scope == "full" && fs::exists(QuarantineSentinelPath())) {
        std::error_code qec;
        fs::remove(QuarantineSentinelPath(), qec);
        LogPrintf("recovery: quarantine sentinel cleared by completed full repair wipe\n");
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
    ExecuteMarkerWipe(marker, /*at_startup=*/false);
}

bool RunStartupRepairTasks()
{
    const fs::path marker = MarkerPath();
    if (fs::exists(marker)) {
        // Crash mid-wipe, or armed on a daemon that was killed instead of
        // stopped: finish the wipe before any DB is opened (6.2.3). Startup
        // rules apply: whitelist/containment validation plus the marker
        // staleness cutoff (a wipe that already began is always finished).
        LogPrintf("recovery: repair marker found at startup; completing wipe before init\n");
        ExecuteMarkerWipe(marker, /*at_startup=*/true);
    }
    // Consume a done-marker from the previous shutdown (state continues in
    // the ledger's repair_state).
    if (fs::exists(MarkerDonePath())) {
        std::error_code dec;
        fs::remove(MarkerDonePath(), dec);
    }
    // Documented escape hatch for the persisted quarantine (B2): an EXPLICIT
    // operator-requested full rebuild (-reindex / -reindex-chainstate /
    // -resetchainstate) reconstructs the drifted caches, so the sentinel is
    // cleared. A plain restart never clears it.
    if (fs::exists(QuarantineSentinelPath()) &&
        (gArgs.GetBoolArg("-reindex", false) || gArgs.GetBoolArg("-reindex-chainstate", false) ||
         gArgs.GetBoolArg("-resetchainstate", false))) {
        std::error_code qec;
        fs::remove(QuarantineSentinelPath(), qec);
        LogPrintf("recovery: quarantine sentinel cleared by explicit operator rebuild flag\n");
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
// Quarantine persistence (B2). Runtime quarantine writes a sentinel in the
// datadir ROOT (outside every wiped directory); at the next start the node
// re-enters a held state (crippled_wait) instead of resuming full duty --
// the runtime DisconnectBlock/ConnectBlock drift conditions are not
// reproducible by the startup tip check, so a plain restart must not be a
// silent quarantine exit. Cleared only by: a completed full repair wipe, a
// verified-healthy repair, or an explicit operator rebuild flag.
// ---------------------------------------------------------------------------
static void WriteQuarantineSentinel(FindingCode code, const std::string& debug_detail)
{
    UniValue json(UniValue::VOBJ);
    json.pushKV("version", 1);
    // Explicit state field: the reader fails CLOSED (treats existence as
    // quarantined) unless it parses cleanly AND finds this set to false. It is
    // only ever written true here; there is no code path that writes false.
    json.pushKV("quarantined", true);
    json.pushKV("ts", GetTime());
    json.pushKV("finding_code", FindingCodeToString(code));
    json.pushKV("debug_detail", debug_detail);
    if (!WriteJsonFile(QuarantineSentinelPath(), json)) {
        LogPrintf("recovery: WARNING: failed to persist quarantine sentinel %s -- quarantine "
                  "will NOT survive a restart\n", fs::PathToString(QuarantineSentinelPath()));
    }
}

static void ClearQuarantineSentinelForVerifiedHealth()
{
    if (!fs::exists(QuarantineSentinelPath())) return;
    std::error_code ec;
    fs::remove(QuarantineSentinelPath(), ec);
    LogPrintf("recovery: quarantine sentinel cleared (verified healthy)\n");
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
    //! Wallet witness-rebuild status, collected WITHOUT m_mutex held (the
    //! query takes cs_wallets/cs_wallet -- lock-order safety, M4).
    WalletWitnessStatus witness;
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
    // Seed the cached guard counters (no contention during construction; the
    // tick refreshes them lock-free from here on).
    m_guard_attempts_used = CountLedgerEntriesInWindow(ledger, "attempts", REPAIR_ATTEMPT_WINDOW_SECS, GetTime());
    m_guard_wipes_in_window = CountLedgerEntriesInWindow(ledger, "wipes", REPAIR_WIPE_WINDOW_SECS, GetTime());
    const std::string repair_state = ledger["repair_state"].isStr() ? ledger["repair_state"].get_str() : "idle";
    if (repair_state == "wiped" || repair_state == "syncing" || repair_state == "rebuilding_witnesses" ||
        repair_state == "verifying") {
        m_repair_in_flight = true;
        m_repair_phase = RepairPhase::SYNCING;
        LogPrintf("recovery: resuming repair tracking (ledger state: %s)\n", repair_state);
    } else if (repair_state == "failed") {
        m_repair_phase = RepairPhase::FAILED;
    }

    // B2 / NF-1 (FAIL CLOSED): a quarantine sentinel from a previous run means
    // that run proved its own state inconsistent at runtime. Re-enter the held
    // state NOW -- gates closed before any subsystem starts -- and have init
    // park the node in crippled_wait (diagnosis over warmup RPC) instead of
    // booting to full duty. A plain restart is never a quarantine exit.
    //
    // The sentinel's mere EXISTENCE is authoritative. The node is quarantined
    // UNLESS the file is absent, OR it parses cleanly to an object that
    // EXPLICITLY declares a healthy (not-quarantined) state (`"quarantined":
    // false`). A truncated / empty / non-object / unreadable / field-missing
    // sentinel -- the classic crash-mid-flush outcome, and a trivial one-byte
    // defeat for anyone with datadir write access -- ASSUMES quarantined. A
    // malformed sentinel must NEVER silently clear quarantine. Parsing is only
    // to ENRICH the finding, never to gate whether we honour it.
    if (fs::exists(QuarantineSentinelPath())) {
        const auto sentinel = ReadJsonFile(QuarantineSentinelPath());
        const bool parsed = sentinel.has_value();
        const bool explicitly_healthy =
            parsed && (*sentinel)["quarantined"].isBool() && !(*sentinel)["quarantined"].get_bool();
        if (!explicitly_healthy) {
            g_quarantined.store(true, std::memory_order_release);
            m_persisted_quarantine = true;
            m_startup_diagnosis = true;
            const std::string code_str =
                parsed && (*sentinel)["finding_code"].isStr() ? (*sentinel)["finding_code"].get_str() : "";
            FindingCode code = FindingCode::DRIFT_EVODB;
            if (code_str == "DRIFT_SAPLING") code = FindingCode::DRIFT_SAPLING;
            else if (code_str == "CHAINSTATE_LOAD_FAILED") code = FindingCode::CHAINSTATE_LOAD_FAILED;
            Finding f;
            f.code = code;
            f.since = parsed && (*sentinel)["ts"].isNum() ? (*sentinel)["ts"].getInt<int64_t>() : GetTime();
            if (parsed) {
                f.debug_detail = "persisted quarantine from a previous run: " +
                                 ((*sentinel)["debug_detail"].isStr() ? (*sentinel)["debug_detail"].get_str() : "");
            } else {
                f.debug_detail = "persisted quarantine sentinel present but UNPARSEABLE "
                                 "(empty/truncated/non-object/unreadable) -- assuming quarantined (fail closed)";
            }
            m_findings.push_back(std::move(f));
            LogPrintf("*** recovery: previous run quarantined itself (%s; sentinel %s); re-entering "
                      "held state. Repair with `repairnode`, or an explicit "
                      "-reindex/-resetchainstate rebuild clears %s\n",
                      FindingCodeToString(code), parsed ? "parsed" : "UNPARSEABLE, fail-closed",
                      fs::PathToString(QuarantineSentinelPath()));
        }
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
    // crippled_wait forever. B4: an ACTIVE quarantine is NEVER erased here --
    // drift raised during the import/connman window must survive
    // init-complete with all gates closed.
    if (IsQuarantined()) {
        m_mode = DaemonMode::QUARANTINED;
    } else if (m_mode == DaemonMode::CRIPPLED_WAIT) {
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

bool RecoveryManager::FindingIsDiskClass(FindingCode code) const
{
    AssertLockHeld(m_mutex);
    for (const Finding& f : m_findings) {
        if (f.code != code) continue;
        for (const auto& [k, v] : f.evidence_num) {
            if (k == "disk_class" && v == 1) return true;
        }
    }
    return false;
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

    // B4: "!init_complete" alone is NOT a safe proxy for "P2P is down".
    // The block-import thread and connman start BEFORE SetInitComplete, so
    // drift raised in that window must pull the full quarantine levers.
    // Only the true pre-P2P phase (chainstate load/verify, before
    // AttachNode wires connman) takes the diagnosis-only crippled_wait
    // path -- there, init itself parks the node before networking exists.
    if (!m_init_complete && !m_connman) {
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
    // B2: persist the quarantine so a plain restart re-enters the held
    // state (the runtime drift conditions are not reproducible at startup).
    WriteQuarantineSentinel(code, debug_detail);
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

void RecoveryManager::RecordStartupLoadFailure(const std::string& load_error_id, const std::string& debug_detail,
                                               bool disk_class)
{
    LOCK(m_mutex);
    Finding f;
    f.code = FindingCode::CHAINSTATE_LOAD_FAILED;
    f.since = GetTime();
    f.evidence_str.emplace_back("load_error", load_error_id);
    // NF-3: a disk/IO/permission load fault must route to ACTION_CHECK_DISK,
    // never to a wipe.
    f.evidence_num.emplace_back("disk_class", disk_class ? 1 : 0);
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

bool RecoveryManager::PersistedQuarantinePending() const
{
    LOCK(m_mutex);
    return m_persisted_quarantine;
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
              "repairnode/stop remain callable; arm a repair with `repairnode` (the daemon then "
              "exits to execute it) or `stop` the node to exit without repairing\n");
    while (!ShutdownRequested()) {
        // An armed repair exits crippled_wait PROMPTLY: there is nothing
        // left to do in this process, and a managing wallet is waiting to
        // relaunch us so the marker-driven wipe (executed in Shutdown())
        // and fresh resync can begin.
        if (WITH_LOCK(m_mutex, return m_repair_phase == RepairPhase::ARMED)) {
            LogPrintf("recovery: crippled_wait: repair armed; initiating clean shutdown to "
                      "execute the repair\n");
            StartShutdown();
            break;
        }
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
    bool repair_in_flight{false};
    {
        LOCK(m_mutex);
        connman = m_connman;
        peerman = m_peerman;
        chainman = m_chainman;
        node = m_node;
        repair_in_flight = m_repair_in_flight;
        want_drift_check = m_repair_in_flight && m_repair_phase == RepairPhase::VERIFYING;
    }
    // Wallet witness status for the repair phase machine. Queried here, with
    // NO recovery lock held, because the query takes cs_wallets/cs_wallet
    // (lock-order invariant: m_mutex is never held across wallet locks, M4).
    if (repair_in_flight) {
        if (const auto query = GetWalletWitnessQuery()) sig.witness = query();
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
        LOCK(cs_main);
        const CBlockIndex* tip = chainman->ActiveTip();
        if (tip) {
            // Only counted as "ran" once the tip was actually evaluated:
            // verified health requires a POSITIVE clean re-check (M5) --
            // a re-check that could not run must never read as clean.
            sig.drift_check_ran = true;
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

// NF-6: verified-health ledger finalization, run with NO m_mutex held.
static void FinalizeVerifiedHealthLedger(int64_t now, int tip_height);

void RecoveryManager::SchedulerTick()
{
    // Ledger IO first, with no lock held (M4).
    RefreshGuardCounts();

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
    bool fire_witness_trigger{false};
    std::string pending_repair_state;       // NF-6: ledger write deferred out of the lock
    bool finalize_verified_health{false};   // NF-6: verified-health finalize deferred
    {
        LOCK(m_mutex);
        if (!sig.attached || !m_init_complete) {
            PublishSnapshot(sig);
            return;
        }
        Classify(sig);
        AdvanceRepairPhases(sig, fire_witness_trigger, pending_repair_state, finalize_verified_health);

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

    // NF-6: repair-phase ledger IO, deferred here so no fsync runs under
    // m_mutex (validation blocks on m_mutex in EnterQuarantine while holding
    // cs_main). The in-memory phase was already updated under the lock, so
    // these writes only persist it.
    if (finalize_verified_health) {
        FinalizeVerifiedHealthLedger(sig.now, sig.tip_height);
        RefreshGuardCounts(); // the reset attempt counters must show immediately
    } else if (!pending_repair_state.empty()) {
        SetLedgerRepairState(pending_repair_state);
    }

    // Wallet witness-rebuild trigger (M4): fired OUTSIDE m_mutex -- it takes
    // cs_wallet (and joins a rebuild thread), which must never nest inside
    // the recovery lock (cs_main -> m_mutex -> cs_wallet would close a
    // three-way cycle with validation's EnterQuarantine).
    if (fire_witness_trigger) {
        if (const auto trigger = GetWalletWitnessTrigger()) trigger();
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
        // M-scheduler-block: the L1 probe does blocking DNS resolution and a
        // TCP dial with a multi-second timeout. That work runs on a detached
        // worker thread writing into a shared slot; this (CScheduler) thread
        // only launches the probe and applies a completed result -- it never
        // blocks on DNS or a dial.
        const int state = m_probe_state->load(std::memory_order_acquire);
        if (state == 1) break; // probe in flight; check again next tick
        if (state == 2 || state == 3) {
            const bool link_ok = state == 2;
            m_probe_state->store(0, std::memory_order_release);
            LOCK(m_mutex);
            m_next_link_probe_time = GetTime() + LINK_PROBE_BACKOFF_SECS;
            if (link_ok) {
                ClearFinding(FindingCode::NET_LOCAL_LINK_DOWN);
                if (m_ladder_stage == 1) {
                    m_ladder_stage = 2;
                    LogPrintf("recovery: L1 link probe ok; advancing to L2 rotation\n");
                }
            } else {
                // 3.1: both probes failed -- our link is down; no peer action
                // can help. Surface and re-probe on backoff.
                Finding f;
                f.code = FindingCode::NET_LOCAL_LINK_DOWN;
                f.since = GetTime();
                f.debug_detail = "DNS seed resolution and TCP dial to fixed seeds both failed";
                UpsertFinding(FindingCode::NET_LOCAL_LINK_DOWN, std::move(f));
            }
            break;
        }
        LaunchLinkProbe();
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

//! 3.1 L1 probe body: distinguish "our link is down" from "the peers are
//! gone". Runs on a detached worker thread (blocking DNS + a bounded TCP
//! dial); touches nothing but its by-value arguments and the shared result
//! slot, so it is safe even if it outlives the manager. Nothing to probe
//! against on chains without seeds (regtest): treat the link as usable so
//! the ladder proceeds.
static void RunLinkProbeWorker(std::vector<std::string> dns_seeds, uint16_t default_port,
                               std::shared_ptr<std::atomic<int>> result)
{
    bool have_target{false};
    bool link_ok{false};
    // DNS-resolve up to two seed names (resolved ONCE; a successful
    // resolution alone proves the local link + resolver work).
    for (size_t i = 0; i < dns_seeds.size() && i < 2 && !link_ok; ++i) {
        have_target = true;
        const std::vector<CNetAddr> addrs = LookupHost(dns_seeds[i], /*nMaxSolutions=*/4, /*fAllowLookup=*/true);
        if (!addrs.empty()) {
            link_ok = true;
            // Confirm reachability with one bounded TCP dial; resolution
            // already proved the link, so a failed dial does not undo it.
            const CService dest{addrs[0], default_port};
            (void)ConnectDirectly(dest, /*manual_connection=*/false);
        }
    }
    if (!have_target) link_ok = true;
    result->store(link_ok ? 2 : 3, std::memory_order_release);
}

void RecoveryManager::LaunchLinkProbe()
{
    int expected{0};
    if (!m_probe_state->compare_exchange_strong(expected, 1, std::memory_order_acq_rel)) return;
    std::vector<std::string> seeds;
    for (const auto& seed : Params().DNSSeeds()) {
        seeds.push_back(seed);
        if (seeds.size() >= 2) break;
    }
    std::thread(RunLinkProbeWorker, std::move(seeds), Params().GetDefaultPort(), m_probe_state).detach();
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

void RecoveryManager::AdvanceRepairPhases(const Signals& sig, bool& fire_witness_trigger,
                                          std::string& pending_repair_state, bool& finalize_verified_health)
{
    AssertLockHeld(m_mutex);
    fire_witness_trigger = false;
    pending_repair_state.clear();
    finalize_verified_health = false;
    if (!m_repair_in_flight) return;

    if (sig.ibd) {
        if (m_repair_phase != RepairPhase::SYNCING) {
            m_repair_phase = RepairPhase::SYNCING;
            pending_repair_state = "syncing"; // NF-6: deferred out of the lock
        }
        return;
    }

    // Post-IBD: the explicit Sapling witness stage (6.4). The wallet is
    // preserved, not untouched: per-note witnesses were built against the
    // pre-wipe chain and must be rebuilt before shielded funds are spendable.
    // The status was collected by CollectSignals WITHOUT m_mutex held, and
    // the trigger is fired by the tick AFTER m_mutex is released (M4: the
    // wallet hooks take cs_wallets/cs_wallet, which must never nest inside
    // this lock).
    const WalletWitnessStatus& wit = sig.witness;
    if (wit.have_wallet) {
        if (!m_witness_stage_triggered) {
            m_witness_stage_triggered = true;
            // Forces detection + rebuild even under
            // -noautorebuildsaplingwitnesses (6.4.b). Fired by the caller
            // outside m_mutex.
            fire_witness_trigger = true;
            m_repair_phase = RepairPhase::REBUILDING_WITNESSES;
            pending_repair_state = "rebuilding_witnesses"; // NF-6: deferred
            return;
        }
        if (wit.rebuild_active || wit.check_pending) {
            if (m_repair_phase != RepairPhase::REBUILDING_WITNESSES) {
                m_repair_phase = RepairPhase::REBUILDING_WITNESSES;
                pending_repair_state = "rebuilding_witnesses"; // NF-6: deferred
            }
            return;
        }
    }

    if (m_repair_phase != RepairPhase::VERIFYING && m_repair_phase != RepairPhase::DONE) {
        m_repair_phase = RepairPhase::VERIFYING;
        m_verify_start_height = sig.tip_height;
        pending_repair_state = "verifying"; // NF-6: deferred
        return;
    }

    if (m_repair_phase == RepairPhase::VERIFYING) {
        // Verified health: a POSITIVE clean drift re-check (M5: a re-check
        // that did not actually run must FAIL this test, never pass it) AND
        // the tip advanced since verification began AND no active findings.
        // Only then do the guard counters reset (6.6: "counter resets only
        // on verified health").
        const bool drift_clean = sig.drift_check_ran && sig.drift_ok;
        const bool tip_advanced = sig.tip_height > m_verify_start_height;
        if (drift_clean && tip_advanced && m_findings.empty()) {
            m_repair_phase = RepairPhase::DONE;
            m_repair_in_flight = false;
            // NF-6: the verified-health ledger reset (+ sentinel clear + log) is
            // deferred out of the lock; m_repair_in_flight is already false so
            // the next tick will not re-enter this branch.
            finalize_verified_health = true;
        } else if (sig.drift_check_ran && !sig.drift_ok) {
            m_repair_phase = RepairPhase::FAILED;
            m_repair_in_flight = false;
            pending_repair_state = "failed"; // NF-6: deferred
            LogPrintf("recovery: repair FAILED verification: consistency drift re-detected after "
                      "resync\n");
        }
    }
}

//! Perform the verified-health ledger finalization (NF-6): run with NO m_mutex
//! held. Resets the attempt counters, marks the repair done, and clears any
//! persisted quarantine sentinel.
static void FinalizeVerifiedHealthLedger(int64_t now, int tip_height)
{
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
    out.pushKV("repair_state_ts", now);
    out.pushKV("health_verified_ts", now);
    WriteLedger(out);
    // Verified healthy: any persisted quarantine is resolved (B2).
    ClearQuarantineSentinelForVerifiedHealth();
    LogPrintf("recovery: repair complete and health verified at height %d; attempt "
              "counters reset\n", tip_height);
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
        bool mark_failed{false};
        {
            LOCK(m_mutex);
            // M6: a REFUSAL must not clobber an in-flight repair's phase state /
            // ledger -- doing so skips the witness-rebuild stage after restart.
            // Only mark FAILED when no repair is actually running.
            if (!m_repair_in_flight) {
                m_repair_phase = RepairPhase::FAILED;
                mark_failed = true;
            }
            Signals sig;
            sig.now = now;
            PublishSnapshot(sig);
        }
        // NF-6: ledger fsync outside m_mutex.
        if (mark_failed) SetLedgerRepairState("failed");
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
    // The EXECUTOR derives its wipe set from scope + this flag against the
    // hard-coded whitelist (B1); the wipe_dirs/wipe_files arrays below are
    // written for transparency and are validated (never trusted) on read.
    marker.pushKV("include_network_state", !network_scope && network_class);
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

    RefreshGuardCounts(); // the attempt just recorded must show immediately
    {
        LOCK(m_mutex);
        m_repair_phase = RepairPhase::ARMED;
        ClearFinding(FindingCode::REPAIR_RATE_LIMITED);
        Signals sig;
        sig.now = now;
        PublishSnapshot(sig);
    }
    LogPrintf("recovery: repair ARMED (scope=%s, reason=%s); wipe executes at shutdown; "
              "`repairnode {disarm:true}` cancels it before then\n",
              network_scope ? "network" : "full", reason);
    return ArmResult::ARMED;
}

bool RecoveryManager::RepairDisarm()
{
    // M-armed-irrevocable: the one in-band undo. Removing the marker before
    // the next shutdown means NO wipe executes -- an accidental arm is no
    // longer an unavoidable wipe on the next stop/crash/reboot.
    const fs::path marker = MarkerPath();
    bool cleared{false};
    if (fs::exists(marker)) {
        std::error_code ec;
        fs::remove(marker, ec);
        if (ec) {
            LogPrintf("recovery: ERROR: failed to remove repair marker on disarm: %s\n", ec.message());
            return false;
        }
        cleared = true;
    }
    // NF-8: do NOT reset repair_state to "idle" while a repair is in flight
    // (wiped/syncing/rebuilding_witnesses/verifying). Disarm cancels a fresh
    // (mistaken) ARM; if an EARLIER repair is still resyncing, clobbering its
    // ledger state to "idle" would strand it (the ctor would not resume
    // tracking on the next restart and the witness-rebuild stage would be
    // skipped). Preserve the existing repair_state in that case; only drop the
    // attempt slot the cancelled arm consumed.
    bool in_flight{false};
    {
        LOCK(m_mutex);
        in_flight = m_repair_in_flight;
    }
    if (cleared) {
        // A cancelled arm performed no wipe and no restart, so it must not
        // consume a slot in the 3-attempts-per-6h loop guard: drop the
        // attempt this arm recorded. The wipe-rate guard is never touched
        // (only COMPLETED wipes feed it), so nothing destructive is
        // forgotten by a disarm.
        UniValue ledger = ReadLedger();
        const std::string existing_state =
            ledger["repair_state"].isStr() ? ledger["repair_state"].get_str() : "idle";
        const std::string new_state = in_flight ? existing_state : "idle";
        UniValue attempts = ledger["attempts"];
        if (attempts.isArray() && attempts.size() > 0) {
            UniValue kept(UniValue::VARR);
            for (size_t i = 0; i + 1 < attempts.size(); ++i) kept.push_back(attempts[i]);
            UniValue out(UniValue::VOBJ);
            for (const auto& key : ledger.getKeys()) {
                if (key != "attempts" && key != "repair_state" && key != "repair_state_ts") {
                    out.pushKV(key, ledger[key]);
                }
            }
            out.pushKV("attempts", kept);
            out.pushKV("repair_state", new_state);
            out.pushKV("repair_state_ts", GetTime());
            WriteLedger(out);
        } else if (!in_flight) {
            SetLedgerRepairState("idle");
        }
        RefreshGuardCounts(); // the released attempt slot must show immediately
    }
    LOCK(m_mutex);
    if (m_repair_phase == RepairPhase::ARMED) {
        m_repair_phase = RepairPhase::NONE;
        cleared = true;
    }
    if (cleared) {
        LogPrintf("recovery: repair DISARMED; the marker was removed and no wipe will execute\n");
        Signals sig;
        sig.now = GetTime();
        PublishSnapshot(sig);
    }
    return cleared;
}

// ---- snapshot publication ----

void RecoveryManager::PublishSnapshot(const Signals& sig)
{
    AssertLockHeld(m_mutex);
    StatusSnapshot snap;

    // daemon_mode discriminator (7.4). crippled_wait wins over quarantined:
    // a persisted quarantine parks the restarted node in crippled_wait (B2),
    // and front-ends key their startup-repair flows off that id -- both
    // states are equally "held / not serving".
    if (m_mode == DaemonMode::CRIPPLED_WAIT) {
        snap.daemon_mode = DaemonMode::CRIPPLED_WAIT;
    } else if (IsQuarantined()) {
        snap.daemon_mode = DaemonMode::QUARANTINED;
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
    // NF-3: a disk/IO/permission-class chainstate-load failure must route to
    // ACTION_CHECK_DISK, NEVER a wipe -- wiping cannot fix a bad disk and risks
    // the operator nuking recoverable data on failing hardware. Only genuine
    // logical corruption (drift, or a non-disk load failure) offers the wipe.
    if (FindingIsDiskClass(FindingCode::CHAINSTATE_LOAD_FAILED)) {
        snap.recommended_action = RecommendedAction::ACTION_CHECK_DISK;
    } else if (HasFinding(FindingCode::DRIFT_EVODB) || HasFinding(FindingCode::DRIFT_SAPLING) ||
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

    // Guard counters come from the cached values refreshed OUTSIDE this lock
    // (M4: ReadLedger() is filesystem IO, and quarantine entry -- holding
    // cs_main -- waits on m_mutex; no tick may do disk IO while holding it).
    snap.attempts_used = m_guard_attempts_used;
    snap.attempts_max = REPAIR_ATTEMPTS_MAX;
    snap.wipes_in_window = m_guard_wipes_in_window;
    snap.wipes_max = REPAIR_WIPES_MAX;

    m_snapshot = std::move(snap);
}

void RecoveryManager::RefreshGuardCounts()
{
    const int64_t now = GetTime();
    const UniValue ledger = ReadLedger(); // file IO, deliberately lock-free
    const int attempts = CountLedgerEntriesInWindow(ledger, "attempts", REPAIR_ATTEMPT_WINDOW_SECS, now);
    const int wipes = CountLedgerEntriesInWindow(ledger, "wipes", REPAIR_WIPE_WINDOW_SECS, now);
    LOCK(m_mutex);
    m_guard_attempts_used = attempts;
    m_guard_wipes_in_window = wipes;
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
