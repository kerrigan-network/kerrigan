// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RECOVERY_RECOVERY_H
#define BITCOIN_RECOVERY_RECOVERY_H

#include <fs.h>
#include <recovery/witnesshook.h>
#include <sync.h>
#include <uint256.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

class ArgsManager;
class CConnman;
class CMasternodeSync;
class CScheduler;
class ChainstateManager;
class PeerManager;

namespace node {
struct NodeContext;
} // namespace node

/**
 * Self-heal / auto-rejoin subsystem (WS-HEAL v2).
 *
 * Owns: signal collection, health classification, the automatic (silent,
 * non-destructive) network-recovery ladder, runtime quarantine on
 * consistency-drift, and the guided (user-confirmed, destructive)
 * wipe+resync repair protocol. State is exposed exclusively through the
 * `getrecoverystatus` / `repairnode` RPC contract (contract_version 2):
 * stable snake_case identifiers and machine fields only -- the daemon never
 * mints display English (front-ends localize off the ids).
 */
namespace recovery {

/** Contract version reported in every getrecoverystatus/repairnode response. */
static constexpr int RECOVERY_CONTRACT_VERSION{2};

//! daemon_mode discriminator (contract v2 7.4). Stable wire ids.
enum class DaemonMode {
    STARTING,      //!< normal init, pre-warmup-finished
    SYNCING,       //!< IBD
    NORMAL,        //!< healthy
    DEGRADED,      //!< auto-engine parked or non-network stall surfaced
    QUARANTINED,   //!< runtime consistency-drift quarantine (5)
    CRIPPLED_WAIT, //!< startup diagnosis published, init parked pre-warmup (5.3)
    REPAIR_ARMED,  //!< repair marker written, awaiting restart
};

//! Finding codes (contract v2 7.2). Stable wire ids; front-ends must
//! tolerate unknown values.
enum class FindingCode {
    NET_LOCAL_LINK_DOWN,
    NET_ISOLATED,
    NET_ECLIPSE_SUSPECT,
    TIP_STALLED_NETWORK,
    TIP_STALLED_NONNETWORK,
    DRIFT_EVODB,
    DRIFT_SAPLING,
    WITNESS_STALE,
    REPAIR_RATE_LIMITED,
    CHAINSTATE_LOAD_FAILED, //!< startup chainstate load/verify failure (crippled_wait)
    NODE_ABORTED,           //!< previous run AbortNode'd; evidence carries the reason
};

//! recommended_action ids (contract v2 7.2).
enum class RecommendedAction {
    ACTION_NONE,
    ACTION_WAIT_AUTO,
    ACTION_GUIDED_NETWORK_REPAIR,
    ACTION_GUIDED_REPAIR,
    ACTION_DIAGNOSE_SUPPORT,
    ACTION_CHECK_DISK,
    ACTION_MANAGE_NODE_ELSEWHERE,
};

//! repair.phase ids (contract v2 6.3/7.2).
enum class RepairPhase {
    NONE,
    ARMED,
    SHUTTING_DOWN,
    WIPING,
    BOOTSTRAPPING, // wallet-managed only; never set by the daemon itself
    SYNCING,
    REBUILDING_WITNESSES,
    VERIFYING,
    DONE,
    FAILED,
};

//! Why quarantine was entered (5.1: the three converted drift sites +
//! the startup variants).
enum class QuarantineReason {
    DRIFT_EVODB_DISCONNECT,
    DRIFT_SAPLING_DISCONNECT,
    DRIFT_EVODB_CONNECT,
    STARTUP_DRIFT,
    STARTUP_LOAD_FAILED,
};

const char* DaemonModeToString(DaemonMode mode);
const char* FindingCodeToString(FindingCode code);
const char* RecommendedActionToString(RecommendedAction action);
const char* RepairPhaseToString(RepairPhase phase);

/**
 * Global quarantine flag (5.2). One-way for the process lifetime; the only
 * exits are guided repair (restart) or operator shutdown. Checked at every
 * duty entry point: block-template assembly, MN duty tick, DKG participation,
 * ChainLock/InstantSend signing, HMP seal sign/broadcast, sendrawtransaction,
 * and re-enabling networking.
 */
extern std::atomic<bool> g_quarantined;

inline bool IsQuarantined()
{
    return g_quarantined.load(std::memory_order_acquire);
}

/** One machine-readable finding with evidence fields (contract v2 7.2). */
struct Finding {
    FindingCode code;
    int64_t since{0};
    //! evidence: machine fields only. debug_detail is explicitly
    //! not-for-display (logs / bug reports).
    std::vector<std::pair<std::string, std::string>> evidence_str;
    std::vector<std::pair<std::string, int64_t>> evidence_num;
    std::string debug_detail;
};

/** Plain-data snapshot backing getrecoverystatus. Deliberately holds no
 *  pointers into chainstate/wallet/net so the warmup-callable RPC handler
 *  can serialize it without touching any un-initialized subsystem (7.5). */
struct StatusSnapshot {
    DaemonMode daemon_mode{DaemonMode::STARTING};
    std::vector<Finding> findings;
    RecommendedAction recommended_action{RecommendedAction::ACTION_NONE};
    // auto (ladder) block
    int ladder_stage{0};
    int cycles_used{0};
    int cycles_max{3};
    int64_t window_resets{0};
    // sync block
    int height{0};
    int target_height{0};
    double progress{0.0};
    int64_t tip_age_secs{0};
    int64_t expected_spacing_secs{120};
    // repair block
    RepairPhase repair_phase{RepairPhase::NONE};
    int64_t bytes_wiped{0};
    int64_t bytes_total_est{0};
    int64_t witnesses_rebuilt{0};
    int64_t witnesses_total{0};
    std::optional<int64_t> eta_secs; // only when cheap to derive; never fabricated
    // guards block
    int attempts_used{0};
    int attempts_max{3};
    int wipes_in_window{0};
    int wipes_max{2};
};

/** Result of a repairnode dry-run (7.3). */
struct RepairPlan {
    std::vector<std::string> wipe_dirs;   // relative labels ("blocks", "chainstate", ...)
    std::vector<std::string> wipe_files;  // relative file names
    std::vector<std::string> preserved;   // labels only, for display mapping
    int64_t bytes_total_est{0};
    std::string confirm_token; // one-time, 5-minute TTL
    // guard state at dry-run time
    int attempts_used{0};
    int wipes_in_window{0};
    bool rate_limited{false};
};

/** Outcome ids for repairnode arming. Stable wire ids. */
enum class ArmResult {
    ARMED,
    BAD_TOKEN,          // unknown/expired confirm token
    ATTEMPTS_EXHAUSTED, // 3 attempts / 6 h loop guard (6.6.1)
    RATE_LIMITED,       // 2 wipes / 7 d wipe-rate guard (6.6.2)
    ALREADY_ARMED,
};

class RecoveryManager
{
public:
    RecoveryManager();
    ~RecoveryManager();

    //! Wire live subsystem pointers once they exist (after connman/peerman
    //! construction). Until attached, ticks are no-ops and quarantine only
    //! records diagnosis.
    void AttachNode(node::NodeContext& node) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    //! Drop subsystem pointers (called from PrepareShutdown before the
    //! pointed-to objects are destroyed).
    void DetachNode() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    //! Mark init finished (warmup cleared). Pre-init quarantine requests
    //! become crippled_wait; post-init ones become runtime quarantine.
    void SetInitComplete() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Periodic diagnosis + auto-engine tick; scheduled on the main
    //! CScheduler. Collects signals (may take cs_main), classifies, and runs
    //! the isolation ladder / stall rotation. Lock order: NEVER holds m_mutex
    //! while acquiring cs_main (validation calls EnterQuarantine with cs_main
    //! held, taking m_mutex).
    void SchedulerTick() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Enter quarantine (5.2) or, pre-init, record the diagnosis for the
    //! crippled_wait startup path (5.3). Safe to call with cs_main held.
    void EnterQuarantine(QuarantineReason reason, const std::string& debug_detail)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Record a startup chainstate-load failure (feeds CHAINSTATE_LOAD_FAILED
    //! + crippled_wait).
    void RecordStartupLoadFailure(const std::string& load_error_id, const std::string& debug_detail)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Whether startup diagnosis requested crippled_wait (drift or load
    //! failure recorded before init completed).
    [[nodiscard]] bool StartupDiagnosisPending() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Park the init thread in crippled_wait: RPC (warmup-callable subset)
    //! serves diagnosis until shutdown is requested (typically by
    //! `repairnode {shutdown:true}`). Returns when shutdown is requested.
    void RunCrippledWait() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Suppression hook: the built-in per-peer stall eviction fired; our T1
    //! rotation must stand down for the suppression window (2.2).
    void NoteBuiltinStallEviction();

    [[nodiscard]] StatusSnapshot GetStatusSnapshot() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! repairnode {dry_run:true}: compute the wipe plan + mint a one-time
    //! confirm token (5-min TTL).
    [[nodiscard]] RepairPlan RepairDryRun(const std::string& scope) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    //! repairnode {confirm_token,...}: validate guards, write the marker
    //! atomically (6.2). Does NOT initiate shutdown itself.
    [[nodiscard]] ArmResult RepairArm(const std::string& confirm_token, const std::string& scope,
                                      bool override_rate_limit)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    mutable Mutex m_mutex;

    // ---- wired subsystems (null until AttachNode / after DetachNode) ----
    CConnman* m_connman GUARDED_BY(m_mutex){nullptr};
    PeerManager* m_peerman GUARDED_BY(m_mutex){nullptr};
    ChainstateManager* m_chainman GUARDED_BY(m_mutex){nullptr};
    CMasternodeSync* m_mn_sync GUARDED_BY(m_mutex){nullptr};
    CScheduler* m_scheduler GUARDED_BY(m_mutex){nullptr};
    node::NodeContext* m_node GUARDED_BY(m_mutex){nullptr};

    bool m_init_complete GUARDED_BY(m_mutex){false};
    bool m_startup_diagnosis GUARDED_BY(m_mutex){false};
    bool m_selfheal_enabled GUARDED_BY(m_mutex){true};

    // ---- published diagnosis ----
    std::vector<Finding> m_findings GUARDED_BY(m_mutex);
    DaemonMode m_mode GUARDED_BY(m_mutex){DaemonMode::STARTING};
    StatusSnapshot m_snapshot GUARDED_BY(m_mutex); // last published snapshot

    // ---- signal state (tick-local aggregation) ----
    int64_t m_last_tip_advance_time GUARDED_BY(m_mutex){0};
    int m_last_tip_height GUARDED_BY(m_mutex){-1};
    int64_t m_expected_spacing GUARDED_BY(m_mutex){120};
    int m_zero_peer_ticks GUARDED_BY(m_mutex){0};

    // ---- auto-engine (isolation ladder) state ----
    int m_ladder_stage GUARDED_BY(m_mutex){0}; // 0=idle 1=L1 2=L2 3=L3
    int m_l2_failures GUARDED_BY(m_mutex){0};
    int m_full_cycles GUARDED_BY(m_mutex){0};
    int m_cycles_used GUARDED_BY(m_mutex){0};        // loop guard (3.5)
    int64_t m_cycle_window_start GUARDED_BY(m_mutex){0};
    bool m_ladder_parked GUARDED_BY(m_mutex){false};
    int64_t m_last_rotation_time GUARDED_BY(m_mutex){0};
    int64_t m_next_link_probe_time GUARDED_BY(m_mutex){0};

    // built-in stall-eviction suppression (2.2); written from the message
    // handler thread, read by the tick.
    std::atomic<int64_t> m_last_builtin_stall_eviction{0};

    // ---- repair state ----
    RepairPhase m_repair_phase GUARDED_BY(m_mutex){RepairPhase::NONE};
    std::string m_confirm_token GUARDED_BY(m_mutex);
    int64_t m_confirm_token_expiry GUARDED_BY(m_mutex){0};
    std::string m_confirm_token_scope GUARDED_BY(m_mutex);
    int64_t m_plan_bytes_est GUARDED_BY(m_mutex){0};
    bool m_repair_in_flight GUARDED_BY(m_mutex){false}; // wipe done, resync running
    int64_t m_verify_start_height GUARDED_BY(m_mutex){-1};
    bool m_witness_stage_triggered GUARDED_BY(m_mutex){false};

    // ---- helpers ----
    struct Signals; // tick-local plain-data signal collection
    Signals CollectSignals();
    void Classify(const Signals& sig) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void AdvanceRepairPhases(const Signals& sig) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void PublishSnapshot(const Signals& sig) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void UpsertFinding(FindingCode code, Finding&& f) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void ClearFinding(FindingCode code) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool HasFinding(FindingCode code) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void RotateOutbounds(const std::string& why) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool ProbeLocalLink() const;
};

/** The process-wide recovery manager. Created early in AppInitMain (before
 *  chainstate load so startup diagnosis has somewhere to live); reset at the
 *  end of Shutdown() after the marker-driven wipe has executed. */
extern std::unique_ptr<RecoveryManager> g_recovery;

// ---- free functions usable without (or before/after) the manager ----

/** Quarantine entry usable from validation (safe with cs_main held). Routes
 *  to the manager when it exists; otherwise records pre-init diagnosis. */
void EnterQuarantine(QuarantineReason reason, const std::string& debug_detail);

/** net_processing hook: the built-in block-stalling eviction disconnected a
 *  peer; suppress our T1 rotation for the anti-double-eviction window. */
void NoteBuiltinStallEviction();

/** Best-effort persistence of an AbortNode reason so the NEXT start can
 *  surface NODE_ABORTED / ACTION_CHECK_DISK (C2 handling). Never throws. */
void RecordAbortReason(const std::string& reason);

/** Whether this process parked in crippled_wait and was released by an
 *  operator/front-end shutdown request. Callers use it to report an orderly
 *  exit (EXIT_SUCCESS) for an intentional repair rather than a startup crash. */
[[nodiscard]] bool CrippledWaitWasReleased();

/** Startup (pre-DB-open): finish any interrupted marker-driven wipe, sweep
 *  leftover rename-tombstones, and consume a marker left by a headless
 *  restart. Returns false only on unrecoverable filesystem errors. */
bool RunStartupRepairTasks();

/** Shutdown-ordered wipe (6.2): executed from Shutdown() after every DB has
 *  been flushed and closed. Rename-then-unlink so the datadir reaches the
 *  bootstrap-triggering state in O(1); marker consumed by rename. */
void ExecuteShutdownWipe();

/** Post-load startup drift check (5.3/5.4): mirrors each DB's best-block
 *  semantics (EvoDB missing key == inconsistent, gated on DIP3-active;
 *  SaplingDB missing key == fresh == consistent). On drift records
 *  crippled_wait diagnosis and returns false. */
bool StartupDriftCheck(node::NodeContext& node);

} // namespace recovery

#endif // BITCOIN_RECOVERY_RECOVERY_H
