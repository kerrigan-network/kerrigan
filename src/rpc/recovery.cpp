// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <evo/chainhelper.h>
#include <evo/evodb.h>
#include <node/context.h>
#include <sapling/sapling_state.h>
#include <random.h>
#include <recovery/recovery.h>
#include <rpc/protocol.h>
#include <rpc/register.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <shutdown.h>
#include <univalue.h>

using node::NodeContext;

// The recovery RPC contract (WS-HEAL v2 7): machine-readable identifiers and
// machine fields ONLY. No response field is display prose; front-ends own all
// human copy, keyed off the stable ids (Qt via tr(), the Electron wallet via
// its locale files, kerrigan-cli via its own English table). `debug_detail`
// is explicitly not-for-display (logs / bug reports).
//
// Both handlers are registered warmup-callable (7.5) and therefore MUST NOT
// touch cs_main, the wallet, or any chainstate pointer: they read only the
// recovery module's plain-data snapshot and filesystem-backed ledger/marker
// state, which exist before any subsystem is initialized.

static UniValue SnapshotToJSON(const recovery::StatusSnapshot& snap)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("contract_version", recovery::RECOVERY_CONTRACT_VERSION);
    result.pushKV("daemon_mode", recovery::DaemonModeToString(snap.daemon_mode));

    UniValue findings(UniValue::VARR);
    for (const recovery::Finding& f : snap.findings) {
        UniValue jf(UniValue::VOBJ);
        jf.pushKV("code", recovery::FindingCodeToString(f.code));
        jf.pushKV("since", f.since);
        UniValue evidence(UniValue::VOBJ);
        for (const auto& [key, value] : f.evidence_str) evidence.pushKV(key, value);
        for (const auto& [key, value] : f.evidence_num) evidence.pushKV(key, value);
        jf.pushKV("evidence", evidence);
        jf.pushKV("debug_detail", f.debug_detail);
        findings.push_back(jf);
    }
    result.pushKV("findings", findings);
    result.pushKV("recommended_action", recovery::RecommendedActionToString(snap.recommended_action));

    UniValue auto_block(UniValue::VOBJ);
    auto_block.pushKV("ladder_stage", snap.ladder_stage);
    auto_block.pushKV("cycles_used", snap.cycles_used);
    auto_block.pushKV("cycles_max", snap.cycles_max);
    auto_block.pushKV("window_resets", snap.window_resets);
    result.pushKV("auto", auto_block);

    UniValue sync(UniValue::VOBJ);
    sync.pushKV("height", snap.height);
    sync.pushKV("target_height", snap.target_height);
    sync.pushKV("progress", snap.progress);
    sync.pushKV("tip_age_secs", snap.tip_age_secs);
    sync.pushKV("expected_spacing_secs", snap.expected_spacing_secs);
    result.pushKV("sync", sync);

    UniValue repair(UniValue::VOBJ);
    repair.pushKV("phase", recovery::RepairPhaseToString(snap.repair_phase));
    repair.pushKV("bytes_wiped", snap.bytes_wiped);
    repair.pushKV("bytes_total_est", snap.bytes_total_est);
    repair.pushKV("witnesses_rebuilt", snap.witnesses_rebuilt);
    repair.pushKV("witnesses_total", snap.witnesses_total);
    if (snap.eta_secs) {
        repair.pushKV("eta_secs", *snap.eta_secs);
    } else {
        repair.pushKV("eta_secs", UniValue{UniValue::VNULL});
    }
    result.pushKV("repair", repair);

    UniValue guards(UniValue::VOBJ);
    guards.pushKV("attempts_used", snap.attempts_used);
    guards.pushKV("attempts_max", snap.attempts_max);
    guards.pushKV("wipes_in_window", snap.wipes_in_window);
    guards.pushKV("wipes_max", snap.wipes_max);
    result.pushKV("guards", guards);

    return result;
}

static RPCHelpMan getrecoverystatus()
{
    return RPCHelpMan{"getrecoverystatus",
        "\nReturns the node's self-heal / recovery status (contract v2).\n"
        "All fields are stable machine identifiers; front-ends own the human-readable copy.\n"
        "Callable during RPC warmup (including crippled_wait startup diagnosis).\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "contract_version", "recovery contract version (2)"},
                {RPCResult::Type::STR, "daemon_mode", "starting|syncing|normal|degraded|quarantined|crippled_wait|repair_armed"},
                {RPCResult::Type::ARR, "findings", "active findings",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "code", "stable finding id (e.g. NET_ISOLATED, DRIFT_EVODB)"},
                        {RPCResult::Type::NUM_TIME, "since", "finding onset (unix time)"},
                        {RPCResult::Type::OBJ_DYN, "evidence", "machine evidence fields (per code)",
                        {
                            {RPCResult::Type::ELISION, "", "code-specific machine fields"},
                        }},
                        {RPCResult::Type::STR, "debug_detail", "free-form, NOT for display (logs/bug reports only)"},
                    }},
                }},
                {RPCResult::Type::STR, "recommended_action", "ACTION_NONE|ACTION_WAIT_AUTO|ACTION_GUIDED_NETWORK_REPAIR|ACTION_GUIDED_REPAIR|ACTION_DIAGNOSE_SUPPORT|ACTION_CHECK_DISK|ACTION_MANAGE_NODE_ELSEWHERE"},
                {RPCResult::Type::OBJ, "auto", "automatic (non-destructive) engine state",
                {
                    {RPCResult::Type::NUM, "ladder_stage", "0=idle 1=L1 2=L2 3=L3"},
                    {RPCResult::Type::NUM, "cycles_used", "ladder cycles used in the current window"},
                    {RPCResult::Type::NUM, "cycles_max", "loop-guard maximum per window"},
                    {RPCResult::Type::NUM_TIME, "window_resets", "when the loop-guard window resets (0 if idle)"},
                }},
                {RPCResult::Type::OBJ, "sync", "chain progress fields",
                {
                    {RPCResult::Type::NUM, "height", "active tip height"},
                    {RPCResult::Type::NUM, "target_height", "best peer-advertised height"},
                    {RPCResult::Type::NUM, "progress", "height/target_height in [0,1]"},
                    {RPCResult::Type::NUM, "tip_age_secs", "seconds since the tip block's timestamp"},
                    {RPCResult::Type::NUM, "expected_spacing_secs", "observed-cadence expected block spacing"},
                }},
                {RPCResult::Type::OBJ, "repair", "guided-repair progress",
                {
                    {RPCResult::Type::STR, "phase", "none|armed|shutting_down|wiping|bootstrapping|syncing|rebuilding_witnesses|verifying|done|failed"},
                    {RPCResult::Type::NUM, "bytes_wiped", ""},
                    {RPCResult::Type::NUM, "bytes_total_est", ""},
                    {RPCResult::Type::NUM, "witnesses_rebuilt", "0 when unknown"},
                    {RPCResult::Type::NUM, "witnesses_total", "0 when unknown"},
                    {RPCResult::Type::NUM, "eta_secs", "null unless cheaply derivable (never fabricated)"},
                }},
                {RPCResult::Type::OBJ, "guards", "repair loop/wipe-rate guard state",
                {
                    {RPCResult::Type::NUM, "attempts_used", "repair attempts in the rolling 6 h window"},
                    {RPCResult::Type::NUM, "attempts_max", ""},
                    {RPCResult::Type::NUM, "wipes_in_window", "completed wipes in the rolling 7 d window"},
                    {RPCResult::Type::NUM, "wipes_max", ""},
                }},
            }},
        RPCExamples{
            HelpExampleCli("getrecoverystatus", "")
          + HelpExampleRpc("getrecoverystatus", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Warmup-callable: touch ONLY the recovery module's snapshot (7.5.b).
    if (!recovery::g_recovery) {
        recovery::StatusSnapshot snap; // daemon_mode: "starting"
        return SnapshotToJSON(snap);
    }
    return SnapshotToJSON(recovery::g_recovery->GetStatusSnapshot());
},
    };
}

static const char* ArmResultToString(recovery::ArmResult res)
{
    switch (res) {
    case recovery::ArmResult::ARMED: return "ARMED";
    case recovery::ArmResult::BAD_TOKEN: return "BAD_TOKEN";
    case recovery::ArmResult::ATTEMPTS_EXHAUSTED: return "ATTEMPTS_EXHAUSTED";
    case recovery::ArmResult::RATE_LIMITED: return "REPAIR_RATE_LIMITED";
    case recovery::ArmResult::ALREADY_ARMED: return "ALREADY_ARMED";
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

static RPCHelpMan repairnode()
{
    return RPCHelpMan{"repairnode",
        "\nGuided node repair (contract v2). Never runs silently: a dry_run call returns the wipe\n"
        "plan and a one-time confirm_token (5 minute TTL); a second call carrying the token arms\n"
        "the repair by writing a marker that is executed at shutdown, after all databases are\n"
        "flushed and closed. The wallet, config, and network keys are always preserved; Sapling\n"
        "note witnesses are rebuilt after resync (repair.phase rebuilding_witnesses).\n"
        "scope \"network\" wipes peers.dat/anchors.dat only (no chain state).\n"
        "Callable during RPC warmup (including crippled_wait startup diagnosis).\n",
        {
            {"dry_run", RPCArg::Type::BOOL, RPCArg::Default{false}, "Compute the plan and mint a confirm token without arming"},
            {"confirm_token", RPCArg::Type::STR, RPCArg::Default{""}, "One-time token from the dry_run response"},
            {"scope", RPCArg::Type::STR, RPCArg::Default{"full"}, "\"full\" (wipe+resync) or \"network\" (peers.dat/anchors.dat only)"},
            {"override_rate_limit", RPCArg::Type::BOOL, RPCArg::Default{false}, "Override the 2-wipes-per-7-days guard (ledgered)"},
            {"shutdown", RPCArg::Type::BOOL, RPCArg::Default{false}, "Also initiate daemon shutdown after arming (headless convenience)"},
            {"disarm", RPCArg::Type::BOOL, RPCArg::Default{false}, "Cancel an armed repair: remove the marker so NO wipe executes at the next shutdown/start"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "contract_version", "recovery contract version (2)"},
                {RPCResult::Type::BOOL, "dry_run", /*optional=*/true, "present on dry-run responses"},
                {RPCResult::Type::STR, "scope", "full|network"},
                {RPCResult::Type::ARR, "wipe_dirs", /*optional=*/true, "directories the repair will remove", {{RPCResult::Type::STR, "", ""}}},
                {RPCResult::Type::ARR, "wipe_files", /*optional=*/true, "files the repair will remove", {{RPCResult::Type::STR, "", ""}}},
                {RPCResult::Type::ARR, "preserved", /*optional=*/true, "stable ids of preserved state", {{RPCResult::Type::STR, "", ""}}},
                {RPCResult::Type::NUM, "bytes_total_est", /*optional=*/true, "estimated bytes to be wiped"},
                {RPCResult::Type::STR, "confirm_token", /*optional=*/true, "one-time confirmation token (5 min TTL)"},
                {RPCResult::Type::OBJ, "guards", /*optional=*/true, "guard state at dry-run time",
                {
                    {RPCResult::Type::NUM, "attempts_used", ""},
                    {RPCResult::Type::NUM, "attempts_max", ""},
                    {RPCResult::Type::NUM, "wipes_in_window", ""},
                    {RPCResult::Type::NUM, "wipes_max", ""},
                    {RPCResult::Type::BOOL, "rate_limited", ""},
                }},
                {RPCResult::Type::BOOL, "armed", /*optional=*/true, "present on arm responses"},
                {RPCResult::Type::STR, "result", /*optional=*/true, "ARMED|BAD_TOKEN|ATTEMPTS_EXHAUSTED|REPAIR_RATE_LIMITED|ALREADY_ARMED|DISARMED|NOT_ARMED"},
                {RPCResult::Type::BOOL, "shutdown_initiated", /*optional=*/true, ""},
                {RPCResult::Type::BOOL, "disarmed", /*optional=*/true, "present on disarm responses"},
            }},
        RPCExamples{
            HelpExampleCli("repairnode", "true")
          + HelpExampleCli("repairnode", "false \"<confirm_token>\" \"full\"")
          + HelpExampleRpc("repairnode", "false, \"<confirm_token>\", \"full\", false, true")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Warmup-callable: touches only recovery-module state + the marker/ledger
    // files. Arming during warmup is safe by construction: the wipe executes
    // after DB close (shutdown) or before DB open (next start) (7.5.c).
    const bool dry_run{request.params[0].isNull() ? false : request.params[0].get_bool()};
    const std::string confirm_token{request.params[1].isNull() ? "" : request.params[1].get_str()};
    const std::string scope{request.params[2].isNull() ? "full" : request.params[2].get_str()};
    const bool override_rate_limit{request.params[3].isNull() ? false : request.params[3].get_bool()};
    const bool do_shutdown{request.params[4].isNull() ? false : request.params[4].get_bool()};
    const bool disarm{request.params[5].isNull() ? false : request.params[5].get_bool()};

    if (scope != "full" && scope != "network") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "scope must be \"full\" or \"network\"");
    }
    if (disarm && (dry_run || do_shutdown || !confirm_token.empty())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "disarm cannot be combined with dry_run/confirm_token/shutdown");
    }
    // GUI-build guard (7.3/8.2): a GUI process owns its own clean
    // shutdown+relaunch chain; letting an RPC caller StartShutdown() here
    // would break that ordering (the GUI refuses to restart once shutdown
    // has been requested). Rejected up front so a refused call never arms.
    if (do_shutdown && recovery::IsRepairShutdownRejected()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "shutdown:true is not available in this build (the GUI owns the restart); "
                           "arm without shutdown and restart from the GUI");
    }
    if (!recovery::g_recovery) {
        throw JSONRPCError(RPC_IN_WARMUP, "recovery manager not yet constructed");
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("contract_version", recovery::RECOVERY_CONTRACT_VERSION);

    if (disarm) {
        const bool cleared = recovery::g_recovery->RepairDisarm();
        result.pushKV("disarmed", cleared);
        result.pushKV("result", cleared ? "DISARMED" : "NOT_ARMED");
        return result;
    }

    if (dry_run) {
        const recovery::RepairPlan plan = recovery::g_recovery->RepairDryRun(scope);
        result.pushKV("dry_run", true);
        result.pushKV("scope", scope);
        UniValue jdirs(UniValue::VARR);
        for (const std::string& d : plan.wipe_dirs) jdirs.push_back(d);
        result.pushKV("wipe_dirs", jdirs);
        UniValue jfiles(UniValue::VARR);
        for (const std::string& f : plan.wipe_files) jfiles.push_back(f);
        result.pushKV("wipe_files", jfiles);
        UniValue jpres(UniValue::VARR);
        for (const std::string& p : plan.preserved) jpres.push_back(p);
        result.pushKV("preserved", jpres);
        result.pushKV("bytes_total_est", plan.bytes_total_est);
        result.pushKV("confirm_token", plan.confirm_token);
        UniValue guards(UniValue::VOBJ);
        guards.pushKV("attempts_used", plan.attempts_used);
        guards.pushKV("attempts_max", 3);
        guards.pushKV("wipes_in_window", plan.wipes_in_window);
        guards.pushKV("wipes_max", 2);
        guards.pushKV("rate_limited", plan.rate_limited);
        result.pushKV("guards", guards);
        return result;
    }

    const recovery::ArmResult res = recovery::g_recovery->RepairArm(confirm_token, scope, override_rate_limit);
    result.pushKV("armed", res == recovery::ArmResult::ARMED);
    result.pushKV("scope", scope);
    result.pushKV("result", ArmResultToString(res));
    if (res == recovery::ArmResult::ARMED && do_shutdown) {
        // Headless convenience (6.2.1): the caller wants the wipe to happen
        // now; the marker-driven wipe executes inside this shutdown.
        StartShutdown();
        result.pushKV("shutdown_initiated", true);
    } else if (res == recovery::ArmResult::ARMED) {
        result.pushKV("shutdown_initiated", false);
    }
    return result;
},
    };
}

static RPCHelpMan recovery_inducedrift()
{
    return RPCHelpMan{"recovery_inducedrift",
        "\nRegression-testing only (-regtest/-devnet): corrupt a derived-cache best-block key on\n"
        "disk so the consistency-drift quarantine and crippled_wait paths can be exercised.\n"
        "db=\"quarantine\" skips the DB and enters quarantine directly, for gating tests.\n",
        {
            {"db", RPCArg::Type::STR, RPCArg::Default{"sapling"}, "\"sapling\", \"evodb\" or \"quarantine\""},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "corrupted", ""},
                {RPCResult::Type::STR, "db", "which cache was corrupted"},
                {RPCResult::Type::STR, "bogus_best_block", /*optional=*/true, "the hash written"},
            }},
        RPCExamples{HelpExampleCli("recovery_inducedrift", "\"sapling\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!Params().IsMockableChain()) {
        throw std::runtime_error("recovery_inducedrift is for regression testing (-regtest mode) only");
    }
    const std::string db{request.params[0].isNull() ? "sapling" : request.params[0].get_str()};
    const NodeContext& node = EnsureAnyNodeContext(request.context);

    UniValue result(UniValue::VOBJ);
    result.pushKV("db", db);
    if (db == "quarantine") {
        // PARK-VS-EXIT: mirror the runtime-drift split so this synthetic hook
        // exercises BOTH terminal behaviours. Under ParkOnFault() (GUI, or the
        // headless -parkonfault test arg) the node parks-and-quarantines alive;
        // otherwise (headless default) it goes DOWN via the AbortNode path with
        // a non-zero exit -- no on-disk corruption and no sentinel, so a plain
        // restart comes back clean.
        if (recovery::ParkOnFault()) {
            recovery::EnterQuarantine(recovery::QuarantineReason::DRIFT_EVODB_CONNECT,
                                      "recovery_inducedrift: synthetic quarantine (regtest only)");
        } else {
            recovery::NoteHeadlessFaultShutdown(
                "SYNTHETIC_DRIFT (recovery_inducedrift)",
                "recovery_inducedrift: synthetic headless fault (regtest only)");
        }
        result.pushKV("corrupted", false);
        return result;
    }

    const uint256 bogus = GetRandHash();
    if (db == "evodb") {
        if (!node.evodb) throw JSONRPCError(RPC_INTERNAL_ERROR, "evodb not available");
        // Write straight to the raw DB (bypassing the transaction layers) so
        // the corruption is both immediately visible to VerifyBestBlock() and
        // persisted across a restart.
        node.evodb->GetRawDB().Write(EVODB_BEST_BLOCK, bogus);
    } else if (db == "sapling") {
        if (!node.chain_helper || !node.chain_helper->sapling_state) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "sapling state not available");
        }
        node.chain_helper->sapling_state->CorruptBestBlockForTesting(bogus);
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "db must be \"sapling\", \"evodb\" or \"quarantine\"");
    }
    result.pushKV("corrupted", true);
    result.pushKV("bogus_best_block", bogus.ToString());
    return result;
},
    };
}

void RegisterRecoveryRPCCommands(CRPCTable& tableRPC)
{
    static const CRPCCommand commands[]{
        // Exactly these two commands are warmup-callable (7.5): both handlers
        // touch only recovery-module state, never cs_main/wallet/chainstate.
        {"recovery", &getrecoverystatus, /*ok_during_warmup=*/true},
        {"recovery", &repairnode, /*ok_during_warmup=*/true},
        {"hidden", &recovery_inducedrift},
    };
    for (const auto& command : commands) {
        tableRPC.appendCommand(command.name, &command);
    }
}
