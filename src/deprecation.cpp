// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Operator-side deprecation height (v1.2.5). See deprecation.h.

#include <deprecation.h>

#include <consensus/params.h>
#include <logging.h>
#include <shutdown.h>
#include <util/translation.h>
#include <warnings.h>

#include <atomic>

namespace deprecation {

namespace {

// Last height at which we logged the warning. Relaxed atomic so the function
// is safe to call from validation threads without an explicit lock. Used only
// to throttle the in-window warning log to DEPRECATION_WARNING_LOG_INTERVAL.
std::atomic<int> g_last_warned_height{-1};

// Latched once the fatal shutdown has been initiated so a second tip update at
// or past the deprecation height does not re-call StartShutdown(). Cheap guard
// against duplicate log lines during the moments between fatal and exit.
std::atomic<bool> g_shutdown_initiated{false};

} // namespace

void CheckDeprecation(int nHeight, const Consensus::Params& params)
{
    const int deprecation_height = params.nDeprecationHeight;
    if (deprecation_height == 0) {
        return; // disabled (default off-mainnet; releases without a cycle).
    }

    if (nHeight >= deprecation_height) {
        if (g_shutdown_initiated.exchange(true)) {
            return; // already shutting down; one fatal line is enough.
        }
        const std::string msg = strprintf(
            "This version of Kerrigan Core has reached its deprecation height "
            "(h=%d, current=%d) and will stop processing blocks. Upgrade to a "
            "current release to continue. Initiating clean shutdown.",
            deprecation_height, nHeight);
        LogPrintf("FATAL: %s\n", msg);
        SetMiscWarning(Untranslated(msg));
        StartShutdown();
        return;
    }

    const int warn_start = deprecation_height - DEPRECATION_WARNING_BLOCKS;
    if (nHeight < warn_start) {
        return; // outside the warning window.
    }

    // Inside the warning window. Throttle the log line to once per
    // DEPRECATION_WARNING_LOG_INTERVAL blocks so a chain that flips around the
    // tip does not spam debug.log, but always refresh the GUI banner so a
    // freshly-opened wallet UI sees the warning immediately.
    const std::string msg = strprintf(
        "This version of Kerrigan Core will stop processing blocks at height "
        "%d (currently %d, %d blocks remaining). Upgrade required.",
        deprecation_height, nHeight, deprecation_height - nHeight);
    SetMiscWarning(Untranslated(msg));

    const int prev = g_last_warned_height.load(std::memory_order_relaxed);
    if (prev < 0 || nHeight - prev >= DEPRECATION_WARNING_LOG_INTERVAL) {
        g_last_warned_height.store(nHeight, std::memory_order_relaxed);
        LogPrintf("WARNING: %s\n", msg);
    }
}

} // namespace deprecation
