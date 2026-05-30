// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DEPRECATION_H
#define BITCOIN_DEPRECATION_H

// ============================================================================
//  Operator-side deprecation height (v1.2.5)
// ============================================================================
//
// This is an OPERATOR-side mechanism, not consensus. A daemon configured with a
// non-zero Consensus::Params::nDeprecationHeight will:
//
//   - log a warning (and surface a GUI banner via SetMiscWarning) starting at
//     DEPRECATION_WARNING_BLOCKS blocks before the deprecation height, repeated
//     every DEPRECATION_WARNING_LOG_INTERVAL blocks so the operator sees it
//     without spamming the log.
//   - at the deprecation height itself, log a fatal message and call
//     StartShutdown() to initiate a clean exit. The operator must upgrade to a
//     release whose nDeprecationHeight is further in the future (or 0).
//
// Rationale: prevents indefinite v1.0.x/v1.1.x/v1.2.0-v1.2.4 stragglers from
// holding a stale chain view. Newer daemons mine straight through this height
// because their own nDeprecationHeight is higher.
//
// Hooked from CChainState::UpdateTip; cold path (one call per accepted tip).
//
// THREAD SAFETY
// -------------
// CheckDeprecation reads only the passed-in height and Consensus::Params (set
// once at startup, read-only afterwards). The internal "have we already
// warned for height X" tracking uses a relaxed atomic so the function is
// safe to call from validation threads without additional locking.

namespace Consensus { struct Params; }

namespace deprecation {

/** Window before the deprecation height during which a warning fires. */
constexpr int DEPRECATION_WARNING_BLOCKS = 15000;

/** How often the warning is re-logged inside the warning window (blocks). */
constexpr int DEPRECATION_WARNING_LOG_INTERVAL = 100;

/**
 * Inspect the active tip at @p nHeight against @p params.nDeprecationHeight.
 *
 * Behaviour:
 *   - nDeprecationHeight == 0                                    -> no-op.
 *   - nHeight in [nDeprecationHeight - DEPRECATION_WARNING_BLOCKS,
 *                 nDeprecationHeight)                            -> warning.
 *   - nHeight >= nDeprecationHeight                              -> fatal,
 *                                                                  StartShutdown().
 *
 * The warning text is also pushed through SetMiscWarning so the existing GUI
 * banner channel surfaces it without a new wiring. Cold path.
 */
void CheckDeprecation(int nHeight, const Consensus::Params& params);

} // namespace deprecation

#endif // BITCOIN_DEPRECATION_H
