// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RECOVERY_WITNESSHOOK_H
#define BITCOIN_RECOVERY_WITNESSHOOK_H

#include <functional>

/**
 * Wallet <-> recovery decoupling shim (WS-HEAL v2 6.4).
 *
 * The guided-repair flow needs to (a) observe whether the wallet's Sapling
 * per-note witness rebuild is pending/running and (b) force the rebuild after
 * a wipe+resync even under -noautorebuildsaplingwitnesses. The wallet library
 * must not reference the node-side recovery manager (wallet-only tools link
 * without libbitcoin_node), so both sides meet at this tiny registry, which
 * lives in libbitcoin_common: the wallet registers, the recovery tick reads.
 */
namespace recovery {

struct WalletWitnessStatus {
    bool have_wallet{false};
    bool rebuild_active{false}; //!< a rebuild replay is running now
    bool check_pending{false};  //!< post-IBD staleness detection has not run yet
};

using WitnessQueryFn = std::function<WalletWitnessStatus()>;
using WitnessTriggerFn = std::function<void()>;

/** Register (or replace) the wallet-side hooks. `query` must be cheap and
 *  lock-free; `trigger` forces staleness detection + rebuild regardless of
 *  -autorebuildsaplingwitnesses. Passing empty functions unregisters. */
void RegisterWalletWitnessHook(WitnessQueryFn query, WitnessTriggerFn trigger);

/** Snapshot the currently registered hooks (either may be empty). */
WitnessQueryFn GetWalletWitnessQuery();
WitnessTriggerFn GetWalletWitnessTrigger();

} // namespace recovery

#endif // BITCOIN_RECOVERY_WITNESSHOOK_H
