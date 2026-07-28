// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <recovery/witnesshook.h>

#include <sync.h>

namespace recovery {

namespace {
Mutex g_witness_hook_mutex;
WitnessQueryFn g_witness_query GUARDED_BY(g_witness_hook_mutex);
WitnessTriggerFn g_witness_trigger GUARDED_BY(g_witness_hook_mutex);
} // namespace

void RegisterWalletWitnessHook(WitnessQueryFn query, WitnessTriggerFn trigger)
{
    LOCK(g_witness_hook_mutex);
    g_witness_query = std::move(query);
    g_witness_trigger = std::move(trigger);
}

WitnessQueryFn GetWalletWitnessQuery()
{
    LOCK(g_witness_hook_mutex);
    return g_witness_query;
}

WitnessTriggerFn GetWalletWitnessTrigger()
{
    LOCK(g_witness_hook_mutex);
    return g_witness_trigger;
}

} // namespace recovery
