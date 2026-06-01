// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/shielded_spend_freeze.h>

#include <policy/planx_rollback.h> // ClassifyShieldedDirection

#include <primitives/transaction.h> // CTransaction

// Process-wide Layer-1 opt-in flag. Defined once here; declared extern in header.
bool g_freeze_shielded_spends = false;

bool IsFrozenShieldedSpend(const CTransaction& tx)
{
    // OUT-direction predicate: the tx spends shielded notes. A note can only ever
    // leave the pool via a spend, so freezing every shielded spend is the airtight
    // closure of the z->t exit (and additionally blocks z->z churn). t->z shield-IN
    // (spends == 0) and pure-transparent txs are not frozen.
    return ClassifyShieldedDirection(tx).SpendsShielded();
}
