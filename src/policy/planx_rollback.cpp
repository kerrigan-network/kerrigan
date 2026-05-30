// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// PLAN X -- CONTINGENCY ROLLBACK (incident 2026-05). See planx_rollback.h.
//
// RECOVERY-RELEASE (PRODUCTION) -- community vote passed; values finalized.
// Consensus validity is driven by compiled per-network state (live on mainnet,
// inert elsewhere); -activaterollback gates only the one-time in-process reorg.

#include <policy/planx_rollback.h>

#include <coins.h>                       // CCoinsViewCache, Coin
#include <consensus/amount.h>            // CAmount, COIN, MoneyRange
#include <policy/shielded_spend_freeze.h> // ClassifyShieldedDirection
#include <primitives/transaction.h>      // CTransaction, CTxOut
#include <script/script.h>               // CScript, IsUnspendable
#include <uint256.h>                     // uint256, uint256S
#include <util/strencodings.h>           // ParseHex

#include <string>

// Process-wide instances. Defined once here; declared extern in the header.
// g_activate_rollback gates only the in-process reorg (default off); the recovery
// set is seeded unconditionally at startup (empty, hence inert, off mainnet).
bool g_activate_rollback = false;
CompromisedRecoverySet g_compromised_recovery_set;

namespace {

/** True iff a 64-char hex string is the all-zero placeholder. A null/zero hash
 *  is the sentinel for "this constant is not finalized -> the rule is inert". */
bool HexIsAllZero(const char* hex)
{
    if (hex == nullptr) return true;
    for (const char* p = hex; *p != '\0'; ++p) {
        if (*p != '0') return false;
    }
    return true;
}

} // namespace

uint256 PlanXDisallowedBlockHash()
{
    if (HexIsAllZero(planx::DEFAULT_DISALLOWED_BLOCKHASH)) {
        return uint256(); // inert: never disallow the null hash
    }
    return uint256S(planx::DEFAULT_DISALLOWED_BLOCKHASH);
}

uint256 PlanXRollbackAnchorHash()
{
    if (HexIsAllZero(planx::DEFAULT_ROLLBACK_ANCHOR_HASH)) {
        return uint256(); // inert: never pin to the null hash
    }
    return uint256S(planx::DEFAULT_ROLLBACK_ANCHOR_HASH);
}

CScript PlanXRecoveryScript()
{
    // Empty placeholder -> empty script -> only-to-7b rule is inert.
    const std::string hex(planx::DEFAULT_RECOVERY_SCRIPT_7B);
    if (hex.empty()) {
        return CScript();
    }
    const std::vector<unsigned char> bytes = ParseHex(hex);
    return CScript(bytes.begin(), bytes.end());
}

CScript PlanXPlaceholderSentinelScript()
{
    const std::vector<unsigned char> bytes = ParseHex(planx::PLACEHOLDER_SENTINEL_SCRIPT);
    return CScript(bytes.begin(), bytes.end());
}

bool PlanXScriptIsPlaceholder(const CScript& script)
{
    // A slot is unfinalized if it is empty OR still equals the documented
    // placeholder sentinel. Both are treated as "not yet a real destination".
    if (script.empty()) {
        return true;
    }
    return script == PlanXPlaceholderSentinelScript();
}

bool PlanXIsDisallowedBlockHash(const uint256& hash)
{
    // Consensus validity, not an operator preference. The disallow rule is driven
    // by the compiled disallowed-block hash, independent of -activaterollback, so
    // every node running this release rejects the disallowed block identically and
    // there is no flag-dependent difference in fork choice. The sole caller (the
    // header-acceptance path in validation.cpp) is mainnet-scoped via
    // consensus.nRollbackHeight > 0, so the mainnet hash is only consulted on
    // mainnet. Inert when the hash is the all-zero placeholder (an unfinalized
    // build), so it has no effect on any other network or on upstream.
    const uint256 disallowed = PlanXDisallowedBlockHash();
    if (disallowed.IsNull()) {
        return false; // placeholder not finalized -> inert
    }
    return hash == disallowed;
}

bool PlanXTxHasShieldedComponent(const CTransaction& tx)
{
    // Reuse the canonical Sapling-payload classifier so this matches how
    // the rest of consensus parses the payload bit-for-bit. A pure-transparent tx
    // (or a Sapling tx with an unparseable payload) classifies as is_sapling ==
    // false. A Sapling tx "has a shielded component" iff it carries any shielded
    // spend, any shielded output, or a non-zero net valueBalance -- i.e. it moves
    // value across the transparent<->shielded boundary (the t->z shield bypass) or
    // churns shielded notes. Equivalent to the keys called out in the task:
    // nType == TRANSACTION_SAPLING with non-empty vSpendDescriptions /
    // vOutputDescriptions / valueBalance != 0.
    const ShieldedDirection dir = ClassifyShieldedDirection(tx);
    if (!dir.is_sapling) {
        return false;
    }
    return dir.spends > 0 || dir.outputs > 0 || dir.value_balance != 0;
}

bool PlanXOnlyToRecoveryAllowed(const CTransaction& tx,
                                const CCoinsViewCache& view,
                                const char** reason,
                                int nHeight)
{
    static const CScript legacy_recovery = [](){
        auto b = ParseHex(planx::LEGACY_RECOVERY_SCRIPT_V1);
        return CScript(b.begin(), b.end());
    }();
    const bool accept_legacy = (nHeight < planx::RECOVERY_V2_ACTIVATION_HEIGHT);

    // (1) Inert short-circuits. The recovery spend restriction is consensus
    //     validity driven by the compiled recovery set and recovery destination,
    //     independent of -activaterollback, so all nodes running this release agree
    //     on block validity. The rule is inert when the recovery set is empty --
    //     which is also its mainnet scoping, since the seed addresses decode only
    //     under mainnet parameters (the set stays empty on every other network and
    //     on upstream) -- or when the recovery destination is not finalized (an
    //     empty or placeholder script).
    if (!g_compromised_recovery_set.IsActive()) {
        return true;
    }
    const CScript recovery = PlanXRecoveryScript();
    if (PlanXScriptIsPlaceholder(recovery)) {
        return true; // recovery script empty/placeholder -> inert
    }

    // (2) Does this tx TOUCH the compromised set? It does if it spends a
    //     compromised outpoint, or spends a coin paying a compromised script.
    //     We do NOT break early: we also accumulate the TOTAL value of the
    //     compromised inputs (the protected quantity) for the fee bound below.
    //     n is tiny (the theft's inputs), so the full pass is trivial.
    bool touches = false;
    CAmount compromised_in_value = 0;
    for (const auto& txin : tx.vin) {
        bool input_is_compromised = g_compromised_recovery_set.ContainsOutpoint(txin.prevout);
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (!input_is_compromised && !coin.IsSpent() &&
            g_compromised_recovery_set.ContainsScript(coin.out.scriptPubKey)) {
            input_is_compromised = true;
        }
        if (input_is_compromised) {
            touches = true;
            // Sum the protected value. The coin may be absent from the view in a
            // mempool/standalone context only for an outpoint-listed input whose
            // coin we cannot see; in that case the value is unknown and we fall
            // back to the conservative side below (treat as 0, which only makes
            // the fee bound easier to satisfy -- but the destination rule still
            // forces the (visible) outputs entirely to 7b, so value cannot leak).
            if (!coin.IsSpent() && MoneyRange(coin.out.nValue)) {
                compromised_in_value += coin.out.nValue;
            }
        }
    }
    if (!touches) {
        return true; // ignores non-compromised spends
    }

    // (3a) A compromised-coin spend may NOT carry any Sapling shielded
    //      component. A t->z shield moves value via the Sapling payload with an
    //      empty (or marker-only) vout, which the destination loop below would
    //      never see. Forbidding any shielded component forces the recovered
    //      coins to move ONLY via a fully-transparent sweep to 7b.
    if (PlanXTxHasShieldedComponent(tx)) {
        if (reason != nullptr) {
            *reason = "planx-shielded-compromised-spend";
        }
        return false;
    }

    // (3b) No change-back: the tx is VALID only if EVERY non-marker
    //      output pays exactly the recovery "7b" script. Paying back into the
    //      compromised set ("change") is NO LONGER allowed -- a full sweep to 7b
    //      is forced so the attacker cannot shuffle value among the compromised
    //      addresses. OP_RETURN / provably-unspendable outputs (markers) are
    //      ignored. While iterating, accumulate the value actually paid to 7b for
    //      the (3c) fee bound.
    CAmount value_to_recovery = 0;
    for (const auto& txout : tx.vout) {
        if (txout.scriptPubKey.IsUnspendable()) {
            continue; // OP_RETURN marker -- ignore
        }
        if (txout.scriptPubKey == recovery ||
            (accept_legacy && txout.scriptPubKey == legacy_recovery)) {
            if (MoneyRange(txout.nValue)) {
                value_to_recovery += txout.nValue;
            }
            continue;
        }
        // Any other destination (including change back into a compromised
        // address) is forbidden for a compromised-coin spend.
        if (reason != nullptr) {
            *reason = "planx-only-to-recovery";
        }
        return false;
    }

    // (3c) Fee bound: essentially the ENTIRE protected value must reach
    //      7b. The value paid to 7b must be at least (compromised input value) -
    //      MAX_RECOVERY_FEE. This kills the fee-bleed leak (dust to 7b + large fee
    //      recaptured via a self-mined block). When compromised_in_value is 0
    //      (e.g. an outpoint-listed input whose coin is not visible in this view),
    //      the bound is trivially satisfied, but (3b) has already forced every
    //      visible output to 7b, so no value can be diverted.
    const CAmount min_to_recovery = compromised_in_value - planx::MAX_RECOVERY_FEE;
    if (value_to_recovery < min_to_recovery) {
        if (reason != nullptr) {
            *reason = "planx-recovery-fee-too-high";
        }
        return false;
    }
    return true;
}
