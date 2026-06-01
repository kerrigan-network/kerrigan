// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Shielded-spend ("z->t un-shield") freeze.
//
// PURPOSE
// -------
// Incident 2026-05: a thief moved ~1/5 of the supply INTO the Sapling shielded
// pool before an earlier transparent freeze activated. The transparent
// outpoint/taint freeze (policy/outpoint_blacklist.h) cannot follow value once
// it is shielded, because shielded notes are spent by nullifier, not by a
// transparent outpoint. This module closes that exit: it denies the thief the
// cash-out by rejecting transactions that WITHDRAW value from the shielded pool
// to transparent outputs (z->t un-shielding).
//
// This is a DEFENSIVE, REVERSIBLE control on the project's own chain, authorised
// by the chain operator. It freezes the act of spending shielded notes; it never
// moves, seizes, or redirects funds, and it touches no key material.
//
// WHAT IS A "z->t UN-SHIELD" ON THIS SCHEMA
// -----------------------------------------
// Kerrigan carries Sapling shielded data as a special-transaction payload, NOT
// as fields on CTransaction directly:
//   * A shielded tx has nVersion >= SPECIAL_VERSION and nType == TRANSACTION_SAPLING.
//   * Its shielded component is serialized into CTransaction::vExtraPayload and
//     deserialized with GetTxPayload<SaplingTxPayload>() (see evo/specialtx.h and
//     sapling/sapling_tx_payload.h).
//   * SaplingTxPayload::vSpendDescriptions  == shielded SPENDS  (notes leaving the
//     pool -- this is the OUT direction).
//   * SaplingTxPayload::vOutputDescriptions == shielded OUTPUTS (notes entering the
//     pool -- this is the IN direction).
//   * SaplingTxPayload::valueBalance is an int64 whose sign is, per the on-chain
//     accounting in consensus/tx_verify.cpp and sapling/sapling_state.cpp:
//         valueBalance > 0  ==>  value LEAVES the shielded pool  (z->t un-shield)
//         valueBalance < 0  ==>  value ENTERS the shielded pool  (t->z shield-in)
//
// SCOPE OF THE CHECK (deliberate, conservative)
// ---------------------------------------------
// The OUT direction is precisely "the tx spends shielded notes", i.e.
// vSpendDescriptions is non-empty. Because Kerrigan shielding was bug-broken and
// the pool's legitimate usage is ~zero, the SIMPLEST robust scope is taken:
//   FROZEN  <=>  the tx spends shielded notes (has >= 1 shielded spend).
// This blocks BOTH z->t (un-shield) AND z->z (shielded-to-shielded), while
// leaving pure-transparent txs and t->z shield-IN (spends == 0, outputs >= 1)
// untouched. Blocking z->z too is intentional: it denies the thief the ability to
// churn notes inside the pool to break linkage before a later un-shield, and a
// note can only ever exit via a spend, so freezing all spends is the airtight
// closure of the exit. The finer "valueBalance > 0 only" predicate is also
// exposed (ShieldedDirection::value_balance) for callers/tests that want the
// strict z->t-only rule.
//
// TWO INDEPENDENT LAYERS (mirrors the outpoint freeze; see the call sites):
//   * Layer 1 (relay/policy) -- mempool reject + block-template exclusion.
//     Non-consensus. DEFAULT OFF, opt-in per node via -freezeshieldedspends. An
//     un-configured node behaves byte-identically to stock. Causes NO chain
//     split: the node simply declines to relay/mine the shielded spend. This is
//     what cooperating pools run immediately.
//   * Layer 2 (consensus) -- a block containing a shielded-spend tx is INVALID
//     at/after a per-network activation height
//     (Consensus::Params::nShieldedSpendFreezeHeight). DEFAULT INERT: the height
//     is 0 on mainnet/testnet at this revision (the human sets the real mainnet
//     height at tag time), so a stock node is byte-identical to upstream. Devnet
//     and regtest use height 1 so tests can exercise the path. This is a hard
//     fork if not universally adopted; it ships paired with a checkpoint.
//
// REVERSIBILITY
// -------------
// Layer 1 is a runtime flag: drop -freezeshieldedspends and restart to lift it,
// with no on-disk consensus state created. Layer 2's invalidity is purely a
// function of the running binary's per-network nShieldedSpendFreezeHeight (a
// compile-time/chainparams value), so lifting it is a release change.
//
// THREAD SAFETY
// -------------
// The detection function is PURE: it reads only the passed transaction and has no
// shared state. It is safe to call from the validation and mining threads
// concurrently. The Layer-1 opt-in flag is set ONCE at startup (before networking
// /validation threads start) and is read-only thereafter, so its reads are
// lock-free.

#ifndef BITCOIN_POLICY_SHIELDED_SPEND_FREEZE_H
#define BITCOIN_POLICY_SHIELDED_SPEND_FREEZE_H

class CTransaction;

/**
 * @brief The freeze predicate: should this tx be frozen as a shielded spend?
 *
 * True iff the tx spends shielded notes (the OUT direction). This is the
 * predicate the relay and consensus call sites use. Pure; never throws.
 */
bool IsFrozenShieldedSpend(const CTransaction& tx);

/**
 * Layer-1 (relay/policy) opt-in flag. DEFAULT FALSE. Set once at startup from
 * -freezeshieldedspends (see init.cpp::InitShieldedSpendFreeze) and read-only
 * thereafter. When false, the mempool reject and template exclusion are skipped
 * and the node is byte-identical to stock on the relay path. Layer 2 (consensus)
 * is independent of this flag and is gated only by the per-network activation
 * height.
 */
extern bool g_freeze_shielded_spends;

#endif // BITCOIN_POLICY_SHIELDED_SPEND_FREEZE_H
