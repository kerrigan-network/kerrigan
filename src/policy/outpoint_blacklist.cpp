// Copyright (c) 2026 The Kerrigan developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/outpoint_blacklist.h>

#include <key_io.h>            // DecodeDestination
#include <logging.h>          // LogPrintf
#include <script/standard.h>  // GetScriptForDestination, IsValidDestination
#include <uint256.h>          // uint256S
#include <util/strencodings.h> // IsHex, ParseUInt32
#include <util/string.h>      // SplitString / Join helpers (TrimString)

#include <fstream>
#include <string>

// Process-wide instances. Defined once here; declared extern in the header.
OutpointBlacklist g_outpoint_blacklist;
bool g_outpoint_blacklist_consensus = false;
int g_outpoint_blacklist_consensus_height = 0;

// Deterministic taint-root freeze (incident 2026-05). Mutated only under cs_main.
TaintSet g_taint_set;

namespace {

/** Strip a trailing "# ..." inline comment and surrounding whitespace. */
std::string StripComment(const std::string& line)
{
    const std::size_t hash = line.find('#');
    std::string s = (hash == std::string::npos) ? line : line.substr(0, hash);
    return TrimString(s);
}

} // namespace

bool OutpointBlacklist::AddOutpointString(const std::string& token, std::vector<std::string>& errors)
{
    // Expected form: "<64-hex-txid>:<vout>"
    const std::size_t colon = token.rfind(':');
    if (colon == std::string::npos) {
        errors.emplace_back("blacklist outpoint missing ':vout' separator: " + token);
        return false;
    }

    const std::string txidHex = TrimString(token.substr(0, colon));
    const std::string voutStr = TrimString(token.substr(colon + 1));

    if (txidHex.size() != 64 || !IsHex(txidHex)) {
        errors.emplace_back("blacklist outpoint has invalid 32-byte hex txid: " + token);
        return false;
    }

    uint32_t vout = 0;
    if (!ParseUInt32(voutStr, &vout)) {
        errors.emplace_back("blacklist outpoint has invalid vout index: " + token);
        return false;
    }

    AddOutpoint(COutPoint(uint256S(txidHex), vout));
    return true;
}

bool OutpointBlacklist::AddAddressString(const std::string& address, std::vector<std::string>& errors)
{
    // Decode against the active network params (set up before this is called).
    const CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest)) {
        errors.emplace_back("blacklist address is not a valid address for this network: " + address);
        return false;
    }
    const CScript script = GetScriptForDestination(dest);
    if (script.empty()) {
        errors.emplace_back("blacklist address produced an empty script: " + address);
        return false;
    }
    AddScript(script);
    return true;
}

std::size_t OutpointBlacklist::LoadFromFile(const fs::path& path, std::vector<std::string>& errors)
{
    std::ifstream file(path);
    if (!file.is_open()) {
        errors.emplace_back("could not open blacklist file: " + fs::PathToString(path));
        return 0;
    }

    std::size_t loaded = 0;
    std::string raw;
    while (std::getline(file, raw)) {
        const std::string line = StripComment(raw);
        if (line.empty()) continue;

        // Disambiguate: a "txid:vout" entry has a ':' AND a 64-hex prefix.
        // Anything else is treated as an address. (Addresses never contain ':'.)
        const bool looks_like_outpoint = (line.find(':') != std::string::npos);
        const bool ok = looks_like_outpoint ? AddOutpointString(line, errors)
                                             : AddAddressString(line, errors);
        if (ok) ++loaded;
    }
    return loaded;
}

// ===========================================================================
//  TaintSet -- deterministic taint propagation rule
// ===========================================================================
//
// The chain WALK (reading blocks [root..H] off the active chain and feeding
// them here in order) lives in validation.cpp, which owns the chain index and
// block storage. THIS function is the pure, side-effect-isolated propagation
// rule: it decides whether one transaction is tainted and, if so, taints all
// of its outputs. Keeping the rule here -- and calling the *same* function from
// both the production walk and the unit tests -- guarantees the tested logic is
// the deployed logic.
//
// Determinism: this function performs only ordered std::set operations and
// byte-wise uint256/CScript comparisons. It contains no floating point, no
// hashing of unordered containers, no locale- or time-dependent behaviour.
// Given identical (txid, vin_prevouts, vout_scripts, seed_script, seed_txids,
// working) it produces an identical result and identical mutation of `working`
// on every platform.
//
// Conservative bias: if ANY input spends a tainted outpoint, OR any output pays
// the seed script, OR the txid is a seed txid, the WHOLE transaction is tainted
// and EVERY output becomes a tainted outpoint. Over-tainting is acceptable;
// under-tainting is not.
bool TaintSet::ApplyTxRule(const uint256& txid,
                           const std::vector<COutPoint>& vin_prevouts,
                           const std::vector<CScript>& vout_scripts,
                           const CScript& seed_script,
                           const std::set<uint256>& seed_txids,
                           std::set<COutPoint>& working)
{
    bool tainted = false;

    // Rule 1: this transaction IS a seed txid -> tainted (all outputs are root taint).
    if (seed_txids.find(txid) != seed_txids.end()) {
        tainted = true;
    }

    // Rule 2: any input spends an already-tainted outpoint -> tainted (descent).
    // Visited in canonical input order; order does not affect the boolean result
    // but we keep it ordered for clarity and to avoid any accidental dependence.
    if (!tainted) {
        for (const COutPoint& prevout : vin_prevouts) {
            if (working.find(prevout) != working.end()) {
                tainted = true;
                break;
            }
        }
    }

    // Rule 3: any output pays the seed (drain) script -> tainted (root taint).
    // Checked even if already tainted is false; cheap and keeps the rule total.
    if (!tainted && !seed_script.empty()) {
        for (const CScript& spk : vout_scripts) {
            if (spk == seed_script) {
                tainted = true;
                break;
            }
        }
    }

    if (!tainted) {
        return false;
    }

    // Tainted: every output of this tx becomes a tainted outpoint. Output index
    // is the canonical vout position. std::set insertion is idempotent and the
    // set's iteration order is the total COutPoint order -- fully deterministic.
    for (uint32_t n = 0; n < vout_scripts.size(); ++n) {
        working.insert(COutPoint(txid, n));
    }
    return true;
}
