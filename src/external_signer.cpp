// Copyright (c) 2018-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <common/run_command.h>
#include <core_io.h>
#include <psbt.h>
#include <util/strencodings.h>
#include <external_signer.h>

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string>
#include <vector>

// Validate no spaces or shell metacharacters in a token that will become
// a single argv element.  Since RunCommandParseJSON uses subprocess::Popen
// with space-splitting (or vector-based construction), any component with
// spaces could inject additional arguments.
static bool IsSafeToken(const std::string& s)
{
    if (s.empty()) return false;
    for (char c : s) {
        if (std::isspace(static_cast<unsigned char>(c))) return false;
        if (c == '\'' || c == '"' || c == '\\' || c == '`' || c == '$' ||
            c == '|' || c == ';' || c == '&' || c == '(' || c == ')' ||
            c == '<' || c == '>' || c == '*' || c == '?' || c == '[' ||
            c == ']' || c == '{' || c == '}') return false;
    }
    return true;
}

// Validate the signer command path: must be non-empty, contain only safe
// characters, and no spaces (prevents argument injection via the command
// path).
static bool IsSafeCommandPath(const std::string& cmd)
{
    if (cmd.empty()) return false;
    for (char c : cmd) {
        if (!std::isalnum(static_cast<unsigned char>(c)) &&
            c != '/' && c != '.' && c != '-' && c != '_') {
            return false;
        }
    }
    return true;
}

ExternalSigner::ExternalSigner(const std::string& command, const std::string chain, const std::string& fingerprint, const std::string name)
    : m_command(command), m_chain(chain), m_fingerprint(fingerprint), m_name(name)
{
    if (!IsSafeCommandPath(m_command)) {
        throw std::runtime_error("Invalid signer command path: " + command);
    }
    if (!IsHex(m_fingerprint)) {
        throw std::runtime_error("Invalid signer fingerprint (must be hex): " + fingerprint);
    }
}

std::string ExternalSigner::NetworkArg() const
{
    return " --chain " + m_chain;
}

bool ExternalSigner::Enumerate(const std::string& command, std::vector<ExternalSigner>& signers, const std::string chain)
{
    if (!IsSafeCommandPath(command)) {
        throw std::runtime_error("Invalid signer command path: " + command);
    }

    // Call <command> enumerate
    const UniValue result = RunCommandParseJSON(command + " enumerate");
    if (!result.isArray()) {
        throw std::runtime_error(strprintf("'%s' received invalid response, expected array of signers", command));
    }
    for (const UniValue& signer : result.getValues()) {
        // Check for error
        const UniValue& error = signer.find_value("error");
        if (!error.isNull()) {
            if (!error.isStr()) {
                throw std::runtime_error(strprintf("'%s' error", command));
            }
            throw std::runtime_error(strprintf("'%s' error: %s", command, error.getValStr()));
        }
        // Check if fingerprint is present
        const UniValue& fingerprint = signer.find_value("fingerprint");
        if (fingerprint.isNull()) {
            throw std::runtime_error(strprintf("'%s' received invalid response, missing signer fingerprint", command));
        }
        const std::string& fingerprintStr = fingerprint.get_str();
        if (!IsHex(fingerprintStr)) {
            throw std::runtime_error(strprintf("'%s' returned invalid fingerprint (must be hex): %s", command, fingerprintStr));
        }
        // Skip duplicate signer
        bool duplicate = false;
        for (const ExternalSigner& signer : signers) {
            if (signer.m_fingerprint.compare(fingerprintStr) == 0) duplicate = true;
        }
        if (duplicate) break;
        std::string name;
        const UniValue& model_field = signer.find_value("model");
        if (model_field.isStr() && model_field.getValStr() != "") {
            name += model_field.getValStr();
        }
        signers.push_back(ExternalSigner(command, chain, fingerprintStr, name));
    }
    return true;
}

UniValue ExternalSigner::DisplayAddress(const std::string& descriptor) const
{
    // Validate descriptor contains no injection characters (descriptors are
    // well-defined: function(args) — alphanumeric, /, ', <, >, ,, #, @, xpub
    // chars).  Reject anything with spaces or shell metacharacters.
    if (!IsSafeToken(descriptor)) {
        throw std::runtime_error("Invalid descriptor for DisplayAddress");
    }
    return RunCommandParseJSON(m_command + " --fingerprint " + m_fingerprint + NetworkArg() + " displayaddress --desc " + descriptor);
}

UniValue ExternalSigner::GetDescriptors(const int account)
{
    return RunCommandParseJSON(m_command + " --fingerprint " + m_fingerprint + NetworkArg() + " getdescriptors --account " + strprintf("%d", account));
}

bool ExternalSigner::SignTransaction(PartiallySignedTransaction& psbtx, std::string& error)
{
    // Serialize the PSBT
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << psbtx;
    // parse ExternalSigner master fingerprint
    if (!IsHex(m_fingerprint)) {
        error = "Invalid signer fingerprint (must be hex)";
        return false;
    }
    std::vector<unsigned char> parsed_m_fingerprint = ParseHex(m_fingerprint);
    // Check if signer fingerprint matches any input master key fingerprint
    auto matches_signer_fingerprint = [&](const PSBTInput& input) {
        for (const auto& entry : input.hd_keypaths) {
            if (parsed_m_fingerprint == MakeUCharSpan(entry.second.fingerprint)) return true;
        }
        return false;
    };

    if (!std::any_of(psbtx.inputs.begin(), psbtx.inputs.end(), matches_signer_fingerprint)) {
        error = "Signer fingerprint " + m_fingerprint + " does not match any of the inputs:\n" + EncodeBase64(ssTx.str());
        return false;
    }

    const std::string command = m_command + " --stdin --fingerprint " + m_fingerprint + NetworkArg();
    const std::string stdinStr = "signtx " + EncodeBase64(ssTx.str());

    const UniValue signer_result = RunCommandParseJSON(command, stdinStr);

    if (signer_result.find_value("error").isStr()) {
        error = signer_result.find_value("error").get_str();
        return false;
    }

    if (!signer_result.find_value("psbt").isStr()) {
        error = "Unexpected result from signer";
        return false;
    }

    PartiallySignedTransaction signer_psbtx;
    std::string signer_psbt_error;
    if (!DecodeBase64PSBT(signer_psbtx, signer_result.find_value("psbt").get_str(), signer_psbt_error)) {
        error = strprintf("TX decode failed %s", signer_psbt_error);
        return false;
    }

    psbtx = signer_psbtx;

    return true;
}
