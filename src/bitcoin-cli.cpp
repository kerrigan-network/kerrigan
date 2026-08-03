// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Copyright (c) 2014-2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/url.h>
#include <compat/compat.h>
#include <compat/stdin.h>
#include <policy/feerate.h>
#include <rpc/client.h>
#include <rpc/mining.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <stacktraces.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/time.h>
#include <util/translation.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <tuple>

#ifndef WIN32
#include <unistd.h>
#endif

#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>
#include <support/events.h>

// The server returns time values from a mockable system clock, but it is not
// trivial to get the mocked time from the server, nor is it needed for now, so
// just use a plain system_clock.
using CliClock = std::chrono::system_clock;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;
UrlDecodeFn* const URL_DECODE = urlDecode;

static const char DEFAULT_RPCCONNECT[] = "127.0.0.1";
static const int DEFAULT_HTTP_CLIENT_TIMEOUT=900;
static constexpr int DEFAULT_WAIT_CLIENT_TIMEOUT = 0;
static const bool DEFAULT_NAMED=false;
static const int CONTINUE_EXECUTION=-1;
static constexpr int8_t UNKNOWN_NETWORK{-1};
// See GetNetworkName() in netbase.cpp
static constexpr std::array NETWORKS{"not_publicly_routable", "ipv4", "ipv6", "onion", "i2p", "cjdns", "internal"};
static constexpr std::array NETWORK_SHORT_NAMES{"npr", "ipv4", "ipv6", "onion", "i2p", "cjdns", "int"};
static constexpr std::array UNREACHABLE_NETWORK_IDS{/*not_publicly_routable*/0, /*internal*/6};

/** Default number of blocks to generate for RPC generatetoaddress. */
static const std::string DEFAULT_NBLOCKS = "1";

/** Default -color setting. */
static const std::string DEFAULT_COLOR_SETTING{"auto"};

static void SetupCliArgs(ArgsManager& argsman)
{
    SetupHelpOptions(argsman);

    const auto defaultBaseParams = CreateBaseChainParams(CBaseChainParams::MAIN);
    const auto testnetBaseParams = CreateBaseChainParams(CBaseChainParams::TESTNET);
    const auto devnetBaseParams = CreateBaseChainParams(CBaseChainParams::DEVNET);
    const auto regtestBaseParams = CreateBaseChainParams(CBaseChainParams::REGTEST);

    argsman.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-conf=<file>", strprintf("Specify configuration file. Relative paths will be prefixed by datadir location. (default: %s)", BITCOIN_CONF_FILENAME), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-datadir=<dir>", "Specify data directory", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-generate",
                   strprintf("Generate blocks, equivalent to RPC getnewaddress followed by RPC generatetoaddress. Optional positional integer "
                             "arguments are number of blocks to generate (default: %s) and maximum iterations to try (default: %s), equivalent to "
                             "RPC generatetoaddress nblocks and maxtries arguments. Example: kerrigan-cli -generate 4 1000",
                             DEFAULT_NBLOCKS, DEFAULT_MAX_TRIES),
                   ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-addrinfo", "Get the number of addresses known to the node, per network and total, after filtering for quality and recency. The total number of addresses known to the node may be higher.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-getinfo", "Get general information from the remote server. Note that unlike server-side RPC calls, the output of -getinfo is the result of multiple non-atomic requests. Some entries in the output may represent results from different states (e.g. wallet balance may be as of a different block from the chain state reported)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-netinfo", "Get network peer connection information from the remote server. An optional integer argument from 0 to 4 can be passed for different peers listings (default: 0). Pass \"help\" for detailed help documentation.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

    argsman.AddArg("-color=<when>", strprintf("Color setting for CLI output (default: %s). Valid values: always, auto (add color codes when standard output is connected to a terminal and OS is not WIN32), never.", DEFAULT_COLOR_SETTING), ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::OPTIONS);
    argsman.AddArg("-confirm", "For \"kerrigan-cli repair\": skip the interactive typed confirmation and accept the wipe plan (intended for scripts; the plan is still printed)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-overrideratelimit", "For \"kerrigan-cli repair\": override the 2-wipes-per-7-days safety guard. The override is recorded in the node's recovery ledger. Repeated repairs usually mean failing hardware - check the disk first", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-named", strprintf("Pass named instead of positional arguments (default: %s)", DEFAULT_NAMED), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcclienttimeout=<n>", strprintf("Timeout in seconds during HTTP requests, or 0 for no timeout. (default: %d)", DEFAULT_HTTP_CLIENT_TIMEOUT), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcconnect=<ip>", strprintf("Send commands to node running on <ip> (default: %s)", DEFAULT_RPCCONNECT), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpccookiefile=<loc>", "Location of the auth cookie. Relative paths will be prefixed by a net-specific datadir location. (default: data dir)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcpassword=<pw>", "Password for JSON-RPC connections", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcport=<port>", strprintf("Connect to JSON-RPC on <port> (default: %u, testnet: %u, devnet: %u, regtest: %u)", defaultBaseParams->RPCPort(), testnetBaseParams->RPCPort(), devnetBaseParams->RPCPort(), regtestBaseParams->RPCPort()), ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcuser=<user>", "Username for JSON-RPC connections", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcwait", "Wait for RPC server to start", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcwallet=<walletname>", "Send RPC for non-default wallet on RPC server (needs to exactly match corresponding -wallet option passed to kerrigand). This changes the RPC endpoint used, e.g. http://127.0.0.1:9998/wallet/<walletname>", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcwaittimeout=<n>", strprintf("Timeout in seconds to wait for the RPC server to start, or 0 for no timeout. (default: %d)", DEFAULT_WAIT_CLIENT_TIMEOUT), ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::OPTIONS);
    argsman.AddArg("-stdin", "Read extra arguments from standard input, one per line until EOF/Ctrl-D (recommended for sensitive information such as passphrases). When combined with -stdinrpcpass, the first line from standard input is used for the RPC password.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-stdinrpcpass", "Read RPC password from standard input as a single line. When combined with -stdin, the first line from standard input is used for the RPC password. When combined with -stdinwalletpassphrase, -stdinrpcpass consumes the first line, and -stdinwalletpassphrase consumes the second.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-stdinwalletpassphrase", "Read wallet passphrase from standard input as a single line. When combined with -stdin, the first line from standard input is used for the wallet passphrase.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

    SetupChainParamsBaseOptions(argsman);
}

/** libevent event log callback */
static void libevent_log_cb(int severity, const char *msg)
{
    // Ignore everything other than errors
    if (severity >= EVENT_LOG_ERR) {
        throw std::runtime_error(strprintf("libevent error: %s", msg));
    }
}

//
// Exception thrown on connection error.  This error is used to determine
// when to wait if -rpcwait is given.
//
class CConnectionFailed : public std::runtime_error
{
public:

    explicit inline CConnectionFailed(const std::string& msg) :
        std::runtime_error(msg)
    {}

};

//
// This function returns either one of EXIT_ codes when it's expected to stop the process or
// CONTINUE_EXECUTION when it's expected to continue further.
//
static int AppInitRPC(int argc, char* argv[])
{
    SetupCliArgs(gArgs);
    std::string error;
    if (!gArgs.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error);
        return EXIT_FAILURE;
    }

    if (gArgs.IsArgSet("-printcrashinfo")) {
        std::cout << GetCrashInfoStrFromSerializedStr(gArgs.GetArg("-printcrashinfo", "")) << std::endl;
        return true;
    }

    if (argc < 2 || HelpRequested(gArgs) || gArgs.IsArgSet("-version")) {
        std::string strUsage = PACKAGE_NAME " RPC client version " + FormatFullVersion() + "\n";

        if (gArgs.IsArgSet("-version")) {
            strUsage += FormatParagraph(LicenseInfo());
        } else {
            strUsage += "\n"
                "Usage:  kerrigan-cli [options] <command> [params]  Send command to " PACKAGE_NAME "\n"
                "or:     kerrigan-cli [options] -named <command> [name=value]...  Send command to " PACKAGE_NAME " (with named arguments)\n"
                "or:     kerrigan-cli [options] help                List commands\n"
                "or:     kerrigan-cli [options] help <command>      Get help for a command\n";
            strUsage += "\n" + gArgs.GetHelpMessage();
        }

        tfm::format(std::cout, "%s", strUsage);
        if (argc < 2) {
            tfm::format(std::cerr, "Error: too few parameters\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }
    if (!CheckDataDirOption()) {
        tfm::format(std::cerr, "Error: Specified data directory \"%s\" does not exist.\n", gArgs.GetArg("-datadir", ""));
        return EXIT_FAILURE;
    }
    if (!gArgs.ReadConfigFiles(error, true)) {
        tfm::format(std::cerr, "Error reading configuration file: %s\n", error);
        return EXIT_FAILURE;
    }
    // Check for chain settings (BaseParams() calls are only valid after this clause)
    try {
        SelectBaseParams(gArgs.GetChainName());
    } catch (const std::exception& e) {
        tfm::format(std::cerr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }
    return CONTINUE_EXECUTION;
}


/** Reply structure for request_done to fill in */
struct HTTPReply
{
    HTTPReply() = default;

    int status{0};
    int error{-1};
    std::string body;
};

static std::string http_errorstring(int code)
{
    switch(code) {
    case EVREQ_HTTP_TIMEOUT:
        return "timeout reached";
    case EVREQ_HTTP_EOF:
        return "EOF reached";
    case EVREQ_HTTP_INVALID_HEADER:
        return "error while reading header, or invalid header";
    case EVREQ_HTTP_BUFFER_ERROR:
        return "error encountered while reading or writing";
    case EVREQ_HTTP_REQUEST_CANCEL:
        return "request was canceled";
    case EVREQ_HTTP_DATA_TOO_LONG:
        return "response body is larger than allowed";
    default:
        return "unknown";
    }
}

static void http_request_done(struct evhttp_request *req, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);

    if (req == nullptr) {
        /* If req is nullptr, it means an error occurred while connecting: the
         * error code will have been passed to http_error_cb.
         */
        reply->status = 0;
        return;
    }

    reply->status = evhttp_request_get_response_code(req);

    struct evbuffer *buf = evhttp_request_get_input_buffer(req);
    if (buf)
    {
        size_t size = evbuffer_get_length(buf);
        const char *data = (const char*)evbuffer_pullup(buf, size);
        if (data)
            reply->body = std::string(data, size);
        evbuffer_drain(buf, size);
    }
}

static void http_error_cb(enum evhttp_request_error err, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);
    reply->error = err;
}

/** Class that handles the conversion from a command-line to a JSON-RPC request,
 * as well as converting back to a JSON object that can be shown as result.
 */
class BaseRequestHandler
{
public:
    virtual ~BaseRequestHandler() = default;
    virtual UniValue PrepareRequest(const std::string& method, const std::vector<std::string>& args) = 0;
    virtual UniValue ProcessReply(const UniValue &batch_in) = 0;
};

/** Process addrinfo requests */
class AddrinfoRequestHandler : public BaseRequestHandler
{
private:
    int8_t NetworkStringToId(const std::string& str) const
    {
        for (size_t i = 0; i < NETWORKS.size(); ++i) {
            if (str == NETWORKS[i]) return i;
        }
        return UNKNOWN_NETWORK;
    }

public:
    UniValue PrepareRequest(const std::string& method, const std::vector<std::string>& args) override
    {
        if (!args.empty()) {
            throw std::runtime_error("-addrinfo takes no arguments");
        }
        UniValue params{RPCConvertValues("getnodeaddresses", std::vector<std::string>{{"0"}})};
        return JSONRPCRequestObj("getnodeaddresses", params, 1);
    }

    UniValue ProcessReply(const UniValue& reply) override
    {
        if (!reply["error"].isNull()) return reply;
        const std::vector<UniValue>& nodes{reply["result"].getValues()};
        if (!nodes.empty() && nodes.at(0)["network"].isNull()) {
            throw std::runtime_error("-addrinfo requires kerrigand server to be running v21.0 and up");
        }
        // Count the number of peers known to our node, by network.
        std::array<uint64_t, NETWORKS.size()> counts{{}};
        for (const UniValue& node : nodes) {
            std::string network_name{node["network"].get_str()};
            const int8_t network_id{NetworkStringToId(network_name)};
            if (network_id == UNKNOWN_NETWORK) continue;
            ++counts.at(network_id);
        }
        // Prepare result to return to user.
        UniValue result{UniValue::VOBJ}, addresses{UniValue::VOBJ};
        uint64_t total{0}; // Total address count
        for (size_t i = 1; i < NETWORKS.size() - 1; ++i) {
            addresses.pushKV(NETWORKS[i], counts.at(i));
            total += counts.at(i);
        }
        addresses.pushKV("total", total);
        result.pushKV("addresses_known", addresses);
        return JSONRPCReplyObj(result, NullUniValue, 1);
    }
};

/** Process getinfo requests */
class GetinfoRequestHandler: public BaseRequestHandler
{
public:
    const int ID_NETWORKINFO = 0;
    const int ID_BLOCKCHAININFO = 1;
    const int ID_WALLETINFO = 2;
    const int ID_BALANCES = 3;

    /** Create a simulated `getinfo` request. */
    UniValue PrepareRequest(const std::string& method, const std::vector<std::string>& args) override
    {
        if (!args.empty()) {
            throw std::runtime_error("-getinfo takes no arguments");
        }
        UniValue result(UniValue::VARR);
        result.push_back(JSONRPCRequestObj("getnetworkinfo", NullUniValue, ID_NETWORKINFO));
        result.push_back(JSONRPCRequestObj("getblockchaininfo", NullUniValue, ID_BLOCKCHAININFO));
        result.push_back(JSONRPCRequestObj("getwalletinfo", NullUniValue, ID_WALLETINFO));
        result.push_back(JSONRPCRequestObj("getbalances", NullUniValue, ID_BALANCES));
        return result;
    }

    /** Collect values from the batch and form a simulated `getinfo` reply. */
    UniValue ProcessReply(const UniValue &batch_in) override
    {
        UniValue result(UniValue::VOBJ);
        const std::vector<UniValue> batch = JSONRPCProcessBatchReply(batch_in);
        // Errors in getnetworkinfo() and getblockchaininfo() are fatal, pass them on;
        // getwalletinfo() and getbalances() are allowed to fail if there is no wallet.
        if (!batch[ID_NETWORKINFO]["error"].isNull()) {
            return batch[ID_NETWORKINFO];
        }
        if (!batch[ID_BLOCKCHAININFO]["error"].isNull()) {
            return batch[ID_BLOCKCHAININFO];
        }
        result.pushKV("version", batch[ID_NETWORKINFO]["result"]["version"]);
        result.pushKV("blocks", batch[ID_BLOCKCHAININFO]["result"]["blocks"]);
        result.pushKV("headers", batch[ID_BLOCKCHAININFO]["result"]["headers"]);
        result.pushKV("verificationprogress", batch[ID_BLOCKCHAININFO]["result"]["verificationprogress"]);
        result.pushKV("timeoffset", batch[ID_NETWORKINFO]["result"]["timeoffset"]);

        UniValue connections(UniValue::VOBJ);
        connections.pushKV("in", batch[ID_NETWORKINFO]["result"]["connections_in"]);
        connections.pushKV("out", batch[ID_NETWORKINFO]["result"]["connections_out"]);
        connections.pushKV("total", batch[ID_NETWORKINFO]["result"]["connections"]);
        connections.pushKV("mn_in", batch[ID_NETWORKINFO]["result"]["connections_mn_in"]);
        connections.pushKV("mn_out", batch[ID_NETWORKINFO]["result"]["connections_mn_out"]);
        connections.pushKV("mn_total", batch[ID_NETWORKINFO]["result"]["connections_mn"]);
        result.pushKV("connections", connections);

        result.pushKV("networks", batch[ID_NETWORKINFO]["result"]["networks"]);
        result.pushKV("difficulty", batch[ID_BLOCKCHAININFO]["result"]["difficulty"]);
        result.pushKV("chain", UniValue(batch[ID_BLOCKCHAININFO]["result"]["chain"]));
        if (!batch[ID_WALLETINFO]["result"].isNull()) {
            result.pushKV("has_wallet", true);
            result.pushKV("keypoolsize", batch[ID_WALLETINFO]["result"]["keypoolsize"]);
            result.pushKV("walletname", batch[ID_WALLETINFO]["result"]["walletname"]);
            if (!batch[ID_WALLETINFO]["result"]["unlocked_until"].isNull()) {
                result.pushKV("unlocked_until", batch[ID_WALLETINFO]["result"]["unlocked_until"]);
            }
            result.pushKV("paytxfee", batch[ID_WALLETINFO]["result"]["paytxfee"]);
        }
        if (!batch[ID_BALANCES]["result"].isNull()) {
            result.pushKV("balance", batch[ID_BALANCES]["result"]["mine"]["trusted"]);
        }
        result.pushKV("relayfee", batch[ID_NETWORKINFO]["result"]["relayfee"]);
        result.pushKV("warnings", batch[ID_NETWORKINFO]["result"]["warnings"]);
        return JSONRPCReplyObj(result, NullUniValue, 1);
    }
};

/** Process netinfo requests */
class NetinfoRequestHandler : public BaseRequestHandler
{
private:
    static constexpr uint8_t MAX_DETAIL_LEVEL{4};
    std::array<std::array<uint16_t, NETWORKS.size() + 1>, 3> m_counts{{{}}}; //!< Peer counts by (in/out/total, networks/total)
    uint8_t m_block_relay_peers_count{0};
    uint8_t m_manual_peers_count{0};
    int8_t NetworkStringToId(const std::string& str) const
    {
        for (size_t i = 0; i < NETWORKS.size(); ++i) {
            if (str == NETWORKS[i]) return i;
        }
        return UNKNOWN_NETWORK;
    }
    uint8_t m_details_level{0}; //!< Optional user-supplied arg to set dashboard details level
    bool DetailsRequested() const { return m_details_level > 0 && m_details_level < 5; }
    bool IsAddressSelected() const { return m_details_level == 2 || m_details_level == 4; }
    bool IsVersionSelected() const { return m_details_level == 3 || m_details_level == 4; }
    bool m_is_asmap_on{false};
    size_t m_max_addr_length{0};
    size_t m_max_addr_processed_length{5};
    size_t m_max_addr_rate_limited_length{6};
    size_t m_max_age_length{5};
    size_t m_max_id_length{2};
    struct Peer {
        std::string addr;
        std::string sub_version;
        std::string conn_type;
        std::string network;
        std::string age;
        std::string transport_protocol_type;
        double min_ping;
        double ping;
        int64_t addr_processed;
        int64_t addr_rate_limited;
        int64_t last_blck;
        int64_t last_recv;
        int64_t last_send;
        int64_t last_trxn;
        int id;
        int mapped_as;
        int version;
        bool is_addr_relay_enabled;
        bool is_bip152_hb_from;
        bool is_bip152_hb_to;
        bool is_outbound;
        bool is_tx_relay;
        bool operator<(const Peer& rhs) const { return std::tie(is_outbound, min_ping) < std::tie(rhs.is_outbound, rhs.min_ping); }
    };
    std::vector<Peer> m_peers;
    std::string ChainToString() const
    {
        if (gArgs.GetChainName() == CBaseChainParams::TESTNET) return " testnet";
        if (gArgs.GetChainName() == CBaseChainParams::DEVNET) return " devnet";
        if (gArgs.GetChainName() == CBaseChainParams::REGTEST) return " regtest";
        return "";
    }
    std::string PingTimeToString(double seconds) const
    {
        if (seconds < 0) return "";
        const double milliseconds{round(1000 * seconds)};
        return milliseconds > 999999 ? "-" : ToString(milliseconds);
    }
    std::string ConnectionTypeForNetinfo(const std::string& conn_type) const
    {
        if (conn_type == "outbound-full-relay") return "full";
        if (conn_type == "block-relay-only") return "block";
        if (conn_type == "manual" || conn_type == "feeler") return conn_type;
        if (conn_type == "addr-fetch") return "addr";
        return "";
    }

public:
    static constexpr int ID_PEERINFO = 0;
    static constexpr int ID_NETWORKINFO = 1;

    UniValue PrepareRequest(const std::string& method, const std::vector<std::string>& args) override
    {
        if (!args.empty()) {
            uint8_t n{0};
            if (ParseUInt8(args.at(0), &n)) {
                m_details_level = std::min(n, MAX_DETAIL_LEVEL);
            } else {
                throw std::runtime_error(strprintf("invalid -netinfo argument: %s\nFor more information, run: kerrigan-cli -netinfo help", args.at(0)));
            }
        }
        UniValue result(UniValue::VARR);
        result.push_back(JSONRPCRequestObj("getpeerinfo", NullUniValue, ID_PEERINFO));
        result.push_back(JSONRPCRequestObj("getnetworkinfo", NullUniValue, ID_NETWORKINFO));
        return result;
    }

    UniValue ProcessReply(const UniValue& batch_in) override
    {
        const std::vector<UniValue> batch{JSONRPCProcessBatchReply(batch_in)};
        if (!batch[ID_PEERINFO]["error"].isNull()) return batch[ID_PEERINFO];
        if (!batch[ID_NETWORKINFO]["error"].isNull()) return batch[ID_NETWORKINFO];

        const UniValue& networkinfo{batch[ID_NETWORKINFO]["result"]};
        if (networkinfo["version"].getInt<int>() < 200000) {
            throw std::runtime_error("-netinfo requires kerrigand server to be running v20.0 and up");
        }
        const int64_t time_now{TicksSinceEpoch<std::chrono::seconds>(CliClock::now())};

        // Count peer connection totals, and if DetailsRequested(), store peer data in a vector of structs.
        for (const UniValue& peer : batch[ID_PEERINFO]["result"].getValues()) {
            const std::string network{peer["network"].get_str()};
            const int8_t network_id{NetworkStringToId(network)};
            if (network_id == UNKNOWN_NETWORK) continue;
            const bool is_outbound{!peer["inbound"].get_bool()};
            const bool is_tx_relay{peer["relaytxes"].isNull() ? true : peer["relaytxes"].get_bool()};
            const std::string conn_type{peer["connection_type"].get_str()};
            ++m_counts.at(is_outbound).at(network_id);        // in/out by network
            ++m_counts.at(is_outbound).at(NETWORKS.size());   // in/out overall
            ++m_counts.at(2).at(network_id);                  // total by network
            ++m_counts.at(2).at(NETWORKS.size());             // total overall
            if (conn_type == "block-relay-only") ++m_block_relay_peers_count;
            if (conn_type == "manual") ++m_manual_peers_count;
            if (DetailsRequested()) {
                // Push data for this peer to the peers vector.
                const int peer_id{peer["id"].getInt<int>()};
                const int mapped_as{peer["mapped_as"].isNull() ? 0 : peer["mapped_as"].getInt<int>()};
                const int version{peer["version"].getInt<int>()};
                const int64_t addr_processed{peer["addr_processed"].isNull() ? 0 : peer["addr_processed"].getInt<int64_t>()};
                const int64_t addr_rate_limited{peer["addr_rate_limited"].isNull() ? 0 : peer["addr_rate_limited"].getInt<int64_t>()};
                const int64_t conn_time{peer["conntime"].getInt<int64_t>()};
                const int64_t last_blck{peer["last_block"].getInt<int64_t>()};
                const int64_t last_recv{peer["lastrecv"].getInt<int64_t>()};
                const int64_t last_send{peer["lastsend"].getInt<int64_t>()};
                const int64_t last_trxn{peer["last_transaction"].getInt<int64_t>()};
                const double min_ping{peer["minping"].isNull() ? -1 : peer["minping"].get_real()};
                const double ping{peer["pingtime"].isNull() ? -1 : peer["pingtime"].get_real()};
                const std::string addr{peer["addr"].get_str()};
                const std::string age{conn_time == 0 ? "" : ToString((time_now - conn_time) / 60)};
                const std::string sub_version{peer["subver"].get_str()};
                const std::string transport{peer["transport_protocol_type"].isNull() ? "v1" : peer["transport_protocol_type"].get_str()};
                const bool is_addr_relay_enabled{peer["addr_relay_enabled"].isNull() ? false : peer["addr_relay_enabled"].get_bool()};
                const bool is_bip152_hb_from{peer["bip152_hb_from"].get_bool()};
                const bool is_bip152_hb_to{peer["bip152_hb_to"].get_bool()};
                m_peers.push_back({addr, sub_version, conn_type, NETWORK_SHORT_NAMES[network_id], age, transport, min_ping, ping, addr_processed, addr_rate_limited, last_blck, last_recv, last_send, last_trxn, peer_id, mapped_as, version, is_addr_relay_enabled, is_bip152_hb_from, is_bip152_hb_to, is_outbound, is_tx_relay});
                m_max_addr_length = std::max(addr.length() + 1, m_max_addr_length);
                m_max_addr_processed_length = std::max(ToString(addr_processed).length(), m_max_addr_processed_length);
                m_max_addr_rate_limited_length = std::max(ToString(addr_rate_limited).length(), m_max_addr_rate_limited_length);
                m_max_age_length = std::max(age.length(), m_max_age_length);
                m_max_id_length = std::max(ToString(peer_id).length(), m_max_id_length);
                m_is_asmap_on |= (mapped_as != 0);
            }
        }

        // Generate report header.
        std::string result{strprintf("%s client %s%s - server %i%s\n\n", PACKAGE_NAME, FormatFullVersion(), ChainToString(), networkinfo["protocolversion"].getInt<int>(), networkinfo["subversion"].get_str())};

        // Report detailed peer connections list sorted by direction and minimum ping time.
        if (DetailsRequested() && !m_peers.empty()) {
            std::sort(m_peers.begin(), m_peers.end());
            result += strprintf("<->   type   net  v  mping   ping send recv  txn  blk  hb %*s%*s%*s ",
                                m_max_addr_processed_length, "addrp",
                                m_max_addr_rate_limited_length, "addrl",
                                m_max_age_length, "age");
            if (m_is_asmap_on) result += " asmap ";
            result += strprintf("%*s %-*s%s\n", m_max_id_length, "id", IsAddressSelected() ? m_max_addr_length : 0, IsAddressSelected() ? "address" : "", IsVersionSelected() ? "version" : "");
            for (const Peer& peer : m_peers) {
                std::string version{ToString(peer.version) + peer.sub_version};
                result += strprintf(
                    "%3s %6s %5s %2s%7s%7s%5s%5s%5s%5s  %2s %*s%*s%*s%*i %*s %-*s%s\n",
                    peer.is_outbound ? "out" : "in",
                    ConnectionTypeForNetinfo(peer.conn_type),
                    peer.network,
                    peer.transport_protocol_type.starts_with('v') == 0 ? peer.transport_protocol_type[1] : ' ',
                    PingTimeToString(peer.min_ping),
                    PingTimeToString(peer.ping),
                    peer.last_send ? ToString(time_now - peer.last_send) : "",
                    peer.last_recv ? ToString(time_now - peer.last_recv) : "",
                    peer.last_trxn ? ToString((time_now - peer.last_trxn) / 60) : peer.is_tx_relay ? "" : "*",
                    peer.last_blck ? ToString((time_now - peer.last_blck) / 60) : "",
                    strprintf("%s%s", peer.is_bip152_hb_to ? "." : " ", peer.is_bip152_hb_from ? "*" : " "),
                    m_max_addr_processed_length, // variable spacing
                    peer.addr_processed ? ToString(peer.addr_processed) : peer.is_addr_relay_enabled ? "" : ".",
                    m_max_addr_rate_limited_length, // variable spacing
                    peer.addr_rate_limited ? ToString(peer.addr_rate_limited) : "",
                    m_max_age_length, // variable spacing
                    peer.age,
                    m_is_asmap_on ? 7 : 0, // variable spacing
                    m_is_asmap_on && peer.mapped_as ? ToString(peer.mapped_as) : "",
                    m_max_id_length, // variable spacing
                    peer.id,
                    IsAddressSelected() ? m_max_addr_length : 0, // variable spacing
                    IsAddressSelected() ? peer.addr : "",
                    IsVersionSelected() && version != "0" ? version : "");
            }
            result += strprintf("                        ms     ms  sec  sec  min  min                %*s\n\n", m_max_age_length, "min");
        }

        // Report peer connection totals by type.
        result += "     ";
        std::vector<int8_t> reachable_networks;
        for (const UniValue& network : networkinfo["networks"].getValues()) {
            if (network["reachable"].get_bool()) {
                const std::string& network_name{network["name"].get_str()};
                const int8_t network_id{NetworkStringToId(network_name)};
                if (network_id == UNKNOWN_NETWORK) continue;
                result += strprintf("%8s", network_name); // column header
                reachable_networks.push_back(network_id);
            }
        };

        for (const size_t network_id : UNREACHABLE_NETWORK_IDS) {
            if (m_counts.at(2).at(network_id) == 0) continue;
            result += strprintf("%8s", NETWORK_SHORT_NAMES.at(network_id)); // column header
            reachable_networks.push_back(network_id);
        }

        result += "   total   block";
        if (m_manual_peers_count) result += "  manual";

        const std::array rows{"in", "out", "total"};
        for (size_t i = 0; i < rows.size(); ++i) {
            result += strprintf("\n%-5s", rows[i]); // row header
            for (int8_t n : reachable_networks) {
                result += strprintf("%8i", m_counts.at(i).at(n)); // network peers count
            }
            result += strprintf("   %5i", m_counts.at(i).at(NETWORKS.size())); // total peers count
            if (i == 1) { // the outbound row has two extra columns for block relay and manual peer counts
                result += strprintf("   %5i", m_block_relay_peers_count);
                if (m_manual_peers_count) result += strprintf("   %5i", m_manual_peers_count);
            }
        }

        // Report local addresses, ports, and scores.
        result += "\n\nLocal addresses";
        const std::vector<UniValue>& local_addrs{networkinfo["localaddresses"].getValues()};
        if (local_addrs.empty()) {
            result += ": n/a\n";
        } else {
            size_t max_addr_size{0};
            for (const UniValue& addr : local_addrs) {
                max_addr_size = std::max(addr["address"].get_str().length() + 1, max_addr_size);
            }
            for (const UniValue& addr : local_addrs) {
                result += strprintf("\n%-*s    port %6i    score %6i", max_addr_size, addr["address"].get_str(), addr["port"].getInt<int>(), addr["score"].getInt<int>());
            }
        }

        return JSONRPCReplyObj(UniValue{result}, NullUniValue, 1);
    }

    const std::string m_help_doc{
        "-netinfo level|\"help\" \n\n"
        "Returns a network peer connections dashboard with information from the remote server.\n"
        "This human-readable interface will change regularly and is not intended to be a stable API.\n"
        "Under the hood, -netinfo fetches the data by calling getpeerinfo and getnetworkinfo.\n"
        + strprintf("An optional integer argument from 0 to %d can be passed for different peers listings; %d to 255 are parsed as %d.\n", MAX_DETAIL_LEVEL, MAX_DETAIL_LEVEL, MAX_DETAIL_LEVEL) +
        "Pass \"help\" to see this detailed help documentation.\n"
        "If more than one argument is passed, only the first one is read and parsed.\n"
        "Suggestion: use with the Linux watch(1) command for a live dashboard; see example below.\n\n"
        "Arguments:\n"
        + strprintf("1. level (integer 0-%d, optional)  Specify the info level of the peers dashboard (default 0):\n", MAX_DETAIL_LEVEL) +
        "                                  0 - Peer counts for each reachable network as well as for block relay peers\n"
        "                                      and manual peers, and the list of local addresses and ports\n"
        "                                  1 - Like 0 but preceded by a peers listing (without address and version columns)\n"
        "                                  2 - Like 1 but with an address column\n"
        "                                  3 - Like 1 but with a version column\n"
        "                                  4 - Like 1 but with both address and version columns\n"
        "2. help (string \"help\", optional) Print this help documentation instead of the dashboard.\n\n"
        "Result:\n\n"
        + strprintf("* The peers listing in levels 1-%d displays all of the peers sorted by direction and minimum ping time:\n\n", MAX_DETAIL_LEVEL) +
        "  Column   Description\n"
        "  ------   -----------\n"
        "  <->      Direction\n"
        "           \"in\"  - inbound connections are those initiated by the peer\n"
        "           \"out\" - outbound connections are those initiated by us\n"
        "  type     Type of peer connection\n"
        "           \"full\"   - full relay, the default\n"
        "           \"block\"  - block relay; like full relay but does not relay transactions or addresses\n"
        "           \"manual\" - peer we manually added using RPC addnode or the -addnode/-connect config options\n"
        "           \"feeler\" - short-lived connection for testing addresses\n"
        "           \"addr\"   - address fetch; short-lived connection for requesting addresses\n"
        "  net      Network the peer connected through (\"ipv4\", \"ipv6\", \"onion\", \"i2p\", \"cjdns\", or \"npr\" (not publicly routable))\n"
        "  v        Version of transport protocol used for the connection\n"
        "  mping    Minimum observed ping time, in milliseconds (ms)\n"
        "  ping     Last observed ping time, in milliseconds (ms)\n"
        "  send     Time since last message sent to the peer, in seconds\n"
        "  recv     Time since last message received from the peer, in seconds\n"
        "  txn      Time since last novel transaction received from the peer and accepted into our mempool, in minutes\n"
        "           \"*\" - we do not relay transactions to this peer (relaytxes is false)\n"
        "  blk      Time since last novel block passing initial validity checks received from the peer, in minutes\n"
        "  hb       High-bandwidth BIP152 compact block relay\n"
        "           \".\" (to)   - we selected the peer as a high-bandwidth peer\n"
        "           \"*\" (from) - the peer selected us as a high-bandwidth peer\n"
        "  addrp    Total number of addresses processed, excluding those dropped due to rate limiting\n"
        "           \".\" - we do not relay addresses to this peer (addr_relay_enabled is false)\n"
        "  addrl    Total number of addresses dropped due to rate limiting\n"
        "  age      Duration of connection to the peer, in minutes\n"
        "  asmap    Mapped AS (Autonomous System) number in the BGP route to the peer, used for diversifying\n"
        "           peer selection (only displayed if the -asmap config option is set)\n"
        "  id       Peer index, in increasing order of peer connections since node startup\n"
        "  address  IP address and port of the peer\n"
        "  version  Peer version and subversion concatenated, e.g. \"70016/Satoshi:21.0.0/\"\n\n"
        "* The peer counts table displays the number of peers for each reachable network as well as\n"
        "  the number of block relay peers and manual peers.\n\n"
        "* The local addresses table lists each local address broadcast by the node, the port, and the score.\n\n"
        "Examples:\n\n"
        "Peer counts table of reachable networks and list of local addresses\n"
        "> kerrigan-cli -netinfo\n\n"
        "The same, preceded by a peers listing without address and version columns\n"
        "> kerrigan-cli -netinfo 1\n\n"
        "Full dashboard\n"
        + strprintf("> kerrigan-cli -netinfo %d\n\n", MAX_DETAIL_LEVEL) +
        "Full live dashboard, adjust --interval or --no-title as needed (Linux)\n"
        + strprintf("> watch --interval 1 --no-title kerrigan-cli -netinfo %d\n\n", MAX_DETAIL_LEVEL) +
        "See this help\n"
        "> kerrigan-cli -netinfo help\n"};
};

/** Process RPC generatetoaddress request. */
class GenerateToAddressRequestHandler : public BaseRequestHandler
{
public:
    UniValue PrepareRequest(const std::string& method, const std::vector<std::string>& args) override
    {
        address_str = args.at(1);
        UniValue params{RPCConvertValues("generatetoaddress", args)};
        return JSONRPCRequestObj("generatetoaddress", params, 1);
    }

    UniValue ProcessReply(const UniValue &reply) override
    {
        UniValue result(UniValue::VOBJ);
        result.pushKV("address", address_str);
        result.pushKV("blocks", reply.get_obj()["result"]);
        return JSONRPCReplyObj(result, NullUniValue, 1);
    }
protected:
    std::string address_str;
};

// ----------------------------------------------------------------------------
// Recovery front-end (WS-HEAL v2 8.3): `kerrigan-cli doctor` and
// `kerrigan-cli repair`. The daemon's getrecoverystatus/repairnode contract
// (contract_version 2) carries stable machine ids ONLY - this file owns the
// CLI's human-readable English for every id, and must tolerate unknown ids
// from newer daemons (rendered verbatim). `debug_detail` is never displayed.
// ----------------------------------------------------------------------------

//! CLI copy for daemon_mode ids. Unknown ids are shown verbatim.
static std::string RecoveryModeText(const std::string& id)
{
    if (id == "starting") return "starting up";
    if (id == "syncing") return "syncing with the network";
    if (id == "normal") return "healthy";
    if (id == "degraded" || id == "running_degraded") return "DEGRADED - running, but needs attention";
    if (id == "quarantined") return "QUARANTINED - paused for safety after detecting a data problem";
    if (id == "crippled_wait") return "AWAITING REPAIR - startup found damaged data and is holding";
    if (id == "repair_armed") return "REPAIR ARMED - restart the daemon to execute the repair";
    return id + " (unrecognized mode - this kerrigan-cli may be older than the daemon)";
}

//! CLI copy for recommended_action ids. Unknown ids are shown verbatim.
static std::string RecoveryActionText(const std::string& id)
{
    if (id == "ACTION_NONE") return "none - the node is healthy";
    if (id == "ACTION_WAIT_AUTO") return "wait - automatic recovery is working on it";
    if (id == "ACTION_GUIDED_NETWORK_REPAIR") return "run: kerrigan-cli repair network   (resets peer data only; no chain wipe)";
    if (id == "ACTION_GUIDED_REPAIR") return "run: kerrigan-cli repair   (guided wipe + resync; wallet preserved)";
    if (id == "ACTION_DIAGNOSE_SUPPORT") return "manual diagnosis needed - check debug.log and ask for support";
    if (id == "ACTION_CHECK_DISK") return "check disk health and free space before attempting repair";
    if (id == "ACTION_MANAGE_NODE_ELSEWHERE") return "manage this node from the machine/wallet that runs it";
    return id + " (unrecognized action)";
}

//! CLI copy for finding codes. Unknown codes are shown verbatim.
static std::string RecoveryFindingText(const std::string& code)
{
    if (code == "NET_LOCAL_LINK_DOWN") return "local network link appears down (DNS/dial probes failing)";
    if (code == "NET_ISOLATED") return "no usable peer connections";
    if (code == "NET_ECLIPSE_SUSPECT") return "peers are known but none work - possible eclipse or stale address book";
    if (code == "TIP_STALLED_NETWORK") return "chain tip stalled (network-attributable)";
    if (code == "TIP_STALLED_NONNETWORK") return "chain tip stalled (peers look fine - NOT network-related)";
    if (code == "DRIFT_EVODB") return "EvoDB disagrees with the chain tip (data corruption)";
    if (code == "DRIFT_SAPLING") return "Sapling database disagrees with the chain tip (data corruption)";
    if (code == "WITNESS_STALE") return "shielded note witnesses are stale";
    if (code == "REPAIR_RATE_LIMITED") return "repair wipe-rate guard tripped (repeated repairs; suspect the disk)";
    if (code == "CHAINSTATE_LOAD_FAILED") return "the chainstate failed to load at startup";
    if (code == "NODE_ABORTED") return "the previous run aborted";
    return code + " (unrecognized finding)";
}

//! CLI copy for repair.phase ids. Unknown ids are shown verbatim.
static std::string RecoveryPhaseText(const std::string& id)
{
    if (id == "none") return "not active";
    if (id == "armed") return "armed - waiting for the daemon to restart";
    if (id == "shutting_down") return "shutting down to execute the wipe";
    if (id == "wiping") return "wiping damaged data";
    if (id == "bootstrapping") return "fetching bootstrap data";
    if (id == "syncing") return "resyncing the chain from the network";
    if (id == "rebuilding_witnesses") return "rebuilding shielded note witnesses";
    if (id == "verifying") return "verifying the repaired state";
    if (id == "done") return "completed";
    if (id == "failed") return "FAILED - see debug.log";
    return id + " (unrecognized phase)";
}

static std::string FormatByteCount(int64_t bytes)
{
    if (bytes < 0) return "unknown";
    constexpr int64_t KB{1000}, MB{1000 * KB}, GB{1000 * MB};
    if (bytes >= GB) return strprintf("%.1f GB", bytes / double(GB));
    if (bytes >= MB) return strprintf("%.1f MB", bytes / double(MB));
    if (bytes >= KB) return strprintf("%.1f kB", bytes / double(KB));
    return strprintf("%d B", bytes);
}

//! One formatted line per finding: CLI English + machine evidence fields.
//! `debug_detail` is deliberately never rendered (contract 7.1).
static std::string FormatFindingLine(const UniValue& finding)
{
    const std::string code{finding["code"].isStr() ? finding["code"].get_str() : "?"};
    std::string line{strprintf("  - %s: %s", code, RecoveryFindingText(code))};
    if (finding["since"].isNum()) {
        line += strprintf("\n      since: %s", FormatISO8601DateTime(finding["since"].getInt<int64_t>()));
    }
    const UniValue& evidence{finding["evidence"]};
    if (evidence.isObject() && !evidence.getKeys().empty()) {
        std::string ev;
        for (const std::string& key : evidence.getKeys()) {
            if (!ev.empty()) ev += ", ";
            ev += key + "=" + evidence[key].getValStr();
        }
        line += "\n      evidence: " + ev;
    }
    return line;
}

/** Process `doctor` requests: a human-readable rendering of
 *  getrecoverystatus, in the spirit of -getinfo/-netinfo. */
class DoctorRequestHandler : public BaseRequestHandler
{
public:
    UniValue PrepareRequest(const std::string& method, const std::vector<std::string>& args) override
    {
        if (!args.empty()) {
            throw std::runtime_error("doctor takes no arguments");
        }
        return JSONRPCRequestObj("getrecoverystatus", NullUniValue, 1);
    }

    UniValue ProcessReply(const UniValue& reply) override
    {
        const UniValue& error{reply["error"]};
        if (!error.isNull()) {
            if (error["code"].isNum() && error["code"].getInt<int>() == RPC_METHOD_NOT_FOUND) {
                throw std::runtime_error("this kerrigand does not support guided recovery (getrecoverystatus not found) - upgrade the daemon");
            }
            return reply;
        }
        const UniValue& r{reply["result"]};
        const std::string mode{r["daemon_mode"].isStr() ? r["daemon_mode"].get_str() : "?"};
        const std::string action{r["recommended_action"].isStr() ? r["recommended_action"].get_str() : "?"};
        const UniValue& sync{r["sync"]};
        const UniValue& auto_block{r["auto"]};
        const UniValue& repair{r["repair"]};
        const UniValue& guards{r["guards"]};

        std::string out;
        out += "Kerrigan node health report\n";
        out += "---------------------------\n";
        out += strprintf("Mode:      %s\n", RecoveryModeText(mode));

        const UniValue& findings{r["findings"]};
        if (!findings.isArray() || findings.empty()) {
            out += "Findings:  (none)\n";
        } else {
            out += strprintf("Findings:  %d active\n", findings.size());
            for (const UniValue& finding : findings.getValues()) {
                out += FormatFindingLine(finding) + "\n";
            }
        }
        out += strprintf("Action:    %s\n", RecoveryActionText(action));

        const int64_t height{sync["height"].isNum() ? sync["height"].getInt<int64_t>() : 0};
        const int64_t target{sync["target_height"].isNum() ? sync["target_height"].getInt<int64_t>() : 0};
        std::string progress_txt;
        if (target > 0) progress_txt = strprintf(" of %d", target);
        out += strprintf("Sync:      height %d%s, tip age %ds (expected block spacing %ds)\n",
                         height, progress_txt,
                         sync["tip_age_secs"].isNum() ? sync["tip_age_secs"].getInt<int64_t>() : 0,
                         sync["expected_spacing_secs"].isNum() ? sync["expected_spacing_secs"].getInt<int64_t>() : 0);

        out += strprintf("Self-heal: ladder stage %s, cycles used %s of %s\n",
                         auto_block["ladder_stage"].getValStr(),
                         auto_block["cycles_used"].getValStr(),
                         auto_block["cycles_max"].getValStr());

        const std::string phase{repair["phase"].isStr() ? repair["phase"].get_str() : "?"};
        out += strprintf("Repair:    %s\n", RecoveryPhaseText(phase));
        if (phase != "none" && phase != "done") {
            // Witness counts of 0/0 mean "count unavailable" (the daemon never
            // fabricates progress); render honestly, never as "0 of 0".
            const int64_t w_done{repair["witnesses_rebuilt"].isNum() ? repair["witnesses_rebuilt"].getInt<int64_t>() : 0};
            const int64_t w_total{repair["witnesses_total"].isNum() ? repair["witnesses_total"].getInt<int64_t>() : 0};
            if (phase == "rebuilding_witnesses") {
                if (w_total == 0) {
                    out += "           witnesses: rebuilding (count unavailable)\n";
                } else {
                    out += strprintf("           witnesses: %d of %d rebuilt\n", w_done, w_total);
                }
            }
            if (repair["eta_secs"].isNum()) {
                out += strprintf("           eta: ~%ds\n", repair["eta_secs"].getInt<int64_t>());
            }
        }

        out += strprintf("Guards:    repair attempts %s of %s (6h window), wipes %s of %s (7d window)",
                         guards["attempts_used"].getValStr(), guards["attempts_max"].getValStr(),
                         guards["wipes_in_window"].getValStr(), guards["wipes_max"].getValStr());

        return JSONRPCReplyObj(UniValue{out}, NullUniValue, 1);
    }
};

/** Process default single requests */
class DefaultRequestHandler: public BaseRequestHandler {
public:
    UniValue PrepareRequest(const std::string& method, const std::vector<std::string>& args) override
    {
        UniValue params;
        if(gArgs.GetBoolArg("-named", DEFAULT_NAMED)) {
            params = RPCConvertNamedValues(method, args);
        } else {
            params = RPCConvertValues(method, args);
        }
        return JSONRPCRequestObj(method, params, 1);
    }

    UniValue ProcessReply(const UniValue &reply) override
    {
        return reply.get_obj();
    }
};

static UniValue CallRPC(BaseRequestHandler* rh, const std::string& strMethod, const std::vector<std::string>& args, const std::optional<std::string>& rpcwallet = {})
{
    std::string host;
    // In preference order, we choose the following for the port:
    //     1. -rpcport
    //     2. port in -rpcconnect (ie following : in ipv4 or ]: in ipv6)
    //     3. default port for chain
    uint16_t port{BaseParams().RPCPort()};
    SplitHostPort(gArgs.GetArg("-rpcconnect", DEFAULT_RPCCONNECT), port, host);
    port = static_cast<uint16_t>(gArgs.GetIntArg("-rpcport", port));

    // Obtain event base
    raii_event_base base = obtain_event_base();

    // Synchronously look up hostname
    raii_evhttp_connection evcon = obtain_evhttp_connection_base(base.get(), host, port);

    // Set connection timeout
    {
        const int timeout = gArgs.GetIntArg("-rpcclienttimeout", DEFAULT_HTTP_CLIENT_TIMEOUT);
        if (timeout > 0) {
            evhttp_connection_set_timeout(evcon.get(), timeout);
        } else {
            // Indefinite request timeouts are not possible in libevent-http, so we
            // set the timeout to a very long time period instead.

            constexpr int YEAR_IN_SECONDS = 31556952; // Average length of year in Gregorian calendar
            evhttp_connection_set_timeout(evcon.get(), 5 * YEAR_IN_SECONDS);
        }
    }

    HTTPReply response;
    raii_evhttp_request req = obtain_evhttp_request(http_request_done, (void*)&response);
    if (req == nullptr) {
        throw std::runtime_error("create http request failed");
    }

    evhttp_request_set_error_cb(req.get(), http_error_cb);

    // Get credentials
    std::string strRPCUserColonPass;
    bool failedToGetAuthCookie = false;
    if (gArgs.GetArg("-rpcpassword", "") == "") {
        // Try fall back to cookie-based authentication if no password is provided
        if (!GetAuthCookie(&strRPCUserColonPass)) {
            failedToGetAuthCookie = true;
        }
    } else {
        strRPCUserColonPass = gArgs.GetArg("-rpcuser", "") + ":" + gArgs.GetArg("-rpcpassword", "");
    }

    struct evkeyvalq* output_headers = evhttp_request_get_output_headers(req.get());
    assert(output_headers);
    evhttp_add_header(output_headers, "Host", host.c_str());
    evhttp_add_header(output_headers, "Connection", "close");
    evhttp_add_header(output_headers, "Content-Type", "application/json");
    evhttp_add_header(output_headers, "Authorization", (std::string("Basic ") + EncodeBase64(strRPCUserColonPass)).c_str());

    // Attach request data
    std::string strRequest = rh->PrepareRequest(strMethod, args).write() + "\n";
    struct evbuffer* output_buffer = evhttp_request_get_output_buffer(req.get());
    assert(output_buffer);
    evbuffer_add(output_buffer, strRequest.data(), strRequest.size());

    // check if we should use a special wallet endpoint
    std::string endpoint = "/";
    if (rpcwallet) {
        char* encodedURI = evhttp_uriencode(rpcwallet->data(), rpcwallet->size(), false);
        if (encodedURI) {
            endpoint = "/wallet/" + std::string(encodedURI);
            free(encodedURI);
        } else {
            throw CConnectionFailed("uri-encode failed");
        }
    }
    int r = evhttp_make_request(evcon.get(), req.get(), EVHTTP_REQ_POST, endpoint.c_str());
    req.release(); // ownership moved to evcon in above call
    if (r != 0) {
        throw CConnectionFailed("send http request failed");
    }

    event_base_dispatch(base.get());

    if (response.status == 0) {
        std::string responseErrorMessage;
        if (response.error != -1) {
            responseErrorMessage = strprintf(" (error code %d - \"%s\")", response.error, http_errorstring(response.error));
        }
        throw CConnectionFailed(strprintf("Could not connect to the server %s:%d%s\n\n"
                    "Make sure the kerrigand server is running and that you are connecting to the correct RPC port.\n"
                    "Use \"kerrigan-cli -help\" for more info.",
                    host, port, responseErrorMessage));
    } else if (response.status == HTTP_UNAUTHORIZED) {
        if (failedToGetAuthCookie) {
            throw std::runtime_error(strprintf(
                "Could not locate RPC credentials. No authentication cookie could be found, and RPC password is not set.  See -rpcpassword and -stdinrpcpass.  Configuration file: (%s)",
                fs::PathToString(GetConfigFile(gArgs.GetPathArg("-conf", BITCOIN_CONF_FILENAME)))));
        } else {
            throw std::runtime_error("Authorization failed: Incorrect rpcuser or rpcpassword");
        }
    } else if (response.status == HTTP_SERVICE_UNAVAILABLE) {
        throw std::runtime_error(strprintf("Server response: %s", response.body));
    } else if (response.status >= 400 && response.status != HTTP_BAD_REQUEST && response.status != HTTP_NOT_FOUND && response.status != HTTP_INTERNAL_SERVER_ERROR)
        throw std::runtime_error(strprintf("server returned HTTP error %d", response.status));
    else if (response.body.empty())
        throw std::runtime_error("no response from server");

    // Parse reply
    UniValue valReply(UniValue::VSTR);
    if (!valReply.read(response.body))
        throw std::runtime_error("couldn't parse reply from server");
    UniValue reply = rh->ProcessReply(valReply);
    if (reply.empty())
        throw std::runtime_error("expected reply to have result, error and id properties");

    return reply;
}

/**
 * ConnectAndCallRPC wraps CallRPC with -rpcwait and an exception handler.
 *
 * @param[in] rh         Pointer to RequestHandler.
 * @param[in] strMethod  Reference to const string method to forward to CallRPC.
 * @param[in] rpcwallet  Reference to const optional string wallet name to forward to CallRPC.
 * @returns the RPC response as a UniValue object.
 * @throws a CConnectionFailed std::runtime_error if connection failed or RPC server still in warmup.
 */
static UniValue ConnectAndCallRPC(BaseRequestHandler* rh, const std::string& strMethod, const std::vector<std::string>& args, const std::optional<std::string>& rpcwallet = {})
{
    UniValue response(UniValue::VOBJ);
    // Execute and handle connection failures with -rpcwait.
    const bool fWait = gArgs.GetBoolArg("-rpcwait", false);
    const int timeout = gArgs.GetIntArg("-rpcwaittimeout", DEFAULT_WAIT_CLIENT_TIMEOUT);
    const auto deadline{std::chrono::steady_clock::now() + 1s * timeout};

    do {
        try {
            response = CallRPC(rh, strMethod, args, rpcwallet);
            if (fWait) {
                const UniValue& error = response.find_value("error");
                if (!error.isNull() && error["code"].getInt<int>() == RPC_IN_WARMUP) {
                    throw CConnectionFailed("server in warmup");
                }
            }
            break; // Connection succeeded, no need to retry.
        } catch (const CConnectionFailed& e) {
            if (fWait && (timeout <= 0 || std::chrono::steady_clock::now() < deadline)) {
                UninterruptibleSleep(1s);
            } else {
                throw CConnectionFailed(strprintf("timeout on transient error: %s", e.what()));
            }
        }
    } while (fWait);
    return response;
}

/** Parse UniValue result to update the message to print to std::cout. */
static void ParseResult(const UniValue& result, std::string& strPrint)
{
    if (result.isNull()) return;
    strPrint = result.isStr() ? result.get_str() : result.write(2);
}

/** Parse UniValue error to update the message to print to std::cerr and the code to return. */
static void ParseError(const UniValue& error, std::string& strPrint, int& nRet)
{
    if (error.isObject()) {
        const UniValue& err_code = error.find_value("code");
        const UniValue& err_msg = error.find_value("message");
        if (!err_code.isNull()) {
            strPrint = "error code: " + err_code.getValStr() + "\n";
        }
        if (err_msg.isStr()) {
            strPrint += ("error message:\n" + err_msg.get_str());
        }
        if (err_code.isNum() && err_code.getInt<int>() == RPC_WALLET_NOT_SPECIFIED) {
            strPrint += "\nTry adding \"-rpcwallet=<filename>\" option to kerrigan-cli command line.";
        }
        if (err_code.isNum() && err_code.getInt<int>() == RPC_IN_QUARANTINE) {
            strPrint += "\nThe node has paused itself after detecting a data problem. Inspect with \"kerrigan-cli doctor\" and fix with \"kerrigan-cli repair\".";
        }
    } else {
        strPrint = "error: " + error.write();
    }
    nRet = abs(error["code"].getInt<int>());
}

/**
 * `kerrigan-cli repair` (WS-HEAL v2 8.3): guided wipe+resync repair.
 * Flow: repairnode dry-run -> print the wipe/preserve plan -> explicit typed
 * confirmation (or -confirm) -> arm with the one-time token + shutdown:true
 * (headless: the daemon shuts down and executes the wipe; restart to resync).
 *
 * The arm call races the daemon's own shutdown, so this verb always bounds
 * any -rpcwait with -rpcwaittimeout=60 (the default of 0 waits forever) and
 * treats a dropped connection on the arm call as an expected outcome, not an
 * error.
 */
static int RepairCommand(const std::vector<std::string>& args, std::string& strPrint)
{
    std::string scope{"full"};
    if (!args.empty()) {
        if (args.size() > 1 || (args[0] != "full" && args[0] != "network")) {
            throw std::runtime_error(
                "usage: kerrigan-cli repair [full|network]\n"
                "  full     wipe chain/derived data and resync from scratch (wallet preserved) - default\n"
                "  network  reset peer/address data only (peers.dat, anchors.dat); no chain wipe\n"
                "options: -confirm (skip the interactive prompt), -overrideratelimit");
        }
        scope = args[0];
    }
    const bool override_rate_limit{gArgs.GetBoolArg("-overrideratelimit", false)};

    // Never hang against a daemon that is mid-wipe: DEFAULT_WAIT_CLIENT_TIMEOUT
    // is 0 (= wait forever), so pair any -rpcwait with a bounded timeout.
    if (!gArgs.IsArgSet("-rpcwaittimeout")) {
        gArgs.ForceSetArg("-rpcwaittimeout", "60");
    }

    DefaultRequestHandler rh;

    // Step 1: current diagnosis, so the operator sees WHY before wiping.
    {
        const UniValue reply{ConnectAndCallRPC(&rh, "getrecoverystatus", /*args=*/{})};
        const UniValue& error{reply.find_value("error")};
        if (!error.isNull()) {
            if (error["code"].isNum() && error["code"].getInt<int>() == RPC_METHOD_NOT_FOUND) {
                throw std::runtime_error("this kerrigand does not support guided recovery (getrecoverystatus not found) - upgrade the daemon");
            }
            int nRet{0};
            ParseError(error, strPrint, nRet);
            return nRet;
        }
        const UniValue& r{reply.find_value("result")};
        tfm::format(std::cout, "Node state: %s\n", RecoveryModeText(r["daemon_mode"].getValStr()));
        const UniValue& findings{r["findings"]};
        if (findings.isArray() && !findings.empty()) {
            for (const UniValue& finding : findings.getValues()) {
                tfm::format(std::cout, "%s\n", FormatFindingLine(finding));
            }
        }
        tfm::format(std::cout, "\n");
    }

    // Step 2: dry-run -> plan + one-time confirm token (5-minute TTL).
    std::string token;
    {
        const UniValue reply{ConnectAndCallRPC(&rh, "repairnode", {"true", "", scope})};
        const UniValue& error{reply.find_value("error")};
        if (!error.isNull()) {
            int nRet{0};
            ParseError(error, strPrint, nRet);
            return nRet;
        }
        const UniValue& plan{reply.find_value("result")};
        const auto list_or_none = [](const UniValue& arr) {
            if (!arr.isArray() || arr.empty()) return std::string{"(none)"};
            std::string joined;
            for (const UniValue& item : arr.getValues()) {
                if (!joined.empty()) joined += ", ";
                joined += item.getValStr();
            }
            return joined;
        };
        tfm::format(std::cout, "Repair plan (scope: %s)\n", scope);
        tfm::format(std::cout, "  will delete:   %s\n", list_or_none(plan["wipe_dirs"]));
        tfm::format(std::cout, "  will delete:   %s (files)\n", list_or_none(plan["wipe_files"]));
        tfm::format(std::cout, "  preserved:     %s\n", list_or_none(plan["preserved"]));
        tfm::format(std::cout, "  size estimate: %s\n",
                    FormatByteCount(plan["bytes_total_est"].isNum() ? plan["bytes_total_est"].getInt<int64_t>() : -1));
        if (scope == "full") {
            tfm::format(std::cout,
                        "\nYour wallet file is preserved and your funds are safe, but shielded (Sapling)\n"
                        "balances will be TEMPORARILY UNSPENDABLE while note witnesses rebuild after the\n"
                        "chain finishes resyncing. Transparent balances are usable as soon as sync completes.\n\n");
        } else {
            tfm::format(std::cout, "\nNo chain or wallet data is touched; only peer/address data is reset.\n\n");
        }

        const UniValue& guards{plan["guards"]};
        const bool rate_limited{guards["rate_limited"].isBool() && guards["rate_limited"].get_bool()};
        if (rate_limited && !override_rate_limit) {
            tfm::format(std::cout,
                        "This node already ran %s repair wipes in the last 7 days (limit %s). Repeated\n"
                        "repairs usually mean failing hardware - check the disk before wiping again.\n"
                        "To proceed anyway, re-run with -overrideratelimit (the override is recorded).\n",
                        guards["wipes_in_window"].getValStr(), guards["wipes_max"].getValStr());
            return EXIT_FAILURE;
        }
        token = plan["confirm_token"].getValStr();
        if (token.empty()) {
            throw std::runtime_error("the daemon did not return a confirm token - repair is unavailable right now");
        }
    }

    // Step 3: explicit confirmation. The typed word is deliberately required
    // (not just Enter): this deletes chain data.
    if (!gArgs.GetBoolArg("-confirm", false)) {
        tfm::format(std::cout, "Type REPAIR to proceed (anything else aborts): ");
        fflush(stdout);
        std::string line;
        if (!std::getline(std::cin, line) || line != "REPAIR") {
            tfm::format(std::cout, "Aborted. Nothing was changed.\n");
            return EXIT_FAILURE;
        }
    }

    // Step 4: arm with the token; shutdown:true so the (headless) daemon shuts
    // down and executes the wipe now. The daemon may close the connection
    // while the reply is in flight - that is expected, not an error.
    try {
        const UniValue reply{ConnectAndCallRPC(&rh, "repairnode",
                                               {"false", token, scope,
                                                override_rate_limit ? "true" : "false",
                                                /*shutdown=*/"true"})};
        const UniValue& error{reply.find_value("error")};
        if (!error.isNull()) {
            int nRet{0};
            ParseError(error, strPrint, nRet);
            return nRet;
        }
        const UniValue& r{reply.find_value("result")};
        const std::string result{r["result"].getValStr()};
        if (result == "ARMED") {
            const bool shutdown_initiated{r["shutdown_initiated"].isBool() && r["shutdown_initiated"].get_bool()};
            if (shutdown_initiated) {
                tfm::format(std::cout,
                            "Repair armed. The daemon is shutting down to wipe the damaged data.\n"
                            "Restart kerrigand to resync; follow progress with: kerrigan-cli doctor\n");
            } else {
                // A GUI-build daemon refuses shutdown:true before arming, so
                // this combination should not occur; handle it honestly anyway.
                tfm::format(std::cout,
                            "Repair armed, but the daemon did not begin shutting down.\n"
                            "Restart the node yourself to execute the repair.\n");
            }
            return EXIT_SUCCESS;
        }
        if (result == "ALREADY_ARMED") {
            tfm::format(std::cout, "A repair is already armed. Restart the node to execute it.\n");
            return EXIT_SUCCESS;
        }
        if (result == "BAD_TOKEN") {
            strPrint = "error: the confirmation token was rejected (tokens are one-time and expire after 5 minutes). Run kerrigan-cli repair again.";
        } else if (result == "ATTEMPTS_EXHAUSTED") {
            strPrint = "error: too many repair attempts in the last 6 hours (limit 3). The counter resets once a repair completes and verifies healthy; if repairs keep failing, check the disk.";
        } else if (result == "REPAIR_RATE_LIMITED") {
            strPrint = "error: repair wipe-rate guard tripped (2 wipes per 7 days). Check the disk; re-run with -overrideratelimit to proceed anyway (recorded).";
        } else {
            strPrint = strprintf("error: repair was not armed (daemon result: %s)", result);
        }
        return EXIT_FAILURE;
    } catch (const CConnectionFailed&) {
        // The shutting-down daemon dropped the connection before the reply
        // arrived. Arming happens before the shutdown begins, so this is the
        // expected success shape - but say exactly what is and isn't known.
        tfm::format(std::cout,
                    "The daemon closed the connection while shutting down (expected during repair).\n"
                    "The arm result could not be read back; check debug.log in the data directory for\n"
                    "\"repair marker\" or restart kerrigand and run: kerrigan-cli doctor\n");
        return EXIT_SUCCESS;
    }
}

/**
 * GetWalletBalances calls listwallets; if more than one wallet is loaded, it then
 * fetches mine.trusted balances for each loaded wallet and pushes them to `result`.
 *
 * @param result  Reference to UniValue object the wallet names and balances are pushed to.
 */
static void GetWalletBalances(UniValue& result)
{
    DefaultRequestHandler rh;
    const UniValue listwallets = ConnectAndCallRPC(&rh, "listwallets", /* args=*/{});
    if (!listwallets.find_value("error").isNull()) return;
    const UniValue& wallets = listwallets.find_value("result");
    if (wallets.size() <= 1) return;

    UniValue balances(UniValue::VOBJ);
    for (const UniValue& wallet : wallets.getValues()) {
        const std::string& wallet_name = wallet.get_str();
        const UniValue getbalances = ConnectAndCallRPC(&rh, "getbalances", /* args=*/{}, wallet_name);
        const UniValue& balance = getbalances.find_value("result")["mine"]["trusted"];
        balances.pushKV(wallet_name, balance);
    }
    result.pushKV("balances", balances);
}

/**
 * GetProgressBar constructs a progress bar with 5% intervals.
 *
 * @param[in]   progress      The proportion of the progress bar to be filled between 0 and 1.
 * @param[out]  progress_bar  String representation of the progress bar.
 */
static void GetProgressBar(double progress, std::string& progress_bar)
{
    if (progress < 0 || progress > 1) return;

    static constexpr double INCREMENT{0.05};
    static const std::string COMPLETE_BAR{"\u2592"};
    static const std::string INCOMPLETE_BAR{"\u2591"};

    for (int i = 0; i < progress / INCREMENT; ++i) {
        progress_bar += COMPLETE_BAR;
    }

    for (int i = 0; i < (1 - progress) / INCREMENT; ++i) {
        progress_bar += INCOMPLETE_BAR;
    }
}

/**
 * ParseGetInfoResult takes in -getinfo result in UniValue object and parses it
 * into a user friendly UniValue string to be printed on the console.
 * @param[out] result  Reference to UniValue result containing the -getinfo output.
 */
static void ParseGetInfoResult(UniValue& result)
{
    if (!result.find_value("error").isNull()) return;

    std::string RESET, GREEN, BLUE, YELLOW, MAGENTA, CYAN;
    bool should_colorize = false;

#ifndef WIN32
    if (isatty(fileno(stdout))) {
        // By default, only print colored text if OS is not WIN32 and stdout is connected to a terminal.
        should_colorize = true;
    }
#endif

    if (gArgs.IsArgSet("-color")) {
        const std::string color{gArgs.GetArg("-color", DEFAULT_COLOR_SETTING)};
        if (color == "always") {
            should_colorize = true;
        } else if (color == "never") {
            should_colorize = false;
        } else if (color != "auto") {
            throw std::runtime_error("Invalid value for -color option. Valid values: always, auto, never.");
        }
    }

    if (should_colorize) {
        RESET = "\x1B[0m";
        GREEN = "\x1B[32m";
        BLUE = "\x1B[34m";
        YELLOW = "\x1B[33m";
        MAGENTA = "\x1B[35m";
        CYAN = "\x1B[36m";
    }

    std::string result_string = strprintf("%sChain: %s%s\n", BLUE, result["chain"].getValStr(), RESET);
    result_string += strprintf("Blocks: %s\n", result["blocks"].getValStr());
    result_string += strprintf("Headers: %s\n", result["headers"].getValStr());

    const double ibd_progress{result["verificationprogress"].get_real()};
    std::string ibd_progress_bar;
    // Display the progress bar only if IBD progress is less than 99%
    if (ibd_progress < 0.99) {
      GetProgressBar(ibd_progress, ibd_progress_bar);
      // Add padding between progress bar and IBD progress
      ibd_progress_bar += " ";
    }

    result_string += strprintf("Verification progress: %s%.4f%%\n", ibd_progress_bar, ibd_progress * 100);
    result_string += strprintf("Difficulty: %s\n\n", result["difficulty"].getValStr());

    result_string += strprintf(
        "%sNetwork: in %s, out %s, total %s, mn_in %s, mn_out %s, mn_total %s%s\n",
        GREEN,
        result["connections"]["in"].getValStr(),
        result["connections"]["out"].getValStr(),
        result["connections"]["total"].getValStr(),
        result["connections"]["mn_in"].getValStr(),
        result["connections"]["mn_out"].getValStr(),
        result["connections"]["mn_total"].getValStr(),
        RESET);
    result_string += strprintf("Version: %s\n", result["version"].getValStr());
    result_string += strprintf("Time offset (s): %s\n", result["timeoffset"].getValStr());

    // proxies
    std::map<std::string, std::vector<std::string>> proxy_networks;
    std::vector<std::string> ordered_proxies;

    for (const UniValue& network : result["networks"].getValues()) {
        const std::string proxy = network["proxy"].getValStr();
        if (proxy.empty()) continue;
        // Add proxy to ordered_proxy if has not been processed
        if (proxy_networks.find(proxy) == proxy_networks.end()) ordered_proxies.push_back(proxy);

        proxy_networks[proxy].push_back(network["name"].getValStr());
    }

    std::vector<std::string> formatted_proxies;
    for (const std::string& proxy : ordered_proxies) {
        formatted_proxies.emplace_back(strprintf("%s (%s)", proxy, Join(proxy_networks.find(proxy)->second, ", ")));
    }
    result_string += strprintf("Proxies: %s\n", formatted_proxies.empty() ? "n/a" : Join(formatted_proxies, ", "));

    result_string += strprintf("Min tx relay fee rate (%s/kB): %s\n\n", CURRENCY_UNIT, result["relayfee"].getValStr());

    if (!result["has_wallet"].isNull()) {
        const std::string walletname = result["walletname"].getValStr();
        result_string += strprintf("%sWallet: %s%s\n", MAGENTA, walletname.empty() ? "\"\"" : walletname, RESET);

        result_string += strprintf("Keypool size: %s\n", result["keypoolsize"].getValStr());
        if (!result["unlocked_until"].isNull()) {
            result_string += strprintf("Unlocked until: %s\n", result["unlocked_until"].getValStr());
        }
        result_string += strprintf("Transaction fee rate (-paytxfee) (%s/kB): %s\n\n", CURRENCY_UNIT, result["paytxfee"].getValStr());
    }
    if (!result["balance"].isNull()) {
        result_string += strprintf("%sBalance:%s %s\n\n", CYAN, RESET, result["balance"].getValStr());
    }

    if (!result["balances"].isNull()) {
        result_string += strprintf("%sBalances%s\n", CYAN, RESET);

        size_t max_balance_length{10};

        for (const std::string& wallet : result["balances"].getKeys()) {
            max_balance_length = std::max(result["balances"][wallet].getValStr().length(), max_balance_length);
        }

        for (const std::string& wallet : result["balances"].getKeys()) {
            result_string += strprintf("%*s %s\n",
                                       max_balance_length,
                                       result["balances"][wallet].getValStr(),
                                       wallet.empty() ? "\"\"" : wallet);
        }
        result_string += "\n";
    }

    const std::string warnings{result["warnings"].getValStr()};
    result_string += strprintf("%sWarnings:%s %s", YELLOW, RESET, warnings.empty() ? "(none)" : warnings);

    result.setStr(result_string);
}

/**
 * Call RPC getnewaddress.
 * @returns getnewaddress response as a UniValue object.
 */
static UniValue GetNewAddress()
{
    std::optional<std::string> wallet_name{};
    if (gArgs.IsArgSet("-rpcwallet")) wallet_name = gArgs.GetArg("-rpcwallet", "");
    DefaultRequestHandler rh;
    return ConnectAndCallRPC(&rh, "getnewaddress", /* args=*/{}, wallet_name);
}

/**
 * Check bounds and set up args for RPC generatetoaddress params: nblocks, address, maxtries.
 * @param[in] address  Reference to const string address to insert into the args.
 * @param     args     Reference to vector of string args to modify.
 */
static void SetGenerateToAddressArgs(const std::string& address, std::vector<std::string>& args)
{
    if (args.size() > 2) throw std::runtime_error("too many arguments (maximum 2 for nblocks and maxtries)");
    if (args.size() == 0) {
        args.emplace_back(DEFAULT_NBLOCKS);
    } else if (args.at(0) == "0") {
        throw std::runtime_error("the first argument (number of blocks to generate, default: " + DEFAULT_NBLOCKS + ") must be an integer value greater than zero");
    }
    args.emplace(args.begin() + 1, address);
}

static int CommandLineRPC(int argc, char *argv[])
{
    std::string strPrint;
    int nRet = 0;
    try {
        // Skip switches
        while (argc > 1 && IsSwitchChar(argv[1][0])) {
            argc--;
            argv++;
        }
        std::string rpcPass;
        if (gArgs.GetBoolArg("-stdinrpcpass", false)) {
            NO_STDIN_ECHO();
            if (!StdinReady()) {
                fputs("RPC password> ", stderr);
                fflush(stderr);
            }
            if (!std::getline(std::cin, rpcPass)) {
                throw std::runtime_error("-stdinrpcpass specified but failed to read from standard input");
            }
            if (StdinTerminal()) {
                fputc('\n', stdout);
            }
            gArgs.ForceSetArg("-rpcpassword", rpcPass);
        }
        std::vector<std::string> args = std::vector<std::string>(&argv[1], &argv[argc]);
        if (gArgs.GetBoolArg("-stdinwalletpassphrase", false)) {
            NO_STDIN_ECHO();
            std::string walletPass;
            if (args.size() < 1 || args[0].substr(0, 16) != "walletpassphrase") {
                throw std::runtime_error("-stdinwalletpassphrase is only applicable for walletpassphrase(change)");
            }
            if (!StdinReady()) {
                fputs("Wallet passphrase> ", stderr);
                fflush(stderr);
            }
            if (!std::getline(std::cin, walletPass)) {
                throw std::runtime_error("-stdinwalletpassphrase specified but failed to read from standard input");
            }
            if (StdinTerminal()) {
                fputc('\n', stdout);
            }
            args.insert(args.begin() + 1, walletPass);
        }
        if (gArgs.GetBoolArg("-stdin", false)) {
            // Read one arg per line from stdin and append
            std::string line;
            while (std::getline(std::cin, line)) {
                args.push_back(line);
            }
            if (StdinTerminal()) {
                fputc('\n', stdout);
            }
        }
        std::unique_ptr<BaseRequestHandler> rh;
        std::string method;
        if (gArgs.IsArgSet("-getinfo")) {
            rh.reset(new GetinfoRequestHandler());
        } else if (gArgs.GetBoolArg("-netinfo", false)) {
            if (!args.empty() && args.at(0) == "help") {
                tfm::format(std::cout, "%s\n", NetinfoRequestHandler().m_help_doc);
                return 0;
            }
            rh.reset(new NetinfoRequestHandler());
        } else if (gArgs.GetBoolArg("-generate", false)) {
            const UniValue getnewaddress{GetNewAddress()};
            const UniValue& error{getnewaddress.find_value("error")};
            if (error.isNull()) {
                SetGenerateToAddressArgs(getnewaddress.find_value("result").get_str(), args);
                rh.reset(new GenerateToAddressRequestHandler());
            } else {
                ParseError(error, strPrint, nRet);
            }
        } else if (gArgs.GetBoolArg("-addrinfo", false)) {
            rh.reset(new AddrinfoRequestHandler());
        } else {
            rh.reset(new DefaultRequestHandler());
            if (args.size() < 1) {
                throw std::runtime_error("too few parameters (need at least command)");
            }
            method = args[0];
            args.erase(args.begin()); // Remove trailing method name from arguments vector
            if (method == "doctor") {
                // Client-side formatted rendering of getrecoverystatus.
                rh.reset(new DoctorRequestHandler());
            }
        }
        if (nRet == 0 && method == "repair") {
            // Client-side multi-step verb (dry-run -> confirm -> arm); prints
            // its own progress, so bypass the single-request path.
            nRet = RepairCommand(args, strPrint);
        } else if (nRet == 0) {
            // Perform RPC call
            std::optional<std::string> wallet_name{};
            if (gArgs.IsArgSet("-rpcwallet")) wallet_name = gArgs.GetArg("-rpcwallet", "");
            const UniValue reply = ConnectAndCallRPC(rh.get(), method, args, wallet_name);

            // Parse reply
            UniValue result = reply.find_value("result");
            const UniValue& error = reply.find_value("error");
            if (error.isNull()) {
                if (gArgs.GetBoolArg("-getinfo", false)) {
                    if (!gArgs.IsArgSet("-rpcwallet")) {
                        GetWalletBalances(result); // fetch multiwallet balances and append to result
                    }
                    ParseGetInfoResult(result);
                }

                ParseResult(result, strPrint);
            } else {
                ParseError(error, strPrint, nRet);
            }
        }
    } catch (const std::exception& e) {
        strPrint = std::string("error: ") + e.what();
        nRet = EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(std::current_exception(), "CommandLineRPC()");
        throw;
    }

    if (strPrint != "") {
        tfm::format(nRet == 0 ? std::cout : std::cerr, "%s\n", strPrint);
    }
    return nRet;
}

MAIN_FUNCTION
{
    RegisterPrettyTerminateHander();
    RegisterPrettySignalHandlers();

#ifdef WIN32
    util::WinCmdLineArgs winArgs;
    std::tie(argc, argv) = winArgs.get();
#endif
    SetupEnvironment();
    if (!SetupNetworking()) {
        tfm::format(std::cerr, "Error: Initializing networking failed\n");
        return EXIT_FAILURE;
    }
    event_set_log_callback(&libevent_log_cb);

    try {
        int ret = AppInitRPC(argc, argv);
        if (ret != CONTINUE_EXECUTION)
            return ret;
    } catch (...) {
        PrintExceptionContinue(std::current_exception(), "AppInitRPC()");
        return EXIT_FAILURE;
    }

    int ret = EXIT_FAILURE;
    try {
        ret = CommandLineRPC(argc, argv);
    } catch (...) {
        PrintExceptionContinue(std::current_exception(), "CommandLineRPC()");
    }
    return ret;
}
