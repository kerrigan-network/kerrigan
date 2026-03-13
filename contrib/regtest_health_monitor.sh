#!/usr/bin/env bash
# regtest_health_monitor.sh — Launch regtest clusters, mine on rotating algos, monitor health
#
# Designed for: 56-thread / 314GB RAM build server
# Default: 8 clusters x 4 nodes = 32 nodes total
#
# Usage:
#   ./contrib/regtest_health_monitor.sh [--clusters N] [--nodes N] [--mine-rounds N]
#   Ctrl-C or EXIT to stop all daemons and clean up.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (override via environment or flags)
# ---------------------------------------------------------------------------
NUM_CLUSTERS="${NUM_CLUSTERS:-8}"
NODES_PER_CLUSTER="${NODES_PER_CLUSTER:-4}"
BASE_PORT="${BASE_PORT:-18400}"
BASE_RPC_PORT="${BASE_RPC_PORT:-18500}"
MINE_ROUNDS="${MINE_ROUNDS:-0}"          # 0 = mine forever
HEALTH_INTERVAL="${HEALTH_INTERVAL:-10}" # seconds between dashboard refreshes

KERRIGAN_BIN_DIR="${KERRIGAN_BIN_DIR:-$(pwd)/src}"
KERRIGAND="${KERRIGAN_BIN:-$KERRIGAN_BIN_DIR/kerrigand}"
KERRIGAN_CLI="${KERRIGAN_CLI:-$KERRIGAN_BIN_DIR/kerrigan-cli}"

# Temporary runtime directory (cleaned on EXIT)
RUN_DIR="${TMPDIR:-/tmp}/kerrigan-regtest-$$"

# Regtest addresses — one per cluster (hardcoded placeholders; valid for regtest)
# In production, generate one per cluster via `kerrigan-cli -regtest getnewaddress`
REGTEST_ADDRESSES=(
    "yMTFNMmhCs4raaaXVRVXaaaaaaaaaaY1" # cluster 0
    "yMTFNMmhCs4raaaXVRVXaaaaaaaaaaY2" # cluster 1
    "yMTFNMmhCs4raaaXVRVXaaaaaaaaaaY3" # cluster 2
    "yMTFNMmhCs4raaaXVRVXaaaaaaaaaaY4" # cluster 3
    "yMTFNMmhCs4raaaXVRVXaaaaaaaaaaY5" # cluster 4
    "yMTFNMmhCs4raaaXVRVXaaaaaaaaaaY6" # cluster 5
    "yMTFNMmhCs4raaaXVRVXaaaaaaaaaaY7" # cluster 6
    "yMTFNMmhCs4raaaXVRVXaaaaaaaaaaY8" # cluster 7
)

# Algo rotation order
ALGOS=("x11" "kawpow" "equihash200" "equihash192")

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

color_status() {
    local val="$1" warn_threshold="$2" err_threshold="$3"
    if (( val <= err_threshold )); then
        echo -e "${RED}${val}${RESET}"
    elif (( val <= warn_threshold )); then
        echo -e "${YELLOW}${val}${RESET}"
    else
        echo -e "${GREEN}${val}${RESET}"
    fi
}

# ---------------------------------------------------------------------------
# Derived layout helpers
# ---------------------------------------------------------------------------
# node_index CLUSTER NODE  → flat index into the node array
node_index() { echo $(( $1 * NODES_PER_CLUSTER + $2 )); }

# node_port CLUSTER NODE
node_port() { echo $(( BASE_PORT + node_index "$1" "$2" )); }

# node_rpc_port CLUSTER NODE
node_rpc_port() { echo $(( BASE_RPC_PORT + node_index "$1" "$2" )); }

# node_datadir CLUSTER NODE
node_datadir() { echo "$RUN_DIR/c${1}n${2}"; }

# ---------------------------------------------------------------------------
# PID tracking
# ---------------------------------------------------------------------------
declare -a NODE_PIDS=()

# ---------------------------------------------------------------------------
# Cleanup — called on EXIT (Ctrl-C, error, or normal exit)
# ---------------------------------------------------------------------------
cleanup() {
    echo -e "\n${CYAN}--- Shutting down all nodes ---${RESET}"
    local c n rpc_port
    for c in $(seq 0 $(( NUM_CLUSTERS - 1 ))); do
        for n in $(seq 0 $(( NODES_PER_CLUSTER - 1 ))); do
            rpc_port=$(node_rpc_port "$c" "$n")
            echo -n "  Stopping cluster $c node $n (rpc $rpc_port)... "
            "$KERRIGAN_CLI" -regtest \
                -rpcport="$rpc_port" -rpcuser=kerr -rpcpassword=kerr \
                stop 2>/dev/null && echo "ok" || echo "already stopped"
        done
    done

    # Give daemons a moment to write their lock files before we rm
    sleep 2

    echo -e "${CYAN}--- Removing run directory $RUN_DIR ---${RESET}"
    rm -rf "$RUN_DIR"
    echo -e "${GREEN}Cleanup complete.${RESET}"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Binary check
# ---------------------------------------------------------------------------
check_binaries() {
    for bin in "$KERRIGAND" "$KERRIGAN_CLI"; do
        if [[ ! -x "$bin" ]]; then
            echo -e "${RED}ERROR: binary not found or not executable: $bin${RESET}" >&2
            echo "Build with: cd /home/raw/kerrigan && make -j\$(nproc)" >&2
            exit 1
        fi
    done
    echo -e "${GREEN}Binaries OK: $KERRIGAND${RESET}"
}

# ---------------------------------------------------------------------------
# Launch a single node
# ---------------------------------------------------------------------------
launch_node() {
    local cluster="$1" node="$2"
    local port rpc_port datadir connect_args
    port=$(node_port "$cluster" "$node")
    rpc_port=$(node_rpc_port "$cluster" "$node")
    datadir=$(node_datadir "$cluster" "$node")
    mkdir -p "$datadir"

    # Build -addnode list: connect each node to all others in the same cluster
    connect_args=()
    local peer
    for peer in $(seq 0 $(( NODES_PER_CLUSTER - 1 ))); do
        if [[ "$peer" != "$node" ]]; then
            connect_args+=("-addnode=127.0.0.1:$(node_port "$cluster" "$peer")")
        fi
    done

    "$KERRIGAND" \
        -regtest \
        -daemon \
        -datadir="$datadir" \
        -port="$port" \
        -rpcport="$rpc_port" \
        -rpcuser=kerr \
        -rpcpassword=kerr \
        -rpcbind=127.0.0.1 \
        -rpcallowip=127.0.0.1 \
        -listen=1 \
        -server=1 \
        -logtimestamps=1 \
        -debug=0 \
        "${connect_args[@]}" \
        2>/dev/null
}

# ---------------------------------------------------------------------------
# Wait for a node's RPC to become responsive
# ---------------------------------------------------------------------------
wait_for_rpc() {
    local cluster="$1" node="$2"
    local rpc_port attempts
    rpc_port=$(node_rpc_port "$cluster" "$node")
    attempts=0
    while ! "$KERRIGAN_CLI" -regtest \
            -rpcport="$rpc_port" -rpcuser=kerr -rpcpassword=kerr \
            getblockchaininfo &>/dev/null; do
        (( attempts++ ))
        if (( attempts > 30 )); then
            echo -e "${RED}TIMEOUT waiting for c${cluster}n${node} (rpc $rpc_port)${RESET}" >&2
            return 1
        fi
        sleep 1
    done
}

# ---------------------------------------------------------------------------
# Launch all clusters
# ---------------------------------------------------------------------------
launch_all() {
    echo -e "${CYAN}=== Launching $NUM_CLUSTERS clusters x $NODES_PER_CLUSTER nodes ===${RESET}"
    mkdir -p "$RUN_DIR"

    local c n
    for c in $(seq 0 $(( NUM_CLUSTERS - 1 ))); do
        echo -n "  Cluster $c: "
        for n in $(seq 0 $(( NODES_PER_CLUSTER - 1 ))); do
            launch_node "$c" "$n"
            echo -n "n$n "
        done
        echo
    done

    echo -e "${CYAN}Waiting for all nodes to become RPC-responsive...${RESET}"
    for c in $(seq 0 $(( NUM_CLUSTERS - 1 ))); do
        for n in $(seq 0 $(( NODES_PER_CLUSTER - 1 ))); do
            wait_for_rpc "$c" "$n"
            echo -n "."
        done
    done
    echo -e " ${GREEN}All nodes ready.${RESET}"

    # Capture PIDs by grepping the daemon's PID file
    for c in $(seq 0 $(( NUM_CLUSTERS - 1 ))); do
        for n in $(seq 0 $(( NODES_PER_CLUSTER - 1 ))); do
            local pidfile
            pidfile="$(node_datadir "$c" "$n")/regtest/kerrigand.pid"
            if [[ -f "$pidfile" ]]; then
                NODE_PIDS+=("$(cat "$pidfile")")
            else
                NODE_PIDS+=("")
            fi
        done
    done
}

# ---------------------------------------------------------------------------
# Mine one block on a cluster with a given algo
# ---------------------------------------------------------------------------
mine_block() {
    local cluster="$1" algo="$2"
    local rpc_port addr
    rpc_port=$(node_rpc_port "$cluster" 0) # mine from first node of cluster
    addr="${REGTEST_ADDRESSES[$cluster]:-yMTFNMmhCs4raaaXVRVXaaaaaaaaaaY1}"

    "$KERRIGAN_CLI" -regtest \
        -rpcport="$rpc_port" -rpcuser=kerr -rpcpassword=kerr \
        generatetoaddress 1 "$addr" 1000000 "$algo" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Health dashboard
# ---------------------------------------------------------------------------
print_dashboard() {
    local round="$1" algo="$2"
    # Move cursor to top of screen for in-place refresh
    printf '\033[H\033[J'

    echo -e "${BOLD}${CYAN}Kerrigan Regtest Health Monitor${RESET}  round=$round  algo=${BOLD}${algo}${RESET}  $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${BOLD}Clusters: $NUM_CLUSTERS  Nodes/cluster: $NODES_PER_CLUSTER  Total: $(( NUM_CLUSTERS * NODES_PER_CLUSTER ))${RESET}"
    echo

    printf "${BOLD}%-6s %-6s %-8s %-8s %-10s %-8s${RESET}\n" \
        "Clust" "Node" "Height" "Peers" "RSS(MB)" "Status"
    printf '%s\n' "$(printf '%.0s-' {1..55})"

    local c n rpc_port height peers pid rss_mb status_str
    for c in $(seq 0 $(( NUM_CLUSTERS - 1 ))); do
        for n in $(seq 0 $(( NODES_PER_CLUSTER - 1 ))); do
            rpc_port=$(node_rpc_port "$c" "$n")
            idx=$(node_index "$c" "$n")
            pid="${NODE_PIDS[$idx]:-}"

            # Check if process is alive
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                status_str="${GREEN}UP${RESET}"
                rss_mb=$(awk '/^VmRSS/{printf "%d", $2/1024}' /proc/"$pid"/status 2>/dev/null || echo "?")
            else
                status_str="${RED}CRASH${RESET}"
                rss_mb="?"
            fi

            # Query height
            height=$("$KERRIGAN_CLI" -regtest \
                -rpcport="$rpc_port" -rpcuser=kerr -rpcpassword=kerr \
                getblockcount 2>/dev/null || echo "?")

            # Query peer count
            peers=$("$KERRIGAN_CLI" -regtest \
                -rpcport="$rpc_port" -rpcuser=kerr -rpcpassword=kerr \
                getconnectioncount 2>/dev/null || echo "?")

            # Color height: warn <5, error 0
            if [[ "$height" =~ ^[0-9]+$ ]]; then
                height_str=$(color_status "$height" 5 0)
            else
                height_str="${RED}${height}${RESET}"
            fi

            # Color peers: warn <2, error 0
            if [[ "$peers" =~ ^[0-9]+$ ]]; then
                peers_str=$(color_status "$peers" 2 0)
            else
                peers_str="${RED}${peers}${RESET}"
            fi

            # Color RSS: warn >500MB, error >1000MB
            if [[ "$rss_mb" =~ ^[0-9]+$ ]]; then
                if (( rss_mb > 1000 )); then
                    rss_str="${RED}${rss_mb}${RESET}"
                elif (( rss_mb > 500 )); then
                    rss_str="${YELLOW}${rss_mb}${RESET}"
                else
                    rss_str="${GREEN}${rss_mb}${RESET}"
                fi
            else
                rss_str="${YELLOW}?${RESET}"
            fi

            printf "%-6s %-6s %-17b %-17b %-19b %-8b\n" \
                "c${c}" "n${n}" "$height_str" "$peers_str" "$rss_str" "$status_str"
        done
        # Blank line between clusters for readability
        echo
    done

    echo -e "${BOLD}Legend:${RESET} ${GREEN}green=OK${RESET}  ${YELLOW}yellow=warn${RESET}  ${RED}red=error/crash${RESET}"
    echo "Press Ctrl-C to stop and clean up."
}

# ---------------------------------------------------------------------------
# Main mining loop
# ---------------------------------------------------------------------------
mine_loop() {
    local round=0 algo_idx=0 c algo
    echo -e "${CYAN}Starting mining loop (MINE_ROUNDS=$MINE_ROUNDS, 0=forever)...${RESET}"
    sleep 1 # brief pause so all nodes settle

    while true; do
        algo="${ALGOS[$algo_idx]}"

        # Mine one block per cluster on the current algo
        for c in $(seq 0 $(( NUM_CLUSTERS - 1 ))); do
            mine_block "$c" "$algo"
        done

        (( round++ )) || true
        print_dashboard "$round" "$algo"

        # Advance algo rotation
        algo_idx=$(( (algo_idx + 1) % ${#ALGOS[@]} ))

        # Honour MINE_ROUNDS limit
        if (( MINE_ROUNDS > 0 && round >= MINE_ROUNDS )); then
            echo -e "${GREEN}Reached MINE_ROUNDS=$MINE_ROUNDS — exiting mining loop.${RESET}"
            break
        fi

        sleep "$HEALTH_INTERVAL"
    done
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --clusters)  NUM_CLUSTERS="$2"; shift 2 ;;
            --nodes)     NODES_PER_CLUSTER="$2"; shift 2 ;;
            --mine-rounds) MINE_ROUNDS="$2"; shift 2 ;;
            --interval)  HEALTH_INTERVAL="$2"; shift 2 ;;
            --bin-dir)   KERRIGAN_BIN_DIR="$2"
                         KERRIGAND="$KERRIGAN_BIN_DIR/kerrigand"
                         KERRIGAN_CLI="$KERRIGAN_BIN_DIR/kerrigan-cli"
                         shift 2 ;;
            -h|--help)
                echo "Usage: $0 [--clusters N] [--nodes N] [--mine-rounds N] [--interval S] [--bin-dir PATH]"
                echo "Env vars: NUM_CLUSTERS, NODES_PER_CLUSTER, BASE_PORT, BASE_RPC_PORT,"
                echo "          MINE_ROUNDS, HEALTH_INTERVAL, KERRIGAN_BIN_DIR"
                exit 0 ;;
            *) echo "Unknown arg: $1" >&2; exit 1 ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    # Validate cluster count doesn't exceed address table
    if (( NUM_CLUSTERS > ${#REGTEST_ADDRESSES[@]} )); then
        echo -e "${RED}ERROR: NUM_CLUSTERS ($NUM_CLUSTERS) exceeds REGTEST_ADDRESSES table (${#REGTEST_ADDRESSES[@]}).${RESET}" >&2
        echo "Extend the REGTEST_ADDRESSES array in this script or reduce --clusters." >&2
        exit 1
    fi

    local total=$(( NUM_CLUSTERS * NODES_PER_CLUSTER ))
    echo -e "${CYAN}Kerrigan Regtest Health Monitor${RESET}"
    echo -e "  Clusters:   $NUM_CLUSTERS"
    echo -e "  Nodes each: $NODES_PER_CLUSTER  (total: $total)"
    echo -e "  Ports:      $BASE_PORT – $(( BASE_PORT + total - 1 ))"
    echo -e "  RPC ports:  $BASE_RPC_PORT – $(( BASE_RPC_PORT + total - 1 ))"
    echo -e "  Run dir:    $RUN_DIR"
    echo -e "  Daemon:     $KERRIGAND"
    echo

    check_binaries
    launch_all
    mine_loop
}

main "$@"
