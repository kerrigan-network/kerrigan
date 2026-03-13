#!/usr/bin/env bash
# launch_testnet.sh — Launch a local 3-node testnet cluster, mine all 4 algos, monitor health
#
# Usage:
#   ./contrib/launch_testnet.sh [--clean] [--nodes N] [--mine-rounds N] [--bin-dir PATH]
#   Ctrl-C to stop daemons (datadirs preserved for restart).

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
NUM_NODES="${NUM_NODES:-3}"
MINE_ROUNDS="${MINE_ROUNDS:-0}"          # 0 = mine forever
HEALTH_INTERVAL="${HEALTH_INTERVAL:-5}"  # seconds between dashboard refreshes
CLEAN=0

KERRIGAN_BIN_DIR="${KERRIGAN_BIN_DIR:-$(pwd)/src}"
KERRIGAND="${KERRIGAN_BIN_DIR}/kerrigand"
KERRIGAN_CLI="${KERRIGAN_BIN_DIR}/kerrigan-cli"

# Persistent testnet datadir root
DATA_ROOT="/mnt/daemons/testnet"

# Port layout: node N gets P2P=17120+N, RPC=19998+N
BASE_P2P_PORT=17120
BASE_RPC_PORT=19998

# RPC credentials (local-only, not security-sensitive)
RPC_USER="kerr"
RPC_PASS="kerr"

# Algo rotation order
ALGOS=("x11" "kawpow" "equihash200" "equihash192")

# Memory tracking
MEM_LOG="$DATA_ROOT/mem_log.csv"
declare -a MEM_BASELINE=()
declare -a MEM_PEAK=()

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --clean)     CLEAN=1; shift ;;
            --nodes)     NUM_NODES="$2"; shift 2 ;;
            --mine-rounds) MINE_ROUNDS="$2"; shift 2 ;;
            --interval)  HEALTH_INTERVAL="$2"; shift 2 ;;
            --bin-dir)   KERRIGAN_BIN_DIR="$2"
                         KERRIGAND="$KERRIGAN_BIN_DIR/kerrigand"
                         KERRIGAN_CLI="$KERRIGAN_BIN_DIR/kerrigan-cli"
                         shift 2 ;;
            -h|--help)
                echo "Usage: $0 [--clean] [--nodes N] [--mine-rounds N] [--interval S] [--bin-dir PATH]"
                echo ""
                echo "  --clean        Wipe datadirs and start fresh"
                echo "  --nodes N      Number of nodes (default: 3)"
                echo "  --mine-rounds  Mining rounds, 0=forever (default: 0)"
                echo "  --interval S   Dashboard refresh seconds (default: 5)"
                echo "  --bin-dir PATH Path to kerrigand/kerrigan-cli (default: ./src)"
                exit 0 ;;
            *) echo "Unknown arg: $1" >&2; exit 1 ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
node_datadir()  { echo "$DATA_ROOT/node${1}"; }
node_p2p_port() { echo $(( BASE_P2P_PORT + $1 )); }
node_rpc_port() { echo $(( BASE_RPC_PORT + $1 )); }

cli() {
    local node="$1"; shift
    "$KERRIGAN_CLI" -datadir="$(node_datadir "$node")" "$@"
}

# Get RSS in MB for a node's daemon (0 if not running)
node_rss_mb() {
    local node="$1"
    local pidfile="$(node_datadir "$node")/testnet3/kerrigand.pid"
    if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        awk '/^VmRSS/{printf "%d", $2/1024}' /proc/"$(cat "$pidfile")"/status 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# Capture baseline RSS for all nodes (call after wallet setup, before mining)
capture_mem_baseline() {
    for n in $(seq 0 $(( NUM_NODES - 1 ))); do
        MEM_BASELINE[$n]=$(node_rss_mb "$n")
        MEM_PEAK[$n]=${MEM_BASELINE[$n]}
    done
    # Initialize CSV log
    mkdir -p "$DATA_ROOT"
    echo "timestamp,round,node,algo,rss_mb,baseline_mb,peak_mb,delta_mb" > "$MEM_LOG"
}

# Log current RSS for all nodes
log_mem() {
    local round="$1" algo="$2"
    local ts
    ts=$(date '+%Y-%m-%dT%H:%M:%S')
    for n in $(seq 0 $(( NUM_NODES - 1 ))); do
        local rss
        rss=$(node_rss_mb "$n")
        local base=${MEM_BASELINE[$n]:-0}
        # Update peak (exclude equihash solving spikes > 1GB by tracking separately)
        if (( rss > ${MEM_PEAK[$n]:-0} )); then
            MEM_PEAK[$n]=$rss
        fi
        local delta=$(( rss - base ))
        echo "$ts,$round,$n,$algo,$rss,$base,${MEM_PEAK[$n]},$delta" >> "$MEM_LOG"
    done
}

# ---------------------------------------------------------------------------
# Check binaries
# ---------------------------------------------------------------------------
check_binaries() {
    for bin in "$KERRIGAND" "$KERRIGAN_CLI"; do
        if [[ ! -x "$bin" ]]; then
            echo -e "${RED}ERROR: binary not found: $bin${RESET}" >&2
            echo "Build with: cd /home/raw/kerrigan && make -j\$(nproc)" >&2
            exit 1
        fi
    done
    echo -e "${GREEN}Binaries OK${RESET}"
}

# ---------------------------------------------------------------------------
# Clean datadirs
# ---------------------------------------------------------------------------
maybe_clean() {
    if (( CLEAN )); then
        echo -e "${YELLOW}--clean: wiping $DATA_ROOT${RESET}"
        rm -rf "$DATA_ROOT"
    fi
}

# ---------------------------------------------------------------------------
# Generate kerrigan.conf for a node
# ---------------------------------------------------------------------------
generate_conf() {
    local node="$1"
    local datadir
    datadir="$(node_datadir "$node")"
    mkdir -p "$datadir"

    local conf="$datadir/kerrigan.conf"

    # Only generate if missing (preserve existing wallets on restart)
    if [[ -f "$conf" ]]; then
        return
    fi

    {
        echo "testnet=1"
        echo "daemon=1"
        echo ""
        echo "[test]"
        echo "server=1"
        echo "listen=1"
        echo "logtimestamps=1"
        echo "port=$(node_p2p_port "$node")"
        echo "rpcport=$(node_rpc_port "$node")"
        echo "rpcuser=$RPC_USER"
        echo "rpcpassword=$RPC_PASS"
        echo "rpcbind=127.0.0.1"
        echo "rpcallowip=127.0.0.1"
        echo ""
        # Connect to all other nodes
        local peer
        for peer in $(seq 0 $(( NUM_NODES - 1 ))); do
            if [[ "$peer" != "$node" ]]; then
                echo "addnode=127.0.0.1:$(node_p2p_port "$peer")"
            fi
        done
    } > "$conf"
    chmod 600 "$conf"

    echo "  Generated $conf"
}

# ---------------------------------------------------------------------------
# Launch a single node
# ---------------------------------------------------------------------------
launch_node() {
    local node="$1"
    local datadir
    datadir="$(node_datadir "$node")"

    # Check if already running
    local pidfile="$datadir/testnet3/kerrigand.pid"
    if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        echo -e "  Node $node: ${YELLOW}already running${RESET}"
        return
    fi

    "$KERRIGAND" -datadir="$datadir" 2>/dev/null
    echo -e "  Node $node: ${GREEN}launched${RESET}"
}

# ---------------------------------------------------------------------------
# Wait for RPC
# ---------------------------------------------------------------------------
wait_for_rpc() {
    local node="$1" attempts=0
    while ! cli "$node" getblockchaininfo &>/dev/null; do
        (( attempts++ )) || true
        if (( attempts > 60 )); then
            echo -e "${RED}TIMEOUT waiting for node $node${RESET}" >&2
            return 1
        fi
        sleep 1
    done
}

# ---------------------------------------------------------------------------
# Create wallet + mining address (first run only)
# ---------------------------------------------------------------------------
declare -a MINING_ADDRS=()

setup_wallet() {
    local node="$1"

    # Check if wallet already exists
    local wallets
    wallets=$(cli "$node" listwallets 2>/dev/null || echo "[]")

    if echo "$wallets" | grep -q '"mining"'; then
        # Wallet exists, get an address from it
        local addr
        addr=$(cli "$node" -rpcwallet=mining getnewaddress 2>/dev/null)
        MINING_ADDRS[$node]="$addr"
        echo -e "  Node $node: reusing wallet, addr=${addr:0:12}..."
        return
    fi

    # Create descriptor wallet (load_on_startup=true required by Kerrigan)
    cli "$node" createwallet "mining" false false "" false true true >/dev/null 2>&1 || true

    local addr
    addr=$(cli "$node" -rpcwallet=mining getnewaddress 2>/dev/null)
    MINING_ADDRS[$node]="$addr"
    echo -e "  Node $node: ${GREEN}wallet created${RESET}, addr=${addr:0:12}..."
}

# ---------------------------------------------------------------------------
# Mine one block
# ---------------------------------------------------------------------------
mine_block() {
    local node="$1" algo="$2"
    local addr="${MINING_ADDRS[$node]}"
    local max_tries=100000000

    # Equihash solvers are heavy and uncancellable — use few nonces to avoid
    # runaway 8GB+ memory if the 600s RPC timeout fires mid-solve.
    # Each nonce takes ~30s (eq192) or ~10s (eq200). With testnet's easy
    # powLimit (~50% pass rate, ~2 solutions/nonce), 10 nonces is >99.9%.
    case "$algo" in
        equihash200) max_tries=15 ;;
        equihash192) max_tries=10 ;;
    esac

    # Extended timeout for KawPoW DAG generation (~1GB, takes minutes on first call)
    # and Equihash solving (~30s/nonce for 192,7)
    cli "$node" -rpcclienttimeout=600 -rpcwallet=mining generatetoaddress 1 "$addr" "$max_tries" "$algo" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Health dashboard
# ---------------------------------------------------------------------------
print_dashboard() {
    local round="$1" algo="$2"
    printf '\033[H\033[J'

    echo -e "${BOLD}${CYAN}Kerrigan Testnet Dashboard${RESET}  round=$round  algo=${BOLD}${algo}${RESET}  $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${BOLD}Nodes: $NUM_NODES  Data: $DATA_ROOT${RESET}"
    echo

    printf "${BOLD}%-5s %-7s %-6s %-13s %-8s %-8s %-8s %-6s${RESET}\n" \
        "Node" "Height" "Peers" "BestAlgo" "RSS" "Base" "Peak" "Δ MB"
    printf '%s\n' "$(printf '%.0s-' {1..70})"

    local n height peers rss_mb status_str best_hash best_algo
    for n in $(seq 0 $(( NUM_NODES - 1 ))); do
        local datadir pidfile
        datadir="$(node_datadir "$n")"
        pidfile="$datadir/testnet3/kerrigand.pid"

        # Check process
        if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            status_str="${GREEN}UP${RESET}"
            rss_mb=$(node_rss_mb "$n")
        else
            status_str="${RED}DOWN${RESET}"
            rss_mb=0
        fi

        local base_mb=${MEM_BASELINE[$n]:-0}
        local peak_mb=${MEM_PEAK[$n]:-0}
        # Update peak
        if (( rss_mb > peak_mb )); then
            MEM_PEAK[$n]=$rss_mb
            peak_mb=$rss_mb
        fi
        local delta_mb=$(( rss_mb - base_mb ))

        # Query height
        height=$(cli "$n" getblockcount 2>/dev/null || echo "?")

        # Query peers
        peers=$(cli "$n" getconnectioncount 2>/dev/null || echo "?")

        # Query best block algo
        best_algo="-"
        if [[ "$height" =~ ^[0-9]+$ ]] && (( height > 0 )); then
            best_hash=$(cli "$n" getbestblockhash 2>/dev/null || echo "")
            if [[ -n "$best_hash" ]]; then
                best_algo=$(cli "$n" getblock "$best_hash" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('algo','?'))" 2>/dev/null || echo "?")
            fi
        fi

        # Color height
        if [[ "$height" =~ ^[0-9]+$ ]]; then
            if (( height == 0 )); then
                height_str="${YELLOW}${height}${RESET}"
            else
                height_str="${GREEN}${height}${RESET}"
            fi
        else
            height_str="${RED}${height}${RESET}"
        fi

        # Color peers
        if [[ "$peers" =~ ^[0-9]+$ ]]; then
            if (( peers == 0 )); then
                peers_str="${RED}${peers}${RESET}"
            elif (( peers < NUM_NODES - 1 )); then
                peers_str="${YELLOW}${peers}${RESET}"
            else
                peers_str="${GREEN}${peers}${RESET}"
            fi
        else
            peers_str="${RED}${peers}${RESET}"
        fi

        # Color RSS: red if >1GB (equihash spike), yellow if delta > 50MB (potential leak)
        if (( rss_mb > 1000 )); then
            rss_str="${RED}${rss_mb}${RESET}"
        elif (( rss_mb > 500 )); then
            rss_str="${YELLOW}${rss_mb}${RESET}"
        else
            rss_str="${GREEN}${rss_mb}${RESET}"
        fi

        # Color delta: yellow if >50MB growth, red if >200MB
        if (( delta_mb > 200 )); then
            delta_str="${RED}+${delta_mb}${RESET}"
        elif (( delta_mb > 50 )); then
            delta_str="${YELLOW}+${delta_mb}${RESET}"
        elif (( delta_mb < -10 )); then
            delta_str="${GREEN}${delta_mb}${RESET}"
        else
            delta_str="${GREEN}+${delta_mb}${RESET}"
        fi

        printf "%-5s %-16b %-15b %-13s %-17b %-8s %-8s %-17b\n" \
            "n${n}" "$height_str" "$peers_str" "$best_algo" "$rss_str" "${base_mb}" "${peak_mb}" "$delta_str"
    done

    echo
    echo -e "${BOLD}Legend:${RESET} ${GREEN}green=OK${RESET}  ${YELLOW}yellow=warn (Δ>50MB)${RESET}  ${RED}red=leak? (Δ>200MB) / equihash spike${RESET}"
    echo -e "Memory log: $MEM_LOG"
    echo "Press Ctrl-C to stop daemons."
}

# ---------------------------------------------------------------------------
# Graceful cleanup on Ctrl-C
# ---------------------------------------------------------------------------
cleanup() {
    echo -e "\n${CYAN}--- Stopping testnet nodes ---${RESET}"
    local n
    for n in $(seq 0 $(( NUM_NODES - 1 ))); do
        echo -n "  Stopping node $n... "
        cli "$n" stop 2>/dev/null && echo "ok" || echo "already stopped"
    done
    echo -e "${GREEN}Datadirs preserved at $DATA_ROOT${RESET}"
    echo "Restart with: $0"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Mining loop
# ---------------------------------------------------------------------------
mine_loop() {
    local round=0 algo_idx=0 algo node_idx
    echo -e "${CYAN}Starting mining loop...${RESET}"
    sleep 2 # let nodes connect to each other

    while true; do
        algo="${ALGOS[$algo_idx]}"

        # Each node mines 1 block with the current algo
        node_idx=$(( round % NUM_NODES ))
        mine_block "$node_idx" "$algo"

        (( round++ )) || true
        log_mem "$round" "$algo"
        print_dashboard "$round" "$algo"

        # Advance algo rotation
        algo_idx=$(( (algo_idx + 1) % ${#ALGOS[@]} ))

        # Honour MINE_ROUNDS limit
        if (( MINE_ROUNDS > 0 && round >= MINE_ROUNDS )); then
            echo -e "${GREEN}Reached MINE_ROUNDS=$MINE_ROUNDS — stopping.${RESET}"
            break
        fi

        sleep "$HEALTH_INTERVAL"
    done
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    echo -e "${BOLD}${CYAN}Kerrigan Testnet Launcher${RESET}"
    echo -e "  Nodes:     $NUM_NODES"
    echo -e "  P2P ports: $BASE_P2P_PORT – $(( BASE_P2P_PORT + NUM_NODES - 1 ))"
    echo -e "  RPC ports: $BASE_RPC_PORT – $(( BASE_RPC_PORT + NUM_NODES - 1 ))"
    echo -e "  Data root: $DATA_ROOT"
    echo -e "  Daemon:    $KERRIGAND"
    echo

    check_binaries
    maybe_clean

    # Phase 1: Generate configs
    echo -e "${CYAN}Generating configs...${RESET}"
    for n in $(seq 0 $(( NUM_NODES - 1 ))); do
        generate_conf "$n"
    done

    # Phase 2: Launch daemons
    echo -e "${CYAN}Launching daemons...${RESET}"
    for n in $(seq 0 $(( NUM_NODES - 1 ))); do
        launch_node "$n"
    done

    # Phase 3: Wait for RPC
    echo -e "${CYAN}Waiting for RPC...${RESET}"
    for n in $(seq 0 $(( NUM_NODES - 1 ))); do
        wait_for_rpc "$n"
        echo -n "."
    done
    echo -e " ${GREEN}All nodes ready.${RESET}"

    # Phase 4: Setup wallets
    echo -e "${CYAN}Setting up wallets...${RESET}"
    for n in $(seq 0 $(( NUM_NODES - 1 ))); do
        setup_wallet "$n"
    done

    # Phase 5: Capture memory baseline
    echo -e "${CYAN}Capturing memory baseline...${RESET}"
    sleep 2
    capture_mem_baseline
    for n in $(seq 0 $(( NUM_NODES - 1 ))); do
        echo -e "  Node $n: ${MEM_BASELINE[$n]} MB"
    done

    # Phase 6: Mine
    mine_loop
}

main "$@"
