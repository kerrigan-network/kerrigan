#!/bin/bash
# Download Sapling zk-SNARK parameters for Kerrigan.
#
# These are the same parameters used by Zcash — the Sapling cryptography
# is protocol-universal and does not change between chains.
#
# Files are stored in ~/.zcash-params/ (shared with Zcash and other Sapling-based coins)
#
# Expected SHA256 hashes (from Zcash ceremony):
#   sapling-spend.params:  8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13
#   sapling-output.params: 2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4

set -euo pipefail

PARAMS_DIR="${HOME}/.zcash-params"
mkdir -p "$PARAMS_DIR"

SPEND_PARAMS="$PARAMS_DIR/sapling-spend.params"
OUTPUT_PARAMS="$PARAMS_DIR/sapling-output.params"

SPEND_SHA256="8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13"
OUTPUT_SHA256="2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4"

DOWNLOAD_URL="https://download.z.cash/downloads"

download_and_verify() {
    local name="$1"
    local dest="$2"
    local expected_hash="$3"

    if [ -f "$dest" ]; then
        local actual_hash
        actual_hash=$(sha256sum "$dest" | cut -d' ' -f1)
        if [ "$actual_hash" = "$expected_hash" ]; then
            echo "[OK] $name already exists with correct hash."
            return 0
        else
            echo "[WARN] $name exists but hash mismatch. Re-downloading..."
            rm -f "$dest"
        fi
    fi

    echo "Downloading $name (~$(du -h "$dest" 2>/dev/null | cut -f1 || echo '?'))..."
    curl -L -o "$dest" "${DOWNLOAD_URL}/${name}" --progress-bar

    local actual_hash
    actual_hash=$(sha256sum "$dest" | cut -d' ' -f1)
    if [ "$actual_hash" != "$expected_hash" ]; then
        echo "[FAIL] Hash mismatch for $name!"
        echo "  Expected: $expected_hash"
        echo "  Got:      $actual_hash"
        rm -f "$dest"
        return 1
    fi

    echo "[OK] $name verified."
}

echo "Fetching Sapling parameters to $PARAMS_DIR..."
echo

download_and_verify "sapling-spend.params" "$SPEND_PARAMS" "$SPEND_SHA256"
download_and_verify "sapling-output.params" "$OUTPUT_PARAMS" "$OUTPUT_SHA256"

echo
echo "All parameters downloaded and verified."
echo "Location: $PARAMS_DIR"
