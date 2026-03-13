# Pool Integration Guide

Kerrigan uses 4 mining algorithms. The `rpcalgoport` feature makes each algo appear as a **standard single-algo coin** to pool software, requiring zero multi-algo awareness.

## rpcalgoport

Each `-rpcalgoport` binding creates a dedicated RPC listener for one algorithm. The GBT response includes a complete `coinbasetxn` with masternode outputs pre-calculated.

### Daemon Configuration

```ini
# kerrigan.conf
rpcuser=pool
rpcpassword=<secret>
rpcallowip=127.0.0.1

# Per-algo RPC ports (mnemonic convention)
rpcalgoport=x11:1100
rpcalgoport=kawpow:5700
rpcalgoport=equihash200:2009
rpcalgoport=equihash192:1927

# Coinbase recipient for pool payouts
pooladdress=<your-kerrigan-address>

# Required for explorer/indexing (optional for mining)
txindex=1
addressindex=1
```

### Port Convention

| Algorithm | Port | Mnemonic |
|-----------|------|----------|
| X11 | 1100 | x**11** + 00 |
| KawPoW | 5700 | RVN stratum convention |
| Equihash 200,9 | 2009 | **200**,**9** |
| Equihash 192,7 | 1927 | **19**2,**7** |

### What Each Port Returns

Every algo port returns a standard GBT response:

- `version` — block version with algo bits pre-set
- `bits` / `target` — per-algo difficulty
- `coinbasetxn` — complete coinbase transaction (pool address + masternode outputs + CbTx payload)
- `previousblockhash`, `curtime`, `height` — standard fields
- Equihash ports also include: `equihash_n`, `equihash_k`, `personalization`, `header_hex`
- KawPoW port includes: `kawpow_header`, `kawpow_seed_hash`

**Key insight**: Because `coinbasetxn` is pre-built by the daemon, pool software does NOT need masternode payment logic, CbTx handling, or multi-algo awareness.

## Miningcore Integration

### Coin Definitions (`coins.json`)

Add 4 entries, one per algorithm:

```json
{
    "kerrigan-x11": {
        "name": "Kerrigan-X11",
        "symbol": "KRGN",
        "family": "bitcoin",
        "algorithm": "x11",
        "useCoinbaseTxPayload": true
    },
    "kerrigan-kawpow": {
        "name": "Kerrigan-KawPoW",
        "symbol": "KRGN",
        "family": "progpow",
        "algorithm": "kawpow"
    },
    "kerrigan-equihash200": {
        "name": "Kerrigan-Equihash200",
        "symbol": "KRGN",
        "family": "equihash",
        "algorithm": "equihash",
        "solver": { "equihashN": 200, "equihashK": 9, "personalization": "ZcashPoW" },
        "diff1": "0x0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "solutionSize": 1344,
        "solutionPreambleSize": 3
    },
    "kerrigan-equihash192": {
        "name": "Kerrigan-Equihash192",
        "symbol": "KRGN",
        "family": "equihash",
        "algorithm": "equihash",
        "solver": { "equihashN": 192, "equihashK": 7, "personalization": "kerrigan" },
        "diff1": "0x0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "solutionSize": 400,
        "solutionPreambleSize": 3
    }
}
```

### Pool Configuration (`config.json`)

Each pool entry points to its algo-specific daemon port:

```json
{
    "pools": [
        {
            "id": "kerrigan-equihash192",
            "enabled": true,
            "coin": "kerrigan-equihash192",
            "address": "<pool-kerrigan-address>",
            "ports": {
                "3032": { "difficulty": 1, "varDiff": { "minDiff": 0.1, "maxDiff": 1024 } }
            },
            "daemons": [{
                "host": "127.0.0.1",
                "port": 1927,
                "user": "pool",
                "password": "<secret>"
            }],
            "paymentProcessing": {
                "enabled": true,
                "minimumPayment": 1,
                "payoutScheme": "PPLNS"
            }
        },
        {
            "id": "kerrigan-equihash200",
            "enabled": true,
            "coin": "kerrigan-equihash200",
            "address": "<pool-kerrigan-address>",
            "ports": {
                "3033": { "difficulty": 1, "varDiff": { "minDiff": 0.1, "maxDiff": 1024 } }
            },
            "daemons": [{
                "host": "127.0.0.1",
                "port": 2009,
                "user": "pool",
                "password": "<secret>"
            }]
        },
        {
            "id": "kerrigan-kawpow",
            "enabled": true,
            "coin": "kerrigan-kawpow",
            "address": "<pool-kerrigan-address>",
            "ports": {
                "3034": { "difficulty": 1 }
            },
            "daemons": [{
                "host": "127.0.0.1",
                "port": 5700,
                "user": "pool",
                "password": "<secret>"
            }]
        },
        {
            "id": "kerrigan-x11",
            "enabled": true,
            "coin": "kerrigan-x11",
            "address": "<pool-kerrigan-address>",
            "ports": {
                "3035": { "difficulty": 1 }
            },
            "daemons": [{
                "host": "127.0.0.1",
                "port": 1100,
                "user": "pool",
                "password": "<secret>"
            }]
        }
    ]
}
```

### Minimal Code Changes

Starting from stock Miningcore, Kerrigan needs only:

1. Coin template entries (above)
2. Use `coinbasetxn` from GBT instead of building coinbase (eliminates masternode code)
3. `BitcoinPayoutHandler` — use `Details[0].Amount` (upstream fix)
4. `ref` parameter fixes for NBitcoin compat (upstream fix)
5. StratumShare record type for stats

**Total: ~50 lines of real changes, not 500+.**

## S-NOMP Integration

### Coin Config (`coins/kerrigan_equihash192.json`)

```json
{
    "name": "KerriganEquihash192",
    "symbol": "KRGN",
    "algorithm": "equihash192_7",
    "peerMagic": "4b52474e",
    "peerMagicFallback": "4b52474e"
}
```

### Pool Config (`pool_configs/kerrigan_equihash192.json`)

```json
{
    "enabled": true,
    "coin": "kerrigan_equihash192.json",
    "address": "<pool-kerrigan-address>",
    "useCoinbasetxn": true,
    "rewardRecipients": {},
    "paymentProcessing": {
        "enabled": true,
        "paymentInterval": 120,
        "minimumPayment": 1,
        "daemon": {
            "host": "127.0.0.1",
            "port": 7121,
            "user": "pool",
            "password": "<secret>"
        }
    },
    "ports": {
        "3032": {
            "diff": 1,
            "varDiff": { "minDiff": 0.1, "maxDiff": 1024, "targetTime": 15 }
        }
    },
    "daemons": [{
        "host": "127.0.0.1",
        "port": 1927,
        "user": "pool",
        "password": "<secret>"
    }]
}
```

**Key setting**: `"useCoinbasetxn": true` — tells S-NOMP to use the daemon's pre-built coinbase instead of constructing its own. This eliminates the need for masternode payment code.

## Troubleshooting

**GPU miners (miniZ, lolMiner) dying after ~10 minutes:**
- Likely cause: near-zero per-algo difficulty causing rapid job notifications
- Fix: ensure difficulty floors are active (testnet: height >= 2260, mainnet: always active)

**Incorrect algo on block updates:**
- S-NOMP stratum-pool `job[8]=false` bug overwrites algo identifier
- Fix: apply the `job[7]=false` patch (see kerrigan-snomp postinstall script)

**Pool not finding blocks:**
- Verify daemon is running with `rpcalgoport` configured
- Test: `curl -u pool:<secret> --data-binary '{"method":"getblocktemplate"}' http://127.0.0.1:1927/`
- Response should include `coinbasetxn` and correct `equihash_n`/`equihash_k`

**Genesis block rejected by `CheckProofOfWork`:**
- The mainnet genesis block was mined with Dash-default nBits (`0x1e0ffff0`, target ~2^236), which exceeds the per-algo X11 `powLimitAlgo` (~2^213). Testnet is unaffected because all algo limits are ~2^255.
- Fix: bypass per-algo limits for the genesis block in three places:
  1. `src/node/blockstorage.cpp` (`ReadBlockFromDisk`) -- omit algo param so it falls back to global `powLimit`
  2. `src/validation.cpp` (`CheckBlockHeader`) -- pass `-1` as algo when `hashPrevBlock` is null
  3. `src/txdb.cpp` (`LoadBlockIndexGuts`) -- pass `-1` as algo when height is 0
