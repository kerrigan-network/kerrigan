# Pool Integration Guide

Kerrigan uses 4 mining algorithms. The `rpcalgoport` feature makes each algo appear as a **standard single-algo coin** to pool software, requiring zero multi-algo awareness.

## rpcalgoport

Each `-rpcalgoport` binding creates a dedicated RPC listener for one algorithm. When the `pooladdress` parameter is passed in the `getblocktemplate` request, the GBT response includes a complete `coinbasetxn` with masternode outputs pre-calculated. (Equihash algos always include `coinbasetxn` regardless.)

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

# Required for explorer/indexing (optional for mining)
txindex=1
addressindex=1
```

**Note:** `rpcalgoport` binds on 127.0.0.1 (loopback) only, matching the security model of the default RPC port. Remote pool software needs SSH tunneling or a reverse proxy.

### Port Convention

| Algorithm | Port | Mnemonic |
|-----------|------|----------|
| X11 | 1100 | x**11** + 00 |
| KawPoW | 5700 | RVN stratum convention |
| Equihash 200,9 | 2009 | **200**,**9** |
| Equihash 192,7 | 1927 | **19**2,**7** |

### What Each Port Returns

Every algo port returns a standard GBT response:

- `version` -- block version with algo bits pre-set
- `bits` / `target` -- per-algo difficulty
- `coinbasevalue` -- total block reward + fees (in satoshis)
- `coinbasevalue_miner` -- pool's share only (vout[0], in satoshis)
- `coinbasetxn` -- pre-built coinbase transaction (**always present for equihash algos**; for X11/KawPoW, pass `"pooladdress": "<addr>"` in the GBT request or include `"coinbasetxn"` in `"capabilities"`)
- `previousblockhash`, `curtime`, `height` -- standard fields
- `algo` -- mining algorithm name (`x11`, `kawpow`, `equihash200`, `equihash192`)
- `blockhash_algorithm` -- always `x11` (block identity hashes use X11 regardless of mining algo)
- `template_hash` -- X11 identity hash of the template (use for post-submitblock lookups)
- `coinbase_payload` -- CbTx extra payload in hex
- `masternode` -- array of required masternode/treasury payment outputs
- Equihash ports also include: `equihash_n`, `equihash_k`, `personalization`, `header_hex`, `finalsaplingroothash`
- KawPoW port also includes: `headerhash`, `seedhash`

When `pooladdress` is passed in the GBT request and `coinbasetxn` is returned, pool software does not need masternode payment logic, CbTx handling, or multi-algo awareness.

### How to Request `coinbasetxn` for X11/KawPoW

Pass `pooladdress` in the GBT template request (this is NOT a kerrigan.conf option):

```bash
curl -u pool:<secret> --data-binary '{"method":"getblocktemplate","params":[{"rules":["segwit"],"pooladdress":"<your-kerrigan-address>"}]}' http://127.0.0.1:1100/
```

Alternatively, include `"capabilities": ["coinbasetxn"]` in the template request. Equihash algos always include `coinbasetxn` regardless.

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
        "algorithm": "kawpow",
        "useCoinbaseTxPayload": true
    },
    "kerrigan-equihash200": {
        "name": "Kerrigan-Equihash200",
        "symbol": "KRGN",
        "family": "equihash",
        "algorithm": "equihash",
        "useCoinbaseTxPayload": true,
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
        "useCoinbaseTxPayload": true,
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

### Important: Block Hash Semantics

Kerrigan uses X11 for **all** block identity hashes, regardless of mining algorithm. This means:
- `getblock`, `getbestblockhash`, `submitblock` all use X11 hashes
- The `template_hash` field in GBT is the X11 identity hash
- PoW validation uses algo-specific hashes internally (SHA256D for equihash, Keccak for KawPoW)
- Miningcore's `BitcoinJob.cs` must hash blocks with X11 for block confirmation lookups

### Important: `coinbasevalue` vs `coinbasevalue_miner`

- `coinbasevalue` = total block reward + fees (all outputs, in satoshis) -- BIP 22 standard
- `coinbasevalue_miner` = pool's share only (vout[0], in satoshis) -- Kerrigan extension

When using `coinbasetxn`, the pool does not need to compute the reward split. `coinbasevalue_miner` tells the pool exactly how much it earned per block for payout accounting.

### Minimal Code Changes

Starting from stock Miningcore, Kerrigan needs only:

1. Coin template entries (above)
2. Use `coinbasetxn` from GBT instead of building coinbase (eliminates masternode code)
3. `BitcoinPayoutHandler` -- use `Details[0].Amount` (upstream fix for MN coins where block `Amount` is 0)
4. `ref` parameter fixes for NBitcoin compat (upstream fix)
5. StratumShare record type for stats

**Total: ~50 lines of real changes, not 500+.**

## S-NOMP Integration

### Coin Configs

`coins/kerrigan_equihash192.json`:
```json
{
    "name": "KerriganEquihash192",
    "symbol": "KRGN",
    "algorithm": "equihash192_7",
    "peerMagic": "4b52474e",
    "peerMagicFallback": "4b52474e"
}
```

`coins/kerrigan_equihash200.json`:
```json
{
    "name": "KerriganEquihash200",
    "symbol": "KRGN",
    "algorithm": "equihash",
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

Set `"useCoinbasetxn": true` -- this tells S-NOMP to use the daemon's pre-built coinbase instead of constructing its own, eliminating the need for masternode payment code.

### Required S-NOMP Patches

Stock S-NOMP does not support `useCoinbasetxn` or equihash192. The following patches are required:

1. **coinbasetxn support** -- When `useCoinbasetxn` is true, use `coinbasetxn.data` from GBT as the complete coinbase transaction instead of building one. Skip `rewardRecipients` and masternode output construction.
2. **equihash192_7 algorithm** -- Register the equihash(192,7) solver in stratum-pool with personalization `"kerrigan"`.
3. **X11 block hash for CheckBlockAccepted** -- Kerrigan uses X11 for all block identity hashes regardless of mining algo. When confirming blocks via `getblock`, hash the submitted block with X11 (not SHA256d or equihash). The `template_hash` field in GBT provides the expected X11 hash.
4. **validateaddress instead of getaddressinfo** -- If building the daemon with `--disable-wallet` (recommended for pool nodes), `getaddressinfo` is unavailable. Use `validateaddress` for address validation in payment processing.
5. **coinVersionBytes in Redis** -- Inject Kerrigan's address version bytes into Redis for payment address validation (mainnet: 45/5 for k/K prefixes; testnet: 107/239).
6. **stratum-pool job[7] fix** -- The `clean_jobs` boolean at array position 8 in mining.notify can overwrite the algo identifier at position 7. See kerrigan-snomp postinstall script.

## Troubleshooting

**GPU miners (miniZ, lolMiner) dying after ~10 minutes:**
- Likely cause: near-zero per-algo difficulty causing rapid job notifications
- Fix: ensure difficulty floors are active (testnet: height >= 2260, mainnet: always active)

**Incorrect algo on block updates:**
- S-NOMP stratum-pool `job[8]=false` bug overwrites algo identifier
- Fix: apply the `job[7]=false` patch (see kerrigan-snomp postinstall script)

**Pool not finding blocks:**
- Verify daemon is running with `rpcalgoport` configured
- Test (equihash): `curl -u pool:<secret> --data-binary '{"method":"getblocktemplate","params":[{"rules":["segwit"]}]}' http://127.0.0.1:1927/`
- Test (x11/kawpow): `curl -u pool:<secret> --data-binary '{"method":"getblocktemplate","params":[{"rules":["segwit"],"pooladdress":"<your-addr>"}]}' http://127.0.0.1:1100/`
- Equihash response should include `coinbasetxn` and correct `equihash_n`/`equihash_k`
- X11/KawPoW response should include `coinbasetxn` when `pooladdress` is provided

**Block hash mismatch after submitblock:**
- Kerrigan uses X11 for all block identity hashes regardless of mining algo
- `getblock` and `getbestblockhash` always return X11 hashes
- The `template_hash` field in GBT matches the X11 identity hash


## Building Coinbase From Scratch

If your pool must rebuild the coinbase instead of using `coinbasetxn`, the
following details are mandatory. Getting any of them wrong orphans every block.

### masternode[] Output Array

GBT returns a `masternode` array with **4 entries** (not 1 like stock Dash):

| Index | Recipient | Typical share |
|-------|-----------|---------------|
| 0 | Growth escrow (consensus-locked P2SH) | 40% |
| 1 | Masternode payment | 20% |
| 2 | Dev fund | 5% |
| 3 | Founders fund | 5% |

The miner receives the remainder (typically 30%). Use `coinbasevalue_miner`
for the miner output amount, NOT `coinbasevalue` (which is the full block
reward including all 4 mandatory outputs).

### CCbTx Payload (nVersion and vExtraPayload)

Kerrigan coinbase transactions use Dash v3 special transaction format:

- `nVersion` must be `0x00050003` (version 3 with type 5 = TRANSACTION_COINBASE)
- `vExtraPayload` must contain the `coinbase_payload` hex from GBT verbatim

The payload encodes the deterministic masternode list merkle root and block
height. The daemon generates it; the pool just preserves the bytes. Do NOT
modify or recompute the payload.

### coinbase_payload and HMP

The `coinbase_payload` may include HMP (Hivemind Protocol) seal identity
data. Pools do not need to understand HMP internals. The payload bytes pass
through verbatim from GBT to the submitted block. The seal signs over the
previous block's state (prevSealHash), not the current coinbase, so
reusing the payload on a pool-rebuilt coinbase is consensus-valid.

### Pseudocode: Rebuilding a Coinbase

```
# 1. Request GBT with pooladdress
gbt = rpc("getblocktemplate", {"pooladdress": POOL_ADDR})

# 2. Build outputs
outputs = []
for mn in gbt["masternode"]:
    outputs.append(TxOut(mn["amount"], decode_script(mn["script"])))
miner_amount = gbt["coinbasevalue_miner"]
outputs.append(TxOut(miner_amount, pay_to_address(POOL_ADDR)))

# 3. Build coinbase input
scriptsig = serialize_height(gbt["height"]) + extranonce1 + extranonce2
coinbase_in = TxIn(prevout=NULL_OUTPOINT, scriptsig=scriptsig, sequence=0xffffffff)

# 4. Assemble transaction with CCbTx payload
tx = Transaction()
tx.nVersion = 0x00050003          # TRANSACTION_COINBASE v3
tx.vin = [coinbase_in]
tx.vout = outputs
tx.nLockTime = 0
tx.vExtraPayload = hex_decode(gbt["coinbase_payload"])  # verbatim

# 5. Submit block with this coinbase
block = assemble_block(gbt, tx)
rpc("submitblock", block.serialize_hex())
```

**Simpler alternative:** Use `coinbasetxn` from GBT directly and skip all of
the above. The daemon handles the entire coinbase construction including
masternode outputs, CbTx payload, and HMP data. The pool only needs to inject
extranonce into the scriptSig for share uniqueness.
