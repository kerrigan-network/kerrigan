# BroodNode Operator Setup (v1.2.0+)

This guide walks an operator through registering a Kerrigan **BroodNode**
on a daemon running v1.2.0 or later. It assumes a working `kerrigand`
that is fully synced and a wallet you control.

> **Status.** v1.2.0 is the first release in which the BROOD code path is
> active in production. Earlier versions registered Evo-collateral
> masternodes, but the HMP privilege tracker never promoted any signer
> beyond `ELDER` because the seal-algo gating was misaligned (see
> `release-notes-v1.2.0.md`). The walk-through below documents v1.2.0
> behaviour; it does not retroactively apply to pre-v1.2.0 daemons.

## What a BroodNode is

A BroodNode is the top HMP privilege tier. It combines:

- A normal **Elder** (a daemon whose HMP identity has solved the
  Elder-threshold number of blocks on at least one algorithm), and
- A **40,000 KRGN** Evo-type masternode collateral, whose registered
  `operatorPubKey` matches that daemon's HMP BLS public key.

When both conditions hold, the privilege tracker reports
`tier = BROOD` for the matching `(pubkey, algo)` pair. That gives the
operator two concrete advantages over a plain Elder:

| Effect | Plain Elder | BroodNode |
|---|---|---|
| VRF selection probability | 60% (3x base) | 80% (4x base) |
| Seal-weight bonus per BROOD signer's algo | n/a | +300 bps, capped at +1200 bps total |

The seal-weight bonus stacks with the cross-algorithm Elder bonus
(+500 bps per off-algo Elder, capped at +1500 bps), so a fully-attended
seal can reach a chain-weight multiplier of `15000 + 1500 + 1200 = 17700`
bps versus the `10000` bps baseline.

## Prerequisites

- `kerrigand` v1.2.0 or later, fully synced to tip.
- 40,000 KRGN in a wallet you control on this daemon (or on a wallet
  you can sign from), available for collateral.
- Familiarity with the `protx` family of RPCs. This guide assumes you
  already know how to register a Regular masternode; the BroodNode
  flow only differs in the collateral amount and the
  `register_fund_evo` variant.
- A static, reachable IPv4 or IPv6 address for the masternode service.
- Platform node credentials (`platformNodeID`, Platform P2P port,
  Platform HTTPS port). All three Platform fields are mandatory in the
  v1.2.0 RPC schema even when Platform itself is not yet in use. The
  `platformNodeID` may be a placeholder 20-byte hex value, and the
  ports must be valid TCP port numbers (1-65535); for pre-Platform
  deployments any port that the daemon's firewall does not actually
  open (e.g. the chain default) is acceptable, since the daemon does
  not refuse registration for an unreachable port.

## Step 1 -- Get this daemon's HMP identity

The HMP identity is the BLS public key persisted in
`<datadir>/hmp_identity.dat`. It is auto-generated on first daemon
start. The new `gethmpidentity` RPC returns the current value:

```bash
kerrigan-cli gethmpidentity
```

```json
{
  "identity": "<48-byte-hex-bls-pubkey>",
  "valid": true
}
```

Copy the `identity` hex string. That is the value you will pass as the
`operatorPubKey` argument to `protx register_fund_evo` in step 4.

> **Important.** `IsBroodNodeOperator()` compares the on-chain
> registered operator key against the BLS public key in
> `hmp_identity.dat`, **not** against any wallet-generated BLS key.
> Registering with a key that does not match what `gethmpidentity`
> returns produces an Evo-collateral masternode that the local daemon
> will not recognise as its own, no Brood-tier privileges will be
> granted, and seal-sign attempts will silently fail.

## Step 2 -- Generate a voting key

The voting key is a separate Kerrigan address used to cast governance
votes on behalf of this BroodNode. You may either:

- **Generate a fresh voting address** (recommended; isolates governance
  authority from owner keys):

  ```bash
  kerrigan-cli getnewaddress "broodnode-voting"
  ```

- **Re-use the owner address** by passing the same address for both
  `ownerAddress` and `votingAddress`. This is operationally simpler but
  collapses governance and ownership authority into a single key; if
  the owner key is compromised, voting is also compromised.

The `bls generate` RPC is **not** used for the voting key. It produces
a BLS keypair, which is the wrong format for `votingAddress` (a P2PKH
address is expected). It is only relevant if you want to use a
locally-generated BLS operator key instead of the daemon's HMP
identity, which defeats the purpose of step 1.

Record the chosen voting address.

## Step 3 -- Fund the collateral

For `register_fund_evo`, the registration RPC funds the collateral
atomically in a single transaction; you do not pre-send the 40,000
KRGN. Skip ahead to step 4 if you intend to use that variant.

For `register_evo` (externally-referenced collateral), send exactly
**40,000 KRGN** to a fresh address you control, wait for at least
one confirmation, and record the funding txid and vout for the RPC:

```bash
kerrigan-cli getnewaddress "broodnode-collateral"
# Returns: <collateralAddress>

kerrigan-cli sendtoaddress <collateralAddress> 40000
# Returns: <fundingTxid>

# Wait for at least 1 confirmation
kerrigan-cli gettransaction <fundingTxid>
```

The collateral output is locked for as long as the masternode is
active; spending it deregisters the BroodNode.

## Step 4 -- Register the BroodNode

Run `protx register_fund_evo` with the values from steps 1-3. Argument
order (positional):

```text
protx register_fund_evo
    <collateralAddress>      # fresh address that will hold the 40000 KRGN
    <coreP2PAddrs>           # "ip:port" string, the masternode service endpoint
    <ownerAddress>           # owner key, controls update_registrar / revoke
    <operatorPubKey>         # value from `gethmpidentity` (step 1)
    <votingAddress>          # from step 2
    <operatorReward>         # 0..10000 (basis points of block reward to operator)
    <payoutAddress>          # where collateral-owner reward is paid
    <platformNodeID>         # 20-byte hex platform node id (placeholder OK pre-Platform)
    <platformP2PPort>        # integer, 0 acceptable as placeholder
    <platformHTTPSPort>      # integer, 0 acceptable as placeholder
    [fundAddress]            # optional, address to fund the registration tx fee from
    [submit]                 # optional bool, default true
```

Concrete invocation with synthetic placeholders:

```bash
kerrigan-cli protx register_fund_evo \
    "KKerriganMainnetCollateralAddrExample" \
    "203.0.113.10:9999" \
    "KKerriganMainnetOwnerAddrExample" \
    "<48-byte-hex-from-gethmpidentity>" \
    "KKerriganMainnetVotingAddrExample" \
    0 \
    "KKerriganMainnetPayoutAddrExample" \
    "0000000000000000000000000000000000000000" \
    0 0
```

The RPC returns the ProRegTx txid. Record it; you will need it as the
`<protxhash>` argument to `protx info` and to `protx update_*` later.

## Step 5 -- Wait for activation and verify the registration

The ProRegTx must reach roughly **5 confirmations** before the
deterministic masternode list (DML) treats the BroodNode as active.
While you wait:

```bash
# Watch for the ProRegTx in the mempool / mined
kerrigan-cli getrawtransaction <protxhash> 1
```

Once confirmed:

```bash
# The BroodNode should appear in the valid list
kerrigan-cli protx list valid

# Inspect the on-chain record (operator key, ports, collateral, payout)
kerrigan-cli protx info <protxhash>
```

In `protx info` output, confirm that `state.pubKeyOperator` is
**byte-for-byte identical** to the `identity` field that
`gethmpidentity` returned in step 1. Any mismatch here is the
single most common cause of "I see myself as ELDER but never BROOD"
later on; fix it now by re-running step 1, regenerating the ProRegTx
with the correct operator key, and waiting for the new tx to confirm.

## Step 6 -- Verify the daemon recognises itself

Run the diagnostics RPC:

```bash
kerrigan-cli gethmpdiagnostics
```

The `identity` field at the top of the response is what the local
daemon advertises. It must match `state.pubKeyOperator` from
`protx info <protxhash>` exactly. If it does, the daemon will treat
its own seal-share emissions as BroodNode-tier as soon as the Elder
threshold is also met (step 7).

## Step 7 -- Mine to ELDER, then to BROOD

Tier promotion is purely block-history-driven. With v1.2.0:

- **NEW to ELDER:** the privilege tracker requires
  `GetEffectiveMinBlocksSolved(height)` blocks solved on a single
  algorithm within the privilege window. On v1.2.0 mainnet activation
  this returns **3**. Pre-v1.2.0 daemons used `nHMPMinBlocksSolved = 10`
  and could not realistically form Elders under observed multi-pool
  hashpower distribution; v1.2.0 recalibrates this.
- **ELDER to BROOD:** automatic. As soon as `IsBroodNodeOperator()`
  finds a matching `(operatorPubKey == hmp_identity)` Evo MN on the
  DML and the daemon already qualifies as ELDER on at least one
  algorithm, `GetTier()` returns `BROOD` for that `(pubkey, algo)`.

Concentrate hashpower on **one algorithm** until the daemon clears the
Elder threshold on it; spreading thinly delays promotion. Watch the
log stream:

```bash
tail -f <datadir>/debug.log | grep "HMP:.*tier"
```

Lines you should see:

```
HMP: *** YOUR NODE *** tier NEW -> ELDER on algo <algo> (height <h>)
HMP: *** YOUR NODE *** tier ELDER -> BROOD on algo <algo> (height <h>)
```

## Verification commands

| Check | Command | What to confirm |
|---|---|---|
| Local identity | `kerrigan-cli gethmpidentity` | `valid: true` and the hex matches your registered `pubKeyOperator` |
| Per-algo tier | `kerrigan-cli gethmpdiagnostics` | `tiers.<algo>.tier == "BROOD"` for the algo you mined on |
| Privileged set membership | `kerrigan-cli gethmpprivilegedset <algo>` | your pubkey appears with `tier: "BROOD"` |
| Seal weight on a block you sealed | `kerrigan-cli getsealstatus <blockhash>` | `seal_weight > 10000`; with a healthy BROOD signer set, expect `12000-17700` |

## Troubleshooting

**"I see myself as ELDER but never BROOD."** The daemon's HMP identity
does not match the on-chain `pubKeyOperator`. Compare:

```bash
kerrigan-cli gethmpidentity
kerrigan-cli protx info <protxhash>
```

If the values differ, the registered ProRegTx was made with the wrong
operator key (most often a `bls generate` BLS key that lives only in
the wallet, not in `hmp_identity.dat`). Use `protx update_registrar`
to rotate the on-chain operator key to the value from
`gethmpidentity`, or, if that is not viable, deregister and start
again from step 4 with the correct key.

**"I see myself as NEW forever."** The Elder threshold has not been
met on any single algorithm. On v1.2.0 the threshold is 3 blocks
solved within the privilege window; on pre-v1.2.0 it was 10. Verify:

```bash
kerrigan-cli gethmpdiagnostics
```

Look at `tiers.<algo>.blocks_solved`. If every algo is below the
threshold, mine more blocks on one of them. Spreading hashpower
across algorithms keeps each per-algo counter below threshold and
prevents promotion.

**"Logs show no tier transitions."** The HMP debug category is gated.
Add to `kerrigan.conf`:

```ini
debug=hmp
```

Restart the daemon, then re-check the log stream filter from step 7.
Note that the privilege tracker only logs the **change**, not steady
state; if you have already been ELDER since before the log started,
no transition is printed until the next state change.

**"`protx list valid` does not show my BroodNode."** Either the
ProRegTx has fewer than the activation-confirmation count required
by the DML, or the funding transaction was malformed (collateral not
exactly 40,000 KRGN, wrong vout). Inspect with:

```bash
kerrigan-cli getrawtransaction <protxhash> 1
kerrigan-cli protx list invalid
```

The `invalid` list explains why a ProRegTx was rejected.

## Risks before committing 40k KRGN

The BROOD privilege path has not previously executed in production.
v1.2.0 ships:

- The first activation-gated path (`nHMPSealAlgoFixHeight`) that lets
  Elders form on mainnet, which is the prerequisite for any BROOD
  promotion at all.
- The first `IsBroodNodeOperator()` lookup that consults the live
  DML, gated on `MnType::Evo`.
- The first VRF tier multiplier of 4 (BROOD), versus the previously
  unreachable code path.

Anyone considering registering a BroodNode on mainnet immediately on
v1.2.0 release should weigh:

1. Waiting for the community testnet rehearsal results to publish.
2. Confirming on testnet that a daemon under their own operational
   conditions reaches and stays at `tier: "BROOD"` across at least
   one full privilege window.
3. Reviewing `release-notes-v1.2.0.md` for any post-tag advisories.

The 40,000 KRGN collateral is recoverable at any time by spending the
collateral output (which deregisters the masternode), so the financial
risk is limited to opportunity cost plus on-chain fees, not the
principal. Operational risk - a daemon that registers but never
qualifies as BROOD because of a key mismatch or a missed Elder
threshold - is the more common failure mode.

## Cross-references

- Whitepaper Section 6.3 ("HMP tier semantics"). The whitepaper update
  documenting BROOD activation lands in the same v1.2.0 release; until
  that revision is published, treat this document as the source of
  truth for v1.2.0 behaviour.
- `kerrigan-cli help gethmpidentity`
- `kerrigan-cli help gethmpdiagnostics`
- `kerrigan-cli help gethmpprivilegedset`
- `kerrigan-cli help getsealstatus`
- `kerrigan-cli help protx register_fund_evo`
- `doc/release-notes-v1.2.0.md` (when published) for the activation
  height and any operator advisories.
