#!/usr/bin/env python3
# Copyright (c) 2026 The Kerrigan developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the keyless value-conserving growth-escrow burn (Plan A').

Two consensus changes ship together at the escrow-sunset boundary
(mainnet 129999/130000; regtest 499/500, which mirror mainnet's
end == burn-1 relationship exactly):

1. EMISSION BURN AT SOURCE (nGrowthEscrowEndHeight): from the block AFTER
   the sunset height the 40% growth-escrow coinbase slot is an OP_RETURN
   burn instead of paying growthEscrowScript -- new emission stops
   accumulating into the (governance-locked, de-facto unspendable) escrow.

2. ESCROW BURN CARVE-OUT (nEscrowBurnHeight): from that same height a
   "pure escrow burn" tx is consensus-valid without a funded governance
   proposal AND without input-script verification. A pure escrow burn is
   defined (validation.cpp::IsPureEscrowBurn) as a plain (TRANSACTION_NORMAL)
   tx whose inputs ALL pay a growth-escrow script (current or legacy) and
   whose outputs are ALL OP_RETURN with sum(out) == sum(in) (zero fee). The
   carve-out can therefore ONLY destroy escrow value -- never redirect it to
   a spendable address, never leak it to the miner as fee. The keys that
   could otherwise spend the escrow are dead (pre-Plan-X rollover), so this
   is the only mechanism that can retire the ~1.26M accumulated balance.

This test proves, on regtest:
  * the emission slot flips to OP_RETURN at the boundary,
  * a pure escrow burn is accepted in a block, consumes the escrow UTXO,
    leaves NOTHING new in the UTXO set (OP_RETURN is unspendable -> AddCoin
    drops it), and reduces total supply by EXACTLY the burned amount,
  * the burn reorgs cleanly: invalidateblock restores the escrow UTXO and
    the supply; reconsiderblock re-burns; a from-scratch node (node1) that
    syncs the chain lands on the identical tip and UTXO-set total (the
    determinism / undo-consistency property),
  * non-pure escrow spends are still rejected by the governance gate:
    a fee leak (out < in), a non-OP_RETURN output, and a mixed
    escrow+ordinary input set all fail to connect.

Modeled on feature_drone_payments.py (hand-built coinbases + submitblock).

NOTE (2026-08-16): written against branch feature/growth-escrow-burn; the
local build tree is root-owned so this has NOT yet been executed. Run once
the tree is chown'd:  test/functional/feature_escrow_burn.py
"""

from decimal import Decimal

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    tx_from_hex,
)
from test_framework.script import CScript, OP_RETURN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# regtest consensus (chainparams.cpp, CRegTestParams):
ESCROW_END_HEIGHT = 499   # consensus.nGrowthEscrowEndHeight (= burn - 1)
ESCROW_BURN_HEIGHT = 500  # consensus.nEscrowBurnHeight
COINBASE_MATURITY = 100


class EscrowBurnTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        # node1 is the from-scratch oracle: it never mines, only syncs, so
        # its UTXO-set total is an independent recomputation of node0's --
        # the determinism / connect-undo consistency check. It also gives
        # node0's getblocktemplate a peer connection.
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[], []]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    # ---- helpers ---------------------------------------------------------

    def mine(self, n):
        # Mine to our own wallet: the framework's deterministic generate()
        # uses Dash-prefixed addresses invalid on Kerrigan regtest.
        return self.generatetoaddress(self.nodes[0], n, self.miner_addr)

    def escrow_slot_script(self):
        """Hex of the 40% growth-escrow slot in the NEXT block's template."""
        bt = self.nodes[0].getblocktemplate()
        return bt['masternode'][0]['script']

    def find_escrow_utxo(self, height, escrow_hex):
        """(txid, vout, value_sat) of the escrow output in the coinbase at
        `height`. Every escrow-era coinbase pays the 40% slot to escrow."""
        node = self.nodes[0]
        cb = node.getblock(node.getblockhash(height), 2)['tx'][0]
        for o in cb['vout']:
            if o['scriptPubKey']['hex'] == escrow_hex:
                return cb['txid'], o['n'], int(round(o['value'] * Decimal(1e8)))
        raise AssertionError("no escrow output in coinbase at height %d" % height)

    def build_block_with_txs(self, extra_txs):
        """Hand-build the next block from the template, appending extra_txs
        AFTER the template's required quorum commitments. Requires an empty
        mempool so the template's coinbase amounts are correct; the burn tx
        is zero-fee so it never changes the coinbase value."""
        node = self.nodes[0]
        assert_equal(node.getmempoolinfo()['size'], 0)
        bt = node.getblocktemplate()
        entries = [[e['script'], e['amount']] for e in bt['masternode']]
        miner_amount = bt['coinbasevalue'] - sum(a for _, a in entries)

        coinbase = CTransaction()
        coinbase.vin = create_coinbase(bt['height']).vin
        coinbase.vout = [CTxOut(int(miner_amount), CScript(bytes.fromhex('51')))]  # OP_TRUE
        for script, amount in entries:
            coinbase.vout.append(CTxOut(int(amount), CScript(bytes.fromhex(script))))
        if len(bt['coinbase_payload']) != 0:
            coinbase.nVersion = 3
            coinbase.nType = 5  # CbTx; reuse the template payload byte-for-byte
            coinbase.vExtraPayload = bytes.fromhex(bt['coinbase_payload'])
        coinbase.calc_sha256()

        block = create_block(coinbase=coinbase, tmpl=bt)
        for tx in bt['transactions']:
            tx2 = tx_from_hex(tx['data'])
            if tx2.nType == 6:  # quorum commitment
                block.vtx.append(tx2)
        block.vtx.extend(extra_txs)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        return block

    def submit(self, extra_txs, expect_ok):
        block = self.nodes[0].submitblock(
            self.build_block_with_txs(extra_txs).serialize().hex())
        if expect_ok:
            assert block is None, "burn block should connect, got %r" % block
        else:
            assert block is not None, "block should have been rejected but connected"
        return block

    def pure_burn_tx(self, escrow_utxo, out_delta=0, opreturn=True, extra_vin=None):
        """Build a burn tx spending `escrow_utxo` (txid, vout, value) with an
        EMPTY scriptSig -- the carve-out bypasses input-script checks, so no
        escrow key is needed. Knobs let the caller break each invariant:
          out_delta < 0  -> a fee leak (sum(out) < sum(in))
          opreturn=False -> a spendable P2PKH output (redirect attempt)
          extra_vin      -> an additional ordinary (non-escrow) input."""
        txid, vout, value = escrow_utxo
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(txid, 16), vout))]
        if extra_vin is not None:
            tx.vin.append(CTxIn(COutPoint(int(extra_vin['txid'], 16), extra_vin['vout'])))
        out_value = value + out_delta
        if opreturn:
            spk = CScript([OP_RETURN, b'krgn-growth-escrow-burn'])
        else:
            # a normal spendable script -> not a pure burn -> gated
            addr = self.nodes[0].getnewaddress()
            spk = CScript(bytes.fromhex(self.nodes[0].getaddressinfo(addr)['scriptPubKey']))
        tx.vout = [CTxOut(out_value, spk)]
        tx.calc_sha256()
        return tx

    def supply(self):
        return self.nodes[0].gettxoutsetinfo()['total_amount']

    # ---- test ------------------------------------------------------------

    def run_test(self):
        node = self.nodes[0]
        node1 = self.nodes[1]
        self.miner_addr = node.getnewaddress()

        self.log.info("escrow era: mine past maturity, capture the escrow slot script")
        self.mine(140)
        escrow_hex = self.escrow_slot_script()
        assert not escrow_hex.startswith('6a'), "escrow slot should NOT be OP_RETURN pre-boundary"

        # Four matured escrow UTXOs: one to burn, three to break invariants.
        burn_utxo = self.find_escrow_utxo(100, escrow_hex)
        fee_utxo = self.find_escrow_utxo(110, escrow_hex)
        redirect_utxo = self.find_escrow_utxo(120, escrow_hex)
        mixed_utxo = self.find_escrow_utxo(130, escrow_hex)
        for u in (burn_utxo, fee_utxo, redirect_utxo, mixed_utxo):
            assert node.gettxout(u[0], u[1]) is not None, "escrow UTXO must be unspent"

        self.log.info("mine to the burn boundary and assert emission now burns at source")
        self.mine(ESCROW_BURN_HEIGHT - node.getblockcount())
        assert_equal(node.getblockcount(), ESCROW_BURN_HEIGHT)
        # From nGrowthEscrowEndHeight+1 the 40% slot is an OP_RETURN burn.
        assert self.escrow_slot_script().startswith('6a'), \
            "emission slot should be OP_RETURN at/after the boundary"

        # Every block still mints net emission (the non-burned slots + miner
        # reward); the 40% escrow slot is now OP_RETURN'd. Measure one block's
        # net emission from a control block so we can isolate the burn's effect
        # on total supply (the burn block carries a coinbase too).
        self.log.info("measure per-block net emission at burn era")
        s0 = self.supply()
        self.mine(1)
        emission = self.supply() - s0

        supply_before = self.supply()
        self.log.info("a pure escrow burn connects, consumes the escrow UTXO, reduces supply")
        burn = self.pure_burn_tx(burn_utxo)
        self.submit([burn], expect_ok=True)
        assert node.gettxout(burn_utxo[0], burn_utxo[1]) is None, "escrow input must be consumed"
        assert node.gettxout(burn.rehash(), 0) is None, "OP_RETURN output must NOT enter the UTXO set"
        burned = Decimal(burn_utxo[2]) / Decimal(1e8)
        # burn block = coinbase mints `emission`, burn tx destroys `burned`.
        assert_equal(self.supply(), supply_before + emission - burned)

        self.log.info("reorg: invalidateblock restores the escrow UTXO and the supply")
        burn_block = node.getbestblockhash()
        node.invalidateblock(burn_block)
        assert node.gettxout(burn_utxo[0], burn_utxo[1]) is not None, "escrow UTXO must be restored"
        assert_equal(self.supply(), supply_before)
        node.reconsiderblock(burn_block)
        assert_equal(node.getbestblockhash(), burn_block)
        assert node.gettxout(burn_utxo[0], burn_utxo[1]) is None, "reconsider must re-burn"
        assert_equal(self.supply(), supply_before + emission - burned)

        self.log.info("from-scratch node1 lands on the identical tip and UTXO-set total")
        self.sync_blocks()
        assert_equal(node1.getbestblockhash(), node.getbestblockhash())
        assert_equal(node1.gettxoutsetinfo()['total_amount'], self.supply())

        self.log.info("non-pure escrow spends are still gated (fee leak / redirect / mixed input)")
        # a) fee leak: 1 sat to the miner -> not value-conserving -> gated
        self.submit([self.pure_burn_tx(fee_utxo, out_delta=-1)], expect_ok=False)
        # b) redirect: a spendable output -> not all-OP_RETURN -> gated
        self.submit([self.pure_burn_tx(redirect_utxo, opreturn=False)], expect_ok=False)
        # c) mixed input: escrow + an ordinary wallet coin -> not all-escrow -> gated
        wallet_coin = next(u for u in node.listunspent(COINBASE_MATURITY) if u['spendable'])
        self.submit([self.pure_burn_tx(mixed_utxo, extra_vin=wallet_coin)], expect_ok=False)

        # The escrow UTXOs that hit the gate remain unspent (their blocks were rejected).
        for u in (fee_utxo, redirect_utxo, mixed_utxo):
            assert node.gettxout(u[0], u[1]) is not None, "gated escrow UTXO must survive"

        self.log.info("escrow burn: all assertions passed")


if __name__ == '__main__':
    EscrowBurnTest().main()
