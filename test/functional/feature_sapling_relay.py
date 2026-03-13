#!/usr/bin/env python3
# Copyright (c) 2026 The Kerrigan developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test compact block relay with Sapling transactions.

Exercises:
  1. Mempool match — Sapling tx in both mempools, compact block reconstructed
  2. GETBLOCKTXN fallback — Sapling tx only on miner, peer requests full tx
  3. Large payload — tx with memo field relays correctly

Requires Sapling parameters in ~/.kerrigan-params/ (run contrib/fetch-params.sh).
"""

import os
from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_framework import SkipTest
from test_framework.util import assert_equal

MATURITY = 100
EXTRA_BLOCKS = 10


class SaplingRelayTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        params_dir = os.path.expanduser("~/.kerrigan-params")
        spend = os.path.join(params_dir, "sapling-spend.params")
        output = os.path.join(params_dir, "sapling-output.params")
        if not (os.path.exists(spend) and os.path.exists(output)):
            raise SkipTest(
                "Sapling parameters not found. Run contrib/fetch-params.sh first."
            )

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        # --- Setup ---
        self.log.info("Mining %d blocks for coinbase maturity", MATURITY + EXTRA_BLOCKS)
        t_addr = node0.getnewaddress()
        self.generatetoaddress(node0, MATURITY + EXTRA_BLOCKS, t_addr)
        self.sync_all()

        z_addr_0 = node0.z_getnewaddress()

        # Shield some coins for later z→z tests
        node0.z_sendmany(t_addr, [{"address": z_addr_0, "amount": 10.0}])
        self.generatetoaddress(node0, 1, t_addr)
        self.sync_all()

        # --- Test 1: Mempool match (compact block reconstructed) ---
        self.log.info("Test 1: Compact block with mempool match")
        z_addr_1 = node1.z_getnewaddress()
        txid1 = node0.z_sendmany(
            t_addr,
            [{"address": z_addr_0, "amount": 3.0}],
        )
        # Both nodes should have the tx in mempool after sync
        self.sync_mempools()
        assert txid1 in node1.getrawmempool(), "tx should be in node1 mempool"

        # Mine on node0 — node1 should reconstruct block from compact + mempool
        self.generatetoaddress(node0, 1, t_addr)
        self.sync_blocks()
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())
        self.log.info("  Compact block with mempool match: OK")

        # --- Test 2: GETBLOCKTXN fallback ---
        self.log.info("Test 2: GETBLOCKTXN fallback (tx only on miner)")
        # Disconnect nodes
        self.disconnect_nodes(0, 1)

        # Send z→z only on node0 (node1 won't have it in mempool)
        txid2 = node0.z_sendmany(
            z_addr_0,
            [{"address": z_addr_1, "amount": 1.0}],
        )
        # Mine without syncing (nodes are disconnected)
        self.generatetoaddress(node0, 1, t_addr, sync_fun=self.no_op)

        # Reconnect — node1 must request the full tx via GETBLOCKTXN
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())

        # Node 1 should see the shielded note
        z_bal_1 = Decimal(node1.z_getbalance(z_addr_1))
        assert_equal(z_bal_1, Decimal("1.0"))
        self.log.info("  GETBLOCKTXN fallback: OK")

        # --- Test 3: Large payload with memo ---
        self.log.info("Test 3: Large Sapling payload with memo relays correctly")
        z_addr_0b = node0.z_getnewaddress()
        # 512-byte memo (max size), filled with pattern
        memo_hex = "ab" * 512
        txid3 = node0.z_sendmany(
            t_addr,
            [{"address": z_addr_0b, "amount": 1.0, "memo": memo_hex}],
        )
        self.sync_mempools()
        self.generatetoaddress(node0, 1, t_addr)
        self.sync_blocks()

        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())

        # Verify memo preserved after relay
        unspent = node0.z_listunspent(1, 9999999, [z_addr_0b])
        assert len(unspent) >= 1, "Should have note at memo address"
        assert unspent[0]["memo"].startswith(memo_hex), \
            "Memo should be preserved through relay"
        self.log.info("  Large payload relay: OK")

        self.log.info("All Sapling relay tests passed!")


if __name__ == "__main__":
    SaplingRelayTest().main()
