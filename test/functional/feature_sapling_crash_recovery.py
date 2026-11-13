#!/usr/bin/env python3
# Copyright (c) 2026 The Kerrigan developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that a node restarts after an unclean stop with Sapling state ahead.

SaplingDB (<datadir>/sapling) is written and synced at every block, while the
coins database and the block index are only written at periodic flushes (the
block index at most hourly, the coins at most daily or when the cache fills).
A SIGKILL, an OOM kill, a segfault or a full disk therefore leaves SaplingDB
ahead of the coins tip, usually at a block the block index never recorded.
Startup used to read that as drift and refuse to start (headless:
"HEADLESS FAULT EXIT (STARTUP_DRIFT ...)"; mainnet: the post-rollback
contamination check). The node must instead bring SaplingDB back to the coins
tip and resync the lost blocks, with the Sapling state matching a node that
never crashed.

Scenarios (each kills node0 with SIGKILL and restarts it in the headless
default, without -parkonfault):
  1. SaplingDB ahead on the same branch, with shields and z->z spends in the
     lost blocks.
  2. SaplingDB on another branch: a reorg after the last flush, then a kill.
  3. A kill right after IBD, before the first flush (coins at genesis).
  4. The sapling/ directory lost: rebuilt from the block files.
  5. A startup rebuild that fails partway (test-only -stopsaplingreplayat),
     then a restart that continues it.
After each, the restarted node must match node1 (a node that never crashed):
same tip, same Sapling value pool, and Sapling spends that both accept.
"""

import os
import shutil
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_framework import SkipTest
from test_framework.test_node import ErrorMatch
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)

MATURITY = 100
DRIFT_EXIT_TAG = "HEADLESS FAULT EXIT"


class SaplingCrashRecoveryTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=False)

    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        params_dir = os.path.expanduser("~/.kerrigan-params")
        for name in ("sapling-spend.params", "sapling-output.params"):
            if not os.path.exists(os.path.join(params_dir, name)):
                raise SkipTest("Sapling parameters not found. Run contrib/fetch-params.sh first.")

    def setup_network(self):
        # node2 is a plain follower of node1 that never stops cleanly before
        # scenario 3, so its coins are never flushed.
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.connect_nodes(2, 1)

    # -- helpers --------------------------------------------------------

    def kill_node(self, i):
        """SIGKILL node i: no shutdown flush of the coins, block index or wallet."""
        node = self.nodes[i]
        node.process.kill()
        node.process.wait(timeout=60)
        node.running = False
        node.process = None
        node.rpc = None
        node.rpc_connected = False
        self.log.info("  node%d killed (SIGKILL)", i)

    def sapling_pool(self, i):
        # gettxoutsetinfo flushes the chainstate, so call it only where a
        # flush does not matter (node1, or node0 after recovery).
        return Decimal(str(self.nodes[i].gettxoutsetinfo("none")["sapling_pool"]))

    def debug_log_since(self, i, offset):
        with open(os.path.join(self.nodes[i].chain_path, "debug.log"), encoding="utf-8") as f:
            f.seek(offset)
            return f.read()

    def debug_log_size(self, i):
        return os.path.getsize(os.path.join(self.nodes[i].chain_path, "debug.log"))

    def restart_after_kill(self, i, extra_args=None):
        """Start node i after a kill; it must come up (no drift exit)."""
        offset = self.debug_log_size(i)
        self.start_node(i, extra_args=extra_args)
        log = self.debug_log_since(i, offset)
        assert DRIFT_EXIT_TAG not in log, "node refused to start after an unclean stop"
        return log

    def assert_in_sync(self, nodes=(0, 1)):
        tips = {self.nodes[i].getbestblockhash() for i in nodes}
        assert_equal(len(tips), 1)
        pools = {self.sapling_pool(i) for i in nodes}
        assert_equal(len(pools), 1)
        return pools.pop()

    def check_spends_both_ways(self, z0, z1):
        """A z->z spend each way, each mined by the other node: both nodes must
        accept the other's anchors and nullifiers."""
        n0, n1 = self.nodes[0], self.nodes[1]
        txid = n0.z_sendmany(z0, [{"address": z1, "amount": 0.5}])
        self.sync_mempools([n0, n1])
        self.generate(n1, 1)
        assert_equal(n0.getrawtransaction(txid, 1)["confirmations"], 1)
        txid = n1.z_sendmany(z1, [{"address": z0, "amount": 0.25}])
        self.sync_mempools([n0, n1])
        self.generate(n0, 1)
        assert_equal(n1.getrawtransaction(txid, 1)["confirmations"], 1)

    # -- scenarios ------------------------------------------------------

    def run_test(self):
        n0, n1 = self.nodes[0], self.nodes[1]
        self.t0 = n0.getnewaddress()
        self.t1 = n1.getnewaddress()
        self.generatetoaddress(n0, MATURITY + 20, self.t0)
        self.generatetoaddress(n1, MATURITY + 20, self.t1)
        self.z0 = n0.z_getnewaddress()
        self.z1 = n1.z_getnewaddress()

        # Shielded funds on both sides, so both can spend later.
        n0.z_sendmany(self.t0, [{"address": self.z0, "amount": 20.0}])
        n1.z_sendmany(self.t1, [{"address": self.z1, "amount": 20.0}])
        self.sync_mempools([n0, n1])
        self.generate(n0, 2)

        self.scenario_ahead_same_branch()
        self.scenario_other_branch()
        self.scenario_kill_after_ibd()
        self.scenario_sapling_dir_lost()
        self.scenario_kill_during_rebuild()

    def scenario_ahead_same_branch(self):
        self.log.info("Scenario 1: kill with SaplingDB ahead on the same branch")
        n0, n1 = self.nodes[0], self.nodes[1]

        # A clean restart flushes node0's coins and block index here.
        self.restart_node(0)
        self.connect_nodes(0, 1)
        flushed_height = n0.getblockcount()

        # Sapling activity that only SaplingDB persists: a shield, z->z spends
        # (nullifiers) and blocks without Sapling txs (carry-forward roots).
        n0.z_sendmany(self.t0, [{"address": self.z0, "amount": 3.0}])
        self.generate(n0, 1)
        n0.z_sendmany(self.z0, [{"address": self.z1, "amount": 2.0}])
        self.generate(n0, 1)
        n1.z_sendmany(self.z1, [{"address": self.z0, "amount": 1.0}])
        self.sync_mempools([n0, n1])
        self.generate(n1, 3)
        z0_balance = Decimal(n0.z_getbalance(self.z0))
        tip = n0.getbestblockhash()
        assert_greater_than(n0.getblockcount(), flushed_height)

        self.kill_node(0)
        log = self.restart_after_kill(0)
        assert "Reconciled Sapling state" in log, "the restart should reconcile SaplingDB"
        assert "rolled back from height" in log, "SaplingDB should roll back from its own records"
        assert_equal(n0.getblockcount(), flushed_height)

        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(n0.getbestblockhash(), tip)
        self.assert_in_sync()
        n0.syncwithvalidationinterfacequeue()
        assert_equal(Decimal(n0.z_getbalance(self.z0)), z0_balance)
        self.check_spends_both_ways(self.z0, self.z1)
        self.assert_in_sync()

    def scenario_other_branch(self):
        self.log.info("Scenario 2: kill after a reorg, SaplingDB on another branch than the coins")
        n0, n1 = self.nodes[0], self.nodes[1]
        self.disconnect_nodes(0, 1)

        # Branch A on node0 (a shield and a z->z spend), flushed by a clean restart.
        n0.z_sendmany(self.t0, [{"address": self.z0, "amount": 4.0}])
        self.generate(n0, 1, sync_fun=self.no_op)
        n0.z_sendmany(self.z0, [{"address": self.z0, "amount": 1.5}])
        self.generate(n0, 1, sync_fun=self.no_op)
        self.restart_node(0)
        branch_a_tip = n0.getbestblockhash()

        # Branch B on node1, longer, with its own Sapling activity.
        n1.z_sendmany(self.t1, [{"address": self.z1, "amount": 5.0}])
        self.generate(n1, 1, sync_fun=self.no_op)
        n1.z_sendmany(self.z1, [{"address": self.z1, "amount": 0.75}])
        self.generate(n1, 3, sync_fun=self.no_op)

        # node0 reorgs to B (SaplingDB follows and syncs), then dies.
        self.connect_nodes(0, 1)
        self.sync_blocks([n0, n1])
        assert branch_a_tip != n0.getbestblockhash()
        self.kill_node(0)

        log = self.restart_after_kill(0)
        assert "Reconciled Sapling state" in log
        assert_equal(n0.getbestblockhash(), branch_a_tip)

        self.connect_nodes(0, 1)
        self.sync_blocks([n0, n1])
        self.assert_in_sync()
        # Branch A's transactions went back to the mempool; mine them on B.
        n0.syncwithvalidationinterfacequeue()
        self.generate(n0, 1)
        self.assert_in_sync()
        self.check_spends_both_ways(self.z0, self.z1)
        self.assert_in_sync()

    def scenario_kill_after_ibd(self):
        self.log.info("Scenario 3: kill a node whose coins were never flushed")
        n2 = self.nodes[2]
        self.sync_blocks([self.nodes[1], n2])
        self.kill_node(2)

        self.restart_after_kill(2)
        self.connect_nodes(2, 1)
        self.sync_blocks([self.nodes[1], n2])
        self.assert_in_sync(nodes=(1, 2))

    def scenario_sapling_dir_lost(self):
        self.log.info("Scenario 4: sapling/ lost, rebuilt from the block files")
        n0 = self.nodes[0]
        self.stop_node(0)
        shutil.rmtree(os.path.join(n0.chain_path, "sapling"))
        log = self.restart_after_kill(0)
        assert "Rebuilding Sapling state from the block files" in log
        self.connect_nodes(0, 1)
        self.sync_blocks([n0, self.nodes[1]])
        self.assert_in_sync()
        self.check_spends_both_ways(self.z0, self.z1)
        self.assert_in_sync()

    def scenario_kill_during_rebuild(self):
        self.log.info("Scenario 5: the startup rebuild fails partway, the next start continues it")
        n0 = self.nodes[0]
        self.stop_node(0)
        shutil.rmtree(os.path.join(n0.chain_path, "sapling"))
        offset = self.debug_log_size(0)
        n0.assert_start_raises_init_error(
            extra_args=["-stopsaplingreplayat=60"],
            expected_msg="Unable to rebuild the Sapling state after an unclean shutdown",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        assert "Sapling rebuild stopped for testing at height 60" in self.debug_log_since(0, offset)
        log = self.restart_after_kill(0)
        # Continued from the blocks the failed start rebuilt, not from scratch.
        assert "Rebuilding Sapling state from the block files" not in log
        assert "rolled back from height" not in log
        assert "Rolling Sapling state forward: height 60 of" in log
        self.connect_nodes(0, 1)
        self.sync_blocks([n0, self.nodes[1]])
        self.assert_in_sync()
        self.check_spends_both_ways(self.z0, self.z1)
        self.assert_in_sync()


if __name__ == '__main__':
    SaplingCrashRecoveryTest().main()
