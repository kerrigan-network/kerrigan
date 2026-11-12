#!/usr/bin/env python3
# Copyright (c) 2026 The Kerrigan developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that a node restarts after it stopped between the coins and EvoDB writes.

A full flush writes the coins database (chainstate/) and then EvoDB (evodb/:
the masternode list, quorum commitments and other special-transaction state),
two separate databases. A kill, an OOM kill, a crash or a full disk between
the two writes leaves EvoDB at the block of the previous flush and the coins
at a later one. Startup used to read that as drift and refuse to start
(headless: "HEADLESS FAULT EXIT (STARTUP_DRIFT ...)"). The node must instead
replay the blocks in between, EvoDB and the Sapling state with the coins.

-crashbeforeevodbflush=<n> (regtest only) makes the node exit at the first
full flush at or above height n, after the coins are written and before
EvoDB is.

Scenarios (node0 stops there and restarts, node1 never stops):
  1. EvoDB behind on the same chain. The blocks in between hold a ProUpServTx
     and a ProUpRegTx, the spend of a masternode's collateral, a ProRegTx and
     a Sapling shield.
  2. EvoDB on another branch: a reorg after the last flush, then the stop.
After each, node0 must match node1: same tip, masternode list, quorum list,
UTXO set and Sapling value pool. Then each must accept the other's blocks,
node0's with a Sapling spend.
"""

import http.client
import os
from decimal import Decimal

from test_framework.test_framework import (
    MASTERNODE_COLLATERAL,
    BitcoinTestFramework,
    MasternodeInfo,
    SkipTest,
)
from test_framework.util import assert_equal, assert_greater_than, p2p_port

DIP3_ARGS = ["-dip3params=2:2"]
CRASH_TAG = "Simulating a crash between the coins and EvoDB writes"
DRIFT_EXIT_TAG = "HEADLESS FAULT EXIT"
RECONCILE_TAG = "after a stop between their writes"


class EvoDBCrashRecoveryTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=False)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [DIP3_ARGS, DIP3_ARGS]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        params_dir = os.path.expanduser("~/.kerrigan-params")
        for name in ("sapling-spend.params", "sapling-output.params"):
            if not os.path.exists(os.path.join(params_dir, name)):
                raise SkipTest("Sapling parameters not found. Run contrib/fetch-params.sh first.")

    # -- helpers --------------------------------------------------------

    def debug_log_size(self, i):
        return os.path.getsize(os.path.join(self.nodes[i].chain_path, "debug.log"))

    def debug_log_since(self, i, offset):
        with open(os.path.join(self.nodes[i].chain_path, "debug.log"), encoding="utf-8") as f:
            f.seek(offset)
            return f.read()

    def state(self, i):
        """What a stop between the two writes must not change."""
        node = self.nodes[i]
        mns = node.protx("list", "registered", True)
        for mn in mns:
            # What this node's wallet holds and its own connection data.
            mn.pop("wallet", None)
            mn.pop("metaInfo", None)
        utxo = node.gettxoutsetinfo()
        hashes = [k for k in utxo if k.startswith("hash_serialized")]
        assert hashes, "gettxoutsetinfo returned no UTXO set hash"
        return {
            "tip": node.getbestblockhash(),
            "masternodes": sorted(mns, key=lambda mn: mn["proTxHash"]),
            "quorums": node.quorum("list"),
            "utxo": {k: utxo[k] for k in ["height", "bestblock", "txouts", "total_amount", "sapling_pool"] + hashes},
        }

    def crash_in_flush(self, i):
        """Flush node i, which was started with -crashbeforeevodbflush."""
        node = self.nodes[i]
        offset = self.debug_log_size(i)
        try:
            node.gettxoutsetinfo("none")
        except (http.client.CannotSendRequest, http.client.RemoteDisconnected, ConnectionError) as e:
            self.log.debug("node%d: %r", i, e)
        else:
            raise AssertionError("the flush should have stopped the node")
        node.wait_until_stopped()
        assert CRASH_TAG in self.debug_log_since(i, offset)
        self.log.info("  node%d stopped after the coins write, before EvoDB's", i)

    def restart_after_crash(self, i):
        """Start node i with its usual arguments; it must come up."""
        offset = self.debug_log_size(i)
        self.start_node(i)
        log = self.debug_log_since(i, offset)
        assert DRIFT_EXIT_TAG not in log, "node refused to start after the stop"
        assert RECONCILE_TAG in log, "the restart should find EvoDB behind the coins"
        assert "Replaying blocks" in log
        return log

    def new_masternode(self, idx):
        mn = MasternodeInfo(evo=False, legacy=False)
        mn.generate_addresses(self.nodes[0])
        mn.set_params(nodePort=p2p_port(10 + idx))
        return mn

    def register_fund(self, mn):
        """A ProRegTx that also creates the collateral, funded from mn.fundsAddr."""
        n0 = self.nodes[0]
        txid = mn.register_fund(n0, submit=True)
        self.generate(n0, 1)
        mn.set_params(proTxHash=txid, collateral_txid=txid, collateral_vout=mn.get_collateral_vout(n0, txid))

    def check_blocks_both_ways(self):
        """A block from each node accepted by the other, node0's with a Sapling spend.

        Mempools are not synced: node0's wallet may put back a transaction of
        the branch it left, which node0 then mines.
        """
        n0, n1 = self.nodes
        self.generate(n1, 1, sync_fun=self.sync_blocks)  # a new tip for node0's wallet to check its witnesses on
        n0.syncwithvalidationinterfacequeue()
        txid = n0.z_sendmany(self.z0, [{"address": self.z0, "amount": 1.0}])
        self.generate(n0, 1, sync_fun=self.sync_blocks)
        assert txid in n1.getblock(n1.getbestblockhash())["tx"]
        self.generate(n1, 1, sync_fun=self.sync_blocks)
        assert_equal(self.state(0), self.state(1))

    # -- scenarios ------------------------------------------------------

    def run_test(self):
        n0 = self.nodes[0]
        self.t0 = n0.getnewaddress()
        self.log.info("Mining coins for one collateral")
        self.generatetoaddress(n0, 101, self.t0)
        while n0.getbalance() < MASTERNODE_COLLATERAL + 50:
            self.generatetoaddress(n0, 50, self.t0)

        self.z0 = n0.z_getnewaddress()
        n0.z_sendmany(self.t0, [{"address": self.z0, "amount": 10.0}])
        # Separate fee sources, so that the two branches of scenario 2 do not
        # spend the same coins.
        self.fee_a = n0.getnewaddress()
        self.fee_b = n0.getnewaddress()
        for _ in range(3):
            n0.sendtoaddress(self.fee_a, 1)
            n0.sendtoaddress(self.fee_b, 1)

        self.mn_a = self.new_masternode(0)
        # In parts: one transaction spending that many coinbase outputs is too large.
        for _ in range(4):
            n0.sendtoaddress(self.mn_a.fundsAddr, MASTERNODE_COLLATERAL // 4)
        n0.sendtoaddress(self.mn_a.fundsAddr, Decimal("0.001"))
        self.generate(n0, 1)
        self.register_fund(self.mn_a)

        self.scenario_behind_same_chain()
        self.scenario_other_branch()

    def scenario_behind_same_chain(self):
        self.log.info("Scenario 1: stop between the writes with EvoDB behind on the same chain")
        n0, n1 = self.nodes
        mn_a = self.mn_a

        # The clean stop flushes the coins and EvoDB here; the next full flush
        # above this height stops between the two writes.
        flushed = n0.getblockcount()
        self.restart_node(0, extra_args=DIP3_ARGS + [f"-crashbeforeevodbflush={flushed + 1}"])
        self.connect_nodes(0, 1)

        mn_a.update_service(n0, submit=True, addrs_core_p2p=[f"127.0.0.2:{mn_a.nodePort}"], fundsAddr=self.fee_a)
        self.generate(n0, 1)
        mn_a.update_registrar(n0, submit=True, votingAddr=n0.getnewaddress(), fundsAddr=self.fee_a)
        self.generate(n0, 1)
        n0.z_sendmany(self.t0, [{"address": self.z0, "amount": 2.0}])
        self.generate(n0, 1)

        # Masternode A's collateral funds masternode B: A leaves the list.
        self.mn_b = self.new_masternode(1)
        raw = n0.createrawtransaction(
            [{"txid": mn_a.collateral_txid, "vout": mn_a.collateral_vout}],
            [{self.mn_b.fundsAddr: MASTERNODE_COLLATERAL + Decimal("0.001")}])
        signed = n0.signrawtransactionwithwallet(n0.fundrawtransaction(raw)["hex"])
        assert signed["complete"]
        n0.sendrawtransaction(signed["hex"])
        self.generate(n0, 1)
        self.register_fund(self.mn_b)

        registered = {mn["proTxHash"] for mn in n1.protx("list", "registered", True)}
        assert mn_a.proTxHash not in registered and self.mn_b.proTxHash in registered
        assert_greater_than(n0.getblockcount(), flushed)
        expected = self.state(1)

        self.crash_in_flush(0)
        log = self.restart_after_crash(0)
        assert "Rolling forward" in log
        assert_equal(self.state(0), expected)

        self.connect_nodes(0, 1)
        self.check_blocks_both_ways()

    def scenario_other_branch(self):
        self.log.info("Scenario 2: a reorg after the last flush, then a stop between the writes")
        n0, n1 = self.nodes
        mn_b = self.mn_b
        self.disconnect_nodes(0, 1)

        # Branch A on node0, with a ProUpServTx, flushed by a clean stop.
        mn_b.update_service(n0, submit=True, addrs_core_p2p=[f"127.0.0.3:{mn_b.nodePort}"], fundsAddr=self.fee_a)
        self.generate(n0, 1, sync_fun=self.no_op)
        branch_a_tip = n0.getbestblockhash()
        self.restart_node(0, extra_args=DIP3_ARGS + [f"-crashbeforeevodbflush={n0.getblockcount() + 2}"])
        assert_equal(n0.getbestblockhash(), branch_a_tip)

        # Branch B on node1, longer, with a ProUpRegTx node0 signs but does not relay.
        raw = mn_b.update_registrar(n0, submit=False, votingAddr=n0.getnewaddress(), fundsAddr=self.fee_b)
        n1.sendrawtransaction(raw)
        self.generate(n1, 3, sync_fun=self.no_op)

        # node0 reorgs to B, then stops in the next flush.
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert branch_a_tip != n0.getbestblockhash()
        expected = self.state(1)

        self.crash_in_flush(0)
        log = self.restart_after_crash(0)
        assert "Rolling back" in log and "Rolling forward" in log
        assert_equal(self.state(0), expected)

        self.connect_nodes(0, 1)
        self.check_blocks_both_ways()


if __name__ == '__main__':
    EvoDBCrashRecoveryTest().main()
