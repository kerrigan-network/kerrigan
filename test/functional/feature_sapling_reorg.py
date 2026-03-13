#!/usr/bin/env python3
# Copyright (c) 2026 The Kerrigan developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Sapling shielded transaction behavior during chain reorgs.

Exercises:
  1. t->z shield, invalidateblock reverts it, reconsiderblock restores it
  2. z->z spend, invalidateblock undoes the spend, restoring original note
  3. Competing-chain reorg via disconnect/reconnect with Sapling txs on loser
  4. Competing-chain reorg with Sapling tx on winner chain (survives reorg)
  5. Deep invalidateblock rolling back past multiple Sapling transactions
  6. Persistence across restart after reorg recovery

Known issue exercised by this test:
  invalidateblock and reconsiderblock return before the wallet's scheduler
  thread finishes processing all BlockDisconnected / BlockConnected callbacks.
  We call syncwithvalidationinterfacequeue after these RPCs to drain the
  notification queue before asserting on wallet state.

Requires Sapling parameters in ~/.kerrigan-params/ (run contrib/fetch-params.sh).
Sapling is active from genesis in regtest (SaplingHeight = 0).
"""

import os
from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_framework import SkipTest
from test_framework.util import assert_equal, assert_greater_than

MATURITY = 100
EXTRA_BLOCKS = 10


class SaplingReorgTest(BitcoinTestFramework):
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

    def sync_validation_queue(self, node):
        """Drain the async validation interface queue so wallet state is up to date.

        invalidateblock / reconsiderblock enqueue BlockDisconnected / BlockConnected
        events on the scheduler thread but return before the wallet processes them.
        This helper ensures the queue is fully drained before we assert on balances.
        """
        node.syncwithvalidationinterfacequeue()

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        # --- Setup: mine blocks for coinbase maturity ---
        self.log.info("Mining %d blocks for coinbase maturity", MATURITY + EXTRA_BLOCKS)
        t_addr_0 = node0.getnewaddress()
        t_addr_1 = node1.getnewaddress()
        self.generatetoaddress(node0, MATURITY + EXTRA_BLOCKS, t_addr_0)
        self.sync_all()

        z_addr_0 = node0.z_getnewaddress()
        z_addr_1 = node1.z_getnewaddress()

        # ================================================================
        # Scenario 1: Invalidate block containing t->z, verify balance reverts
        # ================================================================
        self.log.info("Scenario 1: invalidateblock reverts a t->z shield")

        shield_amount = Decimal("5.0")
        txid_tz = node0.z_sendmany(
            t_addr_0,
            [{"address": z_addr_0, "amount": float(shield_amount)}],
        )
        self.log.info("  t->z txid: %s", txid_tz)

        # Mine 1 block to confirm
        self.generatetoaddress(node0, 1, t_addr_0)
        self.sync_all()
        confirm_height = node0.getblockcount()
        confirm_hash = node0.getbestblockhash()

        # Verify confirmed balance
        z_bal = Decimal(node0.z_getbalance(z_addr_0))
        assert_equal(z_bal, shield_amount)
        unspent = node0.z_listunspent(1, 9999999, [z_addr_0])
        assert_equal(len(unspent), 1)
        assert_equal(Decimal(str(unspent[0]["amount"])), shield_amount)

        # Invalidate the confirmation block
        self.log.info("  Invalidating block %d (%s)", confirm_height, confirm_hash)
        node0.invalidateblock(confirm_hash)
        self.sync_validation_queue(node0)

        # Confirmed balance should revert to 0
        z_bal_after = Decimal(node0.z_getbalance(z_addr_0))
        assert_equal(z_bal_after, Decimal("0"))
        unspent_after = node0.z_listunspent(1, 9999999, [z_addr_0])
        assert_equal(len(unspent_after), 0)
        assert_equal(node0.getblockcount(), confirm_height - 1)
        self.log.info("  Balance reverted to 0 after invalidateblock")

        # Reconsider -- block re-accepted, note re-confirmed
        self.log.info("  Reconsidering block %s", confirm_hash)
        node0.reconsiderblock(confirm_hash)
        self.sync_validation_queue(node0)

        z_bal_restored = Decimal(node0.z_getbalance(z_addr_0))
        assert_equal(z_bal_restored, shield_amount)
        unspent_restored = node0.z_listunspent(1, 9999999, [z_addr_0])
        assert_equal(len(unspent_restored), 1)
        assert_equal(node0.getblockcount(), confirm_height)
        self.log.info("  Balance restored to %s after reconsiderblock", shield_amount)

        # ================================================================
        # Scenario 2: Invalidate block containing z->z, verify spend undone
        # ================================================================
        self.log.info("Scenario 2: invalidateblock undoes a z->z spend")

        zz_amount = Decimal("2.0")
        txid_zz = node0.z_sendmany(
            z_addr_0,
            [{"address": z_addr_1, "amount": float(zz_amount)}],
        )
        self.log.info("  z->z txid: %s", txid_zz)

        self.generatetoaddress(node0, 1, t_addr_0)
        self.sync_all()
        zz_height = node0.getblockcount()
        zz_hash = node0.getbestblockhash()

        # Verify post-send balances
        bal_0_after_send = Decimal(node0.z_getbalance(z_addr_0))
        bal_1_after_send = Decimal(node1.z_getbalance(z_addr_1))
        self.log.info("  Node0 z-bal: %s, Node1 z-bal: %s", bal_0_after_send, bal_1_after_send)
        assert_equal(bal_1_after_send, zz_amount)
        # Node0 has change: shield_amount - zz_amount - fee
        assert bal_0_after_send < shield_amount
        assert bal_0_after_send > Decimal("0")

        # Invalidate the z->z block
        self.log.info("  Invalidating z->z block %d", zz_height)
        node0.invalidateblock(zz_hash)
        self.sync_validation_queue(node0)

        # Node0's original note should be unspent again (full pre-send balance)
        bal_0_unwound = Decimal(node0.z_getbalance(z_addr_0))
        assert_equal(bal_0_unwound, shield_amount)
        self.log.info("  Node0 balance restored to %s (spend undone)", shield_amount)

        # Also invalidate on node1 so it sees the reorg
        node1.invalidateblock(zz_hash)
        self.sync_validation_queue(node1)
        bal_1_unwound = Decimal(node1.z_getbalance(z_addr_1))
        assert_equal(bal_1_unwound, Decimal("0"))
        self.log.info("  Node1 received note disappeared")

        # Reconsider on both nodes
        node0.reconsiderblock(zz_hash)
        node1.reconsiderblock(zz_hash)
        self.sync_validation_queue(node0)
        self.sync_validation_queue(node1)
        self.sync_all()

        assert_equal(Decimal(node0.z_getbalance(z_addr_0)), bal_0_after_send)
        assert_equal(Decimal(node1.z_getbalance(z_addr_1)), zz_amount)
        self.log.info("  Balances restored after reconsiderblock")

        # ================================================================
        # Scenario 3: Competing chains -- loser has Sapling tx, winner does not
        # ================================================================
        self.log.info("Scenario 3: Competing chain fork -- Sapling tx on loser chain")

        # Record pre-fork state
        pre_fork_bal_0 = Decimal(node0.z_getbalance(z_addr_0))
        pre_fork_height = node0.getblockcount()
        self.log.info("  Pre-fork: node0 z-bal=%s, height=%d", pre_fork_bal_0, pre_fork_height)

        # Disconnect nodes to create partition
        self.disconnect_nodes(0, 1)

        # Node0: do a z->z send to a local second address, mine 2 blocks
        z_addr_0b = node0.z_getnewaddress()
        fork_amount = Decimal("1.0")
        txid_fork = node0.z_sendmany(
            z_addr_0,
            [{"address": z_addr_0b, "amount": float(fork_amount)}],
        )
        self.log.info("  Node0 fork tx: %s", txid_fork)
        self.generatetoaddress(node0, 2, t_addr_0, sync_fun=self.no_op)

        # Node1: mine 3 blocks (longer chain, no Sapling txs)
        self.generatetoaddress(node1, 3, t_addr_1, sync_fun=self.no_op)

        node0_height_before = node0.getblockcount()
        node1_height_before = node1.getblockcount()
        self.log.info("  Node0 height: %d, Node1 height: %d (node1 longer)",
                      node0_height_before, node1_height_before)
        assert node1_height_before > node0_height_before

        # Verify node0 sees the fork tx confirmed before reconnect
        bal_0_short = Decimal(node0.z_getbalance(z_addr_0))
        bal_0b_short = Decimal(node0.z_getbalance(z_addr_0b))
        self.log.info("  Node0 pre-reorg: z_addr_0=%s, z_addr_0b=%s", bal_0_short, bal_0b_short)
        assert bal_0b_short > Decimal("0"), "Fork tx should be confirmed on short chain"

        # Reconnect -- node0 reorgs to node1's longer chain
        self.connect_nodes(0, 1)
        self.sync_blocks()
        self.sync_validation_queue(node0)

        node0_height_after = node0.getblockcount()
        assert_equal(node0_height_after, node1_height_before)
        self.log.info("  Node0 reorged to height %d", node0_height_after)

        # Node0's fork Sapling tx should be reverted
        bal_0_after_reorg = Decimal(node0.z_getbalance(z_addr_0))
        bal_0b_after_reorg = Decimal(node0.z_getbalance(z_addr_0b))
        self.log.info("  Node0 z_addr_0 bal: %s, z_addr_0b bal: %s",
                      bal_0_after_reorg, bal_0b_after_reorg)
        # The original note balance should be restored (fork tx reverted)
        assert_equal(bal_0_after_reorg, pre_fork_bal_0)
        assert_equal(bal_0b_after_reorg, Decimal("0"))
        self.log.info("  Fork Sapling tx reverted -- original balance restored")

        # ================================================================
        # Scenario 4: Competing chains -- t->z on WINNER chain survives
        # ================================================================
        self.log.info("Scenario 4: Competing chain -- Sapling tx on winner survives")

        # After Scenario 3's reorg, node0 may have the reverted fork tx in its
        # mempool. This tx references Sapling anchors from the orphaned chain
        # and cannot propagate to node1. We need to clear it before syncing.
        mempool_0 = node0.getrawmempool()
        if mempool_0:
            self.log.info("  Clearing %d stale txs from node0 mempool via mining", len(mempool_0))
            self.generatetoaddress(node0, 1, t_addr_0, sync_fun=self.no_op)
            self.sync_blocks()

        # Get node1 some spendable transparent funds
        self.generatetoaddress(node1, MATURITY + 5, t_addr_1)
        self.sync_all()

        bal1_t = node1.getbalance()
        self.log.info("  Node1 transparent balance: %s", bal1_t)
        assert_greater_than(bal1_t, 0)

        # Record pre-fork state
        pre_s4_bal_1 = Decimal(node1.z_getbalance(z_addr_1))
        self.log.info("  Pre-fork node1 z-bal: %s", pre_s4_bal_1)

        # Disconnect nodes
        self.disconnect_nodes(0, 1)

        fork_point_height = node0.getblockcount()
        self.log.info("  Fork point: height=%d", fork_point_height)

        # Node0: mine 2 blocks (shorter chain), no Sapling activity
        self.generatetoaddress(node0, 2, t_addr_0, sync_fun=self.no_op)

        # Node1: do a fresh t->z shield (avoids anchor issues with reorged notes)
        # and mine 4 blocks (longer chain)
        z_addr_1b = node1.z_getnewaddress()
        s4_amount = Decimal("3.0")
        txid_s4_winner = node1.z_sendmany(
            t_addr_1,
            [{"address": z_addr_1b, "amount": float(s4_amount)}],
        )
        self.log.info("  Node1 t->z on winner chain: %s", txid_s4_winner)
        self.generatetoaddress(node1, 4, t_addr_1, sync_fun=self.no_op)

        node0_h = node0.getblockcount()
        node1_h = node1.getblockcount()
        self.log.info("  Node0 height: %d, Node1 height: %d", node0_h, node1_h)
        assert node1_h > node0_h, "Node1 should have longer chain"

        # Verify node1 sees the shield before reconnect
        bal_1b_pre_recon = Decimal(node1.z_getbalance(z_addr_1b))
        self.log.info("  Node1 z_addr_1b balance before reconnect: %s", bal_1b_pre_recon)
        assert_equal(bal_1b_pre_recon, s4_amount)

        # Reconnect -- node0 reorgs to node1's longer chain
        self.connect_nodes(0, 1)
        self.sync_blocks()
        self.sync_validation_queue(node0)
        self.sync_validation_queue(node1)

        # Node1's Sapling tx on the winner chain should survive
        bal_1b_after = Decimal(node1.z_getbalance(z_addr_1b))
        self.log.info("  Node1 z_addr_1b after reconnect: %s", bal_1b_after)
        assert_equal(bal_1b_after, s4_amount)

        # Node1's pre-existing z balance should be unchanged
        bal_1_after = Decimal(node1.z_getbalance(z_addr_1))
        assert_equal(bal_1_after, pre_s4_bal_1)
        self.log.info("  Sapling tx on winner chain survived the reorg")

        # ================================================================
        # Scenario 5: Deep invalidateblock past multiple Sapling txs
        # ================================================================
        self.log.info("Scenario 5: Deep invalidateblock past multiple Sapling transactions")

        # We have multiple Sapling txs in the chain now. Let's track the state
        # and do a deep rollback past all of them.
        current_height = node0.getblockcount()
        self.log.info("  Current height: %d", current_height)

        # Record node0's total shielded balance
        node0_total_z = Decimal(node0.z_getbalance())
        self.log.info("  Node0 total shielded balance: %s", node0_total_z)

        # Record node1's total shielded balance
        node1_total_z = Decimal(node1.z_getbalance())
        self.log.info("  Node1 total shielded balance: %s", node1_total_z)

        # Invalidate all the way back to just after the maturity blocks
        # (before any Sapling transactions happened)
        deep_target = MATURITY + EXTRA_BLOCKS  # before any Sapling txs
        deep_hash = node0.getblockhash(deep_target + 1)
        self.log.info("  Deep invalidating from block %d down to %d", current_height, deep_target)
        node0.invalidateblock(deep_hash)
        # CRITICAL: must drain the validation queue before checking wallet state.
        # invalidateblock returns before the scheduler thread processes all
        # BlockDisconnected callbacks -- without this sync the balance query
        # races with the wallet's RewindBlock processing.
        self.sync_validation_queue(node0)

        assert_equal(node0.getblockcount(), deep_target)

        # All Sapling balances on node0 should be 0 (all notes unconfirmed/reverted)
        node0_z_deep = Decimal(node0.z_getbalance())
        self.log.info("  Node0 total shielded balance after deep invalidate: %s", node0_z_deep)
        assert_equal(node0_z_deep, Decimal("0"))

        bal_0_deep = Decimal(node0.z_getbalance(z_addr_0))
        assert_equal(bal_0_deep, Decimal("0"))
        self.log.info("  All Sapling notes reverted after deep invalidateblock")

        # Reconsider to restore the chain
        self.log.info("  Reconsidering deep invalidation")
        node0.reconsiderblock(deep_hash)
        self.sync_validation_queue(node0)
        self.sync_blocks()

        # Balances should be fully restored
        node0_z_restored = Decimal(node0.z_getbalance())
        self.log.info("  Node0 total shielded balance restored: %s", node0_z_restored)
        assert_equal(node0_z_restored, node0_total_z)
        self.log.info("  Deep invalidation fully recovered")

        # ================================================================
        # Scenario 6: Persistence across restart after reorg
        # ================================================================
        self.log.info("Scenario 6: Persistence across restart after reorg recovery")

        # Current confirmed balance
        bal_before_restart = Decimal(node0.z_getbalance(z_addr_0))
        total_before_restart = Decimal(node0.z_getbalance())
        height_before_restart = node0.getblockcount()
        self.log.info("  Pre-restart: z_addr_0=%s, total=%s, height=%d",
                      bal_before_restart, total_before_restart, height_before_restart)

        # Stop and restart node0
        self.stop_node(0)
        self.start_node(0)
        self.connect_nodes(0, 1)
        self.sync_blocks()

        # Verify balance survived restart
        bal_after_restart = Decimal(node0.z_getbalance(z_addr_0))
        total_after_restart = Decimal(node0.z_getbalance())
        height_after_restart = node0.getblockcount()

        assert_equal(bal_after_restart, bal_before_restart)
        assert_equal(total_after_restart, total_before_restart)
        assert_equal(height_after_restart, height_before_restart)
        self.log.info("  Post-restart: balances and height match -- DB persistence works")

        # Also verify node1's balance persists across restart
        bal1_before = Decimal(node1.z_getbalance())
        self.stop_node(1)
        self.start_node(1)
        self.connect_nodes(0, 1)
        self.sync_blocks()
        bal1_after = Decimal(node1.z_getbalance())
        assert_equal(bal1_after, bal1_before)
        self.log.info("  Node1 balances also persist across restart")

        self.log.info("All Sapling reorg tests passed!")


if __name__ == "__main__":
    SaplingReorgTest().main()
