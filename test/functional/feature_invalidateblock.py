#!/usr/bin/env python3
# Copyright (c) 2026 The Kerrigan developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test deep chain rollbacks via invalidateblock/reconsiderblock.

Exercises:
  1. Mine 120 blocks (past coinbase maturity of 100)
  2. Transparent transactions between 2 nodes
  3. Sapling shielded transactions (t->z, z->t)
  4. Mine additional blocks to confirm everything
  5. Record all balances (transparent + shielded)
  6. invalidateblock to roll back 20 blocks (past the Sapling tx)
  7. Verify transparent + shielded balances revert
  8. reconsiderblock to restore the chain
  9. Verify all balances return to pre-invalidate values
 10. Roll back ALL THE WAY to genesis (invalidate block 1)
 11. Verify node survives and can recover

Requires Sapling parameters in ~/.kerrigan-params/ (run contrib/fetch-params.sh).
Sapling is active from genesis in regtest (SaplingHeight = 0).
"""

import os
from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_framework import SkipTest
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)

# Coinbase maturity is 100; we mine 120 so 20 coinbase outputs are spendable
MATURITY = 100
SETUP_BLOCKS = 120


class InvalidateBlockDeepTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        # Check that Sapling params are available
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

        # =============================================================
        # Phase 1: Setup -- mine 120 blocks for coinbase maturity
        # =============================================================
        self.log.info("Phase 1: Mining %d blocks for coinbase maturity", SETUP_BLOCKS)
        t_addr_0 = node0.getnewaddress()
        t_addr_1 = node1.getnewaddress()
        self.generatetoaddress(node0, SETUP_BLOCKS, t_addr_0)

        bal_0_initial = node0.getbalance()
        self.log.info("  Node 0 initial transparent balance: %s KRGN", bal_0_initial)
        assert_greater_than(bal_0_initial, 0)

        # =============================================================
        # Phase 2: Transparent transactions between nodes
        # =============================================================
        self.log.info("Phase 2: Transparent transactions between nodes")

        # Send 10 KRGN from node0 to node1 (two separate txns)
        txid_t1 = node0.sendtoaddress(t_addr_1, 4.0)
        txid_t2 = node0.sendtoaddress(t_addr_1, 6.0)
        self.log.info("  Transparent txid 1: %s", txid_t1)
        self.log.info("  Transparent txid 2: %s", txid_t2)

        # Mine 1 block to confirm the transparent txns
        self.generatetoaddress(node0, 1, t_addr_0)

        bal_0_after_t = node0.getbalance()
        bal_1_after_t = node1.getbalance()
        self.log.info("  After transparent sends: node0=%s, node1=%s", bal_0_after_t, bal_1_after_t)
        assert_equal(bal_1_after_t, Decimal("10.0"))

        # =============================================================
        # Phase 3: Sapling shielded transactions (t->z, then z->t)
        # =============================================================
        self.log.info("Phase 3: Sapling shielded transactions")

        z_addr_0 = node0.z_getnewaddress()
        self.log.info("  Node 0 shielded address: %s", z_addr_0)

        # t->z: shield 5 KRGN
        shield_amount = Decimal("5.0")
        txid_tz = node0.z_sendmany(
            t_addr_0,
            [{"address": z_addr_0, "amount": float(shield_amount)}],
        )
        self.log.info("  t->z txid: %s", txid_tz)

        # Mine 1 block to confirm the shielding tx
        self.generatetoaddress(node0, 1, t_addr_0)

        z_bal_0 = Decimal(node0.z_getbalance(z_addr_0))
        self.log.info("  Node 0 shielded balance after t->z: %s", z_bal_0)
        assert_equal(z_bal_0, shield_amount)

        # z->t: unshield 2 KRGN back to transparent on node0
        unshield_amount = Decimal("2.0")
        txid_zt = node0.z_sendmany(
            z_addr_0,
            [{"address": t_addr_0, "amount": float(unshield_amount)}],
        )
        self.log.info("  z->t txid: %s", txid_zt)

        # Mine 1 block to confirm the unshielding tx
        self.generatetoaddress(node0, 1, t_addr_0)

        z_bal_0_after_zt = Decimal(node0.z_getbalance(z_addr_0))
        self.log.info("  Node 0 shielded balance after z->t: %s", z_bal_0_after_zt)
        # Shielded balance should be: 5 - 2 - fee (change note)
        assert z_bal_0_after_zt < shield_amount, \
            "Shielded balance should decrease after z->t"
        assert z_bal_0_after_zt > Decimal("0"), \
            "Should still have shielded change"

        # =============================================================
        # Phase 4: Mine a few more blocks to put distance
        # =============================================================
        self.log.info("Phase 4: Mining 10 more blocks for confirmation depth")
        self.generatetoaddress(node0, 10, t_addr_0)

        # Current chain height should be SETUP_BLOCKS + 1 (t-txns) + 1 (t->z) + 1 (z->t) + 10
        expected_height = SETUP_BLOCKS + 13
        actual_height = node0.getblockcount()
        assert_equal(actual_height, expected_height)
        self.log.info("  Chain height: %d", actual_height)

        # =============================================================
        # Phase 5: Record all balances before rollback
        # =============================================================
        self.log.info("Phase 5: Recording pre-rollback balances")

        pre_t_bal_0 = node0.getbalance()
        pre_t_bal_1 = node1.getbalance()
        pre_z_bal_0 = Decimal(node0.z_getbalance(z_addr_0))
        pre_z_total_0 = Decimal(node0.z_getbalance())
        pre_height = node0.getblockcount()
        pre_best_hash = node0.getbestblockhash()

        self.log.info("  Pre-rollback state:")
        self.log.info("    Height: %d", pre_height)
        self.log.info("    Node 0 transparent: %s", pre_t_bal_0)
        self.log.info("    Node 1 transparent: %s", pre_t_bal_1)
        self.log.info("    Node 0 shielded (z_addr): %s", pre_z_bal_0)
        self.log.info("    Node 0 shielded (total): %s", pre_z_total_0)

        # =============================================================
        # Phase 6: invalidateblock -- roll back 20 blocks
        # =============================================================
        self.log.info("Phase 6: Rolling back 20 blocks via invalidateblock")

        rollback_depth = 20
        rollback_target_height = pre_height - rollback_depth
        rollback_hash = node0.getblockhash(rollback_target_height + 1)
        self.log.info("  Invalidating block at height %d (hash %s)",
                      rollback_target_height + 1, rollback_hash)
        self.log.info("  This rolls back past: transparent sends, t->z, z->t, and confirmation blocks")

        node0.invalidateblock(rollback_hash)

        post_inv_height = node0.getblockcount()
        assert_equal(post_inv_height, rollback_target_height)
        self.log.info("  Height after invalidate: %d (rolled back %d blocks)",
                      post_inv_height, pre_height - post_inv_height)

        # =============================================================
        # Phase 7: Verify balances reverted
        # =============================================================
        self.log.info("Phase 7: Verifying balances reverted after invalidateblock")

        post_inv_t_bal_0 = node0.getbalance()
        post_inv_z_bal_0 = Decimal(node0.z_getbalance(z_addr_0))
        post_inv_z_total_0 = Decimal(node0.z_getbalance())

        self.log.info("  Post-invalidate state:")
        self.log.info("    Node 0 transparent: %s (was %s)", post_inv_t_bal_0, pre_t_bal_0)
        self.log.info("    Node 0 shielded (z_addr): %s (was %s)", post_inv_z_bal_0, pre_z_bal_0)
        self.log.info("    Node 0 shielded (total): %s (was %s)", post_inv_z_total_0, pre_z_total_0)

        # Transparent balance should change (lost coinbase rewards from rolled-back blocks,
        # plus the transparent sends and unshield are no longer confirmed)
        assert post_inv_t_bal_0 != pre_t_bal_0, \
            "Transparent balance should change after 20-block rollback"

        # Shielded balance should revert to 0 -- the t->z and z->t were in rolled-back blocks
        # (rollback_depth=20 rolls past the Sapling txns which were at height ~122-123)
        assert_equal(post_inv_z_bal_0, Decimal("0"))
        assert_equal(post_inv_z_total_0, Decimal("0"))
        self.log.info("  Shielded balances correctly reverted to 0")

        # =============================================================
        # Phase 8: reconsiderblock -- restore the chain
        # =============================================================
        self.log.info("Phase 8: Restoring chain via reconsiderblock")

        node0.reconsiderblock(rollback_hash)

        post_recon_height = node0.getblockcount()
        post_recon_hash = node0.getbestblockhash()
        assert_equal(post_recon_height, pre_height)
        assert_equal(post_recon_hash, pre_best_hash)
        self.log.info("  Height restored to %d", post_recon_height)

        # =============================================================
        # Phase 9: Verify all balances return to pre-invalidate values
        # =============================================================
        self.log.info("Phase 9: Verifying balances restored after reconsiderblock")

        post_recon_t_bal_0 = node0.getbalance()
        post_recon_t_bal_1 = node1.getbalance()
        post_recon_z_bal_0 = Decimal(node0.z_getbalance(z_addr_0))
        post_recon_z_total_0 = Decimal(node0.z_getbalance())

        self.log.info("  Post-reconsider state:")
        self.log.info("    Node 0 transparent: %s (expected %s)", post_recon_t_bal_0, pre_t_bal_0)
        self.log.info("    Node 1 transparent: %s (expected %s)", post_recon_t_bal_1, pre_t_bal_1)
        self.log.info("    Node 0 shielded (z_addr): %s (expected %s)", post_recon_z_bal_0, pre_z_bal_0)
        self.log.info("    Node 0 shielded (total): %s (expected %s)", post_recon_z_total_0, pre_z_total_0)

        assert_equal(post_recon_t_bal_0, pre_t_bal_0)
        assert_equal(post_recon_t_bal_1, pre_t_bal_1)
        assert_equal(post_recon_z_bal_0, pre_z_bal_0)
        assert_equal(post_recon_z_total_0, pre_z_total_0)
        self.log.info("  All balances match pre-invalidate values")

        # =============================================================
        # Phase 10: Roll back ALL THE WAY to genesis
        # =============================================================
        self.log.info("Phase 10: Rolling back to genesis (invalidate block 1)")

        # Disconnect nodes first so node1 doesn't try to resync node0
        self.disconnect_nodes(0, 1)

        block1_hash = node0.getblockhash(1)
        current_height = node0.getblockcount()
        self.log.info("  Current height: %d, invalidating block 1 (%s)", current_height, block1_hash)

        node0.invalidateblock(block1_hash)

        genesis_height = node0.getblockcount()
        assert_equal(genesis_height, 0)
        self.log.info("  Height after genesis rollback: %d", genesis_height)

        # Verify the node is alive and responsive
        genesis_hash = node0.getbestblockhash()
        chain_info = node0.getblockchaininfo()
        assert_equal(chain_info["blocks"], 0)
        self.log.info("  Node 0 is alive at genesis, best hash: %s", genesis_hash)

        # Balances should be zero at genesis
        genesis_t_bal = node0.getbalance()
        genesis_z_bal = Decimal(node0.z_getbalance())
        assert_equal(genesis_t_bal, Decimal("0"))
        assert_equal(genesis_z_bal, Decimal("0"))
        self.log.info("  All balances are 0 at genesis")

        # =============================================================
        # Phase 11: Recover from genesis rollback
        # =============================================================
        self.log.info("Phase 11: Recovering from genesis rollback")

        node0.reconsiderblock(block1_hash)

        recovered_height = node0.getblockcount()
        recovered_hash = node0.getbestblockhash()
        assert_equal(recovered_height, pre_height)
        assert_equal(recovered_hash, pre_best_hash)
        self.log.info("  Recovered to height %d", recovered_height)

        # Verify balances are fully restored after total rollback + recovery
        final_t_bal_0 = node0.getbalance()
        final_z_bal_0 = Decimal(node0.z_getbalance(z_addr_0))
        final_z_total_0 = Decimal(node0.z_getbalance())

        assert_equal(final_t_bal_0, pre_t_bal_0)
        assert_equal(final_z_bal_0, pre_z_bal_0)
        assert_equal(final_z_total_0, pre_z_total_0)
        self.log.info("  All balances fully restored after genesis rollback + recovery:")
        self.log.info("    Transparent: %s", final_t_bal_0)
        self.log.info("    Shielded (z_addr): %s", final_z_bal_0)
        self.log.info("    Shielded (total): %s", final_z_total_0)

        # Reconnect and verify sync works
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(node0.getblockcount(), node1.getblockcount())
        self.log.info("  Nodes synced successfully after recovery")

        self.log.info("All invalidateblock deep rollback tests passed!")


if __name__ == "__main__":
    InvalidateBlockDeepTest().main()
