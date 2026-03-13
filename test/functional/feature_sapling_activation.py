#!/usr/bin/env python3
# Copyright (c) 2026 The Kerrigan developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Sapling activation boundary via -testactivationheight=sapling@N.

Exercises:
  1. Pre-activation: z_getnewaddress works (key gen doesn't require activation)
  2. Pre-activation: z_sendmany fails with "Sapling not active"
  3. Activation: mine to activation height
  4. Post-activation: full t→z / z→z / z→t lifecycle works

Requires Sapling parameters in ~/.kerrigan-params/ (run contrib/fetch-params.sh).
"""

import os
from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_framework import SkipTest
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error

SAPLING_ACTIVATION_HEIGHT = 200
MATURITY = 100


class SaplingActivationTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            [f"-testactivationheight=sapling@{SAPLING_ACTIVATION_HEIGHT}"],
            [f"-testactivationheight=sapling@{SAPLING_ACTIVATION_HEIGHT}"],
        ]

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

        t_addr_0 = node0.getnewaddress()

        # ================================================================
        # Test 1: Pre-activation — z_getnewaddress works
        # ================================================================
        self.log.info("Test 1: Pre-activation z_getnewaddress succeeds")
        z_addr_0 = node0.z_getnewaddress()
        assert z_addr_0.startswith("kregsapling"), \
            "Regtest Sapling address should start with kregsapling, got: " + z_addr_0
        z_addr_1 = node1.z_getnewaddress()
        assert z_addr_1.startswith("kregsapling"), \
            "Regtest Sapling address should start with kregsapling, got: " + z_addr_1
        self.log.info("  z_getnewaddress works before activation")

        # ================================================================
        # Test 2: Pre-activation — z_sendmany fails
        # ================================================================
        self.log.info("Test 2: Pre-activation z_sendmany fails")

        # Mine enough blocks for maturity but stay below activation height
        blocks_to_mine = MATURITY + 10
        assert blocks_to_mine < SAPLING_ACTIVATION_HEIGHT - 1, \
            "Test setup error: maturity blocks would reach activation height"
        self.generatetoaddress(node0, blocks_to_mine, t_addr_0)
        self.sync_all()

        current_height = node0.getblockcount()
        self.log.info("  Current height: %d (activation at %d)", current_height, SAPLING_ACTIVATION_HEIGHT)
        assert current_height < SAPLING_ACTIVATION_HEIGHT

        # Attempt t→z — should fail because Sapling is not active
        assert_raises_rpc_error(
            -4, "Sapling not active",
            node0.z_sendmany, t_addr_0,
            [{"address": z_addr_0, "amount": 5.0}],
        )
        self.log.info("  z_sendmany correctly rejected before activation")

        # ================================================================
        # Test 3: Mine to activation height
        # ================================================================
        self.log.info("Test 3: Mine to activation height")
        remaining = SAPLING_ACTIVATION_HEIGHT - current_height
        self.log.info("  Mining %d blocks to reach activation height %d", remaining, SAPLING_ACTIVATION_HEIGHT)
        self.generatetoaddress(node0, remaining, t_addr_0)
        self.sync_all()

        current_height = node0.getblockcount()
        assert current_height >= SAPLING_ACTIVATION_HEIGHT, \
            f"Expected height >= {SAPLING_ACTIVATION_HEIGHT}, got {current_height}"
        self.log.info("  Reached height %d — Sapling now active", current_height)

        # ================================================================
        # Test 4: Post-activation — full lifecycle
        # ================================================================
        self.log.info("Test 4: Post-activation full lifecycle")

        # 4a: t→z shield
        self.log.info("  4a: t→z shield")
        balance_0 = node0.getbalance()
        self.log.info("    Node 0 transparent balance: %s KRGN", balance_0)
        assert_greater_than(balance_0, 0)

        shield_amount = Decimal("5.0")
        txid_tz = node0.z_sendmany(
            t_addr_0,
            [{"address": z_addr_0, "amount": float(shield_amount)}],
        )
        self.log.info("    t→z txid: %s", txid_tz)

        self.generatetoaddress(node0, 1, t_addr_0)
        self.sync_all()

        z_bal_0 = Decimal(node0.z_getbalance(z_addr_0))
        assert_equal(z_bal_0, shield_amount)
        self.log.info("    Shielded balance: %s KRGN", z_bal_0)

        # 4b: z→z cross-node transfer
        self.log.info("  4b: z→z cross-node transfer")
        zz_amount = Decimal("2.0")
        txid_zz = node0.z_sendmany(
            z_addr_0,
            [{"address": z_addr_1, "amount": float(zz_amount)}],
        )
        self.log.info("    z→z txid: %s", txid_zz)

        self.generatetoaddress(node0, 1, t_addr_0)
        self.sync_all()

        z_bal_1 = Decimal(node1.z_getbalance(z_addr_1))
        assert_equal(z_bal_1, zz_amount)
        self.log.info("    Node 1 shielded balance: %s KRGN", z_bal_1)

        # 4c: z→t unshield
        self.log.info("  4c: z→t unshield")
        t_addr_1 = node1.getnewaddress()
        zt_amount = Decimal("1.0")
        t_bal_before = node1.getbalance()

        txid_zt = node1.z_sendmany(
            z_addr_1,
            [{"address": t_addr_1, "amount": float(zt_amount)}],
        )
        self.log.info("    z→t txid: %s", txid_zt)

        self.sync_mempools()
        self.generatetoaddress(node0, 1, t_addr_0)
        self.sync_all()

        t_bal_after = node1.getbalance()
        assert_greater_than(t_bal_after, t_bal_before)
        self.log.info("    Node 1 transparent balance: %s → %s KRGN", t_bal_before, t_bal_after)

        self.log.info("All Sapling activation tests passed!")


if __name__ == "__main__":
    SaplingActivationTest().main()
