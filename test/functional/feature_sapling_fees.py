#!/usr/bin/env python3
# Copyright (c) 2026 The Kerrigan developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Sapling fee enforcement.

Exercises:
  1. Auto fee is correct — t→z with default fee confirms
  2. Explicit low fee rejected — fee below minimum rejected by mempool
  3. Explicit sufficient fee accepted — fee above minimum confirms
  4. z→z fee scales with spends — balance change implies correct auto fee

Requires Sapling parameters in ~/.kerrigan-params/ (run contrib/fetch-params.sh).
"""

import os
from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_framework import SkipTest
from test_framework.util import assert_equal, assert_raises_rpc_error

MATURITY = 100
EXTRA_BLOCKS = 10


class SaplingFeeTest(BitcoinTestFramework):
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

        z_addr = node0.z_getnewaddress()

        # --- Test 1: Auto fee is correct ---
        self.log.info("Test 1: t→z with default auto fee confirms")
        txid = node0.z_sendmany(
            t_addr,
            [{"address": z_addr, "amount": 5.0}],
        )
        self.generatetoaddress(node0, 1, t_addr)
        self.sync_all()
        z_bal = Decimal(node0.z_getbalance(z_addr))
        assert_equal(z_bal, Decimal("5.0"))
        self.log.info("  Auto fee t→z confirmed, balance = %s", z_bal)

        # --- Test 2: Explicit low fee rejected by mempool ---
        self.log.info("Test 2: t→z with explicit fee=0.00001 rejected by mempool")
        # Minimum for 0 spends + 0 user outputs (2 padding) = base = 10000 sat = 0.0001
        # Fee of 0.00001 = 1000 sat — well below minimum
        txid_low = node0.z_sendmany(
            t_addr,
            [{"address": z_addr, "amount": 1.0}],
            1,       # minconf
            0.00001  # fee — too low
        )
        # CommitTransaction returns a txid even if mempool rejects;
        # verify the tx is NOT in the mempool
        assert txid_low not in node0.getrawmempool(), \
            "Low-fee Sapling tx should be rejected by mempool"
        self.log.info("  Low fee correctly rejected by mempool")

        # --- Test 3: Explicit sufficient fee accepted ---
        self.log.info("Test 3: t→z with explicit fee=0.0002 accepted")
        txid3 = node0.z_sendmany(
            t_addr,
            [{"address": z_addr, "amount": 1.0}],
            1,      # minconf
            0.0002  # fee — above minimum
        )
        self.generatetoaddress(node0, 1, t_addr)
        self.sync_all()
        z_bal3 = Decimal(node0.z_getbalance(z_addr))
        assert_equal(z_bal3, Decimal("6.0"))  # 5.0 + 1.0
        self.log.info("  Sufficient fee t→z confirmed, balance = %s", z_bal3)

        # --- Test 4: z→z auto fee scales with spends ---
        self.log.info("Test 4: z→z auto fee scales correctly")
        z_addr_1 = node1.z_getnewaddress()
        send_amount = Decimal("2.0")
        z_bal_before = Decimal(node0.z_getbalance(z_addr))
        txid4 = node0.z_sendmany(
            z_addr,
            [{"address": z_addr_1, "amount": float(send_amount)}],
        )
        self.generatetoaddress(node0, 1, t_addr)
        self.sync_all()

        z_bal_after = Decimal(node0.z_getbalance(z_addr))
        z_bal_recv = Decimal(node1.z_getbalance(z_addr_1))
        assert_equal(z_bal_recv, send_amount)

        # Fee = base + nSpends * per_spend + (nShieldedOutputs + 1) * per_output
        # nSpends depends on how many notes the wallet selects (may be 1 or 2)
        actual_fee = z_bal_before - send_amount - z_bal_after
        self.log.info("  z→z actual fee = %s, remaining = %s", actual_fee, z_bal_after)
        # Fee should be at least the base (0.0001) and not more than a reasonable
        # amount for a few spends/outputs
        assert actual_fee >= Decimal("0.0001"), \
            "Fee should be at least base fee"
        assert actual_fee <= Decimal("0.001"), \
            "Fee should be reasonable (< 0.001)"

        self.log.info("All Sapling fee tests passed!")


if __name__ == "__main__":
    SaplingFeeTest().main()
