#!/usr/bin/env python3
# Copyright (c) 2026 The Kerrigan developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end test for Sapling shielded transactions.

Exercises the full lifecycle of shielded funds:
  1. z_getnewaddress — generate Sapling payment addresses
  2. z_sendmany t→z — shield transparent coins
  3. z_sendmany z→z — private transfer between two nodes
  4. z_sendmany z→t — unshield back to transparent
  5. z_getbalance / z_listunspent / z_listaddresses — query RPCs
  6. z_exportkey / z_importkey — key round-trip

Requires Sapling parameters in ~/.kerrigan-params/ (run contrib/fetch-params.sh).
Sapling is active from genesis in regtest (SaplingHeight = 0).
"""

import os
from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_framework import SkipTest
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error

# Coinbase maturity + headroom
MATURITY = 100
EXTRA_BLOCKS = 10


class SaplingTest(BitcoinTestFramework):
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

        # --- Setup: mine blocks for maturity ---
        self.log.info("Mining %d blocks for coinbase maturity", MATURITY + EXTRA_BLOCKS)
        t_addr_0 = node0.getnewaddress()
        self.generatetoaddress(node0, MATURITY + EXTRA_BLOCKS, t_addr_0)
        self.sync_all()

        # Sanity: node 0 has spendable transparent funds
        balance_0 = node0.getbalance()
        self.log.info("Node 0 transparent balance: %s KRGN", balance_0)
        assert_greater_than(balance_0, 0)

        # --- Test 1: z_getnewaddress ---
        self.log.info("Test 1: z_getnewaddress")
        z_addr_0 = node0.z_getnewaddress()
        self.log.info("  Node 0 shielded address: %s", z_addr_0)
        assert z_addr_0.startswith("kregsapling"), \
            "Regtest Sapling address should start with kregsapling, got: " + z_addr_0

        z_addr_1 = node1.z_getnewaddress()
        self.log.info("  Node 1 shielded address: %s", z_addr_1)
        assert z_addr_1.startswith("kregsapling"), \
            "Regtest Sapling address should start with kregsapling, got: " + z_addr_1

        # z_listaddresses should show the new addresses
        addrs_0 = node0.z_listaddresses()
        assert len(addrs_0) >= 1, "z_listaddresses should return at least 1 address"
        assert any(a["address"] == z_addr_0 for a in addrs_0), \
            "z_listaddresses should contain the generated address"

        # --- Test 2: z_sendmany t→z (shield coins) ---
        self.log.info("Test 2: z_sendmany t→z (transparent to shielded)")
        shield_amount = Decimal("5.0")
        txid_tz = node0.z_sendmany(
            t_addr_0,
            [{"address": z_addr_0, "amount": float(shield_amount)}],
        )
        self.log.info("  t→z txid: %s", txid_tz)
        assert len(txid_tz) == 64, "txid should be 64 hex chars"

        # Mine a block to confirm the shielding tx
        self.generatetoaddress(node0, 1, t_addr_0)
        self.sync_all()

        # Verify shielded balance
        z_bal_0 = Decimal(node0.z_getbalance(z_addr_0))
        self.log.info("  Node 0 shielded balance: %s KRGN", z_bal_0)
        assert_equal(z_bal_0, shield_amount)

        # z_listunspent should show the note
        unspent_0 = node0.z_listunspent()
        assert len(unspent_0) >= 1, "z_listunspent should show at least 1 note"
        our_note = [n for n in unspent_0 if n["address"] == z_addr_0]
        assert len(our_note) == 1, "Should have exactly 1 note for our address"
        assert_equal(Decimal(str(our_note[0]["amount"])), shield_amount)
        assert our_note[0]["spendable"] is True

        # Total shielded balance (no address filter)
        z_total_0 = Decimal(node0.z_getbalance())
        assert_equal(z_total_0, shield_amount)

        # --- Test 3: z_sendmany z→z (shielded to shielded, cross-node) ---
        self.log.info("Test 3: z_sendmany z→z (shielded to shielded, node0 → node1)")
        zz_amount = Decimal("2.0")
        txid_zz = node0.z_sendmany(
            z_addr_0,
            [{"address": z_addr_1, "amount": float(zz_amount)}],
        )
        self.log.info("  z→z txid: %s", txid_zz)

        # Mine and sync
        self.generatetoaddress(node0, 1, t_addr_0)
        self.sync_all()

        # Node 1 should detect the incoming note via trial decryption
        z_bal_1 = Decimal(node1.z_getbalance(z_addr_1))
        self.log.info("  Node 1 shielded balance: %s KRGN", z_bal_1)
        assert_equal(z_bal_1, zz_amount)

        # Node 0's balance should be reduced by amount + fee
        z_bal_0_after = Decimal(node0.z_getbalance(z_addr_0))
        self.log.info("  Node 0 shielded balance after z→z: %s KRGN", z_bal_0_after)
        # Balance should be: original - sent - fee (fee is small, just check it decreased)
        assert z_bal_0_after < shield_amount, \
            "Node 0 shielded balance should decrease after z→z send"
        assert z_bal_0_after > 0, \
            "Node 0 should still have change from z→z"

        # --- Test 4: z_sendmany z→t (unshield coins) ---
        self.log.info("Test 4: z_sendmany z→t (shielded to transparent)")
        t_addr_1 = node1.getnewaddress()
        zt_amount = Decimal("1.0")
        t_bal_before = node1.getbalance()

        txid_zt = node1.z_sendmany(
            z_addr_1,
            [{"address": t_addr_1, "amount": float(zt_amount)}],
        )
        self.log.info("  z→t txid: %s", txid_zt)

        # Wait for tx to propagate, then mine
        self.sync_mempools()
        self.generatetoaddress(node0, 1, t_addr_0)
        self.sync_all()

        # Node 1 transparent balance should increase
        t_bal_after = node1.getbalance()
        self.log.info("  Node 1 transparent balance: %s → %s KRGN", t_bal_before, t_bal_after)
        assert_greater_than(t_bal_after, t_bal_before)

        # Node 1 shielded balance should decrease
        z_bal_1_after = Decimal(node1.z_getbalance(z_addr_1))
        self.log.info("  Node 1 shielded balance after z→t: %s KRGN", z_bal_1_after)
        assert z_bal_1_after < zz_amount, \
            "Node 1 shielded balance should decrease after z→t"

        # --- Test 5: z_exportkey / z_importkey round-trip ---
        self.log.info("Test 5: z_exportkey / z_importkey")
        exported_key = node0.z_exportkey(z_addr_0)
        self.log.info("  Exported key length: %d hex chars (%d bytes)", len(exported_key), len(exported_key) // 2)
        assert_equal(len(exported_key), 338)  # 169 bytes = 338 hex chars

        # Import on node 1 (no rescan to avoid delay)
        node1.z_importkey(exported_key, "no")

        # Node 1 should now list node 0's address
        addrs_1 = node1.z_listaddresses()
        imported = [a for a in addrs_1 if a["address"] == z_addr_0]
        assert len(imported) == 1, "Imported address should appear in z_listaddresses"
        assert imported[0]["spendable"] is True, "Imported key should be spendable"

        # --- Test 6: memo field ---
        self.log.info("Test 6: z_sendmany with memo field")
        memo_hex = "48656c6c6f204b65727269676e21"  # "Hello Kerrigan!" in hex
        z_addr_0b = node0.z_getnewaddress()  # fresh address for memo test
        memo_amount = Decimal("0.5")

        # Use node 0's remaining shielded balance
        txid_memo = node0.z_sendmany(
            z_addr_0,
            [{"address": z_addr_0b, "amount": float(memo_amount), "memo": memo_hex}],
        )
        self.log.info("  memo txid: %s", txid_memo)

        self.generatetoaddress(node0, 1, t_addr_0)
        self.sync_all()

        # Verify memo in z_listunspent
        unspent = node0.z_listunspent(1, 9999999, [z_addr_0b])
        assert len(unspent) >= 1, "Should have note at memo address"
        note_memo = unspent[0]["memo"]
        # Memo is padded to 512 bytes with zeros
        assert note_memo.startswith(memo_hex), \
            "Memo should start with our data, got: " + note_memo[:40]

        # --- Test 7: error cases ---
        self.log.info("Test 7: Error cases")

        # Invalid shielded address
        assert_raises_rpc_error(
            -5, "Invalid Sapling address",
            node0.z_getbalance, "ks1invalid"
        )

        # z_sendmany with zero amount
        assert_raises_rpc_error(
            -8, None,
            node0.z_sendmany, t_addr_0, [{"address": z_addr_0, "amount": 0}]
        )

        # z_exportkey for unknown address
        assert_raises_rpc_error(
            -4, "Address not found",
            node0.z_exportkey, z_addr_1  # node 0 doesn't know node 1's original addr
        )

        self.log.info("All Sapling tests passed!")


if __name__ == "__main__":
    SaplingTest().main()
