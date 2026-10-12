#!/usr/bin/env python3
# Copyright (c) 2026 The Kerrigan developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test reading shielded payments back from the wallet.

  1. kerrigan-cli converts z_* array/number arguments (vRPCConvertParams)
  2. a shielded-only receive is added to the wallet's transaction list
     (gettransaction / listtransactions / listsinceblock), in the mempool
     and once confirmed
  3. z_viewtransaction decrypts outputs (memo, memoStr), lists spends of
     wallet notes, and still reads a note after it has been spent
  4. z_viewtransaction and the transaction list work in a wallet that only
     holds the viewing key (after an import rescan)

Requires Sapling parameters in ~/.zcash-params/ (run contrib/fetch-params.sh).
"""

import os
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_framework import SkipTest
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

MATURITY = 100
EXTRA_BLOCKS = 10

MEMO_TEXT = "12"
MEMO_HEX = MEMO_TEXT.encode().hex()


class SaplingViewTransactionTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        # The node's default -saplingparamdir, where contrib/fetch-params.sh puts them
        params_dir = os.path.expanduser("~/.zcash-params")
        spend = os.path.join(params_dir, "sapling-spend.params")
        output = os.path.join(params_dir, "sapling-output.params")
        if not (os.path.exists(spend) and os.path.exists(output)):
            raise SkipTest("Sapling parameters not found. Run contrib/fetch-params.sh first.")

    def find_entries(self, entries, txid):
        return [e for e in entries if e["txid"] == txid]

    def run_test(self):
        node0, node1 = self.nodes

        t_addr_0 = node0.getnewaddress()
        self.generatetoaddress(node0, MATURITY + EXTRA_BLOCKS, t_addr_0)
        self.sync_all()

        z_addr_0 = node0.z_getnewaddress()
        z_addr_1 = node1.z_getnewaddress()

        self.log.info("Shield transparent coins on node0")
        txid_tz = node0.z_sendmany(t_addr_0, [{"address": z_addr_0, "amount": 5}])
        self.generatetoaddress(node0, 1, t_addr_0)
        self.sync_all()
        assert_equal(Decimal(node0.z_getbalance(z_addr_0)), Decimal("5"))

        # t->z from the wallet's own coins: every input is known, so the fee is too
        tz_view = node0.z_viewtransaction(txid_tz)
        assert_equal(tz_view["spends"], [])
        assert_equal(len(tz_view["outputs"]), 1)
        assert_equal(tz_view["outputs"][0]["address"], z_addr_0)
        assert_greater_than(Decimal(tz_view["fee"]), 0)

        if self.is_cli_compiled():
            self.log.info("kerrigan-cli converts z_* JSON arguments")
            # Before the fix these failed with "JSON value of type string is
            # not of expected type number/array".
            notes = node0.cli.z_listunspent(1, 9999999, [z_addr_0])
            assert_equal(len(notes), 1)
            assert_equal(Decimal(node0.cli.z_getbalance(z_addr_0, 1)), Decimal("5"))

        self.log.info("Send a shielded payment with a memo to node1")
        amount = Decimal("1.5")
        recipients = [{"address": z_addr_1, "amount": amount, "memo": MEMO_HEX}]
        if self.is_cli_compiled():
            txid_zz = node0.cli.z_sendmany(z_addr_0, recipients, 1)
        else:
            txid_zz = node0.z_sendmany(z_addr_0, recipients, 1)
        self.sync_mempools()

        self.log.info("Unconfirmed shielded receive is in node1's transaction list")
        tx = node1.gettransaction(txid_zz)
        assert_equal(tx["confirmations"], 0)
        details = [d for d in tx["details"] if d.get("shielded")]
        assert_equal(len(details), 1)
        assert_equal(details[0]["address"], z_addr_1)
        assert_equal(details[0]["category"], "receive")
        assert_equal(details[0]["amount"], amount)

        view = node1.z_viewtransaction(txid_zz)
        assert_equal(view["confirmations"], 0)
        assert "blockhash" not in view

        self.generatetoaddress(node0, 1, t_addr_0)
        self.sync_all()

        self.log.info("Confirmed shielded receive: gettransaction / listtransactions / listsinceblock")
        tx = node1.gettransaction(txid_zz)
        assert_equal(tx["confirmations"], 1)
        blockhash = tx["blockhash"]

        entries = self.find_entries(node1.listtransactions("*", 100), txid_zz)
        assert_equal(len(entries), 1)
        assert_equal(entries[0]["category"], "receive")
        assert_equal(entries[0]["address"], z_addr_1)
        assert_equal(entries[0]["amount"], amount)
        assert_equal(entries[0]["shielded"], True)
        assert_equal(entries[0]["confirmations"], 1)
        assert_equal(entries[0]["blockhash"], blockhash)
        assert "vout" not in entries[0]

        entries = self.find_entries(node1.listsinceblock()["transactions"], txid_zz)
        assert_equal(len(entries), 1)
        assert_equal(entries[0]["amount"], amount)

        # The sender's change note is not reported as a receive
        assert_equal(self.find_entries(node0.listtransactions("*", 100), txid_zz), [])

        self.log.info("z_viewtransaction on the recipient")
        view = node1.z_viewtransaction(txid_zz)
        assert_equal(view["txid"], txid_zz)
        assert_equal(view["confirmations"], 1)
        assert_equal(view["blockhash"], blockhash)
        assert_equal(view["spends"], [])
        assert_equal(len(view["outputs"]), 1)
        out = view["outputs"][0]
        assert_equal(out["outgoing"], False)
        assert_equal(out["address"], z_addr_1)
        assert_equal(out["value"], amount)
        assert_equal(out["valueSat"], int(amount * 100000000))
        assert_equal(out["memo"], MEMO_HEX + "00" * (512 - len(MEMO_TEXT)))
        assert_equal(out["memoStr"], MEMO_TEXT)
        zz_fee = Decimal(view["fee"])
        assert_greater_than(zz_fee, 0)

        self.log.info("z_viewtransaction on the sender: spends and change")
        view0 = node0.z_viewtransaction(txid_zz)
        assert_equal(Decimal(view0["fee"]), zz_fee)
        assert_equal(len(view0["spends"]), 1)
        spend = view0["spends"][0]
        assert_equal(spend["txidPrev"], txid_tz)
        assert_equal(spend["address"], z_addr_0)
        assert_equal(spend["value"], Decimal("5"))
        # The payment to node1 is not encrypted to the sender's OVK; only the change is readable
        assert all(o["address"] != z_addr_1 for o in view0["outputs"])
        assert_equal(sum(o["value"] for o in view0["outputs"]), Decimal("5") - amount - zz_fee)

        self.log.info("The memo stays readable after the note is spent")
        txid_back = node1.z_sendmany(z_addr_1, [{"address": z_addr_0, "amount": 1}])
        self.generatetoaddress(node1, 1, t_addr_0)
        self.sync_all()
        assert_equal(node1.z_listunspent(1, 9999999, [z_addr_1]), [])
        view = node1.z_viewtransaction(txid_zz)
        assert_equal(view["outputs"][0]["memoStr"], MEMO_TEXT)
        view_back = node1.z_viewtransaction(txid_back)
        assert_equal(len(view_back["spends"]), 1)
        assert_equal(view_back["spends"][0]["txidPrev"], txid_zz)
        assert_equal(view_back["spends"][0]["value"], amount)

        self.log.info("Viewing-key-only wallet")
        vk = node1.z_exportviewingkey(z_addr_1)
        node1.createwallet(wallet_name="vkonly", disable_private_keys=True)
        vk_wallet = node1.get_wallet_rpc("vkonly")
        vk_wallet.z_importviewingkey(vk, "yes", 0)
        view = vk_wallet.z_viewtransaction(txid_zz)
        assert_equal(view["outputs"][0]["memoStr"], MEMO_TEXT)
        assert_equal(view["outputs"][0]["value"], amount)
        # The import rescan added the shielded receive to the transaction list
        assert_equal(vk_wallet.gettransaction(txid_zz)["blockhash"], blockhash)
        entries = self.find_entries(vk_wallet.listtransactions("*", 100), txid_zz)
        assert_equal(len(entries), 1)
        assert_equal(entries[0]["involvesWatchonly"], True)
        assert_equal(entries[0]["amount"], amount)

        self.log.info("Error cases")
        assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id",
                                node0.z_viewtransaction, "00" * 32)
        coinbase_txid = node0.getblock(node0.getbestblockhash())["tx"][0]
        assert_raises_rpc_error(-5, "Transaction has no shielded data this wallet can read",
                                node0.z_viewtransaction, coinbase_txid)
        assert_raises_rpc_error(-8, "txid must be of length 64",
                                node0.z_viewtransaction, "abcd")


if __name__ == '__main__':
    SaplingViewTransactionTest().main()
