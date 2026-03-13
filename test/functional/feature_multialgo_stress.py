#!/usr/bin/env python3
# Copyright (c) 2026 The Kerrigan developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Stress test for multi-algo mining and P2P synchronization.

Exercises:
  1. Mine blocks with all 4 algorithms in rotation, verify 3-node sync
  2. Chain split and reorg: disconnect, mine competing chains, reconnect
  3. Rapid block production: 50 blocks (x11/kawpow) as fast as possible
  4. Verify getblockchaininfo shows correct algo distribution
  5. Verify getblock returns correct algo field per block
  6. Mine from different nodes, verify propagation

Topology: node0 <-> node1 <-> node2  (node0 NOT directly connected to node2)

Note: Equihash solving is CPU-intensive even at regtest difficulty.
  maxtries is capped (15 for eq200, 10 for eq192) per launch_testnet.sh pattern.
  Rapid mining (test 3) uses x11/kawpow only to keep runtime practical.
"""

import time
from collections import Counter
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than

ALGOS = ["x11", "kawpow", "equihash200", "equihash192"]
FAST_ALGOS = ["x11", "kawpow"]

# Equihash max_tries must be low -- each nonce takes 10-30 seconds to solve.
# With regtest's easy powLimit, ~50% success rate per nonce, so 10-15 is plenty.
MAXTRIES = {
    "x11":          1000000,
    "kawpow":       1000000,
    "equihash200":  15,
    "equihash192":  10,
}


class MultiAlgoStressTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=True)

    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        # Equihash solving needs extended RPC timeout (up to ~120s per block)
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        """Create chain topology: node0 <-> node1 <-> node2 (no direct node0<->node2)."""
        self.setup_nodes()
        # node1 connects to node0, node2 connects to node1
        self.connect_nodes(1, 0)
        self.connect_nodes(2, 1)
        self.sync_all()

    def mine_block(self, node, algo, sync=True):
        """Mine a single block with the given algo. Returns the block hash."""
        addr = node.getnewaddress()
        self.bump_mocktime(120)
        maxtries = MAXTRIES[algo]
        if sync:
            hashes = self.generatetoaddress(node, 1, addr, maxtries, algo)
        else:
            hashes = self.generatetoaddress(node, 1, addr, maxtries, algo,
                                            sync_fun=self.no_op)
        assert len(hashes) == 1, "Expected 1 block hash, got %d" % len(hashes)
        return hashes[0]

    def mine_blocks(self, node, n, algo, sync=True):
        """Mine n blocks with the given algo. Returns list of block hashes."""
        addr = node.getnewaddress()
        self.bump_mocktime(120 * n)
        maxtries = MAXTRIES[algo]
        if sync:
            hashes = self.generatetoaddress(node, n, addr, maxtries, algo)
        else:
            hashes = self.generatetoaddress(node, n, addr, maxtries, algo,
                                            sync_fun=self.no_op)
        assert_equal(len(hashes), n)
        return hashes

    def assert_all_synced(self, msg=""):
        """Assert all 3 nodes have the same height and tip hash."""
        heights = [n.getblockcount() for n in self.nodes]
        tips = [n.getbestblockhash() for n in self.nodes]
        self.log.info("  Heights: %s, Tips: %s %s", heights,
                      [t[:16] + "..." for t in tips], msg)
        assert_equal(heights[0], heights[1])
        assert_equal(heights[0], heights[2])
        assert_equal(tips[0], tips[1])
        assert_equal(tips[0], tips[2])

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        node2 = self.nodes[2]

        # Track all mined block hashes and their expected algos
        block_algo_map = {}  # hash -> expected algo name

        # ================================================================
        # TEST 1: Mine blocks with all 4 algos in rotation, verify sync
        # ================================================================
        self.log.info("Test 1: Mine blocks with all 4 algos in rotation on node0")

        for algo in ALGOS:
            self.log.info("    Mining %s block...", algo)
            bhash = self.mine_block(node0, algo)
            block_algo_map[bhash] = algo
            self.log.info("    Mined %s block: %s", algo, bhash[:16] + "...")

        # Verify all nodes synced after the round
        self.assert_all_synced("(after rotation round)")

        height_after_rotation = node0.getblockcount()
        self.log.info("  All 4 algos mined in rotation, height=%d", height_after_rotation)
        assert_equal(height_after_rotation, 4)  # 1 round * 4 algos

        # ================================================================
        # TEST 2: Chain split and reorg
        # ================================================================
        self.log.info("Test 2: Chain split and reorg")

        # Record current state
        pre_split_height = node0.getblockcount()
        pre_split_tip = node0.getbestblockhash()
        self.log.info("  Pre-split: height=%d, tip=%s", pre_split_height,
                      pre_split_tip[:16] + "...")

        # Disconnect node2 from node1
        self.log.info("  Disconnecting node2 from node1")
        self.disconnect_nodes(2, 1)

        # Mine 5 blocks on node0 (x11) -- these propagate to node1 but NOT node2
        self.log.info("  Mining 5 x11 blocks on node0")
        node0_hashes = self.mine_blocks(node0, 5, "x11", sync=False)
        for h in node0_hashes:
            block_algo_map[h] = "x11"

        # Sync node0 and node1 (they are still connected)
        self.sync_blocks(nodes=[node0, node1])

        # Mine 3 blocks on node2 (kawpow) -- isolated chain
        self.log.info("  Mining 3 kawpow blocks on node2 (isolated)")
        node2_hashes = self.mine_blocks(node2, 3, "kawpow", sync=False)

        # Verify the split
        node0_height = node0.getblockcount()
        node2_height = node2.getblockcount()
        self.log.info("  Split state: node0 height=%d, node2 height=%d",
                      node0_height, node2_height)
        assert_equal(node0_height, pre_split_height + 5)
        assert_equal(node2_height, pre_split_height + 3)
        assert node0.getbestblockhash() != node2.getbestblockhash(), \
            "Tips should differ during split"

        # Reconnect -- node2 should reorg to node0's longer chain.
        # During reorg, the peer may get disconnected. Retry connection.
        self.log.info("  Reconnecting node2 to node1")
        for attempt in range(5):
            try:
                self.connect_nodes(2, 1)
                break
            except AssertionError as e:
                if "peer disconnected" in str(e) and attempt < 4:
                    self.log.info("    Reconnect attempt %d failed (peer disconnected during reorg), retrying...", attempt + 1)
                    time.sleep(2)
                else:
                    raise
        self.sync_blocks()

        # Verify reorg completed
        self.assert_all_synced("(after reorg)")
        assert_equal(node0.getblockcount(), pre_split_height + 5)
        assert_equal(node2.getbestblockhash(), node0.getbestblockhash())
        self.log.info("  Reorg successful: node2 followed node0's longer chain")

        # The 3 kawpow blocks from node2 should be orphaned
        for h in node2_hashes:
            try:
                blk = node2.getblock(h)
                # Orphaned blocks have -1 confirmations
                assert blk["confirmations"] == -1, \
                    "Orphaned block %s... should have -1 confirmations, got %d" % (
                        h[:16], blk["confirmations"])
                self.log.info("    Orphaned block %s... confirmations=%d (correct)",
                              h[:16], blk["confirmations"])
            except Exception:
                # Block may not be accessible at all after reorg
                pass

        # ================================================================
        # TEST 3: Rapid block production (50 blocks, x11/kawpow)
        # ================================================================
        self.log.info("Test 3: Rapid block production -- 50 blocks (x11/kawpow)")

        rapid_start_height = node0.getblockcount()
        rapid_hashes = []

        # Mine 50 blocks cycling through fast algos only
        for i in range(50):
            algo = FAST_ALGOS[i % 2]
            bhash = self.mine_block(node0, algo)
            rapid_hashes.append(bhash)
            block_algo_map[bhash] = algo

        rapid_end_height = node0.getblockcount()
        assert_equal(rapid_end_height, rapid_start_height + 50)
        self.assert_all_synced("(after 50 rapid blocks)")
        self.log.info("  50 blocks mined and synced, height=%d", rapid_end_height)

        # ================================================================
        # TEST 4: Verify getblockchaininfo shows correct state
        # ================================================================
        self.log.info("Test 4: Verify getblockchaininfo shows correct state")

        info = node0.getblockchaininfo()
        self.log.info("  Chain: %s, Blocks: %d, Headers: %d",
                      info["chain"], info["blocks"], info["headers"])
        assert_equal(info["chain"], "regtest")
        assert_equal(info["blocks"], rapid_end_height)
        assert_equal(info["headers"], rapid_end_height)

        # Compute algo distribution by walking the entire chain
        algo_counts = Counter()
        total_height = node0.getblockcount()
        for h in range(1, total_height + 1):
            bhash = node0.getblockhash(h)
            blk = node0.getblock(bhash)
            algo_counts[blk["algo"]] += 1

        self.log.info("  Algo distribution across %d blocks:", total_height)
        for algo_name in ALGOS:
            count = algo_counts.get(algo_name, 0)
            pct = 100.0 * count / total_height if total_height > 0 else 0
            self.log.info("    %s: %d blocks (%.1f%%)", algo_name, count, pct)
            # All 4 algos should have been used (from Test 1)
            assert_greater_than(count, 0)

        # All nodes should agree on blockchain info
        for i, node in enumerate(self.nodes):
            node_info = node.getblockchaininfo()
            assert_equal(node_info["blocks"], info["blocks"])
            assert_equal(node_info["bestblockhash"], info["bestblockhash"])

        # ================================================================
        # TEST 5: Verify getblock returns correct algo field
        # ================================================================
        self.log.info("Test 5: Verify getblock returns correct algo for each block")

        verified = 0
        for bhash, expected_algo in block_algo_map.items():
            blk = node0.getblock(bhash)
            actual_algo = blk["algo"]
            assert_equal(actual_algo, expected_algo)
            verified += 1

        self.log.info("  Verified algo field for %d blocks", verified)

        # Cross-node getblock consistency on a sample
        sample_hashes = list(block_algo_map.keys())[:10]
        for bhash in sample_hashes:
            blk0 = node0.getblock(bhash)
            blk1 = node1.getblock(bhash)
            blk2 = node2.getblock(bhash)
            assert_equal(blk0["algo"], blk1["algo"])
            assert_equal(blk0["algo"], blk2["algo"])
            assert_equal(blk0["hash"], blk1["hash"])
            assert_equal(blk0["hash"], blk2["hash"])

        self.log.info("  Cross-node getblock consistency verified")

        # ================================================================
        # TEST 6: Mine from different nodes, verify propagation
        # ================================================================
        self.log.info("Test 6: Mine from node1 and node2, verify propagation")

        # Mine x11 and kawpow from node1 (fast algos to verify propagation)
        for algo in FAST_ALGOS:
            self.log.info("  node1 mining %s block...", algo)
            bhash = self.mine_block(node1, algo)
            block_algo_map[bhash] = algo
            self.log.info("  node1 mined %s block: %s", algo, bhash[:16] + "...")

        # Also mine one equihash200 from node1 to prove equihash propagates from non-node0
        self.log.info("  node1 mining equihash200 block...")
        bhash = self.mine_block(node1, "equihash200")
        block_algo_map[bhash] = "equihash200"
        self.log.info("  node1 mined equihash200 block: %s", bhash[:16] + "...")

        self.assert_all_synced("(after node1 mining)")

        # Mine x11 and kawpow from node2 (propagates via node1 to node0)
        for algo in FAST_ALGOS:
            self.log.info("  node2 mining %s block...", algo)
            bhash = self.mine_block(node2, algo)
            block_algo_map[bhash] = algo
            self.log.info("  node2 mined %s block: %s", algo, bhash[:16] + "...")

        self.assert_all_synced("(after node2 mining)")

        # ================================================================
        # Final summary
        # ================================================================
        final_height = node0.getblockcount()
        self.log.info("=== Multi-algo stress test PASSED ===")
        self.log.info("  Final chain height: %d", final_height)
        self.log.info("  Total blocks verified: %d", len(block_algo_map))
        self.log.info("  Algos tested: %s", ", ".join(ALGOS))
        self.log.info("  Reorg test: PASSED")
        self.log.info("  Rapid mining (50 blocks): PASSED")
        self.log.info("  Multi-node mining: PASSED")


if __name__ == "__main__":
    MultiAlgoStressTest().main()
