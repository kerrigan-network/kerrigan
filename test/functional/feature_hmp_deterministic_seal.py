#!/usr/bin/env python3
# Copyright (c) 2026 The Kerrigan developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test deterministic seal weighting across reorgs.

nSealWeight is computed in ConnectBlock from the live HMP trackers and folded
into nChainSealWork, the fork-choice key. The privilege tracker's
BlockDisconnected is not the inverse of BlockConnected: entries front-evicted
from the sliding window while a branch connected are not restored when that
branch disconnects. Pre-fix, a node that reorged away from a block and back
onto it weighed the block against a window short by the reorg depth, so the
SAME block could carry a DIFFERENT nSealWeight than it got by straight
extension, and two nodes on the same chain could permanently disagree on
nChainSealWork.

Post-fix (height >= nHMPDeterministicSealHeight, regtest gate
-testactivationheight=hmp_deterministic_seal@N), ConnectBlock rebuilds the
trackers to the block's parent whenever the state anchor does not match (one
rebuild per reorg, validation.cpp) and credits the privilege window from the
raw on-chain signer list, making the weight a pure fold over block data.

Exercises:
  1. Gate active from genesis: two-node Elder bootstrap on x11 with a small
     privilege window (16 blocks) so the window front-evicts continuously.
     Pick a sealed block B at depth 5..7 below the tip, record seal_weight
     and chain_seal_work for the whole span around it, push node0 through a
     reorg detour (invalidateblock below B, mine one detour block,
     reconsiderblock back), and assert every recomputed value is identical
     to the straight-extension value and still matches node1, which never
     reorged.
  2. Gate parked above the tip (legacy behavior): the identical detour run
     on a fresh sealed block B2. Window math makes the legacy divergence
     deterministic here, not probabilistic: with window W=16 and warmup 10,
     disconnecting d >= 8 blocks from tip T leaves the residual window's
     oldest entry at T-15, so any block reconnected at height h <= T-5 sees
     every signer fail the warmup check (h-1 - (T-15) < 10). The Elder set
     comes back empty and the block is re-weighed exactly neutral (10000).
     B2 was sealed (weight > 10000) on straight extension, so its weight
     MUST change across the detour, node0's tip chain_seal_work diverges
     from its own pre-reorg value and from node1's at the identical tip
     hash, and the phase fails loudly if the legacy path ever reproduces
     the original values. That is the negative control: the equality
     asserted in scenario 1 is only meaningful because scenario 2 shows the
     same harness observing the divergence when the gate is off.

Seal assembly runs on wall-clock time and ignores mocktime, so blocks are
paced with real sleeps against a shortened signing window
(-hmpsigningwindowms=300). VRF committee selection is probabilistic (~60% per
Elder per block), so sealed-block selection is a bounded mine-and-scan loop.
"""

import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than

# Wall-clock pacing, matching feature_hmp_prevseal_harmonization.py: the
# SEALSHARE handler rate-limits inbound shares to one per second per peer,
# and cross-node shares are what turn blocks into 2-Elder seals.
SIGNING_WINDOW_MS = 300
BLOCK_PACE = 1.2

GATE_ACTIVE = 1       # fix active from genesis
GATE_INACTIVE = 5000  # parked beyond any height this test reaches

# Small privilege window so front-eviction is continuous, with enough margin
# over the 10-block warmup that Elder status is stable on straight extension
# (worst-case first_seen offset inside a full window still passes warmup).
PRIVILEGE_WINDOW = 16

# The reorg span: invalidate at least SPAN_DEPTH below the tip. Candidate
# sealed blocks are taken from depth 5..7 so the legacy reconnect (residual
# window short by the span) re-weighs them with an empty Elder set.
SPAN_DEPTH = 7
CANDIDATE_MIN_DEPTH = 5
CANDIDATE_MAX_DEPTH = 7

ELDER_BOOTSTRAP_BLOCKS = 120
CANDIDATE_SCAN_BLOCKS = 60
POST_RESTART_WARMUP_BLOCKS = 10

REBUILD_LOG = "HMP: rebuilding tracker state"


def hmp_args(gate):
    return [
        # CCbTx v4 needs DIP3 and v20 active; the regtest defaults (432) are
        # far later than anything this test mines
        "-dip3params=2:2",
        "-testactivationheight=v20@2",
        "-debug=hmp",
        "-hmpsigningwindowms=%d" % SIGNING_WINDOW_MS,
        "-hmpprivilegewindow=%d" % PRIVILEGE_WINDOW,
        "-fallbackfee=0.00001",
        "-testactivationheight=hmp_deterministic_seal@%d" % gate,
    ]


class HMPDeterministicSealTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=False)

    def set_test_params(self):
        # Exactly 2 signers: the SEALSHARE handler rate-limits per IP (200ms)
        # and all regtest nodes share 127.0.0.1, so a third signer would drop
        # the others' shares.
        self.num_nodes = 2
        self.setup_clean_chain = True
        # The SEALSHARE rate limiter keys off GetTime(), which is frozen under
        # the framework's fixed mocktime; seal timing is wall-clock anyway.
        self.disable_mocktime = True
        self.extra_args = [hmp_args(GATE_ACTIVE)] * 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def log_pos(self, node):
        return node.debug_log_bytes()

    def log_since(self, node, pos):
        with open(node.debug_log_path, encoding="utf-8", errors="replace") as f:
            f.seek(pos)
            return f.read()

    def mine_paced(self, miner, addr):
        """Mine one x11 block, sync it, then sleep past the signing window so
        shares are exchanged and the worker thread assembles the seal."""
        block_hash = self.generatetoaddress(miner, 1, addr, sync_fun=self.no_op)[0]
        self.sync_blocks()
        time.sleep(BLOCK_PACE)
        return block_hash

    def both_elder(self, view_node, id0, id1):
        # gethmpidentity and gethmpprivilegedset serialize the same BLS key
        # with different scheme flag bits in the leading byte, so compare on
        # the remaining 47 bytes.
        entries = view_node.gethmpprivilegedset("x11")["x11"]
        tiers = {e["pubkey"][2:]: e["tier"] for e in entries}
        return tiers.get(id0[2:]) == "elder" and tiers.get(id1[2:]) == "elder"

    def bootstrap_elders(self, addrs, id0, id1):
        """Alternate mining between the nodes until both identities reach
        Elder tier on x11. Mining a block is an implicit commitment; Elder
        needs the commitment matured (10 blocks), warmup passed (10 blocks
        since first_seen), blocks_solved >= 3 in the window, and at least one
        seal participation."""
        for i in range(ELDER_BOOTSTRAP_BLOCKS):
            self.mine_paced(self.nodes[i % 2], addrs[i % 2])
            if self.both_elder(self.nodes[1], id0, id1):
                self.log.info("Both identities reached Elder after %d blocks", i + 1)
                return
        raise AssertionError(
            "both identities failed to reach Elder tier within %d blocks; "
            "x11 set: %s" % (ELDER_BOOTSTRAP_BLOCKS,
                             self.nodes[1].gethmpprivilegedset("x11")))

    def find_sealed_candidate(self, addrs):
        """Mine paced blocks until some block at depth 5..7 below the tip
        carries a 2-Elder seal (seal_weight > 10000). Both Elders are
        VRF-selected for the same block ~36% of the time and the assembled
        seal trails into a block two heights later, so a 3-deep scan window
        converges within a handful of blocks. Returns the candidate height."""
        node0 = self.nodes[0]
        for i in range(CANDIDATE_SCAN_BLOCKS):
            tip_height = node0.getblockcount()
            for depth in range(CANDIDATE_MIN_DEPTH, CANDIDATE_MAX_DEPTH + 1):
                height = tip_height - depth
                status = node0.getsealstatus(node0.getblockhash(height))
                if status["has_seal"]:
                    self.log.info("Sealed candidate at height %d (depth %d, "
                                  "weight %d)", height, depth,
                                  status["seal_weight"])
                    return height
            self.mine_paced(self.nodes[i % 2], addrs[i % 2])
        raise AssertionError(
            "no sealed block landed at depth %d..%d within %d paced blocks"
            % (CANDIDATE_MIN_DEPTH, CANDIDATE_MAX_DEPTH, CANDIDATE_SCAN_BLOCKS))

    def capture_span(self, node, lo, hi):
        """Snapshot (hash, seal_weight, chain_seal_work) for heights lo..hi."""
        span = {}
        for height in range(lo, hi + 1):
            block_hash = node.getblockhash(height)
            status = node.getsealstatus(block_hash)
            span[height] = (block_hash, status["seal_weight"],
                            status["chain_seal_work"])
        return span

    def reorg_via_detour(self, fork_hash, tip_hash, addr):
        """Push node0 off the active chain and back: invalidate fork_hash
        (disconnecting everything from there to the tip), mine one detour
        block on the stub so the trackers churn on a competing branch, then
        reconsider so the original chain, which holds more cumulative seal
        work than the single detour block, wins again and every disconnected
        block is reconnected through ConnectBlock with a recomputed
        nSealWeight."""
        node0 = self.nodes[0]
        node0.invalidateblock(fork_hash)
        assert node0.getbestblockhash() != tip_hash
        detour_hash = self.generatetoaddress(node0, 1, addr,
                                             sync_fun=self.no_op)[0]
        assert_equal(node0.getbestblockhash(), detour_hash)
        node0.reconsiderblock(fork_hash)
        assert_equal(node0.getbestblockhash(), tip_hash)

    def run_test(self):
        node0, node1 = self.nodes
        self.connect_nodes(0, 1)

        addrs = [n.getnewaddress() for n in self.nodes]
        id0 = node0.gethmpidentity()["identity"]
        id1 = node1.gethmpidentity()["identity"]
        assert id0 != id1

        self.log.info("Bootstrapping both nodes to Elder tier on x11")
        self.bootstrap_elders(addrs, id0, id1)

        # ================================================================
        # Scenario 1: gate active -- the same block weighs the same whether
        # reached by straight extension or through a reorg detour
        # ================================================================
        self.log.info("Scenario 1: fix active (gate at %d), reorg detour "
                      "preserves seal weights", GATE_ACTIVE)

        b_height = self.find_sealed_candidate(addrs)
        tip_height = node0.getblockcount()
        tip_hash = node0.getbestblockhash()
        fork_height = min(tip_height - SPAN_DEPTH, b_height - 1)
        fork_hash = node0.getblockhash(fork_height)

        pre = self.capture_span(node0, fork_height, tip_height)
        b_hash = pre[b_height][0]
        assert_greater_than(pre[b_height][1], 10000)
        peer_b = node1.getsealstatus(b_hash)
        assert_equal(peer_b["seal_weight"], pre[b_height][1])

        self.disconnect_nodes(0, 1)
        pos0 = self.log_pos(node0)
        self.reorg_via_detour(fork_hash, tip_hash, addrs[0])

        # The gate's anchor check must have fired: the detour left the
        # trackers asymmetric and the first reconnect rebuilds them from disk.
        assert REBUILD_LOG in self.log_since(node0, pos0), (
            "deterministic-seal gate active but no tracker rebuild was "
            "triggered by the reorg")

        post = self.capture_span(node0, fork_height, tip_height)
        for height in range(fork_height, tip_height + 1):
            assert_equal(post[height], pre[height])
        self.log.info("All %d reconnected blocks kept identical seal_weight "
                      "and chain_seal_work (B at %d: weight %d, work %s)",
                      tip_height - fork_height + 1, b_height,
                      post[b_height][1], post[b_height][2])

        # node1 never reorged; node0's recomputed view still matches it.
        peer_b_after = node1.getsealstatus(b_hash)
        assert_equal(peer_b_after["seal_weight"], post[b_height][1])
        assert_equal(peer_b_after["chain_seal_work"], post[b_height][2])
        assert_equal(node1.getsealstatus(tip_hash)["chain_seal_work"],
                     post[tip_height][2])
        self.log.info("Nodes agree on chain_seal_work %s at the tip after "
                      "the detour", post[tip_height][2])

        self.connect_nodes(0, 1)
        self.sync_blocks()

        # ================================================================
        # Scenario 2 (negative control): gate parked -- the identical detour
        # changes the weights, proving scenario 1 would fail on legacy code
        # ================================================================
        self.log.info("Scenario 2: legacy behavior (gate at %d), the same "
                      "detour diverges", GATE_INACTIVE)

        self.restart_node(0, extra_args=hmp_args(GATE_INACTIVE))
        self.restart_node(1, extra_args=hmp_args(GATE_INACTIVE))
        self.connect_nodes(0, 1)
        self.sync_blocks()

        # Build the span to be reorged entirely under the legacy gate so the
        # recorded straight-extension weights are legacy-computed too.
        for i in range(POST_RESTART_WARMUP_BLOCKS):
            self.mine_paced(self.nodes[i % 2], addrs[i % 2])

        b2_height = self.find_sealed_candidate(addrs)
        tip2_height = node0.getblockcount()
        tip2_hash = node0.getbestblockhash()
        fork2_height = min(tip2_height - SPAN_DEPTH, b2_height - 1)
        fork2_hash = node0.getblockhash(fork2_height)

        pre2 = self.capture_span(node0, fork2_height, tip2_height)
        b2_hash = pre2[b2_height][0]
        assert_greater_than(pre2[b2_height][1], 10000)
        peer_tip2 = node1.getsealstatus(tip2_hash)["chain_seal_work"]
        assert_equal(peer_tip2, pre2[tip2_height][2])

        self.disconnect_nodes(0, 1)
        pos0 = self.log_pos(node0)
        self.reorg_via_detour(fork2_hash, tip2_hash, addrs[0])

        assert REBUILD_LOG not in self.log_since(node0, pos0), (
            "gate parked at %d but a tracker rebuild fired anyway; the "
            "control is not exercising the legacy path" % GATE_INACTIVE)

        post2 = self.capture_span(node0, fork2_height, tip2_height)
        assert_equal(post2[b2_height][0], b2_hash)
        assert_equal(node0.getbestblockhash(), tip2_hash)

        # The legacy divergence: B2 was reconnected against a window short by
        # the reorg span, every signer failed warmup, the Elder set came back
        # empty and the block was re-weighed neutral. If the values come back
        # identical the control proves nothing and the test must not pass.
        assert post2[b2_height][1] != pre2[b2_height][1], (
            "negative control failed: gate-off reorg reproduced the original "
            "seal_weight %d for block %s; the scenario is not exercising the "
            "nSealWeight divergence" % (pre2[b2_height][1], b2_hash))
        assert post2[tip2_height][2] != pre2[tip2_height][2], (
            "negative control failed: gate-off reorg reproduced the original "
            "tip chain_seal_work %s" % pre2[tip2_height][2])
        self.log.info("Legacy divergence at height %d: seal_weight %d -> %d, "
                      "tip chain_seal_work %s -> %s", b2_height,
                      pre2[b2_height][1], post2[b2_height][1],
                      pre2[tip2_height][2], post2[tip2_height][2])

        # node1 never reorged and still holds the straight-extension values:
        # two nodes on the identical tip hash now disagree on the fork-choice
        # key, which is the consensus split the deterministic gate closes.
        peer_b2 = node1.getsealstatus(b2_hash)
        assert_equal(peer_b2["seal_weight"], pre2[b2_height][1])
        assert peer_b2["seal_weight"] != post2[b2_height][1]
        assert node1.getsealstatus(tip2_hash)["chain_seal_work"] != \
            post2[tip2_height][2]
        self.log.info("Same tip %s, node0 work %s vs node1 work %s",
                      tip2_hash[:16], post2[tip2_height][2], peer_tip2)

        self.log.info("Deterministic seal weighting holds with the gate on "
                      "and demonstrably diverges with it off")


if __name__ == "__main__":
    HMPDeterministicSealTest().main()
