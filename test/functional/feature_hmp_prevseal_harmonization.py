#!/usr/bin/env python3
# Copyright (c) 2026 The Kerrigan developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the v1.2.6 prevSealHash harmonization across daemon restarts.

Pre-fix (height below nPrevSealHashFixHeight), ConnectBlock derived each seal
session's prevSealHash from the in-memory assembled-seal cache when hot and
fell back to pprev->GetBlockHash() otherwise. The cache does not survive a
restart, so a freshly restarted node fed different VRF input bytes than its
still-running peer at the same height and the two sides rejected each other's
seal shares as "invalid VRF proof". Post-fix every path uses
pprev->GetBlockHash() unconditionally, making the VRF input restart-independent
(validation.cpp ConnectBlock, gated in chainparams.cpp via
-testactivationheight=hmp_prevseal_fix@N on regtest).

Exercises:
  1. Two-node Elder bootstrap on x11 (implicit commitments, 10-block warmup,
     blocks_solved threshold, seal participation)
  2. Gate parked at an unreachable height (legacy behavior): restart node0
     while node1 holds a hot assembled seal for the tip, observe the
     historical VRF cross-rejection on the live SEALSHARE path
  3. Gate at 1 (fix active): heat node1's cache the same way, restart node0
     again, and verify a cross share is accepted for the FIRST post-restart
     block with no VRF rejection logged. The first block is the only
     discriminating one: pre-fix the divergence self-heals after a block via
     the SEALASM relay, so later blocks seal fine either way. Then confirm a
     two-Elder sealed block lands (with exactly 2 Elders a block only gets
     seal_weight > 10000 when both signed) and both nodes agree on
     chain_seal_work for the same tip

If the harmonization regressed (legacy cache-derived path back in effect),
scenario 2 fails twice over: the restarted node0 and the hot node1 diverge on
prevSealHash for the first post-restart block, so its cross shares can never
be accepted, and "rejecting share with invalid VRF proof" reappears in the
logs whenever one is sent (~84% per restart, retried with fresh restarts).

Seal assembly runs on wall-clock time and ignores mocktime, so blocks are
paced with real sleeps against a shortened signing window
(-hmpsigningwindowms=300). VRF committee selection is probabilistic (~60% per
Elder per block), so every observation is a bounded mine-and-poll loop rather
than a single-shot assertion.
"""

import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than

# Wall-clock pacing. The 300ms signing window plus the worker assembly tick
# would allow ~0.5s blocks, but the SEALSHARE handler also rate-limits inbound
# shares to one per second per peer (net_processing.cpp), and cross-node share
# delivery is the whole point here, so blocks are paced past that limit.
SIGNING_WINDOW_MS = 300
BLOCK_PACE = 1.2

GATE_INACTIVE = 5000  # parked beyond any height this test reaches
GATE_ACTIVE = 1       # fix active from genesis

VRF_REJECT_LOG = "rejecting share with invalid VRF proof"
ASSEMBLED_LOG = "HMP: assembled seal for block "

ELDER_BOOTSTRAP_BLOCKS = 120
HEAT_ATTEMPTS = 20
PREFIX_RESTART_ATTEMPTS = 10
PREFIX_BLOCKS_PER_ATTEMPT = 3
POSTFIX_RESTART_ATTEMPTS = 25
SEALED_BLOCK_ATTEMPTS = 40


def hmp_args(gate):
    return [
        # CCbTx v4 needs DIP3 and v20 active; the regtest defaults (432) are
        # far later than anything this test mines
        "-dip3params=2:2",
        "-testactivationheight=v20@2",
        "-debug=hmp",
        "-hmpsigningwindowms=%d" % SIGNING_WINDOW_MS,
        "-fallbackfee=0.00001",
        "-testactivationheight=hmp_prevseal_fix@%d" % gate,
    ]


class HMPPrevSealHarmonizationTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=False)

    def set_test_params(self):
        # Exactly 2 signers: the SEALSHARE handler rate-limits per IP (200ms)
        # and all regtest nodes share 127.0.0.1, so a third signer would drop
        # the others' shares.
        self.num_nodes = 2
        self.setup_clean_chain = True
        # The SEALSHARE rate limiter keys off GetTime(), which is frozen under
        # the framework's fixed mocktime; with mocktime on, every inbound
        # share after the first is dropped and no cross-node seal can form.
        # Seal timing is wall-clock anyway, so run the nodes on real time.
        self.disable_mocktime = True
        self.extra_args = [hmp_args(GATE_INACTIVE)] * 2

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

    def heat_tip_seal(self, miner_idx, addr):
        """Mine on one node until that node assembles a seal for its own tip,
        leaving its in-memory seal cache hot for the next ConnectBlock. The
        miner always has a local session; its own share lands with ~60% VRF
        selection per block, so this converges fast."""
        miner = self.nodes[miner_idx]
        for _ in range(HEAT_ATTEMPTS):
            pos = self.log_pos(miner)
            tip = self.mine_paced(miner, addr)
            if ASSEMBLED_LOG + tip[:16] in self.log_since(miner, pos):
                return tip
        raise AssertionError(
            "node%d never assembled a seal for its tip in %d paced blocks"
            % (miner_idx, HEAT_ATTEMPTS))

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
        # Scenario 1: gate inactive -- restart reproduces the historical
        # VRF cross-rejection
        # ================================================================
        self.log.info("Scenario 1: legacy behavior (gate at %d), restart causes "
                      "prevSealHash divergence", GATE_INACTIVE)

        # A silent attempt is possible: if neither Elder is VRF-selected for
        # the first post-restart block, no share crosses the wire and both
        # caches go cold together, converging on the pprev fallback. Retry
        # with a fresh restart until the rejection is observed.
        rejection_seen = False
        for attempt in range(PREFIX_RESTART_ATTEMPTS):
            # Leave node1 holding a hot assembled seal for the tip, then bounce
            # node0 so its cache is cold. Pre-fix, node1 hashes the assembled
            # seal into the next session while node0 falls back to the pprev
            # block hash.
            self.heat_tip_seal(1, addrs[1])
            self.restart_node(0)
            self.connect_nodes(0, 1)
            self.sync_blocks()

            pos0 = self.log_pos(node0)
            pos1 = self.log_pos(node1)
            for i in range(PREFIX_BLOCKS_PER_ATTEMPT):
                self.mine_paced(self.nodes[i % 2], addrs[i % 2])
                if (VRF_REJECT_LOG in self.log_since(node0, pos0)
                        or VRF_REJECT_LOG in self.log_since(node1, pos1)):
                    rejection_seen = True
                    break
            if rejection_seen:
                self.log.info("Observed legacy VRF cross-rejection on attempt %d",
                              attempt + 1)
                break

        assert rejection_seen, (
            "pre-fix prevSealHash divergence never produced a VRF share "
            "rejection across %d restart attempts" % PREFIX_RESTART_ATTEMPTS)

        # ================================================================
        # Scenario 2: gate active -- the same restart no longer matters
        # ================================================================
        self.log.info("Scenario 2: fix active (gate at %d), restart is harmless",
                      GATE_ACTIVE)

        # Move node1 to the post-fix gate first; node0 follows inside the
        # attempt loop, recreating the exact hot-peer/cold-peer split that
        # broke pre-fix. Cross-rejections during this mixed-gate window are
        # expected and ignored; offsets are taken after node0 is back.
        self.restart_node(1, extra_args=hmp_args(GATE_ACTIVE))
        self.connect_nodes(0, 1)
        self.sync_blocks()

        # The discriminating observation is the FIRST block after node0's
        # restart: its seal session is the only one guaranteed to pair node1's
        # hot cache against node0's cold one. Pre-fix that block's cross
        # shares are always rejected (and the divergence then self-heals via
        # the SEALASM relay, so later blocks prove nothing). Post-fix both
        # sides sign over the pprev block hash and a cross share lands with
        # "(total: 2)" whenever both Elders are VRF-selected (~36% per block),
        # so retry the restart until that positive evidence shows up.
        cross_accept_block = None
        pos0 = pos1 = None
        for attempt in range(POSTFIX_RESTART_ATTEMPTS):
            self.heat_tip_seal(1, addrs[1])
            self.restart_node(0, extra_args=hmp_args(GATE_ACTIVE))
            self.connect_nodes(0, 1)
            self.sync_blocks()

            pos0 = self.log_pos(node0)
            pos1 = self.log_pos(node1)
            first_block = self.mine_paced(node1, addrs[1])

            log0 = self.log_since(node0, pos0)
            log1 = self.log_since(node1, pos1)
            assert VRF_REJECT_LOG not in log0 and VRF_REJECT_LOG not in log1, (
                "VRF share rejection right after a post-fix restart: "
                "prevSealHash still diverges with the gate active")

            needle = "accepted share for block %s" % first_block[:16]
            if any(needle in line and "(total: 2)" in line
                   for line in (log0 + log1).splitlines()):
                cross_accept_block = first_block
                self.log.info("Cross share accepted for the first post-restart "
                              "block on attempt %d", attempt + 1)
                break

        assert cross_accept_block is not None, (
            "no cross-node share accepted for the first post-restart block in "
            "%d attempts; with the fix active both Elders should agree on "
            "prevSealHash immediately after a restart" % POSTFIX_RESTART_ATTEMPTS)

        # With exactly 2 Elders on x11 the agreement threshold is 100%, so
        # seal_weight > 10000 requires BOTH identities in the embedded seal.
        # The cross-accepted seal trails into a block two heights later
        # (trailing depth 2); keep mining until a sealed block shows up.
        start_seal_work = int(
            node1.getsealstatus(node1.getbestblockhash())["chain_seal_work"], 16)
        sealed_hash = None
        for i in range(SEALED_BLOCK_ATTEMPTS):
            block_hash = self.mine_paced(self.nodes[i % 2], addrs[i % 2])
            status = node1.getsealstatus(block_hash)
            if status["has_seal"]:
                sealed_hash = block_hash
                self.log.info("Sealed block at height %d (weight %d) after %d "
                              "more blocks", status["height"],
                              status["seal_weight"], i + 1)
                break

        assert sealed_hash is not None, (
            "no two-Elder sealed block within %d blocks after the post-fix "
            "restart; cross-node shares are not being accepted"
            % SEALED_BLOCK_ATTEMPTS)

        # The live SEALSHARE path must not have rejected any VRF proof since
        # node0 came back: both nodes now derive prevSealHash from the pprev
        # block hash, restart or not. A regression to the cache-derived path
        # reintroduces these lines.
        log0 = self.log_since(node0, pos0)
        log1 = self.log_since(node1, pos1)
        assert VRF_REJECT_LOG not in log0, (
            "node0 rejected a share post-fix: prevSealHash diverged after restart")
        assert VRF_REJECT_LOG not in log1, (
            "node1 rejected a share post-fix: prevSealHash diverged after restart")
        self.log.info("No VRF cross-rejection after the post-fix restart")

        # Both nodes agree on the sealed block and on cumulative seal work.
        status0 = node0.getsealstatus(sealed_hash)
        status1 = node1.getsealstatus(sealed_hash)
        assert_equal(status0["seal_weight"], status1["seal_weight"])
        assert_greater_than(status0["seal_weight"], 10000)

        tip = node1.getbestblockhash()
        assert_equal(node0.getbestblockhash(), tip)
        tip0 = node0.getsealstatus(tip)
        tip1 = node1.getsealstatus(tip)
        assert_equal(tip0["chain_seal_work"], tip1["chain_seal_work"])
        assert_greater_than(int(tip1["chain_seal_work"], 16), start_seal_work)
        self.log.info("Nodes agree on chain_seal_work %s at tip",
                      tip1["chain_seal_work"])

        self.log.info("prevSealHash harmonization holds across restart")


if __name__ == "__main__":
    HMPPrevSealHarmonizationTest().main()
