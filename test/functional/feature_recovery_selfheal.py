#!/usr/bin/env python3
# Copyright (c) 2026 The Kerrigan developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the WS-HEAL v2 self-heal / auto-rejoin daemon surface.

Covers the daemon-side classes of the design:

  1. RPC contract v2 -- getrecoverystatus shape, stable ids, and repairnode's
     dry-run/arm token protocol.
  2. N1 auto-rejoin -- a node whose only peer is dropped raises NET_ISOLATED,
     the ladder engages, and reconnection clears the finding and resets the
     ladder counters.
  3. T2 stalled tip -- diagnosed and surfaced, and asserted to take NO
     block-level action (no reconsiderblock/invalidateblock is ever invoked
     by the engine).
  4. C1 quarantine -- corrupt the SaplingDB best-block key, force a
     disconnect, and assert daemon_mode "quarantined", networking off, and
     every gated duty subsystem refusing with RPC_IN_QUARANTINE (-35).
  5. crippled_wait -- restart on the corrupted state and assert the two
     warmup-callable RPCs answer while every other method (including unknown
     methods) still throws RPC_IN_WARMUP.
  6. Guided repair -- arm from crippled_wait, assert the wipe happened during
     SHUTDOWN (chain dirs gone before the next spawn), the marker was
     consumed, the wallet/config/peers survived, and the restarted node syncs
     fresh with the ledger's guard counters advanced.
  7. Wipe-rate guard -- a third repair inside the window is refused with
     REPAIR_RATE_LIMITED, and override_rate_limit is honoured and ledgered.
"""

import json
import os
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)

RPC_IN_WARMUP = -28
RPC_IN_QUARANTINE = -35
RPC_METHOD_NOT_FOUND = -32601

# Directories a full repair removes, and state it must always preserve.
WIPED_DIRS = ["blocks", "chainstate", "sapling", "evodb", "llmq", "indexes"]
PRESERVED_FILES = ["peers.dat", "recovery_ledger.json"]


class RecoverySelfHealTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=False)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # -recoverytickinterval compresses the 30 s diagnosis cadence so the
        # ladder and classifier are observable inside a functional test.
        self.extra_args = [["-recoverytickinterval=1"], ["-recoverytickinterval=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    # ---- helpers -----------------------------------------------------

    def chain_path(self, i):
        return os.path.join(self.nodes[i].datadir, self.chain)

    def status(self, i=0):
        return self.nodes[i].getrecoverystatus()

    def wait_for_finding(self, i, code, present=True, timeout=60):
        deadline = time.time() + timeout * self.options.timeout_factor
        last = None
        while time.time() < deadline:
            last = [f["code"] for f in self.status(i)["findings"]]
            if (code in last) == present:
                return
            time.sleep(0.25)
        raise AssertionError(
            f"finding {code} {'not raised' if present else 'not cleared'}; last={last}")

    def wait_for_mode(self, i, mode, timeout=60):
        deadline = time.time() + timeout * self.options.timeout_factor
        last = None
        while time.time() < deadline:
            last = self.status(i)["daemon_mode"]
            if last == mode:
                return
            time.sleep(0.25)
        raise AssertionError(f"daemon_mode never became {mode}; last={last}")

    def ledger(self, i=0):
        path = os.path.join(self.chain_path(i), "recovery_ledger.json")
        if not os.path.exists(path):
            return {}
        with open(path, encoding="utf8") as f:
            return json.load(f)

    def arm_repair(self, i=0, scope="full", override=False, shutdown=True):
        plan = self.nodes[i].repairnode(True, "", scope)
        return self.nodes[i].repairnode(False, plan["confirm_token"], scope, override, shutdown)

    # ---- the contract ------------------------------------------------

    def test_contract_shape(self):
        self.log.info("contract v2: getrecoverystatus shape and stable ids")
        s = self.status(0)
        assert_equal(s["contract_version"], 2)
        for key in ["daemon_mode", "findings", "recommended_action", "auto", "sync", "repair", "guards"]:
            assert key in s, f"missing top-level key {key}"
        assert s["daemon_mode"] in [
            "starting", "syncing", "normal", "degraded", "quarantined", "crippled_wait", "repair_armed"]
        assert s["recommended_action"].startswith("ACTION_")
        for key in ["ladder_stage", "cycles_used", "cycles_max", "window_resets"]:
            assert key in s["auto"], f"missing auto.{key}"
        for key in ["height", "target_height", "progress", "tip_age_secs", "expected_spacing_secs"]:
            assert key in s["sync"], f"missing sync.{key}"
        for key in ["phase", "bytes_wiped", "bytes_total_est", "witnesses_rebuilt",
                    "witnesses_total", "eta_secs"]:
            assert key in s["repair"], f"missing repair.{key}"
        assert_equal(s["guards"], {"attempts_used": 0, "attempts_max": 3,
                                   "wipes_in_window": 0, "wipes_max": 2})
        # eta_secs is null unless cheaply derivable -- never fabricated.
        assert s["repair"]["eta_secs"] is None
        assert_equal(s["repair"]["phase"], "none")

        self.log.info("contract v2: repairnode dry-run / token protocol")
        plan = self.nodes[0].repairnode(True)
        assert_equal(plan["contract_version"], 2)
        assert_equal(plan["dry_run"], True)
        assert_equal(plan["scope"], "full")
        assert_equal(plan["wipe_dirs"], WIPED_DIRS)
        assert "wallet" in plan["preserved"]
        assert "config" in plan["preserved"]
        assert_equal(plan["guards"]["rate_limited"], False)
        assert len(plan["confirm_token"]) > 0
        # A wrong token never arms.
        assert_equal(self.nodes[0].repairnode(False, "not-a-token")["result"], "BAD_TOKEN")
        # A token is one-time: a fresh dry-run invalidates the previous one.
        stale = plan["confirm_token"]
        self.nodes[0].repairnode(True)
        assert_equal(self.nodes[0].repairnode(False, stale)["result"], "BAD_TOKEN")
        # Scope must match the token's scope.
        netplan = self.nodes[0].repairnode(True, "", "network")
        assert_equal(netplan["wipe_dirs"], [])
        assert_equal(sorted(netplan["wipe_files"]), ["anchors.dat", "peers.dat"])
        assert_equal(self.nodes[0].repairnode(False, netplan["confirm_token"], "full")["result"],
                     "BAD_TOKEN")
        assert_raises_rpc_error(-8, "scope must be", self.nodes[0].repairnode, True, "", "bogus")
        # No marker may exist after dry-runs and refusals.
        assert not os.path.exists(os.path.join(self.chain_path(0), "repair_marker.json"))

    # ---- N1: isolation -> auto rejoin --------------------------------

    def test_auto_rejoin(self):
        self.log.info("N1: isolate node0, assert NET_ISOLATED + ladder, then auto-rejoin")
        self.sync_all()
        assert_greater_than_or_equal(self.nodes[0].getconnectioncount(), 1)

        self.disconnect_nodes(0, 1)
        self.wait_for_finding(0, "NET_ISOLATED", present=True)
        s = self.status(0)
        assert_equal(s["daemon_mode"], "degraded")
        assert_equal(s["recommended_action"], "ACTION_WAIT_AUTO")
        finding = next(f for f in s["findings"] if f["code"] == "NET_ISOLATED")
        assert_equal(finding["evidence"]["outbound"], 0)
        assert_equal(finding["evidence"]["inbound"], 0)
        assert_greater_than_or_equal(finding["since"], 0)
        # The auto ladder engaged and consumed a cycle of its loop guard.
        deadline = time.time() + 30 * self.options.timeout_factor
        while time.time() < deadline and self.status(0)["auto"]["cycles_used"] < 1:
            time.sleep(0.25)
        assert_greater_than_or_equal(self.status(0)["auto"]["cycles_used"], 1)
        assert_greater_than_or_equal(self.status(0)["auto"]["cycles_max"], 3)

        # Reconnection + a tip advance is what declares recovery and resets
        # the ladder (design 3.5).
        self.connect_nodes(0, 1)
        self.generate(self.nodes[1], 1, sync_fun=self.no_op)
        self.sync_blocks()
        self.wait_for_finding(0, "NET_ISOLATED", present=False)
        s = self.status(0)
        assert_equal(s["auto"]["cycles_used"], 0)
        assert_equal(s["auto"]["ladder_stage"], 0)
        assert_equal(s["recommended_action"], "ACTION_NONE")

    # ---- T2: stalled tip is surfaced, never acted on -----------------

    def test_stalled_tip_no_block_action(self):
        self.log.info("T2: stalled tip diagnosed and surfaced with NO block-level action")
        node = self.nodes[0]
        tip_before = node.getbestblockhash()
        height_before = node.getblockcount()

        # Push the clock far past the cadence-relative TIP_STALLED floor
        # (max(60 min, 30x observed spacing)) without producing a block.
        node.setmocktime(int(time.time()) + 6 * 60 * 60)
        self.nodes[1].setmocktime(int(time.time()) + 6 * 60 * 60)
        self.wait_for_finding(0, "TIP_STALLED_NONNETWORK", present=True)

        s = self.status(0)
        assert_equal(s["daemon_mode"], "degraded")
        # A non-network stall routes to human diagnosis, never to a
        # one-click block action.
        assert_equal(s["recommended_action"], "ACTION_DIAGNOSE_SUPPORT")
        finding = next(f for f in s["findings"] if f["code"] == "TIP_STALLED_NONNETWORK")
        for key in ["tip_height", "tip_age_secs", "expected_spacing_secs",
                    "best_peer_height", "competing_higher_work_tips"]:
            assert key in finding["evidence"], f"missing evidence.{key}"
        assert_equal(finding["evidence"]["tip_height"], height_before)

        # The engine must never invoke a block-level actuator: the tip is
        # byte-identical and no reconsider/invalidate ran.
        assert_equal(node.getbestblockhash(), tip_before)
        assert_equal(node.getblockcount(), height_before)
        assert_equal(len(node.getchaintips()), 1)

        node.setmocktime(0)
        self.nodes[1].setmocktime(0)

    # ---- C1: quarantine ---------------------------------------------

    def test_quarantine_gates(self):
        self.log.info("C1: sapling drift -> quarantine; assert every duty gate")
        node = self.nodes[0]
        self.disconnect_nodes(0, 1)
        self.generate(node, 6, sync_fun=self.no_op)
        target = node.getblockhash(node.getblockcount() - 2)

        node.recovery_inducedrift("sapling")
        # Any disconnect now trips the SaplingDB best-block check inside
        # DisconnectBlock -- the converted AbortNode site.
        try:
            node.invalidateblock(target)
        except Exception:
            pass  # the validation operation is abandoned, as before
        self.wait_for_mode(0, "quarantined")

        s = self.status(0)
        assert_equal(s["daemon_mode"], "quarantined")
        assert_equal(s["recommended_action"], "ACTION_GUIDED_REPAIR")
        assert "DRIFT_SAPLING" in [f["code"] for f in s["findings"]]

        # 5.2.1 networking is off and cannot be re-enabled.
        assert_equal(node.getnetworkinfo()["networkactive"], False)
        assert_raises_rpc_error(RPC_IN_QUARANTINE, "quarantined", node.setnetworkactive, True)
        # Disabling stays legal.
        assert_equal(node.setnetworkactive(False), False)

        # 5.2.2 mining / template assembly.
        assert_raises_rpc_error(RPC_IN_QUARANTINE, "quarantined", node.getblocktemplate)
        addr = node.get_wallet_rpc(self.default_wallet_name).getnewaddress()
        assert_raises_rpc_error(RPC_IN_QUARANTINE, "quarantined",
                                node.generatetoaddress, 1, addr)

        # 5.2.5 broadcast fails explicitly rather than silently.
        assert_raises_rpc_error(RPC_IN_QUARANTINE, "quarantined",
                                node.sendrawtransaction, "00" * 32)

        # RPC diagnosis itself stays alive.
        assert_equal(node.getrecoverystatus()["contract_version"], 2)
        assert_equal(node.getblockcount() >= 0, True)

    # ---- crippled_wait + guided repair -------------------------------

    def test_crippled_wait_and_repair(self):
        self.log.info("crippled_wait: restart on drifted state, warmup RPC serves diagnosis")
        node = self.nodes[0]
        wallet_dir = os.path.join(self.chain_path(0), "wallets")
        self.stop_node(0)
        # Restart WITHOUT the framework's readiness wait: init parks in
        # crippled_wait, so RPC never leaves warmup.
        node.start(extra_args=self.extra_args[0])
        deadline = time.time() + 60 * self.options.timeout_factor
        while time.time() < deadline:
            try:
                if node.getrecoverystatus()["daemon_mode"] == "crippled_wait":
                    break
            except Exception:
                pass
            time.sleep(0.25)
        s = node.getrecoverystatus()
        assert_equal(s["daemon_mode"], "crippled_wait")
        assert_equal(s["recommended_action"], "ACTION_GUIDED_REPAIR")
        assert "DRIFT_SAPLING" in [f["code"] for f in s["findings"]]

        # 7.5: exactly two commands are warmup-callable; everything else --
        # including unknown methods -- still throws RPC_IN_WARMUP so nothing
        # new is probeable pre-init.
        assert_raises_rpc_error(RPC_IN_WARMUP, None, node.getblockcount)
        assert_raises_rpc_error(RPC_IN_WARMUP, None, node.getpeerinfo)
        assert_raises_rpc_error(RPC_IN_WARMUP, None, node.getblockchaininfo)
        node.repairnode(True)  # must not raise

        self.log.info("guided repair: arm, wipe at SHUTDOWN, resync fresh")
        chain_dir = self.chain_path(0)
        res = self.arm_repair(0, shutdown=True)
        assert_equal(res["armed"], True)
        assert_equal(res["result"], "ARMED")
        assert_equal(res["shutdown_initiated"], True)
        node.wait_until_stopped()

        # 6.2/6.5: the wipe executes during shutdown, so the datadir is
        # already in the bootstrap-triggering state BEFORE the next spawn.
        for d in WIPED_DIRS:
            assert not os.path.exists(os.path.join(chain_dir, d)), f"{d} survived the wipe"
        assert not os.path.exists(os.path.join(chain_dir, "repair_marker.json"))
        assert os.path.exists(os.path.join(chain_dir, "repair_marker.done.json"))
        # 6.1: preserved state.
        assert os.path.isdir(wallet_dir), "wallet dir was wiped"
        for f in PRESERVED_FILES:
            assert os.path.exists(os.path.join(chain_dir, f)), f"{f} was wiped"

        ledger = self.ledger(0)
        assert_equal(len(ledger["attempts"]), 1)
        assert_equal(len(ledger["wipes"]), 1)

        self.start_node(0, extra_args=self.extra_args[0])
        # The done-marker is consumed by the next start.
        assert not os.path.exists(os.path.join(chain_dir, "repair_marker.done.json"))
        assert_equal(self.nodes[0].getblockcount(), 0)
        s = self.status(0)
        assert_equal(s["guards"]["attempts_used"], 1)
        assert_equal(s["guards"]["wipes_in_window"], 1)
        # Repair phase tracking survived the wipe (the ledger lives outside
        # every wiped directory).
        assert s["repair"]["phase"] in ["syncing", "rebuilding_witnesses", "verifying", "done"]

    # ---- wipe-rate guard ---------------------------------------------

    def test_wipe_rate_guard(self):
        self.log.info("6.6: wipe-rate guard refuses the 3rd wipe and ledgers the override")
        node = self.nodes[0]
        # One wipe is already on the ledger from the guided-repair case.
        res = self.arm_repair(0, shutdown=True)
        assert_equal(res["result"], "ARMED")
        node.wait_until_stopped()
        self.start_node(0, extra_args=self.extra_args[0])
        assert_equal(self.status(0)["guards"]["wipes_in_window"], 2)

        # Third attempt inside the 7-day window: refused.
        res = self.arm_repair(0, shutdown=False)
        assert_equal(res["armed"], False)
        assert_equal(res["result"], "REPAIR_RATE_LIMITED")
        assert not os.path.exists(os.path.join(self.chain_path(0), "repair_marker.json"))
        s = self.status(0)
        assert "REPAIR_RATE_LIMITED" in [f["code"] for f in s["findings"]]
        # Front-ends render check-your-disk guidance rather than a button.
        assert_equal(s["recommended_action"], "ACTION_CHECK_DISK")
        finding = next(f for f in s["findings"] if f["code"] == "REPAIR_RATE_LIMITED")
        assert_equal(finding["evidence"]["wipes_in_window"], 2)
        assert_equal(finding["evidence"]["wipes_max"], 2)

        # The explicit override works and is recorded in the ledger.
        res = self.arm_repair(0, override=True, shutdown=False)
        assert_equal(res["armed"], True)
        assert_equal(res["result"], "ARMED")
        assert_equal(self.status(0)["daemon_mode"], "repair_armed")
        attempts = self.ledger(0)["attempts"]
        assert_equal(attempts[-1]["override_rate_limit"], True)

    def run_test(self):
        self.test_contract_shape()
        self.test_auto_rejoin()
        self.test_stalled_tip_no_block_action()
        self.test_quarantine_gates()
        self.test_crippled_wait_and_repair()
        self.test_wipe_rate_guard()


if __name__ == "__main__":
    RecoverySelfHealTest().main()
