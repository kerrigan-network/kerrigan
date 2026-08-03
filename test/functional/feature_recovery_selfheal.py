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
     every gated duty subsystem refusing with RPC_IN_QUARANTINE (-37).

PARK-VS-EXIT (owner decision, 2026-07-31): GUI/wallet-managed nodes PARK on a
fault (crippled_wait/quarantine) so the wallet can offer a one-click Repair;
headless kerrigand instead EXITS non-zero with a clear diagnostic so
systemd/monitoring catches the fault. The whole suite runs kerrigand with
-parkonfault=1 to keep exercising the park path; test_headless_exit_on_* drop
the flag to cover the production headless default (exit on startup fault and on
runtime drift).
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

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
    get_rpc_proxy,
    rpc_url,
)

RPC_IN_WARMUP = -28
# Must not collide with RPC_WALLET_ALREADY_LOADED (-35) -- see rpc/protocol.h.
RPC_IN_QUARANTINE = -37
RPC_METHOD_NOT_FOUND = -32601
RPC_INVALID_PARAMETER = -8

# PARK-VS-EXIT (owner decision, 2026-07-31): the distinct, greppable line the
# headless binary emits (log + stderr) when it EXITS non-zero on a fault instead
# of parking. The whole suite runs kerrigand with -parkonfault=1 so it keeps
# exercising the PARK path (GUI/wallet behaviour); the two dedicated headless-
# exit cases drop the flag to prove the default headless behaviour is to exit.
HEADLESS_EXIT_TAG = "HEADLESS FAULT EXIT"
PARK_ON_FAULT_ARG = "-parkonfault=1"

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
        # -selfheal=1 is explicit because every framework datadir carries
        # connect=0, which otherwise infers the auto engine off.
        # -parkonfault=1 simulates a GUI/wallet-managed frontend so the headless
        # kerrigand keeps exercising the PARK path (crippled_wait/quarantine)
        # that the wallet's one-click Repair depends on. The two dedicated
        # headless-exit cases restart WITHOUT this flag to cover the production
        # headless default (exit non-zero on a fault).
        args = ["-recoverytickinterval=1", "-selfheal=1", PARK_ON_FAULT_ARG]
        self.extra_args = [args, args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    # ---- helpers -----------------------------------------------------

    def node_args(self, i):
        """Restart args, with the node's baked -mocktime re-pinned to now.

        TestNode bakes -mocktime into self.args at construction time. The
        stall case pushes mocktime hours forward, so a restart that kept the
        original value would see every block mined after the bump as "from
        the future" and fail VerifyDB."""
        node = self.nodes[i]
        node.args = [a for a in node.args if not a.startswith("-mocktime=")]
        node.mocktime = self.mocktime  # TestNode.start() appends this last
        return self.extra_args[i]

    def node_args_no_park(self, i):
        """node_args(i) with -parkonfault dropped: the production headless
        default, where a fault EXITS non-zero instead of parking."""
        return [a for a in self.node_args(i) if a != PARK_ON_FAULT_ARG]

    def assert_exited_nonzero(self, i, timeout=60):
        """Wait for node i's process to exit and assert a NON-ZERO code, then
        tidy the framework bookkeeping (the node did NOT stop cleanly, so
        wait_until_stopped -- which asserts exit 0 -- must not be used)."""
        node = self.nodes[i]
        deadline = time.time() + timeout * self.options.timeout_factor
        rc = None
        while time.time() < deadline:
            rc = node.process.poll()
            if rc is not None:
                break
            time.sleep(0.25)
        assert rc is not None, "node stayed alive on a headless fault (parked?) instead of exiting"
        assert rc != 0, f"a headless fault must exit non-zero; got exit code {rc}"
        node.running = False
        node.process = None
        node.rpc = None
        node.rpc_connected = False

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

    def mine(self, i, count):
        # The framework's deterministic PRIV_KEYS carry devnet-encoded
        # addresses, so self.generate() cannot be used on this chain; mine to
        # a wallet address instead.
        node = self.nodes[i]
        addr = node.get_wallet_rpc(self.default_wallet_name).getnewaddress()
        return node.generatetoaddress(count, addr, invalid_call=False)

    def warmup_rpc(self, i):
        """Raw RPC proxy that does not wait for warmup to finish.

        TestNode.wait_for_rpc_connection() blocks until getblockcount()
        succeeds, which never happens in crippled_wait -- the whole point of
        the warmup-callable RPC surface."""
        node = self.nodes[i]
        return get_rpc_proxy(rpc_url(node.datadir, node.index, self.chain, node.rpchost),
                             node.index, timeout=30, coveragedir=node.coverage_dir)

    def arm_repair(self, rpc, scope="full", override=False, shutdown=True):
        plan = rpc.repairnode(True, "", scope)
        return rpc.repairnode(False, plan["confirm_token"], scope, override, shutdown)

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
        self.mine(1, 1)
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
        self.mocktime += 6 * 60 * 60
        for n in self.nodes:
            n.setmocktime(self.mocktime)
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

    # ---- C1: quarantine ---------------------------------------------

    def test_quarantine_gates(self):
        self.log.info("C1: sapling drift -> quarantine; assert every duty gate")
        node = self.nodes[0]
        self.disconnect_nodes(0, 1)
        self.mine(0, 6)
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
                                node.generatetoaddress, 1, addr, invalid_call=False)

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
        node.start(extra_args=self.node_args(0))
        rpc = None
        deadline = time.time() + 60 * self.options.timeout_factor
        while time.time() < deadline:
            try:
                rpc = self.warmup_rpc(0)
                if rpc.getrecoverystatus()["daemon_mode"] == "crippled_wait":
                    break
            except Exception:
                rpc = None
            time.sleep(0.25)
        assert rpc is not None, "warmup RPC never came up in crippled_wait"
        s = rpc.getrecoverystatus()
        assert_equal(s["daemon_mode"], "crippled_wait")
        assert_equal(s["recommended_action"], "ACTION_GUIDED_REPAIR")
        assert "DRIFT_SAPLING" in [f["code"] for f in s["findings"]]

        # 7.5: exactly two commands are warmup-callable; everything else --
        # including unknown methods -- still throws RPC_IN_WARMUP so nothing
        # new is probeable pre-init.
        assert_raises_rpc_error(RPC_IN_WARMUP, None, rpc.getblockcount)
        assert_raises_rpc_error(RPC_IN_WARMUP, None, rpc.getpeerinfo)
        assert_raises_rpc_error(RPC_IN_WARMUP, None, rpc.getblockchaininfo)
        # Unknown methods keep returning RPC_IN_WARMUP too, so the new
        # pre-init surface reveals nothing about the command table.
        try:
            rpc.nosuchmethod_recovery_probe()
            raise AssertionError("unknown method did not raise during warmup")
        except JSONRPCException as e:
            assert_equal(e.error["code"], RPC_IN_WARMUP)
        rpc.repairnode(True)  # must not raise

        self.log.info("guided repair: arm, wipe at SHUTDOWN, resync fresh")
        chain_dir = self.chain_path(0)
        res = self.arm_repair(rpc, shutdown=True)
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

        self.start_node(0, extra_args=self.node_args(0))
        # The done-marker is consumed by the next start.
        assert not os.path.exists(os.path.join(chain_dir, "repair_marker.done.json"))
        assert_equal(self.nodes[0].getblockcount(), 0)
        s = self.status(0)
        assert_equal(s["guards"]["attempts_used"], 1)
        assert_equal(s["guards"]["wipes_in_window"], 1)
        # Repair phase tracking survived the wipe (the ledger lives outside
        # every wiped directory).
        assert s["repair"]["phase"] in ["syncing", "rebuilding_witnesses", "verifying", "done"]

        # W1 (6.4): once the resync leaves IBD the flow must pass through the
        # explicit witness-rebuild stage rather than silently declaring done --
        # a preserved wallet's per-note Sapling witnesses were built against
        # the pre-wipe chain.
        self.mine(0, 3)
        seen = set()
        deadline = time.time() + 60 * self.options.timeout_factor
        while time.time() < deadline:
            seen.add(self.status(0)["repair"]["phase"])
            if seen & {"verifying", "done"}:
                break
            time.sleep(0.25)
        assert "rebuilding_witnesses" in seen, f"witness stage skipped; phases seen: {seen}"
        # Phases advance in the documented order; the guard counters only
        # reset on VERIFIED health, so "done" is not required here (this node
        # is deliberately isolated and still carries findings).
        assert seen & {"verifying", "done"}, f"repair never advanced past the witness stage: {seen}"
        # The wallet survived the wipe and is usable again.
        assert_greater_than_or_equal(
            len(self.nodes[0].get_wallet_rpc(self.default_wallet_name).getnewaddress()), 1)

    # ---- wipe-rate guard ---------------------------------------------

    def test_wipe_rate_guard(self):
        self.log.info("6.6: wipe-rate guard refuses the 3rd wipe and ledgers the override")
        node = self.nodes[0]
        # One wipe is already on the ledger from the guided-repair case.
        res = self.arm_repair(node, shutdown=True)
        assert_equal(res["result"], "ARMED")
        node.wait_until_stopped()
        self.start_node(0, extra_args=self.node_args(0))
        assert_equal(self.status(0)["guards"]["wipes_in_window"], 2)

        # Third attempt inside the 7-day window: refused.
        res = self.arm_repair(self.nodes[0], shutdown=False)
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
        res = self.arm_repair(self.nodes[0], override=True, shutdown=False)
        assert_equal(res["armed"], True)
        assert_equal(res["result"], "ARMED")
        assert_equal(self.status(0)["daemon_mode"], "repair_armed")
        attempts = self.ledger(0)["attempts"]
        assert_equal(attempts[-1]["override_rate_limit"], True)

    # ---- B1: the wipe executor never follows marker-supplied paths --------

    def test_marker_cannot_wipe_outside_datadir(self):
        """A crafted marker must not delete anything, anywhere.

        Regression for the confirmed data-loss finding: ResolveWipePath used
        to do `datadir / label` with no validation, so an absolute label
        discarded the datadir prefix and a `../` label escaped it -- and the
        rename-to-tombstone failure then fell through to a direct
        remove_all(). The executor now derives its target set from a
        hard-coded whitelist and validates every marker label; one bad label
        aborts the WHOLE repair with nothing removed."""
        self.log.info("B1: a crafted marker cannot wipe paths outside the datadir")
        node = self.nodes[0]
        chain_dir = self.chain_path(0)

        # Canaries: one OUTSIDE the datadir entirely (absolute path, the
        # confirmed wallet.dat case) and one reached by `..` traversal.
        outside_dir = os.path.join(self.options.tmpdir, "CANARY_outside")
        outside_file = os.path.join(outside_dir, "wallet.dat")
        os.makedirs(outside_dir, exist_ok=True)
        with open(outside_file, "w", encoding="utf8") as f:
            f.write("precious")
        sibling_dir = os.path.join(self.nodes[0].datadir, "CANARY_sibling")
        os.makedirs(sibling_dir, exist_ok=True)
        sibling_file = os.path.join(sibling_dir, "wallet.dat")
        with open(sibling_file, "w", encoding="utf8") as f:
            f.write("precious")

        self.stop_node(0)
        marker_path = os.path.join(chain_dir, "repair_marker.json")
        for wipe_dirs in ([outside_dir], ["../CANARY_sibling"], [outside_dir, "../CANARY_sibling"]):
            with open(marker_path, "w", encoding="utf8") as f:
                json.dump({"version": 1, "armed_ts": int(time.time()), "scope": "full",
                           "wipe_dirs": wipe_dirs, "wipe_files": []}, f)
            # Startup consumes/validates the marker before any DB is opened.
            self.start_node(0, extra_args=self.node_args(0))
            assert os.path.exists(outside_file), "canary OUTSIDE the datadir was deleted"
            assert os.path.exists(sibling_file), "canary reached by `..` was deleted"
            # Fail-closed: refused, not silently executed. The marker is
            # quarantined (not left to re-fire) and the repair reads failed.
            assert not os.path.exists(marker_path), "rejected marker was left armed"
            assert os.path.exists(os.path.join(chain_dir, "repair_marker.rejected.json"))
            assert_equal(self.status(0)["repair"]["phase"], "failed")
            # And nothing legitimate was wiped either -- the abort is total.
            assert os.path.isdir(os.path.join(chain_dir, "blocks")), "blocks/ wiped by a refused marker"
            self.stop_node(0)
            os.remove(os.path.join(chain_dir, "repair_marker.rejected.json"))

        # A marker naming only whitelisted labels but armed long ago is also
        # refused at startup (an accidental/forgotten arm, a restored backup,
        # or a copied datadir must not wipe months later).
        with open(marker_path, "w", encoding="utf8") as f:
            json.dump({"version": 1, "armed_ts": int(time.time()) - 40 * 24 * 3600,
                       "scope": "full", "wipe_dirs": ["blocks"], "wipe_files": []}, f)
        self.start_node(0, extra_args=self.node_args(0))
        assert os.path.isdir(os.path.join(chain_dir, "blocks")), "a stale marker wiped blocks/"
        assert os.path.exists(os.path.join(chain_dir, "repair_marker.rejected.json"))
        os.remove(os.path.join(chain_dir, "repair_marker.rejected.json"))
        # Reset the ledger's repair_state so later cases start from idle.
        assert_equal(self.status(0)["repair"]["phase"], "failed")

    # ---- M-armed-irrevocable: an armed repair can be cancelled -----------

    def test_disarm(self):
        self.log.info("M-armed: an armed repair can be disarmed before it fires")
        node = self.nodes[0]
        chain_dir = self.chain_path(0)
        res = self.arm_repair(node, shutdown=False)
        assert_equal(res["result"], "ARMED")
        assert os.path.exists(os.path.join(chain_dir, "repair_marker.json"))
        assert_equal(self.status(0)["daemon_mode"], "repair_armed")

        res = node.repairnode(False, "", "full", False, False, True)
        assert_equal(res["disarmed"], True)
        assert_equal(res["result"], "DISARMED")
        assert not os.path.exists(os.path.join(chain_dir, "repair_marker.json"))
        assert self.status(0)["daemon_mode"] != "repair_armed"
        # A cancelled arm performed no wipe, so it releases its slot in the
        # 3-attempts-per-6h loop guard (the wipe-rate guard is untouched).
        assert_equal(self.status(0)["guards"]["attempts_used"], 0)
        # Disarming again is a no-op, not an error.
        assert_equal(node.repairnode(False, "", "full", False, False, True)["result"], "NOT_ARMED")
        # Mixing disarm with the arm/dry-run parameters is refused.
        assert_raises_rpc_error(RPC_INVALID_PARAMETER, "disarm cannot be combined",
                               node.repairnode, True, "", "full", False, False, True)

        # And the disarmed node shuts down WITHOUT wiping anything.
        self.stop_node(0)
        for d in WIPED_DIRS[:2]:
            assert os.path.isdir(os.path.join(chain_dir, d)), f"{d} was wiped after a disarm"
        self.start_node(0, extra_args=self.node_args(0))

    # ---- B2/B3/M-stop: quarantine survives a restart ---------------------

    def test_quarantine_survives_restart(self):
        """A quarantined node must not return to full duty on a plain restart.

        Regression for the confirmed escape: quarantine was process-local, so
        `stop` + an identical restart produced daemon_mode "normal",
        networkactive true and a servable block template."""
        self.log.info("B2: quarantine persists across a plain restart")
        node = self.nodes[0]
        node.recovery_inducedrift("quarantine")
        self.wait_for_mode(0, "quarantined")
        # B3: serving suppression does not depend on the net-active flag.
        assert_raises_rpc_error(RPC_IN_QUARANTINE, "quarantined", node.setnetworkactive, True)
        assert_equal(node.getnetworkinfo()["networkactive"], False)
        assert_raises_rpc_error(RPC_IN_QUARANTINE, "quarantined", node.getblocktemplate)
        assert os.path.exists(os.path.join(self.chain_path(0), "quarantine_state.json"))

        # M-stop: `stop` works from the held state (no wipe required to exit).
        self.stop_node(0)

        # Plain restart, identical args: the node comes back HELD, not normal.
        node.start(extra_args=self.node_args(0))
        rpc = None
        deadline = time.time() + 60 * self.options.timeout_factor
        while time.time() < deadline:
            try:
                rpc = self.warmup_rpc(0)
                if rpc.getrecoverystatus()["daemon_mode"] == "crippled_wait":
                    break
            except Exception:
                rpc = None
            time.sleep(0.25)
        assert rpc is not None, "restarted node never reported the persisted quarantine"
        s = rpc.getrecoverystatus()
        assert_equal(s["daemon_mode"], "crippled_wait")
        assert_equal(s["recommended_action"], "ACTION_GUIDED_REPAIR")
        # Duties are unreachable: warmup keeps every non-recovery RPC out,
        # and P2P was never started at all.
        assert_raises_rpc_error(RPC_IN_WARMUP, None, rpc.getblocktemplate)
        assert_raises_rpc_error(RPC_IN_WARMUP, None, rpc.getpeerinfo)

        # M-stop: `stop` is callable during warmup, so the operator always has
        # an in-band exit from the held state that is NOT arming a wipe.
        rpc.stop()
        node.wait_until_stopped()
        assert not os.path.exists(os.path.join(self.chain_path(0), "repair_marker.json")), \
            "stopping a held node armed a wipe"
        # The sentinel survives an exit-without-repair: still held next boot.
        assert os.path.exists(os.path.join(self.chain_path(0), "quarantine_state.json"))

        # The documented non-destructive escape: an EXPLICIT operator rebuild.
        self.start_node(0, extra_args=self.node_args(0) + ["-reindex"])
        assert not os.path.exists(os.path.join(self.chain_path(0), "quarantine_state.json"))
        assert_equal(self.status(0)["daemon_mode"] in ["normal", "syncing", "degraded"], True)

    # Modes that are SETTLED (init has decided). A persisted-quarantine node
    # briefly reports "quarantined" in its pre-init snapshot before init reaches
    # RunCrippledWait -- calling stop() in that window would exit mid-init (a
    # non-zero code), so both are treated as still-transient here.
    _SETTLED_MODES = ("crippled_wait", "normal", "syncing", "degraded")

    def _restart_and_read_mode(self, i):
        """Restart node i (no warmup wait), wait for a SETTLED daemon_mode,
        return it, then stop the node cleanly. Handles crippled_wait (which
        never leaves warmup) via the raw warmup RPC proxy."""
        node = self.nodes[i]
        node.start(extra_args=self.node_args(i))
        rpc = None
        mode = None
        deadline = time.time() + 60 * self.options.timeout_factor
        while time.time() < deadline:
            try:
                rpc = self.warmup_rpc(i)
                mode = rpc.getrecoverystatus()["daemon_mode"]
                if mode in self._SETTLED_MODES:
                    break
            except Exception:
                rpc = None
            time.sleep(0.25)
        assert rpc is not None and mode in self._SETTLED_MODES, \
            f"node never reached a settled daemon_mode (last={mode})"
        rpc.stop()
        node.wait_until_stopped()
        return mode

    def test_sentinel_fail_closed(self):
        """NF-1 (BLOCKER): a malformed quarantine sentinel must FAIL CLOSED --
        the node comes up HELD (crippled_wait), never returns to full duty, and
        the sentinel is never silently cleared. Regression for the confirmed
        one-byte defeat: a truncated/empty/non-object sentinel used to boot the
        node straight back to daemon_mode 'normal'."""
        self.log.info("NF-1: a malformed quarantine sentinel fails CLOSED")
        chain_dir = self.chain_path(0)
        sentinel = os.path.join(chain_dir, "quarantine_state.json")
        # Start from a clean, stopped node with no recovery files lying around.
        self.stop_node(0)
        for name in ("repair_marker.json", "repair_marker.done.json",
                     "repair_marker.rejected.json", "quarantine_state.json"):
            p = os.path.join(chain_dir, name)
            if os.path.exists(p):
                os.remove(p)

        # Every malformed / ambiguous variant must come up HELD, not normal.
        for label, content in (("empty", ""),
                               ("truncated", '{"version":1,"quara'),
                               ("non-object array", "[]"),
                               ("non-object scalar", "42"),
                               ("object missing fields", "{}"),
                               ("explicit quarantined true", '{"version":1,"quarantined":true}')):
            with open(sentinel, "w", encoding="utf8") as f:
                f.write(content)
            mode = self._restart_and_read_mode(0)
            assert_equal(mode, "crippled_wait")  # fail closed for: label
            assert os.path.exists(sentinel), \
                f"a malformed sentinel ({label}) must never be cleared"

        # The ONLY parse that clears quarantine: a clean object that EXPLICITLY
        # declares a healthy (not-quarantined) state.
        with open(sentinel, "w", encoding="utf8") as f:
            f.write('{"version":1,"quarantined":false}')
        mode = self._restart_and_read_mode(0)
        assert mode in ("normal", "syncing", "degraded"), mode
        # And an ABSENT sentinel is normal.
        if os.path.exists(sentinel):
            os.remove(sentinel)
        mode = self._restart_and_read_mode(0)
        assert mode in ("normal", "syncing", "degraded"), mode
        # Leave node0 running clean for anything after.
        self.start_node(0, extra_args=self.node_args(0))

    def test_wipe_fail_closed(self):
        """NF-4 (MAJOR): a wipe that cannot remove a target must FAIL CLOSED --
        it must NOT report success, NOT clear the quarantine sentinel, NOT
        ledger a completed wipe or consume the marker, and the node must stay
        held. Realised by relocating 'blocks' under a private -blocksdir made
        read-only, so the startup wipe can neither rename nor remove it.

        Runs LAST: it deliberately leaves node0's chainstate partially wiped."""
        self.log.info("NF-4: an unremovable wipe target fails CLOSED (REPAIR_FAILED)")
        if os.name != "posix" or (hasattr(os, "geteuid") and os.geteuid() == 0):
            self.log.info("  skipped (needs non-root POSIX to make a target undeletable)")
            return
        node = self.nodes[0]
        chain_dir = self.chain_path(0)
        sentinel = os.path.join(chain_dir, "quarantine_state.json")
        marker = os.path.join(chain_dir, "repair_marker.json")
        done = os.path.join(chain_dir, "repair_marker.done.json")

        self.stop_node(0)
        for name in ("repair_marker.json", "repair_marker.done.json",
                     "repair_marker.rejected.json", "quarantine_state.json",
                     "recovery_ledger.json"):
            p = os.path.join(chain_dir, name)
            if os.path.exists(p):
                os.remove(p)

        # Relocate blocks under a private -blocksdir we can chmod read-only.
        altbd = os.path.join(node.datadir, "altblocks")
        alt_regtest = os.path.join(altbd, self.chain)
        os.makedirs(alt_regtest, exist_ok=True)
        src_blocks = os.path.join(chain_dir, "blocks")
        dst_blocks = os.path.join(alt_regtest, "blocks")
        if os.path.isdir(src_blocks) and not os.path.isdir(dst_blocks):
            os.rename(src_blocks, dst_blocks)
        os.makedirs(dst_blocks, exist_ok=True)
        bd_args = self.node_args(0) + ["-blocksdir=" + altbd]

        # A persisted quarantine sentinel (so we can prove it is RETAINED), plus
        # a freshly-armed valid full-scope marker for the startup wipe to run.
        with open(sentinel, "w", encoding="utf8") as f:
            json.dump({"version": 1, "quarantined": True, "ts": int(time.time()),
                       "finding_code": "DRIFT_EVODB", "debug_detail": "wipe-fail test"}, f)
        # armed_ts MUST be on the node's clock: the daemon runs under -mocktime,
        # so a wall-clock stamp reads as far-future and the marker is refused as
        # stale before the wipe ever runs.
        with open(marker, "w", encoding="utf8") as f:
            json.dump({"version": 1, "armed_ts": int(self.mocktime), "scope": "full",
                       "wipe_dirs": WIPED_DIRS, "wipe_files": []}, f)

        os.chmod(alt_regtest, 0o500)  # read+execute only: no rename/unlink of children
        try:
            node.start(extra_args=bd_args)
            deadline = time.time() + 60 * self.options.timeout_factor
            rpc, mode = None, None
            while time.time() < deadline:
                try:
                    rpc = self.warmup_rpc(0)
                    mode = rpc.getrecoverystatus()["daemon_mode"]
                    if mode in self._SETTLED_MODES:
                        break
                except Exception:
                    rpc = None
                time.sleep(0.25)
            assert rpc is not None and mode in self._SETTLED_MODES, \
                f"node never settled after the failed wipe (last={mode})"
            # Node stays HELD -- success was NOT reported.
            assert_equal(mode, "crippled_wait")
            # The drifted 'blocks' survived (not lied about), and no success
            # bookkeeping happened.
            assert os.path.isdir(dst_blocks), "blocks was reported wiped but is still present"
            assert not os.path.exists(done), "marker was consumed to .done despite a failed wipe"
            assert os.path.exists(marker), "marker was dropped despite a failed wipe (no retry)"
            assert os.path.exists(sentinel), "quarantine sentinel was cleared despite a failed wipe"
            ledger = self.ledger(0)
            assert_equal(ledger.get("repair_state"), "failed")
            assert_equal(len(ledger.get("wipes", [])), 0)  # no completed wipe recorded
            rpc.stop()
            node.wait_until_stopped()
        finally:
            os.chmod(alt_regtest, 0o700)

    # ---- PARK-VS-EXIT: headless nodes EXIT (non-zero) instead of parking ----

    def test_headless_exit_on_persisted_quarantine(self):
        """A headless node that boots to a quarantine sentinel from a previous
        run must EXIT non-zero with the clear diagnostic -- not silently park
        (an invisible PoSe-ban drift for a masternode). The SAME sentinel under
        a park frontend parks in crippled_wait, proving the split is purely
        frontend-driven."""
        self.log.info("PARK-VS-EXIT: headless node with a persisted quarantine sentinel EXITS non-zero")
        node = self.nodes[0]
        chain_dir = self.chain_path(0)
        self.stop_node(0)
        for name in ("repair_marker.json", "repair_marker.done.json",
                     "repair_marker.rejected.json", "quarantine_state.json"):
            p = os.path.join(chain_dir, name)
            if os.path.exists(p):
                os.remove(p)
        sentinel = os.path.join(chain_dir, "quarantine_state.json")
        with open(sentinel, "w", encoding="utf8") as f:
            json.dump({"version": 1, "quarantined": True, "ts": int(self.mocktime),
                       "finding_code": "DRIFT_EVODB", "debug_detail": "headless-exit test"}, f)

        # Headless (no -parkonfault): refuses to start, exits non-zero, and
        # prints the distinct greppable diagnostic to stderr.
        node.assert_start_raises_init_error(
            extra_args=self.node_args_no_park(0),
            expected_msg=HEADLESS_EXIT_TAG,
            match=ErrorMatch.PARTIAL_REGEX)
        # A headless/failed start never clears the sentinel.
        assert os.path.exists(sentinel), "headless exit must not clear the quarantine sentinel"

        # The identical sentinel under a park frontend (-parkonfault) parks in
        # crippled_wait instead -- same state, opposite terminal behaviour.
        mode = self._restart_and_read_mode(0)
        assert_equal(mode, "crippled_wait")
        assert os.path.exists(sentinel)

        # Clear the sentinel and return node0 to normal for the rest of the suite.
        os.remove(sentinel)
        self.start_node(0, extra_args=self.node_args(0))
        self.connect_nodes(0, 1)
        self.sync_all()

    def test_headless_exit_on_runtime_drift(self):
        """A headless RUNTIME consistency drift must take the AbortNode path --
        the node goes DOWN with a non-zero exit rather than sitting alive-and-
        quarantined. Driven through the synthetic recovery_inducedrift hook,
        which mirrors the real DisconnectBlock/ConnectBlock split."""
        self.log.info("PARK-VS-EXIT: headless runtime drift goes DOWN (AbortNode), non-zero, not parked")
        node = self.nodes[0]
        # Run node0 headless WITHOUT -parkonfault (production default). No fault
        # at startup, so it comes up normal.
        self.stop_node(0)
        self.start_node(0, extra_args=self.node_args_no_park(0))
        log_path = node.debug_log_path
        prev_size = os.path.getsize(log_path)

        # Induce a runtime drift. Headless => NoteHeadlessFaultShutdown =>
        # AbortNode => controlled shutdown with a non-zero exit.
        try:
            node.recovery_inducedrift("quarantine")
        except Exception:
            pass  # the RPC connection may drop as shutdown begins

        self.assert_exited_nonzero(0)
        with open(log_path, encoding="utf8") as f:
            f.seek(prev_size)
            tail = f.read()
        assert HEADLESS_EXIT_TAG in tail, f"missing headless-fault diagnostic in log:\n{tail}"
        # It did NOT park: no quarantine sentinel is persisted for a headless exit,
        # so a plain restart comes back clean (nothing was corrupted on disk).
        assert not os.path.exists(os.path.join(self.chain_path(0), "quarantine_state.json")), \
            "a headless runtime fault must not persist a quarantine sentinel"
        # The AbortNode path records node_abort.json so the NEXT start surfaces
        # NODE_ABORTED / ACTION_CHECK_DISK -- correct in production, but it would
        # bleed a CHECK_DISK recommendation into later cases. Clear it here so
        # the rest of the suite starts from a clean advisory state.
        abort_json = os.path.join(self.chain_path(0), "node_abort.json")
        if os.path.exists(abort_json):
            os.remove(abort_json)

        # Restore node0 (with the park arg) for the rest of the suite.
        self.start_node(0, extra_args=self.node_args(0))
        self.connect_nodes(0, 1)
        self.sync_all()

    def run_test(self):
        self.test_contract_shape()
        self.test_headless_exit_on_persisted_quarantine()
        self.test_headless_exit_on_runtime_drift()
        self.test_auto_rejoin()
        self.test_stalled_tip_no_block_action()
        self.test_marker_cannot_wipe_outside_datadir()
        self.test_disarm()
        self.test_quarantine_survives_restart()
        self.test_sentinel_fail_closed()
        self.test_quarantine_gates()
        self.test_crippled_wait_and_repair()
        self.test_wipe_rate_guard()
        self.test_wipe_fail_closed()


if __name__ == "__main__":
    RecoverySelfHealTest().main()
