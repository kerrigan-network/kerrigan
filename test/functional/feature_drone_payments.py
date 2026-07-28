#!/usr/bin/env python3
# Copyright (c) 2026 The Kerrigan developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the inference-drone coinbase payout hard fork (nDronePayoutHeight).

Once the fork is EFFECTIVE -- at/after the height floor AND with the
enable-once spork SPORK_26_DRONE_PAYOUT_ENABLED on (default OFF) -- the 40%
growth-escrow coinbase slot pays a registered, bonded, recently-alive
inference drone (round-robin by last-paid) selected from the deterministic
drone list built from TRANSACTION_DRONE_REGISTER special transactions
(CDroneRegTx extraPayload carrying the full 96-byte BLS min_sig pubkey + a
key-ownership signature; see src/evo/inference_wire.h and
IsDronePayoutEffective in src/evo/dronelist.h).
Regtest params: activation height 200, bond 100 KRGN, heartbeat max-age 20.

Spork-gate coverage: above the floor with the spork OFF, registrations stay
rejected (bad-txns-type) and coinbases pay escrow byte-identically; flipping
the spork on makes the same registration confirm and the payout switch; and
-reindex ACROSS the flip (escrow-era spork-off blocks above the floor,
then drone-era blocks) re-syncs to the same tip -- the reindex-safety
property the lockstep registration gate exists for.

Covers: activation boundary (the TX type is invalid below the fork),
wrong-payee/wrong-amount rejection (bad-cb-payee), the BLS key-ownership
proof (pkh squatting and signature replay are rejected -- review finding M2),
payload-shape consensus rejections (bad-drone-reg-*), round-robin rotation,
signed heartbeats + expiry, payout immutability, collateral-spend
deregistration, the unknown-hardware-class acceptance divergence, reorg
replay, restart/-reindex persistence, and the snapshot/forward-replay
subsystem (review finding M1): both nodes run tiny -dronesnapshotperiod
overrides (different from each other, proving the period is not consensus),
the run crosses many snapshot boundaries, and reorg/restart/-reindex are
exercised across them with full historical-list equality checks.

Modeled on feature_dip3_deterministicmns.py (hand-built coinbases +
submitblock asserting 'bad-cb-payee')."""

import struct
from decimal import Decimal

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    hash256,
    ser_compact_size,
    tx_from_hex,
)
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

DRONE_ACTIVATION_HEIGHT = 200  # regtest consensus.nDronePayoutHeight
DRONE_BOND = 100               # regtest consensus.nDroneCollateralAmount (KRGN)
DRONE_MAX_AGE = 20             # regtest consensus.nDroneMaxAge
TRANSACTION_DRONE_REGISTER = 11

DRONE_SPORK = "SPORK_26_DRONE_PAYOUT_ENABLED"
SPORK_OFF = 4070908800         # far-future sentinel = spork inactive (the default)
# Test-local spork signer, passed via -sporkaddr/-sporkkey overrides (the
# feature_multikeysporks.py pattern). NOTE: the chainparams regtest spork
# address (kSN8WQ66...) has no in-tree WIF, and the WIF the MN framework
# appends (test_framework.py, "sporkkey=cP4EK...") does NOT match it -- a
# pre-existing breakage. This address is that same WIF's key encoded with
# Kerrigan's regtest prefix (107), so the pair below is self-consistent.
SPORK_KEY = "cP4EKFyJsHT39LDqgdcB43Y3YXjNyjb5Fuas1GQSeAtjnZWmZEQK"
SPORK_ADDR = "kSz9fCAxr9NJidVS5eEZVDk4wnxSysGbPk"

# Snapshot periods deliberately DIFFER between the nodes: the snapshot layout
# is local storage, not consensus, so the two nodes must still agree on every
# historical list.
SNAPSHOT_PERIOD_NODE0 = 7
SNAPSHOT_PERIOD_NODE1 = 5

# Fixed BLS min_sig secrets (32-byte scalars; low first byte keeps them below
# the group order). A and B match the golden-vector generator keys.
SK_A = "0a4d492c4b5dc43f344df68cbbd9bafe77256e8fa48cf075b528238cb0266653"
SK_B = "0b058e9be51db61b3caac9b48c4360077baeedb813a48f896f02495fbdb34f0f"
SK_C = "0c" + "cc" * 31
SK_D = "0d" + "dd" * 31
SK_X = "0e" + "ee" * 31  # the attacker's key


class DronePaymentsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        # node1 exists so node0's getblocktemplate has a connection, to
        # cross-check consensus state on a second validator, and -- with a
        # different snapshot period -- to serve as the from-scratch oracle for
        # the snapshot/replay assertions.
        self.num_nodes = 2
        self.setup_clean_chain = True
        # -dip3params: special transactions (the registration vehicle) are
        # gated on DIP0003, which defaults to height 432 on regtest; activate
        # it from the start like mainnet (DIP0003Height = 2). v20/mn_rr must
        # activate alongside it: with HMP active from genesis a DIP3-era
        # coinbase needs CbTx version HMP_SEAL, which CheckCbTx only accepts
        # once v20 is active.
        common_args = ['-dip3params=2:2', '-testactivationheight=v20@2', '-testactivationheight=mn_rr@2',
                       '-sporkaddr=%s' % SPORK_ADDR, '-minsporkkeys=1']
        # node0 holds the matching spork key so the test can flip
        # SPORK_26_DRONE_PAYOUT_ENABLED; node1 learns it via p2p relay.
        self.extra_args = [
            common_args + ['-dronesnapshotperiod=%d' % SNAPSHOT_PERIOD_NODE0, '-sporkkey=%s' % SPORK_KEY],
            common_args + ['-dronesnapshotperiod=%d' % SNAPSHOT_PERIOD_NODE1],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    # ---- helpers ---------------------------------------------------------

    def mine(self, n):
        """Mine to a wallet address. The framework's default generate() uses
        deterministic keys with Dash-prefixed addresses, which are invalid on
        Kerrigan's regtest ('k' prefix), so mine to our own wallet instead."""
        return self.generatetoaddress(self.nodes[0], n, self.miner_addr)

    def make_drone(self, secret):
        """Key material + fresh payout address for one drone identity."""
        node = self.nodes[0]
        key = node.droneblsfromsecret(secret)
        payout_addr = node.getnewaddress()
        return {
            "secret": secret,
            "pubkey": key['public'],
            # RPC strings use uint160::ToString() (reversed); the payload
            # carries raw bytes.
            "pkh": key['pubKeyHash'],
            "pkh_raw": bytes.fromhex(key['pubKeyHash'])[::-1],
            "payout_addr": payout_addr,
            "payout_script": bytes.fromhex(node.getaddressinfo(payout_addr)['scriptPubKey']),
        }

    def ser_payload_nosig(self, pkh_raw, pubkey, iroh, hw_class, collateral_index, payout_script, inputs_hash,
                          version=1, model_tier=0):
        r = struct.pack('<H', version)
        r += pkh_raw
        r += ser_compact_size(len(pubkey)) + pubkey
        r += iroh
        r += bytes([hw_class])
        r += bytes([model_tier])
        r += struct.pack('<I', collateral_index)
        r += ser_compact_size(len(payout_script)) + payout_script
        r += inputs_hash
        return r

    def pick_inputs(self, amount_krgn):
        """Confirmed wallet UTXOs covering amount_krgn (+ fee headroom)."""
        node = self.nodes[0]
        picked, total = [], Decimal(0)
        for u in node.listunspent(1):
            if not u['spendable']:
                continue
            picked.append(u)
            total += u['amount']
            if total >= amount_krgn + 1:
                return picked, total
        raise AssertionError("wallet cannot fund %s KRGN" % amount_krgn)

    def build_drone_tx(self, drone, with_bond=True, hw_class=0x00, iroh=None, mutate_payload=None,
                       break_sig=False, sign_with=None, override_pubkey=None, override_pkh_raw=None,
                       version=1, model_tier=0):
        """Build + wallet-sign a TRANSACTION_DRONE_REGISTER special TX.
        Returns (hex, bond_outpoint_dict_or_None)."""
        node = self.nodes[0]
        fee = Decimal("0.01")
        need = Decimal(DRONE_BOND) if with_bond else Decimal(1)
        utxos, total = self.pick_inputs(need)

        tx = CTransaction()
        tx.nVersion = 3
        tx.nType = TRANSACTION_DRONE_REGISTER
        tx.vin = [CTxIn(COutPoint(int(u['txid'], 16), u['vout'])) for u in utxos]
        change_script = bytes.fromhex(node.getaddressinfo(node.getnewaddress())['scriptPubKey'])
        bond = None
        if with_bond:
            bond_addr = node.getnewaddress()
            bond_script = bytes.fromhex(node.getaddressinfo(bond_addr)['scriptPubKey'])
            tx.vout = [
                CTxOut(DRONE_BOND * COIN, CScript(bond_script)),
                CTxOut(int((total - Decimal(DRONE_BOND) - fee) * COIN), CScript(change_script)),
            ]
        else:
            tx.vout = [CTxOut(int((total - fee) * COIN), CScript(change_script))]

        inputs_hash = hash256(b''.join(i.prevout.serialize() for i in tx.vin))
        payload = self.ser_payload_nosig(
            override_pkh_raw if override_pkh_raw is not None else drone['pkh_raw'],
            bytes.fromhex(override_pubkey if override_pubkey is not None else drone['pubkey']),
            iroh if iroh is not None else bytes(32),
            hw_class, 0, drone['payout_script'], inputs_hash, version=version, model_tier=model_tier)
        if mutate_payload is not None:
            payload = mutate_payload(payload)

        msg_hash = hash256(payload)
        signer = sign_with if sign_with is not None else drone['secret']
        sig = bytes.fromhex(node.droneblssign(signer, msg_hash.hex())['signature'])
        if break_sig:
            sig = sig[:10] + bytes([sig[10] ^ 0x01]) + sig[11:]
        tx.vExtraPayload = payload + ser_compact_size(len(sig)) + sig

        signed = node.signrawtransactionwithwallet(tx.serialize().hex())
        assert signed['complete']
        if with_bond:
            txid = node.decoderawtransaction(signed['hex'])['txid']
            bond = {"txid": txid, "vout": 0}
        return signed['hex'], bond

    def send_registration(self, drone, hw_class=0x00, model_tier=0):
        """Broadcast a full registration (bond output at index 0) and lock the
        bond so the wallet cannot accidentally deregister the drone."""
        node = self.nodes[0]
        hex_tx, bond = self.build_drone_tx(drone, with_bond=True, hw_class=hw_class, model_tier=model_tier)
        txid = node.sendrawtransaction(hex_tx)
        assert_equal(txid, bond['txid'])
        node.lockunspent(False, [bond])
        drone['bond'] = bond
        return bond

    def send_heartbeat(self, drone, **kwargs):
        """Broadcast a bond-less heartbeat (payload for an already-registered
        pkh), key-authenticated by the payload's BLS signature."""
        hex_tx, _ = self.build_drone_tx(drone, with_bond=False, **kwargs)
        return self.nodes[0].sendrawtransaction(hex_tx)

    def spend_bond(self, drone):
        node = self.nodes[0]
        node.lockunspent(True, [drone['bond']])
        spend = node.createrawtransaction(
            [drone['bond']],
            [{node.getnewaddress(): DRONE_BOND - Decimal("0.001")}])
        spend = node.signrawtransactionwithwallet(spend)['hex']
        return node.sendrawtransaction(spend)

    def build_block(self, slot_script=None, slot_amount_delta=0):
        """Hand-build a block from the current template, optionally mutating
        the 40% slot (bt['masternode'][0]). Requires an empty mempool so the
        template's amounts equal the daemon's fee-inclusive recomputation."""
        node = self.nodes[0]
        assert_equal(node.getmempoolinfo()['size'], 0)
        bt = node.getblocktemplate()
        entries = [[e['script'], e['amount']] for e in bt['masternode']]
        if slot_script is not None:
            entries[0][0] = slot_script
        entries[0][1] += slot_amount_delta
        miner_amount = bt['coinbasevalue'] - sum(a for _, a in entries)

        coinbase = CTransaction()
        coinbase.vin = create_coinbase(bt['height']).vin
        coinbase.vout = [CTxOut(int(miner_amount), CScript(bytes.fromhex('51')))]  # OP_TRUE
        for script, amount in entries:
            coinbase.vout.append(CTxOut(int(amount), CScript(bytes.fromhex(script))))
        if len(bt['coinbase_payload']) != 0:
            # Reuse the template's CbTx payload byte-for-byte: it is built by
            # the daemon for exactly this next block, and none of its fields
            # (MN/quorum merkle roots, credit pool, chainlock, HMP seal)
            # depend on the coinbase outputs we are mutating. The python
            # CCbTx class cannot round-trip v4 (HMP_SEAL) payloads.
            coinbase.nVersion = 3
            coinbase.nType = 5  # CbTx
            coinbase.vExtraPayload = bytes.fromhex(bt['coinbase_payload'])
        coinbase.calc_sha256()

        block = create_block(coinbase=coinbase, tmpl=bt)
        # include any required quorum commitments from the template
        for tx in bt['transactions']:
            tx2 = tx_from_hex(tx['data'])
            if tx2.nType == 6:
                block.vtx.append(tx2)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        return block

    def submit_block(self, expected_error=None, **kwargs):
        block = self.build_block(**kwargs)
        result = self.nodes[0].submitblock(block.serialize().hex())
        if expected_error is not None and result != expected_error:
            raise AssertionError('submitblock should have failed with %s but returned %s' % (expected_error, result))
        elif expected_error is None and result is not None:
            raise AssertionError('submitblock returned %s' % result)

    def drone_slot(self):
        """The 40% slot of the current template: (script_hex, amount)."""
        bt = self.nodes[0].getblocktemplate()
        return bt['masternode'][0]['script'], bt['masternode'][0]['amount']

    def dronelist(self, node_idx=0, height=None):
        node = self.nodes[node_idx]
        return node.getdronelist() if height is None else node.getdronelist(height)

    def drone_entry(self, drone, node_idx=0):
        for d in self.dronelist(node_idx)['drones']:
            if d['blsPubKeyHash'] == drone['pkh']:
                return d
        return None

    def spork26(self, node_idx):
        return self.nodes[node_idx].spork('show')[DRONE_SPORK]

    def assert_spork26_all(self, value):
        for i in range(self.num_nodes):
            assert_equal(self.spork26(i), value)

    def assert_next_coinbase_pays(self, script_bytes):
        script_hex = script_bytes.hex()
        slot_script, slot_amount = self.drone_slot()
        assert_equal(slot_script, script_hex)
        self.mine(1)
        node = self.nodes[0]
        block = node.getblock(node.getbestblockhash(), 2)
        paid = [(o['scriptPubKey']['hex'], int(o['valueSat'])) for o in block['tx'][0]['vout']]
        assert (script_hex, slot_amount) in paid, "coinbase did not pay the expected drone slot"

    # ---- test ------------------------------------------------------------

    def run_test(self):
        node = self.nodes[0]

        self.log.info("mine to maturity, well below the activation height")
        self.miner_addr = node.getnewaddress()
        self.mine(120)
        assert node.getblockcount() < DRONE_ACTIVATION_HEIGHT

        drone_a = self.make_drone(SK_A)
        drone_b = self.make_drone(SK_B)
        drone_c = self.make_drone(SK_C)
        drone_d = self.make_drone(SK_D)
        attacker = self.make_drone(SK_X)

        self.log.info("pre-activation: escrow slot, drone_payout_active=false")
        escrow_script, _ = self.drone_slot()
        assert_equal(node.getblocksubsidy()['drone_payout_active'], False)

        self.log.info("below the fork the registration TX type itself is invalid")
        # 'bad-txns-type': the type stays outside the version-3 whitelist
        # until the fork, byte-identical to what pre-fork nodes reject with.
        hex_tx, _ = self.build_drone_tx(drone_a, with_bond=True)
        assert_raises_rpc_error(-26, "bad-txns-type", node.sendrawtransaction, hex_tx)

        self.log.info("cross the activation height floor -- spork still OFF (the default)")
        self.mine(DRONE_ACTIVATION_HEIGHT - node.getblockcount())
        assert_equal(node.getblockcount(), DRONE_ACTIVATION_HEIGHT)
        self.assert_spork26_all(SPORK_OFF)
        # The fork is NOT effective: past the floor but the enable-once spork
        # is off, so the payout rule (and the TX type) stay pre-fork.
        assert_equal(node.getblocksubsidy()['drone_payout_active'], False)
        dl = self.dronelist()
        assert_equal(dl['drone_payout_active'], False)
        assert_equal(dl['count'], 0)

        self.log.info("T1: spork off above the floor: registration still rejected (bad-txns-type)")
        hex_tx, _ = self.build_drone_tx(drone_a, with_bond=True)
        assert_raises_rpc_error(-26, "bad-txns-type", node.sendrawtransaction, hex_tx)

        self.log.info("T1: spork off above the floor: slot byte-identical to pre-fork escrow")
        slot_script, _ = self.drone_slot()
        assert_equal(slot_script, escrow_script)

        self.log.info("spork off: paying the 40% slot elsewhere is still bad-cb-payee")
        random_script = node.decoderawtransaction(node.createrawtransaction(
            [], [{node.getnewaddress(): 1}]))['vout'][0]['scriptPubKey']['hex']
        self.submit_block(slot_script=random_script, expected_error='bad-cb-payee')
        self.submit_block(slot_amount_delta=-1, expected_error='bad-cb-payee')
        self.submit_block()  # unmutated template block connects fine

        self.log.info("mine an escrow-era span ABOVE the floor with the spork off "
                      "(the blocks the T3 reindex must re-validate once the spork is on)")
        for _ in range(4):
            slot_script, _ = self.drone_slot()
            assert_equal(slot_script, escrow_script)
            self.mine(1)
        spork_flip_height = node.getblockcount()
        assert spork_flip_height > DRONE_ACTIVATION_HEIGHT

        self.log.info("T2: flip %s on (enable-once cutover; one-way once registrations confirm)" % DRONE_SPORK)
        node.sporkupdate(DRONE_SPORK, 0)
        self.wait_until(lambda: all(self.spork26(i) == 0 for i in range(self.num_nodes)))
        assert_equal(node.getblocksubsidy()['drone_payout_active'], True)
        assert_equal(self.dronelist()['drone_payout_active'], True)

        self.log.info("T4: spork on + zero eligible drones: slot still byte-identical escrow")
        slot_script, _ = self.drone_slot()
        assert_equal(slot_script, escrow_script)
        self.submit_block(slot_script=random_script, expected_error='bad-cb-payee')
        self.submit_block()  # escrow-paying template still connects

        self.log.info("the BLS key-ownership proof gates registration (review M2)")
        # Squat attempt 1: bind B's pkh to the attacker's pubkey (+ attacker's
        # valid signature over the payload) -- the commitment check kills it.
        hex_tx, _ = self.build_drone_tx(attacker, with_bond=True,
                                        override_pkh_raw=drone_b['pkh_raw'])
        assert_raises_rpc_error(-26, "bad-drone-reg-pubkey-hash", node.sendrawtransaction, hex_tx)
        # Squat attempt 2: B's pkh AND pubkey, but the attacker cannot sign
        # for B's key.
        hex_tx, _ = self.build_drone_tx(drone_b, with_bond=True, sign_with=attacker['secret'])
        assert_raises_rpc_error(-26, "bad-drone-reg-sig", node.sendrawtransaction, hex_tx)
        # A corrupted signature is rejected too.
        hex_tx, _ = self.build_drone_tx(drone_b, with_bond=True, break_sig=True)
        assert_raises_rpc_error(-26, "bad-drone-reg-sig", node.sendrawtransaction, hex_tx)

        self.log.info("payload-shape consensus rejections")
        # Unknown payload version.
        hex_tx, _ = self.build_drone_tx(drone_b, with_bond=True, version=2)
        assert_raises_rpc_error(-26, "bad-drone-reg", node.sendrawtransaction, hex_tx)
        # Truncated payload.
        hex_tx, _ = self.build_drone_tx(drone_b, with_bond=True,
                                        mutate_payload=lambda p: p[:-1])
        assert_raises_rpc_error(-26, "bad-drone-reg", node.sendrawtransaction, hex_tx)
        # No bond output at the collateral index (bond-less TX for a fresh pkh).
        hex_tx, _ = self.build_drone_tx(drone_b, with_bond=False)
        assert_raises_rpc_error(-26, "bad-drone-reg-collateral", node.sendrawtransaction, hex_tx)
        # Stale inputsHash (payload signed for different inputs = replay).
        hex_tx, _ = self.build_drone_tx(drone_b, with_bond=True,
                                        mutate_payload=lambda p: p[:-32] + bytes(32))
        assert_raises_rpc_error(-26, "bad-drone-reg-inputs-hash", node.sendrawtransaction, hex_tx)
        # Out-of-range model tier (> 3) -- rejected even with a valid
        # signature, so stored list state stays canonical 0..3.
        hex_tx, _ = self.build_drone_tx(drone_b, with_bond=True, model_tier=4)
        assert_raises_rpc_error(-26, "bad-drone-reg-tier", node.sendrawtransaction, hex_tx)
        hex_tx, _ = self.build_drone_tx(drone_b, with_bond=True, model_tier=0xFF)
        assert_raises_rpc_error(-26, "bad-drone-reg-tier", node.sendrawtransaction, hex_tx)

        self.log.info("T2: with the spork on, the registration confirms and the very next block MUST pay drone A")
        self.send_registration(drone_a)
        self.mine(1)  # confirm the registration
        height_a = node.getblockcount()
        entry_a = self.drone_entry(drone_a)
        assert entry_a is not None
        assert_equal(entry_a['registeredHeight'], height_a)
        assert_equal(entry_a['eligible'], True)
        assert_equal(entry_a['payoutScript'], drone_a['payout_script'].hex())
        assert_equal(entry_a['collateralHash'], drone_a['bond']['txid'])
        assert_equal(entry_a['collateralIndex'], drone_a['bond']['vout'])

        self.log.info("paying escrow instead of drone A is now bad-cb-payee")
        self.submit_block(slot_script=escrow_script, expected_error='bad-cb-payee')
        self.submit_block(slot_script=drone_a['payout_script'].hex(), slot_amount_delta=1,
                          expected_error='bad-cb-payee')
        self.assert_next_coinbase_pays(drone_a['payout_script'])

        self.log.info("register drone B: strict A/B round-robin by last-paid")
        self.send_registration(drone_b)
        self.mine(1)
        assert_equal(self.dronelist()['count'], 2)
        last_a = self.drone_entry(drone_a)['lastPaidHeight']
        last_b = self.drone_entry(drone_b)['lastPaidHeight']
        assert last_a > 0 and last_b == 0
        for _ in range(4):
            projected = self.dronelist()['projected_payees'][0]
            expected = drone_b if projected == drone_b['pkh'] else drone_a
            self.assert_next_coinbase_pays(expected['payout_script'])
        assert self.drone_entry(drone_a)['lastPaidHeight'] > 0
        assert self.drone_entry(drone_b)['lastPaidHeight'] > 0
        assert self.drone_entry(drone_a)['lastPaidHeight'] != self.drone_entry(drone_b)['lastPaidHeight']

        self.log.info("a signed heartbeat carrying different payout/hardware rebinds NOTHING (immutability)")
        before = self.drone_entry(drone_a)
        rebind = dict(drone_a)
        rebind['payout_script'] = attacker['payout_script']  # rebind attempt, correctly signed by A
        self.send_heartbeat(rebind, hw_class=0x05)
        self.mine(1)
        after = self.drone_entry(drone_a)
        assert_equal(after['payoutScript'], before['payoutScript'])
        assert_equal(after['collateralHash'], before['collateralHash'])
        assert_equal(after['hardwareClass'], before['hardwareClass'])
        assert_equal(after['lastSeenHeight'], node.getblockcount())  # heartbeat still counts

        self.log.info("heartbeat expiry: B keeps heartbeating, A goes stale and drops out of rotation")
        self.send_heartbeat(drone_b)
        self.mine(1)
        hb_b_height = node.getblockcount()
        assert_equal(self.drone_entry(drone_b)['lastSeenHeight'], hb_b_height)
        # Mine until A's last-seen is older than the max age, refreshing B
        # part-way so only A expires.
        a_last_seen = self.drone_entry(drone_a)['lastSeenHeight']
        while node.getblockcount() <= a_last_seen + DRONE_MAX_AGE:
            if node.getblockcount() == a_last_seen + DRONE_MAX_AGE - 5:
                self.send_heartbeat(drone_b)  # mined into the next block
            self.mine(1)
        assert_equal(self.drone_entry(drone_a)['eligible'], False)
        assert_equal(self.drone_entry(drone_b)['eligible'], True)
        assert_equal(self.dronelist()['count'], 2)  # expiry != removal

        self.log.info("stale A gets no payments; every block pays B")
        self.assert_next_coinbase_pays(drone_b['payout_script'])
        self.assert_next_coinbase_pays(drone_b['payout_script'])

        self.log.info("a heartbeat without A's key cannot revive A")
        hex_tx, _ = self.build_drone_tx(drone_a, with_bond=False, sign_with=attacker['secret'])
        assert_raises_rpc_error(-26, "bad-drone-reg-sig", node.sendrawtransaction, hex_tx)
        assert_equal(self.drone_entry(drone_a)['eligible'], False)

        self.log.info("a properly signed heartbeat revives A")
        self.send_heartbeat(drone_a)
        self.mine(1)
        entry_a = self.drone_entry(drone_a)
        assert_equal(entry_a['lastSeenHeight'], node.getblockcount())
        assert_equal(entry_a['eligible'], True)
        assert_equal(self.dronelist()['projected_payees'][0], drone_a['pkh'])
        self.assert_next_coinbase_pays(drone_a['payout_script'])

        self.log.info("unknown hardware class is accepted and stored raw; model tier is stored canonically")
        self.send_registration(drone_c, hw_class=0x2A, model_tier=3)
        self.mine(1)
        entry_c = self.drone_entry(drone_c)
        assert entry_c is not None
        assert_equal(entry_c['hardwareClass'], 0x2A)
        assert_equal(entry_c['modelTier'], 3)  # frontier tier, stored from the payload
        assert_equal(self.drone_entry(drone_a)['modelTier'], 0)  # default tier

        self.log.info("spending the bond deregisters the drone")
        count_before = self.dronelist()['count']
        self.spend_bond(drone_c)
        self.mine(1)
        assert self.drone_entry(drone_c) is None
        assert_equal(self.dronelist()['count'], count_before - 1)

        self.log.info("reorg replay: invalidate across a registration + paid blocks, then reconnect")
        self.send_registration(drone_d)
        self.mine(3)  # D's registration + two payout blocks
        assert self.drone_entry(drone_d) is not None
        tip = node.getbestblockhash()
        recorded_tip_list = node.getdronelist()
        rewind_to = node.getblockcount() - 4
        recorded_old_list = node.getdronelist(rewind_to)
        invalidated_hash = node.getblockhash(rewind_to + 1)
        node.invalidateblock(invalidated_hash)
        assert_equal(node.getblockcount(), rewind_to)
        assert_equal(node.getdronelist(), recorded_old_list)
        assert self.drone_entry(drone_d) is None
        node.reconsiderblock(invalidated_hash)
        assert_equal(node.getbestblockhash(), tip)
        assert_equal(node.getdronelist(), recorded_tip_list)
        assert self.drone_entry(drone_d) is not None
        self.sync_blocks()

        self.log.info("both nodes agree on the drone list")
        assert_equal(self.nodes[0].getdronelist(), self.nodes[1].getdronelist())

        # ---- snapshot / forward-replay subsystem (review finding M1) ------

        def assert_history_matches(reference, node_idx=0, what=""):
            for h, lst in reference.items():
                assert_equal(self.nodes[node_idx].getdronelist(h), lst)
            self.log.info("  history matches%s (%d heights)" % (what, len(reference)))

        tip_height = node.getblockcount()
        n_snaps0 = len([h for h in range(DRONE_ACTIVATION_HEIGHT, tip_height + 1)
                        if h % SNAPSHOT_PERIOD_NODE0 == 0])
        self.log.info("snapshot coverage: tip=%d, node0 crossed %d snapshot boundaries (period %d)"
                      % (tip_height, n_snaps0, SNAPSHOT_PERIOD_NODE0))
        assert n_snaps0 >= 2

        self.log.info("record the full post-fork list history from both nodes")
        history = {}
        for h in range(DRONE_ACTIVATION_HEIGHT - 2, tip_height + 1):
            l0 = self.nodes[0].getdronelist(h)
            l1 = self.nodes[1].getdronelist(h)
            # different snapshot periods, identical consensus state
            assert_equal(l0, l1)
            history[h] = l0

        self.log.info("reorg that rewinds THROUGH a snapshot height")
        snap_h = (tip_height - 2) - ((tip_height - 2) % SNAPSHOT_PERIOD_NODE0)
        assert snap_h > DRONE_ACTIVATION_HEIGHT
        rewind_target = snap_h - 2  # strictly below the snapshot height
        inv_hash = node.getblockhash(rewind_target + 1)
        node.invalidateblock(inv_hash)
        assert_equal(node.getblockcount(), rewind_target)
        for h in range(DRONE_ACTIVATION_HEIGHT - 2, rewind_target + 1):
            assert_equal(node.getdronelist(h), history[h])
        node.reconsiderblock(inv_hash)
        assert_equal(node.getblockcount(), tip_height)
        assert_history_matches(history, what=" after reorg through snapshot height %d" % snap_h)

        self.log.info("plain restart: caches are empty, every historical query walks snapshot+diffs")
        self.restart_node(0, extra_args=self.extra_args[0])
        self.connect_nodes(0, 1)
        # the flipped spork survives the restart via sporks.dat
        assert_equal(self.spork26(0), 0)
        assert_history_matches(history, what=" after restart")
        assert_equal(self.nodes[0].getdronelist(), self.nodes[1].getdronelist())

        self.log.info("T3 (the key reindex-safety test): -reindex ACROSS the spork flip. "
                      "Escrow-era spork-off blocks above the floor (%d..%d) must re-validate "
                      "with the spork now ON -- possible only because no registration ever "
                      "confirmed while the spork was off, so the drone list is empty there "
                      "and the payout branch falls back to byte-identical escrow."
                      % (DRONE_ACTIVATION_HEIGHT, spork_flip_height))
        self.restart_node(0, extra_args=self.extra_args[0] + ['-reindex'])
        self.wait_until(lambda: self.nodes[0].getblockcount() == tip_height)
        # the spork was already ON (loaded from sporks.dat) while the reindex
        # re-validated the whole chain, including the spork-off escrow era
        assert_equal(self.spork26(0), 0)
        assert_equal(self.nodes[0].getbestblockhash(), self.nodes[1].getbestblockhash())
        self.connect_nodes(0, 1)
        assert_history_matches(history, what=" after -reindex")

        self.log.info("post-rebuild payee selection still matches the second validator")
        assert_equal(self.nodes[0].getdronelist()['projected_payees'],
                     self.nodes[1].getdronelist()['projected_payees'])
        self.mine(1)  # a template built from the rebuilt list connects fine
        self.sync_blocks()
        assert_equal(self.nodes[0].getdronelist(), self.nodes[1].getdronelist())


if __name__ == '__main__':
    DronePaymentsTest().main()
