#!/usr/bin/env bash
# Copyright (c) 2018-2023 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
# use testnet settings,  if you need mainnet,  use ~/.kerrigancore/kerrigand.pid file instead
export LC_ALL=C

kerrigan_pid="$(<~/.kerrigancore/testnet3/kerrigand.pid)"
sudo gdb -batch -ex "source debug.gdb" kerrigand "${kerrigan_pid}"
