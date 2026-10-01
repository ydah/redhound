#!/usr/bin/env bash
# テスト用ネットワーク: ホスト側 rh0 (10.99.0.1) <-> 名前空間 rh-peer 側 rh1 (10.99.0.2)
set -euo pipefail
ip netns add rh-peer
ip link add rh0 type veth peer name rh1
ip link set rh1 netns rh-peer
ip addr add 10.99.0.1/24 dev rh0
ip -6 addr add fd00:99::1/64 dev rh0 nodad 2>/dev/null || true
ip link set rh0 up
ip netns exec rh-peer ip addr add 10.99.0.2/24 dev rh1
ip netns exec rh-peer ip -6 addr add fd00:99::2/64 dev rh1 nodad 2>/dev/null || true
ip netns exec rh-peer ip link set rh1 up
ip netns exec rh-peer ip link set lo up
# VLAN 100 のサブインターフェース（8021q モジュールが無い環境ではスキップ）
if ! ip link add link rh0 name rh0.100 type vlan id 100 2>/dev/null; then
  echo "skip VLAN (try: modprobe 8021q)"
  echo "ready: rh0 <-> rh-peer:rh1"
  exit 0
fi
ip addr add 10.99.100.1/24 dev rh0.100
ip link set rh0.100 up
ip netns exec rh-peer ip link add link rh1 name rh1.100 type vlan id 100
ip netns exec rh-peer ip addr add 10.99.100.2/24 dev rh1.100
ip netns exec rh-peer ip link set rh1.100 up
echo "ready: rh0 <-> rh-peer:rh1 (VLAN 100: rh0.100 <-> rh1.100)"
