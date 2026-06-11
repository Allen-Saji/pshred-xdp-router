#!/usr/bin/env bash
# Set up / tear down a veth + netns lab for the pshred XDP demultiplexer.
#
# Topology:
#   root ns                 pshred ns
#   veth0 (10.0.0.1/24) <==> veth1 (10.0.0.2/24)  <- attach XDP here
#
# Packets sent from the root ns to 10.0.0.2:9000 leave via veth0 and arrive as
# ingress on veth1, where the XDP program runs. veth supports generic (SKB) XDP
# and AF_XDP copy mode, so no special NIC is needed.
#
# Usage:
#   sudo ./scripts/veth.sh up
#   sudo ./scripts/veth.sh down
#
# Then, in two shells:
#   sudo ip netns exec pshred ./target/debug/pshred_router -i veth1
#   ./send_shred.sh 10.0.0.2 3 1000

set -euo pipefail

NS=pshred
A=veth0
B=veth1

case "${1:-}" in
  up)
    ip netns add "$NS" 2>/dev/null || true
    ip link add "$A" type veth peer name "$B"
    ip link set "$B" netns "$NS"
    ip addr add 10.0.0.1/24 dev "$A"
    ip link set "$A" up
    ip netns exec "$NS" ip addr add 10.0.0.2/24 dev "$B"
    ip netns exec "$NS" ip link set "$B" up
    ip netns exec "$NS" ip link set lo up
    echo "up: $A (root, 10.0.0.1) <-> $B (netns $NS, 10.0.0.2)"
    echo "loader: sudo ip netns exec $NS \$PWD/target/debug/pshred_router -i $B"
    echo "sender: ./send_shred.sh 10.0.0.2 <proposer> <count>"
    ;;
  down)
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$A" 2>/dev/null || true
    echo "down: removed netns $NS and $A/$B"
    ;;
  *)
    echo "usage: sudo $0 {up|down}" >&2
    exit 1
    ;;
esac
