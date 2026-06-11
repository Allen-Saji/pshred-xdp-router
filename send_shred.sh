#!/usr/bin/env bash
# Send pshred UDP packet(s) to exercise the XDP demultiplexer.
#
# Wire layout (little-endian, 158-byte fixed header) matches
# pshred_router_common::PshredHeader / Constellation Definition 3:
#   u64 epoch@0  u64 cycle@8  u16 proposer@16  u64 pslice@18
#   u32 shred@26  32B commitment@30  32B merkle@62  64B sig@94
#
# Usage:
#   ./send_shred.sh <dest_ip> <proposer> [count] [--bad-eq1]
#     dest_ip   : destination (e.g. 10.0.0.2 for the veth lab)
#     proposer  : proposer index j (1..16 -> redirected; 0 or >16 -> range_drop)
#     count     : packets to send (default 1)
#     --bad-eq1 : send a pslice index that violates Equation (1) -> eq1_drop

set -euo pipefail

DEST="${1:?usage: send_shred.sh <dest_ip> <proposer> [count] [--bad-eq1]}"
PROPOSER="${2:?missing proposer index}"
COUNT="${3:-1}"
MODE="${4:-}"
PORT="${PSHRED_PORT:-9000}"

python3 - "$DEST" "$PROPOSER" "$COUNT" "$PORT" "$MODE" <<'PYEOF'
import socket, struct, sys, time

dest, proposer, count, port, mode = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]

# Real cycle index = unix_nanos / 50_000_000 (Constellation 3.2). pslice t must
# satisfy (c-1)*4 < t <= c*4; t = c*4 is the valid upper bound.
cycle = time.time_ns() // 50_000_000
pslice = cycle * 4
if mode == "--bad-eq1":
    pslice = (cycle - 1) * 4  # equals lower bound -> violates strict (c-1)*4 < t

epoch, shred = 731, 1
head = struct.pack('<QQHQI', epoch, cycle, proposer, pslice, shred)  # 30 bytes
pkt = head + b'\x00' * 32 + b'\x00' * 32 + b'\x00' * 64               # +128 = 158
assert len(pkt) == 158, len(pkt)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(count):
    s.sendto(pkt, (dest, port))
s.close()
print(f"sent {count} pshred(s) to {dest}:{port} | proposer={proposer} cycle={cycle} pslice={pslice}"
      + (" [eq1-violating]" if mode == '--bad-eq1' else ""))
PYEOF
