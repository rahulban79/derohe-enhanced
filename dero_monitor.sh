#!/usr/bin/env bash
# dero_monitor.sh — evidence-based DERO node + mining monitor for the M1 Ultra setup.
# Polls the LAN derod's DERO.GetInfo (chain/height/difficulty/NW-hashrate/peers/mempool)
# and shows reachability of the getwork port. No external deps beyond curl + python3.
#
# Usage:
#   ./dero_monitor.sh [NODE_IP] [RPC_PORT] [GETWORK_PORT] [INTERVAL_SECS]
# Defaults: NODE_IP=<lan-ip>, RPC_PORT=10102, GETWORK_PORT=10100, INTERVAL=10
set -uo pipefail

NODE_IP="${1:-127.0.0.1}"
RPC_PORT="${2:-10102}"
GETWORK_PORT="${3:-10100}"
INTERVAL="${4:-10}"

rpc() {
  curl -s --max-time 4 "http://${NODE_IP}:${RPC_PORT}/json_rpc" \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"DERO.GetInfo\"}" 2>/dev/null
}

echo "DERO monitor → node ${NODE_IP}  RPC:${RPC_PORT}  getwork:${GETWORK_PORT}  every ${INTERVAL}s"
echo "(RPC must be started with --rpc-bind=0.0.0.0:${RPC_PORT}; getwork binds 0.0.0.0:${GETWORK_PORT} by default)"
printf '%-20s %-8s %-10s %-14s %-8s %-6s %-9s\n' "time" "height" "topo" "difficulty" "NW-H/s" "peers" "getwork"
while true; do
  gw="down"
  nc -z -G 1 "${NODE_IP}" "${GETWORK_PORT}" 2>/dev/null && gw="UP"
  json="$(rpc)"
  if [ -n "${json}" ]; then
    echo "${json}" | python3 -c '
import sys, json, datetime
try:
    r = json.load(sys.stdin).get("result", {})
except Exception:
    print("  (RPC returned non-JSON — is DERO.GetInfo exposed on this port?)"); sys.exit(0)
now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
h  = r.get("height", "?")
tp = r.get("topoheight", "?")
df = r.get("difficulty", "?")
hr = r.get("averageblocktime50","?")
nw = r.get("difficulty", 0)
try:
    # NW hashrate ~= difficulty / block_time(18s)
    nwh = f"{(int(nw)/18)/1e6:.3f}M" if nw else "?"
except Exception:
    nwh = "?"
pc = (r.get("incoming_connections_count",0) or 0) + (r.get("outgoing_connections_count",0) or 0)
mp = r.get("tx_pool_size","?")
import os
gw = os.environ.get("GW","?")
print(f"{now:<20} {str(h):<8} {str(tp):<10} {str(df):<14} {nwh:<8} {str(pc):<6} {gw:<9} mempool={mp}")
' GW="${gw}"
  else
    printf '%-20s  RPC unreachable at %s:%s  (getwork=%s) — start derod with --rpc-bind=0.0.0.0:%s\n' \
      "$(date '+%Y-%m-%d %H:%M:%S')" "${NODE_IP}" "${RPC_PORT}" "${gw}" "${RPC_PORT}"
  fi
  sleep "${INTERVAL}"
done
