#!/usr/bin/env bash
# run_derod_lowlatency.sh — start the upgraded derod with the low-latency KCP transport
# profile (fast 10ms flush + fast-retransmit) for faster miniblock propagation.
#
# Run it in YOUR terminal (stop the currently-running derod first with Ctrl-C in its window).
# The blockchain DB in $HOME/dero-data is already synced, so restart catch-up is quick.
# Verify at startup you see:  "P2P KCP profile: LOW-LATENCY (10ms flush + fast-retransmit ...)"
#
# --------------------------------------------------------------------------------------------
# INBOUND PEERS (deep-dive finding: KCP_PassiveOpens=0 forever => inbound has NEVER worked; you sit
# at 2 outbound peers because outbound peer supply is genuinely exhausted). --p2p-bind pins a FIXED
# UDP port so peers can dial you. To actually accept inbound you must ALSO forward UDP 11011 on your
# router to this mining machine's LAN IP. Verify it worked:  the dashboard/GetInfo show
# incoming_connections_count>0 and KCP_PassiveOpens>0 within ~1h. If still 0, the router forward failed.
#
# LAN NODE (reliability): if a second machine also runs derod, add it here as a PRIORITY node (NOT exclusive —
# --add-exclusive-node would DISABLE all WAN gossip). Reciprocally add THIS machine on the second machine.
#   e.g.  --add-priority-node=<second-machine-LAN-IP>:11011
# --------------------------------------------------------------------------------------------
exec ./bin/derod \
  --data-dir=$HOME/dero-data \
  --getwork-bind=127.0.0.1:10100 --rpc-bind=127.0.0.1:10102 \
  --p2p-bind=0.0.0.0:11011 \
  --integrator-address=YOUR_DERO_ADDRESS \
  --fastsync --min-peers=40 --node-tag=my-node \
  --lowlatency \
  --add-priority-node=<peer-ip>:11011 \
  --add-priority-node=<peer-ip>:11011 \
  --add-priority-node=<peer-ip>:11011 \
  --add-priority-node=<peer-ip>:11011
  # ^ seed list refreshed for Release151/152 (2026-08-19): <peer-ip> / <peer-ip> /
  #   <peer-ip> were dropped upstream (config/seed_nodes.go); <peer-ip> + <peer-ip> remain.
  # --add-priority-node=<second-machine-LAN-IP>:11011   # uncomment if the second machine runs derod
