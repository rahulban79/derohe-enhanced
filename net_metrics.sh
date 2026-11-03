#!/usr/bin/env bash
# net_metrics.sh — scrape derod /metrics for miniblock-propagation + peer evidence.
# Usage: ./net_metrics.sh [metrics_url] [label]
#   metrics_url  default http://127.0.0.1:10102/metrics  (derod --rpc-bind)
# Emits: peer counts, propagation histogram (VictoriaMetrics vmrange buckets),
#        count/sum/avg and approximate p50/p90 (bucket-upper-bound estimate).
# Evidence class: [E:OBS] — literal scrape of the live daemon.
set -euo pipefail
URL="${1:-http://127.0.0.1:10102/metrics}"
LABEL="${2:-}"
TS="$(date '+%Y-%m-%d %H:%M:%S %Z')"

RAW="$(curl -s --max-time 6 "$URL" || true)"
if [ -z "$RAW" ]; then
  echo "[$TS] $LABEL  ERROR: no data from $URL (is derod up? correct --rpc-bind port?)"
  exit 1
fi

echo "=================================================================="
echo "[$TS] net_metrics  ${LABEL:+<$LABEL>}  src=$URL"
echo "------------------------------------------------------------------"
# --- peers ---
printf '%s\n' "$RAW" | awk '
  /^p2p_peer_count /          {pc=$2}
  /^p2p_peer_incoming_count / {pin=$2}
  /^p2p_peer_outgoing_count / {pout=$2}
  END{ printf "peers: total=%s  in=%s  out=%s\n", pc+0, pin+0, pout+0 }'

# --- miniblock propagation histogram (seconds) ---
printf '%s\n' "$RAW" | awk '
  BEGIN{ cnt=0; sum=0 }
  /^miniblock_propagation_duration_histogram_seconds_count/ { cnt=$2 }
  /^miniblock_propagation_duration_histogram_seconds_sum/   { sum=$2 }
  /^miniblock_propagation_duration_histogram_seconds_bucket/ {
      # extract vmrange upper bound "lo...hi" (POSIX 2-arg match + split — portable to BSD awk)
      ub=0;
      if (match($0, /vmrange="[^"]*"/)) {
          vr=substr($0, RSTART, RLENGTH);      # vmrange="lo...hi"
          sub(/vmrange="/, "", vr); sub(/"$/, "", vr); sub(/"/, "", vr);   # lo...hi
          split(vr, parts, /\.\.\./);          # parts[1]=lo parts[2]=hi
          ub=parts[2]+0;
      }
      c=$2+0;
      n++; ub_arr[n]=ub; c_arr[n]=c; tot+=c;
  }
  END{
    if (cnt+0==0) { print "propagation: NO SAMPLES yet (node must receive miniblocks from peers with a Sent stamp)"; exit }
    printf "propagation: count=%d  sum=%.4fs  avg=%.4fs (%.1f ms)\n", cnt, sum, sum/cnt, 1000*sum/cnt;
    # approximate percentiles from cumulative bucket counts (upper-bound estimate)
    # sort buckets by upper bound
    for(i=1;i<=n;i++) for(j=i+1;j<=n;j++) if(ub_arr[j]<ub_arr[i]){t=ub_arr[i];ub_arr[i]=ub_arr[j];ub_arr[j]=t; t=c_arr[i];c_arr[i]=c_arr[j];c_arr[j]=t;}
    p50=-1; p90=-1; run=0;
    for(i=1;i<=n;i++){ run+=c_arr[i];
      if(p50<0 && run>=0.50*tot) p50=ub_arr[i];
      if(p90<0 && run>=0.90*tot) p90=ub_arr[i];
    }
    printf "propagation: ~p50<=%.1f ms   ~p90<=%.1f ms   (bucket-upper-bound est, buckets=%d)\n", 1000*p50, 1000*p90, n;
    print "buckets (upper_bound_ms : count):"
    for(i=1;i<=n;i++) if(c_arr[i]>0) printf "   <=%8.1f ms : %d\n", 1000*ub_arr[i], c_arr[i];
  }'
echo "=================================================================="
