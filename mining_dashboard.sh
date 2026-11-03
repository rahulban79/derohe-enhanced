#!/usr/bin/env bash
# mining_dashboard.sh — one-view "monitor everything" for a DERO HE solo miner.
# Sources (all read-only, consensus-safe):
#   * derod /metrics        (KCP health, inbound propagation histograms, peer counts)  metrics/metrics.go
#   * derod DERO.GetInfo     (sync, peers, hashrate_1hr, node-accepted minis)           rpc_dero_getinfo.go
#   * derod DERO.GetBlock    (miners[] per canonical block = GROUND-TRUTH paid share)   rpc_dero_getblock.go:68
#   * dero-miner.log         (raw CPU/GPU H/s + found_CPU/GPU, no metrics endpoint)     cmd/dero-miner/miner.go:147
# Deps: bash + curl + python3 (stdlib only).  Everything delta-based where the daemon counter is cumulative.
#
# Usage: ./mining_dashboard.sh [RPC_HOSTPORT] [INTERVAL] [WINDOW_BLOCKS] [MINER_LOG]
set -uo pipefail
RPC="${1:-127.0.0.1:10102}"
INTERVAL="${2:-10}"
WINDOW="${3:-720}"                 # canonical blocks to average realized reward over (~3.6h @18s)
MINER_LOG="${4:-./dero-miner.log}"
OUR_ADDR="${OUR_ADDR:-YOUR_DERO_ADDRESS}"
# alert thresholds
PEER_MIN="${PEER_MIN:-3}"          # 2 outbound seeds is the measured floor; alert below 3
# steady-state KCP retrans on this uplink measured 21-54% and is dominated by RTO/path-loss, NOT
# congestion (CC-off is a proven no-op here) — 10% would fire constantly. Alert only on a genuinely
# degraded path. [E:OBS delta OutSegs/RetransSegs 2026-07-08]
RETRANS_MAX="${RETRANS_MAX:-60}"   # steady-state %
STALL_SECS="${STALL_SECS:-60}"     # height must advance within this
export RPC INTERVAL WINDOW MINER_LOG OUR_ADDR PEER_MIN RETRANS_MAX STALL_SECS

exec python3 - <<'PY'
import os,sys,time,re,json,urllib.request,collections
RPC=os.environ["RPC"]; INT=float(os.environ["INTERVAL"]); WIN=int(os.environ["WINDOW"])
LOG=os.environ["MINER_LOG"]; OUR=os.environ["OUR_ADDR"]
PEER_MIN=int(os.environ["PEER_MIN"]); RETRANS_MAX=float(os.environ["RETRANS_MAX"]); STALL=float(os.environ["STALL_SECS"])
BLOCK_TIME=18

def rpc(m,p=None):
    d={"jsonrpc":"2.0","id":1,"method":m}
    if p is not None: d["params"]=p            # GetInfo REJECTS a params key -> only send when needed
    req=urllib.request.Request("http://%s/json_rpc"%RPC,data=json.dumps(d).encode(),
                               headers={"Content-Type":"application/json"})
    j=json.load(urllib.request.urlopen(req,timeout=6)); return j.get("result"),j.get("error")

def metrics():
    d=urllib.request.urlopen("http://%s/metrics"%RPC,timeout=6).read().decode()
    def g(k):
        m=re.search(r'^%s (\d+)'%re.escape(k),d,re.M); return int(m.group(1)) if m else 0
    hb={}  # cumulative miniblock inbound-propagation buckets: upper_bound_seconds -> count
    for lo,hi,c in re.findall(r'miniblock_propagation_duration_histogram_seconds_bucket\{vmrange="([\d.eE+-]+)\.\.\.([\d.eE+-]+)"\} (\d+)',d):
        hb[float(hi)]=int(c)
    return {k:g("KCP_"+k) for k in("OutSegs","RetransSegs","LostSegs","InSegs","FECRecovered","CurrEstab","MaxConn")}, hb

def pctile(buckets_delta):
    tot=sum(buckets_delta.values())
    if tot==0: return None,None
    p50=p90=None; run=0
    for ub in sorted(buckets_delta):
        run+=buckets_delta[ub]
        if p50 is None and run>=0.5*tot: p50=ub
        if p90 is None and run>=0.9*tot: p90=ub
    return p50,p90

def miner_log():
    r={"cpu":None,"gpu":None,"found_cpu":None,"found_gpu":None,"rej":None,"acc":None,"ts":None}
    try:
        with open(LOG,'rb') as f:
            f.seek(0,2); sz=f.tell(); f.seek(max(0,sz-60000)); tail=f.read().decode('utf-8','replace').splitlines()
    except Exception: return r
    for ln in reversed(tail):
        if r["cpu"] is None and "TOTAL hashrate" in ln:
            m=re.search(r'H/s[":= ]+([\d.]+)',ln);  r["cpu"]=float(m.group(1)) if m else None; r["ts"]=ln[:19]
        if r["gpu"] is None and "GPU hashrate" in ln:
            m=re.search(r'H/s[":= ]+([\d.]+)',ln);  r["gpu"]=float(m.group(1)) if m else None
        if r["found_cpu"] is None and "REWARD STATS" in ln:
            for key in("found_CPU","found_GPU","rejected","accepted_miniblocks"):
                mm=re.search(key+r'[":= ]+(\d+)',ln)
                if mm:
                    if key=="found_CPU":r["found_cpu"]=int(mm.group(1))
                    if key=="found_GPU":r["found_gpu"]=int(mm.group(1))
                    if key=="rejected":r["rej"]=int(mm.group(1))
                    if key=="accepted_miniblocks":r["acc"]=int(mm.group(1))
        if all(r[k] is not None for k in("cpu","gpu","found_cpu")): break
    return r

# incremental realized-reward window: deque of (height, ours_in_block, slots_in_block, reward_atomic_ours)
win=collections.deque(); scanned_to=None
def scan(top):
    global scanned_to
    lo = top-WIN if scanned_to is None else scanned_to+1
    lo=max(lo, top-WIN)
    for h in range(lo, top):                       # skip the tip (top) — not yet final/stable
        res,e=rpc("DERO.GetBlock",{"height":h})
        if e or not res: continue
        bh=res["block_header"]
        if bh.get("orphan_status"): continue        # orphan = unpaid, exclude
        ms=bh.get("miners") or []; slots=len(ms); ours=sum(1 for m in ms if m==OUR)
        rew=bh.get("reward",0)
        our_atomic=(rew//slots)*ours if slots else 0
        win.append((h,ours,slots,our_atomic))
        scanned_to=h
    while win and win[0][0] < top-WIN: win.popleft()

prev_k=None; prev_hb=None; last_h=None; last_h_ts=time.time()
C="\033[0m";B="\033[1m";R="\033[31m";Gr="\033[32m";Y="\033[33m";Cy="\033[36m"
while True:
    alerts=[]
    try:
        info,_=rpc("DERO.GetInfo"); k,hb=metrics()
    except Exception as ex:
        sys.stdout.write("\033[2J\033[H"); print("%sderod unreachable at %s: %s%s"%(R,RPC,ex,C)); time.sleep(INT); continue
    top=info["topoheight"]; height=info["height"]
    # sync / stall
    now=time.time()
    if last_h is None or height>last_h: last_h=height; last_h_ts=now
    stalled=now-last_h_ts
    if stalled>STALL: alerts.append("HEIGHT STALLED %.0fs (behind/forked?)"%stalled)
    # peers
    pin=info["incoming_connections_count"]; pout=info["outgoing_connections_count"]; ptot=pin+pout
    if ptot<PEER_MIN: alerts.append("PEERS %d < %d — thin propagation pipe raises orphan risk"%(ptot,PEER_MIN))
    # KCP steady-state deltas
    rt=ls=out=fecr=0.0; retpct=lospct=None
    if prev_k:
        out=k["OutSegs"]-prev_k["OutSegs"]; rt=k["RetransSegs"]-prev_k["RetransSegs"]
        ls=k["LostSegs"]-prev_k["LostSegs"]; fecr=k["FECRecovered"]-prev_k["FECRecovered"]
        if out>0:
            retpct=100*rt/out; lospct=100*ls/out
            if retpct>RETRANS_MAX: alerts.append("KCP retrans %.1f%% > %d%% (lossy path -> our mini delayed)"%(retpct,RETRANS_MAX))
    prev_k=k
    # inbound miniblock propagation p50/p90 over this interval (delta buckets)
    dp={}
    if prev_hb is not None:
        for ub,c in hb.items():
            d=c-prev_hb.get(ub,0)
            if d>0: dp[ub]=d
    prev_hb=hb
    p50,p90=pctile(dp)
    # realized reward window
    scan(top)
    w_ours=sum(x[1] for x in win); w_slots=sum(x[2] for x in win); w_atomic=sum(x[3] for x in win)
    w_blocks=len(win)
    paid_frac=(w_ours/w_slots) if w_slots else 0
    # expected fair share from difficulty (NW hashrate) vs our raw hashrate
    ml=miner_log()
    # each block packs 10 miniblocks: 9 at difficulty D and the final at 9*D (config.MINIBLOCK_HIGHDIFF), so the
    # network does 18*D hashes per 18 s block: NW ~= D H/s. The old difficulty*10/BLOCK_TIME formula assumed all
    # 10 at D and understated our fair share ~1.8x (corrected 2026-10-22, Round 15, from consensus code).
    avg_slots = (w_slots/w_blocks) if w_blocks else 10.0
    nw_hs=info["difficulty"]*(9+9)/BLOCK_TIME
    # ml["cpu"] is parsed from the miner's "TOTAL hashrate" line which ALREADY includes the GPU —
    # do NOT add ml["gpu"] again (that double-counts the GPU and inflates fair-share).
    our_hs=(ml["cpu"] or 0)
    fair=our_hs/nw_hs if nw_hs else 0
    # realized DERO/hr over window
    span_blocks=w_blocks if w_blocks else 1
    dero_per_hr=(w_atomic/1e5)/(span_blocks*BLOCK_TIME/3600) if w_blocks else 0
    # Only flag underperformance over a LARGE window where we'd EXPECT several paid minis (>=5) — avoids
    # false 'orphaning' alarms at small n. paid-share vs fair-share is the apples-to-apples signal.
    exp_paid_window=fair*w_slots
    if w_blocks>=300 and exp_paid_window>=5 and paid_frac < fair*0.5:
        alerts.append("paid-share %.3f%% << fair-share %.3f%% over %d blocks (expected ~%.0f, got %d) — find-rate OR orphaning; run reward_audit.py"%(
            paid_frac*100, fair*100, w_blocks, exp_paid_window, w_ours))

    # ---- render ----
    sys.stdout.write("\033[2J\033[H")
    ts=time.strftime("%Y-%m-%d %H:%M:%S")
    print("%s%s DERO SOLO MINING DASHBOARD %s  %s  win=%d blk  every %ds"%(B,Cy,C,ts,WIN,int(INT)))
    print("-"*74)
    print("%sNODE %s  height %d  topo %d  stable %d  blk_time %.1fs (t=18)  up %ds"%(
        B,C,height,top,info["stableheight"],info["averageblocktime50"],info["uptime"]))
    print("%sPEERS%s  total %d (in %d / out %d)   KCP estab %d/%d   miners_connected %d"%(
        B,C,ptot,pin,pout,k["CurrEstab"],k["MaxConn"],info["connected_miners"]))
    if retpct is not None:
        col=R if retpct>RETRANS_MAX else Gr
        print("%sKCP  %s  retrans %s%.1f%%%s  lost %.1f%%  FECrecov %d  (Δ over %ds, steady-state)"%(
            B,C,col,retpct,C,lospct,int(fecr),int(INT)))
    else:
        print("%sKCP  %s  (collecting delta baseline...)"%(B,C))
    if p50 is not None:
        print("%sPROP %s  inbound miniblock p50<=%.0fms p90<=%.0fms  (%d minis seen this interval)"%(
            B,C,p50*1000,p90*1000,sum(dp.values())))
    else:
        print("%sPROP %s  inbound miniblock (collecting...)"%(B,C))
    # NW H/s is difficulty/BLOCK_TIME (Get_Network_HashRate reports difficulty, not physical H/s); it's an
    # estimate. fair-share = our physical H/s / that estimate = our EXPECTED miniblock share.
    print("%sHASH %s  miner TOTAL %s H/s (GPU %s of that)  | NW ~%.0f H/s (diff*%.0fslots/18)  fair-share %.3f%%"%(
        B,C,("%.0f"%ml["cpu"]) if ml["cpu"] else "?",("%.0f"%ml["gpu"]) if ml["gpu"] else "?",nw_hs,avg_slots,fair*100))
    print("-"*74)
    exp_found=fair*w_slots
    fr_col = R if (w_ours==0 and w_blocks>=60) else (Y if paid_frac< fair*0.6 else Gr)
    print("%s%sREWARD (GROUND TRUTH from GetBlock miners[]) %s"%(B,Cy,C))
    print("  window: %d canonical blocks, %d slots"%(w_blocks,w_slots))
    print("  PAID miniblocks (ours): %s%d%s   paid-share %s%.3f%%%s   (fair-share by hashrate %.3f%%)"%(
        B,w_ours,C,fr_col,paid_frac*100,C,fair*100))
    print("  realized reward: %.5f DERO over window  ~= %s%.4f DERO/hr%s  (reward/slots approx; ignores integrator extra part)"%(w_atomic/1e5,B,dero_per_hr,C))
    if ml["found_cpu"] is not None:
        found=(ml["found_cpu"] or 0)+(ml["found_gpu"] or 0)
        print("  miner FOUND (cumulative session) cpu=%s gpu=%s rej=%s  | node-accepted=%s"%(
            ml["found_cpu"],ml["found_gpu"],ml["rej"],info["miniblocks_accepted_count"]))
        print("  NOTE paid/found orphan rate needs a MATCHED window over >=~20 finds — use ./reward_audit.py; "
              "cumulative found here is NOT window-aligned with paid=%d above."%w_ours)
    print("-"*74)
    if alerts:
        for a in alerts: print("%s  ALERT: %s%s"%(R,a,C))
    else:
        print("%s  OK — no alerts%s"%(Gr,C))
    sys.stdout.flush()
    time.sleep(INT)
PY
