#!/usr/bin/env python3
"""miner_intel.py — what the live miner's own JSON log (and derod's miniblock ledger) say about a mining run.

dero-miner writes <exe>.log as JSON lines {"L","T","N","C","M", ...fields}. This tool reads it READ-ONLY and:

  1. splits it into RUNS at each start-up line (message text, not the caller line: callers move between builds —
     log_intel's 'derod/main.go:160' split went blind when r18 moved the line to :182);
  2. per run: version and arguments (threads, --cpu-max, --gpu-mode), TOTAL hashrate stats (warm-up samples
     excluded), GPU split efficiency (staged H/s vs TOTAL, dropped_stale rate and fraction of GPU stage-1 work,
     drops per new chain height vs the staging ring, restarts, mismatches, sort fallbacks), the reward ledger
     (paid fraction, orphans, luck) and the found-share events;
  3. optionally asks derod (read-only JSON-RPC DERO.GetMiningOutcome on 10102 — never the getwork port) for the
     orphan REASONS and its own paid fraction, and reads derod's log for the heights reached in the same window;
  4. applies RULES (thresholds justified below) and writes harness/runtime/minerintel_<ts>.json, one fact per line.

R20: the log is a CHAIN. Before r20 the miner truncated <exe>.log at every start (os.Create), and the user's
restart on 2026-10-28 08:32 erased ~27 h of the r19 run. r20 appends to it and rotates it by size (32 MiB; <exe>.log.1
newest .. .log.3; several runs per file are normal, runs are split at each start-up line), so this tool
reads the rotated files too, oldest first, and records for each file its window and whether the start of its first
run is missing (head_missing: rotated or truncated mid-run). Each run reports its version, its window and the file
it came from. Shares are also followed on derod's side: every accepted own miniblock is a "Own miniblock delivered"
line in derod's log, so a run that hashes but submits nothing for hours (share_drought) is caught, and so are long
gaps no surviving miner log explains (the evidence was lost).

  python3 -I harness/intel/miner_intel.py [--log bin/dero-miner.log] [--derod-log …/derod.log] [--no-rpc] [--json-only]
"""
import argparse, datetime, importlib.util, json, re, statistics, sys, time, urllib.request
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
ROOT = HARNESS.parent
DEFAULT_LOG = ROOT / 'bin/dero-miner.log'
DEFAULT_DEROD_LOG = Path(os.path.expanduser(os.environ.get('DERO_DATADIR', '~/dero-data')) + '/logs/derod.log')
RPC = 'http://127.0.0.1:10102/json_rpc'          # derod's read-only JSON-RPC; the miner's getwork port is 10100
START_M = 'DERO Stargate HE AstroBWT miner'       # cmd/dero-miner/miner.go logger.Info("DERO Stargate HE AstroBWT miner : ...")
WARMUP_SAMPLES = 2                                # the first TOTAL lines include start-up (self-tests, GPU spin-up)
ROTATED_MAX = 9                                   # cmd/dero-miner/minerlog.go MINER_LOG_BACKUPS is 3; read a few more if kept
SILENT_S = 300                                    # TOTAL hashrate is logged every 15 s: 5 min of silence = hung or gone
DROUGHT_EXPECTED = 20                             # shares a gap should have held at the run's own rate: P(0) = e^-20
UNEXPLAINED_GAP_S = 2 * 3600                      # a derod-side share gap no miner log covers
OWN_MB = 'Own miniblock delivered'                # p2p/own_broadcast.go: derod broadcast one of OUR miniblocks
SPLIT_SILENT_S = 180                              # gpu_split.go report_split logs 'GPU split' every 60 s: 3 periods
# R21 split-mode regime (gpu_split.go split_fields, per 60 s window). Calibrated on the two live runs of 2026-10-28:
# r19 (GPU-bound, no backlog counter yet) idled 394,442 TryWork calls/min at 20 threads = 19.7k per thread; r20 waits on
# the CPU sort 41.3 of every 60 s (0.69) and idles 22k/min = 1.1k per thread. The thresholds sit between the two.
REGIME_CPU_BACKLOG = 0.5                          # feeder_cpu_backlog_ms / window: >= half the time staged texts wait on the CPU
REGIME_GPU_IDLE_PER_THREAD_MIN = 5000             # cpu_idle_tries per thread per minute: the CPU threads outrun staging
# R22 BINDING resource (classify_binding). r21 made the GPU kernels ~1.6x faster and the GPU became CO-BINDING: the live
# r21 run (2026-10-29 06:37, uptime 710 s) had the GPU busy 671.8 of 710 s (0.946) AND staged texts waiting on the CPU
# sort 526.3 of 710 s (0.74), which the r21 two-way classifier called plain 'cpu-sort-bound' (the GPU busy counter was
# exported but never read). A resource binds when it is busy at least BIND_GPU_BUSY of the time (GPU) or the CPU sort
# backlog is at least REGIME_CPU_BACKLOG (CPU); both = co-bound. BIND_RING: the ring is full most of the time while
# neither binds = the staging geometry (batch x depth x inflight) is the limit. BIND_CPU_BUDGET: the miner process
# uses at least this share of its --cpu-max budget (threads x cpu_max %), so the duty-cycle cap is the CPU-side limit.
BIND_GPU_BUSY = 0.90
BIND_RING = 0.5
BIND_CPU_BUDGET = 0.85

RULES = {
    'gpu_mismatch': 'ALERT: any gpu_cpu_mismatch > 0 — a GPU/split hash disagreed with the CPU re-hash (never submitted, but the GPU path is wrong)',
    'split_disabled': 'ALERT: the GPU split line reports disabled != "" — split mode turned itself off',
    'sort_disabled': 'ALERT: the descriptor sort turned itself off (GPU split cpu field "descriptor disabled", or the ERROR line "descriptor sort DISABLED") — hashing fell back to SA-IS, about 4x slower per thread',
    'sort_fallbacks': 'WARN: the descriptor sort reports fallbacks > 0 — its 1-in-1024 verification caught a wrong suffix array; that hash was redone with SA-IS, so no wrong share was produced (repeated faults turn the sort off: sort_disabled)',
    'gpu_restarts': 'WARN: the split server restart counter grew within the run (Round 18: an agent\'s long Metal command buffer killed it)',
    'drop_fraction': 'WARN: more than 5 % of GPU-staged nonces dropped as stale (r18 live: ~1.3 %, about one staging ring per new height)',
    'paid_fraction': 'WARN: paid fraction below 0.75 with at least 20 resolved miniblocks (r17-r18 live runs: 0.885-0.92)',
    'hashrate_sag': 'WARN: mean of the last 10 TOTAL samples below 75 % of the run mean (Round 18: agent benchmarks cut 40k to 22k)',
    'rejected': 'WARN: the daemon rejected a submitted miniblock',
    'miner_silent': 'ALERT: the current run\'s last log record is more than 5 min older than the capture (TOTAL hashrate is logged every 15 s) — the miner hung or exited',
    'share_drought': 'ALERT: derod accepted none of our miniblocks for a stretch of the run in which the run\'s own rate expected >= 20 (5/(9 D) shares per hash, the miner\'s own expectedShares; D = median found difficulty); P(0) = e^-20 = 2e-9 — hashing is not reaching the chain',
    'stale_build': 'WARN: the running miner\'s version differs from this tree\'s config/version.go — the installed binary was not restarted (Round 19: G17 judged a stale r18 miner)',
    'head_missing': 'WARN: the oldest miner log does not begin with a start-up line — the record of that run was truncated or rotated away, so its numbers cover only part of it',
    'split_silent': 'ALERT: the current run was started with --gpu-mode=split, is more than 3 min old and has logged no "GPU split" line (report_split logs one every 60 s) — split never came up or its reporter died, and the run mines without the GPU',
    'cpu_starved': 'WARN: (R23, replaces hashrate_sag on a contended box) the run sagged while the census at capture finds foreign '
                   'processes taking the cores the miner\'s --cpu-max budget needs — attributed to the box, not the build; '
                   'no regression may be claimed (G20)',
    'unexplained_gap': 'WARN: derod saw no own miniblock for >= 2 h in a stretch that no surviving miner log covers — the evidence of why was lost (r19: 08:32 restart truncated 27 h)',
}


def records(path, tag=False):
    out = []
    with Path(path).open(errors='replace') as fh:
        for l in fh:
            if not l.startswith('{'):
                continue
            try:
                d = json.loads(l)
            except ValueError:
                continue
            if isinstance(d, dict) and 'T' in d:
                if tag:
                    d['_src'] = str(path)
                out.append(d)
    return out


def log_chain(path, most=ROTATED_MAX):
    """the live log and its rotations, OLDEST first: <log>.N .. <log>.1, <log> (cmd/dero-miner/minerlog.go: size rotation, append)"""
    p = Path(path)
    old = [Path(f'{p}.{i}') for i in range(most, 0, -1) if Path(f'{p}.{i}').exists()]
    return old + ([p] if p.exists() else [])


def chain_records(paths):
    """records of every file in order, each tagged with its file, plus one summary per file"""
    recs, files = [], []
    for f in paths:
        r = records(f, tag=True)
        nul = 0
        with Path(f).open('rb') as fh:
            for l in fh:
                nul += b'\x00' in l
        files.append({'file': str(f), 'records': len(r), 'first': r[0]['T'] if r else None, 'last': r[-1]['T'] if r else None,
                      'starts': sum(1 for d in r if str(d.get('M', '')).startswith(START_M)),
                      'head_missing': bool(r) and not str(r[0].get('M', '')).startswith(START_M), 'nul_lines': nul})
        recs += r
    return recs, files


def tree_version(root=ROOT):
    """the version this tree builds (config/version.go), to tell a stale running miner from the installed one"""
    try:
        m = re.search(r'MustParse\("([^"]+)"\)', (Path(root) / 'config/version.go').read_text())
        return m.group(1) if m else None
    except OSError:
        return None


def ts(t):
    """'2026-10-24T18:49:56.204-0700' -> epoch seconds (offset honoured)."""
    return datetime.datetime.strptime(t, '%Y-%m-%dT%H:%M:%S.%f%z').timestamp()


def split_runs(recs):
    runs, cur = [], []
    for d in recs:
        if str(d.get('M', '')).startswith(START_M) and cur:
            runs.append(cur)
            cur = []
        cur.append(d)
    if cur:
        runs.append(cur)
    return runs


def num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def pct(a, q):
    s = sorted(a)
    return s[int(q * (len(s) - 1))] if s else None


def hashrate_stats(run):
    pts = [(ts(d['T']), num(d.get('H/s'))) for d in run if d.get('M') == 'TOTAL hashrate']
    pts = [p for p in pts if p[1] is not None]
    body = pts[WARMUP_SAMPLES:] if len(pts) > WARMUP_SAMPLES else []
    v = [h for _, h in body]
    if not v:
        return {'samples': 0}
    gaps = [b[0] - a[0] for a, b in zip(body, body[1:])]
    tail = v[-10:]
    return {'samples': len(v), 'warmup_excluded': min(WARMUP_SAMPLES, len(pts)), 'mean': round(statistics.mean(v), 1),
            'median': pct(v, 0.5), 'p10': pct(v, 0.1), 'p90': pct(v, 0.9), 'min': min(v), 'max': max(v),
            'last': v[-1], 'tail10_mean': round(statistics.mean(tail), 1),
            'interval_s': round(statistics.median(gaps), 1) if gaps else None,
            'first_t': body[0][0], 'last_t': body[-1][0]}


def split_stats(run):
    """GPU split lines are cumulative counters (dropped_stale, audited, restarts) plus a per-minute staged_H/s."""
    cfg = next((d for d in run if str(d.get('M', '')).startswith('GPU split mode ACTIVE')), None)
    S = [d for d in run if d.get('M') == 'GPU split']
    if not S:
        return {'active': cfg is not None, 'lines': 0}
    staged = [num(d.get('staged_H/s')) for d in S]
    staged = [x for x in staged if x is not None]
    drops, staged_work = [], 0.0
    for a, b in zip(S, S[1:]):
        dt = ts(b['T']) - ts(a['T'])
        dd = (b.get('dropped_stale') or 0) - (a.get('dropped_stale') or 0)
        if dt > 0 and dd >= 0:
            drops.append((dt, dd))
            staged_work += (num(b.get('staged_H/s')) or 0) * dt
    dropped = sum(dd for _, dd in drops)
    span = sum(dt for dt, _ in drops)
    last = S[-1]
    m = re.search(r'fallbacks=(\d+)', str(last.get('cpu', '')))
    sort_off = next((str(d.get('cpu')) for d in S if 'descriptor disabled' in str(d.get('cpu', ''))), '')
    if not sort_off:
        sort_off = next((str(d.get('M')) for d in run if str(d.get('M', '')).startswith('descriptor sort DISABLED')), '')
    v = re.search(r'verified=(\d+)', str(last.get('cpu', '')))
    out = {'active': True, 'lines': len(S), 'staged_mean': round(statistics.mean(staged), 1) if staged else None,
           'staged_median': pct(staged, 0.5),
           'dropped_total': last.get('dropped_stale'), 'dropped_in_window': dropped,
           'dropped_per_min': round(dropped / span * 60, 1) if span else None,
           # fraction of the GPU's stage-1 output thrown away: dropped / (dropped + sorted), over the same window
           'drop_fraction': round(dropped / (dropped + staged_work), 4) if (dropped + staged_work) > 0 else None,
           'restarts_first': S[0].get('restarts'), 'restarts_last': last.get('restarts'),
           'mismatch': last.get('gpu_cpu_mismatch'), 'disabled': last.get('disabled') or '',
           'cpu_finished': last.get('cpu_finished'), 'audited': last.get('audited'),
           'gpu_us_per_hash': num(last.get('gpu_us_per_hash')),
           # r21: wall-clock GPU duty (union of the command buffers; gpu_us_per_hash double-counts overlap). Mean over
           # the run; None on older logs. Low gpu_busy_pct with high feeder_cpu_backlog_ms = CPU-bound, GPU headroom.
           'gpu_busy_pct_mean': (round(statistics.mean(num(d.get('gpu_busy_pct')) or 0.0 for d in S if 'gpu_busy_pct' in d), 1)
                                 if any('gpu_busy_pct' in d for d in S) else None),
           'sort_fallbacks': int(m.group(1)) if m else None, 'sort_verified': int(v.group(1)) if v else None,
           'sort_disabled': sort_off,
           # r19 regime signal (gpu_split.go split_fields): per-window counters, summed over the run
           'cpu_idle_tries': sum(int(d.get('cpu_idle_tries') or 0) for d in S),
           'feeder_ring_full_ms': sum(int(d.get('feeder_ring_full_ms') or 0) for d in S),
           # r20: the CPU-bound part of the feeder wait (absent on r19 logs: None, not 0)
           'feeder_cpu_backlog_ms': (sum(int(d.get('feeder_cpu_backlog_ms') or 0) for d in S)
                                     if any('feeder_cpu_backlog_ms' in d for d in S) else None),
           'window': (ts(S[0]['T']), ts(last['T']))}
    out['_windows'] = regime_windows(S)
    if cfg:
        out['batch'], out['depth'], out['inflight'] = cfg.get('batch'), cfg.get('depth'), cfg.get('inflight')
        if cfg.get('batch') and cfg.get('depth'):
            out['ring_slots'] = cfg['batch'] * cfg['depth']
    return out


def regime_windows(S):
    """per-window regime readings from consecutive 'GPU split' lines: the first line's window is unknown (it includes
    start-up), so each later line is one window of (its T - the previous T) seconds"""
    out = []
    for a, b in zip(S, S[1:]):
        dt = ts(b['T']) - ts(a['T'])
        if dt <= 0:
            continue
        out.append({'dt_s': dt, 'staged_hs': num(b.get('staged_H/s')), 'idle_tries': int(b.get('cpu_idle_tries') or 0),
                    'ring_full_ms': int(b.get('feeder_ring_full_ms') or 0),
                    'backlog_ms': int(b['feeder_cpu_backlog_ms']) if 'feeder_cpu_backlog_ms' in b else None,
                    'gpu_us': num(b.get('gpu_us_per_hash')),
                    # r21+: the window's wall-clock GPU duty in percent (None on older logs)
                    'gpu_busy_pct': num(b.get('gpu_busy_pct')) if 'gpu_busy_pct' in b else None})
    return out


def write_atomic(path, text):
    """R22 crash safety: a snapshot is written to a hidden temp file in the same directory, fsynced and renamed over
    its name, so a kill mid-write never leaves a torn newest snapshot for run_gates/mine_intel to choke on (they read
    the newest *_<ts>.json; a torn one used to crash the whole gate run). The temp name never matches a *_*.json glob."""
    import os, tempfile
    p = Path(path)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix='.' + p.name + '.', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def classify_binding(gpu_busy, backlog, ring_full, cpu_budget=None):
    """R22: which resource bounds the split, from the fractions of time each one was the limit. Pure; shared by the
    log (miner_intel) and the dashboard (metrics_intel). Returns {'binding', 'why', 'throttle_capped'}:
      co-bound        GPU busy >= BIND_GPU_BUSY and CPU-sort backlog >= REGIME_CPU_BACKLOG: both near their ceiling,
                      speeding up one alone buys at most the other's headroom
      gpu-bound       only the GPU is busy >= BIND_GPU_BUSY
      cpu-sort-bound  only the CPU-sort backlog is >= REGIME_CPU_BACKLOG
      ring-bound      neither, but the feeder waits on a full ring >= BIND_RING of the time: the staging geometry
      balanced        none of the above
      unknown         no GPU-busy reading (pre-r21 build) AND no backlog reading
    throttle_capped: the process used >= BIND_CPU_BUDGET of its --cpu-max budget (None when unknown)."""
    if gpu_busy is None and backlog is None:
        return {'binding': 'unknown', 'why': 'no gpu_busy and no cpu_backlog reading', 'throttle_capped': None}
    g = gpu_busy is not None and gpu_busy >= BIND_GPU_BUSY
    c = backlog is not None and backlog >= REGIME_CPU_BACKLOG
    if g and c:
        b = 'co-bound'
    elif g:
        b = 'gpu-bound'
    elif c:
        b = 'cpu-sort-bound'
    elif ring_full is not None and ring_full >= BIND_RING:
        b = 'ring-bound'
    else:
        b = 'balanced'
    why = (f'gpu_busy {gpu_busy} (binds >= {BIND_GPU_BUSY}), cpu_backlog {backlog} (binds >= {REGIME_CPU_BACKLOG}), '
           f'ring_full {ring_full} (geometry >= {BIND_RING}), cpu_budget {cpu_budget} (capped >= {BIND_CPU_BUDGET})')
    return {'binding': b, 'why': why, 'throttle_capped': None if cpu_budget is None else cpu_budget >= BIND_CPU_BUDGET}


def gpu_ceiling(staged_hs, gpu_busy):
    """ESTIMATE: staged H/s the GPU could feed at 100 % duty, linear in duty (staged / busy). None without both."""
    if not staged_hs or not gpu_busy or gpu_busy <= 0:
        return None
    return round(staged_hs / gpu_busy, 1)


def classify_regime(backlog_fraction, idle_per_min, threads):
    """what bounds split mode: 'cpu-sort-bound' (staged texts wait on the CPU sort at least half the time),
    'gpu-bound' (the CPU threads find nothing staged: idle tries per thread per minute above the threshold),
    'balanced', or 'unknown' (no window). Pure, shared with metrics_intel so the log and /metrics agree."""
    if idle_per_min is None:
        return 'unknown'
    if backlog_fraction is not None and backlog_fraction >= REGIME_CPU_BACKLOG:
        return 'cpu-sort-bound'
    if idle_per_min / max(int(threads or 20), 1) >= REGIME_GPU_IDLE_PER_THREAD_MIN:
        return 'gpu-bound'
    return 'balanced'


def regime_of(windows, threads=None):
    """the run's split regime from its windows: time-weighted fractions (sum of waits / sum of window time), the
    median staged H/s and GPU us/hash, idle tries per minute. backlog is None when no window carried the r20 counter."""
    if not windows:
        return {'windows': 0, 'regime': 'unknown'}
    T = sum(w['dt_s'] for w in windows)
    bl = [w for w in windows if w['backlog_ms'] is not None]
    TB = sum(w['dt_s'] for w in bl)
    backlog = round(sum(w['backlog_ms'] for w in bl) / (TB * 1000), 3) if TB else None
    idle = round(sum(w['idle_tries'] for w in windows) / T * 60, 1)
    staged = [w['staged_hs'] for w in windows if w['staged_hs'] is not None]
    gus = [w['gpu_us'] for w in windows if w['gpu_us'] is not None]
    gb = [w for w in windows if w.get('gpu_busy_pct') is not None]
    TG = sum(w['dt_s'] for w in gb)
    busy = round(sum(w['gpu_busy_pct'] * w['dt_s'] for w in gb) / (TG * 100), 3) if TG else None   # time-weighted
    ring = round(sum(w['ring_full_ms'] for w in windows) / (T * 1000), 3)
    bd = classify_binding(busy, backlog, ring)
    sm = pct(staged, 0.5)
    return {'windows': len(windows), 'seconds': round(T, 1), 'staged_median_hs': sm,
            'cpu_backlog_fraction': backlog, 'ring_full_fraction': ring,
            'idle_tries_per_min': idle, 'gpu_us_per_hash_median': pct(gus, 0.5),
            'regime': classify_regime(backlog, idle, threads),
            'gpu_busy_fraction': busy, 'binding': bd['binding'], 'gpu_ceiling_staged_hs': gpu_ceiling(sm, busy)}


def heights_in(derod_recs, t0, t1):
    """distinct new chain heights derod reached in [t0, t1] (blockchain.go 'Chain extended')."""
    seen = set()
    for d in derod_recs:
        if d.get('M') != 'Chain extended' or not isinstance(d.get('new height'), int):
            continue
        try:
            t = ts(d['T'])
        except (KeyError, ValueError):
            continue
        if t0 <= t <= t1:
            seen.add(d['new height'])
    return len(seen)


def own_times(derod_recs):
    """epoch seconds of every own miniblock derod accepted and broadcast, sorted"""
    out = []
    for d in derod_recs or []:
        if d.get('M') == OWN_MB:
            try:
                out.append(ts(d['T']))
            except (KeyError, ValueError):
                pass
    return sorted(out)


def drought(times, t0, t1, mean_hs, difficulty):
    """the longest stretch of [t0, t1] with no accepted own miniblock, and how many the run's own rate expected in
    it: gap x H/s x 5 / (9 D), the miner's own expectedShares (cmd/dero-miner/outcome.go: 10 shares per 18 D network
    hashes). Pure: the KAT feeds it numbers."""
    inside = [t for t in times if t0 <= t <= t1]
    edges = [t0] + inside + [t1]
    gap, at = max(((b - a, a) for a, b in zip(edges, edges[1:])), default=(0.0, t0))
    exp = round(gap * mean_hs * 5 / (9 * difficulty), 1) if mean_hs and difficulty else None
    return {'submissions': len(inside), 'longest_gap_s': round(gap, 1), 'gap_from': at, 'expected_in_gap': exp}


def unexplained_gaps(times, covered, t0, t1, min_gap=UNEXPLAINED_GAP_S):
    """gaps between derod-side own miniblocks within [t0, t1] whose part NOT covered by any miner-log window [a, b]
    is still >= min_gap: a long silence the surviving miner logs cannot explain (windows are assumed disjoint runs)"""
    edges = [t0] + [t for t in times if t0 <= t <= t1] + [t1]
    out = []
    for a, b in zip(edges, edges[1:]):
        if b - a < min_gap:
            continue
        seen = sum(max(0.0, min(b, cb) - max(a, ca)) for ca, cb in covered)
        if (b - a) - seen >= min_gap:
            out.append({'from': a, 'to': b, 'hours': round((b - a) / 3600, 2), 'uncovered_h': round(((b - a) - seen) / 3600, 2)})
    return out


def stopped_windows(runs):
    """R22: [(exit_t, next_start_t, reason)] for each run whose LAST record is the miner's own 'miner exiting' line
    (cmd/dero-miner/miner.go; r20+ logs append, so the next start-up line follows in the same chain). The miner was
    STOPPED in that interval and its log says why: a derod-side share gap inside it is explained, not lost evidence
    (r21: 20:25:16 'console exit' -> 06:25:17 start was reported as a 10.04 h 'unexplained_gap'). Pure."""
    out = []
    for r, nxt in zip(runs, runs[1:]):
        last = r[-1]
        if str(last.get('M', '')) == 'miner exiting' and str(nxt[0].get('M', '')).startswith(START_M):
            try:
                out.append((ts(last['T']), ts(nxt[0]['T']), str(last.get('reason', ''))))
            except (KeyError, ValueError):
                continue
    return out


def reward_stats(run):
    R = [d for d in run if d.get('M') == 'REWARD STATS']
    found = [d for d in run if str(d.get('M', '')).startswith(('GPU-split found', 'Successfully found', 'GPU found'))]
    out = {'lines': len(R), 'found_events': len(found),
           'found_likely_stale': sum(1 for d in found if d.get('likely_stale') is True)}
    diffs = [num(d.get('difficulty')) for d in found if num(d.get('difficulty'))]
    out['found_difficulty_median'] = pct(diffs, 0.5)
    if not R:
        return out
    r = R[-1]
    for k in ('accepted_miniblocks', 'accepted_blocks', 'rejected', 'found_CPU', 'found_GPU', 'node_submitted', 'node_paid',
              'node_orphaned', 'node_pending', 'paid_CPU', 'paid_GPU', 'orphaned_CPU', 'orphaned_GPU', 'unresolved'):
        out[k] = r.get(k)
    for k in ('paid_fraction', 'luck', 'expected_shares', 'expected_DERO_per_day', 'run_H/s', 'paid_DERO', 'est_earned_DERO'):
        out[k] = num(r.get(k))
    paid, orph = r.get('node_paid') or 0, r.get('node_orphaned') or 0
    out['paid_fraction_recomputed'] = round(paid / (paid + orph), 3) if (paid + orph) else None
    out['resolved'] = paid + orph
    return out


def outcome(rpc_url=RPC, timeout=8):
    body = json.dumps({'jsonrpc': '2.0', 'id': '1', 'method': 'DERO.GetMiningOutcome'}).encode()
    req = urllib.request.Request(rpc_url, data=body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        res = json.loads(r.read()).get('result') or {}
    orph = res.get('orphaned') or {}
    rec = res.get('recent') or []
    return {'submitted': res.get('submitted'), 'paid': res.get('paid'), 'orphaned': orph,
            'orphaned_total': sum(orph.values()), 'pending': res.get('pending'), 'paid_fraction': res.get('paid_fraction'),
            'work_would_be_stale': res.get('work_would_be_stale'),
            'recent_fates': {f: sum(1 for x in rec if x.get('fate') == f) for f in ('paid', 'orphaned', 'pending')},
            'recent_reasons': {k: sum(1 for x in rec if x.get('reason') == k) for k in sorted({x.get('reason') for x in rec if x.get('reason')})},
            # R22: the instants, so a run ledger can join derod's fates to ONE miner run (derod returns the newest 50
            # only: mining_outcome.go 'len(result.Recent) < 50'); [submitted_unix_ms, fate, reason]
            'recent_window': [[x.get('submitted_unix_ms') or (x.get('submitted_unix') or 0) * 1000, x.get('fate'), x.get('reason')]
                              for x in rec],
            'recent_cap': 50}


def profile(run, derod_recs=None):
    p = {'start': run[0]['T'], 'end': run[-1]['T'], 'lines': len(run),
         'hours': round((ts(run[-1]['T']) - ts(run[0]['T'])) / 3600, 2)}
    if run[0].get('_src'):
        p['source'] = run[0]['_src']
        p['head_missing'] = not str(run[0].get('M', '')).startswith(START_M)
    for d in run:
        if d.get('Version'):
            p['version'] = d['Version']
        if isinstance(d.get('Arguments'), dict):
            a = d['Arguments']
            p['threads'], p['cpu_max'], p['gpu_mode'] = a.get('--mining-threads'), a.get('--cpu-max'), a.get('--gpu-mode')
            p['gpu'] = a.get('--gpu')
    p['hashrate'] = hashrate_stats(run)
    p['split'] = split_stats(run)
    p['reward'] = reward_stats(run)
    hs, sp = p['hashrate'], p['split']
    if sp.get('lines'):
        sp['regime'] = regime_of(sp.pop('_windows', []), p.get('threads'))
        sp['regime']['stale_fraction'] = sp.get('drop_fraction')
        sp['regime']['cpu_finished'] = sp.get('cpu_finished')
    if hs.get('samples') and sp.get('staged_mean'):
        # share of the TOTAL rate that went through GPU staging; the rest is CPU threads hashing their own nonces
        p['split']['staged_share_of_total'] = round(sp['staged_mean'] / hs['mean'], 3)
        p['split']['own_cpu_hs'] = round(hs['mean'] - sp['staged_mean'], 1)
    if derod_recs is not None and sp.get('window') and sp.get('dropped_in_window') is not None:
        n = heights_in(derod_recs, *sp['window'])
        sp['heights_in_window'] = n
        if n:
            sp['drops_per_height'] = round(sp['dropped_in_window'] / n, 1)
            if sp.get('ring_slots'):
                sp['drops_per_height_vs_ring'] = round(sp['drops_per_height'] / sp['ring_slots'], 3)
    sp.pop('window', None)
    for k in ('first_t', 'last_t'):
        hs.pop(k, None)
    if derod_recs is not None:
        d = drought(own_times(derod_recs), ts(run[0]['T']), ts(run[-1]['T']), hs.get('mean'),
                    p['reward'].get('found_difficulty_median'))
        d['gap_from'] = datetime.datetime.fromtimestamp(d['gap_from']).astimezone().isoformat(timespec='seconds')
        p['shares'] = d
    return p


def rules(p, current=False, now=None, tree_ver=None, contention=None):
    """ALERT/WARN rules for one run. `current`: the run is the miner that is running now, so silence and a stale
    build can be judged against the capture time `now` and this tree's version `tree_ver`. R23 `contention`: the census
    verdict at capture (contention.py); on a contended box the current run's sag is cpu_starved, never hashrate_sag."""
    out, sp, rw, hs = [], p['split'], p['reward'], p['hashrate']
    if current and now is not None and now - ts(p['end']) > SILENT_S:
        out.append(('miner_silent', 'ALERT', f"last record {p['end'][:19]} is {(now - ts(p['end'])) / 60:.0f} min old"))
    sh = p.get('shares') or {}
    if sh.get('expected_in_gap') is not None and sh['expected_in_gap'] >= DROUGHT_EXPECTED:
        out.append(('share_drought', 'ALERT', f"no accepted own miniblock for {sh['longest_gap_s'] / 3600:.2f} h from "
                                              f"{sh['gap_from'][:19]}; the run's rate expected {sh['expected_in_gap']}"))
    if (current and now is not None and p.get('gpu_mode') == 'split' and not sp.get('lines')
            and now - ts(p['start']) > SPLIT_SILENT_S):
        out.append(('split_silent', 'ALERT', f"--gpu-mode=split since {p['start'][:19]} and no 'GPU split' line in "
                                             f"{(now - ts(p['start'])) / 60:.0f} min"))
    if current and tree_ver and p.get('version') and p['version'] != tree_ver:
        out.append(('stale_build', 'WARN', f"running {p['version']}, tree builds {tree_ver}"))
    if p.get('head_missing'):
        out.append(('head_missing', 'WARN', f"{Path(p.get('source', '?')).name} starts mid-run at {p['start'][:19]}"))
    if (sp.get('mismatch') or 0) > 0:
        out.append(('gpu_mismatch', 'ALERT', f"gpu_cpu_mismatch={sp['mismatch']}"))
    if sp.get('disabled'):
        out.append(('split_disabled', 'ALERT', f"split disabled: {sp['disabled']}"))
    if sp.get('sort_disabled'):
        out.append(('sort_disabled', 'ALERT', f"descriptor sort disabled: {sp['sort_disabled'][:160]}"))
    if (sp.get('sort_fallbacks') or 0) > 0:
        out.append(('sort_fallbacks', 'WARN', f"descriptor sort fallbacks={sp['sort_fallbacks']}"))
    if sp.get('restarts_last') is not None and sp.get('restarts_first') is not None and sp['restarts_last'] > sp['restarts_first']:
        out.append(('gpu_restarts', 'WARN', f"split server restarts {sp['restarts_first']} -> {sp['restarts_last']}"))
    if sp.get('drop_fraction') is not None and sp['drop_fraction'] > 0.05:
        out.append(('drop_fraction', 'WARN', f"{sp['drop_fraction'] * 100:.1f} % of staged nonces dropped stale"))
    if rw.get('paid_fraction_recomputed') is not None and rw.get('resolved', 0) >= 20 and rw['paid_fraction_recomputed'] < 0.75:
        out.append(('paid_fraction', 'WARN', f"paid fraction {rw['paid_fraction_recomputed']} over {rw['resolved']} resolved"))
    if hs.get('samples', 0) >= 20 and hs['tail10_mean'] < 0.75 * hs['mean']:
        if current and (contention or {}).get('contended'):
            out.append(('cpu_starved', 'WARN', f"last-10 mean {hs['tail10_mean']} vs run mean {hs['mean']}, attributed: "
                                               f"{contention.get('why')}; law ESTIMATE {contention.get('law_hs_at_miner_cores')} H/s "
                                               f"at {contention.get('miner_cores')} cores"))
        else:
            out.append(('hashrate_sag', 'WARN', f"last-10 mean {hs['tail10_mean']} vs run mean {hs['mean']}"))
    if (rw.get('rejected') or 0) > 0:
        out.append(('rejected', 'WARN', f"{rw['rejected']} rejected miniblock(s)"))
    return out


def fact(p):
    hs, sp, rw = p['hashrate'], p['split'], p['reward']
    return (f"miner run {p['start'][:19]} end={p['end'][:19]} version={p.get('version')} gpu_mode={p.get('gpu_mode')} threads={p.get('threads')} "
            f"hours={p['hours']} samples={hs.get('samples')} mean_hs={hs.get('mean')} median_hs={hs.get('median')} "
            f"p10_hs={hs.get('p10')} p90_hs={hs.get('p90')} staged_mean_hs={sp.get('staged_mean')} "
            f"staged_share={sp.get('staged_share_of_total')} dropped_per_min={sp.get('dropped_per_min')} "
            f"drop_fraction={sp.get('drop_fraction')} drops_per_height={sp.get('drops_per_height')} "
            f"restarts={sp.get('restarts_last')} mismatch={sp.get('mismatch')} fallbacks={sp.get('sort_fallbacks')} "
            f"paid={rw.get('node_paid')} orphaned={rw.get('node_orphaned')} pending={rw.get('node_pending')} "
            f"paid_fraction={rw.get('paid_fraction_recomputed')} luck={rw.get('luck')} "
            f"accepted_in_window={(p.get('shares') or {}).get('submissions')} longest_gap_s={(p.get('shares') or {}).get('longest_gap_s')} "
            f"source={Path(p.get('source') or '?').name} alerts={len(p['alerts'])}")


def regime_fact(p):
    """one anchorable line per run that has split windows (R21): the regime and the counters that decide it"""
    rg = (p.get('split') or {}).get('regime') or {}
    if not rg.get('windows'):
        return None
    return (f"split regime {p['start'][:19]} version={p.get('version')} regime={rg['regime']} windows={rg['windows']} "
            f"seconds={rg['seconds']} staged_median_hs={rg['staged_median_hs']} cpu_backlog_fraction={rg['cpu_backlog_fraction']} "
            f"ring_full_fraction={rg['ring_full_fraction']} idle_tries_per_min={rg['idle_tries_per_min']} "
            f"stale_fraction={rg.get('stale_fraction')} gpu_us_per_hash_median={rg['gpu_us_per_hash_median']} "
            f"cpu_finished={rg.get('cpu_finished')}")


def binding_fact(p):
    """R22: one anchorable line per run with split windows: the binding resource and the fractions that decide it"""
    rg = (p.get('split') or {}).get('regime') or {}
    if not rg.get('windows'):
        return None
    return (f"split binding {p['start'][:19]} version={p.get('version')} binding={rg.get('binding')} "
            f"gpu_busy_fraction={rg.get('gpu_busy_fraction')} cpu_backlog_fraction={rg['cpu_backlog_fraction']} "
            f"ring_full_fraction={rg['ring_full_fraction']} staged_median_hs={rg['staged_median_hs']} "
            f"gpu_ceiling_staged_hs={rg.get('gpu_ceiling_staged_hs')}")


def analyse(log, derod_log=None, use_rpc=True, rpc_url=RPC, now=None, root=ROOT, lookback_h=48, contention=None):
    now = time.time() if now is None else now
    chain = log_chain(log)
    recs, files = chain_records(chain)
    derod_recs = None
    if derod_log and Path(derod_log).exists():
        derod_recs = [d for d in records(derod_log) if d.get('M') in ('Chain extended', OWN_MB)]
    tv = tree_version(root)
    report = {'captured': datetime.datetime.fromtimestamp(now).astimezone().isoformat(timespec='seconds'), 'log': str(log),
              'logs': [str(f) for f in chain], 'files': files, 'tree_version': tv,
              'derod_log': str(derod_log) if derod_recs is not None else None, 'records': len(recs), 'rules': RULES,
              'runs': [], 'facts': [], 'contention': contention}
    runs = [r for r in split_runs(recs) if len(r) >= 5]
    for i, r in enumerate(runs):
        p = profile(r, derod_recs)
        cur = i == len(runs) - 1 and Path(p.get('source') or log) == Path(log)
        p['alerts'] = [{'rule': k, 'level': lv, 'what': w} for k, lv, w in rules(p, cur, now, tv, contention)]
        report['runs'].append(p)
    for f in files:
        report['facts'].append(f"miner log file {Path(f['file']).name} records={f['records']} first={(f['first'] or '-')[:19]} "
                               f"last={(f['last'] or '-')[:19]} starts={f['starts']} head_missing={f['head_missing']} nul_lines={f['nul_lines']}")
    if derod_recs is not None:
        covered = [(ts(p['start']), ts(p['end'])) for p in report['runs']]
        stops = stopped_windows(runs)
        covered += [(a, b) for a, b, _ in stops]                  # R22: a recorded stop explains its silence
        own = own_times(derod_recs)
        gaps = unexplained_gaps(own, covered, now - lookback_h * 3600, now)
        for g in gaps:
            g['from'] = datetime.datetime.fromtimestamp(g['from']).astimezone().isoformat(timespec='seconds')
            g['to'] = datetime.datetime.fromtimestamp(g['to']).astimezone().isoformat(timespec='seconds')
        report['derod_side'] = {'lookback_h': lookback_h, 'own_accepted': sum(1 for t in own if t >= now - lookback_h * 3600),
                                'unexplained_gaps': gaps,
                                'stopped': [{'from': datetime.datetime.fromtimestamp(a).astimezone().isoformat(timespec='seconds'),
                                             'to': datetime.datetime.fromtimestamp(b).astimezone().isoformat(timespec='seconds'),
                                             'hours': round((b - a) / 3600, 2), 'reason': why}
                                            for a, b, why in stops if b >= now - lookback_h * 3600]}
        for s in report['derod_side']['stopped']:
            report['facts'].append(f"miner stopped {s['from']} -> {s['to']} hours={s['hours']} reason={s['reason']!r}")
        report['facts'].append(f"derod own miniblocks last {lookback_h} h accepted={report['derod_side']['own_accepted']} "
                               f"unexplained_gaps={len(gaps)} longest_unexplained_h={max((g['hours'] for g in gaps), default=0)}")
        if gaps and report['runs']:
            report['runs'][-1]['alerts'].append({'rule': 'unexplained_gap', 'level': 'WARN',
                                                 'what': '; '.join(f"{g['from'][:16]} → {g['to'][:16]} ({g['hours']} h)" for g in gaps[:4])})
    report['facts'][:0] = [fact(p) for p in report['runs']]       # run facts first (mine_intel zips them with runs)
    report['facts'] += [f for f in (regime_fact(p) for p in report['runs']) if f]
    report['facts'] += [f for f in (binding_fact(p) for p in report['runs']) if f]
    if use_rpc:
        try:
            o = outcome(rpc_url)
            report['outcome'] = o
            report['facts'].append(
                f"derod mining outcome submitted={o['submitted']} paid={o['paid']} orphaned={o['orphaned_total']} "
                f"orphan_reasons={json.dumps(o['orphaned'], sort_keys=True)} pending={o['pending']} paid_fraction={o['paid_fraction']}")
        except Exception as e:                               # noqa: BLE001 — the node may be down; say so
            report['outcome'] = {'error': f'{type(e).__name__}: {e}'}
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--log', default=str(DEFAULT_LOG))
    ap.add_argument('--derod-log', default=str(DEFAULT_DEROD_LOG))
    ap.add_argument('--no-rpc', action='store_true')
    ap.add_argument('--no-census', action='store_true', help='skip the foreign-process census (G20 then refuses the snapshot)')
    ap.add_argument('--json-only', action='store_true')
    ap.add_argument('--out', help='write here instead of harness/runtime/minerintel_<ts>.json')
    a = ap.parse_args()
    if not Path(a.log).exists():
        print(f'miner_intel: no miner log at {a.log}')
        return 2
    ct = None
    if not a.no_census:                                   # R23: who else holds the CPU, read-only ps, names only
        try:
            spec = importlib.util.spec_from_file_location(f'contention_for_miner_{id(HERE)}', HERE / 'contention.py')
            CT = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(CT)
            ct = CT.measure(3.0, *CT.miner_caps())
            ct['fact'] = CT.fact(ct)
        except Exception as e:                            # noqa: BLE001 — no census is said, never silently allowed
            ct = {'contended': None, 'why': f'census failed: {type(e).__name__}: {e}'}
    rep = analyse(a.log, a.derod_log, not a.no_rpc, contention=ct)
    if ct and ct.get('fact'):
        rep['facts'].append(ct['fact'])
    out = Path(a.out) if a.out else HARNESS / f"runtime/minerintel_{datetime.datetime.now().strftime('%Y%m%dT%H%M%S')}.json"
    write_atomic(out, json.dumps(rep, indent=1, ensure_ascii=False))   # R22: atomic
    if not a.json_only:
        for p in rep['runs']:
            hs, sp, rw = p['hashrate'], p['split'], p['reward']
            print(f"run {p['start'][:19]} → {p['end'][:19]} ({p['hours']} h) {p.get('version')} mode={p.get('gpu_mode')} "
                  f"threads={p.get('threads')} from {Path(p.get('source') or '?').name}")
            if p.get('shares'):
                print(f"   shares (derod-side): {p['shares']['submissions']} accepted in the run; longest gap "
                      f"{p['shares']['longest_gap_s']} s (expected {p['shares']['expected_in_gap']} at the run's rate)")
            print(f"   TOTAL H/s: n={hs.get('samples')} mean {hs.get('mean')} median {hs.get('median')} p10 {hs.get('p10')} "
                  f"p90 {hs.get('p90')} last-10 {hs.get('tail10_mean')}")
            if sp.get('lines'):
                print(f"   split: staged mean {sp.get('staged_mean')} H/s = {sp.get('staged_share_of_total')} of TOTAL "
                      f"(own CPU {sp.get('own_cpu_hs')}); dropped {sp.get('dropped_per_min')}/min = {sp.get('drop_fraction')} "
                      f"of staged work; {sp.get('drops_per_height')} per new height (ring {sp.get('ring_slots')}); "
                      f"restarts {sp.get('restarts_first')}→{sp.get('restarts_last')} mismatch {sp.get('mismatch')} "
                      f"fallbacks {sp.get('sort_fallbacks')}")
                rg = sp.get('regime') or {}
                print(f"   regime: {rg.get('regime')} over {rg.get('windows')} windows: CPU-sort backlog "
                      f"{rg.get('cpu_backlog_fraction')} of the time, ring full {rg.get('ring_full_fraction')}, idle tries "
                      f"{rg.get('idle_tries_per_min')}/min, staged median {rg.get('staged_median_hs')} H/s, GPU "
                      f"{rg.get('gpu_us_per_hash_median')} us/hash")
            print(f"   reward: paid {rw.get('node_paid')} orphaned {rw.get('node_orphaned')} pending {rw.get('node_pending')} "
                  f"paid_fraction {rw.get('paid_fraction_recomputed')} luck {rw.get('luck')} found {rw.get('found_events')} "
                  f"(GPU {rw.get('found_GPU')}, CPU {rw.get('found_CPU')})")
            for al in p['alerts']:
                print(f"   [{al['level']}] {al['rule']}: {al['what']}")
        if rep.get('outcome'):
            print(f"   derod outcome: {rep['outcome']}")
        for f in rep['files']:
            print(f"   file {Path(f['file']).name}: {f['records']} records {str(f['first'])[:19]} → {str(f['last'])[:19]} "
                  f"starts={f['starts']} head_missing={f['head_missing']} nul_lines={f['nul_lines']}")
        if rep.get('derod_side'):
            print(f"   derod side, last {rep['derod_side']['lookback_h']} h: {rep['derod_side']['own_accepted']} own miniblocks; "
                  f"gaps no miner log explains: {rep['derod_side']['unexplained_gaps']}")
        print(f"wrote {out}: {len(rep['runs'])} run(s), {rep['records']:,} records")
    cur = rep['runs'][-1] if rep['runs'] else {}
    return 7 if any(x['level'] == 'ALERT' for x in cur.get('alerts', [])) else 0


if __name__ == '__main__':
    sys.exit(main())
