#!/usr/bin/env python3
"""miner_runs.py — audit the miner's OWN run ledger (bin/dero-miner.runs.jsonl, r21) and join it with derod and the chain.

cmd/dero-miner/runledger.go appends one JSON line per miner run (final line at a clean exit; a checkpoint every 60 s in
<base>.run.json, recovered as "unclean" at the next start). This tool reads both READ-ONLY and:

  1. VALIDATES every line against what the writer promises and against the miner's own log:
       L1 identity   run_id is the start instant in hex nanoseconds and agrees with `start` (same second)
       L2 clock      last - start == uptime_s (+-2 s: both come from one clock at one instant)
       L3 average    avg_hs == hashes / uptime for some uptime in uptime_s +- 0.5 s (+-1 %): the writer rounds uptime_s
                     but divides by the exact uptime (runledger.go), which alone is +-4 % on a 12 s run (r23c)
       L4 outcome    when outcome_known: paid + orphaned + unresolved == accepted miniblocks + accepted blocks
                     (outcome.go tally: every accepted submission is in exactly one bucket)
       L5 log start  a start-up line of the same version in the miner log within 2 s of `start` (when the log still
                     holds that instant)
       L6 log exit   a clean `end` reason has a 'miner exiting' line with that reason within 2 s of `last`
       L7 order      runs do not overlap (start + uptime <= next start)
       L8 coverage   every r21+ run the log shows that has ended has a ledger line (a missing line = lost evidence)
  2. JOINS each run with derod's miniblock ledger (DERO.GetMiningOutcome 'recent', read-only JSON-RPC on 10102):
     fates whose submitted_unix falls inside the run's window. derod's ledger is in memory: a run that ended before
     derod started is NOT in it (covered=false), and the miner's frozen exit record keeps its 'unresolved' forever.
  3. For those runs, JOINS WITH THE CHAIN: the heights of the run's found miniblocks (miner log 'found DERO miniblock'
     lines) against the miniblocks the main-chain blocks at those heights carry (DERO.GetBlock, read-only), keyed by
     the miner's KeyHash learned from the blocks derod says we were paid in (one KeyHash common to all of them, else
     no chain join). The KeyHash and the wallet address are NEVER written anywhere: the output holds counts only.

  4. (R23) THE PAYOUT LEDGER: per run, the shares the run's own hashes should have found (the miner's expected_shares,
     5/(9 D) per hash, ARCHITECTURE 31.2) against what it found and what was PAID (the chain join when it can verify
     finals, else derod's fates, else the miner's frozen exit tally), in DERO at the per-miniblock reward DERIVED from
     blockchain/transaction_execute.go (BaseReward >> ((h + RRI) / RRI), divided over BLOCK_TIME - MINIBLOCK_HIGHDIFF + 1
     miniblocks; tx fees excluded, so paid DERO is a LOWER bound), with an exact (Garwood) 95 % Poisson interval on the
     found count: expected inside it = luck; expected above it = hashes that did not become shares. One line per run is
     kept in harness/runtime/payout_ledger.jsonl (a better source never gets replaced by a worse one: chain > derod >
     ledger), so a run outlives derod's 50-entry memory.
  5. (R23b) IDLE GAPS: every interval between the end of one run (start + uptime_s) and the start of the next, plus
     an open trailing gap when the newest run ended or its 60 s checkpoint went stale (> 180 s), priced at the
     neighbour runs' own expected share rate x the ledger's paid/found fraction x the per-miniblock reward: the DERO the
     idle time forwent (ESTIMATE, fees excluded). Gate G21 recomputes it.

  6. (r28, B50 / H24-5) THE USER'S PAUSE IS NOT FORGONE PAYOUT: while harness/round.json names the miner track
     'paused' (artifacts/dero-rft.md §0.3, kit/roundtracks.py), the OPEN trailing gap (the newest run ended, no run
     since) is the deliberate pause, not idle time: it is booked as paused_s with idle_s 0 and no forgone shares or
     DERO, and uptime_fraction is taken over the span without it. With --paused-since ISO only the part of that gap
     after the instant is paused (the part before it is still priced). Closed gaps between runs are always priced.
     With the track active (or no registry) nothing changes: the R23b ledger exactly.

Writes harness/runtime/minerruns_<ts>.json (one anchorable fact per line). Never writes the ledger or the checkpoint.
  python3 -I harness/intel/miner_runs.py [--ledger bin/dero-miner.runs.jsonl] [--log bin/dero-miner.log] [--no-rpc]
Exit 0 · 6 a validation check failed · 2 no ledger and no checkpoint.
"""
import argparse, datetime, importlib.util, json, math, re, sys, time, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
ROOT = HARNESS.parent
RPC = 'http://127.0.0.1:10102/json_rpc'
CLOCK_SLACK_S = 2.0
AVG_SLACK = 0.01
LOG_SLACK_S = 2.0
FOUND_M = re.compile(r'found DERO (?:mini)?block')       # gpu_split.go / miner.go 'GPU-split found DERO miniblock (submitting)'
CLEAN_ENDS = ('console exit', 'signal', 'interrupt', 'quit', 'bye')
RECENT_CAP = 50                                          # cmd/derod/rpc/mining_outcome.go: 'len(result.Recent) < 50'
# R23: the r22 writer dropped two fields (cmd/dero-miner/runledger.go run_record_from: '... // r22: the caps in force (the
# tuner may move them) Hashes: m.hashes, Height: m.status.height,' — a comment swallowed them), so every r22 row has
# hashes 0 and height 0 while avg_hs (computed from the live counter) is right. Rows with EXACTLY that signature from
# that build are KNOWN (fixed in r23); a zero from any other build still fails L3/L9.
KNOWN_ZERO_HASHES_VERSION = '+22102026.r22'
PAYOUT_LEDGER = HARNESS / 'runtime/payout_ledger.jsonl'
SOURCE_RANK = {'chain': 3, 'derod': 2, 'ledger': 1, None: 0}


def _mi():
    spec = importlib.util.spec_from_file_location(f'miner_intel_for_runs_{id(HERE)}', HERE / 'miner_intel.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


MI = _mi()


def _rt():
    """kit/roundtracks.py of THIS harness (r28 B50): the miner-track state of the current round"""
    spec = importlib.util.spec_from_file_location(f'roundtracks_for_runs_{id(HERE)}', HARNESS / 'kit/roundtracks.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


RT = _rt()


def ts(s):
    """RFC3339 (the ledger) or the log's '2026-10-28T20:20:38.379-0700' -> epoch seconds"""
    try:
        return datetime.datetime.fromisoformat(s).timestamp()
    except ValueError:
        return MI.ts(s)


def parse_ledger(text):
    """(rows, skipped): mirrors runledger.go parse_run_ledger — a torn or foreign line is skipped and COUNTED"""
    rows, skipped = [], 0
    for l in text.splitlines():
        l = l.strip()
        if not l:
            continue
        try:
            r = json.loads(l)
        except ValueError:
            skipped += 1
            continue
        if not isinstance(r, dict) or r.get('kind') != 'run':
            skipped += 1
            continue
        rows.append(r)
    return rows, skipped


def log_events(records):
    """the miner log's run boundaries and found shares: starts [(t, version)], exits [(t, reason)], found [(t, height)]"""
    starts, exits, found = [], [], []
    pending = None
    for d in records:
        try:
            t = MI.ts(d['T'])
        except (KeyError, ValueError, TypeError):
            continue
        m = str(d.get('M', ''))
        if m.startswith(MI.START_M):
            pending = t
        elif pending is not None and d.get('Version'):
            starts.append((pending, str(d['Version'])))
            pending = None
        elif m == 'miner exiting':
            exits.append((t, str(d.get('reason', ''))))
        elif FOUND_M.search(m) and isinstance(d.get('height'), int):
            found.append((t, d['height']))
    return {'starts': starts, 'exits': exits, 'found': found}


def read_log(path):
    out = []
    p = Path(path)
    if not p.exists():
        return out
    for l in p.read_text(errors='replace').splitlines():
        try:
            out.append(json.loads(l))
        except ValueError:
            pass
    return out


def window(r):
    return ts(r['start']), ts(r['last'])


def known_zero_row(r):
    """the exact r22 writer-bug signature: that build, hashes 0 AND height 0, avg_hs > 0"""
    return (str(r.get('version', '')).endswith(KNOWN_ZERO_HASHES_VERSION) and not r.get('hashes') and not r.get('height')
            and bool(r.get('avg_hs')))


# ───────────────────────────── R23 payout ledger ─────────────────────────────
def reward_constants(root=ROOT):
    """(base, rri, minis, anchors): the reward schedule DERIVED from the lines that declare it (never typed here).
    base = (41 * 100000 * BLOCK_TIME) / 600, rri = 210000 * 600 / BLOCK_TIME (blockchain/transaction_execute.go),
    minis per full block = BLOCK_TIME - MINIBLOCK_HIGHDIFF + 1 (blockchain/miniblocks_consensus.go). Go integer division."""
    cfg = (Path(root) / 'config/config.go').read_text()
    tx = (Path(root) / 'blockchain/transaction_execute.go').read_text()
    bt = int(re.search(r'^const BLOCK_TIME = uint64\((\d+)\)', cfg, re.M).group(1))
    hd = int(re.search(r'^const MINIBLOCK_HIGHDIFF = (\d+)', cfg, re.M).group(1))
    m1 = re.search(r'^const RewardReductionInterval = (\d+) \* (\d+) / config\.BLOCK_TIME', tx, re.M)
    m2 = re.search(r'^const BaseReward = \((\d+) \* (\d+) \* config\.BLOCK_TIME\) / (\d+)', tx, re.M)
    if not re.search(r'return BaseReward >> \(\(height \+ RewardReductionInterval\) / RewardReductionInterval\)', tx):
        raise ValueError('CalcBlockReward no longer reads BaseReward >> ((height + RRI) / RRI): re-derive the payout ledger')
    rri = int(m1.group(1)) * int(m1.group(2)) // bt
    base = int(m2.group(1)) * int(m2.group(2)) * bt // int(m2.group(3))
    return base, rri, bt - hd + 1, {'config/config.go': m1 and f'const BLOCK_TIME = uint64({bt})',
                                    'blockchain/transaction_execute.go': m2.group(0)}


def per_miniblock_atomic(height, consts):
    """atomic units one miniblock share is paid at `height` (fees excluded): CalcBlockReward(h) / minis"""
    base, rri, minis = consts[:3]
    return (base >> ((int(height) + rri) // rri)) // minis


def _pois_cdf(k, lam):
    """P(X <= k) for X ~ Poisson(lam), summed in log space (k up to a few thousand)"""
    if k < 0:
        return 0.0
    if lam <= 0:
        return 1.0
    s, term = 0.0, -lam
    for i in range(int(k) + 1):
        if i:
            term += math.log(lam) - math.log(i)
        s += math.exp(term)
    return min(s, 1.0)


def poisson_ci(k, conf=0.95):
    """exact (Garwood) two-sided interval for a Poisson mean from one count k, by bisection on the CDF. Pure."""
    a = (1 - conf) / 2

    def solve(f, lo, hi):
        for _ in range(200):
            mid = (lo + hi) / 2
            if f(mid):
                lo = mid
            else:
                hi = mid
        return round((lo + hi) / 2, 2)
    hi_b = k + 10 + 10 * math.sqrt(k + 1)
    lower = 0.0 if k == 0 else solve(lambda m: 1 - _pois_cdf(k - 1, m) < a, 0.0, hi_b)   # P(X >= k | m) = a
    upper = solve(lambda m: _pois_cdf(k, m) > a, 0.0, hi_b)                              # P(X <= k | m) = a
    return lower, upper


def payout(rows, derod_join, chain_join, consts, height):
    """per run + total: expected vs found vs paid, in shares and DERO, with the Poisson verdict. Pure."""
    dj = {x['run_id']: x for x in derod_join} if isinstance(derod_join, list) else {}
    cj = {x['run_id']: x for x in chain_join} if isinstance(chain_join, list) else {}
    pm = per_miniblock_atomic(height, consts) if height else None
    out = []
    for r in rows:
        rid = r.get('run_id')
        d, c = dj.get(rid) or {}, cj.get(rid) or {}
        exp = r.get('expected_shares')
        found = int(r.get('found_cpu') or 0) + int(r.get('found_gpu') or 0)
        if c.get('found') is not None and c.get('finals_verifiable'):
            paid, src = c['paid_chain'], 'chain'
        elif d.get('covered') and not d.get('partial'):
            paid, src = d['paid'], 'derod'
        else:
            paid, src = int(r.get('paid_cpu') or 0) + int(r.get('paid_gpu') or 0), 'ledger'
        lo, hi = poisson_ci(found)
        if exp is None or exp <= 0:
            v, plow = 'no expectation', None
        else:
            plow = round(_pois_cdf(found, exp), 4)
            v = 'luck (expected inside the 95 % interval)' if lo <= exp <= hi else (
                'below expectation beyond luck' if exp > hi else 'above expectation beyond luck')
        out.append({'run_id': rid, 'start': r.get('start'), 'version': r.get('version'), 'running': r.get('end') == 'running',
                    'uptime_s': r.get('uptime_s'), 'avg_hs': r.get('avg_hs'), 'expected_shares': exp, 'found': found,
                    'paid': paid, 'paid_source': src, 'paid_fraction_of_found': round(paid / found, 4) if found else None,
                    'luck': round(found / exp, 3) if exp else None, 'found_ci95': [lo, hi], 'p_found_at_most': plow,
                    'verdict': v, 'per_miniblock_atomic': pm,
                    'paid_DERO': None if pm is None else round(paid * pm / 1e5, 5),
                    'expected_DERO': None if pm is None or exp is None else round(exp * pm / 1e5, 5),
                    'paid_vs_expected': round(paid / exp, 3) if exp else None})
    E = sum(x['expected_shares'] or 0 for x in out)
    F = sum(x['found'] for x in out)
    P = sum(x['paid'] for x in out)
    lo, hi = poisson_ci(F)
    tot = {'runs': len(out), 'expected_shares': round(E, 2), 'found': F, 'paid': P, 'found_ci95': [lo, hi],
           'luck': round(F / E, 3) if E else None, 'paid_vs_expected': round(P / E, 3) if E else None,
           'verdict': None if not E else ('luck (expected inside the 95 % interval)' if lo <= E <= hi else
                                          ('below expectation beyond luck' if E > hi else 'above expectation beyond luck')),
           'per_miniblock_atomic': pm, 'paid_DERO': None if pm is None else round(P * pm / 1e5, 5),
           'expected_DERO': None if pm is None else round(E * pm / 1e5, 5), 'fees': 'excluded (paid DERO is a lower bound)'}
    return out, tot


IDLE_MIN_S = 5.0                 # a restart shorter than this is not idle time (the miner exits and starts in < 5 s)
CHECKPOINT_STALE_S = 180.0       # runledger.go checkpoints every 60 s: three missed writes = the run is dead, not running


def idle_gaps(rows, now, per_mb, paid_fraction, log_starts=None, paused=False, paused_since=None):
    """R23b: the time the miner was NOT mining between (and after) its runs, and the shares and DERO that time forwent.
    `rows` are ledger rows plus the checkpoint (end 'running'). A gap's share rate is its two neighbour runs' OWN
    expected share rate (sum of expected_shares / sum of uptime_s: their hashes at their difficulty, 5/(9 D) per hash),
    so a gap is priced at what the box was actually doing around it, never at a typed hashrate. Forgone PAID shares =
    forgone shares x paid_fraction (paid / found over the ledger); DERO = paid shares x per-miniblock reward (fees
    excluded). The trailing gap is open when the newest run ended or its checkpoint went stale. `log_starts` (the miner
    log's start-up instants) cross-checks every gap: a start inside one means a run the ledger does not hold (a build
    without the ledger, or a lost line), so that gap is NOT idle and G21 fails it. ESTIMATE. Pure.
    r28 B50: `paused` (the miner track is paused, §0.3) books the OPEN trailing gap as the user's pause: idle_s 0,
    paused_s the gap (from max(gap start, `paused_since`) when that epoch is given; the part before it is a priced idle
    gap of its own), forgone None; totals carry paused_s and uptime_fraction over span - paused_s."""
    rs = sorted([r for r in rows if r.get('start')], key=lambda r: ts(r['start']))
    out = []

    def rate(*xs):
        up = sum(float(x.get('uptime_s') or 0) for x in xs if x.get('expected_shares') is not None)
        ex = sum(float(x.get('expected_shares') or 0) for x in xs if x.get('expected_shares') is not None)
        return ex / up if up > 0 else None

    def row(a, b, s, e, open_):
        r = rate(a, b) if b is not None else rate(a)
        g = e - s
        sh = None if r is None else round(g * r, 2)
        paid = None if sh is None or paid_fraction is None else round(sh * paid_fraction, 2)
        return {'after_run': a.get('run_id'), 'before_run': None if b is None else b.get('run_id'),
                'from': datetime.datetime.fromtimestamp(s).astimezone().isoformat(timespec='seconds'),
                'to': datetime.datetime.fromtimestamp(e).astimezone().isoformat(timespec='seconds'),
                'idle_s': round(g), 'open': open_, 'after_end': a.get('end'),
                'shares_per_min': None if r is None else round(r * 60, 4), 'forgone_shares': sh,
                'forgone_paid_shares': paid,
                'forgone_DERO': None if paid is None or per_mb is None else round(paid * per_mb / 1e5, 5),
                'log_starts_inside': None if log_starts is None else
                sum(1 for x in log_starts if s + LOG_SLACK_S < x < e - LOG_SLACK_S)}
    for a, b in zip(rs, rs[1:]):
        s = ts(a['start']) + float(a.get('uptime_s') or 0)
        e = ts(b['start'])
        if e - s >= IDLE_MIN_S:
            out.append(row(a, b, s, e, False))
    if rs:
        z = rs[-1]
        last = ts(z['last']) if z.get('last') else ts(z['start']) + float(z.get('uptime_s') or 0)
        if z.get('end') != 'running' or now - last > CHECKPOINT_STALE_S:
            if now - last >= IDLE_MIN_S:
                cut = last if not paused or paused_since is None else min(max(last, float(paused_since)), now)
                if paused and cut - last >= IDLE_MIN_S:
                    out.append(row(z, None, last, cut, False))     # idle before the pause began: still priced
                if paused and now - cut > 0:
                    g = row(z, None, cut, now, True)
                    g.update({'paused': True, 'paused_s': g['idle_s'], 'idle_s': 0, 'forgone_shares': None,
                              'forgone_paid_shares': None, 'forgone_DERO': None})
                    out.append(g)
                elif not paused:
                    out.append(row(z, None, last, now, True))
    span = (now - ts(rs[0]['start'])) if rs else 0
    idle = sum(g['idle_s'] for g in out)
    pz = sum(g.get('paused_s') or 0 for g in out)
    tot = {'gaps': len(out), 'idle_s': idle, 'idle_h': round(idle / 3600, 2), 'span_h': round(span / 3600, 2),
           'paused_s': pz, 'paused_h': round(pz / 3600, 2),
           'uptime_fraction': round(1 - idle / (span - pz), 4) if span - pz > 0 else None,
           'forgone_shares': round(sum(g['forgone_shares'] or 0 for g in out), 2),
           'forgone_paid_shares': round(sum(g['forgone_paid_shares'] or 0 for g in out), 2),
           'forgone_DERO': None if per_mb is None else round(sum(g['forgone_DERO'] or 0 for g in out), 5),
           'paid_fraction': paid_fraction, 'per_miniblock_atomic': per_mb,
           'since': rs[0]['start'] if rs else None, 'open_now': bool(out and out[-1]['open']),
           'method': 'neighbour runs expected_shares/uptime_s x idle_s x paid/found x per-miniblock reward (ESTIMATE, fees excluded)'}
    return out, tot


def merge_payout_ledger(path, runs, now_iso):
    """upsert one line per run_id into the long-term payout ledger; a better paid_source is never replaced by a
    worse one (chain > derod > ledger), a running run is always refreshed. Atomic. Returns the merged rows."""
    p = Path(path)
    old = {}
    if p.exists():
        for l in p.read_text().splitlines():
            try:
                x = json.loads(l)
                old[x['run_id']] = x
            except (ValueError, KeyError, TypeError):
                continue
    for x in runs:
        prev = old.get(x['run_id'])
        if prev and not prev.get('running') and SOURCE_RANK.get(prev.get('paid_source'), 0) > SOURCE_RANK.get(x['paid_source'], 0):
            continue
        old[x['run_id']] = {**x, 'updated': now_iso}
    rows = sorted(old.values(), key=lambda x: str(x.get('start')))
    MI.write_atomic(p, '\n'.join(json.dumps(x, sort_keys=True) for x in rows) + '\n')
    return rows


def validate(rows, ev, now, checkpoint=None):
    """per-row checks {name: (ok, why)} plus the ledger-wide L7/L8. Pure (now and the log events are inputs)."""
    out = []
    log_lo = min((t for t, _ in ev['starts']), default=None)
    for r in rows:
        c = {}
        s, l = window(r)
        try:
            rid = int(str(r.get('run_id')), 16) / 1e9
            c['L1 identity'] = (abs(rid - s) < 1.0, f"run_id {r.get('run_id')} = {rid:.0f} vs start {s:.0f}")
        except ValueError:
            c['L1 identity'] = (False, f"run_id {r.get('run_id')!r} is not hex nanoseconds")
        c['L2 clock'] = (abs((l - s) - float(r.get('uptime_s') or 0)) <= CLOCK_SLACK_S,
                         f"last-start {l - s:.0f} s vs uptime_s {r.get('uptime_s')}")
        up = float(r.get('uptime_s') or 0)
        known = known_zero_row(r)
        if up > 0 and r.get('avg_hs'):
            hs = r.get('hashes', 0)
            want = hs / up
            # r23c (measurement close): runledger.go writes uptime_s = math.Round(uptime) but avg_hs = hashes / uptime,
            # so the exact uptime lies in [uptime_s - 0.5, uptime_s + 0.5]; a 12 s run (22:37:24, avg 33966 vs
            # 416148/12 = 34679) failed the old +-1 % around hashes/uptime_s on rounding alone.
            lo_hs, hi_hs = hs / (up + 0.5), (hs / (up - 0.5) if up > 0.5 else float('inf'))
            c['L3 average'] = (lo_hs * (1 - AVG_SLACK) <= r['avg_hs'] <= hi_hs * (1 + AVG_SLACK) or known,
                               f"avg_hs {r['avg_hs']} vs hashes/uptime {want:.0f}"
                               + (' (KNOWN r22 writer bug: hashes/height not written; fixed in r23)' if known else ''))
        acc_n = int(r.get('accepted_miniblocks') or 0) + int(r.get('accepted_blocks') or 0)
        if acc_n > 0:
            # L9 (R23): a run that had shares accepted knew a job height; 0 means the field was not written
            c['L9 height'] = (int(r.get('height') or 0) > 0 or known, f"height {r.get('height')} with {acc_n} accepted"
                              + (' (KNOWN r22 writer bug)' if known else ''))
        if r.get('outcome_known'):
            res = sum(int(r.get(k) or 0) for k in ('paid_cpu', 'paid_gpu', 'orphaned_cpu', 'orphaned_gpu', 'unresolved'))
            acc = int(r.get('accepted_miniblocks') or 0) + int(r.get('accepted_blocks') or 0)
            c['L4 outcome'] = (res == acc, f"paid+orphaned+unresolved {res} vs accepted {acc}")
        if log_lo is not None and s >= log_lo - LOG_SLACK_S:
            hit = [v for t, v in ev['starts'] if abs(t - s) <= LOG_SLACK_S]
            c['L5 log start'] = (bool(hit) and hit[0] == r.get('version'), f"log start-up lines at start: {hit}")
        end = str(r.get('end', ''))
        if end.startswith(CLEAN_ENDS) and log_lo is not None and s >= log_lo - LOG_SLACK_S:
            hit = [why for t, why in ev['exits'] if abs(t - l) <= LOG_SLACK_S]
            c['L6 log exit'] = (end in hit, f"end {end!r}; log exits near last: {hit}")
        out.append({'run_id': r.get('run_id'), 'start': r.get('start'), 'checks': c})
    srt = sorted(rows, key=lambda r: ts(r['start']))
    overl = [f"{a['start']} + {a.get('uptime_s')} s > {b['start']}" for a, b in zip(srt, srt[1:])
             if ts(a['start']) + float(a.get('uptime_s') or 0) > ts(b['start']) + CLOCK_SLACK_S]
    ledger_wide = {'L7 order': (not overl, f'overlaps {overl}' if overl else f'{len(srt)} runs in order')}
    # L8: every ENDED run of a ledger-writing build (one that wrote any ledger line) is in the ledger
    have = {round(ts(r['start'])) for r in rows}
    if checkpoint:
        have.add(round(ts(checkpoint['start'])))
    writers = {r.get('version') for r in rows} | ({checkpoint.get('version')} if checkpoint else set())
    ended = [(t, v) for t, v in ev['starts'] if v in writers and any(e[0] > t for e in ev['exits'])
             and not any(abs(t - h) <= LOG_SLACK_S for h in have)]
    ledger_wide['L8 coverage'] = (not ended, f'ended runs without a ledger line: {ended}' if ended else
                                  f'every ended run of {sorted(x for x in writers if x)} has a line')
    return out, ledger_wide


def join_outcome(rows, outcome, derod_start):
    """per run: derod's fates whose submission instant falls in the run's window (+5 s for the last submit's reply).
    covered=False when the run ended before derod started (derod's ledger is in memory: those fates are gone)."""
    recent = (outcome or {}).get('recent') or []
    out = []
    for r in rows:
        s, l = window(r)
        cov = derod_start is not None and s >= derod_start - 1
        f = [x for x in recent if s <= float(x.get('submitted_unix_ms', x.get('submitted_unix', 0) * 1000)) / 1000 <= l + 5]
        cnt = {k: sum(1 for x in f if x.get('fate') == k) for k in ('paid', 'orphaned', 'pending')}
        res = cnt['paid'] + cnt['orphaned']
        # derod returns its newest 50 fates only: when the list is full and its oldest entry is after the run's start,
        # the run's earlier shares fell off it (partial)
        oldest = min((float(x.get('submitted_unix_ms', x.get('submitted_unix', 0) * 1000)) / 1000 for x in recent), default=None)
        partial = len(recent) >= RECENT_CAP and oldest is not None and oldest > s
        out.append({'run_id': r.get('run_id'), 'covered': cov, 'partial': partial, **cnt,
                    'reasons': sorted({str(x.get('reason')) for x in f if x.get('fate') == 'orphaned'}),
                    'paid_fraction': round(cnt['paid'] / res, 4) if cov and res and not partial else None})
    return out


def learn_keyhash(outcome, get_block):
    """the ONE miniblock KeyHash common to every block derod says paid one of our REGULAR miniblocks (None when zero
    or several). A FINAL miniblock carries another KeyHash (live 2026-10-29: our paid final at 7827040 sits in block
    b84365b0 whose only Final miniblock has KeyHash 11abf0c0, not ours), so paid finals are left out. A block that
    could not be read is skipped, never intersected as empty. Kept in memory only."""
    common = None
    for x in (outcome or {}).get('recent') or []:
        if x.get('fate') != 'paid' or not x.get('block') or x.get('final'):
            continue
        kh = {m['KeyHash'][:32] for m in get_block(hash=x['block']).get('miniblocks', []) if not m.get('Final')}
        if not kh:
            continue
        common = kh if common is None else common & kh
    return next(iter(common)) if common and len(common) == 1 else None


def learn_builder(outcome, get_block):
    """the miner_address of a block derod says WE built (a paid final's 'built' block), or None. A final share is paid
    when the block at its height carries this miner_address. Kept in memory only, never written."""
    for x in (outcome or {}).get('recent') or []:
        if x.get('fate') == 'paid' and x.get('final') and x.get('built'):
            a = (get_block(hash=x['built']).get('miner_tx') or {}).get('miner_address')
            if a:
                return tuple(a)
    return None


def blocks_at_height(h, get_block, topo_guess):
    """every topo-ordered block whose height is h (derod's resolver counts the topo-ordered blocks at a height as main):
    walk from the topoheight guess to the first block of height h, then forward while the height stays h"""
    t = topo_guess
    for _ in range(64):
        b = get_block(topoheight=t)
        bh = b.get('height')
        if bh is None:
            return []
        if bh == h and get_block(topoheight=t - 1).get('height') != h:
            break
        t += (h - bh) if bh != h else -1
    out = []
    for k in range(8):
        b = get_block(topoheight=t + k)
        if b.get('height') != h:
            break
        out.append(b)
    return out


def chain_join(rows, found, keyhash, get_block, topo_of, builder=None):
    """per run: of the heights it found shares at, how many of our shares the main-chain blocks there carry: our
    regular miniblocks (KeyHash) plus one per block WE built (miner_address == builder: a paid final).
    paid_chain = sum over heights of min(found at h, ours at h); orphaned_chain = found - paid_chain.
    finals_verifiable is False without a known builder address (a paid final would then count as orphaned)."""
    out = []
    for r in rows:
        s, l = window(r)
        hs = {}
        for t, h in found:
            if s - 1 <= t <= l + 1:
                hs[h] = hs.get(h, 0) + 1
        paid = 0
        per = {}
        for h, n in sorted(hs.items()):
            bs = blocks_at_height(h, get_block, topo_of(h))
            ours = sum(1 for b in bs for m in b.get('miniblocks', []) if not m.get('Final') and m.get('KeyHash', '')[:32] == keyhash)
            ours += sum(1 for b in bs if builder and tuple((b.get('miner_tx') or {}).get('miner_address') or ()) == builder)
            per[h] = {'found': n, 'ours_on_chain': ours}
            paid += min(n, ours)
        tot = sum(hs.values())
        out.append({'run_id': r.get('run_id'), 'found': tot, 'paid_chain': paid, 'orphaned_chain': tot - paid,
                    'finals_verifiable': builder is not None,
                    'paid_fraction_chain': round(paid / tot, 4) if tot else None, 'heights': per})
    return out


def rpc_call(url, method, params=None):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, **({'params': params} if params else {})}).encode()
    with urllib.request.urlopen(urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'}),
                                timeout=8) as r:
        return json.loads(r.read()).get('result')


def rpc_block_getter(url):
    cache = {}

    def get_block(hash=None, topoheight=None):
        k = hash or topoheight
        if k not in cache:
            p = {'hash': hash} if hash else {'height': topoheight}     # DERO.GetBlock 'height' is a TOPOheight
            try:
                res = rpc_call(url, 'DERO.GetBlock', p) or {}
                cache[k] = json.loads(res.get('json') or '{}')
            except Exception:                                          # noqa: BLE001 — a missing block is no block
                cache[k] = {}
        return cache[k]
    return get_block


def analyse(ledger_path, log_path, use_rpc=True, rpc_url=RPC, now=None, checkpoint_path=None, paused_since=None):
    now = time.time() if now is None else now
    lp = Path(ledger_path)
    text = lp.read_text() if lp.exists() else ''
    rot = Path(str(lp) + '.1')
    if rot.exists():
        text = rot.read_text() + '\n' + text
    rows, skipped = parse_ledger(text)
    cp = Path(checkpoint_path) if checkpoint_path else lp.with_name(lp.name.replace('.runs.jsonl', '.run.json'))
    checkpoint = None
    if cp.exists():
        try:
            checkpoint = json.loads(cp.read_text())
        except ValueError:
            checkpoint = None
    ev = log_events(read_log(log_path))
    per, wide = validate(rows, ev, now, checkpoint)
    rep = {'captured': datetime.datetime.fromtimestamp(now).astimezone().isoformat(timespec='seconds'),
           'ledger': str(lp), 'log': str(log_path), 'rows': rows, 'skipped_lines': skipped, 'checkpoint': checkpoint,
           'validation': per, 'ledger_checks': {k: {'ok': v[0], 'why': v[1]} for k, v in wide.items()}}
    if use_rpc:
        try:
            outcome = rpc_call(rpc_url, 'DERO.GetMiningOutcome')
            info = rpc_call(rpc_url, 'DERO.GetInfo') or {}
            up = None
            try:
                with urllib.request.urlopen(rpc_url.replace('/json_rpc', '/metrics'), timeout=8) as r:
                    m = re.search(r'^app_uptime_seconds (\S+)', r.read().decode(errors='replace'), re.M)
                    up = float(m.group(1)) if m else None
            except Exception:                                          # noqa: BLE001
                up = None
            derod_start = now - up if up is not None else None
            allrows = rows + ([checkpoint] if checkpoint else [])
            rep['derod'] = {'start': derod_start, 'submitted': (outcome or {}).get('submitted'),
                            'paid': (outcome or {}).get('paid'), 'pending': (outcome or {}).get('pending')}
            rep['derod_join'] = join_outcome(allrows, outcome, derod_start)
            gb = rpc_block_getter(rpc_url)
            kh = learn_keyhash(outcome, gb)
            if kh:
                off = int(info.get('topoheight', 0)) - int(info.get('height', 0))
                rep['chain_join'] = chain_join(allrows, ev['found'], kh, gb, lambda h: h + off, learn_builder(outcome, gb))
            else:
                rep['chain_join'] = {'error': 'no single KeyHash common to the blocks derod says paid us: no chain join'}
            rep['tip_height'] = info.get('height')
        except Exception as e:                                         # noqa: BLE001 — node down is a reading
            rep['derod_join'] = {'error': f'{type(e).__name__}: {e}'}
    # R23: the payout ledger (expected vs found vs paid, DERO, Poisson verdict); without derod, the ledger's own tally
    try:
        consts = reward_constants()
        h = rep.get('tip_height') or max((int(r.get('height') or 0) for r in rows + ([checkpoint] if checkpoint else [])), default=0)
        pr, pt = payout(rows + ([checkpoint] if checkpoint else []), rep.get('derod_join'), rep.get('chain_join'), consts, h)
        rep['payout'] = {'height': h, 'reward_base_atomic': consts[0], 'reward_rri': consts[1], 'minis_per_block': consts[2],
                         'runs': pr, 'total': pt}
        # R23b: idle gaps between runs and what they forwent, priced at the neighbour runs' own share rate
        pf = round(pt['paid'] / pt['found'], 4) if pt.get('found') else None
        st, _ = RT.track_state(RT.load(HARNESS / 'round.json'))      # r28 B50: the user's pause is not forgone
        gaps, gt = idle_gaps(rows + ([checkpoint] if checkpoint else []), now, pt.get('per_miniblock_atomic'), pf,
                             [x for x, _ in ev['starts']], paused=st == 'paused', paused_since=paused_since)
        gt['miner_track'] = st
        rep['idle'] = {'gaps': gaps, 'total': gt}
    except (OSError, ValueError, AttributeError) as e:
        rep['payout'] = {'error': f'{type(e).__name__}: {e}'}
    rep['facts'] = facts(rep)
    return rep


def facts(rep):
    f = []
    dj = {x['run_id']: x for x in rep.get('derod_join') or [] if isinstance(x, dict)} if isinstance(rep.get('derod_join'), list) else {}
    cj = {x['run_id']: x for x in rep.get('chain_join') or []} if isinstance(rep.get('chain_join'), list) else {}
    for r, v in zip(rep['rows'], rep['validation']):
        bad = [k for k, (ok, _) in v['checks'].items() if not ok]
        d, c = dj.get(r.get('run_id')) or {}, cj.get(r.get('run_id')) or {}
        f.append(f"miner run {r['start']} version={r.get('version')} end={r.get('end')!r} uptime_s={r.get('uptime_s')} "
                 f"avg_hs={r.get('avg_hs')} accepted={int(r.get('accepted_miniblocks') or 0) + int(r.get('accepted_blocks') or 0)} "
                 f"ledger_paid={int(r.get('paid_cpu') or 0) + int(r.get('paid_gpu') or 0)} "
                 f"ledger_orphaned={int(r.get('orphaned_cpu') or 0) + int(r.get('orphaned_gpu') or 0)} "
                 f"ledger_unresolved={r.get('unresolved')} derod_covered={d.get('covered')} derod_paid={d.get('paid')} "
                 f"derod_orphaned={d.get('orphaned')} chain_found={c.get('found')} chain_paid={c.get('paid_chain')} "
                 f"chain_orphaned={c.get('orphaned_chain')} checks_failed={bad}")
    cp = rep.get('checkpoint')
    if cp:
        d, c = dj.get(cp.get('run_id')) or {}, cj.get(cp.get('run_id')) or {}
        f.append(f"miner run (running) {cp.get('start')} version={cp.get('version')} last={cp.get('last')} uptime_s={cp.get('uptime_s')} "
                 f"avg_hs={cp.get('avg_hs')} derod_paid={d.get('paid')} derod_orphaned={d.get('orphaned')} "
                 f"derod_pending={d.get('pending')} derod_paid_fraction={d.get('paid_fraction')} chain_found={c.get('found')} "
                 f"chain_paid={c.get('paid_chain')}")
    po = rep.get('payout') or {}
    for x in po.get('runs') or []:
        f.append(f"payout run {x['start']} running={x['running']} expected_shares={x['expected_shares']} found={x['found']} "
                 f"paid={x['paid']} paid_source={x['paid_source']} luck={x['luck']} found_ci95={x['found_ci95']} "
                 f"p_found_at_most={x['p_found_at_most']} paid_DERO={x['paid_DERO']} expected_DERO={x['expected_DERO']} "
                 f"verdict={x['verdict']!r}")
    if po.get('total'):
        t = po['total']
        f.append(f"payout total runs={t['runs']} expected_shares={t['expected_shares']} found={t['found']} paid={t['paid']} "
                 f"luck={t['luck']} paid_vs_expected={t['paid_vs_expected']} found_ci95={t['found_ci95']} "
                 f"per_miniblock_atomic={t['per_miniblock_atomic']} height={po.get('height')} paid_DERO={t['paid_DERO']} "
                 f"expected_DERO={t['expected_DERO']} verdict={t['verdict']!r} fees=excluded")
    idl = rep.get('idle') or {}
    for g in idl.get('gaps') or []:
        f.append(f"idle gap {g['from']} -> {g['to']} idle_s={g['idle_s']} open={g['open']} after_end={g['after_end']!r} "
                 f"shares_per_min={g['shares_per_min']} forgone_shares={g['forgone_shares']} "
                 f"forgone_paid_shares={g['forgone_paid_shares']} forgone_DERO={g['forgone_DERO']} "
                 f"log_starts_inside={g['log_starts_inside']}")
    if idl.get('total'):
        t = idl['total']
        f.append(f"idle total gaps={t['gaps']} idle_h={t['idle_h']} span_h={t['span_h']} uptime_fraction={t['uptime_fraction']} "
                 f"forgone_shares={t['forgone_shares']} forgone_paid_shares={t['forgone_paid_shares']} "
                 f"forgone_DERO={t['forgone_DERO']} paid_fraction={t['paid_fraction']} open_now={t['open_now']} "
                 f"paused_h={t.get('paused_h', 0)} miner_track={t.get('miner_track', 'active')} (ESTIMATE)")
    lc = rep['ledger_checks']
    f.append(f"miner run ledger rows={len(rep['rows'])} skipped_lines={rep['skipped_lines']} "
             + ' '.join(f"{k.split()[0]}={'ok' if v['ok'] else 'FAIL'}" for k, v in lc.items()))
    return f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--ledger', default=str(ROOT / 'bin/dero-miner.runs.jsonl'))
    ap.add_argument('--log', default=str(ROOT / 'bin/dero-miner.log'))
    ap.add_argument('--checkpoint')
    ap.add_argument('--no-rpc', action='store_true')
    ap.add_argument('--out')
    ap.add_argument('--payout-ledger', help='with --out: merge the payout rows into this file instead of none')
    ap.add_argument('--paused-since', help="r28 B50: ISO instant the user paused the miner (only the open gap after it is "
                                           "paused; default: the whole open gap while the track is 'paused')")
    a = ap.parse_args()
    if not Path(a.ledger).exists() and not (a.checkpoint and Path(a.checkpoint).exists()):
        print(f'miner_runs: no ledger at {a.ledger}')
        return 2
    rep = analyse(a.ledger, a.log, not a.no_rpc, checkpoint_path=a.checkpoint,
                  paused_since=ts(a.paused_since) if a.paused_since else None)
    out = Path(a.out) if a.out else HARNESS / f"runtime/minerruns_{datetime.datetime.now().strftime('%Y%m%dT%H%M%S')}.json"
    MI.write_atomic(out, json.dumps(rep, indent=1, ensure_ascii=False))
    if (rep.get('payout') or {}).get('runs') and not a.out:
        merge_payout_ledger(PAYOUT_LEDGER, rep['payout']['runs'], rep['captured'])
    elif (rep.get('payout') or {}).get('runs') and a.payout_ledger:
        merge_payout_ledger(a.payout_ledger, rep['payout']['runs'], rep['captured'])
    for x in rep['facts']:
        print(x)
    bad = [(v['start'], k, why) for v in rep['validation'] for k, (ok, why) in v['checks'].items() if not ok]
    bad += [('ledger', k, v['why']) for k, v in rep['ledger_checks'].items() if not v['ok']]
    for b in bad:
        print('   FAIL', *b)
    print(f'wrote {out}')
    return 6 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
