#!/usr/bin/env python3
"""levers_read.py — r30 post-close (rft §2.29, §0.12 D-22/D-23, §7 B291): the verdict on the R30 quiet-window miner levers
from ONE live run of the miner, against the run before it on the same build, read from the miner's own log only.

The user (2026-11-12) applies --cpu-max 100, --gpu-max 100 and DERO_GSPLIT=8192,3,2 and runs the miner for about 1 h
before Round 31: "make sure to tweak your harness for this change for this round alone - so that you can give the
verdict" and "make sure 1 hr miner run results in no drift i.e it should get all the needed data for next round of miner
improvements". This tool does that WITHOUT weakening any gate (G34 and the 24 h payout reads keep their minimum windows):

  runs      the newest miner run (AFTER) and the run before it (BEFORE, default) are cut at the miner's start-up lines;
            each run's configuration is read from its own lines: build version, CPU duty cap, GPU split geometry
            (batch,depth,inflight of 'GPU split mode ACTIVE'), gpu_max of its 'GPU split' lines
  config    levers_applied: AFTER runs the expected levers (default 8192,3,2 / gpu_max 100 / cap 100) and BEFORE did not
  hash      VALID only when AFTER is a full G34 window (n >= 240, covered >= 3,600 s, CONTINUOUS) on the SAME build as
            BEFORE; ratio = mean AFTER / mean BEFORE; noise = the standard error of 20-line block means of both runs;
            GAIN / LOSS beyond 2 noise, else WITHIN-NOISE; otherwise PARTIAL (the ratio is printed, never a verdict)
  next      the data the next miner round starts from: H/cpu-s, cores, P/E law (live_law, B27), GPU busy, staged H/s,
            own share and the GPU-side cap G (the ceiling model), stale share (B26), feeder backlog / ring-full / idle
  rewards   accepted miniblocks per hour and per 10^9 hashes from the miner's cumulative REWARD STATS of each run, with a
            Poisson 95 % interval on AFTER; always PARTIAL under 24 h of AFTER (the luck spread decides nothing shorter)
  node      derod log (the rotated chain, miner_intel.derod_chain): ERROR lines and the longest 'Chain extended' gap inside
            AFTER, so a starved node (--cpu-max 100 leaves no CPU headroom) shows
Read-only: the logs only (no RPC, no getwork, no P2P).

  nice -n 15 python3 -I harness/intel/levers_read.py [--log bin/dero-miner.launchd.log] [--derod-log …/derod.log]
       [--expect-geom 8192,3,2] [--expect-gpu-max 100] [--expect-cap 100] [--json] [--write]
       # --write: harness/runtime/r30_levers_read_<ts>.json + .txt
  exit 0 a reading was made (any verdict) · 2 fewer than two runs in the log
KAT: harness/kat/test_levers_read_r30.py.
"""
import datetime, importlib.util, json, math, re, statistics, sys
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


HO = _load('ho_levers', HERE / 'hashrate_objective.py')
MI = _load('mi_levers', HERE / 'miner_intel.py')
BLOCK = 20                     # TOTAL lines per block mean (5 min at 15 s): the noise estimate over autocorrelated lines
GEOM_M = 'GPU split mode ACTIVE'
DEROD_LOG = Path(os.path.expanduser(os.environ.get('DERO_DATADIR', '~/dero-data')) + '/logs/derod.log')


def runs_of(recs):
    """[(i0, i1)] record index ranges of each miner run (cut at its start-up line). Pure."""
    starts = [i for i, r in enumerate(recs) if r['M'].startswith(HO.START_M)]
    return [(a, (starts[k + 1] - 1) if k + 1 < len(starts) else len(recs) - 1) for k, a in enumerate(starts)]


def config(run):
    """{version, cpu_cap, geometry, gpu_max} of one run from its own lines. Pure."""
    c = {'version': None, 'cpu_cap': 100, 'geometry': None, 'gpu_max': None}
    for r in run:
        f = r['f']
        if c['version'] is None and f.get('Version'):
            c['version'] = f['Version']
        m = HO.CAP_RX.search(r['M'])
        if m:
            c['cpu_cap'] = int(m.group(1))
        if r['M'].startswith(GEOM_M) and c['geometry'] is None and f.get('batch'):
            c['geometry'] = f"{f.get('batch')},{f.get('depth')},{f.get('inflight')}"
        if r['M'] == 'GPU split' and f.get('gpu_max') is not None:
            c['gpu_max'] = int(HO.num(f['gpu_max']))
    return c


def block_se(vals, block=BLOCK):
    """(mean, standard error of the mean from block means) of a series. Pure."""
    if not vals:
        return None, None
    blocks = [statistics.fmean(vals[i:i + block]) for i in range(0, len(vals) - block + 1, block)]
    se = statistics.stdev(blocks) / math.sqrt(len(blocks)) if len(blocks) >= 2 else None
    return statistics.fmean(vals), se


def run_numbers(run):
    rows = HO.total_rows(run)
    splits = HO.split_rows(run)
    win = HO.window_from_rows(rows, 'run') if rows else None
    hs = [r['hs'] for r in rows]
    mean, se = block_se(hs)
    rewards = [r['f'] for r in run if r['M'] == 'REWARD STATS']
    last = rewards[-1] if rewards else {}
    t0, t1 = (run[0]['t'], run[-1]['t']) if run else (0, 0)
    staged = HO.mean([s['staged'] for s in splits])
    g = [s['f'] for s in [r for r in run if r['M'] == 'GPU split']]
    stale = [HO.num(r['f'].get('stale_sha_skipped')) for r in run if r['M'] == 'TOTAL hashrate' and r['f'].get('H/s_raw')]
    raw = [r['hs_raw'] for r in rows if r.get('hs_raw')]
    return {'window': win, 'mean_hs': mean, 'se_hs': se, 'n': len(rows),
            'h_cpu_s': HO.mean([r['hcpu'] for r in rows]), 'cores': HO.mean([r['cores'] for r in rows]),
            'gpu_busy_pct': HO.mean([s['busy_pct'] for s in splits]), 'staged_hs': staged,
            'own_share': round(1 - staged / mean, 4) if staged and mean else None,
            'g_cap_hs': (round((splits[-1]['gpu_max'] / 100.0) / (HO.mean([s['t_busy_us'] for s in splits]) * 1e-6))
                         if splits and splits[-1].get('gpu_max') and HO.mean([s['t_busy_us'] for s in splits]) else None),
            'stale_share': (round(sum(x - y for x, y in zip(raw, hs[-len(raw):])) / sum(raw), 5) if raw else None),
            'law': HO.live_law(rows),
            'feeder': {k: HO.mean([HO.num(x.get(k)) for x in g]) for k in ('feeder_cpu_backlog_ms', 'feeder_ring_full_ms', 'cpu_idle_tries')},
            'rewards': {'accepted_miniblocks': last.get('accepted_miniblocks'), 'accepted_blocks': last.get('accepted_blocks'),
                        'rejected': last.get('rejected'), 'hours': round((t1 - t0) / 3600, 3)},
            'seconds': t1 - t0}


def hash_verdict(after, before, same_build):
    """(word, detail). Pure."""
    w = after['window'] or {}
    full = (after['n'] >= HO.MIN_WINDOW_N and (w.get('covered_s') or 0) >= HO.MIN_WINDOW_S and w.get('continuity') == 'CONTINUOUS')
    if not (after['mean_hs'] and before['mean_hs']):
        return 'NO-DATA', 'a run has no TOTAL lines'
    ratio = after['mean_hs'] / before['mean_hs']
    se = math.sqrt(sum((x['se_hs'] or 0) ** 2 for x in (after, before))) / before['mean_hs']
    det = f'ratio {ratio:.4f} (after {after["mean_hs"]:,.0f} / before {before["mean_hs"]:,.0f} H/s), noise ±{2 * se:.4f} (2 SE)'
    if not same_build:
        return 'PARTIAL', det + ' · the two runs are different builds: not a lever verdict'
    if not full:
        return 'PARTIAL', det + f' · AFTER is not a full G34 window (n {after["n"]}, covered {w.get("covered_s")} s, {w.get("continuity")})'
    if ratio - 1 > 2 * se:
        return 'GAIN', det
    if 1 - ratio > 2 * se:
        return 'LOSS', det
    return 'WITHIN-NOISE', det


def reward_read(after, before):
    """per-hour and per-10^9-hash miniblock rates; always PARTIAL under 24 h of AFTER. Pure."""
    out = {}
    for name, x in (('after', after), ('before', before)):
        n, h = x['rewards']['accepted_miniblocks'], x['rewards']['hours']
        gh = (x['mean_hs'] or 0) * x['seconds'] / 1e9
        out[name] = {'miniblocks': n, 'hours': h, 'per_hour': round(n / h, 3) if n is not None and h else None,
                     'per_ghash': round(n / gh, 4) if n is not None and gh else None}
    a, b = out['after'], out['before']
    if a['per_ghash'] and b['per_ghash'] and a['miniblocks']:
        lo, hi = [max(0.0, a['miniblocks'] + s * 1.96 * math.sqrt(a['miniblocks'])) for s in (-1, 1)]
        gh = (after['mean_hs'] or 0) * after['seconds'] / 1e9
        out['per_ghash_ratio'] = round(a['per_ghash'] / b['per_ghash'], 3)
        out['per_ghash_ratio_95'] = [round(lo / gh / b['per_ghash'], 3), round(hi / gh / b['per_ghash'], 3)]
    out['label'] = 'PARTIAL (< 24 h of AFTER: luck decides nothing shorter)' if after['seconds'] < 86400 else 'FULL (>= 24 h)'
    return out


def node_read(derod_log, t0, t1):
    """ERROR lines and the longest 'Chain extended' gap of the derod log chain inside [t0, t1]. Read-only."""
    errs, ext = 0, []
    for f in MI.derod_chain(derod_log) if Path(derod_log).exists() else []:
        for d in MI.records(f):
            try:
                t = MI.ts(d['T'])
            except (KeyError, ValueError):
                continue
            if t0 <= t <= t1:
                errs += d.get('L') == 'ERROR'
                if d.get('M') == 'Chain extended':
                    ext.append(t)
    ext.sort()
    gap = max((b - a for a, b in zip(ext, ext[1:])), default=None)
    return {'errors': errs, 'chain_extended': len(ext), 'longest_gap_s': round(gap, 1) if gap is not None else None}


def analyse(log, derod_log=None, expect=('8192,3,2', 100, 100)):
    p = Path(log)
    recs = HO.read_records(p.read_text(errors='replace') if p.exists() else '')
    rs = runs_of(recs)
    if len(rs) < 2:
        return None
    (a0, a1), (b0, b1) = rs[-1], rs[-2]
    A, B = recs[a0:a1 + 1], recs[b0:b1 + 1]
    ca, cb = config(A), config(B)
    na, nb = run_numbers(A), run_numbers(B)
    same = bool(ca['version']) and ca['version'] == cb['version']
    geom, gmax, cap = expect
    applied = ca['geometry'] == geom and ca['gpu_max'] == gmax and ca['cpu_cap'] == cap
    word, det = hash_verdict(na, nb, same)
    rep = {'tool': 'harness/intel/levers_read.py', 'captured': datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
           'log': HO.rel(p), 'after': {'config': ca, **na}, 'before': {'config': cb, **nb}, 'same_build': same,
           'levers_applied': applied, 'expected': {'geometry': geom, 'gpu_max': gmax, 'cpu_cap': cap},
           'hash': {'verdict': word if applied else ('PARTIAL' if word != 'NO-DATA' else word),
                    'detail': det + ('' if applied else f' · AFTER does not run the expected levers ({ca})')},
           'rewards': reward_read(na, nb)}
    if derod_log:
        rep['node'] = node_read(derod_log, A[0]['t'], A[-1]['t'])
    return rep


def text(rep):
    a, b, h = rep['after'], rep['before'], rep['hash']
    L = [f"levers read (rft B291): hash {h['verdict']} — {h['detail']}",
         f"  AFTER  {a['config']} · {a['window']['first'] if a['window'] else '-'} .. {a['window']['last'] if a['window'] else '-'} n {a['n']} · "
         f"{a['mean_hs'] and round(a['mean_hs'])} H/s, {a['h_cpu_s'] and round(a['h_cpu_s'])} H/cpu-s, {a['cores'] and round(a['cores'], 2)} cores, GPU {a['gpu_busy_pct'] and round(a['gpu_busy_pct'], 1)} %",
         f"  BEFORE {b['config']} · n {b['n']} · {b['mean_hs'] and round(b['mean_hs'])} H/s, {b['h_cpu_s'] and round(b['h_cpu_s'])} H/cpu-s, {b['cores'] and round(b['cores'], 2)} cores",
         f"  levers applied {rep['levers_applied']} · same build {rep['same_build']}",
         f"  next round: staged {a['staged_hs'] and round(a['staged_hs'])} H/s, own {a['own_share']}, G cap {a['g_cap_hs']}, stale {a['stale_share']}, law {a['law'].get('status')} "
         f"{a['law'].get('r_P', '')} {a['law'].get('r_E', '')}, feeder {a['feeder']}",
         f"  rewards {rep['rewards']['label']}: {json.dumps({k: v for k, v in rep['rewards'].items() if k != 'label'})}"]
    if rep.get('node'):
        L.append(f"  node: {rep['node']}")
    return '\n'.join(L)


def main(argv):
    import argparse
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    ap = argparse.ArgumentParser()
    ap.add_argument('--log')
    ap.add_argument('--derod-log', default=str(DEROD_LOG))
    ap.add_argument('--expect-geom', default='8192,3,2')
    ap.add_argument('--expect-gpu-max', type=int, default=100)
    ap.add_argument('--expect-cap', type=int, default=100)
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--write', action='store_true')
    a = ap.parse_args(argv)
    log = Path(a.log) if a.log else (HO.pick_log(ROOT) or ROOT / HO.LOGS[0])
    rep = analyse(log, a.derod_log, (a.expect_geom, a.expect_gpu_max, a.expect_cap))
    if rep is None:
        print('levers_read: fewer than two miner runs in the log')
        return 2
    print(json.dumps(rep, indent=1, default=str) if a.json else text(rep))
    if a.write:
        ts = datetime.datetime.now().strftime('%Y%m%dT%H%M')
        base = ROOT / f'harness/runtime/r30_levers_read_{ts}'
        Path(f'{base}.json').write_text(json.dumps(rep, indent=1, default=str) + '\n')
        Path(f'{base}.txt').write_text(text(rep) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
