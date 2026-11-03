#!/usr/bin/env python3
"""contention.py — who else is using the CPU: a READ-ONLY census of the process table, and the contention law.

R23. The live r22 miner ran at 54-67k H/s instead of 84-86k because other processes (six to seven foreign renderer
processes at ~100 % CPU each, nice 0, hours old) took its cores: over 721 s of 2026-10-29 the miner's H/s followed the
cores it got, H/s = 4,817 x cores + 8,000 (r = 0.991; metrics_intel.py STARVED_BUDGET comment). A pipeline A/B, a
hashrate 'regression' or a 'sag' measured in that state says nothing about the build. This module names the state:

  sample()      one `ps -A -o pid=,nice=,time=,etime=,comm=` (read-only; nothing is signalled, reniced or attached)
  census()      two samples -> CPU cores per process NAME (cumulative CPU time delta / wall delta), grouped by name,
                classed miner | node | foreign. Only the executable's BASENAME is kept: no pid, no args, no path, so no
                user path and no command line ever reaches a snapshot (safe_name; KAT IK39 proves it).
  verdict()     contended when the foreign processes take more cores than the box has left after the miner's
                --cpu-max budget and the node, plus CONTENDED_SLACK_CORES; the law turns the cores the miner did not
                get into an H/s ESTIMATE (law_hs / law_loss_hs).

  python3 -I harness/intel/contention.py [--interval 5] [--threads 20 --cpu-max 90] [--json]
Exit 0 quiet · 5 contended · 2 ps failed.
"""
import argparse, json, os, re, subprocess, sys, time
from pathlib import Path

# R22 fit (metrics_intel.py: 'H/s = 4,817 x cores + 8,000, r = 0.991'): an ESTIMATE, valid for the r21/r22 split
# miner at 13-16 cores; outside that range it is an extrapolation and is labelled so by its users.
LAW_SLOPE_HS_PER_CORE = 4817.0
LAW_INTERCEPT_HS = 8000.0
LAW_R = 0.991
LAW_FIT_CORES = (13.0, 16.0)
CONTENDED_SLACK_CORES = 1.0     # scheduler noise, ps itself, Spotlight bursts: one core of foreign load is not contention
STARVED_BUDGET = 0.80           # the miner got < 80 % of its --cpu-max core budget (metrics_intel.STARVED_BUDGET)
MINER_NAMES = ('dero-miner', 'gpu_split_server', 'gpu_hash_sais')
NODE_NAMES = ('derod',)
TOP = 8
PS_CMD = ['ps', '-A', '-o', 'pid=,nice=,time=,etime=,comm=']
HOME = str(Path.home())


def safe_name(comm):
    """the executable's basename only: no directory (so no user path), no arguments, printable, <= 48 chars"""
    c = str(comm or '').strip()
    if HOME and HOME in c:
        c = c.replace(HOME, '')
    c = c.rstrip('/').rsplit('/', 1)[-1]
    c = re.sub(r'[^\x20-\x7e]', '?', c)
    return c[:48] or '?'


def seconds(t):
    """ps 'time'/'etime' -> seconds: [[dd-]hh:]mm:ss[.cc] (macOS lets minutes run past 60: '2311:44.51')"""
    t = str(t).strip()
    days = 0
    if '-' in t:
        d, t = t.split('-', 1)
        days = int(d)
    parts = [float(x) for x in t.split(':')]
    s = 0.0
    for p in parts:
        s = s * 60 + p
    return days * 86400 + s


def parse_ps(text):
    """{pid: (name, nice, cpu_s, etime_s)} from PS_CMD output; a line that does not parse is skipped"""
    out = {}
    for l in (text or '').splitlines():
        f = l.split(None, 4)
        if len(f) < 5:
            continue
        try:
            pid, nice = int(f[0]), int(f[1]) if f[1].lstrip('-').isdigit() else 0
            out[pid] = (safe_name(f[4]), nice, seconds(f[2]), seconds(f[3]))
        except ValueError:
            continue
    return out


def ps_text(run=subprocess.run):
    """ps output; a failed ps raises (R23 merge: its empty stdout used to read as an idle box)"""
    r = run(PS_CMD, capture_output=True, text=True, timeout=20)
    if r.returncode != 0:
        raise subprocess.SubprocessError(f'ps exited {r.returncode}: {(r.stderr or "").strip()[:200]}')
    return r.stdout


def sample(ps=ps_text, clock=time.time):
    """(t, {pid: (name, nice, cpu_s, etime_s)})"""
    return clock(), parse_ps(ps())


def klass(name):
    if name in MINER_NAMES:
        return 'miner'
    if name in NODE_NAMES:
        return 'node'
    return 'foreign'


def census(s0, s1):
    """cores per process name over [t0, t1]. A pid in both samples contributes its CPU-time delta; a pid born inside
    the window contributes all of its CPU time; a pid that died is lost (its last slice is unknown, undercount)."""
    (t0, a), (t1, b) = s0, s1
    dt = t1 - t0
    # R23 merge: a sample with no parseable rows is a failed ps, not an idle box: no census (counts as contended
    # downstream), never all-zero cores that would let a regression claim through
    if dt <= 0 or not a or not b:
        return None
    by = {}
    for pid, (name, nice, cpu, et) in b.items():
        if pid in a and a[pid][0] == name:
            d = cpu - a[pid][2]
        elif et <= dt + 1:
            d = cpu
        else:
            continue                         # pid reused or first seen without a baseline: no honest delta
        g = by.setdefault(name, {'name': name, 'class': klass(name), 'procs': 0, 'cores': 0.0, 'nice_min': nice,
                                 'oldest_s': 0})
        g['procs'] += 1
        g['cores'] += max(d, 0.0) / dt
        g['nice_min'] = min(g['nice_min'], nice)
        g['oldest_s'] = max(g['oldest_s'], int(et))
    groups = sorted(by.values(), key=lambda g: -g['cores'])
    for g in groups:
        g['cores'] = round(g['cores'], 2)
    tot = {k: round(sum(g['cores'] for g in groups if g['class'] == k), 2) for k in ('miner', 'node', 'foreign')}
    fg = [g for g in groups if g['class'] == 'foreign' and g['cores'] >= 0.05]
    return {'interval_s': round(dt, 1), 'cores': tot,
            'foreign_procs': sum(g['procs'] for g in fg), 'foreign_nice0_cores': round(sum(g['cores'] for g in fg if g['nice_min'] <= 0), 2),
            'top_foreign': fg[:TOP], 'other_foreign_cores': round(sum(g['cores'] for g in fg[TOP:]), 2),
            'miner_groups': [g for g in groups if g['class'] == 'miner']}


def law_hs(cores):
    return None if cores is None else round(LAW_SLOPE_HS_PER_CORE * cores + LAW_INTERCEPT_HS)


def verdict(c, ncpu=None, threads=None, cpu_max=None, load1=None):
    """the contention verdict from one census. Pure. budget = threads x cpu_max/100 when the miner's caps are known."""
    ncpu = ncpu or os.cpu_count() or 1
    if c is None:
        return {'contended': None, 'why': 'no census (one sample, or ps failed)'}
    budget = round(threads * cpu_max / 100.0, 2) if threads and cpu_max else None
    miner, node, foreign = c['cores']['miner'], c['cores']['node'], c['cores']['foreign']
    reserved = (budget if budget is not None else miner) + node
    headroom = round(max(ncpu - reserved, 0.0), 2)
    contended = foreign > headroom + CONTENDED_SLACK_CORES
    bf = round(miner / budget, 3) if budget else None
    loss = None
    if budget and miner < budget:
        loss = round(LAW_SLOPE_HS_PER_CORE * (budget - miner))
    top = ', '.join(f"{g['name']} x{g['procs']} {g['cores']}" for g in c['top_foreign'][:4]) or 'none'
    why = (f"foreign {foreign} cores ({c['foreign_procs']} procs; top {top}) vs headroom {headroom} = {ncpu} cpus - "
           f"{'budget ' + str(budget) if budget is not None else 'miner ' + str(miner)} - node {node} (+{CONTENDED_SLACK_CORES} slack)")
    in_fit = LAW_FIT_CORES[0] <= miner <= LAW_FIT_CORES[1]
    return {'contended': contended, 'why': why, 'ncpu': ncpu, 'load1': None if load1 is None else round(load1, 2),
            'miner_cores': miner, 'node_cores': node, 'foreign_cores': foreign, 'budget_cores': budget,
            'budget_fraction': bf, 'starved': bf is not None and bf < STARVED_BUDGET, 'headroom_cores': headroom,
            'law_hs_at_miner_cores': law_hs(miner) if miner else None, 'law_hs_at_budget': law_hs(budget) if budget else None,
            'law_loss_hs': loss, 'law_in_fit_range': in_fit,
            'law': f'H/s = {LAW_SLOPE_HS_PER_CORE:.0f} x cores + {LAW_INTERCEPT_HS:.0f} (r = {LAW_R}, fit {LAW_FIT_CORES[0]:.0f}-{LAW_FIT_CORES[1]:.0f} cores; ESTIMATE)',
            'top_foreign': c['top_foreign'], 'interval_s': c['interval_s'], 'regression_claims': 'refused' if contended else 'allowed'}


def miner_caps(url='http://127.0.0.1:10110/metrics', get=None):
    """(threads, cpu_max) of the running miner from its /metrics (read-only GET), or (None, None)"""
    try:
        if get is None:
            import urllib.request
            with urllib.request.urlopen(urllib.request.Request(url, method='GET'), timeout=5) as r:
                text = r.read().decode(errors='replace')
        else:
            text = get(url)
    except Exception:                                   # noqa: BLE001 — no miner is a reading
        return None, None
    th = re.search(r'^dero_miner_threads (\S+)', text, re.M)
    du = re.search(r'^dero_miner_cpu_duty_percent (\S+)', text, re.M)
    return (int(float(th.group(1))) if th else None), (int(float(du.group(1))) if du else None)


def measure(interval=5.0, threads=None, cpu_max=None, ps=ps_text, sleep=time.sleep, clock=time.time, ncpu=None):
    """two samples `interval` apart -> verdict (with the census inside). Read-only."""
    s0 = sample(ps, clock)
    sleep(interval)
    s1 = sample(ps, clock)
    try:
        load1 = os.getloadavg()[0]
    except OSError:
        load1 = None
    return verdict(census(s0, s1), ncpu, threads, cpu_max, load1)


def fact(v):
    """one anchorable line; process names only"""
    top = ';'.join(f"{g['name']}x{g['procs']}:{g['cores']}" for g in (v.get('top_foreign') or [])[:4]) or 'none'
    return (f"live contention contended={v.get('contended')} foreign_cores={v.get('foreign_cores')} miner_cores={v.get('miner_cores')} "
            f"budget_cores={v.get('budget_cores')} headroom_cores={v.get('headroom_cores')} load1={v.get('load1')} "
            f"law_hs_at_miner_cores={v.get('law_hs_at_miner_cores')} law_hs_at_budget={v.get('law_hs_at_budget')} "
            f"law_loss_hs={v.get('law_loss_hs')} regression_claims={v.get('regression_claims')} top={top} "
            f"interval_s={v.get('interval_s')}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--interval', type=float, default=5.0)
    ap.add_argument('--threads', type=int)
    ap.add_argument('--cpu-max', type=int)
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()
    th, cm = (a.threads, a.cpu_max) if a.threads and a.cpu_max else miner_caps()
    try:
        v = measure(a.interval, th, cm)
    except (OSError, subprocess.SubprocessError) as e:
        print(f'contention: ps failed: {e}')
        return 2
    print(json.dumps(v, indent=1) if a.json else fact(v))
    return 5 if v.get('contended') else 0


if __name__ == '__main__':
    sys.exit(main())
