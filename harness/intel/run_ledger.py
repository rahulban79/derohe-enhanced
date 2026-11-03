#!/usr/bin/env python3
"""run_ledger.py — the long-term miner run ledger: one JSON line per miner run, kept after its log has rotated away.

The miner log is a chain of at most four files (cmd/dero-miner/minerlog.go: 32 MiB, <exe>.log.1..3) and every
miner_intel snapshot keeps only what that chain held at its capture time. This tool folds both into
harness/runtime/run_ledger.jsonl, sorted by run start, so a week of runs stays comparable on one page:

  1. every harness/runtime/minerintel_*.json snapshot (they preserve runs whose log text is gone);
  2. a fresh miner_intel.analyse() of the live rotated chain (READ-ONLY);
  3. derod's DERO.GetMiningOutcome (read-only JSON-RPC on 10102), attached ONLY to the current run and labelled with
     its capture time: the ledger is derod-wide since derod started, not per miner run.

One row per run start. MERGE RULE: a run keeps the observation with the latest `end` (the longest window seen); an
equal or shorter observation never replaces it, so re-running is idempotent and a run never shrinks or vanishes. A
row whose log began mid-run (head_missing) is a FRAGMENT: it is dropped when a row of the same version covers its
whole window, and kept (flagged) otherwise.

  python3 -I harness/intel/run_ledger.py [--log bin/dero-miner.log] [--derod-log …] [--no-rpc] [--ledger file]
Exit 0 · 2 no source at all.
"""
import argparse, datetime, importlib.util, json, os, sys, tempfile, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
LEDGER = HARNESS / 'runtime/run_ledger.jsonl'
FIELDS = ('start', 'end', 'hours', 'version', 'gpu_mode', 'threads', 'mean_hs', 'samples', 'staged_mean_hs', 'regime',
          'cpu_backlog_fraction', 'stale_fraction', 'shares_accepted_derod', 'miner_paid', 'miner_orphaned',
          'paid_fraction', 'head_missing', 'source', 'observed')


def _mi():
    spec = importlib.util.spec_from_file_location(f'miner_intel_for_ledger_{id(HERE)}', HERE / 'miner_intel.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


MI = _mi()


def row(p, source, observed):
    """one ledger row from a miner_intel run profile. Pure."""
    hs, sp, rw = p.get('hashrate') or {}, p.get('split') or {}, p.get('reward') or {}
    rg = sp.get('regime') or {}
    paid, orph = rw.get('node_paid'), rw.get('node_orphaned')
    r = {'start': p['start'], 'end': p['end'], 'hours': p.get('hours'), 'version': p.get('version'),
         'gpu_mode': p.get('gpu_mode'), 'threads': p.get('threads'), 'mean_hs': hs.get('mean'), 'samples': hs.get('samples', 0),
         'staged_mean_hs': sp.get('staged_mean'), 'regime': rg.get('regime'),
         'cpu_backlog_fraction': rg.get('cpu_backlog_fraction'), 'stale_fraction': sp.get('drop_fraction'),
         'shares_accepted_derod': (p.get('shares') or {}).get('submissions'), 'miner_paid': paid, 'miner_orphaned': orph,
         # the miner's own REWARD STATS ledger (node_paid / node_orphaned), recomputed: resolved shares only
         'paid_fraction': round(paid / (paid + orph), 4) if paid is not None and orph is not None and (paid + orph) else None,
         'head_missing': bool(p.get('head_missing')), 'source': source, 'observed': observed}
    return {k: r[k] for k in FIELDS}


def window_join(r, recent, cap=50):
    """R22: derod's fates INSIDE this run's window [start, end + 5 s] from miner_intel's outcome.recent_window
    ([submitted_ms, fate, reason]). None when no fate falls in the window and the window is older than the list
    (derod forgot it, or restarted since); partial when the list is full and starts after the run. Pure."""
    if not recent:
        return None
    s, e = MI.ts(r['start']), MI.ts(r['end'])
    f = [x for x in recent if s <= (x[0] or 0) / 1000 <= e + 5]
    oldest = min((x[0] or 0) / 1000 for x in recent)
    if not f and e < oldest:
        return None
    c = {k: sum(1 for x in f if x[1] == k) for k in ('paid', 'orphaned', 'pending')}
    partial = len(recent) >= cap and oldest > s
    res = c['paid'] + c['orphaned']
    return {**c, 'partial': partial, 'paid_fraction': round(c['paid'] / res, 4) if res and not partial else None}


def chain_fix(r, cj):
    """R22 merge (H22-5 review): a run's exit line freezes the miner's share fates (shares pending at exit never
    resolve), so a closed run's miner_paid / paid_fraction can be wrong (the 20:20 r21 run: 0 of 1 resolved at exit,
    2 of 3 on the chain). cj is that run's miner_runs.chain_join entry: our shares on the main chain. The row keeps
    chain_outcome; when the fractions differ, paid_fraction becomes the chain's and the exit value is kept as
    paid_fraction_exit (paid_source 'chain'). Pure; cj None or without a fraction returns r unchanged."""
    if not cj or cj.get('paid_fraction_chain') is None:
        return r
    out = dict(r)
    out['chain_outcome'] = {'run_id': cj.get('run_id'), 'found': cj.get('found'), 'paid': cj.get('paid_chain'),
                            'orphaned': cj.get('orphaned_chain'), 'paid_fraction': cj['paid_fraction_chain'],
                            'finals_verifiable': cj.get('finals_verifiable')}
    exit_pf = r.get('paid_fraction_exit', r.get('paid_fraction'))
    if exit_pf != cj['paid_fraction_chain']:
        out['paid_fraction_exit'] = exit_pf
        out['paid_fraction'] = cj['paid_fraction_chain']
        out['paid_source'] = 'chain'
    return out


def merge(old, new):
    """old + new rows -> the ledger. One row per start; the latest `end` wins (ties keep the old row); a head_missing
    fragment inside a same-version row's window is dropped. Pure; sorted by start."""
    by = {}
    for r in list(old) + list(new):
        k = r['start']
        if k not in by or MI.ts(r['end']) > MI.ts(by[k]['end']):
            keep = dict(r)
            if k in by and by[k].get('derod_outcome') and not keep.get('derod_outcome'):
                keep['derod_outcome'] = by[k]['derod_outcome']
            if k in by and by[k].get('chain_outcome') and not keep.get('chain_outcome'):   # R22 merge: keep the chain fates
                co = by[k]['chain_outcome']
                keep = chain_fix(keep, {'run_id': co.get('run_id'), 'found': co.get('found'), 'paid_chain': co.get('paid'),
                                        'orphaned_chain': co.get('orphaned'), 'paid_fraction_chain': co.get('paid_fraction'),
                                        'finals_verifiable': co.get('finals_verifiable')})
            by[k] = keep
        elif r.get('derod_outcome') and MI.ts(r['end']) == MI.ts(by[k]['end']) and not by[k].get('derod_outcome'):
            by[k]['derod_outcome'] = r['derod_outcome']
    rows = sorted(by.values(), key=lambda r: MI.ts(r['start']))
    out = []
    for r in rows:
        if r.get('head_missing') and any(
                o is not r and not o.get('head_missing') and o.get('version') == r.get('version')
                and MI.ts(o['start']) <= MI.ts(r['start']) and MI.ts(r['end']) <= MI.ts(o['end']) for o in rows):
            continue
        out.append(r)
    return out


def read_ledger(path):
    out = []
    p = Path(path)
    if not p.exists():
        return out
    for l in p.read_text().splitlines():
        l = l.strip()
        if l:
            out.append(json.loads(l))       # a corrupt ledger line is an error, never silently skipped
    return out


def write_ledger(path, rows):
    """atomic: temp file in the same directory, then rename (a crash never leaves half a ledger)"""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix='.run_ledger.')
    with os.fdopen(fd, 'w') as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + '\n')
    os.replace(tmp, p)


def from_snapshot(path):
    d = json.loads(Path(path).read_text())
    return [row(p, f'snapshot:{Path(path).name}', d.get('captured')) for p in d.get('runs', []) if p.get('start')]


def build(ledger=LEDGER, log=None, derod_log=None, use_rpc=True, snapshots=None, now=None, rpc_url=None):
    """the new ledger rows (written by the caller). `snapshots`: minerintel_*.json files to backfill from."""
    old = read_ledger(ledger)
    new = []
    for s in sorted(snapshots if snapshots is not None else (HARNESS / 'runtime').glob('minerintel_*.json')):
        new += from_snapshot(s)
    if log and Path(log).exists():
        rep = MI.analyse(log, derod_log, use_rpc, **({'rpc_url': rpc_url} if rpc_url else {}),
                         now=time.time() if now is None else now)
        live = [row(p, 'live:' + Path(p.get('source') or log).name, rep['captured']) for p in rep['runs']]
        o = rep.get('outcome') or {}
        if live and o and 'error' not in o:
            live[-1]['derod_outcome'] = {'captured': rep['captured'], 'scope': 'derod since its start (not per miner run)',
                                         'submitted': o.get('submitted'), 'paid': o.get('paid'),
                                         'orphaned': o.get('orphaned_total'), 'pending': o.get('pending'),
                                         'paid_fraction': None if o.get('paid_fraction') is None else round(o['paid_fraction'], 4)}
        for x in live:                                      # R22: per-run join with derod's fates (window)
            x['derod_window'] = window_join(x, o.get('recent_window') or [], o.get('recent_cap') or 50) \
                if o and 'error' not in o else None
        new += live
    return merge(old, new)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--log', default=str(MI.DEFAULT_LOG))
    ap.add_argument('--derod-log', default=str(MI.DEFAULT_DEROD_LOG))
    ap.add_argument('--no-rpc', action='store_true')
    ap.add_argument('--ledger', default=str(LEDGER))
    a = ap.parse_args()
    if not Path(a.log).exists() and not list((HARNESS / 'runtime').glob('minerintel_*.json')):
        print('run_ledger: no miner log and no minerintel snapshot')
        return 2
    rows = build(a.ledger, a.log, a.derod_log if Path(a.derod_log).exists() else None, not a.no_rpc)
    write_ledger(a.ledger, rows)
    for r in rows:
        print(f"{r['start'][:16]} {r['hours']:>6} h {str(r['version'])[-14:]:>14} {str(r['gpu_mode']):>5} mean {r['mean_hs']} "
              f"staged {r['staged_mean_hs']} {r['regime']} backlog {r['cpu_backlog_fraction']} stale {r['stale_fraction']} "
              f"accepted {r['shares_accepted_derod']} paid {r['miner_paid']}/{r['miner_orphaned']} pf {r['paid_fraction']}"
              + (' FRAGMENT' if r['head_missing'] else '') + (f" · derod {r['derod_outcome']}" if r.get('derod_outcome') else ''))
    print(f'wrote {a.ledger}: {len(rows)} run(s)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
