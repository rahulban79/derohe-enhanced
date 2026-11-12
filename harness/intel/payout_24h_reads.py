#!/usr/bin/env python3
"""payout_24h_reads.py — r30 (rft §7 B2, B39, B7; §8 payout plan PO3, PO6, PO7): the three 24 h payout reads the miner
track resumed (user decision (a), 2026-11-08), as one tool the coordinator runs after 2026-11-09 21:19 PST (24 h after
the launchd bootstrap of 2026-11-08 21:19:22).

Every read is a DELTA between snapshots of the live counters, never a single scrape: derod's counters are since ITS
start, so a window is first snapshot -> last snapshot, and a counter that falls between two snapshots (derod or miner
restarted) restarts from 0: its delta is the sum of the rises plus the value after each fall (DR3).

  snap   append one snapshot to harness/runtime/r30_24h_snaps.jsonl: derod /metrics (127.0.0.1:10102/metrics; the
         getwork_*, miniblock_ours_*, p2p_miniblock_* series), derod GetInfo height and GetMiningOutcome COUNTS (no
         'recent', no hashes), the miner /metrics (127.0.0.1:10110; dero_miner_* counters). Read-only; never getwork/P2P.
  b2     orphans by reason vs delivery latency (PO3): the window's miniblock_ours_orphaned_total{reason} deltas kept apart
         (DR2), paid/submitted deltas, the mean first / median / last ack seconds of our miniblocks (sum/count deltas),
         and per-interval orphan counts against the interval's mean median-ack (the correlation once >= 3 intervals).
  b39    the final-flip delay (PO6): getwork_final_flip_l9_seconds mean over the window (sum/count deltas),
         getwork_final_flip_slow_total (> 150 ms) and getwork_final_flips_total deltas, dead normal jobs per 128 flips.
         The REFUTED lead (GWO24-1, rft §9) stands; this is the 24 h re-read.
  b7     the dispatcher read (PO7): getwork_stale_height_jobs_total per block (height delta), superseded jobs, dispatch
         by reason, the miner's split stale drops by reason. The payout gain itself stays an ESTIMATE (+0.3-2 %): it is
         not observable from counters; the label says so even on a full window.

  r30 B252 (DR5, a window that spans a session pause or a restart): the window is CLASSIFIED, never silently merged.
  derod and the miner are detached and keep counting while the session is paused, so snapshots far apart are still one
  window: CONTINUOUS. A restart between two snapshots (miner uptime_seconds falls, or any kept counter falls) is a gap:
  the window is SEGMENTED, the gap is recorded (from, to, seconds, which side restarted) and every delta that crosses it
  is a LOWER BOUND (what was counted between the last reading and the restart is lost; DR3 keeps the value after it).

  A window shorter than 24 h is REFUSED (exit 5, 'window < 24 h') unless --partial, which labels the read PARTIAL
  (never a verdict) (DR1, DR4).

  nice -n 15 python3 -I harness/intel/payout_24h_reads.py snap
  nice -n 15 python3 -I harness/intel/payout_24h_reads.py b2|b39|b7 [--since ISO] [--until ISO] [--live] [--partial] [--json]
        # --live first takes a fresh snapshot (the window's end = now)
  exit 0 read · 2 fewer than two snapshots in the window · 5 window < 24 h (without --partial) · 6 a source unreachable (snap)
"""
import datetime, json, re, sys, time, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SNAPS = 'harness/runtime/r30_24h_snaps.jsonl'
DEROD_METRICS = 'http://127.0.0.1:10102/metrics'
MINER_METRICS = 'http://127.0.0.1:10110/metrics'
RPC = 'http://127.0.0.1:10102/json_rpc'
DAY_S = 86400.0
DEROD_KEEP = re.compile(r'^(getwork_|miniblock_ours_|p2p_miniblock_)')
MINER_KEEP = re.compile(r'^dero_miner_(hashes_total|stale_sha_skipped_total|split_stale_drops_total|split_stale_sha_skipped_total'
                        r'|found_total|paid_total|orphaned_total|accepted_|uptime_seconds|cpu_seconds_total)')
METRIC_RX = re.compile(r'^([a-zA-Z_:][\w:]*(?:\{[^}]*\})?)\s+(-?[\d.eE+]+)\s*$')


def parse_metrics(text, keep):
    """{series: value} of the kept series; histogram buckets dropped (sum/count kept). Pure."""
    out = {}
    for l in text.splitlines():
        if not l or l[0] == '#' or '_bucket' in l:
            continue
        m = METRIC_RX.match(l.strip())
        if m and keep.match(m.group(1)):
            try:
                out[m.group(1)] = float(m.group(2))
            except ValueError:
                pass
    return out


def counter_delta(values):
    """the increase of a counter over a series of readings; a fall means a restart from 0, so the value after it counts
    in full (DR3). None readings are skipped. Pure."""
    vs = [v for v in values if v is not None]
    if len(vs) < 2:
        return 0.0 if vs else None
    d = 0.0
    for a, b in zip(vs, vs[1:]):
        d += (b - a) if b >= a else b
    return d


def series(snaps, side, key):
    return [(s.get(side) or {}).get(key) for s in snaps]


def window(snaps, since=None, until=None):
    """the snapshots inside [since, until], oldest first. Pure."""
    out = [s for s in snaps if (since is None or s['t'] >= since) and (until is None or s['t'] <= until)]
    return sorted(out, key=lambda s: s['t'])


def continuity(snaps):
    """DR5: {'class': CONTINUOUS | SEGMENTED, 'segments': [{from, to, snapshots}], 'gaps': [{from, to, s, why}]}.
    A gap = a restart between two consecutive snapshots: the miner's uptime fell, or a kept counter of a side fell.
    Snapshot spacing alone is never a gap (the daemons keep counting). Pure."""
    gaps, segs, start = [], [], 0
    for i, (a, b) in enumerate(zip(snaps, snaps[1:]), 1):
        why = []
        for side in ('derod', 'miner'):
            da, db = a.get(side) or {}, b.get(side) or {}
            fell = [k for k in da if k in db and isinstance(da[k], (int, float)) and isinstance(db[k], (int, float))
                    and db[k] < da[k] and (k.endswith('_total') or k.endswith('_count') or k.endswith('_sum')
                                          or k == 'dero_miner_uptime_seconds')]
            if fell:
                why.append(f'{side} restarted ({len(fell)} counter(s) fell, e.g. {sorted(fell)[0]})')
        if why:
            gaps.append({'from': a.get('iso'), 'to': b.get('iso'), 's': round(b['t'] - a['t'], 1), 'why': '; '.join(why)})
            segs.append((start, i - 1))
            start = i
    if snaps:
        segs.append((start, len(snaps) - 1))
    return {'class': 'SEGMENTED' if gaps else 'CONTINUOUS', 'gaps': gaps,
            'segments': [{'from': snaps[x].get('iso'), 'to': snaps[y].get('iso'), 'snapshots': y - x + 1} for x, y in segs],
            'deltas': 'lower bound across each gap (DR5)' if gaps else 'exact (one window)'}


def window_label(snaps, partial):
    """(ok_to_read, label, hours). < 24 h: refused unless partial (then PARTIAL, never a verdict). Pure."""
    if len(snaps) < 2:
        return False, 'NO-WINDOW (fewer than two snapshots)', 0.0
    h = (snaps[-1]['t'] - snaps[0]['t']) / 3600.0
    if h * 3600.0 >= DAY_S:
        return True, 'FULL (>= 24 h)', round(h, 2)
    if partial:
        return True, f'PARTIAL ({h:.2f} h < 24 h): not a verdict', round(h, 2)
    return False, 'window < 24 h', round(h, 2)


def labels(snaps, side, prefix):
    """the label sets of one metric family present in any snapshot, e.g. {'block_race', 'slots_full'}"""
    rx = re.compile(re.escape(prefix) + r'\{reason="([^"]+)"\}')
    out = set()
    for s in snaps:
        for k in (s.get(side) or {}):
            m = rx.fullmatch(k)
            if m:
                out.add(m.group(1))
    return sorted(out)


def mean_of(snaps, base):
    s, c = counter_delta(series(snaps, 'derod', base + '_sum')), counter_delta(series(snaps, 'derod', base + '_count'))
    return (round(s / c, 6) if s is not None and c else None), (int(c) if c is not None else None)


def read_b2(snaps):
    orph = {r: int(counter_delta(series(snaps, 'derod', f'miniblock_ours_orphaned_total{{reason="{r}"}}')) or 0)
            for r in labels(snaps, 'derod', 'miniblock_ours_orphaned_total')}
    paid = counter_delta(series(snaps, 'derod', 'miniblock_ours_paid_total'))
    sub = counter_delta(series(snaps, 'derod', 'miniblock_ours_submitted_total'))
    tot = sum(orph.values())
    out = {'orphaned_by_reason': orph, 'paid': int(paid or 0), 'submitted': int(sub or 0),
           'orphan_rate': round(tot / (tot + paid), 4) if paid is not None and tot + paid else None}
    for k in ('first', 'median', 'last'):
        out[f'{k}_ack_mean_s'], out[f'{k}_ack_n'] = mean_of(snaps, f'miniblock_ours_{k}_ack_seconds')
    iv = []
    for a, b in zip(snaps, snaps[1:]):
        o = sum(int(counter_delta([(a.get('derod') or {}).get(f'miniblock_ours_orphaned_total{{reason="{r}"}}'),
                                   (b.get('derod') or {}).get(f'miniblock_ours_orphaned_total{{reason="{r}"}}')]) or 0)
                for r in orph)
        lat, nn = mean_of([a, b], 'miniblock_ours_median_ack_seconds')
        if lat is not None:
            iv.append((o, lat))
    out['intervals'] = len(iv)
    out['orphans_vs_median_ack_pearson'] = pearson(iv) if len(iv) >= 3 else 'pending (< 3 intervals)'
    return out


def pearson(pts):
    xs, ys = [p[0] for p in pts], [p[1] for p in pts]
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    sxy = sum((x - mx) * (y - my) for x, y in pts)
    sxx = sum((x - mx) ** 2 for x in xs)
    syy = sum((y - my) ** 2 for y in ys)
    return round(sxy / (sxx * syy) ** 0.5, 3) if sxx and syy else 'undefined (no variation)'


def read_b39(snaps):
    mean, cnt = mean_of(snaps, 'getwork_final_flip_l9_seconds')
    slow = counter_delta(series(snaps, 'derod', 'getwork_final_flip_slow_total'))
    flips = counter_delta(series(snaps, 'derod', 'getwork_final_flips_total'))
    dead = counter_delta(series(snaps, 'derod', 'getwork_dead_normal_jobs_total'))
    return {'flip_l9_mean_ms': round(mean * 1000, 2) if mean is not None else None, 'flip_l9_n': cnt,
            'slow_gt_150ms': int(slow or 0), 'flips': int(flips or 0),
            'dead_normal_jobs_per_128_flips': round(128 * dead / flips, 2) if flips and dead is not None else None,
            'lead': 'REFUTED as a dispatcher defect in r24 (GWO24-1, rft §9): a re-read, not a re-opened defect'}


def read_b7(snaps):
    hs = [s.get('height') for s in snaps if s.get('height')]
    blocks = (hs[-1] - hs[0]) if len(hs) >= 2 and hs[-1] >= hs[0] else None
    stale = counter_delta(series(snaps, 'derod', 'getwork_stale_height_jobs_total'))
    sup = counter_delta(series(snaps, 'derod', 'getwork_jobs_superseded_total'))
    disp = {r: int(counter_delta(series(snaps, 'derod', f'getwork_job_dispatch_total{{reason="{r}"}}')) or 0)
            for r in labels(snaps, 'derod', 'getwork_job_dispatch_total')}
    mdrop = {}
    for s in snaps:
        for k in (s.get('miner') or {}):
            m = re.fullmatch(r'dero_miner_split_stale_drops_total\{reason="([^"]+)"\}', k)
            if m:
                mdrop[m.group(1)] = None
    for r in mdrop:
        mdrop[r] = int(counter_delta(series(snaps, 'miner', f'dero_miner_split_stale_drops_total{{reason="{r}"}}')) or 0)
    return {'blocks': blocks, 'stale_height_jobs': int(stale or 0),
            'stale_height_jobs_per_block': round(stale / blocks, 3) if blocks and stale is not None else None,
            'jobs_superseded': int(sup or 0), 'dispatch_by_reason': disp, 'miner_split_stale_drops': mdrop,
            'gain': 'ESTIMATE +0.3-2 % (rft §7 B7): not observable from counters; stale-height jobs are harmless (do not "fix")'}


READS = {'b2': read_b2, 'b39': read_b39, 'b7': read_b7}


def http_get(url, timeout=10):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode(errors='replace')


def rpc(method, timeout=10):
    req = urllib.request.Request(RPC, data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method}).encode(),
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read()).get('result') or {}


def take_snap():
    """(snapshot, errors) from the live sources, read-only. Counts only: no hashes, no addresses."""
    now = time.time()
    s = {'t': now, 'iso': datetime.datetime.fromtimestamp(now).astimezone().isoformat(timespec='seconds')}
    errs = []
    try:
        s['derod'] = parse_metrics(http_get(DEROD_METRICS), DEROD_KEEP)
    except Exception as e:                                       # noqa: BLE001
        errs.append(f'derod /metrics: {type(e).__name__}')
    try:
        s['miner'] = parse_metrics(http_get(MINER_METRICS), MINER_KEEP)
    except Exception as e:                                       # noqa: BLE001
        errs.append(f'miner /metrics: {type(e).__name__}')
    try:
        s['height'] = rpc('DERO.GetInfo').get('height')
    except Exception as e:                                       # noqa: BLE001
        errs.append(f'GetInfo: {type(e).__name__}')
    try:
        o = rpc('DERO.GetMiningOutcome')
        s['outcome'] = {k: o.get(k) for k in ('submitted', 'paid', 'orphaned', 'pending')}
    except Exception as e:                                       # noqa: BLE001
        errs.append(f'GetMiningOutcome: {type(e).__name__}')
    s['errors'] = errs
    return s, errs


def load_snaps(path):
    out = []
    p = Path(path)
    if p.exists():
        for l in p.read_text().splitlines():
            try:
                d = json.loads(l)
                if isinstance(d.get('t'), (int, float)):
                    out.append(d)
            except ValueError:
                pass
    return out


def append_snap(path, s):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open('a') as f:
        f.write(json.dumps(s, sort_keys=True) + '\n')


def main(argv):
    import argparse
    if not argv or {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    ap = argparse.ArgumentParser()
    ap.add_argument('cmd', choices=['snap'] + sorted(READS))
    ap.add_argument('--snaps', default=str(ROOT / SNAPS))
    ap.add_argument('--since')
    ap.add_argument('--until')
    ap.add_argument('--live', action='store_true')
    ap.add_argument('--partial', action='store_true')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args(argv)
    if a.cmd == 'snap' or a.live:
        s, errs = take_snap()
        append_snap(a.snaps, s)
        if a.cmd == 'snap':
            print(f"snapshot {s['iso']}: derod {len(s.get('derod') or {})} series, miner {len(s.get('miner') or {})}, "
                  f"height {s.get('height')}, outcome {s.get('outcome')}" + (f' · errors {errs}' if errs else ''))
            return 6 if errs else 0
    tp = (lambda v: None if not v else datetime.datetime.fromisoformat(v.replace(' ', 'T')).astimezone().timestamp())
    snaps = window(load_snaps(a.snaps), tp(a.since), tp(a.until))
    ok, label, hours = window_label(snaps, a.partial)
    if not ok:
        print(f'{a.cmd}: {label} ({hours} h over {len(snaps)} snapshot(s)); re-run after the window is 24 h or pass --partial')
        return 2 if label.startswith('NO-WINDOW') else 5
    cont = continuity(snaps)                                     # DR5
    if cont['class'] == 'SEGMENTED':
        label += f" · SEGMENTED ({len(cont['gaps'])} restart gap(s)): deltas are lower bounds"
    rep = {'read': a.cmd, 'label': label, 'hours': hours, 'from': snaps[0]['iso'], 'to': snaps[-1]['iso'],
           'snapshots': len(snaps), 'continuity': cont, 'result': READS[a.cmd](snaps)}
    print(json.dumps(rep, indent=1) if a.json else
          f"{a.cmd} [{label}] {rep['from']} .. {rep['to']} ({hours} h, {len(snaps)} snapshots): {json.dumps(rep['result'])}")
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
