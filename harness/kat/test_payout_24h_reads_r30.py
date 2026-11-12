#!/usr/bin/env python3
"""test_payout_24h_reads_r30.py — r30 (rft §7 B2, B39, B7): the 24 h payout reads of harness/intel/payout_24h_reads.py.

  DR1 a window shorter than 24 h is refused (exit 5, 'window < 24 h'); 24 h or more reads (FULL)
  DR2 b2 keeps the orphan reasons apart (block_race vs slots_full deltas) and the orphan rate uses paid + orphaned
  DR3 a counter that falls between snapshots (derod restarted) restarts from 0: its delta is the rises plus the value
      after the fall, never negative; b39's flip mean and slow count come from those deltas
  DR4 --partial reads a short window but labels it PARTIAL (never a verdict); b7's gain stays an ESTIMATE label
  DR5 (r30 B252) a window across a session pause stays one CONTINUOUS window (exact deltas); a derod or miner restart
      between two snapshots is a recorded gap: SEGMENTED, deltas labelled lower bounds

  python3 -I harness/kat/test_payout_24h_reads_r30.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, importlib.util, io, json, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'tool': 'harness/intel/payout_24h_reads.py'}
T0 = 1794200000.0


def load(over):
    spec = importlib.util.spec_from_file_location('p24_kat', Path(over.get('tool') or (ROOT / PATHS['tool'])))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def snap(t, br, sf, paid, l9s=0.0, l9c=0, slow=0, flips=0, h=100, stale=0):
    return {'t': t, 'iso': f't{int(t)}', 'height': h, 'derod': {
        'miniblock_ours_orphaned_total{reason="block_race"}': br, 'miniblock_ours_orphaned_total{reason="slots_full"}': sf,
        'miniblock_ours_paid_total': paid, 'miniblock_ours_submitted_total': paid + br + sf,
        'miniblock_ours_median_ack_seconds_sum': paid * 0.2, 'miniblock_ours_median_ack_seconds_count': paid,
        'getwork_final_flip_l9_seconds_sum': l9s, 'getwork_final_flip_l9_seconds_count': l9c,
        'getwork_final_flip_slow_total': slow, 'getwork_final_flips_total': flips, 'getwork_dead_normal_jobs_total': flips / 8,
        'getwork_stale_height_jobs_total': stale}, 'miner': {}}


def run_main(m, snaps, args):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 's.jsonl'
        p.write_text(''.join(json.dumps(s) + '\n' for s in snaps))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = m.main(args + ['--snaps', str(p), '--json'])
        return rc, buf.getvalue()


def kat_dr1(over):
    m = load(over)
    short = [snap(T0, 0, 0, 0), snap(T0 + 23 * 3600, 1, 2, 90)]
    full = [snap(T0, 0, 0, 0), snap(T0 + 24 * 3600, 1, 2, 90)]
    rc1, o1 = run_main(m, short, ['b2'])
    rc2, o2 = run_main(m, full, ['b2'])
    return rc1 == 5 and 'window < 24 h' in o1 and rc2 == 0 and '"FULL' in o2, (rc1, o1[:120], rc2, o2[:120])


def kat_dr2(over):
    m = load(over)
    r = m.read_b2([snap(T0, 1, 1, 10), snap(T0 + 3600, 2, 4, 50), snap(T0 + 7200, 3, 5, 96)])
    return (r['orphaned_by_reason'] == {'block_race': 2, 'slots_full': 4} and r['paid'] == 86
            and r['orphan_rate'] == round(6 / 92, 4) and r['median_ack_mean_s'] == 0.2), r


def kat_dr3(over):
    m = load(over)
    d = m.counter_delta([10, 15, 3, 7])                          # 10->15 (+5), restart ->3 (+3), ->7 (+4)
    s = [snap(T0, 0, 0, 0, l9s=1.0, l9c=100, slow=2, flips=100), snap(T0 + 3600, 0, 0, 0, l9s=2.0, l9c=200, slow=3, flips=200),
         snap(T0 + 7200, 0, 0, 0, l9s=0.5, l9c=40, slow=1, flips=40)]   # derod restarted between 2 and 3
    r = m.read_b39(s)
    return (d == 12 and r['flips'] == 140 and r['slow_gt_150ms'] == 2 and r['flip_l9_n'] == 140
            and r['flip_l9_mean_ms'] == round(1.5 / 140 * 1000, 2)), (d, r)


def kat_dr5(over):
    """r30 B252: a window across a session pause stays ONE window (the daemons kept counting: CONTINUOUS, exact deltas);
    a restart between two snapshots is a recorded gap (SEGMENTED, the label says the deltas are lower bounds)"""
    m = load(over)
    cont = [snap(T0, 0, 0, 0), snap(T0 + 20 * 3600, 1, 1, 80), snap(T0 + 24 * 3600, 1, 2, 96)]   # 20 h without a snapshot
    seg = [snap(T0, 0, 0, 10), snap(T0 + 10 * 3600, 1, 1, 50), snap(T0 + 24 * 3600, 0, 1, 30)]   # derod restarted
    for x, up in zip(seg, (100, 36100, 86500)):
        x['miner'] = {'dero_miner_uptime_seconds': up}
    mres = [dict(snap(T0, 0, 0, 0), miner={'dero_miner_uptime_seconds': 5000.0}),
            dict(snap(T0 + 24 * 3600, 0, 0, 5), miner={'dero_miner_uptime_seconds': 60.0})]   # the miner restarted
    rc1, o1 = run_main(m, cont, ['b2'])
    rc2, o2 = run_main(m, seg, ['b2'])
    c, sg, mr = m.continuity(cont), m.continuity(seg), m.continuity(mres)
    j2 = json.loads(o2) if rc2 == 0 else {}
    ok = (rc1 == 0 and c['class'] == 'CONTINUOUS' and c['gaps'] == [] and 'SEGMENTED' not in o1
          and sg['class'] == 'SEGMENTED' and len(sg['gaps']) == 1 and sg['gaps'][0]['from'] == f't{int(T0 + 36000)}'
          and 'derod restarted' in sg['gaps'][0]['why'] and [x['snapshots'] for x in sg['segments']] == [2, 1]
          and rc2 == 0 and 'SEGMENTED' in j2.get('label', '') and 'lower bound' in j2.get('label', '')
          and j2.get('continuity', {}).get('class') == 'SEGMENTED'
          and mr['class'] == 'SEGMENTED' and 'miner restarted' in mr['gaps'][0]['why'])
    return ok, (c['class'], sg['class'], sg['gaps'], mr['gaps'], j2.get('label'))


def kat_dr4(over):
    m = load(over)
    short = [snap(T0, 0, 0, 0, h=100, stale=0), snap(T0 + 2 * 3600, 1, 0, 20, h=500, stale=600)]
    rc, o = run_main(m, short, ['b7', '--partial'])
    rep = json.loads(o) if rc == 0 else {}
    return (rc == 0 and rep.get('label', '').startswith('PARTIAL') and 'not a verdict' in rep['label']
            and rep['result']['stale_height_jobs_per_block'] == 1.5 and rep['result']['gain'].startswith('ESTIMATE')), (rc, o[:300])


KATS = [('DR1', kat_dr1), ('DR2', kat_dr2), ('DR3', kat_dr3), ('DR4', kat_dr4), ('DR5', kat_dr5)]
OWNERS = {'B2': ['DR1', 'DR2', 'DR4'], 'B39': ['DR3', 'DR1'], 'B7': ['DR4'], 'B252': ['DR5']}
MUTATIONS = [
    ('tool', "    if partial:\n        return True, f'PARTIAL", "    if True:\n        return True, f'PARTIAL",
     'B2: a short window is read without --partial'),
    ('tool', "    orph = {r: int(counter_delta(series(snaps, 'derod', f'miniblock_ours_orphaned_total{{reason=\"{r}\"}}')) or 0)\n"
             "            for r in labels(snaps, 'derod', 'miniblock_ours_orphaned_total')}",
     "    orph = {'all': sum(int(counter_delta(series(snaps, 'derod', f'miniblock_ours_orphaned_total{{reason=\"{r}\"}}')) or 0)\n"
     "            for r in labels(snaps, 'derod', 'miniblock_ours_orphaned_total'))}", 'B2: orphan reasons lumped'),
    ('tool', "        d += (b - a) if b >= a else b", "        d += b - a", 'B39: a derod restart makes a negative delta'),
    ('tool', "        return True, f'PARTIAL ({h:.2f} h < 24 h): not a verdict', round(h, 2)",
     "        return True, 'FULL (>= 24 h)', round(h, 2)", 'B7: a partial window is labelled FULL'),
    ('tool', "                    and db[k] < da[k] and", "                    and False and",
     'B252: a restart between two snapshots is merged into one window (no gap recorded)'),
    ('tool', "    if cont['class'] == 'SEGMENTED':\n        label +=", "    if False:\n        label +=",
     'B252: a SEGMENTED window is labelled as an exact read'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_dr30', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run_kats(over):
    res = []
    for name, fn in KATS:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                ok, det = fn(over)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        res.append((name, bool(ok), str(det)))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr30 payout-24h-reads KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = 0
    for key, find, repl, why in MUTATIONS:
        src = ROOT / PATHS[key]
        text = src.read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='dr30-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r30 payout-24h-reads KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
