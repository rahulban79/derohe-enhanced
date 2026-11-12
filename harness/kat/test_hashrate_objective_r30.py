#!/usr/bin/env python3
"""test_hashrate_objective_r30.py — r30 (rft §7 B235, B236 schema, B27 law; §2.21 objective > 150 kH/s): the objective
tool harness/intel/hashrate_objective.py and its gate G34 report progress from measured live windows only.

  HO1 a bench, ESTIMATE or proxy record is refused as a live window; a log of bench records only gives no window (G34 INFO)
  HO2 progress = live mean / 150,000 with its window anchor (source, first and last instants, n), over --since only
  HO3 the ceiling is min(S, G/(1-own)) from records (own from staged vs TOTAL, G from t_busy and the duty cap, S from a
      quiet bench record); without an S record it is 'pending', never a literal
  HO4 live_law() recovers r_P / r_E from P/E split TOTAL lines (B27) and says PENDING without the fields (r29 lines)
  HO5 a bench record without quiet: true or without its contention reading is refused (B236 schema)
  HO6 G34: PASS only for a measured live window above 150,000; INFO below it and for an ESTIMATE window above it
  HO7 (r30 verifier G34a) minimum window: PASS needs n >= 240 TOTAL lines AND >= 3,600 s; one 151k line never PASSes
  HO8 (G34a) a --bench run (start-up marker or untimed bench table header) is refused as a window; the launchd log is
      the only log read while it exists, never bin/dero-miner.log
  HO9 (G34b) g34_verdict refuses a dict flagged estimate or proxy even when it says kind live, measured true
  HO10 (G34c) the effective since/until (first and last TOTAL line used) is recorded; split lines after the last TOTAL
      line are not read; a re-run with the printed since/until reproduces the window and the ceiling
  HO11 (r30 B252) a window that spans a pause is classified, never merged: 241 lines 15 s apart (the detached miner kept
      logging through a session pause) are one CONTINUOUS window that PASSes; 120 + 121 lines around a 2 h hole are
      SEGMENTED with the gap recorded, and their covered 3,585 s (not the 2 h span) keeps G34 at INFO 'too short'

  python3 -I harness/kat/test_hashrate_objective_r30.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, datetime, importlib.util, io, json, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'tool': 'harness/intel/hashrate_objective.py'}


def load(over):
    spec = importlib.util.spec_from_file_location('hashobj_kat', Path(over.get('tool') or (ROOT / PATHS['tool'])))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def jl(t, msg, **f):
    d = {'L': 'INFO', 'T': t, 'N': 'miner', 'M': msg}
    d.update(f)
    return json.dumps(d)


START = 'DERO Stargate HE AstroBWT miner : It is an alpha version'


def synth_log(d, lines):
    p = Path(d) / 'dero-miner.log'
    p.write_text('\n'.join(lines) + '\n')
    return p


def base_lines(hs=(90000, 100000), p_e=None):
    L = [jl('2026-11-08T21:00:00.000-0800', 'TOTAL hashrate', **{'H/s': '50000', 'cpu_cores': '9', 'H/cpu-s': '5555'}),
         jl('2026-11-08T21:19:22.000-0800', START),
         jl('2026-11-08T21:19:22.100-0800', 'CPU duty cycle capped at 90% per thread (use --cpu-max=100 for full speed)')]
    for i, h in enumerate(hs):
        f = {'H/s': str(h), 'cpu_cores': '18.00', 'H/cpu-s': '5400'}
        if p_e:
            f['p_cores'], f['e_cores'] = str(p_e[i][0]), str(p_e[i][1])
        L.append(jl(f'2026-11-08T21:{20 + i:02d}:00.000-0800', 'TOTAL hashrate', **f))
        if i == 0:   # HO10: the split line sits inside the TOTAL window (one after the last TOTAL line is not read)
            L.append(jl('2026-11-08T21:20:30.000-0800', 'GPU split', **{'staged_H/s': '85500', 'gpu_busy_us_per_hash': '10.00',
                                                                      'gpu_busy_pct': '95.0', 'gpu_max': 96}))
    return L


def kat_ho1(over):
    m = load(over)
    refused = [m.live_window_of('x', r) for r in ({'kind': 'bench', 'quiet': True, 'mean_hs': 160000, 'measured': True},
                                                    {'kind': 'live', 'estimate': True, 'mean_hs': 160000, 'measured': True},
                                                    {'kind': 'proxy', 'mean_hs': 160000, 'measured': True})]
    good = m.live_window_of('y', {'kind': 'live', 'measured': True, 'mean_hs': 95000, 'n': 4})
    with tempfile.TemporaryDirectory() as d:
        b = Path(d) / 'r30_ceiling_cpu.json'
        b.write_text(json.dumps({'kind': 'bench', 'quiet': True, 'contention': {'contended': False}, 'side': 'cpu', 'S_hs': 160000}))
        rep = m.analyse(synth_log(d, [jl('2026-11-08T21:19:22.000-0800', START)]), bench_paths=[b])
    return (refused == [None, None, None] and good and good['mean_hs'] == 95000 and rep['window'] is None
            and rep['g34']['word'] == 'INFO'), (refused, good, rep['window'], rep['g34'])


def kat_ho2(over):
    m = load(over)
    with tempfile.TemporaryDirectory() as d:
        rep = m.analyse(synth_log(d, base_lines()), since=m.parse_time('2026-11-08T21:19:22-08:00'))
    w = rep['window']
    return (w['mean_hs'] == 95000 and w['n'] == 2 and rep['progress'] == round(95000 / 150000, 4)
            and w['first'].startswith('2026-11-08T21:20:00') and w['last'].startswith('2026-11-08T21:21:00')
            and w['source'] == 'dero-miner.log'), (w, rep['progress'])


def kat_ho3(over):
    m = load(over)
    with tempfile.TemporaryDirectory() as d:
        log = synth_log(d, base_lines())
        b = Path(d) / 'r30_ceiling_cpu.json'
        b.write_text(json.dumps({'kind': 'bench', 'quiet': True, 'contention': {'contended': False, 'foreign_cores': 0.3},
                                 'side': 'cpu', 'S_hs': 104000}))
        rep = m.analyse(log, bench_paths=[b])
        rep0 = m.analyse(log, bench_paths=[])
    c = rep['ceiling']
    own = 1 - 85500 / 95000
    G = 0.96 / 10e-6
    want = round(min(104000, G / (1 - own)))
    return (abs(c['own'] - round(own, 4)) < 1e-9 and c['G']['value'] == round(G) and c['ceiling_hs'] == want
            and c['binding'] == 'cpu' and rep0['ceiling']['ceiling_hs'] == 'pending'
            and str(rep0['ceiling']['S']).startswith('pending')), (c, want, rep0['ceiling'])


def kat_ho4(over):
    m = load(over)
    rp, re_ = 5950.0, 2000.0
    pe = [(15.0, 3.0), (16.0, 2.0), (14.0, 4.0), (15.5, 3.5)]
    rows = [{'hs': rp * p + re_ * e, 'p_cores': p, 'e_cores': e} for p, e in pe]
    fit = m.live_law(rows)
    pend = m.live_law([{'hs': 90000, 'p_cores': None, 'e_cores': None}] * 5)
    return (fit['status'] == 'FIT' and abs(fit['r_P'] - rp) < 1 and abs(fit['r_E'] - re_) < 1 and fit['n'] == 4
            and pend['status'] == 'PENDING'), (fit, pend)


def kat_ho5(over):
    m = load(over)
    bad = [m.bench_ok(r)[0] for r in ({'kind': 'bench', 'contention': {'contended': False}, 'side': 'cpu', 'S_hs': 1},
                                      {'kind': 'bench', 'quiet': True, 'side': 'cpu', 'S_hs': 1},
                                      {'kind': 'bench', 'quiet': True, 'contention': {}, 'side': 'gpu', 'G_staged_hs': 1})]
    ok = m.bench_ok({'kind': 'bench', 'quiet': True, 'contention': {'contended': False}, 'side': 'gpu', 'G_staged_hs': 120000})[0]
    with tempfile.TemporaryDirectory() as d:
        b = Path(d) / 'r30_ceiling_gpu.json'
        b.write_text(json.dumps({'kind': 'bench', 'side': 'gpu', 'G_staged_hs': 999999}))
        rep = m.analyse(synth_log(d, base_lines()), bench_paths=[b])
    return (bad == [False, False, False] and ok and len(rep['benches_refused']) == 1 and not rep['benches_used']
            and rep['ceiling']['G']['source'].startswith('live')), (bad, ok, rep['benches_refused'], rep['ceiling']['G'])


def kat_ho6(over):
    m = load(over)
    hi = m.g34_verdict({'kind': 'live', 'measured': True, 'mean_hs': 151000, 'source': 's', 'n': 240, 'duration_s': 3600})
    lo = m.g34_verdict({'kind': 'live', 'measured': True, 'mean_hs': 95000, 'source': 's', 'n': 240, 'duration_s': 3600})
    edge = m.g34_verdict({'kind': 'live', 'measured': True, 'mean_hs': 150000, 'source': 's', 'n': 240, 'duration_s': 3600})
    est = m.g34_verdict({'kind': 'estimate', 'measured': False, 'mean_hs': 160000, 'source': 's', 'n': 240,
                         'duration_s': 3600})
    none = m.g34_verdict(None)
    return (hi[1] == 'PASS' and lo[1] == 'INFO' and edge[1] == 'INFO' and est[1] == 'INFO' and none[1] == 'INFO'
            and 'below the objective' in lo[2]
            and all(x[0] is True for x in (hi, lo, edge, est, none))), (hi, lo, edge, est, none)


def long_lines(n, step_s, hs, head=(), t0=1794201600.0):
    """START + head lines + n TOTAL lines every step_s seconds from t0 (2026-11-08T21:20:00-08:00)"""
    tz = datetime.timezone(datetime.timedelta(hours=-8))
    ts = lambda t: datetime.datetime.fromtimestamp(t, tz).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + '-0800'
    L = [jl(ts(t0 - 30), START)] + list(head)
    for i in range(n):
        L.append(jl(ts(t0 + i * step_s), 'TOTAL hashrate', **{'H/s': str(hs), 'cpu_cores': '18.00', 'H/cpu-s': '8400'}))
    return L


def g34_in(m, files):
    """G34 over a synthetic repo root holding `files` {relpath: lines}"""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / 'bin').mkdir()
        for rp, lines in files.items():
            (root / rp).write_text('\n'.join(lines) + '\n')
        return m.g34(root), (m.pick_log(root).name if m.pick_log(root) else None)


def kat_ho7(over):
    m = load(over)
    one = g34_in(m, {'bin/dero-miner.log': long_lines(1, 15, 151000)})[0][1]
    full = g34_in(m, {'bin/dero-miner.log': long_lines(241, 15, 151000)})[0][1]        # 240 x 15 s = 3,600 s
    short_s = g34_in(m, {'bin/dero-miner.log': long_lines(240, 15, 151000)})[0][1]     # 3,585 s
    short_n = g34_in(m, {'bin/dero-miner.log': long_lines(239, 16, 151000)})[0][1]     # 3,808 s but n 239
    return (one.startswith('INFO') and full.startswith('PASS') and short_s.startswith('INFO')
            and short_n.startswith('INFO') and 'too short' in short_s and 'too short' in short_n), (one, full, short_s, short_n)


def kat_ho8(over):
    m = load(over)
    mark = jl('2026-11-08T21:19:31.000-0800', '--bench runs at full speed: --cpu-max (90%) applies to mining only')
    hdr = '             Threads           Total Time     Total Iterations            Time/PoW         Hash/CPU-Sec        Hash Rate/Sec '
    b1 = g34_in(m, {'bin/dero-miner.log': long_lines(241, 15, 200000, head=[mark])})[0][1]
    b2 = g34_in(m, {'bin/dero-miner.log': long_lines(241, 15, 200000, head=[hdr])})[0][1]
    with tempfile.TemporaryDirectory() as d:
        rep = m.analyse(synth_log(d, long_lines(241, 15, 200000, head=[mark])))
    both, name = g34_in(m, {'bin/dero-miner.launchd.log': ['22/11 10:00:00\tINFO\tminer\tnothing here'],
                            'bin/dero-miner.log': long_lines(241, 15, 160000)})
    only, name2 = g34_in(m, {'bin/dero-miner.log': long_lines(241, 15, 160000)})
    return (b1.startswith('INFO') and b2.startswith('INFO') and 'bench' in b1 and 'bench' in b2 and rep['window'] is None
            and rep['refused_bench'] and both[1].startswith('INFO') and name == 'dero-miner.launchd.log'
            and only[1].startswith('PASS') and name2 == 'dero-miner.log'), (b1, b2, rep['refused_bench'], both, name, only[1][:40])


def kat_ho9(over):
    m = load(over)
    w = {'kind': 'live', 'measured': True, 'mean_hs': 999999, 'source': 's', 'n': 300, 'duration_s': 4500}
    est = m.g34_verdict(dict(w, estimate=True))
    prx = m.g34_verdict(dict(w, proxy='staged x 1.1'))
    ctl = m.g34_verdict(dict(w))
    return est[1] == 'INFO' and prx[1] == 'INFO' and ctl[1] == 'PASS', (est, prx, ctl)


def kat_ho10(over):
    m = load(over)
    sp = lambda t, st: jl(t, 'GPU split', **{'staged_H/s': st, 'gpu_busy_us_per_hash': '10.00', 'gpu_busy_pct': '95.0',
                                             'gpu_max': 96})
    L = [jl('2026-11-08T21:19:50.000-0800', START),
         jl('2026-11-08T21:20:00.000-0800', 'TOTAL hashrate', **{'H/s': '95000', 'cpu_cores': '18', 'H/cpu-s': '5300'}),
         sp('2026-11-08T21:20:07.000-0800', '85500'),
         jl('2026-11-08T21:20:15.250-0800', 'TOTAL hashrate', **{'H/s': '95000', 'cpu_cores': '18', 'H/cpu-s': '5300'}),
         sp('2026-11-08T21:20:40.000-0800', '20000')]          # after the last TOTAL line: outside the window
    with tempfile.TemporaryDirectory() as d:
        log = synth_log(d, L)
        rep = m.analyse(log)
        again = m.analyse(log, since=rep['since_epoch'], until=rep['until_epoch'])
        txt = m.text_report(rep)
    last = m.parse_time('2026-11-08T21:20:15.250-08:00')
    own = round(1 - 85500 / 95000, 4)
    return (rep['until_epoch'] == last and rep['until'].startswith('2026-11-08T21:20:15') and rep['ceiling']['own'] == own
            and again['window'] == rep['window'] and again['ceiling'] == rep['ceiling']
            and f"--until {last}" in txt), (rep['since_epoch'], rep['until_epoch'], rep['ceiling']['own'], again['ceiling']['own'])


def kat_ho11(over):
    m = load(over)
    tz = datetime.timezone(datetime.timedelta(hours=-8))
    ts = lambda t: datetime.datetime.fromtimestamp(t, tz).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + '-0800'
    t0 = 1794201600.0
    cont = long_lines(241, 15, 151000)
    seg = long_lines(120, 15, 151000) + [jl(ts(t0 + 1785 + 7200 + i * 15), 'TOTAL hashrate',
                                            **{'H/s': '151000', 'cpu_cores': '18.00', 'H/cpu-s': '8400'}) for i in range(121)]
    with tempfile.TemporaryDirectory() as d:
        wc = m.analyse(synth_log(d, cont))['window']
    with tempfile.TemporaryDirectory() as d:
        ws = m.analyse(synth_log(d, seg))['window']
    gc = g34_in(m, {'bin/dero-miner.log': cont})[0][1]
    gs = g34_in(m, {'bin/dero-miner.log': seg})[0][1]
    ok = (wc['continuity'] == 'CONTINUOUS' and wc['gaps'] == [] and gc.startswith('PASS')
          and ws['continuity'] == 'SEGMENTED' and len(ws['gaps']) == 1 and abs(ws['gaps'][0]['s'] - 7200) < 1
          and [x['n'] for x in ws['segments']] == [120, 121] and abs(ws['covered_s'] - 3585) < 1 and ws['duration_s'] > 10000
          and gs.startswith('INFO') and 'too short' in gs and 'SEGMENTED' in gs)
    return ok, (wc.get('continuity'), ws.get('continuity'), ws.get('covered_s'), gc[:40], gs[-120:])


def kat_ho12(over):
    """r30 B263: a steady-foreign lower-bound bench (quiet false, bound lower, census) is listed apart, never a ceiling
    input and never exit 6; a malformed one (quiet false without bound lower) is still refused (exit 6)"""
    m = load(over)
    lb = {'kind': 'bench', 'quiet': False, 'bound': 'lower', 'contention': {'contended': True, 'foreign_cores': 3.5},
          'side': 'cpu', 'S_hs': 105990}
    bad = {'kind': 'bench', 'quiet': False, 'contention': {'contended': True}, 'side': 'cpu', 'S_hs': 105990}
    with tempfile.TemporaryDirectory() as d:
        a, b = Path(d) / 'lb.json', Path(d) / 'bad.json'
        a.write_text(json.dumps(lb))
        b.write_text(json.dumps(bad))
        low = []
        g1, r1 = m.load_benches([str(a)], low)
        low2 = []
        g2, r2 = m.load_benches([str(b)], low2)
    ok = g1 == [] and r1 == [] and len(low) == 1 and g2 == [] and len(r2) == 1 and low2 == [] \
        and m.lower_bound_ok(lb) and not m.lower_bound_ok(bad) and not m.lower_bound_ok(dict(lb, quiet=True)) \
        and not m.lower_bound_ok(dict(lb, contention={}))
    return ok, (g1, r1, low, r2, low2)


KATS = [('HO1', kat_ho1), ('HO2', kat_ho2), ('HO3', kat_ho3), ('HO4', kat_ho4), ('HO5', kat_ho5), ('HO6', kat_ho6),
        ('HO7', kat_ho7), ('HO8', kat_ho8), ('HO9', kat_ho9), ('HO10', kat_ho10), ('HO11', kat_ho11),
        ('HO12', kat_ho12)]
OWNERS = {'B235': ['HO1', 'HO2', 'HO3', 'HO6'], 'B236': ['HO5', 'HO1'], 'B27': ['HO4'],
          'r30 G34a': ['HO7', 'HO8'], 'r30 G34b': ['HO9'], 'r30 G34c': ['HO10'], 'B252': ['HO11'], 'B263': ['HO12']}
MUTATIONS = [
    ('tool', "        if rec.get('kind') in ('bench', 'estimate', 'proxy') or rec.get('estimate') or rec.get('proxy'):\n"
             "            return None\n        if rec.get('kind') == 'live' and rec.get('measured') is True",
     "        if False:\n            return None\n        if True", 'B235: a bench / ESTIMATE record is accepted as a live window'),
    ('tool', "        out['ceiling_hs'] = round(min(S, G / (1 - own)))", "        out['ceiling_hs'] = round(min(S, G))",
     'B235: the own-hash term is dropped from the ceiling'),
    ('tool', "    if not win or win.get('kind') != 'live' or win.get('measured') is not True:", "    if not win:",
     'B235: G34 passes on an ESTIMATE window'),
    ('tool', "'progress': round(win['mean_hs'] / OBJECTIVE_HS, 4)", "'progress': round(win['mean_hs'] / 100000, 4)",
     'B235: progress against the wrong objective'),
    ('tool', "    return {'status': 'FIT', 'r_P': round(r_p, 1), 'r_E': round(r_e, 1)",
     "    return {'status': 'FIT', 'r_P': round(r_e, 1), 'r_E': round(r_p, 1)", 'B27: the live-law fit swaps P and E'),
    ('tool', "    if rec.get('quiet') is not True:", "    if False:", 'B236: a bench not marked quiet is a ceiling input'),
    ('tool', "            and isinstance(rec.get('contention'), dict) and bool(rec['contention']) and rec.get('side') in ('cpu', 'gpu')",
     "            and rec.get('side') in ('cpu', 'gpu')", 'B263: a lower-bound record without its census is accepted'),
    ('tool', "    return (isinstance(rec, dict) and rec.get('kind') == 'bench' and rec.get('quiet') is False and rec.get('bound') == 'lower'",
     "    return (isinstance(rec, dict) and rec.get('kind') == 'bench' and rec.get('quiet') is False",
     'B263: a malformed unquiet record (no bound lower) escapes the refusal'),
    ('tool', "            lower.append(rel(p))\n            continue", "            pass",
     'B263: a lower-bound record falls through to the refusal (exit 6 in S7)'),
    ('tool', "    if win['mean_hs'] > OBJECTIVE_HS:\n", "    if win['mean_hs'] > OBJECTIVE_HS * 0.5:\n",
     'B235: G34 PASSes at half the objective (full-length window)'),
    ('tool', "    if win['mean_hs'] > OBJECTIVE_HS:\n", "    if win['mean_hs'] >= OBJECTIVE_HS:\n",
     'B235: G34 PASSes at exactly 150,000 (the objective is "above")'),
    ('tool', "MIN_WINDOW_N = 240 ", "MIN_WINDOW_N = 1 ", 'r30 G34a: a window of one TOTAL line can PASS'),
    ('tool', "MIN_WINDOW_S = 3600 ", "MIN_WINDOW_S = 0 ", 'r30 G34a: a window shorter than an hour can PASS'),
    ('tool', "    if marks:  ", "    if False:  ", 'r30 G34a: a --bench run is read as a live window'),
    ('tool', "        elif BENCH_RX.search(l):", "        elif False:", 'r30 G34a: the untimed bench table header is not a marker'),
    ('tool', "LOGS = ['bin/dero-miner.launchd.log', 'bin/dero-miner.log']", "LOGS = ['bin/dero-miner.log', 'bin/dero-miner.launchd.log']",
     'r30 G34a: bin/dero-miner.log is read while the launchd log exists'),
    ('tool', "    if win.get('estimate') or win.get('proxy'):", "    if False:", 'r30 G34b: g34_verdict accepts an estimate/proxy-flagged dict'),
    ('tool', "    splits = split_rows(recs, eff_since, eff_until)", "    splits = split_rows(recs, since, until)",
     'r30 G34c: split lines after the last TOTAL line feed own and G'),
    ('tool', "            'since_epoch': eff_since, 'until_epoch': eff_until,", "            'since_epoch': since, 'until_epoch': until,",
     'r30 G34c: the record does not carry the effective until'),
    ('tool', "        if ts[i] - ts[i - 1] > gap_s:", "        if False:",
     'B252: a hole in the TOTAL lines is merged into one window (no gap recorded)'),
    ('tool', "    n, dur = num(win.get('n')), num(win.get('covered_s', win.get('duration_s')))",
     "    n, dur = num(win.get('n')), num(win.get('duration_s'))",
     'B252: G34 counts the span across a gap as window time'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_ho30', HARNESS / 'kit' / 'katmut.py')
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
        print(f'\nr30 hashrate-objective KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
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
        with tempfile.TemporaryDirectory(prefix='ho30-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r30 hashrate-objective KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
