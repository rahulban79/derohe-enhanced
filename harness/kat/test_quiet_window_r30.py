#!/usr/bin/env python3
"""test_quiet_window_r30.py — r30 (rft §7 B236, B239, B25, B26): the quiet-window runner, the shm-budget preflight and the
B26 effective-hashrate read of metrics_intel.

  QW1 B236  the runner refuses while the live miner runs: miner /metrics up, a derod getwork miner, a dero-miner or
            gpu_split_server process, or an unreadable process table (each alone)
  QW2 B236  the plan is the brief's order (build, S4b, B25, B3 CPU, S4c, B3 GSPLIT, B236, B237) and the total is the
            sum of the step estimates plus one census each
  QW3 B236  resumable: DONE/SKIPPED steps are never re-run; --from and --only select; a REFUSED step runs again
  QW4 B236  a contended census REFUSES the step: no bench runs, no record is written, the state says REFUSED, exit 5
  QW5 B236  ABBA verdicts: B-WINS needs ratio >= 1.01 and all pairs but one; a within-noise ratio is not a win
  QW6 B236  a bench record carries kind bench, quiet true and its census, and hashrate_objective.bench_ok accepts it
  QW7 B239  gctrace: the GC CPU share is the LAST gc line's P% (since process start); none -> None
  QW8 B25   an E-core reading counts only when the E arm's p_frac <= 0.05
  QW10 B3   the GSPLIT runs are ABCD DCBA over geometry x gpu-max: every arm twice, mirrored positions
  QW9 B236  `run` re-executes itself inside ONE benchlock --heavy slot (the brief's "under benchlock --heavy"), and a
            timing bench runs under the exclusive bench lock (benchlock without --heavy)
  QW11 B255 the plan's stallwatch line parses with stallwatch's own parser (--log is required) and names the DONE and
            the REFUSED stop marker
  QW12 B256 each step's census uses the step's own budget (s4b 4 threads, b25 16, b237 15, GPU-side 4, b3cpu/b236 20);
            census_gate: a partial-box step is quiet only by contention.py; a full-box step runs under foreign load
            <= 20 % of the cpus ('steady-foreign'), never above; steady_after bounds the move to 1 core
  QW13 B256 a full-box step under steady foreign load: DONE with both censuses when the load held, REFUSED (exit 5, no
            DONE status) when it moved; its bench record says quiet false, bound lower, with the foreign cores
  QW14 B257 an exit 5 writes the REFUSED marker (step and why); the next run removes it when it starts
  SP1 B239  shm preflight: a geometry larger than available - margin is REFUSED (exit 7), one that fits is OK
  SP2 B239  the preflight's sizes are the Go golden file's (cmd/dero-miner/gsplit/testdata/shm_layout_r30.json) and its
            formula reproduces every golden size
  SP3 B239  an unreadable vm_stat is REFUSED, never a pass
  HS1 B26   metrics_intel's sampled hashrate uses dero_miner_hashes_effective_total (stale_sha_skipped excluded) when
            the miner exports it, says so (hashrate_excludes), and falls back to hashes_total, labelled, for a pre-r30 miner

  python3 -I harness/kat/test_quiet_window_r30.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, importlib.util, io, json, sys, tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'qw': 'harness/pipeline/quiet_window.py', 'ri': 'harness/intel/resource_intel.py', 'mi': 'harness/intel/metrics_intel.py'}


def load(over, key):
    spec = importlib.util.spec_from_file_location(f'{key}_qw30', Path(over.get(key) or (ROOT / PATHS[key])))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def kat_qw1(over):
    m = load(over, 'qw')
    quiet = m.live_miner_reasons(None, 'dero_getwork_miners 0\n', ['launchd', 'derod', 'python3', 'miner.test'])
    cases = [m.live_miner_reasons('dero_miner_up 1', 'dero_getwork_miners 0\n', ['derod']),
             m.live_miner_reasons(None, 'dero_getwork_miners 1\n', ['derod']),
             m.live_miner_reasons(None, None, ['derod', 'dero-miner']),
             m.live_miner_reasons(None, None, ['gpu_split_server']),
             m.live_miner_reasons(None, None, None)]
    return quiet == [] and all(len(c) == 1 for c in cases), (quiet, cases)


def kat_qw2(over):
    m = load(over, 'qw')
    order = [s[0] for s in m.STEPS]
    want = ['build', 's4b', 'b25', 'b3cpu', 's4c', 'b3gsplit', 'b236', 'b237']
    tot = m.total_minutes()
    return order == want and tot == round(sum(s[2] for s in m.STEPS) + m.CENSUS_MIN * len(m.STEPS), 1) and tot > 0, (order, tot)


def kat_qw3(over):
    m = load(over, 'qw')
    st = {'steps': {'build': {'status': 'DONE'}, 's4b': {'status': 'DONE'}, 'b25': {'status': 'REFUSED'},
                    'b3cpu': {'status': 'SKIPPED'}}}
    p = m.pending_steps(st)
    f = m.pending_steps(st, start='s4c')
    o = m.pending_steps(st, only='s4b')
    return p == ['b25', 's4c', 'b3gsplit', 'b236', 'b237'] and f == ['s4c', 'b3gsplit', 'b236', 'b237'] and o == [], (p, f, o)


def kat_qw4(over):
    m = load(over, 'qw')
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / 'harness').mkdir()
        (root / 'harness/round.json').write_text(json.dumps({'benchlock': str(root / 'lock')}))
        a = SimpleNamespace(only='b25', from_=None, wait_quiet_min=0, heavy_slot=False)
        r = m.Runner(a, root=root)
        ran = []
        m.fetch = lambda url, timeout=3: None
        m.ps_names = lambda: ['derod']
        m.census = lambda threads=20, cpu_max=100: (False, {'contended': True, 'why': 'foreign 6.0 cores'})
        r.step_b25 = lambda: ran.append('b25') or ('DONE', {})
        rc = r.run()
        st = json.loads((root / m.QW / 'state.json').read_text())
        recs = list((root / 'harness').rglob('r30_*bench*.json')) + list((root / 'harness').rglob('r30_ceiling_*.json'))
        return rc == 5 and not ran and st['steps']['b25']['status'] == 'REFUSED' and not recs, (rc, ran, st, recs)


def kat_qw5(over):
    m = load(over, 'qw')
    win = m.abba([100, 101, 99, 100], [103, 104, 102, 103])
    noise = m.abba([100, 101, 99, 100], [100.5, 100.2, 99.8, 100.4])
    lose = m.abba([100, 101, 99, 100], [95, 96, 94, 95])
    arms = m.sortrate_arms([{'arm': 'bf', 'round': 1, 'sorts_per_cpu_s': 2.0}, {'arm': 'r29', 'round': 0, 'sorts_per_cpu_s': 1.0},
                            {'arm': 'bf', 'round': 0, 'sorts_per_cpu_s': 3.0}])
    return (win['verdict'] == 'B-WINS' and noise['verdict'] == 'WITHIN-NOISE' and lose['verdict'] == 'A-WINS'
            and arms == {'r29': [1.0], 'bf': [3.0, 2.0]}), (win, noise, lose, arms)


def kat_qw6(over):
    m = load(over, 'qw')
    spec = importlib.util.spec_from_file_location('ho_qw30', ROOT / 'harness/intel/hashrate_objective.py')
    HO = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(HO)
    rc = m.bench_record('cpu', 101000.0, {'contended': False, 'exit': 0})
    rg = m.bench_record('gpu', 120000.0, {'contended': False, 'exit': 0}, geometry='8192,3,2', gpu_max=100)
    ok_c, ok_g = HO.bench_ok(rc), HO.bench_ok(rg)
    return (rc['kind'] == 'bench' and rc['quiet'] is True and rc['contention'] and ok_c[0] and ok_g[0]
            and rc.get('S_hs') == 101000.0 and rg.get('G_staged_hs') == 120000.0), (rc, ok_c, ok_g)


def kat_qw7(over):
    m = load(over, 'qw')
    txt = ('noise\ngc 1 @0.014s 3%: 0.28+3.9 ms clock\ngc 2 @1.0s 0%: 0.1 ms clock\n'
           'gc 17 @90.2s 1%: 0.1+1 ms clock, 2->3->1 MB\n')
    g, none = m.parse_gctrace(txt), m.parse_gctrace('no gc here')
    return g == {'gc_cycles': 17, 'gc_cpu_pct': 1} and none['gc_cpu_pct'] is None, (g, none)


def kat_qw8(over):
    m = load(over, 'qw')
    e = [{'sorts_per_cpu_s': 2000, 'p_frac': 0.01}, {'sorts_per_cpu_s': 2100, 'p_frac': 0.02}]
    p = [{'sorts_per_cpu_s': 5900, 'p_frac': 0.99}]
    bad = [{'sorts_per_cpu_s': 5000, 'p_frac': 0.6}]
    v, w = m.e_core_verdict(e, p), m.e_core_verdict(bad, p)
    return v['e_arm_on_e_cores'] and v['r_E'] == 2050 and v['r_P'] == 5900 and not w['e_arm_on_e_cores'], (v, w)


def kat_qw9(over):
    m = load(over, 'qw')
    import os
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / 'harness').mkdir()
        (root / 'harness/round.json').write_text(json.dumps({'benchlock': str(root / 'lock')}))
        calls = []
        m.fetch = lambda url, timeout=3: None
        m.ps_names = lambda: ['derod']
        real_call, real_popen = m.subprocess.call, m.subprocess.Popen
        m.subprocess.call = lambda argv, **kw: calls.append(list(argv)) or 0
        old = os.environ.pop('DERO_QW_INNER', None)
        try:
            rc = m.Runner(SimpleNamespace(only=None, from_=None, wait_quiet_min=0), root=root).run()
            seen = []

            class P:
                def __init__(self, argv, **kw):
                    seen.append(list(argv))

                def wait(self, timeout=None):
                    return 0
            m.subprocess.Popen = P
            r = m.Runner(SimpleNamespace(only=None, from_=None, wait_quiet_min=0), root=root)
            r.idx = 0
            r.qw.mkdir(parents=True, exist_ok=True)
            r.sh('b25', ['x.test'])
        finally:
            m.subprocess.call, m.subprocess.Popen = real_call, real_popen
            if old is not None:
                os.environ['DERO_QW_INNER'] = old
        outer = calls[0] if calls else []
        bench = seen[0] if seen else []
        ok = (rc == 0 and '--heavy' in outer and outer.index('--heavy') < outer.index('--') and 'run' in outer
              and any(str(x).endswith('benchlock.py') for x in bench) and '--heavy' not in bench and bench[-1] == 'x.test')
        return ok, (outer, bench)


def kat_qw10(over):
    m = load(over, 'qw')
    o = m.gsplit_order(('A', 'B'), (96, 100))
    pos = {}
    for i, x in enumerate(o):
        pos.setdefault(x, []).append(i)
    mirrored = all(sum(v) == len(o) - 1 for v in pos.values())
    return len(o) == 8 and len(pos) == 4 and all(len(v) == 2 for v in pos.values()) and mirrored, (o, pos)


GOLDEN = 'cmd/dero-miner/gsplit/testdata/shm_layout_r30.json'


def kat_sp1(over):
    m = load(over, 'ri')
    gib = 1024 ** 3
    big = m.shm_verdict(9 * gib, 12 * gib, 64 * gib)              # margin max(4096 MB, 6.4 GB) -> 12 - 6.4 < 9
    fits = m.shm_verdict(6 * gib, 40 * gib, 64 * gib)
    tight = m.shm_verdict(6 * gib, 9 * gib, 16 * gib, margin_mb=4096)   # 9 - 4 = 5 < 6
    return (not big['fits']) and fits['fits'] and not tight['fits'], (big, fits, tight)


def kat_sp2(over):
    m = load(over, 'ri')
    g = json.loads((ROOT / GOLDEN).read_text())
    bad = []
    for row in g['geometries']:
        got, src = m.shm_bytes(tuple(row['geom']), g)
        form, _ = m.shm_bytes(tuple(row['geom']), dict(g, geometries=[]))
        if got != row['bytes'] or src != 'golden' or form != row['bytes']:
            bad.append((row['geom'], got, form, row['bytes']))
    return not bad and len(g['geometries']) >= 2, bad


def kat_sp3(over):
    m = load(over, 'ri')
    v = m.shm_verdict(1, None, 64 * 1024 ** 3)
    parsed = m.parse_vm_stat('Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free:  10.\n'
                             'Pages inactive:  5.\nPages speculative: 1.\nPages purgeable: 4.\n')
    return (not v['fits']) and parsed == 20 * 16384 and m.parse_vm_stat('garbage') is None, (v, parsed)


def kat_hs1(over):
    m = load(over, 'mi')
    s0 = {'dero_miner_hashes_total': {(): 1000.0}, 'dero_miner_hashes_effective_total': {(): 990.0}, 'dero_miner_uptime_seconds': {(): 10.0}}
    s1 = {'dero_miner_hashes_total': {(): 2000.0}, 'dero_miner_hashes_effective_total': {(): 1980.0}, 'dero_miner_uptime_seconds': {(): 20.0}}
    new = m.derive(None, None, s0, s1, 10.0)['miner']
    o0 = {k: v for k, v in s0.items() if k != m.HS_KEY}
    o1 = {k: v for k, v in s1.items() if k != m.HS_KEY}
    old = m.derive(None, None, o0, o1, 10.0)['miner']
    return (new['hashrate_sampled'] == 99.0 and new['hashrate_excludes'] == 'stale_sha_skipped'
            and old['hashrate_sampled'] == 100.0 and old['hashrate_excludes'].startswith('none')), (new.get('hashrate_sampled'), old.get('hashrate_sampled'))


def _runner(m, d, only, census_seq, step=None):
    root = Path(d)
    (root / 'harness').mkdir(exist_ok=True)
    (root / 'harness/round.json').write_text(json.dumps({'benchlock': str(root / 'lock')}))
    a = SimpleNamespace(only=only, from_=None, wait_quiet_min=0, heavy_slot=False)
    r = m.Runner(a, root=root)
    calls = []
    m.fetch = lambda url, timeout=3: None
    m.ps_names = lambda: ['derod']
    seq = list(census_seq)

    def fake(threads=20, cpu_max=100):
        calls.append((threads, cpu_max))
        return seq.pop(0) if len(seq) > 1 else seq[0]
    m.census = fake
    setattr(r, f'step_{only}', step or (lambda: ('DONE', {})))
    return r, root, calls


def kat_qw11(over):
    m = load(over, 'qw')
    spec = importlib.util.spec_from_file_location('sw_qw30', ROOT / 'harness/kit/stallwatch.py')
    sw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sw)
    import shlex
    line = m.plan_text().split('liveness: ', 1)[1].splitlines()[0]
    argv = shlex.split(line.replace('<file holding "cd <repo> && nice -n 15 python3 -I harness/pipeline/quiet_window.py run">', 'CMDFILE'))
    i = argv.index('harness/kit/stallwatch.py')
    try:
        a = sw.parse(argv[i + 1:])
    except SystemExit as e:
        return False, f'stallwatch.parse exits {e.code} on the plan line: {line}'
    return (a.log and a.done.endswith('r30_qw/DONE') and a.stop == [m.QW + '/REFUSED'] and a.match == 'quiet_window.py run'), vars(a)


def kat_qw12(over):
    m = load(over, 'qw')
    caps = {k: m.STEP_CAPS[k] for k in ('s4b', 'b25', 'b237', 's4c', 'b3gsplit', 'b3cpu', 'b236')}
    want = {'s4b': (4, 100), 'b25': (16, 100), 'b237': (15, 100), 's4c': (4, 100), 'b3gsplit': (4, 100),
            'b3cpu': (20, 100), 'b236': (20, 100)}
    g = [m.census_gate('s4b', False, {'foreign_cores': 3.4, 'ncpu': 20}),
         m.census_gate('s4b', True, {'foreign_cores': 3.4, 'ncpu': 20}),
         m.census_gate('b3cpu', False, {'foreign_cores': 3.4, 'ncpu': 20}),
         m.census_gate('b236', False, {'foreign_cores': 4.5, 'ncpu': 20}),
         m.census_gate('b3cpu', False, {'ncpu': 20})]
    s = [m.steady_after({'foreign_cores': 3.4}, {'foreign_cores': 3.6, 'ncpu': 20})[0],
         m.steady_after({'foreign_cores': 3.4}, {'foreign_cores': 4.6, 'ncpu': 20})[0],
         m.steady_after({'foreign_cores': 3.9}, {'foreign_cores': 4.3, 'ncpu': 20})[0],
         m.steady_after({'foreign_cores': 3.4}, {'ncpu': 20})[0]]
    with tempfile.TemporaryDirectory() as d:
        r, root, calls = _runner(m, d, 's4b', [(True, {'foreign_cores': 3.4, 'ncpu': 20})])
        rc = r.run()
    return (caps == want and [x[1] for x in g] == ['contended', 'quiet', 'steady-foreign', 'contended', 'contended']
            and s == [True, False, False, False] and rc == 0 and calls[:1] == [(4, 100)]), (caps, g, s, rc, calls)


def kat_qw13(over):
    m = load(over, 'qw')
    held = (False, {'contended': True, 'foreign_cores': 3.4, 'ncpu': 20})
    moved = (False, {'contended': True, 'foreign_cores': 5.0, 'ncpu': 20})
    with tempfile.TemporaryDirectory() as d:
        r, root, calls = _runner(m, d, 'b3cpu', [held, (False, {'contended': True, 'foreign_cores': 3.5, 'ncpu': 20})])
        rc1 = r.run()
        st1 = json.loads((root / m.QW / 'state.json').read_text())['steps']['b3cpu']
    with tempfile.TemporaryDirectory() as d:
        r, root, calls2 = _runner(m, d, 'b3cpu', [held, moved])
        rc2 = r.run()
        st2 = json.loads((root / m.QW / 'state.json').read_text())['steps']['b3cpu']
    rec = m.bench_record('cpu', 100.0, {'qw_mode': 'steady-foreign', 'foreign_cores': 3.4})
    q = m.bench_record('cpu', 100.0, {'qw_mode': 'quiet', 'foreign_cores': 0.5})
    ok1 = rc1 == 0 and st1['status'] == 'DONE' and st1['result']['foreign_load']['before'] == 3.4 \
        and st1['result']['foreign_load']['after'] == 3.5 and calls == [(20, 100), (20, 100)]
    ok2 = rc2 == 5 and st2['status'] == 'REFUSED' and 'moved' in st2['why']
    ok3 = rec['quiet'] is False and rec['bound'] == 'lower' and rec['foreign_cores'] == 3.4 and q['quiet'] is True and 'bound' not in q
    return ok1 and ok2 and ok3, (rc1, st1.get('status'), rc2, st2.get('status'), st2.get('why'), rec.get('quiet'), calls)


def kat_qw14(over):
    m = load(over, 'qw')
    with tempfile.TemporaryDirectory() as d:
        r, root, _ = _runner(m, d, 's4b', [(False, {'contended': True, 'foreign_cores': 9.0, 'ncpu': 20})])
        rc1 = r.run()
        mk = root / m.QW / 'REFUSED'
        txt = mk.read_text() if mk.exists() else ''
        r2, _, _ = _runner(m, d, 's4b', [(True, {'foreign_cores': 0.5, 'ncpu': 20})])
        rc2 = r2.run()
        gone = not mk.exists()
    return rc1 == 5 and txt.startswith('s4b REFUSED') and 'contended' in txt and rc2 == 0 and gone, (rc1, txt, rc2, gone)


KATS = [('QW1', kat_qw1), ('QW2', kat_qw2), ('QW3', kat_qw3), ('QW4', kat_qw4), ('QW5', kat_qw5), ('QW6', kat_qw6),
        ('QW11', kat_qw11), ('QW12', kat_qw12), ('QW13', kat_qw13), ('QW14', kat_qw14),
        ('QW7', kat_qw7), ('QW8', kat_qw8), ('QW9', kat_qw9), ('QW10', kat_qw10), ('SP1', kat_sp1), ('SP2', kat_sp2), ('SP3', kat_sp3), ('HS1', kat_hs1)]
OWNERS = {'B236': ['QW1', 'QW2', 'QW3', 'QW4', 'QW5', 'QW6', 'QW9', 'QW13', 'QW14'], 'B239': ['QW7', 'SP1', 'SP2', 'SP3'], 'B25': ['QW8'], 'B3': ['QW10'], 'B26': ['HS1'], 'B255': ['QW11'], 'B256': ['QW12', 'QW13'], 'B257': ['QW14']}
MUTATIONS = [
    ('qw', "    if gm is not None and gm > 0:", "    if False:", 'B236: a connected getwork miner does not refuse the run'),
    ('qw', "        live = sorted({n for n in names if n in LIVE_NAMES})", "        live = []",
     'B236: a running dero-miner process does not refuse the run'),
    ('qw', "    return [i for i in ids if (st.get('steps', {}).get(i) or {}).get('status') not in ('DONE', 'SKIPPED')]",
     "    return ids", 'B236: done steps are re-run (not resumable)'),
    ('qw', "                if not ok:\n                    return self.refuse(sid,", "                if False:\n                    return self.refuse(sid,",
     'B236: a contended census still benches'),
    # r30 B255-B257
    ('qw', " --stall-s 900 --max-restarts 1 --log harness/runtime/r30_qw/stallwatch.log')", " --stall-s 900 --max-restarts 1')",
     'B255: the plan prints a stallwatch line without --log (stallwatch exits 2)'),
    ('qw', "                caps = STEP_CAPS.get(sid, (20, 100))                 # r30 B256: the step's own budget",
     "                caps = (20, 100)", 'B256: every census assumes 20 threads x 100 % (the old headroom 0)'),
    ('qw', "    if full_box(sid, ncpu) and isinstance(fc, (int, float)) and fc <= STEADY_FOREIGN_MAX_FRAC * ncpu:",
     "    if isinstance(fc, (int, float)) and fc <= STEADY_FOREIGN_MAX_FRAC * ncpu:", 'B256: a partial-box step bypasses contention.py'),
    ('qw', "    if full_box(sid, ncpu) and isinstance(fc, (int, float)) and fc <= STEADY_FOREIGN_MAX_FRAC * ncpu:",
     "    if full_box(sid, ncpu) and isinstance(fc, (int, float)):", 'B256: a full-box step runs under any foreign load'),
    ('qw', "    if abs(a - b) > STEADY_FOREIGN_DELTA:", "    if False:", 'B256: a foreign load that moved across the step is evidence'),
    ('qw', "            if mode == 'steady-foreign' and status == 'DONE':", "            if False:",
     'B256: no census after a steady-foreign step'),
    ('qw', "    rec = {'kind': 'bench', 'quiet': not steady,", "    rec = {'kind': 'bench', 'quiet': True,",
     'B256: a bench under foreign load claims a quiet box'),
    ('qw', "    (self.qw / 'REFUSED').write_text(f'{sid} REFUSED {t}: {why}\\n')", "    pass",
     'B257: an exit 5 leaves no REFUSED marker (a watchdog relaunches it)'),
    ('qw', "        (self.qw / 'REFUSED').unlink(missing_ok=True)            # r30 B257: a new run clears the final marker",
     "        pass", 'B257: a stale REFUSED marker survives a new run'),
    ('qw', "    elif ratio >= ABBA_GAIN_MIN and won >= n - 1:", "    elif ratio >= 1.0:", 'B236: a within-noise ratio counts as a win'),
    ('qw', "    rec = {'kind': 'bench', 'quiet': not steady, 'contention': contention,", "    rec = {'kind': 'bench', 'contention': contention,",
     'B236: a bench record without quiet: true'),
    ('qw', "    return {'gc_cycles': int(hits[-1][0]), 'gc_cpu_pct': int(hits[-1][1])}",
     "    return {'gc_cycles': int(hits[0][0]), 'gc_cpu_pct': int(hits[0][1])}", 'B239: the first gc line (start-up) read as the GC share'),
    ('qw', "    out['e_arm_on_e_cores'] = pe is not None and pe <= E_ARM_MAX_PFRAC", "    out['e_arm_on_e_cores'] = True",
     'B25: a P-core run accepted as an E-core reading'),
    ('qw', "        if getattr(a, 'heavy_slot', True) and os.environ.get('DERO_QW_INNER') != '1':",
     "        if False:", 'B236: the window runs outside a benchlock --heavy slot'),
    ('qw', "        full = ([sys.executable, '-I', str(self.root / 'harness/pipeline/benchlock.py'), '--'] if lock else []) + cmd",
     "        full = cmd", 'B236: a timing bench runs without the exclusive bench lock'),
    ('qw', "    return first + first[::-1]", "    return first + first", 'B3: the GSPLIT arms are not mirrored (drift biases the ratio)'),
    ('ri', "    fits = shm <= avail - margin_mb * MB", "    fits = shm <= avail", 'B239: the shm margin is not applied'),
    ('ri', "        if tuple(g['geom']) == tuple(geom):\n            return g['bytes'], 'golden'",
     "        if False:\n            return g['bytes'], 'golden'", 'B239: the golden sizes are ignored'),
    ('ri', "        size += al(slots * golden['sstride_words'] * 4)", "        size += al(slots * golden['sstride_words'])",
     'B239: the formula drops the int32 width of the GPU SA slots'),
    ('ri', "    if avail is None:\n        return {'fits': False,", "    if avail is None:\n        return {'fits': True,",
     'B239: an unreadable vm_stat passes'),
    ('mi', "            'hashrate_sampled': None if m0 is None else rate(m0, m1, HS_KEY if",
     "            'hashrate_sampled': None if m0 is None else rate(m0, m1, 'dero_miner_hashes_total' if",
     'B26: the sampled hashrate counts never-hashed stale_sha_skipped texts'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_qw30', HARNESS / 'kit' / 'katmut.py')
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
        res.append((name, ok, str(det)))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr30 quiet-window KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        src = ROOT / PATHS[key]
        text = src.read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='qw30-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        coupled += bool(cpl) and verdict == 'proved'
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r30 quiet-window KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
