#!/usr/bin/env python3
"""test_payout_ledger_r30.py — r30 (rft §7 B238; §8 PO4, PO8, PO10): the daily DERO/day KPI of
harness/intel/payout_ledger.py.

  PL1 DERO/day = paid shares x per_miniblock_DERO / window days — not found, not expected
  PL2 derod orphan reasons stay apart in the window and derod-wide counts (block_race vs slots_full)
  PL3 the wallet / integrator address never appears in stdout or in the written record, even when the miner log and the
      derod header carry it; the PO8 check still says 'match', and 'mismatch' when the integrator is another address
      (r30 verifier: a check that always says 'match' is caught)
  PL4 --since: REWARD STATS lines before since are a baseline (not counted), the window's days run from since, and a run
      that ended before since contributes nothing
  PL5 the luck grade follows the Garwood 95 % interval: LUCKY / WITHIN / UNLUCKY; the interval is pinned:
      poisson_ci(149) = [126.04, 174.94] (Garwood two-sided 95 %: chi2(0.025, 298)/2, chi2(0.975, 300)/2)
  PL6 the expected DERO/day is the window's expected shares x per_miniblock_DERO / days (so measured/expected =
      paid / expected shares), never the miner's last instantaneous expected_DERO_per_day

  python3 -I harness/kat/test_payout_ledger_r30.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, importlib.util, io, json, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'tool': 'harness/intel/payout_ledger.py'}
WALLET = 'dero1qyKATwalletSTRINGthatMUSTneverAPPEARinOUTPUTxxxxxxxxxxxxxxxxxxxxxxxxxx'
START = 'DERO Stargate HE AstroBWT miner : It is an alpha version'


def load(over):
    p = Path(over.get('tool') or (ROOT / PATHS['tool']))
    if over.get('tool'):                                  # the mutant imports its siblings from the real harness
        for sib in ('hashrate_objective.py', 'miner_runs.py', 'miner_intel.py'):
            (p.parent / sib).write_text((HARNESS / 'intel' / sib).read_text())
        (p.parent.parent / 'kit').mkdir(exist_ok=True)
        (p.parent.parent / 'kit' / 'roundtracks.py').write_text((HARNESS / 'kit' / 'roundtracks.py').read_text())
    spec = importlib.util.spec_from_file_location('payout_ledger_kat', p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def jl(t, msg, **f):
    d = {'L': 'INFO', 'T': t, 'N': 'miner', 'M': msg}
    d.update(f)
    return json.dumps(d)


def rs(t, found, paid, orph, exp, per_mb='0.03000', exp_day='50.00'):
    return jl(t, 'REWARD STATS', found_CPU=0, found_GPU=found, paid_CPU=0, paid_GPU=paid, orphaned_CPU=0,
              orphaned_GPU=orph, unresolved=found - paid - orph, expected_shares=str(exp), per_miniblock_DERO=per_mb,
              expected_DERO_per_day=exp_day)


def log_lines():
    return [jl('2026-11-08T10:00:00.000-0800', START),                 # an earlier run, ended before the window
            rs('2026-11-08T10:30:00.000-0800', 40, 40, 0, 40),
            jl('2026-11-08T12:00:00.000-0800', START),
            jl('2026-11-08T12:00:01.000-0800', f'System will mine to "{WALLET}" with 20 threads. Good Luck!!'),
            rs('2026-11-08T12:30:00.000-0800', 10, 8, 1, 9),               # before since: baseline
            rs('2026-11-08T18:00:00.000-0800', 60, 50, 2, 45),             # at until
            jl('2026-11-08T18:00:00.000-0800', 'TOTAL hashrate', **{'H/s': '95000', 'cpu_cores': '18'})]


SINCE, UNTIL = '2026-11-08T12:00:00-08:00', '2026-11-08T18:00:00-08:00'
SINCE2 = '2026-11-08T13:00:00-08:00'


def row(m, since=SINCE2, outcome=None):
    recs = m.HO.read_records('\n'.join(log_lines()))
    return m.make_row('window', recs, m.HO.parse_time(since), m.HO.parse_time(UNTIL), outcome, [])


def kat_pl1(over):
    m = load(over)
    r = row(m)
    days = 5 / 24.0                                              # 13:00 .. 18:00
    want = round((50 - 8) * 0.03 / days, 3)
    return r['DERO_per_day'] == want and r['miner']['paid'] == 42 and r['miner']['found'] == 50, (r['DERO_per_day'], want, r['miner'])


def outcome():
    rec = [{'hash': 'a', 'submitted_unix_ms': 1794211200000 + i * 60000, 'fate': f, 'reason': rsn}
           for i, (f, rsn) in enumerate([('paid', None), ('orphaned', 'block_race'), ('orphaned', 'slots_full'),
                                          ('orphaned', 'slots_full'), ('pending', None)])]
    rec.append({'hash': 'b', 'submitted_unix_ms': 1794211200000 + 9 * 60000, 'fate': 'paid', 'final': True, 'built': 'blk'})
    return {'submitted': 9, 'paid': 4, 'orphaned': {'block_race': 1, 'slots_full': 3}, 'pending': 1, 'recent': rec[::-1]}


def kat_pl2(over):
    m = load(over)
    w, scope, wide = m.derod_window(outcome(), 1794211200 - 1, 1794211200 + 3600)
    return (w['orphaned'] == {'block_race': 1, 'slots_full': 2} and wide['orphaned'] == {'block_race': 1, 'slots_full': 3}
            and w['paid'] == 2 and w['pending'] == 1 and scope.startswith('window complete')), (w, wide, scope)


OTHER = 'dero1qyKATintegratorOTHERaddressNOTtheMINERSxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'


def ledger_run(m, integrator):
    with tempfile.TemporaryDirectory() as d:
        log = Path(d) / 'dero-miner.log'
        log.write_text('\n'.join(log_lines()) + '\n')
        out = Path(d) / 'payout_daily.jsonl'

        def fake(url, method, params=None, timeout=10):
            if method == 'DERO.GetMiningOutcome':
                return outcome()
            return {'block_header': {'miners': ['x'] * 9 + [integrator]}}
        m.rpc_call = fake
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = m.main(['--log', str(log), '--since', SINCE, '--until', UNTIL, '--runs', '--out', str(out), '--json'])
        txt = buf.getvalue() + out.read_text()
        rows = [json.loads(l) for l in out.read_text().splitlines()]
    return rc, txt, rows


def kat_pl3(over):
    m = load(over)
    rc, txt, rows = ledger_run(m, WALLET)
    rc2, txt2, rows2 = ledger_run(m, OTHER)                      # the integrator is not the miner's wallet
    return (rc == 0 and WALLET not in txt and WALLET[:20] not in txt and rows
            and all(r['integrator_check'] == 'match' for r in rows)
            and rc2 == 0 and rows2 and all(r['integrator_check'] == 'mismatch' for r in rows2)
            and WALLET[:20] not in txt2 and OTHER[:20] not in txt2), (
        rc, [r['integrator_check'] for r in rows], rc2, [r['integrator_check'] for r in rows2], WALLET in txt)


def kat_pl4(over):
    m = load(over)
    r = row(m, SINCE2)
    r0 = row(m, '2026-11-08T09:00:00-08:00')                    # includes the earlier run in full
    return (r['hours'] == 5.0 and r['miner']['found'] == 50 and r['miner']['runs'] == 1
            and r0['miner']['found'] == 100 and r0['miner']['runs'] == 2), (r['hours'], r['miner'], r0['miner'])


def kat_pl5(over):
    m = load(over)
    g = [m.luck_grade(f, e)[0] for f, e in ((50, 30.0), (50, 48.0), (50, 80.0))]
    lo, hi = m.luck_grade(50, 48.0)[1]
    pin = m.luck_grade(149, 150.0)                               # Garwood two-sided 95 %, k = 149
    return (g == ['LUCKY', 'WITHIN', 'UNLUCKY'] and lo < 50 < hi and pin[0] == 'WITHIN'
            and tuple(pin[1]) == (126.04, 174.94)), (g, lo, hi, pin)


def kat_pl6(over):
    m = load(over)
    r = row(m)
    days = r['hours'] / 24.0
    want = round(r['miner']['expected_shares'] * r['per_miniblock_DERO'] / days, 3)
    ratio = round(r['miner']['paid'] / r['miner']['expected_shares'], 3)
    return (r['expected_DERO_per_day'] == want and abs(r['measured_over_expected'] - ratio) <= 0.002
            and 'miner_expected_DERO_per_day_last' in r), (r['expected_DERO_per_day'], want, r['measured_over_expected'], ratio)


KATS = [('PL1', kat_pl1), ('PL2', kat_pl2), ('PL3', kat_pl3), ('PL4', kat_pl4), ('PL5', kat_pl5), ('PL6', kat_pl6)]
OWNERS = {'B238': [k for k, _ in KATS]}
MUTATIONS = [
    ('tool', "        'measured_over_expected': round(per_day / exp_win, 3) if per_day is not None and exp_win else None,",
     "        'measured_over_expected': round(per_day / exp_day, 3) if per_day is not None and exp_day else None,",
     'B238 PL6: measured/expected against the instantaneous miner figure'),
    ('tool', "    paid_dero = tot['paid'] * per_mb if per_mb is not None else None",
     "    paid_dero = tot['found'] * per_mb if per_mb is not None else None", 'B238 PL1: DERO/day from found shares'),
    ('tool', "            w['orphaned'][reason] = w['orphaned'].get(reason, 0) + 1",
     "            w['orphaned']['orphaned'] = w['orphaned'].get('orphaned', 0) + 1", 'B238 PL2: orphan reasons lumped'),
    ('tool', "    return 'match' if h8(miner_addr) == h8(integrator_addr) else 'mismatch'",
     "    return f'match {miner_addr}' if h8(miner_addr) == h8(integrator_addr) else 'mismatch'",
     'B238 PL3: the wallet string leaks into the PO8 check'),
    ('tool', "        base = before[-1] if before else None", "        base = None", 'B238 PL4: lines before since are counted'),
    ('tool', "    if expected < lo:\n        return 'LUCKY', (lo, hi)\n    if expected > hi:\n        return 'UNLUCKY', (lo, hi)",
     "    if expected < lo:\n        return 'UNLUCKY', (lo, hi)\n    if expected > hi:\n        return 'LUCKY', (lo, hi)",
     'B238 PL5: luck grades swapped'),
    ('tool', "    lo, hi = MR.poisson_ci(k)\n", "    lo, hi = MR.poisson_ci(k + 10)\n", 'B238 PL5: the Garwood interval is taken at k + 10'),
    ('tool', "    return 'match' if h8(miner_addr) == h8(integrator_addr) else 'mismatch'\n", "    return 'match'\n",
     'B238 PL3: integrator_check always says match'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_pl30', HARNESS / 'kit' / 'katmut.py')
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
        print(f'\nr30 payout-ledger KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
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
        with tempfile.TemporaryDirectory(prefix='pl30-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r30 payout-ledger KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
