#!/usr/bin/env python3
"""test_miner_card_r30.py — r30 (rft §2.20 R30 rule (e), B235, B238): the area_intel miner card reads the new records
(G34's hashrate-objective record, the payout ledger's DERO/day KPI) through a record_field source, never a typed literal.

  AC1 B235  record_field: the NEWEST file of the glob, the dot path's scalar, an anchor line that quotes it, and the
            scale display (progress to 150,000)
  AC2 B238  a .jsonl record takes its LAST row matching `where` (kind window, not the day row)
  AC3 B235  no file, no field or a non-scalar -> pending with the reason (no anchor, no row)
  AC4 B235  harness/areas.json's miner area registers the r30 KAT files, G34, the gm-r30 mutations and both
            record_field metrics

  python3 -I harness/kat/test_miner_card_r30.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, importlib.util, io, json, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'ai': 'harness/intel/area_intel.py', 'areas': 'harness/areas.json'}


def load(over):
    spec = importlib.util.spec_from_file_location('ai_card30', Path(over.get('ai') or (ROOT / PATHS['ai'])))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def kat_ac1(over):
    m = load(over)
    with tempfile.TemporaryDirectory() as d:
        r = Path(d) / 'harness/runtime'
        r.mkdir(parents=True)
        (r / 'r30_hashrate_objective_20261108T2200.json').write_text(json.dumps({'window': {'mean_hs': 90000.0}}, indent=1))
        (r / 'r30_hashrate_objective_20261109T2200.json').write_text(json.dumps({'window': {'mean_hs': 96000.5}}, indent=1))
        e = m.record_field(Path(d), {'glob': 'harness/runtime/r30_hashrate_objective_*.json', 'path': 'window.mean_hs', 'scale': 150000})
        return (e.get('value') == 96000.5 and e['anchor']['file'].endswith('20261109T2200.json') and e['anchor']['line'] > 0
                and '64.0 %' in e.get('display', '')), e


def kat_ac2(over):
    m = load(over)
    with tempfile.TemporaryDirectory() as d:
        r = Path(d) / 'harness/runtime'
        r.mkdir(parents=True)
        rows = [{'kind': 'window', 'DERO_per_day': 40.1}, {'kind': 'window', 'DERO_per_day': 53.5}, {'kind': 'day', 'DERO_per_day': 7.0}]
        (r / 'payout_daily.jsonl').write_text(''.join(json.dumps(x, sort_keys=True) + '\n' for x in rows))
        e = m.record_field(Path(d), {'glob': 'harness/runtime/payout_daily.jsonl', 'path': 'DERO_per_day', 'where': {'kind': 'window'}})
        return e.get('value') == 53.5 and e['anchor']['line'] == 2, e


def kat_ac3(over):
    m = load(over)
    with tempfile.TemporaryDirectory() as d:
        r = Path(d) / 'harness/runtime'
        r.mkdir(parents=True)
        none = m.record_field(Path(d), {'glob': 'harness/runtime/nothing_*.json', 'path': 'a'})
        (r / 'x_1.json').write_text(json.dumps({'a': {'b': 1}}))
        nested = m.record_field(Path(d), {'glob': 'harness/runtime/x_*.json', 'path': 'a'})
        missing = m.record_field(Path(d), {'glob': 'harness/runtime/x_*.json', 'path': 'a.c'})
        return all(x['value'] == 'pending' and x.get('why') and not x.get('anchor') for x in (none, nested, missing)), (none, nested, missing)


def kat_ac4(over):
    a = json.loads(Path(over.get('areas') or (ROOT / PATHS['areas'])).read_text())
    m = next(x for x in a['areas'] if x['id'] == 'miner')
    need = {'harness/kat/test_hashrate_objective_r30.py', 'harness/kat/test_payout_ledger_r30.py',
            'harness/kat/test_payout_24h_reads_r30.py', 'harness/kat/test_quiet_window_r30.py', 'harness/kat/test_miner_card_r30.py'}
    kinds = {x['id']: (x.get('source') or {}).get('kind') for x in m['metrics']}
    ok = (need <= set(m['kat_files']) and 'G34' in m['gates'] and 'gm-r30' in m['gomut_prefixes']
          and kinds.get('objective_live_hs') == 'record_field' and kinds.get('dero_per_day') == 'record_field')
    return ok, (sorted(need - set(m['kat_files'])), m['gates'], kinds)


KATS = [('AC1', kat_ac1), ('AC2', kat_ac2), ('AC3', kat_ac3), ('AC4', kat_ac4)]
OWNERS = {'B235': ['AC1', 'AC3', 'AC4'], 'B238': ['AC2']}
MUTATIONS = [
    ('ai', "    f = files[-1]\n", "    f = files[0]\n", 'B235: the oldest record read instead of the newest'),
    ('ai', "            rows = [r for r in rows if all(r.get(k) == v for k, v in (s.get('where') or {}).items())]\n",
     "", 'B238: the jsonl where-filter is ignored (the day row read as the window KPI)'),
    ('ai', "    if v is None or isinstance(v, (dict, list)) or is_pending(v):", "    if v is None:",
     'B235: a non-scalar field becomes a card value'),
    ('areas', '"G34"', '"G3x"', 'B235: G34 not registered on the miner card'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_card30', HARNESS / 'kit' / 'katmut.py')
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
        print(f'\nr30 miner-card KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) < 1 or (key != 'areas' and text.count(find) != 1):
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='card30-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r30 miner-card KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
