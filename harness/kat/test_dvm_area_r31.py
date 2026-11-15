#!/usr/bin/env python3
"""test_dvm_area_r31.py — r31 (rft §7 B290, B288; D-21 non-consensus): the DVM in the harness tools.
  DA1 error_census classify: the DVM log lines get their own classes — 'SC not found', 'error executing sc', 'SC install
      rejected', 'SC reverted for an anonymous sender' -> sc_revert; 'Recover while executing SC' (with a stack) ->
      sc_panic_recovered, not a node bug; 'error Parsing hard coded sc' stays node-bug but NAMED (derod panics at init);
      an unrelated ERROR is still node-bug 'an ERROR no rule explains' (detector signal-coverage findings
      DF-signal-coverage-f9e05db2de / d53b9dc7a2 / 7c30b99da6 / 360ce09444 / 18b6c6faf2)
  DA2 error_census census() over a forged derod run: the DVM kinds are counted by class and none is a node-bug kind
  DA3 metrics_intel dvm_card: counts by result, reverts by reason (zero reasons left out), the histogram means from
      _sum/_count, executions per minute from two samples; None for a scrape without sc_* families (a pre-r31 binary);
      derive() attaches it as agg['dvm']
  DA4 metrics_intel rules/facts: sc_metrics_handler_panics_total > 0 fires WARN dvm_handler_panics (0: silent); the
      facts carry one 'live dvm ...' line
All inputs are forged in memory or a temporary directory; nothing is fetched, nothing outside it is written.
  python3 -I harness/kat/test_dvm_area_r31.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, importlib.util, io, json, shutil, sys, tempfile, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'census': 'harness/intel/error_census.py', 'mi': 'harness/intel/metrics_intel.py'}
COPY_DIRS = ['harness/intel', 'harness/kit']
TS = '2026-11-13T10:00:00.000-0800'


def load(over, key):
    root = Path(over.get('root') or ROOT)
    spec = importlib.util.spec_from_file_location(f'da31_{key}_{uuid.uuid4().hex[:6]}', root / PATHS[key])
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def rec(M, L='ERROR', **k):
    return dict({'L': L, 'T': TS, 'N': 'CORE', 'C': 'blockchain/transaction_execute.go:1', 'M': M}, **k)


STACK = ('goroutine 1 [running]:\npanic({0x0, 0x0})\n\t/x/runtime/panic.go:1 +0x1\n'
         'github.com/deroproject/derohe/dvm.ErrorRevert(0x1)\n\t/x/derohe/dvm/simulator.go:260 +0x1\n')


def kat_da1(over):
    ec = load(over, 'census')
    got = {}
    for M, extra in (('SC not found', {}), ('error executing sc', {'error': 'Discarded knowingly'}),
                     ('SC install rejected, contract source does not parse', {}),
                     ('SC reverted for an anonymous sender; burn value destroyed, fee kept', {}),
                     ('Recover while executing SC ', {'stack': STACK, 'r': 'leaf not found'}),
                     ('error Parsing hard coded sc', {}), ('something unrelated', {})):
        d = rec(M, **extra)
        of = ec.own_frame(d.get('stack')) if d.get('stack') else None
        got[M.split(',')[0].split(';')[0].strip()] = ec.classify(d, 'ERROR', of, extra.get('error', ''), [])
    want_cls = {'SC not found': 'sc_revert', 'error executing sc': 'sc_revert', 'SC install rejected': 'sc_revert',
                'SC reverted for an anonymous sender': 'sc_revert', 'Recover while executing SC': 'sc_panic_recovered',
                'error Parsing hard coded sc': 'node-bug', 'something unrelated': 'node-bug'}
    ok = ({k: v[0] for k, v in got.items()} == want_cls
          and got['Recover while executing SC'][2] is False and got['SC not found'][2] is False
          and got['error Parsing hard coded sc'][2] is True and 'derod panics at init' in got['error Parsing hard coded sc'][1]
          and got['something unrelated'][1] == 'an ERROR no rule explains')
    return ok, {k: v[:1] + (v[2],) for k, v in got.items()}


def kat_da2(over):
    ec = load(over, 'census')
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 'derod.log'
        lines = [rec('DERO HE daemon :  It is an alpha version, use it for testing/evaluations purpose only.', L='INFO',
                     C='derod/main.go:270'),
                 rec('SC not found', scid='ab' * 32), rec('SC not found', scid='cd' * 32),
                 rec('Recover while executing SC ', stack=STACK, r='leaf not found', txid='ef' * 32),
                 rec('SC reverted for an anonymous sender; burn value destroyed, fee kept', L='INFO')]
        p.write_text('\n'.join(json.dumps(x) for x in lines) + '\n')
        c = ec.census(ec.records([p]))
    ok = (c is not None and c['by_class'] == {'sc_revert': 2, 'sc_panic_recovered': 1} and c['node_bug_kinds'] == []
          and len(c['kinds']) == 2)
    return ok, (c or {}).get('by_class'), (c or {}).get('node_bug_kinds')


SCRAPE0 = '''sc_install_total{result="ok"} 1
sc_install_total{result="error"} 0
sc_invoke_total{result="ok"} 2
sc_invoke_total{result="error"} 0
sc_revert_total{reason="out_of_gas"} 0
sc_out_of_gas_total 0
sc_panic_recovered_total 0
sc_metrics_handler_panics_total 0
'''
SCRAPE1 = '''sc_install_total{result="ok"} 3
sc_install_total{result="error"} 1
sc_invoke_total{result="ok"} 5
sc_invoke_total{result="error"} 3
sc_revert_total{reason="out_of_gas"} 1
sc_revert_total{reason="parse"} 1
sc_revert_total{reason="discarded"} 2
sc_revert_total{reason="other"} 0
sc_out_of_gas_total 1
sc_panic_recovered_total 1
sc_metrics_handler_panics_total 0
sc_gas_compute_used_bucket{vmrange="1.000e+03...1.136e+03"} 4
sc_gas_compute_used_sum 4400
sc_gas_compute_used_count 4
sc_exec_seconds_sum 0.5
sc_exec_seconds_count 4
dero_chain_height 7600000
'''


def kat_da3(over):
    mi = load(over, 'mi')
    c = mi.dvm_card(mi.parse(SCRAPE0), mi.parse(SCRAPE1), 60.0)
    none = mi.dvm_card(None, mi.parse('dero_chain_height 7600000\n'), 0)
    agg = mi.derive(mi.parse(SCRAPE0), mi.parse(SCRAPE1), None, None, 60.0)
    want = {'installs_ok': 3, 'installs_error': 1, 'invokes_ok': 5, 'invokes_error': 3, 'reverts': 4,
            'revert_by_reason': {'discarded': 2, 'out_of_gas': 1, 'parse': 1}, 'out_of_gas': 1, 'panic_recovered': 1,
            'handler_panics': 0, 'gas_compute_mean': 1100.0, 'gas_storage_mean': None, 'exec_seconds_mean': 0.125,
            'executions_per_min': 9.0}
    ok = c == want and none is None and agg.get('dvm') == want
    return ok, c, none


def kat_da4(over):
    mi = load(over, 'mi')
    # the card is built here, not by derive(), so a derive() mutation stays DA3's alone (coupling 0)
    quiet = {'interval_s': 0, 'dvm': mi.dvm_card(None, mi.parse(SCRAPE1), 0)}
    loud = {'interval_s': 0, 'dvm': mi.dvm_card(None, mi.parse(SCRAPE1.replace('sc_metrics_handler_panics_total 0',
                                                                                'sc_metrics_handler_panics_total 2')), 0)}
    rq = [r for r in mi.rules(quiet, {'derod': True}) if r[0] == 'dvm_handler_panics']
    rl = [r for r in mi.rules(loud, {'derod': True}) if r[0] == 'dvm_handler_panics']
    fl = [f for f in mi.facts(quiet, []) if f.startswith('live dvm ')]
    ok = (rq == [] and len(rl) == 1 and rl[0][1] == 'WARN' and 'dvm_handler_panics' in mi.RULES and len(fl) == 1
          and 'installs_ok=3 ' in fl[0] and 'out_of_gas=1 ' in fl[0] and "revert_by_reason={'discarded': 2" in fl[0])
    return ok, rq, rl, fl


KATS = [('DA1', kat_da1), ('DA2', kat_da2), ('DA3', kat_da3), ('DA4', kat_da4)]
OWNERS = {'B290 census': ['DA1', 'DA2'], 'B290 card': ['DA3'], 'B290 alert': ['DA4']}
MUTATIONS = [   # (file key, find, replace, why — the first two words name the defect, see OWNERS)
    ('census', "    for pref, cls, why in DVM_RULES:\n        if str(d.get('M', '')).startswith(pref):",
     "    for pref, cls, why in DVM_RULES:\n        if False:", 'B290 census: the DVM rules are never applied'),
    ('census', "            return cls, why, cls == 'node-bug'", "            return cls, why, True",
     'B290 census: every DVM line is also a node bug'),
    ('census', "            return cls, why, cls == 'node-bug'", "            return cls, why, False",
     'B290 census: the hard-coded SC parse failure is not a node bug'),
    ('census', "DVM_RULES = [('Recover while executing SC', 'sc_panic_recovered',",
     "DVM_RULES = [('Recover while executing SC', 'sc_revert',", 'B290 census: a recovered SC panic is booked as a revert'),
    ('census', "             ('SC not found', 'sc_revert',", "             ('SC not found!', 'sc_revert',",
     "B290 census: 'SC not found' falls to node-bug"),
    ('census', "             ('error Parsing hard coded sc', 'node-bug',", "             ('error Parsing hard coded sc!', 'node-bug',",
     'B290 census: the hard-coded SC parse failure is unexplained again'),
    ('mi', "    if d1 is None or 'sc_install_total' not in d1:\n        return None",
     "    if d1 is None:\n        return None", 'B290 card: a pre-r31 scrape yields an empty card'),
    ('mi', "        if r and v:\n            by[r] = n(v)", "        if r:\n            by[r] = n(v)",
     'B290 card: zero reasons are listed'),
    ('mi', "        return round(sm / c, 6) if c else None", "        return round(sm, 6) if c else None",
     'B290 card: the histogram mean is the sum'),
    ('mi', "            'executions_per_min': None if d0 is None or dt <= 0 else round((execs(d1) - execs(d0)) / dt * 60, 2)}",
     "            'executions_per_min': None if d0 is None or dt <= 0 else round(execs(d1) / dt * 60, 2)}",
     'B290 card: the execution rate counts since start, not in the window'),
    ('mi', "        if card is not None:\n            out['dvm'] = card", "        if False:\n            out['dvm'] = card",
     'B290 card: derive drops the card'),
    ('mi', "    if v.get('handler_panics'):\n        out.append(", "    if False:\n        out.append(",
     'B290 alert: a DVM handler panic never warns'),
    ('mi', "    if v:\n        f.append(f\"live dvm ", "    if False:\n        f.append(f\"live dvm ",
     'B290 alert: the facts carry no DVM line'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_da31', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def defect(why):
    return ' '.join(why.split(':')[0].split()[:2])


def run_kats(over):
    res = []
    for name, fn in KATS:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                ok, *det = fn(over)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — a crash is a failure
            ok, det = False, [f'{type(e).__name__}: {e}']
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
        print(f'\nr31 dvm-area KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='da31-mut-') as d:
            for rel in COPY_DIRS:
                shutil.copytree(ROOT / rel, Path(d) / rel, ignore=shutil.ignore_patterns('__pycache__', '*.json', '.go_mutate*'))
            (Path(d) / PATHS[key]).write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({'root': d}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(defect(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r31 dvm-area KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
