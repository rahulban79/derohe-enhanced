#!/usr/bin/env python3
"""Known-answer tests + mutation proofs: every test the CURRENT round names (func TestR<n>* / FuzzR<n>*, n = the round of
harness/round.json 'current') is registered in fix_build_verify.NEW_TESTS for its package, so the S3 test stage runs it
(r24 AI24-6, self-detected by harness/intel/area_intel.py: the 120 TestR24* of the R24 merge ran in no NEW_TESTS entry).

  NT1 the tree: unregistered(round_funcs(tree), NEW_TESTS) is empty (an exact name in the package's alternation), and
      no OPT-IN test is registered (a test whose first lines t.Skip unless an os.Getenv is set: S3 needs every
      registered name to PASS, so registering one FAILs S3 - pipeline run 3, R24_EVICT / R24_TXPOOL_LOAD).
  NT2 forged shapes: an unregistered name, a name registered only in another package, and a prefix-only match
      (TestR24Foo registered, TestR24FooBar not) are all named; a registered one is not; opt_in() reads an env-gated
      skip and not a plain one.

  python3 -I harness/kat/test_new_tests_registered_r24.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import importlib.util, json, re, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
FBV = 'pipeline/fix_build_verify.py'
COPY = [FBV, 'gen_deroarch.py', 'prep_corpus.py', 'consensus_guard.py', 'miners/minelib.py', 'intel/miner_intel.py',
        'intel/go_mutate.py', 'run_gates.py', 'round.json', 'loop/KNOWN_TEST_FAILURES.json']
COPY_DIRS = ['kit']


def load_fbv(base):
    for m in ('gen_deroarch', 'prep_corpus', 'assetkit', 'textkit', 'connectorkit', 'diagramkit', 'minelib', 'roundtracks'):
        sys.modules.pop(m, None)
    spec = importlib.util.spec_from_file_location(f'fbv_{id(base)}_{len(sys.modules)}', base / FBV)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def round_prefix():
    reg = json.loads((HARNESS / 'round.json').read_text(encoding='utf-8'))
    n = re.fullmatch(r'r(\d+)[a-z]?', reg['current']).group(0)
    return 'R' + n[1:]


OPT_IN_LINES = 4   # how many lines after `func TestX(` an env-gated skip may sit in


def opt_in(body_lines):
    """True when the test's first lines skip unless an environment variable is set (an opt-in harness). Pure."""
    head = '\n'.join(body_lines[:OPT_IN_LINES])
    return 'os.Getenv(' in head and 't.Skip' in head


def round_funcs(prefix, with_opt_in=False):
    """{pkg: [names]} of func Test<prefix>* / Fuzz<prefix>* in the working tree (tracked or not, vendor aside); with
    with_opt_in, also {pkg: [names]} of the opt-in ones (which are left out of the first map)"""
    out = subprocess.run(['git', 'grep', '-n', '--untracked', '-E', rf'^func (Test|Fuzz){prefix}[A-Za-z0-9_]*\(', '--',
                          '*.go', ':!vendor'], cwd=ROOT, capture_output=True, text=True).stdout
    d, oi = {}, {}
    for l in out.splitlines():
        f, ln, rest = l.split(':', 2)
        name = re.match(r'func (\w+)\(', rest).group(1)
        lines = (ROOT / f).read_text(errors='replace').splitlines()[int(ln):]
        (oi if opt_in(lines) else d).setdefault('./' + f.rsplit('/', 1)[0] + '/', []).append(name)
    return (d, oi) if with_opt_in else d


def registered_opt_in(oi, new_tests):
    return sorted(f'{pkg}{n}' for pkg, names in oi.items() for n in names
                  if n in set(str(new_tests.get(pkg, '')).split('|')))


def unregistered(funcs, new_tests):
    return sorted(f'{pkg}{n}' for pkg, names in funcs.items() for n in names
                  if n not in set(str(new_tests.get(pkg, '')).split('|')))


def nt1(base):
    F = load_fbv(base)
    funcs, oi = round_funcs(round_prefix(), with_opt_in=True)
    n = sum(len(v) for v in funcs.values())
    miss = unregistered(funcs, F.NEW_TESTS)
    reg_oi = registered_opt_in(oi, F.NEW_TESTS)
    return (n > 0 and not miss and not reg_oi), (f'{n} {round_prefix()} tests in {len(funcs)} packages, unregistered '
                                                 f'{len(miss)} {miss[:5]}; opt-in {sum(len(v) for v in oi.values())} '
                                                 f'{sorted(oi.items())}, registered opt-in {reg_oi}')


def nt2(base):
    funcs = {'./a/': ['TestR24One', 'TestR24OneBar'], './b/': ['TestR24Two', 'TestR24Three']}
    reg = {'./a/': 'TestR24One|TestX', './c/': 'TestR24Two', './b/': 'TestR24Three'}
    got = unregistered(funcs, reg)
    oi_env = opt_in(['\tif os.Getenv("R24_EVICT") != "1" {', '\t\tt.Skip("opt-in")', '\t}'])
    oi_plain = opt_in(['\tif testing.Short() {', '\t\tt.Skip("short")', '\t}'])
    oi_late = opt_in(['\tx := 1', '\ty := 2', '\tz := 3', '\tw := 4', '\tif os.Getenv("A") == "" { t.Skip() }'])
    roi = registered_opt_in({'./a/': ['TestR24Env']}, {'./a/': 'TestR24One|TestR24Env'})
    ok = got == ['./a/TestR24OneBar', './b/TestR24Two'] and oi_env and not oi_plain and not oi_late and roi == ['./a/TestR24Env']
    return ok, f'got {got} opt_in env/plain/late {oi_env}/{oi_plain}/{oi_late} registered_opt_in {roi}'


KATS = [('NT1', nt1), ('NT2', nt2)]
MUTATIONS = [
    ('NT1', FBV, "        './p2p/': 'TestR24", "        './p2pX/': 'TestR24", 'the r24 p2p tests registered under a wrong package'),
    ('NT1', FBV, "'TestR24AggregateShortfallNotScored|", "'", 'one r24 test dropped from NEW_TESTS'),
    ('NT1', FBV, "        './glue/txcanon/': 'TestR24AdmitRunsTxpolicy',\n",
     "        './cmd/simulator/': 'TestR24EvictionSparesTemplateTxs|TestR24TxpoolLoad',\n"
     "        './glue/txcanon/': 'TestR24AdmitRunsTxpolicy',\n", 'the opt-in simulator harnesses registered (S3 FAIL)'),
]


def copy_tree():
    d = Path(tempfile.mkdtemp(prefix='r24nt-')) / 'harness'
    for rel in COPY:
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HARNESS / rel, d / rel)
    for rel in COPY_DIRS:
        shutil.copytree(HARNESS / rel, d / rel, dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__', '.cache'))
    return d


def main():
    fails = 0
    base = copy_tree()
    for name, fn in KATS:
        try:
            ok, det = fn(base)
        except Exception as e:                                    # noqa: BLE001
            ok, det = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:400]}")
    shutil.rmtree(base.parent, ignore_errors=True)
    missed, byname = 0, dict(KATS)
    for kat, rel, find, repl, why in MUTATIONS:
        d = copy_tree()
        p = d / rel
        text = p.read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??      {kat}: {why} — find text occurs {text.count(find)} times')
            missed += 1
            shutil.rmtree(d.parent, ignore_errors=True)
            continue
        p.write_text(text.replace(find, repl), encoding='utf-8')
        try:
            load_fbv(d)
        except Exception as e:                                      # noqa: BLE001
            print(f'  INVALID {kat}: {why} — mutant does not load ({type(e).__name__})')
            missed += 1
            shutil.rmtree(d.parent, ignore_errors=True)
            continue
        try:
            ok2 = byname[kat](d)[0]
        except Exception:                                          # noqa: BLE001 — a crash is a detection
            ok2 = False
        print(f"  {'proved ' if not ok2 else 'MISSED '} {kat}: {why}")
        missed += ok2
        shutil.rmtree(d.parent, ignore_errors=True)
    print(f'\nr24 new-tests-registered KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
