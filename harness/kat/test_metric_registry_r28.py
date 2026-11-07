#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for harness/intel/metric_registry.py (r28 rpc-metrics; the R28 sweep gap
"/metrics: 296 of 298 families carry no # HELP / # TYPE").

  MR1 parse_scrape on a forged exposition: counter / gauge / le-histogram / vmrange-histogram / summary are told
      apart by their label KEYS (r28 build bug: 'quantile="' contains 'le="', so go_gc_duration_seconds read as a
      histogram-shaped gauge and its _sum/_count were left unregistered); _sum/_count fold into their family; a
      '# TYPE' line wins over the shape.
  MR2 build on a forged tree: the constructor kind, the comment help with its round tag stripped, a gauge callback
      over an add-only atomic typed counter (and one over a Store'd atomic left a gauge), a scrape-only family found
      by its literal, a derived help marked as such, the area by code_paths, the unit by suffix, and a hand help kept
      across a rebuild.
  MR3 check on forged registries: K1 a scrape family not registered, K2 a bad type / empty help, K3 a counter without
      _total and a gauge named _total, K4 a source moved, K5 RPC_METHODS.md naming an unregistered x_total; a clean
      registry has none.
  MR4 the committed tree: metrics/metric_registry.json passes check (K2-K5, no scrape: the scrape carries peer
      addresses and is never committed), covers every constructor literal of the tree, and is the file
      metrics/registry_r28.go embeds.
  MR5 the CLI: --help exits 0 and writes nothing; build without --scrape exits 2.

Mutation independence (harness/kit/katmut.py): each mutation's reason starts with its defect id (r28 MR<n>).

  python3 -I harness/kat/test_metric_registry_r28.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught by its own KAT, was INVALID, or coupled.
"""
import importlib.util, json, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
TOOL = 'harness/intel/metric_registry.py'


def load(path):
    spec = importlib.util.spec_from_file_location(f'mreg_{abs(hash(str(path)))}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


SCRAPE = '''# TYPE typed_total counter
typed_total 3
c_total{k="a"} 1
g 2
p_seconds_bucket{le="0.1"} 1
p_seconds_bucket{le="+Inf"} 2
p_seconds_sum 0.3
p_seconds_count 2
v_seconds_bucket{vmrange="1.000e+00...1.136e+00"} 1
v_seconds_sum 1.1
v_seconds_count 1
s_seconds{quantile="0"} 0.1
s_seconds{quantile="1"} 0.9
s_seconds_sum 1
s_seconds_count 2
fp_total 9
'''


def mr1(M):
    f = M.parse_scrape(SCRAPE)
    want = {'typed_total': 'counter', 'c_total': 'counter', 'g': 'gauge', 'p_seconds': 'histogram', 'v_seconds': 'vmhistogram',
            's_seconds': 'summary', 'fp_total': 'counter'}
    return f == want, f'parsed {f}'


def forged_tree(d):
    (d / 'harness').mkdir(parents=True)
    (d / 'harness' / 'areas.json').write_text(json.dumps({'areas': [
        {'id': 'rpcws', 'code_paths': ['cmd/derod/rpc/']}, {'id': 'security', 'code_paths': ['cmd/derod/rpc/rpc_abuse.go']},
        {'id': 'syncp2p', 'code_paths': ['p2p/']}]}))
    (d / 'cmd/derod/rpc').mkdir(parents=True)
    (d / 'p2p').mkdir(parents=True)
    (d / 'cmd/derod/rpc/a.go').write_text(
        'package rpc\n'
        '// r25 (CO24-C1): requests refused for a reason worth a series\n'
        'var x = metrics.Set.NewCounter(`c_total{k="a"}`)\n'
        'var y = metrics.Set.GetOrCreateHistogram("v_seconds") // handler time per call\n'
        'func w() { fmt.Fprintf(w, "fp_total %d\\n", 1) }\n')
    (d / 'cmd/derod/rpc/rpc_abuse.go').write_text('package rpc\nvar z = metrics.Set.NewGauge("g", nil)\n')
    (d / 'p2p/p.go').write_text(
        'package p2p\nvar n uint64\nvar m uint64\n'
        'var _ = metrics.Set.GetOrCreateGauge("addonly_total", func() float64 { return float64(atomic.LoadUint64(&n)) })\n'
        'var _ = metrics.Set.GetOrCreateGauge("stored_total", func() float64 { return float64(atomic.LoadUint64(&m)) })\n'
        'func f() { atomic.AddUint64(&n, 1); atomic.StoreUint64(&m, 0) }\n')
    (d / 'cmd/derod/rpc/a_test.go').write_text('package rpc\nvar t = metrics.Set.NewCounter("test_only_total")\n')


def mr2(M):
    with tempfile.TemporaryDirectory() as t:
        d = Path(t)
        forged_tree(d)
        reg = M.build(d, SCRAPE)
        e = {x['name']: x for x in reg['families']}
        probs = []
        if 'test_only_total' in e:
            probs.append('a _test.go literal was registered')
        c = e.get('c_total', {})
        if (c.get('type'), c.get('source'), c.get('help'), c.get('area'), c.get('unit')) != (
                'counter', 'cmd/derod/rpc/a.go', 'requests refused for a reason worth a series', 'rpcws', '1'):
            probs.append(f'c_total {c}')
        v = e.get('v_seconds', {})
        if (v.get('type'), v.get('help'), v.get('unit')) != ('vmhistogram', 'handler time per call', 'seconds'):
            probs.append(f'v_seconds {v}')
        if e.get('g', {}).get('area') != 'security':
            probs.append(f"g area {e.get('g')} (the longest code_paths match)")
        if e.get('addonly_total', {}).get('type') != 'counter' or e.get('stored_total', {}).get('type') != 'gauge':
            probs.append(f"add-only callback typing {e.get('addonly_total')} {e.get('stored_total')}")
        fp = e.get('fp_total', {})
        if fp.get('source') != 'cmd/derod/rpc/a.go' or not fp.get('in_scrape'):
            probs.append(f'scrape-only family by literal {fp}')
        g = e.get('typed_total', {})
        if g.get('help_source') != 'name' or '(derived from the name)' not in g.get('help', ''):
            probs.append(f'derived help {g}')
        reg['families'] = [dict(x, help='HAND TEXT', help_source='hand') if x['name'] == 'g' else x for x in reg['families']]
        again = {x['name']: x for x in M.build(d, SCRAPE, reg)['families']}
        if again['g']['help'] != 'HAND TEXT' or again['g']['help_source'] != 'hand':
            probs.append('a hand help was overwritten by a rebuild')
        return not probs, '; '.join(probs) or f"{len(e)} families"


def mr3(M):
    with tempfile.TemporaryDirectory() as t:
        d = Path(t)
        forged_tree(d)
        (d / 'cmd/derod/rpc/RPC_METHODS.md').write_text('counts `c_total{k}` and `ghost_total`; field `first_seen_ms`\n')
        reg = M.build(d, SCRAPE)
        clean = M.check(reg, d, SCRAPE, True)
        if ('K5', 'RPC_METHODS.md names `ghost_total`, not a registered family') not in clean or \
                any(k in ('K1', 'K2', 'K4') for k, _ in clean) or any('c_total' in m or 'first_seen_ms' in m for _, m in clean):
            return False, f'clean registry: {clean}'
        clean = set(M.check(reg, d, None, False))
        cases = {
            'K1': (lambda r: r['families'].pop(), SCRAPE),
            'K2': (lambda r: r['families'][0].update(type='bogus'), None),
            'K2h': (lambda r: r['families'][0].update(help=''), None),
            'K3': (lambda r: r['families'].append(dict(r['families'][0], name='plain_counter', type='counter')), None),
            'K3g': (lambda r: r['families'].append(dict(r['families'][0], name='x_total', type='gauge')), None),
            'K4': (lambda r: [x.update(source='cmd/derod/rpc/moved.go') for x in r['families'] if x['name'] == 'c_total'], None),
        }
        bad = []
        for k, (mut, scrape) in cases.items():
            r = json.loads(json.dumps(reg))
            mut(r)
            got = {p[0] for p in set(M.check(r, d, scrape, False)) - clean}   # the problems the forged defect ADDS
            if k[:2] not in got:
                bad.append(f'{k} not reported ({got})')
        return not bad, '; '.join(bad) or 'K1-K5 each reported'


def mr4(_M, root=ROOT):
    M = load(root / TOOL)                     # the tree's own tool: MR4 judges the committed registry, not a mutant
    reg_path = root / 'metrics' / 'metric_registry.json'
    reg = json.loads(reg_path.read_text(encoding='utf-8'))
    probs = M.check(reg, root, None, True)
    names = {e['name'] for e in reg['families']}
    missing = sorted(set(M.mine_source(root)) - names)
    embed = '//go:embed metric_registry.json' in (root / 'metrics' / 'registry_r28.go').read_text(encoding='utf-8')
    ok = not probs and not missing and embed and len(names) >= 250
    return ok, f'{len(names)} families, problems {probs[:3]}, unregistered constructor literals {missing[:5]}, embed {embed}'


def mr5(tool):
    with tempfile.TemporaryDirectory() as t:
        before = sorted(p.name for p in Path(t).iterdir())
        h = subprocess.run([sys.executable, '-I', str(tool), '--help'], cwd=t, capture_output=True, text=True, timeout=60)
        b = subprocess.run([sys.executable, '-I', str(tool), 'build', '--out', str(Path(t) / 'r.json')], cwd=t,
                           capture_output=True, text=True, timeout=60)
        after = sorted(p.name for p in Path(t).iterdir())
        ok = h.returncode == 0 and 'metric_registry' in h.stdout and b.returncode == 2 and before == after
        return ok, f'--help {h.returncode}, build without --scrape {b.returncode}, files written {sorted(set(after) - set(before))}'


KATS = ['MR1', 'MR2', 'MR3', 'MR4', 'MR5']
OWNERS = {f'r28 MR{i}': [f'MR{i}'] for i in range(1, 6)}
MUTATIONS = [   # (find, replace, why: 'r28 MR<n>: ...') in harness/intel/metric_registry.py
    ("        shapes.setdefault(name, set()).add('le' if 'le' in keys else",
     "        shapes.setdefault(name, set()).add('le' if 'le=\"' in labels else", "r28 MR1: label shape by substring (quantile= contains le=)"),
    ("        if name.endswith('_bucket') and 'le' in sh:", "        if name.endswith('_bucket'):", "r28 MR1: every _bucket read as an le-histogram"),
    ("    text = ROUND_TAG.sub('', text).strip()", "    text = text.strip()", "r28 MR2: round tag kept in the help"),
    ("                e['type'], e['type_note'] = 'counter',", "                e['type_note'] = 'counter',", "r28 MR2: add-only gauge callback left a gauge"),
    ("        if name in keep:\n", "        if False:\n", "r28 MR2: a hand help overwritten by a rebuild"),
    ("        if rel.startswith(('vendor/', 'harness/', 'forensics/')) or '/vendor/' in rel or rel.endswith('_test.go'):",
     "        if rel.startswith(('vendor/', 'harness/', 'forensics/')) or '/vendor/' in rel:", "r28 MR2: _test.go literals registered"),
    ("            if e.get('type') == 'counter' and not n.endswith('_total'):", "            if False:", "r28 MR3: K3 counter naming not checked"),
    ("                probs.append(('K1', f'{fam}: exported on /metrics, not in the registry'))", "                pass",
     "r28 MR3: K1 scrape families not checked"),
    ("            probs.append(('K4', f'{n}: declared in {src[n][\"source\"]}, registry says {s}'))", "            pass",
     "r28 MR3: K4 moved source not reported"),
    ("        if text is None:\n            ap.error('build needs --scrape (a /metrics capture file)')\n", "",
     "r28 MR5: build without a scrape writes a registry missing every runtime family"),
]


def run_on(mut=None):
    """the KATs against the tool, or against a mutant copy of it (the committed registry is always the tree's)"""
    tool = ROOT / TOOL
    with tempfile.TemporaryDirectory() as t:
        if mut:
            text = tool.read_text(encoding='utf-8').replace(mut[0], mut[1], 1)
            tool = Path(t) / 'metric_registry.py'
            tool.write_text(text, encoding='utf-8')
            compile(text, str(tool), 'exec')
        M = load(tool)
        M.ROOT = ROOT
        res = []
        for name, fn in (('MR1', lambda: mr1(M)), ('MR2', lambda: mr2(M)), ('MR3', lambda: mr3(M)), ('MR4', lambda: mr4(M)),
                         ('MR5', lambda: mr5(tool))):
            try:
                ok, det = fn()
            except Exception as e:                      # a crash under a mutation is a failure of that KAT
                ok, det = False, f'{type(e).__name__}: {e}'
            res.append((name, ok, det))
        return res


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_r28mr', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    if sys.argv[1:2] in (['-h'], ['--help']):
        print(__doc__)
        return 0
    res = run_on()
    for name, o, det in res:
        print(f"{'ok  ' if o else 'FAIL'} {name} {det[:500]}")
    if not all(o for _, o, _ in res):
        return 3
    K = katmut()
    missed = coupled = 0
    text = (ROOT / TOOL).read_text(encoding='utf-8')
    for mut in MUTATIONS:
        find, repl, why = mut
        if text.count(find) != 1:
            print(f'  ??      {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        try:
            r = run_on(mut)
        except SyntaxError as e:
            print(f'  INVALID {why}: mutant does not compile ({e.msg})')
            missed += 1
            continue
        failed = [n for n, o, _ in r if not o]
        verdict, extra = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f"  {verdict:8} {why}" + (f'  [{",".join(failed)}]' if failed else '')
              + (f'  COUPLED {extra}' if extra and verdict == 'proved' else ''))
        missed += verdict != 'proved'
        coupled += bool(extra) and verdict == 'proved'
    print('\n' + K.summary('r28 metric-registry KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed or coupled else 0


if __name__ == '__main__':
    sys.exit(main())
