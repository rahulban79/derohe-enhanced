#!/usr/bin/env python3
"""test_area_intel_r31.py — r31 prep (rft §7 B274-B276, user 2026-11-12 §2.25): area_intel lands MORE but COHERENT
proposals for every area: open §7 rows, ledger 'Open after Round 23c..30' items, coverage gaps, one proposal per row,
and a feed coherence check that G23 enforces; the new 'cryptography' area owns the primitives.

  AI1 backlog_findings: an open row waiting on a measurement is 'measure-pending', an open high-priority row is a high
      'backlog-open', a closed row is no proposal
  AI2 ledger_items / ledger_findings: of the 'Open after Round N' items only those still open AND without a §7 row
      land ('ledger-pending' on a pending chip, else 'ledger-open'), in the area their keywords name; closed items, items
      whose rows are registered, and items naming an unregistered row (backlog-unassigned owns those) do not
  AI3 gap_findings: code paths without a KAT = 'kat-gap'; Go code without a mutation = 'mutation-gap'; harness-only code
      is no mutation gap (a missing metric stays the staleness detector's 'no-metrics': one finding per fact)
  AI4 dedupe_rows: a row two areas list is one proposal, in the first area of the registry, naming the other
  AI5 feed_problems: duplicate ids, an unknown area, two proposals for one row, a missing evidence file are each
      reported; a clean feed has none
  AI6 the registry: 'cryptography' is a required, active area that owns bn256 / Keccak / randomness / payment proofs
      while the range-proof files stay with 'disclosure'; every area has keywords; validate() finds no error; it opens
      'since' r31 (area_opened: not scored while r30 is current, so the closed R30 pages stay byte-exact); the 'dvm' area
      (B286) is required, opens 'since' r31 and owns dvm/, the SC execution path and the SC RPC / wallet files
  AI7 coherence.check_areas: no drift for an area that has not opened; a drift once its round is current
  AI8 a lettered sub-row (B252c) is a §7 row: parsed, accepted in an area's backlog, sorted after its parent

  python3 -I harness/kat/test_area_intel_r31.py      # exit 0 · 3 a KAT failed · 4 a mutation was missed
"""
import contextlib, importlib.util, io, json, sys, tempfile, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'tool': 'harness/intel/area_intel.py', 'coh': 'harness/intel/coherence.py'}
SIBLINGS = ('harness/intel/area_intel.py', 'harness/intel/coherence.py', 'harness/intel/backlog_truth.py')


def load(over):
    root = Path(over.get('root') or ROOT)
    spec = importlib.util.spec_from_file_location(f'ai31_{uuid.uuid4().hex[:6]}', root / PATHS['tool'])
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def row(item, status, dim='x', line=10):
    return {'item': item, 'dim': dim, 'anchor': 'a', 'status': status, 'line': line}


def kat_ai1(over):
    m = load(over)
    blog = {'B1': row('read the flip delay', 'OPEN (R30: pending quiet window)'),
            'B2': row('peer DoS budget', 'OPEN (R31, priority high)'),
            'B3': row('old', 'FIXED (r29)'), 'B4': row('plain', 'OPEN (R31)')}
    f = {k: (kind, sev) for kind, sev, t, e, k in m.backlog_findings({'backlog': ['B1', 'B2', 'B3', 'B4', 'B9']}, blog)}
    ok = f == {'B1': ('measure-pending', 'medium'), 'B2': ('backlog-open', 'high'), 'B4': ('backlog-open', 'medium')}
    return ok, f


HTML = ('<section id="open30"><h2>Open after Round 30</h2><ul>'
        '<li>B5: registered and closed <span class="chip good">R30 now: CLOSED</span></li>'
        '<li>mempool admission ranks every tx 0 <span class="chip pending">pending measurement</span></li>'
        '<li>Keccak domain separation of hash-to-point not checked</li>'
        '<li>an old note <span class="chip good">R30 now: CLOSED; FIXED</span></li>'
        '<li>B999: nobody owns this row</li></ul></section>'
        '<section id="open29"><ul><li>B6 open row <span class="chip warn">PARTLY</span></li></ul></section>')


def kat_ai2(over):
    m = load(over)
    items = m.ledger_items(HTML, rounds=('30', '29'))
    areas = [{'id': 'harness', 'keywords': ['pipeline']}, {'id': 'mempool', 'keywords': ['mempool', 'admission']},
             {'id': 'cryptography', 'keywords': ['Keccak', 'hash-to-point']}]
    f = m.ledger_findings(items, {'B5', 'B6'}, areas, 'artifacts/dero-r1-r30.html')
    got = {a: [(k, s) for k, s, t, e, key in v] for a, v in f.items()}
    closed = [i['closed'] for i in items]
    ok = (len(items) == 6 and closed[0] and closed[3] and not closed[1] and items[1]['pending']
          and got == {'mempool': [('ledger-pending', 'medium')], 'cryptography': [('ledger-open', 'low')]}
          and items[4]['rows'] == ['B999'])
    return ok, (got, closed, [i['rows'] for i in items])


def kat_ai3(over):
    m = load(over)
    g = lambda a, k, n, mt: sorted(x[0] for x in m.gap_findings(a, k, n, mt))
    go = {'code_paths': ['p2p/', 'rpc/x.go']}
    hy = {'code_paths': ['harness/intel/x.py']}
    r = (g(go, [], 0, False), g(go, ['k'], 3, True), g(hy, [], 0, True), g(hy, ['k'], 0, True))
    ok = r == (['kat-gap', 'mutation-gap'], [], ['kat-gap'], [])
    return ok, r


def kat_ai4(over):
    m = load(over)
    props = [{'id': 'b', 'area': 'disclosure', 'kind': 'backlog-open', 'row': 'B8'},
             {'id': 'a', 'area': 'cryptosupply', 'kind': 'backlog-open', 'row': 'B8'},
             {'id': 'c', 'area': 'disclosure', 'kind': 'kat-gap'}]
    out = m.dedupe_rows(props, ['cryptosupply', 'disclosure'])
    ids = sorted(p['id'] for p in out)
    a = next((p for p in out if p['id'] == 'a'), {})
    return ids == ['a', 'c'] and a.get('also_areas') == ['disclosure'], (ids, a)


def kat_ai5(over):
    m = load(over)
    reg = {'areas': [{'id': 'harness'}, {'id': 'miner'}]}
    good = {'proposals': [{'id': 'p1', 'area': 'miner', 'kind': 'backlog-open', 'severity': 'medium', 'row': 'B1',
                           'evidence': [{'file': 'harness/areas.json'}]}]}
    bad = {'proposals': [{'id': 'p1', 'area': 'miner', 'kind': 'backlog-open', 'severity': 'medium', 'row': 'B1', 'evidence': []},
                         {'id': 'p1', 'area': 'nowhere', 'kind': 'x', 'severity': 'medium'},
                         {'id': 'p3', 'area': 'harness', 'kind': 'measure-pending', 'severity': 'high', 'row': 'B1', 'evidence': []},
                         {'id': 'p4', 'area': 'harness', 'kind': 'kat-gap', 'severity': 'low', 'evidence': [{'file': 'no/such/file.py'}]}]}
    pg, pb = m.feed_problems(good, reg, ROOT), m.feed_problems(bad, reg, ROOT)
    t = ' | '.join(pb)
    ok = pg == [] and 'duplicate proposal ids' in t and "'nowhere'" in t and 'two backlog proposals' in t and 'no/such/file.py' in t
    return ok, (pg, pb)


def kat_ai6(over):
    m = load(over)
    reg = json.loads((ROOT / 'harness/areas.json').read_text())
    crypto = next((a for a in reg['areas'] if a['id'] == 'cryptography'), None)
    dvm = next((a for a in reg['areas'] if a['id'] == 'dvm'), None)
    own = {f: m.area_of(reg['areas'], f) for f in ('cryptography/bn256/curve.go', 'cryptography/crypto/keccak.go',
                                                   'cryptography/crypto/random.go', 'proof/proof.go',
                                                   'cryptography/crypto/proof_verify.go')}
    errs, _ = m.validate(reg, ROOT)
    ok = (crypto is not None and crypto['status'] == 'active' and 'cryptography' in m.REQUIRED_AREAS
          and own == {'cryptography/bn256/curve.go': 'cryptography', 'cryptography/crypto/keccak.go': 'cryptography',
                      'cryptography/crypto/random.go': 'cryptography', 'proof/proof.go': 'cryptography',
                      'cryptography/crypto/proof_verify.go': 'disclosure'}
          and all(a.get('keywords') for a in reg['areas']) and not errs
          and crypto.get('since') == 'r31' and not m.area_opened(crypto, 'r30', ['r29', 'r30', 'r31'])
          and m.area_opened(crypto, 'r31', ['r29', 'r30', 'r31']) and m.area_opened({}, 'r30', ['r30'])
          and dvm is not None and dvm.get('since') == 'r31' and 'dvm' in m.REQUIRED_AREAS
          and m.area_of(reg['areas'], 'dvm/dvm.go') == 'dvm' and m.area_of(reg['areas'], 'blockchain/transaction_execute.go') == 'dvm'
          and m.area_of(reg['areas'], 'cmd/derod/rpc/rpc_dero_getsc.go') == 'dvm' and m.area_of(reg['areas'], 'blockchain/blockchain.go') != 'dvm')
    return ok, (own, errs[:3])


def kat_ai7(over):
    """coherence.check_areas: an area 'since' r31 has no scorecard while r30 is current (no drift); once r31 is current
    its missing scorecard is a drift"""
    root = Path(over.get('root') or ROOT)
    spec = importlib.util.spec_from_file_location(f'coh31_{uuid.uuid4().hex[:6]}', root / PATHS['coh'])
    C = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(C)
    out = []
    for cur in ('r30', 'r31'):
        with tempfile.TemporaryDirectory() as d:
            h = Path(d) / 'harness'
            (h / 'runtime').mkdir(parents=True)
            (h / 'round.json').write_text(json.dumps({'current': cur, 'rounds': [{'id': 'r30', 'status': 'measured'},
                                                                               {'id': 'r31', 'status': 'planned'}]}))
            (h / 'areas.json').write_text(json.dumps({'areas': [{'id': 'old', 'status': 'active'},
                                                                {'id': 'new', 'status': 'active', 'since': 'r31'}]}))
            (h / 'runtime/area_intel.json').write_text(json.dumps({'areas': [{'id': 'old', 'state': 'OK', 'title': 'Old'}]}))
            c = C.Ctx(d)
            C.check_areas(c)
            out.append([str(x)[:120] for x in c.drifts if 'new' in str(x)])
    return out[0] == [] and len(out[1]) == 1, out


def kat_ai8(over):
    """r31 prep: a lettered sub-row (| B252c |) is a §7 row: backlog_rows() parses it, validate() accepts it in an area's
    backlog, and backlog_key() sorts B252 < B252a < B252c < B253 (they were invisible to the feed and the registry)"""
    m = load(over)
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / 'artifacts').mkdir()
        (Path(d) / 'artifacts/dero-rft.md').write_text('| B252 | a | x | a | OPEN |\n| B252c | stage reuse | tooling | a | OPEN (R31) |\n')
        rows = m.backlog_rows(Path(d))
    errs = [e for e in m.validate({'rounds': [{'id': 'r30'}], 'areas': [{'id': 'x', 'status': 'active', 'backlog': ['B252c']}]}, ROOT)[0]
            if 'backlog id' in e]
    order = sorted(['B253', 'B252c', 'B252', 'B252a'], key=m.backlog_key)
    ok = sorted(rows) == ['B252', 'B252c'] and rows['B252c']['dim'] == 'tooling' and errs == [] and order == ['B252', 'B252a', 'B252c', 'B253']
    return ok, (sorted(rows), errs, order)


KATS = [('AI1', kat_ai1), ('AI2', kat_ai2), ('AI3', kat_ai3), ('AI4', kat_ai4), ('AI5', kat_ai5), ('AI6', kat_ai6), ('AI7', kat_ai7), ('AI8', kat_ai8)]
OWNERS = {'B274': ['AI1', 'AI3', 'AI4', 'AI5', 'AI8'], 'B276': ['AI2'], 'B275': ['AI6', 'AI7']}
MUTATIONS = [
    ('tool', "        kind = 'measure-pending' if MEASURE_RX.search(row['status']) else 'backlog-open'",
     "        kind = 'backlog-open'", 'B274: a row waiting on a measurement is not measure-pending'),
    ('tool', "        if not row or not is_open(row['status']):", "        if not row:", 'B274: a closed row becomes a proposal'),
    ('tool', "        sev = 'high' if HIGH_RX.search(text) else 'medium'", "        sev = 'medium'", 'B274: a high-priority row is medium'),
    ('tool', "        if it['closed'] or (it['rows'] and all(r in reg_bl for r in it['rows'])):", "        if it['rows'] and all(r in reg_bl for r in it['rows']):",
     'B276: a closed ledger item becomes a proposal'),
    ('tool', "        if it['rows']:          # a row nobody owns", "        if False:          # a row nobody owns",
     'B276: an item naming an unregistered row is proposed twice'),
    ('tool', "        n = sum(1 for k in a.get('keywords', []) if k.lower() in t)", "        n = 0",
     'B276: ledger items are not assigned by keywords'),
    ('tool', "    if code and not mut_total:", "    if not mut_total:", 'B274: harness-only code is a mutation gap'),
    ('tool', "    if a.get('code_paths') and not kat_present:", "    if False:", 'B274: an area without a KAT is no gap'),
    ('tool', "            if row in seen:\n                seen[row].setdefault('also_areas', []).append(p['area'])\n                continue",
     "            if False:\n                seen[row].setdefault('also_areas', []).append(p['area'])\n                continue",
     'B274: a shared row is proposed in two areas'),
    ('tool', "            if p.get('row') in rows:", "            if False:", 'B274: two proposals for one row pass the coherence check'),
    ('tool', "        m = re.match(r'^\\|\\s*(BD?\\d+[a-z]?)\\s*\\|(.*)\\|\\s*$', l)", "        m = re.match(r'^\\|\\s*(BD?\\d+)\\s*\\|(.*)\\|\\s*$', l)",
     'B274: a lettered sub-row is invisible to the feed'),
    ('tool', "        if p.get('area') not in known:", "        if False:", 'B274: an unknown area passes the coherence check'),
    ('tool', "                  'cryptography',   # r31 (user", "                  # r31 (user", 'B275: the cryptography area is not required'),
    ('tool', "    return order.index(cur) >= order.index(s)", "    return True", 'B275: an area is scored before the round it opens with'),
    ('tool', "                  'dvm')   # r31", "                  )   # r31", 'B275: the dvm area is not required'),
    ('coh', "        if a.get('since') in _order and c.rcur.get('id') in _order and _order.index(c.rcur['id']) < _order.index(a['since']):",
     "        if False:", 'B275: coherence expects a scorecard for an area that has not opened'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_ai31', HARNESS / 'kit' / 'katmut.py')
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
        print(f'\nr31 area-intel KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='ai31-mut-') as d:
            for rel in SIBLINGS:                                   # the mutant tree: the tools load their siblings
                (Path(d) / rel).parent.mkdir(parents=True, exist_ok=True)
                (Path(d) / rel).write_text((ROOT / rel).read_text(encoding='utf-8'), encoding='utf-8')
            (Path(d) / PATHS[key]).write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({'root': d}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r31 area-intel KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
