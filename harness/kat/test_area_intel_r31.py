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
  AI9 B296 tooling_intel books a pipeline-derived KPI to its record's round (record_round, kpi_rounds; harness_kpis on
      forged records: an r30 project-only run read during r31 is r30); area_intel's current read carries that round as
      live_round, so live_belongs() books it to r30 and never to r31; a tree KPI (memory_index_bytes) has none
  AI10 B295 the memory-index metrics are contract-driven (the index grows a line per round, rft §0.6): better 'none'
      with alert_if longest > 300 (§0.9 rule 4) and bytes > tooling_intel.INDEX_MAX_BYTES (300 x 200 = 60,000), so
      265 -> 273 and 8,875 -> 9,684 raise no regression and 301 / 60,001 trip the alert
  AI12 on the r31 page ('R31 now:' chips) a REPORT-ONLY / MITIGATED item is closed (backlog_truth's closed
      words); a lettered sub-row id (B252d) names its row (the r31 feed's 9 ledger-open items: 6 report-only, 3 lettered)
  AI11 anchor_tokens reads a '.jsonl' record as itself (it read 'x.jsonl' as the token 'x.json': B250 / B259 / B268 /
      B272 were 'anchor-broken' on existing pipeline records) and a glob anchor (`dvm/*_test.go`, B289) by globbing

  python3 -I harness/kat/test_area_intel_r31.py      # exit 0 · 3 a KAT failed · 4 a mutation was missed
"""
import contextlib, importlib.util, io, json, sys, tempfile, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'tool': 'harness/intel/area_intel.py', 'coh': 'harness/intel/coherence.py', 'ti': 'harness/intel/tooling_intel.py',
         'areas': 'harness/areas.json'}
SIBLINGS = ('harness/intel/area_intel.py', 'harness/intel/coherence.py', 'harness/intel/backlog_truth.py',
            'harness/intel/tooling_intel.py', 'harness/areas.json')


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


def load_ti(over):
    root = Path(over.get('root') or ROOT)
    spec = importlib.util.spec_from_file_location(f'ti31_{uuid.uuid4().hex[:6]}', root / PATHS['ti'])
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _ev(rnd, wall_end='2026-11-13T05:02:35-08:00'):
    return [{'t': '2026-11-13T04:00:00-08:00', 'stage': 'run', 'status': 'BEGIN', 'round': rnd},
            {'t': '2026-11-13T04:00:30-08:00', 'stage': 'flaky', 'status': 'PASS', 'flaky': '0'},
            {'t': '2026-11-13T04:00:00-08:00', 'stage': 'project', 'status': 'START'},
            {'t': wall_end, 'stage': 'project', 'status': 'PASS', 'kats': '35/35', 'mutations': '34/34', 'gates': '32/34'}]


def kat_ai9(over):
    """B296: a pipeline-derived tooling KPI is booked to the round of the record it was read from"""
    T, m = load_ti(over), load(over)
    bad = []
    if T.record_round(_ev('r30')) != 'r30' or T.record_round([{'stage': 'run'}]) != T.PENDING:
        bad.append(f'record_round {T.record_round(_ev("r30"))}')
    with tempfile.TemporaryDirectory() as d:
        runs = Path(d) / 'harness/loop/runs'
        runs.mkdir(parents=True)
        (Path(d) / 'harness/kat').mkdir(parents=True)
        (runs / 'pipeline_20261113T040000.jsonl').write_text('\n'.join(json.dumps(o) for o in _ev('r30')) + '\n')
        k = T.harness_kpis(Path(d))
        if k.get('project_wall_s') != 3755 or (k.get('kpi_rounds') or {}).get('project_wall_s') != 'r30' \
                or (k.get('kpi_rounds') or {}).get('flaky') != 'r30' or 'memory_index_bytes' in (k.get('kpi_rounds') or {}):
            bad.append(f"harness_kpis {k.get('project_wall_s')} {k.get('kpi_rounds')}")
        tdoc = {'capture_file': 'tooling_x.json', 'kpis': {'project_wall_s': 3755, 'memory_index_bytes': 9684,
                                                            'kpi_rounds': {'project_wall_s': 'r30'}}}
        rt = Path(d) / 'harness/runtime'
        rt.mkdir(parents=True)
        (rt / 'tooling_intel.json').write_text(json.dumps(tdoc))
        (rt / 'tooling_x.json').write_text(json.dumps(tdoc, indent=1))
        reg = {'rounds': [{'id': 'r30'}, {'id': 'r31'}], 'areas': [{'id': 'tooling', 'metrics': [
            {'id': 'project_wall_s', 'source': {'kind': 'tooling', 'field': 'project_wall_s'}},
            {'id': 'memory_index_bytes', 'source': {'kind': 'tooling', 'field': 'memory_index_bytes'}}]}]}
        cv = m.current_values(Path(d), reg)[0]['tooling']
        pw, mb = cv.get('project_wall_s') or {}, cv.get('memory_index_bytes') or {}
        if pw.get('value') != 3755 or pw.get('live_round') != 'r30' or m.live_belongs(pw, 'r31') or not m.live_belongs(pw, 'r30'):
            bad.append(f'project_wall_s current read {pw}')
        if mb.get('value') != 9684 or 'live_round' in mb:
            bad.append(f'memory_index_bytes current read {mb}')
    if m.record_round_of({'kpis': {'kpi_rounds': {'x': 'not-a-round'}}}, 'x') is not None:
        bad.append('record_round_of accepts a non-round')
    return not bad, '; '.join(bad) or 'pipeline KPIs booked to their record round'


def kat_ai10(over):
    """B295: the memory-index metrics take better none + alert_if (the R28 L25-24 rule for a contract-driven metric)"""
    T, m = load_ti(over), load(over)
    root = Path(over.get('root') or ROOT)
    reg = json.loads((root / PATHS['areas']).read_text())
    tool = next(a for a in reg['areas'] if a['id'] == 'tooling')
    ms = {x['id']: x for x in tool['metrics']}
    bad = []
    want = {'memory_index_longest': T.INDEX_MAX_LINE, 'memory_index_bytes': T.INDEX_MAX_BYTES}
    for mid, cap in want.items():
        x = ms.get(mid) or {}
        r = x.get('alert_if') or {}
        if x.get('better') != 'none' or r.get('op') != '>' or r.get('value') != cap:
            bad.append(f"{mid}: better {x.get('better')} alert_if {r} (want none, > {cap})")
            continue
        if m.alert(r, cap) or not m.alert(r, cap + 1):
            bad.append(f'{mid}: alert at {cap} / {cap + 1} wrong')
    if T.INDEX_MAX_BYTES != T.INDEX_MAX_LINE * T.INDEX_MAX_LINES or T.INDEX_MAX_LINE != 300:
        bad.append(f'INDEX_MAX_BYTES {T.INDEX_MAX_BYTES}')
    if m.trend(8875, 9684, ms.get('memory_index_bytes', {}).get('better'), 0.02)[1] or \
            m.trend(265, 273, ms.get('memory_index_longest', {}).get('better'), 0.0)[1]:
        bad.append('the R31 growth (8,875 -> 9,684 B, 265 -> 273) is still a regression')
    return not bad, '; '.join(bad) or 'memory index: better none, alert > 300 / > 60,000'


HTML31 = ('<section id="open24"><h2>Open after Round 24</h2><ul>'
          '<li>Batch proof verification is in guarded code <span class="chip warn">R25: still report-only</span> '
          '<span class="chip warn">R31 now: REPORT-ONLY</span></li>'
          '<li>cookie stays report-only <span class="chip warn">R31 now: MITIGATED</span></li>'
          '<li>mempool admission ranks every tx 0 <span class="chip warn">R31 now: OPEN</span></li>'
          '<li>B252d: a slow KAT <span class="chip warn">R31 now: PARTIAL</span></li></ul></section>')


def kat_ai12(over):
    """r31 Part B: on the r31 page ('R31 now:' chips, the last chip) a REPORT-ONLY / MITIGATED lead is closed (backlog_truth's
    closed words: no action from this project); a lettered sub-row id (B252d) is the row it names"""
    m = load(over)
    items = m.ledger_items(HTML31, rounds=('24',))
    closed = [i['closed'] for i in items]
    rows = [i['rows'] for i in items]
    areas = [{'id': 'mempool', 'keywords': ['mempool']}, {'id': 'tooling', 'keywords': ['KAT']}]
    f = m.ledger_findings(items, {'B252d'}, areas, 'artifacts/dero-r1-r31.html')
    got = {a: [k for k, s, t, e, key in v] for a, v in f.items()}
    ok = closed == [True, True, False, False] and rows[3] == ['B252d'] and got == {'mempool': ['ledger-open']}
    return ok, (closed, rows, got)


def kat_ai11(over):
    """a .jsonl pipeline record in a §7 anchor cell is one token that resolves"""
    m = load(over)
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / 'harness/loop/runs').mkdir(parents=True)
        (Path(d) / 'harness/loop/runs/pipeline_20261111T231923.jsonl').write_text('{}\n')
        (Path(d) / 'dvm').mkdir()
        (Path(d) / 'dvm/a_test.go').write_text('package dvm\n')
        ok_t, bad_t, _ = m.anchor_tokens(Path(d), '`harness/loop/runs/pipeline_20261111T231923.jsonl` (step x); `gone.json`; '
                                                  '`dvm/*_test.go`, `wallet/*_test.go`')
    ok = ok_t == ['harness/loop/runs/pipeline_20261111T231923.jsonl', 'dvm/*_test.go'] and bad_t == ['gone.json', 'wallet/*_test.go']
    return ok, (ok_t, bad_t)


KATS = [('AI1', kat_ai1), ('AI2', kat_ai2), ('AI3', kat_ai3), ('AI4', kat_ai4), ('AI5', kat_ai5), ('AI6', kat_ai6), ('AI7', kat_ai7), ('AI8', kat_ai8),
        ('AI9', kat_ai9), ('AI10', kat_ai10), ('AI11', kat_ai11), ('AI12', kat_ai12)]
OWNERS = {'B274': ['AI1', 'AI3', 'AI4', 'AI5', 'AI8'], 'B276': ['AI2', 'AI12'], 'B275': ['AI6', 'AI7'], 'B296': ['AI9'], 'B295': ['AI10'],
          'r31 anchor-jsonl': ['AI11'], 'r31 ledger-open': ['AI12']}
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
    # r31 Part B (B296, B295, anchor-jsonl)
    ('ti', "    k = {'harness_record_round': record_round(ev)}        # r31 (B296)", "    k = {'harness_record_round': 'r31'}",
     'B296: the record round is the current round, not the record\'s'),
    ('ti', "    out['kpi_rounds'] = kpi_rounds(out)                    # r31 (B296): area_intel books each to its record's round",
     "    out['kpi_rounds'] = {}", 'B296: tooling_intel does not name the record round of its KPIs'),
    ('ti', "            out['flaky_record_round'] = record_round(ev)        # r31 (B296)", "            pass",
     'B296: the flaky KPI is not booked to its record round'),
    ('tool', "                    if kr:\n                        e['live_round'] = kr", "                    if False:\n                        e['live_round'] = kr",
     'B296: area_intel books a pipeline KPI to the current round'),
    ('tool', "    return kr if isinstance(kr, str) and re.fullmatch(r'r\\d+[a-z]?', kr) else None", "    return kr or None",
     'B296: any string is taken as a round'),
    ('areas', '"unit": "B",\n     "better": "none",\n     "noise_rel": 0.02,', '"unit": "B",\n     "better": "lower",\n     "noise_rel": 0.02,',
     'B295: the index size is lower-is-better again (the 8,875 -> 9,684 high proposal)'),
    ('areas', '"field": "memory_index_longest"\n     },\n     "alert_if": {\n      "op": ">",\n      "value": 300',
     '"field": "memory_index_longest"\n     },\n     "alert_if": {\n      "op": ">",\n      "value": 265',
     'B295: the longest-line alert is below the rule (265, not 300)'),
    ('ti', "INDEX_MAX_BYTES = INDEX_MAX_LINE * INDEX_MAX_LINES", "INDEX_MAX_BYTES = 9000", 'B295: the byte cap is a hand number below the rule'),
    ('tool', "(?:go|py|jsonl|json|txt|md|swift|html|sh))(?![\\w-])", "(?:go|py|json|jsonl|txt|md|swift|html|sh))",
     'r31 anchor-jsonl: a .jsonl record is read as a missing .json'),
    ('tool', "    for mt in re.finditer(r'`?([\\w./*-]+\\.", "    for mt in re.finditer(r'`?([\\w./-]+\\.",
     'r31 anchor-jsonl: a glob anchor (dvm/*_test.go) is read as the file _test.go'),
    ('tool', "r'IMPLEMENTED|answered|retired|REPORT-ONLY|MITIGATED|REJECTED|SHIPPED|ACCEPTED)(?![\\w-])', re.I)",
     "r'IMPLEMENTED|answered|retired)(?![\\w-])', re.I)", 'r31 ledger-open: a REPORT-ONLY / MITIGATED item is a proposal'),
    ('tool', "ROW_RX = re.compile(r'\\b(BD?\\d{1,3}[a-z]?)\\b')", "ROW_RX = re.compile(r'\\b(BD?\\d{1,3})\\b')",
     'r31 ledger-open: a lettered sub-row id is no row'),
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
