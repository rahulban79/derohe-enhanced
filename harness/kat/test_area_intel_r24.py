#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the r24 area-intelligence layer (harness/intel/area_intel.py).

Every KAT builds a small synthetic tree in a temp dir (registry, round registry, pipeline + go_mutate records, gate
ledger, log_intel snapshots, a dero-rft §7 table, Go test files) and runs the module against it. No network, nothing
in the real tree is read or written.

  AI1 registry validation: the fixture registry is clean; an anchorless measured value, an unknown status, a missing
      required area and a paused area without a resolving reason are each an error (no anchor, no row).
  AI2 anchors: OK on the cited line, MOVED when the quote is elsewhere, BROKEN when it is gone, NOFILE, SHORT.
  AI3 ownership: the most specific code path wins (exact file > glob > longer directory prefix).
  AI4 trend: a drop beyond noise in a higher-is-better metric and a rise in a lower-is-better metric are regressions
      (proposals); a move inside noise is not.
  AI5 paused: an area whose track is paused in round.json is PAUSED with no failing proposal although its gate newly
      FAILs and a mutation survives (both kept in 'held'); the same faults in an active area are proposals.
  AI6 detectors: MISSED and INVALID mutations, a new derod ERROR kind, a newly failing gate, zero coverage, stale
      evidence, a §7 row whose anchor no longer resolves, an unassigned §7 row, an unassigned KAT file and a recorded
      value that no longer recomputes each yield their proposal kind.
  AI7 G23: passes on a fresh run; fails when the scorecard is stale, when areas.json changed after the run, when the
      proposals feed is from another run, and when a value was refused for its anchor.
  AI8 auto metrics: tests are attributed through the file that defines them, mutations through the file they mutate.
  AI9 (r24 verify) backing: a hand-entered value must be stated by its anchored line (as written, rounded, a ratio
      whose two numbers are on the line, or a `derive` over numbers on the line); a value the line does not state is
      an error even though its anchor resolves.
  AI10 (r24 integration) observatory feeds: an area's detector feed turns each OBSERVED detector into a medium
      'observatory-observed' proposal and each ANOMALY into a low 'observatory-anomaly' proposal, anchored on the
      detector's line; a NORMAL / NO-DATA detector is not proposed; its node-gap feed (CO24-*) is proposed as 'node-gap'.

  python3 -I harness/kat/test_area_intel_r24.py   # KATs, then each mutation on a temp copy must flip its KAT
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught. A mutation that crashes the KAT is INVALID, not caught.
"""
import datetime, importlib.util, json, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
MOD = 'intel/area_intel.py'
REQ = ('harness', 'security', 'cryptosupply', 'getworkops', 'mempool', 'chainperf', 'rpcws', 'syncp2p',
       'wallet', 'storage', 'observability', 'docs', 'disclosure', 'miner', 'tooling')   # r25: tooling (§0.9)


def load(base):
    spec = importlib.util.spec_from_file_location(f'area_intel_{id(base)}_{len(sys.modules)}', base / MOD)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def W(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def J(o):
    return json.dumps(o)


def area(aid, **kw):
    a = {'id': aid, 'title': aid, 'owner_dim': aid, 'status': 'active', 'code_paths': [], 'metrics': [], 'kat_files': [],
         'gates': [], 'gomut_prefixes': [], 'backlog': [], 'history': {}}
    a.update(kw)
    return a


def fixture(tmp, **opt):
    """A synthetic tree. Rounds r0..r3; current r3; r2 and r3 have pipeline records."""
    r = Path(tmp)
    W(r, 'evidence.txt', 'speed 100 units\nspeed 80 units\nlatency 10 ms\nlatency 10.5 ms\nlatency 12 ms\nold value 5\n'
                         'paused: the miner track is paused by the user\nround r2 opened here\npeers 13 connected\n'
                         'flips 238 dead 34\ncpu=5.309856s\n11 are all caught\n')
    W(r, 'p2p/penalty.go', 'package p2p\n')
    W(r, 'p2p/sync.go', 'package p2p\n')
    W(r, 'p2p/penalty_test.go', 'package p2p\nfunc TestPen(t *testing.T) {}\n')
    W(r, 'p2p/sync_test.go', 'package p2p\nfunc TestSync(t *testing.T) {}\nfunc TestR3Orphan(t *testing.T) {}\nfunc TestR30Other(t *testing.T) {}\n')
    W(r, 'cmd/dero-miner/x.go', 'package main\n')
    W(r, 'harness/kat/test_owned.py', '# owned\n')
    W(r, 'harness/kat/test_orphan.py', '# nobody registers me\n')
    ev = lambda q, line: {'file': 'evidence.txt', 'quote': q, 'line': line}
    areas = {a: area(a) for a in REQ}
    areas['security'].update(code_paths=['p2p/penalty*'], gates=['G2'], kat_files=['harness/kat/test_owned.py'],
                             metrics=[{'id': 'speed', 'better': 'higher', 'noise_rel': 0.05},
                                      {'id': 'lat', 'better': 'lower', 'noise_rel': 0.10},
                                      {'id': 'lat2', 'better': 'lower', 'noise_rel': 0.10}],
                             history={'r2': {'speed': {'value': 100, 'anchor': ev('speed 100 units', 1)},
                                             'lat': {'value': 10, 'anchor': ev('latency 10 ms', 3)},
                                             'lat2': {'value': 10, 'anchor': ev('latency 10 ms', 3)}},
                                      'r3': {'speed': {'value': opt.get('speed_now', 80), 'anchor': ev(f"speed {opt.get('speed_now', 80)} units", 2)},
                                             'lat': {'value': 10.5, 'anchor': ev('latency 10.5 ms', 4)},
                                             'lat2': {'value': 12, 'anchor': ev('latency 12 ms', 5)}}},
                             backlog=['B1'])
    areas['syncp2p'].update(code_paths=['p2p/'], gates=['G9'], kat_files=['harness/kat/test_owned.py'], backlog=['B2'],
                            metrics=[{'id': 'peers', 'better': 'higher', 'noise_rel': 0.1}],
                            history={'r3': {'peers': {'value': 13, 'anchor': ev('peers 13 connected', 9)}},
                                     'r2': {'mutations': {'value': '9/9', 'anchor': ev('round r2 opened here', 8)}}})
    areas['storage'].update(code_paths=['blockchain/storefs.go'], metrics=[{'id': 'old', 'better': 'lower'}],
                            history={'r0': {'old': {'value': 5, 'anchor': ev('old value 5', 6)}}}, kat_files=['harness/kat/test_owned.py'])
    areas['miner'].update(status='active' if opt.get('miner_registry_active') else 'paused', track='miner',
                          paused_why=ev('paused: the miner track is paused by the user', 7),
                          code_paths=['cmd/dero-miner/'], gates=['G17'], kat_files=['harness/kat/test_owned.py'])
    if opt.get('anchorless'):
        areas['security']['history']['r3']['speed'] = {'value': 80}
    if opt.get('broken_anchor'):
        areas['security']['history']['r2']['speed']['anchor'] = ev('speed 999 units', 1)
    if opt.get('bad_status'):
        areas['docs']['status'] = 'sleeping'
    if opt.get('drop_area'):
        areas.pop('disclosure')
    if opt.get('paused_no_why'):
        areas['wallet']['status'] = 'paused'
    reg = {'schema': 1, 'stale_rounds': 2, 'rounds': [{'id': x, 'pipeline_full': 'pending', 'pipeline_project': 'pending'}
                                                      for x in ('r0', 'r1', 'r2', 'r3')], 'areas': list(areas.values())}
    W(r, 'harness/areas.json', json.dumps(reg, indent=1))
    W(r, 'harness/round.json', J({'current': 'r3', 'rounds': [{'id': 'r3', 'tracks': {'miner': 'paused', 'node': 'active'}}]}))
    for rid, ts, caught in (('r2', '20260101T000000', 'CAUGHT'), ('r3', '20260102T000000', 'CAUGHT')):
        W(r, f'harness/loop/runs/pipeline_{ts}.jsonl', '\n'.join(J(o) for o in [
            {'stage': 'run', 'status': 'BEGIN', 'round': rid},
            {'stage': 'test', 'status': 'PASS', 'new_tests': {'./p2p/': {'passed': ['TestPen', 'TestSync'], 'failed': []}}},
            {'stage': 'kats', 'status': 'PASS', 'results': {'test_owned.py': ['owned: 1/1 ok']}},
            {'stage': 'mutate', 'status': 'PASS'},
            {'stage': 'done', 'status': 'END', 'ok': True}]) + '\n')   # r30 B231: a completed record ends with END
        res = [{'id': 'gm-pen', 'file': 'p2p/penalty.go', 'result': caught},
               {'id': 'gm-sync', 'file': 'p2p/sync.go', 'result': 'CAUGHT'}]
        if rid == 'r3':
            res += [{'id': 'gm-sync-missed', 'file': 'p2p/sync.go', 'result': 'MISSED'},
                    {'id': 'gm-sync-invalid', 'file': 'p2p/sync.go', 'result': 'INVALID'},
                    {'id': 'gm-miner-missed', 'file': 'cmd/dero-miner/x.go', 'result': 'MISSED'}]
        W(r, f'harness/runtime/gomut_{ts}.json', json.dumps({'caught': sum(x['result'] == 'CAUGHT' for x in res), 'total': len(res),
                                                             'results': res}, indent=1))
    gl = ['| when | cycle | gate | result | detail |', '|---|---|---|---|---|']
    for cyc, g9, g17 in (('pipeline-20260101T000000', 'PASS', 'PASS'), ('pipeline-20260102T000000', 'FAIL', 'FAIL')):
        gl += [f'| t | {cyc} | G2 the second gate | PASS | ok |', f'| t | {cyc} | G9 the live daemon | {g9} | detail |',
               f'| t | {cyc} | G17 the live miner | {g17} | miner silent |']
    W(r, 'harness/loop/GATES.md', '\n'.join(gl) + '\n')
    W(r, 'harness/runtime/logintel_1.json', J({'runs': [{'errors': {'p2p/sync.go:5 other': 1}}]}))
    W(r, 'harness/runtime/logintel_2.json', J({'runs': [{'errors': {'p2p/sync.go:5 other': 1, 'p2p/sync.go:9 timeout': 2}}]}))
    W(r, 'artifacts/dero-rft.md', '## 7. backlog\n\n| # | Item | Dimension | Evidence anchor | Status |\n|---|---|---|---|---|\n'
                                 '| B1 | thing | security | p2p/penalty.go | OPEN |\n'
                                 '| B2 | other | syncp2p | p2p/gone_file.go | OPEN |\n'
                                 '| B3 | nobody | ops | p2p/sync.go | OPEN |\n'
                                 '| B4 | done | ops | p2p/sync.go | CLOSED in r2 |\n')
    return r


def props_of(pdoc, area=None, kind=None):
    return [p for p in pdoc['proposals'] if (area is None or p['area'] == area) and (kind is None or p['kind'] == kind)]


def run(M, root):
    doc, pdoc, err = M.evaluate(root)
    return doc, pdoc, err, {c['id']: c for c in doc['areas']}


# ───────────────────────────── KATs ─────────────────────────────
def ai1(base, tmp):
    M = load(base)
    out = {}
    for name, kw in (('clean', {}), ('anchorless', {'anchorless': True}), ('status', {'bad_status': True}),
                     ('required', {'drop_area': True}), ('paused_no_why', {'paused_no_why': True})):
        t = Path(tempfile.mkdtemp(dir=tmp))
        r = fixture(t, **kw)
        e, _ = M.validate(json.loads((r / 'harness/areas.json').read_text()), r)
        out[name] = len(e)
    ok = out['clean'] == 0 and all(out[k] >= 1 for k in ('anchorless', 'status', 'required', 'paused_no_why'))
    return ok, f'errors per fixture {out}'


def ai2(base, tmp):
    M = load(base)
    r = fixture(tmp)
    got = [M.resolve_anchor(r, a)['status'] for a in (
        {'file': 'evidence.txt', 'quote': 'speed 80 units', 'line': 2},
        {'file': 'evidence.txt', 'quote': 'speed 80 units', 'line': 5},
        {'file': 'evidence.txt', 'quote': 'speed 81 units', 'line': 2},
        {'file': 'nope.txt', 'quote': 'speed 80 units', 'line': 2},
        {'file': 'evidence.txt', 'quote': 'sp', 'line': 2},
        {'file': 'evidence.txt'})]
    return got == ['OK', 'MOVED', 'BROKEN', 'NOFILE', 'SHORT', 'NONE'], f'statuses {got}'


def ai3(base, tmp):
    M = load(base)
    areas = [area('rpcws', code_paths=['cmd/derod/rpc/']), area('security', code_paths=['cmd/derod/rpc/rpc_abuse.go', 'p2p/penalty*']),
             area('getworkops', code_paths=['cmd/derod/rpc/getwork_*']), area('syncp2p', code_paths=['p2p/']),
             area('miner', code_paths=['cmd/dero-miner/'])]
    cases = {'cmd/derod/rpc/rpc_abuse.go': 'security', 'cmd/derod/rpc/getwork_flip.go': 'getworkops',
             'cmd/derod/rpc/rpc_dero_getinfo.go': 'rpcws', 'p2p/penalty_test.go': 'security', 'p2p/chain_sync.go': 'syncp2p',
             'cmd/dero-miner/miner.go': 'miner', 'walletapi/wallet.go': None}
    got = {f: M.area_of(areas, f) for f in cases}
    return got == cases, f'owners {got}'


def ai4(base, tmp):
    M = load(base)
    r = fixture(tmp)
    doc, pdoc, err, C = run(M, r)
    regs = sorted(p['title'].split(':')[0] for p in props_of(pdoc, 'security', 'metric-regression'))
    t_in = M.trend(10, 10.5, 'lower', 0.10)
    t_up = M.trend(100, 80, 'higher', 0.05)
    ok = regs == ['lat2', 'speed'] and t_in == ('flat', False) and t_up == ('down', True) and M.trend(None, 5, 'higher') == ('new', False)
    return ok, f'regressions {regs} trend(10->10.5 lower, 10%)={t_in} trend(100->80 higher)={t_up} err={err[:2]}'


def ai5(base, tmp):
    M = load(base)
    r = fixture(Path(tempfile.mkdtemp(dir=tmp)))
    doc, pdoc, err, C = run(M, r)
    mi, sp = C['miner'], C['syncp2p']
    held = sorted(h['kind'] for h in mi['held'])
    # the registry still says active but round.json pauses the track: PAUSED, and only the mismatch is proposed
    r2 = fixture(Path(tempfile.mkdtemp(dir=tmp)), miner_registry_active=True)
    _, pdoc2, _, C2 = run(M, r2)
    kinds2 = sorted(p['kind'] for p in props_of(pdoc2, 'miner'))
    ok = (mi['state'] == 'PAUSED' and not props_of(pdoc, 'miner') and 'gate-newly-failing' in held and 'mutation-missed' in held
          and mi['gates_now']['state'].get('G17') == 'FAIL'
          and props_of(pdoc, 'syncp2p', 'gate-newly-failing') and sp['state'] == 'ATTENTION'
          and C2['miner']['state'] == 'PAUSED' and kinds2 == ['track-mismatch'])
    return bool(ok), (f"miner state={mi['state']} held={held} proposals={len(props_of(pdoc, 'miner'))} · syncp2p state={sp['state']} · "
                      f"track-only pause: state={C2['miner']['state']} proposals={kinds2}")


def ai6(base, tmp):
    M = load(base)
    r = fixture(tmp)
    doc, pdoc, err, C = run(M, r)
    want = {('syncp2p', 'mutation-missed'), ('syncp2p', 'mutation-invalid'), ('syncp2p', 'log-new-error-kind'),
            ('syncp2p', 'gate-newly-failing'), ('syncp2p', 'backlog-anchor-broken'), ('syncp2p', 'history-drift'),
            ('cryptosupply', 'zero-coverage'), ('storage', 'stale-evidence'), ('harness', 'backlog-unassigned'),
            ('harness', 'kat-unassigned'), ('syncp2p', 'tests-unregistered')}
    have = {(p['area'], p['kind']) for p in pdoc['proposals']}
    newk = [p['title'] for p in props_of(pdoc, 'syncp2p', 'log-new-error-kind')]
    una = [p['title'] for p in props_of(pdoc, 'harness', 'backlog-unassigned')]
    unreg = [p['title'] for p in props_of(pdoc, 'syncp2p', 'tests-unregistered')]
    ok = want <= have and len(unreg) == 1 and 'TestR3Orphan' in unreg[0] and 'TestR30' not in unreg[0] and len(newk) == 1 and 'timeout' in newk[0] and len(una) == 1 and 'B3' in una[0] \
        and not props_of(pdoc, 'security', 'backlog-anchor-broken')
    return ok, f'missing {sorted(want - have)} · unregistered {unreg} · new kinds {newk} · unassigned {una}'


def ai7(base, tmp):
    M = load(base)
    out = {}
    r = fixture(Path(tempfile.mkdtemp(dir=tmp)))
    doc, pdoc, err = M.evaluate(r)
    M.write(r, doc, pdoc)
    out['fresh'] = M.g23(r)[0]
    later = datetime.datetime.fromisoformat(doc['captured']) + datetime.timedelta(hours=30)
    out['stale'] = M.g23(r, at=later)[0]
    p = r / 'harness/runtime/area_proposals.json'
    pd = json.loads(p.read_text())
    pd['run_id'] = 'other'
    p.write_text(json.dumps(pd))
    out['other_run'] = M.g23(r)[0]
    M.write(r, doc, pdoc)
    reg = r / 'harness/areas.json'
    reg.write_text(reg.read_text().replace('"title": "docs"', '"title": "docs (edited)"'))
    out['edited'] = M.g23(r)[0]
    r2 = fixture(Path(tempfile.mkdtemp(dir=tmp)))
    d2, p2, _ = M.evaluate(r2)
    (r2 / 'evidence.txt').write_text('nothing here any more\n')       # the anchors of the shown values are gone
    M.write(r2, d2, p2)
    out['anchor_gone'] = M.g23(r2)[0]
    r3 = fixture(Path(tempfile.mkdtemp(dir=tmp)), broken_anchor=True)
    d3, p3, _ = M.evaluate(r3)
    M.write(r3, d3, p3)
    c3 = {c['id']: c for c in d3['areas']}
    out['refused'] = M.g23(r3)[0]
    out['refused_count'] = c3['security']['anchors']['refused']
    r4 = fixture(Path(tempfile.mkdtemp(dir=tmp)))      # a computed value refused at capture time (registry clean)
    d4, p4, _ = M.evaluate(r4)
    d4['areas'][0]['anchors'].update(refused=1, refused_ids=['new_tests@r3'])
    M.write(r4, d4, p4)
    out['refused_computed'] = M.g23(r4)[0]
    ok = out['fresh'] and not out['stale'] and not out['other_run'] and not out['edited'] and not out['anchor_gone'] \
        and not out['refused'] and out['refused_count'] == 1 and not out['refused_computed']
    return ok, f'{out}'


def ai8(base, tmp):
    M = load(base)
    r = fixture(tmp)
    reg = json.loads((r / 'harness/areas.json').read_text())
    vals, rr = M.auto_round(r, reg, 'r2', M.test_index(r))
    got = {a: (vals[a]['new_tests']['value'], vals[a]['mutations']['value']) for a in ('security', 'syncp2p', 'miner')}
    ok = got == {'security': (1, '1/1'), 'syncp2p': (1, '1/1'), 'miner': (0, '0/0')} and rr['full'] == 'pipeline_20260101T000000'
    return ok, f'(new_tests, mutations) {got} records {rr}'


def ai9(base, tmp):
    """r24 verify-areaintel: no anchor, no row also means the anchored line must state the value."""
    M = load(base)
    ev = lambda q, line: {'file': 'evidence.txt', 'quote': q, 'line': line}
    cases = {   # name: (history entry, unit, want an error)
        'as written': ({'value': 80, 'anchor': ev('speed 80 units', 2)}, '', False),
        'unbacked': ({'value': 81, 'anchor': ev('speed 80 units', 2)}, '', True),
        'rounded': ({'value': 5.31, 'anchor': ev('cpu=5.309856s', 11)}, '', False),
        'mis-rounded': ({'value': 5.32, 'anchor': ev('cpu=5.309856s', 11)}, '', True),
        'derive ok': ({'value': 0.143, 'derive': '34/238', 'anchor': ev('flips 238 dead 34', 10)}, '', False),
        'derive pct': ({'value': 100.0, 'derive': '100*11/11', 'anchor': ev('11 are all caught', 12)}, '%', False),
        'derive off line': ({'value': 0.147, 'derive': '35/238', 'anchor': ev('flips 238 dead 34', 10)}, '', True),
        'derive wrong': ({'value': 0.2, 'derive': '34/238', 'anchor': ev('flips 238 dead 34', 10)}, '', True),
        'derive code': ({'value': 1, 'derive': '__import__("os")', 'anchor': ev('flips 238 dead 34', 10)}, '', True),
        'ratio ok': ({'value': '11/11', 'anchor': ev('11 are all caught', 12)}, '', False),
        'ratio half': ({'value': '12/11', 'anchor': ev('11 are all caught', 12)}, '', True),
        'display': ({'value': 4800, 'display': 'latency 12', 'anchor': ev('latency 12 ms', 5)}, '', False),
    }
    got = {}
    for name, (ent, unit, want) in cases.items():
        t = Path(tempfile.mkdtemp(dir=tmp))
        r = fixture(t)
        reg = json.loads((r / 'harness/areas.json').read_text())
        for a in reg['areas']:
            if a['id'] == 'docs':
                a['metrics'] = [{'id': 'hand', 'better': 'none', 'unit': unit, 'source': {'kind': 'manual'}}]
                a['history'] = {'r3': {'hand': ent}}
        e, _ = M.validate(reg, r)
        got[name] = any(x.startswith('docs.hand@r3') for x in e) == want
    return all(got.values()), f'as expected per case {got}'


def ai10(base, tmp):
    """r24 integration: consensus_intel.json / peer_intel.json style feeds become area proposals."""
    M = load(base)
    r = fixture(Path(tempfile.mkdtemp(dir=tmp)))
    obs = {'detectors': [{'id': 'D1', 'grade': 'OBSERVED', 'title': 'v2 remnant', 'value': '1 seen'},
                         {'id': 'D2', 'grade': 'ANOMALY', 'title': 'first-relay concentration', 'findings': [{'peer': 'peer-0a1b2c3d'}]},
                         {'id': 'D3', 'grade': 'NORMAL', 'title': 'clock'}, {'id': 'D4', 'grade': 'NO-DATA', 'title': 'late'}],
           'proposals': [{'id': 'CO24-X1', 'severity': 'low', 'title': 'count refusals', 'anchors': []}]}
    W(r, 'harness/runtime/obs_intel.json', json.dumps(obs, indent=1))
    reg = json.loads((r / 'harness/areas.json').read_text())
    for a in reg['areas']:
        if a['id'] == 'observability':
            a['detector_feeds'] = [{'file': 'harness/runtime/obs_intel.json', 'list': 'detectors', 'grades': ['OBSERVED', 'ANOMALY']}]
            a['feeds'] = [{'file': 'harness/runtime/obs_intel.json', 'list': 'proposals', 'kind': 'node-gap'}]
    W(r, 'harness/areas.json', json.dumps(reg, indent=1))
    doc, pdoc, err, C = run(M, r)
    got = sorted((p['kind'], p['severity'], p['title'].split(' ')[0].rstrip(':')) for p in props_of(pdoc, 'observability')
                 if p['kind'].startswith('observatory-') or p['kind'] == 'node-gap')
    want = [('node-gap', 'low', 'CO24-X1'), ('observatory-anomaly', 'low', 'D2'), ('observatory-observed', 'medium', 'D1')]
    lines = (r / 'harness/runtime/obs_intel.json').read_text().splitlines()
    anch = all(any(e.get('line') and '"id": "D' in lines[e['line'] - 1] for e in p.get('evidence') or [])
               for p in props_of(pdoc, 'observability') if p['kind'].startswith('observatory-'))
    return got == want and anch, f'proposals {got} · anchored on the detector line {anch}'


KATS = [('AI1', ai1), ('AI2', ai2), ('AI3', ai3), ('AI4', ai4), ('AI5', ai5), ('AI6', ai6), ('AI7', ai7), ('AI8', ai8),
        ('AI9', ai9), ('AI10', ai10)]

# (kat, find, replace, why) — each must flip its KAT to FAIL on a temp copy of area_intel.py
MUTATIONS = [
    ('AI10', "                if g not in (fd.get('grades') or ('OBSERVED', 'ANOMALY')):", "                if g in ('NO-DATA',):",
     'a NORMAL detector is proposed as if it fired (r24 integration)'),
    ('AI10', "        for fd in a.get('detector_feeds') or []:", "        for fd in []:", 'an observatory detector feed is ignored (r24 integration)'),
    ('AI10', "                found.append((f'observatory-{g.lower()}', 'medium' if g == 'OBSERVED' else 'low',",
     "                found.append((f'observatory-{g.lower()}', 'low',", 'an OBSERVED rule violation is filed as low (r24 integration)'),
    ('AI4', "    return d, (better == 'higher' and d == 'down') or (better == 'lower' and d == 'up')", "    return d, False",
     'a regression beyond noise is not detected'),
    ('AI4', "    tol = abs(prev) * noise_rel", "    tol = 0", 'noise is ignored: a move inside noise is called a regression'),
    ('AI5', "        if paused:      # PAUSED, never failing", "        if False:      # PAUSED, never failing",
     'a paused area is shown failing'),
    ('AI5', "    if t and tracks.get(t) == 'paused':", "    if False:", "round.json's paused track does not pause the area"),
    ('AI1', "                if not resolved(st):           # no anchor, no row", "                if False:           # no anchor, no row",
     'an anchorless measured value is accepted'),
    ('AI1', "    for need in REQUIRED_AREAS:", "    for need in ():", 'a required area can be dropped from the registry'),
    ('AI1', "        if a.get('status') == 'paused' and not resolved(resolve_anchor(root, a.get('paused_why'))):",
     "        if False:", 'an area can be paused without a reason that resolves'),
    ('AI2', "    return {'status': 'BROKEN', 'line': None}", "    return {'status': 'OK', 'line': None}",
     'a quote that is gone still resolves'),
    ('AI3', "            if s > best_s:", "            if s >= 0 and best is None:", 'the first matching area wins, not the most specific'),
    ('AI6', "BAD_MUT = ('MISSED', 'STALE', 'INVALID', 'BROKEN', 'NEWFAIL')", "BAD_MUT = ('MISSED', 'STALE', 'BROKEN', 'NEWFAIL')",
     'an INVALID mutation is not reported'),
    ('AI6', "        for p in lis[-6:-1]:", "        for p in lis[-6:]:", 'new ERROR kinds are compared against the snapshot itself'),
    ('AI6', "    if cur in order and gap > stale_n:", "    if cur in order and gap > stale_n + 5:",   # r28: re-anchored (staleness() is a function now, N28-03); r30: gap skips paused rounds (B231)
     'stale evidence is never reported'),
    ('AI6', "        (ok if ((root / t).exists() or Path(t).name in files) else bad).append(t)", "        ok.append(t)",
     'a §7 anchor to a file that is gone still resolves'),
    ('AI6', "                if bef and bef[0] == 'PASS':", "                if False:", 'a newly failing gate is filed as an old failure'),
    ('AI6', "                if e is h and c and not is_pending(c.get('value')) and c.get('computed') and not same_value(c['value'], h['value']):",
     "                if False:", 'a recorded value that no longer recomputes is not reported'),
    ('AI6', "                          and area_of(areas, f) == a['id'] and (d, n) not in ran and (d, n) not in opt)",
     "                          and area_of(areas, f) == a['id'] and False)", 'tests the round never ran are not reported'),
    ('AI7', "    if age >= FRESH_H:", "    if False:", 'a stale scorecard passes G23'),
    ('AI7', "    if doc.get('registry', {}).get('sha') != sha(P['reg']):", "    if False:", 'areas.json edited after the run passes G23'),
    ('AI7', "    if refused:\n", "    if False:\n", 'a value refused for its anchor passes G23'),
    ('AI7', "    if pdoc.get('run_id') != doc.get('run_id'):", "    if False:", 'a proposals feed from another run passes G23'),
    ('AI8', "                f = tidx.get((d, name))", "                f = None", 'tests are attributed by package only'),
    # r24 verify-areaintel: value backing
    ('AI9', "                if resolved(st) and mid not in AUTO and kind not in RECOMP:     # r24 verify: the line states it",
     "                if False:", 'a value its anchored line does not state is accepted'),
    ('AI9', "RECOMP = ('pipeline', 'gomut_all', 'gomut_upstream', 'pipeline_step')",
     "RECOMP = ('pipeline', 'gomut_all', 'gomut_upstream', 'pipeline_step', 'manual')", 'manual values are exempted as if recomputed'),
    ('AI9', "        miss = [x for x in lits if x not in nums and x not in free]", "        miss = []",
     'a derive over numbers that are not on the line is accepted'),
    ('AI9', "        if abs(res - target) > 0.5 * 10 ** -dec + 1e-12:", "        if False:",
     'a derive that does not compute the value is accepted'),
    ('AI9', "        return (float(m.group(1)) in nums and float(m.group(2)) in nums), 'ratio'",
     "        return (float(m.group(2)) in nums), 'ratio'", 'a ratio with only its denominator on the line is accepted'),
    ('AI9', "        return any(abs(n - float(val)) <= 0.5 * 10 ** -dec + 1e-12 for n in nums), 'number'",
     "        return any(abs(n - float(val)) <= 1.0 for n in nums), 'number'", 'a number near a printed one is accepted'),
]


def copy_mod():
    d = Path(tempfile.mkdtemp(prefix='r24ai-'))
    (d / MOD).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(HARNESS / MOD, d / MOD)
    shutil.copy2(HARNESS / 'intel/backlog_truth.py', d / 'intel/backlog_truth.py')   # r30 B230: is_open reads it
    return d


def main():
    fails = 0
    base = copy_mod()
    for name, fn in KATS:
        tmp = Path(tempfile.mkdtemp(prefix='r24aifx-'))
        try:
            ok, det = fn(base, tmp)
        except Exception as e:                                    # noqa: BLE001
            ok, det = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:420]}")
        shutil.rmtree(tmp, ignore_errors=True)
    shutil.rmtree(base, ignore_errors=True)
    missed = 0
    byname = dict(KATS)
    for kat, find, repl, why in MUTATIONS:
        d = copy_mod()
        p = d / MOD
        text = p.read_text()
        if text.count(find) != 1:
            print(f'  ??      {kat}: {why} — find text occurs {text.count(find)} times')
            missed += 1
            shutil.rmtree(d, ignore_errors=True)
            continue
        p.write_text(text.replace(find, repl))
        t2 = Path(tempfile.mkdtemp(prefix='r24aifx-m-'))
        try:
            ok2, _ = byname[kat](d, t2)
            verdict = 'MISSED ' if ok2 else 'proved '
        except Exception as e:                                     # noqa: BLE001 — a crash proves nothing: INVALID
            ok2, verdict = True, f'INVALID ({type(e).__name__})'
        print(f'  {verdict} {kat}: {why}')
        missed += ok2
        shutil.rmtree(d, ignore_errors=True)
        shutil.rmtree(t2, ignore_errors=True)
    print(f'\nR24 area-intel KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
