#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the r25 changes to harness/intel/area_intel.py (dero-rft §7 B52, B54, B89).

  AC1 dated corrections (B52: `record` never overwrites a booked value, so a superseded one stayed frozen; r24
      gates/kats were booked at c4cebe6 before G24/G25 and new KATs existed): apply_correction keeps the old value, its
      anchor and display under `corrections` with a date, a why and an evidence anchor; correct() in auto mode corrects
      exactly the values whose records now recompute differently and leaves equal ones alone; validate refuses an
      undated, why-less or evidence-less correction.
  AC2 event denominator (B54: block_tx_roundtrip_observed_total 0 over 217 blocks that carried 0 txs was booked as a
      measured 0): with needs_event, a 0 whose event counter is 0 or absent is `pending: no event`; a 0 with events is a
      reading; a non-zero value is kept; a source without needs_event is untouched.
  AC3 booking by binary (B89, lesson #69): a /metrics capture with no '# version' line yields live_round 'unknown',
      which record() never books; a capture of the r24 binary yields 'r24' and books to r24 only; a log_intel run of the
      r24 binary (its 4 ERRORs at tip) is an r24 reading, never r25's.
  AC4 opt-in tests (B52: area_intel filed the two env-gated simulator harnesses as tests-unregistered while NT1 excludes
      them by design): opt_in_body reads an env-gated skip in the first lines, not a plain or a late one.
  AC5 step names (tooling class 'substring step match', c191245): step_is matches the command or the command plus its
      arguments, never a longer script name sharing the prefix.
  AC6 volatile anchors (rft §7 B106, R25 measurement): a consensus KPI is anchored on the KPI line of the timestamped
      capture that states the value, never on harness/runtime/consensus_intel.json (rewritten by every S7 run: three r25
      values went BROKEN one run after `record`); with no capture stating the value the JSON stays the fallback.

  python3 -I harness/kat/test_area_r25.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import importlib.util, json, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
SRC = HARNESS / 'intel' / 'area_intel.py'


def load(path):
    spec = importlib.util.spec_from_file_location(f'ai25_{abs(hash(str(path)))}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def tree(d, prom_text=None):
    r = Path(d)
    (r / 'harness/runtime').mkdir(parents=True)
    (r / 'harness/loop/runs').mkdir(parents=True)
    (r / 'ev.txt').write_text('gates now 5/5 in the last cycle\ngates were 4/4 at c4cebe6\nlive txcount: blocks 217 tx_total 0\n')
    reg = {'rounds': [{'id': 'r23c'}, {'id': 'r24'}, {'id': 'r25'}], 'areas': [
        {'id': 'harness', 'title': 'h', 'owner_dim': 'h', 'status': 'active', 'code_paths': [], 'kat_files': [], 'gates': [],
         'gomut_prefixes': [], 'backlog': [], 'metrics': [{'id': 'obs', 'source': {'kind': 'prom', 'name': 'block_tx_roundtrip_observed_total'}}],
         'history': {'r24': {'gates': {'value': '4/4', 'anchor': {'file': 'ev.txt', 'quote': 'gates were 4/4 at c4cebe6', 'line': 2}},
                             'kats': {'value': '3/3', 'anchor': {'file': 'ev.txt', 'quote': 'gates were 4/4 at c4cebe6', 'line': 2}}}}}]}
    (r / 'harness/areas.json').write_text(json.dumps(reg))
    (r / 'harness/round.json').write_text(json.dumps({'current': 'r25', 'rounds': [{'id': 'r25', 'status': 'in-progress'}]}))
    if prom_text is not None:
        (r / 'harness/runtime/area_prom_20261103T000000.txt').write_text(prom_text)
    return r


def ac1(m):
    out = {}
    e = m.apply_correction({'value': '4/4', 'anchor': {'file': 'ev.txt', 'quote': 'q', 'line': 2}, 'display': '4/4'},
                           {'value': '5/5', 'anchor': {'file': 'ev.txt', 'quote': 'gates now 5/5', 'line': 1}}, '2026-11-03', 'why',
                           {'file': 'ev.txt', 'quote': 'gates now 5/5', 'line': 1})
    c = (e.get('corrections') or [{}])[-1]
    out['kept_old'] = e['value'] == '5/5' and c.get('was') == '4/4' and c.get('date') == '2026-11-03' and c.get('was_display') == '4/4'
    e2 = m.apply_correction(e, {'value': 'pending', 'why': 'w'}, '2026-11-04', 'again', c['evidence'])
    out['chain'] = [x['was'] for x in e2['corrections']] == ['4/4', '5/5'] and e2['value'] == 'pending'
    with tempfile.TemporaryDirectory() as d:
        r = tree(d)
        ev = {'file': 'ev.txt', 'quote': 'gates now 5/5 in the last cycle', 'line': 1}
        m.auto_round = lambda root, reg, rid, tidx: ({'harness': {'gates': {'value': '5/5', 'computed': True, 'anchor': ev},
                                                                    'kats': {'value': '3/3', 'computed': True, 'anchor': ev}}}, {})
        n, probs = m.correct(r, 'r24', 'records recompute', '2026-11-03')
        h = json.loads((r / 'harness/areas.json').read_text())['areas'][0]['history']['r24']
        out['auto'] = n == 1 and not probs and h['gates']['value'] == '5/5' and h['gates']['corrections'][0]['was'] == '4/4' \
            and 'corrections' not in h['kats']
        n0, p0 = m.correct(r, 'r24', '', '2026-11-03')
        out['needs_why'] = n0 == 0 and bool(p0)
        good = m.correction_problems(r, h['gates']['corrections'])
        bad = [len(m.correction_problems(r, [c])) for c in (
            {'date': '3 Nov', 'was': 1, 'why': 'x', 'evidence': ev},
            {'date': '2026-11-03', 'was': 1, 'why': ' ', 'evidence': ev},
            {'date': '2026-11-03', 'why': 'x', 'evidence': ev},
            {'date': '2026-11-03', 'was': 1, 'why': 'x', 'evidence': {'file': 'ev.txt', 'quote': 'not in the file at all'}})]
        out['validate'] = good == [] and bad == [1, 1, 1, 1]
        n2, p2 = m.correct(r, 'r24', 'B54', '2026-11-03', 'harness.kats', {'value': 'pending', 'why': 'B54', 'evidence':
                           {'file': 'ev.txt', 'quote': 'live txcount: blocks 217 tx_total 0', 'line': 3}})
        h2 = json.loads((r / 'harness/areas.json').read_text())['areas'][0]['history']['r24']
        out['manual'] = n2 == 1 and h2['kats']['value'] == 'pending' and h2['kats']['corrections'][0]['was'] == '3/3'
    return all(out.values()), f'{out}'


def ac2(m):
    s = {'kind': 'prom', 'name': 'obs', 'needs_event': {'name': 'blockchain_tx_total', 'what': 'a tx-carrying block'}}
    a = m.event_gate({'value': 0.0, 'anchor': {}}, s, {'blockchain_tx_total': (0.0, 'l', 1)})
    b = m.event_gate({'value': 0.0, 'anchor': {}}, s, {})
    c = m.event_gate({'value': 0.0, 'anchor': {}}, s, {'blockchain_tx_total': (12.0, 'l', 1)})
    d = m.event_gate({'value': 3.0, 'anchor': {}}, s, {})
    e = m.event_gate({'value': 0.0, 'anchor': {}}, {'kind': 'prom', 'name': 'obs'}, {})
    got = [m.is_pending(a['value']) and 'no event' in a['why'], m.is_pending(b['value']), c['value'] == 0.0, d['value'] == 3.0, e['value'] == 0.0]
    names = m.prom_names({'areas': [{'metrics': [{'id': 'x', 'source': s}]}]})
    return all(got) and 'blockchain_tx_total' in names, f'got {got} names {sorted(names)}'


def ac3(m):
    out = {}
    with tempfile.TemporaryDirectory() as d:
        r = tree(d, '# r24 area_intel: read-only GET\nblock_tx_roundtrip_observed_total 7\n')
        cv, _ = m.current_values(r, json.loads((r / 'harness/areas.json').read_text()))
        e = cv['harness']['obs']
        out['unknown'] = e.get('live_round') == 'unknown' and not m.live_belongs(e, 'r25') and not m.live_belongs(e, 'r24')
    with tempfile.TemporaryDirectory() as d:
        r = tree(d, '# r24 area_intel\n# version 3.6.0-153.DEROHE.STARGATE+22102026.r24\nblock_tx_roundtrip_observed_total 7\n')
        cv, _ = m.current_values(r, json.loads((r / 'harness/areas.json').read_text()))
        e = cv['harness']['obs']
        out['r24'] = e.get('live_round') == 'r24' and m.live_belongs(e, 'r24') and not m.live_belongs(e, 'r25')
    out['tree_value'] = m.live_belongs({'value': 1}, 'r25')
    with tempfile.TemporaryDirectory() as d:            # a log_intel run of the r24 binary is an r24 reading
        r = tree(d)
        reg = json.loads((r / 'harness/areas.json').read_text())
        reg['areas'][0]['metrics'].append({'id': 'errs', 'source': {'kind': 'logintel', 'field': 'errors_at_tip'}})
        (r / 'harness/runtime/logintel_20261103T000000.json').write_text(json.dumps({'runs': [
            {'version': '3.6.0-153.DEROHE.STARGATE+22102026.r24', 'errors_at_tip': 4}]}, indent=1))
        cv, _ = m.current_values(r, reg)
        e = cv['harness']['errs']
        out['logintel_r24'] = e.get('value') == 4 and e.get('live_round') == 'r24' and not m.live_belongs(e, 'r25')
    return all(out.values()), f'{out}'


def ac4(m):
    got = [m.opt_in_body(['\tif os.Getenv("R24_EVICT") != "1" {', '\t\tt.Skip("opt-in")', '\t}']),
           m.opt_in_body(['\tif testing.Short() {', '\t\tt.Skip("short")', '\t}']),
           m.opt_in_body(['\tx := 1', '\ty := 2', '\tz := 3', '\tw := 4', '\tif os.Getenv("A") == "" { t.Skip() }'])]
    with tempfile.TemporaryDirectory() as d:
        r = Path(d)
        (r / 'p').mkdir()
        (r / 'p/a_test.go').write_text('package p\nfunc TestR25Env(t *testing.T) {\n\tif os.Getenv("X") == "" {\n\t\tt.Skip("opt-in")\n'
                                       '\t}\n}\nfunc TestR25Plain(t *testing.T) {\n}\n')
        opt = m.opt_in_tests(r, {('p/', 'TestR25Env'): 'p/a_test.go', ('p/', 'TestR25Plain'): 'p/a_test.go'})
    return got == [True, False, False] and opt == {('p/', 'TestR25Env')}, f'got {got} opt {opt}'


def ac5(m):
    got = [m.step_is('harness/gen_deroarch.py build', 'harness/gen_deroarch.py build'),
           m.step_is('harness/intel/coherence.py --record', 'harness/intel/coherence.py'),
           m.step_is('harness/kat/test_coherence_r24.py', 'coherence.py'),
           m.step_is('harness/intel/coherence.py.bak', 'harness/intel/coherence.py'),
           m.step_is('anything', '')]
    return got == [True, True, False, False, False], f'got {got}'


def ac6(m):
    out = {}
    with tempfile.TemporaryDirectory() as d:
        r = tree(d)
        reg = json.loads((r / 'harness/areas.json').read_text())
        reg['areas'][0]['metrics'].append({'id': 'bt', 'source': {'kind': 'consensus', 'field': 'block_time_mean_s'}})
        (r / 'harness/runtime/consensus_intel.json').write_text(json.dumps({'binary_round': 'r25', 'kpis': {'block_time_mean_s': 18.504}}, indent=1))
        (r / 'harness/runtime/consensus_capture_20261104T160043Z.txt').write_text('# version x\nkpi block_time_mean_s = 18.504\n')
        (r / 'harness/runtime/consensus_capture_20261104T150208Z.txt').write_text('kpi block_time_mean_s = 18.525\n')
        cv, _ = m.current_values(r, reg)
        a = (cv['harness']['bt'].get('anchor') or {})
        out['capture'] = a.get('file') == 'harness/runtime/consensus_capture_20261104T160043Z.txt' and a.get('line') == 2
        (r / 'harness/runtime/consensus_capture_20261104T160043Z.txt').unlink()
        cv, _ = m.current_values(r, reg)
        out['fallback'] = (cv['harness']['bt'].get('anchor') or {}).get('file') == 'harness/runtime/consensus_intel.json'
    return all(out.values()), f'{out}'


KATS = [('AC1', ac1), ('AC2', ac2), ('AC3', ac3), ('AC4', ac4), ('AC5', ac5), ('AC6', ac6)]
MUTATIONS = [
    ("    prior.append({'date': date, 'was': old.get('value'),", "    prior = []\n    prior.append({'date': date, 'was': old.get('value'),",
     'an earlier correction is dropped'),
    ("                    and not is_pending(ent.get('value')) and not same_value(ent['value'], c['value'])):",
     "                    and not is_pending(ent.get('value'))):", 'a value that still recomputes is "corrected" too'),
    ("        if not DATE_RX.match(str(c.get('date', ''))):", "        if False:", 'an undated correction passes validate'),
    ("        if not resolved(resolve_anchor(root, c.get('evidence'))):", "        if False:",
     'a correction without evidence passes validate'),
    ("    if not why or not why.strip():\n        return 0, ['a correction needs --why']\n", "", 'a correction without a why is applied'),
    ("    if ev and ev[0] > 0:", "    if True:", 'a 0 with no event is booked as a reading (B54)'),
    ("    if not ne or not isinstance(e, dict) or is_pending(e.get('value')) or num(e.get('value')) != 0:",
     "    if not ne or not isinstance(e, dict) or is_pending(e.get('value')):", 'a non-zero reading is gated as no event'),
    ("            if (s.get('needs_event') or {}).get('name') and not summed_only:\n                ns.add(s['needs_event']['name'])\n", "",
     'the event counter is never captured'),
    ("                    e = {'value': v, 'anchor': line_anchor(root, prel, l), 'live_round': prom_round or UNKNOWN_ROUND}",
     "                    e = {'value': v, 'anchor': line_anchor(root, prel, l), 'live_round': prom_round}",
     'a capture without a version line carries no live_round (booked to the current round)'),
    ("                         'live_round': capture_round(f\"# version {cur.get('version')}\\n\", round_order(reg)) or UNKNOWN_ROUND}",
     "                         'live_round': None}", "a log_intel reading of the r24 binary is booked to r25 (B89)"),
    ("    return 'os.Getenv(' in head and 't.Skip' in head\n\n\ndef opt_in_tests", "    return 't.Skip' in head\n\n\ndef opt_in_tests",
     'a plain skip read as opt-in'),
    ("    head = '\\n'.join(body_lines[:OPT_IN_LINES])\n    return 'os.Getenv(' in head and 't.Skip' in head\n\n\ndef opt_in_tests",
     "    head = '\\n'.join(body_lines)\n    return 'os.Getenv(' in head and 't.Skip' in head\n\n\ndef opt_in_tests", 'a late env check read as opt-in'),
    ("    return bool(w) and (st == w or st.startswith(w + ' '))", "    return bool(w) and st.startswith(w)",
     'a step matched by prefix (substring step match)'),
    ("    return bool(w) and (st == w or st.startswith(w + ' '))", "    return bool(w) and (w in st)",
     'a step matched by substring'),
    ("                    e = {'value': kv[s['field']], 'anchor': anc or line_anchor(", "                    e = {'value': kv[s['field']], 'anchor': None or line_anchor(",
     'a consensus KPI anchored on the volatile consensus_intel.json (B106)'),
]


def main():
    mod = load(SRC)
    ok = True
    for name, fn in KATS:
        try:
            o, det = fn(mod)
        except Exception as e:                                    # noqa: BLE001
            o, det = False, f'{type(e).__name__}: {e}'
        print(f"{'ok  ' if o else 'FAIL'} {name} {det[:400]}")
        ok &= o
    if not ok:
        return 3
    src, missed = SRC.read_text(encoding='utf-8'), 0
    for find, repl, why in MUTATIONS:
        if src.count(find) != 1:
            print(f'  ??      {why}: find text occurs {src.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'area_intel.py'
            p.write_text(src.replace(find, repl, 1), encoding='utf-8')
            try:
                m = load(p)
            except Exception as e:                                # noqa: BLE001
                print(f'  INVALID {why}: mutant does not load ({type(e).__name__})')
                missed += 1
                continue
            survived = True
            for _, fn in KATS:
                try:
                    survived &= fn(load(p))[0]
                except Exception:                                 # noqa: BLE001 — a crash is a detection
                    survived = False
        print(f"  {'MISSED ' if survived else 'proved '} {why}")
        missed += survived
    print(f'\nr25 area-intel KATs: {len(KATS)}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
