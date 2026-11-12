#!/usr/bin/env python3
"""KAT + mutation proofs for the R30 tooling rows B204 B230 B231 B232 B233 and the proposal triage (rft §7, §8
tooling). No live file is read or written: every registry, record and skill is a temp file; the tree is only read.

  TR1  B230  area_intel.is_open uses the backlog_truth classifier: forged FIXED / REPORT-ONLY / CONFIRMED leads and an
             'OPEN … **r29: FIXED:**' row are closed; OPEN / PARTLY / IMPLEMENTED are open (the old 3-word regex read
             68 of the 73 'unassigned' Part A rows as open). backlog_rows reads BD rows; backlog_key sorts B2 < B10 < BD1.
  TR2  B230  anchor_tokens: a ~/ home path is testimony, never a broken tree anchor.
  TR3  B231  minerintel source: the newest minerintel run is booked to the round its run.version names (r30), not to
             registry.current (r31); a run of a round whose miner track was paused is shown, not graded.
  TR4  B231  discover_round_records skips a record without its END line (the run in progress) and takes the newest
             completed one.
  TR5  B231  staleness() does not count rounds in which the area's track was paused (last reading r23c, r24-r29
             paused, r30 = 1 round: not stale); with no paused round the same series is stale.
  TR6  B231  a prom_ratio display carries the metric's unit ('53.6 ms (1.019 / 19 x 1000)').
  TR7  B231  disclosure_live source: check S3 of the newest capture (S2 FAIL, S3 PASS -> 1), booked by getinfo.version.
  TR8  B231  the card's pending_why is the newest point's why when it is pending (the event gate), else None.
  TR9  B232  tooling_intel GENERATORS covers every page generator (harness/gen_*.py, artifacts/src/gen_*.py,
             harness/soundness.py); ledger_cmd resolves the round-named page (r30 page when it exists, else the newest).
  TR10 B233  backlog_truth.body_rank reads a round-prefixed bold status ('**r29: FIXED:**') and ignores one quoted in a
             `code span`. r30 verify D6: also a multi-word prefix ('**r29 merge: FIXED**', '**r29: cost bench DONE,
             …**'), an upper-case one ('**R29: FIXED:**') and DONE; '**r29: not FIXED**' states nothing; a status in a
             ``double-backtick `span` `` is quoted; a REJECTED lead (B183) is closed-class.
  TR11 B204  skill_fresh at round open: a skill at the previous round is DUE (fresh 1), one last recorded earlier (a
             resumed track's skill at r23c) still raises (fresh 0); round_open_grace is None once the round merged.
  TR12 r30   the proposal triage map is carried run to run (a verdict survives the proposal leaving the feed) and
             triage_problems refuses a verdict outside fix / bookkeeping / not-a-defect.

  python3 -I harness/kat/test_tooling_r30.py   # KATs, then each mutation (on a temp copy) must fail its owning KAT
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not proved (MISSED / WRONG-KAT / INVALID) or was coupled.
"""
import contextlib, importlib.util, io, json, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
PATHS = {'ai': 'harness/intel/area_intel.py', 'bt': 'harness/intel/backlog_truth.py', 'ti': 'harness/intel/tooling_intel.py'}


def P(over, key):
    return Path(over.get(key) or ROOT / PATHS[key])


def load(over, key):
    """the module; area_intel loads backlog_truth from its own directory, so a mutant pair sits in one temp dir."""
    path = P(over, key)
    if key == 'ai' and 'bt' in over and Path(over['bt']).parent != path.parent:
        d = Path(tempfile.mkdtemp(prefix='tr30-pair-'))
        shutil.copyfile(path, d / 'area_intel.py')
        shutil.copyfile(over['bt'], d / 'backlog_truth.py')
        path = d / 'area_intel.py'
    elif key == 'ai' and path.parent != ROOT / 'harness/intel':
        bt = path.parent / 'backlog_truth.py'
        if not bt.exists():
            shutil.copyfile(P(over, 'bt'), bt)
    spec = importlib.util.spec_from_file_location(f'tr30_{key}_{abs(hash(str(path)))}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stdout(io.StringIO()):
        spec.loader.exec_module(m)
    return m


def tree(files):
    d = Path(tempfile.mkdtemp(prefix='tr30-'))
    for rel, body in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body if isinstance(body, str) else json.dumps(body))
    return d


def kat_tr1(over):
    ai = load(over, 'ai')
    closed = ['FIXED (r28): the guard landed', 'REPORT-ONLY (R25): upstream design', 'CONFIRMED live 2026-11-05',
              'OPEN (R29 harness): pin each round **r29: FIXED:** pins land at 7a1b']
    opened = ['OPEN (R30, tooling)', 'PARTLY (R28): 5 files tagged', 'IMPLEMENTED (r29)', 'BACKEND READY']
    bad = [c for c in closed if ai.is_open(c)] + [o for o in opened if not ai.is_open(o)]
    rft = ('| id | item | dim | anchor | status |\n|---|---|---|---|---|\n| B10 | x | t | a.go | OPEN |\n'
           '| BD3 | y | d | b.go | OPEN |\n| B2 | z | t | c.go | OPEN |\n')
    d = tree({'artifacts/dero-rft.md': rft})
    try:
        rows = ai.backlog_rows(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    if 'BD3' not in rows:
        bad.append('BD rows invisible')
    if sorted(rows, key=ai.backlog_key) != ['B2', 'B10', 'BD3']:
        bad.append(f'order {sorted(rows, key=ai.backlog_key)}')
    return not bad, f'misread {bad}' if bad else 'closed-class leads and round-prefixed bold read as closed; BD rows, natural order'


def kat_tr2(over):
    ai = load(over, 'ai')
    d = tree({'harness/x.py': ''})
    try:
        ok, bad, gk = ai.anchor_tokens(d, '`~/derohe-persist/round_state/r30_NOTES.md`; `harness/x.py`', {'x.py'})
    finally:
        shutil.rmtree(d, ignore_errors=True)
    good = bad == [] and 'harness/x.py' in ok and any('r30_NOTES.md' in g for g in gk)
    return good, f'ok {ok} bad {bad} testimony {gk}'


def _mi_tree(paused_r30=False):
    run = {'version': '3.6.0-153.DEROHE.STARGATE+22102026.r30', 'hashrate': {'mean': 96205.5}}
    rj = {'current': 'r31', 'rounds': [{'id': 'r29', 'tracks': {'miner': 'paused'}},
                                       {'id': 'r30', 'tracks': {'miner': 'paused' if paused_r30 else 'active'}},
                                       {'id': 'r31', 'tracks': {'miner': 'active'}}]}
    return tree({'harness/round.json': rj, 'harness/runtime/minerintel_20261108T231500.json':
                 json.dumps({'runs': [run]}, indent=1)})


def kat_tr3(over):
    ai = load(over, 'ai')
    reg = {'rounds': [{'id': 'r29'}, {'id': 'r30'}, {'id': 'r31'}], 'current': 'r31', 'areas': []}
    d = _mi_tree()
    try:
        e = ai.minerintel_value(d, {'kind': 'minerintel', 'field': 'hashrate.mean', 'unit': 'H/s'}, reg)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    d = _mi_tree(paused_r30=True)
    try:
        e2 = ai.minerintel_value(d, {'kind': 'minerintel', 'field': 'hashrate.mean'}, reg)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    ok = (e.get('value') == 96205.5 and e.get('live_round') == 'r30' and e.get('anchor')
          and ai.is_pending(e2.get('value')) and 'not graded' in str(e2.get('why')))
    return bool(ok), f'active {e}; paused {e2}'


def kat_tr4(over):
    ai = load(over, 'ai')
    begin = {'stage': 'run', 'status': 'BEGIN', 'round': 'r29'}
    done = '\n'.join(json.dumps(x) for x in [begin, {'stage': 'project', 'status': 'PASS', 'gates': '30/33'},
                                              {'stage': 'done', 'status': 'END', 'ok': True}]) + '\n'
    live = '\n'.join(json.dumps(x) for x in [begin, {'stage': 'project', 'status': 'START'}]) + '\n'
    d = tree({'harness/loop/runs/pipeline_20261108T123859.jsonl': done,
              'harness/loop/runs/pipeline_20261108T165350.jsonl': live})
    try:
        r = ai.discover_round_records(d, {'rounds': [{'id': 'r29', 'pipeline_full': 'pending'}]}, 'r29')
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return r.get('project') == 'pipeline_20261108T123859', f'project record {r}'


def kat_tr5(over):
    ai = load(over, 'ai')
    order = ['r23c', 'r24', 'r25', 'r26', 'r27', 'r28', 'r28d', 'r29', 'r30']
    mc = [{'id': 'live_hs', 'last': {'round': 'r23c'}}]
    md = [{'id': 'live_hs'}]
    _, f1 = ai.staleness(mc, md, {}, order, 'r30', 2, paused_rounds=order[1:8])
    _, f2 = ai.staleness(mc, md, {}, order, 'r30', 2)
    return f1 is None and f2 and f2[0] == 'stale-evidence', f'paused r24-r29: {f1}; none paused: {f2 and f2[0]}'


def kat_tr6(over):
    ai = load(over, 'ai')
    reg = {'rounds': [{'id': 'r29'}], 'areas': [{'id': 'g', 'metrics': [
        {'id': 'flip', 'unit': 'ms', 'source': {'kind': 'prom_ratio', 'num': 'gw_flip_seconds_sum',
                                                'den': 'gw_flip_seconds_count', 'scale': 1000}}]}]}
    d = tree({'harness/round.json': {'current': 'r29', 'rounds': [{'id': 'r29'}]},
              'harness/runtime/area_prom_20261108T201509.txt':
              '# version 3.6.0-153.DEROHE.STARGATE+22102026.r29\ngw_flip_seconds_sum 1.019\ngw_flip_seconds_count 19\n'})
    try:
        e = ai.current_values(d, reg)[0]['g'].get('flip') or {}
    finally:
        shutil.rmtree(d, ignore_errors=True)
    disp = str(e.get('display'))
    return ' ms ' in disp and 'x 1000' in disp, f'display {disp!r}'


def kat_tr7(over):
    ai = load(over, 'ai')
    reg = {'rounds': [{'id': 'r28d'}, {'id': 'r29'}], 'areas': []}
    cap = ('# disclosure live\ngetinfo.version 3.6.0-153.DEROHE.STARGATE+22102026.r28d\n'
           'check FAIL S2 auditor formula_supply == CalcSupply(segment_to)\n'
           'check PASS S3 GetMonetaryIntegrity.emission agrees with GetEmissionAudit: 18 shared fields equal\n')
    d = tree({'harness/runtime/disclosure_live_20261108T122048Z.txt': cap})
    try:
        e = ai.disclosure_live_value(d, {'kind': 'disclosure_live', 'check': 'S3'}, reg)
        e2 = ai.disclosure_live_value(d, {'kind': 'disclosure_live'}, reg)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    ok = e.get('value') == 1 and e.get('live_round') == 'r28d' and e.get('anchor') and e2.get('value') == 1
    return bool(ok), f'S3 {e}; default {e2.get("value")}'


def kat_tr8(over):
    ai = load(over, 'ai')
    w = 'pending: no event (blockchain_tx_total is 0); a 0 here is not a reading'
    a = ai.newest_pending_why([{'round': 'r26', 'value': 3}, {'round': 'r29', 'value': 'pending', 'why': w}])
    b = ai.newest_pending_why([{'round': 'r26', 'value': 'pending', 'why': 'x'}, {'round': 'r29', 'value': 3}])
    return a == w and b is None, f'pending last {a!r}; measured last {b!r}'


def kat_tr9(over):
    ti = load(over, 'ti')
    cmds = {c[0] for c, _ in ti.GENERATORS}
    gens = {str(p.relative_to(ROOT)) for p in list((ROOT / 'harness').glob('gen_*.py')) + list((ROOT / 'artifacts/src').glob('gen_*.py'))}
    gens.add('harness/soundness.py')
    miss = sorted(gens - cmds)
    d = tree({'harness/round.json': {'current': 'r30'}, 'artifacts/dero-r1-r28.html': '', 'artifacts/dero-r1-r29.html': ''})
    try:
        a = ti.ledger_cmd(d)
        (d / 'artifacts/dero-r1-r30.html').write_text('')
        b = ti.ledger_cmd(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    ok = not miss and a and a[1] == 'artifacts/dero-r1-r29.html' and a[0][:3] == ['artifacts/src/gen_ledger.py', '--last', '29'] \
        and b and b[1] == 'artifacts/dero-r1-r30.html'
    return bool(ok), f'generators missing {miss}; ledger {a} then {b}'


def kat_tr10(over):
    bt = load(over, 'bt')
    a = bt.body_rank('OPEN (R29 harness): pins **r29: FIXED:** at 7a1b')
    b = bt.body_rank('OPEN (R30): KAT on forged `**r29: FIXED:**` rows')
    c = bt.body_rank('OPEN (R28): x **CLOSED (r28)**')
    ok = a[0] == bt.RANK['closed'] and b[0] is None and c[0] == bt.RANK['closed']
    # r30 verify D6
    closed = {'multi-word': 'OPEN (R29): x **r29 merge: FIXED** at 9ce1', 'upper': 'PARTLY (R29): **R29: FIXED:** y',
              'done': 'REJECTED-free OPEN: a **r29: cost bench DONE, class unchanged:** z'}
    quoted = {'double-backtick': 'OPEN (R30): KAT on ``a `**r29: FIXED**` b`` rows',
              'double-backtick-odd': 'OPEN (R30): the input ``**r29: FIXED** ` x`` row',
              'negated': 'OPEN (R30): **r29: not FIXED** yet'}
    got = {k: bt.body_rank(v)[0] for k, v in {**closed, **quoted}.items()}
    bad = [k for k in closed if got[k] != bt.RANK['closed']] + [k for k in quoted if got[k] is not None]
    rej = bt.lead_class('REJECTED (not merged); kept as the counter-example **r29: cost bench DONE (REJECTED):**')
    ok = ok and not bad and rej == 'closed'
    return ok, f'prefixed {a}; code span {b}; plain {c}; D6 wrong {bad}; REJECTED lead {rej}'


def _skills(d, rounds):
    for name, last in rounds.items():
        (d / '.skills' / name).mkdir(parents=True, exist_ok=True)
        (d / '.skills' / name / 'SKILL.md').write_text(f'# {name}\n\n## Round {last.lstrip("r")} (x)\ntext\n')


def kat_tr11(over):
    ti = load(over, 'ti')
    reg = {'current': 'r30', 'rounds': [{'id': 'r28d', 'status': 'measured'}, {'id': 'r29', 'status': 'measured'},
                                        {'id': 'r30', 'status': 'in-progress', 'merge_commit': 'pending'},
                                        {'id': 'r31', 'status': 'planned'}]}
    g = ti.round_open_grace(reg, 'r30')
    merged = json.loads(json.dumps(reg))
    merged['rounds'][2]['merge_commit'] = 'abc123'
    g2 = ti.round_open_grace(merged, 'r30')
    d = Path(tempfile.mkdtemp(prefix='tr30-sk-'))
    try:
        _skills(d, {'node': 'r29', 'miner': 'r23c'})
        k1 = ti.skill_kpis(d, 'r30', [], g)
        shutil.rmtree(d / '.skills')
        _skills(d, {'node': 'r29', 'miner': 'r29'})
        k2 = ti.skill_kpis(d, 'r30', [], g)
        k3 = ti.skill_kpis(d, 'r30', [], g2)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    ok = (g == 'r29' and g2 is None and k1['skill_fresh'] == 0 and k1['skill_due'] == ['node']
          and k2['skill_fresh'] == 1 and k3['skill_fresh'] == 0)
    return ok, f"grace {g}/{g2}; r29+r23c fresh {k1['skill_fresh']} due {k1['skill_due']}; r29+r29 {k2['skill_fresh']}; merged {k3['skill_fresh']}"


def kat_tr12(over):
    ai = load(over, 'ai')
    t = {'verdict': 'fix', 'round': 'r30', 'how': 'classifier (B230)'}
    old = {'proposals': [{'id': 'AP-a', 'first_seen': 'r29', 'runs_seen': 3}],
           'triage': {'AP-a': t, 'AP-gone': {'verdict': 'bookkeeping', 'round': 'r30', 'how': 'registered'}}}
    props = [{'id': 'AP-a'}, {'id': 'AP-new'}]
    tri = ai.carry_proposals(props, old, 'r30')
    bad_doc = {'triage': {'AP-x': {'verdict': 'later', 'round': 'r30', 'how': 'h'}, 'AP-y': {'verdict': 'fix'}}}
    probs = ai.triage_problems(bad_doc)
    ok = (props[0].get('triage') == t and props[0]['first_seen'] == 'r29' and props[0]['runs_seen'] == 4
          and 'triage' not in props[1] and 'AP-gone' in tri and len(probs) == 2 and not ai.triage_problems({'triage': tri}))
    return ok, f'carried {props}; map {sorted(tri)}; problems {probs}'


KATS = [('TR1', kat_tr1), ('TR2', kat_tr2), ('TR3', kat_tr3), ('TR4', kat_tr4), ('TR5', kat_tr5), ('TR6', kat_tr6),
        ('TR7', kat_tr7), ('TR8', kat_tr8), ('TR9', kat_tr9), ('TR10', kat_tr10), ('TR11', kat_tr11), ('TR12', kat_tr12)]
OWNERS = {f'r30 TR{i}': [f'TR{i}'] for i in range(1, 13)}
OWNERS['r30 TR10'] = ['TR10', 'TR1']           # is_open reads body_rank: a body_rank mutant fails TR1 too

MUTATIONS = [   # (key, find, replace, why)
    ('ai', "    if not _BT:\n        _BT.append(_backlog_truth())\n    bt = _BT[0]\n    if bt.lead_class(status) == 'closed':\n        return False\n    return bt.body_rank(status)[0] != bt.RANK['closed']",
     "    return not re.match(r'^(CLOSED|REFUTED|DONE)\\b', status.strip(), re.I)", 'r30 TR1: B230 the 3-word is_open regex'),
    ('ai', "        m = re.match(r'^\\|\\s*(BD?\\d+)\\s*\\|(.*)\\|\\s*$', l)", "        m = re.match(r'^\\|\\s*(B\\d+)\\s*\\|(.*)\\|\\s*$', l)",
     'r30 TR1: B230 BD rows invisible'),
    ('ai', "        if text[max(0, mt.start(1) - 1):mt.start(1)] == '~' or text[max(0, mt.start(1) - 6):mt.start(1)].endswith('$HOME'):",
     "        if False:", 'r30 TR2: B230 a home path is read as a broken tree anchor'),
    ('ai', "    rid = capture_round(f\"# version {run.get('version')}\\n\", round_order(reg)) or UNKNOWN_ROUND",
     "    rid = reg.get('current') or UNKNOWN_ROUND", 'r30 TR3: B231 a miner run is booked to registry.current'),
    ('ai', "    if round_tracks(root).get(rid, {}).get('miner') == 'paused':", "    if False:",
     'r30 TR3: B231 a paused-round reward-only run is graded'),
    ('ai', "        if not any(o.get('status') == 'END' for _, o in ev):\n            continue\n", "",
     'r30 TR4: B231 the record in progress (no END) is read'),
    ('ai', "    gap = sum(1 for r in order[lastr + 1:order.index(cur) + 1] if r not in set(paused_rounds)) if cur in order else 0",
     "    gap = order.index(cur) - lastr if cur in order else 0", 'r30 TR5: B231 paused rounds count toward staleness'),
    ('ai', "                    unit = f\" {m['unit']}\" if m.get('unit') else ''", "                    unit = ''",
     'r30 TR6: B231 the prom_ratio display drops its unit'),
    ('ai', "    want = s.get('check', 'S3')", "    want = 'S2'", 'r30 TR7: B231 disclosure_live reads S2 instead of S3'),
    ('ai', "    return pts[-1].get('why') if pts and is_pending(pts[-1].get('value')) else None", "    return None",
     'r30 TR8: B231 the card drops the event-gate why'),
    ('ti', "    (['artifacts/src/gen_ledger.py'], LEDGER_PAGE),\n", "", 'r30 TR9: B232 the ledger generator leaves GENERATORS'),
    ('ti', "    n = int(m.group(1)) if m and (root / f'artifacts/dero-r1-r{m.group(1)}.html').exists() else (pages[-1][0] if pages else None)",
     "    n = int(m.group(1)) if m else None", 'r30 TR9: B232 the ledger page of a round not yet written is double-run'),
    ('bt', "BOLD_RX = re.compile(r'\\*\\*\\s*(?:[rR]\\d+\\w*\\s*:?(?:\\s+(?!(?:not|no|never|un\\w*)\\b)[A-Za-z][\\w-]*){0,4}?\\s*:?\\s*)?'",
     "BOLD_RX = re.compile(r'\\*\\*\\s*'", 'r30 TR10: B233 the round-prefix group dropped'),
    ('bt', "(?:\\s+(?!(?:not|no|never|un\\w*)\\b)[A-Za-z][\\w-]*){0,4}?", "",
     'r30 TR10: verify D6 a multi-word round prefix (**r29 merge: FIXED**) is not read'),
    ('bt', "(?:[rR]\\d+\\w*\\s*:?", "(?:r\\d+\\w*\\s*:?", 'r30 TR10: verify D6 an upper-case prefix (**R29: FIXED**) is not read'),
    ('bt', "(?:\\s+(?!(?:not|no|never|un\\w*)\\b)[A-Za-z]", "(?:\\s+[A-Za-z]",
     'r30 TR10: verify D6 a negated status (**r29: not FIXED**) is read as closed'),
    ('bt', "                     r'(CONFIRMED|CLOSED|FIXED|REFUTED|DONE)\\b')", "                     r'(CONFIRMED|CLOSED|FIXED|REFUTED)\\b')",
     'r30 TR10: verify D6 a bold DONE is not read'),
    ('bt', "CODE_SPAN_RX = re.compile(r'(?<!`)(`+)(?!`)(?:.*?[^`])??\\1(?!`)')", "CODE_SPAN_RX = re.compile(r'`[^`\\n]*`')",
     'r30 TR10: verify D6 a double-backtick code span is not one span (the pre-fix pattern)'),
    ('bt', "'REPORT-ONLY', 'REJECTED')", "'REPORT-ONLY')", 'r30 TR10: verify D6 REJECTED is not a closed word'),
    ('bt', "    cell = CODE_SPAN_RX.sub(lambda m: ' ' * len(m.group(0)), str(cell or ''))", "    cell = str(cell or '')",
     'r30 TR10: B233 a status quoted in a code span is read'),
    ('ti', "        if last and grace and last.lower() == str(grace).lower() and last.lower() != str(current).lower():",
     "        if False:", 'r30 TR11: B204 no round-open grace (a previous-round skill is stale at round open)'),
    ('ti', "        if last and grace and last.lower() == str(grace).lower() and last.lower() != str(current).lower():",
     "        if last and grace and last.lower() != str(current).lower():", 'r30 TR11: B204 any older skill is graced (a resumed skill does not raise)'),
    ('ti', "    if r.get('status') not in ('in-progress', 'planned') or str(r.get('merge_commit') or 'pending') != 'pending':",
     "    if r.get('status') not in ('in-progress', 'planned'):", 'r30 TR11: B204 the grace outlives the merge'),
    ('ai', "        if p['id'] in triage:                       # a triaged proposal shows its verdict\n            p['triage'] = triage[p['id']]\n",
     "", 'r30 TR12: triage verdicts are not shown on the carried proposals'),
    ('ai', "        if not isinstance(t, dict) or t.get('verdict') not in TRIAGE_VERDICTS:",
     "        if not isinstance(t, dict):", 'r30 TR12: any triage verdict word is accepted'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_r30tr', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run_kats(over):
    out = []
    for name, fn in KATS:
        try:
            ok, det = fn(over)
        except Exception as e:                                    # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        out.append((name, ok, det))
    return out


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    K = katmut()
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    fails = sum(1 for _, ok, _ in res if not ok)
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        src = P({}, key)
        text = src.read_text()
        if text.count(find) != 1:
            print(f'  INVALID  {why} — find text occurs {text.count(find)} time(s)')
            missed += 1
            continue
        d = Path(tempfile.mkdtemp(prefix='tr30-mut-'))
        mp = d / src.name
        mp.write_text(text.replace(find, repl, 1))
        try:
            failed = [n for n, ok, _ in run_kats({key: mp}) if not ok]
        finally:
            shutil.rmtree(d, ignore_errors=True)
        verdict, extra = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:9s} {why}  {failed}')
        missed += verdict != 'proved'
        coupled += bool(extra) and verdict == 'proved'
    print('\n' + K.summary('r30 tooling KATs', len(KATS) - fails if fails else len(KATS), len(MUTATIONS), missed, coupled))
    return 3 if fails else (4 if missed or coupled else 0)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
