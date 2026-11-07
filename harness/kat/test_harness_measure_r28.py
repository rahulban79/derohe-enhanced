#!/usr/bin/env python3
"""KAT + mutation proofs for the R28 harness-measure group (rft §0.9, §6 S7 / steps 3a, 15, 20; §7 B20 B53 B133 B135
B148 B149, N28-02, N28-03). No network, no live file written: every registry, record and output is a temp file or a
read of the tracked tree.

  HS1  B149  harness/kit/roundlists.py: the tree's four round lists carry the open round (0 missing); a forged root
             without r28 in areas.json rounds, without 28 in gen_ledger LAST_CHOICES, without the planned R29 in
             mine_evolution ORDER is reported once per list; the pre-fix R27-measurement shape (registry current r27,
             areas.json rounds ending at r26) is reported as 'areas: r27 missing' (B149's own failure).
  HS2  N28-03 area_intel.staleness / stale_exempt: a metric of a paused track and a single-round record do not count
             toward stale-evidence (getworkops at r28: no finding); the same metrics with the track active are stale;
             an area with only AUTO metrics is no-metrics; harness/areas.json tags the three getwork flip metrics
             track 'miner' and r24_mutations single_round 'r24'.
  HS3  r28   tooling.checkpoint_age (a 10-min loop's sawtooth): 120 s (r27) -> 259 s (r28) is no regression and no
             alert; 1,300 s trips the alert (> 1200 s, the metric's own target).
  HS4  N28-02 area_intel.pin_round pins only unpinned fields; the registry pins every round before the current one
             (unpinned_rounds(r28) == []: before r28 r25, r26 and r27 were unpinned); r27 harness.kats is 26/26 with
             its dated correction (was 25/25); record() calls pin_round.
  HS5  B133  harness/kit/stepbudget.py: norm() folds run ids; step_secs() prefers the event's own secs, falls back to
             the gap, skips skipped steps; over() / wall_over(); the tree's STEP_BUDGETS.json flags the r26 record
             pipeline_20261105T090420 (frontend2 KAT 858 s, wall 1,904 s) and passes the r27 record
             pipeline_20261105T193623; fix_build_verify writes secs per S7 step and budget_report() into the project
             event (pending, never a crash, without the budget file).
  HS6  B135  live_window.scrub_prom masks every non-reserved IPv4 (loopback kept); poll() writes the masked text (a
             planted peer label never reaches the scrape file); metric_map of the masked text equals the raw one.
  HS7  B53   harness/pipeline/regen_round.py: the miner order equals the pipeline's S7 order; prep_corpus first,
             coverage after every miner, build after coverage, gen_index after build, coherence last; no step reads
             the live node (--capture/--live); the dry run runs nothing; apply() stops at the first failing step
             (exit 3) and returns 4 when coherence still drifts.
  HS8  r28   live_window.event_lines: every PENDING_EVENTS id gets one line; zero deltas say 'no event in S s / N
             blocks (node uptime U s, k samples)'; a counter that rose says 'EVENT +n'; an absent counter is
             'pending (absent)'; B61 counts samples with topoheight != height; summarise() appends the lines.
  HS9  B135  harness/intel/privacy_audit.py classify(): the newest fresh file of a runtime family that leaks is a
             writer, an older one or a stale family historical, harness/kat/* fixture, anything else static; --dir
             exits 5 on a planted capture and 0 on a clean one, and never prints the address.
  HS10 B133  run_gates.TimedResults: wall seconds per gate (fake clock), summed per gate id; write_timing writes
             only with DERO_GATE_TIMING and returns the slowest first.
  HS11 B148  resource_intel.level: mds_stores 50,360 MB (2026-11-06 00:39) is a REDUCE reason naming the user's
             decision; 8,380 MB is not.
  HS12 B149  tooling_intel: r28_kpis on a forged root reports round_lists_missing, and targets() turns a missing
             round list and a writer leak into violations (an empty list and 0 leaks into none).

  python3 -I harness/kat/test_harness_measure_r28.py   # KATs, then each mutation (on a temp copy) must fail its KAT
Mutation independence (harness/kit/katmut.py): each mutation's reason starts with its defect id; OWNERS maps it to
the KAT(s) that own it. Exit 0 all ok · 3 a KAT failed · 4 a mutation was not proved (MISSED / WRONG-KAT / INVALID)
or was coupled (target 0).
"""
import contextlib, datetime, importlib.util, io, json, os, re, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
PATHS = {'rl': 'harness/kit/roundlists.py', 'ai': 'harness/intel/area_intel.py', 'areas': 'harness/areas.json',
         'sb': 'harness/kit/stepbudget.py', 'budgets': 'harness/loop/STEP_BUDGETS.json',
         'fbv': 'harness/pipeline/fix_build_verify.py', 'lw': 'harness/intel/live_window.py',
         'rg': 'harness/pipeline/regen_round.py', 'pa': 'harness/intel/privacy_audit.py', 'gates': 'harness/run_gates.py',
         'ri': 'harness/intel/resource_intel.py', 'ti': 'harness/intel/tooling_intel.py'}
R26_RECORD = 'harness/loop/runs/pipeline_20261105T090420.jsonl'
R27_RECORD = 'harness/loop/runs/pipeline_20261105T193623.jsonl'
LAN = '10.20.30.40'                       # a planted private-LAN address (not reserved: privkit treats it as a host)
PEER = '172.31.200.7'                     # a planted RFC 1918 peer address (verifier r28: no routable address in a tracked file)


def P(over, key):
    return Path(over.get(key) or (ROOT / PATHS[key]))


def load(over, key):
    """the module at PATHS[key] (or the mutant in `over`), imported under a fresh name; kit/ and intel/ of the real
    tree resolve the module's own sibling imports (privkit, roundtracks, gen_deroarch for run_gates)."""
    path = P(over, key)
    extra = [str(path.parent), str(HARNESS / 'kit'), str(HARNESS)]
    for m in ('privkit', 'roundtracks', 'gen_deroarch', 'prep_corpus', 'assetkit', 'connectorkit', 'textkit', 'diagramkit'):
        sys.modules.pop(m, None)
    sys.path[:0] = extra
    try:
        spec = importlib.util.spec_from_file_location(f'hs28_{key}_{abs(hash(str(path)))}_{len(sys.modules)}', path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    finally:
        del sys.path[:len(extra)]
    return m


def forged_lists(over, drop_area=None, drop_ledger=None, drop_order=None, current=None, areas_upto=None):
    """a temp root holding the four round-list files of the tree (or mutants), optionally edited."""
    d = Path(tempfile.mkdtemp(prefix='hs28-rl-'))
    for rel in ('harness/round.json', 'harness/areas.json', 'artifacts/src/gen_ledger.py', 'harness/miners/mine_evolution.py'):
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        src = P(over, 'areas') if rel == 'harness/areas.json' else ROOT / rel
        shutil.copy2(src, d / rel)
    reg = json.loads((d / 'harness/round.json').read_text())
    if current:
        reg['current'] = current
        reg['rounds'] = [r for r in reg['rounds'] if r['id'] <= current]
        for r in reg['rounds']:
            if r['id'] == current:
                r['status'] = 'in-progress'
        (d / 'harness/round.json').write_text(json.dumps(reg))
    ar = json.loads((d / 'harness/areas.json').read_text())
    if drop_area:
        ar['rounds'] = [r for r in ar['rounds'] if r['id'] != drop_area]
    if areas_upto:
        ids = [r['id'] for r in ar['rounds']]
        ar['rounds'] = ar['rounds'][:ids.index(areas_upto) + 1]
    (d / 'harness/areas.json').write_text(json.dumps(ar))
    if drop_ledger:
        f = d / 'artifacts/src/gen_ledger.py'
        f.write_text(f.read_text().replace(f', {drop_ledger})', ')', 1))
    if drop_order:
        f = d / 'harness/miners/mine_evolution.py'
        f.write_text(f.read_text().replace(f", '{drop_order}']", ']', 1))
    return d


def kat_hs1(over):
    RL = load(over, 'rl')
    bad = []
    real = RL.check(ROOT if 'areas' not in over else forged_lists(over))
    if real:
        bad.append(f'the tree misses {real}')
    cases = [(dict(drop_area='r28'), 'areas: r28 missing'), (dict(drop_ledger=28), 'ledger: 28 missing'),
             (dict(drop_order='R29'), 'evolution: next planned R29 missing'),
             (dict(current='r27', areas_upto='r26'), 'areas: r27 missing')]
    for kw, want in cases:
        d = forged_lists(over, **kw)
        try:
            got = RL.check(d)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        if not any(g.startswith(want) for g in got):
            bad.append(f'{kw}: want {want!r}, got {got}')
    return not bad, '; '.join(bad) or f'0 missing on the tree; {len(cases)} forged gaps each reported'


def kat_hs2(over):
    AI = load(over, 'ai')
    bad = []
    order = ['r23c', 'r24', 'r25', 'r26', 'r27', 'r28']
    mdefs = [{'id': 'flip', 'track': 'miner'}, {'id': 'r24m', 'single_round': 'r24'}]
    cards = [{'id': 'flip', 'last': {'round': 'r23c'}}, {'id': 'r24m', 'last': {'round': 'r24'}},
             {'id': 'kats', 'last': {'round': 'r28'}}]
    ns, f = AI.staleness(cards, mdefs, {'miner': 'paused'}, order, 'r28', 2)
    if f is not None or set(ns) != {'flip', 'r24m'}:
        bad.append(f'paused track: finding {f}, not_stale {sorted(ns)}')
    ns, f = AI.staleness(cards[:1] + cards[2:], [{'id': 'flip', 'track': 'miner'}], {'miner': 'active'}, order, 'r28', 2)
    if not f or f[0] != 'stale-evidence' or 'since r23c' not in f[2] or ns:
        bad.append(f'active track: want stale-evidence since r23c and no exemption, got {f} {ns}')
    ns, f = AI.staleness([{'id': 'kats', 'last': {'round': 'r28'}}], [], {}, order, 'r28', 2)
    if not f or f[0] != 'no-metrics':
        bad.append(f'AUTO only: want no-metrics, got {f}')
    reg = json.loads(P(over, 'areas').read_text())
    gw = {m['id']: m for a in reg['areas'] if a['id'] == 'getworkops' for m in a['metrics']}
    for mid in ('flip_delay_cond_ms', 'dead_jobs_per_flip', 'flip_l9_ms'):
        if gw.get(mid, {}).get('track') != 'miner':
            bad.append(f'getworkops.{mid} not track miner')
    if gw.get('r24_mutations', {}).get('single_round') != 'r24':
        bad.append('getworkops.r24_mutations not single_round r24')
    ns, f = AI.staleness([{'id': k, 'last': ({'round': 'r23c'} if k != 'flip_l9_ms' else {'round': 'r24'})} for k in gw],
                         list(gw.values()), {'miner': 'paused'}, order, 'r28', 2)
    if f is not None:
        bad.append(f'getworkops with the registry metrics still {f}')
    return not bad, '; '.join(bad) or 'paused-track / single-round metrics exempt; active track stale; getworkops tagged'


def kat_hs3(over):
    AI = load(over, 'ai')
    reg = json.loads(P(over, 'areas').read_text())
    m = next(m for a in reg['areas'] if a['id'] == 'tooling' for m in a['metrics'] if m['id'] == 'checkpoint_age')
    bad = []
    _, regress = AI.trend(120, 259, m.get('better', 'none'), float(m.get('noise_rel', 0.05)))
    if regress:
        bad.append('120 -> 259 s is booked as a regression')
    if AI.alert(m.get('alert_if'), 259):
        bad.append('259 s trips the alert')
    if not AI.alert(m.get('alert_if'), 1300):
        bad.append('1,300 s does not trip the alert')
    return not bad, '; '.join(bad) or 'sawtooth not a regression; > 1200 s alerts'


def kat_hs4(over):
    AI = load(over, 'ai')
    bad = []
    reg = {'rounds': [{'id': 'r9', 'pipeline_full': 'pending', 'pipeline_project': 'p_old'}]}
    made = AI.pin_round(reg, 'r9', {'full': 'f1', 'project': 'p_new'})
    if reg['rounds'][0] != {'id': 'r9', 'pipeline_full': 'f1', 'pipeline_project': 'p_old'} or made != 'pipeline_full=f1':
        bad.append(f'pin_round {reg["rounds"][0]} made {made!r}')
    if AI.pin_round(reg, 'r9', {'full': 'f2', 'project': 'p2'}) != '':
        bad.append('a pinned round was re-pinned')
    areas = json.loads(P(over, 'areas').read_text())
    un = []                     # an unpinned field is allowed only where no record of the round exists (r22: none)
    for rid in AI.unpinned_rounds(areas, 'r28'):
        ent = next(r for r in areas['rounds'] if r['id'] == rid)
        found = AI.discover_round_records(ROOT, {'rounds': [{'id': rid}]}, rid)
        un += [f'{rid}.{k}={found[s]}' for k, s in (('pipeline_full', 'full'), ('pipeline_project', 'project'))
               if (not ent.get(k) or AI.is_pending(ent.get(k))) and found.get(s)]
    if un:
        bad.append(f'unpinned rounds before r28 with a record: {un}')
    h = next(a for a in areas['areas'] if a['id'] == 'harness')['history'].get('r27', {}).get('kats', {})
    if h.get('value') != '26/26' or not any(c.get('was') == '25/25' and c.get('date') for c in h.get('corrections', [])):
        bad.append(f"harness.kats@r27 {h.get('value')!r} without its dated 25/25 correction")
    src = P(over, 'ai').read_text()
    body = src[src.index('def record(root, rid):'):src.index('# ───────────────────────────── r25 (B52): dated corrections')]
    if 'pin_round(reg, rid, discover_round_records(root, reg, rid))' not in body:
        bad.append('record() does not pin the round')
    return not bad, '; '.join(bad) or 'pins only unpinned fields; r25-r27 pinned; r27 kats corrected; record pins'


def kat_hs5(over):
    SB = load(over, 'sb')
    bad = []
    if SB.norm('harness/run_gates.py pipeline-20261105T193623') != 'harness/run_gates.py pipeline-<TS>':
        bad.append('norm keeps the run id')
    ev = [{'t': '2026-11-06T00:00:00-08:00', 'stage': 'project', 'status': 'START'},
          {'t': '2026-11-06T00:00:10-08:00', 'stage': 'project', 'status': 'INFO', 'step': 'a.py'},
          {'t': '2026-11-06T00:01:10-08:00', 'stage': 'project', 'status': 'INFO', 'step': 'b.py', 'secs': 5.0},
          {'t': '2026-11-06T00:01:11-08:00', 'stage': 'project', 'status': 'INFO', 'step': 'm.py', 'skipped': 'paused'},
          {'t': '2026-11-06T00:03:11-08:00', 'stage': 'project', 'status': 'INFO', 'step': 'c.py'}]
    st = SB.step_secs(ev)
    if st != [('a.py', 10.0), ('b.py', 5.0), ('c.py', 120.0)]:
        bad.append(f'step_secs {st}')
    doc = {'default_s': 60, 'project_wall_s': 100, 'steps': {'c.py': 200}}
    if SB.over(st, doc) != [] or SB.over([('d.py', 61.0)], doc) != [('d.py', 61.0, 60.0)]:
        bad.append(f'over {SB.over(st, doc)} / {SB.over([("d.py", 61.0)], doc)}')
    if SB.wall_over(st, doc) != (135.0, 100.0, True):
        bad.append(f'wall_over {SB.wall_over(st, doc)}')
    budgets = json.loads(P(over, 'budgets').read_text())
    r26 = SB.report([json.loads(l) for l in (ROOT / R26_RECORD).read_text().splitlines() if l.strip()], budgets)
    r27 = SB.report([json.loads(l) for l in (ROOT / R27_RECORD).read_text().splitlines() if l.strip()], budgets)
    if not (r26['wall_over'] and any('test_forensics_frontend2_r26.py' in x for x in r26['over'])):
        bad.append(f'the r26 regression record is not flagged {r26}')
    if r27['over'] or r27['wall_over']:
        bad.append(f'the r27 record is flagged {r27["over"]}')
    fsrc = P(over, 'fbv').read_text()
    for need in ("event('project', 'INFO', step=' '.join(st[1:3]), rc=rc, last=last, secs=secs)",
                 'failing=failing, over_budget=budget_report(_ev))'):
        if need not in fsrc:
            bad.append(f'fix_build_verify lacks {need[:60]!r}')
    m = re.search(r'\ndef budget_report\(.*?\n(?=\n\n)', fsrc, re.S)
    if m:
        ns = {'importlib': importlib, 'HARNESS': P(over, 'sb').parent.parent, 'ROOT': Path(tempfile.mkdtemp(prefix='hs28-nob-')),
              'OSError': OSError, 'ValueError': ValueError}
        exec(compile(re.search(r'\ndef _stepbudget\(.*?\n(?=\n\n)', fsrc, re.S).group(0) + m.group(0), 'fbv', 'exec'), ns)
        got = ns['budget_report'](ev)
        if not (isinstance(got, str) and got.startswith('pending')):
            bad.append(f'budget_report without a budget file: {got!r}')
    else:
        bad.append('fix_build_verify has no budget_report')
    return not bad, '; '.join(bad) or 'secs preferred; budgets flag r26 (858 s), pass r27; pipeline writes secs + over_budget'


def kat_hs6(over):
    LW = load(over, 'lw')
    bad = []
    raw = (f'p2p_first_relay_total{{peer="{PEER}"}} 3\np2p_first_relay_total{{peer="{LAN}"}} 2\n'
           'rpc_requests_total{addr="127.0.0.1"} 5\nblockchain_block_rejected_total{reason="other"} 0\n')
    s = LW.scrub_prom(raw)
    if PEER in s or LAN in s or '127.0.0.1' not in s:
        bad.append(f'scrub_prom kept a peer or lost loopback: {s!r}')
    if LW.metric_map(raw) != LW.metric_map(s):
        bad.append('the summary of the masked scrape differs')
    d = Path(tempfile.mkdtemp(prefix='hs28-lw-'))
    out = str(d / 's.jsonl')
    clock = iter([0, 0, 0, 0, 0, 100, 100, 100])
    try:
        LW.poll(out, 50, lambda m, p=None: {'uptime_seconds': 1}, metrics=lambda: raw, step=60, metrics_every=1,
                clock=lambda: next(clock, 100), sleep=lambda s: None)
        scr = (d / 's_metrics_000.prom').read_text()
        if PEER in scr or LAN in scr:
            bad.append('poll wrote a peer address into the scrape')
    except StopIteration:
        bad.append('poll clock ran out')
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return not bad, '; '.join(bad) or 'scrapes masked before they are written; summary unchanged'


def kat_hs7(over):
    RG = load(over, 'rg')
    bad = []
    fsrc = P(over, 'fbv').read_text()
    m = re.search(r"for m in\s*\n?\s*\(([^)]*)\)\]", fsrc)
    s7 = tuple(x.strip(" '\n") for x in m.group(1).split(',')) if m else ()
    if tuple(RG.MINERS) != s7:
        bad.append(f'miner order {RG.MINERS} != S7 {s7}')
    steps = [' '.join(s) for s in RG.STEPS]
    idx = lambda pfx: next((i for i, s in enumerate(steps) if s.startswith(pfx)), None)
    miners = [i for i, s in enumerate(steps) if s.startswith('harness/miners/mine_') and 'coverage' not in s]
    cov, build, gi, coh = (idx('harness/miners/mine_coverage'), idx('harness/gen_deroarch.py build'),
                           idx('harness/gen_index.py'), idx('harness/intel/coherence.py'))
    if idx('harness/prep_corpus.py') != 0:
        bad.append('prep_corpus is not first')
    if None in (cov, build, gi, coh) or not (max(miners) < cov < build < gi < coh == len(steps) - 1):
        bad.append(f'order prep/miners/coverage/build/index/coherence broken: {steps}')
    if '--strict' not in steps[build or 0]:
        bad.append('build is not --strict')
    if any(f in s for s in steps for f in ('--capture', '--live')):
        bad.append('a step reads the live node')
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = RG.main([])
    if rc != 0 or 'dry run' not in buf.getvalue():
        bad.append(f'dry run rc {rc}')
    seq = []
    rc3, done3 = RG.apply(Path('.'), run=lambda a, c: (seq.append(a), 1 if 'mine_flows' in a[0] else 0)[1], log=lambda *x: None)
    if rc3 != 3 or not done3 or 'mine_flows' not in done3[-1][0]:
        bad.append(f'apply did not stop at the failing step (rc {rc3}, last {done3[-1:] if done3 else None})')
    rc4, _ = RG.apply(Path('.'), run=lambda a, c: 4 if 'coherence' in a[0] else 0, log=lambda *x: None)
    if rc4 != 4:
        bad.append(f'coherence drift returns {rc4} (want 4)')
    return not bad, '; '.join(bad) or f'{len(steps)} steps in S7 order; stops on failure; drift = 4'


def rows_fixture(topo_off=0, inc=0):
    rows = []
    for i in range(4):
        h = 7863000 + i * 3
        rows.append({'t': f'T{i}', 'epoch': 1000.0 + 60 * i,
                     'cs': {'uptime_seconds': 500 + 60 * i, 'version': 'v'},
                     'sync': {'height': h, 'topoheight': h + (topo_off if i == 2 else 0), 'status': 'synced',
                              'lag_blocks': 0, 'tip_age_seconds': 5.0, 'peers_outgoing': 14, 'peers_incoming': inc},
                     'info': {}})
    return rows


PROM0 = ('p2p_sync_peer_holds_total 0\np2p_inbound_proven_lane_admits_total 0\np2p_inbound_proven_lane_refusals_total 0\n'
         'p2p_inbound_proven_quota_evictions_total 0\nblockchain_block_rejected_total{reason="other"} 0\n'
         'blockchain_block_rejected_total{reason="panic"} 0\nrpc_error_responses_total{code="-32031"} 0\n'
         'p2p_sync_relay_forgiven_total 0\np2p_sync_served_forgiven_total 0\np2p_sync_strike_decays_total 0\n'
         'p2p_sync_held_fallbacks_total 0\n')


def kat_hs8(over):
    LW = load(over, 'lw')
    bad = []
    L = LW.event_lines(rows_fixture(), [PROM0, PROM0])
    ids = [l.split()[1] for l in L]
    if ids != [e[0] for e in LW.PENDING_EVENTS] or set(ids) != {'B47', 'B48', 'B57', 'B61', 'B85', 'B99'}:
        bad.append(f'event ids {ids}')
    if not all('no event in 180 s / 9 blocks (node uptime 680 s, 4 samples)' in l for l in L):
        bad.append(f'zero-delta lines: {L[:2]}')
    p1 = PROM0.replace('blockchain_block_rejected_total{reason="panic"} 0', 'blockchain_block_rejected_total{reason="panic"} 2')
    L2 = dict((l.split()[1], l) for l in LW.event_lines(rows_fixture(topo_off=1, inc=1), [PROM0, p1]))
    if 'EVENT +2' not in L2.get('B57', ''):
        bad.append(f"B57 rise: {L2.get('B57')}")
    if 'EVENT +1' not in L2.get('B61', '') or 'topoheight != height 1/4' not in L2.get('B61', ''):
        bad.append(f"B61: {L2.get('B61')}")
    if 'EVENT' not in L2.get('B48', ''):
        bad.append(f"B48 inbound: {L2.get('B48')}")
    L3 = dict((l.split()[1], l) for l in LW.event_lines(rows_fixture(), ['x 1\n', 'x 1\n']))
    if 'pending (absent)' not in L3.get('B47', ''):
        bad.append(f"absent counter: {L3.get('B47')}")
    S = LW.summarise(rows_fixture(), [PROM0, PROM0]) or []
    if not any(l.startswith('pending-event B99') for l in S):
        bad.append('summarise does not carry the event lines')
    return not bad, '; '.join(bad) or '6 events with denominators; rises and absences stated'


def kat_hs9(over):
    PA = load(over, 'pa')
    bad = []
    now = datetime.datetime(2026, 11, 6, 1, 0, 0)
    files = {'harness/runtime/logintel_20261103T092514.json': 9, 'harness/runtime/logintel_20261105T232944.json': 0,
             'harness/runtime/triage_20261105T235242.json': 2, 'harness/runtime/triage_20261101T140710.json': 4,
             'harness/runtime/derod_console_20261021.log': 3, 'harness/kat/test_x.py': 1, 'ARCHITECTURE.md': 5}
    c = PA.classify(files, now, 72)
    want = {'harness/runtime/logintel_20261103T092514.json': 'historical', 'harness/runtime/triage_20261105T235242.json': 'writer',
            'harness/runtime/triage_20261101T140710.json': 'historical', 'harness/runtime/derod_console_20261021.log': 'historical',
            'harness/kat/test_x.py': 'fixture', 'ARCHITECTURE.md': 'static'}
    got = {k: v[0] for k, v in c.items()}
    if got != want:
        bad.append(f'classify {got}')
    d = Path(tempfile.mkdtemp(prefix='hs28-pa-'))
    try:
        (d / 'a.prom').write_text(f'p2p_first_relay_total{{peer="{PEER}"}} 1\n')
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = PA.main(['--dir', str(d)])
        if rc != 5 or PEER in buf.getvalue():
            bad.append(f'--dir planted rc {rc} (printed the address: {PEER in buf.getvalue()})')
        (d / 'a.prom').write_text('p2p_first_relay_total{peer="<peer>"} 1\nx{addr="127.0.0.1"} 1\n')
        with contextlib.redirect_stdout(io.StringIO()):
            rc = PA.main(['--dir', str(d)])
        if rc != 0:
            bad.append(f'--dir clean rc {rc}')
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return not bad, '; '.join(bad) or 'writer / historical / fixture / static; --dir 5 planted, 0 clean, no address printed'


def kat_hs10(over):
    G = load(over, 'gates')
    bad = []
    t = iter([0.0, 2.0, 2.5, 10.0])
    r = G.TimedResults(clock=lambda: next(t))
    r.append(('G1 a', True, ''))
    r.append(('G2 b', True, ''))
    r.append(('G1 again', True, ''))
    if r.timing() != {'G1': 9.5, 'G2': 0.5} or len(r) != 3:
        bad.append(f'timing {r.timing()}')
    d = Path(tempfile.mkdtemp(prefix='hs28-gt-'))
    try:
        if G.write_timing(r, env={}) != [] or list(d.iterdir()):
            bad.append('timing written without DERO_GATE_TIMING')
        out = G.write_timing(r, env={'DERO_GATE_TIMING': str(d / 't.json')})
        if out[:1] != ['G1 9.5s'] or json.loads((d / 't.json').read_text()) != {'G1': 9.5, 'G2': 0.5}:
            bad.append(f'write_timing {out}')
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return not bad, '; '.join(bad) or 'per-gate seconds; opt-in file'


def kat_hs11(over):
    RI = load(over, 'ri')
    base = {'swap': {'total_mb': 6144.0, 'used_mb': 4502.0, 'free_mb': 1642.0}, 'memory_free_pct': 93,
            'procs': {'watch': {'fseventsd': 42.0, 'mds_stores': 50359.6}}, 'scratchpad': {'clone_trees': 10}}
    lv, why = RI.level(base)
    bad = []
    if lv != 'REDUCE' or not any('mds_stores' in w and "user's decision" in w for w in why):
        bad.append(f'50,360 MB: {lv} {why}')
    base['procs']['watch']['mds_stores'] = 8380.0
    lv, why = RI.level(base)
    if lv != 'OK' or any('mds_stores' in w for w in why):
        bad.append(f'8,380 MB: {lv} {why}')
    return not bad, '; '.join(bad) or 'mds_stores >= 16 GiB is REDUCE (report-only)'


def kat_hs12(over):
    TI = load(over, 'ti')
    bad = []
    d = forged_lists(over, drop_area='r28')
    try:
        (d / 'harness/kit').mkdir(parents=True, exist_ok=True)
        shutil.copy2(P(over, 'rl'), d / 'harness/kit/roundlists.py')
        k = TI.r28_kpis(d)
        if not any('r28' in x for x in (k.get('round_lists_missing') or [])):
            bad.append(f"forged root: round_lists_missing {k.get('round_lists_missing')}")
    finally:
        shutil.rmtree(d, ignore_errors=True)
    v = TI.targets({'round_lists_missing': ['areas: r28 missing'], 'privacy_writer_leaks': 1})
    if not any('B149' in x for x in v) or not any('B135' in x for x in v):
        bad.append(f'targets {v}')
    if TI.targets({'round_lists_missing': [], 'privacy_writer_leaks': 0}):
        bad.append('a clean record has violations')
    return not bad, '; '.join(bad) or 'round lists and writer leaks are rule-2 targets'


KATS = [('HS1', kat_hs1), ('HS2', kat_hs2), ('HS3', kat_hs3), ('HS4', kat_hs4), ('HS5', kat_hs5), ('HS6', kat_hs6),
        ('HS7', kat_hs7), ('HS8', kat_hs8), ('HS9', kat_hs9), ('HS10', kat_hs10), ('HS11', kat_hs11), ('HS12', kat_hs12)]

# katmut (harness/kit/katmut.py, rft §0.9 rule 1): the reason starts with the defect id; OWNERS names the owning KATs
OWNERS = {'B149': ['HS1', 'HS12'], 'r28 N28-03': ['HS2'], 'r28 checkpoint': ['HS3'], 'r28 N28-02': ['HS4'], 'B133': ['HS5', 'HS10'],
          'B135': ['HS6', 'HS9', 'HS12'], 'B53': ['HS7'], 'r28 events': ['HS8'], 'B148': ['HS11']}

MUTATIONS = [
    ('rl', "        if rid not in L['areas']:", "        if False:", 'B149: a round missing from areas.json rounds passes'),
    ('rl', "    if n is not None and n not in L['ledger']:", "    if False:", 'B149: the ledger LAST_CHOICES check is gone'),
    ('rl', "    if nxt and evolution_label(nxt[0]) not in L['evolution']:", "    if False:", 'B149: the next planned round is not checked in ORDER'),
    ('rl', "        out = (out + vals) if aug else vals", "        out = vals", 'B149: an ORDER += extension is read as a reassignment'),
    ('ai', "    if t and (tracks or {}).get(t) == 'paused':", "    if t:", 'r28 N28-03: a track metric is exempt while the track is active'),
    ('ai', "    if m.get('single_round'):", "    if False:", 'r28 N28-03: a single-round record still counts as stale'),
    ('ai', "    if not defined and not_stale:\n        return not_stale, None\n", "", 'r28 N28-03: an all-exempt area is no-metrics'),
    ('areas', '"den": "getwork_final_flip_l9_seconds_count",\n      "scale": 1000\n     },\n     "track": "miner"',
     '"den": "getwork_final_flip_l9_seconds_count",\n      "scale": 1000\n     }', 'r28 N28-03: getworkops.flip_l9_ms untagged (stale again)'),
    ('areas', '"better": "none",\n     "noise_rel": 0.0,\n     "source": {\n      "kind": "tooling",\n      "field": "checkpoint_age_s"\n     },\n     "alert_if"',
     '"better": "lower",\n     "noise_rel": 0.0,\n     "source": {\n      "kind": "tooling",\n      "field": "checkpoint_age_s"\n     },\n     "alert_if"',
     'r28 checkpoint: checkpoint_age is lower-is-better again (the 120 -> 259 s high proposal)'),
    ('ai', "        if v and (not ent.get(k) or is_pending(ent.get(k))):", "        if v:", 'r28 N28-02: pin_round overwrites a pinned record'),
    ('ai', "    pinned = pin_round(reg, rid, discover_round_records(root, reg, rid))       # r28 N28-02 (B52 at record time)",
     "    pinned = ''", 'r28 N28-02: record no longer pins the round'),
    ('areas', '"pipeline_project": "pipeline_20261105T193623"', '"pipeline_project": "pending"', 'r28 N28-02: r27 unpinned again'),
    ('sb', "            if isinstance(o.get('secs'), (int, float)):", "            if False:", 'B133: the step\'s own secs are ignored'),
    ('sb', "and o.get('status') == 'INFO' and not o.get('skipped'):", "and o.get('status') == 'INFO':", 'B133: a skipped step is timed'),
    ('sb', "        if n > lim:", "        if n > lim * 10:", 'B133: an overrun is not reported'),
    ('budgets', '"harness/kat/test_forensics_frontend2_r26.py": 350', '"harness/kat/test_forensics_frontend2_r26.py": 900',
     'B133: the frontend2 budget hides the r26 regression'),
    ('fbv', "        event('project', 'INFO', step=' '.join(st[1:3]), rc=rc, last=last, secs=secs)",
     "        event('project', 'INFO', step=' '.join(st[1:3]), rc=rc, last=last)", 'B133: S7 no longer records step secs'),
    ('lw', "                f.write(scrub_prom(metrics()))           # r28 B135: no peer address reaches the raw scrape",
     "                f.write(metrics())", 'B135: the raw scrape keeps peer addresses'),
    ('lw', "    return privkit.mask(text or '')", "    return text or ''", 'B135: scrub_prom masks nothing'),
    ('rg', "          'areas', 'consensus', 'peers')\nSTEPS", "          'consensus', 'areas', 'peers')\nSTEPS", 'B53: the miner order differs from S7'),
    ('rg', "            ['harness/miners/mine_triage.py'],             # on-disk inputs only (no --capture)",
     "            ['harness/miners/mine_triage.py', '--capture'],", 'B53: the regeneration reads the live node'),
    ('rg', "        if rc not in OK_RC.get(s[0], (0,)):", "        if False:", 'B53: a failing step does not stop the regeneration'),
    ('rg', "            ['harness/gen_index.py'],\n            ['harness/kit/soundpage.py', '--check-measured'],",
     "            ['harness/kit/soundpage.py', '--check-measured'],", 'B53: gen_index dropped (index stale after the build)'),
    ('lw', "        elif delta > 0:", "        elif delta > 99:", 'r28 events: a counter that rose is reported as no event'),
    ('lw', "        if not seen:\n            verdict = 'pending (absent)'", "        if False:\n            verdict = 'pending (absent)'",
     'r28 events: an absent counter reads as no event'),
    ('lw', "                ne = sum(1 for h, t in pairs if h != t)", "                ne = 0", 'r28 events: B61 topoheight != height not counted'),
    ('lw', "    L += event_lines(rows, prom)                             # r28: pending events with their denominators\n", "",
     'r28 events: the summary drops the event lines'),
    ('pa', "            out[rel] = ('writer' if newest[f] == rel and fresh else 'historical', n)",
     "            out[rel] = ('historical', n)", 'B135: a current writer leak is called historical'),
    ('pa', "    return 5 if bad else 0\n\n\nif __name__", "    return 0\n\n\nif __name__", 'B135: --dir passes a planted capture'),
    ('pa', "        if str(rel).startswith('harness/kat/'):\n            out[rel] = ('fixture', n)\n        elif f:",
     "        if f:", 'B135: KAT fixtures are not told apart'),
    ('gates', "        self.t0 = now\n        super().append(item)", "        super().append(item)", 'B133: gate timing accumulates from the start'),
    ('gates', "    if not dest or not hasattr(res, 'timing'):", "    if not hasattr(res, 'timing'):", 'B133: gate timing written without the opt-in'),
    ('ri', "    if mds is not None and mds >= REDUCE_MDS_STORES_MB:                       # r28 (B148)",
     "    if False:", 'B148: a 50 GB Spotlight index store is OK'),
    ('ti', "        k['round_lists_missing'] = RL.check(root) if RL else PENDING", "        k['round_lists_missing'] = []",
     'B149: tooling_intel does not read the round lists'),
    ('ti', "    if isinstance(k.get('round_lists_missing'), list) and k['round_lists_missing']:", "    if False:",
     'B149: a missing round list is not a target violation'),
    ('ti', "    if isinstance(k.get('privacy_writer_leaks'), int) and k['privacy_writer_leaks']:", "    if False:",
     'B135: a writer leak is not a target violation'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_hs28', HARNESS / 'kit' / 'katmut.py')
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
        res.append((name, ok, det))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:500]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr28 harness-measure KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        src = ROOT / PATHS[key]
        text = src.read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='hs28-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            try:
                if mut.suffix == '.py':
                    compile(mut.read_text(encoding='utf-8'), str(mut), 'exec')
                else:
                    json.loads(mut.read_text(encoding='utf-8'))
            except (SyntaxError, ValueError) as e:
                print(f'  INVALID   {why}: mutant does not load ({type(e).__name__})')
                missed += 1
                continue
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, extra = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else '')
              + (f'  coupled {extra}' if verdict == 'proved' and extra else ''))
        missed += verdict != 'proved'
        coupled += verdict == 'proved' and bool(extra)
    print('\n' + K.summary('r28 harness-measure KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed or coupled else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
