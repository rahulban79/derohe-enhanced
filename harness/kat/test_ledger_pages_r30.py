#!/usr/bin/env python3
"""KAT + mutation proofs for the R30 ledger/pages + disclosure dimension (rft §7 B219, B220, B221, B223, B224, B225,
B226, B227, B229, B214, B228, B203 (c); §8 "ledger/pages"). No network, no node: forged rows, records and pages in
memory or temp dirs; the committed checks read this tree's records and the closed --last 29 page.

  LP1 B219   ledger_item_map.json maps every "Open after" item of the closed r29 page's #ceilings / #open23c..#open29
             to ids that exist (§7, CLOSED28:<id>, pseudo); now_chips puts exactly one chip per item; an unmapped item
             gets a bad chip; a closed lead gives good (REPORT-ONLY / MITIGATED warn), an open one warn; #closed28
             REPORT-ONLY warn from r30 only.
  LP2 B220   open30: every §7 row whose lead is not closed lands in exactly one group; the 11 miner rows + B39 in the
             miner group; B184 standing with the ESTIMATE 124,352 blocks ≈ 2026-12-05 at tip 7,875,648; a scope row
             (closed lead) is listed; a record closure only when its record holds.
  LP3 B221   latest_pipe skips a pending verdict; ver_rows has one row per measured PIPE; add_stages inserts a missing
             stage into the escaped and the plain flowchart; stage_ids reads S4c from the docstring.
  LP4 B223   pipe_from_records on forged runs: the newest project-only END is the project run; verdict PASS only with
             S1-S5 PASS and END ok; KAT files counted; s4b ratio with absolutes and 'GPU side STALE'; live_emission
             uses mean_micros and names the reorg attribution.
  LP5 B224   parse_live_window: Δsum/Δcount (not the absolute sum), s/block, peers first/last, window reorgs.
  LP6 B229   observatory gaps skip implemented proposals from r30; a closed page (last None / < 30) keeps them.
  LP7 B226   G22 number backing: a stale record value FAILs, an unshown value FAILs; a digit unit with no number
             backing FAILs unless it names its as_of_round or soundpage generates it.
  LP8 B225   guard_classes counts 1 logging-only, 1 build-metadata, 6 constructs, 1 helper on the committed guard
             record; gen_blocks: no 'carried forward', G13 = len(files), every number entry re-checks.
  LP9 B227   current_ledger_page: dataset r28d with pages r28, r29 gives dero-r1-r29.html; dead_hrefs finds a missing
             page; a PAUSED gate is never FAIL and counts apart; press_kpis / matrix_caption from the track.
  LP10 B228  DT10: registry r27 measured with the track at R26 FAILs (L7); DT11: FX-N4 not implemented while BD5 is
             IMPLEMENTED FAILs (L8), and implemented while BD5 is OPEN FAILs; roundlists names a round the track lacks.
  LP11 B203c derofdn_watch: same refs UNCHANGED; a new tag or a moved head CHANGED; annotated tags read peeled.
  LP12 B217   the #fx-replay prose on a page of round >= 30 leads with run C (the HF3 entry) and labels the 7,467,546
             rejection of runs A/B a tool artifact (D2-14); a closed page (29) keeps the two-run text.
  LP13 B214   the r30 entry's LIVE-track clause reads the track: booked at R30 (R27/R28/R28d), carried (R24-R26),
             pending (R29/R30); LP5 also reads tip_age from the record (R30 D3d).
  Committed: the track is at R30 with FX-N4 / FX-N9 implemented, every claim re-tested R30, G24 lag/FX<->BD clean;
             the newest DEROFDN watch record is UNCHANGED; the soundness page's generated blocks are current.

  python3 -I harness/kat/test_ledger_pages_r30.py   # exit 0 ok · 3 a KAT failed · 4 a mutation not caught / INVALID
"""
import datetime, importlib.util, json, re, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
FILES = ['artifacts/src/r30_section.py', 'artifacts/src/observatory_section.py', 'artifacts/src/forensics_section.py',
         'harness/gen_index.py', 'harness/gen_deroarch.py', 'harness/soundness.py', 'harness/loop/ledger_item_map.json',
         'harness/prep_corpus.py']
DIRS = ['harness/kit', 'harness/intel', 'harness/miners']


def load(base, rel, tag):
    spec = importlib.util.spec_from_file_location(f'lp30_{tag}_{id(base)}_{len(sys.modules)}', base / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def chip(k, t):
    return f'<span class="chip {k}">{t}</span>'


_CACHE = {}


def real_rows():
    if 'rows' not in _CACHE:
        R = load(ROOT, 'artifacts/src/r30_section.py', 'real')
        _CACHE['rows'] = R.rft_rows(str(ROOT))
    return _CACHE['rows']


def lp1(base):
    f = []
    R = load(base, 'artifacts/src/r30_section.py', 'r30')
    imap = json.loads((base / 'harness/loop/ledger_item_map.json').read_text())
    page = (ROOT / 'artifacts/dero-r1-r29.html').read_text()
    rows = dict(real_rows())
    rows.update({f'CLOSED28:{k}': {'class': 'closed', 'status': 'REPORT-ONLY', 'cells': [k, '']} for k in ('L24-9', 'L24-25')})
    rows.update({k: {'class': 'closed', 'status': v['status'], 'cells': [k, '']} for k, v in (imap.get('pseudo') or {}).items()})
    n = 0
    for sid in ('ceilings', 'open23c', 'open24', 'open25', 'open26', 'open27', 'open28', 'open29'):
        sec = re.search(rf'<section id="{sid}".*?</section>', page, re.S).group(0)
        keys = R.li_keys(sec, sid)
        n += len(keys)
        for k in keys:
            ids = (imap.get('items') or {}).get(k)
            if not ids:
                f.append(f'LP1 {k}: no map entry')
            elif [i for i in ids if i not in rows]:
                f.append(f'LP1 {k}: maps to unknown ids {[i for i in ids if i not in rows]}')
        out = R.now_chips(sec, sid, imap, rows, 30, chip)
        if out.count('R30 now:') != len(keys):
            f.append(f'LP1 {sid}: {out.count("R30 now:")} now chips for {len(keys)} items')
        if 'class="chip bad">R30 now: unmapped' in out:
            f.append(f'LP1 {sid}: an item rendered unmapped')
    if n < 150:
        f.append(f'LP1 only {n} items found')
    fr = {'B1': {'class': 'open', 'status': 'OPEN (user)'}, 'B8': {'class': 'closed', 'status': 'REPORT-ONLY (consensus)'},
          'B12': {'class': 'closed', 'status': 'CLOSED in R23c'}, 'BD5': {'class': 'implemented', 'status': 'IMPLEMENTED (R25)'}}
    sec = '<section id="open99"><ul><li>a</li><li>b</li><li>c</li><li>d</li><li>e</li><li>f</li></ul></section>'
    o = R.now_chips(sec, 'open99', {'items': {'open99/0': ['B1'], 'open99/1': ['B8'], 'open99/2': ['B12'], 'open99/3': ['BD5'], 'open99/5': ['B12', 'B1']}}, fr, 30, chip)
    want = ['chip warn">R30 now: B12 CLOSED; B1 OPEN', 'chip warn">R30 now: OPEN', 'chip warn">R30 now: REPORT-ONLY', 'chip good">R30 now: CLOSED', 'chip new">R30 now: IMPLEMENTED', 'chip bad">R30 now: unmapped item open99/4']
    for w in want:
        if w not in o:
            f.append(f'LP1 forged: {w!r} missing in {o[:200]}')
    if R.closed28_kind('REPORT-ONLY (consensus)', 30) != 'warn' or R.closed28_kind('MITIGATED in r24', 30) != 'warn':
        f.append('LP1 closed28: REPORT-ONLY / MITIGATED not warn at r30')
    if R.closed28_kind('REPORT-ONLY (consensus)', 29) != 'good' or R.closed28_kind('CLOSED', 30) != 'good':
        f.append('LP1 closed28: a closed page or a CLOSED verdict is not good')
    return f


def forged_rows():
    mk = lambda c, s, t='item text': {'class': c, 'status': s, 'cells': ['x', t]}
    rows = {f'B{i}': mk('open', 'OPEN (R30: miner track resumed)') for i in (2, 3, 4, 5, 6, 7, 20, 25, 26, 27, 37)}
    rows.update({'B1': mk('open', 'OPEN (user)'), 'B39': mk('closed', 'REFUTED in r24'), 'B47': mk('closed', 'CLOSED (R28)'),
                 'B184': mk('closed', 'STANDING watch'), 'B190': mk('closed', 'FIXED (r28d)'), 'B193': mk('open', 'OPEN'),
                 'B201': mk('open', 'OPEN'), 'B63': mk('implemented', 'IMPLEMENTED (R25)'), 'B12': mk('closed', 'CLOSED')})
    return rows


def lp2(base):
    f = []
    R = load(base, 'artifacts/src/r30_section.py', 'r30')
    rows = forged_rows()
    td = Path(tempfile.mkdtemp(prefix='lp30rec_'))
    try:
        (td / 'rec.json').write_text(json.dumps({'kpis': {'skill_fresh': 1}}))
        imap = {'watch': {'B47': 'sync-hold counters'}, 'miner_extra': {'B39': '24 h flip'}, 'scope': {'B190': 'UNCLEAR by scope'},
                'standing': ['B184'], 'record_closures': {'B193': {'record': 'rec.json', 'key': 'kpis.skill_fresh', 'want': 1}}}
        o = R.open30(rows, imap, tip=7_875_648, tip_at=datetime.datetime(2026, 11, 8, 16, 33, 40), spb=18.52, root=str(td))
        ids = [x[1] for x in o]
        if len(ids) != len(set(ids)):
            f.append(f'LP2 an id listed twice: {ids}')
        for i, r in rows.items():
            if r['class'] != 'closed' and i not in ids:
                f.append(f'LP2 non-closed {i} missing from OPEN30')
        g = {x[1]: x for x in o}
        if g.get('B47', ('',))[0] != 'watch' or 'sync-hold counters' not in g['B47'][4]:
            f.append(f'LP2 B47 not in the watch group with its counter: {g.get("B47")}')
        if [i for i in R.MINER_ROWS if g.get(i, ('',))[0] != 'miner'] or g.get('B39', ('',))[0] != 'miner':
            f.append('LP2 the miner group lacks a miner row or B39')
        if g.get('B184', ('',))[0] != 'standing' or '124,352 blocks' not in g['B184'][4] or '2026-12-05' not in g['B184'][4]:
            f.append(f'LP2 B184 standing ESTIMATE wrong: {g.get("B184")}')
        if 'B190' not in g or 'UNCLEAR by scope' not in g['B190'][4]:
            f.append('LP2 B190 scope row missing')
        if 'closed by record' not in g.get('B193', ('',) * 5)[4]:
            f.append('LP2 B193 record closure not applied')
        (td / 'rec.json').write_text(json.dumps({'kpis': {'skill_fresh': 0}}))
        o2 = {x[1]: x for x in R.open30(rows, imap, root=str(td))}
        if 'closed by record' in o2['B193'][4]:
            f.append('LP2 a record closure applied while its record does not hold')
    finally:
        shutil.rmtree(td, ignore_errors=True)
    return f


def lp3(base):
    f = []
    R = load(base, 'artifacts/src/r30_section.py', 'r30')
    pipes = [('R28', {'verdict': 'PASS', 'mutations': '1579/1579', 'gates': '29/32', 'kats': '35/35'}),
             ('R29', {'verdict': 'PASS', 'mutations': '1619/1619', 'gates': '30/33', 'kats': '35/35'}), ('R30', {'verdict': 'pending'})]
    lab, p = R.latest_pipe(pipes)
    if lab != 'R29':
        f.append(f'LP3 latest_pipe {lab}')
    v = R.ver_rows(pipes)
    if len(v) != 2 or v[-1] != ('R29', 1619, 30, 35):
        f.append(f'LP3 ver_rows {v}')
    fbv = '"""doc\n  S1 guard      x\n  S4b miner    y\n  S4c gpu      (R22) the GPU side of split, like\n  S5 shadow    z\n"""'
    ids = R.stage_ids(fbv)
    if ids != ['S1', 'S4b', 'S4c', 'S5']:
        f.append(f'LP3 stage_ids {ids}')
    lab = R.stage_labels(fbv)
    plain = 'flowchart TD\n  S1["a"] --> S4b["b"]\n  S4b --> S5["c"]'
    o = R.add_stages(plain, ids, lab)
    if 'S4b --> S4c[' not in o or 'S4c --> S5' not in o:
        f.append(f'LP3 add_stages plain: {o}')
    esc = 'flowchart TD\n  S1[&quot;a&quot;] --&gt; S4b[&quot;b&quot;]\n  S4b --&gt; S5[&quot;c&quot;]'
    o = R.add_stages(esc, ids, lab)
    if 'S4b --&gt; S4c[&quot;' not in o or 'S4c --&gt; S5' not in o:
        f.append(f'LP3 add_stages escaped: {o}')
    return f


def _w(td, name, events):
    (td / 'harness/loop/runs').mkdir(parents=True, exist_ok=True)
    (td / f'harness/loop/runs/{name}.jsonl').write_text('\n'.join(json.dumps(e) for e in events) + '\n')


def lp4(base):
    f = []
    R = load(base, 'artifacts/src/r30_section.py', 'r30')
    td = Path(tempfile.mkdtemp(prefix='lp30runs_'))
    try:
        beg = {'stage': 'run', 'status': 'BEGIN', 'round': 'r29'}
        full = [beg] + [{'stage': s, 'status': 'PASS'} for s in R.S1_S5 if s not in ('mutate', 'race', 'build', 'minerbench', 'shadow')] + [
            {'stage': 'mutate', 'status': 'PASS', 'last': "['go mutations: 1619/1619 caught']"}, {'stage': 'race', 'status': 'PASS', 'packages_ok': '27', 'races': '0'},
            {'stage': 'build', 'status': 'PASS', 'version': 'v29'}, {'stage': 'shadow', 'status': 'PASS', 'blocks_compared': '120', 'mismatches': '0'},
            {'stage': 'minerbench', 'status': 'PASS', 'vs_installed_cpu': '1.001', 'vs_installed_mode': 'auto',
             'vs_installed_per_mode': "{'auto': {'staged': 3470.2, 'installed': 3466.8}}", 'split_gpu_side': "{'status': 'STALE', 'why': 'old'}"},
            {'stage': 'project', 'status': 'FAIL'}, {'stage': 'done', 'status': 'END', 'ok': 'False'}]
        _w(td, 'pipeline_20261108T062853', full)
        proj = lambda ok: [beg, {'stage': 'guard', 'status': 'PASS'}] + [{'stage': 'project', 'status': 'INFO', 'step': f'harness/kat/test_{i}.py', 'rc': '0'} for i in range(3)] + [
            {'stage': 'project', 'status': 'PASS' if ok else 'FAIL', 'kats': '35/35', 'mutations': '34/34', 'gates': '30/33',
             'over_budget': {'steps': 118, 'wall_s': 2866.9, 'wall_budget_s': 3500.0}}, {'stage': 'done', 'status': 'END', 'ok': str(ok)}]
        _w(td, 'pipeline_20261108T123859', proj(True))
        _w(td, 'pipeline_20261108T165350', proj(True))
        P = R.pipe_from_records(str(td), 'r29')
        exp = {'run_id': 'pipeline_20261108T062853', 'project_run': 'pipeline_20261108T165350', 'verdict': 'PASS', 'kats': '35/35',
               'mutations': '1619/1619', 'race_packages': '27 packages 0 races', 'kat_files': '3/3', 'steps': 118, 'wall_s': 2866.9}
        for k, v in exp.items():
            if P.get(k) != v:
                f.append(f'LP4 {k}: {P.get(k)!r} != {v!r}')
        if P['s4b'] != 'PASS ×1.001 (staged 3,470.2 vs installed 3,466.8 H/cpu-s, auto); GPU side STALE':
            f.append(f'LP4 s4b: {P["s4b"]}')
        _w(td, 'pipeline_20261108T175000', proj(False))
        if R.pipe_from_records(str(td), 'r29')['verdict'] != 'FAIL':
            f.append('LP4 a closing project run that FAILED still gives PASS')
        if R.pipe_from_records(str(td), 'r31')['verdict'] != 'pending':
            f.append('LP4 a round with no records is not pending')
    finally:
        shutil.rmtree(td, ignore_errors=True)
    t = 'GetEmissionAudit: ' + json.dumps({'audited': 219, 'alerts': 0, 'payees': 1450, 'payees_verified': 1450, 'mean_micros': 4465.06,
                                            'cpu_micros_total': 999999, 'reorgs': 1}) + '\n'
    s = R.emission_text(R.parse_emission(t), 0)
    if s != '219 audited, 0 alerts, payees 1,450/1,450, 4,465 µs per block, reorgs 1 vs 0 in the window (attribution pending)':
        f.append(f'LP4 live_emission: {s}')
    return f


WIN = '''samples 61 (61 usable) from 2026-11-08T15:33:40-0800 to 2026-11-08T16:33:40-0800
first 2026-11-08T15:33:40-0800: version v uptime 39 s height 7875456 status synced lag 0 tip_age 8.6 s out 14 in 4 recovered_panics 0
first GetConsensusStats counters {} reorgs 2 final_violations 0
last 2026-11-08T16:33:40-0800: version v uptime 3640 s height 7875648 status synced lag 0 tip_age 8.5 s out 13 in 27 recovered_panics 0
last GetConsensusStats counters {} reorgs 3 final_violations 0
series: status {'synced': 61}; lag max 0; tip_age mean 12.5 s median 9.6 max 45.3; outgoing min 13 max 15; RPC read errors 0
blocks in the window (first..last sample) 192 (7875456..7875648)
  block_propagation_duration_histogram_seconds_count 3 -> 201
  block_propagation_duration_histogram_seconds_sum 0.413288 -> 34.98627400000001
  p2p_miniblock_send_ack_seconds_count{origin="relay"} 352 -> 50018
  p2p_miniblock_send_ack_seconds_sum{origin="relay"} 56.69070183199999 -> 9466.545895970034
'''


def lp5(base):
    f = []
    R = load(base, 'artifacts/src/r30_section.py', 'r30')
    o = R.parse_live_window(WIN)
    chk = {'tip_age_mean_s': 12.5, 'blocks': 192, 's_per_block': 18.75, 'peers_in': 27, 'peers_out': 13, 'peers_in_first': 4, 'reorgs_window': 1}
    for k, v in chk.items():
        if o.get(k) != v:
            f.append(f'LP5 {k}: {o.get(k)!r} != {v!r}')
    if o.get('prop_ms') is None or abs(o['prop_ms'] - 174.611) > 0.01:
        f.append(f'LP5 prop_ms {o.get("prop_ms")} (want Δsum/Δcount 174.61)')
    if o.get('relay_ack_ms') is None or abs(o['relay_ack_ms'] - 189.463) > 0.01:
        f.append(f'LP5 relay_ack_ms {o.get("relay_ack_ms")}')
    if o.get('latency_median_ms') is not None:
        f.append('LP5 a latency the record does not carry was filled')
    # R30 D3d: tip_age is read from the record (another value reads back; a record without it is None, never a constant)
    o2 = R.parse_live_window(WIN.replace('tip_age mean 12.5 s', 'tip_age mean 31.2 s'))
    o3 = R.parse_live_window(re.sub(r'tip_age mean [\d.]+ s', 'tip_age n/a', WIN))
    if o2.get('tip_age_mean_s') != 31.2 or o3.get('tip_age_mean_s') is not None:
        f.append(f"LP5 tip_age_mean_s {o2.get('tip_age_mean_s')!r} / {o3.get('tip_age_mean_s')!r} (want 31.2 / None)")
    return f


def lp6(base):
    f = []
    O = load(base, 'artifacts/src/observatory_section.py', 'obs')
    d = {'chain': {'proposals': []}, 'peers': {'proposals': [{'id': 'CO24-N1', 'title': 't1', 'status': 'implemented (r25)'},
                                                             {'id': 'CO24-N9', 'title': 't9', 'status': 'open'}]}, 'bmap': {'CO24-N1': 'B63'}}
    if [g[0] for g in O.gaps(d)] != ['CO24-N9']:
        f.append(f'LP6 gaps() kept an implemented proposal: {O.gaps(d)}')
    if [g[0] for g in O.gaps(d, None)] != ['CO24-N1', 'CO24-N9']:
        f.append('LP6 the closed-page reading lost a proposal')
    o30 = O.open_items(d, 30)
    if o30[0][1:] != ('good', 'implemented (r25), live') or o30[1][2] != 'open (R25, node-side)':
        f.append(f'LP6 open_items r30: {o30}')
    if [x[2] for x in O.open_items(d)] != ['open (R25, node-side)'] * 2:
        f.append('LP6 a closed page changed its open_items')
    return f


def lp7(base):
    f = []
    S = load(base, 'harness/soundness.py', 'snd')
    td = Path(tempfile.mkdtemp(prefix='lp30snd_'))
    try:
        (td / 'r.json').write_text(json.dumps({'a': {'n': 9}, 'files': [1, 2, 3]}))
        (td / 'w.txt').write_text('x\nGetEmissionAudit: {"audited": 219}\n')
        e = {'id': 'x', 'kind': 'record', 'match': 'Gate G13: 9 files.', 'source': 's'}
        ok = S.check_number({'type': 'number', 'file': 'r.json', 'key': 'a.n', 'want': 9}, e, td)
        if not ok[0]:
            f.append(f'LP7 a current figure failed: {ok}')
        st = S.check_number({'type': 'number', 'file': 'r.json', 'key': 'a.n', 'want': 7}, {**e, 'match': 'Gate G13: 7 files.'}, td)
        if st[0]:
            f.append('LP7 a stale figure (record 9, page 7) passed')
        if S.check_number({'type': 'number', 'file': 'r.json', 'key': 'a.n', 'want': 7}, e, td)[0]:
            f.append('LP7 an entry written for 7 passed against a record of 9')
        if S.check_number({'type': 'number', 'file': 'r.json', 'key': 'a.n', 'want': 9}, {**e, 'match': 'Gate G13: files.'}, td)[0]:
            f.append('LP7 a number not shown in the unit passed')
        if S.record_value(td, 'r.json', 'files#len') != 3 or S.record_value(td, 'w.txt', 'GetEmissionAudit:audited') != 219:
            f.append('LP7 record_value #len / text-record read wrong')
        if not S.needs_number({'kind': 'record', 'match': 'The guard passed on 7 files.', 'source': 's'}):
            f.append('LP7 an unbound digit unit is not required to have a number backing')
        if S.needs_number({'kind': 'record', 'match': 'Shadow run for Round 23: 120 blocks.', 'source': 's', 'as_of_round': 'R23'}):
            f.append('LP7 an as_of_round named in the text still needs a number')
        if S.needs_number({'kind': 'record', 'match': 'R28 and G13 and r28d.', 'source': 's'}):
            f.append('LP7 identifiers (R28, G13) counted as figures')
        reg = {'claims': [{'id': 'u', 'kind': 'record', 'match': 'The guard passed on 7 files.', 'exact': True, 'source': 's'},
                          {'id': 'c', 'kind': 'code', 'match': 'Code line.', 'exact': True, 'backing': [{'type': 'anchor', 'file': 'r.json', 'line': 1, 'quote': '"a"'}]}]}
        r = S.evaluate('<p>The guard passed on 7 files.</p><p>Code line.</p>', reg, {}, root=td, live=False)
        if r['ok'] or not any('B226' in w for w in r['why']):
            f.append(f'LP7 evaluate passed an unbound figure: {r["why"][:2]}')
    finally:
        shutil.rmtree(td, ignore_errors=True)
    return f


def lp8(base):
    f = []
    SP = load(base, 'harness/kit/soundpage.py', 'sp')
    S = load(base, 'harness/soundness.py', 'snd')
    g = json.loads((ROOT / 'harness/loop/CONSENSUS_GUARD.json').read_text())
    gc = SP.guard_classes(g)
    if gc != {'logging-only': 1, 'build-metadata': 1, 'constructs': 6, 'helper': 1}:
        f.append(f'LP8 guard_classes {gc}')
    blocks = SP.gen_blocks(ROOT)
    names = [b[0] for b in blocks]
    for n in ('header', 'section0', 'tiles', 'release', 'footer'):
        if n not in names:
            f.append(f'LP8 block {n} missing')
    allh = ''.join(b[1] for b in blocks)
    if 'carried forward' in allh:
        f.append('LP8 a generated block says carried forward')
    rel = dict((b[0], b) for b in blocks).get('release')
    if rel and f'({len(g["files"])} files' not in rel[1]:
        f.append('LP8 the G13 sentence does not carry len(files)')
    for _, _, es in blocks:
        for e in es:
            for b in e.get('backing') or []:
                ok = S.check_number(b, e, ROOT)
                if not ok[0]:
                    f.append(f'LP8 {e["id"]}: {ok[1]}')
    return f


def lp9(base):
    f = []
    FS = load(base, 'artifacts/src/forensics_section.py', 'fs')
    if FS.current_ledger_page(['dero-r1-r28.html', 'dero-r1-r29.html', 'index.html'], 'r28d') != 'dero-r1-r29.html':
        f.append('LP9 dataset r28d with ledger r29 does not give dero-r1-r29.html')
    if FS.current_ledger_page([], 'r28d') != 'dero-r1-r28.html':
        f.append('LP9 no page listed: not the dataset parent page')
    C = load(base, 'harness/intel/coherence.py', 'coh')
    d = C.dead_hrefs('<a href="dero-r1-r28d.html#x">a</a>\n<a href="https://x.y/a.html">b</a> <a href="ok.html">c</a>', lambda h: h == 'ok.html')
    if d != [(1, 'dero-r1-r28d.html')]:
        f.append(f'LP9 dead_hrefs {d}')
    GI = load(base, 'harness/gen_index.py', 'gi')
    if GI.gate_state("PAUSED (miner): harness/round.json") != 'PAUSED' or GI.gate_state('PASS') != 'PASS' or GI.gate_state('FAIL x') != 'FAIL':
        f.append('LP9 gate_state')
    if 'FAIL' in GI.gate_cell('PAUSED (miner)'):
        f.append('LP9 a PAUSED gate renders FAIL')
    lab = GI.gates_label([['', '', '', 'G1', 'PASS'], ['', '', '', 'G17', 'PAUSED (miner)'], ['', '', '', 'G2', 'FAIL']])
    if lab != '1/2 (+1 PAUSED)':
        f.append(f'LP9 gates_label {lab}')
    GD = load(base, 'harness/gen_deroarch.py', 'gd')
    tv = {'C1': ('CONFIRMED', 'R30'), 'C2': ('PARTLY-CONFIRMED', 'R30'), 'C8': ('CANNOT-DETERMINE-LOCALLY', 'R30')}
    tv.update({f'C{i}': ('PARTLY-CONFIRMED', 'R30') for i in range(3, 8)})
    k = GD.press_kpis(tv)
    if [x[0] for x in k] != ['8', '1', '6', '0', '1']:
        f.append(f'LP9 press_kpis {k}')
    if 'C2) is partly confirmed' not in GD.matrix_caption(tv) or 'refuted' in GD.matrix_caption(tv):
        f.append(f'LP9 matrix_caption {GD.matrix_caption(tv)}')
    return f


def lp10(base):
    f = []
    DT = load(base, 'harness/intel/disclosure_track.py', 'dt')
    tr = {'rounds': ['R24', 'R25', 'R26', 'R27'], 'current_round': 'R26', 'fixes': []}
    reg = {'rounds': [{'id': 'r26', 'status': 'measured'}, {'id': 'r27', 'status': 'measured'}, {'id': 'r28', 'status': 'in-progress'}]}
    if not DT.lag_problems(tr, reg):
        f.append('B228 DT10 a track at R26 with r27 measured passed')
    if DT.lag_problems({**tr, 'current_round': 'R27'}, reg):
        f.append('DT10 a current track failed')
    if not DT.lag_problems({**tr, 'rounds': ['R24', 'R25', 'R26']}, reg):
        f.append('DT10 a measured round missing from the track passed')
    fx = lambda st: {'fixes': [{'id': 'FX-N4', 'kind': 'NODE-LOCAL', 'status': st}]}
    if not DT.fx_bd_problems(fx('feasible-not-implemented'), {'FX-N4': ('BD5', 'implemented')}):
        f.append('B228 DT11 FX-N4 not implemented while BD5 is IMPLEMENTED passed')
    if not DT.fx_bd_problems(fx('implemented'), {'FX-N4': ('BD5', 'open')}):
        f.append('B228 DT11 FX-N4 implemented while BD5 is OPEN passed')
    if DT.fx_bd_problems(fx('implemented'), {'FX-N4': ('BD5', 'implemented')}):
        f.append('DT11 an agreeing pair failed')
    ev = DT.evaluate({**tr, 'claims': [], 'facts': [], 'press_map': {}}, root=base, registry=reg, bd={})
    if not any('G24 lag' in w for w in ev['why']):
        f.append('DT10 evaluate() does not run the lag check when given a registry')
    RL = load(base, 'harness/kit/roundlists.py', 'rl')
    L = {'registry': ['r23c', 'r24', 'r25', 'r26'], 'current': 'r26', 'planned': [], 'areas': ['r23c', 'r24', 'r25', 'r26'],
         'ledger': [24, 25, 26], 'evolution': ['R23c', 'R24', 'R25', 'R26'], 'disclosure': ['R8', 'R24', 'R26']}
    p = RL.problems(L)
    if not any('disclosure: R25 missing' in x for x in p) or any('R23c' in x for x in p):
        f.append(f'LP10 roundlists track check: {p}')
    return f


LS = '''{a} refs/heads/main
{b} refs/heads/community-dev
{c} refs/tags/Release153
{d} refs/tags/Release153^{{}}
'''


def lp11(base):
    f = []
    W = load(base, 'harness/intel/derofdn_watch.py', 'dw')
    a, b, c, d = 'a' * 40, 'b' * 40, 'c' * 40, 'd' * 40
    now = W.parse(LS.format(a=a, b=b, c=c, d=d))
    if now['tags'].get('Release153') != d:
        f.append(f'LP11 annotated tag not peeled: {now["tags"]}')
    base_ = W.baseline_of({'heads': {'main': a[:12] + ' (= baseline)', 'community-dev': b}, 'tags': 1, 'newest_tags': {'Release153': d[:8]}})
    if W.compare(now, base_)['result'] != 'UNCHANGED':
        f.append(f'LP11 same refs: {W.compare(now, base_)}')
    if W.compare(W.parse(LS.format(a='e' * 40, b=b, c=c, d=d)), base_)['result'] != 'CHANGED':
        f.append('LP11 a moved head is UNCHANGED')
    rev = f'{d} refs/tags/Release153^{{}}\n{c} refs/tags/Release153\n{a} refs/heads/main\n'
    if W.parse(rev)['tags'].get('Release153') != d:
        f.append('LP11 an annotated tag listed after its peeled line lost the peeled commit')
    more = LS.format(a=a, b=b, c=c, d=d) + f'{"f" * 40} refs/tags/Release154\n'
    if W.compare(W.parse(more), base_)['result'] != 'CHANGED':
        f.append('LP11 a new tag is UNCHANGED')
    return f


def lp12(base):
    f = []
    import html as _h
    FM = load(ROOT, 'harness/forensics/facts.py', 'fm')
    FS = load(base, 'artifacts/src/forensics_section.py', 'fs12')
    ds, rec = FM.page_inputs(str(ROOT), str(ROOT))
    F = FM.build(ds, str(ROOT), rec)
    if 'runc_topos' not in F.facts:
        return ['LP12 the newest dataset carries no run C facts']
    # r30 merge (v5 registered): the closed r29 page is built from ITS frozen inputs (the r28d dataset), as gen_ledger
    # --last 29 does; the newest dataset (r30) no longer carries the legacy replay_wall1_ok fact the closed prose reads
    ds29, rec29 = FM.page_inputs(str(ROOT), str(ROOT / 'artifacts/src/frozen/r29'))
    F29 = FM.build(ds29, str(ROOT), rec29)
    def sec(rnd, facts):
        out = FS.section_v2(facts, FM, _h.escape, chip, rnd)
        return re.search(r'<section id="fx-replay".*?</section>', out[0] if isinstance(out, tuple) else out, re.S).group(0)
    t30, t29 = sec(30, F), sec(29, F29)
    if '<b>Run C</b>' not in t30 or t30.find('<b>Run C</b>') > t30.find('<b>Runs A and B</b>') or 'a tool artifact of the pre-fix entry' not in t30:
        f.append('LP12 the r30 replay prose does not lead with run C or does not label the A/B rejection a tool artifact')
    if '<b>Run C</b>' in t29 or 'carries two node replay runs' not in t29:
        f.append('LP12 the closed r29 replay prose changed')
    return f


def lp13(base):
    """R30 verifier note (B214): the r30 entry's LIVE-track clause comes from the track: rounds booked at the current
    round, rounds carried from their own rounds, pending rounds"""
    f = []
    R = load(base, 'artifacts/src/r30_section.py', 'r30l')
    dt = {'current_round': 'R30', 'live': {'_doc': 'd', 'R24': {'record': 'a'}, 'R27': {'record': 'b'}, 'R28d': {'record': 'c'},
                                           'R29': 'pending live', 'R30': 'pending live'},
          'tested_at': {'R24': '04ceb55', 'R27': 'live only: x; booked at R30 (B214)', 'R28d': 'live only: y; booked at R30 (B214)',
                        'R29': 'pending live (booked at R30, B214)'}}
    t = R.live_track_rounds(dt)
    if t != {'carried': ['R24'], 'booked': ['R27', 'R28d'], 'pending': ['R29', 'R30']}:
        f.append(f'LP13 live_track_rounds {t}')
    x = R.live_track_text(dt)
    if 'books R27 and R28d at R30' not in x or 'R24 carry' not in x or 'R29 / R30 as pending live' not in x or 'R24 to' in x:
        f.append(f'LP13 live_track_text {x!r}')
    return f


def lp14(base):
    """r30 B222: the Live miner row comes from the newest LIVE, measured hashrate_objective record; a bench record or an
    unmeasured window never fills it; no record -> pending"""
    f = []
    R = load(base, 'artifacts/src/r30_section.py', 'lp14')
    with tempfile.TemporaryDirectory() as td:
        rt = Path(td) / 'harness/runtime'
        rt.mkdir(parents=True)
        if R.miner_live(td) is not None or R.miner_live_text(None) != R.PENDING:
            f.append('LP14: no record must read pending')
        live = {'objective_hs': 150000, 'progress': 0.64, 'window': {'kind': 'live', 'measured': True, 'mean_hs': 96004.9,
                'excludes_stale_sha': True, 'cores': 17.97, 'h_cpu_s': 5344.0, 'n': 254, 'continuity': 'CONTINUOUS',
                'first': '2026-11-11T19:30:46-08:00', 'last': '2026-11-11T20:34:05-08:00'},
                'ceiling': {'ceiling_hs': 95574, 'binding': 'cpu'}, 'live_law': {'status': 'FIT', 'r_P': 5491.5, 'r_E': 4582.2, 'n': 254}}
        (rt / 'r30_hashrate_objective_20261111T2034.json').write_text(json.dumps(live))
        bench = dict(live, window=dict(live['window'], kind='bench', mean_hs=150000.0))
        (rt / 'r30_hashrate_objective_20261111T2100.json').write_text(json.dumps(bench))
        ml = R.miner_live(td)
        txt = R.miner_live_text(ml)
        if not ml or ml[0] != 'harness/runtime/r30_hashrate_objective_20261111T2034.json':
            f.append(f'LP14: the newest LIVE record must be picked, not the newer bench: {ml and ml[0]}')
        for want in ('96.0 kH/s', 'excludes stale-SHA', '17.97 cores', '5,344 H/cpu-s', '64.0 %', 'CONTINUOUS',
                     'measured ceiling 95,574 H/s (binding cpu)', 'B27 law FIT'):
            if want not in txt:
                f.append(f'LP14: {want!r} missing from {txt[:160]!r}')
    return f


def lp15(base):
    """r30 B261: the soundness page's project-run sentence anchors the run's record when it exists and anchors nothing
    while the run is pending (never harness/loop/runs/pending.jsonl)"""
    f = []
    SP = load(base, 'harness/kit/soundpage.py', 'lp15')
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / 'harness/loop/runs').mkdir(parents=True)
        (Path(td) / 'harness/loop/runs/pipeline_X.jsonl').write_text(json.dumps({'stage': 'project', 'status': 'PASS', 'kats': '36/36'}) + '\n')
        (Path(td) / 'harness/loop/runs/pipeline_F.jsonl').write_text(json.dumps({'stage': 'project', 'status': 'FAIL', 'step': 'x', 'why': 'exit 4'}) + '\n')
        nokats = SP.project_backing(td, {'project_run': 'pipeline_F'})
        pend = SP.project_backing(td, {'project_run': 'pending'})
        gone = SP.project_backing(td, {'project_run': 'pipeline_missing'})
        have = SP.project_backing(td, {'project_run': 'pipeline_X'})
    if pend != [] or gone != [] or nokats != []:
        f.append(f'LP15: a pending / missing run, or a project FAIL without kats, must anchor nothing: {pend} {gone} {nokats}')
    if not have or have[0].get('file') != 'harness/loop/runs/pipeline_X.jsonl' or have[0].get('want') != '36/36':
        f.append(f'LP15: an existing run must be anchored: {have}')
    return f


def committed():
    f = []
    t = json.loads((ROOT / 'harness/loop/disclosure_track.json').read_text())
    if t.get('current_round') != 'R30':
        f.append(f'committed: track current_round {t.get("current_round")}')
    fx = {x['id']: x for x in t.get('fixes') or []}
    for k in ('FX-N4', 'FX-N9'):
        if fx.get(k, {}).get('status') != 'implemented' or not fx.get(k, {}).get('implemented_in'):
            f.append(f'committed: {k} not implemented in the track')
    for c in t.get('claims') or []:
        if c['history'][-1].get('round') != 'R30':
            f.append(f'committed: {c["id"]} not re-tested R30')
    for r in ('R27', 'R28', 'R28d', 'R29', 'R30'):
        if r not in (t.get('live') or {}):
            f.append(f'committed: LIVE track lacks {r}')
    R = load(ROOT, 'artifacts/src/r30_section.py', 'r30c')
    if R.live_track_rounds(t)['booked'] != ['R27', 'R28', 'R28d']:
        f.append(f"committed: the track books {R.live_track_rounds(t)['booked']} at R30 (rows.md B214: R27/R28/R28d)")
    gl = (ROOT / 'artifacts/src/gen_ledger.py').read_text()
    if 'books R24 to R28d' in gl or 'R30.live_track_text(_DTJ)' not in gl:
        f.append('committed: the r30 entry still types the LIVE-track rounds instead of reading the track')
    DT = load(ROOT, 'harness/intel/disclosure_track.py', 'dtc')
    reg = json.loads((ROOT / 'harness/round.json').read_text())
    if DT.lag_problems(t, reg) or DT.fx_bd_problems(t, DT.bd_leads(ROOT)):
        f.append(f'committed: G24 lag / FX<->BD: {DT.lag_problems(t, reg) + DT.fx_bd_problems(t, DT.bd_leads(ROOT))}')
    W = load(ROOT, 'harness/intel/derofdn_watch.py', 'dwc')
    nr = W.newest_record(ROOT)
    if not nr or json.loads(Path(nr).read_text()).get('result') != 'UNCHANGED':
        f.append(f'committed: newest DEROFDN watch {nr} not UNCHANGED')
    SP = load(ROOT, 'harness/kit/soundpage.py', 'spc')
    if SP.write_gen(ROOT, check=True)[0]:
        f.append('committed: the soundness page generated blocks are stale')
    return f


def kats(base):
    f = []
    for fn in (lp1, lp2, lp3, lp4, lp5, lp6, lp7, lp8, lp9, lp10, lp11, lp12, lp13, lp14, lp15):
        try:
            f += fn(base)
        except Exception as e:                                       # noqa: BLE001
            f.append(f'{fn.__name__} crashed: {type(e).__name__}: {e}')
    return f


MUTATIONS = [   # (file under the copied base, old, new)
    ('harness/loop/ledger_item_map.json', '"open29/0": [', '"open29/0-dropped": ['),
    ('artifacts/src/r30_section.py', "        return 'warn' if w.split()[0] in WARN_CLOSED else 'good'", "        return 'good'"),
    ('artifacts/src/r30_section.py', "    if last >= 30 and str(status or '').strip().upper().startswith(WARN_CLOSED):", "    if str(status or '').strip().upper().startswith(WARN_CLOSED):"),
    ('artifacts/src/r30_section.py', "        c = now_chip(ids, rows, rnd, chip) if ids else chip('bad', f'R{rnd} now: unmapped item {k}')", "        c = now_chip(ids, rows, rnd, chip) if ids else ''"),
    ('artifacts/src/r30_section.py', "    i, r = min(rs, key=lambda x: (rank.get(x[1]['class'], 0), x[0]))", "    i, r = max(rs, key=lambda x: (rank.get(x[1]['class'], 0), x[0]))"),
    ('artifacts/src/r30_section.py', "        if i in taken or (r['class'] == 'closed' and i not in standing and i not in scope):", "        if i in taken or r['class'] == 'closed':"),
    ('artifacts/src/r30_section.py', "    for i, ctr in watch.items():\n        if i in rows:", "    for i, ctr in watch.items():\n        if False:"),
    ('artifacts/src/r30_section.py', "    left = hf4 - int(tip)", "    left = hf4 - int(tip) + 1"),
    ('artifacts/src/r30_section.py', "        if i in rec and root is not None and record_holds(root, rec[i]):", "        if i in rec and root is not None:"),
    ('artifacts/src/r30_section.py', "    for i, why in extra_miner.items():\n        if i in rows:", "    for i, why in extra_miner.items():\n        if False:"),
    ('artifacts/src/r30_section.py', "        if str((p or {}).get('verdict', PENDING)).strip().lower() not in ('', PENDING):\n            return lab, p", "        return lab, p"),
    ('artifacts/src/r30_section.py', "    for lab, p in pipes:\n        if str((p or {}).get('verdict', PENDING)).strip().lower() in ('', PENDING):\n            continue", "    for lab, p in pipes[:-2]:\n        if str((p or {}).get('verdict', PENDING)).strip().lower() in ('', PENDING):\n            continue"),
    ('artifacts/src/r30_section.py', "        if re.search(rf'\\b{sid}\\[', src) or re.search(rf'\\b{sid} {arrow}', src):", "        if True:"),
    ('artifacts/src/r30_section.py', "    arrow = '--&gt;' if esc else '-->'", "    arrow = '-->'"),
    # r30 B261 (LP15)
    ('harness/kit/soundpage.py', "    return [{'type': 'number', 'file': f'harness/loop/runs/{run}.jsonl', 'key': 'stage=project.kats', 'want': want}]",
     "    return [{'type': 'number', 'file': f'harness/loop/runs/{run}.jsonl', 'key': 'stage=project.kats', 'want': '35/35'}]"),
    ('harness/kit/soundpage.py', "    if want is None:\n        return []", "    if False:\n        return []"),
    # r30 B222 (LP14)
    ('artifacts/src/r30_section.py', "        if w.get('kind') == 'live' and w.get('measured') is True and isinstance(w.get('mean_hs'), (int, float)):",
     "        if isinstance(w.get('mean_hs'), (int, float)):"),
    ('artifacts/src/r30_section.py', "    if not ml:\n        return PENDING\n    path, d = ml", "    if not ml:\n        return '0 kH/s'\n    path, d = ml"),
    ('artifacts/src/r30_section.py', "         f\"stale-SHA skipped), {w.get('cores', PENDING)} cores,", "         f\"stale-SHA skipped), 18 cores,"),
    ('artifacts/src/r30_section.py', "    proj = [r for r in runs if not _st(r[1], 'build') and _st(r[1], 'project')]", "    proj = [r for r in runs if _st(r[1], 'project')][:1]"),
    ('artifacts/src/r30_section.py', "        proj_ok = str(end.get('ok')) == 'True' and pr.get('status') == 'PASS'", "        proj_ok = True"),
    ('artifacts/src/r30_section.py', "    return f'{st} ×{r}{ab}' + (f'; GPU side {gpu.group(1)}' if gpu else '')", "    return f'{st} {r} H/cpu-s' + (f'; GPU side {gpu.group(1)}' if gpu else '')"),
    ('artifacts/src/r30_section.py', "    us = d.get('mean_micros')\n", "    us = None\n"),
    ('artifacts/src/r30_section.py', "        s += f', reorgs {e[\"reorgs\"]}' + (f' vs {window_reorgs} in the window (attribution pending)' if window_reorgs is not None and window_reorgs != e['reorgs'] else '')", "        s += f', reorgs {e[\"reorgs\"]}'"),
    ('artifacts/src/r30_section.py', "    return 1000.0 * (s[1] - s[0]) / (c[1] - c[0])", "    return 1000.0 * s[1] / c[1]"),
    ('artifacts/src/r30_section.py', "        o['s_per_block'] = (t1 - t0).total_seconds() / int(b.group(1))", "        o['s_per_block'] = 18.52"),
    ('artifacts/src/r30_section.py', "    o['reorgs_window'] = int(rg['last']) - int(rg['first']) if 'first' in rg and 'last' in rg else None", "    o['reorgs_window'] = int(rg['last']) if 'last' in rg else None"),
    ('artifacts/src/r30_section.py', "        P['kat_files'] = f\"{sum(1 for e in ks if str(e.get('rc')) == '0')}/{len(ks)}\" if ks else PENDING", "        P['kat_files'] = '80/80'"),
    # R30 D3d + the verifier's LIVE-track note
    ('artifacts/src/r30_section.py', "    o['tip_age_mean_s'] = float(m.group(1)) if m else None", "    o['tip_age_mean_s'] = 12.5"),
    ('artifacts/src/r30_section.py', "        elif cur and f'booked at {cur}' in str(ta.get(r, '')):", "        elif cur:"),
    ('artifacts/src/r30_section.py', "        s += f' ({_span(t[\"carried\"])} carry the records booked in their own rounds)'", "        s = s.replace(_and(t['booked']), _span(t['carried'] + t['booked']))"),
    ('artifacts/src/observatory_section.py', "            if implemented is None or is_implemented(p) == bool(implemented):", "            if True:"),
    ('artifacts/src/observatory_section.py', "    if last is None or last < 30:\n        return", "    if True:\n        return"),
    ('harness/soundness.py', "    if v != b.get('want'):\n        return False", "    if False:\n        return False"),
    ('harness/soundness.py', "    if disp not in norm(entry.get('match', '')):\n        return False", "    if False:\n        return False"),
    ('harness/soundness.py', "            if needs_number(c):\n                res.append", "            if False:\n                res.append"),
    ('harness/soundness.py', "    if aor and re.search(", "    if False and re.search("),
    ('harness/soundness.py', "DIGIT_GROUP = re.compile(r'(?<![\\w.#/-])\\d[\\d,]*(?:\\.\\d+)?(?![\\w])')", "DIGIT_GROUP = re.compile(r'\\d')"),
    ('harness/kit/soundpage.py', "        k = ('constructs' if '+' in v else 'build-metadata' if v.startswith('build-metadata') else", "        k = ('constructs' if '+' in v and 'mempool' not in str(f.get('file')) else 'build-metadata' if v.startswith('build-metadata') else"),
    ('harness/kit/soundpage.py', "    rel3 = [(f'Gate G13: every consensus-package change since upstream is logging-only or a reviewed allowed construct ({len(guard.get(\"files\") or [])} files: {gtxt}).',", "    rel3 = [(f'Gate G13: every consensus-package change since upstream is logging-only or a reviewed allowed construct (7 files: {gtxt}).',"),
    ('harness/kit/soundpage.py', "    t = (f'DERO HE · node 3.6.0-153 +{nm.get(\"version_suffix\", \"pending\")} · Round {n} review {st} (opened '", "    t = (f'DERO HE · node 3.6.0-153 +{nm.get(\"version_suffix\", \"pending\")} · Round {n} review {st}, carried forward (opened '"),
    ('artifacts/src/forensics_section.py', "    if ns:\n        return ns[-1][1]", "    if False:\n        return ns[-1][1]"),
    ('artifacts/src/forensics_section.py', "f'recorded: {N(\"end_state_A\")}.</p>' if new and 'runc_topos' in f else", "f'recorded: {N(\"end_state_A\")}.</p>' if False else"),
    ('harness/intel/coherence.py', "            if not h.startswith(('/', '.')) and not exists(h):", "            if False:"),
    ('harness/gen_index.py', "    return 'PASS' if r == 'PASS' else 'PAUSED' if r.startswith('PAUSED') else 'FAIL'", "    return 'PASS' if r == 'PASS' else 'FAIL'"),
    ('harness/gen_index.py', "    return f'{p}/{len(st) - k}' + (f' (+{k} PAUSED)' if k else '')", "    return f'{p}/{len(st)}'"),
    ('harness/gen_deroarch.py', "            (str(cs.count('PARTLY-CONFIRMED')), 'partly confirmed'), (str(cs.count('REFUTED')), 'refuted here'),", "            (str(cs.count('PARTLY-CONFIRMED') - 1), 'partly confirmed'), (str(cs.count('REFUTED') + 1), 'refuted here'),"),
    ('harness/gen_deroarch.py', "    return f'The headline (C1) is {w(\"C1\")}; the stated *mechanism* (C2) is {w(\"C2\")}", "    return f'The headline (C1) is {w(\"C1\")}; the stated *mechanism* (C2) is refuted"),
    ('harness/intel/disclosure_track.py', "    if cur in ri and nm in ri and ri[cur] < ri[nm]:", "    if False:"),
    ('harness/intel/disclosure_track.py', "    if nm not in ri:\n        return [", "    if False:\n        return ["),
    ('harness/intel/disclosure_track.py', "        if cls in ('implemented', 'closed') and not impl:", "        if False:"),
    ('harness/intel/disclosure_track.py', "        if impl and cls not in ('implemented', 'closed'):", "        if False:"),
    ('harness/kit/roundlists.py', "            if evolution_label(rid) not in L['disclosure']:", "            if False:"),
    ('harness/intel/derofdn_watch.py', "    changed = bool(moved or gone or new_heads or new_tags or moved_tags)", "    changed = bool(gone or new_heads)"),
    ('harness/intel/derofdn_watch.py', "            if kind == 'tags' and not peeled and name in out['tags']:", "            if False:"),
]


def make_base():
    b = Path(tempfile.mkdtemp(prefix='lp30base_'))
    for d in DIRS:
        shutil.copytree(ROOT / d, b / d, ignore=shutil.ignore_patterns('__pycache__'))
    (b / 'harness/forensics').mkdir(parents=True, exist_ok=True)
    for p in (ROOT / 'harness/forensics').glob('*.py'):     # forensics_section loads bounds.py / facts.py beside its ROOT
        shutil.copy2(p, b / 'harness/forensics' / p.name)
    for f in FILES:
        (b / f).parent.mkdir(parents=True, exist_ok=True)
        if (ROOT / f).exists():          # an old tree without the r30 files must FAIL its KATs, not crash the runner
            shutil.copy2(ROOT / f, b / f)
    return b


def main():
    base = make_base()
    try:
        f = kats(base)
        try:
            f += committed()
        except Exception as e:                                       # noqa: BLE001
            f.append(f'committed crashed: {type(e).__name__}: {e}')
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print('LP1-LP15 + committed:', 'PASS' if not f else 'FAIL\n  ' + '\n  '.join(f))
    if f:
        return 3
    rc, caught, n = 0, 0, 0
    for i, (fn, old, new) in enumerate(MUTATIONS, 1):
        n += 1
        tmp = make_base()
        try:
            src = (tmp / fn).read_text()
            if src.count(old) != 1:
                print(f'mutation {i} INVALID: text found {src.count(old)} times in {fn}'); rc = 4; continue
            (tmp / fn).write_text(src.replace(old, new, 1))
            mf = kats(tmp)
            if mf and not all('crashed' in x for x in mf):
                caught += 1
                print(f'mutation {i} CAUGHT ({fn}): {mf[0][:110]}')
            else:
                print(f'mutation {i} NOT CAUGHT ({fn}): {old.strip()[:80]}' + (f' [only crashes: {mf[0][:80]}]' if mf else '')); rc = 4
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f'r30 ledger-pages KATs: 15/15 ok · mutations caught {caught}/{n}')
    return rc


if __name__ == '__main__':
    sys.exit(main())
