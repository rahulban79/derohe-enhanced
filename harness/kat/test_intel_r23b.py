#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the R23b harness layer (no network, no live file written, no go test).

  IK47 soundness gate G22 (harness/soundness.py; r23b merge: a unit must be covered WHOLE by one entry, stray text
       and headings are units, a test is fingerprinted with its package's sources): a page whose every claim unit is registered, whose code claims are
       backed by a PASS on unchanged files, a re-read anchor, a recomputation and a live check PASSES; each of these
       FAILS it: a sentence added to the page with no entry, a registry entry the page no longer carries, a test that
       FAILED, a PASS whose watch file changed since (fingerprint), a watch file the record never fingerprinted, an
       anchor whose line moved, a derivation that disagrees, a live auditor with an alert, an unreachable node, a code
       claim with no backing, a non-code entry with no source. The registry's test list is what S3s runs.
  IK48 miner_runs idle gaps: the gap between two runs is (next start - (start + uptime)); priced at the neighbours'
       own expected share rate x paid fraction x per-miniblock reward; an ended newest run leaves an OPEN gap to now, a
       live checkpoint does not, a stale one (> 180 s) does; a restart < 5 s is not idle; a miner start-up line inside a
       gap is counted. G21 recomputes the idle ledger and FAILS a tampered DERO, a tampered paid-share count, a gap
       holding a start-up line, and a missing idle ledger.
  IK49 fix_build_verify R23b: skip_only finds the tests that only SKIPPED under -race (S3a re-runs them without it);
       full_record is a full-mode run that reached S4b; soundness_record marks a test with no declaring file MISSING and
       fingerprints its file plus the claim's watch files. run_gates.pipeline_for_ab judges A/Bs from the full record
       when the newest is project-only, and G20 FAILS when no record holds an A/B stage.
  IK50 run_gates G17: the binding label must equal the shared classifier on its own fractions (co-bound at GPU 0.914 /
       backlog 0.91 though the backlog-only regime says cpu-sort-bound); a GPU duty within 0.05 of 0.90 is named marginal.
  IK51 mine_localdiff: hunk_segments splits at each added func and numbers each added line by its new-file line;
       cite_segment prefers the segment's func declaration; near_in resolves a repeated line to the copy inside its own
       segment, never the file's first copy (39 of 2,924 citations landed outside their segment before).

  python3 -I harness/kat/test_intel_r23b.py            # KATs, then each mutation on a temp copy must flip its KAT
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught.
"""
import hashlib, importlib.util, json, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
MODS = {'sound': 'soundness.py', 'runs': 'intel/miner_runs.py', 'fbv': 'pipeline/fix_build_verify.py',
        'gates': 'run_gates.py', 'ld': 'miners/mine_localdiff.py'}
EXTRA = ['gen_deroarch.py', 'prep_corpus.py', 'consensus_guard.py', 'miners/minelib.py', 'intel/miner_intel.py',
         'intel/contention.py']
EXTRA_DIRS = ['kit']


def load(base, name):
    for m in ('gen_deroarch', 'prep_corpus', 'assetkit', 'textkit', 'connectorkit', 'diagramkit', 'minelib'):
        sys.modules.pop(m, None)
    extra = {'gates': [str(base / 'kit'), str(base)], 'ld': [str(base / 'miners')]}.get(name, [])
    sys.path[:0] = extra
    try:
        spec = importlib.util.spec_from_file_location(f'{name}_{id(base)}_{len(sys.modules)}', base / MODS[name])
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    finally:
        del sys.path[:len(extra)]
    return m


# ───────────────────────────── IK47 ─────────────────────────────
PAGE = ('<html><body><p class="eyebrow">node r23</p><section><p>The bug is real in code.</p>'
        '<div class="fig"><span class="v">0</span><span class="k">alerts</span></div>'
        '<ul><li>HF3 keys the validity cache on the full transaction bytes.</li><li>The auditor has 0 alerts today.</li>'
        '<li>Quoted from the Foundation.</li></ul>'
        '<div class="code">// a.go\n12  if x { // the gate</div></section></body></html>')


def sound_fixture(tmp):
    root = tmp / 'root'
    (root / 'pkg').mkdir(parents=True, exist_ok=True)
    src = ''.join(f'line {i}\n' for i in range(1, 12)) + '\tif tx.Height >= HF3 {\n'
    (root / 'pkg/a.go').write_text(src)
    (root / 'pkg/a_test.go').write_text('package pkg\nfunc TestReplay(t *testing.T) {}\n')
    (root / 'pkg/b.go').write_text('package pkg\n// code under test that no watch list names\n')
    (root / 'blockchain').mkdir(exist_ok=True)
    (root / 'blockchain/hardfork_fixes.go').write_text(
        '\t// duplicates\n' + ''.join(f'\t"{i:064x}": {{Bl_Tips: "{i:064x}", Height: {7415466 + i}, Tx_Parity: false}},\n' for i in range(3))
        + '\t// false parity\n' + f'\t"{9:064x}": {{Bl_Tips: "{9:064x}", Height: 7497942, Tx_Parity: true}},\n')
    reg = {'page': 'page.html', 'claims': [
        {'id': 'eyebrow', 'kind': 'record', 'match': 'node r23', 'source': 'version'},
        {'id': 'intro', 'kind': 'scope', 'match': 'The bug is real in code.', 'source': 'framing'},
        {'id': 'fig', 'kind': 'live-figure', 'match': '0 alerts', 'exact': True, 'source': 'RPC'},
        {'id': 'cache', 'kind': 'code', 'match': 'HF3 keys the validity cache on the full transaction bytes.',
         'backing': [{'type': 'anchor', 'file': 'pkg/a.go', 'line': 12, 'quote': 'if tx.Height >= HF3 {'},
                     {'type': 'test', 'pkg': './pkg/', 'name': 'TestReplay', 'race': False},
                     {'type': 'derive', 'name': 'hf3_split', 'want': {'dup': 3, 'parity': 1, 'total': 4}}],
         'watch': ['pkg/a.go']},
        {'id': 'auditor', 'kind': 'code', 'match': 'The auditor has 0 alerts today.', 'backing': [{'type': 'live', 'name': 'emission_audit'}]},
        {'id': 'foundation', 'kind': 'external', 'match': 'Quoted from the Foundation', 'source': 'press'},
        {'id': 'code-file', 'kind': 'scope', 'match': '// a.go', 'source': 'label'},
        {'id': 'code-12', 'kind': 'code', 'match': '12 if x { // the gate', 'backing': [{'type': 'anchor', 'file': 'pkg/a.go', 'line': 12, 'quote': 'if tx.Height'}]},
        {'id': 'offpage', 'kind': 'code', 'match': 'never on the page', 'on_page': False,
         'backing': [{'type': 'test', 'pkg': './pkg/', 'name': 'TestReplay', 'race': False}], 'watch': ['pkg/a.go']}]}
    sha = lambda p: hashlib.sha256((root / p).read_bytes()).hexdigest()
    last = {'run': 'T1', 'tests': {'./pkg/::TestReplay': {'status': 'PASS', 'race': False, 'file': 'pkg/a_test.go',
                                                          'fingerprint': {'pkg/a_test.go': sha('pkg/a_test.go'), 'pkg/a.go': sha('pkg/a.go'),
                                                                          'pkg/b.go': sha('pkg/b.go')}}}}
    return root, reg, last


def ik47(base, tmp):
    S = load(base, 'sound')
    root, reg, last = sound_fixture(tmp)
    good = lambda m: {'enabled': True, 'status': 'OK', 'alerts': 0, 'emission_consistent': True, 'audited': 10}
    ev = lambda page=PAGE, r=reg, l=last, get=good: S.evaluate(page, r, l, root=root, live=True, get=get)
    base_r = ev()
    cp = lambda: json.loads(json.dumps(reg))
    r_extra = ev(page=PAGE.replace('</ul>', '<li>A new unbacked claim.</li></ul>'))
    r_stale = ev(page=PAGE.replace('<li>Quoted from the Foundation.</li>', ''))
    lf = json.loads(json.dumps(last)); lf['tests']['./pkg/::TestReplay']['status'] = 'FAIL'
    r_fail = ev(l=lf)
    (root / 'pkg/a.go').write_text((root / 'pkg/a.go').read_text() + '// edited\n')
    r_changed = ev()
    root2, reg2, last2 = sound_fixture(tmp / 'b')
    rw = json.loads(json.dumps(reg2)); rw['claims'][3]['watch'] = ['pkg/a.go', 'pkg/other.go']
    r_unfp = S.evaluate(PAGE, rw, last2, root=root2, live=True, get=good)
    ra = json.loads(json.dumps(reg2)); ra['claims'][7]['backing'][0]['line'] = 11
    r_anchor = S.evaluate(PAGE, ra, last2, root=root2, live=True, get=good)
    rd = json.loads(json.dumps(reg2)); rd['claims'][3]['backing'][2]['want']['dup'] = 67
    r_derive = S.evaluate(PAGE, rd, last2, root=root2, live=True, get=good)
    r_alert = S.evaluate(PAGE, reg2, last2, root=root2, live=True, get=lambda m: {**good(m), 'alerts': 1})

    def down(m):
        raise OSError('refused')
    r_down = S.evaluate(PAGE, reg2, last2, root=root2, live=True, get=down)
    rn = json.loads(json.dumps(reg2)); rn['claims'][7]['backing'] = []
    r_nob = S.evaluate(PAGE, rn, last2, root=root2, live=True, get=good)
    rs = json.loads(json.dumps(reg2)); del rs['claims'][5]['source']
    r_nos = S.evaluate(PAGE, rs, last2, root=root2, live=True, get=good)
    r_good2 = S.evaluate(PAGE, reg2, last2, root=root2, live=True, get=good)
    # r23b merge (H23b-1 fixes): a sentence appended to a registered unit, text outside every unit tag (a heading, a
    # bare div), and a record that never fingerprinted the package's own sources all FAIL
    r_append = S.evaluate(PAGE.replace('The bug is real in code.', 'The bug is real in code. Inflation is impossible.'),
                          reg2, last2, root=root2, live=True, get=good)
    r_stray = S.evaluate(PAGE.replace('</section>', '<div>Inflation is <span>impossible</span>.</div></section>'),
                         reg2, last2, root=root2, live=True, get=good)
    r_head = S.evaluate(PAGE.replace('</section>', '<h2>Fixed in this build</h2></section>'), reg2, last2, root=root2,
                        live=True, get=good)
    lp = json.loads(json.dumps(last2)); del lp['tests']['./pkg/::TestReplay']['fingerprint']['pkg/b.go']
    r_pkgsrc = S.evaluate(PAGE, reg2, lp, root=root2, live=True, get=good)
    wf = S.watch_files(reg2, './pkg/', 'TestReplay', root=root2)
    tests = S.soundness_tests(reg2)
    units = S.page_units(PAGE)
    res = {'good': base_r['ok'] and r_good2['ok'], 'extra': r_extra['ok'], 'stale': r_stale['ok'], 'fail': r_fail['ok'],
           'changed': r_changed['ok'], 'unfp': r_unfp['ok'], 'anchor': r_anchor['ok'], 'derive': r_derive['ok'],
           'alert': r_alert['ok'], 'down': r_down['ok'], 'nobacking': r_nob['ok'], 'nosource': r_nos['ok'],
           'append': r_append['ok'], 'stray': r_stray['ok'], 'head': r_head['ok'], 'pkgsrc': r_pkgsrc['ok'], 'wf_pkg': 'pkg/b.go' in wf}
    ok = (res == {'good': True, 'extra': False, 'stale': False, 'fail': False, 'changed': False, 'unfp': False,
                  'anchor': False, 'derive': False, 'alert': False, 'down': False, 'nobacking': False, 'nosource': False,
                  'append': False, 'stray': False, 'head': False, 'pkgsrc': False, 'wf_pkg': True}
          and tests == {'./pkg/': [('TestReplay', False)]} and ('code', '12 if x { // the gate') in units
          and base_r['off_page'] == ['offpage'] and len(units) == 8)
    return ok, f'{res} tests {tests} units {len(units)} why {base_r["why"][:2]}'


# ───────────────────────────── IK48 ─────────────────────────────
def ik48(base, tmp):
    R, G = load(base, 'runs'), load(base, 'gates')
    t0 = 1_800_000_000
    iso = lambda s: R.datetime.datetime.fromtimestamp(t0 + s).astimezone().isoformat(timespec='seconds')
    a = {'run_id': 'a', 'start': iso(0), 'last': iso(600), 'uptime_s': 600, 'end': 'console exit', 'expected_shares': 10.0}
    b = {'run_id': 'b', 'start': iso(3600), 'last': iso(4200), 'uptime_s': 600, 'end': 'console exit', 'expected_shares': 20.0}
    c = {'run_id': 'c', 'start': iso(4203), 'last': iso(4800), 'uptime_s': 597, 'end': 'console exit', 'expected_shares': 9.95}
    gaps, tot = R.idle_gaps([b, a, c], t0 + 6000, 3075, 0.9, [t0 + 1000.0])
    g1 = gaps[0]
    # neighbours a,b: 30 shares / 1200 s = 0.025/s; gap 3000 s -> 75 shares, 67.5 paid, 2.07563 DERO
    want1 = (g1['idle_s'] == 3000 and g1['shares_per_min'] == 1.5 and g1['forgone_shares'] == 75.0
             and g1['forgone_paid_shares'] == 67.5 and g1['forgone_DERO'] == 2.07563 and g1['log_starts_inside'] == 1)
    # b -> c is a 3 s restart (not idle); c ended -> open gap 4800 -> 6000 at c's own rate
    op = gaps[-1]
    want2 = len(gaps) == 2 and op['open'] and op['idle_s'] == 1200 and tot['open_now'] and tot['idle_s'] == 4200
    run = {**c, 'end': 'running', 'last': iso(5990)}
    g_live, t_live = R.idle_gaps([a, b, run], t0 + 6000, 3075, 0.9)
    g_stale, t_stale = R.idle_gaps([a, b, {**run, 'last': iso(5000)}], t0 + 6000, 3075, 0.9)
    want3 = not t_live['open_now'] and len(g_live) == 1 and t_stale['open_now'] and g_stale[-1]['idle_s'] == 1000
    gaps2, tot2 = R.idle_gaps([a, b], t0 + 4200, 3075, 0.9, [])
    mr = lambda gs, tt: {'idle': {'gaps': gs, 'total': tt}}
    ok_g = G.g21_idle(mr(gaps2, tot2), 3075)[0]
    td = json.loads(json.dumps(gaps2)); td[0]['forgone_DERO'] = 9.9
    tp = json.loads(json.dumps(gaps2)); tp[0]['forgone_paid_shares'] = 75.0
    ti = json.loads(json.dumps(gaps2)); ti[0]['log_starts_inside'] = 1
    bad = (G.g21_idle(mr(td, tot2), 3075)[0], G.g21_idle(mr(tp, tot2), 3075)[0], G.g21_idle(mr(ti, tot2), 3075)[0],
           G.g21_idle({}, 3075)[0])
    ok = want1 and want2 and want3 and ok_g and bad == (False, False, False, False)
    return ok, f'g1 {g1} open {op["idle_s"]} live {t_live["open_now"]} stale {t_stale["open_now"]} g21 {ok_g} bad {bad}'


# ───────────────────────────── IK49 ─────────────────────────────
def ik49(base, tmp):
    F, G, S = load(base, 'fbv'), load(base, 'gates'), load(base, 'sound')
    res = {'TestA': {'pass': 0, 'fail': 0, 'skip': 3}, 'TestB': {'pass': 3, 'fail': 0}, 'TestC': {'pass': 0, 'fail': 0, 'skip': 1},
           'TestD': {'pass': 2, 'fail': 1, 'skip': 0}}
    so = F.skip_only(res, ['TestA', 'TestB', 'TestD', 'TestZ'])
    fr = (F.full_record({'mode': 'full', 'stages': {'minerbench': {'status': 'PASS'}}}),
          F.full_record({'mode': 'project-only', 'stages': {'guard': {}, 'project': {}}}),
          F.full_record({'stages': {'guard': {}}}))
    reg = {'claims': [{'id': 'x', 'kind': 'code', 'match': 'm', 'watch': ['w.go'],
                       'backing': [{'type': 'test', 'pkg': './nopkg_r23b/', 'name': 'TestNowhere'}]}]}
    rec = F.soundness_record({('./nopkg_r23b/', 'TestNowhere'): ('PASS', True)}, reg, S, sha=lambda p: 'h')
    r = rec['./nopkg_r23b/::TestNowhere']
    full = {'run': 'F', 'mode': 'full', 'stages': {'minerbench': {'status': 'PASS', 'contention': {'contended': False}}}}
    proj = {'run': 'P', 'mode': 'project-only', 'stages': {'guard': {}, 'project': {}}}
    pa = (G.pipeline_for_ab(proj, full)[0], G.pipeline_for_ab(full, None)[0], G.pipeline_for_ab(proj, None)[0])
    mt = {'contention': {'contended': False, 'regression_claims': 'allowed'}, 'alerts': []}
    g20 = (G.g20_contention(mt, None, None, require_ab=True)[0], G.g20_contention(mt, None, full, require_ab=True)[0],
           G.g20_contention(mt, None, None)[0])
    ok = (so == ['TestA'] and fr == (True, False, False) and r['status'] == 'MISSING' and r['fingerprint'] == {'w.go': 'h'}
          and pa[0] is full and pa[1] is full and pa[2] is None and g20 == (False, True, True))
    return ok, f'skip_only {so} full {fr} rec {r} ab {[x and x["run"] for x in pa]} g20 {g20}'


# ───────────────────────────── IK50 ─────────────────────────────
def ik50(base, tmp):
    G = load(base, 'gates')
    cur = lambda b, lab: {'split': {'regime': {'gpu_busy_fraction': b, 'cpu_backlog_fraction': 0.91, 'ring_full_fraction': 0.997,
                                               'regime': 'cpu-sort-bound', 'binding': lab}}}
    q = G.g17_binding(cur(0.914, 'co-bound'))
    wrong = G.g17_binding(cur(0.914, 'cpu-sort-bound'))
    far = G.g17_binding(cur(0.70, 'cpu-sort-bound'))
    none = G.g17_binding({'split': {'regime': {'regime': 'cpu-sort-bound'}}})
    ok = q[0] and 'marginal' in q[1] and not wrong[0] and far[0] and 'marginal' not in far[1] and none[0]
    return ok, f'quiet {q} wrong {wrong[0]} far {far} none {none[0]}'


# ───────────────────────────── IK51 ─────────────────────────────
def ik51(base, tmp):
    L = load(base, 'ld')
    diff = ('@@ -10,0 +20,3 @@ func old() {\n+\tcpu_throttle(&throttle_start)\n+\t// doc comment of the next func is long\n'
            '+func next_one() {\n@@ -40,0 +60,2 @@\n+func short() {\n+\treturn a_much_longer_line_than_the_declaration\n')
    segs = L.hunk_segments(diff)
    want_segs = [[(20, 'cpu_throttle(&throttle_start)'), (21, '// doc comment of the next func is long')],
                 [(22, 'func next_one() {')], [(60, 'func short() {'), (61, 'return a_much_longer_line_than_the_declaration')]]
    f = tmp / 'dup.go'
    body = ['x'] * 70
    body[4] = '\tcpu_throttle(&throttle_start)'          # line 5: the file's FIRST copy
    body[19] = '\tcpu_throttle(&throttle_start)'         # line 20: the segment's own copy
    body[20], body[21] = '\t// doc comment of the next func is long', 'func next_one() {'
    body[59], body[60] = 'func short() {', '\treturn a_much_longer_line_than_the_declaration'
    f.write_text('\n'.join(body) + '\n')
    near = L.near_in(str(f))
    longq = lambda s: len(L.M.norm(s)) >= L.M.MIN_Q
    seg_dup = [(20, 'cpu_throttle(&throttle_start)')]
    c_dup = L.cite_segment(seg_dup, near, longq)
    c_decl = L.cite_segment(segs[2], near, longq)
    ok = segs == want_segs and c_dup and c_dup['line'] == 20 and c_decl and c_decl['line'] == 60
    return ok, f'segs {segs == want_segs} dup {c_dup and c_dup["line"]} decl {c_decl and c_decl["line"]}'


KATS = [('IK47', ik47), ('IK48', ik48), ('IK49', ik49), ('IK50', ik50), ('IK51', ik51)]

MUTATIONS = [
    ('IK47', 'sound', "        if not m:\n            unreg.append(f'{kind}: {u[:90]}')", "        if False:\n            unreg.append(f'{kind}: {u[:90]}')",
     'a sentence added to the page without a registry entry passes'),
    ('IK47', 'sound', "    stale = [c['id'] for c in claims if c.get('on_page', True) and not hit[c['id']]]", "    stale = []",
     'a registry entry the page no longer carries passes'),
    ('IK47', 'sound', "        if rec.get('status') != 'PASS':", "        if False:", 'a FAILED soundness test backs a claim'),
    ('IK47', 'sound', "        changed = [f for f, h in (rec.get('fingerprint') or {}).items() if sha(Path(root) / f) != h]",
     "        changed = []", 'a PASS on other (since changed) code backs a claim'),
    ('IK47', 'sound', "        missing = sorted(want - set(rec.get('fingerprint') or {}))", "        missing = []",
     'a watch file the record never fingerprinted is accepted'),
    ('IK47', 'sound', "        if not (1 <= i <= len(lines)) or norm(b['quote']) not in norm(lines[i - 1]):", "        if False:",
     'a moved anchor passes'),
    ('IK47', 'sound', "        return bool(cmp(d, b.get('want') or {})), f\"{b['name']} = {d} (page {b.get('want')})\"",
     "        return True, f\"{b['name']} = {d} (page {b.get('want')})\"", 'a recomputation that disagrees with the page passes'),
    ('IK47', 'sound', "    ok = (r.get('enabled') is True and r.get('status') == 'OK' and r.get('alerts') == 0",
     "    ok = (r.get('enabled') is True and r.get('status') == 'OK'", 'an emission alert passes the live check'),
    ('IK47', 'sound', "            return False, f\"{b.get('name')}: node not reachable ({type(e).__name__})\"",
     "            return True, f\"{b.get('name')}: node not reachable ({type(e).__name__})\"", 'an unreachable node passes the live check'),
    ('IK47', 'sound', "            if not c.get('backing'):\n                res.append((False, 'a code claim with no backing'))", "            pass",
     'a code claim with no backing passes'),
    ('IK47', 'sound', "        elif not c.get('source'):", "        elif False:", 'a non-code entry without a source passes'),
    ('IK47', 'sound', "        elif uncovered(u, byid[m[0]]['match']):", "        elif False:",
     'a sentence appended to a registered unit passes on the old fragment (r23b merge)'),
    ('IK47', 'sound', "            (self.stack[-1][3] if self.stack else self.top_stray).append(d + ' ')", "            pass",
     'text outside every unit tag (a bare div or span) is never a unit (r23b merge)'),
    ('IK47', 'sound', "    fs = set(pkg_sources(pkg, root))", "    fs = set()",
     "a test's own package sources are not fingerprinted (r23b merge)"),
    ('IK47', 'sound', "        want = set(entry.get('watch') or []) | set(pkg_sources(b['pkg'], root))",
     "        want = set(entry.get('watch') or [])", 'a record without the package sources is accepted (r23b merge)'),
    ('IK48', 'runs', "        e = ts(b['start'])\n        if e - s >= IDLE_MIN_S:", "        e = ts(b['start'])\n        if e - s >= 1e9:",
     'gaps between runs are never counted'),
    ('IK48', 'runs', "        r = rate(a, b) if b is not None else rate(a)", "        r = rate(a)", 'a gap is priced at one neighbour only'),
    ('IK48', 'runs', "        if z.get('end') != 'running' or now - last > CHECKPOINT_STALE_S:", "        if z.get('end') != 'running':",
     'a dead run whose checkpoint went stale counts as running (no open gap)'),
    ('IK48', 'runs', "                sum(1 for x in log_starts if s + LOG_SLACK_S < x < e - LOG_SLACK_S)}", "                0}",
     'a miner start inside a gap is not counted'),
    ('IK48', 'gates', "        if g.get('log_starts_inside'):", "        if False:", 'G21 accepts a gap that holds an unledgered run'),
    ('IK48', 'gates', "        if g.get('forgone_paid_shares') is not None and pm is not None and abs(g['forgone_paid_shares'] * pm / 1e5 - (g.get('forgone_DERO') or 0)) > 1e-4:",
     "        if False:", 'G21 accepts a forgone DERO its own counts do not give'),
    ('IK48', 'gates', "        return False, 'no idle-gap ledger in the snapshot'", "        return True, 'no idle-gap ledger in the snapshot'",
     'G21 passes a snapshot without the idle ledger'),
    ('IK49', 'fbv', "    return [n for n in names if n in res and res[n].get('skip') and not res[n].get('pass') and not res[n].get('fail')]",
     "    return []", 'a test that only skipped under -race is never re-run'),
    ('IK49', 'fbv', "        out[f'{pkg}::{name}'] = {'status': status if f else 'MISSING',", "        out[f'{pkg}::{name}'] = {'status': status,",
     'a test with no declaring file backs a claim'),
    ('IK49', 'fbv', "    return summary.get('mode', 'full') == 'full' and 'minerbench' in (summary.get('stages') or {})",
     "    return True", 'a project-only run overwrites the full A/B record'),
    ('IK49', 'gates', "    if has(full):", "    if False:", 'G20 reads only the newest (project-only) record'),
    ('IK49', 'gates', "    if require_ab and not pipe:", "    if False:", 'G20 passes with no A/B record at all'),
    ('IK50', 'gates', "    if want != rg.get('binding'):", "    if False:", 'G17 accepts a binding label its own fractions contradict'),
    ('IK50', 'gates', "    near = abs(rg['gpu_busy_fraction'] - BIND_GPU_BUSY) <= BIND_MARGIN", "    near = False",
     'a marginal binding label is not named'),
    ('IK51', 'ld', "            if l.startswith('+func ') and cur:", "            if False and cur:", 'hunks are not split at added funcs'),
    ('IK51', 'ld', "    first = [seg[0]] if seg and seg[0][1].startswith('func ') else []", "    first = []",
     'a func segment cites its longest line instead of its declaration'),
    ('IK51', 'ld', "    return lambda cand, ln: M.anchor_near(f, cand, ln, window=SEG_WINDOW)",
     "    return lambda cand, ln: M.anchor(f, cand, full_line=True)", 'a repeated line is cited at its first copy in the file'),
]


def copy_tree():
    d = Path(tempfile.mkdtemp(prefix='r23bkat-'))
    for rel in list(MODS.values()) + EXTRA:
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HARNESS / rel, d / rel)
    for rel in EXTRA_DIRS:
        shutil.copytree(HARNESS / rel, d / rel, ignore=shutil.ignore_patterns('__pycache__', '.cache'))
    return d


def main():
    fails = 0
    base = copy_tree()
    for name, fn in KATS:
        tmp = Path(tempfile.mkdtemp(prefix='r23bfx-'))
        try:
            ok, det = fn(base, tmp)
        except Exception as e:                                    # noqa: BLE001
            ok, det = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:400]}")
        shutil.rmtree(tmp, ignore_errors=True)
    shutil.rmtree(base, ignore_errors=True)
    missed = 0
    byname = dict(KATS)
    for kat, mod, find, repl, why in MUTATIONS:
        d = copy_tree()
        p = d / MODS[mod]
        text = p.read_text()
        if text.count(find) != 1:
            print(f'  ??      {kat}: {why} — find text occurs {text.count(find)} times')
            missed += 1
            shutil.rmtree(d, ignore_errors=True)
            continue
        p.write_text(text.replace(find, repl))
        t2 = Path(tempfile.mkdtemp(prefix='r23bfx-m-'))
        try:
            ok2 = byname[kat](d, t2)[0]
        except Exception:                                          # noqa: BLE001 — a crash is a detection
            ok2 = False
        print(f"  {'proved ' if not ok2 else 'MISSED '} {kat}: {why}")
        missed += ok2
        shutil.rmtree(d, ignore_errors=True)
        shutil.rmtree(t2, ignore_errors=True)
    print(f'\nR23b harness KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
