#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the R28 backlog-sweep fixes (dero-rft §0.6, §7; the R28 Part A sweep gaps).

Every KAT runs on an APFS clone of harness/ (the mutant's clone under a mutation) with forged inputs written into the
clone: a forged artifacts/dero-rft.md, harness/round.json, closure record, miner run ledger rows and a forged git repo.

  BT1 row cells: a §7 row whose status text holds a bare pipe (R26 B105 'node|network') keeps that text in its status
      cell, in backlog_truth.row_cells/backlog_rows AND in coherence.rft_backlog (both took the last fragment, so B105
      read 'network; a regression ...' = open while the row is FIXED); an escaped pipe is not a split; lead classes.
  BT2 rows R1-R3: a lead IMPLEMENTED whose cell states **CONFIRMED is stale (R1); BACKEND READY with PAGES IMPLEMENTED
      is stale (R1); an IMPLEMENTED row named by a §13 '**CONFIRMED live:**' list is stale (R2) while a PARTIAL row the
      same list names is not (B36: a partial confirmation); a CLOSED row is clean; PAUSED (miner) without §0.3 (R3).
  BT3 header H1-H6: 'Round N is measured' vs the newest measured round, 'the next round to run is **Round N**' across
      the blockquote's '> ' line break, How to start / §1 / §8 headings vs the current (opened) round, §7 'through the
      RN merge' vs the newest merge; a coherent header gives 0 drifts.
  BT4 closures C1-C5: a CLOSED closure without records, a record under <scratch>, a missing record, a premise that
      fails (repo_contains), a §7 lead whose class differs from new_status, a decision request with one option, a
      consensus NO-GO not REPORT-ONLY, a via_rows row still open, a dedup_into row missing; a good record is clean; on
      the real tree every R28 closure record path exists and every premise holds (C1, C2).
  BT5 G25 hook: coherence.CHECKS names 'rows' and coherence.run(skip all but rows) returns the backlog_truth drifts of
      the forged rft (a stale header) and 0 on a coherent one.
  BT6 B50 (H24-5) miner_runs.idle_gaps: with the miner track paused the OPEN trailing gap is paused_s (idle_s 0, no
      forgone shares / DERO), uptime is over span - paused, closed gaps are still priced, --paused-since splits the
      open gap (the part before it is priced idle), and the gap idle_s still sum to the total (G21's rule); with the
      track active the R23b ledger is unchanged; analyse() reads the registry's track.
  BT7 disclosure OK-AT-SEED (the R23 X-SUPPLY drift emission_audit.go:578 -> :580): in a forged git repo, an R1 anchor
      cited at the seed tree's line that has drifted at HEAD is OK-AT-SEED with seeded_at {rev, rounds: [R1]}, DRIFT
      without it or for a round outside seeded_at.rounds, and a MISSING quote stays MISSING.

Mutation independence (harness/kit/katmut.py): each mutation's reason starts with its defect id (r28 BT<n>).

  python3 -I harness/kat/test_backlog_truth_r28.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught by its own KAT, was INVALID, or coupled.
"""
import importlib.util, json, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent


def load(path, name):
    spec = importlib.util.spec_from_file_location(f'{name}_{abs(hash(str(path)))}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


HDR_OK = """# T

> **What this is.** x. **Round 2 is measured** (y); the next round to run is
> **Round 3** (in progress).

## How to start (Round 3; every round the same)

## 1. The prompt to paste (Round 3)

"""
SEC7 = """## 7. Consolidated OPEN backlog (through the R2 merge; deduplicated)

| # | Item | Dimension | Evidence anchor | Status |
|---|---|---|---|---|
| B1 | one | d | e | IMPLEMENTED (R2); later **CONFIRMED live** in R2 |
| B2 | two | d | e | BACKEND READY (R2): facts; PAGES IMPLEMENTED (R2) |
| B3 | three | d | e | IMPLEMENTED (R2, node-side) |
| B4 | four | d | e | PARTIAL: fields read, 24 h read pending |
| B5 | five | d | e | CLOSED (CONFIRMED live R2) |
| B6 | six | d | e | OPEN · PAUSED (miner): later |
| B7 | seven | d | e | OPEN · PAUSED (miner, §0.3) |
| B8 | eight | d | `x` | FIXED (R2): classes every metric node|network; a regression becomes medium |
| B9 | nine | d | e | OPEN (a\\|b) |

## 8. Round 3 dimension plan (x)

## 13. Update log — after measurement (round N)

| §12 claims CONFIRMED / REFUTED / PLAUSIBLE | **CONFIRMED live:** B3 counters; B4 payee fields. **Unit-proven, live pending-no-event:** B9 |
"""
REG = {'current': 'r3', 'rounds': [{'id': 'r1', 'status': 'measured', 'merge_commit': 'aaaaaaa'},
                                   {'id': 'r2', 'status': 'measured', 'merge_commit': 'bbbbbbb'},
                                   {'id': 'r3', 'status': 'in-progress', 'merge_commit': 'pending'}]}


def forge(root, hdr=HDR_OK, sec7=SEC7, reg=REG):
    (root / 'artifacts').mkdir(parents=True, exist_ok=True)
    (root / 'artifacts/dero-rft.md').write_text(hdr + sec7, encoding='utf-8')
    (root / 'harness/round.json').write_text(json.dumps(reg), encoding='utf-8')


def bt(P):
    return load(P['root'] / 'harness/intel/backlog_truth.py', 'backlog_truth')


def found(drifts, check, needle):
    return any(d['check'] == check and needle in (d['expected'] + ' ' + d['found'] + ' ' + d['source']) for d in drifts)


# ───────────────────────────── BT1 ─────────────────────────────
def kat_bt1(P):
    B = bt(P)
    C = load(P['root'] / 'harness/intel/coherence.py', 'coherence')
    row = '| B105 | t | h | `a` | FIXED (R26): classes every metric node|network; a regression on a network metric |'
    cells = B.row_cells(row)
    rows = B.backlog_rows(SEC7)
    cb = C.rft_backlog(SEC7)
    ok = (len(cells) == 5 and cells[4].startswith('FIXED') and 'network; a regression' in cells[4]
          and B.lead_class(rows['B8']['status']) == 'closed' and C.status_class(cb['B8'][1]) == 'closed'
          and rows['B9']['status'] == 'OPEN (a\\|b)' and len(B.row_cells('| B9 | a | b | c | OPEN (a\\|b) |')) == 5
          and B.lead_class('IMPLEMENTED (x)') == 'implemented' and B.lead_class('BACKEND READY (x)') == 'backend'
          and B.lead_class('REPORT-ONLY (consensus, upstream)') == 'closed' and B.lead_class('OPEN · PAUSED') == 'open'
          and B.lead_class('**CLOSED in r24**') == 'closed')
    return ok, f"cells {len(cells)} status {cells[-1][:40]!r}; coherence B8 {cb['B8'][1][:30]!r}"


# ───────────────────────────── BT2 ─────────────────────────────
def kat_bt2(P):
    root = P['root']
    forge(root)
    B = bt(P)
    r = B.run(root, skip=('header', 'closures', 'inventory'))
    d = r['drifts']
    want = (found(d, 'rows', 'B1 lead at least CONFIRMED') and found(d, 'rows', 'B2 lead at least PAGES IMPLEMENTED')
            and found(d, 'rows', 'B3 CLOSED-class (§13') and found(d, 'rows', 'B6 PAUSED row cites §0.3'))
    clean = not any(x in (dd['expected'] + dd['found']) for dd in d for x in ('B4 ', 'B5 ', 'B7 ', 'B8 ', 'B9 '))
    return want and clean and len(d) == 4, f"{len(d)} drifts: {[dd['expected'][:40] for dd in d]}"


# ───────────────────────────── BT3 ─────────────────────────────
def kat_bt3(P):
    root = P['root']
    B = bt(P)
    forge(root)
    good = B.run(root, skip=('rows', 'closures', 'inventory'))['drifts']
    bad_hdr = HDR_OK.replace('**Round 2 is measured**', '**Round 1 is measured**').replace('> **Round 3** (in', '> **Round 2** (in') \
        .replace('How to start (Round 3;', 'How to start (Round 2;').replace('prompt to paste (Round 3)', 'prompt to paste (Round 2)')
    forge(root, hdr=bad_hdr, sec7=SEC7.replace('## 8. Round 3 dimension', '## 8. Round 2 dimension').replace('through the R2 merge', 'through the R1 merge'))
    d = B.run(root, skip=('rows', 'closures', 'inventory'))['drifts']
    hs = [x['source'][-3:-1] for x in d]
    ok = not good and all(found(d, 'header', h) for h in ('(H1)', '(H2)', '(H3)', '(H4)', '(H5)', '(H6)')) and len(d) == 6
    return ok, f"good {len(good)}; bad {len(d)}: {hs}"


# ───────────────────────────── BT4 ─────────────────────────────
def kat_bt4(P):
    root = P['root']
    B = bt(P)
    forge(root)
    (root / 'harness/runtime').mkdir(parents=True, exist_ok=True)
    (root / 'harness/runtime/rec.txt').write_text('evidence line\n')
    cl = {'closures': [
        {'item': 'B5', 'new_status': 'CLOSED (x)', 'records': ['harness/runtime/rec.txt'],
         'premises': [{'kind': 'repo_contains', 'file': 'harness/runtime/rec.txt', 'quote': 'evidence line'}]},       # good
        {'item': 'B8', 'new_status': 'FIXED (x)', 'records': []},                                                       # C1 none
        {'item': 'L1', 'new_status': 'CLOSED (x)', 'records': [str(root / 'harness/runtime/rec.txt')]},                # C1 absolute
        {'item': 'L2', 'new_status': 'CLOSED (x)', 'records': ['harness/runtime/absent.txt']},                          # C1 missing
        {'item': 'L3', 'new_status': 'STANDING rule', 'records': ['harness/runtime/rec.txt'],
         'premises': [{'kind': 'repo_contains', 'file': 'harness/runtime/rec.txt', 'quote': 'not in the file'}]},      # C2
        {'item': 'B3', 'new_status': 'CLOSED (CONFIRMED)', 'records': ['harness/runtime/rec.txt']},                      # C3
        {'item': 'B7', 'closable_how': 'user-decision', 'new_status': 'OPEN · PAUSED (miner, §0.3)',
         'decision_request': {'question': 'resume?', 'options': ['yes'], 'evidence': ['e']}},                          # C4 options
        {'item': 'B9', 'closable_how': 'consensus-NO-GO', 'new_status': 'OPEN (upstream)'},                             # C4 NO-GO
        {'item': 'L4', 'new_status': 'CLOSED (via B6)', 'records': ['harness/runtime/rec.txt'], 'via_rows': ['B6']},    # C5 via
        {'item': 'L5', 'new_status': 'SUPERSEDED', 'records': ['harness/runtime/rec.txt'], 'dedup_into': ['B77']},     # C5 dedup
        {'item': 'L6', 'new_status': 'CLOSED (via B5)', 'records': ['harness/runtime/rec.txt'], 'via_rows': ['B5'],
         'dedup_into': ['B6']},                                                                                         # good
    ]}
    p = root / 'harness/loop/backlog_closures_r3.json'
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cl))
    d = B.run(root, skip=('rows', 'header', 'inventory'))['drifts']
    exp = ['B8: a CLOSED-class status names a record', 'L1: record /', 'L2: record harness/runtime/absent.txt',
           'L3: premise repo_contains', 'B3 closed (closure', 'B7: decision_request', 'B9: REPORT-ONLY', 'L4: §7 B6 closed-class',
           'L5: §7 row B77 exists']
    miss = [e for e in exp if not found(d, 'closures', e)]
    clean = not any(dd['expected'].startswith(('B5', 'L6')) for dd in d)    # (no exact count: BT1's split mutant adds a B8 C3)
    # the real tree: every R28 closure record exists and every premise holds (C1, C2)
    real = B.run(ROOT if P.get('real_root') is None else P['real_root'], skip=('rows', 'header', 'inventory'))['drifts']
    real12 = [x for x in real if x['source'] in ('C1', 'C2')]
    return not miss and clean and not real12, f"missing {miss}; {len(d)} drifts; real C1/C2 {real12[:2]}"


# ───────────────────────────── BT5 ─────────────────────────────
def kat_bt5(P):
    root = P['root']
    C = load(root / 'harness/intel/coherence.py', 'coherence')
    skip = tuple(x for x in C.CHECKS if x != 'rows')
    forge(root, hdr=HDR_OK.replace('How to start (Round 3;', 'How to start (Round 2;'))
    bad = C.run(root, skip=skip)
    forge(root)
    good = C.run(root, skip=skip)
    gd = [d for d in good['drifts'] if d['check'] == 'header']
    ok = 'rows' in C.CHECKS and found(bad['drifts'], 'header', '(H3)') and not gd and bad['facts'] > 0
    return ok, f"bad {len(bad['drifts'])} good header drifts {len(gd)} facts {bad['facts']}"


# ───────────────────────────── BT6 ─────────────────────────────
def kat_bt6(P):
    root = P['root']
    M = load(root / 'harness/intel/miner_runs.py', 'miner_runs')
    t0 = 1_700_000_000
    iso = lambda t: __import__('datetime').datetime.fromtimestamp(t).astimezone().isoformat(timespec='seconds')
    rows = [{'run_id': 'a', 'start': iso(t0), 'uptime_s': 3600, 'expected_shares': 60, 'end': 'console exit', 'last': iso(t0 + 3600)},
            {'run_id': 'b', 'start': iso(t0 + 7200), 'uptime_s': 3600, 'expected_shares': 60, 'end': 'console exit', 'last': iso(t0 + 10800)}]
    now = t0 + 10800 + 36000
    ga, ta = M.idle_gaps(rows, now, 3075, 0.9)
    gp, tp = M.idle_gaps(rows, now, 3075, 0.9, paused=True)
    gs, tsp = M.idle_gaps(rows, now, 3075, 0.9, paused=True, paused_since=t0 + 10800 + 6000)
    act = (len(ga) == 2 and ga[-1]['open'] and ga[-1]['idle_s'] == 36000 and ta['idle_s'] == 39600
           and ta['forgone_DERO'] is not None and ta['forgone_DERO'] > 0 and ta.get('paused_s', 0) == 0)
    pau = (len(gp) == 2 and gp[0]['idle_s'] == 3600 and gp[0]['forgone_shares'] == 60.0 and gp[-1].get('paused')
           and gp[-1]['idle_s'] == 0 and gp[-1]['paused_s'] == 36000 and gp[-1]['forgone_DERO'] is None
           and tp['idle_s'] == 3600 and tp['paused_s'] == 36000 and tp['forgone_shares'] == 60.0
           and tp['uptime_fraction'] == round(1 - 3600 / (46800 - 36000), 4)
           and sum(g['idle_s'] for g in gp) == tp['idle_s'])
    spl = (len(gs) == 3 and gs[1]['idle_s'] == 6000 and not gs[1]['open'] and gs[1]['forgone_shares'] == 100.0
           and gs[2]['paused_s'] == 30000 and tsp['idle_s'] == 9600 and sum(g['idle_s'] for g in gs) == tsp['idle_s'])
    # analyse() reads the registry of this harness: forge a paused one and a ledger
    d = Path(tempfile.mkdtemp(prefix='bt6_', dir=P['tmp']))
    (d / 'runs.jsonl').write_text(''.join(json.dumps({**r, 'kind': 'run', 'height': 7800000}) + '\n' for r in rows))
    M.reward_constants = lambda root=None: (8610000, 6300000, 10, {})   # the clone has no config/ or blockchain/
    (root / 'harness/round.json').write_text(json.dumps({'current': 'r3', 'rounds': [{'id': 'r3', 'status': 'in-progress', 'tracks': {'miner': 'paused', 'node': 'active'}}]}))
    rep_p = M.analyse(d / 'runs.jsonl', d / 'none.log', use_rpc=False, now=now)
    (root / 'harness/round.json').write_text(json.dumps({'current': 'r3', 'rounds': [{'id': 'r3', 'status': 'in-progress', 'tracks': {'miner': 'active', 'node': 'active'}}]}))
    rep_a = M.analyse(d / 'runs.jsonl', d / 'none.log', use_rpc=False, now=now)
    tp_, ta_ = ((rep_p.get('idle') or {}).get('total') or {}), ((rep_a.get('idle') or {}).get('total') or {})
    trk = (tp_.get('miner_track') == 'paused' and tp_.get('paused_s') == 36000 and ta_.get('miner_track') == 'active'
           and ta_.get('paused_s') == 0 and ta_.get('idle_s') == 39600)
    return act and pau and spl and trk, f"active {act} paused {pau} split {spl} track {trk} ({tp.get('uptime_fraction')})"


# ───────────────────────────── BT7 ─────────────────────────────
def git(d, *a):
    return subprocess.run(['git', '-C', str(d), *a], capture_output=True, text=True, check=True,
                          env={'GIT_AUTHOR_NAME': 'k', 'GIT_AUTHOR_EMAIL': 'k@example.invalid', 'GIT_COMMITTER_NAME': 'k',
                               'GIT_COMMITTER_EMAIL': 'k@example.invalid', 'PATH': '/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin',
                               'HOME': str(d)}).stdout.strip()


def kat_bt7(P):
    root = P['root']
    D = load(root / 'harness/intel/disclosure_track.py', 'disclosure_track')
    g = Path(tempfile.mkdtemp(prefix='bt7_', dir=P['tmp']))
    git(g, 'init', '-q')
    (g / 'src.go').write_text('a\nb\nr.Limit = "proves only that no plaintext value moved"\nc\n')
    git(g, 'add', 'src.go')
    git(g, 'commit', '-qm', 'seed')
    seed = git(g, 'rev-parse', '--short', 'HEAD')
    (g / 'src.go').write_text('a\nb\nx\ny\nr.Limit = "proves only that no plaintext value moved"\nc\n')
    git(g, 'commit', '-qam', 'later')
    anc = {'file': 'src.go', 'line': 3, 'quote': 'r.Limit = "proves only that no plaintext value moved"'}
    gone = {'file': 'src.go', 'line': 3, 'quote': 'a quote that is in no version of the file'}

    def track(seeded, rnd='R1', anchors=(anc,)):
        t = {'rounds': ['R1', 'R2'], 'current_round': 'R2',
             'claims': [{'id': 'C1', 'history': [{'round': rnd, 'verdict': 'CONFIRMED', 'state': 'open', 'why': 'w', 'anchors': list(anchors)}]}]}
        if seeded:
            t['seeded_at'] = {'rev': seed, 'rounds': ['R1'], 'why': 'kat'}
        return t

    def st(t):
        D._LC.clear()
        return D.evaluate(t, root=g)['anchor_status']
    a = st(track(True))
    b = st(track(False))
    c = st(track(True, rnd='R2'))
    e = st(track(True, anchors=(gone,)))
    ok = (a == {'OK-AT-SEED': 1} and b == {'DRIFT': 1} and c == {'DRIFT': 1} and e == {'MISSING': 1}
          and D.seed_of({'seeded_at': {'rev': 'zz', 'rounds': ['R1']}}) == (None, ()) and 'OK-AT-SEED' in D.ANCHOR_OK)
    return ok, f"seeded {a} unseeded {b} other-round {c} missing {e}"


# ───────────────────────────── BT8 ─────────────────────────────
def kat_bt8(P):
    """r28 Part D (B174): after an implementation §1 names the NEXT round (coherence's rule); H4 agrees with it."""
    root = P['root']
    B = bt(P)
    reg = {'current': 'r3', 'rounds': [{'id': 'r1', 'status': 'measured', 'merge_commit': 'aaaaaaa'},
                                       {'id': 'r2', 'status': 'measured', 'merge_commit': 'bbbbbbb'},
                                       {'id': 'r3', 'status': 'implemented', 'merge_commit': 'ccccccc'},
                                       {'id': 'r4', 'status': 'planned', 'merge_commit': 'pending'}]}
    sec7 = SEC7.replace('through the R2 merge', 'through the R3 merge')
    forge(root, hdr=HDR_OK.replace('prompt to paste (Round 3)', 'prompt to paste (Round 4)'), sec7=sec7, reg=reg)
    good = [d for d in B.run(root, skip=('rows', 'closures', 'inventory'))['drifts'] if '(H4)' in d['source']]
    forge(root, sec7=sec7, reg=reg)
    bad = [d for d in B.run(root, skip=('rows', 'closures', 'inventory'))['drifts'] if '(H4)' in d['source']]
    reg_ip = {**reg, 'rounds': reg['rounds'][:2] + [{**reg['rounds'][2], 'status': 'in-progress'}] + reg['rounds'][3:]}
    forge(root, sec7=sec7, reg=reg_ip)          # in progress: §1 still names the current round
    ip = [d for d in B.run(root, skip=('rows', 'closures', 'inventory'))['drifts'] if '(H4)' in d['source']]
    ok = not good and not ip and len(bad) == 1 and bad[0]['expected'] == 'Round 4' and 'want = rlabel(c.next) if (c.done and c.next) else lab' in \
        (P['root'] / 'harness/intel/coherence.py').read_text()
    return ok, f"implemented r3, §1 Round 4: H4 drifts {len(good)}; §1 Round 3: {[d['expected'] for d in bad]}; in-progress {len(ip)}"


KATS = [('BT1', kat_bt1), ('BT2', kat_bt2), ('BT3', kat_bt3), ('BT4', kat_bt4), ('BT5', kat_bt5), ('BT6', kat_bt6), ('BT7', kat_bt7),
        ('BT8', kat_bt8)]
OWNERS = {f'r28 BT{i}': [f'BT{i}'] for i in range(1, 9)}

MUTATIONS = [
    ('harness/intel/backlog_truth.py', "                want = want_h4 if h == 'H4' else rlabel(c.cur)", "                want = rlabel(c.cur)",
     'r28 BT8: H4 requires the current round after its implementation (B174)'),
    ('harness/intel/backlog_truth.py', "    want_h4 = rlabel(nxt_id) if c.rcur.get('status') in ('implemented', 'shipped', 'measured') and nxt_id else rlabel(c.cur)",
     "    want_h4 = rlabel(nxt_id) if nxt_id else rlabel(c.cur)", 'r28 BT8: an in-progress round also wants the next round\'s prompt (B174)'),
    ('harness/intel/backlog_truth.py', "    if len(cells) > 5:\n        cells = cells[:4] + [' | '.join(cells[4:])]\n    return cells",
     "    return cells", 'r28 BT1: a bare pipe in the status splits the status cell'),
    ('harness/intel/coherence.py', "        if len(cells) > 5:                 # r28: a bare pipe in the status text (B105 'node|network') stays in the status\n            cells = cells[:4] + [' | '.join(cells[4:])]\n",
     "", 'r28 BT1: coherence.rft_backlog reads the last fragment of B105'),
    ('harness/intel/backlog_truth.py', "        if br is not None and br > RANK[lc]:", "        if False:", 'r28 BT2: a lead below the row\'s own bold status is not stale'),
    ('harness/intel/backlog_truth.py', "        if bid in conf and lc in ('implemented', 'backend'):", "        if False:", 'r28 BT2: §13 CONFIRMED live does not reach §7'),
    ('harness/intel/backlog_truth.py', "        if bid in conf and lc in ('implemented', 'backend'):", "        if bid in conf and lc != 'closed':",
     'r28 BT2: a PARTIAL confirmation (B36) reads as a stale lead'),
    ('harness/intel/backlog_truth.py', "and '§0.3' not in st:", "and False:", 'r28 BT2: a PAUSED row need not cite §0.3'),
    ('harness/intel/backlog_truth.py', "            if newest_measured and m.group(1) != newest_measured:", "            if False:", 'r28 BT3: H1 is not checked'),
    ('harness/intel/backlog_truth.py', "re.sub(r'^>\\s?', '', l) for l in ls[:hdr_end]", "l for l in ls[:hdr_end]",
     'r28 BT3: the next-round phrase across the blockquote break is not seen'),
    ('harness/intel/backlog_truth.py', "             (r'^## 8\\. Round (\\d+[a-z]?) dimension plan', 'H5'))", "             )",
     'r28 BT3: the §8 heading is not checked'),
    ('harness/intel/backlog_truth.py', "            if newest_merged and m.group(1) != newest_merged:", "            if False:", 'r28 BT3: H6 is not checked'),
    ('harness/intel/backlog_truth.py', "            if SCRATCH_RX.search(str(p)) or not (c.root / str(p)).exists():", "            if not (c.root / str(p)).exists():",
     'r28 BT4: a <scratch> record counts as a tree record'),
    ('harness/intel/backlog_truth.py', "            if lead_class(r['status']) != cls:", "            if False:", 'r28 BT4: §7 lead vs closure class unchecked'),
    ('harness/intel/backlog_truth.py', "len(dr.get('options') or []) < 2", "len(dr.get('options') or []) < 1", 'r28 BT4: a one-option decision request passes'),
    ('harness/intel/backlog_truth.py', "            if r is None or lead_class(r['status']) != 'closed':\n                c.drift('closures', c.rft_rel, r and r['line'], f'{item}: §7 {v} closed-class (via_rows)',",
     "            if r is None:\n                c.drift('closures', c.rft_rel, r and r['line'], f'{item}: §7 {v} closed-class (via_rows)',", 'r28 BT4: an open via_rows row closes the item'),
    ('harness/intel/backlog_truth.py', "        return (q in t), (", "        return True, (", 'r28 BT4: a premise always holds'),
    ('harness/intel/coherence.py', ", 'rows': lambda: check_rows(c)}", "}", 'r28 BT5: G25 does not run the rows check'),
    ('harness/intel/miner_runs.py', "                if paused and now - cut > 0:", "                if False:", 'r28 BT6: the pause is booked as forgone payout again'),
    ('harness/intel/miner_runs.py', "round(1 - idle / (span - pz), 4) if span - pz > 0 else None", "round(1 - idle / span, 4) if span > 0 else None",
     'r28 BT6: uptime counts the pause in the span'),
    ('harness/intel/miner_runs.py', "[x for x, _ in ev['starts']], paused=st == 'paused', paused_since=paused_since)",
     "[x for x, _ in ev['starts']], paused=False, paused_since=paused_since)", 'r28 BT6: analyse() ignores the registry track'),
    ('harness/intel/miner_runs.py', "                if paused and cut - last >= IDLE_MIN_S:", "                if False:", 'r28 BT6: idle before --paused-since is dropped'),
    ('harness/intel/disclosure_track.py', "                if resolve(a, root, seed[0])['status'] == 'OK':", "                if False:",
     'r28 BT7: a seeded round\'s drifted anchor drifts for ever'),
    ('harness/intel/disclosure_track.py', "            if r['status'] == 'DRIFT' and rnd and rnd in seed[1] and seed[0]:", "            if r['status'] == 'DRIFT' and rnd and seed[0]:",
     'r28 BT7: a round outside seeded_at.rounds is read at the seed'),
]


def clone_tree(dst):
    dst = Path(dst)
    dst.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(['cp', '-cR', str(HARNESS), str(dst / 'harness')], capture_output=True, text=True)
    if r.returncode != 0:
        shutil.copytree(HARNESS, dst / 'harness', symlinks=True)
    for p in sorted((dst / 'harness').rglob('__pycache__'), reverse=True):
        shutil.rmtree(p, ignore_errors=True)
    return dst


def run_kats(P):
    res = []
    for name, fn in KATS:
        try:
            o, det = fn(P)
        except Exception as e:                                    # noqa: BLE001
            o, det = False, f'{type(e).__name__}: {e}'
        res.append((name, o, det))
    return res


def run_on(mutation=None):
    with tempfile.TemporaryDirectory(prefix='bt28_') as d:
        root = clone_tree(Path(d) / 'r')
        if mutation:
            rel, find, repl, _ = mutation
            p = root / rel
            p.write_text(p.read_text(encoding='utf-8').replace(find, repl, 1), encoding='utf-8')
            if p.suffix == '.py':
                compile(p.read_text(encoding='utf-8'), str(p), 'exec')
        # BT4's real-tree half reads the live closure record with the (mutant) tool against the real tree's rft
        return run_kats({'root': root, 'tmp': d, 'real_root': ROOT})


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_r28', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    res = run_on()
    for name, o, det in res:
        print(f"{'ok  ' if o else 'FAIL'} {name} {det[:500]}")
    if not all(o for _, o, _ in res):
        return 3
    K = katmut()
    missed = coupled = 0
    for mut in MUTATIONS:
        rel, find, repl, why = mut
        text = (ROOT / rel).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??      {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        try:
            res = run_on(mut)
        except SyntaxError as e:
            print(f'  INVALID {why}: mutant does not compile ({e.msg})')
            missed += 1
            continue
        failed = [n for n, o, _ in res if not o]
        verdict, extra = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f"  {verdict:8} {why}" + (f'  [{",".join(failed)}]' if failed else '')
              + (f'  COUPLED {extra}' if extra and verdict == 'proved' else ''))
        missed += verdict != 'proved'
        coupled += bool(extra) and verdict == 'proved'
    print('\n' + K.summary('r28 backlog-sweep KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed or coupled else 0


if __name__ == '__main__':
    sys.exit(main())
