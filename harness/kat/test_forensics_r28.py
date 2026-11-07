#!/usr/bin/env python3
"""KAT + mutation proofs for the R28 forensics closure (rft §0.8, §6 step 3a; backlog B126, B107, B109, B110, B147, B76,
B123, A10c / D2-14 / D2-16 / D2-19 / D2-20, N28-08, N28-12). No network, no node; forged datasets and forged git
repositories in temp dirs; the committed checks read this tree.

  FX1 classes v2 tagging (B126): a v2 record whose `class` is a slot value ('pending', None, 'pending: defect class')
      gets ONE defect class (table TXID -> DC1, other tx -> DC3, block records -> DC3); a non-slot class is never
      overwritten; tagging is idempotent; tag_dataset refuses a sealed version; v2.derive's tagger (tag_v2_files)
      produces the bytes tag_dataset writes (G28 re-derivation == in-place tagging).
  FX2 G32 record half on the v2 layout (bounds.check_records_v2): an untagged dataset FAILS (the R26/R27 vacuous
      PASS), an unknown class FAILS, a count that differs from classes.json FAILS, a tagged dataset PASSES.
  FX3 classes.build DC3 window figures on v2 (D2-19): v2 fees.json with every v1 pending block settled -> exact over
      full coverage with v2's sums; one block still pending -> lower-bound.
  FX4 pinsnap (B147): a pinned file changed in the worktree FAILS pins.check but RESOLVES from git objects; an unknown
      hash is unresolvable (FAIL); a cited line range resolves from history; a tampered aggregate FAILS; resolve_tools
      finds a moved tool and refuses an unknown one; the snapshot re-check passes on the resolved bytes.
  FX5 v3 corrections: run C (HF3 entry) MATCH -> pending_reason and evidence_class name run C, runs are compared per
      entry point (A/B vs C), wall rows accepted by run C name the HF3 entry; run_c refuses a roots file whose SHA-256
      differs from the merge record.
  FX6 v3.replay: a content-pin failure stops the replay before any derivation (mode partial, FAIL).
  FX7 facts.dataset_at (closed pages, frozen inputs): a version whose tree manifest moved on is read as committed
      under the manifest SHA-256 the page names; an unknown SHA-256 falls back to the tree copy (so the page FAILS).
  FX8 audit: r28 requires D2-14, D2-16 and D2-20 (fail closed); build_challenges over the committed r28 rerun HOLDS
      D2-14/D2-16, and a forged rerun whose dataset run roots differ from the audit's own replay turns D2-14 to FAILS and
      D2-16 to UNRESOLVED.
  FX9 B124: v1's store index reads blobs/ only, so a staging dir beside blobs/ never changes it; a new blob does.
  Committed: r26 sealed, r28 newest and open; G32 non-vacuous on r28; r28 content pins include the decoder inputs
  (globals/globals.go among them); the sealed r25 pins resolve (pinsnap).

  python3 -I harness/kat/test_forensics_r28.py   # exit 0 ok · 3 a KAT failed · 4 a mutation not caught / INVALID
"""
import copy, gzip, hashlib, importlib.util, io, json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
T1, T2, T3 = 'aa' * 32, 'bb' * 32, 'cc' * 32          # T1 is a table TXID


def load(base, rel, tag):
    spec = importlib.util.spec_from_file_location(f'fx28_{tag}_{id(base)}_{len(sys.modules)}', base / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def sha(b):
    return hashlib.sha256(b).hexdigest()


def gz(rows):
    buf = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=buf, mtime=0, compresslevel=9) as g:
        for r in rows:
            g.write((json.dumps(r, sort_keys=True, separators=(',', ':')) + '\n').encode())
    return buf.getvalue()


def rows_of(p):
    return [json.loads(l) for l in gzip.decompress(Path(p).read_bytes()).decode().splitlines() if l.strip()]


def forge_root(t, sealed=()):
    """a tree with the HF3 table source (one Bl_Tips line per table TXID), a ledger and a v2-layout dataset rV"""
    (t / 'blockchain').mkdir(parents=True)
    (t / 'blockchain' / 'hardfork_fixes.go').write_text(f'var X = []T{{\n\t"{T1}" // Bl_Tips: x\n}}\n')
    (t / 'forensics').mkdir()
    (t / 'forensics' / 'ledger.json').write_text(json.dumps({'versions': [{'version': v, 'sealed': True} for v in sealed]}))
    ds = t / 'forensics' / 'rV'
    (ds / 'derived').mkdir(parents=True); (ds / 'raw').mkdir()
    (ds / 'derived' / 'txs.jsonl.gz').write_bytes(gz([{'txid': T1, 'class': 'pending'}, {'txid': T2, 'class': None},
                                                      {'txid': T3, 'class': 'DC0'}]))
    (ds / 'derived' / 'blocks_fees.jsonl.gz').write_bytes(gz([{'height': 1, 'class': 'pending'}]))
    (ds / 'derived' / 'roots_window.jsonl.gz').write_bytes(gz([{'topo': 1, 'class': 'pending: defect class'}]))
    (ds / 'raw' / 'tx_bodies.jsonl.gz').write_bytes(gz([{'txid': T1, 'class': 'pending'}, {'txid': T2, 'class': 'pending'}]))
    (ds / 'raw' / 'wall1_blocks.jsonl.gz').write_bytes(gz([{'height': 0, 'class': 'pending'}]))
    return ds


def fx1(C, t):
    f = []
    ds = forge_root(t)
    before = {rel: (ds / rel).read_bytes() for rel in C.V2_RECORD_FILES}
    n = C.tag_dataset(ds, t)
    tx = rows_of(ds / 'derived/txs.jsonl.gz')
    if [r['class'] for r in tx] != ['DC1', 'DC3', 'DC0']:
        f.append(f'FX1 tx tags {[r["class"] for r in tx]} (want DC1, DC3 and the non-slot DC0 kept)')
    for rel in ('derived/blocks_fees.jsonl.gz', 'derived/roots_window.jsonl.gz', 'raw/wall1_blocks.jsonl.gz'):
        if {r['class'] for r in rows_of(ds / rel)} != {'DC3'}:
            f.append(f'FX1 {rel} not DC3')
    if [r['class'] for r in rows_of(ds / 'raw/tx_bodies.jsonl.gz')] != ['DC1', 'DC3']:
        f.append('FX1 raw tx_bodies not tagged DC1/DC3')
    if n.get('derived/txs.jsonl.gz:DC1') != 1:
        f.append(f'FX1 tag counts {n}')
    after = {rel: (ds / rel).read_bytes() for rel in C.V2_RECORD_FILES}
    for rel, b in after.items():     # serialized exactly as v2.jl / v2.gz_bytes (compact JSON, gzip mtime 0, level 9)
        if b != gz(rows_of(ds / rel)):
            f.append(f'FX1 {rel}: tagged bytes are not in the v2 serialization'); break
    C.tag_dataset(ds, t)
    if after != {rel: (ds / rel).read_bytes() for rel in C.V2_RECORD_FILES}:
        f.append('FX1 tagging is not idempotent')
    via_derive = C.tag_v2_files(before, C.hf3_txids(t))
    if via_derive != after:
        f.append('FX1 tag_v2_files (v2.derive) bytes differ from tag_dataset (G28 would fail)')
    (t / 'forensics' / 'ledger.json').write_text(json.dumps({'versions': [{'version': 'rV', 'sealed': True}]}))
    try:
        C.tag_dataset(ds, t)
        f.append('FX1 tag_dataset rewrote a sealed version')
    except SystemExit:
        pass
    return f


def fx2(B, C, t):
    f = []
    ds = forge_root(t)
    cl = {'records': {}}
    p, n = B.check_records(ds, cl)
    if not any('not a defect class' in x for x in p):
        f.append(f'FX2 a v2 dataset with pending records passes the record half: {p[:2]}')
    rows = rows_of(ds / 'derived/txs.jsonl.gz'); rows[2]['class'] = 'pending'
    (ds / 'derived/txs.jsonl.gz').write_bytes(gz(rows))
    p, n = B.check_records(ds, cl)
    if not any('vacuous' in x for x in p) or n:
        f.append(f'FX2 an untagged v2 dataset passes the record half: {p[:2]}')
    C.tag_dataset(ds, t)
    cl = {'records': C.v2_record_census(ds)}
    p, n = B.check_records(ds, cl)
    if p or n != 8:
        f.append(f'FX2 a tagged dataset fails or miscounts: {p[:2]} n={n}')
    bad = copy.deepcopy(cl); bad['records']['derived/txs.jsonl.gz']['DC1'] = 2
    if not any('records.derived/txs.jsonl.gz' in x for x in B.check_records(ds, bad)[0]):
        f.append('FX2 a count differing from classes.json passes')
    rows = rows_of(ds / 'derived/blocks_fees.jsonl.gz'); rows[0]['class'] = 'DC9'
    (ds / 'derived/blocks_fees.jsonl.gz').write_bytes(gz(rows))
    if not any('not a defect class' in x for x in B.check_records(ds, cl)[0]):
        f.append('FX2 an unknown class passes')
    return f


def fx3(C, t):
    f = []
    ds = forge_root(t)
    C.tag_dataset(ds, t)
    base = t / 'forensics' / 'rB'
    (base / 'derived').mkdir(parents=True)
    hf3 = {'rows': [{'txid': T1, 'group': 'duplicates', 'carriers': [1, 2], 'tx_parity': False}],
           'table': {'entries': 1}, 'counts': {'bodies_raw': 1, 'carriers_total': 2, 'carriers_nonce_bypassed': 1}}
    (base / 'derived' / 'hf3.json').write_text(json.dumps(hf3))
    em = {'per_block': {'supply_identity_ok': 3, 'blocks': 3, 'burn_known_sum': 0}, 'window_emission_atomic': 9,
          'fees': {'known_sum_atomic': 5, 'known_blocks': 2, 'pending_blocks': 1}, 'grade': {'verdict_grade': 'X'}, 'scope': 's'}
    (base / 'derived' / 'emission.json').write_text(json.dumps(em))
    (base / 'derived' / 'grades.json').write_text(json.dumps({'counts': {}}))
    (base / 'derived' / 'window.jsonl.gz').write_bytes(gz([{'height': h, 'tx_hashes': [T1] if h < 3 else []} for h in (1, 2, 3)]))

    def figs(v2):
        (ds / 'derived' / 'fees.json').write_text(json.dumps({'v2': v2}))
        cl, _ = C.build(C.Inputs(ds, base, t), {'headline': {'dc2_present_now': True}}, None, [], None)
        return {x['id']: x for x in cl['figures']}, cl
    ok_v2 = {'window_fee_sum': 77, 'window_burn_sum': 11, 'window_fee_pending_blocks': 0, 'still_pending': 0, 'settled': 1}
    fg, cl = figs(ok_v2)
    fee = fg['dc3-window-fees']
    if (fee['value'], fee['bound_type'], fee['coverage']['num'], fee['coverage']['den']) != (77, 'exact', 3, 3):
        f.append(f'FX3 settled v2 fees not exact over 3/3: {fee["value"], fee["bound_type"], fee["coverage"]}')
    if fg['dc3-window-public-burns']['value'] != 11:
        f.append('FX3 burns do not read v2')
    if 'derived/txs.jsonl.gz' not in cl['records']:
        f.append(f'FX3 classes.json records not in the v2 layout: {cl["records"]}')
    fg, _ = figs(dict(ok_v2, still_pending=1))
    if fg['dc3-window-fees']['bound_type'] != 'lower-bound':
        f.append('FX3 a still-pending block leaves the fee figure exact')
    return f


def _git(repo, *a):
    return subprocess.run(['git', '-C', str(repo), *a], capture_output=True, text=True, check=True).stdout


def forge_repo(t):
    r = t / 'repo'
    (r / 'harness').mkdir(parents=True)
    _git(t, 'init', '-q', str(r))
    (r / 'harness' / 'tool.py').write_text('v = 1\n')
    (r / 'src.go').write_text('package x\nvar A = 1\nvar B = 2\n')
    (r / 'cite.go').write_text('package y\nvar C = 3\n')
    _git(r, 'add', '-A'); _git(r, '-c', 'user.email=k@t', '-c', 'user.name=kat', 'commit', '-qm', 'one')
    return r


def fx4(S, P, t):
    f = []
    r = forge_repo(t)
    pins = {'replay_tools': {'harness/tool.py': P.file_sha(r, 'harness/tool.py')},
            'decoder_inputs': {'src.go': P.file_sha(r, 'src.go')}, 'hf3_table': {'src.go': P.file_sha(r, 'src.go')},
            'cited_lines': {'src.go:2-3': P.lines_sha(r, 'src.go', 2, 3)}, 'decoder_platform': 'x/y'}
    pins['aggregate_sha256'] = P.aggregate(pins)
    lister = lambda root, goos=None, goarch=None: ['src.go']
    if S.resolve(pins, r)['failures']:
        f.append('FX4 fresh pins do not resolve')
    (r / 'src.go').write_text('package x\nvar A = 9\nvar B = 9\n')
    (r / 'harness' / 'tool.py').write_text('v = 2\n')
    if not P.check(pins, r, lister):
        f.append('FX4 pins.check passes a changed pinned file (setup)')
    res = S.resolve(pins, r)
    if res['failures'] or sorted(S.summary(res)['differ_from_worktree']) != ['harness/tool.py', 'src.go']:
        f.append(f'FX4 changed pinned files do not resolve from git: {res["failures"][:2]} {S.summary(res)}')
    snap = t / 'snap'
    s, sf = S.snapshot(pins, snap, r, lister)
    if sf or (snap / 'src.go').read_text() != 'package x\nvar A = 1\nvar B = 2\n':
        f.append(f'FX4 the snapshot does not hold the pinned bytes: {sf[:2]}')
    bad = copy.deepcopy(pins); bad['decoder_inputs']['src.go'] = '0' * 64; bad['aggregate_sha256'] = P.aggregate(bad)
    if not any('unresolvable pin' in x for x in S.resolve(bad, r)['failures']):
        f.append('FX4 an unknown hash resolves')
    tam = dict(pins, aggregate_sha256='1' * 64)
    if not any('aggregate' in x for x in S.resolve(tam, r)['failures']):
        f.append('FX4 a tampered aggregate resolves')
    cit = copy.deepcopy(pins); cit['cited_lines'] = {'src.go:2-2': sha(b'var A = 7')}; cit['aggregate_sha256'] = P.aggregate(cit)
    if not any('cited' in x for x in S.resolve(cit, r)['failures']):
        f.append('FX4 an unknown cited range resolves')
    (r / 'cite.go').write_text('package y\n// moved\nvar C = 3\n')      # a cited-only file whose line moved on
    co = copy.deepcopy(pins); co['cited_lines'] = {'cite.go:2-2': sha(b'var C = 3')}; co['aggregate_sha256'] = P.aggregate(co)
    rc = S.resolve(co, r)
    if rc['failures'] or rc['cited'].get('cite.go:2-2') in (None, 'worktree'):
        f.append(f'FX4 a moved cited line does not resolve from git: {rc["failures"][:1]} {rc["cited"]}')
    co['cited_lines'] = {'cite.go:2-2': sha(b'var C = 4')}; co['aggregate_sha256'] = P.aggregate(co)
    if not any('unresolvable cited' in x for x in S.resolve(co, r)['failures']):
        f.append('FX4 an unknown range of a cited-only file resolves')
    if S.resolve_tools({'harness/tool.py': sha(b'v = 1\n')}, r):
        f.append('FX4 resolve_tools misses a moved tool')
    if not S.resolve_tools({'harness/tool.py': '2' * 64}, r):
        f.append('FX4 resolve_tools accepts an unknown tool hash')
    return f


def fx5(V3, t):
    f = []
    sr = {'runs': {'A': {'roots_sha256': 'a', 'end_state_check': 'pending: x'}, 'B': {'roots_sha256': 'a', 'end_state_check': 'pending: x'},
                   'C': {'roots_sha256': 'c', 'end_state_check': 'MATCH'}},
          'runs_byte_identical': False, 'window_coverage': {'pending_reason': 'its replay stopped at 7,467,516'}}
    w = {'wall2': {'rows': [{'node_replay': 'accepted (Add_Complete_Block at this commit; root abc)'}]}, 'replay_stops': {'runs': {}}}
    files = {'derived/state_roots.json': json.dumps(sr).encode(), 'derived/walls.json': json.dumps(w).encode()}
    ent = {'A': 'pre', 'B': 'pre', 'C': V3.HF3_ENTRY}
    out = V3.correct(files, ent)
    s2, w2 = json.loads(out['derived/state_roots.json']), json.loads(out['derived/walls.json'])
    if s2.get('runs_byte_identical_per_entry') != {'pre': True, V3.HF3_ENTRY: True} or 'runs_byte_identical' in s2:
        f.append(f'FX5 runs not compared per entry: {s2.get("runs_byte_identical_per_entry")}')
    if 'run C' not in s2['window_coverage']['pending_reason'] or V3.HF3_ENTRY not in s2['evidence_class']:
        f.append('FX5 the pre-fix texts survive a MATCH run')
    if V3.HF3_ENTRY not in w2['wall2']['rows'][0]['node_replay']:
        f.append('FX5 a wall row accepted by run C does not name the HF3 entry')
    sr_nc = copy.deepcopy(sr); sr_nc['runs']['C']['end_state_check'] = 'pending: y'
    o3 = json.loads(V3.correct({'derived/state_roots.json': json.dumps(sr_nc).encode(), 'derived/walls.json': json.dumps(w).encode()}, ent)['derived/state_roots.json'])
    if 'run C' in o3['window_coverage']['pending_reason']:
        f.append('FX5 the run-C text is written without a MATCH')
    # run_c refuses a roots file with another SHA-256 than the merge record
    rt = t / 'root'
    (rt / 'harness' / 'runtime').mkdir(parents=True)
    good = b'{"topo":1}\n{"topo":2}\n'
    (rt / V3.MERGE_RECORD).write_text(json.dumps({'roots_jsonl_sha256': sha(good), 'roots_lines': 2, 'a2_binary_sha256': 'b',
                                                   'replay': {'last_root': 'r', 'end_state_match': True, 'started': 's'}}))
    (t / 'roots_bad.jsonl').write_bytes(b'{"topo":1}\n{"topo":3}\n')   # same line count, other bytes
    (t / 'roots_good.jsonl').write_bytes(good)
    ds = t / 'ds'
    try:
        V3.run_c(ds, t / 'roots_bad.jsonl', rt)
        f.append('FX5 run_c accepts a roots file whose SHA-256 differs from the record')
    except SystemExit:
        pass
    c = V3.run_c(ds, t / 'roots_good.jsonl', rt)
    s = json.loads((ds / 'raw/replay_runs/C/summary.json').read_text())
    if c['lines'] != 2 or s.get('entry') != V3.HF3_ENTRY or 'started' in s:
        f.append(f'FX5 run C summary wrong: {s}')
    return f


def fx6(V3, t):
    f = []
    ds = t / 'ds'
    (ds / 'raw').mkdir(parents=True); (ds / 'replay').mkdir()
    (ds / 'raw' / 'tx_bodies.jsonl.gz').write_bytes(gz([]))
    (ds / 'replay' / 'expected.sha256').write_text('')
    files = {'raw/tx_bodies.jsonl.gz': sha((ds / 'raw/tx_bodies.jsonl.gz').read_bytes()), 'replay/expected.sha256': sha(b'')}
    m = {'files': files, 'tools': {}, 'inputs': {}, 'tierB_store': {'tx_index_sha256': sha(b'')},
         'content_pins': {'replay_tools': {'nope.py': '0' * 64}, 'decoder_inputs': {'x.go': '0' * 64}, 'hf3_table': {'h.go': '0' * 64},
                          'cited_lines': {}, 'aggregate_sha256': 'z'}}
    (ds / 'manifest.json').write_text(json.dumps(m))
    try:
        rep = V3.replay(ds, None, t, lister=lambda r, a=None, b=None: ['x.go'])
    except Exception as e:                                   # noqa: BLE001 — derivation ran although the pins failed
        return [f'FX6 the replay derived despite a content-pin failure ({type(e).__name__})']
    if rep['result'] != 'FAIL' or rep['rederive']['mode'] != 'partial' or not any('content pins' in x for x in rep['fail_reasons']):
        f.append(f'FX6 a content-pin failure does not stop the replay: {rep["result"]} {rep["rederive"]["mode"]} {rep["fail_reasons"][:2]}')
    return f


def fx7(FX, t):
    f = []
    r = t / 'repo'
    d = r / 'forensics' / 'rQ'
    d.mkdir(parents=True)
    _git(t, 'init', '-q', str(r))
    (d / 'manifest.json').write_text('{"v": 1}\n'); (d / 'data.txt').write_text('old\n')
    _git(r, 'add', '-A'); _git(r, '-c', 'user.email=k@t', '-c', 'user.name=kat', 'commit', '-qm', 'one')
    old = sha(b'{"v": 1}\n')
    (d / 'manifest.json').write_text('{"v": 2}\n'); (d / 'data.txt').write_text('newer\n')
    _git(r, 'add', '-A'); _git(r, '-c', 'user.email=k@t', '-c', 'user.name=kat', 'commit', '-qm', 'two')   # a later commit
    (d / 'manifest.json').write_text('{"v": 3}\n'); (d / 'data.txt').write_text('new\n')
    got = FX.dataset_at(r, 'rQ', old)
    if got == d or sha((got / 'manifest.json').read_bytes()) != old or (got / 'data.txt').read_text() != 'old\n':
        f.append(f'FX7 a closed page does not read the version as committed: {got}')
    if FX.dataset_at(r, 'rQ', sha(b'{"v": 3}\n')) != d:
        f.append('FX7 the tree copy is not used when it matches')
    if FX.dataset_at(r, 'rQ', '3' * 64) != d:
        f.append('FX7 an unknown manifest hash does not fall back to the tree copy')
    shutil.rmtree(got.parent.parent, ignore_errors=True)
    return f


def fx8(AC, A2):
    f = []
    req = set(AC.REQUIRED_BY_VERSION.get('r28', ()))
    if not {'D2-14', 'D2-16', 'D2-20'} <= req:
        f.append(f'FX8 r28 audit requirements miss D2-14/D2-16/D2-20: {sorted(req)}')
    rp = ROOT / 'forensics' / 'r28' / 'audit' / 'audit_report.json'
    if not rp.exists():
        return f + ['FX8 forensics/r28/audit/audit_report.json missing']
    R = json.loads(rp.read_text())['rerun']
    res = {c['id']: c['result'] for c in A2.build_challenges(R)}
    if res.get('D2-14') != 'HOLDS' or res.get('D2-16') != 'HOLDS':
        f.append(f'FX8 committed rerun: D2-14 {res.get("D2-14")}, D2-16 {res.get("D2-16")}')
    bad = copy.deepcopy(R)
    for n in bad['runs']['hf3_entry_runs']:
        bad['runs']['runs'][n]['roots_jsonl_sha256'] = '4' * 64
    res = {c['id']: c['result'] for c in A2.build_challenges(bad)}
    if res.get('D2-14') != 'FAILS' or res.get('D2-16') != 'UNRESOLVED':
        f.append(f'FX8 a dataset run differing from the own replay: D2-14 {res.get("D2-14")}, D2-16 {res.get("D2-16")}')
    return f


def fx9(R, t):
    """B124 hygiene residual: v1's tier B store index (replay.store_index) reads blobs/ only, so a staging directory beside
    blobs/ (the R26 builder's stage_r26) can never change v1's index or its replay"""
    st = t / 'store'
    (st / 'blobs').mkdir(parents=True)
    for b in (b'one', b'two'):
        (st / 'blobs' / sha(b)).write_bytes(b)
    before = R.store_index(st)
    (st / 'stage_r26' / 'sub').mkdir(parents=True)
    (st / 'stage_r26' / 'sub' / 'x.json').write_text('{}')
    (st / 'stage_r26' / sha(b'three')).write_bytes(b'three')
    if R.store_index(st) != before:
        return ['FX9 a staging dir beside blobs/ changes the v1 store index (B124)']
    (st / 'blobs' / sha(b'four')).write_bytes(b'four')
    return [] if R.store_index(st) != before else ['FX9 a new blob does not change the v1 store index']


def kats(base):
    C = load(base, 'forensics/classes.py', 'classes')
    B = load(base, 'forensics/bounds.py', 'bounds')
    P = load(base, 'forensics/pins.py', 'pins')
    S = load(base, 'forensics/pinsnap.py', 'pinsnap')
    V3 = load(base, 'forensics/v3.py', 'v3')
    FX = load(base, 'forensics/facts.py', 'facts')
    AC = load(base, 'forensics/audit_check.py', 'audit_check')
    A2 = load(base, 'forensics/audit2.py', 'audit2')
    out = []
    for fn, args in ((fx1, (C,)), (fx2, (B, C)), (fx3, (C,)), (fx4, (S, P)), (fx5, (V3,)), (fx6, (V3,)), (fx7, (FX,))):
        with tempfile.TemporaryDirectory(prefix='fx28_') as t:
            out += fn(*args, Path(t))
    out += fx8(AC, A2)
    R = load(base, 'forensics/replay.py', 'replay')
    with tempfile.TemporaryDirectory(prefix='fx28_') as t:
        out += fx9(R, Path(t))
    return out


def committed():
    f = []
    led = json.loads((ROOT / 'forensics' / 'ledger.json').read_text())['versions']
    by = {v['version']: v for v in led}
    if not by.get('r26', {}).get('sealed'):
        f.append('committed: r26 is not sealed (§6 step 3a)')
    if led[-1]['version'] != 'r28' or led[-1].get('supersedes') != ['r26']:
        f.append(f'committed: newest version {led[-1]}')
    B = load(HARNESS, 'forensics/bounds.py', 'bc')
    ok, det = B.g32(ROOT)
    if not ok or ' 0 tagged records' in det:
        f.append(f'committed: G32 {det[:200]}')
    m = json.loads((ROOT / 'forensics' / 'r28' / 'manifest.json').read_text())
    if 'globals/globals.go' not in (m.get('content_pins') or {}).get('decoder_inputs', {}):
        f.append('committed: r28 does not content-pin the decoder inputs')
    S = load(HARNESS, 'forensics/pinsnap.py', 'sc')
    r25 = json.loads((ROOT / 'forensics' / 'r25' / 'manifest.json').read_text())
    rf = S.resolve(r25.get('content_pins'), ROOT)['failures']
    if rf:
        f.append(f'committed: the sealed r25 pins do not resolve: {rf[:2]}')
    return f


MUTATIONS = [   # (file under harness/forensics, old, new)
    ('classes.py', "    if rec.get('class') in V2_SLOT_VALUES:", "    if True:"),
    ('classes.py', "V2_SLOT_VALUES = (None, 'pending', 'pending: defect class')", "V2_SLOT_VALUES = (None, 'pending: defect class')"),
    ('classes.py', "    cls = tag_tx(rec, table) if kind == 'tx' else tag_block(rec)", "    cls = tag_block(rec)"),
    ('classes.py', "        out.append(json.dumps(r, sort_keys=True, separators=(',', ':')))", "        out.append(json.dumps(r, sort_keys=True))"),
    ('classes.py', "        ex = 'exact' if v2fees['window_fee_pending_blocks'] == 0 and v2fees['still_pending'] == 0 and known == den else 'lower-bound'",
     "        ex = 'exact'"),
    ('classes.py', "    v2fees = (I.json('derived/fees.json') or {}).get('v2') if v2 else None", "    v2fees = None"),
    ('classes.py', "        return tag_dataset_v2(ds, root)", "        return {}"),
    ('bounds.py', "    if n_files and not n_tagged:", "    if False:"),
    ('bounds.py', "        elif dict(seen) != {k: v for k, v in want.items() if k in CLASS_IDS} or any(k not in CLASS_IDS for k in want):",
     "        elif False:"),
    ('bounds.py', "            if c in CLASS_IDS:\n                seen[c] += 1", "            if True:\n                seen[c] += 1"),
    ('pinsnap.py', "        if matcher(b):\n            return 'worktree', b", "        return 'worktree', b"),
    ('pinsnap.py', "            if src is None:\n                fails.append(f'unresolvable pin ({grp}): {rel}')\n                continue",
     "            if src is None:\n                continue"),
    ('pinsnap.py', "    if pins.get('aggregate_sha256') != P.aggregate(pins):", "    if False:"),
    ('pinsnap.py', "        if src is None:\n            fails.append(f'unresolvable pinned tool: {rel}')", "        if False:\n            pass"),
    ('pinsnap.py', "    for rel, b in r['_bytes'].items():\n        dst = out / rel", "    for rel, b in []:\n        dst = out / rel"),
    ('pinsnap.py', "        src, b = find_bytes(root, f, h, matcher=lambda b, a=a, z=z, h=h: _lines(b, a, z) == h)",
     "        src, b = find_bytes(root, f, h, matcher=lambda b, a=a, z=z, h=h: True)"),
    ('v3.py', "    if sha(b) != rec['roots_jsonl_sha256']:", "    if False:"),
    ('v3.py', "    if full and not pf:", "    if True:"),
    ('v3.py', "        groups.setdefault(runs_entry.get(n, '?'), set()).add(r['roots_sha256'])", "        groups.setdefault('all', set()).add(r['roots_sha256'])"),
    ('v3.py', "            if complete else sr['window_coverage']['pending_reason'])", "            )"),
    ('v3.py', "    s.update({'a2_binary_sha256': rec['a2_binary_sha256'], 'entry': HF3_ENTRY,", "    s.update({'a2_binary_sha256': rec['a2_binary_sha256'],"),
    ('facts.py', "            hashlib.sha256((cur / 'manifest.json').read_bytes()).hexdigest() == manifest_sha:", "            True:"),
    ('facts.py', "        if b.returncode or hashlib.sha256(b.stdout).hexdigest() != manifest_sha:", "        if b.returncode:"),
    ('audit_check.py', "'D2-13', 'D2-14', 'D2-16', 'D2-20')}", "'D2-13', 'D2-14', 'D2-20')}"),
    ('replay.py', "    blobs = sorted(p.name for p in (Path(store) / 'blobs').glob('*'))", "    blobs = sorted(p.name for p in Path(store).rglob('*') if p.is_file())"),
    ('audit2.py', "        c14 = bool(OR) and ok14 and all(r['roots_jsonl_sha256'] == OR['roots_sha256'] and r['stopped'] == 'completed' for r in hf)",
     "        c14 = bool(OR) and ok14"),
    ('audit2.py', "    in_ds = bool(hf) and a10c_ok and all(r['roots_jsonl_sha256'] == OR['roots_sha256'] for r in hf) and str(SR['a10c_answer']).startswith('bound')",
     "    in_ds = bool(hf) and a10c_ok and str(SR['a10c_answer']).startswith('bound')"),
]


def main():
    f = kats(HARNESS) + committed()
    print('FX1-FX9 + committed:', 'PASS' if not f else 'FAIL\n  ' + '\n  '.join(f))
    if f:
        return 3
    rc, caught, n = 0, 0, 0
    for i, (fn, old, new) in enumerate(MUTATIONS, 1):
        n += 1
        tmp = Path(tempfile.mkdtemp(prefix='fx28mut_'))
        try:
            shutil.copytree(HARNESS / 'forensics', tmp / 'forensics', ignore=shutil.ignore_patterns('__pycache__'))
            src = (tmp / 'forensics' / fn).read_text()
            if src.count(old) != 1:
                print(f'mutation {i} INVALID: text found {src.count(old)} times in {fn}'); rc = 4; continue
            (tmp / 'forensics' / fn).write_text(src.replace(old, new, 1))
            try:
                mf = kats(tmp)
            except Exception as e:                                   # noqa: BLE001 — a crash is not a catch
                print(f'mutation {i} INVALID: {type(e).__name__}: {e}'); rc = 4; continue
            if mf:
                caught += 1
                print(f'mutation {i} CAUGHT ({fn}): {mf[0][:110]}')
            else:
                print(f'mutation {i} NOT CAUGHT ({fn}): {old.strip()[:80]}'); rc = 4
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f'mutations caught {caught}/{n}')
    return rc


if __name__ == '__main__':
    sys.exit(main())
