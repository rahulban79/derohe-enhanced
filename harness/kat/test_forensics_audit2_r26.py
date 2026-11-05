#!/usr/bin/env python3
"""KAT + mutation proofs for the R26 forensics-audit2 tooling (rft §0.8.5, §8 forensics-audit2; B97, D2-01; G29 over
every version). No network, no node, no live file written: every case runs on forged inputs in a temp dir or on the
committed v1 tier A blobs (forensics/r25/raw/blobs, real RAW bodies; no proof byte is ever built or changed).

  AU1  verify_dataset L9: an OPEN version whose manifest differs from its ledger entry FAILS; re-registered, it PASSES;
  AU2  structural verifier, points: the bn256 generator (1, 2) passes; flag 0x02, x = P and an off-curve x FAIL;
  AU3  structural verifier, scalars: Order - 1 passes, Order FAILS; the proof layout equals the decoder length (1..7);
  AU4  structural verifier on real RAW bodies (v1 tier A): every NORMAL body 0 failed checks; a truncated body is a
       decode error, never a pass;
  AU5  duplicate-body census: two holders with equal bytes = equal; two holders with different bytes under one TXID
       = different (TXID hook: no second body is built); one holder = single_source; a copy whose TXID differs is
       rejected, never counted;
  AU6  holder independence: v1 raw/ and the fetched staging copy from the same pseudonymous source are ONE holder;
  AU7  tips walk: a contiguous single-tip chain is walked whole; a missing parent stops it (gap seen); multi-tip counted;
  AU8  wall 4: the HF3 step's Parity ((h > H) == Tx_Parity) vs the field's zero value, counted per carrier;
  AU9  G31 re-check: exact without full coverage, unbounded as 0, DC2 as 0, lower bound labelled total each FAIL;
  AU10 challenges from a rerun: D2-01 FAILS when the ledger differs; D2-14 FAILS (overturn) when the audit's own replay
       completes at the recorded treehash, HOLDS when it was not run; every built report has 0 verdict problems;
  AU11 G29 end to end on a forged dataset: PASS; a challenge flipped after the audit, a dropped history run, a report
       naming another dataset, a missing required challenge each FAIL; g29 over two versions FAILS when the newest
       has no audit (never only the newest checked);
  AU12 binding_of for a v2 manifest binds tools + inputs, not the commit (a manifest re-written at another commit
       keeps its audit), and changes when a pinned tool changes.
  Committed: audit2 selftest PASS; G29 PASS for every version on this tree; verify_dataset PASS.

  python3 -I harness/kat/test_forensics_audit2_r26.py   # exit 0 ok · 3 a KAT failed · 4 a mutation not caught / INVALID
"""
import copy, hashlib, importlib.util, json, os, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent


def load(base, name):
    d = str(base / 'forensics')
    sys.path.insert(0, d)
    try:
        for k in ('audit_check', 'manifest_check', 'audit2', 'verify_dataset'):
            sys.modules.pop(k, None)
        spec = importlib.util.spec_from_file_location(name, base / 'forensics' / f'{name}.py')
        m = importlib.util.module_from_spec(spec)
        sys.modules[name] = m
        spec.loader.exec_module(m)
        return m
    finally:
        sys.path.remove(d)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def jdump(o):
    return json.dumps(o, indent=1, sort_keys=True) + '\n'


# ---------------------------------------------------------------------------------------------------------- AU1
def au1(base):
    f = []
    VD = load(base, 'verify_dataset')
    t = Path(tempfile.mkdtemp(prefix='au1_'))
    try:
        fx = t / 'forensics'
        ds = fx / 'r26'
        (ds / 'derived').mkdir(parents=True)
        (ds / 'derived/x.json').write_text('{}\n')
        m = {'dataset': 'r26', 'supersedes': [], 'files': {'derived/x.json': sha(b'{}\n')}}
        (ds / 'manifest.json').write_text(jdump(m))
        led = {'versions': [{'version': 'r26', 'manifest_sha256': sha((ds / 'manifest.json').read_bytes()),
                             'sealed': False, 'supersedes': []}]}
        (fx / 'ledger.json').write_text(jdump(led))
        fails, _ = VD.verify(fx, t, None, check_tools=False)
        if any(x.startswith('L9') for x in fails):
            f.append('AU1 L9 fires on a registered open version')
        m['note'] = 'manifest re-written after registration'
        (ds / 'manifest.json').write_text(jdump(m))
        fails, _ = VD.verify(fx, t, None, check_tools=False)
        if not any(x.startswith('L9') for x in fails):
            f.append('AU1 an open manifest that differs from its ledger entry passes (L9)')
        VD.write_ledger(fx, 'r26', False)
        fails, _ = VD.verify(fx, t, None, check_tools=False)
        if fails:
            f.append(f'AU1 re-registered version still fails: {fails[:2]}')
    finally:
        shutil.rmtree(t, ignore_errors=True)
    return f


# ---------------------------------------------------------------------------------------------------------- AU2-AU4
def au2_4(base):
    f = []
    A2 = load(base, 'audit2')
    P, N = A2.bn256_constants(ROOT)
    g = (1).to_bytes(32, 'big') + b'\x00'
    if A2.point_problem(g, P) is not None:
        f.append('AU2 the generator fails')
    if A2.point_problem((1).to_bytes(32, 'big') + b'\x01', P) is not None:
        f.append('AU2 the generator with flag 1 fails')
    if A2.point_problem((1).to_bytes(32, 'big') + b'\x02', P) != 'point-flag-not-0-or-1':
        f.append('AU2 flag 0x02 passes')
    if A2.point_problem(P.to_bytes(32, 'big') + b'\x00', P) != 'point-x-not-reduced':
        f.append('AU2 x = P passes')
    if A2.point_problem((P + 1).to_bytes(32, 'big') + b'\x00', P) != 'point-x-not-reduced':
        f.append('AU2 x = P + 1 passes')
    nq = next(x for x in range(2, 500) if pow((x ** 3 + 3) % P, (P - 1) // 2, P) == P - 1)
    if A2.point_problem(nq.to_bytes(32, 'big') + b'\x00', P) != 'point-not-on-curve':
        f.append('AU2 an off-curve x passes')
    if A2.scalar_problem((N - 1).to_bytes(32, 'big'), N) is not None:
        f.append('AU3 Order - 1 fails')
    if A2.scalar_problem(N.to_bytes(32, 'big'), N) != 'scalar-not-reduced':
        f.append('AU3 Order passes')
    AC = sys.modules['audit_check']
    for pw in range(1, 8):
        lay = A2.proof_layout(pw)
        if sum(c * (33 if k == 'P' else 32) for k, c in lay) != AC.proof_len(pw):
            f.append(f'AU3 layout {pw}')
    blobs = sorted((ROOT / 'forensics/r25/raw/blobs').iterdir())
    normal = 0
    for p in blobs:
        b = p.read_bytes()
        kind, d = AC.classify_blob(b)
        if kind != 'tx' or AC.TXTYPES[d['type']] != 'NORMAL':
            continue
        r = A2.struct_tx(b, P, N)
        normal += 1
        if r['checks'] or not r['points'] or not r['scalars']:
            f.append(f'AU4 real NORMAL body {p.name[:8]} fails structurally: {r["checks"]}')
        if normal == 1:
            try:
                A2.struct_tx(b[:-1], P, N)
                f.append('AU4 a truncated body passes')
            except (AC.DecodeError, IndexError, ValueError):
                pass
            c = A2.struct_census({'t1': b, 't2': b[:-5]}, P, N)
            if c['decode_errors'] != 1 or c['proof_carrying'] != 1:
                f.append(f'AU4 census counts {c}')
    if normal < 10:
        f.append(f'AU4 only {normal} NORMAL tier A bodies found')
    return f


# ---------------------------------------------------------------------------------------------------------- AU5-AU8
def au5_8(base):
    f = []
    A2 = load(base, 'audit2')
    b1, b2 = b'body-one', b'body-two'
    tid = lambda b: 'T' if b.startswith(b'body') else 'X'          # TXID hook: no real second body is built
    car = {'T': [10, 12], 'S': [5]}
    cp = {'T': [('v1-raw:src-2', sha(b1), b1), ('archive-copy', sha(b1), b1)], 'S': []}
    r = A2.dup_census(car, cp, {'T': {}}, txid_of=tid)['counts']
    if r['equal'] != 1 or r['different'] or r['multi_block_txids'] != 1:
        f.append(f'AU5 equal case {r}')
    cp['T'] = [('v1-raw:src-2', sha(b1), b1), ('archive-copy', sha(b2), b2)]
    r = A2.dup_census(car, cp, {'T': {}}, txid_of=tid)['counts']
    if r['different'] != 1:
        f.append(f'AU5 different bodies under one TXID not counted {r}')
    cp['T'] = [('v1-raw:src-2', sha(b1), b1), ('archive-copy', sha(b'zz'), b'zz')]
    r = A2.dup_census(car, cp, {'T': {}}, txid_of=tid)['counts']
    if r['copy_txid_mismatch'] != 1 or r['single_source'] != 1:
        f.append(f'AU5 a copy with another TXID counted {r}')
    cp['T'] = [('v1-raw:src-2', sha(b1), b1), ('fetched:src-2', sha(b2), b2)]
    r = A2.dup_census(car, cp, {'T': {}}, txid_of=tid)['counts']
    if r['single_source'] != 1 or r['different']:
        f.append(f'AU6 one source counted as two holders {r}')
    if A2.holder('v1-raw:src-2') != A2.holder('fetched:src-2') or A2.holder('archive-copy') == A2.holder('fetched:src-2'):
        f.append('AU6 holder mapping')
    # AU7 walk
    blk = lambda i, h, tips: {'id': i, 'height': h, 'tips': tips, 'tx_hashes': []}
    by = {'c': blk('c', 3, ['b']), 'b': blk('b', 2, ['a']), 'a': blk('a', 1, ['z'])}
    ch, multi = A2.walk(by, 'c', 1)
    if sorted(ch) != [1, 2, 3] or multi:
        f.append(f'AU7 whole walk {sorted(ch)} multi {multi}')
    by2 = dict(by); by2.pop('b'); by2['x'] = blk('x', 2, ['a'])     # a block at the gap height that 'c' does not name
    ch, _ = A2.walk(by2, 'c', 1)
    if sorted(ch) != [3]:
        f.append(f'AU7 a missing parent is walked over (or bridged by height) {sorted(ch)}')
    by3 = dict(by); by3['c'] = blk('c', 3, ['b', 'q'])
    _, multi = A2.walk(by3, 'c', 1)
    if multi != 1:
        f.append('AU7 multi-tip not counted')
    # AU8 wall 4
    chain = {h: {'tx_hashes': []} for h in range(100, 111)}
    chain[100]['tx_hashes'] = ['t' * 64]
    chain[106]['tx_hashes'] = ['t' * 64]
    table = {'t' * 64: {'height': 100, 'tx_parity': True}}
    rows = A2.wall4_hf3(chain, table, 100, 110)
    if [r['parity_with_step'] for r in rows] != [False, True] or sum(r['differs'] for r in rows) != 1:
        f.append(f'AU8 parity rows {rows}')
    table = {'t' * 64: {'height': 100, 'tx_parity': False}}
    rows = A2.wall4_hf3(chain, table, 100, 110)
    if [r['parity_with_step'] for r in rows] != [True, False]:
        f.append(f'AU8 false Tx_Parity rows {rows}')
    return f


# ---------------------------------------------------------------------------------------------------------- AU9
def au9(base):
    f = []
    A2 = load(base, 'audit2')
    ok = {'id': 'a', 'class': 'DC3', 'label': 'fees', 'value': 5, 'scope': {}, 'bound_type': 'exact',
          'coverage': {'num': 3, 'den': 3}}
    if A2.g31_problems([ok]):
        f.append('AU9 a well-formed figure fails')
    for name, mut in (('exact without coverage', {'coverage': {'num': 2, 'den': 3}}),
                      ('unbounded as 0', {'bound_type': 'unbounded', 'value': 0}),
                      ('DC2 as 0', {'class': 'DC2', 'bound_type': 'lower-bound', 'value': 0}),
                      ('lower bound as total', {'bound_type': 'lower-bound', 'label': 'total fees'}),
                      ('no scope', {'scope': None}),
                      ('bad bound type', {'bound_type': 'about'})):
        x = dict(ok, **mut)
        if mut.get('scope', 1) is None:
            x.pop('scope')
        if not A2.g31_problems([x]):
            f.append(f'AU9 {name} passes')
    return f


# ---------------------------------------------------------------------------------------------------------- AU10-AU12
def committed_rerun():
    rp = ROOT / 'forensics/r26/audit/audit_report.json'
    return json.loads(rp.read_text())['rerun'] if rp.exists() else None


def au10(base, R0):
    f = []
    A2 = load(base, 'audit2')
    AC = sys.modules['audit_check']
    if R0 is None:
        return ['AU10 no committed r26 audit report (rerun) to build from']
    R = copy.deepcopy(R0)
    by = lambda R: {c['id']: c for c in A2.build_challenges(R)}
    R['ledger'] = dict(R['ledger'], equal=False, entry_sha256='0' * 64)
    if by(R)['D2-01']['result'] != 'FAILS':
        f.append('AU10 D2-01 holds with a differing ledger entry')
    R['ledger'] = dict(R['ledger'], equal=True)
    if by(R)['D2-01']['result'] != 'HOLDS':
        f.append('AU10 D2-01 fails with an equal ledger entry')
    if R.get('own_replay'):
        R['own_replay'] = dict(R['own_replay'], stopped='completed', end_eq_recorded_treehash=True,
                               walls_accepted={'wall2': True, 'wall3': True, 'wall4': True})
        if by(R)['D2-14']['result'] != 'FAILS':
            f.append('AU10 D2-14 holds although the own replay completed at our treehash')
        R2 = dict(R, own_replay=dict(R['own_replay'], walls_accepted={'wall4': False}))
        if by(R2)['D2-14']['result'] != 'HOLDS':
            f.append('AU10 D2-14 overturned although a wall was not accepted')
    R3 = dict(R, own_replay=None)
    if by(R3)['D2-14']['result'] != 'HOLDS':
        f.append('AU10 D2-14 overturned with no own replay')
    for RR in (R, R3):
        chs = A2.build_challenges(RR)
        vs = A2.build_verdicts(chs, RR)
        p = AC.verdict_problems(vs, chs)
        if p:
            f.append(f'AU10 verdict problems on a built report: {p[:2]}')
    return f


def forge_dataset(base, R0, t, name='r26'):
    """A forged dataset dir with a manifest and an audit built by audit2 from the committed rerun."""
    A2 = load(base, 'audit2')
    ds = t / 'forensics' / name
    (ds / 'derived').mkdir(parents=True)
    (ds / 'derived/x.json').write_text('{"v": 1}\n')
    R = copy.deepcopy(R0)
    R['dataset'] = name
    man = {'dataset': name, 'supersedes': [], 'tools': {'harness/forensics/v2.py': 'a' * 64}, 'inputs': {},
           'files': {'derived/x.json': sha(b'{"v": 1}\n')}}
    AC = sys.modules['audit_check']
    R['binding'] = dict(AC.binding_of(man), manifest_sha256_at_audit='f' * 64)
    rep, chj = A2.build_report(R, ds)
    a = ds / 'audit'
    a.mkdir()
    (a / 'audit_report.json').write_text(jdump(rep))
    (a / 'challenges.json').write_text(jdump(chj))
    (a / 'AUDIT.md').write_text(A2.render_md(rep, chj))
    seal_manifest(ds, man)
    return ds, man


def seal_manifest(ds, man):
    man['files'] = {str(p.relative_to(ds)): sha(p.read_bytes()) for p in sorted(ds.rglob('*'))
                    if p.is_file() and p.name != 'manifest.json'}
    (ds / 'manifest.json').write_text(jdump(man))


def au11(base, R0):
    f = []
    if R0 is None:
        return ['AU11 no committed r26 audit report (rerun) to build from']
    t = Path(tempfile.mkdtemp(prefix='au11_'))
    priv = t / 'private'
    priv.mkdir()
    try:
        (t / 'harness/intel').mkdir(parents=True)
        shutil.copy(ROOT / 'harness/intel/disclosure_track.py', t / 'harness/intel/disclosure_track.py')
        ds, man = forge_dataset(base, R0, t)
        AC = load(base, 'audit_check')
        fails, _ = AC.g29_check(ds, t, private=str(priv))
        if fails:
            f.append(f'AU11 a well-formed forged audit fails: {fails[:3]}')
        # a challenge flipped after the audit (report and manifest re-sealed: only the gate's own rules catch it)
        cj = json.loads((ds / 'audit/challenges.json').read_text())
        orig = (ds / 'audit/challenges.json').read_text()
        for c in cj['challenges']:
            if c['result'] != 'HOLDS':
                c['result'] = 'HOLDS'
                break
        (ds / 'audit/challenges.json').write_text(jdump(cj))
        seal_manifest(ds, man)
        if not AC.g29_check(ds, t, private=str(priv))[0]:
            f.append('AU11 a challenge flipped to HOLDS after the audit passes')
        (ds / 'audit/challenges.json').write_text(orig)
        seal_manifest(ds, man)
        # a missing required challenge
        cj = json.loads(orig)
        cj['challenges'] = [c for c in cj['challenges'] if c['id'] != 'D2-11']
        (ds / 'audit/challenges.json').write_text(jdump(cj))
        seal_manifest(ds, man)
        if not any('required challenge D2-11' in x for x in AC.g29_check(ds, t, private=str(priv))[0]):
            f.append('AU11 an audit without the duplicate-body census passes')
        (ds / 'audit/challenges.json').write_text(orig)
        seal_manifest(ds, man)
        # a report naming another dataset
        rep = json.loads((ds / 'audit/audit_report.json').read_text())
        orep = (ds / 'audit/audit_report.json').read_text()
        rep['dataset'] = 'r25'
        (ds / 'audit/audit_report.json').write_text(jdump(rep))
        seal_manifest(ds, man)
        if not any('names dataset' in x for x in AC.g29_check(ds, t, private=str(priv))[0]):
            f.append('AU11 a report naming another dataset passes')
        (ds / 'audit/audit_report.json').write_text(orep)
        seal_manifest(ds, man)
        # a dropped history run: build a second audit keeping the first, then delete the kept run
        A2 = load(base, 'audit2')
        hd = ds / 'audit/history/audit-1'
        hd.mkdir(parents=True)
        for k in ('audit_report.json', 'challenges.json', 'AUDIT.md'):
            shutil.copy(ds / 'audit' / k, hd / k)
        R = json.loads(orep)['rerun']
        rep2, chj2 = A2.build_report(R, ds)
        (ds / 'audit/audit_report.json').write_text(jdump(rep2))
        (ds / 'audit/challenges.json').write_text(jdump(chj2))
        (ds / 'audit/AUDIT.md').write_text(A2.render_md(rep2, chj2))
        seal_manifest(ds, man)
        AC = load(base, 'audit_check')
        fl, s = AC.g29_check(ds, t, private=str(priv))
        if fl or s.get('history_runs') != 1:
            f.append(f'AU11 an audit with its history fails: {fl[:2]}')
        shutil.rmtree(hd.parent)
        seal_manifest(ds, man)
        if not any('history' in x for x in AC.g29_check(ds, t, private=str(priv))[0]):
            f.append('AU11 a dropped history run passes')
        # g29 over two versions: the older audited, the newest without an audit
        ds2 = t / 'forensics' / 'r27'
        (ds2 / 'derived').mkdir(parents=True)
        (ds2 / 'derived/y.json').write_text('{}\n')
        seal_manifest(ds2, {'dataset': 'r27', 'supersedes': [], 'files': {}})
        A2b = load(base, 'audit2')
        rep3, chj3 = A2b.build_report(R, ds)
        (ds / 'audit/audit_report.json').write_text(jdump(rep3))
        (ds / 'audit/challenges.json').write_text(jdump(chj3))
        (ds / 'audit/AUDIT.md').write_text(A2b.render_md(rep3, chj3))
        seal_manifest(ds, man)
        led = {'versions': [{'version': 'r26', 'manifest_sha256': '0', 'sealed': True, 'supersedes': []},
                            {'version': 'r27', 'manifest_sha256': '0', 'sealed': False, 'supersedes': []}]}
        (t / 'forensics/ledger.json').write_text(jdump(led))
        os.environ['FORENSICS_PRIVATE'] = str(priv)
        AC = load(base, 'audit_check')
        ok, det = AC.g29(t)
        if ok or 'r27' not in det:
            f.append(f'AU11 g29 passes with an unaudited newest version: {det[:120]}')
        led['versions'] = led['versions'][:1]
        (t / 'forensics/ledger.json').write_text(jdump(led))
        ok, det = AC.g29(t)
        if not ok:
            f.append(f'AU11 g29 fails on one audited version: {det[:160]}')
        # the older version going stale must fail too, even when the newest is fine
        led['versions'] = [{'version': 'r26', 'manifest_sha256': '0', 'sealed': True, 'supersedes': []},
                           {'version': 'r28', 'manifest_sha256': '0', 'sealed': False, 'supersedes': []}]
        ds3, man3 = forge_dataset(base, R0, t, 'r28')
        (t / 'forensics/ledger.json').write_text(jdump(led))
        (ds / 'derived/x.json').write_text('{"v": 2}\n')
        seal_manifest(ds, man)
        AC = load(base, 'audit_check')
        ok, det = AC.g29(t)
        if ok or 'r26' not in det:
            f.append(f'AU11 g29 passes with a stale earlier audit: {det[:120]}')
    finally:
        os.environ.pop('FORENSICS_PRIVATE', None)
        shutil.rmtree(t, ignore_errors=True)
    return f


def au12(base):
    f = []
    AC = load(base, 'audit_check')
    m = {'files': {'derived/a': '1'}, 'tools': {'harness/forensics/v2.py': 'a'}, 'inputs': {'x': 'b'}, 'git_base_commit': 'c1'}
    b1 = AC.binding_of(m)['data_sha256']
    if AC.binding_of(dict(m, git_base_commit='c2'))['data_sha256'] != b1:
        f.append('AU12 a v2 binding changes with the commit')
    if AC.binding_of(dict(m, tools={'harness/forensics/v2.py': 'z'}))['data_sha256'] == b1:
        f.append('AU12 a v2 binding ignores a changed tool')
    if AC.binding_of(dict(m, files={'derived/a': '1', 'audit/AUDIT.md': '9'}))['data_sha256'] != b1:
        f.append('AU12 audit/ files change the binding')
    if AC.binding_of(dict(m, files={'derived/a': '2'}))['data_sha256'] == b1:
        f.append('AU12 a changed data file keeps the binding')
    return f


def kats(base, R0):
    return au1(base) + au2_4(base) + au5_8(base) + au9(base) + au10(base, R0) + au11(base, R0) + au12(base)


def committed():
    f = []
    A2 = load(HARNESS, 'audit2')
    st = A2.selftest_struct(ROOT)
    if st:
        f.append(f'committed: audit2 selftest {st}')
    AC = load(HARNESS, 'audit_check')
    ok, det = AC.g29(ROOT)
    if not ok:
        f.append(f'committed: G29 {det[:200]}')
    VD = load(HARNESS, 'verify_dataset')
    fails, _ = VD.verify(ROOT / 'forensics', ROOT, VD.committed_ledger(ROOT))
    if fails:
        f.append(f'committed: verify_dataset {fails[:2]}')
    return f


MUTATIONS = [  # (file under harness/forensics, old, new)
    ('verify_dataset.py', "        if e.get('sealed') is not True and sha(mb) != e.get('manifest_sha256'):", "        if False:"),
    ('audit_check.py', "    for v in vs:\n        f, s = g29_check(fx / v, repo)", "    for v in vs[-1:]:\n        f, s = g29_check(fx / v, repo)"),
    ('audit_check.py', "                       'r26': ('D2-01', 'D2-02', 'D2-04', 'D2-05', 'D2-11', 'D2-12', 'D2-14')}", "                       'r26': ()}"),
    ('audit_check.py', "    if 'dataset' in rep and rep.get('dataset') != ds.name:", "    if False:"),
    ('audit_check.py', "        core['tools'] = man['tools']\n        core['inputs'] = man.get('inputs')", "        core['git_base_commit'] = man.get('git_base_commit')"),
    ('audit2.py', "    if b[32] not in (0, 1):", "    if b[32] > 2:"),
    ('audit2.py', "    if x >= P:\n        return 'point-x-not-reduced'", "    if x > P:\n        return 'point-x-not-reduced'"),
    ('audit2.py', "    if rhs and pow(rhs, (P - 1) // 2, P) != 1:", "    if False:"),
    ('audit2.py', "    return 'scalar-not-reduced' if int.from_bytes(b, 'big') >= N else None", "    return 'scalar-not-reduced' if int.from_bytes(b, 'big') > N else None"),
    ('audit2.py', "    return src.split(':', 1)[1] if ':' in src else src", "    return src"),
    ('audit2.py', "        elif len(hashes) == 1:\n            st = 'equal'", "        elif len(hashes) >= 1:\n            st = 'equal'"),
    ('audit2.py', "                cnt['copy_txid_mismatch'] += 1\n                continue", "                cnt['copy_txid_mismatch'] += 1"),
    ('audit2.py', "                par = (h > e['height']) == e['tx_parity']", "                par = (h >= e['height']) == e['tx_parity']"),
    ('audit2.py', "        cur = by_id.get(cur['tips'][0])", "        cur = by_id.get(cur['tips'][0]) or next(iter([r for r in by_id.values() if r['height'] == cur['height'] - 1]), None)"),
    ('audit2.py', "        if len(cur['tips']) != 1:\n            multi += 1", "        if len(cur['tips']) > 2:\n            multi += 1"),
    ('audit2.py', "                  L['equal'], [{'class': 'RAW', 'what': f\"ledger", "                  True, [{'class': 'RAW', 'what': f\"ledger"),
    ('audit2.py', "                  not ok14,", "                  True,"),
    ('audit2.py', "        if bt == 'exact' and not (isinstance(cov.get('num'), int) and cov.get('num') == cov.get('den')):", "        if False:"),
    ('audit2.py', "        if bt == 'unbounded' and f.get('value') in (0, '0', '', None):", "        if False:"),
    ('audit2.py', "        if bt == 'lower-bound' and re.search(r'\\btotal\\b', lab) and 'not a total' not in lab:", "        if False:"),
    ('audit2.py', "        if f.get('class') == 'DC2' and f.get('value') in (0, '0'):", "        if False:"),
]


def main():
    R0 = committed_rerun()
    f = kats(HARNESS, R0) + committed()
    print('AU1-AU12:', 'PASS' if not f else 'FAIL\n  ' + '\n  '.join(f))
    if f:
        return 3
    rc, caught = 0, 0
    for i, (fn, old, new) in enumerate(MUTATIONS, 1):
        tmp = Path(tempfile.mkdtemp(prefix='aumut_'))
        try:
            shutil.copytree(HARNESS / 'forensics', tmp / 'forensics')
            src = (tmp / 'forensics' / fn).read_text()
            if src.count(old) != 1:
                print(f'mutation {i} INVALID: text found {src.count(old)} times in {fn}'); rc = 4; continue
            (tmp / 'forensics' / fn).write_text(src.replace(old, new, 1))
            try:
                mf = kats(tmp, R0)
            except Exception as e:                                   # noqa: BLE001
                print(f'mutation {i} INVALID: {type(e).__name__}: {e}'); rc = 4; continue
            if mf:
                caught += 1
                print(f'mutation {i} CAUGHT ({fn}): {mf[0][:110]}')
            else:
                print(f'mutation {i} NOT CAUGHT ({fn}): {old.strip()[:80]}'); rc = 4
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f'mutations caught {caught}/{len(MUTATIONS)}')
    return rc


if __name__ == '__main__':
    sys.exit(main())
