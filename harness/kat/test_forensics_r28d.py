#!/usr/bin/env python3
"""KAT + mutation proofs for the r28d forensics dataset v4 (rft §7 B180, §8 R28d plan M-4; §0.8.1 rule 4, §0.8.9).
No network, no node, no decoder build: forged rows, a stub decoder and forged dataset trees in temp dirs; the committed
checks read this tree.

  V1 v4.correct_fq: FQ2 gains criterion S-RT and one dated correction; every other byte of fq.json is v3's; FQ2's
     coverage dc1_obs stays as it was.
  V2 v4.dc1_structure: only DC1 rows count; a TXID with two carriers is 'two_inclusions'; the criterion is every payload
     ring 2 AND RPCType 0 (a ring-2 RPCType-1 or a mixed tx is not counted); a body the store does not hold is
     'missing', a decoder failure 'undecodable'; coverage num/den = decoded / DC1 rows.
  V3 verify_dataset: a sub-round version sorts after its round and before the next (r28 < r28d < r29); 'r28dd' is not a
     version name; a ledger listing r28d before r28 FAILS L1.
  V4 bounds.classes_dataset picks the newest version holding derived/classes.json, r28d over r28; the r28d dataset's
     ledger page is its parent round's (dero-r1-r28.html).
  V5 audit2.audit_dc1_structure: the audit's own counts equal a correct claim and not a tampered one; an fq.json that
     changes anything beyond FQ2 S-RT / corrections is not 'rest equal'; an S-RT result that disagrees with the own count
     is caught.
  V6 audit_check: an audit of r28d must carry D2-26 and D2-27 (fail closed).
  Committed: r28 sealed and superseded by r28d (newest, open); r28d's DC1 structure is 53 / 14 / 7 / 1 with 60 meeting
  S-RT over 75 of 75 bodies; its FQ2 carries S-RT with DC1-obs 0.

  python3 -I harness/kat/test_forensics_r28d.py   # exit 0 ok · 3 a KAT failed · 4 a mutation not caught / INVALID
"""
import gzip, importlib.util, io, json, shutil, sys, tempfile, types
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
T1, T2, T3, T4, T5 = ('a1' * 32, 'b2' * 32, 'c3' * 32, 'd4' * 32, 'e5' * 32)


def load(base, rel, tag):
    sys.path.insert(0, str(base / 'forensics'))
    try:
        spec = importlib.util.spec_from_file_location(f'fx28d_{tag}_{id(base)}_{len(sys.modules)}', base / rel)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    finally:
        sys.path.pop(0)


def gz(rows):
    buf = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=buf, mtime=0, compresslevel=9) as g:
        for r in rows:
            g.write((json.dumps(r, sort_keys=True, separators=(',', ':')) + '\n').encode())
    return buf.getvalue()


FQ_V3 = {'FQ1': {'status': 'answered'}, 'FQ2': {'coverage': {'dc1_detected': 75, 'dc1_obs': 0}, 'criteria': {
    'P1': {'result': '0 of 75'}, 'S-R22': {'result': '0 of 75 within held bodies'}}, 'status': 'answered for the recorded criteria'},
    'schema': 1}


def dc1_claim(n=75):
    return {'criterion': {'result': f'60 of {n}', 'two_inclusions': '53 of 67', 'single_inclusion': '7 of 8'},
            'bodies': {'decoded': n, 'dc1_rows': n}}


def kats(base):
    f = []
    V4 = load(base, 'forensics/v4.py', 'v4')
    # V1 ------------------------------------------------------------------------------------------------------------
    out = json.loads(V4.correct_fq(json.dumps(FQ_V3).encode(), dc1_claim()))
    q = out['FQ2']
    if 'S-RT' not in q.get('criteria', {}) or not str(q['criteria'].get('S-RT', {}).get('result', '')).startswith('60 of 75 '):
        f.append('V1 FQ2 S-RT missing or wrong')
    if len(q.get('corrections') or []) != 1 or q['corrections'][0].get('date') != V4.CORRECTION_DATE:
        f.append('V1 FQ2 correction missing or undated')
    rest = json.loads(json.dumps(out))
    rest['FQ2']['criteria'].pop('S-RT', None)
    rest['FQ2'].pop('corrections', None)
    if rest != FQ_V3:
        f.append('V1 correct_fq changed fq.json beyond FQ2 S-RT and corrections')
    # V2 ------------------------------------------------------------------------------------------------------------
    rows = [{'txid': T1, 'class': 'DC1', 'body_sha256': 'h1'}, {'txid': T2, 'class': 'DC1', 'body_sha256': 'h2'},
            {'txid': T3, 'class': 'DC1', 'body_sha256': 'h3'}, {'txid': T4, 'class': 'DC1', 'body_sha256': 'h4'},
            {'txid': T5, 'class': 'DC3', 'body_sha256': 'h5'}, {'txid': 'f6' * 32, 'class': 'DC1', 'body_sha256': 'gone'}]
    incl = json.dumps({'rows': [{'txid': T1, 'heights': [10, 12]}, {'txid': T4, 'heights': [20, 21]}]}).encode()
    pay = {T1: [(2, 0)], T2: [(16, 1)], T3: [(2, 1)], T4: [(2, 0), (2, 0)], T5: [(2, 0)]}

    def decode(_dec, items, _work):
        res = {}
        for key, kind, b in items:
            if key == T3 and b == b'bad':
                res[key] = {'ok': False}
            else:
                res[key] = {'ok': True, 'payloads': [{'ring_size': r, 'rpc_type': t} for r, t in pay[key]]}
        return res
    stub = types.SimpleNamespace(gzip=gzip, read_store=lambda stores, h: None if h == 'gone' else h.encode(),
                                 decode=decode, build_decoder=lambda w: 'stub', dump=V4.v2.dump)
    real = V4.v2
    V4.v2 = stub
    try:
        d = V4.dc1_structure(gz(rows), incl, ['s'], 'w')
    finally:
        V4.v2 = real
    want = {'criterion': 2, 'criterion:two_inclusions': 2, 'ring2+rpctype0': 2, 'two_inclusions:ring2+rpctype0': 2,
            'ring16+rpctype1': 1, 'single_inclusion:ring16+rpctype1': 1, 'ring2+rpctype1': 1, 'single_inclusion:ring2+rpctype1': 1}
    if d.get('counts') != want:
        f.append(f"V2 dc1 counts {d.get('counts')}")
    if d['bodies'] != {'dc1_rows': 5, 'held': 4, 'missing': 1, 'decoded': 4, 'undecodable': 0}:
        f.append(f"V2 bodies {d['bodies']}")
    if (d['coverage']['num'], d['coverage']['den']) != (4, 5) or d['groups']['two_inclusions'] != 2:
        f.append(f"V2 coverage/groups {d['coverage']} {d['groups']}")
    if d['criterion']['result'] != '2 of 5' or d.get('class') != 'DC1':
        f.append(f"V2 criterion {d['criterion']}")
    # V3 ------------------------------------------------------------------------------------------------------------
    VD = load(base, 'forensics/verify_dataset.py', 'vd')
    if sorted(['r29', 'r28d', 'r28', 'r26'], key=VD.vkey) != ['r26', 'r28', 'r28d', 'r29']:
        f.append('V3 version order')
    if VD.VDIR.match('r28dd') or not VD.VDIR.match('r28d'):
        f.append('V3 version name grammar')
    tmp = Path(tempfile.mkdtemp(prefix='fx28d_'))
    try:
        fx = tmp / 'forensics'
        for v in ('r28', 'r28d'):
            (fx / v).mkdir(parents=True)
            (fx / v / 'manifest.json').write_text(json.dumps({'dataset': v, 'files': {}}))
        (fx / 'ledger.json').write_text(json.dumps({'versions': [{'version': 'r28d', 'manifest_sha256': 'x', 'sealed': True},
                                                                 {'version': 'r28', 'manifest_sha256': 'y', 'sealed': False}]}))
        fails, _ = VD.verify(fx, tmp, None, check_tools=False)
        if not any('increasing order' in x for x in fails):
            f.append('V3 r28d listed before r28 is not refused (L1)')
        # V4 --------------------------------------------------------------------------------------------------------
        B = load(base, 'forensics/bounds.py', 'b')
        for v in ('r28', 'r28d'):
            (fx / v / 'derived').mkdir()
            (fx / v / 'derived' / 'classes.json').write_text('{}')
        got = B.classes_dataset(tmp)
        if got is None or got.name != 'r28d':
            f.append(f'V4 classes_dataset picked {got}')
        if B.pages(tmp, fx / 'r28d')[0].name != 'dero-r1-r28.html' or B.pages(tmp, fx / 'r28')[0].name != 'dero-r1-r28.html':
            f.append(f"V4 the r28d dataset's ledger page is {B.pages(tmp, fx / 'r28d')[0].name}, not its parent round's")
        # V5 --------------------------------------------------------------------------------------------------------
        A2 = load(base, 'forensics/audit2.py', 'a2')
        ds = fx / 'r28d'
        (fx / 'r28' / 'derived' / 'fq.json').write_text(json.dumps(FQ_V3))
        (ds / 'manifest.json').write_text(json.dumps({'dataset': 'r28d', 'supersedes': ['r28'], 'files': {}}))
        fqd = json.loads(V4.correct_fq(json.dumps(FQ_V3).encode(), {'criterion': {'result': '1 of 2', 'two_inclusions': '1 of 1', 'single_inclusion': '0 of 1'},
                                                                   'bodies': {'decoded': 2, 'dc1_rows': 2}}))
        (ds / 'derived' / 'fq.json').write_text(json.dumps(fqd))
        own = {'criterion': 1, 'criterion:two_inclusions': 1, 'ring2+rpctype0': 1, 'two_inclusions:ring2+rpctype0': 1,
               'ring16+rpctype1': 1, 'single_inclusion:ring16+rpctype1': 1}
        (ds / 'derived' / 'dc1_structure.json').write_text(json.dumps({'class': 'DC1', 'counts': own, 'coverage': {'num': 2, 'den': 2}}))
        table = {T1: {}, T2: {}}
        carriers = {T1: [1, 2], T2: [3]}
        dec = {T1: {'payloads': [{'ring': 2, 'rpc_type': 0}]}, T2: {'payloads': [{'ring': 16, 'rpc_type': 1}]}}
        X = A2.audit_dc1_structure(ds, tmp, table, carriers, dec)
        if not (X['counts_equal'] and X['fq_rest_equal_base'] and X['fq2_srt_agrees'] and X['fq2_dc1_obs'] == 0 == X['fq2_dc1_obs_base']):
            f.append(f'V5 a correct claim is not upheld: {X}')
        bad = dict(own, criterion=2)
        (ds / 'derived' / 'dc1_structure.json').write_text(json.dumps({'class': 'DC1', 'counts': bad, 'coverage': {'num': 2, 'den': 2}}))
        if A2.audit_dc1_structure(ds, tmp, table, carriers, dec)['counts_equal']:
            f.append('V5 a tampered count is upheld')
        fq2 = json.loads(json.dumps(fqd))
        fq2['FQ1']['status'] = 'changed'
        fq2['FQ2']['criteria'].setdefault('S-RT', {})['result'] = '2 of 2 carry it'
        (ds / 'derived' / 'fq.json').write_text(json.dumps(fq2))
        Y = A2.audit_dc1_structure(ds, tmp, table, carriers, dec)
        if Y['fq_rest_equal_base'] or Y['fq2_srt_agrees']:
            f.append(f'V5 an fq.json change beyond S-RT, or a disagreeing S-RT, is upheld: {Y}')
        chs = A2.build_challenges.__code__.co_consts
        if not any(isinstance(c, str) and c == 'D2-26' for c in chs) or not any(isinstance(c, str) and c == 'D2-27' for c in chs):
            f.append('V5 build_challenges does not emit D2-26/D2-27')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # V6 ------------------------------------------------------------------------------------------------------------
    AC = load(base, 'forensics/audit_check.py', 'ac')
    req = AC.REQUIRED_BY_VERSION.get('r28d') or ()
    if 'D2-26' not in req or 'D2-27' not in req or 'D2-16' not in req:
        f.append(f'V6 r28d required challenges {req}')
    return f


def committed():
    f = []
    led = json.loads((ROOT / 'forensics' / 'ledger.json').read_text())['versions']
    by = {v['version']: v for v in led}
    if not by.get('r28', {}).get('sealed'):
        f.append('committed: r28 is not sealed (§6 step 3a, before r28d)')
    if 'r28d' in by and (led[-1]['version'] != 'r28d' and not by['r28d'].get('sealed')):
        f.append(f'committed: r28d is neither newest nor sealed: {led[-1]}')
    if by.get('r28d', {}).get('supersedes') != ['r28']:
        f.append(f"committed: r28d supersedes {by.get('r28d', {}).get('supersedes')}")
    d = json.loads((ROOT / 'forensics' / 'r28d' / 'derived' / 'dc1_structure.json').read_text())
    c = d.get('counts', {})
    want = {'two_inclusions:ring2+rpctype0': 53, 'two_inclusions:ring16+rpctype1': 14, 'single_inclusion:ring2+rpctype0': 7,
            'single_inclusion:ring16+rpctype1': 1, 'criterion': 60}
    if any(c.get(k) != v for k, v in want.items()) or d['bodies'].get('decoded') != 75 or d['bodies'].get('dc1_rows') != 75:
        f.append(f'committed: r28d DC1 structure {c} {d.get("bodies")}')
    q = json.loads((ROOT / 'forensics' / 'r28d' / 'derived' / 'fq.json').read_text())['FQ2']
    if not str(q.get('criteria', {}).get('S-RT', {}).get('result', '')).startswith('60 of 75 ') or q.get('coverage', {}).get('dc1_obs') != 0:
        f.append('committed: r28d FQ2 S-RT / DC1-obs')
    return f


MUTATIONS = [   # (file under harness/forensics, old, new)
    ('v4.py', "    q['criteria'][SRT] = {", "    q['criteria']['S-RT-x'] = {"),
    ('v4.py', "    q.setdefault('corrections', []).append({", "    q.setdefault('corrections', []).extend([]) or ({"),
    ('v4.py', "        if rings == [2] and fmts == [0]:", "        if rings == [2]:"),
    ('v4.py', "        group = 'two_inclusions' if r['txid'] in multi else 'single_inclusion'", "        group = 'single_inclusion'"),
    ('v4.py', "            if r.get('class') == 'DC1']", "            ]"),
    ('v4.py', "        if b is None:\n            missing += 1\n            continue", "        if b is None:\n            continue"),
    ('verify_dataset.py', "    return (int(m.group(1)), m.group(2))", "    return (int(m.group(1)), '')"),
    ('verify_dataset.py', "VDIR = re.compile(r'^r(\\d+)([a-z]?)$')", "VDIR = re.compile(r'^r(\\d+)([a-z]*)$')"),
    ('bounds.py', "        m = re.fullmatch(r'r(\\d+)([a-z]?)', d.name)", "        m = re.fullmatch(r'r(\\d+)()', d.name)"),
    ('bounds.py', "f\"dero-r1-{re.sub(r'^(r\\d+)[a-z]$', r'\\1', ds.name)}.html\"", "f'dero-r1-{ds.name}.html'"),
    ('audit2.py', "            'claimed_counts': claim.get('counts'), 'counts_equal': claim.get('counts') == dict(sorted(own.items())),",
     "            'claimed_counts': claim.get('counts'), 'counts_equal': True,"),
    ('audit2.py', "    q.pop('corrections', None)\n", "    q.pop('corrections', None)\n    fq = dict(fq, FQ1=base.get('FQ1'))\n"),
    ('audit2.py', "'fq2_srt_agrees': str(srt.get('result', '')).startswith(want + ' '),", "'fq2_srt_agrees': True,"),
    ('audit_check.py', "                                'D2-26', 'D2-27')}", "                                )}"),
]


def main():
    f = kats(HARNESS) + committed()
    print('V1-V6 + committed:', 'PASS' if not f else 'FAIL\n  ' + '\n  '.join(f))
    if f:
        return 3
    rc, caught, n = 0, 0, 0
    for i, (fn, old, new) in enumerate(MUTATIONS, 1):
        n += 1
        tmp = Path(tempfile.mkdtemp(prefix='fx28dmut_'))
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
