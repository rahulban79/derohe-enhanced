#!/usr/bin/env python3
"""KAT + mutation proofs for the R29 forensics dimension (rft §7 B107, B110, B97, B111; §8 R29 forensics). No network,
no node, no decoder build: forged rows, forged trees and fake endpoints in temp dirs; the committed checks read this tree.

  FR1 v4 row tagging (B107): a wall row carrying a table TXID -> DC1, else DC3; replay_stops DC1 iff a stopped tx is a
      table TXID, else DC3; an inclusion row DC1 iff its TXID is in the table, else DC0; the inclusions file DC0 iff any
      row is DC0; only slot values are filled (a set class is never overwritten); tagging is idempotent; class_rules
      written.
  FR2 G32 rows half (bounds.check_rows_r29): a correctly tagged dataset passes and counts every row; a 'pending' row,
      a DC3 wall row that carries a table TXID, a DC1 inclusion row outside the table, a wrong file class and a wrong
      replay_stops class each FAIL; the rule reads the table by bounds' own parse.
  FR3 audit2 D2-28 (audit_row_classes + build_challenges): the own walk's tx list decides a wall row's class (not the
      row's hf3_table_txs claim); a claim that differs, an unwalked row, inclusion rows != the own multi-block set and a
      pending slot each turn D2-28 to FAILS; a correct claim HOLDS; audit_check requires D2-28 for r28d.
  FR4 audit2 --stage takes several dirs (colon-separated): body_copies reads copies from every one; each is guarded.
  FR5 b97 (B97): check_copy keeps only a body whose own TXID equals the TXID asked; fetch_endpoint asks in chunks of 16,
      writes verified copies only, counts unserved / mismatch / errors; census groups copies by holder (2+ holders,
      equal vs different bodies, single holder, no copy).
  FR6 b110 (B110): join counts SC txs and carrier blocks inside run C's range, exact only when every carrier block is
      audited with ok/ok_sc, else lower-bound; a not-exported block is counted, the 89 below run C stay pending.
  FR7 b111 (B111 (A)): topo.map records decode (LE version, height); last_written skips clean records; a topo below the
      prune height is refused; clone refuses while derod runs, a destination under dero-data*, an existing one; it
      clones only balances/ and topo.map and writes the marker; census binds 7,498,540 to the recorded treehash and
      says NOT answered when the root differs; remove refuses a dir without the marker.
  Committed: r28d is the newest version; G32 passes with the walls/inclusions rows counted (33 wall rows + replay_stops
  + 67 inclusion rows + the file = 102); walls DC1 3 / DC3 30, inclusions DC1 67.

  python3 -I harness/kat/test_forensics_r29.py   # exit 0 ok · 3 a KAT failed · 4 a mutation not caught / INVALID
"""
import gzip, hashlib, importlib.util, io, json, shutil, struct, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
T1, T2, T3 = 'a1' * 32, 'b2' * 32, 'c3' * 32          # T1 is the table TXID


def load(base, rel, tag):
    sys.path.insert(0, str(base / 'forensics'))
    try:
        spec = importlib.util.spec_from_file_location(f'fr29_{tag}_{id(base)}_{len(sys.modules)}', base / rel)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    finally:
        sys.path.pop(0)


def walls(c1='pending', c2='pending', cs='pending'):
    return {'replay_stops': {'class': cs, 'runs': {'A': {'txid': T2}, 'B': {'txid': T2}}},
            'wall1': {'radius': 0, 'rows': [{'height': 10, 'blid': 'b10', 'hf3_table_txs': [T1], 'class': c1},
                                            {'height': 11, 'blid': 'b11', 'hf3_table_txs': [], 'class': c2}]}}


def inclusions(cls=('pending', 'pending'), fc='pending'):
    return {'class': fc, 'rows': [{'txid': T1, 'heights': [10, 12], 'class': cls[0]},
                                  {'txid': T3, 'heights': [11, 12], 'class': cls[1]}]}


def forge_tree(t, w, i):
    (t / 'blockchain').mkdir(parents=True, exist_ok=True)
    (t / 'blockchain' / 'hardfork_fixes.go').write_text(f'var X = []T{{\n\t"{T1}", // Bl_Tips: x\n\t"{T3}", // other\n}}\n')
    ds = t / 'forensics' / 'rV'
    (ds / 'derived').mkdir(parents=True, exist_ok=True)
    (ds / 'derived' / 'walls.json').write_text(json.dumps(w))
    (ds / 'derived' / 'inclusions.json').write_text(json.dumps(i))
    return ds


def fr1(base):
    f = []
    V4 = load(base, 'forensics/v4.py', 'v4')
    tb = {T1}
    w = json.loads(V4.tag_walls(json.dumps(walls()).encode(), tb))
    if [r['class'] for r in w['wall1']['rows']] != ['DC1', 'DC3'] or w['replay_stops']['class'] != 'DC3':
        f.append(f"FR1 wall/stops classes {[r['class'] for r in w['wall1']['rows']]} {w['replay_stops']['class']}")
    if 'class_rules' not in w:
        f.append('FR1 walls class_rules missing')
    w2 = walls(); w2['replay_stops']['runs']['A']['txid'] = T1
    if json.loads(V4.tag_walls(json.dumps(w2).encode(), tb))['replay_stops']['class'] != 'DC1':
        f.append('FR1 a stop on a table TXID is not DC1')
    i = json.loads(V4.tag_inclusions(json.dumps(inclusions()).encode(), tb))
    if [r['class'] for r in i['rows']] != ['DC1', 'DC0'] or i['class'] != 'DC0':
        f.append(f"FR1 inclusion classes {[r['class'] for r in i['rows']]} file {i['class']}")
    i1 = json.loads(V4.tag_inclusions(json.dumps({'class': 'pending', 'rows': [inclusions()['rows'][0]]}).encode(), tb))
    if i1['class'] != 'DC1':
        f.append('FR1 an all-table inclusions file is not DC1')
    kept = json.loads(V4.tag_walls(json.dumps(walls(c1='DC0')).encode(), tb))
    if kept['wall1']['rows'][0]['class'] != 'DC0':
        f.append('FR1 a set class was overwritten')
    once = V4.tag_walls(json.dumps(walls()).encode(), tb)
    if V4.tag_walls(once, tb) != once:
        f.append('FR1 tagging is not idempotent')
    if 'derived/walls.json' not in V4.NEW or 'derived/inclusions.json' not in V4.NEW:
        f.append('FR1 walls/inclusions are not v4 outputs (they would be inherited untagged)')
    return f


def fr2(base):
    f = []
    B = load(base, 'forensics/bounds.py', 'b')
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        good_w, good_i = walls('DC1', 'DC3', 'DC3'), inclusions(('DC1', 'DC0'), 'DC0')
        ds = forge_tree(t, good_w, good_i)
        tb = B.hf3_table_own(t)
        if tb != {T1}:
            f.append(f'FR2 own table parse {tb}')
        p, n = B.check_rows_r29(ds, tb)
        if p or n != 6:
            f.append(f'FR2 a correct dataset: {p} rows {n}')
        for name, w, i in [('pending row', walls('pending', 'DC3', 'DC3'), good_i),
                           ('DC3 table wall', walls('DC3', 'DC3', 'DC3'), good_i),
                           ('wrong stops', walls('DC1', 'DC3', 'DC1'), good_i),
                           ('DC1 outside table', good_w, inclusions(('DC1', 'DC1'), 'DC1')),
                           ('wrong file class', good_w, inclusions(('DC1', 'DC0'), 'DC1'))]:
            ds = forge_tree(t, w, i)
            if not B.check_rows_r29(ds, tb)[0]:
                f.append(f'FR2 {name} not caught')
    return f


def fr3(base):
    f = []
    A = load(base, 'forensics/audit2.py', 'a')
    AC = load(base, 'forensics/audit_check.py', 'ac')
    chain = {10: {'id': 'b10', 'tx_hashes': [T1]}, 11: {'id': 'b11', 'tx_hashes': []}, 12: {'id': 'b12', 'tx_hashes': [T1, T3]}}
    carriers = {T1: [10, 12], T3: [11, 12], T2: [12]}
    tb = {T1}
    with tempfile.TemporaryDirectory() as td:
        def run(w, i, ch=chain, ca=carriers):
            w = dict(w, class_rules={})
            ds = forge_tree(Path(td), w, i)
            return A.audit_row_classes(ds, ch, tb, ca)
        good_w, good_i = walls('DC1', 'DC3', 'DC3'), inclusions(('DC1', 'DC0'), 'DC0')
        ok = lambda Y: (Y['pending'] == 0 and not Y['wall_differ'] and Y['wall_unwalked'] == 0 and Y['wall_equal'] == Y['wall_rows']
                        and Y['stops_equal'] and Y['rows_txids_eq_own_multi'] and Y['inclusion_equal'] == Y['inclusion_rows']
                        and Y['file_class_equal'])
        Y = run(good_w, good_i)
        if not ok(Y):
            f.append(f'FR3 a correct claim fails: {Y}')
        # the row claims no table tx, the own walk says block 11 carries none either -> still DC3; but forge the claim
        lie = walls('DC1', 'DC3', 'DC3'); lie['wall1']['rows'][0]['hf3_table_txs'] = []
        Y = run(lie, good_i)
        if not ok(Y):
            f.append('FR3 the own walk did not decide the wall class (the row hf3_table_txs claim was used)')
        for name, w, i, ch in [('differ', walls('DC3', 'DC3', 'DC3'), good_i, chain),
                               ('unwalked', good_w, good_i, {11: chain[11], 12: chain[12]}),
                               ('other block at the height', good_w, good_i, {**chain, 10: {'id': 'bX', 'tx_hashes': [T1]}}),
                               ('pending', walls('DC1', 'pending', 'DC3'), good_i, chain),
                               ('rows != own multi', good_w, {'class': 'DC1', 'rows': [inclusions(('DC1', 'DC0'))['rows'][0]]}, chain),
                               ('file class', good_w, inclusions(('DC1', 'DC0'), 'DC1'), chain)]:
            Y = run(w, i, ch)
            if ok(Y):
                f.append(f'FR3 {name} not caught')
    if 'D2-28' not in AC.REQUIRED_BY_VERSION.get('r28d', ()):
        f.append('FR3 audit_check does not require D2-28 for r28d')
    if 'D2-28' not in A.AFFECTS_ALWAYS:
        f.append('FR3 D2-28 informs no verdict')
    return f


def fr4(base):
    f = []
    A = load(base, 'forensics/audit2.py', 'a4')
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        v1 = t / 'v1'; (v1 / 'raw').mkdir(parents=True); (v1 / 'raw/provenance.json').write_text('{"tx_objects": []}')
        s1, s2 = t / 's1', t / 's2'
        for s, src, h in ((s1, 'src-1', '01'), (s2, 'src-2', '02')):
            (s / 'txs').mkdir(parents=True)
            (s / 'txs' / f'x.{src}.json').write_text(json.dumps({'txid_requested': T1, 'source': src, 'as_hex': h}))
        out = A.body_copies({T1}, [], t / 'v2', v1, None, f'{s1}:{s2}')
        if sorted(c[0] for c in out[T1]) != ['fetched:src-1', 'fetched:src-2']:
            f.append(f'FR4 copies from two stage dirs: {[c[0] for c in out[T1]]}')
        if len(A.body_copies({T1}, [], t / 'v2', v1, None, str(s1))[T1]) != 1:
            f.append('FR4 one stage dir')
    src = (base / 'forensics' / 'audit2.py').read_text()
    if "*(stage.split(':') if stage else [])" not in src:
        f.append('FR4 run() does not guard every stage dir')
    return f


def fr5(base):
    f = []
    B = load(base, 'forensics/b97_holders_r29.py', 'b97')
    fake = lambda b: b.decode()            # a "body" whose own TXID is its text
    if B.check_copy(T1, T1.encode().hex(), fake) != 'ok' or B.check_copy(T1, T2.encode().hex(), fake) != 'txid-mismatch':
        f.append('FR5 check_copy ok/mismatch')
    if B.check_copy(T1, '', fake) != 'unserved' or B.check_copy(T1, 'zz', fake) != 'bad-hex':
        f.append('FR5 check_copy unserved/bad-hex')
    txids = [f'{i:064x}' for i in range(20)]
    calls = []

    def post(url, body):
        c = body['params']['txs_hashes']
        calls.append(len(c))
        hexes = [(t if t != txids[3] else txids[4]).encode().hex() if t != txids[5] else '' for t in c]
        return {'result': {'txs_as_hex': hexes, 'txs': [{} for _ in c]}}
    with tempfile.TemporaryDirectory() as td:
        orig = B.check_copy
        B.check_copy = lambda t, h, fn=fake: orig(t, h, fake)
        try:
            st, kept = B.fetch_endpoint('src-x', 'u', txids, td, 5.0, post=post, now=lambda: 'T', sleep=lambda s: None)
        finally:
            B.check_copy = orig
        if calls != [16, 4]:
            f.append(f'FR5 chunks {calls}')
        if st['ok'] != 18 or st['unserved'] != 1 or st['txid-mismatch'] != 1 or len(list(Path(td, 'txs').glob('*.json'))) != 18:
            f.append(f'FR5 counts {st}')
        if Path(td, 'txs', f'{txids[3]}.src-x.json').exists():
            f.append('FR5 a mismatching body was written')
        st2, _ = B.fetch_endpoint('src-y', 'u', txids[:2], td, 5.0, post=lambda u, b: (_ for _ in ()).throw(OSError('x')),
                                  now=lambda: 'T', sleep=lambda s: None)
        if st2['errors'] != 1 or st2['unserved'] != 2:
            f.append(f'FR5 endpoint error {st2}')
    with tempfile.TemporaryDirectory() as td:
        a, b = Path(td, 'a'), Path(td, 'b')
        for d in (a, b):
            (d / 'txs').mkdir(parents=True)
        w = lambda d, n, t, body, src: (d / 'txs' / n).write_text(json.dumps({'txid_requested': t, 'source': src, 'as_hex': body.encode().hex()}))
        w(a, '1.json', T1, T1, 'src-1'); w(b, '2.json', T1, T1, 'src-2')    # T1: two holders, equal
        w(a, '3.json', T2, T2, 'src-1'); w(b, '4.json', T2, T2, 'src-1')    # T2: one holder twice
        w(b, '5.json', T3, T2, 'src-2')                                     # T3: a mismatching body only
        T4 = 'd4' * 32
        w(a, '6.json', T4, T4, 'src-1'); w(b, '7.json', T4, T4 + ' ', 'src-2')   # T4: two holders, different bodies
        r = B.census([a, b], [T1, T2, T3, T4], lambda b: b.decode().strip())
        if r['counts'] != {'txids': 4, 'two_plus_holders': 2, 'equal': 1, 'different': 1, 'single_holder': 1, 'no_copy': 1}:
            f.append(f"FR5 census {r['counts']}")
    return f


def fr6(base):
    f = []
    B = load(base, 'forensics/b110_sc_payouts_r29.py', 'b110')
    lo, hi = B.RUN_C
    sc = [{'carrier_height': lo - 1}, {'carrier_height': lo}, {'carrier_height': lo}, {'carrier_height': lo + 5}]
    blocks = {lo: {'verdict': 'ok_sc', 'sc_payout': 300, 'sc_deposits': 400, 'sc_calls': 2},
              lo + 5: {'verdict': 'ok', 'sc_payout': 0, 'sc_deposits': 10, 'sc_calls': 1}}
    g = B.join(sc, blocks)
    if (g['value'], g['bound_type'], g['coverage']['txs'], g['coverage']['blocks']) != (300, 'exact', {'num': 3, 'den': 3}, {'num': 2, 'den': 2}):
        f.append(f"FR6 exact join {g['value']} {g['bound_type']} {g['coverage']}")
    if g['below_run_c'] != {'txs': 1, 'value': 'pending', 'reason': g['below_run_c']['reason']} or g['class'] != 'DC3':
        f.append(f"FR6 below run C {g['below_run_c']}")
    g = B.join(sc, {**blocks, lo + 5: {'verdict': 'sc_unexplained', 'sc_payout': 0}})
    if g['bound_type'] != 'lower-bound' or g['coverage']['blocks'] != {'num': 1, 'den': 2}:
        f.append(f"FR6 an unexplained block {g['bound_type']} {g['coverage']}")
    g = B.join(sc, {lo: blocks[lo]})
    if g['bound_type'] != 'lower-bound' or g['blocks_not_exported'] != 1:
        f.append(f"FR6 a missing block {g['bound_type']} {g['blocks_not_exported']}")
    g = B.join(sc, {**blocks, lo: dict(blocks[lo], error='x')})
    if g['bound_type'] != 'lower-bound':
        f.append('FR6 an errored block counted exact')
    return f


def topo_bytes(recs):
    return b''.join(bytes.fromhex(b) + struct.pack('<QQ', v, h) for b, v, h in recs)


def fr7(base):
    f = []
    B = load(base, 'forensics/b111_qcs1_r29.py', 'b111')
    P = B.PRUNED
    buf = bytes(48 * (P - 1)) + topo_bytes([('33' * 32, 5, P - 1), ('11' * 32, 7, P), ('22' * 32, 9, P + 1)]) + bytes(48)
    if B.topo_record(buf, P) != ('11' * 32, 7, P) or B.topo_record(buf, P + 3) is not None:
        f.append(f'FR7 topo_record {B.topo_record(buf, P)}')
    if B.last_written(buf) != P + 1:
        f.append(f'FR7 last_written {B.last_written(buf)}')
    try:
        B.census_versions(buf, [P - 1]); f.append('FR7 a topo below the prune height was accepted')
    except SystemExit:
        pass
    try:
        B.census_versions(buf, [P + 2]); f.append('FR7 a clean record was accepted')
    except SystemExit:
        pass
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        src = t / 'src'; (src / 'balances').mkdir(parents=True); (src / 'topo.map').write_bytes(buf); (src / 'bltx_store').mkdir()
        copied = []
        cp = lambda a, b: (copied.append(str(a)), shutil.copytree(a, b) if Path(a).is_dir() else shutil.copyfile(a, b))
        for name, dst, run in [('derod running', t / 'c1', True), ('under dero-data', t / 'dero-data-x' / 'c', False)]:
            try:
                B.cmd_clone(src, dst, pgrep=lambda r=run: r, cp=cp); f.append(f'FR7 clone {name} accepted')
            except SystemExit:
                pass
            if copied:
                f.append(f'FR7 clone {name}: copied before refusing {copied}')
                copied.clear()
        (t / 'exists').mkdir()
        try:
            B.cmd_clone(src, t / 'exists', pgrep=lambda: False, cp=cp); f.append('FR7 clone into an existing dir accepted')
        except SystemExit:
            pass
        c = t / 'clone'
        B.cmd_clone(src, c, pgrep=lambda: False, cp=cp)
        if sorted(p.name for p in c.iterdir()) != [B.MARKER, 'balances', 'topo.map']:
            f.append(f'FR7 clone contents {sorted(p.name for p in c.iterdir())}')
        root = t / 'root'
        (root / 'harness/runtime').mkdir(parents=True); (root / 'forensics/r28d/derived').mkdir(parents=True)
        lines = ['x'] * 111 + [f'encbal topoheight={P} status=OK treehash={"ab" * 32} registration=1']
        (root / B.TREEHASH_SOURCE[0]).write_text('\n'.join(lines) + '\n')
        (root / B.ARCHIVE_SCOPE).write_text(json.dumps({'Q-CS1': {'balance_tree_keys': 100, 'sc_meta_keys': 1, 'sc_tree_keys_total': 2}}))
        seen = []
        runner = lambda b, d, v, r='ab' * 32: (seen.append(v), {'ok': True, 'version': v, 'root': r, 'balance_tree_keys': 130})[1]
        try:
            res = B.cmd_census(c, 'bin', [P], True, root=root, runner=runner)
        except SystemExit as e:
            f.append(f'FR7 census with --tip refused: {e}')
            return f
        if seen != [7, 9] or not res['status'].startswith('answered') or res['comparisons']['held_archive_7467515']['anchor_minus_archive'] != 30:
            f.append(f"FR7 census {seen} {res['status']} {res['comparisons']['held_archive_7467515']}")
        res = B.cmd_census(c, 'bin', [P], False, root=root, runner=lambda b, d, v: {'ok': True, 'version': v, 'root': 'cd' * 32})
        if res['status'].startswith('answered') or res['census'][str(P)]['root_check']['equal']:
            f.append('FR7 a root different from the recorded treehash answered Q-CS1')
        try:
            B.cmd_remove(src); f.append('FR7 remove without the marker accepted')
        except SystemExit:
            pass
        B.cmd_remove(c)
        if c.exists():
            f.append('FR7 remove left the clone')
    if not B.under_node_store('/x/dero-data/mainnet') or B.under_node_store('/x/derohe-persist/c'):
        f.append('FR7 under_node_store')
    return f


def kats(base):
    f = []
    for k in (fr1, fr2, fr3, fr4, fr5, fr6, fr7):
        try:
            f += k(base)
        except (Exception, SystemExit) as e:   # noqa: BLE001 — a crash (or an unexpected refusal) is a failure
            f.append(f'{k.__name__} crashed: {type(e).__name__}: {e}')
    return f


def committed():
    f = []
    led = json.loads((ROOT / 'forensics' / 'ledger.json').read_text())['versions']
    if led[-1]['version'] != 'r28d':
        f.append(f"committed: newest version {led[-1]['version']}")
    B = load(HARNESS, 'forensics/bounds.py', 'bc')
    ok, det = B.g32(ROOT)
    if not ok or '102 walls/inclusions rows' not in det:
        f.append(f'committed: G32 {det[:200]}')
    w = json.loads((ROOT / 'forensics/r28d/derived/walls.json').read_text())
    i = json.loads((ROOT / 'forensics/r28d/derived/inclusions.json').read_text())
    wc = sorted(r['class'] for k in ('wall1', 'wall2', 'wall3') for r in w[k]['rows'])
    if (wc.count('DC1'), wc.count('DC3')) != (3, 30) or {r['class'] for r in i['rows']} != {'DC1'} or len(i['rows']) != 67 or i['class'] != 'DC1':
        f.append(f"committed: walls {wc.count('DC1')}/{wc.count('DC3')} inclusions {len(i['rows'])} {i['class']}")
    return f


MUTATIONS = [   # (file under harness/forensics, old, new)
    ('v4.py', "    return 'DC1' if any(t in table for t in (row.get('hf3_table_txs') or [])) else 'DC3'", "    return 'DC3'"),
    ('v4.py', "    return 'DC1' if any((r or {}).get('txid') in table for r in (stops.get('runs') or {}).values()) else 'DC3'", "    return 'DC3' if stops else 'DC1'"),
    ('v4.py', "    return 'DC1' if row.get('txid') in table else 'DC0'", "    return 'DC1'"),
    ('v4.py', "    if o.get('class') in SLOTS:", "    if True:"),
    ('v4.py', "    _fill(i, 'DC0' if any(r.get('class') == 'DC0' for r in i.get('rows') or []) else 'DC1')", "    _fill(i, 'DC1')"),
    ('v4.py', "NEW = ['derived/dc1_structure.json', 'derived/fq.json'] + TAGGED", "NEW = ['derived/dc1_structure.json', 'derived/fq.json']"),
    ('bounds.py', "            want = 'DC1' if set(r.get('hf3_table_txs') or []) & table else 'DC3'", "            want = r.get('class')"),
    ('bounds.py', "        want = 'DC1' if r.get('txid') in table else 'DC0'", "        want = r.get('class')"),
    ('bounds.py', "    if st.get('class') != want:", "    if False:"),
    ('bounds.py', "    want = 'DC0' if 'DC0' in got else 'DC1'", "    want = inc.get('class')"),
    ('bounds.py', "        if m and 'Bl_Tips' in l:", "        if m:"),
    ('audit2.py', "            own = 'DC1' if any(t in table for t in o['tx_hashes']) else 'DC3'", "            own = 'DC1' if r.get('hf3_table_txs') else 'DC3'"),
    ('audit2.py', "    out['rows_txids_eq_own_multi'] = {r.get('txid') for r in rows} == multi", "    out['rows_txids_eq_own_multi'] = True"),
    ('audit2.py', "            if not o or o['id'] != r.get('blid'):", "            if not o:"),
    ('audit2.py', "    for sd in (stage.split(':') if stage else []):", "    for sd in ([stage.split(':')[0]] if stage else []):"),
    ('audit2.py', "    'D2-28': ALL_V,", "    'D2-29': ALL_V,"),
    ('audit_check.py', "REQUIRED_BY_VERSION['r28d'] += ('D2-28',)", "pass"),
    ('b97_holders_r29.py', "        return 'ok' if txid_fn(b) == txid else 'txid-mismatch'", "        return 'ok'"),
    ('b97_holders_r29.py', "            if v == 'ok':", "            if v != 'unserved':"),
    ('b97_holders_r29.py', "        elif len(hs) < 2:", "        elif len(hs) < 1:"),
    ('b97_holders_r29.py', "            st = 'equal' if len(bodies) == 1 else 'different'", "            st = 'equal'"),
    ('b97_holders_r29.py', "CHUNK = 16 ", "CHUNK = 20 "),
    ('b110_sc_payouts_r29.py', "    exact = [h for h in aud if blocks[h].get('verdict') in EXACT and not blocks[h].get('error')]", "    exact = aud"),
    ('b110_sc_payouts_r29.py', "    full = len(exact) == len(hs) and len(hs) > 0", "    full = len(exact) == len(aud)"),
    ('b110_sc_payouts_r29.py', "    inr = [r for r in sc if lo <= r['carrier_height'] <= hi]", "    inr = list(sc)"),
    ('b111_qcs1_r29.py', "        if t < PRUNED:", "        if t < 0:"),
    ('b111_qcs1_r29.py', "    if derod_running(pgrep):\n        raise SystemExit('refused: derod is running", "    if False:\n        raise SystemExit('refused: derod is running"),
    ('b111_qcs1_r29.py', "    if under_node_store(dst):\n        raise SystemExit('refused: --dst", "    if False:\n        raise SystemExit('refused: --dst"),
    ('b111_qcs1_r29.py', "    blid, ver, h = buf[o:o + 32], *struct.unpack('<QQ', buf[o + 32:o + RECORD])", "    blid, ver, h = buf[o:o + 32], *struct.unpack('>QQ', buf[o + 32:o + RECORD])"),
    ('b111_qcs1_r29.py', "        if buf[t * RECORD:t * RECORD + 32] != bytes(32):", "        if True:"),
    ('b111_qcs1_r29.py', "                               'equal': o.get('root') == th['root']}", "                               'equal': True}"),
    ('b111_qcs1_r29.py', "    if not (clone / MARKER).exists():\n        raise SystemExit(f'refused: {clone} has no {MARKER} marker (remove", "    if False:\n        raise SystemExit(f'refused: {clone} has no {MARKER} marker (remove"),
]


def main():
    f = kats(HARNESS) + committed()
    print('FR1-FR7 + committed:', 'PASS' if not f else 'FAIL\n  ' + '\n  '.join(f))
    if f:
        return 3
    rc, caught, n = 0, 0, 0
    for i, (fn, old, new) in enumerate(MUTATIONS, 1):
        n += 1
        tmp = Path(tempfile.mkdtemp(prefix='fr29mut_'))
        try:
            shutil.copytree(HARNESS / 'forensics', tmp / 'forensics', ignore=shutil.ignore_patterns('__pycache__'))
            src = (tmp / 'forensics' / fn).read_text()
            if src.count(old) != 1:
                print(f'mutation {i} INVALID: text found {src.count(old)} times in {fn}'); rc = 4; continue
            (tmp / 'forensics' / fn).write_text(src.replace(old, new, 1))
            mf = kats(tmp)
            if mf and not all('crashed' in x for x in mf):
                caught += 1
                print(f'mutation {i} CAUGHT ({fn}): {mf[0][:110]}')
            else:
                print(f'mutation {i} NOT CAUGHT ({fn}): {old.strip()[:80]}' + (f' [only crashes: {mf[0][:80]}]' if mf else '')); rc = 4
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f'mutations caught {caught}/{n}')
    return rc


if __name__ == '__main__':
    sys.exit(main())
