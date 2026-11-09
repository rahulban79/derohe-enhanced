#!/usr/bin/env python3
"""test_b182_fetch_r29.py — r29 (rft §7 B182, user option (a)): the fetched-body registration census accepts a body
only when the node's decoder re-derives the requested txid byte-exact and a held block lists it, and extends the held
range downward only along an unbroken tips chain.

  BF1  lz() counts leading zero bytes (0, 1, 3, 32)
  BF2  accept_tx: a txid mismatch, a reserialize mismatch, a decode error and an unlisted txid are each refused; a good
       body is accepted
  BF3  chain_join: an unbroken chain joins every fetched block; a block whose id is not a tip of the block above stops it
       there; a gap stops it
  BF4  the committed record harness/runtime/r29_b182_fetch_census.json: every range complete, reg_lt3 empty, 0 rejected
       bodies and blocks, the upper join of 7,498,540 holds

  python3 -I harness/kat/test_b182_fetch_r29.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, importlib.util, io, json, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'tool': 'harness/forensics/b182_fetch_census_r29.py', 'record': 'harness/runtime/r29_b182_fetch_census.json'}


def P(over, key):
    return Path(over.get(key) or (ROOT / PATHS[key]))


def load(over):
    spec = importlib.util.spec_from_file_location('b182f', P(over, 'tool'))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def kat_bf1(over):
    m = load(over)
    got = [m.lz('11' + '00' * 31), m.lz('0011' + '00' * 30), m.lz('000000aa' + '00' * 28), m.lz('00' * 32)]
    return got == [0, 1, 3, 32], got


def kat_bf2(over):
    m = load(over)
    t = '000000ab' + 'cd' * 28
    good = {'ok': True, 'txid': t, 'reserialize_equal': True}
    cases = [(good, {t}, True), ({**good, 'txid': 'ff' * 32}, {t}, False), ({**good, 'reserialize_equal': False}, {t}, False),
             ({'ok': False, 'error': 'x'}, {t}, False), (good, set(), False)]
    got = [m.accept_tx(t, d, listed)[0] for d, listed, _ in cases]
    return got == [c[2] for c in cases], got


def kat_bf3(over):
    m = load(over)
    f = {9: {'id': 'b9', 'tips': ['b8']}, 8: {'id': 'b8', 'tips': ['b7']}, 7: {'id': 'b7', 'tips': ['b6']}}
    j1, br1 = m.chain_join(['b9'], f, 9)
    f2 = {**f, 8: {'id': 'xx', 'tips': ['b7']}}
    j2, br2 = m.chain_join(['b9'], f2, 9)
    f3 = {9: f[9], 7: f[7]}
    j3, br3 = m.chain_join(['b9'], f3, 9)
    ok = j1 == {7, 8, 9} and br1 is None and j2 == {9} and br2 == 8 and j3 == {9} and br3 is None
    return ok, (sorted(j1), br1, sorted(j2), br2, sorted(j3), br3)


def kat_bf4(over):
    d = json.loads(P(over, 'record').read_text())
    rs = [d[k] for k in ('wall1_7412665_7415463', 'gap_7415464_7415465', 'fetched_below_7412665')]
    ok = (all(r['complete'] and r['reg_lt3'] == [] and r['untyped'] == 0 for r in rs)
          and d['fetched_txs']['rejected'] == [] and d['fetched_blocks']['rejected_count'] == 0
          and d['fetched_blocks']['chain_broken_at'] is None and d['upper_join_7498540']['joins'] is True)
    return ok, [(r['range'], r['registrations'], r['complete']) for r in rs]


KATS = [('BF1', kat_bf1), ('BF2', kat_bf2), ('BF3', kat_bf3), ('BF4', kat_bf4)]
OWNERS = {'B182': ['BF1', 'BF2', 'BF3', 'BF4']}
MUTATIONS = [
    ('tool', "        if x:\n            break\n        n += 1", "        n += 1", 'B182: lz counts every byte'),
    ('tool', "    if not (d.get('ok') and d.get('txid') == txid and d.get('reserialize_equal')):",
     "    if not (d.get('ok') and d.get('reserialize_equal')):", 'B182: a body with another txid is accepted'),
    ('tool', "    if not (d.get('ok') and d.get('txid') == txid and d.get('reserialize_equal')):",
     "    if not (d.get('ok') and d.get('txid') == txid):", 'B182: a body that does not re-serialize is accepted'),
    ('tool', "    if txid not in listed:\n        return False", "    if False:\n        return False",
     'B182: an unlisted txid is accepted'),
    ('tool', "        if want is None or fetched_ok[h]['id'] not in want:\n            return joined, h",
     "        if want is None:\n            return joined, h", 'B182: a block off the tips chain is joined'),
    ('record', '"joins": true', '"joins": false', 'B182: the upper join is recorded as broken'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_bf29', HARNESS / 'kit' / 'katmut.py')
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
        res.append((name, ok, str(det)))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:500]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr29 b182 fetch KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
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
        with tempfile.TemporaryDirectory(prefix='bf29-mut-') as d:
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
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r29 b182 fetch KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
