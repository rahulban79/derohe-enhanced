#!/usr/bin/env python3
"""R33 KATs for the pool playbook and its independent auditor (artifacts/dero-game-theory-rft.md §7 GT-B29, GT-B34,
lessons 37-38). Pure: no node, no wallet; real mainnet blocks from dvm/testdata/r33_mainnet_blocks.json.

  PC1 parse_block reads every real block exactly as gt_pool.pproc: 10 miniblocks, one final (the last), every height
      field = the block height, the tip of 7,915,142 = the id of 7,915,141; a wrong tx count is refused
  PC2 expected_epoch: credits = non-final miniblocks with a member tag (8 bytes); the final miniblock and non-member
      tags earn nothing; the stake boost applies only once matured (since + epochlen <= h) and is capped at 100
  PC3 pool_audit.audit uses the CONTRACT's proven set (pr<h> keys), not a driver's list (lesson 38): a fake RPC with
      21 proven heights of which the driver knew 15 still audits all 21
  PC4 the loop's resume rules are in the code: a recorded epoch is skipped, a funded epoch is not funded again, a
      member that already claimed does not claim again, contract-proven heights are preloaded

  python3 -I harness/kat/test_pool_cycle_r33.py       exit 0 PASS · 3 a KAT failed · 4 a mutation survived
"""
import importlib.util, json, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATHS = {'cycle': 'playbooks/gt_pool_cycle.py', 'audit': 'harness/gametheory/pool_audit.py'}


def load(over, key, name):
    path = Path(over.get(key) or ROOT / PATHS[key])
    sys.path.insert(0, str(ROOT / 'playbooks'))
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def blocks():
    return json.loads((ROOT / 'dvm/testdata/r33_mainnet_blocks.json').read_text())


def tagged(b, tags):
    """the block's bytes with non-final miniblock i carrying tags[i] in bytes 32..39"""
    raw = bytearray.fromhex(b['blob'])
    p = len(raw) - 32 * b['txcount'] - 1
    q = p - 48 * 10 - 1
    for i, t in enumerate(tags):
        if t:
            off = q + 1 + 48 * i
            raw[off + 32:off + 40] = bytes.fromhex(t)
    return raw.hex()


def pc1(over):
    g = load(over, 'cycle', 'pc1')
    bs, bad = blocks(), []
    for b in bs:
        tip, mbs = g.parse_block(b['blob'], b['txcount'], 10)
        if len(mbs) != 10 or [x[0] for x in mbs].count(True) != 1 or not mbs[-1][0] or any(x[3] != b['height'] for x in mbs):
            bad.append(f"layout at {b['height']}")
    if g.parse_block(bs[1]['blob'], 0, 10)[0] != bs[0]['blid']:
        bad.append('tip of 7,915,142 is not the id of 7,915,141')
    try:
        g.parse_block(bs[3]['blob'], bs[3]['txcount'] + 1, 10)
        bad.append('a wrong tx count was accepted')
    except ValueError as ex:
        if 'tx count byte' not in str(ex):
            bad.append(f'a wrong tx count was refused by a later check only ({ex})')
    _, mb0 = g.parse_block(bs[0]['blob'], 0, 10)
    if any(len(x[2]) != 16 for x in mb0):
        bad.append('the tag is not read as 8 bytes (GT-B32)')
    return not bad, '; '.join(bad) or f'{len(bs)} real blocks parsed; tip link; wrong tx count refused'


def pc2(over):
    g = load(over, 'cycle', 'pc2')
    b = blocks()[0]
    A, B, X = 'a1' * 8, 'b2' * 8, 'c3' * 8
    _, mbs = g.parse_block(tagged(b, [A, A, B, X, '', '', '', '', '', A]), b['txcount'], 10)   # index 9 = the final miniblock
    h = b['height']
    bad = []
    w, W, TW = g.expected_epoch([(h, mbs)], {A, B})
    if w != {A: 2, B: 1} or W != {A: 200, B: 100} or TW != 300:
        bad.append(f'plain credits {w} {W} {TW}')
    w, W, TW = g.expected_epoch([(h, mbs)], {A, B}, {A: (50000, h - 400), B: (10 ** 9, h - 399)}, 100000, 400)
    if W != {A: 300, B: 100}:
        bad.append(f'stake maturity/boost {W}')
    w, W, TW = g.expected_epoch([(h, mbs)], {A}, {A: (10 ** 9, 0)}, 100000, 400)
    if W != {A: 400}:
        bad.append(f'boost cap {W}')
    return not bad, '; '.join(bad) or 'credits, non-member and final excluded, maturity, cap'


def pc3(over):
    pa = load(over, 'audit', 'pc3')
    b = blocks()[0]
    A = 'a1' * 8
    raw = tagged(b, [A])
    h0 = b['height']
    proven = list(range(h0, h0 + 21))                       # 21 proven by the contract; a driver knew only 15

    def fake_rpc(url, method, params):
        if method == 'DERO.GetSC':
            sk = {f'pr{h}': 1 for h in proven}
            e = h0 // 400
            sk.update({'epochlen': 400, 'mcount': 10, 'cap': 100, 'S': 100000, f'tag_{A}': 'x',
                       f'w{e}_{A}': 21, f'W{e}_{A}': 2100, f'TW{e}': 2100, 'burned': 0, f'P{e}': 0})
            return {'stringkeys': sk, 'balance': 0}
        h = params['height']                                 # every proven height returns the same tagged block,
        bb = bytearray.fromhex(raw)                          # with its miniblock height fields set to h
        p = len(bb) - 32 * b['txcount'] - 1
        q = p - 48 * 10 - 1
        for i in range(10):
            off = q + 1 + 48 * i
            bb[off + 3:off + 8] = h.to_bytes(5, 'big')
        return {'blob': bb.hex(), 'block_header': {'txcount': b['txcount']}}
    pa.rpc = fake_rpc
    r = pa.audit('x', 'y', h0 // 400, [A])
    ok = r['ok'] and r['proven'] == 21 and r['credits'] == {A: 21}
    return ok, f"proven {r['proven']} credits {r['credits']} ok {r['ok']} {r['problems'][:2]}"


def pc4(over):
    src = Path(over.get('cycle') or ROOT / PATHS['cycle']).read_text()
    need = ["done[str(e)].get('recorded')", "if not done.get(str(e), {}).get('funded'):",
            "f'c{e}_{self.tags[n]}' not in v0", "self.proven |= self.contract_proven(e, epochlen)",
            "chain_proven = sorted(int(k[2:]) for k in v if k.startswith('pr')"]
    miss = [x for x in need if x not in src]
    return not miss, f'missing {miss}' if miss else '5 resume/authority rules present'


KATS = [('PC1', pc1), ('PC2', pc2), ('PC3', pc3), ('PC4', pc4)]
MUTATIONS = [  # (KAT, file key, old, new, what)
    ('PC1', 'cycle', "    if b[p] != ntx:", "    if False:", 'the tx count byte is not checked'),
    ('PC1', 'cycle', "x[32:40].hex()", "x[32:36].hex()", 'a 4-byte tag read (GT-B32)'),
    ('PC2', 'cycle', "            if final or fl not in tags:", "            if fl not in tags:", 'the final miniblock is credited'),
    ('PC2', 'cycle', "b = min(100 * amt // S, 100) if amt and since + epochlen <= h else 0", "b = min(100 * amt // S, 100) if amt else 0", 'the stake maturity is ignored'),
    ('PC3', 'audit', "    proven = sorted(int(k[2:]) for k in v if k.startswith('pr') and k[2:].isdigit() and int(k[2:]) // epochlen == e)",
     "    proven = sorted(int(k[2:]) for k in v if k.startswith('pr') and k[2:].isdigit() and int(k[2:]) // epochlen == e)[:15]", 'the audit trusts a partial proven list (lesson 38)'),
    ('PC4', 'cycle', "if not done.get(str(e), {}).get('funded'):", "if True:", 'a relaunch funds the epoch again'),
]


def main():
    fails = 0
    res = []
    for k, f in KATS:
        ok, why = f({})
        res.append(ok)
        print(f"{'ok  ' if ok else 'FAIL'} {k}: {why}")
        fails += not ok
    if fails:
        print(f'\nr33 pool-cycle KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    missed = 0
    with tempfile.TemporaryDirectory() as td:
        for i, (k, key, old, new, what) in enumerate(MUTATIONS):
            src = (ROOT / PATHS[key]).read_text()
            if old not in src:
                print(f'MISSED {k}: target not found ({what})')
                missed += 1
                continue
            mp = Path(td) / f'm{i}_{Path(PATHS[key]).name}'
            mp.write_text(src.replace(old, new, 1))
            try:
                ok, _ = dict(KATS)[k]({key: str(mp)})
            except Exception:  # noqa: BLE001 — a crash proves nothing
                ok = True
            caught = not ok
            missed += not caught
            print(f"{'CAUGHT' if caught else 'MISSED'} {k}: {what}")
    print(f'\nr33 pool-cycle KATs: {len(KATS)}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
