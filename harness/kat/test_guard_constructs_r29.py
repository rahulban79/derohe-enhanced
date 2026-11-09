#!/usr/bin/env python3
"""KATs for the two consensus_guard constructs the user's R29 decisions allowed (dero-rft §7 B19 (a), B144 (a)).

GC1 the tree: guard PASS and both constructs used (mempool-milli-fee-rank, rpc-money-copy-128bit).
GC2 each construct is load-bearing: with it removed from ALLOWED the guard FAILS on its own file (S1 fails without
    the entry, passes with it).
GC3 scope ('files'): the B144 diff fed to the guard under another consensus file name FAILS.
GC4 'moved' cancels only lines that only moved: the B19 diff plus one more deleted line ('return true') FAILS.
GC5 'minus' is required: the B19 plus-lines with the old sort line KEPT (both comparators) FAIL.
GC6 an unrelated state change in a construct's own file FAILS (mempool.go: the integer FeesPerByte assignment
    changed alongside the construct).
GC7 'moved' cancels only its listed lines: moving another statement inside mempool.go (pool.modified = true placed
    before the store) FAILS.
Each negative case feeds the guard a stubbed git/READ; the live tree is never written.
  python3 -I harness/kat/test_guard_constructs_r29.py   (exit 0 = every case behaves)
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import consensus_guard as G

MP, RW = 'blockchain/mempool/mempool.go', 'rpc/wallet_rpc.go'


def run_with(files, new_text, old_text):
    """evaluate() on a stubbed tree: `files` changed; READ gives new_text[f], git show gives old_text[f]"""
    real_git, real_read = G.git, G.READ

    def git(*a):
        if a[0] == 'diff':
            return ''.join(f'M\t{f}\n' for f in files)
        if a[0] == 'show':
            return old_text[a[1].split(':', 1)[1]]
        return ''
    G.git, G.READ = git, (lambda f: new_text[f])
    try:
        return G.evaluate()
    finally:
        G.git, G.READ = real_git, real_read


def main():
    bad = []
    base = G.evaluate.__defaults__[0]
    old = {f: G.git('show', f'{base}:{f}') for f in (MP, RW)}
    new = {f: G.READ(f) for f in (MP, RW)}

    def case(name, cond, detail=''):
        print(f"  {'ok ' if cond else 'BAD'} {name} {detail}")
        if not cond:
            bad.append(name)

    r = G.evaluate()
    case('GC1 tree PASS with both constructs used', r['ok'] and {'mempool-milli-fee-rank', 'rpc-money-copy-128bit'} <= set(r['allowed_used']),
         f"ok={r['ok']} used={sorted(set(r['allowed_used']))}")
    for name, f in (('mempool-milli-fee-rank', MP), ('rpc-money-copy-128bit', RW)):
        saved = G.ALLOWED.pop(name)
        try:
            r2 = run_with([f], new, old)
        finally:
            G.ALLOWED[name] = saved
        case(f'GC2 without {name} the guard FAILS on {f}', not r2['ok'] and any(v['file'] == f for v in r2['violations']))
    other = 'rpc/rpc.go'
    r3 = run_with([other], {other: new[RW]}, {other: old[RW]})
    case('GC3 the B144 diff under another file name FAILS (scope)', not r3['ok'])
    mp4 = new[MP].replace('\t\treturn true\n\t})\n\n\t// inverted', '\t})\n\n\t// inverted', 1)
    assert mp4 != new[MP], 'GC4 anchor'
    r4 = run_with([MP], {MP: mp4}, old)
    case("GC4 one more deleted line next to the construct FAILS ('moved' is not a wildcard)", not r4['ok'])
    keep = 'sort.SliceStable(data, func(i, j int) bool { return data[i].FeesPerByte > data[j].FeesPerByte })'
    mp5 = new[MP].replace('\tsort.SliceStable(data, func(i, j int) bool { return data[i].MilliFeesPerByte', '\t' + keep + '\n\tsort.SliceStable(data, func(i, j int) bool { return data[i].MilliFeesPerByte', 1)
    assert mp5 != new[MP], 'GC5 anchor'
    r5 = run_with([MP], {MP: mp5}, old)
    case('GC5 the old comparator kept beside the new one FAILS (minus required)', not r5['ok'])
    mp6 = new[MP].replace('object.FEEperBYTE = tx.Fees() / object.Size', 'object.FEEperBYTE = tx.Fees() / (object.Size + 1)', 1)
    assert mp6 != new[MP], 'GC6 anchor'
    r6 = run_with([MP], {MP: mp6}, old)
    case("GC6 an unrelated change in the construct's file FAILS", not r6['ok'])
    mv = '\tpool.txs.Store(tx_hash, &object)\n\tpool.modified = true // pool has been modified\n'
    assert new[MP].count(mv) == 1, 'GC7 anchor'
    mp7 = new[MP].replace(mv, '\tpool.modified = true // pool has been modified\n\tpool.txs.Store(tx_hash, &object)\n', 1)
    r7 = run_with([MP], {MP: mp7}, old)
    case("GC7 another moved statement in the construct's file FAILS ('moved' is a list)", not r7['ok'])
    print('r29 guard-construct KATs:', 'PASS 7/7' if not bad else f'FAIL {bad}')
    return 0 if not bad else 3


if __name__ == '__main__':
    sys.exit(main())
