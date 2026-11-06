#!/usr/bin/env python3
"""mine_inventory.py — the measured package map and the first-party import graph.

Every number is counted from the filesystem (corpus/pkgindex.json, built by a walk); every row is anchored on
the `package <name>` clause of the package's first file, so the row cannot outlive the package. Import edges
are read from the import blocks themselves and anchored on the import line that proves the edge.
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import collections, json, re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import minelib as M

MOD = 'github.com/deroproject/derohe/'

# role: what the package is for, in the project's own vocabulary. The numbers come from the walk, never from here.
ROLE = {
 'astrobwt':    'AstroBWT proof-of-work: Burrows-Wheeler suffix-array hashing, the CPU-bound half of mining.',
 'block':       'The block and miniblock wire objects: serialisation, the 48-byte miniblock, the miniblock DAG.',
 'blockchain':  'Consensus core: block admission, difficulty, the balance tree, tx execution, mempool and regpool.',
 'cmd':         'All shipped binaries: derod, dero-wallet-cli, dero-miner, explorer, simulator and the tools.',
 'config':      'Chain configuration and the version string: block time, ring sizes, ports, hard-fork heights.',
 'cryptography': 'The HE primitives: bn256 pairing curve, bulletproofs range proofs, Schnorr/ring signatures.',
 'dvm':         'The DERO Virtual Machine: smart-contract parsing, type checking and the execution simulator.',
 'errormsg':    'Shared sentinel errors used across packages so comparisons stay identity-based.',
 'globals':     'Process-wide state: the logger, the chosen network, argument parsing and the panic recover chain.',
 'glue':        'The seam between the daemon RPC layer and the blockchain object.',
 'metrics':     'Counters and timers the daemon exposes for its own health.',
 'p2p':         'The peer-to-peer layer over KCP/UDP: handshake, chain sync, object fetch, broadcast, bans.',
 'pow':         'The proof-of-work entry point the block verifier calls.',
 'premine':     'The genesis premine constant.',
 'proof':       'Transaction proof decoding, used to prove a payment to a third party.',
 'rpc':         'The wire types of the JSON-RPC API shared by daemon and wallet.',
 'transaction': 'The transaction object: statement, proof, payloads and their serialisation.',
 'walletapi':   'Everything a wallet does: key derivation, balance decoding, tx building, daemon sync, the RPC server.',
}


def main():
    idx = M.pkgindex()
    rows, unv = [], []
    for pkg, d in sorted(idx['packages'].items(), key=lambda kv: -kv[1]['loc']):
        # The `package X` clause is the natural anchor, but for short names it is under the resolver's
        # 12-character floor ("package p2p" is 11). Fall back to the package's first declaration, which is
        # both long enough and specific to this package.
        a = None
        for f_ in [d['first_file']] + M.go_files(pkg)[:6]:
            if not f_:
                continue
            for ln, line in M.grep(f_, r'^package\s+\w+'):
                if len(M.norm(line)) >= M.MIN_Q:
                    a = {'file': f_, 'quote': line.strip(), 'line': ln}
                    break
            if a:
                break
        if not a:
            for name, f_, ln, kind, pk in M.tags():
                if pk == pkg and kind in ('func', 'type', 'const', 'var'):
                    raw, _ = M.lines(f_)
                    if raw and len(M.norm(raw[ln - 1])) >= M.MIN_Q:
                        a = {'file': f_, 'quote': raw[ln - 1].strip(), 'line': ln}
                        break
        if not a:
            unv.append({'title': f'package {pkg}', 'why': 'no package clause found to anchor on'})
            continue
        rows.append({'id': f'inv-{pkg}', 'section': 'packages', 'title': pkg, 'class': 'SRC',
                     'claim': f"{ROLE.get(pkg, 'first-party package')} Measured: {d['files']} source files, "
                              f"{d['loc']:,} lines, {d['test_files']} test files ({d['test_loc']:,} lines) in {len(d['dirs'])} directories.",
                     'pkg': pkg, 'files': d['files'], 'loc': d['loc'], 'test_files': d['test_files'],
                     'test_loc': d['test_loc'], 'dirs': len(d['dirs']),
                     'evidence': [a]})

    # ---- first-party import graph: an edge exists only where an import line proves it
    edges = collections.Counter()
    proof = {}
    for pkg in idx['packages']:
        for f in M.go_files(pkg):
            for ln, line in M.grep(f, re.escape(MOD)):
                m = re.search(re.escape(MOD) + r'([a-z0-9_/]+)', line)
                if not m:
                    continue
                dst = m.group(1).split('/')[0]
                if dst == pkg or dst not in idx['packages']:
                    continue
                edges[(pkg, dst)] += 1
                proof.setdefault((pkg, dst), (f, line.strip(), ln))
    for (src, dst), n in sorted(edges.items(), key=lambda kv: (-kv[1], kv[0])):
        f, q, ln = proof[(src, dst)]
        rows.append({'id': f'dep-{src}-{dst}', 'section': 'imports', 'title': f'{src} → {dst}', 'class': 'SRC',
                     'claim': f'{src} imports {dst} in {n} file-level import statement(s); the first is in {f}.',
                     'from': src, 'to': dst, 'count': n,
                     'evidence': [{'file': f, 'quote': q, 'line': ln}]})

    # ---- vendored third-party weight (EXT). go.mod here is 2 lines (no require block), so the proof that a
    # vendored module is really linked in is the first-party import line that pulls it in. No importer, no row.
    importers = collections.defaultdict(list)
    for pkg in idx['packages']:
        for f in M.go_files(pkg):
            for ln, line in M.grep(f, r'"(github\.com|golang\.org|go\.etcd\.io|go\.uber\.org|gopkg\.in|bitbucket\.org)/'):
                m = re.search(r'"((?:github\.com|golang\.org|go\.etcd\.io|go\.uber\.org|gopkg\.in|bitbucket\.org)/[^"]+)"', line)
                if m and not m.group(1).startswith(MOD):
                    importers[m.group(1)].append((f, line.strip(), ln, pkg))
    for mod, d in sorted(idx['vendor'].items(), key=lambda kv: -kv[1]['loc'])[:16]:
        hit = next((v for k, v in importers.items() if k == mod or k.startswith(mod + '/')), None)
        if not hit:
            unv.append({'title': f'vendor {mod}', 'why': 'vendored but no first-party import line found — '
                                                         'it is a transitive dependency of another vendored module'})
            continue
        f, q, ln, pkg = hit[0]
        # second anchor, inside the vendored module: without it the row's only proof is a first-party import
        # line, which is an SRC fact, and the resolver would (correctly) refuse the EXT class.
        own = None
        for g in sorted((M.ROOT / 'vendor' / mod).rglob('*.go'))[:40]:
            gr = str(g.relative_to(M.ROOT))
            for ln2, line2 in M.grep(gr, r'^package\s+\w+'):
                if len(M.norm(line2)) >= M.MIN_Q:
                    own = {'file': gr, 'quote': line2.strip(), 'line': ln2}
                    break
            if own:
                break
        if not own:
            unv.append({'title': f'vendor {mod}', 'why': 'no package clause of 12+ characters inside the module '
                                                         'to prove the EXT class'})
            continue
        rows.append({'id': 'vend-' + re.sub(r'[^a-z0-9]+', '-', mod.lower()), 'section': 'vendor',
                     'title': mod, 'class': 'EXT',
                     'claim': f'Vendored third-party module linked into the DERO binaries: {d["files"]} Go files, '
                              f'{d["loc"]:,} lines. First-party importers: {len({h[3] for h in hit})} package(s), '
                              f'{len(hit)} import line(s).',
                     'module': mod, 'files': d['files'], 'loc': d['loc'], 'importers': sorted({h[3] for h in hit}),
                     'evidence': [own, {'file': f, 'quote': q, 'line': ln}]})
    M.emit('inventory', rows, unv, 'mine_inventory.py')


if __name__ == '__main__':
    main()
