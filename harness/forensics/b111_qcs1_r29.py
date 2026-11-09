#!/usr/bin/env python3
"""R29 B111 option (A): Q-CS1 balance-tree census at our anchor 7,498,540 (and at the clone's tip) on an APFS clone of
the mainnet datadir, taken while derod is STOPPED (rft §0.8.9 Q-CS1, §7 B111; the user's decision 2026-11-08:
"B111 (A)"). The live store is never opened: graviton opens a store O_RDWR, so only the clone is ever read.

  python3 -I harness/forensics/b111_qcs1_r29.py clone  --src DATADIR/mainnet --dst CLONE         (derod must be stopped)
  python3 -I harness/forensics/b111_qcs1_r29.py census --clone CLONE --classstats BIN --out FILE [--topo 7498540] [--tip]
                                                         [--scope TEXT]
  python3 -I harness/forensics/b111_qcs1_r29.py remove --clone CLONE
  python3 -I harness/forensics/b111_qcs1_r29.py plan   [--src DATADIR/mainnet] [--dst CLONE]    (prints the sequence)

clone : refuses while any process named derod runs; refuses a destination inside a dero-data* path component or one
        that exists; APFS-clones (cp -c) ONLY balances/ and topo.map (the census reads nothing else), then writes the
        marker QCS1_CLONE into the clone. The source is only read (copy-on-write).
census: maps each topo to its state version through the clone's topo.map (48-byte records: block id 32, state version
        u64 LE, height u64 LE; blockchain/storetopo.go:69-80), refuses a topo below the prune height 7,498,540, runs
        tools/forensics/classstats `census` on clone/balances, and binds the result at 7,498,540 to our recorded
        treehash (the run C end root, harness/runtime/r25_forensics_discovery_20261103.txt:112). Counts only: no key,
        amount or address is written.
remove: deletes the clone, only a directory holding the QCS1_CLONE marker and outside every dero-data* component.
"""
import argparse, hashlib, json, os, re, shutil, struct, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
PRUNED = 7498540                                     # rft: never a state read below prunedheight 7,498,540
RECORD = 48
MARKER = 'QCS1_CLONE'
TREEHASH_SOURCE = ('harness/runtime/r25_forensics_discovery_20261103.txt', 112)
ARCHIVE_SCOPE = 'forensics/r28d/derived/invariant.json'   # the R26 census at topo 7,467,515 (held archive)
R22 = {'count': 2141950, 'version': 337537, 'source': 'memory dero-crypto-audit-r22 (APFS clone of the live store, 2026-10-29)'}


def under_node_store(p):
    """True when any component of p (as given or resolved) starts with 'dero-data' (the live store and siblings)"""
    for q in {str(Path(p)), str(Path(p).resolve())}:
        if any(c.lower().startswith('dero-data') for c in Path(q).parts):
            return True
    return False


def derod_running(pgrep=None):
    """True when a process named exactly derod is running (pgrep -x derod exit 0)"""
    if pgrep is not None:
        return pgrep()
    return subprocess.run(['pgrep', '-x', 'derod'], capture_output=True).returncode == 0


def topo_record(buf, topo):
    """(block id hex, state version, height) of record `topo` in a topo.map byte string, or None past the end"""
    o = topo * RECORD
    if o + RECORD > len(buf):
        return None
    blid, ver, h = buf[o:o + 32], *struct.unpack('<QQ', buf[o + 32:o + RECORD])
    return blid.hex(), ver, h


def last_written(buf):
    """the highest topo whose record holds a block id (a clean record is all zero)"""
    n = len(buf) // RECORD
    for t in range(n - 1, -1, -1):
        if buf[t * RECORD:t * RECORD + 32] != bytes(32):
            return t
    return -1


def recorded_treehash(root=ROOT):
    l = (Path(root) / TREEHASH_SOURCE[0]).read_text().splitlines()[TREEHASH_SOURCE[1] - 1]
    m = re.search(r'topoheight=(\d+) .*treehash=([0-9a-f]{64})', l)
    return {'topo': int(m.group(1)), 'root': m.group(2)} if m else {}


def plan(src, dst):
    return [
        'USER: stop derod (Ctrl-C or `exit` in its console); wait until `pgrep -x derod` prints nothing',
        f'COORDINATOR: python3 -I harness/forensics/b111_qcs1_r29.py clone --src {src} --dst {dst}',
        'USER: start the new derod (r29) as usual; click Allow on the macOS firewall prompt',
        f'COORDINATOR: python3 -I harness/forensics/b111_qcs1_r29.py census --clone {dst} --classstats <classstats binary> '
        '--tip --out harness/runtime/r29_b111_qcs1.json',
        f'COORDINATOR: python3 -I harness/forensics/b111_qcs1_r29.py remove --clone {dst}',
    ]


def cmd_clone(src, dst, pgrep=None, cp=None):
    src, dst = Path(src), Path(dst)
    if derod_running(pgrep):
        raise SystemExit('refused: derod is running (stop it first; the clone must be of a stopped store)')
    if under_node_store(dst):
        raise SystemExit('refused: --dst lies inside a dero-data* path component (never write under a node store)')
    if dst.exists():
        raise SystemExit('refused: --dst exists (a clone is always new)')
    for n in ('balances', 'topo.map'):
        if not (src / n).exists():
            raise SystemExit(f'refused: {src} has no {n} (expected DATADIR/mainnet)')
    dst.mkdir(parents=True)
    run = cp or (lambda a, b: subprocess.run(['cp', '-c', '-R', str(a), str(b)], check=True))
    run(src / 'balances', dst / 'balances')
    run(src / 'topo.map', dst / 'topo.map')
    if derod_running(pgrep):   # started while copying: the clone may be torn
        shutil.rmtree(dst)
        raise SystemExit('refused: derod started during the clone; clone deleted, retry with derod stopped')
    (dst / MARKER).write_text(json.dumps({'kind': 'r29_b111_clone', 'files': ['balances', 'topo.map']}) + '\n')
    return {'clone': str(dst), 'topo_records': (dst / 'topo.map').stat().st_size // RECORD}


def census_versions(buf, topos):
    out = {}
    for t in topos:
        if t < PRUNED:
            raise SystemExit(f'refused: topo {t} is below the prune height {PRUNED} (never a state read below it)')
        r = topo_record(buf, t)
        if r is None or r[0] == '00' * 32:
            raise SystemExit(f'refused: topo {t} has no record in the clone topo.map')
        out[t] = {'blid': r[0], 'version': r[1], 'height': r[2]}
    return out


def run_classstats(binary, balances, version):
    env = dict(os.environ, FORENSICS_STORE_COPY_OK=str(Path(balances).resolve()))
    p = subprocess.run(['nice', '-n', '15', binary], input=json.dumps({'kind': 'census', 'balances': str(balances),
                       'version': version}) + '\n', capture_output=True, text=True, env=env, timeout=7200)
    lines = [l for l in p.stdout.splitlines() if l.strip()]
    return json.loads(lines[-1]) if lines else {'ok': False, 'error': p.stderr[-300:]}


def cmd_census(clone, binary, topos, tip, root=ROOT, runner=run_classstats, scope=None):
    clone = Path(clone)
    if not (clone / MARKER).exists():
        raise SystemExit(f'refused: {clone} has no {MARKER} marker (census reads only a clone made by `clone`)')
    if under_node_store(clone):
        raise SystemExit('refused: the clone lies inside a dero-data* path component')
    buf = (clone / 'topo.map').read_bytes()
    topos = list(topos)
    if tip:
        topos.append(last_written(buf))
    vs = census_versions(buf, sorted(set(topos)))
    th = recorded_treehash(root)
    res = {'kind': 'r29_b111_qcs1', 'scope': {'store': scope or 'APFS clone of the stopped mainnet datadir (balances/, topo.map)',
                                              'pruned_height': PRUNED}, 'census': {}}
    for t, v in vs.items():
        o = runner(binary, clone / 'balances', v['version'])
        o = {k: o.get(k) for k in ('ok', 'error', 'version', 'root', 'balance_tree_keys', 'balance_key_lengths',
                                   'sc_meta_keys', 'sc_tree_keys_total', 'sc_tree_key_lengths', 'sc_trees_nonempty')}
        o.update({'topo': t, 'height': v['height'], 'blid': v['blid']})
        if t == th.get('topo'):
            o['root_check'] = {'recorded_root': th['root'], 'source': f'{TREEHASH_SOURCE[0]}:{TREEHASH_SOURCE[1]}',
                               'equal': o.get('root') == th['root']}
        res['census'][str(t)] = o
    a = json.loads((Path(root) / ARCHIVE_SCOPE).read_text()).get('Q-CS1', {})
    anc = res['census'].get(str(PRUNED), {})
    res['comparisons'] = {
        'held_archive_7467515': {'balance_tree_keys': a.get('balance_tree_keys'), 'sc_meta_keys': a.get('sc_meta_keys'),
                                 'sc_tree_keys_total': a.get('sc_tree_keys_total'), 'source': ARCHIVE_SCOPE,
                                 'anchor_minus_archive': (anc.get('balance_tree_keys') - a['balance_tree_keys'])
                                 if anc.get('ok') and isinstance(anc.get('balance_tree_keys'), int)
                                 and isinstance(a.get('balance_tree_keys'), int) else 'pending'},
        'r22': dict(R22, class_='EXT to this census (an earlier round, live store at a later version)')}
    res['status'] = ('answered at 7,498,540' if anc.get('ok') and (anc.get('root_check') or {}).get('equal') else
                     'NOT answered: the census at 7,498,540 failed or its root differs from the recorded treehash')
    return res


def cmd_remove(clone):
    clone = Path(clone)
    if under_node_store(clone):
        raise SystemExit('refused: inside a dero-data* path component')
    if not (clone / MARKER).exists():
        raise SystemExit(f'refused: {clone} has no {MARKER} marker (remove deletes only a clone made by `clone`)')
    shutil.rmtree(clone)
    return {'removed': str(clone)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest='cmd', required=True)
    p = sp.add_parser('clone'); p.add_argument('--src', required=True); p.add_argument('--dst', required=True)
    p = sp.add_parser('census'); p.add_argument('--clone', required=True); p.add_argument('--classstats', required=True)
    p.add_argument('--topo', type=int, action='append'); p.add_argument('--tip', action='store_true'); p.add_argument('--out', required=True)
    p.add_argument('--scope', help='what the clone is a clone of (default: the stopped mainnet datadir)')
    p = sp.add_parser('remove'); p.add_argument('--clone', required=True)
    p = sp.add_parser('plan'); p.add_argument('--src', default='<DATADIR>/mainnet'); p.add_argument('--dst', default='<CLONE>')
    a = ap.parse_args(argv)
    if a.cmd == 'plan':
        print('\n'.join(plan(a.src, a.dst)))
        return 0
    if a.cmd == 'clone':
        print(json.dumps(cmd_clone(a.src, a.dst)))
        return 0
    if a.cmd == 'remove':
        print(json.dumps(cmd_remove(a.clone)))
        return 0
    res = cmd_census(a.clone, a.classstats, a.topo or [PRUNED], a.tip, scope=a.scope)
    txt = json.dumps(res, indent=1, sort_keys=True) + '\n'
    Path(a.out).write_text(txt)
    print(res['status'], hashlib.sha256(txt.encode()).hexdigest()[:16])
    return 0 if res['status'].startswith('answered') else 4


if __name__ == '__main__':
    sys.exit(main())
