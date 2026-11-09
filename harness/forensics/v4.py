#!/usr/bin/env python3
"""r28d forensics dataset v4 `forensics/r28d/` (rft §0.8.3, §0.8.9, §6 step 3a; backlog B180, §8 R28d plan M-4). v4 is
a CORRECTION of the sealed v3 (`supersedes: ["r28"]`); v1, v2 and v3 are never rewritten.

What v4 changes against v3, and why (B180, from the DEROFDN community-dev evaluation, CD1-CD3, 2026-11-06):
  * derived/dc1_structure.json  NEW. A structural census of the 75 DC1 txs, counts only: for each held DC1 body the
                                ring size of every payload (Statement.RingSize) and the payload format byte (the
                                unencrypted RPCType: 0 = the legacy format, 1 = the _V2 format; transaction/
                                transaction.go), read by the node's own decoder (tools/forensics `tx`), split by
                                whether the TXID is carried by one RAW block or by two (derived/inclusions.json). No
                                amount, address or TXID is written (rft §9; D4: amount recovery is out of scope).
  * derived/fq.json             FQ2 gains the structural criterion S-RT (every payload ring 2 AND the legacy payload
                                format), the precondition an EXT explainer relies on for readable amounts, with a
                                dated correction: FQ2's "0 of 75" was complete for P1 and S-R22 only. DC1-obs is
                                unchanged: S-RT is a precondition, not an observation of an amount.
  * derived/walls.json,         R29 (B107): v3's two files with every row's `class` slot filled by the rules of
    derived/inclusions.json     TAG_RULES (rft §0.8.9 rule 8: every derived row names its class); every other byte of
                                each row is v3's. G32 (bounds.py check_rows_r29) and audit2 D2-28 re-derive the class
                                of every row independently.
Inherited unchanged from v3 (bytes and SHA-256 checked against v3's manifest): every raw/ file and every other
derived/ file. The replay re-derives v3's derived set with v3.derive (pinned, used, never edited), then the v4
files, and checks every SHA-256; v3's fq.json (the input of the FQ2 correction) is pinned in `inputs`.

  python3 -I harness/forensics/v4.py build    [--dataset forensics/r28d] [--store DIR]
  python3 -I harness/forensics/v4.py manifest [--dataset forensics/r28d] [--store DIR]
  python3 -I harness/forensics/v4.py replay   forensics/r28d [--store DIR] [--record harness/runtime/forensics_replay.json]
Read-only towards every node and store; nothing here talks to a network.
"""
import argparse, json, os, platform, shutil, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import v3  # noqa: E402  (pinned by the sealed v3; used, never edited)
import pins as P  # noqa: E402
import classes as CL  # noqa: E402  (hf3_txids: the table parse v2/v3 use; classes.py is a sealed tool, never edited)

v2 = v3.v2
VERSION = 4
BASE = 'forensics/r28'
CORRECTION_DATE = '2026-11-06'
TAGGED = ['derived/walls.json', 'derived/inclusions.json']   # R29 B107: v3's rows with the class slot filled
NEW = ['derived/dc1_structure.json', 'derived/fq.json'] + TAGGED
TOOLS = v3.TOOLS + ['harness/forensics/v4.py']
# fq.json is re-derived by v4 (the FQ2 correction is a pure function of v3's fq.json and dc1_structure.json), so it is
# no longer a class file here; the three forensics-classes outputs stay pinned, not re-derived
CLASS_FILES = {k: v for k, v in v3.CLASS_FILES.items() if k != 'derived/fq.json'}
DEFAULT_STORE = v3.DEFAULT_STORE
SRT = 'S-RT'


def sha(b):
    return v2.sha(b)


def fsha(p):
    return v2.fsha(p)


def inherit_list(root=ROOT):
    """every v3 file v4 takes byte for byte: raw/ and derived/ less the files v4 writes (audit/, replay/ are v3's own)"""
    bm = json.loads((Path(root) / BASE / 'manifest.json').read_text())['files']
    return sorted(k for k in bm if k.startswith(('raw/', 'derived/')) and k not in NEW)


# ------------------------------------------------------------------------------------------------ build
def inherit(ds, root=ROOT):
    """copy v3's files byte for byte; each must equal v3's manifest entry and v3 must be sealed. {rel: sha256}"""
    ds, b = Path(ds), Path(root) / BASE
    led = json.loads((Path(root) / 'forensics' / 'ledger.json').read_text())
    if not any(v['version'] == Path(BASE).name and v.get('sealed') for v in led['versions']):
        raise SystemExit(f'refused: {BASE} is not sealed (seal it first, rft §6 step 3a)')
    bm = json.loads((b / 'manifest.json').read_text())['files']
    out = {}
    for rel in inherit_list(root):
        src = b / rel
        if not src.exists() or fsha(src) != bm.get(rel):
            raise SystemExit(f'refused: {BASE}/{rel} differs from its manifest (inherit only sealed bytes)')
        dst = ds / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
        out[rel] = bm[rel]
    return out


def dc1_structure(txs_gz, inclusions, stores, work):
    """the structural census of the DC1 txs (counts only) from derived txs rows, the inclusions file and the held
    bodies (each re-hashed to its body_sha256), decoded by the node's own decoder. Returns the JSON object."""
    rows = [r for r in (json.loads(l) for l in v2.gzip.decompress(txs_gz).decode().splitlines() if l.strip())
            if r.get('class') == 'DC1']
    multi = {r['txid'] for r in json.loads(inclusions)['rows'] if len(r.get('heights') or []) > 1}
    items, missing = [], 0
    for r in rows:
        b = v2.read_store(stores, r['body_sha256'])
        if b is None:
            missing += 1
            continue
        items.append((r['txid'], 'tx', b))
    dec = v2.decode(v2.build_decoder(work), items, work)
    counts, decoded, undecodable = {}, 0, 0
    for r in rows:
        d = dec.get(r['txid'])
        if d is None:
            continue
        if not d.get('ok'):
            undecodable += 1
            continue
        decoded += 1
        ps = d.get('payloads') or []
        rings = sorted({p['ring_size'] for p in ps})
        fmts = sorted({p['rpc_type'] for p in ps})
        key = '+'.join([f'ring{x}' for x in rings] + [f'rpctype{x}' for x in fmts])
        group = 'two_inclusions' if r['txid'] in multi else 'single_inclusion'
        for k in (key, f'{group}:{key}'):
            counts[k] = counts.get(k, 0) + 1
        if rings == [2] and fmts == [0]:
            for k in ('criterion', f'criterion:{group}'):
                counts[k] = counts.get(k, 0) + 1
    n2 = sum(1 for r in rows if r['txid'] in multi)
    return {
        'class': 'DC1', 'evidence_class': ('DERIVED (the node decoder tools/forensics `tx` over the held DC1 bodies: '
                                           'ring size = Statement.RingSize, payload format = the unencrypted RPCType '
                                           'byte, transaction/transaction.go)'),
        'question': f'FQ2 structural criterion {SRT}: how many DC1 txs carry every payload at ring 2 with the legacy '
                    'payload format (RPCType 0), the precondition an EXT explainer relies on for readable amounts',
        'scope': {'heights': [7415466, 7497942], 'txs': 'the DC1 rows of derived/txs.jsonl.gz'},
        'coverage': {'num': decoded, 'den': len(rows), 'num_anchor': 'held bodies decoded by the node decoder',
                     'den_anchor': 'derived/txs.jsonl.gz class DC1'},
        'bodies': {'dc1_rows': len(rows), 'held': len(items), 'missing': missing, 'decoded': decoded,
                   'undecodable': undecodable},
        'groups': {'two_inclusions': n2, 'single_inclusion': len(rows) - n2,
                   'rule': 'two_inclusions = the TXID is carried by more than one RAW block (derived/inclusions.json rows)'},
        'counts': dict(sorted(counts.items())),
        'criterion': {'id': SRT, 'what': 'every payload ring 2 and the legacy payload format (RPCType 0)',
                      'result': f"{counts.get('criterion', 0)} of {len(rows)}",
                      'two_inclusions': f"{counts.get('criterion:two_inclusions', 0)} of {n2}",
                      'single_inclusion': f"{counts.get('criterion:single_inclusion', 0)} of {len(rows) - n2}"},
        'note': ('counts only: no amount, address or TXID is written; amount recovery is out of scope (rft §9; '
                 'decision D4); the structural precondition is not an observation of an amount'),
    }


def correct_fq(fq_v3, dc1):
    """v3's fq.json plus FQ2's S-RT criterion and its dated correction (pure)"""
    fq = json.loads(fq_v3)
    q = fq['FQ2']
    c = dc1['criterion']
    q['criteria'][SRT] = {
        'anchor': 'derived/dc1_structure.json criterion',
        'result': f"{c['result']} carry it ({c['two_inclusions']} two-inclusion, {c['single_inclusion']} single)",
        'scope': f"{dc1['bodies']['decoded']} of {dc1['bodies']['dc1_rows']} DC1 bodies decoded by the node decoder",
        'what': ('the structural precondition an EXT explainer relies on for readable amounts: every payload ring 2 and '
                 'the legacy payload format (RPCType 0); a precondition, not an observed amount'),
    }
    q.setdefault('corrections', []).append({
        'date': CORRECTION_DATE, 'version': 'r28d', 'row': 'rft §7 B180',
        'what': ('FQ2 tested P1 and S-R22 only, so its 0 of 75 was complete for those two criteria, not for every '
                 f'structural criterion; {SRT} is added (counts only). DC1-obs is unchanged (coverage dc1_obs 0): '
                 f'{SRT} is a precondition, not an observation of an amount (amount recovery is out of scope, rft §9, D4)'),
    })
    return v2.dump(fq)


# ------------------------------------------------------------------------------------------------ R29 B107 row classes
SLOTS = (None, 'pending', 'pending: defect class')
TAG_RULES = {
    'wall_row': 'DC1 when the block carries an HF3 table TXID (hf3_table_txs non-empty), else DC3 (a block-level row '
                'states public-value identities, classes.tag_block)',
    'replay_stops': 'DC1 when a stopped tx is an HF3 table TXID, else DC3 (the stop is a block-level fact about this code '
                    'and that state; a stop that persisted through the HF3 entry would be DC0, rft §0.8.9)',
    'inclusion_row': 'DC1 when the TXID is in the HF3 table, else DC0 (a duplicate outside the table fits no class)',
    'inclusions': 'DC0 when any row is DC0, else DC1 (the file names one class)',
}


def wall_class(row, table):
    return 'DC1' if any(t in table for t in (row.get('hf3_table_txs') or [])) else 'DC3'


def stops_class(stops, table):
    return 'DC1' if any((r or {}).get('txid') in table for r in (stops.get('runs') or {}).values()) else 'DC3'


def inclusion_class(row, table):
    return 'DC1' if row.get('txid') in table else 'DC0'


def _fill(o, cls):
    if o.get('class') in SLOTS:
        o['class'] = cls
    return o


def tag_walls(b, table):
    """walls.json bytes -> the same with every wall row and replay_stops classed (only slot values are filled)"""
    w = json.loads(b)
    for k, v in w.items():
        if k.startswith('wall') and isinstance(v, dict):
            for r in v.get('rows') or []:
                _fill(r, wall_class(r, table))
    if isinstance(w.get('replay_stops'), dict):
        _fill(w['replay_stops'], stops_class(w['replay_stops'], table))
    w['class_rules'] = {k: TAG_RULES[k] for k in ('wall_row', 'replay_stops')}
    return v2.dump(w)


def tag_inclusions(b, table):
    """inclusions.json bytes -> the same with every row and the file classed"""
    i = json.loads(b)
    for r in i.get('rows') or []:
        _fill(r, inclusion_class(r, table))
    _fill(i, 'DC0' if any(r.get('class') == 'DC0' for r in i.get('rows') or []) else 'DC1')
    i['class_rules'] = {k: TAG_RULES[k] for k in ('inclusion_row', 'inclusions')}
    return v2.dump(i)


def derive(ds, stores, out, work, root=ROOT):
    """v3.derive (pinned) over v4's raw/, then the v4 files from its outputs; returns {rel: bytes}"""
    files = v3.derive(ds, stores, out, work, root)
    table = CL.hf3_txids(root)
    files['derived/walls.json'] = tag_walls(files['derived/walls.json'], table)
    files['derived/inclusions.json'] = tag_inclusions(files['derived/inclusions.json'], table)
    dc1 = dc1_structure(files['derived/txs.jsonl.gz'], files['derived/inclusions.json'], stores, work)
    files['derived/dc1_structure.json'] = v2.dump(dc1)
    files['derived/fq.json'] = correct_fq((Path(root) / BASE / 'derived/fq.json').read_bytes(), dc1)
    for rel in NEW:
        p = Path(out) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(files[rel])
    return files


def cmd_build(a):
    ds = Path(a.dataset)
    if (ds / 'manifest.json').exists():
        led = json.loads((ROOT / 'forensics' / 'ledger.json').read_text())
        if any(v['version'] == ds.name and v.get('sealed') for v in led['versions']):
            raise SystemExit(f'refused: {ds.name} is sealed')
    ds.mkdir(parents=True, exist_ok=True)
    inh = inherit(ds)
    work = Path(tempfile.mkdtemp(prefix='v4d_'))
    try:
        files = derive(ds, [a.store], work / 'out', work)
        for rel in NEW:
            (ds / rel).write_bytes(files[rel])
        same = {k: sha(files[k]) == fsha(ds / k) for k in files if k not in NEW and (ds / k).exists()}
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if not all(same.values()):
        raise SystemExit(f'refused: v3.derive over the inherited raw/ differs from v3: {sorted(k for k, v in same.items() if not v)}')
    print(json.dumps({'inherited': len(inh), 'rederived_equal_v3': len(same),
                      'new': {k: sha(files[k])[:16] for k in NEW}}, indent=1))


# ------------------------------------------------------------------------------------------------ manifest / replay
def rederived(files):
    return {k: h for k, h in files.items() if k.startswith('derived/') and k not in CLASS_FILES}


def content_pins(root=ROOT, lister=None):
    """v3's pin rules (pins.py) over v4's replay tools and every decoder build input, the HF3 table"""
    root = Path(root)
    e = subprocess.run(['go', 'env', 'GOOS', 'GOARCH'], capture_output=True, text=True, cwd=str(root)).stdout.split()
    dec = (lister or P.decoder_input_paths)(root, e[0], e[1])
    cp = {'replay_tools': {t: P.file_sha(root, t) for t in TOOLS},
          'decoder_inputs': {t: P.file_sha(root, t) for t in dec},
          'decoder_platform': f'{e[0]}/{e[1]}', 'hf3_table': {P.HF3_TABLE: P.file_sha(root, P.HF3_TABLE)}, 'cited_lines': {},
          'normalized': {k: 'the `var Version = ...` line is replaced by a placeholder before hashing' for k in P.NORMALIZE if k in dec}}
    cp['aggregate_sha256'] = P.aggregate(cp)
    return cp


REPLAY_SH = '''#!/bin/sh
# forensics/r28d replay (rft §0.8.3, gate G28): ONE command checks the content pins (tools + decoder inputs), re-derives
# every derived/ file of dataset v4 from raw/ (v3.derive, then the v4 files) into a scratch dir and checks every
# SHA-256. Tier B blobs (tx bodies) are read from $FORENSICS_R28_STORE (default: v2's store, shared, never written).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
store=${FORENSICS_R28_STORE:-$HOME/derohe-persist/forensics_raw_r26}
exec nice -n 15 python3 -I "$root/harness/forensics/v4.py" replay "$root/forensics/r28d" --store "$store" "$@"
'''


def inputs(root=ROOT):
    """v1 inputs v3 reads, plus v3's fq.json (the input of the FQ2 correction), pinned by SHA-256"""
    out = {t: fsha(Path(root) / t) for t in v2.V1_INPUTS}
    out[BASE + '/derived/fq.json'] = fsha(Path(root) / BASE / 'derived/fq.json')
    return out


def cmd_manifest(a, root=ROOT):
    ds = Path(a.dataset)
    files = v2.dataset_files(ds)
    (ds / 'replay').mkdir(exist_ok=True)
    (ds / 'replay/expected.sha256').write_text(''.join(f'{h}  {k}\n' for k, h in sorted(rederived(files).items())))
    (ds / 'replay/replay.sh').write_text(REPLAY_SH)
    os.chmod(ds / 'replay/replay.sh', 0o755)
    files = v2.dataset_files(ds)
    shas = [r['sha256'] for r in v2.read_gz(ds / 'raw/tx_bodies.jsonl.gz')]
    idx, n = v2.store_index([a.store], shas)
    git = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
    gov = subprocess.run(['go', 'version'], capture_output=True, text=True).stdout.strip()
    bm = json.loads((Path(root) / BASE / 'manifest.json').read_text())
    m = {'dataset': ds.name, 'version': VERSION, 'supersedes': [Path(BASE).name], 'files': files,
         'tools': {t: fsha(Path(root) / t) for t in TOOLS}, 'hf3_table': {'file': v2.HF3, 'sha256': fsha(Path(root) / v2.HF3)},
         'inputs': inputs(root),
         'inputs_rule': ('v1 files and v3 derived/fq.json read by path and pinned by SHA-256; v1..v3 are never rewritten '
                         '(rft §0.8.1 rule 4)'),
         'inherited': {'from': BASE, 'base_manifest_sha256': fsha(Path(root) / BASE / 'manifest.json'),
                       'files': {k: bm['files'][k] for k in inherit_list(root)}},
         'supersedes_reason': ('corrects v3: FQ2 tested P1 and S-R22 only; the structural criterion S-RT (ring 2 and the '
                               'legacy payload format) is added as counts (derived/dc1_structure.json) with a dated FQ2 '
                               'correction; DC1-obs unchanged (B180); R29: walls.json and inclusions.json rows carry '
                               'their defect class (B107, TAG_RULES)'),
         'content_pins': content_pins(root),
         'tierB_store': {'location': '$FORENSICS_R28_STORE (tier B store outside git, shared with v2/v3, read-only; a label, not a path)',
                         'tx_bodies': n, 'tx_index_sha256': idx},
         'git_base_commit': git, 'go': gov, 'python': platform.python_version(),
         'replay_tool': 'harness/forensics/v4.py',
         'replay': {'command': f'sh forensics/{ds.name}/replay/replay.sh [--record harness/runtime/forensics_replay.json]',
                    'expected': 'replay/expected.sha256',
                    'node_replay': ('raw/replay_runs/<run>/ are outputs of tools/forensics/a2 replay (inherited from v3); '
                                    're-hashed here, re-run with a2 (about 20 minutes), not re-derived by Python')},
         'class_files': {k: v for k, v in sorted(CLASS_FILES.items()) if k in files},
         'class_slot': '`class` on every per-tx/per-block record = the defect class of rft §0.8.9 (tagged from the first '
                       'write, inherited from v3); `evidence_class` = RAW/DERIVED/EXT (§0.8.2)'}
    (ds / 'manifest.json').write_bytes(v2.dump(m))
    print('manifest', sha((ds / 'manifest.json').read_bytes()), len(files), 'files')


def replay(ds, store, root=ROOT, lister=None):
    """v3.replay's steps with v4's derive, v4's inputs and the content pins (a changed decoder input FAILS before any
    derivation)"""
    ds = Path(ds)
    mb = (ds / 'manifest.json').read_bytes()
    m = json.loads(mb)
    rep = {'dataset': ds.name, 'manifest_sha256': sha(mb), 'fail_reasons': [], 'steps': []}
    f = rep['fail_reasons']
    pf = P.check(m.get('content_pins'), root, lister)
    rep['content_pins'] = {'equal': not pf, 'failures': pf[:20], 'aggregate_sha256': (m.get('content_pins') or {}).get('aggregate_sha256')}
    f += [f'content pins: {x}' for x in pf[:5]]
    for rel, h in sorted(m['files'].items()):
        p = ds / rel
        if not p.exists() or fsha(p) != h:
            f.append(f'manifest: {rel} missing or changed')
    for rel in sorted(set(v2.dataset_files(ds)) - set(m['files'])):
        f.append(f'manifest: unlisted {rel}')
    for t, h in sorted(m['tools'].items()):
        if not (Path(root) / t).exists() or fsha(Path(root) / t) != h:
            f.append(f'tool changed: {t}')
    for t, h in sorted(m['inputs'].items()):
        if not (Path(root) / t).exists() or fsha(Path(root) / t) != h:
            f.append(f'pinned input changed: {t}')
    for t, h in sorted((m.get('inherited') or {}).get('files', {}).items()):
        if m['files'].get(t) != h:
            f.append(f'inherited file differs from v3: {t}')
    rep['steps'].append('manifest')
    stores = [store] if store else []
    shas = [r['sha256'] for r in v2.read_gz(ds / 'raw/tx_bodies.jsonl.gz')]
    idx, n = v2.store_index(stores, shas)
    full = n == len(shas) and idx == m['tierB_store']['tx_index_sha256']
    rep['store'] = {'tx_bodies_present': n, 'tx_bodies_listed': len(shas), 'index_equal': idx == m['tierB_store']['tx_index_sha256']}
    rep['steps'].append('store')
    exp = rederived(m['files'])
    if (ds / 'replay/expected.sha256').read_text() != ''.join(f'{h}  {k}\n' for k, h in sorted(exp.items())):
        f.append('expected.sha256 differs from the manifest')
    rd = {'expected': len(exp), 'equal': 0, 'mismatch': [], 'missing': [], 'extra': [], 'mode': 'full' if full else 'partial'}
    if full and not pf:
        work = Path(tempfile.mkdtemp(prefix='v4r_'))
        try:
            out = derive(ds, stores, work / 'out', work, root)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        out = {k: v for k, v in out.items() if k.startswith('derived/') and k not in CLASS_FILES}
        for k, h in sorted(exp.items()):
            if k not in out:
                rd['missing'].append(k)
            elif sha(out[k]) != h:
                rd['mismatch'].append(k)
            else:
                rd['equal'] += 1
        rd['extra'] = sorted(set(out) - set(exp))
        rd['rederived'] = len(out)
        if rd['mismatch'] or rd['missing'] or rd['extra']:
            f.append(f"re-derive: {len(rd['mismatch'])} mismatch, {len(rd['missing'])} missing, {len(rd['extra'])} extra")
    else:
        rd['rederived'] = 0
        rd['mode'] = 'partial'
        f.append('mode partial: ' + ('content pins differ (no re-derivation)' if pf else 'the tier B store is missing tx bodies'))
    rep['rederive'] = rd
    rep['steps'].append('rederive')
    rep['tools_sha256'] = {t: (fsha(Path(root) / t) if (Path(root) / t).exists() else 'missing') for t in TOOLS}
    rep['result'] = 'PASS' if not f else 'FAIL'
    return rep


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest='cmd', required=True)
    p = sp.add_parser('build'); p.add_argument('--dataset', default='forensics/r28d'); p.add_argument('--store', default=str(DEFAULT_STORE))
    p = sp.add_parser('manifest'); p.add_argument('--dataset', default='forensics/r28d'); p.add_argument('--store', default=str(DEFAULT_STORE))
    p = sp.add_parser('replay'); p.add_argument('dataset'); p.add_argument('--store'); p.add_argument('--record'); p.add_argument('--report')
    a = ap.parse_args(argv)
    if a.cmd == 'replay':
        rep = replay(a.dataset, a.store)
        txt = v2.dumps(rep)
        if a.report:
            Path(a.report).write_text(txt)
        if a.record:
            import replay as v1replay  # the one record writer (G28 reads it)
            v1replay.record_run(a.record, txt, rep)
        sys.stdout.write(txt)
        print(f"v4 replay {rep['result']} mode={rep['rederive']['mode']} report_sha256={sha(txt.encode())}", file=sys.stderr)
        return 0 if rep['result'] == 'PASS' else 5
    {'build': cmd_build, 'manifest': cmd_manifest}[a.cmd](a)
    return 0


if __name__ == '__main__':
    sys.exit(main())
