#!/usr/bin/env python3
"""R28 forensics dataset v3 `forensics/r28/` (rft §0.8.3, §0.8.7, §6 step 3a; backlog B76, B123, B126, B147, A10c, D2-14,
D2-16). v3 is a CORRECTION of the sealed v2 (`supersedes: ["r26"]`); v1 and v2 are never rewritten.

What v3 changes against v2, and why:
  * raw/replay_runs/C/      the node replay through the sync path's HF3 entry (p2p.Add_Complete_Block_HF3, the B123 fix)
                            from the archive seed 7,467,515 to our anchor 7,498,540: 31,025 blocks, end root ca11cc21 =
                            our own treehash. The roots bytes are pinned by the SHA-256 the R26 merge recorded
                            (harness/runtime/r26_merge_a2_hf3_replay_20261104.json roots_jsonl_sha256); a roots file whose
                            hash differs is refused. Runs A/B (the pre-fix bare Add_Complete_Block, stopped at 7,467,546)
                            stay as RAW history: the wall-4 stop is a tool artifact, and v3 says so.
  * derived/                re-derived by v2.derive (unchanged, pinned) over v3's raw/; the longest run (C) gives the
                            pre/post roots and the end-state check, so derived/state_roots.json carries a MATCH and A10c
                            is bound IN THE DATASET (audit D2-16). Three v2 texts that describe the pre-fix runs are
                            corrected by a pure post-processing step here (v2.py itself is pinned by the sealed v2).
  * records                 tagged with their defect class from the first write (B126; classes.tag_v2_files in v2.derive,
                            raw/ by classes.py --tag), so G32's record half holds from the start.
  * content_pins            v3 pins its replay tools AND every build input of the decoder `./tools/forensics` (pins.py
                            decoder_input_paths; config/version.go normalised), at the R28 head with the B147 globals
                            fixes applied. The sealed v1 keeps its own pins; they resolve from git objects (pinsnap.py).
Inherited unchanged from v2 (bytes and SHA-256 checked against v2's manifest): raw/tx_bodies, raw/missing_txs,
raw/wall1_blocks, raw/a2_attempt, raw/archive_seed, raw/replay_runs/{A,B}, derived/invariant.json.

  python3 -I harness/forensics/v3.py build    --dataset forensics/r28 --store DIR --run-c-roots FILE
  python3 -I harness/forensics/v3.py manifest --dataset forensics/r28 --store DIR
  python3 -I harness/forensics/v3.py replay   forensics/r28 [--store DIR] [--record harness/runtime/forensics_replay.json]
Read-only towards every node and store; nothing here talks to a network.
"""
import argparse, json, os, platform, shutil, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import v2  # noqa: E402  (pinned by the sealed v2; used, never edited)
import pins as P  # noqa: E402

VERSION = 3
BASE = 'forensics/r26'
RUN_C = 'C'
MERGE_RECORD = 'harness/runtime/r26_merge_a2_hf3_replay_20261104.json'
HF3_ENTRY = 'p2p.Add_Complete_Block_HF3'
INHERIT = ['raw/tx_bodies.jsonl.gz', 'raw/missing_txs.json', 'raw/wall1_blocks.jsonl.gz', 'raw/a2_attempt.json',
           'raw/archive_seed.json', 'raw/replay_runs/A/rejection.json', 'raw/replay_runs/A/roots.jsonl.gz',
           'raw/replay_runs/A/summary.json', 'raw/replay_runs/B/rejection.json', 'raw/replay_runs/B/roots.jsonl.gz',
           'raw/replay_runs/B/summary.json', 'derived/invariant.json']
TOOLS = v2.TOOLS + ['harness/forensics/v3.py', 'harness/forensics/pins.py']
CLASS_FILES = dict(v2.CLASS_FILES)
DEFAULT_STORE = Path.home() / 'derohe-persist' / 'forensics_raw_r26'


def sha(b):
    return v2.sha(b)


def fsha(p):
    return v2.fsha(p)


# ------------------------------------------------------------------------------------------------ build
def inherit(ds, base=BASE, root=ROOT):
    """copy v2's raw inputs byte for byte; each must equal v2's manifest entry. {rel: sha256}"""
    ds, b = Path(ds), Path(root) / base
    bm = json.loads((b / 'manifest.json').read_text())['files']
    out = {}
    for rel in INHERIT:
        src = b / rel
        if not src.exists() or fsha(src) != bm.get(rel):
            raise SystemExit(f'refused: {base}/{rel} differs from its manifest (inherit only sealed bytes)')
        dst = ds / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
        out[rel] = bm[rel]
    return out


def run_c(ds, roots_file, root=ROOT):
    """raw/replay_runs/C from a roots JSONL whose SHA-256 equals the one the R26 merge recorded"""
    rec = json.loads((Path(root) / MERGE_RECORD).read_text())
    b = Path(roots_file).read_bytes()
    if sha(b) != rec['roots_jsonl_sha256']:
        raise SystemExit(f'refused: roots file sha256 {sha(b)[:16]} != recorded {rec["roots_jsonl_sha256"][:16]} ({MERGE_RECORD})')
    lines = [l.strip() for l in b.decode().splitlines() if l.strip()]
    if len(lines) != rec['roots_lines']:
        raise SystemExit('refused: roots line count differs from the record')
    s = {k: v for k, v in rec['replay'].items() if k not in ('started', 'finished', 'seconds')}
    s.update({'a2_binary_sha256': rec['a2_binary_sha256'], 'entry': HF3_ENTRY,
              'roots_jsonl_sha256': rec['roots_jsonl_sha256'],
              'provenance': f'the R26 merge run ({MERGE_RECORD}); roots bytes equal to the recorded SHA-256 (two audit2 '
                            'reproductions are byte-identical, forensics/r26/audit D2-14)'})
    d = Path(ds) / 'raw' / 'replay_runs' / RUN_C
    d.mkdir(parents=True, exist_ok=True)
    (d / 'roots.jsonl.gz').write_bytes(v2.gz_bytes(lines))
    (d / 'summary.json').write_bytes(v2.dump(s))
    return {'lines': len(lines), 'end_root': s.get('last_root'), 'end_state_match': s.get('end_state_match')}


def correct(files, runs_entry):
    """pure post-processing of v2.derive's texts that describe only the pre-fix runs (v2.py is pinned; R28)"""
    out = dict(files)
    sr = json.loads(out['derived/state_roots.json'])
    complete = [n for n, r in sr['runs'].items() if r.get('end_state_check') == 'MATCH']
    sr['evidence_class'] = ('DERIVED (node replay: tools/forensics/a2 replay; run C through ' + HF3_ENTRY +
                            ', the sync path entry; runs A/B through the bare blockchain.Add_Complete_Block, B123)')
    sr['runs_entry'] = runs_entry
    if 'window_coverage' in sr:
        sr['window_coverage']['pending_reason'] = (
            'no base state before this range: (a2) TreeSection blocked (derived/a2.json); our archive starts at 7,453,290 and '
            'its own roots 7,453,290..7,467,515 are the base of run C, which is end-state-checked'
            if complete else sr['window_coverage']['pending_reason'])
    sr.pop('runs_byte_identical', None)
    groups = {}
    for n, r in sr['runs'].items():
        groups.setdefault(runs_entry.get(n, '?'), set()).add(r['roots_sha256'])
    sr['runs_byte_identical_per_entry'] = {k: len(v) == 1 for k, v in sorted(groups.items())}
    out['derived/state_roots.json'] = v2.dump(sr)
    w = json.loads(out['derived/walls.json'])
    for wall in w.values():
        for row in wall.get('rows', []) if isinstance(wall, dict) else []:
            nr = row.get('node_replay')
            if isinstance(nr, str) and nr.startswith('accepted (Add_Complete_Block at this commit'):
                row['node_replay'] = nr.replace('accepted (Add_Complete_Block at this commit',
                                                f'accepted ({HF3_ENTRY} at this commit, run {RUN_C}', 1)
    w['replay_stops']['reading'] = ('runs A/B stopped at 7,467,546 because the pre-fix tool skipped the HF3 table step '
                                    f'(B123: a tool artifact, audit D2-14); run {RUN_C} through {HF3_ENTRY} accepts it and '
                                    'every later block to our anchor')
    out['derived/walls.json'] = v2.dump(w)
    return out


def runs_entry(ds):
    out = {}
    for d in sorted((Path(ds) / 'raw' / 'replay_runs').iterdir()):
        s = json.loads((d / 'summary.json').read_text())
        out[d.name] = s.get('entry', 'blockchain.Add_Complete_Block (pre-fix tool, B123)')
    return out


def derive(ds, stores, out, work, root=ROOT):
    files = v2.derive(ds, stores, out, work, root)
    files = correct(files, runs_entry(ds))
    for rel in ('derived/state_roots.json', 'derived/walls.json'):
        (Path(out) / rel).write_bytes(files[rel])
    return files


def cmd_build(a):
    ds = Path(a.dataset)
    if (ds / 'manifest.json').exists():
        led = json.loads((ROOT / 'forensics' / 'ledger.json').read_text())
        if any(v['version'] == ds.name and v.get('sealed') for v in led['versions']):
            raise SystemExit(f'refused: {ds.name} is sealed')
    ds.mkdir(parents=True, exist_ok=True)
    inh = inherit(ds)
    c = run_c(ds, a.run_c_roots)
    work = Path(tempfile.mkdtemp(prefix='v3d_'))
    try:
        files = derive(ds, [a.store], ds, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print(json.dumps({'inherited': len(inh), 'run_c': c, 'derived': {k: sha(v)[:16] for k, v in sorted(files.items())}}, indent=1))


# ------------------------------------------------------------------------------------------------ manifest / replay
def rederived(files):
    return {k: h for k, h in files.items() if k.startswith('derived/') and k not in CLASS_FILES and k not in INHERIT}


def content_pins(root=ROOT, lister=None):
    """v3 content pins: every v3 replay tool and every decoder build input (pins.py rules), the HF3 table"""
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
# forensics/r28 replay (rft §0.8.3, gate G28): ONE command checks the content pins (tools + decoder inputs), re-derives
# every derived/ file of dataset v3 from raw/ (and the pinned v1 RAW inputs) into a scratch dir and checks every SHA-256.
# Tier B blobs (tx bodies) are read from $FORENSICS_R28_STORE (default: v2's store, which v3 shares and never writes).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
store=${FORENSICS_R28_STORE:-$HOME/derohe-persist/forensics_raw_r26}
exec nice -n 15 python3 -I "$root/harness/forensics/v3.py" replay "$root/forensics/r28" --store "$store" "$@"
'''


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
         'inputs': {t: fsha(Path(root) / t) for t in v2.V1_INPUTS},
         'inputs_rule': 'v1 files read by path and pinned by SHA-256; v1 and v2 are never rewritten (rft §0.8.1 rule 4)',
         'inherited': {'from': BASE, 'base_manifest_sha256': fsha(Path(root) / BASE / 'manifest.json'),
                       'files': {k: bm['files'][k] for k in INHERIT}},
         'supersedes_reason': ('corrects v2: the node replay through the HF3 entry (run C, B123) replaces the pre-fix stop at '
                               '7,467,546 as the state-root source, so the end-state check and A10c are in the dataset; '
                               'records tagged from the first write (B126); decoder inputs content-pinned (B147)'),
         'content_pins': content_pins(root),
         'tierB_store': {'location': '$FORENSICS_R28_STORE (tier B store outside git, shared with v2, read-only; R28 merge: a label, not a path)',
                         'tx_bodies': n, 'tx_index_sha256': idx},
         'git_base_commit': git, 'go': gov, 'python': platform.python_version(),
         'replay_tool': 'harness/forensics/v3.py',
         'replay': {'command': f'sh forensics/{ds.name}/replay/replay.sh [--record harness/runtime/forensics_replay.json]',
                    'expected': 'replay/expected.sha256',
                    'node_replay': ('raw/replay_runs/<run>/ are outputs of tools/forensics/a2 replay; run C used ' + HF3_ENTRY +
                                    '; re-hashed here, re-run with a2 (about 20 minutes), not re-derived by Python')},
         'class_files': {k: v for k, v in sorted(CLASS_FILES.items()) if k in files},
         'class_slot': '`class` on every per-tx/per-block record = the defect class of rft §0.8.9 (tagged from the first '
                       'write); `evidence_class` = RAW/DERIVED/EXT (§0.8.2)'}
    (ds / 'manifest.json').write_bytes(v2.dump(m))
    print('manifest', sha((ds / 'manifest.json').read_bytes()), len(files), 'files')


def replay(ds, store, root=ROOT, lister=None):
    """v2.replay's steps with v3's derive and the content pins (a changed decoder input FAILS before any derivation)"""
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
            f.append(f'v1 input changed: {t}')
    for t, h in sorted((m.get('inherited') or {}).get('files', {}).items()):
        if m['files'].get(t) != h:
            f.append(f'inherited file differs from v2: {t}')
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
        work = Path(tempfile.mkdtemp(prefix='v3r_'))
        try:
            out = derive(ds, stores, work / 'out', work, root)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        out = {k: v for k, v in out.items() if k not in INHERIT}
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
    p = sp.add_parser('build'); p.add_argument('--dataset', default='forensics/r28'); p.add_argument('--store', default=str(DEFAULT_STORE))
    p.add_argument('--run-c-roots', required=True)
    p = sp.add_parser('manifest'); p.add_argument('--dataset', default='forensics/r28'); p.add_argument('--store', default=str(DEFAULT_STORE))
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
        print(f"v3 replay {rep['result']} mode={rep['rederive']['mode']} report_sha256={sha(txt.encode())}", file=sys.stderr)
        return 0 if rep['result'] == 'PASS' else 5
    {'build': cmd_build, 'manifest': cmd_manifest}[a.cmd](a)
    return 0


if __name__ == '__main__':
    sys.exit(main())
