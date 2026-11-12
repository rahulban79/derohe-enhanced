#!/usr/bin/env python3
"""r30 forensics dataset v5 `forensics/r30/` (rft §7 B207; §8 "R30 audit plan" S0 and S5). v5 BUILDS ON the sealed v4
(`supersedes: ["r28d"]`); v1..v4 are never rewritten (rft §0.8.1 rule 4).

What v5 adds or re-derives against v4, and why:
  * derived/classes.json, derived/fq.json   RE-DERIVED (B107: no longer pinned class files) by classes_r30.transform from
                                v4's class files and the held records: dc1-two-bodies computed (B202), the DC2
                                denominator (B203 a), S-RT named as a precondition (B203 2/3), a `moves_when` on every
                                non-exact figure, DC0 below the window (B209), the claim grant (B210), run C SC payouts
                                (B110). The DC2 value stays the word unbounded (G31).
  * derived/dc0_genesis.json    S0: multi-block TXIDs below the window (dc0_genesis.py over the pinned B182 checkpoint)
  * derived/claim_grant.json    S0: registrations below 144,000 vs blockchain/supply.go:7-9 (claim_grant.py)
  * derived/dc2_den.json        S0: proof-carrying txs 0..7,498,539 from the three B182 census records (dc2_den.py)
  * derived/b111_premine.json   S0: the B111 1-key residual as a HYPOTHESIS record (b111_premine.py; never the R29 record)
  * derived/presence.json       B216: re-read at the R30 head (presence.py); pinned like v4 (a class file: git revs)
  * derived/coverage.json, emission_genesis.json, public_values_genesis.json, version_census.json,
    dc0_genesis_typed.json, genesis_census.json   S2-S5 (B215 B211 B212 B209 B208): projections of the pinned genesis
                                census record (genesis_derive_r30.v5_files; coverage.build over the same records)
Pinned inputs (`inputs`, by SHA-256): the three B182 census records, r29_b97_holders, r29_b110_sc_payouts,
r29_b111_qcs1, v4's classes.json and fq.json, and the checkpoint itself (outside git; `checkpoint` = label + SHA-256).
Inherited unchanged from v4 (bytes and SHA-256 checked against v4's manifest): every raw/ file and every other derived/
file. The replay re-derives v4's derived set with v4.derive (pinned, used, never edited), then the v5 files.

  python3 -I harness/forensics/v5.py build    [--dataset forensics/r30] [--store DIR] [--checkpoint FILE]
  python3 -I harness/forensics/v5.py manifest [--dataset forensics/r30] [--store DIR]
  python3 -I harness/forensics/v5.py replay   forensics/r30 [--store DIR] [--checkpoint FILE] [--record harness/runtime/forensics_replay.json]
Read-only towards every node and store; nothing here talks to a network.
"""
import argparse, json, os, platform, shutil, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import v4  # noqa: E402  (pinned by the sealed v4; used, never edited)
import pins as P  # noqa: E402
import classes_r30 as CR  # noqa: E402
import s0_checkpoint as S0  # noqa: E402
import claim_grant, dc0_genesis, dc2_den, b111_premine  # noqa: E402,E401
import genesis_derive_r30 as GD  # noqa: E402  (R30 genesis..tip census projections, B208 B211 B212 B209 B215)

v2 = v4.v2
VERSION = 5
BASE = 'forensics/r28d'
S0_FILES = ['derived/dc0_genesis.json', 'derived/claim_grant.json', 'derived/dc2_den.json', 'derived/b111_premine.json']
NEW = ['derived/classes.json', 'derived/fq.json'] + S0_FILES + GD.V5_FILES
PRESENCE = 'derived/presence.json'
TOOLS = v4.TOOLS + ['harness/forensics/v5.py', 'harness/forensics/classes_r30.py', 'harness/forensics/s0_checkpoint.py',
                    'harness/forensics/claim_grant.py', 'harness/forensics/dc0_genesis.py', 'harness/forensics/dc2_den.py',
                    'harness/forensics/b111_premine.py', 'harness/forensics/b182_deep_r29.py',
                    'harness/forensics/genesis_r30.py', 'harness/forensics/genesis_derive_r30.py', 'harness/forensics/coverage.py',
                    'harness/forensics/canon_parity_r30.py', 'tools/forensics/b182deep2/main.go']
# classes.json is re-derived here (B107); presence.json is re-read at the round head and invariant.json stays v4's:
# both are class files (pinned in `files`, not re-derived by the replay)
CLASS_FILES = {k: x for k, x in v4.CLASS_FILES.items() if k != 'derived/classes.json'}
RECORDS = {'b182_deep': 'harness/runtime/r29_b182_deep_census.json', 'b182_fetch': 'harness/runtime/r29_b182_fetch_census.json',
           'b182_offline': 'harness/runtime/r29_b182_offline_census.json', 'b97': 'harness/runtime/r29_b97_holders.json',
           'b110': 'harness/runtime/r29_b110_sc_payouts.json', 'b111': 'harness/runtime/r29_b111_qcs1.json',
           'genesis_census': GD.CENSUS, 'genesis_tip': GD.TIP, 'canon_parity': 'harness/runtime/r30_genesis_canon_parity.json',
           # r30 v5b: the B111 key-count fit, generated from records by genesis_derive_r30.b111_keys (no longer hand-typed)
           'genesis_b111_keys': 'harness/runtime/r30_genesis_b111_keys.json'}
DEFAULT_STORE = v4.DEFAULT_STORE


def sha(b):
    return v2.sha(b)


def fsha(p):
    return v2.fsha(p)


def inherit_list(root=ROOT):
    """every v4 file v5 takes byte for byte: raw/ and derived/ less the files v5 writes (and presence, re-read)"""
    bm = json.loads((Path(root) / BASE / 'manifest.json').read_text())['files']
    return sorted(k for k in bm if k.startswith(('raw/', 'derived/')) and k not in NEW and k != PRESENCE)


def inherit(ds, root=ROOT):
    """copy v4's files byte for byte; each must equal v4's manifest entry and v4 must be sealed. {rel: sha256}"""
    ds, b = Path(ds), Path(root) / BASE
    led = json.loads((Path(root) / 'forensics' / 'ledger.json').read_text())
    if not any(x['version'] == Path(BASE).name and x.get('sealed') for x in led['versions']):
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


def record_pins(root=ROOT):
    return {rel: fsha(Path(root) / rel) for rel in RECORDS.values()}


def s0_files(checkpoint, root=ROOT):
    """the four S0 records as dataset files (bytes); the checkpoint must hash to its recorded SHA-256"""
    ck = S0.load(checkpoint, root)
    if not ck['pin_equal']:
        raise SystemExit(f'refused: the checkpoint hashes to {ck["sha256"][:16]}, not the recorded {S0.CHECKPOINT_SHA256[:16]}')
    d = lambda o: (json.dumps(o, indent=1, sort_keys=True) + '\n').encode()
    return {'derived/dc0_genesis.json': d(dc0_genesis.build(ck, root)),
            'derived/claim_grant.json': d(claim_grant.build(ck, root)),
            'derived/dc2_den.json': d(dc2_den.build(root, BASE)),
            'derived/b111_premine.json': d(b111_premine.build(root, BASE))}


def derive(ds, stores, out, work, root=ROOT, checkpoint=S0.DEFAULT_CHECKPOINT):
    """v4.derive (pinned) over v5's raw/, then the v5 files from its outputs and the pinned records; {rel: bytes}"""
    root = Path(root)
    files = v4.derive(ds, stores, out, work, root)
    files.update(s0_files(checkpoint, root))
    files.update(GD.v5_files(root))                      # R30 genesis..tip: projections of the pinned census record
    J = lambda rel: json.loads((root / rel).read_text())
    S = {k: json.loads(files[k]) for k in S0_FILES}
    pins = {**record_pins(root), f'{BASE}/derived/classes.json': fsha(root / BASE / 'derived/classes.json'),
            f'{BASE}/derived/fq.json': fsha(root / BASE / 'derived/fq.json')}
    cb, fb = CR.transform((root / BASE / 'derived/classes.json').read_bytes(), files['derived/fq.json'],
                          files['derived/inclusions.json'], J(RECORDS['b97']), S['derived/dc2_den.json'],
                          S['derived/dc0_genesis.json'], S['derived/claim_grant.json'], J(RECORDS['b110']),
                          version=Path(ds).name, base=Path(BASE).name, pins=pins)
    files['derived/classes.json'], files['derived/fq.json'] = cb, fb
    for rel in NEW:
        p = Path(out) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(files[rel])
    return files


def presence_at_head(ds, root=ROOT):
    """B216: presence.json re-read at the round head (presence.py, git show per rev; never the working tree)"""
    import presence as PR
    out = PR.presence(str(root), PR.DEFAULT_REVS)
    (Path(ds) / PRESENCE).parent.mkdir(parents=True, exist_ok=True)
    (Path(ds) / PRESENCE).write_text(json.dumps(out, indent=1, sort_keys=True) + '\n')
    return out


def head_commit(root=ROOT):
    return subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()


def presence_head_label(presence, build_commit):
    """B216: 'round head <c>' when presence re-read the build commit, else 'as of <c>' (pure)"""
    c = next((r.get('commit') for r in presence.get('revs', []) if r.get('rev') == 'HEAD'), None)
    if not c:
        return 'pending: presence has no HEAD rev'
    return f'round head {c[:12]}' if build_commit and c == build_commit else f'as of {c[:12]}'


def cmd_build(a):
    ds = Path(a.dataset)
    if (ds / 'manifest.json').exists():
        led = json.loads((ROOT / 'forensics' / 'ledger.json').read_text())
        if any(x['version'] == ds.name and x.get('sealed') for x in led['versions']):
            raise SystemExit(f'refused: {ds.name} is sealed')
    ds.mkdir(parents=True, exist_ok=True)
    inh = inherit(ds)
    presence_at_head(ds)
    work = Path(tempfile.mkdtemp(prefix='v5d_'))
    try:
        files = derive(ds, [a.store], work / 'out', work, ROOT, a.checkpoint)
        for rel in NEW:
            (ds / rel).write_bytes(files[rel])
        same = {k: sha(files[k]) == fsha(ds / k) for k in files if k not in NEW and (ds / k).exists()}
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if not all(same.values()):
        raise SystemExit(f'refused: v4.derive over the inherited raw/ differs from v4: {sorted(k for k, v in same.items() if not v)}')
    print(json.dumps({'inherited': len(inh), 'rederived_equal_v4': len(same), 'new': {k: sha(files[k])[:16] for k in NEW}}, indent=1))


def rederived(files):
    return {k: h for k, h in files.items() if k.startswith('derived/') and k not in CLASS_FILES}


def content_pins(root=ROOT, lister=None):
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
# forensics/r30 replay (rft §0.8.3, gate G28): ONE command checks the content pins (tools + decoder inputs), re-derives
# every derived/ file of dataset v5 from raw/ (v4.derive, then the v5 files) into a scratch dir and checks every
# SHA-256. Tier B blobs from $FORENSICS_R28_STORE, the S0 checkpoint from $FORENSICS_R29_DEEP (both read-only).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
store=${FORENSICS_R28_STORE:-$HOME/derohe-persist/forensics_raw_r26}
exec nice -n 15 python3 -I "$root/harness/forensics/v5.py" replay "$root/forensics/r30" --store "$store" "$@"
'''


def inputs(root=ROOT):
    out = v4.inputs(root)
    out.update(record_pins(root))
    out[BASE + '/derived/classes.json'] = fsha(Path(root) / BASE / 'derived/classes.json')
    out[BASE + '/derived/fq.json'] = fsha(Path(root) / BASE / 'derived/fq.json')
    return dict(sorted(out.items()))


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
    git = head_commit(root)
    pres = json.loads((ds / PRESENCE).read_text())
    bm = json.loads((Path(root) / BASE / 'manifest.json').read_text())
    m = {'dataset': ds.name, 'version': VERSION, 'supersedes': [Path(BASE).name], 'files': files,
         'tools': {t: fsha(Path(root) / t) for t in TOOLS}, 'hf3_table': {'file': v2.HF3, 'sha256': fsha(Path(root) / v2.HF3)},
         'inputs': inputs(root),
         'inputs_rule': 'records and v1..v4 files read by path and pinned by SHA-256; v1..v4 are never rewritten (rft §0.8.1 rule 4)',
         'checkpoint': {'file': S0.CHECKPOINT_LABEL, 'sha256': S0.CHECKPOINT_SHA256},
         'inherited': {'from': BASE, 'base_manifest_sha256': fsha(Path(root) / BASE / 'manifest.json'),
                       'files': {k: bm['files'][k] for k in inherit_list(root)}},
         'supersedes_reason': ('builds on v4: class figures re-derived from held evidence (B202 two bodies, B203 DC2 '
                               'denominator and moves-when notes, B209 DC0 below the window, B210 claim grant, B110 run C '
                               'SC payouts); S0 records from the pinned B182 checkpoint; presence at the R30 head (B216)'),
         'presence_head': presence_head_label(pres, git),
         'content_pins': content_pins(root),
         'tierB_store': {'location': '$FORENSICS_R28_STORE (tier B store outside git, shared with v2..v4, read-only; a label, not a path)',
                         'tx_bodies': n, 'tx_index_sha256': idx},
         'git_base_commit': git, 'go': subprocess.run(['go', 'version'], capture_output=True, text=True).stdout.strip(),
         'python': platform.python_version(), 'replay_tool': 'harness/forensics/v5.py',
         'replay': {'command': f'sh forensics/{ds.name}/replay/replay.sh [--record harness/runtime/forensics_replay.json]',
                    'expected': 'replay/expected.sha256'},
         'class_files': {k: x for k, x in sorted(CLASS_FILES.items()) if k in files},
         'class_slot': bm.get('class_slot')}
    (ds / 'manifest.json').write_bytes(v2.dump(m))
    print('manifest', sha((ds / 'manifest.json').read_bytes()), len(files), 'files')


def replay(ds, store, root=ROOT, lister=None, checkpoint=S0.DEFAULT_CHECKPOINT):
    """v4.replay's steps with v5's derive, inputs, content pins and the checkpoint pin"""
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
            f.append(f'inherited file differs from v4: {t}')
    rep['steps'].append('manifest')
    ck_ok = Path(checkpoint).exists() and S0.sha_file(checkpoint) == (m.get('checkpoint') or {}).get('sha256')
    rep['checkpoint'] = {'present': Path(checkpoint).exists(), 'sha256_equal': ck_ok}
    stores = [store] if store else []
    shas = [r['sha256'] for r in v2.read_gz(ds / 'raw/tx_bodies.jsonl.gz')]
    idx, n = v2.store_index(stores, shas)
    full = n == len(shas) and idx == m['tierB_store']['tx_index_sha256'] and ck_ok
    rep['store'] = {'tx_bodies_present': n, 'tx_bodies_listed': len(shas), 'index_equal': idx == m['tierB_store']['tx_index_sha256']}
    rep['steps'].append('store')
    exp = rederived(m['files'])
    if (ds / 'replay/expected.sha256').read_text() != ''.join(f'{h}  {k}\n' for k, h in sorted(exp.items())):
        f.append('expected.sha256 differs from the manifest')
    rd = {'expected': len(exp), 'equal': 0, 'mismatch': [], 'missing': [], 'extra': [], 'mode': 'full' if full else 'partial'}
    if full and not pf:
        work = Path(tempfile.mkdtemp(prefix='v5r_'))
        try:
            out = derive(ds, stores, work / 'out', work, root, checkpoint)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        out = {k: x for k, x in out.items() if k.startswith('derived/') and k not in CLASS_FILES}
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
        why = ('content pins differ (no re-derivation)' if pf else 'the S0 checkpoint is missing or differs' if not ck_ok
               else 'the tier B store is missing tx bodies')
        f.append('mode partial: ' + why)
    rep['rederive'] = rd
    rep['steps'].append('rederive')
    rep['tools_sha256'] = {t: (fsha(Path(root) / t) if (Path(root) / t).exists() else 'missing') for t in TOOLS}
    rep['result'] = 'PASS' if not f else 'FAIL'
    return rep


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest='cmd', required=True)
    for c in ('build', 'manifest'):
        p = sp.add_parser(c); p.add_argument('--dataset', default='forensics/r30'); p.add_argument('--store', default=str(DEFAULT_STORE))
        p.add_argument('--checkpoint', default=str(S0.DEFAULT_CHECKPOINT))
    p = sp.add_parser('replay'); p.add_argument('dataset'); p.add_argument('--store'); p.add_argument('--record'); p.add_argument('--report')
    p.add_argument('--checkpoint', default=str(S0.DEFAULT_CHECKPOINT))
    a = ap.parse_args(argv)
    if a.cmd == 'replay':
        rep = replay(a.dataset, a.store, checkpoint=a.checkpoint)
        txt = v2.dumps(rep)
        if a.report:
            Path(a.report).write_text(txt)
        if a.record:
            import replay as v1replay  # the one record writer (G28 reads it)
            v1replay.record_run(a.record, txt, rep)
        sys.stdout.write(txt)
        print(f"v5 replay {rep['result']} mode={rep['rederive']['mode']} report_sha256={sha(txt.encode())}", file=sys.stderr)
        return 0 if rep['result'] == 'PASS' else 5
    {'build': cmd_build, 'manifest': cmd_manifest}[a.cmd](a)
    return 0


if __name__ == '__main__':
    sys.exit(main())
