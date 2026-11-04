#!/usr/bin/env python3
"""R25 forensics-replay (rft §0.8.1 rule 2, §0.8.3 replay/, §0.8.8 G28; B77): re-derive every derived/ file of a dataset
version from raw/ alone, with the content-pinned tools and sources, into a scratch dir, and check every SHA-256.

  python3 -I harness/forensics/replay.py forensics/r25 [--store DIR] [--archive-copy DIR] [--work DIR] [--keep]
      [--report FILE] [--record FILE]
  (one command: forensics/r25/replay/replay.sh)

Steps, every one recorded in the report:
  1. pinned:    CONTENT pins (pins.py; manifest content_pins): every replay tool, every decoder build input (go list
                -deps, vendored packages, go.mod and go.sum/modules.txt where present), the HF3 table and the exact source lines derive.py
                cites re-hash equal, and the decoder input set is unchanged. Any later commit passes as long as those
                bytes are identical (R25 integration; until then HEAD had to equal 17da0dc). `pinned_commit` (the
                manifest's git_base_commit) is reported for provenance only;
  2. manifest:  every dataset file listed with an equal SHA-256, none unlisted, pinned tools + HF3 table equal
                (manifest_check.py, MF1);
  3. raw:       every raw/blobs/<name> re-hashes to its name, and every headerchain row's blob (dataset or tier B store)
                re-hashes to the row's sha256 and SHA3-256 to its block id (KAT MF2: a planted altered byte FAILS here
                even when the manifest was rewritten to match it);
  4. store:     the tier B store's index SHA-256 equals the manifest's;
  5. expected:  replay/expected.sha256 lists exactly the manifest's derived/ entries;
  6. decoder:   `go build -trimpath -buildvcs=false -mod=vendor ./tools/forensics` into the scratch dir (the pinned
                sources; -buildvcs=false since the R25 integration: Go stamps the git revision and dirty flag into the
                binary, so the decoder hash, and with it the report, changed with every commit), SHA-256
                compared with the manifest's decoder pin;
  7. re-derive: extract.py then derive.py with --out <scratch>/derived; every output compared with the manifest.
                Without the tier B store, extract cannot run (it needs every blob): its outputs are then hash-checked
                only (mode partial). Without the archive copy, derived/archive_state is hash-checked only (partial).
                G28 needs mode full.
The report is deterministic (no times, no absolute paths, no scratch names): two runs from different cwds must be
byte-identical. --record appends {when, cwd tag (sha256 of the cwd, never the cwd), report sha256} to a run record
that G28 reads (verify_dataset.py g28). Exit 0 PASS · 5 FAIL · 2 usage/safety refusal.
"""
import argparse, gzip, hashlib, json, os, platform, shutil, subprocess, sys, tempfile, zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import manifest_check  # noqa: E402
import pins  # noqa: E402

FORBIDDEN_ROOTS = [Path.home() / 'dero-data']           # node datadirs: never read in place, never written
REPLAY_TOOLS = pins.REPLAY_TOOLS
PARTIAL_EXTRACT = ['extract/blocks.jsonl.gz', 'extract/txs.jsonl.gz', 'extract/integrity.json']
ARCHIVE_STATE = ['archive_state/roots.jsonl.gz', 'archive_state/proof_checks.jsonl', 'archive_state/source.json']


class Refused(Exception):
    pass


def sha(b):
    return hashlib.sha256(b).hexdigest()


def fsha(p):
    return sha(Path(p).read_bytes())


def guard(p, what):
    rp = Path(os.path.realpath(p))
    for f in FORBIDDEN_ROOTS:
        fr = Path(os.path.realpath(f))
        if rp == fr or fr in rp.parents:
            raise Refused(f'refused: {what} lies inside a node datadir; replay reads only copies')
    return rp


def check_pinned(m, root=ROOT, lister=None):
    """Content pins, not a commit: deterministic for any commit whose pinned bytes are equal (no HEAD in the report)."""
    cp = m.get('content_pins')
    f = (pins.check(cp, root, lister) if cp else
         ['manifest has no content_pins (written before the R25 integration: re-pin with write_manifest.py)'])
    cp = cp or {}
    return {'pinned_commit': m.get('git_base_commit', ''), 'content_pins_equal': not f,
            'content_pin_failures': f[:20], 'content_pin_failure_count': len(f),
            'content_pins_aggregate_sha256': cp.get('aggregate_sha256'),
            'content_pin_counts': {g: len(cp.get(g, {})) for g in ('replay_tools', 'decoder_inputs', 'hf3_table',
                                                                    'cited_lines')},
            'reading': ('pinned_commit is provenance only; replay is bound to the content pins (pins.py), so it passes '
                        'at any later commit whose pinned bytes are identical')}


def check_raw(ds, store):
    """MF2: content addresses and block ids re-hash from the bytes themselves (independent of the manifest)."""
    ds = Path(ds)
    fails, n_blobs = [], 0
    for p in sorted((ds / 'raw' / 'blobs').glob('*')):
        n_blobs += 1
        if fsha(p) != p.name:
            fails.append(f'raw blob content != its address: raw/blobs/{p.name[:16]}')
    hc = ds / 'raw' / 'headerchain.jsonl.gz'
    rows = [json.loads(l) for l in gzip.open(hc, 'rt') if l.strip()] if hc.exists() else []
    if not rows:
        fails.append('raw/headerchain.jsonl.gz missing or empty')
    n_rows = n_store = n_absent = 0
    for r in rows:
        n_rows += 1
        p = ds / 'raw' / 'blobs' / r['sha256']
        if not p.exists():
            q = Path(store) / 'blobs' / r['sha256'] if store else None
            if q is None or not q.exists():
                n_absent += 1
                continue
            p = q
            n_store += 1
        b = p.read_bytes()
        if sha(b) != r['sha256']:
            fails.append(f"block blob sha256 != headerchain row: {r['blid'][:16]}")
        if hashlib.sha3_256(b).hexdigest() != r['blid']:
            fails.append(f"block blob SHA3-256 != block id (check i): {r['blid'][:16]}")
    if store and n_absent:
        fails.append(f'{n_absent} headerchain blobs absent from both raw/blobs and the store')
    ap, n_anchor = ds / 'raw' / 'anchors.json', 0
    for a in (json.loads(ap.read_text()) if ap.exists() else []):
        if a.get('kind') != 'block':
            continue
        n_anchor += 1
        p = ds / 'raw' / 'blobs' / a.get('sha256', '-')
        if not p.exists() or hashlib.sha3_256(p.read_bytes()).hexdigest() != a.get('id'):
            fails.append(f"anchor block blob missing or SHA3-256 != its id: {str(a.get('id'))[:16]}")
    if not n_anchor:
        fails.append('raw/anchors.json holds no anchor block')
    return fails, {'dataset_blobs': n_blobs, 'headerchain_rows': n_rows, 'anchor_blocks': n_anchor, 'rows_from_store': n_store,
                   'rows_blob_absent': n_absent,
                   'reading': ('rows whose blob is in neither raw/blobs nor the store are tier B blocks kept outside '
                               'git; without the store they are re-checked only through the manifest-pinned extract '
                               'outputs') if not store else 'every headerchain row re-hashed from its blob'}


def store_index(store):
    blobs = sorted(p.name for p in (Path(store) / 'blobs').glob('*'))
    return len(blobs), sha(''.join(b + '\n' for b in blobs).encode())


def expected_lines(m):
    return ''.join(f'{h}  {k}\n' for k, h in sorted(m['files'].items()) if k.startswith('derived/'))


def check_expected(ds, m):
    p = Path(ds) / 'replay' / 'expected.sha256'
    if not p.exists():
        return ['replay/expected.sha256 missing'], False
    ok = p.read_text() == expected_lines(m)
    return ([] if ok else ['replay/expected.sha256 differs from the manifest derived/ entries']), True


def compare(work_derived, m):
    """Every re-derived file against the manifest: equal / mismatch / missing / extra (paths relative to derived/)."""
    exp = {k[len('derived/'):]: h for k, h in m['files'].items() if k.startswith('derived/')}
    wd = Path(work_derived)
    got = {str(p.relative_to(wd)): fsha(p) for p in sorted(wd.rglob('*')) if p.is_file()} if wd.exists() else {}
    mism = sorted(k for k in exp if k in got and got[k] != exp[k])
    return {'expected': len(exp), 'equal': sum(1 for k in exp if got.get(k) == exp[k]), 'mismatch': mism,
            'missing': sorted(set(exp) - set(got)), 'extra': sorted(set(got) - set(exp)),
            'aggregate': sha(''.join(f'{k} {got[k]}\n' for k in sorted(got)).encode())}


def run_step(cmd, env=None):
    p = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=str(ROOT))
    return p.returncode, p.stdout, p.stderr


def replay(ds, store=None, archive=None, work=None, keep=False, build=True, run=run_step, pinned=check_pinned):
    """The report dict. `run` and `pinned` are injectable so the KAT (MF2) drives this whole flow on a forged dataset."""
    ds = Path(ds).resolve()
    if store:
        store = guard(store, '--store')
    if archive:
        archive = guard(archive, '--archive-copy')
    m_bytes = (ds / 'manifest.json').read_bytes()
    m = json.loads(m_bytes)
    fails = []
    rep = {'dataset': ds.name, 'manifest_sha256': sha(m_bytes)}
    rep['pinned'] = pinned(m)
    if not rep['pinned']['content_pins_equal']:
        fails.append('content pins differ: ' + (rep['pinned']['content_pin_failures'] or ['?'])[0])
    rep['tools_sha256'] = {t: fsha(ROOT / t) for t in REPLAY_TOOLS if (ROOT / t).exists()}
    mf = manifest_check.check(ds, ROOT)
    rep['manifest_check'] = {'ok': not mf, 'failures': mf[:50], 'failure_count': len(mf),
                             'files_listed': len(m.get('files', {}))}
    fails += [f'manifest: {x}' for x in mf[:5]]
    rf, rs = check_raw(ds, store)
    rep['raw'] = dict(rs, ok=not rf, failures=rf[:50], failure_count=len(rf))
    fails += [f'raw: {x}' for x in rf[:5]]
    if store:
        n, idx = store_index(store)
        pin = m.get('tierB_store', {})
        rep['store'] = {'given': True, 'count': n, 'index_sha256_equals_manifest': idx == pin.get('index_sha256')}
        if idx != pin.get('index_sha256'):
            fails.append('tier B store index differs from the manifest')
    else:
        rep['store'] = {'given': False, 'reading': 'not applicable: no store given; extract outputs hash-checked only'}
    ef, present = check_expected(ds, m)
    rep['expected_sha256_file'] = {'present': present, 'equals_manifest': not ef}
    fails += ef
    tmp = Path(work) if work else Path(tempfile.mkdtemp(prefix='fxreplay_'))
    tmp = guard(tmp, '--work')
    if tmp == ds or ds in tmp.parents:
        raise Refused('refused: --work lies inside the dataset')
    try:
        out = tmp / 'derived'
        if out.exists():
            shutil.rmtree(out)
        out.mkdir(parents=True)
        dec = tmp / 'bin' / 'forensics'
        if build:
            dec.parent.mkdir(parents=True, exist_ok=True)
            env = dict(os.environ, GOFLAGS='-mod=vendor', CGO_ENABLED=os.environ.get('CGO_ENABLED', '1'))
            rc, so, se = run(['go', 'build', '-trimpath', '-buildvcs=false', '-o', str(dec), './tools/forensics'], env)
            if rc:
                fails.append('decoder build failed')
                rep['decoder'] = {'built': False, 'error': se.strip().splitlines()[-1:] or ['no stderr']}
            else:
                pin = m.get('tool_versions', {}).get('decoder_sha256')
                rep['decoder'] = {'built': True, 'sha256': fsha(dec),
                                  'equals_manifest': (fsha(dec) == pin) if pin else 'not applicable: not pinned'}
        hash_only = []
        mode = 'full'
        steps = {}
        if 'decoder' in rep and not rep['decoder'].get('built'):
            raise Refused('decoder build failed')
        py = sys.executable
        if store and (not rf):
            cmd = [py, '-I', str(HERE / 'extract.py'), '--dataset', str(ds), '--store', str(store), '--decoder', str(dec),
                   '--out', str(out)]
            if archive:
                cmd += ['--archive-copy', str(archive)]
            rc, so, se = run(cmd)
            steps['extract'] = {'rc': rc, 'stdout_sha256': sha(so.encode()), 'stderr_tail': se.strip().splitlines()[-1:]}
            if rc:
                fails.append(f'extract.py exit {rc}')
        else:
            mode = 'partial'
            steps['extract'] = {'rc': 'not applicable: not run (' + ('raw check failed' if rf else 'no tier B store') + ')'}
            for rel in PARTIAL_EXTRACT:
                hash_only.append(rel)
        if not archive or 'extract' not in steps or steps['extract'].get('rc') != 0:
            if not archive:
                mode = 'partial'
            for rel in ARCHIVE_STATE:
                if rel not in hash_only:
                    hash_only.append(rel)
        for rel in hash_only:  # hash-checked by step 2; copied so derive.py reads the manifest-equal bytes
            src = ds / 'derived' / rel
            if src.exists() and not (out / rel).exists():
                (out / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, out / rel)
        cmd = [py, '-I', str(HERE / 'derive.py'), '--dataset', str(ds), '--out', str(out)]
        if store:
            cmd += ['--store', str(store)]
        rc, so, se = run(cmd)
        steps['derive'] = {'rc': rc, 'stdout_sha256': sha(so.encode()), 'stderr_tail': se.strip().splitlines()[-1:]}
        if rc:
            fails.append(f'derive.py exit {rc}')
        cmp_ = compare(out, m)
        cmp_['mode'] = mode
        cmp_['hash_checked_only'] = sorted(hash_only)
        cmp_['rederived'] = cmp_['expected'] - len(hash_only)
        rep['steps'] = steps
        rep['rederive'] = cmp_
        for k in ('mismatch', 'missing', 'extra'):
            if cmp_[k]:
                fails.append(f"re-derive {k}: {len(cmp_[k])} file(s), first {cmp_[k][0]}")
    finally:
        if not keep and not work:
            shutil.rmtree(tmp, ignore_errors=True)
    tv = m.get('tool_versions', {})
    rep['toolchain'] = {'python': platform.python_version(), 'zlib': zlib.ZLIB_RUNTIME_VERSION,
                        'python_equals_manifest': platform.python_version() == m.get('python'),
                        'zlib_equals_manifest': (zlib.ZLIB_RUNTIME_VERSION == tv['zlib']) if 'zlib' in tv
                        else 'not applicable: not pinned',
                        'go_equals_manifest': subprocess.run(['go', 'version'], capture_output=True,
                                                             text=True).stdout.strip() == m.get('go')}
    rep['toolchain_reading'] = ('informational: a toolchain differing from the manifest is not itself a failure; the '
                                're-derived bytes decide')
    rep['fail_reasons'] = fails
    rep['result'] = 'PASS' if not fails else 'FAIL'
    return rep


def dumps(rep):
    return json.dumps(rep, indent=1, sort_keys=True) + '\n'


def record_run(path, rep_text, rep):
    import datetime
    p = Path(path)
    rec = json.loads(p.read_text()) if p.exists() else {}
    if rec.get('manifest_sha256') != rep['manifest_sha256'] or rec.get('dataset') != rep['dataset']:
        rec = {'dataset': rep['dataset'], 'manifest_sha256': rep['manifest_sha256'], 'runs': []}
    rec['runs'].append({'when': datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
                        'cwd_tag': sha(os.getcwd().encode())[:16], 'report_sha256': sha(rep_text.encode()),
                        'result': rep['result'], 'mode': rep['rederive']['mode'] if 'rederive' in rep else 'not run'})
    rec['report'] = rep
    rec['note'] = ('G28 (verify_dataset.py g28) needs >= 2 runs bound to the current manifest with distinct cwd tags, '
                   'equal report SHA-256, result PASS and mode full. cwd_tag is a hash, never the path.')
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(rec, indent=1, sort_keys=True) + '\n')


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('dataset'); ap.add_argument('--store'); ap.add_argument('--archive-copy')
    ap.add_argument('--work'); ap.add_argument('--keep', action='store_true')
    ap.add_argument('--report'); ap.add_argument('--record')
    a = ap.parse_args(argv)
    try:
        rep = replay(a.dataset, a.store, a.archive_copy, a.work, a.keep)
    except Refused as e:
        print('REFUSED:', e, file=sys.stderr)
        return 2
    txt = dumps(rep)
    if a.report:
        Path(a.report).write_text(txt)
    if a.record:
        record_run(a.record, txt, rep)
    sys.stdout.write(txt)
    print(f"replay {rep['result']} mode={rep.get('rederive', {}).get('mode')} report_sha256={sha(txt.encode())}",
          file=sys.stderr)
    return 0 if rep['result'] == 'PASS' else 5


if __name__ == '__main__':
    sys.exit(main())
