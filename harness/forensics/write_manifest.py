#!/usr/bin/env python3
"""Write forensics/r<N>/manifest.json: commit, tool versions and SHA-256s, the HF3 table SHA-256, and the SHA-256 of
every dataset file (rft §0.8.3). Later stages re-run it after adding files; `stages` records who wrote what.

  python3 -I harness/forensics/write_manifest.py --dataset forensics/r25 --stage acquire [--store DIR]
"""
import argparse, hashlib, json, platform, subprocess, sys, zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import pins  # noqa: E402

# `tools` (strict, manifest_check MF1) = the replay tools; every other tool is recorded in `tools_provenance` only, so a
# later edit of a KAT or of the audit tool never voids a sealed dataset (R25 integration: content pins, pins.py).
PROVENANCE_TOOLS = ['harness/forensics/provenance.py', 'harness/forensics/acquire.py', 'harness/forensics/verify_acquire.py',
         'harness/forensics/write_manifest.py', 'tools/forensics/main.go', 'harness/kat/test_forensics_r25.py',
         'harness/forensics/extract.py', 'harness/forensics/derive.py', 'harness/forensics/keccak.py',
         'harness/forensics/lint.py', 'harness/forensics/manifest_check.py', 'tools/forensics/extract.go',
         'harness/forensics/replay.py', 'harness/forensics/verify_dataset.py', 'harness/forensics/audit_check.py',
         'harness/forensics/pins.py']


def _keccak_version():
    p = ROOT / 'harness' / 'forensics' / 'keccak.py'
    if not p.exists():
        return 'missing: keccak.py not present'
    for line in p.read_text().splitlines():
        if line.startswith('IMPL_VERSION'):
            return line.split('=', 1)[1].strip().strip("'")
    return 'missing: no IMPL_VERSION line'


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dataset', required=True); ap.add_argument('--stage', required=True); ap.add_argument('--store')
    ap.add_argument('--decoder', help='a decoder built by `go build -trimpath -buildvcs=false -mod=vendor ./tools/forensics` (replay.py pins it)')
    a = ap.parse_args()
    ds = Path(a.dataset)
    mf = ds / 'manifest.json'
    old = json.loads(mf.read_text()) if mf.exists() else {}
    files = {str(p.relative_to(ds)): sha(p) for p in sorted(ds.rglob('*')) if p.is_file() and p.name != 'manifest.json'}
    go = subprocess.run(['go', 'version'], capture_output=True, text=True).stdout.strip()
    base = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
    m = {
        'dataset': ds.name, 'version': 1, 'supersedes': [],
        'git_base_commit': base, 'working_tree': 'the commit HEAD when this manifest was written; provenance only (replay is bound to content_pins)',
        'provenance_commits': dict(old.get('provenance_commits') or
                                   ({'dataset v1 built (acquire, extract, replay, audit stages)': old['git_base_commit']}
                                    if old.get('git_base_commit') else {}), **{a.stage: base}),
        'python': platform.python_version(), 'go': go,
        'tool_versions': dict({'keccak_pure_python': _keccak_version(), 'zlib': zlib.ZLIB_RUNTIME_VERSION,
                               'decoder': ('go build -trimpath -buildvcs=false -mod=vendor ./tools/forensics (main.go + extract.go above), '
                                           'vendored node packages unchanged')},
                              **({'decoder_sha256': sha(a.decoder)} if a.decoder else
                                 {k: v for k, v in old.get('tool_versions', {}).items() if k == 'decoder_sha256'})),
        'tools': {t: sha(ROOT / t) for t in pins.REPLAY_TOOLS if (ROOT / t).exists()},
        'tools_provenance': {t: sha(ROOT / t) for t in PROVENANCE_TOOLS if (ROOT / t).exists()},
        'content_pins': pins.compute(ROOT),
        'hf3_table': {'file': 'blockchain/hardfork_fixes.go', 'sha256': sha(ROOT / 'blockchain/hardfork_fixes.go')},
        'files': files,
        'stages': dict(old.get('stages', {}), **{a.stage: sorted(files)}),
    }
    if (ds / 'replay' / 'replay.sh').exists():
        m['replay'] = {
            'command': f'sh forensics/{ds.name}/replay/replay.sh [--archive-copy DIR] [--record harness/runtime/forensics_replay.json]',
            'expected': 'replay/expected.sha256 lists exactly the derived/ entries of this manifest',
            'mode_full': 'tier B store present AND archive copy given: every derived/ file is re-derived from raw/ (G28)',
            'mode_partial': ('without the tier B store, derived/extract/* is hash-checked only (extract needs every blob); '
                             'without the archive copy (our replaywall store, not in the dataset), derived/archive_state/* '
                             'is hash-checked only; G28 does not accept partial'),
            'decoder': 'rebuilt by replay.py from the pinned sources; its SHA-256 is compared with tool_versions.decoder_sha256',
            'gate': 'G28: harness/forensics/verify_dataset.py g28 (ledger forensics/ledger.json + the run record)'}
    if a.store:
        blobs = sorted(p.name for p in (Path(a.store) / 'blobs').glob('*'))
        m['tierB_store'] = {'location': '~/derohe-persist/forensics_raw/blobs (outside git)', 'count': len(blobs),
                            'index_sha256': hashlib.sha256(''.join(b + '\n' for b in blobs).encode()).hexdigest()}
    mf.write_text(json.dumps(m, indent=1, sort_keys=True) + '\n')
    print('manifest', len(files), 'files', sha(mf))


if __name__ == '__main__':
    main()
