#!/usr/bin/env python3
"""R25 S7 step (rft §0.8.8, §6 S7): replay the newest forensic dataset on every project run, labelled honestly.

  python3 -I harness/forensics/s7_replay.py [--out harness/runtime/forensics_s7_replay.json]

Full mode needs the tier B store ($FORENSICS_STORE, default ~/derohe-persist/forensics_raw) AND a copy of our replaywall
archive ($FORENSICS_ARCHIVE_COPY, default ~/derohe-persist/forensics_archive_copy, an APFS clone, never the datadir).
On a machine without them the run is PARTIAL and says so: extract/* and archive_state/* are hash-checked only. The run
never writes the G28 record (harness/runtime/forensics_replay.json): G28 keeps judging the two recorded full runs, and
a FULL S7 run must reproduce their report byte for byte (a third, independent byte-exact replay).
Exit 0 = PASS (full, report equal to the recorded one; or partial and labelled) · 5 = FAIL.
"""
import argparse, hashlib, json, os, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import replay  # noqa: E402
import verify_dataset  # noqa: E402


def label(rep, rsha, recorded, missing):
    """r30 (B218): the honest S7 label (pure). A report that did not PASS prints its own fail_reasons (never a guessed
    'no archive copy'); PARTIAL is printed only for a PASS report, naming the inputs that are really absent (`missing`:
    the list of absent inputs this replay tool needs, e.g. ['tier B store', 'archive copy', 'S0 checkpoint'])."""
    mode = rep.get('rederive', {}).get('mode', 'not run')
    if rep.get('result') != 'PASS':
        why = '; '.join(rep.get('fail_reasons', [])[:3]) or 'no reason recorded'
        return f'FAIL: {why}'
    if mode == 'full':
        return (f"FULL: {rep['rederive']['equal']}/{rep['rederive']['expected']} derived files re-derived, report "
                f"{'equal to' if rsha in recorded else 'DIFFERENT from'} the recorded G28 runs")
    return (f"PARTIAL ({', '.join('no ' + m for m in missing) or 'inputs present, re-derivation skipped'} on this machine): "
            f"{rep.get('rederive', {}).get('rederived', 0)} files re-derived, {len(rep.get('rederive', {}).get('hash_checked_only', []))} "
            'hash-checked only; G28 still rests on the two recorded full runs')


PIN_DRIFT = ('content pins: pinned file changed', 'mode partial: content pins differ')  # the drift and its consequence


def use_pinned_snapshot(sealed, rep):
    """r31 (B326): a SEALED newest version whose only failures are content-pin drifts (a later round changed a pinned
    decoder input, e.g. the R31 logging-only blockchain.go edits) is replayed by its pinned source: a pinsnap snapshot
    (rft §6 step 3a: "a sealed version whose pinned bytes moved on is verified by pinsnap"), never re-pinned. An OPEN
    version, any other failure, or a run already inside a snapshot keeps the strict verdict. Pure."""
    reasons = rep.get('fail_reasons') or []
    return (bool(sealed) and rep.get('result') != 'PASS' and bool(reasons) and all(r.startswith(PIN_DRIFT) for r in reasons)
            and any(r.startswith(PIN_DRIFT[0]) for r in reasons)
            and os.environ.get('S7_REPLAY_PINNED') != '1')


def replay_in_snapshot(man, root=ROOT):
    """build the pinned-source snapshot (pinsnap.snapshot: every pin resolved to its exact bytes from git, pins.check
    re-run inside) and run THIS step inside it; returns (out dict or None, problem or None)"""
    import pinsnap
    with tempfile.TemporaryDirectory(prefix='s7pin-') as td:
        s, f = pinsnap.snapshot(man.get('content_pins'), Path(td) / 'src', root)
        if f:
            return None, f'pinned snapshot failed: {f[:3]}'
        o = Path(td) / 'out.json'
        p = subprocess.run([sys.executable, '-I', str(Path(td) / 'src/harness/forensics/s7_replay.py'), '--out', str(o)],
                           cwd=str(Path(td) / 'src'), capture_output=True, text=True,
                           env=dict(os.environ, S7_REPLAY_PINNED='1'), timeout=3600)
        if not o.exists():
            return None, f'snapshot replay wrote no record (rc {p.returncode})'
        return dict(json.loads(o.read_text()), snapshot={k: s.get(k) for k in ('pinned_files', 'from_worktree', 'snapshot_check')}), None


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=str(ROOT / 'harness/runtime/forensics_s7_replay.json'))
    a = ap.parse_args(argv)
    led = json.loads((ROOT / 'forensics/ledger.json').read_text())
    ds = ROOT / 'forensics' / led['versions'][-1]['version']
    store = Path(os.environ.get('FORENSICS_STORE', Path.home() / 'derohe-persist/forensics_raw'))
    arch = Path(os.environ.get('FORENSICS_ARCHIVE_COPY', Path.home() / 'derohe-persist/forensics_archive_copy'))
    store = store if (store / 'blobs').is_dir() else None
    arch = arch if arch.is_dir() else None
    man = json.loads((ds / 'manifest.json').read_text())
    missing = [] if store else ['tier B store']
    if not arch:
        missing.append('archive copy')
    if man.get('replay_tool') == 'harness/forensics/v5.py':  # r30: dataset v5 (v4.derive + the class/S0 files)
        import v5
        s5 = Path(os.environ.get('FORENSICS_R28_STORE', Path.home() / 'derohe-persist/forensics_raw_r26'))
        missing = ([] if (s5 / 'blobs').is_dir() else ['tier B store']) + ([] if v5.S0.DEFAULT_CHECKPOINT.exists() else ['S0 checkpoint'])
        rep = v5.replay(ds, s5 if (s5 / 'blobs').is_dir() else None)
        txt = v5.v2.dumps(rep)
    elif man.get('replay_tool') == 'harness/forensics/v4.py':  # r28d: dataset v4 (v3.derive + the DC1 structure + FQ2 S-RT)
        import v4
        s4 = Path(os.environ.get('FORENSICS_R28_STORE', Path.home() / 'derohe-persist/forensics_raw_r26'))
        missing = [] if (s4 / 'blobs').is_dir() else ['tier B store']
        rep = v4.replay(ds, s4 if (s4 / 'blobs').is_dir() else None)
        txt = v4.v2.dumps(rep)
    elif man.get('replay_tool') == 'harness/forensics/v3.py':  # R28: dataset v3 (content pins + v2.derive + run C corrections)
        import v3
        s3 = Path(os.environ.get('FORENSICS_R28_STORE', Path.home() / 'derohe-persist/forensics_raw_r26'))
        missing = [] if (s3 / 'blobs').is_dir() else ['tier B store']
        rep = v3.replay(ds, s3 if (s3 / 'blobs').is_dir() else None)
        txt = v3.v2.dumps(rep)
    elif man.get('replay_tool') == 'harness/forensics/v2.py':  # r26: dataset v2 has its own re-derivation (v2.py replay)
        import v2
        s2 = Path(os.environ.get('FORENSICS_R26_STORE', Path.home() / 'derohe-persist/forensics_raw_r26'))
        missing = [] if (s2 / 'blobs').is_dir() else ['tier B store']
        rep = v2.replay(ds, s2 if (s2 / 'blobs').is_dir() else None)
        txt = v2.dumps(rep)
    else:
        rep = replay.replay(ds, store, arch)
        txt = replay.dumps(rep)
    rsha = hashlib.sha256(txt.encode()).hexdigest()
    rec_p = ROOT / verify_dataset.RECORD
    rec = json.loads(rec_p.read_text()) if rec_p.exists() else {}
    recorded = {r.get('report_sha256') for r in rec.get('runs', [])} if rec.get('manifest_sha256') == rep['manifest_sha256'] else set()
    mode = rep.get('rederive', {}).get('mode', 'not run')
    ok = rep['result'] == 'PASS' and (mode != 'full' or rsha in recorded)
    out = {'dataset': ds.name, 'manifest_sha256': rep['manifest_sha256'], 'mode': mode, 'result': 'PASS' if ok else 'FAIL',
           'report_sha256': rsha, 'label': label(rep, rsha, recorded, missing), 'fail_reasons': rep.get('fail_reasons', [])}
    if use_pinned_snapshot(led['versions'][-1].get('sealed'), rep):
        snap, prob = replay_in_snapshot(man)
        if prob:
            out['fail_reasons'] = out['fail_reasons'] + [prob]
        else:
            ok = snap.get('result') == 'PASS'
            out = dict(snap, label=f"SEALED, pinned source: {snap.get('label')}", pin_drift=rep.get('fail_reasons', []))
    Path(a.out).write_text(json.dumps(out, indent=1, sort_keys=True) + '\n')
    print(('PASS ' if ok else 'FAIL ') + out['label'])
    return 0 if ok else 5


if __name__ == '__main__':
    sys.exit(main())
