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
import argparse, hashlib, json, os, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import replay  # noqa: E402
import verify_dataset  # noqa: E402


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
    if man.get('replay_tool') == 'harness/forensics/v3.py':  # R28: dataset v3 (content pins + v2.derive + run C corrections)
        import v3
        s3 = Path(os.environ.get('FORENSICS_R28_STORE', Path.home() / 'derohe-persist/forensics_raw_r26'))
        rep = v3.replay(ds, s3 if (s3 / 'blobs').is_dir() else None)
        txt = v3.v2.dumps(rep)
    elif man.get('replay_tool') == 'harness/forensics/v2.py':  # r26: dataset v2 has its own re-derivation (v2.py replay)
        import v2
        s2 = Path(os.environ.get('FORENSICS_R26_STORE', Path.home() / 'derohe-persist/forensics_raw_r26'))
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
    label = (f"FULL: {rep['rederive']['equal']}/{rep['rederive']['expected']} derived files re-derived, report "
             f"{'equal to' if rsha in recorded else 'DIFFERENT from'} the recorded G28 runs" if mode == 'full' else
             f"PARTIAL ({'no tier B store' if not store else 'no archive copy'} on this machine): "
             f"{rep.get('rederive', {}).get('rederived', 0)} files re-derived, {len(rep.get('rederive', {}).get('hash_checked_only', []))} "
             'hash-checked only; G28 still rests on the two recorded full runs')
    out = {'dataset': ds.name, 'manifest_sha256': rep['manifest_sha256'], 'mode': mode, 'result': 'PASS' if ok else 'FAIL',
           'report_sha256': rsha, 'label': label, 'fail_reasons': rep.get('fail_reasons', [])}
    Path(a.out).write_text(json.dumps(out, indent=1, sort_keys=True) + '\n')
    print(('PASS ' if ok else 'FAIL ') + label)
    return 0 if ok else 5


if __name__ == '__main__':
    sys.exit(main())
