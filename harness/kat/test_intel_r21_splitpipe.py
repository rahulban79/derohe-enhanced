#!/usr/bin/env python3
"""Known-answer test + mutation proof for the R21 splitpipe harness change (no network, no live file written).

  IK21 miner_intel.split_stats reads the r21 'GPU split' field gpu_busy_pct (wall-clock GPU duty, the union of the
       command buffers' spans) as a run mean, and reports None on logs that predate it (never 0)

  python3 -I harness/kat/test_intel_r21_splitpipe.py
Exit 0 ok · 3 the KAT failed · 4 the mutation was not caught.
"""
import importlib.util, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
MOD = 'intel/miner_intel.py'


def load(path):
    spec = importlib.util.spec_from_file_location(f'miner_intel_{abs(hash(str(path)))}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def line(t, **kv):
    d = {'M': 'GPU split', 'T': t, 'staged_H/s': '70000', 'dropped_stale': 0}
    d.update(kv)
    return d


def ik21(m):
    run = [line('2026-10-28T13:15:54.098-0700', gpu_busy_pct='60.0'), line('2026-10-28T13:16:54.098-0700', gpu_busy_pct='70.0'),
           line('2026-10-28T13:17:54.098-0700', gpu_busy_pct='80.0')]
    got = m.split_stats(run).get('gpu_busy_pct_mean')
    if got != 70.0:
        return f'gpu_busy_pct_mean {got!r}, want 70.0'
    old = [line('2026-10-28T13:15:54.098-0700'), line('2026-10-28T13:16:54.098-0700')]
    got = m.split_stats(old).get('gpu_busy_pct_mean', 'missing')
    if got is not None:
        return f'pre-r21 log: gpu_busy_pct_mean {got!r}, want None'
    return None


MUTATIONS = [
    ("if any('gpu_busy_pct' in d for d in S) else None", "if True else None", 'an old log reports a 0% GPU duty'),
    ("for d in S if 'gpu_busy_pct' in d), 1)", "for d in S[-1:] if 'gpu_busy_pct' in d), 1)", 'only the last window is read'),
]


def main():
    err = ik21(load(HARNESS / MOD))
    if err:
        print('FAIL IK21', err)
        return 3
    print('ok   IK21')
    missed = 0
    src = (HARNESS / MOD).read_text()
    for find, repl, why in MUTATIONS:
        if src.count(find) != 1:
            print('STALE', why)
            missed += 1
            continue
        d = Path(tempfile.mkdtemp(prefix='ik21-'))
        try:
            p = d / 'miner_intel.py'
            p.write_text(src.replace(find, repl))
            try:
                caught = ik21(load(p)) is not None
            except Exception:
                caught = True
        finally:
            shutil.rmtree(d)
        print('CAUGHT' if caught else 'MISSED', why)
        missed += 0 if caught else 1
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
