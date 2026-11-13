#!/usr/bin/env python3
"""regen_round.py — r28 (rft §7 B53, §0.6 rule 6, §6 steps 3a/15): the one-command regeneration that brings G25 to 0.

Every round start since R24 opened with coherence drifts of one class (B53): the start captures (area scorecard,
chain and peer observatories) and the round's first commits are newer than dero-src-arch.html and the evolution
record, so coherence names 'rebuild: miners + gen_deroarch.py build' / 'run mine_evolution.py, then gen_deroarch.py
build' (R28 Part A: 10 drifts, <scratch>/r28/live/coherence_start.txt). The fix was typed by hand each time, in the
order the R27 merge record states (rft §13 live log 2026-11-05 13:08): prep_corpus -> the 13 miners + runtime/triage
on their on-disk inputs (no --capture: no new live read) + coverage -> gen_deroarch build --strict -> retrofit ->
gen_index -> soundpage --check-measured -> coherence. This tool is that order, tracked (STEPS), with a KAT
(harness/kat/test_harness_measure_r28.py HS7: the miner order equals the pipeline S7 order, every step after its
inputs, no step that connects to derod).

It never captures (no RPC, no getwork, no P2P): a stale capture is refreshed by its own observatory first; this tool
only rebuilds what is generated from the files already on disk. A CLOSED ledger page is never regenerated here (its
inputs are frozen, rft §0.6; Part A closes it).

  python3 -I harness/pipeline/regen_round.py              # dry run: print the plan, run nothing (exit 0)
  python3 -I harness/pipeline/regen_round.py --apply      # run each step at nice 15; stop at the first failure
Exit 0 coherence PASS (or dry run) · 4 coherence still drifts after the regeneration · 3 a step failed · 2 bad args.
"""
import os, subprocess, sys, time
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parent.parent.parent
PY = sys.executable
# the S7 miner order of harness/pipeline/fix_build_verify.py s7_project (KAT HS7 compares them)
MINERS = ('inventory', 'consts', 'flows', 'logbridge', 'localdiff', 'evolution', 'findings', 'press', 'forensics', 'intel',
          'areas', 'consensus', 'peers')
STEPS = ([['harness/prep_corpus.py']]
         + [[f'harness/miners/mine_{m}.py'] for m in MINERS]
         + [['harness/miners/mine_runtime.py'],            # on-disk snapshot only (no --capture)
            ['harness/miners/mine_triage.py'],             # on-disk inputs only (no --capture)
            ['harness/miners/mine_coverage.py'],           # last miner: it reads every other raw file
            ['harness/gen_deroarch.py', 'build', '--strict'],
            ['harness/kit/retrofit.py', 'apply', 'harness/model/evidence/release151-migration-report.json'],
            ['harness/kit/soundpage.py', '--write-gen'],   # r30 (B225): the soundness page's record blocks
            ['harness/kit/soundpage.py', '--write-known'], # r30 merge (v5): the dataset section; G30/G31 fail without it
            ['artifacts/src/gen_enhancements.py'],         # r31 prep (rft §2.27): before the index that lists it
            ['harness/gen_index.py'],
            ['harness/kit/soundpage.py', '--check-measured'],
            ['harness/intel/coherence.py', '--record']])
CAPTURE_FLAGS = ('--capture', '--live')                    # a regeneration never reads the live node
OK_RC = {'harness/intel/coherence.py': (0, 4)}             # 4 = drift: reported as the result, not a crash


def plan():
    return [' '.join(s) for s in STEPS]


def apply(root=ROOT, run=None, log=print, clock=time.monotonic):
    """run STEPS in `root` (cwd) one by one; returns (exit code, [(step, rc, secs)]). `run(argv, cwd)` -> rc is
    injectable for the KAT."""
    run = run or (lambda argv, cwd: subprocess.run(['nice', '-n', '15', PY, '-I'] + argv, cwd=cwd).returncode)
    done = []
    for s in STEPS:
        if any(f in s for f in CAPTURE_FLAGS):
            log(f'refused: {" ".join(s)} would read the live node')
            return 3, done
        t = clock()
        rc = run(s, str(root))
        done.append((' '.join(s), rc, round(clock() - t, 1)))
        log(f'[regen] {" ".join(s)} rc {rc} ({done[-1][2]} s)')
        if rc not in OK_RC.get(s[0], (0,)):
            log(f'[regen] FAILED at {" ".join(s)} (rc {rc}); fix the cause, then re-run (earlier steps are idempotent)')
            return 3, done
    return (4 if done and done[-1][1] == 4 else 0), done


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    bad = [a for a in argv if a not in ('--apply',)]
    if bad:
        print(f'regen_round: unknown argument(s) {bad}')
        return 2
    if '--apply' not in argv:
        print('regen_round dry run (nothing runs; --apply runs each step at nice 15):')
        for i, s in enumerate(plan(), 1):
            print(f'  {i:2d}. {s}')
        return 0
    os.chdir(ROOT)
    rc, done = apply(ROOT)
    print(f"regen_round: {len(done)}/{len(STEPS)} steps, {sum(d[2] for d in done):.0f} s · "
          f"{'coherence PASS' if rc == 0 else 'coherence DRIFT' if rc == 4 else 'FAILED'}")
    return rc


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
