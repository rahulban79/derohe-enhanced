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
  python3 -I harness/pipeline/regen_round.py --apply      # run each step at nice 15; stop at the first failure;
                                                         # then the page gates
  python3 -I harness/pipeline/regen_round.py --gates      # the page gates only (r31 B271)
r31 (B271b): after retrofit it re-renders the current round's ledger page as S7 does (gen_ledger.py --last <N>, N from
harness/round.json). r31 (B271): then the page-level gates on the regenerated pages, before any closing project-only
run: G30 (facts.py --g30), the FE8 forensics-frontend KAT, pdfscan of artifacts/*.pdf, a pubscrub dry run of the
published pages into a scratch dir (the out-of-repo tool, read-only: -B, DERO_PDFSCAN = this tree's pdfscan; absent =
SKIP with the reason) and coherence. KAT harness/kat/test_regen_gates_r31.py; HS7 (test_harness_measure_r28).
Exit 0 coherence PASS (or dry run) · 4 coherence still drifts after the regeneration · 3 a step failed · 6 a page gate
FAILED · 2 bad args · 5 the regeneration and its gates PASS but the area proposals feed is STALE (below).
r31 (detector agent note, rft §8 R31 Part B item 7): when the area detector records are stale (harness/intel/detectors.py
--check: a scanned input, the tool or the registry changed since they were written) the regeneration re-runs
`detectors.py --all` right after prep_corpus (a pure on-disk scan, never the node). The proposals feed
(harness/runtime/area_proposals.json) is written by area_intel.py, which reads derod's /metrics with --live, so this tool
never runs it: when the feed was not built from the detector records now on disk (a record stale, missing, or written
after the feed) it names the command (python3 -I harness/intel/area_intel.py --live) and exits 5.
"""
import json, os, re, shutil, subprocess, sys, tempfile, time
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parent.parent.parent
PY = sys.executable
# the S7 miner order of harness/pipeline/fix_build_verify.py s7_project (KAT HS7 compares them)
MINERS = ('inventory', 'consts', 'flows', 'logbridge', 'localdiff', 'evolution', 'findings', 'press', 'forensics', 'intel',
          'areas', 'consensus', 'peers')
HEAD_STEPS = ([['harness/prep_corpus.py']]
              + [[f'harness/miners/mine_{m}.py'] for m in MINERS]
              + [['harness/miners/mine_runtime.py'],            # on-disk snapshot only (no --capture)
                 ['harness/miners/mine_triage.py'],             # on-disk inputs only (no --capture)
                 ['harness/miners/mine_coverage.py'],           # last miner: it reads every other raw file
                 ['harness/gen_deroarch.py', 'build', '--strict'],
                 ['harness/kit/retrofit.py', 'apply', 'harness/model/evidence/release151-migration-report.json']])


def ledger_step(root=ROOT):
    """r31 (B271b): the S7 re-render of the CURRENT round's ledger page (fix_build_verify s7_project: gen_ledger.py
    --last <N> artifacts/dero-r1-r<N>.html), N read from harness/round.json 'current' (a sub-round r28d re-renders its
    parent's page, as S7 does); [] when the round has no page yet (S7 skips it then too). The pipeline re-renders it
    after rewriting area_intel.json; without it here a regen after a pipeline run ends in coherence DRIFT (2026-11-13:
    16 drifts, the ledger's Areas section and observatory names)."""
    root = Path(root)
    try:
        cur = json.loads((root / 'harness/round.json').read_text()).get('current')
    except (OSError, ValueError, AttributeError):
        return []
    m = re.fullmatch(r'r(\d+)[a-z]?', str(cur or ''))
    if not m or not (root / f'artifacts/dero-r1-r{m.group(1)}.html').exists():
        return []
    return [['artifacts/src/gen_ledger.py', '--last', m.group(1), f'artifacts/dero-r1-r{m.group(1)}.html']]


TAIL_STEPS = ([['harness/kit/soundpage.py', '--write-gen'],   # r30 (B225): the soundness page's record blocks
            ['harness/kit/soundpage.py', '--write-known'], # r30 merge (v5): the dataset section; G30/G31 fail without it
            ['artifacts/src/gen_enhancements.py'],         # r31 prep (rft §2.27): before the index that lists it
            ['harness/gen_index.py'],
            ['harness/kit/soundpage.py', '--write-measured'],  # r31 (B329): the measured line reads round.json; write it, then check
            ['harness/kit/soundpage.py', '--check-measured'],
            ['harness/intel/coherence.py', '--record']])


DETECTORS = 'harness/intel/detectors.py'
FEED = 'harness/runtime/area_proposals.json'
FEED_CMD = 'python3 -I harness/intel/area_intel.py --live'
FEED_STALE = 5


def detectors_mod(root=ROOT):
    """the tree's harness/intel/detectors.py as a module (None when the tree has none: older trees regenerate as before)."""
    import importlib.util
    tool = Path(root) / DETECTORS
    if not tool.is_file():
        return None
    spec = importlib.util.spec_from_file_location(f'regen_detectors_{abs(hash(str(tool)))}', tool)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def detector_stale(root=ROOT, D=None):
    """{detector: [reasons]} of every stale or missing detector record of `root` (the detectors.py --check rule:
    stale_reasons); {} when all are fresh or the tree has no detectors.py. Reads files only."""
    D = D or detectors_mod(root)
    if D is None:
        return {}
    return {n: rs for n in D.DETECTORS for rs in [D.stale_reasons(Path(root), n)] if rs}


def detector_step(root=ROOT, D=None):
    """[[detectors.py, --all]] when a detector record of `root` is stale (re-run before the miners read the tree),
    else []. --all is a static scan of the tree: it never reads the live node."""
    return [[DETECTORS, '--all']] if detector_stale(root, D) else []


def feed_stale(root=ROOT, D=None):
    """[] when the area proposals feed was built from the detector records now on disk; else the reasons: the feed is
    missing or unreadable, a detector record is stale / missing, or a record was written after the feed read it (its
    generated_at differs from the feed's detectors[name].generated_at). Reads files only."""
    root = Path(root)
    D = D or detectors_mod(root)
    if D is None:
        return []
    try:
        feed = json.loads((root / FEED).read_text())
    except OSError:
        return [f'{FEED} missing']
    except ValueError:
        return [f'{FEED} unreadable']
    seen = feed.get('detectors') or {}
    out = [f'detector {n} record {"; ".join(rs)}' for n, rs in detector_stale(root, D).items()]
    for n in D.DETECTORS:
        try:
            gen = json.loads((root / f'{D.OUT_DIR}/detector_{n}.json').read_text()).get('generated_at')
        except (OSError, ValueError):
            continue
        if (seen.get(n) or {}).get('generated_at') != gen:
            out.append(f"detector {n} record written {gen}, the feed (run {feed.get('run_id', '?')}) read "
                       f"{(seen.get(n) or {}).get('generated_at', 'none')}")
    return out


def steps(root=ROOT):
    """the regeneration of `root`, in order: prep_corpus, the area detectors when their records are stale (r31),
    miners .. retrofit, the current round's ledger re-render (B271b), then the soundness / enhancements / index pages
    and coherence."""
    return HEAD_STEPS[:1] + detector_step(root) + HEAD_STEPS[1:] + ledger_step(root) + TAIL_STEPS


STEPS = steps()
CAPTURE_FLAGS = ('--capture', '--live')                    # a regeneration never reads the live node
OK_RC = {'harness/intel/coherence.py': (0, 4)}             # 4 = drift: reported as the result, not a crash


# r31 (B271, R31-3): the page-level gates on the regenerated pages, BEFORE any closing project-only run. The R30 closing
# runs 1-4 each failed on ONE page-level defect (B263, B264, the pdfscan IPv4 false positive, B265) that these checks
# would have found in minutes. Each gate: (name, argv | None, skip reason | None, env additions). Run after --apply's
# steps, or alone with --gates. A gate that cannot run is a SKIP with its reason, never a silent PASS.
PUBSCRUB = Path(os.environ.get('DERO_PUBSCRUB') or Path.home() / 'a private export toolpubscrub.py')
PUB_PAGES = ('artifacts/dero-r1-r{n}.html', 'artifacts/dero-soundness-{r}.html', 'artifacts/dero-src-arch.html',
             'artifacts/index.html', 'artifacts/dero-enhancements-*.html')   # the published Artifact pages (rft §6 step 18)
GATE_FAIL = 6


def current_round(root=ROOT):
    try:
        return str(json.loads((Path(root) / 'harness/round.json').read_text()).get('current') or '')
    except (OSError, ValueError, AttributeError):
        return ''


def pub_pages(root=ROOT):
    """the regenerated pages that are published (relative paths that exist), for the pubscrub dry run."""
    root, r = Path(root), current_round(root)
    m = re.fullmatch(r'r(\d+)[a-z]?', r)
    out = []
    for pat in PUB_PAGES:
        if '{n}' in pat and not m:
            continue
        pat = pat.format(n=m.group(1) if m else '', r=r)
        out += sorted(str(q.relative_to(root)) for q in root.glob(pat))
    return out


def gate_plan(root=ROOT, pubscrub=None, out_dir=None):
    """[(name, argv | None, skip_reason | None, env)] of the page gates of `root`. Pure apart from reading the tree."""
    root = Path(root)
    pubscrub = Path(pubscrub or PUBSCRUB)
    pdfs = sorted(str(q.relative_to(root)) for q in (root / 'artifacts').glob('*.pdf'))
    pages = pub_pages(root)
    g = [('G30 forensics frontend', [PY, '-I', 'harness/forensics/facts.py', '--g30'], None, {}),
         ('FE8 forensics frontend KAT', [PY, '-I', 'harness/kat/test_forensics_frontend2_r26.py'], None, {}),
         ('pdfscan', [PY, '-I', 'harness/kit/pdfscan.py'] + pdfs if pdfs else None,
          None if pdfs else 'no PDF in artifacts/ (the ledger PDF is printed at publish: scan it then)', {})]
    if not pubscrub.is_file():
        g.append(('pubscrub dry run', None, f'no pubscrub at {pubscrub.name} (outside the repo: the publish step checks it)', {}))
    elif not pages:
        g.append(('pubscrub dry run', None, 'no published page in artifacts/', {}))
    else:
        # read-only: -B (no __pycache__ beside the tool), every output into a scratch out dir, the repo's pdfscan
        g.append(('pubscrub dry run', [PY, '-I', '-B', str(pubscrub), str(out_dir or '<scratch out dir>')] + pages, None,
                  {'DERO_PDFSCAN': str(root / 'harness/kit/pdfscan.py')}))
    g.append(('doc currency', [PY, '-I', 'harness/intel/doc_currency.py'], None, {}))   # r31 (B332): round summaries reviewed
    g.append(('readme build', [PY, '-I', 'harness/intel/readme_build.py', '--check'], None, {}))   # r32a: build/run section current
    g.append(('coherence', [PY, '-I', 'harness/intel/coherence.py'], None, {}))
    return g


def gates_rc(results):
    """GATE_FAIL when any gate FAILED, else 0 (a SKIP is reported, not failed). Pure."""
    return GATE_FAIL if any(v == 'FAIL' for _, v, _ in results) else 0


def page_gates(root=ROOT, run=None, log=print, pubscrub=None, scratch=None):
    """run the page gates; [(name, PASS|FAIL|SKIP, detail)]. `run(argv, cwd, env)` -> (rc, tail) is injectable."""
    def _run(argv, cwd, env):
        r = subprocess.run(['nice', '-n', '15'] + argv, cwd=cwd, env=dict(os.environ, **env), capture_output=True, text=True)
        return r.returncode, (r.stdout + r.stderr).strip().splitlines()[-1:]
    run = run or _run
    out_dir = tempfile.mkdtemp(prefix='regen-pubscrub-', dir=scratch or os.environ.get('REGEN_SCRATCH') or None)
    res = []
    try:
        for name, argv, skip, env in gate_plan(root, pubscrub, out_dir):
            if argv is None:
                res.append((name, 'SKIP', skip))
            else:
                rc, tail = run(argv, str(root), env)
                res.append((name, 'PASS' if rc == 0 else 'FAIL', f'rc {rc} ' + ' '.join(tail)[:300]))
            log(f'[gate] {res[-1][1]:<4} {name}: {res[-1][2]}')
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)
    return res


def plan(root=ROOT):
    return [' '.join(s) for s in steps(root)]


def apply(root=ROOT, run=None, log=print, clock=time.monotonic):
    """run STEPS in `root` (cwd) one by one; returns (exit code, [(step, rc, secs)]). `run(argv, cwd)` -> rc is
    injectable for the KAT."""
    run = run or (lambda argv, cwd: subprocess.run(['nice', '-n', '15', PY, '-I'] + argv, cwd=cwd).returncode)
    done = []
    for s in steps(root):
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
    if done and done[-1][1] == 4:
        return 4, done
    fs = feed_stale(root)                                  # r31: the feed is area_intel's (it reads the node): name it
    if fs:
        log(f'[regen] FEED STALE: {FEED} was not built from the detector records on disk ({"; ".join(fs[:3])}'
            f'{" ..." if len(fs) > 3 else ""}): run {FEED_CMD} (it reads /metrics; this tool never does)')
        return FEED_STALE, done
    return 0, done


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    bad = [a for a in argv if a not in ('--apply', '--gates')]
    if bad:
        print(f'regen_round: unknown argument(s) {bad}')
        return 2
    if '--gates' in argv and '--apply' not in argv:
        os.chdir(ROOT)
        res = page_gates(ROOT)
        grc = gates_rc(res)
        print(f"regen_round --gates: {sum(v == 'PASS' for _, v, _ in res)} PASS, {sum(v == 'FAIL' for _, v, _ in res)} FAIL, "
              f"{sum(v == 'SKIP' for _, v, _ in res)} SKIP · {'page gates PASS' if not grc else 'a page gate FAILED'}")
        return grc
    if '--apply' not in argv:
        print('regen_round dry run (nothing runs; --apply runs each step at nice 15, then the page gates):')
        for i, s in enumerate(plan(), 1):
            print(f'  {i:2d}. {s}')
        fs = feed_stale(ROOT)
        print(f'  feed {FEED}: ' + (f'STALE ({len(fs)} reason(s)); after the regeneration run {FEED_CMD}' if fs else 'built from the detector records on disk'))
        for name, argv_, skip, _ in gate_plan(ROOT):
            print(f'  gate {name}: ' + (' '.join(str(x).replace(str(Path.home()), '~') for x in argv_[1:5]) + (' ...' if len(argv_) > 5 else '') if argv_ else f'SKIP ({skip})'))
        return 0
    os.chdir(ROOT)
    planned = len(steps(ROOT))                             # before the run: a detector re-run leaves the records fresh
    rc, done = apply(ROOT)
    print(f"regen_round: {len(done)}/{planned} steps, {sum(d[2] for d in done):.0f} s · "
          f"{'coherence PASS' if rc in (0, FEED_STALE) else 'coherence DRIFT' if rc == 4 else 'FAILED'}"
          + (f' · area feed STALE: run {FEED_CMD}' if rc == FEED_STALE else ''))
    if rc == 3:
        return rc
    grc = gates_rc(page_gates(ROOT))                       # r31 (B271): the page gates before any closing run
    print(f"regen_round: page gates {'PASS' if not grc else 'FAILED (fix before the closing project-only run)'}")
    return grc or rc


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
