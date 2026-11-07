#!/usr/bin/env python3
"""round_checkpoint.py — snapshot what a DERO round has done, what is in flight and what is pending, so a session that
stops (token run-out, crash, closed terminal) can be resumed from the exact point. dero-rft.md §2.13 / §0.10.

Reads only live sources (never memory of the conversation): harness/round.json, git log since the round base, the
workflow journals of the session (started vs result per agent label), the round's scratch dirs (patches, verify.md),
the pipeline records, bin/derod --version, the running derod, the GitHub copy. Writes:
  ~/derohe-persist/round_state/<round>_state.json   machine-readable state
  ~/derohe-persist/round_state/<round>_RESUME.md    human / next-session resume brief (the exact commands)
  ~/derohe-persist/round_state/history/<stamp>_*    one copy per run (pruned to the last 200)
Usage: round_checkpoint.py [--loop SECONDS]   (nice it; read-only except its own output dir)

r25 (§2.13): this file (harness/intel/round_checkpoint.py) is the source of truth; ~/derohe-persist/round_checkpoint.py
execs it when the repo copy exists (and keeps its own last copy as the fallback). KAT: harness/kat/test_round_checkpoint_r25.py
(RC1 a planted in-flight agent is listed in-flight; RC2 a DONE step is never re-listed as pending: done is sticky across
runs and a step whose live probe now fails is shown 'done, re-verify'; RC3 history is pruned to HISTORY_KEEP; RC4 only a
'R<id>: ... merge' subject is the merge commit; RC5 a <round>_NOTES.md in OUT is appended to the brief). Paths are overridable for the KAT: ROUND_CKPT_REPO, ROUND_CKPT_OUT,
ROUND_CKPT_PROJ, ROUND_CKPT_SCRATCH, ROUND_CKPT_PUB.
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import json, os, re, subprocess, sys, time, glob, shutil
from pathlib import Path

HOME = Path.home()
_HERE = Path(__file__).resolve()
_REPO_DEFAULT = _HERE.parents[2] if _HERE.parent.name == 'intel' and _HERE.parents[1].name == 'harness' \
    else HOME / 'derohe-Release151'
REPO = Path(os.environ.get('ROUND_CKPT_REPO') or _REPO_DEFAULT)
PUB = Path(os.environ.get('ROUND_CKPT_PUB') or HOME / 'public-copy')
OUT = Path(os.environ.get('ROUND_CKPT_OUT') or HOME / 'derohe-persist' / 'round_state')
PROJ = Path(os.environ.get('ROUND_CKPT_PROJ') or HOME / '.claude' / 'projects' / 'project')
SCRATCH_ROOT = Path(os.environ.get('ROUND_CKPT_SCRATCH') or '<scratch>')
HISTORY_KEEP = 200

# the §6 end-of-round order (dero-rft.md §6 parts A-E), with a probe that decides done / not done from live sources
STEPS = [
    ('A1 round opened in registry', lambda s: s['registry'].get('status') in ('in-progress', 'implemented', 'shipped', 'measured')),
    ('B  open-loop workflows finished', lambda s: s['workflows'] and all(w['done'] >= w['started'] > 0 for w in s['workflows'])),
    ('C  merge commit "R<id>:" on local-enhancements', lambda s: bool(s['merge_commits'])),
    ('C  full pipeline PASS after the merge', lambda s: s['last_full_pipeline_pass_after_merge']),
    ('C  installed: bin/derod reports the round suffix', lambda s: s['installed']),
    ('D  ledger dero-r1-r<id>.html exists', lambda s: s['ledger_exists']),
    ('D  registry status implemented', lambda s: s['registry'].get('status') in ('implemented', 'shipped', 'measured')),
    # r25: 'after the docs' = the ledger page exists (a project-only PASS before the docs is not this step; sticky DONE
    # would otherwise freeze an early PASS)
    ('D  project-only pipeline PASS after the docs', lambda s: s['ledger_exists'] and s['last_project_pass']),
    ('D  user notified to restart derod (see RESUME notes)', lambda s: s['derod_running_suffix'] == s['suffix']),
    ('E  live measurement read (registry measured)', lambda s: s['registry'].get('status') == 'measured'),
    ('E  GitHub copy synced to the measured head', lambda s: s['github_synced']),
]


def select_derod(rows, repo, cwd_of):
    """r28 (tools-kats, N28-05): the pid (str) of the running derod, or '' when there is none or it is ambiguous.
    rows = [(pid, ucomm)] from `ps -axo pid=,ucomm=`: only a process whose accounting name is EXACTLY 'derod' is a
    candidate, so a shell, a `tail -f derod.log` or a wait loop that merely carries 'bin/derod --data-dir' in its
    command line can never be picked (the old `pgrep -f '^./bin/derod|bin/derod --data-dir' | head -1` matched full
    command lines, rft §5 asks for pid-based waits). Two or more derods (the S5 shadow beside the user's node): the
    one whose working directory is `repo` (cwd_of(pid) -> path or None); still ambiguous -> ''. Pure apart from
    cwd_of."""
    cands = sorted({str(p).strip() for p, c in rows if str(c).strip() == 'derod' and str(p).strip().isdigit()}, key=int)
    if len(cands) <= 1:
        return cands[0] if cands else ''
    want = os.path.realpath(str(repo))
    mine = [p for p in cands if (cwd_of(p) or '') and os.path.realpath(cwd_of(p)) == want]
    return mine[0] if len(mine) == 1 else ''


def ps_rows():
    """[(pid, ucomm)] of every process (read-only `ps`); [] when ps fails"""
    out = sh(['ps', '-axo', 'pid=,ucomm='])
    if out.startswith('ERR'):
        return []
    return [tuple(l.split(None, 1)) for l in out.splitlines() if len(l.split(None, 1)) == 2]


def cwd_of(pid):
    """the working directory of pid from `lsof -a -p PID -d cwd -Fn` (read-only), or None"""
    out = sh(['lsof', '-a', '-p', str(pid), '-d', 'cwd', '-Fn'])
    return next((l[1:] for l in out.splitlines() if l.startswith('n/')), None)


def sh(cmd, cwd=None, timeout=60):
    try:
        return subprocess.run(cmd, cwd=cwd, shell=isinstance(cmd, str), capture_output=True, text=True,
                              timeout=timeout).stdout.strip()
    except Exception as e:  # a missing tool must not stop the checkpoint
        return f'ERR {e}'


def registry():
    d = json.loads((REPO / 'harness/round.json').read_text())
    cur = d.get('current')
    r = next((x for x in d['rounds'] if x['id'] == cur), {})
    return cur, r, d


def workflows(since_ts, proj=None):
    """every workflow journal of the project newer than since_ts: per agent 'in-flight' (started, no result) or 'done'
    (with its summary). Pure on the files under proj (KAT RC1)."""
    proj = PROJ if proj is None else Path(proj)
    out = []
    for jd in sorted(proj.glob('*/subagents/workflows/wf_*')):
        j = jd / 'journal.jsonl'
        if not j.exists() or j.stat().st_mtime < since_ts:
            continue
        started, done, labels = 0, 0, {}
        for line in j.read_text().splitlines():
            try:
                x = json.loads(line)
            except ValueError:
                continue
            if x.get('type') == 'started':
                started += 1
                labels[x.get('key')] = {'label': x.get('label'), 'state': 'in-flight'}
            elif x.get('type') == 'result':
                done += 1
                k = x.get('key')
                labels.setdefault(k, {'label': '?'})['state'] = 'done'
                res = x.get('result') or {}
                if isinstance(res, dict):
                    labels[k]['summary'] = ' '.join(str(res.get('summary') or res.get('verdict') or '').split())[:300]
        script = next(iter(sorted(proj.glob(f'*/workflows/scripts/*-{jd.name}.js'))), None)
        out.append({'run_id': jd.name, 'started': started, 'done': done, 'script': str(script) if script else None,
                    'agents': list(labels.values()), 'journal': str(j)})
    return out


def merge_commits(log, tag):
    """the round's merge commits among 'hash subject' lines: subject 'R<id>: ...' (or 'R<id> ...') that names a merge.
    r25: any 'R25:' subject used to count, so the rft-only commit a888afd marked step C done before any merge. Pure (RC4)."""
    return [l for l in log if re.match(rf'^\w+ {re.escape(tag)}\b:?.*\bmerge\b', l, re.I)]


def run_result(txt):
    """(full, passed) of one pipeline record (harness/loop/runs/pipeline_*.jsonl). full = it ran the shadow (S5), so a
    --no-install full run counts; passed = its 'done' event says ok true. r25: passed used to look for a 'run' PASS
    event or a 'verdict' that the pipeline never writes, so no run ever counted as PASS (step C stayed NOT DONE after
    pipeline_20261103T182557 PASS). Pure (RC6)."""
    full = bool(re.search(r'"stage":\s*"(shadow|install)"', txt))
    done = [l for l in txt.splitlines() if re.search(r'"stage":\s*"done"', l)]
    return full, bool(done) and bool(re.search(r'"ok":\s*true', done[-1]))


def sticky_steps(probed, prev):
    """the step list of this run: a step DONE in the previous state stays DONE (§0.10: never redo a DONE step); when its
    live probe now fails it is marked 'reverify' (re-verify it; lesson #69), never re-listed as pending. Pure (RC2)."""
    was = {p.get('step') for p in (prev or []) if p.get('done')}
    out = []
    for st in probed:
        s = dict(st)
        if not s['done'] and s['step'] in was:
            s['done'], s['reverify'] = True, True
        out.append(s)
    return out


def prune_history(h, keep=HISTORY_KEEP):
    """keep the newest `keep` history copies (names start with the sortable stamp). Returns the number removed (RC3)."""
    old = sorted(p for p in Path(h).glob('*') if p.is_file())[:-keep] if keep > 0 else []
    for p in old:
        p.unlink()
    return len(old)


def previous_steps(round_id, out=None):
    try:
        return json.loads((Path(out or OUT) / f'{round_id}_state.json').read_text()).get('steps') or []
    except (OSError, ValueError):
        return []


def snapshot():
    cur, r, d = registry()
    base = r.get('new_tests_base') or 'HEAD~1'
    suffix = r.get('version_suffix') if r.get('version_suffix') not in (None, 'pending') else f'22102026.{cur}'
    log = sh(['git', 'log', '--format=%h %s', f'{base}..HEAD'], cwd=REPO).splitlines()
    tag = cur.upper()
    merge = merge_commits(log, tag)
    runs = sorted((REPO / 'harness/loop/runs').glob('pipeline_*.jsonl'))
    def result(p):
        return run_result(p.read_text(errors='replace'))
    merge_time = 0
    if merge:
        merge_time = int(sh(['git', 'log', '-1', '--format=%ct', merge[-1].split()[0]], cwd=REPO) or 0)
    full_pass = proj_pass = False
    last_runs = []
    for p in runs[-12:]:
        full, ok = result(p)
        last_runs.append({'run': p.stem, 'full': full, 'pass': ok})
        if p.stat().st_mtime >= merge_time and merge_time:
            full_pass = full_pass or (full and ok)
        proj_pass = ok if not full else proj_pass
    ver = sh([str(REPO / 'bin/derod'), '--version'])
    run_ver = ''
    pid = select_derod(ps_rows(), REPO, cwd_of)           # r28 N28-05: exact process name, never a pattern
    if pid:
        lines = sh(f"grep '\"Version\"' {HOME}/dero-data/logs/derod.log | tail -1")
        m = re.search(r'STARGATE\+([\w.]+)', lines)
        run_ver = m.group(1) if m else ''
    scratch = sorted(SCRATCH_ROOT.glob(f'*/scratchpad/{cur}'))
    dims = {}
    for sd in scratch:
        for p in sorted(sd.iterdir()):
            if p.is_dir():
                pats = [str(x) for x in p.glob('*.patch')]
                dims[p.name] = {'dir': str(p), 'patches': pats, 'verify_md': (p / 'verify.md').exists()}
    pub_head = sh(['git', 'log', '-1', '--format=%h %s'], cwd=PUB)
    gs = r.get('github_sync', {})
    s = {
        'stamp': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'round': cur, 'suffix': suffix, 'registry': r,
        'repo_head': sh(['git', 'log', '-1', '--format=%h %s'], cwd=REPO), 'dirty_files': len(sh(['git', 'status', '--short'], cwd=REPO).splitlines()),
        'commits_since_base': log, 'merge_commits': merge,
        'workflows': workflows(int(sh(['git', 'log', '-1', '--format=%ct', base], cwd=REPO) or 0)), 'scratch_dims': dims,
        'pipeline_runs': last_runs, 'last_full_pipeline_pass_after_merge': full_pass, 'last_project_pass': proj_pass,
        'installed': suffix in ver, 'bin_derod_version': ver, 'derod_pid': pid, 'derod_running_suffix': run_ver,
        'ledger_exists': (REPO / f'artifacts/dero-r1-{cur}.html').exists(),
        'github_head': pub_head, 'github_synced': bool(gs.get('target') not in (None, 'pending')) and r.get('status') == 'measured',
        'rft_addendum': [str(p) for p in SCRATCH_ROOT.glob(f'*/scratchpad/{cur}/rft_addendum.md')],
    }
    s['steps'] = sticky_steps([{'step': n, 'done': bool(f(s))} for n, f in STEPS], previous_steps(cur))
    return s


def resume_md(s):
    L = [f"# {s['round'].upper()} resume brief — {s['stamp']}", '',
         'Written by harness/intel/round_checkpoint.py from live sources (dero-rft.md §0.10). A new session: read this, then',
         'dero-rft.md §0.10 and §6 from the first step marked NOT DONE. Never redo a DONE step; re-verify it instead.', '',
         f"- Repo head: `{s['repo_head']}` ({s['dirty_files']} uncommitted files)",
         f"- Registry: `{s['round']}` status **{s['registry'].get('status')}**, base `{s['registry'].get('new_tests_base')}`",
         f"- bin/derod: `{s['bin_derod_version']}`; running derod pid {s['derod_pid'] or 'none'} on `{s['derod_running_suffix'] or '?'}`",
         f"- GitHub copy head: `{s['github_head']}`", '', '## Procedure state (§6)', '']
    for st in s['steps']:
        L.append(f"- [{'x' if st['done'] else ' '}] {st['step']}" + (' (DONE earlier; live probe now fails: re-verify, do not redo)' if st.get('reverify') else ''))
    L += ['', '## Workflows (resume a stopped one with its script + run id; finished agents replay from cache)', '']
    for w in s['workflows']:
        L.append(f"### {w['run_id']}: {w['done']}/{w['started']} agents finished")
        if w['script']:
            L.append(f"Resume: `Workflow({{scriptPath: \"{w['script']}\", resumeFromRunId: \"{w['run_id']}\"}})`")
        for a in w['agents']:
            L.append(f"- {a.get('label')}: **{a.get('state')}**" + (f" — {a['summary']}" if a.get('summary') else ''))
        L.append('')
    L += ['## Scratch outputs of this round', '']
    for k, v in s['scratch_dims'].items():
        L.append(f"- `{k}`: {len(v['patches'])} patch(es){' + verify.md' if v['verify_md'] else ''} — {v['dir']}")
    L += ['', '## Commits since the round base', ''] + [f'- {c}' for c in s['commits_since_base'][:60]]
    L += ['', '## Pipeline runs (newest last)', ''] + [f"- {r['run']}: {'full' if r['full'] else 'project-only'} {'PASS' if r['pass'] else 'not PASS'}" for r in s['pipeline_runs']]
    L += ['', '## User instructions captured this round (verbatim, to be folded into dero-rft.md §2)', ''] + [f'- {p}' for p in s['rft_addendum']]
    notes = OUT / f"{s['round']}_NOTES.md"   # r25: the coordinator's handoff notes, appended verbatim
    if notes.exists():
        L += ['', notes.read_text()]
    return '\n'.join(L) + '\n'


def write(s):
    OUT.mkdir(parents=True, exist_ok=True)
    os.chmod(OUT, 0o700)
    j, m = OUT / f"{s['round']}_state.json", OUT / f"{s['round']}_RESUME.md"
    j.write_text(json.dumps(s, indent=1, default=str) + '\n')
    m.write_text(resume_md(s))
    h = OUT / 'history'
    h.mkdir(exist_ok=True)
    stamp = time.strftime('%Y%m%dT%H%M%S')
    shutil.copy2(m, h / f'{stamp}_{m.name}')
    prune_history(h)
    for sd in SCRATCH_ROOT.glob(f"*/scratchpad/{s['round']}"):   # also next to the round's scratch (mirrored by backup_scratch.sh)
        shutil.copy2(m, sd / m.name)
    return m


if __name__ == '__main__':
    loop = int(sys.argv[sys.argv.index('--loop') + 1]) if '--loop' in sys.argv else 0
    while True:
        print(write(snapshot()), flush=True)
        if not loop:
            break
        time.sleep(loop)
