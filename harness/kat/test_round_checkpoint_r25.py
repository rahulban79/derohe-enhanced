#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for harness/intel/round_checkpoint.py (r25, dero-rft §0.10 / §2.13).

  RC1 a planted workflow journal: an agent with 'started' and no 'result' is listed in-flight, a finished one is done
      with its summary, and the resume brief names it in-flight with the exact resume call.
  RC2 a §6 step DONE in the previous state is never re-listed as pending: when its live probe now fails it stays DONE
      and is marked 're-verify, do not redo'; a step never done stays pending; the brief renders both.
  RC3 the history directory is pruned to HISTORY_KEEP (200) copies, and the newest are the ones kept.
  RC4 only an 'R<id>: ... merge' subject is the round's merge commit (the rft-only 'R25: dero-rft §0.10 ...' commit is
      not; another round's merge is not).
  RC5 a planted <round>_NOTES.md (the coordinator's handoff notes) is appended to the resume brief.
  RC6 a pipeline record is a full run when it ran the shadow (a --no-install run counts) and a PASS when its 'done'
      event says ok true.

All inputs are forged in a temporary directory (ROUND_CKPT_* overrides); nothing outside it is read or written.

  python3 -I harness/kat/test_round_checkpoint_r25.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import importlib.util, json, os, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
SRC = HARNESS / 'intel' / 'round_checkpoint.py'


def load(path, env):
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        spec = importlib.util.spec_from_file_location(f'rc25_{abs(hash(str(path)))}', path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return m


def jl(*rows):
    return ''.join(json.dumps(r) + '\n' for r in rows)


def rc1(T, d):
    proj = Path(d) / 'proj'
    wf = proj / 'sess' / 'subagents' / 'workflows' / 'wf_test-1'
    wf.mkdir(parents=True)
    (wf / 'journal.jsonl').write_text(jl({'type': 'launched'},
                                         {'type': 'started', 'key': 'a', 'label': 'verify-peers'},
                                         {'type': 'started', 'key': 'b', 'label': 'forensics-acquire'},
                                         {'type': 'result', 'key': 'a', 'result': {'summary': 'upheld 9/9'}}))
    sc = proj / 'sess' / 'workflows' / 'scripts'
    sc.mkdir(parents=True)
    (sc / 'dero-r25-x-wf_test-1.js').write_text('//')
    w = T.workflows(0, proj)
    ag = {a['label']: a for a in w[0]['agents']} if w else {}
    ok = len(w) == 1 and w[0]['started'] == 2 and w[0]['done'] == 1 and ag.get('forensics-acquire', {}).get('state') == 'in-flight' \
        and ag.get('verify-peers', {}).get('state') == 'done' and ag['verify-peers'].get('summary') == 'upheld 9/9'
    s = {'round': 'r25', 'stamp': 'x', 'repo_head': 'h', 'dirty_files': 0, 'registry': {}, 'bin_derod_version': 'v',
         'derod_pid': '', 'derod_running_suffix': '', 'github_head': 'g', 'steps': [], 'workflows': w, 'scratch_dims': {},
         'commits_since_base': [], 'pipeline_runs': [], 'rft_addendum': []}
    md = T.resume_md(s) if ok else ''
    ok = ok and '- forensics-acquire: **in-flight**' in md and 'resumeFromRunId: "wf_test-1"' in md
    return ok, f"{[(a['label'], a['state']) for x in w for a in x['agents']]}"


def rc2(T, d):
    out = Path(d) / 'out'
    out.mkdir()
    (out / 'r25_state.json').write_text(json.dumps({'steps': [{'step': 'C  merge', 'done': True},
                                                              {'step': 'D  ledger', 'done': False}]}))
    prev = T.previous_steps('r25', out)
    probed = [{'step': 'C  merge', 'done': False}, {'step': 'D  ledger', 'done': False}, {'step': 'E  live', 'done': True}]
    st = T.sticky_steps(probed, prev)
    by = {x['step']: x for x in st}
    ok = by['C  merge']['done'] and by['C  merge'].get('reverify') and not by['D  ledger']['done'] and by['E  live']['done'] \
        and not by['E  live'].get('reverify')
    s = {'round': 'r25', 'stamp': 'x', 'repo_head': 'h', 'dirty_files': 0, 'registry': {}, 'bin_derod_version': 'v',
         'derod_pid': '', 'derod_running_suffix': '', 'github_head': 'g', 'steps': st, 'workflows': [], 'scratch_dims': {},
         'commits_since_base': [], 'pipeline_runs': [], 'rft_addendum': []}
    md = T.resume_md(s)
    ok = ok and '- [x] C  merge (DONE earlier' in md and '- [ ] D  ledger' in md and '- [ ] C  merge' not in md
    return bool(ok), f'{st}'


def rc3(T, d):
    h = Path(d) / 'hist'
    h.mkdir()
    for i in range(250):
        (h / f'20261103T{i:06d}_r25_RESUME.md').write_text(str(i))
    n = T.prune_history(h)
    left = sorted(p.name for p in h.iterdir())
    ok = n == 50 and len(left) == T.HISTORY_KEEP == 200 and left[0] == '20261103T000050_r25_RESUME.md' \
        and left[-1] == '20261103T000249_r25_RESUME.md'
    return ok, f'removed {n} left {len(left)} first {left[:1]} last {left[-1:]}'


def rc4(T, d):
    log = ['a888afd R25: dero-rft §0.10 resume after a stopped session', '17da0dc R25 open: node + forensics',
           'b1 R24: node-only merge (x) -> r24', 'c2 R25: node-only merge (rpcrobust, consensus) -> 3.6.0-153+22102026.r25']
    m = T.merge_commits(log, 'R25')
    return m == [log[3]], f'{m}'


def rc5(T, d):
    """a planted <round>_NOTES.md in OUT (the coordinator's handoff notes) appears verbatim in the brief; absent, none."""
    s = {'round': 'r25', 'stamp': 'x', 'repo_head': 'h', 'dirty_files': 0, 'registry': {}, 'bin_derod_version': 'v',
         'derod_pid': '', 'derod_running_suffix': '', 'github_head': 'g', 'steps': [], 'workflows': [], 'scratch_dims': {},
         'commits_since_base': [], 'pipeline_runs': [], 'rft_addendum': []}
    T.OUT.mkdir(parents=True, exist_ok=True)
    n = T.OUT / 'r25_NOTES.md'
    n.unlink(missing_ok=True)
    without = T.resume_md(s)
    n.write_text('## Handoff notes\nPLANTED-NOTE-r25: merge agent in flight\n')
    try:
        with_notes = T.resume_md(s)
    finally:
        n.unlink()
    return 'PLANTED-NOTE-r25' in with_notes and 'PLANTED-NOTE-r25' not in without, f'{len(without)} {len(with_notes)}'


def rc6(T, d):
    """pipeline records: a --no-install full run that ends ok is a full PASS; a full run that ends not ok is not; a
    project-only run (no shadow) that ends ok is a project PASS"""
    ev = lambda **k: json.dumps(k) + '\n'
    full_ok = ev(stage='run', status='BEGIN') + ev(stage='shadow', status='PASS') + ev(stage='install', status='SKIP') + ev(stage='done', status='END', ok=True)
    full_bad = ev(stage='run', status='BEGIN') + ev(stage='shadow', status='FAIL') + ev(stage='done', status='END', ok=False)
    proj_ok = ev(stage='run', status='BEGIN') + ev(stage='project', status='PASS') + ev(stage='done', status='END', ok=True)
    got = (T.run_result(full_ok), T.run_result(full_bad), T.run_result(proj_ok), T.run_result(ev(stage='run', status='BEGIN')))
    return got == ((True, True), (True, False), (False, True), (False, False)), f'{got}'


KATS = [('RC1', rc1), ('RC2', rc2), ('RC3', rc3), ('RC4', rc4), ('RC5', rc5), ('RC6', rc6)]

MUTATIONS = [   # (find, replace, why)
    ("labels[x.get('key')] = {'label': x.get('label'), 'state': 'in-flight'}",
     "labels[x.get('key')] = {'label': x.get('label'), 'state': 'done'}", 'a started agent is listed done (in-flight lost)'),
    ("labels.setdefault(k, {'label': '?'})['state'] = 'done'", "labels.setdefault(k, {'label': '?'})['state'] = 'in-flight'",
     'a finished agent is listed in-flight'),
    ("        if not s['done'] and s['step'] in was:", "        if False:", 'a DONE step is re-listed as pending'),
    ("        return json.loads((Path(out or OUT) / f'{round_id}_state.json').read_text()).get('steps') or []",
     "        return []", 'the previous state is not read (done is not sticky)'),
    ("[:-keep] if keep > 0 else []", "[:keep] if keep > 0 else []", 'pruning drops the newest copies'),
    ("[:-keep] if keep > 0 else []", "[:0] if keep > 0 else []", 'history is never pruned'),
    ("{re.escape(tag)}\\b:?.*\\bmerge\\b'", "{re.escape(tag)}\\b'", "any 'R<id>:' commit counts as the merge"),
    ("        L.append(f\"Resume: `Workflow({{scriptPath: \\\"{w['script']}\\\", resumeFromRunId: \\\"{w['run_id']}\\\"}})`\")",
     "        pass", 'the brief omits the resume call'),
    ("    return full, bool(done) and bool(re.search(r'\"ok\":\\s*true', done[-1]))", "    return full, bool(done)",
     'a run that ended not ok counts as PASS'),
    ("    full = bool(re.search(r'\"stage\":\\s*\"(shadow|install)\"', txt))", "    full = '\"stage\": \"install\"' in txt",
     'a full run is recognised only by an install event'),
    ("    if notes.exists():\n        L += ['', notes.read_text()]\n", "", 'the handoff notes are not appended to the brief'),
]


def run_kats(T):
    res = []
    for name, fn in KATS:
        with tempfile.TemporaryDirectory() as d:
            try:
                o, det = fn(T, d)
            except Exception as e:                                # noqa: BLE001
                o, det = False, f'{type(e).__name__}: {e}'
        res.append((name, bool(o), det))
    return res


def main():
    with tempfile.TemporaryDirectory() as base:
        env = {k: str(Path(base) / k.lower()) for k in ('ROUND_CKPT_REPO', 'ROUND_CKPT_OUT', 'ROUND_CKPT_PROJ',
                                                         'ROUND_CKPT_SCRATCH', 'ROUND_CKPT_PUB')}
        T = load(SRC, env)
        res = run_kats(T)
        for name, o, det in res:
            print(f"{'ok  ' if o else 'FAIL'} {name} {det[:300]}")
        if not all(o for _, o, _ in res):
            return 3
        missed = 0
        text = SRC.read_text(encoding='utf-8')
        for find, repl, why in MUTATIONS:
            if text.count(find) != 1:
                print(f'  ??      {why}: find text occurs {text.count(find)} times')
                missed += 1
                continue
            with tempfile.TemporaryDirectory() as d:
                p = Path(d) / SRC.name
                p.write_text(text.replace(find, repl, 1), encoding='utf-8')
                try:
                    m = load(p, env)
                except Exception as e:                            # noqa: BLE001
                    print(f'  INVALID {why}: mutant does not load ({type(e).__name__})')
                    missed += 1
                    continue
                survived = all(o for _, o, _ in run_kats(m))
            print(f"  {'MISSED ' if survived else 'proved '} {why}")
            missed += survived
    print(f'\nr25 round-checkpoint KATs: {len(KATS)}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
