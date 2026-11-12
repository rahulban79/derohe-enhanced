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
  RC7 (r30 B252) Agent-tool subagent transcripts: a SubagentHandback is done, a recent open one in-flight, an old open
      one stalled, a handback followed by a new prompt is open again; dim from the prompt, a HANDOFF.md naming the agent
      wins; the brief lists the states and the HANDOFF path.
  RC8 (r30 B252) OS jobs: a background Bash job of the session is session-bound (loop kind named); a ppid-1 stallwatch
      is detached with the file it grows, its size, counter and planned end; tail readers and the caller's own wrapper
      are not listed; the miner is an observe-only user daemon with its wallet masked; the DUE view orders overdue
      before upcoming, gates 'after', never lists a done item; the brief renders both.

  RC9 (r30 B254a) the running derod's suffix survives a log rotation: the newest Version line wins, whether it sits in
      derod.log or (after a 100 MB rotation) only in the newest lumberjack backup derod-<UTC>.log; none anywhere -> ''.

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


def _tr(*recs):
    return ''.join(json.dumps(r) + '\n' for r in recs)


def _asst(*blocks, stop=None):
    return {'type': 'assistant', 'message': {'role': 'assistant', 'stop_reason': stop, 'content': list(blocks)}}


def _user(text):
    return {'type': 'user', 'message': {'role': 'user', 'content': text}}


def rc7(T, d):
    """r30 B252: Agent-tool subagent transcripts — a SubagentHandback is done, a recent tool call is in-flight, an old
    open one is stalled, a handback followed by a new prompt and a tool call is open again; the dim comes from the
    prompt, a HANDOFF.md naming the agent wins; the brief lists each state and the HANDOFF path"""
    import time as _t
    proj, scr = Path(d) / 'proj', Path(d) / 'scr'
    sub = proj / 'sess' / 'subagents'
    sub.mkdir(parents=True)
    for dim in ('dimx', 'dimy', 'dimz'):
        (scr / 'sess' / 'scratchpad' / 'r30' / dim).mkdir(parents=True)
    (scr / 'sess' / 'scratchpad' / 'r30' / 'dimz' / 'HANDOFF.md').write_text('Agent: a0000000000000c03\n## Done\n- x\n')
    hb = {'type': 'tool_use', 'name': 'SubagentHandback', 'input': {'message': 'r'}}
    bash = {'type': 'tool_use', 'name': 'Bash', 'input': {}}
    T_ = {'a0000000000000a01': _tr(_user('work in SCRATCH/r30/dimx/tree'), _asst(bash), _asst(hb)),
          'a0000000000000b02': _tr(_user('work in <scratch>/r30/dimy/tree please'), _asst(bash)),
          'a0000000000000c03': _tr(_user('scratchpad/r30/dimx/ first, then dimz'), _asst(bash)),
          'a0000000000000d04': _tr(_user('scratchpad/r30/dimy/x'), _asst(hb), _user('one more thing'), _asst(bash)),
          'a0000000000000e05': _tr(_user('scratchpad/r30/dimx/a'), _asst({'type': 'text', 'text': 'r'}, stop='end_turn'),
                                   _user('continue please')),
          'a0000000000000f06': _tr(_user('scratchpad/r30/dimx/a'), _asst({'type': 'text', 'text': 'r'}, stop='end_turn'))}
    now = _t.time()
    for aid, txt in T_.items():
        f = sub / f'agent-{aid}.jsonl'
        f.write_text(txt)
        (sub / f'agent-{aid}.meta.json').write_text(json.dumps({'description': f'desc {aid[-3:]}'}))
    old = now - 7200
    os.utime(sub / 'agent-a0000000000000c03.jsonl', (old, old))
    A = {a['id']: a for a in T.agents(0, 'r30', proj, scr, now=now)}
    st = {k: v['state'] for k, v in A.items()}
    ok = (st == {'a0000000000000a01': 'done', 'a0000000000000b02': 'in-flight', 'a0000000000000c03': 'stalled',
                 'a0000000000000d04': 'in-flight', 'a0000000000000e05': 'in-flight', 'a0000000000000f06': 'done'}
          and A['a0000000000000b02']['dim'] == 'dimy' and A['a0000000000000a01']['dim'] == 'dimx'
          and A['a0000000000000c03']['dim'] == 'dimz' and str(A['a0000000000000c03']['handoff']).endswith('dimz/HANDOFF.md'))
    s = {'round': 'r30', 'stamp': 'x', 'repo_head': 'h', 'dirty_files': 0, 'registry': {}, 'bin_derod_version': 'v',
         'derod_pid': '', 'derod_running_suffix': '', 'github_head': 'g', 'steps': [], 'workflows': [], 'scratch_dims': {},
         'commits_since_base': [], 'pipeline_runs': [], 'rft_addendum': [], 'agents': list(A.values())}
    md = T.resume_md(s) if ok else ''
    ok = ok and '`a0000000000000b02` desc b02: **in-flight**' in md and '**stalled**' in md and 'dimz/HANDOFF.md' in md
    return bool(ok), f'{st} dims {[(k[-3:], v["dim"]) for k, v in A.items()]}'


def rc8(T, d):
    """r30 B252: OS jobs — a background Bash job of the session is session-bound (its loop kind named), a ppid-1
    stallwatch is detached with the file it grows, its size, its counter and its plan's end; a tail reader is ignored; the
    caller's own wrapper is not listed; the miner is an observe-only user daemon with its wallet masked. The DUE view
    lists an overdue item before an upcoming one, a ready item once its 'after' is done, and never a done item."""
    import time as _t
    w = Path(d) / 'live' / 'series.jsonl'
    w.parent.mkdir(parents=True)
    w.write_text('x' * 123)
    (w.parent / 'plan.json').write_text(json.dumps({'end_epoch': 1794296611.7}))
    (w.parent / 'progress.json').write_text(json.dumps({'samples': 7}))
    snapw = "/bin/bash -c source /h/.claude/shell-snapshots/snapshot-bash-1.sh 2>/dev/null || true && eval "
    rows = [{'pid': 100, 'ppid': 50, 'start': 's', 'cmd': 'claude --resume abc'},
            {'pid': 104, 'ppid': 100, 'start': 's', 'cmd': snapw + "'python3 round_pause.py status' < /dev/null"},
            {'pid': 105, 'ppid': 104, 'start': 's', 'cmd': 'python3 -I round_pause.py status'},
            {'pid': 110, 'ppid': 100, 'start': 's', 'cmd': snapw + "'nice -n 15 python3 -I x/round_checkpoint.py --loop 300' < /dev/null"},
            {'pid': 111, 'ppid': 110, 'start': 's', 'cmd': 'python3 -I x/round_checkpoint.py --loop 300'},
            {'pid': 200, 'ppid': 1, 'start': 's', 'cmd': f'python3 -I {d}/tree/harness/kit/stallwatch.py --match live_window.py '
             f'--work {w} --progress {w.parent}/progress.json --done {w.parent}/DONE --stall-s 1200'},
            {'pid': 201, 'ppid': 200, 'start': 's', 'cmd': f'python3 -I {d}/tree/harness/intel/live_window.py watch'},
            {'pid': 300, 'ppid': 1, 'start': 's', 'cmd': f'tail -n +1 -f {d}/x.log'},
            {'pid': 400, 'ppid': 1, 'start': 's', 'cmd': '/r/bin/dero-miner --wallet-address=YOUR_DERO_ADDRESS --gpu'}]
    det, bound = T.jobs(rows, 105, [str(d)])
    dk = {j['pid']: j for j in det}
    ok = ([(j['pid'], j['kind']) for j in bound] == [(110, 'checkpoint-loop')] and sorted(dk) == [200, 400]
          and dk[200]['kind'] == 'stallwatch' and dk[200]['out'] == str(w) and dk[200]['size'] == 123
          and dk[200]['progress_value'] == {'samples': 7} and dk[200]['end'] and dk[200]['done'] is False
          and dk[400]['kind'] == 'user-daemon' and 'dero1qy5' not in dk[400]['cmd'] and 'masked' in dk[400]['cmd'])
    now = _t.time()
    iso = lambda t: __import__('datetime').datetime.fromtimestamp(t).astimezone().isoformat(timespec='seconds')
    led = {'items': [{'id': 'U1', 'due': iso(now + 3600), 'what': 'later', 'status': 'pending'},
                     {'id': 'D1', 'due': iso(now - 60), 'what': 'late', 'status': 'pending'},
                     {'id': 'D0', 'due': iso(now - 7200), 'what': 'old done', 'status': 'done', 'evidence': 'e'},
                     {'id': 'R1', 'after': ['D0'], 'what': 'gated', 'status': 'pending'},
                     {'id': 'W1', 'after': ['D1'], 'what': 'waits', 'status': 'pending'},
                     {'id': 'E1', 'when': 'the run ends', 'what': 'event', 'status': 'pending'}]}
    over, ready, up = T.due_view(led, now)
    ok = ok and [i['id'] for i in over] == ['D1'] and [i['id'] for i in ready] == ['R1'] and [i['id'] for i in up] == ['U1', 'W1', 'E1']
    s = {'round': 'r30', 'stamp': 'x', 'repo_head': 'h', 'dirty_files': 0, 'registry': {}, 'bin_derod_version': 'v',
         'derod_pid': '', 'derod_running_suffix': '', 'github_head': 'g', 'steps': [], 'workflows': [], 'scratch_dims': {},
         'commits_since_base': [], 'pipeline_runs': [], 'rft_addendum': [], 'jobs': {'detached': det, 'session_bound': bound},
         'due': led}
    md = T.resume_md(s) if ok else ''
    ok = ok and md.index('OVERDUE D1') < md.index('upcoming U1') and 'old done' not in md.split('## Due actions')[1] \
        and 'pid 200 stallwatch' in md and 'pid 110 checkpoint-loop' in md
    return bool(ok), f'bound {[(j["pid"], j["kind"]) for j in bound]} det {[(j["pid"], j["kind"], j.get("size")) for j in det]} due {[i["id"] for i in over]}/{[i["id"] for i in ready]}/{[i["id"] for i in up]}'


def rc9(T, d):
    d = Path(d)
    v = lambda s: json.dumps({'L': 'INFO', 'T': '2026-11-08T15:33:00.679-0800', 'M': '', 'Version': f'3.6.0-153.DEROHE.STARGATE+{s}'}) + '\n'
    x = json.dumps({'L': 'DEBUG', 'M': 'fixed loop'}) + '\n'
    (d / 'derod-2026-11-01T00-00-00.000.log').write_text(v('22102026.r27') + x)
    (d / 'derod-2026-11-09T21-17-18.376.log').write_text(v('22102026.r28') + x + v('22102026.r29') + x)
    (d / 'derod.log').write_text(x * 3)
    rotated = T.derod_run_suffix(d)
    (d / 'derod.log').write_text(x + v('22102026.r30') + x)
    live = T.derod_run_suffix(d)
    e = d / 'empty'
    e.mkdir()
    (e / 'derod.log').write_text(x)
    none = T.derod_run_suffix(e)
    return (rotated, live, none) == ('22102026.r29', '22102026.r30', ''), (rotated, live, none)


KATS = [('RC1', rc1), ('RC2', rc2), ('RC3', rc3), ('RC4', rc4), ('RC5', rc5), ('RC6', rc6), ('RC7', rc7), ('RC8', rc8),
        ('RC9', rc9)]

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
    # r30 B252 (RC7, RC8)
    ("    if any(c.get('type') == 'tool_use' and c.get('name') == 'SubagentHandback' for c in blocks):\n        return 'done'",
     "    if any(c.get('type') == 'tool_use' and c.get('name') == 'SubagentHandback' for c in blocks):\n        return 'open'",
     'B252: a handed-back agent is listed open'),
    ("('in-flight' if now - mt < stale_s else 'stalled')", "'in-flight'", 'B252: an idle, never handed-back agent is in-flight'),
    ("        hand = by_id.get(aid)\n", "        hand = None\n", 'B252: a HANDOFF.md that names its agent is ignored'),
    ("        later = [r for r in recs[last_i + 1:] if r.get('type') == 'user'", "        later = [r for r in [] if r.get('type') == 'user'",
     'B252: a continued agent (new prompt after its end_turn) is listed done'),
    ("            if SNAP_MARK not in r['cmd'] or pid in covered:", "            if True:", 'B252: session-bound jobs are not listed'),
    ("    for rx, to in MASK_RX:\n", "    for rx, to in ():\n", 'B252: the miner wallet is not masked'),
    ("        if re.match(r'^(\\S*/)?(tail|sleep|grep|ps|lsof)\\b', cmd) or SNAP_MARK in cmd:", "        if SNAP_MARK in cmd:",
     'B252: a tail reader is listed as a detached job'),
    ("    over = sorted([i for i in open_ if due_epoch(i) is not None and due_epoch(i) <= now], key=due_epoch)",
     "    over = sorted([i for i in open_ if due_epoch(i) is not None and due_epoch(i) > now], key=due_epoch)",
     'B252: overdue items are taken from the future'),
    ("and not i.get('when') and all(", "and all(", "B252: an item waiting on its 'when' event is listed ready"),
    ("    open_ = [i for i in items if i.get('status') not in ('done', 'skipped')]", "    open_ = list(items)",
     'B252: a done due item is listed again'),
    ("            j['progress_value'] = json.loads(Path(a['progress']).read_text()) if a.get('progress') else None",
     "            j['progress_value'] = None", "B252: a detached job's work counter is not recorded"),
    # r30 B254a (RC9)
    ("    for f in ([live] if live.exists() else []) + backups:", "    for f in ([live] if live.exists() else []):",
     'B254a: the rotated backups are not read (suffix lost after a rotation)'),
    ("        backups = sorted((f for f in d.glob('derod-*.log') if f.is_file()), reverse=True)",
     "        backups = sorted((f for f in d.glob('derod-*.log') if f.is_file()))", 'B254a: the oldest backup wins'),
    ("                    if '\"Version\"' in line:\n                        last = line",
     "                    if '\"Version\"' in line and last is None:\n                        last = line", 'B254a: the first Version line of a file wins'),
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
