#!/usr/bin/env python3
"""test_round_pause_r30.py — r30 (rft §7 B252, §0.10, §2.22): one-command round pause / resume
(harness/intel/round_pause.py) and the agent HANDOFF.md checker (harness/kit/handoff.py).

  RP1 a clone with a commit the repo lacks, a dirty tracked file and an untracked file is saved (bundle, patch, untracked
      archive); after the tree is deleted, the restore commands re-create it: same branch head, same dirty content, same
      untracked file
  RP2 a detached job at resume: alive + output grew = LIVE (one window); alive + counter rose = LIVE; alive, no work =
      ALIVE-NO-WORK once silent past its stall window (ALIVE within it); a live keeper is KEEPER; a dead helper with a
      DONE beside its script is FINISHED; dead + done marker = FINISHED; dead past its planned end = ENDED; dead otherwise = DIED with its
      restart command and the two-segment lost-window plan (never merged); a dead user daemon is never restarted
  RP3 the loop keeper never runs a loop twice: a second launch is 'kept'; while another copy of the loop runs the keeper
      stands by; when that copy dies the keeper runs the loop itself; SIGTERM stops the keeper and its loop
  RP4 the DUE ledger schema: a good ledger passes; a due time without its zone, an 'after' naming an unknown item, a
      done item without evidence and an unknown status are each reported
  RP5 the pipeline record: a 'done' ok event is PASS (failed stages listed on FAIL); no 'done' event with a live
      fix_build_verify is RUNNING; without one it is DIED with the watchdog's re-run command
  RP6 the agent checkpoint message names the agent id, its HANDOFF.md, the handoff.py check, and leaves detached jobs running
  RP7 resume plans in order and never redoes DONE work: an overdue due item and a ready (after-gated) one are planned, a
      done one is not; a PASS pipeline is listed DONE, not re-run; a missing clone gets its re-create commands; an
      in-flight agent at the pause is re-spawned from its HANDOFF.md, one that handed back since is DONE, one done at
      the pause is not re-examined; the first NOT-DONE §6 step is the sticky one
  RP8 the persist copy of round_checkpoint.py is made a verified copy of the repo tool (old copy kept once as .bak-<sha8>,
      shas in round_state/tools_sha.json); a second sync changes nothing
  RP9 a detached loop's 24 h snapshot file is merged into the repo copy by time: the union, in time order, each instant
      once (the first copy wins), non-snapshot lines dropped; the file is replaced atomically
  RP10 declared evidence at resume: a snaps file whose loop runs and grew is LIVE, its derod restart gap makes the read
      SEGMENTED, a > gap_s hole is a cadence hole (deltas exact), its ingest waits while a pipeline RUNS; a dead loop is
      DIED (restart only by decision, gap recorded); a log without a pidfile is GROWING / NOT-GROWING
  RP11 (r30 B252e) the pause skips its scratch backup only when LAST_BACKUP is < 900 s old AND a backup loop runs; an old,
      future, unreadable or missing stamp, or no loop, runs it (the 2026-11-09 pause spent 9.5 min in the rsync)
  HF1 a complete HANDOFF.md (Agent, Branch head = the tree HEAD, Done, In flight, Next with a command) passes
  HF2 a missing Agent line and a Next section without a command are reported
  HF3 a head that is no longer the tree HEAD is 'stale'

All inputs are forged in temporary directories (ROUND_CKPT_* / ROUND_PAUSE_* overrides); nothing outside them is
written; RP3 starts only its own marker processes and stops them.

  python3 -I harness/kat/test_round_pause_r30.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, datetime, importlib.util, io, json, os, shutil, signal, subprocess, sys, tempfile, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'tool': 'harness/intel/round_pause.py', 'handoff': 'harness/kit/handoff.py'}
SIBLINGS = ['harness/intel/round_checkpoint.py', 'harness/kit/handoff.py', 'harness/intel/round_pause.py', 'harness/intel/payout_24h_reads.py']


def load(over, env=None, name='rp30'):
    """round_pause loaded from a tree root (the real one, or a mutant copy) under env overrides"""
    root = Path(over.get('root') or ROOT)
    old = {k: os.environ.get(k) for k in (env or {})}
    os.environ.update(env or {})
    try:
        spec = importlib.util.spec_from_file_location(f'{name}_{uuid.uuid4().hex[:6]}', root / PATHS['tool'])
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return m


def load_ho(over):
    root = Path(over.get('root') or ROOT)
    spec = importlib.util.spec_from_file_location(f'ho30_{uuid.uuid4().hex[:6]}', root / PATHS['handoff'])
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def envs(d):
    return {k: str(Path(d) / k.lower()) for k in ('ROUND_CKPT_REPO', 'ROUND_CKPT_OUT', 'ROUND_CKPT_PROJ', 'ROUND_CKPT_SCRATCH',
                                                   'ROUND_CKPT_PUB', 'ROUND_CKPT_PERSIST')}


def g(cwd, *a):
    r = subprocess.run(['git', '-C', str(cwd), *a], capture_output=True, text=True, timeout=60,
                       env=dict(os.environ, GIT_AUTHOR_NAME='k', GIT_AUTHOR_EMAIL='k@k', GIT_COMMITTER_NAME='k',
                                GIT_COMMITTER_EMAIL='k@k'))
    return r.stdout.strip()


def mkrepo(p):
    p.mkdir(parents=True, exist_ok=True)
    g(p, 'init', '-q', '-b', 'main')
    (p / 'a.txt').write_text('one\n')
    g(p, 'add', 'a.txt')
    g(p, 'commit', '-q', '-m', 'base')
    return p


def iso(t):
    return datetime.datetime.fromtimestamp(t).astimezone().isoformat(timespec='seconds')


def kat_rp1(over):
    with tempfile.TemporaryDirectory() as d:
        E = envs(d)
        repo = mkrepo(Path(E['ROUND_CKPT_REPO']))
        tree = Path(E['ROUND_CKPT_SCRATCH']) / 'sess' / 'scratchpad' / 'r30' / 'dimA' / 'tree'
        tree.parent.mkdir(parents=True)
        subprocess.run(['git', 'clone', '-q', '--shared', str(repo), str(tree)], check=True, capture_output=True)
        g(tree, 'checkout', '-q', '-b', 'r30-dimA')
        (tree / 'b.txt').write_text('committed on the branch\n')
        g(tree, 'add', 'b.txt')
        g(tree, 'commit', '-q', '-m', 'wip')
        head = g(tree, 'rev-parse', 'HEAD')
        (tree / 'a.txt').write_text('one\nDIRTY\n')
        (tree / 'new.txt').write_text('untracked\n')
        m = load(over, E)
        c = m.clone_state(tree)
        c['saved'] = m.save_clone(c, Path(d) / 'work')
        shutil.rmtree(tree)
        rcs = [subprocess.run(x, shell=True, capture_output=True, timeout=120).returncode for x in m.restore_cmds(c)]
        ok = (c['dim'] == 'dimA' and len(c['dirty']) == 1 and c['untracked'] == ['new.txt'] and not c['merged_in_repo']
              and all(k in c['saved'] for k in ('patch', 'untracked_tgz', 'bundle')) and rcs == [0] * len(rcs)
              and g(tree, 'rev-parse', 'HEAD') == head and g(tree, 'branch', '--show-current') == 'r30-dimA'
              and (tree / 'a.txt').read_text() == 'one\nDIRTY\n' and (tree / 'new.txt').read_text() == 'untracked\n')
        return ok, (c.get('dim'), c.get('dirty'), c.get('untracked'), sorted(c['saved']), rcs)


def kat_rp2(over):
    with tempfile.TemporaryDirectory() as d:
        m = load(over, envs(d))
        now = time.time()
        f = {k: Path(d) / f'{k}.out' for k in 'abcdefg'}
        for p in f.values():
            p.write_text('x' * 10)
        prog = Path(d) / 'prog.json'
        prog.write_text(json.dumps({'cpu_s': 50}))
        done = Path(d) / 'DONE'
        done.write_text('0\n')
        rows = [{'pid': 11, 'ppid': 1, 'start': 's', 'cmd': '/x/python3 a'}, {'pid': 12, 'ppid': 1, 'start': 's', 'cmd': '/x/python3 b'},
                {'pid': 13, 'ppid': 1, 'start': 's', 'cmd': '/x/python3 c'}, {'pid': 14, 'ppid': 1, 'start': 's', 'cmd': '/x/python3 h'},
                {'pid': 15, 'ppid': 1, 'start': 's', 'cmd': '/x/python3 i'}]
        hd = Path(d) / 'helper'
        hd.mkdir()
        (hd / 'prog.sh').write_text('#')
        (hd / 'DONE').write_text('0\n')
        f['a'].write_text('x' * 30)                              # grew since the pause
        os.utime(f['c'], (now - 4000, now - 4000))               # silent longer than its stall window
        J = lambda pid, k, **kw: dict({'pid': pid, 'kind': 'stallwatch', 'cmd': f'/x/python3 {k}', 'cmd_full': f'/x/python3 {k} --full',
                                       'out': str(f[k]), 'size': 10, 'cwd': d}, **kw)
        f['h'] = Path(d) / 'h.out'
        f['h'].write_text('x' * 10)
        res = {k: m.classify_job(j, rows, now, now - 3000 if k == 'c' else now - 600)[0] for k, j in {
            'h': J(14, 'h', stall_s=1200),
            'i': dict(J(15, 'h'), kind='keeper', cmd='/x/python3 i', out=None, size=None),
            'j': dict(J(25, 'a'), kind='job', cmd=f'/bin/bash {hd}/prog.sh', cmd_full=f'/bin/bash {hd}/prog.sh', out=None, size=None),
            'a': J(11, 'a'),
            'b': J(12, 'b', progress=str(prog), progress_value={'cpu_s': 10}),
            'c': J(13, 'c'),
            'd': J(21, 'd', done_file=str(done)),
            'e': J(22, 'e', end=time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime(now - 60))),
            'f': J(23, 'f'),
            'g': J(24, 'g', kind='user-daemon')}.items()}
        died = m.classify_job(J(23, 'f'), rows, now, now - 600)
        ok = (res == {'i': 'KEEPER', 'j': 'FINISHED', 'h': 'ALIVE', 'a': 'LIVE', 'b': 'LIVE', 'c': 'ALIVE-NO-WORK', 'd': 'FINISHED', 'e': 'ENDED', 'f': 'DIED', 'g': 'NOT-RUNNING'}
              and '/x/python3 f --full' in died[2] and 'segment 1' in died[2] and 'never merged' in died[2])
        return ok, (res, died[2][:160])


def kat_rp3(over):
    marker = f'kat-loop-{uuid.uuid4().hex}'
    with tempfile.TemporaryDirectory() as d:
        E = envs(d)
        E['ROUND_PAUSE_LOOPS'] = json.dumps({'kl': {'match': marker, 'cmd': [sys.executable, '-c', 'import time; time.sleep(120)', marker],
                                                    'log': str(Path(d) / 'kl.log')}})
        E['ROUND_PAUSE_POLL'] = '0.1'
        m = load(over, E)
        procs = lambda: [r['pid'] for r in m.RC.proc_rows() if marker in r['cmd'] and 'round_pause.py keep' not in r['cmd']]
        foreign = None
        old = {k: os.environ.get(k) for k in E}
        os.environ.update(E)
        try:
            def wait(cond, s=8.0):
                t = time.time()
                while time.time() - t < s:
                    if cond():
                        return True
                    time.sleep(0.05)
                return False
            a1, k1 = m.launch_keeper('kl')
            ok1 = wait(lambda: len(procs()) == 1)
            a2, k2 = m.launch_keeper('kl')
            time.sleep(0.5)
            n_after_second = len(procs())
            os.kill(k1, signal.SIGTERM)
            ok_stop = wait(lambda: not procs() and m.keeper_pid('kl') is None)
            foreign = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)', marker])
            a3, k3 = m.launch_keeper('kl')
            time.sleep(0.7)
            standby = procs() == [foreign.pid]
            foreign.terminate()
            foreign.wait(5)
            took = wait(lambda: len(procs()) == 1 and procs()[0] != foreign.pid)
            os.kill(k3, signal.SIGTERM)
            ok_stop2 = wait(lambda: not procs())
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            for r in m.RC.proc_rows():                       # never leave a marker process behind
                if marker in r['cmd'] or (f'round_pause.py keep kl' in r['cmd'] and d in r['cmd']):
                    with contextlib.suppress(OSError):
                        os.kill(r['pid'], signal.SIGTERM)
            if foreign and foreign.poll() is None:
                foreign.kill()
        ok = (k1 and ok1 and a2.startswith('kept') and k2 == k1 and n_after_second == 1 and ok_stop and standby and took
              and ok_stop2)
        return bool(ok), (a1, a2, n_after_second, ok_stop, standby, took, ok_stop2)


def kat_rp4(over):
    with tempfile.TemporaryDirectory() as d:
        m = load(over, envs(d))
        good = {'items': [{'id': 'A', 'due': '2026-11-09T22:51:00-08:00', 'what': 'w', 'status': 'pending'},
                          {'id': 'B', 'after': ['A'], 'what': 'w', 'status': 'done', 'evidence': 'e'}]}
        bad = {'items': [{'id': 'A', 'due': '2026-11-09T22:51:00', 'what': 'w', 'status': 'pending'},
                         {'id': 'B', 'after': ['Z'], 'what': 'w', 'status': 'pending'},
                         {'id': 'C', 'due': '2026-11-09T22:51:00-08:00', 'what': 'w', 'status': 'done'},
                         {'id': 'D', 'due': '2026-11-09T22:51:00-08:00', 'what': 'w', 'status': 'later'}]}
        pg, pb = m.check_due(good), m.check_due(bad)
        txt = ' | '.join(pb)
        ok = (pg == [] and 'A: due' in txt and 'no zone' in txt and "unknown item 'Z'" in txt and 'C: done without evidence' in txt
              and "D: status 'later'" in txt)
        return ok, (pg, pb)


def kat_rp5(over):
    with tempfile.TemporaryDirectory() as d:
        E = envs(d)
        m = load(over, E)
        runs = Path(E['ROUND_CKPT_REPO']) / 'harness/loop/runs'
        runs.mkdir(parents=True)
        ev = lambda **k: json.dumps(k) + '\n'
        p = runs / 'pipeline_20261109T000001.jsonl'
        p.write_text(ev(stage='run', status='BEGIN') + ev(stage='guard', status='PASS') + ev(stage='race', status='FAIL')
                     + ev(stage='done', status='END', ok=False))
        fail = m.pipeline_state(E['ROUND_CKPT_REPO'], [])
        p.write_text(ev(stage='run', status='BEGIN') + ev(stage='guard', status='PASS') + ev(stage='done', status='END', ok=True))
        pas = m.pipeline_state(E['ROUND_CKPT_REPO'], [])
        p.write_text(ev(stage='run', status='BEGIN') + ev(stage='guard', status='PASS') + ev(stage='mutate', status='START'))
        live = m.pipeline_state(E['ROUND_CKPT_REPO'], [{'pid': 5, 'ppid': 1, 'start': 's',
                                                        'cmd': '/usr/bin/python3 -I harness/pipeline/fix_build_verify.py --no-install'}])
        sw = {'kind': 'stallwatch', 'match': 'fix_build_verify.py --no-install', 'cmd_full': 'python3 -I harness/kit/stallwatch.py --match X',
              'cwd': '/r', 'pid': 9}
        dead = m.pipeline_state(E['ROUND_CKPT_REPO'], [], [sw])
        ok = (fail['verdict'] == 'FAIL' and fail['failed'] == ['race'] and pas['verdict'] == 'PASS' and live['verdict'] == 'RUNNING'
              and dead['verdict'] == 'DIED' and dead['passed'] == ['guard'] and 'cd /r && nohup python3 -I harness/kit/stallwatch.py' in dead['rerun'])
        return ok, (fail['verdict'], pas['verdict'], live['verdict'], dead['verdict'], dead['rerun'])


def kat_rp6(over):
    with tempfile.TemporaryDirectory() as d:
        m = load(over, envs(d))
        msg = m.checkpoint_message({'id': 'a0123456789abcdef', 'dim': 'miner', 'handoff': '/s/r30/miner/HANDOFF.md'}, 'r30', 'r30-pause-x')
        ok = ('a0123456789abcdef' in msg and '/s/r30/miner/HANDOFF.md' in msg and 'handoff.py check /s/r30/miner/HANDOFF.md' in msg
              and 'Leave detached measurement jobs running' in msg and 'Commit your work in progress' in msg)
        return ok, msg[:200]


def kat_rp7(over):
    marker = f'kat-none-{uuid.uuid4().hex}'
    with tempfile.TemporaryDirectory() as d:
        E = envs(d)
        E['ROUND_PAUSE_LOOPS'] = json.dumps({'kl': {'match': marker, 'cmd': ['true'], 'log': os.devnull}})
        out = Path(E['ROUND_CKPT_OUT'])
        out.mkdir(parents=True)
        repo = Path(E['ROUND_CKPT_REPO'])
        (repo / 'harness/loop/runs').mkdir(parents=True)
        (repo / 'harness/loop/runs/pipeline_20261109T000001.jsonl').write_text(
            json.dumps({'stage': 'guard', 'status': 'PASS'}) + '\n' + json.dumps({'stage': 'done', 'status': 'END', 'ok': True}) + '\n')
        now = time.time()
        (out / 'r30_DUE.json').write_text(json.dumps({'items': [
            {'id': 'D-READ', 'due': iso(now - 600), 'what': '24 h reads', 'status': 'pending', 'cmd': 'python3 -I reads.py'},
            {'id': 'D-OLD', 'due': iso(now - 9000), 'what': 'ALREADY-DONE-ITEM', 'status': 'done', 'evidence': 'x'},
            {'id': 'D-GATE', 'after': ['D-OLD'], 'what': 'gated next', 'status': 'pending'},
            {'id': 'D-LATER', 'due': iso(now + 9000), 'what': 'LATER-ITEM', 'status': 'pending'}]}))
        (out / 'r30_state.json').write_text(json.dumps({'steps': [{'step': 'C  merge', 'done': True}, {'step': 'C  full pipeline PASS', 'done': False}]}))
        hand = Path(d) / 'HANDOFF.md'
        hand.write_text('Agent: a0000000000000a01\nBranch b head 1234567\n## Done\n- x\n## In flight\n- none\n## Next\n- `go`\n')
        rec = {'pause_id': 'r30-pause-x', 'stamp': iso(now - 3600), 't': now - 3600, 'detached': [],
               'clones': [{'dim': 'gone', 'tree': str(Path(d) / 'gone' / 'tree'), 'branch': 'r30-gone', 'head': 'abc1234',
                           'saved': {'bundle': '/b/gone.bundle', 'patch': '/b/gone.patch'}}],
               'agents': [{'id': 'a0000000000000a01', 'state': 'in-flight', 'dim': 'x', 'handoff': str(hand), 'description': 'dim x'},
                          {'id': 'a0000000000000b02', 'state': 'done'},
                          {'id': 'a0000000000000c03', 'state': 'in-flight', 'dim': 'y', 'handoff': None, 'description': 'dim y'}],
               'pipeline': {'run': 'pipeline_20261109T000001', 'verdict': 'RUNNING'}, 'steps': []}
        (out / 'r30_PAUSE.json').write_text(json.dumps(rec))
        sub = Path(E['ROUND_CKPT_PROJ']) / 'sess' / 'subagents'          # c03 handed back after the pause
        sub.mkdir(parents=True)
        (sub / 'agent-a0000000000000c03.jsonl').write_text(json.dumps({'type': 'assistant', 'message': {
            'role': 'assistant', 'content': [{'type': 'tool_use', 'name': 'SubagentHandback', 'input': {}}]}}) + '\n')
        m = load(over, E)
        old = {k: os.environ.get(k) for k in E}
        os.environ.update(E)
        try:
            r = m.resume('r30', dry=True, out=str(out))
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        plan = '\n'.join(r['plan'])
        ok = (r['due']['overdue'] == ['D-READ'] and 'D-GATE' in r['due']['ready'] and 'ALREADY-DONE-ITEM' not in plan
              and 'LATER-ITEM' not in plan and plan.index('D-READ') < plan.index('§6')
              and 'python3 -I reads.py' in plan and 'git clone -q --shared' in plan and 'fetch -q /b/gone.bundle' in plan
              and 're-spawn' in str(r['agents']) and str(hand) in plan and 'a0000000000000b02' not in plan
              and sorted(a[0] for a in r['agents']) == ['a0000000000000a01', 'a0000000000000c03']
              and 'a0000000000000c03' not in plan and 'agent a0000000000000c03 handed back' in r['done']
              and 'pipeline_20261109T000001 PASS' in ' '.join(r['done']) and 'pipeline_20261109T000001' not in plan
              and r['first_not_done_step'] == 'C  full pipeline PASS' and any(n == 'kl' and w == 'MISSING' for n, w, _ in r['loops']))
        return ok, (r['due'], r['first_not_done_step'], r['plan'][:3], r['done'][:3])


def kat_rp8(over):
    with tempfile.TemporaryDirectory() as d:
        E = envs(d)
        src = Path(E['ROUND_CKPT_REPO']) / 'harness/intel/round_checkpoint.py'
        src.parent.mkdir(parents=True)
        src.write_text('# repo tool v2\n')
        pers = Path(E['ROUND_CKPT_PERSIST']) / 'round_checkpoint.py'
        pers.parent.mkdir(parents=True)
        pers.write_text('# old persist copy\n')
        m = load(over, E)
        r1 = m.sync_persist_tool()
        baks = sorted(p.name for p in pers.parent.glob('round_checkpoint.py.bak-*'))
        r2 = m.sync_persist_tool()
        baks2 = sorted(p.name for p in pers.parent.glob('round_checkpoint.py.bak-*'))
        rec = json.loads((Path(E['ROUND_CKPT_OUT']) / 'tools_sha.json').read_text())
        ok = (r1['same'] and pers.read_text() == '# repo tool v2\n' and len(baks) == 1 and baks == baks2 and r2['same']
              and rec['repo_sha256'] == rec['persist_sha256'] == m.sha256(src)
              and (pers.parent / baks[0]).read_text() == '# old persist copy\n')
        return ok, (r1['same'], baks, rec.get('same'))


def _snap(t, paid, up=None):
    d = {'t': t, 'iso': f't{int(t)}', 'derod': {'miniblock_ours_paid_total': paid}, 'miner': {}}
    if up is not None:
        d['miner'] = {'dero_miner_uptime_seconds': up}
    return json.dumps(d, sort_keys=True)


def kat_rp9(over):
    with tempfile.TemporaryDirectory() as d:
        m = load(over, envs(d))
        dst, src = Path(d) / 'dst.jsonl', Path(d) / 'src.jsonl'
        dst.write_text(_snap(100, 1) + '\n' + _snap(300, 3) + '\n')
        src.write_text(_snap(100, 1) + '\n' + 'not json\n' + _snap(200, 2) + '\n' + _snap(400, 4) + '\n')
        b, n, after = m.ingest_snaps(src, dst)
        ts = [json.loads(l)['t'] for l in dst.read_text().splitlines()]
        ok = (b, n, after) == (2, 4, 4) and ts == [100, 200, 300, 400] and not (Path(d) / 'dst.jsonl.tmp').exists()
        return ok, ((b, n, after), ts)


def kat_rp10(over):
    with tempfile.TemporaryDirectory() as d:
        m = load(over, envs(d))
        f = Path(d) / 'snaps.jsonl'
        f.write_text(_snap(0, 10, 100) + '\n' + _snap(600, 20, 700) + '\n')
        then = {'size': f.stat().st_size, 'lines': 2}
        f.write_text(f.read_text() + _snap(1200, 5, 1300) + '\n' + _snap(5000, 9, 5100) + '\n')  # derod restart, then a hole
        pidf = Path(d) / 'loop.pid'
        pidf.write_text(f'{os.getpid()}\n')
        e = {'id': 'snaps', 'out': str(f), 'pidfile': str(pidf), 'kind': 'snaps', 'gap_s': 1800, 'ingest_to': '/r/x.jsonl', 'restart': 'R'}
        w1, d1, p1 = m.classify_evidence(then, e, m.evidence_state(e), 'RUNNING')
        pidf.write_text('999999\n')
        w2, _, p2 = m.classify_evidence(then, e, m.evidence_state(e), 'PASS')
        log = Path(d) / 'miner.log'
        log.write_text('a\n')
        le = {'id': 'log', 'out': str(log), 'kind': 'log', 'cadence_s': 15}
        t2 = {'size': log.stat().st_size, 'lines': 1, 't': time.time()}
        w5, _, _ = m.classify_evidence(t2, le, m.evidence_state(le), 'PASS')        # 0 s quiet: within 2 x cadence
        os.utime(log, (time.time() - 300, time.time() - 300))
        t2['t'] = time.time() - 300
        w3, _, _ = m.classify_evidence(t2, le, m.evidence_state(le), 'PASS')
        log.write_text('a\nb\n')
        w4, _, _ = m.classify_evidence(t2, le, m.evidence_state(le), 'PASS')
        pl = ' | '.join(p1)
        ok = (w1 == 'LIVE' and 'SEGMENTED' in d1 and 'SEGMENTED' in pl and 'cadence holes' in pl and 'AFTER the in-flight pipeline' in pl
              and w2 == 'DIED' and any('ingest NOW' in x for x in p2) and any('`R`' in x for x in p2)
              and w3 == 'NOT-GROWING' and w4 == 'GROWING' and w5 == 'QUIET')
        return ok, (w1, d1, p1, w2, w3, w4, w5)


HAND = ('# HANDOFF\n\nAgent: a0123456789abcdef\nBranch r30-x head {head}\n\n## Done\n- c1 KAT 3/3\n\n## In flight\n- none\n\n'
        '## Next\n- `python3 -I harness/kat/test_x.py`\n')


def kat_hf1(over):
    H = load_ho(over)
    with tempfile.TemporaryDirectory() as d:
        t = mkrepo(Path(d) / 'dim' / 'tree')
        head = g(t, 'rev-parse', '--short=8', 'HEAD')
        p = Path(d) / 'dim' / 'HANDOFF.md'
        p.write_text(HAND.format(head=head))
        ok, probs, parsed = H.check(p)
        merge_form = Path(d) / 'm.md'                 # the merge agent's form is accepted (with its Agent line)
        merge_form.write_text(f'# R30 merge agent handoff\nAgent: a450a8265a7f1a0b6\nRepo /r, branch local-enhancements, head {head}.\n'
                              '## Done\n- x\n## In flight\n- run 7\n## Next exact commands\n1. `grep -E x log`\n')
        ok2, probs2, _ = H.check(merge_form, tree=t)
        return (ok and not probs and parsed['agent'] == 'a0123456789abcdef' and parsed['branch'] == 'r30-x' and ok2), (probs, probs2)


def kat_hf2(over):
    H = load_ho(over)
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 'HANDOFF.md'
        p.write_text(HAND.format(head='1234567').replace('Agent: a0123456789abcdef\n', '').replace('`python3 -I harness/kat/test_x.py`', 'run the tests'))
        ok, probs, _ = H.check(p)
        t = ' | '.join(probs)
        return (not ok and 'Agent' in t and 'no exact command' in t), probs


def kat_hf3(over):
    H = load_ho(over)
    with tempfile.TemporaryDirectory() as d:
        t = mkrepo(Path(d) / 'dim' / 'tree')
        old = g(t, 'rev-parse', '--short=8', 'HEAD')
        (t / 'a.txt').write_text('two\n')
        g(t, 'commit', '-q', '-am', 'moved on')
        p = Path(d) / 'dim' / 'HANDOFF.md'
        p.write_text(HAND.format(head=old))
        ok, probs, _ = H.check(p)
        return (not ok and any(x.startswith('stale') for x in probs)), probs


def kat_rp11(over):
    with tempfile.TemporaryDirectory() as d:
        m = load(over, envs(d))
        now = time.mktime(time.strptime('2026-11-11 05:00:00', '%Y-%m-%d %H:%M:%S'))
        f = lambda s, loop=True: m.backup_decision(s, now, loop)[0]
        got = (f('2026-11-11 04:50:00 backup done'), f('2026-11-11 04:45:00 backup done'), f('2026-11-11 04:45:01 backup done'),
               f('2026-11-11 04:59:00 backup done', loop=False), f(None), f('garbage'), f('2026-11-11 05:10:00 backup done'))
        return got == (False, True, False, True, True, True, True), got


KATS = [('RP1', kat_rp1), ('RP2', kat_rp2), ('RP3', kat_rp3), ('RP4', kat_rp4), ('RP5', kat_rp5), ('RP6', kat_rp6),
        ('RP7', kat_rp7), ('RP8', kat_rp8), ('RP9', kat_rp9), ('RP10', kat_rp10), ('HF1', kat_hf1), ('HF2', kat_hf2), ('HF3', kat_hf3),
        ('RP11', kat_rp11)]
OWNERS = {'B252 save': ['RP1'], 'B252 job': ['RP2'], 'B252 keep': ['RP3'], 'B252 due': ['RP4', 'RP7'], 'B252 pipe': ['RP5', 'RP7'],
          'B252 msg': ['RP6'], 'B252 ingest': ['RP9'], 'B252 evidence': ['RP10'], 'B252 resume': ['RP7'], 'B252 persist': ['RP8'], 'B252 handoff': ['HF1', 'HF2', 'HF3'],
          'B252e backup': ['RP11']}
MUTATIONS = [   # (file key, find, replace, why — the first two words name the defect, see OWNERS)
    ('tool', "    if c['head'] and not c['merged_in_repo'] and c['branch']:", "    if False:", 'B252 save: commits the repo lacks are not bundled'),
    ('tool', "    if c['dirty']:\n        rc, _, raw", "    if False:\n        rc, _, raw", 'B252 save: uncommitted tracked changes are not saved'),
    ('tool', "    if c['untracked']:\n        files", "    if False:\n        files", 'B252 save: untracked files are not saved'),
    ('tool', "        L.append(f\"git -C {c['tree']} apply --binary {s['patch']}\")", "        pass", 'B252 save: the restore skips the patch'),
    ('tool', "        if grew or rose:", "        if False:", 'B252 job: a job that kept collecting is not LIVE'),
    ('tool', "    if alive and j.get('kind') == 'keeper':", "    if False:", 'B252 job: a standing-by keeper is flagged ALIVE-NO-WORK'),
    ('tool', "        if hit:\n            j = dict(j, done_file=str(hit))", "        if False:\n            j = dict(j, done_file=str(hit))",
     'B252 job: a helper that ended with its job is called DIED'),
    ('tool', "        if quiet < thr:\n            return 'ALIVE'", "        if False:\n            return 'ALIVE'",
     'B252 job: a job quiet within its cadence is flagged ALIVE-NO-WORK'),
    ('tool', "        if quiet < thr:\n            return 'ALIVE'", "        if True:\n            return 'ALIVE'",
     'B252 job: a job silent past its stall window is not flagged'),
    ('tool', "    done = bool(j.get('done_file')) and Path(j['done_file']).exists()", "    done = False", 'B252 job: a finished job is called DIED'),
    ('tool', "    if end_t and end_t <= now:", "    if False:", 'B252 job: a job past its planned end is called DIED'),
    ('tool', "                                          f'recorded, segment 2 starts at the restart (lost window -> re-measure; never merged)')",
     "                                          f'')", 'B252 job: a died window is merged silently'),
    ('tool', "    if k:\n        return 'kept", "    if False:\n        return 'kept", 'B252 keep: a second launch starts a second keeper'),
    ('tool', "        elif others:", "        elif False:", 'B252 keep: the keeper runs a loop while another copy runs'),
    ('tool', "        if i.get('due') and not re.search(", "        if False and not re.search(", 'B252 due: a due time without its zone passes'),
    ('tool', "        if i.get('status') == 'done' and not i.get('evidence'):", "        if False:", 'B252 due: a done item without evidence passes'),
    ('tool', "    verdict = ('PASS' if ok else 'FAIL') if done else ('RUNNING' if alive else 'DIED')",
     "    verdict = ('PASS' if ok else 'FAIL') if done else 'RUNNING'", 'B252 pipe: a dead pipeline is called RUNNING'),
    ('tool', "    elif pnow.get('verdict') == 'PASS':\n        done_list.append(", "    elif pnow.get('verdict') == 'PASS':\n        plan.append(",
     'B252 pipe: a PASS pipeline is planned again'),
    ('tool', "    for i in over + ready:", "    for i in ready:", 'B252 due: an overdue action is left out of the plan'),
    ('tool', "        if n.get('state') == 'done':\n            agents_out.append", "        if False:\n            agents_out.append",
     'B252 resume: a handed-back agent is re-spawned'),
    ('tool', "        if a['state'] == 'done':\n            continue\n        n = agents_now", "        n = agents_now",
     'B252 resume: an agent done at the pause is re-spawned'),
    ('tool', "(4) Check it: `python3 -I harness/kit/handoff.py check {hand}` must exit 0. (5) Hand back.\")",
     "(5) Hand back.\")", 'B252 msg: the message does not ask for the handoff check'),
    ('tool', "        os.replace(tmp, pers)", "        pass", 'B252 persist: the persist copy is never synced'),
    ('tool', "            if not bak.exists():\n                shutil.copy2(pers, bak)", "            if False:\n                shutil.copy2(pers, bak)",
     'B252 persist: the old persist copy is not kept'),
    ('tool', "        if k in seen:\n            continue", "        if False:\n            continue", 'B252 ingest: a snapshot is ingested twice'),
    ('tool', "    return [l for _, l in sorted(out)]", "    return [l for _, l in out]", 'B252 ingest: the merged file is not in time order'),
    ('tool', "            gate = 'NOW' if pipeline_verdict not in ('RUNNING',) else 'AFTER the in-flight pipeline ends'",
     "            gate = 'NOW'", 'B252 evidence: the ingest is planned while a pipeline runs'),
    ('tool', "        if cont.get('class') == 'SEGMENTED':\n            plan.append", "        if False:\n            plan.append",
     'B252 evidence: a restart gap in the 24 h window is not reported'),
    ('tool', "        if now_state['alive'] and grew:", "        if now_state['alive'] or grew:", 'B252 evidence: a dead loop whose file grew earlier is LIVE'),
    ('tool', "    return ('GROWING' if grew else 'NOT-GROWING')", "    return ('GROWING' if True else 'NOT-GROWING')", 'B252 evidence: a log that stopped is GROWING'),
    ('handoff', "    if 'next' in d['sections'] and not CMD_RX.search", "    if False and not CMD_RX.search",
     'B252 handoff: a Next section without a command passes'),
    ('handoff', "        elif not th.startswith(d['head']):", "        elif False:", 'B252 handoff: a stale head passes'),
    ('handoff', "    if not d['agent']:", "    if False:", 'B252 handoff: a missing Agent line passes'),
    ('tool', "    if age < 0 or age >= fresh_s:", "    if age >= fresh_s:", 'B252e backup: a future stamp skips the backup'),
    ('tool', "    if not loop_running:\n        return True", "    if False:\n        return True",
     'B252e backup: skipped with no backup loop running'),
    ('tool', "    if age < 0 or age >= fresh_s:", "    if age < 0 or age >= 10 * fresh_s:", 'B252e backup: a stale stamp skips the backup'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_rp30', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def defect(why):
    return ' '.join(why.split(':')[0].split()[:2])


def run_kats(over):
    res = []
    for name, fn in KATS:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                ok, det = fn(over)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        res.append((name, bool(ok), str(det)))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr30 round-pause KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='rp30-mut-') as d:
            for rel in SIBLINGS:                                   # the mutant tree: round_pause loads its siblings
                (Path(d) / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / rel, Path(d) / rel)
            shutil.copy2(HARNESS / 'kit' / 'katmut.py', Path(d) / 'harness/kit/katmut.py')
            (Path(d) / PATHS[key]).write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({'root': d}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(defect(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r30 round-pause KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
