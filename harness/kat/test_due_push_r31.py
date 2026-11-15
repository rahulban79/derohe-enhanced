#!/usr/bin/env python3
"""test_due_push_r31.py — r31 (rft §7 B270, R31-2): a user-action DUE item reaches the user by a push notification at the
moment it falls due. R30 lost 6.5 h of miner uptime (12:59 install -> 19:30 restart) on a terminal prompt the user did not
see. The agents cannot push; the coordinator can, so harness/intel/round_pause.py lists what to push and records it.

  DP1 check_due: a pending user action (then_tell_user, user_action: true, or owner 'user') without push: true is a
      problem; user_action: true or owner 'user' without then_tell_user is a problem; a complete one passes; a non-user item needs no
      push; a done (historical) user action is not re-judged
  DP2 due_push_view: the user actions due NOW (overdue by time, or ready after their 'after' items are done), not pushed
      yet, in due order; a pushed one, a not-yet-due one, a done one, a 'when'-gated one and a non-user one are not listed
  DP3 the command round trip: `due-push` exits 5 and prints the exact push text '[<round> <ID>] <then_tell_user>'; `check`
      prints a WARN for it; `due-pushed ID` records pushed_at; a second `due-pushed` is refused (the first time is kept);
      `due-push` then exits 0 and lists nothing (never re-pushed)

All inputs are forged in temporary directories (ROUND_CKPT_* overrides); nothing outside them is written.

  python3 -I harness/kat/test_due_push_r31.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, importlib.util, io, json, os, shutil, sys, tempfile, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'tool': 'harness/intel/round_pause.py'}
SIBLINGS = ['harness/intel/round_checkpoint.py', 'harness/kit/handoff.py', 'harness/intel/round_pause.py']


def envs(d):
    return {k: str(Path(d) / k.lower()) for k in ('ROUND_CKPT_REPO', 'ROUND_CKPT_OUT', 'ROUND_CKPT_PROJ', 'ROUND_CKPT_SCRATCH',
                                                   'ROUND_CKPT_PUB', 'ROUND_CKPT_PERSIST')}


def load(over, env):
    root = Path(over.get('root') or ROOT)
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        spec = importlib.util.spec_from_file_location(f'dp31_{uuid.uuid4().hex[:6]}', root / PATHS['tool'])
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return m


def iso(t):
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(t)) + time.strftime('%z', time.localtime(t))


def item(i, **k):
    return dict({'id': i, 'what': f'w {i}', 'status': 'pending'}, **k)


def kat_dp1(over):
    with tempfile.TemporaryDirectory() as d:
        m = load(over, envs(d))
        due = '2026-11-13T10:00:00-08:00'
        good = {'items': [item('U', due=due, then_tell_user='restart derod', push=True),
                          item('N', due=due),
                          item('H', due=due, then_tell_user='old', status='done', evidence='e')]}
        bad = {'items': [item('A', due=due, then_tell_user='restart derod'),
                         item('B', due=due, user_action=True, push=True),
                         item('C', due=due, owner='user', then_tell_user='push GitHub', push='yes'),
                         item('D', due=due, owner='user', push=True)]}
        pg, pb = m.check_due(good), m.check_due(bad)
        t = ' | '.join(pb)
        ok = (pg == [] and 'A: a user action without push: true' in t and 'B: a user action without its then_tell_user' in t
              and 'C: a user action without push: true' in t and 'D: a user action without its then_tell_user' in t
              and len(pb) == 4)
        return ok, (pg, pb)


def kat_dp2(over):
    with tempfile.TemporaryDirectory() as d:
        m = load(over, envs(d))
        now = time.time()
        u = dict(user_action=True, then_tell_user='t', push=True)
        led = {'items': [item('LATE2', due=iso(now - 60), **u), item('LATE1', due=iso(now - 3600), **u),
                         item('PUSHED', due=iso(now - 600), pushed_at=iso(now - 500), **u),
                         item('FUTURE', due=iso(now + 3600), **u),
                         item('DONE', due=iso(now - 600), status='done', evidence='e', **u),
                         item('PRE', status='done', evidence='e'), item('READY', after=['PRE'], **u),
                         item('WAIT', after=['FUTURE'], **u), item('WHEN', when='the user says so', **u),
                         item('AGENT', due=iso(now - 900))]}
        got = [i['id'] for i in m.due_push_view(led, now)]
        return got == ['LATE1', 'LATE2', 'READY'], got


def kat_dp3(over):
    with tempfile.TemporaryDirectory() as d:
        E = envs(d)
        m = load(over, E)
        out = Path(d) / 'out'
        out.mkdir()
        now = time.time()
        led = {'items': [item('D-RESTART', due=iso(now - 120), user_action=True, then_tell_user='restart derod on the r31 build', push=True,
                              cmd='echo x'), item('D-AGENT', due=iso(now - 120))]}
        p = out / 'r31_DUE.json'
        p.write_text(json.dumps(led))

        def run(*a):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = m.main(list(a) + ['--round', 'r31', '--out', str(out)])
            return rc, buf.getvalue()
        r1, o1 = run('due-push')
        rc_, oc = run('check')
        r2, o2 = run('due-pushed', 'D-RESTART')
        stamp = json.loads(p.read_text())['items'][0].get('pushed_at')
        r3, _ = run('due-pushed', 'D-RESTART')
        r4, o4 = run('due-push')
        r5, _ = run('due-pushed', 'D-AGENT')
        stamp2 = json.loads(p.read_text())['items'][0].get('pushed_at')
        ok = (r1 == 5 and '[r31 D-RESTART] restart derod on the r31 build' in o1 and 'D-AGENT' not in o1
              and rc_ == 0 and 'WARN due D-RESTART' in oc and r2 == 0 and bool(stamp) and r3 == 2 and stamp2 == stamp
              and r4 == 0 and 'nothing to push' in o4 and r5 == 2)
        return ok, (r1, rc_, r2, r3, r4, r5, stamp, o1[-200:], oc[-200:])


KATS = [('DP1', kat_dp1), ('DP2', kat_dp2), ('DP3', kat_dp3)]
OWNERS = {'B270 schema': ['DP1'], 'B270 view': ['DP2', 'DP3'], 'B270 record': ['DP3'], 'B270 loud': ['DP3']}
MUTATIONS = [   # (file key, find, replace, why — the first two words name the defect, see OWNERS)
    ('tool', "            if i.get('push') is not True:", "            if False:", 'B270 schema: a user action without push: true passes'),
    ('tool', "            if not (isinstance(i.get('then_tell_user'), str) and i['then_tell_user'].strip()):", "            if False:",
     'B270 schema: a user action without its text passes'),
    ('tool', "    return (i.get('user_action') is True or bool(i.get('then_tell_user'))\n            or str(",
     "    return (i.get('user_action') is True\n            or str(", 'B270 schema: a then_tell_user item is not a user action'),
    ('tool', "or str(i.get('owner') or '').strip().lower() == 'user')", "or False)", 'B270 schema: an owner-user item is not a user action'),
    ('tool', "    return [i for i in over + ready if is_user_action(i) and not i.get('pushed_at')]",
     "    return [i for i in over + ready if is_user_action(i)]", 'B270 view: a pushed item is pushed again'),
    ('tool', "    return [i for i in over + ready if is_user_action(i) and not i.get('pushed_at')]",
     "    return [i for i in over if is_user_action(i) and not i.get('pushed_at')]", 'B270 view: an after-gated item that became ready is not pushed'),
    ('tool', "    return [i for i in over + ready if is_user_action(i) and not i.get('pushed_at')]",
     "    return [i for i in ready + over if is_user_action(i) and not i.get('pushed_at')]", 'B270 view: the push order is not the due order'),
    ('tool', "    if not hit or not is_user_action(hit[0]) or hit[0].get('pushed_at'):",
     "    if not hit or not is_user_action(hit[0]):", 'B270 record: a second record overwrites the first push time'),
    ('tool', "    hit[0]['pushed_at'] = now_iso(t)", "    pass", 'B270 record: the push is never recorded'),
    ('tool', "        return 5\n    if a.cmd == 'due-pushed':", "        return 0\n    if a.cmd == 'due-pushed':", 'B270 loud: a due-push with work exits 0'),
    ('tool', "            print(f\"WARN due {i['id']}: a user action", "            (f\"WARN due {i['id']}: a user action",
     'B270 loud: check is silent on an unpushed due action'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_dp31', HARNESS / 'kit' / 'katmut.py')
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
        print(f'\nr31 due-push KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='dp31-mut-') as d:
            for rel in SIBLINGS:
                (Path(d) / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / rel, Path(d) / rel)
            (Path(d) / PATHS[key]).write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({'root': d}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(defect(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r31 due-push KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
