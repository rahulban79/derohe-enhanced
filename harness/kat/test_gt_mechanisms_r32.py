#!/usr/bin/env python3
"""test_gt_mechanisms_r32.py — r32 (artifacts/dero-game-theory-rft.md; D-GT-1..3): the game-theory layer in the harness.
  GT1 banguard on a forged private file: a listed address is banned, others pass, scan_text finds the line, the refusal
      message never carries the address, a missing or empty file fails closed, the CLI exits 6
  GT2 banguard on the REAL private file (D-GT-2): the user's address, read from the private launch config or the private
      memory (never printed, never written), is banned; SKIPPED-and-labelled where the private file is absent
  GT3 econsim: every check holds, the contract Initialize defaults equal the models, the critical bond is the sign change
  GT4 econsim stop-inflow (Ponzi) test: M1/M2/M3 pass, the planted pyramid M-NOGO-1 is flagged
  GT5 gt_pipeline contract lint: the three contracts are clean; UPDATE_SC_CODE, a setter without the frozen guard and a
      missing entrypoint are each caught
  GT6 gt_pipeline discovery: the DVM builtin census finds >= 30 builtins and none exposing a miner/integrator/reward; a
      forged builtin named miner_address is caught
  GT7 playbooks: a mainnet dry run (temporary GT_HOME / GT_WALLETS) starts no process, logs >= 6 user actions, exits 5; the
      user-action gate refuses mainnet without --mainnet-confirm; start_proc refuses a non-gt binary; an event with a
      banned address is refused
  GT8 sizing (D-GT-7): no measured mining keeps the D-GT-6 default (2 wallets x 4 DERO) even with a high estimate; a
      first-cycle cost above a target raises it (x2 margin); a measured rate that earns a third target in <= 24 h adds
      juror j1, a slow measured rate does not; a log shorter than 30 min is not a measurement
  GT9 gt_gate.py g36 (the R32 success criterion): INFO with the blocker until all five cycle steps are measured WITH
      evidence, True only then; time_to_coins.py estimate(): the fraction f = h/(H+h) and 9f miniblocks per block;
      cycle_from_earn.py summarise(): a balance that matches the chain scan within one share is 'measured', a mismatch
      is not, and no address reaches the record
  GT10 the earn-run lessons (2026-11-15): gtlib.stale_bins flags a gt-* binary that is missing or older than a
      non-test .go source of its command (a relaunch once passed a new flag to an old gt-wallet); the earn recipes (the
      gt_earn docstring and the page runbook) touch DONE only on success (&&) and watch the PoW counters pow_<wallet>.json
  GT11 earn-run bug 2: gt_earn.register_outcome reads 'already registered' (-32098) as success and anything else
      non-zero as an error; register_wallet mirrors the PoW counter into events.jsonl (pow_tick); a SIGTERM to gt_earn
      kills its register child (own process group), so a stallwatch relaunch cannot leave a grinder behind
  GT13 r32 pipeline run 5: cycle_from_earn writes the tracked records only on --write (the live trigger never does)
  GT12 D-GT-8 viability gate (sizing.viability / plan_two_wallet) and the trigger: at 1 DERO each with the estimated
      fees a 5-round plan passes all five checks (a fees <= 10 % of a stake per round, b each participant's EV >= 0,
      c the MAT boost adds EV, d no Ponzi, e spend <= 75 % of each budget); each check fails alone when its input is
      pushed past its bound; a 0.3 DERO budget is refused with the smallest passing budget; settled_balances counts a
      wallet read only 8+ blocks below the tip (STABLE_LIMIT)
All inputs are forged in memory or a temporary directory; nothing is fetched; nothing outside it is written.
  python3 -I harness/kat/test_gt_mechanisms_r32.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, hashlib, importlib.util, io, json, os, re, shutil, subprocess, sys, tempfile, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'ban': 'harness/gametheory/banguard.py', 'econ': 'harness/gametheory/econsim.py', 'size': 'harness/gametheory/sizing.py',
         'gate': 'harness/gametheory/gt_gate.py', 'ttc': 'harness/gametheory/time_to_coins.py',
         'earnrec': 'harness/gametheory/cycle_from_earn.py', 'page': 'artifacts/src/gen_gametheory.py',
         'earn': 'playbooks/gt_earn.py', 'trig': 'playbooks/gt_trigger.py',
         'pipe': 'harness/gametheory/gt_pipeline.py', 'lib': 'playbooks/gtlib.py', 'cycle': 'playbooks/gt_cycle.py', 'audit': 'harness/gametheory/cycle_audit.py'}
COPY_DIRS = ['harness/gametheory', 'playbooks', 'gametheory', 'harness/kit']
FAKE = 'deto1qy' + 'q' * 58 + 'fake'
OTHER = 'deto1qy' + 'z' * 58 + 'okok'


def load(over, key, extra_env=None):
    root = Path(over.get('root') or ROOT)
    for d in ('harness/gametheory', 'playbooks'):
        p = str(root / d)
        if p not in sys.path:
            sys.path.insert(0, p)
    for m in ('banguard', 'econsim', 'gtlib'):
        sys.modules.pop(m, None)
    sys.path[:] = [p for p in sys.path if not (p.endswith('harness/gametheory') or p.endswith('/playbooks')) or p.startswith(str(root))]
    spec = importlib.util.spec_from_file_location(f'gt32_{key}_{uuid.uuid4().hex[:6]}', root / PATHS[key])
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def forged_ban(d):
    f = Path(d) / 'banned.json'
    f.write_text(json.dumps({'banned_sha256': [hashlib.sha256(FAKE.encode()).hexdigest()]}))
    return f


def kat_gt1(over):
    with tempfile.TemporaryDirectory() as d:
        os.environ['GT_BANNED_FILE'] = str(forged_ban(d))
        try:
            b = load(over, 'ban')
            hs = b.load_hashes()
            msg = ''
            try:
                b.assert_allowed(FAKE, 'kat')
            except b.BannedAddress as e:
                msg = str(e)
            lines = b.scan_text(f'a\nx {FAKE} y\n{OTHER}\n', hs)
            empty = Path(d) / 'empty.json'
            empty.write_text(json.dumps({'banned_sha256': []}))
            fail_closed = 0
            for bad in (empty, Path(d) / 'missing.json'):
                try:
                    b.load_hashes(bad)
                except (OSError, ValueError):
                    fail_closed += 1
            cli = subprocess.run([sys.executable, '-I', str(Path(over.get('root') or ROOT) / PATHS['ban']), 'check', FAKE],
                                 capture_output=True, text=True, env=dict(os.environ))
            ok = (b.is_banned(FAKE, hs) and not b.is_banned(OTHER, hs) and lines == [2] and msg and FAKE not in msg
                  and fail_closed == 2 and cli.returncode == 6 and FAKE not in cli.stdout)
            return ok, lines, fail_closed, cli.returncode
        finally:
            os.environ.pop('GT_BANNED_FILE', None)


def real_address():
    """The user's address from the PRIVATE launch config or memory (outside the repo); None when absent."""
    cands = list((Path.home() / 'Library' / 'LaunchAgents').glob('*dero*')) + \
        list((Path.home() / '.claude' / 'projects').glob('*/memory/user-hardware-topology.md'))
    for c in cands:
        try:
            m = re.search(r'\b(dero1[0-9a-z]{60,})\b', c.read_text(errors='ignore'))
        except OSError:
            continue
        if m:
            return m.group(1)
    return None


def kat_gt2(over):
    b = load(over, 'ban')
    pf = b.banned_file()
    if not pf.exists():
        return True, 'SKIPPED: the private ban file is absent (a public clone); GT1 covers the logic'
    a = real_address()
    if a is None:
        return True, 'SKIPPED: no private source of the address on this machine'
    msg = ''
    try:
        b.assert_allowed(a, 'real')
    except b.BannedAddress as e:
        msg = str(e)
    ok = b.is_banned(a) and bool(msg) and a not in msg and b.scan_text(f'x {a}') == [1]
    return ok, 'the real address is banned (not shown)'


def kat_gt3(over):
    e = load(over, 'econ')
    res = e.analyse(32)
    root = Path(over.get('root') or ROOT)
    d1 = e.contract_defaults((root / 'gametheory/contracts/gt_attest.bas').read_text())
    d2 = e.contract_defaults((root / 'gametheory/contracts/gt_service.bas').read_text())
    d3 = e.contract_defaults((root / 'gametheory/contracts/gt_prize.bas').read_text())
    same = all(d1.get(k) == v for k, v in e.M1_DEFAULTS.items()) and all(d2.get(k) == v for k, v in e.M2_DEFAULTS.items()) \
        and all(d3.get(k) == v for k, v in e.M3_DEFAULTS.items())
    p = dict(e.M1_DEFAULTS)
    crit = e.m1_critical_bond(p, 10, 5, 1000, 0.5)
    above = e.m1_payoffs(dict(p, bond=int(crit) + 1), 10, 5, 1000, 1.0, 0.5)
    below = e.m1_payoffs(dict(p, bond=int(crit) - 1), 10, 5, 1000, 1.0, 0.5)
    wash_in = e.m2_wash_profitable(dict(e.M2_DEFAULTS), [1000] * 10)['net_gain']
    wash_out = e.m2_wash_profitable(dict(e.M2_DEFAULTS, rho=60), [1000] * 10)['net_gain']
    ok = res['ok'] and same and crit == 100000 and above < 0 < below and wash_in <= 0 < wash_out
    return ok, [c['check'] for c in res['checks'] if not c['ok']], same, crit, wash_in, wash_out


def kat_gt4(over):
    e = load(over, 'econ')
    r = {k: e.stop_inflow_check(f()) for k, f in (('M1', e.ledger_m1), ('M2', e.ledger_m2), ('M3', e.ledger_m3),
                                                   ('N1', e.ledger_nogo_pyramid))}
    ok = not r['M1']['ponzi_shaped'] and not r['M2']['ponzi_shaped'] and not r['M3']['ponzi_shaped'] and r['N1']['ponzi_shaped']
    return ok, {k: v['ponzi_shaped'] for k, v in r.items()}


def kat_gt5(over):
    p = load(over, 'pipe')
    root = Path(over.get('root') or ROOT)
    mech = json.loads((root / 'gametheory/mechanisms.json').read_text())
    clean = {}
    for m in mech['mechanisms']:
        if m['status'] == 'GO':
            clean[m['id']] = p.lint_contract((root / 'gametheory/contracts' / m['contract']).read_text(), m['entrypoints'])[1]
    base = (root / 'gametheory/contracts/gt_service.bas').read_text()
    upd = base.replace('40 STORE("mat", HEXDECODE(scidhex))', '40 UPDATE_SC_CODE(scidhex)')
    nofreeze = base.replace('20 IF LOAD("frozen") != 0 THEN GOTO 900\n30 IF fee == 0', '20 LET fee = fee\n30 IF fee == 0')
    i_upd = p.lint_contract(upd, [])[1]
    i_nf = p.lint_contract(nofreeze, [])[1]
    i_miss = p.lint_contract(base, ['Notarize', 'Withdraw'])[1]
    ok = (all(not v for v in clean.values()) and any('UPDATE_SC_CODE' in x for x in i_upd)
          and any('SetParams' in x for x in i_nf) and any('missing entrypoint Withdraw' in x for x in i_miss))
    return ok, clean, i_upd, i_nf, i_miss


def kat_gt6(over):
    p = load(over, 'pipe')
    b = p.dvm_builtins()
    bad = [k for k in b if p.MINER_WORDS.search(k)]
    forged = 'func_table["miner_address"] = []func_data{func_data{Range: x, ComputeCost: 7, StorageCost: 0}}'
    hit = [m.group(1) for m in re.finditer(r'func_table\["([a-z0-9_]+)"\].*?ComputeCost: (\d+)', forged)
           if p.MINER_WORDS.search(m.group(1))]
    ok = len(b) >= 30 and not bad and 'signer' in b and 'random' in b and hit == ['miner_address']
    return ok, len(b), bad, hit


def kat_gt7(over):
    root = Path(over.get('root') or ROOT)
    with tempfile.TemporaryDirectory() as d:
        env = dict(os.environ, GT_HOME=str(Path(d) / 'home'), GT_WALLETS=str(Path(d) / 'w'), GT_BANNED_FILE=str(forged_ban(d)))
        r = subprocess.run([sys.executable, '-I', str(root / 'playbooks/gt_playbook.py'), 'all', '--network', 'mainnet',
                            '--dry-run', '--run-id', 'kat'], capture_output=True, text=True, env=env, timeout=120)
        st = json.loads((Path(d) / 'home/runs/kat/state.json').read_text())
        ua = r.stdout.count('user_action_required')
        os.environ.update({k: env[k] for k in ('GT_HOME', 'GT_WALLETS', 'GT_BANNED_FILE')})
        try:
            g = load(over, 'lib')
            run = g.Run('kat2', 'mainnet', dry_run=False, mainnet_confirm=False)
            gate = run.user_action_gate('x', 'cmd')
            refused_exe = refused_event = False
            try:
                g.start_proc(run, 'x', ['/bin/echo', 'hi'])
            except SystemExit:
                refused_exe = True
            try:
                run.event('kat', detail=f'addr {FAKE}')
            except g.banguard.BannedAddress:
                refused_event = True
        finally:
            for k in ('GT_HOME', 'GT_WALLETS', 'GT_BANNED_FILE'):
                os.environ.pop(k, None)
        ok = r.returncode == 5 and not st['procs'] and ua >= 6 and gate is False and refused_exe and refused_event
        return ok, r.returncode, ua, gate, refused_exe, refused_event


def kat_gt8(over):
    s = load(over, 'size')
    gas = {'gt_attest.bas:Initialize': [1000, 200], 'gt_prize.bas:Enter': [5000, 276]}
    par = {'attest': {'bond': 615, 'minstake': 100000}, 'prize': {'rbond': 10000}, 'service': {'fee': 1000}}
    d0 = s.decide(par, gas, None, 999.0, 'x')
    big = dict(par, attest={'bond': 100000, 'minstake': 100000})
    d1 = s.decide(big, gas, None, None, 'x')
    d2 = s.decide(par, gas, 40.0, None, 'x')
    d3 = s.decide(par, gas, 2.0, None, 'x')
    t0 = '2026-11-15T01:00:00-08:00'
    short = [{'kind': 'earn_tick', 'ts': t0, 'chain_credited': 0}, {'kind': 'earn_tick', 'ts': '2026-11-15T01:10:00-08:00', 'chain_credited': 9225}]
    long_ = [{'kind': 'earn_tick', 'ts': t0, 'chain_credited': {'m1': 0}}, {'kind': 'earn_tick', 'ts': '2026-11-15T02:00:00-08:00', 'chain_credited': {'m1': 100000}}]
    r_short, _ = s.measured_rate(short)
    r_long, h = s.measured_rate(long_)
    ok = (d0['n_wallets'] == 2 and d0['targets_atomic'] == {'m1': 400000, 'm2': 400000}
          and d1['targets_atomic']['m1'] > 400000
          and d1['targets_atomic']['m1'] == -(-d1['first_cycle_cost_atomic']['m1'] * 2 // 10000) * 10000 and d2['n_wallets'] == 3 and 'j1' in d2['targets_atomic']
          and d3['n_wallets'] == 2 and r_short is None and abs(r_long - 24.0) < 1e-6)
    return ok, d0['n_wallets'], d1['targets_atomic'], d2['n_wallets'], d3['n_wallets'], r_short, r_long


def kat_gt9(over):
    G, T, C = load(over, 'gate'), load(over, 'ttc'), load(over, 'earnrec')
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / 'harness/runtime').mkdir(parents=True)
        f = Path(d) / 'harness/runtime/gt_mainnet_cycle.json'
        steps = {s: {'status': 'measured', 'evidence': 'x'} for s in G.CYCLE}
        steps['game_settled'] = {'status': 'pending', 'blocker': 'waiting'}
        f.write_text(json.dumps({'steps': steps}))
        a = G.g36(d)
        (Path(d) / 'harness/runtime/gt_cycle_audit_mainnet.json').write_text(   # r32 run 9: G36 needs the chain audit
            json.dumps({'record': 'y', 'game_settled': True, 'sum_check': {'ok': True}}))
        steps['game_settled'] = {'status': 'measured', 'evidence': 'y'}
        steps['registered'] = {'status': 'measured'}                   # no evidence: not measured (audit present)
        f.write_text(json.dumps({'steps': steps}))
        b = G.g36(d)
        steps['registered'] = {'status': 'measured', 'evidence': 'x'}
        f.write_text(json.dumps({'steps': steps}))
        c = G.g36(d)
    e = T.estimate(1000000, 7905000, 1, 100, 1.0, 18000.0, 8000.0)
    H = 9 * 1000000 / 10.0
    rows = [{'kind': 'registered', 'wallets': ['m1', 'm2'], 'ts': '2026-11-15T03:00:00-08:00'},
            {'kind': 'earn_tick', 'ts': '2026-11-15T03:00:00-08:00', 'chain_credited': {'m1': 0, 'm2': 0}},
            {'kind': 'earn_tick', 'ts': '2026-11-15T04:00:00-08:00', 'chain_credited': {'m1': 30750, 'm2': 3075}},
            {'kind': 'earn_balances', 'ts': '2026-11-15T04:00:00-08:00', 'wallet_balance': {'m1': 30750, 'm2': 9000},
             'chain_credited': {'m1': 30750, 'm2': 3075}}]
    s = C.summarise(rows)
    ok = (a[0] == 'INFO' and 'waiting' in a[1] and b[0] == 'INFO' and c[0] is True
          and abs(e['fraction'] - round(5344 / (H + 5344), 5)) < 1e-9 and abs(e['miniblocks_per_block'] - 9 * e['fraction']) < 1e-3
          and s['registered_confirmed'] == ['m1', 'm2'] and s['balance_matches_chain'] == {'m1': True, 'm2': False}
          and 'dero1' not in json.dumps(s))
    return ok, a, b[0], c[0], e['fraction'], s['balance_matches_chain']


def kat_gt10(over):
    import os as _os, time as _time
    g = load(over, 'lib')
    root = Path(over.get('root') or ROOT)
    with tempfile.TemporaryDirectory() as d:
        r, b = Path(d) / 'repo', Path(d) / 'bin'
        (r / 'cmd/gt-wallet').mkdir(parents=True)
        b.mkdir()
        src = r / 'cmd/gt-wallet/main.go'
        src.write_text('package main')
        (r / 'cmd/gt-wallet/main_test.go').write_text('package main')
        missing = g.stale_bins(b, r, ['gt-wallet'])
        (b / 'gt-wallet').write_text('bin')
        now = _time.time()
        _os.utime(src, (now - 100, now - 100))
        _os.utime(r / 'cmd/gt-wallet/main_test.go', (now + 100, now + 100))     # a newer TEST file does not count
        _os.utime(b / 'gt-wallet', (now, now))
        fresh = g.stale_bins(b, r, ['gt-wallet'])
        _os.utime(src, (now + 50, now + 50))
        stale = g.stale_bins(b, r, ['gt-wallet'])
    recipes = [(root / PATHS['earn']).read_text(), (root / PATHS['page']).read_text()]
    rec_ok = all('&& touch earn.DONE' in x and 'pow_m1.json' in x and '; touch earn.DONE' not in x for x in recipes)
    ok = missing == [('gt-wallet', 'cmd/gt-wallet/main.go')] and fresh == [] and [s[0] for s in stale] == ['gt-wallet'] and rec_ok
    return ok, missing, fresh, stale, rec_ok


FAKE_REG = '''import json, os, sys, time
p = sys.argv[sys.argv.index('--progress') + 1]
open(p, 'w').write(json.dumps({'tries': 1234}))
if os.environ.get('FAKE_PIDFILE'):
    open(os.environ['FAKE_PIDFILE'], 'w').write(str(os.getpid()))
time.sleep(float(os.environ.get('FAKE_SLEEP', '2.5')))
sys.stderr.write('gt-wallet register: DERO.SendRawTransaction: -32098 address already registered')
sys.exit(1)
'''


def kat_gt11(over):
    import signal as _sig, time as _time
    root = Path(over.get('root') or ROOT)
    with tempfile.TemporaryDirectory() as d:
        env_keep = {k: os.environ.get(k) for k in ('GT_HOME', 'GT_WALLETS', 'GT_BANNED_FILE')}
        os.environ.update(GT_HOME=str(Path(d) / 'home'), GT_WALLETS=str(Path(d) / 'w'), GT_BANNED_FILE=str(forged_ban(d)))
        try:
            g = load(over, 'lib')
            spec = importlib.util.spec_from_file_location(f'gt32_earn_{uuid.uuid4().hex[:6]}', root / PATHS['earn'])
            e = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(e)
            o1 = e.register_outcome(0, '{"txid": "00ab"}', '')[0]
            o2 = e.register_outcome(1, '', 'x -32098 address already registered')[0]
            o3 = e.register_outcome(1, '', 'connection refused')[0]
            fake = Path(d) / 'fake_reg.py'
            fake.write_text(FAKE_REG)
            run = g.Run('kat11', 'mainnet')
            prog = Path(d) / 'pow.json'
            out = e.register_wallet(run, 'm9', [sys.executable, '-I', str(fake), '--progress', str(prog)], dict(os.environ), prog, tick_s=1)
            evs = [json.loads(l) for l in (run.dir / 'events.jsonl').read_text().splitlines()]
            ticks = [x for x in evs if x['kind'] == 'pow_tick' and x.get('tries') == 1234]
            already = [x for x in evs if x['kind'] == 'already_registered']
            # SIGTERM to an earn driver kills its register child
            pidf = Path(d) / 'child.pid'
            drv = Path(d) / 'drv.py'
            drv.write_text('import sys, signal, importlib.util\n'
                           f'sys.path.insert(0, {str(root / "playbooks")!r})\n'
                           f'spec = importlib.util.spec_from_file_location("e", {str(root / PATHS["earn"])!r})\n'
                           'e = importlib.util.module_from_spec(spec); spec.loader.exec_module(e)\n'
                           'import gtlib\n'
                           'signal.signal(signal.SIGTERM, e._term)\n'
                           "r = gtlib.Run('kat11b', 'mainnet')\n"
                           f"e.register_wallet(r, 'm9', [sys.executable, '-I', {str(fake)!r}, '--progress', {str(prog)!r}], dict(__import__('os').environ), {str(prog)!r})\n")
            env = dict(os.environ, FAKE_PIDFILE=str(pidf), FAKE_SLEEP='30')
            pr = subprocess.Popen([sys.executable, '-I', str(drv)], env=env)
            t0 = _time.time()
            while not pidf.exists() and _time.time() - t0 < 20:
                _time.sleep(0.2)
            cpid = int(pidf.read_text()) if pidf.exists() else None
            pr.send_signal(_sig.SIGTERM)
            pr.wait(timeout=20)
            _time.sleep(1.0)
            alive = False
            if cpid:
                try:
                    os.kill(cpid, 0)
                    alive = True
                except OSError:
                    alive = False
        finally:
            for k2, v in env_keep.items():
                if v is None:
                    os.environ.pop(k2, None)
                else:
                    os.environ[k2] = v
    ok = (o1, o2, o3) == ('sent', 'already', 'error') and out['outcome'] == 'already' and ticks and already \
        and cpid is not None and not alive
    return ok, (o1, o2, o3), out['outcome'], len(ticks), cpid is not None, alive


def kat_gt12(over):
    s = load(over, 'size')
    root = Path(over.get('root') or ROOT)
    sys.path.insert(0, str(root / 'playbooks'))
    spec = importlib.util.spec_from_file_location(f'gt32_trig_{uuid.uuid4().hex[:6]}', root / PATHS['trig'])
    tg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tg)
    ok_plan = s.plan_two_wallet(336, 1000, 100000)
    base = dict(ok_plan.get('plan') or {})
    v0 = s.viability(base, 336, 1000, 100000)
    va = s.viability(dict(base, principal=5000), 336, 1000, 100000)['checks']['a_fees_bounded']
    vb = s.viability(dict(base, sponsor=1000), 336, 1000, 100000)['checks']['b_participants_gain']
    vc = s.viability(dict(base, boost=0), 336, 1000, 100000)['checks']['c_same_address_incentive']
    vd = s.viability(base, 336, 1000, 100000, ponzi_shaped=True)['checks']['d_no_ponzi']
    ve = s.viability(base, 336, 1000, 90000)['checks']['e_budget']   # spend fits 90,000 but not its 75 %
    small = s.plan_two_wallet(336, 1000, 30000)
    rows = [{'kind': 'earn_tick', 'height': 100}, {'kind': 'earn_balances', 'wallet_balance': {'m1': 1, 'm2': 2}},
            {'kind': 'earn_tick', 'height': 105}, {'kind': 'earn_balances', 'wallet_balance': {'m1': 3, 'm2': 4}}]
    st = tg.settled_balances(rows, 110)            # 105 > 110 - 8: only the first read is settled
    ok = (ok_plan['viable'] and v0['ok'] and not va and not vb and not vc and not vd and not ve
          and not small['viable'] and (small.get('min_budget_each_atomic') or 0) > 30000 and st == {'m1': 1, 'm2': 2})
    return ok, ok_plan.get('plan'), (va, vb, vc, vd, ve), small, st


def kat_gt13(over):
    """r32 pipeline run 5 (G3 corpus + page STALE): the live trigger's call of cycle_from_earn (no --write) must leave
    the tracked records alone; only the pipeline's --write snapshot writes them. ROOT is pointed at a temp tree."""
    C = load(over, 'earnrec')
    rows = [{'kind': 'registered', 'wallets': ['m1', 'm2'], 'ts': '2026-11-15T03:00:00-08:00'},
            {'kind': 'earn_tick', 'ts': '2026-11-15T03:00:00-08:00', 'chain_credited': {'m1': 0, 'm2': 0}},
            {'kind': 'earn_balances', 'ts': '2026-11-15T04:00:00-08:00', 'wallet_balance': {'m1': 3075, 'm2': 3075},
             'chain_credited': {'m1': 3075, 'm2': 3075}}]
    with tempfile.TemporaryDirectory() as d:
        rt = Path(d) / 'harness/runtime'
        rt.mkdir(parents=True)
        (rt / 'gt_mainnet_cycle.json').write_text(json.dumps({'steps': {}}))
        ev = Path(d) / 'events.jsonl'
        ev.write_text(''.join(json.dumps(r) + '\n' for r in rows))
        C.ROOT = Path(d)
        with contextlib.redirect_stdout(io.StringIO()):
            r0 = C.main(['--events', str(ev)])
        live_wrote = (rt / 'gt_earn_mainnet.json').exists() or json.loads((rt / 'gt_mainnet_cycle.json').read_text()) != {'steps': {}}
        with contextlib.redirect_stdout(io.StringIO()):
            r1 = C.main(['--events', str(ev), '--write'])
        snap_wrote = (rt / 'gt_earn_mainnet.json').exists()
    ok = r0 == 0 and not live_wrote and r1 == 0 and snap_wrote
    return ok, r0, live_wrote, r1, snap_wrote


def kat_gt14(over):
    """r32 run-7 lesson: gt_earn.pick_next gives the slice to the wallet furthest below target and never to one at
    target (round-robin once gave m1 at 1.199 DERO a 20-min slice while m2 sat at 0.95); unknown balances -> round-robin."""
    root = Path(over.get('root') or ROOT)
    with tempfile.TemporaryDirectory() as d:
        env_keep = {k: os.environ.get(k) for k in ('GT_HOME', 'GT_WALLETS', 'GT_BANNED_FILE')}
        os.environ.update(GT_HOME=str(Path(d) / 'home'), GT_WALLETS=str(Path(d) / 'w'), GT_BANNED_FILE=str(forged_ban(d)))
        try:
            sys.path.insert(0, str(root / 'playbooks'))
            spec = importlib.util.spec_from_file_location(f'gt32_earn_{uuid.uuid4().hex[:6]}', root / PATHS['earn'])
            e = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(e)
            names, tgt = ['m1', 'm2'], 100000
            a = [e.pick_next(names, {'m1': 119925, 'm2': 95325}, tgt, i) for i in range(4)]     # m1 done -> always m2
            b = [e.pick_next(names, {'m1': 50000, 'm2': 80000}, tgt, i) for i in range(2)]      # furthest below first
            c = [e.pick_next(names, {}, tgt, i) for i in range(4)]                               # nothing known: rotate
            u = e.pick_next(names, {'m1': 119925, 'm2': None}, tgt, 0)                          # failed read: re-measure m2
        finally:
            for k2, v in env_keep.items():
                if v is None:
                    os.environ.pop(k2, None)
                else:
                    os.environ[k2] = v
    ok = a == ['m2'] * 4 and b == ['m1', 'm1'] and c == ['m1', 'm2', 'm1', 'm2'] and u == 'm2'
    return ok, a, b, c, u


def kat_gt15(over):
    """r32 run-8 lessons (2026-11-15 08:47-08:57 mainnet): a tx counts as final only in a VALID block CONFIRM_DEPTH deep
    (attest Freeze was seen mined, then sat in no main-chain block and no pool); a reverted Claim fails closed instead of
    driving Finalize(i=-1); arg_u refuses a value outside Uint64; a frozen contract takes no setup call; the trigger
    gives up after 3 failed cycles in a row."""
    root = Path(over.get('root') or ROOT)
    with tempfile.TemporaryDirectory() as d:
        env_keep = {k: os.environ.get(k) for k in ('GT_HOME', 'GT_WALLETS', 'GT_BANNED_FILE')}
        os.environ.update(GT_HOME=str(Path(d) / 'home'), GT_WALLETS=str(Path(d) / 'w'), GT_BANNED_FILE=str(forged_ban(d)))
        try:
            g = load(over, 'lib')
            sys.path.insert(0, str(root / 'playbooks'))
            mods = {}
            for key in ('cycle', 'trig'):
                spec = importlib.util.spec_from_file_location(f'gt32_{key}_{uuid.uuid4().hex[:6]}', root / PATHS[key])
                mods[key] = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mods[key])
            cy, tg = mods['cycle'], mods['trig']
            st = [cy.tx_state({'in_pool': True, 'block_height': -1}, 100),
                  cy.tx_state({'in_pool': False, 'block_height': 90, 'valid_block': 'ab'}, 100),
                  cy.tx_state({'in_pool': False, 'block_height': 99, 'valid_block': 'ab'}, 100),
                  cy.tx_state({'in_pool': False, 'block_height': 95, 'valid_block': ''}, 100),   # the run-8 case
                  cy.tx_state({}, 100)]
            try:
                cy.claim_index(0, 0)
                rev = False
            except RuntimeError:
                rev = True
            ci = cy.claim_index(4, 5)
            bad = []
            for v in (-1, 1 << 64):
                try:
                    g.arg_u('i', v)
                    bad.append(False)
                except ValueError:
                    bad.append(True)
            okarg = g.arg_u('i', 5)['value'] == 5
            su = (cy.setup_needed({'frozen': 1}), cy.setup_needed({'frozen': 0}), cy.setup_needed({}))
            gu = (tg.give_up(2), tg.give_up(3))
        finally:
            for k2, v in env_keep.items():
                if v is None:
                    os.environ.pop(k2, None)
                else:
                    os.environ[k2] = v
    ok = (st == ['pending', 'final', 'pending', 'lost', 'lost'] and rev and ci == 4 and bad == [True, True] and okarg
          and su == (False, True, True) and gu == (False, True))
    return ok, st, rev, ci, bad, su, gu


def kat_gt16(over):
    """r32 run-9 lesson (2026-11-15 rounds 3-5): m2's Enter landed 21-22 blocks after the Draw, past the 20-block commit
    window, so three rounds had one entrant. entry_index reads j back by the wallet's own commit (parallel Enters land
    in any order); game_settled needs a drawn round that EVERY player entered."""
    root = Path(over.get('root') or ROOT)
    with tempfile.TemporaryDirectory() as d:
        env_keep = {k: os.environ.get(k) for k in ('GT_HOME', 'GT_WALLETS', 'GT_BANNED_FILE')}
        os.environ.update(GT_HOME=str(Path(d) / 'home'), GT_WALLETS=str(Path(d) / 'w'), GT_BANNED_FILE=str(forged_ban(d)))
        try:
            sys.path.insert(0, str(root / 'playbooks'))
            spec = importlib.util.spec_from_file_location(f'gt32_cycle_{uuid.uuid4().hex[:6]}', root / PATHS['cycle'])
            cy = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cy)
            v = {'h5_0': 'b' * 64, 'h5_1': 'a' * 64, 'h4_0': 'a' * 64, 'n5': 2}
            ei = (cy.entry_index(v, 5, 'a' * 64), cy.entry_index(v, 5, 'b' * 64), cy.entry_index(v, 5, 'c' * 64))
            solo = [{'drawn': 1, 'winner_index': 0, 'entrants': 1}] * 3
            duo = solo + [{'drawn': 1, 'winner_index': 1, 'entrants': 2}]
            old = [{'drawn': 1, 'winner_index': 0}]                           # a record without entrants
            gs = (cy.game_settled(solo, 2), cy.game_settled(duo, 2), cy.game_settled(old, 2))
        finally:
            for k2, val in env_keep.items():
                if val is None:
                    os.environ.pop(k2, None)
                else:
                    os.environ[k2] = val
    ok = ei == (1, 0, None) and gs == (False, True, False)
    return ok, ei, gs


def kat_gt17(over):
    """r32 run-9 lesson: the first mainnet cycle record counted three one-entrant rounds and reported payoffs that
    included mining. cycle_audit re-derives entrants from the prize contract's n<r> and takes the mining credited in
    the cycle window out of the payoffs (a closed game sums to -fees); G36 passes only with an audit of the same record."""
    with tempfile.TemporaryDirectory() as d:
        env_keep = {k: os.environ.get(k) for k in ('GT_HOME', 'GT_WALLETS', 'GT_BANNED_FILE')}
        os.environ.update(GT_HOME=str(Path(d) / 'home'), GT_WALLETS=str(Path(d) / 'w'), GT_BANNED_FILE=str(forged_ban(d)))
        try:
            A, G = load(over, 'audit'), load(over, 'gate')
            rec = {'_path': 'r.json', 'measured_at': '2026-11-15T10:00:00-08:00', 'wallets': ['m1', 'm2'],
                   'results': {'m3_rounds': [{'round': 1, 'drawn': 1, 'winner_index': 1}, {'round': 2, 'drawn': 1, 'winner_index': 0}]},
                   'payoff_atomic': {'m1': 1000, 'm2': 5000}, 'fees_total_atomic': 1000}
            evs = [{'kind': 'cycle_start', 'ts': '2026-11-15T09:00:00-08:00'}]
            earn = [{'kind': 'earn_tick', 'ts': '2026-11-15T08:59:00-08:00', 'height': 1, 'chain_credited': {'m1': 0, 'm2': 0}},
                    {'kind': 'earn_tick', 'ts': '2026-11-15T10:01:00-08:00', 'height': 9, 'chain_credited': {'m1': 3000, 'm2': 4000}}]
            au = A.audit(rec, evs, earn, {'n1': 2, 'n2': 1})
            solo = A.audit(rec, evs, earn, {'n1': 1, 'n2': 1})
            rt = Path(d) / 'harness/runtime'
            rt.mkdir(parents=True)
            steps = {k: {'status': 'measured', 'evidence': 'r.json'} for k in G.CYCLE}
            (rt / 'gt_mainnet_cycle.json').write_text(json.dumps({'steps': steps}))
            g_none = G.g36(d)[0]
            (rt / 'gt_cycle_audit_mainnet.json').write_text(json.dumps(au))
            g_ok = G.g36(d)[0]
            (rt / 'gt_cycle_audit_mainnet.json').write_text(json.dumps(solo))
            g_solo = G.g36(d)[0]
            (rt / 'gt_cycle_audit_mainnet.json').write_text(json.dumps(dict(au, record='other.json')))
            g_other = G.g36(d)[0]
        finally:
            for k2, val in env_keep.items():
                if val is None:
                    os.environ.pop(k2, None)
                else:
                    os.environ[k2] = val
    ok = (au['genuine_rounds'] == [1] and au['solo_rounds'] == [2] and au['game_settled'] is True
          and au['net_game_payoff_atomic'] == {'m1': -2000, 'm2': 1000} and au['sum_check']['ok'] is True
          and solo['game_settled'] is False and g_none == 'INFO' and g_ok is True and g_solo == 'INFO' and g_other == 'INFO')
    return ok, au['genuine_rounds'], au['net_game_payoff_atomic'], au['sum_check'], (g_none, g_ok, g_solo, g_other)


KATS = [('GT1', kat_gt1), ('GT2', kat_gt2), ('GT3', kat_gt3), ('GT4', kat_gt4), ('GT5', kat_gt5), ('GT6', kat_gt6),
        ('GT7', kat_gt7), ('GT8', kat_gt8), ('GT9', kat_gt9), ('GT10', kat_gt10), ('GT11', kat_gt11), ('GT12', kat_gt12),
        ('GT13', kat_gt13), ('GT14', kat_gt14), ('GT15', kat_gt15), ('GT16', kat_gt16), ('GT17', kat_gt17)]

OWNERS = {'r32 ban': ['GT1', 'GT2', 'GT7'], 'r32 econ': ['GT3'], 'r32 ponzi': ['GT4'], 'r32 lint': ['GT5'],
          'r32 discovery': ['GT6'], 'r32 playbook': ['GT7'], 'r32 sizing': ['GT8'], 'r32 cycle': ['GT9'], 'r32 earnrun': ['GT10'], 'r32 earnbug2': ['GT11'], 'r32 viability': ['GT12'], 'r32 liverec': ['GT13'], 'r32 slicepick': ['GT14'], 'r32 txfinal': ['GT15'], 'r32 claimpost': ['GT15'], 'r32 uint': ['GT15'], 'r32 setupskip': ['GT15'], 'r32 giveup': ['GT15'], 'r32 entryidx': ['GT16'], 'r32 settled2': ['GT16'], 'r32 audit': ['GT17'], 'r32 g36audit': ['GT17']}
MUTATIONS = [
    ('audit', "    net = {w: rec['payoff_atomic'][w] - mined[w] for w in rec['wallets']} if mined else None", "    net = {w: rec['payoff_atomic'][w] for w in rec['wallets']} if mined else None", 'r32 audit: mining credits counted as game payoff'),
    ('gate', "        if au.get('record') != ev or not au.get('game_settled') or not (au.get('sum_check') or {}).get('ok'):", '        if False:', 'r32 g36audit: G36 passes on the record without its chain audit'),
    ('cycle', "        if k.startswith(f'h{r}_') and v == commit:", "        if k.startswith(f'h{r}_'):", 'r32 entryidx: the entry index is assumed, not read back by commit'),
    ('cycle', " and int(x.get('entrants', 0)) >= players for x in rounds)", ' for x in rounds)', 'r32 settled2: a one-entrant round counts as a settled game'),
    ('cycle', "    if tx.get('valid_block') and bh > 0:", '    if bh > 0:', 'r32 txfinal: a tx seen in an orphaned block counts as mined'),
    ('cycle', '    if int(nc_after) != int(nc_before) + 1:', '    if False:', 'r32 claimpost: a reverted Claim drives Finalize(i=-1)'),
    ('lib', '    if not 0 <= v < 1 << 64:', '    if False:', 'r32 uint: a negative Uint64 argument reaches the wallet'),
    ('cycle', "    return int((stringkeys or {}).get('frozen', 0) or 0) == 0", '    return True', 'r32 setupskip: a frozen contract re-takes setup calls'),
    ('trig', '    return fails >= cap', '    return False', 'r32 giveup: a failing cycle is retried without bound'),
    ('earn', "        return min(below, key=lambda n: (bals[n], names.index(n)))", "        pass", 'r32 slicepick: a wallet at target still gets mining slices'),
    ('earnrec', "    if not a.write:\n        print(", "    if False:\n        print(", 'r32 liverec: the live trigger rewrites the tracked records'),
    ('size', "        'a_fees_bounded': fee_frac <= FEE_FRACTION_MAX,", "        'a_fees_bounded': True,", 'r32 viability: fees are never bounded'),
    ('size', "        'b_participants_gain': ev['m2'] >= 0 and S * w1 / W - per_round['m1'] >= 0,", "        'b_participants_gain': True,",
     'r32 viability: a losing participant passes'),
    ('size', "        'e_budget': all(spend[r] <= budget_each * (1 - SAFETY) for r in spend),", "        'e_budget': all(spend[r] <= budget_each for r in spend),",
     'r32 viability: the fee safety margin is dropped'),
    ('trig', "        elif r.get('kind') == 'earn_balances' and last_h is not None and last_h <= height_now - STABLE_LIMIT:",
     "        elif r.get('kind') == 'earn_balances' and last_h is not None:", 'r32 viability: an unsettled balance triggers the game'),
    ('earn', "    if 'already registered' in (stderr or '') or '-32098' in (stderr or ''):\n        return 'already', None",
     "    if False:\n        return 'already', None", 'r32 earnbug2: already registered is an error'),
    ('earn', "            os.killpg(p.pid, signal.SIGTERM)", "            pass", 'r32 earnbug2: the register child survives a relaunch'),
    ('earn', "            run.event('pow_tick', wallet=name, tries=tries)", "            pass", 'r32 earnbug2: the grind shows no work'),
    ('lib', "        if not bp.exists() or (newest and newest.stat().st_mtime > bp.stat().st_mtime):",
     "        if not bp.exists():", 'r32 earnrun: an old binary is never found stale'),
    ('lib', "        gos = [f for f in src.glob('*.go') if not f.name.endswith('_test.go')]", "        gos = list(src.glob('*.go'))",
     'r32 earnrun: a test file makes the binary stale'),
    ('earn', "earn.log 2>&1 && touch earn.DONE", "earn.log 2>&1; touch earn.DONE", 'r32 earnrun: a crashed run ends the watch'),
    ('gate', "    done = [s for s in CYCLE if (steps.get(s) or {}).get('status') == 'measured' and (steps.get(s) or {}).get('evidence')]",
     "    done = [s for s in CYCLE if (steps.get(s) or {}).get('status') == 'measured']", 'r32 cycle: a step without evidence counts'),
    ('ttc', "    f = h / (H + h)", "    f = h / H", 'r32 cycle: the miner fraction ignores its own hashrate'),
    ('earnrec', "    agree = {w: (last_bal.get(w) is not None and abs(int(last_bal[w]) - int(last_cred.get(w, 0))) <= SHARE_TOL)",
     "    agree = {w: (last_bal.get(w) is not None)", 'r32 cycle: a balance is trusted without the chain scan'),
    ('size', "    if rate is None:\n        reasons.append('R3 no measured mainnet mining yet", "    rate = rate if rate is not None else est_rate\n    if rate is None:\n        reasons.append('R3 no measured mainnet mining yet",
     'r32 sizing: an estimate decides the wallet count'),
    ('size', "        need = math.ceil(c * MARGIN / (DERO // 10)) * (DERO // 10)", "        need = math.ceil(c / (DERO // 10)) * (DERO // 10)",
     'r32 sizing: the safety margin is dropped'),
    ('size', "    if hours < 0.5:\n        return None, hours", "    if hours < 0:\n        return None, hours", 'r32 sizing: a 10-minute log counts as a measurement'),
    ('size', "        if hours <= MAX_HOURS:", "        if True:", 'r32 sizing: a slow measured rate still adds a wallet'),
    ('ban', "    return hashlib.sha256(addr.strip().encode()).hexdigest()", "    return hashlib.sha256(addr.strip().encode()).hexdigest()[::-1]",
     'r32 ban: the digest no longer matches the private file'),
    ('ban', "            if digest(m.group(0)) in hs:\n                out.append(i)", "            if False:\n                out.append(i)",
     'r32 ban: scan_text never finds a banned address'),
    ('ban', "        raise BannedAddress(f'{what}: the address is on the private ban list (D-GT-2); refused')",
     "        raise BannedAddress(f'{what}: {addr} is on the private ban list (D-GT-2); refused')",
     'r32 ban: the refusal message leaks the address'),
    ('ban', "    if not hs:\n        raise ValueError('the banned-address file holds no hash')", "    if False:\n        raise ValueError('the banned-address file holds no hash')",
     'r32 ban: an empty ban list fails open'),
    ('econ', "    return (1 - caught) * p['reward'] * mat_value / caught", "    return p['reward'] * mat_value / caught",
     'r32 econ: the critical bond ignores the escape probability'),
    ('econ', "    w = [f * (100 + p['boost']) // 100 if b else f for f, b in zip(fees, boosted)]",
     "    w = [f * (100 + p['boost']) // 100 for f, b in zip(fees, boosted)]", 'r32 econ: everyone is boosted in the rebate model'),
    ('econ', "    bad = [x for x in ledger if x['source'] not in SOURCES_OK and x['source'] != 'none']",
     "    bad = [x for x in ledger if x['source'] == 'none']", 'r32 ponzi: later-deposit funding is not flagged'),
    ('econ', "SOURCES_OK = {'own_principal', 'own_bond',", "SOURCES_OK = {'later_deposit', 'own_principal', 'own_bond',",
     'r32 ponzi: later deposits are an allowed source'),
    ('pipe', "    if re.search(r'UPDATE_SC_CODE', text, re.I):", "    if False:", 'r32 lint: an upgradable contract passes'),
    ('pipe', "            if 'LOAD(\"frozen\") != 0 THEN GOTO 900' not in body or", "            if False and",
     'r32 lint: a setter that ignores Freeze passes'),
    ('pipe', "MINER_WORDS = re.compile(r'miner|coinbase|integrator|reward', re.I)", "MINER_WORDS = re.compile(r'zzz_never', re.I)",
     'r32 discovery: a miner-exposing builtin would go unnoticed'),
    ('lib', "        if self.net['spends_real_dero'] and not self.mc:", "        if False:",
     'r32 playbook: mainnet spends run without --mainnet-confirm'),
    ('lib', "    if not exe.startswith('gt-'):", "    if False:", 'r32 playbook: a playbook may start any binary'),
    ('lib', "        if banguard.scan_text(text):\n            raise banguard.BannedAddress('an event would carry a banned address; refused')",
     "        if False:\n            raise banguard.BannedAddress('an event would carry a banned address; refused')",
     'r32 ban: a banned address can reach the event log'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_gt32', HARNESS / 'kit' / 'katmut.py')
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
                ok, *det = fn(over)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — a crash is a failure
            ok, det = False, [f'{type(e).__name__}: {e}']
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
        print(f'\nr32 gt-mechanisms KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='gt32-mut-') as d:
            for rel in COPY_DIRS:
                shutil.copytree(ROOT / rel, Path(d) / rel, ignore=shutil.ignore_patterns('__pycache__', 'params_r32.json'))
            shutil.copytree(ROOT / 'dvm', Path(d) / 'dvm', ignore=shutil.ignore_patterns('*_test.go', 'testdata'))
            (Path(d) / 'artifacts/src').mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / PATHS['page'], Path(d) / PATHS['page'])
            (Path(d) / PATHS[key]).write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({'root': d}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(defect(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r32 gt-mechanisms KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
