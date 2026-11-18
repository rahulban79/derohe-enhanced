#!/usr/bin/env python3
"""gt_pipeline.py — r32 (artifacts/dero-game-theory-rft.md §0.2, §6): the zero-touch game-theory pipeline.

research -> discovery -> implementation -> debug -> enhancement -> playbook -> report, every stage deterministic and
LLM-free (the agents of a round author and refine the programs; this pipeline re-proves them and emits the playbook
parameters). Each stage writes JSONL events to harness/loop/runs/gt_pipeline_<ts>.jsonl and bumps a work counter in
the progress file, so harness/kit/stallwatch.py can judge liveness by work.

  research        gametheory/research/sources.json + dossier.md: every [n] cited exists, every claim has a class,
                  steer sources are never the only support of a design implication; counts per kind
  discovery       the DVM builtin census (dvm/dvm_functions.go func_table): names + compute costs; the D-GT-3 fact
                  "no builtin exposes the block's miner or integrator" machine-checked; reward_intel --check
  implementation  contract lint (gametheory/contracts/*.bas): every entrypoint of gametheory/mechanisms.json exists,
                  no UPDATE_SC_CODE (immutable rules), Freeze exists, owner setters refuse after Freeze, no banned
                  address, Initialize defaults = the econsim models
  debug           go test ./dvm -run R32GT and ./cmd/simulator -run R32 (GT_GAS_OUT gas census per entrypoint)
  enhancement     econsim checks + the parameter search: per network the smallest bond that deters inflation with a
                  2x margin at the assumed MAT value and detection rate, the prize cap from the withholding bounds at
                  the live block reward (reward_intel), the no-wash bound -> playbooks/params_r32.json
  playbook        the mainnet dry run (plan, user actions, gas) always; --sim also runs the full sim-chain playbook
  report          harness/runtime/gt_pipeline_last.json (+ a DONE marker for the monitor)

  python3 -I harness/gametheory/gt_pipeline.py [--sim] [--run-id ID] [--stages a,b,...]   exit 0 PASS · 4 a stage FAILED
"""
import argparse, datetime, json, os, re, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
GT = ROOT / 'harness' / 'gametheory'
RUNS = ROOT / 'harness' / 'loop' / 'runs'
RUNTIME = ROOT / 'harness' / 'runtime'
sys.path.insert(0, str(GT))
import banguard  # noqa: E402
import econsim  # noqa: E402

STAGES = ['research', 'discovery', 'implementation', 'debug', 'enhancement', 'playbook', 'report']
MINER_WORDS = re.compile(r'miner|coinbase|integrator|reward', re.I)


class P:
    def __init__(self, ts, progress):
        self.ts, self.progress, self.work = ts, Path(progress) if progress else None, 0
        RUNS.mkdir(parents=True, exist_ok=True)
        self.log = RUNS / f'gt_pipeline_{ts}.jsonl'
        self.res = {}

    def event(self, stage, status, **kw):
        self.work += 1
        rec = dict(ts=datetime.datetime.now().astimezone().isoformat(timespec='seconds'), stage=stage, status=status, **kw)
        line = json.dumps(rec, sort_keys=True)
        if banguard.scan_text(line):
            raise banguard.BannedAddress('a pipeline event would carry a banned address')
        with open(self.log, 'a') as f:
            f.write(line + '\n')
        if self.progress:
            self.progress.write_text(json.dumps({'work': self.work, 'stage': stage, 'status': status, 'ts': rec['ts']}))
        print(f"{rec['ts']} {stage:<14} {status:<5} " + ' '.join(f'{k}={v}' for k, v in kw.items())[:240])


def sh(argv, timeout=1800, env=None):
    r = subprocess.run(['nice', '-n', '15'] + argv, cwd=ROOT, capture_output=True, text=True, timeout=timeout,
                       env=dict(os.environ, **(env or {})))
    return r.returncode, r.stdout + r.stderr


# ---------------------------------------------------------------- stages
def st_research(p):
    src = json.loads((ROOT / 'gametheory/research/sources.json').read_text())
    dos = (ROOT / 'gametheory/research/dossier.md').read_text()
    ns = {int(s['n']) for s in src}
    cited = {int(x) for x in re.findall(r'\[(\d+)\]', dos)}
    kinds = {}
    for s in src:
        kinds[s['kind']] = kinds.get(s['kind'], 0) + 1
    missing = sorted(cited - ns)
    bad_kind = [s['n'] for s in src if s['kind'] not in ('doc', 'paper', 'steer')]
    # a design implication backed only by steer sources is not evidence (child rft §0.8)
    steer = {int(s['n']) for s in src if s['kind'] == 'steer'}
    impl = dos.split('Design implications', 1)[1].split('Open questions', 1)[0] if 'Design implications' in dos else ''
    steer_only = [l[:60] for l in impl.splitlines() if l.strip().startswith(('-', '*', '1', '2', '3', '4', '5', '6', '7', '8', '9'))
                  and re.findall(r'\[(\d+)\]', l) and all(int(x) in steer for x in re.findall(r'\[(\d+)\]', l))]
    ok = not missing and not bad_kind and not steer_only and bool(impl) and len(src) >= 20
    p.event('research', 'PASS' if ok else 'FAIL', sources=len(src), kinds=kinds, cited=len(cited),
            missing=missing, steer_only=len(steer_only))
    return ok, {'sources': len(src), 'kinds': kinds, 'cited': len(cited), 'steer_only_implications': steer_only}


def dvm_builtins():
    t = (ROOT / 'dvm/dvm_functions.go').read_text()
    return {m.group(1): int(m.group(2)) for m in re.finditer(r'func_table\["([a-z0-9_]+)"\].*?ComputeCost: (\d+)', t)}


def st_discovery(p):
    b = dvm_builtins()
    miner_like = sorted(k for k in b if MINER_WORDS.search(k))
    inputs = (ROOT / 'dvm/dvm.go').read_text().split('type Blockchain_Input struct', 1)[1].split('}', 1)[0]
    input_fields = re.findall(r'^\s*([A-Za-z_]+)\s', inputs, re.M)
    rc, out = sh([sys.executable, '-I', 'harness/gametheory/reward_intel.py', '--check'], timeout=300)
    ok = len(b) >= 30 and 'Signer' in input_fields and not miner_like and not any(MINER_WORDS.search(f) for f in input_fields) and rc == 0
    p.event('discovery', 'PASS' if ok else 'FAIL', builtins=len(b), miner_builtins=miner_like, chain_inputs=input_fields,
            reward_anchors_rc=rc)
    return ok, {'builtins': b, 'chain_inputs': input_fields, 'miner_observable': bool(miner_like),
                'reward_anchor_check': out.strip().splitlines()[-1:] if out.strip() else []}


def lint_contract(text, entrypoints):
    funcs = re.findall(r'^Function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(', text, re.M)
    issues = []
    for e in entrypoints:
        if e not in funcs:
            issues.append(f'missing entrypoint {e}')
    if re.search(r'UPDATE_SC_CODE', text, re.I):
        issues.append('UPDATE_SC_CODE present (rules not immutable)')
    setters = [f for f in ('SetParams', 'SetMAT', 'SetFees') if f in funcs]
    if setters and 'Freeze' not in funcs:                     # r33: Freeze is required where the owner can set rules
        issues.append('no Freeze()')
    # r33 audit regressions, machine-checked (GT-A01/A12, lessons 34-35)
    init = text.split('Function Initialize(', 1)[1].split('End Function', 1)[0] if 'Function Initialize(' in text else ''
    first = next((l.strip() for l in init.splitlines()[1:] if l.strip()), '')
    if not re.match(r'^\d+\s+IF EXISTS\("owner"\) == 1 THEN GOTO \d+$', first):
        issues.append('GT-A01: Initialize does not start with the run-once guard')
    if 'IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO' not in init:
        issues.append('GT-A12: Initialize does not refuse an anonymous owner')
    code = re.sub(r'/\*.*?\*/', '', text, flags=re.S)        # checks on code, not on the explanatory comments
    code = re.sub(r'//[^\n]*', '', code)
    if re.search(r'ADDRESS_RAW\(SIGNER\(\)\)', code):
        issues.append('lesson 34: ADDRESS_RAW(SIGNER()) is the empty string')
    for i, line in enumerate(text.splitlines(), 1):
        if re.search(r'\bTHEN\b(?!\s+GOTO\b)', line):
            issues.append(f'line {i}: IF ... THEN without GOTO (lesson 35)')
        if 'SEND_DERO_TO_ADDRESS' in line and ('"burned"' in line or 'LOAD("owner")' in line and 'gt_pool' in text[:200]):
            issues.append(f'line {i}: a SEND reads the burn or pays the owner')
    for f in setters:
        if f in funcs:
            body = text.split(f'Function {f}(', 1)[1].split('End Function', 1)[0]
            if 'LOAD("frozen") != 0 THEN GOTO 900' not in body or 'LOAD("owner") != SIGNER()' not in body:
                issues.append(f'{f} does not refuse after Freeze or for a non-owner')
    if banguard.scan_text(text):
        issues.append('banned address')
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if s and s[0].isdigit() and not re.match(r'^\d+\s+\S', s):
            issues.append(f'line {i}: empty numbered line')
    return funcs, issues


def st_implementation(p):
    mech = json.loads((ROOT / 'gametheory/mechanisms.json').read_text())
    out, ok = {}, True
    defaults_map = {'gt_attest.bas': econsim.M1_DEFAULTS, 'gt_service.bas': econsim.M2_DEFAULTS, 'gt_prize.bas': econsim.M3_DEFAULTS}
    for m in mech['mechanisms']:
        if m['status'] != 'GO':
            continue
        text = (ROOT / 'gametheory/contracts' / m['contract']).read_text()
        funcs, issues = lint_contract(text, m['entrypoints'])
        d = econsim.contract_defaults(text)
        model = defaults_map.get(m['contract'], {})
        drift = {k: (d.get(k), v) for k, v in model.items() if d.get(k) != v}
        if drift:
            issues.append(f'defaults differ from the econsim model: {drift}')
        out[m['id']] = {'functions': len(funcs), 'issues': issues}
        ok &= not issues
    p.event('implementation', 'PASS' if ok else 'FAIL', contracts={k: len(v['issues']) for k, v in out.items()})
    return ok, out


def st_debug(p):
    gas = RUNTIME / 'gt_gas_census.json'
    if gas.exists():
        gas.unlink()
    rc1, o1 = sh(['go', 'test', '-p', '1', './dvm', '-run', 'R32GT|R32aAudit|R33', '-count=1', '-v'], env={'GT_GAS_OUT': str(gas)})   # r32a: + M4
    rc2, o2 = sh(['go', 'test', '-p', '1', './cmd/simulator', '-run', 'R32', '-count=1'])
    passed = re.findall(r'^--- PASS: (TestR3[23]\w+)', o1, re.M)
    failed = re.findall(r'^--- FAIL: (TestR3[23]\w+)', o1 + o2, re.M)
    logs = re.findall(r'r32_gametheory_test.go:\d+: (.+)', o1)
    g = json.loads(gas.read_text()) if gas.exists() else {}
    ok = bool(rc1 == 0 and rc2 == 0 and len(passed) >= 15 and sum(x.startswith('TestR33') for x in passed) >= 30 and not failed and g)   # r32a: 9 R32GT + 6 R32aAudit
    p.event('debug', 'PASS' if ok else 'FAIL', go_dvm_rc=rc1, go_sim_rc=rc2, passed=len(passed), failed=failed,
            gas_entries=len(g))
    return ok, {'passed': passed, 'failed': failed, 'logs': logs, 'gas': g, 'tail': (o1 + o2)[-600:] if not ok else ''}


def st_enhancement(p, res):
    an = econsim.analyse(seed=32)
    live = {}
    try:
        live = json.loads((RUNTIME / 'gt_reward_live.json').read_text())
    except (OSError, ValueError):
        pass
    reward = None
    for k in ('reward_atomic', 'block_reward', 'reward'):
        v = live.get('summary', {}).get(k) if isinstance(live.get('summary'), dict) else None
        if isinstance(v, (int, float)):
            reward = int(v)
            break
    if reward is None:
        m = re.search(r'"reward[a-z_]*":\s*(\d{4,})', json.dumps(live))
        reward = int(m.group(1)) if m else 30750
    params = {}
    # the MAT value assumption: the boost a MAT buys is worth BOOST_SHARE of the miniblock reward it attests
    # (sim block reward 61500 measured on the sim chain, mainnet from reward_intel); sensitivity is in econsim
    BOOST_SHARE = 0.10
    for net, blk, caught in (('sim', 61500, 0.855), ('testnet', 61500, 0.855), ('mainnet', reward, 0.5)):
        base = dict(econsim.M1_DEFAULTS)
        mat_value = BOOST_SHARE * (blk / 10) / base['reward']
        crit = econsim.m1_critical_bond(base, 10, 5, mat_value, caught)
        bond = int(max(2000, 2 * crit))   # D-GT-7: the 1-DERO default would not fit the 2-wallet mainnet budget; evidence = 2 x critical
        s = dict(econsim.M2_DEFAULTS)
        assert s['rho'] * (100 + s['boost']) <= 10000
        z = dict(econsim.M3_DEFAULTS)
        cap = econsim.m3_withholding(z, 0, 4, block_reward_forgone=blk // 10)['max_safe_prize']
        windows = {'sim': (240, 120, 120, 300, 150), 'testnet': (240, 120, 120, 300, 150), 'mainnet': (200, 100, 100, 400, 100)}[net]
        params[net] = {
            'attest': dict(base, bond=bond, window=windows[0], commitw=windows[1], revealw=windows[2]),
            'service': dict(s, epoch=windows[3]),
            'prize': dict(z, commitw=windows[4], revealw=windows[4]),
            'derived': {'critical_bond': round(crit, 2), 'mat_value_atomic': round(mat_value, 4), 'boost_share': BOOST_SHARE, 'caught': caught,
                        'prize_cap_atomic': cap, 'block_reward_atomic': blk}}
    out = ROOT / 'playbooks' / 'params_r32.json'
    out.write_text(json.dumps({'_doc': 'generated by harness/gametheory/gt_pipeline.py enhancement; read by playbooks/gtlib.py',
                               'params': params}, indent=1, sort_keys=True) + '\n')
    gas = res.get('debug', {}).get('gas', {})
    max_gas = max((v[0] for v in gas.values()), default=0)
    # D-GT-7: the harness-computed mainnet sizing (wallet count + target per role) from the measured data
    rc_s, out_s = sh([sys.executable, '-I', 'harness/gametheory/sizing.py', '--write'], timeout=120)
    ok = an['ok'] and rc_s == 0 and all(params[n]['attest']['bond'] >= 2 * params[n]['derived']['critical_bond'] for n in params) and max_gas < 10_000_000
    p.event('enhancement', 'PASS' if ok else 'FAIL', econsim=f"{sum(c['ok'] for c in an['checks'])}/{len(an['checks'])}",
            block_reward=reward, max_compute_gas=max_gas, params='playbooks/params_r32.json')
    return ok, {'econsim': an, 'params': params}


def st_playbook(p, sim, run_id):
    rc, out = sh([sys.executable, '-I', 'playbooks/gt_playbook.py', 'all', '--network', 'mainnet', '--dry-run',
                  '--run-id', f'{run_id}-mainnet-dry'], timeout=300)
    ua = len(re.findall(r'user_action_required', out))
    # D-GT-4: the mainnet earn step (register + mine a NEW gt wallet) stops at the user's --mainnet-confirm (exit 5);
    # its plan reads the live difficulty (read-only) and records the time-to-coins estimate
    rc_e, out_e = sh([sys.executable, '-I', 'playbooks/gt_earn.py', '--wallet', 'm1', '--run-id', f'{run_id}-earn-plan'], timeout=120)
    rc_t, _ = sh([sys.executable, '-I', 'harness/gametheory/time_to_coins.py'], timeout=60)
    rc_c, _ = sh([sys.executable, '-I', 'harness/gametheory/cycle_from_earn.py', '--write'], timeout=60)   # 2 = no earn log yet
    recs = sorted((ROOT / 'harness/runtime').glob('gt_cycle_mainnet_*.json'))   # r32 run 9: the chain audit G36 requires
    rc_a = sh([sys.executable, '-I', 'harness/gametheory/cycle_audit.py', '--record', str(recs[-1].relative_to(ROOT)), '--write'],
              timeout=300)[0] if recs else 0
    rc_r, _ = sh([sys.executable, '-I', 'harness/gametheory/recipe_lint.py'], timeout=30)   # r32a: live DONE recipes (2 = none yet)
    rc_g, _ = sh([sys.executable, '-I', 'playbooks/gt_cycle.py', '--network', 'mainnet'], timeout=60)  # 5 = refused w/o confirm   # read-only; the page's record is written on purpose (--write)
    ok = rc == 5 and ua >= 6 and rc_e == 5 and rc_t == 0 and rc_c in (0, 2) and rc_a == 0 and rc_r in (0, 2) and rc_g == 5   # 5 = the mainnet plan stops at every user step
    info = {'mainnet_dry_rc': rc, 'user_actions': ua, 'earn_plan_rc': rc_e, 'time_to_coins_rc': rc_t, 'earn_record_rc': rc_c, 'cycle_audit_rc': rc_a, 'recipe_lint_rc': rc_r, 'cycle_gate_rc': rc_g}
    if sim:
        rc2, out2 = sh([sys.executable, '-I', 'playbooks/gt_playbook.py', 'all', '--network', 'sim', '--run-id', f'{run_id}-sim',
                        '--mine-seconds', '45'], timeout=3600)
        info['sim_rc'] = rc2
        rp = Path.home() / 'derohe-persist' / 'gt-sim' / 'runs' / f'{run_id}-sim' / 'report.json'
        if rp.exists():
            rep = json.loads(rp.read_text())
            info['sim_checks'] = rep.get('checks')
            info['sim_wallets'] = rep.get('wallets')
        ok &= rc2 == 0
    p.event('playbook', 'PASS' if ok else 'FAIL', **{k: v for k, v in info.items() if k not in ('sim_wallets', 'sim_checks')})
    return ok, info


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--sim', action='store_true')
    ap.add_argument('--run-id', default=None)
    ap.add_argument('--stages', default=','.join(STAGES))
    ap.add_argument('--progress', default=None)
    ap.add_argument('--done', default=None, help='marker file written at the end (the monitor waits for it)')
    a = ap.parse_args(argv)
    ts = datetime.datetime.now().strftime('%Y%m%dT%H%M%S')
    run_id = a.run_id or f'gtp-{ts}'
    p = P(ts, a.progress)
    want = a.stages.split(',')
    verdict, results = {}, {}
    p.event('pipeline', 'START', run_id=run_id, stages=want, sim=a.sim)
    t0 = time.time()
    for st in STAGES:
        if st not in want or st == 'report':
            continue
        try:
            if st == 'research':
                ok, r = st_research(p)
            elif st == 'discovery':
                ok, r = st_discovery(p)
            elif st == 'implementation':
                ok, r = st_implementation(p)
            elif st == 'debug':
                ok, r = st_debug(p)
            elif st == 'enhancement':
                ok, r = st_enhancement(p, results)
            elif st == 'playbook':
                ok, r = st_playbook(p, a.sim, run_id)
        except Exception as e:  # noqa: BLE001 — a crashed stage is a FAIL with its reason
            ok, r = False, {'error': f'{type(e).__name__}: {e}'}
            p.event(st, 'FAIL', error=r['error'][:200])
        verdict[st], results[st] = ok, r
    summary = {'run_id': run_id, 'ts': ts, 'log': str(p.log.relative_to(ROOT)), 'verdict': verdict,
               'pass': all(verdict.values()), 'wall_s': round(time.time() - t0, 1),
               'results': {k: v for k, v in results.items() if k != 'enhancement'},
               'econsim_checks': results.get('enhancement', {}).get('econsim', {}).get('checks'),
               'params': results.get('enhancement', {}).get('params')}
    pb = results.get('playbook', {})
    summary['kpis'] = {'stages_pass': sum(1 for x in verdict.values() if x), 'stages': len(verdict),
                       'econsim_ok': sum(1 for c in (summary['econsim_checks'] or []) if c['ok']),
                       'dvm_tests_pass': len(results.get('debug', {}).get('passed', [])),
                       'sim_checks_ok': sum(1 for c in (pb.get('sim_checks') or []) if c.get('ok')) if a.sim else 'pending',
                       'sim_checks': len(pb.get('sim_checks') or []) if a.sim else 'pending'}
    text = json.dumps(summary, indent=1, sort_keys=True, default=str)
    if banguard.scan_text(text):
        raise banguard.BannedAddress('the pipeline summary would carry a banned address')
    (RUNTIME / 'gt_pipeline_last.json').write_text(text)
    p.event('report', 'PASS' if summary['pass'] else 'FAIL', verdict=verdict, wall_s=summary['wall_s'])
    if a.done:
        Path(a.done).write_text(('PASS' if summary['pass'] else 'FAIL') + f' {run_id}\n')
    return 0 if summary['pass'] else 4


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
