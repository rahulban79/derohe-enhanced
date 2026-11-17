#!/usr/bin/env python3
"""gt_earn.py — r32 (artifacts/dero-game-theory-rft.md D-GT-4): earn the first coins of a NEW gt wallet by mining.

The user (2026-11-15): "first some coins needs to be earned for those new wallets through automated mining through
pipelines of round 32". On the sim chain this is part of gt_playbook.py (`all`). On mainnet it is this script, and every
mainnet action runs ONLY with --mainnet-confirm, which the user passes (this session's permission system refused the
mainnet registration and the removal of that gate; both stay the user's, rft §0.4 D-GT-4).

  python3 -I playbooks/gt_earn.py --wallet m1 --plan                       # read-only: the plan + time-to-coins estimate
  python3 -I playbooks/gt_earn.py --wallet m1 --mainnet-confirm [--threads 8] [--cpu-max 80] [--target-dero 1.0]
      1. the wallet ~/dero-wallets/gt/mainnet/<name>.db (created if missing; seed never printed; banguard-checked)
      2. registration: the txid ground to 3 zero bytes (gt-wallet register --pow-threads), sent to the local derod RPC
      3. a pipeline-owned miner (gt-dero-miner, nice 15, capped threads) mining to that wallet via 127.0.0.1:10100
      4. every 60 s: the wallet balance (gt-wallet balance) and the miniblocks the chain credits to the wallet since the
         start height (DERO.GetBlock miners, compared in memory, never written) -> earn.jsonl; stops at the target
Watched run (the recipe; DONE only on success, so a crash is relaunched; the PoW counter is a work file):
  echo "cd ~/derohe-Release151 && python3 -I playbooks/gt_earn.py --wallet m1,m2 --mainnet-confirm --rebuild ... >> earn.log 2>&1 && touch earn.DONE" > earn.cmd
  python3 -I harness/kit/stallwatch.py --match 'gt_earn.py --wallet m1,m2' --cmd-file earn.cmd --work <run>/events.jsonl \
      --work <run>/pow_m1.json --work <run>/pow_m2.json --done earn.DONE --stall-s 3600 --log earn.watch.log
Never: the user's own address (banguard), derod start/stop/renice, the user's launchd miner or bin/, ~/dero-data,
P2P 11011. Exit 0 target reached / plan printed · 5 --mainnet-confirm missing · 6 banned address · 1 error.
"""
import argparse, json, os, signal, subprocess, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gtlib  # noqa: E402
from gtlib import banguard, rpc_call  # noqa: E402

ROOT = gtlib.ROOT


# r32 earn-run bug 2 (main session 2026-11-15 03:51): a stallwatch relaunch killed gt_earn but not its gt-wallet
# register child, which still sent m2's registration; the relaunch then ground 33.1M tries again and was refused with
# -32098 'address already registered'. Now (1) the register child dies with gt_earn (SIGTERM handler, own session
# group), (2) 'already registered' counts as success, (3) the PoW counter is mirrored into events.jsonl (pow_tick every
# 30 s), so the default work file shows the grind's progress.
CHILD = {'p': None}
# r32a (main session 2026-11-15 14:28): a SIGTERM to gt_earn raised SystemExit past rotate(), whose miner (a detached
# nohup child recorded in state.json) kept mining; a relaunch would keep it (start_proc is idempotent per NAME) and start
# a second miner for another wallet. Now the handler and rotate() stop every recorded miner (stop_miners).
RUN = {'run': None}


def stop_miners(run, keep=None):
    """stop every recorded mainnet-miner-* process of this run except `keep`; returns the names stopped"""
    out = []
    for name in sorted((run.state.get('procs') or {})):
        if name.startswith('mainnet-miner-') and name != keep and gtlib.stop_proc(run, name):
            out.append(name)
    return out


def _term(signum, frame):
    if RUN['run'] is not None:
        stop_miners(RUN['run'])
    p = CHILD['p']
    if p is not None and p.poll() is None:
        try:
            os.killpg(p.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            p.terminate()
    raise SystemExit(128 + signum)


def register_outcome(rc, stdout, stderr):
    """('sent', record) · ('already', None) · ('error', text) for one gt-wallet register exit. Pure."""
    if rc == 0:
        try:
            rec = json.loads(stdout.strip().splitlines()[-1])
            return ('already', None) if rec.get('already_registered') else ('sent', rec)
        except (ValueError, IndexError):
            return 'error', 'unreadable register output'
    if 'already registered' in (stderr or '') or '-32098' in (stderr or ''):
        return 'already', None
    return 'error', (stderr or '').strip()[-300:]


def register_wallet(run, name, argv, env, progress, tick_s=30):
    """run gt-wallet register in its own process group, mirror its PoW counter into events.jsonl, classify the exit."""
    p = subprocess.Popen(['nice', '-n', '15'] + argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
                         start_new_session=True)
    CHILD['p'] = p
    last = time.time()
    while p.poll() is None:
        time.sleep(1)
        if time.time() - last >= tick_s:
            last = time.time()
            try:
                tries = json.loads(Path(progress).read_text()).get('tries')
            except (OSError, ValueError):
                tries = None
            run.event('pow_tick', wallet=name, tries=tries)
    out, err = p.communicate()
    CHILD['p'] = None
    kind, rec = register_outcome(p.returncode, out, err)
    if kind == 'sent':
        run.event('registered_sent', wallet=name, txid=rec['txid'][:16], pow_tries=rec.get('pow_tries'),
                  pow_seconds=round(rec.get('pow_seconds', 0), 1))
    elif kind == 'already':
        run.event('already_registered', wallet=name, note='the node says registered (an earlier send landed): success')
    return {'outcome': kind, 'detail': rec}


def pick_next(names, bals, target, i, targets=None):
    """r32 run-7 lesson: the next slice goes to the wallet furthest below target (the last measured balances); a wallet
    already at target never gets a slice (round-robin wasted a 20-min slice on m1 at 1.199 while m2 sat at 0.95).
    With no balance known yet it is plain round-robin. r32a (2026-11-16 05:05): `targets` = the next ladder step's need
    per wallet (gt_ladder writes earn_targets.json); the wallet furthest below ITS need goes first (step 5 waited on the
    sponsor m1 while the poorest-first rotation mined m5, already above its need); when every wallet meets its need the
    global target applies again (poorest first)."""
    unknown = [n for n in names if bals.get(n) is None]
    for tier in ((targets or {}), {}):
        t = {n: int(tier.get(n, target)) for n in names}
        below = [n for n in names if bals.get(n) is not None and bals[n] < t[n]]
        if tier and not below:
            continue
        if below and not unknown:
            return max(below, key=lambda n: (t[n] - bals[n], -names.index(n)))
        break
    pool = unknown or names
    return pool[i % len(pool)]


def read_targets():
    """{wallet: atomic} from <GT_HOME>/mainnet/earn_targets.json (written by gt_ladder), or {}."""
    p = gtlib.GT_HOME / 'mainnet' / 'earn_targets.json'
    try:
        return {k: int(v) for k, v in json.loads(p.read_text()).get('targets_atomic', {}).items()}
    except (OSError, ValueError, AttributeError):
        return {}


def rotate(a, run, names, addrs, wdir, gw):
    """D-GT-5: one pipeline-owned miner rotates among the miner wallets (slice_min each) so every one earns; every
    minute the chain-credited miniblocks per wallet are recorded; it ends when each wallet holds target_dero."""
    daemon = gtlib.NETWORKS['mainnet']['daemon']
    credited = {n: 0 for n in names}
    seen = int(rpc_call(daemon, 'DERO.GetInfo')['height'])
    t_end = time.time() + a.max_hours * 3600
    i = 0
    bals = {}
    while time.time() < t_end:
        n = pick_next(names, bals, int(a.target_dero * 100000), i, read_targets())
        i += 1
        stop_miners(run, keep=f'mainnet-miner-{n}')    # one pipeline-owned miner at a time
        gtlib.start_proc(run, f'mainnet-miner-{n}', [str(gtlib.BIN / 'gt-dero-miner'), f'--wallet-address={addrs[n]}',
                                                     f"--daemon-rpc-address={gtlib.NETWORKS['mainnet']['getwork']}",
                                                     f'--mining-threads={a.threads}', f'--cpu-max={a.cpu_max}', '--node-rpc-address=off'])
        run.event('mainnet_miner_started', wallet=n, height=seen, threads=a.threads, cpu_max=a.cpu_max)
        t_slice = time.time() + a.slice_min * 60
        while time.time() < min(t_slice, t_end):
            time.sleep(60)
            h = int(rpc_call(daemon, 'DERO.GetInfo')['height'])
            for x in range(seen + 1, h - 1):
                bh = rpc_call(daemon, 'DERO.GetBlock', {'height': x})['block_header']
                ms = bh.get('miners', [])
                for m in (ms[:-1] if len(ms) == 10 else ms):
                    for nn, ad in addrs.items():
                        if m == ad and nn in credited:
                            credited[nn] += int(bh.get('reward', 0)) // 10
                seen = x
            run.event('earn_tick', mining=n, height=h, chain_credited={k: v for k, v in credited.items()})
        gtlib.stop_proc(run, f'mainnet-miner-{n}')
        bals = {}
        for nn in names:
            envn = dict(os.environ, GT_WALLET_PASSWORD=(wdir / f'{nn}.pass').read_text().strip())
            r = subprocess.run(['nice', '-n', '15'] + gw + ['balance', '--daemon', daemon, '--file', str(wdir / f'{nn}.db'), '--mainnet-confirm'],
                               capture_output=True, text=True, env=envn, timeout=600)
            bals[nn] = json.loads(r.stdout.strip().splitlines()[-1])['mature'] if r.returncode == 0 else None
        run.event('earn_balances', wallet_balance=bals, chain_credited=credited)
        if all((b or 0) >= int(a.target_dero * 100000) for b in bals.values()):
            break
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--wallet', default='m1', help='one miner wallet, or a comma list m1,m2,m3: the miner rotates among them')
    ap.add_argument('--slice-min', type=float, default=20.0, help='minutes per wallet in the rotation (D-GT-5: every miner wallet earns)')
    ap.add_argument('--register-roles', default='', help='also create + register these role wallets (e.g. sponsor,chal,j1,j2,j3,u1,u2)')
    ap.add_argument('--run-id', default='r32-mainnet-earn')
    ap.add_argument('--threads', type=int, default=8)
    ap.add_argument('--cpu-max', type=int, default=80)
    ap.add_argument('--target-dero', type=float, default=1.0)
    ap.add_argument('--plan', action='store_true')
    ap.add_argument('--mainnet-confirm', action='store_true', help='USER ONLY: register, mine and spend on mainnet')
    ap.add_argument('--max-hours', type=float, default=6.0)
    ap.add_argument('--rebuild', action='store_true', help='rebuild a gt-* binary older than its Go sources (else refuse)')
    a = ap.parse_args(argv)
    est = subprocess.run([sys.executable, '-I', str(ROOT / 'harness/gametheory/time_to_coins.py'), '--threads', str(a.threads),
                          '--cpu-max', str(a.cpu_max), '--target-dero', str(a.target_dero)], capture_output=True, text=True)
    plan = json.loads(est.stdout) if est.returncode == 0 else {'error': est.stderr[-200:]}
    run = gtlib.Run(a.run_id, 'mainnet', dry_run=a.plan or not a.mainnet_confirm, mainnet_confirm=a.mainnet_confirm)
    run.event('earn_plan', wallet=a.wallet, threads=a.threads, cpu_max=a.cpu_max, target_dero=a.target_dero,
              expected_hours=plan.get('expected_hours_to_target'), first_miniblock_s=plan.get('expected_first_miniblock_s'),
              dero_per_day=plan.get('dero_per_day'))
    if a.plan or not a.mainnet_confirm:
        print(json.dumps(plan, indent=1))
        if not a.mainnet_confirm and not a.plan:
            run.event('user_action_required', what='mainnet registration + mining of a new gt wallet',
                      cmd=f'python3 -I playbooks/gt_earn.py --wallet {a.wallet} --mainnet-confirm')
            return 5
        return 0
    gtlib.ensure_bins(run, ['gt-wallet', 'gt-dero-miner'], rebuild=a.rebuild)
    wdir = gtlib.WALLETS / 'mainnet'
    wdir.mkdir(parents=True, exist_ok=True)
    os.chmod(gtlib.WALLETS, 0o700)
    os.chmod(wdir, 0o700)
    pf = wdir / f'{a.wallet}.pass'
    if not pf.exists():
        pf.write_text(gtlib.new_password())
        os.chmod(pf, 0o600)
    env = dict(os.environ, GT_WALLET_PASSWORD=pf.read_text().strip())
    gw = [str(gtlib.BIN / 'gt-wallet')]
    f = ['--file', str(wdir / f'{a.wallet}.db'), '--mainnet-confirm']

    def gtw(*args):
        r = subprocess.run(['nice', '-n', '15'] + gw + list(args) + f, capture_output=True, text=True, env=env, timeout=7200)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip()[-300:])
        return json.loads(r.stdout.strip().splitlines()[-1])

    RUN['run'] = run
    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)
    names = [x for x in a.wallet.split(',') if x]
    roles = [x for x in a.register_roles.split(',') if x]
    try:
        addrs = {}
        for nm in names + roles:
            pfn = wdir / f'{nm}.pass'
            if not pfn.exists():
                pfn.write_text(gtlib.new_password())
                os.chmod(pfn, 0o600)
            envn = dict(os.environ, GT_WALLET_PASSWORD=pfn.read_text().strip())
            fn = ['--file', str(wdir / f'{nm}.db'), '--mainnet-confirm']
            r = subprocess.run(['nice', '-n', '15'] + gw + ['create', '--if-missing'] + fn, capture_output=True, text=True, env=envn, timeout=600)
            if r.returncode != 0:
                raise RuntimeError(r.stderr.strip()[-300:])
            addrs[nm] = json.loads(r.stdout.strip().splitlines()[-1])['address']
            banguard.assert_allowed(addrs[nm], f'wallet {nm}')
            try:
                rpc_call(gtlib.NETWORKS['mainnet']['daemon'], 'DERO.GetEncryptedBalance', {'address': addrs[nm], 'topoheight': -1})
            except RuntimeError:
                out = register_wallet(run, nm, gw + ['register', '--daemon', gtlib.NETWORKS['mainnet']['daemon'],
                                                     '--pow-threads', str(max(1, a.threads)), '--progress',
                                                     str(run.dir / f'pow_{nm}.json')] + fn, envn, run.dir / f'pow_{nm}.json')
                if out['outcome'] == 'error':
                    raise RuntimeError(out['detail'])
        t0 = time.time()                               # every wallet registered before any miner connects
        while True:
            pending = []
            for nm, ad in addrs.items():
                try:
                    rpc_call(gtlib.NETWORKS['mainnet']['daemon'], 'DERO.GetEncryptedBalance', {'address': ad, 'topoheight': -1})
                except RuntimeError:
                    pending.append(nm)
            if not pending:
                break
            if time.time() - t0 > 3600:
                raise RuntimeError(f'registrations not mined in 1 h: {pending}')
            time.sleep(20)
        run.event('registered', wallets=sorted(addrs))
        if len(names) > 1:
            return rotate(a, run, names, addrs, wdir, gw)
        addr = addrs[names[0]]
        a.wallet = names[0]
        banguard.assert_allowed(addr, f'wallet {a.wallet}')
        daemon = gtlib.NETWORKS['mainnet']['daemon']
        h0 = int(rpc_call(daemon, 'DERO.GetInfo')['height'])
        gtlib.start_proc(run, f'mainnet-miner-{a.wallet}', [str(gtlib.BIN / 'gt-dero-miner'), f'--wallet-address={addr}',
                                                            f"--daemon-rpc-address={gtlib.NETWORKS['mainnet']['getwork']}",
                                                            f'--mining-threads={a.threads}', f'--cpu-max={a.cpu_max}', '--node-rpc-address=off'])
        run.event('mainnet_miner_started', wallet=a.wallet, height=h0, threads=a.threads, cpu_max=a.cpu_max)
        credited, seen, t0 = 0, h0, time.time()
        target = int(a.target_dero * 100000)
        while time.time() - t0 < a.max_hours * 3600:
            time.sleep(60)
            h = int(rpc_call(daemon, 'DERO.GetInfo')['height'])
            for x in range(seen + 1, h - 1):         # settled heights only
                bh = rpc_call(daemon, 'DERO.GetBlock', {'height': x})['block_header']
                ms = bh.get('miners', [])
                credited += sum(int(bh.get('reward', 0)) // 10 for m in (ms[:-1] if len(ms) == 10 else ms) if m == addr)
                seen = x
            bal = gtw('balance', '--daemon', daemon)
            run.event('earn_tick', wallet=a.wallet, height=h, wallet_balance=bal['mature'], chain_credited=credited,
                      minutes=round((time.time() - t0) / 60, 1))
            if bal['mature'] >= target:
                break
        gtlib.stop_proc(run, f'mainnet-miner-{a.wallet}')
        run.event('mainnet_miner_stopped', wallet=a.wallet, chain_credited=credited, minutes=round((time.time() - t0) / 60, 1))
        return 0
    except banguard.BannedAddress as e:
        run.event('banned', error=str(e))
        return 6
    except Exception as e:  # noqa: BLE001
        run.event('error', error=f'{type(e).__name__}: {e}'[:300])
        gtlib.stop_proc(run, f'mainnet-miner-{a.wallet}')
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
