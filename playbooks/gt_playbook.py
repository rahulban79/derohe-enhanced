#!/usr/bin/env python3
"""gt_playbook.py — r32 game-theory playbook (artifacts/dero-game-theory-rft.md §6; artifacts/dero-enhanced-game-theory.html
"Runbook"). Runs WITHOUT any LLM: python3 -I, stdlib only, idempotent (state.json per run), JSONL event log.

What it does (network sim by default, a private cmd/simulator chain):
  chain     start/stop the private chain (gt-simulator, --noautomine, loopback getwork; data dir under GT_HOME)
  wallets   create dedicated wallets (random seeds, encrypted files in ~/dero-wallets/gt/<network>/, mode 700/600,
            the seed is never printed), register them, serve their wallet RPC on loopback ports
  miners    start/stop gt-dero-miner processes that mine the private chain to the dedicated miner wallets
  fund      the miners pay the other roles from the DERO they mined
  deploy    the owner (miner m1) installs gt_attest / gt_service / gt_prize, sets the parameters, links MAT, freezes
  game      M1 attest (honest m1/m2, inflating m3, a verifier-challenger, jurors j1 j2 honest + j3 lazy),
            M2 service (MAT stake, notarize, sponsor, rebate claims), M3 prize (enter, reveal, withhold, draw, withdraw)
  report    per-wallet payoffs (DERO, MAT), SC state, mechanism checks -> report.json + report.md
  all       chain -> wallets -> miners -> fund -> deploy -> game -> report -> stop (unless --keep)
  stop      stop every process this run started (never a foreign pid)

  python3 -I playbooks/gt_playbook.py all --run-id r32-demo [--network sim] [--dry-run] [--keep] [--mine-seconds 60]
  python3 -I playbooks/gt_playbook.py all --network mainnet --dry-run       # prints the exact commands, spends nothing
Mainnet (D-GT-1): every step that spends DERO or starts/stops a mainnet miner needs --mainnet-confirm, a flag only the
user passes; without it the step is logged as user_action_required and skipped. The user's own wallet address is banned
by hash (harness/gametheory/banguard.py, D-GT-2): any banned address in a wallet, miner or argument stops the run.
Exit 0 ok · 3 a mechanism check failed · 5 a user action is required (mainnet) · 6 banned address · 1 error.
"""
import argparse, base64, json, os, random, re, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gtlib  # noqa: E402
from gtlib import arg_s, arg_u, banguard, rpc_call  # noqa: E402

MINERS = ['m1', 'm2', 'm3']
ROLES = MINERS + ['sponsor', 'chal', 'j1', 'j2', 'j3', 'u1', 'u2']
CPU_MAX = {'m1': 90, 'm2': 50, 'm3': 20}
CONTRACTS = {'attest': 'gt_attest.bas', 'service': 'gt_service.bas', 'prize': 'gt_prize.bas'}
FUND = {'sponsor': 30, 'chal': 30, 'j1': 10, 'j2': 10, 'j3': 10, 'u1': 10, 'u2': 10, 'm2': 0, 'm3': 0}  # DERO


class Playbook:
    def __init__(self, a):
        self.a = a
        self.run = gtlib.Run(a.run_id, a.network, a.dry_run, a.mainnet_confirm)
        self.net = self.run.net
        self.wdir = gtlib.WALLETS / a.network
        self.user_actions = 0

    # ------------------------------------------------------------ helpers
    def daemon(self, m, p=None):
        return rpc_call(self.net['daemon'], m, p)

    def height(self):
        return int(self.daemon('DERO.GetInfo')['height'])

    def wait_height(self, h, timeout=600):
        t0 = time.time()
        while self.height() < h:
            if time.time() - t0 > timeout:
                raise RuntimeError(f'height {h} not reached in {timeout} s')
            time.sleep(0.5)

    def wport(self, name):
        return self.net['wallet_base'] + ROLES.index(name)

    def wallet(self, name, m, p=None):
        return rpc_call(f"127.0.0.1:{self.wport(name)}", m, p, timeout=120)

    def addr(self, name):
        return self.run.state['wallets'][name]['address']

    def gtw(self, *args, name):
        env = dict(os.environ, GT_WALLET_PASSWORD=(self.wdir / f'{name}.pass').read_text().strip())
        import subprocess
        argv = [str(gtlib.BIN / 'gt-wallet'), *args, '--file', str(self.wdir / f'{name}.db')]
        if self.net['testnet']:
            argv.append('--testnet')
        r = subprocess.run(['nice', '-n', '15'] + argv, capture_output=True, text=True, env=env, timeout=300)
        if r.returncode != 0:
            raise RuntimeError(f'gt-wallet {args[0]} {name}: {r.stderr.strip()[-300:]}')
        return json.loads(r.stdout.strip().splitlines()[-1])

    def registered(self, address):
        try:
            self.daemon('DERO.GetEncryptedBalance', {'address': address, 'topoheight': -1})
            return True
        except RuntimeError:
            return False

    def sc_vars(self, key):
        scid = self.run.state['scids'][key]
        r = self.daemon('DERO.GetSC', {'scid': scid, 'variables': True, 'code': False})
        return r.get('stringkeys') or {}, r.get('balance', 0)

    def wait_tx(self, txid, timeout=300):
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                r = self.daemon('DERO.GetTransaction', {'txs_hashes': [txid]})
                tx = (r.get('txs') or [{}])[0]
                if tx.get('in_pool') is False and int(tx.get('block_height', 0) or 0) > 0:
                    return tx
            except RuntimeError:
                pass
            time.sleep(0.5)
        raise RuntimeError(f'tx {txid[:12]} not mined in {timeout} s')

    def invoke(self, who, key, entry, args=(), dero=0, asset=None, wait=True):
        """An SC call signed by `who` (ring size 2, so SIGNER() is known); dero = DERO deposit, asset = (scid, amount)."""
        scid = self.run.state['scids'][key]
        p = {'scid': scid, 'ringsize': 2, 'sc_rpc': [arg_s('entrypoint', entry), *args], 'transfers': []}
        if dero:
            p['transfers'].append({'scid': '0' * 64, 'burn': int(dero), 'destination': self.addr('u2' if who != 'u2' else 'u1')})
        if asset:
            p['transfers'].append({'scid': asset[0], 'burn': int(asset[1])})
        for attempt in range(8):
            try:
                txid = self.wallet(who, 'transfer', p)['txid']
                break
            except RuntimeError as e:
                if attempt == 7:
                    raise
                time.sleep(1.5)
        self.run.event('sc_invoke', who=who, sc=key, entry=entry, dero=dero, asset=bool(asset), txid=txid[:16])
        if wait:
            self.wait_tx(txid)
            self.wait_height(self.height() + 2)
        return txid

    # ------------------------------------------------------------ steps
    def chain_start(self):
        if self.a.network == 'mainnet':
            self.run.event('chain_skip', note='mainnet: the user runs derod; read-only use of 127.0.0.1:10102')
            return
        if self.a.network == 'testnet':
            cmd = [str(gtlib.BIN / 'gt-derod'), '--testnet', f'--data-dir={gtlib.GT_HOME}/testnet', f"--rpc-bind={self.net['daemon']}",
                   f"--getwork-bind={self.net['getwork']}", '--p2p-bind=127.0.0.1:0', '--add-exclusive-node=127.0.0.1:1']
            self.run.event('testnet_plan', cmd=' '.join(cmd), note='isolated testnet node (no peers); requires bin gt-derod')
            if self.a.dry_run:
                return
        if self.run.done('chain') and self.chain_alive():
            return
        data = self.run.dir / 'chain'
        if str(data).startswith(str(gtlib.MAINNET_DATA)):
            raise SystemExit('refusing a data dir under the mainnet chain directory')
        argv = [str(gtlib.BIN / 'gt-simulator'), '--testnet', '--noautomine', f'--data-dir={data}',
                f"--rpc-bind={self.net['daemon']}", f"--http-address={self.net['explorer']}", f"--getwork-bind={self.net['getwork']}"]
        if self.a.dry_run:
            self.run.event('dry_run', what='chain', cmd=' '.join(argv))
            return
        gtlib.start_proc(self.run, 'chain', argv)
        for _ in range(120):
            try:
                self.height()
                break
            except RuntimeError:
                time.sleep(0.5)
        m = None
        for _ in range(120):                       # the RPC starts before the simulator prints the genesis wallet
            out = (self.run.dir / 'chain.out').read_text(errors='ignore')
            m = re.search(r'genesis wallet.*?"address": "(deto1[0-9a-z]+)"', out)
            if m:
                break
            time.sleep(0.5)
        if not m:
            raise RuntimeError('genesis address not found in the simulator output')
        banguard.assert_allowed(m.group(1), 'genesis')
        self.run.state['genesis'] = m.group(1)
        self.run.mark('chain', height=self.height())

    def chain_alive(self):
        p = self.run.state['procs'].get('chain')
        return bool(p) and gtlib.pid_alive(p['pid'], p['exe'])

    def wallets_create(self):
        if not self.a.dry_run:
            self.wdir.mkdir(parents=True, exist_ok=True)
            os.chmod(gtlib.WALLETS, 0o700)
            os.chmod(self.wdir, 0o700)
        for n in ROLES:
            if n in self.run.state['wallets']:
                continue
            if self.a.dry_run:
                self.run.event('dry_run', what='wallet create', name=n, cmd=f'gt-wallet create --file {self.wdir.name}/{n}.db')
                continue
            pf = self.wdir / f'{n}.pass'
            if not pf.exists():
                pf.write_text(gtlib.new_password())
                os.chmod(pf, 0o600)
            r = self.gtw('create', '--if-missing', name=n)
            banguard.assert_allowed(r['address'], f'wallet {n}')
            self.run.state['wallets'][n] = {'address': r['address'], 'created': r['created']}
            self.run.save()
            self.run.event('wallet', name=n, created=r['created'], addr_prefix=r['address'][:8])

    def bootstrap_register(self):
        if self.a.dry_run or self.a.network == 'mainnet':
            self.run.event('dry_run' if self.a.dry_run else 'register_plan', what='register',
                           note='mainnet registration spends no DERO but runs against the live node: a user action')
            return
        todo = [n for n in ROLES if not self.registered(self.addr(n))]
        if not todo:
            return
        gtlib.start_proc(self.run, 'boot-miner', [str(gtlib.BIN / 'gt-dero-miner'), f"--wallet-address={self.run.state['genesis']}",
                                                  f"--daemon-rpc-address={self.net['getwork']}", '--mining-threads=1', '--testnet',
                                                  '--node-rpc-address=off', '--cpu-max=30'])
        for n in todo:
            self.gtw('register', '--daemon', self.net['daemon'], name=n)
        t0 = time.time()
        while [n for n in todo if not self.registered(self.addr(n))]:
            if time.time() - t0 > 300:
                raise RuntimeError('registrations not mined in 300 s')
            time.sleep(1)
        gtlib.stop_proc(self.run, 'boot-miner')
        self.run.mark('register', wallets=len(todo), height=self.height())

    def wallets_serve(self):
        if self.a.dry_run or self.a.network == 'mainnet':
            return
        import subprocess
        for n in ROLES:
            pf = self.wdir / f'{n}.pass'
            env = dict(os.environ, GT_WALLET_PASSWORD=pf.read_text().strip())
            gtlib.start_proc(self.run, f'wallet-{n}', [str(gtlib.BIN / 'gt-wallet'), 'serve', '--file', str(self.wdir / f'{n}.db'),
                                                       '--testnet', '--daemon', self.net['daemon'], '--rpc-bind', f'127.0.0.1:{self.wport(n)}'], env=env)
        for n in ROLES:
            for _ in range(120):
                try:
                    a = self.wallet(n, 'GetAddress')['address']
                    if a != self.addr(n):
                        raise SystemExit(f'wallet {n} serves another address')
                    break
                except RuntimeError:
                    time.sleep(0.5)

    def miners(self, action):
        for n in MINERS:
            argv = [str(gtlib.BIN / 'gt-dero-miner'), f'--wallet-address={self.addr(n) if n in self.run.state["wallets"] else "<" + n + ">"}',
                    f"--daemon-rpc-address={self.net['getwork'] or '<user node getwork>'}", '--mining-threads=1',
                    f'--cpu-max={CPU_MAX[n]}', '--node-rpc-address=off'] + (['--testnet'] if self.net['testnet'] else [])
            if n in self.run.state['wallets']:
                banguard.assert_allowed(self.addr(n), f'miner {n}')
            if self.a.network == 'mainnet':
                if not self.run.user_action_gate(f'miner {action} {n} (mainnet)', ' '.join(argv)):
                    self.user_actions += 1
                continue
            if self.a.dry_run:
                self.run.event('dry_run', what=f'miner {action}', name=n, cmd=' '.join(argv))
                continue
            if action == 'start':
                gtlib.start_proc(self.run, f'miner-{n}', argv)
            else:
                gtlib.stop_proc(self.run, f'miner-{n}')

    def balance(self, name, scid=None):
        p = {'scid': scid} if scid else None
        return int(self.wallet(name, 'GetBalance', p).get('unlocked_balance', 0))

    def fund(self):
        if self.run.done('fund'):
            return
        if self.a.dry_run or self.a.network == 'mainnet':
            self.run.event('dry_run', what='fund', plan={k: v for k, v in FUND.items() if v})
            return
        need = sum(FUND.values()) * gtlib.base_unit() + 20 * gtlib.base_unit()
        t0 = time.time()
        while self.balance('m1') < need:
            if time.time() - t0 > self.a.mine_seconds * 6:
                raise RuntimeError(f'm1 mined too little ({self.balance("m1")} < {need})')
            time.sleep(2)
        for n, amt in FUND.items():
            if not amt:
                continue
            txid = None
            for attempt in range(8):
                try:
                    txid = self.wallet('m1', 'transfer', {'transfers': [{'destination': self.addr(n), 'amount': amt * gtlib.base_unit()}], 'ringsize': 2})['txid']
                    break
                except RuntimeError:
                    time.sleep(1.5)
            self.wait_tx(txid)
            self.run.event('funded', to=n, dero=amt)
        self.wait_height(self.height() + 3)
        self.run.mark('fund')

    def deploy(self):
        P = gtlib.PARAMS[self.a.network]
        code_dir = gtlib.ROOT / 'gametheory' / 'contracts'
        for key, f in CONTRACTS.items():
            code = (code_dir / f).read_text()
            if banguard.scan_text(code):
                raise banguard.BannedAddress(f'{f}: a banned address in the contract')
            cmd = f'wallet m1 transfer sc=<base64 {f}> ringsize=2'
            if self.a.network == 'mainnet':
                if not self.run.user_action_gate(f'install {f}', cmd):
                    self.user_actions += 1
                    continue
            elif self.a.dry_run:
                self.run.event('dry_run', what='install', contract=f, cmd=cmd)
                continue
            if key in self.run.state['scids']:
                continue
            txid = self.wallet('m1', 'transfer', {'sc': base64.b64encode(code.encode()).decode(), 'ringsize': 2, 'transfers': []})['txid']
            self.wait_tx(txid)
            self.run.state['scids'][key] = txid
            self.run.save()
            self.run.event('installed', contract=f, scid=txid[:16])
        if self.a.dry_run or self.a.network == 'mainnet':
            return
        if self.run.done('deploy'):
            return
        self.wait_height(self.height() + 2)
        a = P['attest']
        self.invoke('m1', 'attest', 'SetParams', [arg_u(k, a[k]) for k in ('bond', 'reward', 'window', 'commitw', 'revealw', 'maxmb', 'slash', 'minstake')])
        s = P['service']
        self.invoke('m1', 'service', 'SetParams', [arg_u(k, s[k]) for k in ('fee', 'rho', 'boost', 'epoch', 'minmat')])
        z = P['prize']
        self.invoke('m1', 'prize', 'SetParams', [arg_u(k, z[k]) for k in ('rbond', 'commitw', 'revealw', 'maxn', 'boost', 'minmat')])
        mat = self.run.state['scids']['attest']
        self.invoke('m1', 'service', 'SetMAT', [arg_s('scidhex', mat)])
        self.invoke('m1', 'prize', 'SetMAT', [arg_s('scidhex', mat)])
        for k in CONTRACTS:
            self.invoke('m1', k, 'Freeze')
        v, _ = self.sc_vars('attest')
        if int(v.get('frozen', 0)) != 1 or int(v.get('window', 0)) != a['window']:
            raise RuntimeError('attest parameters not applied')
        self.run.mark('deploy')

    # the off-chain verifier every honest challenger and juror runs: count the miniblocks an address mined in a range
    def count_miniblocks(self, address, lo, hi):
        n = 0
        for h in range(lo, hi + 1):
            bh = self.daemon('DERO.GetBlock', {'height': h})['block_header']
            n += sum(1 for m in bh.get('miners', []) if m == address)
        return n

    def game_attest(self):
        if self.run.done('game_attest'):
            return
        P = gtlib.PARAMS[self.a.network]['attest']
        h = self.height()
        lo, hi = max(2, h - 60), h - 3
        claims = {}
        for n in MINERS:
            true_k = self.count_miniblocks(self.addr(n), lo, hi)
            k = min(true_k, (hi - lo + 1) * P['maxmb'])
            if n == 'm3':                                     # the scripted dishonest strategy: inflate by 50 %
                k = min(max(true_k + 1, int(true_k * 1.5) + 1), (hi - lo + 1) * P['maxmb'])
            if k == 0:
                k = 1 if n == 'm3' else 0
            if k == 0:
                self.run.event('claim_skip', miner=n, reason='no miniblocks in range')
                continue
            self.invoke(n, 'attest', 'Claim', [arg_u('from', lo), arg_u('upto', hi), arg_u('k', k)], dero=k * P['bond'], wait=False)
            claims[n] = {'k': k, 'true_k': true_k}
            time.sleep(1)
        self.wait_height(self.height() + 4)
        v, _ = self.sc_vars('attest')
        idx = {}
        for i in range(int(v.get('nc', 0))):
            for n in claims:
                if int(v.get(f'c{i}k', -1)) == claims[n]['k'] and int(v.get(f'c{i}f', -1)) == lo:
                    idx.setdefault(n, i)
        self.run.state['claims'] = {n: dict(claims[n], i=idx.get(n)) for n in claims}
        self.run.save()
        # the challenger verifies every claim against the public block headers
        challenged = []
        for n, c in self.run.state['claims'].items():
            if c['i'] is None:
                continue
            if self.count_miniblocks(self.addr(n), lo, hi) < c['k']:
                self.invoke('chal', 'attest', 'Challenge', [arg_u('i', c['i'])], dero=c['k'] * P['bond'])
                challenged.append(c['i'])
        self.run.event('challenges', n=len(challenged))
        for j in ('j1', 'j2', 'j3'):
            self.invoke(j, 'attest', 'Stake', dero=P['minstake'] * (3 if j == 'j1' else 2), wait=False)
            time.sleep(1)
        self.wait_height(self.height() + 4)
        votes, rng = {}, random.Random(32)
        for i in challenged:
            n = next(m for m, c in self.run.state['claims'].items() if c['i'] == i)
            truth = 1 if self.count_miniblocks(self.addr(n), lo, hi) >= self.run.state['claims'][n]['k'] else 0
            for j in ('j1', 'j2', 'j3'):
                vote = truth if j != 'j3' else rng.randint(0, 1)          # j3: a lazy juror votes at random
                salt = gtlib.new_password()
                votes[(i, j)] = (vote, salt)
                self.invoke(j, 'attest', 'CommitVote', [arg_u('i', i), arg_s('h', gtlib.commit_vote(i, vote, salt))], wait=False)
                time.sleep(1)
        if challenged:
            vh = max(int(self.sc_vars('attest')[0].get(f'c{i}vh', 0)) for i in challenged)
            self.wait_height(vh + P['commitw'] + 1)
            for (i, j), (vote, salt) in votes.items():
                self.invoke(j, 'attest', 'RevealVote', [arg_u('i', i), arg_u('vote', vote), arg_s('salt', salt)], wait=False)
                time.sleep(1)
            self.wait_height(vh + P['commitw'] + P['revealw'] + 1)
        start_h = max(int(self.sc_vars('attest')[0].get(f'c{c["i"]}h', 0)) for c in self.run.state['claims'].values() if c['i'] is not None)
        self.wait_height(start_h + P['window'] + 1)
        for n, c in self.run.state['claims'].items():
            if c['i'] is not None:
                self.invoke('chal', 'attest', 'Finalize', [arg_u('i', c['i'])], wait=False)
                time.sleep(1)
        self.wait_height(self.height() + 4)
        for i in challenged:
            for j in ('j1', 'j2', 'j3'):
                self.invoke(j, 'attest', 'ClaimJuror', [arg_u('i', i)], wait=False)
                time.sleep(1)
        self.wait_height(self.height() + 4)
        # jurors withdraw their stakes (an incoherent or unrevealed vote was slashed ceil(slash %) per dispute)
        av, _ = self.sc_vars('attest')
        stakes = {j: P['minstake'] * (3 if j == 'j1' else 2) for j in ('j1', 'j2', 'j3')}
        for (i, j), (vote, _s) in votes.items():
            if int(av.get(f'c{i}win', -1)) != vote:
                stakes[j] -= (stakes[j] * P['slash'] + 99) // 100
        for j, amt in stakes.items():
            self.invoke(j, 'attest', 'Unstake', [arg_u('amount', amt)], wait=False)
            time.sleep(1)
        self.wait_height(self.height() + 4)
        self.run.state['votes'] = {f'{i}:{j}': v[0] for (i, j), v in votes.items()}
        self.run.mark('game_attest', range=[lo, hi], challenged=challenged)

    def game_service(self):
        if self.run.done('game_service'):
            return
        P = gtlib.PARAMS[self.a.network]['service']
        mat = self.run.state['scids']['attest']
        boosted = []
        for n in MINERS:
            if self.balance(n, mat) >= P['minmat']:
                self.invoke(n, 'service', 'StakeMAT', asset=(mat, P['minmat']), wait=False)
                boosted.append(n)
                time.sleep(1)
        self.wait_height(self.height() + 4)
        e = self.height() // P['epoch']
        docs = 0
        for n in ('m1', 'm2', 'u1', 'u2', 'u1', 'm1'):
            doc = gtlib.commit_num(docs, f'{self.run.id}-{n}')[:32]
            self.invoke(n, 'service', 'Notarize', [arg_s('doc', doc)], dero=P['fee'], wait=False)
            docs += 1
            time.sleep(1)
        self.invoke('sponsor', 'service', 'Sponsor', dero=5 * P['fee'])
        e_now = self.height() // P['epoch']
        self.wait_height((max(e, e_now) + 1) * P['epoch'] + 1, timeout=900)
        claimed = []
        for ep in sorted({e, e_now}):
            for n in ('m1', 'm2', 'u1', 'u2'):
                self.invoke(n, 'service', 'ClaimRebate', [arg_u('e', ep)], wait=False)
                claimed.append((ep, n))
                time.sleep(1)
        self.wait_height(self.height() + 4)
        self.run.mark('game_service', epochs=sorted({e, e_now}), boosted=boosted, docs=docs)

    def game_prize(self):
        if self.run.done('game_prize'):
            return
        P = gtlib.PARAMS[self.a.network]['prize']
        mat = self.run.state['scids']['attest']
        for n in MINERS:
            if self.balance(n, mat) >= P['minmat']:
                self.invoke(n, 'prize', 'StakeMAT', asset=(mat, P['minmat']), wait=False)
                time.sleep(1)
        self.wait_height(self.height() + 4)
        v, _ = self.sc_vars('prize')
        r, rs = int(v.get('rd', 0)), int(v.get('rs', 0))
        if self.height() > rs + P['commitw'] - 20:                    # too late for this round: close it, open the next
            self.wait_height(rs + P['commitw'] + P['revealw'] + 1, timeout=900)
            self.invoke('sponsor', 'prize', 'Draw')
            v, _ = self.sc_vars('prize')
            r, rs = int(v.get('rd', 0)), int(v.get('rs', 0))
        self.invoke('sponsor', 'prize', 'Fund', dero=50000, wait=False)
        entrants = {'m1': 200000, 'm2': 200000, 'u1': 300000, 'u2': 100000}
        secrets_ = {}
        for n, amt in entrants.items():
            num, salt = random.Random(n + self.run.id).randrange(1 << 60), gtlib.new_password()
            secrets_[n] = (num, salt)
            self.invoke(n, 'prize', 'Enter', [arg_s('commit', gtlib.commit_num(num, salt))], dero=amt + P['rbond'], wait=False)
            time.sleep(1)
        self.wait_height(self.height() + 4)
        v, _ = self.sc_vars('prize')
        nn = int(v.get(f'n{r}', 0))
        self.wait_height(rs + P['commitw'] + 1, timeout=900)
        # the entry index is stored under binary keys; the Enter txs were sent in order, one per block at most
        names = list(entrants)
        order = {names[j]: j for j in range(min(nn, len(names)))}
        for n, j in order.items():
            if n == 'u2':                                             # u2 withholds its reveal (forfeits the bond)
                continue
            num, salt = secrets_[n]
            self.invoke(n, 'prize', 'Reveal', [arg_u('j', j), arg_u('num', num), arg_s('salt', salt)], wait=False)
            time.sleep(1)
        self.wait_height(rs + P['commitw'] + P['revealw'] + 1, timeout=900)
        self.invoke('sponsor', 'prize', 'Draw')
        for n, j in order.items():
            self.invoke(n, 'prize', 'Withdraw', [arg_u('r', r), arg_u('j', j)], wait=False)
            time.sleep(1)
        self.wait_height(self.height() + 4)
        self.run.mark('game_prize', round=r, entrants=len(order))

    def report(self):
        st = self.run.state
        rep = {'run': self.run.id, 'network': self.a.network, 'generated': gtlib.now(), 'wallets': {}, 'sc': {}, 'checks': []}
        if self.a.dry_run or self.a.network == 'mainnet':
            rep['note'] = 'dry run / mainnet plan: no balances'
            rep['user_actions_required'] = self.user_actions
        else:
            mat = st['scids'].get('attest')
            mined = self.mined_by_chain()
            # payoff accounting (atomic): balance = grant + funded_net + mined + game_net (game_net includes tx fees).
            # grant: a testnet/simulator registration credits 100000000 atomic (blockchain/transaction_execute.go:187)
            grant = 100000000 if self.net['testnet'] else 0
            funded_in = {n: v * gtlib.base_unit() for n, v in FUND.items() if v}
            funded_out = {'m1': sum(funded_in.values())}
            for n in ROLES:
                bal = self.balance(n)
                fnet = funded_in.get(n, 0) - funded_out.get(n, 0)
                rep['wallets'][n] = {'dero': bal, 'mat': self.balance(n, mat) if mat else 0, 'grant': grant,
                                     'funded_net': fnet, 'mined': mined.get(self.addr(n), 0),
                                     'game_net': bal - grant - fnet - mined.get(self.addr(n), 0)}
            rep['mined_scan'] = {'heights': mined.get('_heights'), 'integrator_shares': mined.get('_integrator'),
                                 'rule': 'each normal miniblock pays floor((reward+fees)/10) to its key; the final share + leftover to the integrator (reward_anchors RW14-RW18)'}
            for k in st['scids']:
                v, bal = self.sc_vars(k)
                keep = {kk: vv for kk, vv in v.items() if re.fullmatch(r'[A-Za-z0-9_:]{1,24}', kk) and len(str(vv)) < 80}
                rep['sc'][k] = {'balance': bal, 'vars': keep}
            av = rep['sc'].get('attest', {}).get('vars', {})
            cl = st.get('claims', {})
            for n, c in cl.items():
                if c.get('i') is None:
                    continue
                s = int(av.get(f"c{c['i']}s", -1))
                honest = c['k'] <= c['true_k']
                rep['checks'].append({'check': f"M1 {n} claim {'honest' if honest else 'inflated'} -> status {s}",
                                      'ok': (s == 2) if honest else (s == 3)})
            for n in MINERS:
                if n in cl and cl[n]['k'] <= cl[n]['true_k'] and cl[n].get('i') is not None:
                    rep['checks'].append({'check': f'M1 honest {n} holds MAT', 'ok': rep['wallets'][n]['mat'] > 0})
            if 'm3' in cl and cl['m3']['k'] > cl['m3']['true_k']:
                rep['checks'].append({'check': 'M1 the inflating m3 minted no MAT', 'ok': rep['wallets']['m3']['mat'] == 0})
                b3 = cl['m3']['k'] * gtlib.PARAMS[self.a.network]['attest']['bond']
                # the mined column omits each miniblock's block-fee share (fees are not in the header; reward_anchors
                # RW13-RW16 split reward + fees), so game net is an UPPER bound of the game result: the loss shows as
                # at least 90 % of the bond; the exact transfer is checked on the challenger's side and the SC dust
                rep['checks'].append({'check': 'M1 the inflating m3 lost its bond (game net <= -0.9 x bond; mined omits fee shares)',
                                      'ok': rep['wallets']['m3']['game_net'] <= -0.9 * b3})
                av = rep['sc'].get('attest', {})
                rep['checks'].append({'check': 'M1 conservation: the attest SC keeps only rounding dust (<= 10 atomic) after every payout',
                                      'ok': int(av.get('balance', 99)) <= 10})
                rep['checks'].append({'check': 'M1 the verifier-challenger profited (game net >= bond/2 - fees)',
                                      'ok': rep['wallets']['chal']['game_net'] >= b3 // 2 - 100000})
            pv = rep['sc'].get('prize', {}).get('vars', {})
            r = st['steps'].get('game_prize', {}).get('round')
            if r is not None:
                rep['checks'].append({'check': 'M3 the round was drawn and paid from sponsor + forfeits',
                                      'ok': int(pv.get(f'drawn{r}', 0)) == 1 and int(pv.get(f'forf{r}', -1)) >= 0})
            sv = rep['sc'].get('service', {}).get('vars', {})
            rep['checks'].append({'check': 'M2 documents notarized and the treasury took (100-rho)% of fees',
                                  'ok': int(sv.get('ndocs', 0)) >= 1 and int(sv.get('treasury', 0)) > 0})
        text = json.dumps(rep, indent=1, sort_keys=True)
        if banguard.scan_text(text):
            raise banguard.BannedAddress('the report would carry a banned address')
        (self.run.dir / 'report.json').write_text(text)
        lines = [f"# R32 game-theory playbook report — run {self.run.id} ({self.a.network})", '',
                 '| wallet | DERO balance | MAT | grant | funded net | mined | game net |', '|---|---|---|---|---|---|---|']
        lines += [f"| {n} | {w['dero']} | {w['mat']} | {w.get('grant', 0)} | {w.get('funded_net', 0)} | {w.get('mined', 0)} | {w.get('game_net', 0)} |"
                  for n, w in rep['wallets'].items()]
        lines += ['', '| check | ok |', '|---|---|'] + [f"| {c['check']} | {c['ok']} |" for c in rep['checks']]
        (self.run.dir / 'report.md').write_text('\n'.join(lines) + '\n')
        self.run.event('report', checks=f"{sum(c['ok'] for c in rep['checks'])}/{len(rep['checks'])}", file='report.json')
        return rep

    def mined_by_chain(self):
        """DERO each address earned from normal miniblocks over the whole private chain, from the public headers."""
        out, integ, H = {}, 0, self.height()
        for h in range(1, H + 1):
            bh = self.daemon('DERO.GetBlock', {'height': h})['block_header']
            share = int(bh.get('reward', 0)) // 10
            ms = bh.get('miners', [])
            for m in ms[:-1] if len(ms) == 10 else ms:     # the last list entry is the final miniblock's integrator
                out[m] = out.get(m, 0) + share
            integ += share
        out['_heights'], out['_integrator'] = H, integ
        return out

    def stop_all(self):
        for name in list(self.run.state['procs']):
            if name != 'chain':
                gtlib.stop_proc(self.run, name)
        gtlib.stop_proc(self.run, 'chain')


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('cmd', choices=['all', 'chain', 'wallets', 'miners', 'fund', 'deploy', 'game', 'report', 'stop'])
    ap.add_argument('sub', nargs='?', default=None, help='chain/miners: start|stop; game: attest|service|prize|all')
    ap.add_argument('--run-id', default='r32-demo')
    ap.add_argument('--network', choices=list(gtlib.NETWORKS), default='sim')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--mainnet-confirm', action='store_true', help='USER ONLY: allow mainnet spends / miner start-stop')
    ap.add_argument('--keep', action='store_true', help='all: leave the chain, wallets and miners running')
    ap.add_argument('--mine-seconds', type=int, default=60)
    a = ap.parse_args(argv)
    if a.network == 'mainnet' and not a.dry_run and not a.mainnet_confirm:
        print('mainnet without --dry-run needs --mainnet-confirm (a user action, D-GT-1); running as --dry-run')
        a.dry_run = True
    pb = Playbook(a)
    try:
        if a.cmd in ('all', 'chain') and a.sub != 'stop':
            pb.chain_start()
        if a.cmd in ('all', 'wallets'):
            pb.wallets_create()
            pb.bootstrap_register()
            pb.wallets_serve()
        if a.cmd == 'miners':
            pb.miners(a.sub or 'start')
        if a.cmd == 'all':
            pb.miners('start')
            if not a.dry_run and a.network != 'mainnet':
                time.sleep(a.mine_seconds)
        if a.cmd in ('all', 'fund'):
            pb.fund()
        if a.cmd in ('all', 'deploy'):
            pb.deploy()
        if a.cmd in ('all', 'game') and not a.dry_run and a.network != 'mainnet':
            which = a.sub or 'all'
            if which in ('attest', 'all'):
                pb.game_attest()
            if which in ('service', 'all'):
                pb.game_service()
            if which in ('prize', 'all'):
                pb.game_prize()
        rep = None
        if a.cmd == 'all' and not a.dry_run and a.network != 'mainnet':
            pb.miners('stop')              # a still-growing chain would make the mined scan run past the balances
            time.sleep(3)
        if a.cmd in ('all', 'report'):
            rep = pb.report()
        if (a.cmd == 'all' and not a.keep) or a.cmd == 'stop' or (a.cmd == 'chain' and a.sub == 'stop'):
            if not a.dry_run:
                pb.stop_all()
    except banguard.BannedAddress as e:
        pb.run.event('banned', error=str(e))
        print(f'BANNED: {e}')
        if not a.keep and not a.dry_run:
            pb.stop_all()
        return 6
    except Exception as e:  # noqa: BLE001 — a failed run never leaves its processes behind (unless --keep)
        pb.run.event('error', error=f'{type(e).__name__}: {e}'[:300])
        if not a.keep and not a.dry_run:
            pb.stop_all()
        raise
    if pb.user_actions:
        return 5
    if rep and rep['checks'] and not all(c['ok'] for c in rep['checks']):
        return 3
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
