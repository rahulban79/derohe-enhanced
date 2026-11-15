#!/usr/bin/env python3
"""gt_cycle.py — r32 GT-B9 (artifacts/dero-game-theory-rft.md D-GT-5/6/7; gate G36): ONE full game-theory cycle between
two funded wallets, measured. No LLM; python3 -I; stdlib only.

  mainnet (the real path; every step needs --mainnet-confirm, the user's D-GT-4 authorisation):
    python3 -I playbooks/gt_cycle.py --network mainnet --wallets m1,m2 --mainnet-confirm [--fast]
  pre-flight on the sim chain (a chain + registered wallets from `gt_playbook.py ... --keep`):
    python3 -I playbooks/gt_cycle.py --network sim --run-id <sim run> --wallets m1,m2 [--fast]

Steps (each logged to <GT_HOME>/runs/<run>/events.jsonl; the cycle record without addresses or SCIDs goes to
harness/runtime/gt_mainnet_cycle.json on mainnet, harness/runtime/gt_cycle_sim.json on the sim):
  1 serve both wallets' RPC on loopback; read the starting balances; require each >= the sizing target
    (harness/runtime/gt_sizing_last.json, D-GT-7) on mainnet
  2 deploy gt_attest, gt_service, gt_prize from the first wallet (ring size 2: it is the owner); set the network's
    parameters (--fast: short windows for a first measured cycle: 20 blocks, epoch 40); link MAT; freeze
  3 M1: the first wallet claims k miniblocks it really mined in a past range (counted from the chain), unchallenged,
    finalized after the window -> MAT minted
  4 M3: both enter one prize round (principal + reveal bond), both reveal, draw, both withdraw
  5 M2: both notarize a digest, the first sponsors, after the epoch both claim the rebate
  6 measure: each tx's fee from the wallet balance before/after (minus its deposit), payoffs per wallet (DERO, MAT),
    gas per entrypoint from the DVM census, timings; write the cycle record
"""
import argparse, base64, datetime, json, os, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gtlib  # noqa: E402
from gtlib import arg_s, arg_u, banguard, rpc_call  # noqa: E402

ROOT = gtlib.ROOT
CONTRACTS = {'attest': 'gt_attest.bas', 'service': 'gt_service.bas', 'prize': 'gt_prize.bas'}
CONFIRM_DEPTH = 3     # blocks below the tip before a tx counts as final (r32 run 8: a tx seen mined was reorged away)
LOST_S = 60           # a tx neither in a valid block nor in the pool for this long is lost and is resent
SEND_TRIES = 3


def game_settled(rounds, players):
    """G36 step game_settled: at least one round drawn with a winner AND every player entered (r32 run 9: rounds with
    one entrant only recycle the sponsor's own prize and are not a game)."""
    return any(x.get('drawn') == 1 and x.get('winner_index', -1) >= 0 and int(x.get('entrants', 0)) >= players for x in rounds)


class TxLost(RuntimeError):
    pass


def tx_state(tx, height, depth=CONFIRM_DEPTH):
    """r32 run-8 lesson: 'final' only for a tx in a VALID block at least `depth` below the tip; 'pending' while it is
    in the pool or still shallow; 'lost' when the daemon has it in no valid block and not in the pool (attest Freeze
    6067a385fc44 was reported mined at 08:47, then sat in no main-chain block and in no pool)."""
    if tx.get('in_pool'):
        return 'pending'
    bh = int(tx.get('block_height', 0) or 0)
    if tx.get('valid_block') and bh > 0:
        return 'final' if height - bh >= depth else 'pending'
    return 'lost'


ENTER_MARGIN = 4      # blocks before the commit window closes: later than this, the round is skipped, not entered


def entry_index(stringkeys, r, commit):
    """the index j the prize contract gave this wallet's entry in round r, found by its own commit (h<r>_<j>); None
    when the Enter was rejected. Parallel Enters land in any order, so j is read back, never assumed."""
    for k, v in (stringkeys or {}).items():
        if k.startswith(f'h{r}_') and v == commit:
            return int(k.split('_', 1)[1])
    return None


def claim_index(nc_before, nc_after):
    """the claim index a successful Claim created; a reverted Claim (nc unchanged) fails closed instead of driving
    Finalize(i = nc - 1 = -1)."""
    if int(nc_after) != int(nc_before) + 1:
        raise RuntimeError(f'postcondition: Claim reverted (nc {nc_before} -> {nc_after})')
    return int(nc_before)


def setup_needed(stringkeys):
    """a contract already frozen takes no SetParams/SetMAT/Freeze (each would revert and only burn its fee)."""
    return int((stringkeys or {}).get('frozen', 0) or 0) == 0


class Cycle:
    def __init__(self, a):
        self.a = a
        self.run = gtlib.Run(a.run_id, a.network, dry_run=False, mainnet_confirm=a.mainnet_confirm)
        self.net = gtlib.NETWORKS[a.network]
        self.wdir = gtlib.WALLETS / a.network
        self.names = a.wallets.split(',')
        self.port = {n: self.net['wallet_base'] + 50 + i for i, n in enumerate(self.names)}
        self.addr, self.fees, self.t0 = {}, [], time.time()
        self.pending_w = []      # (wallet, round, j) withdrawals deferred past the next round's entries
        P = gtlib.PARAMS[a.network]
        self.P = {k: dict(v) for k, v in P.items()}
        self.plan = json.loads(Path(a.plan).read_text()).get('plan', {}) if a.plan else {}
        if self.plan:                                   # D-GT-8: the sizing plan sets the stakes
            self.P['attest']['bond'] = self.plan.get('bond', self.P['attest']['bond'])
            self.P['prize']['rbond'] = self.plan.get('rbond', self.P['prize']['rbond'])
            self.P['prize']['boost'] = self.plan.get('boost', self.P['prize']['boost'])
        if a.fast or a.plan:     # D-GT-8: a planned pilot uses short windows (a round ~15 min instead of ~1 h on mainnet)
            self.P['attest'].update(window=20, commitw=10, revealw=10)
            self.P['service'].update(epoch=40)
            self.P['prize'].update(commitw=20, revealw=20)

    def ev(self, kind, **kw):
        rec = self.run.event(kind, **kw)
        # liveness = work: mirror every cycle event into the trigger's event log, which is the stallwatch work file of a
        # trigger-launched cycle (a multi-round game would otherwise look like a stalled trigger)
        if self.a.network == 'mainnet':
            tf = gtlib.GT_HOME / 'runs' / 'r32-mainnet-trigger' / 'events.jsonl'
            if tf.parent.exists():
                with open(tf, 'a') as f:
                    f.write(json.dumps({'ts': rec['ts'], 'kind': 'cycle_progress', 'step': kind}) + '\n')
        return rec

    def daemon(self, m, p=None):
        return rpc_call(self.net['daemon'], m, p)

    def height(self):
        return int(self.daemon('DERO.GetInfo')['height'])

    def wait_height(self, h, timeout=7200):
        t0 = time.time()
        while self.height() < h:
            if time.time() - t0 > timeout:
                raise RuntimeError(f'height {h} not reached')
            time.sleep(3)

    def wallet(self, n, m, p=None):
        return rpc_call(f'127.0.0.1:{self.port[n]}', m, p, timeout=180)

    def balance(self, n, scid=None):
        return int(self.wallet(n, 'GetBalance', {'scid': scid} if scid else None).get('unlocked_balance', 0))

    def wait_tx(self, txid, timeout=1800):
        t0, lost_since = time.time(), None
        while time.time() - t0 < timeout:
            try:
                tx = (self.daemon('DERO.GetTransaction', {'txs_hashes': [txid]}).get('txs') or [{}])[0]
                st = tx_state(tx, self.height())
            except RuntimeError:
                tx, st = None, 'pending'
            if st == 'final':
                return tx
            if st == 'lost':
                lost_since = lost_since or time.time()
                if time.time() - lost_since > LOST_S:
                    raise TxLost(f'tx {txid[:12]} in no valid block and not in the pool for {LOST_S} s')
            else:
                lost_since = None
            time.sleep(2)
        raise RuntimeError(f'tx {txid[:12]} not final')

    def send(self, n, p, what):
        """send one wallet transfer and wait until it is final; a lost tx is resent (SEND_TRIES)."""
        for k in range(SEND_TRIES):
            for i in range(8):
                try:
                    txid = self.wallet(n, 'transfer', p)['txid']
                    break
                except RuntimeError:
                    if i == 7:
                        raise
                    time.sleep(3)
            try:
                self.wait_tx(txid)
                return txid
            except TxLost as e:
                self.ev('tx_lost', who=n, what=what, txid=txid, attempt=k + 1, error=str(e))
                if k == SEND_TRIES - 1:
                    raise

    def other(self, n):
        return self.addr[self.names[1] if n == self.names[0] else self.names[0]]

    def call(self, n, key, entry, args=(), dero=0, asset=None):
        """one SC call, waited for; its fee measured from the wallet balance (before - after - deposit + refund)."""
        scid = self.run.state['scids'][key]
        p = {'scid': scid, 'ringsize': 2, 'sc_rpc': [arg_s('entrypoint', entry), *args], 'transfers': []}
        if dero:
            p['transfers'].append({'scid': '0' * 64, 'burn': int(dero), 'destination': self.other(n)})
        if asset:
            p['transfers'].append({'scid': asset[0], 'burn': int(asset[1])})
        b0 = self.balance(n)
        txid = self.send(n, p, f'{key}.{entry}')
        self.wait_height(self.height() + 2)
        b1 = self.balance(n)
        rec = {'who': n, 'sc': key, 'entry': entry, 'deposit': dero, 'balance_delta': b1 - b0, 'txid_prefix': txid[:12],
               'fee': self.fee_of(n, txid)}   # the fee from the wallet's own transfer entry: valid while mining continues
        self.fees.append(rec)
        self.ev('sc_call', txid=txid, **rec)   # the full txid stays in the local event log only
        return txid

    def fee_of(self, n, txid):
        """the fee the wallet recorded for its own tx (GetTransferbyTXID entry.fees); None when not found yet."""
        for _ in range(20):
            try:
                e = self.wallet(n, 'GetTransferbyTXID', {'txid': txid}).get('entry') or {}
                if e.get('fees') is not None:
                    return int(e['fees'])
            except RuntimeError:
                pass
            time.sleep(2)
        return None

    def vars(self, key):
        r = self.daemon('DERO.GetSC', {'scid': self.run.state['scids'][key], 'variables': True})
        return r.get('stringkeys') or {}, int(r.get('balance', 0))

    # ------------------------------------------------------------------ steps
    def serve(self):
        for n in self.names:
            env = dict(os.environ, GT_WALLET_PASSWORD=(self.wdir / f'{n}.pass').read_text().strip())
            flag = ['--testnet'] if self.net['testnet'] else ['--mainnet-confirm']
            gtlib.start_proc(self.run, f'cycle-wallet-{n}', [str(gtlib.BIN / 'gt-wallet'), 'serve', '--file', str(self.wdir / f'{n}.db'),
                                                             *flag, '--daemon', self.net['daemon'], '--rpc-bind', f'127.0.0.1:{self.port[n]}'], env=env)
        for n in self.names:
            for _ in range(240):
                try:
                    self.addr[n] = self.wallet(n, 'GetAddress')['address']
                    break
                except RuntimeError:
                    time.sleep(1)
            banguard.assert_allowed(self.addr[n], f'wallet {n}')

    def deploy(self):
        m = self.names[0]
        for key, f in CONTRACTS.items():
            if key in self.run.state['scids']:
                continue
            code = (ROOT / 'gametheory/contracts' / f).read_text()
            b0 = self.balance(m)
            txid = self.send(m, {'sc': base64.b64encode(code.encode()).decode(), 'ringsize': 2, 'transfers': []}, f'{key}.install')
            self.wait_height(self.height() + 2)
            self.run.state['scids'][key] = txid
            self.run.save()
            rec = {'who': m, 'sc': key, 'entry': 'install', 'deposit': 0, 'balance_delta': self.balance(m) - b0, 'code_bytes': len(code),
                   'txid_prefix': txid[:12], 'fee': self.fee_of(m, txid)}
            self.fees.append(rec)
            self.ev('installed', contract=f, **{k: v for k, v in rec.items() if k != 'who'})
        a, s, z = self.P['attest'], self.P['service'], self.P['prize']
        todo = {k: setup_needed(self.vars(k)[0]) for k in CONTRACTS}     # a re-run skips contracts already frozen
        self.ev('setup_plan', todo=todo)
        if todo['attest']:
            self.call(m, 'attest', 'SetParams', [arg_u(k, a[k]) for k in ('bond', 'reward', 'window', 'commitw', 'revealw', 'maxmb', 'slash', 'minstake')])
        if todo['service']:
            self.call(m, 'service', 'SetParams', [arg_u(k, s[k]) for k in ('fee', 'rho', 'boost', 'epoch', 'minmat')])
        if todo['prize']:
            self.call(m, 'prize', 'SetParams', [arg_u(k, z[k]) for k in ('rbond', 'commitw', 'revealw', 'maxn', 'boost', 'minmat')])
        mat = self.run.state['scids']['attest']
        if todo['service']:
            self.call(m, 'service', 'SetMAT', [arg_s('scidhex', mat)])
        if todo['prize']:
            self.call(m, 'prize', 'SetMAT', [arg_s('scidhex', mat)])
        for k in CONTRACTS:
            if todo[k]:
                self.call(m, k, 'Freeze')
        bad = [k for k in CONTRACTS if setup_needed(self.vars(k)[0])]
        if bad:
            raise RuntimeError(f'postcondition: not frozen after setup: {bad}')

    def mined_range(self, address, lo, hi):
        k = 0
        for h in range(lo, hi + 1):
            ms = self.daemon('DERO.GetBlock', {'height': h})['block_header'].get('miners', [])
            k += sum(1 for x in (ms[:-1] if len(ms) == 10 else ms) if x == address)
        return k

    def m1_claim(self):
        m, a = self.names[0], self.P['attest']
        h = self.height()
        lo, hi = max(2, h - min(990, a.get('maxspan', 1000) - 10)), h - 3
        k = min(self.mined_range(self.addr[m], lo, hi), (hi - lo + 1) * a['maxmb'], self.plan.get('k', 10**9))
        if k == 0:
            self.ev('m1_skip', reason='no miniblocks of the first wallet in the last 300 heights')
            return None
        nc0 = int(self.vars('attest')[0].get('nc', 0))
        self.call(m, 'attest', 'Claim', [arg_u('from', lo), arg_u('upto', hi), arg_u('k', k)], dero=k * a['bond'])
        v, _ = self.vars('attest')
        i = claim_index(nc0, v.get('nc', 0))
        self.wait_height(int(v.get(f'c{i}h', h)) + a['window'] + 1)
        self.call(self.names[1], 'attest', 'Finalize', [arg_u('i', i)])
        v, _ = self.vars('attest')
        return {'k': k, 'status': int(v.get(f'c{i}s', -1)), 'mat': self.balance(m, self.run.state['scids']['attest'])}

    def par(self, jobs):
        """r32 run-9 lesson: one call per wallet at the same time (independent accounts); calls of ONE wallet stay serial
        because each spends the balance its previous tx left."""
        if not jobs:
            return []
        with ThreadPoolExecutor(max_workers=len(jobs)) as ex:
            return [f.result() for f in [ex.submit(fn) for fn in jobs]]

    def flush_withdraws(self):
        by = {}
        for n, r, j in self.pending_w:
            by.setdefault(n, []).append((r, j))
        self.pending_w = []
        self.par([lambda n=n, L=L: [self.call(n, 'prize', 'Withdraw', [arg_u('r', r), arg_u('j', j)]) for r, j in L]
                  for n, L in by.items()])

    def m3_round(self):
        """r32 run-9 lesson: on 2026-11-15 rounds 3-5 took m2's Enter 21-22 blocks after the Draw, past the 20-block
        commit window, because Withdraw x2, Fund and m1's Enter ran serially first. Now: both Enters in parallel,
        first in the window; then the previous round's Withdraws and the Fund; Reveals in parallel; Draw."""
        z = self.P['prize']
        v, _ = self.vars('prize')
        r, rs = int(v.get('rd', 0)), int(v.get('rs', 0))
        if self.height() > rs + z['commitw'] - ENTER_MARGIN:
            self.wait_height(rs + z['commitw'] + z['revealw'] + 1)
            self.call(self.names[0], 'prize', 'Draw')
            v, _ = self.vars('prize')
            r, rs = int(v.get('rd', 0)), int(v.get('rs', 0))
        principal = self.plan.get('principal', self.a.principal)
        com = {}
        for n in self.names:
            num, salt = int.from_bytes(os.urandom(7), 'big'), gtlib.new_password()
            com[n] = (num, salt, gtlib.commit_num(num, salt))
        self.par([lambda n=n: self.call(n, 'prize', 'Enter', [arg_s('commit', com[n][2])], dero=principal + z['rbond'])
                  for n in self.names])
        v, _ = self.vars('prize')
        idx = {n: entry_index(v, r, com[n][2]) for n in self.names}
        entrants = int(v.get(f'n{r}', 0))
        if entrants < len(self.names) or None in idx.values():
            self.ev('enter_rejected', round=r, entrants=entrants, missing=[n for n in self.names if idx[n] is None],
                    height=self.height(), window_end=rs + z['commitw'])
        self.flush_withdraws()
        self.call(self.names[0], 'prize', 'Fund', dero=self.plan.get('sponsor', self.a.sponsor))
        self.wait_height(rs + z['commitw'] + 1)
        self.par([lambda n=n: self.call(n, 'prize', 'Reveal', [arg_u('j', idx[n]), arg_u('num', com[n][0]), arg_s('salt', com[n][1])])
                  for n in self.names if idx[n] is not None])
        self.wait_height(rs + z['commitw'] + z['revealw'] + 1)
        self.call(self.names[0], 'prize', 'Draw')
        self.pending_w += [(n, r, idx[n]) for n in self.names if idx[n] is not None]
        v, _ = self.vars('prize')
        return {'round': r, 'entrants': entrants, 'entries': {str(j): n for n, j in idx.items() if j is not None},
                'winner_index': int(v.get(f'win{r}', -1)), 'paid': int(v.get(f'paid{r}', 0)),
                'drawn': int(v.get(f'drawn{r}', 0))}

    def m2_epoch(self):
        s = self.P['service']
        e = self.height() // s['epoch']
        for n in self.names:
            self.call(n, 'service', 'Notarize', [arg_s('doc', gtlib.commit_num(time.time_ns(), n)[:32])], dero=s['fee'])
        self.call(self.names[0], 'service', 'Sponsor', dero=s['fee'])
        e2 = self.height() // s['epoch']
        self.wait_height((max(e, e2) + 1) * s['epoch'] + 1)
        for ep in sorted({e, e2}):
            for n in self.names:
                try:
                    self.call(n, 'service', 'ClaimRebate', [arg_u('e', ep)])
                except RuntimeError as x:
                    self.ev('claim_skip', who=n, epoch=ep, error=str(x)[:120])
        v, _ = self.vars('service')
        return {'epochs': sorted({e, e2}), 'docs': int(v.get('ndocs', 0)), 'treasury': int(v.get('treasury', 0))}

    def record(self, start, res):
        end = {n: self.balance(n) for n in self.names}
        mat = self.run.state['scids'].get('attest')
        out = {'network': self.a.network, 'measured_at': gtlib.now(), 'run': self.a.run_id, 'fast': self.a.fast,
               'wallets': self.names, 'start_dero': {n: f'{v / 1e5:.5f}' for n, v in start.items()},
               'end_dero': {n: f'{v / 1e5:.5f}' for n, v in end.items()},
               'payoff_atomic': {n: end[n] - start[n] for n in self.names},
               'mat': {n: self.balance(n, mat) for n in self.names} if mat else {},
               'calls': self.fees, 'results': res, 'wall_s': round(time.time() - self.t0, 1),
               'fees_total_atomic': sum(int(c.get('fee') or 0) for c in self.fees),
               'sc_balances_atomic': {k: self.vars(k)[1] for k in self.run.state['scids']},
               'plan': self.plan,
               'params': self.P}
        text = json.dumps(out, indent=1, sort_keys=True)
        if banguard.scan_text(text):
            raise banguard.BannedAddress('the cycle record would carry a banned address')
        (self.run.dir / 'cycle.json').write_text(text)
        if self.a.network == 'mainnet':
            ev = f'harness/runtime/gt_cycle_mainnet_{datetime.datetime.now().strftime("%Y%m%dT%H%M%S")}.json'
            (ROOT / ev).write_text(text + '\n')
            cyc = json.loads((ROOT / 'harness/runtime/gt_mainnet_cycle.json').read_text())
            st = cyc.setdefault('steps', {})
            for k, ok in (('roles_funded', all(v >= 1 for v in start.values())), ('contract_deployed', len(self.run.state['scids']) == 3),
                          ('game_settled', game_settled(res.get('m3_rounds') or [res.get('m3') or {}], len(self.names)))):
                if ok:
                    st[k] = {'status': 'measured', 'evidence': ev, 'at': out['measured_at']}
            (ROOT / 'harness/runtime/gt_mainnet_cycle.json').write_text(json.dumps(cyc, indent=1) + '\n')
        else:
            (ROOT / 'harness/runtime/gt_cycle_sim.json').write_text(text + '\n')
        self.ev('cycle_record', payoff=out['payoff_atomic'], wall_s=out['wall_s'])
        return out


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--network', choices=['sim', 'mainnet'], default='mainnet')
    ap.add_argument('--run-id', default='r32-mainnet-cycle')
    ap.add_argument('--wallets', default='m1,m2')
    ap.add_argument('--fast', action='store_true')
    ap.add_argument('--principal', type=int, default=100000, help='M3 principal per wallet, atomic (default 1 DERO)')
    ap.add_argument('--sponsor', type=int, default=10000, help='M3 sponsor prize from the first wallet, atomic')
    ap.add_argument('--mainnet-confirm', action='store_true')
    ap.add_argument('--rebuild', action='store_true', help='rebuild a gt-* binary older than its Go sources (else refuse)')
    ap.add_argument('--plan', default=None, help='a sizing plan JSON (harness/runtime/gt_plan_mainnet.json, D-GT-8)')
    ap.add_argument('--with-m2', action='store_true', help='also run the M2 notary epoch (not in the D-GT-8 plan)')
    a = ap.parse_args(argv)
    if a.network == 'mainnet' and not a.mainnet_confirm:
        print('mainnet needs --mainnet-confirm (D-GT-4); nothing done')
        return 5
    c = Cycle(a)
    gtlib.ensure_bins(c.run, ['gt-wallet'], rebuild=a.rebuild)
    try:
        c.serve()
        start = {n: c.balance(n) for n in c.names}
        c.ev('cycle_start', start_dero={n: f'{v / 1e5:.5f}' for n, v in start.items()})
        if a.network == 'mainnet':
            # D-GT-8: mining continues in parallel (fees come from the wallets' transfer entries, not balance deltas);
            # the start threshold is the plan's (1 DERO each by default), else the sizing targets
            need = int((json.loads(Path(a.plan).read_text()).get('threshold_atomic') if a.plan else 0) or 0)
            sz = json.loads((ROOT / 'harness/runtime/gt_sizing_last.json').read_text())
            short = {n: start[n] for n in c.names if start[n] < (need or int(sz['targets_atomic'].get(n, 0)))}
            if short:
                c.ev('cycle_wait', reason='below the sizing target (D-GT-7)', short={k: f'{v / 1e5:.5f}' for k, v in short.items()})
                return 7
        c.deploy()
        res = {'m1': c.m1_claim(), 'm3_rounds': []}
        for _ in range(int(c.plan.get('rounds', 1))):
            res['m3_rounds'].append(c.m3_round())
        res['m3'] = res['m3_rounds'][-1]
        c.flush_withdraws()
        if a.with_m2:
            res['m2'] = c.m2_epoch()
        c.record(start, res)
        return 0
    except banguard.BannedAddress as e:
        c.ev('banned', error=str(e))
        return 6
    except Exception as e:  # noqa: BLE001
        c.ev('error', error=f'{type(e).__name__}: {e}'[:300])
        return 1
    finally:
        for n in c.names:
            gtlib.stop_proc(c.run, f'cycle-wallet-{n}')


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
