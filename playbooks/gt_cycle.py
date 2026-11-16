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
CONTRACTS = {'attest': 'gt_attest.bas', 'service': 'gt_service.bas', 'prize': 'gt_prize.bas', 'audit': 'gt_audit.bas'}   # r32a: + audit
AUDIT_VERDICT_KEYS = ('bounty', 'cin', 'n', 'st', 'nw', 'disp', 'refund', 'share', 'rem', 'forf')   # gt_audit.bas key map
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
WINDOW_CALLS = 4      # a commit / reveal window holds this many confirmed calls (r32a sim pre-flight: a fixed 20 blocks
#                       closed before one confirmed call landed on a chain with ~0.7 s blocks; mainnet ~7 blocks per call)


STORAGE_GAS_FREE = 150   # below this a size-based fee already covers the storage gas (measured fees 226-417 on mainnet)
STORAGE_FEE_FLOOR = 600  # above every measured size-based fee (<= 417), so a set fee never undercuts the pool minimum


def storage_fee(gasstorage):
    """r32a sim pre-flight: the DVM's storage-gas limit IS the tx fee (blockchain/transaction_execute.go:395 passes
    tx.Fees() as gasstorage_incoming; dvm/sc.go:244-250, capped at config.MAX_STORAGE_GAS_ATOMIC_UNITS 20,000), and the
    wallet sizes the fee by tx size, so gt_audit Settle (a small tx with many STOREs) paid 235 and reverted with
    'Insufficient Storage Gas'. The fee is set to the estimate + 30 % + 100 (floor STORAGE_FEE_FLOOR, cap 20,000). Pure."""
    return min(20000, max(STORAGE_FEE_FLOOR, int(gasstorage) * 13 // 10 + 100))


def windows_for(bpc, base=20, calls=WINDOW_CALLS):
    """(window blocks, enter margin) from the measured blocks per confirmed call. Pure."""
    import math as _m
    w = max(base, _m.ceil(calls * max(1.0, bpc)))
    return w, max(ENTER_MARGIN, _m.ceil(bpc) + 2)


def sc_str_eq(v, s):
    """r32a sim pre-flight: DERO.GetSC returns every String variable hex-encoded (fmt.Sprintf("%x", []byte(v)),
    cmd/derod/rpc/rpc_dero_getsc.go:138), so a stored commit reads back as the hex of its ASCII bytes. Pure."""
    return isinstance(v, str) and v == s.encode().hex()


def entry_index(stringkeys, r, commit):
    """the index j the prize contract gave this wallet's entry in round r, found by its own commit (h<r>_<j>); None
    when the Enter was rejected. Parallel Enters land in any order, so j is read back, never assumed."""
    for k, v in (stringkeys or {}).items():
        if k.startswith(f'h{r}_') and sc_str_eq(v, commit):
            return int(k.split('_', 1)[1])
    return None


def entry_index_audit(stringkeys, a, commit):
    """the entrant index j gt_audit gave a commit in round a: the key whose value is that commit, named
    a<a>_<j>_c or a<a>_c<j> (both layouts accepted until the contract's key map is pinned). Pure."""
    import re as _re
    for k, v in (stringkeys or {}).items():
        if not sc_str_eq(v, commit):
            continue
        m = _re.match(rf'^a{a}_(\d+)_c$', k) or _re.match(rf'^a{a}_c(\d+)$', k)
        if m:
            return int(m.group(1))
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
        if self.plan.get('abond'):                      # r32a: the audit bond is frozen for the whole ladder
            self.P['audit']['bond'] = self.plan['abond']
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
                tx = self.wait_tx(txid)
                self.last_bh = int((tx or {}).get('block_height', 0) or 0)   # the inclusion height, kept on the call record
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
        est = self.gas_estimate(n, scid, p)
        if est and est.get('gasstorage', 0) > STORAGE_GAS_FREE:
            p['fees'] = storage_fee(est['gasstorage'])
        b0 = self.balance(n)
        txid = self.send(n, p, f'{key}.{entry}')
        self.wait_height(self.height() + 2)
        b1 = self.balance(n)
        rec = {'who': n, 'sc': key, 'entry': entry, 'deposit': dero, 'balance_delta': b1 - b0, 'txid_prefix': txid[:12],
               'bh': getattr(self, 'last_bh', None), 'gas_est': est, 'fees_set': p.get('fees'),
               'fee': self.fee_of(n, txid)}   # the fee from the wallet's own transfer entry: valid while mining continues
        self.fees.append(rec)
        self.ev('sc_call', txid=txid, **rec)   # the full txid stays in the local event log only
        return txid

    def gas_estimate(self, n, scid, p):
        """DERO.GetGasEstimate for one SC call as signer n (read-only; the daemon runs it on a state snapshot). The
        handler runs SC_RPC as given, so the SC_ACTION / SC_ID arguments the wallet would add are added here
        (rpc/rpc_sc.go: SC_CALL = 0). None when the estimate fails (logged; the call goes ahead unchanged)."""
        q = {'sc_rpc': [{'name': 'SC_ACTION', 'datatype': 'U', 'value': 0}, {'name': 'SC_ID', 'datatype': 'H', 'value': scid}]
                       + list(p['sc_rpc']), 'transfers': p['transfers'], 'signer': self.addr[n]}
        try:
            r = self.daemon('DERO.GetGasEstimate', q)
            return {'gascompute': int(r.get('gascompute', 0)), 'gasstorage': int(r.get('gasstorage', 0))}
        except RuntimeError as e:
            self.ev('gas_estimate_failed', who=n, error=str(e)[:200])
            return None

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
            h_send = self.height()
            txid = self.send(m, {'sc': base64.b64encode(code.encode()).decode(), 'ringsize': 2, 'transfers': []}, f'{key}.install')
            self.run.state.setdefault('bpc_samples', []).append(self.height() - h_send)   # blocks per confirmed call
            self.wait_height(self.height() + 2)
            self.run.state['scids'][key] = txid
            self.run.save()
            rec = {'who': m, 'sc': key, 'entry': 'install', 'deposit': 0, 'balance_delta': self.balance(m) - b0, 'code_bytes': len(code),
                   'txid_prefix': txid[:12], 'fee': self.fee_of(m, txid)}
            self.fees.append(rec)
            self.ev('installed', contract=f, **{k: v for k, v in rec.items() if k != 'who'})
        smp = self.run.state.get('bpc_samples') or []
        if smp and 'windows' not in self.run.state:     # sized once, before the parameters are frozen for the ladder
            bpc = sorted(smp)[len(smp) // 2]
            w, mg = windows_for(bpc)
            self.run.state['windows'] = {'bpc': bpc, 'window': w, 'margin': mg}
            self.run.save()
            self.ev('windows_sized', bpc=bpc, window=w, margin=mg)
        ws = self.run.state.get('windows')
        if ws:
            self.P['prize'].update(commitw=ws['window'], revealw=ws['window'])
            self.P['audit'].update(commitw=ws['window'], revealw=ws['window'])
        a, s, z, u = self.P['attest'], self.P['service'], self.P['prize'], self.P['audit']
        todo = {k: setup_needed(self.vars(k)[0]) for k in CONTRACTS}     # a re-run skips contracts already frozen
        self.ev('setup_plan', todo=todo)
        if todo['attest']:
            self.call(m, 'attest', 'SetParams', [arg_u(k, a[k]) for k in ('bond', 'reward', 'window', 'commitw', 'revealw', 'maxmb', 'slash', 'minstake')])
        if todo['service']:
            self.call(m, 'service', 'SetParams', [arg_u(k, s[k]) for k in ('fee', 'rho', 'boost', 'epoch', 'minmat')])
        if todo['prize']:
            self.call(m, 'prize', 'SetParams', [arg_u(k, z[k]) for k in ('rbond', 'commitw', 'revealw', 'maxn', 'boost', 'minmat')])
        if todo['audit']:
            self.call(m, 'audit', 'SetParams', [arg_u(k, u[k]) for k in ('bond', 'commitw', 'revealw', 'maxn')])
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

    def mined_counts(self, lo, hi):
        """normal miniblocks per address over [lo, hi], one scan shared by every claimer (r32a: N wallets)."""
        out = {}
        for h in range(lo, hi + 1):
            ms = self.daemon('DERO.GetBlock', {'height': h})['block_header'].get('miners', [])
            for x in (ms[:-1] if len(ms) == 10 else ms):
                out[x] = out.get(x, 0) + 1
        return out

    def claims(self):
        """r32a: every wallet claims the miniblocks IT mined (the linear same-address incentive, research §Q1: a bonus per
        accepted miniblock is split-invariant). Claims are sent one by one (each verified by claim_index); a wallet's
        span starts after its previous claim (the contract refuses `from <= lc`); the next wallet finalizes each claim
        after the window, all finalizers in parallel."""
        a = self.P['attest']
        h = self.height()
        hi = h - 3
        last = self.run.state.setdefault('claim_upto', {})
        lo_all = max(2, h - min(990, a.get('maxspan', 1000) - 10))
        counts = self.mined_counts(max(lo_all, min([int(last.get(n, 0)) + 1 for n in self.names] + [hi])), hi)
        made = []
        for n in self.names:
            lo = max(lo_all, int(last.get(n, 0)) + 1)
            if lo > hi:
                continue
            k = min(counts.get(self.addr[n], 0) if lo <= hi else 0, (hi - lo + 1) * a['maxmb'], self.plan.get('k', 10**9))
            if k == 0:
                self.ev('claim_skip', who=n, reason='no miniblocks of this wallet in its span')
                continue
            nc0 = int(self.vars('attest')[0].get('nc', 0))
            self.call(n, 'attest', 'Claim', [arg_u('from', lo), arg_u('upto', hi), arg_u('k', k)], dero=k * a['bond'])
            v, _ = self.vars('attest')
            i = claim_index(nc0, v.get('nc', 0))
            last[n] = hi
            self.run.save()
            made.append((n, i, k, int(v.get(f'c{i}h', h))))
        if not made:
            return []
        self.wait_height(max(x[3] for x in made) + a['window'] + 1)
        nxt = {n: self.names[(j + 1) % len(self.names)] for j, n in enumerate(self.names)}
        by = {}
        for n, i, _k, _h in made:
            by.setdefault(nxt[n], []).append(i)
        self.par([lambda f=f, L=L: [self.call(f, 'attest', 'Finalize', [arg_u('i', i)]) for i in L] for f, L in by.items()])
        v, _ = self.vars('attest')
        mat = self.run.state['scids']['attest']
        return [{'who': n, 'k': k, 'status': int(v.get(f'c{i}s', -1)), 'mat': self.balance(n, mat)} for n, i, k, _h in made]

    def audit_round(self, task, bounty, span=30):
        """r32a: one gt_audit bounty round over a settled range. The sponsor (names[0]) commits its answer hidden; every
        other wallet computes the answer itself (harness/gametheory/audit_tasks.py, read-only) and commits it bound to its
        own address; reveals after the commit window; Settle; pull withdrawals. Records the contract's verdict."""
        import importlib.util as _iu
        spec = _iu.spec_from_file_location('audit_tasks', ROOT / 'harness/gametheory/audit_tasks.py')
        AT = _iu.module_from_spec(spec)
        spec.loader.exec_module(AT)
        u = self.P['audit']
        tip = self.height()
        hi = tip - AT.SETTLE - 1
        lo = hi - span + 1
        sp = self.names[0]
        rpc = AT.RI.Rpc(url=f"http://{self.net['daemon']}/json_rpc")        # the cycle's own network, read-only
        floor = AT.RI.PRUNED_FLOOR if self.a.network == 'mainnet' else 0
        ans_s, why = AT.compute(task, lo, hi, rpc=rpc, floor=floor)
        if why:
            raise RuntimeError(f'audit task {task}: {why}')
        com = {}
        for n in self.names[1:]:          # every auditor re-derives the answer itself, BEFORE the Post: Enter follows at once
            mine, why = AT.compute(task, lo, hi, rpc=rpc, floor=floor)
            if why:
                raise RuntimeError(f'audit task {task} for {n}: {why}')
            salt = gtlib.new_password()
            com[n] = (mine['answer'], salt, gtlib.audit_commit(mine['answer'], salt, self.addr[n]))
        salt_s = gtlib.new_password()
        na0 = int(self.vars('audit')[0].get('na', 0))
        self.call(sp, 'audit', 'Post', [arg_u('task', task), arg_u('from', lo), arg_u('upto', hi),
                                        arg_s('commit', gtlib.audit_sponsor_commit(ans_s['answer'], salt_s))], dero=bounty)
        v, _ = self.vars('audit')
        if int(v.get('na', 0)) != na0 + 1:
            raise RuntimeError(f'postcondition: audit Post reverted (na {na0} -> {v.get("na")})')
        ar = na0
        self.par([lambda n=n: self.call(n, 'audit', 'Enter', [arg_u('a', ar), arg_s('commit', com[n][2])], dero=u['bond'])
                  for n in com])
        v, _ = self.vars('audit')
        idx = {n: entry_index_audit(v, ar, com[n][2]) for n in com}
        if None in idx.values():
            self.ev('audit_enter_rejected', round=ar, missing=[n for n in idx if idx[n] is None])
        start = int(v[f'a{ar}_start'])                  # gt_audit key map: p+start = the Post height
        self.wait_height(start + u['commitw'] + 1)
        self.call(sp, 'audit', 'RevealSponsor', [arg_u('a', ar), arg_s('answer', ans_s['answer']), arg_s('salt', salt_s)])
        self.par([lambda n=n: self.call(n, 'audit', 'Reveal', [arg_u('a', ar), arg_u('j', idx[n]), arg_s('answer', com[n][0]),
                                                                arg_s('salt', com[n][1])]) for n in com if idx[n] is not None])
        v, _ = self.vars('audit')
        arev = {n: int(v.get(f'a{ar}_{idx[n]}_v', 0)) for n in com if idx[n] is not None}
        if not all(arev.values()) or f'a{ar}_sa' not in v:
            self.ev('audit_reveal_rejected', round=ar, revealed=arev, sponsor_revealed=f'a{ar}_sa' in v, start=start,
                    commitw=u['commitw'], revealw=u['revealw'], height=self.height())
        self.wait_height(start + u['commitw'] + u['revealw'] + 1)
        self.call(sp, 'audit', 'Settle', [arg_u('a', ar)])
        self.par([lambda n=n: self.call(n, 'audit', 'Withdraw', [arg_u('a', ar), arg_u('j', idx[n])]) for n in com if idx[n] is not None])
        v, _ = self.vars('audit')
        return {'audit_round': ar, 'task': task, 'name': ans_s['name'], 'from': lo, 'upto': hi, 'bounty': bounty,
                'auditors': len(com), 'entered': sum(1 for x in idx.values() if x is not None),
                'summary': ans_s['summary'],
                'verdict': {k: v.get(f'a{ar}_{k}') for k in AUDIT_VERDICT_KEYS}}   # outcome keys only: no signer bytes

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
        margin = (self.run.state.get('windows') or {}).get('margin', ENTER_MARGIN)
        if self.height() > rs + z['commitw'] - margin:
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
        v, _ = self.vars('prize')
        revealed = {n: int(v.get(f'v{r}_{idx[n]}', 0)) for n in self.names if idx[n] is not None}
        if not all(revealed.values()):                  # r32a pre-flight: rounds drew no winner; say which reveal failed
            self.ev('reveal_rejected', round=r, revealed=revealed, rs=rs, commitw=z['commitw'], revealw=z['revealw'],
                    height=self.height())
        self.wait_height(rs + z['commitw'] + z['revealw'] + 1)
        self.call(self.names[0], 'prize', 'Draw')
        self.pending_w += [(n, r, idx[n]) for n in self.names if idx[n] is not None]
        v, _ = self.vars('prize')
        return {'round': r, 'entrants': entrants, 'entries': {str(j): n for n, j in idx.items() if j is not None},
                'revealed': sum(revealed.values()),
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
            needs = (json.loads(Path(a.plan).read_text()).get('needs_atomic') or {}) if a.plan else {}   # r32a: per wallet
            short = {n: start[n] for n in c.names
                     if start[n] < int(needs.get(n) or need or int(sz['targets_atomic'].get(n, 0)))}
            if short:
                c.ev('cycle_wait', reason='below the sizing target (D-GT-7)', short={k: f'{v / 1e5:.5f}' for k, v in short.items()})
                return 7
        c.deploy()
        ladder = 'audits' in c.plan                      # r32a: a ladder step (N wallets, every wallet claims, audit rounds)
        if ladder:
            cl = c.claims()
            res = {'claims': cl, 'm1': next((x for x in cl if x['who'] == c.names[0]), None), 'm3_rounds': [], 'audits': []}
        else:
            res = {'m1': c.m1_claim(), 'm3_rounds': []}
        for _ in range(int(c.plan.get('rounds', 1))):
            res['m3_rounds'].append(c.m3_round())
        res['m3'] = res['m3_rounds'][-1]
        c.flush_withdraws()
        for t in range(int(c.plan.get('audits', 0))):
            res['audits'].append(c.audit_round(1 + t % 2, int(c.plan['bounty'])))   # task 1 headers, 2 emission, ...
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
