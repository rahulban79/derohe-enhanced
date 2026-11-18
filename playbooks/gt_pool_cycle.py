#!/usr/bin/env python3
"""gt_pool_cycle.py — R33 GT-B29 (artifacts/dero-game-theory-rft.md §8.1 M5/M6): one measured epoch of the verified
mining pool gt_pool.bas, with the beacon gt_beacon.bas, run WITHOUT any LLM (python3 -I, stdlib only, JSONL events).

  install   gt_pool + gt_beacon from the wallet of the first name (txid = SCID; a re-run reuses the run's SCIDs and
            refuses an SCID whose on-chain code is not the file's code)
  register  every wallet Registers (the entry fee); its tag (gtlib.pool_tag) must then exist in the contract
  fund      the first wallet Funds the current epoch with --sponsor atomic
  mine      sim only: one tagged gt-dero-miner per wallet on the private chain (mainnet: the earn job mines with
            --game-tag, playbooks/gt_earn.py)
  prove     --anchors times: Anchor (the tx lands in some block H), ProveBlock(H), then ProveParent back --depth blocks
            (never below the epoch start or an already proven height); provers rotate over the wallets
  claim     after the epoch's proof window every wallet with credit Claims
  audit     the chain audit: for every proven height the block bytes are read again (DERO.GetBlock) and parsed here;
            credits per tag, weights, the total, every claim against pool x W / TW (cap), and the contract's DERO
            balance against burned + every pool + every stake
  beacon    the first wallet Publishes the measured figures with their height range
  record    harness/runtime/gt_pool_<network>_<ts>.json (+ the audit verdict)

  python3 -I playbooks/gt_pool_cycle.py --network sim --wallets m1,m2,m3 [--anchors 3 --depth 6]
  python3 -I playbooks/gt_pool_cycle.py --network mainnet --mainnet-confirm --wallets m1,m2,m3,m4,m5
Mainnet spends real DERO of the NEW gt wallets only (D-GT-4); the user's address is banned by hash (D-GT-2).
Exit 0 ok · 3 the audit failed · 5 mainnet without --mainnet-confirm · 6 banned address · 1 error.
"""
import argparse, base64, datetime, json, os, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gtlib  # noqa: E402
import gt_cycle  # noqa: E402
from gtlib import arg_s, arg_u, banguard  # noqa: E402

ROOT = gtlib.ROOT
POOL = {'pool': 'gt_pool.bas', 'beacon': 'gt_beacon.bas'}


def parse_block(blob_hex, ntx, m):
    """(tip hex, [(final, keyhash hex, flags hex, height)]) of a serialized block, parsed from the end exactly as
    gt_pool.pproc does (block/block.go serialize; block/miniblock.go Serialize). Raises on a layout mismatch."""
    b = bytes.fromhex(blob_hex)
    p = len(b) - 32 * ntx - 1
    if b[p] != ntx:
        raise ValueError(f'tx count byte {b[p]} != {ntx}')
    q = p - 48 * m - 1
    if b[q] != m or b[q - 33] != 1:
        raise ValueError('miniblock count / tip count mismatch')
    mbs = []
    for i in range(m):
        x = b[q + 1 + 48 * i: q + 1 + 48 * (i + 1)]
        mbs.append((bool(x[0] & 0x20), x[16:32].hex(), x[32:40].hex(), int.from_bytes(x[3:8], 'big')))
    return b[q - 32:q].hex(), mbs


def expected_epoch(blocks, tags, stakes=None, S=100000, epochlen=400):
    """credits per tag and weights from parsed proven blocks: [(h, mbs)] -> ({tag: w}, {tag: W}, TW). stakes =
    {tag: (amount, since)}: the boost min(100 * s / S, 100) applies when since + epochlen <= h (gt_pool credit())."""
    w, W = {}, {}
    for h, mbs in blocks:
        for final, _, fl, _ in mbs:
            if final or fl not in tags:
                continue
            w[fl] = w.get(fl, 0) + 1
            amt, since = (stakes or {}).get(fl, (0, 0))
            b = min(100 * amt // S, 100) if amt and since + epochlen <= h else 0
            W[fl] = W.get(fl, 0) + 100 + b
    return w, W, sum(W.values())


def hexvar(v):
    """GetSC returns String variables hex-encoded (rpc_dero_getsc.go:138)."""
    try:
        return bytes.fromhex(v).decode('latin-1')
    except (ValueError, TypeError):
        return v


class PoolCycle(gt_cycle.Cycle):
    def __init__(self, a):
        super().__init__(a)
        self.proofs, self.proven = [], set()
        self.members = a.members.split(',') if a.members else list(self.names)
        self.locks = {x.split('=')[0]: int(x.split('=')[1]) for x in a.lock.split(',')} if a.lock else {}

    def install(self):
        m = self.names[0]
        for key, f in POOL.items():
            code = (ROOT / 'gametheory/contracts' / f).read_text()
            scid = self.run.state['scids'].get(key)
            if scid:
                got = self.daemon('DERO.GetSC', {'scid': scid, 'code': True, 'variables': False}).get('code', '')
                if got.strip() != code.strip():
                    raise RuntimeError(f'{key} {scid[:12]}: on-chain code is not {f} (D-GT-20: never reuse unaudited code)')
                continue
            txid = self.send(m, {'sc': base64.b64encode(code.encode()).decode(), 'ringsize': 2, 'transfers': []}, f'{key}.install')
            self.wait_height(self.height() + 2)
            self.run.state['scids'][key] = txid
            self.run.save()
            self.ev('installed', contract=f, scid_prefix=txid[:12], fee=self.fee_of(m, txid))

    def mcount(self):
        hdr = self.daemon('DERO.GetBlock', {'height': self.height() - 1})
        return len(hdr['block_header'].get('miners', [])) or 10

    def setup(self):
        v, _ = self.vars('pool')
        if self.a.network != 'mainnet' and int(v.get('nm', 0)) == 0:
            mc = self.mcount()
            if mc != int(v.get('mcount', 10)):
                self.call(self.names[0], 'pool', 'SetMcount', [arg_u('n', mc)])
                self.ev('mcount_set', n=mc)
        for n in self.members:
            if f'tag_{self.tags[n]}' in self.vars('pool')[0]:
                continue
            if self.tags[n] in ('0' * 16, 'f' * 16):
                self.ev('tag_refused', who=n)
                continue
            self.call(n, 'pool', 'Register', dero=int(v.get('fee', 1000)))
            if f'tag_{self.tags[n]}' not in self.vars('pool')[0]:
                raise RuntimeError(f'{n}: tag {self.tags[n]} not in the pool after Register (tag rule mismatch)')
            self.ev('registered', who=n, tag=self.tags[n])
        self.lock_h = None
        for n, amt in self.locks.items():
            if int(self.vars('pool')[0].get(f's_{self.tags[n]}', 0)) == 0:
                self.call(n, 'pool', 'Lock', dero=amt)
                self.lock_h = self.height()
                self.ev('stake_locked', who=n, amount=amt, h=self.lock_h)

    def sim_miners(self):
        if self.a.network == 'mainnet':
            return
        # GT-B1 strategy mixes: name:threads:cpu[:tag-of-whom|none]; default one tagged miner per member
        spec = self.a.miner_spec.split(',') if self.a.miner_spec else [f'{n}:1:40' for n in self.members]
        for item in spec:
            f = item.split(':')
            n, th, cpu = f[0], f[1], f[2]
            who = f[3] if len(f) > 3 else n
            argv = [str(gtlib.BIN / 'gt-dero-miner'), f'--wallet-address={self.addr[n]}', f"--daemon-rpc-address={self.net['getwork']}",
                    f'--mining-threads={th}', '--testnet', '--node-rpc-address=off', f'--cpu-max={cpu}']
            if who != 'none':
                argv.append(f'--game-tag={self.tags[who]}')
            gtlib.start_proc(self.run, f'pool-miner-{n}', argv)
            self.ev('sim_miner', who=n, threads=int(th), cpu=int(cpu), tag_of=who)

    def prove_call(self, prover, entry, h):
        b = self.daemon('DERO.GetBlock', {'height': h})
        ntx = int(b['block_header'].get('txcount', 0) or 0)
        args = [arg_u('h', h), arg_s('hx', b['blob']), arg_u('ntx', ntx)]
        scid = self.run.state['scids']['pool']
        p = {'scid': scid, 'ringsize': 2, 'sc_rpc': [arg_s('entrypoint', entry), *args], 'transfers': []}
        est = self.gas_estimate(prover, scid, p)           # per block: the storage gas depends on the block
        # r33 sim pre-flight: 1.3 x the estimate + 100 paid ~2,225 for ~1,637 storage gas, more than the 2,000 prover fee;
        # a proof's storage gas is set by the block (fixed per layout), so the estimate + 200 suffices
        p['fees'] = min(20000, est['gasstorage'] + 200) if est else 3000
        b0 = self.balance(prover)
        txid = self.send(prover, p, f'pool.{entry}')
        rec = {'who': prover, 'sc': 'pool', 'entry': entry, 'h': h, 'ntx': ntx, 'gas_est': est, 'fees_set': p['fees'],
               'fee': self.fee_of(prover, txid), 'txid_prefix': txid[:12], 'balance_delta_hint': None}
        self.fees.append(rec)
        self.proofs.append(rec)
        self.ev('proof', **{k: v for k, v in rec.items() if k != 'who'}, prover=prover)
        if f'pr{h}' not in self.vars('pool')[0]:
            raise RuntimeError(f'{entry}({h}) did not record the proof')
        self.proven.add(h)
        _ = b0

    def prove(self, e, epochlen):
        lo = e * epochlen
        for i in range(self.a.anchors):
            if self.height() >= (e + 1) * epochlen - 2:
                break
            n = self.names[i % len(self.names)]
            self.call(n, 'pool', 'Anchor')
            H = int(self.last_bh or 0)
            v, _ = self.vars('pool')
            if f'b{H}' not in v:
                self.ev('anchor_missing', h=H)        # the tx's block was not the one recorded (side block / reorg)
                continue
            got = self.daemon('DERO.GetBlock', {'height': H})['block_header']['hash']
            if hexvar(v[f'b{H}']).encode('latin-1').hex() != got:
                raise RuntimeError(f'anchor at {H} is not the main-chain block id')
            if H // epochlen != e:
                self.ev('anchor_next_epoch', h=H)
                break
            self.prove_call(self.names[(i + 1) % len(self.names)], 'ProveBlock', H)
            for k, h in enumerate(range(H - 1, max(lo, H - 1 - self.a.depth), -1)):
                if h in self.proven:
                    break
                self.prove_call(self.names[(i + k) % len(self.names)], 'ProveParent', h)
            if i + 1 < self.a.anchors:
                self.wait_height(self.height() + self.a.gap)

    def member_blocks(self, lo, hi):
        """heights in [lo, hi] whose header names a member as the miner of a non-final miniblock (off-chain, read-only)."""
        mine = set(self.addr.values())
        out = []
        for h in range(lo, hi + 1):
            ms = self.daemon('DERO.GetBlock', {'height': h})['block_header'].get('miners', [])
            if any(x in mine for x in (ms[:-1] if len(ms) >= 2 else ms)):
                out.append(h)
        return out

    def contract_proven(self, e, epochlen):
        v, _ = self.vars('pool')
        return {int(k[2:]) for k in v if k.startswith('pr') and k[2:].isdigit() and int(k[2:]) // epochlen == e}

    def prove_follow(self, e, epochlen, budget):
        """R33 GT-B34: prove where member work is. Watch new blocks; after a block with member miniblocks, Anchor (the
        tx lands a few blocks later at H) and walk back from H to that block only. Costs ~(H - m + 1) proofs per member
        block instead of a fixed depth; stops at the epoch's last usable height or after `budget` proofs."""
        lo, seen = e * epochlen, max(e * epochlen, self.height() - 1)
        self.proven |= self.contract_proven(e, epochlen)          # resume: proofs of a relaunched process
        k = 0
        while len(self.proofs) < budget and self.height() < (e + 1) * epochlen - 3:
            top = self.height() - 1
            hits = [h for h in self.member_blocks(seen + 1, top) if h not in self.proven and h // epochlen == e]
            seen = max(seen, top)
            if not hits:
                time.sleep(20)
                continue
            target = min(hits)
            n = self.names[k % len(self.names)]
            k += 1
            self.call(n, 'pool', 'Anchor')
            H = int(self.last_bh or 0)
            v, _ = self.vars('pool')
            if f'b{H}' not in v or H // epochlen != e:
                self.ev('anchor_skip', h=H, reason='not recorded' if f'b{H}' not in v else 'next epoch')
                continue
            self.prove_call(self.names[k % len(self.names)], 'ProveBlock', H)
            for j, h in enumerate(range(H - 1, max(lo, target) - 1, -1)):
                if h in self.proven or len(self.proofs) >= budget:
                    break
                self.prove_call(self.names[(k + j) % len(self.names)], 'ProveParent', h)
            seen = max(seen, H)
        self.ev('follow_done', proofs=len(self.proofs), proven=len(self.proven))

    def claim(self, e, epochlen, grace):
        self.wait_height((e + 1) * epochlen + grace, timeout=4 * 3600)
        out = {}
        for n in self.members:
            v0 = self.vars('pool')[0]
            if f'W{e}_{self.tags[n]}' in v0 and f'c{e}_{self.tags[n]}' not in v0:      # resume: never claim twice
                self.call(n, 'pool', 'Claim', [arg_u('e', e)])
                out[n] = int(self.vars('pool')[0].get(f'c{e}_{self.tags[n]}', 0))
        return out

    def audit(self, e, m):
        v, bal = self.vars('pool')
        tagset = {self.tags[n] for n in self.members}
        stakes = {t: (int(v.get(f's_{t}', 0)), int(v.get(f'since_{t}', 0))) for t in tagset}
        blocks, bad = [], []
        epochlen = int(v.get('epochlen', 400))
        # mainnet epoch 19,793 (2026-11-17): a relaunched process audited only its own proofs and missed 6 proven by the
        # first process; the contract's pr<h> keys are the authoritative proven set
        chain_proven = sorted(int(k[2:]) for k in v if k.startswith('pr') and k[2:].isdigit() and int(k[2:]) // epochlen == e)
        self.proven |= set(chain_proven)
        for h in chain_proven:
            b = self.daemon('DERO.GetBlock', {'height': h})
            _, mbs = parse_block(b['blob'], int(b['block_header'].get('txcount', 0) or 0), m)
            if any(x[3] != h for x in mbs):
                bad.append(f'height field at {h}')
            blocks.append((h, mbs))
        w, W, TW = expected_epoch(blocks, tagset, stakes, int(v.get('S', 100000)), epochlen)
        for t in tagset:
            if int(v.get(f'w{e}_{t}', 0)) != w.get(t, 0) or int(v.get(f'W{e}_{t}', 0)) != W.get(t, 0):
                bad.append(f'tag {t}: contract w {v.get(f"w{e}_{t}")} W {v.get(f"W{e}_{t}")} vs chain {w.get(t, 0)} {W.get(t, 0)}')
        if int(v.get(f'TW{e}', 0)) != TW:
            bad.append(f'TW {v.get(f"TW{e}")} vs {TW}')
        P0 = int(v.get(f'P0_{e}', 0))
        cap = int(v.get('cap', 30))
        for t in tagset:
            if f'c{e}_{t}' in v:
                want = min(P0 * W.get(t, 0) // TW, P0 * cap // 100) if TW else 0
                if int(v[f'c{e}_{t}']) != want:
                    bad.append(f'claim {t}: {v[f"c{e}_{t}"]} vs formula {want}')
        liab = int(v.get('burned', 0)) + sum(int(x) for k, x in v.items() if k.startswith('P') and k[1:].isdigit()) \
            + sum(int(x) for k, x in v.items() if k.startswith('s_'))
        if liab != bal:
            bad.append(f'conservation: balance {bal} vs burned + pools + stakes {liab}')
        return {'ok': not bad, 'problems': bad, 'credits': w, 'weights': W, 'TW': TW, 'P0': P0, 'balance': bal,
                'burned': int(v.get('burned', 0)), 'proven': len(blocks), 'proven_range': [min(self.proven, default=0), max(self.proven, default=0)]}

    def publish(self, e, au):
        lo, hi = au['proven_range']
        if not hi:
            return
        s = f"e{e}: proven {au['proven']} blocks, credits {sum(au['credits'].values())}, TW {au['TW']}, pool {au['P0']}, burned {au['burned']}"
        self.call(self.names[0], 'beacon', 'Publish', [arg_s('k', f'pool_e{e}'), arg_s('v', s[:512]), arg_u('from', lo), arg_u('upto', hi)])
        # GT-B35: the concentration alarm over every epoch the pool holds (harness/gametheory/pool_census.py)
        import importlib.util as _iu
        sp = _iu.spec_from_file_location('pool_census', ROOT / 'harness/gametheory/pool_census.py')
        PC = _iu.module_from_spec(sp)
        sp.loader.exec_module(PC)
        cv = PC.verdict(PC.census(self.vars('pool')[0]))
        cs = f"census epochs {cv['epochs'][0]}-{cv['epochs'][-1]}: {cv['miniblocks']} miniblocks, {cv['keyhashes']} keyhashes, top {cv['top_share']:.3f}: {cv['state']}" if cv['epochs'] else 'census: none'
        self.call(self.names[0], 'beacon', 'Publish', [arg_s('k', 'pool_census'), arg_s('v', cs[:512]), arg_u('from', lo), arg_u('upto', hi)])
        self.ev('census', **cv)
        self.call(self.names[0], 'beacon', 'Publish', [arg_s('k', 'pool_scid'), arg_s('v', self.run.state['scids']['pool']),
                                                       arg_u('from', lo), arg_u('upto', hi)])


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--network', choices=['sim', 'mainnet'], default='sim')
    ap.add_argument('--run-id', default=None)
    ap.add_argument('--wallets', default='m1,m2,m3')
    ap.add_argument('--sponsor', type=int, default=100000, help='atomic funded into the epoch by the first wallet (1 DERO)')
    ap.add_argument('--anchors', type=int, default=4)
    ap.add_argument('--depth', type=int, default=8, help='ProveParent steps back from each anchor')
    ap.add_argument('--gap', type=int, default=20, help='heights between anchors')
    ap.add_argument('--epochs', type=int, default=1, help='GT-B12 continuous mode: measured epochs in a row (every other epoch: claims of e end in e + 1)')
    ap.add_argument('--follow', action='store_true', help='GT-B34: prove only around blocks with member work')
    ap.add_argument('--max-proofs', type=int, default=40, help='proof budget per epoch (follow mode)')
    ap.add_argument('--members', default=None, help='wallets that Register (default: all of --wallets)')
    ap.add_argument('--miner-spec', default=None, help='sim: name:threads:cpu[:tag-of|none],... (GT-B1 strategy mixes)')
    ap.add_argument('--lock', default=None, help='name=atomic,...: members that Lock stake before the measured epoch')
    ap.add_argument('--mainnet-confirm', action='store_true')
    ap.add_argument('--rebuild', action='store_true')
    a = ap.parse_args(argv)
    a.run_id = a.run_id or f'r33-pool-{a.network}'
    a.fast, a.plan = False, None
    if a.network == 'mainnet' and not a.mainnet_confirm:
        print('mainnet needs --mainnet-confirm (D-GT-4); nothing done')
        return 5
    c = PoolCycle(a)
    gtlib.ensure_bins(c.run, ['gt-wallet', 'gt-dero-miner'], rebuild=a.rebuild)
    rc = 1
    try:
        c.serve()
        c.start_height = c.height()
        start = {n: c.balance(n) for n in c.names}
        c.ev('pool_cycle_start', start_dero={n: f'{x / 1e5:.5f}' for n, x in start.items()})
        c.tags = {n: gtlib.pool_tag(c.addr[n]) for n in c.names}
        c.sim_miners()        # sim: blocks are mined only by these tagged miners, so they start before the first tx
        c.install()
        c.setup()
        v, _ = c.vars('pool')
        epochlen, grace, m = int(v.get('epochlen', 400)), int(v.get('grace', 100)), int(v.get('mcount', 10))
        fails, rc, e = 0, 0, None
        for k in range(a.epochs):
            c.proofs, c.proven, c.fees = [], set(), []
            e = c.height() // epochlen if e is None else max(e + 2, c.height() // epochlen)   # claims of e end in e + 1
            if c.lock_h is not None and k == 0:                    # stake must be locked one epoch before credited work
                e = max(e, (c.lock_h + epochlen) // epochlen + 1)
            if c.height() < e * epochlen:
                c.wait_height(e * epochlen + 2, timeout=4 * 3600)
            if c.height() % epochlen > epochlen - 3 * a.gap - 10:     # too late in this epoch: use the next one
                e += 1
                c.wait_height(e * epochlen + 2, timeout=4 * 3600)
            # mainnet cycle 1 (2026-11-17): with one credited member the 30 % per-identity cap left 70 % of the pot; it is
            # not lost: Rollover moves an epoch's leftover into the current epoch once its claims closed (e + 5 epochs)
            v, _ = c.vars('pool')
            cur = c.height() // epochlen
            for k2, x in list(v.items()):
                if k2.startswith('P') and k2[1:].isdigit() and int(x) > 0 and int(k2[1:]) + 5 <= cur and int(k2[1:]) != cur:
                    try:
                        c.call(c.names[0], 'pool', 'Rollover', [arg_u('e', int(k2[1:]))])
                        c.ev('rollover', epoch=int(k2[1:]), amount=int(x), to=cur)
                    except RuntimeError as ex:
                        c.ev('rollover_failed', epoch=int(k2[1:]), error=str(ex)[:200])
            try:
                e0 = {n: c.balance(n) for n in c.names}
                done = c.run.state.setdefault('pool_epochs', {})
                if str(e) in done and done[str(e)].get('recorded'):      # a relaunch resumes, never re-plays an epoch
                    c.ev('epoch_skip', epoch=e, reason='already recorded by this run')
                    continue
                if not done.get(str(e), {}).get('funded'):
                    c.call(c.names[0], 'pool', 'Fund', [arg_u('e', e)], dero=a.sponsor)
                    done[str(e)] = {'funded': True}
                    c.run.save()
                else:
                    c.ev('fund_skip', epoch=e, reason='funded before a relaunch')
                if a.follow:
                    c.prove_follow(e, epochlen, a.max_proofs)
                else:
                    c.prove(e, epochlen)
                claims = c.claim(e, epochlen, grace)
                au = c.audit(e, m)
            except (RuntimeError, gt_cycle.TxLost) as ex:            # GT-B12: a failed epoch is recorded, the loop goes on
                fails += 1
                c.ev('epoch_failed', epoch=e, error=str(ex)[:300], fails_in_a_row=fails)
                if fails >= 3:
                    c.ev('loop_stopped', reason='3 failed epochs in a row')
                    return 3
                continue
            c.ev('pool_audit', ok=au['ok'], problems=au['problems'][:5], proven=au['proven'], credits=au['credits'], epoch=e)
            if au['ok']:
                c.publish(e, au)
            end = {n: c.balance(n) for n in c.names}
            fees = sum(int(r.get('fee') or 0) for r in c.fees)
            ts = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')
            rec = {'run': a.run_id, 'network': a.network, 'epoch': e, 'epochlen': epochlen, 'start_height': c.start_height,
                   'end_height': c.height(), 'scids': c.run.state['scids'], 'tags': c.tags, 'claims': claims, 'audit': au,
                   'proofs': c.proofs, 'calls': c.fees, 'fees_total_atomic': fees, 'mode': 'follow' if a.follow else 'anchors',
                   'start_atomic': e0, 'end_atomic': end, 'wall_s': round(time.time() - c.t0), 'loop_index': k}
            out = ROOT / 'harness/runtime' / f'gt_pool_{a.network}_{ts}.json'
            out.write_text(json.dumps(rec, indent=1))
            c.ev('pool_record', file=out.name, ok=au['ok'], fees=fees, epoch=e)
            c.run.state.setdefault('pool_epochs', {}).setdefault(str(e), {})['recorded'] = out.name
            c.run.save()
            fails = 0 if au['ok'] else fails + 1
            rc = 0 if au['ok'] else 3
            if fails >= 3:
                c.ev('loop_stopped', reason='3 failed audits in a row')
                return 3
        return rc
    except banguard.BannedAddress as ex:
        c.ev('banned', error=str(ex))
        return 6
    except Exception as ex:  # noqa: BLE001
        c.ev('error', error=f'{type(ex).__name__}: {ex}'[:300])
        return 1
    finally:
        for n in c.names:
            gtlib.stop_proc(c.run, f'pool-miner-{n}')
            gtlib.stop_proc(c.run, f'cycle-wallet-{n}')


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
