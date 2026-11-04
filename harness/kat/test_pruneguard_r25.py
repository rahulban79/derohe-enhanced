#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the harness prune guard (harness/kit/pruneguard.py, r25, rft §5 / B85).

  PG1 state_topo follows each handler's own rule: GetEncryptedBalance uses topoheight >= 0 as is (an omitted field is
      0 = genesis, the case that reads pruned state by default), < 0 or a treehash = the tip; GetSC uses >= 1, else the
      tip; any other method reads no historical state (None); a positional [params] list is read too
  PG2 check: below prunedheight raises StateBelowPrune; AT prunedheight is allowed (the live node answers 7,498,540
      and not 7,498,539); an unpruned node (0) never refuses; the tip never
  PG3 guarded_call: GetInfo.prunedheight is read when not given; a refused call never reaches the node; an allowed
      state read writes exactly one call-log line {t, method, topoheight} (no address, no params); a non-state call is
      neither checked nor logged
  PG4 the error census reads that call log: a recovered GetEncryptedBalance panic logged within the window of a
      logged call is classed self-inflicted

  python3 -I harness/kat/test_pruneguard_r25.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import datetime, importlib.util, json, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
SRC = HARNESS / 'kit' / 'pruneguard.py'
ADDR = 'deto1qyexampleaddressnotreal'


def load(path, name='pruneguard'):
    spec = importlib.util.spec_from_file_location(f'{name}_{abs(hash(str(path)))}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def kats(pg):
    bad = []
    st = pg.state_topo
    cases = [(('DERO.GetEncryptedBalance', {'address': ADDR}), 0), (('DERO.GetEncryptedBalance', {'address': ADDR, 'topoheight': -1}), 'tip'),
             (('getencryptedbalance', {'address': ADDR, 'topoheight': 7498539}), 7498539),
             (('DERO.GetEncryptedBalance', {'address': ADDR, 'topoheight': 5, 'treehash': 'ab'}), 'tip'),
             (('DERO.GetSC', {'scid': '00', 'topoheight': 0}), 'tip'), (('getsc', {'scid': '00', 'topoheight': 1}), 1),
             (('DERO.GetSC', {'scid': '00'}), 'tip'), (('DERO.GetInfo', None), None),
             (('DERO.GetBlockHeaderByTopoHeight', {'topoheight': 3}), None),
             (('DERO.GetEncryptedBalance', [{'address': ADDR, 'topoheight': 12}]), 12)]
    for (m, p), want in cases:
        if st(m, p) != want:
            bad.append(f'PG1 state_topo({m}, {p}) = {st(m, p)!r}, want {want!r}')
    # PG2
    def refused(m, p, pruned):
        try:
            pg.check(m, p, pruned)
            return False
        except pg.StateBelowPrune:
            return True
    for m, p, pruned, want in [('DERO.GetEncryptedBalance', {'topoheight': 7498539}, 7498540, True),
                               ('DERO.GetEncryptedBalance', {'topoheight': 7498540}, 7498540, False),
                               ('DERO.GetEncryptedBalance', {}, 7498540, True),
                               ('DERO.GetEncryptedBalance', {'topoheight': 3}, 0, False),
                               ('DERO.GetEncryptedBalance', {'topoheight': -1}, 7498540, False),
                               ('DERO.GetSC', {'topoheight': 7415466}, 7498540, True),
                               ('DERO.GetSC', {'topoheight': 0}, 7498540, False)]:
        if refused(m, p, pruned) != want:
            bad.append(f'PG2 check({m}, {p}, {pruned}) refused={not want}, want {want}')
    # PG3
    d = Path(tempfile.mkdtemp(prefix='r25pg-'))
    try:
        log = d / 'calls.jsonl'
        sent = []

        def rpc(method, params):
            sent.append(method)
            return {'prunedheight': 7498540} if method == 'DERO.GetInfo' else {'status': 'OK'}
        try:
            pg.guarded_call(rpc, 'DERO.GetEncryptedBalance', {'address': ADDR, 'topoheight': 7415465}, call_log=log)
            bad.append('PG3 a call below prunedheight was not refused')
        except pg.StateBelowPrune:
            pass
        if 'DERO.GetEncryptedBalance' in sent or sent != ['DERO.GetInfo']:
            bad.append(f'PG3 sent {sent}: a refused call reached the node, or GetInfo was not read')
        sent.clear()
        pg.guarded_call(rpc, 'DERO.GetEncryptedBalance', {'address': ADDR, 'topoheight': 7850831}, pruned=7498540, call_log=log)
        pg.guarded_call(rpc, 'DERO.GetInfo', None, call_log=log)
        rows = [json.loads(l) for l in log.read_text().splitlines()] if log.exists() else []
        if sent != ['DERO.GetEncryptedBalance', 'DERO.GetInfo'] or len(rows) != 1 or \
                set(rows[0]) != {'t', 'method', 'topoheight'} or rows[0]['topoheight'] != 7850831 or ADDR in log.read_text():
            bad.append(f'PG3 sent {sent}, call log {rows}')
        # PG4
        t = datetime.datetime.fromisoformat(rows[0]['t']) if rows else datetime.datetime.now(datetime.timezone.utc)
        loc = t.astimezone(datetime.timezone(datetime.timedelta(hours=-8)))
        T = loc.strftime('%Y-%m-%dT%H:%M:%S.') + f'{loc.microsecond // 1000:03d}-0800'
        lines = [json.dumps({'L': 'INFO', 'T': T, 'N': 'derod', 'C': 'derod/main.go:160', 'M': 'DERO HE daemon :  x'}),
                 json.dumps({'L': 'ERROR', 'T': T, 'N': 'RPC', 'C': 'rpc/rpc_errors.go:30', 'M': 'RPC handler recovered a panic',
                             'stack': 'panic({0x1})\n\t/x/panic.go:1 +0x1\ngithub.com/deroproject/derohe/cmd/derod/rpc.GetEncryptedBalance({0x1})\n'
                                      '\t/x/derohe/cmd/derod/rpc/rpc_dero_getencryptedbalance.go:92 +0x5d8\n'})]
        dl = d / 'derod.log'
        dl.write_text('\n'.join(lines) + '\n')
        sys.path.insert(0, str(HARNESS / 'kit'))
        sys.path.insert(0, str(HARNESS / 'intel'))
        try:
            ec = load(HARNESS / 'intel' / 'error_census.py', 'error_census')
        finally:
            sys.path.pop(0)
            sys.path.pop(0)
        ec.pruneguard = pg
        rep = ec.census(list(ec.records([dl])), 1, log)
        k = rep['kinds'][0] if rep and rep['kinds'] else {}
        if k.get('class') != 'self-inflicted':
            bad.append(f"PG4 census class {k.get('class')} for a panic at a logged call's instant")
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return bad


MUTATIONS = [
    ('omitted topoheight treated as the tip', '        return t if t >= 0 else \'tip\'', '        return t if t > 0 else \'tip\''),
    ('the prune point itself refused', 'and t < pruned:', 'and t <= pruned:'),
    ('GetSC topoheight 0 taken literally', "        return t if t >= 1 else 'tip'", "        return t if t >= 0 else 'tip'"),
    ('guarded_call skips the check', '    check(method, params, pruned)\n    log_call', '    log_call'),
    ('call log carries the params', "    rec = {'t': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds'), 'method': method,\n           'topoheight': topo}",
     "    rec = {'t': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds'), 'method': method,\n           'topoheight': topo, 'params': str(params)}"),
    ('state reads not logged', '    log_call(method, t, call_log)\n    return rpc(method, params)', '    return rpc(method, params)'),
]


def main():
    pg = load(SRC)
    bad = kats(pg)
    for b in bad:
        print('FAIL', b)
    if bad:
        return 3
    print('ok   PG1-PG4')
    src = SRC.read_text(encoding='utf-8')
    missed = 0
    for name, a, b in MUTATIONS:
        if src.count(a) != 1:
            print('INVALID', name, '(find text count', src.count(a), ')')
            missed += 1
            continue
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'pruneguard.py'
            mut = src.replace(a, b, 1)
            if 'str(params)' in b:   # the mutant's log_call must see params: pass them through
                mut = mut.replace('def log_call(method, topo, call_log=None):', 'def log_call(method, topo, call_log=None, params=None):')
                mut = mut.replace('    log_call(method, t, call_log)\n', '    log_call(method, t, call_log, params)\n')
            p.write_text(mut, encoding='utf-8')
            try:
                r = kats(load(p))
            except Exception as e:                       # noqa: BLE001
                print('INVALID', name, type(e).__name__, e)
                missed += 1
                continue
        print('CAUGHT' if r else 'MISSED', name, (r[:1] if r else ''))
        missed += 0 if r else 1
    print(f'r25 prune-guard KATs: 4/4 ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
