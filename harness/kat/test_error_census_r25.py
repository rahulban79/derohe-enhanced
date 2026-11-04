#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the derod error census (harness/intel/error_census.py, rft §6 step 1a, r25).

The fixture is a forged derod JSON log of two runs (an older one and the current one) whose current run holds the
shapes seen on the live node: the four B85 recovered panics of 2026-11-03 08:37:44 (stack in Go's frame format, own
frame rpc_dero_getencryptedbalance.go:92), peer GetObject failures from different peers, the miner-absent WARNING, plus
an unknown WARNING, an unknown ERROR and a recovered panic nobody's call explains. The run crosses the DST change
(-0700 then -0800), and a probe call log (harness/kit/pruneguard.py format, UTC) names the calls we made.

  EC1 run selection: --run 1 is the current run only; --run 2 the older one
  EC2 kinds: three GetObject failures from three peers with different numbers are ONE kind (peer address removed)
  EC3 own frame: the first own-code frame after panic( (not rpc_internal_error, not the deferred recover)
  EC4 classes: self-inflicted (and also a node bug), node-bug, peer-caused, operational, unclassified
  EC5 time + method matching: a call matches through its UTC instant (the -0800 offset is honoured) and only for the
      handler named by the own frame; an offset-blind parse or a method-blind match is wrong
  EC6 privacy: the snapshot carries no non-reserved IP and no home path (leaks() empty; a LAN address and a home path
      are in the fixture)
  EC7 exit codes: 5 with a node-bug kind, 0 on a clean run, 2 without a log
  EC8 wiring: S7 runs error_census.py and JUDGED accepts exits 0 and 5 with a new error_census_*.json

  python3 -I harness/kat/test_error_census_r25.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import contextlib, importlib.util, io, json, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
SRC = HARNESS / 'intel' / 'error_census.py'
FBV = HARNESS / 'pipeline' / 'fix_build_verify.py'


def load(path):
    sys.path.insert(0, str(HARNESS / 'kit'))
    sys.path.insert(0, str(Path(path).parent))
    try:
        spec = importlib.util.spec_from_file_location(f'ec_{abs(hash(str(path)))}_{len(sys.modules)}', path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    finally:
        sys.path.pop(0)
        sys.path.pop(0)


STACK = ('goroutine 1634941 [running]:\nruntime/debug.Stack()\n\t/opt/go/src/runtime/debug/stack.go:26 +0x64\n'
         'github.com/deroproject/derohe/cmd/derod/rpc.rpc_internal_error({0x1, 0x2})\n'
         '\t/Users/someone/derohe-Release151/cmd/derod/rpc/rpc_errors.go:30 +0xd4\n'
         'github.com/deroproject/derohe/cmd/derod/rpc.{H}.func1()\n'
         '\t/Users/someone/derohe-Release151/cmd/derod/rpc/{F}:35 +0x2c\n'
         'panic({0x102fd97a0?, 0x103147990?})\n\t/opt/go/src/runtime/panic.go:860 +0x12c\n'
         'github.com/deroproject/derohe/cmd/derod/rpc.{H}({0x1, 0x2}, {{0x3, 0x4}})\n'
         '\t/Users/someone/derohe-Release151/cmd/derod/rpc/{F}:{L} +0x5d8\n'
         'reflect.Value.call({0x1, 0x2, 0x13}, {0x1, 0x4}, {0x1, 0x2, 0x2})\n\t/opt/go/src/reflect/value.go:581 +0x9a0\n')


# a private-LAN address (not reserved, so it must be masked); built at runtime so a privacy scan of the tree that
# flags every LAN literal does not trip on this fixture (it names no real host)
LAN = '.'.join(('10', '20', '30', '40'))


def stack(h, f, line):
    return STACK.replace('{H}', h).replace('{F}', f).replace('{L}', str(line))


def rec(L, T, N, C, M, **kv):
    return json.dumps({'L': L, 'T': T, 'N': N, 'C': C, 'M': M, **kv})


def fixture(d):
    """Write the forged log and call log into d; return (log path, call log path)."""
    start = lambda T: rec('INFO', T, 'derod', 'derod/main.go:160', 'DERO HE daemon :  It is an alpha version')
    lines = [start('2026-10-31T01:00:00.000-0700'),
             rec('INFO', '2026-10-31T01:00:00.001-0700', 'derod', 'derod/main.go:163', '', Version='3.6.0-153+old'),
             rec('ERROR', '2026-10-31T02:00:00.000-0700', 'CORE', 'blockchain/x.go:1', 'old run error', error='e'),
             start('2026-10-31T23:00:00.000-0700'),
             rec('INFO', '2026-10-31T23:00:00.001-0700', 'derod', 'derod/main.go:163', '', Version='3.6.0-153+cur'),
             # before the DST change (-0700)
             rec('ERROR', '2026-10-31T23:10:00.000-0700', 'P2P.outgoing.198.51.100.7:11011', 'p2p/object_errors.go:95',
                 'Call failed GetObject', error='peer answered 0 blocks for 4 requested'),
             rec('INFO', '2026-10-31T23:20:00.000-0700', 'GETWORK', 'rpc/websocket_getwork_server.go:674',
                 'WARNING: no miner connected, this node is not earning', absent_for='10m'),
             # after it (-0800)
             rec('ERROR', '2026-11-03T08:37:44.254-0800', 'RPC', 'rpc/rpc_errors.go:30', 'RPC handler recovered a panic',
                 stack=stack('GetEncryptedBalance', 'rpc_dero_getencryptedbalance.go', 92)),
             rec('ERROR', '2026-11-03T08:37:44.307-0800', 'RPC', 'rpc/rpc_errors.go:30', 'RPC handler recovered a panic',
                 stack=stack('GetEncryptedBalance', 'rpc_dero_getencryptedbalance.go', 92)),
             rec('ERROR', '2026-11-03T09:10:00.000-0800', f'P2P.outgoing.{LAN}:18089', 'p2p/object_errors.go:95',
                 'Call failed GetObject', error='peer answered 1 blocks for 4 requested'),
             rec('ERROR', '2026-11-03T09:11:00.000-0800', 'P2P.outgoing.203.0.113.9:40000', 'p2p/object_errors.go:95',
                 'Call failed GetObject', error='peer answered 2 blocks for 3 requested'),
             rec('INFO', '2026-11-03T09:20:00.000-0800', 'GETWORK', 'rpc/websocket_getwork_server.go:674',
                 'WARNING: no miner connected, this node is not earning', absent_for='1h'),
             rec('INFO', '2026-11-03T09:30:00.000-0800', 'P2P', 'p2p/new.go:1', 'WARNING: something nobody has seen'),
             rec('ERROR', '2026-11-03T09:40:00.000-0800', 'CORE', 'blockchain/store.go:77', 'write failed',
                 error='open /Users/someone/dero-data/mainnet/balances/x: disk full'),
             # a recovered panic at 10:00 while a GetEncryptedBalance call was logged then: a method MISmatch
             rec('ERROR', '2026-11-03T10:00:00.000-0800', 'RPC', 'rpc/rpc_errors.go:30', 'RPC handler recovered a panic',
                 stack=stack('GetSC', 'rpc_dero_getsc.go', 61)),
             # a recovered panic whose matching call was logged at its UTC instant (19:30:00Z = 11:30:00-0800)
             rec('ERROR', '2026-11-03T11:30:00.400-0800', 'RPC', 'rpc/rpc_errors.go:30', 'RPC handler recovered a panic',
                 stack=stack('GetRandomAddress', 'rpc_dero_getrandomaddress.go', 89))]
    log = d / 'derod.log'
    log.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    calls = d / 'calls.jsonl'
    calls.write_text('\n'.join(json.dumps(c) for c in [
        {'t': '2026-11-03T18:00:00.000+00:00', 'method': 'DERO.GetEncryptedBalance', 'topoheight': 7},
        {'t': '2026-11-03T19:30:00.000+00:00', 'method': 'DERO.GetRandomAddress', 'topoheight': None}]) + '\n',
        encoding='utf-8')
    return log, calls


def by_handler(rep, h):
    return [k for k in rep['kinds'] if k.get('handler') == h]


def kats(ec):
    bad = []
    d = Path(tempfile.mkdtemp(prefix='r25ec-'))
    try:
        log, calls = fixture(d)
        recs = list(ec.records([log]))
        rep = ec.census(recs, 1, calls)
        old = ec.census(recs, 2, calls)
        # EC1
        if rep['run']['version'] != '3.6.0-153+cur' or any(k['message'] == 'old run error' for k in rep['kinds']):
            bad.append(f"EC1 run 1 is not the current run: {rep['run']}")
        if not old or [k['message'] for k in old['kinds']] != ['old run error']:
            bad.append('EC1 run 2 must hold only the old run error')
        # EC2
        go = [k for k in rep['kinds'] if k['message'] == 'Call failed GetObject']
        if len(go) != 1 or go[0]['count'] != 3 or go[0]['class'] != 'peer-caused':
            bad.append(f"EC2 GetObject kinds {[(k['component'], k['count'], k['class']) for k in go]}")
        # EC3
        eb = by_handler(rep, 'GetEncryptedBalance')
        if len(eb) != 1 or eb[0]['own_frame'] != 'cmd/derod/rpc/rpc_dero_getencryptedbalance.go:92' or eb[0]['count'] != 2:
            bad.append(f"EC3 own frame {[(k['own_frame'], k['count']) for k in eb]}")
        # EC4
        cls = {k['message'][:30] + '|' + str(k.get('handler')): (k['class'], k['also_node_bug']) for k in rep['kinds']}
        want = {'RPC handler recovered a panic|GetEncryptedBalance': ('self-inflicted', True),
                'RPC handler recovered a panic|GetSC': ('node-bug', True),
                'RPC handler recovered a panic|GetRandomAddress': ('self-inflicted', True),
                'write failed|None': ('node-bug', False),
                'WARNING: no miner connected, t|None': ('operational', False),
                'WARNING: something nobody has |None': ('unclassified', False)}
        for k, v in want.items():
            if cls.get(k) != v:
                bad.append(f'EC4 {k}: {cls.get(k)} want {v}')
        if rep['by_class'].get('self-inflicted') != 3:
            bad.append(f"EC4 by_class {rep['by_class']}")
        # EC5: the GetSC panic at 10:00-0800 (18:00Z) coincides with a GetEncryptedBalance call: method mismatch -> not ours;
        # the GetRandomAddress one matches only through the -0800 offset (naive parsing puts it 8 h off)
        if cls.get('RPC handler recovered a panic|GetSC', ('',))[0] != 'node-bug':
            bad.append('EC5 a call of another method made a panic self-inflicted')
        if abs(ec.epoch('2026-11-03T11:30:00.400-0800') - ec.epoch('2026-11-03T12:30:00.400-0700')) > 1e-6:
            bad.append('EC5 epoch ignores the UTC offset')
        # EC6
        text = json.dumps(rep)
        if ec.leaks(text) or LAN in text or '/Users/' in text or 'stack' in json.dumps([k.keys() for k in rep['kinds']], default=list):
            bad.append(f'EC6 snapshot leaks {ec.leaks(text)[:3]}')
        # EC7
        out = d / 'out.json'
        args = ['error_census.py', '--files', str(log), '--call-log', str(calls), '--out', str(out), '--json-only']
        rc5 = run_main(ec, args)
        clean = d / 'clean.log'
        clean.write_text('\n'.join(log.read_text().splitlines()[3:5]) + '\n', encoding='utf-8')
        rc0 = run_main(ec, ['error_census.py', '--files', str(clean), '--out', str(d / 'o2.json'), '--json-only'])
        rc2 = run_main(ec, ['error_census.py', '--files', str(d / 'none*.log'), '--out', str(d / 'o3.json'), '--json-only'])
        if (rc5, rc0, rc2) != (5, 0, 2) or not out.exists():
            bad.append(f'EC7 exit codes {(rc5, rc0, rc2)} want (5, 0, 2)')
        elif ec.leaks(out.read_text()):
            bad.append('EC6 the written snapshot leaks')
    finally:
        shutil.rmtree(d, ignore_errors=True)
    # EC8
    fbv = FBV.read_text(encoding='utf-8')
    if "'error_census': ((0, 5), 'error_census_*.json')" not in fbv or \
            "[sys.executable, 'harness/intel/error_census.py', '--json-only']" not in fbv or \
            fbv.index('harness/intel/error_census.py') > fbv.index("'harness/intel/area_intel.py', '--live'"):
        bad.append('EC8 S7 does not run error_census.py before area_intel, or JUDGED does not accept 0/5')
    return bad


def run_main(ec, argv):
    old = sys.argv
    sys.argv = argv
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return ec.main()
    finally:
        sys.argv = old


MUTATIONS = [
    ('call window 0 s', 'MATCH_WINDOW_S = 2.0 ', 'MATCH_WINDOW_S = 0.0 '),
    ('own frame = first own frame (no panic gate)', '        if seen_panic and fn.startswith(OWN_MODULE)', '        if fn.startswith(OWN_MODULE)'),
    ('peer address kept in the component', '    return m.group(1) if m else privkit.mask(n)', '    return privkit.mask(n)'),
    ('numbers kept in the kind text', '    return NUM.sub(\'N\', HEX.sub(\'H\', s))[:160]', '    return HEX.sub(\'H\', s)[:160]'),
    ('UTC offset ignored', "    return datetime.datetime.strptime(t, '%Y-%m-%dT%H:%M:%S.%f%z').timestamp()",
     "    return datetime.datetime.strptime(t[:23], '%Y-%m-%dT%H:%M:%S.%f').timestamp()"),
    ('method-blind call match', "(not of or handler_of(of).lower() == c['method'])", '(True)'),
    ('self-inflicted panics not node bugs', "return 'self-inflicted', f\"{c['why']} ({c['anchor']})\", panic_line",
     "return 'self-inflicted', f\"{c['why']} ({c['anchor']})\", False"),
    ('runs not split', '        if is_start(d) and cur:\n            runs.append(cur)', '        if False:\n            runs.append(cur)'),
    ('home paths kept', "    s = privkit.mask(HOME.sub('~', str(s or '')))", "    s = privkit.mask(str(s or ''))"),
    ('exit 0 with node bugs', "    return 5 if rep['node_bug_kinds'] else 0", '    return 0'),
    ('unknown WARNING called operational', "        return 'unclassified', 'a WARNING no rule knows: read it', False",
     "        return 'operational', 'a WARNING no rule knows: read it', False"),
]


def main():
    ec = load(SRC)
    bad = kats(ec)
    for b in bad:
        print('FAIL', b)
    if bad:
        return 3
    print('ok   EC1-EC8')
    src = SRC.read_text(encoding='utf-8')
    missed = 0
    for name, a, b in MUTATIONS:
        if src.count(a) != 1:
            print('INVALID', name, '(find text count', src.count(a), ')')
            missed += 1
            continue
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'intel' / 'error_census.py'
            p.parent.mkdir()
            shutil.copy2(HARNESS / 'intel' / 'log_intel.py', p.parent / 'log_intel.py')
            p.write_text(src.replace(a, b, 1), encoding='utf-8')
            try:
                m = load(p)
                m.HARNESS = HARNESS
                r = kats(m)
            except Exception as e:                       # noqa: BLE001 — a mutant that does not load is INVALID
                print('INVALID', name, type(e).__name__, e)
                missed += 1
                continue
        print('CAUGHT' if r else 'MISSED', name, (r[:1] if r else ''))
        missed += 0 if r else 1
    print(f'r25 error-census KATs: 8/8 ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
