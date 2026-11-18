#!/usr/bin/env python3
"""test_gt_harness_r33.py — R33 harness work items (artifacts/dero-game-theory-rft.md §7 GT-B3, GT-B11, GT-B15, GT-B17,
GT-B18; §8.2 R33-W3/W11/W15/W17/W18). GT-B20 has its own KAT: harness/kat/test_version_bump_r33.py.

  H3  gas_census: per network class and contract:entrypoint the call count, the gas-estimate count, min/median/max of
      gasstorage and of the fee paid, and fee - gasstorage; a sim record never enters the mainnet census; an unreadable
      record is skipped; the real records give a mainnet census of their own (no address, no txid in the output)
  H11 time_to_coins: --hs replaces the R30 quiet-box rate; hs_from_rate inverts estimate(); the earn-log rate sums the
      increase between ticks and counts a counter drop as a relaunch (from 0); --from-earn-log drives the estimate
  H15 audit task 3 (SC balance turnstile): deterministic, independent of the SCID order and case, a moved balance
      changes the answer; the topoheight is refused below the pruned floor, inside the settle depth, and bad / no SCIDs
      are refused before any GetSC; GetSC is read AT the topoheight
  H17 gt_earn's credit counter: (base reward + the block's fees) // len(miniblocks), the integrator's final share
      excluded (the chain-audit rule, cycle_audit.chain_mined); no reward // 10 counter left in gt_earn
  H18 gtlib.stale_bins: with a recorded <bin>.srchash a touched source is NOT stale and a changed source (the command,
      an in-module package it imports, a vendored package) IS; without a hash the file-time rule applies;
      rebuild_bins records the hash
All inputs are forged in memory or a temporary directory; nothing is fetched; nothing outside it is written.
  python3 -I harness/kat/test_gt_harness_r33.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, hashlib, importlib.util, io, json, os, shutil, subprocess, sys, tempfile, types, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
PATHS = {'census': 'harness/gametheory/gas_census.py', 'ttc': 'harness/gametheory/time_to_coins.py',
         'atask': 'harness/gametheory/audit_tasks.py', 'earn': 'playbooks/gt_earn.py', 'lib': 'playbooks/gtlib.py'}
COPY_DIRS = ['harness/gametheory', 'playbooks', 'harness/kit']
COPY_FILES = ['harness/runtime/gt_reward_live.json']
FAKE = 'deto1qy' + 'q' * 58 + 'fake'


def _mod(root, key):
    for m in ('gtlib', 'banguard', 'cycle_audit', 'sizing', 'reward_intel'):
        sys.modules.pop(m, None)
    sys.path[:] = [p for p in sys.path if not (p.endswith('harness/gametheory') or p.endswith('/playbooks'))]
    for sub in ('playbooks', 'harness/gametheory'):
        sys.path.insert(0, str(Path(root) / sub))
    spec = importlib.util.spec_from_file_location(f'gt33h_{key}_{uuid.uuid4().hex[:6]}', Path(root) / PATHS[key])
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _with_env(fn):
    """run fn(d) with a forged ban list and temp GT dirs (the playbook modules import gtlib)."""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / 'banned.json'
        f.write_text(json.dumps({'banned_sha256': [hashlib.sha256(FAKE.encode()).hexdigest()]}))
        keep = {k: os.environ.get(k) for k in ('GT_HOME', 'GT_WALLETS', 'GT_BANNED_FILE')}
        os.environ.update(GT_HOME=str(Path(d) / 'home'), GT_WALLETS=str(Path(d) / 'w'), GT_BANNED_FILE=str(f))
        try:
            return fn(d)
        finally:
            for k, v in keep.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


def kat_h3(over):
    root = Path(over.get('root') or ROOT)
    C = _mod(root, 'census')
    mn = {'network': 'mainnet', 'calls': [
        {'sc': 'prize', 'entry': 'Enter', 'gas_est': {'gascompute': 10, 'gasstorage': 271}, 'fees_set': 600, 'fee': 600},
        {'sc': 'prize', 'entry': 'Enter', 'fee': 339},                                       # an R32 call: no estimate
        {'sc': 'prize', 'entry': 'Enter', 'gas_est': {'gascompute': 12, 'gasstorage': 270}, 'fees_set': None, 'fee': 400},
        {'sc': 'attest', 'entry': 'install', 'fee': 12571}]}
    sim = {'network': 'sim', 'calls': [{'sc': 'prize', 'entry': 'Enter', 'gas_est': {'gasstorage': 9999}, 'fee': 1}],
           'proofs': [{'sc': 'pool', 'entry': 'ProveBlock', 'gas_est': {'gascompute': 6, 'gasstorage': 1700}, 'fees_set': 2300, 'fee': 2300}]}
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / 'gt_cycle_mainnet_20261116T000000.json').write_text(json.dumps(mn))
        (Path(d) / 'gt_pool_sim_20261117T000000.json').write_text(json.dumps(sim))
        (Path(d) / 'gt_pool_sim_20261117T000001.json').write_text('{not json')
        recs, bad = C.records(d)
        c = C.census(recs)
        rc = C.main(['--runtime', d, '--out', str(Path(d) / 'out.json')])
        written = json.loads((Path(d) / 'out.json').read_text()) if (Path(d) / 'out.json').exists() else {}
    e = c.get('mainnet', {}).get('entrypoints', {}).get('prize:Enter', {})
    s = c.get('sim', {}).get('entrypoints', {})
    real = C.census(C.records(ROOT / 'harness/runtime')[0])
    real_text = json.dumps(real)
    ok = (bad == ['gt_pool_sim_20261117T000001.json'] and e.get('calls') == 3 and e.get('with_gas_est') == 2
          and e.get('gasstorage') == {'min': 270, 'median': 270.5, 'max': 271, 'n': 2}
          and e.get('fee') == {'min': 339, 'median': 400, 'max': 600, 'n': 3}
          and e.get('fee_minus_gasstorage') == {'min': 130, 'median': 229.5, 'max': 329, 'n': 2} and e.get('fees_set') == 1
          and c['mainnet']['entrypoints']['attest:install']['gasstorage'] is None
          and set(s) == {'prize:Enter', 'pool:ProveBlock'} and 'pool:ProveBlock' not in c['mainnet']['entrypoints']
          and s['pool:ProveBlock']['fee_minus_gasstorage']['min'] == 600
          and rc == 0 and written.get('census') == c
          and real.get('mainnet', {}).get('calls', 0) > 0 and all('mainnet' in n for n in real['mainnet']['records'])
          and 'dero1' not in real_text and 'txid' not in real_text)
    return ok, e, sorted(s), bad, real.get('mainnet', {}).get('calls')


def _earn_log(d):
    rows = [{'kind': 'registered', 'ts': '2026-11-15T03:00:00-08:00'},
            {'kind': 'earn_tick', 'ts': '2026-11-15T03:00:00-08:00', 'chain_credited': {'m1': 0}},
            {'kind': 'earn_tick', 'ts': '2026-11-15T03:30:00-08:00', 'chain_credited': {'m1': 30750}},
            {'kind': 'earn_tick', 'ts': '2026-11-15T04:00:00-08:00', 'chain_credited': {'m1': 6150}},   # relaunch
            {'kind': 'earn_tick', 'ts': '2026-11-15T04:30:00-08:00', 'chain_credited': {'m1': 12300}}]
    f = Path(d) / 'events.jsonl'
    f.write_text('\n'.join(json.dumps(r) for r in rows) + '\nnot json\n')
    return f


def kat_h11(over):
    root = Path(over.get('root') or ROOT)
    T = _mod(root, 'ttc')
    D, ht, bms, fms = 3443669, 7916000, 18000.0, 8000.0
    quiet = T.estimate(D, ht, 8, 80, 1.0, bms, fms)
    given = T.estimate(D, ht, 8, 80, 1.0, bms, fms, hs=22400)
    back = T.hs_from_rate(given['dero_per_day'], D, ht, bms, fms)
    with tempfile.TemporaryDirectory() as d:
        f = _earn_log(d)
        rate, hours = T.earn_log_rate(f)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = T.main(['--difficulty', str(D), '--height', str(ht), '--from-earn-log', str(f)])
        out = json.loads(buf.getvalue())
    want_rate = (30750 + 6150 + 6150) / 100000 / 1.5 * 24
    ok = (quiet['our_hs'] == round(5344 * 8 * 0.8) and given['our_hs'] == 22400 and given['fraction'] < quiet['fraction']
          and back is not None and abs(back - 22400) / 22400 < 0.01
          and rate is not None and abs(rate - want_rate) < 1e-9 and abs(hours - 1.5) < 1e-9
          and rc == 0 and out.get('measured', {}).get('measured_dero_per_day') == round(want_rate, 3)
          and out['our_hs'] == out['measured']['effective_hs'] and out['our_hs'] != quiet['our_hs']
          and abs(out['dero_per_day'] - want_rate) < 0.01 and '/' not in out['measured']['earn_log'].split('/', 1)[1])
    return ok, quiet['our_hs'], given['our_hs'], round(back or 0), rate, out.get('measured')


def kat_h15(over):
    root = Path(over.get('root') or ROOT)
    A = _mod(root, 'atask')
    s1, s2, s3 = 'a' * 64, 'b' * 64, '0' * 63 + '1'
    bal = {s1: 1000, s2: 96000, s3: 0}
    a1 = A.turnstile_answer(bal)
    a2 = A.turnstile_answer({s3.upper(): 0, s2: 96000, s1.upper(): 1000})
    a3 = A.turnstile_answer(dict(bal, **{s2: 95999}))
    calls = []

    def rpc(m, p=None):
        calls.append((m, dict(p or {})))
        if m == 'DERO.GetInfo':
            return {'height': 7900100, 'topoheight': 7900100}
        return {'balance': bal[p['scid']], 'status': 'OK'}
    got, why = A.compute(3, None, None, rpc=rpc, scids=[s2, s1, s1.upper(), s3], topo=7900050)
    sc_calls = [p for m, p in calls if m == 'DERO.GetSC']
    n_before = len(calls)
    refusals = [A.compute(3, None, None, rpc=rpc, scids=[s1], topo=t)[1] for t in (7900090, 100, 0)]
    bad = [A.compute(3, None, None, rpc=rpc, scids=x, topo=7900050)[1] for x in (['xyz'], [], ['c' * 64] * 1 + [f'{i:064x}' for i in range(40)])]
    reads_after = [m for m, _ in calls[n_before:] if m == 'DERO.GetSC']
    ok = (a1[0] == a2[0] and len(a1[0]) == 64 and a1[0] == a1[0].lower() and a3[0] != a1[0]
          and a1[1] == {'scids': 3, 'total_balance': 97000} and why is None and got['answer'] == a1[0]
          and got['summary']['total_balance'] == 97000 and len(sc_calls) == 3 and all(p['topoheight'] == 7900050 for p in sc_calls)
          and all(r is not None for r in refusals + bad) and reads_after == [] and A.TASKS.get(3) == 'turnstile')
    return ok, a1[1], why, refusals, bad


def kat_h17(over):
    root = Path(over.get('root') or ROOT)

    def body(d):
        E = _mod(root, 'earn')
        blocks = {100: ['a1'] * 9 + ['a1'], 101: ['a2', 'x', 'a1'], 102: ['x'] * 10}
        fee = {100: 0, 101: 4200, 102: 0}

        def rpc(m, p):
            if m == 'DERO.GetBlockHeadersRange':
                return {'headers': [{'topoheight': t, 'fees': fee[t]} for t in range(p['start_topoheight'], p['end_topoheight'] + 1)]}
            return {'block_header': {'miners': blocks[p['height']], 'reward': 30750, 'topoheight': p['height']}}
        got = E.chain_credits(rpc, 100, 102, {'m1': 'a1', 'm2': 'a2'})
        empty = E.chain_credits(lambda m, p: (_ for _ in ()).throw(AssertionError('no read for an empty range')), 103, 102, {'m1': 'a1'})
        return got, empty
    got, empty = _with_env(body)
    src = (root / PATHS['earn']).read_text()
    no_old = "reward', 0)) // 10" not in src
    wired = src.count('chain_credits(lambda m, p: rpc_call(daemon, m, p)') == 2
    ok = got == {'m1': 9 * 3075 + 11650, 'm2': 11650} and empty == {'m1': 0} and no_old and wired
    return ok, got, empty, no_old, wired


def _repo(r):
    (r / 'cmd/gt-wallet').mkdir(parents=True)
    (r / 'lib').mkdir()
    (r / 'vendor/x.org/y').mkdir(parents=True)
    (r / 'go.mod').write_text('module example.com/m\n\ngo 1.17\n')
    (r / 'cmd/gt-wallet/main.go').write_text('package main\n\nimport (\n\t"fmt"\n\tl "example.com/m/lib"\n)\n\nfunc main() { fmt.Println(l.X) }\n')
    (r / 'cmd/gt-wallet/main_test.go').write_text('package main\n')
    (r / 'lib/lib.go').write_text('package lib\n\nimport "x.org/y"\n\nvar X = y.Y\n')
    (r / 'vendor/x.org/y/y.go').write_text('package y\n\nvar Y = 1\n')
    (r / 'other.go').write_text('package other\n')


def kat_h18(over):
    import time as _time
    root = Path(over.get('root') or ROOT)

    def body(d):
        g = _mod(root, 'lib')
        r, b = Path(d) / 'repo', Path(d) / 'bin'
        _repo(r)
        b.mkdir()
        (b / 'gt-wallet').write_text('bin')
        now = _time.time()
        os.utime(b / 'gt-wallet', (now, now))
        for f in r.rglob('*.go'):
            os.utime(f, (now - 100, now - 100))
        res = {'files': sorted(p.relative_to(r).as_posix() for p in g.build_sources(r, 'cmd/gt-wallet'))}
        (b / 'gt-wallet.srchash').write_text(g.source_hash(r, 'cmd/gt-wallet') + '\n')
        res['fresh'] = g.stale_bins(b, r, ['gt-wallet'])
        os.utime(r / 'cmd/gt-wallet/main.go', (now + 50, now + 50))                 # touched, content as built
        res['touched'] = g.stale_bins(b, r, ['gt-wallet'])
        for rel in ('lib/lib.go', 'vendor/x.org/y/y.go', 'cmd/gt-wallet/main.go'):
            t0 = (r / rel).read_text()
            (r / rel).write_text(t0 + '// edited\n')
            res[rel] = [s[0] for s in g.stale_bins(b, r, ['gt-wallet'])]
            (r / rel).write_text(t0)
        (r / 'other.go').write_text('package other // edited\n')                   # not imported: no rebuild
        (r / 'cmd/gt-wallet/main_test.go').write_text('package main // edited\n')  # a test file: no rebuild
        res['unrelated'] = g.stale_bins(b, r, ['gt-wallet'])
        (b / 'gt-wallet.srchash').unlink()
        res['fallback'] = [s[0] for s in g.stale_bins(b, r, ['gt-wallet'])]           # no hash: main.go is newer
        built = []

        def fake_run(argv, cwd=None, check=None, timeout=None):
            built.append(argv)
            Path(argv[argv.index('-o') + 1]).write_text('newbin')
            return types.SimpleNamespace(returncode=0)
        g.subprocess = types.SimpleNamespace(run=fake_run)
        g.rebuild_bins([('gt-wallet', None)], b, r)
        res['recorded'] = (b / 'gt-wallet.srchash').read_text().strip() == g.source_hash(r, 'cmd/gt-wallet')
        res['after_rebuild'] = g.stale_bins(b, r, ['gt-wallet'])
        res['built'] = len(built)
        return res
    res = _with_env(body)
    ok = (res['files'] == ['cmd/gt-wallet/main.go', 'go.mod', 'lib/lib.go', 'vendor/x.org/y/y.go']
          and res['fresh'] == [] and res['touched'] == []
          and all(res[k] == ['gt-wallet'] for k in ('lib/lib.go', 'vendor/x.org/y/y.go', 'cmd/gt-wallet/main.go'))
          and res['unrelated'] == [] and res['fallback'] == ['gt-wallet'] and res['recorded'] and res['after_rebuild'] == []
          and res['built'] == 1)
    return ok, res


KATS = [('H3', kat_h3), ('H11', kat_h11), ('H15', kat_h15), ('H17', kat_h17), ('H18', kat_h18)]
OWNERS = {'r33 census': ['H3'], 'r33 ttc': ['H11'], 'r33 turnstile': ['H15'], 'r33 earnsplit': ['H17'], 'r33 srchash': ['H18']}
MUTATIONS = [
    ('census', "    return 'mainnet' if str(rec.get('network', '')).lower() == 'mainnet' else 'sim'", "    return 'mainnet'",
     'r33 census: sim records are mixed into the mainnet census'),
    ('census', "                    r['margin'].append(fee - gs)", "                    r['margin'].append(fee)",
     'r33 census: the margin ignores the storage-gas estimate'),
    ('census', "                if fee is not None:\n                    r['fee'].append(fee)", "                if fee is not None and gs is not None:\n                    r['fee'].append(fee)",
     'r33 census: the fee of a call without an estimate is dropped'),
    ('census', "        for lst in LISTS:", "        for lst in ('calls',):", 'r33 census: the gt_pool proofs are left out'),
    ('ttc', "    h = float(hs) if hs is not None else H_PER_CPU_S * threads * cpu_max / 100.0", "    h = H_PER_CPU_S * threads * cpu_max / 100.0",
     'r33 ttc: --hs is ignored (the R30 quiet-box rate stays)'),
    ('ttc', "    return f * H / (1 - f)", "    return f * H", 'r33 ttc: the measured rate is inverted without our own share of the hashrate'),
    ('ttc', "        hs = hs_from_rate(rate, D, H, block_ms, final_ms)", "        hs = None", 'r33 ttc: the earn-log rate never reaches the estimate'),
    ('atask', "    return sorted({str(s).strip().lower() for s in scids or [] if str(s).strip()})",
     "    return [str(s).strip() for s in scids or [] if str(s).strip()]", 'r33 turnstile: the answer depends on the SCID order and case'),
    ('atask', "    if topo > tip_topo - SETTLE:", "    if False:", 'r33 turnstile: an unsettled topoheight is audited'),
    ('atask', "    if topo < max(floor, 1):", "    if False:", 'r33 turnstile: a pruned topoheight is audited'),
    ('atask', "    return {s: int(rpc('DERO.GetSC', {'scid': s, 'code': False, 'variables': False, 'topoheight': int(topo)}).get('balance') or 0)",
     "    return {s: int(rpc('DERO.GetSC', {'scid': s, 'code': False, 'variables': False}).get('balance') or 0)",
     'r33 turnstile: GetSC reads the tip, not the settled topoheight'),
    ('earn', "    import cycle_audit\n    return cycle_audit.chain_mined(rpc_fn, lo, hi, addrs)",
     "    out = {w: 0 for w in addrs}\n    for x in range(lo, hi + 1):\n        bh = rpc_fn('DERO.GetBlock', {'height': x})['block_header']\n"
     "        ms = bh.get('miners', [])\n        for m in (ms[:-1] if len(ms) == 10 else ms):\n            for w, ad in addrs.items():\n"
     "                if m == ad:\n                    out[w] += int(bh.get('reward', 0)) // 10\n    return out",
     'r33 earnsplit: the credit counter goes back to reward // 10'),
    ('earn', "                credited += chain_credits(lambda m, p: rpc_call(daemon, m, p), seen + 1, h - 2, {a.wallet: addr})[a.wallet]",
     "                credited += sum(int(rpc_call(daemon, 'DERO.GetBlock', {'height': x})['block_header'].get('reward', 0)) // 10 for x in range(seen + 1, h - 1))",
     'r33 earnsplit: the one-wallet earn loop keeps its own reward // 10 counter'),
    ('lib', "            if hp.read_text().strip() != source_hash(root, BIN_SOURCES[b]):", "            if False:",
     'r33 srchash: a recorded hash never makes a binary stale'),
    ('lib', "        if bp.exists() and hp.is_file():", "        if False:", 'r33 srchash: the recorded hash is ignored (file times decide)'),
    ('lib', "                    todo.append(root / ip[len(mod):].lstrip('/'))", "                    pass",
     'r33 srchash: an imported in-module package is not hashed'),
    ('lib', "                elif (root / 'vendor' / ip).is_dir():", "                elif False:", 'r33 srchash: a vendored package is not hashed'),
    ('lib', "        htmp.write_text(sh + '\\n')\n        os.replace(htmp, bin_dir / (b + SRCHASH_SUFFIX))", "        pass",
     'r33 srchash: rebuild_bins records no hash'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_gt33h', ROOT / 'harness/kit/katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


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
    if argv[:1] == ['--kats-json']:                                # one mutant's run, in a fresh interpreter
        print(json.dumps([n for n, ok, _ in run_kats({'root': argv[1]}) if not ok]))
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:400]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr33 gt-harness KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='gt33h-mut-') as d:
            for rel in COPY_DIRS:
                shutil.copytree(ROOT / rel, Path(d) / rel, ignore=shutil.ignore_patterns('__pycache__'))
            for rel in COPY_FILES:
                (Path(d) / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(ROOT / rel, Path(d) / rel)
            (Path(d) / PATHS[key]).write_text(text.replace(find, repl, 1), encoding='utf-8')
            p = subprocess.run([sys.executable, '-I', __file__, '--kats-json', d], capture_output=True, text=True, timeout=600)
            try:
                failed = json.loads(p.stdout.strip().splitlines()[-1])
            except (ValueError, IndexError):
                failed = [n for n, _ in KATS]                       # the mutant broke the run: every KAT failed
        verdict, cpl = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r33 gt-harness KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
