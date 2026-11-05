#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the R26 harness + tooling fixes (dero-rft §0.9 rule 1; §7 B90, B92, B93, B98,
B101, B104, B105, B116, B117, B119).

  HT1 B98 fix_build_verify.shadow_teardown: a forged shadow base (control + candidate, each with data/, the copied
      derod, console.txt, derod.log) and one still-running child: the child is stopped, data/ and derod are removed,
      the logs are kept, a node that never started (no proc) is fine; s5_shadow calls it in a `finally` and
      _s5_shadow registers its nodes before any of them starts.
  HT2 B101 fix_build_verify.paused_skip: miner_intel / miner_runs are skipped only while the miner track is paused AND
      their input file is absent; an active track, a present log or another step runs; s7_project consults it first.
  HT3 B101 log_intel.lines/ts: records across the DST change sort by instant (01:20-0700, 01:30-0700, 01:10-0800),
      not by the local-time string, and ts() subtracts across it (2,400 s); a value without an offset still parses.
  HT4 B93 gen_deroarch: inputs_time() reads SOURCE_DATE_EPOCH, else the HEAD commit time of the tree (a forged repo);
      render() never calls datetime.now(); build() refreshes the corpus index BEFORE it computes the fingerprint.
  HT5 B105 area_intel: a 'network' metric's regression / live alert becomes a medium network-observation whose
      suggested row is an OBSERVATION; a 'node' metric is unchanged; an unknown class is a registry error; the live
      registry classes the observatory KPIs (integrator_only_final_share, lag_max) network and peers_active node.
  HT6 B104 kit/rpcparams: on a forged Go tree, the B104 call (GetBlockHeadersRange with start/end) is a problem, the
      json-tag spelling is not; an unknown method, params to a no-param handler, an object to a positional handler
      are problems; tuple-table and request-body literals are found; a `type A B` alias resolves; the live tree has
      0 problems over >= 40 literal calls.
  HT7 B116 disclosure_track: an EARLIER round's fact whose quote moved after that round's head is OK-AT-HEAD (head
      from the track's round_heads or the registry's head_after), not DRIFT; without a head it is DRIFT; the same
      anchor in the CURRENT round stays DRIFT; a quote missing from the tree stays MISSING.
  HT8 B117 tooling_intel.py / mine_triage.py: `--help` exits 0 and writes nothing (isolated copies); an unknown
      tooling_intel flag exits 2.
  HT9 B119 kit/privkit.scrub_argv: a forged derod argv loses its home path, node tag (both spellings), integrator
      address and peer address (pseudonymised), keeps pid and every other flag; mine_runtime.capture writes the
      scrubbed process lines; fix_build_verify.record_cmds scrubs the shadow candidate's LAN dial address.
  HT10 B92 tooling_intel.skill_kpis: a skill declaring a paused track is not required to be fresh, every other skill
      is, at least one must be; a skill over SKILL_MAX_LINES is reported and is a target violation.
  HT11 B90 mine_evolution.ORDER lists every registry round that is not planned AND the next planned round.
  HT12 B131 tooling_intel.scrub_plants carries the machine-model and agent-tool-path shapes (box model, the R1 row's
      quoted claim, the lower-case node tag, the memory-link directory, both session settings files) and the clean
      control keeps their near-misses; with the configured scrubber present, the planted control has 0 false negatives
      and 0 false positives (pending, not failed, on a machine without it).

  python3 -I harness/kat/test_harness_tooling_r26.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import ast, copy, importlib.util, json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
FBV = HARNESS / 'pipeline' / 'fix_build_verify.py'
LOGI = HARNESS / 'intel' / 'log_intel.py'
GDA = HARNESS / 'gen_deroarch.py'
AREA = HARNESS / 'intel' / 'area_intel.py'
RPCP = HARNESS / 'kit' / 'rpcparams.py'
DISC = HARNESS / 'intel' / 'disclosure_track.py'
TOOL = HARNESS / 'intel' / 'tooling_intel.py'
TRIAGE = HARNESS / 'miners' / 'mine_triage.py'
PRIV = HARNESS / 'kit' / 'privkit.py'
RUNTIME_MINER = HARNESS / 'miners' / 'mine_runtime.py'
EVO = HARNESS / 'miners' / 'mine_evolution.py'
HOME_PLANT = '/' + 'Users' + '/someone'                  # a generic home-path shape (no real user)
SALT = 's' * 64


def load(path, name='ht26'):
    spec = importlib.util.spec_from_file_location(f'{name}_{abs(hash(str(path)))}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


def extract(path, names, assigns=(), extra=None):
    """the named top-level functions (and assignments) of a large module, compiled alone: fix_build_verify.py and
    gen_deroarch.py do work at import"""
    tree = ast.parse(Path(path).read_text(encoding='utf-8'))
    body = [n for n in tree.body if (isinstance(n, ast.FunctionDef) and n.name in names) or
            (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in assigns for t in n.targets)) or
            (isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and n.target.id in assigns)]
    import datetime, re, signal
    ns = {'Path': Path, 'sys': sys, 'os': os, 'shutil': shutil, 'signal': signal, 'subprocess': subprocess,
          'datetime': datetime, 're': re, 'json': json, 'HARNESS': HARNESS, 'ROOT': ROOT, **(extra or {})}
    exec(compile(ast.Module(body=body, type_ignores=[]), str(path), 'exec'), ns)   # noqa: S102 — this repo's own code
    return type('M', (), {n: (staticmethod(ns[n]) if callable(ns[n]) else ns[n]) for n in list(names) + list(assigns)})


def fn_node(path, name):
    tree = ast.parse(Path(path).read_text(encoding='utf-8'))
    return next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)


def calls(node):
    return [c.func.id if isinstance(c.func, ast.Name) else (c.func.attr if isinstance(c.func, ast.Attribute) else '')
            for c in ast.walk(node) if isinstance(c, ast.Call)]


# ───────────────────────────── HT1 B98 ─────────────────────────────
def ht1(P):
    F = extract(P['fbv'], ['shadow_teardown'])
    with tempfile.TemporaryDirectory() as d:
        base = Path(d) / 'dero-shadow-x'
        for n in ('control', 'candidate'):
            (base / n / 'data' / 'mainnet').mkdir(parents=True)
            (base / n / 'data' / 'mainnet' / 'blob').write_bytes(b'x' * 1024)
            (base / n / 'derod').write_bytes(b'binary')
            (base / n / 'console.txt').write_text('console\n')
            (base / n / 'derod.log').write_text('{"L":"INFO"}\n')
        child = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.readline()'], stdin=subprocess.PIPE)
        nodes = {'control': {'proc': child}, 'candidate': {}}
        try:
            removed = F.shadow_teardown(nodes, base)
            stopped = child.poll() is not None           # read BEFORE the KAT's own cleanup below
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
        left = sorted(str(p.relative_to(base)) for p in base.rglob('*'))
        none = F.shadow_teardown({}, Path(d) / 'absent')
    want_left = ['candidate', 'candidate/console.txt', 'candidate/derod.log', 'control', 'control/console.txt', 'control/derod.log']
    s5 = fn_node(P['fbv'], 's5_shadow')
    fin = [c for t in ast.walk(s5) if isinstance(t, ast.Try) for f in t.finalbody for c in calls(f)]
    inner = fn_node(P['fbv'], '_s5_shadow')
    reg_line = next((n.lineno for n in ast.walk(inner) if isinstance(n, ast.Assign) and any(
        isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and t.value.id == 'live' for t in n.targets)), None)
    popen_line = min((n.lineno for n in ast.walk(inner) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                      and n.func.attr == 'Popen'), default=None)
    ok = (stopped and left == want_left and len(removed) == 4 and none == [] and 'shadow_teardown' in fin
          and '_s5_shadow' in calls(s5) and reg_line is not None and popen_line is not None and reg_line < popen_line)
    return ok, f'stopped {stopped} left {left} removed {len(removed)} finally {fin} live-reg line {reg_line} < Popen {popen_line}'


# ───────────────────────────── HT2 B101 ─────────────────────────────
def ht2(P):
    F = extract(P['fbv'], ['paused_skip'], ['MINER_STEP_INPUTS'])
    with tempfile.TemporaryDirectory() as d:
        r = Path(d)
        a = F.paused_skip('harness/intel/miner_intel.py', 'paused', r)
        b = F.paused_skip('harness/intel/miner_runs.py', 'paused', r)
        c = F.paused_skip('harness/intel/miner_intel.py', 'active', r)
        e = F.paused_skip('harness/intel/log_intel.py', 'paused', r)
        (r / 'bin').mkdir()
        (r / 'bin' / 'dero-miner.log').write_text('{}\n')
        f = F.paused_skip('harness/intel/miner_intel.py', 'paused', r)
        g = F.paused_skip('harness/intel/miner_runs.py', 'paused', r)
    s7 = fn_node(P['fbv'], 's7_project')
    loop = next((n for n in ast.walk(s7) if isinstance(n, ast.For) and isinstance(n.target, ast.Name) and n.target.id == 'st'), None)
    first = loop is not None and 'paused_skip' in calls(loop.body[0]) and any(isinstance(x, ast.Continue) for x in ast.walk(loop.body[1]))
    ok = bool(a) and bool(b) and c is None and e is None and f is None and bool(g) and first
    return ok, f'paused/absent {bool(a)},{bool(b)} active {c} other {e} present {f} runs-absent {bool(g)} loop-first {first}'


# ───────────────────────────── HT3 B101 DST ─────────────────────────────
def ht3(P):
    L = load(P['logi'], 'logi')
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 'derod.log'
        recs = [{'T': '2026-11-01T01:10:00.000-0800', 'M': 'c'}, {'T': '2026-11-01T01:30:00.000-0700', 'M': 'b'},
                {'T': '2026-11-01T01:20:00.000-0700', 'M': 'a'}, {'M': 'no time'}]
        p.write_text(''.join(json.dumps(r) + '\n' for r in recs))
        got = [r['M'] for r in L.lines([p])]
    dt = L.ts('2026-11-01T01:10:00.000-0800') - L.ts('2026-11-01T01:30:00.000-0700')
    naive = isinstance(L.ts('2026-11-01T01:10:00.000'), float)
    ok = got == ['no time', 'a', 'b', 'c'] and dt == 2400 and naive
    return ok, f'order {got} dt {dt} naive-parses {naive}'


# ───────────────────────────── HT4 B93 ─────────────────────────────
def ht4(P):
    G = extract(P['gda'], ['inputs_time'])
    t1 = G.inputs_time(ROOT, {'SOURCE_DATE_EPOCH': '1700000000'})
    with tempfile.TemporaryDirectory() as d:
        env = {**os.environ, 'GIT_AUTHOR_DATE': '2026-01-02T03:04:05+00:00', 'GIT_COMMITTER_DATE': '2026-01-02T03:04:05+00:00',
               'GIT_AUTHOR_NAME': 'k', 'GIT_AUTHOR_EMAIL': 'k@k', 'GIT_COMMITTER_NAME': 'k',
               'GIT_COMMITTER_EMAIL': 'k@k'}
        subprocess.run(['git', 'init', '-q', d], check=True, env=env)
        (Path(d) / 'f').write_text('x\n')
        subprocess.run(['git', '-C', d, 'add', 'f'], check=True, env=env)
        subprocess.run(['git', '-C', d, 'commit', '-q', '-m', 'k'], check=True, env=env)
        t2 = G.inputs_time(d, {})
        t3 = G.inputs_time(d, {})
    rnd = fn_node(P['gda'], 'render')
    no_now = not any(isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr == 'now'
                     for c in ast.walk(rnd))
    bld = fn_node(P['gda'], 'build')
    order = [(n.lineno, 'prep') for n in ast.walk(bld) if isinstance(n, ast.Call) and any(
        isinstance(x, ast.Constant) and x.value == 'prep_corpus.py' for x in ast.walk(n))]
    order += [(n.lineno, 'fp') for n in ast.walk(bld) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'fingerprint']
    order.sort()
    prep_first = bool(order) and order[0][1] == 'prep' and any(k == 'fp' for _, k in order)
    ok = int(t1.timestamp()) == 1700000000 and int(t2.timestamp()) == 1767323045 and t2 == t3 and no_now and prep_first
    return ok, f'epoch {int(t1.timestamp())} head {int(t2.timestamp())} stable {t2 == t3} render-no-now {no_now} order {order}'


# ───────────────────────────── HT5 B105 ─────────────────────────────
def ht5(P):
    A = load(P['area'], 'area')
    net = {'id': 'lag_max', 'class': 'network'}
    node = {'id': 'peers_active'}
    k1 = A.classed(net, 'metric-regression', 'high', 'lag_max: 0 -> 82442')
    k2 = A.classed(net, 'live-alert', 'high', 'lag_max = 82442 trips > 25')
    k3 = A.classed(node, 'metric-regression', 'high', 'peers_active: 15 -> 3')
    r1 = A.suggested_row(k1[0], k1[2], 'peers', 'x:1', 'r26')
    r3 = A.suggested_row(k3[0], k3[2], 'peers', 'x:1', 'r26')
    reg = A.load_registry(ROOT)
    e0, _ = A.validate(reg, ROOT)
    bad = copy.deepcopy(reg)
    next(a for a in bad['areas'] if a['id'] == 'peers')['metrics'][0]['class'] = 'bogus'
    e1, _ = A.validate(bad, ROOT)
    cls = {(a['id'], m['id']): m.get('class', 'node') for a in reg['areas'] for m in a.get('metrics', [])}
    live = (cls.get(('consensus', 'integrator_only_final_share')), cls.get(('peers', 'lag_max')), cls.get(('peers', 'peers_active')))
    ok = (k1[:2] == ('network-observation', 'medium') and k2[:2] == ('network-observation', 'medium') and 'network KPI' in k1[2]
          and k3 == ('metric-regression', 'high', 'peers_active: 15 -> 3') and 'OBSERVATION (network' in r1 and 'OPEN (self-detected' in r3
          and not e0 and any('class must be one of' in x for x in e1) and live == ('network', 'network', 'node'))
    return ok, f'{k1[:2]} {k2[:2]} {k3[:2]} rows {r1[-60:]!r} / {r3[-40:]!r} errors {len(e0)}->{len(e1)} live {live}'


# ───────────────────────────── HT6 B104 ─────────────────────────────
GO_WS = '''package rpc
var servicemux = handler.ServiceMap{
	"DERO": handler.Map{
		"Echo":                 handler.New(Echo),
		"GetInfo":              handler.New(GetInfo),
		"GetBlockHeadersRange": handler.New(GetBlockHeadersRange),
		"GetGasEstimate":       handler.New(GetGasEstimate),
	},
	"DAEMON": handler.Map{
		"Other": handler.New(Other),
	},
}
func Echo(ctx context.Context, args []string) string { return "" }
func GetInfo(ctx context.Context) (result GetInfo_Result, err error) { return }
'''
GO_EXP = '''package rpc
type GetBlockHeadersRange_Params struct {
	Start int64 `json:"start_topoheight"`
	End   int64 `json:"end_topoheight"`
}
func GetBlockHeadersRange(ctx context.Context, p GetBlockHeadersRange_Params) (result X, err error) { return }
func GetGasEstimate(ctx context.Context, p rpc.GasEstimate_Params) (result rpc.Y, err error) { return }
'''
GO_RPC = '''package rpc
type GasEstimate_Params Transfer_Params // same structure
type Transfer_Params struct {
	SC_ID string `json:"scid"`
	Ringsize uint64 `json:"ringsize,omitempty"`
}
'''
PY_CALLS = '''
def probe(rpc, url):
    rpc(url, 'DERO.GetBlockHeadersRange', {'start': 1, 'end': 2})
    rpc(url, 'DERO.GetBlockHeadersRange', {'start_topoheight': 1, 'end_topoheight': 2})
    rpc(url, 'DERO.GetInfo', {'x': 1})
    rpc(url, 'DERO.GetNothing', {'a': 1})
    rpc(url, 'DERO.Echo', {'a': 1})
    rpc(url, 'DERO.GetGasEstimate', {'scid': 'a', 'ringsize': 2})
PROBES = [('DERO.GetGasEstimate', {'sc_id': 1})]
BODY = {'jsonrpc': '2.0', 'method': 'DERO.GetBlockHeadersRange', 'params': {'start': 0}}
'''


def ht6(P):
    R = load(P['rpcp'], 'rpcp')
    with tempfile.TemporaryDirectory() as d:
        r = Path(d)
        (r / 'cmd/derod/rpc').mkdir(parents=True)
        (r / 'rpc').mkdir()
        (r / 'harness').mkdir()
        (r / 'cmd/derod/rpc/websocket_server.go').write_text(GO_WS)
        (r / 'cmd/derod/rpc/rpc_dero_explorer.go').write_text(GO_EXP)
        (r / 'rpc/daemon_rpc.go').write_text(GO_RPC)
        (r / 'harness/probe.py').write_text(PY_CALLS)
        params = R.go_params(r)
        bad = R.check(R.harness_calls(r), params)
    lines = sorted(int(b.split(':')[1].split()[0]) for b in bad)
    lp, lc = R.go_params(ROOT), R.harness_calls(ROOT)
    live_bad = R.check(lc, lp)
    ok = (params.get('DERO.GetBlockHeadersRange') == ['end_topoheight', 'start_topoheight'] and params.get('DERO.GetInfo') is None
          and params.get('DERO.Echo') == R.POSITIONAL and params.get('DERO.GetGasEstimate') == ['ringsize', 'scid']
          and 'DERO.Other' not in params and lines == [3, 5, 6, 7, 9, 10] and not live_bad and len(lc) >= 40)
    return ok, f'params {params} problem lines {lines} · live {len(lc)} calls, {len(live_bad)} problems {live_bad[:2]}'


# ───────────────────────────── HT7 B116 ─────────────────────────────
def git(d, *a, env=None):
    return subprocess.run(['git', '-C', str(d), *a], check=True, capture_output=True, text=True, env=env).stdout.strip()


def ht7(P):
    D = load(P['disc'], 'disc')
    env = {**os.environ, 'GIT_AUTHOR_NAME': 'k', 'GIT_AUTHOR_EMAIL': 'k@k', 'GIT_COMMITTER_NAME': 'k',
           'GIT_COMMITTER_EMAIL': 'k@k'}
    quote = 'the quoted line of the anchored source'
    with tempfile.TemporaryDirectory() as d:
        r = Path(d)
        subprocess.run(['git', 'init', '-q', d], check=True, env=env)
        (r / 'src.go').write_text(f'a\nb\n{quote}\n')
        git(r, 'add', 'src.go', env=env)
        git(r, 'commit', '-q', '-m', 'R1 head', env=env)
        head1 = git(r, 'rev-parse', 'HEAD')
        (r / 'src.go').write_text(f'a\nb\ninserted later\n{quote}\n')
        git(r, 'commit', '-q', '-am', 'R2', env=env)
        (r / 'harness').mkdir()
        anc = {'file': 'src.go', 'line': 3, 'quote': quote}

        def track(heads, frnd='R1', q=quote):
            t = {'rounds': ['R1', 'R2'], 'current_round': 'R2', 'claims': [], 'fixes': [],
                 'facts': [{'id': 'F1', 'round': frnd, 'status': 'MEASURED', 'anchors': [{**anc, 'quote': q}]}]}
            if heads is not None:
                t['round_heads'] = heads
            return t

        def st(t):
            D._LC.clear()
            rep = D.evaluate(t, root=r)
            return rep['anchor_status'], len(rep['drift'])
        a = st(track({'R1': head1}))
        b = st(track(None))
        c = st(track({'R2': head1}, frnd='R2'))
        e = st(track({'R1': head1}, q='a quote that is in no version of the file'))
        (r / 'harness/round.json').write_text(json.dumps({'rounds': [{'id': 'r1', 'head_after': head1[:9]}]}))
        f = st(track(None))
        heads = D.round_heads({'round_heads': {'R9': 'abc1234'}}, r)
    ok = (a == ({'OK-AT-HEAD': 1}, 0) and b == ({'DRIFT': 1}, 1) and c == ({'DRIFT': 1}, 1) and e == ({'MISSING': 1}, 0)
          and f == ({'OK-AT-HEAD': 1}, 0) and heads == {'R1': head1[:9], 'R9': 'abc1234'})
    return ok, f'at-head {a} no-head {b} current {c} missing {e} registry {f} heads {heads}'


# ───────────────────────────── HT8 B117 ─────────────────────────────
def run_isolated(src_files, rel_script, args):
    with tempfile.TemporaryDirectory() as d:
        r = Path(d)
        for rel, src in src_files.items():
            (r / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, r / rel)
        for sub in ('harness/runtime', 'harness/model/raw', 'harness/loop'):
            (r / sub).mkdir(parents=True, exist_ok=True)
        before = {p for p in r.rglob('*') if p.is_file()}
        p = subprocess.run([sys.executable, '-I', str(r / rel_script), *args], cwd=r, capture_output=True, text=True, timeout=300,
                           env={**os.environ, 'HOME': str(r)})
        after = {p for p in r.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
        return p.returncode, p.stdout + p.stderr, sorted(str(x.relative_to(r)) for x in after - before)


def ht8(P):
    rc1, o1, w1 = run_isolated({'harness/intel/tooling_intel.py': P['tool']}, 'harness/intel/tooling_intel.py', ['--help'])
    rc2, o2, w2 = run_isolated({'harness/intel/tooling_intel.py': P['tool']}, 'harness/intel/tooling_intel.py', ['--bogus'])
    rc3, o3, w3 = run_isolated({'harness/miners/mine_triage.py': P['triage'], 'harness/miners/minelib.py': HARNESS / 'miners/minelib.py'},
                               'harness/miners/mine_triage.py', ['--help'])
    ok = rc1 == 0 and 'usage' in o1 and not w1 and rc2 == 2 and not w2 and rc3 == 0 and 'usage' in o3 and not w3
    return ok, f'tooling --help rc {rc1} wrote {w1} · --bogus rc {rc2} wrote {w2} · triage --help rc {rc3} wrote {w3} {o3[-120:]!r}'


# ───────────────────────────── HT9 B119 ─────────────────────────────
def ht9(P):
    K = load(P['priv'], 'priv')
    addr = 'dero1q' + 'plantedaddr' * 6
    addr2 = 'deto1q' + 'plantedaddrb' * 6          # address-shaped, behind no private flag (verify r26)
    line = (f'34438  5:01:02 912345 ./bin/derod --data-dir={HOME_PLANT}/dero-data --rpc-bind=127.0.0.1:10102 '
            f'--integrator-address={addr} --node-tag=my-box-tag --node-tag second-tag --add-priority-node=1.2.3.4:11011 '
            f'--log-dir={HOME_PLANT}/dero-data/logs --lowlatency --wallet-file {addr2}')
    o = K.scrub_argv(line, SALT)
    peer = K.pseudo_ip('1.2.3.4', SALT)
    leak = [x for x in (HOME_PLANT, addr, addr2, 'my-box-tag', 'second-tag', '1.2.3.4') if x in o]
    both = K.argv_scrubbed(o) and not K.argv_scrubbed(line)
    mrt = ast.unparse(fn_node(P['rt'], 'main'))
    cond = 'argv_scrubbed(line)' in mrt and 'verbatim' in mrt
    kept = all(x in o for x in ('34438', '--rpc-bind=127.0.0.1:10102', '--lowlatency', '--node-tag=<node-tag>',
                                '--integrator-address=<address>', f'--add-priority-node={peer}:11011', '--data-dir=~/dero-data'))
    cap = fn_node(P['rt'], 'capture')
    proc = any(isinstance(n, ast.Assign) and any(isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant)
                                                 and t.slice.value == 'process' for t in n.targets) and 'scrub_process' in calls(n)
               for n in ast.walk(cap))
    F = extract(P['fbv'], ['record_cmds'], extra={'HARNESS': P['priv'].parent.parent})
    rc = F.record_cmds({'candidate': {'cmd': ['/x/derod', '--add-exclusive-node=192.168.77.9:11011', '--p2p-bind=127.0.0.1:21011']}}, SALT)
    lan_gone = '192.168.77.9' not in json.dumps(rc) and K.pseudo_ip('192.168.77.9', SALT) in json.dumps(rc) and '127.0.0.1:21011' in json.dumps(rc)
    ok = not leak and kept and proc and lan_gone and both and cond
    return ok, f'leaks {leak} kept {kept} capture-scrubs {proc} shadow-cmds {lan_gone} scrubbed-check {both} claim-follows-snapshot {cond} -> {o[:200]}'


# ───────────────────────────── HT10 B92 ─────────────────────────────
def ht10(P):
    T = load(P['tool'], 'tool')
    with tempfile.TemporaryDirectory() as d:
        r = Path(d)
        for name, text in (('miner', '# m\n**Track:** miner\n## Round 25 (x)\n'), ('node', '# n\n## Round 25 (x)\n## Round 26 (y)\n')):
            (r / '.skills' / name).mkdir(parents=True)
            (r / '.skills' / name / 'SKILL.md').write_text(text)
        a = T.skill_kpis(r, 'r26', ['miner'])
        b = T.skill_kpis(r, 'r26', [])
        shutil.rmtree(r / '.skills' / 'node')
        c = T.skill_kpis(r, 'r26', ['miner'])
        (r / '.skills' / 'miner' / 'SKILL.md').write_text('# m\n## Round 26 (x)\n' + 'line\n' * T.SKILL_MAX_LINES)
        e = T.skill_kpis(r, 'r26', [])
    v = T.targets({'skill_fresh': 1, 'skill_over_budget': ['miner']})
    pt = T.paused_tracks({'rounds': [{'id': 'r26', 'tracks': {'miner': 'paused', 'x': 'active'}}]}, 'r26')
    ok = (a['skill_fresh'] == 1 and a['skill_paused'] == ['miner'] and b['skill_fresh'] == 0 and c['skill_fresh'] == 0
          and e['skill_over_budget'] == ['miner'] and e['skill_fresh'] == 1 and any('over' in x for x in v) and pt == ['miner'])
    return ok, f'paused-ok {a["skill_fresh"]} active-stale {b["skill_fresh"]} only-paused {c["skill_fresh"]} budget {e["skill_over_budget"]} targets {v} paused {pt}'


# ───────────────────────────── HT11 B90 ─────────────────────────────
def ht11(P):
    E = extract(P['evo'], [], ['ORDER'])
    reg = json.loads((HARNESS / 'round.json').read_text(encoding='utf-8'))
    keys = [('R' + str(r['id'])[1:], r.get('status')) for r in reg.get('rounds') or []]
    missing = [k for k, s in keys if s != 'planned' and k not in E.ORDER]
    planned = [k for k, s in keys if s == 'planned']
    nxt = planned[0] if planned else None
    ok = not missing and (nxt is None or nxt in E.ORDER)
    return ok, f'missing {missing} next planned {nxt} in ORDER {nxt in E.ORDER if nxt else None}'


# ───────────────────────────── HT12 B131 ─────────────────────────────
B131_SHAPES = ['M1' + '-Ultra', 'M1 hard' + 'ware', 'm1' + 'ultra', '.' + 'claude/projects/', '.' + 'claude/settings.json',
               '.' + 'claude/settings.local.json']


def ht12(P):
    T = load(P['tool'], 'ht26tool')
    plants = T.scrub_plants() or []
    missing = [s for s in B131_SHAPES if not any(s in p for p in plants)]
    near = 'Ultra' in T.CLEAN_CONTROL and 'settings.json' in T.CLEAN_CONTROL
    sc = T.scrub_control()
    live = sc.get('scrub_false_negatives')
    ctl_ok = (live == T.PENDING) or (live == 0 and sc.get('scrub_false_positives') == 0)
    return not missing and near and ctl_ok, f'missing shapes {missing} near-miss lines {near} control {sc}'


KATS = [('HT1', ht1), ('HT2', ht2), ('HT3', ht3), ('HT4', ht4), ('HT5', ht5), ('HT6', ht6), ('HT7', ht7), ('HT8', ht8),
        ('HT9', ht9), ('HT10', ht10), ('HT11', ht11), ('HT12', ht12)]
PATHS = {'fbv': FBV, 'logi': LOGI, 'gda': GDA, 'area': AREA, 'rpcp': RPCP, 'disc': DISC, 'tool': TOOL, 'triage': TRIAGE,
         'priv': PRIV, 'rt': RUNTIME_MINER, 'evo': EVO}

MUTATIONS = [   # (key, find, replace, why)
    ('fbv', "                if junk.is_dir():\n                    shutil.rmtree(junk, ignore_errors=True)\n",
     "                if junk.is_dir():\n                    pass\n", 'B98: the teardown leaves the data clone'),
    ('fbv', "        if p is None or p.poll() is not None:\n            continue\n", "        if True:\n            continue\n",
     'B98: the teardown leaves a shadow derod running'),
    ('fbv', "        removed = shadow_teardown(live.get('nodes'), base)", "        removed = []",
     'B98: s5_shadow never tears down'),
    ('fbv', "    live['nodes'] = nodes                                  # B98", "    pass                                  # B98",
     'B98: the nodes are not registered for the teardown'),
    ('fbv', "    if need is None or track != 'paused' or (Path(root) / need).exists():",
     "    if need is None or (Path(root) / need).exists():", 'B101: a missing miner log is skipped with the track active'),
    ('fbv', "    if need is None or track != 'paused' or (Path(root) / need).exists():",
     "    if need is None or track != 'paused':", 'B101: a present miner log is skipped'),
    ('fbv', "        skip = paused_skip(st[1], MINER_TRACK[0], ROOT)                    # r26 B101\n        if skip:",
     "        skip = None\n        if skip:", 'B101: s7_project never consults paused_skip'),
    ('logi', "    recs.sort(key=sort_key)", "    recs.sort(key=lambda d: d.get('T', ''))", 'B101: sort by the local-time string'),
    ('logi', "        return datetime.datetime.strptime(t, '%Y-%m-%dT%H:%M:%S.%f%z').timestamp()\n    except ValueError:",
     "        return datetime.datetime.strptime(t[:23], '%Y-%m-%dT%H:%M:%S.%f').timestamp()\n    except ValueError:",
     'B101: ts() ignores the UTC offset'),
    ('gda', "    if v.isdigit():\n        return datetime.datetime.fromtimestamp(int(v), tz)", "    if False:\n        return None",
     'B93: SOURCE_DATE_EPOCH ignored'),
    ('gda', "    now = inputs_time()                  # r26 B93: reproducible (two builds of one tree are byte-exact)\n",
     "    now = datetime.datetime.now().astimezone()\n",
     'B93: the page prints the wall-clock build time'),
    ('gda', "    subprocess.run([sys.executable, str(HERE / 'prep_corpus.py')], capture_output=True)\n    src = sources(rows)",
     "    src = sources(rows)", 'B93: the fingerprint hashes the previous build\'s corpus index'),
    ('area', "    if m.get('class', 'node') != 'network':\n        return kind, severity, title",
     "    if True:\n        return kind, severity, title", 'B105: a network KPI is booked as a node regression'),
    ('area', "    status = (f'OBSERVATION (network, self-detected {cur}, area_intel; no node regression)' if kind == NETWORK_KIND",
     "    status = (f'OBSERVATION (network, self-detected {cur}, area_intel; no node regression)' if False",
     'B105: a network observation suggests an OPEN regression row'),
    ('area', "            if m.get('class', 'node') not in METRIC_CLASSES:      # r26 B105",
     "            if False:      # r26 B105", 'B105: an unknown metric class passes validation'),
    ('rpcp', "        unknown = [k for k in ks if k not in tags]", "        unknown = []", 'B104: a key outside the json tags passes'),
    ('rpcp', "            if ks:\n                bad.append(f'{where}: sends {sorted(ks)} but the handler takes no params')",
     "            if False:\n                bad.append(f'{where}: sends {sorted(ks)} but the handler takes no params')",
     'B104: params to a no-param handler pass'),
    ('rpcp', "        elif isinstance(n, (ast.Tuple, ast.List)):        # a probe table: ('DERO.X', {...})",
     "        elif False:        # a probe table: ('DERO.X', {...})", 'B104: probe-table literals are not read'),
    ('rpcp', "            if ks and 'method' in ks and 'params' in ks:", "            if False:",
     'B104: request-body literals are not read'),
    ('rpcp', "            if typ in alias and typ not in structs:", "            if False:", 'B104: a `type A B` alias is not resolved'),
    ('disc', "                if h['status'] == 'OK':\n                    r = {**r, 'status': 'OK-AT-HEAD', 'head': heads[rnd]}",
     "                if False:\n                    r = {**r, 'status': 'OK-AT-HEAD', 'head': heads[rnd]}", 'B116: an earlier round\'s anchor drifts for ever'),
    ('disc', "and ri.get(rnd, ri[cur]) < ri[cur] and heads.get(rnd):", "and heads.get(rnd):",
     'B116: a CURRENT-round anchor is resolved at an old head (its drift hidden)'),
    ('disc', "            if re.fullmatch(r'[0-9a-f]{7,40}', v):", "            if False:", 'B116: the registry heads are ignored'),
    ('tool', "    try:\n        a = parse(argv)\n    except SystemExit as e:", "    try:\n        a = parse([x for x in argv if x not in ('--help', '-h', '--bogus')])\n    except SystemExit as e:",
     'B117: tooling_intel --help runs the tool'),
    ('triage', "    a = parse(argv)\n", "    a = parse([x for x in (argv or sys.argv[1:]) if x not in ('--help', '-h')])\n",
     'B117: mine_triage --help runs the miner'),
    ('priv', "        if k in ARGV_PRIVATE_FLAGS:", "        if False:", 'B119: the node tag and integrator flags are kept'),
    ('priv', "    s = HOME_RX.sub('~', s)\n", "", 'B119: the home path is kept'),
    ('priv', "    s = ADDRESS_RX.sub('<address>', s)\n    s = HOME_RX.sub('~', s)\n    return pseudonymise_text(s, salt)",
     "    s = ADDRESS_RX.sub('<address>', s)\n    s = HOME_RX.sub('~', s)\n    return s", 'B119: the priority peer\'s address is kept'),
    ('priv', "        if eq:\n                t = f'{k}={ARGV_PRIVATE_FLAGS[k]}'\n            else:\n                hide = ARGV_PRIVATE_FLAGS[k]",
     "        if eq:\n                t = f'{k}={ARGV_PRIVATE_FLAGS[k]}'\n            else:\n                hide = None",
     'B119: `--node-tag VALUE` (space form) is kept'),
    ('priv', "    s = ADDRESS_RX.sub('<address>', s)\n    s = HOME_RX.sub('~', s)\n    return pseudonymise_text(s, salt)",
     "    s = HOME_RX.sub('~', s)\n    return pseudonymise_text(s, salt)", 'B119: an address-shaped token behind no flag is kept (verify r26)'),
    ('priv', "    return scrub_argv(line, '0' * 64) == str(line)", "    return True", 'B119: a raw snapshot line counts as scrubbed (verify r26)'),
    ('rt', "                   'path withheld (B119).' if argv_scrubbed(line) else", "                   'path withheld (B119).' if True else",
     'B119: the process row claims a raw snapshot is scrubbed (verify r26)'),
    ('rt', "    snap['process'] = scrub_process([l.strip() for l in ps.splitlines() if '/bin/derod' in l and 'grep' not in l])",
     "    snap['process'] = [l.strip() for l in ps.splitlines() if '/bin/derod' in l and 'grep' not in l]",
     'B119: mine_runtime writes the raw argv'),
    ('fbv', "        return {k: [privkit.scrub_argv(str(t), salt) for t in n.get('cmd') or []] for k, n in (nodes or {}).items()}",
     "        return {k: list(n.get('cmd') or []) for k, n in (nodes or {}).items()}", 'B119 class: the shadow record keeps the LAN address'),
    ('tool', "        if skill_track(t) in set(paused):", "        if False:", 'B92: a paused-track skill must be fresh'),
    ('tool', "    out['skill_fresh'] = int(fresh and required > 0)", "    out['skill_fresh'] = int(fresh)",
     'B92: no skill recording the round counts as fresh'),
    ('tool', "        if len(t.splitlines()) > SKILL_MAX_LINES:", "        if False:", 'B92: a skill over its budget is not reported'),
    ('tool', "        plants += ['M1' + '-Ultra', '\"M1 hard' + 'ware ceiling\"', 'm1' + 'ultra', '~/.' + 'claude/projects/x/memory/',",
     "        plants += ['~/.' + 'claude/projects/x/memory/',", 'B131: the machine-model plants are dropped from the control'),
    ('tool', "                   '.' + 'claude/settings.json', '.' + 'claude/settings.local.json']",
     "                   ]", 'B131: the session settings-file plants are dropped from the control'),
    ('evo', "ORDER += ['R25', 'R26', 'R27']", "ORDER += ['R25', 'R26']", 'B90: the next planned round is missing from ORDER'),
]


def run_kats(P):
    res = []
    for name, fn in KATS:
        try:
            o, det = fn(P)
        except Exception as e:                                    # noqa: BLE001
            o, det = False, f'{type(e).__name__}: {e}'
        res.append((name, o, det))
    return res


def main():
    res = run_kats(PATHS)
    for name, o, det in res:
        print(f"{'ok  ' if o else 'FAIL'} {name} {det[:400]}")
    if not all(o for _, o, _ in res):
        return 3
    missed = 0
    for key, find, repl, why in MUTATIONS:
        path = PATHS[key]
        text = path.read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??      {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory() as d:
            # the mutant keeps its directory layout (minelib / kit imports resolve beside it)
            rel = path.relative_to(ROOT)
            mut = Path(d) / rel
            mut.parent.mkdir(parents=True, exist_ok=True)
            for sib in path.parent.glob('*.py'):
                shutil.copy2(sib, mut.parent / sib.name)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            try:
                compile(mut.read_text(encoding='utf-8'), str(mut), 'exec')
            except SyntaxError as e:
                print(f'  INVALID {why}: mutant does not compile ({e.msg})')
                missed += 1
                continue
            P = {**PATHS, key: mut}
            res = run_kats(P)
            survived = all(o for _, o, _ in res)
            failed = [n for n, o, _ in res if not o]
        print(f"  {'MISSED ' if survived else 'proved '} {why}" + ('' if survived else f'  [{",".join(failed)}]'))
        missed += survived
    print(f'\nr26 harness-tooling KATs: {len(KATS)}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
