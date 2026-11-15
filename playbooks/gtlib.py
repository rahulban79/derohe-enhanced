"""gtlib.py — r32 shared library of the game-theory playbooks (artifacts/dero-game-theory-rft.md §6, D-GT-1/D-GT-2).

No LLM, stdlib only, python3 -I. Everything a playbook does goes through here: the network table, the ban guard, the
JSONL event log, the JSON-RPC clients (daemon and wallet), and process control limited to the processes the playbook
itself started (pidfile + basename check; a foreign pid is never signalled).
"""
import base64, datetime, hashlib, json, os, secrets, signal, subprocess, sys, time, urllib.error, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
HOME = Path.home()
GT_HOME = Path(os.environ.get('GT_HOME') or HOME / 'derohe-persist' / 'gt-sim')
WALLETS = Path(os.environ.get('GT_WALLETS') or HOME / 'dero-wallets' / 'gt')
BIN = GT_HOME / 'bin'
MAINNET_DATA = HOME / 'dero-data'                     # the user's mainnet chain: never written, never a --data-dir

sys.path.insert(0, str(ROOT / 'harness' / 'gametheory'))
import banguard  # noqa: E402

# the networks. sim: cmd/simulator (difficulty 1, --noautomine, opt-in loopback getwork); testnet: an isolated
# derod --testnet with its own data dir (no peers); mainnet: the user's live node, read-only unless --mainnet-confirm
NETWORKS = {
    'sim': {'testnet': True, 'daemon': '127.0.0.1:47102', 'getwork': '127.0.0.1:47100', 'explorer': '127.0.0.1:47180',
            'wallet_base': 47200, 'spends_real_dero': False},
    'testnet': {'testnet': True, 'daemon': '127.0.0.1:47402', 'getwork': '127.0.0.1:47400', 'explorer': None,
                'wallet_base': 47500, 'spends_real_dero': False},
    # mainnet getwork: the local derod's (the miner path runs only behind --mainnet-confirm, which the USER passes)
    'mainnet': {'testnet': False, 'daemon': '127.0.0.1:10102', 'getwork': '127.0.0.1:10100', 'explorer': None,
                'wallet_base': 47800, 'spends_real_dero': True},
}

# the R32 mechanism parameters per network: the sim chain makes ~6 blocks/s, so its windows are wider in blocks
PARAMS = {
    'sim': {'attest': {'bond': 100000, 'reward': 100, 'window': 240, 'commitw': 120, 'revealw': 120, 'maxmb': 10,
                       'slash': 10, 'minstake': 100000},
            'service': {'fee': 1000, 'rho': 50, 'boost': 100, 'epoch': 300, 'minmat': 100},
            'prize': {'rbond': 10000, 'commitw': 150, 'revealw': 150, 'maxn': 32, 'boost': 100, 'minmat': 100}},
}
PARAMS['testnet'] = PARAMS['sim']
PARAMS['mainnet'] = {'attest': {'bond': 100000, 'reward': 100, 'window': 200, 'commitw': 100, 'revealw': 100,
                                'maxmb': 10, 'slash': 10, 'minstake': 100000},
                     'service': {'fee': 1000, 'rho': 50, 'boost': 100, 'epoch': 400, 'minmat': 100},
                     'prize': {'rbond': 10000, 'commitw': 100, 'revealw': 100, 'maxn': 32, 'boost': 100, 'minmat': 100}}

# the pipeline's enhancement stage writes the derived parameters (playbooks/params_r32.json); they override the table
_GEN = HERE / 'params_r32.json'
if _GEN.exists():
    for _net, _p in json.loads(_GEN.read_text()).get('params', {}).items():
        PARAMS[_net] = {k: {kk: vv for kk, vv in v.items()} for k, v in _p.items() if k in ('attest', 'service', 'prize')}


def now():
    return datetime.datetime.now().astimezone().isoformat(timespec='seconds')


class Run:
    """One playbook run: <GT_HOME>/runs/<run_id>/ holds state.json (idempotence) and events.jsonl."""

    def __init__(self, run_id, network, dry_run=False, mainnet_confirm=False):
        if network not in NETWORKS:
            raise SystemExit(f'unknown network {network}')
        self.id, self.network, self.dry, self.mc = run_id, network, dry_run, mainnet_confirm
        self.net = NETWORKS[network]
        self.dir = GT_HOME / 'runs' / run_id
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        self.state_file = self.dir / 'state.json'
        self.state = json.loads(self.state_file.read_text()) if self.state_file.exists() else {
            'run_id': run_id, 'network': network, 'created': now(), 'steps': {}, 'wallets': {}, 'procs': {}, 'scids': {}}
        if self.state.get('network') != network:
            raise SystemExit(f'run {run_id} belongs to network {self.state.get("network")}')
        self.save()

    def save(self):
        tmp = self.state_file.with_suffix('.tmp')
        tmp.write_text(json.dumps(self.state, indent=1, sort_keys=True))
        tmp.replace(self.state_file)

    def event(self, kind, **kw):
        rec = dict(ts=now(), run=self.id, network=self.network, kind=kind, dry_run=self.dry, **kw)
        text = json.dumps(rec, sort_keys=True)
        if banguard.scan_text(text):
            raise banguard.BannedAddress('an event would carry a banned address; refused')
        with open(self.dir / 'events.jsonl', 'a') as f:
            f.write(text + '\n')
        print(f"[{rec['ts']}] {kind} " + ' '.join(f'{k}={v}' for k, v in kw.items() if k not in ('detail',))[:300])
        return rec

    def done(self, step):
        return self.state['steps'].get(step, {}).get('status') == 'done'

    def mark(self, step, **kw):
        self.state['steps'][step] = dict(status='done', at=now(), **kw)
        self.save()

    # the mainnet rule (D-GT-1): anything that spends real DERO or starts/stops a mainnet miner is a USER action
    def user_action_gate(self, what, cmd):
        if self.net['spends_real_dero'] and not self.mc:
            self.event('user_action_required', what=what, cmd=cmd,
                       note='mainnet: pass --mainnet-confirm yourself to run this step (D-GT-1); nothing was done')
            return False
        if self.dry:
            self.event('dry_run', what=what, cmd=cmd)
            return False
        return True


# ---------------------------------------------------------------- JSON-RPC
def rpc_call(hostport, method, params=None, timeout=30, retries=6, login=None):
    req_obj = {'jsonrpc': '2.0', 'id': '1', 'method': method}
    if params is not None:                    # derod refuses params on parameterless methods (-32602, r27 B132)
        req_obj['params'] = params
    body = json.dumps(req_obj).encode()
    hdr = {'Content-Type': 'application/json'}
    if login:
        hdr['Authorization'] = 'Basic ' + base64.b64encode(login.encode()).decode()
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(f'http://{hostport}/json_rpc', body, hdr)
            d = json.load(urllib.request.urlopen(req, timeout=timeout))
            if d.get('error'):
                raise RuntimeError(f"{method}: {d['error']}")
            return d.get('result')
        except (urllib.error.URLError, ConnectionError, TimeoutError, json.JSONDecodeError) as e:
            last = e
            time.sleep(min(0.25 * 2 ** i, 4))
        except RuntimeError as e:
            msg = str(e)
            if 'rate' in msg.lower() or 'too many' in msg.lower():
                last = e
                time.sleep(min(0.25 * 2 ** i, 4))
                continue
            raise
    raise RuntimeError(f'{method} at {hostport}: {last}')


def arg_u(name, v):
    """a DVM Uint64 argument; fail closed on a value outside [0, 2^64) (r32 run-8 lesson: Finalize(i=-1) reached the
    wallet as an undecodable param and came back as an opaque -32602 after 8 retries)."""
    v = int(v)
    if not 0 <= v < 1 << 64:
        raise ValueError(f'arg_u {name}={v}: outside Uint64')
    return {'name': name, 'datatype': 'U', 'value': v}


def arg_s(name, v):
    return {'name': name, 'datatype': 'S', 'value': str(v)}


def commit_vote(i, vote, salt):
    return hashlib.sha256(f'{i}:{vote}:{salt}'.encode()).hexdigest()


def commit_num(n, salt):
    return hashlib.sha256(f'{n}:{salt}'.encode()).hexdigest()


# ---------------------------------------------------------------- processes (own only)
def start_proc(run, name, argv, cwd=None, env=None):
    """nohup-style start at nice 15; pid + argv basename recorded; idempotent (a live recorded pid is kept)."""
    p = run.state['procs'].get(name)
    if p and pid_alive(p['pid'], p['exe']):
        run.event('proc_kept', name=name, pid=p['pid'])
        return p['pid']
    exe = Path(argv[0]).name
    if not exe.startswith('gt-'):
        raise SystemExit(f'refusing to start {exe}: playbooks start only gt-* binaries')
    log = open(run.dir / f'{name}.out', 'ab')
    pr = subprocess.Popen(['nice', '-n', '15'] + argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                          cwd=cwd or run.dir, env=env, start_new_session=True)
    run.state['procs'][name] = {'pid': pr.pid, 'exe': exe, 'started': now()}
    run.save()
    run.event('proc_started', name=name, pid=pr.pid, exe=exe)
    return pr.pid


def pid_alive(pid, exe):
    """True only if pid runs and its command basename is exe (a recycled pid of another program is not ours)."""
    try:
        out = subprocess.run(['ps', '-p', str(pid), '-o', 'comm='], capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return False
    return bool(out) and Path(out).name == exe


def stop_proc(run, name, wait_s=15):
    p = run.state['procs'].get(name)
    if not p:
        return False
    if pid_alive(p['pid'], p['exe']):
        os.kill(p['pid'], signal.SIGTERM)
        t0 = time.time()
        while time.time() - t0 < wait_s and pid_alive(p['pid'], p['exe']):
            time.sleep(0.2)
        if pid_alive(p['pid'], p['exe']):
            os.kill(p['pid'], signal.SIGKILL)
    run.state['procs'].pop(name, None)
    run.save()
    run.event('proc_stopped', name=name, pid=p['pid'])
    return True


def base_unit():
    """Atomic units per DERO (5 decimals)."""
    return 100000


def new_password():
    return secrets.token_hex(16)


# r32 (main-session lesson 2026-11-15 03:28): a relaunched earn run passed --progress to a gt-wallet built before the
# flag existed and died with a usage error. Every playbook checks its gt-* binaries against their Go sources first.
BIN_SOURCES = {'gt-wallet': 'cmd/gt-wallet', 'gt-simulator': 'cmd/simulator', 'gt-dero-miner': 'cmd/dero-miner'}


def stale_bins(bin_dir=None, root=None, names=None):
    """[(binary, newest source file)] for each gt-* binary that is missing or older than any non-test .go file of its
    command directory. Pure apart from the file stats."""
    bin_dir, root = Path(bin_dir or BIN), Path(root or ROOT)
    out = []
    for b in names or BIN_SOURCES:
        src = root / BIN_SOURCES[b]
        gos = [f for f in src.glob('*.go') if not f.name.endswith('_test.go')]
        newest = max(gos, key=lambda f: f.stat().st_mtime) if gos else None
        bp = bin_dir / b
        if not bp.exists() or (newest and newest.stat().st_mtime > bp.stat().st_mtime):
            out.append((b, str(newest.relative_to(root)) if newest else None))
    return out


def rebuild_bins(stale, bin_dir=None, root=None):
    """go build each stale binary to a temp name in bin_dir, then an atomic rename (a running copy keeps its inode)."""
    bin_dir, root = Path(bin_dir or BIN), Path(root or ROOT)
    for b, _ in stale:
        tmp = bin_dir / f'.{b}.new'
        subprocess.run(['nice', '-n', '15', 'go', 'build', '-o', str(tmp), './' + BIN_SOURCES[b]], cwd=root, check=True,
                       timeout=1800)
        os.replace(tmp, bin_dir / b)


def ensure_bins(run, names, rebuild=False):
    """refuse (SystemExit 8) or rebuild when a needed gt-* binary is older than its sources."""
    st = stale_bins(names=names)
    if not st:
        return
    run.event('stale_binaries', stale=[b for b, _ in st], newest_source=[s for _, s in st], rebuild=rebuild)
    if not rebuild:
        raise SystemExit(f'stale gt binaries {[b for b, _ in st]}: rebuild them (pass --rebuild) before this run')
    rebuild_bins(st)
