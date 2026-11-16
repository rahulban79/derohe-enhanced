#!/usr/bin/env python3
"""test_readme_build_r32a.py — r32a (the user, 2026-11-15: the README must say how to build and then use the binaries,
in sync with the newest round): KATs for harness/intel/readme_build.py, the generator of the README's build section.

  RB1 option_lines reads docopt option lines; first_sentence keeps 'e.g.' and drops the [default: ...] part;
      default_of reads it; scrub replaces the build machine's CPU count behind --mining-threads by its meaning
  RB2 splice inserts the section at the top when absent and replaces it in place (idempotent, the rest unchanged)
  RB3 render: the marker names the newest measured round and the version; placeholders only; no host path, no
      machine default, no non-loopback IPv4 in the section
  RB4 the tree's README.md is current (readme_build --check exit 0; it builds the binaries into a temp dir)

  python3 -I harness/kat/test_readme_build_r32a.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 missed
"""
import contextlib, importlib.util, io, re, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
TOOL = HARNESS / 'intel/readme_build.py'

HELP = """Options:
  --mining-threads=<threads>         Number of CPU threads for mining [default: 20]
  --gpu=<path>    Also mine on the GPU at <path> (e.g. gpu-miner-poc/gpu_hash_sais). Adds ~+15% alongside the CPU.
  --cpu-max=<percent>    Cap per-thread duty to this percent. More text here [default: 90]
  --lowlatency	  Use the low-latency profile
"""


def load(over):
    p = Path(over.get('tool') or TOOL)
    spec = importlib.util.spec_from_file_location('rb_mod', p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def kat_rb1(over):
    m = load(over)
    o = m.option_lines(HELP)
    u, t = m.scrub('--mining-threads', *o['--mining-threads'])
    fs = (m.first_sentence(o['--gpu'][1]), m.first_sentence(o['--cpu-max'][1]))
    ok = (set(o) == {'--mining-threads', '--gpu', '--cpu-max', '--lowlatency'} and '20' not in t
          and m.default_of(t) == 'the number of CPU threads of the machine it runs on' and m.default_of(o['--cpu-max'][1]) == '90'
          and fs[0].endswith('(e.g. gpu-miner-poc/gpu_hash_sais).') and fs[1] == 'Cap per-thread duty to this percent.')
    return ok, (sorted(o), t, fs)


def kat_rb2(over):
    m = load(over)
    blk = m.BEGIN + '\nX\n' + m.END
    a = m.splice('# Welcome\nbody\n', blk)
    b = m.splice(a, m.BEGIN + '\nY\n' + m.END)
    c = m.splice(b, m.BEGIN + '\nY\n' + m.END)
    ok = a.startswith(m.BEGIN) and a.endswith('# Welcome\nbody\n') and 'Y' in b and 'X' not in b and b == c and b.count(m.BEGIN) == 1
    return ok, (a[:40], b[:40])


def kat_rb3(over):
    m = load(over)
    opts = m.option_lines(HELP)
    g = {'version': '3.6.0-153.DEROHE.STARGATE+22102026.r31', 'round': 'r32', 'gomin': '1.17', 'gov': '1.26',
         'ports': {'RPC_Default_Port': 10102, 'GETWORK_Default_Port': 10100, 'Wallet_RPC_Default_Port': 10103},
         'bins': {'derod': './cmd/derod', 'dero-miner': './cmd/dero-miner', 'dero-wallet-cli': './cmd/dero-wallet-cli'},
         'vf': {'dero-miner': ['--cpu-max', '--gpu'], 'derod': ['--lowlatency']},
         'helps': {'derod': opts, 'dero-miner': opts, 'dero-wallet-cli': opts}}
    r = m.render(g)
    ips = [x for x in re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', r) if x not in ('127.0.0.1', '0.0.0.0')]
    ok = ('current through r32 · 3.6.0-153.DEROHE.STARGATE+22102026.r31' in r and '/Users/' not in r and '~/' not in r
          and '[default: 20]' not in r and '| 20 |' not in r and not ips and '<your-address>' in r
          and 'go build -o bin/derod ./cmd/derod' in r and r.startswith(m.BEGIN) and r.endswith(m.END))
    return ok, (ips, len(r))


def kat_rb4(over):
    if over:                       # the live-tree check is not a mutation target (it builds binaries)
        return True, 'skipped under a mutation'
    r = subprocess.run(['nice', '-n', '15', sys.executable, '-I', str(TOOL), '--check'], cwd=ROOT, capture_output=True, text=True, timeout=900)
    return r.returncode == 0, (r.stdout + r.stderr).strip()[-200:]


KATS = [('RB1', kat_rb1), ('RB2', kat_rb2), ('RB3', kat_rb3), ('RB4', kat_rb4)]
OWNERS = {'r32a scrub': ['RB1', 'RB3'], 'r32a sentence': ['RB1'], 'r32a splice': ['RB2'], 'r32a marker': ['RB3']}
MUTATIONS = [
    ('tool', "    if flag in MACHINE_DEFAULTS:", "    if False:", 'r32a scrub: the machine CPU count is printed as the default'),
    ('tool', "    m = re.search(r'(?<!e\\.g)\\.\\s+(?=[A-Z])', t)", "    m = re.search(r'\\.\\s+', t)", 'r32a sentence: the cut breaks inside (e.g.)'),
    ('tool', "    if BEGIN in readme and END in readme:", "    if False:", 'r32a splice: a regeneration adds a second section'),
    ('tool', "current through {g[\"round\"]} · {g[\"version\"]} -->'", "current through r0 · {g[\"version\"]} -->'",
     'r32a marker: the section names the wrong round'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_rb', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run_kats(over):
    res = []
    for name, fn in KATS:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                ok, det = fn(over)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        res.append((name, ok, str(det)))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr32a readme-build KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = 0
    text = TOOL.read_text(encoding='utf-8')
    for key, find, repl, why in MUTATIONS:
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='rb-mut-') as d:
            mut = Path(d) / 'readme_build.py'
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r32a readme-build KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 0 if not missed else 4


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
