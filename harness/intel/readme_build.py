#!/usr/bin/env python3
"""readme_build.py — r32a: the README's "Build and run this build" section, generated from the tree every round.

Why (the user, 2026-11-15): the public README did not say how to build and then use the binaries of this build, and the
little it said was not kept in sync with the newest round. The upstream "DERO Installation" text further down clones the
upstream repository and names a wallet port this build does not use. The section is now GENERATED from evidence:

  version      config/version.go (the string `derod --version` prints)
  round        harness/round.json: the newest MEASURED round (the README describes what was measured)
  Go           go.mod `go` line (the minimum) and the toolchain that built and tested it (`go version`, number only)
  binaries     harness/pipeline/fix_build_verify.py BINARIES (what the pipeline builds and installs) + gt-wallet
  flags        each binary built into a temporary directory and its own --help read: the flags the pipeline's build stage
               verifies (s4_build miner_flags / derod_flags) plus the core flags, each with its help text and default
  ports        config/config.go Mainnet (RPC, getwork, wallet RPC)
PRIVACY: a default the help prints from the build machine (the CPU count behind --mining-threads) is replaced by its
meaning; no path, host or address of the machine is written. Placeholders (<your-address>) are used in every example.

The section sits between <!-- build-run:begin --> and <!-- build-run:end --> at the top of README.md (the public sync
puts its round header above it). Never hand-edited.

  python3 -I harness/intel/readme_build.py --write     # regenerate the section
  python3 -I harness/intel/readme_build.py --check     # exit 0 current · 5 stale (regen_round page gate) · 2 error
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):
    print(__doc__)
    raise SystemExit(0)
import ast, json, re, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
BEGIN, END = '<!-- build-run:begin -->', '<!-- build-run:end -->'
CORE = {'derod': ['--data-dir', '--rpc-bind', '--p2p-bind', '--getwork-bind', '--integrator-address', '--prune-history'],
        'dero-miner': ['--wallet-address', '--daemon-rpc-address', '--mining-threads'],
        'dero-wallet-cli': ['--wallet-file', '--restore-deterministic-wallet', '--daemon-address', '--rpc-server', '--rpc-bind',
                            '--xswd-allow-remote']}
MACHINE_DEFAULTS = {'--mining-threads': 'the number of CPU threads of the machine it runs on'}


def binaries(root):
    """the BINARIES dict of the pipeline (what S4 builds). Pure apart from the read."""
    t = (root / 'harness/pipeline/fix_build_verify.py').read_text()
    m = re.search(r'^BINARIES = (\{[^\n]*\})', t, re.M)
    return ast.literal_eval(m.group(1))


def verified_flags(root):
    """the enhanced flags the build stage verifies per binary (s4_build miner_flags / derod_flags). Pure apart from the read."""
    t = (root / 'harness/pipeline/fix_build_verify.py').read_text()
    out = {}
    for name, var in (('dero-miner', 'miner_flags'), ('derod', 'derod_flags')):
        m = re.search(rf'{var} = \{{f: f in \([^)]*\) for f in \((.*?)\)\}}', t, re.S)
        out[name] = [f for f in re.findall(r"'(--[a-z0-9-]+)'", m.group(1))] if m else []
    return out


def option_lines(help_text):
    """{flag: (usage form, help text)} from a docopt-style --help. Pure."""
    out = {}
    for line in help_text.splitlines():
        m = re.match(r'^\s+(--[a-z0-9_-]+)(=<[^>]*>)?\s+(.*)$', line)
        if m and m.group(1) not in out:
            out[m.group(1)] = (m.group(1) + (m.group(2) or ''), m.group(3).strip())
    return out


def scrub(flag, usage, text):
    """replace a default the help prints from the build machine by its meaning. Pure."""
    if flag in MACHINE_DEFAULTS:
        text = re.sub(r'\[default: [^\]]*\]', f'[default: {MACHINE_DEFAULTS[flag]}]', text)
    return usage, text


def first_sentence(text, limit=170):
    """the help text up to its first sentence end (a '. ' before a capital, never inside 'e.g.'), the [default: ...] part
    removed (it has its own column). Pure."""
    t = re.sub(r'\s*\[default: [^\]]*\]', '', text).strip()
    m = re.search(r'(?<!e\.g)\.\s+(?=[A-Z])', t)
    s = t[:m.start() + 1] if m else t
    return s if len(s) <= limit else s[:limit - 1].rstrip() + '…'


def default_of(text):
    m = re.search(r'\[default: ([^\]]*)\]', text)
    return m.group(1) if m else ''


def table(name, opts, flags):
    rows = []
    for f in flags:
        if f in opts:
            u, t = scrub(f, *opts[f])
            rows.append(f'| `{u}` | {default_of(t).replace("|", "/")} | {first_sentence(t).replace("|", "/")} |')
    return ('| flag | default | what the binary\'s --help says |\n|---|---|---|\n' + '\n'.join(rows)) if rows else '(no options read)'


def gather(root=ROOT):
    ver = re.search(r'MustParse\("([^"]+)"\)', (root / 'config/version.go').read_text()).group(1)
    reg = json.loads((root / 'harness/round.json').read_text())
    measured = [r['id'] for r in reg['rounds'] if r.get('status') == 'measured'][-1]
    gomin = re.search(r'^go (\S+)', (root / 'go.mod').read_text(), re.M).group(1)
    gov = re.search(r'go(\d+\.\d+)', subprocess.run(['go', 'version'], capture_output=True, text=True).stdout).group(1)
    cfg = (root / 'config/config.go').read_text()
    mb = cfg[cfg.index('var Mainnet = CHAIN_CONFIG'):]
    ports = {k: int(re.search(rf'{k}:\s+(\d+)', mb).group(1)) for k in ('RPC_Default_Port', 'GETWORK_Default_Port', 'Wallet_RPC_Default_Port')}
    bins = binaries(root)
    vf = verified_flags(root)
    helps = {}
    with tempfile.TemporaryDirectory() as d:
        for name, pkg in bins.items():
            r = subprocess.run(['nice', '-n', '15', 'go', 'build', '-o', str(Path(d) / name), pkg], cwd=root, capture_output=True, text=True)
            if r.returncode != 0:
                raise RuntimeError(f'go build {pkg}: {r.stderr[-300:]}')
            h = subprocess.run([str(Path(d) / name), '--help'], capture_output=True, text=True, timeout=60)
            helps[name] = option_lines(h.stdout + h.stderr)
    return {'version': ver, 'round': measured, 'gomin': gomin, 'gov': gov, 'ports': ports, 'bins': bins, 'vf': vf, 'helps': helps}


def render(g):
    p = g['ports']
    b = ' && '.join(f'go build -o bin/{n} {pkg}' for n, pkg in g['bins'].items())
    out = [BEGIN, f'<!-- generated by harness/intel/readme_build.py from the tree; current through {g["round"]} · {g["version"]} -->', '',
           '## Build and run this build', '',
           f'Node build `{g["version"]}`, current through Round {g["round"][1:]} (the newest measured round of `harness/round.json`). '
           'This section is generated from the tree every round; the "DERO Installation" section further down is the upstream '
           'project\'s text and describes the upstream binaries.', '',
           '### Build', '',
           f'Go {g["gomin"]} or newer (`go.mod`); the pipeline builds and tests this round with Go {g["gov"]}. From the repository root:', '',
           '```bash', b, '```', '',
           'These are the binaries the harness pipeline builds, tests (unit, race, mutation and shadow-node stages) and installs. '
           'On macOS the optional GPU hash server is built with `gpu-miner-poc/build.sh gpu_split_server`; the game-theory '
           'wallet tool with `go build -o bin/gt-wallet ./cmd/gt-wallet`.', '',
           '### Run the node (mainnet)', '',
           '```bash',
           f'./bin/derod --data-dir=<datadir> --rpc-bind=127.0.0.1:{p["RPC_Default_Port"]} '
           f'--getwork-bind=127.0.0.1:{p["GETWORK_Default_Port"]} --p2p-bind=0.0.0.0:<udp-port> --lowlatency '
           '--integrator-address=<your-address>',
           '```', '',
           f'The JSON-RPC answers on port {p["RPC_Default_Port"]} (`Content-Type: application/json`), miners connect to getwork on '
           f'{p["GETWORK_Default_Port"]}, and P2P runs over UDP (KCP), so a router forward must be for UDP. Without '
           '`--integrator-address` the integrator reward of a block this node builds goes to the developers\' address '
           '(`blockchain/blockchain.go`), so a node that serves miners should set it.', '',
           table('derod', g['helps']['derod'], CORE['derod'] + [f for f in g['vf'].get('derod', []) if f not in CORE['derod']]), '',
           '### Mine', '',
           '```bash',
           f'./bin/dero-miner --wallet-address=<your-address> --daemon-rpc-address=127.0.0.1:{p["GETWORK_Default_Port"]} --mining-threads=<n>',
           '```', '',
           'Each flag\'s text and default below are the binary\'s own `--help`; `tools/launchd` installs the miner as a '
           'supervised macOS service (`--supervised`).', '',
           table('dero-miner', g['helps']['dero-miner'], CORE['dero-miner'] + [f for f in g['vf'].get('dero-miner', []) if f not in CORE['dero-miner']]), '',
           '### Wallet', '',
           '```bash',
           f'./bin/dero-wallet-cli --wallet-file=<file> --daemon-address=127.0.0.1:{p["RPC_Default_Port"]}',
           '```', '',
           'Restore with `--restore-deterministic-wallet` from your seed. The wallet file is created relative to the working '
           f'directory. The wallet RPC (`--rpc-server`) binds where `--rpc-bind` says (the mainnet wallet RPC port in the code '
           f'is {p["Wallet_RPC_Default_Port"]}).', '',
           table('dero-wallet-cli', g['helps']['dero-wallet-cli'], CORE['dero-wallet-cli']), '',
           '### Game-theory playbooks (Round 32 onwards)', '',
           '```bash',
           'python3 -I playbooks/gt_playbook.py all --run-id demo            # a private simulator chain; spends nothing',
           'python3 -I playbooks/gt_playbook.py all --network mainnet --dry-run   # prints the mainnet commands, spends nothing',
           '```', '',
           'Every mainnet step that spends DERO or starts a miner needs `--mainnet-confirm`; the contracts are in '
           '`gametheory/contracts/`, the design and results in `harness/dero-enhanced-game-theory.html`.', '',
           '### Verify', '',
           '```bash',
           'python3 -I harness/pipeline/fix_build_verify.py --project-only   # re-project and gate the installed state',
           '```', '', END]
    return '\n'.join(out)


def splice(readme, block):
    """README text with the block replaced, or inserted at the top when absent. Pure."""
    if BEGIN in readme and END in readme:
        return readme[:readme.index(BEGIN)] + block + readme[readme.index(END) + len(END):]
    return block + '\n\n' + readme


def main(argv):
    write, check = '--write' in argv, '--check' in argv
    rp = ROOT / 'README.md'
    try:
        new = splice(rp.read_text(encoding='utf-8'), render(gather()))
    except (OSError, RuntimeError, ValueError, AttributeError, KeyError, IndexError) as e:
        print(f'readme_build: error {type(e).__name__}: {str(e)[:200]}')
        return 2
    cur = rp.read_text(encoding='utf-8')
    if write:
        if new != cur:
            rp.write_text(new, encoding='utf-8')
        print('readme_build: README.md build section written')
        return 0
    if new != cur:
        print('readme_build: STALE: README.md build section differs from the tree (run --write)')
        return 5
    print('readme_build: current')
    return 0 if check or not argv else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
