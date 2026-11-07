#!/usr/bin/env python3
"""prep_corpus.py — derived, line-addressable inputs for the DERO HE living-architecture page.

  python3 prep_corpus.py            # build corpus/tags.tsv + corpus/manifest.json + corpus/pkgindex.json
  python3 prep_corpus.py --check    # exit 0 CURRENT · 3 STALE (an input changed since the last run)

Roots and what a line found under each can PROVE (the class vocabulary is closed):
  SRC      first-party DERO Go source + the project's own build scripts (everything not under vendor/)
  EXT      quoted, not owned: vendor/ (third-party code this build links in) and harness/external/
           (documents published by others and taken under audit — a line proves only that they SAID it).
  HARNESS  the owner's own measured system: harness/runtime/** (live RPC snapshots, the derod console log),
           RUN_REPORT.md, ARCHITECTURE.md, the monitoring shell scripts.
  GK       the project's knowledge base: .skills/**/SKILL.md and the session memory store.
  PLAN     harness/loop/PROPOSALS.md — work proposed and not yet run.

Nothing here writes into the source tree. Inputs are read-only.
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import hashlib, json, os, re, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent                                   # <repo>
CORPUS = HERE / 'corpus'
MEMORY = Path.home() / '.claude/projects' / ('-' + str(Path.home()).strip('/').replace('/', '-') + '-derohe-Release142') / 'memory'
RUNTIME = HERE / 'runtime'
EXTERNAL = HERE / 'external'      # externally published documents under audit (press statements, advisories)
BASELINE = HERE / 'baseline'      # exact git copies of source an older running binary was built from (DK27)
PROPOSALS = HERE / 'loop/PROPOSALS.md'

# first-party Go packages (SRC). gpu-miner-poc is a separate experiment tree, kept out of the page's scope.
SRC_PKGS = ['astrobwt', 'block', 'blockchain', 'cmd', 'config', 'cryptography', 'dvm', 'errormsg',
            'globals', 'glue', 'metrics', 'p2p', 'pow', 'premine', 'proof', 'rpc', 'transaction', 'walletapi',
            'tools']   # R20: tools/dashboard is first-party since r19; without it its loc- rows were refused as OUTSIDE
SRC_SCRIPTS = ['build_all.sh', 'build_package.sh', 'run_derod_lowlatency.sh', 'run_integration_test.sh',
               'dero_monitor.sh', 'mining_dashboard.sh', 'net_metrics.sh', 'reward_audit.py', 'go.mod']
HARNESS_DOCS = ['RUN_REPORT.md', 'ARCHITECTURE.md', 'DISCOVERY.md', 'Changelog.md', 'Start.md', 'README.md']
VENDOR = ROOT / 'vendor'
SKILLS = ROOT / '.skills'
SKIP_DIRS = {'.git', 'vendor', 'gpu-miner-poc', 'node_modules', '__pycache__', 'harness', 'artifacts',
             'mainnet', 'memory-mirror', 'licenses', 'bin'}


AUTO_RE = re.compile(rb'<!-- AUTO:BEGIN.*?<!-- AUTO:END -->', re.S)


def sha(p):
    """Content hash. The skill's AUTO block is excluded: the build writes it, so hashing it would make the
    page permanently stale against its own output."""
    try:
        b = Path(p).read_bytes()
    except OSError:
        return None
    if str(p).endswith('SKILL.md'):
        # strip the generated block AND the whitespace that appending it introduced, so the first build
        # (which creates the block) leaves the same hash as every build after it
        b = AUTO_RE.sub(b'', b).rstrip()
    return hashlib.sha256(b).hexdigest()[:16]


def go_files(base, skip_tests=False):
    out = []
    for dp, dn, fn in os.walk(base):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in fn:
            if f.endswith('.go') and not (skip_tests and f.endswith('_test.go')):
                out.append(Path(dp) / f)
    return sorted(out)


def lex(p):
    """Absolute path WITHOUT following symlinks.

    class_of asks "is this path inside that root", which is a question about the path, not about the inode.
    Path.resolve() answers the inode question, and under a scratch tree whose entries are symlinks into the
    real repository every file escaped the root and became unclassifiable (KAT DK05, 2026-10-20).
    """
    return os.path.abspath(os.path.expanduser(str(p)))


def class_of(p):
    """Where a path lives decides what a line in it can prove."""
    s = lex(p)
    if s.startswith(lex(VENDOR) + '/') or s.startswith(lex(EXTERNAL) + '/'):
        return 'EXT'
    if s.startswith(lex(RUNTIME) + '/') or s.startswith(lex(BASELINE) + '/'):
        return 'HARNESS'
    if s == lex(PROPOSALS):
        return 'PLAN'
    if s.startswith(lex(SKILLS) + '/') or s.startswith(lex(MEMORY) + '/'):
        return 'GK'
    if any(s == lex(ROOT / d) for d in HARNESS_DOCS):
        return 'HARNESS'
    if s.startswith(lex(ROOT) + '/'):
        rel = s[len(lex(ROOT)) + 1:]
        top = rel.split('/')[0]
        if top in SRC_PKGS or rel in SRC_SCRIPTS:
            return 'SRC'
    return None


def build_tags():
    """ctags over the first-party Go tree. One line per symbol: name<TAB>file<TAB>line<TAB>kind<TAB>pkg."""
    files = []
    for pkg in SRC_PKGS:
        files += [str(f) for f in go_files(ROOT / pkg)]
    out = []
    r = subprocess.run(['ctags', '--languages=Go', '--fields=+n-f', '-x', '--_xformat=%N\t%F\t%n\t%K', *files],
                       capture_output=True, text=True, cwd=ROOT)
    if files and (r.returncode != 0 or not r.stdout.strip()):
        # r28 (tools-kats): with Xcode's /usr/bin/ctags first on PATH (BSD ctags, no long options: 'illegal option -- -', measured 2026-11-06)
        # this wrote a one-blank-line tags.tsv and exited 0: mine_inventory then lost 4 package rows and mine_coverage
        # measured 0 functions, all without an error. Stop before anything is written.
        why = (r.stderr or r.stdout).strip().splitlines()[:1]
        print(f'prep_corpus: ctags produced no symbols for {len(files)} Go files (exit {r.returncode}: {why}); '
              f'universal-ctags must be first on PATH (`ctags --version` names Universal Ctags)', file=sys.stderr)
        raise SystemExit(2)
    for line in r.stdout.splitlines():
        parts = line.split('\t')
        if len(parts) < 4:
            continue
        name, f, ln, kind = parts[0], parts[1], parts[2], parts[3]
        try:
            f = str(Path(f).resolve().relative_to(ROOT))
        except ValueError:
            continue
        out.append(f'{name}\t{f}\t{ln}\t{kind}\t{f.split("/")[0]}')
    (CORPUS / 'tags.tsv').write_text('\n'.join(sorted(set(out))) + '\n')
    return len(set(out))


def build_pkgindex():
    """Measured per-package inventory. Every number here comes from a filesystem walk, never from a doc."""
    idx = {}
    for pkg in SRC_PKGS:
        base = ROOT / pkg
        if not base.is_dir():
            continue
        src = go_files(base, skip_tests=True)
        tst = [f for f in go_files(base) if f.name.endswith('_test.go')]
        loc = sum(len(f.read_text(errors='replace').splitlines()) for f in src)
        tloc = sum(len(f.read_text(errors='replace').splitlines()) for f in tst)
        subs = sorted({str(f.parent.relative_to(ROOT)) for f in src})
        idx[pkg] = {'files': len(src), 'loc': loc, 'test_files': len(tst), 'test_loc': tloc,
                    'dirs': subs, 'first_file': str(src[0].relative_to(ROOT)) if src else None}
    # vendored third-party (EXT), counted the same way
    vend = {}
    if VENDOR.is_dir():
        for mod in sorted(VENDOR.glob('*/*/*')):
            if not mod.is_dir():
                continue
            fs = [f for f in mod.rglob('*.go')]
            if fs:
                vend[str(mod.relative_to(VENDOR))] = {'files': len(fs),
                                                      'loc': sum(len(f.read_text(errors='replace').splitlines()) for f in fs)}
    (CORPUS / 'pkgindex.json').write_text(json.dumps({'packages': idx, 'vendor': vend}, indent=1))
    return len(idx), len(vend)


def inputs():
    """Every file the page may cite, with its class and hash — the staleness basis."""
    out = {}
    for pkg in SRC_PKGS:
        for f in go_files(ROOT / pkg):
            out[str(f.relative_to(ROOT))] = 'SRC'
    for s in SRC_SCRIPTS:
        if (ROOT / s).exists():
            out[s] = 'SRC'
    for d in HARNESS_DOCS:
        if (ROOT / d).exists():
            out[d] = 'HARNESS'
    if RUNTIME.is_dir():
        for f in sorted(RUNTIME.iterdir()):
            if f.is_file():
                out[str(f.relative_to(ROOT))] = 'HARNESS'
    if EXTERNAL.is_dir():
        for f in sorted(EXTERNAL.iterdir()):
            if f.is_file():
                out[str(f.relative_to(ROOT))] = 'EXT'
    for f in sorted(SKILLS.rglob('SKILL.md')):
        out[str(f.relative_to(ROOT))] = 'GK'
    for f in sorted(MEMORY.glob('*.md')) if MEMORY.is_dir() else []:
        out[str(f)] = 'GK'
    if PROPOSALS.exists():
        out[str(PROPOSALS.relative_to(ROOT))] = 'PLAN'
    return out


def manifest():
    inp = inputs()
    man = {'root': str(ROOT), 'files': {}}
    for rel, cls in sorted(inp.items()):
        p = Path(rel) if Path(rel).is_absolute() else ROOT / rel
        man['files'][rel] = {'class': cls, 'sha': sha(p), 'lines': len(p.read_text(errors='replace').splitlines()) if p.exists() else 0}
    man['counts'] = {}
    for v in man['files'].values():
        man['counts'][v['class']] = man['counts'].get(v['class'], 0) + 1
    return man


def main():
    CORPUS.mkdir(exist_ok=True)
    check = '--check' in sys.argv
    new = manifest()
    old_p = CORPUS / 'manifest.json'
    if check:
        if not old_p.exists():
            print('STALE: no manifest')
            return 3
        old = json.loads(old_p.read_text())
        diff = [k for k in set(old['files']) | set(new['files'])
                if (old['files'].get(k) or {}).get('sha') != (new['files'].get(k) or {}).get('sha')]
        print(('CURRENT' if not diff else f'STALE: {len(diff)} changed, e.g. {diff[:5]}'), f"· {sum(new['counts'].values())} inputs")
        return 0 if not diff else 3
    n_tags = build_tags()
    n_pkg, n_vend = build_pkgindex()
    old_p.write_text(json.dumps(new, indent=1))
    print(f"corpus: {sum(new['counts'].values())} inputs {new['counts']} · tags {n_tags} symbols · "
          f"pkgindex {n_pkg} first-party packages, {n_vend} vendored modules")
    return 0


if __name__ == '__main__':
    sys.exit(main())
