#!/usr/bin/env python3
"""R25 content pins for forensic replay (rft §0.8.1 rule 2, §0.8.8 G28).

A dataset version re-derives with "the pinned script at the pinned commit". Up to the R25 integration replay.py read
that literally (git HEAD == manifest git_base_commit), so v1 could only be replayed at 17da0dc and every later commit
FAILED. The pin is now the CONTENT the derivation depends on, recorded in manifest.json as `content_pins`:

  replay_tools   SHA-256 of every replay tool (replay.py, extract.py, derive.py, keccak.py, manifest_check.py, pins.py,
                 tools/forensics/*.go);
  decoder_inputs SHA-256 of every build input of `go build -trimpath -mod=vendor ./tools/forensics`: each non-standard
                 package file `go list -deps` names (Go, cgo, asm, C, H, embed files; vendored packages included), plus
                 go.mod, go.sum and vendor/modules.txt where they exist, listed for the pinned GOOS/GOARCH. One normalisation:
                 config/version.go is hashed with its `var Version = ...` line replaced by a fixed placeholder (the build
                 suffix changes every round; no decoder output reads it, rft §0.8.8 note in the manifest);
  hf3_table      SHA-256 of blockchain/hardfork_fixes.go;
  cited_lines    SHA-256 of the exact source LINES each code citation of derive.py names (file:a-b), so a cited line
                 that moves or changes FAILS while an unrelated edit elsewhere in that file does not.

Replay works at any commit as long as these bytes are identical; `pinned_commit` is still reported for provenance.
  python3 -I harness/forensics/pins.py [--check forensics/r25/manifest.json]
"""
import hashlib, json, os, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
REPLAY_TOOLS = ['harness/forensics/replay.py', 'harness/forensics/extract.py', 'harness/forensics/derive.py',
                'harness/forensics/keccak.py', 'harness/forensics/manifest_check.py', 'harness/forensics/pins.py',
                'tools/forensics/main.go', 'tools/forensics/extract.go']
HF3_TABLE = 'blockchain/hardfork_fixes.go'
MODULE_FILES = ['go.mod', 'go.sum', 'vendor/modules.txt']
NORMALIZE = {'config/version.go': (re.compile(rb'^var Version = .*$', re.M), b'var Version = <build suffix: not pinned>')}
LIST_FMT = ('{{if not .Standard}}{{.Dir}}\t{{join .GoFiles " "}} {{join .CgoFiles " "}} {{join .SFiles " "}} '
            '{{join .CFiles " "}} {{join .HFiles " "}} {{join .EmbedFiles " "}}{{end}}')
CITE_TOK = re.compile(r'([A-Za-z0-9_./-]+\.go)?:(\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*)')


def sha(b):
    return hashlib.sha256(b).hexdigest()


def file_sha(root, rel):
    p = Path(root) / rel
    if not p.exists():
        return None
    b = p.read_bytes()
    if rel in NORMALIZE:
        rx, rep = NORMALIZE[rel]
        b = rx.sub(rep, b)
    return sha(b)


def decoder_input_paths(root=ROOT, goos=None, goarch=None):
    """Sorted repo-relative paths of every non-standard build input of ./tools/forensics (vendor mode)."""
    root = Path(root)
    env = dict(os.environ, GOFLAGS='-mod=vendor')
    if goos:
        env['GOOS'] = goos
    if goarch:
        env['GOARCH'] = goarch
    p = subprocess.run(['go', 'list', '-deps', '-f', LIST_FMT, './tools/forensics'], capture_output=True, text=True,
                       cwd=str(root), env=env)
    if p.returncode:
        raise RuntimeError('go list failed: ' + (p.stderr.strip().splitlines() or ['no stderr'])[-1])
    out = {f for f in MODULE_FILES if (root / f).exists()}  # this tree has go.mod only (no go.sum, no modules.txt)
    rr = os.path.realpath(root)
    for line in p.stdout.splitlines():
        if '\t' not in line:
            continue
        d, files = line.split('\t', 1)
        rel_d = os.path.relpath(os.path.realpath(d), rr)
        if rel_d.startswith('..'):
            raise RuntimeError(f'a build input lies outside the repository: {d}')
        for f in files.split():
            out.add(os.path.normpath(os.path.join(rel_d, f)))
    return sorted(out)


def citations(text):
    """[(file, first, last)] for every code citation in `text`: `file.go:a[-b][,c...]`, and a later bare `:c[-d]` in the
    same text (e.g. "blockchain.go:826 (nonce), :858 (verify)") continues the last named file."""
    res, cur = [], None
    for m in CITE_TOK.finditer(text):
        f, spec = m.group(1), m.group(2)
        if f:
            cur = f
        elif not cur or (m.start() and text[m.start() - 1] not in ' ,('):
            continue  # a bare ':n' continues the last file only after a space, comma or '(' (never 'disc:119')
        for part in re.split(r',\s*', spec):
            a, _, b = part.partition('-')
            res.append((cur, int(a), int(b or a)))
    return res


def cited_from_derive(root=ROOT):
    """The code citations of derive.py's C table (the strings only; parsed without importing derive.py)."""
    src = (Path(root) / 'harness/forensics/derive.py').read_text()
    m = re.search(r'^C = \{.*?^\}', src, re.S | re.M)
    if not m:
        raise RuntimeError('derive.py has no citation table C')
    vals = re.findall(r"'[a-z_]+':\s*'([^']*)'", m.group(0))
    out = []
    for v in vals:
        for seg in v.split(';'):
            out += citations(seg)
    return sorted(set(out))


def lines_sha(root, f, a, b):
    p = Path(root) / f
    if not p.exists():
        return None
    ls = p.read_bytes().split(b'\n')
    if b > len(ls) or a < 1:
        return None
    return sha(b'\n'.join(ls[a - 1:b]))


def compute(root=ROOT, goos=None, goarch=None, lister=None):
    root = Path(root)
    if goos is None or goarch is None:
        e = subprocess.run(['go', 'env', 'GOOS', 'GOARCH'], capture_output=True, text=True, cwd=str(root)).stdout.split()
        goos, goarch = (goos or e[0]), (goarch or e[1])
    dec = (lister or decoder_input_paths)(root, goos, goarch)
    pins = {
        'replay_tools': {t: file_sha(root, t) for t in REPLAY_TOOLS},
        'decoder_inputs': {t: file_sha(root, t) for t in dec},
        'decoder_platform': f'{goos}/{goarch}',
        'hf3_table': {HF3_TABLE: file_sha(root, HF3_TABLE)},
        'cited_lines': {f'{f}:{a}-{b}': lines_sha(root, f, a, b) for f, a, b in cited_from_derive(root)},
        'normalized': {k: 'the `var Version = ...` line is replaced by a placeholder before hashing' for k in NORMALIZE
                       if k in dec},
    }
    pins['aggregate_sha256'] = aggregate(pins)
    return pins


def aggregate(pins):
    rows = []
    for grp in ('replay_tools', 'decoder_inputs', 'hf3_table', 'cited_lines'):
        for k, h in sorted(pins.get(grp, {}).items()):
            rows.append(f'{grp} {k} {h}\n')
    return sha(''.join(rows).encode())


def check(pins, root=ROOT, lister=None):
    """[failures]: every pinned file / cited line range must re-hash equal, and the decoder input SET must be equal.
    `lister` (root, goos, goarch) -> [paths] replaces `go list` (KAT MF12 drives a synthetic tree with it)."""
    root = Path(root)
    if not pins:
        return ['manifest has no content_pins']
    fails = []
    for grp in ('replay_tools', 'decoder_inputs', 'hf3_table'):
        if not pins.get(grp):
            fails.append(f'content pin group {grp} is empty')
        for rel, h in sorted(pins.get(grp, {}).items()):
            now = file_sha(root, rel)
            if now is None:
                fails.append(f'pinned file missing ({grp}): {rel}')
            elif now != h:
                fails.append(f'pinned file changed ({grp}): {rel}')
    for key, h in sorted(pins.get('cited_lines', {}).items()):
        f, _, rng = key.rpartition(':')
        a, _, b = rng.partition('-')
        now = lines_sha(root, f, int(a), int(b or a))
        if now is None or now != h:
            fails.append(f'cited lines changed: {key}')
    if pins.get('decoder_inputs'):
        goos, _, goarch = pins.get('decoder_platform', '/').partition('/')
        try:
            now_set = (lister or decoder_input_paths)(root, goos or None, goarch or None)
        except RuntimeError as e:
            fails.append(f'decoder input set not listable: {e}')
        else:
            pinned_set = sorted(pins['decoder_inputs'])
            if now_set != pinned_set:
                add = sorted(set(now_set) - set(pinned_set))
                rem = sorted(set(pinned_set) - set(now_set))
                fails.append(f'decoder input set changed: +{len(add)} -{len(rem)} (first {(add or rem)[0]})')
    if pins.get('aggregate_sha256') != aggregate(pins):
        fails.append('content_pins aggregate_sha256 does not match its own entries')
    return fails


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ['--check'] and len(argv) == 2:
        m = json.loads(Path(argv[1]).read_text())
        f = check(m.get('content_pins'))
        print('content pins:', 'PASS' if not f else f'FAIL ({len(f)})')
        for x in f[:50]:
            print(' ', x)
        return 0 if not f else 7
    p = compute()
    print(json.dumps({k: (len(v) if isinstance(v, dict) else v) for k, v in p.items()}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
