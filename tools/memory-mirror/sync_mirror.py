#!/usr/bin/env python3
"""r25 (dero-rft §0.9 rule 5, B88): rebuild the scrubbed in-repo memory mirror from one private stamp.

  python3 -I tools/memory-mirror/sync_mirror.py --stamp <private stamp dir> --repo <repo root> [--pubscrub FILE]

Every *.md of the stamp goes through pubscrub.py (the publish scrubber: wallet prefix, e-mail, home paths, IPs, host
and app names) into a temporary directory. A scrubbed file that still carries a private-identifier shape
(harness/intel/tooling_intel.py private_hits: a home path, a scratchpad project dir name, an e-mail, a DERO address, a
non-reserved IPv4) is NOT mirrored: its manifest line says '-' and the run names it (by file name only). One extra
two rules run after pubscrub (redact): an e-mail shape is written '<e-mail>' (pubscrub rewrites the user's name inside
an address but leaves the address shape, so its own residual check failed on one memory file, 2026-11-03), and a
non-reserved IPv4 '<ip>' (pubscrub's IP scan misses an address that ends a sentence, '... 192.0.2.1.'). The mirror
directory is then replaced: files of an older sync that are no longer produced are removed. memory-mirror/MANIFEST.sha256
gets one line per source file: '<source sha256> <mirror sha256 or -> <file>' (the drift check reads it).

r27 (rft §0.9 rule 5, B88 residual): pubscrub's own residual check runs on ITS output, i.e. before the redact rules,
so every round reported 'pubscrub rc 1' for files whose residual redact() had already removed, or had never been
written to remove (the export tool's own names, the tool-signature trailer, the OS version): the residual was printed and
never driven to 0. Now redact() also rewrites those three shapes (the tool names are read from harness/loop/
TOOL_PATHS.json, so this published file never names the tool), and the residual is measured where it matters: pubscrub
runs a second time over the FINAL mirror bytes. A file whose final residual names a check outside RESIDUAL_ALLOW (each
allowed check carries its reason) is refused like a private hit. The run prints both return codes ('pubscrub rc raw X ·
final Y') and the final residual per file.

Exit 0 mirrored · 1 a file was refused for a private identifier or an unexplained residual (the others are still
mirrored) · 2 bad invocation.
"""
import argparse, ast, hashlib, importlib.util, json, os, re, subprocess, sys, tempfile
from pathlib import Path


EMAIL_RX = re.compile(rb'[\w.+-]+@[\w-]+\.[\w.]+')

# r26 (Part A; rft §1 R26 "scrub the 4 older memory-mirror files that name machine models"): machine models of the
# private setup are machine info (memory feedback-publish-privacy, 2026-11-03), and pubscrub rewrites only a few exact
# phrases of them (the export rules hold R10, not pubscrub). The facts stay (core counts, GPU, RAM); only the model
# names are generalised. Ordered: the longer phrase first. Lower-case identifiers (file names such as
# dero-miner-m1-ceiling, the compiler flag -mcpu=apple-m1) are code anchors and are kept.
MODEL_RULES = [
    (re.compile(r'(?:Apple )?(\*\*)?M1 Ultra Mac' ' Studio'), r'\1mining host'),
    (re.compile(r'(?:\bthe )?(?:Apple )?M1 Ultra'), 'the mining host'),
    (re.compile(r'Mac' ' Studio'), 'mining host'),
    (re.compile(r'(?:\bLAN )?MacBook(?: Pro)?'), 'second LAN machine'),
    (re.compile(r"\bM1's\b"), "hardware's"),
    (re.compile(r'\ban M1\b'), 'the chip'),
    (re.compile(r'\bM1 cores\b'), 'cores'),
    (re.compile(r'\bM1\b'), 'CPU'),
]


# r27: the residual shapes redact() did not cover before. The trailer and the link are written so that this file does not
# match the publish check for them; the OS version keeps the word 'macOS' and drops the number and the build.
SIG_RULES = [
    (re.compile(r'Co-Authored-By:\s*Claude\b[^\n"]*'), '<tool trailer>'),
    (re.compile(r'claude[.]ai/(?:code/)?artifact\S*'), '<tool link>'),
    (re.compile(r'\bmacOS \d{1,2}(?:\.\d+){1,2}(?: \([0-9A-Z]{4,8}\))?'), 'macOS <version>'),
]
TOOL_WORD = '<export tool>'
# the pubscrub residual checks a mirror file may keep, with the reason (memory-mirror/ is never published, rft §0.9 rule 5)
RESIDUAL_ALLOW = {
    'ext-impl': 'names of external implementations are public facts; the GitHub copy excludes memory-mirror/',
    'ext-author': 'a public author name of an external implementation; the GitHub copy excludes memory-mirror/',
}
RESIDUAL_LINE = re.compile(r'^(\S+) \d+ rules \[.*?\] residual (\{.*?\}) ips (.*)$')


def tool_terms(cfg):
    """the out-of-repo tool names a mirror file must not carry, from a TOOL_PATHS mapping {key: '~/dir/sub/file.py'}:
    every directory component under the home and the stem of every tool file except the scrubber's (pubscrub is a
    published name). Longest first, so a longer name is replaced before a name it contains. Pure."""
    out = set()
    for k, v in (cfg or {}).items():
        if k.startswith('_') or not isinstance(v, str):
            continue
        parts = [x for x in Path(v).parts if x not in ('~', '/', '')]
        if not parts:
            continue
        out.update(parts[:-1])
        if k != 'pubscrub':
            out.add(Path(parts[-1]).stem)
    return sorted(out, key=lambda x: (-len(x), x))


def tool_config(repo):
    try:
        return json.loads((Path(repo) / 'harness/loop/TOOL_PATHS.json').read_text())
    except (OSError, ValueError):
        return {}


def scrub_tools(t, terms):
    """r27: the tool names (tool_terms) -> TOOL_WORD, the tool-signature trailer and link, the OS version (SIG_RULES). Pure."""
    for w in terms:
        t = re.sub(r'(?<![\w-])' + re.escape(w) + r'(?![\w-])', TOOL_WORD, t)
    for rx, rep in SIG_RULES:
        t = rx.sub(rep, t)
    return t


def parse_residual(stdout):
    """{file name: {check: count, 'ip': [..]}} from pubscrub's per-file report lines; a file with an empty residual and no
    leaked address maps to {}. Pure."""
    out = {}
    for l in stdout.splitlines():
        m = RESIDUAL_LINE.match(l.strip())
        if not m:
            continue
        try:
            found = dict(ast.literal_eval(m.group(2)))
            ips = ast.literal_eval(m.group(3))
        except (ValueError, SyntaxError):
            found, ips = {'unparsed': 1}, []
        if isinstance(ips, (list, tuple)) and ips:
            found['ip'] = len(ips)
        out[os.path.basename(m.group(1))] = found
    return out


def final_residual(stdout):
    """parse_residual of the final pass, or None (not measured) when the scrubber printed no report line at all (a
    stand-in scrubber, or a scrubber without the report format): an unmeasured residual refuses nothing and is
    printed 'pending'. Pure."""
    return parse_residual(stdout) or None


def unexplained(found):
    """the residual checks of one file that RESIDUAL_ALLOW does not explain. Pure."""
    return {k: v for k, v in (found or {}).items() if k not in RESIDUAL_ALLOW}


def generalise_models(t):
    """machine-model names -> generic wording (MODEL_RULES). Pure."""
    for rx, rep in MODEL_RULES:
        t = rx.sub(rep, t)
    return t


def redact(b, T, terms=()):
    """the rules run after pubscrub: an e-mail shape -> '<e-mail>'; a non-reserved IPv4 (tooling_intel's shape, which
    also reads an address that ends a sentence) -> '<ip>'; r26: machine-model names generalised (MODEL_RULES); r27: the
    tool names, the tool-signature trailer/link and the OS version (scrub_tools). Pure."""
    b = EMAIL_RX.sub(b'<e-mail>', b)
    t = b.decode('utf-8', errors='replace')
    rx = dict(T.PRIVATE_RX)['ipv4']
    t = rx.sub(lambda m: m.group(0) if T.IP_OK.match(m.group(0)) or any(int(x) > 255 for x in m.group(0).split('.')) else '<ip>', t)
    t = generalise_models(t)
    t = scrub_tools(t, terms)
    return t.encode('utf-8')


def load_tooling(repo):
    spec = importlib.util.spec_from_file_location('tooling_intel_for_mirror', Path(repo) / 'harness/intel/tooling_intel.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def sha(b):
    return hashlib.sha256(b).hexdigest()


def plan(stamp_files, scrubbed, hits, residual=None):
    """{name: mirror bytes or None} and the refused names: a scrubbed file with a private hit is refused; r27: so is a
    file whose final residual (residual = {name: found}, None = not measured) has a check RESIDUAL_ALLOW does not
    explain, or that the final pass did not report on. Pure."""
    keep, refused = {}, []
    for n in sorted(stamp_files):
        b = scrubbed.get(n)
        if (b is None or hits(b.decode('utf-8', errors='replace'))
                or (residual is not None and (n not in residual or unexplained(residual[n])))):
            keep[n] = None
            refused.append(n)
        else:
            keep[n] = b
    return keep, refused


def manifest_lines(stamp_files, keep):
    """'<source sha> <mirror sha or -> <file>' per source file, sorted. Pure."""
    return [f"{sha(stamp_files[n])} {sha(keep[n]) if keep.get(n) is not None else '-'} {n}" for n in sorted(stamp_files)]


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument('--stamp', required=True)
    ap.add_argument('--repo', required=True)
    ap.add_argument('--pubscrub', default=None, help='default: harness/loop/TOOL_PATHS.json "pubscrub" of --repo')
    a = ap.parse_args(argv)
    stamp, repo = Path(a.stamp), Path(a.repo)
    if a.pubscrub is None and (repo / 'harness').is_dir():
        tp = load_tooling(repo).tool_path('pubscrub', repo)
        a.pubscrub = str(tp) if tp else ''
    if not stamp.is_dir() or not (repo / 'harness').is_dir() or not Path(a.pubscrub).is_file():
        print('sync_mirror: --stamp, --repo or --pubscrub not found')
        return 2
    T = load_tooling(repo)
    terms = tool_terms(tool_config(repo))
    src = {p.name: p.read_bytes() for p in sorted(stamp.glob('*.md'))}
    scrubbed = {}
    with tempfile.TemporaryDirectory(prefix='r25mirror-') as d:
        r = subprocess.run([sys.executable, '-I', a.pubscrub, d, *[str(stamp / n) for n in src]], capture_output=True, text=True)
        for n in src:
            p = Path(d) / n
            if p.exists():
                scrubbed[n] = redact(p.read_bytes(), T, terms)
    # r27: the residual of the FINAL bytes (a second pubscrub pass over the redacted files)
    with tempfile.TemporaryDirectory(prefix='r27mirror-') as d2:
        fin, chk = Path(d2) / 'final', Path(d2) / 'check'
        fin.mkdir()
        chk.mkdir()
        for n, b in scrubbed.items():
            (fin / n).write_bytes(b)
        r2 = subprocess.run([sys.executable, '-I', a.pubscrub, str(chk), *[str(fin / n) for n in sorted(scrubbed)]],
                            capture_output=True, text=True)
        residual = final_residual(r2.stdout)
    keep, refused = plan(src, scrubbed, T.private_hits, residual)
    out = repo / T.MIRROR
    if out.exists():
        for p in out.iterdir():
            if p.is_file():
                p.unlink()
    out.mkdir(exist_ok=True)
    for n, b in keep.items():
        if b is not None:
            (out / n).write_bytes(b)
    (out / T.MANIFEST).write_text('\n'.join(manifest_lines(src, keep)) + '\n')
    left = {n: f for n, f in sorted((residual or {}).items()) if f}
    print(f'sync_mirror: {sum(1 for b in keep.values() if b is not None)} mirrored, {len(refused)} refused for a private '
          f'identifier or an unexplained residual {refused}, pubscrub rc raw {r.returncode} · final {r2.returncode}, '
          f"final residual {(left or 0) if residual is not None else 'pending (no report line)'}"
          + (f" (allowed: {sorted({k for f in left.values() for k in f if k in RESIDUAL_ALLOW})})" if left else ''))
    return 1 if refused else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
