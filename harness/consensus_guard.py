#!/usr/bin/env python3
"""consensus_guard.py — prove a source change cannot alter what this node accepts or computes.

A DERO node that computes a different fee, balance, tree root or validity verdict than the rest of
the network forks itself off it. So every change to a consensus-visible package must be shown to be
logging-only before a binary is built from it.

Method: for each changed .go file under a consensus-visible package, normalise the base and the new
version — drop comments, drop every statement that is a logger call, collapse whitespace — and diff
what is left. The residue must be empty, or consist only of entries in ALLOWED, each of which is a
reviewed, named construct with the reason it cannot change state. New non-test files in those
packages may only define identifiers that are used inside an ALLOWED construct.

  python3 harness/consensus_guard.py [--base bf274e5] [--json out.json]
  exit 0 = logging-only (or allowed), 5 = a consensus-visible change was found
"""
import argparse, json, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEP_FILES = ('go.mod', 'go.sum', 'go.work', 'go.work.sum')
BUILD_INPUTS = ('*.go', '*.s', '*.S', '*.h', '*.c', '*.cc', '*.cpp', '*.m', '*.syso', 'vendor', *DEP_FILES)
CONSENSUS = ('blockchain/', 'dvm/', 'transaction/', 'cryptography/', 'block/', 'astrobwt/', 'pow/', 'premine/',
             'config/', 'proof/', 'rpc/')
# config/version.go's build metadata (after '+') identifies a binary; semver ignores it and the
# handshake compares only Major/Minor/Patch/Pre (p2p/rpc_handshake.go Verify_Handshake)
ALLOWED = {
    'find-blocks-empty-guard': {
        'lines': ['if len(topos_start) == 0 || len(topos_end) == 0 {', 'return nil', '}'],
        'why': 'Find_Blocks_Height_Range returns nil instead of indexing an empty slice; REACH proves that no '
               'consensus code calls it (only RPC GetTransaction, the console and the simulator, via IS_TX_Valid)',
        'reach': 'Find_Blocks_Height_Range',
    },
    'miner-suffix-sort-hook': {
        'lines': ['if SuffixSort == nil || !SuffixSort(scratch.data[:data_len], scratch.sa[:data_len]) {', '}',
                  'atomic.AddUint64(&RecoveredPanics, 1)', 'import "sync/atomic"'],
        'why': 'a nil hook around the built-in sort plus a counter in the existing recover; ASSIGNED proves only the '
               'miner ever sets SuffixSort, so derod verifies every PoW with the built-in SA-IS exactly as before',
        'assigned': {'SuffixSort': 'cmd/dero-miner/'},
    },
    'miner-hook-declarations': {
        'lines': ['var SuffixSort func(text []byte, sa []int32) bool', 'var RecoveredPanics uint64'],
        'why': 'declarations of the hook and the counter (zero values: nil, 0)',
        'assigned': {'SuffixSort': 'cmd/dero-miner/'},
    },
    'zero-signer-recover-return': {
        'lines': ['if is_zero_signer_revert(r) {', 'return', '}'],
        'why': 'an early return inside the deferred recover of process_transaction_sc; it assigns nothing, '
               'so the named results (gas, err) keep the values they had at the panic — exactly as before',
    },
}


def READ(f):
    """The new version of a file. A KAT replaces this to feed the guard a mutated tree."""
    return (ROOT / f).read_text() if (ROOT / f).exists() else ''


def git(*a):
    return subprocess.run(['git', *a], cwd=ROOT, capture_output=True, text=True).stdout


def strip(src):
    src = re.sub(r'/\*.*?\*/', ' ', src, flags=re.S)
    out = []
    for l in src.splitlines():
        l = re.sub(r'(^|[^:"])//.*$', r'\1', l)          # line comments (not inside "http://")
        s = l.strip()
        if not s:
            continue
        if re.match(r'^(c\.|connection\.)?\w*logger(\.V\(\d+\))?\.(Info|Error)\(.*\)$', s) and \
                not re.search(r'(?<![=!<>:])=(?!=)|\+\+|--', re.sub(r'"(?:[^"\\]|\\.)*"', '""', s)):
            continue                                     # a logging statement that assigns nothing: no state
        out.append(re.sub(r'\s+', ' ', s))
    return out


def callers(name):
    """(file, line, enclosing function) of every non-comment call of .name( outside vendor/ and the harness."""
    out = []
    r = subprocess.run(['grep', '-rn', '--include=*.go', rf'\.{name}(', '.'], cwd=ROOT, capture_output=True, text=True)
    for hit in r.stdout.splitlines():
        f, ln, text = hit.split(':', 2)
        f = f.lstrip('./')
        if f.startswith(('vendor/', 'harness/')) or f.endswith('_test.go') or text.strip().startswith('//') \
                or re.search(rf'func \([^)]*\) {name}\(', text):
            continue
        src = READ(f).splitlines()
        enc = next((m.group(1) for l in reversed(src[:int(ln)]) for m in [re.match(r'^func (?:\([^)]*\) )?(\w+)\(', l)] if m), '?')
        out.append((f, int(ln), enc))
    return out


def reach_ok(name, seen=None):
    """True when no consensus-package function outside this call chain can reach `name`. A caller in cmd/ is an
    application entry point; a caller inside a consensus package must itself pass the same test."""
    seen = seen or set()
    if name in seen:
        return True, []
    seen.add(name)
    bad, chain = [], []
    for f, ln, enc in callers(name):
        chain.append(f'{f}:{ln} in {enc}')
        if f.startswith('cmd/'):
            continue
        if f.startswith(CONSENSUS):
            ok, sub_chain = reach_ok(enc, seen)
            chain += sub_chain
            if not ok:
                bad.append(f'{f}:{ln} in {enc}')
        else:
            bad.append(f'{f}:{ln} in {enc} (outside cmd/ and not checked)')
    return not bad, chain + [f'UNSAFE {b}' for b in bad]


def assigned_ok(name, prefix):
    """Every non-test assignment `X.name =` / `name =` (outside its declaration) is under prefix."""
    r = subprocess.run(['grep', '-rnE', '--include=*.go', rf'(\.|\b){name}\s*=[^=]', '.'], cwd=ROOT, capture_output=True, text=True)
    bad, seen = [], []
    for hit in r.stdout.splitlines():
        f, ln, txt = hit.split(':', 2)
        f = f.lstrip('./')
        if f.startswith(('vendor/', 'harness/')) or f.endswith('_test.go') or txt.strip().startswith(('//', 'var ')):
            continue
        seen.append(f'{f}:{ln}')
        if not f.startswith(prefix):
            bad.append(f'{f}:{ln}')
    return not bad, seen, bad


def residue(old, new):
    import difflib
    d = [l for l in difflib.unified_diff(strip(old), strip(new), lineterm='', n=0)
         if l[:1] in '+-' and not l.startswith(('+++', '---'))]
    return d


def evaluate(base='bf274e5'):
    a = argparse.Namespace(base=base)
    # every build input, not only *.go: assembly/C/syso in a consensus package and ANY vendor/ file (including
    # vendor/modules.txt) or go.work can change what the compiler links into the consensus code
    changed = [l.split('\t') for l in git('diff', '--no-renames', '--name-status', a.base, '--', *BUILD_INPUTS).splitlines()]
    changed += [['A', f] for f in git('ls-files', '--others', '--exclude-standard', '--', *BUILD_INPUTS).splitlines()]
    # --no-renames: a rename/delete must surface as D old + A new, else a deleted consensus file pairs with an
    # unrelated added file (R059 blockchain/tx_fees.go -> cmd/...) and only the non-consensus path is judged
    changed = [[c[0], c[-1]] for c in changed if len(c) >= 2]
    report = {'base': a.base, 'files': [], 'violations': [], 'allowed_used': []}
    allowed_lines = {name: [re.sub(r'\s+', ' ', x) for x in spec['lines']] for name, spec in ALLOWED.items()}
    for st, f in changed:
        if f in DEP_FILES or (f.startswith('vendor/') and not f.endswith('_test.go')):
            # a dependency change can alter anything, including graviton's tree hashing; never allowed silently
            report['violations'].append({'file': f, 'what': 'dependency changed (vendor/ or go.mod/go.sum)'})
            report['files'].append({'file': f, 'status': st, 'verdict': 'DEPENDENCY CHANGED'})
            continue
        if not f.startswith(CONSENSUS) or f.endswith('_test.go'):
            continue
        if not f.endswith('.go'):
            # the normaliser understands Go only; an assembly/C change is state-affecting until reviewed by hand
            report['violations'].append({'file': f, 'what': 'non-Go build input changed in a consensus package'})
            report['files'].append({'file': f, 'status': st, 'verdict': 'NON-GO BUILD INPUT CHANGED'})
            continue
        new = READ(f)
        old = git('show', f'{a.base}:{f}') if st != 'A' else ''
        entry = {'file': f, 'status': st}
        if f == 'config/version.go':
            ov = re.search(r'MustParse\("([^"+]+)', old)
            nv = re.search(r'MustParse\("([^"+]+)', new)
            ok = bool(ov and nv and ov.group(1) == nv.group(1))
            entry['verdict'] = 'build-metadata only' if ok else 'VERSION CORE CHANGED'
            if not ok:
                report['violations'].append({'file': f, 'what': 'version core changed'})
            report['files'].append(entry)
            continue
        if st == 'A':
            # a new helper file: every identifier it declares must be used only inside an ALLOWED construct
            decls = re.findall(r'^(?:func|var|const)\s+([A-Za-z_]\w*)', new, flags=re.M)
            uses = []
            for d in decls:
                for g in git('grep', '-n', rf'\b{d}\b', '--', '*.go').splitlines() + \
                         subprocess.run(['grep', '-rn', rf'\b{d}\b', '--include=*.go', '.'], cwd=ROOT,
                                        capture_output=True, text=True).stdout.splitlines():
                    p = g.split(':', 1)[0].lstrip('./')
                    if p in (f,) or p.endswith('_test.go') or p.startswith('vendor/'):
                        continue
                    uses.append(g)
            bad = [u for u in dict.fromkeys(uses) if 'if is_zero_signer_revert(r) {' not in u]
            entry['verdict'] = 'helper used only inside an allowed construct' if not bad else 'HELPER USED ELSEWHERE'
            entry['uses'] = sorted(set(uses))
            if bad:
                report['violations'].append({'file': f, 'what': 'helper referenced outside an allowed construct', 'where': bad})
            report['files'].append(entry)
            continue
        r = residue(old, new)
        plus = [l[1:] for l in r if l.startswith('+')]
        minus = [l[1:] for l in r if l.startswith('-')]
        used = []
        for name, lines in allowed_lines.items():
            if plus[:len(lines)] == lines or all(x in plus for x in lines):
                spec = ALLOWED[name]
                for nm, prefix in (spec.get('assigned') or {}).items():
                    ok, seen, bad = assigned_ok(nm, prefix)
                    entry.setdefault('assigned', {})[nm] = seen
                    if not ok:
                        report['violations'].append({'file': f, 'what': f"{name}: {nm} assigned outside {prefix}", 'where': bad})
                if spec.get('reach'):
                    ok, chain = reach_ok(spec['reach'])
                    entry.setdefault('reach', {})[spec['reach']] = chain
                    if not ok:
                        report['violations'].append({'file': f, 'what': f"{name}: {spec['reach']} is reachable from consensus code", 'chain': chain})
                        continue
                for x in lines:
                    if x in plus:
                        plus.remove(x)
                used.append(name)
        entry['residue_plus'], entry['residue_minus'], entry['allowed'] = plus, minus, used
        entry['verdict'] = 'logging-only' + (f' + {", ".join(used)}' if used else '') if not plus and not minus else 'STATE-AFFECTING DIFF'
        if plus or minus:
            report['violations'].append({'file': f, 'what': 'non-logging change', 'plus': plus, 'minus': minus})
        report['allowed_used'] += used
        report['files'].append(entry)
    report['ok'] = not report['violations']
    report['allowed'] = {k: v['why'] for k, v in ALLOWED.items() if k in report['allowed_used']}
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--base', default='bf274e5')
    ap.add_argument('--json')
    a = ap.parse_args()
    report = evaluate(a.base)
    out = json.dumps(report, indent=1)
    if a.json:
        Path(a.json).write_text(out)
    for e in report['files']:
        print(f"  {e['verdict']:52s} {e['file']}")
    print('consensus guard:', 'PASS' if report['ok'] else 'FAIL', f"({len(report['files'])} consensus-package file(s) changed vs {a.base})")
    for v in report['violations']:
        print('  VIOLATION', v)
    return 0 if report['ok'] else 5


if __name__ == '__main__':
    sys.exit(main())
