#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the held patches (dero-rft §7 B147, B144; R28 glue-global).

A held patch (harness/loop/held/*.patch) is a fix that cannot land yet because the file it changes is content-pinned
by a sealed forensic dataset (forensics/r<N>/manifest.json content_pins): changing the file fails test_forensics_r25
MF12 and G28 (R27 merge). The hold is only safe while it stays applicable, justified and visible, so every run checks:

  HP1 every held patch that no other held patch supersedes ('# ... Supersedes <name>' in its header) applies forward
      on the tree (git apply --check, the switch file excluded: HP3 owns it; nothing is written); a superseded one is
      named, never checked.
  HP2 the hold is still justified: every non-test file a live held patch changes is pinned by some dataset manifest
      (read from the JSON here, independently of tooling_intel). A target no manifest pins means the hold is obsolete:
      land the patch.
  HP3 the tree state is coherent: every live patch names its switch ('# Switch: <file> <const>': b147_landed in
      globals/r28_b147_state_test.go, rpc_copy_landed in rpc/r28_rpc_copy_state_test.go); while the const is false
      every pinned target of that patch keeps its pinned sha256 (held), and once true it must differ (landed). A switch
      that disagrees with the bytes is the state the Go tests also refuse, caught here without a Go build. A LANDED
      patch (moved to harness/loop/held/landed/, R28 merge: B147) is no longer live; its switch must read true.
  HP4 tooling_intel.content_pinned lists every path a content_pins section names (the decoder inputs, and the file of
      each cited line: globals/globals.go, rpc/wallet_rpc.go, block/block.go, glue/txprecheck/window.go on r25):
      before R28 it read only harness/, tools/ and glue/ paths with a regex, so the R27 glue-global agents saw
      globals.go as editable (B147 guard 'pending').
  HP5 (--go only, slow) the landing patch on a `git clone --shared` of HEAD plus the working-tree diff: go test
      ./globals/ ./rpc/ passes after `git apply`, i.e. the landing is ready to run with the next dataset version.

Every KAT runs on a temporary copy (the files it needs, APFS clone where possible), never on the live tree; under a
mutation the copy is the mutant. Mutation independence: harness/kit/katmut.py (each mutation names its KAT).

  python3 -I harness/kat/test_held_patches_r28.py [--go]
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught by its own KAT, was INVALID, or coupled.
"""
import hashlib, importlib.util, json, re, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
HELD = 'harness/loop/held'
SWITCH = 'globals/r28_b147_state_test.go'          # the B147 landing's switch (named in its patch header)
SWITCH_HDR_RX = re.compile(r'^# Switch: (\S+) (\w+)\s*$', re.M)
SUPERSEDES_RX = re.compile(r'^#.*\bSupersedes ([\w.-]+\.patch)', re.M)
TARGET_RX = re.compile(r'^\+\+\+ b/(\S+)', re.M)
MUST_LIST = ('globals/globals.go', 'rpc/wallet_rpc.go', 'block/block.go', 'glue/txprecheck/window.go')
COPY = ['harness/intel/tooling_intel.py', HELD, 'forensics', 'globals', 'rpc/wallet_rpc.go', 'rpc/r28_rpc_copy_state_test.go']


def copy_root(dst):
    """the files the KATs read, copied (cp -c: APFS clone) into dst; forensics/ only its manifests"""
    dst = Path(dst)
    for rel in COPY:
        src, out = ROOT / rel, dst / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        if rel == 'forensics':
            for m in sorted(src.glob('*/manifest.json')):
                (out / m.parent.name).mkdir(parents=True, exist_ok=True)
                shutil.copy2(m, out / m.parent.name / 'manifest.json')
        elif src.is_dir():
            if subprocess.run(['cp', '-cR', str(src), str(out)], capture_output=True).returncode != 0:
                shutil.copytree(src, out)
        else:
            shutil.copy2(src, out)
    return dst


def patches(root):
    """{name: text} of the held patches and the set of names some other held patch supersedes"""
    ps = {p.name: p.read_text(encoding='utf-8') for p in sorted((Path(root) / HELD).glob('*.patch'))}
    sup = {s for n, t in ps.items() for s in SUPERSEDES_RX.findall(t) if s != n}
    return ps, sup


def manifest_pins(root):
    """{repo path: sha256} from every forensics/*/manifest.json content_pins section (newest version last wins);
    'path:lines' citations are skipped here (they pin lines, not a whole-file hash)"""
    out = {}
    for m in sorted(Path(root).glob('forensics/*/manifest.json')):
        try:
            cp = json.loads(m.read_text(encoding='utf-8')).get('content_pins') or {}
        except (OSError, ValueError):
            continue
        for sec in cp.values():
            if isinstance(sec, dict):
                out.update({k: v for k, v in sec.items() if ':' not in k and isinstance(v, str)})
    return out


def live_targets(root, only=None):
    ps, sup = patches(root)
    return sorted({t for n, txt in ps.items() if n not in sup and only in (None, n) for t in TARGET_RX.findall(txt)
                   if not t.endswith('_test.go')})


def switch_of(text):
    """(file, const) of a patch's '# Switch: <file> <const>' header line, or None"""
    m = SWITCH_HDR_RX.search(text)
    return (m.group(1), m.group(2)) if m else None


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def hp1(P):
    root = P['root']
    ps, sup = patches(root)
    if not ps:
        return False, 'no held patch found'
    bad = []
    for n, txt in ps.items():
        if n in sup:
            continue
        # the switch hunk is HP3's: its state is judged there (a flipped switch is not an HP1 context failure)
        sw = switch_of(txt)
        ex = [f'--exclude={sw[0]}'] if sw else []
        r = subprocess.run(['git', 'apply', '--check', *ex, '-'], input=txt, text=True, cwd=root, capture_output=True)
        if r.returncode != 0:
            bad.append(f'{n}: {r.stderr.strip()[:200]}')
    live = sorted(set(ps) - sup)
    return not bad, f'live {live} superseded {sorted(sup)}' + (f' NOT APPLICABLE {bad}' if bad else '')


def hp2(P):
    pins = manifest_pins(P['root'])
    tg = live_targets(P['root'])
    obsolete = [t for t in tg if t not in pins]
    return bool(tg) and not obsolete, f'targets {tg}' + (f' NOT PINNED (hold obsolete: land it) {obsolete}' if obsolete else ' all pinned')


def hp3(P):
    root = Path(P['root'])
    ps, sup = patches(root)
    pins = manifest_pins(root)
    out, bad = [], []
    for n, txt in sorted(ps.items()):
        if n in sup:
            continue
        sw = switch_of(txt)
        if not sw:
            bad.append(f'{n}: no "# Switch: <file> <const>" header')
            continue
        m = re.search(rf'^const {sw[1]} = (true|false)$', (root / sw[0]).read_text(encoding='utf-8'), re.M) \
            if (root / sw[0]).exists() else None
        if not m:
            bad.append(f'{n}: {sw[0]} has no const {sw[1]}')
            continue
        landed = m.group(1) == 'true'
        state = {t: sha(root / t) == pins[t] for t in live_targets(root, n) if t in pins and (root / t).exists()}
        wrong = [t for t, same in state.items() if same == landed]
        out.append(f'{n}: {sw[1]}={landed} pinned-bytes {state}')
        if wrong:                         # a patch with no pinned target is HP2's (hold obsolete), not judged here
            bad.append(f'{n}: INCOHERENT {wrong}')
    for lp in sorted((root / HELD / 'landed').glob('*.patch')):     # R28 merge: a landed patch keeps its switch on
        sw = switch_of(lp.read_text(encoding='utf-8'))
        if not sw:
            continue                      # landed before switches existed (r27): nothing to check
        m = re.search(rf'^const {sw[1]} = (true|false)$', (root / sw[0]).read_text(encoding='utf-8'), re.M) \
            if (root / sw[0]).exists() else None
        out.append(f'landed/{lp.name}: {sw[1]}={m.group(1) if m else None}')
        if not m or m.group(1) != 'true':
            bad.append(f'landed/{lp.name}: switch {sw[1]} is not true')
    return not bad and bool(out), '; '.join(out) + (f' BAD {bad}' if bad else '')


def pinned_files(root):
    """every repo file a content_pins section names (whole-file pins and the files of 'path:lines' citations)"""
    out = set()
    for m in sorted(Path(root).glob('forensics/*/manifest.json')):
        try:
            cp = json.loads(m.read_text(encoding='utf-8')).get('content_pins') or {}
        except (OSError, ValueError):
            continue
        out |= {k.split(':', 1)[0] for sec in cp.values() if isinstance(sec, dict) for k in sec}
    return out


def hp4(P):
    root = Path(P['root'])
    spec = importlib.util.spec_from_file_location(f'ti_hp4_{abs(hash(str(root)))}', root / 'harness/intel/tooling_intel.py')
    T = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(T)
    got, want = T.content_pinned(root), pinned_files(root)
    miss = sorted(want - got)
    named = [p for p in MUST_LIST if p in want]
    return bool(want) and not miss, (f'{len(got)} listed, {len(want)} pinned (incl. {named})' +
                                     (f' MISSING {len(miss)}: {miss[:6]}' if miss else ''))


def hp5():
    """the landing rehearsal: clone --shared HEAD, carry the working tree over, apply the live landing patch, go test"""
    with tempfile.TemporaryDirectory(prefix='hp5_') as d:
        c = Path(d) / 'c'
        run = lambda *a, **k: subprocess.run(list(a), capture_output=True, text=True, **k)
        if run('git', 'clone', '-q', '--shared', str(ROOT), str(c)).returncode != 0:
            return False, 'clone failed'
        rev = run('git', 'rev-parse', 'HEAD', cwd=ROOT).stdout.strip()
        run('git', 'checkout', '-q', rev, cwd=c)
        diff = subprocess.run(['git', 'diff', 'HEAD', '--binary'], cwd=ROOT, capture_output=True).stdout
        if diff and subprocess.run(['git', 'apply', '-'], input=diff, cwd=c, capture_output=True).returncode != 0:
            return False, 'working-tree diff did not apply to the clone'
        for f in run('git', 'ls-files', '--others', '--exclude-standard', cwd=ROOT).stdout.split():
            (c / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / f, c / f)
        ps, sup = patches(ROOT)
        live = [n for n in ps if n not in sup]
        for n in live:
            r = run('git', 'apply', str(ROOT / HELD / n), cwd=c)
            if r.returncode != 0:
                return False, f'{n}: {r.stderr.strip()[:200]}'
        r = run('nice', '-n', '15', 'go', 'test', '-p', '1', '-count=1', './globals/', './rpc/', cwd=c)
        return r.returncode == 0, f'landing {live}: go test ./globals/ ./rpc/ -> {r.stdout.strip()[-300:]} {r.stderr.strip()[-300:]}'


KATS = [('HP1', hp1), ('HP2', hp2), ('HP3', hp3), ('HP4', hp4)]
OWNERS = {f'r28 HP{i}': [f'HP{i}'] for i in range(1, 5)}

MUTATIONS = [   # (repo-relative file in the copy, find, replace, why: 'r28 HP<n>: ...')
    # R28 merge: B147 landed, so the globals mutations are re-anchored on the one live patch (rpc copy) and on the
    # landed switch (rft §10 'an edit moves other KATs' anchors': re-anchored, never deleted)
    (f'{HELD}/r28_rpc_money_copy.patch', ' func FormatMoneyPrecision(', ' func FormatMoneyPrecision2(',
     'r28 HP1: a held patch whose context no longer matches the tree'),
    ('forensics/*/manifest.json', '"rpc/wallet_rpc.go":', '"rpc/wallet_rpc.go.unpinned":',  # a glob: every manifest
     'r28 HP2: a held target that no dataset pins any more (the hold is obsolete)'),
    (SWITCH, 'const b147_landed = true', 'const b147_landed = false',
     'r28 HP3: a landed patch whose switch is back off'),
    ('rpc/r28_rpc_copy_state_test.go', 'const rpc_copy_landed = false', 'const rpc_copy_landed = true',
     'r28 HP3: the rpc copy switch on over the pinned (held) bytes'),
    (f'{HELD}/r28_rpc_money_copy.patch', '# Switch: rpc/r28_rpc_copy_state_test.go rpc_copy_landed\n', '',
     'r28 HP3: a live held patch that names no switch'),
    ('rpc/wallet_rpc.go', 'package rpc\n', 'package rpc\n\n// edited outside the landing\n',
     'r28 HP3: a pinned target changed while the switch says held'),
    ('harness/intel/tooling_intel.py', "        for sec in pins.values():\n            if isinstance(sec, dict):",
     "        for sec in ():\n            if isinstance(sec, dict):",
     'r28 HP4: content_pinned back to the regex-only listing (decoder inputs missed)'),
]


def run_on(mutation=None):
    with tempfile.TemporaryDirectory(prefix='hp28_') as d:
        root = copy_root(Path(d) / 'r')
        if mutation:
            rel, find, repl, _ = mutation
            for p in (sorted(root.glob(rel)) if '*' in rel else [root / rel]):   # R28 merge: a glob mutates every match
                p.write_text(p.read_text(encoding='utf-8').replace(find, repl, 1), encoding='utf-8')
                if p.suffix == '.py':
                    compile(p.read_text(encoding='utf-8'), str(p), 'exec')
        res = []
        for name, fn in KATS:
            try:
                o, det = fn({'root': root})
            except Exception as e:                                    # noqa: BLE001
                o, det = False, f'{type(e).__name__}: {e}'
            res.append((name, o, det))
        return res


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_r28hp', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    if set(argv) - {'--go'}:
        print(f'unknown argument(s) {sorted(set(argv) - {"--go"})}', file=sys.stderr)
        return 2
    res = run_on()
    if '--go' in argv:
        o, det = hp5()
        res.append(('HP5', o, det))
    for name, o, det in res:
        print(f"{'ok  ' if o else 'FAIL'} {name} {det[:600]}")
    if not all(o for _, o, _ in res):
        return 3
    K = katmut()
    missed = coupled = 0
    for mut in MUTATIONS:
        rel, find, repl, why = mut
        files = sorted(ROOT.glob(rel)) if '*' in rel else [ROOT / rel]
        counts = [p.read_text(encoding='utf-8').count(find) for p in files]
        if not any(counts) or any(c > 1 for c in counts):          # a glob: once in each file that has it
            print(f'  ??      {why}: find text occurs {counts} times')
            missed += 1
            continue
        try:
            r = run_on(mut)
        except SyntaxError as e:
            print(f'  INVALID {why}: mutant does not compile ({e.msg})')
            missed += 1
            continue
        failed = [n for n, o, _ in r if not o]
        verdict, extra = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f"  {verdict:8} {why}" + (f'  [{",".join(failed)}]' if failed else '')
              + (f'  COUPLED {extra}' if extra and verdict == 'proved' else ''))
        missed += verdict != 'proved'
        coupled += bool(extra) and verdict == 'proved'
    print('\n' + K.summary('r28 held-patch KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed or coupled else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
