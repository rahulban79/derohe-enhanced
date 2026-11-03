#!/usr/bin/env python3
"""verify_deroarch.py — KAT suite for harness/ (the DERO HE living-architecture page).

  python3 kat/verify_deroarch.py              # KATs on a scratch COPY of harness/ (the tree symlinked read-only)
  python3 kat/verify_deroarch.py --mutations  # each mutation breaks the tool on a fresh copy; ITS KAT must flip to FAIL

A KAT that is not True on the unmutated copy is DEGENERATE (not proved). Nothing here writes the real harness
or the real page.

  DK01 every anchor of every rendered row re-resolves to the same file:line        ← the evidence contract
  DK02 resolve() is deterministic: two runs give identical rows                    ← recompute-from-source
  DK03 a row whose quote is not in its file is refused, never rendered             ← the quarantine works
  DK04 a row whose class its anchors cannot prove is re-classed and says so        ← class = where the proof points
  DK05 a quote under 12 characters is refused                                      ← no trivial anchors
  DK06 `check` exits 3 when a model file changes after the build                   ← drift is caught
  DK07 the class vocabulary is closed and agrees with prep_corpus.class_of         ← one definition of each class
  DK08 log bridge: every bridged console line's literal is really on that Go line  ← console → source is true
  DK09 log bridge plausibility: the emitter is in a package that owns that logger  ← no coincidental matches
  DK10 flows: every hop re-reads, hop order is 1..n, a broken chain is not drawn   ← diagrams cannot lie
  DK11 consts known answer: BLOCK_TIME and the halving interval recomputed here    ← constants are read, not typed
  DK12 difficulty bounds known answer: e^(1/M) and e^(-1/M) recomputed here        ← derived numbers are derived
  DK13 inventory known answer: a package's line count equals an independent walk   ← measurements are measurements
  DK14 local changes: every "modified vs Release153" file really differs in git    ← the baseline claim is real
  DK15 runtime: every live reading equals the value on the snapshot line it cites  ← the node's numbers are the node's
  DK16 artifact-kit: assetkit + textkit audits pass and the kit modules are sources ← a kit change makes the page stale
  DK17 skill sync: the AUTO block carries the stamp's fingerprint and row count    ← harness → skill
  DK18 no private key material anywhere on the page                                ← the wallet seed never leaks in
  DK19 the HF3 grandfather-table count on the page equals an independent count     ← the release fingerprint is honest
  DK20 the tip-age reading is recomputed from the snapshot, and the claim matches  ← at-tip is never assumed
  DK21 a claim quoted from an external document is EXT and is attributed, never asserted  ← said ≠ so
  DK22 a forensic verdict is never proved only by the document it audits                  ← no circular proof
  DK23 the SC-revert keyhash is recomputed: blake2s(33 zero bytes) vs the key the node printed  ← cause, not story
  DK24 a REMOTE error cites rpc2's ServerError line; a LOCAL one never does                     ← whose fault is proved
  DK25 every ERROR line is triaged exactly once; counts and tx-store paths recomputed from the log ← no error hidden
  DK26 the consensus guard passes on the tree AND fails when a state change is injected       ← fixes stay off-consensus
  DK27 every harness/baseline copy is byte-identical to the git blob it claims to be           ← the "before" is real
  DK28 the current run's mean block interval, recomputed from the raw log by a different formula ← cadence is measured
  DK29 the topo.map record claim, recomputed from the file with the size constant read from Go    ← the datadir check is real
  DK30 risk coverage recomputed by an independent method (Go source scan, not the ctags table)   ← coverage is measured
  DK31 the miner run's mean hashrate, recomputed from the raw miner log by a regex (not json)     ← hashrate is measured
       (R20: over the whole rotated chain <log>.N .. <log>, so a restart between snapshot and KAT moves no sample)
  DK32 the live dashboard's sampled H/s, recomputed from the snapshot's two raw counter readings   ← the rate is measured
  DK33 the split regime card (CPU-sort backlog, ring full, idle/min, label), recomputed from the raw miner log text ← the regime is measured
  DK34 the run-ledger card's run count and span, recomputed from the ledger file's own lines             ← the ledger is the file
  DK35 r23c evolution: every round's commits partition base..head, and its +/- lines equal git's own shortstat ← history is git's
Exit 0 all ok · 3 any FAIL/DEGENERATE · 4 a mutation that its KAT did not catch.
"""
import collections, html, json, math, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path

REAL = Path(__file__).resolve().parent.parent
ROOT = REAL.parent
PY = sys.executable


def scratch():
    """A writable copy of harness/ inside a tree whose other top-level entries are read-only symlinks."""
    d = Path(tempfile.mkdtemp(prefix='derokat-'))
    for p in ROOT.iterdir():
        if p.name in ('harness', 'artifacts', '.skills'):
            continue
        os.symlink(p, d / p.name)
    # .skills is COPIED: a build writes the SKILL AUTO block, and through a symlink every scratch build (and every
    # mutation) rewrote the real skill file (discovery harness-gaps-02)
    shutil.copytree(ROOT / '.skills', d / '.skills', symlinks=True)
    shutil.copytree(REAL, d / 'harness', symlinks=True,
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    (d / 'artifacts').mkdir(exist_ok=True)
    return d


def gen(d):
    sys.path.insert(0, str(d / 'harness'))
    sys.path.insert(0, str(d / 'harness/kit'))
    sys.path.insert(0, str(d / 'harness/miners'))
    for m in [k for k in list(sys.modules) if k in ('gen_deroarch', 'prep_corpus', 'minelib', 'assetkit', 'textkit',
                                                    'connectorkit', 'diagramkit')]:
        del sys.modules[m]
    import gen_deroarch as G
    return G


def run(d, *a):
    return subprocess.run([PY, str(d / 'harness' / a[0]), *a[1:]], capture_output=True, text=True, cwd=d)


def build(d):
    return run(d, 'gen_deroarch.py', 'build')


# ───────────────────────────── the KATs ─────────────────────────────
def dk01(d, V, H, st):
    for r in V:
        for e in r['evidence']:
            try:
                lines = Path(e['abs']).read_text(errors='replace').splitlines()
            except OSError:
                return False, f"{r['id']}: unreadable {e['abs']}"
            i = e.get('line', 0)
            if not (1 <= i <= len(lines)):
                return False, f"{r['id']}: line {i} out of range"
            q_, l_ = re.sub(r'\s+', ' ', e['quote']).strip(), re.sub(r'\s+', ' ', lines[i - 1]).strip()
            if q_ not in l_:
                # r24: a pseudonymised peer address (kit/privkit.py) is compared in the salt-free masked form only
                sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'kit'))
                import privkit as _PK
                if not (_PK.PSEUDO.search(q_) and _PK.mask(q_) in _PK.mask(l_)):
                    return False, f"{r['id']}: quote not on {Path(e['abs']).name}:{i}"
    return True, f'{sum(len(r["evidence"]) for r in V)} anchors re-resolved'


def dk02(d, V, H, st):
    G = gen(d)
    a = json.dumps(G.resolve()[0], sort_keys=True, default=str)
    b = json.dumps(G.resolve()[0], sort_keys=True, default=str)
    return a == b, f'two resolves, {len(a)} chars each, identical={a == b}'


def dk03(d, V, H, st):
    G = gen(d)
    raw = d / 'harness/model/raw/consts.json'
    doc = json.loads(raw.read_text())
    orig = raw.read_text()
    doc['rows'].append({'id': 'kat-bogus', 'section': 'cadence', 'title': 'KAT bogus row', 'class': 'SRC',
                        'claim': 'this row must never be drawn',
                        'evidence': [{'file': 'config/config.go', 'quote': 'const BLOCK_TIME = uint64(99999)'}]})
    raw.write_text(json.dumps(doc))
    try:
        rows, rej, _, _ = G.resolve()
        drawn = any(r['id'] == 'kat-bogus' for r in rows)
        quarantined = any(r.get('id') == 'kat-bogus' for r in rej)
        return (not drawn) and quarantined, f'drawn={drawn} quarantined={quarantined}'
    finally:
        raw.write_text(orig)


def dk04(d, V, H, st):
    G = gen(d)
    raw = d / 'harness/model/raw/consts.json'
    orig = raw.read_text()
    doc = json.loads(orig)
    doc['rows'].append({'id': 'kat-misclass', 'section': 'cadence', 'title': 'KAT misclassified row', 'class': 'GK',
                        'claim': 'declared GK but proved by a line of first-party source',
                        'evidence': [{'file': 'config/config.go', 'quote': 'const BLOCK_TIME = uint64(18)'}]})
    raw.write_text(json.dumps(doc))
    try:
        rows = G.resolve()[0]
        r = next((x for x in rows if x['id'] == 'kat-misclass'), None)
        return bool(r and r['class'] == 'SRC' and r.get('class_note')), f"class={r and r['class']} note={bool(r and r.get('class_note'))}"
    finally:
        raw.write_text(orig)


def dk05(d, V, H, st):
    G = gen(d)
    e = G.resolve_ev({'file': 'config/config.go', 'quote': 'const'})
    return e['status'] == 'SHORT', f"an 5-character quote resolved to {e['status']} (want SHORT)"


def dk06(d, V, H, st):
    raw = d / 'harness/model/raw/consts.json'
    orig = raw.read_bytes()
    raw.write_bytes(orig + b'\n')
    try:
        r = run(d, 'gen_deroarch.py', 'check')
        return r.returncode == 3, f'check after touching a model file exited {r.returncode} (want 3): {r.stdout.strip()[:90]}'
    finally:
        raw.write_bytes(orig)


def dk07(d, V, H, st):
    G = gen(d)
    closed = {'SRC', 'EXT', 'HARNESS', 'GK', 'PLAN'}
    for r in V:
        for e in r['evidence']:
            if e['kind'] not in closed:
                return False, f"{r['id']}: class {e['kind']!r} is outside the vocabulary"
            if G.class_of(Path(e['abs'])) != e['kind']:
                return False, f"{r['id']}: {Path(e['abs']).name} is {G.class_of(Path(e['abs']))}, row says {e['kind']}"
    return True, f'{sum(len(r["evidence"]) for r in V)} anchors, every class agrees with prep_corpus.class_of'


def dk08(d, V, H, st):
    n = 0
    for r in V:
        if r.get('section') != 'logbridge':
            continue
        f, ln = r['emitter'].rsplit(':', 1)
        line = Path(ROOT / f).read_text(errors='replace').splitlines()[int(ln) - 1]
        probe = re.sub(r'\s+', ' ', r['message'].replace('\\n', '')).strip()
        if '"' + probe not in re.sub(r'\s+', ' ', line):
            kv = re.search(r'"' + re.escape(probe) + r'", "', re.sub(r'\s+', ' ', line))
            if not kv:
                return False, f"{r['id']}: {r['message'][:40]!r} is not a literal on {f}:{ln}"
        n += 1
    return n > 0, f'{n} bridged console lines, every literal on its own Go line'


def dk09(d, V, H, st):
    reg = collections.defaultdict(set)
    for r in V:
        if r.get('section') == 'loggers':
            top = r['owner'].split('/')[0] if not r['owner'].startswith('cmd/') else r['owner'].rsplit('/', 1)[0]
            reg[r['title']].add(top)
    n = 0
    for r in V:
        if r.get('section') != 'logbridge':
            continue
        root = r['logger'].split('.')[0]
        own = reg.get(root)
        f = re.sub(r'\.base$', '', re.sub(r'^harness/baseline/[^/]+/', '', r['emitter'].rsplit(':', 1)[0]))   # a baseline copy owns what its original owned
        top = f.split('/')[0] if not f.startswith('cmd/') else f.rsplit('/', 1)[0]
        if own and top not in own:
            return False, f"{r['id']}: logger {root} is owned by {sorted(own)} but the emitter is in {top}"
        n += 1
    return n > 0, f'{n} bridges, every emitter inside a package that owns its logger name'


def dk10(d, V, H, st):
    chains = collections.defaultdict(list)
    for r in V:
        if r.get('section') == 'hops':
            chains[r['chain']].append(r['order'])
    if not chains:
        return False, 'no chains drawn'
    for c, orders in chains.items():
        if sorted(orders) != list(range(1, len(orders) + 1)):
            return False, f'chain {c} hop order is {sorted(orders)}, not 1..{len(orders)}'
    drawn = {r['chain'] for r in V if r.get('section') == 'flows'}
    if set(chains) != drawn:
        return False, f'hops exist for {sorted(set(chains) - drawn)} but no chain row was drawn'
    return True, f'{len(chains)} chains, {sum(len(v) for v in chains.values())} hops, every order contiguous'


def dk11(d, V, H, st):
    bt = next((r for r in V if r['id'] == 'const-bt'), None)
    rri = next((r for r in V if r['id'] == 'const-rri'), None)
    if not bt or not rri:
        return False, 'the block-time or interval row is missing'
    want = 210000 * 600 // 18
    ok = 'uint64(18)' in str(bt['value']) and str(want) in str(rri['claim']).replace(',', '')
    return ok, f'BLOCK_TIME={bt["value"]} · interval recomputed here = {want:,} · on the page: {str(rri["claim"])[:60]!r}'


def dk12(d, V, H, st):
    r = next((x for x in V if x['id'] == 'find-diffstep'), None)
    if not r:
        return False, 'the difficulty-bounds finding is missing'
    e, M = 2.71828182845905, 8
    up, dn = round(math.pow(e, 1 / M), 5), round(math.pow(e, -1 / M), 5)
    return (abs(r['up'] - up) < 1e-9 and abs(r['down'] - dn) < 1e-9), f'page {r["up"]}/{r["down"]} vs recomputed {up}/{dn}'


def dk13(d, V, H, st):
    for r in V:
        if r.get('section') != 'packages':
            continue
        loc = 0
        for dp, dn, fn in os.walk(ROOT / r['pkg']):
            dn[:] = [x for x in dn if x not in {'.git', 'vendor', '__pycache__'}]
            for f in fn:
                if f.endswith('.go') and not f.endswith('_test.go'):
                    loc += len((Path(dp) / f).read_text(errors='replace').splitlines())
        if loc != r['loc']:
            return False, f"{r['pkg']}: page says {r['loc']}, an independent walk counts {loc}"
    return True, 'every package line count matches an independent os.walk'


def dk14(d, V, H, st):
    mods = [r for r in V if r.get('section') == 'local']
    if not mods:
        return False, 'no local-change rows'
    names = subprocess.run(['git', 'diff', '--name-only', 'Release153', 'HEAD'],
                           cwd=ROOT, capture_output=True, text=True).stdout.split()
    bad = [r['path'] for r in mods if r['path'] not in names]
    return not bad, f'{len(mods)} files claimed changed vs Release153; git agrees on {len(mods) - len(bad)}' + (f' BAD {bad[:3]}' if bad else '')


def dk15(d, V, H, st):
    n = 0
    for r in V:
        # DERIVED readings (tip age, ingestion rate, the process line, the socket counts) are computed from
        # the snapshot rather than read out of one field, so the key/value test does not apply to them.
        # DK20 recomputes the two that matter from the snapshot's own fields.
        if r.get('section') != 'runtime' or not r.get('field') or \
                r['field'] in ('process', 'sockets', 'cadence', 'tip_age', 'ingest_rate'):
            continue
        if r['field'] == 'build_skew':
            # derived from two anchors: the version the daemon reported and the one this tree declares
            if len(r['evidence']) < 2:
                return False, f"{r['id']}: compares two anchors but carries {len(r['evidence'])}"
            run_l, src_l = (Path(e['abs']).read_text(errors='replace').splitlines()[e['line'] - 1] for e in r['evidence'][:2])
            rv = re.search(r'"version":\s*"([^"]+)"', run_l)
            sv = re.search(r'MustParse\("([^"]+)"\)', src_l)
            want = 'same' if rv and sv and rv.group(1) == sv.group(1) else 'older'
            if not (rv and sv) or r['value'] != want:
                return False, f"{r['id']}: says {r['value']}, recomputed {want} from the two cited lines"
            n += 1
            continue
        e = r['evidence'][0]
        line = Path(e['abs']).read_text(errors='replace').splitlines()[e['line'] - 1]
        # the key/value PAIR, not the value alone: "1" is a substring of "7590761" and a bare `in` test
        # let a mutated reading through (caught by the mutation harness on 2026-10-20)
        pair = f'"{r["field"]}": {json.dumps(r["value"])}'
        if pair not in ' '.join(line.split()):
            return False, f"{r['id']}: {pair} is not on {Path(e['abs']).name}:{e['line']}"
        n += 1
    return n > 0, f'{n} live readings, each equal to the value on the snapshot line it cites'


def dk16(d, V, H, st):
    sys.path.insert(0, str(d / 'harness/kit'))
    import assetkit as ak, textkit as tk
    a, t = ak.audit(H), tk.audit(H)
    kit = [p for p in st['sources'] if '/kit/' in p and p.endswith('.py')]
    return a['ok'] and t['ok'] and len(kit) >= 4, \
        f"assetkit ok={a['ok']} ({a['untagged_cells']} untagged) · textkit ok={t['ok']} · {len(kit)} kit modules are page sources"


def dk17(d, V, H, st):
    sk = (d / '.skills/dero-miner-tuning/SKILL.md')   # the scratch copy the scratch build wrote (scratch() copies .skills)
    if not sk.exists():
        return False, 'the skill is missing'
    t = sk.read_text()
    m = re.search(r'<!-- AUTO:BEGIN.*?<!-- AUTO:END -->', t, re.S)
    if not m:
        return False, 'the skill has no AUTO block'
    blk = m.group(0)
    return (st['fingerprint'] in blk and str(st['stats']['rows']) in blk), \
        f"AUTO block names the fingerprint={st['fingerprint'] in blk} and the row count={str(st['stats']['rows']) in blk}"


SEED_RUN = 12
_WORDS = []


def mnemonic_words():
    """every word of the wallet's mnemonic lists (walletapi/mnemonics/*_mnemonics.go string literals)"""
    if not _WORDS:
        ws = set()
        for f in sorted((ROOT / 'walletapi/mnemonics').glob('*_mnemonics.go')):
            ws |= {w for w in re.findall(r'"([^"\s]{3,})"', f.read_text(errors='replace'))}
        _WORDS.append(ws)
    return _WORDS[0]


def mnemonic_runs(text, words=None):
    """the maximal runs of >= SEED_RUN consecutive tokens that are all mnemonic-list words, as space-joined strings"""
    ws = mnemonic_words() if words is None else words
    out, cur = [], []
    for tok in re.findall(r"[^\W\d_]+", text) + ['']:
        if tok and (tok in ws or tok.lower() in ws):
            cur.append(tok)
            continue
        if len(cur) >= SEED_RUN:
            out.append(' '.join(cur))
        cur = []
    return out


def upstream_fixture(run):
    """True when the run (or, for a run longer than a seed, its first 25 words) is verbatim in a Release153 test file"""
    w = run.split()
    probe = ' '.join(w[:25]) if len(w) > 25 else run
    r = subprocess.run(['git', 'grep', '-q', '-F', '-e', probe, 'Release153', '--', '*_test.go'], cwd=ROOT,
                       capture_output=True, text=True)
    return r.returncode == 0


def dk18(d, V, H, st):
    # R20: a seed is 24-25 mnemonic words (or 64 hex chars), not any text after 'seed:'. The old \S+ fired on the r19
    # wallet-cli comment "(the recovery seed: whoever reads it owns the funds)", which made DK18 fail on prose.
    # r20 merge (HR20-8 review): the page is HTML, so tags and entities are stripped first, and the words may be
    # separated by any whitespace (newlines, double spaces), commas, semicolons or quotes; a quoted, <code>-wrapped,
    # line-split or comma-separated seed matched none of the R20 pattern's forms. The prose sentence still passes
    # (6 words, then ')').
    T = html.unescape(re.sub(r'<[^>]*>', ' ', H))
    seed_rx = r'\bseed\s*(?:phrase|words)?\s*[:=]\s*["\'`(]*\s*(?:(?:[a-z]+[\s,;"\'`]+){11,}[a-z]+|[0-9a-f]{64})'
    m = re.search(seed_rx, T, re.I)
    if m:
        return False, f'a seed phrase appears on the page: {m.group(0)[:60]!r}'
    # R23b: an UNLABELLED seed passed: the page quoted three 25-word recovery seeds from the walletapi simulator tests
    # (a localdiff citation of r23_hf3_replay_test.go) and seed_rx needs 'seed:' in front. Any run of >= 12 words of
    # the wallet's own mnemonic lists is a seed unless it is a public upstream test fixture (verbatim in a Release153
    # *_test.go); fixtures are reported, never silently passed. The run itself is never printed.
    runs = mnemonic_runs(T)
    leaked = [r for r in runs if not upstream_fixture(r)]
    if leaked:
        return False, (f'{len(leaked)} unlabelled mnemonic run(s) of >= {SEED_RUN} wallet-list words on the page that no '
                       f'upstream test fixture holds (first starts {leaked[0].split()[0][:1]}…, {len(leaked[0].split())} words)')
    pats = [
            (r'\b[0-9a-f]{64}\b\s*(?:private|secret)', 'a private key'),
            (r'--password[= ]\S+', 'a password on a command line'),
            (r'\bwallet\.db\b.*\bpassword\b', 'a wallet password')]
    for rx, what in pats:
        m = re.search(rx, H, re.I)
        if m:
            return False, f'{what} appears on the page: {m.group(0)[:60]!r}'
    return True, (f'{len(pats)} key-material patterns checked, none present; {len(runs)} mnemonic run(s), all public '
                  f'upstream test fixtures')


def dk19(d, V, H, st):
    r = next((x for x in V if x['id'] == 'find-hf3table'), None)
    if not r:
        return False, 'the grandfather-table finding is missing'
    n = len([l for l in (ROOT / 'blockchain/hardfork_fixes.go').read_text().splitlines()
             if re.match(r'^\t"[0-9a-f]{64}":', l)])
    return r['count'] == n, f'page says {r["count"]}, an independent count of the file gives {n}'


def dk20(d, V, H, st):
    """The tip-age reading is the one that decides whether every other live reading means what it looks like,
    so it is recomputed here from the snapshot's own fields rather than trusted."""
    r = next((x for x in V if x['id'] == 'rt-tipage'), None)
    if not r:
        return False, 'no tip-age row (the node may have been unreachable when the snapshot was taken)'
    snap = json.loads(Path(r['evidence'][0]['abs']).read_text())
    tip = snap.get('tip') or {}
    import datetime as _dt
    ts = (tip.get('timestamp_ms') or 0) / 1000
    cap = _dt.datetime.fromisoformat(snap['captured']).timestamp()
    want = round(cap - ts)
    if abs(want - r['value']) > 5:
        return False, f'row says {r["value"]} s, recomputed from the snapshot {want} s'
    # and the claim must not call a far-behind node "at the tip"
    behind = r['value'] > 600
    says_behind = 'CATCHING UP' in r['claim']
    if behind != says_behind:
        return False, f'age {r["value"]} s but the claim says {"at the tip" if not says_behind else "catching up"}'
    # the ingestion rate is the other derived reading; recompute it from the two snapshots it spans
    rr = next((x for x in V if x['id'] == 'rt-rate'), None)
    msg = f'tip age {r["value"]:,} s recomputed to {want:,} s; the claim matches the number'
    if rr:
        snaps = sorted(Path(r['evidence'][0]['abs']).parent.glob('snap_*.json'))
        if len(snaps) >= 2:
            a_, b_ = (json.loads(x.read_text()) for x in snaps[-2:])
            dt = (_dt.datetime.fromisoformat(b_['captured']) - _dt.datetime.fromisoformat(a_['captured'])).total_seconds()
            dh = b_['getinfo']['height'] - a_['getinfo']['height']
            got = round(dh / dt, 3)
            if abs(got - rr['value']) > 0.01:
                return False, f'ingestion rate row says {rr["value"]}, recomputed {got}'
            msg += f'; ingestion rate {rr["value"]}/s recomputed to {got}/s'
    return True, msg


def dk21(d, V, H, st):
    """A quoted claim is never an established fact. Every row anchored in the external document must carry the
    EXT class and must attribute what it says, and the page must never present one as the tree's own finding."""
    bad = []
    for r in V:
        ext = [e for e in r['evidence'] if '/harness/external/' in e['abs']]
        if not ext:
            continue
        if r['class'] != 'EXT':
            bad.append(f"{r['id']}: anchored in the external document but classed {r['class']}")
        c = str(r.get('claim') or '')
        if not re.search(r'(states|said|asserts|claims|according to|Foundation)', c):
            bad.append(f"{r['id']}: quotes the document without attributing it")
    return not bad, (f'{sum(1 for r in V if any("/harness/external/" in e["abs"] for e in r["evidence"]))} rows cite '
                     f'the external document; all EXT and attributed' if not bad else f'{len(bad)}: {bad[:3]}')


def dk22(d, V, H, st):
    """A forensic conclusion may not be proved by the document it is auditing. Every forensics row must anchor
    in the source tree, the vendored code or a runtime capture — never only in the press statement — and must
    carry one of the four permitted verdicts."""
    OK = {'CONFIRMED', 'PARTLY-CONFIRMED', 'REFUTED', 'CANNOT-DETERMINE-LOCALLY'}
    rows = [r for r in V if r.get('section') == 'forensics']
    if not rows:
        return True, 'no forensics rows yet (the audit has not been merged)'
    bad = []
    for r in rows:
        if r.get('audit_verdict') not in OK:
            bad.append(f"{r['id']}: verdict {r.get('verdict')!r} outside the permitted set")
        if all('/harness/external/' in e['abs'] for e in r['evidence']):
            bad.append(f"{r['id']}: proved only by the document it audits")
        if not r['evidence']:
            bad.append(f"{r['id']}: no anchors")
    return not bad, (f'{len(rows)} forensics rows, each with a permitted verdict and at least one anchor outside '
                     f'the audited document' if not bad else f'{len(bad)}: {bad[:3]}')



def _tri(V):
    return {r['id']: r for r in V if r.get('section') == 'triage'}


def _log_of(r):
    e = next((e for e in r['evidence'] if '/harness/runtime/derod_console_' in e['abs']), None)
    return Path(e['abs']) if e else None


def dk23(d, V, H, st):
    """The SC-revert row says the missing key is the all-zero signer. Recompute that from the log line itself."""
    import hashlib
    T = _tri(V)
    r = T.get('tri-sc-zerosigner')
    if not r:
        return True, 'no SC-revert errors in the capture'
    e = next(e for e in r['evidence'] if '/harness/runtime/derod_console_' in e['abs'])
    line = Path(e['abs']).read_text(errors='replace').splitlines()[e['line'] - 1]
    keys = set(re.findall(r'keyhash ([0-9a-f]{64}) not found', line))
    zero = hashlib.blake2s(bytes(33), digest_size=32).hexdigest()
    truth = keys == {zero}
    if r.get('keyhash_is_zero_signer') != truth:
        return False, f'row says keyhash_is_zero_signer={r.get("keyhash_is_zero_signer")}, recomputed {truth}'
    if truth != ('exactly' in r['claim']):
        return False, 'the claim wording disagrees with the recomputed hash'
    return True, f'blake2s(33×00) = {zero[:16]}… {"==" if truth else "!="} the printed keyhash; row agrees'


def dk24(d, V, H, st):
    """Origin is a claim about which machine produced the text. REMOTE must be proved by rpc2's ServerError line
    (that is the only path that carries a peer's error string here); LOCAL must not lean on it."""
    bad = []
    for r in _tri(V).values():
        srv = any('cenkalti/rpc2/client.go' in e['abs'] and 'ServerError(resp.Error)' in e['quote'] for e in r['evidence'])
        if r['origin'] == 'REMOTE' and not srv:
            bad.append(f"{r['id']}: REMOTE without the ServerError anchor")
        if r['origin'] == 'LOCAL' and srv:
            bad.append(f"{r['id']}: LOCAL but proved by the ServerError path")
    n = len(_tri(V))
    return not bad, (f'{n} triage rows, every origin proved by its anchors' if not bad else '; '.join(bad[:3]))


PAT = {'tri-sc-zerosigner': r'Recover while executing SC', 'tri-sc-parse': r'error Parsing sc',
       'tri-remote-emptyblock': r'Invalid Major Version in Block', 'tri-remote-txstore': r'/bltx_store/'}


def dk25(d, V, H, st):
    """Recount every class straight from the log; every ERROR line must land in exactly one class; the tx-store
    directory each peer printed must equal bytes 16/17 of the txid (storefs.getpath)."""
    T = _tri(V)
    if not T:
        return True, 'no triage rows'
    log = next(filter(None, (_log_of(r) for r in T.values())))
    errs = [l for l in log.read_text(errors='replace').splitlines() if re.match(r'^\d\d/\d\d \d\d:\d\d:\d\d\s+ERROR\s', l)]
    bad = []
    for rid, pat in PAT.items():
        if rid in T and T[rid]['count'] != sum(1 for l in errs if re.search(pat, l)):
            bad.append(f'{rid}: row {T[rid]["count"]} vs log {sum(1 for l in errs if re.search(pat, l))}')
    pipes = sum(1 for l in errs if 'closed pipe' in l)
    got = sum(T[k]['count'] for k in ('tri-closedpipe-cascade', 'tri-closedpipe-churn') if k in T)
    if pipes != got:
        bad.append(f'closed-pipe rows {got} vs log {pipes}')
    total = sum(r['count'] for r in T.values())
    if total != len(errs):
        bad.append(f'{total} triaged vs {len(errs)} ERROR lines')
    for l in errs:
        for a, b, tx in re.findall(r'bltx_store/([0-9a-f]{2})/([0-9a-f]{2})/([0-9a-f]{64})\.tx', l):
            h = bytes.fromhex(tx)
            if (f'{h[16]:02x}', f'{h[17]:02x}') != (a, b):
                bad.append(f'tx-store path {a}/{b} is not getpath({tx[:12]}…)')
    return not bad, (f'{len(errs)} ERROR lines → {len(T)} classes, every count and tx-store path recomputed'
                     if not bad else '; '.join(bad[:3]))



def _guard(d):
    sys.path.insert(0, str(d / 'harness'))
    sys.modules.pop('consensus_guard', None)
    import consensus_guard as G
    G.ROOT = ROOT          # git cannot see through the scratch copy's symlinked directories; judge the real tree
    return G


def dk26(d, V, H, st):
    """A guard that only ever says PASS proves nothing: it must pass on the tree and fail on a planted change."""
    G = _guard(d)
    rep = G.evaluate()
    if not rep['ok']:
        return False, f"guard FAILS on the tree: {rep['violations'][:2]}"
    orig = G.READ

    def planted(f):
        t = orig(f)
        if f == 'blockchain/transaction_execute.go':
            t = t.replace('gas = tx.Fees()\n', 'gas = tx.Fees()\n\tgas = 0\n', 1)
        return t
    G.READ = planted
    neg = G.evaluate()
    G.READ = orig
    if neg['ok']:
        return False, 'guard PASSES with "gas = 0" planted in process_transaction_sc — it is blind'
    return True, (f"{len(rep['files'])} consensus-package files changed vs {rep['base']}: "
                  + '; '.join(f"{e['file']} = {e['verdict']}" for e in rep['files'])
                  + ' · planted "gas = 0" caught')


def dk27(d, V, H, st):
    """The baseline copies are what the log bridge and the triage rows cite for code this tree has changed."""
    import hashlib
    bad, n = [], 0
    for man in sorted((d / 'harness/baseline').glob('*/MANIFEST.json')):
        m = json.loads(man.read_text())
        for f, blob in m['files'].items():
            n += 1
            data = (man.parent / (f + m.get('suffix', ''))).read_bytes()
            got = hashlib.sha1(b'blob %d\0' % len(data) + data).hexdigest()
            want = subprocess.run(['git', 'rev-parse', f"{m['base']}:{f}"], cwd=ROOT, capture_output=True,
                                  text=True).stdout.strip()
            if not (got == blob == want):
                bad.append(f'{f}: copy {got[:10]} manifest {blob[:10]} git {want[:10]}')
    return not bad, (f'{n} baseline file(s), each equal to its git blob' if not bad else '; '.join(bad[:3]))



def dk28(d, V, H, st):
    """log_intel averages per-step gaps; this recomputes (t_last - t_first) / (h_last - h_first) over the same at-tip
    window straight from the JSON log lines. Two formulas, one answer, or the cadence number is not trustworthy."""
    import datetime as _dt, glob as _g
    runs = [r for r in V if r.get('section') == 'intel' and r.get('kind') == 'log-run']
    if not runs:
        return False, 'no log-run rows on the page'
    r = runs[-1]
    snap = json.loads(Path(r['evidence'][0]['abs']).read_text())
    run = snap['runs'][-1]
    since, until = run['blocks']['at_tip_since'], run['end']
    if not since:
        return False, 'current run has no at-tip window'
    t0 = _dt.datetime.fromisoformat(since).timestamp()
    t1 = _dt.datetime.fromisoformat(until[:23]).timestamp()
    pts, seen = [], set()
    for f in sorted(set(_g.glob(os.path.expanduser(os.environ.get('DERO_DATADIR', '~/dero-data')) + '/logs/derod*.log') + _g.glob(str(ROOT / 'bin/derod*.log')))):
        with open(f, errors='replace') as fh:
            for l in fh:
                if '"Chain extended"' not in l:
                    continue
                try:
                    x = json.loads(l)
                except ValueError:
                    continue
                t = _dt.datetime.strptime(x['T'][:23], '%Y-%m-%dT%H:%M:%S.%f').timestamp()
                h = x.get('new height')
                if t0 - 1 <= t <= t1 and isinstance(h, int) and h not in seen:
                    seen.add(h)
                    pts.append((t, h))
    pts.sort()
    # r22 merge: at_tip_since is cut to the second and the window opens 1 s early, so replay blocks of the catch-up
    # that ended in that second slipped in (2026-10-29: 58 extra heights in ~1 s -> 18.00 s vs the page's 18.52 s).
    # Drop leading points whose per-height gap is a replay gap, the rule log_intel uses to find the tip (CATCHUP_GAP_S).
    while len(pts) > 1 and (pts[1][0] - pts[0][0]) / max(1, pts[1][1] - pts[0][1]) < 5:
        pts.pop(0)
    if len(pts) < 20:
        return False, f'only {len(pts)} blocks in the window'
    mean = (pts[-1][0] - pts[0][0]) / (pts[-1][1] - pts[0][1])
    ok = abs(mean - r['mean']) <= 0.5
    return ok, f"page {r['mean']} s vs recomputed {mean:.2f} s over {len(pts)} blocks ({'agree' if ok else 'DISAGREE'})"


def dk29(d, V, H, st):
    """The topo-records row claims a record count and a remainder; re-read topo.map and the record size from the Go."""
    r = next((x for x in V if x['id'] == 'intel-dd-topo-records'), None)
    if not r:
        return False, 'no topo-records row'
    size = int(re.search(r'const TOPORECORD_SIZE int64 = (\d+)', (ROOT / 'blockchain/storetopo.go').read_text()).group(1))
    claim_n = int(re.search(r'= ([\d,]+) records', r['claim']).group(1).replace(',', ''))
    claim_rem = int(re.search(r'remainder (\d+)', r['claim']).group(1))
    now = Path(os.path.expanduser(os.environ.get('DERO_DATADIR', '~/dero-data')) + '/mainnet/topo.map').stat().st_size
    ok = now % size == claim_rem and now // size >= claim_n
    return ok, (f'claimed {claim_n:,} records remainder {claim_rem}; now {now // size:,} records remainder {now % size} '
                f'(record size {size} from storetopo.go)')



def dk30(d, V, H, st):
    """mine_coverage reads ctags; this scans the Go source for `func` declarations itself and joins them with the
    raw rows' cited lines. Both must agree on how many risk functions exist and how many are covered."""
    t = next((r for r in V if r['id'] == 'cov-total'), None)
    if not t:
        return False, 'no coverage total row'
    sys.path.insert(0, str(d / 'harness/miners'))
    sys.modules.pop('mine_coverage', None)
    import mine_coverage as MC
    cited = collections.defaultdict(set)
    for p in sorted((d / 'harness/model/raw').glob('*.json')):
        if p.stem in ('coverage', 'riskmap'):
            continue
        for r in json.loads(p.read_text()).get('rows', []):
            for e in r.get('evidence') or []:
                if e.get('file') and e.get('line'):
                    cited[e['file']].add(int(e['line']))
    risk = cov = 0
    for f in sorted(ROOT.rglob('*.go')):
        rel = str(f.relative_to(ROOT))
        if not rel.startswith(MC.PKGS_IN_SCOPE) or rel.endswith('_test.go') or rel.startswith(('vendor/', 'harness/')):
            continue
        text = f.read_text(errors='replace')
        # blank /* */ blocks keeping their newlines: a commented-out func is not a function (review 2026-10-22)
        text = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group().count('\n'), text, flags=re.S)
        lines = text.splitlines()
        decl = [(i + 1, m.group(1)) for i, l in enumerate(lines)
                for m in [re.match(r'^func (?:\([^)]*\) )?(\w+)\s*[\[(]', l)] if m]
        for ln, name in decl:
            if not MC.RISK.search(name):
                continue
            end = next((i + 2 for i in range(ln, len(lines)) if lines[i] == '}'), len(lines) + 1)   # own brace rule
            risk += 1
            cov += any(ln <= x < end for x in cited.get(rel, ()))
    ok = abs(risk - t['risk']) <= 1 and abs(cov - t['risk_covered']) <= 1   # two methods, one answer
    return ok, f"page risk {t['risk_covered']}/{t['risk']} vs source scan {cov}/{risk} ({'agree' if ok else 'DISAGREE'})"


def _row_logs(r, st):
    """the miner log paths a row recorded. R21: mine_intel stores a log inside the checkout RELATIVE to it (an absolute
    path sent DK31/DK33 to the checkout the page was built in: 0 samples in every other clone, the r20 merge's 'DK31
    fails on base too'), so a relative path is read under THIS checkout; paths outside it stay absolute."""
    return [str(f) if Path(str(f)).is_absolute() else str(ROOT / str(f)) for f in (r.get('logs') or [r.get('log')]) if f]


def dk31(d, V, H, st):
    """miner_intel parses JSON records and skips its warm-up samples; this re-reads the raw log TEXT with a regex over
    the same [start, end] window and the same warm-up rule. Two readers, one mean (0.5 %), or the row is not measured."""
    rows = [r for r in V if r.get('kind') == 'miner-run']
    if not rows:
        return False, 'no miner-run rows on the page'
    r = rows[-1]
    snap = json.loads(Path(r['evidence'][0]['abs']).read_text())
    run = next((x for x in snap['runs'] if x['start'] == r['start']), None)
    if not run:
        return False, 'the row\u2019s run is not in its snapshot'
    rx = re.compile(r'"T":"([^"]+)".*"M":"TOTAL hashrate","H/s":"(\d+(?:\.\d+)?)"')
    vals = []
    # every file of the chain, plus each one's rotated siblings: the run may have moved from <log> to <log>.1
    files = []
    for f in _row_logs(r, st):
        base = re.sub(r'\.\d+$', '', str(f))
        files += [base] + [f'{base}.{i}' for i in range(1, 10)]
    for f in dict.fromkeys(files):
        if not Path(f).exists():
            continue
        with open(f, errors='replace') as fh:
            for l in fh:
                m = rx.search(l)
                if m and run['start'] <= m.group(1) <= run['end']:
                    vals.append(float(m.group(2)))
    vals = vals[2:]                                   # miner_intel WARMUP_SAMPLES, restated
    if len(vals) < 3:
        return False, f'only {len(vals)} TOTAL samples in the window'
    mean = sum(vals) / len(vals)
    ok = abs(mean - r['mean_hs']) <= 0.005 * mean and len(vals) == r['samples']
    return ok, (f"page {r['mean_hs']} H/s over {r['samples']} samples vs raw-text {mean:.1f} over {len(vals)} "
                f"({'agree' if ok else 'DISAGREE'})")


def dk32(d, V, H, st):
    """metrics_intel turns two counter readings into a rate; this recomputes it from the snapshot's raw readings
    (hashes_total at t0 and t1), so the page's H/s is a measured difference, not a typed or 15 s gauge value"""
    rows = [r for r in V if r.get('kind') == 'metrics-live']
    if not rows:
        return False, 'no live-metrics row on the page'
    r = rows[-1]
    snap = json.loads(Path(r['evidence'][0]['abs']).read_text())
    (t0, t1), (h0, h1) = snap['raw']['t'], snap['raw']['miner_hashes_total']
    if None in (h0, h1) or t1 <= t0:
        return False, f'the snapshot has no usable raw readings {snap["raw"]}'
    rate = (h1 - h0) / (t1 - t0)
    ok = abs(rate - r['hashrate_sampled']) <= 0.01 * max(rate, 1) and r['hashrate_sampled'] > 0
    return ok, f"page {r['hashrate_sampled']} H/s vs raw ({h1:.0f} - {h0:.0f}) / {t1 - t0:.1f} s = {rate:.1f} ({'agree' if ok else 'DISAGREE'})"


def dk33(d, V, H, st):
    """miner_intel derives the regime from parsed JSON records; this re-reads the raw log TEXT with regexes over the
    row's [start, end] window, skips the first window (its length is unknown) and recomputes the time-weighted
    fractions and the label with the thresholds restated here (0.5 backlog; 5,000 idle tries per thread per minute)"""
    import datetime as _dt
    rows = [r for r in V if r.get('kind') == 'split-regime']
    if not rows:
        return False, 'no split-regime row on the page'
    r = rows[-1]
    rx = re.compile(r'"T":"([^"]+)".*"M":"GPU split".*"cpu_idle_tries":(\d+),"feeder_ring_full_ms":(\d+)'
                    r'(?:,"feeder_cpu_backlog_ms":(\d+))?')
    pts, files = [], []
    for f in _row_logs(r, st):
        base = re.sub(r'\.\d+$', '', str(f))
        files += [f'{base}.{i}' for i in range(9, 0, -1)] + [base]
    for f in dict.fromkeys(files):
        if not Path(f).exists():
            continue
        with open(f, errors='replace') as fh:
            for l in fh:
                m = rx.search(l)
                if m and r['start'] <= m.group(1) <= (r.get('end') or '~'):
                    t = _dt.datetime.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
                    pts.append((t, int(m.group(2)), int(m.group(3)), None if m.group(4) is None else int(m.group(4))))
    pts.sort()
    w = [(b[0] - a[0], b[1], b[2], b[3]) for a, b in zip(pts, pts[1:]) if b[0] > a[0]]
    if len(w) < 2:
        return False, f'only {len(w)} split windows in the raw log for {r["start"]}'
    T = sum(x[0] for x in w)
    bl = [x for x in w if x[3] is not None]
    backlog = round(sum(x[3] for x in bl) / (sum(x[0] for x in bl) * 1000), 3) if bl else None
    ring = round(sum(x[2] for x in w) / (T * 1000), 3)
    idle = round(sum(x[1] for x in w) / T * 60, 1)
    label = ('cpu-sort-bound' if backlog is not None and backlog >= 0.5 else
             'gpu-bound' if idle / 20 >= 5000 else 'balanced')
    ok = (len(w) == r['windows'] and backlog == r['cpu_backlog_fraction'] and ring == r['ring_full_fraction']
          and abs(idle - r['idle_tries_per_min']) <= 0.1 and label == r['regime'])
    return ok, (f"page {r['regime']} backlog {r['cpu_backlog_fraction']} ring {r['ring_full_fraction']} idle {r['idle_tries_per_min']} "
                f"over {r['windows']} windows vs raw-text {label} {backlog} {ring} {idle} over {len(w)} ({'agree' if ok else 'DISAGREE'})")


def dk34(d, V, H, st):
    """the run-ledger card names a run count and a date span; this counts the ledger file's non-empty lines and reads
    the first start / last end itself"""
    rows = [r for r in V if r.get('kind') == 'run-ledger']
    if not rows:
        return False, 'no run-ledger row on the page'
    r = rows[-1]
    f = Path(r['evidence'][0]['abs'])
    L = [json.loads(l) for l in f.read_text().splitlines() if l.strip()]
    want = f'{len(L)} runs, {L[0]["start"][:10]} to {L[-1]["end"][:10]}' if L else None
    starts = [x['start'] for x in L]
    ok = bool(L) and r['runs'] == len(L) and want in r['title'] and starts == sorted(starts, key=lambda s: s[:19]) \
        and len(set(starts)) == len(starts)
    return ok, f"page '{r['title']}' vs file {want} (one line per start: {len(set(starts)) == len(starts)})"


def dk35(d, V, H, st):
    """r23c: the evolution section. The rounds' commit lists must partition `git log base..head` exactly (no commit
    dropped, none counted twice), and each round's +/- lines must equal the sum of `git show --shortstat` over its
    commits: a different git command and a different parser from the miner's --numstat walk."""
    rs = [r for r in V if r.get('kind') == 'evo-round']
    if not rs:
        return False, 'no evolution round row on the page'
    base, head = rs[0]['base'], rs[0]['head']
    g = lambda *a: subprocess.run(['git', *a], cwd=ROOT, capture_output=True, text=True).stdout
    want = g('log', '--no-merges', '--format=%h', f'{base}..{head}').split()
    have = [c for r in rs for c in r['commits']]
    if sorted(want) != sorted(have) or len(set(have)) != len(have):
        return False, f'commit partition differs: git {len(want)}, rounds {len(have)} ({len(set(have))} distinct)'
    bad = []
    for r in rs:
        a = dl = 0
        for c in r['commits']:
            t = g('show', '--shortstat', '--no-renames', '--format=', c)
            a += int((re.search(r'(\d+) insertion', t) or [0, 0])[1])
            dl += int((re.search(r'(\d+) deletion', t) or [0, 0])[1])
        if (a, dl) != (r['added'], r['removed']):
            bad.append(f"{r['round']}: page +{r['added']}/-{r['removed']} vs shortstat +{a}/-{dl}")
    return not bad, (f'{len(have)} commits partition {base}..{head} over {len(rs)} rounds; lines match shortstat'
                     if not bad else '; '.join(bad[:3]))


KATS = [('DK20', dk20), ('DK01', dk01), ('DK02', dk02), ('DK03', dk03), ('DK04', dk04), ('DK05', dk05), ('DK06', dk06),
        ('DK07', dk07), ('DK08', dk08), ('DK09', dk09), ('DK10', dk10), ('DK11', dk11), ('DK12', dk12),
        ('DK13', dk13), ('DK14', dk14), ('DK15', dk15), ('DK16', dk16), ('DK17', dk17), ('DK18', dk18),
        ('DK19', dk19), ('DK21', dk21), ('DK22', dk22), ('DK23', dk23), ('DK24', dk24), ('DK25', dk25),
        ('DK26', dk26), ('DK27', dk27), ('DK28', dk28), ('DK29', dk29), ('DK30', dk30), ('DK31', dk31), ('DK32', dk32),
        ('DK33', dk33), ('DK34', dk34), ('DK35', dk35)]


# ───────────────────────────── mutations ─────────────────────────────
def mut_anchor_line(d):
    """move a rendered anchor off its line"""
    p = d / 'harness/model/verified.json'
    V = json.loads(p.read_text())
    V[0]['evidence'][0]['line'] = 99999
    p.write_text(json.dumps(V))


def mut_quote(d):
    p = d / 'harness/model/verified.json'
    V = json.loads(p.read_text())
    V[0]['evidence'][0]['quote'] = 'this text is on no line of any file'
    p.write_text(json.dumps(V))


def mut_class(d):
    p = d / 'harness/model/verified.json'
    V = json.loads(p.read_text())
    for r in V:
        r['evidence'][0]['kind'] = 'INVENTED'
        break
    p.write_text(json.dumps(V))


def mut_floor(d):
    """lower the 12-character floor: trivial anchors would be accepted"""
    p = d / 'harness/gen_deroarch.py'
    p.write_text(p.read_text().replace('if len(q) < 12:', 'if len(q) < 2:'))


def mut_bridge(d):
    p = d / 'harness/model/verified.json'
    V = json.loads(p.read_text())
    for r in V:
        if r.get('section') == 'logbridge':
            r['emitter'] = 'config/config.go:34'
            break
    p.write_text(json.dumps(V))


def mut_plaus(d):
    p = d / 'harness/model/verified.json'
    V = json.loads(p.read_text())
    for r in V:
        if r.get('section') == 'logbridge':
            r['logger'] = 'GETWORK'
            r['emitter'] = 'p2p/controller.go:121'
            break
    p.write_text(json.dumps(V))


def mut_hops(d):
    p = d / 'harness/model/verified.json'
    V = json.loads(p.read_text())
    for r in V:
        if r.get('section') == 'hops':
            r['order'] = 99
            break
    p.write_text(json.dumps(V))


def mut_loc(d):
    p = d / 'harness/model/verified.json'
    V = json.loads(p.read_text())
    for r in V:
        if r.get('section') == 'packages':
            r['loc'] = r['loc'] + 1000
            break
    p.write_text(json.dumps(V))


def mut_diff(d):
    p = d / 'harness/model/verified.json'
    V = json.loads(p.read_text())
    for r in V:
        if r['id'] == 'find-diffstep':
            r['up'] = 2.0
            break
    p.write_text(json.dumps(V))


def mut_runtime(d):
    p = d / 'harness/model/verified.json'
    V = json.loads(p.read_text())
    for r in V:
        if r.get('section') == 'runtime' and r.get('field') == 'height':
            r['value'] = 1
            break
    p.write_text(json.dumps(V))


def mut_press_class(d):
    """present a quoted claim as the tree's own SRC finding"""
    p = d / 'harness/model/verified.json'
    V = json.loads(p.read_text())
    for r in V:
        if any('/harness/external/' in e['abs'] for e in r['evidence']):
            r['class'] = 'SRC'
            break
    p.write_text(json.dumps(V))


def mut_tipage(d):
    """make the tip-age claim contradict its own number, in whichever direction the live state allows: a
    far-behind node is called "at the tip", and a node at the tip is called "catching up". A one-way mutation
    turns into a silent no-op the moment the node really reaches the tip (it did, 2026-10-21 04:13)."""
    p = d / 'harness/model/verified.json'
    V = json.loads(p.read_text())
    for r in V:
        if r['id'] == 'rt-tipage':
            a, b = 'The node is CATCHING UP, not at the tip.', 'The node is at the tip.'
            c = r['claim']
            r['claim'] = c.replace(a, b) if a in c else c.replace(b, a)
            assert r['claim'] != c, 'mutation found neither phrase; it would prove nothing'
            break
    p.write_text(json.dumps(V))


def mut_hf3(d):
    p = d / 'harness/model/verified.json'
    V = json.loads(p.read_text())
    for r in V:
        if r['id'] == 'find-hf3table':
            r['count'] = 16
            break
    p.write_text(json.dumps(V))


def mut_localdiff(d):
    """point a local-change row at a file git says did NOT change. Chosen at run time: a hard-coded file
    (blockchain/blockchain.go) became a real change in Round 12 and the mutation silently stopped mutating."""
    changed = set(subprocess.run(['git', 'diff', '--name-only', 'Release153', 'HEAD'], cwd=ROOT,
                                 capture_output=True, text=True).stdout.split())
    tracked = subprocess.run(['git', 'ls-files', '*.go'], cwd=ROOT, capture_output=True, text=True).stdout.split()
    unchanged = next(f for f in tracked if f not in changed and not f.startswith(('vendor/', 'harness/')))
    p = d / 'harness/model/verified.json'
    V = json.loads(p.read_text())
    for r in V:
        if r.get('section') == 'local':
            r['path'] = unchanged
            break
    p.write_text(json.dumps(V))



def _mut_tri(d, rid, fn):
    p = d / 'harness/model/verified.json'
    V = json.loads(p.read_text())
    hit = False
    for r in V:
        if r['id'] == rid:
            fn(r)
            hit = True
    assert hit, f'{rid} not on the page; the mutation would prove nothing'
    p.write_text(json.dumps(V))


def mut_zerosigner(d):
    """claim the printed keyhash is NOT the zero signer"""
    def f(r):
        r['keyhash_is_zero_signer'] = not r['keyhash_is_zero_signer']
    _mut_tri(d, 'tri-sc-zerosigner', f)


def mut_origin(d):
    """blame a peer for an error this node raised itself"""
    def f(r):
        r['origin'] = 'REMOTE'
    _mut_tri(d, 'tri-sc-zerosigner', f)


def mut_tricount(d):
    """hide one error: under-count a class"""
    def f(r):
        r['count'] -= 1
    _mut_tri(d, 'tri-remote-txstore', f)



def mut_guard_blind(d):
    """blind the consensus guard: its normaliser drops every statement, so nothing can ever differ"""
    p = d / 'harness/consensus_guard.py'
    t = p.read_text()
    t2 = t.replace("        out.append(re.sub(r'\\s+', ' ', s))", "        pass")
    assert t2 != t, 'guard normaliser not found; the mutation would prove nothing'
    p.write_text(t2)


def mut_baseline(d):
    """tamper with a baseline copy"""
    f = sorted((d / 'harness/baseline').glob('*/blockchain/transaction_execute.go*'))[0]
    f.write_text(f.read_text() + '\n// tampered\n')



def mut_cadence(d):
    """claim the current run ran 5 s slower than it did"""
    def f(r):
        r['mean'] = round(r['mean'] + 5, 2)
    runs = [r['id'] for r in json.loads((d / 'harness/model/verified.json').read_text()) if r.get('kind') == 'log-run']
    _mut_tri(d, runs[-1], f)


def mut_topo_claim(d):
    """claim topo.map has a partial trailing record"""
    def f(r):
        r['claim'] = r['claim'].replace('remainder 0', 'remainder 7')
    _mut_tri(d, 'intel-dd-topo-records', f)



def mut_coverage(d):
    """overstate risk coverage by 10 functions"""
    def f(r):
        r['risk_covered'] += 10
    _mut_tri(d, 'cov-total', f)


def mut_miner_mean(d):
    """overstate the current miner run's mean hashrate by 5,000 H/s"""
    def f(r):
        r['mean_hs'] = round(r['mean_hs'] + 5000, 1)
    runs = [r['id'] for r in json.loads((d / 'harness/model/verified.json').read_text()) if r.get('kind') == 'miner-run']
    _mut_tri(d, runs[-1], f)


def mut_seed(d):
    """a 25-word recovery seed leaks onto the page (DK18 had no mutation before R20)"""
    p = d / 'artifacts/dero-src-arch.html'
    words = ' '.join(['abbey', 'cactus', 'dwelt', 'eagle', 'fabric'] * 5)
    p.write_text(p.read_text().replace('</body>', f'<p>seed: {words}</p></body>', 1))


def mut_seed_code(d):
    """r20 merge: a quoted 25-word seed wrapped in <code> (the realistic HTML leak the R20 pattern missed)"""
    p = d / 'artifacts/dero-src-arch.html'
    words = ' '.join(['abbey', 'cactus', 'dwelt', 'eagle', 'fabric'] * 5)
    p.write_text(p.read_text().replace('</body>', f'<p>seed: <code>"{words}"</code></p></body>', 1))


def mut_seed_unlabelled(d):
    """R23b: a 25-word seed with no 'seed:' label, as a quoted Go string in a code citation (what the page carried)"""
    p = d / 'artifacts/dero-src-arch.html'
    words = ' '.join(['gables', 'hatchet', 'igloo', 'jaded', 'kennel'] * 5)
    p.write_text(p.read_text().replace('</body>', f'<code>Recover(dir, "QWER", "{words}")</code></body>', 1))


def mut_seed_lines(d):
    """r20 merge: a 25-word seed split over lines, with a double space and commas"""
    p = d / 'artifacts/dero-src-arch.html'
    words = ',\n'.join(['abbey  cactus', 'dwelt eagle', 'fabric'] * 5)
    p.write_text(p.read_text().replace('</body>', f'<pre>Seed words =\n{words}</pre></body>', 1))


def mut_live_rate(d):
    """report the 15 s gauge (or any other number) instead of the measured counter difference: +10 %"""
    def f(r):
        r['hashrate_sampled'] = round(r['hashrate_sampled'] * 1.1, 2)
    _mut_tri(d, 'intel-live-metrics', f)


def mut_regime_backlog(d):
    """overstate the CPU-sort backlog of the split regime card by 0.2"""
    def f(r):
        r['cpu_backlog_fraction'] = round((r['cpu_backlog_fraction'] or 0) + 0.2, 3)
    _mut_tri(d, 'intel-split-regime', f)


def mut_regime_label(d):
    """flip the regime label (cpu-sort-bound <-> gpu-bound) against its own numbers"""
    def f(r):
        r['regime'] = 'gpu-bound' if r['regime'] != 'gpu-bound' else 'cpu-sort-bound'
    _mut_tri(d, 'intel-split-regime', f)


def mut_regime_window(d):
    """the regime card claims more windows than the raw log holds (a stretched window)"""
    def f(r):
        r['windows'] += 3
    _mut_tri(d, 'intel-split-regime', f)


def mut_ledger_runs(d):
    """the ledger card claims one run more than the file holds"""
    def f(r):
        r['runs'] += 1
    _mut_tri(d, 'intel-run-ledger', f)


def mut_evo_lines(d):
    """r23c: a round claims 100 more added lines than git holds"""
    p = d / 'harness/model/verified.json'
    V = json.loads(p.read_text())
    r = next(r for r in V if r.get('kind') == 'evo-round' and r['commits'])
    r['added'] += 100
    p.write_text(json.dumps(V))


def mut_evo_commit(d):
    """r23c: a commit is moved from one round into another as a duplicate (counted twice)"""
    p = d / 'harness/model/verified.json'
    V = json.loads(p.read_text())
    rs = [r for r in V if r.get('kind') == 'evo-round' and r['commits']]
    rs[-1]['commits'].append(rs[0]['commits'][0])
    p.write_text(json.dumps(V))


MUTATIONS = [
    ('DK01', 'a rendered anchor points at a line that is not there', mut_anchor_line),
    ('DK01', 'a rendered quote is text that is on no line', mut_quote),
    ('DK07', 'an evidence class outside the closed vocabulary', mut_class),
    ('DK05', 'the 12-character anchor floor is lowered to 2', mut_floor),
    ('DK08', 'a bridged console line is attributed to the wrong Go line', mut_bridge),
    ('DK09', 'a bridge crosses from one logger owner to another', mut_plaus),
    ('DK10', 'a hop is given an order outside its chain', mut_hops),
    ('DK13', 'a package line count is inflated by 1000', mut_loc),
    ('DK12', 'the difficulty upper bound is replaced with 2.0', mut_diff),
    ('DK15', 'a live reading no longer matches its snapshot line', mut_runtime),
    ('DK19', 'the grandfather-table count is set to the old 16', mut_hf3),
    ('DK14', 'a local-change row names a file that did not change', mut_localdiff),
    ('DK20', 'the tip-age claim is flipped against its own number (behind ↔ at tip)', mut_tipage),
    ('DK21', 'a quoted press claim is presented as the tree\u2019s own SRC finding', mut_press_class),
    ('DK23', 'the printed keyhash is declared not to be the zero signer', mut_zerosigner),
    ('DK24', 'an error this node raised is blamed on a peer', mut_origin),
    ('DK25', 'one transaction-store error is hidden from the count', mut_tricount),
    ('DK26', 'the consensus guard is blinded (its normaliser drops every statement)', mut_guard_blind),
    ('DK27', 'a baseline copy of the old source is tampered with', mut_baseline),
    ('DK28', 'the current run\u2019s mean block interval is overstated by 5 s', mut_cadence),
    ('DK29', 'topo.map is claimed to end in a partial record', mut_topo_claim),
    ('DK30', 'risk coverage is overstated by ten functions', mut_coverage),
    ('DK31', 'the current miner run\u2019s mean hashrate is overstated by 5,000 H/s', mut_miner_mean),
    ('DK32', 'the live dashboard\u2019s sampled hashrate is overstated by 10 %', mut_live_rate),
    ('DK33', 'the split regime\u2019s CPU-sort backlog is overstated by 0.2', mut_regime_backlog),
    ('DK33', 'the split regime label is flipped against its own numbers', mut_regime_label),
    ('DK33', 'the split regime card claims three windows the raw log does not hold', mut_regime_window),
    ('DK34', 'the run ledger card claims one run more than the file holds', mut_ledger_runs),
    ('DK35', 'an evolution round claims 100 added lines git does not hold', mut_evo_lines),
    ('DK35', 'an evolution round counts another round\u2019s commit a second time', mut_evo_commit),
    ('DK18', 'a 25-word recovery seed appears on the page', mut_seed),
    ('DK18', 'a quoted 25-word seed wrapped in <code> appears on the page', mut_seed_code),
    ('DK18', 'a 25-word seed split over lines with commas appears on the page', mut_seed_lines),
    ('DK18', 'an unlabelled 25-word seed in a quoted code citation appears on the page', mut_seed_unlabelled),
]


def load(d):
    V = json.loads((d / 'harness/model/verified.json').read_text())
    H = (d / 'artifacts/dero-src-arch.html').read_text()
    st = json.loads((d / 'harness/stamp.json').read_text())
    return V, H, st


def main():
    muts = '--mutations' in sys.argv
    d = scratch()
    r = build(d)
    if r.returncode not in (0,):
        print('BUILD FAILED in the scratch copy:', (r.stderr or r.stdout)[-400:])
        return 3
    V, H, st = load(d)
    results, fails = [], 0
    for name, fn in KATS:
        try:
            ok, detail = fn(d, V, H, st)
        except Exception as e:                                    # noqa: BLE001
            ok, detail = False, f'{type(e).__name__}: {e}'
        results.append((name, ok, detail))
        if not ok:
            fails += 1
        print(f"{'ok  ' if ok else 'FAIL'} {name} {detail[:150]}")
    unproved = 0
    if muts:
        print('\nmutations (each must flip ITS kat to FAIL):')
        byname = dict(KATS)
        for kat, why, mut in MUTATIONS:
            d2 = scratch()
            if build(d2).returncode != 0:
                print(f'  ??  {kat} {why}: scratch build failed')
                unproved += 1
                shutil.rmtree(d2, ignore_errors=True)
                continue
            mut(d2)
            try:
                V2, H2, st2 = load(d2)
                ok2 = byname[kat](d2, V2, H2, st2)[0]
            except Exception:                                      # noqa: BLE001
                ok2 = False                                        # a crash is a detection
            print(f"  {'proved ' if not ok2 else 'MISSED '} {kat}: {why}")
            if ok2:
                unproved += 1
            shutil.rmtree(d2, ignore_errors=True)
    out = {'ok': len(KATS) - fails, 'total': len(KATS), 'muts': len(MUTATIONS) if muts else 0,
           'mut_proved': (len(MUTATIONS) - unproved) if muts else 0,
           'fails': [n for n, o, _ in results if not o]}
    (REAL / 'loop/KAT_LAST.json').write_text(json.dumps(out, indent=1))  # one field per line: anchorable
    print(f"\nKATs: {len(KATS) - fails}/{len(KATS)} ok"
          + (f' · mutations proved {len(MUTATIONS) - unproved}/{len(MUTATIONS)}' if muts else ''))
    shutil.rmtree(d, ignore_errors=True)
    return 3 if fails else (4 if unproved else 0)


if __name__ == '__main__':
    sys.exit(main())
