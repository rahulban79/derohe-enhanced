#!/usr/bin/env python3
"""r25 tooling intelligence: per-round metrics of the non-core tooling and assets (dero-rft §0.9, area `tooling`, B87).

Reads (never writes) the harness records, the KAT files, the project memory directory, the in-repo memory mirror, the
skills, the evolution miner's round axis, the gate list, and (opt-in) re-runs the page generators, the publish
scrubber and the scripts. Writes:

  harness/runtime/tooling_<ts>.json      one record per run: every KPI on its own line (the anchor of area `tooling`)
  harness/runtime/tooling_intel.json     the same record (the newest), read by harness/intel/area_intel.py

KPIs (§0.9 rule 2; 'pending' when the input is missing, never a guess):
  harness   kats_passed/kats_total, kat_mutations_proved/total (the 'mutations proved X/Y' line of every KAT step, nothing
            else: tooling class 'count-regex misread'), harness_mutations (verify_deroarch), gates_pass/total/paused,
            project_wall_s and the slowest steps (tool runtimes), flaky (newest full run's S3a)
  memory    memory_files, memory_index_lines/bytes/longest/over_300, memory_index_dangling (links to no file),
            memory_unindexed (files no index line links), memory_index_duplicates, memory_stale_claims
            (harness/loop/STALE_MEMORY_CLAIMS.json: a refuted claim still in the memory without a dated correction)
  mirror    mirror_drift (memory-mirror/MANIFEST.sha256: source changed since the sync, file missing, hand-edited, or a
            private identifier in the in-repo copy)
  skills    skill_last_round, skill_fresh (last '## Round <N>' heading = the registry's current round)
  rounds    order_gaps (non-planned registry rounds missing from mine_evolution.ORDER, B90), order_next_missing
  gates     gate_id_duplicates (one G<n> used by two different gate titles in run_gates.py, lesson #68)
  classes   defect_classes_without_kat (every R24/R25 tooling defect class must name a KAT that exists, §0.9 rule 1)
  resume    checkpoint_age_s: seconds since the round's resume checkpoint (harness/intel/round_checkpoint.py, §0.10;
            ~/derohe-persist/round_state/<round>_state.json 'stamp'; the --loop 600 writes one every 10 min)
  opt-in    --determinism: generator double runs byte-exact (gen_index, soundness, gen_deroarch build), in an
            isolated copy of the tree (r25 merge: it used to run in place);
            --scrub-control: pubscrub planted-secret control (false negatives must be 0; false positives counted);
            --scripts: every repo-root *.sh passes `bash -n`, every tools/<go dir> builds (no live effect)

Privacy: no home path, user name, address or IP is written; the memory dir is shown as ~/.claude/projects/<project>/memory.
The planted secrets of --scrub-control are built at run time in a temporary directory and never written to the tree.

  python3 -I harness/intel/tooling_intel.py [--memory-dir DIR] [--determinism] [--scrub-control] [--scripts]
Exit 0 every target met · 5 a §0.9 rule-2 target is violated (the record is still written) · 2 bad invocation.
"""
import datetime, hashlib, json, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
PENDING = 'pending'
INDEX_MAX_LINE = 300          # §0.9 rule 4: one line per topic, at most 300 characters
INDEX_MAX_LINES = 200         # §0.9 rule 4: under 200 lines
PROJECT_HOME = 'derohe-Release142'     # the Claude project whose memory dir this repo's rounds use (rft §0.2 Memories)
MEMORY_SHOWN = '~/.claude/projects/<project>/memory'
MIRROR = 'memory-mirror'
MANIFEST = 'MANIFEST.sha256'
CLAIMS = 'harness/loop/STALE_MEMORY_CLAIMS.json'
SOUNDNESS_PAGE = '<soundness page of the current round>'   # r25: resolved per tree by harness/kit/soundpage.py


def soundness_rel(root):
    import importlib.util
    spec = importlib.util.spec_from_file_location(f'soundpage_for_tooling_{id(root)}', HARNESS / 'kit/soundpage.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m.rel(root)


GENERATORS = [            # (command, output page) for --determinism; each is run twice and the page hashed after each
    (['harness/gen_index.py'], 'artifacts/index.html'),
    (['harness/soundness.py'], SOUNDNESS_PAGE),   # r25: the current round's page (harness/kit/soundpage.py)
    (['harness/gen_deroarch.py', 'build'], 'artifacts/dero-src-arch.html'),
]
# §0.9 rule 1: every tooling defect class of R24/R25 and the KAT (file, id marker) that reproduces it
DEFECT_CLASSES = [
    ('substring step match', 'harness/kat/test_intel_r21.py', "Path(str(step).split()[0]).stem == k"),   # c191245 IK24 case
    ('substring step match (area_intel pipeline_step)', 'harness/kat/test_area_r25.py', 'AC5'),
    ('duplicate gate ids', 'harness/kat/test_tooling_intel_r25.py', 'TI6'),
    ('count-regex misread', 'harness/kat/test_coherence_r24.py', "('CO1', \"GRADE_N"),           # cbaf664
    ('count-regex misread (KAT mutation lines)', 'harness/kat/test_tooling_intel_r25.py', 'TI4'),
    ('partial-page privacy scan', 'harness/kat/test_peer_intel_r24.py', 'PI13'),
    ('partial-page privacy scan (memory mirror)', 'harness/kat/test_tooling_intel_r25.py', 'TI2'),
    ('live reading booked to the wrong round', 'harness/kat/test_area_record_r24.py', 'AR4'),
    ('live reading booked to the wrong round (no version line)', 'harness/kat/test_area_r25.py', 'AC3'),
    ('probes hitting pruned state', 'harness/kat/test_stateguard_r25.py', 'SG1'),
    ('round missing from the evolution ORDER', 'harness/kat/test_tooling_intel_r25.py', 'TI5'),
    ('counter of 0 booked without its event', 'harness/kat/test_area_r25.py', 'AC2'),
    ('superseded booked value frozen', 'harness/kat/test_area_r25.py', 'AC1'),
    ('opt-in check writes the tree it measures (--determinism in place)', 'harness/kat/test_tooling_intel_r25.py', 'TI11'),
]
# generic private-identifier shapes (no private literal in this file): an absolute home path, a scratchpad project dir
# name, an e-mail, a DERO address, a non-reserved IPv4
PRIVATE_RX = [
    ('home-path', re.compile(r'/Users/[A-Za-z0-9._-]+')),
    ('project-dirname', re.compile(r'-Users-[A-Za-z0-9._]+-')),
    ('email', re.compile(r'[\w.+-]+@[\w-]+\.[\w.]+')),
    ('dero-address', re.compile(r'\bdero[i1]q[0-9a-z]{30,}')),
    # r25: '(?!\d|\.\d)', not '(?![\d.])': an address that ends a sentence ('gateway 192.0.2.1.') is still an address
    # (the in-repo mirror carried one past both this check and pubscrub's IP scan, 2026-11-03)
    ('ipv4', re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)')),
]
IP_OK = re.compile(r'^(?:127\.|10\.|0\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|255\.)')


def now():
    return datetime.datetime.now().astimezone()


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def default_memory_dir():
    env = os.environ.get('DERO_MEMORY_DIR')
    if env:
        return Path(env)
    proj = '-' + str(Path.home() / PROJECT_HOME).strip('/').replace('/', '-')
    return Path.home() / '.claude' / 'projects' / proj / 'memory'


# ───────────────────────────── harness records ─────────────────────────────
def read_jsonl(p):
    out = []
    try:
        for l in Path(p).read_text().splitlines():
            try:
                out.append(json.loads(l))
            except ValueError:
                pass
    except OSError:
        pass
    return out


def frac(v):
    """'35/35' -> (35, 35); anything else -> None. Pure."""
    m = re.fullmatch(r'\s*(\d+)\s*/\s*(\d+)\s*', str(v or ''))
    return (int(m.group(1)), int(m.group(2))) if m else None


GATES_RX = re.compile(r'^\s*(\d+)\s*/\s*(\d+)(?:\s*\(\+(\d+)\s+PAUSED)?')
KAT_MUT_RX = re.compile(r'mutations proved (\d+)\s*/\s*(\d+)')


def kat_mutations(lines):
    """(proved, total) summed over KAT summary lines. Only the literal 'mutations proved X/Y' counts: a line such as
    'ANOMALY 7848898 blocks behind us' or 'mutations: 3 INVALID' is never read as a count (tooling class 'count-regex
    misread', cbaf664 / CO1). Pure."""
    p = t = 0
    for l in lines:
        for m in KAT_MUT_RX.finditer(str(l)):
            p, t = p + int(m.group(1)), t + int(m.group(2))
    return p, t


def ts(o):
    try:
        return datetime.datetime.fromisoformat(o['t'])
    except (KeyError, ValueError, TypeError):
        return None


def step_runtimes(ev):
    """[(step, seconds)] of one record's project steps: the gap from the previous event's timestamp (the records stamp
    each step when it ends, to the second). Pure."""
    out, prev = [], None
    for o in ev:
        t = ts(o)
        if o.get('stage') == 'project' and o.get('step') and t and prev:
            out.append((o['step'], int((t - prev).total_seconds())))
        if t:
            prev = t
    return out


def project_summary(ev, rel):
    """KPIs of one pipeline record that ran S7 (a project-only run or the end of a full run). Pure."""
    k = {}
    start = next((ts(o) for o in ev if o.get('stage') == 'project' and o.get('status') == 'START'), None)
    end = next((o for o in ev if o.get('stage') == 'project' and o.get('status') in ('PASS', 'FAIL')), None)
    if not end:
        return {'harness_record': rel, 'kats_passed': PENDING}
    kf, mf = frac(end.get('kats')), frac(end.get('mutations'))
    g = GATES_RX.match(str(end.get('gates') or ''))
    k['harness_record'] = rel
    k['project_status'] = end.get('status')
    if kf:
        k['kats_passed'], k['kats_total'] = kf
    if mf:
        k['harness_mutations_caught'], k['harness_mutations_total'] = mf
    if g:
        k['gates_pass'], k['gates_total'], k['gates_paused'] = int(g.group(1)), int(g.group(2)), int(g.group(3) or 0)
    lines = [l for o in ev if o.get('stage') == 'project' and str(o.get('step', '')).startswith('harness/kat/')
             for l in (o.get('last') or [])]
    p, t = kat_mutations(lines)
    if t:
        k['kat_mutations_proved'], k['kat_mutations_total'] = p, t
        k['kat_mutation_kill_pct'] = round(100.0 * p / t, 2)
    if start and ts(end):
        k['project_wall_s'] = int((ts(end) - start).total_seconds())
    rt = sorted(step_runtimes(ev), key=lambda x: -x[1])
    k['slowest_steps'] = [f'{s} {n}s' for s, n in rt[:5]]
    return k


def harness_kpis(root):
    runs = Path(root) / 'harness/loop/runs'
    recs = sorted(runs.glob('pipeline_*.jsonl'))
    out = {}
    for p in reversed(recs):          # the newest record that ran S7
        ev = read_jsonl(p)
        if any(o.get('stage') == 'project' and o.get('status') in ('PASS', 'FAIL') for o in ev):
            out.update(project_summary(ev, f'harness/loop/runs/{p.name}'))
            break
    for p in reversed(recs):          # the newest record with an S3a flaky stage
        ev = read_jsonl(p)
        fl = next((o for o in ev if o.get('stage') == 'flaky' and o.get('status') in ('PASS', 'FAIL')), None)
        if fl is not None and str(fl.get('flaky', '')).isdigit():
            out['flaky'] = int(fl['flaky'])
            out['flaky_record'] = f'harness/loop/runs/{p.name}'
            break
    out['kat_files'] = len(list((Path(root) / 'harness/kat').glob('test_*.py')))
    return out


# ───────────────────────────── memory ─────────────────────────────
LINK_RX = re.compile(r'\]\(([^)\s]+\.md)\)')


def memory_index_kpis(mdir):
    """index hygiene of MEMORY.md in `mdir` (§0.9 rule 4). Pure over the directory."""
    mdir = Path(mdir)
    idx = mdir / 'MEMORY.md'
    try:
        text = idx.read_text(encoding='utf-8')
    except OSError:
        return {'memory_files': PENDING}
    files = sorted(p.name for p in mdir.glob('*.md'))
    lines = text.splitlines()
    entries = [l for l in lines if l.lstrip().startswith('- [')]
    links = [m for l in entries for m in LINK_RX.findall(l)]
    topics = [f for f in files if f != 'MEMORY.md']
    return {'memory_files': len(files), 'memory_index_lines': len(lines), 'memory_index_bytes': len(text.encode('utf-8')),
            'memory_index_longest': max((len(l) for l in lines), default=0),
            'memory_index_over_300': sum(1 for l in lines if len(l) > INDEX_MAX_LINE),
            'memory_index_dangling': sorted({x for x in links if x not in files}),
            'memory_unindexed': sorted(set(topics) - set(links)),
            'memory_index_duplicates': sorted({x for x in links if links.count(x) > 1})}


CORRECTION_RX = re.compile(r'(REVISED|REFUTED|CORRECTED|corrected|correction|superseded|stale)[^\n]{0,40}\d{4}-\d{2}-\d{2}'
                           r'|\d{4}-\d{2}-\d{2}[^\n]{0,40}(REVISED|REFUTED|CORRECTED|corrected|correction|superseded|stale)')


def stale_claims(mdir, claims):
    """the registered refuted claims still present in the memory dir on a line that carries no dated correction. Pure
    over the directory; `claims` = [{id, quote, ...}]."""
    out = []
    for c in claims or []:
        q = c.get('quote')
        if not q:
            continue
        for p in sorted(Path(mdir).glob('*.md')):
            try:
                for i, l in enumerate(p.read_text(encoding='utf-8', errors='replace').splitlines(), 1):
                    if q in l and not CORRECTION_RX.search(l):
                        out.append(f"{c.get('id')}: {p.name}:{i}")
            except OSError:
                continue
    return out


def private_hits(text):
    """[(kind, count)] of private-identifier shapes in `text`; reserved/documentation IPv4s and loopback do not count.
    Pure."""
    out = []
    for kind, rx in PRIVATE_RX:
        hits = rx.findall(text)
        if kind == 'ipv4':
            hits = [h for h in hits if not IP_OK.match(h) and all(0 <= int(x) <= 255 for x in h.split('.'))]
        if hits:
            out.append((kind, len(hits)))
    return out


def read_manifest(p):
    """{file: (source_sha, mirror_sha or '-')} from a MANIFEST.sha256 whose lines are '<source sha> <mirror sha|->
    <file>' ('-' = refused by tools/memory-mirror/sync_mirror.py for a private identifier), or None without a manifest."""
    out = {}
    try:
        for l in Path(p).read_text().splitlines():
            m = re.fullmatch(r'([0-9a-f]{64})\s+([0-9a-f]{64}|-)\s+(\S+)', l.strip())
            if m:
                out[m.group(3)] = (m.group(1), m.group(2))
    except OSError:
        return None
    return out


def mirror_drift(mdir, mirror):
    """(count, reasons) of the in-repo scrubbed mirror against the memory dir (§0.9 rule 5): no manifest = every mirror
    file and every source file is drift; a source file the manifest does not list (new since the sync), a source whose
    hash differs from the manifest's (changed since the sync), a listed file absent from the mirror, a mirror file the
    manifest does not list or whose bytes differ from the manifest's hash (hand-edited), a file refused for a private
    identifier ('-'), and a mirror file carrying a private identifier each count once. Pure over the directories."""
    mdir, mirror = Path(mdir), Path(mirror)
    src = {p.name: sha256(p.read_bytes()) for p in mdir.glob('*.md')} if mdir.is_dir() else {}
    mir = {p.name: p for p in mirror.glob('*.md')} if mirror.is_dir() else {}
    man = read_manifest(mirror / MANIFEST)
    if man is None:
        reasons = [f'{n}: no {MANIFEST}' for n in sorted(set(mir) | set(src))]
        return len(reasons), reasons
    reasons = []
    for n in sorted(set(src) | set(mir) | set(man)):
        why = None
        if n in src and n not in man:
            why = 'not in the manifest (new since the sync)'
        elif n in man and man[n][1] == '-':
            why = 'refused by the scrub (private identifier left): not mirrored'
        elif n in man and n not in mir:
            why = 'listed in the manifest, absent from the mirror'
        elif n in mir and n not in man:
            why = 'in the mirror but not in the manifest'
        elif sha256(mir[n].read_bytes()) != man[n][1]:
            why = 'mirror bytes differ from the manifest (hand-edited)'
        elif n not in src:
            why = 'source no longer exists'
        elif src[n] != man[n][0]:
            why = 'source changed since the sync'
        if why is None and n in mir:
            ph = private_hits(mir[n].read_text(encoding='utf-8', errors='replace'))
            if ph:
                why = f'private identifier {ph}'
        if why:
            reasons.append(f'{n}: {why}')
    return len(reasons), reasons


# ───────────────────────────── skills, rounds, gates, classes ─────────────────────────────
ROUND_HEAD_RX = re.compile(r'^## Round (\d+[a-z]?)\b', re.M)


def skill_kpis(root, current):
    sk = sorted((Path(root) / '.skills').glob('*/SKILL.md'))
    if not sk:
        return {'skills': 0, 'skill_last_round': PENDING}
    out = {'skills': len(sk), 'skill_lines': {}, 'skill_last_round': {}}
    fresh = True
    for p in sk:
        t = p.read_text(encoding='utf-8', errors='replace')
        rounds = ROUND_HEAD_RX.findall(t)
        last = ('r' + rounds[-1]) if rounds else None
        out['skill_lines'][p.parent.name] = len(t.splitlines())
        out['skill_last_round'][p.parent.name] = last or PENDING
        fresh &= bool(last) and last.lower() == str(current).lower()
    out['skill_fresh'] = int(fresh)
    return out


def order_gaps(registry, order):
    """(gaps, next_missing): registry rounds that are not 'planned' but whose ledger key ('r24' -> 'R24') is not in the
    evolution ORDER (the miner then refuses their commits, B90), and the planned rounds not yet listed (an early warning
    for the round's first commit, e.g. an 'R26 plan:' commit). Pure."""
    gaps, nxt = [], []
    for r in (registry or {}).get('rounds') or []:
        key = 'R' + str(r.get('id', ''))[1:]
        if key in order:
            continue
        (nxt if r.get('status') == 'planned' else gaps).append(key)
    return gaps, nxt


def evolution_order(root):
    """mine_evolution.ORDER, from its own 'ORDER = ...' / 'ORDER += ...' lines (run alone, without the miner's imports),
    or None when the file or the lines cannot be read."""
    try:
        src = (Path(root) / 'harness/miners/mine_evolution.py').read_text()
    except OSError:
        return None
    ns = {}
    try:
        for l in src.splitlines():
            if re.match(r'^ORDER\s*\+?=', l):
                exec(compile(l, 'mine_evolution.py', 'exec'), {'range': range}, ns)   # noqa: S102 — this repo's own line
    except Exception:                                                                 # noqa: BLE001
        return None
    return ns.get('ORDER')


GATE_APPEND_RX = re.compile(r"res\.append\(\(\s*'(G\d+)\s+([^']*)'")


def duplicate_gate_ids(src):
    """{gate id: [titles]} for every G<n> that run_gates.py appends under two different titles (two patches both named
    their new gate 'G23', lesson #68). Branches of one gate append the same title, which is not a duplicate. Pure."""
    seen = {}
    for g, title in GATE_APPEND_RX.findall(src):
        seen.setdefault(g, set()).add(title.strip())
    return {g: sorted(t) for g, t in seen.items() if len(t) > 1}


def classes_without_kat(root, classes=None):
    out = []
    for name, f, marker in classes or DEFECT_CLASSES:
        try:
            if marker not in (Path(root) / f).read_text(errors='replace'):
                out.append(f'{name}: {marker} not in {f}')
        except OSError:
            out.append(f'{name}: {f} missing')
    return out


# ───────────────────────────── opt-in probes ─────────────────────────────
STAMP_RX = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2}|Z)?|\b[0-9a-f]{16}\b')


def diff_kind(a, b):
    """'byte-exact', 'DIFFERS: build time/fingerprint only' (equal once ISO timestamps and 16-hex fingerprints are
    masked), or 'DIFFERS'. Pure. A timestamp-only difference is still a mismatch (§0.9 rule 2), named so the fix is
    obvious (r25: dero-src-arch.html prints 'page built <now>' and a fingerprint of it)."""
    if a == b:
        return 'byte-exact'
    ta, tb = a.decode('utf-8', 'replace'), b.decode('utf-8', 'replace')
    return 'DIFFERS: build time/fingerprint only' if STAMP_RX.sub('#', ta) == STAMP_RX.sub('#', tb) else 'DIFFERS'


def checkpoint_dir():
    return Path(os.environ.get('ROUND_CKPT_OUT') or Path.home() / 'derohe-persist' / 'round_state')


def checkpoint_age(out_dir, current, at=None):
    """seconds since the stamp of <current>_state.json in out_dir (round_checkpoint.py), or 'pending' when there is
    none or it does not parse. Pure on the file (KAT TI12)."""
    try:
        st = json.loads((Path(out_dir) / f'{current}_state.json').read_text()).get('stamp')
        t = datetime.datetime.strptime(st, '%Y-%m-%dT%H:%M:%S%z')
    except (OSError, ValueError, TypeError):
        return PENDING
    at = at or datetime.datetime.now(datetime.timezone.utc)
    return max(0, int((at - t).total_seconds()))


def isolated_copy(root, dest):
    """copy the tree at `root` (its .git included: the generators read git) to `dest` as an APFS clone (`cp -c`, no
    data copied), else a plain copy. r25 (merge, harnesstool verify OPEN): --determinism ran the generators IN PLACE
    and left tracked files modified (SKILL.md, artifacts/*.html, harness/corpus, model/verified.json, stamp.json)."""
    dest = Path(dest)
    r = subprocess.run(['cp', '-cR', str(Path(root)) + '/', str(dest)], capture_output=True, text=True)
    if r.returncode != 0 or not dest.is_dir():
        shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(root, dest, symlinks=True)
    return dest


def determinism(root, generators=None):
    """{page: 'byte-exact' | 'DIFFERS[: build time/fingerprint only]' | 'FAILED <rc>'} after running each generator
    twice in an isolated copy of the tree (never in place: the docstring's 'never writes' holds, KAT TI11)."""
    out = {}
    with tempfile.TemporaryDirectory(prefix='tooling_det_') as tmp:
        work = isolated_copy(root, Path(tmp) / 'tree')
        for cmd, page in (GENERATORS if generators is None else generators):
            if page == SOUNDNESS_PAGE:
                page = soundness_rel(work)
            hs, raw = [], []
            for _ in range(2):
                r = subprocess.run(['nice', '-n', '15', sys.executable, '-I', *cmd], cwd=work, capture_output=True,
                                   text=True, timeout=1800)
                if r.returncode != 0:
                    hs.append(f'FAILED {r.returncode}')
                    break
                try:
                    raw.append((work / page).read_bytes())
                    hs.append(sha256(raw[-1]))
                except OSError:
                    hs.append('FAILED no page')
                    break
            out[page] = hs[0] if hs[0].startswith('FAILED') else (hs[-1] if hs[-1].startswith('FAILED') else
                                                                   diff_kind(raw[0], raw[1]))
    return out


def scrub_counts(plants, scrubbed, clean_in, clean_out):
    """(false negatives, false positives): plants still present after the scrub, and lines of a clean control text that
    the scrub changed. Pure."""
    fn = sum(1 for p in plants if p and p in scrubbed)
    a, b = clean_in.splitlines(), clean_out.splitlines()
    fp = sum(1 for i in range(max(len(a), len(b))) if (a[i] if i < len(a) else None) != (b[i] if i < len(b) else None))
    return fn, fp


TOOL_PATHS = 'harness/loop/TOOL_PATHS.json'     # r25: out-of-repo tool locations (that dir is not published)


def tool_path(key, root=ROOT):
    """the configured location of an out-of-repo tool (TOOL_PATHS.json, '~' expanded), or None"""
    try:
        v = json.loads((Path(root) / TOOL_PATHS).read_text()).get(key)
    except (OSError, ValueError):
        return None
    return Path(os.path.expanduser(v)) if v else None


def scrub_plants(root=ROOT):
    """synthetic planted secrets in the shapes the scrubber must remove, built at run time from the scrubber's own rule
    table and the home directory (never written to the tree): a home path, an e-mail, a LAN address, the wallet prefix
    with a synthetic tail, a mapped peer address."""
    rules = tool_path('sync_rules', root)
    plants = [str(Path.home()) + '/derohe-Release151/x.go', 'someone.planted' + '@' + 'gmail.com']
    try:
        src = rules.read_text()
        lan = re.search(r"\('lan', re\.compile\(rb'[^']*?(\d+)\\\.(\d+)\\\.(\d+)\\\.", src)
        if lan:
            plants.append('.'.join(lan.groups()) + '.77')
        w = re.search(r"\('wallet', re\.compile\(rb'([0-9a-z]+)'\)\)", src)
        if w:
            plants.append(w.group(1) + 'plantedplantedplantedplanted')
        ip = re.search(r"IP_MAP = \{\s*'([\d.]+)'", src)
        if ip:
            plants.append(ip.group(1))
    except (OSError, AttributeError):
        return None
    return plants


CLEAN_CONTROL = ('the node listens on 127.0.0.1:10102 and 0.0.0.0:11011\n'
                 'a documentation address 203.0.113.10 and a resolver 8.8.8.8\n'
                 'the home directory is written ~ in every page\n'
                 'topoheight 7,498,540 is the prune point\n'
                 'gate G27 scans the whole page\n')


def scrub_control():
    tool = tool_path('pubscrub')
    plants = scrub_plants()
    if tool is None or not tool.exists() or plants is None:
        return {'scrub_false_negatives': PENDING, 'why': 'pubscrub.py not on this machine'}
    with tempfile.TemporaryDirectory(prefix='r25scrub-') as d:
        src, out = Path(d) / 'in', Path(d) / 'out'
        src.mkdir()
        out.mkdir()
        # each plant twice: alone, and ending a sentence (an IP followed by '.' escaped a lookahead scan, 2026-11-03)
        (src / 'plant.html').write_text(''.join(f'<p>{p}</p>\n<p>it ends this sentence {p}.</p>\n' for p in plants))
        (src / 'clean.html').write_text(CLEAN_CONTROL)
        r = subprocess.run([sys.executable, '-I', str(tool), str(out), str(src / 'plant.html'), str(src / 'clean.html')],
                           capture_output=True, text=True, timeout=300)
        try:
            fn, fp = scrub_counts(plants, (out / 'plant.html').read_text(), CLEAN_CONTROL, (out / 'clean.html').read_text())
        except OSError:
            return {'scrub_false_negatives': PENDING, 'why': f'pubscrub wrote no output (rc {r.returncode})'}
    return {'scrub_plants': len(plants), 'scrub_false_negatives': fn, 'scrub_false_positives': fp, 'scrub_rc': r.returncode}


def scripts(root):
    ok, bad = 0, []
    for p in sorted(Path(root).glob('*.sh')) + sorted((Path(root) / 'tools').rglob('*.sh')):
        r = subprocess.run(['bash', '-n', str(p)], capture_output=True, text=True, timeout=60)
        if r.returncode == 0:
            ok += 1
        else:
            bad.append(p.relative_to(root).as_posix())
    for d in sorted(x for x in (Path(root) / 'tools').iterdir() if x.is_dir() and list(x.glob('*.go'))):
        r = subprocess.run(['nice', '-n', '15', 'go', 'build', '-o', os.devnull, './' + d.relative_to(root).as_posix()],
                           cwd=root, capture_output=True, text=True, timeout=900)
        if r.returncode == 0:
            ok += 1
        else:
            bad.append(d.relative_to(root).as_posix() + '/')
    return {'scripts_ok': ok, 'scripts_total': ok + len(bad), 'scripts_bad': bad}


# ───────────────────────────── the run ─────────────────────────────
def targets(k):
    """the §0.9 rule-2 violations of one record. Pure."""
    v = []
    if isinstance(k.get('mirror_drift'), int) and k['mirror_drift']:
        v.append(f"mirror_drift {k['mirror_drift']} (must be 0 at round end)")
    if k.get('defect_classes_without_kat'):
        v.append(f"tooling defect classes without a KAT {k['defect_classes_without_kat']}")
    if k.get('order_gaps'):
        v.append(f"rounds missing from the evolution ORDER {k['order_gaps']}")
    if k.get('gate_id_duplicates'):
        v.append(f"gate ids used by two gates {k['gate_id_duplicates']}")
    if isinstance(k.get('flaky'), int) and k['flaky']:
        v.append(f"flaky tests {k['flaky']} (target 0)")
    if isinstance(k.get('scrub_false_negatives'), int) and k['scrub_false_negatives']:
        v.append(f"pubscrub false negatives {k['scrub_false_negatives']} on the planted control")
    if any(x != 'byte-exact' for x in (k.get('determinism') or {}).values()):
        v.append(f"generator double run not byte-exact {k['determinism']}")
    if isinstance(k.get('memory_index_over_300'), int) and k['memory_index_over_300']:
        v.append(f"memory index lines over {INDEX_MAX_LINE} chars: {k['memory_index_over_300']}")
    if isinstance(k.get('memory_index_lines'), int) and k['memory_index_lines'] >= INDEX_MAX_LINES:
        v.append(f"memory index {k['memory_index_lines']} lines (>= {INDEX_MAX_LINES})")
    if k.get('memory_stale_claims'):
        v.append(f"stale memory claims {k['memory_stale_claims']}")
    if k.get('skill_fresh') == 0:
        v.append(f"skill not recorded for the current round {k.get('skill_last_round')}")
    if k.get('scripts_bad'):
        v.append(f"scripts that do not build {k['scripts_bad']}")
    return v


def run(root, mdir, opt_det=False, opt_scrub=False, opt_scripts=False):
    root = Path(root)
    try:
        registry = json.loads((root / 'harness/round.json').read_text())
    except (OSError, ValueError):
        registry = {}
    cur = registry.get('current', PENDING)
    k = {'round': cur}
    k.update(harness_kpis(root))
    k.update(memory_index_kpis(mdir))
    try:
        claims = json.loads((root / CLAIMS).read_text()).get('claims', [])
    except (OSError, ValueError):
        claims = None
    if claims is None or not Path(mdir).is_dir():
        k['memory_stale_claims'] = PENDING
    else:
        k['memory_stale_claims'] = stale_claims(mdir, claims)
        k['memory_stale_claim_count'] = len(k['memory_stale_claims'])
    if Path(mdir).is_dir():
        n, why = mirror_drift(mdir, root / MIRROR)
        k['mirror_drift'], k['mirror_drift_reasons'] = n, why[:60]
    else:
        k['mirror_drift'] = PENDING
    k.update(skill_kpis(root, cur))
    order = evolution_order(root)
    if order is None:
        k['order_gaps'] = PENDING
    else:
        k['order_gaps'], k['order_next_missing'] = order_gaps(registry, order)
    try:
        k['gate_id_duplicates'] = duplicate_gate_ids((root / 'harness/run_gates.py').read_text())
    except OSError:
        k['gate_id_duplicates'] = PENDING
    k['checkpoint_age_s'] = checkpoint_age(checkpoint_dir(), cur)
    k['defect_classes'] = len(DEFECT_CLASSES)
    k['defect_classes_without_kat'] = classes_without_kat(root)
    k['determinism'] = determinism(root) if opt_det else {}
    if opt_scrub:
        k.update(scrub_control())
    if opt_scripts:
        k.update(scripts(root))
    k['determinism_mismatches'] = sum(1 for x in k['determinism'].values() if x != 'byte-exact') if opt_det else PENDING
    if isinstance(k.get('gate_id_duplicates'), dict):
        k['gate_id_duplicate_count'] = len(k['gate_id_duplicates'])
    for key in ('memory_index_dangling', 'memory_unindexed', 'memory_index_duplicates', 'defect_classes_without_kat',
                'order_gaps'):
        if isinstance(k.get(key), list):
            k[key + '_count'] = len(k[key])
    k['violations'] = targets(k)
    return k


def write(root, k):
    stamp = now().strftime('%Y%m%dT%H%M%S')
    rec = {'_doc': 'r25 tooling_intel (harness/intel/tooling_intel.py; dero-rft §0.9): one KPI per line, the anchor of '
                   'area tooling. pending = not measured.', 'captured': now().isoformat(timespec='seconds'),
           'memory_dir': MEMORY_SHOWN, 'capture_file': f'tooling_{stamp}.json', 'kpis': k}
    text = json.dumps(rec, indent=1, ensure_ascii=False) + '\n'
    rt = Path(root) / 'harness/runtime'
    (rt / f'tooling_{stamp}.json').write_text(text)
    (rt / 'tooling_intel.json').write_text(text)
    return f'harness/runtime/tooling_{stamp}.json'


def main(argv):
    mdir = default_memory_dir()
    if '--memory-dir' in argv:
        i = argv.index('--memory-dir')
        if i + 1 >= len(argv):
            print('--memory-dir needs a directory')
            return 2
        mdir = Path(argv[i + 1])
    k = run(ROOT, mdir, '--determinism' in argv, '--scrub-control' in argv, '--scripts' in argv)
    rel = write(ROOT, k)
    print(f"tooling_intel: round {k['round']} · KATs {k.get('kats_passed')}/{k.get('kats_total')} · KAT mutations "
          f"{k.get('kat_mutations_proved')}/{k.get('kat_mutations_total')} · gates {k.get('gates_pass')}/{k.get('gates_total')} "
          f"(+{k.get('gates_paused')} PAUSED) · memory index {k.get('memory_index_bytes')} B, longest {k.get('memory_index_longest')} · "
          f"mirror drift {k.get('mirror_drift')} · stale claims {k.get('memory_stale_claim_count', k.get('memory_stale_claims'))} · "
          f"wrote {rel}")
    for v in k['violations']:
        print('  TARGET', v)
    return 5 if k['violations'] else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
