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
            (harness/loop/STALE_MEMORY_CLAIMS.json: a refuted claim still in the memory without a dated correction);
            r27: memory_index_ranges (an index line that states a numbered range '#a–#b' for the file it links, and
            that file's highest '#N' line differs: the index under-states the file), memory_dead_refs (a repo path
            with a file extension that a memory file names and the tree no longer has)
            r28 (B140): memory_dead_names (a bare code-file name, e.g. 'txn_exec.go:131', that no tracked file of the
            tree ends with; the out-of-repo tools of TOOL_PATHS.json and OUT_OF_REPO_NAMES aside), memory_dead_symbols
            (inside one `code span`: a --flag or a func() written after a resolved code file that the file's source does
            not define), rft_lesson_ranges (a line of artifacts/dero-rft.md that names the lessons file and a '#a–#b'
            range whose end differs from the file's highest '#N': the rft §10 header and the memory disagree)
  mirror    mirror_drift (memory-mirror/MANIFEST.sha256: source changed since the sync, file missing, hand-edited, or a
            private identifier in the in-repo copy)
  skills    skill_last_round, skill_fresh (last '## Round <N>' heading = the registry's current round); r26 (B92):
            skill_over_budget (> SKILL_MAX_LINES lines), skill_paused (a skill whose '**Track:** <name>' is paused is
            not required to be fresh; at least one other skill must be)
  tools     r26 (B117 class, report-only): tools_without_help, harness tools whose `--help` would run them;
            r27 (tools-kats): kat_coverage: tools_total, tools_without_kat (no harness/kat/*.py names the tool's file),
            kat_coverage_pct; kat_mutations_coupled (the 'mutations coupled N' lines of the KAT steps: a mutation that
            also fails a KAT outside the defect it undoes, harness/kit/katmut.py; target 0); r28 (tools-kats, N28-04):
            tools_without_kat is a target (0) once every tool has one (78/78 at the R28 tools-kats clone)
  rounds    order_gaps (non-planned registry rounds missing from mine_evolution.ORDER, B90), order_next_missing;
            r28 (B149, lesson #80): round_list_gaps, every non-planned harness/round.json round that one of the other
            round lists lacks (harness/areas.json rounds, artifacts/src/gen_ledger.py LAST_CHOICES for a numeric id,
            mine_evolution ORDER); a target violation (a round opened in one registry is opened in every registry)
  gates     gate_id_duplicates (one G<n> used by two different gate titles in run_gates.py, lesson #68)
  classes   defect_classes_without_kat (every R24/R25 tooling defect class must name a KAT that exists, §0.9 rule 1)
  r28       round_lists_missing (harness/kit/roundlists.py: a registry round missing from areas.json rounds,
            gen_ledger LAST_CHOICES or mine_evolution ORDER, B149; target 0); steps_over_budget / project_wall_budget_s
            (harness/kit/stepbudget.py over the same record as project_wall_s, B133; report-only); privacy_writer_leaks
            (harness/intel/privacy_audit.py: a runtime family whose newest file, written in the last 72 h, carries a
            peer address, B135; target 0) and privacy_historical_files (report-only)
  resume    checkpoint_age_s: seconds since the round's resume checkpoint (harness/intel/round_checkpoint.py, §0.10;
            ~/derohe-persist/round_state/<round>_state.json 'stamp'; the --loop 600 writes one every 10 min)
  opt-in    --determinism: generator double runs byte-exact (gen_index, soundness, gen_deroarch build, r30 B232: the
            round-named ledger gen_ledger.py --last N artifacts/dero-r1-r<N>.html), in an
            isolated copy of the tree (r25 merge: it used to run in place). r28 (N28-09): a default run (no
            --determinism) reports determinism_last, the newest earlier record that DID measure it (its file, capture
            time, age and mismatch count), labelled as carried; determinism_mismatches itself stays 'pending';
            --scrub-control: pubscrub planted-secret control (false negatives must be 0; false positives counted);
            r28 (B122): --scrub-pages: the configured pubscrub over every artifacts/*.html into a temporary directory
            (the publish copies of §6 step 18, never the tree): scrub_page_residual (per page, the checks pubscrub's
            own final scan still finds and the leaked addresses; target 0), scrub_page_home_forms (a '~/' home form
            left in a publish copy, rft §5 privacy; target 0), scrub_page_vscode (editor links left, dead in a copy;
            report-only);
            --scripts: every repo-root *.sh passes `bash -n`, every tools/<go dir> builds (no live effect)

Privacy: no home path, user name, address or IP is written; the memory dir is shown as <memory> (r28: the record named
the agent tool's project directory, a tool-config path, rft §5; pubscrub's own placeholder is used instead).
The planted secrets of --scrub-control are built at run time in a temporary directory and never written to the tree.

  python3 -I harness/intel/tooling_intel.py [--memory-dir DIR] [--determinism] [--scrub-control] [--scripts] [--scrub-pages]
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
MEMORY_SHOWN = '<memory>'        # r28: pubscrub's placeholder (the tool's project-dir form is a tool-config path)
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


LEDGER_PAGE = '<ledger page of the current round>'   # r30 (B232): resolved per tree by ledger_cmd()


def ledger_cmd(root):
    """(command, page) of the round-named ledger page: the registry's current round number N gives
    artifacts/dero-r1-r<N>.html when it exists, else the newest dero-r1-r<M>.html of the tree (a round whose page is
    not written yet re-checks the last page); None when the tree has no ledger page. A sub-round (r28d) uses its
    number (r28 -> dero-r1-r28.html). Pure on the files."""
    root = Path(root)
    try:
        cur = json.loads((root / 'harness/round.json').read_text()).get('current') or ''
    except (OSError, ValueError):
        cur = ''
    m = re.fullmatch(r'r(\d+)[a-z]?', str(cur))
    pages = sorted((int(x.group(1)), x.group(0)) for x in
                   (re.fullmatch(r'dero-r1-r(\d+)\.html', p.name) for p in (root / 'artifacts').glob('dero-r1-r*.html')) if x)
    n = int(m.group(1)) if m and (root / f'artifacts/dero-r1-r{m.group(1)}.html').exists() else (pages[-1][0] if pages else None)
    if n is None:
        return None
    page = f'artifacts/dero-r1-r{n}.html'
    return ['artifacts/src/gen_ledger.py', '--last', str(n), page], page


GENERATORS = [            # (command, output page) for --determinism; each is run twice and the page hashed after each
    (['harness/gen_index.py'], 'artifacts/index.html'),
    (['harness/soundness.py'], SOUNDNESS_PAGE),   # r25: the current round's page (harness/kit/soundpage.py)
    (['harness/gen_deroarch.py', 'build'], 'artifacts/dero-src-arch.html'),
    # r30 (rft §7 B232): the round-named ledger page (gen_ledger.py --last N OUT) was never double-run; the r29 audit
    # found the check stale and the ledger outside it. Run once per round with --determinism (a scratch copy)
    (['artifacts/src/gen_ledger.py'], LEDGER_PAGE),
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
    # r26 (harness-tooling): the classes found at R25 measurement / R26 Part A
    ('a failed stage leaves its scratch behind (S5 shadow clone, B98)', 'harness/kat/test_harness_tooling_r26.py', 'HT1'),
    ('a paused track fails a clean checkout (miner_intel exit 2, B101)', 'harness/kat/test_harness_tooling_r26.py', 'HT2'),
    ('local-time string order across DST (log_intel, B101)', 'harness/kat/test_harness_tooling_r26.py', 'HT3'),
    ('generator not byte-exact on a double run (build time, stale index, B93)', 'harness/kat/test_harness_tooling_r26.py', 'HT4'),
    ('network observation booked as a node regression (B105)', 'harness/kat/test_harness_tooling_r26.py', 'HT5'),
    ('probe params not from the Go json tags (B104)', 'harness/kat/test_harness_tooling_r26.py', 'HT6'),
    ('an earlier round\'s anchor drifts for ever (B116)', 'harness/kat/test_harness_tooling_r26.py', 'HT7'),
    ('--help runs the tool (B117)', 'harness/kat/test_harness_tooling_r26.py', 'HT8'),
    ('a tracked snapshot keeps a raw command line (B119)', 'harness/kat/test_harness_tooling_r26.py', 'HT9'),
    # r27 (tools-kats): the classes found at the R26 measurement / R27 Part A
    ('--help runs the tool or raises (B120: 33 tools, gen_deroarch KeyError)', 'harness/kat/test_tools_kats_r27.py', 'TK1'),
    ('a build silently loses anchors of a stale raw file (43 consensus rows, R26)', 'harness/kat/test_tools_kats_r27.py', 'TK2'),
    ('a KAT coupled to out-of-repo state (HT12 called the real scrubber)', 'harness/kat/test_tools_kats_r27.py', 'TK3'),
    ('a recorded audit finding booked as a regression (B134)', 'harness/kat/test_tools_kats_r27.py', 'TK5'),
    ('a wait loop that matches itself (pgrep -f, R26 x3)', 'harness/kat/test_tools_kats_r27.py', 'TK6'),
    # r27b (resource hygiene, B148): the classes found while measuring the RAM / swap / file-event load
    ('a fan-out launched with no resource preflight (B148)', 'harness/kat/test_resource_hygiene_r27.py', 'RH3'),
    ('clone trees kept and mirrored for ever (scratch GC, B148)', 'harness/kat/test_resource_hygiene_r27.py', 'RH5'),
    ('a dry run that writes (git add -N empty blob, B148)', 'harness/kat/test_resource_hygiene_r27.py', 'RH5'),
    ('hardlinked pack mtime read as tree activity (B148)', 'harness/kat/test_resource_hygiene_r27.py', 'RH5'),
    ('backup mirrors reproducible clone trees (B148)', 'harness/kat/test_resource_hygiene_r27.py', 'RH7'),
    # r28 (tools-kats): the classes found at the R27 measurement / R28 Part A and while writing the R28 KATs
    ('a round opened in one registry but not in every round list (B149, lesson #80)', 'harness/kat/test_tools_kats_r28.py', 'TK17'),
    ('a KAT mutation anchored on a round literal goes stale at every round open (N28-01)', 'harness/kat/test_tools_kats_r28.py', 'TK18'),
    ('a process found by a command-line pattern (pgrep -f) instead of its exact name (N28-05)', 'harness/kat/test_tools_kats_r28.py', 'TK19'),
    ('a planned round booked as an item a miner could not anchor (evolution unverified 1)', 'harness/kat/test_tools_kats_r28.py', 'TK20'),
    ('a missing untracked input read as empty (corpus/tags.tsv)', 'harness/kat/test_tools_kats_r28.py', 'TK22'),
    ('a generator that exits 0 on an empty tool run (ctags first on PATH, prep_corpus)', 'harness/kat/test_miners_r28.py', 'MK8'),
    ('a KAT coupled through state another KAT wrote (raw files, MK3 -> MK7)', 'harness/kat/test_miners_r28.py',
     'MK3 -> MK7 coupling'),
    ('a per-item subprocess fan-out (201 recursive greps in mine_coverage: 125 s -> 1.2 s)', 'harness/kat/test_miners_r28.py',
     'callers_equal_grep'),
    # r28 (artifacts-memory): the classes found at the R27 verification / R28 Part A
    ('a privacy shape matched in one spelling only (box-proc, N28-06)', 'harness/kat/test_artifacts_memory_r28.py', 'AM8'),
    ('a publish copy measured only on the planted control, never on the pages (B122; ~/ home forms)', 'harness/kat/test_artifacts_memory_r28.py', 'AM9'),
    ('a memory names a file, flag or function the tree lacks (B140)', 'harness/kat/test_artifacts_memory_r28.py', 'AM10'),
    ('one count stated in two documents drifts (rft §10 lesson range, B140)', 'harness/kat/test_artifacts_memory_r28.py', 'AM11'),
    ('a freshness rule bound to one file name (the miner skill, B92)', 'harness/kat/test_artifacts_memory_r28.py', 'AM12'),
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
    # r28 (N28-06): the box's process census, case-insensitive. The export check matches one mixed-case spelling only, so
    # the lower-case daemon name in a memory reached the in-repo mirror (R27 verifier advisory). Built from parts, so
    # this published file carries none of the names.
    ('box-proc', re.compile('(?i)(?<![\\w-])(?:' + '|'.join(['window' + 'server', 'fs' + 'events' + 'd?', 'activity' + r'\s+' + 'monitor',
                                                         'code' + r'\s+' + 'helper', 'mds' + '_stores', 'md' + r'worker\w*'])
                            + ')(?![\\w-])')),
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
KAT_COUPLED_RX = re.compile(r'mutations coupled (\d+)\b')       # r27: harness/kit/katmut.py summary


def kat_coupled(lines):
    """the sum of 'mutations coupled N' over KAT summary lines, or None when no line carries one (not measured). Pure."""
    hits = [int(m.group(1)) for l in lines for m in KAT_COUPLED_RX.finditer(str(l))]
    return sum(hits) if hits else None
# r27 (harness-measure): the seven forensics KATs (test_forensics_r25/_r26/_g30_r25/_bounds_r26/_classes_r26/_audit2_r26/
# _frontend2_r26) end with 'mutations caught X/Y', so their mutations were never in kat_mutations_total (652/652 in
# the r26 record). The literal 'mutations caught X/Y' counts too; still no other number pair.
KAT_MUT_RX = re.compile(r'mutations (?:proved|caught) (\d+)\s*/\s*(\d+)')


def kat_mutations(lines):
    """(proved, total) summed over KAT summary lines. Only the literal 'mutations proved X/Y' (r27: or 'mutations caught
    X/Y') counts: a line such as
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
    c = kat_coupled(lines)
    k['kat_mutations_coupled'] = PENDING if c is None else c
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


# r27 (memory control): the index line of a numbered-lessons file states the range it covers; R27 Part A found the index
# at '#1–#77' while the file had reached #79 (and the rft §10 header a third count). A numbered entry is a line that starts
# with '#<N>' (optionally bold); the stated bound is the largest upper end of the '#a–#b' ranges on the index line (a
# line may also quote a sub-range such as '#72–77').
RANGE_RX = re.compile(r'#(\d+)\s*[–-]\s*#?(\d+)')
ENTRY_RX = re.compile(r'^\s*(?:[-*]\s*)?(?:\*\*)?#(\d+)\b', re.M)


def index_ranges(mdir):
    """[(file, stated upper bound, highest numbered entry)] for every index line whose linked file has numbered entries
    and whose stated range ends below or above the file's highest entry. Pure over the directory."""
    mdir = Path(mdir)
    try:
        text = (mdir / 'MEMORY.md').read_text(encoding='utf-8')
    except OSError:
        return PENDING
    out = []
    for l in text.splitlines():
        links = LINK_RX.findall(l)
        rng = RANGE_RX.findall(l)
        if not links or not rng:
            continue
        stated = max(int(b) for _a, b in rng)
        try:
            nums = [int(x) for x in ENTRY_RX.findall((mdir / links[0]).read_text(encoding='utf-8', errors='replace'))]
        except OSError:
            continue
        if nums and max(nums) != stated:
            out.append((links[0], stated, max(nums)))
    return out


# r27 (memory control): a memory that names a repo file must still resolve. Only a token that starts with a top-level
# directory of the tree and ends in a file name with an extension counts (prose such as 'block/s' or 'artifacts/GitHub'
# does not); a token with a placeholder ('<', '*', '{') is a pattern, not a file. Measured at R27: dero-r24-round.md
# names harness/runtime/r24_live_first/hour_20261102.txt, which never existed (the records are r24_live_first_ and
# r24_live_hour_20261102.txt).
# r28 Part D (B172): the lookahead also refuses '-': 'bin/derod.round5-backup' (an existing file) was read as
# 'bin/derod.round5' and reported dead (dero-network-changes.md, dero-r25-round.md: 3 of the 6 memory_dead_refs of
# 2026-11-06 05:00 were this misread).
REF_RX = re.compile(r'(?<![\w/~.<-])((?:[A-Za-z_][\w.-]*/)+[\w-][\w.-]*\.[A-Za-z]\w{0,5})(?![\w/<*{-])')


def dead_refs(mdir, root):
    """['<memory file>: <path>'] every repo path (REF_RX, first component a top-level directory of `root`) a memory file
    names that `root` does not have. Pure over the two directories."""
    root, mdir = Path(root), Path(mdir)
    if not mdir.is_dir():
        return PENDING
    tops = {p.name for p in root.iterdir() if p.is_dir() and not p.name.startswith('.')}
    out = []
    for p in sorted(mdir.glob('*.md')):
        try:
            t = p.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        for m in sorted(set(REF_RX.findall(t))):
            if m.split('/')[0] in tops and not (root / m).exists():
                out.append(f'{p.name}: {m}')
    return out


# r28 (B140, "extend the KPI to function/flag names"): dead_refs reads only paths that start with a top-level directory, so
# a bare file name ('txn_exec.go:131' in dero-miner-changes.md; the code is blockchain/transaction_execute.go:133) and a
# flag or function written next to a tool resolved nothing. dead_names reads every bare code-file name; dead_symbols the
# `--flag` / `func()` tokens written after a resolved code file inside one `code span` (the span is the command; a flag
# elsewhere on the line belongs to another tool: the line-level reading gave 25 false hits on the memory of 2026-11-06,
# the span reading 0: 95 code-span references resolve to one file, 6 of them carry a flag/func() token). Out-of-repo
# tools (TOOL_PATHS.json and OUT_OF_REPO_NAMES) are not dead.
CODE_NAME_RX = re.compile(r'(?<![\w/~.<$-])((?:[A-Za-z_][\w.-]*/)*[A-Za-z_][\w.-]*\.(?:py|go|sh))(?![\w/<*{])')
CODE_EXT = ('.py', '.go', '.sh')
OUT_OF_REPO_NAMES = ('backup_scratch.sh',)      # ~/derohe-persist/backup_scratch.sh (rft §0.9 scope, §2.4)
SPAN_RX = re.compile(r'`([^`\n]+)`')
FLAG_RX = re.compile(r'(?<![\w-])(--[a-z][a-z0-9]*(?:-[a-z0-9]+)*)(?![\w-])')
SYM_RX = re.compile(r'(?:[:.]|\s)([A-Za-z_]\w*)\(\)')


def tracked_files(root):
    """the tree's tracked paths (git ls-files), else every file under `root` (.git aside). Sorted posix paths."""
    r = subprocess.run(['git', '-C', str(root), 'ls-files'], capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        return sorted(r.stdout.split('\n')[:-1] if r.stdout.endswith('\n') else r.stdout.split('\n'))
    return sorted(p.relative_to(root).as_posix() for p in Path(root).rglob('*') if p.is_file() and '.git' not in p.parts)


def out_of_repo_names(root):
    """the file names of the out-of-repo tools: the basenames of TOOL_PATHS.json and OUT_OF_REPO_NAMES. Static."""
    try:
        cfg = json.loads((Path(root) / TOOL_PATHS).read_text())
    except (OSError, ValueError):
        cfg = {}
    return {Path(v).name for k, v in cfg.items() if not k.startswith('_') and isinstance(v, str)} | set(OUT_OF_REPO_NAMES)


def code_tokens(text):
    """the code-file names a text names; 'a.go/b.go' (two files written as one token) yields both. Pure."""
    out = []
    for tok in CODE_NAME_RX.findall(text):
        parts = tok.split('/')
        if any(x.endswith(CODE_EXT) for x in parts[:-1]):
            out += [x for x in parts if x.endswith(CODE_EXT)]
        else:
            out.append(tok)
    return out


def resolve_name(tok, files):
    """the tracked paths a code-file token names: itself, or every path that ends with '/<tok>'. Pure."""
    return [f for f in files if f == tok or f.endswith('/' + tok)]


def dead_names(mdir, root, files=None, outside=None):
    """['<memory file>: <name>'] every code-file name (bare or with directories) a memory names that no tracked file
    ends with. Pure over the inputs when `files` and `outside` are given."""
    mdir = Path(mdir)
    if not mdir.is_dir():
        return PENDING
    files = tracked_files(root) if files is None else files
    outside = out_of_repo_names(root) if outside is None else set(outside)
    out = []
    for p in sorted(mdir.glob('*.md')):
        t = p.read_text(encoding='utf-8', errors='replace')
        for tok in sorted(set(code_tokens(t))):
            if tok.split('/')[-1] in outside or resolve_name(tok, files):
                continue
            out.append(f'{p.name}: {tok}')
    return out


def dead_symbols(mdir, root, files=None):
    """['<memory file>:<line>: <path> <token>'] a --flag or func() written after a code file inside one `code span`
    that the file's source does not contain (a flag) or define (def / func / method). A token is read against the one
    file it follows (the next code file in the span starts its own command). Pure over the directories."""
    mdir, root = Path(mdir), Path(root)
    if not mdir.is_dir():
        return PENDING
    files = tracked_files(root) if files is None else files
    out = []
    for p in sorted(mdir.glob('*.md')):
        for i, l in enumerate(p.read_text(encoding='utf-8', errors='replace').splitlines(), 1):
            for span in SPAN_RX.findall(l):
                ms = list(CODE_NAME_RX.finditer(span))
                for j, m in enumerate(ms):
                    hit = resolve_name(m.group(1), files)
                    if len(hit) != 1:
                        continue                      # unresolved (dead_names) or ambiguous: no owner to read
                    try:
                        src = (root / hit[0]).read_text(encoding='utf-8', errors='replace')
                    except OSError:
                        continue
                    end = ms[j + 1].start() if j + 1 < len(ms) else len(span)
                    tail = re.split(r'[;|&]', span[m.end():end])[0]
                    for f in sorted(set(FLAG_RX.findall(tail))):
                        if f not in src:
                            out.append(f'{p.name}:{i}: {hit[0]} {f}')
                    for s in sorted(set(SYM_RX.findall(' ' + tail))):
                        if not re.search(r'(?:def|func(?:\s*\([^)]*\))?)\s+' + re.escape(s) + r'\s*[\[(]', src):
                            out.append(f'{p.name}:{i}: {hit[0]} {s}()')
    return out


LESSONS_FILE = 'session-reasoning-patterns.md'


def rft_lesson_ranges(root, mdir, lessons=LESSONS_FILE):
    """r28: [(rft line number, stated upper bound, the lessons file's highest '#N')] for every line of
    artifacts/dero-rft.md that names the lessons file (its stem) and a '#a–#b' range whose largest upper end differs
    from the file's highest numbered entry (the memory index is index_ranges'). 'pending' without either file. Pure over
    the two files."""
    try:
        rft = (Path(root) / 'artifacts/dero-rft.md').read_text(encoding='utf-8', errors='replace')
        nums = [int(x) for x in ENTRY_RX.findall((Path(mdir) / lessons).read_text(encoding='utf-8', errors='replace'))]
    except OSError:
        return PENDING
    if not nums:
        return PENDING
    stem, top, out = lessons[:-3], max(nums), []
    for i, l in enumerate(rft.splitlines(), 1):
        if stem not in l:
            continue
        rng = RANGE_RX.findall(l)
        if rng and max(int(b) for _a, b in rng) != top:
            out.append((i, max(int(b) for _a, b in rng), top))
    return out


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


# r26 B92: each skill has a size budget (§0.9 rule 2 'skills'), and a skill may name the track it serves with a line
# `**Track:** <name>` in its first 12 lines. A skill of a PAUSED track (harness/round.json rounds[current].tracks) is not
# required to record the current round (reported 'PAUSED'); every other skill is, and at least one must be: when
# every skill serves a paused track, the round is recorded nowhere and skill_fresh is 0.
SKILL_MAX_LINES = 1200
TRACK_LINE_RX = re.compile(r'^\*\*Track:\*\*\s*([a-z][\w-]*)', re.M)


def skill_track(text):
    """the track a skill declares in its head, or None (a skill without one serves the round). Pure."""
    m = TRACK_LINE_RX.search('\n'.join(text.splitlines()[:12]))
    return m.group(1) if m else None


def round_open_grace(registry, current):
    """r30 (rft §7 B204): the previous round id while the current round is OPEN (status in-progress or planned and no
    merge_commit yet), else None. At round open no skill can hold the new round's entry (it is written at Part D), so a
    skill whose last entry is the round just before is DUE, not stale; one last recorded earlier (a resumed track's
    skill, e.g. the miner skill at r23c when R30 opened after r29) is still stale. Pure."""
    rounds = [r for r in (registry or {}).get('rounds') or [] if isinstance(r, dict)]
    ids = [r.get('id') for r in rounds]
    if current not in ids:
        return None
    r = rounds[ids.index(current)]
    if r.get('status') not in ('in-progress', 'planned') or str(r.get('merge_commit') or 'pending') != 'pending':
        return None
    prev = [x.get('id') for x in rounds[:ids.index(current)] if x.get('status') != 'planned']
    return prev[-1] if prev else None


def skill_kpis(root, current, paused=(), grace=None):
    """skill KPIs; `grace` (round_open_grace) = the previous round, whose entry counts as DUE (not stale) at round
    open (r30 B204)."""
    sk = sorted((Path(root) / '.skills').glob('*/SKILL.md'))
    if not sk:
        return {'skills': 0, 'skill_last_round': PENDING}
    out = {'skills': len(sk), 'skill_lines': {}, 'skill_last_round': {}, 'skill_over_budget': [], 'skill_paused': [],
           'skill_due': [], 'skill_grace': grace or None}
    fresh, required = True, 0
    for p in sk:
        t = p.read_text(encoding='utf-8', errors='replace')
        rounds = ROUND_HEAD_RX.findall(t)
        last = ('r' + rounds[-1]) if rounds else None
        name = p.parent.name
        out['skill_lines'][name] = len(t.splitlines())
        out['skill_last_round'][name] = last or PENDING
        if len(t.splitlines()) > SKILL_MAX_LINES:
            out['skill_over_budget'].append(name)
        if skill_track(t) in set(paused):
            out['skill_paused'].append(name)
            continue
        required += 1
        if last and grace and last.lower() == str(grace).lower() and last.lower() != str(current).lower():
            out['skill_due'].append(name)              # r30 B204: due at Part D, not stale at round open
            continue
        fresh &= bool(last) and last.lower() == str(current).lower()
    out['skill_fresh'] = int(fresh and required > 0)
    return out


HELP_RX = re.compile(r'ArgumentParser\(|[\'"]--help[\'"]|[\'"]-h[\'"]')
MAIN_RX = re.compile(r'^if __name__ == [\'"]__main__[\'"]', re.M)


PIN_RX = re.compile(r'"((?:harness|tools|glue)/[^"\s:]+)')


def content_pinned(root):
    """r27: the repo files a committed forensic dataset pins by content (forensics/r<N>/manifest.json: replay tools,
    cited files). Their bytes cannot change without a new dataset version (G28, rft §0.8.8): adding a --help guard to
    harness/forensics/pins.py failed test_forensics_r25 MF1/MF12 ('pinned tool changed'). Static."""
    out = set()
    for m in sorted(Path(root).glob('forensics/*/manifest.json')):
        try:
            text = m.read_text(errors='replace')
        except OSError:
            continue
        out |= set(PIN_RX.findall(text))
        # r28 (glue-global, B147): the regex sees only harness/, tools/ and glue/ paths, so the 484 decoder inputs
        # (globals/globals.go among them: the R27 glue-global fix to it failed MF12 at the merge) and the files of
        # cited lines outside those trees (block/block.go:120-120) were not listed. Every key of a content_pins
        # section is a pinned repo path (a 'path:lines' citation pins its file).
        try:
            pins = (json.loads(text).get('content_pins') or {})
        except ValueError:
            continue
        for sec in pins.values():
            if isinstance(sec, dict):
                out |= {str(k).split(':', 1)[0] for k in sec}
    return out


def tools_without_help(root, pinned=None):
    """r26 (B117 class, report-only): the harness tools (a __main__ entry; KAT files aside) whose source has no
    argument parser and no explicit --help branch, so `--help` RUNS them (tooling_intel and mine_triage were two of
    them). Static: nothing is executed. Sorted repo-relative paths. r27: a content-pinned tool (content_pinned) is not
    listed here: it is reported apart (tools_without_help_pinned), since its bytes wait for the next dataset version."""
    pinned = content_pinned(root) if pinned is None else pinned
    out = []
    for p in sorted((Path(root) / 'harness').rglob('*.py')):
        rel = p.relative_to(root).as_posix()
        if rel.startswith('harness/kat/') or '__pycache__' in p.parts or rel in pinned:
            continue
        t = p.read_text(encoding='utf-8', errors='replace')
        if MAIN_RX.search(t) and not HELP_RX.search(t):
            out.append(rel)
    return out


def harness_tools(root):
    """repo-relative paths of the harness tools: a __main__ entry, KAT files and __pycache__ aside. Static."""
    out = []
    for p in sorted((Path(root) / 'harness').rglob('*.py')):
        rel = p.relative_to(root).as_posix()
        if rel.startswith('harness/kat/') or '__pycache__' in p.parts:
            continue
        if MAIN_RX.search(p.read_text(encoding='utf-8', errors='replace')):
            out.append(rel)
    return out


def kat_coverage(root):
    """r27 (tools-kats): the KAT coverage map. A tool is covered when a harness/kat/*.py names its file (its path, or
    its file name as a quoted literal or a path segment: `HARNESS / 'intel' / 'x.py'`, 'intel/x.py'). Static: nothing
    is run. {tools_total, tools_with_kat, tools_without_kat, kat_coverage_pct, kat_map {tool: [kat files]}}."""
    kats = {p.name: p.read_text(encoding='utf-8', errors='replace') for p in sorted((Path(root) / 'harness/kat').glob('*.py'))}
    tools = harness_tools(root)
    cmap, missing = {}, []
    for rel in tools:
        name = rel.rsplit('/', 1)[-1]
        sub = rel[len('harness/'):]
        rx = re.compile(r'''(?<![\w.-])(?:%s|%s)['"]''' % (re.escape(name), re.escape(sub)))
        hit = sorted(k for k, txt in kats.items() if rx.search(txt) or rel in txt)
        cmap[rel] = hit
        if not hit:
            missing.append(rel)
    n = len(tools)
    return {'tools_total': n, 'tools_with_kat': n - len(missing), 'tools_without_kat': missing,
            'kat_coverage_pct': round(100.0 * (n - len(missing)) / n, 1) if n else PENDING, 'kat_map': cmap}


def paused_tracks(registry, current):
    """the tracks the registry marks 'paused' for the current round (kit/roundtracks semantics). Pure."""
    r = next((x for x in (registry or {}).get('rounds') or [] if x.get('id') == current), {})
    tr = r.get('tracks') if isinstance(r.get('tracks'), dict) else {}
    return sorted(k for k, v in tr.items() if v == 'paused')


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


def ledger_choices(root):
    """gen_ledger.LAST_CHOICES, from its own 'LAST_CHOICES = (...)' line, or None when it cannot be read. Static."""
    try:
        src = (Path(root) / 'artifacts/src/gen_ledger.py').read_text()
    except OSError:
        return None
    m = re.search(r'^LAST_CHOICES = \(([\d,\s]+)\)', src, re.M)
    return tuple(int(x) for x in re.findall(r'\d+', m.group(1))) if m else None


def round_list_gaps(registry, areas_rounds, choices, order):
    """r29 (B166): ONE implementation. The lines of harness/kit/roundlists.problems (the one round-list reader, KAT
    HS1) over the given lists; a list that could not be read is None and its lines are skipped (reported as pending
    by the caller). Until r29 this was a second copy of the B149 rule (r28 TK17), with its own line format."""
    rounds = (registry or {}).get('rounds') or []
    if not rounds:
        return []
    RL = _kit(Path(__file__).resolve().parent.parent.parent, 'kit/roundlists.py', 'roundlists')
    if RL is None:
        return []
    L = {'registry': [str(r.get('id', '')) for r in rounds], 'current': registry.get('current'),
         'planned': [str(r.get('id', '')) for r in rounds if r.get('status') == 'planned'],
         'areas': list(areas_rounds or []), 'ledger': list(choices or []), 'evolution': list(order or [])}
    skip = {name for name, x in (('areas', areas_rounds), ('ledger', choices), ('evolution', order)) if x is None}
    return [p for p in RL.problems(L) if p.split(':', 1)[0] not in skip]


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
            elif page == LEDGER_PAGE:
                lc = ledger_cmd(work)
                if lc is None:
                    out[LEDGER_PAGE] = 'FAILED no ledger page'
                    continue
                cmd, page = lc
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


def determinism_last(runtime_dir, at=None):
    """r28 (N28-09): the newest tooling_<ts>.json under runtime_dir whose determinism map is non-empty (a run with
    --determinism), as {file, captured, age_s, mismatches, result}, or 'pending' when no record measured it. A default
    run carries this beside determinism_mismatches 'pending': the carried value is labelled with its file and age and
    is never booked as this run's reading. Pure on the files."""
    for p in sorted(Path(runtime_dir).glob('tooling_2*.json'), reverse=True):
        try:
            rec = json.loads(p.read_text())
        except (OSError, ValueError):
            continue
        det = (rec.get('kpis') or {}).get('determinism')
        if not isinstance(det, dict) or not det:
            continue
        age = PENDING
        try:
            t = datetime.datetime.fromisoformat(rec.get('captured'))
            age = max(0, int(((at or datetime.datetime.now(datetime.timezone.utc)) - t).total_seconds()))
        except (TypeError, ValueError):
            pass
        return {'file': f'harness/runtime/{p.name}', 'captured': rec.get('captured', PENDING), 'age_s': age,
                'mismatches': sum(1 for x in det.values() if x != 'byte-exact'), 'result': det}
    return PENDING


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


# r26 B131: the machine-model and agent-tool-path shapes the R26 publish had to scrub by hand (built from parts, so the
# tree never carries the literal strings): the box model, the R1 row's quoted claim, the node tag in lower case, the
# memory-link directory and the two session settings files. r27 (tools-kats): a module constant, so the KAT reads the
# shapes without the out-of-repo rule table (HT12 used to fail for every tooling_intel mutation: the mutant's ROOT
# had no TOOL_PATHS.json, so scrub_plants() returned None: KAT coupling [HT8,HT12], [HT10,HT12]).
MODEL_TOOL_PLANTS = ['M1' + '-Ultra', '"M1 hard' + 'ware ceiling"', 'm1' + 'ultra', '~/.' + 'claude/' + 'projects/x/memory/',
                     '.' + 'claude/settings.json', '.' + 'claude/settings.local.json']


# r28: a home-relative path is a home path in a publish copy (rft §5 privacy, 'also ~/ forms in published copies'); the
# R27 scrubber turns '<home>/x' into '~/x' and keeps it (tooling_intel --scrub-pages: 4 '~/' forms in 2 of 15 copies at
# R28). Synthetic: no real directory name.
HOME_FORM_PLANTS = ['~/' + 'planted-home-dir/notes.txt']


def scrub_plants(root=ROOT):
    """synthetic planted secrets in the shapes the scrubber must remove, built at run time from the scrubber's own rule
    table and the home directory (never written to the tree): a home path, an e-mail, a LAN address, the wallet prefix
    with a synthetic tail, a mapped peer address; from r26 (B131) the machine-model and agent-tool-path shapes.
    None when `root` names no readable rule table (harness/loop/TOOL_PATHS.json 'sync_rules')."""
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
        plants += MODEL_TOOL_PLANTS                                       # r26 B131
        plants += HOME_FORM_PLANTS                                        # r28: '~/' forms (rft §5 privacy)
    except (OSError, AttributeError):
        return None
    return plants


CLEAN_CONTROL = ('the node listens on 127.0.0.1:10102 and 0.0.0.0:11011\n'
                 'a documentation address 203.0.113.10 and a resolver 8.8.8.8\n'
                 'the home directory is written ~ in every page\n'
                 'topoheight 7,498,540 is the prune point\n'
                 'gate G27 scans the whole page\n'
                 'R1 and M1 are labels; Pro, Max and Ultra are plain words; the hardware is not named\n'   # r26 B131 near-misses
                 'harness/loop/TOOL_PATHS.json and a settings.json are not tool paths\n')


def scrub_control(root=ROOT, tool=None):
    """the planted-secret control of the scrubber `tool` (default: the configured pubscrub of `root`). r27: `root` and
    `tool` are parameters, so the KAT runs it on a forged rule table and forged scrubbers (perfect, leaky, over-eager)
    and the out-of-repo scrubber is measured only by `--scrub-control` (§13), never inside a KAT."""
    tool = Path(tool) if tool is not None else tool_path('pubscrub', root)
    plants = scrub_plants(root)
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


HOME_FORM_RX = re.compile(r'(?<![\w/.~-])~/[A-Za-z0-9._-]+')
VSCODE_RX = re.compile(r'vscode://')
RESIDUAL_LINE_RX = re.compile(r'^(\S+) \d+ rules \[.*?\] residual (\{.*?\}) ips (.*)$')


def page_residual(stdout):
    """{page file name: {check: count, 'ip': n}} from pubscrub's per-file report lines (the format sync_mirror reads);
    {} for a report without lines. Pure."""
    import ast
    out = {}
    for l in stdout.splitlines():
        m = RESIDUAL_LINE_RX.match(l.strip())
        if not m:
            continue
        try:
            found, ips = dict(ast.literal_eval(m.group(2))), ast.literal_eval(m.group(3))
        except (ValueError, SyntaxError):
            found, ips = {'unparsed': 1}, []
        if isinstance(ips, (list, tuple)) and ips:
            found['ip'] = len(ips)
        out[os.path.basename(m.group(1))] = found
    return out


def scrub_pages(root=ROOT, tool=None, pages=None):
    """r28 (B122): the publish copies of every artifacts/*.html (§6 step 18), made by the scrubber `tool` (default: the
    configured pubscrub of `root`) into a temporary directory, then read: the residual pubscrub's own final scan
    reports per page, the '~/' home forms and the editor links left in each copy. The tree is never written.
    {scrub_pages_total, scrub_page_residual {page: found} (pages with a residual only), scrub_page_home_forms
    {page: n}, scrub_page_vscode {page: n}, scrub_pages_rc}; 'pending' without the scrubber or a report line."""
    tool = tool_path('pubscrub', root) if tool is None else Path(tool)
    pages = sorted((Path(root) / 'artifacts').glob('*.html')) if pages is None else [Path(x) for x in pages]
    if tool is None or not tool.exists():
        return {'scrub_page_residual': PENDING, 'why': 'pubscrub.py not on this machine'}
    if not pages:
        return {'scrub_page_residual': PENDING, 'why': 'no artifacts pages'}
    with tempfile.TemporaryDirectory(prefix='r28pages-') as d:
        r = subprocess.run(['nice', '-n', '15', sys.executable, '-I', str(tool), d, *[str(p) for p in pages]],
                           capture_output=True, text=True, timeout=1800)
        res = page_residual(r.stdout)
        home, vs = {}, {}
        for p in pages:
            try:
                t = (Path(d) / p.name).read_text(encoding='utf-8', errors='replace')
            except OSError:
                res.setdefault(p.name, {'no copy': 1})
                continue
            if HOME_FORM_RX.search(t):
                home[p.name] = len(HOME_FORM_RX.findall(t))
            if VSCODE_RX.search(t):
                vs[p.name] = len(VSCODE_RX.findall(t))
    if not res:
        return {'scrub_page_residual': PENDING, 'why': f'pubscrub printed no report line (rc {r.returncode})'}
    missing = sorted(p.name for p in pages if p.name not in res)
    left = {n: f for n, f in sorted(res.items()) if f}
    left.update({n: {'unreported': 1} for n in missing})
    return {'scrub_pages_total': len(pages), 'scrub_page_residual': left, 'scrub_page_home_forms': home,
            'scrub_page_vscode': vs, 'scrub_pages_rc': r.returncode}


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
    if isinstance(k.get('tools_without_kat'), list) and k['tools_without_kat']:
        v.append(f"harness tools without a KAT {k['tools_without_kat'][:6]} (target 0 from R28, N28-04)")
    if k.get('gate_id_duplicates'):
        v.append(f"gate ids used by two gates {k['gate_id_duplicates']}")
    if isinstance(k.get('flaky'), int) and k['flaky']:
        v.append(f"flaky tests {k['flaky']} (target 0)")
    if isinstance(k.get('kat_mutations_coupled'), int) and k['kat_mutations_coupled']:
        v.append(f"KAT mutations coupled {k['kat_mutations_coupled']} (a mutation also fails a KAT of another defect; target 0)")
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
    if isinstance(k.get('memory_index_ranges'), list) and k['memory_index_ranges']:
        v.append(f"memory index ranges differ from their files {k['memory_index_ranges']}")
    if isinstance(k.get('memory_dead_refs'), list) and k['memory_dead_refs']:
        v.append(f"memory files name repo paths that do not exist {k['memory_dead_refs'][:5]}")
    if isinstance(k.get('memory_dead_names'), list) and k['memory_dead_names']:
        v.append(f"memory files name code files the tree does not have {k['memory_dead_names'][:5]}")
    if isinstance(k.get('memory_dead_symbols'), list) and k['memory_dead_symbols']:
        v.append(f"memory files name flags/functions their tool lacks {k['memory_dead_symbols'][:5]}")
    if isinstance(k.get('rft_lesson_ranges'), list) and k['rft_lesson_ranges']:
        v.append(f"dero-rft.md states a lesson range the lessons file does not end at {k['rft_lesson_ranges']}")
    if isinstance(k.get('scrub_page_residual'), dict) and k['scrub_page_residual']:
        v.append(f"publish copies keep a scrub residual {k['scrub_page_residual']}")
    if isinstance(k.get('scrub_page_home_forms'), dict) and k['scrub_page_home_forms']:
        v.append(f"publish copies keep '~/' home forms {k['scrub_page_home_forms']} (rft §5 privacy)")
    if k.get('skill_fresh') == 0:
        v.append(f"skill not recorded for the current round {k.get('skill_last_round')}"
                 + (f" (paused-track skills {k['skill_paused']})" if k.get('skill_paused') else ''))
    if k.get('skill_over_budget'):
        v.append(f"skills over {SKILL_MAX_LINES} lines {k['skill_over_budget']}")
    if k.get('scripts_bad'):
        v.append(f"scripts that do not build {k['scripts_bad']}")
    # r29 B166: round_list_gaps had a second target for the same lines; this is the one
    if isinstance(k.get('round_lists_missing'), list) and k['round_lists_missing']:
        v.append(f"round lists miss a registry round {k['round_lists_missing'][:4]} (B149)")
    if isinstance(k.get('privacy_writer_leaks'), int) and k['privacy_writer_leaks']:
        v.append(f"a current runtime writer stores peer addresses: {k['privacy_writer_leaks']} family(ies) (B135)")
    return v


def _kit(root, rel, name):
    """r28: a module of THIS tree's harness (kit/roundlists.py, kit/stepbudget.py, intel/privacy_audit.py), or None."""
    import importlib.util
    try:
        spec = importlib.util.spec_from_file_location(f'{name}_for_tooling_{id(root)}', Path(root) / 'harness' / rel)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    except (OSError, ImportError, SyntaxError):
        return None


def r28_kpis(root):
    """r28 KPIs: round lists (B149), step budgets of the newest S7 record (B133), runtime privacy (B135). Each is
    'pending' when its module or input is missing."""
    root = Path(root)
    k = {}
    RL = _kit(root, 'kit/roundlists.py', 'roundlists')
    try:
        k['round_lists_missing'] = RL.check(root) if RL else PENDING
    except (OSError, ValueError, SyntaxError, KeyError):
        k['round_lists_missing'] = PENDING
    SB = _kit(root, 'kit/stepbudget.py', 'stepbudget')
    recs = sorted((root / 'harness/loop/runs').glob('pipeline_*.jsonl'))
    k['steps_over_budget'] = k['project_wall_budget_s'] = PENDING
    if SB:
        for p in reversed(recs):
            ev = read_jsonl(p)
            if any(o.get('stage') == 'project' and o.get('status') in ('PASS', 'FAIL') for o in ev):
                try:
                    r = SB.report(ev, SB.load(root))
                except (OSError, ValueError):
                    break
                k['steps_over_budget'] = r['over']
                k['steps_over_budget_count'] = len(r['over'])
                k['project_wall_budget_s'] = r['wall_budget_s']
                k['project_wall_over_budget'] = r['wall_over']
                break
    PA = _kit(root, 'intel/privacy_audit.py', 'privacy_audit')
    k['privacy_writer_leaks'] = k['privacy_historical_files'] = PENDING
    if PA:
        try:
            allowed = PA.privkit.code_literal_ips(root)
            cls = PA.classify(PA.scan(root, PA.tracked(root), allowed), datetime.datetime.now())
            k['privacy_writer_leaks'] = sum(1 for c, _ in cls.values() if c == 'writer')
            k['privacy_historical_files'] = sum(1 for c, _ in cls.values() if c == 'historical')
            k['privacy_static_files'] = sorted(r for r, (c, _) in cls.items() if c == 'static')[:20]
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    return k


def run(root, mdir, opt_det=False, opt_scrub=False, opt_scripts=False, opt_pages=False):
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
    k['memory_index_ranges'] = index_ranges(mdir)
    k['memory_dead_refs'] = dead_refs(mdir, root)
    files = tracked_files(root)                                  # r28 (B140)
    k['memory_dead_names'] = dead_names(mdir, root, files)
    k['memory_dead_symbols'] = dead_symbols(mdir, root, files)
    k['rft_lesson_ranges'] = rft_lesson_ranges(root, mdir)
    if Path(mdir).is_dir():
        n, why = mirror_drift(mdir, root / MIRROR)
        k['mirror_drift'], k['mirror_drift_reasons'] = n, why[:60]
    else:
        k['mirror_drift'] = PENDING
    k.update(skill_kpis(root, cur, paused_tracks(registry, cur), round_open_grace(registry, cur)))
    order = evolution_order(root)
    if order is None:
        k['order_gaps'] = PENDING
    else:
        k['order_gaps'], k['order_next_missing'] = order_gaps(registry, order)
    try:
        areas_rounds = [r.get('id') for r in json.loads((root / 'harness/areas.json').read_text()).get('rounds', [])]
    except (OSError, ValueError):
        areas_rounds = None
    choices = ledger_choices(root)
    if areas_rounds is None and choices is None and order is None:
        k['round_list_gaps'] = PENDING
    else:
        k['round_list_gaps'] = round_list_gaps(registry, areas_rounds, choices, order)
        k['round_lists_read'] = [n for n, x in (('areas.json rounds', areas_rounds), ('LAST_CHOICES', choices),
                                                ('ORDER', order)) if x is not None]
    try:
        k['gate_id_duplicates'] = duplicate_gate_ids((root / 'harness/run_gates.py').read_text())
    except OSError:
        k['gate_id_duplicates'] = PENDING
    k['checkpoint_age_s'] = checkpoint_age(checkpoint_dir(), cur)
    k.update(r28_kpis(root))                                     # r28: B149 round lists, B133 budgets, B135 privacy
    k['tools_without_help'] = tools_without_help(root)          # report-only (no §0.9 target yet)
    k['tools_without_help_count'] = len(k['tools_without_help'])
    k['tools_without_help_pinned'] = sorted(set(tools_without_help(root, pinned=set())) - set(k['tools_without_help']))
    cov = kat_coverage(root)                                     # r28: a rule-2 target (tools_without_kat 0)
    k.update({x: cov[x] for x in ('tools_total', 'tools_with_kat', 'tools_without_kat', 'kat_coverage_pct')})
    k['tools_without_kat_count'] = len(cov['tools_without_kat'])
    k['defect_classes'] = len(DEFECT_CLASSES)
    k['defect_classes_without_kat'] = classes_without_kat(root)
    k['determinism'] = determinism(root) if opt_det else {}
    if opt_scrub:
        k.update(scrub_control())
    if opt_pages:
        k.update(scrub_pages(root))
    if opt_scripts:
        k.update(scripts(root))
    k['determinism_mismatches'] = sum(1 for x in k['determinism'].values() if x != 'byte-exact') if opt_det else PENDING
    if not opt_det:
        k['determinism_last'] = determinism_last(root / 'harness/runtime')       # r28 (N28-09): carried, labelled
    if isinstance(k.get('gate_id_duplicates'), dict):
        k['gate_id_duplicate_count'] = len(k['gate_id_duplicates'])
    for key in ('memory_index_dangling', 'memory_unindexed', 'memory_index_duplicates', 'defect_classes_without_kat',
                'order_gaps', 'memory_index_ranges', 'memory_dead_refs', 'round_list_gaps', 'memory_dead_names',
                'memory_dead_symbols', 'rft_lesson_ranges'):
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


def parse(argv):
    """r26 B117: a real argument parser. main() used to test `'--x' in argv`, so `--help` ran the whole tool and wrote a
    runtime snapshot (harness/runtime/tooling_20261104T114625.json); an unknown flag was ignored the same way. Now
    --help prints the usage and exits 0 having written nothing, and an unknown flag exits 2."""
    import argparse
    ap = argparse.ArgumentParser(prog='tooling_intel.py', description=__doc__.split('\n\n')[0],
                                 epilog='Exit 0 every target met · 5 a §0.9 rule-2 target is violated · 2 bad invocation.')
    ap.add_argument('--memory-dir', type=Path, default=None, help='the memory dir (default: this project\'s)')
    ap.add_argument('--determinism', action='store_true', help='generator double runs, in an isolated copy')
    ap.add_argument('--scrub-control', action='store_true', help='pubscrub planted-secret control')
    ap.add_argument('--scripts', action='store_true', help='bash -n every *.sh, build every tools/<go dir>')
    ap.add_argument('--scrub-pages', action='store_true', help='pubscrub every artifacts page into a temp dir; residual')
    return ap.parse_args(argv)


def _det_last(d):
    """the default run's determinism label: 'pending (last: N mismatches, <file>, <age> s ago)'. Pure."""
    if not isinstance(d, dict):
        return 'pending (never measured: run --determinism)'
    return f"pending (last: {d['mismatches']} mismatch(es), {d['file']}, {d['age_s']} s ago)"


def main(argv):
    try:
        a = parse(argv)
    except SystemExit as e:                       # --help (0) or a bad invocation (2): nothing was run or written
        return e.code if isinstance(e.code, int) else 2
    mdir = a.memory_dir or default_memory_dir()
    k = run(ROOT, mdir, a.determinism, a.scrub_control, a.scripts, a.scrub_pages)
    rel = write(ROOT, k)
    # r27: 'KATs 35/35' was the verify_deroarch DK suite next to kat_files 47 (harness/kat/test_*.py): two counts, one word
    print(f"tooling_intel: round {k['round']} · DK KATs (verify_deroarch) {k.get('kats_passed')}/{k.get('kats_total')} · "
          f"KAT files {k.get('kat_files')} · KAT mutations "
          f"{k.get('kat_mutations_proved')}/{k.get('kat_mutations_total')} (coupled {k.get('kat_mutations_coupled')}) · "
          f"tools with a KAT {k.get('tools_with_kat')}/{k.get('tools_total')} · without --help {k.get('tools_without_help_count')} · gates {k.get('gates_pass')}/{k.get('gates_total')} "
          f"(+{k.get('gates_paused')} PAUSED) · memory index {k.get('memory_index_bytes')} B, longest {k.get('memory_index_longest')} · "
          f"mirror drift {k.get('mirror_drift')} · stale claims {k.get('memory_stale_claim_count', k.get('memory_stale_claims'))} · "
          f"round-list gaps {k.get('round_list_gaps_count', k.get('round_list_gaps'))} · determinism "
          f"{k.get('determinism_mismatches') if a.determinism else _det_last(k.get('determinism_last'))} · wrote {rel}")
    for v in k['violations']:
        print('  TARGET', v)
    return 5 if k['violations'] else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
