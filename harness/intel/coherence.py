#!/usr/bin/env python3
"""r24 cross-artifact coherence: every artifact quotes a shared fact the way its ONE canonical source states it.

The round's artifacts (the ledger dero-r1-r<N>.html, dero-src-arch.html, index.html, the soundness page, RUN_REPORT.md,
ARCHITECTURE.md, the skill, the round registry, the area registry and scorecard, the disclosure track and its model,
and artifacts/dero-rft.md) state the same facts many times. This tool extracts those statements and compares each one
with the source that owns the fact (artifacts/dero-rft.md "Artifact contract"):

  fact                                   canonical source
  current round id / status / suffix     harness/round.json (suffix also config/version.go)
  pipeline figures of a run id           harness/loop/runs/<run id>.jsonl (mutate, race, shadow, flaky, project stages)
  registry go_mutations                  the mutate stage of rounds[current].pipeline_full
  measured live miner figures            harness/runtime/r*_live_window_*.txt (the window capture: mean H/s, H/cpu-s, GPU busy)
  disclosure verdict + state per claim   harness/loop/disclosure_track.json (newest history entry)
  area states                            harness/runtime/area_intel.json (+ harness/areas.json status / track)
  backlog status of tracked ids          the artifacts/dero-rft.md §7 table
  page names                             the artifacts/ directory + the registry's current round
  src-arch freshness                     harness/stamp.json source hashes (prep_corpus.sha) + git round commits vs
                                         harness/runtime/evolution_git.tsv
  consensus / peer observatory facts     the capture a statement names (harness/runtime/consensus_capture_<ts>.txt,
                                         peer_capture_<ts>.jsonl); the newest harness/runtime/consensus_intel.json and
                                         peer_intel.json for the src-arch sections and the ledger summary (r24)

Checks (each drift names file:line, expected, found and the canonical source):
  a round      current round id, status, version suffix agree where they are stated for the current round
  b pipeline   every figure that follows a pipeline_<ts> id in the same block equals THAT run's record
  c registry   rounds[current].go_mutations == mutate stage of rounds[current].pipeline_full
  d live       a figure stated for a live-window capture (block names its start time and round, or the capture file)
               equals the capture
  e disclosure ledger "Disclosure track" and src-arch section 10 verdicts/states == the track; the model is current
  f areas      ledger and src-arch area states == area_intel.json; src-arch scorecard run id == area_intel run id;
               proposals from the same run; paused areas match the round's tracks
  g backlog    a block outside §7 that names exactly one tracked id and a status word must not contradict §7's class
               (CLOSED class: CLOSED / REFUTED / FIXED / DONE / MITIGATED; OPEN class: OPEN / PARTIAL / DOCUMENT /
               pending; a block saying "closed in rNN"/"CLOSED"/"FIXED"/"REFUTED" against an OPEN-class row, or
               "still OPEN"/"remains open" against a CLOSED-class row, is drift)
  h pages      every .html linked from index.html exists; index links the current ledger, src-arch and the
               soundness page; dero-rft.md names the current ledger page; the current ledger page exists once the
               round is implemented and carries its own (non-scaffold) round section
  j observatory (r24) a capture file an artifact names exists; a detector grade count (OBSERVED n / ANOMALY n /
               NORMAL n) or key KPI (participants, mean block time, first-relay share, out / in) stated next to a capture
               file equals that capture; the src-arch 'chainobs' and 'peers' sections show the newest capture time and
               grade counts; the ledger's consensus-observatory section names the newest capture files
  i src-arch   every source hash in harness/stamp.json still matches (same function as gen_deroarch check), the
               page size matches the stamp, and every round-marked commit up to HEAD that changes more than generated
               outputs is in evolution_git.tsv (else STALE: rebuild with mine_evolution.py + gen_deroarch.py build)

A statement an artifact does not make is not a drift. Read-only: it never edits an artifact.

  python3 -I harness/intel/coherence.py [--root DIR] [--json] [--record] [--skip index,...]
      exit 0 coherent · 4 drift found · 2 a canonical source is unreadable
"""
import argparse, datetime, hashlib, html, json, re, subprocess, sys
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
STATUSES = ('planned', 'in-progress', 'implemented', 'shipped', 'measured')
DONE = ('implemented', 'shipped', 'measured')
TRACKED_IDS = ('B18', 'B19', 'B28', 'B29', 'B30', 'B34', 'B35', 'B38', 'B39', 'BD5', 'BD6', 'BD7', 'BD8', 'BD9')
CHECKS = ('round', 'pipeline', 'registry', 'live', 'disclosure', 'areas', 'backlog', 'pages', 'index', 'srcarch', 'observatory', 'forensics')
# outputs the generators write; a commit touching only these does not change what src-arch shows
GENERATED = (r'harness/stamp\.json$', r'harness/model/verified\.json$', r'harness/model/raw/', r'harness/runtime/',
             r'harness/loop/runs/', r'harness/loop/GATES\.md$', r'harness/loop/[A-Z_]+_LAST\.json$',
             r'harness/loop/(REJECTED|SKIPPED|UNVERIFIED|CONSENSUS_GUARD)\.(json|md)$', r'harness/corpus/',
             r'artifacts/dero-src-arch\.(html|pdf)$', r'artifacts/index\.html$', r'artifacts/[^/]+\.pdf$')
AUTO_RE = re.compile(rb'<!-- AUTO:BEGIN.*?<!-- AUTO:END -->', re.S)
PID = re.compile(r'pipeline_(\d{8}T\d{6})')
TIME = re.compile(r'\b(\d\d:\d\d)(?::\d\d)?(?:\s*(?:–|-|→|->|to)\s*\d\d:\d\d(?::\d\d)?)?')


# ───────────────────────────── helpers ─────────────────────────────
def sha(p):
    """harness/prep_corpus.sha (the stamp's content hash): sha256[:16]; a SKILL.md hashes without its AUTO block."""
    try:
        b = Path(p).read_bytes()
    except OSError:
        return None
    if str(p).endswith('SKILL.md'):
        b = AUTO_RE.sub(b'', b).rstrip()
    return hashlib.sha256(b).hexdigest()[:16]


def num(s):
    return int(str(s).replace(',', ''))


def rlabel(rid):
    """'r24' -> '24', 'r23c' -> '23c'"""
    return rid[1:] if rid and rid[0] in 'rR' else rid


def read(p):
    try:
        return Path(p).read_text(errors='replace')
    except OSError:
        return None


def md_units(text):
    """(line, text) blocks of a Markdown file: a table row, a heading or a list item is one block; a paragraph (wrapped
    lines) is one block."""
    out, cur, start = [], [], 0
    for i, l in enumerate(text.splitlines(), 1):
        s = l.strip()
        new = (not s) or s.startswith(('|', '#', '- ', '* ', '> ')) or re.match(r'^\d+[a-z]?\. ', s)
        if new and cur:
            out.append((start, '\n'.join(cur)))
            cur = []
        if not s:
            continue
        if s.startswith(('|', '#')):
            out.append((i, l))
            continue
        if not cur:
            start = i
        cur.append(l)
    if cur:
        out.append((start, '\n'.join(cur)))
    return out


BLOCK_END = re.compile(r'</(?:tr|li|p|h\d|section|article|div|figcaption|pre|td)>|<br\s*/?>', re.I)


def strip(h):
    return re.sub(r'\s+', ' ', html.unescape(re.sub(r'<[^>]+>', ' ', h))).strip()


def html_units(text):
    """(line, plain text) blocks of an HTML page, split at block-level closing tags; the line is the block's start."""
    out, pos = [], 0
    nl = [m.start() for m in re.finditer('\n', text)]

    def line_of(off):
        import bisect
        return bisect.bisect_right(nl, off) + 1
    for m in BLOCK_END.finditer(text):
        seg = text[pos:m.start()]
        t = strip(seg)
        if t:
            out.append((line_of(pos), t))
        pos = m.end()
    t = strip(text[pos:])
    if t:
        out.append((line_of(pos), t))
    return out


def units_of(path, text):
    return html_units(text) if str(path).endswith('.html') else md_units(text)


def md_section(text, heading_rx):
    """(first line, lines) of the Markdown section whose heading matches heading_rx, up to the next heading of the
    same or higher level."""
    ls = text.splitlines()
    for i, l in enumerate(ls):
        m = re.match(r'^(#+)\s', l)
        if m and re.search(heading_rx, l):
            lvl = len(m.group(1))
            j = i + 1
            while j < len(ls):
                m2 = re.match(r'^(#+)\s', ls[j])
                if m2 and len(m2.group(1)) <= lvl:
                    break
                j += 1
            return i + 1, ls[i:j]
    return None, None


# ───────────────────────────── canonical sources ─────────────────────────────
def load_pipeline(root, rid):
    """{'mutate': (c, t), 'race': (pkgs, races), 'shadow': {...}, 'flaky': (tests, flaky), 'project': {...}} of one run."""
    p = Path(root) / 'harness/loop/runs' / f'pipeline_{rid}.jsonl'
    t = read(p)
    if t is None:
        return None
    f = {'_file': f'harness/loop/runs/pipeline_{rid}.jsonl'}
    for l in t.splitlines():
        try:
            r = json.loads(l)
        except ValueError:
            continue
        st, s = r.get('stage'), r.get('status')
        if s in ('START', 'INFO', 'BEGIN'):
            continue
        if st == 'mutate':
            m = re.search(r'(\d+)/(\d+) caught', ' '.join(r.get('last') or []))
            if m:
                f['mutate'] = (int(m.group(1)), int(m.group(2)))
        elif st == 'race' and 'packages_ok' in r:
            f['race'] = (r['packages_ok'], r.get('races', 0))
        elif st == 'shadow' and 'blocks_compared' in r:
            f['shadow'] = {'blocks': r['blocks_compared'], 'treehashes': r.get('treehash_compared'), 'mismatches': r.get('mismatches')}
        elif st == 'flaky' and 'tests' in r:
            f['flaky'] = (r['tests'], r.get('flaky'))
        elif st == 'project' and 'kats' in r:
            g = re.match(r'(\d+)/(\d+)', str(r.get('gates', '')))
            f['project'] = {'kats': tuple(map(int, r['kats'].split('/'))), 'mutations': tuple(map(int, r['mutations'].split('/'))),
                            'gates': (int(g.group(1)), int(g.group(2))) if g else None, 'status': s}
        elif st == 'install':
            f['install'] = s
    return f


def load_live(root):
    """[{file, round, start, mean, h_cpu_s, gpu_busy}] from harness/runtime/r*_live_window_*.txt"""
    out = []
    for p in sorted((Path(root) / 'harness/runtime').glob('r*_live_window_*.txt')):
        t = read(p) or ''
        m0 = re.search(r'from \d{4}-\d\d-\d\dT(\d\d:\d\d)', t)
        m1 = re.search(r'H/s mean (\d+).*?H/cpu-s (\d+).*?gpu_busy ([\d.]+)', t)
        if m0 and m1:
            out.append({'file': p.name, 'round': p.name.split('_')[0], 'start': m0.group(1), 'mean': int(m1.group(1)),
                        'h_cpu_s': int(m1.group(2)), 'gpu_busy': float(m1.group(3))})
    return out


def rft_backlog(text):
    """{id: (line, status cell)} from the §7 table of dero-rft.md."""
    out = {}
    ln, sec = md_section(text, r'^## 7\.|Consolidated OPEN backlog')
    if not sec:
        return out
    for k, l in enumerate(sec):
        cells = [c.strip() for c in l.strip().strip('|').split('|')]
        if len(cells) >= 3 and re.fullmatch(r'BD?\d+', cells[0]):
            out[cells[0]] = (ln + k, cells[-1])
    return out


def status_class(s):
    s = s.strip().upper()
    if re.match(r'^(CLOSED|REFUTED|FIXED|DONE|MITIGATED|SHIPPED)', s):
        return 'closed'
    return 'open'


class Ctx:
    def __init__(self, root):
        self.root = Path(root)
        self.drifts, self.facts, self.notes = [], 0, []
        reg = json.loads((self.root / 'harness/round.json').read_text())
        self.reg = reg
        self.cur = reg['current']
        self.rounds = reg['rounds']
        self.rcur = next(r for r in self.rounds if r['id'] == self.cur)
        ids = [r['id'] for r in self.rounds]
        i = ids.index(self.cur)
        self.next = ids[i + 1] if i + 1 < len(ids) else None
        self.label = rlabel(self.cur)
        self.status = self.rcur.get('status')
        self.done = self.status in DONE
        self.ledger = f'artifacts/dero-r1-r{re.match(r"\d+", self.label).group(0)}.html'
        self._pipes = {}

    def rel(self, p):
        try:
            return str(Path(p).relative_to(self.root))
        except ValueError:
            return str(p)

    def drift(self, check, f, line, expected, found, source):
        self.drifts.append({'check': check, 'file': self.rel(f), 'line': line, 'expected': str(expected),
                            'found': str(found), 'source': source})

    def fact(self, n=1):
        self.facts += n

    def pipe(self, rid):
        if rid not in self._pipes:
            self._pipes[rid] = load_pipeline(self.root, rid)
        return self._pipes[rid]

    def text(self, rel):
        return read(self.root / rel)


def soundness_rel(root):
    """r25: the current round's soundness page (harness/kit/soundpage.py; one page per round, older ones are history)"""
    import importlib.util
    kit = next((k for k in (Path(root) / 'harness/kit/soundpage.py', HARNESS / 'kit/soundpage.py') if k.is_file()), None)
    if kit is None:
        return 'artifacts/dero-soundness-<no soundpage helper>.html'
    spec = importlib.util.spec_from_file_location(f'soundpage_for_coherence_{id(root)}', kit)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    try:
        return m.rel(root)
    except (OSError, ValueError):
        return 'artifacts/dero-soundness-<no current round>.html'


def artifact_files(c):
    fs = ['RUN_REPORT.md', 'ARCHITECTURE.md', '.skills/dero-miner-tuning/SKILL.md', 'artifacts/dero-rft.md',
          'artifacts/dero-src-arch.html', 'artifacts/index.html', soundness_rel(c.root), c.ledger]
    return [f for f in dict.fromkeys(fs) if (c.root / f).exists()]


# ───────────────────────────── checks ─────────────────────────────
def check_round(c):
    r, cur, lab = c.rcur, c.cur, c.label
    if r.get('status') not in STATUSES:
        c.drift('round', 'harness/round.json', None, f'one of {STATUSES}', r.get('status'), 'ROUND_STATUSES')
    c.fact()
    vg = c.text('config/version.go') or ''
    m = re.search(r'\+(\d{8}\.r\d+[a-z]?)"', vg)
    vs = r.get('version_suffix')
    if m and vs not in (None, 'pending') :
        c.fact()
        if m.group(1) != vs:
            ln = next((i for i, l in enumerate(vg.splitlines(), 1) if m.group(1) in l), None)
            c.drift('round', 'config/version.go', ln, vs, m.group(1), 'harness/round.json rounds[current].version_suffix')
    rft = c.text('artifacts/dero-rft.md')
    if rft:
        ls = rft.splitlines()
        hdr_end = next((i for i, l in enumerate(ls) if l.startswith('## ')), len(ls))
        for i, l in enumerate(ls[:hdr_end], 1):
            for mm in re.finditer(r'now at \*\*Round (\d+[a-z]?)\*\*', l):
                c.fact()
                if mm.group(1) != lab:
                    c.drift('round', 'artifacts/dero-rft.md', i, f'Round {lab}', f'Round {mm.group(1)}', 'harness/round.json current')
            # header statement of a round's registry status: `rNN` <status>
            for mm in re.finditer(r'`(r\d+[a-z]?)`\s*(?:is\s*|status\s*)?`?(planned|in-progress|implemented|shipped|measured)\b', l):
                rr = next((x for x in c.rounds if x['id'] == mm.group(1)), None)
                if rr:
                    c.fact()
                    if rr.get('status') != mm.group(2):
                        c.drift('round', 'artifacts/dero-rft.md', i, f"{mm.group(1)} {rr.get('status')}", f'{mm.group(1)} {mm.group(2)}',
                                'harness/round.json rounds[].status')
            for mm in re.finditer(r'current\s*`(r\d+[a-z]?)`', l):
                c.fact()
                if mm.group(1) != cur:
                    c.drift('round', 'artifacts/dero-rft.md', i, f'current `{cur}`', f'current `{mm.group(1)}`', 'harness/round.json current')
        want = rlabel(c.next) if (c.done and c.next) else lab
        for i, l in enumerate(ls, 1):
            mm = re.match(r'^## 1\. The prompt to paste \(Round (\d+[a-z]?)\)', l)
            if mm:
                c.fact()
                if mm.group(1) != want:
                    c.drift('round', 'artifacts/dero-rft.md', i, f'Round {want} (round {cur} is {c.status})', f'Round {mm.group(1)}', 'harness/round.json')
        if c.done:
            c.fact()
            if not re.search(rf'^### Round {re.escape(lab)} — after implementation', rft, re.M):
                c.drift('round', 'artifacts/dero-rft.md', None, f'a §12 entry "### Round {lab} — after implementation"', 'none', f'harness/round.json {cur} status {c.status}')
        if c.status == 'measured':
            c.fact()
            if not re.search(rf'^### Round {re.escape(lab)} — after measurement', rft, re.M):
                c.drift('round', 'artifacts/dero-rft.md', None, f'a §13 entry "### Round {lab} — after measurement"', 'none', f'harness/round.json {cur} status measured')
        # §0.3: the pause statement follows the registry's tracks
        tr = (c.rcur.get('tracks') or {}).get('miner', 'active')
        for i, l in enumerate(ls, 1):
            if re.match(r'^\*\*State: (PAUSED|ACTIVE)', l):
                c.fact()
                said = 'paused' if 'PAUSED' in l.split('**')[1] else 'active'
                if said != ('paused' if tr == 'paused' else 'active'):
                    c.drift('round', 'artifacts/dero-rft.md', i, f'miner track {tr}', said, 'harness/round.json rounds[current].tracks.miner')
    # the round's own section in RUN_REPORT, ARCHITECTURE, SKILL once implemented
    if c.done:
        for f, rx in (('RUN_REPORT.md', rf'^## Round {re.escape(lab)}\b'), ('ARCHITECTURE.md', rf'^## \d+\. .*Round {re.escape(lab)}\b'),
                      ('.skills/dero-miner-tuning/SKILL.md', rf'^## Round {re.escape(lab)}\b')):
            t = c.text(f)
            if t is None:
                continue
            ln, sec = md_section(t, rx)
            c.fact()
            if not sec:
                c.drift('round', f, None, f'a Round {lab} section', 'none', f'harness/round.json {cur} status {c.status}')
                continue
            if re.search(r'\(planned\)|not started', sec[0]):
                c.drift('round', f, ln, f'Round {lab} section filled ({c.status})', sec[0].strip()[:120], 'harness/round.json rounds[current].status')
            for k, l in enumerate(sec):
                for mm in re.finditer(r'(?:installed|shipped) as `?\+?(\d{8}\.r\d+[a-z]?)', l):
                    c.fact()
                    if vs not in (None, 'pending') and mm.group(1) != vs:
                        c.drift('round', f, ln + k, vs, mm.group(1), 'harness/round.json rounds[current].version_suffix')


FIG = [  # (key, regex) — order matters: 'harness mutations' before 'mutations'
    ('hmut', re.compile(r'harness mutations:? (\d[\d,]*)/(\d[\d,]*)')),
    ('mut', re.compile(r'(?<!harness )(?<!harness-)\bmutations:? (\d[\d,]*)/(\d[\d,]*)')),
    ('kats', re.compile(r'\bKATs:? (\d+)/(\d+)')),
    ('gates', re.compile(r'\bgates:? (\d+)/(\d+)')),
    ('race', re.compile(r'\brace:? (\d+) (?:packages|pkgs),? (\d+) races?')),
    ('blocks', re.compile(r'\bshadow:? (\d+)(?:/\d+)? blocks')),
    ('treehashes', re.compile(r'(\d+) treehashes')),
    ('mismatches', re.compile(r'(\d+) mismatches')),
    ('flaky_n', re.compile(r'(\d+) flaky\b(?!=)|\bflaky=(\d+)')),
    ('flaky_tests', re.compile(r'flaky:? (\d+) ?[×x] ?3')),
]


def expect_fig(rec, key, m):
    """(expected, found) of one figure against a run record, or None when the record has no such stage."""
    g = tuple(num(x) for x in m.groups() if x is not None)
    pr = rec.get('project')
    if key == 'hmut':
        return (pr['mutations'], g) if pr else None
    if key == 'mut':
        if 'mutate' in rec:
            return rec['mutate'], g
        return (pr['mutations'], g) if pr else None
    if key == 'kats':
        return (pr['kats'], g) if pr else None
    if key == 'gates':
        return (pr['gates'], g) if pr and pr.get('gates') else None
    if key == 'race':
        return (rec['race'], g) if 'race' in rec else None
    sh = rec.get('shadow')
    if key in ('blocks', 'treehashes', 'mismatches'):
        return ((sh[key],), g) if sh and sh.get(key) is not None else None
    fl = rec.get('flaky')
    if key == 'flaky_n':
        return ((fl[1],), g) if fl else None
    if key == 'flaky_tests':
        return ((fl[0],), g) if fl else None
    return None


def check_pipeline(c, files):
    for f in files:
        t = c.text(f)
        for ln, u in units_of(f, t):
            ids = list(PID.finditer(u))
            if not ids:
                continue
            for k, mid in enumerate(ids):
                end = ids[k + 1].start() if k + 1 < len(ids) else len(u)
                seg = u[mid.end():end]
                rec = c.pipe(mid.group(1))
                if rec is None:   # an old run whose record was not kept: nothing to compare (noted, not a drift)
                    c.notes.append(f"{c.rel(c.root / f)}:{ln}: no record for {mid.group(0)}")
                    continue
                taken = []
                for key, rx in FIG:
                    for m in rx.finditer(seg):
                        if any(a <= m.start() < b for a, b in taken):
                            continue
                        taken.append((m.start(), m.end()))
                        e = expect_fig(rec, key, m)
                        if e is None:
                            continue
                        c.fact()
                        if tuple(e[0]) != tuple(e[1]):
                            c.drift('pipeline', f, ln + u[:mid.end() + m.start()].count('\n'), f"{key} {'/'.join(map(str, e[0]))}",
                                    f"{key} {'/'.join(map(str, e[1]))}", rec['_file'])


def check_registry(c):
    pf, gm = c.rcur.get('pipeline_full'), c.rcur.get('go_mutations')
    if pf in (None, 'pending') or gm in (None, 'pending'):
        return
    rec = c.pipe(pf.replace('pipeline_', ''))
    c.fact()
    if rec is None:
        c.drift('registry', 'harness/round.json', None, f'a record for {pf}', 'missing', 'harness/loop/runs/')
        return
    if 'mutate' in rec and '/'.join(map(str, rec['mutate'])) != gm:
        c.drift('registry', 'harness/round.json', None, '/'.join(map(str, rec['mutate'])), gm, rec['_file'] + ' stage mutate')
    for k in ('merge_commit', 'head_after'):
        v = c.rcur.get(k)
        if v not in (None, 'pending') and (c.root / '.git').exists():
            c.fact()
            if subprocess.run(['git', '-C', str(c.root), 'cat-file', '-e', f'{v}^{{commit}}'], capture_output=True).returncode:
                c.drift('registry', 'harness/round.json', None, f'{k} a commit of this repository', v, 'git')


def check_live(c, files):
    for cap in load_live(c.root):
        tag = re.compile(rf'\b{re.escape(cap["round"])}\b', re.I)
        for f in files:
            t = c.text(f)
            for ln, u in units_of(f, t):
                if not ((cap['start'] in u and tag.search(u)) or cap['file'] in u):
                    continue
                src = f"harness/runtime/{cap['file']}"
                times = [(m.start(), m.group(1)) for m in TIME.finditer(u)]

                def bound(off):
                    """the figure belongs to the capture when the nearest time (range) before it is the capture's start,
                    or when no time precedes it and the block cites the capture file"""
                    pre = [t for o, t in times if o < off]
                    return pre[-1] == cap['start'] if pre else cap['file'] in u
                for rx, want, show in (
                        (r'(\d{2},\d{3}) H/s(?: TOTAL)? mean', cap['mean'], f"{cap['mean']:,}"),
                        (r'TOTAL(?: H/s)? mean:? (\d{2},\d{3})', cap['mean'], f"{cap['mean']:,}"),
                        (r'(\d,\d{3}) H/cpu-s', cap['h_cpu_s'], f"{cap['h_cpu_s']:,}")):
                    for m in re.finditer(rx, u):
                        if not bound(m.start()):
                            continue
                        c.fact()
                        if num(m.group(1)) != want:
                            c.drift('live', f, ln + u[:m.start()].count('\n'), show, m.group(1), src)
                for m in re.finditer(r'(\d+\.\d)k H/s TOTAL mean', u):
                    if not bound(m.start()):
                        continue
                    c.fact()
                    if abs(float(m.group(1)) - cap['mean'] / 1000) > 0.05:
                        c.drift('live', f, ln + u[:m.start()].count('\n'), f"{cap['mean'] / 1000:.1f}k", m.group(1) + 'k', src)
                for m in re.finditer(r'GPU busy:? (\d+\.\d) ?%', u):
                    if not bound(m.start()):
                        continue
                    c.fact()
                    if float(m.group(1)) != cap['gpu_busy']:
                        c.drift('live', f, ln + u[:m.start()].count('\n'), cap['gpu_busy'], m.group(1), src)


def norm_verdict(s):
    return re.sub(r'[\s_]+', '-', s.strip()).upper()


def check_disclosure(c):
    tr_t = c.text('harness/loop/disclosure_track.json')
    if tr_t is None:
        return
    tr = json.loads(tr_t)
    latest = {cl['id']: cl['history'][-1] for cl in tr.get('claims', []) if cl.get('history')}
    cr = tr.get('current_round')
    src = 'harness/loop/disclosure_track.json'
    # the model the src-arch page is built from
    mt = c.text('harness/model/raw/disclosure.json')
    if mt:
        md = json.loads(mt)
        c.fact()
        want = hashlib.sha256(json.dumps(tr, sort_keys=True).encode()).hexdigest()[:16]
        if md.get('track_sha') != want:
            c.drift('disclosure', 'harness/model/raw/disclosure.json', None, f'track_sha {want}', md.get('track_sha'), src + ' (run disclosure_track.py --emit-model)')
        for row in md.get('rows', []):
            if row.get('kind') == 'track-claim' and row.get('track_id') in latest:
                h = (row.get('history') or {}).get(latest[row['track_id']]['round'])
                c.fact()
                if not h or (h.get('verdict'), h.get('state')) != (latest[row['track_id']]['verdict'], latest[row['track_id']]['state']):
                    c.drift('disclosure', 'harness/model/raw/disclosure.json', None,
                            f"{row['track_id']} {latest[row['track_id']]['verdict']} / {latest[row['track_id']]['state']}",
                            f"{row['track_id']} {(h or {}).get('verdict')} / {(h or {}).get('state')}", src)
    # ledger "Disclosure track" section
    lt = c.text(c.ledger)
    if lt and '<!--disclosure-track:begin-->' in lt:
        a = lt.index('<!--disclosure-track:begin-->')
        b = lt.find('<!--disclosure-track:end-->', a)
        seg = lt[a:b if b > 0 else len(lt)]
        base = lt[:a].count('\n') + 1
        heads = [strip(x) for x in re.findall(r'<th>(.*?)</th>', seg, re.S)]
        for m in re.finditer(r'<tr>(.*?)</tr>', seg, re.S):
            tds = [strip(x) for x in re.findall(r'<td>(.*?)</td>', m.group(1), re.S)]
            if len(tds) < 3:
                continue
            cid = tds[0].split('·')[0].strip()
            if cid not in latest:
                continue
            lat = latest[cid]
            ln = base + seg[:m.start()].count('\n')
            c.fact(2)
            if lat['round'] in heads:
                v = tds[heads.index(lat['round'])]
                if norm_verdict(v) != lat['verdict']:
                    c.drift('disclosure', c.ledger, ln, f"{cid} {lat['round']} {lat['verdict']}", f'{cid} {v}', src)
            if tds[-1] != lat['state']:
                c.drift('disclosure', c.ledger, ln, f"{cid} state {lat['state']}", f'{cid} state {tds[-1]}', src)
    # src-arch section 10 table t-dtrack
    st = c.text('artifacts/dero-src-arch.html')
    if st and 'id="t-dtrack"' in st:
        a = st.index('id="t-dtrack"')
        b = st.find('</table>', a)
        seg = st[a:b]
        base = st[:a].count('\n') + 1
        for m in re.finditer(r'<tr>(.*?)</tr>', seg, re.S):
            tds = [strip(x) for x in re.findall(r'<td[^>]*>(.*?)</td>', m.group(1), re.S)]
            if len(tds) < 2:
                continue
            mm = re.match(r'([A-Z][\w-]*?)\s+—', tds[0])
            if not mm or mm.group(1) not in latest:
                continue
            cid, lat = mm.group(1), latest[mm.group(1)]
            ln = base + seg[:m.start()].count('\n')
            pairs = re.findall(r'\b(R\d+[a-z]?) ([a-z][a-z -]*?)(?= R\d+[a-z]? | now:|$)', tds[1])
            sm = re.search(r'now: (\S+)', tds[1])
            c.fact(2)
            if not pairs or pairs[-1][0] != lat['round'] or norm_verdict(pairs[-1][1]) != lat['verdict']:
                c.drift('disclosure', 'artifacts/dero-src-arch.html', ln, f"{cid} {lat['round']} {lat['verdict']}",
                        f"{cid} {' '.join(pairs[-1]) if pairs else 'no verdict'}", src + ' (rebuild: gen_deroarch.py build)')
            if not sm or sm.group(1) != lat['state']:
                c.drift('disclosure', 'artifacts/dero-src-arch.html', ln, f"{cid} now: {lat['state']}",
                        f"{cid} now: {sm.group(1) if sm else 'none'}", src + ' (rebuild: gen_deroarch.py build)')
    _ = cr


def check_areas(c):
    at, rt = c.text('harness/runtime/area_intel.json'), c.text('harness/areas.json')
    if at is None or rt is None:
        return
    ai, reg = json.loads(at), json.loads(rt)
    src = 'harness/runtime/area_intel.json'
    state = {a['id']: a.get('state') for a in ai.get('areas', [])}
    title = {a.get('title'): a['id'] for a in ai.get('areas', [])}
    tracks = c.rcur.get('tracks') or {}
    for a in reg.get('areas', []):
        c.fact()
        if a['id'] not in state:
            c.drift('areas', src, None, f"a scorecard for area {a['id']}", 'none', 'harness/areas.json')
            continue
        if (a.get('status') == 'paused') != (state[a['id']] == 'PAUSED'):
            c.drift('areas', 'harness/areas.json', None, f"{a['id']} {state[a['id']]}", f"{a['id']} status {a.get('status')}", src)
        if a.get('status') == 'paused' and a.get('track'):
            c.fact()
            if tracks.get(a['track'], 'active') != 'paused':
                c.drift('areas', 'harness/areas.json', None, f"track {a['track']} {tracks.get(a['track'], 'active')}",
                        f"{a['id']} paused", 'harness/round.json rounds[current].tracks')
    pt = c.text('harness/runtime/area_proposals.json')
    if pt:
        c.fact()
        if json.loads(pt).get('run_id') != ai.get('run_id'):
            c.drift('areas', 'harness/runtime/area_proposals.json', None, f"run_id {ai.get('run_id')}", json.loads(pt).get('run_id'), src)
    lt = c.text(c.ledger)
    if lt and '<section id="areas"' in lt:
        a0 = lt.index('<section id="areas"')
        seg = lt[a0:lt.find('</section>', a0)]
        base = lt[:a0].count('\n') + 1
        for m in re.finditer(r'<article class="acard[^"]*" id="area-([\w-]+)">(.*?)</article>', seg, re.S):
            ch = re.search(r'<span class="chip[^"]*">(.*?)</span>', m.group(2), re.S)
            if m.group(1) not in state or not ch:
                continue
            c.fact()
            if strip(ch.group(1)) != state[m.group(1)]:
                c.drift('areas', c.ledger, base + seg[:m.start()].count('\n'), f"{m.group(1)} {state[m.group(1)]}",
                        f"{m.group(1)} {strip(ch.group(1))}", src + ' (regenerate the ledger)')
    st = c.text('artifacts/dero-src-arch.html')
    if st and 'id="areas"' in st:
        a0 = st.index('id="areas"')
        seg = st[a0:st.find('</section>', a0)]
        base = st[:a0].count('\n') + 1
        rm = re.search(r'Scorecard run (\d{8}T\d{6})', strip(seg[:20000]))
        if rm:
            c.fact()
            if rm.group(1) != ai.get('run_id'):
                c.drift('areas', 'artifacts/dero-src-arch.html', base, f"scorecard run {ai.get('run_id')}", rm.group(1), src + ' (rebuild: gen_deroarch.py build)')
        for m in re.finditer(r'<tr>(.*?)</tr>', seg, re.S):
            tds = [strip(x) for x in re.findall(r'<td[^>]*>(.*?)</td>', m.group(1), re.S)]
            if len(tds) < 2:
                continue
            tt = tds[0].replace(' HARNESS', '').strip()
            aid = title.get(tt) or next((v for k, v in title.items() if k and tt.startswith(k)), None)
            if not aid:
                continue
            got = tds[1].replace('HARNESS', '').strip()
            c.fact()
            if got != state[aid]:
                c.drift('areas', 'artifacts/dero-src-arch.html', base + seg[:m.start()].count('\n'), f'{aid} {state[aid]}', f'{aid} {got}',
                        src + ' (rebuild: gen_deroarch.py build)')


CLOSED_SAY = re.compile(r'\b(CLOSED|closed in r\d+\w*|FIXED|fixed in r\d+\w*|REFUTED)\b')
OPEN_SAY = re.compile(r'\b(still OPEN|still open|remains open|remains OPEN|stays OPEN|stays open)\b')


def check_backlog(c, ids=TRACKED_IDS):
    rft = c.text('artifacts/dero-rft.md')
    if not rft:
        return
    bl = rft_backlog(rft)
    idrx = re.compile(r'\b(BD?\d+)\b')
    targets = []
    lt = c.text(c.ledger)
    if lt:
        a = lt.find('id="r' + c.label + '"')
        if a > 0:
            targets.append((c.ledger, html_units(lt[a:]), lt[:a].count('\n')))
    for f, rx in (('RUN_REPORT.md', rf'^## Round {re.escape(c.label)}\b'), ('ARCHITECTURE.md', rf'^## \d+\. .*Round {re.escape(c.label)}\b')):
        t = c.text(f)
        if t:
            ln, sec = md_section(t, rx)
            if sec:
                targets.append((f, md_units('\n'.join(sec)), ln - 1))
    for f, us, off in targets:
        for ln, u in us:
            found = {x for x in idrx.findall(u) if x in ids and x in bl}
            if len(found) != 1:
                continue
            bid = found.pop()
            cls = status_class(bl[bid][1])
            said = 'closed' if CLOSED_SAY.search(u) else ('open' if OPEN_SAY.search(u) else None)
            if said is None:
                continue
            c.fact()
            if said != cls:
                c.drift('backlog', f, off + ln, f'{bid} {cls} (§7: {bl[bid][1][:60]})', f'{bid} said {said}', f'artifacts/dero-rft.md:{bl[bid][0]} (§7)')


def check_pages(c, index=True):
    art = c.root / 'artifacts'
    if c.done:
        c.fact()
        if not (c.root / c.ledger).exists():
            c.drift('pages', c.ledger, None, f'the ledger page of round {c.cur} ({c.status})', 'missing', 'harness/round.json current')
        else:
            lt = c.text(c.ledger)
            a = lt.find(f'id="r{c.label}"')
            c.fact()
            if a < 0:
                c.drift('pages', c.ledger, None, f'a section id="r{c.label}"', 'none', 'harness/round.json current')
            elif 'scaffold: not started' in lt[a:a + 4000]:
                c.drift('pages', c.ledger, lt[:a].count('\n') + 1, f'the Round {c.label} section filled ({c.status})', 'scaffold', 'harness/round.json')
            else:
                vs = c.rcur.get('version_suffix')
                seg = strip(lt[a:a + 3000])
                for m in re.finditer(r'\+(\d{8}\.r\d+[a-z]?)', seg):
                    c.fact()
                    if vs not in (None, 'pending') and m.group(1) != vs:
                        c.drift('round', c.ledger, lt[:a].count('\n') + 1, '+' + vs, '+' + m.group(1), 'harness/round.json version_suffix')
                    break
    rft = c.text('artifacts/dero-rft.md')
    if rft and c.done:
        c.fact()
        if Path(c.ledger).name not in rft:
            c.drift('pages', 'artifacts/dero-rft.md', None, f'names {Path(c.ledger).name}', 'not named', 'harness/round.json current')
    if not index:
        return
    it = c.text('artifacts/index.html')
    if it is None:
        return
    # the index lists each page as a card naming artifacts/<file> (its link goes to the published copy)
    links = set(re.findall(r'artifacts/([\w.-]+\.html)', it)) | set(re.findall(r'href="([^"#?:/]+\.html)"', it))
    for h in sorted(links):
        c.fact()
        if not (art / h).exists():
            ln = next((i for i, l in enumerate(it.splitlines(), 1) if h in l), None)
            c.drift('index', 'artifacts/index.html', ln, f'{h} exists in artifacts/', 'missing', 'artifacts/ listing')
    need = ['dero-src-arch.html', Path(soundness_rel(c.root)).name]   # r25: the current round's soundness page
    if (c.root / c.ledger).exists():
        need.append(Path(c.ledger).name)
    for n in need:
        if (art / n).exists():
            c.fact()
            if n not in links:
                c.drift('index', 'artifacts/index.html', None, f'a link to {n}', 'none', 'artifacts/ listing + harness/round.json current')


# r24 (integration): the consensus observatory's facts. A capture file is the canonical source of what it captured; the
# newest consensus_intel.json / peer_intel.json are the canonical source of the 'current' observatory sections.
CAP_RX = re.compile(r'\b(consensus_capture_\d{8}T\d{6}Z?\.txt|peer_capture_\d{8}T\d{6}Z?\.jsonl|peer_logx_\d{8}T\d{6}Z?\.jsonl)\b')
GRADE_N = r'\b{}:? (\d{{1,2}})(?!\d|[.,]\d|\s*(?:blocks?|ms|s\b|%|x\b|times|lines|peers))'
OBS_FIG = {  # kind -> [(name, regex, key in the capture facts)]
    # a grade COUNT is one or two digits not followed by a unit: '▲ ANOMALY 7848898 blocks behind us' is a finding's
    # value, not a count (pipeline_20261102T223327 false drift)
    'consensus': [('OBSERVED', re.compile(GRADE_N.format('OBSERVED')), 'observed'), ('ANOMALY', re.compile(GRADE_N.format('ANOMALY')), 'anomaly'),
                  ('NORMAL', re.compile(GRADE_N.format('NORMAL')), 'normal'),
                  ('participants', re.compile(r'\b(\d+) participants\b(?! whose)'), 'participants'),
                  ('mean block time', re.compile(r'mean block time (\d+\.\d+) ?s\b'), 'block_time_mean_s')],
    'peers': [('OBSERVED', re.compile(GRADE_N.format('OBSERVED')), 'observed'), ('ANOMALY', re.compile(GRADE_N.format('ANOMALY')), 'anomaly'),
              ('first-relay share', re.compile(r'first-relay share (\d+(?:\.\d+)?) ?%'), 'first_relay_pct'),
              ('out / in', re.compile(r'\b(\d+) out / (\d+) in\b'), 'out_in')]}


def capture_facts(root, name):
    """{'kind', facts...} of one capture file, or None when it is missing/unreadable."""
    t = read(Path(root) / 'harness/runtime' / name)
    if t is None:
        return None
    if name.startswith('consensus_capture_'):
        f = {'kind': 'consensus'}
        for m in re.finditer(r'^kpi (\w+) = (.+)$', t, re.M):
            f[m.group(1)] = m.group(2).strip()
        s = re.search(r'^summary OBSERVED=(\d+) ANOMALY=(\d+) NORMAL=(\d+)', t, re.M)
        if s:
            f.update(observed=s.group(1), anomaly=s.group(2), normal=s.group(3))
        c = re.search(r'^# source live captured (\S+)', t, re.M)
        f['captured'] = c.group(1) if c else None
        return f
    if name.startswith('peer_capture_'):
        for l in t.splitlines():
            try:
                o = json.loads(l)
            except ValueError:
                continue
            if o.get('src') == 'kpis':
                f = {'kind': 'peers', 'observed': str(o.get('observed')), 'anomaly': str(o.get('anomaly')),
                     'out_in': f"{o.get('outgoing')}/{o.get('incoming')}"}
                if isinstance(o.get('first_relay_top_share'), (int, float)):
                    f['first_relay_pct'] = round(100 * o['first_relay_top_share'], 1)
                return f
        return {'kind': 'peers'}
    return {'kind': 'logx'}


def check_observatory(c, files):
    ci, pi = c.text('harness/runtime/consensus_intel.json'), c.text('harness/runtime/peer_intel.json')
    cdoc = json.loads(ci) if ci else None
    pdoc = json.loads(pi) if pi else None
    rt = c.root / 'harness/runtime'
    newest_c = sorted(rt.glob('consensus_capture_*.txt'))[-1].name if list(rt.glob('consensus_capture_*.txt')) else None
    newest_p = (pdoc or {}).get('capture_file')
    cache = {}
    for f in files + ['harness/README.md']:
        t = c.text(f)
        if not t:
            continue
        for ln, u in units_of(f, t):
            ms = [(m.start(), m.group(1)) for m in CAP_RX.finditer(u)]
            if not ms:
                continue
            for o, name in ms:
                if name not in cache:
                    cache[name] = capture_facts(c.root, name)
                c.fact()
                if cache[name] is None:
                    c.drift('observatory', f, ln, f'{name} in harness/runtime', 'missing (dangling capture id)', 'harness/runtime/')
            for kind, figs in OBS_FIG.items():
                cands = [(o, n) for o, n in ms if cache.get(n) and cache[n]['kind'] == kind]
                if not cands:
                    continue
                known = [(o, n) for o, n in ms if cache.get(n) and cache[n]['kind'] in OBS_FIG]
                for label, rx, key in figs:
                    for m in rx.finditer(u):
                        # a figure belongs to the nearest capture named before it (else the first one named), and only
                        # when that capture is of this kind: a unit may quote the chain and the peer capture side by side
                        pre = [n for o, n in known if o < m.start()]
                        name = pre[-1] if pre else known[0][1]
                        if cache[name]['kind'] != kind:
                            continue
                        want = cache[name].get(key)
                        if want is None:
                            continue
                        got = f'{m.group(1)}/{m.group(2)}' if key == 'out_in' else m.group(1)
                        c.fact()
                        same = (abs(float(got) - float(want)) < 0.051) if key in ('first_relay_pct', 'block_time_mean_s') else str(got) == str(want)
                        if not same:
                            c.drift('observatory', f, ln + u[:m.start()].count('\n'), f'{label} {want}', f'{label} {got}', f'harness/runtime/{name}')
    # the 'current' sections: src-arch chainobs / peers and the ledger summary follow the newest observatory outputs
    st = c.text('artifacts/dero-src-arch.html')
    for sid, doc, grades in (('chainobs', cdoc, (cdoc or {}).get('summary') or {}),
                             ('peers', pdoc, {'OBSERVED': ((pdoc or {}).get('kpis') or {}).get('observed'),
                                              'ANOMALY': ((pdoc or {}).get('kpis') or {}).get('anomaly')})):
        if not st or doc is None or f'<section id="{sid}"' not in st:
            continue
        a0 = st.index(f'<section id="{sid}"')
        seg = strip(st[a0:st.find('</section>', a0)])
        base = st[:a0].count('\n') + 1
        cm = re.search(r'Capture (\S+?)[,. ]', seg)
        c.fact()
        if not cm or cm.group(1) != str(doc.get('captured')):
            c.drift('observatory', 'artifacts/dero-src-arch.html', base, f"{sid} capture {doc.get('captured')}",
                    f"{sid} capture {cm.group(1) if cm else 'none'}", 'harness/runtime/' + ('consensus_intel.json' if sid == 'chainobs' else 'peer_intel.json') + ' (rebuild: miners + gen_deroarch.py build)')
        for g in ('OBSERVED', 'ANOMALY'):
            m = re.search(rf'(\d+) detectors {g}', seg)
            if m and grades.get(g) is not None:
                c.fact()
                if int(m.group(1)) != int(grades[g]):
                    c.drift('observatory', 'artifacts/dero-src-arch.html', base, f'{sid} {g} {grades[g]}', f'{sid} {g} {m.group(1)}',
                            'harness/runtime/' + ('consensus_intel.json' if sid == 'chainobs' else 'peer_intel.json'))
    lt = c.text(c.ledger)
    if lt and '<section id="consensus-observatory"' in lt:
        a0 = lt.index('<section id="consensus-observatory"')
        seg = lt[a0:lt.find('</section>', a0)]
        base = lt[:a0].count('\n') + 1
        for want, src in ((newest_c, 'harness/runtime/consensus_capture_*.txt (newest)'), (newest_p, 'harness/runtime/peer_intel.json capture_file')):
            if want:
                c.fact()
                if want not in seg:
                    got = [n for n in CAP_RX.findall(seg) if n[:9] == want[:9]]
                    c.drift('observatory', c.ledger, base, f'names {want}', got[0] if got else 'none', src + ' (regenerate the ledger)')



def is_generated(path):
    return any(re.search(rx, path) for rx in GENERATED)


def git(c, *a):
    r = subprocess.run(['git', '-C', str(c.root), *a], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


def check_srcarch(c):
    st_t = c.text('harness/stamp.json')
    page = c.root / 'artifacts/dero-src-arch.html'
    if st_t is None or not page.exists():
        return
    st = json.loads(st_t)
    old = st.get('root')
    drift = []
    for p, h in (st.get('sources') or {}).items():
        q = p
        if old and str(c.root) != old and (p == old or p.startswith(old.rstrip('/') + '/')):
            q = str(c.root) + p[len(old.rstrip('/')):]
        c.fact()
        if sha(q) != h:
            drift.append(p[len(old.rstrip('/')) + 1:] if old and p.startswith(old) else p)
    if drift:
        c.drift('srcarch', 'artifacts/dero-src-arch.html', None, 'every stamped source unchanged since the build',
                f"STALE: {len(drift)} source(s) changed, e.g. {', '.join(drift[:4])}", 'harness/stamp.json (rebuild: gen_deroarch.py build)')
    c.fact()
    if st.get('bytes') is not None and page.stat().st_size != st['bytes']:
        c.drift('srcarch', 'artifacts/dero-src-arch.html', None, f"{st['bytes']} bytes (stamp)", f'{page.stat().st_size} bytes (edited by hand?)', 'harness/stamp.json')
    # round-marked commits up to HEAD vs evolution_git.tsv
    if not (c.root / '.git').exists():
        return
    tsv = c.text('harness/runtime/evolution_git.tsv') or ''
    have = set(re.findall(r'^C\t\d+\t([0-9a-f]+)\t', tsv, re.M))
    log = git(c, 'log', '--format=%h%x09%s', '-n', '400')
    if log is None:
        return
    lab = re.escape(c.label)
    rx = re.compile(rf'^(?:Round |R|r){lab}(?![0-9a-z])')
    missing = []
    for l in log.splitlines():
        h, _, s = l.partition('\t')
        if not rx.match(s):
            continue
        c.fact()
        if any(h.startswith(x) or x.startswith(h) for x in have):
            continue
        fs = (git(c, 'show', '--name-only', '--format=', h) or '').split()
        real = [f for f in fs if not is_generated(f)]
        if real == ['.skills/dero-miner-tuning/SKILL.md'] or (real and set(real) <= {'.skills/dero-miner-tuning/SKILL.md'}):
            a, b = git(c, 'show', f'{h}^:.skills/dero-miner-tuning/SKILL.md'), git(c, 'show', f'{h}:.skills/dero-miner-tuning/SKILL.md')
            if a is not None and b is not None and AUTO_RE.sub(b'', a.encode()).rstrip() == AUTO_RE.sub(b'', b.encode()).rstrip():
                real = []
        if real:
            missing.append(h)
    if missing:
        c.drift('srcarch', 'harness/runtime/evolution_git.tsv', 3, f'every R{c.label} commit up to HEAD',
                f"STALE: {len(missing)} round commit(s) missing, e.g. {', '.join(missing[:4])}", 'git log (run mine_evolution.py, then gen_deroarch.py build)')


def check_forensics(c):
    """r25 (rft §0.6 rule for G30): every figure of the ledger's forensics sections and of the src-arch "Forensic dataset"
    line against the newest forensic dataset (harness/forensics/facts.py does the reading); one drift per failure, and
    the manifest SHA-256 the RUN_REPORT / ARCHITECTURE round sections quote (first 8+ hex after "manifest") must be the
    newest manifest's."""
    fp = c.root / 'harness' / 'forensics' / 'facts.py'
    if not fp.exists() or not (c.root / 'forensics' / 'ledger.json').exists():
        return
    import importlib.util as _iu
    sp = _iu.spec_from_file_location(f'facts_for_coherence_{id(c)}', fp)
    FX = _iu.module_from_spec(sp)
    sp.loader.exec_module(FX)
    try:
        ds = FX.newest_dataset(c.root)
        F = FX.build(ds, c.root)
    except Exception as e:                                           # noqa: BLE001
        c.fact()
        c.drift('forensics', 'forensics/ledger.json', None, 'a readable newest dataset', f'{type(e).__name__}: {e}', 'harness/forensics/facts.py')
        return
    msha = F.facts['manifest_sha256']['value']
    for x in F.problems:
        c.fact()
        c.drift('forensics', f'forensics/{ds.name}/manifest.json', None, 'dataset files equal to the manifest', x, 'manifest_check')
    for rel, b, e, need in ((c.ledger, FX.BEGIN, FX.END, True), ('artifacts/dero-src-arch.html', FX.SA_BEGIN, FX.SA_END, False)):
        p = c.root / rel
        if not p.exists():
            continue
        txt = p.read_text()
        c.fact()
        if b not in txt:
            if rel == c.ledger and re.search(r'r(\d+)\.html$', rel) and int(re.search(r'r(\d+)\.html$', rel).group(1)) < 25:
                continue
            c.drift('forensics', rel, None, f'the forensics block {b}', 'none', f'forensics/{ds.name}/manifest.json')
            continue
        probs, n = FX.check_page(txt, F, b, e, need)
        c.facts += n
        for x in probs:
            c.drift('forensics', rel, None, 'every figure traced to its dataset file + SHA-256', x[:200], f'forensics/{ds.name} (G30)')
    for rel in ('RUN_REPORT.md', 'ARCHITECTURE.md'):
        t = c.text(rel) or ''
        for i, l in enumerate(t.splitlines(), 1):
            for mm in re.finditer(r'forensic[^|]{0,80}?manifest (?:SHA-256 )?`?([0-9a-f]{8,64})', l):
                c.fact()
                if not msha.startswith(mm.group(1)):
                    c.drift('forensics', rel, i, msha[:12], mm.group(1)[:12], f'forensics/{ds.name}/manifest.json')


# ───────────────────────────── driver ─────────────────────────────
def run(root=ROOT, skip=()):
    c = Ctx(root)
    files = artifact_files(c) + ['harness/round.json']
    files = [f for f in files if (c.root / f).exists()]
    steps = {'round': lambda: check_round(c), 'pipeline': lambda: check_pipeline(c, files), 'registry': lambda: check_registry(c),
             'live': lambda: check_live(c, files), 'disclosure': lambda: check_disclosure(c), 'areas': lambda: check_areas(c),
             'backlog': lambda: check_backlog(c), 'pages': lambda: check_pages(c, index='index' not in skip),
             'srcarch': lambda: check_srcarch(c), 'observatory': lambda: check_observatory(c, files),
             'forensics': lambda: check_forensics(c)}
    for k, fn in steps.items():
        if k not in skip:
            fn()
    return {'captured': datetime.datetime.now().astimezone().isoformat(timespec='seconds'), 'round': c.cur, 'status': c.status,
            'ledger': c.ledger, 'files': files, 'skipped': sorted(skip), 'facts': c.facts, 'drifts': c.drifts, 'notes': c.notes,
            'ok': not c.drifts}


def g25(root=ROOT):
    """The gate G25 (run_gates.py): every check except the index page, which gen_index.py rewrites AFTER run_gates in
    S7; the S7 step `coherence.py --record` after gen_index runs the full set, index included."""
    r = run(root, skip=('index',))
    d = r['drifts']
    det = f"{r['facts']} statements checked in round {r['round']} ({r['status']}); {len(d)} drift(s)"
    if d:
        det += ' · ' + '; '.join(f"{x['check']} {x['file']}:{x['line'] or '-'} expected {x['expected']} found {x['found']}" for x in d[:6])
    return r['ok'], det


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--root', default=str(ROOT))
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--record', action='store_true')
    ap.add_argument('--skip', default='', help='comma list of checks to skip: ' + ','.join(CHECKS))
    a = ap.parse_args(argv)
    try:
        r = run(Path(a.root).resolve(), skip=tuple(x for x in a.skip.split(',') if x))
    except (OSError, ValueError, KeyError, StopIteration) as e:
        print(f'coherence: a canonical source is unreadable: {type(e).__name__}: {e}')
        return 2
    if a.record:
        rt = Path(a.root) / 'harness/runtime'
        ts = datetime.datetime.now().strftime('%Y%m%dT%H%M%S')
        for p in (rt / f'coherence_{ts}.json', rt / 'coherence_last.json'):
            p.write_text(json.dumps(r, indent=1) + '\n')
    if a.json:
        print(json.dumps(r, indent=1))
    else:
        for d in r['drifts']:
            print(f"DRIFT {d['check']:<10} {d['file']}:{d['line'] or '-'}  expected {d['expected']}  found {d['found']}  [{d['source']}]")
        print(f"coherence {r['round']} ({r['status']}): {r['facts']} statements checked over {len(r['files'])} artifacts, "
              f"{len(r['drifts'])} drift(s) · {'PASS' if r['ok'] else 'DRIFT'}")
    return 0 if r['ok'] else 4


if __name__ == '__main__':
    sys.exit(main())
