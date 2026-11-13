#!/usr/bin/env python3
"""r28 backlog truth: every artifacts/dero-rft.md §7 row says what its newest record says, the rft header names the
rounds the registry names, and every closure the round books has a record that exists (dero-rft §0.6, §7; G25 'rows').

R28 Part A found what G25 could not see (closure inventory, sweep gaps): 16 §7 rows still read IMPLEMENTED / BACKEND
READY although §13 had recorded them CONFIRMED live or their gate PASS, and the header prose said "Round 26 is
measured ... the next round is Round 27" two rounds late while G25 reported 0 drifts. This tool makes those classes
checkable. Canonical sources, in order: harness/round.json (rounds), the §13 measurement sections (what was CONFIRMED
live), the §7 row itself (its lead status and the bold statuses inside it), and harness/loop/backlog_closures_r<N>.json
(the round's closure records: item, new status, record paths, premises, decision requests).

Checks (each drift names file:line, expected, found and the source):
  rows      R1 lead-stale  a row whose cell states a stronger status in bold (**CONFIRMED…**, **CLOSED…**, **FIXED…**;
                           r30 B233: also round-prefixed, **r29: FIXED:**; r30 verify D6: **DONE…**, an upper-case or
                           multi-word prefix **R29: …** / **r29 merge: FIXED**; a ``double-backtick`` span quotes)
                           or "PAGES IMPLEMENTED" than its lead (IMPLEMENTED / BACKEND READY / OPEN …)
            R2 s13         an id a §13 "CONFIRMED live:" list (or a §13 row whose cell starts **CONFIRMED live**) names
                           while its §7 lead is IMPLEMENTED or BACKEND READY (an OPEN / PARTIAL lead may be a partial
                           confirmation: B36's payee fields were CONFIRMED in R27 while its 24 h read is pending)
            R3 paused      a row whose lead says PAUSED (miner) without citing §0.3 (the resume condition is stated
                           once, there)
  header    H1 the header's "Round N is measured" == the newest measured registry round; H2 "the next round to run is
            Round N" == the current round (planned / in-progress) or the one after it; H3 "## How to start (Round N",
            H4 "## 1. The prompt to paste (Round N)", H5 "## 8. Round N dimension plan" == the current round once it is
            opened (in-progress or later); H6 "## 7. Consolidated OPEN backlog (through the RN merge" == the newest round
            with a merge commit
  closures  C1 every record path of a CLOSED-class closure exists in the tree (no <scratch>, no absolute path);
            C2 every premise holds (repo_contains {file, quote}; goroot_contains {file, quote}; go_at_least "1.24");
            C3 the §7 lead class == the closure's new_status class (after the merge applies the round's rft deltas);
            C4 a user-decision closure carries a decision_request {question, options >= 2, evidence}; a consensus-NO-GO
               one says REPORT-ONLY and names its upstream design anchor
            C5 a ledger item closed through §7 rows (via_rows) finds each of them closed-class; a summary item
               (dedup_into) finds each row it was folded into
  inventory (--inventory FILE, optional) every obsolete-proof entry that cites "rft §7 B<n> <CLOSED-word>" finds that
            row closed-class in §7

Classes: closed = CLOSED / REFUTED / FIXED / DONE / MITIGATED / SHIPPED / CONFIRMED / DECIDED / ANSWERED / SUPERSEDED /
ACCEPTED / STANDING / REPORT-ONLY / REJECTED; implemented = IMPLEMENTED; backend = BACKEND READY; open = everything else (OPEN,
PAUSED, PENDING, PARTIAL, BLOCKED, HELD, …). Read-only: it never edits an artifact.

  python3 -I harness/intel/backlog_truth.py [--root DIR] [--rft FILE] [--closures FILE] [--inventory FILE]
                                            [--skip rows,header,closures] [--json] [--record]
      exit 0 coherent · 4 drift found · 2 a canonical source is unreadable
"""
import argparse, datetime, json, os, re, subprocess, sys
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
CHECKS = ('rows', 'header', 'closures', 'inventory')
RANK = {'open': 0, 'backend': 1, 'implemented': 2, 'closed': 3}
CLOSED_WORDS = ('CLOSED', 'REFUTED', 'FIXED', 'DONE', 'MITIGATED', 'SHIPPED', 'CONFIRMED', 'DECIDED', 'ANSWERED',
                'SUPERSEDED', 'ACCEPTED', 'STANDING', 'REPORT-ONLY', 'REJECTED')   # r30 verify D6: REJECTED (B183)
LEAD_RX = re.compile(r'^[\s*`_~]*(?:PAGES\s+)?(' + '|'.join(re.escape(w) for w in CLOSED_WORDS)
                     + r'|IMPLEMENTED|BACKEND READY)\b')
# r30 (rft §7 B233): a bold status may carry a round prefix ('**r29: FIXED:**', '**r30 CONFIRMED**'): the r29 audit
# found 11 rows whose newest bold status was round-prefixed and so invisible to R1
# r30 verify D6: the prefix may be upper-case ('**R29: FIXED**') and several words long ('**r29 merge: FIXED**',
# '**r29: cost bench DONE**', at most four words after the round id, none a negation: '**r29: not FIXED**' states
# nothing); DONE is a closed bold status too
BOLD_RX = re.compile(r'\*\*\s*(?:[rR]\d+\w*\s*:?(?:\s+(?!(?:not|no|never|un\w*)\b)[A-Za-z][\w-]*){0,4}?\s*:?\s*)?'
                     r'(CONFIRMED|CLOSED|FIXED|REFUTED|DONE)\b')
PAGES_RX = re.compile(r'\bPAGES IMPLEMENTED\b')
# a CommonMark code span: a run of N backticks up to the next run of exactly N (r30 verify D6: ``a `b` c`` is one span)
CODE_SPAN_RX = re.compile(r'(?<!`)(`+)(?!`)(?:.*?[^`])??\1(?!`)')
ID_RX = re.compile(r'\b(BD?\d+[a-z]?)\b')   # r31 prep: B252c-style sub-rows too
ROW_ID = re.compile(r'BD?\d+[a-z]?')
SCRATCH_RX = re.compile(r'<scratch>|/private/tmp/|^/|^~')


def read(p):
    try:
        return Path(p).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return None


def rlabel(rid):
    """'r24' -> '24', 'R23c' -> '23c'. Pure."""
    rid = str(rid or '')
    return rid[1:] if rid[:1] in 'rR' else rid


def lead_class(cell):
    """the class of a status cell's LEAD (its first status word). Pure."""
    m = LEAD_RX.match(str(cell or '').strip())
    if not m:
        return 'open'
    w = m.group(1)
    if w == 'IMPLEMENTED':
        return 'implemented'
    if w == 'BACKEND READY':
        return 'backend'
    return 'closed'


def status_class(s):
    """the class of a closure's new_status (same words as a lead). Pure."""
    return lead_class(s)


def body_rank(cell):
    """the strongest status the cell states AFTER its lead: bold **CONFIRMED/CLOSED/FIXED/REFUTED** = closed, PAGES
    IMPLEMENTED = implemented; (rank, word) or (None, None). Pure."""
    best = (None, None)
    # r30 (B233): a `code span` quotes a status (a row naming the KAT input `**r29: FIXED:**`), it does not state one
    cell = CODE_SPAN_RX.sub(lambda m: ' ' * len(m.group(0)), str(cell or ''))
    for m in BOLD_RX.finditer(cell):
        if cell[:m.start()].strip(' *`_'):           # not the lead itself
            return RANK['closed'], m.group(1)
    for m in PAGES_RX.finditer(cell):
        if cell[:m.start()].strip(' *`_'):
            best = (RANK['implemented'], 'PAGES IMPLEMENTED')
    return best


def md_section(lines, rx):
    """(first line number 1-based, lines) of the '## ' section whose heading matches rx; (None, []) if absent. Pure."""
    r = re.compile(rx)
    for i, l in enumerate(lines):
        if l.startswith('## ') and r.search(l):
            j = next((k for k in range(i + 1, len(lines)) if lines[k].startswith('## ')), len(lines))
            return i + 1, lines[i:j]
    return None, []


def row_cells(line):
    """the cells of one markdown table row, split on UNESCAPED pipes; a 5-column §7 row (#, item, dimension, evidence,
    status) whose status text holds a bare pipe (R26 B105 'node|network') keeps that text in its status cell: the
    status is everything from the fifth cell on (coherence.rft_backlog took the last fragment). Pure."""
    cells = [c.strip() for c in re.split(r'(?<!\\)\|', line.strip().strip('|'))]
    if len(cells) > 5:
        cells = cells[:4] + [' | '.join(cells[4:])]
    return cells


def backlog_rows(text):
    """{id: {'line', 'cells', 'status'}} of the §7 table. Pure."""
    ls = text.splitlines()
    ln, sec = md_section(ls, r'^## 7\.|Consolidated OPEN backlog')
    out = {}
    for k, l in enumerate(sec):
        if not l.startswith('|'):
            continue
        cells = row_cells(l)
        if len(cells) >= 3 and ROW_ID.fullmatch(cells[0]):
            out[cells[0]] = {'line': ln + k, 'cells': cells, 'status': cells[-1]}
    return out


def s13_confirmed(text):
    """{id: [line, ...]} that a §13 measurement section records CONFIRMED live: the ids inside a
    '**CONFIRMED live:** …' span (to the next '**'), the id of a '**<id> CONFIRMED live:**' label, and the ids in the
    first cell of a §13 table row whose next cell starts '**CONFIRMED live**'. Pure."""
    ls = text.splitlines()
    ln, sec = md_section(ls, r'^## 13\.')
    out = {}

    def add(i, ids):
        for x in ids:
            out.setdefault(x, []).append(ln + i)
    for i, l in enumerate(sec):
        for m in re.finditer(r'\*\*CONFIRMED live:\*\*(.*?)(?=\*\*|$)', l):
            add(i, ID_RX.findall(m.group(1)))
        for m in re.finditer(r'\*\*(BD?\d+) CONFIRMED live', l):
            add(i, [m.group(1)])
        cells = [c.strip() for c in l.strip().strip('|').split('|')] if l.startswith('|') else []
        if len(cells) >= 2 and cells[1].startswith('**CONFIRMED live**'):
            add(i, ID_RX.findall(cells[0]))
    return out


class Ctx:
    def __init__(self, root, rft_path=None, closures_path=None, inventory_path=None):
        self.root = Path(root)
        self.rft_rel = 'artifacts/dero-rft.md'
        self.rft_path = Path(rft_path) if rft_path else self.root / self.rft_rel
        self.rft = read(self.rft_path)
        if self.rft is None:
            raise OSError(f'{self.rft_path} unreadable')
        self.reg = json.loads((self.root / 'harness/round.json').read_text(encoding='utf-8'))
        self.cur = self.reg['current']
        self.rounds = self.reg['rounds']
        self.rcur = next(r for r in self.rounds if r['id'] == self.cur)
        self.closures_path = Path(closures_path) if closures_path else self.root / f'harness/loop/backlog_closures_{self.cur}.json'
        self.inventory_path = Path(inventory_path) if inventory_path else None
        self.drifts, self.facts, self.notes = [], 0, []
        self.rows = backlog_rows(self.rft)

    def drift(self, check, f, line, expected, found, source):
        self.drifts.append({'check': check, 'file': f, 'line': line, 'expected': str(expected), 'found': str(found),
                            'source': source})


# ───────────────────────────── rows ─────────────────────────────
def check_rows(c):
    conf = s13_confirmed(c.rft)
    for bid, r in c.rows.items():
        st = r['status']
        lc = lead_class(st)
        c.facts += 1
        br, word = body_rank(st)
        if br is not None and br > RANK[lc]:
            c.drift('rows', c.rft_rel, r['line'], f'{bid} lead at least {word} (the row states it)', f'{bid} lead {lc}: {st[:60]}',
                    'the §7 row itself (R1 lead-stale)')
        if bid in conf and lc in ('implemented', 'backend'):     # an open lead may be a PARTIAL confirmation (B36)
            c.drift('rows', c.rft_rel, r['line'], f'{bid} CLOSED-class (§13 CONFIRMED live at line {conf[bid][0]})',
                    f'{bid} lead {lc}: {st[:60]}', f'{c.rft_rel}:{conf[bid][0]} (§13, R2)')
        if re.match(r'^[\s*`]*(OPEN\s*·\s*)?PAUSED \(miner', st) and '§0.3' not in st:
            c.drift('rows', c.rft_rel, r['line'], f'{bid} PAUSED row cites §0.3 (the resume condition)', st[:60], '§0.3 (R3)')


# ───────────────────────────── header ─────────────────────────────
def check_header(c):
    ls = c.rft.splitlines()
    ids = [r['id'] for r in c.rounds]
    measured = [r['id'] for r in c.rounds if r.get('status') == 'measured']
    newest_measured = rlabel(measured[-1]) if measured else None
    i = ids.index(c.cur)
    opened = c.rcur.get('status') in ('in-progress', 'implemented', 'shipped', 'measured')
    if c.rcur.get('status') in ('planned', 'in-progress', 'implemented', 'shipped'):
        nxt = rlabel(c.cur)
    else:
        nxt = rlabel(ids[i + 1]) if i + 1 < len(ids) else None
    merged = [r['id'] for r in c.rounds if re.fullmatch(r'[0-9a-f]{7,40}', str(r.get('merge_commit') or ''))]
    newest_merged = rlabel(merged[-1]) if merged else None
    hdr_end = next((k for k, l in enumerate(ls) if l.startswith('## ')), len(ls))
    for k, l in enumerate(ls[:hdr_end], 1):
        for m in re.finditer(r'\*\*Round (\d+[a-z]?) is measured\*\*', l):
            c.facts += 1
            if newest_measured and m.group(1) != newest_measured:
                c.drift('header', c.rft_rel, k, f'Round {newest_measured} is measured', f'Round {m.group(1)} is measured',
                        'harness/round.json newest measured round (H1)')
    hdr = ' '.join(re.sub(r'^>\s?', '', l) for l in ls[:hdr_end])     # the blockquote's '> ' breaks a phrase across lines
    for m in re.finditer(r'the next round to run is\s*\*\*Round (\d+[a-z]?)\*\*', hdr):
        c.facts += 1
        if nxt and m.group(1) != nxt:
            k = next((n for n, l in enumerate(ls[:hdr_end], 1) if f'Round {m.group(1)}**' in l and 'measured' not in l), None)
            c.drift('header', c.rft_rel, k, f'next round Round {nxt}', f'Round {m.group(1)}', 'harness/round.json current (H2)')
    heads = ((r'^## How to start \(Round (\d+[a-z]?)\b', 'H3'), (r'^## 1\. The prompt to paste \(Round (\d+[a-z]?)\)', 'H4'),
             (r'^## 8\. Round (\d+[a-z]?) dimension plan', 'H5'))
    # r28 Part D (B174): once the current round is implemented (or later) and the registry names the next one, §1 holds
    # the NEXT round's prompt, the rule coherence.py applies ('round' check, line 'want = rlabel(c.next) if c.done');
    # H4 had required the current round, so the two checkers could not both pass after an implementation.
    nxt_id = ids[i + 1] if i + 1 < len(ids) else None
    want_h4 = rlabel(nxt_id) if c.rcur.get('status') in ('implemented', 'shipped', 'measured') and nxt_id else rlabel(c.cur)
    for k, l in enumerate(ls, 1):
        for rx, h in heads:
            m = re.match(rx, l)
            if m:
                c.facts += 1
                want = want_h4 if h == 'H4' else rlabel(c.cur)
                if opened and m.group(1) != want:
                    c.drift('header', c.rft_rel, k, f'Round {want}', f'Round {m.group(1)}',
                            f'harness/round.json current {c.cur} ({c.rcur.get("status")}) ({h})')
        m = re.match(r'^## 7\. Consolidated OPEN backlog \(through the R(\d+[a-z]?) merge', l)
        if m:
            c.facts += 1
            if newest_merged and m.group(1) != newest_merged:
                c.drift('header', c.rft_rel, k, f'through the R{newest_merged} merge', f'R{m.group(1)}',
                        'harness/round.json newest merge_commit (H6)')


# ───────────────────────────── closures ─────────────────────────────
def goroot():
    try:
        return subprocess.run(['go', 'env', 'GOROOT'], capture_output=True, text=True, timeout=30).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def goversion():
    try:
        out = subprocess.run(['go', 'env', 'GOVERSION'], capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.match(r'go(\d+)\.(\d+)', out)
    return (int(m.group(1)), int(m.group(2))) if m else None


def premise_ok(root, p, gr=None, gv=None):
    """(ok, why) of one premise {kind, file, quote | version}. Pure apart from reading files."""
    kind = p.get('kind')
    if kind in ('repo_contains', 'goroot_contains'):
        base = Path(root) if kind == 'repo_contains' else (Path(gr) if gr else None)
        if base is None:
            return False, 'no GOROOT'
        t = read(base / str(p.get('file') or ''))
        if t is None:
            return False, f"{p.get('file')} unreadable"
        q = str(p.get('quote') or '')
        if len(q) < 6:
            return False, 'quote shorter than 6 characters'
        return (q in t), (f"{p.get('file')} holds the quote" if q in t else f"{p.get('file')} lost {q[:50]!r}")
    if kind == 'go_at_least':
        m = re.fullmatch(r'(\d+)\.(\d+)', str(p.get('version') or ''))
        if not m or gv is None:
            return False, 'no go version'
        need = (int(m.group(1)), int(m.group(2)))
        return gv >= need, f'go{gv[0]}.{gv[1]} vs >= go{need[0]}.{need[1]}'
    return False, f'unknown premise kind {kind!r}'


def check_closures(c):
    t = read(c.closures_path)
    rel = os.path.relpath(c.closures_path, c.root)
    if t is None:
        c.notes.append(f'no closure record {rel}: closures not checked')
        return
    rec = json.loads(t)
    gr, gv = None, None
    if any(p.get('kind') == 'goroot_contains' for x in rec.get('closures', []) for p in x.get('premises') or []):
        gr = goroot()
    if any(p.get('kind') == 'go_at_least' for x in rec.get('closures', []) for p in x.get('premises') or []):
        gv = goversion()
    seen = set()
    for x in rec.get('closures') or []:
        item, ns = x.get('item'), str(x.get('new_status') or '')
        c.facts += 1
        if not item or item in seen:
            c.drift('closures', rel, None, 'one closure per item', f'{item!r} missing or repeated', rel)
            continue
        seen.add(item)
        cls = status_class(ns)
        recs = x.get('records') or []
        if cls == 'closed' and not recs:
            c.drift('closures', rel, None, f'{item}: a CLOSED-class status names a record path', 'no records', 'C1')
        for p in recs:
            if SCRATCH_RX.search(str(p)) or not (c.root / str(p)).exists():
                c.drift('closures', rel, None, f'{item}: record {p} exists in the tree', 'missing or outside the tree', 'C1')
        for p in x.get('premises') or []:
            ok, why = premise_ok(c.root, p, gr, gv)
            if not ok:
                c.drift('closures', rel, None, f'{item}: premise {p.get("kind")} holds', why, 'C2')
        if ROW_ID.fullmatch(str(item)) and item in c.rows:
            r = c.rows[item]
            if lead_class(r['status']) != cls:
                c.drift('closures', c.rft_rel, r['line'], f'{item} {cls} (closure: {ns[:60]})',
                        f"{item} {lead_class(r['status'])}: {r['status'][:60]}", f'{rel} (C3)')
        for v in x.get('via_rows') or []:            # C5: a ledger item closed BY a §7 row needs that row closed
            r = c.rows.get(v)
            if r is None or lead_class(r['status']) != 'closed':
                c.drift('closures', c.rft_rel, r and r['line'], f'{item}: §7 {v} closed-class (via_rows)',
                        (r or {}).get('status', 'no row')[:60], f'{rel} (C5)')
        for v in x.get('dedup_into') or []:          # C5: a summary item deduplicated into rows needs those rows
            if v not in c.rows:
                c.drift('closures', c.rft_rel, None, f'{item}: §7 row {v} exists (dedup_into)', 'no row', f'{rel} (C5)')
        how = x.get('closable_how')
        if how == 'user-decision':
            dr = x.get('decision_request') or {}
            if not dr.get('question') or len(dr.get('options') or []) < 2 or not dr.get('evidence'):
                c.drift('closures', rel, None, f'{item}: decision_request with a question, >= 2 options and evidence',
                        json.dumps(dr)[:80], 'C4 (rft §0.1: never decide for the user)')
        if how == 'consensus-NO-GO' and ('REPORT-ONLY' not in ns or not x.get('upstream_anchor')):
            c.drift('closures', rel, None, f'{item}: REPORT-ONLY with an upstream design anchor', ns[:60], 'C4')


def check_inventory(c):
    if not c.inventory_path:
        return
    inv = json.loads(c.inventory_path.read_text(encoding='utf-8'))
    for x in inv:
        if x.get('closable_how') != 'obsolete-proof':
            continue
        for m in re.finditer(r'rft §7 (BD?\d+)\b[^;]*?\b(' + '|'.join(CLOSED_WORDS) + r')\b', str(x.get('evidence') or '')):
            c.facts += 1
            r = c.rows.get(m.group(1))
            if r is None or lead_class(r['status']) != 'closed':
                c.drift('inventory', c.rft_rel, r and r['line'], f"{m.group(1)} closed-class (cited by {x.get('item')})",
                        (r or {}).get('status', 'no row')[:60], str(c.inventory_path.name))


def run(root=ROOT, rft=None, closures=None, inventory=None, skip=()):
    c = Ctx(root, rft, closures, inventory)
    for k, fn in (('rows', check_rows), ('header', check_header), ('closures', check_closures), ('inventory', check_inventory)):
        if k not in skip:
            fn(c)
    return {'captured': datetime.datetime.now().astimezone().isoformat(timespec='seconds'), 'round': c.cur,
            'status': c.rcur.get('status'), 'rft': str(c.rft_path), 'rows': len(c.rows), 'facts': c.facts,
            'drifts': c.drifts, 'notes': c.notes, 'ok': not c.drifts}


def drifts_for_coherence(root=ROOT):
    """the drifts in coherence.py's shape (G25 'rows' check); [] when the registry or the rft is unreadable"""
    try:
        return run(root)['drifts']
    except (OSError, ValueError, KeyError, StopIteration):
        return []


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--root', default=str(ROOT))
    ap.add_argument('--rft', help='check this copy of dero-rft.md (e.g. with the round deltas applied)')
    ap.add_argument('--closures', help='the closure record (default harness/loop/backlog_closures_<current>.json)')
    ap.add_argument('--inventory', help='a closure inventory JSON list (Part A) to cross-check obsolete-proof entries')
    ap.add_argument('--skip', default='', help='comma list of checks to skip: ' + ','.join(CHECKS))
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--record', action='store_true', help='write harness/runtime/backlog_truth_<ts>.json + _last.json')
    a = ap.parse_args(argv)
    try:
        r = run(Path(a.root).resolve(), a.rft, a.closures, a.inventory, tuple(x for x in a.skip.split(',') if x))
    except (OSError, ValueError, KeyError, StopIteration) as e:
        print(f'backlog_truth: a canonical source is unreadable: {type(e).__name__}: {e}')
        return 2
    if a.record:
        rt = Path(a.root) / 'harness/runtime'
        ts = datetime.datetime.now().strftime('%Y%m%dT%H%M%S')
        out = {**r, 'rft': os.path.relpath(r['rft'], a.root) if str(r['rft']).startswith(str(Path(a.root).resolve())) else Path(r['rft']).name}
        for p in (rt / f'backlog_truth_{ts}.json', rt / 'backlog_truth_last.json'):
            p.write_text(json.dumps(out, indent=1) + '\n')
    if a.json:
        print(json.dumps(r, indent=1))
    else:
        for d in r['drifts']:
            print(f"DRIFT {d['check']:<9} {d['file']}:{d['line'] or '-'}  expected {d['expected']}  found {d['found']}  [{d['source']}]")
        for n in r['notes']:
            print(f'note  {n}')
        print(f"backlog truth {r['round']} ({r['status']}): {r['rows']} §7 rows, {r['facts']} statements, "
              f"{len(r['drifts'])} drift(s) · {'PASS' if r['ok'] else 'DRIFT'}")
    return 0 if r['ok'] else 4


if __name__ == '__main__':
    sys.exit(main())
