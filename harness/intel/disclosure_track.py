#!/usr/bin/env python3
"""disclosure_track.py — r24: the Foundation-disclosure track, re-tested every round (artifacts/dero-rft.md §0.5).

On 2026-10-20 the DERO Foundation published a range-proof soundness defect (harness/external/derofoundation-press-
20261020.txt). Round 8 audited it (harness/model/raw/forensics.json, ARCHITECTURE §25); R23/R23b re-tested the HF3
half (soundness page, G22). Until r24 nothing re-tested those verdicts when the tree moved: an anchor could drift or
vanish and the page kept drawing the R8 verdict. This tool makes the audit a per-round instrument.

Input: harness/loop/disclosure_track.json — per claim, one entry per round {round, verdict, state, why, anchors},
plus the round's new facts and the potential fixes (FORK-REQUIRED designs vs NODE-LOCAL measures, each with status).

  evaluate()   L1 every anchor {file, line, quote} is re-read: OK (the quote is on that line), DRIFT (it is on one
                  other line: reported with the new line, the claim must be re-read), MISSING / NOFILE / SHORT (FAIL:
                  the claim must be re-tested before it can render).
               L2 a verdict or state that differs from the claim's previous round must carry a `why` and at least one
                  resolving anchor outside harness/external (the EXT-under-audit rule: the advisory proves only that
                  it was said). The first entry of a claim must carry one too.
               L3 every claim has an entry for the track's current round (re-tested this round, or FAIL).
               L4 vocabularies: verdict, state, fact status, fix kind/status/feasible; a FORK-REQUIRED design must say
                  it needs a coordinated fork; an implemented NODE-LOCAL measure must cite where it is implemented.
               L6 every row of harness/model/raw/press.json is mapped in press_map to a track claim or to
                  "NOT-TESTED: <reason>" (r24: forensics and press number their claims differently, and five press
                  claims had no verdict row; a new Foundation claim cannot slip in untested).
               L5 no exploit content: every text of the track (and of the rendered pages with --pages) is linted
                  against EXPLOIT_PATTERNS (parameter choices for the proof's free scalar, forging procedures, step
                  lists). A match FAILS. The legacy R8 rows are linted too and reported as `legacy_lint` (they are
                  regenerated from a git-excluded audit transcript, so they are flagged for the round lead, not
                  rewritten here).
  emit_model() harness/model/raw/disclosure.json: one row per claim (history), per R24 fact and per fix, each with its
               anchors, for gen_deroarch's press section (no anchor, no row: its resolver drops an unanchored row).
  --live       read-only RPC on 127.0.0.1:10102 (Content-Type: application/json, B38): GetInfo, GetEmissionAudit,
               GetMonetaryIntegrity. Recomputes CalcSupply(height) from the tree's own constant lines and checks
               (S1) GetInfo.total_supply == CalcSupply(h) / 100000 — the published supply is the formula, so it would
               read the same on an inflated chain (forensics OPERATOR TAKEAWAY); (S2) the auditor's formula_supply ==
               CalcSupply(segment_to); (S3) GetMonetaryIntegrity.emission agrees with GetEmissionAudit on every shared
               field (CI24-1: the r23c integrity RPC published issued 0 / false while the auditor said true);
               (S4) the HF3 exemption window is closed. Writes harness/runtime/disclosure_live_<ts>.txt.
  --census N   read-only: the proofs of the transactions in the last N blocks, decoded here (transaction.go /
               proof_generate.go layout) and checked for scalar canonicality (every proof scalar < bn256.Order, read
               from cryptography/bn256/constants.go) and shape (IP rounds 7, |f| = 2·log2(ring)). Writes
               harness/runtime/disclosure_census_<ts>.json. A census can show NON-canonical encodings; it can NOT
               show a defective-witness proof (same shape, same encoding rules: forensics C1/C3).

  python3 -I harness/intel/disclosure_track.py [--check] [--emit-model] [--live] [--census N] [--pages] [--json OUT]
                                              [--rev REV [--rev-strict]] [--rebase-lines]
Exit 0 ok · 3 a check failed (also: a --live cross-check FAIL, a --census scalar >= Order) · 2 bad input.
"""
import argparse, datetime, hashlib, json, re, subprocess, sys, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
ROOT = HARNESS.parent
TRACK = HARNESS / 'loop/disclosure_track.json'
MODEL = HARNESS / 'model/raw/disclosure.json'
RUNTIME = HARNESS / 'runtime'
RPC = 'http://127.0.0.1:10102/json_rpc'

VERDICTS = ('CONFIRMED', 'PARTLY-CONFIRMED', 'REFUTED', 'CANNOT-DETERMINE-LOCALLY', 'NOT-TESTED', 'pending')
STATES = ('open', 'fixed-node-local', 'closed-by-design', 'report-only', 'upstream', 'pending')
FACT_STATUS = ('CONFIRMED', 'MEASURED', 'PLAUSIBLE', 'pending')
FIX_KINDS = ('FORK-REQUIRED', 'NODE-LOCAL')
FIX_STATUS = ('design', 'implemented', 'implemented-earlier', 'feasible-not-implemented', 'infeasible', 'pending')
ANCHOR_OK = ('OK', 'DRIFT')
EXTERNAL = 'harness/external/'
MIN_QUOTE = 12

# Exploit-content lint (dero-rft §5: no exploit content for the range-proof defect or any inflation technique). The
# patterns target PROCEDURAL or PARAMETRIC text (a value choice for the free scalar, a construction procedure, a step
# list), not the defensive vocabulary the audit needs ("μ is in no preimage", "what must be bound"). Each one is proved
# by a KAT (harness/kat/test_disclosure_track_r24.py DT4).
EXPLOIT_PATTERNS = [
    ('free-scalar choice', r'\b(choos\w*|pick\w*|select\w*|solv\w*|tun\w*|adjust\w*)\s+(the\s+|a\s+)?(proof\.)?(mu|μ|blinding scalar)\b'),
    ('free-scalar formula', r'(?<![\w.])(proof\.)?(mu|μ)\s*(:=|=|←)\s*\S'),
    ('forging procedure', r'\b(how\s+to|steps?\s+to|in\s+order\s+to|we\s+can|you\s+can|one\s+can|attackers?\s+can|prover\s+can)\s+'
                          r'(forge|build|construct|craft|make)\s+(a|an|the)?\s*(\w+\s+)?(proof|transfer|witness|transaction)s?\b'),
    ('witness recipe', r'\b(adversarial|malicious|bad|invalid)\s+witness\s+(construction|recipe|generation|for)\b'),
    ('step list', r'\bstep\s*\d+\s*[:.)]\s*[^.]{0,80}\b(mu|μ|witness|out-of-range|bits?|that|t̂)\b'),
    ('out-of-range recipe', r'\bout[- ]of[- ]range\s+(bits?|values?|amounts?)\b[^.]{0,50}\b(then|so that|and set|encode|commit)\b'),
    ('exploit artefact', r'\b(here\s+is|below\s+is|the\s+following|attached|a\s+working|our)\s+(proof[- ]of[- ]concept|PoC|exploit)\b'
                         r'|\bexploit\s+(code|script|recipe|steps|procedure)\b'),
    ('inflation recipe', r'\b(how\s+to|in\s+order\s+to)\s+(mint|inflate|create)\b[^.]{0,40}\b(coins?|DERO|supply|value)\b'),
]
_EXPLOIT = [(n, re.compile(p, re.I)) for n, p in EXPLOIT_PATTERNS]

TYPO = str.maketrans({'‘': "'", '’': "'", '“': '"', '”': '"', '–': '-', '—': '-', ' ': ' ', '…': '...'})


def norm(s):
    """gen_deroarch.norm: whitespace runs and typographic quotes, nothing else"""
    return re.sub(r'\s+', ' ', str(s or '').translate(TYPO)).strip()


# ───────────────────────────── anchors ─────────────────────────────
_LC = {}
REV_FALLBACK = True     # --rev: files absent at rev are read from the worktree (--rev-strict turns it off)


def file_lines(rel, root=ROOT, rev=None):
    """the file's lines from disk (rev None) or from `git show rev:rel` (a later round re-reads at its own head)"""
    key = (str(root), rel, rev)
    if key not in _LC:
        try:
            if rev:
                out = subprocess.run(['git', 'show', f'{rev}:{rel}'], cwd=root, capture_output=True, timeout=30)
                _LC[key] = out.stdout.decode(errors='replace').splitlines() if out.returncode == 0 else None
                if _LC[key] is None and REV_FALLBACK and (root / rel).is_file():
                    # a file this patch adds (or a runtime capture) is not at rev: read it from the worktree, as the
                    # rebased tree will hold it
                    _LC[key] = (root / rel).read_text(errors='replace').splitlines()
            else:
                p = Path(rel).expanduser() if rel.startswith('~') else (Path(rel) if Path(rel).is_absolute() else root / rel)
                _LC[key] = p.read_text(errors='replace').splitlines()
        except (OSError, subprocess.SubprocessError):
            _LC[key] = None
    return _LC[key]


def resolve(a, root=ROOT, rev=None):
    """{file, line, quote} -> status OK | DRIFT (on one other line) | MULTI (not on its line, on several) | MISSING |
    NOFILE | SHORT, with the line(s) where the quote is now"""
    rel, q, line = str(a.get('file') or ''), norm(a.get('quote')), a.get('line')
    out = {'file': rel, 'line': line, 'quote': a.get('quote')}
    if len(q) < MIN_QUOTE:
        return {**out, 'status': 'SHORT'}
    ls = file_lines(rel, root, rev)
    if ls is None:
        return {**out, 'status': 'NOFILE'}
    hits = [i + 1 for i, l in enumerate(ls) if q in norm(l)]
    if not hits:
        return {**out, 'status': 'MISSING'}
    if isinstance(line, int) and line in hits:
        return {**out, 'status': 'OK', 'now': line}
    if len(hits) == 1:
        return {**out, 'status': 'DRIFT', 'now': hits[0]}
    return {**out, 'status': 'MULTI', 'now': hits[:5]}


def is_external(a):
    return str(a.get('file') or '').startswith(EXTERNAL)


# ───────────────────────────── lint ─────────────────────────────
def texts(o, path=''):
    """every string inside o, with its JSON path. An anchor's `quote` is skipped: it must resolve verbatim to a line of
    the tree (L1), so it cannot carry text the track invented — and the honest prover's own lines (e.g. the line that
    computes the blinding response) would otherwise read as a formula"""
    if isinstance(o, str):
        yield path, o
    elif isinstance(o, dict):
        for k, v in o.items():
            if k == 'quote' and 'file' in o:
                continue
            yield from texts(v, f'{path}.{k}' if path else str(k))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from texts(v, f'{path}[{i}]')


def lint_text(s):
    return [n for n, rx in _EXPLOIT if rx.search(str(s))]


def lint(o, where):
    hits = []
    for p, s in texts(o):
        for n in lint_text(s):
            hits.append({'where': f'{where}:{p}', 'pattern': n, 'text': s[:160]})
    return hits


# ───────────────────────────── evaluate ─────────────────────────────
def round_index(track):
    return {r: i for i, r in enumerate(track.get('rounds') or [])}


def evaluate(track, root=ROOT, rev=None, legacy=None, pages=None):
    why, drift, bad, resolved = [], [], [], []
    ri = round_index(track)
    cur = track.get('current_round')
    if cur not in ri:
        why.append(f'current_round {cur!r} is not in rounds {track.get("rounds")}')

    def anchors_of(where, anchors):
        rs = []
        for a in anchors or []:
            r = resolve(a, root, rev)
            r['where'] = where
            rs.append(r)
            resolved.append(r)
            if r['status'] == 'DRIFT':
                drift.append(r)
            elif r['status'] not in ANCHOR_OK:
                bad.append(r)
        return rs

    claims = track.get('claims') or []
    seen = set()
    for c in claims:
        cid = c.get('id')
        if not cid or cid in seen:
            why.append(f'claim id {cid!r} missing or repeated')
            continue
        seen.add(cid)
        hist = c.get('history') or []
        if not hist:
            why.append(f'{cid}: no history')
            continue
        order = [ri.get(h.get('round'), -1) for h in hist]
        if order != sorted(order) or len(set(order)) != len(order) or -1 in order:
            why.append(f'{cid}: history rounds {[h.get("round") for h in hist]} not in track order / unknown / repeated')
        prev = None
        for h in hist:
            tag = f'{cid}@{h.get("round")}'
            if h.get('verdict') not in VERDICTS:
                why.append(f'{tag}: verdict {h.get("verdict")!r} not in {VERDICTS}')
            if h.get('state') not in STATES:
                why.append(f'{tag}: state {h.get("state")!r} not in {STATES}')
            rs = anchors_of(tag, h.get('anchors'))
            own = [r for r in rs if r['status'] in ANCHOR_OK and not is_external(r)]
            changed = prev is None or (h.get('verdict'), h.get('state')) != (prev.get('verdict'), prev.get('state'))
            if changed and h.get('verdict') != 'pending':
                if not own:
                    why.append(f'{tag}: verdict/state {"set" if prev is None else "changed"} '
                               f'({(prev or {}).get("verdict")}/{(prev or {}).get("state")} -> {h.get("verdict")}/{h.get("state")}) '
                               f'without a resolving non-EXT anchor')
                if len(norm(h.get('why'))) < 20:
                    why.append(f'{tag}: verdict/state changed without a why')
            prev = h
        if cur in ri and not any(h.get('round') == cur for h in hist):
            why.append(f'{cid}: not re-tested in the current round {cur}')
    for f in track.get('facts') or []:
        tag = f'fact {f.get("id")}'
        if f.get('status') not in FACT_STATUS:
            why.append(f'{tag}: status {f.get("status")!r} not in {FACT_STATUS}')
        rs = anchors_of(tag, f.get('anchors'))
        if f.get('status') != 'pending' and not [r for r in rs if r['status'] in ANCHOR_OK and not is_external(r)]:
            why.append(f'{tag}: {f.get("status")} without a resolving non-EXT anchor')
        for cl in f.get('claims') or []:
            if cl not in seen:
                why.append(f'{tag}: names unknown claim {cl}')
    for x in track.get('fixes') or []:
        tag = f'fix {x.get("id")}'
        if x.get('kind') not in FIX_KINDS:
            why.append(f'{tag}: kind {x.get("kind")!r} not in {FIX_KINDS}')
        if x.get('status') not in FIX_STATUS:
            why.append(f'{tag}: status {x.get("status")!r} not in {FIX_STATUS}')
        if x.get('feasible') not in (True, False, 'pending'):
            why.append(f'{tag}: feasible must be true, false or "pending"')
        if x.get('kind') == 'FORK-REQUIRED':
            if 'coordinated' not in norm(x.get('design')).lower() and 'coordinated' not in norm(x.get('compat')).lower():
                why.append(f'{tag}: a FORK-REQUIRED design must state that it needs a coordinated fork')
            if x.get('status') in ('implemented', 'implemented-earlier'):
                why.append(f'{tag}: a FORK-REQUIRED change cannot be implemented node-locally')
        rs = anchors_of(tag, x.get('anchors'))
        if not [r for r in rs if r['status'] in ANCHOR_OK]:
            why.append(f'{tag}: no resolving anchor')
        if x.get('status') in ('implemented', 'implemented-earlier') and not x.get('implemented_in'):
            why.append(f'{tag}: implemented without implemented_in (the file that implements it)')
        if x.get('status') == 'infeasible' and x.get('feasible') is not False:
            why.append(f'{tag}: status infeasible but feasible is {x.get("feasible")!r}')
        for cl in x.get('claims') or []:
            if cl not in seen:
                why.append(f'{tag}: names unknown claim {cl}')
    pm = track.get('press_map') or {}
    for pid, tgt in pm.items():
        if not (tgt in seen or str(tgt).startswith('NOT-TESTED:')):
            why.append(f'press_map {pid} -> {tgt!r}: neither a track claim nor "NOT-TESTED: <reason>"')
    for r in ((legacy or {}).get('press') or {}).get('rows') or []:
        if r.get('id') not in pm:
            why.append(f'press row {r.get("id")} has no press_map entry: a new Foundation claim must be mapped (L6)')
    for r in bad:
        why.append(f'anchor {r["status"]} {r["file"]}:{r["line"]} ({r["where"]}): re-test the claim')
    hits = lint(track, 'track')
    for k, v in (pages or {}).items():
        for n in lint_text(v):
            hits.append({'where': f'page:{k}', 'pattern': n, 'text': ''})
    for h in hits:
        why.append(f'exploit-like content ({h["pattern"]}) at {h["where"]}')
    leg = []
    for k, doc in (legacy or {}).items():
        for r in (doc or {}).get('rows') or []:
            for p, s in texts({kk: vv for kk, vv in r.items() if kk in ('title', 'claim', 'reasoning', 'what', 'said')}):
                for n in lint_text(s):
                    leg.append({'where': f'{k}:{r.get("id")}.{p}', 'pattern': n})
    st = {}
    for r in resolved:
        st[r['status']] = st.get(r['status'], 0) + 1
    return {'ok': not why, 'why': why, 'rev': rev or 'worktree', 'current_round': cur, 'claims': len(claims),
            'facts': len(track.get('facts') or []), 'fixes': len(track.get('fixes') or []),
            'anchors': len(resolved), 'anchor_status': st,
            'drift': [{k: r[k] for k in ('where', 'file', 'line', 'now')} for r in drift],
            'bad': [{k: r.get(k) for k in ('where', 'file', 'line', 'status', 'now')} for r in bad],
            'lint_hits': hits, 'legacy_lint': leg}


def rebase_lines(track, rep_drift):
    """--rebase-lines: move the line of a DRIFTed anchor to where its quote is now, for the CURRENT round's entries,
    facts and the fixes only. Earlier rounds keep the line they cited (their drift stays visible as history). Never
    touches a MISSING anchor: a vanished quote means re-test, not renumber. Returns the number of lines moved."""
    cur, moved = track.get('current_round'), 0
    groups = [h.get('anchors') or [] for c in track.get('claims') or [] for h in c.get('history') or [] if h.get('round') == cur]
    groups += [f.get('anchors') or [] for f in track.get('facts') or [] if f.get('round') == cur]
    groups += [x.get('anchors') or [] for x in track.get('fixes') or []]
    for anchors in groups:
        for a in anchors:
            r = resolve(a)
            if r['status'] == 'DRIFT':
                a['line'] = r['now']
                moved += 1
    return moved


def latest(c):
    return (c.get('history') or [{}])[-1]


# ───────────────────────────── model rows for gen_deroarch ─────────────────────────────
def page_class(rel, root=ROOT):
    """the src-arch class of a path (prep_corpus.class_of): harness code and loop files have none, so the page's resolver
    would count them as unresolved anchors; the model carries only anchors the page can class (the track keeps all)"""
    sys.path.insert(0, str(root / 'harness'))
    try:                       # no fallback: a harness without prep_corpus cannot class anything, and must say so
        from prep_corpus import class_of
        return class_of(root / rel)
    finally:
        sys.path.pop(0)


def _ev(anchors, root=ROOT):
    return [{'file': a['file'], 'quote': a['quote'], 'line': a.get('line')} for a in anchors or []
            if a.get('file') and page_class(a['file'], root)]


def emit_model(track, root=ROOT):
    rows = []
    rounds = track.get('rounds') or []
    for c in track.get('claims') or []:
        lt = latest(c)
        hist = {h['round']: {'verdict': h.get('verdict'), 'state': h.get('state'), 'why': h.get('why', '')}
                for h in c.get('history') or []}
        rows.append({'id': f'dt-claim-{c["id"].lower()}', 'section': 'disclosure', 'kind': 'track-claim',
                     'class': 'SRC', 'title': f'{c["id"]} — {c.get("title", "")}', 'claim': lt.get('why', ''),
                     'press_ids': c.get('press') or [], 'track_id': c['id'], 'history': hist, 'rounds': rounds,
                     'verdict_now': lt.get('verdict'), 'state_now': lt.get('state'),
                     'evidence': _ev(lt.get('anchors'), root)})
    for f in track.get('facts') or []:
        rows.append({'id': f'dt-fact-{f["id"].lower()}', 'section': 'disclosure', 'kind': 'track-fact', 'class': 'SRC',
                     'title': f'{f["id"]} — {f.get("title", "")}', 'claim': f.get('text', ''),
                     'round': f.get('round'), 'status': f.get('status'), 'claims': f.get('claims') or [],
                     'all_anchors': bool(f.get('all_anchors')), 'evidence': _ev(f.get('anchors'), root)})
    for x in track.get('fixes') or []:
        rows.append({'id': f'dt-fix-{x["id"].lower()}', 'section': 'disclosure', 'kind': 'track-fix', 'class': 'SRC',
                     'title': f'{x["id"]} — {x.get("title", "")}', 'claim': x.get('design', ''),
                     'fix_kind': x.get('kind'), 'status': x.get('status'), 'feasible': x.get('feasible'),
                     'verify': x.get('verify', ''), 'compat': x.get('compat', ''), 'claims': x.get('claims') or [],
                     'implemented_in': x.get('implemented_in', ''), 'evidence': _ev(x.get('anchors'), root)})
    return {'key': 'disclosure', 'generated_by': 'harness/intel/disclosure_track.py --emit-model',
            'track_sha': hashlib.sha256(json.dumps(track, sort_keys=True).encode()).hexdigest()[:16],
            'rows': rows, 'unverified': []}


def model_current(track, model_doc, root=ROOT):
    return bool(model_doc) and model_doc == emit_model(track, root)


# ───────────────────────────── live, read-only ─────────────────────────────
def rpc(method, params=None, url=RPC, timeout=15):
    body = {'jsonrpc': '2.0', 'id': 1, 'method': method}
    if params is not None:
        body['params'] = params
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.loads(r.read().decode())
    if 'error' in d and d['error']:
        raise RuntimeError(f'{method}: {d["error"]}')
    return d.get('result')


def _const(rel, rx, root=ROOT, rev=None):
    for i, l in enumerate(file_lines(rel, root, rev) or []):
        m = re.search(rx, l)
        if m:
            return m, i + 1
    raise LookupError(f'{rel}: no line matches {rx}')


def supply_formula(root=ROOT, rev=None):
    """CalcSupply as the tree states it, read from its own lines (a refactor that moves them fails loudly, not silently):
    PREMINE + the hard-coded claim credit + sum over halving epochs of CalcBlockReward(epoch start) x blocks"""
    pm, lp = _const('config/config.go', r'const PREMINE uint64 = (\d+)', root, rev)
    bt, lb = _const('config/config.go', r'const BLOCK_TIME = uint64\((\d+)\)', root, rev)
    cr, lc = _const('blockchain/supply.go', r'supply \+= (\d+)$', root, rev)
    ri, lr = _const('blockchain/transaction_execute.go', r'const RewardReductionInterval = (\d+) \* (\d+) / config\.BLOCK_TIME', root, rev)
    br, lbr = _const('blockchain/transaction_execute.go', r'const BaseReward = \((\d+) \* (\d+) \* config\.BLOCK_TIME\) / (\d+)', root, rev)
    _const('blockchain/transaction_execute.go', r'return BaseReward >> \(\(height \+ RewardReductionInterval\) / RewardReductionInterval\)', root, rev)
    T = int(bt.group(1))
    RRI = int(ri.group(1)) * int(ri.group(2)) // T
    BASE = (int(br.group(1)) * int(br.group(2)) * T) // int(br.group(3))
    PRE, CRED = int(pm.group(1)), int(cr.group(1))

    def reward(h):
        return BASE >> ((h + RRI) // RRI)

    def calc(height):
        s, rem, ep = PRE + CRED, height, 0
        while rem > 0:
            n = min(RRI, rem)
            s += reward(ep) * n
            rem -= n
            ep += RRI
        return s
    src = {'PREMINE': f'config/config.go:{lp}', 'BLOCK_TIME': f'config/config.go:{lb}', 'credit': f'blockchain/supply.go:{lc}',
           'RewardReductionInterval': f'blockchain/transaction_execute.go:{lr}', 'BaseReward': f'blockchain/transaction_execute.go:{lbr}'}
    return calc, {'PREMINE': PRE, 'credit': CRED, 'RRI': RRI, 'BaseReward': BASE, 'src': src}


SHARED_EMISSION = ('enabled', 'status', 'audited', 'alerts', 'segment_from', 'segment_to', 'observed_emission',
                   'formula_emission', 'emission_consistent', 'formula_supply', 'issued_emission',
                   'issued_matches_formula', 'payees', 'payees_verified', 'payees_explained', 'burns', 'gaps', 'reorgs')


def live_checks(info, audit, integ, calc):
    """(checks, ok) — pure; the KAT feeds forged readings"""
    out = []
    h = int(info.get('height') or 0)
    want = calc(h) // 100000
    out.append(('S1 GetInfo.total_supply is the formula', info.get('total_supply') == want,
                f'height {h}: total_supply {info.get("total_supply")} vs CalcSupply(h)/100000 = {want}'))
    st = audit.get('segment_to')
    if isinstance(st, int):
        out.append(('S2 auditor formula_supply == CalcSupply(segment_to)', audit.get('formula_supply') == calc(st),
                    f'segment_to {st}: formula_supply {audit.get("formula_supply")} vs {calc(st)}'))
    em = (integ or {}).get('emission') or {}
    diff = [k for k in SHARED_EMISSION if k in audit and k in em and audit[k] != em[k]]
    miss = [k for k in SHARED_EMISSION if k in audit and k not in em]
    out.append(('S3 GetMonetaryIntegrity.emission agrees with GetEmissionAudit', not diff and not miss,
                'disagree: ' + ', '.join(f'{k} audit={audit[k]} integrity={em[k]}' for k in diff)
                + (f'; integrity lacks {miss}' if miss else '') if (diff or miss) else
                f'{len([k for k in SHARED_EMISSION if k in audit])} shared fields equal'))
    hx = (integ or {}).get('hf3_exemption') or {}
    out.append(('S4 HF3 exemption window closed', hx.get('window_closed') is True and hx.get('all_below_hf3') is True,
                f'entries {hx.get("entries")}, heights {hx.get("min_height")}..{hx.get("max_height")} < hf3 '
                f'{hx.get("hf3_height")}, last_includable {hx.get("last_includable_height")}, chain {hx.get("chain_height")}, '
                f'window_closed {hx.get("window_closed")}'))
    return out, all(ok for _, ok, _ in out)


def run_live(root=ROOT, get=rpc):
    calc, consts = supply_formula(root)
    when = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    info, audit, integ = get('DERO.GetInfo'), get('DERO.GetEmissionAudit'), get('DERO.GetMonetaryIntegrity')
    checks, ok = live_checks(info, audit, integ, calc)
    em = (integ or {}).get('emission') or {}
    hx = (integ or {}).get('hf3_exemption') or {}
    lines = [f'disclosure_track live read {when} (read-only RPC 127.0.0.1:10102, Content-Type: application/json)',
             f'getinfo.version {info.get("version")}', f'getinfo.height {info.get("height")}',
             f'getinfo.total_supply {info.get("total_supply")}',
             f'calcsupply.recomputed {calc(int(info.get("height") or 0))} (consts {json.dumps(consts["src"], sort_keys=True)})']
    lines += [f'audit.{k} {audit.get(k)}' for k in SHARED_EMISSION if k in audit]
    lines += [f'integrity.emission.{k} {em.get(k)}' for k in SHARED_EMISSION if k in em]
    lines += [f'integrity.hf3_exemption.{k} {hx.get(k)}' for k in ('entries', 'min_height', 'max_height', 'hf3_height',
                                                                   'all_below_hf3', 'tx_parity_true', 'parity_true',
                                                                   'last_includable_height', 'window_closed', 'digest')]
    lines += [f'check {"PASS" if c_ok else "FAIL"} {n}: {d}' for n, c_ok, d in checks]
    RUNTIME.mkdir(exist_ok=True)
    out = RUNTIME / f'disclosure_live_{when}.txt'
    out.write_text('\n'.join(lines) + '\n')
    return {'file': str(out.relative_to(ROOT)), 'ok': ok, 'checks': checks, 'consts': consts}


# ───────────────────────────── proof-scalar census, read-only ─────────────────────────────
def bn256_order(root=ROOT, rev=None):
    m, ln = _const('cryptography/bn256/constants.go', r'var Order = bigFromBase10\("(\d+)"\)', root, rev)
    return int(m.group(1)), f'cryptography/bn256/constants.go:{ln}'


def payload_limit(root=ROOT, rev=None):
    m, ln = _const('transaction/transaction.go', r'const PAYLOAD_LIMIT = 1 \+ (\d+)', root, rev)
    return 1 + int(m.group(1)), f'transaction/transaction.go:{ln}'


class Rd:
    def __init__(self, b):
        self.b, self.i = b, 0

    def take(self, n):
        if self.i + n > len(self.b):
            raise ValueError('short read')
        s = self.b[self.i:self.i + n]
        self.i += n
        return s

    def uvarint(self):
        x = s = 0
        while True:
            c = self.take(1)[0]
            x |= (c & 0x7f) << s
            if c < 0x80:
                return x
            s += 7
            if s > 63:
                raise ValueError('uvarint overflow')


def tx_types(root=ROOT, rev=None):
    """the TransactionType iota order, read from transaction/transaction.go (r24: a typed tuple had BURN_TX and NORMAL
    swapped, which labelled 58 mainnet NORMAL transfers as BURN_TX — the order is the tree's, never re-typed)"""
    _, ln = _const('transaction/transaction.go', r'^\s*PREMINE\s+TransactionType = iota', root, rev)
    names = []
    for l in (file_lines('transaction/transaction.go', root, rev) or [])[ln - 1:ln + 12]:
        m = re.match(r'\s*([A-Z_]+)\b', l)
        if not m or m.group(1) == ')':
            break
        names.append(m.group(1))
    return tuple(names), f'transaction/transaction.go:{ln}'


TX_TYPES = ('PREMINE', 'REGISTRATION', 'COINBASE', 'NORMAL', 'BURN_TX', 'SC_TX')   # transaction.go:33-38; tx_types() re-reads


def parse_tx_proofs(raw, plimit=145, types=TX_TYPES):
    """the scalar fields and shape of each payload proof of one serialized tx (transaction.go Deserialize,
    protocol_structures.go Statement.Deserialize, proof_generate.go Proof.Deserialize, proof_innerproduct.go
    InnerProduct.Deserialize). Returns {type, payloads: [{ring, m, ip_rounds, scalars: {name: int}}]} or raises."""
    r = Rd(raw)
    if r.uvarint() != 1:
        raise ValueError('version != 1')
    r.uvarint(); r.uvarint()
    tt = r.uvarint()
    if tt >= len(types):
        raise ValueError(f'type {tt}')
    t = types[tt]
    if t in ('PREMINE', 'SC_TX'):
        r.uvarint()
    if t in ('PREMINE', 'COINBASE', 'REGISTRATION'):
        r.take(33)
    if t == 'REGISTRATION':
        r.take(64)
    if t not in ('BURN_TX', 'NORMAL', 'SC_TX'):
        return {'type': t, 'payloads': []}
    r.uvarint(); r.take(32)
    n = r.uvarint()
    rings = []
    for _ in range(n):
        r.uvarint(); r.take(32); r.take(1); r.take(plimit)          # burn, scid, rpctype, rpcpayload
        lg = r.take(1)[0]
        ring = 1 << lg
        if ring > 128:
            raise ValueError('ring too large')
        bpp = r.take(1)[0]
        r.uvarint(); r.take(33)                                      # fees, D
        r.take(ring * bpp)                                           # pointers
        r.take(33 * ring)                                            # C
        r.take(32)                                                   # roothash
        rings.append((ring, bpp))
    if t == 'SC_TX':
        r.take(r.uvarint())
    pays = []
    for ring, bpp in rings:
        m = ring.bit_length() - 1                                    # GetPowerof2(len(pointers)/bpp) = log2(ring)
        r.take(4 * 33)
        r.take(8 * 33 * m)
        r.take(33)                                                   # u
        sc = {f'f[{j}]': int.from_bytes(r.take(32), 'big') for j in range(2 * m)}
        sc['z_A'] = int.from_bytes(r.take(32), 'big')
        r.take(2 * 33)                                               # T_1, T_2
        for k in ('that', 'mu', 'c', 's_sk', 's_r', 's_b', 's_tau'):
            sc[k] = int.from_bytes(r.take(32), 'big')
        sc['ip.a'] = int.from_bytes(r.take(32), 'big')
        sc['ip.b'] = int.from_bytes(r.take(32), 'big')
        r.take(7 * 2 * 33)                                           # 7 IP rounds, L and R
        pays.append({'ring': ring, 'm': m, 'ip_rounds': 7, 'scalars': sc})
    if r.i != len(raw):
        raise ValueError(f'{len(raw) - r.i} trailing bytes')
    return {'type': t, 'payloads': pays}


def census_of(txs, order, plimit=145, types=TX_TYPES):
    """pure: {txs, payloads, scalars, noncanonical: [{txid, payload, field}], parse_errors, types}"""
    out = {'txs': 0, 'payloads': 0, 'scalars': 0, 'noncanonical': [], 'parse_errors': [], 'types': {}}
    for txid, raw in txs:
        try:
            p = parse_tx_proofs(raw, plimit, types)
        except (ValueError, IndexError) as e:
            out['parse_errors'].append({'txid': txid, 'why': str(e)})
            continue
        out['txs'] += 1
        out['types'][p['type']] = out['types'].get(p['type'], 0) + 1
        for i, pl in enumerate(p['payloads']):
            out['payloads'] += 1
            for k, v in pl['scalars'].items():
                out['scalars'] += 1
                if v >= order:
                    out['noncanonical'].append({'txid': txid, 'payload': i, 'field': k})
    return out


def run_census(blocks, root=ROOT, get=rpc):
    order, osrc = bn256_order(root)
    info = get('DERO.GetInfo')
    top = int(info['height'])
    txids, heights = [], 0
    for h in range(top, max(0, top - blocks), -1):
        b = get('DERO.GetBlock', {'height': h})
        heights += 1
        for t in json.loads(b.get('json') or '{}').get('tx_hashes') or []:
            txids.append(t)
    txs = []
    for i in range(0, len(txids), 16):
        res = get('DERO.GetTransaction', {'txs_hashes': txids[i:i + 16]})
        hexes = res.get('txs_as_hex') or [t.get('as_hex') or '' for t in res.get('txs') or []]   # rpc/daemon_rpc.go:204
        for tid, hx in zip(txids[i:i + 16], hexes):
            if hx:
                txs.append((tid, bytes.fromhex(hx)))
    plimit, psrc = payload_limit(root)
    types, tsrc = tx_types(root)
    c = census_of(txs, order, plimit, types)
    when = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    doc = {'captured': when, 'source': 'read-only RPC 127.0.0.1:10102 (GetBlock, GetTransaction)', 'tip': top,
           'blocks': heights, 'tx_hashes': len(txids), 'bodies': len(txs), 'order_src': osrc,
           'payload_limit_src': psrc, 'tx_types_src': tsrc, 'tx_types': list(types), **c}
    RUNTIME.mkdir(exist_ok=True)
    out = RUNTIME / f'disclosure_census_{when}.json'
    out.write_text(json.dumps(doc, indent=1) + '\n')
    return {'file': str(out.relative_to(ROOT)), **doc}


def snapshot_doc(track, rep, legacy, when):
    """the round record: one key per line (indent 1), so a page row can anchor on a line of it"""
    cur = track.get('current_round')
    cl = track.get('claims') or []
    pm = track.get('press_map') or {}
    prow = [r.get('id') for r in ((legacy or {}).get('press') or {}).get('rows') or []]
    by_v = {}
    for c in cl:
        v = latest(c).get('verdict')
        by_v[v] = by_v.get(v, 0) + 1
    return {'captured': when, 'tool': 'harness/intel/disclosure_track.py', 'rev': rep['rev'], 'current_round': cur,
            'verdict': 'PASS' if rep['ok'] else 'FAIL',
            'claims_retested': f"{sum(1 for c in cl if any(h.get('round') == cur for h in c.get('history') or []))}/{len(cl)}",
            'latest_verdicts': by_v,
            'anchors_resolved': f"{sum(v for k, v in rep['anchor_status'].items() if k in ANCHOR_OK)}/{rep['anchors']}",
            'anchors_drifted': len(rep['drift']), 'anchors_bad': len(rep['bad']),
            'drift': [f"{d['file']}:{d['line']} -> :{d['now']} ({d['where']})" for d in rep['drift']],
            'bad': [f"{b['status']} {b['file']}:{b['line']} ({b['where']})" for b in rep['bad']],
            'press_rows_mapped': f"{sum(1 for i in prow if i in pm)}/{len(prow)}",
            'press_not_tested': sorted(k for k, v in pm.items() if str(v).startswith('NOT-TESTED:')),
            'exploit_lint_hits': len(rep['lint_hits']), 'legacy_lint_hits': len(rep['legacy_lint']),
            'legacy_lint_rows': sorted({h['where'].split('.')[0] for h in rep['legacy_lint']}),
            'facts': len(track.get('facts') or []),
            'fixes_fork_required': sum(1 for x in track.get('fixes') or [] if x.get('kind') == 'FORK-REQUIRED'),
            'fixes_node_local_implemented': sum(1 for x in track.get('fixes') or [] if x.get('kind') == 'NODE-LOCAL'
                                                and str(x.get('status', '')).startswith('implemented')),
            'fixes_infeasible': sum(1 for x in track.get('fixes') or [] if x.get('status') == 'infeasible'),
            'model_current': rep.get('model_current'), 'why': rep['why']}


def write_snapshot(track, rep, legacy):
    when = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    RUNTIME.mkdir(exist_ok=True)
    out = RUNTIME / f'disclosure_track_{when}.json'
    out.write_text(json.dumps(snapshot_doc(track, rep, legacy, when), indent=1, ensure_ascii=False) + '\n')
    return str(out.relative_to(ROOT))


# ───────────────────────────── main ─────────────────────────────
SECTION_MARK = ('<!--disclosure-track:begin-->', '<!--disclosure-track:end-->')


def page_sections(root=ROOT):
    """the rendered disclosure-track sections (between SECTION_MARK) of the src-arch page and the newest ledger"""
    out = {}
    for p in [root / 'artifacts/dero-src-arch.html'] + sorted((root / 'artifacts').glob('dero-r1-r*.html')):
        try:
            t = p.read_text(errors='replace')
        except OSError:
            continue
        for k, m in enumerate(re.finditer(re.escape(SECTION_MARK[0]) + r'(.*?)' + re.escape(SECTION_MARK[1]), t, re.S)):
            out[f'{p.name}#{k}'] = re.sub(r'<[^>]+>', ' ', html_unescape(m.group(1)))
    return out


def html_unescape(s):
    import html
    return html.unescape(s)


def load(root=ROOT):
    track = json.loads((root / 'harness/loop/disclosure_track.json').read_text())
    legacy = {}
    for k in ('press', 'forensics'):
        try:
            legacy[k] = json.loads((root / f'harness/model/raw/{k}.json').read_text())
        except (OSError, json.JSONDecodeError):
            legacy[k] = None
    return track, legacy


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--check', action='store_true', help='also FAIL when harness/model/raw/disclosure.json is stale')
    ap.add_argument('--emit-model', action='store_true', help='write harness/model/raw/disclosure.json')
    ap.add_argument('--rev', default=None, help='re-read anchors at this git revision instead of the worktree')
    ap.add_argument('--live', action='store_true', help='read-only RPC supply/integrity cross-checks')
    ap.add_argument('--census', type=int, default=0, help='proof-scalar census over the last N blocks (read-only RPC)')
    ap.add_argument('--pages', action='store_true', help='lint the rendered disclosure sections of the pages')
    ap.add_argument('--json', default=None, help='write the full report here')
    ap.add_argument('--snapshot', action='store_true', help='write harness/runtime/disclosure_track_<ts>.json (the round record)')
    ap.add_argument('--rev-strict', action='store_true', help='with --rev: a file absent at rev is NOFILE (no worktree fallback)')
    ap.add_argument('--rebase-lines', action='store_true',
                    help="move DRIFTed lines of the current round's entries, facts and fixes to their new line (writes the track)")
    a = ap.parse_args(argv)
    global REV_FALLBACK
    REV_FALLBACK = not a.rev_strict
    try:
        track, legacy = load()
    except (OSError, json.JSONDecodeError) as e:
        print(f'disclosure_track: cannot read the track: {e}')
        return 2
    if a.rebase_lines:
        n = rebase_lines(track, None)
        TRACK.write_text(json.dumps(track, indent=1, ensure_ascii=False) + '\n')
        print(f'rebase-lines: {n} anchor line(s) moved in {TRACK.relative_to(ROOT)}')
    rep = evaluate(track, rev=a.rev, legacy=legacy, pages=page_sections() if a.pages else None)
    if a.emit_model:
        MODEL.write_text(json.dumps(emit_model(track), indent=1, ensure_ascii=False) + '\n')
    try:
        cur = json.loads(MODEL.read_text())
    except (OSError, json.JSONDecodeError):
        cur = None
    rep['model_current'] = model_current(track, cur)
    if a.check and not rep['model_current']:
        rep['ok'] = False
        rep['why'].append('harness/model/raw/disclosure.json is stale: run disclosure_track.py --emit-model')
    if a.live:
        try:
            rep['live'] = run_live()
        except Exception as e:                                       # noqa: BLE001 — report, do not hide
            rep['live'] = {'ok': None, 'error': f'{type(e).__name__}: {e}'}
    if a.census:
        try:
            rep['census'] = run_census(a.census)
        except Exception as e:                                       # noqa: BLE001
            rep['census'] = {'error': f'{type(e).__name__}: {e}'}
    # r24 (verifier): a live cross-check that FAILS, or a census that counts a scalar >= Order, is a failed check (exit
    # 3, as the docstring says); before this an inflated GetInfo.total_supply (S1) printed FAIL and still exited 0.
    # An unreadable node (ok None) is not a reading: it is printed, and the exit code is unchanged.
    lv = rep.get('live') or {}
    if lv.get('ok') is False:
        rep['ok'] = False
        rep['why'].append('live cross-check ' + ', '.join(n.split()[0] for n, c, _ in lv.get('checks') or [] if not c)
                          + f" FAIL ({lv.get('file')})")
    nc = len((rep.get('census') or {}).get('noncanonical') or [])
    if nc:
        rep['ok'] = False
        rep['why'].append(f"census: {nc} proof scalar(s) >= bn256.Order ({(rep.get('census') or {}).get('file')})")
    if a.json:
        Path(a.json).write_text(json.dumps(rep, indent=1, default=str) + '\n')
    if a.snapshot:
        rep['snapshot'] = write_snapshot(track, rep, legacy)
    print(f"disclosure track {'PASS' if rep['ok'] else 'FAIL'} ({rep['rev']}): {rep['claims']} claims, {rep['facts']} facts, "
          f"{rep['fixes']} fixes; anchors {rep['anchors']} {rep['anchor_status']}; drift {len(rep['drift'])}; "
          f"lint {len(rep['lint_hits'])}; legacy lint {len(rep['legacy_lint'])}; model {'current' if rep['model_current'] else 'STALE'}")
    for d in rep['drift']:
        print(f"  DRIFT {d['file']}:{d['line']} -> :{d['now']} ({d['where']})")
    for w in rep['why']:
        print(f'  FAIL {w}')
    for l in rep['legacy_lint']:      # the pattern and the row only: the flagged text is not re-printed
        print(f"  legacy {l['pattern']} at {l['where']} (flagged for the round lead: dero-rft §7 BD8)")
    if 'live' in rep:
        lv = rep['live']
        if lv.get('error'):
            print(f"  live: could not read: {lv['error']}")
        else:
            print(f"  live {lv['file']}")
            for n, ok, d in lv['checks']:
                print(f"    {'PASS' if ok else 'FAIL'} {n}: {d}")
    if 'census' in rep:
        c = rep['census']
        print(f"  census: {c.get('error') or str({k: c.get(k) for k in ('file', 'blocks', 'tx_hashes', 'bodies', 'txs', 'payloads', 'scalars', 'types')}) + ' noncanonical ' + str(len(c.get('noncanonical') or [])) + ' parse_errors ' + str(len(c.get('parse_errors') or []))}")
    return 0 if rep['ok'] else 3


if __name__ == '__main__':
    sys.exit(main())
