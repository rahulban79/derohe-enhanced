#!/usr/bin/env python3
"""gen_deroarch.py — the projection behind artifacts/dero-src-arch.html. Never hand-edit the page.

  python3 gen_deroarch.py resolve   # check every raw row against its evidence → model/verified.json + loop/REJECTED.json
  python3 gen_deroarch.py build     # resolve + render + stamp + rewrite the skill's AUTO block
  python3 gen_deroarch.py check     # 0 CURRENT · 3 STALE (a model file, kit module, miner or cited file changed)
  python3 gen_deroarch.py selftest  # proves check and resolve can fail

THE CONTRACT. A raw row (harness/model/raw/<key>.json) is rendered only when at least one of its {file, quote}
anchors is found verbatim on ONE line of its file (whitespace runs and typographic quotes normalised, nothing
else, >= 12 characters). Where the anchor points decides what the row can prove:

  first-party Go, build scripts, go.mod   SRC      a line of the DERO source tree
  vendor/**, harness/external/**          EXT      quoted, not owned: code this build links in, and
                                                   documents published by others and taken under audit
  harness/runtime/**, RUN_REPORT.md, …    HARNESS  the owner's own measured system
  .skills/**, the session memory store    GK       the project's knowledge base
  harness/loop/PROPOSALS.md               PLAN     proposed, not run

A row whose declared class its anchors cannot prove is re-derived from its first anchor and the page says so.
A row with no resolvable anchor is never drawn: it goes to loop/REJECTED.json and the page's quarantine.
"""
import collections, datetime, functools, hashlib, html, json, math, os, re, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
MODEL = HERE / 'model'
RAW = MODEL / 'raw'
VERIFY = MODEL / 'verify'
LOOP = HERE / 'loop'
CORPUS = HERE / 'corpus'
OUT = ROOT / 'artifacts' / 'dero-src-arch.html'
STAMP = HERE / 'stamp.json'
SKILL = ROOT / '.skills/dero-miner-tuning/SKILL.md'
AUTO_RE = re.compile(r'<!-- AUTO:BEGIN.*?<!-- AUTO:END -->', re.S)
sys.path.insert(0, str(HERE / 'kit'))
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / 'miners'))
import assetkit as ak            # noqa: E402
import connectorkit as ck        # noqa: E402
import textkit as tk             # noqa: E402
import diagramkit as dk          # noqa: E402
import areakit                   # noqa: E402  (r24: the per-area scorecard block)
import consensuskit              # noqa: E402  (r24: the chain-consensus observatory block)
import peerkit                   # noqa: E402  (r24 consensus-network: the network-peer observatory block)
import privkit                   # noqa: E402  (r24: peer addresses pseudonymised; masked anchor matching)
from prep_corpus import class_of, MEMORY, SRC_PKGS   # noqa: E402

RAW_KEYS = ['inventory', 'consts', 'flows', 'findings', 'forensics', 'press', 'logbridge', 'localdiff',
            'runtime', 'proposals', 'triage', 'intel', 'coverage', 'riskmap', 'evolution',   # r23c: evolution (git)
            'areacards',   # r24: per-area scorecards (miners/mine_areas.py <- intel/area_intel.py)
            'disclosure',   # r24: the per-round disclosure track (harness/intel/disclosure_track.py --emit-model)
            'consensus',     # r24: the chain-consensus observatory (miners/mine_consensus.py <- intel/consensus_intel.py)
            'peercards']   # r24: the network-peer observatory (miners/mine_peers.py <- intel/peer_intel.py)
KIND_ORDER = ['SRC', 'EXT', 'HARNESS', 'GK', 'PLAN']
E = lambda s: html.escape(str(s if s is not None else ''), quote=True)
TYPO = str.maketrans({'‘': "'", '’': "'", '“': '"', '”': '"', '–': '-', '—': '-',
                      ' ': ' ', '…': '...'})
SEV = {'defect': ('defect', 'var(--gap)'), 'fix': ('fixed here', 'var(--ok)'), 'operational': ('operational', 'var(--warn)'),
       'reporting': ('reporting', 'var(--mut)'), 'analysis': ('analysis', 'var(--l4)')}
SECTION_OF = {'packages': 'map', 'imports': 'map', 'vendor': 'deps', 'cadence': 'consensus', 'emission': 'consensus',
              'difficulty': 'consensus', 'tx': 'consensus', 'state': 'consensus', 'hardfork': 'consensus',
              'network': 'consensus', 'flows': 'flows', 'hops': 'flows', 'findings': 'findings',
              'logbridge': 'bridge', 'loggers': 'bridge', 'local': 'local', 'local-other': 'local',
              'commits': 'local', 'runtime': 'live', 'proposals': 'next', 'press': 'press', 'forensics': 'press',
              'triage': 'triage', 'triage-census': 'triage', 'intel': 'intel', 'coverage': 'coverage',
              'riskmap': 'coverage', 'evolution': 'evolution', 'evo-module': 'evolution', 'evo-file': 'evolution',
              'areas': 'areas',   # r24
              'chainobs': 'chainobs',   # r24: consensus observatory — chain
              'peers': 'peers',   # r24 (consensus-network)
              'disclosure': 'press'}   # r24


def norm(s):
    return re.sub(r'\s+', ' ', str(s or '').translate(TYPO)).strip()


def abspath(f):
    f = str(f or '').strip()
    p = Path(f).expanduser() if f.startswith('~') else Path(f)
    return p if p.is_absolute() else ROOT / f


_FC = {}


def flines(p):
    if p not in _FC:
        try:
            raw = ak.lines_of(p.read_text(errors='replace'))
        except OSError:
            raw = None
        _FC[p] = (raw, [norm(l) for l in raw] if raw is not None else None)
    return _FC[p]


def resolve_ev(ev):
    p = abspath(ev.get('file'))
    q = norm(ev.get('quote'))
    out = {'file': str(ev.get('file')), 'abs': str(p), 'quote': ev.get('quote'), 'kind': class_of(p)}
    if out['kind'] is None:
        return {**out, 'status': 'OUTSIDE'}
    raw, nl = flines(p)
    if raw is None:
        return {**out, 'status': 'NOFILE'}
    if len(q) < 12:
        return {**out, 'status': 'SHORT'}
    hits = [i + 1 for i, l in enumerate(nl) if q in l]
    if not hits and privkit.PSEUDO.search(q):
        # r24: a pseudonymised quote (miners/minelib.emit, kit/privkit.py) resolves on the raw line it was taken from,
        # compared in the salt-free masked form; only when the exact match fails, so no other anchor changes
        mq = privkit.mask(q)
        hits = [i + 1 for i, l in enumerate(nl) if mq in privkit.mask(l)]
    if not hits:
        return {**out, 'status': 'MISSING'}
    hint = ev.get('line')
    line = hint if isinstance(hint, int) and hint in hits else hits[0]
    return {**out, 'status': 'OK' if len(hits) == 1 else 'MULTI', 'line': line, 'occ': len(hits)}


def row_sig(claim, quotes):
    # r24: compared in the masked form, so pseudonymising a peer address (privkit) does not void a verifier's verdict
    return hashlib.sha256(json.dumps([privkit.mask(norm(claim)), sorted(privkit.mask(norm(q)) for q in quotes)]).encode()).hexdigest()[:16]


def apply_verdicts(rows, rejected, stats):
    """MERGE LAWS (adversarial verifiers write model/verify/verdicts_*.json):
         REFUTED               → the row leaves the page for the quarantine, with the verifier's reason
         PARTLY / OVERSTATED   → the corrected claim is drawn; the original stays in the tooltip
         fix_fields            → only onto an EXISTING field of the same type; anything else becomes a visible note
         no verdict            → "not re-verified" badge
         judged an older claim → the verdict does not apply; badge "changed since verification"
    """
    verdicts = {}
    for f in sorted(VERIFY.glob('verdicts_*.json')):
        try:
            d = json.loads(f.read_text())
        except json.JSONDecodeError:
            continue
        for v in (d.get('verdicts') if isinstance(d, dict) else d) or []:
            if v.get('id'):
                verdicts[v['id']] = {**v, '_file': f.name}
    judged = {}
    for f in sorted(VERIFY.glob('in_*.json')):
        try:
            for r in json.loads(f.read_text()):
                judged[r['id']] = row_sig(r.get('claim'), [e.get('quote', '') for e in r.get('evidence') or []])
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
    out = []
    for r in rows:
        v = verdicts.get(r['id'])
        sig = row_sig(r.get('claim'), [e.get('quote', '') for e in r['evidence']])
        r['sig'] = sig
        if v and judged.get(r['id']) and judged[r['id']] != sig:
            r['verdict'] = None
            r['verdict_note'] = 'changed since verification'
            stats['verdict_stale'] += 1
            out.append(r)
            continue
        if not v:
            r['verdict'] = None
            out.append(r)
            continue
        vd = str(v.get('verdict', '')).upper()
        r['verdict'] = vd
        r['verdict_why'] = v.get('why') or v.get('reason')
        stats[f'verdict_{vd.lower() or "blank"}'] += 1
        if vd == 'REFUTED':
            rejected.append({'id': r['id'], 'source': r['source'], 'title': r.get('title'), 'claim': r.get('claim'),
                             'why': 'REFUTED by verifier: ' + str(r['verdict_why'])[:300]})
            continue
        if v.get('fixed_claim'):
            r['original_claim'] = r['claim']
            r['claim'] = v['fixed_claim']
        for k, nv in (v.get('fix_fields') or {}).items():
            if k not in r:
                r.setdefault('fix_notes', []).append(f'verifier tried to set unknown field "{k}"')
            elif type(nv) is not type(r[k]):
                r.setdefault('fix_notes', []).append(f'verifier tried to set "{k}" to the wrong type')
            else:
                r[k] = nv
        out.append(r)
    return out


def resolve():
    rows, rejected, unverified, seen = [], [], [], set()
    stats = collections.Counter()
    for key in RAW_KEYS:
        f = RAW / f'{key}.json'
        if not f.exists():
            continue
        d = json.loads(f.read_text())
        for u in d.get('unverified') or []:
            unverified.append({'source': key, **(u if isinstance(u, dict) else {'title': str(u)})})
        for r in d.get('rows') or []:
            stats['raw'] += 1
            rid = str(r.get('id') or f'{key}-{stats["raw"]}')
            evs = [resolve_ev(e) for e in (r.get('evidence') or []) if isinstance(e, dict)]
            good = [e for e in evs if e['status'] in ('OK', 'MULTI')]
            stats['anchors'] += len(evs)
            stats['anchors_ok'] += len(good)
            if rid in seen:
                rejected.append({'id': rid, 'source': key, 'title': r.get('title'), 'why': 'duplicate id'})
                continue
            if r.get('all_anchors') and len(good) < len(evs):
                # a claim COMPUTED from several anchors is false as soon as one of them moves (2026-10-22: the
                # build-skew row kept rendering "this tree declares +21102026" after the version line changed)
                rejected.append({'id': rid, 'source': key, 'section': r.get('section'), 'title': r.get('title'),
                                 'claim': r.get('claim'),
                                 'why': 'all_anchors row lost ' + ', '.join(f"{Path(e['file']).name} ({e['status']})"
                                                                           for e in evs if e not in good)[:300]})
                continue
            if not good:
                rejected.append({'id': rid, 'source': key, 'section': r.get('section'), 'title': r.get('title'),
                                 'claim': r.get('claim'),
                                 'why': 'no anchor resolved: ' + ', '.join(f"{e['status']} {Path(e['file']).name}" for e in evs)[:300]})
                continue
            seen.add(rid)
            kinds = [k for k in KIND_ORDER if any(e['kind'] == k for e in good)]
            said = str(r.get('class') or '').upper()
            note = ''
            if said in kinds:
                cls = said
            else:
                cls = good[0]['kind']
                note = f'class re-derived from its evidence (the miner said {said or "nothing"})'
                stats['reclassed'] += 1
            row = {**r, 'id': rid, 'source': key, 'class': cls, 'classes': [cls] + [k for k in kinds if k != cls],
                   'evidence': good, 'dropped_anchors': [e for e in evs if e not in good]}
            if note:
                row['class_note'] = note
            row['page_section'] = SECTION_OF.get(r.get('section'), 'map')
            rows.append(row)
    rows = apply_verdicts(rows, rejected, stats)
    stats['rows'] = len(rows)
    stats['rejected'] = len(rejected)
    stats['unverified'] = len(unverified)
    return rows, rejected, unverified, dict(stats)


# ───────────────────────────── assetkit wiring ─────────────────────────────
def ev_class(o):
    return o.get('classes') or [o.get('class')] if isinstance(o, dict) else None


def rel(p):
    s = str(p)
    if s.startswith(str(ROOT) + '/'):
        return s[len(str(ROOT)) + 1:]
    if MEMORY and s.startswith(str(MEMORY)):
        return 'memory/' + Path(s).name
    return s


def cites_fn(o):
    if not isinstance(o, dict):
        return []
    out = []
    for e in o.get('evidence') or []:
        out.append(ak.cite_file(e['abs'], e.get('line'), e.get('quote', ''), cls=e.get('kind') or 'SRC',
                                label=f"{rel(e['abs'])}:{e.get('line')}"))
    return out


cls_of = functools.partial(ak.cls_of, ev_class=ev_class, cites_fn=cites_fn)


def CL(row):
    return cls_of(row)


def tag(row):
    return ak.ctag(cls_of(row))


# ───────────────────────────── html helpers ─────────────────────────────
# textkit's clip helpers return finished markup (the tooltip span plus the ⓘ marker). Escaping that turns the
# tooltip into visible text and the cut loses its sentence — G11 then fails in the rendered DOM only, which is
# an expensive way to find a one-character mistake. md() now detects kit markup and passes it through, so
# md(tk.html_clip(...)) is harmless instead of a trap.
_KIT = re.compile(r'class="tt[ "]|class="tt-i"')


def md(s):
    if _KIT.search(str(s or '')):
        return str(s)
    s = E(s)
    s = re.sub(r'`([^`]+)`', r'<code>\1</code>', s)
    s = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', s)
    # single-* italic, markdown-style: stars must hug non-space and not sit mid-word or beside another *,
    # and the span may not cross a tag (no < or >), so Go-pointer code inside <code> is never matched
    return re.sub(r'(?<![\w*])\*(\S(?:[^*<>]*?\S)?)\*(?![\w*])', r'<em>\1</em>', s)


def proof(row, n=3):
    evs = row.get('evidence') or []
    bits = []
    for e in evs[:n]:
        bits.append(f'<a class="pf" href="vscode://file/{E(e["abs"])}:{e.get("line")}" title="{E(e.get("quote", "")[:220])}">'
                    f'{E(rel(e["abs"]))}:{e.get("line")}</a>')
    if len(evs) > n:
        bits.append(f'<span class="mut">+{len(evs) - n} more</span>')
    return ' '.join(bits)


def table(heads, rows, tid='', filt=False, cls='', notag=None):
    f = (f'<div class="tf"><input type="search" data-filter="{tid}" placeholder="filter {len(rows)} rows…" '
         f'aria-label="filter table"><span class="tfn" id="{tid}-n"></span></div>') if filt and tid else ''
    nt = f' data-notag="{E(notag)}"' if notag else ''
    h = ''.join(f'<th>{x}</th>' for x in heads)
    b = ''.join('<tr' + (f' id="{E(r[0])}"' if isinstance(r, tuple) else '') + '>'
                + ''.join(f'<td>{c}</td>' for c in (r[1] if isinstance(r, tuple) else r)) + '</tr>' for r in rows)
    return f'{f}<div class="tw"><table{" id=" + chr(34) + tid + chr(34) if tid else ""}{nt}><thead><tr>{h}</tr></thead><tbody>{b}</tbody></table></div>'


def note(s, kind=''):
    return f'<p class="note {kind}">{md(s)}</p>'


def kpis(items):
    return '<div class="kpis">' + ''.join(
        f'<div class="kpi"><div class="kv">{E(v)}</div><div class="kl">{md(l)}</div></div>' for v, l in items) + '</div>'


def fig(svg, cap, label):
    s = svg.replace('<svg ', f'<svg role="img" aria-label="{E(label)}" ', 1)
    return f'<figure><div class="figbox">{s}</div><figcaption>{md(cap)}</figcaption></figure>'


def chip(word, col):
    return f'<span class="chip" style="--c:{col}">{E(word)}</span>'


def badges(r):
    out = []
    if r.get('verdict'):
        out.append(chip(r['verdict'].lower(), 'var(--ok)' if r['verdict'] in ('CONFIRMED', 'OK') else 'var(--warn)'))
    elif r.get('verdict_note'):
        out.append(chip(r['verdict_note'], 'var(--warn)'))
    else:
        out.append(chip('not re-verified', 'var(--mut)'))
    if r.get('class_note'):
        out.append(chip('re-classed', 'var(--warn)'))
    return ''.join(out)


# ───────────────────────────── diagrams ─────────────────────────────
LAYER_LANE = {'p2p': 'p2p', 'core': 'blockchain', 'state': 'graviton', 'dvm': 'dvm', 'ext': 'vendor',
              'getwork': 'getwork', 'miner': 'dero-miner', 'pow': 'astrobwt', 'wallet': 'walletapi',
              'crypto': 'cryptography', 'rpc': 'rpc', 'derod': 'derod'}


def flow_spec(cid, title, hops):
    nodes, edges = [], []
    for h in hops:
        nodes.append({'id': h['id'], 'label': h.get('fn') or h['title'], 'sub': rel(h['evidence'][0]['abs']).split('/')[-1]
                      + ':' + str(h['evidence'][0].get('line')), 'lane': LAYER_LANE.get(h.get('layer'), h.get('layer')),
                      '_row': h})
    for a, b in zip(hops, hops[1:]):
        edges.append({'from': a['id'], 'to': b['id'], 'label': '', 'step': b['order'] - 1, '_row': b})
    lanes = []
    for h in hops:
        ln = LAYER_LANE.get(h.get('layer'), h.get('layer'))
        if ln not in lanes:
            lanes.append(ln)
    return {'id': f'flow-{cid}', 'kind': 'sequence', 'lanes': lanes, 'nodes': nodes, 'edges': edges}


def pkg_spec(pkgs, deps):
    """The first-party import graph. Lanes are the architectural tiers the imports themselves imply."""
    TIER = {'cmd': 'binaries', 'p2p': 'network', 'blockchain': 'consensus', 'dvm': 'consensus', 'block': 'consensus',
            'walletapi': 'wallet', 'rpc': 'wire', 'transaction': 'wire', 'proof': 'wire',
            'cryptography': 'primitives', 'astrobwt': 'primitives', 'pow': 'primitives',
            'config': 'foundation', 'globals': 'foundation', 'metrics': 'foundation', 'glue': 'foundation',
            'errormsg': 'foundation', 'premine': 'foundation'}
    keep = {p['pkg'] for p in pkgs}
    nodes = [{'id': p['pkg'], 'label': p['pkg'], 'sub': f"{p['loc']:,} lines · {p['files']} files",
              'lane': TIER.get(p['pkg'], 'foundation'), '_row': p} for p in pkgs]
    seen, edges = set(), []
    for d in sorted(deps, key=lambda x: -x['count']):
        if d['from'] in keep and d['to'] in keep and (d['from'], d['to']) not in seen:
            seen.add((d['from'], d['to']))
            edges.append({'from': d['from'], 'to': d['to'], 'label': '', '_row': d,
                          'why_not_step': 'an import relation, not a step in an execution order'})
    return {'id': 'pkgmap', 'kind': 'relations',
            'why_kind': 'these are import relations between packages, not an execution order',
            'lanes': ['binaries', 'network', 'consensus', 'wallet', 'wire', 'primitives', 'foundation'],
            'nodes': nodes, 'edges': edges}


def dkcls(o):
    return cls_of(o.get('_row')) if isinstance(o, dict) and o.get('_row') else cls_of(o)


# ───────────────────────────── page-specific charts (all kit-compliant) ─────────────────────────────
def _find(by, fid):
    for r in by.get('findings', []):
        if r['id'] == fid:
            return r
    return None


def diff_chart(by):
    """The difficulty controller's two bounded steps, as bars — magnitude only; the sign is in each note.
    Values are read from find-diffstep (up/down), which the findings miner COMPUTED from the source constants."""
    f = _find(by, 'find-diffstep')
    if not f:
        return ''
    up = (float(f.get('up', 1.13315)) - 1) * 100
    dn = (1 - float(f.get('down', 0.8825))) * 100
    items = [
        {'label': 'Block solved instantly  (solvetime → 0)', 'value': round(up, 2), 'colour': 'var(--warn)',
         'note': f'difficulty rises by at most ×{f.get("up")} = +{up:.2f}% in one block', '_row': f},
        {'label': 'Block on the 18 s target', 'value': 0.2, 'colour': 'var(--mut)',
         'note': 'solvetime == blocktime → exponent 0 → ×1.0, no change', '_row': f},
        {'label': 'Slowest the clamp admits  (solvetime = 2×)', 'value': round(dn, 2), 'colour': 'var(--ok)',
         'note': f'difficulty falls by at most {(float(f.get("down"))-1)*100:.2f}%; the 2× clamp is why one slow block cannot collapse it', '_row': f},
    ]
    return fig(dk.bars(items, dkcls, W=1000, label_w=330, unit='%'),
              'Per-block difficulty change is bounded and **asymmetric**: a hashrate spike can be absorbed no faster '
              'than +13.3%/block and a drop no faster than −11.8%/block, which is why the measured mean block time '
              'hovers around 18 s rather than sitting on it. Both numbers are computed at build time from '
              '`const E`, `M := int64(8)` and the 2× solve-time clamp — never typed in.',
              'difficulty controller step bounds')


def emit_chart(by):
    """The halving schedule as reward-per-epoch bars, computed here from BaseReward and the interval."""
    f = _find(by, 'find-emission')
    if not f:
        return ''
    base = int(f.get('base', 123000))
    cur = None
    for r in by.get('runtime', []):
        if r.get('field') == 'height':
            try:
                cur = (int(r['value']) + int(f.get('interval', 7000000))) // int(f.get('interval', 7000000))
            except Exception:
                cur = None
    items = []
    for e in range(1, 8):
        atomic = base >> e
        items.append({'label': f'Epoch {e}' + ('  ← current' if e == cur else ''),
                      'value': round(atomic / 100000, 5), 'colour': 'var(--l4)' if e != cur else 'var(--gap)',
                      'note': f'{atomic:,} atomic units = {atomic/100000:g} DERO per block'
                              + ('  (the epoch this chain is in now)' if e == cur else ''), '_row': f})
    return fig(dk.bars(items, dkcls, W=1000, label_w=200, unit=' DERO'),
              'Block subsidy halves every 7,000,000 blocks (≈ four years at 18 s). The `+1` epoch offset in '
              '`CalcBlockReward` skips the first Bitcoin-equivalent interval outright, which is what halves the total '
              'supply relative to Bitcoin. Each bar is `BaseReward >> epoch`, computed from the two `const` lines.',
              'block subsidy per halving epoch')


def verdict_matrix(by):
    """Claim C1..C8 → verdict, as a coloured grid. One g.as per claim, class/citation from the forensics row."""
    fore = by.get('forensics', [])
    canon = {}
    for r in fore:
        pc = r.get('press_claim', '')
        # prefer the synthesis row (id like 'c2-...') as the canonical verdict for each press claim
        if pc.startswith('C') and (pc not in canon or r['id'][:2].lower() == pc.lower()):
            canon[pc] = r
    claims = [(f'C{i}', canon.get(f'C{i}')) for i in range(1, 9)]
    claims = [(c, r) for c, r in claims if r]
    if not claims:
        return ''
    VC = {'CONFIRMED': 'var(--gap)', 'PARTLY-CONFIRMED': 'var(--warn)',
          'REFUTED': 'var(--ok)', 'CANNOT-DETERMINE-LOCALLY': 'var(--mut)'}
    LABEL = {'C1': 'A soundness defect exists', 'C2': 'Mechanism: prover-adjustable unbound generator',
             'C3': 'The broken check is the sole magnitude gate', 'C4': 'Inherited from ConsenSys Zether',
             'C5': 'Present from genesis of the proof path', 'C6': 'HF3 double-spend; 23.9M created (floor)',
             'C7': '5,000,000 burned in the same era', 'C8': 'Ending support; no rollback'}
    rh, top, W = 34, 8, 1000
    Hh = top + len(claims) * rh + 6
    o = [f'<svg class="dk" viewBox="0 0 {W} {Hh}" xmlns="http://www.w3.org/2000/svg">']
    for k, (c, r) in enumerate(claims):
        y = top + k * rh
        v = r.get('audit_verdict', '?')
        col = VC.get(v, 'var(--mut)')
        short = {'CONFIRMED': 'CONFIRMED', 'PARTLY-CONFIRMED': 'PARTLY', 'REFUTED': 'REFUTED',
                 'CANNOT-DETERMINE-LOCALLY': 'CANNOT TELL LOCALLY'}.get(v, v)
        pill, pw = ak.svg_ctag(W - 8, y + 14, dkcls({'_row': r}))
        o.append('<g class="as">'
                 + f'<rect x="4" y="{y}" width="{W-8}" height="{rh-7}" rx="6" fill="var(--panel2)" stroke="var(--line)"/>'
                 + dk.text(16, y + 18, c, 12.5, weight='700', fill=col)
                 + f'<rect x="44" y="{y+5}" width="176" height="{rh-17}" rx="4" fill="{col}" fill-opacity=".15" stroke="{col}" stroke-width="1"/>'
                 + dk.text(132, y + 18, tk.fit(short, 168, 9.5, True), 9.5, 'middle', '700', col)
                 + dk.text(236, y + 18, tk.fit(LABEL.get(c, ''), W - 236 - pw - 22, 11, False), 11, fill='var(--ink)')
                 + pill
                 + f'<title>{E(c)} — {E(v)} — {E(LABEL.get(c, ""))}</title></g>')
    o.append('</svg>')
    return fig(''.join(o),
              'Each of the Foundation’s eight claims against the verdict this tree returns. **Red = a defect '
              'confirmed here; green = the claim as stated is refuted; amber = partly; grey = not decidable from a '
              'pruned node.** The headline (C1) is confirmed; the stated *mechanism* (C2) is the one refuted outright.',
              'press claims versus local verdict')


def sharedbase_svg(by):
    """STRUCTURAL schematic of C1: which terms ride which NUMS base in the verification point. Not an attack —
    it names where each value sits and cites the lines. One g.as per box; classes from the proof-verifier rows."""
    f = _find(by, 'find-screvert')          # any SRC row anchored in cryptography/ gives the SRC class+cite
    row = None
    for r in by.get('forensics', []):
        if 'proof_verify.go' in json.dumps(r.get('evidence', [])):
            row = r
            break
    if not row:
        return ''
    cl = dkcls({'_row': row})
    W, Hh = 1000, 300

    def box(x, y, w, h, title, sub, fill='var(--panel)', col='var(--line)', withpill=True):
        pill, pw = ak.svg_ctag(x + w - 6, y + 13, cl) if withpill else ('', 0)
        t = dk.text(x + 9, y + 18, tk.fit(title, w - pw - 18, 11.5, True), 11.5, weight='700')
        s2 = dk.text(x + 9, y + 34, tk.fit(sub, w - 16, 9.5), 9.5, fill='var(--mut)') if sub else ''
        return (f'<g class="as"><rect x="{x}" y="{y}" width="{w}" height="{h}" rx="7" fill="{fill}" stroke="{col}" stroke-width="1.3"/>'
                + t + s2 + pill + f'<title>{E(title)} — {E(sub)}</title></g>')

    # plain connecting lines (no marker-end: connectorkit treats marker-end paths as traceable connectors,
    # and a structural schematic is not a numbered connector sequence)
    o = [f'<svg class="dk" viewBox="0 0 {W} {Hh}" xmlns="http://www.w3.org/2000/svg">']
    # top row: challenge chain
    o.append(box(16, 16, 300, 46, 'Challenge c  (hard-checked)', 'proof_verify.go:422 — rejects unless c = H(x, A_*)'))
    o.append(box(356, 16, 300, 46, 'o = reducedhash(c)', 'proof_verify.go:428 — public, derived from c'))
    o.append('<line x1="316" y1="39" x2="352" y2="39" stroke="var(--mut)" stroke-width="1.4"/>'
             + dk.text(334, 35, '→', 13, 'middle', '700', 'var(--mut)'))
    # the shared base H and the two terms on it
    o.append(box(356, 92, 628, 150, 'NUMS base  H  (gparams.H)', 'algebra_pedersen.go — a fixed hash-to-point constant; the Pedersen blinding base', fill='var(--panel2)', col='var(--warn)'))
    o.append(box(380, 126, 280, 44, 'u_x = H^o   (IP generator)', 'proof_verify.go:430 — a KNOWN multiple of H'))
    o.append(box(680, 126, 284, 44, '−μ   (blinding scalar)', 'proof_verify.go:452 — μ in NO Fiat-Shamir preimage'))
    o.append(box(380, 182, 584, 44, 'both ride the same base H → one H-axis equation, one free prover scalar μ', '', fill='transparent', col='var(--gap)'))
    o.append('<line x1="506" y1="62" x2="506" y2="88" stroke="var(--mut)" stroke-width="1.4"/>'
             + dk.text(514, 79, '↓', 13, 'start', '700', 'var(--mut)'))
    # the final check
    o.append(box(16, 92, 300, 46, 'final check: P_calculated == P', 'proof_innerproduct.go:307 — a bare point string-compare', col='var(--gap)'))
    o.append(box(16, 162, 300, 64, 'Consequence (C1)', 'the IP check no longer forces `that` to the true inner product on the H-axis', fill='transparent', col='var(--gap)'))
    o.append('</svg>')
    return fig(''.join(o),
              'A **structural** map of the confirmed defect (C1): the inner-product generator `u_x = H^o` and the '
              'unbound blinding scalar `−μ` sit on the *same* NUMS base `H`, and `μ` is bound by no '
              'challenge. This shows *where each value lives*, with the citing line on every box — not an attack '
              'construction. The adversarial verifiers stopped at exactly this structural fact.',
              'C1 shared-base structure of the verification point')


# r24: the disclosure track (harness/loop/disclosure_track.json -> model/raw/disclosure.json): per-claim verdicts per
# round, the round's new facts, and the potential fixes. Every row comes through resolve(), so an unanchored one is not
# drawn (no anchor, no row); the markers let disclosure_track.py --pages lint exactly this text for exploit content.
DT_VCOL = {'CONFIRMED': 'var(--gap)', 'PARTLY-CONFIRMED': 'var(--warn)', 'REFUTED': 'var(--ok)',
           'CANNOT-DETERMINE-LOCALLY': 'var(--mut)', 'NOT-TESTED': 'var(--mut)', 'pending': 'var(--mut)'}
DT_SCOL = {'open': 'var(--gap)', 'upstream': 'var(--warn)', 'report-only': 'var(--mut)', 'closed-by-design': 'var(--ok)',
           'fixed-node-local': 'var(--ok)', 'pending': 'var(--mut)'}
DT_FCOL = {'implemented': 'var(--ok)', 'implemented-earlier': 'var(--ok)', 'design': 'var(--l4)',
           'feasible-not-implemented': 'var(--warn)', 'infeasible': 'var(--mut)', 'pending': 'var(--mut)'}


def fx_dataset_line():
    """r25 (rft §0.8.6): the "Forensic dataset" line of section 10, rendered by artifacts/src/forensics_section.fx_line from
    the newest forensics/<version>/ (every figure a dataset fact span; G30 checks it between <!--fxline:begin/end-->)."""
    import html as _h, importlib.util as _iu
    p = ROOT / 'artifacts' / 'src' / 'forensics_section.py'
    if not p.exists():
        return ''
    sp = _iu.spec_from_file_location(f'fx_section_for_deroarch_{id(p)}', p)
    m = _iu.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m.fx_line(_h.escape)


def disclosure_track_html(by):
    rows = by.get('disclosure', [])
    if not rows:
        return ''
    cl = [r for r in rows if r.get('kind') == 'track-claim']
    fa = [r for r in rows if r.get('kind') == 'track-fact']
    fx = [r for r in rows if r.get('kind') == 'track-fix']
    rounds = (cl[0].get('rounds') if cl else []) or []
    cur = rounds[-1] if rounds else ''
    o = [fx_dataset_line(), '<!--disclosure-track:begin-->']
    retested = sum(1 for r in cl if cur in (r.get('history') or {}))
    o.append('<h3>Round history: every claim, re-tested each round</h3>')
    o.append(kpis([(f'{retested}/{len(cl)}', f'claims re-tested in {cur}'),
                   (str(len(fa)), f'new facts in {cur}'),
                   (str(sum(1 for r in fx if r.get('fix_kind') == 'FORK-REQUIRED')), 'fix designs that need a coordinated fork'),
                   (str(sum(1 for r in fx if r.get('fix_kind') == 'NODE-LOCAL' and str(r.get('status', '')).startswith('implemented'))),
                    'node-local measures in place'),
                   (str(sum(1 for r in fx if r.get('status') == 'infeasible')), 'measures shown infeasible')]))
    o.append(note('Each claim is re-read every round by `harness/intel/disclosure_track.py` (gate **G24**): an anchor that '
                  'moved is reported as drift, one that vanished blocks the row, and a verdict may change only with a reason '
                  'and an anchor outside the advisory itself. Rounds without an entry did not test that claim.'))
    tr = []
    for r in cl:
        h = r.get('history') or {}
        seq = ' '.join(f'<span class="mono">{E(rd)}</span> ' + chip(str(h[rd]["verdict"]).lower().replace('-', ' '),
                                                                   DT_VCOL.get(h[rd]['verdict'], 'var(--mut)'))
                       for rd in rounds if rd in h)
        st = r.get('state_now') or ''
        seq += ' ' + chip('now: ' + st, DT_SCOL.get(st, 'var(--mut)'))
        tr.append([f'<b>{E(r["title"])}</b>', seq, md(tk.html_clip(r.get('claim') or '', 260)), proof(r, 2)])
    o.append(table(['Claim', 'verdict', 'Latest re-test', 'proof'], ak.tag_rows(tr, cl, ['', None, '', None], cls_of),
                   't-dtrack', filt=True))
    if fa:
        o.append(f'<h3>New in {E(cur)}: what the re-test found</h3>')
        o.append(note('Defensive facts only: what the proof binds, what a node can and cannot observe. No construction of '
                      'any proof is described or was attempted.'))
        o.append('<div class="cards">')
        for r in fa:
            o.append(f'''<div class="card analysis" id="{E(r["id"])}">
              <h4>{E(r["title"])} {tag(r)}</h4>
              <div>{chip(str(r.get("status", "")).lower(), "var(--ok)" if r.get("status") in ("CONFIRMED", "MEASURED") else "var(--mut)")}
                   {"".join(chip("bears on " + c, "var(--l4)") for c in r.get("claims") or [])}</div>
              <p>{md(r.get("claim", ""))}</p>
              <div class="meta"><span class="mut">Proof:</span> {proof(r, 6)}</div></div>''')
        o.append('</div>')
    if fx:
        o.append('<h3>Potential fixes</h3>')
        o.append(note('**FORK-REQUIRED** designs say what must be bound or checked; none can ship from this tree alone, '
                      'because changing what verifies forks a node off the network (the consensus guard refuses it). '
                      '**NODE-LOCAL** measures change nothing that blocks accept; each is marked implemented, feasible, '
                      'or infeasible with the line that shows why.'))
        for kind, lab in (('FORK-REQUIRED', 'Protocol-level designs (need a coordinated fork)'),
                          ('NODE-LOCAL', 'Node-local measures (no fork)')):
            sub = [r for r in fx if r.get('fix_kind') == kind]
            if not sub:
                continue
            o.append(f'<h4>{E(lab)}</h4>')
            ft = []
            for r in sub:
                body = md(r.get('claim', ''))
                if r.get('verify'):
                    body += '<br><b>Verify.</b> ' + md(r['verify'])
                if r.get('compat'):
                    body += '<br><b>Activation / compatibility.</b> ' + md(r['compat'])
                if r.get('implemented_in'):
                    body += '<br><b>Where.</b> <code>' + E(r['implemented_in']) + '</code>'
                fe = r.get('feasible')
                stc = chip(str(r.get('status', '')), DT_FCOL.get(r.get('status'), 'var(--mut)')) + ' ' + chip(
                    'feasible' if fe is True else ('infeasible' if fe is False else 'feasibility pending'),
                    'var(--ok)' if fe is True else 'var(--mut)')
                stc += ' ' + ' '.join(chip(c, 'var(--l4)') for c in r.get('claims') or [])
                ft.append([f'<b>{E(r["title"])}</b>', body, stc, proof(r, 2)])
            o.append(table(['Fix', 'Design and verification', 'verdict', 'proof'],
                           ak.tag_rows(ft, sub, ['', '', None, None], cls_of), f't-dfix-{kind.lower()}'))
    o.append('<!--disclosure-track:end-->')
    return ''.join(o)


ORIGIN = [('LOCAL', 'Our code, executing a block', 'the error is raised by this node while it runs the chain'),
          ('LOCAL-CONSEQUENCE', 'Our reaction to a peer', 'a side effect of how this node handles a peer fault'),
          ('TRANSPORT', 'A socket closed under a read', 'connection teardown; which side closed is not logged'),
          ('REMOTE', 'A peer\u2019s own error, relayed', 'rpc2 ServerError: the text was produced on the peer')]


def triage_svg(by):
    """Error class → where it originates. One box per triaged class (its own class pill), one per origin lane.
    Structural lines only: this is a classification, not a sequence."""
    rows = by.get('triage', [])
    if not rows:
        return ''
    order = [o[0] for o in ORIGIN]
    rows = sorted(rows, key=lambda r: (order.index(r.get('origin', 'REMOTE')), r['id']))
    W, bh, gap = 1000, 46, 12
    Hh = 16 + len(rows) * (bh + gap) + 6
    o = [f'<svg class="dk" viewBox="0 0 {W} {Hh}" xmlns="http://www.w3.org/2000/svg">']
    col = {'LOCAL': 'var(--gap)', 'LOCAL-CONSEQUENCE': 'var(--warn)', 'TRANSPORT': 'var(--mut)', 'REMOTE': 'var(--l4)'}

    def box(x, y, w, h, title, sub, cl, stroke, fill='var(--panel)'):
        pill, pw = ak.svg_ctag(x + w - 6, y + 13, cl)
        t = dk.text(x + 9, y + 18, tk.fit(title, w - pw - 18, 11.5, True), 11.5, weight='700')
        s2 = dk.text(x + 9, y + 34, tk.fit(sub, w - 16, 9.5), 9.5, fill='var(--mut)') if sub else ''
        return (f'<g class="as"><rect x="{x}" y="{y}" width="{w}" height="{h}" rx="7" fill="{fill}" stroke="{stroke}" '
                f'stroke-width="1.3"/>' + t + s2 + pill + f'<title>{E(title)} — {E(sub)}</title></g>')

    ys = {}
    for i, r in enumerate(rows):
        y = 16 + i * (bh + gap)
        ys.setdefault(r['origin'], []).append(y + bh / 2)
        o.append(box(16, y, 600, bh, f'{r.get("count", "?")}×  {r["title"].split(":")[0].split(",")[0]}', r.get('triage_verdict', ''),
                     dkcls({'_row': r}), col.get(r['origin'], 'var(--line)')))
    for key, title, sub in ORIGIN:
        if key not in ys:
            continue
        cy = sum(ys[key]) / len(ys[key])
        top = max(16, min(Hh - bh - 6, cy - bh / 2))
        anyrow = next(r for r in rows if r['origin'] == key)
        for y in ys[key]:
            o.append(f'<line x1="616" y1="{y:.0f}" x2="700" y2="{top + bh / 2:.0f}" stroke="{col[key]}" stroke-width="1.4"/>')
        o.append(box(700, top, 284, bh, title, sub, dkcls({'_row': anyrow}), col[key], 'var(--panel2)'))
    o.append('</svg>')
    return fig(''.join(o),
               'Every ERROR line in the capture, grouped by class (left, with its count and verdict) and joined to '
               'where it actually comes from (right). Only the **LOCAL** lane is this node\u2019s own code, and '
               'its one entry is the known, deterministic SC-revert defect. Everything in the **REMOTE** lane '
               'was produced on another machine and relayed verbatim.',
               'Console errors by origin')



def catchup_svg(by):
    """A small gauge: how far behind the tip this node is, from the captured tip-age reading."""
    rt = {r.get('field'): r for r in by.get('runtime', []) if r.get('field')}
    ta = rt.get('tip_age')
    if not ta:
        return ''
    try:
        days = float(ta['value']) / 86400
        blocks = float(ta['value']) / 18
    except Exception:
        return ''
    W, Hh = 1000, 86
    cl = dkcls({'_row': ta})
    atip = days < 0.1
    frac = 0.02 if atip else min(0.97, days / 45)          # 45-day visual scale
    bx, bw = 16, W - 32
    fillw = max(6, bw * (1 - frac))
    col = 'var(--ok)' if atip else 'var(--warn)'
    pill, pw = ak.svg_ctag(W - 8, 20, cl)
    o = [f'<svg class="dk" viewBox="0 0 {W} {Hh}" xmlns="http://www.w3.org/2000/svg">',
         '<g class="as">',
         dk.text(16, 20, 'Catch-up to the live tip', 12, weight='700'),
         f'<rect x="{bx}" y="34" width="{bw}" height="22" rx="5" fill="var(--panel2)" stroke="var(--line)"/>',
         f'<rect x="{bx}" y="34" width="{fillw:.0f}" height="22" rx="5" fill="{col}" fill-opacity=".30" stroke="{col}"/>',
         dk.text(bx + 8, 49, tk.fit(('AT TIP' if atip else f'tip block is {days:.1f} days / ~{blocks:,.0f} blocks behind the live network'), bw - pw - 20, 10.5, True), 10.5, weight='700', fill=col),
         dk.text(16, 74, tk.fit('wall clock − the tip block’s own timestamp; the only local reading that distinguishes at-tip from far-behind', W - pw - 24, 9.5), 9.5, fill='var(--mut)'),
         pill,
         '<title>catch-up gauge from the tip block age</title></g></svg>']
    return fig(''.join(o),
              'The node is still replaying history toward the tip. This gauge is the tip block’s age against the '
              'wall clock — the reading finding `find-attip` shows is the only one that can tell at-tip from '
              'far-behind, because every GetInfo summary field reads healthy meanwhile.',
              'catch-up to the live tip')


# ───────────────────────────── r23c: the evolution of the tree, R1 → the current round ─────────────────────────────
# Every number below is read from harness/model/raw/evolution.json (mine_evolution.py, from git) and every asset cites
# the line of harness/runtime/evolution_git.tsv it was read from. Nothing is counted here; the page only draws.
EVO_COLS = [('dero-miner', 'miner'), ('gpu-miner-poc', 'gpu-poc'), ('p2p', 'p2p'), ('derod + rpc', 'derod/rpc'),
            ('glue', 'glue'), ('blockchain', 'chain'), ('walletapi', 'wallet'), ('other first-party Go', 'other Go'),
            ('tools', 'tools'), ('experiments', 'experim.'), ('harness code', 'harness'), ('harness data', 'h. data'),
            ('artifacts', 'artifacts'), ('docs', 'docs'), ('other', 'other')]
EVO_SHORT = {'R1-3': 'R1–3', 'R9': 'R9–10'}
EVO_LAYERS = [('Miner', ('cmd/dero-miner', 'gpu-miner-poc')),
              ('Daemon, p2p, glue', ('cmd/derod', 'p2p', 'metrics', 'glue', 'rpc')),
              ('Consensus and core', ('blockchain', 'config', 'block', 'transaction', 'dvm', 'cryptography', 'astrobwt',
                                      'pow', 'proof', 'globals', 'errormsg', 'premine')),
              ('Wallet', ('walletapi', 'cmd/dero-wallet-cli', 'cmd/webwallet')),
              ('Tools, explorer, ops', ('tools', 'cmd/')),
              ('Harness and artifacts', ('harness', 'artifacts'))]


def kfmt(n):
    n = int(n)
    return f'{n}' if n < 1000 else (f'{n / 1000:.1f}k' if n < 10000 else f'{n / 1000:.0f}k')


def evo_rounds(by):
    return sorted([r for r in by.get('evolution', []) if r.get('kind') == 'evo-round'], key=lambda r: r['order'])


def evo_layer(m):
    for i, (_, pre) in enumerate(EVO_LAYERS):
        if any(m == p or m.startswith(p.rstrip('/') + '/') or (p.endswith('/') and m.startswith(p)) for p in pre):
            return i
    return 4 if m.startswith('cmd/') else 2


def evo_heatmap(by):
    """round × subsystem, colour = log10(lines changed); one g.as, every cell's numbers in its tooltip"""
    rs = evo_rounds(by)
    if not rs:
        return ''
    W, LW, TW, top, rh = 1120, 104, 66, 58, 22
    cw = (W - LW - TW - 8) / len(EVO_COLS)
    H = top + rh * len(rs) + 44
    vals = [v[1] + v[2] for r in rs for v in r['subs'].values()]
    mx = math.log10(max(vals + [10]) + 1)
    pill, pw = ak.svg_ctag(W - 8, 16, dkcls({'_row': rs[-1]}))
    o = [f'<svg class="dk evo-wide" viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg"><g class="as">',
         dk.text(8, 18, tk.fit('Lines changed per round and subsystem (colour: log10 of added + removed lines)', W - pw - 24, 12, True), 12, weight='700'),
         pill]
    for j, (key, short) in enumerate(EVO_COLS):
        x = LW + j * cw + cw / 2
        o.append(f'<g><title>{E(key)}{" — consensus package, held by the consensus guard (G13)" if key == "blockchain" else ""}</title>'
                 + dk.text(x, 46, short, 9.2, 'middle', '700', 'var(--mut)') + '</g>')
    o.append(dk.text(LW + len(EVO_COLS) * cw + TW / 2 + 4, 46, 'Σ lines', 9.2, 'middle', '700', 'var(--mut)'))
    for i, r in enumerate(rs):
        y = top + i * rh
        lab = EVO_SHORT.get(r['round'], r['round'])
        o.append(f'<g><title>{E(r["claim"])}</title>' + dk.text(8, y + 15, lab, 10.5, weight='700') + '</g>')
        if r.get('pending'):
            o.append(f'<rect x="{LW:.0f}" y="{y + 2}" width="{len(EVO_COLS) * cw:.0f}" height="{rh - 4}" rx="4" fill="none" '
                     f'stroke="var(--warn)" stroke-dasharray="4 3"/>'
                     + dk.text(LW + 10, y + 15, 'pending measurement: no commit names this round yet', 10, weight='700', fill='var(--warn)'))
            continue
        for j, (key, _) in enumerate(EVO_COLS):
            v = r['subs'].get(key)
            x = LW + j * cw
            if not v:
                o.append(f'<rect x="{x + 1:.1f}" y="{y + 2}" width="{cw - 2:.1f}" height="{rh - 4}" rx="3" fill="none" stroke="var(--rule)"/>')
                continue
            n = v[1] + v[2]
            t = math.log10(n + 1) / mx
            ink = 'var(--bg)' if t > 0.55 else 'var(--ink)'
            o.append(f'<g><title>{E(EVO_SHORT.get(r["round"], r["round"]))} · {E(key)}: {v[0]} commit(s), {v[3]} file(s), '
                     f'+{v[1]:,} / −{v[2]:,} lines</title>'
                     f'<rect x="{x + 1:.1f}" y="{y + 2}" width="{cw - 2:.1f}" height="{rh - 4}" rx="3" fill="var(--accent)" '
                     f'fill-opacity="{0.10 + 0.85 * t:.2f}"/>'
                     + dk.text(x + cw / 2, y + 15, kfmt(n), 9.2, 'middle', '700', ink) + '</g>')
        o.append(dk.text(LW + len(EVO_COLS) * cw + TW / 2 + 4, y + 15, kfmt(r['added'] + r['removed']), 9.6, 'middle', '700'))
    ly = top + rh * len(rs) + 22
    o.append(dk.text(8, ly + 4, 'scale', 9.2, weight='700', fill='var(--mut)'))
    for k, n in enumerate([10, 100, 1000, 10000]):
        t = min(1, math.log10(n + 1) / mx)
        x = LW + k * 92
        o.append(f'<rect x="{x}" y="{ly - 8}" width="28" height="14" rx="3" fill="var(--accent)" fill-opacity="{0.10 + 0.85 * t:.2f}"/>'
                 + dk.text(x + 34, ly + 4, f'{kfmt(n)} lines', 9.2, fill='var(--mut)'))
    o.append(dk.text(LW + 4 * 92 + 10, ly + 4, tk.fit('empty cell: the round did not touch that subsystem · Σ = every path the round changed', W - LW - 4 * 92 - 20, 9.2), 9.2, fill='var(--mut)'))
    o.append('<title>round by subsystem heatmap of lines changed since Release152</title></g></svg>')
    chain = ', '.join(EVO_SHORT.get(r['round'], r['round']) for r in rs if 'blockchain' in r['subs']) or 'no round'
    # r23c (review): G13 compares against bf274e5 (consensus_guard.evaluate base, the Release153-identical commit); a
    # chain change in a round before that commit's round is part of the guard's baseline, not something it held
    g13 = next((r for r in rs if any(c.startswith('bf274e5') for c in r['commits'])), None)
    pre = [EVO_SHORT.get(r['round'], r['round']) for r in rs
           if 'blockchain' in r['subs'] and g13 and r['order'] < g13['order']]
    g13t = (f'the consensus guard (G13) holds every change after its baseline bf274e5 '
            f'({EVO_SHORT.get(g13["round"], g13["round"]) if g13 else "?"}, Release153 content) to logging and '
            f'non-consensus paths' + (f'; the {", ".join(pre)} change predates that baseline and is part of the '
                                      f'Release153 content it compares against' if pre else ''))
    return fig(''.join(o),
               'Each row is a round as the Enhancement Ledger groups it, each column a subsystem of the tree. A cell is '
               'the lines that round added plus removed under that subsystem, from `git log --numstat --no-renames`; '
               'hover a cell for its commits, files and the split. **h. data** is the harness’s own captured '
               'evidence (runtime snapshots, model rows, gate ledgers) and is why the Σ column dwarfs the code columns. '
               f'The **chain** column is the consensus package: it changes only in {chain}, and {g13t}.',
               'round by subsystem heatmap')


def evo_curve(by):
    """cumulative lines changed, two series on one axis (both are lines of source); the pending round is marked, not plotted"""
    rs = evo_rounds(by)
    if not rs:
        return ''
    W, H, L, Rm, T, B = 1120, 300, 64, 168, 34, 46
    done = [r for r in rs if not r.get('pending')]
    ymax = max([r['cum_code'] for r in done] + [1])
    step = 10 ** max(0, len(str(int(ymax))) - 1)
    ymax = (int(ymax / step) + 1) * step
    X = lambda i: L + (W - L - Rm) * i / max(1, len(rs) - 1)
    Y = lambda v: T + (H - T - B) * (1 - v / ymax)
    pill, pw = ak.svg_ctag(W - 8, 16, dkcls({'_row': done[-1]}))
    o = [f'<svg class="dk evo-wide" viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg"><g class="as">',
         dk.text(8, 18, tk.fit('Cumulative lines changed since Release152, round by round', W - pw - 24, 12, True), 12, weight='700'), pill]
    for k in range(5):
        v = ymax * k / 4
        o.append(f'<line x1="{L}" x2="{W - Rm}" y1="{Y(v):.1f}" y2="{Y(v):.1f}" stroke="var(--rule)"/>'
                 + dk.text(L - 6, Y(v) + 3, kfmt(v), 9.2, 'end', fill='var(--mut)'))
    for i, r in enumerate(rs):
        o.append(dk.text(X(i), H - B + 16, EVO_SHORT.get(r['round'], r['round']), 8.6, 'middle',
                         fill='var(--warn)' if r.get('pending') else 'var(--mut)'))
    pend = [i for i, r in enumerate(rs) if r.get('pending')]
    for i in pend:
        o.append(f'<line x1="{X(i):.1f}" x2="{X(i):.1f}" y1="{T}" y2="{H - B}" stroke="var(--warn)" stroke-dasharray="4 3"/>'
                 + dk.text(X(i) - 6, T + 10, 'pending', 9.2, 'end', '700', 'var(--warn)'))
    SER = [('cum_code', 'all code', 'var(--accent)'),
           ('cum_go', 'shipped Go', 'var(--l4)')]
    for key, name, col in SER:
        pts = [(X(rs.index(r)), Y(r[key]), r) for r in done]
        o.append(f'<polyline points="{" ".join(f"{x:.1f},{y:.1f}" for x, y, _ in pts)}" fill="none" stroke="{col}" stroke-width="2"/>')
        for x, y, r in pts:
            o.append(f'<g><title>{E(EVO_SHORT.get(r["round"], r["round"]))}: {E(name)} {r[key]:,} lines changed so far '
                     f'(this round {r["code"] if key == "cum_code" else r["go"]:,})</title>'
                     f'<circle cx="{x:.1f}" cy="{y:.1f}" r="7" fill="transparent"/>'
                     f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.2" fill="{col}" stroke="var(--panel)" stroke-width="1.5"/></g>')
        x, y, r = pts[-1]
        o.append(dk.text(x + 10, y + 4, tk.fit(f'{name} {kfmt(r[key])}', Rm - 14, 9.6, True), 9.6, weight='700'))
    o.append('<title>cumulative lines changed per round</title></g></svg>')
    big = max(done, key=lambda r: (r['code'], -r['order']))
    return fig(''.join(o),
               'The enhancement curve. Both series are lines added plus removed, summed round by round from the same '
               'numstat, so they share one axis: **all code** counts every source file this branch wrote (the miner, '
               'GPU proof of concept, node, wallet, tools and the harness), **first-party Go that ships** only the `.go` '
               f'files of packages a binary links. The largest single step is {EVO_SHORT.get(big["round"], big["round"])} '
               f'({big["code"]:,} code lines); a round with no commit yet is drawn as a dashed line, never as a flat step.',
               'cumulative enhancement curve')


def evo_modmap(by):
    """upstream vs enhanced: every module as a box in its layer; new modules carry the round that added them"""
    mods = [r for r in by.get('evo-module', [])]
    if not mods:
        return ''
    cols = collections.defaultdict(list)
    rank = lambda r: (0 if not r['upstream'] else (1 if r['rounds'] else 2), -(r['added'] + r['removed']), r['module'])
    for r in mods:
        cols[evo_layer(r['module'])].append(r)
    W, top, bh, gap = 1120, 52, 48, 6
    cwid = W / len(EVO_LAYERS)
    n = max(len(v) for v in cols.values())
    H = top + n * (bh + gap) + 34
    o = [f'<svg class="dk evo-wide" viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg">',
         dk.text(8, 18, 'Upstream Release152 modules and the modules this branch added, by layer', 12, weight='700')]
    for c, (name, _) in enumerate(EVO_LAYERS):
        x0 = c * cwid + 6
        o.append(dk.text(x0 + 2, 42, tk.fit(name, cwid - 14, 10.4, True), 10.4, weight='700', fill='var(--mut)'))
        for i, r in enumerate(sorted(cols.get(c, []), key=rank)):
            y = top + i * (bh + gap)
            new, mod = not r['upstream'], bool(r['rounds'])
            col = 'var(--ok)' if new else ('var(--l4)' if mod else 'var(--line)')
            pill, pw = ak.svg_ctag(x0 + cwid - 16, y + 27, dkcls({'_row': r}))
            sub = (f'new in {EVO_SHORT.get(r["first_round"], r["first_round"])}' if new else
                   f'changed in {len(r["rounds"])} round{"s" * (len(r["rounds"]) != 1)}' if mod else 'upstream, unchanged')
            sub2 = (f'{r["files_n"]} file{"s" * (r["files_n"] != 1)} · +{kfmt(r["added"])} / −{kfmt(r["removed"])}'
                    if (new or mod) else 'as tagged')
            o.append(f'<g class="as"><title>{E(r["claim"])}</title>'
                     f'<rect x="{x0:.0f}" y="{y}" width="{cwid - 12:.0f}" height="{bh}" rx="6" fill="{col}" '
                     f'fill-opacity="{0.13 if new else (0.07 if mod else 0)}" stroke="{col}"'
                     f'{"" if (new or mod) else " stroke-dasharray=" + chr(34) + "3 3" + chr(34)}/>'
                     + dk.text(x0 + 8, y + 15, tk.fit(r['module'], cwid - 28, 9.6, True), 9.6, weight='700',
                               fill='var(--ink)' if (new or mod) else 'var(--mut)')
                     + dk.text(x0 + 8, y + 30, tk.fit(sub, cwid - 32 - pw, 8.6), 8.6,
                               weight='700' if new else '400', fill='var(--ok)' if new else 'var(--mut)')
                     + dk.text(x0 + 8, y + 42, tk.fit(sub2, cwid - 28, 8.6), 8.6, fill='var(--mut)')
                     + pill + '</g>')
    ly = H - 14
    for k, (word, col, op) in enumerate([('new module (round that added it)', 'var(--ok)', .13),
                                         ('upstream module, changed here', 'var(--l4)', .07),
                                         ('upstream module, unchanged', 'var(--line)', 0)]):
        x = 8 + k * 300
        o.append(f'<g class="as"><rect x="{x}" y="{ly - 10}" width="22" height="13" rx="3" fill="{col}" fill-opacity="{op}" stroke="{col}"/>'
                 + dk.text(x + 28, ly + 1, word, 9.4, fill='var(--mut)') + ak.svg_ctag(x + 280, ly - 3, dkcls({'_row': mods[0]}))[0] + '</g>')
    o.append('</svg>')
    return fig(''.join(o),
               'A module is a directory of the tree (three levels under `cmd/`, two elsewhere). **Upstream** means the '
               'directory exists in the Release152 tag (`git ls-tree` at the base commit); a new module is labelled with '
               'the first round whose commits touched it. Boxes run from new, to changed, to unchanged, and then by '
               'lines changed. Hover a box for its rounds, commits and files.',
               'upstream versus enhanced module map')


def evolved(by, files=None, prefixes=(), what='this section'):
    """r23c (b): the 'evolved' strip under a section: which rounds changed the files the section cites, one line per
    round with that round's own doc heading. files: repo-relative paths; prefixes: directory prefixes."""
    rs = [r for r in evo_rounds(by) if not r.get('pending')]
    if not rs:
        return ''
    files = set(files or ())
    hits = []
    for r in rs:
        fs = [(p, v) for p, v in r['files'].items() if p in files or any(p.startswith(x) for x in prefixes)]
        if fs:
            hits.append((r, fs))
    if not hits:
        # r23c (review): 'upstream code as tagged' holds only for files that ARE in the Release152 tree; a section that
        # cites the harness's own captures (intel) cites files the base never had, and the strip must say so
        bp = set(next((r.get('base_paths') or [] for r in by.get('evolution', []) if r.get('kind') == 'evo-base'), []))
        newf = sorted(p for p in files if p not in bp and not p.startswith('vendor/'))
        if newf:
            return (f'<div class="evo"><span class="evo-h">Evolved</span> <span class="mut">no source file {E(what)} '
                    f'cites was changed by a round: '
                    + (f'{len(files) - len(newf)} cited file(s) are upstream Release152 files, unchanged, and '
                       if len(files) > len(newf) else 'none of the ')
                    + f'{len(newf)} {"are not" if len(files) > len(newf) else "cited files is"} in the Release152 tree (the harness’s own captured '
                    f'data, which the code counts leave out), e.g. <code>{E(Path(newf[0]).name)}</code>.</span></div>')
        return (f'<div class="evo"><span class="evo-h">Evolved</span> <span class="mut">no file {E(what)} cites has '
                f'changed since Release152: it is upstream code as tagged.</span></div>')
    chips = ''.join(f'<a class="evo-c" href="#{E(r["id"])}" title="{len(fs)} cited file(s) changed">{E(EVO_SHORT.get(r["round"], r["round"]))}</a>'
                    for r, _ in hits)
    li = []
    for r, fs in hits:
        doc = next((e for e in r['evidence'] if e['abs'].endswith('ARCHITECTURE.md')), None)
        a, d = sum(v[0] for _, v in fs), sum(v[1] for _, v in fs)
        names = ', '.join(f'<code>{E(Path(p).name)}</code>' for p, _ in sorted(fs, key=lambda x: -(x[1][0] + x[1][1]))[:3])
        li.append(f'<li><b>{E(EVO_SHORT.get(r["round"], r["round"]))}</b> — {len(fs)} file(s), +{a:,} / −{d:,}: {names}'
                  f'{" and " + str(len(fs) - 3) + " more" if len(fs) > 3 else ""}'
                  + (f' · <span class="mut">ARCHITECTURE {E(r["doc_section"])}: {E(r["doc_what"])}</span> '
                     f'<a class="pf" href="vscode://file/{E(doc["abs"])}:{doc.get("line")}">{E(rel(doc["abs"]))}:{doc.get("line")}</a>'
                     if doc else '') + '</li>')
    return (f'<details class="evo"><summary><span class="evo-h">Evolved in {len(hits)} round(s)</span> {chips}</summary>'
            f'<ul>{"".join(li)}</ul></details>')


def evo_section(by, A, H):
    rs = evo_rounds(by)
    mods = by.get('evo-module', [])
    fl = sorted(by.get('evo-file', []), key=lambda r: r['rank'])
    base = next((r for r in by.get('evolution', []) if r.get('kind') == 'evo-base'), None)
    done = [r for r in rs if not r.get('pending')]
    cur = done[-1]['round'] if done else '?'
    A(H('evolution', f'How the tree evolved, R1 → {EVO_SHORT.get(cur, cur)}',
        'Every round of work on this node left commits on `local-enhancements`. This section reads them back out of '
        'git: which subsystems each round touched, how much, which modules are new against upstream, which files took '
        'the most change, and how the total grew. Under each later section an **Evolved** strip names the rounds that '
        'changed the files that section cites, with each round’s own write-up.'))
    if not rs:
        A(note('No evolution rows: run `harness/miners/mine_evolution.py`.', 'warn'))
        A('</section>')
        return
    A(kpis([(str(sum(r['commit_n'] for r in rs)), 'local commits since Release152'),
            (str(len(done)), 'rounds with commits'),
            (kfmt(sum(r['added'] for r in rs)) + ' / ' + kfmt(sum(r['removed'] for r in rs)), 'lines added / removed (all paths)'),
            (kfmt(done[-1]['cum_code']) if done else '-', 'lines of code changed (cumulative)'),
            (kfmt(done[-1]['cum_go']) if done else '-', 'of them first-party Go that ships'),
            (str(sum(1 for m in mods if not m['upstream'])), 'new modules'),
            (str(sum(1 for m in mods if m['upstream'] and m['rounds'])), 'upstream modules changed')]))
    if base:
        A(f'<p class="sub">{md(base["claim"])} {tag(base)} <span class="mut">Proof:</span> {proof(base, 2)}</p>')
    for r in rs:
        if r.get('pending'):
            A(note(f"**{EVO_SHORT.get(r['round'], r['round'])} is pending measurement.** No commit on the branch names "
                   f"it yet, so git has nothing to count; the heatmap and the curve mark it as pending rather than "
                   f"drawing a zero. It fills in on the first build after its commit.", 'warn'))
    A(evo_heatmap(by))
    A(evo_curve(by))
    A('<h3>The rounds, as git records them</h3>')
    top3 = lambda r: ', '.join(f'{k} {kfmt(v[1] + v[2])}' for k, v in sorted(
        ((k, v) for k, v in r['subs'].items() if k not in ('harness data', 'docs', 'other')),
        key=lambda kv: -(kv[1][1] + kv[1][2]))[:3]) or '-'
    rr = [(r['id'], [f'<b>{E(EVO_SHORT.get(r["round"], r["round"]))}</b>' + (' ' + chip('pending', 'var(--warn)') if r.get('pending') else ''),
                     f'<span class="mono" style="white-space:nowrap" title="{E(" to ".join(r["dates"]))}">{E(" → ".join(dict.fromkeys(d[5:] for d in r["dates"])) or "-")}</span>',
                     f'<span class="num">{r["commit_n"]}</span>', f'<span class="num">{r["paths_n"]}</span>',
                     f'<span class="num">+{r["added"]:,} / −{r["removed"]:,}</span>',
                     f'<span class="num">{r["code"]:,}</span>', E(top3(r)),
                     md(f'{r["doc_section"]} {r["doc_what"]}' if r['doc_section'] else '-'), proof(r, 3)])
          for r in rs]
    yrs = ', '.join(sorted({d[:4] for r in rs for d in r['dates']}))
    A(table(['Round', f'Dates ({yrs})', 'Commits', 'Paths', 'Lines', 'Code lines', 'Most-changed code', 'Written up in', 'proof'],
            [(i, c) for i, c in zip([x[0] for x in rr],
                                    ak.tag_rows([x[1] for x in rr], rs, ['', '', '', '', '', '', '', '', None], cls_of))],
            't-evo-rounds'))
    A('<h3>Upstream versus enhanced: the module map</h3>')
    A(evo_modmap(by))
    A('<h3>The file churn leaderboard</h3>')
    A(f'<p class="lede" style="margin:4px 0 8px">The {len(fl)} source files with the most lines added plus removed since '
      f'Release152: source code only (Go, C, assembly, Swift/Metal, Python, shell); captured data, JSON, docs and generated pages are excluded. The bar is relative to the top file.</p>')
    mx = max([r['added'] + r['removed'] for r in fl] + [1])
    ftr = [[f'<span class="num">{r["rank"]}</span>', f'<span class="mono">{E(r["path"])}</span>', E(r['subsystem']),
            f'<span class="evo-bar" style="--w:{100 * (r["added"] + r["removed"]) / mx:.1f}%"></span>'
            f'<span class="num">+{r["added"]:,} / −{r["removed"]:,}</span>',
            f'<span class="num">{r["commit_n"]}</span>',
            ' '.join(E(EVO_SHORT.get(x, x)) for x in r['rounds']), proof(r, 1)] for r in fl]
    A(table(['#', 'File', 'Subsystem', 'Lines', 'Commits', 'Rounds', 'proof'],
            ak.tag_rows(ftr, fl, [None, '', '', '', '', '', None], cls_of), 't-evo-files', filt=True))
    mt = sorted(mods, key=lambda r: (r['upstream'], -(r['added'] + r['removed']), r['module']))
    mtr = [[f'<span class="mono">{E(r["module"])}</span>',
            chip('new', 'var(--ok)') if not r['upstream'] else (chip('changed', 'var(--l4)') if r['rounds'] else chip('unchanged', 'var(--mut)')),
            E(EVO_SHORT.get(r['first_round'], r['first_round']) or '-'), f'<span class="num">{len(r["rounds"])}</span>',
            f'<span class="num">{r["files_n"]}</span>', f'<span class="num">+{r["added"]:,} / −{r["removed"]:,}</span>',
            proof(r, 1)] for r in mt]
    A('<h3>Every module, new and changed</h3>')
    A(table(['Module', 'Status', 'First round', 'Rounds', 'Files', 'Lines', 'proof'],
            ak.tag_rows(mtr, mt, ['', '', '', '', '', '', None], cls_of), 't-evo-mods', filt=True))
    A(note('**The round rule.** A commit whose subject starts `Round N`, `RN` or `rN` belongs to round N (with its '
           'letter); the commit that ports the Release142 enhancements is R1–R3, which ran on the Release142 tree '
           'before this repository existed; every other commit belongs to the **next** round-marked commit, because a '
           'round’s fixes land before its docs commit (da2fd6a and 3c5ffbf are Round 4b, d28c5b7 and 9612278 '
           'Round 6). Rounds are grouped as the Enhancement Ledger groups them: 4/4b/4c/4d, 6/6b and 9/9b/10 are one '
           'round each; R23b and R23c stand alone. The rule is written into the snapshot header, line 2.'))
    A('</section>')


# ───────────────────────────── the page ─────────────────────────────
CSS = r'''
:root{
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;
  --bg:#eef1f4; --panel:#ffffff; --panel2:#f5f7f9; --ink:#131a21; --mut:#5d6b78; --line:#cdd6de;
  --cluster:#0c6a73; --l4:#245f99; --ok:#15703f; --warn:#9a6212; --gap:#ab2f27; --queued:#6b5bbf; --host:#0c6a73;
  --ak-accent:#0c6a73; --ak-alert:#ab2f27; --ak-line:#cdd6de; --ak-panel:#ffffff; --ak-panel2:#f5f7f9;
  --ak-ink:#131a21; --ak-muted:#5d6b78;
  --rule:#dde4ea; --accent:#0c6a73; --accent2:#9a5a18;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#0e1216; --panel:#161c22; --panel2:#1b232a; --ink:#e4ecf2; --mut:#93a3b1; --line:#2c3843;
  --cluster:#3fb0ab; --l4:#6aa6e0; --ok:#4bbd7e; --warn:#d7a04a; --gap:#e87a6f; --queued:#a292ec; --host:#3fb0ab;
  --ak-accent:#3fb0ab; --ak-alert:#e87a6f; --ak-line:#2c3843; --ak-panel:#161c22; --ak-panel2:#1b232a;
  --ak-ink:#e4ecf2; --ak-muted:#93a3b1; --rule:#263039; --accent:#3fb0ab; --accent2:#d79a52;
}}
:root[data-theme="dark"]{
  --bg:#0e1216; --panel:#161c22; --panel2:#1b232a; --ink:#e4ecf2; --mut:#93a3b1; --line:#2c3843;
  --cluster:#3fb0ab; --l4:#6aa6e0; --ok:#4bbd7e; --warn:#d7a04a; --gap:#e87a6f; --queued:#a292ec; --host:#3fb0ab;
  --ak-accent:#3fb0ab; --ak-alert:#e87a6f; --ak-line:#2c3843; --ak-panel:#161c22; --ak-panel2:#1b232a;
  --ak-ink:#e4ecf2; --ak-muted:#93a3b1; --rule:#263039; --accent:#3fb0ab; --accent2:#d79a52;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 var(--sans);
     -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
.wrap{max-width:1180px;margin:0 auto;padding:0 16px 96px}
a{color:var(--accent)}
code,.mono{font-family:var(--mono)}
h1,h2,h3{text-wrap:balance;margin:0}
/* ── masthead: a status strip, because the subject is an instrument that is running right now ── */
header.mast{border-bottom:1px solid var(--rule);background:
  linear-gradient(180deg,color-mix(in srgb,var(--accent) 7%,var(--bg)) 0%,var(--bg) 100%)}
.mast .wrap{padding-top:34px;padding-bottom:22px}
.eyebrow{font:600 10.5px/1 var(--mono);letter-spacing:.2em;text-transform:uppercase;color:var(--accent);margin-bottom:12px}
h1{font-size:clamp(28px,4.4vw,46px);line-height:1.04;letter-spacing:-.025em;font-weight:760}
h1 .dim{color:var(--mut);font-weight:420}
.sub{margin:12px 0 0;max-width:68ch;color:var(--mut);font-size:15.5px}
.tickers{display:flex;flex-wrap:wrap;gap:8px;margin-top:18px}
.tick{display:flex;align-items:baseline;gap:7px;background:var(--panel);border:1px solid var(--line);
      border-radius:7px;padding:5px 10px;font-size:12px}
.tick b{font:700 13px/1 var(--mono);font-variant-numeric:tabular-nums}
.tick span{color:var(--mut);font-size:10.5px;letter-spacing:.05em;text-transform:uppercase}
.tick.live b{color:var(--ok)} .tick.warnt b{color:var(--warn)}
/* ── nav ── */
nav.toc{position:sticky;top:0;z-index:40;background:color-mix(in srgb,var(--bg) 88%,transparent);
        backdrop-filter:blur(9px);border-bottom:1px solid var(--rule)}
nav.toc .wrap{display:flex;gap:2px;overflow-x:auto;padding-top:7px;padding-bottom:7px;scrollbar-width:thin}
nav.toc a{color:var(--mut);text-decoration:none;font:600 11.5px/1 var(--sans);letter-spacing:.02em;
          padding:6px 9px;border-radius:6px;white-space:nowrap}
nav.toc a:hover{color:var(--ink);background:var(--panel2)}
/* ── sections ── */
section{padding-top:46px;scroll-margin-top:52px}
h2{font-size:23px;letter-spacing:-.015em;font-weight:720;display:flex;align-items:baseline;gap:10px}
h2 .num{font:700 11px/1 var(--mono);color:var(--accent);letter-spacing:.1em}
h3{font-size:15.5px;font-weight:700;margin:26px 0 8px;letter-spacing:-.005em}
.lede{color:var(--mut);max-width:74ch;margin:9px 0 18px}
.note{background:var(--panel2);border-left:3px solid var(--line);padding:10px 13px;border-radius:0 7px 7px 0;
      margin:14px 0;font-size:13.5px;color:var(--mut);max-width:88ch}
.note.warn{border-left-color:var(--warn)} .note.bad{border-left-color:var(--gap)} .note.good{border-left-color:var(--ok)}
.note b{color:var(--ink)}
/* ── kpis ── */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(142px,1fr));gap:10px;margin:18px 0}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:11px 13px}
.kv{font:700 21px/1.1 var(--mono);font-variant-numeric:tabular-nums;letter-spacing:-.02em}
.kl{color:var(--mut);font-size:11.5px;margin-top:5px;line-height:1.35}
/* ── tables ── */
.tw{overflow-x:auto;border:1px solid var(--line);border-radius:9px;background:var(--panel);margin:12px 0}
table{border-collapse:collapse;width:100%;font-size:13px}
th{text-align:left;font:700 10.5px/1.3 var(--mono);letter-spacing:.07em;text-transform:uppercase;color:var(--mut);
   padding:9px 11px;border-bottom:1px solid var(--line);background:var(--panel2);position:sticky;top:0;z-index:1}
td{padding:8px 11px;border-bottom:1px solid var(--rule);vertical-align:top}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:var(--panel2)}
td .mono,td code{font-size:12px}
.num{font-variant-numeric:tabular-nums;text-align:right;white-space:nowrap}
.tf{display:flex;align-items:center;gap:9px;margin:14px 0 0}
.tf input{flex:0 1 300px;padding:6px 10px;border:1px solid var(--line);border-radius:7px;background:var(--panel);
          color:var(--ink);font:13px var(--sans)}
.tfn{color:var(--mut);font-size:11.5px}
a.pf{font-family:var(--mono);font-size:11.5px;color:var(--mut);text-decoration:none;border-bottom:1px dotted var(--line);
     white-space:nowrap}
@media (max-width:600px){a.pf{white-space:normal;overflow-wrap:anywhere}}
a.pf:hover{color:var(--accent);border-bottom-color:var(--accent)}
.mut{color:var(--mut)}
.chip{display:inline-block;font:700 9.6px/1.5 var(--mono);letter-spacing:.05em;text-transform:uppercase;
      padding:1px 6px;border-radius:9px;color:var(--c);border:1px solid var(--c);background:color-mix(in srgb,var(--c) 11%,transparent);
      white-space:nowrap;margin-right:4px}
/* ── cards ── */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:13px;margin:16px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 15px}
.card.defect{border-left:3px solid var(--gap)} .card.fix{border-left:3px solid var(--ok)}
.card.operational{border-left:3px solid var(--warn)} .card.analysis{border-left:3px solid var(--l4)}
.card.reporting{border-left:3px solid var(--mut)}
.card h4{margin:0 0 7px;font-size:14.5px;font-weight:710;letter-spacing:-.005em}
.card p{margin:7px 0;font-size:13.2px;color:var(--ink)}
.card code{overflow-wrap:anywhere}
.card .meta{margin-top:10px;padding-top:9px;border-top:1px solid var(--rule);font-size:12px;color:var(--mut)}
.card .meta b{color:var(--ink);font-weight:650}
/* ── figures ── */
figure{margin:18px 0}
.figbox{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px}
figcaption{color:var(--mut);font-size:12.5px;margin-top:8px;max-width:84ch}
svg{display:block;max-width:100%;height:auto}
/* ── index ── */
#sx-q{width:100%;max-width:520px;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:var(--panel);
      color:var(--ink);font:14px var(--sans)}
#sx-facets{display:flex;flex-wrap:wrap;gap:6px;margin:11px 0}
.sx-f{font:600 11px/1 var(--sans);padding:5px 9px;border:1px solid var(--line);border-radius:14px;background:var(--panel);
      color:var(--mut);cursor:pointer}
.sx-f.on{background:var(--accent);border-color:var(--accent);color:#fff}
#sx-res{margin-top:12px;display:grid;gap:7px}
.sx-hit{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:9px 11px;font-size:13px}
.sx-hit a{font-weight:650;text-decoration:none}
.sx-hit .w{color:var(--mut);font-size:11.5px;display:block;margin-top:3px}
details{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:11px 14px;margin:12px 0}
summary{cursor:pointer;font-weight:650;font-size:13.5px}
footer{margin-top:62px;padding-top:20px;border-top:1px solid var(--rule);color:var(--mut);font-size:12.5px}
@media (max-width:620px){.wrap{padding:0 16px 70px}h1{font-size:27px}.kpis{grid-template-columns:repeat(auto-fit,minmax(124px,1fr))}}
@media print{nav.toc{display:none}}
/* ── r23c: evolved strips and churn bars ── */
.evo{background:var(--panel2);border:1px solid var(--rule);border-left:3px solid var(--accent);border-radius:0 8px 8px 0;
     padding:7px 11px;margin:10px 0 14px;font-size:12.5px}
.evo summary{font-weight:600;font-size:12.5px}
.evo ul{margin:8px 0 2px;padding-left:18px}.evo li{margin:3px 0;overflow-wrap:anywhere}
.evo-h{font:700 10px/1.4 var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--accent);margin-right:4px}
a.evo-c{display:inline-block;font:700 10px/1.5 var(--mono);padding:0 6px;margin:1px 2px;border-radius:9px;border:1px solid var(--accent);
        color:var(--accent);text-decoration:none;background:color-mix(in srgb,var(--accent) 10%,transparent)}
svg.evo-wide{min-width:860px}
.evo-bar{display:block;height:5px;width:var(--w);min-width:2px;border-radius:3px;background:var(--accent);opacity:.7;margin-bottom:3px}
'''

JS = r'''
(function(){
  // table filters
  document.querySelectorAll('input[data-filter]').forEach(function(inp){
    var t=document.getElementById(inp.getAttribute('data-filter')); if(!t) return;
    var cnt=document.getElementById(inp.getAttribute('data-filter')+'-n');
    function run(){var q=inp.value.toLowerCase(),n=0;
      [].forEach.call(t.tBodies[0].rows,function(r){var hit=!q||r.textContent.toLowerCase().indexOf(q)>=0;
        r.style.display=hit?'':'none'; if(hit)n++;});
      if(cnt)cnt.textContent=q?(n+' of '+t.tBodies[0].rows.length+' rows'):'';}
    inp.addEventListener('input',run);
  });
  // super index
  var IX=window.__IX||[],q=document.getElementById('sx-q'),res=document.getElementById('sx-res'),
      fac=document.getElementById('sx-facets'),act=null;
  function draw(){
    var s=(q&&q.value||'').toLowerCase().trim(), out=[];
    if(s.length>1||act){
      for(var i=0;i<IX.length&&out.length<40;i++){var r=IX[i];
        if(act&&r.s!==act)continue;
        if(s.length>1&&(r.n+' '+r.w+' '+r.s).toLowerCase().indexOf(s)<0)continue;
        out.push(r);}
    }
    res.innerHTML=out.map(function(r){
      return '<div class="sx-hit"><a href="#'+r.id+'">'+r.n+'</a> '+r.c+
             '<span class="w">'+r.s+' · '+r.w+'</span></div>';}).join('')
      ||'<p class="mut" style="font-size:13px">'+((s.length>1||act)?'No row matches.':'Type at least two characters, or pick a facet.')+'</p>';
  }
  if(fac){fac.addEventListener('click',function(e){var b=e.target.closest('.sx-f');if(!b)return;
    var v=b.getAttribute('data-f');act=(act===v)?null:v;
    [].forEach.call(fac.children,function(c){c.classList.toggle('on',c.getAttribute('data-f')===act);});draw();});}
  if(q){q.addEventListener('input',draw);draw();}
})();
'''


def render(rows, rejected, unverified, stats, fp):
    ak.reg_reset()
    by = collections.defaultdict(list)
    for r in rows:
        by[r['section']].append(r)
    pkgs = sorted(by['packages'], key=lambda r: -r['loc'])
    deps = by['imports']
    rt = {r['field']: r for r in by['runtime'] if r.get('field')}
    gi = lambda k, d='-': rt[k]['value'] if k in rt else d
    now = inputs_time()                  # r26 B93: reproducible (two builds of one tree are byte-exact)
    # r23c: the repo-relative files a group of rows cites, for the 'evolved' strips
    sfiles = lambda secs: {rel(e['abs']) for k in secs for r in by.get(k, []) for e in r['evidence']}
    O = []
    A = O.append

    # ───── masthead
    live_h = gi('height'); live_d = gi('difficulty'); live_bt = gi('averageblocktime50')
    refused = (f"{stats['rejected']} row(s) failed that test and are listed, with the reason, in the "
               f'quarantine.' if stats['rejected'] else
               f"Nothing was refused this build; {stats['unverified']} item(s) the miners could not anchor "
               f'at all are named in the quarantine, and the selftest proves the check can still fail.')
    captured = (by['runtime'][0].get('captured') if by['runtime'] else '')
    A(f'''<header class="mast"><div class="wrap">
      <div class="eyebrow">Living architecture · projected from the tree, not written about it</div>
      <h1>DERO HE <span class="dim">— the whole source tree,<br>read against the node that is running it</span></h1>
      <p class="sub">Every statement on this page is drawn only if a line of this repository, of the code it vendors, or of a
      snapshot of the live daemon still says so — {stats['anchors_ok']} anchors behind {stats['rows']} rows, each
      re-read from disk at gate time. {refused}</p>
      <div class="tickers">
        <div class="tick live"><b>{E(live_h)}</b><span>chain height</span></div>
        <div class="tick"><b>{E(gi('version'))}</b><span>version</span></div>
        <div class="tick"><b>{E(live_bt)}s</b><span>mean block, last 50</span></div>
        <div class="tick"><b>{E(f"{int(live_d):,}" if str(live_d).isdigit() else live_d)}</b><span>difficulty</span></div>
        <div class="tick"><b>{E(gi('outgoing_connections_count'))} out / {E(gi('incoming_connections_count'))} in</b><span>peers</span></div>
        <div class="tick"><b>{sum(p['loc'] for p in pkgs):,}</b><span>first-party lines</span></div>
        <div class="tick"><b>{stats['anchors_ok']}/{stats['anchors']}</b><span>anchors resolved</span></div>
      </div>
      <p class="sub" style="margin-top:14px;font-size:12.5px">Snapshot captured {E(captured)} · inputs as of {E(now.isoformat(timespec='seconds'))} (HEAD commit time) · fingerprint <code>{E(fp)}</code></p>
    </div></header>''')

    NAV = [('live', 'Live node'), ('evolution', 'Evolution'), ('map', 'Package map'), ('consensus', 'Consensus rules'), ('flows', 'Execution paths'),
           ('findings', 'Findings'), ('intel', 'Node intelligence'), ('coverage', 'Coverage'), ('triage', 'Console errors'), ('press', 'Disclosure audit'), ('areas', 'Areas'), ('chainobs', 'Consensus observatory'), ('peers', 'Network peers'), ('bridge', 'Log bridge'), ('local', 'Local changes'),
           ('deps', 'Vendored code'), ('quarantine', 'Quarantine'), ('index', 'Index'), ('method', 'Method')]
    A('<nav class="toc"><div class="wrap">' + ''.join(f'<a href="#{i}">{E(t)}</a>' for i, t in NAV) + '</div></nav>')
    A('<div class="wrap">')
    sec = [0]

    def H(sid, title, lede):
        sec[0] += 1
        return (f'<section id="{sid}"><h2><span class="num">{sec[0]:02d}</span>{E(title)}</h2>'
                f'<p class="lede">{md(lede)}</p>')

    # ───── 01 live node
    A(H('live', 'The node this page was read against',
        'A page about a daemon that is not running is a page about a guess. These numbers come from one read-only '
        'JSON-RPC snapshot taken while the page was built; each row cites the line of that snapshot it was read from.'))
    rt_rows = sorted(by['runtime'], key=lambda r: (not r['title'].startswith('★'), r['title']))
    rtr = [[f'<b>{E(r["title"])}</b>', f'<span class="mono">{E(r["value"])}</span>', md(r.get('how') or ''), proof(r, 1)]
           for r in rt_rows]
    A(table(['Reading', 'Value', 'What it means', 'proof'],
            ak.tag_rows(rtr, rt_rows, ['', '', '', None], cls_of), 't-rt', filt=True))
    tipage = rt.get('tip_age')
    if tipage and int(tipage['value']) > 600:
        A(note(f"**This node has not reached the tip.** Its newest block was minted "
               f"{int(tipage['value']) / 86400:.1f} days ago, about {int(tipage['value']) / 18:,.0f} blocks behind the "
               f"live network, and it is ingesting them at "
               f"{rt['ingest_rate']['value'] if 'ingest_rate' in rt else '?'} blocks per second — replay speed, not "
               f"tip speed. Every other reading here is self-consistent and says **OK**: that is the point of the "
               f"finding *Nothing in GetInfo tells you whether the node has reached the tip*. Read the two "
               f"★ rows below before any of the others.", 'bad'))
        A(catchup_svg(by))
    A(evolved(by, sfiles(['runtime']), what='this section'))
    inc = gi('incoming_connections_count', 1)
    if str(inc) == '0':
        A(note('**Incoming peers are zero.** Every peer in the pool was dialled out by this node. The listener is up, but '
               'nothing outside can reach it: see finding *The peer-to-peer listener is UDP, not TCP* — a TCP forward '
               'on 11011 forwards nothing, because no TCP socket on 11011 exists.', 'warn'))
    A('</section>')

    # ───── r23c: the evolution of the tree, read from git
    evo_section(by, A, H)

    # ───── 02 package map
    A(H('map', 'What the tree is made of',
        'Eighteen first-party packages. Size is measured by walking the tree, and every import edge below is proved by '
        'the import line that creates it — so the diagram is the dependency graph the compiler sees, not a drawing of '
        'one. Hover any arrow to trace it; the ▶ plays them in turn.'))
    A(kpis([(f"{len(pkgs)}", 'first-party packages'), (f"{sum(p['loc'] for p in pkgs):,}", 'lines of Go'),
            (f"{sum(p['files'] for p in pkgs)}", 'source files'),
            (f"{sum(p['test_files'] for p in pkgs)}", 'test files'),
            (f"{len(deps)}", 'import edges'), (f"{len(by['vendor'])}", 'vendored modules drawn')]))
    A(fig(dk.lanes(pkg_spec(pkgs, deps), dkcls, W=1120),
          'Import relations between the first-party packages, grouped into the tiers the imports imply. '
          'An arrow means at least one file of the left package imports the right one; the count is in the table below.',
          'first-party package import graph'))
    A(fig(dk.bars([{'label': p['pkg'], 'value': p['loc'], 'note': p['claim'][:160], '_row': p} for p in pkgs[:12]],
                  dkcls, W=1000, label_w=180, unit=' lines'), dkcls and
          'The twelve largest packages by measured non-test lines. walletapi and cmd dominate because both carry '
          'several binaries’ worth of behaviour.', 'lines of code per package'))
    A(evolved(by, prefixes=sorted(p['pkg'].rstrip('/') + '/' for p in pkgs), what='this package map'))
    ptr = [[f'<b class="mono">{E(p["pkg"])}</b>', md(p.get('claim').split(' Measured:')[0]),
            f'<span class="num">{p["loc"]:,}</span>', f'<span class="num">{p["files"]}</span>',
            f'<span class="num">{p["test_files"]}</span>', proof(p, 1)] for p in pkgs]
    A(table(['Package', 'Role', 'Lines', 'Files', 'Tests', 'proof'],
            ak.tag_rows(ptr, pkgs, ['', '', '', '', '', None], cls_of), 't-pkg', filt=True))
    top = sorted(deps, key=lambda d: -d['count'])[:18]
    dtr = [[f'<span class="mono">{E(d["from"])} → {E(d["to"])}</span>', f'<span class="num">{d["count"]}</span>', proof(d, 1)]
           for d in top]
    A('<h3>The most-used import edges</h3>')
    A(table(['Edge', 'Import lines', 'proof'], ak.tag_rows(dtr, top, ['', '', None], cls_of), 't-dep'))
    A('</section>')

    # ───── 03 consensus
    A(H('consensus', 'The rules, and the arithmetic behind them',
        'Every constant below was read out of the line that declares it. Where a number follows from others — the '
        'halving interval, the bounds on a difficulty step — it is computed at build time from those same lines, so '
        'the page cannot drift from the tree.'))
    GROUPS = [('cadence', 'Cadence and chain shape', 'How often a block is expected and when it is considered settled.'),
              ('difficulty', 'The difficulty controller', 'An exponential controller with a damping factor and two clamps.'),
              ('emission', 'Emission and the reward split', 'What a block pays, and to whom.'),
              ('tx', 'Transaction limits', 'What the verifier will accept.'),
              ('state', 'State trees', 'The two graviton trees that hold all consensus state.'),
              ('hardfork', 'Hard forks', 'The heights at which the rules changed.'),
              ('network', 'Network identity and ports', 'Which port is which — the most common operational trap on this page.')]
    for key, title, lede in GROUPS:
        g = by[key]
        if not g:
            continue
        A(f'<h3>{E(title)}</h3><p class="lede" style="margin:4px 0 8px">{md(lede)}</p>')
        if key == 'difficulty':
            A(diff_chart(by))
        if key == 'emission':
            A(emit_chart(by))
        A(evolved(by, sfiles([key]), what='this group'))
        tr = [[f'<b>{E(r["title"])}</b>', f'<code>{E(r["value"])}</code>', md(r.get('role') or ''), proof(r, 1)] for r in g]
        A(table(['Rule', 'Value in the tree', 'Why it matters', 'proof'],
                ak.tag_rows(tr, g, ['', '', '', None], cls_of), f't-c-{key}'))
    A('</section>')

    # ───── 04 flows
    A(H('flows', 'The paths a block, a share and a transaction actually take',
        'Each chain is a declared sequence of hops; the build locates every hop in the tree and refuses to draw the '
        'chain if even one of them has moved. Hover a connector to trace it, or press ▶ to walk the chain in order.'))
    chains = {r['chain']: r for r in by['flows']}
    hops = collections.defaultdict(list)
    for h in by['hops']:
        hops[h['chain']].append(h)
    for cid, c in chains.items():
        hs = sorted(hops[cid], key=lambda h: h['order'])
        A(f'<h3>{E(c["title"])}</h3><p class="lede" style="margin:4px 0 10px">{md(c["claim"])}</p>')
        A(evolved(by, {rel(e['abs']) for h in hs for e in h['evidence']}, what='this chain'))
        A(fig(dk.lanes(flow_spec(cid, c['title'], hs), dkcls, W=1120),
              f'{len(hs)} hops, each anchored on the line that implements it.', c['title']))
        srows = [{'n': h['order'], 'where': h['layer'], 'what': h.get('fn') or h['title'], 'object': h.get('where'),
                  'state': None, 'note': h['claim'], '_row': h} for h in hs]
        A(fig(dk.steps(srows, dkcls, W=1120), 'The same chain as a stepper: where each hop runs, what it does, and the '
                                              'file and line it was found at.', c['title'] + ' — steps'))
    A('</section>')

    # ───── 05 findings
    A(H('findings', 'What reading the code against the running node established',
        'Two of these are defects in code this node runs; two are local fixes already shipped; the rest is arithmetic '
        'and operational fact. Each card lists what it costs and what, if anything, should be done — including where '
        'the right answer is to change nothing.'))
    F = sorted(by['findings'], key=lambda r: ['defect', 'operational', 'reporting', 'fix', 'analysis'].index(r.get('severity', 'analysis')))
    A(evolved(by, sfiles(['findings']), what='these findings'))
    A('<div class="cards">')
    for r in F:
        word, col = SEV.get(r.get('severity'), ('note', 'var(--mut)'))
        A(f'''<div class="card {E(r.get('severity',''))}" id="{E(r['id'])}">
          <h4>{E(r['title'])} {tag(r)}</h4>
          <div>{chip(word, col)}{badges(r)}</div>
          <p>{md(r['claim'])}</p>
          <div class="meta"><b>Impact.</b> {md(r.get('impact',''))}<br><b>What to do.</b> {md(r.get('action',''))}
          <br><span class="mut">Proof:</span> {proof(r, 4)}</div></div>''')
    A('</div></section>')


    # ───── node intelligence: what the intel tools measured on the live node, its logs and its datadir
    intel = by.get('intel', [])
    if intel:
        A(H('intel', 'Node intelligence: the logs, the datadir and the tests, measured',
            'Three read-only tools look at what the daemon leaves behind. **log_intel** splits every JSON log the node '
            'wrote into runs and measures each one; **datadir_intel** checks the on-disk stores against the formats '
            'the Go source defines and against the running node; **go_mutate** undoes each local fix and checks that '
            'its test notices. Every number below is read from the snapshot the tool wrote.'))
        runs = [r for r in intel if r.get('kind') == 'log-run']
        dd = [r for r in intel if r.get('kind') == 'datadir']
        other = [r for r in intel if r.get('kind') in ('mutation', 'discovery', 'metrics', 'outcome', 'metrics-live', 'share-gaps', 'split-regime', 'run-ledger',
                                                       'split-binding', 'miner-runs', 'payout-ledger', 'contention')]
        mruns = [r for r in intel if r.get('kind') == 'miner-run']
        cur = runs[-1] if runs else None
        A(kpis([(str(sum(1 for r in dd if r.get('result') == 'PASS')) + '/' + str(sum(1 for r in dd if r.get('result') != 'INFO')),
                 'datadir checks passing'),
                (f"{cur['mean']} s" if cur else '\u2014', 'mean block interval, current run'),
                (str(cur['errors_at_tip']) if cur else '\u2014', 'ERROR lines at tip, current run'),
                (next((f"{r['caught']}/{r['total']}" for r in other if r.get('kind') == 'mutation'), '\u2014'),
                 'Go mutations caught'),
                (next((f"{r['confirmed']}+{r['partly']}/{r['findings']}" for r in other if r.get('kind') == 'discovery'), '\u2014'),
                 'discovery findings confirmed (+partly)')]))
        A(evolved(by, sfiles(['intel']), what='this section'))
        if runs:
            A(fig(dk.bars([{'label': r['title'][:44], 'value': r['mean'] or 0,
                            'note': f"mean {r['mean']} s · median {r['median']} s · p90 {r['p90']} s over {r['intervals']:,} intervals",
                            '_row': r} for r in runs], dkcls, W=1000, label_w=330, unit=' s'),
                  'Mean interval between blocks while at the tip, one bar per run of the daemon (target 18 s). The '
                  'gaps are skewed (p90 about 31 s), so the median sits near 16 s while the mean sits near 18.5 s; the '
                  '64-hour run measures 18.54 s here and 18.52 s in the Round-6 GetInfo audit, two independent '
                  'instruments.', 'Block cadence per run'))
            rtr = [[f'<b>{E(r["title"])}</b>', f'<span class="mono">{r["mean"]} / {r["median"]} / {r["p90"]}</span>',
                    f'<span class="mono">{r["errors_at_tip"]}</span>',
                    E('; '.join(f"{x['level']} {x['rule']}" for x in r['alerts']) or 'none'), proof(r, 1)] for r in runs]
            A(table(['Run', 'mean / median / p90 s', 'ERRORs at tip', 'alerts', 'proof'],
                    ak.tag_rows(rtr, runs, ['', '', '', '', None], cls_of), 't-intel-runs'))
        if mruns:
            mtr = [[f'<b>{E(r["title"])}</b>' + (f'<br><span class="mono">{E(r["start"][:16])} \u2192 {E(str(r.get("end"))[:16])} '
                    f'\u00b7 {E(Path(str(r.get("log"))).name)} \u00b7 {r.get("accepted_in_window")} accepted, longest gap '
                    f'{r.get("longest_gap_s")} s</span>' if r.get('end') else ''),
                    f'<span class="mono">{r["mean_hs"]} / {r["staged_hs"]}</span>',
                    f'<span class="mono">{r["drop_fraction"]}</span>', f'<span class="mono">{r["paid_fraction"]}</span>',
                    E('; '.join(f"{x['level']} {x['rule']}" for x in r['alerts']) or 'none'), proof(r, 1)] for r in mruns]
            A('<h3>The miner, measured from its own log</h3>')
            A(table(['Run', 'TOTAL / GPU-staged H/s (mean)', 'stale-drop fraction', 'paid fraction', 'alerts', 'proof'],
                    ak.tag_rows(mtr, mruns, ['', '', '', '', '', None], cls_of), 't-intel-miner'))
        if dd:
            RC = {'PASS': 'var(--ok)', 'FAIL': 'var(--gap)', 'KNOWN': 'var(--warn)', 'INFO': 'var(--mut)'}
            dtr = [[f'<span class="mono">{E(r["title"])}</span>', chip(r['result'].lower(), RC.get(r['result'], 'var(--mut)')),
                    tk.html_clip(r['claim'].split(' \u2014 ', 1)[-1], 160), proof(r, 1)] for r in dd]   # html_clip output is markup: never E() it
            A('<h3>The datadir, checked against the code that writes it</h3>')
            A(table(['Check', 'Result', 'What decided it', 'proof'],
                    ak.tag_rows(dtr, dd, ['', '', '', None], cls_of), 't-intel-dd'))
        if other:
            A('<div class="cards">')
            for r in other:
                A(f'''<div class="card analysis" id="{E(r['id'])}"><h4>{E(r['title'])} {tag(r)}</h4>
                  <div>{badges(r)}</div><p>{md(r['claim'])}</p>
                  <div class="meta"><span class="mut">Proof:</span> {proof(r, 2)}</div></div>''')
            A('</div>')
        A('</section>')


    # ───── coverage and the risk surface
    cov = by.get('coverage', [])
    rk = by.get('riskmap', [])
    if cov:
        tot = next((r for r in cov if r.get('kind') == 'total'), None)
        A(H('coverage', 'What this page covers, and the risk surface it does not yet explain',
            'A function counts as **covered** when some row cites a line inside it. **Risk** functions are the ones '
            'whose names carry verification, proof of work, difficulty, fees, balances, handshakes, bans or pruning. '
            'The register below lists every one of them with measured structure only — size, callers, panics, '
            'recovers — and is excluded from the coverage figure so it cannot inflate it. Gate G16 is a ratchet: it '
            'fails if any risk function that an earlier snapshot covered is uncovered now.'))
        if tot:
            A(kpis([(f"{tot['risk_covered']}/{tot['risk']}", 'risk functions cited by a row'),
                    (f"{tot['covered']}/{tot['funcs']}", 'functions covered'),
                    (str(sum(1 for r in rk if r.get('consensus'))), 'risk functions in consensus packages'),
                    (str(sum(1 for r in rk if r.get('panics'))), 'risk functions that can panic()')]))
        A(evolved(by, sfiles(['riskmap']), what='the risk register'))
        pk = [r for r in cov if r.get('kind') == 'pkg']
        if pk:
            A(fig(dk.bars([{'label': r['pkg'], 'value': r['risk'] - r['risk_covered'],
                            'note': r['claim'][:150], '_row': r} for r in pk[:12]], dkcls, W=1000, label_w=260, unit=' uncovered'),
                  'Uncovered risk functions per package. The two new execution paths on this page (transaction '
                  'verification and miniblock proof of work) close part of the blockchain package\u2019s gap.',
                  'Uncovered risk functions by package'))
        if rk:
            rtr = [[f'<span class="mono">{E(r["title"])}</span>', f'<span class="mono">{E(r["file"])}</span>',
                    f'<span class="mono">{r["lines"]}</span>', f'<span class="mono">{r["caller_files"]}</span>',
                    f'<span class="mono">{r["panics"]}/{r["recovers"]}</span>',
                    chip('consensus' if r['consensus'] else 'local', 'var(--gap)' if r['consensus'] else 'var(--mut)'),
                    proof(r, 1)] for r in sorted(rk, key=lambda r: (-r['panics'], r['file']))]
            A('<h3>The risk register</h3>')
            A(table(['Function', 'File', 'Lines', 'Files using it', 'panic/recover', 'Package', 'proof'],
                    ak.tag_rows(rtr, rk, ['', '', '', '', '', '', None], cls_of), 't-riskmap', filt=True))
        A('</section>')


    # ───── console errors, triaged
    tri = by.get('triage', [])
    if tri:
        A(H('triage', 'Every error the console printed: whose it is, and what it costs',
            'A console full of ERROR lines reads as a sick node. It usually is not. Each class below is traced to the '
            'Go line that prints it, to the side of the connection that produced it, and to what the chain itself '
            'says about the transactions involved. The keyhash and tx-store checks are **recomputed at build '
            'time**, not quoted. Each row also says what **this tree** now does about it: the fixes are logging '
            'and peer handling only, and the consensus guard proves no consensus-visible line changed.'))
        org = {o[0]: o[1] for o in ORIGIN}
        A(kpis([(str(sum(r.get('count', 0) for r in tri)), 'ERROR lines in the capture'),
                (str(len(tri)), 'distinct causes'),
                (str(sum(r.get('count', 0) for r in tri if r['origin'] == 'REMOTE')), 'produced on a peer, not here'),
                (str(sum(1 for r in tri if r['origin'] == 'LOCAL' and 'defect' in r.get('triage_verdict', ''))), 'defects in code this node runs'),
                ('0', 'need action on this node')]))
        A(triage_svg(by))
        A(evolved(by, sfiles(['triage']), what='the triage'))
        for c in by.get('triage-census', []):
            A(f'<p class="sub">{md(c["claim"])} {tag(c)} <span class="mut">Proof:</span> {proof(c, 2)}</p>')
        order = [o[0] for o in ORIGIN]
        tri = sorted(tri, key=lambda r: (order.index(r.get('origin', 'REMOTE')), r['id']))
        ttr = [[f'<b>{E(r["title"].split(":")[0].split(",")[0])}</b>', chip(r['origin'].lower(), 'var(--mut)'),
                f'<span class="mono">{r.get("count", "")}</span>', E(r.get('triage_verdict', '')),
                md(tk.html_clip(r.get('fix') or 'unchanged', 90)), proof(r, 2)] for r in tri]
        A(table(['Error', 'Origin', 'Count', 'Verdict', 'This tree now', 'proof'],
                ak.tag_rows(ttr, tri, ['', '', '', '', '', None], cls_of), 't-tri', filt=True))
        A('<div class="cards">')
        for r in tri:
            A(f'''<div class="card {'defect' if r['origin'] == 'LOCAL' and 'defect' in r.get('triage_verdict', '') else 'analysis'}" id="{E(r['id'])}">
              <h4>{E(r['title'])} {tag(r)}</h4>
              <div>{chip(org.get(r['origin'], r['origin']), 'var(--l4)')}{chip(r.get('triage_verdict', ''), 'var(--mut)')}{badges(r)}</div>
              <p>{md(r['claim'])}</p>
              <div class="meta"><b>Impact.</b> {md(r.get('impact', ''))}<br><b>What to do.</b> {md(r.get('action', ''))}
              {('<br><b>Fixed in this tree.</b> ' + md(r['fix'])) if r.get('fix') else ''}
              <br><span class="mut">Proof:</span> {proof(r, 8)}</div></div>''')
        A('</div></section>')


    # ───── disclosure audit: what was said, and what the tree says back
    press, fore = by['press'], by['forensics']
    if press or fore:
        A(H('press', 'The Foundation\u2019s disclosure, tested against this tree',
            'On 2026-10-20 the DERO Foundation published a range-proof soundness defect and withdrew support for '
            'the chain. The claims are reproduced below from the page\u2019s own text and carry the **EXT** class: a '
            'line of that document proves only that it was *said*. Whether each is **so** is decided by the rows '
            'underneath, which anchor in the source tree and in the running node instead. The two are deliberately '
            'kept apart.'))
        VCOL = {'CONFIRMED': 'var(--gap)', 'PARTLY-CONFIRMED': 'var(--warn)', 'REFUTED': 'var(--ok)',
                'CANNOT-DETERMINE-LOCALLY': 'var(--mut)'}
        if fore:
            A(kpis([(str(len(fore)), 'findings that survived adversarial review'),
                    (str(sum(1 for r in fore if r.get('audit_verdict') == 'CONFIRMED')), 'press claims confirmed here'),
                    (str(sum(1 for r in fore if r.get('audit_verdict') == 'REFUTED')), 'refuted here'),
                    (str(sum(1 for r in fore if r.get('audit_verdict') == 'CANNOT-DETERMINE-LOCALLY')),
                     'not decidable from a pruned node')]))
        A(evolved(by, sfiles(['forensics']), what='the audit'))
        if press:
            A('<h3>What was claimed</h3>')
            ptr = [[f'<b>{E(r["title"])}</b>', md(tk.html_clip(r.get('what') or '', 150)), proof(r, 1)] for r in press]
            A(table(['Claim', 'What it asserts', 'proof'],
                    ak.tag_rows(ptr, press, ['', '', None], cls_of), 't-press', filt=True))
        if fore:
            A(verdict_matrix(by))
            A('<h3>The confirmed defect, structurally</h3>')
            A(sharedbase_svg(by))
            A('<h3>What this tree and this node show</h3>')
            A('<div class="cards">')
            order = {'CONFIRMED': 0, 'PARTLY-CONFIRMED': 1, 'CANNOT-DETERMINE-LOCALLY': 2, 'REFUTED': 3}
            for r in sorted(fore, key=lambda r: (order.get(r.get('audit_verdict'), 4), r['id'])):
                v = r.get('audit_verdict', '?')
                A(f'''<div class="card {E(r.get("severity", ""))}" id="{E(r["id"])}">
                  <h4>{E(r["title"])} {tag(r)}</h4>
                  <div>{chip(v.lower().replace("-", " "), VCOL.get(v, "var(--mut)"))}
                       {chip(r.get("severity", "note"), "var(--mut)")}
                       {chip("bears on " + str(r.get("press_claim", "\u2014")), "var(--l4)")}
                       {badges(r)}</div>
                  <p>{md(r["claim"])}</p>
                  <div class="meta"><b>How it was established.</b> {md(r.get("reasoning", ""))}
                  <br><span class="mut">Proof:</span> {proof(r, 5)}</div></div>''')
            A('</div>')
        A(disclosure_track_html(by))   # r24: round history, new facts, potential fixes
        A('</section>')

    # ───── r24: every area of the stack, scored (after the disclosure audit, so its section number is unchanged)
    areakit.render(by, A, H, {'E': E, 'md': md, 'proof': proof, 'table': table, 'ak': ak, 'cls_of': cls_of, 'kpis': kpis})
    # ───── r24: the chain-consensus observatory (after Areas, so sections 10 and 11 keep their numbers)
    consensuskit.render(by, A, H, {'E': E, 'md': md, 'proof': proof, 'table': table, 'ak': ak, 'cls_of': cls_of, 'kpis': kpis,
                                   'note': note, 'fig': fig, 'chip': chip, 'dk': dk, 'tk': tk})

    # ───── r24 (consensus-network): the nodes this node talks to, pseudonymised (after Areas, so 10 and 11 keep their numbers)
    peerkit.render(by, A, H, {'E': E, 'md': md, 'proof': proof, 'table': table, 'ak': ak, 'cls_of': cls_of, 'kpis': kpis,
                              'fig': fig, 'chip': chip})

    # ───── 06 log bridge
    A(H('bridge', 'Every line the daemon printed, joined to the line that printed it',
        'The console is evidence only if each line can be traced to the source that emits it. A match counts only when '
        'the literal sits in a package that owns the logger name derod printed — the registry below is mined from the '
        '`WithName` calls themselves, so the rule is read out of the tree rather than asserted here.'))
    A(evolved(by, sfiles(['logbridge', 'loggers']), what='the bridge'))
    lb = sorted(by['logbridge'], key=lambda r: (r['t'], r['id']))
    ltr = [[f'<span class="mono">{E(r["t"])}</span>', chip(r['level'].lower(), 'var(--gap)' if r['level'] == 'ERROR' else 'var(--mut)'),
            f'<span class="mono">{E(r["logger"])}</span>', tk.html_clip(r['message'], 86),
            proof(r, 2)] for r in lb]
    A(table(['Time', 'Level', 'Logger', 'Message', 'proof'],
            ak.tag_rows(ltr, lb, ['', '', '', '', None], cls_of), 't-lb', filt=True))
    lg = sorted(by['loggers'], key=lambda r: r['title'])
    A('<h3>The logger registry</h3>')
    A(table(['Name', 'Registered in', 'proof'],
            ak.tag_rows([[f'<span class="mono">{E(r["title"])}</span>', f'<span class="mono">{E(r["owner"])}</span>', proof(r, 1)]
                         for r in lg], lg, ['', '', None], cls_of), 't-lg'))
    A('</section>')

    # ───── 07 local changes
    A(H('local', 'What this tree does that upstream Release153 does not',
        'The baseline is the upstream tag, and the diff is `git diff Release153..HEAD`. Only twelve shipped Go files '
        'differ; everything else added here is documentation, this harness, or experiments that no binary links.'))
    loc = sorted(by['local'], key=lambda r: (r['status'], r['path']))
    A(evolved(by, {r['path'] for r in loc}, what='this diff'))
    A(kpis([(str(len(loc)), 'shipped Go files changed'),
            (str(sum(r['added'] for r in loc)), 'lines added'), (str(sum(r['removed'] for r in loc)), 'lines removed'),
            (str(len(by['commits'])), 'commits on the branch'),
            (str(len([r for r in by['local-other'] if r.get('kind') == 'experiment'])), 'experiment-only paths')]))
    ltr2 = [[f'<span class="mono">{E(r["path"])}</span>', chip(r['status'], 'var(--ok)' if r['status'] == 'added' else 'var(--l4)'),
             f'<span class="num">+{r["added"]} / −{r["removed"]}</span>', tk.html_clip(r.get('subject') or '', 70),
             proof(r, 1)] for r in loc]
    A(table(['File', 'Status', 'Lines', 'Commit subject', 'proof'],
            ak.tag_rows(ltr2, loc, ['', '', '', '', None], cls_of), 't-loc'))
    cm = by['commits']
    A('<h3>The commit ledger</h3>')
    A(table(['Commit', 'Subject', 'Files', 'Shipped Go', 'proof'],
            ak.tag_rows([[f'<code>{E(r["sha"])}</code>', tk.html_clip(r['subject'], 86),
                          f'<span class="num">{r["files"]}</span>', f'<span class="num">{r["code_files"]}</span>', proof(r, 1)]
                         for r in cm], cm, ['', '', '', '', None], cls_of), 't-cm', filt=True))
    A('</section>')

    # ───── 08 vendored
    A(H('deps', 'The third-party code this build links in',
        'Vendored modules are quoted, not owned — they carry the EXT class. A module is listed only when a first-party '
        'import line proves it is really linked; two of the largest are transitive and are named in the quarantine instead.'))
    A(evolved(by, prefixes=('vendor/', 'go.mod'), what='the vendored tree'))
    vd = sorted(by['vendor'], key=lambda r: -r['loc'])
    A(table(['Module', 'Lines', 'Files', 'Imported by', 'proof'],
            ak.tag_rows([[f'<span class="mono">{E(r["module"])}</span>', f'<span class="num">{r["loc"]:,}</span>',
                          f'<span class="num">{r["files"]}</span>',
                          ' '.join(f'<code>{E(p)}</code>' for p in (r.get('importers') or [])[:4]), proof(r, 1)]
                         for r in vd], vd, ['', '', '', '', None], cls_of), 't-vd'))
    A('</section>')

    # ───── 09 quarantine
    A(H('quarantine', 'What was refused, and why',
        'A page that only shows what it can prove is worth nothing unless it also shows what it could not. These rows '
        'were produced by the miners and then dropped, or were reported by a miner as unprovable in the first place.'))
    A(kpis([(str(stats['rejected']), 'rows refused and not drawn'), (str(stats['unverified']), 'items a miner could not anchor'),
            (str(stats.get('reclassed', 0)), 'rows re-classed from their evidence'),
            (str(stats['anchors'] - stats['anchors_ok']), 'individual anchors that did not resolve')]))
    if rejected:
        A('<h3>Refused rows</h3>')
        A(table(['Id', 'From', 'Title', 'Why it was refused'],
                [[f'<code>{E(x.get("id"))}</code>', f'<code>{E(x.get("source"))}</code>',
                  tk.html_clip(str(x.get('title') or ''), 70), tk.html_clip(str(x.get('why')), 190)] for x in rejected],
                't-rej', notag='a ledger of rows that are NOT part of the page’s claims'))
    if unverified:
        A('<h3>Items a miner could not anchor</h3>')
        A(table(['From', 'Item', 'Why'],
                [[f'<code>{E(u.get("source"))}</code>', tk.html_clip(str(u.get('title') or ''), 70),
                  tk.html_clip(str(u.get('why')), 220)] for u in unverified],
                't-unv', notag='a ledger of items the miners refused to claim'))
    A('</section>')

    # ───── 10 index
    A(H('index', 'Everything on this page, searchable',
        'One entry per drawn row. Type two characters, or pick a facet.'))
    IX = [{'id': r['id'], 'n': E(str(r.get('title') or r['id'])), 's': r['page_section'],
           'c': ak.ctag(cls_of(r)), 'w': E(rel(r['evidence'][0]['abs']) + ':' + str(r['evidence'][0].get('line')))}
          for r in rows]
    facets = collections.Counter(r['page_section'] for r in rows)
    A('<input type="search" id="sx-q" placeholder="search every row…" aria-label="search every row">')
    A('<div id="sx-facets">' + ''.join(f'<button class="sx-f" data-f="{E(k)}">{E(k)} <b>{v}</b></button>'
                                       for k, v in sorted(facets.items())) + '</div>')
    A('<div id="sx-res"></div>')
    A(f'<script>window.__IX={json.dumps(IX)};</script>')
    A('</section>')

    # ───── 11 method
    A(H('method', 'How to re-run, break and extend this',
        'The page is a projection. Re-running the harness on an unchanged tree must reproduce it byte for byte; '
        'changing anything it cites must make `check` fail.'))
    A(f'''<details open><summary>The pipeline</summary>
      <pre style="overflow-x:auto;font:12px/1.6 var(--mono);color:var(--mut)">python3 harness/prep_corpus.py            # index the tree: {CORPUS.name}/tags.tsv, pkgindex.json, manifest.json
python3 harness/miners/mine_inventory.py  # packages, import graph, vendored weight
python3 harness/miners/mine_consts.py     # consensus constants, read from their declaring lines
python3 harness/miners/mine_flows.py      # the six execution chains, hop by hop
python3 harness/miners/mine_logbridge.py  # console lines -> the Go literal that printed them
python3 harness/miners/mine_localdiff.py  # this tree vs upstream Release153
python3 harness/miners/mine_evolution.py  # r23c: rounds x subsystems x modules from git log base..HEAD
python3 harness/miners/mine_runtime.py --capture   # a fresh read-only snapshot of the live daemon
python3 harness/miners/mine_findings.py   # the analysis rows (numbers computed, never typed)
python3 harness/gen_deroarch.py build     # resolve + render + stamp + skill AUTO block
python3 harness/run_gates.py &lt;label&gt;      # G1..G12 -> harness/loop/GATES.md
python3 harness/kat/verify_deroarch.py --mutations   # DK01..DK35; each mutation must flip its KAT</pre></details>''')
    cnt = collections.Counter(e['kind'] for r in rows for e in r['evidence'])
    A('<h3>What the evidence is made of</h3>')
    A(table(['Class', 'Anchors', 'What a line of it proves'],
            [[chip(k, {'SRC': 'var(--ok)', 'EXT': 'var(--l4)', 'HARNESS': 'var(--accent2)', 'GK': 'var(--queued)',
                       'PLAN': 'var(--mut)'}.get(k, 'var(--mut)')), f'<span class="num">{v}</span>', md(w)]
             for k, v, w in [(k, cnt.get(k, 0), w) for k, w in
                             [('SRC', 'a line of the first-party DERO source, its build scripts or go.mod'),
                              ('EXT', 'a line of third-party code under `vendor/` that this build links in'),
                              ('HARNESS', 'the owner’s own measured system: a live snapshot, the console log, the run report'),
                              ('GK', 'the project’s knowledge base: its skill and memory store'),
                              ('PLAN', 'something proposed in `harness/loop/PROPOSALS.md` and not yet run')]] if v or k in ('SRC', 'EXT')],
            't-cls', notag='the class vocabulary itself, not an asset'))
    A(f'''<footer>Built by <code>harness/gen_deroarch.py</code> from {stats['raw']} mined rows
      · {stats['anchors_ok']} of {stats['anchors']} anchors resolved · fingerprint <code>{E(fp)}</code>
      · {E(now.strftime('%Y-%m-%d %H:%M %Z'))}. Private page; it cites absolute paths on this machine.
      <br>Evolution (r23c): base {E(next((r['base'] for r in by.get('evolution', []) if r.get('kind') == 'evo-base'), '?'))}
      = tag Release152 = merge-base(HEAD, Release153); a commit belongs to the round its subject names (Round N / RN / rN),
      the Release142 port to R1–R3, any other commit to the next round-marked commit; rounds grouped as the Enhancement
      Ledger groups them.</footer>''')
    A('</section></div>')

    head = (f'<style>{CSS}{ak.CT_CSS}{ak.CITE_CSS}{ck.CONNECTOR_CSS}{tk.TT_CSS}{dk.CSS}</style>')
    body = ''.join(O) + ak.cites_script() + f'<script>{ak.CT_JS}{ak.CITE_JS}{tk.TT_JS}{JS}{ck.CONNECTOR_JS}</script>'
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>DERO HE Source Architecture</title>'
            + head + '</head><body>' + body + '</body></html>')


# ───────────────────────────── stamp, drift, skill sync ─────────────────────────────
from prep_corpus import sha   # noqa: E402 — ONE definition of the content hash. It excludes the
# skill's AUTO block, which this build writes, so the page can never be stale against its own output.


def sources(rows):
    """Everything the page depends on. A change to any of it makes the page STALE (living-architecture law)."""
    s = {str(HERE / 'gen_deroarch.py'), str(HERE / 'prep_corpus.py'), str(SKILL)}
    s |= {str(p) for p in (HERE / 'kit').glob('*.py')}
    s |= {str(p) for p in (HERE / 'miners').glob('*.py')}
    s |= {str(p) for p in RAW.glob('*.json')}
    s |= {str(p) for p in VERIFY.glob('*.json')}
    s |= {str(CORPUS / 'pkgindex.json'), str(CORPUS / 'manifest.json')}
    s |= {e['abs'] for r in rows for e in r['evidence']}
    return sorted(s)


def inputs_time(root=None, env=None):
    """r26 B93: the time the page prints. It was datetime.now(), so no two builds of one tree were byte-exact (§0.9 rule
    2; tooling_intel --determinism: 'DIFFERS'). Now SOURCE_DATE_EPOCH when set (the reproducible-builds convention),
    else the HEAD commit time of the tree, else now (no git). The wall-clock build time stays in harness/stamp.json
    ('built'), which is a record, not a generated page."""
    env = os.environ if env is None else env
    tz = datetime.datetime.now().astimezone().tzinfo
    v = str(env.get('SOURCE_DATE_EPOCH') or '').strip()
    if v.isdigit():
        return datetime.datetime.fromtimestamp(int(v), tz)
    r = subprocess.run(['git', '-C', str(root or ROOT), 'log', '-1', '--format=%ct', 'HEAD'], capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip().isdigit():
        return datetime.datetime.fromtimestamp(int(r.stdout.strip()), tz)
    return datetime.datetime.now().astimezone()


def fingerprint(src):
    h = hashlib.sha256()
    for p in src:
        h.update(f'{p}:{sha(p)}\n'.encode())
    return h.hexdigest()[:16]


def svg_lint(h):
    """Text that overflows its own box is a lie the eye believes. One violation is one too many."""
    bad = []
    for m in re.finditer(r'<svg[^>]*viewBox="0 0 ([\d.]+) ([\d.]+)"(.*?)</svg>', h, re.S):
        w = float(m.group(1))
        for t in re.finditer(r'<text x="(-?[\d.]+)"[^>]*font-size="([\d.]+)"[^>]*text-anchor="(\w+)"[^>]*>(.*?)</text>',
                             m.group(3), re.S):
            x, size, anc = float(t.group(1)), float(t.group(2)), t.group(3)
            # Measure only what RENDERS inline. textkit puts the full sentence of a clipped label in a
            # <title> tooltip (and a ⓘ marker in a tspan) INSIDE the <text>; neither takes inline width, so
            # drop the title's text before counting, or a correctly-clipped label reads as an overflow.
            inner = re.sub(r'<title>.*?</title>', '', t.group(4), flags=re.S)
            txt = re.sub(r'<[^>]+>', '', inner)
            wpx = len(txt) * size * tk.CW
            right = x + wpx if anc == 'start' else (x + wpx / 2 if anc == 'middle' else x)
            if right > w + 2 or (anc == 'start' and x < -2):
                bad.append(f'{txt[:40]!r} right={right:.0f} > {w:.0f}')
    return bad


def sync_skill(st=None):
    """Two-way: the build rewrites the skill's AUTO block; the hand-written part of the skill is a page source."""
    if not SKILL.exists():
        return False
    st = st or json.loads(STAMP.read_text())
    s = st['stats']
    g = (LOOP / 'GATES.md')
    # newest result per gate in the latest cycle: a fixed [-12:] window under-counted once G13 existed (coherence-07)
    rows = [l.split('|') for l in (g.read_text().splitlines() if g.exists() else []) if l.startswith('| 20')]
    cyc = rows[-1][2].strip() if rows else ''
    latest = {}
    for r in rows:
        if r[2].strip() == cyc:
            latest[r[3].strip()] = '|'.join(r)
    last = list(latest.values())
    gp = sum(1 for l in last if '| PASS |' in l)
    k = json.loads((LOOP / 'KAT_LAST.json').read_text()) if (LOOP / 'KAT_LAST.json').exists() else {}
    block = (f'<!-- AUTO:BEGIN  written by harness/gen_deroarch.py build — do not edit by hand -->\n'
             f'### Living architecture page (auto)\n\n'
             f'`artifacts/dero-src-arch.html` is a projection of `harness/model/`, rebuilt by '
             f'`python3 harness/gen_deroarch.py build`.\n\n'
             f'| what | value |\n|---|---|\n'
             f'| built | {st["built"]} |\n| fingerprint | `{st["fingerprint"]}` |\n'
             f'| rows drawn / mined | {s["rows"]} / {s["raw"]} |\n'
             f'| anchors resolved | {s["anchors_ok"]} / {s["anchors"]} |\n'
             f'| rows refused (quarantined) | {s["rejected"]} |\n'
             f'| items a miner could not anchor | {s.get("unverified", 0)} |\n'
             f'| svg text-fit violations | {st.get("svg_lint", "?")} |\n'
             f'| last gate run | {gp}/{len(last)} PASS |\n'
             f'| KATs | {k.get("ok", "?")}/{k.get("total", "?")} ok, mutations proved {k.get("mut_proved", "?")}/{k.get("muts", "?")} |\n\n'
             f'Re-run after ANY change to the tree: `python3 harness/prep_corpus.py && for m in '
             f'inventory consts flows logbridge localdiff evolution runtime findings; do python3 harness/miners/mine_$m.py; done '
             f'&& python3 harness/gen_deroarch.py build && python3 harness/run_gates.py manual`.\n'
             f'<!-- AUTO:END -->')
    t = SKILL.read_text()
    SKILL.write_text(AUTO_RE.sub(lambda _: block, t) if AUTO_RE.search(t) else t.rstrip() + '\n\n' + block + '\n')
    return True


def build():
    rows, rejected, unverified, stats = resolve()
    LOOP.mkdir(exist_ok=True)
    (MODEL / 'verified.json').write_text(json.dumps(rows, indent=1, ensure_ascii=False))
    (LOOP / 'REJECTED.json').write_text(json.dumps(rejected, indent=1, ensure_ascii=False))
    (LOOP / 'UNVERIFIED.json').write_text(json.dumps(unverified, indent=1, ensure_ascii=False))
    (LOOP / 'UNVERIFIED.md').write_text('# Items the miners could not anchor\n\n| from | item | why |\n|---|---|---|\n'
                                        + ''.join(f"| {u.get('source')} | {str(u.get('title'))[:90].replace('|', '/')} | "
                                                  f"{str(u.get('why'))[:220].replace('|', '/')} |\n" for u in unverified))
    # r26 B93: refresh the corpus index BEFORE the fingerprint. It ran only after the page was written, so the page
    # hashed the PREVIOUS build's manifest.json (its root, the runtime files added since) and a second build of the same
    # tree printed another fingerprint. The manifest reads no output of this build (SKILL.md is hashed without its AUTO
    # block), so the refresh after sync_skill below writes the same bytes again.
    subprocess.run([sys.executable, str(HERE / 'prep_corpus.py')], capture_output=True)
    src = sources(rows)
    fp = fingerprint(src)
    h = render(rows, rejected, unverified, stats, fp)
    lint = svg_lint(h)
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(h)
    st = {'built': datetime.datetime.now().astimezone().isoformat(timespec='seconds'), 'fingerprint': fp, 'root': str(ROOT),
          'stats': stats, 'svg_lint': len(lint), 'svg_lint_examples': lint[:4], 'bytes': len(h.encode()),
          'sources': {p: sha(p) for p in src}}
    STAMP.write_text(json.dumps(st, indent=1))
    # sync_skill runs LAST and is hash-neutral: sha() excludes the AUTO block it writes, so the fingerprint
    # the skill reports is the final one. The corpus manifest indexes the same inputs, so refresh it and
    # re-hash the two derived index files the build itself just rewrote.
    sync_skill(st)
    subprocess.run([sys.executable, str(HERE / 'prep_corpus.py')], capture_output=True)
    for own in (CORPUS / 'manifest.json', CORPUS / 'pkgindex.json'):
        if str(own) in st['sources']:
            st['sources'][str(own)] = sha(own)
    STAMP.write_text(json.dumps(st, indent=1))
    bad = [r for r in rows if not r['evidence']]
    print(f"build: {stats['rows']} rows ({stats['raw']} mined, {stats['rejected']} refused) · "
          f"{stats['anchors_ok']}/{stats['anchors']} anchors · svg_lint {len(lint)} · "
          f"{len(h):,} bytes · fingerprint {fp}")
    if lint:
        print('  svg_lint:', lint[:3])
    return 3 if bad or lint else 0


def stamp_root(st):
    """the checkout the stamp was built in: its 'root' (R20+), else derived from where gen_deroarch.py itself was"""
    if st.get('root'):
        return st['root']
    k = next((p for p in st.get('sources', {}) if p.endswith('/harness/gen_deroarch.py')), None)
    return k[:-len('/harness/gen_deroarch.py')] if k else None


def relocate(p, old_root, new_root=None):
    """a path recorded under the checkout `old_root`, re-read under this checkout. Stamps and evidence record
    ABSOLUTE paths, so before R20 `check` and G2 in a clone silently judged the LIVE tree (H7 follow-up): the clone's
    own edits could not make its page STALE. Paths outside old_root (the datadir, ~/...) are left alone."""
    new_root = str(new_root or ROOT)
    p = str(p)
    if old_root and old_root != new_root and (p == old_root or p.startswith(old_root.rstrip('/') + '/')):
        return new_root + p[len(old_root.rstrip('/')):]
    return p


def check(stamp=STAMP):
    if not stamp.exists() or not OUT.exists():
        print('STALE: never built')
        return 3
    st = json.loads(stamp.read_text())
    old = stamp_root(st)
    drift = [p for p, s in st['sources'].items() if sha(relocate(p, old)) != s]
    if OUT.stat().st_size != st['bytes']:
        drift.append(str(OUT) + ' (page edited by hand)')
    print(('CURRENT' if not drift else f'STALE: {len(drift)} source(s) changed, e.g. '
           + ', '.join(Path(d).name for d in drift[:4])) + f" · {len(st['sources'])} sources tracked")
    return 0 if not drift else 3


def selftest():
    """check and resolve must be ABLE to fail, or neither proves anything."""
    import tempfile
    ok = True
    st = json.loads(STAMP.read_text())
    me = next((p for p in st['sources'] if p.endswith('/harness/gen_deroarch.py')), str(HERE / 'gen_deroarch.py'))
    tampered = {**st, 'sources': {**st['sources'], me: 'deadbeefdeadbeef'}}
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
        json.dump(tampered, f)
    r1 = check(Path(f.name))
    ok &= r1 == 3
    good = resolve_ev({'file': 'config/config.go', 'quote': 'const BLOCK_TIME = uint64(18)'})
    bad = resolve_ev({'file': 'config/config.go', 'quote': 'const BLOCK_TIME = uint64(1800)'})
    short = resolve_ev({'file': 'config/config.go', 'quote': 'const'})
    outside = resolve_ev({'file': '/etc/hosts', 'quote': 'localhost is not evidence here'})
    ok &= good['status'] == 'OK' and bad['status'] == 'MISSING' and short['status'] == 'SHORT' and outside['status'] == 'OUTSIDE'
    print(f"selftest: tampered stamp → {r1} (want 3) · real quote → {good['status']} · altered → {bad['status']} "
          f"· short → {short['status']} · outside-root → {outside['status']} · {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 3


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'build'
    if cmd == 'resolve':
        rows, rej, unv, stats = resolve()
        print(json.dumps(stats))
        print('\n'.join(f"REJ {x['id']}: {str(x['why'])[:150]}" for x in rej[:40]))
        sys.exit(0)
    if cmd == 'export-verify':
        VERIFY.mkdir(exist_ok=True)
        rows = resolve()[0]
        keep = ('role', 'value', 'impact', 'action', 'severity', 'where', 'pkg', 'loc', 'path', 'message', 'emitter', 'field')
        for name, keys in (('A', ('findings', 'consts')), ('B', ('flows', 'hops', 'logbridge')),
                           ('C', ('packages', 'imports', 'vendor', 'local', 'commits', 'runtime'))):
            sel = [{'id': r['id'], 'source': r['source'], 'section': r.get('section'), 'title': r.get('title'),
                    'claim': r.get('claim'), **{k: r.get(k) for k in keep if r.get(k) is not None},
                    'evidence': [{'file': e['abs'], 'line': e['line'], 'quote': e['quote']} for e in r['evidence']]}
                   for r in rows if r.get('section') in keys]
            (VERIFY / f'in_{name}.json').write_text(json.dumps(sel, indent=1, ensure_ascii=False))
            print(name, len(sel))
        sys.exit(0)
    if cmd == 'export-pending':
        rows = resolve()[0]
        pend = [r for r in rows if r.get('verdict') is None]
        print(f'{len(pend)} row(s) without a current verdict:',
              dict(collections.Counter(r['section'] for r in pend)))
        sys.exit(0)
    if cmd == 'sync-skill':
        sys.exit(0 if sync_skill() else 3)
    sys.exit({'build': build, 'check': check, 'selftest': selftest}[cmd]())
