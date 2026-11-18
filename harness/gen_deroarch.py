#!/usr/bin/env python3
"""gen_deroarch.py — the projection behind artifacts/dero-src-arch.html. Never hand-edit the page.

  python3 gen_deroarch.py resolve   # check every raw row against its evidence → model/verified.json + loop/REJECTED.json
  python3 gen_deroarch.py build     # resolve + render + stamp + rewrite the skill's AUTO block
  python3 gen_deroarch.py check     # 0 CURRENT · 3 STALE (a model file, kit module, miner or cited file changed)
  python3 gen_deroarch.py selftest  # proves check and resolve can fail
  python3 gen_deroarch.py build --strict   # r27: exit 3 when an anchor of a mined row went MISSING (stale raw file)
  python3 gen_deroarch.py --help    # this text, exit 0 (an unknown command: usage on stderr, exit 2)

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

r33 OVERHAUL (the way artifacts/dero-enhanced-game-theory.html was rebuilt). The page is grouped into six parts
(PARTS: orientation, the source tree, the running node, findings and audits, observatories, the harness) under a
sticky contents column; sections render into their own buffers and are numbered in contents order. New: plain-language
orientation sections (start, tour, lifecycle, glossary) and a harness section, generated SVG diagrams (the tree in
layers, the execution paths in order, the build pipeline), chartkit charts with a <title>, a <desc> naming every value
and a data table (kitgate G13), design tokens with a light and a dark theme and a theme button, citations named from
the repository root, and the privacy pass pub() (no local path, address, LAN address or machine name; page_lint makes
the build exit 3 if one survives). The records and section ids coherence binds to are unchanged.
KAT harness/kat/test_src_arch_page_r33.py (SA0-SA8, 14 mutations).
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
import chartkit as chk           # noqa: E402  (r33: accessible charts, each with its text alternative)
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


# r27 (tools-kats; R26 measurement: a build after consensus_intel / area_intel but before mine_consensus / mine_areas
# printed 6352/6396 anchors and nothing else: 43 consensus rows quoted harness/runtime/consensus_intel.json values the
# fresh intel run had replaced). resolve() tallies every anchor that did not resolve per (raw key, miner, file, status);
# build() names each one with the miner to re-run, and `build --strict` fails on any.
LOST = collections.Counter()
LOST_STATUSES = ('MISSING', 'NOFILE')


def lost_report(lost):
    """the warning lines of a LOST tally, largest first: '<n> anchor(s) <status> in raw/<key>.json -> <file>: re-run
    harness/miners/<miner> (the file changed after the miner quoted it)'. Pure."""
    out = []
    for (key, miner, f, status), n in sorted(lost.items(), key=lambda kv: (-kv[1], kv[0])):
        what = 'is gone' if status == 'NOFILE' else 'changed after the miner quoted it'
        out.append(f"{n} anchor(s) {status} in raw/{key}.json -> {f}: re-run harness/miners/{miner or 'mine_' + key + '.py'} "
                   f"(the file {what})")
    return out


def resolve():
    rows, rejected, unverified, seen = [], [], [], set()
    stats = collections.Counter()
    LOST.clear()
    for key in RAW_KEYS:
        f = RAW / f'{key}.json'
        if not f.exists():
            continue
        d = json.loads(f.read_text())
        miner = d.get('generated_by')
        for u in d.get('unverified') or []:
            unverified.append({'source': key, **(u if isinstance(u, dict) else {'title': str(u)})})
        for r in d.get('rows') or []:
            stats['raw'] += 1
            rid = str(r.get('id') or f'{key}-{stats["raw"]}')
            evs = [resolve_ev(e) for e in (r.get('evidence') or []) if isinstance(e, dict)]
            good = [e for e in evs if e['status'] in ('OK', 'MULTI')]
            stats['anchors'] += len(evs)
            stats['anchors_ok'] += len(good)
            for e in evs:
                if e['status'] in LOST_STATUSES:
                    LOST[(key, miner, e['file'], e['status'])] += 1
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
        # r33: the citation names the file from the repository root ('/' + path, as the game-theory page does): no
        # absolute local path reaches the page; the quote is scrubbed of home/datadir paths by pub() at the end
        out.append(ak.cite_file('/' + rel(e['abs']).lstrip('/'), e.get('line'), e.get('quote', ''), cls=e.get('kind') or 'SRC',
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
        # r33: a file:line label (repo-relative), not an editor link: the row's class tag opens the same citation
        bits.append(f'<span class="pf" title="{E(e.get("quote", "")[:220])}">{E(rel(e["abs"]))}:{e.get("line")}</span>')
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


# the architectural tier of each first-party package (r33: shared by the import graph and the layered overview)
PKG_TIER = {'cmd': 'binaries', 'tools': 'binaries', 'p2p': 'network', 'blockchain': 'consensus', 'dvm': 'consensus', 'block': 'consensus',
            'walletapi': 'wallet', 'rpc': 'wire', 'transaction': 'wire', 'proof': 'wire',
            'cryptography': 'primitives', 'astrobwt': 'primitives', 'pow': 'primitives',
            'config': 'foundation', 'globals': 'foundation', 'metrics': 'foundation', 'glue': 'foundation',
            'errormsg': 'foundation', 'premine': 'foundation'}
TIERS = [('binaries', 'Programs you run', 'the executables: the daemon, the wallet, the miner, the explorer, the simulator and tools'),
         ('network', 'Talking to peers', 'how a node finds peers and exchanges blocks and transactions with them'),
         ('wallet', 'The wallet', 'keys, encrypted balances and building transfers on the user side'),
         ('consensus', 'Consensus and execution', 'what makes a block valid, how the chain grows, and the smart-contract VM'),
         ('wire', 'Wire formats and the API', 'the objects that travel: transactions, proofs and the JSON-RPC types'),
         ('primitives', 'Cryptography and proof of work', 'the maths the rules rest on: pairing curves, range proofs, AstroBWT'),
         ('foundation', 'Shared foundation', 'configuration, process-wide state, metrics and the glue between layers')]


def pkg_spec(pkgs, deps):
    """The first-party import graph. Lanes are the architectural tiers the imports themselves imply."""
    TIER = PKG_TIER
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


def track_verdicts(root=None):
    """r30 (B227): {claim id: (verdict, round)} of the disclosure track's newest entry per claim
    (harness/loop/disclosure_track.json); {} when unreadable. The press KPIs and the matrix caption read it, so they
    follow the track instead of the R8 audit rows."""
    import json as _j
    try:
        t = _j.loads((Path(root or ROOT) / 'harness/loop/disclosure_track.json').read_text())
    except (OSError, ValueError):
        return {}
    return {c['id']: (c['history'][-1].get('verdict'), c['history'][-1].get('round')) for c in t.get('claims') or [] if c.get('history')}


def press_kpis(tv):
    """r30 (B227): [(value, label)] counted over the track's C1-C8 verdicts. Pure."""
    cs = [tv[f'C{i}'][0] for i in range(1, 9) if f'C{i}' in tv]
    rd = next((tv[f'C{i}'][1] for i in range(1, 9) if f'C{i}' in tv), 'pending')
    return [(str(len(cs)), f'press claims C1-C8 re-tested (track, {rd})'), (str(cs.count('CONFIRMED')), 'confirmed here'),
            (str(cs.count('PARTLY-CONFIRMED')), 'partly confirmed'), (str(cs.count('REFUTED')), 'refuted here'),
            (str(cs.count('CANNOT-DETERMINE-LOCALLY')), 'not decidable from a pruned node')]


def matrix_caption(tv):
    """r30 (B227): the C1 / C2 sentence of the matrix caption from the track (C2 is PARTLY-CONFIRMED there, not
    refuted). Pure."""
    w = lambda c: {'CONFIRMED': 'confirmed', 'PARTLY-CONFIRMED': 'partly confirmed', 'REFUTED': 'refuted',
                   'CANNOT-DETERMINE-LOCALLY': 'not decidable locally'}.get((tv.get(c) or ('pending',))[0], 'pending')
    return f'The headline (C1) is {w("C1")}; the stated *mechanism* (C2) is {w("C2")} (disclosure track, {(tv.get("C1") or (None, "pending"))[1]}).'


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
    TV = track_verdicts()
    LABEL = {'C1': 'A soundness defect exists', 'C2': 'Mechanism: prover-adjustable unbound generator',
             'C3': 'The broken check is the sole magnitude gate', 'C4': 'Inherited from ConsenSys Zether',
             'C5': 'Present from genesis of the proof path', 'C6': 'HF3 double-spend; 23.9M created (floor)',
             'C7': '5,000,000 burned in the same era', 'C8': 'Ending support; no rollback'}
    rh, top, W = 34, 8, 1000
    Hh = top + len(claims) * rh + 6
    o = [f'<svg class="dk" viewBox="0 0 {W} {Hh}" xmlns="http://www.w3.org/2000/svg">']
    for k, (c, r) in enumerate(claims):
        y = top + k * rh
        v = (TV.get(c) or (r.get('audit_verdict', '?'),))[0]
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
              'pruned node.** ' + (matrix_caption(TV) if TV else 'The headline (C1) is confirmed; the stated *mechanism* (C2) is the one refuted outright.'),
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
# ───────────────────────────── r33: theme tokens, layout, privacy ─────────────────────────────
# The page is rebuilt (r33) the way artifacts/dero-enhanced-game-theory.html was: design tokens with a light and a dark
# theme (prefers-color-scheme, overridden by the theme button: :root[data-theme]), a sticky table of contents grouped
# into parts, plain-language orientation sections over the deep technical reference, generated inline SVG diagrams and
# chartkit charts (each with a <title>, a <desc> naming every value and a data table), evidence tags that open the exact
# file:line citations, and no local path, address, LAN address or machine name (pub()). KAT harness/kat/test_src_arch_page_r33.py.
LIGHT = {'bg': '#f3f5f7', 'surface': '#ffffff', 'surface-2': '#eef2f5', 'fg': '#131a21', 'muted': '#55636f', 'line': '#d3dbe2',
         'rule': '#e1e7ec', 'accent': '#0b6e75', 'accent-soft': '#dcefee', 'accent2': '#9a5a18', 'series-1': '#2a78d6',
         'series-2': '#8a96a3', 'alert': '#b3412f', 'ok': '#15703f', 'warn': '#9a6212', 'gap': '#ab2f27', 'l4': '#245f99',
         'queued': '#6b5bbf', 'flow': '#b0661a', 'code-bg': '#f2f4f6',
         'shadow': '0 1px 2px rgba(20,30,40,.06),0 6px 22px rgba(20,30,40,.06)'}
DARK = {'bg': '#0e1216', 'surface': '#161c22', 'surface-2': '#1c242b', 'fg': '#e4ecf2', 'muted': '#97a6b3', 'line': '#2c3843',
        'rule': '#243039', 'accent': '#4fc3cc', 'accent-soft': '#12343a', 'accent2': '#d79a52', 'series-1': '#3987e5',
        'series-2': '#6b7884', 'alert': '#ef8a78', 'ok': '#4bbd7e', 'warn': '#d7a04a', 'gap': '#e87a6f', 'l4': '#6aa6e0',
        'queued': '#a292ec', 'flow': '#e9a25a', 'code-bg': '#12171b',
        'shadow': '0 1px 2px rgba(0,0,0,.4),0 8px 26px rgba(0,0,0,.35)'}
# the names the kit modules (assetkit, connectorkit, diagramkit, areakit, consensuskit, peerkit) and the older sections
# read: each is an alias of a theme token, so both themes reach every block without a second palette
ALIASES = ('--panel:var(--surface);--panel2:var(--surface-2);--ink:var(--fg);--mut:var(--muted);--cluster:var(--accent);'
           '--host:var(--accent);--ak-accent:var(--accent);--ak-alert:var(--gap);--ak-line:var(--line);--ak-panel:var(--surface);'
           '--ak-panel2:var(--surface-2);--ak-ink:var(--fg);--ak-muted:var(--muted);--ak-src:var(--ok);--ak-harness:var(--accent2);'
           '--ak-plan:var(--l4);--ak-gk:var(--queued);--sans:var(--body)')


def theme_css():
    v = lambda d: ';'.join(f'--{k}:{x}' for k, x in d.items())
    return (f':root{{{v(LIGHT)};{ALIASES};color-scheme:light;'
            '--body:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;'
            '--mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;--radius:10px}'
            f'@media (prefers-color-scheme: dark){{:root:not([data-theme="light"]){{{v(DARK)};color-scheme:dark}}}}'
            f':root[data-theme="dark"]{{{v(DARK)};color-scheme:dark}}')


CSS = r'''
*{box-sizing:border-box}
html{scroll-behavior:smooth;-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 var(--body);-webkit-font-smoothing:antialiased;overflow-x:hidden}
a{color:var(--accent);text-underline-offset:2px}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:3px}
code,.mono{font-family:var(--mono)}
h1,h2,h3{text-wrap:balance;margin:0}
.skip{position:absolute;left:-999px;top:8px;background:var(--surface);padding:8px 12px;border:1px solid var(--line);z-index:99}.skip:focus{left:8px}
/* ── layout: a sticky contents column beside the page ── */
.layout{display:grid;grid-template-columns:236px minmax(0,1fr);gap:40px;max-width:1360px;margin:0 auto;padding:0 26px}
nav.toc{position:sticky;top:0;align-self:start;max-height:100vh;overflow:auto;padding:28px 0;font-size:13px}
.toct{font:700 11px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin:0 0 10px 10px}
nav.toc ol,#tocd ol{list-style:none;margin:0;padding:0}
nav.toc li.part,#tocd li.part{font:700 10.5px/1.2 var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--accent);margin:14px 0 4px 10px}
nav.toc a,#tocd a{display:flex;gap:9px;align-items:baseline;padding:4px 10px;border-radius:7px;color:var(--fg);text-decoration:none;line-height:1.3}
nav.toc a:hover,#tocd a:hover{background:var(--surface-2)}nav.toc a.on{background:var(--accent-soft);color:var(--accent);font-weight:600}
.sn{font:700 11px/1 var(--mono);color:var(--muted);min-width:1.6em}
#tocd{display:none;margin:10px 14px 0;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:8px 10px}
#tocd summary{cursor:pointer;font-weight:600}
main{min-width:0;padding:28px 0 80px}
/* ── hero ── */
.hero{display:grid;gap:10px;padding:6px 0 4px}
.kicker{font:600 12px/1.4 var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--accent)}.kick2{color:var(--muted);text-transform:none;letter-spacing:0}
h1{font-size:clamp(28px,4.2vw,44px);line-height:1.06;letter-spacing:-.025em;font-weight:760;max-width:26ch}
h1 .dim{color:var(--muted);font-weight:420}
.lede{color:var(--muted);max-width:76ch;margin:8px 0 16px}
.hero .lede{font-size:17px;margin:0}
.hero-links{display:flex;flex-wrap:wrap;gap:10px;margin-top:4px}
.btn{display:inline-flex;align-items:center;gap:6px;font:600 13.5px/1 var(--body);padding:10px 14px;border-radius:8px;border:1px solid var(--accent);background:var(--accent);color:var(--surface);text-decoration:none;cursor:pointer}
.btn.ghost{background:transparent;color:var(--accent)}.btn:hover{filter:brightness(1.08)}
.sub{margin:10px 0 0;max-width:80ch;color:var(--muted);font-size:14px}
.tickers{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.tick{display:flex;align-items:baseline;gap:7px;background:var(--surface);border:1px solid var(--line);border-radius:7px;padding:5px 10px;font-size:12px}
.tick b{font:700 13px/1 var(--mono);font-variant-numeric:tabular-nums}
.tick span{color:var(--muted);font-size:10.5px;letter-spacing:.05em;text-transform:uppercase}
.tick.live b{color:var(--ok)}
/* ── sections ── */
section{scroll-margin-top:14px;margin-top:50px}
h2{font-size:clamp(21px,2.4vw,25px);letter-spacing:-.012em;font-weight:720;display:flex;align-items:baseline;gap:12px;
   border-bottom:1px solid var(--line);padding-bottom:8px;margin:0 0 4px}
h2 .sn{font-size:12.5px;color:var(--accent);background:var(--accent-soft);border-radius:6px;padding:4px 7px;min-width:auto}
h3{font-size:17px;font-weight:700;margin:28px 0 8px;letter-spacing:-.005em}
h4{font-size:14.5px;font-weight:700;margin:0 0 6px}
.partbanner{margin:64px 0 -26px;font:700 11px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--accent)}
.prose p,.prose li{max-width:78ch}
.note{background:var(--surface-2);border-left:3px solid var(--line);padding:10px 13px;border-radius:0 7px 7px 0;margin:14px 0;font-size:13.5px;color:var(--muted);max-width:90ch}
.note.warn{border-left-color:var(--warn)} .note.bad{border-left-color:var(--gap)} .note.good{border-left-color:var(--ok)}
.note b{color:var(--fg)}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,340px),1fr));gap:14px;align-items:start}
.grid3{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,260px),1fr));gap:14px;align-items:start}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,330px),1fr));gap:14px;align-items:start}
.charts figure.chart{margin:0}
.lg{font:700 10px var(--mono);padding:0 4px;border:1px dotted currentColor;border-radius:3px}.lg-SRC{color:var(--ok)}.lg-EXT{color:var(--l4)}.lg-HARNESS{color:var(--accent2)}.lg-GK{color:var(--queued)}.lg-PLAN{color:var(--muted)}
/* ── kpis ── */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:18px 0}
.kpi{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:11px 13px;box-shadow:var(--shadow)}
.kv{font:700 21px/1.1 var(--mono);font-variant-numeric:tabular-nums;letter-spacing:-.02em}
.kl{color:var(--muted);font-size:11.5px;margin-top:5px;line-height:1.35}
/* ── tables ── */
.tw,.tablebox{overflow-x:auto;border:1px solid var(--line);border-radius:var(--radius);background:var(--surface);margin:12px 0;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;font-size:13px;font-variant-numeric:tabular-nums}
th{text-align:left;font:700 10.5px/1.3 var(--mono);letter-spacing:.07em;text-transform:uppercase;color:var(--muted);padding:9px 11px;border-bottom:1px solid var(--line);background:var(--surface-2);position:sticky;top:0;z-index:1}
td{padding:8px 11px;border-bottom:1px solid var(--rule);vertical-align:top}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:var(--surface-2)}
td .mono,td code{font-size:12px}
td code{word-break:break-word}
.num{font-variant-numeric:tabular-nums;text-align:right;white-space:nowrap}
.tf{display:flex;align-items:center;gap:9px;margin:14px 0 0}
.tf input{flex:0 1 300px;min-width:0;padding:6px 10px;border:1px solid var(--line);border-radius:7px;background:var(--surface);color:var(--fg);font:13px var(--body)}
.tfn{color:var(--muted);font-size:11.5px}
.pf{font-family:var(--mono);font-size:11.5px;color:var(--muted);border-bottom:1px dotted var(--line);white-space:nowrap;cursor:help}
@media (max-width:600px){.pf{white-space:normal;overflow-wrap:anywhere}}
.mut{color:var(--muted)}
.chip{display:inline-block;font:700 9.6px/1.5 var(--mono);letter-spacing:.05em;text-transform:uppercase;padding:1px 6px;border-radius:9px;color:var(--c);
      border:1px solid var(--c);background:color-mix(in srgb,var(--c) 11%,transparent);white-space:nowrap;margin-right:4px}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0}.chips a{font:600 12.5px var(--mono);padding:6px 10px;border:1px solid var(--line);border-radius:999px;background:var(--surface);text-decoration:none}
/* ── cards ── */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,330px),1fr));gap:13px;margin:16px 0}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:14px 16px;box-shadow:var(--shadow);min-width:0}
.card.defect{border-left:3px solid var(--gap)} .card.fix{border-left:3px solid var(--ok)}
.card.operational{border-left:3px solid var(--warn)} .card.analysis{border-left:3px solid var(--l4)}
.card.reporting{border-left:3px solid var(--muted)} .card.lead{border-top:3px solid var(--accent)}
.card h3{margin-top:2px;font-size:16px}
.card h4{margin:0 0 7px;font-size:14.5px;font-weight:710}
.card p{margin:7px 0;font-size:13.5px}
.card ul{padding-left:20px;margin:6px 0}.card li{margin:4px 0;font-size:13.5px}
.card code{overflow-wrap:anywhere}
.card .meta{margin-top:10px;padding-top:9px;border-top:1px solid var(--rule);font-size:12px;color:var(--muted)}
.card .meta b{color:var(--fg);font-weight:650}
.tier{border-left:4px solid var(--accent)}
.pkgl{list-style:none;padding:0;margin:8px 0 0}.pkgl li{padding:7px 0;border-top:1px solid var(--rule)}.pkgl li:first-child{border-top:0}
.pkgl .m{display:block;font:400 11.5px var(--mono);color:var(--muted)}
.legend{display:flex;flex-wrap:wrap;gap:8px 16px;margin:8px 0;font-size:13px}.legend span{display:inline-flex;gap:6px;align-items:baseline}
/* ── figures ── */
figure{margin:18px 0;min-width:0}
.figbox,.scrollx{overflow-x:auto;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:10px;-webkit-overflow-scrolling:touch}
figcaption{color:var(--muted);font-size:12.5px;margin-top:8px;max-width:86ch}
svg{display:block;max-width:100%;height:auto}
svg.dg{width:100%;min-width:760px;color:var(--fg)}
svg.dg .box{fill:var(--surface);stroke:var(--line);stroke-width:1.3}
svg.dg .boxa{fill:var(--accent-soft);stroke:var(--accent);stroke-width:1.4}
svg.dg .band{fill:var(--surface-2);stroke:none}
svg.dg .ln{stroke:var(--accent);stroke-width:1.7;fill:none}
svg.dg .ln.m{stroke:var(--flow)} svg.dg .ln.r{stroke:var(--series-2);stroke-width:1.5}
svg.dg .nb circle{fill:var(--accent)} svg.dg .nb text{font:700 10px var(--mono);fill:var(--surface);text-anchor:middle;dominant-baseline:central}
svg.dg a{cursor:pointer}svg.dg a:hover .box,svg.dg a:focus .box{stroke:var(--accent)}
/* ── index ── */
#sx-q{width:100%;max-width:520px;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:var(--surface);color:var(--fg);font:14px var(--body)}
#sx-facets{display:flex;flex-wrap:wrap;gap:6px;margin:11px 0}
.sx-f{font:600 11px/1 var(--body);padding:5px 9px;border:1px solid var(--line);border-radius:14px;background:var(--surface);color:var(--muted);cursor:pointer}
.sx-f.on{background:var(--accent);border-color:var(--accent);color:var(--surface)}
#sx-res{margin-top:12px;display:grid;gap:7px}
.sx-hit{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:9px 11px;font-size:13px}
.sx-hit a{font-weight:650;text-decoration:none}
.sx-hit .w{color:var(--muted);font-size:11.5px;display:block;margin-top:3px;overflow-wrap:anywhere}
details{background:var(--surface);border:1px solid var(--line);border-radius:9px;padding:11px 14px;margin:12px 0}
summary{cursor:pointer;font-weight:650;font-size:13.5px}
figure.chart details.chart-data{border:0;padding:0;background:none;margin:4px 0 0}
pre{background:var(--code-bg);border:1px solid var(--line);border-radius:8px;padding:12px 14px;overflow-x:auto;font:400 12px/1.6 var(--mono);max-width:100%}
footer{margin-top:56px;padding-top:18px;border-top:1px solid var(--rule);color:var(--muted);font-size:12.5px;max-width:96ch}
/* ── r23c: evolved strips and churn bars ── */
.evo{background:var(--surface-2);border:1px solid var(--rule);border-left:3px solid var(--accent);border-radius:0 8px 8px 0;padding:7px 11px;margin:10px 0 14px;font-size:12.5px}
.evo summary{font-weight:600;font-size:12.5px}
.evo ul{margin:8px 0 2px;padding-left:18px}.evo li{margin:3px 0;overflow-wrap:anywhere}
.evo-h{font:700 10px/1.4 var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--accent);margin-right:4px}
a.evo-c{display:inline-block;font:700 10px/1.5 var(--mono);padding:0 6px;margin:1px 2px;border-radius:9px;border:1px solid var(--accent);color:var(--accent);text-decoration:none;background:color-mix(in srgb,var(--accent) 10%,transparent)}
svg.evo-wide{min-width:860px}
.evo-bar{display:block;height:5px;width:var(--w);min-width:2px;border-radius:3px;background:var(--accent);opacity:.7;margin-bottom:3px}
/* in chart data tables a class tag is a coloured dot (it keeps its class name as its accessible label) */
figure.chart td .ct{font-size:0;width:8px;height:8px;padding:0;border-radius:50%;border:0;background:currentColor;margin-left:6px;vertical-align:1px;line-height:0}
@media (prefers-reduced-motion: reduce){html{scroll-behavior:auto}*{transition:none !important;animation:none !important}}
@media (max-width:900px){.layout{grid-template-columns:minmax(0,1fr);gap:0;padding:0 14px}nav.toc{display:none}#tocd{display:block}main{padding-top:16px}h1{max-width:none}section{margin-top:36px}.partbanner{margin:48px 0 -18px}.kpis{grid-template-columns:repeat(auto-fit,minmax(124px,1fr))}}
@media print{nav.toc,#tocd,.skip,#themebtn{display:none}.layout{display:block}}
'''

THEME_JS = r'''(function(){var r=document.documentElement,b=document.getElementById('themebtn'),k='sa-theme',m=['auto','light','dark'],v='auto';
function set(x){v=x;if(x==='auto')r.removeAttribute('data-theme');else r.setAttribute('data-theme',x);if(b){b.textContent='Theme: '+x;b.setAttribute('aria-label','Colour theme: '+x+' (click to change)');}}
v=r.getAttribute('data-theme')||'auto';try{v=localStorage.getItem(k)||v;}catch(e){}set(m.indexOf(v)<0?'auto':v);
if(b)b.addEventListener('click',function(){var n=m[(m.indexOf(v)+1)%3];try{localStorage.setItem(k,n);}catch(e){}set(n);});
var links=[].slice.call(document.querySelectorAll('nav.toc a'));if('IntersectionObserver' in window&&links.length){var io=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){links.forEach(function(a){a.classList.toggle('on',a.getAttribute('href')==='#'+e.target.id);});}});},{rootMargin:'-20% 0px -70% 0px'});
[].forEach.call(document.querySelectorAll('main>section[id]'),function(s){io.observe(s);});}})();'''

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

# r33: the page's privacy pass. Every display string (a quote in a tooltip or a citation, a claim, a log line) is
# scrubbed of what names this box: a home, datadir, repository or scratch path, the agent tool's directories, a DERO
# address, an e-mail, a LAN address and the machine's model names. The anchors themselves are untouched (they live in
# harness/model/verified.json and are re-read from disk by G1/G2); the page shows the placeholder instead.
PUB_RULES = [
    (re.compile(r'(?:/Users|/home)/[A-Za-z0-9._-]+/derohe-Release1\d\d\b'), '[repo]'),
    (re.compile(r'(?:/Users|/home)/[A-Za-z0-9._-]+/dero-data\b'), '[datadir]'),
    (re.compile(r'(?:/Users|/home)/[A-Za-z0-9._-]+/\.claude/[^\s"\'<>&,;)]*'), '[tool-dir]'),
    (re.compile(r'(?:/Users|/home)/[A-Za-z0-9._-]+'), '[home]'),
    (re.compile(r'/private/(?:tmp|var)/[^\s"\'<>&,;)]*'), '[scratch]'),
    (re.compile(r'~/dero-data\b'), '[datadir]'),
    (re.compile(r'~/derohe-Release1\d\d\b'), '[repo]'),
    (re.compile(r'(?:~/)?\.claude/[^\s"\'<>&,;)]*'), '[tool-dir]'),
    (re.compile(r'(?<![\w/.~-])~/(?=[A-Za-z0-9._-])'), '[home]/'),
    (re.compile(r'-Users-[A-Za-z0-9]+-[\w-]*'), '[project]'),
    (re.compile(r'\b(?:dero|deto)(?:1|i)[0-9a-z]{4,}\b'), '[address]'),   # a full address or a quoted prefix of one
    (re.compile(r'(?i)(?<![\w.+-])[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b'), '[e-mail]'),
    (re.compile(r'(?<![\d.])(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7]))(?:\.\d{1,3}){2}(?![\d\w]|\.\d)'), '[lan-ip]'),
    (re.compile(r'(?i)\bMac[- ]?Studio\b'), 'host'),
    (re.compile(r'(?i)\bMacBook(?:[- ](?:Pro|Air))?\b'), 'laptop'),
    (re.compile(r'(?i)\bM[1-9][- ]?(?:Ultra|Max|Pro)\b'), 'host'),
]
# r33: the node and user names come from outside the repo (privkit.private_terms), never as literals in this file
import privkit as _pk     # noqa: E402
PUB_RULES += _pk.private_terms()


def pub(h):
    """the page with every PUB_RULES match replaced by its placeholder. Pure."""
    for rx, rep in PUB_RULES:
        h = rx.sub(rep, h)
    return h


def privacy_problems(h, allowed_ips=None):
    """[why] for every private value left on the page (KAT SA5 and the build's page_lint). Pure but for the IP allow-list."""
    out = []
    for rx, rep in PUB_RULES:
        n = len(rx.findall(h))
        if n:
            out.append(f'{n} match(es) of the rule for {rep}')
    leaks = privkit.page_ip_leaks(h, allowed_ips if allowed_ips is not None else ())
    if leaks:
        out.append(f'{len(leaks)} non-reserved IPv4 literal(s) that no tracked .go file holds')
    return out


@functools.lru_cache(maxsize=1)
def _code_ips():
    return frozenset(privkit.code_literal_ips(ROOT))


def page_lint(h):
    """r33: what the build refuses beside svg_lint: a private value (pub() missed it) or a chart without its text
    alternative (chartkit.audit, kitgate G13)."""
    bad = [f'privacy: {p}' for p in privacy_problems(h, _code_ips())]
    ca = chk.audit(h)
    bad += [f'chart {c}: {why}' for c, why in ca['bad']]
    return bad


def current_round(root=None):
    """('r33', 'Round 33') from harness/round.json 'current'; ('', '') when unreadable."""
    try:
        cur = str(json.loads(((root or ROOT) / 'harness' / 'round.json').read_text()).get('current') or '')
    except (OSError, ValueError, AttributeError):
        return '', ''
    m = re.fullmatch(r'r(\d+)([a-z]?)', cur)
    return cur, (f'Round {m.group(1)}{m.group(2)}' if m else cur)


# ───────────────────────────── r33: page parts, chart and diagram helpers ─────────────────────────────
PARTS = [('Orientation', [('start', 'Start here'), ('tour', 'The tree in layers'), ('lifecycle', 'How the parts work together'),
                          ('glossary', 'Glossary')]),
         ('The source tree', [('map', 'Package map'), ('consensus', 'Consensus rules'), ('flows', 'Execution paths'),
                              ('deps', 'Vendored code'), ('local', 'Local changes'), ('evolution', 'Evolution')]),
         ('The running node', [('live', 'Live node'), ('intel', 'Node intelligence'), ('bridge', 'Log bridge'),
                               ('triage', 'Console errors')]),
         ('Findings and audits', [('findings', 'Findings'), ('coverage', 'Coverage and risk'), ('press', 'Disclosure audit')]),
         ('Observatories', [('areas', 'Areas'), ('chainobs', 'Chain observatory'), ('peers', 'Network peers')]),
         ('The harness', [('harness', 'How this page is built'), ('method', 'Re-run and extend'), ('quarantine', 'Quarantine'),
                          ('index', 'Index')])]
SECTION_IDS = [i for _, s in PARTS for i, _ in s]
# the chains of the flows section in the order a transfer meets them (r33 lifecycle diagram); the rest are miner internals
LIFE = ['startup', 'p2pconn', 'wallet', 'mining', 'minipow', 'ingest', 'txverify', 'scexec']
DEFS = ('<defs><marker id="sa-ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        '<path d="M0,0 L10,5 L0,10 z" fill="currentColor" opacity=".6"/></marker></defs>')


def rows_cl(rows, why):
    """one class tag for an asset drawn from many rows: the classes their anchors carry, with every row's citations
    (capped at 60, each class keeping at least one)."""
    xs = [c for r in rows if isinstance(r, dict) for c in cites_fn(r)]
    if not xs:
        return ak.fixed('HARNESS', why, [])
    kinds = sorted({c['c'] for c in xs}, key=lambda k: KIND_ORDER.index(k) if k in KIND_ORDER else 9)
    keep = []
    for k in kinds:
        keep.append(next(c for c in xs if c['c'] == k))
    for c in xs:
        if len(keep) >= 60:
            break
        if c not in keep:
            keep.append(c)
    return kinds, 'der', f'derived from the {len(rows)} row(s) it draws ({why})', keep


def chart_pill(rows, why, W=720):
    """the evidence pill of a chart (top-right of its plot area)."""
    return ak.svg_ctag(W - 4, 9, rows_cl(rows, why))[0]


def cell_tagger(rows):
    return lambda i: ak.ctag(cls_of(rows[i])) if i < len(rows) and isinstance(rows[i], dict) else ''


def hbar(cid, title, desc, rows, cats, vals, unit='', note='', W=720, label_w=190, **kw):
    """chartkit.hbar_chart tagged by the rows it draws (one pill on the plot, a dot per data-table cell)."""
    return chk.hbar_chart(cid, title, desc, cats, vals, unit=unit, note=note, W=W, label_w=label_w,
                          pill_svg=chart_pill(rows, title, W), cell_tag=cell_tagger(rows), **kw)


def vbar(cid, title, desc, rows, cats, vals, unit='', note='', W=340, H=210, tag_rows_=None):
    tr = tag_rows_ if tag_rows_ is not None else [[r] for r in rows]
    return chk.bar_chart(cid, title, desc, cats, vals, unit=unit, note=note, W=W, H=H,
                         pill_svg=chart_pill(rows, title, W), cell_tag=(lambda i: ak.ctag(rows_cl(tr[i], title)) if i < len(tr) and tr[i] else ''))


def shortlab(s, n=26):
    """a category label that fits a chart's label column, never cut mid-word with a lost sentence: the chart's <desc>
    and data table carry the full name."""
    s = str(s)
    return s if len(s) <= n else s[:n - 1].rstrip() + '.'


def first_num(v):
    """the number a declaring expression states: the literal inside a conversion (uint64(18) -> 18), else the last one."""
    s = str(v or '')
    m = re.search(r'\(\s*(\d[\d_]*)\s*\)', s) or ([*re.finditer(r'(?<![\w.])(\d[\d_]*)(?![\w.])', s)] or [None])[-1]
    return m.group(1).replace('_', '') if m else '?'


def tier_diagram(pkgs, deps):
    """r33: the tree in layers. One band per tier (PKG_TIER), a box per package with its measured size (its own
    class tag), and on the right one bracket per pair of tiers that import each other, its tooltip the import-line
    count: relations, not an execution order (connectorkit plays them top to bottom)."""
    by_t = collections.OrderedDict((t[0], []) for t in TIERS)
    for p in pkgs:
        by_t.setdefault(PKG_TIER.get(p['pkg'], 'foundation'), []).append(p)
    W, top, bh, gap, LW, RW = 1100, 14, 66, 24, 236, 196
    bands = [t for t in by_t if by_t[t]]
    H = top + len(bands) * (bh + gap) - gap + 14
    ty = {t: top + i * (bh + gap) for i, t in enumerate(bands)}
    name = {t[0]: t[1] for t in TIERS}
    tot = collections.Counter()
    for d in deps:
        a, b = PKG_TIER.get(d['from'], 'foundation'), PKG_TIER.get(d['to'], 'foundation')
        if a != b and a in ty and b in ty:
            tot[(a, b)] += d['count']
    edges = sorted(tot.items(), key=lambda kv: (abs(bands.index(kv[0][1]) - bands.index(kv[0][0])), bands.index(kv[0][0])))
    desc = (f'{len(bands)} layers of the first-party tree, top to bottom: ' + '; '.join(
        f"{name.get(t, t)}: " + ', '.join(f"{p['pkg']} ({p['loc']:,} lines)" for p in by_t[t]) for t in bands)
        + '. Import relations between layers (import lines): ' + '; '.join(f'{name.get(a, a)} imports {name.get(b, b)}: {n}' for (a, b), n in edges) + '.')
    o = [f'<svg class="dg" viewBox="0 0 {W} {H}" role="img" aria-labelledby="tier-t tier-d" data-cxkind="relations" '
         f'data-cxwhy="import relations between layers, not an execution order"><title id="tier-t">The DERO HE tree in {len(bands)} layers</title>'
         f'<desc id="tier-d">{E(desc)}</desc>{DEFS}']
    for t in bands:
        y = ty[t]
        o.append(f'<rect class="band notag" x="0" y="{y}" width="{W - RW + 6}" height="{bh}" rx="9"/>')
        o.append(dk.text(12, y + 26, tk.fit(name.get(t, t), LW - 18, 12.5, True), 12.5, weight='700'))
        o.append(dk.text(12, y + 45, tk.fit(f'{len(by_t[t])} package(s) · {sum(p["loc"] for p in by_t[t]):,} lines', LW - 20, 10.5), 10.5, fill='var(--muted)'))
        ps = by_t[t]
        avail = W - RW - LW - 6
        bw = min(220, (avail - 8 * (len(ps) - 1)) / len(ps))
        for k, p in enumerate(ps):
            x = LW + k * (bw + 8)
            pill, pw = ak.svg_ctag(x + bw - 5, y + 13, cls_of(p))
            o.append(f'<a href="#pkg-{E(p["pkg"])}"><g class="as"><rect class="box" x="{x:.1f}" y="{y + 7}" width="{bw:.1f}" height="{bh - 14}" rx="7"/>'
                     + dk.text(x + 9, y + 30, tk.fit(p['pkg'], bw - pw - 16, 12.5, True), 12.5, weight='700')
                     + dk.text(x + 9, y + 47, tk.fit(f"{p['loc']:,} lines · {p['files']} files" if bw >= 170 else f"{p['loc']:,} lines", bw - 14, 10), 10, fill='var(--muted)')
                     + pill + f'<title>{E(p["pkg"])}: {E((p.get("claim") or "").split(" Measured:")[0])}</title></g></a>')
    x0 = W - RW + 14
    for k, ((a, b), n) in enumerate(edges):
        ya, yb = ty[a] + bh / 2 + (k % 3 - 1) * 9, ty[b] + bh / 2 + (k % 3 - 1) * 9
        xk = x0 + 14 + k * ((RW - 40) / max(1, len(edges)))
        d = f'M{x0 - 10},{ya:.1f} L{xk:.1f},{ya:.1f} L{xk:.1f},{yb:.1f} L{x0 - 8},{yb:.1f}'
        o.append(f'<path class="ln r" d="{d}" marker-end="url(#sa-ah)"><title>{E(name.get(a, a))} imports {E(name.get(b, b))}: {n} import line(s)</title></path>')
    o.append('</svg>')
    tab = [[E(name.get(a, a)), E(name.get(b, b)), f'<span class="num">{n}</span>'] for (a, b), n in edges]
    rel_rows = [[d for d in deps if PKG_TIER.get(d['from'], 'foundation') == a and PKG_TIER.get(d['to'], 'foundation') == b] for (a, b), _ in edges]
    trs = [[c[0], c[1], c[2] + ' ' + ak.ctag(rows_cl(rr, 'the import edges it sums'))] for c, rr in zip(tab, rel_rows)]
    return ('<figure><div class="scrollx">' + ''.join(o) + '</div><figcaption>Each box is one first-party package (click it for its '
            'card); each bracket on the right joins two layers where a package of the upper one imports a package of the lower one '
            '(hover for the number of import lines, ▶ traces them in turn). The per-package graph is in the Package map.</figcaption>'
            '<details><summary>The layer relations as a table</summary>'
            + table(['Layer', 'imports layer', 'import lines'], trs, 't-tier-rel', notag='each count carries its own derived tag')
            + '</details></figure>')


def life_diagram(chains, hops):
    """r33: the execution paths in the order a transfer meets them, numbered (connectorkit plays them in order); the
    miner internals hang off the mining step as un-numbered connectors that say why they are not steps."""
    main = [c for c in LIFE if c in chains]
    extra = [c for c in chains if c not in LIFE]
    per, bw, bh, gx, gy = 4, 248, 92, 22, 44
    W = 20 + per * bw + (per - 1) * gx + 34
    nrow = (len(main) + per - 1) // per + (1 if extra else 0)
    H = 16 + nrow * (bh + gy) - gy + 30
    pos = {}
    for i, c in enumerate(main):
        r, k = divmod(i, per)
        k = k if r % 2 == 0 else per - 1 - k          # snake: the second row runs right to left
        pos[c] = (20 + k * (bw + gx), 16 + r * (bh + gy))
    if extra:                                      # miner internals: the last row, right-aligned under the right column
        r = (len(main) + per - 1) // per
        for k, c in enumerate(extra):
            pos[c] = (20 + (per - len(extra) + k) * (bw + gx), 16 + r * (bh + gy))
    desc = ('The execution paths of this page in the order a transfer meets them: ' + '; '.join(
        f'{i + 1} {chains[c]["title"].split(" — ")[0]} ({len(hops.get(c, []))} hops)' for i, c in enumerate(main))
        + ('. Miner internals beside the mining step: ' + '; '.join(chains[c]['title'].split(' — ')[0] for c in extra) if extra else '') + '.')
    o = [f'<svg class="dg" viewBox="0 0 {W} {H}" role="img" aria-labelledby="life-t life-d"><title id="life-t">How the parts work together: '
         f'the execution paths in order</title><desc id="life-d">{E(desc)}</desc>{DEFS}']
    for i, c in enumerate(main + extra):
        x, y = pos[c]
        ch = chains[c]
        hs = sorted(hops.get(c, []), key=lambda h: h['order'])
        lanes = list(dict.fromkeys(LAYER_LANE.get(h.get('layer'), h.get('layer')) for h in hs))
        pill, pw = ak.svg_ctag(x + bw - 6, y + 12, cls_of(ch))
        ln = ', '.join(lanes)
        sub2 = ln if len(ln) * 10 * tk.CW <= bw - 18 else f'{len(lanes)} layers'
        o.append(f'<a href="#chain-{E(c)}"><g class="as"><rect class="{"box" if c in LIFE else "boxa"}" x="{x}" y="{y}" width="{bw}" height="{bh}" rx="8"/>'
                 + dk.text(x + 10, y + 26, tk.fit(ch['title'].split(' — ')[0], bw - pw - 20, 12.5, True), 12.5, weight='700')
                 + dk.text(x + 10, y + 46, tk.fit(f'{len(hs)} hops, re-located at build time', bw - 18, 10.5), 10.5, fill='var(--muted)')
                 + dk.text(x + 10, y + 63, tk.fit(sub2, bw - 18, 10), 10, fill='var(--muted)')
                 + dk.text(x + 10, y + 80, tk.fit(f'starts at {rel(hs[0]["evidence"][0]["abs"]).split("/")[-1]}' if hs else '', bw - 18, 10), 10, fill='var(--muted)')
                 + pill + f'<title>{E(ch["title"])}</title></g></a>')
    for i in range(len(main) - 1):
        (x1, y1), (x2, y2) = pos[main[i]], pos[main[i + 1]]
        if y1 == y2:
            if x2 > x1:
                d, bx = f'M{x1 + bw},{y1 + bh / 2} L{x2 - 3},{y2 + bh / 2}', (x1 + bw + x2) / 2
            else:
                d, bx = f'M{x1},{y1 + bh / 2} L{x2 + bw + 3},{y2 + bh / 2}', (x2 + bw + x1) / 2
            by_ = y1 + bh / 2 - 13
        else:
            d = f'M{x1 + bw / 2},{y1 + bh} L{x2 + bw / 2},{y2 - 3}'
            bx, by_ = x1 + bw / 2 + 14, (y1 + bh + y2) / 2
        o.append(f'<g class="cx"><path class="ln" d="{d}" marker-end="url(#sa-ah)"/><g class="nb"><circle cx="{bx:.1f}" cy="{by_:.1f}" r="9"/>'
                 f'<text x="{bx:.1f}" y="{by_:.1f}">{i + 1}</text></g></g>')
    if 'mining' in pos:
        mx, my = pos['mining']
        for k, c in enumerate(extra):
            x, y = pos[c]
            xr = W - 8 - 6 * k                     # up the right margin, clear of every box
            o.append(f'<path class="ln m" d="M{x + bw - 30},{y} L{x + bw - 30},{y - 12 - 6 * k} L{xr},{y - 12 - 6 * k} L{xr},{my + 20 + 8 * k} L{mx + bw + 3},{my + 20 + 8 * k}" '
                     f'marker-end="url(#sa-ah)" data-cxwhy="a miner internal: how the miner produces the share of the mining step, not a step of the chain"/>')
    o.append(dk.text(W / 2, H - 8, 'numbered = the order a transfer meets the paths · orange = miner internals · click a box for its path', 10.5, anchor='middle', fill='var(--muted)'))
    o.append('</svg>')
    return ('<figure><div class="scrollx">' + ''.join(o) + '</div><figcaption>Press ▶ to walk the paths in order. Transaction '
            'verification and smart-contract execution run inside the core hops of block ingest; they are drawn after it because '
            'that is where a reader meets them in the code.</figcaption></figure>')


def pipe_diagram(stats, nraw, nsrc):
    """r33: how this page is built and checked, numbered in run order; each box cites the harness line that does it."""
    def at(relp, rx, why):
        p = ROOT / relp
        try:
            ls = p.read_text(errors='replace').splitlines()
        except OSError:
            return ak.fixed('HARNESS', why, [])
        ln = next((i + 1 for i, l in enumerate(ls) if re.search(rx, l)), None)
        if not ln:
            return ak.fixed('HARNESS', why, [])
        return ak.fixed('HARNESS', why, [ak.cite_file('/' + relp, ln, ls[ln - 1].strip()[:200], 'HARNESS', label=relp,
                                                     note="the harness's own code; path from the repository root")])
    steps = [('Index the tree', 'harness/prep_corpus.py', r'^def main|^if __name__', 'tags, package index, manifest'),
             ('Mine the rows', 'harness/miners/minelib.py', r'^def emit', f'{nraw} raw files, each row with anchors'),
             ('Resolve every anchor', 'harness/gen_deroarch.py', r'^def resolve\(', f"{stats['anchors_ok']:,}/{stats['anchors']:,} anchors re-read"),
             ('Render this page', 'harness/gen_deroarch.py', r'^def render\(', f"{stats['rows']:,} rows drawn"),
             ('Stamp the sources', 'harness/gen_deroarch.py', r'^def build\(', f'{nsrc:,} source hashes'),
             ('Page gates G5-G14', 'harness/kit/kitgate.py', r'G13', 'scripts, tags, citations, charts'),
             ('Known-answer tests', 'harness/kat/verify_deroarch.py', r'DK01', 'each with a mutation proof'),
             ('Coherence G25', 'harness/intel/coherence.py', r'^def check_srcarch', 'page figures = the records')]
    per, bw, bh, gx, gy = 4, 248, 80, 22, 44
    W = 20 + per * bw + (per - 1) * gx + 20
    H = 16 + 2 * (bh + gy) - gy + 16
    pos = []
    for i in range(len(steps)):
        r, k = divmod(i, per)
        k = k if r % 2 == 0 else per - 1 - k
        pos.append((20 + k * (bw + gx), 16 + r * (bh + gy)))
    desc = 'How the page is built, in run order: ' + '; '.join(f'{i + 1} {t} ({s}): {m}' for i, (t, s, _, m) in enumerate(steps)) + '.'
    o = [f'<svg class="dg" viewBox="0 0 {W} {H}" role="img" aria-labelledby="pipe-t pipe-d"><title id="pipe-t">How this page is built and checked</title>'
         f'<desc id="pipe-d">{E(desc)}</desc>{DEFS}']
    for i, (t, s, rx, m) in enumerate(steps):
        x, y = pos[i]
        cl = at(s, rx, f'step {i + 1}: {t}')
        pill, pw = ak.svg_ctag(x + bw - 6, y + 12, cl)
        o.append(f'<g class="as"><rect class="{"boxa" if i in (2, 7) else "box"}" x="{x}" y="{y}" width="{bw}" height="{bh}" rx="8"/>'
                 + dk.text(x + 10, y + 26, tk.fit(t, bw - pw - 20, 12.5, True), 12.5, weight='700')
                 + dk.text(x + 10, y + 46, tk.fit(s, bw - 18, 10), 10, fill='var(--muted)')
                 + dk.text(x + 10, y + 64, tk.fit(m, bw - 18, 10.5), 10.5) + pill + '</g>')
    for i in range(len(steps) - 1):
        (x1, y1), (x2, y2) = pos[i], pos[i + 1]
        if y1 == y2:
            if x2 > x1:
                d, bx = f'M{x1 + bw},{y1 + bh / 2} L{x2 - 3},{y2 + bh / 2}', (x1 + bw + x2) / 2
            else:
                d, bx = f'M{x1},{y1 + bh / 2} L{x2 + bw + 3},{y2 + bh / 2}', (x2 + bw + x1) / 2
            by_ = y1 + bh / 2 - 13
        else:
            d, bx, by_ = f'M{x1 + bw / 2},{y1 + bh} L{x2 + bw / 2},{y2 - 3}', x1 + bw / 2 + 14, (y1 + bh + y2) / 2
        o.append(f'<g class="cx"><path class="ln" d="{d}" marker-end="url(#sa-ah)"/><g class="nb"><circle cx="{bx:.1f}" cy="{by_:.1f}" r="9"/>'
                 f'<text x="{bx:.1f}" y="{by_:.1f}">{i + 1}</text></g></g>')
    o.append('</svg>')
    return ('<figure><div class="scrollx">' + ''.join(o) + '</div><figcaption>Press ▶ to walk the build in order. Steps 1–5 are '
            '<code>gen_deroarch.py build</code> and the miners before it; 6–8 are the gates that must pass before the page is '
            'trusted. A row whose anchor stops resolving at step 3 is not drawn: it goes to the quarantine.</figcaption></figure>')


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
    cur_id, cur_name = current_round()
    # r23c: the repo-relative files a group of rows cites, for the 'evolved' strips
    sfiles = lambda secs: {rel(e['abs']) for k in secs for r in by.get(k, []) for e in r['evidence']}
    # r33: every section renders into its own buffer (H opens it); the page assembles them in PARTS order and numbers
    # them there, so a section's number follows the table of contents, not the order the code draws it in
    bufs = collections.OrderedDict()
    cur = ['_pre']
    bufs['_pre'] = []

    def A(s):
        bufs[cur[0]].append(s)

    def H(sid, title, lede):
        cur[0] = sid
        bufs[sid] = []
        return (f'<section id="{sid}"><h2><span class="sn">00</span>{E(title)}</h2>'
                f'<p class="lede">{md(lede)}</p>')

    cid_rows = {r['id']: r for r in rows}
    C = lambda i: cid_rows.get(i)
    pk = {p['pkg']: p for p in pkgs}
    role = lambda p: (p.get('claim') or '').split(' Measured:')[0].strip() or 'first-party package'
    T = lambda r: tag(r) if r else ''
    chains = {r['chain']: r for r in by['flows']}
    hops = collections.defaultdict(list)
    for h in by['hops']:
        hops[h['chain']].append(h)
    tv = track_verdicts()
    pkv = press_kpis(tv) if tv else []

    # ───── hero (r33: names the round, the theme button, the live tickers)
    live_h = gi('height'); live_d = gi('difficulty'); live_bt = gi('averageblocktime50')
    refused = (f"{stats['rejected']} row(s) failed that test and are listed, with the reason, in the quarantine." if stats['rejected'] else
               f"Nothing was refused this build; {stats['unverified']} item(s) the miners could not anchor at all are named in "
               f'the quarantine, and the selftest proves the check can still fail.')
    captured = (by['runtime'][0].get('captured') if by['runtime'] else '')
    hero = (f'''<header class="hero"><div class="kicker">DERO HE · source architecture · {E(cur_name)}
      <span class="kick2">(projected from the tree at build time, not written about it)</span></div>
      <h1>The DERO HE source tree, <span class="dim">end to end — read against the node that runs it</span></h1>
      <p class="lede">A map of the whole DERO HE node for a developer who has never opened it: what each package is for,
      how a transfer becomes a block, which constants the consensus rules rest on, and what the running node, its logs and
      its peers show. Every statement below is drawn only if a line of this repository, of the code it vendors, or of a
      snapshot of the live daemon still says so — {stats['anchors_ok']:,} anchors behind {stats['rows']:,} rows, re-read
      from disk at build time. {refused} The small coloured tags open the exact file and line.</p>
      <div class="hero-links"><a class="btn" href="#start">Start here →</a><a class="btn ghost" href="#tour">The tree in layers</a>
      <a class="btn ghost" href="#lifecycle">How a transfer becomes a block</a><a class="btn ghost" href="#index">Search every row</a>
      <button type="button" id="themebtn" class="btn ghost" aria-label="Colour theme: auto (click to change)">Theme: auto</button></div>
      <div class="tickers" aria-label="The live node at build time">
        <div class="tick live"><b>{E(live_h)}</b><span>chain height</span></div>
        <div class="tick"><b>{E(gi('version'))}</b><span>version</span></div>
        <div class="tick"><b>{E(live_bt)}s</b><span>mean block, last 50</span></div>
        <div class="tick"><b>{E(f"{int(live_d):,}" if str(live_d).isdigit() else live_d)}</b><span>difficulty</span></div>
        <div class="tick"><b>{E(gi('outgoing_connections_count'))} out / {E(gi('incoming_connections_count'))} in</b><span>peers</span></div>
        <div class="tick"><b>{sum(p['loc'] for p in pkgs):,}</b><span>first-party lines</span></div>
        <div class="tick"><b>{stats['anchors_ok']}/{stats['anchors']}</b><span>anchors resolved</span></div>
      </div>
      <p class="sub" style="font-size:12.5px">Snapshot captured {E(captured)} · inputs as of {E(now.isoformat(timespec='seconds'))} (HEAD commit time) · fingerprint <code>{E(fp)}</code></p>
    </header>''')

    # ═════════ Part I · Orientation ═════════
    # ───── start here
    bt, mbsz, stab = C('const-bt'), C('const-mbsz'), C('const-stab')
    minr, maxr = C('const-minr'), C('const-maxr')
    A(H('start', 'Start here: DERO HE in plain words',
        'DERO HE is a privacy-first blockchain node written in Go: balances are stored encrypted, every transfer proves '
        'in zero knowledge that it balances, and smart contracts run in a small BASIC-like virtual machine. This page maps '
        'its whole source tree and reads it against a running node. The three cards say what the node does; the '
        'sections after them walk the tree from the top down.'))
    A('<div class="grid3">')
    A(f'''<div class="card lead"><h3>What the node does</h3><p><code>derod</code> keeps a copy of the chain, exchanges blocks
      and transactions with its peers, checks every one of them against the consensus rules, and serves wallets (JSON-RPC)
      and miners (GETWORK). A block is targeted every <b>{E(first_num(bt and bt['value']))} seconds</b> {T(bt)} and carries
      the miniblocks miners submit, <b>{E(first_num(mbsz and mbsz['value']))} bytes</b> each {T(mbsz)}; a block
      {E(first_num(stab and stab['value']))} deep is treated as settled {T(stab)}.</p>
      <p class="mut">Read next: <a href="#lifecycle">how a transfer becomes a block</a>, <a href="#consensus">the rules</a>.</p></div>''')
    cr, tvr = pk.get('cryptography'), chains.get('txverify')
    A(f'''<div class="card lead"><h3>What makes it private</h3><p>Balances live on chain as ciphertexts. A transfer hides its sender
      and receiver in a ring of accounts — between <b>{E(first_num(minr and minr['value']))}</b> {T(minr)} and
      <b>{E(first_num(maxr and maxr['value']))}</b> {T(maxr)} members — and carries a proof that the encrypted amounts balance
      without revealing them. The maths is in <code>cryptography</code>: {md(role(cr) if cr else 'the HE primitives')} {T(cr)}</p>
      <p class="mut">Read next: <a href="#chain-txverify">transaction verification</a>{' ' + T(tvr) if tvr else ''}, <a href="#press">the disclosed range-proof defect</a>.</p></div>''')
    ab, dvm = pk.get('astrobwt'), pk.get('dvm')
    A(f'''<div class="card lead"><h3>How the chain is secured and extended</h3><p>Miners prove work in <code>astrobwt</code>
      ({md(role(ab) if ab else '')}) {T(ab)} The difficulty follows an exponential controller {T(C('const-diff'))}, and
      the reward per block halves on a fixed schedule {T(C('const-calc'))}. Programs on chain run in <code>dvm</code>
      ({md(role(dvm) if dvm else '')}) {T(dvm)}</p>
      <p class="mut">Read next: <a href="#chain-mining">mining</a>, <a href="#chain-scexec">smart-contract execution</a>.</p></div>''')
    A('</div>')
    # how to read the page: the evidence classes, as a chart
    cnt = collections.Counter(e['kind'] for r in rows for e in r['evidence'])
    KW = [('SRC', 'a line of the first-party DERO source, its build scripts or go.mod'),
          ('EXT', 'a line of third-party code under vendor/, or of a document taken under audit: said, not so'),
          ('HARNESS', 'the owner’s own measured system: a live snapshot, a log, a record of a run'),
          ('GK', 'the project’s knowledge base: its skill and memory store'),
          ('PLAN', 'proposed in harness/loop/PROPOSALS.md and not yet run')]
    kk = [(k, w) for k, w in KW if cnt.get(k)]
    A('<h3>How to read this page</h3>')
    A('<div class="grid2"><div class="prose"><p>Every row, card, bar and box carries a small <b>class tag</b>. Hover or focus it '
      'to see the exact file and line it was read from, with the quoted line; click to pin the panel. The class says what kind '
      'of proof the line is:</p><ul>' + ''.join(f'<li><span class="lg lg-{k}">{k}</span> {E(w)}</li>' for k, w in kk)
      + '</ul><p>Plain-language passages like this one are orientation, not claims: every number in them comes from a tagged row. '
      'Long tables have a filter box; the <a href="#index">index</a> searches every row of the page.</p></div>')
    A(vbar('ch-classes', 'Anchors behind the page, by evidence class', 'How many anchors (file and line) of each class the drawn rows rest on.',
           rows, [k for k, _ in kk], [cnt[k] for k, _ in kk], unit='anchors', W=380, H=230,
           tag_rows_=[[r for r in rows if any(e['kind'] == k for e in r['evidence'])][:60] for k, _ in kk]))
    A('</div>')
    # health at a glance: the area scorecard, the observatories and the disclosure track, each from its own rows
    ar = by.get('areas', [])
    ast = collections.Counter(r['state'] for r in ar)
    cobs = by.get('chainobs', [])
    csum = next((r for r in cobs if r.get('kind') == 'summary'), None)
    cg = (csum or {}).get('grades') or {}
    prow = next((r for r in by.get('peers', []) if r.get('kind') == 'kpi'), None)
    pk2 = (prow or {}).get('kpis') or {}
    A('<h3>Health at a glance</h3>')
    A('<p class="lede" style="margin:4px 0 8px">Four instruments that run every round, summarised from the same rows their own '
      'sections draw. Each chart has its data table under it.</p><div class="charts">')
    if ar:
        so = [s for s in ('OK', 'WATCH', 'ATTENTION', 'FAIL', 'PAUSED') if ast.get(s)] + sorted(s for s in ast if s not in ('OK', 'WATCH', 'ATTENTION', 'FAIL', 'PAUSED'))
        A(vbar('ch-area-states', f'Areas of the stack by state ({len(ar)} scored)', 'The number of areas of harness/areas.json in each state of the newest scorecard.',
               ar, so, [ast[s] for s in so], unit='areas', tag_rows_=[[r for r in ar if r['state'] == s] for s in so]))
    if cg:
        go = [g for g in ('OBSERVED', 'ANOMALY', 'NORMAL', 'NO-DATA') if g in cg]
        A(vbar('ch-chain-grades', 'Chain observatory: detectors by grade', 'How the consensus observatory graded its detectors on the newest capture.',
               [csum], go, [int(cg[g]) for g in go], unit='detectors', tag_rows_=[[csum]] * len(go)))
    if prow and pk2:
        pg = [('OBSERVED', pk2.get('observed')), ('ANOMALY', pk2.get('anomaly'))]
        pg = [(g, v) for g, v in pg if v is not None]
        A(vbar('ch-peer-grades', 'Peer observatory: detectors flagged', 'How many peer detectors the network-peer observatory graded OBSERVED or ANOMALY.',
               [prow], [g for g, _ in pg], [int(v) for _, v in pg], unit='detectors', tag_rows_=[[prow]] * len(pg)))
    if pkv:
        dl = pkv[1:]
        dclaims = [r for r in by.get('disclosure', []) if r.get('kind') == 'track-claim'] or by.get('forensics', [])
        A(hbar('ch-disclosure', f'Foundation disclosure: {pkv[0][0]} claims by verdict', 'The newest verdict of each press claim C1-C8 in the disclosure track.',
               [dclaims[0]] * len(dl), [l.replace(' here', '').replace(' from a pruned node', '') for _, l in dl], [int(v) for v, _ in dl], unit='claims',
               label_w=130, W=380, row=30))
    A('</div>')
    A(kpis([(f"{len(pkgs)}", 'first-party packages'), (f"{sum(p['loc'] for p in pkgs):,}", 'lines of first-party Go'),
            (str(len(chains)), 'execution paths traced'), (str(len([r for r in by.get('findings', [])])), 'findings'),
            (f"{stats['rows']:,}", 'rows on this page'), (f"{stats['anchors_ok']:,}", 'anchors re-read at build')]))
    A('<h3>Where to go next</h3><div class="grid2">'
      '<div class="card"><h4>New to the code</h4><p><a href="#tour">The tree in layers</a> → <a href="#lifecycle">how the parts work together</a> '
      '→ <a href="#flows">the execution paths, hop by hop</a> → <a href="#glossary">the glossary</a>.</p></div>'
      '<div class="card"><h4>Working on the protocol</h4><p><a href="#consensus">Consensus rules and their arithmetic</a> → '
      '<a href="#coverage">the risk register</a> → <a href="#press">the disclosure audit</a> → <a href="#chainobs">the chain observatory</a>.</p></div>'
      '<div class="card"><h4>Running a node</h4><p><a href="#live">The live node</a> → <a href="#triage">every console error, triaged</a> → '
      '<a href="#bridge">the log bridge</a> → <a href="#peers">the network peers</a>.</p></div>'
      '<div class="card"><h4>Changing this page</h4><p><a href="#harness">How it is built</a> → <a href="#method">re-run and extend</a> → '
      '<a href="#quarantine">what was refused</a>. The DVM game suite has its own guide: '
      '<a href="dero-enhanced-game-theory.html">verified games for DERO miners</a>.</p></div></div>')
    A('</section>')

    # ───── the tree in layers
    ntier = len({PKG_TIER.get(p['pkg'], 'foundation') for p in pkgs})
    A(H('tour', 'The tree in layers',
        f'{len(pkgs)} first-party packages, grouped into {ntier} layers from the programs you run down to the shared '
        'foundation. The layers follow the imports: a package sits above the packages it imports. Each box is a '
        'package with its measured size; click it for its card below.'))
    A(tier_diagram(pkgs, deps))
    A('<div class="cards">')
    for tid, tname, tdesc in TIERS:
        ps = [p for p in pkgs if PKG_TIER.get(p['pkg'], 'foundation') == tid]
        if not ps:
            continue
        A(f'<div class="card tier"><h3>{E(tname)}</h3><p class="mut">{E(tdesc)}.</p><ul class="pkgl">'
          + ''.join(f'<li id="pkg-{E(p["pkg"])}"><code>{E(p["pkg"])}/</code> {T(p)} — {md(role(p))}'
                    f'<span class="m">{p["loc"]:,} lines · {p["files"]} source files · {p["test_files"]} test files</span></li>' for p in ps)
          + '</ul></div>')
    A('</div>')
    A('<div class="charts">')
    A(hbar('ch-pkg-files', 'Source files and test files per package', 'Measured source files per first-party package, with the test files as a tick.',
           pkgs, [p['pkg'] for p in pkgs], [p['files'] for p in pkgs], unit='files', label_w=110, W=560,
           ticks=[p['test_files'] for p in pkgs], tick_name='test files', series='source files'))
    A('</div>')
    A('</section>')

    # ───── how the parts work together
    if chains:
        A(H('lifecycle', 'How the parts work together',
            f'The page traces {len(chains)} execution paths through the tree, hop by hop, each hop re-located in the source '
            'at build time. Read in the order below they follow a transfer from start-up to a committed block. Each path '
            'is drawn in full in Execution paths; the table names the file where its code starts.'))
        A(life_diagram(chains, hops))
        order = [c for c in LIFE if c in chains] + [c for c in chains if c not in LIFE]
        lanes_all = []
        for c in order:
            for h in sorted(hops[c], key=lambda h: h['order']):
                ln = LAYER_LANE.get(h.get('layer'), h.get('layer'))
                if ln not in lanes_all:
                    lanes_all.append(ln)
        mat = [[sum(1 for h in hops[c] if LAYER_LANE.get(h.get('layer'), h.get('layer')) == ln) for ln in lanes_all] for c in order]
        A(chk.matrix_chart('ch-chain-layers', 'Which layers each execution path passes through',
                           'The number of hops of each execution path that run in each layer of the tree.',
                           [shortlab(chains[c]['title'].split(' — ')[0], 30) for c in order], lanes_all, mat, unit='hops',
                           pill_svg=ak.svg_ctag(200 + 56 * len(lanes_all) + 8, 9, rows_cl([chains[c] for c in order], 'the paths it counts'))[0],
                           row_tag=lambda i: ak.ctag(cls_of(chains[order[i]])), label_w=200, cell_w=56, col_h=78, zero='·'))
        ltr = [[f'<b>{E(chains[c]["title"].split(" — ")[0])}</b>', md(tk.html_clip(chains[c].get('claim') or '', 110)),
                f'<span class="num">{len(hops[c])}</span>',
                (f'<span class="mono" style="overflow-wrap:anywhere">{E(rel(sorted(hops[c], key=lambda h: h["order"])[0]["evidence"][0]["abs"]))}</span>' if hops[c] else '-'),
                proof(chains[c], 1)] for c in order]
        A('<h3>Where each path starts in the code</h3>')
        A(table(['Path', 'What it shows', 'Hops', 'Start reading at', 'proof'],
                ak.tag_rows(ltr, [chains[c] for c in order], ['', '', '', '', None], cls_of), 't-life'))
        A('</section>')

    # ───── glossary
    G = [('Block', 'const-bt', 'A batch of transactions the network agrees on. One is targeted every few seconds; the value is the target block time.'),
         ('Miniblock', 'const-mbsz', 'The unit a miner submits: a fixed-size header that carries its own proof of work. A block collects several.'),
         ('Stable depth', 'const-stab', 'How many blocks must follow a block before the node treats it as settled.'),
         ('Difficulty', 'const-diff', 'How hard a miniblock is to find. It is recomputed every block from how long the last one took.'),
         ('Block reward', 'const-base', 'The new coins a block pays its miners; it halves on a fixed schedule.'),
         ('Reward halving', 'const-calc', 'The formula that halves the reward every reduction interval.'),
         ('Ring size', 'const-minr', 'A transfer hides its real sender and receiver among this many accounts at least.'),
         ('Maximum ring', 'const-maxr', 'The largest ring a transfer may use.'),
         ('Fee per kilobyte', 'const-fee', 'What a transaction pays per kilobyte of its size.'),
         ('Graviton', 'const-btree', 'The versioned key-value store that holds all consensus state; the balance tree is one of its trees.'),
         ('Hard fork (HF3)', 'const-mhf3', 'A height at which the rules changed for every node at once.'),
         ('GETWORK', 'const-gw', 'The port miners connect to for a job (a block template) and to submit miniblocks.'),
         ('JSON-RPC', 'const-rpcp', 'The daemon’s API port for wallets, explorers and tools.'),
         ('Wallet RPC', 'const-wrpc', 'The port a wallet serves its own API on.'),
         ('Integrator address', 'const-dev', 'The address a miner names to receive the integrator share. Its value is withheld on this page.')]
    PG = [('Homomorphic encryption (HE)', 'cryptography', 'Encryption that still allows adding the hidden amounts: the H and E of DERO HE.'),
          ('AstroBWT', 'astrobwt', 'The proof-of-work hash: a Burrows-Wheeler suffix sort that favours CPUs.'),
          ('DVM', 'dvm', 'The DERO Virtual Machine that runs smart contracts written in DVM-BASIC.'),
          ('walletapi', 'walletapi', 'The library every DERO wallet is built on.')]
    gl = []
    gobj = []
    for term, cid, plain in G:
        r = C(cid)
        if r:
            val = 'withheld' if cid == 'const-dev' else r.get('value')
            gl.append([f'<b>{E(term)}</b>', E(plain), f'<code>{E(val)}</code> <span class="mut">({E(r["title"])})</span>', proof(r, 1)])
            gobj.append(r)
    for term, pkn, plain in PG:
        r = pk.get(pkn)
        if r:
            gl.append([f'<b>{E(term)}</b>', E(plain), f'<code>{E(pkn)}/</code> <span class="mut">{md(role(r))}</span>', proof(r, 1)])
            gobj.append(r)
    for term, ch, plain in (('KCP over UDP', 'p2pconn', 'The transport peers use: a reliable protocol over UDP, so a TCP port forward reaches nothing.'),
                            ('Registration', 'txverify', 'The first transaction of a new account; it carries a signature instead of a ring proof.')):
        r = chains.get(ch)
        if r:
            gl.append([f'<b>{E(term)}</b>', E(plain), f'<span class="mut">execution path: {E(r["title"].split(" — ")[0])}</span>', proof(r, 1)])
            gobj.append(r)
    if gl:
        A(H('glossary', 'Glossary',
            'The words this page uses, in plain language, each tied to the line of the tree that defines it. The values are '
            'read from the source at build time.'))
        A(table(['Term', 'In plain words', 'In the tree', 'proof'], ak.tag_rows(gl, gobj, ['', '', '', None], cls_of), 't-gloss', filt=True))
        A('</section>')

    # ═════════ Part II · The source tree ═════════
    # ───── package map
    A(H('map', 'Package map: what the tree is made of',
        'The first-party packages, sized by walking the tree; every import edge below is proved by the import line that '
        'creates it — so the diagram is the dependency graph the compiler sees, not a drawing of one. Hover any arrow to '
        'trace it; the ▶ plays them in turn.'))
    A(kpis([(f"{len(pkgs)}", 'first-party packages'), (f"{sum(p['loc'] for p in pkgs):,}", 'lines of Go'),
            (f"{sum(p['files'] for p in pkgs)}", 'source files'),
            (f"{sum(p['test_files'] for p in pkgs)}", 'test files'),
            (f"{len(deps)}", 'import edges'), (f"{len(by['vendor'])}", 'vendored modules drawn')]))
    A(fig(dk.lanes(pkg_spec(pkgs, deps), dkcls, W=1120),
          'Import relations between the first-party packages, grouped into the tiers the imports imply. '
          'An arrow means at least one file of the left package imports the right one; the count is in the table below.',
          'first-party package import graph'))
    A(hbar('ch-pkg-loc', 'Lines of Go per first-party package', 'Measured non-test lines of Go per first-party package.',
           pkgs, [p['pkg'] for p in pkgs], [p['loc'] for p in pkgs], unit='lines', label_w=110, W=760,
           note='walletapi and cmd dominate because both carry several binaries’ worth of behaviour.'))
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

    # ───── consensus
    A(H('consensus', 'Consensus rules, and the arithmetic behind them',
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

    # ───── flows
    A(H('flows', 'Execution paths: the way a block, a share and a transaction actually go',
        'Each chain is a declared sequence of hops; the build locates every hop in the tree and refuses to draw the '
        'chain if even one of them has moved. Hover a connector to trace it, or press ▶ to walk the chain in order.'))
    for cid, c in chains.items():
        hs = sorted(hops[cid], key=lambda h: h['order'])
        A(f'<h3 id="chain-{E(cid)}">{E(c["title"])}</h3><p class="lede" style="margin:4px 0 10px">{md(c["claim"])}</p>')
        A(evolved(by, {rel(e['abs']) for h in hs for e in h['evidence']}, what='this chain'))
        A(fig(dk.lanes(flow_spec(cid, c['title'], hs), dkcls, W=1120),
              f'{len(hs)} hops, each anchored on the line that implements it.', c['title']))
        srows = [{'n': h['order'], 'where': h['layer'], 'what': h.get('fn') or h['title'], 'object': h.get('where'),
                  'state': None, 'note': h['claim'], '_row': h} for h in hs]
        A(fig(dk.steps(srows, dkcls, W=1120), 'The same chain as a stepper: where each hop runs, what it does, and the '
                                              'file and line it was found at.', c['title'] + ' — steps'))
    A('</section>')

    # ───── vendored
    A(H('deps', 'Vendored code: the third-party code this build links in',
        'Vendored modules are quoted, not owned — they carry the EXT class. A module is listed only when a first-party '
        'import line proves it is really linked; two of the largest are transitive and are named in the quarantine instead.'))
    A(evolved(by, prefixes=('vendor/', 'go.mod'), what='the vendored tree'))
    vd = sorted(by['vendor'], key=lambda r: -r['loc'])
    if vd:
        A(hbar('ch-vendor', 'Lines per vendored module', 'Measured lines of each vendored module a first-party import links in.',
               vd, [shortlab(r['module'].split('/')[-1] if len(r['module']) > 26 else r['module'], 26) for r in vd], [r['loc'] for r in vd],
               unit='lines', label_w=190, W=760, cols=('module', 'lines'),
               note='Labels are the last path element of the module where the full path is long; the data table and the table below name it in full.'))
    A(table(['Module', 'Lines', 'Files', 'Imported by', 'proof'],
            ak.tag_rows([[f'<span class="mono">{E(r["module"])}</span>', f'<span class="num">{r["loc"]:,}</span>',
                          f'<span class="num">{r["files"]}</span>',
                          ' '.join(f'<code>{E(p)}</code>' for p in (r.get('importers') or [])[:4]), proof(r, 1)]
                         for r in vd], vd, ['', '', '', '', None], cls_of), 't-vd'))
    A('</section>')

    # ───── local changes
    A(H('local', 'Local changes: what this tree does that upstream Release153 does not',
        'The baseline is the upstream tag, and the diff is `git diff Release153..HEAD`. The shipped Go files that differ '
        'are listed first; everything else added here is documentation, this harness, or experiments that no binary links.'))
    loc = sorted(by['local'], key=lambda r: (r['status'], r['path']))
    A(evolved(by, {r['path'] for r in loc}, what='this diff'))
    A(kpis([(str(len(loc)), 'shipped Go files changed'),
            (str(sum(r['added'] for r in loc)), 'lines added'), (str(sum(r['removed'] for r in loc)), 'lines removed'),
            (str(len(by['commits'])), 'commits on the branch'),
            (str(len([r for r in by['local-other'] if r.get('kind') == 'experiment'])), 'experiment-only paths')]))
    pkgchg = collections.defaultdict(list)
    for r in loc:
        pkgchg[r['path'].split('/')[0] if '/' in r['path'] else '(root)'].append(r)
    pco = sorted(pkgchg, key=lambda k: -sum(r['added'] + r['removed'] for r in pkgchg[k]))[:16]
    if pco:
        A(hbar('ch-local-pkg', 'Shipped Go lines changed against Release153, by top-level directory',
               'Lines added plus removed in the shipped Go files of each top-level directory, against the upstream tag.',
               [pkgchg[k][0] for k in pco], pco, [sum(r['added'] + r['removed'] for r in pkgchg[k]) for k in pco],
               unit='lines changed', label_w=120, W=760, ticks=[len(pkgchg[k]) for k in pco], tick_name='files',
               series='lines added + removed', cols=('directory', 'lines changed', 'files')))
    ltr2 = [[f'<span class="mono">{E(r["path"])}</span>', chip(r['status'], 'var(--ok)' if r['status'] == 'added' else 'var(--l4)'),
             f'<span class="num">+{r["added"]} / −{r["removed"]}</span>', tk.html_clip(r.get('subject') or '', 70),
             proof(r, 1)] for r in loc]
    A(table(['File', 'Status', 'Lines', 'Commit subject', 'proof'],
            ak.tag_rows(ltr2, loc, ['', '', '', '', None], cls_of), 't-loc', filt=True))
    cm = by['commits']
    A('<h3>The commit ledger</h3>')
    A(table(['Commit', 'Subject', 'Files', 'Shipped Go', 'proof'],
            ak.tag_rows([[f'<code>{E(r["sha"])}</code>', tk.html_clip(r['subject'], 86),
                          f'<span class="num">{r["files"]}</span>', f'<span class="num">{r["code_files"]}</span>', proof(r, 1)]
                         for r in cm], cm, ['', '', '', '', None], cls_of), 't-cm', filt=True))
    A('</section>')

    # ───── evolution (r23c), read from git
    evo_section(by, A, H)
    if bufs.get('evolution') and bufs['evolution'][-1] == '</section>':
        bufs['evolution'].pop()                  # evo_section closes its section: the r33 chart goes inside it
    rs = [r for r in evo_rounds(by) if not r.get('pending')]
    if rs:
        A('<h3>Commits per round, at a glance</h3>')
        A(hbar('ch-evo-commits', 'Commits per round on local-enhancements', 'The number of commits git attributes to each round by the round rule.',
               rs, [EVO_SHORT.get(r['round'], r['round']) for r in rs], [r['commit_n'] for r in rs], unit='commits',
               label_w=70, W=640, row=20, ticks=None))
        A('</section>')
    else:
        A('</section>')

    # ═════════ Part III · The running node ═════════
    # ───── live node
    A(H('live', 'Live node: the node this page was read against',
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

    # ───── node intelligence
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
        lrun = runs[-1] if runs else None
        A(kpis([(str(sum(1 for r in dd if r.get('result') == 'PASS')) + '/' + str(sum(1 for r in dd if r.get('result') != 'INFO')),
                 'datadir checks passing'),
                (f"{lrun['mean']} s" if lrun else '—', 'mean block interval, current run'),
                (str(lrun['errors_at_tip']) if lrun else '—', 'ERROR lines at tip, current run'),
                (next((f"{r['caught']}/{r['total']}" for r in other if r.get('kind') == 'mutation'), '—'),
                 'Go mutations caught'),
                (next((f"{r['confirmed']}+{r['partly']}/{r['findings']}" for r in other if r.get('kind') == 'discovery'), '—'),
                 'discovery findings confirmed (+partly)')]))
        A(evolved(by, sfiles(['intel']), what='this section'))
        if runs:
            A(hbar('ch-cadence', 'Mean block interval at the tip, per run of the daemon',
                   'The mean interval between blocks while at the tip, one bar per run of the daemon, with the median as a tick; the target is 18 s.',
                   runs, [shortlab(r['title'], 34) for r in runs], [float(r['mean'] or 0) for r in runs], unit='s', label_w=250, W=760,
                   ticks=[float(r['median'] or 0) for r in runs], tick_name='median', series='mean', marker=(18, 'target 18 s'),
                   cols=('run', 'mean s', 'median s'),
                   note='The gaps are skewed (p90 about 31 s), so the median sits below the mean; two independent instruments agree on the long run.'))
            rtr = [[f'<b>{E(r["title"])}</b>', f'<span class="mono">{r["mean"]} / {r["median"]} / {r["p90"]}</span>',
                    f'<span class="mono">{r["errors_at_tip"]}</span>',
                    E('; '.join(f"{x['level']} {x['rule']}" for x in r['alerts']) or 'none'), proof(r, 1)] for r in runs]
            A(table(['Run', 'mean / median / p90 s', 'ERRORs at tip', 'alerts', 'proof'],
                    ak.tag_rows(rtr, runs, ['', '', '', '', None], cls_of), 't-intel-runs'))
        if mruns:
            mtr = [[f'<b>{E(r["title"])}</b>' + (f'<br><span class="mono">{E(r["start"][:16])} → {E(str(r.get("end"))[:16])} '
                    f'· {E(Path(str(r.get("log"))).name)} · {r.get("accepted_in_window")} accepted, longest gap '
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
                    tk.html_clip(r['claim'].split(' — ', 1)[-1], 160), proof(r, 1)] for r in dd]   # html_clip output is markup: never E() it
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

    # ───── log bridge
    A(H('bridge', 'Log bridge: every line the daemon printed, joined to the line that printed it',
        'The console is evidence only if each line can be traced to the source that emits it. A match counts only when '
        'the literal sits in a package that owns the logger name derod printed — the registry below is mined from the '
        '`WithName` calls themselves, so the rule is read out of the tree rather than asserted here.'))
    A(evolved(by, sfiles(['logbridge', 'loggers']), what='the bridge'))
    lb = sorted(by['logbridge'], key=lambda r: (r['t'], r['id']))
    lgc = collections.Counter(r['logger'] for r in lb)
    if lgc:
        lgo = sorted(lgc, key=lambda k: (-lgc[k], k))
        A(hbar('ch-bridge-loggers', 'Bridged console lines per logger', 'How many of the bridged console lines each named logger printed.',
               [next(r for r in lb if r['logger'] == k) for k in lgo], lgo, [lgc[k] for k in lgo], unit='lines', label_w=140, W=620, row=22))
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

    # ───── console errors, triaged
    tri = by.get('triage', [])
    if tri:
        A(H('triage', 'Console errors: every error the console printed, whose it is, and what it costs',
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
        order = [o[0] for o in ORIGIN]
        tri = sorted(tri, key=lambda r: (order.index(r.get('origin', 'REMOTE')), r['id']))
        A(hbar('ch-triage', 'ERROR lines per cause in the console capture', 'How many ERROR lines each triaged cause printed, grouped by where it originates.',
               tri, [shortlab(r['title'].split(':')[0].split(',')[0], 30) for r in tri], [int(r.get('count') or 0) for r in tri],
               unit='lines', label_w=230, W=760, cols=('cause', 'ERROR lines')))
        A(evolved(by, sfiles(['triage']), what='the triage'))
        for c in by.get('triage-census', []):
            A(f'<p class="sub">{md(c["claim"])} {tag(c)} <span class="mut">Proof:</span> {proof(c, 2)}</p>')
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

    # ═════════ Part IV · Findings and audits ═════════
    # ───── findings
    A(H('findings', 'Findings: what reading the code against the running node established',
        'Some of these are defects in code this node runs; some are local fixes already shipped; the rest is arithmetic '
        'and operational fact. Each card lists what it costs and what, if anything, should be done — including where '
        'the right answer is to change nothing.'))
    F = sorted(by['findings'], key=lambda r: ['defect', 'operational', 'reporting', 'fix', 'analysis'].index(r.get('severity', 'analysis')))
    sv = collections.Counter(r.get('severity', 'analysis') for r in F)
    if sv:
        so = [s for s in ('defect', 'operational', 'reporting', 'fix', 'analysis') if sv.get(s)]
        A(vbar('ch-findings', 'Findings by kind', 'How many findings of each kind this page carries.', F,
               [SEV[s][0] if s in SEV else s for s in so], [sv[s] for s in so], unit='findings', W=420,
               tag_rows_=[[r for r in F if r.get('severity', 'analysis') == s] for s in so]))
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

    # ───── coverage and the risk surface
    cov = by.get('coverage', [])
    rk = by.get('riskmap', [])
    if cov:
        tot = next((r for r in cov if r.get('kind') == 'total'), None)
        A(H('coverage', 'Coverage and risk: what this page covers, and the risk surface it does not yet explain',
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
        pkc = [r for r in cov if r.get('kind') == 'pkg']
        if pkc:
            A(hbar('ch-risk-pkg', 'Risk functions per package: covered and uncovered',
                   'Risk functions per package that no row of this page cites yet (the bar), with the covered ones as a tick.',
                   pkc[:14], [shortlab(r['pkg'], 24) for r in pkc[:14]], [r['risk'] - r['risk_covered'] for r in pkc[:14]],
                   unit='uncovered', label_w=170, W=760, ticks=[r['risk_covered'] for r in pkc[:14]], tick_name='covered',
                   series='uncovered', cols=('package', 'uncovered', 'covered'),
                   note='The transaction-verification and miniblock proof-of-work paths close part of the blockchain package’s gap.'))
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

    # ───── disclosure audit: what was said, and what the tree says back
    press, fore = by['press'], by['forensics']
    if press or fore:
        A(H('press', 'Disclosure audit: the Foundation’s disclosure, tested against this tree',
            'On 2026-10-20 the DERO Foundation published a range-proof soundness defect and withdrew support for '
            'the chain. The claims are reproduced below from the page’s own text and carry the **EXT** class: a '
            'line of that document proves only that it was *said*. Whether each is **so** is decided by the rows '
            'underneath, which anchor in the source tree and in the running node instead. The two are deliberately '
            'kept apart.'))
        VCOL = {'CONFIRMED': 'var(--gap)', 'PARTLY-CONFIRMED': 'var(--warn)', 'REFUTED': 'var(--ok)',
                'CANNOT-DETERMINE-LOCALLY': 'var(--mut)'}
        if fore:
            A(kpis(press_kpis(track_verdicts())) if track_verdicts() else kpis([(str(len(fore)), 'findings that survived adversarial review'),
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
                       {chip("bears on " + str(r.get("press_claim", "—")), "var(--l4)")}
                       {badges(r)}</div>
                  <p>{md(r["claim"])}</p>
                  <div class="meta"><b>How it was established.</b> {md(r.get("reasoning", ""))}
                  <br><span class="mut">Proof:</span> {proof(r, 5)}</div></div>''')
            A('</div>')
        A(disclosure_track_html(by))   # r24: round history, new facts, potential fixes
        A('</section>')

    # ═════════ Part V · Observatories ═════════
    areakit.render(by, A, H, {'E': E, 'md': md, 'proof': proof, 'table': table, 'ak': ak, 'cls_of': cls_of, 'kpis': kpis})
    consensuskit.render(by, A, H, {'E': E, 'md': md, 'proof': proof, 'table': table, 'ak': ak, 'cls_of': cls_of, 'kpis': kpis,
                                   'note': note, 'fig': fig, 'chip': chip, 'dk': dk, 'tk': tk})
    peerkit.render(by, A, H, {'E': E, 'md': md, 'proof': proof, 'table': table, 'ak': ak, 'cls_of': cls_of, 'kpis': kpis,
                              'fig': fig, 'chip': chip})

    # ═════════ Part VI · The harness ═════════
    A(H('harness', 'How this page is built and checked',
        'The page is a projection, not a document: a harness indexes the tree, miners turn it into rows that each carry '
        'anchors (a file and a quoted line), the build re-reads every anchor and draws only the rows that still resolve, '
        'and gates check the result. Re-running it on an unchanged tree reproduces the page byte for byte.'))
    srcs = collections.Counter(r.get('source') or '?' for r in rows)
    A(pipe_diagram(stats, len(RAW_KEYS), len(sources(rows))))
    so = sorted(srcs, key=lambda k: (-srcs[k], k))
    A('<div class="charts">')
    A(hbar('ch-rows-miner', 'Rows on the page, by the miner that produced them', 'How many drawn rows each raw model file (one per miner) contributed.',
           [next(r for r in rows if (r.get('source') or '?') == k) for k in so], so, [srcs[k] for k in so], unit='rows', label_w=110, W=560, row=21))
    ps = collections.Counter(r['page_section'] for r in rows)
    pso = sorted(ps, key=lambda k: (-ps[k], k))
    A(hbar('ch-rows-section', 'Rows on the page, by section', 'How many drawn rows each section of the page carries.',
           [next(r for r in rows if r['page_section'] == k) for k in pso], pso, [ps[k] for k in pso], unit='rows', label_w=110, W=560, row=21))
    A('</div>')
    A(note('**Three promises the gates keep.** Nothing is drawn without an anchor that still resolves (G1, G2). A figure that '
           'another artifact also states equals its record (coherence, G25: area states, disclosure verdicts, the scorecard '
           'run, the observatory captures and grades, the source stamp). The page carries no local path, address or machine '
           'name: quotes are shown with placeholders such as [home], [datadir] and [repo], and citations name files from the '
           'repository root.', 'good'))
    A('</section>')

    # ───── method
    A(H('method', 'Re-run, break and extend this',
        'The page is a projection. Re-running the harness on an unchanged tree must reproduce it byte for byte; '
        'changing anything it cites must make `check` fail.'))
    A(f'''<details open><summary>The pipeline</summary>
      <pre>python3 harness/prep_corpus.py            # index the tree: {CORPUS.name}/tags.tsv, pkgindex.json, manifest.json
python3 harness/miners/mine_inventory.py  # packages, import graph, vendored weight
python3 harness/miners/mine_consts.py     # consensus constants, read from their declaring lines
python3 harness/miners/mine_flows.py      # the execution chains, hop by hop
python3 harness/miners/mine_logbridge.py  # console lines -> the Go literal that printed them
python3 harness/miners/mine_localdiff.py  # this tree vs upstream Release153
python3 harness/miners/mine_evolution.py  # r23c: rounds x subsystems x modules from git log base..HEAD
python3 harness/miners/mine_runtime.py --capture   # a fresh read-only snapshot of the live daemon
python3 harness/miners/mine_findings.py   # the analysis rows (numbers computed, never typed)
python3 harness/gen_deroarch.py build     # resolve + render + stamp + skill AUTO block
python3 -I harness/pipeline/regen_round.py --apply   # every miner on its on-disk inputs, the build, the page gates, coherence
python3 -I harness/kit/kitgate.py artifacts/dero-src-arch.html --width 1280,485   # page gates G5-G14
python3 harness/run_gates.py &lt;label&gt;      # G1..G36 -> harness/loop/GATES.md
python3 harness/kat/verify_deroarch.py --mutations   # DK01..DK35; each mutation must flip its KAT
python3 -I harness/kat/test_src_arch_page_r33.py     # r33: sections, charts, records, privacy, theme</pre></details>''')
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
    A('</section>')

    # ───── quarantine
    A(H('quarantine', 'Quarantine: what was refused, and why',
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

    # ───── index
    A(H('index', 'Index: everything on this page, searchable',
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
    A(f'''<footer>Built by <code>harness/gen_deroarch.py</code> from {stats['raw']} mined rows
      · {stats['anchors_ok']} of {stats['anchors']} anchors resolved · fingerprint <code>{E(fp)}</code>
      · {E(now.strftime('%Y-%m-%d %H:%M %Z'))} · {E(cur_name)}. Citations name files from the repository root; quoted lines show
      [home], [datadir], [repo] and [address] in place of local values.
      <br>Evolution (r23c): base {E(next((r['base'] for r in by.get('evolution', []) if r.get('kind') == 'evo-base'), '?'))}
      = tag Release152 = merge-base(HEAD, Release153); a commit belongs to the round its subject names (Round N / RN / rN),
      the Release142 port to R1–R3, any other commit to the next round-marked commit; rounds grouped as the Enhancement
      Ledger groups them.</footer>''')
    A('</section>')

    # ───── assembly: the parts in order, sections numbered as the contents lists them
    have = [i for i in SECTION_IDS if i in bufs]
    extra = [i for i in bufs if i not in SECTION_IDS and i != '_pre']     # a kit section the parts do not name yet
    num = {i: n for n, i in enumerate(have + extra, 1)}
    title_of = {i: t for _, s in PARTS for i, t in s}
    toc = []
    body = []
    for pname, secs in PARTS + ([('More', [(i, i) for i in extra])] if extra else []):
        ids = [i for i, _ in secs if i in bufs]
        if not ids:
            continue
        toc.append(f'<li class="part">{E(pname)}</li>' + ''.join(
            f'<li><a href="#{i}"><span class="sn">{num[i]}</span>{E(title_of.get(i, i))}</a></li>' for i in ids))
        body.append(f'<p class="partbanner" aria-hidden="true">{E(pname)}</p>')
        for i in ids:
            s = ''.join(bufs[i])
            body.append(s.replace(f'<section id="{i}"><h2><span class="sn">00</span>', f'<section id="{i}"><h2><span class="sn">{num[i]}</span>', 1))
    toc_html = ''.join(toc)
    cites = ak.compact(ak._REG)
    cites['H'] = ''                     # r33: no home directory reaches the page (citations are repo-relative)
    reg_js = ('<script type="application/json" id="ak-cites">'
              + json.dumps(cites, ensure_ascii=False, separators=(',', ':')).replace('</', '<\\/') + '</script>')
    head = (f'<style>{theme_css()}{CSS}{chk.CHART_CSS}{chk.MATRIX_CSS}{ak.CT_CSS}{ak.CITE_CSS}{ck.CONNECTOR_CSS}{tk.TT_CSS}{dk.CSS}</style>')
    page = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">'
            f'<title>DERO HE Source Architecture ({E(cur_name)})</title>'
            + head + '</head><body><a class="skip" href="#main">Skip to the content</a>'
            f'<details id="tocd"><summary>Contents</summary><ol>{toc_html}</ol></details>'
            f'<div class="layout"><nav class="toc" aria-label="Contents"><div class="toct">Contents</div><ol>{toc_html}</ol></nav>'
            f'<main id="main">{hero}{"".join(bufs["_pre"])}{"".join(body)}</main></div>'
            + reg_js + f'<script>{ak.CT_JS}{ak.CITE_JS}{tk.TT_JS}{JS}{ck.CONNECTOR_JS}</script><script>{THEME_JS}</script>'
            '</body></html>')
    return pub(page)


# ───────────────────────────── stamp, drift, skill sync ─────────────────────────────
from prep_corpus import sha   # noqa: E402 — ONE definition of the content hash. It excludes the
# skill's AUTO block, which this build writes, so the page can never be stale against its own output.


def sources(rows):
    """Everything the page depends on. A change to any of it makes the page STALE (living-architecture law)."""
    s = {str(HERE / 'gen_deroarch.py'), str(HERE / 'prep_corpus.py'), str(SKILL), str(HERE / 'round.json')}   # r33: the page names the round
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


def build(strict=False):
    rows, rejected, unverified, stats = resolve()
    lost = lost_report(LOST)
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
    lint = svg_lint(h) + page_lint(h)          # r33: + a private value or a chart without its text alternative
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(h)
    st = {'built': datetime.datetime.now().astimezone().isoformat(timespec='seconds'), 'fingerprint': fp, 'root': str(ROOT),
          'stats': stats, 'svg_lint': len(lint), 'svg_lint_examples': lint[:4], 'bytes': len(h.encode()),
          'anchors_lost': lost,                              # r27: per raw file, with the miner to re-run
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
    for l in lost:
        print('  WARN', l)
    if lost and strict:
        print(f'  build --strict: {sum(LOST.values())} anchor(s) lost: re-run the named miner(s), then build again')
    return 3 if bad or lint or (lost and strict) else 0


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


COMMANDS = ('resolve', 'build', 'check', 'selftest', 'export-verify', 'export-pending', 'sync-skill')


def main(argv):
    """r27 (tools-kats): `gen_deroarch.py --help` raised KeyError '--help' (exit 1) and any unknown word did the same.
    Now --help prints the module docstring (exit 0), an unknown command or flag prints the usage on stderr (exit 2),
    and `build --strict` is the only flag a command takes."""
    if any(a in ('-h', '--help') for a in argv):
        print(__doc__)
        return 0
    cmd = argv[0] if argv else 'build'
    flags = argv[1:]
    if cmd not in COMMANDS or any(f != '--strict' for f in flags) or (flags and cmd != 'build'):
        print(f"usage: gen_deroarch.py [{'|'.join(COMMANDS)}] [--strict (build only)] · got {' '.join(argv)!r}", file=sys.stderr)
        return 2
    if cmd == 'resolve':
        rows, rej, unv, stats = resolve()
        print(json.dumps(stats))
        print('\n'.join(f"REJ {x['id']}: {str(x['why'])[:150]}" for x in rej[:40]))
        return 0
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
        return 0
    if cmd == 'export-pending':
        rows = resolve()[0]
        pend = [r for r in rows if r.get('verdict') is None]
        print(f'{len(pend)} row(s) without a current verdict:',
              dict(collections.Counter(r['section'] for r in pend)))
        return 0
    if cmd == 'sync-skill':
        return 0 if sync_skill() else 3
    if cmd == 'build':
        return build(strict='--strict' in flags)
    return {'check': check, 'selftest': selftest}[cmd]()


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
