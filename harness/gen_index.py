#!/usr/bin/env python3
"""gen_index.py — artifacts/index.html, the hub of this project's artifact suite.

It is itself a projection: every number on it is read from stamp.json, loop/KAT_LAST.json, loop/GATES.md and the
retrofit evidence files. Published URLs live in harness/model/published.json ({"<file>": "<url>"}) and are shown
only when they are there.

  python3 harness/gen_index.py            # render
  python3 harness/gen_index.py check      # 0 CURRENT · 3 STALE
"""
import collections, datetime, hashlib, html, json, re, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
ART = ROOT / 'artifacts'
OUT = ART / 'index.html'
PUB = HERE / 'model/published.json'
MEMORY = Path.home() / '.claude/projects' / ('-' + str(Path.home()).strip('/').replace('/', '-') + '-derohe-Release142') / 'memory'
sys.path.insert(0, str(HERE / 'kit'))
sys.path.insert(0, str(HERE))
import assetkit as ak  # noqa: E402
import textkit as tk   # noqa: E402
from gen_deroarch import CSS  # noqa: E402  — one visual identity across the suite

E = lambda s: html.escape(str(s if s is not None else ''), quote=True)


def cite_at(path, needle, cls, why):
    """A class pill whose citation is the exact line of the harness ledger the number was read from."""
    rel = Path(path)
    try:
        lines = rel.read_text(errors='replace').splitlines()
    except OSError:
        return ''
    i = next((k + 1 for k, l in enumerate(lines) if needle in l), None)
    if i is None:
        return ''
    c = ak.cite_file(str(rel), i, lines[i - 1].strip()[:200], cls=cls,
                     label=str(rel).replace(str(Path.home()), '~'))
    return ak.ctag(ak.fixed(cls, why, [c]))


def _mtag(t):
    col = {'project': 'var(--l4)', 'feedback': 'var(--queued)', 'reference': 'var(--host)', 'user': 'var(--accent2)'}.get(t, 'var(--mut)')
    return f'<span class="chip" style="--c:{col}">{html.escape(str(t))}</span>'


def memories():
    """Every memory file with its name, type and one-line description, read from its own frontmatter.
    GK class: a line of the memory store. Self-updating — the section reflects whatever is on disk."""
    out = []
    if not MEMORY.is_dir():
        return out
    for f in sorted(MEMORY.glob('*.md')):
        if f.name == 'MEMORY.md':
            continue
        txt = f.read_text(errors='replace')
        name = re.search(r'^name:\s*(.+)$', txt, re.M)
        desc = re.search(r'^description:\s*"?(.+?)"?\s*$', txt, re.M)
        typ = re.search(r'^\s{2}type:\s*(.+)$', txt, re.M)
        # the line to cite: the description line (proves the summary is read from the file, not written here)
        dline = next((i + 1 for i, l in enumerate(txt.splitlines()) if l.startswith('description:')), 1)
        out.append({'file': f.name, 'name': name.group(1).strip() if name else f.stem,
                    'type': typ.group(1).strip() if typ else '?',
                    'desc': (desc.group(1).strip() if desc else '').strip('"'),
                    'path': str(f), 'line': dline})
    return out


def gates():
    g = HERE / 'loop/GATES.md'
    if not g.exists():
        return [], ''
    rows = [l.split('|') for l in g.read_text().splitlines() if l.startswith('| 20')]
    if not rows:
        return [], ''
    last_cycle = rows[-1][2].strip()
    # a label can be reused across runs; keep only the newest result per gate so a re-run never double-counts
    latest = {}
    for r in rows:
        if r[2].strip() == last_cycle:
            latest[r[3].strip()] = r
    return list(latest.values()), last_cycle


def main():
    st = json.loads((HERE / 'stamp.json').read_text())
    kat = json.loads((HERE / 'loop/KAT_LAST.json').read_text()) if (HERE / 'loop/KAT_LAST.json').exists() else {}
    pub = json.loads(PUB.read_text()) if PUB.exists() else {}
    last, cycle = gates()
    mems = memories()
    mtype = collections.Counter(m['type'] for m in mems)
    passed = sum(1 for r in last if r[4].strip() == 'PASS')
    V = json.loads((HERE / 'model/verified.json').read_text())
    cls = collections.Counter(e['kind'] for r in V for e in r['evidence'])
    now = datetime.datetime.now().astimezone()
    ak.reg_reset()

    PAGES = [
        {'file': 'dero-src-arch.html', 'title': 'Source architecture',
         'what': 'The whole first-party tree \u2014 18 packages, the consensus constants and the arithmetic they imply, '
                 'six execution chains drawn hop by hop, the live daemon, and the findings that reading one against '
                 'the other produced.',
         'rows': st['stats']['rows'], 'anchors': f"{st['stats']['anchors_ok']}/{st['stats']['anchors']}",
         'built': st['built'][:16].replace('T', ' '), 'fp': st['fingerprint'],
         'how': 'projected by <code>harness/gen_deroarch.py</code> from <code>harness/model/</code>',
         'gates': f'{passed}/{len(last)} in cycle {cycle}' if last else '\u2014',
         'kat': f"{kat.get('ok')}/{kat.get('total')} KATs, {kat.get('mut_proved')}/{kat.get('muts')} mutations proved" if kat else '\u2014'},
        {'file': 'release151-migration-report.html', 'title': 'Release151/152/153 migration report',
         'what': 'Rounds 4\u20136b: crossing hard fork 3, the replay wall and its cure, the chain split, the six p2p '
                 'fixes, the 64-hour health audit, and the wallet CLI. Hand-written, then raised to the same '
                 'standard by the kit: every cell carries its evidence class and opens its citations.',
         'rows': 122, 'anchors': '122/122 cells cited', 'built': '2026-10-20 (kit applied)', 'fp': 'retrofit',
         'how': 'retrofitted by <code>harness/kit/retrofit.py</code> from '
                '<code>harness/model/evidence/release151-migration-report.json</code>',
         'gates': 'G5 G6 G7 G10 G11 G12 PASS (kitgate)', 'kat': 'covered by DK16'},
    ]
    # r24: the CURRENT ledger page (the registry's current round when its page exists, else the highest
    # dero-r1-r<N>.html), not the R21 page this index linked until r24 (harness/intel/coherence.py check h).
    def _ledger():
        try:
            cur = json.loads((HERE / 'round.json').read_text()).get('current', '')
            m = re.match(r'r(\d+)', cur)
            if m and (ART / f'dero-r1-r{m.group(1)}.html').exists():
                return ART / f'dero-r1-r{m.group(1)}.html'
        except (OSError, ValueError):
            pass
        pages = sorted(ART.glob('dero-r1-r*.html'), key=lambda q: int(re.search(r'r(\d+)\.html$', q.name).group(1)))
        return pages[-1] if pages else ART / 'dero-r1-r21.html'
    LG = _ledger()
    LN = re.search(r'r(\d+)\.html$', LG.name).group(1)
    if LG.exists():   # hand-written ledger: its counts are read from the page itself, not asserted here
        lt = LG.read_text(errors='replace')
        PAGES.append(
            {'file': LG.name, 'title': f'DERO Enhancement Ledger (Rounds 1\u2013{LN})',
             'what': 'Every non-consensus change to derod, dero-miner, the wallet CLI and the harness from Round 1 to '
                     f'Round {LN}: what changed, why, a code excerpt from git for each round, a flow diagram, the measured '
                     'evidence, refuted ideas, a subsystem index, and the 150 KH/s ceiling arithmetic.',
             'rows': len(re.findall(r'<section[^>]*id="r\d+[a-z]?"', lt)),
             'anchors': f"{lt.count('<figcaption')} code excerpts \u00b7 {lt.count('class=\"mmsrc\"')} diagrams",
             'built': datetime.datetime.fromtimestamp(LG.stat().st_mtime).astimezone().strftime('%Y-%m-%d %H:%M'),
             'fp': hashlib.sha256(LG.read_bytes()).hexdigest()[:16],
             'how': 'generated by <code>artifacts/src/gen_ledger.py</code> from the pipeline records, <code>RUN_REPORT.md</code>, '
                    '<code>ARCHITECTURE.md</code> and <code>git show</code>; privacy-scanned (no paths, addresses, IPs or hostnames)',
             'gates': 'cross-checked by G25 (harness/intel/coherence.py)', 'kat': '\u2014'})
    import soundpage as SPG   # noqa: E402  r25: one soundness page per round (harness/kit/soundpage.py)
    SP = ART / SPG.name(HERE.parent)
    SR = SPG.page_round(SP.name)
    if SP.exists():   # r24: the soundness review page (gate G22, harness/soundness.py); r25: the current round's page
        sl = (HERE / 'loop/SOUNDNESS_LAST.json')
        PAGES.append(
            {'file': SP.name, 'title': f'Soundness review (Round {SR[1:].upper()}: HF3 exemption, supply, emission audit, forensics)',
             'what': 'What the node\u2019s code does about the HF3 proof skip, the nonce bypass, the already-mined guard, the '
                     'validity window, the TXID scope, the CalcSupply formula and the emission auditor, re-verified this round: '
                     'every claim unit is registered in harness/loop/SOUNDNESS_CLAIMS.json and re-checked.',
             'rows': SP.read_text(errors='replace').count('<p'), 'anchors': 'claim units registered (G22)',
             'built': datetime.datetime.fromtimestamp(SP.stat().st_mtime).astimezone().strftime('%Y-%m-%d %H:%M'),
             'fp': hashlib.sha256(SP.read_bytes()).hexdigest()[:16],
             'how': 'hand-written; every claim unit backed by a test, an anchor, a derivation or a live read '
                    '(<code>harness/soundness.py</code>)' + ('' if sl.exists() else ' (no soundness record yet)'),
             'gates': 'G22', 'kat': '\u2014'})
    for hn in SPG.history(HERE.parent):   # r25: earlier rounds' soundness pages, kept unchanged as history (not gated)
        HP = ART / hn
        PAGES.append(
            {'file': hn, 'title': f'Soundness review, Round {SPG.page_round(hn)[1:].upper()} (history)',
             'what': f'The soundness review as written in Round {SPG.page_round(hn)[1:].upper()}; kept unchanged because older ledger '
                     f'pages link it. The current review is {SP.name}.',
             'rows': HP.read_text(errors='replace').count('<p'), 'anchors': 'history (not re-gated)',
             'built': datetime.datetime.fromtimestamp(HP.stat().st_mtime).astimezone().strftime('%Y-%m-%d %H:%M'),
             'fp': hashlib.sha256(HP.read_bytes()).hexdigest()[:16],
             'how': 'hand-written; frozen when the next round wrote its own page', 'gates': '\u2014', 'kat': '\u2014'})

    ST, KT, GT = HERE / 'stamp.json', HERE / 'loop/KAT_LAST.json', HERE / 'loop/GATES.md'
    EV = HERE / 'model/evidence/release151-migration-report.json'
    W = 'read from this harness ledger, which the build and the gate run write'
    TAGS = {
        'dero-src-arch.html': {
            'tag_rows': cite_at(ST, '"rows":', 'HARNESS', W), 'tag_anchors': cite_at(ST, '"anchors_ok":', 'HARNESS', W),
            'tag_gates': cite_at(GT, 'G1 every rendered anchor resolved', 'HARNESS', W),
            'tag_kat': cite_at(KT, '"mut_proved":', 'HARNESS', W),
            'tag_built': cite_at(ST, '"built":', 'HARNESS', W), 'tag_fp': cite_at(ST, '"fingerprint":', 'HARNESS', W)},
        'release151-migration-report.html': {
            'tag_rows': cite_at(EV, '"page":', 'HARNESS', 'the retrofit evidence file that declares this page'),
            'tag_anchors': cite_at(EV, '"sections":', 'HARNESS', 'section-level declarations in the evidence file'),
            'tag_gates': cite_at(EV, '"classes":', 'HARNESS', 'the class map the kit gates this page against'),
            'tag_kat': cite_at(HERE / 'kat/verify_deroarch.py', 'DK16 artifact-kit', 'HARNESS',
                               'the KAT that covers the kit audits'),
            'tag_built': cite_at(EV, '"clips":', 'HARNESS', 'the clips declared when the kit was applied'),
            'tag_fp': cite_at(EV, '"name":', 'HARNESS', 'the evidence file this page is retrofitted from')},
        LG.name: {
            'tag_rows': cite_at(LG, f'id="r{LN}', 'HARNESS', 'the last round section of the page'),
            'tag_anchors': cite_at(LG, '<figcaption', 'HARNESS', 'the first captioned git excerpt'),
            'tag_gates': '', 'tag_kat': '',
            'tag_built': cite_at(LG, '<title>', 'HARNESS', 'the page source'),
            'tag_fp': ''},
    }
    for p in PAGES:
        p.update({k: '' for k in ('tag_rows', 'tag_anchors', 'tag_gates', 'tag_kat', 'tag_built', 'tag_fp')}, **TAGS.get(p['file'], {}))
    cards = []
    for p in PAGES:
        url = pub.get(p['file'])
        link = (f'<a class="open" href="{E(url)}" target="_blank" rel="noopener noreferrer">open the published page \u2192</a>'
                if url else '<span class="mut">not published</span>')
        cards.append(f'''<article class="acard">
          <h3>{E(p['title'])}</h3>
          <p class="file"><code>artifacts/{E(p['file'])}</code></p>
          <p>{p['what']}</p>
          <dl>
            <div><dt>rows / cells</dt><dd>{E(p['rows'])} {p['tag_rows']}</dd></div>
            <div><dt>anchors</dt><dd>{E(p['anchors'])} {p['tag_anchors']}</dd></div>
            <div><dt>gates</dt><dd>{E(p['gates'])} {p['tag_gates']}</dd></div>
            <div><dt>KATs</dt><dd>{E(p['kat'])} {p['tag_kat']}</dd></div>
            <div><dt>built</dt><dd>{E(p['built'])} {p['tag_built']}</dd></div>
            <div><dt>fingerprint</dt><dd><code>{E(p['fp'])}</code> {p['tag_fp']}</dd></div>
          </dl>
          <p class="how">{p['how']}</p>
          <p>{link}</p>
        </article>''')

    mrows = ''.join(
        f'<tr><td><b>{E(m["name"])}</b><br><span class="mut" style="font-size:11px">{E(m["file"])}</span></td>'
        f'<td>{_mtag(m["type"])}</td>'
        f'<td>{E(m["desc"])}</td>'
        f'<td><a class="open" href="vscode://file/{E(m["path"])}:{m["line"]}" '
        f'style="font-family:var(--mono);font-size:11px">{E(m["file"])}:{m["line"]}</a></td></tr>'
        for m in mems)
    mkpis = ''.join(f'<div class="kpi"><div class="kv">{v}</div><div class="kl">{E(k)}</div></div>'
                    for k, v in [('entries', len(mems))] + sorted(mtype.items()))
    grows = ''.join(f"<tr><td><b>{E(r[3].strip())}</b></td>"
                    f"<td>{'<span class=ok-t>PASS</span>' if r[4].strip() == 'PASS' else '<span class=bad-t>FAIL</span>'}</td>"
                    f"<td class=mut>{tk.html_clip(r[5].strip(), 150)}</td></tr>" for r in last)

    body = f'''<header class="mast"><div class="wrap">
      <div class="eyebrow">Artifact suite \u00b7 DERO HE \u00b7 <repo></div>
      <h1>{len(PAGES)} pages, one evidence contract</h1>
      <p class="sub">The two gated artifacts are drawn only from lines that still exist \u2014 in the Go tree, in the
      third-party code it links, in snapshots of the daemon that is running, or in this project's own notes: one is
      projected from a model, the other is a hand-written report that the same kit has since annotated. The
      Rounds 1\u2013{LN} enhancement ledger is generated from the pipeline records, the run report, the architecture
      notes and git, and the soundness review is gated by G22; every artifact quotes its figures from one canonical
      source, which G25 (<code>harness/intel/coherence.py</code>) cross-checks. This page reports their current state
      and how to rebuild them.</p>
      <div class="tickers">
        <div class="tick live"><b>{passed}/{len(last)}</b><span>gates passing</span></div>
        <div class="tick"><b>{E(kat.get('ok'))}/{E(kat.get('total'))}</b><span>KATs</span></div>
        <div class="tick"><b>{E(kat.get('mut_proved'))}/{E(kat.get('muts'))}</b><span>mutations proved</span></div>
        <div class="tick"><b>{st['stats']['anchors_ok']}</b><span>anchors resolved</span></div>
        <div class="tick"><b>{cls.get('SRC', 0)}</b><span>SRC anchors</span></div>
        <div class="tick"><b>{cls.get('HARNESS', 0)}</b><span>HARNESS anchors</span></div>
        <div class="tick"><b>{cls.get('EXT', 0)}</b><span>EXT anchors</span></div>
      </div></div></header>
    <div class="wrap">
      <section id="pages"><h2><span class="num">01</span>The artifacts</h2>
      <div class="acards">{''.join(cards)}</div></section>

      <section id="contract"><h2><span class="num">02</span>The contract the two gated pages obey</h2>
      <p class="lede">A statement is drawn only if at least one of its anchors \u2014 a {{file, quote}} pair \u2014 is found
      verbatim on one line of that file, at least 12 characters after whitespace is normalised. Where the anchor
      points decides what the statement may claim.</p>
      <div class="tw"><table data-notag="the class vocabulary itself, not an asset"><thead><tr><th>class</th><th>a line of it proves</th><th>anchors in use</th></tr></thead><tbody>
        <tr><td><b>SRC</b></td><td>the first-party DERO source, its build scripts or go.mod</td><td class="num">{cls.get('SRC', 0)}</td></tr>
        <tr><td><b>EXT</b></td><td>third-party code under <code>vendor/</code> that this build links in \u2014 quoted, not owned</td><td class="num">{cls.get('EXT', 0)}</td></tr>
        <tr><td><b>HARNESS</b></td><td>the owner's own measured system: live snapshots, the console log, the run report</td><td class="num">{cls.get('HARNESS', 0)}</td></tr>
        <tr><td><b>GK</b></td><td>this project's knowledge base: its skill and memory store</td><td class="num">{cls.get('GK', 0)}</td></tr>
        <tr><td><b>PLAN</b></td><td>proposed in <code>harness/loop/PROPOSALS.md</code> and not yet run</td><td class="num">{cls.get('PLAN', 0)}</td></tr>
      </tbody></table></div>
      <p class="note">A row whose declared class its anchors cannot prove is re-derived from its first anchor and the
      page says so. A row with no resolvable anchor is never drawn \u2014 it goes to the quarantine with its reason.</p>
      </section>

      <section id="gates"><h2><span class="num">03</span>The last gate run</h2>
      <p class="lede">Cycle <code>{E(cycle)}</code>. Re-run with <code>python3 harness/run_gates.py &lt;label&gt;</code>.</p>
      <div class="tw"><table data-notag="a ledger of gate results, not a set of claims"><thead><tr><th>gate</th><th>result</th><th>detail</th></tr></thead><tbody>{grows}</tbody></table></div>
      </section>


      <section id="memory"><h2><span class="num">04</span>The memory store</h2>
      <p class="lede">Persistent, cross-session memory for this project — {len(mems)} entries under
      <code>~/.claude/projects/…/memory/</code>, each one fact, cross-linked with <code>[[wikilinks]]</code>.
      This table is read from the files themselves on every build, so it is never out of date. GK class: the
      project's own knowledge base.</p>
      <div class="kpis">{mkpis}</div>
      <div class="tw"><table id="t-mem" data-notag="a listing of the project\u2019s GK knowledge base; each row cites its own file"><thead><tr><th>memory</th><th>type</th><th>what it captures</th><th>file</th></tr></thead><tbody>
      {mrows}
      </tbody></table></div>
      </section>

      <section id="rebuild"><h2><span class="num">05</span>Rebuilding both</h2>
      <pre>cd <repo>
python3 harness/prep_corpus.py
for m in inventory consts flows logbridge localdiff findings; do python3 harness/miners/mine_$m.py; done
python3 harness/miners/mine_runtime.py --capture     # needs derod listening on 127.0.0.1:10102
python3 harness/gen_deroarch.py build
python3 harness/kit/retrofit.py apply harness/model/evidence/release151-migration-report.json
python3 harness/gen_index.py
python3 harness/run_gates.py &lt;label&gt;
python3 harness/kat/verify_deroarch.py --mutations</pre>
      <p class="note">The hook at <code>harness/hooks/autosync.py</code> does the middle of this automatically whenever a
      model file, a miner, the kit or the skill is edited.</p>
      </section>
      <footer>Rendered by <code>harness/gen_index.py</code> \u00b7 {E(now.strftime('%Y-%m-%d %H:%M %Z'))} \u00b7
      private pages: they cite absolute paths on this machine.</footer>
    </div>'''

    extra = ('''.acards{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:14px;margin:18px 0}
    .acard{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:16px 17px}
    .acard h3{margin:0 0 4px;font-size:17px}
    .acard .file{margin:0 0 10px;font-size:12px}
    .acard p{font-size:13.4px;margin:8px 0}
    .acard dl{display:grid;grid-template-columns:1fr 1fr;gap:7px 14px;margin:13px 0 0;padding-top:11px;border-top:1px solid var(--rule)}
    .acard dt{font:700 9.6px/1.4 var(--mono);letter-spacing:.07em;text-transform:uppercase;color:var(--mut)}
    .acard dd{margin:1px 0 0;font-size:12.6px;font-variant-numeric:tabular-nums}
    .acard .how{color:var(--mut);font-size:12px;margin-top:12px}
    .acard a.open{display:inline-block;margin-top:8px;font-weight:650;font-size:13px;text-decoration:none;
      border-bottom:2px solid color-mix(in srgb,var(--accent) 45%,transparent)}
    .ok-t{color:var(--ok);font-weight:700;font-size:11.5px;font-family:var(--mono)}
    .bad-t{color:var(--gap);font-weight:700;font-size:11.5px;font-family:var(--mono)}
    pre{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:13px 15px;
      font:12.3px/1.75 var(--mono);color:var(--ink)}''')

    h = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
         '<meta name="viewport" content="width=device-width,initial-scale=1">'
         '<title>DERO HE Artifact Suite</title>'
         f'<style>{CSS}{extra}{ak.CT_CSS}{ak.CITE_CSS}{tk.TT_CSS}</style></head><body>'
         + body + ak.cites_script() + f'<script>{ak.CT_JS}{ak.CITE_JS}{tk.TT_JS}</script></body></html>')
    if len(sys.argv) > 1 and sys.argv[1] == 'check':
        cur = OUT.read_text() if OUT.exists() else ''
        same = re.sub(r'\d{4}-\d\d-\d\d \d\d:\d\d', '', cur) == re.sub(r'\d{4}-\d\d-\d\d \d\d:\d\d', '', h)
        print('CURRENT' if same else 'STALE')
        return 0 if same else 3
    OUT.write_text(h)
    print(f'index: {len(h):,} bytes \u00b7 {len(PAGES)} artifacts \u00b7 gates {passed}/{len(last)} \u00b7 '
          f"KATs {kat.get('ok')}/{kat.get('total')}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
