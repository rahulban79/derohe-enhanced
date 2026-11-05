"""soundpage.py — r25: the soundness review is a per-round page, like the ledger (artifacts/dero-rft.md §0.6, §6 step 13).

Until R25 every tool named one fixed page, artifacts/dero-soundness-r23.html. From R25 each round writes its own
review page, artifacts/dero-soundness-<round>.html, where <round> is harness/round.json `current`; earlier pages stay
unchanged as history (old ledger pages link them and must keep regenerating byte-exact). Every harness tool that needs
the soundness page asks this module, so no tool can keep pointing at a stale round:

  name(root)          'dero-soundness-<current>.html'  (raises ValueError when the registry has no current round)
  rel(root)           'artifacts/' + name(root)
  history(root)       the other dero-soundness-r*.html pages under artifacts/, oldest first (historic, not gated)
  page_round(fname)   'r25' for 'dero-soundness-r25.html', else None

Pure except the reads of harness/round.json and the artifacts/ listing. KAT: harness/kat/test_soundpage_r25.py.

r26 (forensics-frontend2, rft §0.8.9 "Where it shows", B114): the generator of the page's section "What can be known:
defect classes and bounds" (between <!--known:begin--> and <!--known:end-->, never hand-edited):

  known_section(root)       (html, claim entries): the class x {detectable per tx, amount observable, bound, present now}
                            matrix (a class block, G31), the DC2-present headline (G32), the missing-invariant
                            certificate and the rules; every number is a dataset fact span (G30) or a class figure
  write_known(root)         splices it into the current round's page (before the first dossier on first use) and
                            replaces the `known-*` entries of harness/loop/SOUNDNESS_CLAIMS.json (G22: one entry per unit)
  python3 -I harness/kit/soundpage.py --write-known | --check-known      (exit 0 · 3 the page section is stale)
KAT: harness/kat/test_forensics_frontend2_r26.py (FE6-FE8).
"""
import html, importlib.util, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
RX = re.compile(r'^dero-soundness-(r\d+[a-z]?)\.html$')


def current(root=ROOT):
    reg = json.loads((Path(root) / 'harness/round.json').read_text())
    cur = reg.get('current') if isinstance(reg, dict) else None
    if not isinstance(cur, str) or not re.fullmatch(r'r\d+[a-z]?', cur):
        raise ValueError(f'harness/round.json has no usable current round: {cur!r}')
    return cur


def name(root=ROOT):
    return f'dero-soundness-{current(root)}.html'


def rel(root=ROOT):
    return 'artifacts/' + name(root)


def page_round(fname):
    m = RX.match(Path(fname).name)
    return m.group(1) if m else None


def _key(r):
    m = re.match(r'r(\d+)([a-z]?)', r)
    return (int(m.group(1)), m.group(2))


def history(root=ROOT):
    cur = name(root)
    pages = [p.name for p in (Path(root) / 'artifacts').glob('dero-soundness-r*.html') if page_round(p.name) and p.name != cur]
    return sorted(pages, key=lambda n: _key(page_round(n)))



# ───────────────────────────── r26: the generated "What can be known" section ─────────────────────────────
KN_BEGIN, KN_END = '<!--known:begin-->', '<!--known:end-->'
KNOWN_ID = 'known-'
CLAIMS = 'harness/loop/SOUNDNESS_CLAIMS.json'


def _load(root, rel, tag):
    sp = importlib.util.spec_from_file_location(f'{tag}_for_soundpage_{len(sys.modules)}', Path(root) / rel)
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


def known_section(root=ROOT):
    """(html, [claim entries]) of the section, read from the newest dataset (v2 or later); raises when none is readable"""
    root = Path(root)
    FM = _load(root, 'harness/forensics/facts.py', 'facts')
    FS = _load(root, 'artifacts/src/forensics_section.py', 'fxsection')
    SN = _load(root, 'harness/soundness.py', 'soundness')
    F = FM.build(FM.newest_dataset(root), root)
    if not FM.is_v2(F.m):
        raise ValueError(f'{F.ds.name} is not a dataset with defect classes (manifest version 2)')
    if F.problems:
        raise ValueError(f'{F.ds.name}: {F.problems[0]}')
    N, C, I, figs = FS.renderers(F, FM, html.escape)
    B = lambda fid: f'<span class="fxbound">{N(fid)}</span>'
    h = [KN_BEGIN, '<section class="dossier" id="known">',
         f'<div class="dhead"><span class="pill" style="background:var(--bad)">Dataset {N("dataset")}</span>'
         '<h2>What can be known: defect classes and bounds</h2></div>',
         f'<p data-fc-headline="dc2-present"><b>Still open now:</b> {N("cl_headline")}</p>',
         '<p>Three defect classes are kept apart in every figure, and each figure names its class, scope, coverage and bound. '
         f'The figures below are read from the forensic dataset <code>forensics/{N("dataset")}</code> (manifest '
         f'<code>{N("manifest_sha256")}</code>); hover a number for its file and SHA-256.</p>',
         KN_BEGIN.replace('known', 'classes'),
         '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:14px">'
         '<thead><tr><th style="text-align:left">Class</th><th style="text-align:left">Detectable per transaction</th>'
         '<th style="text-align:left">Amount observable</th><th style="text-align:left">Bound</th>'
         '<th style="text-align:left">Present in the current code</th></tr></thead><tbody>',
         f'<tr><td>DC1 duplication ladder</td><td>yes: the structural facts of the {N("table_entries")} table TXIDs, '
         f'{N("bodies_raw")} bodies RAW</td><td>DC1-obs {C("dc1-obs-coverage")} of {N("clf:dc1-obs-coverage:den")}; '
         f'{N("cl_dc1_pending")} DC1-pending</td><td>{B("clf:dc1-obs-coverage:bound")}; amounts {C("dc1-obs-amount")}</td>'
         f'<td>{N("pr:DC1:HEAD:admits")} (closures {N("pr:DC1:HEAD:closures")} of {N("pr:DC1:HEAD:closures_total")})</td></tr>',
         f'<tr><td>DC2 proof soundness</td><td>no: {N("fq:FQ5:status")}</td><td>no</td>'
         f'<td>{B("clf:dc2-created-value:bound")}: {C("dc2-created-value")} over {N("clf:dc2-created-value:scope")}</td>'
         f'<td>{N("pr:DC2:HEAD:admits")} at the round head, {N("pr:DC2:Release153:admits")} at Release153, '
         f'{N("pr:DC2:DeroHE:admits")} at the genesis-era tag</td></tr>',
         f'<tr><td>DC3 public-value identities</td><td>yes: public fields</td><td>yes</td>'
         f'<td>{B("clf:dc3-window-emission:bound")}: window emission {C("dc3-window-emission")}; fees {C("dc3-window-fees")} '
         f'({B("clf:dc3-window-fees:bound")} in the class file; the audit&rsquo;s own sum over dataset v2 is '
         f'{N("v:V2-FEES:fig:v2-window-fees")}, {N("v:V2-FEES:fig:v2-window-fees:bound")}, challenge D2-19 '
         f'{N("ch:D2-19:result")})</td><td>{N("pr:DC3:HEAD:admits")}</td></tr>',
         f'<tr><td>DC0 outside every class</td><td>yes</td><td>not applicable</td><td>{B("clf:dc0-window-duplicates:bound")}: '
         f'{C("dc0-window-duplicates")}</td><td>not applicable</td></tr>',
         '</tbody></table></div>', KN_END.replace('known', 'classes'),
         '<div class="cols"><div class="box o"><h3>The missing-invariant certificate</h3><ul>',
         f'<li>{N("q2_question")} <b>{N("q2_answer")}</b> ({N("q2_anchors_ok")} of {N("q2_anchors")} code anchors re-read).</li>',
         f'<li>{N("q3_question")} <b>{N("q3_answer")}</b>.</li>',
         f'<li>Missing invariant: {N("q3_missing")}.</li>',
         f'<li>Shown absent by: {N("q3_shown_by")}.</li>',
         f'<li>Consequence: {N("q3_consequence")}.</li>',
         '</ul></div><div class="box"><h3>Rules on this page and the ledger</h3><ul>',
         '<li>A fixed path is not a restored supply: a fix status says that a code path admits no new cases; it changes no '
         'historical grade.</li>',
         '<li>An unknown is pending, never zero: an undecidable quantity shows as unbounded or pending.</li>',
         f'<li>A historical replay is not a current-state proof: the node replay of {N("mr_added")} blocks ends at our own '
         f'state root ({N("mr_end_match")}), which shows our state is consistent with the blocks it accepted and nothing about '
         'hidden amounts.</li>',
         '</ul></div></div>',
         '<p class="src">Generated by harness/kit/soundpage.py from the dataset files, never hand-edited; every figure is traced '
         'by gate G30 and every class figure by gates G31 and G32. The full sections are on the ledger page.</p>',
         '</section>', KN_END]
    out = '\n'.join(h)
    msha = F.facts['manifest_sha256']['value']
    entries, seen = [], set()
    for kind, u in SN.page_units(out):
        if u in seen:
            continue
        seen.add(u)
        entries.append({'id': f'{KNOWN_ID}{len(entries) + 1:02d}', 'kind': 'record', 'match': u, 'exact': True,
                        'source': (f'generated by harness/kit/soundpage.py known_section() from forensics/{F.ds.name} (manifest '
                                   f'{msha[:16]}); each figure is a data-src/data-sha span re-checked by gate G30, each class '
                                   'figure by G31/G32 against derived/classes.json')})
    return out, entries


def splice(page, section):
    """the page with its known block replaced (or inserted before the first dossier section on first use)"""
    if KN_BEGIN in page and KN_END in page:
        return page[:page.index(KN_BEGIN)] + section + page[page.index(KN_END) + len(KN_END):]
    i = page.find('<section class="dossier"')
    if i < 0:
        raise ValueError('no dossier section to insert the known block before')
    return page[:i] + section + '\n\n' + page[i:]


def merge_claims(reg, entries):
    reg = dict(reg)
    reg['claims'] = [c for c in reg.get('claims', []) if not str(c.get('id', '')).startswith(KNOWN_ID)] + entries
    return reg


def write_known(root=ROOT, check=False):
    """(changed, page rel): splice the section into the current page and refresh the known-* claim entries;
    check=True only compares (a stale section is a difference)"""
    root = Path(root)
    sec, ent = known_section(root)
    pp = root / rel(root)
    old = pp.read_text()
    new = splice(old, sec)
    cp = root / CLAIMS
    reg = json.loads(cp.read_text())
    reg2 = merge_claims(reg, ent)
    changed = new != old or reg2 != reg
    if not check and changed:
        pp.write_text(new)
        cp.write_text(json.dumps(reg2, indent=1, ensure_ascii=False) + '\n')
    return changed, rel(root)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--write-known', action='store_true')
    ap.add_argument('--check-known', action='store_true')
    ap.add_argument('--root', default=str(ROOT))
    a = ap.parse_args(argv)
    if a.write_known or a.check_known:
        ch, r = write_known(a.root, check=a.check_known)
        print(f'{r}: known section {"stale" if a.check_known and ch else "written" if ch else "current"}')
        return 3 if a.check_known and ch else 0
    print(name(a.root))
    return 0


if __name__ == '__main__':
    sys.exit(main())
