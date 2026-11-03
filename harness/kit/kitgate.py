#!/usr/bin/env python3
"""kitgate — the artifact-kit gates for ANY page, static + headless Chrome (one command, one verdict).

  python3 kitgate.py PAGE [--label L] [--ledger FILE.md] [--width 1280,485] [--no-browser]

  G5  every inline <script> parses (node --check)
  G6  HTML tag balance (scripts stripped)
  G7  connectors: every diagram with a connector glows on hover (SVG url() filter, own colour); when a diagram has
      numbered units, ▶ plays them once in order and the same button stops it (connectorkit probe)
  G10 every asset carries a class tag: assetkit.audit (static) + no .ct-UNK and no untagged g.as in the rendered DOM
  G11 no cut sentence without its tooltip + ⓘ: textkit.audit on the page AND on the rendered DOM
  G12 every tag opens its exact citations: assetkit.cite_audit (0 uncited, 0 malformed) + the popover opens on an HTML
      pill and an SVG pill with only vscode://file/ or https:// links, pins on click and closes on Escape
  exit 0 all PASS · 3 any FAIL. --ledger appends one row per gate (markdown table) for a living ledger.
"""
import datetime, html as _html, html.parser, json, re, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import assetkit as ak  # noqa: E402
import connectorkit as ck  # noqa: E402
import textkit as tk  # noqa: E402

CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr', 'path', 'rect', 'line',
        'circle', 'polygon', 'polyline', 'stop', 'use', 'ellipse', 'image', 'feblend', 'fegaussianblur', 'femergenode', 'feoffset',
        'fecolormatrix', 'feflood', 'fecomposite', 'animate', 'animatetransform', 'set'}
# optional end tags (HTML spec): their absence is not imbalance
OPTIONAL = {'p', 'li', 'td', 'th', 'tr', 'thead', 'tbody', 'tfoot', 'option', 'dt', 'dd', 'colgroup', 'html', 'body', 'head'}

PROBE = "<script>" + ck.PROBE_HEAD + "window.__errs=[];addEventListener('error',function(e){window.__errs.push(String(e.message)+' @'+e.lineno);});</script>"
TAGS_JS = ("var bt={unk:document.querySelectorAll('.ct-UNK').length,as:0,as_untagged:0,pills:document.querySelectorAll('.ct[data-ci]').length,"
           "pills_unfocusable:document.querySelectorAll('.ct[data-ci]:not([tabindex])').length};"
           "[].forEach.call(document.querySelectorAll('svg g.as'),function(g){bt.as++;if(!g.querySelector('.ct'))bt.as_untagged++;});"
           "bt.cite={};['.ct[data-ci]:not(.ct-nocite):not(g)','g.ct[data-ci]:not(.ct-nocite)'].forEach(function(sel,k){var p=document.querySelector(sel);if(!p)return;"
           "p.dispatchEvent(new PointerEvent('pointerover',{bubbles:true}));var b=document.getElementById('ak-cite'),a=b?b.querySelectorAll('a[href]'):[];"
           "var good=[].filter.call(a,function(x){return /^(vscode:\\/\\/file\\/|https:\\/\\/)/.test(x.getAttribute('href'));}).length;"
           "p.dispatchEvent(new MouseEvent('click',{bubbles:true}));var pinned=!!(b&&b.classList.contains('on')&&/pinned/.test(b.textContent));"
           "document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape'}));bt.cite[k?'svg':'html']={open:!!(b&&a.length),links:a.length,good_links:good,pinned:pinned,closed:!!(b&&!b.classList.contains('on'))};"
           "if(b&&b.classList.contains('on')){b.classList.remove('on');}});")
PROBE_END = ("<script>addEventListener('load',function(){" + ck.PROBE_START_JS + "setTimeout(function(){" + TAGS_JS + ck.PROBE_COLLECT_JS +
             "var d=document.createElement('pre');d.id='KITPROBE';d.textContent=JSON.stringify({errors:window.__errs,trace:tr,tags:bt,"
             "has_conn:!!document.querySelector('svg [marker-end]:not(marker *),svg path.ie,svg path.cx,svg g.cx'),"
             "has_num:!!document.querySelector('svg g.cx .nb text')});document.body.appendChild(d);},400);});</script>")


class Bal(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.st, self.err = [], []

    def handle_starttag(self, t, a):
        if t not in VOID:
            self.st.append(t)

    def handle_startendtag(self, t, a):
        pass

    def handle_endtag(self, t):
        if t in VOID:
            return
        if self.st and self.st[-1] == t:
            self.st.pop()
        elif t in self.st:
            while self.st and self.st[-1] != t:
                x = self.st.pop()
                if x not in OPTIONAL:
                    self.err.append(f'unclosed <{x}> before </{t}>')
            self.st.pop()
        elif t not in OPTIONAL:
            self.err.append(f'stray </{t}>')


def browser(h, width):
    body = h.replace('<head>', '<head>' + PROBE, 1) if '<head>' in h else PROBE + h
    body = body.replace('</body>', PROBE_END + '</body>') if '</body>' in body else body + PROBE_END
    with tempfile.NamedTemporaryFile('w', suffix='.html', delete=False) as f:
        f.write(body)
    r = subprocess.run([CHROME, '--headless=new', '--disable-gpu', f'--window-size={width},1000', '--virtual-time-budget=8000',
                        '--dump-dom', 'file://' + f.name], capture_output=True, text=True, timeout=600)
    m = re.search(r'<pre id="KITPROBE">(.*?)</pre>', r.stdout, re.S)
    return (json.loads(_html.unescape(m.group(1))) if m else {'missing': True, 'stderr': r.stderr[-300:]}), r.stdout


def run(page, label='manual', ledger=None, widths=(1280,), use_browser=True):
    h = Path(page).read_text()
    res = []
    # only real JavaScript: no type, or a JavaScript type (data blocks — JSON, compressed cards — are not code)
    js = '\n;\n'.join(body for attrs, body in re.findall(r'<script\b([^>]*)>(.*?)</script>', h, re.S)
                       if not re.search(r'type="(?!text/javascript|application/javascript|module)', attrs))
    with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False) as f:
        f.write(js)
    r = subprocess.run(['node', '--check', f.name], capture_output=True, text=True)
    res.append(('G5 page scripts parse', r.returncode == 0, (r.stderr.strip().splitlines() or ['node --check ok'])[0][:160]))
    b = Bal()
    b.feed(re.sub(r'<script[^>]*>.*?</script>|<style[^>]*>.*?</style>', '', h, flags=re.S))
    left = [t for t in b.st if t not in OPTIONAL]
    res.append(('G6 HTML tag balance', not b.err and not left, f'{len(b.err)} error(s), {len(left)} unclosed' + (f': {b.err[:3]} {left[:3]}' if b.err or left else '')))
    probes, doms = {}, {}
    if use_browser:
        for w in widths:
            probes[w], doms[w] = browser(h, w)
    p0 = probes.get(widths[0], {}) if use_browser else {}
    if use_browser:
        if p0.get('has_conn'):
            ok7, s7 = ck.check(p0.get('trace'), need_play=bool(p0.get('has_num')))
        else:
            ok7, s7 = True, 'no connector on this page'
        ok7 = ok7 and not p0.get('missing') and not p0.get('errors')
        res.append(('G7 connectors glow (+ ▶ plays numbered ones)', ok7, s7 + (f" errors={p0.get('errors')[:3]}" if p0.get('errors') else '') + (' PROBE MISSING ' + str(p0.get('stderr')) if p0.get('missing') else '')))
    st = ak.audit(h)
    # compressed lazy fragments (cards that inflate in the browser) are assets too: audit each one decoded
    import base64, gzip
    lz = {'cards': 0, 'cells': 0, 'untagged': 0, 'unk': 0, 'svg_untagged': 0}
    for body in re.findall(r'<script type="application/x-vf-gzip-b64" class="lazyz"[^>]*>([A-Za-z0-9+/=\s]*)</script>', h):
        frag = gzip.decompress(base64.b64decode(body)).decode('utf-8', 'replace')
        a_ = ak.audit(frag)
        lz['cards'] += 1
        lz['cells'] += a_['asset_cells']
        lz['untagged'] += a_['untagged_cells']
        lz['unk'] += a_['unclassified']
        lz['svg_untagged'] += a_['svg_untagged']
    st['ok'] = st['ok'] and not lz['untagged'] and not lz['unk'] and not lz['svg_untagged']
    bt = p0.get('tags') or {}
    ok10 = st['ok'] and (not use_browser or (not bt.get('unk') and not bt.get('as_untagged') and not bt.get('pills_unfocusable')))
    res.append(('G10 every asset carries a class tag', ok10, f"static: {st['asset_cells']} table cells ({st['untagged_cells']} untagged), {st['svg_assets']} diagram assets ({st['svg_untagged']} untagged), {st['unclassified']} unclassified, {st['notag_tables']} ledger tables opted out"
                + (f" · {lz['cards']} compressed cards: {lz['cells']} cells ({lz['untagged']} untagged, {lz['unk']} unclassified, {lz['svg_untagged']} untagged boxes)" if lz['cards'] else '')
                + (f" · browser: {bt.get('pills')} pills ({bt.get('pills_unfocusable')} not focusable), {bt.get('unk')} UNK, {bt.get('as')} g.as ({bt.get('as_untagged')} untagged)" if use_browser else '')
                + (f" e.g. {st['examples'][:2]} {st['svg_examples'][:2]}" if not st['ok'] else '')))
    ts_ = tk.audit(h)
    td_ = tk.audit(doms.get(widths[0], '')) if use_browser else ts_
    ok11 = ts_['ok'] and td_['ok']
    res.append(('G11 no cut sentence without its tooltip', ok11, f"static: {ts_['cut_with_tooltip']} shortened texts carry the full sentence + ⓘ, {ts_['cut_without_tooltip']} do not"
                + (f" · rendered DOM: {td_['cut_with_tooltip']} with, {td_['cut_without_tooltip']} without" if use_browser else '') + (f" e.g. {(ts_['examples'] + td_['examples'])[:3]}" if not ok11 else '')))
    ca = ak.cite_audit(h)
    cp = bt.get('cite') or {}
    kinds = [k for k in ('html', 'svg') if k in cp]
    pop_ok = (not use_browser) or (bool(kinds) and all(cp[k].get('open') and cp[k].get('good_links') == cp[k].get('links') and cp[k].get('pinned') and cp[k].get('closed') for k in kinds))
    ok12 = ca['ok'] and pop_ok
    res.append(('G12 every tag opens its exact citations', ok12, f"registry {ca['registry']} entries · " + ', '.join(
        f"{k} {v['cited']} cited / {v['nocite']} uncited" + (f" / {v['contradicted']} contradicted" if v.get('contradicted') else '') for k, v in sorted(ca['by_class'].items()))
        + f" · malformed {ca['malformed']} · popover {cp if use_browser else 'not run'}"))
    if ledger:
        ts = datetime.datetime.now().astimezone().isoformat(timespec='seconds')
        g = Path(ledger)
        if not g.exists():
            g.write_text('# kit gates — appended by artifact-kit/kitgate.py\n\n| time | page | label | gate | result | evidence |\n|---|---|---|---|---|---|\n')
        with g.open('a') as f:
            for name, ok, ev in res:
                f.write(f"| {ts} | {Path(page).name} | {label} | {name} | {'PASS' if ok else 'FAIL'} | {ev.replace('|', '/')[:600]} |\n")
    return res


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    page = argv[0]
    label = argv[argv.index('--label') + 1] if '--label' in argv else 'manual'
    ledger = argv[argv.index('--ledger') + 1] if '--ledger' in argv else None
    widths = tuple(int(x) for x in argv[argv.index('--width') + 1].split(',')) if '--width' in argv else (1280,)
    res = run(page, label, ledger, widths, '--no-browser' not in argv)
    for name, ok, ev in res:
        print(f"{'PASS' if ok else 'FAIL'}  {name}: {ev[:900]}")
    return 0 if all(ok for _, ok, _ in res) else 3


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
