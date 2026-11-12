#!/usr/bin/env python3
"""KAT + mutation proofs for R30 B206 (HIGH, privacy): the PDF path leaked local link targets. No live file is read or
written: every page, print copy and PDF is a temp file (the PDFs are built byte by byte here, stdlib only).

  PP1  print_copy.py rewrites every <a href> that is not http(s)/mailto/#… to an anchor-only target: a fixture page with
       a file:// link, an absolute path, a scratch path and a relative cross-page link keeps none of them as an href
       (the pre-r30 print_copy FAILS: it copied every href, and Chrome resolved them to file:///<print dir>/…).
  PP2  end to end (when Google Chrome is installed): the fixture, a link added by the page's own JavaScript included,
       printed by headless Chrome from the print copy, has 0 local /URI annotations and 0 path hits by bytes
       (r30 verify D4: also a static SVG <a xlink:href>, SVG links a late script builds with
       setAttributeNS(XLINK, 'xlink:href', …) and setAttributeNS(null, 'href', …) — the verifier's pc/page.html — and
       an xlink:href changed in place on an element already in the page, which only an attribute observer sees).
  PP3  harness/kit/pdfscan.py reads the RAW bytes: a /URI in plain object syntax, one packed in a FlateDecode object
       stream (a scratch path, and an absolute path with no path class), an /Info /Title in UTF-16BE hex and one with
       octal escapes (`\\057Users\\057…`), an XMP packet, a path in a compressed page content stream are each a
       finding; a clean PDF (https, relative and #anchor links, an image whose inflated bytes hold '~/a' and '(') is not.
  PP5  pdfscan --rewrite (the re-scrub of the older local prints): every local /URI literal is replaced in place by a
       relative target of the same byte length (a scratch page -> its basename#frag, a repo link -> ../<repo path>, the
       :line suffix dropped), an https one is kept, the file length is unchanged and the re-scan is clean.
  PP6  fail CLOSED (r30 verify D1): a /FlateDecode stream that does not inflate (raw deflate, no zlib header) and a
       stream behind a filter the scan does not decode (LZWDecode, an unknown name) are findings with no path in view;
       ASCIIHexDecode, ASCII85Decode, RunLengthDecode and a chain [/ASCIIHexDecode /FlateDecode] are DECODED (the
       /Users path inside is a users-path hit, nothing undecoded); the CLI exits 5 on the raw-deflate and ASCIIHex
       fixtures (the verifier's flate_rawdeflate.pdf / asciihex.pdf, rebuilt here); a DCTDecode image is exempt.
  PP4  harness/intel/privacy_audit.py scans PDFs: --dir with a dirty PDF exits 5 (the pre-r30 audit skipped *.pdf and
       exited 0), --pdf dirty exits 5, --pdf clean exits 0.

  python3 -I harness/kat/test_privacy_pdf_r30.py [--before-print FILE] [--before-audit FILE] [--no-chrome]
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not proved (MISSED / WRONG-KAT / INVALID) or was coupled.
"""
import base64, contextlib, importlib.util, io, os, re, shutil, signal, subprocess, sys, tempfile, zlib
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
PATHS = {'pc': 'artifacts/src/print_copy.py', 'ps': 'harness/kit/pdfscan.py', 'pa': 'harness/intel/privacy_audit.py',
         'pk': 'harness/kit/privkit.py'}
CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
OPTS = {'chrome': True}
SAFE = re.compile(r'(?i)^(?:https?:|mailto:|#)')

FIXTURE = '''<!doctype html><html><head><meta charset="utf-8"><title>fixture</title></head><body>
<h1 id="top">KAT page</h1><h2 id="peers">peers</h2>
<a href="#top">same-page anchor</a>
<a href="file://<scratch>">file url</a>
<a href="/Users/kat/derohe/artifacts/dero-src-arch.html#peers">absolute path</a>
<a href='scratchpad/r30/pdf/dero-soundness-r23.html'>scratch path</a>
<a class="x" href=dero-src-arch.html#chainobs>relative cross-page</a>
<a href="https://example.org/a">public</a> <a href="mailto:x@example.org">mail</a>
<svg width="100" height="30"><a id="sx" xlink:href="svgx.html" xmlns:xlink="http://www.w3.org/1999/xlink"><text x="5" y="20">svg xa</text></a></svg>
<div id="js"></div>
<script>var a=document.createElement("a");a.href="dero-soundness-r29.html";a.textContent="js link";
document.getElementById("js").appendChild(a);
setTimeout(function(){var N="http://www.w3.org/2000/svg",s=document.createElementNS(N,"svg");s.setAttribute("width","160");
s.setAttribute("height","20");var sa=document.createElementNS(N,"a");
sa.setAttributeNS("http://www.w3.org/1999/xlink","xlink:href","/Users/someone/jssvg.html");
var t=document.createElementNS(N,"text");t.setAttribute("y","15");t.textContent="jssvg";sa.appendChild(t);s.appendChild(sa);
var sb=document.createElementNS(N,"a");sb.setAttributeNS(null,"href","file:///Users/someone/jssvg2.html");
var t2=document.createElementNS(N,"text");t2.setAttribute("x","60");t2.setAttribute("y","15");t2.textContent="jssvg2";
sb.appendChild(t2);s.appendChild(sb);document.body.appendChild(s);},500);
setTimeout(function(){document.getElementById("sx").setAttributeNS("http://www.w3.org/1999/xlink","xlink:href",
"/Users/someone/late.html");},1200);</script>
</body></html>
'''


def P(over, key):
    return Path(over.get(key) or ROOT / PATHS[key])


def tree_with(over, tmp):
    """a temp tree <tmp>/harness/{intel,kit} + artifacts/src holding the four files (mutant where `over` says)."""
    for key, rel in PATHS.items():
        dst = Path(tmp) / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(P(over, key), dst)
    return Path(tmp)


def load(path, name):
    spec = importlib.util.spec_from_file_location(f'pp30_{name}_{abs(hash(str(path)))}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stdout(io.StringIO()):
        spec.loader.exec_module(m)
    return m


def run(cmd, timeout=120, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)


def print_copy(over, tmp, page):
    src, dst = Path(tmp) / 'page.html', Path(tmp) / 'print.html'
    src.write_text(page)
    r = run([sys.executable, '-I', str(P(over, 'pc')), str(src), str(dst)])
    if r.returncode:
        raise RuntimeError(f'print_copy rc {r.returncode}: {r.stderr[-200:]}')
    return dst


def hrefs(html):
    return [next(g for g in m.groups() if g is not None) for m in
            re.finditer(r'''<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))''', html, re.I)]


def kat_pp1(over):
    with tempfile.TemporaryDirectory(prefix='pp1-') as tmp:
        out = print_copy(over, tmp, FIXTURE).read_text()
    hs = hrefs(out)
    bad = [h for h in hs if not SAFE.match(h)]
    if len(hs) < 7:
        return False, f'print copy lost links: {hs}'
    if bad:
        return False, f'{len(bad)} non-anchor link target(s) survive the print copy: {[h[:40] for h in bad]}'
    want = {'#top', '#peers', '#chainobs', '#', 'https://example.org/a', 'mailto:x@example.org'}
    if not want <= set(hs):
        return False, f'targets {sorted(set(hs))} miss {sorted(want - set(hs))}'
    if '/Users/' in out.split('<script')[0] or 'data-print-href="dero-src-arch.html"' not in out:
        return False, 'data-print-href must keep the basename only'
    return True, f'{len(hs)} links, every one http(s)/mailto/#anchor'


def _nice15():
    """child priority: nice 15 (already niced: as is). os.nice raised under a nice-15 KAT runner (macOS EPERM past the
    ceiling), which failed PP2 as a SubprocessError."""
    with contextlib.suppress(OSError):
        os.nice(max(0, 15 - os.nice(0)))


def chrome_print(html_path, pdf_path, prof, dump=None):
    """headless Chrome print of one file (dump: --dump-dom into that file instead: the live DOM after the scripts ran,
    no beforeprint event); the process group is waited on and killed on timeout (no stray helper)."""
    out = [f'--print-to-pdf={pdf_path}'] if dump is None else ['--dump-dom']
    cmd = [CHROME, '--headless=new', '--disable-gpu', '--no-pdf-header-footer', '--virtual-time-budget=4000',
           f'--user-data-dir={prof}', *out, 'file://' + str(html_path)]
    sink = open(dump, 'wb') if dump is not None else subprocess.DEVNULL
    p = subprocess.Popen(cmd, stdout=sink, stderr=subprocess.DEVNULL, start_new_session=True,
                         preexec_fn=_nice15)
    try:
        p.wait(timeout=90)
    except subprocess.TimeoutExpired:
        pass
    finally:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(p.pid, signal.SIGKILL)
        with contextlib.suppress(Exception):
            p.wait(timeout=10)
        if dump is not None:
            sink.close()
    return Path(pdf_path if dump is None else dump).is_file()


DOM_HREF = re.compile(r'\s(?:xlink:)?href="([^"]*)"')


def kat_pp2(over):
    if not OPTS['chrome'] or not os.path.exists(CHROME):
        return True, 'skipped (no Google Chrome / --no-chrome): PP1 holds the static rule'
    with tempfile.TemporaryDirectory(prefix='pp2-') as tmp:
        ps = load(P(over, 'ps'), 'ps')
        dst = print_copy(over, tmp, FIXTURE)
        if not chrome_print(dst, Path(tmp) / 'out.pdf', Path(tmp) / 'prof'):
            return False, 'Chrome wrote no PDF'
        r = ps.scan_bytes((Path(tmp) / 'out.pdf').read_bytes())
        # the guard's observer alone (no beforeprint): every href / xlink:href of the live DOM after the scripts ran
        dom = Path(tmp) / 'dom.html'
        hs = DOM_HREF.findall(dom.read_text(errors='replace')) if chrome_print(dst, None, Path(tmp) / 'prof2', dom) else []
    if r['finding'] or r['uris'] < 2:
        return False, f"printed PDF: hits {r['hits']} local /URI {r['local_uris']} of {r['uris']}"
    loc = [h for h in hs if not SAFE.match(h)]
    if len(hs) < 10 or loc:
        return False, f'live DOM (observer only): {len(hs)} link targets, {len(loc)} local'
    return True, f"printed PDF: /URI {r['uris']} (local 0), 0 path hits; live DOM {len(hs)} targets, 0 local"


# ---- synthetic PDFs (stdlib) -------------------------------------------------------------------------------------
def pdf(objs, info=None):
    """bytes of a PDF whose numbered objects are `objs` (bytes bodies, 1-based); a valid xref table."""
    out, offs = bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n'), []
    for i, body in enumerate(objs, 1):
        offs.append(len(out))
        out += f'{i} 0 obj\n'.encode() + body + b'\nendobj\n'
    x = len(out)
    out += f'xref\n0 {len(objs) + 1}\n0000000000 65535 f \n'.encode()
    for o in offs:
        out += f'{o:010d} 00000 n \n'.encode()
    out += f'trailer\n<< /Size {len(objs) + 1} /Root 1 0 R'.encode() + (f' /Info {info} 0 R'.encode() if info else b'')
    out += f' >>\nstartxref\n{x}\n%%EOF\n'.encode()
    return bytes(out)


def stream(d, data, flate=True):
    z = zlib.compress(data) if flate else data
    return b'<< ' + d + (b' /Filter /FlateDecode' if flate else b'') + f' /Length {len(z)} >>\nstream\n'.encode() + z + b'\nendstream'


BASE = [b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >>']


def annot(uri):
    return b'<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /A << /S /URI /URI ' + uri + b' >> >>'


def utf16hex(s):
    return b'<FEFF' + s.encode('utf-16-be').hex().upper().encode() + b'>'


def dirty_pdfs():
    return {
        'uri-raw': pdf(BASE + [annot(b'(file:///Users/kat/x/dero-soundness-r29.html)')]),
        'uri-objstm': pdf(BASE + [stream(b'/Type /ObjStm /N 1 /First 4',
                                         b'5 0 ' + annot(b'(file://<scratch>)'))]),
        'info-utf16': pdf(BASE + [annot(b'(https://example.org/)'), b'<< /Title ' + utf16hex('/Users/kat/page.html') + b' >>'], info=5),
        'xmp': pdf(BASE + [annot(b'(#top)'), stream(b'/Type /Metadata /Subtype /XML',
                                                   b'<x:xmpmeta><dc:source>/private/var/folders/k/a.html</dc:source></x:xmpmeta>', flate=False)]),
        'title-octal': pdf(BASE + [annot(b'(#top)'), b'<< /Title (\\057Users\\057kat\\057page.html) >>'], info=5),
        # an absolute local target with no path class: only the /URI reader of the inflated object stream sees it
        'uri-objstm-abs': pdf(BASE + [stream(b'/Type /ObjStm /N 1 /First 4', b'5 0 ' + annot(b'(/srv/print/p.html)'))]),
        # a path in a compressed page content stream, no /URI: only the inflated / string views see it
        'content-flate': pdf(BASE + [annot(b'(#top)'), stream(b'', b'BT (/Users/kat/derohe/a.html) Tj ET')]),
    }


def raw_stream(d, data):
    """a stream whose dictionary `d` names its own filter(s) and whose body is `data` as given."""
    return b'<< ' + d + f' /Length {len(data)} >>\nstream\n'.encode() + data + b'\nendstream'


def rl_encode(x):
    """RunLengthDecode bytes of `x` (literal runs of <= 128, end-of-data 128). Pure."""
    out = bytearray()
    for i in range(0, len(x), 100):
        c = x[i:i + 100]
        out += bytes([len(c) - 1]) + c
    return bytes(out + b'\x80')


SECRET = b'BT (/Users/dave/zz) Tj ET'


def failclosed_pdfs():
    """{name: (bytes, must decode)}: must decode = the /Users path is read (a users-path hit, nothing undecoded)."""
    return {
        'flate-rawdeflate': (pdf(BASE + [raw_stream(b'/Filter /FlateDecode', zlib.compress(SECRET)[2:-4])]), False),
        'lzw': (pdf(BASE + [raw_stream(b'/Filter /LZWDecode', b'\x80\x0b\x60\x50\x22\x0c\x0c\x85\x01')]), False),
        'unknown-filter': (pdf(BASE + [raw_stream(b'/Filter /FooDecode', SECRET[::-1])]), False),
        'asciihex': (pdf(BASE + [raw_stream(b'/Filter /ASCIIHexDecode', SECRET.hex().encode() + b'>')]), True),
        'ascii85': (pdf(BASE + [raw_stream(b'/Filter /A85', base64.a85encode(SECRET) + b'~>')]), True),
        'runlength': (pdf(BASE + [raw_stream(b'/Filter /RunLengthDecode', rl_encode(SECRET))]), True),
        'chain-ahx-flate': (pdf(BASE + [raw_stream(b'/Filter [/ASCIIHexDecode /FlateDecode]',
                                                   zlib.compress(SECRET).hex().encode() + b'>')]), True),
    }


def kat_pp6(over):
    ps = load(P(over, 'ps'), 'ps')
    bad = []
    for name, (b, dec) in failclosed_pdfs().items():
        r = ps.scan_bytes(b)
        users = r['hits'].get('users-path', 0)
        if not r['finding']:
            bad.append(f'{name} not a finding')
        elif dec and (not users or r.get('undecoded') or r['inflate_failed']):
            bad.append(f"{name} not decoded (hits {r['hits']}, undecoded {r.get('undecoded')}, failed {r['inflate_failed']})")
        elif not dec and users:
            bad.append(f'{name}: the path was read, the fixture tests nothing')
    with tempfile.TemporaryDirectory(prefix='pp6-') as tmp:
        for name in ('flate-rawdeflate', 'asciihex'):
            f = Path(tmp) / f'{name}.pdf'
            f.write_bytes(failclosed_pdfs()[name][0])
            r = run([sys.executable, '-I', str(P(over, 'ps')), str(f)])
            if r.returncode != 5:
                bad.append(f'CLI {name} exit {r.returncode}, want 5')
    return not bad, '; '.join(bad) or f'{len(failclosed_pdfs())} fail-closed fixtures: undecodable = finding, AHx/A85/RL/chain decoded; CLI exit 5'


def clean_pdf():
    img = b'\x00\x01(~/abc ( \xff' * 40
    return pdf(BASE[:2] + [b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R 5 0 R 6 0 R] >>',
                           annot(b'(https://example.org/p)'), annot(b'(dero-soundness-r29.html)'), annot(b'<23746F70>'),
                           stream(b'/Type /XObject /Subtype /Image /Width 8 /Height 5', img),
                           raw_stream(b'/Type /XObject /Subtype /Image /Width 1 /Height 1 /Filter /DCTDecode',
                                      b'\xff\xd8\xff\xe0 not decoded \xff\xd9'),
                           b'<< /Producer (Skia/PDF m146) /Creator (Mozilla/5.0 HeadlessChrome/146.0.7680.80) >>'], info=9)


def kat_pp3(over):
    ps = load(P(over, 'ps'), 'ps')
    bad = []
    for name, b in dirty_pdfs().items():
        r = ps.scan_bytes(b)
        if not r['finding']:
            bad.append(f'{name} not found')
    r = ps.scan_bytes(clean_pdf())
    if r['finding']:
        bad.append(f"clean PDF flagged: {r['hits']} local /URI {r['local_uris']}")
    if r['uris'] != 3:
        bad.append(f"clean PDF: {r['uris']} /URI read, want 3")
    return not bad, '; '.join(bad) or f'{len(dirty_pdfs())} dirty PDFs found, the clean one passes'


def kat_pp4(over):
    with tempfile.TemporaryDirectory(prefix='pp4-') as tmp:
        t = tree_with(over, Path(tmp) / 't')
        pa = t / PATHS['pa']
        cap = Path(tmp) / 'cap'
        cap.mkdir()
        (cap / 'notes.txt').write_text('nothing here\n')
        (cap / 'print.pdf').write_bytes(dirty_pdfs()['uri-objstm'])
        (Path(tmp) / 'clean.pdf').write_bytes(clean_pdf())
        r1 = run([sys.executable, '-I', str(pa), '--dir', str(cap)])
        r2 = run([sys.executable, '-I', str(pa), '--pdf', str(cap / 'print.pdf')])
        r3 = run([sys.executable, '-I', str(pa), '--pdf', str(Path(tmp) / 'clean.pdf')])
    got = (r1.returncode, r2.returncode, r3.returncode)
    return got == (5, 5, 0), f'--dir dirty / --pdf dirty / --pdf clean exit {got}, want (5, 5, 0)' + (
        '' if got == (5, 5, 0) else f' {r1.stdout[-160:]!r}')


def kat_pp5(over):
    ps = load(P(over, 'ps'), 'ps')
    uris = [b'(file://<scratch>)',
            b'(vscode://file//Users/kat/derohe-Release151/p2p/chain_sync.go:123)',
            b'(file:///Users/kat/derohe-Release151/README.md)', b'(https://example.org/keep)']
    b = pdf(BASE[:2] + [b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R 5 0 R 6 0 R 7 0 R] >>']
            + [annot(u) for u in uris])
    nb, n, unfix = ps.rewrite_local_uris(b)
    bad = []
    if len(nb) != len(b):
        bad.append(f'length {len(b)} -> {len(nb)}')
    r = ps.scan_bytes(nb)
    if r['finding'] or n != 3 or unfix:
        bad.append(f"rewrote {n} (unfixable {unfix}), residual {r['hits']} local {r['local_uris']}")
    got = [re.sub(r'^(?:\./)+', '', u) for u in ps.uris_of(nb)]
    want = ['dero-soundness-r23.html#c2', '../p2p/chain_sync.go', '../README.md', 'https://example.org/keep']
    if got != want:
        bad.append(f'targets {got}, want {want}')
    if b.replace(b'/URI', b'') == nb.replace(b'/URI', b'') or nb[:200] != b[:200]:
        bad.append('object syntax outside the /URI strings changed or nothing changed')
    return not bad, '; '.join(bad) or '3 local /URI rewritten in place, same length, relative targets, 0 residual'


KATS = [('PP1', kat_pp1), ('PP2', kat_pp2), ('PP3', kat_pp3), ('PP4', kat_pp4), ('PP5', kat_pp5), ('PP6', kat_pp6)]
OWNERS = {'r30 PP1': ['PP1', 'PP2'], 'r30 PP2': ['PP2'], 'r30 PP3': ['PP3', 'PP4', 'PP6', 'PP2'], 'r30 PP4': ['PP4'],
          'r30 PP5': ['PP5'], 'r30 PP6': ['PP6']}

MUTATIONS = [   # (key, find, replace, why)
    ('pc', "    a, counts['links rewritten'] = rewrite_links(a)\n", "",
     'r30 PP1: B206 the print copy keeps every href (the pre-r30 behaviour)'),
    ('pc', "    return href[i:] if i >= 0 else '#'", "    return href",
     'r30 PP1: B206 a cross-page / file target is kept as is'),
    ('pc', "    return pre + GUARD + a, counts", "    return pre + a, counts",
     'r30 PP2: B206 links added by the page script are printed unguarded'),
    ('pc', "'var x=e.getAttributeNS(X,\"href\");if(bad(e,x)){keep(e,x);e.setAttributeNS(X,\"xlink:href\",tgt(x));}}'", "'}'",
     'r30 PP2: verify D4 an SVG xlink:href set by setAttributeNS is not rewritten'),
    ('pc', "'.observe(document.documentElement,{subtree:true,childList:true,attributes:true});});'",
     "'.observe(document.documentElement,{subtree:true,childList:true,attributes:true,attributeFilter:[\"href\"]});});'",
     'r30 PP2: verify D4 the observer filters to the plain href (a namespaced attribute is never reported)'),
    ('pc', "'function fix(){document.querySelectorAll(\"*\").forEach(one);}'",
     "'function fix(){document.querySelectorAll(\"a[href]\").forEach(one);}'",
     'r30 PP2: verify D4 only a[href] elements are read (the pre-fix selector)'),
    ('ps', "    views = {'raw': [b], 'inflated': infl, 'strings': strings_of(sk) + [s for x in texty for s in strings_of(x)]}",
     "    views = {'raw': [b], 'inflated': [], 'strings': strings_of(sk)}",
     'r30 PP3: B206 compressed (object) streams are not inflated'),
    ('ps', "    uris = uris_of(sk) + [u for x in texty for u in uris_of(x)]", "    uris = uris_of(sk)",
     'r30 PP3: B206 /URI targets inside object streams are not read'),
    ('ps', "    for m in HEX_RX.finditer(b):\n        s = hexstr(m.group(1))\n        if s:\n            out.append(text_of(s))\n",
     "", 'r30 PP3: B206 hex / UTF-16 strings (/Info /Title) are not decoded'),
    ('ps', "            elif nx and nx in b'01234567':", "            elif False:",
     'r30 PP3: B206 octal escapes in a literal are not decoded'),
    ('ps', "        chain = filters_of(d)\n        if not chain:\n            continue\n", "        continue\n",
     'r30 PP3: B206 no stream is inflated at all'),
    ('ps', "'finding': bool(hits) or loc > 0 or bad > 0 or bool(und)}", "'finding': bool(hits) or loc > 0 or bool(und)}",
     'r30 PP6: verify D1 a stream that fails to inflate is ignored (fail open)'),
    ('ps', "DECODERS = {b'FlateDecode': flate, b'ASCIIHexDecode': ascii_hex,", "DECODERS = {b'FlateDecode': flate,",
     'r30 PP6: verify D1 ASCIIHexDecode is not decoded'),
    ('ps', "            if undecoded is not None:\n                undecoded[und] = undecoded.get(und, 0) + 1\n", "",
     'r30 PP6: verify D1 a non-Flate / unknown filter is skipped silently (the pre-fix behaviour)'),
    ('ps', "    for f in chain:\n        if f in IMAGE_FILTERS:", "    for f in reversed(chain):\n        if f in IMAGE_FILTERS:",
     'r30 PP6: verify D1 a filter chain is applied out of order'),
    ('ps', "        if f in IMAGE_FILTERS:\n            return data, None\n", "",
     'r30 PP3: verify D1 an image codec is not exempt (every JPEG is a finding)'),
    ('ps', "            for name, rx in LEAK_RX + (STRING_ONLY_RX if vn == 'strings' else []):",
     "            for name, rx in LEAK_RX + STRING_ONLY_RX:", 'r30 PP3: B206 the ~/ class reads binary bytes (false positives)'),
    ('pa', "SKIP_SUFFIX = ('.go', '.png', '.jpg', '.gz', '.zst', '.bin', '.ico', '.woff', '.woff2', '.sum', '.mod')",
     "SKIP_SUFFIX = ('.go', '.png', '.jpg', '.gz', '.zst', '.bin', '.ico', '.woff', '.woff2', '.pdf', '.sum', '.mod')",
     'r30 PP4: B206 privacy_audit skips *.pdf again'),
    ('pa', "    bad = sum(1 for c, _ in cls.values() if c in ('writer', 'file', 'pdf'))",
     "    bad = sum(1 for c, _ in cls.values() if c in ('writer', 'file'))", 'r30 PP4: B206 a dirty PDF is not a finding'),
    ('ps', "    if gap % 2:                                        # one ignored backslash before an ordinary character",
     "    if False:", 'r30 PP5: B206 an odd gap is not padded (the file length changes)'),
    ('ps', "        new = '../' + re.sub(r'(:\\d+)+$', '', m.group(1))", "        new = path",
     'r30 PP5: B206 a repo link keeps its absolute path'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_r30pp', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run_kats(over):
    out = []
    for name, fn in KATS:
        try:
            ok, det = fn(over)
        except Exception as e:                                    # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        out.append((name, ok, det))
    return out


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    OPTS['chrome'] = '--no-chrome' not in argv
    over = {}
    for flag, key in (('--before-print', 'pc'), ('--before-audit', 'pa')):
        if flag in argv:
            over[key] = Path(argv[argv.index(flag) + 1])
    res = run_kats(over)
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    fails = sum(1 for _, ok, _ in res if not ok)
    if over:
        return 3 if fails else 0
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        src = P({}, key)
        text = src.read_text()
        if text.count(find) != 1:
            print(f'  INVALID  {why} — find text occurs {text.count(find)} time(s)')
            missed += 1
            continue
        d = Path(tempfile.mkdtemp(prefix='pp30-mut-'))
        mp = d / src.name
        mp.write_text(text.replace(find, repl, 1))
        try:
            failed = [n for n, ok, _ in run_kats({key: mp}) if not ok]
        finally:
            shutil.rmtree(d, ignore_errors=True)
        verdict, extra = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:9s} {why}  {failed}')
        missed += verdict != 'proved'
        coupled += bool(extra) and verdict == 'proved'
    print('\n' + K.summary('r30 privacy-pdf KATs', len(KATS) - fails if fails else len(KATS), len(MUTATIONS), missed, coupled))
    return 3 if fails else (4 if missed or coupled else 0)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
