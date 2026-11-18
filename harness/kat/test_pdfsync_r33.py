#!/usr/bin/env python3
"""test_pdfsync_r33.py — r33 (rft §0.6 row 'Artifact PDFs', §7 B335): every artifact PDF is the print of its current page.

At the R33 start all 10 artifacts/*.pdf were older than their pages and file times could not prove which page a PDF
was printed from. harness/kit/pdfsync.py keeps artifacts/pdf_manifest.json (per PDF: the page's SHA-256, the PDF's
SHA-256, the time; `required` = the pages that must have a PDF); regen_round reprints the stale ones and gates --check.

  PS1 a changed page makes its PDF STALE (html-changed); an unchanged page is in sync; --check exits 3 / 0
  PS2 a hand-edited PDF (one byte) is STALE (pdf-changed); a PDF with no manifest entry, a missing manifest and a
      required page without its PDF are STALE (no-entry, manifest-missing, no-pdf)
  PS3 the print path runs the recipe and refuses a PDF that fails pdfscan: a forged Chrome print carrying a local
      /URI is not written (the old PDF and the manifest are unchanged, exit 5); a clean one is written with neutral
      /Creator and /Producer and its entry records the page and PDF hashes
  PS4 the required set cannot shrink silently: a print of one page keeps every other required page; an entry outside
      `required` is STALE (not-required); a page required at git HEAD and gone from the list is STALE
      (dropped-silently) unless --drop recorded it with a reason; --print never invents a PDF for a page without one
  PS5 regen_round: TAIL_STEPS runs `pdfsync.py --print` after the pages are generated and before coherence, and
      gate_plan has the `pdfsync` gate (`--check`) when the tree has the tool
  PS6 print_copy.chrome_argv is the recipe: --headless=new, --no-pdf-header-footer, --virtual-time-budget=25000, a
      private --user-data-dir, --print-to-pdf, a file:// URL; --offline adds the NOTFOUND resolver rule

Pages, PDFs and manifests are forged in temporary directories; Chrome is never run (the print step is injected and
writes a forged PDF); the real print_copy.py --neutral-info and pdfscan.py run on the forged bytes.

  python3 -I harness/kat/test_pdfsync_r33.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, importlib.util, io, json, subprocess, sys, tempfile, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'ps': 'harness/kit/pdfsync.py', 'rg': 'harness/pipeline/regen_round.py', 'pc': 'artifacts/src/print_copy.py'}

CLEAN = (b'%PDF-1.4\n1 0 obj\n<</Type /Catalog /Pages 2 0 R>>\nendobj\n2 0 obj\n<</Type /Pages /Kids [] /Count 0>>\n'
         b'endobj\n3 0 obj\n<</Creator (Mozilla/5.0 HeadlessChrome/999.0.0.0 Safari/537.36)\n/Producer (Skia/PDF m999)>>\n'
         b'endobj\ntrailer\n<</Root 1 0 R /Info 3 0 R>>\n%%EOF\n')
XMP = CLEAN.replace(b'trailer', b'4 0 obj\n<</Type /Metadata /Subtype /XML>>\nstream\n<x:xmpmeta><xmp:CreatorTool>'
                    b'HeadlessChrome 999.0.0.0</xmp:CreatorTool></x:xmpmeta>\nendstream\nendobj\ntrailer')
LEAK = CLEAN.replace(b'<</Type /Pages', b'<</A <</S /URI /URI (file:///Users/someone/scratchpad/x.html)>> /Type /Pages')


def load(over, key):
    path = Path(over.get(key) or (ROOT / PATHS[key]))
    spec = importlib.util.spec_from_file_location(f'ps33_{key}_{uuid.uuid4().hex[:6]}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    if key == 'ps':
        m.TOOLS = ROOT                       # the recipe's tools of this tree, even for a mutant copy elsewhere
    return m


def forge(d, pages=('a', 'b'), pdf=True):
    r = Path(d) / 'tree'
    (r / 'artifacts').mkdir(parents=True, exist_ok=True)
    for p in pages:
        (r / f'artifacts/{p}.html').write_text(f'<html><body><h1>{p}</h1><a href="other.html#x">x</a></body></html>')
        if pdf:
            (r / f'artifacts/{p}.pdf').write_bytes(b'%PDF-old ' + p.encode())
    (r / 'artifacts/nopdf.html').write_text('<html>no pdf</html>')
    return r


def chrome(data):
    calls = []

    def f(cp, out, profile, offline=False):
        calls.append(Path(cp).read_text())
        Path(out).write_bytes(data)
        return 0
    f.calls = calls
    return f


def quiet(fn, *a, **k):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*a, **k)


def kat_ps1(over):
    m = load(over, 'ps')
    bad = []
    with tempfile.TemporaryDirectory() as d:
        r = forge(d)
        rc = m.do_print(r, ['a', 'b'], chrome_fn=chrome(CLEAN), log=lambda *a: None, floor=[])
        if rc != 0 or m.status(r, floor=[]) != []:
            bad.append(f'after the print: rc {rc} status {m.status(r, floor=[])}')
        m.ROOT = r
        if quiet(m.main, ['--check']) != 0:
            bad.append('--check of an in-sync tree is not 0')
        (r / 'artifacts/a.html').write_text('<html><body><h1>a, changed</h1></body></html>')
        st = m.status(r, floor=[])
        if st != [('a', 'html-changed')]:
            bad.append(f'changed page: {st}')
        if quiet(m.main, ['--check']) != 3:
            bad.append('--check of a stale tree is not 3')
        if 'nopdf' in str(st) or 'nopdf' in json.dumps(json.loads((r / m.MANIFEST).read_text())):
            bad.append('a page without a PDF entered the manifest')
    return not bad, '; '.join(bad) or 'html-changed; --check 3/0'


def kat_ps2(over):
    m = load(over, 'ps')
    bad = []
    with tempfile.TemporaryDirectory() as d:
        r = forge(d)
        if m.status(r, floor=[])[:1] != [('*', 'manifest-missing')]:
            bad.append(f'no manifest: {m.status(r, floor=[])}')
        m.do_print(r, ['a', 'b'], chrome_fn=chrome(CLEAN), log=lambda *a: None, floor=[])
        (r / 'artifacts/new.html').write_text('<html>new</html>')
        (r / 'artifacts/new.pdf').write_bytes(b'%PDF-new')
        if m.status(r, floor=[]) != [('new', 'no-entry')]:
            bad.append(f'a PDF outside the manifest: {m.status(r, floor=[])}')
        (r / 'artifacts/new.pdf').unlink()
        b = bytearray((r / 'artifacts/b.pdf').read_bytes())
        b[-3] ^= 1
        (r / 'artifacts/b.pdf').write_bytes(bytes(b))
        if m.status(r, floor=[]) != [('b', 'pdf-changed')]:
            bad.append(f'hand-edited PDF: {m.status(r, floor=[])}')
        man = json.loads((r / m.MANIFEST).read_text())
        man['pdfs'].pop('a')
        (r / m.MANIFEST).write_text(json.dumps(man))
        st = dict(m.status(r, floor=[]))
        if st.get('a') != 'no-entry':
            bad.append(f'missing entry: {st}')
        (r / 'artifacts/a.pdf').unlink()
        if dict(m.status(r, floor=[])).get('a') != 'no-pdf':
            bad.append(f'missing PDF: {m.status(r, floor=[])}')
        (r / m.MANIFEST).write_text('{not json')
        if m.status(r, floor=[])[:1] != [('*', 'manifest-unreadable')]:
            bad.append('unreadable manifest')
    return not bad, '; '.join(bad) or 'pdf-changed, no-entry, no-pdf, manifest-missing/unreadable'


def kat_ps3(over):
    m = load(over, 'ps')
    bad = []
    with tempfile.TemporaryDirectory() as d:
        r = forge(d, pages=('a',))
        old = (r / 'artifacts/a.pdf').read_bytes()
        logs = []
        rc = m.do_print(r, ['a'], chrome_fn=chrome(LEAK), log=logs.append, floor=[])
        if rc != 5:
            bad.append(f'leaky print exit {rc} (want 5)')
        if (r / 'artifacts/a.pdf').read_bytes() != old:
            bad.append('a PDF failing pdfscan was written')
        if (r / m.MANIFEST).exists() and 'a' in json.loads((r / m.MANIFEST).read_text()).get('pdfs', {}):
            bad.append('a PDF failing pdfscan entered the manifest')
        if not any('pdfscan exit 5' in x for x in logs):
            bad.append(f'the refusal does not name pdfscan: {logs[:1]}')
        if [p.name for p in (r / 'artifacts').iterdir() if 'pdfsync' in p.name]:
            bad.append('a temp print was left in artifacts/')
        logs = []
        if m.do_print(r, ['a'], chrome_fn=chrome(XMP), log=logs.append, floor=[]) != 5 or (r / 'artifacts/a.pdf').read_bytes() != old:
            bad.append('a PDF whose XMP keeps a browser token was written')
        if not any('neutral-info exit 5' in x for x in logs):
            bad.append(f'the refusal does not name neutral-info: {logs[:1]}')
        ch = chrome(CLEAN)
        rc = m.do_print(r, ['a'], chrome_fn=ch, log=lambda *a: None, floor=[])
        got = (r / 'artifacts/a.pdf').read_bytes()
        if rc != 0:
            bad.append(f'clean print: exit {rc} (want 0)')
        if b'HeadlessChrome' in got or b'Skia' in got or b'(DERO HE ledger print)' not in got or len(got) != len(CLEAN):
            bad.append('the written PDF did not pass neutral-info')
        if not ch.calls or 'pdf-link-guard' not in ch.calls[0] or 'href="#x"' not in ch.calls[0]:
            bad.append('Chrome was not given the print copy')
        e = json.loads((r / m.MANIFEST).read_text())['pdfs'].get('a', {})
        if e.get('html_sha256') != m.sha256(r / 'artifacts/a.html') or e.get('pdf_sha256') != m.sha256(r / 'artifacts/a.pdf'):
            bad.append(f'entry hashes {e}')
        if not e.get('printed_at') or str(r) in json.dumps(e) or '/' in e.get('html', '/') + e.get('pdf', '/'):
            bad.append('entry has no time or carries a path')
    return not bad, '; '.join(bad) or 'leaky print refused (5); clean print neutral + hashed'


def kat_ps4(over):
    m = load(over, 'ps')
    bad = []
    with tempfile.TemporaryDirectory() as d:
        r = forge(d, pages=('a', 'b', 'c'))
        m.do_print(r, ['a', 'b', 'c'], chrome_fn=chrome(CLEAN), log=lambda *a: None, floor=[])
        (r / 'artifacts/a.html').write_text('<html>a2</html>')
        m.do_print(r, ['a'], chrome_fn=chrome(CLEAN), log=lambda *a: None, floor=[])
        man = json.loads((r / m.MANIFEST).read_text())
        if man['required'] != ['a', 'b', 'c'] or set(man['pdfs']) != {'a', 'b', 'c'}:
            bad.append(f"a one-page print changed the set: {man['required']}")
        man['required'] = ['a', 'b']
        (r / m.MANIFEST).write_text(json.dumps(man))
        if dict(m.status(r, floor=[])).get('c') != 'not-required':
            bad.append(f'entry outside required: {m.status(r, floor=[])}')
        man['pdfs'].pop('c')
        (r / m.MANIFEST).write_text(json.dumps(man))
        (r / 'artifacts/c.pdf').unlink()
        if dict(m.status(r, floor=['a', 'b', 'c'])).get('c') != 'dropped-silently':
            bad.append(f'silent shrink vs HEAD: {m.status(r, floor=["a", "b", "c"])}')
        man['required'] = ['a', 'b', 'c']
        (r / m.MANIFEST).write_text(json.dumps(man))
        if quiet(m.do_drop, r, 'c', None) != 2:
            bad.append('--drop without a reason was accepted')
        if quiet(m.do_drop, r, 'c', 'page retired') != 0 or m.status(r, floor=['a', 'b', 'c']) != []:
            bad.append(f'a recorded drop is still STALE: {m.status(r, floor=["a", "b", "c"])}')
        if quiet(m.do_print, r, ['nopdf'], chrome_fn=chrome(CLEAN), floor=[]) != 2 or (r / 'artifacts/nopdf.pdf').exists():
            bad.append('--print invented a PDF for a page without one')
        # head_required reads the manifest committed at HEAD of the tree's own git work tree
        g = lambda *a: subprocess.run(['git', '-C', str(r), *a], capture_output=True, text=True)
        g('init', '-q')
        g('add', 'artifacts/pdf_manifest.json')
        g('-c', 'user.name=k', '-c', 'user.email=k@example.org', 'commit', '-qm', 'm')
        if m.head_required(r) != ['a', 'b']:
            bad.append(f'head_required {m.head_required(r)}')
        if m.head_required(r / 'artifacts') is not None:
            bad.append('head_required read a parent work tree')
    return not bad, '; '.join(bad) or 'set kept; not-required; dropped-silently; --drop recorded; nothing invented'


def kat_ps5(over):
    R = load(over, 'rg')
    bad = []
    names = [' '.join(s) for s in R.TAIL_STEPS]
    i = names.index('harness/kit/pdfsync.py --print') if 'harness/kit/pdfsync.py --print' in names else None
    if i is None or not (names.index('harness/gen_index.py') < i < names.index('harness/intel/coherence.py --record')):
        bad.append(f'pdfsync --print step not between gen_index and coherence: {names}')
    if i is not None and i < names.index('harness/kit/soundpage.py --check-measured'):
        bad.append('pdfsync prints before the last page write')
    g = {x[0]: x for x in R.gate_plan(ROOT, Path('/nonexistent/pubscrub.py'), '/tmp/x')}
    a = ' '.join(str(v) for v in (g.get('pdfsync', (0, None))[1] or []))
    if 'harness/kit/pdfsync.py --check' not in a:
        bad.append(f'no pdfsync --check gate: {a or list(g)}')
    with tempfile.TemporaryDirectory() as d:
        if 'pdfsync' in [x[0] for x in R.gate_plan(Path(d), Path('/nonexistent/p.py'), '/tmp/x')]:
            bad.append('the pdfsync gate is planned for a tree without the tool')
    return not bad, '; '.join(bad) or 'step before coherence; gate --check'


def kat_ps6(over):
    pc = load(over, 'pc')
    bad = []
    a = pc.chrome_argv('/t/p.print.html', '/t/o.pdf', '/t/prof', chrome='CH')
    for want in ('CH', '--headless=new', '--no-pdf-header-footer', '--virtual-time-budget=25000', '--user-data-dir=/t/prof',
                 '--print-to-pdf=/t/o.pdf', 'file:///t/p.print.html'):
        if want not in a:
            bad.append(f'missing {want}')
    if a[0] != 'CH' or a[-1] != 'file:///t/p.print.html' or any('NOTFOUND' in x for x in a):
        bad.append(f'argv order/offline {a}')
    if not any('MAP * ~NOTFOUND' in x for x in pc.chrome_argv('p', 'o', 'f', offline=True)):
        bad.append('--offline does not block host resolution')
    return not bad, '; '.join(bad) or 'recipe flags; private profile; offline rule'


KATS = [('PS1', kat_ps1), ('PS2', kat_ps2), ('PS3', kat_ps3), ('PS4', kat_ps4), ('PS5', kat_ps5), ('PS6', kat_ps6)]
OWNERS = {'B335 html': ['PS1'], 'B335 pdf': ['PS2'], 'B335 entry': ['PS2', 'PS4'], 'B335 scan': ['PS3'],
          'B335 shrink': ['PS4'], 'B335 regen': ['PS5'], 'B335 recipe': ['PS6', 'PS3']}
MUTATIONS = [   # (file key, find, replace, why — the first two words name the defect, see OWNERS)
    ('ps', "        elif sha256(html) != e.get('html_sha256'):\n            out.append((s, 'html-changed'))\n", "",
     'B335 html: a changed page leaves its PDF in sync'),
    ('ps', "        return STALE if st else 0", "        return 0", 'B335 html: --check exits 0 on a stale tree'),
    ('ps', "        elif sha256(pdf) != e.get('pdf_sha256'):\n            out.append((s, 'pdf-changed'))\n", "",
     'B335 pdf: a hand-edited PDF is not detected'),
    ('ps', "        elif not isinstance(e, dict):\n            out.append((s, 'no-entry'))\n", "        elif not isinstance(e, dict):\n            pass\n",
     'B335 entry: a PDF without its manifest entry is in sync'),
    ('ps', "        elif not pdf.is_file():\n            out.append((s, 'no-pdf'))\n", "        elif not pdf.is_file():\n            continue\n",
     'B335 pdf: a required page without its PDF is in sync'),
    ('ps', "    for s in sorted(req | set(on_disk(root))):", "    for s in sorted(req):",
     'B335 entry: a PDF outside the manifest is never read'),
    ('ps', "        if src != 0:\n            return None, f'pdfscan exit {src}: {stail}'\n", "",
     'B335 scan: a PDF failing pdfscan is written'),
    ('ps', "        if nrc != 0:\n            return None, f'neutral-info exit {nrc}: {ntail}'\n", "",
     'B335 scan: a PDF with a browser fingerprint is written'),
    ('ps', "        nrc, ntail = _tool(PRINT_COPY, '--neutral-info', out)", "        nrc, ntail = 0, ''",
     'B335 scan: neutral-info is skipped'),
    ('ps', "    return FAIL if failed else STALE if left else 0", "    return STALE if left else 0",
     'B335 scan: a failed print exits like a stale one'),
    ('ps', "        man['required'] = sorted(set(man['required']) | {s})      # never shrinks here",
     "        man['required'] = sorted(set(want))", 'B335 shrink: a one-page print cuts the required set'),
    ('ps', "    for s in sorted(set(floor) - req - dropped):\n        out.append((s, 'dropped-silently'))\n", "",
     'B335 shrink: a page cut from required vs HEAD is not detected'),
    ('ps', "    for s in sorted(set(ent) - req):\n        out.append((s, 'not-required'))\n", "",
     'B335 shrink: an entry outside required is not detected'),
    ('ps', "        if new:\n            log(", "        if False:\n            log(", 'B335 shrink: --print invents a PDF for a page without one'),
    ('ps', "    if not reason:\n        log(", "    if False:\n        log(", 'B335 shrink: --drop without a reason'),
    ('ps', "        if top.returncode or Path(top.stdout.strip()).resolve() != root:", "        if top.returncode:",
     'B335 shrink: HEAD read from a parent work tree'),
    ('ps', "        text, counts = pc.make_print_copy(html.read_text(encoding='utf-8'))",
     "        text, counts = html.read_text(encoding='utf-8'), {}", 'B335 recipe: Chrome prints the page, not the print copy'),
    ('rg', "            ['harness/kit/pdfsync.py', '--print'],", "", 'B335 regen: regen_round does not reprint stale PDFs'),
    ('rg', "        g.append(('pdfsync', [PY, '-I', PDFSYNC, '--check'], None, {}))", "        pass",
     'B335 regen: no pdfsync --check gate'),
    ('pc', "RECIPE_FLAGS = ('--headless=new', '--no-pdf-header-footer', '--virtual-time-budget=25000')",
     "RECIPE_FLAGS = ('--headless=new', '--virtual-time-budget=25000')", 'B335 recipe: the PDF carries a header and footer'),
    ('pc', "OFFLINE_FLAGS = ('--host-resolver-rules=MAP * ~NOTFOUND', ", "OFFLINE_FLAGS = (", 'B335 recipe: --offline still resolves hosts'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_ps33', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def defect(why):
    return ' '.join(why.split(':')[0].split()[:2])


def run_kats(over):
    res = []
    for name, fn in KATS:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                ok, det = fn(over)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        res.append((name, bool(ok), str(det)))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr33 pdfsync KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='ps33-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            try:
                compile(mut.read_text(encoding='utf-8'), str(mut), 'exec')
            except SyntaxError as e:
                print(f'  INVALID   {why}: mutant does not load ({e})')
                missed += 1
                continue
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(defect(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r33 pdfsync KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
