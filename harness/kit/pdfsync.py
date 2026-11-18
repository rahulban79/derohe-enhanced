#!/usr/bin/env python3
"""pdfsync.py — r33 (rft §0.6 row 'Artifact PDFs', §7 B335): every artifacts/X.pdf is the print of the CURRENT X.html.

File times cannot prove that a PDF was printed from the page beside it (at the R33 start all 10 PDFs were older than
their pages; dero-enhanced-game-theory.pdf predated the page's redesign). artifacts/pdf_manifest.json records, per
PDF, the SHA-256 of the HTML it was printed from, the SHA-256 and size of the PDF written, and the UTC time; its
`required` list is the set of pages that must have a PDF (bootstrapped once from the PDFs on disk: this tool never
invents a PDF for a page that had none).

  python3 -I harness/kit/pdfsync.py --check            # exit 0 every required PDF in sync · 3 STALE (listed)
  python3 -I harness/kit/pdfsync.py --print [PAGE...]  # reprint the stale PDFs, or the named ones, then the manifest
  python3 -I harness/kit/pdfsync.py --list             # page, state, html/pdf hash, size, printed_at
  python3 -I harness/kit/pdfsync.py --drop PAGE --reason TEXT   # the only way a page leaves `required` (recorded)
  options: --offline (Chrome resolves no host: CDN diagrams and web fonts are then absent) · --chrome PATH

STALE reasons: html-changed (the page's SHA-256 is not the one the PDF was printed from) · pdf-changed (the PDF's
bytes are not the ones the manifest recorded: a hand edit or another print) · no-entry (a PDF with its page and no
manifest entry, or a required page without one) · no-pdf (a required page whose PDF is missing) · html-missing (a
required page whose HTML is gone: --drop it or restore it) · not-required (an entry outside `required`: the list was
cut by hand) · dropped-silently (a page `required` at git HEAD is neither required now nor recorded in `dropped`) ·
manifest-missing / manifest-unreadable.

The print is the recipe of artifacts/src/print_copy.py, step by step, per page, in a private temp dir:
  1. the print copy (print_copy.make_print_copy, the same function as `print_copy.py PAGE PRINT`)
  2. headless Chrome --print-to-pdf (print_copy.chrome_argv: the recipe flags, a throw-away --user-data-dir)
  3. python3 -I artifacts/src/print_copy.py --neutral-info OUT.pdf   (exit 0 required)
  4. python3 -I harness/kit/pdfscan.py OUT.pdf                       (exit 0 required)
  5. the page is re-hashed (it must not have changed during the print)
Only then is the PDF moved into artifacts/ (atomic replace) and its manifest entry written; any failed step leaves the
old PDF and the manifest untouched and the run exits 5. The manifest holds basenames only (no directory, no host).
No network by the tool itself (Chrome loads only what the page declares; --offline blocks that too), never the node.
Exit 0 in sync · 3 STALE · 5 a print failed (Chrome, neutral-info or pdfscan) · 2 bad invocation.
KAT harness/kat/test_pdfsync_r33.py (PS1-PS6, mutations).
"""
import datetime, hashlib, importlib.util, json, os, re, shutil, signal, subprocess, sys, tempfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent.parent      # the tree whose print_copy / pdfscan run the recipe
ROOT = TOOLS
ART = 'artifacts'
MANIFEST = 'artifacts/pdf_manifest.json'
PRINT_COPY = 'artifacts/src/print_copy.py'
PDFSCAN = 'harness/kit/pdfscan.py'
PY = sys.executable
STALE, FAIL, BAD = 3, 5, 2
CHROME_TIMEOUT = 900
SCHEMA = 1
RECIPE = ('print_copy.make_print_copy -> Chrome --headless=new --no-pdf-header-footer --virtual-time-budget=25000 '
          '--print-to-pdf -> print_copy.py --neutral-info -> pdfscan.py exit 0')
UNPRINTABLE = ('html-missing',)


# ───────────────────────────── reading ─────────────────────────────
def sha256(p):
    """hex SHA-256 of a file, None when it cannot be read."""
    try:
        h = hashlib.sha256()
        with open(p, 'rb') as f:
            for blk in iter(lambda: f.read(1 << 20), b''):
                h.update(blk)
        return h.hexdigest()
    except OSError:
        return None


def stem_of(name):
    """'dero-r1-r21' of 'dero-r1-r21', '…/dero-r1-r21.html' or 'dero-r1-r21.pdf'. Pure."""
    b = re.split(r'[\\/]', str(name))[-1]
    return re.sub(r'\.(html|pdf)$', '', b)


def on_disk(root):
    """the stems with BOTH artifacts/X.pdf and artifacts/X.html (dotfiles, i.e. temp prints, excluded)."""
    a = Path(root) / ART
    return sorted(p.stem for p in a.glob('*.pdf') if not p.name.startswith('.') and (a / f'{p.stem}.html').is_file())


def load_manifest(root):
    """(manifest | None, problem | None): None + 'manifest-missing' when absent, + 'manifest-unreadable' when bad."""
    p = Path(root) / MANIFEST
    try:
        m = json.loads(p.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return None, 'manifest-missing'
    except (OSError, ValueError):
        return None, 'manifest-unreadable'
    if not isinstance(m, dict) or not isinstance(m.get('pdfs'), dict) or not isinstance(m.get('required'), list):
        return None, 'manifest-unreadable'
    return m, None


def head_required(root):
    """the `required` list of the manifest committed at git HEAD of `root` (None when `root` is not the top of a git
    work tree or HEAD has no manifest). Read-only git."""
    root = Path(root).resolve()
    try:
        top = subprocess.run(['git', '-C', str(root), 'rev-parse', '--show-toplevel'], capture_output=True, text=True,
                             timeout=30)
        if top.returncode or Path(top.stdout.strip()).resolve() != root:
            return None
        r = subprocess.run(['git', '-C', str(root), 'show', f'HEAD:{MANIFEST}'], capture_output=True, text=True, timeout=30)
        if r.returncode:
            return None
        req = json.loads(r.stdout).get('required')
        return [str(x) for x in req] if isinstance(req, list) else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def status(root, man=None, problem=None, floor=None):
    """[(stem, reason)] of every STALE PDF of `root`, sorted; [] = in sync. `man`/`problem` default to the manifest on
    disk, `floor` (the required list that may not shrink silently) to git HEAD's."""
    root = Path(root)
    if man is None and problem is None:
        man, problem = load_manifest(root)
    if floor is None:
        floor = head_required(root) or []
    a = root / ART
    out = []
    if man is None:
        out.append(('*', problem or 'manifest-missing'))
        man = {'required': [], 'pdfs': {}, 'dropped': {}}
    req, ent, dropped = set(man['required']), man['pdfs'], set((man.get('dropped') or {}).keys())
    for s in sorted(set(floor) - req - dropped):
        out.append((s, 'dropped-silently'))
    for s in sorted(set(ent) - req):
        out.append((s, 'not-required'))
    for s in sorted(req | set(on_disk(root))):
        html, pdf, e = a / f'{s}.html', a / f'{s}.pdf', ent.get(s)
        if not html.is_file():
            out.append((s, 'html-missing'))
        elif not pdf.is_file():
            out.append((s, 'no-pdf'))
        elif not isinstance(e, dict):
            out.append((s, 'no-entry'))
        elif sha256(html) != e.get('html_sha256'):
            out.append((s, 'html-changed'))
        elif sha256(pdf) != e.get('pdf_sha256'):
            out.append((s, 'pdf-changed'))
    return out


# ───────────────────────────── printing ─────────────────────────────
def _load(rel, name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _nice15():
    try:
        os.nice(max(0, 15 - os.nice(0)))
    except OSError:
        pass


def chrome_print(print_html, out_pdf, profile, chrome=None, offline=False):
    """run the recipe's headless Chrome on one print copy; the process group is killed after it exits or times out
    (no stray helper). Returns Chrome's exit code (None on timeout)."""
    pc = _load(PRINT_COPY, 'pdfsync_print_copy')
    argv = pc.chrome_argv(print_html, out_pdf, profile, chrome=chrome or pc.CHROME, offline=offline)
    p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                         preexec_fn=_nice15)
    rc = None
    try:
        rc = p.wait(timeout=CHROME_TIMEOUT)
    except subprocess.TimeoutExpired:
        pass
    finally:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
    return rc


def _tool(rel, *args):
    r = subprocess.run([PY, '-I', str(TOOLS / rel), *map(str, args)], capture_output=True, text=True)
    return r.returncode, ((r.stdout + r.stderr).strip().splitlines() or [''])[-1][:200]


def print_one(root, stem, chrome_fn=None, scratch=None, offline=False, log=print):
    """print artifacts/<stem>.pdf from artifacts/<stem>.html by the recipe; (entry | None, detail). The PDF in
    artifacts/ is replaced only when every step passed."""
    root = Path(root)
    html, pdf = root / ART / f'{stem}.html', root / ART / f'{stem}.pdf'
    h0 = sha256(html)
    if h0 is None:
        return None, 'html-missing'
    pc = _load(PRINT_COPY, 'pdfsync_print_copy')
    tmp = Path(tempfile.mkdtemp(prefix='pdfsync-', dir=scratch or os.environ.get('PDFSYNC_SCRATCH') or None))
    try:
        cp = tmp / f'{stem}.print.html'
        out = tmp / f'{stem}.pdf'
        text, counts = pc.make_print_copy(html.read_text(encoding='utf-8'))
        cp.write_text(text, encoding='utf-8')
        (tmp / 'profile').mkdir()
        rc = (chrome_fn or chrome_print)(cp, out, tmp / 'profile', offline=offline)
        if not out.is_file() or out.read_bytes()[:5] != b'%PDF-':
            return None, f'chrome wrote no PDF (rc {rc})'
        nrc, ntail = _tool(PRINT_COPY, '--neutral-info', out)
        if nrc != 0:
            return None, f'neutral-info exit {nrc}: {ntail}'
        src, stail = _tool(PDFSCAN, out)
        if src != 0:
            return None, f'pdfscan exit {src}: {stail}'
        if sha256(html) != h0:
            return None, 'the page changed during the print'
        part = root / ART / f'.{stem}.pdfsync-tmp.pdf'
        shutil.copyfile(out, part)
        os.replace(part, pdf)
        entry = {'html': html.name, 'html_sha256': h0, 'html_bytes': html.stat().st_size, 'pdf': pdf.name,
                 'pdf_sha256': sha256(pdf), 'pdf_bytes': pdf.stat().st_size,
                 'printed_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                 'offline': bool(offline), 'links_rewritten': counts.get('links rewritten', 0), 'recipe': RECIPE}
        return entry, f'{entry["pdf_bytes"]} bytes, pdfscan 0'
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def write_manifest(root, man):
    """atomic, deterministic (sorted keys, one trailing newline)."""
    p = Path(root) / MANIFEST
    t = p.with_name(p.name + '.tmp')
    t.write_text(json.dumps(man, indent=1, sort_keys=True, ensure_ascii=False) + '\n', encoding='utf-8')
    os.replace(t, p)


def base_manifest(root):
    """the manifest to update: the one on disk, else the bootstrap (`required` = the PDFs on disk with their page)."""
    man, _ = load_manifest(root)
    if man is None:
        man = {'schema': SCHEMA, 'rule': 'every required page has a PDF printed from its current HTML (rft §0.6)',
               'required': on_disk(root), 'pdfs': {}, 'dropped': {}}
    man.setdefault('dropped', {})
    return man


def do_print(root, pages=None, chrome_fn=None, scratch=None, offline=False, log=print, floor=None):
    """reprint `pages` (stems) or every printable STALE one; exit code (0 | 3 | 5 | 2)."""
    root = Path(root)
    man = base_manifest(root)
    req = set(man['required'])
    if pages:
        want = [stem_of(p) for p in pages]
        new = [s for s in want if s not in req and s not in on_disk(root)]
        if new:
            log(f'pdfsync: refused {new}: not a required page and no PDF on disk (this tool never invents a PDF)')
            return BAD
    else:
        want = sorted({s for s, r in status(root, man, None, floor) if s != '*' and r not in UNPRINTABLE
                       and r != 'dropped-silently'})
    failed = 0
    for s in want:
        entry, det = print_one(root, s, chrome_fn=chrome_fn, scratch=scratch, offline=offline, log=log)
        log(f"[pdfsync] {'OK  ' if entry else 'FAIL'} {s}.pdf: {det}")
        if entry is None:
            failed += 1
            continue
        man['pdfs'][s] = entry
        man['required'] = sorted(set(man['required']) | {s})      # never shrinks here
        write_manifest(root, man)
    if not want and not (Path(root) / MANIFEST).is_file() and man['required']:
        write_manifest(root, man)
    left = status(root, None, None, floor)
    for s, r in left:
        log(f'[pdfsync] STALE {s}: {r}')
    log(f'pdfsync --print: {len(want) - failed}/{len(want)} printed, {failed} failed, {len(left)} STALE')
    return FAIL if failed else STALE if left else 0


def do_drop(root, page, reason, log=print):
    if not reason:
        log('pdfsync --drop needs --reason TEXT (a page leaves `required` only on the record)')
        return BAD
    man = base_manifest(root)
    s = stem_of(page)
    if s not in man['required']:
        log(f'pdfsync --drop: {s} is not required')
        return BAD
    man['required'] = [x for x in man['required'] if x != s]
    man['pdfs'].pop(s, None)
    man['dropped'][s] = {'reason': reason,
                         'at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
    write_manifest(root, man)
    log(f'pdfsync: {s} dropped from required ({reason})')
    return 0


def do_list(root, log=print):
    man, problem = load_manifest(root)
    st = dict((s, r) for s, r in status(root, man, problem))
    ent = (man or {}).get('pdfs', {})
    for s in sorted(set((man or {}).get('required', [])) | set(on_disk(root)) | set(ent)):
        e = ent.get(s) or {}
        log(f"{s:<34} {st.get(s, 'in-sync'):<16} html {str(e.get('html_sha256'))[:12]:<12} pdf "
            f"{str(e.get('pdf_sha256'))[:12]:<12} {e.get('pdf_bytes', '-'):>10} {e.get('printed_at', '-')}")
    if '*' in st:
        log(f"manifest: {st['*']}")
    return 0


def main(argv):
    if not argv or {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0 if argv else BAD
    args, opts = [], {'offline': False, 'chrome': None, 'reason': None}
    it = iter(argv)
    for a in it:
        if a == '--offline':
            opts['offline'] = True
        elif a in ('--chrome', '--reason'):
            opts[a[2:]] = next(it, None)
        else:
            args.append(a)
    cmd, rest = args[0], args[1:]
    if cmd == '--check' and not rest:
        st = status(ROOT)
        for s, r in st:
            print(f'STALE {s}: {r}')
        man, _ = load_manifest(ROOT)
        n = len((man or {}).get('required', []))
        print(f'pdfsync --check: {n} required PDF(s), {len(st)} STALE' + (' · run pdfsync.py --print' if st else ' · all in sync'))
        return STALE if st else 0
    if cmd == '--print':
        cf = None
        if opts['chrome']:
            cf = lambda c, o, p, offline=False: chrome_print(c, o, p, chrome=opts['chrome'], offline=offline)
        return do_print(ROOT, rest, chrome_fn=cf, offline=opts['offline'])
    if cmd == '--list' and not rest:
        return do_list(ROOT)
    if cmd == '--drop' and len(rest) == 1:
        return do_drop(ROOT, rest[0], opts['reason'])
    print(f'pdfsync: bad invocation {argv} (see --help)')
    return BAD


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
