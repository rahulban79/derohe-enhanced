#!/usr/bin/env python3
"""test_print_copy_r31.py — r31 (rft §7 B279): the ledger PDF carries a neutral /Creator and /Producer.

Headless Chrome writes /Creator as its user agent (OS and browser version, a '<N>.0.0.0' token the public sync's byte
IP scan read as an address) and /Producer as the Skia version: a mild fingerprint in both published PDFs.
artifacts/src/print_copy.py --neutral-info replaces both, byte length kept.

  PC1 neutral_info on a forged Chrome-style PDF: the same byte length; every xref offset and startxref still point at
      their object / 'xref'; /Creator reads 'DERO HE ledger print' and /Producer 'PDF', each padded with spaces; no
      byte outside the two values changes; a second pass changes nothing
  PC2 the string forms: a literal with escaped and unbalanced parens '\\)' and a hex UTF-16BE value are both replaced;
      info_fingerprint names browser/OS/engine classes before and none after
  PC3 the command: --neutral-info rewrites the file in place, exit 0; a token in an uncompressed XMP packet (not
      rewritten) exits 5; a missing file exits 2

The PDFs are forged in temporary directories (byte-level, version strings synthetic); no committed PDF is read or written.

  python3 -I harness/kat/test_print_copy_r31.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, importlib.util, io, re, sys, tempfile, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'pc': 'artifacts/src/print_copy.py'}
UA = b'(Mozilla/5.0 \\(Macintosh; Intel Mac OS X 10_15_7\\) AppleWebKit/537.36 \\(KHTML, like Gecko\\) HeadlessChrome/999.0.0.0 Safari/537.36 x\\) y)'


def load(over):
    path = Path(over.get('pc') or (ROOT / PATHS['pc']))
    spec = importlib.util.spec_from_file_location(f'pc31_{uuid.uuid4().hex[:6]}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def forge(creator=UA, producer=b'(Skia/PDF m999)', xmp=b''):
    objs = [b'<</Type /Catalog /Pages 2 0 R>>', b'<</Type /Pages /Kids [] /Count 0>>',
            b'<</Creator ' + creator + b'\n/Producer ' + producer + b"\n/CreationDate (D:20261112091200+00'00')>>"]
    if xmp:
        objs.append(b'<</Type /Metadata /Subtype /XML /Length ' + str(len(xmp)).encode() + b'>>\nstream\n' + xmp + b'\nendstream')
    out, offs = bytearray(b'%PDF-1.4\n'), []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += f'{i} 0 obj\n'.encode() + o + b'\nendobj\n'
    x = len(out)
    out += f'xref\n0 {len(objs) + 1}\n0000000000 65535 f \n'.encode() + b''.join(f'{o:010d} 00000 n \n'.encode() for o in offs)
    out += f'trailer\n<</Size {len(objs) + 1} /Root 1 0 R /Info 3 0 R>>\nstartxref\n{x}\n%%EOF\n'.encode()
    return bytes(out)


def xref_ok(b):
    x = int(re.search(rb'startxref\s+(\d+)', b).group(1))
    if b[x:x + 4] != b'xref':
        return False
    offs = [int(m.group(1)) for m in re.finditer(rb'(\d{10}) 00000 n', b)]
    return all(re.match(rb'%d 0 obj' % (i + 1), b[o:]) for i, o in enumerate(offs))


def info(b, key):
    m = re.search(re.escape(key) + rb'\s*(\((?:[^()\\]|\\.)*\)|<[0-9A-Fa-f\s]*>)( *)', b)
    return (m.group(1), len(m.group(2))) if m else (None, 0)


def kat_pc1(over):
    m = load(over)
    b = forge()
    nb, n = m.neutral_info(b)
    bad = []
    if len(nb) != len(b) or not xref_ok(nb):
        bad.append(f'length {len(b)} -> {len(nb)} or xref broken')
    c, cp = info(nb, b'/Creator')
    p, pp = info(nb, b'/Producer')
    if c != b'(DERO HE ledger print)' or p != b'(PDF)' or cp < 1 or pp < 1 or n != 2:
        bad.append(f'values {c} {p} pad {cp} {pp} n {n}')
    diff = [i for i in range(min(len(b), len(nb))) if b[i] != nb[i]]
    i0 = b.index(b'/Creator') + len(b'/Creator ')
    i1 = b.index(b'\n/CreationDate')
    if diff and (min(diff) < i0 or max(diff) >= i1):
        bad.append('bytes outside the info values changed')
    nb2, n2 = m.neutral_info(nb)
    if nb2 != nb or n2:
        bad.append('a second pass changed the file')
    return not bad, '; '.join(bad) or 'same length, xref intact, neutral values, idempotent'


def kat_pc2(over):
    m = load(over)
    hexc = b'<FEFF' + 'Mozilla/5.0 (Windows NT 10.0) Chrome/999.0.0.0'.encode('utf-16-be').hex().upper().encode() + b'>'
    b = forge(creator=hexc, producer=b'(Skia/PDF m999 \\) odd)')
    before = m.info_fingerprint(b)
    nb, n = m.neutral_info(b)
    after = m.info_fingerprint(nb)
    bad = []
    if not any('chrome' in x for x in before) or not any('skia' in x for x in before) or not any('/Creator' in x for x in before):
        bad.append(f'fingerprint before {before}')
    if after or n != 2 or len(nb) != len(b) or not xref_ok(nb):
        bad.append(f'after {after} n {n}')
    if info(nb, b'/Creator')[0] != b'(DERO HE ledger print)' or b'odd' in nb:
        bad.append('a hex or escaped-paren value survived')
    ua = m.info_fingerprint(forge())
    if not any('0.0.0' in x for x in ua):
        bad.append(f'the <N>.0.0.0 token is not named: {ua}')
    return not bad, '; '.join(bad) or f'{len(before)} classes before, 0 after'


def kat_pc3(over):
    m = load(over)
    bad = []
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / 'a.pdf'
        f.write_bytes(forge())
        with contextlib.redirect_stdout(io.StringIO()):
            rc = m.main(['--neutral-info', str(f)])
        if rc != 0 or b'HeadlessChrome' in f.read_bytes() or b'(PDF)' not in f.read_bytes():
            bad.append(f'in place: rc {rc}')
        g = Path(d) / 'x.pdf'
        g.write_bytes(forge(xmp=b'<x:xmpmeta><xmp:CreatorTool>HeadlessChrome/999.0.0.0</xmp:CreatorTool></x:xmpmeta>'))
        with contextlib.redirect_stdout(io.StringIO()):
            rx = m.main(['--neutral-info', str(g)])
            rm = m.main(['--neutral-info', str(Path(d) / 'missing.pdf')])
        if rx != 5 or rm != 2:
            bad.append(f'xmp token rc {rx} (want 5), missing rc {rm} (want 2)')
    return not bad, '; '.join(bad) or 'in place 0; xmp token 5; missing 2'


KATS = [('PC1', kat_pc1), ('PC2', kat_pc2), ('PC3', kat_pc3)]
OWNERS = {'B279 bytes': ['PC1', 'PC2', 'PC3'],  # the command is the bytes path end to end
          'B279 forms': ['PC2'], 'B279 cmd': ['PC3'], 'B279 check': ['PC2', 'PC3']}
MUTATIONS = [   # (file key, find, replace, why — the first two words name the defect, see OWNERS)
    ('pc', "        new = want + b' ' * (e - s_ - len(want))", "        new = want", 'B279 bytes: the rewrite changes the file length'),
    ('pc', "NEUTRAL_INFO = {b'/Creator': b'DERO HE ledger print', b'/Producer': b'PDF'}", "NEUTRAL_INFO = {b'/Creator': b'DERO HE ledger print'}",
     'B279 bytes: /Producer keeps the engine version'),
    ('pc', "    if b[i:i + 1] == b'<' and b[i:i + 2] != b'<<':\n        j = b.find(b'>', i)\n        return None if j < 0 else j + 1",
     "    if False:\n        pass", 'B279 forms: a hex /Creator is not rewritten'),
    ('pc', "        if c == b'\\\\':\n            j += 2\n            continue\n", "", 'B279 forms: an escaped paren ends the string early'),
    ('pc', "    return sorted(set(hits))", "    return []", 'B279 check: the token check sees nothing'),
    ('pc', "    if n:\n        with open(dst + '.tmp', 'wb') as f:", "    if False:\n        with open(dst + '.tmp', 'wb') as f:", 'B279 cmd: the file is never rewritten'),
    ('pc', "    return 5 if left else 0", "    return 0", 'B279 cmd: a token left exits 0'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_pc31', HARNESS / 'kit' / 'katmut.py')
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
        print(f'\nr31 print-copy KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='pc31-mut-') as d:
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
    print('\n' + K.summary('r31 print-copy KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
