#!/usr/bin/env python3
"""pdfscan.py — r30 (rft §7 B206, §10 'binaries by bytes'): a privacy scan of a PDF's RAW bytes, Python stdlib only.

The R29 print (print_copy.py + headless Chrome) carried 9 link annotations `/URI (file:///private/tmp/…/scratchpad/…)`
with the account name in them while `pdftotext` showed 0 hits: a text scan reads the page text, never the annotation
dictionaries, the document info, the XMP packet or a compressed object stream. This scan reads four views:

  raw       the file's bytes as written
  inflated  every `stream … endstream` with a /Filter, its chain applied in order (FlateDecode, ASCIIHexDecode,
            ASCII85Decode, RunLengthDecode; object streams too, so an annotation packed into an /ObjStm is read).
            FAIL CLOSED (r30 verify D1): a stream that does not decode (raw deflate, truncated, bad hex) and a filter
            not decoded here that is not an image codec (LZWDecode, Crypt, an unknown name) are each a finding;
            DCT / JPX / JBIG2 / CCITTFax image streams are exempt (their output is pixels)
  strings   every PDF string of raw + inflated, decoded: literal `( … )` with its escapes, hex `< … >`, UTF-16BE (BOM)
            — /Title, /Author, /Producer, /URI targets may be hex or UTF-16
  uri       every /URI target (literal or hex, raw or inflated); one that is not http(s)/mailto/relative is a finding

A finding is a path class (LEAK_RX) in any view, a /URI with a local target (file:, an absolute path, a scratch
path), a stream that failed to decode or a stream behind an undecoded non-image filter. Counts and classes only are
printed: a hit is never echoed (the account name would be).

  python3 -I harness/kit/pdfscan.py FILE.pdf [...] [--json OUT]
  python3 -I harness/kit/pdfscan.py --rewrite IN.pdf OUT.pdf      # same-length /URI re-scrub (OUT may be IN)
Exit 0 clean · 5 a finding in any file · 2 bad invocation / unreadable file.

--rewrite (r30 B206 item 4, the older local prints): every local /URI literal in the file's object syntax is replaced IN
PLACE by a relative target of the SAME byte length, so no offset, xref entry or page changes: a repo path
(…/derohe-Release1NN/p2p/x.go:12, vscode://file//…) becomes '../p2p/x.go' (the PDF sits in artifacts/), a print-dir
page (file:///…/scratchpad/…/dero-soundness-r29.html#a) its basename + fragment; the gap is padded with './' and, for an
odd byte, one ignored backslash (PDF 32000-1, the literal-string escapes of section 7.3.4: a backslash before an ordinary character is dropped). A local
target inside a compressed stream cannot keep its length and is reported (unfixed). The result is re-scanned.
"""
import base64, json, re, sys, zlib
from pathlib import Path

# path classes that must never reach a published or local copy of a page (rft §5 privacy, B206)
LEAK_RX = [
    ('file-url', re.compile(rb'(?i)file:/')),
    ('users-path', re.compile(rb'/Users/[A-Za-z0-9._-]')),
    ('private-tmp', re.compile(rb'/private/(?:tmp|var)/')),
    ('tmp-claude', re.compile(rb'claude-\d{3,}')),
    ('project-slug', re.compile(rb'-Users-[A-Za-z0-9]')),
    ('scratchpad', re.compile(rb'(?i)scratchpad/')),
    ('tool-dir', re.compile(rb'\.claude/')),
]
# read in the decoded-string view only: in compressed or binary bytes '~/' + a letter occurs by chance (the r21/r22
# prints, which hold no home path, gave 5 raw hits each)
STRING_ONLY_RX = [('home-tilde', re.compile(rb'(?<![\w/.~-])~/[A-Za-z0-9._-]'))]
STREAM_RX = re.compile(rb'<<((?:[^<>]|<<(?:[^<>]|<<[^<>]*>>)*>>|<[0-9A-Fa-f\s]*>)*)>>\s*stream\r?\n', re.S)
HEX_RX = re.compile(rb'<([0-9A-Fa-f\s]{2,})>')
URI_RX = re.compile(rb'/URI\s*(\(|<(?!<))')
SAFE_URI = re.compile(r'(?i)^(?:https?:|mailto:|#)')
ESC = {b'n': b'\n', b'r': b'\r', b't': b'\t', b'b': b'\b', b'f': b'\f', b'(': b'(', b')': b')', b'\\': b'\\'}


SPECIAL = re.compile(rb'[()\\]')


def literal_at(b, i):
    """(decoded bytes, end index) of the PDF literal string whose '(' is at b[i]. Balanced parens, escapes, octal,
    line continuations. Pure."""
    out, depth, j, n = bytearray(), 1, i + 1, len(b)
    while j < n:
        m = SPECIAL.search(b, j)
        if not m:
            out += b[j:]
            return bytes(out), n
        out += b[j:m.start()]
        j = m.start()
        c = b[j:j + 1]
        if c == b'\\':
            nx = b[j + 1:j + 2]
            if nx in ESC:
                out += ESC[nx]
                j += 2
            elif nx in (b'\r', b'\n'):
                j += 3 if b[j + 1:j + 3] == b'\r\n' else 2
            elif nx and nx in b'01234567':
                k = j + 1
                while k < j + 4 and b[k:k + 1] and b[k:k + 1] in b'01234567':
                    k += 1
                out.append(int(b[j + 1:k], 8) & 0xFF)
                j = k
            else:
                j += 1
            continue
        if c == b'(':
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return bytes(out), j + 1
        out += c
        j += 1
    return bytes(out), n


def skeleton(b):
    """`b` with every stream body cut out (the object syntax only), so the string lexer never reads binary. Pure."""
    parts, i = [], 0
    for m in re.finditer(rb'(?<!end)stream\r?\n', b):
        if m.start() < i:
            continue
        e = b.find(b'endstream', m.end())
        if e < 0:
            break
        parts.append(b[i:m.end()])
        i = e
    parts.append(b[i:])
    return b''.join(parts)


def hexstr(h):
    h = re.sub(rb'\s', b'', h)
    if len(h) % 2:
        h += b'0'
    try:
        return bytes.fromhex(h.decode())
    except ValueError:
        return b''


def text_of(s):
    """bytes of a decoded PDF string, UTF-16BE (with BOM) turned into UTF-8 so LEAK_RX reads it. Pure."""
    if s[:2] == b'\xfe\xff':
        return s[2:].decode('utf-16-be', errors='replace').encode()
    return s


BINARY_DICT = re.compile(rb'/Subtype\s*/(?:Image|Type1C|CIDFontType0C|OpenType)|/Length[123]\s|/FontFile')


# r30 verify D1 (fail CLOSED): every filter of a stream's /Filter chain is applied in order; a filter that is not
# decoded here and is not an image codec, or a decode that fails, is itself a FINDING (the scan cannot read the bytes)
FILTER_RX = re.compile(rb'/Filter\s*(\[[^\]]*\]|/[^\s/<>\[\]()]+)')
ABBREV = {b'Fl': b'FlateDecode', b'AHx': b'ASCIIHexDecode', b'A85': b'ASCII85Decode', b'LZW': b'LZWDecode',
          b'RL': b'RunLengthDecode', b'DCT': b'DCTDecode', b'CCF': b'CCITTFaxDecode'}
IMAGE_FILTERS = {b'DCTDecode', b'JPXDecode', b'JBIG2Decode', b'CCITTFaxDecode'}


def filters_of(d):
    """the /Filter chain of a stream dictionary, abbreviations expanded ([] when the stream is unfiltered). Pure."""
    m = FILTER_RX.search(d)
    if not m:
        return []
    return [ABBREV.get(f, f) for f in re.findall(rb'/([^\s/<>\[\]()]+)', m.group(1))]


class DecodeError(Exception):
    pass


def flate(x):
    z = zlib.decompressobj()
    try:
        out = z.decompress(x) + z.flush()
    except zlib.error as e:
        raise DecodeError(str(e))
    if not z.eof:
        raise DecodeError('truncated deflate stream')
    return out


def ascii_hex(x):
    e = x.find(b'>')
    h = re.sub(rb'\s', b'', x if e < 0 else x[:e])
    if e < 0 or re.search(rb'[^0-9A-Fa-f]', h):
        raise DecodeError('bad ASCIIHex')
    return bytes.fromhex((h + b'0' * (len(h) % 2)).decode())


def ascii85(x):
    e = x.find(b'~>')
    if e < 0:
        raise DecodeError('no ~> end')
    body = re.sub(rb'\s', b'', x[:e])
    if body.startswith(b'<~'):
        body = body[2:]
    try:
        return base64.a85decode(body)
    except ValueError as e:
        raise DecodeError(str(e))


def run_length(x):
    out, i, n = bytearray(), 0, len(x)
    while i < n:
        c = x[i]
        if c == 128:
            return bytes(out)
        if c < 128:
            if i + 1 + c + 1 > n:
                raise DecodeError('short literal run')
            out += x[i + 1:i + 2 + c]
            i += c + 2
        else:
            if i + 1 >= n:
                raise DecodeError('short repeat run')
            out += x[i + 1:i + 2] * (257 - c)
            i += 2
    raise DecodeError('no end-of-data byte')


DECODERS = {b'FlateDecode': flate, b'ASCIIHexDecode': ascii_hex, b'ASCII85Decode': ascii85,
            b'RunLengthDecode': run_length}


def decode_chain(data, chain):
    """(decoded bytes, undecoded filter name or None): `data` through `chain` in order, up to an image codec (exempt:
    its output is pixels). An unknown / undecoded filter stops the chain and is named. Raises DecodeError. Pure."""
    for f in chain:
        if f in IMAGE_FILTERS:
            return data, None
        fn = DECODERS.get(f)
        if fn is None:
            return data, f.decode('latin-1')
        data = fn(data)
    return data, None


def inflate_streams(b, with_dicts=False, undecoded=None):
    """([decoded bytes], n_filtered, n_failed) for every filtered stream of `b` (with_dicts: [(dict, decoded)]); a
    stream whose chain names a filter this scan does not decode (not an image codec) is counted into `undecoded`
    ({name: n}) and its bytes are not read. Pure."""
    outs, n, bad = [], 0, 0
    for m in STREAM_RX.finditer(b):
        d = m.group(1)
        chain = filters_of(d)
        if not chain:
            continue
        n += 1
        start = m.end()
        lm = re.search(rb'/Length\s+(\d+)(?!\s+\d+\s+R)', d)
        end = start + int(lm.group(1)) if lm else b.find(b'endstream', start)
        if end < start or end > len(b):
            end = b.find(b'endstream', start)
        try:
            x, und = decode_chain(b[start:end], chain)
        except DecodeError:
            end2 = b.find(b'endstream', start)
            try:
                x, und = decode_chain(b[start:end2], chain)
            except DecodeError:
                bad += 1
                continue
        if und is not None:
            if undecoded is not None:
                undecoded[und] = undecoded.get(und, 0) + 1
            continue
        outs.append((d, x) if with_dicts else x)
    return outs, n, bad


def strings_of(b):
    """every decoded literal and hex string of `b` (a coarse lexer: a '(' outside a string starts one). Pure."""
    out, i, n = [], 0, len(b)
    for m in HEX_RX.finditer(b):
        s = hexstr(m.group(1))
        if s:
            out.append(text_of(s))
    while True:
        i = b.find(b'(', i)
        if i < 0 or i >= n:
            break
        s, j = literal_at(b, i)
        out.append(text_of(s))
        i = max(j, i + 1)
    return out


def uris_of(b):
    """every /URI target of `b`, decoded to str. Pure."""
    res = []
    for m in URI_RX.finditer(b):
        if m.group(1) == b'(':
            s, _ = literal_at(b, m.end() - 1)
        else:
            e = b.find(b'>', m.end())
            s = hexstr(b[m.end():e])
        res.append(text_of(s).decode('utf-8', errors='replace'))
    return res


def local_uri(u):
    """True for a /URI that names a local file: file:, an absolute path, a home/scratch path; http(s), mailto, an
    anchor and a plain relative name are not. Pure."""
    u = u.strip()
    if SAFE_URI.match(u):
        return False
    return (u.startswith(('/', '~', '\\')) or re.match(r'(?i)^[a-z][a-z0-9+.-]*:', u) is not None
            or any(rx.search(u.encode()) for _, rx in LEAK_RX))


def scan_bytes(b):
    """{'hits': {class: n}, 'local_uris': n, 'uris': n, 'streams': n, 'inflate_failed': n, 'views': {...}} over the
    raw, inflated and decoded-string views of a PDF's bytes. Pure."""
    und = {}
    pairs, n, bad = inflate_streams(b, with_dicts=True, undecoded=und)
    infl = [x for _, x in pairs]
    # the string lexer reads object syntax only: the file's skeleton and the inflated non-binary streams (object
    # streams, XMP, page content); image and font programs are scanned as bytes (raw/inflated views), not lexed
    texty = [x for d, x in pairs if not BINARY_DICT.search(d)]
    sk = skeleton(b)
    views = {'raw': [b], 'inflated': infl, 'strings': strings_of(sk) + [s for x in texty for s in strings_of(x)]}
    hits, per = {}, {}
    for vn, parts in views.items():
        for part in parts:
            for name, rx in LEAK_RX + (STRING_ONLY_RX if vn == 'strings' else []):
                k = len(rx.findall(part))
                if k:
                    hits[name] = hits.get(name, 0) + k
                    per[vn] = per.get(vn, 0) + k
    uris = uris_of(sk) + [u for x in texty for u in uris_of(x)]
    loc = sum(1 for u in uris if local_uri(u))
    return {'hits': hits, 'hits_by_view': per, 'uris': len(uris), 'local_uris': loc, 'streams': n,
            'inflate_failed': bad, 'undecoded': und, 'finding': bool(hits) or loc > 0 or bad > 0 or bool(und)}


REPO_RX = re.compile(r'/derohe-Release1\d\d/(.*)$')


def relative_target(u):
    """the relative print target of one local /URI string (see --rewrite). Pure."""
    path, frag = (u.split('#', 1) + [''])[:2]
    path = re.sub(r'(?i)^(?:vscode://file/*|file://)', '/', path)
    m = REPO_RX.search(path)
    if m:
        new = '../' + re.sub(r'(:\d+)+$', '', m.group(1))
    else:
        new = re.sub(r'(:\d+)+$', '', re.split(r'[\\/]', path)[-1]) or '#'
    return new + ('#' + frag if frag and new != '#' else '')


NOT_ORDINARY = set(b'nrtbf01234567()\\\r\n')


def padded(new, n):
    """PDF literal-string bytes, exactly n long, that decode to './' * k + `new`; None when `new` does not fit. Pure."""
    body = re.sub(rb'([()\\])', rb'\\\1', new.encode())
    gap = n - len(body)
    if gap < 0:
        return None
    res = b'./' * (gap // 2) + body
    if gap % 2:                                        # one ignored backslash before an ordinary character
        k = next((j for j, c in enumerate(res) if c not in NOT_ORDINARY and (j == 0 or res[j - 1:j] != b'\\')), None)
        if k is None:
            return None
        res = res[:k] + b'\\' + res[k:]
    return res


def rewrite_local_uris(b):
    """(new bytes, n rewritten, n unfixable) with every local /URI literal of `b`'s object syntax replaced by a
    same-length relative target. Stream bodies are never touched. Pure."""
    out, n, i = bytearray(b), 0, 0
    spans, k = [], 0
    for m in re.finditer(rb'(?<!end)stream\r?\n', b):
        if m.start() < k:
            continue
        e = b.find(b'endstream', m.end())
        if e < 0:
            break
        spans.append((m.end(), e))
        k = e
    def in_stream(pos):
        return any(a <= pos < z for a, z in spans)
    for m in re.finditer(rb'/URI\s*\(', b):
        if in_stream(m.start()):
            continue
        st = m.end() - 1
        sv, end = literal_at(b, st)
        u = text_of(sv).decode('utf-8', errors='replace')
        if not local_uri(u):
            continue
        new = padded(relative_target(u), end - st - 2)
        if new is None or len(new) != end - st - 2:
            i += 1
            continue
        out[st + 1:end - 1] = new
        n += 1
    infl, _, _ = inflate_streams(b)
    i += sum(1 for x in infl for u in uris_of(x) if local_uri(u))
    return bytes(out), n, i


def scan_file(p):
    return scan_bytes(Path(p).read_bytes())


def main(argv):
    if not argv or {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0 if argv else 2
    if argv[0] == '--rewrite':
        if len(argv) != 3:
            print('pdfscan: --rewrite IN OUT')
            return 2
        b = Path(argv[1]).read_bytes()
        nb, n, unfix = rewrite_local_uris(b)
        r = scan_bytes(nb)
        tmp = Path(argv[2] + '.pdfscan-tmp')
        tmp.write_bytes(nb)
        tmp.replace(argv[2])
        print(f"{'FAIL' if r['finding'] else 'OK  '} {Path(argv[2]).name}: rewrote {n} /URI (unfixable {unfix}), "
              f"length {len(b)} -> {len(nb)}, residual hits {sum(r['hits'].values())} local /URI {r['local_uris']}")
        return 5 if r['finding'] or len(nb) != len(b) else 0
    out = None
    if '--json' in argv:
        k = argv.index('--json')
        out = argv[k + 1] if k + 1 < len(argv) else None
        argv = argv[:k] + argv[k + 2:]
    res, rc = {}, 0
    for f in argv:
        try:
            r = scan_file(f)
        except OSError as e:
            print(f'pdfscan: {Path(f).name}: unreadable ({e.__class__.__name__})')
            return 2
        res[Path(f).name] = r
        rc = 5 if r['finding'] else rc
        print(f"{'FAIL' if r['finding'] else 'OK  '} {Path(f).name}: hits {sum(r['hits'].values())} {r['hits']} "
              f"by view {r['hits_by_view']} · /URI {r['uris']} (local {r['local_uris']}) · filtered {r['streams']} "
              f"(failed {r['inflate_failed']}, undecoded {r['undecoded']})")
    if out:
        Path(out).write_text(json.dumps(res, indent=1, sort_keys=True) + '\n')
    return rc


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
