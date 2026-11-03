#!/usr/bin/env python3
"""urlcheck — deterministic proof that a cited URL still says what the citation quotes (no model in the loop).

A researcher (human or agent) proposes {key, url, quote}. This tool downloads the URL itself and accepts the citation
only if the quote occurs in the fetched text: HTML tags stripped, entities decoded, whitespace / quotes / dashes / NBSP /
zero-width characters normalised, case-insensitive. A GitHub blob URL is read from raw.githubusercontent.com and, with a
#L<n> anchor, the quote must sit on that line or within ±3 lines of it.

  python3 urlcheck.py results_glob out.json [--cache DIR]   → writes {"citations": [...], "summary": {...}}
  each citation: key, url, quote, source_title, supports, verified (bool), check ('found' | 'quote-not-found' |
  'line-mismatch' | 'http-<code>' | 'fetch-error' | 'no-url'), checked_at, sha256 of the fetched body

An unverified citation is kept (so nothing is silently dropped) but a page must never present it as proof.
"""
import glob, hashlib, html, json, re, sys, time, unicodedata, urllib.request, urllib.error, datetime
from pathlib import Path

UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15'


def norm(t):
    t = html.unescape(t)
    t = unicodedata.normalize('NFKC', t)
    t = re.sub(r'[​-‏⁠﻿]', '', t)
    t = t.replace('“', '"').replace('”', '"').replace('‘', "'").replace('’', "'").replace('–', '-').replace('—', '-').replace('\xa0', ' ')
    t = re.sub(r'`', '', t)
    return re.sub(r'\s+', ' ', t).strip().lower()


def strip_html(b):
    b = re.sub(r'(?is)<(script|style|noscript)[^>]*>.*?</\1>', ' ', b)
    b = re.sub(r'(?s)<[^>]+>', ' ', b)
    return b


def raw_of(url):
    """(raw file URL, (first line, last line) or None) for a GitHub or GitLab blob URL; (None, None) otherwise"""
    m = re.match(r'https://github\.com/([^/]+)/([^/]+)/blob/([^#]+?)(?:#L(\d+)(?:-L(\d+))?)?$', url)
    if m:
        raw = f'https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}/{m.group(3)}'
        a, b = m.group(4), m.group(5)
    else:
        m = re.match(r'(https://gitlab\.com/.+?)/-/blob/([^#]+?)(?:#L(\d+)(?:-(\d+))?)?$', url)
        if not m:
            return None, None
        raw = f'{m.group(1)}/-/raw/{m.group(2)}'
        a, b = m.group(3), m.group(4)
    return raw, ((int(a), int(b or a)) if a else None)


def fetch(url, cache):
    k = hashlib.sha256(url.encode()).hexdigest()[:24]
    cf = cache / k if cache else None
    if cf and cf.exists():
        d = json.loads(cf.read_text())
        return d['status'], d['body']
    req = urllib.request.Request(url, headers={'User-Agent': UA, 'Accept': '*/*'})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read(6_000_000).decode('utf-8', 'replace')
            st = r.status
    except urllib.error.HTTPError as e:
        st, body = e.code, ''
    except Exception as e:  # noqa: BLE001 — any network failure is a recorded verdict, not a crash
        st, body = 0, f'fetch-error {type(e).__name__}: {e}'
    if st != 200:   # some hosts refuse Python's HTTP client but serve curl (e.g. quay.io's API): one curl retry
        import subprocess
        r = subprocess.run(['curl', '-sSL', '-m', '30', '-w', '\n%{http_code}', url], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.rstrip().endswith('200'):
            st, body = 200, r.stdout.rstrip()[:-3]
    if cf:
        cf.write_text(json.dumps({'url': url, 'status': st, 'body': body}))
    return st, body


def check(url, quote, cache=None):
    if not url:
        return False, 'no-url', ''
    if not quote:
        return False, 'no-quote', ''
    raw, line = raw_of(url)
    st, body = fetch(raw or url, cache)
    if st != 200:
        return False, ('fetch-error' if st == 0 else f'http-{st}'), ''
    h = hashlib.sha256(body.encode()).hexdigest()[:16]
    q = norm(quote.strip(' .…').replace('...', ' '))
    if raw:
        lines = body.splitlines()
        if line:
            win = norm(' '.join(lines[max(0, line[0] - 4):line[1] + 3]))
            if q in win:
                return True, 'found', h
            return (False, 'line-mismatch', h) if q in norm(body) else (False, 'quote-not-found', h)
        return (q in norm(body)), ('found' if q in norm(body) else 'quote-not-found'), h
    text = norm(strip_html(body))
    if q in text:
        return True, 'found', h
    # inline markup (<code>, <a>, <em>) must not split words: strip tags with no space, then compare whitespace-free
    # (still the exact characters of the quote, in order)
    tight = norm(re.sub(r'(?s)<[^>]+>', '', re.sub(r'(?is)<(script|style|noscript)[^>]*>.*?</\1>', ' ', body)))
    if q in tight or re.sub(r'\s+', '', q) in re.sub(r'\s+', '', text) or re.sub(r'\s+', '', q) in re.sub(r'\s+', '', tight):
        return True, 'found', h
    # a quote copied from rendered markdown may lose inline markup: retry on the raw body too
    return (q in norm(body)), ('found' if q in norm(body) else 'quote-not-found'), h


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    cache = None
    if '--cache' in sys.argv:
        cache = Path(sys.argv[sys.argv.index('--cache') + 1])
        cache.mkdir(parents=True, exist_ok=True)
    rows = []
    for f in sorted(glob.glob(sys.argv[1])):
        rows += json.loads(Path(f).read_text())
    out, seen = [], {}
    now = datetime.datetime.now().astimezone().isoformat(timespec='seconds')
    for r in rows:
        k = (r.get('url'), r.get('quote'))
        if k not in seen:
            seen[k] = check(r.get('url'), r.get('quote'), cache)
            time.sleep(0.05)
        ok, why, h = seen[k]
        out.append({**{x: r.get(x) for x in ('key', 'url', 'quote', 'source_title', 'supports')}, 'verified': ok, 'check': why, 'checked_at': now, 'body_sha256': h})
    summ = {'items': len(out), 'verified': sum(o['verified'] for o in out), 'by_check': {}}
    for o in out:
        summ['by_check'][o['check']] = summ['by_check'].get(o['check'], 0) + 1
    summ['distinct_urls'] = len({o['url'] for o in out if o['url']})
    Path(sys.argv[2]).write_text(json.dumps({'schema': 'artifact-kit/urlcheck@1', 'summary': summ, 'citations': out}, indent=1, ensure_ascii=False))
    print(json.dumps(summ))
    return 0


if __name__ == '__main__':
    sys.exit(main())
