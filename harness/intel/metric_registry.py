#!/usr/bin/env python3
"""metric_registry.py — the machine-readable registry of every /metrics family derod exports (r28 rpc-metrics).

Before r28, 296 of the 298 families on the live r27 /metrics carried no '# HELP' / '# TYPE' line, so every reader (the
intel tools, area_intel, the dashboards, the page claims) depended on names copied into docs and KATs, and a renamed or
dropped series was noticed only when a reading went missing. This tool keeps metrics/metric_registry.json, which derod
embeds (metrics/registry_r28.go) to write HELP and TYPE for every registered family, and checks it against the source
tree, a /metrics scrape and the docs.

  python3 -I harness/intel/metric_registry.py build --scrape FILE [--out metrics/metric_registry.json]
  python3 -I harness/intel/metric_registry.py check [--scrape FILE] [--docs] [--json]
  python3 -I harness/intel/metric_registry.py --help

build  mines every metric-name literal of a metrics constructor in first-party Go source (vendor and _test.go files
       aside) and every family of the scrape; each entry is {name, type, unit, area, help, source}. type: the
       constructor's kind (Counter/FloatCounter -> counter, Gauge -> gauge, Histogram -> vmhistogram, i.e.
       VictoriaMetrics vmrange buckets, which are NOT Prometheus le-histograms and get no TYPE line, Summary ->
       summary), else read from the scrape's sample shape. help: the Go comment on or right above the declaring line
       (a family only the scrape shows: its literal's first hit in the source, else 'dynamic'); a family with no
       comment gets a help made from its name, marked '(derived from the name)' so nobody mistakes it for a statement.
       area: harness/areas.json code_paths of the declaring file. unit: from the name's suffix (Prometheus base units).
       Entries already in --out keep a hand-written 'help' (help_source "hand") across rebuilds.
check  K1 every scrape family is registered · K2 every entry has a valid name/type/unit/area/help · K3 naming: a
       counter ends in _total and nothing else does (upstream families are listed apart, they keep their names) ·
       K4 a source-declared family is still declared in the source · K5 (--docs) every backticked metric-like name
       in cmd/derod/rpc/RPC_METHODS.md is registered (dero-rft.md hits are reported, not failed: it quotes history).
       Exit 0 ok · 3 a check failed · 2 bad usage/input. Nothing is fetched: give the scrape as a file.
A scrape carries peer addresses in labels: keep it in a scratch directory, never commit it (rft §5 privacy).
"""
import argparse, fnmatch, json, re, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
ROOT = HARNESS.parent
OUT = ROOT / 'metrics' / 'metric_registry.json'
NAME = re.compile(r'^[a-zA-Z_:][a-zA-Z0-9_:]*$')
CTOR = re.compile(r'\b(NewCounter|GetOrCreateCounter|NewFloatCounter|GetOrCreateFloatCounter|NewGauge|GetOrCreateGauge|'
                  r'NewHistogram|GetOrCreateHistogram|NewSummary|GetOrCreateSummary|NewPrometheusHistogram|'
                  r'GetOrCreatePrometheusHistogram)\(\s*(?:fmt\.Sprintf\(\s*)?[`"]([a-zA-Z_:][a-zA-Z0-9_:]*)[{`"%]')
KIND = {'Counter': 'counter', 'FloatCounter': 'counter', 'Gauge': 'gauge', 'Histogram': 'vmhistogram',
        'Summary': 'summary', 'PrometheusHistogram': 'histogram'}
TYPES = ('counter', 'gauge', 'histogram', 'vmhistogram', 'summary', 'untyped')
LABEL_KEY = re.compile(r'(?:^|,)\s*([a-zA-Z_][a-zA-Z0-9_]*)="')
SAMPLE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{([^}]*)\})?\s+(\S+)')
UPSTREAM = ('go_', 'process_', 'KCP_', 'flag', 'vm_')       # families named by vendored code: reported, never renamed
UNITS = (('_seconds', 'seconds'), ('_bytes', 'bytes'), ('_ms', 'milliseconds'), ('_us', 'microseconds'),
         ('_ratio', 'ratio'), ('_percent', 'percent'), ('_blocks', 'blocks'), ('_timestamp', 'seconds'))
NON_BASE = {'milliseconds', 'microseconds', 'percent'}  # Prometheus base units are seconds/bytes/ratio: K3 lists these
PREFIX_AREA = (('p2p_', 'syncp2p'), ('KCP_', 'syncp2p'), ('chunk_', 'syncp2p'), ('rpc_', 'rpcws'), ('getwork_', 'getworkops'),
               ('miniblock_', 'getworkops'), ('mempool_', 'mempool'), ('regpool_', 'mempool'), ('tx_', 'mempool'),
               ('block_', 'consensus'), ('blockchain_', 'consensus'), ('emission_', 'cryptosupply'),
               ('dero_miner_', 'miner'), ('dero_', 'observability'), ('go_', 'observability'),
               ('process_', 'observability'), ('app_', 'observability'), ('free_disk', 'storage'), ('file_', 'storage'),
               ('config_', 'observability'), ('recovered_', 'observability'))
METRIC_TOKEN = re.compile(r'`([a-z][a-z0-9_]*_total)(?:\{[^`]*\})?`')    # a counter claim; JSON fields (first_seen_ms ...) are not metrics
ROUND_TAG = re.compile(r'^(?:r\d+[a-z]?(?:\s+[\w-]+)?(?:\s*\([^)]*\))?\s*[:,-]\s*)+', re.I)
ADD_ONLY = re.compile(r'atomic\.LoadUint64\(&(\w+)\)')


def unit_of(name):
    """the unit a family's name states (Prometheus suffix convention); '1' when it states none. Pure."""
    base = name[:-len('_total')] if name.endswith('_total') else name
    for suf, unit in UNITS:
        if base.endswith(suf):
            return unit
    return '1'


def area_of(path, areas):
    """the area whose code_paths match a repo-relative file best (the longest matching pattern). Pure."""
    best, blen = None, -1
    for a in areas:
        for pat in a.get('code_paths', []):
            ok = fnmatch.fnmatch(path, pat) if any(c in pat for c in '*?[') else (path == pat or (pat.endswith('/') and path.startswith(pat)))
            if ok and len(pat) > blen:
                best, blen = a['id'], len(pat)
    return best


def area_by_prefix(name):
    for p, a in PREFIX_AREA:
        if name.startswith(p):
            return a
    return 'observability'


def comment_help(lines, i):
    """the Go comment on line i (trailing) or the comment block right above it, one line, <= 200 chars. Pure."""
    m = re.search(r'//\s*(.+)$', lines[i])
    text = m.group(1).strip() if m and '`' not in m.group(1)[:1] else ''
    if not text:
        block, j = [], i - 1
        while j >= 0 and lines[j].strip().startswith('//') and len(block) < 3:
            block.insert(0, lines[j].strip()[2:].strip())
            j -= 1
        text = ' '.join(block)
    text = re.sub(r'\s+', ' ', text).strip()
    text = ROUND_TAG.sub('', text).strip()                     # 'r23c: ...', 'r25 (CO24-C1): ...' are history, not meaning
    if len(text) < 12 or text.startswith(('nolint', 'TODO')):
        return ''
    if len(text) > 200:
        text = text[:200].rsplit(' ', 1)[0] + ' ...'
    return text


def derived_help(name, kind):
    words = name[:-len('_total')] if name.endswith('_total') else name
    what = {'counter': 'count of', 'gauge': 'current', 'vmhistogram': 'distribution of', 'histogram': 'distribution of',
            'summary': 'summary of'}.get(kind, '')
    return f"{what} {words.replace('_', ' ')} (derived from the name)".strip()


def go_files(root):
    for p in sorted(root.rglob('*.go')):
        rel = p.relative_to(root).as_posix()
        if rel.startswith(('vendor/', 'harness/', 'forensics/')) or '/vendor/' in rel or rel.endswith('_test.go'):
            continue
        yield rel, p


def mine_source(root):
    """{family: {type, source, help}} from every constructor literal in first-party Go source. First declaration wins."""
    out = {}
    for rel, p in go_files(root):
        try:
            lines = p.read_text(encoding='utf-8', errors='replace').split('\n')
        except OSError:
            continue
        for i, l in enumerate(lines):
            for m in CTOR.finditer(l):
                kind = KIND[re.sub(r'^(New|GetOrCreate)', '', m.group(1))]
                fam = m.group(2)
                if fam not in out:
                    out[fam] = {'type': kind, 'source': rel, 'help': comment_help(lines, i)}
                    v = ADD_ONLY.search(' '.join(lines[i:i + 3]))
                    if kind == 'gauge' and fam.endswith('_total') and v:
                        out[fam]['callback_var'] = v.group(1)
    # a gauge callback over an atomic that is only ever added to IS a counter (p2p_inbound_*_total, r20-r25): TYPE counter
    texts = None
    for fam, e in out.items():
        if 'callback_var' in e:
            if texts is None:
                texts = '\n'.join(p.read_text(encoding='utf-8', errors='replace') for _, p in go_files(root))
            var = e.pop('callback_var')
            if not re.search(r'(Store|Swap|CompareAndSwap)Uint64\(&' + var + r'\b', texts):
                e['type'], e['type_note'] = 'counter', f'gauge callback over the add-only atomic {var}'
    return out


def parse_scrape(text):
    """{family: type} of a Prometheus text exposition, the type read from the sample shape and any '# TYPE'. Pure."""
    fams, typed, shapes = {}, {}, {}
    for l in text.split('\n'):
        if l.startswith('# TYPE '):
            parts = l.split()
            if len(parts) >= 4:
                typed[parts[2]] = parts[3]
            continue
        if not l or l.startswith('#'):
            continue
        m = SAMPLE.match(l)
        if not m:
            continue
        name, labels = m.group(1), m.group(3) or ''
        keys = set(LABEL_KEY.findall(labels))                    # by key: 'quantile="' contains 'le="'
        shapes.setdefault(name, set()).add('le' if 'le' in keys else 'vmrange' if 'vmrange' in keys
                                           else 'quantile' if 'quantile' in keys else '')
    for name, sh in shapes.items():
        base = re.sub(r'_(bucket|sum|count)$', '', name)
        if name.endswith('_bucket') and 'le' in sh:
            fams[base] = 'histogram'
        elif name.endswith('_bucket') and 'vmrange' in sh:
            fams[base] = 'vmhistogram'
        elif 'quantile' in sh:
            fams[name] = 'summary'
        elif name != base and (base + '_bucket') in shapes or (name != base and base in fams):
            continue
        else:
            fams.setdefault(name, typed.get(name) or ('counter' if name.endswith('_total') else 'gauge'))
    for name in list(fams):                                    # _sum/_count of a histogram or summary are its samples
        base = re.sub(r'_(sum|count)$', '', name)
        if base != name and fams.get(base) in ('histogram', 'vmhistogram', 'summary'):
            del fams[name]
    for name, t in typed.items():
        if name in fams:
            fams[name] = t
    return fams


def find_literal(root, fam, cache={}):
    """(file, help) of the first first-party Go file that names the family as a literal (a Fprintf writer, a label
    builder), else (None, '')."""
    if 'files' not in cache:
        cache['files'] = [(rel, p.read_text(encoding='utf-8', errors='replace').split('\n')) for rel, p in go_files(root)]
    rx = re.compile(r'[`"\\n ]' + re.escape(fam) + r'[{ `"%_]?')
    for rel, lines in cache['files']:
        for i, l in enumerate(lines):
            if fam in l and rx.search(l):
                return rel, comment_help(lines, i)
    return None, ''


def build(root, scrape_text, old=None):
    areas = json.loads((root / 'harness' / 'areas.json').read_text(encoding='utf-8'))['areas']
    src = mine_source(root)
    live = parse_scrape(scrape_text) if scrape_text else {}
    keep = {e['name']: e for e in (old or {}).get('families', []) if e.get('help_source') == 'hand'}
    fams = []
    for name in sorted(set(src) | set(live)):
        if name in src:
            e = dict(name=name, type=src[name]['type'], source=src[name]['source'], help=src[name]['help'])
            if name in live and live[name] != e['type'] and not (e['type'] == 'vmhistogram' and live[name] in ('vmhistogram', 'histogram')):
                e['type_scrape'] = live[name]
        else:
            f, h = (None, '') if name.startswith(UPSTREAM) else find_literal(root, name)
            e = dict(name=name, type=live[name], source=f or ('vendored' if name.startswith(UPSTREAM) else 'dynamic'), help=h)
        if name.startswith(('go_', 'process_')) and not e['help']:
            e['help'] = 'Go runtime / process metric written by the vendored VictoriaMetrics/metrics exporter (or metrics/process_darwin.go)'
        e['help_source'] = 'comment' if e['help'] else 'name'
        if not e['help']:
            e['help'] = derived_help(name, e['type'])
        if name in keep:
            e['help'], e['help_source'] = keep[name]['help'], 'hand'
        e['unit'] = unit_of(name)
        e['area'] = (area_of(e['source'], areas) if e['source'] not in ('dynamic', 'vendored') else None) or area_by_prefix(name)
        e['in_scrape'] = name in live
        fams.append(e)
    return {'_doc': 'generated by harness/intel/metric_registry.py build; embedded by metrics/registry_r28.go (HELP/TYPE '
                    'on /metrics). Edit a help by hand with help_source "hand"; everything else is regenerated.',
            'schema': 1, 'families': fams}


def check(reg, root=ROOT, scrape_text=None, docs=False):
    """the problems of a registry: [(K, message)]. Pure given its inputs (root is read for K4/K5)."""
    probs, names = [], {}
    for e in reg.get('families', []):
        n = e.get('name', '')
        if not NAME.match(n) or n in names:
            probs.append(('K2', f'bad or duplicate name {n!r}'))
        names[n] = e
        if e.get('type') not in TYPES:
            probs.append(('K2', f'{n}: type {e.get("type")!r}'))
        if not str(e.get('help', '')).strip() or '\n' in str(e.get('help', '')):
            probs.append(('K2', f'{n}: empty or multi-line help'))
        if not e.get('area') or not e.get('unit'):
            probs.append(('K2', f'{n}: no area/unit'))
        if not n.startswith(UPSTREAM):
            if e.get('type') == 'counter' and not n.endswith('_total'):
                probs.append(('K3', f'{n}: a counter whose name does not end in _total'))
            if e.get('type') != 'counter' and n.endswith('_total'):
                probs.append(('K3', f'{n}: a {e.get("type")} named _total'))
    if scrape_text is not None:
        for fam in sorted(parse_scrape(scrape_text)):
            if fam not in names:
                probs.append(('K1', f'{fam}: exported on /metrics, not in the registry'))
    src = mine_source(root)
    for n, e in names.items():
        s = e.get('source', '')
        if s not in ('dynamic', 'vendored') and n in src and src[n]['source'] != s:
            probs.append(('K4', f'{n}: declared in {src[n]["source"]}, registry says {s}'))
        elif s not in ('dynamic', 'vendored') and n not in src and not (root / s).exists():
            probs.append(('K4', f'{n}: its source {s} no longer exists'))
    if docs:
        doc = root / 'cmd' / 'derod' / 'rpc' / 'RPC_METHODS.md'
        for tok in sorted(set(METRIC_TOKEN.findall(doc.read_text(encoding='utf-8')))):
            if tok not in names and not any(tok == x + suf for x in names for suf in ('_bucket', '_sum', '_count')):
                probs.append(('K5', f'RPC_METHODS.md names `{tok}`, not a registered family'))
    return probs


def naming_report(reg):
    """report-only naming findings: non-base units and upstream counters without _total. Pure."""
    out = []
    for e in reg['families']:
        if e['unit'] in NON_BASE:
            out.append(f"{e['name']}: unit {e['unit']} (Prometheus base unit: seconds/ratio)")
        if e['name'].startswith(UPSTREAM) and e['type'] == 'counter' and not e['name'].endswith('_total'):
            out.append(f"{e['name']}: upstream counter without _total (kept: vendored name)")
    return out


def rft_doc_names(root, names):
    p = root / 'artifacts' / 'dero-rft.md'
    if not p.exists():
        return []
    return sorted(t for t in set(METRIC_TOKEN.findall(p.read_text(encoding='utf-8'))) if t not in names)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0], formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__)
    ap.add_argument('cmd', choices=['build', 'check'])
    ap.add_argument('--scrape')
    ap.add_argument('--out', default=str(OUT))
    ap.add_argument('--root', default=str(ROOT))
    ap.add_argument('--docs', action='store_true')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args(argv)
    root = Path(a.root)
    text = Path(a.scrape).read_text(encoding='utf-8') if a.scrape else None
    out = Path(a.out)
    if a.cmd == 'build':
        if text is None:
            ap.error('build needs --scrape (a /metrics capture file)')
        old = json.loads(out.read_text(encoding='utf-8')) if out.exists() else None
        reg = build(root, text, old)
        out.write_text(json.dumps(reg, indent=1, sort_keys=True) + '\n', encoding='utf-8')
        n = len(reg['families'])
        hs = sum(1 for e in reg['families'] if e['help_source'] != 'name')
        print(f'metric_registry: {n} families ({sum(e["in_scrape"] for e in reg["families"])} in the scrape, '
              f'{n - sum(e["in_scrape"] for e in reg["families"])} source-only), help from a comment/hand {hs}, from the name {n - hs} -> {out}')
        return 0
    reg = json.loads(out.read_text(encoding='utf-8'))
    probs = check(reg, root, text, a.docs)
    names = {e['name'] for e in reg['families']}
    rep = {'families': len(reg['families']), 'problems': [f'{k} {m}' for k, m in probs], 'naming': naming_report(reg),
           'rft_names_not_registered': rft_doc_names(root, names) if a.docs else None}
    if a.json:
        print(json.dumps(rep, indent=1))
    else:
        for p in rep['problems']:
            print('FAIL', p)
        for p in rep['naming']:
            print('NOTE', p)
        if rep['rft_names_not_registered']:
            print(f"NOTE dero-rft.md names {len(rep['rft_names_not_registered'])} metric-like tokens not registered "
                  f"(history or other processes; report only): {', '.join(rep['rft_names_not_registered'][:40])}")
        print(f"metric_registry check: {rep['families']} families, {len(probs)} problems, {len(rep['naming'])} naming notes")
    return 3 if probs else 0


if __name__ == '__main__':
    sys.exit(main())
