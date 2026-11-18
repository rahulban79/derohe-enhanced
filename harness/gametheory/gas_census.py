#!/usr/bin/env python3
"""gas_census.py — r33 GT-B3 (artifacts/dero-game-theory-rft.md §7, §8.2 R33-W3): the per-entrypoint fee census of the
game-theory contracts, from the records the cycles already wrote. Nothing is fetched, nothing is sent.

Inputs: every harness/runtime/gt_cycle_mainnet_*.json and gt_pool_*_*.json record. Their `calls` (and, for gt_pool
records, `proofs`) lists carry per call: sc, entry, gas_est {gascompute, gasstorage} (DERO.GetGasEstimate, read-only,
since R32a), fees_set (the fee the cycle asked for; null = the wallet's default) and fee (the fee actually paid).
Lesson 24: the storage-gas limit IS the fee (blockchain/transaction_execute.go passes tx.Fees() as gasstorage), so the
margin fee - gasstorage is what keeps a call from reverting with 'Insufficient Storage Gas'.

Per network class (mainnet / sim: a record whose `network` is not mainnet is counted separately, never mixed) and per
contract:entrypoint:
  calls                 every recorded call
  with_gas_est          the calls that carry a gas estimate (older records do not)
  gasstorage            min / median / max over those
  gascompute            min / median / max over those
  fee                   min / median / max of the fee actually paid (every call with a fee)
  fee_minus_gasstorage  min / median / max over the calls with both (negative = paid below the estimate)
  fees_set              how many calls set the fee explicitly
Writes harness/runtime/gt_gas_census_mainnet.json (sorted keys; record names only, no txid, no address) and prints the
table.

  python3 -I harness/gametheory/gas_census.py [--runtime DIR] [--out FILE] [--no-write]
Exit 0 · 2 no record found · 6 an address would be written.
"""
import argparse, glob, json, re, statistics, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
RUNTIME = ROOT / 'harness/runtime'
OUT = RUNTIME / 'gt_gas_census_mainnet.json'
PATTERNS = ('gt_cycle_mainnet_*.json', 'gt_pool_*_*.json')
LISTS = ('calls', 'proofs')
ADDR_RX = re.compile(r'de[rt]o1[0-9a-z]{20,}')


def records(runtime=RUNTIME):
    """[(file name, record)] of every census input, sorted by name; unreadable files are skipped (reported)."""
    out, bad = [], []
    for pat in PATTERNS:
        for f in sorted(glob.glob(str(Path(runtime) / pat))):
            try:
                d = json.loads(Path(f).read_text())
            except (OSError, ValueError):
                bad.append(Path(f).name)
                continue
            if isinstance(d, dict):
                out.append((Path(f).name, d))
    seen, uniq = set(), []
    for n, d in out:
        if n not in seen:
            seen.add(n)
            uniq.append((n, d))
    return sorted(uniq), bad


def net_class(rec):
    """'mainnet' only for a record that says so; every other network (sim, testnet, absent) is 'sim'. Pure."""
    return 'mainnet' if str(rec.get('network', '')).lower() == 'mainnet' else 'sim'


def _stats(xs):
    if not xs:
        return None
    return {'min': min(xs), 'median': statistics.median(xs), 'max': max(xs), 'n': len(xs)}


def _int(v):
    try:
        return None if v is None or isinstance(v, bool) else int(v)
    except (TypeError, ValueError):
        return None


def census(recs):
    """{net: {'records': [...], 'entrypoints': {'sc:entry': row}}} from [(name, record)]. Pure."""
    acc = {}
    for name, rec in recs:
        net = net_class(rec)
        a = acc.setdefault(net, {'records': [], 'rows': {}})
        a['records'].append(name)
        for lst in LISTS:
            for c in rec.get(lst) or []:
                if not isinstance(c, dict) or not c.get('entry'):
                    continue
                k = f"{c.get('sc') or '?'}:{c['entry']}"
                r = a['rows'].setdefault(k, {'calls': 0, 'gs': [], 'gc': [], 'fee': [], 'margin': [], 'fees_set': 0, 'records': set()})
                r['calls'] += 1
                r['records'].add(name)
                ge = c.get('gas_est') if isinstance(c.get('gas_est'), dict) else {}
                gs, gc, fee = _int(ge.get('gasstorage')), _int(ge.get('gascompute')), _int(c.get('fee'))
                if gs is not None:
                    r['gs'].append(gs)
                if gc is not None:
                    r['gc'].append(gc)
                if fee is not None:
                    r['fee'].append(fee)
                if gs is not None and fee is not None:
                    r['margin'].append(fee - gs)
                if _int(c.get('fees_set')) is not None:
                    r['fees_set'] += 1
    out = {}
    for net, a in sorted(acc.items()):
        rows = {}
        for k, r in sorted(a['rows'].items()):
            rows[k] = {'calls': r['calls'], 'with_gas_est': len(r['gs']), 'gasstorage': _stats(r['gs']),
                       'gascompute': _stats(r['gc']), 'fee': _stats(r['fee']), 'fee_minus_gasstorage': _stats(r['margin']),
                       'fees_set': r['fees_set'], 'records': len(r['records'])}
        out[net] = {'records': sorted(a['records']), 'calls': sum(r['calls'] for r in rows.values()), 'entrypoints': rows}
    return out


def _fmt(s, key):
    if not s:
        return '-'
    v = s[key]
    return str(int(v)) if float(v).is_integer() else f'{v:.1f}'


def table(c):
    """the printed census: one line per network class and contract:entrypoint. Pure."""
    head = (f"{'net':<8}{'sc:entry':<26}{'calls':>6}{'gas_n':>6}{'gs_min':>8}{'gs_med':>8}{'gs_max':>8}"
            f"{'fee_min':>8}{'fee_med':>8}{'fee_max':>8}{'mrg_min':>8}{'mrg_med':>8}{'mrg_max':>8}")
    lines = [head, '-' * len(head)]
    for net, d in c.items():
        for k, r in d['entrypoints'].items():
            lines.append(f"{net:<8}{k:<26}{r['calls']:>6}{r['with_gas_est']:>6}"
                         + ''.join(f'{_fmt(r[f], q):>8}' for f in ('gasstorage', 'fee', 'fee_minus_gasstorage')
                                   for q in ('min', 'median', 'max')))
        lines.append(f"{net:<8}{'(total)':<26}{d['calls']:>6}  records {len(d['records'])}")
    return '\n'.join(lines)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--runtime', default=str(RUNTIME))
    ap.add_argument('--out', default=str(OUT))
    ap.add_argument('--no-write', action='store_true')
    a = ap.parse_args(argv)
    recs, bad = records(a.runtime)
    if not recs:
        print('gas_census: no gt_cycle_mainnet_*.json / gt_pool_*_*.json record found')
        return 2
    c = census(recs)
    doc = {'record': 'r33 GT-B3 per-entrypoint gas and fee census (harness/gametheory/gas_census.py)',
           'inputs': list(PATTERNS), 'unreadable': bad,
           'note': 'fee = the fee actually paid; fee_minus_gasstorage < 0 means a call paid below its storage-gas '
                   'estimate (lesson 24: the storage-gas limit is the fee); sim records are counted apart from mainnet',
           'census': c}
    text = json.dumps(doc, indent=1, sort_keys=True) + '\n'
    if ADDR_RX.search(text):
        print('gas_census: refused: an address would be written')
        return 6
    print(table(c))
    if not a.no_write:
        Path(a.out).write_text(text)
        print(f'\nwrote {Path(a.out).name}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
