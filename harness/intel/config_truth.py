#!/usr/bin/env python3
"""config_truth.py (r28, group p2p-config; dero-rft §0.6 artifact contract, §7 B30/B48/B99/B141) — documented vs used.

Every number the round prompt states about the p2p and config rules (a hold of 30 s, a 4,096-entry proven lane, a
10/s accept budget, LAGGING_PEER_BLOCKS 25, the 50 ms future-timestamp rule, HF3 at 7,504,640 ...) is a claim about
the code. This tool reads each value from the Go source (a small constant evaluator: int/float literals, typed
conversions, `N * time.Unit`, `1 << N`, one named constant), reads the same value from the sentence of
artifacts/dero-rft.md that states it, and reports per claim: AGREE, DRIFT (the text and the code differ), MISSING
(the source constant is gone: the claim needs a new anchor) or UNDOCUMENTED (the code has it, the text states no
value: informational). It also checks the build tag rule: config/version.go's build metadata must be the newest
version_suffix the round registry (harness/round.json) knows, i.e. the tree never carries a tag the registry has not
assigned and never falls more than one round behind it.

The derod --help text (Usage line and Options section) is checked against the code by the Go test
cmd/derod TestR28UsageDefaultsMatchCode (run with --go).

  python3 -I harness/intel/config_truth.py [--go] [--json OUT]
  exit 0 no DRIFT/MISSING and the tag rule holds · 3 otherwise
"""
import argparse, json, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
UNIT = {'time.Nanosecond': 1e-9, 'time.Microsecond': 1e-6, 'time.Millisecond': 1e-3, 'time.Second': 1, 'time.Minute': 60,
        'time.Hour': 3600}

# (id, go file, constant name or ('rx', regex with one group), unit of the code value, rft regex with one group, scale
# from the rft number to the code unit). The rft regex None = no stated value (UNDOCUMENTED when the code has it).
CLAIMS = [
    ('LAGGING_PEER_BLOCKS', 'p2p/metrics_preregister.go', 'LAGGING_PEER_BLOCKS', 'blocks', r'LAGGING_PEER_BLOCKS ([\d,]+)', 1),
    ('MAX_OUTBOUND_PER_NETGROUP', 'p2p/diversity.go', 'MAX_OUTBOUND_PER_NETGROUP', 'conns', r'MAX_OUTBOUND_PER_NETGROUP ([\d,]+)', 1),
    ('PROVEN_MAX', 'p2p/proven_lane.go', 'PROVEN_MAX', 'entries', r'proven-peer lane \(([\d,]+) entries\)', 1),
    ('PROVEN_MAX (B30 row)', 'p2p/proven_lane.go', 'PROVEN_MAX', 'entries', r'verified handshake \(([\d,]+) entries\)', 1),
    ('PROVEN_PER_NETGROUP', 'p2p/proven_lane.go', 'PROVEN_PER_NETGROUP', 'proofs', None, 1),
    ('SYNC_HOLD_BASE', 'p2p/peer_observe.go', 'SYNC_HOLD_BASE', 's', r'holds the peer ([\d,]+) s', 1),
    ('SYNC_STRIKE_FORGET', 'p2p/peer_observe.go', 'SYNC_STRIKE_FORGET', 's', r'a failure > ([\d,]+) min after the last hold ended', 60),
    ('INBOUND_ACCEPT_RATE', 'p2p/controller.go', 'INBOUND_ACCEPT_RATE', '/s', r'pre-TLS accept budget \(~([\d,.]+)/s all unknown inbound', 1),
    ('INBOUND_GROUP_RATE', 'p2p/controller.go', 'INBOUND_GROUP_RATE', '/s', r'all unknown inbound, ([\d,.]+)/s per /16', 1),
    ('future timestamp rule', 'blockchain/blockchain.go', ('rx', r'UnixMilli\(\) \+ (\d+)\)\)'), 'ms', r'the ([\d,]+) ms future-timestamp rule', 1),
    ('MAJOR_HF3_HEIGHT', 'config/config.go', ('rx', r'MAJOR_HF3_HEIGHT:\s+(\d+),'), 'height', r'to HF3 ([\d,]+)\)', 1),
    ('CHUNK_POW_SLOW', 'p2p/r28_chunk_pow.go', 'CHUNK_POW_SLOW', 's', None, 1),
]


def go_consts(src):
    """{name: expression text} for every `const NAME = EXPR` / `NAME = EXPR` line inside a const block. Pure."""
    out, in_block = {}, False
    for line in src.splitlines():
        s = re.sub(r'//.*$', '', line).strip()
        if s.startswith('const ('):
            in_block = True
            continue
        if in_block and s == ')':
            in_block = False
            continue
        m = re.match(r'^(?:const\s+)?([A-Za-z_]\w*)(?:\s+[\w.]+)?\s*=\s*(.+)$', s)
        if m and (s.startswith('const ') or in_block):
            out[m.group(1)] = m.group(2).strip()
    return out


def evaluate(expr, consts, depth=0):
    """The numeric value of a constant expression (durations in seconds), or None. Pure."""
    e = expr.strip()
    if depth > 4:
        return None
    m = re.fullmatch(r'(?:u?int(?:8|16|32|64)?|float64)\((.+)\)', e)
    if m:
        return evaluate(m.group(1), consts, depth + 1)
    if re.fullmatch(r'\d+', e):
        return int(e)
    if re.fullmatch(r'\d+\.\d*|\d*\.\d+', e):
        return float(e)
    m = re.fullmatch(r'(\d+)\s*<<\s*(\d+)', e)
    if m:
        return int(m.group(1)) << int(m.group(2))
    m = re.fullmatch(r'(.+?)\s*\*\s*(time\.\w+)', e)
    if m and m.group(2) in UNIT:
        v = evaluate(m.group(1), consts, depth + 1)
        return None if v is None else v * UNIT[m.group(2)]
    if e in UNIT:
        return UNIT[e]
    if re.fullmatch(r'[A-Za-z_]\w*', e) and e in consts:
        return evaluate(consts[e], consts, depth + 1)
    return None


def code_value(root, path, sym):
    f = Path(root) / path
    if not f.exists():
        return None
    src = f.read_text()
    if isinstance(sym, tuple):
        m = re.search(sym[1], src)
        return int(m.group(1)) if m else None
    c = go_consts(src)
    return evaluate(c[sym], c) if sym in c else None


def doc_value(text, rx, scale):
    if rx is None:
        return None
    m = re.search(rx, text)
    if not m:
        return 'absent'
    return float(m.group(1).replace(',', '')) * scale


def grade(code, doc):
    """AGREE / DRIFT / MISSING / UNDOCUMENTED. Pure."""
    if code is None:
        return 'MISSING'
    if doc is None:
        return 'UNDOCUMENTED'
    if doc == 'absent':
        return 'DRIFT'          # the sentence that stated the value is gone or reworded: re-anchor it
    return 'AGREE' if abs(float(code) - float(doc)) < 1e-9 else 'DRIFT'


def tag_rule(version_src, registry):
    """(ok, detail): the build metadata of config/version.go is the newest non-pending version_suffix up to the current
    round. Pure."""
    m = re.search(r'semver\.MustParse\("[^"+]+\+([^"]+)"\)', version_src)
    if not m:
        return False, 'no build metadata in config/version.go'
    tag = m.group(1)
    rounds = registry.get('rounds', [])
    cur = registry.get('current')
    known = []
    for r in rounds:
        if r.get('version_suffix') not in (None, '', 'pending'):
            known.append(r['version_suffix'])
        if r.get('id') == cur:
            break
    if not known:
        return False, 'the registry assigns no version_suffix'
    if tag not in known:
        return False, f'tag {tag} is not a version_suffix the registry assigned (newest {known[-1]})'
    if tag != known[-1]:
        return False, f'tag {tag} is behind the registry (newest {known[-1]})'
    return True, f'tag {tag} = newest registered suffix (current round {cur})'


def run(root=ROOT):
    rft = (Path(root) / 'artifacts' / 'dero-rft.md').read_text()
    rows = []
    for cid, path, sym, unit, rx, scale in CLAIMS:
        code = code_value(root, path, sym)
        doc = doc_value(rft, rx, scale)
        rows.append({'claim': cid, 'file': path, 'unit': unit, 'code': code, 'documented': doc, 'grade': grade(code, doc)})
    ok_tag, tag_detail = tag_rule((Path(root) / 'config' / 'version.go').read_text(),
                                  json.loads((Path(root) / 'harness' / 'round.json').read_text()))
    return rows, ok_tag, tag_detail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--go', action='store_true', help='also run cmd/derod TestR28UsageDefaultsMatchCode (help text vs code)')
    ap.add_argument('--json')
    a = ap.parse_args()
    rows, ok_tag, tag_detail = run()
    go = None
    if a.go:
        r = subprocess.run(['nice', '-n', '15', 'go', 'test', '-p', '1', '-count=1', '-run', '^TestR28Usage', './cmd/derod/'],
                           cwd=ROOT, capture_output=True, text=True, timeout=600)
        go = {'exit': r.returncode, 'tail': (r.stdout + r.stderr)[-1500:]}
    bad = [x for x in rows if x['grade'] in ('DRIFT', 'MISSING')]
    ok = not bad and ok_tag and (go is None or go['exit'] == 0)
    for x in rows:
        print(f"  {x['grade']:<12} {x['claim']:<28} code {x['code']} {x['unit']} · documented {x['documented']}")
    print(f"  {'ok  ' if ok_tag else 'FAIL'} build tag rule: {tag_detail}")
    if go is not None:
        print(f"  {'ok  ' if go['exit'] == 0 else 'FAIL'} derod --help vs code (TestR28UsageDefaultsMatchCode, exit {go['exit']})")
    rec = {'tool': 'harness/intel/config_truth.py', 'claims': rows, 'tag_rule': {'ok': ok_tag, 'detail': tag_detail}, 'help_text': go, 'ok': ok}
    if a.json:
        Path(a.json).write_text(json.dumps(rec, indent=1) + '\n')
    n = {g: sum(x['grade'] == g for x in rows) for g in ('AGREE', 'DRIFT', 'MISSING', 'UNDOCUMENTED')}
    print(f"config_truth: {'PASS' if ok else 'FAIL'} {n}")
    return 0 if ok else 3


if __name__ == '__main__':
    sys.exit(main())
