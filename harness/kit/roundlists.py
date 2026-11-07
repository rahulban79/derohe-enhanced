#!/usr/bin/env python3
"""roundlists.py — r28 (rft §7 B149, lesson #80): every round list carries the open round.

A round opened in one registry is not opened in every registry. R27 Part D set harness/round.json r27 but not
harness/areas.json `rounds`, so area_intel booked every r27 capture to round 'unknown' and `record r27` failed `check`
with 18 errors (B149). The lists that must name a round, read from the tree (never from memory):

  registry   harness/round.json rounds[].id                 (the source: current + every non-planned round)
  areas      harness/areas.json rounds[].id                 (area_intel capture_round / record / check)
  ledger     artifacts/src/gen_ledger.py LAST_CHOICES         (a numeric round N -> N; 'r23c' style rounds are not pages)
  evolution  harness/miners/mine_evolution.py ORDER           ('R<N>' / 'R23b' labels; also the next planned round)

check(root) returns one problem line per (list, round) that is missing: the current round must be in all four; every
non-planned registry round must be in areas and evolution; the registry's next planned round must be in evolution
(B90: before its first 'R<N>' commit lands). Read-only; the file lists are parsed with ast (no tool is imported).

  python3 -I harness/kit/roundlists.py [--root DIR]     # exit 0 every list complete · 5 a list misses a round · 2 unreadable
"""
import ast, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
FILES = {'registry': 'harness/round.json', 'areas': 'harness/areas.json', 'ledger': 'artifacts/src/gen_ledger.py',
         'evolution': 'harness/miners/mine_evolution.py'}


def _assigned(text, name):
    """the literal values assigned or `+=`-extended to `name` at module level, in order (tuple/list/range/f-string
    comprehensions of R<n> evaluated). Pure."""
    out = []
    tree = ast.parse(text)
    for node in tree.body:
        tgt = val = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            tgt, val, aug = node.targets[0].id, node.value, False
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            tgt, val, aug = node.target.id, node.value, True
        if tgt != name:
            continue
        vals = _eval(val)
        out = (out + vals) if aug else vals
    return out


def _eval(node):
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _eval(node.left) + _eval(node.right)
    if isinstance(node, (ast.List, ast.Tuple)):
        return [e.value for e in node.elts if isinstance(e, ast.Constant)]
    if isinstance(node, ast.ListComp) and isinstance(node.elt, ast.JoinedStr):      # [f'R{n}' for n in range(a, b)]
        gen = node.generators[0]
        if isinstance(gen.iter, ast.Call) and getattr(gen.iter.func, 'id', '') == 'range':
            a, b = (x.value for x in gen.iter.args[:2])
            pre = ''.join(v.value for v in node.elt.values if isinstance(v, ast.Constant))
            return [f'{pre}{n}' for n in range(a, b)]
    return []


def read_lists(root=ROOT):
    """{list: [round ids as the list names them]} plus the registry's current / planned ids. Raises OSError/ValueError
    when a file is unreadable."""
    root = Path(root)
    reg = json.loads((root / FILES['registry']).read_text())
    areas = json.loads((root / FILES['areas']).read_text())
    return {'registry': [r['id'] for r in reg.get('rounds', [])],
            'current': reg.get('current'),
            'planned': [r['id'] for r in reg.get('rounds', []) if r.get('status') == 'planned'],
            'areas': [r['id'] for r in areas.get('rounds', [])],
            'ledger': _assigned((root / FILES['ledger']).read_text(), 'LAST_CHOICES'),
            'evolution': _assigned((root / FILES['evolution']).read_text(), 'ORDER')}


def ledger_number(rid):
    """'r28' -> 28; 'r23c' / 'r23b' -> None (sub-rounds are not ledger pages). Pure."""
    m = re.fullmatch(r'r(\d+)', str(rid or ''))
    return int(m.group(1)) if m else None


def evolution_label(rid):
    """'r28' -> 'R28', 'r23c' -> 'R23c'. Pure."""
    return 'R' + str(rid)[1:]


def problems(L):
    """the missing (list, round) lines of read_lists() output. Pure."""
    out = []
    cur = L.get('current')
    if not cur or cur not in L['registry']:
        return [f'registry: current round {cur!r} is not a registry round']
    nonplanned = [r for r in L['registry'] if r not in L['planned']]
    for rid in nonplanned:
        if rid not in L['areas']:
            out.append(f'areas: {rid} missing from {FILES["areas"]} rounds')
        if evolution_label(rid) not in L['evolution']:
            out.append(f'evolution: {evolution_label(rid)} missing from {FILES["evolution"]} ORDER')
    n = ledger_number(cur)
    if n is not None and n not in L['ledger']:
        out.append(f'ledger: {n} missing from {FILES["ledger"]} LAST_CHOICES (current round {cur})')
    order = L['registry']
    nxt = [r for r in L['planned'] if order.index(r) > order.index(cur)]
    if nxt and evolution_label(nxt[0]) not in L['evolution']:
        out.append(f'evolution: next planned {evolution_label(nxt[0])} missing from {FILES["evolution"]} ORDER (B90)')
    return out


def check(root=ROOT):
    return problems(read_lists(root))


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    root = Path(argv[argv.index('--root') + 1]) if '--root' in argv else ROOT
    try:
        L = read_lists(root)
    except (OSError, ValueError, SyntaxError) as e:
        print(f'roundlists: unreadable ({type(e).__name__}: {e})')
        return 2
    P = problems(L)
    for p in P:
        print('MISSING', p)
    print(f"roundlists: current {L['current']} · registry {len(L['registry'])} · areas {len(L['areas'])} · ledger "
          f"{max(L['ledger']) if L['ledger'] else 'none'} · evolution {L['evolution'][-1] if L['evolution'] else 'none'} · "
          f"missing {len(P)}")
    return 5 if P else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
