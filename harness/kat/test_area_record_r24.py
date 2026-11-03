#!/usr/bin/env python3
"""Known-answer test + mutation proofs for area_intel.recordable (r24 merge: `area_intel.py record r24` crashed with
AttributeError: 'list' object has no attribute 'get' on the '_unregistered' bookkeeping key of auto_round).

  AR2 recordable on a forged area: a measured anchored entry is booked; a pending one, an unanchored one, a
      '_unregistered' list and a non-dict value are not, and nothing raises.
  AR3 bookable: a recomputed metric (AUTO id or RECOMP kind) is booked; a prom reading stated on its line is booked; a
      derived ratio, a labelled-series sum and a row count whose line does not state the value are refused (record
      r24 once booked six such values and `area_intel.py check` then failed, AI9).
  AR4 live_belongs: an entry without live_round, and one whose capture's binary round is the round being recorded, may
      be booked; a reading of the r23c binary is never booked to r24 (§0.4).

  python3 -I harness/kat/test_area_record_r24.py
Exit 0 all ok · 3 the KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import importlib.util, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
SRC = HARNESS / 'intel' / 'area_intel.py'
AN = {'file': 'f', 'quote': 'q', 'line': 1}


def load(path):
    spec = importlib.util.spec_from_file_location(f'ai_{abs(hash(str(path)))}', path)
    m = importlib.util.module_from_spec(spec)
    sys.path[:0] = [str(HARNESS / 'intel'), str(HARNESS / 'kit'), str(HARNESS)]
    try:
        spec.loader.exec_module(m)
    finally:
        del sys.path[:3]
    return m


def ar2(m):
    ms = {'good': {'value': 3, 'anchor': AN}, 'pend': {'value': 'pending', 'why': 'x'}, 'noanchor': {'value': 2},
          '_unregistered': ['p/TestR24X'], 'odd': ['not', 'a', 'dict'], '_meta': {'value': 1, 'anchor': AN}}
    try:
        got = [k for k, _ in m.recordable(ms)]
    except Exception as e:                                        # noqa: BLE001
        return False, f'raised {type(e).__name__}: {e}'
    return got == ['good'], f'booked {got}'


def ar3(m):
    rk = next(iter(m.RECOMP))
    cases = [
        (m.bookable({'value': 5}, 'mutations', None, '', 'x'), True),
        (m.bookable({'value': 5}, 'some', rk, '', 'x'), True),
        (m.bookable({'value': 34}, 'dead', 'prom', '', 'getwork_dead_normal_jobs_total 34 || q'), True),
        (m.bookable({'value': 0.1429}, 'ratio', 'prom_ratio', '', 'getwork_dead_normal_jobs_total 34 || q'), False),
        (m.bookable({'value': 233497.0}, 'sum', 'prom', '', 'rpc_requests_total{method="DERO.Echo"} 12 || q'), False),
        (m.bookable({'value': 7}, 'rows', 'raw_count', '', '"audit_verdict": "CONFIRMED", || q'), False),
    ]
    got = [bool(c[0][0]) for c in cases]
    return got == [w for _, w in cases], f'got {got}'


def ar4(m):
    got = [m.live_belongs({'value': 1}, 'r24'), m.live_belongs({'value': 1, 'live_round': 'r24'}, 'r24'),
           m.live_belongs({'value': 1, 'live_round': 'R24'}, 'r24'), m.live_belongs({'value': 1, 'live_round': 'r23c'}, 'r24')]
    return got == [True, True, True, False], f'got {got}'


MUTATIONS = [
    ("        if k.startswith('_') or not isinstance(e, dict):\n            continue\n", '', 'bookkeeping keys booked / crash'),
    ("        if is_pending(e.get('value')) or not e.get('anchor'):\n            continue\n        out.append",
     "        out.append", 'pending or unanchored values booked'),
    ("k.startswith('_') or not isinstance(e, dict)", "not isinstance(e, dict)", "a '_' dict entry booked as history"),
    ("    ok, how = backed(ent, text, unit)\n    return ok, how\n", "    return True, 'unchecked'\n",
     'a value its line does not state is booked'),
    ("    if mid in AUTO or kind in RECOMP:\n        return True, 'recomputed'\n", "",
     'a recomputed value is refused (would leave AUTO history pending)'),
    ("    return lr is None or str(lr).lower() == str(rid).lower()", "    return True", 'an r23c live reading booked to r24'),
    ("    return lr is None or str(lr).lower() == str(rid).lower()", "    return lr is None",
     "the current binary's own live reading refused"),
]


def main():
    mod = load(SRC)
    ok = True
    for name, fn in (('AR2', ar2), ('AR3', ar3), ('AR4', ar4)):
        o, det = fn(mod)
        print(f"{'ok  ' if o else 'FAIL'} {name} {det}")
        ok = ok and o
    if not ok:
        return 3
    src, missed = SRC.read_text(encoding='utf-8'), 0
    for find, repl, why in MUTATIONS:
        if src.count(find) != 1:
            print(f'  ??      AR2: {why} — find text occurs {src.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'area_intel.py'
            p.write_text(src.replace(find, repl, 1), encoding='utf-8')
            try:
                m = load(p)
            except Exception as e:                                # noqa: BLE001
                print(f'  INVALID AR2: {why} — mutant does not load ({type(e).__name__})')
                missed += 1
                continue
            ok2 = ar2(m)[0] and ar3(m)[0] and ar4(m)[0]
        print(f"  {'proved ' if not ok2 else 'MISSED '} AR2-AR4: {why}")
        missed += ok2
    print(f'\nr24 area-record KATs: 3/3 ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
