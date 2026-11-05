#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for sealed anchors of volatile KPI sources in the area history
(harness/intel/area_intel.py seal_volatile; R26 closed loop, pipeline_20261104T193301 S7 FAIL).

S7's facts step rewrites harness/runtime/forensics_intel.json every run; from R26 it holds dataset v2's KPIs, so the 14
r25 forensics values recorded against it (audit_holds 24, grade_pending 1, ...) no longer resolved and area_intel --live
exited 2 with 7 'anchor-broken' high proposals. The B106 class (consensus_intel.json) again, for the forensics source.

  AS1 record() books a forensics KPI against the round's sealed copy harness/runtime/forensics_intel_<round>.json; after
      forensics_intel.json is rewritten with other values the recorded anchor still resolves (status OK) and states the
      recorded value
  AS2 the real tree: every history anchor of area `forensics` resolves, and none points at the volatile file

  python3 -I harness/kat/test_area_seal_r26.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import importlib.util, json, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
SRC = HARNESS / 'intel' / 'area_intel.py'
VOL = 'harness/runtime/forensics_intel.json'


def load(path):
    spec = importlib.util.spec_from_file_location(f'as26_{abs(hash(str(path)))}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def tree(d):
    r = Path(d)
    (r / 'harness/runtime').mkdir(parents=True)
    (r / 'harness/loop/runs').mkdir(parents=True)
    reg = {'rounds': [{'id': 'r25'}, {'id': 'r26'}], 'areas': [
        {'id': 'forensics', 'title': 'f', 'owner_dim': 'f', 'status': 'active', 'code_paths': [], 'kat_files': [], 'gates': [],
         'gomut_prefixes': [], 'backlog': [], 'metrics': [{'id': 'audit_holds', 'source': {'kind': 'forensics', 'field': 'audit_holds'}}],
         'history': {}}]}
    (r / 'harness/areas.json').write_text(json.dumps(reg))
    (r / 'harness/round.json').write_text(json.dumps({'current': 'r25', 'rounds': [{'id': 'r25', 'status': 'in-progress'}]}))
    (r / VOL).write_text(json.dumps({'kpis': {'audit_holds': 24, 'audit_fails': 0}}, indent=1))
    return r


def as1(m):
    out = {}
    with tempfile.TemporaryDirectory() as d:
        r = tree(d)
        m.record(r, 'r25')
        h = json.loads((r / 'harness/areas.json').read_text())['areas'][0]['history'].get('r25', {}).get('audit_holds') or {}
        a = h.get('anchor') or {}
        out['booked'] = h.get('value') == 24
        out['sealed'] = a.get('file') == 'harness/runtime/forensics_intel_r25.json'
        (r / VOL).write_text(json.dumps({'kpis': {'audit_holds': 20, 'audit_fails': 3, 'extra': 1}}, indent=1))
        st = m.resolve_anchor(r, a) if a else {'status': 'NONE'}
        out['resolves'] = st.get('status') == 'OK'
        out['states'] = st.get('status') == 'OK' and '24' in (r / a['file']).read_text().splitlines()[st['line'] - 1]
    return all(out.values()), f'{out}'


def as2(m):
    reg = json.loads((ROOT / 'harness/areas.json').read_text())
    bad, vol, n = [], [], 0
    for a in reg['areas']:
        if a['id'] != 'forensics':
            continue
        for rid, h in a.get('history', {}).items():
            for k, e in h.items():
                if not isinstance(e, dict) or not e.get('anchor'):
                    continue
                n += 1
                if e['anchor'].get('file') == VOL:
                    vol.append(f'{k}@{rid}')
                if m.resolve_anchor(ROOT, e['anchor']).get('status') != 'OK':
                    bad.append(f'{k}@{rid}')
    return n > 0 and not bad and not vol, f'{n} anchors, unresolved {bad[:5]}, on the volatile file {vol[:5]}'


KATS = [('AS1', as1), ('AS2', as2)]
MUTATIONS = [
    ("    sealed = seal_volatile(root, rid, vals)\n", "", 'record books against the volatile file'),
    ("        (Path(root) / dst).write_bytes((Path(root) / src).read_bytes())\n", "", 'the sealed copy is never written'),
    ("            e['anchor'] = {**e['anchor'], 'file': dst}\n", "            pass\n", 'anchors are not re-pointed at the sealed copy'),
]


def main():
    mod = load(SRC)
    ok = True
    for name, fn in KATS:
        try:
            o, det = fn(mod)
        except Exception as e:                                    # noqa: BLE001
            o, det = False, f'{type(e).__name__}: {e}'
        print(f"{'ok  ' if o else 'FAIL'} {name} {det[:400]}")
        ok &= o
    if not ok:
        return 3
    src, missed = SRC.read_text(encoding='utf-8'), 0
    for find, repl, why in MUTATIONS:
        if src.count(find) != 1:
            print(f'  ??      {why}: find text occurs {src.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'area_intel.py'
            p.write_text(src.replace(find, repl, 1), encoding='utf-8')
            try:
                mm = load(p)
            except Exception as e:                                # noqa: BLE001
                print(f'  INVALID {why}: mutant does not load ({type(e).__name__})')
                missed += 1
                continue
            try:
                survived = as1(mm)[0]
            except Exception:                                     # noqa: BLE001 — a crash is a detection
                survived = False
        print(f"  {'MISSED ' if survived else 'proved '} {why}")
        missed += survived
    print(f'\nr26 area-seal KATs: {len(KATS)}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
