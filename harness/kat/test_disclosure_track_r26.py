#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the r26 additions to the disclosure track (harness/intel/disclosure_track.py;
artifacts/dero-rft.md §0.5 and §0.8.9 FQ4-FQ6; no network, nothing written into the tree).

  DT10 an INTERPRETATION fact (FQ5: an argument from source, rft §0.8.2) passes only with at least two resolving non-EXT
       anchors and a `refuted_if` text: with one anchor it FAILS, with two anchors on the same line it FAILS, without
       refuted_if it FAILS, with an anchor only under harness/external it FAILS; the well-formed one PASSES.
  DT11 the committed R26 track: current_round R26 with an R26 entry on every claim; NF26-3 (FQ5) is an INTERPRETATION
       with refuted_if, and the page model carries refuted_if; FX-F5 and FX-F6 are FORK-REQUIRED designs that state
       a coordinated fork and what holders pay; FX-N10 (the structural transcript KAT) is implemented in the Go test
       file and every R26 entry and fact resolves.

  python3 -I harness/kat/test_disclosure_track_r26.py   # KATs, then each mutation on a temp copy must flip its KAT
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import copy, importlib.util, json, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
MOD = 'intel/disclosure_track.py'


def load(base):
    spec = importlib.util.spec_from_file_location(f'dt26_{id(base)}_{len(sys.modules)}', base / MOD)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def copy_mod():
    d = Path(tempfile.mkdtemp(prefix='dt26_kat_')) / 'harness'
    (d / 'intel').mkdir(parents=True)
    shutil.copy2(HARNESS / MOD, d / MOD)
    return d


A1 = {'file': 'cryptography/crypto/proof_verify.go', 'line': 430, 'quote': 'u_x := new(bn256.G1).ScalarMult(gparams.H, o)'}
A2 = {'file': 'blockchain/supply.go', 'line': 5, 'quote': 'func CalcSupply(height uint64) uint64 {'}
A2b = {'file': 'cryptography/crypto/proof_verify.go', 'line': 430, 'quote': 'ScalarMult(gparams.H, o)'}
EXT = {'file': 'harness/external/derofoundation-press-20261020.txt', 'line': 1, 'quote': 'DERO Foundation press page'}


def track_with(fact):
    claim = {'id': 'CX', 'title': 't', 'press': [], 'history': [
        {'round': 'R26', 'verdict': 'CONFIRMED', 'state': 'upstream', 'why': 'the forged claim of the r26 KAT, anchored',
         'anchors': [A1]}]}
    return {'rounds': ['R26'], 'current_round': 'R26', 'press_map': {}, 'claims': [claim], 'facts': [fact], 'fixes': []}


def fact(anchors, refuted_if='a public test that the verifier does not already imply is exhibited'):
    f = {'id': 'NFX-1', 'round': 'R26', 'title': 't', 'text': 'an interpretation from source', 'status': 'INTERPRETATION',
         'anchors': anchors, 'claims': ['CX']}
    if refuted_if is not None:
        f['refuted_if'] = refuted_if
    return f


def kat_dt10(base):
    m = load(base)
    bad = []
    good = m.evaluate(track_with(fact([A1, A2])), root=ROOT)
    if not good['ok']:
        bad.append(f'well-formed INTERPRETATION failed: {good["why"][:2]}')
    for label, f in (('one anchor', fact([A1])), ('two anchors on one line', fact([A1, A2b])),
                     ('no refuted_if', fact([A1, A2], refuted_if=None)), ('short refuted_if', fact([A1, A2], refuted_if='maybe')),
                     ('EXT as second anchor', fact([A1, EXT]))):
        if m.evaluate(track_with(f), root=ROOT)['ok']:
            bad.append(f'{label} passed')
    return not bad, '; '.join(bad) or '1 well-formed PASS, 5 forged FAIL'


def kat_dt11(base):
    m = load(base)
    t = json.loads((HARNESS / 'loop/disclosure_track.json').read_text())
    bad = []
    rr = t.get('rounds') or []   # r30 (B214): the track moved on (R30); R26 stays booked and every claim keeps its R26 entry
    if 'R26' not in rr or t.get('current_round') not in rr or rr.index(t['current_round']) < rr.index('R26'):
        bad.append(f'current_round {t.get("current_round")}')
    for c in t['claims']:
        if not any(h['round'] == 'R26' for h in c['history']):
            bad.append(f'{c["id"]} has no R26 entry')
    facts = {f['id']: f for f in t['facts']}
    fq5 = facts.get('NF26-3') or {}
    if fq5.get('status') != 'INTERPRETATION' or len(m.norm(fq5.get('refuted_if'))) < 20:
        bad.append('NF26-3 is not an INTERPRETATION with refuted_if')
    model = m.emit_model(t, ROOT)
    row = next((r for r in model['rows'] if r['id'] == 'dt-fact-nf26-3'), {})
    if not row.get('refuted_if'):
        bad.append('the page model drops refuted_if')
    fixes = {x['id']: x for x in t['fixes']}
    for fid in ('FX-F5', 'FX-F6'):
        x = fixes.get(fid) or {}
        if x.get('kind') != 'FORK-REQUIRED' or x.get('status') != 'design':
            bad.append(f'{fid} is not a FORK-REQUIRED design')
        if 'coordinated' not in (x.get('design', '') + x.get('compat', '')).lower() or 'holder' not in x.get('compat', '').lower():
            bad.append(f'{fid} does not state the coordinated fork and the holders\' cost')
    n10 = fixes.get('FX-N10') or {}
    if n10.get('status') != 'implemented' or n10.get('implemented_in') != 'cryptography/crypto/r26_transcript_binding_test.go':
        bad.append('FX-N10 is not implemented in the transcript KAT')
    r = m.evaluate(t, root=ROOT)
    r26bad = [b for b in r['bad'] if '@R26' in b['where'] or 'NF26' in b['where'] or b['where'] in ('fix FX-F5', 'fix FX-F6', 'fix FX-N10')]
    if r26bad or not r['ok']:
        bad.append(f'evaluation: ok={r["ok"]} r26 anchors bad {r26bad[:3]} why {r["why"][:2]}')
    return not bad, '; '.join(bad) or f'R26 on {len(t["claims"])} claims, FQ5 INTERPRETATION, FX-F5/F6 designs, FX-N10'


KATS = [('DT10', kat_dt10), ('DT11', kat_dt11)]

MUTATIONS = [
    ('DT10', "            if len({(r['file'], r['line']) for r in own}) < INTERP_MIN_ANCHORS:",
     "            if False:", 'an INTERPRETATION with one anchor passes'),
    ('DT10', "            if len(norm(f.get('refuted_if'))) < 20:", "            if False:",
     'an INTERPRETATION need not say what refutes it'),
    ('DT10', "            if len({(r['file'], r['line']) for r in own}) < INTERP_MIN_ANCHORS:",
     "            if len(own) < INTERP_MIN_ANCHORS:", 'two anchors on one line count as two'),
    ('DT10', "FACT_STATUS = ('CONFIRMED', 'MEASURED', 'PLAUSIBLE', 'INTERPRETATION', 'pending')",
     "FACT_STATUS = ('CONFIRMED', 'MEASURED', 'PLAUSIBLE', 'pending')", 'INTERPRETATION is not a fact status'),
    ('DT11', "                     **({'refuted_if': f['refuted_if']} if f.get('refuted_if') else {})})",
     "                     })", 'the page model drops refuted_if'),
]


def main():
    fails = 0
    base = copy_mod()
    byname = dict(KATS)
    for name, fn in KATS:
        try:
            ok, det = fn(base)
        except Exception as e:                                    # noqa: BLE001
            ok, det = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:400]}")
    shutil.rmtree(base.parent, ignore_errors=True)
    missed = 0
    for kat, find, repl, why in MUTATIONS:
        d = copy_mod()
        p = d / MOD
        text = p.read_text()
        if text.count(find) != 1:
            print(f'  ??      {kat}: {why} — find text occurs {text.count(find)} times')
            missed += 1
            shutil.rmtree(d.parent, ignore_errors=True)
            continue
        p.write_text(text.replace(find, repl))
        try:                                                        # a mutant that does not load is INVALID, never CAUGHT
            load(d)
        except Exception as e:                                      # noqa: BLE001
            print(f'  INVALID {kat}: {why} — mutant does not load ({type(e).__name__}: {e})')
            missed += 1
            shutil.rmtree(d.parent, ignore_errors=True)
            continue
        try:
            ok, _ = byname[kat](d)
        except Exception:                                           # noqa: BLE001 — a crash under mutation flips the KAT
            ok = False
        shutil.rmtree(d.parent, ignore_errors=True)
        if ok:
            print(f'  MISSED  {kat}: {why}')
            missed += 1
        else:
            print(f'  proved  {kat}: {why}')
    print(f'\nr26 disclosure-track KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
