#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the r24 disclosure track (harness/intel/disclosure_track.py; no network,
nothing written into the tree: forged trees live in a temp dir).

  DT1 the committed track evaluates PASS on this checkout: every anchor resolves, every claim was re-tested in the
      current round, every press row is mapped, no exploit-like text, and harness/model/raw/disclosure.json is current.
  DT2 anchor drift cannot pass unseen: in a forged tree with one line inserted above an anchored line the anchor is
      DRIFT (with the new line), not OK; with the quote deleted it is MISSING and the evaluation FAILS.
  DT3 a verdict cannot change without evidence: a later round that flips a verdict with no anchor, with only the
      advisory (harness/external) as anchor, or with no why, FAILS; the same flip with a source anchor and a why PASSES.
  DT4 exploit-like content fails: each lint pattern catches its own trigger fragment (in a fact text, and in a rendered
      page section); the defensive vocabulary the audit needs ('mu is in no preimage', 'what must be bound') PASSES.
      The fragments below are bare trigger tokens with no technical content.
  DT5 the live cross-checks fail on forged readings: an inflated total_supply (S1), an auditor formula off by one unit
      (S2), an integrity RPC that disagrees with the auditor (S3, the CI24-1 shape), an open HF3 window (S4); the
      recomputed CalcSupply equals the auditor's formula_supply recorded in the committed live snapshot.
  DT6 the proof-scalar census: a synthetic NORMAL transaction laid out as transaction.go / proof_generate.go read it
      parses, a scalar equal to bn256.Order is counted non-canonical, Order-1 is not; a trailing byte is a parse error.
  DT7 vocabulary and coverage laws: a FORK-REQUIRED design that does not say 'coordinated', or is marked implemented,
      FAILS; an implemented NODE-LOCAL measure without implemented_in FAILS; a press row without a press_map entry FAILS;
      a claim with no entry for the current round FAILS.
  DT8 the model keeps only anchors the page can class (harness code files are dropped) and a changed track makes the
      committed model stale.
  DT9 (r24 verifier) the exit code carries the live and census readings: --live with a FAILing cross-check exits 3, with
      all checks passing exits 0, with an unreadable node (ok None) exits 0; --census with one scalar >= Order exits 3,
      with none exits 0 (the CLI is driven with the evaluation and the RPC readings stubbed: no network, nothing written).

  python3 -I harness/kat/test_disclosure_track_r24.py   # KATs, then each mutation on a temp copy must flip its KAT
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import copy, importlib.util, json, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
MOD = 'intel/disclosure_track.py'


def load(base):
    spec = importlib.util.spec_from_file_location(f'dt_{id(base)}_{len(sys.modules)}', base / MOD)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def copy_mod():
    d = Path(tempfile.mkdtemp(prefix='dt_kat_')) / 'harness'
    (d / 'intel').mkdir(parents=True)
    shutil.copy2(HARNESS / MOD, d / MOD)
    return d


def real():
    track = json.loads((HARNESS / 'loop/disclosure_track.json').read_text())
    legacy = {k: json.loads((HARNESS / f'model/raw/{k}.json').read_text()) for k in ('press', 'forensics')}
    return track, legacy


def mini(anchors, hist2=None, cur='R24'):
    """a one-claim track; hist2 is an optional second (current-round) entry"""
    h = [{'round': 'R8', 'verdict': 'CONFIRMED', 'state': 'open', 'why': 'the first entry of the forged claim, with its anchor',
          'anchors': anchors}]
    if hist2:
        h.append(hist2)
    return {'rounds': ['R8', 'R24'], 'current_round': cur, 'press_map': {},
            'claims': [{'id': 'CX', 'title': 't', 'press': [], 'history': h}], 'facts': [], 'fixes': []}


def kat_dt1(base):
    m = load(base)
    track, legacy = real()
    r = m.evaluate(track, root=ROOT, legacy=legacy)
    cur = json.loads((HARNESS / 'model/raw/disclosure.json').read_text())
    mc = m.model_current(track, cur, ROOT)
    return r['ok'] and mc and not r['bad'], f"ok={r['ok']} model_current={mc} anchors={r['anchor_status']} why={r['why'][:3]}"


SRCF = 'cryptography/crypto/proof_verify.go'
QUOTE = 'u_x := new(bn256.G1).ScalarMult(gparams.H, o)'


def forged_root(insert=False, delete=False):
    d = Path(tempfile.mkdtemp(prefix='dt_root_'))
    (d / Path(SRCF).parent).mkdir(parents=True)
    ls = (ROOT / SRCF).read_text().splitlines()
    i = next(k for k, l in enumerate(ls) if QUOTE in l)
    if insert:
        ls.insert(i, '// r24 KAT: an inserted line moves the anchor')
    if delete:
        ls[i] = '// r24 KAT: the anchored line is gone'
    (d / SRCF).write_text('\n'.join(ls) + '\n')
    return d, i + 1


def kat_dt2(base):
    m = load(base)
    d0, line = forged_root()
    a = [{'file': SRCF, 'line': line, 'quote': QUOTE}]
    ok0 = m.evaluate(mini(a, {'round': 'R24', 'verdict': 'CONFIRMED', 'state': 'open', 'why': '', 'anchors': a}), root=d0)
    d1, _ = forged_root(insert=True)
    r1 = m.evaluate(mini(a, {'round': 'R24', 'verdict': 'CONFIRMED', 'state': 'open', 'why': '', 'anchors': a}), root=d1)
    d2, _ = forged_root(delete=True)
    r2 = m.evaluate(mini(a, {'round': 'R24', 'verdict': 'CONFIRMED', 'state': 'open', 'why': '', 'anchors': a}), root=d2)
    for d in (d0, d1, d2):
        shutil.rmtree(d, ignore_errors=True)
    drift_ok = bool(r1['drift']) and all(x['now'] == line + 1 for x in r1['drift']) and r1['anchor_status'].get('OK', 0) == 0
    miss_why = any(w.startswith('anchor MISSING') for w in r2['why'])
    ok = ok0['ok'] and drift_ok and not r2['ok'] and r2['anchor_status'].get('MISSING', 0) == 2 and miss_why
    return ok, f"clean={ok0['ok']} drift={r1['drift'][:1]} status1={r1['anchor_status']} missing={r2['anchor_status']} fail2={not r2['ok']}"


def kat_dt3(base):
    m = load(base)
    good = [{'file': SRCF, 'line': next(i + 1 for i, l in enumerate((ROOT / SRCF).read_text().splitlines()) if QUOTE in l),
             'quote': QUOTE}]
    ext = [{'file': 'harness/external/derofoundation-press-20261020.txt', 'line': 21,
            'quote': 'A critical cryptographic soundness failure exists in the transfer-proof verification path used by DEROHE.'}]
    why = 'the flip is explained by the line it cites, re-read this round'
    cases = [('no anchor', {'round': 'R24', 'verdict': 'REFUTED', 'state': 'open', 'why': why, 'anchors': []}, False),
             ('only the advisory', {'round': 'R24', 'verdict': 'REFUTED', 'state': 'open', 'why': why, 'anchors': ext}, False),
             ('no why', {'round': 'R24', 'verdict': 'REFUTED', 'state': 'open', 'why': '', 'anchors': good}, False),
             ('state flip, no anchor', {'round': 'R24', 'verdict': 'CONFIRMED', 'state': 'fixed-node-local', 'why': why, 'anchors': []}, False),
             ('evidenced flip', {'round': 'R24', 'verdict': 'REFUTED', 'state': 'open', 'why': why, 'anchors': good}, True),
             ('unchanged, no anchor', {'round': 'R24', 'verdict': 'CONFIRMED', 'state': 'open', 'why': '', 'anchors': []}, True)]
    bad = []
    for label, h2, want in cases:
        r = m.evaluate(mini(good, h2), root=ROOT)
        if r['ok'] != want:
            bad.append(f'{label}: ok={r["ok"]} want {want} ({r["why"][:2]})')
    return not bad, '; '.join(bad) or f'{len(cases)} cases as expected'


TRIGGERS = {   # bare trigger tokens, one per pattern (no technical content)
    'free-scalar choice': 'choosing the blinding scalar',
    'free-scalar formula': 'mu := x',
    'forging procedure': 'how to forge a proof',
    'witness recipe': 'adversarial witness construction',
    'step list': 'step 1: mu',
    'out-of-range recipe': 'out-of-range bits then',
    'exploit artefact': 'exploit code',
    'inflation recipe': 'how to mint coins',
}
DEFENSIVE = ['proof.mu is in no Fiat-Shamir preimage and is bound by no challenge',
             'what the transcript must bind: the blinding scalar and the inner-product generator',
             'no construction of any proof is described or was attempted',
             'the agents did not build a forged proof and did not build a proof-of-concept']


def kat_dt4(base):
    m = load(base)
    names = [n for n, _ in m.EXPLOIT_PATTERNS]
    bad = []
    if sorted(names) != sorted(TRIGGERS):
        bad.append(f'pattern set {names} != KAT triggers {sorted(TRIGGERS)}')
    good = [{'file': SRCF, 'line': 1, 'quote': QUOTE}]
    for n, frag in TRIGGERS.items():
        if n not in m.lint_text(frag):
            bad.append(f'{n} misses {frag!r}')
        t = mini(good)
        t['claims'][0]['history'][0]['anchors'] = [{'file': SRCF, 'quote': QUOTE,
                                                    'line': next(i + 1 for i, l in enumerate((ROOT / SRCF).read_text().splitlines()) if QUOTE in l)}]
        t['claims'][0]['history'].append({'round': 'R24', 'verdict': 'CONFIRMED', 'state': 'open', 'why': '', 'anchors': []})
        t['facts'] = [{'id': 'NFX', 'round': 'R24', 'title': 'x', 'text': f'prefix {frag} suffix', 'status': 'pending', 'anchors': [], 'claims': []}]
        if m.evaluate(t, root=ROOT)['ok']:
            bad.append(f'track text with {n} passed')
        t['facts'] = [{'id': 'NFY', 'round': 'R24', 'title': 'y', 'text': 't', 'status': 'pending', 'anchors': [], 'claims': [],
                       'quote': frag}]      # a field named quote that is not an anchor's is page text: linted
        if m.evaluate(t, root=ROOT)['ok']:
            bad.append(f'a non-anchor quote field with {n} passed')
        t['facts'] = []
        if m.evaluate(t, root=ROOT, pages={'p': f'rendered {frag} text'})['ok']:
            bad.append(f'page text with {n} passed')
        if not m.evaluate(t, root=ROOT)['ok']:
            bad.append(f'the clean forged track fails: {m.evaluate(t, root=ROOT)["why"][:2]}')
    for s in DEFENSIVE:
        if m.lint_text(s):
            bad.append(f'defensive text flagged: {s!r} -> {m.lint_text(s)}')
    return not bad, '; '.join(bad[:4]) or f'{len(TRIGGERS)} patterns caught, {len(DEFENSIVE)} defensive texts clean'


def kat_dt5(base):
    m = load(base)
    calc, consts = m.supply_formula(ROOT)
    live = sorted((HARNESS / 'runtime').glob('disclosure_live_*.txt'))
    rec = {}
    for l in live[0].read_text().splitlines():
        k, _, v = l.partition(' ')
        rec[k] = v
    h, fs = int(rec['getinfo.height']), int(rec['audit.formula_supply'])
    seg = int(rec['audit.segment_to'])
    info = {'height': h, 'total_supply': calc(h) // 100000}
    audit = {k: v for k, v in (('segment_to', seg), ('formula_supply', calc(seg)), ('issued_emission', 5), ('issued_matches_formula', True),
                               ('payees', 7), ('alerts', 0))}
    integ = {'emission': dict(audit), 'hf3_exemption': {'window_closed': True, 'all_below_hf3': True}}
    bad = []
    if calc(seg) != fs:
        bad.append(f'CalcSupply({seg}) = {calc(seg)} != recorded formula_supply {fs}')
    _, ok = m.live_checks(info, audit, integ, calc)
    if not ok:
        bad.append('consistent readings fail')
    forg = [('S1', dict(info, total_supply=info['total_supply'] + 1), audit, integ),
            ('S2', info, dict(audit, formula_supply=audit['formula_supply'] + 1), dict(integ, emission=dict(audit, formula_supply=audit['formula_supply'] + 1))),
            ('S3', info, audit, dict(integ, emission=dict(audit, issued_emission=0, issued_matches_formula=False, payees=0))),
            ('S3', info, audit, dict(integ, emission={k: v for k, v in audit.items() if k != 'payees'})),
            ('S4', info, audit, dict(integ, hf3_exemption={'window_closed': False, 'all_below_hf3': True}))]
    for want, i, a, g in forg:
        checks, ok = m.live_checks(i, a, g, calc)
        failed = [n.split()[0] for n, c, _ in checks if not c]
        if ok or want not in failed:
            bad.append(f'forged {want} not caught (failed={failed})')
    return not bad, '; '.join(bad) or f'formula = recorded {fs} at {seg}; {len(forg)} forgeries caught'


def synth_tx(m, scalars_value, extra=b''):
    types, _ = m.tx_types(ROOT)
    plimit, _ = m.payload_limit(ROOT)
    uv = lambda x: bytes([x]) if x < 0x80 else None
    b = uv(1) + uv(0) + uv(0) + uv(types.index('NORMAL'))
    b += uv(1) + bytes(32) + uv(1)                                   # height, BLID, one payload
    b += uv(0) + bytes(32) + b'\x00' + bytes(plimit)                 # burn, SCID, rpc type, rpc payload
    b += b'\x01' + b'\x08' + uv(0) + bytes(33) + bytes(2 * 8) + bytes(2 * 33) + bytes(32)   # ring 2, bpp 8, fee, D, ptrs, C, roothash
    m_ = 1
    sc = scalars_value.to_bytes(32, 'big')
    b += bytes(4 * 33) + bytes(8 * 33 * m_) + bytes(33)              # BA BS A B, 8 vectors, u
    b += sc * (2 * m_) + sc + bytes(2 * 33) + sc * 7 + sc * 2 + bytes(7 * 2 * 33)
    return b + extra


def kat_dt6(base):
    m = load(base)
    order, _ = m.bn256_order(ROOT)
    bad = []
    p = m.parse_tx_proofs(synth_tx(m, order - 1), m.payload_limit(ROOT)[0], m.tx_types(ROOT)[0])
    pl = p['payloads'][0] if p['payloads'] else {}
    if p['type'] != 'NORMAL' or pl.get('ring') != 2 or pl.get('m') != 1 or len(pl.get('scalars', {})) != 2 + 1 + 7 + 2:
        bad.append(f'parse shape wrong: {p["type"]} {pl.get("ring")} {pl.get("m")} {len(pl.get("scalars", {}))}')
    c0 = m.census_of([('a', synth_tx(m, order - 1))], order, m.payload_limit(ROOT)[0], m.tx_types(ROOT)[0])
    c1 = m.census_of([('b', synth_tx(m, order))], order, m.payload_limit(ROOT)[0], m.tx_types(ROOT)[0])
    c2 = m.census_of([('c', synth_tx(m, 1, b'\x00'))], order, m.payload_limit(ROOT)[0], m.tx_types(ROOT)[0])
    if c0['noncanonical'] or c0['scalars'] != 12:
        bad.append(f'Order-1 counted non-canonical ({len(c0["noncanonical"])}) or scalars {c0["scalars"]}')
    if len(c1['noncanonical']) != 12:
        bad.append(f'Order counted {len(c1["noncanonical"])} of 12')
    if not c2['parse_errors']:
        bad.append('a trailing byte parsed clean')
    return not bad, '; '.join(bad) or 'parse, boundary (Order-1 / Order) and trailing-byte cases as expected'


def kat_dt7(base):
    m = load(base)
    track, legacy = real()
    bad = []

    def expect_fail(label, fn):
        t = copy.deepcopy(track)
        lg = copy.deepcopy(legacy)
        fn(t, lg)
        if m.evaluate(t, root=ROOT, legacy=lg)['ok']:
            bad.append(f'{label} passed')

    fork = next(i for i, x in enumerate(track['fixes']) if x['kind'] == 'FORK-REQUIRED')
    impl = next(i for i, x in enumerate(track['fixes']) if x['kind'] == 'NODE-LOCAL' and x['status'] == 'implemented')

    def no_coord(t, lg):
        import re as _re
        for k in ('design', 'compat'):
            t['fixes'][fork][k] = _re.sub('coordinated', 'joint', t['fixes'][fork][k], flags=_re.I)
    expect_fail('fork design without "coordinated"', no_coord)
    expect_fail('fork design marked implemented', lambda t, lg: t['fixes'][fork].update(status='implemented', implemented_in='x'))
    expect_fail('implemented node-local without implemented_in', lambda t, lg: t['fixes'][impl].update(implemented_in=''))
    expect_fail('unmapped press row', lambda t, lg: lg['press']['rows'].append({'id': 'c99-new'}))
    expect_fail('claim not re-tested this round', lambda t, lg: t['claims'][0].update(history=[h for h in t['claims'][0]['history'] if h['round'] != t['current_round']]))
    expect_fail('unknown verdict word', lambda t, lg: t['claims'][0]['history'][-1].update(verdict='SURE'))
    return not bad, '; '.join(bad) or '6 forged tracks fail'


def kat_dt8(base):
    m = load(base)
    track, _ = real()
    doc = m.emit_model(track, ROOT)
    files = {e['file'] for r in doc['rows'] for e in r['evidence']}
    leaked = sorted(f for f in files if f.startswith('harness/') and not f.startswith(('harness/runtime/', 'harness/external/', 'harness/baseline/')))
    t2 = copy.deepcopy(track)
    t2['claims'][0]['title'] += ' (edited)'
    stale = m.model_current(t2, json.loads((HARNESS / 'model/raw/disclosure.json').read_text()), ROOT)
    return not leaked and not stale and len(doc['rows']) == len(track['claims']) + len(track['facts']) + len(track['fixes']), \
        f'leaked={leaked[:3]} edited-track-still-current={stale} rows={len(doc["rows"])}'


def kat_dt9(base):
    import contextlib, io
    m = load(base)
    rep0 = {'ok': True, 'why': [], 'rev': 'worktree', 'claims': 0, 'facts': 0, 'fixes': 0, 'anchors': 0,
            'anchor_status': {}, 'drift': [], 'lint_hits': [], 'legacy_lint': []}
    m.load = lambda *a, **k: ({}, [])
    m.evaluate = lambda *a, **k: copy.deepcopy(rep0)
    m.model_current = lambda *a, **k: True
    cases = [
        ('live FAIL', ['--live'], {'file': 'x', 'ok': False, 'checks': [('S1 x', False, 'd'), ('S2 y', True, 'd')]}, None, 3),
        ('live PASS', ['--live'], {'file': 'x', 'ok': True, 'checks': [('S1 x', True, 'd')]}, None, 0),
        ('live unreadable', ['--live'], {'ok': None, 'error': 'URLError: refused'}, None, 0),
        ('census non-canonical', ['--census', '5'], None, {'file': 'c', 'noncanonical': [{'tx': 't'}], 'parse_errors': []}, 3),
        ('census clean', ['--census', '5'], None, {'file': 'c', 'noncanonical': [], 'parse_errors': []}, 0),
    ]
    bad = []
    for name, argv, live, census, want in cases:
        m.run_live = (lambda live=live: live)
        m.run_census = (lambda n, census=census: census)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = m.main(argv)
        if rc != want:
            bad.append(f'{name}: exit {rc}, want {want}')
    return not bad, '; '.join(bad) or f'{len(cases)} exit-code cases as expected'


KATS = [('DT1', kat_dt1), ('DT2', kat_dt2), ('DT3', kat_dt3), ('DT4', kat_dt4), ('DT5', kat_dt5), ('DT6', kat_dt6),
        ('DT7', kat_dt7), ('DT8', kat_dt8), ('DT9', kat_dt9)]

MUTATIONS = [
    ('DT2', "    if isinstance(line, int) and line in hits:\n        return {**out, 'status': 'OK', 'now': line}",
     "    if hits:\n        return {**out, 'status': 'OK', 'now': line}", 'a moved anchor reads as OK (drift undetected)'),
    ('DT2', "            elif r['status'] not in ANCHOR_OK:\n                bad.append(r)",
     "            elif False:\n                bad.append(r)", 'a vanished anchor does not fail'),
    ('DT3', "                if not own:", "                if False:", 'a verdict changes with no anchor'),
    ('DT3', "                if len(norm(h.get('why'))) < 20:", "                if False:", 'a verdict changes with no why'),
    ('DT3', "            own = [r for r in rs if r['status'] in ANCHOR_OK and not is_external(r)]",
     "            own = [r for r in rs if r['status'] in ANCHOR_OK]", 'the advisory alone may justify a verdict'),
    ('DT3', "            changed = prev is None or (h.get('verdict'), h.get('state')) != (prev.get('verdict'), prev.get('state'))",
     "            changed = prev is None", 'a later round may flip a verdict unchecked'),
    ('DT4', "    hits = lint(track, 'track')", "    hits = []", 'the track text is not linted'),
    ('DT4', "        for n in lint_text(v):\n            hits.append({'where': f'page:{k}'",
     "        for n in []:\n            hits.append({'where': f'page:{k}'", 'the rendered pages are not linted'),
    ('DT4', "    ('free-scalar formula', r'(?<![\\w.])(proof\\.)?(mu|μ)\\s*(:=|=|←)\\s*\\S'),\n", "",
     'one exploit pattern dropped'),
    ('DT4', "            if k == 'quote' and 'file' in o:\n                continue",
     "            if k == 'quote':\n                continue", 'any field named quote escapes the lint'),
    ('DT5', "    out.append(('S1 GetInfo.total_supply is the formula', info.get('total_supply') == want,",
     "    out.append(('S1 GetInfo.total_supply is the formula', True,", 'an inflated published supply passes'),
    ('DT5', "    out.append(('S3 GetMonetaryIntegrity.emission agrees with GetEmissionAudit', not diff and not miss,",
     "    out.append(('S3 GetMonetaryIntegrity.emission agrees with GetEmissionAudit', not miss,", 'CI24-1 passes'),
    ('DT5', "    out.append(('S4 HF3 exemption window closed', hx.get('window_closed') is True and hx.get('all_below_hf3') is True,",
     "    out.append(('S4 HF3 exemption window closed', hx.get('all_below_hf3') is True,", 'an open HF3 window passes'),
    ('DT5', "            s += reward(ep) * n", "            s += reward(ep) * n + 1", 'the recomputed formula is wrong'),
    ('DT6', "                if v >= order:", "                if v > order:", 'a scalar equal to Order counts as canonical'),
    ('DT6', "    if r.i != len(raw):", "    if False:", 'trailing bytes are accepted'),
    ('DT7', "            if 'coordinated' not in norm(x.get('design')).lower() and 'coordinated' not in norm(x.get('compat')).lower():",
     "            if False:", 'a fork design need not say it needs a coordinated fork'),
    ('DT7', "        if r.get('id') not in pm:", "        if False:", 'a new press claim slips in unmapped'),
    ('DT7', "        if cur in ri and not any(h.get('round') == cur for h in hist):",
     "        if False:", 'a claim need not be re-tested this round'),
    ('DT7', "        if x.get('status') in ('implemented', 'implemented-earlier') and not x.get('implemented_in'):",
     "        if False:", 'an implemented measure need not say where'),
    ('DT8', "            if a.get('file') and page_class(a['file'], root)]", "            if a.get('file')]",
     'harness code anchors reach the page model'),
    ('DT9', "    if lv.get('ok') is False:\n        rep['ok'] = False", "    if False:\n        rep['ok'] = False",
     'a failing live cross-check exits 0'),
    ('DT9', "    if nc:\n        rep['ok'] = False", "    if False:\n        rep['ok'] = False",
     'a non-canonical census exits 0'),
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
    print(f'\nr24 disclosure-track KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
