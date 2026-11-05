#!/usr/bin/env python3
"""KAT + mutation proofs for gate G30 (rft §0.8.8; harness/forensics/facts.py): the ledger's forensics sections trace
every figure to a dataset file + SHA-256. No network, no live file written.

  GF1 a forged dataset's facts render, and a page built from them PASSES check_page (spans counted);
  GF2 a span whose text differs from the dataset value, that names another file, another SHA-256, or an unknown fact FAILS;
  GF3 a number left outside a span FAILS, also inside a table cell or a list; identifiers (R25, G28, A4b, B73, §0.8.6,
      file.go:12-13, expected.sha256, a 16-hex id) do not; text inside <script>/<style> is not visible text;
  GF4 the explorer data: the encoding round-trips (B64X: no vowel, no '.'), and a changed id byte, timestamp delta,
      miniblock count, fee, tier, tx list or a dropped row FAILS; missing embedded data FAILS;
  GF5 (MF8/MF9 over the sections) exploit-pattern text and an IPv4 / home path inside the sections FAIL;
  GF6 a dataset file whose bytes differ from the manifest is reported as a fact problem;
  GF7 (r26) a closed page (artifacts/src/frozen/r<N>/) is built from and checked against its frozen record files.
  Committed: when artifacts/dero-r1-r25.html exists, G30 passes on it (and the src-arch line).

  python3 -I harness/kat/test_forensics_g30_r25.py   # exit 0 ok · 3 a KAT failed · 4 a mutation not caught / INVALID
"""
import gzip, hashlib, importlib.util, json, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent


def load(base, rel, tag):
    spec = importlib.util.spec_from_file_location(f'g30_{tag}_{id(base)}_{len(sys.modules)}', base / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def h(b):
    return hashlib.sha256(b).hexdigest()


def forge(tmp):
    """A tiny dataset with the files facts.build reads (two window rows)."""
    ds = tmp / 'forensics' / 'rX'
    (ds / 'derived').mkdir(parents=True)
    (ds / 'raw').mkdir()
    (ds / 'audit').mkdir()
    (ds / 'replay').mkdir()
    rows = [{'height': 100, 'blid': 'aa' * 32, 'sha256': 'bb' * 32, 'timestamp_ms': 1000, 'miniblocks': 10, 'fees': 80,
             'tx_hashes': ['cc' * 32], 'hf3_txids': ['dd' * 32], 'tier': 'A', 'tips': ['99' * 32],
             'state_root_post': 'not reconstructable: x'},
            {'height': 101, 'blid': 'ee' * 32, 'sha256': 'ff' * 32, 'timestamp_ms': 19000, 'miniblocks': 9, 'fees': 'pending',
             'tx_hashes': [], 'hf3_txids': [], 'tier': 'B', 'tips': ['aa' * 32], 'state_root_post': '0' * 63 + '1'}]
    (ds / 'derived' / 'window.jsonl.gz').write_bytes(gzip.compress(''.join(json.dumps(r) + '\n' for r in rows).encode(), mtime=0))
    J = lambda rel, o: (ds / rel).write_text(json.dumps(o))
    J('derived/summary.json', {'window_rows': 2, 'window': [100, 101], 'tierA_blocks': 1, 'tx_records': 1, 'hf3_records': 1,
                               'hf3_missing': 0, 'link_rows': 0, 'state_roots_held_window_topos': 1, 'txid_python_keccak_eq': 1,
                               'serialize_keccak_python_eq': 1, 'tierA_block_id_python_sha3_eq': 1,
                               'grades': {'NOT-DECIDABLE-FROM-PUBLIC-DATA/E1': 1, 'NOT-DECIDABLE-FROM-PUBLIC-DATA/E2': 0}})
    J('derived/emission.json', {'window_emission_atomic': 61500, 'window_emission_dero': '0.61500', 'calc_supply_at_window_start': 1,
                                'calc_supply_after_window': 61501, 'base_reward_per_block_atomic': [30750],
                                'fees': {'known_blocks': 1, 'known_sum_atomic': 80, 'pending_blocks': 1},
                                'per_block': {'burn_known_sum': 0, 'coinbase_ok': 2, 'supply_identity_ok': 2, 'tx_free_blocks': 1,
                                              'node_eq_python_reward': 2, 'base_reward_sum_node': 61500, 'base_reward_sum_python': 61500},
                                'grade': {'verdict_grade': 'PROVEN-NO-INFLATION-IN-SCOPE', 'scope': 'two blocks'}})
    J('derived/hf3.json', {'counts': {'carriers_total': 1, 'dual_carrier': 0, 'single_carrier': 1, 'bodies_raw': 1,
                                      'bl_tips_is_carrier_tip': 1, 'bl_tips_is_carrier_itself': 0, 'carriers_nonce_bypassed': 1,
                                      'carriers_parity_override_changes_execution': 0,
                                      'proof_current_verifier': {'pass': 0, 'fail': 0, 'not decidable: ring state unavailable': 1}},
                           'table': {'entries': 1, 'groups': {'duplicates': 1, 'no duplicates, but false parity': 0}, 'parity_literal_set': 0, 'sha256': 'ab' * 32},
                           'b83_proof_field': {'nonzero': 0, 'blocks': 2}, 'paths': {'verify_cache_fill': 'blockchain/x.go:1-2'},
                           'rows': [{'txid': '0045a6d4' + 'dd' * 28, 'table_height': 100, 'line': 7, 'fee': 80, 'carriers': [100],
                                     'ring_sizes': [2], 'nonce_bypassed_carriers': [100], 'parity_override_changes_execution': [],
                                     'proof_current_verifier': 'not decidable: ring state unavailable', 'evidence_grade': 'E2',
                                     'group': 'duplicates', 'tx_parity': True, 'body_sha256': '12' * 32}]})
    J('derived/state_roots.json', {'held': {'window_topos_with_post_root': 1}, 'not_reconstructable': {'window_topos': 1},
                                   'corroboration_by_tx_statement_roothash': {'equal': 0}})
    J('raw/missing.json', {'missing_count': 0})
    J('raw/a2_feasibility.json', {'state_at_7415465': {'answered_ok': 1, 'of': 1}})
    J('raw/sources.json', {'candidates_probed': 2, 'answered_getinfo': 1, 'sources': {'src-1': {'serves_window': True}}})
    J('raw/anchors.json', [{'kind': 'block', 'height': 102, 'id': '34' * 32}, {'kind': 'archive_topo_records', 'topo_range': [100, 101], 'count': 2}])
    (ds / 'replay' / 'expected.sha256').write_text('x  derived/a\n')
    J('audit/challenges.json', {'challenges': [{'id': 'A1', 'claim': 'claim with 82,477 in it', 'result': 'HOLDS', 'evidence': [{'class': 'RAW', 'what': 'w 5'}]}]})
    J('audit/audit_report.json', {'counts': {'challenges': 1, 'holds': 1, 'overturned': 0, 'unresolved': 0, 'verdicts': 1, 'downgraded': 0,
                                             'overturned_all_runs': 0}, 'binding': {'data_sha256': '56' * 32}, 'history': [],
                                  'verdicts': [{'id': 'V-EXT-23886517', 'question': 'the external figure 23,886,517.3 DERO (x)', 'audit_grade': 'SPECULATION'}]})
    files = {str(p.relative_to(ds)): h(p.read_bytes()) for p in sorted(ds.rglob('*')) if p.is_file()}
    (ds / 'manifest.json').write_text(json.dumps({'dataset': 'rX', 'version': 1, 'files': files, 'git_base_commit': 'c' * 40,
                                                  'content_pins': {'aggregate_sha256': 'e' * 64}, 'hf3_table': {'sha256': 'ab' * 32}}))
    (tmp / 'forensics' / 'ledger.json').write_text(json.dumps({'versions': [{'version': 'rX'}]}))
    for rel in ('harness/forensics/audit_check.py', 'harness/intel/disclosure_track.py'):
        (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, tmp / rel)
    return ds


def page(FX, F, body_extra='', data=None):
    f = F.facts
    S = lambda k: (f'<span class="fxn" data-fx="{k}" data-src="{f[k]["file"]}" data-sha="{f[k]["sha256"]}">{FX.fmt(f[k]["value"])}</span>')
    d = FX.explorer_data(F.ds) if data is None else data
    return (FX.BEGIN + f'<section><p>Window {S("window_first")} to {S("window_last")}: {S("window_rows")} heights; '
            f'<span class="fxid">R25</span> <span class="fxid">G28</span> <span class="fxid">(a2)</span> A4b B73 §0.8.6 blockchain/x.go:12-13 replay/expected.sha256 '
            f'<code>0045a6d4c51a8578</code>; {S("ch:A1:claim")}; {S("ext:23886517")}</p>' + body_extra +
            '<script>var a=12345;</script><style>.x{width:100px}</style>'
            f'<script type="application/json" id="fx-data">{json.dumps(d, separators=(",", ":"))}</script></section>' + FX.END)


def kats(base):
    FX = load(base, 'forensics/facts.py', 'facts')
    fails = []

    def ok(c, m):
        if not c:
            fails.append(m)
    tmp = Path(tempfile.mkdtemp(prefix='g30kat_'))
    try:
        ds = forge(tmp)
        F = FX.build(ds, tmp)
        ok(not F.problems, f'GF1 forged dataset has fact problems: {F.problems[:2]}')
        good = page(FX, F)
        p, n = FX.check_page(good, F)
        ok(p == [] and n == 5, f'GF1 a traced page fails: {p[:2]} n={n}')
        sh = F.facts['window_rows']['sha256']
        for name, bad in (('wrong value', good.replace(f'data-sha="{sh}">2<', f'data-sha="{sh}">3<')),
                          ('wrong sha', good.replace(f'data-fx="window_rows" data-src="derived/summary.json" data-sha="{sh}"',
                                                     'data-fx="window_rows" data-src="derived/summary.json" data-sha="' + '0' * 64 + '"')),
                          ('wrong file', good.replace('data-fx="window_rows" data-src="derived/summary.json"', 'data-fx="window_rows" data-src="derived/emission.json"')),
                          ('unknown fact', good.replace('data-fx="window_rows"', 'data-fx="no_such_fact"'))):
            ok(FX.check_page(bad, F)[0] != [], f'GF2 a span with a {name} passes')
        for name, extra in (('bare number', '<p>about 1,575 blocks</p>'), ('number in a cell', '<table><tr><td>42</td></tr></table>'),
                            ('number in a list', '<ul><li>7.5 %</li></ul>'), ('short hex', '<p>0045a6d4…</p>')):
            ok(any('untraced' in x for x in FX.check_page(page(FX, F, extra), F)[0]), f'GF3 a {name} outside a span passes')
        d = FX.explorer_data(ds)
        ok(FX.explorer_decode(d)[1]['fees'] == 'pending' and FX.unb64x(FX.b64x(b'\x00\xffabc')) == b'\x00\xffabc', 'GF4 round trip')
        ok(not set('aeiouAEIOU.') & set(d['ids']), 'GF4 the id column carries a vowel or a dot')
        ids = bytearray(FX.unb64x(d['ids'])); ids[5] ^= 1
        for name, mut in (('id byte', dict(d, ids=FX.b64x(bytes(ids)))), ('timestamp delta', dict(d, ts=[d['ts'][0], d['ts'][1] + 1])),
                          ('miniblock count', dict(d, mb='99')), ('fee', dict(d, fee={'0': 81})), ('pending fee', dict(d, feep=[])),
                          ('tier', dict(d, tierA=[])), ('tx list', dict(d, txs={})), ('dropped row', dict(d, n=1, ts=d['ts'][:1], mb=d['mb'][:1])),
                          ('carriers', dict(d, carriers=[])), ('roots', dict(d, roots=[]))):
            ok(FX.check_explorer(mut, ds) != [], f'GF4 explorer data with a changed {name} passes')
        nod = good.replace('id="fx-data"', 'id="fx-other"')
        ok(any('no embedded explorer data' in x for x in FX.check_page(nod, F)[0]), 'GF4 a page without explorer data passes')
        ok(FX.section_lint(good, tmp, tmp / 'none') == [], f'GF5 a clean section fails the lint: {FX.section_lint(good, tmp, tmp / "none")[:1]}')
        for name, extra in (('exploit text', '<p>here is a working exploit script</p>'), ('an IPv4', '<p>peer 8.8.4.4 answered</p>'),
                            ('a home path', '<p>/Users/someone/x</p>')):
            ok(FX.section_lint(page(FX, F, extra), tmp, tmp / 'none') != [], f'GF5 {name} in the sections passes the lint')
        (ds / 'derived' / 'summary.json').write_text((ds / 'derived' / 'summary.json').read_text().replace('"window_rows": 2', '"window_rows": 3'))
        F2 = FX.build(ds, tmp)
        ok(any('derived/summary.json' in x for x in F2.problems), 'GF6 a dataset file differing from the manifest is not reported')
        (ds / 'derived' / 'summary.json').write_text((ds / 'derived' / 'summary.json').read_text().replace('"window_rows": 3', '"window_rows": 2'))
        fails.extend(gf7(FX, tmp, page))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return fails


def gf7(FX, tmp, page):
    """GF7 (r26, rft §0.6 closed pages): a closed ledger page (artifacts/src/frozen/r<N>/ exists) is built from and
    checked against its FROZEN record files: after S7 rewrites the live disclosure track, the frozen page still renders
    the same and G30 still passes on it, while the live facts name the new record SHA-256."""
    out = []
    dt = tmp / 'harness' / 'loop' / 'disclosure_track.json'
    dt.parent.mkdir(parents=True, exist_ok=True)
    dt.write_text(json.dumps({'claims': [{'id': 'C1'}], 'facts': []}))
    fz = tmp / 'artifacts' / 'src' / 'frozen' / 'r7'
    (fz / 'harness' / 'loop').mkdir(parents=True)
    (fz / 'forensics').mkdir(parents=True)
    shutil.copyfile(dt, fz / 'harness' / 'loop' / 'disclosure_track.json')
    shutil.copyfile(tmp / 'forensics' / 'ledger.json', fz / 'forensics' / 'ledger.json')
    pg = tmp / 'artifacts' / 'dero-r1-r7.html'
    if FX.page_dyn_root(tmp, pg) != fz:
        out.append(f'GF7 the frozen input root of a closed page is not found: {FX.page_dyn_root(tmp, pg)}')
        return out
    Fz = FX.build(*FX.page_inputs(tmp, fz))
    f = Fz.facts
    S = lambda k: f'<span class="fxn" data-fx="{k}" data-src="{f[k]["file"]}" data-sha="{f[k]["sha256"]}">{FX.fmt(f[k]["value"])}</span>'
    pg.write_text(page(FX, Fz, f'<p>track {S("dt_claims")}</p>'))
    sa = tmp / 'artifacts' / 'dero-src-arch.html'
    sa.write_text(FX.SA_BEGIN + FX.SA_END)
    frozen_sha = f['dt_claims']['sha256']
    dt.write_text(json.dumps({'claims': [{'id': 'C1'}, {'id': 'C2'}], 'facts': []}))   # S7 rewrites the live record
    Fl = FX.build(FX.newest_dataset(tmp), tmp)
    if Fl.facts['dt_claims']['sha256'] == frozen_sha:
        out.append('GF7 the live facts still name the frozen record')
    Fz2 = FX.build(*FX.page_inputs(tmp, fz))
    if Fz2.facts['dt_claims']['sha256'] != frozen_sha or Fz2.facts['dt_claims']['value'] != 1:
        out.append(f'GF7 a closed page reads the live record: {Fz2.facts["dt_claims"]}')
    okk, det = FX.g30(tmp, pg, sa)
    if not okk:
        out.append(f'GF7 G30 fails on a closed page whose live record moved: {det[:200]}')
    return out


def committed():
    lp = ROOT / 'artifacts' / 'dero-r1-r25.html'
    if not lp.exists():
        return []
    FX = load(HARNESS, 'forensics/facts.py', 'factsc')
    okk, det = FX.g30(ROOT)
    return [] if okk else [f'G30 on the committed pages: {det[:300]}']


MUTATIONS = [
    ("        if html.unescape(shown) != fmt(f['value']):", "        if False:"),
    ("        if src != f['file'] or h != f['sha256']:", "        if False:"),
    ("        if not f:\n            p.append(f'span {fid}: no such fact')\n            continue",
     "        if not f:\n            continue"),
    ("    for mm in re.finditer(r'\\d[\\d,.]*', left):", "    for mm in re.finditer(r'\\d[\\d,.]*', ''):"),
    ("        if {k: g[k] for k in want} != want:", "        if False:"),
    ("        if d.get(k) != want[k]:\n            p.append(f'explorer field {k} differs from the dataset')", "        if False:\n            pass"),
    ("            p.append('no embedded explorer data (#fx-data)')", "            pass"),
    ("        if rx.search(vis):\n            p.append(f'exploit-pattern text in the sections: {n}')", "        if False:\n            pass"),
    ("        if rx.search(vis):\n            p.append(f'private text in the sections: {n}')", "        if False:\n            pass"),
    ("            if not b or sha(b) != h:", "            if not b:"),
    ("    seg = re.sub(r'<script\\b.*?</script>', ' ', seg, flags=re.S)\n", "\n"),
    ("    seg = FXID.sub(_fxid_text, seg)\n", "\n"),   # r26 verify: the identifier-span rule (facts._fxid_text)
    # r26 GF7 (closed pages read their frozen record files)
    ("            p = self.rec_root / rel\n", "            p = self.root / rel\n"),
    ("    return d if d is not None and d.is_dir() else None\n", "    return None\n"),
    ("        FP = build(pds, root, prec)\n", "        FP = F\n"),
]


def main():
    f = kats(HARNESS) + committed()
    print('GF1-GF7:', 'PASS' if not f else 'FAIL\n  ' + '\n  '.join(f))
    if f:
        return 3
    rc, caught = 0, 0
    for i, (old, new) in enumerate(MUTATIONS, 1):
        tmp = Path(tempfile.mkdtemp(prefix='g30mut_'))
        try:
            shutil.copytree(HARNESS / 'forensics', tmp / 'forensics')
            src = (tmp / 'forensics' / 'facts.py').read_text()
            if old not in src:
                print(f'mutation {i} INVALID: text not found'); rc = 4; continue
            (tmp / 'forensics' / 'facts.py').write_text(src.replace(old, new, 1))
            try:
                mf = kats(tmp)
            except Exception as e:                                   # noqa: BLE001
                print(f'mutation {i} INVALID: {type(e).__name__}: {e}'); rc = 4; continue
            if mf:
                caught += 1
                print(f'mutation {i} CAUGHT: {mf[0]}')
            else:
                print(f'mutation {i} NOT CAUGHT: {old.strip()[:70]}'); rc = 4
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f'mutations caught {caught}/{len(MUTATIONS)}')
    return rc


if __name__ == '__main__':
    sys.exit(main())
