#!/usr/bin/env python3
"""KAT + mutation proofs for gate G32 (class separation and presence) and the class backend (rft §0.8.9; B107, B109,
B110, B111-B113): harness/forensics/classes.py, presence.py, invariant.py and bounds.g32. No network; forged datasets
in a temp dir; presence and invariant anchors are read through a fake `git show` reader.

  CL1 classes.build: the table TXIDs are DC1 and every other tx DC3; a TXID in two window blocks outside the table is
      DC0 (and one inside is not); one class per figure; FQ1 counts the table groups against the RAW carriers;
  CL2 tag_dataset fills `defect_class` (and a literal class slot), never overwrites the evidence `class`, and refuses
      r25 / a sealed version;
  CL3 check_records: a record without a class, an unknown class or a count that differs from classes.json FAILS;
  CL4 FQ4 structural transcript KAT: at this tree's HEAD Proof.Verify + InnerProduct.Verify have 10 challenges, none
      names proof.mu, and the preimage digest is PINNED below; adding mu to a preimage flips mu_in_a_preimage and the
      digest (a future upstream fix shows up here and in presence.json);
  CL5 presence: an anchor is found by its quote, a moved line or a lost quote is reported by check(); closure anchors
      do not decide `admits`; the headline follows DC2 at the first rev;
  CL6 g32: the DC2-present headline is required on the ledger, soundness and src-arch pages once the round's ledger page
      exists (a missing one FAILS, none rendered yet = pending, PASS); a presence re-read drift FAILS;
  CL7 invariant: Q-CS1 is answered only when the census root equals the recorded archive root; a Q-CS2 anchor that does
      not re-read turns Q-CS2/Q-CS3 into pending;
  CL8 struct_census: a commitment digest shared by two txs is counted; the per-tx list names table TXIDs only;
  CL9 the FQ3 wallet census reads every tag (fake reader): a tag without the deterministic-r line is not counted.
  CL10 DC1-obs is computed from the criteria (P1 or S-R22 on a table TXID), never assumed 0; a missing D is no commitment.
  Committed: g32 passes on this tree and presence.json re-reads unchanged.

  python3 -I harness/kat/test_forensics_classes_r26.py   # exit 0 ok · 3 a KAT failed · 4 a mutation not caught / INVALID
"""
import copy, gzip, importlib.util, json, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
# FQ4 pin (rft §0.8.9): the ordered challenge preimages of Proof.Verify (+ hashmash1) and InnerProduct.Verify at the
# R26 head, Release152 and Release153 (presence.py transcript_summary). A change here is a presence change: re-read
# the verifier, record it in the disclosure track, then re-pin. Never re-pin to make a run green.
PIN_FQ4 = {'challenges': 10, 'mu_in_a_preimage': False,
           'preimage_sha256': 'af17aac24a335435c992f49bdf694d2b7b10001044713e18999ff947b63792c6'}

T1, T2, T3 = 'aa' * 32, 'bb' * 32, 'cc' * 32          # T1, T2 are table TXIDs


def load(base, rel, tag):
    spec = importlib.util.spec_from_file_location(f'cl_{tag}_{id(base)}_{len(sys.modules)}', base / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def forge(t, dup_outside=False):
    """a tiny base dataset rB with the files classes.build reads"""
    ds = t / 'forensics' / 'rB'
    (ds / 'derived' / 'tx').mkdir(parents=True)
    (ds / 'derived' / 'block').mkdir(parents=True)
    J = lambda rel, o: (ds / rel).write_text(json.dumps(o))
    J('derived/hf3.json', {'rows': [{'txid': T1, 'group': 'duplicates', 'carriers': [100, 101], 'tx_parity': True},
                                    {'txid': T2, 'group': 'no duplicates, but false parity', 'carriers': [102], 'tx_parity': False}],
                           'counts': {'bodies_raw': 2, 'carriers_nonce_bypassed': 2, 'carriers_total': 3},
                           'table': {'entries': 2}})
    J('derived/emission.json', {'window_emission_atomic': 61500, 'scope': 'two blocks',
                                'per_block': {'supply_identity_ok': 3, 'blocks': 3, 'burn_known_sum': 0},
                                'fees': {'known_sum_atomic': 80, 'known_blocks': 2, 'pending_blocks': 1},
                                'grade': {'verdict_grade': 'PROVEN-NO-INFLATION-IN-SCOPE'}})
    J('derived/grades.json', {'counts': {'NOT-DECIDABLE-FROM-PUBLIC-DATA/E2': 2}})
    rows = [{'height': 100, 'tx_hashes': [T1, T3], 'class': 'RAW'}, {'height': 101, 'tx_hashes': [T1] + ([T3] if dup_outside else []), 'class': 'RAW'},
            {'height': 102, 'tx_hashes': [T2], 'class': 'RAW'}]
    (ds / 'derived' / 'window.jsonl.gz').write_bytes(gzip.compress(''.join(json.dumps(r) + '\n' for r in rows).encode(), mtime=0))
    for tx in (T1, T2, T3):
        J(f'derived/tx/{tx}.json', {'txid': tx, 'value_field': 0, 'burn_total': 0, 'class': 'RAW body (checks i-iii)'})
    J('derived/block/100.json', {'height': 100, 'class': 'pending: defect class'})
    return ds


def cl1(C, t):
    out = []
    ds = forge(t)
    I = C.Inputs(t / 'forensics' / 'rN', ds, t)
    cl, fq = C.build(I, {'headline': {'dc2_present_now': True, 'text': 'x'}}, None, [], {'claims': []})
    if cl['records']['tx'] != {'DC1': 2, 'DC3': 1}:
        out.append(f'CL1 tx tags {cl["records"]["tx"]}')
    if cl['classes']['DC0']['detected'] != 0:
        out.append('CL1 a table duplicate counted as DC0')
    if any(f['class'] not in ('DC0', 'DC1', 'DC2', 'DC3') for f in cl['figures']):
        out.append('CL1 a figure without one class')
    a = fq['FQ1']['answer']
    if not a['table_groups_match_raw_carriers'] or a['duplicates_two_carriers'] != '1 of 1' or a['tx_parity_true'] != 1:
        out.append(f'CL1 FQ1 counts {a}')
    if fq['FQ2']['criteria']['P1']['result'] != '0 of 2':
        out.append(f'CL1 FQ2 P1 {fq["FQ2"]["criteria"]["P1"]}')
    t2 = t / 'dup'
    ds2 = forge(t2, dup_outside=True)
    cl2, fq2 = C.build(C.Inputs(t2 / 'forensics' / 'rN', ds2, t2), None, None, [], None)
    if cl2['classes']['DC0']['detected'] != 1 or fq2['FQ1']['answer']['dc0_window_duplicates'] != 1:
        out.append('CL1 a duplicate outside the table is not DC0')
    f = {x['id']: x for x in cl2['figures']}['dc0-window-duplicates']
    if f['value'] != 1 or f['class'] != 'DC0':
        out.append(f'CL1 the DC0 figure {f}')
    # a public value field on a table tx makes P1 count it
    (ds / 'derived' / 'tx' / f'{T1}.json').write_text(json.dumps({'txid': T1, 'value_field': 5, 'burn_total': 0}))
    _, fq3 = C.build(C.Inputs(t / 'forensics' / 'rN', ds, t), None, None, [], None)
    if fq3['FQ2']['criteria']['P1']['result'] != '1 of 2':
        out.append('CL1 P1 ignores a public value field')
    return out


def cl2(C, t):
    out = []
    ds = forge(t)
    (t / 'forensics' / 'ledger.json').write_text(json.dumps({'versions': [{'version': 'rS', 'sealed': True}]}))
    v2 = t / 'forensics' / 'rN'
    shutil.copytree(ds, v2)
    n = C.tag_dataset(v2, t)
    r = json.loads((v2 / 'derived' / 'tx' / f'{T1}.json').read_text())
    if r.get('defect_class') != 'DC1' or r.get('class') != 'RAW body (checks i-iii)':
        out.append(f'CL2 tag of a table tx {r}')
    r3 = json.loads((v2 / 'derived' / 'tx' / f'{T3}.json').read_text())
    if r3.get('defect_class') != 'DC3':
        out.append('CL2 a non-table tx not DC3')
    b = json.loads((v2 / 'derived' / 'block' / '100.json').read_text())
    if b.get('defect_class') != 'DC3' or b.get('class') != 'DC3':
        out.append(f'CL2 the class slot not filled {b}')
    w = [json.loads(l) for l in gzip.decompress((v2 / 'derived' / 'window.jsonl.gz').read_bytes()).decode().splitlines()]
    if any(x.get('defect_class') != 'DC3' or x.get('class') != 'RAW' for x in w):
        out.append('CL2 window rows not tagged (or evidence class overwritten)')
    if n.get('tx_DC1') != 2 or n.get('window_DC3') != 3:
        out.append(f'CL2 counts {n}')
    for name in ('r25', 'rS'):
        d = t / 'forensics' / name
        if not d.exists():
            shutil.copytree(ds, d)
        try:
            C.tag_dataset(d, t)
            out.append(f'CL2 tagging {name} was not refused')
        except SystemExit:
            pass
    return out


def cl3(B, t):
    out = []
    ds = t / 'forensics' / 'rN'
    (ds / 'derived' / 'tx').mkdir(parents=True)
    (ds / 'derived' / 'tx' / 'a.json').write_text(json.dumps({'defect_class': 'DC1'}))
    (ds / 'derived' / 'tx' / 'b.json').write_text(json.dumps({'defect_class': 'DC3'}))
    good = {'records': {'tx': {'DC1': 1, 'DC3': 1}}}
    p, n = B.check_records(ds, good)
    if p or n != 2:
        out.append(f'CL3 valid records refused {p}')
    p, _ = B.check_records(ds, {'records': {'tx': {'DC1': 2, 'DC3': 1}}})
    if not p:
        out.append('CL3 a count mismatch passes')
    (ds / 'derived' / 'tx' / 'c.json').write_text(json.dumps({'class': 'RAW'}))
    p, _ = B.check_records(ds, {'records': {'tx': {'DC1': 1, 'DC3': 1}}})
    if not any('defect_class' in x for x in p):
        out.append('CL3 a record without a class passes')
    (ds / 'derived' / 'tx' / 'c.json').write_text(json.dumps({'defect_class': 'DC9'}))
    p, _ = B.check_records(ds, {'records': {'tx': {'DC1': 1, 'DC3': 1}}})
    if not p:
        out.append('CL3 an unknown class passes')
    p, _ = B.check_records(t / 'empty', {'records': {'tx': {'DCX': 1}}})
    if not p:
        out.append('CL3 an unknown class in classes.json passes')
    return out


def cl4(P):
    out = []
    import subprocess
    show = lambda rel: subprocess.run(['git', '-C', str(ROOT), 'show', f'HEAD:{rel}'], capture_output=True).stdout.decode()
    v, g, ip = show('cryptography/crypto/proof_verify.go'), show('cryptography/crypto/proof_generate.go'), show('cryptography/crypto/proof_innerproduct.go')
    s = P.transcript_summary(P.transcript(v, g, ip))
    for k, want in PIN_FQ4.items():
        if s.get(k) != want:
            out.append(f'CL4 FQ4 pin {k}: HEAD has {s.get(k)!r}, pinned {want!r}')
    if s.get('challenges_by_func') != {'proof': 9, 'innerproduct': 1}:
        out.append(f'CL4 challenge split {s.get("challenges_by_func")}')
    v2 = v.replace('\t\tinput = append(input, sigmasupport.A_u.Marshal()...)\n',
                   '\t\tinput = append(input, sigmasupport.A_u.Marshal()...)\n\t\tinput = append(input, ConvertBigIntToByte(proof.mu)...)\n', 1)
    s2 = P.transcript_summary(P.transcript(v2, g, ip))
    if v2 == v or not s2['mu_in_a_preimage'] or s2['preimage_sha256'] == s['preimage_sha256']:
        out.append('CL4 a preimage that binds mu is not seen')
    s3 = P.transcript_summary(P.transcript(v, None, ip))
    if s3['challenges'] != 9:
        out.append('CL4 the hashmash1 challenge is not inlined from proof_generate.go')
    if P.transcript_summary(P.transcript('package x', g, ip)).get('found') is not False:
        out.append('CL4 a missing Verify is not reported')
    return out


def fake_reader(files):
    return lambda root, rev, rel: files.get(rev, {}).get(rel)


def cl5(P):
    out = []
    pv = ('u_x := new(bn256.G1).ScalarMult(gparams.H, o)\n'
          'P = new(bn256.G1).Add(P, new(bn256.G1).ScalarMult(gparams.H, new(big.Int).Mod(new(big.Int).Neg(proof.mu), bn256.Order)))\n')
    ipf = 'x\n\tif P_calculated.String() != P.String() { // need something better here\n'
    files = {'R1': {'cryptography/crypto/proof_verify.go': pv, 'cryptography/crypto/proof_innerproduct.go': ipf,
                    'blockchain/hardfork_fixes.go': '\tvar HF3_Affected_Txs = map[string]*HF3_Tx_Data{ // the table\n',
                    'blockchain/transaction_verify.go': 'if t, ok := HF3_Affected_Txs[tx_hash.String()]; ok {\n'},
             'R0': {'crypto/proof_verify.go': '\n' + pv}}
    rd = fake_reader(files)
    o = P.presence(ROOT, ['R1', 'R0'], reader=rd)
    d2 = o['classes']['DC2']
    if d2['R1']['admits'] is not True or d2['R1']['anchors'][0]['anchor'] != 'cryptography/crypto/proof_verify.go:1':
        out.append(f'CL5 DC2 at R1 {d2["R1"]}')
    if d2['R0']['admits'] is not False or d2['R0']['anchors'][0]['anchor'] != 'crypto/proof_verify.go:2':
        out.append(f'CL5 path alias / a missing anchor at R0 {d2["R0"]}')
    d1 = o['classes']['DC1']['R1']
    if d1['admits'] is not True or d1['closures_present'] != 0 or d1['closures_total'] != 2:
        out.append(f'CL5 closure anchors decide admits {d1}')
    if o['headline']['dc2_present_now'] is not True:
        out.append('CL5 headline does not follow DC2 at the first rev')
    o2 = P.presence(ROOT, ['R0'], reader=rd)
    if o2['headline']['dc2_present_now'] is not False:
        out.append('CL5 headline claims DC2 present without its anchors')
    return out


def cl6(B, t):
    out = []
    ds = t / 'forensics' / 'r26' / 'derived'
    ds.mkdir(parents=True)
    cl = {'figures': [{'id': 'x', 'class': 'DC2'}], 'classes': {c: {} for c in ('DC0', 'DC1', 'DC2', 'DC3')}, 'records': {},
          'headline': {'dc2_present_now': True}}
    pr = {'revs': [{'rev': 'HEAD'}], 'headline': {'dc2_present_now': True},
          'classes': {c: {'HEAD': {'admits': True, 'anchors': [{'anchor': 'f.go:1'}]}} for c in ('DC1', 'DC2', 'DC3')}}
    (ds / 'classes.json').write_text(json.dumps(cl))
    (ds / 'presence.json').write_text(json.dumps(pr))
    nod = lambda p, r: []
    ok, det = B.g32(t, pres_check=nod)
    if not ok or 'pending' not in det:
        out.append(f'CL6 no ledger page yet must pass as pending: {det[:120]}')
    ok, _ = B.g32(t, pres_check=lambda p, r: ['DC2 @ HEAD moved'])
    if ok:
        out.append('CL6 a presence drift passes')
    a = t / 'artifacts'
    a.mkdir()
    H = '<p data-fc-headline="dc2-present">DC2 is present in the current consensus code</p>'
    (a / 'dero-r1-r26.html').write_text(H)
    (a / 'dero-src-arch.html').write_text(H)
    ok, _ = B.g32(t, pres_check=nod)
    if ok:
        out.append('CL6 a missing soundness headline passes once the ledger page exists')
    (a / 'dero-soundness-r26.html').write_text(H)
    ok, det = B.g32(t, pres_check=nod)
    if not ok:
        out.append(f'CL6 three headlines refused: {det[:160]}')
    (a / 'dero-src-arch.html').write_text('<p data-fc-headline="dc2-present">DC2 status: see below</p>')
    ok, _ = B.g32(t, pres_check=nod)
    if ok:
        out.append('CL6 a headline that does not say DC2 is present passes')
    (a / 'dero-src-arch.html').write_text(H)
    c2 = copy.deepcopy(cl); c2['headline']['dc2_present_now'] = False
    (ds / 'classes.json').write_text(json.dumps(c2))
    ok, _ = B.g32(t, pres_check=nod)
    if ok:
        out.append('CL6 classes.json headline differing from presence.json passes')
    (ds / 'classes.json').write_text(json.dumps(cl))
    p2 = copy.deepcopy(pr); del p2['classes']['DC3']
    (ds / 'presence.json').write_text(json.dumps(p2))
    ok, _ = B.g32(t, pres_check=nod)
    if ok:
        out.append('CL6 a class without a presence entry passes')
    (ds / 'presence.json').write_text(json.dumps(pr))
    c3 = copy.deepcopy(cl); c3['figures'][0]['class'] = 'DCZ'
    (ds / 'classes.json').write_text(json.dumps(c3))
    ok, _ = B.g32(t, pres_check=nod)
    if ok:
        out.append('CL6 a figure without a valid class passes')
    return out


def cl7(V, t):
    out = []
    base = t / 'forensics' / 'rB'
    (base / 'derived' / 'archive_state').mkdir(parents=True)
    (base / 'derived' / 'archive_state' / 'roots.jsonl.gz').write_bytes(gzip.compress(
        (json.dumps({'topo': 50, 'root': 'ab' * 32, 'state_version_topo_record': 7}) + '\n').encode(), mtime=0))
    good = {'ok': True, 'root': 'ab' * 32, 'version': 7, 'balance_tree_keys': 10, 'sc_meta_keys': 1, 'sc_tree_keys_total': 3,
            'sc_tree_key_lengths': {'33': 2}}
    q = V.qcs1(good, 50, base)
    if not q['status'].startswith('answered') or q['balance_tree_keys'] != 10 or q['sc_tree_keys_length_33'] != 2:
        out.append(f'CL7 a matching census not answered {q}')
    for bad in (dict(good, root='cd' * 32), dict(good, version=8), dict(good, ok=False, error='x')):
        if V.qcs1(bad, 50, base)['status'].startswith('answered'):
            out.append('CL7 a census whose root/version differs is answered')
    if V.qcs1(good, 51, base)['status'].startswith('answered'):
        out.append('CL7 a census at an unrecorded topo is answered')
    files = {'HEAD': {f: '\n'.join(q for _, _, ff, q in V.QCS2_ANCHORS if ff == f) for _, _, f, _ in V.QCS2_ANCHORS}}
    o = V.build(ROOT, None, None, None, reader=fake_reader(files))
    if o['Q-CS2']['answer'] != 'no' or o['Q-CS3']['answer'] != 'no' or o['status'] != 'partial':
        out.append(f'CL7 all anchors present: {o["Q-CS2"]["answer"]} {o["status"]}')
    f2 = copy.deepcopy(files)
    f2['HEAD']['walletapi/daemon_communication.go'] = 'nothing here'
    o2 = V.build(ROOT, None, None, None, reader=fake_reader(f2))
    if o2['Q-CS2']['answer'] != 'pending' or o2['Q-CS3']['answer'] != 'pending':
        out.append('CL7 a missing anchor does not turn Q-CS2/3 pending')
    return out


def cl8(C):
    out = []
    st = [{'ok': True, 'txid': T1, 'payloads': [{'d_sha256': 'd1'}]}, {'ok': True, 'txid': T3, 'payloads': [{'d_sha256': 'd1'}]},
          {'ok': True, 'txid': T2, 'payloads': [{'d_sha256': 'd2'}, {'d_sha256': 'd2'}]}, {'ok': False, 'txid': 'x', 'payloads': []}]
    s = C.struct_census(st, {T1, T2})
    if s['commitments_shared_across_txs'] != 1 or s['txs_with_a_shared_commitment'] != 2:
        out.append(f'CL8 cross-tx sharing {s}')
    if s['table_txs_with_a_shared_commitment'] != [T1]:
        out.append(f'CL8 per-tx list not limited to table TXIDs {s["table_txs_with_a_shared_commitment"]}')
    if s['txs_with_intra_tx_shared_commitment'] != 1 or s['bodies_decoded'] != 3 or s['payloads'] != 4:
        out.append(f'CL8 intra-tx / decode counts {s}')
    # two payloads without a D are not one shared commitment (the helper's 'missing: ...' marker is not a digest)
    miss = 'missing: no D in the statement'
    s2 = C.struct_census([{'ok': True, 'txid': T1, 'payloads': [{'d_sha256': miss}]}, {'ok': True, 'txid': T3, 'payloads': [{'d_sha256': miss}]}], {T1})
    if s2['commitments_shared_across_txs'] != 0 or s2['table_txs_with_a_shared_commitment'] or s2['payloads'] != 2:
        out.append(f'CL8 a missing D counted as a shared commitment {s2}')
    return out


def cl10(C, t):
    """CL10 (verify r26): DC1-obs is COMPUTED from the criteria: an S-R22 hit on a table TXID makes DC1-obs 1, DC1-pending
    the rest, and the amount figure pending (never 'none determinable'); no hit keeps 0 and 'none determinable'"""
    out = []
    ds = forge(t)
    I = lambda: C.Inputs(t / 'forensics' / 'rN', ds, t)
    hit = [{'ok': True, 'txid': T1, 'payloads': [{'d_sha256': 'd1'}]}, {'ok': True, 'txid': T3, 'payloads': [{'d_sha256': 'd1'}]}]
    cl, fq = C.build(I(), None, None, hit, None)
    f = {x['id']: x for x in cl['figures']}
    if f['dc1-obs-coverage']['value'] != 1 or f['dc1-obs-coverage']['coverage']['num'] != 1:
        out.append(f'CL10 an S-R22 table hit is not DC1-obs: {f["dc1-obs-coverage"]["value"]}')
    if not str(f['dc1-obs-amount']['value']).startswith('pending'):
        out.append(f'CL10 DC1-obs amount claims {f["dc1-obs-amount"]["value"]!r} with a non-empty DC1-obs')
    if cl['classes']['DC1']['subclasses'] != {'DC1-obs': 1, 'DC1-hidden': 0, 'DC1-pending': 1} or fq['FQ2']['coverage']['dc1_obs'] != 1:
        out.append(f'CL10 subclasses {cl["classes"]["DC1"]["subclasses"]} / FQ2 {fq["FQ2"]["coverage"]}')
    cl0, _ = C.build(I(), None, None, [], None)
    f0 = {x['id']: x for x in cl0['figures']}
    if f0['dc1-obs-coverage']['value'] != 0 or not f0['dc1-obs-amount']['value'].startswith('none determinable'):
        out.append(f'CL10 no hit: {f0["dc1-obs-coverage"]["value"]} / {f0["dc1-obs-amount"]["value"]}')
    (ds / 'derived' / 'tx' / f'{T2}.json').write_text(json.dumps({'txid': T2, 'value_field': 0, 'burn_total': 7}))
    cl1_, _ = C.build(I(), None, None, [], None)
    if {x['id']: x for x in cl1_['figures']}['dc1-obs-coverage']['value'] != 1:
        out.append('CL10 a P1 table hit is not DC1-obs')
    return out


def cl9(P):
    out = []
    files = {'A': {P.WALLET: 'x\n' + P.WALLET_R + '\n'}, 'B': {P.WALLET: 'x\n' + P.WALLET_R + '\nfunc pick_ring_order(\n'},
             'C': {P.WALLET: 'no such line'}, 'HEAD': {P.WALLET: P.WALLET_R + '\nfunc pick_ring_order(\n'}}
    w = P.wallet_r(ROOT, fake_reader(files), ['A', 'B', 'C'])
    if w['tags_total'] != 3 or w['tags_with_deterministic_r'] != 2 or w['tags_with_pick_ring_order'] != 1:
        out.append(f'CL9 wallet census {w}')
    if w['reading'] != 'see rows' or w['head_pick_ring_order_line'] != 2:
        out.append(f'CL9 reading claims no boundary on mixed tags: {w["reading"]}')
    w2 = P.wallet_r(ROOT, fake_reader(files), ['A'])
    if not w2['reading'].startswith('every tag'):
        out.append('CL9 the all-tags reading is not given')
    return out


def kats(base):
    C = load(base, 'forensics/classes.py', 'classes')
    B = load(base, 'forensics/bounds.py', 'bounds')
    P = load(base, 'forensics/presence.py', 'presence')
    V = load(base, 'forensics/invariant.py', 'invariant')
    out = []
    for fn, args in ((cl1, (C,)), (cl2, (C,)), (cl3, (B,)), (cl6, (B,)), (cl7, (V,)), (cl10, (C,))):
        with tempfile.TemporaryDirectory(prefix='clk_') as t:
            out += fn(*args, Path(t))
    out += cl4(P) + cl5(P) + cl8(C) + cl9(P)
    return out


def committed():
    B = load(HARNESS, 'forensics/bounds.py', 'bc')
    ds = B.classes_dataset(ROOT)
    if ds is None:
        return []
    ok, det = B.g32(ROOT)
    return [] if ok else [f'G32 on this tree: {det[:300]}']


MUTATIONS = [
    ('classes.py', "    return 'DC1' if rec.get('txid') in table else 'DC3'", "    return 'DC1'"),
    ('classes.py', "    dc0 = sorted(t for t in multi if t not in table)", "    dc0 = sorted(t for t in multi)"),
    ('classes.py', "    if 'class' in rec and rec['class'] in SLOT_VALUES:", "    if 'class' in rec:"),
    ('classes.py', "    if any(v.get('version') == ds.name and v.get('sealed') for v in led.get('versions', [])) or ds.name == 'r25':",
     "    if ds.name == 'r25':"),
    ('classes.py', "    if any(v.get('version') == ds.name and v.get('sealed') for v in led.get('versions', [])) or ds.name == 'r25':",
     "    if any(v.get('version') == ds.name and v.get('sealed') for v in led.get('versions', [])):"),
    ('classes.py', "    p1_txids = {r['txid'] for r in txr if r.get('txid') in table and (r.get('value_field') or r.get('burn_total'))}",
     "    p1_txids = set()"),
    ('classes.py', "        if len(ds) != len(set(ds)):", "        if False:"),
    ('classes.py', "    shared = {d: t for d, t in d2tx.items() if len(t) > 1}", "    shared = {d: t for d, t in d2tx.items() if len(t) > 2}"),
    ('classes.py', "            'table_txs_with_a_shared_commitment': sorted(t for t in txs if t in table),",
     "            'table_txs_with_a_shared_commitment': txs,"),
    ('classes.py', "        n['window_DC3'] = len(rows)", "        n['window_DC3'] = len(rows) - 1"),
    ('bounds.py', "            if c not in CLASS_IDS:\n                p.append(f'derived/{kind}/{f.name}: defect_class {c!r}')",
     "            if False:\n                p.append(f'derived/{kind}/{f.name}: defect_class {c!r}')"),
    ('bounds.py', "                if seen[(kind, c)] != n:", "                if False:"),
    ('bounds.py', "            if c not in CLASS_IDS:\n                p.append(f'records.{kind}: unknown class {c}')", "            if False:\n                pass"),
    ('bounds.py', "    if present and led.exists():", "    if False:"),
    ('bounds.py', "            if not pg.exists() or not headline_ok(pg.read_text()):", "            if not pg.exists():"),
    ('bounds.py', "    return 'DC2' in t and re.search(r'\\bpresent\\b', t, re.I) is not None", "    return True"),
    ('bounds.py', "            fails += [f'presence re-read: {x}' for x in pres_check(ds / 'derived' / 'presence.json', root)]", "            pass"),
    ('bounds.py', "        if cl.get('headline', {}).get('dc2_present_now') != pr.get('headline', {}).get('dc2_present_now'):", "        if False:"),
    ('bounds.py', "            if not row or not row.get('anchors'):", "            if False:"),
    ('bounds.py', "        if f.get('class') not in CLASS_IDS:\n            fails.append(f'figure {f.get(\"id\")}: no class')", "        if False:\n            pass"),
    ('presence.py', "            admits = all(g['present'] for g in core)", "            admits = all(g['present'] for g in got)"),
    ('presence.py', "        if q and q in norm(l):", "        if q and q == norm(l):"),
    ('presence.py', "        'dc2_present_now': head.get('admits') is True,", "        'dc2_present_now': True,"),
    ('presence.py', "            if mm.group(1) in methods:", "            if False:"),
    ('presence.py', "        ib, ifirst = _func_body(ip_src, r'^func \\(ip \\*InnerProduct\\) Verify\\(')", "        ib, ifirst = None, 0"),
    ('presence.py', "            'fields_named_in_preimages': names, 'mu_in_a_preimage': 'mu' in names,", "            'fields_named_in_preimages': names, 'mu_in_a_preimage': False,"),
    ('presence.py', "            cur = []\n            continue", "            continue"),
    ('presence.py', "    with_r = [r['tag'] for r in rows if r['deterministic_r_line']]", "    with_r = [r['tag'] for r in rows]"),
    ('presence.py', "            if rows and len(with_r) == len(rows) and not any(r['pick_ring_order'] for r in rows) else 'see rows',",
     "            if rows else 'see rows',"),
    ('invariant.py', "    if c.get('root') != want or c.get('version') != ver:", "    if c.get('root') != want:"),
    ('invariant.py', "    if c.get('root') != want or c.get('version') != ver:", "    if c.get('version') != ver:"),
    ('invariant.py', "    ok = all(a['ok'] for a in anchors)", "    ok = True"),
    ('invariant.py', "    sc33 = int(c.get('sc_tree_key_lengths', {}).get('33', 0))", "    sc33 = 0"),
    ('classes.py', "    n_obs = len(p1_txids | set(sc['table_txs_with_a_shared_commitment'])) if sc else 'pending'",
     "    n_obs = 0 if sc else 'pending'"),
    ('classes.py', "    n_obs = len(p1_txids | set(sc['table_txs_with_a_shared_commitment'])) if sc else 'pending'",
     "    n_obs = len(set(sc['table_txs_with_a_shared_commitment'])) if sc else 'pending'"),
    ('classes.py', "                  f'pending: {n_obs} DC1-obs TXID(s); their amounts are not computed here (rule 13)') if sc else 'pending'",
     "                  'none determinable: DC1-obs is empty under the recorded criteria') if sc else 'pending'"),
    ('classes.py', "if not str(p['d_sha256']).startswith('missing')]", "]"),
]


def main():
    f = kats(HARNESS) + committed()
    print('CL1-CL10:', 'PASS' if not f else 'FAIL\n  ' + '\n  '.join(f))
    if f:
        return 3
    rc, caught, n = 0, 0, 0
    for i, (fn, old, new) in enumerate(MUTATIONS, 1):
        n += 1
        tmp = Path(tempfile.mkdtemp(prefix='clmut_'))
        try:
            shutil.copytree(HARNESS / 'forensics', tmp / 'forensics')
            src = (tmp / 'forensics' / fn).read_text()
            if src.count(old) != 1:
                print(f'mutation {i} INVALID: text found {src.count(old)} times in {fn}'); rc = 4; continue
            (tmp / 'forensics' / fn).write_text(src.replace(old, new, 1))
            try:
                mf = kats(tmp)
            except Exception as e:                                   # noqa: BLE001
                print(f'mutation {i} INVALID: {type(e).__name__}: {e}'); rc = 4; continue
            if mf:
                caught += 1
                print(f'mutation {i} CAUGHT ({fn}): {mf[0][:100]}')
            else:
                print(f'mutation {i} NOT CAUGHT ({fn}): {old.strip()[:80]}'); rc = 4
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f'mutations caught {caught}/{n}')
    return rc


if __name__ == '__main__':
    sys.exit(main())
