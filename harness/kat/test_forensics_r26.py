#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for dataset v2 (R26 forensics-data; artifacts/dero-rft.md §0.8.3, §0.8.7 R26).
No network, no live file read or written. Extends MF1-MF12 (test_forensics_r25.py) with:

  MF13 tx bodies, check (iii) with two implementations (v2.check_tx): a good body passes; a node TXID that differs, a
       TXID in no verified block, a Python Keccak-256 of the core bytes that differs (decoder and Python disagree) and
       a decode failure each FAIL. Committed: every raw/tx_bodies row has all three checks True and its body in the
       tier B store re-hashes to its sha256 (when the store is present).
  MF14 fees (v2.block_fees): a block with every body known sums fees and burns; one missing body renders `pending: ..`,
       never 0 (rft §0.8.9 rule 10); an empty tx list is 0. Committed: derived/fees.json settles v1's 1,575 pending
       blocks only when blocks_fees has no pending row, and no v1-known row disagrees. v2.sc_count counts the decoder's
       'SC' type (R26 verify: a 'SC_TX' compare counted 0 of 199); committed sc_txs equal the SC rows of derived/txs
       and sc_payouts stay pending while the scope holds any.
  MF15 end-state check (v2.end_state_check): MATCH only at the anchor with our treehash; another root there is a
       DIVERGENCE; a run that stopped earlier is pending, never MATCH. Committed: state_roots runs agree with their roots.
  MF16 roothash witnesses (v2.witnesses): equal / differ against replay roots, the seed top read as an archive root,
       archive roots second, a ref outside both counted apart. Committed: 0 differ.
  MF17 v2 replay (v2.replay; G28 on v2): on a copied tree root a clean replay without the store is `partial` with only
       that reason; a changed v1 input, a changed v2 tool, a changed HF3 table, an altered or unlisted dataset file each
       FAIL with their reason; `bodies` and `wall1` refuse v1's tier B store as --store before any work (v1's replay
       hashes that store's listing: one added blob FAILS v1, self-detected in R26). Committed: the v1 inputs the v2
       manifest pins equal the files (v1 never rewritten).
       R26 merge: the four forensics-classes files (v2.CLASS_FILES) are pinned but not re-derived by v2 (v2.rederived);
       an altered classes file FAILS; committed: each one on disk is listed in `files` and `class_files` and absent
       from replay/expected.sha256 (before this the merged tree failed G28: 4 unlisted files).
  MF18 class slot (v2.class_slot_problems): a record without `class` or `evidence_class`, or with an empty class,
       FAILS; committed per-tx / per-block / per-topo records all carry it.

  python3 harness/kat/test_forensics_r26.py      exit 0 PASS, 3 a KAT failed, 4 a mutation not caught / invalid
"""
import gzip, json, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
DS = ROOT / 'forensics' / 'r26'
STORE = Path.home() / 'derohe-persist' / 'forensics_raw_r26'


def load(base):
    sys.path.insert(0, str(base / 'forensics'))
    for m in ('v2', 'keccak', 'provenance'):
        sys.modules.pop(m, None)
    import v2  # noqa: E402
    sys.path.pop(0)
    return v2


def rows(p):
    return [json.loads(l) for l in gzip.open(p)] if p.exists() else []


def safe(fn, *a):
    """call a rule under test; an exception where a refusal or a value was expected is a failure, returned as None"""
    try:
        return fn(*a)
    except Exception:
        return None


def mf13(v2, committed=True):
    f = []
    core = b'forged core statement bytes'
    txid = v2.keccak.keccak256(core).hex()
    blid = 'ab' * 32
    good = {'ok': True, 'txid': txid, 'core_hex': core.hex(), 'reserialize_equal': True}
    ch, _ = v2.check_tx(txid, b'x', good, {blid: [txid]})
    if not all(ch.get(k) is True for k in ('iii_txid', 'iii_in_block', 'py_keccak_eq')):
        f.append('MF13 a good body did not pass check (iii)')
    for name, dec, lists in [
        ('node TXID differs', dict(good, txid='cd' * 32), {blid: [txid]}),
        ('in no verified block', good, {blid: ['ef' * 32]}),
        ('python keccak differs', dict(good, core_hex=(core + b'!').hex()), {blid: [txid]}),
        ('decode failure', {'ok': False, 'error': 'x'}, {blid: [txid]})]:
        ch, _ = v2.check_tx(txid, b'x', dec, lists)
        if all(ch.get(k) is True for k in ('iii_txid', 'iii_in_block', 'py_keccak_eq')):
            f.append(f'MF13 a body with {name} passed check (iii)')
    if committed:
        rs = rows(DS / 'raw/tx_bodies.jsonl.gz')
        if not rs:
            f.append('MF13 committed raw/tx_bodies.jsonl.gz is empty or missing')
        for r in rs:
            if not all(r['checks'].get(k) is True for k in ('iii_txid', 'iii_in_block', 'py_keccak_eq')):
                f.append(f"MF13 committed body {r['txid'][:16]} lacks a passed check")
                break
            b = v2.read_store([STORE], r['sha256']) if (STORE / 'blobs').is_dir() else b''
            if b is None:
                f.append(f"MF13 committed body {r['txid'][:16]} is missing from the tier B store")
                break
    return f


def mf14(v2, committed=True):
    f = []
    tr = {'a': {'fee': 80, 'burn_total': 5}, 'b': {'fee': 20, 'burn_total': 0}}
    if safe(v2.block_fees, ['a', 'b'], tr) != (100, 5):
        f.append('MF14 known bodies do not sum to (100, 5)')
    fe, bu = (safe(v2.block_fees, ['a', 'c'], tr) or ('raised', 0))
    if not (isinstance(fe, str) and fe.startswith('pending') and isinstance(bu, str)):
        f.append(f'MF14 a block with a missing body rendered {fe!r} (must be pending, never 0)')
    if safe(v2.block_fees, [], tr) != (0, 0):
        f.append('MF14 an empty tx list is not (0, 0)')
    # SC_TX count (R26 verify: the decoder's tx_type is TransactionType.String() = 'SC'; a 'SC_TX' compare counted 0)
    st = {'s': {'tx_type': 'SC'}, 'n': {'tx_type': 'NORMAL'}, 'r': {'tx_type': 'REGISTRATION'}}
    if safe(v2.sc_count, ['s', 'n', 'r', 's', 'x'], st) != 2:
        f.append('MF14 sc_count of [SC, NORMAL, REGISTRATION, SC, missing] is not 2')
    if committed:
        txr = {r['txid']: r for r in rows(DS / 'derived/txs.jsonl.gz')}
        hc = {}
        for r in rows(ROOT / 'forensics/r25/raw/headerchain.jsonl.gz'):
            hc[r['height']] = r
        want = sum(1 for h, r in hc.items() if v2.WINDOW[0] <= h <= v2.ANCHOR_TOPO
                   for t in r.get('tx_hashes') or [] if txr.get(t, {}).get('tx_type') == 'SC')
        fees = json.loads((DS / 'derived/fees.json').read_text())
        br = rows(DS / 'derived/blocks_fees.jsonl.gz')
        pend = [b for b in br if not isinstance(b['fees'], int)]
        if fees['v2']['still_pending'] != len([b for b in pend if b['v1_fees_status'] == 'pending']):
            f.append('MF14 committed fees.json still_pending disagrees with blocks_fees rows')
        if fees['v1_known_rows_disagreeing']:
            f.append('MF14 committed v2 fees disagree with v1 known rows')
        if fees['v2']['sc_txs'] != want or sum(b['sc_txs'] for b in br) != want:
            f.append(f"MF14 committed sc_txs {fees['v2']['sc_txs']} != SC txs in derived/txs of the scope ({want})")
        if want and fees['sc_payouts'] != v2.PENDING_SC:
            f.append('MF14 committed sc_payouts is not pending although the scope holds SC txs')
    return f


def mf15(v2, committed=True):
    f = []
    ours = 'aa' * 32
    if v2.end_state_check({7: {'root': ours}}, 7, ours) != 'MATCH':
        f.append('MF15 an anchor root equal to ours is not MATCH')
    if v2.end_state_check({7: {'root': 'bb' * 32}}, 7, ours) != 'DIVERGENCE':
        f.append('MF15 an anchor root differing from ours is not DIVERGENCE')
    r = safe(v2.end_state_check, {5: {'root': ours}}, 7, ours) or 'raised'
    if not r.startswith('pending'):
        f.append(f'MF15 a run that stopped before the anchor rendered {r!r}')
    if not (safe(v2.end_state_check, {}, 7, ours) or 'raised').startswith('pending'):
        f.append('MF15 an empty run is not pending')
    if committed:
        sr = json.loads((DS / 'derived/state_roots.json').read_text())
        for name, run in sr['runs'].items():
            reached = run['topo_range'] and run['topo_range'][1] >= v2.ANCHOR_TOPO
            if run['end_state_check'] == 'MATCH' and not reached:
                f.append(f'MF15 committed run {name} claims MATCH without reaching the anchor')
    return f


def mf16(v2, committed=True):
    f = []
    tx = lambda ref, rh: {'payloads': [{'roothash': rh}], 'ref_height': ref}
    roots = {10: {'root': 'r10'}, 11: {'root': 'r11'}}
    arch = {10: 'a10', 5: 'a5'}
    w = v2.witnesses({'t1': tx(11, 'r11'), 't2': tx(11, 'zz'), 't3': tx(10, 'a10'), 't4': tx(5, 'a5'), 't5': tx(3, 'q'),
                      't6': {'payloads': [], 'ref_height': 0}}, roots, arch, 10)
    want = {'equal': 1, 'differ': 1, 'archive_equal': 2, 'archive_differ': 0, 'outside_held_roots': 1}
    got = {k: w[k] for k in want}
    if got != want:
        f.append(f'MF16 witnesses {got} != {want}')
    if w['rows_differ'] != ['t2']:
        f.append(f"MF16 rows_differ {w['rows_differ']} != ['t2']")
    if committed:
        sr = json.loads((DS / 'derived/state_roots.json').read_text())
        if sr['roothash_witnesses']['differ'] or sr['roothash_witnesses']['archive_differ']:
            f.append('MF16 committed roothash witnesses differ')
    return f


def copy_root(tmp):
    """a minimal tree for v2.replay: the dataset, its pinned tools, the v1 inputs and the HF3 table"""
    m = json.loads((DS / 'manifest.json').read_text())
    for rel in list(m['tools']) + list(m['inputs']) + [m['hf3_table']['file']]:
        (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, tmp / rel)
    shutil.copytree(DS, tmp / 'forensics' / 'r26')
    return tmp / 'forensics' / 'r26'


def mf17(v2, committed=True):
    f = []
    if not (DS / 'manifest.json').exists():
        return ['MF17 forensics/r26/manifest.json missing']
    cases = [('clean', None), ('v1 input', 'forensics/r25/derived/emission.json'), ('tool', 'harness/forensics/v2.py'),
             ('hf3', 'blockchain/hardfork_fixes.go'), ('dataset file', 'forensics/r26/derived/fees.json'),
             ('unlisted', 'forensics/r26/derived/extra.json')]
    want = {'v1 input': 'v1 input changed', 'tool': 'tool changed', 'hf3': 'HF3 table changed',
            'dataset file': 'missing or changed', 'unlisted': 'unlisted'}
    for name, rel in cases:
        tmp = Path(tempfile.mkdtemp(prefix='fx26_'))
        try:
            ds = copy_root(tmp)
            if rel:
                p = tmp / rel
                p.write_bytes((p.read_bytes() if p.exists() else b'') + b'\n')
            rep = v2.replay(ds, None, tmp)
            reasons = ' | '.join(rep['fail_reasons'])
            if name == 'clean':
                if rep['rederive']['mode'] != 'partial' or len(rep['fail_reasons']) != 1:
                    f.append(f'MF17 a clean copy without the store is not partial-only: {reasons[:120]}')
            elif rep['result'] != 'FAIL' or want[name] not in reasons:
                f.append(f'MF17 a changed {name} did not FAIL with its reason ({reasons[:120]})')
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    # v2 never writes v1's tier B store: v1's replay hashes that store's listing (self-detected in R26, B-row)
    import argparse
    for cmd in (v2.cmd_bodies, v2.cmd_wall1):
        tmp = Path(tempfile.mkdtemp(prefix='fx26s_'))
        try:
            v2.V1_STORE = tmp / 'v1store'  # a stand-in: a mutant that skips the refusal can never touch the real store
            ns = argparse.Namespace(dataset=str(tmp / 'ds'), stage=str(tmp), archive_copy=str(tmp), store=str(v2.V1_STORE))
            try:
                cmd(ns)
                f.append(f'MF17 {cmd.__name__} accepted v1\'s tier B store as its --store')
            except SystemExit as e:
                if "v1's tier B store" not in str(e):
                    f.append(f'MF17 {cmd.__name__} refused v1 store for another reason: {e}')
            except Exception as e:
                f.append(f'MF17 {cmd.__name__} did not refuse v1\'s store before working: {type(e).__name__}')
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    # R26 merge: the forensics-classes files are pinned, never re-derived by v2
    got = safe(getattr(v2, 'rederived', None), {'derived/fees.json': 'a', 'derived/classes.json': 'b', 'derived/presence.json': 'c', 'raw/x.json': 'd'})
    if got != {'derived/fees.json': 'a'}:
        f.append(f'MF17 rederived() kept a class file or a raw file: {got}')
    if (DS / 'derived' / 'classes.json').exists():
        tmp = Path(tempfile.mkdtemp(prefix='fx26c_'))
        try:
            ds = copy_root(tmp)
            p = ds / 'derived' / 'classes.json'
            p.write_bytes(p.read_bytes() + b'\n')
            rep = v2.replay(ds, None, tmp)
            if rep['result'] != 'FAIL' or 'derived/classes.json missing or changed' not in ' | '.join(rep['fail_reasons']):
                f.append('MF17 an altered derived/classes.json did not FAIL the v2 replay')
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    if committed:
        m = json.loads((DS / 'manifest.json').read_text())
        exp = (DS / 'replay' / 'expected.sha256').read_text()
        for rel in getattr(v2, 'CLASS_FILES', None) or ('derived/classes.json', 'derived/fq.json', 'derived/presence.json', 'derived/invariant.json'):
            if (DS / rel).exists():
                if rel not in m['files'] or rel not in (m.get('class_files') or {}):
                    f.append(f'MF17 {rel} is on disk but not pinned as a class file in the manifest')
                if f'  {rel}\n' in exp:
                    f.append(f'MF17 {rel} is in expected.sha256 (v2 would have to re-derive it)')
        # verify_dataset L7 (G28) reads the same class_files exception from the manifest
        sys.path.insert(0, str(HARNESS / 'forensics'))
        sys.modules.pop('verify_dataset', None)
        import verify_dataset  # noqa: E402
        sys.path.pop(0)
        l7 = [x for x in verify_dataset.verify(ROOT / 'forensics', ROOT)[0] if x.startswith('L7 ')]
        if l7:
            f.append('MF17 ' + l7[0])
        for rel, h in m['inputs'].items():
            if v2.fsha(ROOT / rel) != h:
                f.append(f'MF17 v1 input {rel} differs from the v2 manifest pin (v1 rewritten?)')
        if m.get('supersedes') != []:
            f.append('MF17 v2 supersedes something (planned: [])')
    return f


def mf18(v2, committed=True):
    f = []
    if v2.class_slot_problems([{'class': 'pending', 'evidence_class': 'RAW'}]):
        f.append('MF18 a record with both slots was flagged')
    for bad in ({'evidence_class': 'RAW'}, {'class': 'pending'}, {'class': '', 'evidence_class': 'RAW'}):
        if not safe(v2.class_slot_problems, [bad]):
            f.append(f'MF18 a record {bad} passed the class-slot check')
    if committed:
        for rel in ('raw/tx_bodies.jsonl.gz', 'derived/txs.jsonl.gz', 'derived/blocks_fees.jsonl.gz',
                    'derived/roots_window.jsonl.gz'):
            p = v2.class_slot_problems(rows(DS / rel), rel)
            if p:
                f.append('MF18 committed ' + p[0])
    return f


TESTS = {'MF13': mf13, 'MF14': mf14, 'MF15': mf15, 'MF16': mf16, 'MF17': mf17, 'MF18': mf18}

MUTATIONS = [
    ('MF13', 'forensics/v2.py', "    checks['py_keccak_eq'] = bool(core) and keccak.keccak256(core).hex() == txid",
     "    checks['py_keccak_eq'] = True"),
    ('MF13', 'forensics/provenance.py', "    if not carriers:", "    if False:"),
    ('MF14', 'forensics/v2.py', "    if len(have) != len(txs):\n        why", "    if False:\n        why"),
    ('MF14', 'forensics/v2.py', "    return sum(txrows[t]['fee'] for t in txs), sum(txrows[t]['burn_total'] for t in txs)",
     "    return sum(txrows[t]['fee'] for t in txs), sum(txrows[t]['fee'] for t in txs)"),
    ('MF14', 'forensics/v2.py', "txrows[t]['tx_type'] == SC_TX_TYPE)", "txrows[t]['tx_type'] == 'SC_TX')"),
    ('MF15', 'forensics/v2.py', "    return 'MATCH' if end['root'] == ours else 'DIVERGENCE'", "    return 'MATCH'"),
    ('MF15', 'forensics/v2.py', "    if end is None:\n        last", "    if False:\n        last"),
    ('MF16', 'forensics/v2.py', "        if ref in roots and ref != seed_top:", "        if ref in roots:"),
    ('MF16', 'forensics/v2.py', "            k = 'equal' if roots[ref]['root'] == rh else 'differ'", "            k = 'equal'"),
    ('MF17', 'forensics/v2.py', "            f.append(f'v1 input changed: {t}')", "            pass"),
    ('MF17', 'forensics/v2.py', "            f.append(f'tool changed: {t}')", "            pass"),
    ('MF17', 'forensics/v2.py', "        f.append(f'manifest: unlisted {rel}')", "        pass"),
    ('MF17', 'forensics/v2.py', "    if Path(a.store).resolve() == V1_STORE.resolve():\n        raise SystemExit(\"refused: --store is v1's tier B store; v1",
     "    if False:\n        raise SystemExit(\"refused: --store is v1's tier B store; v1"),
    ('MF17', 'forensics/v2.py', "    if Path(a.store).resolve() == V1_STORE.resolve():\n        raise SystemExit(\"refused: --store is v1's tier B store\")",
     "    if False:\n        raise SystemExit(\"refused: --store is v1's tier B store\")"),
    ('MF17', 'forensics/v2.py', "if k.startswith('derived/') and k not in CLASS_FILES}", "if k.startswith('derived/')}"),
    ('MF17', 'forensics/v2.py', "if k.startswith('derived/') and k not in CLASS_FILES}", "if k not in CLASS_FILES}"),
    ('MF18', 'forensics/v2.py', "        if not isinstance(r, dict) or 'class' not in r or 'evidence_class' not in r:",
     "        if not isinstance(r, dict):"),
    ('MF18', 'forensics/v2.py', "        elif not isinstance(r['class'], str) or not r['class']:", "        elif False:"),
]


def main():
    rc = 0
    v2 = load(HARNESS)
    for k, fn in TESTS.items():
        f = fn(v2, True)
        print(f"{k}: {'PASS' if not f else 'FAIL'}" + ('' if not f else '\n  ' + '\n  '.join(f[:5])))
        if f:
            rc = 3
    if rc:
        return rc
    caught = 0
    for i, (k, rel, old, new) in enumerate(MUTATIONS, 1):
        tmp = Path(tempfile.mkdtemp(prefix='fx26mut_'))
        try:
            shutil.copytree(HARNESS / 'forensics', tmp / 'forensics')
            src = (tmp / rel).read_text()
            if src.count(old) != 1:
                print(f'mutation {i} ({k}) INVALID: text found {src.count(old)} times'); rc = 4; continue
            (tmp / rel).write_text(src.replace(old, new, 1))
            try:
                f = TESTS[k](load(tmp), False)
            except Exception as e:
                print(f'mutation {i} ({k}) INVALID: mutant did not load/run: {type(e).__name__}: {e}'); rc = 4; continue
            if f:
                caught += 1
                print(f'mutation {i} ({k}) CAUGHT: {f[0][:100]}')
            else:
                print(f'mutation {i} ({k}) NOT CAUGHT: {old.strip()[:60]}'); rc = 4
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f'mutations caught {caught}/{len(MUTATIONS)}')
    return rc


if __name__ == '__main__':
    sys.exit(main())
