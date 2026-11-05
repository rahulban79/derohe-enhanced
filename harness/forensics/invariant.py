#!/usr/bin/env python3
"""R26 current-state questions and the missing-invariant certificate (rft §0.8.9 Q-CS1..3; B111, B112).

  python3 -I harness/forensics/invariant.py [--census FILE --census-topo N --base forensics/r25] [--write forensics/r26/derived/invariant.json]
  python3 -I harness/forensics/invariant.py --check forensics/r26/derived/invariant.json     # re-read every anchor, exit 9 on drift

Q-CS1 (enumeration): the census FILE is the output of tools/forensics/classstats kind=census, run on an APFS clone of a
held archive (never the live store, never ~/dero-data). It is accepted only when its Load_Merkle_Hash root equals the
root the base dataset recorded for that topo (derived/archive_state/roots.jsonl.gz); otherwise Q-CS1 stays `pending`
with the mismatch as its evidence.
Q-CS2 / Q-CS3 (conservation relation; certificate): answered from SOURCE anchors, each re-read now by its quote at HEAD
(`git show`). An anchor that does not re-read turns the answer into `pending`. These are INTERPRETATIONS of SRC; the
independent audit (forensics-audit2) refutes by default. No amount is opened, related or estimated here (rule 13).
"""
import argparse, gzip, hashlib, json, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
R22_KEYS = {'count': 2141950, 'version': 337537, 'source': 'memory dero-crypto-audit-r22 (APFS clone of the live store, 2026-10-29)',
            'class': 'EXT to this dataset (an earlier round\'s measurement, not re-derivable here)'}

QCS2_ANCHORS = [
    ('balance_encoding', 'an account balance is an ElGamal pair (Left, Right)', 'cryptography/crypto/algebra_elgamal.go', 'type ElGamal struct {'),
    ('per_account_key', 'a new balance is an encryption of zero under the account\'s own public key', 'blockchain/transaction_execute.go',
     'balance := crypto.ConstructElGamal(acckey.G1(), crypto.ElGamal_BASE_G) // init zero balance'),
    ('homomorphic_update_delta', 'each payload adds a per-account ciphertext delta built from the statement (C[i], D)', 'blockchain/transaction_execute.go',
     'echanges := crypto.ConstructElGamal(tx.Payloads[t].Statement.C[i], tx.Payloads[t].Statement.D)'),
    ('homomorphic_update', 'the stored balance is updated by ciphertext addition only', 'blockchain/transaction_execute.go',
     'nb.Balance = nb.Balance.Add(echanges) // homomorphic addition of changes'),
    ('ciphertext_add', 'ciphertext addition is component-wise point addition', 'cryptography/crypto/algebra_elgamal.go',
     'func (e *ElGamal) Add(addendum *ElGamal) *ElGamal {'),
    ('opening_needs_secret', 'opening a balance uses the holder\'s secret key', 'walletapi/daemon_communication.go',
     'balance_point.Add(el.Left, new(bn256.G1).Neg(new(bn256.G1).ScalarMult(el.Right, w.account.Keys.Secret.BigInt())))'),
    ('supply_is_formula', 'the reported supply is the emission formula, not a sum of balances', 'cmd/derod/rpc/rpc_dero_getinfo.go',
     'result.Total_Supply = blockchain.CalcSupply(uint64(chain.Get_Height()))'),
    ('sole_magnitude_gate', 'consensus accepts a payload on one proof boolean', 'blockchain/transaction_verify.go',
     'if !tx.Payloads[t].Proof.Verify(tx.Payloads[t].SCID, index, &tx.Payloads[t].Statement, tx.GetHash(), tx.Payloads[t].BurnValue) {'),
    ('node_limit_stated', 'the node\'s own integrity report states that encrypted value is invisible to it', 'cmd/derod/rpc/monetary_integrity.go',
     '"emission: proves only that no plaintext value moved outside the published (C, D) deltas'),
]


def norm(s):
    return re.sub(r'\s+', ' ', s).strip()


def show(root, rev, rel):
    p = subprocess.run(['git', '-C', str(root), 'show', f'{rev}:{rel}'], capture_output=True)
    return p.stdout.decode('utf-8', 'replace') if p.returncode == 0 else None


def read_anchors(root, rev='HEAD', reader=show):
    out = []
    for key, what, f, q in QCS2_ANCHORS:
        t = reader(root, rev, f)
        ln = None
        if t is not None:
            nq = norm(q)
            ln = next((i for i, l in enumerate(t.splitlines(), 1) if nq in norm(l)), None)
        out.append({'id': key, 'what': what, 'anchor': f'{f}:{ln}' if ln else f'absent: quote not found in {f}', 'ok': ln is not None})
    return out


def archive_root(base, topo):
    p = Path(base) / 'derived' / 'archive_state' / 'roots.jsonl.gz'
    if not p.exists():
        return None, None
    for l in gzip.decompress(p.read_bytes()).decode().splitlines():
        r = json.loads(l)
        if r.get('topo') == topo:
            return r.get('root'), r.get('state_version_topo_record')
    return None, None


def qcs1(census, topo, base):
    if census is None:
        return {'status': 'pending: no census run (needs an APFS clone of a held archive or a stopped-node datadir; never the live store)'}
    want, ver = archive_root(base, topo)
    c = census
    if not c.get('ok'):
        return {'status': f'pending: census failed: {c.get("error", "?")}'}
    if c.get('root') != want or c.get('version') != ver:
        why = f'no recorded root for topo {topo} in the base dataset' if want is None else 'census root/version differs from the recorded archive root'
        return {'status': f'pending: {why}', 'census_root': c.get('root'),
                'recorded_root': want, 'census_version': c.get('version'), 'recorded_version': ver}
    sc33 = int(c.get('sc_tree_key_lengths', {}).get('33', 0))
    return {
        'status': 'answered (scope: the held replaywall archive at topo %d, not our anchor 7,498,540)' % topo,
        'scope': {'topo': topo, 'state_version': ver, 'store': 'APFS clone of the replaywall archive copy (read through a clone, never in place)'},
        'root_check': {'census_root': c['root'], 'recorded_root': want, 'equal': True, 'recorded_in': 'derived/archive_state/roots.jsonl.gz'},
        'balance_tree_keys': c['balance_tree_keys'],
        'balance_key_lengths': c.get('balance_key_lengths', {}),
        'sc_meta_keys': c['sc_meta_keys'],
        'sc_tree_keys_total': c['sc_tree_keys_total'],
        'sc_tree_keys_length_33': sc33,
        'sc_tree_keys_length_33_note': 'structural only: a 33-byte key has the length of a compressed point (candidate holder-balance entry); not decoded',
        'r22_comparison': dict(R22_KEYS, difference_r22_minus_this=R22_KEYS['count'] - c['balance_tree_keys'],
                               note='different scope: R22 counted the live store at a later version; the difference is not a finding'),
        'answer': 'every registered account and SC tree entry is enumerable from the state tree (a key count is public); '
                  'the balances they hold are ciphertexts, so enumeration does not make them summable (Q-CS2)',
    }


def build(root=ROOT, census=None, topo=None, base=None, reader=show):
    anchors = read_anchors(root, 'HEAD', reader)
    ok = all(a['ok'] for a in anchors)
    q1 = qcs1(census, topo, base) if census is not None else qcs1(None, None, None)
    q2 = {
        'question': 'Is the aggregate of balances bound by a publicly checkable conservation relation?',
        'status': 'answered (INTERPRETATION of SRC; audit refutes by default)' if ok else 'pending: an anchor did not re-read',
        'answer': 'no' if ok else 'pending',
        'reason': ('every balance is a ciphertext under its holder\'s own key and changes only by ciphertext addition; opening any balance '
                   'needs that holder\'s secret key, and no aggregate key or aggregate opening exists in the code; consensus checks one proof '
                   'boolean per payload and never compares any aggregate with the formula supply, which RPC reports as CalcSupply'),
        'anchors': anchors,
    }
    q3 = {
        'question': 'Can a supply statement be proven from the current state alone?',
        'status': q2['status'],
        'answer': 'no' if ok else 'pending',
        'certificate': {
            'missing_invariant': 'a publicly checkable opening of the aggregate of all balances (or a consensus-checked relation between it and CalcSupply)',
            'absence_shown_by': [a['anchor'] for a in anchors if a['id'] in ('per_account_key', 'homomorphic_update', 'opening_needs_secret', 'supply_is_formula', 'sole_magnitude_gate')],
            'consequence': 'a complete public accounting of the supply of this ledger cannot be derived from public data; '
                           'every aggregate over hidden balances is unbounded while DC2 is open',
            'joins': 'disclosure track FX-N7 (summing the balance tree: infeasible)',
        } if ok else 'pending',
    }
    status = 'answered' if ok and str(q1.get('status', '')).startswith('answered') else 'partial' if ok else 'pending'
    return {'schema': 'r26 invariant v1 (rft §0.8.9 Q-CS1..3)', 'status': status, 'Q-CS1': q1, 'Q-CS2': q2, 'Q-CS3': q3}


def check(path, root=ROOT):
    old = json.loads(Path(path).read_text())
    now = read_anchors(root)
    rec = old['Q-CS2']['anchors']
    return [f'{a["id"]}: recorded {a["anchor"]} now {b["anchor"]}' for a, b in zip(rec, now) if a['anchor'] != b['anchor']] + (
        ['anchor count changed'] if len(rec) != len(now) else [])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--root', default=str(ROOT))
    ap.add_argument('--census')
    ap.add_argument('--census-topo', type=int)
    ap.add_argument('--base', default='forensics/r25')
    ap.add_argument('--write')
    ap.add_argument('--check')
    a = ap.parse_args(argv)
    root = Path(a.root)
    if a.check:
        d = check(a.check, root)
        print('invariant anchors: ' + ('UNCHANGED' if not d else 'CHANGED\n  ' + '\n  '.join(d)))
        return 9 if d else 0
    census = None
    if a.census:
        census = json.loads(Path(a.census).read_text().splitlines()[0])
    out = build(root, census, a.census_topo, root / a.base)
    if a.census:
        out['Q-CS1']['census_output_sha256'] = hashlib.sha256(Path(a.census).read_bytes()).hexdigest()
    if a.write:
        Path(root / a.write).parent.mkdir(parents=True, exist_ok=True)
        (root / a.write).write_text(json.dumps(out, indent=1, sort_keys=True) + '\n')
    print(f"invariant: {out['status']}; Q-CS1 {out['Q-CS1']['status'][:60]}; Q-CS2 {out['Q-CS2']['answer']}; Q-CS3 {out['Q-CS3']['answer']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
