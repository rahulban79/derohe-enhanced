#!/usr/bin/env python3
"""R26 defect-class presence (rft §0.8.9 rule 12, FQ4; B107, B113): for each defect class, the code path that admits
it, re-read at the round's head and at upstream tags, with file:line and present yes / no.

  python3 -I harness/forensics/presence.py [--revs HEAD,Release152,Release153,DeroHE] [--write forensics/r26/derived/presence.json]
  python3 -I harness/forensics/presence.py --check forensics/r26/derived/presence.json    # re-read now, exit 9 on a change

An anchor is {role, files (path aliases, first that exists at the rev wins), quote}. It is read with `git show REV:FILE`
(never the working tree, so a dirty tree cannot fake presence) and found by its quote (whitespace-normalised); its line
is reported, or `absent` with the files tried. A class `admits` at a rev when every non-closure anchor is present; the
closure anchors (the paths that stop NEW cases) are reported next to it. A fix status never changes a historical grade
(rule 10): presence only says what the code at a rev admits now.

FQ4 structural transcript KAT: `transcript()` lists, for Proof.Verify at a rev, every challenge (a reducedhash /
HashtoNumber call) with the expressions of its preimage, and reports their SHA-256 and whether any preimage names
proof.mu. The digest is pinned by harness/kat/test_forensics_classes_r26.py, so an upstream change of what the
challenges bind shows up as a failing KAT and a presence change. It records names only, never values, and no proof is
built or modified (rft §5, §9 NO-GO).
"""
import argparse, hashlib, json, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
VERIFY = ['cryptography/crypto/proof_verify.go', 'crypto/proof_verify.go']
IPROOF = ['cryptography/crypto/proof_innerproduct.go', 'crypto/proof_innerproduct.go']
DEFAULT_REVS = ['HEAD', 'Release152', 'Release153', 'DeroHE']
REV_ROLE = {'HEAD': 'the round head', 'Release152': 'the Release152 tag (HF3 release)',
            'Release153': 'the newest upstream tag in this repository', 'DeroHE': 'the earliest tag in this repository (genesis era, 2020-12-19)'}

ANCHORS = {
    'DC1': [
        {'role': 'the HF3 exemption table (75 TXIDs)', 'files': ['blockchain/hardfork_fixes.go'],
         'quote': 'var HF3_Affected_Txs = map[string]*HF3_Tx_Data{'},
        {'role': 'a table TXID enters the verification cache before any check', 'files': ['blockchain/transaction_verify.go'],
         'quote': 'if t, ok := HF3_Affected_Txs[tx_hash.String()]; ok {'},
        {'role': 'closure: from HF3 the cache key is the hash of the whole tx (height-bound skip)', 'closure': True,
         'files': ['blockchain/transaction_verify.go'], 'quote': 'tx_cache = crypto.Keccak256(tx.Serialize())'},
        {'role': 'closure (node-local): relay/RPC admission refuses the 75 TXIDs by ID', 'closure': True,
         'files': ['glue/txprecheck/window.go'], 'quote': 'if _, ok := blockchain.HF3_Affected_Txs[string(key[:])]; ok {'},
    ],
    'DC2': [
        {'role': 'inner-product generator derived from the checked challenge (C1 anchor 1)', 'files': VERIFY,
         'quote': 'u_x := new(bn256.G1).ScalarMult(gparams.H, o)'},
        {'role': 'the blinding term on the same base (C1 anchor 2)', 'files': VERIFY,
         'quote': 'P = new(bn256.G1).Add(P, new(bn256.G1).ScalarMult(gparams.H, new(big.Int).Mod(new(big.Int).Neg(proof.mu), bn256.Order)))'},
        {'role': 'the final inner-product equality (C1 anchor 3)', 'files': IPROOF,
         'quote': 'if P_calculated.String() != P.String() { // need something better here'},
    ],
    'DC3': [
        {'role': 'the emission formula', 'files': ['blockchain/supply.go'], 'quote': 'func CalcSupply(height uint64) uint64 {'},
        {'role': 'the homomorphic balance update (public deltas are what DC3 can check)', 'files': ['blockchain/transaction_execute.go'],
         'quote': 'nb.Balance = nb.Balance.Add(echanges) // homomorphic addition of changes'},
    ],
}


def norm(s):
    return re.sub(r'\s+', ' ', s).strip()


def git(root, *a):
    p = subprocess.run(['git', '-C', str(root), *a], capture_output=True)
    return p.returncode, p.stdout


def rev_commit(root, rev):
    rc, out = git(root, 'rev-parse', '--verify', '--quiet', rev + '^{commit}')
    return out.decode().strip() if rc == 0 and out.strip() else None


def show(root, rev, rel):
    rc, out = git(root, 'show', f'{rev}:{rel}')
    return out.decode('utf-8', 'replace') if rc == 0 else None


def find(text, quote):
    q = norm(quote)
    for i, l in enumerate(text.splitlines(), 1):
        if q and q in norm(l):
            return i
    return None


def read_anchor(root, rev, a, reader=show):
    for f in a['files']:
        t = reader(root, rev, f)
        if t is None:
            continue
        ln = find(t, a['quote'])
        if ln is not None:
            return {'role': a['role'], 'closure': bool(a.get('closure')), 'present': True, 'file': f, 'line': ln,
                    'anchor': f'{f}:{ln}', 'quote': a['quote']}
    return {'role': a['role'], 'closure': bool(a.get('closure')), 'present': False,
            'anchor': 'absent: quote not found in ' + ', '.join(a['files']), 'quote': a['quote']}


# ── FQ4 structural transcript inventory (names only) ──
GENERATE = ['cryptography/crypto/proof_generate.go', 'crypto/proof_generate.go']


def _func_body(src, header_rx):
    """(body text, first line number) of the first func whose header matches header_rx, or (None, 0)"""
    m = re.search(header_rx, src, re.M)
    if not m:
        return None, 0
    start = m.start()
    depth, j, opened = 0, src.index('{', start), False
    while j < len(src):
        c = src[j]
        if c == '{':
            depth += 1
            opened = True
        elif c == '}':
            depth -= 1
            if opened and depth == 0:
                break
        j += 1
    return src[start:j + 1], src[:start].count('\n') + 1


def _args(s):
    """the balanced argument text of the first call in s (s starts just after the opening parenthesis)"""
    d = 1
    for k, c in enumerate(s):
        if c == '(':
            d += 1
        elif c == ')':
            d -= 1
            if d == 0:
                return s[:k]
    return s


def _challenges(body, first, methods=None, where='verify'):
    """every reducedhash / HashtoNumber call of a func body (and every call of a challenge METHOD of `methods`, whose
    preimage is that method's own), with the expressions appended to `input` since its last reset"""
    out, cur = [], []
    methods = methods or {}
    for n, raw in enumerate(body.splitlines()):
        l = raw.split('//', 1)[0].strip()
        if not l:
            continue
        if re.match(r'var input \[\]byte$', l) or re.match(r'input\s*:?=\s*\[\]byte\{\}', l):
            cur = []
            continue
        m = re.match(r'input = append\(input, (.*)\.\.\.\)$', l)
        if m:
            cur.append(norm(m.group(1)))
            continue
        for cm in re.finditer(r'\b(reducedhash|HashtoNumber)\(', l):
            arg = norm(_args(l[cm.end():]))
            out.append({'where': where, 'line': first + n, 'call': cm.group(1), 'preimage': list(cur) if arg == 'input' else [arg]})
        for mm in re.finditer(r'\bproof\.(\w+)\(', l):
            if mm.group(1) in methods:
                out.append({'where': where, 'line': first + n, 'call': 'proof.' + mm.group(1), 'preimage': methods[mm.group(1)]})
    return out


def challenge_methods(gen_src):
    """{method: preimage} for every Proof method that returns reducedhash(input) (e.g. hashmash1)"""
    out = {}
    if not gen_src:
        return out
    for m in re.finditer(r'^func \(proof \*Proof\) (\w+)\(', gen_src, re.M):
        body, first = _func_body(gen_src[m.start():], r'^func ')
        if body and re.search(r'return reducedhash\(input\)', body):
            ch = _challenges(body, first)
            if ch:
                out[m.group(1)] = ch[-1]['preimage']
    return out


def transcript(src, gen_src=None, ip_src=None):
    """[{where, line, call, preimage: [expr, ...]}] for every challenge of Proof.Verify (with its challenge methods) and
    of InnerProduct.Verify; None when Proof.Verify is not found."""
    body, first = _func_body(src, r'^func \(proof \*Proof\) Verify\(')
    if body is None:
        return None
    out = _challenges(body, first, challenge_methods(gen_src), 'proof')
    if ip_src:
        ib, ifirst = _func_body(ip_src, r'^func \(ip \*InnerProduct\) Verify\(')
        if ib:
            out += _challenges(ib, ifirst, None, 'innerproduct')
    return out


def transcript_summary(tr):
    if tr is None:
        return {'found': False, 'reason': 'missing: func (proof *Proof) Verify not found'}
    blob = json.dumps([[c['where'], c['call'], c['preimage']] for c in tr], separators=(',', ':')).encode()
    names = sorted({m for c in tr for e in c['preimage'] for m in re.findall(r'\b(?:proof|ip)\.(\w+)', e)})
    return {'found': True, 'challenges': len(tr), 'preimage_sha256': hashlib.sha256(blob).hexdigest(),
            'fields_named_in_preimages': names, 'mu_in_a_preimage': 'mu' in names,
            'challenges_by_func': {w: sum(c['where'] == w for c in tr) for w in ('proof', 'innerproduct')}}


# ── FQ3 code side: which wallet code derives payload randomness from (roothash, ring list) only ──
WALLET = 'walletapi/transaction_build.go'
WALLET_R = 'r := crypto.ReducedHash(rencrypted.EncodeCompressed())'
WALLET_FIX = 'func pick_ring_order('


def tags(root):
    rc, out = git(root, 'for-each-ref', '--sort=creatordate', '--format=%(refname:short)', 'refs/tags')
    return out.decode().split() if rc == 0 else []


def wallet_r(root=ROOT, reader=show, tag_list=None):
    """per tag: does the wallet derive r deterministically (the R22 C3 precondition), and is the local fix present"""
    rows = []
    for t in (tag_list if tag_list is not None else tags(root)):
        src = reader(root, t, WALLET)
        rows.append({'tag': t, 'deterministic_r_line': find(src, WALLET_R) if src else None,
                     'pick_ring_order': bool(src and find(src, WALLET_FIX))})
    head = reader(root, 'HEAD', WALLET) or ''
    with_r = [r['tag'] for r in rows if r['deterministic_r_line']]
    return {'file': WALLET, 'quote': WALLET_R, 'tags_total': len(rows), 'tags_with_deterministic_r': len(with_r),
            'tags_with_pick_ring_order': sum(r['pick_ring_order'] for r in rows),
            'earliest_tag': rows[0]['tag'] if rows else 'pending', 'newest_tag': rows[-1]['tag'] if rows else 'pending',
            'head_deterministic_r_line': find(head, WALLET_R) or 'absent',
            'head_pick_ring_order_line': find(head, WALLET_FIX) or 'absent',
            'reading': ('every tag derives r from (roothash, ring public keys in order, sender key); no upstream tag carries a '
                        'ring-order fix, so no wallet-version boundary exists upstream; the head fix is local (R22)')
            if rows and len(with_r) == len(rows) and not any(r['pick_ring_order'] for r in rows) else 'see rows',
            'rows_sha256': hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()}


def presence(root=ROOT, revs=None, reader=show):
    root = Path(root)
    revs = revs or DEFAULT_REVS
    out = {'schema': 'r26 presence v1 (rft §0.8.9 rule 12, FQ4)', 'revs': [], 'classes': {}}
    for rev in revs:
        c = rev_commit(root, rev) if reader is show else rev
        out['revs'].append({'rev': rev, 'commit': c or 'missing: not a commit in this repository', 'role': REV_ROLE.get(rev, 'given')})
    for cls, anchors in ANCHORS.items():
        rows = {}
        for rv in out['revs']:
            rev = rv['rev']
            if not rv['commit'] or rv['commit'].startswith('missing'):
                rows[rev] = {'admits': 'pending: revision not available', 'anchors': []}
                continue
            got = [read_anchor(root, rev, a, reader) for a in anchors]
            core = [g for g in got if not g['closure']]
            clos = [g for g in got if g['closure']]
            admits = all(g['present'] for g in core)
            rows[rev] = {'admits': admits, 'anchors': got,
                         'closures_present': sum(g['present'] for g in clos), 'closures_total': len(clos)}
        out['classes'][cls] = rows
    # FQ4: the transcript inventory per rev
    fq4 = {}
    for rv in out['revs']:
        rev = rv['rev']
        src = None
        for k, f in enumerate(VERIFY):
            src = reader(root, rev, f)
            if src is not None:
                tr = transcript(src, reader(root, rev, GENERATE[k]), reader(root, rev, IPROOF[k]))
                fq4[rev] = dict(transcript_summary(tr), file=f)
                break
        if src is None:
            fq4[rev] = {'found': False, 'reason': 'missing: no proof_verify.go at this revision'}
    out['fq4_transcript'] = fq4
    if reader is show:
        out['fq3_wallet'] = wallet_r(root, reader)
    head = out['classes']['DC2'].get(revs[0], {})
    out['headline'] = {
        'dc2_present_now': head.get('admits') is True,
        'text': ('DC2 (proof soundness) is present in the current consensus code at the round head: its three C1 '
                 'anchors re-read OK; any aggregate over genesis .. now is unbounded') if head.get('admits') is True else
                ('pending: the DC2 anchors did not all re-read at the round head'),
    }
    return out


def check(path, root=ROOT):
    """re-read every anchor now; [differences]"""
    old = json.loads(Path(path).read_text())
    new = presence(root, [r['rev'] for r in old['revs']])
    diffs = []
    for cls, rows in old['classes'].items():
        for rev, r in rows.items():
            n = new['classes'].get(cls, {}).get(rev)
            if n is None or n.get('admits') != r.get('admits') or [a.get('anchor') for a in n['anchors']] != [a.get('anchor') for a in r['anchors']]:
                diffs.append(f'{cls} @ {rev}: recorded {r.get("admits")} {[a.get("anchor") for a in r["anchors"]]} now {n and n.get("admits")} {n and [a.get("anchor") for a in n["anchors"]]}')
    for rev, t in old.get('fq4_transcript', {}).items():
        if new['fq4_transcript'].get(rev, {}).get('preimage_sha256') != t.get('preimage_sha256'):
            diffs.append(f'FQ4 transcript @ {rev} changed')
    return diffs


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--root', default=str(ROOT))
    ap.add_argument('--revs', default=','.join(DEFAULT_REVS))
    ap.add_argument('--write')
    ap.add_argument('--check')
    a = ap.parse_args(argv)
    if a.check:
        d = check(a.check, a.root)
        print('presence: ' + ('UNCHANGED' if not d else 'CHANGED\n  ' + '\n  '.join(d)))
        return 9 if d else 0
    out = presence(a.root, [r for r in a.revs.split(',') if r])
    txt = json.dumps(out, indent=1, sort_keys=True) + '\n'
    if a.write:
        Path(a.write).parent.mkdir(parents=True, exist_ok=True)
        Path(a.write).write_text(txt)
    for cls, rows in out['classes'].items():
        print(cls, ' '.join(f'{rev}={r["admits"]}' for rev, r in rows.items()))
    print('FQ4', {rev: (t.get('challenges'), t.get('mu_in_a_preimage'), (t.get('preimage_sha256') or '')[:12]) for rev, t in out['fq4_transcript'].items()})
    return 0


if __name__ == '__main__':
    sys.exit(main())
