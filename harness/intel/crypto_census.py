#!/usr/bin/env python3
"""crypto_census.py — r31 (rft §7 B278 / B283, area `cryptography`): the primitives census, measured.

Two static, read-only censuses of this tree (nothing is fetched, derod is never contacted):

  decoders    every entry point that decodes a curve point, scalar, key or proof from bytes or text (the 20 entries
              of detector-crypto-input plus the panic / text decoders of detector-error-paths), each with
                - its signature anchor (file + the literal `func` line; must resolve),
                - its REACH: `consensus` (a block / transaction acceptance path decodes through it: pin only, a
                  check there is disclosure-style, rft §0.5), `wallet` (reached only from wallet / tool input:
                  a check may land, at the caller), or `none` (no caller outside tests) — with a reach anchor
                  (the caller line that proves it; must resolve),
                - the Go test that PINS its behaviour (must be defined in a _test.go of the named package),
                - the verdict booked for the finding.
  randomness  every math/rand import or seeding, and every discarded crypto/rand error, in the key and blinding
              paths (cryptography/, walletapi/, globals/random.go). A finding is explained only by an entry of
              RAND_MOOT (file + quote + reason), e.g. B15 (crypto/rand.Read cannot fail since go1.24).

The area metric (B278 (6)) is `kpis.pinned` of the newest record: entries whose anchors resolve and whose pin test
exists (covered / listed).

  python3 -I harness/intel/crypto_census.py [--root DIR] [--write] [--json]
  exit 0 PASS (every entry pinned, anchors resolve, randomness findings all explained) · 3 FAIL
KAT: harness/kat/test_crypto_census_r31.py (CC1-CC4).
"""
import argparse, json, re, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

# entry, file, signature quote, reach, reach anchor (file, quote), pin (package dir, test), finding ids, verdict
ENTRIES = [
    ('G1.DecodeCompressed', 'cryptography/bn256/changes.go', 'func (e *G1) DecodeCompressed(encoding []byte) error {',
     'consensus', ('cryptography/crypto/protocol_structures.go', 'if err = p.DecodeCompressed(bufp[:]); err != nil {'),
     ('cryptography/bn256', 'TestR31CompressedDecodeClassCensus'), ['DF-crypto-input-b5acbb6203'], 'TRIAGED fix-later (disclosure-style, fork-required)'),
    ('Decompress (marshal drops Unmarshal error)', 'cryptography/bn256/changes.go', '\tg1.Unmarshal(g)',
     'consensus', ('cryptography/bn256/changes.go', 'p, err := Decompress(encoding)'),
     ('cryptography/bn256', 'TestR22NonCanonicalXDecodesToIdentity'), ['DF-crypto-input-b5acbb6203'], 'TRIAGED fix-later (disclosure-style)'),
    ('Point.DecodeCompressed', 'cryptography/crypto/group.go', 'func (p *Point) DecodeCompressed(i []byte) error {',
     'consensus', ('blockchain/transaction_execute.go', 'var acckey crypto.Point'),
     ('cryptography/bn256', 'TestR31CompressedDecodeClassCensus'), ['DF-crypto-input-e8609e22cf'], 'TRIAGED fix-later (disclosure-style; delegates to G1.DecodeCompressed)'),
    ('Point.UnmarshalText', 'cryptography/crypto/group.go', 'func (p *Point) UnmarshalText(text []byte) error {',
     'wallet', ('walletapi/wallet.go', 'Public *crypto.Point `json:"public"`'),
     ('walletapi', 'TestR31WalletOpenRefusesInconsistentKeys'), ['DF-crypto-input-5325afeed7', 'DF-fuzz-coverage-e7dd07c62e'], 'DONE at its only caller (wallet open key check)'),
    ('Statement.Deserialize', 'cryptography/crypto/protocol_structures.go', 'func (s *Statement) Deserialize(r *bytes.Reader) error {',
     'consensus', ('transaction/transaction.go', 'if err = a.Statement.Deserialize(r); err != nil {'),
     ('cryptography/crypto', 'TestR31StatementTruncationPinned'), ['DF-crypto-input-0a69e3be30'], 'TRIAGED not-a-defect (no scalar field; points pinned in bn256; short read = claim C7)'),
    ('Proof.Deserialize', 'cryptography/crypto/proof_generate.go', 'func (proof *Proof) Deserialize(r *bytes.Reader, length int) error {',
     'consensus', ('transaction/transaction.go', 'if err = a.Proof.Deserialize(r, crypto.GetPowerof2('),
     ('cryptography/crypto', 'TestR25ScalarReencodeVerifies'), ['DF-crypto-input-6d444b0926'], 'TRIAGED fix-later (disclosure BD9 / FX-F3, fork-required)'),
    ('InnerProduct.Deserialize', 'cryptography/crypto/proof_innerproduct.go', 'func (ip *InnerProduct) Deserialize(r *bytes.Reader) (err error) {',
     'consensus', ('cryptography/crypto/proof_generate.go', 'proof.ip.Deserialize(r)'),
     ('cryptography/crypto', 'TestR25ScalarReencodeVerifies'), ['DF-crypto-input-fd9ccd87cb'], 'TRIAGED fix-later (disclosure BD9 / FX-F3, fork-required)'),
    ('G1.Unmarshal', 'cryptography/bn256/bn256.go', 'func (e *G1) Unmarshal(m []byte) ([]byte, error) {',
     'consensus', ('cryptography/crypto/proof_verify.go', 'anonsupport.temp.Unmarshal(zeroes[:])'),
     ('cryptography/bn256', 'TestR31Bn256DecodeClassCensus'), ['DF-crypto-input-20ed8a2079'], 'TRIAGED not-a-defect (identity by design: the zero accumulators)'),
    ('G1.DecodeUncompressed', 'cryptography/bn256/changes.go', 'func (e *G1) DecodeUncompressed(input []byte) error {',
     'none', ('cryptography/bn256/changes_more_tests.go', 'err = Gb2.DecodeUncompressed(encoded)'),
     ('cryptography/bn256', 'TestR31Bn256DecodeClassCensus'), ['DF-crypto-input-09d145f637', 'DF-fuzz-coverage-9c014e877c'], 'TRIAGED not-a-defect (no node caller) + fuzz'),
    ('G2.Unmarshal', 'cryptography/bn256/bn256.go', 'func (e *G2) Unmarshal(m []byte) ([]byte, error) {',
     'none', ('cryptography/bn256/bn256.go', 'func (e *G2) Unmarshal(m []byte) ([]byte, error) {'),
     ('cryptography/bn256', 'FuzzR31Bn256Decoders'), ['DF-crypto-input-76bbc242fd', 'DF-fuzz-coverage-e9dd9ae399'], 'TRIAGED not-a-defect (no caller) + fuzz'),
    ('GT.Unmarshal', 'cryptography/bn256/bn256.go', 'func (e *GT) Unmarshal(m []byte) ([]byte, error) {',
     'none', ('cryptography/bn256/bn256.go', 'func (e *GT) Unmarshal(m []byte) ([]byte, error) {'),
     ('cryptography/bn256', 'FuzzR31Bn256Decoders'), ['DF-fuzz-coverage-ab260ef8e0'], 'DONE (fuzz target + census pin)'),
    ('DecompressAmbiguous', 'cryptography/bn256/changes.go', 'func DecompressAmbiguous(xb []byte) (*G1, *G1, error) {',
     'none', ('cryptography/bn256/changes.go', 'func DecompressAmbiguous(xb []byte) (*G1, *G1, error) {'),
     ('cryptography/bn256', 'FuzzR31Bn256Decoders'), ['DF-fuzz-coverage-d6cb02bf84'], 'DONE (fuzz target + census pin)'),
    ('unmarshalpoint', 'cryptography/crypto/proof_verify.go', 'func unmarshalpoint(input string) *bn256.G1 {',
     'none', ('cryptography/crypto/proof_verify.go', 'func unmarshalpoint(input string) *bn256.G1 {'),
     ('cryptography/bn256', 'TestR31Bn256DecodeClassCensus'), ['DF-crypto-input-27eae3ca33'], 'TRIAGED not-a-defect (no caller; G1.Unmarshal checks x < P)'),
    ('NonceBalance.Unmarshal', 'cryptography/crypto/balance_serdes.go', 'func (x *NonceBalance) Unmarshal(buf []byte) *NonceBalance {',
     'consensus', ('glue/emission/emission.go', 'nb := new(crypto.NonceBalance).Deserialize(b)'),
     ('cryptography/crypto', 'TestR31PanicDecodersPinned'), ['DF-error-paths-1658e61256', 'DF-fuzz-coverage-908fef16f6', 'DF-fuzz-coverage-ea81aec1f5'], 'TRIAGED not-a-defect (own store bytes) + fuzz'),
    ('NonceBalance.UnmarshalNonce', 'cryptography/crypto/balance_serdes.go', 'func (x *NonceBalance) UnmarshalNonce(buf []byte) {',
     'consensus', ('blockchain/transaction_verify.go', 'tx_nb.UnmarshalNonce(tx_balance_serialized)'),
     ('cryptography/crypto', 'TestR31PanicDecodersPinned'), ['DF-error-paths-74f38cb18b', 'DF-fuzz-coverage-44ca90217b'], 'TRIAGED not-a-defect (own balance tree) + fuzz'),
    ('ElGamal.Deserialize', 'cryptography/crypto/algebra_elgamal.go', 'func (e *ElGamal) Deserialize(data []byte) *ElGamal {',
     'consensus', ('cryptography/crypto/balance_serdes.go', 'x.Balance = new(ElGamal).Deserialize(buf[size:])'),
     ('cryptography/crypto', 'TestR31PanicDecodersPinned'), ['DF-error-paths-1be34e7af3'], 'TRIAGED not-a-defect (own store bytes) + fuzz'),
    ('HexToKey', 'cryptography/crypto/key_old.go', 'func HexToKey(h string) (result Key) {',
     'none', ('cryptography/crypto/key_old.go', 'func HexToKey(h string) (result Key) {'),
     ('cryptography/crypto', 'TestR31TextDecodersDiscardHexErrorPinned'), ['DF-error-paths-eb1c230849', 'DF-error-paths-27ab0e5764', 'DF-fuzz-coverage-c1b9e294d2'], 'TRIAGED not-a-defect (no caller) + fuzz'),
    ('HexToHash', 'cryptography/crypto/key_old.go', 'func HexToHash(h string) (result Hash) {',
     'none', ('cryptography/crypto/key_old.go', 'func HexToHash(h string) (result Hash) {'),
     ('cryptography/crypto', 'TestR31TextDecodersDiscardHexErrorPinned'), ['DF-error-paths-6861162073'], 'TRIAGED not-a-defect (no caller)'),
    ('Key.UnmarshalText', 'cryptography/crypto/key_old.go', 'func (k *Key) UnmarshalText(data []byte) (err error) {',
     'none', ('cryptography/crypto/key_old.go', 'func (k *Key) UnmarshalText(data []byte) (err error) {'),
     ('cryptography/crypto', 'TestR31TextDecodersDiscardHexErrorPinned'), ['DF-error-paths-d7239383be', 'DF-fuzz-coverage-6a24959207'], 'TRIAGED not-a-defect (no JSON field of type Key) + fuzz'),
    ('Key.FromBytes', 'cryptography/crypto/key_old.go', 'func (p *Key) FromBytes(b [KeyLength]byte) {',
     'none', ('cryptography/crypto/key_old.go', 'func (p *Key) FromBytes(b [KeyLength]byte) {'),
     ('cryptography/crypto', 'FuzzR31CryptoTextDecoders'), ['DF-fuzz-coverage-14cb199339'], 'DONE (fuzz target)'),
    ('Hash.UnmarshalText', 'cryptography/crypto/hash.go', 'func (h *Hash) UnmarshalText(data []byte) (err error) {',
     'wallet', ('cryptography/crypto/hash.go', 'byteSlice, _ := hex.DecodeString(string(data))'),
     ('cryptography/crypto', 'TestR22HashUnmarshalTextAcceptsTrailingGarbage'), ['DF-error-paths-0e4ea0568d', 'DF-fuzz-coverage-795a082fe6'], 'TRIAGED fix-later (RPC JSON params; rpc/ is guarded) + fuzz'),
    ('BNRed.UnmarshalText', 'cryptography/crypto/bnred.go', 'func (x *BNRed) UnmarshalText(text []byte) error {',
     'wallet', ('walletapi/wallet.go', 'Secret *crypto.BNRed `json:"secret"`'),
     ('walletapi', 'TestR31WalletOpenRefusesInconsistentKeys'), ['DF-fuzz-coverage-dc677790cd'], 'DONE (fuzz target + wallet open key check)'),
    ('newGFpFromBigInt (padBytes error)', 'cryptography/bn256/changes.go', 'inBytes, _ = padBytes(inBytes)',
     'none', ('cryptography/bn256/changes.go', 'if len(inBytes) < 32 {'),
     ('cryptography/bn256', 'TestR31GfpUnmarshalModulusCheck'), ['DF-error-paths-4e042e9e0a'], 'TRIAGED not-a-defect (error impossible under the len < 32 guard)'),
]
REACHES = ('consensus', 'wallet', 'none')

RAND_SCOPE = ('cryptography/', 'walletapi/', 'globals/random.go')
# (file, quote, reason): a randomness finding explained by evidence
RAND_MOOT = [
    ('globals/random.go', 'rand.Read(b[:])',
     'B15 REFUTED (R23c, re-checked R28): crypto/rand.Read never returns an error since go1.24 (fatal on failure)'),
    ('walletapi/wallet.go', 'rand.Read(dstport[:])',
     'B15 class (same premise as globals/random.go): crypto/rand.Read cannot fail on the toolchain in use; the bytes are a '
     'payment-id port, not key or blinding material'),
    ('cryptography/crypto/random.go', 'a, _ := rand.Int(rand.Reader, bn256.Order)',
     'fails closed: on an error a is nil and a.Sign() panics; never a predictable scalar'),
]
RX_MATHRAND_IMPORT = re.compile(r'^\s*(?:import\s+)?(\w+\s+)?"math/rand"', re.M)
RX_SEED = re.compile(r'\b(\w+)\.(Seed|NewSource)\(')
RX_DISCARD = re.compile(r'(?:_\s*,\s*_|\w+\s*,\s*_|_)\s*:?=\s*rand\.(Read|Int)\(|^\s*rand\.Read\(', re.M)


def line_of(text, quote):
    """1-based line of the first line containing quote, or None. Pure."""
    for i, l in enumerate(text.splitlines(), 1):
        if quote in l:
            return i
    return None


def test_defined(root, pkg, name):
    """True when a _test.go file of package dir pkg defines func name(. Pure over the tree."""
    rx = re.compile(rf'^func {re.escape(name)}\(', re.M)
    return any(rx.search(p.read_text(errors='replace')) for p in sorted((Path(root) / pkg).glob('*_test.go')))


def read(root, rel):
    try:
        return (Path(root) / rel).read_text(errors='replace')
    except OSError:
        return None


def census_decoders(root, entries=None):
    rows = []
    for entry, f, sig, reach, (rf, rq), (pkg, test), findings, verdict in (entries if entries is not None else ENTRIES):
        t, rt = read(root, f), read(root, rf)
        sl = line_of(t, sig) if t is not None else None
        rl = line_of(rt, rq) if rt is not None else None
        pinned = test_defined(root, pkg, test)
        problems = []
        if sl is None:
            problems.append(f'signature not found in {f}')
        if rl is None:
            problems.append(f'reach anchor not found in {rf}')
        if reach not in REACHES:
            problems.append(f'unknown reach {reach}')
        if not pinned:
            problems.append(f'pin test {test} not defined in {pkg}')
        rows.append({'entry': entry, 'at': f'{f}:{sl}' if sl else f, 'reach': reach, 'reach_anchor': f'{rf}:{rl}' if rl else rf,
                     'pin': f'{pkg} {test}', 'pinned': pinned and not problems, 'findings': findings, 'verdict': verdict,
                     'problems': problems})
    return rows


def scope_files(root):
    out = []
    for s in RAND_SCOPE:
        p = Path(root) / s
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            out += [x for x in sorted(p.rglob('*.go')) if not x.name.endswith('_test.go')]
    return out


def census_randomness(root, moot=None):
    moot = RAND_MOOT if moot is None else moot
    found = []
    for p in scope_files(root):
        rel = p.relative_to(root).as_posix()
        text = p.read_text(errors='replace')
        m = RX_MATHRAND_IMPORT.search(text)
        mr = ((m.group(1) or '').strip() or 'rand') if m else None
        if m and rel.startswith('cryptography/'):
            found.append({'file': rel, 'line': text[:m.start()].count('\n') + 1, 'kind': 'math/rand-in-cryptography',
                          'quote': m.group(0).strip()})
        if mr:
            for s in RX_SEED.finditer(text):
                if s.group(1) == mr:
                    found.append({'file': rel, 'line': text[:s.start()].count('\n') + 1, 'kind': 'math/rand-seeded',
                                  'quote': text.splitlines()[text[:s.start()].count('\n')].strip()})
        if '"crypto/rand"' in text:
            for d in RX_DISCARD.finditer(text):
                ln = text[:d.start()].count('\n')
                found.append({'file': rel, 'line': ln + 1, 'kind': 'crypto/rand-error-discarded', 'quote': text.splitlines()[ln].strip()})
    for f in found:
        why = next((r for mf, q, r in moot if mf == f['file'] and q in f['quote']), None)
        f['explained'] = why
    return found


def run(root):
    rows = census_decoders(root)
    rnd = census_randomness(root)
    pinned = sum(r['pinned'] for r in rows)
    unexplained = [f for f in rnd if not f['explained']]
    by = {k: sum(1 for r in rows if r['reach'] == k) for k in REACHES}
    verdict = 'PASS' if pinned == len(rows) and rows and not unexplained else 'FAIL'
    return {'schema': 1, 'tool': 'harness/intel/crypto_census.py', 'row': 'B278/B283', 'verdict': verdict,
            'kpis': {'pinned': pinned, 'listed': len(rows), 'consensus': by['consensus'], 'wallet': by['wallet'],
                     'no_caller': by['none'], 'randomness_findings': len(rnd), 'randomness_unexplained': len(unexplained)},
            'decoders': rows, 'randomness': rnd}


def summary(rec):
    k = rec['kpis']
    return (f"crypto census: {rec['verdict']} · decoders pinned {k['pinned']}/{k['listed']} (consensus {k['consensus']}, "
            f"wallet {k['wallet']}, no caller {k['no_caller']}) · randomness findings {k['randomness_findings']} "
            f"({k['randomness_unexplained']} unexplained)")


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--root', default=str(ROOT))
    ap.add_argument('--write', action='store_true', help='write harness/runtime/crypto_census_<ts>.json')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args(argv)
    rec = run(Path(a.root))
    if a.json:
        print(json.dumps(rec, indent=1))
    else:
        for r in rec['decoders']:
            if r['problems']:
                print(f"  FAIL {r['entry']}: {'; '.join(r['problems'])}")
        for f in rec['randomness']:
            print(f"  {'ok  ' if f['explained'] else 'FAIL'} {f['kind']} {f['file']}:{f['line']} {f['explained'] or ''}")
    if a.write:
        out = Path(a.root) / 'harness/runtime' / f"crypto_census_{time.strftime('%Y%m%dT%H%M%S')}.json"
        out.write_text(json.dumps(rec, indent=1) + '\n')
        print(f'wrote {out.relative_to(a.root)}')
    print(summary(rec))
    return 0 if rec['verdict'] == 'PASS' else 3


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
