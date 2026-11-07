#!/usr/bin/env python3
"""Known-answer tests + mutation proofs (R28 dvm-blockchain): the DVM's deterministic RANDOM() stream
(dvm/deterministic_random_number.go Initialize_RND / Random / Random_MAX) reproduced by an independent pure-Python
implementation that shares no code with Go: Keccak-256 from harness/forensics/keccak.py and HSalsa20 written here
from the Salsa20 specification. The vectors live in dvm/testdata/r28_rnd_vectors.json; the Go side is
dvm/r28_dvm_kat_test.go TestR28RNDCrossImpl, which runs the Go generator over the same file.

The Go generator: key = Keccak256(SCID || BLID || TXID); value at position p (from 1) =
BigEndian.Uint64(HSalsa20(in = BE64(p) || 8 zero bytes, key, constant = in)[0:8]). The constant is the input block
itself, not the Salsa20 sigma: a quirk, consensus-visible (an SC's RANDOM() output), pinned as is.

  RN1 HSalsa20 here reproduces the published NaCl vector (firstkey -> secondkey, sigma constant)
  RN2 every vector's values and Random_MAX results equal this implementation's
  RN3 the vector set covers zero seeds, distinct SCID/BLID/TXID, max 1 and a max above 2^63
  mutations (on this implementation, never on the tree): sigma constant, position from 0, seed order
      TXID||BLID||SCID, little-endian output word, SHA3 instead of legacy Keccak: each must change a vector (CAUGHT)

  python3 -I harness/kat/test_dvm_rnd_crossimpl_r28.py [--write]   # --write regenerates the vector file
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught.
"""
import importlib.util, json, struct, sys
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
VEC = ROOT / 'dvm' / 'testdata' / 'r28_rnd_vectors.json'
SIGMA = b'expand 32-byte k'
M32 = 0xffffffff


def keccak_mod():
    spec = importlib.util.spec_from_file_location('keccak_rn', HARNESS / 'forensics' / 'keccak.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _rotl(v, n):
    return ((v << n) | (v >> (32 - n))) & M32


def hsalsa20(inp, key, const):
    """HSalsa20 per the Salsa20 spec / NaCl crypto_core_hsalsa20: 20 rounds, no feed-forward, words 0,5,10,15,6..9."""
    c = struct.unpack('<4I', const)
    k = struct.unpack('<8I', key)
    i = struct.unpack('<4I', inp)
    x = [c[0], k[0], k[1], k[2], k[3], c[1], i[0], i[1], i[2], i[3], c[2], k[4], k[5], k[6], k[7], c[3]]

    def qr(a, b, cc, d):
        x[b] ^= _rotl((x[a] + x[d]) & M32, 7)
        x[cc] ^= _rotl((x[b] + x[a]) & M32, 9)
        x[d] ^= _rotl((x[cc] + x[b]) & M32, 13)
        x[a] ^= _rotl((x[d] + x[cc]) & M32, 18)
    for _ in range(10):
        qr(0, 4, 8, 12); qr(5, 9, 13, 1); qr(10, 14, 2, 6); qr(15, 3, 7, 11)
        qr(0, 1, 2, 3); qr(5, 6, 7, 4); qr(10, 11, 8, 9); qr(15, 12, 13, 14)
    return struct.pack('<8I', x[0], x[5], x[10], x[15], x[6], x[7], x[8], x[9])


IMPL = {'const': 'in', 'pos0': 1, 'order': 'scid,blid,txid', 'out': 'be', 'hash': 'keccak'}


def stream(scid, blid, txid, n, impl=IMPL, K=None):
    K = K or keccak_mod()
    parts = {'scid': scid, 'blid': blid, 'txid': txid}
    seed = b''.join(parts[p] for p in impl['order'].split(','))
    key = (K.keccak256 if impl['hash'] == 'keccak' else K.sha3_256)(seed)
    out, pos = [], impl['pos0']
    for _ in range(n):
        inp = struct.pack('>Q', pos) + bytes(8)
        o = hsalsa20(inp, key, inp if impl['const'] == 'in' else SIGMA)
        out.append(struct.unpack('>Q' if impl['out'] == 'be' else '<Q', o[:8])[0])
        pos += 1
    return out


def h(byte0, fill=0):
    return bytes([byte0]) + bytes([fill]) * 31


SEEDS = [(bytes(32), bytes(32), bytes(32)), (h(1), h(2), h(3)), (h(3), h(2), h(1)), (h(0xaa, 0x11), h(0x55, 0x22), h(0x0f, 0xf0))]
MAXES = [1, 2, 10, 1000, 2 ** 32 + 15, 2 ** 63 + 5]


def build(impl=IMPL, K=None):
    K = K or keccak_mod()
    cases = []
    for s, b, t in SEEDS:
        vals = stream(s, b, t, 4, impl, K)
        # Random_MAX(n) consumes the next value: position 5 onward, one per max
        nxt = stream(s, b, t, 4 + len(MAXES), impl, K)[4:]
        cases.append({'scid': s.hex(), 'blid': b.hex(), 'txid': t.hex(), 'values': [str(v) for v in vals],
                      'max': [{'n': str(m), 'want': str(v % m)} for m, v in zip(MAXES, nxt)]})
    return {'_doc': 'R28 DVM RANDOM() cross-implementation vectors: values = the first 4 Random() of '
                    'Initialize_RND(scid, blid, txid); max = Random_MAX(n) called after them, in order. Built by '
                    'harness/kat/test_dvm_rnd_crossimpl_r28.py (pure Python), checked against the Go generator by '
                    'dvm/r28_dvm_kat_test.go TestR28RNDCrossImpl.', 'cases': cases}


def main():
    K = keccak_mod()
    if '--write' in sys.argv[1:]:
        VEC.parent.mkdir(parents=True, exist_ok=True)
        VEC.write_text(json.dumps(build(K=K), indent=1) + '\n')
        print(f'wrote {VEC.relative_to(ROOT)}')
    fails = []
    # RN1: NaCl crypto_core_hsalsa20 vector (tests/core1: firstkey -> secondkey, zero input, sigma)
    firstkey = bytes.fromhex('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')
    secondkey = '1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389'
    if hsalsa20(bytes(16), firstkey, SIGMA).hex() != secondkey:
        fails.append('RN1 HSalsa20 does not reproduce the NaCl vector')
    vec = json.loads(VEC.read_text())
    want = build(K=K)
    if vec['cases'] != want['cases']:
        fails.append('RN2 the vector file differs from this implementation')
    maxes = {int(m['n']) for c in vec['cases'] for m in c['max']}
    zero_seed = any(c['scid'] == c['blid'] == c['txid'] == '00' * 32 for c in vec['cases'])
    if not (zero_seed and 1 in maxes and max(maxes) > 2 ** 63 and len({c['scid'] for c in vec['cases']}) >= 3):
        fails.append('RN3 coverage: zero seed, max 1, max > 2^63, 3+ distinct SCIDs')
    for f in fails:
        print('FAIL', f)
    print(f'KATs: RN1 RN2 RN3 {"ok" if not fails else "FAILED"} ({len(vec["cases"])} seeds)')
    if fails:
        return 3
    missed = []
    for name, ch in [('sigma constant', {'const': 'sigma'}), ('position from 0', {'pos0': 0}),
                     ('seed order txid,blid,scid', {'order': 'txid,blid,scid'}), ('little-endian word', {'out': 'le'}),
                     ('sha3 not keccak', {'hash': 'sha3'})]:
        impl = dict(IMPL, **ch)
        caught = build(impl, K)['cases'] != vec['cases']
        print(f'  {"CAUGHT" if caught else "MISSED"}  {name}')
        if not caught:
            missed.append(name)
    print(f'mutations: {5 - len(missed)}/5 caught')
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
