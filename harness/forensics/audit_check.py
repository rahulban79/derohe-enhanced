#!/usr/bin/env python3
"""Independent audit of a forensic dataset (rft §0.8.5, §8 forensics-audit, B78/B82; gate G29; KAT MF3, MF4).

A SECOND implementation. It shares no code with the builder's tools: it does not import extract.py, derive.py,
keccak.py, provenance.py or the Go helper, and it does not read the builder's decoded outputs as inputs. It has its
own Keccak-f[1600] (round constants and rotation offsets generated from the FIPS 202 definitions, not copied tables),
its own decoders of the block and transaction wire formats (block/block.go, block/miniblock.go,
transaction/transaction.go, cryptography/crypto/protocol_structures.go, cryptography/crypto/proof_generate.go at the
pinned commit), its own parser of the HF3 table and of the emission constants (read from the source text), and its
own tips walk. Every check runs from the bytes in raw/ (and the tier B store). The builder's derived/ files are read
only at the END, as CLAIMS to compare against.

  python3 -I harness/forensics/audit_check.py run forensics/r25 --store DIR [--archive DIR] [--live DIR]
          [--private DIR] [--jobs N] --out DIR        # writes audit_rerun.json (deterministic: no time, no path)
  python3 -I harness/forensics/audit_check.py g29 [REPO]   # gate G29 over forensics/<newest>/audit/
  python3 -I harness/forensics/audit_check.py selftest      # Keccak/SHA3 KATs + decoder KATs

Evidence classes (rft §0.8.2) are carried on every verdict input: RAW, DERIVED, SRC, EXT, INTERPRETATION.
Exploit content: none. Proof results are pass/fail plus the check name, never how a proof is built (§0.8.1 rule 6).
"""
import gzip, hashlib, json, os, re, subprocess, sys
from pathlib import Path

IMPL_VERSION = 'audit-check-1'
ROOT = Path(__file__).resolve().parent.parent.parent

# =============================================================================================== Keccak (own)
_MASK = (1 << 64) - 1


def _gen_rc():
    """Round constants from the LFSR rc(t) of FIPS 202 §3.2.5 (x^8 + x^6 + x^5 + x^4 + 1)."""
    def rc_bit(t):
        if t % 255 == 0:
            return 1
        R = [1, 0, 0, 0, 0, 0, 0, 0]                  # R[0..7], R = 10000000
        for _ in range(t % 255):
            R = [0] + R                               # R = 0 || R
            R[0] ^= R[8]; R[4] ^= R[8]; R[5] ^= R[8]; R[6] ^= R[8]
            R = R[:8]                                 # Trunc8
        return R[0]
    out = []
    for ir in range(24):
        c = 0
        for j in range(7):
            if rc_bit(j + 7 * ir):
                c |= 1 << ((1 << j) - 1)
        out.append(c)
    return out


def _gen_rho_pi():
    """(source lane, destination lane, rotation) for rho followed by pi (FIPS 202 §3.2.2-3.2.3)."""
    rot = {(0, 0): 0}
    x, y = 1, 0
    for t in range(24):
        rot[(x, y)] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    steps = []
    for x in range(5):
        for y in range(5):
            # pi: A'[x, y] = A[(x + 3y) mod 5, x]  <=>  A[x, y] goes to A'[y, (2x + 3y) mod 5]
            steps.append((x + 5 * y, y + 5 * ((2 * x + 3 * y) % 5), rot[(x, y)]))
    return steps


RC = _gen_rc()
RHO_PI = _gen_rho_pi()


def _f1600(A):
    B = [0] * 25
    for rc in RC:
        C = [A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20] for x in range(5)]
        for x in range(5):
            c1 = C[(x + 1) % 5]
            d = C[(x - 1) % 5] ^ (((c1 << 1) | (c1 >> 63)) & _MASK)
            for y in range(0, 25, 5):
                A[x + y] ^= d
        for src, dst, r in RHO_PI:
            v = A[src]
            B[dst] = ((v << r) | (v >> (64 - r))) & _MASK if r else v
        for y in range(0, 25, 5):
            b0, b1, b2, b3, b4 = B[y], B[y + 1], B[y + 2], B[y + 3], B[y + 4]
            A[y] = b0 ^ ((~b1) & b2)
            A[y + 1] = b1 ^ ((~b2) & b3)
            A[y + 2] = b2 ^ ((~b3) & b4)
            A[y + 3] = b3 ^ ((~b4) & b0)
            A[y + 4] = b4 ^ ((~b0) & b1)
        A[0] ^= rc
    return A


def _sponge(data, rate, ds, n):
    m = bytearray(data)
    m.append(ds)
    while len(m) % rate:
        m.append(0)
    m[-1] |= 0x80
    A = [0] * 25
    lanes = rate // 8
    for off in range(0, len(m), rate):
        blk = m[off:off + rate]
        for i in range(lanes):
            A[i] ^= int.from_bytes(blk[8 * i:8 * i + 8], 'little')
        _f1600(A)
    out = b''.join(A[i].to_bytes(8, 'little') for i in range(lanes))
    return out[:n]


def sha3_256(b):
    return _sponge(b, 136, 0x06, 32)


def keccak256(b):
    return _sponge(b, 136, 0x01, 32)


KAT = [  # (function, message, digest) — FIPS 202 examples and the published Keccak-256 (pre-standard padding) vectors
    ('sha3', b'', 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'),
    ('sha3', b'abc', '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'),
    ('sha3', b'\xa3' * 200, '79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787'),
    ('keccak', b'', 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'),
    ('keccak', b'abc', '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'),
    ('keccak', b'The quick brown fox jumps over the lazy dog',
     '4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15'),
]


def hash_selftest():
    fails = []
    for kind, msg, want in KAT:
        got = (sha3_256 if kind == 'sha3' else keccak256)(msg).hex()
        if got != want:
            fails.append(f'KAT {kind}({len(msg)} B) {got[:16]} != {want[:16]}')
    for n in (0, 1, 55, 135, 136, 137, 271, 272, 273, 1000):  # rate boundaries vs an unrelated implementation
        msg = bytes((7 * i + 3) & 0xff for i in range(n))
        if sha3_256(msg) != hashlib.sha3_256(msg).digest():
            fails.append(f'sha3 differs from hashlib at length {n}')
    if keccak256(b'x') == sha3_256(b'x'):
        fails.append('keccak256 == sha3_256: the two paddings do not differ')
    return fails


# =============================================================================================== decoders (own)
class DecodeError(Exception):
    pass


def uvarint(b, i):
    """encoding/binary.Uvarint: error on truncation or overflow (more than 10 bytes, or >64 bits)."""
    x, s = 0, 0
    for k in range(10):
        if i + k >= len(b):
            raise DecodeError('truncated uvarint')
        c = b[i + k]
        if c < 0x80:
            if k == 9 and c > 1:
                raise DecodeError('uvarint overflow')
            return x | (c << s), i + k + 1, k + 1
        x |= (c & 0x7f) << s
        s += 7
    raise DecodeError('uvarint overflow')


def take(b, i, n):
    if i + n > len(b):
        raise DecodeError('truncated field')
    return b[i:i + n], i + n


PREMINE, REGISTRATION, COINBASE, NORMAL, BURN_TX, SC_TX = range(6)
TXTYPES = {0: 'PREMINE', 1: 'REGISTRATION', 2: 'COINBASE', 3: 'NORMAL', 4: 'BURN', 5: 'SC'}
PAYLOAD_LIMIT = 1 + 144          # transaction.go:62
MINIBLOCK_SIZE = 48              # miniblock.go:33


def _tx_header(b, i):
    """Transaction prefix + payload statements up to the end of the core statement (transaction.go:304-411)."""
    t = {}
    t['version'], i, _ = uvarint(b, i)
    if t['version'] != 1:
        raise DecodeError('tx version != 1')
    t['source_network'], i, _ = uvarint(b, i)
    t['dest_network'], i, _ = uvarint(b, i)
    typ, i, _ = uvarint(b, i)
    if typ not in TXTYPES:
        raise DecodeError('unknown tx type')
    t['type'] = typ
    t['value'] = 0
    t['value_field_present'] = typ in (PREMINE, SC_TX)
    if typ in (PREMINE, SC_TX):
        t['value'], i, _ = uvarint(b, i)
    if typ in (PREMINE, COINBASE, REGISTRATION):
        a, i = take(b, i, 33)
        t['miner_address_sha256'] = hashlib.sha256(a).hexdigest()  # never the address itself
    if typ == REGISTRATION:
        _, i = take(b, i, 64)
    t['payloads'] = []
    if typ in (BURN_TX, NORMAL, SC_TX):
        t['height'], i, _ = uvarint(b, i)
        blid, i = take(b, i, 32)
        t['blid'] = blid.hex()
        n, i, _ = uvarint(b, i)
        if n < 1:
            raise DecodeError('asset_count < 1')
        for _ in range(n):
            p = {}
            p['burn'], i, _ = uvarint(b, i)
            scid, i = take(b, i, 32)
            p['scid_zero'] = scid == bytes(32)
            p['scid'] = scid.hex()
            rt, i = take(b, i, 1)
            p['rpc_type'] = rt[0]
            _, i = take(b, i, PAYLOAD_LIMIT)
            pw, i = take(b, i, 1)
            ring = 1 << pw[0]
            if ring > 128:
                raise DecodeError('ring size too large')
            p['power'], p['ring'] = pw[0], ring
            bpp, i = take(b, i, 1)
            p['bpp'] = bpp[0]
            p['fees'], i, _ = uvarint(b, i)
            _, i = take(b, i, 33)                       # D
            ptrs, i = take(b, i, ring * bpp[0])
            p['pointers_distinct'] = (len({ptrs[k * bpp[0]:(k + 1) * bpp[0]] for k in range(ring)}) == ring) if bpp[0] else False
            _, i = take(b, i, 33 * ring)                # C
            rh, i = take(b, i, 32)
            p['roothash'] = rh.hex()
            t['payloads'].append(p)
    if typ == SC_TX:
        n, i, _ = uvarint(b, i)
        if n > len(b) - i:
            raise DecodeError('SC len out of range')
        _, i = take(b, i, n)
        t['scdata_len'] = n
    return t, i


def proof_len(power):
    """Proof wire length for ring 2^power (proof_generate.go:84-140): BA BS A B, 8 points per round, u, f (2L),
    z_A, T_1 T_2, that mu, c s_sk s_r s_b s_tau, inner product a b + 7 (L,R) pairs."""
    L = power
    return 4 * 33 + L * 8 * 33 + 33 + 2 * L * 32 + 32 + 2 * 33 + 2 * 32 + 5 * 32 + 2 * 32 + 7 * 2 * 33


def decode_tx(b):
    t, core = _tx_header(b, 0)
    t['core_len'] = core
    i = core
    if t['type'] in (BURN_TX, NORMAL, SC_TX):
        for p in t['payloads']:
            if p['bpp'] == 0 or p['ring'] < 1:
                raise DecodeError('bad statement shape')
            n = proof_len(p['power'])
            pr, i = take(b, i, n)
            f0 = pr[4 * 33 + p['power'] * 8 * 33 + 33: 4 * 33 + p['power'] * 8 * 33 + 33 + 32]
            p['proof_parity'] = f0 == bytes(32)       # Proof.Parity(): f[0] == 0 (proof_generate.go:76-82)
    if i != len(b) and t['type'] not in (PREMINE, COINBASE):
        raise DecodeError('extra bytes after tx')
    t['txid'] = keccak256(b[:core]).hex()             # TXID = Keccak256(core statement) (transaction.go:191-199)
    t['fees_total'] = sum(p['fees'] for p in t['payloads'] if p['scid_zero'])   # Fees() (transaction.go:226-234)
    t['burn_total'] = sum(p['burn'] for p in t['payloads'])
    return t


def decode_block(b):
    i = 0
    bl = {}
    bl['major'], i, _ = uvarint(b, i)
    bl['minor'], i, _ = uvarint(b, i)
    ts, i = take(b, i, 8)
    bl['timestamp_ms'] = int.from_bytes(ts, 'big')
    bl['height'], i, _ = uvarint(b, i)
    mt, i = _tx_header(b, i)
    if mt['type'] != COINBASE:
        raise DecodeError('miner tx is not COINBASE')
    bl['miner_tx_type'] = TXTYPES[mt['type']]
    bl['miner_value_field_present'] = mt['value_field_present']
    pf, i = take(b, i, 32)
    bl['proof_field_nonzero'] = pf != bytes(32)
    n, i, w = uvarint(b, i)
    if w != 1:
        raise DecodeError('tips count width')
    bl['tips'] = []
    for _ in range(n):
        h, i = take(b, i, 32)
        bl['tips'].append(h.hex())
    n, i, w = uvarint(b, i)
    if w > 2:
        raise DecodeError('miniblock count width')
    finals = 0
    for _ in range(n):
        mb, i = take(b, i, MINIBLOCK_SIZE)
        if mb[0] & 0xf != 1:
            raise DecodeError('miniblock version')
        finals += 1 if mb[0] & 0x20 else 0
    bl['miniblocks'], bl['miniblocks_final'] = n, finals
    n, i, _ = uvarint(b, i)
    bl['tx_hashes'] = []
    for _ in range(n):
        h, i = take(b, i, 32)
        bl['tx_hashes'].append(h.hex())
    if i != len(b):
        raise DecodeError('extra bytes after block')
    return bl


def classify_blob(b):
    """Decode a blob as a block or a tx; exactly one must succeed."""
    res = []
    try:
        res.append(('block', decode_block(b)))
    except (DecodeError, IndexError):
        pass
    try:
        res.append(('tx', decode_tx(b)))
    except (DecodeError, IndexError):
        pass
    if len(res) != 1:
        return ('undecodable' if not res else 'ambiguous'), None
    return res[0]


def _blob_job(path):
    b = Path(path).read_bytes()
    kind, d = classify_blob(b)
    out = {'name': Path(path).name, 'sha256': hashlib.sha256(b).hexdigest(), 'size': len(b), 'kind': kind}
    if kind == 'block':
        out['sha3'] = sha3_256(b).hex()
        out['d'] = d
    elif kind == 'tx':
        out['d'] = d
    return out


# =============================================================================================== source (SRC) parsers
def parse_hf3(text):
    """HF3_Affected_Txs literal entries with their group comment and line (hardfork_fixes.go:27)."""
    out, group = {}, None
    rx = re.compile(r'"([0-9a-f]{64})":\s*\{Bl_Tips:\s*"([0-9a-f]{64})",\s*Height:\s*(\d+),\s*Tx_Parity:\s*(true|false)\s*(,[^}]*)?\}')
    for ln, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if s.startswith('//'):
            group = s.lstrip('/ ').strip()
            continue
        m = rx.search(line)
        if m:
            if m.group(1) in out:
                raise ValueError('duplicate table key')
            out[m.group(1)] = {'bl_tips': m.group(2), 'height': int(m.group(3)), 'tx_parity': m.group(4) == 'true',
                               'parity_literal_set': bool(m.group(5) and 'Parity' in m.group(5).replace('Tx_Parity', '')),
                               'group': group, 'line': ln}
        elif '"' in s and re.search(r'"[0-9a-f]{64}"', s):
            raise ValueError(f'unparsed table line {ln}')
    return out


def parse_constants(repo):
    """Emission constants read from the source text; the formulas are matched literally so a change is noticed."""
    cfg = (repo / 'config/config.go').read_text()
    ex = (repo / 'blockchain/transaction_execute.go').read_text()
    sup = (repo / 'blockchain/supply.go').read_text()
    c = {}
    c['BLOCK_TIME'] = int(re.search(r'const BLOCK_TIME = uint64\((\d+)\)', cfg).group(1))
    c['PREMINE'] = int(re.search(r'const PREMINE uint64 = (\d+)', cfg).group(1))
    c['MAJOR_HF3_HEIGHT'] = int(re.search(r'MAJOR_HF3_HEIGHT:\s+(\d+),', cfg).group(1))
    c['grant'] = int(re.search(r'supply \+= (\d+)', sup).group(1))
    ok = ('const RewardReductionInterval = 210000 * 600 / config.BLOCK_TIME' in ex and
          'const BaseReward = (41 * 100000 * config.BLOCK_TIME) / 600' in ex and
          'return BaseReward >> ((height + RewardReductionInterval) / RewardReductionInterval)' in ex and
          'supply += CalcBlockReward(epochStartHeight) * blocksInEpoch' in sup and
          'share := full_reward / uint64(len(bl.MiniBlocks))' in ex and
          'leftover := full_reward - (share * uint64(len(bl.MiniBlocks)))' in ex and
          'if mbl.Final {' in ex)
    c['formulas_match_source'] = ok
    c['RRI'] = 210000 * 600 // c['BLOCK_TIME']
    c['BaseReward'] = (41 * 100000 * c['BLOCK_TIME']) // 600
    return c


def block_reward(c, h):
    return c['BaseReward'] >> ((h + c['RRI']) // c['RRI'])


def calc_supply(c, h):
    s = c['PREMINE'] + c['grant']
    rem, start = h, 0
    while rem > 0:
        n = min(rem, c['RRI'])
        s += block_reward(c, start) * n
        rem -= n
        start += c['RRI']
    return s


# Code anchors the exception-path classification depends on: (file, line, text that must be on that line).
CODE_ANCHORS = [
    ('blockchain/transaction_verify.go', 232, 'if t, ok := HF3_Affected_Txs[tx_hash.String()]; ok {'),
    ('blockchain/transaction_verify.go', 233, 'transaction_valid_cache.Store(tx_hash, time.Now())'),
    ('blockchain/transaction_verify.go', 236, 'tips_string += fmt.Sprintf("%s", t.Bl_Tips)'),
    ('blockchain/transaction_verify.go', 237, 'chain.cache_IsNonceValidTips.Add(tips_string, true)'),
    ('blockchain/transaction_verify.go', 90, 'tips_string := tx_hash.String()'),
    ('blockchain/transaction_verify.go', 94, 'if _, found := chain.cache_IsNonceValidTips.Get(tips_string); found {'),
    ('blockchain/transaction_verify.go', 433, 'tx_cache := tx_hash'),
    ('blockchain/transaction_verify.go', 434, 'if tx.Height >= uint64(globals.Config.MAJOR_HF3_HEIGHT) {'),
    ('blockchain/transaction_verify.go', 438, 'if _, ok := transaction_valid_cache.Load(tx_cache); ok {'),
    ('blockchain/transaction_verify.go', 454, 'if !tx.Payloads[t].Proof.Verify('),
    ('blockchain/transaction_execute.go', 213, 'parity := tx.Payloads[t].Proof.Parity()'),
    ('blockchain/transaction_execute.go', 244, 'if t, ok := HF3_Affected_Txs[tx.GetHash().String()]; ok {'),
    ('blockchain/transaction_execute.go', 245, 'parity = t.Parity'),
    ('blockchain/blockchain.go', 826, 'Verify_Transaction_NonCoinbase_CheckNonce_Tips(hf_version, cbl.Txs[j], bl.Tips)'),
    ('blockchain/blockchain.go', 858, 'chain.Verify_Transaction_NonCoinbase(cbl.Txs[j])'),
    ('p2p/hf3_parity.go', 74, 'if verify != nil {'),
    ('p2p/hf3_parity.go', 77, 't.Parity = (height > t.Height) == t.Tx_Parity'),
    ('glue/txprecheck/window.go', 140, 'if _, ok := blockchain.HF3_Affected_Txs[string(key[:])]; ok {'),
]


def check_anchors(repo):
    out = []
    for f, ln, text in CODE_ANCHORS:
        lines = (repo / f).read_text().splitlines()
        out.append({'file': f, 'line': ln, 'present': ln <= len(lines) and text in lines[ln - 1]})
    return out


# =============================================================================================== content scan
PRIV_RX = [
    ('ipv4', re.compile(r'(?<![\d.])(?!(?:10|127)\.)(?!192\.168\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')),
    ('ipv6', re.compile(r'\b(?:[0-9a-f]{1,4}:){4,7}[0-9a-f]{1,4}\b', re.I)),
    ('home path', re.compile(r'/(?:Users|home|private/tmp|var/folders)/\w')),
    ('dero address', re.compile(r'\bde[rt]oi?1[02-9ac-hj-np-z]{20,}')),
    ('host', re.compile(r'\b[\w-]+\.(?:local|lan|internal)\b')),
    ('url', re.compile(r'\b(?:https?|wss?)://', re.I)),
]


def exploit_patterns(repo):
    """The G24 exploit lint patterns, read from harness/intel/disclosure_track.py (not the builder's code)."""
    src = (repo / 'harness/intel/disclosure_track.py').read_text()
    m = re.search(r'EXPLOIT_PATTERNS = \[(.*?)\n\]', src, re.S)
    pats = []
    if m:
        ns = {}
        exec('P = [' + m.group(1) + '\n]', {'__builtins__': {}}, ns)   # a literal list of (name, regex) tuples
        pats = [(n, re.compile(p, re.I)) for n, p in ns['P']]
    extra = [('procedure words', re.compile(r'\b(forg(?:e|ed|ing)\s+(?:a\s+)?(?:valid\s+)?proof|craft(?:ed|ing)?\s+(?:a\s+)?(?:proof|tx|transaction)'
                                         r'|attack\s+(?:recipe|steps|procedure)|exploit\s+(?:code|recipe|steps|procedure|script))\b', re.I))]
    return pats + extra


def iter_texts(ds):
    for p in sorted(ds.rglob('*')):
        if not p.is_file() or p.parent.name == 'blobs':
            continue
        rel = str(p.relative_to(ds))
        raw = p.read_bytes()
        if p.suffix == '.gz':
            raw = gzip.decompress(raw)
        try:
            yield rel, raw.decode('utf-8')
        except UnicodeDecodeError:
            yield rel, None


def scan_dataset(ds, repo, private_terms, skip_prefix=None):
    pats = exploit_patterns(repo)
    hits, undecodable, scanned = [], [], 0
    for rel, text in iter_texts(ds):
        if skip_prefix and rel.startswith(skip_prefix):
            continue
        if text is None:
            undecodable.append(rel)
            continue
        scanned += 1
        for n, rx in pats:
            m = rx.search(text)
            if m:
                hits.append({'file': rel, 'kind': 'exploit:' + n, 'match_sha256': hashlib.sha256(m.group(0).encode()).hexdigest()[:16]})
        for n, rx in PRIV_RX:
            m = rx.search(text)
            if m:
                hits.append({'file': rel, 'kind': 'privacy:' + n, 'match_sha256': hashlib.sha256(m.group(0).encode()).hexdigest()[:16]})
        for t in private_terms:
            if t and t in text:
                hits.append({'file': rel, 'kind': 'privacy:private term', 'match_sha256': hashlib.sha256(t.encode()).hexdigest()[:16]})
    return {'files_scanned': scanned, 'binary_skipped': undecodable, 'hits': hits,
            'patterns': len(pats) + len(PRIV_RX), 'private_terms_loaded': len(private_terms)}


def load_private_terms(d):
    terms = set()
    if not d or not Path(d).is_dir():
        return []
    for p in sorted(Path(d).glob('*.json')):
        try:
            o = json.loads(p.read_text())
        except (ValueError, OSError):
            continue
        stack = [o]
        while stack:
            x = stack.pop()
            if isinstance(x, dict):
                stack += list(x.values()) + [k for k in x.keys() if isinstance(k, str)]
            elif isinstance(x, list):
                stack += x
            elif isinstance(x, str):
                s = x.strip()
                # hosts, IPs, addresses, paths: anything long enough to be identifying and not a pseudonym/hex id
                if len(s) >= 7 and not re.search(r'\s|[{}\[\]()]', s) and not re.match(r'\d{4}-\d\d-\d\dT', s) and (
                        re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?', s)                       # IPv4[:port]
                        or re.fullmatch(r'\[?[0-9a-f:]+\]?(?::\d+)?', s, re.I) and s.count(':') >= 3  # IPv6
                        or re.fullmatch(r'(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?', s, re.I)             # host[:port]
                        or re.match(r'(?:https?|wss?)://', s) or s.startswith(('dero1', 'deto1', 'deroi1', '/'))):
                    terms.add(s)
    for t in list(terms):                       # the host of every private URL is itself a private term
        m = re.match(r'(?:https?|wss?)://\[?([^/\]]+?)\]?(?::\d+)?(?:/|$)', t)
        if m and len(m.group(1)) >= 4:
            terms.add(m.group(1))
    # drop generic strings that are not identifying (method names, versions)
    return sorted(t for t in terms if not re.fullmatch(r'[\w.-]*\d+\.\d+\.\d+[\w.+-]*|DERO\.\w+|\w+\.\w+\(.*\)', t))


# =============================================================================================== the audit run
def _jsonl_gz(p):
    return [json.loads(l) for l in gzip.decompress(Path(p).read_bytes()).decode().splitlines() if l.strip()]


def _pool_map(fn, items, jobs):
    if jobs <= 1:
        return [fn(x) for x in items]
    import multiprocessing as mp
    ctx = mp.get_context('fork')
    with ctx.Pool(jobs) as pool:
        return pool.map(fn, items, chunksize=256)


def git_first_commit_time(repo, needle, path):
    try:
        r = subprocess.run(['git', '-C', str(repo), 'log', '--format=%H %at', '--reverse', '-S', needle, '--', path],
                           capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = [l for l in r.stdout.splitlines() if l.strip()]
    if r.returncode or not lines:
        return None
    h, t = lines[0].split()
    return {'commit': h[:12], 'author_time': int(t)}


def run_audit(ds, repo, store, archive, live, private, jobs):
    ds, repo = Path(ds), Path(repo)
    R = {'impl': IMPL_VERSION, 'dataset': ds.name}
    st = hash_selftest()
    R['selftest'] = {'hash_kats': len(KAT), 'failures': st}
    if st:
        R['result'] = 'FAIL: selftest'
        return R
    manifest_bytes = (ds / 'manifest.json').read_bytes()
    man = json.loads(manifest_bytes)
    R['binding'] = binding_of(man)
    R['binding']['manifest_sha256_at_audit'] = hashlib.sha256(manifest_bytes).hexdigest()

    # ---------------------------------------------------------------- 1. every blob: content address, decode, id
    paths = sorted(str(p) for p in (ds / 'raw' / 'blobs').iterdir() if p.is_file())
    tierA = _pool_map(_blob_job, paths, jobs)
    tierB = []
    if store and Path(store).is_dir():
        sp = sorted(str(p) for p in Path(store).iterdir() if p.is_file())
        tierB = _pool_map(_blob_job, sp, jobs)
    R['store_present'] = bool(tierB)
    blobs = {}
    content_addr_fail, undec = [], []
    for src, lst in (('A', tierA), ('B', tierB)):
        for o in lst:
            if o['name'] != o['sha256']:
                content_addr_fail.append(src + ':' + o['name'][:16])
            if o['kind'] not in ('block', 'tx'):
                undec.append(src + ':' + o['name'][:16])
            o['tier'] = src
            prev = blobs.get(o['sha256'])
            if prev is None or src == 'A':
                o['also_in_store'] = bool(prev) or False
                blobs[o['sha256']] = o
    idx = hashlib.sha256(''.join(o['name'] + '\n' for o in sorted(tierB, key=lambda x: x['name'])).encode()).hexdigest() if tierB else None
    R['blobs'] = {'tierA_files': len(tierA), 'tierB_files': len(tierB),
                  'tierA_blocks': sum(o['kind'] == 'block' for o in tierA), 'tierA_txs': sum(o['kind'] == 'tx' for o in tierA),
                  'tierB_blocks': sum(o['kind'] == 'block' for o in tierB), 'tierB_txs': sum(o['kind'] == 'tx' for o in tierB),
                  'distinct_blobs': len(blobs), 'content_address_failures': content_addr_fail, 'undecodable': undec,
                  'tierB_index_sha256': idx, 'tierB_index_eq_manifest': (idx == man.get('tierB_store', {}).get('index_sha256')) if idx else None,
                  'tierB_count_eq_manifest': (len(tierB) == man.get('tierB_store', {}).get('count')) if tierB else None}
    blocks = {}
    for o in blobs.values():
        if o['kind'] == 'block':
            blocks.setdefault(o['sha3'], o)
    txs = {}
    for o in blobs.values():
        if o['kind'] == 'tx':
            txs.setdefault(o['d']['txid'], o)

    # ---------------------------------------------------------------- 2. anchor and the tips walk (check ii)
    anchors = json.loads((ds / 'raw' / 'anchors.json').read_text())
    anc = [a for a in anchors if a.get('kind') == 'block'][0]
    A = {'id': anc['id'], 'height': anc['height'], 'blob_present': anc['id'] in blocks}
    if live:
        lt = Path(live) / 'live_topo_7498540_7504640.bin'
        rec = lt.read_bytes()
        A['live_topo_records_sha256'] = hashlib.sha256(rec).hexdigest()
        topo = {7498540 + k: (rec[48 * k:48 * k + 32].hex(), int.from_bytes(rec[48 * k + 40:48 * k + 48], 'little'))
                for k in range(len(rec) // 48)}
        A['live_topo_record_at_anchor_eq_id'] = topo[anc['height']][0] == anc['id']
        A['live_topo_record_height_field'] = topo[anc['height']][1]
        # walk the live node's own blocks from the HF3 fork block down to the anchor, by tips
        lb = Path(live) / 'live_blocks'
        cur, steps, ok, v3 = topo[7504640][0], 0, True, None
        fork_major = None
        while True:
            p = lb / cur
            if not p.exists():
                ok = False
                break
            b = p.read_bytes()
            if sha3_256(b).hex() != cur:
                ok = False
                break
            d = decode_block(b)
            if fork_major is None:
                fork_major = d['major']
            if topo.get(d['height'], (None,))[0] != cur:
                ok = False
                break
            if cur == anc['id']:
                break
            if len(d['tips']) != 1:
                ok = False
                break
            cur = d['tips'][0]
            steps += 1
        A['live_blocks_index_sha256'] = hashlib.sha256(''.join(n + '\n' for n in sorted(os.listdir(lb))).encode()).hexdigest()
        A['live_walk_hf3_to_anchor'] = {'from_height': 7504640, 'from_id': topo[7504640][0], 'reached_anchor': ok and cur == anc['id'],
                                        'steps': steps, 'fork_block_major_version': fork_major,
                                        'fork_id_prefix_v3_fingerprint': topo[7504640][0][:8] == 'e454090e'}
    R['anchor'] = A

    reached, order = {}, []
    cur = anc['id']
    walk_ok, multi_tip = True, 0
    lowest_needed = 7415464
    while True:
        o = blocks.get(cur)
        if o is None:
            walk_ok = False
            break
        d = o['d']
        reached[cur] = d
        order.append(cur)
        if d['height'] <= lowest_needed:
            break
        if len(d['tips']) != 1:
            multi_tip += 1
        nxt = [t for t in d['tips'] if t in blocks]
        if len(nxt) != len(d['tips']) or not nxt:
            walk_ok = False
            break
        cur = nxt[0]  # single-tip chain (multi_tip counts any exception)
    heights = [reached[i]['height'] for i in order]
    contiguous = all(heights[k] - heights[k + 1] == 1 for k in range(len(heights) - 1))
    by_height = {reached[i]['height']: i for i in order}
    W0, W1 = 7415466, 7497942
    in_window = [h for h in range(W0, W1 + 1) if h in by_height]
    unreached_blocks = sorted(set(blocks) - set(reached))
    R['walk'] = {'ok': walk_ok, 'blocks_reached': len(order), 'top_height': heights[0] if heights else None,
                 'bottom_height': heights[-1] if heights else None, 'contiguous_heights': contiguous, 'multi_tip_blocks': multi_tip,
                 'window_heights_reached': len(in_window), 'window_heights_total': W1 - W0 + 1,
                 'blocks_not_reached': len(unreached_blocks), 'topo_eq_height_derived': contiguous and heights[0] == anc['height']}

    # ---------------------------------------------------------------- 3. tier B counts and per-block emission
    c = parse_constants(repo)
    R['constants'] = {k: c[k] for k in ('BLOCK_TIME', 'PREMINE', 'grant', 'RRI', 'BaseReward', 'MAJOR_HF3_HEIGHT', 'formulas_match_source')}
    rows = {}
    em = {'blocks': 0, 'coinbase_type_ok': 0, 'miner_value_field_absent': 0, 'exactly_one_final_miniblock': 0,
          'distribution_identity_ok': 0, 'supply_step_eq_reward': 0, 'reward_sum': 0, 'fees_known_blocks': 0,
          'fees_known_sum': 0, 'fees_pending_blocks': 0, 'burn_known_sum': 0, 'proof_field_nonzero': 0,
          'tx_bearing_blocks': 0, 'txs': 0, 'major_versions': {}, 'reward_values': set()}
    for h in in_window:
        d = reached[by_height[h]]
        em['blocks'] += 1
        em['coinbase_type_ok'] += d['miner_tx_type'] == 'COINBASE'
        em['miner_value_field_absent'] += not d['miner_value_field_present']
        em['proof_field_nonzero'] += d['proof_field_nonzero']
        em['major_versions'][str(d['major'])] = em['major_versions'].get(str(d['major']), 0) + 1
        base = block_reward(c, h)
        em['reward_values'].add(base)
        em['reward_sum'] += base
        step = calc_supply(c, h + 1) - calc_supply(c, h)
        em['supply_step_eq_reward'] += step == base
        if d['tx_hashes']:
            em['tx_bearing_blocks'] += 1
            em['txs'] += len(d['tx_hashes'])
        known = all(t in txs for t in d['tx_hashes'])
        fees = sum(txs[t]['d']['fees_total'] for t in d['tx_hashes']) if known else None
        if known:
            em['fees_known_blocks'] += 1
            em['fees_known_sum'] += fees
            em['burn_known_sum'] += sum(txs[t]['d']['burn_total'] for t in d['tx_hashes'])
        else:
            em['fees_pending_blocks'] += 1
        n, F = d['miniblocks'], d['miniblocks_final']
        em['exactly_one_final_miniblock'] += F == 1
        # paid = integrator (share + leftover) + share per non-final miniblock (transaction_execute.go:126-160);
        # with fees unknown the identity paid == base + fees still holds iff F == 1 (it is linear in full_reward)
        if n >= 1:
            full = base + (fees or 0)
            share = full // n
            paid = share + (full - share * n) + share * (n - F)
            em['distribution_identity_ok'] += paid == full
        rows[h] = {'blid': by_height[h], 'tips': d['tips'], 'tx_hashes': d['tx_hashes'], 'miniblocks': n, 'final': F,
                   'base': base, 'fees': fees, 'ts': d['timestamp_ms'], 'proof_nz': d['proof_field_nonzero'],
                   'sha256': blocks[by_height[h]]['sha256'], 'supply_before': calc_supply(c, h), 'supply_after': calc_supply(c, h + 1)}
    em['reward_values'] = sorted(em['reward_values'])
    em['calc_supply_delta'] = calc_supply(c, W1 + 1) - calc_supply(c, W0)
    em['reward_sum_eq_supply_delta'] = em['calc_supply_delta'] == em['reward_sum']
    R['emission'] = em

    # ---------------------------------------------------------------- 4. txs: TXID (iii) + inclusion
    carriers_of = {}
    for h in in_window + [x for x in sorted(by_height) if x not in range(W0, W1 + 1)]:
        for t in reached[by_height[h]]['tx_hashes']:
            carriers_of.setdefault(t, []).append(h)
    txr = {'bodies': len(txs), 'txid_in_verified_block': sum(t in carriers_of for t in txs),
           'blob_names_eq_sha256': all(o['name'] == o['sha256'] for o in blobs.values() if o['kind'] == 'tx')}
    R['txs'] = txr

    # ---------------------------------------------------------------- 5. HF3 table vs RAW chain; exception paths
    table_text = (repo / 'blockchain/hardfork_fixes.go').read_text()
    T = parse_hf3(table_text)
    groups = {}
    for v in T.values():
        groups[v['group']] = groups.get(v['group'], 0) + 1
    R['hf3_table'] = {'entries': len(T), 'groups': groups, 'tx_parity_true': sum(v['tx_parity'] for v in T.values()),
                      'parity_literal_set': sum(v['parity_literal_set'] for v in T.values()),
                      'min_height': min(v['height'] for v in T.values()), 'max_height': max(v['height'] for v in T.values()),
                      'sha256': hashlib.sha256((repo / 'blockchain/hardfork_fixes.go').read_bytes()).hexdigest()}
    R['hf3_table']['sha256_eq_manifest'] = R['hf3_table']['sha256'] == man.get('hf3_table', {}).get('sha256')
    R['code_anchors'] = check_anchors(repo)
    HF3H = c['MAJOR_HF3_HEIGHT']
    per, agg = {}, {'bodies_raw': 0, 'carriers': 0, 'dual': 0, 'single': 0, 'height_is_earliest_carrier': 0,
                    'bl_tips_is_tip_of_earliest': 0, 'bl_tips_is_earliest_itself': 0, 'ref_blid_eq_bl_tips': 0,
                    'ref_blid_on_raw_chain_at_ref_height': 0, 'tx_height_below_hf3': 0, 'proof_skip_carriers': 0,
                    'nonce_bypass_carriers': 0, 'nonce_full_carriers': 0, 'parity_changes_carriers': 0,
                    'sanity_rawcheckable_pass': 0, 'types': {}, 'public_value_nonzero': 0,
                    'carrier_gap_heights': [], 'carrier_before_table_commit': 0, 'table_commit_known': 0}
    first_commits = {}
    for txid, e in sorted(T.items()):
        o = txs.get(txid)
        rec = {'table_height': e['height'], 'group': e['group'], 'tx_parity': e['tx_parity'], 'body_raw': o is not None}
        car = sorted(carriers_of.get(txid, []))
        rec['carrier_heights'] = car
        if o is not None:
            agg['bodies_raw'] += 1
            d = o['d']
            rec['txid_recomputed_eq'] = d['txid'] == txid
            rec['type'] = TXTYPES[d['type']]
            agg['types'][rec['type']] = agg['types'].get(rec['type'], 0) + 1
            rec['fee'], rec['burn_total'], rec['value'] = d['fees_total'], d['burn_total'], d['value']
            agg['public_value_nonzero'] += bool(d['burn_total'] or d['value'])
            rec['ref_height'], rec['ref_blid'] = d.get('height'), d.get('blid')
            rh = d.get('height')
            rec['ref_block'] = ('outside_raw_range' if rh not in by_height else
                                'on_raw_chain' if by_height[rh] == d.get('blid') else 'not_on_raw_chain')
            agg['ref_blid_on_raw_chain_at_ref_height'] += rec['ref_block'] == 'on_raw_chain'
            agg['ref_block_outside_raw_range'] = agg.get('ref_block_outside_raw_range', 0) + (rec['ref_block'] == 'outside_raw_range')
            agg['ref_block_not_on_raw_chain'] = agg.get('ref_block_not_on_raw_chain', 0) + (rec['ref_block'] == 'not_on_raw_chain')
            agg['ref_blid_eq_bl_tips'] += d.get('blid') == e['bl_tips']
            rec['tx_height_below_hf3'] = d.get('height', HF3H) < HF3H
            agg['tx_height_below_hf3'] += rec['tx_height_below_hf3']
            ps = d['payloads']
            sane = (len(ps) >= 1 and any(p['scid_zero'] for p in ps) and all(p['roothash'] == ps[0]['roothash'] for p in ps)
                    and all(2 <= p['ring'] <= 128 and p['pointers_distinct'] for p in ps)
                    and not (d['type'] == BURN_TX and d['value'] == 0))
            rec['sanity_rawcheckable'] = sane
            agg['sanity_rawcheckable_pass'] += sane
            rec['roothash'] = ps[0]['roothash'] if ps else None
            rec['ring_sizes'] = [p['ring'] for p in ps]
        if len(car) == 2:
            agg['dual'] += 1
            agg['carrier_gap_heights'].append(car[1] - car[0])
        elif len(car) == 1:
            agg['single'] += 1
        rec['height_is_earliest_carrier'] = bool(car) and car[0] == e['height']
        agg['height_is_earliest_carrier'] += rec['height_is_earliest_carrier']
        if car:
            first = by_height[car[0]]
            rec['bl_tips_is_tip_of_earliest'] = reached[first]['tips'] == [e['bl_tips']]
            rec['bl_tips_is_earliest_itself'] = first == e['bl_tips']
            agg['bl_tips_is_tip_of_earliest'] += rec['bl_tips_is_tip_of_earliest']
            agg['bl_tips_is_earliest_itself'] += rec['bl_tips_is_earliest_itself']
        cl = []
        for h in car:
            bid = by_height[h]
            d = reached[bid]
            x = {'height': h, 'blid': bid}
            x['proof_skip'] = bool(o is not None and rec.get('tx_height_below_hf3') and h < HF3H)
            x['nonce_bypass'] = d['tips'] == [e['bl_tips']]
            override = (h > e['height']) == e['tx_parity']
            nat = [p.get('proof_parity') for p in (o['d']['payloads'] if o else [])]
            x['parity_override'] = override
            x['parity_changes_execution'] = (any(n != override for n in nat) if nat else None)
            agg['carriers'] += 1
            agg['proof_skip_carriers'] += x['proof_skip']
            agg['nonce_bypass_carriers'] += x['nonce_bypass']
            agg['nonce_full_carriers'] += not x['nonce_bypass']
            agg['parity_changes_carriers'] += bool(x['parity_changes_execution'])
            cl.append(x)
        rec['carriers'] = cl
        fc = git_first_commit_time(repo, txid, 'blockchain/hardfork_fixes.go')
        if fc and car:
            agg['table_commit_known'] += 1
            ts = reached[by_height[car[0]]]['timestamp_ms'] // 1000
            rec['first_table_commit'] = fc['commit']
            rec['earliest_carrier_before_table_commit'] = ts < fc['author_time']
            rec['table_commit_minus_carrier_hours'] = round((fc['author_time'] - ts) / 3600, 1)
            agg['carrier_before_table_commit'] += rec['earliest_carrier_before_table_commit']
            m = rec['table_commit_minus_carrier_hours']
            agg['min_margin_hours'] = m if agg.get('min_margin_hours') is None else min(agg['min_margin_hours'], m)
            first_commits[fc['commit']] = first_commits.get(fc['commit'], 0) + 1
        per[txid] = rec
    agg['carrier_gap_heights'] = sorted(set(agg['carrier_gap_heights']))
    agg['first_table_commits'] = first_commits
    R['hf3'] = agg
    R['hf3_per_txid'] = per

    # ---------------------------------------------------------------- 6. archive corroboration (our replaywall copy)
    if archive:
        ap = Path(archive)
        rec = (ap / 'topo_7453290_7467921.bin').read_bytes()
        nz = eq = ne = 0
        sv = {}
        for k in range(len(rec) // 48):
            h = 7453290 + k
            bid = rec[48 * k:48 * k + 32]
            if bid == bytes(32):
                continue
            nz += 1
            sv[h] = int.from_bytes(rec[48 * k + 32:48 * k + 40], 'little')
            if by_height.get(h) == bid.hex():
                eq += 1
            else:
                ne += 1
        files = [p for p in (ap / 'bltx_store').rglob('*') if p.is_file() and '.block' in p.name]
        fid_ok = fbytes_eq = on_chain = off_chain = 0
        for p in files:
            b = p.read_bytes()
            name = p.name.split('.')[0]
            if sha3_256(b).hex() == name:
                fid_ok += 1
            if name in reached:
                on_chain += 1
                fbytes_eq += hashlib.sha256(b).hexdigest() == blocks[name]['sha256']
            else:
                off_chain += 1
        last_committed = max(sv) if sv else None
        above = [p for p in files if int(p.name.rsplit('_', 1)[-1]) > (last_committed or 0)]
        above_on_chain = sum(p.name.split('.')[0] in reached for p in above)
        txfiles = [p for p in (ap / 'bltx_store').rglob('*.tx')]
        hf3_in_archive = [p.name[:-3] for p in txfiles if p.name[:-3] in T]
        hf3_bytes_eq = sum(txs.get(t) is not None and hashlib.sha256(next(q for q in txfiles if q.name[:-3] == t).read_bytes()).hexdigest() == txs[t]['sha256'] for t in hf3_in_archive)
        # the 2 proof results rest on the tx's own Statement.Roothash: RAW, inside the TXID, compared with the
        # builder's archive root claim at the ref block's state version (our own topo record copy gives the version)
        ref_sv = {}
        for t in ('414f79b8ff3c862eaa5727c6591542218881c751ba4fe052c9aaeeec0cfedfcd', '0045a6d4c51a8578b6c97f2b376415653583505f21032eb6a808cd1643a300a7'):
            r = per.get(t, {})
            h = r.get('ref_height')
            ref_sv[t[:8]] = {'ref_height': h, 'archive_record_eq_ref_blid': (h in sv and by_height.get(h) == r.get('ref_blid')),
                             'state_version': sv.get(h), 'roothash': r.get('roothash')}
        # every tx body our archive holds: TXID from its bytes, inclusion in the RAW chain, and its Statement.Roothash
        # against the builder's archive root claim at the ref block (a RAW witness of that root, :336-338)
        claim_roots = {r['topo']: r['root'] for r in _jsonl_gz(ds / 'derived' / 'archive_state' / 'roots.jsonl.gz')}
        wit = {'bodies': len(txfiles), 'txid_eq_name': 0, 'in_raw_chain_block': 0, 'ref_on_raw_chain': 0,
               'ref_in_held_range': 0, 'roothash_eq_claimed_root': 0, 'roothash_ne_claimed_root': 0, 'undecodable': 0,
               'distinct_ref_topos_witnessed': 0, 'fills_pending_fee_blocks': 0}
        topos_w = set()
        arch_txs = {}
        for q in txfiles:
            b = q.read_bytes()
            try:
                d = decode_tx(b)
            except (DecodeError, IndexError):
                wit['undecodable'] += 1
                continue
            if d['txid'] != q.name[:-3]:
                continue
            wit['txid_eq_name'] += 1
            if d['txid'] not in carriers_of:
                continue
            wit['in_raw_chain_block'] += 1
            arch_txs[d['txid']] = d
            rh = d.get('height')
            if rh is None:
                continue
            if by_height.get(rh) == d.get('blid'):
                wit['ref_on_raw_chain'] += 1
                if rh in claim_roots:
                    wit['ref_in_held_range'] += 1
                    eqr = all(p['roothash'] == claim_roots[rh] for p in d['payloads'])
                    wit['roothash_eq_claimed_root' if eqr else 'roothash_ne_claimed_root'] += 1
                    if eqr:
                        topos_w.add(rh)
        wit['distinct_ref_topos_witnessed'] = len(topos_w)
        for h in in_window:
            if rows[h]['fees'] is None and all(t in txs or t in arch_txs for t in rows[h]['tx_hashes']):
                wit['fills_pending_fee_blocks'] += 1
        R['archive_tx_witness'] = wit
        R['archive'] = {'topo_records_sha256': hashlib.sha256(rec).hexdigest(), 'committed_records': nz, 'records_eq_raw_chain': eq,
                        'records_ne_raw_chain': ne, 'last_committed_height': last_committed, 'block_files': len(files),
                        'block_file_name_eq_sha3': fid_ok, 'block_files_on_raw_chain': on_chain, 'block_files_off_chain': off_chain,
                        'on_chain_bytes_eq_raw': fbytes_eq, 'files_above_last_committed': len(above),
                        'files_above_last_committed_on_raw_chain': above_on_chain, 'tx_files': len(txfiles),
                        'hf3_bodies_in_archive': len(hf3_in_archive), 'hf3_bodies_bytes_eq_raw': hf3_bytes_eq, 'ref_state': ref_sv}

    # ---------------------------------------------------------------- 7. the builder's claims, compared at the END
    R['claims'] = compare_claims(ds, rows, per, txs, R)
    R['scan'] = scan_dataset(ds, repo, load_private_terms(private), skip_prefix='audit/')
    R['scan']['scope'] = 'every text file of the dataset outside audit/ (audit/ is scanned by G29 after it is written)'
    return R


def compare_claims(ds, rows, per, txs, R):
    out = {}
    dv = ds / 'derived'
    win = {r['height']: r for r in _jsonl_gz(dv / 'window.jsonl.gz')}
    hc = {r['height']: r for r in _jsonl_gz(ds / 'raw' / 'headerchain.jsonl.gz')}
    mism = {}

    def bump(k):
        mism[k] = mism.get(k, 0) + 1
    for h, m in rows.items():
        w = win.get(h)
        if w is None:
            bump('window_row_missing')
            continue
        if w.get('blid') != m['blid'] or w.get('sha3_256') != m['blid']:
            bump('blid')
        if w.get('sha256') != m['sha256']:
            bump('sha256')
        if w.get('topo') != h:
            bump('topo')
        if w.get('tips') != m['tips']:
            bump('tips')
        if w.get('tx_hashes') != m['tx_hashes'] or w.get('tx_count') != len(m['tx_hashes']):
            bump('tx_list')
        if w.get('miniblocks') != m['miniblocks'] or w.get('miniblocks_final') != m['final']:
            bump('miniblocks')
        if w.get('base_reward') != m['base']:
            bump('base_reward')
        if w.get('supply_before') != m['supply_before'] or w.get('supply_after') != m['supply_after']:
            bump('supply')
        if w.get('timestamp_ms') != m['ts']:
            bump('timestamp')
        if w.get('proof_field_nonzero') != m['proof_nz']:
            bump('proof_field')
        wf = w.get('fees')
        if m['fees'] is None:
            if isinstance(wf, int):
                bump('fees_claimed_where_audit_pending')
        elif wf != m['fees']:
            bump('fees')
        if w.get('reward_ext') != m['base']:
            bump('reward_ext_ne_formula (EXT)')
        x = hc.get(h)
        if x is None or x.get('blid') != m['blid'] or x.get('sha256') != m['sha256']:
            bump('headerchain')
    out['window_rows_compared'] = len(rows)
    out['window_mismatch'] = mism
    out['window_rows_total'] = len(win)

    em = json.loads((dv / 'emission.json').read_text())
    a = R['emission']
    out['emission'] = {
        'window_emission_eq': em.get('window_emission_atomic') == a['reward_sum'],
        'fees_known_blocks_eq': em.get('fees', {}).get('known_blocks') == a['fees_known_blocks'],
        'fees_known_sum_eq': em.get('fees', {}).get('known_sum_atomic') == a['fees_known_sum'],
        'fees_pending_eq': em.get('fees', {}).get('pending_blocks') == a['fees_pending_blocks'],
        'grade': em.get('grade', {}).get('verdict_grade'),
        'scope_mentions_distribution': 'miniblock' in json.dumps(em.get('grade', {})).lower()}

    hf = json.loads((dv / 'hf3.json').read_text()) if (dv / 'hf3.json').exists() else {}
    tx_m = {}

    def tb(k):
        tx_m[k] = tx_m.get(k, 0) + 1
    carrier_fields = 0
    for txid, mine in per.items():
        p = dv / 'tx' / f'{txid}.json'
        if not p.exists():
            tb('tx_record_missing')
            continue
        t = json.loads(p.read_text())
        if t.get('txid') != txid:
            tb('txid')
        if txs.get(txid) and t.get('body', {}).get('sha256') != txs[txid]['sha256']:
            tb('body_sha256')
        if t.get('fee') != mine.get('fee'):
            tb('fee')
        if t.get('burn_total') != mine.get('burn_total'):
            tb('burn_total')
        if t.get('tx_type') != mine.get('type'):
            tb('tx_type')
        if t.get('ref_height') != mine.get('ref_height') or t.get('ref_blid') != mine.get('ref_blid'):
            tb('ref')
        if t.get('txid_recomputed', {}).get('core_statement_len') != (txs[txid]['d']['core_len'] if txs.get(txid) else None):
            tb('core_len')
        tc = sorted(t.get('carriers', []), key=lambda x: x['height'])
        if [c['height'] for c in tc] != mine['carrier_heights']:
            tb('carrier_heights')
            continue
        for bc, mc in zip(tc, mine['carriers']):
            carrier_fields += 1
            ep = bc.get('exception_path', {})
            if bc.get('blid') != mc['blid']:
                tb('carrier_blid')
            if ep.get('tips_eq_table_bl_tips') != mc['nonce_bypass']:
                tb('nonce_bypass')
            if ('bypassed' in str(ep.get('nonce_check', ''))) != mc['nonce_bypass']:
                tb('nonce_check_text')
            if ('skipped' in str(ep.get('proof_verification', ''))) != mc['proof_skip']:
                tb('proof_skip')
            if ep.get('execution_parity', {}).get('override_changes_execution') != mc['parity_changes_execution']:
                tb('parity_changes_execution')
            if ep.get('execution_parity', {}).get('entry_parity') != mc['parity_override']:
                tb('parity_override_value')
        sem = t.get('table_semantics', {})
        if sem.get('height_is_inclusion_height_of_a_carrier') != mine['height_is_earliest_carrier']:
            tb('b82_height')
        if sem.get('bl_tips_is_tip_of_that_carrier') != mine.get('bl_tips_is_tip_of_earliest'):
            tb('b82_bl_tips')
        if sem.get('bl_tips_is_that_carrier_itself') != mine.get('bl_tips_is_earliest_itself'):
            tb('b82_bl_tips_itself')
        g = t.get('grade', {})
        pf = g.get('public_fields', {})
        if pf.get('fee') != mine.get('fee') or pf.get('burn_total') != mine.get('burn_total') or pf.get('value_field') != mine.get('value'):
            tb('grade_public_fields')
    out['hf3_records_compared'] = len(per)
    out['hf3_carrier_rows_compared'] = carrier_fields
    out['hf3_mismatch'] = tx_m
    out['hf3_json_present'] = bool(hf)
    gr = json.loads((dv / 'grades.json').read_text())
    out['grades'] = {'per_txid': len(gr.get('per_txid', [])),
                     'grades': sorted({g.get('verdict_grade') for g in gr.get('per_txid', [])}),
                     'claims_chain_accepted_only_through_exemption': sum('accepted the tx only through the exemption' in json.dumps(g)
                                                                          for g in gr.get('per_txid', []))}
    pc = {}
    for line in (dv / 'archive_state' / 'proof_checks.jsonl').read_text().splitlines():
        if line.strip():
            o = json.loads(line)
            if o.get('txid') in per:
                pc[o['txid'][:8]] = {'result': str(o.get('result', o.get('verdict'))),
                                     'state_root': o.get('state_root') or 'not applicable: no held state'}
    out['proof_checks_claimed'] = {k: pc[k] for k in sorted(pc)}
    out['proof_checks_claimed_counts'] = {r: sum(v['result'] == r for v in pc.values()) for r in sorted({v['result'] for v in pc.values()})}
    return out


# =============================================================================================== G29 + verdict rules
GRADES = ('PROVEN-INFLATION', 'PROVEN-NO-INFLATION-IN-SCOPE', 'NOT-DECIDABLE-FROM-PUBLIC-DATA', 'SPECULATION', 'pending')
PROVEN = ('PROVEN-INFLATION', 'PROVEN-NO-INFLATION-IN-SCOPE')
EVIDENCE = ('RAW', 'DERIVED')


def binding_of(man):
    """What the audit is bound to: every dataset file outside audit/, the HF3 table, the store index, and the tools: the
    content pins' aggregate when the manifest has them (R25 integration; the commit is provenance only, so an audit no
    longer goes stale when the manifest is re-written at a later commit), else the commit."""
    files = {k: v for k, v in sorted(man.get('files', {}).items()) if not k.startswith('audit/')}
    core = {'files': files, 'hf3_table': man.get('hf3_table'), 'tierB_store': man.get('tierB_store')}
    if (man.get('content_pins') or {}).get('aggregate_sha256'):
        core['content_pins'] = man['content_pins']['aggregate_sha256']
    elif isinstance(man.get('tools'), dict) and man.get('tools'):
        # v2 manifests (v2.py) pin their tools and v1 inputs by content but carry no content_pins: bind to those, not
        # to the commit, so re-writing the manifest at a later commit does not stale the audit (R26 forensics-audit2)
        core['tools'] = man['tools']
        core['inputs'] = man.get('inputs')
    else:
        core['git_base_commit'] = man.get('git_base_commit')
    return {'data_sha256': hashlib.sha256(json.dumps(core, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'files_bound': len(files)}


def verdict_problems(verdicts, challenges):
    """MF3 + MF4. A PROVEN grade needs only RAW/DERIVED inputs (an EXT- or interpretation-only input FAILS: MF3), and
    any verdict named by a FAILS/UNRESOLVED challenge must not stay PROVEN (MF4)."""
    fails = []
    bad = {c['id'] for c in challenges if c.get('result') in ('FAILS', 'UNRESOLVED')}
    for v in verdicts:
        g = v.get('audit_grade')
        if g not in GRADES:
            fails.append(f"{v.get('id')}: unknown grade {g}")
            continue
        if g in PROVEN:
            ins = v.get('inputs') or []
            if not ins:
                fails.append(f"{v.get('id')}: {g} with no inputs")
            if any(i.get('class') not in EVIDENCE for i in ins):
                fails.append(f"{v.get('id')}: {g} rests on a non-evidence input (MF3: EXT/INTERPRETATION only)")
            if not v.get('scope') and g == 'PROVEN-NO-INFLATION-IN-SCOPE':
                fails.append(f"{v.get('id')}: PROVEN-NO-INFLATION-IN-SCOPE without its scope")
            hit = sorted(set(v.get('challenges', [])) & bad)
            if hit:
                fails.append(f"{v.get('id')}: still {g} with open/failed challenge(s) {','.join(hit)} (MF4)")
    for c in challenges:
        if c.get('result') in ('FAILS', 'UNRESOLVED'):
            aff = c.get('affects') or []
            if not aff:
                fails.append(f"{c['id']}: {c['result']} without the verdicts it affects")
            for a in aff:
                vs = [v for v in verdicts if v.get('id') == a or (a == 'V-HF3-ALL' and str(v.get('id')).startswith('V-HF3-'))]
                if not vs:
                    fails.append(f"{c['id']}: affects unknown verdict {a}")
                for v in vs:   # a listed FAILS/UNRESOLVED challenge keeps the verdict off PROVEN (the 'hit' rule above)
                    if c['id'] not in v.get('challenges', []):
                        fails.append(f"{c['id']}: verdict {v['id']} does not list it")
        if c.get('result') not in ('HOLDS', 'FAILS', 'UNRESOLVED'):
            fails.append(f"{c.get('id')}: result {c.get('result')} is not HOLDS/FAILS/UNRESOLVED")
    return fails


# challenges an audit of a version must carry (R26: v2 is audited by audit2.py). A version not named here needs the v1
# list A1-A4 (the rule before R26), so a new version fails closed until its own list is added here.
REQUIRED_BY_VERSION = {'r25': ('A1', 'A2', 'A3', 'A4'),
                       'r26': ('D2-01', 'D2-02', 'D2-04', 'D2-05', 'D2-11', 'D2-12', 'D2-14')}


def g29_check(ds, repo=None, private=None):
    """G29 for one dataset version: audit report present, bound to the dataset as it is now, its rerun clean, and
    every FAILS/UNRESOLVED challenge reflected in a downgraded verdict."""
    ds = Path(ds)
    fails = []
    a = ds / 'audit'
    try:
        rep = json.loads((a / 'audit_report.json').read_text())
        ch = json.loads((a / 'challenges.json').read_text())
    except (OSError, ValueError) as e:
        return fails + [f'G29 audit report unreadable: {type(e).__name__}'], {}
    man = json.loads((ds / 'manifest.json').read_text())
    b = binding_of(man)
    if rep.get('binding', {}).get('data_sha256') != b['data_sha256']:
        fails.append('G29 audit is bound to other data (dataset files changed after the audit)')
    for k in ('audit_report.json', 'challenges.json', 'AUDIT.md'):
        got = hashlib.sha256((a / k).read_bytes()).hexdigest() if (a / k).exists() else 'missing'
        if man.get('files', {}).get('audit/' + k) != got:
            fails.append(f'G29 audit/{k} ' + ('missing' if got == 'missing' else 'differs from the manifest'))
    if rep.get('rerun_sha256') != hashlib.sha256(json.dumps(rep.get('rerun'), sort_keys=True, separators=(',', ':')).encode()).hexdigest():
        fails.append('G29 rerun block does not match its SHA-256')
    if rep.get('implementation', {}).get('shares_code_with_builder') is not False:
        fails.append('G29 audit is not a second implementation')
    if rep.get('rerun', {}).get('selftest', {}).get('failures'):
        fails.append('G29 audit selftest failed')
    if rep.get('rerun', {}).get('scan', {}).get('hits'):
        fails.append('G29 exploit/privacy hits remain in the dataset')
    terms = load_private_terms(private if private is not None else os.environ.get(
        'FORENSICS_PRIVATE', str(Path.home() / 'derohe-persist' / 'forensics_private')))
    sc = scan_dataset(ds, Path(repo) if repo else ROOT, terms)
    if sc['hits']:
        fails.append(f"G29 {len(sc['hits'])} exploit/privacy hit(s) in the dataset text: "
                     + ', '.join(sorted({h['file'] + ' ' + h['kind'] for h in sc['hits']}))[:300])
    chs = ch.get('challenges', [])
    if len({c.get('id') for c in chs}) != len(chs):
        fails.append('G29 duplicate challenge ids')
    req = REQUIRED_BY_VERSION.get(ds.name) or REQUIRED_BY_VERSION['r25']
    for want in req:
        if not any(c.get('id', '').startswith(want) for c in chs):
            fails.append(f'G29 required challenge {want} absent')
    if 'dataset' in rep and rep.get('dataset') != ds.name:   # an audit copied from another version
        fails.append(f"G29 audit report names dataset {rep.get('dataset')!r}, not {ds.name}")
    fails += ['G29 ' + x for x in verdict_problems(rep.get('verdicts', []), chs)]
    n_open = sum(c.get('result') == 'UNRESOLVED' for c in chs)
    n_fail = sum(c.get('result') == 'FAILS' for c in chs)
    if rep.get('counts', {}).get('overturned') != n_fail or rep.get('counts', {}).get('unresolved') != n_open:
        fails.append('G29 report counts disagree with challenges.json')
    hist = rep.get('history', [])
    hist_n = sum(h.get('counts', {}).get('overturned', 0) for h in hist)
    if 'overturned_all_runs' in rep.get('counts', {}) and rep['counts']['overturned_all_runs'] != n_fail + hist_n:
        fails.append('G29 overturned_all_runs disagrees with the current run plus audit/history')
    hd = ds / 'audit' / 'history'
    on_disk = sorted(p.name for p in hd.iterdir() if p.is_dir()) if hd.exists() else []
    if on_disk != [h.get('run') for h in hist]:
        fails.append('G29 audit/history runs on disk differ from the report history (an earlier run dropped or added)')
    for h in hist:
        rp = hd / h.get('run', '?') / 'audit_report.json'
        if not rp.exists() or hashlib.sha256(rp.read_bytes()).hexdigest() != h.get('report_sha256'):
            fails.append(f"G29 audit/history/{h.get('run')} report changed after it was recorded")
    return fails, {'challenges': len(chs), 'fails': n_fail, 'unresolved': n_open, 'scanned': sc['files_scanned'],
                   'overturned_all_runs': n_fail + hist_n, 'history_runs': len(hist),
                   'private_terms': len(terms),
                   'downgraded': sum(bool(v.get('downgraded')) for v in rep.get('verdicts', []))}


def g29(repo):
    """G29 over EVERY ledger version (R26, forensics-audit2): each version must carry its own audit, bound to its
    data as it is now; the newest one included (an unaudited newest version FAILS, an earlier audit going stale FAILS)."""
    repo = Path(repo)
    fx = repo / 'forensics'
    led = json.loads((fx / 'ledger.json').read_text()) if (fx / 'ledger.json').exists() else {}
    vs = [v['version'] for v in led.get('versions', [])]
    if not vs:
        return False, 'no forensic dataset version in forensics/ledger.json'
    parts, bad = [], []
    for v in vs:
        f, s = g29_check(fx / v, repo)
        if f:
            bad.append(f'{v}: ' + '; '.join(f[:4]) + (f' (+{len(f) - 4})' if len(f) > 4 else ''))
            continue
        parts.append(f"{v}: {s['challenges']} challenges ({s['fails']} FAILS = overturned, {s['unresolved']} UNRESOLVED; "
                     f"overturned over all {s['history_runs'] + 1} audit runs: {s['overturned_all_runs']}), "
                     f"{s['downgraded']} downgraded, 0 hits in {s['scanned']} text files")
    if bad:
        return False, ' | '.join(bad)
    return True, (f"{len(vs)} version(s), each audit bound to its current data, every FAILS/UNRESOLVED reflected, second "
                  'implementation: ' + ' | '.join(parts))


# =============================================================================================== challenges + report
def _res(ok, unresolved=False):
    return 'UNRESOLVED' if unresolved else ('HOLDS' if ok else 'FAILS')


def build_challenges(R, proof):
    """One row per assumption or claim; each result is computed from the rerun, never typed in."""
    A, W, E, H, T, X = R['anchor'], R['walk'], R['emission'], R['hf3'], R['hf3_table'], R.get('archive', {})
    AW, C, B = R.get('archive_tx_witness', {}), R['claims'], R['blobs']
    lw = A.get('live_walk_hf3_to_anchor', {})
    per = R['hf3_per_txid']
    aa = [t for t, r in per.items() if r.get('bl_tips_is_earliest_itself')]
    pr = {o['txid'][:8]: o for o in proof}
    ch = []

    def add(i, claim, source, test, ok, evidence, affects=None, unresolved=False, note=''):
        ch.append({'id': i, 'claim': claim, 'claim_source': source, 'test': test, 'result': _res(ok, unresolved),
                   'evidence': evidence, 'affects': affects or [], 'note': note})

    add('A1', 'anchor block 7,498,540 (e18be51e) is on the v3 chain', 'rft §0.8.5; raw/anchors.json',
        'own copy of the live node topo.map records 7,498,540..7,504,640: the record at 7,498,540 is the anchor id with '
        'height field 7,498,540; from the record at 7,504,640 (the HF3 fork block) a tips walk over the live node\'s own '
        'block files (APFS clones), each SHA3-256-checked by this implementation, reaches the anchor; the fork block '
        'decodes with major version 3 and id prefix e454090e (the v3 fingerprint)',
        bool(A.get('live_topo_record_at_anchor_eq_id') and lw.get('reached_anchor') and lw.get('fork_block_major_version') == 3
             and lw.get('fork_id_prefix_v3_fingerprint')),
        [{'class': 'RAW', 'what': f"live topo records sha256 {A.get('live_topo_records_sha256', 'missing')[:16]}; "
                                  f"{lw.get('steps')} tips steps from height 7,504,640 to the anchor; fork block major {lw.get('fork_block_major_version')}"},
         {'class': 'EXT', 'what': 'raw/sources.json: 6 archival sources report v3 at 7,504,640 (corroboration only)'}],
        ['V-EMISSION', 'V-HF3-ALL'])
    add('A2', "the table's Height is the inclusion height (B82)", 'rft §0.8.5; B82; derived/tx/*.json table_semantics',
        "own carrier census over the RAW chain (every block's tx list from this decoder): for each of the 75 TXIDs the "
        'earliest carrier height equals the table Height; Bl_Tips is that carrier\'s sole tip, or the carrier itself',
        H['height_is_earliest_carrier'] == 75 and H['bl_tips_is_tip_of_earliest'] + H['bl_tips_is_earliest_itself'] == 75,
        [{'class': 'DERIVED', 'what': f"Height == earliest carrier height {H['height_is_earliest_carrier']}/75; Bl_Tips == its tip "
                                      f"{H['bl_tips_is_tip_of_earliest']}/75, == the carrier itself {H['bl_tips_is_earliest_itself']}/75; "
                                      f"tx.BLID == Bl_Tips {H['ref_blid_eq_bl_tips']}/75; dual carriers {H['dual']}, single {H['single']}, "
                                      f"carrier gaps {H['carrier_gap_heights']} heights"},
         {'class': 'SRC', 'what': f"blockchain/hardfork_fixes.go sha256 {T['sha256'][:16]} (= manifest: {T['sha256_eq_manifest']}), "
                                  f"{T['entries']} entries, groups {T['groups']}"}],
        ['V-HF3-ALL'], note='Height is the inclusion height of the EARLIEST carrier; for dual-carrier TXIDs the later carrier '
                            'is 1-6 heights after it.')
    add('A2b', 'for aa0faf67 the table Bl_Tips is the carrier block itself, not its tip', 'acquire/extract open item',
        'same census, this TXID only; consequence checked: its carrier\'s tips list differs from [Bl_Tips], so the nonce '
        'bypass key of transaction_verify.go:234-237 does not match at that carrier (full nonce check :98-196)',
        aa == ['aa0faf67a2856ee30ed4e275c1079d1572b1bcb03d4a9ca682bd825e11d81a43'] and
        per[aa[0]]['carriers'][0]['nonce_bypass'] is False if aa else False,
        [{'class': 'DERIVED', 'what': f"TXIDs whose Bl_Tips is the carrier itself: {[t[:8] for t in aa]}"}], ['V-HF3-ALL'])
    add('A3', "a file's name is its id (content addressing)", 'rft §0.8.5; raw/blobs, tier B store, archive block files',
        'every tier A file and every tier B store file hashed (SHA-256 == name); every block blob SHA3-256 (own Keccak) == '
        'the id it is reached by; every replaywall block file (APFS clone) SHA3-256 == the id in its name',
        not B['content_address_failures'] and not B['undecodable'] and B['tierB_index_eq_manifest'] is True and
        X.get('block_file_name_eq_sha3') == X.get('block_files'),
        [{'class': 'RAW', 'what': f"tier A {B['tierA_files']} files ({B['tierA_blocks']} blocks, {B['tierA_txs']} txs), tier B {B['tierB_files']} "
                                  f"files, 0 content-address failures; store index {str(B['tierB_index_sha256'])[:16]} == manifest"},
         {'class': 'RAW', 'what': f"replaywall block files {X.get('block_files')}: name == SHA3-256 {X.get('block_file_name_eq_sha3')}"}],
        ['V-EMISSION', 'V-HF3-ALL'])
    add('A4a', 'the exemption skips proof verification for these bodies under the pinned code',
        'derived/tx/*.json exception_path.proof_verification',
        'code anchors at the pinned commit (18 lines, text present); the body field tx.Height < MAJOR_HF3_HEIGHT '
        '(cache key = TXID, transaction_verify.go:433-436) for every body; every carrier below HF3; the RAW-checkable '
        'statement sanity rules (payload count, base payload, roothash equality, ring size, distinct pointers, burn) pass, '
        'so the path reaches :438 unless the state-dependent checks (:327-431) fail, which needs the ring state',
        all(x['present'] for x in R['code_anchors']) and H['tx_height_below_hf3'] == 75 and H['proof_skip_carriers'] == H['carriers']
        and H['sanity_rawcheckable_pass'] == 75,
        [{'class': 'SRC', 'what': f"{sum(x['present'] for x in R['code_anchors'])}/{len(R['code_anchors'])} code anchors present"},
         {'class': 'DERIVED', 'what': f"tx.Height < {R['constants']['MAJOR_HF3_HEIGHT']}: {H['tx_height_below_hf3']}/75; skip on "
                                      f"{H['proof_skip_carriers']}/{H['carriers']} carriers; sanity {H['sanity_rawcheckable_pass']}/75"}],
        ['V-HF3-ALL'], note='A code-path classification (INTERPRETATION of SRC + RAW): what a node running the pinned code '
                            'does. It is not a record of what any node did when the blocks were first accepted (A4b).')
    hist_claims = C['grades']['claims_chain_accepted_only_through_exemption']
    a4b_claim = ('the chain accepted the tx only through the exemption (0045a6d4)' if hist_claims else
                 'no derived grade asserts how the network first accepted a table tx (the A4b wording "the chain accepted '
                 'the tx only through the exemption", overturned by audit-1, was corrected at its source, derive.py; '
                 f"{hist_claims} grade(s) still carry it)")
    add('A4b', a4b_claim, 'derived/grades.json and derived/tx/0045a6d4….json '
        'grade.deciding_fact_missing',
        'for every TXID, the first git commit that adds it to blockchain/hardfork_fixes.go (git log -S) against the '
        'timestamp of its earliest RAW carrier: the claim needs the table to exist when the network accepted the block',
        hist_claims == 0 or H['carrier_before_table_commit'] < H['table_commit_known'],
        [{'class': 'DERIVED', 'what': f"earliest carrier precedes the first table commit for {H['carrier_before_table_commit']}/"
                                      f"{H['table_commit_known']} TXIDs (minimum margin {H.get('min_margin_hours')} h); first commits "
                                      f"{H['first_table_commits']}"},
         {'class': 'EXT', 'what': f"git author dates and miner-set block timestamps are claims of time; the {H.get('min_margin_hours')} h "
                                  'minimum margin is far above any timestamp tolerance'}],
        ['V-HF3-0045a6d4'], note=('Overturned wording. Supported reading: "a node running the pinned code accepts it only '
                                  'through the exemption (today\'s verifier rejects the proof)". How the network accepted these '
                                  'blocks in 2026-08 is not determined by this dataset.' if hist_claims else
                                  'Overturned in audit-1 (audit/history/audit-1); the derived wording now states only what '
                                  'A4a (code path under the pinned code) and A11 (verifier re-run) support. The test is '
                                  'unchanged: the claim would FAIL again if any grade reintroduced it.'))
    add('A5', 'topo == height in every window row (topo_ext was EXT)', 'raw/headerchain.jsonl.gz topo_ext; derived/window.jsonl.gz topo',
        'own tips walk from the anchor (topo 7,498,540 by our live topo record): single-tip chain, heights contiguous, so '
        'each block\'s topo is DERIVED as anchor topo minus its step count, independent of the sources',
        W['ok'] and W['contiguous_heights'] and W['multi_tip_blocks'] == 0 and W['topo_eq_height_derived'] and not C['window_mismatch'].get('topo'),
        [{'class': 'DERIVED', 'what': f"{W['blocks_reached']} blocks walked {W['top_height']}..{W['bottom_height']}, multi-tip "
                                      f"{W['multi_tip_blocks']}, contiguous {W['contiguous_heights']}"}], ['V-EMISSION'])
    add('A6', 'the window is complete: 82,477 of 82,477 heights RAW with checks (i)-(ii)', 'acquire verdict',
        'own walk covers every window height; no blob in the store is left unreached; check (i) by own SHA3',
        W['window_heights_reached'] == W['window_heights_total'] == 82477 and W['blocks_not_reached'] == 0,
        [{'class': 'RAW', 'what': f"window heights reached {W['window_heights_reached']}/{W['window_heights_total']}; unreached "
                                  f"blocks {W['blocks_not_reached']}"}], ['V-EMISSION'])
    add('A7', 'each of the 94 TXIDs recomputes, and sits in a verified block (check iii)', 'extract verdict (Python Keccak over Go-emitted core bytes)',
        "own Keccak-256 over the core statement sliced from the RAW body bytes by this decoder (not re-serialized), the "
        'body parsed to its last byte (proof lengths from the ring size), and the TXID found in a walked block',
        R['txs']['bodies'] == 94 and R['txs']['txid_in_verified_block'] == 94 and all(r.get('txid_recomputed_eq') for r in per.values()),
        [{'class': 'DERIVED', 'what': f"{R['txs']['bodies']} bodies, TXID in a verified block {R['txs']['txid_in_verified_block']}; "
                                      'the wire bytes are canonical (raw-slice hash == node TXID)'}], ['V-HF3-ALL'])
    add('A8', 'window emission = CalcSupply(7,497,943) - CalcSupply(7,415,466) = 2,536,167,750 atomic', 'derived/emission.json',
        'constants and formulas read from config.go, supply.go, transaction_execute.go (text-matched); per-block reward '
        'and supply step recomputed for 82,477 heights', E['reward_sum_eq_supply_delta'] and E['supply_step_eq_reward'] == 82477
        and R['constants']['formulas_match_source'] and C['emission']['window_emission_eq'],
        [{'class': 'DERIVED', 'what': f"reward values {E['reward_values']}, sum {E['reward_sum']}, CalcSupply delta {E['calc_supply_delta']}"},
         {'class': 'SRC', 'what': 'blockchain/supply.go:5-27, blockchain/transaction_execute.go:44-45,60-62, config/config.go:34,61'}],
        ['V-EMISSION'], note='The identity is true by construction (CalcSupply sums CalcBlockReward), so alone it shows only '
                             'that the reward schedule is flat across the window. The informative public checks are A8b.')
    add('A8b', 'the formula coinbase pays out exactly base + fees in every window block', 'audit (strengthens V-EMISSION)',
        'own decode of every block: the miner tx is COINBASE with no value field, exactly one Final miniblock, and the '
        'payout rule of transaction_execute.go:126-160 (integrator share + leftover, share per non-final miniblock) sums to '
        'base + fees; the identity is linear in the fee, so it holds also where fees are pending',
        E['coinbase_type_ok'] == E['miner_value_field_absent'] == E['exactly_one_final_miniblock'] == E['distribution_identity_ok'] == 82477,
        [{'class': 'RAW', 'what': f"COINBASE {E['coinbase_type_ok']}, no value field {E['miner_value_field_absent']}, one final miniblock "
                                  f"{E['exactly_one_final_miniblock']}, payout identity {E['distribution_identity_ok']} of {E['blocks']}"}],
        ['V-EMISSION'])
    add('A8c', 'fees: known for 80,902 blocks (16,800 atomic), pending for 1,575', 'derived/emission.json fees',
        'own Fees() (zero-SCID payload fees) over the held bodies; a block with any body missing is pending',
        C['emission']['fees_known_blocks_eq'] and C['emission']['fees_known_sum_eq'] and C['emission']['fees_pending_eq'],
        [{'class': 'DERIVED', 'what': f"known {E['fees_known_blocks']} blocks sum {E['fees_known_sum']}, pending {E['fees_pending_blocks']}; "
                                      f"our archive holds bodies that would settle {AW.get('fills_pending_fee_blocks', 'pending')} of the pending blocks"}],
        ['V-EMISSION'])
    add('A9', "no window block fills the header 'Proof' field (B83)", 'acquire/extract census',
        'own decode of the 32-byte field after the miner tx in every walked block', E['proof_field_nonzero'] == 0,
        [{'class': 'RAW', 'what': f"non-zero Proof field in {E['proof_field_nonzero']} of {E['blocks']} window blocks"}], ['V-STATE-ROOTS'])
    rs = X.get('ref_state', {})
    add('A10a', 'the held archive state is the state the 2 decided txs were built against', 'extract open item',
        "own copy of the replaywall topo records: the record at each tx's ref height is the tx's BLID; the verifier's root "
        "at that state version equals the tx's own Statement.Roothash (RAW, inside the TXID)",
        all(v.get('archive_record_eq_ref_blid') for v in rs.values()) and len(rs) == 2 and
        all(pr.get(k, {}).get('state_root') == v.get('roothash') for k, v in rs.items()),
        [{'class': 'RAW', 'what': f"{k}: ref height {v.get('ref_height')} state version {v.get('state_version')} roothash {str(v.get('roothash'))[:16]}"}
         for k, v in sorted(rs.items())], ['V-HF3-0045a6d4', 'V-HF3-414f79b8'])
    add('A10b', 'no archive state root contradicts a RAW witness', 'derived/state_roots.json held (14,226 topos)',
        'every tx body our archive holds (210): TXID from its bytes, in a RAW-chain block, ref block on the RAW chain, and '
        "its Statement.Roothash compared with the builder's archive root at the ref topo",
        AW.get('roothash_ne_claimed_root') == 0 and AW.get('roothash_eq_claimed_root', 0) > 0,
        [{'class': 'RAW', 'what': f"{AW.get('bodies')} archive bodies, TXID == name {AW.get('txid_eq_name')}, in RAW blocks "
                                  f"{AW.get('in_raw_chain_block')}; roothash == claimed root {AW.get('roothash_eq_claimed_root')}, "
                                  f"!= {AW.get('roothash_ne_claimed_root')}; distinct topos witnessed {AW.get('distinct_ref_topos_witnessed')}"}],
        ['V-STATE-ROOTS'])
    add('A10c', 'the 14,226 archive roots are the canonical state roots of those topos', 'reading of derived/state_roots.json held',
        'needs either a witness per topo or an end-state check that binds the archive\'s fastsync base (topo 7,453,290); '
        'witnessed topos counted (A10b), end-state check not run (R26, (a2))', False,
        [{'class': 'DERIVED', 'what': f"witnessed {AW.get('distinct_ref_topos_witnessed')} of 14,226 topos; base tree from a fastsync "
                                      'bootstrap (its source unverified), no end-state check'}],
        ['V-STATE-ROOTS'], unresolved=True, note='The builder labels these roots "not end-state-checked"; this row keeps that '
                                                  'label binding: they are not shown as canonical roots (V-STATE-ROOTS -> pending).')
    pass_ok = pr.get('414f79b8', {}).get('verdict') == 'pass'
    fail_ok = pr.get('0045a6d4', {}).get('verdict') == 'fail:proof_verify'
    add('A11', "today's verifier: 414f79b8 PASS, 0045a6d4 FAIL at a named proof check", 'derived/archive_state/proof_checks.jsonl',
        "re-run of the node's own verifier (tools/forensics verify, pinned binary sha256 = manifest decoder pin) on an "
        "independent APFS clone of the replaywall balances, HF3 cache not used",
        pass_ok and fail_ok and C['proof_checks_claimed'].get('414f79b8', {}).get('result') == 'pass'
        and C['proof_checks_claimed'].get('0045a6d4', {}).get('result') == 'fail',
        [{'class': 'DERIVED', 'what': f"414f79b8 {pr.get('414f79b8', {}).get('verdict')}; 0045a6d4 {pr.get('0045a6d4', {}).get('verdict')} "
                                      f"({pr.get('0045a6d4', {}).get('failed_check', 'missing')}); single implementation (the node's verifier)"}],
        ['V-HF3-0045a6d4', 'V-HF3-414f79b8'], note='Single implementation by design (rft §0.8.5): no second proof verifier exists here.')
    add('A12', 'exception-path counts: nonce bypassed on 74 carriers, full on 68, parity override changes execution on 73 of 142',
        'derived/tx/*.json carriers[].exception_path',
        "own rule evaluation: bypass iff the carrier's tips == [Bl_Tips] (transaction_verify.go:90-96, :234-237); override "
        "= (carrier height > Height) == Tx_Parity (hf3_parity.go:77) against the natural parity read from the raw proof "
        "bytes (Proof.Parity(): f[0] == 0, proof_generate.go:76-82; transaction_execute.go:213, :243-246)",
        H['nonce_bypass_carriers'] == 74 and H['nonce_full_carriers'] == 68 and H['parity_changes_carriers'] == 73
        and H['carriers'] == 142 and not C['hf3_mismatch'],
        [{'class': 'DERIVED', 'what': f"bypass {H['nonce_bypass_carriers']}, full {H['nonce_full_carriers']}, parity changes "
                                      f"{H['parity_changes_carriers']}/{H['carriers']}; builder records compared field by field: "
                                      f"{C['hf3_carrier_rows_compared']} carrier rows, mismatches {C['hf3_mismatch'] or 0}"}], ['V-HF3-ALL'])
    add('A13', 'the 75 bodies carry no public value (burn 0, no value field)', 'derived/grades.json public_fields',
        'own decode: tx type, value field, burn values, fees', H['public_value_nonzero'] == 0 and H['types'] == {'NORMAL': 75},
        [{'class': 'RAW', 'what': f"types {H['types']}; bodies with public value {H['public_value_nonzero']}"}], ['V-HF3-ALL'])
    add('A14', 'the builder\'s 82,477 window rows equal an independent re-derivation', 'derived/window.jsonl.gz, raw/headerchain.jsonl.gz',
        'field by field: id, SHA-256, topo, tips, tx list, miniblocks/final, base reward, supply before/after, timestamp, '
        'Proof field, fees (or pending), headerchain id and SHA-256', not C['window_mismatch'] and C['window_rows_compared'] == 82477,
        [{'class': 'DERIVED', 'what': f"rows compared {C['window_rows_compared']}, mismatches {C['window_mismatch'] or 0}"}], ['V-EMISSION'])
    add('A15', 'tier B counts: 83,077 blocks (window + 599 link + anchor), 1,726 tx-bearing window blocks with 1,835 txs, store 83,171 objects',
        'acquire counts', 'own census of the store and the walk', B['tierB_blocks'] == 83077 and B['tierB_files'] == 83171 and
        E['tx_bearing_blocks'] == 1726 and E['txs'] == 1835,
        [{'class': 'RAW', 'what': f"store blocks {B['tierB_blocks']}, txs {B['tierB_txs']}, files {B['tierB_files']}; tx-bearing "
                                  f"{E['tx_bearing_blocks']}, txs {E['txs']}"}], ['V-EMISSION'])
    add('A16', 'the archive files above its last committed topo (incl. fdb50de0 at 7,467,516) are off the RAW chain', 'extract (disc:131)',
        'own copy of the replaywall store: files above the last committed height checked against the walked chain',
        X.get('files_above_last_committed') == 406 and X.get('files_above_last_committed_on_raw_chain') == 0
        and X.get('records_eq_raw_chain') == 14226 and X.get('on_chain_bytes_eq_raw') == 14226,
        [{'class': 'RAW', 'what': f"committed records {X.get('committed_records')} == RAW chain {X.get('records_eq_raw_chain')}, bytes equal "
                                  f"{X.get('on_chain_bytes_eq_raw')}; files above {X.get('files_above_last_committed')}, on chain "
                                  f"{X.get('files_above_last_committed_on_raw_chain')}"}], ['V-HF3-ALL'])
    add('A17', 'EXT fields (reward_ext, topo_ext, treehash_ext) are never used as evidence', 'raw/headerchain.jsonl.gz, raw/a2_feasibility.json',
        'every check above re-derives topo, reward and roots without them; reward_ext compared only as a claim',
        not C['window_mismatch'].get('reward_ext_ne_formula (EXT)'),
        [{'class': 'DERIVED', 'what': 'topo from the walk (A5), reward from the formula (A8); reward_ext == formula on every row (EXT agrees)'}],
        ['V-EMISSION'])
    add('A18', 'NOT-DECIDABLE-FROM-PUBLIC-DATA is the right grade for all 75 HF3 TXIDs', 'derived/grades.json',
        'a PROVEN-INFLATION grade would need a failing public-value identity: none fails (A8b, A13); a PROVEN-NO-INFLATION '
        'grade would need the hidden amounts: they are ElGamal ciphertexts and 73 proofs cannot be re-run (no state), '
        'the 2 that can leave the amount hidden; no grade rests on EXT', H['public_value_nonzero'] == 0 and
        C['grades']['grades'] == ['NOT-DECIDABLE-FROM-PUBLIC-DATA'],
        [{'class': 'DERIVED', 'what': 'A8b, A12, A13; grade per TXID with checked items and the missing fact'}], ['V-HF3-ALL'])
    add('A19', 'the dataset text holds no exploit content and no private information', 'rft §0.8.1 rules 6-7',
        f"{R['scan']['patterns']} patterns (the G24 exploit lint of disclosure_track.py plus privacy regexes) and "
        f"{R['scan']['private_terms_loaded']} private terms (read at run time, never stored) over {R['scan']['files_scanned']} text files",
        not R['scan']['hits'], [{'class': 'DERIVED', 'what': f"hits {len(R['scan']['hits'])}"}], ['V-HF3-ALL', 'V-EMISSION'])
    return ch


def build_verdicts(ch):
    by = {c['id']: c for c in ch}

    def chs(v):
        return sorted(c['id'] for c in ch if v in c['affects'] or ('V-HF3-ALL' in c['affects'] and v.startswith('V-HF3-')))
    bad = lambda ids: [i for i in ids if by[i]['result'] != 'HOLDS']
    vs = []
    em_ch = chs('V-EMISSION')
    vs.append({'id': 'V-EMISSION', 'question': 'was value created beyond the emission formula by the window\'s coinbase?',
               'builder_grade': 'PROVEN-NO-INFLATION-IN-SCOPE', 'source': 'derived/emission.json',
               'audit_grade': 'PROVEN-NO-INFLATION-IN-SCOPE' if not bad(em_ch) else 'NOT-DECIDABLE-FROM-PUBLIC-DATA',
               'scope': ('the formula coinbase of the 82,477 window blocks 7,415,466..7,497,942 and its payout: each block has one '
                         'COINBASE miner tx with no value field, exactly one Final miniblock, a payout equal to base + fees, and '
                         'base rewards summing to CalcSupply(7,497,943) - CalcSupply(7,415,466). Says nothing about hidden '
                         '(encrypted) amounts, the fee deductions inside them, or burns/SC payouts of the 1,575 blocks whose '
                         'bodies are pending'),
               'inputs': [{'class': 'RAW', 'what': '82,477 window blocks, checks (i)-(ii) by the audit'},
                          {'class': 'DERIVED', 'what': 'coinbase type, value field, final-miniblock and payout census (A8b)'},
                          {'class': 'DERIVED', 'what': 'reward per block and the CalcSupply identity from the source constants (A8)'}],
               'rules': ['blockchain/transaction_execute.go:60-62,126-160', 'blockchain/supply.go:5-27'],
               'challenges': em_ch})
    return vs, chs


def audit_history(ds):
    """Earlier audit runs of this dataset version, kept unchanged under audit/history/<run>/ (never rewritten): their
    binding, counts, overturned / unresolved ids and claim corrections, so an overturn stays on record after the
    builder fixes the claim at its source."""
    out = []
    hd = Path(ds) / 'audit' / 'history'
    for d in sorted(p for p in hd.iterdir() if p.is_dir()) if hd.exists() else []:
        rp, cp = d / 'audit_report.json', d / 'challenges.json'
        if not rp.exists() or not cp.exists():
            continue
        r, c = json.loads(rp.read_text()), json.loads(cp.read_text())
        out.append({'run': d.name, 'binding': r.get('binding', {}), 'counts': r.get('counts', {}),
                    'report_sha256': hashlib.sha256(rp.read_bytes()).hexdigest(),
                    'overturned': sorted(x['id'] for x in c.get('challenges', []) if x.get('result') == 'FAILS'),
                    'unresolved': sorted(x['id'] for x in c.get('challenges', []) if x.get('result') == 'UNRESOLVED'),
                    'claim_corrections': {v['id']: v['claim_corrections'] for v in r.get('verdicts', [])
                                          if v.get('claim_corrections')}})
    return out


def build_report(R, proof, ds):
    ch = build_challenges(R, proof)
    vs, chs = build_verdicts(ch)
    by = {c['id']: c for c in ch}
    for txid, r in sorted(R['hf3_per_txid'].items()):
        vid = 'V-HF3-' + txid[:8]
        ids = chs(vid)
        notes = [by[i]['note'] for i in ids if by[i]['result'] != 'HOLDS' and by[i]['note']]
        vs.append({'id': vid, 'txid': txid, 'question': 'did this tx create value beyond the emission formula?',
                   'builder_grade': 'NOT-DECIDABLE-FROM-PUBLIC-DATA', 'source': f'derived/tx/{txid}.json grade',
                   'audit_grade': 'NOT-DECIDABLE-FROM-PUBLIC-DATA',
                   'deciding_fact_missing': ('the hidden (ElGamal) amounts; a proof result cannot settle them (C1, rft §0.5)'
                                             if txid[:8] in ('414f79b8', '0045a6d4') else
                                             'the ring state at the reference block (proof not re-runnable) and the hidden amounts'),
                   'inputs': [{'class': 'RAW', 'what': 'body and carriers (A3, A7)'}, {'class': 'DERIVED', 'what': 'exception path (A12), public fields (A13)'}],
                   'challenges': ids, 'claim_corrections': notes,
                   'downgraded': False, 'downgrade_note': ('already at NOT-DECIDABLE-FROM-PUBLIC-DATA; the failed claim is '
                                                           'corrected in claim_corrections' if notes else '')})
    sr = chs('V-STATE-ROOTS')
    vs.append({'id': 'V-STATE-ROOTS', 'question': 'what were the pre/post balance-tree roots of the window\'s blocks?',
               'builder_grade': 'held for 14,226 topos (DERIVED, not end-state-checked); 68,251 not reconstructable',
               'source': 'derived/state_roots.json', 'audit_grade': 'pending' if [i for i in sr if by[i]['result'] != 'HOLDS'] else 'NOT-DECIDABLE-FROM-PUBLIC-DATA',
               'inputs': [{'class': 'DERIVED', 'what': 'archive roots (our replaywall store), witnessed at the topos of A10b'}],
               'challenges': sr, 'downgraded': bool([i for i in sr if by[i]['result'] != 'HOLDS']),
               'downgrade_note': ('pending: the 14,226 roots are shown as the archive node\'s own roots (DERIVED from an unverified '
                                  'fastsync base), witnessed by RAW Statement.Roothash at the A10b topos only, until the R26 '
                                  'end-state check')})
    for vid, fig in (('V-EXT-23886517', '23,886,517.3 DERO'), ('V-EXT-5000000', '5,000,000 DERO')):
        vs.append({'id': vid, 'question': f'the external figure {fig} (Foundation disclosure)', 'builder_grade': 'not graded (not_in_scope)',
                   'source': 'derived/emission.json not_in_scope', 'audit_grade': 'SPECULATION',
                   'inputs': [{'class': 'EXT', 'what': f'{fig}: press/disclosure claim'}],
                   'reason': 'EXT only: no RAW or DERIVED input in this dataset reproduces or refutes it (rft §0.8.2)',
                   'challenges': [], 'downgraded': False})
    n_fail = sum(c['result'] == 'FAILS' for c in ch)
    n_open = sum(c['result'] == 'UNRESOLVED' for c in ch)
    rerun = {k: R[k] for k in sorted(R) if k != 'hf3_per_txid'}
    rerun['hf3_per_txid_sha256'] = hashlib.sha256(json.dumps(R['hf3_per_txid'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    proof_rows = [{'txid': o['txid'], 'verdict': o.get('verdict'), 'failed_check': o.get('failed_check') or 'not applicable: passed',
                   'state_root': o.get('state_root'), 'checks': [(c['name'], c['result']) for c in o.get('checks', [])]}
                  for o in sorted(proof, key=lambda x: x['txid'])]
    rep = {'dataset': R['dataset'], 'binding': R['binding'],
           'implementation': {'name': IMPL_VERSION, 'file': 'harness/forensics/audit_check.py', 'shares_code_with_builder': False,
                              'own': ['Keccak-f[1600] (constants generated from FIPS 202)', 'block/tx/miniblock/statement/proof-length decoders',
                                      'HF3 table parser', 'emission constants and CalcSupply', 'tips walk', 'exception-path rules'],
                              'reused': ["the node's own proof verifier (tools/forensics verify) for A11 only, by design (rft §0.8.5)"]},
           'inputs_outside_dataset': {'tierB_store_index_sha256': R['blobs']['tierB_index_sha256'],
                                      'live_topo_records_sha256': R['anchor'].get('live_topo_records_sha256'),
                                      'live_blocks_index_sha256': R['anchor'].get('live_blocks_index_sha256'),
                                      'archive_topo_records_sha256': R.get('archive', {}).get('topo_records_sha256'),
                                      'note': 'APFS clones/copies in the scratchpad of our own live node and replaywall archive; '
                                              'read-only, never in place; not in the dataset (paths withheld)'},
           'counts': {'challenges': len(ch), 'holds': sum(c['result'] == 'HOLDS' for c in ch), 'overturned': n_fail,
                      'unresolved': n_open, 'verdicts': len(vs), 'downgraded': sum(bool(v.get('downgraded')) for v in vs),
                      'claims_corrected': sum(bool(v.get('claim_corrections')) for v in vs)},
           'verdicts': vs, 'proof_rerun': proof_rows, 'rerun': rerun}
    rep['rerun_sha256'] = hashlib.sha256(json.dumps(rerun, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    rep['history'] = audit_history(ds)
    rep['counts']['overturned_all_runs'] = n_fail + sum(h['counts'].get('overturned', 0) for h in rep['history'])
    for h in rep['history']:
        for vid, notes in h['claim_corrections'].items():
            for v in vs:
                if v['id'] == vid:
                    v.setdefault('correction_history', []).append(f"{h['run']}: {'; '.join(notes)} (corrected at source)")
    return rep, {'note': 'independent audit challenges (rft §0.8.5): result HOLDS / FAILS / UNRESOLVED; any FAILS or UNRESOLVED '
                         'downgrades or corrects the verdicts it affects (audit_report.json verdicts)',
                 'binding': R['binding'], 'challenges': ch}


def render_md(rep, chj):
    c = rep['counts']
    L = ['# Independent audit of forensics/' + rep['dataset'], '',
         f"Auditor: a second implementation (`{rep['implementation']['name']}`, `harness/forensics/audit_check.py`) that shares "
         'no code with the builder. Refute by default (rft §0.8.5).', '',
         f"Bound to the dataset data `{rep['binding']['data_sha256']}` ({rep['binding']['files_bound']} files outside audit/), audited "
         f"from manifest `{rep['binding']['manifest_sha256_at_audit']}`. Rerun block SHA-256 `{rep['rerun_sha256']}`.", '',
         f"**Result: {c['challenges']} challenges, {c['holds']} HOLD, {c['overturned']} FAIL (overturned), {c['unresolved']} UNRESOLVED; "
         f"{c['downgraded']} verdict downgraded, {c['claims_corrected']} claim corrected.**", '',
         '## What was re-run from raw/', '',
         'Every tier A file and tier B store object was hashed. Each blob was decoded by this implementation as a block or a tx. '
         'Block ids are SHA3-256 under our own Keccak. The tips walk runs from our anchor. TXIDs are Keccak-256 of the core '
         'statement, sliced from the raw bytes. Emission comes from the source constants. The exception-path rules are '
         'evaluated against the RAW chain. The archive was checked through our own copies. Only after all of that were the '
         "builder's derived/ files read, as claims to compare.", '',
         '## Challenges', '', '| id | claim | result | evidence |', '|---|---|---|---|']
    for ch in chj['challenges']:
        ev = '; '.join(f"{e['class']}: {e['what']}" for e in ch['evidence'])
        L.append(f"| {ch['id']} | {ch['claim']} | **{ch['result']}** | {ev.replace('|', '/')} |")
    L += ['', '## Overturned and unresolved', '']
    for ch in chj['challenges']:
        if ch['result'] != 'HOLDS':
            L.append(f"- **{ch['id']} {ch['result']}**: {ch['claim']}. Test: {ch['test']}. {ch['note']} Affects: {', '.join(ch['affects'])}.")
    if rep.get('history'):
        L += ['', '## Audit history (earlier runs, kept unchanged under audit/history/)', '']
        for h in rep['history']:
            hc = h['counts']
            L.append(f"- **{h['run']}** (manifest `{h['binding'].get('manifest_sha256_at_audit', '?')[:16]}…`, report "
                     f"`{h['report_sha256'][:16]}…`): {hc.get('challenges')} challenges, {hc.get('holds')} HOLD, "
                     f"{hc.get('overturned')} FAIL (overturned: {', '.join(h['overturned']) or 'none'}), "
                     f"{hc.get('unresolved')} UNRESOLVED ({', '.join(h['unresolved']) or 'none'}).")
        L.append(f"- Overturns over all runs of this version: {c.get('overturned_all_runs')}.")
    L += ['', '## Verdicts after the audit', '', '| verdict | builder | audit | note |', '|---|---|---|---|']
    grades = {}
    for v in rep['verdicts']:
        if v['id'].startswith('V-HF3-'):
            grades[v['audit_grade']] = grades.get(v['audit_grade'], 0) + 1
            if not v.get('claim_corrections') and not v.get('correction_history'):
                continue
        note = (v.get('downgrade_note') or v.get('reason') or ('; '.join(v.get('claim_corrections', []))) or
                '; '.join(v.get('correction_history', [])))
        L.append(f"| {v['id']} | {v['builder_grade']} | **{v['audit_grade']}** | {note} |")
    L.append(f"| V-HF3-* (75 TXIDs) | NOT-DECIDABLE-FROM-PUBLIC-DATA | **{', '.join(f'{k} {n}' for k, n in grades.items())}** | per TXID in audit_report.json |")
    em = [v for v in rep['verdicts'] if v['id'] == 'V-EMISSION'][0]
    L += ['', f"Scope of V-EMISSION: {em['scope']}.", '', '## Proof re-run (single implementation: the node verifier)', '']
    for p in rep['proof_rerun']:
        L.append(f"- `{p['txid'][:16]}…`: {p['verdict']}" + (f" (check: {p['failed_check']})" if p['verdict'] != 'pass' else ''))
    L += ['', 'Only the pass/fail result and the name of the failed check are recorded (rft §0.8.1 rule 6).', '',
          '## Limits', '',
          '- The proof results come from one implementation, the node\'s verifier. No second verifier exists here.',
          '- Archive roots are witnessed only where an archive tx body points at them (A10b). Binding all of them needs the R26 end-state check.',
          '- Hidden amounts are ElGamal ciphertexts. No grade here says anything about them.', '']
    return '\n'.join(L)


# =============================================================================================== CLI
def _cli():
    import argparse
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run')
    r.add_argument('dataset'); r.add_argument('--store'); r.add_argument('--archive'); r.add_argument('--live')
    r.add_argument('--private'); r.add_argument('--jobs', type=int, default=1); r.add_argument('--out', required=True)
    g = sub.add_parser('g29'); g.add_argument('repo', nargs='?', default=str(ROOT))
    b = sub.add_parser('build'); b.add_argument('dataset'); b.add_argument('--rerun', required=True); b.add_argument('--proof', required=True)
    sub.add_parser('selftest')
    a = ap.parse_args()
    if a.cmd == 'selftest':
        f = hash_selftest()
        print('selftest', 'PASS' if not f else 'FAIL: ' + '; '.join(f))
        return 0 if not f else 3
    if a.cmd == 'build':
        R = json.loads(Path(a.rerun).read_text())
        proof = [json.loads(l) for l in Path(a.proof).read_text().splitlines() if l.strip()]
        proof = [{k: o.get(k) for k in ('txid', 'verdict', 'state_root', 'checks')} | {'failed_check': next(
            (c.get('detail') for c in o.get('checks', []) if c.get('result') == 'fail'), None)} for o in proof]
        rep, chj = build_report(R, proof, Path(a.dataset))
        out = Path(a.dataset) / 'audit'
        out.mkdir(exist_ok=True)
        (out / 'audit_report.json').write_text(json.dumps(rep, indent=1, sort_keys=True) + '\n')
        (out / 'challenges.json').write_text(json.dumps(chj, indent=1, sort_keys=True) + '\n')
        (out / 'AUDIT.md').write_text(render_md(rep, chj))
        print('audit', rep['counts'])
        return 0
    if a.cmd == 'g29':
        ok, det = g29(a.repo)
        print('G29', 'PASS' if ok else 'FAIL', det)
        return 0 if ok else 3
    R = run_audit(a.dataset, ROOT, a.store, a.archive, a.live, a.private, a.jobs)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    txt = json.dumps(R, indent=1, sort_keys=True, default=sorted) + '\n'
    (out / 'audit_rerun.json').write_text(txt)
    print('audit_rerun', hashlib.sha256(txt.encode()).hexdigest())
    return 0


if __name__ == '__main__':
    sys.exit(_cli())
