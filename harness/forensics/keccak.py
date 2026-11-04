#!/usr/bin/env python3
"""Pinned pure-Python Keccak-f[1600] sponge (rft §0.8.5, §0.8.8 MF6). Shares no code with Go or hashlib.

  keccak256(b)  legacy Keccak-256 (pad 0x01), as DERO's TXID: Keccak256(SerializeCoreStatement), transaction.go:195
  sha3_256(b)   FIPS-202 SHA3-256 (pad 0x06), as DERO's block id (block/block.go GetHash)

The KAT vectors live in harness/kat/test_forensics_r25.py (MF6); IMPL_VERSION changes whenever this file changes
behaviour, and the manifest pins this file by SHA-256.
"""
IMPL_VERSION = 'keccak-pure-py-1'

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
    0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _rol(v, n):
    n %= 64
    return ((v << n) | (v >> (64 - n))) & _M if n else v


def _f1600(A):
    for rc in _RC:
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol(C[(x + 1) % 5], 1) for x in range(5)]
        A = [[A[x][y] ^ D[x] for y in range(5)] for x in range(5)]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rol(A[x][y], _ROT[x][y])
        A = [[B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        A[0][0] ^= rc
    return A


def _sponge(data, rate, pad, outlen):
    data = bytes(data)
    msg = bytearray(data)
    msg.append(pad)
    while len(msg) % rate:
        msg.append(0)
    msg[-1] |= 0x80
    A = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        blk = msg[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            A[x][y] ^= int.from_bytes(blk[8 * i:8 * i + 8], 'little')
        A = _f1600(A)
    out = bytearray()
    while len(out) < outlen:
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            out += A[x][y].to_bytes(8, 'little')
        if len(out) < outlen:
            A = _f1600(A)
    return bytes(out[:outlen])


def keccak256(data):
    return _sponge(data, 136, 0x01, 32)


def sha3_256(data):
    return _sponge(data, 136, 0x06, 32)
