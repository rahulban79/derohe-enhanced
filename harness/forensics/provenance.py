#!/usr/bin/env python3
"""R25 forensics provenance rules (artifacts/dero-rft.md §0.8.2, §0.8.4). Pure functions, no network, no I/O.

Every externally fetched byte is EXT until it passes the checks of §0.8.4; only then may it be labelled RAW:
  (i)   block: SHA3-256(blob) == the block id it was fetched as (and == the node decoder's id when one is given);
  (ii)  block: the block id is reached from one of OUR OWN anchors by following tips links through blocks that
        themselves passed (i);
  (iii) tx: the TXID recomputed from the body (node decoder, Keccak256 of the core statement) == the TXID asked for,
        AND that TXID is in the tx list of a block that passed (i) and (ii).
An object of our own store (archive copy / live node at or above prunedheight) is RAW on its own provenance only
after the same content check (i) or (iii-a); it is an anchor for (ii) only if it is listed in anchors.
KAT MF5 (harness/kat/test_forensics_r25.py) forges every failure and mutates every rule here.
"""
import hashlib

RAW, EXT = 'RAW', 'EXT'
BLOCK_CHECKS = ('i', 'ii')
TX_CHECKS = ('iii_txid', 'iii_in_block')


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def check_i(blob, claimed_id, decoder_id=None):
    """(i): SHA3-256 of the blob equals the claimed block id (and the node decoder's id, if supplied)."""
    if not isinstance(blob, (bytes, bytearray)) or not blob:
        return False, 'i: empty or non-bytes blob'
    got = hashlib.sha3_256(blob).hexdigest()
    if got != (claimed_id or '').lower():
        return False, f'i: sha3-256(blob) {got[:16]} != claimed id {(claimed_id or "")[:16]}'
    if decoder_id is not None and decoder_id.lower() != got:
        return False, f'i: decoder id {decoder_id[:16]} != sha3-256(blob) {got[:16]}'
    return True, 'i: ok'


def tips_walk(tips_of, anchors, passed_i):
    """(ii): ids reachable from anchors by tips links, stepping only through blocks that passed (i).

    tips_of: {block_id: [tip ids]}; anchors: ids of our own blocks; passed_i: ids whose (i) passed. An anchor that is
    not itself in tips_of still seeds the walk only if its tips are known (tips_of)."""
    reached, stack = set(), [a for a in anchors if a in tips_of]
    seen = set(stack)
    while stack:
        b = stack.pop()
        for t in tips_of.get(b, ()):
            if t in passed_i and t not in reached:
                reached.add(t)
            if t in passed_i and t not in seen:
                seen.add(t)
                stack.append(t)
    return reached


def check_iii(txid_asked, txid_recomputed, verified_block_txlists):
    """(iii): recomputed TXID == asked TXID, and it sits in the tx list of a block that passed (i) and (ii).

    verified_block_txlists: {block_id: [txids]} restricted by the CALLER to blocks that passed (i)+(ii)."""
    a = (txid_asked or '').lower()
    if not txid_recomputed or txid_recomputed.lower() != a:
        return {'iii_txid': False, 'iii_in_block': False}, f'iii: recomputed txid {str(txid_recomputed)[:16]} != {a[:16]}'
    carriers = sorted(b for b, l in verified_block_txlists.items() if a in l)
    if not carriers:
        return {'iii_txid': True, 'iii_in_block': False}, 'iii: txid in no verified block'
    return {'iii_txid': True, 'iii_in_block': True, 'carriers': carriers}, 'iii: ok'


def classify(kind, checks):
    """RAW only when every required check is literally True; anything else (missing, False, None) is EXT."""
    need = BLOCK_CHECKS if kind == 'block' else TX_CHECKS
    return RAW if all(checks.get(c) is True for c in need) else EXT


def provenance_problems(entries):
    """Validator over provenance entries: a RAW label needs every check True for its kind and a SHA-256."""
    bad = []
    for e in entries:
        if e.get('class') == RAW:
            need = BLOCK_CHECKS if e.get('kind') == 'block' else TX_CHECKS
            ch = e.get('checks') or {}
            miss = [c for c in need if ch.get(c) is not True]
            if miss:
                bad.append(f"{e.get('kind')}:{str(e.get('id'))[:16]} labelled RAW but check(s) {','.join(miss)} not passed")
            if not e.get('sha256'):
                bad.append(f"{e.get('kind')}:{str(e.get('id'))[:16]} labelled RAW without sha256")
        elif e.get('class') not in (EXT, RAW):
            bad.append(f"{e.get('kind')}:{str(e.get('id'))[:16]} has unknown class {e.get('class')!r}")
    return bad
