#!/usr/bin/env python3
"""mine_press.py — the DERO Foundation's published claims, as claims.

Each row anchors on the line of harness/external/derofoundation-press-20261020.txt that carries it, so its class
is EXT: **a line of this file proves only that the Foundation said it.** Whether it is TRUE is decided by the
forensics rows (model/raw/forensics.json), which anchor in the source tree and the chain instead. The two are
deliberately kept apart — conflating "they said it" with "it is so" is the failure this whole harness exists to
prevent.

The claim list is declared here with the exact substring that must still be on a line of the file; if the
document is re-fetched and a claim has been edited away, the row disappears and the change is visible.
"""
import re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import minelib as M

DOC = 'harness/external/derofoundation-press-20261020.txt'
SRC = 'https://derofoundation.co/#/press'

# id, short title, the verbatim substring that must be on a line, what the claim asserts
CLAIMS = [
 ('c1-soundness', 'A critical soundness failure in the transfer-proof path',
  'A critical cryptographic soundness failure exists in the transfer-proof verification path used by DEROHE.',
  'The headline claim: the proof system that guards every transfer is unsound.'),
 ('c2-transcript', 'The shared generator is not bound into the Fiat-Shamir transcript',
  'constructs its generator `u_x` as a multiple of the same base `H` used by the unbound blinding scalar',
  'The asserted mechanism, in the Foundation\u2019s own symbols: the IPA closing the 128-bit combined range '
  'proof builds its generator u_x on the same base H that the blinding scalar \u03bc uses; \u03bc is never in the '
  'transcript, so a prover can move \u03bc to cancel a discrepancy in the inner-product witness and leave the '
  'verification point P unchanged. This is the sentence the forensics must test.'),
 ('c3-knowledge', 'A knowledge-soundness break that ordinary testing could not surface',
  'This is a knowledge-soundness break in the component that was supposed to prevent undetectable inflation',
  'Asserts both the class of break and why it escaped: honest proofs still verify, so only an adversarial '
  'witness exposes it.'),
 ('c4-zether', 'The construction was inherited from ConsenSys Anonymous Zether',
  'The construction was inherited from the ConsenSys Anonymous Zether lineage.',
  'Attribution of lineage, with a pinned Solidity reference at ZetherVerifier.sol#L222-L230.'),
 ('c5-genesis', 'Exploitable from genesis of this proof path',
  'for value to be created or destroyed without detection by the range-proof gate',
  'Scope claim: the window is the entire life of the proof path, and the Foundation says it cannot determine '
  'how much, if any, such activity occurred.'),
 ('c6-created', 'Spendable coin created (floor): 23,886,517.3 DERO',
  'Spendable coin created (floor)',
  'A quantified claim about a SEPARATE defect — the double-spend closed by HF3 — stated as a floor because '
  'fourteen affected transactions cannot be decoded.'),
 ('c7-burned', 'Burned in the same era: 5,000,000 DERO',
  'Bound by consensus to coins that genuinely left a funded account. That these wallets paid it is not proven.',
  'The offsetting figure, with the Foundation itself marking the attribution as unproven.'),
 ('c8-hf3', 'Fixed by HF3 at 7,504,640',
  'Activated 21 August 2026. Node operators must run release 152 or later.',
  'The remedy and the operator instruction. This node crossed that height and runs 3.6.0-153.'),
 ('c9-endsupport', 'The Foundation is ending support for the current chain',
  'We are ending official support, maintenance, and endorsement of the current DERO mainnet',
  'Governance consequence: no rollback, no corrective hard fork, support withdrawn.'),
 ('c10-noaudit', 'No prior public audit identified the shared-generator seam',
  'no prior public audit or report identified the shared-generator seam',
  'A claim about the state of prior review — not verifiable from this tree, recorded so the page can say so.'),
 ('c11-undecodable', 'Fourteen affected transactions cannot be decoded',
  'Fourteen affected transactions cannot be decoded, so the figure understates by an unknown amount.',
  'The stated limit of the Foundation’s own forensics, and the reason the headline figure is a floor.'),
 ('c13-reported', 'The range-proof defect was reported after HF3 and after the 1 September statement',
  'The range-proof defect described here was reported to the Foundation weeks after HF3 addressed the separate',
  'Timeline claim that separates the two defects: HF3 fixed the transaction-duplication issue; the range-proof '
  'report came later, from a user credited as \u201cMoco\u201d.'),
 ('c14-adversarial', 'Only an adversarial witness reveals the failure',
  'Only an adversarial witness (out-of-range bits plus a compensating',
  'Explains why the defect is invisible to a test suite built from honest inputs \u2014 the same reason this '
  'harness gates on mutations rather than on passing tests.'),
 ('c12-checkable', 'The Foundation invites verification against a node',
  'Everything factual here is checkable against a node, and we would rather you checked it',
  'The standard the Foundation sets for itself, and therefore the standard this harness applies to it.'),
]


def main():
    rows, unv = [], []
    if not (M.ROOT / DOC).exists():
        M.emit('press', [], [{'title': 'press statement', 'why': f'{DOC} has not been retrieved'}], 'mine_press.py')
        return
    for cid, title, needle, what in CLAIMS:
        a = M.anchor(DOC, needle, full_line=True)
        if not a:
            unv.append({'title': title, 'why': f'this sentence is no longer on any line of {DOC} — the '
                                               f'statement may have been edited since it was retrieved: {needle[:70]}'})
            continue
        rows.append({'id': cid, 'section': 'press', 'title': title, 'class': 'EXT',
                     'claim': f'The DERO Foundation states: “{a["quote"][:400]}” {what}',
                     'said': a['quote'][:400], 'what': what, 'source': SRC,
                     'evidence': [a]})
    M.emit('press', rows, unv, 'mine_press.py')


if __name__ == '__main__':
    main()
