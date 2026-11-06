#!/usr/bin/env python3
"""mine_forensics.py — the independent audit of the DERO Foundation's disclosure.

Input: model/forensics_in.json, written from the multi-agent audit run (dero-rangeproof-forensics). Each entry
is a finding that already survived three adversarial verifiers. This miner does NOT trust that: it re-resolves
every anchor against the tree before the row is written, and it enforces the two laws that keep the audit
honest —

  * a finding may not be proved ONLY by the document it audits (harness/external/**). At least one anchor must
    land in the source tree, the vendored code, or a runtime capture. KAT DK22 re-checks this on the page.
  * the verdict must be one of CONFIRMED / PARTLY-CONFIRMED / REFUTED / CANNOT-DETERMINE-LOCALLY.

Anything failing either law goes to `unverified` with the reason, never to `rows`.
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import minelib as M

IN = M.HARNESS / 'model/forensics_in.json'
VERDICTS = {'CONFIRMED', 'PARTLY-CONFIRMED', 'REFUTED', 'CANNOT-DETERMINE-LOCALLY'}
SEV = {'critical', 'high', 'medium', 'low', 'informational'}


def missing_input_plan(in_exists, raw_doc):
    """What to do when the audit input may be absent (verifier H7). forensics_in.json is git-excluded (it holds the
    audit transcript), so a clean clone has no input: overwriting raw/forensics.json with 0 rows shrank the page and
    failed G16. Returns ('mine', None) when the input exists; otherwise ('skip', reason) when a committed raw doc with
    rows can be kept, or ('empty', reason) when there is nothing to keep."""
    if in_exists:
        return 'mine', None
    n = len((raw_doc or {}).get('rows') or [])
    if n:
        return 'skip', (f'SKIP: {IN.name} is absent (git-excluded audit transcript); the committed '
                        f'raw/forensics.json ({n} rows) is kept unchanged')
    return 'empty', f'{IN.name} has not been written yet — the audit has not been merged'


def record_skip(key, why, path=None):
    """merge {key: {why, when}} into harness/loop/SKIPPED.json — the explicit, inspectable record of a skipped miner"""
    import datetime
    path = path or (M.HARNESS / 'loop/SKIPPED.json')
    try:
        doc = json.loads(path.read_text()) if path.exists() else {}
    except ValueError:
        doc = {}
    doc[key] = {'why': why, 'when': datetime.datetime.now().astimezone().isoformat(timespec='seconds')}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1, ensure_ascii=False))


def main():
    raw = M.RAW / 'forensics.json'
    try:
        raw_doc = json.loads(raw.read_text()) if raw.exists() else None
    except ValueError:
        raw_doc = None
    action, why = missing_input_plan(IN.exists(), raw_doc)
    if action == 'skip':
        # R20 (H7 follow-up): the committed raw file is left BYTE-identical. r19 wrote a 'skipped' key into it, which
        # dirtied a tracked file in every clean clone and contradicted "kept unchanged". The SKIP is recorded in the
        # run-state file loop/SKIPPED.json instead (not a page source, so the page fingerprint is unaffected).
        record_skip('forensics', why)
        print(f'forensics.json: {why}')
        return
    if action == 'empty':
        M.emit('forensics', [], [{'title': 'forensic audit', 'why': why}], 'mine_forensics.py')
        return
    doc = json.loads(IN.read_text())
    items = doc if isinstance(doc, list) else doc.get('findings') or []
    rows, unv = [], []
    for f in items:
        fid = str(f.get('id') or '').strip()
        v = str(f.get('verdict') or '').upper()
        title = f.get('title') or fid
        if v not in VERDICTS:
            unv.append({'title': title, 'why': f'verdict {v!r} is outside the permitted set {sorted(VERDICTS)}'})
            continue
        evs, lost = [], []
        for e in f.get('evidence') or []:
            a = M.anchor(e.get('file', ''), e.get('quote', ''), hint=e.get('line'), full_line=False)
            if a:
                evs.append(a)
            else:
                lost.append(f"{e.get('file')}:{e.get('line')} :: {str(e.get('quote'))[:60]}")
        if not evs:
            unv.append({'title': title, 'why': 'no anchor re-resolved against the tree: ' + '; '.join(lost[:3])})
            continue
        if all('harness/external/' in str(e['file']) for e in evs):
            unv.append({'title': title, 'why': 'proved only by the document it audits — a forensic conclusion '
                                               'needs an anchor in the tree, the vendored code or a capture'})
            continue
        rows.append({'id': f'fx-{fid}' if not fid.startswith('fx-') else fid, 'section': 'forensics',
                     'title': title, 'class': None,                      # derived from where the anchors point
                     'claim': f.get('claim') or '', 'reasoning': f.get('reasoning') or '',
                     'audit_verdict': v, 'press_claim': f.get('press_claim') or '—',
                     'severity': (f.get('severity') or 'informational') if (f.get('severity') or '') in SEV else 'informational',
                     'dimension': f.get('dimension') or '', 'votes': f.get('total_votes'),
                     'refuted_votes': f.get('refuted_votes'),
                     'dropped_anchors': lost, 'evidence': evs})
        if lost:
            unv.append({'title': f'{title} — partial', 'why': f'{len(lost)} of this finding’s anchors no '
                                                                   f'longer resolve and were dropped: {lost[:2]}'})
    M.emit('forensics', rows, unv, 'mine_forensics.py')


if __name__ == '__main__':
    main()
