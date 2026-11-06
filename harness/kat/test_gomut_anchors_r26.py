#!/usr/bin/env python3
"""Known-answer test + mutation proof for the Go-mutation registry's anchors (harness/intel/go_mutations.json; R26
closed loop, pipeline_20261104T175125 S3b FAIL: 1327/1329 caught, 2 STALE).

The R26 node-net change B103 rewrote the "Miniblock refused" log call and B99 added a forgive step after
alt_track.note in p2p/consensus_obs_r25.go, so the find texts of gm-r25-consensus-refusal-peer-is-address and
gm-r25-consensus-accepted-block-not-tracked no longer occurred in the file. The merge checked duplicate ids only, and
the STALE spec surfaced 55 minutes into S3b. This KAT runs in S3k (before S3b) and fails on any such spec in seconds.

  GA1 every mutation in the registry names an existing file and its find text occurs exactly once there (go_mutate
      marks any other count STALE); ids are unique; find != replace.
  GA2 negative controls: a planted spec whose find text is gone, one whose find text occurs twice, one with a missing
      file, a duplicate id, a no-op replace and a round-tag anchor are each reported.
  GA3 (R27 closed loop, pipeline_20261105T133652 S3k FAIL: gm-r27-p2pcfg-cfg-version-date anchored on '+22102026.r26',
      so the R27 version bump to .r27 made it STALE): a mutation of config/version.go must not anchor on the round tag
      (+<DDMMYYYY>.r<N>), which changes every round; it is reported by problems() and so by GA1.

  python3 -I harness/kat/test_gomut_anchors_r26.py
Exit 0 all ok · 3 the KAT failed · 4 a mutation of the checker was not caught.
"""
import json, re, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REG = ROOT / 'harness' / 'intel' / 'go_mutations.json'
ROUND_TAG_RX = re.compile(r'\+\d{8}\.r\d+')   # r27: the per-round build tag of config/version.go
VERSION_FILE = 'config/version.go'


def problems(spec, root, count=lambda text, find: text.count(find), want=1):
    """the anchor problems of a go_mutations.json spec against the tree at root. Pure apart from file reads."""
    out, seen, cache = [], set(), {}
    for m in spec.get('mutations', []):
        mid = m.get('id')
        if mid in seen:
            out.append(f'{mid}: duplicate id')
        seen.add(mid)
        if m.get('find') == m.get('replace'):
            out.append(f'{mid}: replace equals find (a no-op mutant)')
        if m.get('file') == VERSION_FILE and ROUND_TAG_RX.search(m.get('find', '')):
            out.append(f'{mid}: find text anchors on the round tag of {VERSION_FILE} (STALE at the next version bump)')
        p = Path(root) / m.get('file', '')
        if p not in cache:
            cache[p] = p.read_text() if p.is_file() else None
        if cache[p] is None:
            out.append(f"{mid}: file {m.get('file')} missing")
            continue
        n = count(cache[p], m.get('find', ''))
        if n != want:
            out.append(f"{mid}: find text occurs {n} time(s) in {m.get('file')} (STALE in go_mutate)")
    return out


def ga1(fn):
    spec = json.loads(REG.read_text())
    p = fn(spec, ROOT)
    return not p and len(spec['mutations']) > 0, f"{len(spec['mutations'])} mutations, problems {p[:5]}"


def ga2(fn):
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / 'a.go').write_text('x := 1\ny := 2\ny := 2\n')
        good = {'id': 'ok', 'file': 'a.go', 'find': 'x := 1', 'replace': 'x := 0'}
        cases = {
            'gone': [good, {'id': 'g', 'file': 'a.go', 'find': 'z := 3', 'replace': 'z := 4'}],
            'twice': [good, {'id': 't', 'file': 'a.go', 'find': 'y := 2', 'replace': 'y := 3'}],
            'nofile': [good, {'id': 'n', 'file': 'b.go', 'find': 'x', 'replace': 'y'}],
            'dupid': [good, dict(good)],
            'noop': [good, {'id': 'p', 'file': 'a.go', 'find': 'x := 1', 'replace': 'x := 1'}],
            'roundtag': [good, {'id': 'r', 'file': 'config/version.go', 'find': '+22102026.r27', 'replace': '+32102026.r27'}],
        }
        (Path(d) / 'config').mkdir()
        (Path(d) / 'config' / 'version.go').write_text('var Version = semver.MustParse("3.6.0-153.DEROHE.STARGATE+22102026.r27")\n')
        clean = fn({'mutations': [good]}, d)
        got = {k: bool(fn({'mutations': v}, d)) for k, v in cases.items()}
    return not clean and all(got.values()), f'clean {clean} cases {got}'


MUTANTS = [
    ('count >= 1 passes (a duplicated anchor slips through)', lambda s, r: problems(s, r, count=lambda t, f: min(t.count(f), 1))),
    ('a missing find text passes', lambda s, r: problems(s, r, count=lambda t, f: max(t.count(f), 1))),
    ('duplicate ids ignored', lambda s, r: [x for x in problems(s, r) if 'duplicate id' not in x]),
    ('missing files ignored', lambda s, r: [x for x in problems(s, r) if 'missing' not in x]),
    ('no-op mutants ignored', lambda s, r: [x for x in problems(s, r) if 'no-op' not in x]),
    ('round-tag anchors ignored', lambda s, r: [x for x in problems(s, r) if 'round tag' not in x]),
]


def main():
    ok = True
    for name, f in (('GA1', ga1), ('GA2', ga2)):
        r, det = f(problems)
        print(f"{'ok  ' if r else 'FAIL'} {name} {det[:300]}")
        ok &= r
    if not ok:
        return 3
    missed = 0
    for why, fn in MUTANTS:
        caught = not (ga1(fn)[0] and ga2(fn)[0])
        print(f"  {'proved ' if caught else 'MISSED '} {why}")
        missed += not caught
    print(f'\nr26 gomut-anchors KATs: 2/2 ok (GA3 inside GA1/GA2) · mutations proved {len(MUTANTS) - missed}/{len(MUTANTS)}')
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
