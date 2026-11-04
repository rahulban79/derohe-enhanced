#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the S6 install backup name and the S5 control build (harness/pipeline/fix_build_verify.py
backup_tag / known_suffixes / control_binary; r25 pipeline run 3, pipeline_20261103T144257).

  IT1 Go packs string literals without a terminator: '...STARGATE+22102026.r24invalid human-readable part' is the r24
      build (backup .22102026.r24-backup), not 'r24i'; '...r24payload' is not 'r24p'; a registry-named letter suffix
      (r23b, r23c) is kept; a pre-round tag ('+21102026') and no version string ('unknown') are named as such.
  IT2 known_suffixes reads every version_suffix of a registry and skips 'pending'; the committed registry names r23b.
  IT3 control_binary (S5): the shadow control is the live node's build: bin/derod when it carries the live tag, else
      bin/derod.<live tag>-backup (after an install), else bin/derod; an unknown live version falls back to bin/derod.

  python3 -I harness/kat/test_install_tag_r25.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import importlib.util, json, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
SRC = HARNESS / 'pipeline' / 'fix_build_verify.py'


def load(base):
    spec = importlib.util.spec_from_file_location(f'it25_{abs(hash(str(base)))}_{len(sys.modules)}', base / 'pipeline' / SRC.name)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def it1(m):
    known = {'22102026.r23b', '22102026.r23c', '22102026.r24', 'pending'}
    cases = [(b'xx3.6.0-153.DEROHE.STARGATE+22102026.r24invalid human-readable part', '22102026.r24'),
             (b'STARGATE+22102026.r24payload %d', '22102026.r24'),
             (b'STARGATE+22102026.r23bGenesis', '22102026.r23b'),
             (b'STARGATE+22102026.r23cx', '22102026.r23c'),
             (b'STARGATE+21102026bug', '21102026'),
             (b'no version here', 'unknown')]
    got = [m.backup_tag(b, known) for b, _ in cases]
    return got == [w for _, w in cases], f'{got}'


def it2(m):
    reg = {'rounds': [{'version_suffix': '22102026.r23b'}, {'version_suffix': 'pending'}, {}, 'junk']}
    a = m.known_suffixes(reg)
    live = m.known_suffixes(json.loads((HARNESS / 'round.json').read_text()))
    return a == {'22102026.r23b'} and '22102026.r23b' in live and 'pending' not in live, f'{a} live={sorted(live)}'


def it3(m):
    """the shadow CONTROL is the live node's build: bin/derod when it is that build, else its backup, else bin/derod"""
    with tempfile.TemporaryDirectory() as d:
        b = Path(d)
        (b / 'derod').write_bytes(b'x STARGATE+22102026.r25invalid')
        (b / 'derod.22102026.r24-backup').write_bytes(b'x STARGATE+22102026.r24invalid')
        live24 = '3.6.0-153.DEROHE.STARGATE+22102026.r24'
        a = m.control_binary(b, live24, set())[0].name
        c = m.control_binary(b, '3.6.0-153.DEROHE.STARGATE+22102026.r25', set())[0].name
        e = m.control_binary(b, '3.6.0-153.DEROHE.STARGATE+22102026.r23c', {'22102026.r23c'})[0].name
        f = m.control_binary(b, None, set())[0].name
    got = (a, c, e, f)
    return got == ('derod.22102026.r24-backup', 'derod', 'derod', 'derod'), f'{got}'


KATS = [('IT1', it1), ('IT2', it2), ('IT3', it3)]
MUTATIONS = [
    ("    return tag + letter if letter and tag + letter in known else tag", "    return tag + letter",
     "the next literal's first letter is read as a round suffix (r24i)"),
    ("    return tag + letter if letter and tag + letter in known else tag", "    return tag",
     'a registry-named letter suffix (r23b) is dropped (its backup overwrites r23)'),
    ("            and r.get('version_suffix') not in (None, PENDING)}", "            }", "'pending' counts as a known suffix"),
    ("    if not m:\n        return 'unknown'\n", "", 'a binary with no version string crashes the install'),
    ("    if bak.exists():\n        return bak,", "    if False:\n        return bak,",
     'the shadow control is the freshly installed build, not the one the live node runs'),
    ("    if have == want:\n        return cur,", "    if True:\n        return cur,", 'the live tag is ignored (control always bin/derod)'),
]


def tree():
    d = Path(tempfile.mkdtemp(prefix='it25-')) / 'harness'
    (d / 'pipeline').mkdir(parents=True)
    shutil.copy2(SRC, d / 'pipeline' / SRC.name)
    shutil.copy2(HARNESS / 'round.json', d / 'round.json')
    return d


def run(m):
    res = []
    for n, f in KATS:
        try:
            o, det = f(m)
        except Exception as e:                                    # noqa: BLE001
            o, det = False, f'{type(e).__name__}: {e}'
        res.append((n, bool(o), det))
    return res


def main():
    d = tree()
    try:
        res = run(load(d))
        for n, o, det in res:
            print(f"{'ok  ' if o else 'FAIL'} {n} {det[:300]}")
        if not all(o for _, o, _ in res):
            return 3
        text, missed = SRC.read_text(), 0
        for find, repl, why in MUTATIONS:
            if text.count(find) != 1:
                print(f'  ??      {why}: find text occurs {text.count(find)} times')
                missed += 1
                continue
            (d / 'pipeline' / SRC.name).write_text(text.replace(find, repl, 1))
            try:
                mm = load(d)
            except Exception as e:                                # noqa: BLE001
                print(f'  INVALID {why}: mutant does not load ({type(e).__name__})')
                missed += 1
                continue
            survived = all(o for _, o, _ in run(mm))
            print(f"  {'MISSED ' if survived else 'proved '} {why}")
            missed += survived
        print(f'\nr25 install-tag KATs: {len(KATS)}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
        return 4 if missed else 0
    finally:
        shutil.rmtree(d.parent, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
