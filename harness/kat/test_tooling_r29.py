#!/usr/bin/env python3
"""KAT + mutation proofs for the R29 tooling group (rft §0.9, §7 B170 B168 B167 B155). No network, no live file
written: every registry, dataset, cache and memo is a temp file; the tree is only read.

  TL1  B170  area_intel.booked_at / pin_ownership / areas_as_of: a (round, area) is pinned at the NEWEST commit that
             changed its booked VALUES (an anchor-line move books nothing); an existing pin is never rewritten; a
             pinned round attributes through its pinned code_paths / gates, an unpinned one through today's.
  TL2  B168  go_mutate.listed_tests / missing_tests: `go test -list .` names (not the 'ok' line); an alternation
             reports each missing name; an unreadable list (None) never makes a mutation STALE.
  TL3  B167  facts.prune_dataset_cache: an extraction whose tree is gone, or unread past the age, is removed; a live
             recent one, a symlink and a plain file are kept.
  TL4  B155  audit_check.scan_dataset memo: the memoised scan equals the full scan (memo=False) hit for hit; a second
             scan reuses every text; a changed file is scanned again; a changed private term invalidates the memo.

  python3 -I harness/kat/test_tooling_r29.py   # KATs, then each mutation (on a temp copy) must fail its owning KAT
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not proved (MISSED / WRONG-KAT / INVALID) or was coupled.
"""
import gzip, importlib.util, json, os, shutil, sys, tempfile, time
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
PATHS = {'ai': 'harness/intel/area_intel.py', 'gm': 'harness/intel/go_mutate.py', 'fx': 'harness/forensics/facts.py',
         'ac': 'harness/forensics/audit_check.py'}


def P(over, key):
    return Path(over.get(key) or ROOT / PATHS[key])


def load(over, key):
    path = P(over, key)
    spec = importlib.util.spec_from_file_location(f'tl29_{key}_{abs(hash(str(path)))}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _areas(ver, paths, gates, hist):
    return {'areas': [{'id': 'a', 'code_paths': paths, 'gates': gates, 'history': hist},
                      {'id': 'b', 'code_paths': ['b/'], 'gates': ['G2'], 'history': {}}]}


def kat_tl1(over):
    AI = load(over, 'ai')
    bad = []
    v1 = {'r1': {'m': {'value': 3, 'anchor': {'line': 10}}}}
    v1_moved = {'r1': {'m': {'value': 3, 'anchor': {'line': 12}}}}
    v2 = {'r1': {'m': {'value': 4, 'anchor': {'line': 12}}}}
    log = [('c4', _areas(4, ['a/', 'g/'], ['G1', 'G9'], v2)),          # newest: a correction under the new ownership
           ('c3', _areas(3, ['a/', 'g/'], ['G1', 'G9'], v1_moved)),    # ownership grew; only an anchor line moved
           ('c2', _areas(2, ['a/'], ['G1'], v1)),                     # first booking
           ('c1', _areas(1, ['a/'], ['G1'], {}))]
    at = AI.booked_at(log)
    if at.get(('r1', 'a')) != 'c4':
        bad.append(f"newest value change: {at}")
    at2 = AI.booked_at(log[1:])
    if at2.get(('r1', 'a')) != 'c2':
        bad.append(f'an anchor-line move re-booked the round: {at2}')
    reg = {'areas': [{'id': 'a', 'code_paths': ['a/', 'g/'], 'gates': ['G1', 'G9']}, {'id': 'b', 'code_paths': ['b/'], 'gates': []}],
           'rounds': [{'id': 'r1'}, {'id': 'r2'}]}
    n = AI.pin_ownership(reg, 'r1', [{'id': 'a', 'code_paths': ['a/'], 'gates': ['G1']}])
    n2 = AI.pin_ownership(reg, 'r1', [{'id': 'a', 'code_paths': ['x/'], 'gates': []}])
    if (n, n2) != (1, 0) or reg['rounds'][0]['ownership']['a'] != {'code_paths': ['a/'], 'gates': ['G1']}:
        bad.append(f'pin {n}/{n2} {reg["rounds"][0].get("ownership")}')
    then = {a['id']: a for a in AI.areas_as_of(reg, 'r1')}
    now = {a['id']: a for a in AI.areas_as_of(reg, 'r2')}
    if then['a']['code_paths'] != ['a/'] or then['a']['gates'] != ['G1'] or now['a']['gates'] != ['G1', 'G9']:
        bad.append(f'as_of r1 {then["a"]} r2 {now["a"]}')
    if AI.area_of(AI.areas_as_of(reg, 'r1'), 'g/x.go') is not None or AI.area_of(AI.areas_as_of(reg, 'r2'), 'g/x.go') != 'a':
        bad.append('attribution does not follow the pin')
    return not bad, '; '.join(bad) or 'booked values keep the ownership they were booked under'


def kat_tl2(over):
    GM = load(over, 'gm')
    bad = []
    out = 'TestA\nTestB_x\nFuzzC\nExampleD\nok  \tgithub.com/x/y\t0.01s\n'
    L = GM.listed_tests(out)
    if L != {'TestA', 'TestB_x', 'FuzzC', 'ExampleD'}:
        bad.append(f'listed {sorted(L)}')
    if GM.missing_tests('TestA', L) or GM.missing_tests('TestA|TestGone|TestB_x', L) != ['TestGone']:
        bad.append(f"missing {GM.missing_tests('TestA|TestGone|TestB_x', L)}")
    if GM.missing_tests('TestGone', None) != []:
        bad.append('an unreadable list made a mutation STALE')
    return not bad, '; '.join(bad) or 'a mutation whose test is gone is STALE, never MISSED'


def kat_tl3(over):
    FX = load(over, 'fx')
    bad = []
    base = Path(tempfile.mkdtemp(prefix='tl29-cache-'))
    live_tree = Path(tempfile.mkdtemp(prefix='tl29-tree-'))
    try:
        now = time.time()
        for name, root, age in (('dead', base / 'no-such-tree', 60), ('live', live_tree, 60), ('old', live_tree, 9 * 86400),
                                ('legacy', None, 9 * 86400), ('fresh_legacy', None, 60)):
            d = base / name
            (d / 'forensics').mkdir(parents=True)
            if root is not None:
                (d / 'ROOT.txt').write_text(str(root) + '\n')
                os.utime(d / 'ROOT.txt', (now - age, now - age))
            os.utime(d, (now - age, now - age))
        old_target = live_tree / 'old_target'          # a week-old directory behind a symlink: never followed
        old_target.mkdir()
        os.utime(old_target, (now - 9 * 86400, now - 9 * 86400))
        (base / 'link').symlink_to(old_target)
        (base / 'note.txt').write_text('x')
        gone = FX.prune_dataset_cache(base, now=now)
        left = sorted(p.name for p in base.iterdir())
        if sorted(gone) != ['dead', 'legacy', 'old'] or left != ['fresh_legacy', 'link', 'live', 'note.txt']:
            bad.append(f'gone {gone} left {left}')
        if not old_target.is_dir():
            bad.append('the directory behind a symlink was touched')
    finally:
        shutil.rmtree(base, ignore_errors=True)
        shutil.rmtree(live_tree, ignore_errors=True)
    return not bad, '; '.join(bad) or 'gone or week-old extractions are removed, live ones kept'


def kat_tl4(over):
    AC = load(over, 'ac')
    bad = []
    ds = Path(tempfile.mkdtemp(prefix='tl29-ds-'))
    memo = Path(tempfile.mkdtemp(prefix='tl29-memo-')) / 'memo.json'
    try:
        (ds / 'derived').mkdir()
        (ds / 'derived' / 'a.txt').write_text('plain text, nothing here\n')
        (ds / 'derived' / 'b.json').write_text('{"note": "a private-term-7 sits here"}\n')
        (ds / 'derived' / 'c.jsonl.gz').write_bytes(gzip.compress(b'{"x": "the private-term-7 again"}\n'))
        (ds / 'derived' / 'd.txt').write_text('plain text, nothing here\n')          # same bytes as a.txt
        terms = ['private-term-7']
        full = AC.scan_dataset(ds, ROOT, terms, memo=False)
        first = AC.scan_dataset(ds, ROOT, terms, memo=memo)
        r1 = AC.LAST_MEMO_REUSED
        second = AC.scan_dataset(ds, ROOT, terms, memo=memo)
        r2 = AC.LAST_MEMO_REUSED
        if not (full == first == second) or len(full['hits']) != 2:
            bad.append(f"memo differs from the full scan: {len(full['hits'])}/{len(first['hits'])}/{len(second['hits'])}")
        if (r1, r2) != (0, 4):
            bad.append(f'reuse {r1}/{r2} (want 0/4)')
        (ds / 'derived' / 'a.txt').write_text('now a private-term-7 here too\n')
        third = AC.scan_dataset(ds, ROOT, terms, memo=memo)
        r3 = AC.LAST_MEMO_REUSED
        if third != AC.scan_dataset(ds, ROOT, terms, memo=False) or len(third['hits']) != 3 or r3 != 3:
            bad.append(f"a changed file was not scanned again: {len(third['hits'])} hits")
        other = AC.scan_dataset(ds, ROOT, ['another-term'], memo=memo)
        if AC.LAST_MEMO_REUSED != 0 or other != AC.scan_dataset(ds, ROOT, ['another-term'], memo=False):
            bad.append(f'a changed term set reused {AC.LAST_MEMO_REUSED} memo entries')
        if 'private-term-7' in memo.read_text():
            bad.append('the memo holds a private term in clear')
    finally:
        shutil.rmtree(ds, ignore_errors=True)
        shutil.rmtree(memo.parent, ignore_errors=True)
    return not bad, '; '.join(bad) or 'the memoised G29 scan equals the full scan; changes are re-scanned'


KATS = [('TL1', kat_tl1), ('TL2', kat_tl2), ('TL3', kat_tl3), ('TL4', kat_tl4)]
OWNERS = {'B170': ['TL1'], 'B168': ['TL2'], 'B167': ['TL3'], 'B155': ['TL4']}

MUTATIONS = [   # (key, find, replace, why)
    ('ai', "            if k not in out and old.get(k) != v:", "            if old.get(k) != v:",
     'B170: the OLDEST value change wins (a correction does not move the pin)'),
    ('ai', "        return {(rid, a.get('id')): json.dumps({m: (e or {}).get('value') for m, e in (ms or {}).items()}, sort_keys=True)",
     "        return {(rid, a.get('id')): json.dumps(ms, sort_keys=True)", 'B170: an anchor-line move re-books the round'),
    ('ai', "        if a.get('id') and a['id'] not in own:", "        if a.get('id'):", 'B170: an existing pin is rewritten'),
    ('ai', "    pin = ent.get('ownership') or {}", "    pin = {}", 'B170: a pinned round attributes through today\'s ownership'),
    ('gm', "    return {l.strip() for l in (text or '').splitlines() if TEST_NAME_RX.fullmatch(l.strip())}",
     "    return {l.strip() for l in (text or '').splitlines() if l.strip()}", "B168: the 'ok <pkg>' line is read as a test name"),
    ('gm', "    if listed is None:\n        return []", "    if listed is None:\n        listed = set()", 'B168: an unreadable list makes every mutation STALE'),
    ('gm', "    return [n for n in str(test).split('|') if n and n not in listed]", "    return [n for n in [str(test)] if n and n not in listed]",
     'B168: an alternation is read as one name'),
    ('fx', "        if (root is not None and not Path(root).is_dir()) or age > max_age_s:", "        if age > max_age_s:",
     'B167: an extraction of a deleted tree is kept'),
    ('fx', "        if not e.is_dir() or e.is_symlink():", "        if not e.is_dir():", 'B167: a symlinked entry is followed and removed'),
    ('ac', "            old = o['entries'] if o.get('fingerprint') == fp else {}", "            old = o['entries']",
     'B155: a memo made under other patterns or terms is reused'),
    ('ac', "        if k in old:", "        if old:", 'B155: any memo entry stands for every file'),
    ('ac', "    for t in sorted(hashlib.sha256(t.encode()).hexdigest() for t in private_terms if t):",
     "    for t in []:", 'B155: the private terms are not in the fingerprint'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_r29tl', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run_kats(over):
    out = []
    for name, fn in KATS:
        try:
            ok, det = fn(over)
        except Exception as e:                                    # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        out.append((name, ok, det))
    return out


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    K = katmut()
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    fails = sum(1 for _, ok, _ in res if not ok)
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        src = P({}, key)
        text = src.read_text()
        if text.count(find) != 1:
            print(f'  INVALID  {why} — find text occurs {text.count(find)} time(s)')
            missed += 1
            continue
        d = Path(tempfile.mkdtemp(prefix='tl29-mut-'))
        mp = d / src.name
        mp.write_text(text.replace(find, repl, 1))
        try:
            failed = [n for n, ok, _ in run_kats({key: mp}) if not ok]
        finally:
            shutil.rmtree(d, ignore_errors=True)
        verdict, extra = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:9s} {why}  {failed}')
        missed += verdict != 'proved'
        coupled += bool(extra) and verdict == 'proved'
    print('\n' + K.summary('r29 tooling KATs', len(KATS) - fails if fails else len(KATS), len(MUTATIONS), missed, coupled))
    return 3 if fails else (4 if missed or coupled else 0)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
