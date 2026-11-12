#!/usr/bin/env python3
"""test_b182_census_r30.py — r30 merge (rft §7 B240, B205): the R29 orphan tool harness/forensics/b182_census_r29.py
is REGISTERED, not retired: its record harness/runtime/r29_b182_offline_census.json is one of the three B182 census
records the v5 dataset pins (B207) and dc2_den.py sums (B203 (a)), so the tool that wrote it must reproduce it.

  CR1 B240  the tool re-run on the committed inputs (forensics/r28/derived/txs.jsonl.gz, forensics/r25/derived/
            link.jsonl.gz, forensics/r28/raw/wall1_blocks.jsonl.gz) writes the committed record byte for byte
  CR2 B240  the record's input sha256 pins equal the committed inputs (a changed input is named, not absorbed)
  CR3 B240  harness/areas.json's forensics area registers this KAT and the tool (coherence_audit reaches it)

  python3 -I harness/kat/test_b182_census_r30.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, hashlib, importlib.util, io, json, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'tool': 'harness/forensics/b182_census_r29.py', 'areas': 'harness/areas.json'}
RECORD = ROOT / 'harness/runtime/r29_b182_offline_census.json'


def rerun(over):
    with tempfile.TemporaryDirectory(prefix='b182-cr-') as d:
        out = Path(d) / 'census.json'
        r = subprocess.run([sys.executable, '-I', str(over.get('tool') or (ROOT / PATHS['tool'])), str(ROOT / 'forensics'),
                            str(out)], capture_output=True, text=True, timeout=300)
        return r.returncode, (out.read_text() if out.exists() else None), r.stderr[-300:]


def kat_cr1(over):
    rc, text, err = rerun(over)
    want = RECORD.read_text()
    return rc == 0 and text == want, (rc, None if text is None else len(text), len(want), err)


def kat_cr2(over):
    rc, text, err = rerun(over)
    if rc or text is None:
        return False, (rc, err)
    pins = json.loads(text).get('inputs') or {}
    real = {p: hashlib.sha256((ROOT / 'forensics' / p).read_bytes()).hexdigest() for p in pins}
    return bool(pins) and pins == real and pins == json.loads(RECORD.read_text()).get('inputs'), sorted(pins)


def kat_cr3(over):
    a = json.loads(Path(over.get('areas') or (ROOT / PATHS['areas'])).read_text())
    f = next(x for x in a['areas'] if x['id'] == 'forensics')
    ok = 'harness/kat/test_b182_census_r30.py' in f['kat_files'] and PATHS['tool'] in f['code_paths']
    return ok, (PATHS['tool'] in f['code_paths'], 'harness/kat/test_b182_census_r30.py' in f['kat_files'])


KATS = [('CR1', kat_cr1), ('CR2', kat_cr2), ('CR3', kat_cr3)]
OWNERS = {'B240': ['CR1', 'CR2', 'CR3']}
MUTATIONS = [
    ('tool', "'reg_lt3': [t for t in regs if lz(t) < 3],", "'reg_lt3': [t for t in regs if lz(t) <= 3],",
     'B240: the below-3-zero-bytes registration rule widened to <= 3'),
    ('tool', "census('gap_7415464_7415465', 7415464, 7415465, L)", "census('gap_7415464_7415465', 7415464, 7415464, L)",
     'B240: the 7,415,464..465 gap range cut by one block'),
    ('tool', "'complete': not missing and not untyped}", "'complete': not missing}",
     'B240: a range with untyped txs graded complete'),
    ('areas', '"harness/kat/test_b182_census_r30.py"', '"harness/kat/test_b182_census_r3x.py"',
     'B240: the KAT not registered on the forensics card'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_b182cr', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run_kats(over):
    res = []
    for name, fn in KATS:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                ok, det = fn(over)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        res.append((name, ok, str(det)))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr30 b182-census KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) < 1 or (key != 'areas' and text.count(find) != 1):
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='b182cr-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r30 b182-census KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
