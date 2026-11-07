#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for harness/intel/b36_payee_read.py (dero-rft §7 B36; R28 glue-global).

All inputs are forged in memory or in a temp dir (series lines carry real crc32 checksums); no RPC is sent.

  BP1 parse_series: a good line is read; a torn line, a bad checksum and a non-JSON body are dropped and counted;
      a pre-r27 checkpoint (no v) is parsed but checkpoints() never returns it (its payees are unknown, never 0): a
      segment whose only checkpoint is pre-r27 is PENDING, even at that checkpoint's height.
  BP2 compare(): RPC segment_to == a v2 checkpoint height of the same segment with equal counts -> EQUAL, and B36 is
      confirmed only with span >= 86,400 s and 0 alerts (23 h 59 min 59 s: not confirmed); one differing count ->
      MISMATCH; a checkpoint of ANOTHER segment at that height is not used (BOUND or PENDING).
  BP3 between checkpoints: RPC counts >= the newest checkpoint -> BOUND; below it, a decreasing series, verified above
      payees, or alerts -> BAD; an empty series -> PENDING.
  BP4 main() on a forged series and a stubbed RPC: exit 0 EQUAL, 3 MISMATCH, 4 when --wait ends without equality;
      --out names the series by basename only (no directory); --help exits 0.

  python3 -I harness/kat/test_b36_payee_read_r28.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught by its own KAT, was INVALID, or coupled.
"""
import contextlib, importlib.util, io, json, shutil, sys, tempfile, zlib
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
TOOL = 'harness/intel/b36_payee_read.py'


def load(root):
    spec = importlib.util.spec_from_file_location(f'b36_{abs(hash(str(root)))}', Path(root) / TOOL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def line(rec):
    j = json.dumps(rec, separators=(',', ':'))
    return f'{j} {zlib.crc32(j.encode()) & 0xffffffff:08x}'


def cp(h, payees, seg_from=100, t=None, start=1000, v=2, alerts=0, ver=None, exp=None):
    r = {'kind': 'checkpoint', 'time': t if t is not None else start + DAY, 'seg_start': start, 'height': h,
         'segment_from': seg_from, 'segment_to': h, 'alerts': alerts}
    if v:
        r.update(v=v, payees=payees, payees_verified=payees if ver is None else ver,
                 payees_explained=payees if exp is None else exp)
    return r


DAY = 86400


def rpc(seg_to, payees, seg_from=100, alerts=0):
    return {'segment_from': seg_from, 'segment_to': seg_to, 'payees': payees, 'payees_verified': payees,
            'payees_explained': payees, 'alerts': alerts}


def bp1(B):
    good = line(cp(200, 70))
    text = '\n'.join([good, good[:-5], good[:-1] + ('0' if good[-1] != '0' else '1'), 'not json 0000abcd',
                      line(cp(300, 0, v=0))])
    recs, dropped = B.parse_series(text)
    cps = B.checkpoints(recs, 100)
    pre = B.compare(rpc(300, 175), [cp(300, 0, v=0)])['verdict']    # a pre-r27 record at the segment end: unknown
    ok = len(recs) == 2 and dropped == 3 and [c['height'] for c in cps] == [200] and pre == 'PENDING'
    return ok, f'records {len(recs)} dropped {dropped} v2 checkpoints {[c["height"] for c in cps]} pre-r27 {pre}'


def bp2(B):
    recs = [cp(200, 70), cp(300, 140)]
    eq = B.compare(rpc(300, 140), recs)
    short = B.compare(rpc(300, 140), [cp(200, 70), cp(300, 140, t=1000 + DAY - 1)])
    mis = B.compare(dict(rpc(300, 140), payees_explained=139), recs)
    other = B.compare(rpc(300, 140, seg_from=250), recs)
    ok = (eq['verdict'] == 'EQUAL' and B.confirmed(eq) and short['verdict'] == 'EQUAL' and not B.confirmed(short)
          and mis['verdict'] == 'MISMATCH' and other['verdict'] == 'PENDING')
    return ok, f"equal {eq['verdict']}/{B.confirmed(eq)} 24h-1s {short['verdict']}/{B.confirmed(short)} " \
               f"mismatch {mis['verdict']} other-segment {other['verdict']}"


def bp3(B):
    recs = [cp(200, 70), cp(300, 140)]
    got = {
        'bound': B.compare(rpc(350, 175), recs)['verdict'],
        'behind': B.compare(rpc(350, 130), recs)['verdict'],
        'decreasing': B.compare(rpc(350, 175), [cp(200, 70), cp(300, 60)])['verdict'],
        'verified_above': B.compare(rpc(350, 175), [cp(200, 70, ver=71)])['verdict'],
        'alerts': B.compare(rpc(350, 175, alerts=1), recs)['verdict'],
        'empty': B.compare(rpc(350, 175), [])['verdict'],
    }
    want = {'bound': 'BOUND', 'behind': 'BAD', 'decreasing': 'BAD', 'verified_above': 'BAD', 'alerts': 'BAD',
            'empty': 'PENDING'}
    return got == want, f'{got}'


def bp4(B):
    with tempfile.TemporaryDirectory(prefix='bp4_') as d:
        s = Path(d) / 'sub' / 'emission_series.jsonl'
        s.parent.mkdir()
        s.write_text('\n'.join(line(c) for c in (cp(200, 70), cp(300, 140))) + '\n')
        out = Path(d) / 'rec.txt'
        codes = {}
        for name, ans, extra in (('equal', rpc(300, 140), []), ('mismatch', dict(rpc(300, 140), payees=141), []),
                                 ('nowait-bound', rpc(350, 175), []),
                                 ('wait-bound', rpc(350, 175), ['--wait', '0.2', '--poll', '0.1'])):
            B.rpc_call = lambda method, url=None, timeout=15, _a=ans: dict(_a)
            with contextlib.redirect_stdout(io.StringIO()):
                codes[name] = B.main(['--series', str(s), '--out', str(out), *extra])
        rec = out.read_text()
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                B.main(['--help'])
                helped = False
            except SystemExit as e:
                helped = e.code == 0
    ok = (codes == {'equal': 0, 'mismatch': 3, 'nowait-bound': 0, 'wait-bound': 4} and d not in rec
          and 'emission_series.jsonl' in rec and helped)
    return ok, f'exit codes {codes} basename-only {d not in rec} help {helped}'


KATS = [('BP1', bp1), ('BP2', bp2), ('BP3', bp3), ('BP4', bp4)]
OWNERS = {f'r28 BP{i}': [f'BP{i}'] for i in range(1, 5)}

MUTATIONS = [   # (find, replace, why)
    ("            ok = len(crc) == 8 and int(crc, 16) == zlib.crc32(body.encode()) & 0xffffffff",
     "            ok = len(crc) == 8", 'r28 BP1: a bad checksum is read as a record'),
    ("    cps = [r for r in records if r.get('kind') == 'checkpoint' and int(r.get('v') or 0) >= 2",
     "    cps = [r for r in records if r.get('kind') == 'checkpoint'", 'r28 BP1: a pre-r27 checkpoint counts as payees 0'),
    ("    return res.get('verdict') == 'EQUAL' and res.get('span_24h') is True and not res.get('rpc_alerts')",
     "    return res.get('verdict') == 'EQUAL' and not res.get('rpc_alerts')", 'r28 BP2: confirmed without 24 h'),
    ("        diff = {k: (rpc.get(k), at.get(k)) for k in FIELDS if rpc.get(k) != at.get(k)}",
     "        diff = {k: (rpc.get(k), at.get(k)) for k in FIELDS[:1] if rpc.get(k) != at.get(k)}",
     'r28 BP2: only payees compared at the checkpoint'),
    ("           and r.get('segment_from') == segment_from]", "           ]", 'r28 BP2: another segment\'s checkpoint is used'),
    ("    if any(rpc.get(k, 0) < last.get(k, 0) for k in FIELDS) or (seg_to or 0) < last.get('height', 0):",
     "    if False:", 'r28 BP3: an RPC segment behind its checkpoint is BOUND'),
    ("        if prev and any(c.get(k, 0) < prev.get(k, 0) for k in FIELDS):", "        if False:",
     'r28 BP3: a decreasing series passes'),
    ("    if a.wait > 0 and res['verdict'] != 'EQUAL':\n        return 4", "    if False:\n        return 4",
     'r28 BP4: --wait without equality exits 0'),
    ("    text = render(res, Path(a.series).name, dropped,", "    text = render(res, a.series, dropped,",
     'r28 BP4: the record names the series by its full path'),
]


def run_on(mutation=None):
    with tempfile.TemporaryDirectory(prefix='bp28_') as d:
        root = Path(d)
        (root / TOOL).parent.mkdir(parents=True)
        shutil.copy2(ROOT / TOOL, root / TOOL)
        if mutation:
            find, repl, _ = mutation
            p = root / TOOL
            p.write_text(p.read_text(encoding='utf-8').replace(find, repl, 1), encoding='utf-8')
            compile(p.read_text(encoding='utf-8'), str(p), 'exec')
        res = []
        for name, fn in KATS:
            try:
                o, det = fn(load(root))
            except Exception as e:                                    # noqa: BLE001
                o, det = False, f'{type(e).__name__}: {e}'
            res.append((name, o, det))
        return res


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_r28bp', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_on()
    for name, o, det in res:
        print(f"{'ok  ' if o else 'FAIL'} {name} {det[:500]}")
    if not all(o for _, o, _ in res):
        return 3
    K = katmut()
    missed = coupled = 0
    text = (ROOT / TOOL).read_text(encoding='utf-8')
    for mut in MUTATIONS:
        find, repl, why = mut
        if text.count(find) != 1:
            print(f'  ??      {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        try:
            r = run_on(mut)
        except SyntaxError as e:
            print(f'  INVALID {why}: mutant does not compile ({e.msg})')
            missed += 1
            continue
        failed = [n for n, o, _ in r if not o]
        verdict, extra = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f"  {verdict:8} {why}" + (f'  [{",".join(failed)}]' if failed else '')
              + (f'  COUPLED {extra}' if extra and verdict == 'proved' else ''))
        missed += verdict != 'proved'
        coupled += bool(extra) and verdict == 'proved'
    print('\n' + K.summary('r28 b36-payee-read KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed or coupled else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
