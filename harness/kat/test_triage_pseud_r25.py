#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the triage miner's peer names (harness/miners/mine_triage.py pseud_peer;
r25 pipeline run 3, pipeline_20261103T144257 S7 FAIL at verify_deroarch --mutations: 'tri-remote-txstore not on the
page').

  TP1 pseud_peer names a console peer address exactly as scrub_snapshot names it in the snapshot's 'peer <ip> ...'
      fact (so the row's fact anchor resolves), keeps reserved addresses, and never returns the raw address.
  TP2 every triage row that looks a peer up (remote-emptyblock, remote-txstore, closedpipe-churn) derives its peer
      list through pseud_peer; a raw lookup loses the anchor and the row leaves the page.

  python3 -I harness/kat/test_triage_pseud_r25.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import importlib.util, re, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
SRC = HARNESS / 'miners' / 'mine_triage.py'


def load(path):
    sys.path.insert(0, str(HARNESS / 'miners'))
    spec = importlib.util.spec_from_file_location(f'tp25_{abs(hash(str(path)))}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def tp1(m, text):
    salt = 'kat-salt-r25'
    snap = m.scrub_snapshot({'facts': ['peer 82.1.2.3 address=82.1.2.3:11011 goodcount=3']}, salt)
    name = m.pseud_peer('82.1.2.3:11011', salt).split(':')[0]
    ok = snap['facts'][0].startswith(f'peer {name} ') and name.startswith('peer-') and '82.1.2.3' not in name \
        and m.pseud_peer('127.0.0.1:11011', salt) == '127.0.0.1:11011'
    return ok, f'{name} {snap["facts"][0][:60]}'


def tp2(m, text):
    raw = re.findall(r"        peer = sorted\(\{(.*?) for e in (mv|ts|churn)\}\)", text)
    return len(raw) == 3 and all(x.startswith('pseud_peer(') for x, _ in raw), f'{raw}'


KATS = [('TP1', tp1), ('TP2', tp2)]
MUTATIONS = [
    ("    return privkit.pseudonymise_text(addr, salt or privkit.load_salt())", "    return addr",
     'the raw console address is used (anchor lost, raw IP in the claim)'),
    ("        peer = sorted({pseud_peer(e['logger'].split('.', 2)[2]) for e in ts})", "        peer = sorted({e['logger'].split('.', 2)[2] for e in ts})",
     'tri-remote-txstore looks its peer up by the raw address'),
    ("        peer = sorted({pseud_peer(e['logger'].split('.', 2)[2]) for e in mv})", "        peer = sorted({e['logger'].split('.', 2)[2] for e in mv})",
     'tri-remote-emptyblock looks its peer up by the raw address'),
]


def run(m, text):
    res = []
    for n, f in KATS:
        try:
            o, det = f(m, text)
        except Exception as e:                                    # noqa: BLE001
            o, det = False, f'{type(e).__name__}: {e}'
        res.append((n, bool(o), det))
    return res


def main():
    text = SRC.read_text()
    res = run(load(SRC), text)
    for n, o, det in res:
        print(f"{'ok  ' if o else 'FAIL'} {n} {det[:300]}")
    if not all(o for _, o, _ in res):
        return 3
    missed = 0
    for find, repl, why in MUTATIONS:
        if text.count(find) != 1:
            print(f'  ??      {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        d = Path(tempfile.mkdtemp(prefix='tp25-'))
        try:
            p = d / SRC.name
            mt = text.replace(find, repl, 1)
            p.write_text(mt)
            try:
                mm = load(p)
            except Exception as e:                                # noqa: BLE001
                print(f'  INVALID {why}: mutant does not load ({type(e).__name__})')
                missed += 1
                continue
            survived = all(o for _, o, _ in run(mm, mt))
        finally:
            shutil.rmtree(d, ignore_errors=True)
        print(f"  {'MISSED ' if survived else 'proved '} {why}")
        missed += survived
    print(f'\nr25 triage-pseud KATs: {len(KATS)}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
