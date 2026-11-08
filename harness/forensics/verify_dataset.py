#!/usr/bin/env python3
"""Re-verify every forensic dataset version byte for byte (rft §0.8.1 rule 4 "build on, never rewrite", §0.8.8 G28;
KAT MF10). Read-only unless --register / --seal is given.

  python3 -I harness/forensics/verify_dataset.py forensics/                 # every version; exit 0 PASS, 8 FAIL
  python3 -I harness/forensics/verify_dataset.py forensics/ --register r25  # add the open version to the ledger
  python3 -I harness/forensics/verify_dataset.py forensics/ --seal r25      # freeze it: its manifest SHA-256 is final

The ledger forensics/ledger.json lists every version in order: {version, manifest_sha256, sealed, supersedes}.
Rules (each a FAIL):
  L1 every forensics/r<N>/ with a manifest is in the ledger, and every ledger entry has its directory;
  L2 a sealed version's manifest.json hashes to the ledger's manifest_sha256 (rewriting it in place FAILS, even when
     every file and the manifest were rewritten consistently);
  L3 every version's files re-hash equal to its manifest, with none unlisted or missing (manifest_check.py); the
     newest version is also checked against the current pinned tools and HF3 table;
  L4 only the newest version may be open (unsealed);
  L5 a version's `supersedes` names only earlier sealed versions (a correction is a new version, never an edit);
  L6 the ledger extends the ledger committed at git HEAD: same entries in order, sealed entries unchanged;
  L7 a version's replay/expected.sha256, when present, lists exactly its manifest's derived/ entries, less the ones its
     manifest names in `class_files` (R26: the forensics-classes outputs, pinned in `files` but not re-derived);
  L8 the ledger's `version` field of each manifest equals its directory name;
  L9 an OPEN version's manifest.json hashes to its ledger entry too (R26 forensics-audit2 D2-01: the v2 manifest was
     re-written at the merge, 00f39689 -> 181ab956, without a re-register, and L2 checks sealed versions only):
     re-register (--register) after every manifest write.
g28(root): the G28 gate = the rules above on root/forensics plus the replay run record
harness/runtime/forensics_replay.json: >= 2 runs bound to the newest manifest's SHA-256, from distinct cwd tags, every
report SHA-256 equal, result PASS, mode full, and the record's replay tools equal the current files.
"""
import argparse, hashlib, json, re, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import manifest_check  # noqa: E402

VDIR = re.compile(r'^r(\d+)([a-z]?)$')   # r28d: a sub-round version (r28d) sorts after r28, before r29


def vkey(name):
    """'r28' -> (28, ''), 'r28d' -> (28, 'd'); the order of dataset versions. Pure."""
    m = VDIR.match(name)
    return (int(m.group(1)), m.group(2))
RECORD = 'harness/runtime/forensics_replay.json'


def sha(b):
    return hashlib.sha256(b).hexdigest()


def committed_ledger(root, rel='forensics/ledger.json'):
    p = subprocess.run(['git', '-C', str(root), 'show', f'HEAD:{rel}'], capture_output=True, text=True)
    return json.loads(p.stdout) if p.returncode == 0 and p.stdout.strip() else None


def versions_on_disk(fx):
    out = {}
    for d in Path(fx).iterdir():
        if d.is_dir() and VDIR.match(d.name) and (d / 'manifest.json').exists():
            out[d.name] = d
    return dict(sorted(out.items(), key=lambda kv: vkey(kv[0])))


def verify(fx, root=ROOT, committed=None, check_tools=True):
    """[failures], {per-version summary}. `committed` is the ledger at git HEAD (None = no committed ledger)."""
    fx = Path(fx)
    fails, summ = [], {}
    lp = fx / 'ledger.json'
    if not lp.exists():
        return ['L1 forensics/ledger.json missing'], summ
    led = json.loads(lp.read_text()).get('versions', [])
    disk = versions_on_disk(fx)
    names = [e.get('version') for e in led]
    if len(set(names)) != len(names):
        fails.append('L1 a version appears twice in the ledger')
    for v in disk:
        if v not in names:
            fails.append(f'L1 {v} has a directory but no ledger entry')
    for v in names:
        if v not in disk:
            fails.append(f'L1 {v} is in the ledger but its directory or manifest is gone')
    order = [vkey(v) if v and VDIR.match(v) else (-1, '') for v in names]
    if order != sorted(order) or (-1, '') in order:
        fails.append('L1 ledger versions are not r<N> in increasing order')
    newest = names[-1] if names else None
    sealed_before = set()
    for i, e in enumerate(led):
        v = e.get('version')
        if v not in disk:
            continue
        d = disk[v]
        mb = (d / 'manifest.json').read_bytes()
        m = json.loads(mb)
        s = {'manifest_sha256': sha(mb), 'sealed': bool(e.get('sealed')), 'files': len(m.get('files', {}))}
        if m.get('dataset') != v:
            fails.append(f'L8 {v}: manifest dataset field is {m.get("dataset")!r}')
        if e.get('sealed') is True:
            if sha(mb) != e.get('manifest_sha256'):
                fails.append(f'L2 {v}: sealed manifest rewritten in place (sha256 differs from the ledger)')
        elif v != newest:
            fails.append(f'L4 {v}: an earlier version is not sealed')
        if e.get('sealed') is not True and sha(mb) != e.get('manifest_sha256'):
            fails.append(f'L9 {v}: open manifest differs from its ledger entry (re-register after writing the manifest)')
        tools_ok = check_tools and v == newest
        mf = manifest_check.check(d, root, manifest=None if tools_ok else dict(m, tools={}, hf3_table=None))
        fails += [f'L3 {v}: {x}' for x in mf[:20]]
        s['manifest_check'] = 'PASS' if not mf else f'FAIL ({len(mf)})'
        s['tools_checked'] = tools_ok
        for sup in e.get('supersedes', []) or m.get('supersedes', []):
            if sup not in sealed_before:
                fails.append(f'L5 {v}: supersedes {sup}, which is not an earlier sealed version')
        if e.get('supersedes', []) != m.get('supersedes', []):
            fails.append(f'L5 {v}: ledger and manifest disagree on supersedes')
        ex = d / 'replay' / 'expected.sha256'
        if ex.exists():
            cf = m.get('class_files') or {}     # R26 merge: forensics-classes outputs, pinned but not re-derived by the replay
            want = ''.join(f'{h}  {k}\n' for k, h in sorted(m.get('files', {}).items()) if k.startswith('derived/') and k not in cf)
            if ex.read_text() != want:
                fails.append(f'L7 {v}: replay/expected.sha256 differs from its manifest derived/ entries')
            s['expected_sha256'] = 'equal' if ex.read_text() == want else 'differs'
        if e.get('sealed') is True:
            sealed_before.add(v)
        summ[v] = s
    if committed is not None:
        cv = committed.get('versions', [])
        if len(cv) > len(led) or [c.get('version') for c in cv] != names[:len(cv)]:
            fails.append('L6 the ledger does not extend the committed ledger (an entry was removed or reordered)')
        else:
            for c, e in zip(cv, led):
                if c.get('sealed') and (c != e):
                    fails.append(f"L6 {c.get('version')}: a sealed committed ledger entry was changed")
    return fails, summ


def check_record(rec, manifest_sha, tools_now):
    """G28's replay half: the run record must prove two byte-exact full PASS replays of THIS manifest."""
    if not rec:
        return ['G28 no replay run record']
    f = []
    if rec.get('manifest_sha256') != manifest_sha:
        f.append('G28 replay record is bound to another manifest (re-run replay.py --record)')
    runs = rec.get('runs', [])
    if len(runs) < 2:
        f.append(f'G28 {len(runs)} replay run(s) recorded, need 2')
    if len({r.get('cwd_tag') for r in runs}) < 2:
        f.append('G28 the replay runs do not come from two different cwds')
    if len({r.get('report_sha256') for r in runs}) != 1:
        f.append('G28 the replay reports are not byte-identical')
    if any(r.get('result') != 'PASS' for r in runs) or not runs:
        f.append('G28 a replay run did not PASS')
    if any(r.get('mode') != 'full' for r in runs) or not runs:
        f.append('G28 a replay run was partial (no tier B store or no archive copy)')
    rt = (rec.get('report') or {}).get('tools_sha256', {})
    if not rt or any(tools_now.get(k) != h for k, h in rt.items()):
        f.append('G28 a replay tool changed since the recorded runs')
    rep = rec.get('report') or {}
    txt = json.dumps(rep, indent=1, sort_keys=True) + '\n'
    if rep.get('result') != 'PASS' or sha(txt.encode()) not in {r.get('report_sha256') for r in runs}:
        f.append('G28 the stored report is not the one the runs hashed')
    return f


def g28(root=ROOT):
    root = Path(root)
    fx = root / 'forensics'
    if not fx.exists():
        return False, 'no forensics/ dataset (R25 requires dataset v1)'
    fails, summ = verify(fx, root, committed_ledger(root))
    newest = list(summ)[-1] if summ else None
    rp = root / RECORD
    rec = json.loads(rp.read_text()) if rp.exists() else None
    if newest:
        tools_now = {t: sha((root / t).read_bytes()) for t in (rec or {}).get('report', {}).get('tools_sha256', {})
                     if (root / t).exists()}
        fails += check_record(rec, summ[newest]['manifest_sha256'], tools_now)
    if fails:
        return False, f'{len(fails)} failure(s): ' + '; '.join(fails[:4])
    runs = rec['runs']
    vlist = ', '.join(k + ':' + v['manifest_check'] for k, v in summ.items())
    return True, (f"{len(summ)} version(s) re-verified ({vlist}); "
                  f"{newest} manifest {summ[newest]['manifest_sha256'][:12]}: {len(runs)} full replays byte-exact "
                  f"(report {runs[-1]['report_sha256'][:12]}), {rec['report']['rederive']['equal']}/"
                  f"{rec['report']['rederive']['expected']} derived files equal")


def write_ledger(fx, version, seal):
    fx = Path(fx)
    lp = fx / 'ledger.json'
    led = json.loads(lp.read_text()) if lp.exists() else {'versions': []}
    m = json.loads((fx / version / 'manifest.json').read_bytes())
    e = {'version': version, 'manifest_sha256': sha((fx / version / 'manifest.json').read_bytes()),
         'sealed': bool(seal), 'supersedes': m.get('supersedes', [])}
    vs = led['versions']
    for i, x in enumerate(vs):
        if x['version'] == version:
            if x.get('sealed'):
                raise SystemExit(f'{version} is sealed: a correction is a new version')
            vs[i] = e
            break
    else:
        vs.append(e)
    led['note'] = ('append-only ledger of forensic dataset versions (rft §0.8.1 rule 4); a sealed entry never changes; '
                   'verify_dataset.py checks every version against it')
    lp.write_text(json.dumps(led, indent=1, sort_keys=True) + '\n')
    return e


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('forensics'); ap.add_argument('--register'); ap.add_argument('--seal')
    ap.add_argument('--gate', action='store_true', help='also check the replay run record (G28)')
    a = ap.parse_args(argv)
    if a.register or a.seal:
        print(json.dumps(write_ledger(a.forensics, a.register or a.seal, bool(a.seal)), sort_keys=True))
    fx = Path(a.forensics).resolve()
    root = fx.parent
    if a.gate:
        ok, det = g28(root)
        print(('PASS' if ok else 'FAIL') + '  G28 dataset reproducible: ' + det)
        return 0 if ok else 8
    fails, summ = verify(fx, root, committed_ledger(root))
    print(json.dumps({'versions': summ, 'failures': fails, 'result': 'PASS' if not fails else 'FAIL'},
                     indent=1, sort_keys=True))
    return 0 if not fails else 8


if __name__ == '__main__':
    sys.exit(main())
