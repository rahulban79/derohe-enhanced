"""roundtracks.py — r24: the round registry's per-round tracks (harness/round.json rounds[current].tracks).

The user paused the miner-enhancement track in R24 (artifacts/dero-rft.md §0.3, §2.7): no live miner runs, so the checks
that read a live miner — gates G17 (miner_silent), G18 (the miner half: endpoint_down and the miner ALERT rules), G21
(the payout read) and the pipeline's A/B stages S4b minerbench / S4c gpubench — report an explicit PAUSED (miner)
outcome that cites §0.3, ONLY while the registry says so. The checks themselves are not weakened: each still runs and
its unchanged verdict is quoted in the PAUSED detail, and with tracks.miner 'active' or absent (or an unreadable
registry, or an unknown value) the exact pre-r24 behaviour holds — every doubt resolves to 'active', so a typo can
never silence a check; harness/kat/test_round_registry_r23c.py fails such a registry instead.

Shared by harness/run_gates.py (imported from kit/), harness/pipeline/fix_build_verify.py and (r27)
harness/intel/metrics_intel.py (both loaded by path). Pure except load(); harness/kat/test_round_tracks_r24.py holds the
KATs and the mutation proofs, harness/kat/test_harness_measure_r27.py the r27 exit-code ones.
"""
import json
from pathlib import Path

TRACKS = ('miner', 'node')                      # r24: the tracks a round may name
TRACK_VALUES = ('active', 'paused')
PAUSED = 'PAUSED'                               # the third gate/stage outcome, next to PASS and FAIL
PAUSE_REF = 'artifacts/dero-rft.md §0.3'
PAUSABLE_GATES = ('G17', 'G18', 'G21')          # the gates that read a live miner (§0.3)
PAUSABLE_STAGES = ('minerbench', 'gpubench')    # S4b, S4c
# r24: the sources whose change makes a paused S4b/S4c run anyway — a miner change is out of scope while paused
# (§0.3), so if one appears the A/B evidence is required exactly as before
MINER_PATHS = ('cmd/dero-miner', 'astrobwt', 'gpu-miner-poc')
# r25 (B49): the miner BINARY is also built from node packages (`go list -deps ./cmd/dero-miner`: config, rpc, block,
# transaction, globals, metrics, cryptography/*, glue/httpguard, tools/dashboard at 17da0dc), so a node-side change to
# one of them changes the miner too; while paused, such a change runs S4b/S4c as a miner change does. A package's
# non-test .go files in its own directory count (not its subdirectories: rpc/ is a dependency, cmd/derod/rpc/ is not).
# config/version.go changes every round with the version string only; a diff that touches nothing else is exempt.
MINER_DEPS_CMD = ['go', 'list', '-deps', '-f', '{{if .Module}}{{if .Module.Main}}{{.Dir}}{{end}}{{end}}', './cmd/dero-miner']
VERSION_FILE = 'config/version.go'
# r25 (verify): the module build inputs are miner inputs too. The miner imports 30 vendored third-party packages
# (`go list -deps ./cmd/dero-miner` at 17da0dc) and MINER_DEPS_CMD lists first-party dirs only, so a go.mod / go.sum /
# vendor/ change rebuilt the miner without running S4b/S4c. Any such change counts (conservative: vendor/ moves rarely).
MODULE_INPUTS = ('go.mod', 'go.sum', 'vendor/modules.txt')


def miner_dep_dirs(go_list_out, root):
    """repo-relative package dirs of the miner's first-party dependencies from MINER_DEPS_CMD output. Pure."""
    root = str(root).rstrip('/') + '/'
    out = set()
    for l in str(go_list_out or '').splitlines():
        l = l.strip()
        if l.startswith(root):
            out.add(l[len(root):].strip('/'))
        elif l == root.rstrip('/'):
            out.add('')
    return sorted(out)


def version_only(diff_text):
    """True when a unified diff of config/version.go changes only the `var Version = semver.MustParse(...)` line. Pure."""
    ch = [l for l in str(diff_text or '').splitlines()
          if l[:1] in '+-' and not l.startswith(('+++', '---'))]
    return bool(ch) and all('semver.MustParse(' in l and 'Version' in l for l in ch)


def miner_relevant(paths, dep_dirs, version_is_only=False):
    """the changed paths that change the miner: anything under MINER_PATHS, a module build input (MODULE_INPUTS, or
    a non-test source under vendor/), or a non-test .go file (or a C/asm source) directly inside one of `dep_dirs`; config/version.go is skipped when `version_is_only`. Pure."""
    deps = set(dep_dirs or [])
    out = []
    for p in paths:
        if p.startswith(tuple(m + '/' for m in MINER_PATHS)) or p in MINER_PATHS:
            out.append(p)
            continue
        if p in MODULE_INPUTS or (p.startswith('vendor/') and p.endswith(('.go', '.c', '.h', '.s'))
                                  and not p.endswith('_test.go')):
            out.append(p)   # r25 (verify): a module / vendored-source change rebuilds the miner
            continue
        d, _, f = p.rpartition('/')
        if d not in deps or f.endswith('_test.go') or not f.endswith(('.go', '.c', '.h', '.s')):
            continue
        if p == VERSION_FILE and version_is_only:
            continue
        out.append(p)
    return sorted(out)


def load(path):
    """the registry dict from `path`, or None when it is missing or unreadable"""
    try:
        reg = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None
    return reg if isinstance(reg, dict) else None


def current_round(reg):
    if not isinstance(reg, dict):
        return None
    return next((r for r in reg.get('rounds') or [] if isinstance(r, dict) and r.get('id') == reg.get('current')), None)


def track_state(reg, track='miner'):
    """(state, why) of one track of the CURRENT round: 'paused' only when the registry literally says 'paused';
    everything else — no registry, no current round, no tracks, no entry, an unknown value — is 'active'. Pure."""
    cur = current_round(reg)
    if cur is None:
        return 'active', 'no registry or no current round: the track runs (pre-r24 behaviour)'
    tr = cur.get('tracks')
    if tr is None:
        return 'active', f"rounds[{cur.get('id')}] names no tracks: the track runs (pre-r24 behaviour)"
    v = tr.get(track) if isinstance(tr, dict) else None
    if v == 'paused':
        return 'paused', f"harness/round.json rounds[{cur.get('id')}].tracks.{track} = 'paused' ({PAUSE_REF})"
    if v in (None, 'active'):
        return 'active', f"rounds[{cur.get('id')}].tracks.{track} = {v!r}: the track runs"
    return 'active', (f"rounds[{cur.get('id')}].tracks.{track} = {v!r} is not one of {TRACK_VALUES}: treated as active "
                      '(the check runs); the registry KAT fails this registry')


def track_problems(reg):
    """registry errors about tracks: a round's `tracks` must be an object naming only known tracks, each 'active' or
    'paused'. Pure (round_problems in fix_build_verify adds these to its own)."""
    err = []
    for r in (reg.get('rounds') or []) if isinstance(reg, dict) else []:
        if not isinstance(r, dict) or 'tracks' not in r:
            continue
        tr, rid = r['tracks'], r.get('id')
        if not isinstance(tr, dict):
            err.append(f'{rid}: tracks must map track -> active|paused, not {type(tr).__name__}')
            continue
        for k, v in tr.items():
            if k not in TRACKS:
                err.append(f'{rid}: tracks.{k} is not a known track {TRACKS}')
            if v not in TRACK_VALUES:
                err.append(f'{rid}: tracks.{k} = {v!r} not in {TRACK_VALUES}')
    return err


def gate_id(name):
    """'G17 the live miner is healthy' -> 'G17'"""
    return str(name).split(' ', 1)[0]


def gate_outcome(name, ok, detail, state, why):
    """(ok, detail) of one gate after the track rule. A pausable gate while the miner track is paused reports PAUSED
    and quotes the unchanged check's verdict; anything else is returned untouched. Pure."""
    if state != 'paused' or gate_id(name) not in PAUSABLE_GATES:
        return ok, detail
    return PAUSED, f"PAUSED (miner): {why}; the unchanged check said {'PASS' if ok else 'FAIL'}: {detail}"


def word(ok):
    """the ledger word of a gate outcome: PAUSED, else PASS/FAIL by truth (the pre-r24 rule)"""
    return PAUSED if ok == PAUSED else ('PASS' if ok else 'FAIL')


def all_ok(results):
    """run_gates exit rule: every gate PASSED or was PAUSED"""
    return all(ok == PAUSED or bool(ok) for _, ok, _ in results)


def stage_paused(state, changed):
    """(paused, why) for S4b/S4c: paused only while the miner track is paused AND no miner source changed since the
    round's base (`changed`: the changed paths under MINER_PATHS; None = could not tell, which runs the stage). Pure."""
    if state != 'paused':
        return False, 'miner track active: the A/B runs'
    if changed is None:
        return False, 'miner track paused but the miner-source diff could not be read: the A/B runs'
    if changed:
        return False, (f'miner track paused but miner sources changed since the round base ({sorted(changed)[:5]}): '
                       'a miner change is out of scope while paused (§0.3), so its A/B evidence is required: the A/B runs')
    return True, f'PAUSED (miner): {PAUSE_REF}; no miner source changed since the round base'


def gate_tally(lines, state):
    """S7: (passed, paused, bad) over one run's GATES.md rows. A PAUSED row counts only for a pausable gate while the
    miner track is paused; any other PAUSED row is bad (a gate that paused when it may not). Pure."""
    passed, paused, bad = 0, 0, []
    for l in lines:
        cells = [c.strip() for c in l.split('|')]
        g, res = (cells[3], cells[4]) if len(cells) > 4 else ('', '')
        if res == 'PASS':
            passed += 1
        elif res == PAUSED and state == 'paused' and gate_id(g) in PAUSABLE_GATES:
            paused += 1
        else:
            bad.append(g)
    return passed, paused, bad


# r27 (harness-measure): the metrics_intel ALERT rules about the miner (moved here from run_gates.py, which imports
# them, so the snapshot's exit code and G18 split the alerts with ONE classifier). Every other ALERT is the node's.
MINER_ALERT_RULES = ('miner_disconnected', 'split_disabled', 'gpu_mismatch', 'no_hashing', 'miner_behind')


def miner_alert(a):
    """True for an ALERT about the miner: one of MINER_ALERT_RULES, or endpoint_down naming the miner. Pure."""
    return a.get('rule') in MINER_ALERT_RULES or (a.get('rule') == 'endpoint_down' and str(a.get('what', '')).startswith('miner '))


def metrics_exit(alerts, up, state):
    """(rc, why, paused) of one metrics_intel snapshot: 2 when neither endpoint answered; 7 when a node ALERT fired, or
    a miner ALERT while the miner track is not paused; else 0. While paused (rft §0.3) a miner ALERT is reported as
    PAUSED (miner) in `paused` (the alert itself stays in the snapshot, so G18 still quotes it) and does not set 7.
    Before r27 every snapshot exited 7 while paused (the absent miner's endpoint_down), so S7 could not tell a real
    derod ALERT (not_synced, tip_age > 600 s) from the pause by the exit code. Pure."""
    if not any((up or {}).values()):
        return 2, 'neither /metrics endpoint answered', []
    al = [a for a in alerts or [] if a.get('level') == 'ALERT']
    node = [a['rule'] for a in al if not miner_alert(a)]
    miner = [a['rule'] for a in al if miner_alert(a)]
    paused = miner if state == 'paused' else []
    if node:
        return 7, f'node ALERT {sorted(set(node))}', paused
    if miner and state != 'paused':
        return 7, f'miner ALERT {sorted(set(miner))} (miner track active)', paused
    if paused:
        return 0, f'PAUSED (miner): {PAUSE_REF}; miner ALERT {sorted(set(paused))} not counted', paused
    return 0, 'no ALERT', paused
