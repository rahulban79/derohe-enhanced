"""roundtracks.py — r24: the round registry's per-round tracks (harness/round.json rounds[current].tracks).

The user paused the miner-enhancement track in R24 (artifacts/dero-rft.md §0.3, §2.7): no live miner runs, so the checks
that read a live miner — gates G17 (miner_silent), G18 (the miner half: endpoint_down and the miner ALERT rules), G21
(the payout read) and the pipeline's A/B stages S4b minerbench / S4c gpubench — report an explicit PAUSED (miner)
outcome that cites §0.3, ONLY while the registry says so. The checks themselves are not weakened: each still runs and
its unchanged verdict is quoted in the PAUSED detail, and with tracks.miner 'active' or absent (or an unreadable
registry, or an unknown value) the exact pre-r24 behaviour holds — every doubt resolves to 'active', so a typo can
never silence a check; harness/kat/test_round_registry_r23c.py fails such a registry instead.

Shared by harness/run_gates.py (imported from kit/) and harness/pipeline/fix_build_verify.py (loaded by path). Pure
except load(); harness/kat/test_round_tracks_r24.py holds the KATs and the mutation proofs.
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
