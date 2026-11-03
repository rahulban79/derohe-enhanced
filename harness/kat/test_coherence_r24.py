#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the r24 cross-artifact coherence checker (harness/intel/coherence.py, G25).

Every KAT builds a small synthetic tree in a temp dir (round registry, version.go, a pipeline record, a live-window
capture, area registry + scorecard + proposals, disclosure track + model, the ledger page, src-arch, index, soundness
page, RUN_REPORT, ARCHITECTURE, SKILL, dero-rft.md, a stamp and a git history with an evolution tsv) on which the
checker PASSES, then plants ONE disagreement and requires a drift of the expected check. Nothing in the real tree is
read or written.

  CO1  the coherent fixture PASSES (negative control: a commit that only touches generated outputs is not missing
       from the evolution tsv)
  CO2  ledger html: a figure bound to a pipeline id differs from that run's record            -> pipeline
  CO3  ledger html: a disclosure verdict or state / an area state differs from the track / scorecard    -> disclosure, areas
  CO4  src-arch html: section-10 state, Areas state, scorecard run id, a live-window figure     -> disclosure, areas, live
  CO5  index: the current ledger page is not listed                                            -> index
  CO6  RUN_REPORT: wrong installed suffix; a closed backlog id said "still OPEN"               -> round, backlog
  CO7  ARCHITECTURE: a shadow figure differs from the record                                   -> pipeline
  CO8  SKILL: the round's section is missing; a KAT figure differs                             -> round, pipeline
  CO9  round.json: go_mutations differs from the mutate stage; version_suffix vs version.go    -> registry, round
  CO10 areas: areas.json status vs the scorecard; scorecard vs proposals run id                -> areas
  CO11 disclosure_track.json changed without re-emitting the model; model track_sha forged     -> disclosure
  CO12 dero-rft.md: header round, §1 round, §0.3 pause statement, §7 status vs the ledger      -> round, backlog
  CO13 a stale src-arch (a stamped source changed)                                             -> srcarch
  CO14 a round commit that changes a real file is missing from evolution_git.tsv               -> srcarch
  CO15 the current round's ledger page is missing                                              -> pages
  CO16 (r24 integration) observatory: a grade count / KPI stated next to a capture file differs from that capture
       (RUN_REPORT, ARCHITECTURE); a src-arch observatory section shows another capture time or grade count; the
       ledger's consensus-observatory section names an older capture; an artifact names a capture that is not there
                                                                                               -> observatory

Mutation proofs: each mutation weakens coherence.py on a temp copy; at least one KAT must then fail.
  python3 -I harness/kat/test_coherence_r24.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught. A mutation that crashes the checker is INVALID, not caught.
"""
import hashlib, json, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
MOD = HARNESS / 'intel/coherence.py'
RID = '20261102T110200'
AREAS_RUN = '20261102T123330'
TRACK = {'current_round': 'R24', 'rounds': ['R8', 'R24'],
         'claims': [{'id': 'C1', 'title': 'A soundness defect exists',
                     'history': [{'round': 'R8', 'verdict': 'CONFIRMED', 'state': 'open'},
                                 {'round': 'R24', 'verdict': 'CONFIRMED', 'state': 'upstream'}]},
                    {'id': 'C8', 'title': 'Supply effect',
                     'history': [{'round': 'R24', 'verdict': 'CANNOT-DETERMINE-LOCALLY', 'state': 'report-only'}]}]}


def w(root, rel, text):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def sha16(b):
    return hashlib.sha256(b).hexdigest()[:16]


def git(root, *a):
    return subprocess.run(['git', '-C', str(root), *a], capture_output=True, text=True, check=True).stdout


def model(track):
    return {'key': 'disclosure', 'track_sha': sha16(json.dumps(track, sort_keys=True).encode()),
            'rows': [{'kind': 'track-claim', 'track_id': c['id'],
                      'history': {h['round']: {'verdict': h['verdict'], 'state': h['state']} for h in c['history']}}
                     for c in track['claims']]}


def build(root):
    root = Path(root)
    w(root, 'harness/round.json', json.dumps({'current': 'r24', 'rounds': [
        {'id': 'r23c', 'status': 'measured', 'version_suffix': '22102026.r23c'},
        {'id': 'r24', 'status': 'implemented', 'version_suffix': '22102026.r24', 'pipeline_full': f'pipeline_{RID}',
         'go_mutations': '1108/1108', 'merge_commit': 'pending', 'head_after': 'pending', 'tracks': {'miner': 'paused', 'node': 'active'}},
        {'id': 'r25', 'status': 'planned', 'version_suffix': 'pending'}]}, indent=1))
    w(root, 'config/version.go', 'package config\nvar Version = semver.MustParse("3.6.0-153.DEROHE.STARGATE+22102026.r24")\n')
    recs = [{'stage': 'flaky', 'status': 'PASS', 'tests': 120, 'flaky': 0},
            {'stage': 'mutate', 'status': 'PASS', 'last': ['go mutations: 1108/1108 caught · upstream failures recorded 3']},
            {'stage': 'race', 'status': 'PASS', 'packages_ok': 26, 'races': 0},
            {'stage': 'shadow', 'status': 'PASS', 'blocks_compared': 120, 'treehash_compared': 240, 'mismatches': 0},
            {'stage': 'project', 'status': 'PASS', 'kats': '35/35', 'mutations': '34/34', 'gates': '22/25 (+3 PAUSED, miner)'}]
    w(root, f'harness/loop/runs/pipeline_{RID}.jsonl', ''.join(json.dumps(r) + '\n' for r in recs))
    w(root, 'harness/runtime/r23c_live_window_20261102.txt',
      'log bin/dero-miner.log from 2026-11-02T01:08 n 81\n'
      'H/s mean 94273 median 96297 min 86209 max 97651 | cores 17.37 | H/cpu-s 5435 | staged 87904 gpu_busy 95.6 | finds 28\n')
    w(root, 'harness/areas.json', json.dumps({'areas': [{'id': 'harness', 'status': 'active'},
                                                       {'id': 'miner', 'status': 'paused', 'track': 'miner'}]}))
    w(root, 'harness/runtime/area_intel.json', json.dumps({'run_id': AREAS_RUN, 'areas': [
        {'id': 'harness', 'title': 'Harness itself', 'state': 'OK'}, {'id': 'miner', 'title': 'Miner', 'state': 'PAUSED'}]}))
    w(root, 'harness/runtime/area_proposals.json', json.dumps({'run_id': AREAS_RUN, 'proposals': []}))
    w(root, 'harness/loop/disclosure_track.json', json.dumps(TRACK, indent=1))
    w(root, 'harness/model/raw/disclosure.json', json.dumps(model(TRACK)))
    pipe = f'pipeline_{RID}'
    w(root, 'artifacts/dero-r1-r24.html',
      '<html><body>\n'
      '<section id="r24"><h2>R24 +22102026.r24 node-only round</h2>\n'
      f'<p>Full run {pipe} PASS: mutations 1108/1108, race 26 packages 0 races, gates 22/25 + 3 PAUSED.</p>\n'
      '<ul><li>B18 compact-block observe: CLOSED in r24</li></ul></section>\n'
      '<!--disclosure-track:begin--><section id="disclosure"><table class="ev"><thead><tr><th>Claim</th><th>R8</th><th>R24</th><th>State now</th></tr></thead><tbody>\n'
      '<tr><td>C1 &middot; A soundness defect exists</td><td><span class="chip bad">CONFIRMED</span></td><td><span class="chip bad">CONFIRMED</span></td><td>upstream</td></tr>\n'
      '<tr><td>C8 &middot; Supply effect</td><td></td><td><span class="chip pending">CANNOT-DETERMINE-LOCALLY</span></td><td>report-only</td></tr>\n'
      '</tbody></table></section><!--disclosure-track:end-->\n'
      '<section id="areas" aria-labelledby="areas-h"><div class="areas">'
      '<article class="acard" id="area-harness"><h3>Harness itself</h3><div><span class="chip good">OK</span></div></article>\n'
      '<article class="acard paused" id="area-miner"><h3>Miner</h3><div><span class="chip pending">PAUSED</span></div></article>\n'
      '</div></section></body></html>\n')
    w(root, 'artifacts/dero-src-arch.html',
      '<html><body>\n<section id="press"><table id="t-dtrack"><thead><tr><th>Claim</th><th>verdict</th></tr></thead><tbody>\n'
      '<tr><td><b>C1 — A soundness defect exists</b></td><td><span class="mono">R8</span> <span class="chip">confirmed</span> '
      '<span class="mono">R24</span> <span class="chip">confirmed</span> now: upstream</td><td>x</td></tr>\n'
      '<tr><td><b>C8 — Supply effect</b></td><td><span class="mono">R24</span> <span class="chip">cannot determine locally</span> now: report-only</td><td>x</td></tr>\n'
      '</tbody></table></section>\n'
      f'<section id="areas"><p>Scorecard run {AREAS_RUN} (2026-11-02).</p><table><tbody>\n'
      '<tr><td>Harness itself <span>HARNESS</span></td><td>OK</td><td>harness</td></tr>\n'
      '<tr><td>Miner</td><td>PAUSED</td><td>miner</td></tr>\n</tbody></table></section>\n'
      '<p>Live r23c window 01:08–01:28: 94,273 H/s TOTAL mean, 5,435 H/cpu-s, GPU busy 95.6 % (baseline r23b 09:27–09:37: 5,164 H/cpu-s).</p>\n'
      '</body></html>\n')
    w(root, 'artifacts/dero-soundness-r23.html', '<html><body><p>soundness</p></body></html>\n')
    w(root, 'artifacts/index.html', '<html><body><p class="file"><code>artifacts/dero-src-arch.html</code></p>'
      '<p class="file"><code>artifacts/dero-r1-r24.html</code></p><p class="file"><code>artifacts/dero-soundness-r23.html</code></p></body></html>\n')
    w(root, 'RUN_REPORT.md', '# Run report\n\n## Round 24 (2026-11-02) — node-only round; installed as +22102026.r24\n\n'
      f'- Pipeline: {pipe} PASS, race 26 packages 0 races, shadow 120 blocks, 240 treehashes, 0 mismatches.\n'
      '- B18 (compact-block Observe) is CLOSED in r24.\n\n**Open after Round 24:** pending.\n')
    w(root, 'ARCHITECTURE.md', '# Architecture\n\n## 42. ★ Round 24 — the node-only round (+22102026.r24)\n\n'
      f'**42.8 Pipeline.** {pipe}: shadow 120 blocks, 240 treehashes, 0 mismatches; mutations 1108/1108.\n')
    w(root, '.skills/dero-miner-tuning/SKILL.md', '# skill\n\n## Round 24 (2026-11-02) — node only\n\n'
      f'- Installed as +22102026.r24 ({pipe}: KATs 35/35, harness mutations 34/34).\n')
    w(root, 'artifacts/dero-rft.md',
      '# DERO HE — the round prompt\n\n> The loop, now at **Round 24**.\n> - **Round registry:** current `r24` implemented; `r25` planned.\n\n'
      '## 0. The loop\n\n### 0.3 Paused tracks: miner enhancements\n\n**State: PAUSED until the user explicitly asks to resume.**\n\n'
      '## 1. The prompt to paste (Round 25)\n\nLedger dero-r1-r24.html.\n\n'
      '## 7. Consolidated OPEN backlog\n\n| # | Item | Dimension | Evidence anchor | Status |\n|---|---|---|---|---|\n'
      '| B18 | compact path Observe | p2p | anchor | CLOSED in r24 (SP24-1) |\n| B19 | FeesPerByte | txpool | anchor | OPEN |\n\n'
      '## 12. Update log\n\n### Round 24 — after implementation\n\nentry\n')
    # r24 (integration): the two observatories' outputs and the statements that quote them
    w(root, 'harness/runtime/consensus_capture_20261103T044707Z.txt', '# consensus_intel capture 20261103T044707Z\n'
      '# source live captured 2026-11-03T04:47:46+00:00\nkpi participants = 40\nkpi block_time_mean_s = 18.4\n'
      'summary OBSERVED=1 ANOMALY=1 NORMAL=16 NO-DATA=0\n')
    w(root, 'harness/runtime/consensus_capture_20261103T050817Z.txt', '# consensus_intel capture 20261103T050817Z\n'
      '# source live captured 2026-11-03T04:47:46+00:00\nkpi participants = 44\nkpi block_time_mean_s = 18.466\n'
      'summary OBSERVED=1 ANOMALY=1 NORMAL=16 NO-DATA=0\n')
    w(root, 'harness/runtime/consensus_intel.json', json.dumps({'captured': '2026-11-03T04:47:46+00:00',
                                                               'summary': {'OBSERVED': 1, 'ANOMALY': 1, 'NORMAL': 16, 'NO-DATA': 0}}))
    w(root, 'harness/runtime/peer_capture_20261102T210148.jsonl', json.dumps({'src': 'kpis', 'peers_active': 13, 'outgoing': 13,
      'incoming': 0, 'first_relay_top_share': 0.654, 'observed': 3, 'anomaly': 2}) + '\n')
    w(root, 'harness/runtime/peer_intel.json', json.dumps({'captured': '2026-11-02T21:01:48-08:00', 'capture_file': 'peer_capture_20261102T210148.jsonl',
                                                          'kpis': {'observed': 3, 'anomaly': 2}}))
    sub(root, 'artifacts/dero-src-arch.html', '</body></html>',
        '<section id="chainobs"><h2>Consensus observatory — chain</h2><p>Capture 2026-11-03T04:47:46+00:00, binary x.</p>'
        '<div class="kpis"><div class="kpi"><div class="kv">1</div><div class="kl">detectors OBSERVED</div></div>'
        '<div class="kpi"><div class="kv">1</div><div class="kl">detectors ANOMALY</div></div></div></section>\n'
        '<section id="peers"><h2>Consensus observatory — network peers</h2><p>Capture 2026-11-02T21:01:48-08:00 on x.</p>'
        '<div class="kpis"><div class="kpi"><div class="kv">3</div><div class="kl">detectors OBSERVED</div></div></div>'
        '<p>peer-0a1b2c3d ▲ ANOMALY 7848898 blocks behind us [harness/runtime/peer_capture_20261102T210148.jsonl:16]</p></section>\n</body></html>')
    sub(root, 'artifacts/dero-r1-r24.html', '</body></html>',
        '<section id="consensus-observatory"><p>Chain consensus_capture_20261103T050817Z.txt: OBSERVED 1 · ANOMALY 1 · NORMAL 16; '
        'peers peer_capture_20261102T210148.jsonl: OBSERVED 3 · ANOMALY 2.</p></section></body></html>')
    sub(root, 'RUN_REPORT.md', '**Open after Round 24:**', '- Consensus observatory (`harness/runtime/consensus_capture_20261103T050817Z.txt`): '
        'OBSERVED 1, ANOMALY 1, NORMAL 16; 44 participants, mean block time 18.466 s.\n\n**Open after Round 24:**')
    sub(root, 'ARCHITECTURE.md', 'mutations 1108/1108.\n', 'mutations 1108/1108.\n\n**42.10 Consensus observatory.** '
        '`peer_capture_20261102T210148.jsonl`: 13 out / 0 in, first-relay share 65.4 %, OBSERVED 3, ANOMALY 2.\n')
    sub(root, '.skills/dero-miner-tuning/SKILL.md', 'harness mutations 34/34).\n', 'harness mutations 34/34).\n'
        '- Read the observatory: `harness/runtime/consensus_capture_20261103T050817Z.txt` first.\n')
    w(root, 'src/main.go', 'package main\n')
    page = root / 'artifacts/dero-src-arch.html'
    w(root, 'harness/stamp.json', json.dumps({'root': str(root), 'bytes': page.stat().st_size, 'fingerprint': 'x',
                                              'sources': {str(root / 'src/main.go'): sha16((root / 'src/main.go').read_bytes())}}))
    w(root, 'notes.txt', 'notes\n')
    git(root, 'init', '-q')
    git(root, '-c', 'user.email=k@t', '-c', 'user.name=kat', 'add', '-A')
    git(root, '-c', 'user.email=k@t', '-c', 'user.name=kat', 'commit', '-qm', 'R24: merge')
    h = git(root, 'rev-parse', '--short', 'HEAD').strip()
    w(root, 'harness/runtime/evolution_git.tsv', f'# evolution\n# rule\n# head {h}; 1 commits\nC\t001\t{h}\tR24\t2026-11-02\tfiles=1\t+1\t-0\tR24: merge\n')
    git(root, '-c', 'user.email=k@t', '-c', 'user.name=kat', 'add', '-A')
    git(root, '-c', 'user.email=k@t', '-c', 'user.name=kat', 'commit', '-qm', 'R24 records: generated outputs only')


def sub(root, rel, old, new):
    p = Path(root) / rel
    t = p.read_text()
    assert old in t, f'fixture lacks {old!r} in {rel}'
    p.write_text(t.replace(old, new, 1))


def jedit(root, rel, fn):
    p = Path(root) / rel
    d = json.loads(p.read_text())
    fn(d)
    p.write_text(json.dumps(d))


def run(mod, root):
    r = subprocess.run([sys.executable, '-I', str(mod), '--root', str(root), '--json'], capture_output=True, text=True, timeout=120)
    if r.returncode not in (0, 4):
        raise RuntimeError(f'checker exit {r.returncode}: {(r.stdout + r.stderr)[-300:]}')
    d = json.loads(r.stdout)
    return r.returncode, {x['check'] for x in d['drifts']}, d


def commit_note(root):
    sub(root, 'notes.txt', 'notes', 'notes changed')
    git(root, '-c', 'user.email=k@t', '-c', 'user.name=kat', 'commit', '-qam', 'R24 tweak: a real change after the evolution snapshot')


def set_c1(d):
    d['claims'][0]['history'][-1]['verdict'] = 'PARTLY-CONFIRMED'


CASES = [  # (id, [(planted change, expected check)])
    ('CO2', [(lambda r: sub(r, 'artifacts/dero-r1-r24.html', 'mutations 1108/1108', 'mutations 1107/1108'), 'pipeline')]),
    ('CO3', [(lambda r: sub(r, 'artifacts/dero-r1-r24.html', '<td><span class="chip bad">CONFIRMED</span></td><td>upstream',
                            '<td><span class="chip warn">PARTLY-CONFIRMED</span></td><td>upstream'), 'disclosure'),
             (lambda r: sub(r, 'artifacts/dero-r1-r24.html', '</span></td><td>upstream</td>', '</span></td><td>open</td>'), 'disclosure'),
             (lambda r: sub(r, 'artifacts/dero-r1-r24.html', '<span class="chip good">OK</span>', '<span class="chip warn">WATCH</span>'), 'areas')]),
    ('CO4', [(lambda r: sub(r, 'artifacts/dero-src-arch.html', 'now: upstream', 'now: closed'), 'disclosure'),
             (lambda r: sub(r, 'artifacts/dero-src-arch.html', '<td>OK</td>', '<td>WATCH</td>'), 'areas'),
             (lambda r: sub(r, 'artifacts/dero-src-arch.html', f'Scorecard run {AREAS_RUN}', 'Scorecard run 20261102T010101'), 'areas'),
             (lambda r: sub(r, 'artifacts/dero-src-arch.html', '5,435 H/cpu-s', '5,453 H/cpu-s'), 'live')]),
    ('CO5', [(lambda r: sub(r, 'artifacts/index.html', '<p class="file"><code>artifacts/dero-r1-r24.html</code></p>', ''), 'index')]),
    ('CO6', [(lambda r: sub(r, 'RUN_REPORT.md', 'installed as +22102026.r24', 'installed as +22102026.r23c'), 'round'),
             (lambda r: sub(r, 'RUN_REPORT.md', 'is CLOSED in r24', 'still OPEN'), 'backlog')]),
    ('CO7', [(lambda r: sub(r, 'ARCHITECTURE.md', '240 treehashes', '238 treehashes'), 'pipeline')]),
    ('CO8', [(lambda r: sub(r, '.skills/dero-miner-tuning/SKILL.md', '## Round 24 (2026-11-02) — node only', '## Notes'), 'round'),
             (lambda r: sub(r, '.skills/dero-miner-tuning/SKILL.md', 'KATs 35/35', 'KATs 34/35'), 'pipeline')]),
    ('CO9', [(lambda r: jedit(r, 'harness/round.json', lambda d: d['rounds'][1].update(go_mutations='1107/1108')), 'registry'),
             (lambda r: jedit(r, 'harness/round.json', lambda d: d['rounds'][1].update(version_suffix='22102026.r24b')), 'round')]),
    ('CO10', [(lambda r: jedit(r, 'harness/areas.json', lambda d: d['areas'][1].update(status='active')), 'areas'),
              (lambda r: jedit(r, 'harness/runtime/area_proposals.json', lambda d: d.update(run_id='20261102T999999')), 'areas')]),
    ('CO11', [(lambda r: jedit(r, 'harness/loop/disclosure_track.json', set_c1), 'disclosure'),
              (lambda r: jedit(r, 'harness/model/raw/disclosure.json', lambda d: d.update(track_sha='deadbeefdeadbeef')), 'disclosure')]),
    ('CO12', [(lambda r: sub(r, 'artifacts/dero-rft.md', 'now at **Round 24**', 'now at **Round 23c**'), 'round'),
              (lambda r: sub(r, 'artifacts/dero-rft.md', '(Round 25)', '(Round 24)'), 'round'),
              (lambda r: sub(r, 'artifacts/dero-rft.md', '**State: PAUSED', '**State: ACTIVE'), 'round'),
              (lambda r: sub(r, 'artifacts/dero-rft.md', '| CLOSED in r24 (SP24-1) |', '| OPEN (verify) |'), 'backlog')]),
    ('CO13', [(lambda r: sub(r, 'src/main.go', 'package main', 'package main // edited'), 'srcarch')]),
    ('CO14', [(commit_note, 'srcarch')]),
    ('CO15', [(lambda r: (Path(r) / 'artifacts/dero-r1-r24.html').unlink(), 'pages')]),
    ('CO16', [(lambda r: sub(r, 'RUN_REPORT.md', 'OBSERVED 1, ANOMALY 1', 'OBSERVED 2, ANOMALY 1'), 'observatory'),
              (lambda r: sub(r, 'ARCHITECTURE.md', 'first-relay share 65.4 %', 'first-relay share 64.7 %'), 'observatory'),
              (lambda r: sub(r, 'artifacts/dero-src-arch.html', '<div class="kv">1</div><div class="kl">detectors ANOMALY', '<div class="kv">2</div><div class="kl">detectors ANOMALY'), 'observatory'),
              (lambda r: sub(r, 'artifacts/dero-src-arch.html', 'Capture 2026-11-02T21:01:48-08:00', 'Capture 2026-11-02T20:41:19-08:00'), 'observatory'),
              (lambda r: sub(r, 'artifacts/dero-r1-r24.html', 'Chain consensus_capture_20261103T050817Z.txt', 'Chain consensus_capture_20261103T044707Z.txt'), 'observatory'),
              (lambda r: sub(r, 'artifacts/dero-r1-r24.html', 'OBSERVED 3 · ANOMALY 2', 'OBSERVED 4 · ANOMALY 2'), 'observatory'),
              (lambda r: sub(r, '.skills/dero-miner-tuning/SKILL.md', 'consensus_capture_20261103T050817Z.txt` first', 'consensus_capture_20261103T999999Z.txt` first'), 'observatory')]),
]


def kats(mod, base, only=None):
    """[(id, ok, why)] for CO1..CO15 against the checker `mod`; each case works on a fresh copy of the fixture."""
    out = []
    with tempfile.TemporaryDirectory() as td:
        t = Path(td) / 'co1'
        shutil.copytree(base, t, symlinks=True)
        _fix_stamp(t)
        rc, checks, d = run(mod, t)
        out.append(('CO1', rc == 0 and not checks and d['facts'] >= 20, f"rc {rc} drifts {sorted(checks)} facts {d['facts']}"))
        for cid, plants in CASES:
            if only and cid not in only:
                continue
            ok, why = True, []
            for k, (plant, want) in enumerate(plants):
                t = Path(td) / f'{cid}_{k}'
                shutil.copytree(base, t, symlinks=True)
                _fix_stamp(t)
                plant(t)
                rc, checks, _ = run(mod, t)
                good = rc == 4 and want in checks
                ok &= good
                why.append(f'{want}:{"caught" if good else f"MISSED rc {rc} {sorted(checks)}"}')
            out.append((cid, ok, ', '.join(why)))
    return out


def _fix_stamp(t):
    """a copied fixture keeps its stamp valid: the stamp records absolute paths under the build root."""
    st = json.loads((t / 'harness/stamp.json').read_text())
    old = st['root']
    st['root'] = str(t)
    st['sources'] = {str(t) + p[len(old):]: h for p, h in st['sources'].items()}
    (t / 'harness/stamp.json').write_text(json.dumps(st))


MUTATIONS = [  # (KAT expected to catch it, old, new, what)
    ('CO2', "            return rec['mutate'], g", "            return g, g", 'the mutate figure is not compared'),
    ('CO7', "    ('treehashes', re.compile(r'(\\d+) treehashes')),", '', 'treehash figures are not extracted'),
    ('CO3', "            if tds[-1] != lat['state']:", "            if False:", 'the ledger disclosure state is not compared'),
    ('CO4', "            if got != state[aid]:", "            if False:", 'the src-arch area state is not compared'),
    ('CO4', "                    return pre[-1] == cap['start'] if pre else cap['file'] in u", "                    return False", 'live figures never bind'),
    ('CO5', "            if n not in links:", "            if False:", 'index links are not required'),
    ('CO6', "            if said != cls:", "            if False:", 'backlog statements are not compared'),
    ('CO8', "                c.drift('round', f, None, f'a Round {lab} section', 'none', f'harness/round.json {cur} status {c.status}')",
     "                pass", 'a missing round section is not reported'),
    ('CO9', "    if 'mutate' in rec and '/'.join(map(str, rec['mutate'])) != gm:", "    if False:", 'registry go_mutations not compared'),
    ('CO10', "        if json.loads(pt).get('run_id') != ai.get('run_id'):", "        if False:", 'proposals run id not compared'),
    ('CO11', "        if md.get('track_sha') != want:", "        if False:", 'the disclosure model sha is not compared'),
    ('CO12', "                if mm.group(1) != want:", "                if False:", 'the §1 round is not compared'),
    ('CO13', "        if sha(q) != h:", "        if False:", 'stamp sources are not re-hashed'),
    ('CO14', "    if missing:\n        c.drift('srcarch'", "    if False:\n        c.drift('srcarch'", 'missing round commits are not reported'),
    ('CO14', "        if any(h.startswith(x) or x.startswith(h) for x in have):", "        if True:", 'every round commit counts as present'),
    ('CO1', "        real = [f for f in fs if not is_generated(f)]", "        real = fs", 'generated-only commits count as missing (control)'),
    ('CO15', "            c.drift('pages', c.ledger, None, f'the ledger page of round {c.cur} ({c.status})', 'missing', 'harness/round.json current')",
     "            pass", 'a missing ledger page is not reported'),
    ('CO16', "                    c.drift('observatory', f, ln, f'{name} in harness/runtime', 'missing (dangling capture id)', 'harness/runtime/')",
     "                    pass", 'a dangling capture id is not reported (r24 integration)'),
    ('CO1', "GRADE_N = r'\\b{}:? (\\d{{1,2}})(?!\\d|[.,]\\d|\\s*(?:blocks?|ms|s\\b|%|x\\b|times|lines|peers))'", "GRADE_N = r'\\b{}:? (\\d+)\\b'",
     "a finding's value ('ANOMALY 7848898 blocks behind') is read as a grade count (r24 integration, control)"),
    ('CO16', "                        if not same:", "                        if False:", 'a figure next to a capture file is not compared (r24 integration)'),
    ('CO16', "        if not cm or cm.group(1) != str(doc.get('captured')):", "        if False:", 'a src-arch observatory section may show another capture (r24 integration)'),
    ('CO16', "                if int(m.group(1)) != int(grades[g]):", "                if False:", 'src-arch observatory grade counts are not compared (r24 integration)'),
    ('CO16', "                if want not in seg:", "                if False:", 'the ledger observatory section may name an older capture (r24 integration)'),
    ('CO1', "                        pre = [n for o, n in known if o < m.start()]", "                        pre = []", 'figures bind to the first capture named, not the nearest: a coherent two-capture block drifts (r24 integration, control)'),
]


def main():
    fails = missed = 0
    with tempfile.TemporaryDirectory() as td:
        base = Path(td) / 'base'
        base.mkdir()
        build(base)
        res = kats(MOD, base)
        for cid, ok, why in res:
            print(f"{'ok  ' if ok else 'FAIL'} {cid}: {why}")
            fails += not ok
        src = MOD.read_text()
        for cid, old, new, what in MUTATIONS:
            if old not in src:
                print(f'MISSED {cid}: mutation target not found ({what})')
                missed += 1
                continue
            mp = Path(td) / f'mut_{len(old)}_{abs(hash(old)) % 10**6}.py'
            mp.write_text(src.replace(old, new, 1))
            try:
                r = dict((k, ok) for k, ok, _ in kats(mp, base, only={cid}))
                caught = not r.get(cid, True)
                verdict = 'CAUGHT' if caught else 'MISSED'
            except Exception as e:                                     # noqa: BLE001 — a crash proves nothing: INVALID
                caught, verdict = False, f'INVALID ({type(e).__name__})'
            missed += not caught
            print(f'{verdict} {cid}: {what}')
    print(f'\nr24 coherence KATs: {len(res) - fails}/{len(res)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
