#!/usr/bin/env python3
"""run_gates.py — closed-loop eval gates for artifacts/dero-src-arch.html (Evidence-Loop Protocol §4.4).

  G1  every rendered anchor resolved       stamp: anchors_ok == anchors, no row drawn without one
  G2  the tree really says so              re-read every cited line from disk and re-match the quote
  G3  corpus is current                    prep_corpus.py --check
  G4  svg text-fit lint = 0                no label wider than its own viewBox
  G5  page script parses                   node --check on the concatenated inline scripts
  G6  HTML tag balance                     html.parser stack, void elements excluded
  G7  render probes                        headless Chrome at 1280 px and 480 px: no un-contained horizontal
                                           overflow, zero uncaught JS errors, connector hover-trace + ordered
                                           play (connectorkit), the index answers a query, a filter hides rows
  G8  projection gate                      `check` CURRENT and `selftest` PASS
  G9  the daemon still agrees              the live node's version and chain match what the page says
  G10 asset class tags                     assetkit.audit: every asset carries SRC|EXT|HARNESS|GK|PLAN, none UNK
  G11 no cut sentence                      textkit.audit on the page AND on Chrome's rendered DOM
  G12 citations behind tags                assetkit.cite_audit + browser: hover opens the panel, click pins, Esc closes
  G13 consensus guard                      consensus_guard.evaluate(): changed consensus-package lines are logging-only
  G14 datadir integrity                    newest harness/runtime/datadir_*.json has no FAIL and is < 24 h old
  G15 log health of the current run        newest logintel snapshot: the current run fires no ALERT rule
  G16 risk coverage does not drop          ratchet: no risk function covered by any earlier snapshot is uncovered now
  G17 the live miner is healthy            newest minerintel snapshot (< 24 h): the current miner run fires no ALERT rule
                                           (GPU/CPU mismatch, split or sort disabled, silent, share drought); the detail
                                           names the run's version vs the tree's, its window and the log files read;
                                           R21: names the split regime (cpu-sort-bound / gpu-bound / balanced) and
                                           FAILS when a split run of THIS tree's build logs no CPU-backlog counter
                                           (r20+ always logs feeder_cpu_backlog_ms: a missing counter is broken reporting)
  G18 the live dashboard agrees            newest metrics snapshot (harness/intel/metrics_intel.py, < 24 h): both
                                           /metrics endpoints answered and no ALERT (sync, tip age, miner connected and
                                           on derod's height, hashes advancing, split enabled); R21: a split miner of
                                           THIS tree's build must export the regime counters (backlog/ring/idle)
  G19 the binding resource is known       R22: newest metrics snapshot (< 24 h): a split miner of THIS tree's build
                                           names its binding resource (co-bound / gpu-bound / cpu-sort-bound /
                                           ring-bound / balanced) from the GPU duty, CPU-sort backlog and ring-full
                                           fractions; the GPU duty is recomputed from the snapshot's raw counter pair
                                           and the label from the fractions (shared classifier), so a label that
                                           disagrees with its own numbers, or a missing GPU-busy counter, fails
  G20 no claim from a contended box       R23: the newest metrics snapshot carries a foreign-process census (names only);
                                           when it says contended, the snapshot must say so (box_contended WARN,
                                           regression_claims refused); the newest minerintel snapshot may not fire
                                           hashrate_sag while its own census says contended (that is cpu_starved); and the
                                           newest pipeline's S4b/S4c may not PASS or FAIL on a ratio from a contended box:
                                           a contended A/B is REFUSED (correctness checks still FAIL)
  G21 the payout ledger holds             R23: the newest minerruns snapshot (< 24 h): every L-check passes, and the payout
                                           ledger is present and recomputable (paid DERO = paid x per-miniblock reward,
                                           expected inside or outside its own Poisson interval as the verdict says)
  G22 the soundness page is backed      R23b: every claim unit of the current round's soundness page (each <p>, <li>, figure,
                                           r25: artifacts/dero-soundness-<current>.html, named by harness/kit/soundpage.py;
                                           tile, code line) is classified in loop/SOUNDNESS_CLAIMS.json; every CODE claim
                                           (height-bound proof skip, pinned nonce bypass, already-mined guard, validity
                                           window 11, TXID scope, CalcSupply, emission auditor) is backed by a named test
                                           that ran PASS in loop/SOUNDNESS_LAST.json on unchanged files, a source anchor
                                           re-read from disk, a recomputation, or a live read-only RPC check (soundness.py)
  R23b G17 also recomputes the binding label from the run's own fractions (shared classifier) and names it beside the
       backlog-only regime label; G20 judges A/Bs from loop/PIPELINE_FULL_LAST.json when the newest record is a partial
       run (project-only) and FAILS when no record holds an A/B stage; G21 also recomputes the idle-gap ledger.
  r24 G17/G18/G21 report PAUSED (miner) while harness/round.json rounds[current].tracks.miner == 'paused'
       (artifacts/dero-rft.md §0.3; kit/roundtracks.py): the unchanged check still runs and its verdict is quoted;
       G18's derod half is still judged (derod down or a derod ALERT FAILS it); G20 counts a PAUSED A/B stage only
       while paused. With the track 'active' or absent every gate behaves exactly as before.
  r24 G25 the artifacts agree with their canonical sources (harness/intel/coherence.py; the index page is judged by
       the S7 step after gen_index.py instead).
  r24 G26 the chain-consensus observatory is fresh, graded and anchored (harness/intel/consensus_intel.py g26): a live
       capture < 24 h old, all 20 detectors (r25: + D19, D20) graded OBSERVED/ANOMALY/NORMAL/NO-DATA, rule and row anchors re-read, no
       address/IP literal in harness/runtime/consensus_intel.json or the newest consensus_capture_*.txt.
  r24 G27 the peer observatory is fresh, private and anchored (harness/intel/peer_intel.py g27; consensus-network dim):
       newest peer_intel.json < 24 h, its capture unchanged, no IP or private tag in its outputs or the rendered 'peers'
       section, every peers row anchored, no detector graded without its code rule line; r24 integration: no peer
       address (non-reserved IPv4) and no private string anywhere in dero-src-arch.html, model/verified.json or the
       log-derived raw files (kit/privkit.py page_ip_leaks).
  r25 G28 the forensic dataset is reproducible (harness/forensics/verify_dataset.py g28; forensics-replay, B77): every
       version under forensics/ re-verifies byte for byte against forensics/ledger.json (sealed manifests unchanged),
       and harness/runtime/forensics_replay.json holds >= 2 full replay.py PASS runs of the newest manifest from
       distinct cwds with byte-identical reports.
  r25 G29 the forensic dataset is independently audited (harness/forensics/audit_check.py g29; forensics-audit, B78): the
       newest version's audit/ (audit_report.json, challenges.json, AUDIT.md) is bound to its current data, every FAILS or
       UNRESOLVED challenge is reflected in a non-PROVEN verdict, no PROVEN verdict rests on EXT, A1-A4 are challenged, and
       the dataset text carries no exploit or private content (KAT MF3, MF4). r26 (forensics-audit2): EVERY ledger version
       carries its own audit (v2 by harness/forensics/audit2.py, challenges D2-01.., required per version), each bound to
       its current data (KAT test_forensics_audit2_r26.py AU10-AU12).
  r25 G30 the forensics frontend traces to the dataset (harness/forensics/facts.py g30; B79): every number in the ledger's
       forensics sections (<!--forensics:begin/end-->) and in the src-arch "Forensic dataset" line is a fact span naming
       its dataset file and SHA-256 (= the manifest entry) and showing the value re-derived now; no untraced number; the
       window explorer's embedded data decodes to derived/window.jsonl.gz (KAT test_forensics_g30_r25.py).
  r26 G31 forensic figures carry their class bound (harness/forensics/bounds.py g31; forensics-classes, B108): every figure
       of forensics/r<N>/derived/classes.json has {class, scope, coverage num/den + anchors, bound_type}; exact only at full
       coverage and never DC2; unbounded renders as the word, never 0; no total for a bound; no cross-class sum; a fix
       status never regrades history; forbidden phrases only negated; no amount-recovery or exploit text in the four
       class files; invariant anchors re-read; every page class block traces to classes.json (KAT test_forensics_bounds_r26.py).
  r26 G32 defect classes are separated and their presence re-read (harness/forensics/bounds.py g32; B109): one class per
       tagged record and figure; DC1-DC3 presence entries at HEAD re-read unchanged (presence.py check); the DC2-present
       headline on the ledger, soundness and src-arch pages from the round's first ledger render (KAT test_forensics_classes_r26.py).
Appends one row per gate to loop/GATES.md. Exit 0 all pass (or PAUSED) · 3 any fail.  Usage: run_gates.py [cycle-label]
"""
import datetime, html, html.parser, json, re, subprocess, sys, tempfile, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'kit'))
sys.path.insert(0, str(HERE))
import assetkit as ak            # noqa: E402
import connectorkit as ck        # noqa: E402
import textkit as tk             # noqa: E402
import roundtracks as RT         # noqa: E402  r24: the paused miner track (artifacts/dero-rft.md §0.3)
import privkit                   # noqa: E402  r24: pseudonymised peer addresses, masked anchor matching
from gen_deroarch import OUT as PAGE, STAMP, MODEL, abspath, norm, relocate, stamp_root   # noqa: E402

PY = sys.executable
CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr',
        'path', 'rect', 'line', 'circle', 'polygon', 'polyline', 'stop', 'use', 'ellipse', 'feGaussianBlur',
        'feMerge', 'feMergeNode', 'feColorMatrix', 'animate'}

PROBE = ("<script>" + ck.PROBE_HEAD +
         "window.__errs=[];addEventListener('error',function(e){window.__errs.push(String(e.message)+' @'+e.lineno);});</script>")
CITE_JS = ("var bt={unk:document.querySelectorAll('.ct-UNK').length,cite:{}};"
           "['span.ct[data-ci]:not(.ct-nocite)','g.ct[data-ci]:not(.ct-nocite)'].forEach(function(sel,k){"
           "var p=document.querySelector(sel);if(!p)return;"
           "p.dispatchEvent(new PointerEvent('pointerover',{bubbles:true}));"
           "var b=document.getElementById('ak-cite'),a=b?b.querySelectorAll('a[href]'):[];"
           "var good=[].filter.call(a,function(x){return /^(vscode:\\/\\/file\\/|https:\\/\\/)/.test(x.getAttribute('href'));}).length;"
           "p.dispatchEvent(new MouseEvent('click',{bubbles:true}));"
           "var pinned=!!(b&&b.classList.contains('on')&&/pinned/.test(b.textContent));"
           "document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape'}));"
           "bt.cite[k?'svg':'html']={open:!!(b&&a.length),links:a.length,good_links:good,pinned:pinned,"
           "closed:!!(b&&!b.classList.contains('on'))};});")
INDEX_JS = ("var ix={};try{var q=document.getElementById('sx-q');if(q){q.value='difficulty';"
            "q.dispatchEvent(new Event('input'));ix.hits=document.querySelectorAll('#sx-res .sx-hit').length;"
            "ix.facets=document.querySelectorAll('#sx-facets .sx-f').length;q.value='';q.dispatchEvent(new Event('input'));}"
            "var f=document.querySelector('input[data-filter=\"t-pkg\"]'),t=document.getElementById('t-pkg');"
            "if(f&&t){var n0=[].filter.call(t.tBodies[0].rows,function(r){return r.style.display!=='none';}).length;"
            "f.value='walletapi';f.dispatchEvent(new Event('input'));ix.filter_before=n0;"
            "ix.filter_after=[].filter.call(t.tBodies[0].rows,function(r){return r.style.display!=='none';}).length;"
            "f.value='';f.dispatchEvent(new Event('input'));}}catch(e){ix.err=String(e);}")
PROBE_END = (r"""<script>addEventListener('load',function(){""" + ck.PROBE_START_JS + r"""setTimeout(function(){
var W=document.documentElement.clientWidth,o=[];
document.querySelectorAll('body *').forEach(function(e){var r=e.getBoundingClientRect();if(r.width&&r.right>W+1){
var p=e.parentElement,ok=false;while(p){var cs=getComputedStyle(p);
if(cs.overflowX=='auto'||cs.overflowX=='scroll'||cs.overflowX=='hidden'){ok=true;break;}p=p.parentElement;}
if(!ok)o.push(e.tagName+'.'+(e.getAttribute('class')||'')+' r='+Math.round(r.right));}});
""" + CITE_JS + INDEX_JS + ck.PROBE_COLLECT_JS + r"""
var d=document.createElement('pre');d.id='PROBE';
d.textContent=JSON.stringify({W:W,overflow:o.slice(0,25),errors:window.__errs,trace:tr,tags:bt,index:ix});
document.body.appendChild(d);},500);});</script>""")


class Bal(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.st, self.err = [], []

    def handle_starttag(self, t, a):
        if t not in VOID:
            self.st.append(t)

    def handle_startendtag(self, t, a):
        pass

    def handle_endtag(self, t):
        if t in VOID:
            return
        if self.st and self.st[-1] == t:
            self.st.pop()
        elif t in self.st:
            while self.st and self.st[-1] != t:
                self.err.append(f'unclosed <{self.st.pop()}> before </{t}>')
            self.st.pop()
        else:
            self.err.append(f'stray </{t}>')


def g17_regime_ok(cur, tree_ver):
    """R21: an r20+ split run logs feeder_cpu_backlog_ms in every 'GPU split' window, so a split run of THIS tree's
    build whose regime has windows but no backlog fraction is broken reporting (G17 fails). Older builds are exempt."""
    sp = cur.get('split') or {}
    rg = sp.get('regime') or {}
    return not (sp.get('lines') and cur.get('version') and cur.get('version') == tree_ver and rg.get('windows')
                and rg.get('cpu_backlog_fraction') is None)


def g18_regime_ok(m, tree_ver):
    """R21: a split miner (split_share > 0) of THIS tree's build must export the regime counters on /metrics"""
    rg = m.get('split_regime') or {}
    return not (m.get('split_share') and tree_ver and m.get('version') == tree_ver
                and (rg.get('cpu_backlog_fraction') is None or rg.get('idle_tries_per_min') is None))


def _classifier():
    """miner_intel.classify_binding from THIS harness (the one metrics_intel used), loaded by path"""
    import importlib.util
    spec = importlib.util.spec_from_file_location(f'miner_intel_for_gates_{id(HERE)}', HERE / 'intel/miner_intel.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m.classify_binding


def g19_binding(mt, tree_ver, classify=None):
    """R22: (ok, detail) for the newest metrics snapshot `mt`. Exempt (ok): no miner, full mode, or another build.
    A split miner of this tree's build must carry split_binding with a GPU-busy fraction; that fraction must equal the
    raw counter pair's rate (+-0.002) and the label must equal the shared classifier's verdict on the stored fractions."""
    m = (mt or {}).get('miner') or {}
    if not m.get('split_share') or not tree_ver or m.get('version') != tree_ver:
        return True, f"exempt (split_share {m.get('split_share')}, version {m.get('version')}, tree {tree_ver})"
    bd = m.get('split_binding') or {}
    if not bd or bd.get('gpu_busy_fraction') is None:
        return False, 'split miner of this build without a GPU-busy reading: the binding resource is unknown'
    raw = (mt.get('raw') or {})
    gp, t = raw.get('miner_split_gpu_busy_s') or [None, None], raw.get('t') or [None, None]
    if None in gp or None in t or t[1] <= t[0]:
        return False, 'no raw GPU-busy counter pair: the binding fraction cannot be recomputed'
    re_busy = (gp[1] - gp[0]) / (t[1] - t[0])
    if abs(re_busy - bd['gpu_busy_fraction']) > 0.002:
        return False, f"gpu_busy_fraction {bd['gpu_busy_fraction']} but the raw pair says {re_busy:.4f}"
    want = (classify or _classifier())(bd['gpu_busy_fraction'], bd.get('cpu_backlog_fraction'), bd.get('ring_full_fraction'),
                                       bd.get('cpu_budget_fraction'))['binding']
    if want != bd.get('binding'):
        return False, f"label {bd.get('binding')} disagrees with its own fractions ({want})"
    return True, (f"binding {bd['binding']} · GPU busy {bd['gpu_busy_fraction']} (raw {re_busy:.3f}), CPU-sort backlog "
                  f"{bd.get('cpu_backlog_fraction')}, ring full {bd.get('ring_full_fraction')}, CPU {bd.get('cpu_cores')} cores = "
                  f"{bd.get('cpu_budget_fraction')} of the --cpu-max budget · GPU-only ceiling estimate "
                  f"{bd.get('gpu_ceiling_staged_hs')} staged H/s · CPU-own {bd.get('cpu_own_hs')} H/s "
                  f"({bd.get('cpu_own_hashes_per_idle_try')} hashes per idle try)")


def g17_binding(cur, classify=None):
    """R23b: (ok, note) — the regime label (classify_regime) looks only at the CPU-sort backlog, so it says
    'cpu-sort-bound' while the GPU is also at its ceiling (quiet box 2026-10-30 06:09-06:23: GPU busy 0.914-0.919,
    backlog 0.91, /metrics binding co-bound in 4/4 snapshots). The run's `binding` must equal the shared classifier's
    verdict on its own fractions; the note names it and flags a GPU duty within BIND_MARGIN of the threshold, where the
    label flips between readings (log 0.867 cpu-sort-bound vs /metrics 0.906 co-bound, 19:16)."""
    rg = ((cur or {}).get('split') or {}).get('regime') or {}
    if rg.get('gpu_busy_fraction') is None:
        return True, f"binding n/a (no GPU-busy reading; regime {rg.get('regime')})"
    want = (classify or _classifier())(rg['gpu_busy_fraction'], rg.get('cpu_backlog_fraction'), rg.get('ring_full_fraction'))['binding']
    if want != rg.get('binding'):
        return False, f"binding {rg.get('binding')} disagrees with its own fractions ({want})"
    near = abs(rg['gpu_busy_fraction'] - BIND_GPU_BUSY) <= BIND_MARGIN
    return True, (f"binding {want} (GPU busy {rg['gpu_busy_fraction']}, backlog {rg.get('cpu_backlog_fraction')})"
                  + (f'; GPU busy within {BIND_MARGIN} of {BIND_GPU_BUSY}: the label is marginal (co-bound vs '
                     f'{want if want != "co-bound" else "cpu-sort-bound"})' if near else ''))


BIND_GPU_BUSY, BIND_MARGIN = 0.90, 0.05


def pipeline_for_ab(last, full, state='active'):
    """R23b: (record, label) G20 judges A/Bs from: the newest record when it is a full run with an A/B stage, else
    PIPELINE_FULL_LAST. None when neither holds one (G20 then FAILS: no A/B evidence is not a clean A/B).
    r24: a stage recorded PAUSED (miner track paused, §0.3) counts as the A/B stage only while the track is paused;
    once it is active again a paused-only record is no A/B evidence."""
    has = lambda r: bool(r) and any(st in (r.get('stages') or {}) and (
        state == 'paused' or ((r.get('stages') or {}).get(st) or {}).get('status') != RT.PAUSED) for st in AB_STAGES)
    if has(last):
        return last, f"PIPELINE_LAST {last.get('run')}"
    if has(full):
        return full, (f"PIPELINE_FULL_LAST {full.get('run')} (newest record {(last or {}).get('run')} is "
                      f"{(last or {}).get('mode', 'partial')}: no A/B stage)")
    return None, f"no pipeline record with an A/B stage (newest {(last or {}).get('run')} mode {(last or {}).get('mode')})"


AB_STAGES = ('minerbench', 'gpubench')


def g20_contention(mt, mi=None, pipe=None, require_ab=False, state='active'):
    """R23: (ok, detail). `mt` newest metrics snapshot, `mi` newest minerintel snapshot, `pipe` loop/PIPELINE_LAST.json.
    Refuses: a snapshot without a census; a contended census the snapshot does not act on; a hashrate_sag (a regression
    claim) next to a contended census; a pipeline A/B that PASSED or FAILED on a ratio while its census said contended."""
    why, notes = [], []
    ct = (mt or {}).get('contention')
    if not ct or ct.get('contended') is None:
        why.append('the metrics snapshot carries no foreign-process census: contention unknown, so no claim can be judged')
    else:
        rules = {a['rule'] for a in (mt.get('alerts') or [])}
        notes.append(f"census {'CONTENDED' if ct['contended'] else 'quiet'}: foreign {ct.get('foreign_cores')} cores, miner "
                     f"{ct.get('miner_cores')}/{ct.get('budget_cores')}, law {ct.get('law_hs_at_miner_cores')} H/s")
        if ct['contended'] and ('box_contended' not in rules or ct.get('regression_claims') != 'refused'):
            why.append('contended census but the snapshot neither warns box_contended nor refuses regression claims')
        if not ct['contended'] and ct.get('regression_claims') != 'allowed':
            why.append(f"quiet census but regression_claims {ct.get('regression_claims')}")
    mct = (mi or {}).get('contention') or {}
    if mi is not None:
        cur = (mi.get('runs') or [{}])[-1]
        sag = [a for a in cur.get('alerts', []) if a['rule'] == 'hashrate_sag']
        if mct.get('contended') and sag:
            why.append(f"minerintel claims hashrate_sag while its own census says contended ({mct.get('why')})")
        notes.append(f"minerintel census {mct.get('contended')}")
    if require_ab and not pipe:
        why.append('no pipeline record holds an A/B stage: the contention of the last A/B cannot be judged')
    for st in AB_STAGES:
        rec = ((pipe or {}).get('stages') or {}).get(st)
        if not rec:
            continue
        if rec.get('status') == RT.PAUSED:          # r24: no ratio was measured, so no claim to judge
            if state != 'paused':
                why.append(f'{st} PAUSED while the miner track is active: no A/B ran')
            notes.append(f'{st} PAUSED (miner, {RT.PAUSE_REF})')
            continue
        c = rec.get('contention')
        if c is None:
            notes.append(f'{st} {rec.get("status")} (pre-R23 record: no census)')
            continue
        if c.get('contended') and rec.get('status') == 'PASS':
            why.append(f'{st} PASSED an A/B on a contended box: {c.get("why")}')
        if c.get('contended') and rec.get('status') == 'FAIL' and not rec.get('correctness_fail'):
            why.append(f'{st} FAILED on a ratio measured on a contended box (a regression claim): {c.get("why")}')
        notes.append(f"{st} {rec.get('status')} (contended {c.get('contended')})")
    return not why, '; '.join(why + notes)


def g21_payout(mr, per_mb=None):
    """R23: (ok, detail) for the newest minerruns snapshot: L-checks pass, the payout ledger is present and its DERO
    and verdict recompute from its own counts. `per_mb` overrides the snapshot's per-miniblock reward (KAT)."""
    if not mr:
        return False, 'no minerruns snapshot: run harness/intel/miner_runs.py'
    bad = [f"{v['start'][:16]} {k}" for v in mr.get('validation') or [] for k, c in v['checks'].items()
           if not (c[0] if isinstance(c, (list, tuple)) else c.get('ok'))]
    bad += [k for k, v in (mr.get('ledger_checks') or {}).items() if not v.get('ok')]
    po = mr.get('payout') or {}
    if not po.get('total'):
        return False, f"no payout ledger in the snapshot ({po.get('error', 'missing')})" + (f'; failed checks {bad}' if bad else '')
    t = po['total']
    pm = per_mb if per_mb is not None else t.get('per_miniblock_atomic')
    if pm is None or t.get('paid_DERO') is None or abs(t['paid'] * pm / 1e5 - t['paid_DERO']) > 1e-4:
        bad.append(f"paid_DERO {t.get('paid_DERO')} != paid {t.get('paid')} x {pm} atomic")
    lo, hi = t.get('found_ci95') or [None, None]
    E = t.get('expected_shares')
    if E and lo is not None:
        want = 'luck' if lo <= E <= hi else ('below' if E > hi else 'above')
        if not str(t.get('verdict', '')).startswith(want):
            bad.append(f"verdict {t.get('verdict')!r} but expected {E} vs interval [{lo}, {hi}] says {want}")
    if sum(x.get('paid') or 0 for x in po.get('runs') or []) != t['paid']:
        bad.append('per-run paid does not sum to the total')
    ok_i, det_i = g21_idle(mr, pm)
    if not ok_i:
        bad.append(det_i)
    return not bad, (f"paid {t['paid']} of {E} expected ({t.get('paid_DERO')} DERO of {t.get('expected_DERO')}), found "
                     f"{t.get('found')} in [{lo}, {hi}]: {t.get('verdict')} · {det_i}" + (f' · FAILED {bad}' if bad else ''))


def g21_idle(mr, pm):
    """R23b: (ok, detail) — the idle-gap ledger is present and recomputes: each gap's paid shares = shares x the
    ledger's paid fraction, DERO = paid shares x per-miniblock reward, no miner start-up line inside a gap (that would
    be a run the ledger lost, not idle time), and the gaps sum to the total."""
    idl = (mr or {}).get('idle') or {}
    t = idl.get('total')
    if not t:
        return False, 'no idle-gap ledger in the snapshot'
    bad = []
    pf = t.get('paid_fraction')
    for g in idl.get('gaps') or []:
        if g.get('forgone_shares') is not None and pf is not None and abs(g['forgone_shares'] * pf - (g.get('forgone_paid_shares') or 0)) > 0.011:
            bad.append(f"gap {g['from'][:16]}: paid shares {g.get('forgone_paid_shares')} != {g['forgone_shares']} x {pf}")
        if g.get('forgone_paid_shares') is not None and pm is not None and abs(g['forgone_paid_shares'] * pm / 1e5 - (g.get('forgone_DERO') or 0)) > 1e-4:
            bad.append(f"gap {g['from'][:16]}: DERO {g.get('forgone_DERO')} != {g['forgone_paid_shares']} x {pm} atomic")
        if g.get('log_starts_inside'):
            bad.append(f"gap {g['from'][:16]} holds {g['log_starts_inside']} miner start(s) the ledger does not: not idle")
    if abs(sum(g.get('idle_s') or 0 for g in idl.get('gaps') or []) - (t.get('idle_s') or 0)) > 1:
        bad.append('gap idle_s do not sum to the total')
    return not bad, (f"idle {t.get('idle_h')} h of {t.get('span_h')} h since {str(t.get('since'))[:16]} (uptime "
                     f"{t.get('uptime_fraction')}), forgone ~{t.get('forgone_paid_shares')} paid shares = "
                     f"{t.get('forgone_DERO')} DERO (ESTIMATE){', idle NOW' if t.get('open_now') else ''}"
                     + (f' · IDLE FAILED {bad[:3]}' if bad else ''))


def snap_age_h(snap, now=None):
    now = now or datetime.datetime.now().astimezone()
    return (now - datetime.datetime.fromisoformat(snap['captured'])).total_seconds() / 3600


def g17_gate(mi, name, now=None):
    """(ok, detail) of G17 for the newest minerintel snapshot `mi` (None = none) named `name`. r24: moved out of main()
    unchanged so a KAT can feed it; the track rule is applied by miner_gates."""
    if mi is None:
        return False, 'no miner snapshot: run harness/intel/miner_intel.py'
    age_h = snap_age_h(mi, now)
    cur = mi['runs'][-1] if mi['runs'] else {}
    alerts = [a for a in cur.get('alerts', []) if a['level'] == 'ALERT']
    hs, sp, sh = cur.get('hashrate', {}), cur.get('split', {}), cur.get('shares') or {}
    tv = mi.get('tree_version')
    ver = cur.get('version')
    rg = sp.get('regime') or {}
    regime_ok = g17_regime_ok(cur, tv)
    bind_ok, bind_note = g17_binding(cur)
    return (bool(cur) and not alerts and age_h < 24 and regime_ok and bind_ok,
            f"{name} ({age_h:.1f} h old) · run {cur.get('start', '?')[:19]} → {cur.get('end', '?')[:19]} "
            f"({cur.get('hours')} h) version {ver} ({'= tree' if ver and ver == tv else f'tree builds {tv}'}), "
            f"{cur.get('gpu_mode')} · logs read {[Path(f).name for f in mi.get('logs', [mi.get('log', '?')])]} · "
            f"mean {hs.get('mean')} H/s, staged {sp.get('staged_mean')}, drop {sp.get('drop_fraction')} · "
            f"regime {rg.get('regime')} (CPU-sort backlog {rg.get('cpu_backlog_fraction')}, ring full "
            f"{rg.get('ring_full_fraction')}, idle {rg.get('idle_tries_per_min')}/min over {rg.get('windows')} windows)"
            f" · {bind_note}"
            f"{'' if regime_ok else ' · NO BACKLOG COUNTER from this tree build'} · "
            f"accepted {sh.get('submissions')} longest gap {sh.get('longest_gap_s')} s · "
            f"alerts {[a['rule'] for a in cur.get('alerts', [])]}" + ('' if age_h < 24 else ' · STALE'))


def g18_gate(mt, name, tree_ver, now=None):
    """(ok, detail) of G18 for the newest metrics snapshot `mt` (None = none). r24: moved out of main() unchanged."""
    if mt is None:
        return False, 'no metrics snapshot: run harness/intel/metrics_intel.py'
    age_h = snap_age_h(mt, now)
    al = [a for a in mt.get('alerts', []) if a['level'] == 'ALERT']
    d, m = mt.get('derod') or {}, mt.get('miner') or {}
    mrg = m.get('split_regime') or {}
    mreg_ok = g18_regime_ok(m, tree_ver)
    return (all(mt.get('up', {}).values()) and not al and age_h < 24 and mreg_ok,
            f"{name} ({age_h:.1f} h old) up {mt.get('up')} · derod {d.get('sync_status')} tip "
            f"{d.get('tip_age_s')} s, peers {d.get('peers_out')}/{d.get('peers_in')} · miner {m.get('hashrate_sampled')} H/s "
            f"sampled, height {m.get('height')} vs {d.get('height')}, expected {m.get('expected_shares_per_h')} shares/h · "
            f"split regime {mrg.get('regime')} (staged {mrg.get('staged_hs')} H/s, backlog {mrg.get('cpu_backlog_fraction')}, "
            f"stale {mrg.get('stale_fraction')}){'' if mreg_ok else ' · REGIME COUNTERS MISSING'} · "
            f"alerts {[a['rule'] for a in mt.get('alerts', [])]}" + ('' if age_h < 24 else ' · STALE'))


# r24: the metrics_intel ALERT rules about the miner (metrics_intel.rules); every other ALERT is the node's
MINER_ALERT_RULES = ('miner_disconnected', 'split_disabled', 'gpu_mismatch', 'no_hashing', 'miner_behind')


def miner_alert(a):
    return a.get('rule') in MINER_ALERT_RULES or (a.get('rule') == 'endpoint_down' and str(a.get('what', '')).startswith('miner '))


def g18_derod_half(mt, now=None):
    """r24: (ok, why) of G18's node half — what the miner pause does NOT cover: the derod /metrics endpoint answered,
    no derod ALERT (not_synced, tip_age, endpoint_down derod, ...), and the snapshot is < 24 h old. Pure."""
    if mt is None:
        return False, 'no metrics snapshot'
    why = []
    if not (mt.get('up') or {}).get('derod'):
        why.append('derod /metrics did not answer')
    why += [f"derod ALERT {a['rule']}" for a in mt.get('alerts', []) if a['level'] == 'ALERT' and not miner_alert(a)]
    if snap_age_h(mt, now) >= 24:
        why.append('STALE')
    return not why, '; '.join(why) or 'derod up, no derod ALERT'


def g21_gate(mr, name, now=None):
    """(ok, detail) of G21 for the newest minerruns snapshot `mr` (None = none). r24: moved out of main() unchanged."""
    if mr is None:
        return False, 'no minerruns snapshot: run harness/intel/miner_runs.py'
    age21 = snap_age_h(mr, now)
    ok21, det21 = g21_payout(mr)
    return ok21 and age21 < 24, f"{name} ({age21:.1f} h old) · {det21}" + ('' if age21 < 24 else ' · STALE')


G17_NAME, G18_NAME, G21_NAME = 'G17 the live miner is healthy', 'G18 the live dashboard agrees', 'G21 the payout ledger holds'


def miner_gates(mi, mt, mr, tree_ver, track, now=None):
    """r24: [(name, ok, detail)] of G17, G18, G21 from (snapshot, name) pairs and track = (state, why) of the miner
    track (kit/roundtracks.track_state). Active: exactly the pre-r24 verdicts. Paused (artifacts/dero-rft.md §0.3):
    PAUSED with the unchanged verdict quoted, except that G18 still FAILS when its derod half fails."""
    state, why = track
    out = []
    for name, (ok, det) in ((G17_NAME, g17_gate(mi[0], mi[1], now)), (G18_NAME, g18_gate(mt[0], mt[1], tree_ver, now)),
                            (G21_NAME, g21_gate(mr[0], mr[1], now))):
        ok2, det2 = RT.gate_outcome(name, ok, det, state, why)
        if name == G18_NAME and ok2 == RT.PAUSED:
            dok, dwhy = g18_derod_half(mt[0], now)
            if not dok:
                ok2, det2 = False, f'derod half FAILS (the miner pause does not cover the node): {dwhy} · {det}'
        out.append((name, ok2, det2))
    return out


TRACK = RT.track_state(RT.load(HERE / 'round.json'))   # r24: (state, why) of the miner track of the current round


def run(cmd, **k):
    return subprocess.run(cmd, capture_output=True, text=True, **k)


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else 'manual'
    h = PAGE.read_text()
    st = json.loads(STAMP.read_text())
    s = st['stats']
    V = json.loads((MODEL / 'verified.json').read_text())
    res = []

    ev = [e for r in V for e in r['evidence']]
    bad = [e for e in ev if e.get('status') not in ('OK', 'MULTI') or not e.get('line')]
    res.append(('G1 every rendered anchor resolved', not bad and len(V) == s['rows'] > 0,
                f"{len(V)} rows rendered · {len(ev) - len(bad)}/{len(ev)} rendered anchors resolved · "
                f"raw {s['anchors_ok']}/{s['anchors']} · {s['rejected']} rows refused"))

    # G2 — independent re-read: do not trust the stamp, open each cited file again
    miss, old_root = [], stamp_root(st)
    for r in V:
        for e in r['evidence']:
            try:      # relocate: the page may have been built in another checkout; re-read THIS one (R20)
                lines = Path(relocate(e['abs'], old_root)).read_text(errors='replace').splitlines()
            except OSError:
                miss.append(f"{r['id']}: unreadable {e['abs']}")
                continue
            i = e.get('line', 0)
            q_, l_ = norm(e['quote']), norm(lines[i - 1]) if 1 <= i <= len(lines) else None
            # r24: a pseudonymised peer address (kit/privkit.py) is compared in the salt-free masked form only
            if l_ is None or (q_ not in l_ and not (privkit.PSEUDO.search(q_) and privkit.mask(q_) in privkit.mask(l_))):
                miss.append(f"{r['id']}: {Path(e['abs']).name}:{i}")
    res.append(('G2 every cited line re-read from disk', not miss,
                f'{len(ev)} anchors re-read, {len(miss)} no longer match' + (f' e.g. {miss[:3]}' if miss else '')))

    r = run([PY, str(HERE / 'prep_corpus.py'), '--check'])
    res.append(('G3 corpus current', r.returncode == 0, r.stdout.strip()[:200]))
    res.append(('G4 svg text-fit lint', st.get('svg_lint', 1) == 0,
                f"{st.get('svg_lint')} violation(s) {st.get('svg_lint_examples', [])[:2]}"))

    js = '\n;\n'.join(re.findall(r'<script>(.*?)</script>', h, re.S))
    with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False) as f:
        f.write(js)
    r = run(['node', '--check', f.name])
    res.append(('G5 page script parses', r.returncode == 0, (r.stderr.strip().splitlines() or ['node --check ok'])[0][:160]))

    b = Bal()
    b.feed(re.sub(r'<script[^>]*>.*?</script>', '', h, flags=re.S))
    left = [t for t in b.st if t not in ('html', 'body', 'head')]
    res.append(('G6 HTML tag balance', not b.err and not left,
                f'{len(b.err)} error(s), {len(left)} unclosed {b.err[:3]} {left[:3]}'))

    probes, doms = {}, {}
    for w in (1280, 480):
        with tempfile.NamedTemporaryFile('w', suffix='.html', delete=False) as f:
            f.write(h.replace('<head>', '<head>' + PROBE, 1).replace('</body>', PROBE_END + '</body>'))
        r = run([CHROME, '--headless=new', '--disable-gpu', f'--window-size={w},1000',
                 '--virtual-time-budget=20000', '--dump-dom', 'file://' + f.name], timeout=420)
        m = re.search(r'<pre id="PROBE">(.*?)</pre>', r.stdout, re.S)
        probes[w] = json.loads(html.unescape(m.group(1))) if m else {'missing': True, 'stderr': r.stderr[-300:]}
        doms[w] = r.stdout
    ok7, det = True, []
    for w, p in probes.items():
        if p.get('missing'):
            ok7 = False
            det.append(f'{w}px: probe missing {p.get("stderr")}')
            continue
        okc, summ = ck.check(p.get('trace'))
        ix = p.get('index') or {}
        okx = (ix.get('hits', 0) > 0 and ix.get('facets', 0) > 0
               and 0 < ix.get('filter_after', 0) < ix.get('filter_before', 0))
        ok7 &= not p['overflow'] and not p['errors'] and okc and okx
        det.append(f"{w}px: overflow={len(p['overflow'])} errors={len(p['errors'])} index={ix} {summ}"
                   + (f" {p['overflow'][:3]} {p['errors'][:2]}" if p['overflow'] or p['errors'] else ''))
    res.append(('G7 render probes', ok7, ' | '.join(det)))

    r1 = run([PY, str(HERE / 'gen_deroarch.py'), 'check'])
    r2 = run([PY, str(HERE / 'gen_deroarch.py'), 'selftest'])
    res.append(('G8 projection gate', r1.returncode == 0 and r2.returncode == 0,
                (r1.stdout.strip() + ' · ' + (r2.stdout.strip().splitlines() or [''])[-1])[:260]))

    # G9 — the page claims things about a live daemon; ask it again
    try:
        req = urllib.request.Request('http://127.0.0.1:10102/json_rpc',
                                     data=json.dumps({'jsonrpc': '2.0', 'id': '1', 'method': 'DERO.GetInfo'}).encode(),
                                     headers={'Content-Type': 'application/json'})
        gi = json.loads(urllib.request.urlopen(req, timeout=8).read())['result']
        shown = {r['field']: r['value'] for r in V if r.get('section') == 'runtime' and r.get('field')}
        same_ver = gi['version'] == shown.get('version')
        grew = gi['height'] >= int(shown.get('height', 0))
        # The decisive reading: the tip block's own age. GetInfo alone cannot distinguish a node at the tip from
        # one replaying history (finding find-attip), so the gate asks the chain, not the summary.
        hreq = urllib.request.Request('http://127.0.0.1:10102/json_rpc',
                                      data=json.dumps({'jsonrpc': '2.0', 'id': '1',
                                                       'method': 'DERO.GetBlockHeaderByTopoHeight',
                                                       'params': {'topoheight': gi['topoheight']}}).encode(),
                                      headers={'Content-Type': 'application/json'})
        bh = json.loads(urllib.request.urlopen(hreq, timeout=8).read())['result']['block_header']
        import time as _t
        age = _t.time() - (bh['timestamp'] / 1000)
        was = float(shown.get('tip_age') or age)
        closing = age <= was + 60          # catching up, or at worst holding station
        at_tip = age < 600
        ok9 = same_ver and grew and gi['status'] == 'OK' and closing
        d9 = (f"live height {gi['height']} (page {shown.get('height')}, "
              f"{gi['height'] - int(shown.get('height', 0))} newer) · version "
              f"{'matches' if same_ver else 'DIFFERS: ' + gi['version']} · difficulty {gi['difficulty']:,} · "
              f"peers {gi['outgoing_connections_count']}/{gi['incoming_connections_count']} · "
              f"TIP AGE {age / 3600:.1f} h ({'AT TIP' if at_tip else f'~{age / 18:,.0f} blocks behind'}, "
              f"page said {was / 3600:.1f} h, {'closing' if closing else 'FALLING FURTHER BEHIND'}) · "
              f"major_version {bh['major_version']}")
    except Exception as e:                                           # noqa: BLE001
        # a gate that passes when it cannot look proves nothing (discovery harness-gaps-05)
        ok9, d9 = False, f'daemon not reachable ({type(e).__name__}) — the live claims on the page cannot be re-checked'
    res.append(('G9 the live daemon still agrees', ok9, d9))

    a = ak.audit(h)
    bt = probes.get(1280, {}).get('tags') or {}
    res.append(('G10 every asset carries a class tag', a['ok'] and not bt.get('unk'),
                f"{a['asset_cells']} cells ({a['untagged_cells']} untagged), {a['svg_assets']} diagram assets "
                f"({a['svg_untagged']} untagged), {a['unclassified']} unclassified, {a['notag_tables']} ledger tables "
                f"opted out · browser UNK={bt.get('unk')}"
                + (f" e.g. {a['examples'][:2]} {a['svg_examples'][:2]}" if not a['ok'] else '')))

    t1, t2 = tk.audit(h), tk.audit(doms.get(1280, ''))
    res.append(('G11 no cut sentence', t1['ok'] and t2['ok'],
                f"page: {json.dumps({k: v for k, v in t1.items() if k != 'examples'})} · "
                f"rendered: {json.dumps({k: v for k, v in t2.items() if k != 'examples'})}"
                + (f" {t1.get('examples', [])[:2]} {t2.get('examples', [])[:2]}" if not (t1['ok'] and t2['ok']) else '')))

    ca = ak.cite_audit(h)
    cp = bt.get('cite') or {}
    okb = all(v.get('open') and v.get('good_links') == v.get('links') and v.get('pinned') and v.get('closed')
              for v in cp.values()) and len(cp) == 2
    res.append(('G12 citations behind every tag', ca['ok'] and okb,
                f"registry={ca['registry']} by_class={ca['by_class']} malformed={ca['malformed']} "
                f"no_ci={ca['pills_without_ci']} · browser {cp}"))

    # G14 — the datadir agrees with the formats the source defines and with the running node
    import glob as _g
    dds = sorted(_g.glob(str(HERE / 'runtime/datadir_*.json')))
    if dds:
        dd = json.loads(Path(dds[-1]).read_text())
        age_h = (datetime.datetime.now().astimezone() - datetime.datetime.fromisoformat(dd['captured'])).total_seconds() / 3600
        fails = [c['check'] for c in dd['checks'] if c['result'] == 'FAIL']
        known = [c['check'] for c in dd['checks'] if c['result'] == 'KNOWN']
        res.append(('G14 datadir integrity', not fails and age_h < 24,
                    f"{Path(dds[-1]).name} ({age_h:.1f} h old): {sum(1 for c in dd['checks'] if c['result'] == 'PASS')} PASS, "
                    f"FAIL {fails}, KNOWN {known}" + ('' if age_h < 24 else ' · STALE: rerun harness/intel/datadir_intel.py')))
    else:
        res.append(('G14 datadir integrity', False, 'no datadir snapshot: run harness/intel/datadir_intel.py'))
    # G15 — the current run of the daemon, from its own log: no ALERT-level rule fires
    lis = sorted(_g.glob(str(HERE / 'runtime/logintel_*.json')))
    if lis:
        li = json.loads(Path(lis[-1]).read_text())
        cur = li['runs'][-1] if li['runs'] else {}
        alerts = [a for a in cur.get('alerts', []) if a['level'] == 'ALERT']
        res.append(('G15 log health of the current run', bool(cur) and not alerts,
                    f"run since {cur.get('start', '?')[:19]} ({cur.get('version')}): mean {cur.get('blocks', {}).get('at_tip_mean_s')} s, "
                    f"ERRORs at tip {cur.get('errors_at_tip')}, alerts {[a['rule'] for a in cur.get('alerts', [])]}"))
    else:
        res.append(('G15 log health of the current run', False, 'no log snapshot: run harness/intel/log_intel.py'))

    # G16 — risk coverage never goes backwards: a RATCHET over every earlier snapshot, keyed by file::function, so
    # re-running the miner cannot launder a drop (review 2026-10-22)
    covs = sorted(_g.glob(str(HERE / 'runtime/coverage_*.json')))
    if covs:
        def covered_set(p):
            return {m.group(1) for fct in json.loads(Path(p).read_text())['facts']
                    for m in [re.match(r'coverage risk-function (\S+) covered=1$', fct)] if m}
        def existing_set(p):
            return {m.group(1) for fct in json.loads(Path(p).read_text())['facts']
                    for m in [re.match(r'coverage risk-function (\S+) covered=\d$', fct)] if m}
        # only snapshots made by the SAME miner (method = hash of mine_coverage.py) are comparable: a corrected miner
        # (e.g. one that stopped counting a hop that never ran) must not be held to its buggy predecessor's numbers
        meth = lambda p: json.loads(Path(p).read_text()).get('method')
        same = [p for p in covs[:-1] if meth(p) == meth(covs[-1])]
        now_cov, now_all = covered_set(covs[-1]), existing_set(covs[-1])
        ever = set().union(*[covered_set(p) for p in same]) if same else set()
        lost = sorted((ever & now_all) - now_cov)        # still exists, was covered, is not now
        cur_c = json.loads(Path(covs[-1]).read_text())['total']
        res.append(('G16 risk coverage does not drop', bool(now_all) and not lost,
                    f"risk {cur_c['risk_covered']}/{cur_c['risk']}; ratchet over {len(same)} earlier snapshot(s) of method {meth(covs[-1])}: "
                    f"{len(ever)} function(s) ever covered, lost {lost[:5]}" + ('' if now_all else ' · snapshot has no risk-function facts')))
    else:
        res.append(('G16 risk coverage does not drop', False, 'no coverage snapshot: run harness/miners/mine_coverage.py'))

    # G17 — the live miner, from its own log (harness/intel/miner_intel.py): no ALERT-level rule in the current run
    # G18 — the live dashboard: both /metrics endpoints, sampled twice and cross-checked (harness/intel/metrics_intel.py)
    # G21 (R23) — the payout ledger: L-checks pass, DERO and verdict recompute
    # r24: the three miner gates, with the paused-track rule (kit/roundtracks.py, artifacts/dero-rft.md §0.3)
    mis = sorted(_g.glob(str(HERE / 'runtime/minerintel_*.json')))
    mts = sorted(_g.glob(str(HERE / 'runtime/metrics_*.json')))
    mrs = sorted(_g.glob(str(HERE / 'runtime/minerruns_*.json')))
    tvm = re.search(r'MustParse\("([^"]+)"\)', (HERE.parent / 'config/version.go').read_text())
    snap = lambda ps: (json.loads(Path(ps[-1]).read_text()), Path(ps[-1]).name) if ps else (None, None)
    g17, g18, g21 = miner_gates(snap(mis), snap(mts), snap(mrs), tvm.group(1) if tvm else None, TRACK)
    res.append(g17)
    res.append(g18)
    if mts:
        mt = json.loads(Path(mts[-1]).read_text())
        age_h = (datetime.datetime.now().astimezone() - datetime.datetime.fromisoformat(mt['captured'])).total_seconds() / 3600

    # G19 (R22) — the binding resource of the split, named from the GPU duty and the CPU backlog, recomputable
    if mts:
        ok19, det19 = g19_binding(mt, tvm.group(1) if tvm else None)
        res.append(('G19 the binding resource is known', ok19 and age_h < 24,
                    f"{Path(mts[-1]).name} ({age_h:.1f} h old) · {det19}" + ('' if age_h < 24 else ' · STALE')))
    else:
        res.append(('G19 the binding resource is known', False, 'no metrics snapshot: run harness/intel/metrics_intel.py'))

    # G20 (R23) — no A/B or regression claim from a contended box
    mis_l = sorted(_g.glob(str(HERE / 'runtime/minerintel_*.json')))
    pl, pfl = HERE / 'loop/PIPELINE_LAST.json', HERE / 'loop/PIPELINE_FULL_LAST.json'
    pab, pab_label = pipeline_for_ab(json.loads(pl.read_text()) if pl.exists() else None,
                                     json.loads(pfl.read_text()) if pfl.exists() else None, state=TRACK[0])
    ok20, det20 = g20_contention(json.loads(Path(mts[-1]).read_text()) if mts else None,
                                 json.loads(Path(mis_l[-1]).read_text()) if mis_l else None, pab, require_ab=True,
                                 state=TRACK[0])
    det20 = f'{det20}; A/B record: {pab_label}'
    res.append(('G20 no A/B or regression claim from a contended box', ok20, det20))
    res.append(g21)

    # G22 (R23b) — every code-behaviour claim on the soundness page is backed by a test, an anchor, a recomputation or a
    # live read (harness/soundness.py; the tests run in the pipeline's S3s stage)
    try:
        import importlib.util as _iu
        _sp = _iu.spec_from_file_location(f'soundness_for_gates_{id(HERE)}', HERE / 'soundness.py')
        SM = _iu.module_from_spec(_sp)
        _sp.loader.exec_module(SM)
        g22 = SM.evaluate(*SM.load(HERE.parent))
        res.append(('G22 the soundness page is backed', g22['ok'],
                    f"{g22['units']} page units, {g22['code_backed']}/{g22['code_claims']} code claims backed "
                    f"({len(g22['off_page'])} off-page), {len(g22['tests'])} tests from record {g22['record']}, "
                    f"unregistered {len(g22['unregistered'])}, stale {len(g22['stale'])}"
                    + (f" · {'; '.join(g22['why'])[:400]}" if g22['why'] else '')))
    except Exception as e:                                           # noqa: BLE001 — a gate that cannot look fails
        res.append(('G22 the soundness page is backed', False, f'soundness check could not run: {type(e).__name__}: {e}'))

    # G23 (r24) — every active area has an anchored scorecard and the proposals feed is fresh (harness/intel/area_intel.py)
    try:
        import importlib.util as _iu23
        _sp23 = _iu23.spec_from_file_location(f'area_intel_for_gates_{id(HERE)}', HERE / 'intel/area_intel.py')
        AI = _iu23.module_from_spec(_sp23)
        _sp23.loader.exec_module(AI)
        ok23, det23 = AI.g23(HERE.parent)
        res.append(('G23 every area is scored, anchored and fresh', ok23, det23))
    except Exception as e:                                           # noqa: BLE001 — a gate that cannot look fails
        res.append(('G23 every area is scored, anchored and fresh', False, f'area_intel could not run: {type(e).__name__}: {e}'))
    # G24 (r24; G23 at merge, renumbered: G23 is area intelligence) — the Foundation-disclosure track is re-tested (artifacts/dero-rft.md §0.5): every anchor of
    # loop/disclosure_track.json re-read (DRIFT reported, MISSING fails), no verdict change without a reason and a non-EXT
    # anchor, every claim re-tested in the current round, every press row mapped, no exploit-like text in the track or in
    # the rendered disclosure sections, and model/raw/disclosure.json current (harness/intel/disclosure_track.py)
    try:
        import importlib.util as _iu
        _dp = _iu.spec_from_file_location(f'disclosure_track_for_gates_{id(HERE)}', HERE / 'intel/disclosure_track.py')
        DT = _iu.module_from_spec(_dp)
        _dp.loader.exec_module(DT)
        _tr, _lg = DT.load(HERE.parent)
        g24 = DT.evaluate(_tr, root=HERE.parent, legacy=_lg, pages=DT.page_sections(HERE.parent))
        _mc = DT.model_current(_tr, json.loads((HERE / 'model/raw/disclosure.json').read_text()), HERE.parent)
        res.append(('G24 the disclosure track is re-tested', g24['ok'] and _mc,
                    f"{g24['claims']} claims re-tested in {g24['current_round']}, {g24['facts']} facts, {g24['fixes']} fixes; "
                    f"anchors {g24['anchors']} {g24['anchor_status']}, drift {len(g24['drift'])}; exploit lint "
                    f"{len(g24['lint_hits'])} (legacy rows flagged {len(g24['legacy_lint'])}); model "
                    f"{'current' if _mc else 'STALE'}" + (f" · {'; '.join(g24['why'])[:400]}" if g24['why'] else '')))
    except Exception as e:                                           # noqa: BLE001 — a gate that cannot look fails
        res.append(('G24 the disclosure track is re-tested', False, f'disclosure track could not run: {type(e).__name__}: {e}'))

    # G25 (r24) — the artifacts agree with their canonical sources (harness/intel/coherence.py; dero-rft "Artifact
    # contract"): round id/status/suffix, every pipeline figure vs its run record, registry go_mutations, live-window
    # figures, disclosure verdicts, area states, tracked backlog statuses, page names, src-arch freshness. The index
    # page is checked by the S7 step `coherence.py --record` that runs AFTER gen_index.py (this gate runs before it, so
    # judging the index here would judge the previous run's page): G25 skips only that one check.
    try:
        import importlib.util as _iu25
        _sp25 = _iu25.spec_from_file_location(f'coherence_for_gates_{id(HERE)}', HERE / 'intel/coherence.py')
        CO = _iu25.module_from_spec(_sp25)
        _sp25.loader.exec_module(CO)
        ok25, det25 = CO.g25(HERE.parent)
        res.append(('G25 the artifacts agree with their canonical sources', ok25, det25))
    except Exception as e:                                           # noqa: BLE001 — a gate that cannot look fails
        res.append(('G25 the artifacts agree with their canonical sources', False, f'coherence could not run: {type(e).__name__}: {e}'))

    # G26 (r24) — the chain-consensus observatory (harness/intel/consensus_intel.py): a fresh (< 24 h) LIVE capture, every
    # registered detector reported with a grade (NO-DATA allowed only where a live log window or the own address can be
    # missing), every rule anchor re-read from the tree, every page row anchored, no address or IP literal in the outputs
    try:
        import importlib.util as _iu26
        _sp26 = _iu26.spec_from_file_location(f'consensus_intel_for_gates_{id(HERE)}', HERE / 'intel/consensus_intel.py')
        CI = _iu26.module_from_spec(_sp26)
        _sp26.loader.exec_module(CI)
        ok26, det26 = CI.g26(HERE.parent)
        res.append(('G26 the chain-consensus observatory is fresh, graded and anchored', ok26, det26))
    except Exception as e:                                           # noqa: BLE001 — a gate that cannot look fails
        res.append(('G26 the chain-consensus observatory is fresh, graded and anchored', False, f'consensus_intel could not run: {type(e).__name__}: {e}'))
    # G27 (r24 consensus-network) — the network-peer observatory is fresh, private and anchored (harness/intel/peer_intel.py
    # g27): peer_intel.json < 24 h with its capture file unchanged; no IPv4/IPv6 address and none of the newest private
    # capture's addresses or tags in peer_intel.json, the capture, the log extract, model/raw/peercards.json or the rendered
    # 'peers' section of dero-src-arch.html; every peers row anchored on a line that still says it; no detector graded
    # without its rule line; r24 integration: the WHOLE page, verified.json and the log-derived raw files are scanned too.
    try:
        import importlib.util as _iu27
        _sp27 = _iu27.spec_from_file_location(f'peer_intel_for_gates_{id(HERE)}', HERE / 'intel/peer_intel.py')
        PI = _iu27.module_from_spec(_sp27)
        _sp27.loader.exec_module(PI)
        ok27, det27 = PI.g27(HERE.parent)
        res.append(('G27 the peer observatory is fresh, private and anchored', ok27, det27))
    except Exception as e:                                           # noqa: BLE001 — a gate that cannot look fails
        res.append(('G27 the peer observatory is fresh, private and anchored', False, f'peer_intel could not run: {type(e).__name__}: {e}'))
    # G28 (r25 forensics-replay, B77) — the forensic dataset is reproducible (harness/forensics/verify_dataset.py g28):
    # every version re-verifies byte for byte against forensics/ledger.json, and two recorded full replay.py runs of the
    # newest manifest (distinct cwds) re-derived every derived/ file with byte-identical reports
    try:
        import importlib.util as _iu28
        _sp28 = _iu28.spec_from_file_location(f'verify_dataset_for_gates_{id(HERE)}', HERE / 'forensics/verify_dataset.py')
        VD = _iu28.module_from_spec(_sp28)
        _sp28.loader.exec_module(VD)
        ok28, det28 = VD.g28(HERE.parent)
        res.append(('G28 the forensic dataset is reproducible', ok28, det28))
    except Exception as e:                                           # noqa: BLE001 — a gate that cannot look fails
        res.append(('G28 the forensic dataset is reproducible', False, f'verify_dataset could not run: {type(e).__name__}: {e}'))
    # G29 (r25 forensics-audit, B78; r26 every version) — the independent audit is present (audit_check.py g29): bound to
    # each dataset version's current data, 0 FAILS/UNRESOLVED challenges left on a PROVEN verdict (MF3/MF4), A1-A4 challenged,
    # a second implementation, and no exploit/private text in the dataset
    try:
        import importlib.util as _iu29
        _sp29 = _iu29.spec_from_file_location(f'audit_check_for_gates_{id(HERE)}', HERE / 'forensics/audit_check.py')
        AC = _iu29.module_from_spec(_sp29)
        _sp29.loader.exec_module(AC)
        ok29, det29 = AC.g29(HERE.parent)
        res.append(('G29 the forensic dataset is independently audited', ok29, det29))
    except Exception as e:                                           # noqa: BLE001 — a gate that cannot look fails
        res.append(('G29 the forensic dataset is independently audited', False, f'audit_check could not run: {type(e).__name__}: {e}'))
    # G30 (r25 forensics frontend, B79) — every figure of the ledger's forensics sections and of the src-arch "Forensic
    # dataset" line is a span naming its dataset file and SHA-256 and equal to the fact re-derived from the dataset now;
    # no number is left untraced; the window explorer's embedded data decodes to derived/window.jsonl.gz row by row
    try:
        import importlib.util as _iu30
        _sp30 = _iu30.spec_from_file_location(f'facts_for_gates_{id(HERE)}', HERE / 'forensics/facts.py')
        FX = _iu30.module_from_spec(_sp30)
        _sp30.loader.exec_module(FX)
        ok30, det30 = FX.g30(HERE.parent)
        res.append(('G30 the forensics frontend traces to the dataset', ok30, det30))
    except Exception as e:                                           # noqa: BLE001 — a gate that cannot look fails
        res.append(('G30 the forensics frontend traces to the dataset', False, f'facts could not run: {type(e).__name__}: {e}'))
    # G31 / G32 (r26 forensics-classes, B108/B109; rft §0.8.9) — bound honesty: every class figure carries {class, scope,
    # coverage, bound_type}, exact only at full coverage and never for DC2, unbounded never rendered as 0, no total for a
    # bound, no cross-class sum, no fix status regrading history, forbidden phrases only negated, no amount-recovery text;
    # class separation + presence: one class per record and figure, DC1-DC3 presence anchors re-read at HEAD, and the
    # DC2-present headline on the ledger, soundness and src-arch pages once the round's ledger page exists
    try:
        import importlib.util as _iu31
        _sp31 = _iu31.spec_from_file_location(f'bounds_for_gates_{id(HERE)}', HERE / 'forensics/bounds.py')
        BD = _iu31.module_from_spec(_sp31)
        _sp31.loader.exec_module(BD)
        ok31, det31 = BD.g31(HERE.parent)
        res.append(('G31 forensic figures carry their class bound', ok31, det31))
        ok32, det32 = BD.g32(HERE.parent)
        res.append(('G32 defect classes are separated and their presence re-read', ok32, det32))
    except Exception as e:                                           # noqa: BLE001 — a gate that cannot look fails
        res.append(('G31 forensic figures carry their class bound', False, f'bounds could not run: {type(e).__name__}: {e}'))
        res.append(('G32 defect classes are separated and their presence re-read', False, f'bounds could not run: {type(e).__name__}: {e}'))

    # G13 — a fix may change logging and peer handling, never what the node accepts or computes
    import consensus_guard as CG
    cg = CG.evaluate()
    res.append(('G13 consensus guard: every consensus-package change is logging-only', cg['ok'],
                f"{len(cg['files'])} file(s) vs {cg['base']}: "
                + '; '.join(f"{e['file']}={e['verdict']}" for e in cg['files'])
                + (f" · VIOLATIONS {cg['violations'][:2]}" if cg['violations'] else '')))

    now = datetime.datetime.now().astimezone().isoformat(timespec='seconds')
    gl = HERE / 'loop/GATES.md'
    gl.parent.mkdir(exist_ok=True)
    if not gl.exists():
        gl.write_text('# Gate ledger — dero-src-arch\n\n| when | cycle | gate | result | detail |\n|---|---|---|---|---|\n')
    with gl.open('a') as f:
        for g, ok, d in res:
            f.write(f"| {now} | {label} | {g} | {RT.word(ok)} | {str(d).replace('|', '/')[:600]} |\n")
    for g, ok, d in res:
        print(f"{RT.word(ok)}  {g}: {str(d)[:360]}")
    run([PY, str(HERE / 'gen_deroarch.py'), 'sync-skill'])
    sys.exit(0 if RT.all_ok(res) else 3)


if __name__ == '__main__':
    main()
