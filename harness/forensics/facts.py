#!/usr/bin/env python3
"""R25 forensic facts (rft §0.8.6, §0.8.8 G30): every figure the ledger's forensics sections and the src-arch
"Forensic dataset" line show, each read from ONE dataset file (or the G28 run record) and carrying that file's SHA-256.

  python3 -I harness/forensics/facts.py [--dataset forensics/r25] [--write harness/runtime/forensics_intel.json]
  python3 -I harness/forensics/facts.py --g30 [--page artifacts/dero-r1-r25.html] [--srcarch artifacts/dero-src-arch.html]

A fact is {value, file, sha256, how}. `file` is dataset-relative (`derived/summary.json`) or repo-relative for the
run record (`harness/runtime/forensics_replay.json`, class 'record'); `sha256` is the manifest's entry for a dataset file
(re-hashed: a mismatch is a G30 failure) or the record's own hash. The renderers wrap every number in
<span class="fxn" data-fx="ID" data-src="FILE" data-sha="SHA">TEXT</span>; G30 (g30()) re-derives every fact from the
dataset as it is now and checks, for every rendered span: the fact exists, TEXT == fmt(value), FILE and SHA equal the
fact's; then it strips the spans and identifiers from the forensics sections and refuses any number left over (no
untraced figure). It also checks the window explorer's embedded data (decoded row by row against
derived/window.jsonl.gz) and the src-arch line. Exit 0 PASS · 9 FAIL.

r26 (forensics-frontend2, B114): a dataset with manifest `version` 2 (forensics/r26/, dataset v2) is read by build_v2().
v2 keeps no copy of the v1 files it builds on; it pins them in manifest `inputs` (forensics/r25/... by SHA-256), so a
v2 fact may name a file of an EARLIER sealed version (class 'prior': `file` is repo-relative, `sha256` is that version's
manifest entry, and the bytes, the v2 pin and the sealed ledger entry are all re-checked). The class figures of
derived/classes.json render as <span class="fcl" ...> (harness/forensics/bounds.py, G31); G30 strips them from its
untraced-number scan and checks them with bounds.check_page, so a page has one rule for every number. G30 also checks
the soundness page's generated section (<!--known:begin--> ... <!--known:end-->, harness/kit/soundpage.py).
"""
import argparse, base64, gzip, hashlib, html, json, os, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
RECORD = 'harness/runtime/forensics_replay.json'
# custom base64 alphabet with no vowel and no '.': an embedded hash column can never spell a word or an IPv4 address
# that a privacy grep looks for (pubscrub's checks, rft §6 step 18). Index i -> B64X[i].
B64X = ('BCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789' + '!#$%()*+-/:;')
assert len(B64X) == 64 and len(set(B64X)) == 64 and not set('aeiouAEIOU.') & set(B64X)
_STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
_TO_X = str.maketrans(_STD, B64X)
_FROM_X = str.maketrans(B64X, _STD)


def b64x(b):
    return base64.b64encode(b).decode().rstrip('=').translate(_TO_X)


def unb64x(s):
    s = s.translate(_FROM_X)
    return base64.b64decode(s + '=' * (-len(s) % 4))


def sha(b):
    return hashlib.sha256(b).hexdigest()


def fmt(v):
    """The one display form of a fact value (G30 compares rendered text with it)."""
    if isinstance(v, bool):
        return 'yes' if v else 'no'
    if isinstance(v, int):
        return f'{v:,}'
    if isinstance(v, float):
        return f'{v:,.1f}'
    return str(v)


def _get(o, path):
    for k in path:
        o = o[k]
    return o


class Facts:
    def __init__(self, ds, root=ROOT, rec_root=None):
        self.ds, self.root = Path(ds), Path(root)
        # r26: the root a 'record' file is read from (a closed ledger page: its frozen inputs, artifacts/src/frozen/r<N>/)
        self.rec_root = Path(rec_root) if rec_root else self.root
        self.mb = (self.ds / 'manifest.json').read_bytes()
        self.m = json.loads(self.mb)
        self.files = self.m.get('files', {})
        self.cache = {}
        self.facts = {}
        self.problems = []

    def _file(self, rel, cls='dataset'):
        if rel in self.cache:
            return self.cache[rel]
        if cls == 'record':
            p = self.rec_root / rel
            b = p.read_bytes() if p.exists() else b''
            h = sha(b) if b else 'missing'
        elif cls == 'prior':
            b, h = self._prior(rel)
        elif rel == 'manifest.json':
            b, h = self.mb, sha(self.mb)
        else:
            p = self.ds / rel
            b = p.read_bytes() if p.exists() else b''
            h = self.files.get(rel, 'unlisted')
            if not b or sha(b) != h:
                self.problems.append(f'{rel}: bytes differ from the manifest entry (or missing)')
        self.cache[rel] = (b, h)
        return b, h

    def _prior(self, rel):
        """r26: (bytes, sha) of `forensics/<version>/<file>`, a file of an earlier SEALED dataset version that this
        dataset reads (v2 pins it in manifest `inputs`); the sha is that version's manifest entry, re-checked against the
        bytes, the pin and the sealed ledger entry (a problem otherwise, so G30 fails)."""
        m = re.fullmatch(r'forensics/(r\d+)/(.+)', rel)
        if not m:
            self.problems.append(f'{rel}: not a dataset file path')
            return b'', 'unlisted'
        ver, inner = m.groups()
        mp = self.root / 'forensics' / ver / 'manifest.json'
        mb = mp.read_bytes() if mp.exists() else b''
        try:
            led = json.loads((self.root / 'forensics' / 'ledger.json').read_text())
        except (OSError, ValueError):
            led = {}
        ent = next((v for v in led.get('versions', []) if v.get('version') == ver), {})
        if not mb or not ent.get('sealed') or ent.get('manifest_sha256') != sha(mb):
            self.problems.append(f'{rel}: version {ver} is not a sealed ledger version whose manifest matches its entry')
        h = (json.loads(mb).get('files', {}) if mb else {}).get(inner, 'unlisted')
        pin = self.m.get('inputs', {}).get(rel)
        if pin is not None and pin != h:
            self.problems.append(f'{rel}: the {self.ds.name} pin {pin[:12]} differs from the {ver} manifest {h[:12]}')
        p = self.root / rel
        b = p.read_bytes() if p.exists() else b''
        if not b or sha(b) != h:
            self.problems.append(f'{rel}: bytes differ from the {ver} manifest entry (or missing)')
        return b, h

    def json(self, rel, cls='dataset'):
        b, h = self._file(rel, cls)
        return (json.loads(b) if b else {}), h

    def add(self, fid, rel, value, how, cls='dataset'):
        _, h = self._file(rel, cls)
        self.facts[fid] = {'value': value, 'file': rel, 'sha256': h, 'how': how, 'class': cls}
        return value

    def j(self, fid, rel, path, cls='dataset'):
        o, _ = self.json(rel, cls)
        try:
            v = _get(o, path)
        except (KeyError, IndexError, TypeError):
            v = 'pending'
            self.problems.append(f'{fid}: {rel} has no {"/".join(map(str, path))}')
        return self.add(fid, rel, v, '/'.join(map(str, path)), cls)


RECORD_PATHS = {'replay_wall1_ok': ('store', 'wall1_blocks', 'check_i_ok'), 'replay_bodies': ('store', 'tx_bodies_present'),
                'replay_equal': ('rederive', 'equal'), 'replay_expected': ('rederive', 'expected')}
LEGACY_UNRECORDED = {'replay_wall1_ok': 'r25..r28d pages render it (v1 replay wrote it; v2..v4 replays never did)'}


def vkey_name(name):
    m = re.fullmatch(r'r(\d+)([a-z]?)', str(name))
    return (int(m.group(1)), m.group(2)) if m else (0, '')


def record_paths_for(name):
    """r30 v5 registration (B218): the RECORD figures a dataset's facts carry. From r30 the page renders the audit's own
    wall-1 check (ch:D2-04) instead of replay_wall1_ok, which no replay since v1 writes; the legacy figure is then not a
    fact at all (a page that still names it fails G30 as an unknown fact) instead of a problem that blocks every v5
    render. Pre-r30 datasets keep it (their closed pages render it, LEGACY_UNRECORDED). Pure."""
    if vkey_name(name) < (30, ''):
        return dict(RECORD_PATHS)
    return {k: v for k, v in RECORD_PATHS.items() if k not in LEGACY_UNRECORDED}


def unrecorded_paths(rep, paths, legacy):
    """r30 (B218): [(fact id, dotted path)] for record facts whose path is missing in a PASS report (pure)"""
    if not rep or rep.get('result') != 'PASS':
        return []
    out = []
    for fid, path in sorted(paths.items()):
        o = rep
        for k in path:
            o = o.get(k) if isinstance(o, dict) else None
        if o is None and fid not in legacy:
            out.append((fid, '.'.join(path)))
    return out


def presence_head_label(pr, build_commit):
    """r30 (B216): 'round head <c>' when presence re-read the dataset's build commit, else 'as of <c>' (pure)"""
    c = next((r.get('commit') for r in (pr or {}).get('revs', []) if r.get('rev') == 'HEAD'), None)
    if not c:
        return 'pending: presence has no HEAD rev'
    return f'round head {c[:12]}' if build_commit and c == build_commit else f'as of {c[:12]}'


def window_rows(ds):
    return [json.loads(l) for l in gzip.open(Path(ds) / 'derived' / 'window.jsonl.gz', 'rt') if l.strip()]


def build(ds, root=ROOT, rec_root=None):
    """Facts(ds) with every figure of the forensics sections, plus the per-TXID and per-row tables."""
    F = Facts(ds, root, rec_root)
    m = F.m
    if is_v2(m):
        return build_v2(F)
    F.add('version', 'manifest.json', m.get('version'), 'version')
    F.add('dataset', 'manifest.json', m.get('dataset'), 'dataset')
    F.add('files_listed', 'manifest.json', len(m.get('files', {})), 'len(files)')
    F.add('manifest_sha256', 'manifest.json', F._file('manifest.json')[1], 'sha256(manifest.json)')
    F.add('pinned_commit', 'manifest.json', str(m.get('git_base_commit', ''))[:12], 'git_base_commit[:12]')
    cp = m.get('content_pins', {})
    for g in ('replay_tools', 'decoder_inputs', 'cited_lines'):
        F.add(f'pins_{g}', 'manifest.json', len(cp.get(g, {})), f'len(content_pins.{g})')
    F.add('pins_aggregate', 'manifest.json', str(cp.get('aggregate_sha256', 'missing'))[:16], 'content_pins.aggregate_sha256[:16]')
    F.add('hf3_table_sha', 'manifest.json', str(m.get('hf3_table', {}).get('sha256', ''))[:16], 'hf3_table.sha256[:16]')
    F.add('store_count', 'manifest.json', m.get('tierB_store', {}).get('count', 'pending'), 'tierB_store.count')
    F.add('decoder_sha', 'manifest.json', str(m.get('tool_versions', {}).get('decoder_sha256', ''))[:16], 'tool_versions.decoder_sha256[:16]')
    S = 'derived/summary.json'
    for k in ('window_rows', 'tierA_blocks', 'tx_records', 'hf3_records', 'hf3_missing', 'link_rows',
              'state_roots_held_window_topos', 'txid_python_keccak_eq', 'serialize_keccak_python_eq', 'tierA_block_id_python_sha3_eq'):
        F.j(k, S, [k])
    F.j('window_first', S, ['window', 0])
    F.j('window_last', S, ['window', 1])
    F.j('grade_e1', S, ['grades', 'NOT-DECIDABLE-FROM-PUBLIC-DATA/E1'])
    F.j('grade_e2', S, ['grades', 'NOT-DECIDABLE-FROM-PUBLIC-DATA/E2'])
    EM = 'derived/emission.json'
    for fid, path in (('emission_atomic', ['window_emission_atomic']), ('emission_dero', ['window_emission_dero']),
                      ('supply_start', ['calc_supply_at_window_start']), ('supply_end', ['calc_supply_after_window']),
                      ('base_reward', ['base_reward_per_block_atomic', 0]), ('fees_known_blocks', ['fees', 'known_blocks']),
                      ('fees_known_sum', ['fees', 'known_sum_atomic']), ('fees_pending_blocks', ['fees', 'pending_blocks']),
                      ('burn_known_sum', ['per_block', 'burn_known_sum']), ('coinbase_ok', ['per_block', 'coinbase_ok']),
                      ('supply_identity_ok', ['per_block', 'supply_identity_ok']), ('tx_free_blocks', ['per_block', 'tx_free_blocks']),
                      ('node_eq_python_reward', ['per_block', 'node_eq_python_reward']),
                      ('reward_sum_node', ['per_block', 'base_reward_sum_node']), ('reward_sum_python', ['per_block', 'base_reward_sum_python']),
                      ('emission_grade', ['grade', 'verdict_grade'])):
        F.j(fid, EM, path)
    H = 'derived/hf3.json'
    for fid, path in (('carriers_total', ['counts', 'carriers_total']), ('dual_carrier', ['counts', 'dual_carrier']),
                      ('single_carrier', ['counts', 'single_carrier']), ('bodies_raw', ['counts', 'bodies_raw']),
                      ('bl_tips_is_tip', ['counts', 'bl_tips_is_carrier_tip']), ('bl_tips_is_self', ['counts', 'bl_tips_is_carrier_itself']),
                      ('nonce_bypassed', ['counts', 'carriers_nonce_bypassed']),
                      ('parity_changes', ['counts', 'carriers_parity_override_changes_execution']),
                      ('proof_pass', ['counts', 'proof_current_verifier', 'pass']), ('proof_fail', ['counts', 'proof_current_verifier', 'fail']),
                      ('proof_nd', ['counts', 'proof_current_verifier', 'not decidable: ring state unavailable']),
                      ('table_entries', ['table', 'entries']), ('group_dup', ['table', 'groups', 'duplicates']),
                      ('group_fp', ['table', 'groups', 'no duplicates, but false parity']),
                      ('parity_literal_set', ['table', 'parity_literal_set']), ('proof_field_nonzero', ['b83_proof_field', 'nonzero']),
                      ('proof_field_blocks', ['b83_proof_field', 'blocks'])):
        F.j(fid, H, path)
    hf, _ = F.json(H)
    F.add('tx_parity_true', H, sum(1 for r in hf.get('rows', []) if r.get('tx_parity') is True), 'count(rows.tx_parity == true)')
    SR = 'derived/state_roots.json'
    F.j('roots_held', SR, ['held', 'window_topos_with_post_root'])
    F.j('roots_nr', SR, ['not_reconstructable', 'window_topos'])
    F.j('roots_witnessed', SR, ['corroboration_by_tx_statement_roothash', 'equal'])
    RW = 'raw/missing.json'
    F.j('missing_count', RW, ['missing_count'])
    A2 = 'raw/a2_feasibility.json'
    F.j('a2_ok_7415465', A2, ['state_at_7415465', 'answered_ok'])
    F.j('a2_of', A2, ['state_at_7415465', 'of'])
    SRC = 'raw/sources.json'
    F.j('src_probed', SRC, ['candidates_probed'])
    F.j('src_answered', SRC, ['answered_getinfo'])
    src, _ = F.json(SRC)
    F.add('src_serving', SRC, sum(1 for v in (src.get('sources') or {}).values() if v.get('serves_window')), 'count(sources.serves_window)')
    F.add('window_sha', 'derived/window.jsonl.gz', F._file('derived/window.jsonl.gz')[1][:16], 'sha256(derived/window.jsonl.gz)[:16]')
    F.add('expected_lines', 'replay/expected.sha256', len(F._file('replay/expected.sha256')[0].decode().splitlines()),
          'lines(replay/expected.sha256)')
    AR = 'audit/audit_report.json'
    for k in ('challenges', 'holds', 'overturned', 'unresolved', 'verdicts', 'downgraded', 'overturned_all_runs'):
        F.j(f'audit_{k}', AR, ['counts', k])
    ar, _ = F.json(AR)
    F.add('audit_history_runs', AR, len(ar.get('history', [])), 'len(history)')
    F.add('audit_data_sha', AR, str(ar.get('binding', {}).get('data_sha256', ''))[:16], 'binding.data_sha256[:16]')
    vs = ar.get('verdicts', [])
    F.add('v_hf3_nd', AR, sum(1 for v in vs if v['id'].startswith('V-HF3-') and v.get('audit_grade') == 'NOT-DECIDABLE-FROM-PUBLIC-DATA'),
          'count(verdicts V-HF3-* audit_grade NOT-DECIDABLE)')
    F.add('v_speculation', AR, sum(1 for v in vs if v.get('audit_grade') == 'SPECULATION'), 'count(verdicts audit_grade SPECULATION)')
    F.add('v_pending', AR, sum(1 for v in vs if v.get('audit_grade') == 'pending'), 'count(verdicts audit_grade pending)')
    F.add('v_proven_scope', AR, sum(1 for v in vs if v.get('audit_grade') == 'PROVEN-NO-INFLATION-IN-SCOPE'),
          'count(verdicts audit_grade PROVEN-NO-INFLATION-IN-SCOPE)')
    F.add('v_proven_inflation', AR, sum(1 for v in vs if v.get('audit_grade') == 'PROVEN-INFLATION'), 'count(verdicts audit_grade PROVEN-INFLATION)')
    for h in ar.get('history', []):
        F.add(f"hist_{h['run']}_overturned", AR, h['counts'].get('overturned', 0), f"history[{h['run']}].counts.overturned")
        F.add(f"hist_{h['run']}_holds", AR, h['counts'].get('holds', 0), f"history[{h['run']}].counts.holds")
    rec, _ = F.json(RECORD, 'record')
    runs = rec.get('runs', []) if rec.get('manifest_sha256') == F.facts['manifest_sha256']['value'] else []
    F.add('replay_runs', RECORD, len(runs), 'len(runs) bound to the current manifest', 'record')
    F.add('replay_runs_full_pass', RECORD, sum(1 for r in runs if r.get('result') == 'PASS' and r.get('mode') == 'full'),
          'count(runs PASS full)', 'record')
    F.add('replay_report', RECORD, (runs[-1]['report_sha256'][:16] if runs else 'pending'), 'runs[-1].report_sha256[:16]', 'record')
    F.add('replay_byte_exact', RECORD, bool(runs) and len({r['report_sha256'] for r in runs}) == 1 and len(runs) >= 2,
          'runs >= 2 with one report_sha256', 'record')
    F.add('replay_last', RECORD, (runs[-1]['when'].replace('T', ' ') if runs else 'pending'), 'runs[-1].when (local time of that run, with its offset)', 'record')
    rep = rec.get('report', {}) if runs else {}
    F.add('replay_equal', RECORD, rep.get('rederive', {}).get('equal', 'pending'), 'report.rederive.equal', 'record')
    F.add('replay_expected', RECORD, rep.get('rederive', {}).get('expected', 'pending'), 'report.rederive.expected', 'record')
    F.add('replay_rows_store', RECORD, rep.get('raw', {}).get('rows_from_store', 'pending'), 'report.raw.rows_from_store', 'record')
    F.add('replay_headerchain_rows', RECORD, rep.get('raw', {}).get('headerchain_rows', 'pending'), 'report.raw.headerchain_rows', 'record')
    F.add('replay_dataset_blobs', RECORD, rep.get('raw', {}).get('dataset_blobs', 'pending'), 'report.raw.dataset_blobs', 'record')
    # per TXID (the 75-row table): every number of a row is its own fact
    for r in hf.get('rows', []):
        k = 'tx:' + r['txid'][:8]
        F.add(k + ':height', H, r['table_height'], f"rows[txid={r['txid'][:8]}].table_height")
        F.add(k + ':line', H, r['line'], f"rows[txid={r['txid'][:8]}].line (blockchain/hardfork_fixes.go)")
        F.add(k + ':fee', H, r['fee'], f"rows[txid={r['txid'][:8]}].fee")
        F.add(k + ':ncar', H, len(r['carriers']), f"len(rows[txid={r['txid'][:8]}].carriers)")
        F.add(k + ':carriers', H, ', '.join(f'{c:,}' for c in r['carriers']), f"rows[txid={r['txid'][:8]}].carriers")
        F.add(k + ':ring', H, '/'.join(str(x) for x in r.get('ring_sizes', [])), f"rows[txid={r['txid'][:8]}].ring_sizes")
        F.add(k + ':nonce_bypassed', H, len(r.get('nonce_bypassed_carriers', [])), f"len(rows[txid={r['txid'][:8]}].nonce_bypassed_carriers)")
        F.add(k + ':parity_changes', H, len(r.get('parity_override_changes_execution', [])),
              f"len(rows[txid={r['txid'][:8]}].parity_override_changes_execution)")
    for r in hf.get('rows', []):
        k = 'tx:' + r['txid'][:8]
        F.add(k + ':proof', H, r['proof_current_verifier'], f"rows[txid={r['txid'][:8]}].proof_current_verifier")
        F.add(k + ':grade', H, r['evidence_grade'], f"rows[txid={r['txid'][:8]}].evidence_grade")
        F.add(k + ':group', H, r['group'], f"rows[txid={r['txid'][:8]}].group")
        F.add(k + ':parity', H, r['tx_parity'], f"rows[txid={r['txid'][:8]}].tx_parity")
        F.add(k + ':txid', H, r['txid'], f"rows[txid={r['txid'][:8]}].txid")
        F.add(k + ':body', H, r['body_sha256'][:16], f"rows[txid={r['txid'][:8]}].body_sha256[:16]")
    for key, v in sorted((hf.get('paths') or {}).items()):
        F.add('path:' + key, H, v, f'paths.{key} (code citation)')
    CH = 'audit/challenges.json'
    chj, _ = F.json(CH)
    for c in chj.get('challenges', []):
        F.add(f"ch:{c['id']}:claim", CH, c.get('claim', ''), f"challenges[{c['id']}].claim (verbatim)")
        F.add(f"ch:{c['id']}:result", CH, c.get('result', ''), f"challenges[{c['id']}].result")
        F.add(f"ch:{c['id']}:evidence", CH, '; '.join(f"{e['class']}: {e['what']}" for e in c.get('evidence', [])),
              f"challenges[{c['id']}].evidence (verbatim)")
        F.add(f"ch:{c['id']}:note", CH, c.get('note') or '', f"challenges[{c['id']}].note (verbatim)")
    for v in vs:
        F.add(f"v:{v['id']}:grade", AR, v.get('audit_grade', ''), f"verdicts[{v['id']}].audit_grade")
        for fld in ('scope', 'reason', 'downgrade_note', 'deciding_fact_missing'):
            if v.get(fld):
                F.add(f"v:{v['id']}:{fld}", AR, v[fld], f"verdicts[{v['id']}].{fld} (verbatim)")
        if v.get('correction_history'):
            F.add(f"v:{v['id']}:correction", AR, '; '.join(v['correction_history']), f"verdicts[{v['id']}].correction_history")
    for h in ar.get('history', []):
        F.add(f"hist_{h['run']}_ids", AR, ', '.join(h['overturned']) or 'none', f"history[{h['run']}].overturned")
        F.add(f"hist_{h['run']}_unresolved", AR, ', '.join(h['unresolved']) or 'none', f"history[{h['run']}].unresolved")
        F.add(f"hist_{h['run']}_report", AR, h['report_sha256'][:16], f"history[{h['run']}].report_sha256[:16]")
    for name, tx in (('wall2', '0045a6d4'), ('wall3', '4d56a1a1')):
        r = next((x for x in hf.get('rows', []) if x['txid'].startswith(tx)), None)
        F.add(name, H, r['table_height'] if r else 'pending', f'rows[txid={tx}].table_height (replay wall, disc:139)')
    an, _ = F.json('raw/anchors.json')
    arch = next((x for x in an if x.get('kind') == 'archive_topo_records'), {})
    blk = next((x for x in an if x.get('kind') == 'block'), {})
    F.add('archive_first', 'raw/anchors.json', (arch.get('topo_range') or ['pending'])[0], 'archive_topo_records.topo_range[0]')
    F.add('archive_last', 'raw/anchors.json', (arch.get('topo_range') or ['pending', 'pending'])[-1], 'archive_topo_records.topo_range[1]')
    F.add('archive_count', 'raw/anchors.json', arch.get('count', 'pending'), 'archive_topo_records.count')
    F.add('anchor_height', 'raw/anchors.json', blk.get('height', 'pending'), 'block anchor height')
    F.add('anchor_id', 'raw/anchors.json', str(blk.get('id', ''))[:16], 'block anchor id[:16]')
    for v in vs:
        if v['id'].startswith('V-EXT-'):
            mm = re.search(r'figure ([\d,.]+) DERO', v.get('question', ''))
            F.add('ext:' + v['id'][6:], AR, mm.group(1) if mm else 'pending', f"verdicts[{v['id']}].question (EXT figure)")
    em, _ = F.json(EM)
    F.add('emission_scope', EM, em.get('grade', {}).get('scope', 'pending'), 'grade.scope (verbatim)')
    # round-over-round growth: the R24 disclosure track and the R25 discovery note (records outside the dataset)
    DT = 'harness/loop/disclosure_track.json'
    dt, _ = F.json(DT, 'record')
    F.add('dt_claims', DT, len(dt.get('claims', [])), 'len(claims)', 'record')
    F.add('dt_facts_r24', DT, sum(1 for x in dt.get('facts', []) if x.get('round') == 'R24'), 'count(facts round R24)', 'record')
    F.add('dt_facts_r25', DT, sum(1 for x in dt.get('facts', []) if x.get('round') == 'R25'), 'count(facts round R25)', 'record')
    DISC = 'harness/runtime/r25_forensics_discovery_20261103.txt'
    dtxt = F._file(DISC, 'record')[0].decode(errors='replace')
    mm = re.search(r'live_tx_bodies_available=(\d+) of (\d+)', dtxt)
    F.add('disc_live_bodies', DISC, int(mm.group(1)) if mm else 'pending', 'live_tx_bodies_available (line 103)', 'record')
    F.add('disc_live_of', DISC, int(mm.group(2)) if mm else 'pending', 'live_tx_bodies_available … of (line 103)', 'record')
    return F


V1 = 'forensics/r25'
MERGE_REPLAY = 'harness/runtime/r26_merge_a2_hf3_replay_20261104.json'
DT = 'harness/loop/disclosure_track.json'
CLASS_IDS = ('DC0', 'DC1', 'DC2', 'DC3')


def is_v2(m):
    return isinstance(m.get('version'), int) and m.get('version') >= 2   # R28: v3 (forensics/r28) has the v2 layout


def _short(v, n=16):
    return str(v)[:n] if v not in (None, '') else 'pending'


def build_v2(F):
    """r26: every figure of the dataset-v2 forensics sections (forensics_section.section_v2), the src-arch lines and the
    soundness page's generated section. Dataset files are class 'dataset'; the sealed v1 files v2 pins are 'prior';
    run records are 'record'. A missing key is a problem (G30 fails) and the value is 'pending'."""
    m = F.m
    F.add('version', 'manifest.json', m.get('version'), 'version')
    F.add('dataset', 'manifest.json', m.get('dataset'), 'dataset')
    F.add('files_listed', 'manifest.json', len(m.get('files', {})), 'len(files)')
    F.add('manifest_sha256', 'manifest.json', F._file('manifest.json')[1], 'sha256(manifest.json)')
    F.add('pinned_commit', 'manifest.json', str(m.get('git_base_commit', ''))[:12], 'git_base_commit[:12]')
    F.add('tools_pinned', 'manifest.json', len(m.get('tools', {})), 'len(tools)')
    F.add('inputs_pinned', 'manifest.json', len(m.get('inputs', {})), 'len(inputs) (v1 files read by path, pinned by SHA-256)')
    F.add('class_files', 'manifest.json', len(m.get('class_files', {})), 'len(class_files)')
    F.add('hf3_table_sha', 'manifest.json', str(m.get('hf3_table', {}).get('sha256', ''))[:16], 'hf3_table.sha256[:16]')
    F.add('store_tx_bodies', 'manifest.json', m.get('tierB_store', {}).get('tx_bodies', 'pending'), 'tierB_store.tx_bodies')
    F.add('supersedes', 'manifest.json', ', '.join(m.get('supersedes') or []) or 'none', 'supersedes')
    S = 'derived/summary.json'
    for k in ('txs_decoded', 'tx_bodies_raw', 'tx_bodies_needed', 'tx_bodies_missing', 'txblocks', 'v1_pending_fee_blocks',
              'v1_pending_settled', 'v1_pending_still', 'records_with_class_slot', 'replay_runs'):
        F.j(k, S, [k])
    F.j('window_first', S, ['window', 0])
    F.j('window_last', S, ['window', 1])
    F.j('end_state_A', S, ['end_state', 'A'])
    # the v1 files v2 builds on (sealed; pinned in manifest inputs)
    WIN = f'{V1}/derived/window.jsonl.gz'
    wb, _ = F._file(WIN, 'prior')
    nrows = sum(1 for l in (gzip.decompress(wb).decode().splitlines() if wb else []) if l.strip())
    F.add('window_rows', WIN, nrows, 'rows of the v1 window file (pinned in manifest inputs)', 'prior')
    F.add('window_sha', WIN, F._file(WIN, 'prior')[1][:16], 'sha256[:16] (the v1 manifest entry = the v2 pin)', 'prior')
    EM = f'{V1}/derived/emission.json'
    for fid, path in (('emission_atomic', ['window_emission_atomic']), ('emission_dero', ['window_emission_dero']),
                      ('supply_start', ['calc_supply_at_window_start']), ('supply_end', ['calc_supply_after_window']),
                      ('base_reward', ['base_reward_per_block_atomic', 0]), ('coinbase_ok', ['per_block', 'coinbase_ok']),
                      ('supply_identity_ok', ['per_block', 'supply_identity_ok']), ('tx_free_blocks', ['per_block', 'tx_free_blocks']),
                      ('node_eq_python_reward', ['per_block', 'node_eq_python_reward']),
                      ('emission_grade', ['grade', 'verdict_grade']), ('emission_scope', ['grade', 'scope'])):
        F.j(fid, EM, path, 'prior')
    H = f'{V1}/derived/hf3.json'
    for fid, path in (('carriers_total', ['counts', 'carriers_total']), ('dual_carrier', ['counts', 'dual_carrier']),
                      ('single_carrier', ['counts', 'single_carrier']), ('bodies_raw', ['counts', 'bodies_raw']),
                      ('bl_tips_is_tip', ['counts', 'bl_tips_is_carrier_tip']), ('bl_tips_is_self', ['counts', 'bl_tips_is_carrier_itself']),
                      ('nonce_bypassed', ['counts', 'carriers_nonce_bypassed']),
                      ('parity_changes', ['counts', 'carriers_parity_override_changes_execution']),
                      ('proof_pass', ['counts', 'proof_current_verifier', 'pass']), ('proof_fail', ['counts', 'proof_current_verifier', 'fail']),
                      ('proof_nd', ['counts', 'proof_current_verifier', 'not decidable: ring state unavailable']),
                      ('table_entries', ['table', 'entries']), ('group_dup', ['table', 'groups', 'duplicates']),
                      ('group_fp', ['table', 'groups', 'no duplicates, but false parity']),
                      ('parity_literal_set', ['table', 'parity_literal_set'])):
        F.j(fid, H, path, 'prior')
    hf, _ = F.json(H, 'prior')
    F.add('tx_parity_true', H, sum(1 for r in hf.get('rows', []) if r.get('tx_parity') is True), 'count(rows.tx_parity == true)', 'prior')
    for r in hf.get('rows', []):
        k, t = 'tx:' + r['txid'][:8], r['txid'][:8]
        for fld, v, how in (('height', r['table_height'], 'table_height'), ('line', r['line'], 'line (blockchain/hardfork_fixes.go)'),
                            ('fee', r['fee'], 'fee'), ('ncar', len(r['carriers']), 'len(carriers)'),
                            ('carriers', ', '.join(f'{c:,}' for c in r['carriers']), 'carriers'),
                            ('nonce_bypassed', len(r.get('nonce_bypassed_carriers', [])), 'len(nonce_bypassed_carriers)'),
                            ('parity_changes', len(r.get('parity_override_changes_execution', [])), 'len(parity_override_changes_execution)'),
                            ('proof', r['proof_current_verifier'], 'proof_current_verifier'), ('grade', r['evidence_grade'], 'evidence_grade'),
                            ('group', r['group'], 'group'), ('parity', r['tx_parity'], 'tx_parity'), ('txid', r['txid'], 'txid'),
                            ('body', r['body_sha256'][:16], 'body_sha256[:16]')):
            F.add(f'{k}:{fld}', H, v, f'rows[txid={t}].{how}', 'prior')
    for key, v in sorted((hf.get('paths') or {}).items()):
        F.add('path:' + key, H, v, f'paths.{key} (code citation)', 'prior')
    F.j('missing_count', f'{V1}/raw/missing.json', ['missing_count'], 'prior')
    AN = f'{V1}/raw/anchors.json'
    an, _ = F.json(AN, 'prior')
    an = an if isinstance(an, list) else []
    arch = next((x for x in an if x.get('kind') == 'archive_topo_records'), {})
    blk = next((x for x in an if x.get('kind') == 'block'), {})
    F.add('archive_first', AN, (arch.get('topo_range') or ['pending'])[0], 'archive_topo_records.topo_range[0]', 'prior')
    F.add('archive_last', AN, (arch.get('topo_range') or ['pending', 'pending'])[-1], 'archive_topo_records.topo_range[1]', 'prior')
    F.add('anchor_height', AN, blk.get('height', 'pending'), 'block anchor height', 'prior')
    F.add('anchor_id', AN, _short(blk.get('id')), 'block anchor id[:16]', 'prior')
    for name, tx in (('wall2', '0045a6d4'), ('wall3', '4d56a1a1')):
        r = next((x for x in hf.get('rows', []) if x['txid'].startswith(tx)), None)
        F.add(name, H, r['table_height'] if r else 'pending', f'rows[txid={tx}].table_height (replay wall)', 'prior')
    # fees, burns, SC (dataset v2)
    FE = 'derived/fees.json'
    for fid, path in (('fee_window_sum', ['v2', 'window_fee_sum']), ('burn_window_sum', ['v2', 'window_burn_sum']),
                      ('fee_window_txblocks', ['v2', 'window_txblocks']), ('fee_window_pending', ['v2', 'window_fee_pending_blocks']),
                      ('fee_gap_sum', ['v2', 'gap_fee_sum']), ('burn_gap_sum', ['v2', 'gap_burn_sum']), ('fee_gap_txblocks', ['v2', 'gap_txblocks']),
                      ('fee_settled', ['v2', 'settled']), ('fee_settled_sum', ['v2', 'settled_fee_sum']), ('burn_settled_sum', ['v2', 'settled_burn_sum']),
                      ('fee_still_pending', ['v2', 'still_pending']), ('sc_txs', ['v2', 'sc_txs']), ('sc_tx_blocks', ['v2', 'sc_tx_blocks']),
                      ('fee_v1_known_blocks', ['v1', 'known_blocks']), ('fee_v1_known_sum', ['v1', 'known_sum_atomic']),
                      ('fee_v1_pending_blocks', ['v1', 'pending_blocks']), ('sc_payouts', ['sc_payouts']), ('fees_scope', ['scope']),
                      ('fees_rule', ['rule'])):
        F.j(fid, FE, path)
    fe, _ = F.json(FE)
    F.add('fee_v1_disagree', FE, len(fe.get('v1_known_rows_disagreeing') or []), 'len(v1_known_rows_disagreeing)')
    # state roots, node replay runs, walls, (a2), inclusions
    SR = 'derived/state_roots.json'
    sr0, _ = F.json(SR)
    # R28 v3: runs of two entry points (pre-fix A/B, HF3-entry C) are compared per entry; v2 has one flag
    ident = (['runs_byte_identical_per_entry', 'blockchain.Add_Complete_Block (pre-fix tool, B123)']
             if 'runs_byte_identical_per_entry' in (sr0 or {}) else ['runs_byte_identical'])
    if 'C' in ((sr0 or {}).get('runs') or {}):
        for fid, path in (('runc_end_state', ['runs', 'C', 'end_state_check']), ('runc_topos', ['runs', 'C', 'topos']),
                          ('runc_first', ['runs', 'C', 'topo_range', 0]), ('runc_last', ['runs', 'C', 'topo_range', 1]),
                          ('runs_identical_hf3', ['runs_byte_identical_per_entry', 'p2p.Add_Complete_Block_HF3'])):
            F.j(fid, SR, path)
    for fid, path in (('roots_topos', ['window_coverage', 'topos_with_pre_post_root']), ('roots_window_topos', ['window_coverage', 'window_topos']),
                      ('roots_pending_first', ['window_coverage', 'pending_range', 0]), ('roots_pending_last', ['window_coverage', 'pending_range', 1]),
                      ('run_fail_topo', ['runs', 'A', 'fail_topo']), ('run_fail_error', ['runs', 'A', 'fail_error']),
                      ('run_topos', ['runs', 'A', 'topos']), ('run_first', ['runs', 'A', 'topo_range', 0]), ('run_last', ['runs', 'A', 'topo_range', 1]),
                      ('runs_identical', ident), ('wit_equal', ['roothash_witnesses', 'equal']),
                      ('wit_differ', ['roothash_witnesses', 'differ']), ('wit_archive_equal', ['roothash_witnesses', 'archive_equal']),
                      ('wit_archive_differ', ['roothash_witnesses', 'archive_differ']), ('wit_outside', ['roothash_witnesses', 'outside_held_roots']),
                      ('a10c_answer', ['a10c', 'answer']), ('anchor_topo', ['anchor_topo'])):
        F.j(fid, SR, path)
    sr, _ = F.json(SR)
    F.add('our_treehash', SR, _short(sr.get('our_treehash_at_anchor')), 'our_treehash_at_anchor[:16]')
    F.add('seed_root', SR, _short((sr.get('a10c') or {}).get('seed_top_root')), 'a10c.seed_top_root[:16]')
    WL = 'derived/walls.json'
    for fid, path in (('wall4_topo', ['replay_stops', 'runs', 'A', 'topo']), ('wall4_check', ['replay_stops', 'runs', 'A', 'check']),
                      ('wall4_in_table', ['replay_stops', 'runs', 'A', 'txid_in_hf3_table']),
                      ('wall1_radius', ['wall1', 'radius'])):
        F.j(fid, WL, path)
    wl, _ = F.json(WL)
    F.add('wall4_txid', WL, _short(((wl.get('replay_stops') or {}).get('runs') or {}).get('A', {}).get('txid')), 'replay_stops.runs.A.txid[:16]')
    F.add('wall1_rows', WL, len((wl.get('wall1') or {}).get('rows') or []), 'len(wall1.rows)')
    F.j('a2_verdict', 'derived/a2.json', ['verdict'])
    F.j('a2_question', 'derived/a2.json', ['question'])
    F.j('incl_in_table', 'derived/inclusions.json', ['in_hf3_table'])
    inc, _ = F.json('derived/inclusions.json')
    F.add('incl_not_in_table', 'derived/inclusions.json', len(inc.get('not_in_hf3_table') or []), 'len(not_in_hf3_table)')
    # the merge-stage node replay through the HF3 entry (a run record outside the dataset, rft §7 B123)
    MR, RC = MERGE_REPLAY, 'record'
    for fid, path in (('mr_added', ['replay', 'added']), ('mr_txs', ['replay', 'txs']), ('mr_from', ['replay', 'from']), ('mr_to', ['replay', 'to']),
                      ('mr_end_match', ['replay', 'end_state_match']), ('mr_seconds', ['replay', 'seconds']), ('mr_stopped', ['replay', 'stopped'])):
        F.j(fid, MR, path, RC)
    mr, _ = F.json(MR, RC)
    F.add('mr_last_root', MR, _short((mr.get('replay') or {}).get('last_root')), 'replay.last_root[:16]', RC)
    F.add('mr_walls_accepted', MR, sum(1 for w in (mr.get('walls') or {}).values() if w.get('accepted') is True), 'count(walls.accepted)', RC)
    F.add('mr_walls', MR, len(mr.get('walls') or {}), 'len(walls)', RC)
    F.add('mr_roots_sha', MR, _short(mr.get('roots_jsonl_sha256')), 'roots_jsonl_sha256[:16]', RC)
    # classes.json (the class figures themselves render as fcl spans; these are the class-level facts)
    CL = 'derived/classes.json'
    for fid, path in (('cl_dc1_obs', ['classes', 'DC1', 'subclasses', 'DC1-obs']), ('cl_dc1_hidden', ['classes', 'DC1', 'subclasses', 'DC1-hidden']),
                      ('cl_dc1_pending', ['classes', 'DC1', 'subclasses', 'DC1-pending']), ('cl_dc1_detected', ['classes', 'DC1', 'detected_raw']),
                      ('cl_dc1_rule', ['classes', 'DC1', 'subclass_rule']), ('cl_dc1_grade', ['classes', 'DC1', 'grade']),
                      ('cl_dc2_grade', ['classes', 'DC2', 'grade']), ('cl_dc2_present', ['classes', 'DC2', 'present_now']),
                      ('cl_dc2_c1_verdict', ['classes', 'DC2', 'track_c1', 'verdict']), ('cl_dc2_c1_state', ['classes', 'DC2', 'track_c1', 'state']),
                      ('cl_dc3_grade', ['classes', 'DC3', 'grade']), ('cl_dc0_detected', ['classes', 'DC0', 'detected']),
                      ('cl_headline', ['headline', 'text']), ('cl_base', ['base']),
                      ('cl_hist_e1', ['historical_grades', 'counts', 'NOT-DECIDABLE-FROM-PUBLIC-DATA/E1']),
                      ('cl_hist_e2', ['historical_grades', 'counts', 'NOT-DECIDABLE-FROM-PUBLIC-DATA/E2'])):
        F.j(fid, CL, path)
    cl, _ = F.json(CL)
    figs = cl.get('figures') or []
    F.add('cl_figures', CL, len(figs), 'len(figures)')
    for b in ('exact', 'lower-bound', 'upper-bound', 'unbounded'):
        F.add(f'cl_bound:{b}', CL, sum(1 for f in figs if f.get('bound_type') == b), f'count(figures.bound_type == {b})')
    for f in figs:
        k, c = 'clf:' + f['id'], f.get('coverage') or {}
        F.add(k + ':label', CL, f.get('label', ''), f'figures[{f["id"]}].label')
        F.add(k + ':num', CL, c.get('num', 'pending'), f'figures[{f["id"]}].coverage.num')
        F.add(k + ':den', CL, c.get('den', 'pending'), f'figures[{f["id"]}].coverage.den')
        F.add(k + ':num_anchor', CL, c.get('num_anchor', ''), f'figures[{f["id"]}].coverage.num_anchor')
        F.add(k + ':den_anchor', CL, c.get('den_anchor', ''), f'figures[{f["id"]}].coverage.den_anchor')
        F.add(k + ':scope', CL, (f.get('scope') or {}).get('text', 'pending'), f'figures[{f["id"]}].scope.text')
        F.add(k + ':bound', CL, f.get('bound_type', 'pending'), f'figures[{f["id"]}].bound_type')
        F.add(k + ':unit', CL, f.get('unit', ''), f'figures[{f["id"]}].unit')
        if f.get('note'):
            F.add(k + ':note', CL, f['note'], f'figures[{f["id"]}].note (verbatim)')
        if f.get('moves_when'):   # r30 (B203): what would move a non-exact figure
            F.add(k + ':moves_when', CL, f['moves_when'], f'figures[{f["id"]}].moves_when (verbatim)')
        if f.get('grade'):
            F.add(k + ':grade', CL, f['grade'], f'figures[{f["id"]}].grade')
    # presence.json: per class, per rev
    PR = 'derived/presence.json'
    pr, _ = F.json(PR)
    revs = [r.get('rev') for r in pr.get('revs', [])]
    F.add('pr_revs', PR, len(revs), 'len(revs)')
    for r in pr.get('revs', []):
        F.add(f'pr_rev:{r.get("rev")}:commit', PR, _short(r.get('commit'), 12), f'revs[{r.get("rev")}].commit[:12]')
        F.add(f'pr_rev:{r.get("rev")}:role', PR, r.get('role', ''), f'revs[{r.get("rev")}].role')
    F.j('pr_headline', PR, ['headline', 'text'])
    F.add('pr_head_label', PR, presence_head_label(pr, F.m.get('git_base_commit')),
          "revs[HEAD].commit vs manifest git_base_commit: 'round head <c>' or 'as of <c>' (r30 B216)")
    F.j('pr_dc2_present', PR, ['headline', 'dc2_present_now'])
    for cid, cv in sorted((pr.get('classes') or {}).items()):
        for rev, row in sorted(cv.items()):
            k = f'pr:{cid}:{rev}'
            an = row.get('anchors') or []
            F.add(k + ':admits', PR, row.get('admits', 'pending'), f'classes.{cid}.{rev}.admits')
            F.add(k + ':present', PR, sum(1 for a in an if a.get('present')), f'count(classes.{cid}.{rev}.anchors.present)')
            F.add(k + ':anchors', PR, len(an), f'len(classes.{cid}.{rev}.anchors)')
            F.add(k + ':closures', PR, row.get('closures_present', 'pending'), f'classes.{cid}.{rev}.closures_present')
            F.add(k + ':closures_total', PR, row.get('closures_total', 'pending'), f'classes.{cid}.{rev}.closures_total')
            F.add(k + ':where', PR, '; '.join(a.get('anchor', '') for a in an if a.get('present')) or 'none',
                  f'classes.{cid}.{rev}.anchors[present].anchor')
            for i, a in enumerate(an):
                F.add(f'{k}:role:{i}', PR, a.get('role', ''), f'classes.{cid}.{rev}.anchors[{i}].role')
    # invariant.json (Q-CS1..3, the missing-invariant certificate)
    IV = 'derived/invariant.json'
    for fid, path in (('q1_status', ['Q-CS1', 'status']), ('q1_answer', ['Q-CS1', 'answer']), ('q1_keys', ['Q-CS1', 'balance_tree_keys']),
                      ('q1_sc_keys', ['Q-CS1', 'sc_tree_keys_total']), ('q1_sc_meta', ['Q-CS1', 'sc_meta_keys']),
                      ('q1_sc_33', ['Q-CS1', 'sc_tree_keys_length_33']), ('q1_sc_33_note', ['Q-CS1', 'sc_tree_keys_length_33_note']),
                      ('q1_topo', ['Q-CS1', 'scope', 'topo']), ('q1_version', ['Q-CS1', 'scope', 'state_version']),
                      ('q1_store', ['Q-CS1', 'scope', 'store']), ('q1_root_equal', ['Q-CS1', 'root_check', 'equal']),
                      ('q1_r22_count', ['Q-CS1', 'r22_comparison', 'count']), ('q1_r22_class', ['Q-CS1', 'r22_comparison', 'class']),
                      ('q1_r22_note', ['Q-CS1', 'r22_comparison', 'note']), ('q1_r22_diff', ['Q-CS1', 'r22_comparison', 'difference_r22_minus_this']),
                      ('q2_question', ['Q-CS2', 'question']), ('q2_answer', ['Q-CS2', 'answer']), ('q2_reason', ['Q-CS2', 'reason']),
                      ('q2_status', ['Q-CS2', 'status']), ('q3_question', ['Q-CS3', 'question']), ('q3_answer', ['Q-CS3', 'answer']),
                      ('q3_status', ['Q-CS3', 'status']), ('q3_missing', ['Q-CS3', 'certificate', 'missing_invariant']),
                      ('q3_consequence', ['Q-CS3', 'certificate', 'consequence']), ('q3_joins', ['Q-CS3', 'certificate', 'joins'])):
        F.j(fid, IV, path)
    iv, _ = F.json(IV)
    F.add('q1_root', IV, _short(((iv.get('Q-CS1') or {}).get('root_check') or {}).get('census_root')), 'Q-CS1.root_check.census_root[:16]')
    q2a = (iv.get('Q-CS2') or {}).get('anchors') or []
    F.add('q2_anchors', IV, len(q2a), 'len(Q-CS2.anchors)')
    F.add('q2_anchors_ok', IV, sum(1 for a in q2a if a.get('ok')), 'count(Q-CS2.anchors.ok)')
    for i, a in enumerate(q2a):
        F.add(f'q2_anchor:{i}', IV, a.get('anchor', ''), f'Q-CS2.anchors[{i}].anchor')
        F.add(f'q2_what:{i}', IV, a.get('what', ''), f'Q-CS2.anchors[{i}].what')
    F.add('q3_shown_by', IV, '; '.join(((iv.get('Q-CS3') or {}).get('certificate') or {}).get('absence_shown_by') or []) or 'pending',
          'Q-CS3.certificate.absence_shown_by')
    # fq.json (FQ1..FQ6 status)
    FQ = 'derived/fq.json'
    fq, _ = F.json(FQ)
    for q in ('FQ1', 'FQ2', 'FQ3', 'FQ4', 'FQ5', 'FQ6'):
        F.add(f'fq:{q}:status', FQ, (fq.get(q) or {}).get('status', 'pending'), f'{q}.status')
        F.add(f'fq:{q}:question', FQ, (fq.get(q) or {}).get('question', 'pending'), f'{q}.question')
    for fid, path in (('fq1_distinct', ['FQ1', 'answer', 'window_distinct_txids']), ('fq1_txblocks', ['FQ1', 'answer', 'window_tx_carrying_blocks']),
                      ('fq1_multi', ['FQ1', 'answer', 'window_txids_in_two_or_more_blocks']), ('fq1_in_table', ['FQ1', 'answer', 'of_which_in_table']),
                      ('fq1_two_bodies', ['FQ1', 'answer', 'two_bodies_under_one_txid']), ('fq1_note', ['FQ1', 'note']),
                      ('fq2_p1', ['FQ2', 'criteria', 'P1', 'result']), ('fq2_sr22', ['FQ2', 'criteria', 'S-R22', 'result']),
                      ('fq2_sr22_scope', ['FQ2', 'criteria', 'S-R22', 'scope']), ('fq2_consequence', ['FQ2', 'consequence']),
                      ('fq3_boundary', ['FQ3', 'boundary_height']), ('fq3_link', ['FQ3', 'mechanism_link_to_dc1']),
                      ('fq3_tags', ['FQ3', 'code_side', 'upstream_tags_with_deterministic_r', 'tags_total']),
                      ('fq3_tags_r', ['FQ3', 'code_side', 'upstream_tags_with_deterministic_r', 'tags_with_deterministic_r']),
                      ('fq3_tags_fix', ['FQ3', 'code_side', 'upstream_tags_with_deterministic_r', 'tags_with_pick_ring_order']),
                      ('fq3_bodies', ['FQ3', 'census', 'bodies_decoded']), ('fq3_shared', ['FQ3', 'census', 'txs_with_a_shared_commitment']),
                      ('fq5_answer', ['FQ5', 'answer'])):
        F.j(fid, FQ, path)
    q2 = (fq.get('FQ2') or {})
    if 'S-RT' in (q2.get('criteria') or {}):   # r30 (B203 2/3): the S-RT precondition and the dated corrections, from fq.json
        F.j('fq2_srt', FQ, ['FQ2', 'criteria', 'S-RT', 'result'])
        F.add('fq2_corrections', FQ, len(q2.get('corrections') or []), 'len(FQ2.corrections)')
    # the independent audit (audit2) of v2
    AR = 'audit/audit_report.json'
    for k in ('challenges', 'holds', 'overturned', 'unresolved', 'verdicts', 'downgraded', 'overturned_all_runs',
              'overturned_distinct_all_runs', 'claims_corrected'):
        F.j(f'audit_{k}', AR, ['counts', k])
    ar, _ = F.json(AR)
    F.add('audit_history_runs', AR, len(ar.get('history', [])), 'len(history)')
    F.add('audit_data_sha', AR, _short(ar.get('binding', {}).get('data_sha256')), 'binding.data_sha256[:16]')
    F.add('audit_files_bound', AR, ar.get('binding', {}).get('files_bound', 'pending'), 'binding.files_bound')
    F.add('audit_impl', AR, (ar.get('implementation') or {}).get('name', 'pending'), 'implementation.name')
    F.add('audit_impl_file', AR, (ar.get('implementation') or {}).get('file', 'pending'), 'implementation.file')
    F.add('audit_shares_code', AR, (ar.get('implementation') or {}).get('shares_code_with_builder', 'pending'), 'implementation.shares_code_with_builder')
    for i, n in enumerate(ar.get('nogo') or []):
        F.add(f'nogo:{i}:what', AR, n.get('what', ''), f'nogo[{i}].what')
        F.add(f'nogo:{i}:instead', AR, n.get('instead', ''), f'nogo[{i}].instead')
    vs = ar.get('verdicts', [])
    for v in vs:
        vid = v['id']
        F.add(f'v:{vid}:grade', AR, v.get('audit_grade', 'pending'), f'verdicts[{vid}].audit_grade')
        for fld in ('question', 'reason', 'builder_grade', 'source'):
            if v.get(fld):
                F.add(f'v:{vid}:{fld}', AR, v[fld], f'verdicts[{vid}].{fld} (verbatim)')
        F.add(f'v:{vid}:open', AR, ', '.join(v.get('open_or_failed') or []) or 'none', f'verdicts[{vid}].open_or_failed')
        for fg in v.get('figures') or []:
            F.add(f'v:{vid}:fig:{fg["id"]}', AR, fg.get('value', 'pending'), f'verdicts[{vid}].figures[{fg["id"]}].value')
            F.add(f'v:{vid}:fig:{fg["id"]}:bound', AR, fg.get('bound_type', 'pending'), f'verdicts[{vid}].figures[{fg["id"]}].bound_type')
            cv = fg.get('coverage') or {}
            F.add(f'v:{vid}:fig:{fg["id"]}:num', AR, cv.get('num', 'pending'), f'verdicts[{vid}].figures[{fg["id"]}].coverage.num')
            F.add(f'v:{vid}:fig:{fg["id"]}:den', AR, cv.get('den', 'pending'), f'verdicts[{vid}].figures[{fg["id"]}].coverage.den')
    gr = {}
    for v in vs:
        gr[v.get('audit_grade', 'pending')] = gr.get(v.get('audit_grade', 'pending'), 0) + 1
    for g in ('NOT-DECIDABLE-FROM-PUBLIC-DATA', 'PROVEN-NO-INFLATION-IN-SCOPE', 'PROVEN-INFLATION', 'SPECULATION', 'pending'):
        F.add(f'v_grade:{g}', AR, gr.get(g, 0), f'count(verdicts audit_grade {g})')
    for h in ar.get('history', []):
        F.add(f"hist_{h['run']}_overturned", AR, h['counts'].get('overturned', 0), f"history[{h['run']}].counts.overturned")
        F.add(f"hist_{h['run']}_holds", AR, h['counts'].get('holds', 0), f"history[{h['run']}].counts.holds")
        F.add(f"hist_{h['run']}_ids", AR, ', '.join(h.get('overturned') or []) or 'none', f"history[{h['run']}].overturned")
        F.add(f"hist_{h['run']}_unresolved", AR, ', '.join(h.get('unresolved') or []) or 'none', f"history[{h['run']}].unresolved")
        F.add(f"hist_{h['run']}_report", AR, _short(h.get('report_sha256')), f"history[{h['run']}].report_sha256[:16]")
    CH = 'audit/challenges.json'
    chj, _ = F.json(CH)
    for c in chj.get('challenges', []):
        F.add(f"ch:{c['id']}:claim", CH, c.get('claim', ''), f"challenges[{c['id']}].claim (verbatim)")
        F.add(f"ch:{c['id']}:result", CH, c.get('result', ''), f"challenges[{c['id']}].result")
        F.add(f"ch:{c['id']}:evidence", CH, '; '.join(f"{e['class']}: {e['what']}" for e in c.get('evidence', [])),
              f"challenges[{c['id']}].evidence (verbatim)")
        F.add(f"ch:{c['id']}:note", CH, c.get('note') or '', f"challenges[{c['id']}].note (verbatim)")
    # the G28 run record (bound to this manifest)
    rec, _ = F.json(RECORD, 'record')
    runs = rec.get('runs', []) if rec.get('manifest_sha256') == F.facts['manifest_sha256']['value'] else []
    F.add('replay_runs_bound', RECORD, len(runs), 'len(runs) bound to the current manifest', 'record')
    F.add('replay_runs_full_pass', RECORD, sum(1 for r in runs if r.get('result') == 'PASS' and r.get('mode') == 'full'),
          'count(runs PASS full)', 'record')
    F.add('replay_report', RECORD, (runs[-1]['report_sha256'][:16] if runs else 'pending'), 'runs[-1].report_sha256[:16]', 'record')
    F.add('replay_byte_exact', RECORD, bool(runs) and len({r['report_sha256'] for r in runs}) == 1 and len(runs) >= 2,
          'runs >= 2 with one report_sha256', 'record')
    F.add('replay_last', RECORD, (runs[-1]['when'].replace('T', ' ') if runs else 'pending'), 'runs[-1].when', 'record')
    rep = rec.get('report', {}) if runs else {}
    F.add('replay_equal', RECORD, rep.get('rederive', {}).get('equal', 'pending'), 'report.rederive.equal', 'record')
    F.add('replay_expected', RECORD, rep.get('rederive', {}).get('expected', 'pending'), 'report.rederive.expected', 'record')
    F.add('replay_bodies', RECORD, rep.get('store', {}).get('tx_bodies_present', 'pending'), 'report.store.tx_bodies_present', 'record')
    if 'replay_wall1_ok' in record_paths_for(F.ds.name):
        F.add('replay_wall1_ok', RECORD, rep.get('store', {}).get('wall1_blocks', {}).get('check_i_ok', 'pending'),
              'report.store.wall1_blocks.check_i_ok', 'record')
    # r30 (B218): a RECORD figure whose path a PASS report never writes is a label of nothing; flagged unless it is a
    # legacy figure a closed page still renders (rendered from r30 on as the audit's own wall-1 check, D2-04)
    F.unrecorded = unrecorded_paths(rep, record_paths_for(F.ds.name), LEGACY_UNRECORDED if vkey_name(F.ds.name) < (30, '') else {})
    F.problems += [f'record figure {k}: report path {p} is absent in a PASS report (B218)' for k, p in F.unrecorded]
    # the dataset ledger (all versions) and the disclosure track
    LG = 'forensics/ledger.json'
    lg, _ = F.json(LG, 'record')
    lv = lg.get('versions', [])
    F.add('ledger_versions', LG, len(lv), 'len(versions)', 'record')
    for v in lv:
        F.add(f"ledger:{v.get('version')}:sha", LG, _short(v.get('manifest_sha256')), f"versions[{v.get('version')}].manifest_sha256[:16]", 'record')
        F.add(f"ledger:{v.get('version')}:sealed", LG, v.get('sealed', 'pending'), f"versions[{v.get('version')}].sealed", 'record')
    dt, _ = F.json(DT, 'record')
    F.add('dt_claims', DT, len(dt.get('claims', [])), 'len(claims)', 'record')
    for rd in ('R24', 'R25', 'R26'):
        F.add(f'dt_facts_{rd.lower()}', DT, sum(1 for x in dt.get('facts', []) if x.get('round') == rd), f'count(facts round {rd})', 'record')
    for fx in dt.get('fixes', []):
        if fx.get('id') in ('FX-F5', 'FX-F6'):
            F.add(f"dt:{fx['id']}:kind", DT, fx.get('kind', 'pending'), f"fixes[{fx['id']}].kind", 'record')
            F.add(f"dt:{fx['id']}:title", DT, fx.get('title', 'pending'), f"fixes[{fx['id']}].title", 'record')
            F.add(f"dt:{fx['id']}:status", DT, fx.get('status', 'pending'), f"fixes[{fx['id']}].status", 'record')
    return F


def kpis(F):
    """Area `forensics` metrics (harness/areas.json), every one a fact."""
    f = F.facts
    if is_v2(F.m):   # r26: the same KPI names, read from the v2 facts (the window rows and table bodies are the pinned v1 files)
        return {'window_heights_raw': f['window_rows']['value'], 'window_heights_missing': f['missing_count']['value'],
                'tx_bodies_raw': f['bodies_raw']['value'], 'tx_records': f['txs_decoded']['value'],
                'replay_byte_exact': 1 if f['replay_byte_exact']['value'] is True else 0,
                'replay_full_runs': f['replay_runs_full_pass']['value'],
                'audit_holds': f['audit_holds']['value'], 'audit_fails': f['audit_overturned']['value'],
                'audit_unresolved': f['audit_unresolved']['value'], 'audit_overturned_all_runs': f['audit_overturned_all_runs']['value'],
                'grade_not_decidable': f['v_grade:NOT-DECIDABLE-FROM-PUBLIC-DATA']['value'],
                'grade_proven_in_scope': f['v_grade:PROVEN-NO-INFLATION-IN-SCOPE']['value'],
                'grade_proven_inflation': f['v_grade:PROVEN-INFLATION']['value'], 'grade_speculation': f['v_grade:SPECULATION']['value'],
                'grade_pending': f['v_grade:pending']['value'], 'grade_e1': f['cl_hist_e1']['value'], 'grade_e2': f['cl_hist_e2']['value'],
                'class_figures': f['cl_figures']['value'], 'dc1_obs': f['cl_dc1_obs']['value'], 'dc1_pending': f['cl_dc1_pending']['value']}
    return {'window_heights_raw': f['window_rows']['value'], 'window_heights_missing': f['missing_count']['value'],
            'tx_bodies_raw': f['bodies_raw']['value'], 'tx_records': f['tx_records']['value'],
            'replay_byte_exact': 1 if f['replay_byte_exact']['value'] is True else 0,
            'replay_full_runs': f['replay_runs_full_pass']['value'],
            'audit_holds': f['audit_holds']['value'], 'audit_fails': f['audit_overturned']['value'],
            'audit_unresolved': f['audit_unresolved']['value'], 'audit_overturned_all_runs': f['audit_overturned_all_runs']['value'],
            'grade_not_decidable': f['v_hf3_nd']['value'], 'grade_proven_in_scope': f['v_proven_scope']['value'],
            'grade_proven_inflation': f['v_proven_inflation']['value'], 'grade_speculation': f['v_speculation']['value'],
            'grade_pending': f['v_pending']['value'], 'grade_e1': f['grade_e1']['value'], 'grade_e2': f['grade_e2']['value']}


def newest_dataset(root=ROOT):
    led = json.loads((Path(root) / 'forensics' / 'ledger.json').read_text())
    return Path(root) / 'forensics' / led['versions'][-1]['version']


FROZEN = 'artifacts/src/frozen'


def page_inputs(root=ROOT, dyn_root=None):
    """r26 (rft §0.6 closed pages): (dataset dir, record root) a ledger page is built from. dyn_root = the page's input
    root (gen_ledger DYN_ROOT: artifacts/src/frozen/r<N>/ for a closed page, else the tree). A closed page names the
    newest dataset of ITS frozen forensics/ledger.json (the dataset itself is never rewritten, so it is read from the
    tree) and reads its record files (G28 run record, disclosure track, discovery note) from the frozen copy, so S7
    rewriting the live records no longer changes it."""
    root = Path(root)
    dyn = Path(dyn_root) if dyn_root else root
    if (dyn / 'forensics' / 'ledger.json').exists():
        led = json.loads((dyn / 'forensics' / 'ledger.json').read_text())
        e = led['versions'][-1]
        return dataset_at(root, e['version'], e.get('manifest_sha256')), dyn
    return newest_dataset(root), root


CACHE_MAX_AGE_S = 7 * 86400     # r29 (B167): an extraction nobody read for a week is removed


def prune_dataset_cache(base, now=None, max_age_s=CACHE_MAX_AGE_S):
    """r29 (B167 residual, V-3): remove the dataset_at extractions under `base` whose tree is gone (the root they
    were extracted for, recorded in ROOT.txt, no longer exists: a deleted clone) or that nobody read for max_age_s
    (mtime of ROOT.txt, touched on every read). An entry without ROOT.txt (pre-r29) counts as unread since its own
    mtime. Returns the removed entry names. Only direct children of `base` are touched."""
    import shutil, time
    base = Path(base)
    now = time.time() if now is None else now
    gone = []
    if not base.is_dir():
        return gone
    for e in sorted(base.iterdir()):
        if not e.is_dir() or e.is_symlink():
            continue
        mark = e / 'ROOT.txt'
        try:
            root = mark.read_text().strip() if mark.exists() else None
            age = now - (mark.stat().st_mtime if mark.exists() else e.stat().st_mtime)
        except OSError:
            continue
        if (root is not None and not Path(root).is_dir()) or age > max_age_s:
            shutil.rmtree(e, ignore_errors=True)
            gone.append(e.name)
    return gone


def dataset_at(root, version, manifest_sha):
    """R28: the dataset directory whose manifest.json hashes to manifest_sha. The tree's copy when it matches; else the
    version as it was committed with that manifest, extracted from the git object store into a per-user cache (a closed
    page froze an OPEN version that was later tagged and sealed, B126: the page keeps reading exactly the bytes it named).
    No match anywhere: the tree's copy, so the page check FAILS on the differing hashes instead of passing silently."""
    import subprocess, tarfile, io, tempfile
    root = Path(root)
    cur = root / 'forensics' / version
    rel = f'forensics/{version}/manifest.json'
    if not manifest_sha or not (cur / 'manifest.json').exists() or \
            hashlib.sha256((cur / 'manifest.json').read_bytes()).hexdigest() == manifest_sha:
        return cur
    log = subprocess.run(['git', '-C', str(root), 'log', '--all', '--format=%H', '--', rel], capture_output=True, text=True)
    for c in log.stdout.split():
        b = subprocess.run(['git', '-C', str(root), 'show', f'{c}:{rel}'], capture_output=True)
        if b.returncode or hashlib.sha256(b.stdout).hexdigest() != manifest_sha:
            continue
        tag = hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:12]   # one cache per tree: the base links point into it
        base = Path(tempfile.gettempdir()) / f'fx_dataset_at_{os.getuid()}'
        cache = base / f'{tag}_{manifest_sha[:32]}'
        prune_dataset_cache(base)                                  # r29 (B167): never this entry while its tree lives
        d = cache / 'forensics' / version
        if not (d / 'manifest.json').exists():
            arc = subprocess.run(['git', '-C', str(root), 'archive', '--format=tar', c, f'forensics/{version}'], capture_output=True)
            if arc.returncode:
                break
            cache.mkdir(parents=True, exist_ok=True)
            with tarfile.open(fileobj=io.BytesIO(arc.stdout)) as t:
                t.extractall(cache, filter='data')
        (cache / 'ROOT.txt').write_text(str(root.resolve()) + '\n')   # r29 (B167): who it is for; mtime = last read
        for sib in sorted((root / 'forensics').iterdir()):   # the sealed base versions it reads by repo-relative path
            if sib.is_dir() and sib.name != version and not (cache / 'forensics' / sib.name).exists():
                (cache / 'forensics' / sib.name).symlink_to(sib.resolve())
        if hashlib.sha256((d / 'manifest.json').read_bytes()).hexdigest() == manifest_sha:
            return d
        break
    return cur


def page_dyn_root(root, page):
    """the frozen input root of ledger page dero-r1-r<N>.html when artifacts/src/frozen/r<N>/ exists, else None"""
    m = re.search(r'r(\d+)\.html$', Path(page).name)
    d = Path(root) / FROZEN / f'r{m.group(1)}' if m else None
    return d if d is not None and d.is_dir() else None


def write_intel(F, out):
    doc = {'_doc': ('r25 area `forensics` KPIs (harness/forensics/facts.py --write): each value is a fact of the newest forensic '
                    'dataset, with the file and SHA-256 it was read from in `facts`; rewritten every S7'),
           'dataset': F.facts['dataset']['value'], 'manifest_sha256': F.facts['manifest_sha256']['value'],
           'kpis': kpis(F), 'facts': F.facts, 'problems': F.problems}
    Path(out).write_text(json.dumps(doc, indent=1, sort_keys=True) + '\n')
    return doc


# ----------------------------------------------------------------------------------------------- explorer data
def _b36(n):
    d = '0123456789abcdefghijklmnopqrstuvwxyz'
    return d[n] if 0 <= n < 36 else '?'


def _manifest(ds):
    try:
        return json.loads((Path(ds) / 'manifest.json').read_text())
    except (OSError, ValueError):
        return {}


def _v1_dir(ds):
    """r26: the sealed v1 dataset a v2 dataset builds on (its manifest `inputs` paths are repo-relative)"""
    return Path(ds).parent.parent / V1


def explorer_rows(ds):
    """the rows the window explorer shows: v1 = derived/window.jsonl.gz; r26 v2 = the pinned v1 window rows with the fee
    of every v1-pending row settled from v2 derived/blocks_fees.jsonl.gz (a row v2 does not settle stays pending)"""
    if not is_v2(_manifest(ds)):
        return window_rows(ds)
    rows = window_rows(_v1_dir(ds))
    bf = {r['height']: r for r in (json.loads(l) for l in gzip.open(Path(ds) / 'derived' / 'blocks_fees.jsonl.gz', 'rt') if l.strip())}
    out = []
    for r in rows:
        r = dict(r)
        if not isinstance(r['fees'], int) and isinstance(bf.get(r['height'], {}).get('fees'), int):
            r['fees'] = bf[r['height']]['fees']
        out.append(r)
    return out


def _hf3_rows(ds):
    d = _v1_dir(ds) if is_v2(_manifest(ds)) else Path(ds)
    return json.loads((d / 'derived' / 'hf3.json').read_text()).get('rows', [])


def _replay_roots(ds):
    """r26 v2: [first, last, count] of the window rows whose pre/post roots our node replay holds (roots_window.jsonl.gz)"""
    if not is_v2(_manifest(ds)):
        return None
    t = sorted(r['topo'] for r in (json.loads(l) for l in gzip.open(Path(ds) / 'derived' / 'roots_window.jsonl.gz', 'rt') if l.strip())
               if r.get('in_window'))
    return [t[0], t[-1], len(t)] if t else []


def explorer_data(ds):
    """The window explorer's embedded data (compact, columnar), in height order from `first`:
      ids   per height 32 B block id + 32 B blob SHA-256, B64X-encoded (the tips link of height h is the id of h-1:
            single-tip chain, audit A5; `tips_single_chain` records that this holds for every row);
      ts    timestamp_ms of the first row, then deltas;  mb  miniblocks per row, one base-36 char each;
      fee   {row index: fee} for fee > 0;  feep  row indexes whose fees are pending (bodies not in raw/);
      txs   {row index: [tx hash, ...]};  hf3  {row index: [HF3 TXID prefix (16 hex), ...]};
      tierA row indexes held in full (tier A);  roots  [first, last, count] of rows with a held post-state root;
      carriers  the 142 carrier heights (derived/hf3.json)."""
    rows = explorer_rows(ds)
    hfrows = _hf3_rows(ds)
    roots = [i for i, r in enumerate(rows) if not str(r.get('state_root_post', '')).startswith('not reconstructable')]
    v2 = is_v2(_manifest(ds))
    rr = _replay_roots(ds) if v2 else None
    first = rows[0]['height']
    extra = {'rroots': ([rr[0] - first, rr[1] - first, rr[2]] if rr else [])} if v2 else {}
    return {**extra, 'src': (f'{V1}/derived/window.jsonl.gz + derived/blocks_fees.jsonl.gz' if v2 else 'derived/window.jsonl.gz'),
            'first': rows[0]['height'], 'n': len(rows),
            'ids': b64x(b''.join(bytes.fromhex(r['blid']) + bytes.fromhex(r['sha256']) for r in rows)),
            'ts': [rows[0]['timestamp_ms']] + [rows[i]['timestamp_ms'] - rows[i - 1]['timestamp_ms'] for i in range(1, len(rows))],
            'mb': ''.join(_b36(r['miniblocks']) for r in rows),
            'fee': {str(i): r['fees'] for i, r in enumerate(rows) if isinstance(r['fees'], int) and r['fees'] > 0},
            'feep': [i for i, r in enumerate(rows) if not isinstance(r['fees'], int)],
            'txs': {str(i): r['tx_hashes'] for i, r in enumerate(rows) if r.get('tx_hashes')},
            'hf3': {str(i): [x[:16] for x in r.get('hf3_txids') or []] for i, r in enumerate(rows) if r.get('hf3_txids')},
            'tierA': [i for i, r in enumerate(rows) if r.get('tier') == 'A'],
            'roots': [roots[0], roots[-1], len(roots)] if roots else [],
            'carriers': sorted({h for r in hfrows for h in r.get('carriers', [])}),
            'tips_single_chain': all(r.get('tips') == [rows[i - 1]['blid']] for i, r in enumerate(rows) if i)}


def explorer_decode(d):
    """Rows rebuilt from the embedded data alone (what the page's script shows): G30 compares them with the dataset."""
    ids = unb64x(d['ids'])
    out, t = [], 0
    # r27 (B133): the two index sets once per call, not once per row (set(d['tierA']) rebuilt for each of the window's
    # rows was 11.9 s of the 63.5 s frontend2 KAT body, 13 calls, cProfile 2026-11-05); same rows, same order
    feep, tier_a = set(d['feep']), set(d['tierA'])
    for i in range(d['n']):
        t = d['ts'][0] if i == 0 else t + d['ts'][i]
        out.append({'height': d['first'] + i, 'blid': ids[64 * i:64 * i + 32].hex(), 'sha256': ids[64 * i + 32:64 * i + 64].hex(),
                    'timestamp_ms': t, 'miniblocks': int(d['mb'][i], 36),
                    'fees': 'pending' if i in feep else d['fee'].get(str(i), 0),
                    'tx_hashes': d['txs'].get(str(i), []), 'hf3': d['hf3'].get(str(i), []),
                    'tier': 'A' if i in tier_a else 'B',
                    'tips': [ids[64 * (i - 1):64 * (i - 1) + 32].hex()] if i else None})
    return out


def check_explorer(d, ds):
    """[problems]: every row the embedded explorer data decodes to must equal derived/window.jsonl.gz (and hf3.json)."""
    p = []
    try:
        got = explorer_decode(d)
    except Exception as e:                                           # noqa: BLE001
        return [f'explorer data does not decode: {type(e).__name__}: {e}']
    rows = explorer_rows(ds)
    if len(got) != len(rows):
        return [f'explorer data has {len(got)} rows, {d.get("src")} has {len(rows)}']
    feep, tier_a = set(d.get('feep', [])), set(d.get('tierA', []))
    bad = 0
    for i, (g, r) in enumerate(zip(got, rows)):
        want = {'height': r['height'], 'blid': r['blid'], 'sha256': r['sha256'], 'timestamp_ms': r['timestamp_ms'],
                'miniblocks': r['miniblocks'], 'fees': r['fees'] if isinstance(r['fees'], int) else 'pending',
                'tx_hashes': r.get('tx_hashes') or [], 'hf3': [x[:16] for x in r.get('hf3_txids') or []],
                'tier': r.get('tier'), 'tips': r.get('tips') if i else None}
        if {k: g[k] for k in want} != want:
            bad += 1
            if bad <= 3:
                k = next(k for k in want if g[k] != want[k])
                p.append(f'explorer row {r["height"]}: {k} {str(g[k])[:20]} != dataset {str(want[k])[:20]}')
    if bad > 3:
        p.append(f'explorer: {bad} rows differ in total')
    want = explorer_data(ds)
    for k in ('roots', 'carriers', 'tips_single_chain', 'first', 'n', 'src') + (('rroots',) if 'rroots' in want else ()):
        if d.get(k) != want[k]:
            p.append(f'explorer field {k} differs from the dataset')
    return p


# ----------------------------------------------------------------------------------------------- G30
SPAN = re.compile(r'<span class="fxn" data-fx="([^"]+)" data-src="([^"]*)" data-sha="([0-9a-f]*|missing|unlisted)">(.*?)</span>', re.S)
FXID = re.compile(r'<span class="fxid">.*?</span>', re.S)
# r26: a class figure of derived/classes.json (bounds.py SPAN; checked by bounds.check_page, which g30() also runs)
FCL = re.compile(r'<span class="fcl" data-fc="[^"]*" data-cls="[^"]*" data-bound="[^"]*" data-cov="[^"]*" data-scope="[^"]*">.*?</span>', re.S)
BEGIN, END = '<!--forensics:begin-->', '<!--forensics:end-->'
SA_BEGIN, SA_END = '<!--fxline:begin-->', '<!--fxline:end-->'
KN_BEGIN, KN_END = '<!--known:begin-->', '<!--known:end-->'   # r26: the soundness page's generated section
# identifiers a reader sees as names, not figures (round, gate, challenge, backlog and section ids; file:line citations;
# the evidence-grade names; hash algorithm names); everything else with a digit must be a fact span
IDENT = re.compile(r'(?:\bR\d+[a-z]?\b|\bG\d+\b|\bA\d+[a-z]?\b|\bB\d+\b|\bMF\d+\b|\bE[12]\b|\bC\d\b|§[\d.]+|'
                   r'\b[\w./-]+\.(?:sha256|jsonl|json|html|txt|go|py|gz|md|sh)\b(?::\d+(?:[-,]\d+)*)?|SHA3?-256|Keccak-256|'
                   r'\bv\d\b|\bsrc-\d\b|\baudit-\d\b|\b[0-9a-f]{12,64}\b|\bHF3\b|\b(?:i|ii|iii)\b|base64|ElGamal|1st|2nd|'
                   # r26: defect classes, research questions, track rows, audit-2 ids, upstream tags (names, not figures)
                   r'\bDC\d\b(?:-\w+)?|\bFQ\d\b|\bQ-CS\d\b|\bFX-[NF]\d+\b|\bNF\d+-\d+\b|\bS-R22\b|\bP1\b|\bD2-\d+\b|'
                   r'\bV2?-[A-Z][A-Z0-9-]*\b|\bRelease\d+\b)')


def _fxid_text(m):
    s = html.unescape(re.sub(r'<[^>]+>', '', m.group(0)[len('<span class="fxid">'):-len('</span>')])).strip()
    return ' ' if re.fullmatch(r'\S+', s) and re.search(r'[A-Za-z\u00a7]', s) else ' ' + s + ' '


def _visible(seg):
    seg = re.sub(r'<script\b.*?</script>', ' ', seg, flags=re.S)
    seg = re.sub(r'<style\b.*?</style>', ' ', seg, flags=re.S)
    seg = re.sub(r'<svg\b.*?</svg>', ' ', seg, flags=re.S)   # charts: their numbers are data-fx spans in the caption
    # r26 verify: an identifier span is a name only when its text is ONE token holding a letter (v2, a2, D2-19, a file
    # path); any other text (a bare number, or a name followed by a number) stays visible, so its digits are untraced
    seg = FXID.sub(_fxid_text, seg)
    seg = SPAN.sub(' ', seg)
    seg = FCL.sub(' ', seg)
    seg = re.sub(r'<[^>]+>', ' ', seg)
    return html.unescape(seg)


def check_page(text, F, begin=BEGIN, end=END, need_explorer=True):
    p = []
    if begin not in text or end not in text:
        return [f'no {begin} … {end} block'], 0
    seg = text[text.index(begin):text.index(end)]
    n = 0
    for fid, src, h, shown in SPAN.findall(seg):
        n += 1
        f = F.facts.get(fid)
        if not f:
            p.append(f'span {fid}: no such fact')
            continue
        if src != f['file'] or h != f['sha256']:
            p.append(f'span {fid}: names {src} {h[:12]} but the fact is {f["file"]} {f["sha256"][:12]}')
        if html.unescape(shown) != fmt(f['value']):
            p.append(f'span {fid}: shows {html.unescape(shown)!r}, the dataset says {fmt(f["value"])!r}')
    left = IDENT.sub(' ', _visible(seg))
    for mm in re.finditer(r'\d[\d,.]*', left):
        ctx = left[max(0, mm.start() - 40):mm.end() + 20].replace('\n', ' ')
        p.append(f'untraced number {mm.group(0)!r} in: …{ctx.strip()}…')
        if len(p) > 40:
            break
    if need_explorer:
        mm = re.search(r'<script type="application/json" id="fx-data">(.*?)</script>', seg, re.S)
        if not mm:
            p.append('no embedded explorer data (#fx-data)')
        else:
            p += check_explorer(json.loads(mm.group(1)), F.ds)
    return p, n


def section_lint(text, root=ROOT, private_dir=None):
    """MF8/MF9 over the rendered sections: the G24 exploit patterns and the privacy regexes of the independent audit tool
    (audit_check.py), plus the private source terms when the private endpoint dir exists. [problems]."""
    import importlib.util as _iu
    sp = _iu.spec_from_file_location(f'audit_for_facts_{id(text)}', Path(root) / 'harness/forensics/audit_check.py')
    A = _iu.module_from_spec(sp)
    sp.loader.exec_module(A)
    vis = _visible(text) + ' ' + ' '.join(html.unescape(m.group(4)) for m in SPAN.finditer(text))
    p = []
    for n, rx in A.exploit_patterns(Path(root)):
        if rx.search(vis):
            p.append(f'exploit-pattern text in the sections: {n}')
    for n, rx in A.PRIV_RX:
        if rx.search(vis):
            p.append(f'private text in the sections: {n}')
    pd = Path(private_dir) if private_dir else Path.home() / 'derohe-persist' / 'forensics_private'
    for term in A.load_private_terms(pd):
        if term and term in text:
            p.append('a private source term in the sections')
            break
    return p


def g30(root=ROOT, page=None, srcarch=None, sound=None):
    root = Path(root)
    try:
        ds = newest_dataset(root)
    except (OSError, ValueError, KeyError, IndexError):
        return False, 'no forensic dataset in forensics/ledger.json'
    F = build(ds, root)
    fails = [f'dataset: {x}' for x in F.problems]
    if page is None:
        pages = sorted((root / 'artifacts').glob('dero-r1-r*.html'), key=lambda q: int(re.search(r'r(\d+)\.html$', q.name).group(1)))
        pages = [q for q in pages if int(re.search(r'r(\d+)\.html$', q.name).group(1)) >= 25]
        page = pages[-1] if pages else None
    if page is None or not Path(page).exists():
        return False, 'no ledger page dero-r1-r<N>.html with N >= 25'
    ptxt = Path(page).read_text()
    # r26: a closed page (its round has frozen inputs) is checked against the facts it was built from, not the live records
    dyn = page_dyn_root(root, page)
    FP = F
    if dyn is not None:
        pds, prec = page_inputs(root, dyn)
        FP = build(pds, root, prec)
        fails += [f'{Path(page).name} (frozen inputs): {x}' for x in FP.problems]
    pf, n = check_page(ptxt, FP)
    fails += [f'{Path(page).name}: {x}' for x in pf]
    if BEGIN in ptxt and END in ptxt:
        fails += [f'{Path(page).name}: {x}' for x in section_lint(ptxt[ptxt.index(BEGIN):ptxt.index(END)], root)]
    sa = Path(srcarch) if srcarch else root / 'artifacts' / 'dero-src-arch.html'
    sf, n2 = check_page(sa.read_text(), F, SA_BEGIN, SA_END, need_explorer=False) if sa.exists() else (['missing'], 0)
    fails += [f'{sa.name}: {x}' for x in sf]
    extra = ''
    if is_v2(F.m):
        # r26: the soundness page's generated section, and every class figure (fcl span) on the three pages
        n3, ncl, sp = 0, 0, (Path(sound) if sound else soundness_page(root))
        # r26 verify: on a v2 dataset the generated sections are REQUIRED (a removed section is a failure, not a skip)
        if sp is not None and sp.exists():
            st = sp.read_text()
            if KN_BEGIN in st and KN_END in st:
                kf, n3 = check_page(st, F, KN_BEGIN, KN_END, need_explorer=False)
                fails += [f'{sp.name}: {x}' for x in kf]
                fails += [f'{sp.name}: {x}' for x in section_lint(st[st.index(KN_BEGIN):st.index(KN_END)], root)]
            else:
                fails.append(f'{sp.name}: no {KN_BEGIN} … {KN_END} section (required on a v2 dataset)')
        else:
            fails.append('the soundness page of the round is missing (its generated section is required on a v2 dataset)')
        BD = _bounds(root)
        cl = json.loads((F.ds / 'derived' / 'classes.json').read_text()) if (F.ds / 'derived' / 'classes.json').exists() else None
        if cl is None:
            fails.append('derived/classes.json missing (the class blocks cannot be checked)')
        # R28: a closed ledger page is checked against the class file of the dataset it was built from (FP.ds, possibly
        # an earlier version as committed, dataset_at), the live pages against the newest dataset's
        clp = (json.loads((FP.ds / 'derived' / 'classes.json').read_text())
               if FP is not F and (FP.ds / 'derived' / 'classes.json').exists() else cl)
        for pg in (Path(page), sa, sp):
            if pg is None or not pg.exists() or cl is None:
                continue
            t = pg.read_text()
            bp, k = BD.check_page(t, clp if pg == Path(page) else cl, need=True, root=root)
            ncl += k
            fails += [f'{pg.name} (class block): {x}' for x in bp]
        extra = (f' and {n3} on {sp.name if sp else "the soundness page"} (plus {ncl} class figures checked against '
                 f'derived/classes.json)')
    if fails:
        return False, f'{len(fails)} failure(s): ' + '; '.join(fails[:4])
    return True, (f'{ds.name} manifest {F.facts["manifest_sha256"]["value"][:12]}: {n} figures on {Path(page).name} and {n2} on '
                  f'{sa.name}{extra} trace to their dataset file + SHA-256; 0 untraced numbers; explorer data = '
                  f'{explorer_data_src(F.ds)}')


def explorer_data_src(ds):
    return f'{V1}/derived/window.jsonl.gz + derived/blocks_fees.jsonl.gz' if is_v2(_manifest(ds)) else 'derived/window.jsonl.gz'


def _bounds(root):
    import importlib.util as _iu
    sp = _iu.spec_from_file_location(f'bounds_for_facts_{len(sys.modules)}', Path(root) / 'harness/forensics/bounds.py')
    m = _iu.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


def soundness_page(root):
    """the current round's soundness page (harness/kit/soundpage.py), or None"""
    import importlib.util as _iu
    try:
        sp = _iu.spec_from_file_location(f'soundpage_for_facts_{len(sys.modules)}', Path(root) / 'harness/kit/soundpage.py')
        m = _iu.module_from_spec(sp)
        sp.loader.exec_module(m)
        return Path(root) / m.rel(root)
    except Exception:                                                # noqa: BLE001
        return None


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--dataset'); ap.add_argument('--write'); ap.add_argument('--g30', action='store_true')
    ap.add_argument('--page'); ap.add_argument('--srcarch')
    a = ap.parse_args(argv)
    if a.g30:
        ok, det = g30(ROOT, a.page, a.srcarch)
        print(('PASS' if ok else 'FAIL') + '  G30 forensics frontend traces to the dataset: ' + det)
        return 0 if ok else 9
    F = build(Path(a.dataset) if a.dataset else newest_dataset())
    if a.write:
        doc = write_intel(F, a.write)
        print(json.dumps(doc['kpis'], sort_keys=True))
    else:
        print(json.dumps({k: v['value'] for k, v in F.facts.items()}, indent=1, sort_keys=True))
    if F.problems:
        print('problems:', F.problems, file=sys.stderr)
        return 9
    return 0


if __name__ == '__main__':
    sys.exit(main())
