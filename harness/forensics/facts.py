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
"""
import argparse, base64, gzip, hashlib, html, json, re, sys
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
    def __init__(self, ds, root=ROOT):
        self.ds, self.root = Path(ds), Path(root)
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
            p = self.root / rel
            b = p.read_bytes() if p.exists() else b''
            h = sha(b) if b else 'missing'
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


def window_rows(ds):
    return [json.loads(l) for l in gzip.open(Path(ds) / 'derived' / 'window.jsonl.gz', 'rt') if l.strip()]


def build(ds, root=ROOT):
    """Facts(ds) with every figure of the forensics sections, plus the per-TXID and per-row tables."""
    F = Facts(ds, root)
    m = F.m
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


def kpis(F):
    """Area `forensics` metrics (harness/areas.json), every one a fact."""
    f = F.facts
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


def explorer_data(ds):
    """The window explorer's embedded data (compact, columnar), in height order from `first`:
      ids   per height 32 B block id + 32 B blob SHA-256, B64X-encoded (the tips link of height h is the id of h-1:
            single-tip chain, audit A5; `tips_single_chain` records that this holds for every row);
      ts    timestamp_ms of the first row, then deltas;  mb  miniblocks per row, one base-36 char each;
      fee   {row index: fee} for fee > 0;  feep  row indexes whose fees are pending (bodies not in raw/);
      txs   {row index: [tx hash, ...]};  hf3  {row index: [HF3 TXID prefix (16 hex), ...]};
      tierA row indexes held in full (tier A);  roots  [first, last, count] of rows with a held post-state root;
      carriers  the 142 carrier heights (derived/hf3.json)."""
    rows = window_rows(ds)
    hf = json.loads((Path(ds) / 'derived' / 'hf3.json').read_text())
    roots = [i for i, r in enumerate(rows) if not str(r.get('state_root_post', '')).startswith('not reconstructable')]
    return {'src': 'derived/window.jsonl.gz', 'first': rows[0]['height'], 'n': len(rows),
            'ids': b64x(b''.join(bytes.fromhex(r['blid']) + bytes.fromhex(r['sha256']) for r in rows)),
            'ts': [rows[0]['timestamp_ms']] + [rows[i]['timestamp_ms'] - rows[i - 1]['timestamp_ms'] for i in range(1, len(rows))],
            'mb': ''.join(_b36(r['miniblocks']) for r in rows),
            'fee': {str(i): r['fees'] for i, r in enumerate(rows) if isinstance(r['fees'], int) and r['fees'] > 0},
            'feep': [i for i, r in enumerate(rows) if not isinstance(r['fees'], int)],
            'txs': {str(i): r['tx_hashes'] for i, r in enumerate(rows) if r.get('tx_hashes')},
            'hf3': {str(i): [x[:16] for x in r.get('hf3_txids') or []] for i, r in enumerate(rows) if r.get('hf3_txids')},
            'tierA': [i for i, r in enumerate(rows) if r.get('tier') == 'A'],
            'roots': [roots[0], roots[-1], len(roots)] if roots else [],
            'carriers': sorted({h for r in hf.get('rows', []) for h in r.get('carriers', [])}),
            'tips_single_chain': all(r.get('tips') == [rows[i - 1]['blid']] for i, r in enumerate(rows) if i)}


def explorer_decode(d):
    """Rows rebuilt from the embedded data alone (what the page's script shows): G30 compares them with the dataset."""
    ids = unb64x(d['ids'])
    out, t = [], 0
    for i in range(d['n']):
        t = d['ts'][0] if i == 0 else t + d['ts'][i]
        out.append({'height': d['first'] + i, 'blid': ids[64 * i:64 * i + 32].hex(), 'sha256': ids[64 * i + 32:64 * i + 64].hex(),
                    'timestamp_ms': t, 'miniblocks': int(d['mb'][i], 36),
                    'fees': 'pending' if i in set(d['feep']) else d['fee'].get(str(i), 0),
                    'tx_hashes': d['txs'].get(str(i), []), 'hf3': d['hf3'].get(str(i), []),
                    'tier': 'A' if i in set(d['tierA']) else 'B',
                    'tips': [ids[64 * (i - 1):64 * (i - 1) + 32].hex()] if i else None})
    return out


def check_explorer(d, ds):
    """[problems]: every row the embedded explorer data decodes to must equal derived/window.jsonl.gz (and hf3.json)."""
    p = []
    try:
        got = explorer_decode(d)
    except Exception as e:                                           # noqa: BLE001
        return [f'explorer data does not decode: {type(e).__name__}: {e}']
    rows = window_rows(ds)
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
    for k in ('roots', 'carriers', 'tips_single_chain', 'first', 'n', 'src'):
        if d.get(k) != want[k]:
            p.append(f'explorer field {k} differs from the dataset')
    return p


# ----------------------------------------------------------------------------------------------- G30
SPAN = re.compile(r'<span class="fxn" data-fx="([^"]+)" data-src="([^"]*)" data-sha="([0-9a-f]*|missing|unlisted)">(.*?)</span>', re.S)
FXID = re.compile(r'<span class="fxid">.*?</span>', re.S)
BEGIN, END = '<!--forensics:begin-->', '<!--forensics:end-->'
SA_BEGIN, SA_END = '<!--fxline:begin-->', '<!--fxline:end-->'
# identifiers a reader sees as names, not figures (round, gate, challenge, backlog and section ids; file:line citations;
# the evidence-grade names; hash algorithm names); everything else with a digit must be a fact span
IDENT = re.compile(r'(?:\bR\d+[a-z]?\b|\bG\d+\b|\bA\d+[a-z]?\b|\bB\d+\b|\bMF\d+\b|\bE[12]\b|\bC\d\b|§[\d.]+|'
                   r'\b[\w./-]+\.(?:sha256|jsonl|json|html|txt|go|py|gz|md|sh)\b(?::\d+(?:[-,]\d+)*)?|SHA3?-256|Keccak-256|'
                   r'\bv\d\b|\bsrc-\d\b|\baudit-\d\b|\b[0-9a-f]{12,64}\b|\bHF3\b|\b(?:i|ii|iii)\b|base64|ElGamal|1st|2nd)')


def _visible(seg):
    seg = re.sub(r'<script\b.*?</script>', ' ', seg, flags=re.S)
    seg = re.sub(r'<style\b.*?</style>', ' ', seg, flags=re.S)
    seg = re.sub(r'<svg\b.*?</svg>', ' ', seg, flags=re.S)   # charts: their numbers are data-fx spans in the caption
    seg = FXID.sub(' ', seg)
    seg = SPAN.sub(' ', seg)
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


def g30(root=ROOT, page=None, srcarch=None):
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
    pf, n = check_page(ptxt, F)
    fails += [f'{Path(page).name}: {x}' for x in pf]
    if BEGIN in ptxt and END in ptxt:
        fails += [f'{Path(page).name}: {x}' for x in section_lint(ptxt[ptxt.index(BEGIN):ptxt.index(END)], root)]
    sa = Path(srcarch) if srcarch else root / 'artifacts' / 'dero-src-arch.html'
    sf, n2 = check_page(sa.read_text(), F, SA_BEGIN, SA_END, need_explorer=False) if sa.exists() else (['missing'], 0)
    fails += [f'{sa.name}: {x}' for x in sf]
    if fails:
        return False, f'{len(fails)} failure(s): ' + '; '.join(fails[:4])
    return True, (f'{ds.name} manifest {F.facts["manifest_sha256"]["value"][:12]}: {n} figures on {Path(page).name} and {n2} on '
                  f'{sa.name} trace to their dataset file + SHA-256; 0 untraced numbers; explorer data = derived/window.jsonl.gz')


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
