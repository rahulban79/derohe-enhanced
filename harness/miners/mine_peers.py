#!/usr/bin/env python3
"""mine_peers.py (r24) — the network-peer observatory of harness/intel/peer_intel.py, as page rows (section 'peers').

Every row anchors on a line of the pseudonymised capture (harness/runtime/peer_capture_<ts>.jsonl), of the log extract
(peer_logx_<ts>.jsonl) or, for a detector or a proposal, on the code line its rule lives on (SRC). A value the miner
cannot anchor never becomes a row: it goes to 'unverified'. No row carries an IP address or a peer tag: peer_intel
never writes one, and gate G27 re-scans these rows and the rendered section.
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import minelib as M

SRC = 'harness/runtime/peer_intel.json'


def cap_anchor(rel, line, prefix):
    """the capture/logx line `line` of file `rel`, when it starts with `prefix` (the line is re-read, never trusted)."""
    raw, _ = M.lines(rel)
    if raw is None or not isinstance(line, int) or not 0 < line <= len(raw):
        return None
    if not raw[line - 1].startswith(prefix):
        return None
    q = raw[line - 1][:160]
    a = M.anchor(rel, q, hint=line)
    return a if a and a['line'] == line else None


def code_anchor(rule):
    if not rule or not rule.get('line'):
        return None
    a = M.anchor(rule['file'], rule['quote'], hint=rule['line'])
    return a if a and a['line'] == rule['line'] else None


def main():
    p = M.ROOT / SRC
    if not p.exists():
        M.emit('peercards', [], [{'title': 'peer observatory', 'why': f'{SRC} not written yet: run harness/intel/peer_intel.py --live'}], 'mine_peers.py')
        return
    try:
        rep = json.loads(p.read_text())
    except ValueError as e:
        M.emit('peercards', [], [{'title': 'peer observatory', 'why': f'{SRC} unreadable: {e}'}], 'mine_peers.py')
        return
    capf = f"harness/runtime/{rep.get('capture_file')}"
    logxf = f"harness/runtime/{rep.get('logx_file')}"
    rows, unv = [], []
    base = {'section': 'peers', 'class': 'HARNESS', 'captured': rep.get('captured'), 'node_version': rep.get('node_version'),
            'capture_file': rep.get('capture_file')}

    def cap(line, src):
        return cap_anchor(capf, line, '{"src": "%s"' % src)

    # KPI row
    k = rep.get('kpis') or {}
    ev = [a for a in (cap(rep.get('kpi_line'), 'kpis'), cap(rep.get('sync_line'), 'GetSyncInfo'), cap(rep.get('header_line'), 'capture')) if a]
    if ev:
        rows.append({**base, 'id': 'peers-kpis', 'kind': 'kpi', 'title': 'Peer set at capture', 'kpis': k,
                     'thresholds': rep.get('thresholds'), 'log': rep.get('log'),
                     'claim': (f"{k.get('peers_active')} active peers ({k.get('outgoing')} out / {k.get('incoming')} in), lag max "
                               f"{k.get('lag_max')}, latency median {k.get('latency_median_ms')} ms, {k.get('netgroups')} distinct /16s, "
                               f"first-relay top share {k.get('first_relay_top_share')}, chain {k.get('chain_fingerprint')}."),
                     'evidence': ev})
    else:
        unv.append({'title': 'peer KPIs', 'why': 'the kpis line is not in the capture'})
    # peers
    for pr in rep.get('peers') or []:
        a = cap(pr.get('line'), 'GetPeerInfo')
        if not a or f'"peer": "{pr["peer"]}"' not in a['quote']:
            unv.append({'title': pr.get('peer'), 'why': 'capture line does not carry this peer'})
            continue
        rows.append({**base, 'id': 'peers-' + pr['peer'], 'kind': 'peer', 'title': pr['peer'], 'peer': pr,
                     'claim': f"{pr['peer']}: lag {pr.get('lag')}, {pr.get('latency_ms')} ms, clock {pr.get('clock_offset_ms')} ms, "
                              f"{pr.get('version_class')}, first relays {pr.get('first_relays')}.", 'evidence': [a]})
    # detectors
    for d in rep.get('detectors') or []:
        ev = []
        ca = code_anchor(d.get('rule'))
        if ca:
            ev.append(ca)
        fs = []
        for f in d.get('findings') or []:
            fa = []
            if f.get('cap_line'):
                a = cap_anchor(capf, f['cap_line'], '{"src": ')
                node_wide = f['peer'].startswith('(') or a and a['quote'].startswith(('{"src": "diversity"', '{"src": "metrics"', '{"src": "GetSyncInfo"'))
                if a and (node_wide or f'"peer": "{f["peer"]}"' in a['quote']):   # a per-peer line must name this very peer
                    fa.append(a)
            for ln in (f.get('logx_lines') or [])[:3]:
                a = cap_anchor(logxf, ln, '{"file": ')
                if a and f'"peer": "{f["peer"]}"' in a['quote']:     # the extract line must name this very peer
                    fa.append(a)
            if not fa:
                unv.append({'title': f"{d['id']} {f.get('peer')}", 'why': 'finding without an anchored observation line'})
                continue
            fs.append({**{k2: f[k2] for k2 in ('peer', 'grade', 'what')}, 'cites': [f"{x['file']}:{x['line']}" for x in fa]})
            for x in fa:
                if len(ev) < 8 and x not in ev:
                    ev.append(x)
        if d.get('grade') != 'pending' and not ca:
            unv.append({'title': d['id'], 'why': 'detector rule line not anchored'})
            continue
        if not ev:
            unv.append({'title': d['id'], 'why': 'detector without any anchor'})
            continue
        observed_on = any(e['file'].startswith('harness/runtime/') for e in ev)
        rows.append({**base, 'class': 'HARNESS' if observed_on else 'SRC',    # a detector with no observation proves only its rule
                     'id': f"peers-{d['id']}", 'kind': 'detector', 'title': d['title'], 'det': d['id'], 'grade': d['grade'],
                     'test': d.get('test'), 'rule': f"{d['rule']['file']}:{d['rule'].get('line')}" if d.get('rule') else None,
                     'findings': fs, 'diversity': d.get('diversity'), 'why': d.get('why'),
                     'claim': f"{d['id']} {d['title']}: {d['grade']} ({len(fs)} finding(s)).", 'evidence': ev})
    # r25 (pipeline run 5, G16): CO24-N4 moved the ban body into Ban_Address_Reason; Ban_Address stays as the pre-r25
    # entry point (the startup self-test ban, the inbound-guard tests) and books its bans 'unattributed'. Said here so
    # the page keeps covering it (riskmap ratchet: 'lost p2p/bans.go::Ban_Address')
    la = M.anchor('p2p/bans.go', 'return Ban_Address_Reason(address, ban_seconds, BAN_SOURCE_UNATTRIBUTED, "")')
    if la:
        rows.append({**base, 'class': 'SRC', 'id': 'peers-ban-legacy-entry', 'kind': 'code', 'title': 'Ban_Address: the pre-r25 ban entry point',
                     'claim': 'Ban_Address keeps its signature and places the ban exactly as before through Ban_Address_Reason, '
                              'with source "unattributed" and no reason (CO24-N4); the console ban command and the score bans '
                              'name their source.', 'evidence': [la]})
    else:
        unv.append({'title': 'Ban_Address legacy entry', 'why': 'the delegation line is not in p2p/bans.go'})
    # census: bans, v2 offences, first relays, log kinds, builders
    c = rep.get('census') or {}
    for b in c.get('bans') or []:
        a = cap(b.get('line'), 'ban_list.json')
        if a:
            rows.append({**base, 'id': f"peers-ban-{b['entry']}", 'kind': 'ban', 'title': b['entry'], 'ban': b,
                         'claim': f"ban {b['entry']} ({b['scope']}), {b.get('remaining_s')} s left, v2 offender {b.get('v2_offender')}.", 'evidence': [a]})
    for v in c.get('v2_offences') or []:
        a = cap(v.get('line'), 'v2_offences.json')
        if a:
            rows.append({**base, 'id': f"peers-v2-{v['peer']}", 'kind': 'v2', 'title': v['peer'], 'v2': v,
                         'claim': f"{v['peer']} dropped {v.get('n')}x for the v2 remnant chain.", 'evidence': [a]})
    for f in c.get('first_relay') or []:
        a = cap(f.get('line'), 'first_relay.json')
        if a:
            rows.append({**base, 'id': f"peers-fr-{f['peer']}", 'kind': 'first_relay', 'title': f['peer'], 'fr': f,
                         'claim': f"{f['peer']} delivered {f.get('firsts')} blocks first (mean {f.get('delay_mean_ms')} ms after their builder).", 'evidence': [a]})
    a = cap(c.get('log_kinds_line'), 'log_kinds')
    if a:
        rows.append({**base, 'id': 'peers-logkinds', 'kind': 'log_kinds', 'title': 'P2P log events by kind', 'kinds': c.get('log_kinds'),
                     'claim': f"{len(c.get('log_kinds') or {})} P2P event kinds over {rep.get('log', {}).get('runs')} daemon runs in the log.", 'evidence': [a]})
    a = cap(rep.get('builders_line'), 'first_relay.json')
    if a:
        rows.append({**base, 'id': 'peers-builders', 'kind': 'builders', 'title': 'Block builders seen through first relays',
                     'builders': rep.get('builders'),
                     'claim': f"{len(rep.get('builders') or {})} distinct block builders (pseudonymous) reached us first through a peer.", 'evidence': [a]})
    # handshake failure kinds and call timeouts come from metric lines of the capture
    raw, _ = M.lines(capf)
    for i, l in enumerate(raw or [], 1):
        if l.startswith('{"src": "metrics", "name": "p2p_handshake_failures_by_kind_total"') or \
           l.startswith('{"src": "metrics", "name": "p2p_call_timeouts_total"') or \
           l.startswith('{"src": "metrics", "name": "p2p_stuck_peer_') or \
           l.startswith('{"src": "metrics", "name": "p2p_grey_quarantined_total"') or \
           l.startswith('{"src": "metrics", "name": "p2p_gossip_quarantine_refusals_total"') or \
           l.startswith('{"src": "metrics", "name": "p2p_handshake_failures_total"') or \
           l.startswith('{"src": "metrics", "name": "p2p_bans_total"') or \
           l.startswith('{"src": "metrics", "name": "p2p_penalty_'):
            try:
                o = json.loads(l)
            except ValueError:
                continue
            a = cap_anchor(capf, i, '{"src": "metrics"')
            if a:
                lab = ','.join(f'{k2}={v2}' for k2, v2 in sorted((o.get('labels') or {}).items()))
                rows.append({**base, 'id': f"peers-m-{o['name']}{'-' + lab if lab else ''}", 'kind': 'metric', 'title': o['name'],
                             'labels': lab, 'value': o['value'], 'claim': f"{o['name']}{'{' + lab + '}' if lab else ''} = {o['value']:g}.", 'evidence': [a]})
    # series
    sraw, _ = M.lines('harness/runtime/peer_series.jsonl')
    pts = []
    for i, l in enumerate(sraw or [], 1):
        try:
            o = json.loads(l)
        except ValueError:
            continue
        a = M.anchor('harness/runtime/peer_series.jsonl', l[:120], hint=i)
        if a and a['line'] == i:
            pts.append({k2: o.get(k2) for k2 in ('captured', 'peers', 'lag_max', 'latency_median_ms', 'first_relay_top_share',
                                                 'netgroups', 'observed', 'anomaly', 'v2_seen_7d', 'handshake_failures')} | {'line': i})
    if pts:
        rows.append({**base, 'id': 'peers-series', 'kind': 'series', 'title': 'Rolling series', 'points': pts[-48:],
                     'claim': f"{len(pts)} captures in the rolling series.",
                     'evidence': [M.anchor('harness/runtime/peer_series.jsonl', sraw[pts[-1]['line'] - 1][:120], hint=pts[-1]['line'])]})
    # proposals for the node (R25): anchored on the code line that shows the gap
    for pp in rep.get('proposals') or []:
        a = M.anchor(pp['anchor']['file'], pp['anchor']['quote'], hint=pp['anchor'].get('line')) if pp['anchor'].get('line') else None
        if not a:
            unv.append({'title': pp['id'], 'why': 'proposal anchor not in this tree'})
            continue
        rows.append({**base, 'class': 'SRC', 'id': f"peers-{pp['id']}", 'kind': 'proposal', 'title': pp['title'], 'pid': pp['id'],
                     'gap': pp['gap'], 'proposal': pp['proposal'], 'target': pp.get('target'), 'status': pp.get('status'),
                     'claim': f"{pp['id']}: {pp['title']}.", 'evidence': [a]})
    M.emit('peercards', rows, unv, 'mine_peers.py')


if __name__ == '__main__':
    main()
