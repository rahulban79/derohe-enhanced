"""peerkit (r24): the 'Consensus observatory — network peers' block of dero-src-arch.html, from rows of section 'peers'
(harness/miners/mine_peers.py <- harness/intel/peer_intel.py).

render(by, A, H, h) appends the section; `h` carries the page helpers (E, md, proof, table, ak, cls_of, kpis, fig, chip)
so this module holds no page state. Every cell is a value a row carries; each row cites the capture line it was read
from (proof column). Peers appear only by pseudonym; no address or tag ever reaches a row (gate G27 re-scans the
rendered section).
"""
GRADE_COL = {'OBSERVED': 'var(--gap)', 'ANOMALY': 'var(--warn)', 'NORMAL': 'var(--ok)', 'pending': 'var(--mut)'}
GRADE_ICON = {'OBSERVED': '●', 'ANOMALY': '▲', 'NORMAL': '✓', 'pending': '…'}
VCLASS = (('current', 'var(--ok)'), ('outdated', 'var(--warn)'), ('custom', 'var(--gap)'))


def _grade(g, chip):
    return chip(f"{GRADE_ICON.get(g, '')} {g}", GRADE_COL.get(g, 'var(--mut)'))


def _hbar(E, items, unit, label, fmt=lambda v: f'{v:g}', mark=None, ref=None, pill=('', 0)):
    """one horizontal bar per (name, value); a single series, so no legend: the caption names it. `mark(name, v)` gives
    a status colour for a bar that crosses a stated threshold; `ref` draws that threshold as a dashed line."""
    items = [(n, v) for n, v in items if isinstance(v, (int, float))]
    if not items:
        return ''
    W, lw, rh, top = 640, 120, 18, 22
    vmax = max([abs(v) for _, v in items] + [ref or 0]) or 1
    pw = W - lw - 70
    h = top + rh * len(items) + 8
    out = [f'<svg viewBox="0 0 {W} {h}" width="100%" xmlns="http://www.w3.org/2000/svg"><g class="as">', pill[0]]
    for i, (n, v) in enumerate(items):
        y = top + i * rh
        w = max(2, abs(v) / vmax * pw)
        col = (mark(n, v) if mark else None) or 'var(--l4)'
        out.append(f'<g><title>{E(n)}: {E(fmt(v))} {E(unit)}</title>'
                   f'<rect x="0" y="{y}" width="{W}" height="{rh}" fill="transparent"/>'
                   f'<text x="{lw - 6}" y="{y + 12.5}" font-size="10.5" text-anchor="end" fill="var(--ink2, currentColor)">{E(n)}</text>'
                   f'<rect x="{lw}" y="{y + 3}" width="{w:.1f}" height="{rh - 6}" rx="3" fill="{col}"/>'
                   f'<text x="{lw + w + 5:.1f}" y="{y + 12.5}" font-size="10.5" text-anchor="start" fill="var(--mut)">{E(fmt(v))}</text></g>')
    if ref:
        x = lw + ref / vmax * pw
        out.append(f'<line x1="{x:.1f}" y1="{top - 4}" x2="{x:.1f}" y2="{h - 4}" stroke="var(--gap)" stroke-dasharray="3 3"/>')
    out.append('</g></svg>')
    return ''.join(out)


def _vmix(E, counts, pill=('', 0)):
    tot = sum(counts.values()) or 1
    W, H_, x = 640, 46, 0
    W_bar = W - pill[1] - 12
    out = [f'<svg viewBox="0 0 {W} {H_}" width="100%" xmlns="http://www.w3.org/2000/svg"><g class="as">', pill[0]]
    for name, col in VCLASS:
        n = counts.get(name, 0)
        if not n:
            continue
        w = n / tot * W_bar
        out.append(f'<g><title>{E(name)}: {n} of {tot} peers</title><rect x="{x + 1:.1f}" y="4" width="{max(w - 2, 2):.1f}" height="18" rx="3" fill="{col}"/>'
                   + (f'<text x="{x + 4:.1f}" y="38" font-size="11" text-anchor="start" fill="var(--mut)">{E(name)} {n}</text>' if w > 80 else '')
                   + '</g>')
        x += w
    out.append('</g></svg>')
    return ''.join(out)


def render(by, A, H, h):
    rows = by.get('peers') or []
    if not rows:
        return
    E, md, proof, table, ak, cls_of, kpis, fig, chip = (h['E'], h['md'], h['proof'], h['table'], h['ak'], h['cls_of'],
                                                         h['kpis'], h['fig'], h['chip'])
    kind = lambda k: [r for r in rows if r.get('kind') == k]
    kr = (kind('kpi') or [{}])[0]
    pill = lambda r, y=10: ak.svg_ctag(636, y, cls_of(r))         # each chart carries the class of the row it is drawn from
    k = kr.get('kpis') or {}
    th = kr.get('thresholds') or {}
    cap = rows[0].get('captured', '')
    A(H('peers', 'Consensus observatory — network peers',
        'The nodes this daemon exchanges blocks, miniblocks and transactions with, measured from its own read-only view '
        '(`DERO.GetPeerInfo`, `DERO.GetSyncInfo`, `/metrics`, the P2P lines of the derod log, and copies of `peers.json`, '
        '`first_relay.json`, `v2_offences.json`, `ban_list.json`) by `harness/intel/peer_intel.py`. Peers are shown only by a '
        'salted pseudonym; addresses and tags never leave the private capture. Each detector cites the code line of the rule '
        'it checks. **OBSERVED** = the node\'s own rule fired on that peer (rule line and observation line cited); '
        '**ANOMALY** = unusual by the stated test and threshold, not an accusation; **NORMAL** = the detector ran and nothing '
        f'crossed it. Capture {E(cap)} on {E(rows[0].get("node_version", ""))}.'))
    A(kpis([(str(k.get('peers_active', 'pending')), 'active peers'),
            (f"{k.get('outgoing', '?')} / {k.get('incoming', '?')}", 'out / in'),
            (str(k.get('lag_max', 'pending')), 'max lag (blocks)'),
            (f"{k.get('latency_median_ms', 'pending')} ms", 'median latency'),
            (str(k.get('netgroups', 'pending')), 'distinct /16s'),
            (f"{round(100 * k['first_relay_top_share'], 1)}%" if isinstance(k.get('first_relay_top_share'), (int, float)) else 'pending', 'top first-relay share'),
            (str(k.get('observed', 0)), 'detectors OBSERVED'), (str(k.get('anomaly', 0)), 'detectors ANOMALY')]))
    A(f'<p class="note">Chain fingerprint {E(k.get("chain_fingerprint", "pending"))}; sync {E(k.get("sync_status", "pending"))}; '
      f'v2-remnant peers seen in 7 days: {E(k.get("v2_seen_7d", "pending"))}; ban-list entries: {E(k.get("bans_listed", "pending"))}; '
      f'block builders seen through first relays: {E(k.get("builders_seen", "pending"))}. Proof: {proof(kr, 3)}</p>')
    # detectors
    A('<h3>Detectors: health, activity and wrongdoing, each against a code rule</h3>')
    dets = kind('detector')
    dr = []
    for r in dets:
        fs = r.get('findings') or []
        ftxt = '<br>'.join(f"<span class=\"mono\">{E(f['peer'])}</span> {_grade(f['grade'], chip)} {E(f['what'])} "
                           f"<span class=\"mut\">[{E(', '.join(f.get('cites') or []))}]</span>" for f in fs[:6])
        if len(fs) > 6:
            ftxt += f'<br><span class="mut">+{len(fs) - 6} more in harness/runtime/peer_intel.json</span>'
        dr.append([f"<b>{E(r['det'])}</b>", E(r['title']), _grade(r['grade'], chip), md(r.get('test') or ''),
                   ftxt or ('<span class="mut">' + E(r.get('why') or 'no finding') + '</span>'), proof(r, 2)])
    A(table(['ID', 'Detector', 'Grade', 'Rule / test', 'Findings (pseudonym, grade, observation [anchor])', 'proof'],
            ak.tag_rows(dr, dets, ['', '', '', '', '', None], cls_of), 't-peerdet', filt=True))
    # peers
    A('<h3>Peers at capture (pseudonymous)</h3>')
    pr = kind('peer')
    pt = []
    for r in pr:
        p = r['peer']
        age = f"{p['connected_s'] / 3600:.1f} h" if isinstance(p.get('connected_s'), (int, float)) else '—'
        sh = f"{100 * p['mb_first_share']:.0f}%" if isinstance(p.get('mb_first_share'), (int, float)) else '—'
        pt.append([f"<span class=\"mono\">{E(p['peer'])}</span>", E(p.get('dir')), E(p.get('lag')), E(p.get('top_version')),
                   E(p.get('version_class')), E(p.get('latency_ms')), E(p.get('clock_offset_ms')), E(age),
                   E(f"{(p.get('bytes_in') or 0) / 1e6:.1f} / {(p.get('bytes_out') or 0) / 1e6:.1f}"), E(p.get('first_relays')),
                   E(sh), E(p.get('relay_delay_ms') if p.get('relay_delay_ms') is not None else '—'), E(p.get('builders')), proof(r, 1)])
    A(table(['Peer', 'Dir', 'Lag', 'Top ver.', 'Version', 'Latency ms', 'Clock ms', 'Connected', 'MB in / out',
             'First relays', 'Miniblocks first', 'Relay delay ms', 'Builders', 'proof'],
            ak.tag_rows(pt, pr, ['', '', '', '', '', '', '', '', '', '', '', '', '', None], cls_of), 't-peers', filt=True))
    # charts (single series each: the caption names it; every bar has a hover title)
    lat = sorted(((r['peer']['peer'], r['peer'].get('latency_ms')) for r in pr), key=lambda t: -(t[1] or 0))
    if lat:
        A(fig(_hbar(E, lat, 'ms', 'latency', fmt=lambda v: f'{v:.0f}', pill=pill(pr[0])),
              'Round-trip latency per peer (GetPeerInfo `latency_ms`), slowest first.', 'latency per peer'))
    clk = sorted(((r['peer']['peer'], r['peer'].get('clock_offset_ms')) for r in pr), key=lambda t: -abs(t[1] or 0))
    lim = th.get('clock_future_ms', 50)
    if clk:
        A(fig(_hbar(E, clk, 'ms', 'clock', fmt=lambda v: f'{v:+.1f}', mark=lambda n, v: 'var(--warn)' if abs(v) > lim else None, ref=lim, pill=pill(pr[0])),
              f'Clock offset per peer (`clock_offset_ms`, magnitude; sign in the hover). Dashed line: {lim} ms, the consensus '
              'future-timestamp allowance (blockchain/blockchain.go); a bar beyond it is an ANOMALY (D6).', 'clock offset per peer'))
    lag = [(r['peer']['peer'], r['peer'].get('lag')) for r in pr]
    if lag and any(v for _, v in lag):
        A(fig(_hbar(E, lag, 'blocks', 'lag', mark=lambda n, v: 'var(--warn)' if abs(v) > 25 else None, ref=25, pill=pill(pr[0])),
              'Lag behind our tip per peer (blocks). Dashed line: LAGGING_PEER_BLOCKS = 25.', 'lag per peer'))
    elif lag:
        A(f'<p class="note">Every active peer is at our height (lag 0 for all {len(lag)}), so the lag chart is omitted. Proof: {proof(kr, 1)}</p>')
    frs = sorted(((r['fr']['peer'], r['fr'].get('firsts')) for r in kind('first_relay')), key=lambda t: -(t[1] or 0))
    if frs:
        A(fig(_hbar(E, frs[:14], 'blocks', 'first relays', pill=pill(kind('first_relay')[0])),
              'Blocks each peer delivered to us first (first_relay.json `firsts`, the decaying ranking that keeps the best relays '
              'connected). One peer far ahead of the rest is the D9 concentration indicator.', 'first relays per peer'))
    vc = k.get('versions') or {}
    if vc:
        A(fig(_vmix(E, vc, pill=pill(kr)), 'Version mix of the active peers: current = this tree\'s 3.6.0-153 line, outdated = an older plain '
              'release string, custom = anything else (not shown).', 'version mix'))
    # census
    A('<h3>Bans, offences, handshakes and P2P events</h3>')
    cen = kind('ban') + kind('v2')
    if cen:
        ct = []
        for r in cen:
            if r['kind'] == 'ban':
                b = r['ban']
                ct.append([f"<span class=\"mono\">{E(b['entry'])}</span>", 'ban list', E(b['scope']), E(f"{b.get('remaining_s')} s left"),
                           E('v2-remnant offender' if b.get('v2_offender') else 'reason not recorded (CO24-N4)'), proof(r, 1)])
            else:
                v = r['v2']
                ct.append([f"<span class=\"mono\">{E(v['peer'])}</span>", 'v2 offences', 'ip', E(f"dropped {v.get('n')}x"),
                           E(f"connected now: {v.get('connected')}"), proof(r, 1)])
        A(table(['Entry', 'Source', 'Scope', 'State', 'Reason', 'proof'], ak.tag_rows(ct, cen, ['', '', '', '', '', None], cls_of), 't-peerban'))
    mr = kind('metric')
    if mr:
        A(table(['Counter', 'Labels', 'Value', 'proof'],
                ak.tag_rows([[f"<span class=\"mono\">{E(r['title'])}</span>", E(r.get('labels') or '—'), E(f"{r['value']:g}"), proof(r, 1)] for r in mr],
                            mr, ['', '', '', None], cls_of), 't-peerm', filt=True))
    lk = kind('log_kinds')
    if lk:
        r = lk[0]
        kt = [[f"<span class=\"mono\">{E(n)}</span>", E(v['peers']), E(v['lines']), proof(r, 1)] for n, v in sorted((r.get('kinds') or {}).items(), key=lambda kv: -kv[1]['lines'])]
        A(table(['P2P log event kind (whole log)', 'Peers', 'Lines', 'proof'], ak.tag_rows(kt, [r] * len(kt), ['', '', '', None], cls_of), 't-peerlog'))
    bl = kind('builders')
    if bl:
        r = bl[0]
        bt = [[f"<span class=\"mono\">{E(n)}</span>", E(v), proof(r, 1)] for n, v in list((r.get('builders') or {}).items())[:12]]
        A('<h3>Consensus participants seen through relays</h3>')
        A(f'<p class="note">Block builders (the first 8 bytes of a block\'s miner key, pseudonymised; this node\'s own key would read '
          f'<span class="mono">this-node</span>) whose blocks reached us first through some peer, with the count over the decaying '
          f'first-relay table: {len(r.get("builders") or {})} distinct builders. Top 12:</p>')
        A(table(['Builder', 'First deliveries', 'proof'], ak.tag_rows(bt, [r] * len(bt), ['', '', None], cls_of), 't-peerbld'))
    sr = kind('series')
    if sr:
        r = sr[0]
        st = [[E(p.get('captured')), E(p.get('peers')), E(p.get('lag_max')), E(p.get('latency_median_ms')), E(p.get('first_relay_top_share')),
               E(p.get('netgroups')), E(p.get('observed')), E(p.get('anomaly')), E(p.get('handshake_failures'))] for p in r['points'][-12:]]
        A('<h3>Rolling series (harness/runtime/peer_series.jsonl)</h3>')
        A(table(['Captured', 'Peers', 'Max lag', 'Latency median', 'Top first-relay share', '/16s', 'OBSERVED', 'ANOMALY', 'Handshake failures'],
                ak.tag_rows(st, [r] * len(st), [''] * 9, cls_of), 't-peerseries'))
    pp = kind('proposal')
    if pp:
        A('<h3>What the node cannot show yet: proposals for R25</h3>')
        A('<p class="note">Each gap below is a node-side measurement this observatory needed and could not read. Each is anchored on '
          'the code line that shows the gap and is carried to dero-rft §7 and the area proposals feed (area <span class="mono">peers</span>), '
          'so the next round implements it: the self-recursive loop.</p>')
        A(table(['ID', 'Gap', 'Evidence', 'Proposal', 'Status', 'proof'],
                ak.tag_rows([[f"<b>{E(r['pid'])}</b>", E(r['title']), E(r['gap']), E(r['proposal']), E(r.get('status')), proof(r, 1)] for r in pp],
                            pp, ['', '', '', '', '', None], cls_of), 't-peerprop'))
    A('</section>')
