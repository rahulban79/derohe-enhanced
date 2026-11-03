"""areakit (r24): the 'Areas' block of dero-src-arch.html, drawn from model rows of section 'areas' (mine_areas.py).

render(by, A, H, h) appends the section; `h` carries the page helpers (E, md, proof, table, tag, kpis, note, ak,
cls_of) so this module holds no page state. Every cell is a value a row carries, and each row cites the scorecard
lines it was read from (proof column); a value the scorecard could not anchor never reaches a row (mine_areas.py).
"""

STATE_COL = {'OK': 'var(--ok)', 'WATCH': 'var(--warn)', 'ATTENTION': 'var(--gap)', 'NO-DATA': 'var(--mut)', 'PAUSED': 'var(--mut)'}
ARROW = {'up': '↑', 'down': '↓', 'flat': '→', 'new': '•', 'n-a': ''}


def _metrics(r, E, n=4):
    out = []
    for m in (r.get('shown') or [])[:n]:
        t = ARROW.get(m.get('trend') or 'n-a', '')
        prev = f" (was {E(m['prev'])} in {E(m['prev_round'])})" if m.get('prev') else ''
        flag = ' <b>regression</b>' if m.get('regression') else ''
        out.append(f"<span class=\"mono\">{E(m['id'])}</span> {E(m['display'])} [{E(m['round'])}] {t}{prev}{flag}")
    return '<br>'.join(out) or '—'


def render(by, A, H, h):
    rows = by.get('areas') or []
    if not rows:
        return
    E, md, proof, table, ak, cls_of, kpis = h['E'], h['md'], h['proof'], h['table'], h['ak'], h['cls_of'], h['kpis']
    cap = rows[0].get('captured', '')
    A(H('areas', 'Every area of the stack, scored each round',
        'One scorecard per area of `harness/areas.json` (harness, security, crypto and supply, getwork and ops, '
        'mempool, chain performance, RPC and websockets, sync and P2P, wallet, storage, observability, docs, the '
        'Foundation disclosure, the miner). `harness/intel/area_intel.py` computes each from the round records and '
        'the live node; its self-detected items feed dero-rft §7 and §8. A paused area is shown **PAUSED**, '
        f'never failing. Scorecard run {E(rows[0].get("run_id", ""))} ({E(cap)}).'))
    st = {}
    for r in rows:
        st[r['state']] = st.get(r['state'], 0) + 1
    A(kpis([(str(len(rows)), 'areas scored'), (str(st.get('OK', 0)), 'OK'),
            (str(st.get('WATCH', 0) + st.get('ATTENTION', 0)), 'need attention'), (str(st.get('PAUSED', 0)), 'paused'),
            (str(sum(r.get('proposals', 0) for r in rows)), 'proposals for the next round')]))
    tr = [[f"<b>{E(r['title'])}</b>", f"<span style=\"color:{STATE_COL.get(r['state'], 'var(--mut)')}\">{E(r['state'])}</span>",
           E(r['owner']), E(r['mut']), E(r['gates']), E(', '.join(r['backlog_open']) or '—'), E(str(r['proposals'])),
           _metrics(r, E), proof(r, 2)] for r in rows]
    A(table(['Area', 'State', 'Owner (§8)', 'Mutations', 'Gates', 'Open backlog', 'Proposals', 'Last measured (round, trend)', 'proof'],
            ak.tag_rows(tr, rows, ['', '', '', '', '', '', '', '', None], cls_of), 't-areas', filt=True))
    A('</section>')
