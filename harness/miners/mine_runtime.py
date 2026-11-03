#!/usr/bin/env python3
"""mine_runtime.py — the live daemon as evidence.

  python3 miners/mine_runtime.py [--capture]

--capture takes a fresh read-only snapshot of the running derod (JSON-RPC on 127.0.0.1:10102, plus `ps`) into
harness/runtime/snap_<ts>.json, PRETTY-PRINTED so every field sits on its own line and can be anchored like any
other source line. Without it the miner reads the snapshots already on disk. Nothing here writes to the daemon:
every method called is a getter.

The claims are interpretations of measured fields; the numbers are read out of the snapshot the row cites.
"""
import datetime, json, re, subprocess, sys, urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import minelib as M

RUNTIME = M.HARNESS / 'runtime'
RPC = 'http://127.0.0.1:10102/json_rpc'

# field -> (title, how to read it). The value printed on the page is always the one in the snapshot.
READING = {
 'height':          ('Chain height', 'Blocks accepted on the main chain.'),
 'topoheight':      ('Topological height', 'Position in the DAG ordering; equal to height when no side branch is live.'),
 'stableheight':    ('Stable height', 'Settled depth: topoheight minus STABLE_LIMIT (8).'),
 'prunedheight':    ('Prune point', 'Block bodies below this are gone. A peer asking for anything older gets an error, not a panic.'),
 'difficulty':      ('Current difficulty', 'The v3 chain runs near 5-6 M; the abandoned v2 remnant chain sits near 2 M, so this one number identifies which chain the node follows.'),
 'averageblocktime50': ('Mean spacing of the last 50 blocks', 'Computed from the block TIMESTAMPS of the tip and the block 50 before it, so it reports the cadence the network ran at when those blocks were minted — not how fast this node is ingesting them, and not whether it has reached the tip. '
                       'Read it together with the tip age below.'),
 'outgoing_connections_count': ('Outgoing peers', 'Connections this node dialled.'),
 'incoming_connections_count': ('Incoming peers', 'Connections dialled to us. Zero means no inbound path exists — UDP 11011 is not forwarded.'),
 'tx_pool_size':    ('Mempool depth', 'Transactions waiting for a miner.'),
 'total_supply':    ('Total supply', 'Emitted coins, premine included.'),
 'version':         ('Reported version', 'What peers see in the handshake.'),
 'uptime':          ('Uptime (s)', 'Seconds since this derod process started.'),
 'treehash':        ('Balance-tree root', 'The graviton root hash committed at the tip.'),
 'top_block_hash':  ('Tip block id', 'Hash of the block at height.'),
 'connected_miners': ('Connected miners', 'GETWORK websocket clients. Zero while only the node runs.'),
 'alt_blocks_count': ('Alternative blocks', 'Non-zero means a reorg is in flight.'),
}


def rpc(method, params=None):
    body = json.dumps({'jsonrpc': '2.0', 'id': '1', 'method': method, **({'params': params} if params else {})}).encode()
    req = urllib.request.Request(RPC, data=body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=8) as r:
        return json.loads(r.read())


def capture():
    RUNTIME.mkdir(exist_ok=True)
    snap = {'captured': datetime.datetime.now().astimezone().isoformat(timespec='seconds')}
    try:
        snap['getinfo'] = rpc('DERO.GetInfo').get('result', {})
    except Exception as e:                                        # noqa: BLE001  the node may be stopped
        snap['getinfo_error'] = str(e)
    for m, key in (('DERO.GetTxPool', 'txpool'), ('DERO.GetHeight', 'getheight')):
        try:
            snap[key] = rpc(m).get('result', {})
        except Exception as e:                                    # noqa: BLE001
            snap[key + '_error'] = str(e)
    # The tip BLOCK HEADER. Its timestamp against the wall clock is the only purely local way to tell whether
    # this node is current: GetInfo.averageblocktime50 is computed from block timestamps and therefore reports
    # the network's historical cadence at whatever height we have reached, and GetInfo.target_height is never
    # assigned. Without this reading a node 40 days behind looks healthy.
    try:
        topo = (snap.get('getinfo') or {}).get('topoheight')
        bh = rpc('DERO.GetBlockHeaderByTopoHeight', {'topoheight': topo}).get('result', {}).get('block_header', {})
        ts = (bh.get('timestamp') or 0) / 1000
        snap['tip'] = {'topoheight': topo, 'major_version': bh.get('major_version'),
                       'timestamp_ms': bh.get('timestamp'),
                       'block_time_iso': datetime.datetime.fromtimestamp(ts).astimezone().isoformat(timespec='seconds') if ts else None,
                       'age_seconds': round(datetime.datetime.now().timestamp() - ts) if ts else None}
    except Exception as e:                                        # noqa: BLE001
        snap['tip_error'] = str(e)
    ps = subprocess.run(['ps', '-Ao', 'pid,etime,rss,command'], capture_output=True, text=True).stdout
    snap['process'] = [l.strip() for l in ps.splitlines() if '/bin/derod' in l and 'grep' not in l]
    lsof = subprocess.run(['lsof', '-nP', '-iUDP', '-iTCP', '-a', '-c', 'derod'], capture_output=True, text=True).stdout
    snap['sockets'] = {'udp': len([l for l in lsof.splitlines() if ' UDP ' in l]),
                       'tcp_listen': len([l for l in lsof.splitlines() if 'LISTEN' in l])}
    ts = datetime.datetime.now().strftime('%Y%m%dT%H%M%S')
    p = RUNTIME / f'snap_{ts}.json'
    p.write_text(json.dumps(snap, indent=1))                      # one field per line: every field is anchorable
    print(f'captured {p.name}: height {snap.get("getinfo", {}).get("height")} '
          f'· {snap["sockets"]["udp"]} UDP sockets · {len(snap["process"])} derod process(es)')
    return p


def main():
    if '--capture' in sys.argv:
        capture()
    snaps = sorted(RUNTIME.glob('snap_*.json'))
    if not snaps:
        M.emit('runtime', [], [{'title': 'live node', 'why': 'no snapshot in harness/runtime/'}], 'mine_runtime.py')
        return
    rows, unv = [], []
    latest = snaps[-1]
    rel = str(latest.relative_to(M.ROOT))
    d = json.loads(latest.read_text())
    gi = d.get('getinfo') or {}
    for k, (title, how) in READING.items():
        if k not in gi:
            unv.append({'title': title, 'why': f'GetInfo did not return "{k}" in {latest.name}'})
            continue
        # the needle carries the VALUE as well as the key: '"height":' alone is 9 characters and the 12-char
        # floor would refuse it, and the pair is what actually proves the reading.
        a = M.anchor(rel, f'"{k}": {json.dumps(gi[k])}', full_line=True) or M.anchor(rel, f'"{k}":', full_line=True)
        if not a:
            unv.append({'title': title, 'why': f'field "{k}" not on its own line of the snapshot'})
            continue
        rows.append({'id': f'rt-{k}', 'section': 'runtime', 'title': title, 'class': 'HARNESS',
                     'claim': f'{title}: {gi[k]}. {how}', 'field': k, 'value': gi[k], 'how': how,
                     'captured': d.get('captured'), 'evidence': [a]})
    # ---- build skew: does the running daemon run the source this tree declares?
    vline = next((l for l in (M.lines('config/version.go')[0] or []) if 'MustParse(' in l), '')
    vm = re.search(r'MustParse\("([^"]+)"\)', vline)
    if vm and gi.get('version'):
        a_run = M.anchor(rel, f'"version": "{gi["version"]}"', full_line=True)
        a_src = M.anchor('config/version.go', vline.strip(), full_line=True)
        if a_run and a_src:
            same = gi['version'] == vm.group(1)
            core = gi['version'].split('+')[0] == vm.group(1).split('+')[0]
            rows.append({'id': 'rt-buildskew', 'section': 'runtime', 'title': 'Running build vs this tree',
                         'class': 'HARNESS', 'field': 'build_skew', 'value': 'same' if same else 'older',
                         'all_anchors': True,          # the claim compares the two; it is void if either moves
                         'claim': (f'The daemon runs {gi["version"]} and this tree declares {vm.group(1)}. '
                                   + ('They are the same build.' if same else
                                      ('Same release, different build: the fixes in this tree take effect only '
                                       'after derod is restarted on the new binary.' if core else
                                       'DIFFERENT RELEASE: check which binary is running.'))),
                         'evidence': [a_run, a_src]})
    # the process and its sockets
    for i, line in enumerate(d.get('process') or []):
        a = M.anchor(rel, line[:120], full_line=True) or M.anchor(rel, '/bin/derod', full_line=True)
        if a:
            pid, etime = (line.split() + ['', ''])[:2]
            rows.append({'id': f'rt-proc-{i}', 'section': 'runtime', 'title': 'derod process', 'class': 'HARNESS',
                         'claim': f'One derod process is running: pid {pid}, elapsed {etime}. The full argument '
                                  f'vector is the operator’s own command line, recorded verbatim in the snapshot.',
                         'field': 'process', 'value': f'pid {pid}', 'evidence': [a]})
    sk = d.get('sockets') or {}
    a = M.anchor(rel, '"udp":', full_line=True)
    if a and sk:
        rows.append({'id': 'rt-sockets', 'section': 'runtime', 'title': 'Open sockets', 'class': 'HARNESS',
                     'claim': f'{sk.get("udp")} UDP sockets and {sk.get("tcp_listen")} listening TCP sockets are open '
                              f'in the derod process. The UDP count is the KCP peer sessions plus the 11011 listener; '
                              f'the TCP listeners are the two loopback RPC ports.',
                     'field': 'sockets', 'value': sk, 'evidence': [a]})
    # ---- the tip's age: the reading that decides whether any other reading means what it looks like
    tip = d.get('tip') or {}
    rate = None
    if len(snaps) >= 2:
        a_, b_ = json.loads(snaps[-2].read_text()), d
        try:
            dt = (datetime.datetime.fromisoformat(b_['captured']) - datetime.datetime.fromisoformat(a_['captured'])).total_seconds()
            dh = b_['getinfo']['height'] - a_['getinfo']['height']
            if dt > 0 and dh > 0:
                rate = dh / dt
        except Exception:                                          # noqa: BLE001
            pass
    if tip.get('age_seconds') is not None:
        a = M.anchor(rel, f'"age_seconds": {tip["age_seconds"]}', full_line=True)
        age = tip['age_seconds']
        behind = age / 18
        if a:
            rows.append({'id': 'rt-tipage', 'section': 'runtime', 'title': '★ Age of the tip block', 'class': 'HARNESS',
                         'claim': f'The newest block this node holds was minted {age:,} s ago '
                                  f'({age / 86400:.1f} days, block time {tip.get("block_time_iso")}). At the 18-second '
                                  f'target that is about {behind:,.0f} blocks behind the live network. '
                                  + ('The node is CATCHING UP, not at the tip.' if age > 600 else
                                     'The node is at the tip.'),
                         'field': 'tip_age', 'value': age, 'how': 'Wall clock minus the tip block’s own timestamp. '
                                                                  'The only reading here that can tell at-tip from far behind.',
                         'captured': d.get('captured'), 'evidence': [a]})
    if rate:
        a = M.anchor(rel, f'"height": {d["getinfo"]["height"]}', full_line=True)
        if a:
            eta = ''
            if tip.get('age_seconds', 0) > 600 and rate > 1 / 18:
                secs = (tip['age_seconds'] / 18) / (rate - 1 / 18)
                eta = f' At that net rate the remaining gap closes in roughly {secs / 3600:.1f} hours.'
            rows.append({'id': 'rt-rate', 'section': 'runtime', 'title': 'Measured ingestion rate', 'class': 'HARNESS',
                         'claim': f'Between the last two snapshots this node accepted {rate:.2f} blocks per second '
                                  f'({1 / rate:.2f} s per block of wall time). The network mints one per 18 s, so a '
                                  f'rate far above 1/18 means the node is replaying history, not following the tip.'
                                  + eta,
                         'field': 'ingest_rate', 'value': round(rate, 3),
                         'how': 'Height delta divided by capture-time delta across the two most recent snapshots.',
                         'evidence': [a]})
    M.emit('runtime', rows, unv, 'mine_runtime.py')


if __name__ == '__main__':
    main()
