#!/usr/bin/env python3
"""datadir_intel.py — read-only integrity checks of the live DERO datadir, derived from the code that writes it.

Every format constant is READ from the Go source, never typed: the topo record size from
`const TOPORECORD_SIZE int64 = 48` (blockchain/storetopo.go), the record layout from storetopofs.Read, the block and
tx fan-out bytes from storefs.getpath / getpathtx, the graviton version-pointer width from how version_root.bin is
indexed. If a release changes any of them the checker follows instead of silently checking the old format.

Safe while derod runs: files are only opened for reading; the live node is asked over RPC for the values the files
must agree with. Checks (each PASS/FAIL/INFO with the numbers that decided it):

  topo-records     topo.map is a whole number of records
  topo-tip         the last non-clean record is the node's topoheight and top block (RPC)
  topo-monotonic   state_version never decreases; height never decreases and has no gaps after the first block
  topo-prune       the prune point computed from the file equals RPC prunedheight
  grav-versions    version_root.bin: whole pointers, count == newest state_version, all in bounds and monotonic
  bltx-fanout      every block file sits under h[0]/h[1], every tx under h[16]/h[17]
  bltx-topo        every topo record after the prune point has its block file; filename height/version agree
  peers-schema     peers.json fields and types; how many connected peers would survive a reload (the 2026-10-22 defect)
  bans-schema      ban_list.json keys are IPs or networks
  first-relay      first_relay.json (r18 persistence): fields = the RelayStat json tags in p2p/first_relay.go; how many
                   entries load_first_relay_from would restore (FIRST_RELAY_FORGET read from the source)
  v2-offences      v2_offences.json: fields = the v2_record json tags in p2p/penalty.go; entries V2_FORGET keeps
  archives         what else sits in the data directory (informational)

  python3 harness/intel/datadir_intel.py [--datadir <datadir>] [--quick]
"""
import argparse, collections, datetime, ipaddress, json, os, re, struct, sys, time, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
ROOT = HARNESS.parent
RPC = 'http://127.0.0.1:10102/json_rpc'


def src(rel):
    return (ROOT / rel).read_text(errors='replace')


def constants():
    """The format, from the source."""
    st = src('blockchain/storetopo.go')
    rec = int(re.search(r'const TOPORECORD_SIZE int64 = (\d+)', st).group(1))
    fs = src('blockchain/storefs.go')
    blk = re.search(r'func \(s \*storefs\) getpath\(h \[32\]byte\) string \{.*?return filepath\.Join\(filepath\.Join\(s\.basedir, "bltx_store"\), fmt\.Sprintf\("%02x", h\[(\d+)\]\), fmt\.Sprintf\("%02x", h\[(\d+)\]\)\)', fs, re.S)
    txp = re.search(r'func \(s \*storefs\) getpathtx\(h \[32\]byte\) string \{.*?return filepath\.Join\(filepath\.Join\(s\.basedir, "bltx_store"\), fmt\.Sprintf\("%02x", h\[(\d+)\]\), fmt\.Sprintf\("%02x", h\[(\d+)\]\)\)', fs, re.S)
    return {'TOPORECORD_SIZE': rec, 'block_fanout': (int(blk.group(1)), int(blk.group(2))),
            'tx_fanout': (int(txp.group(1)), int(txp.group(2))),
            'anchors': {'TOPORECORD_SIZE': 'blockchain/storetopo.go', 'getpath/getpathtx': 'blockchain/storefs.go'}}


def go_int_expr(expr):
    """the value of a Go integer constant expression made only of decimal literals, '*' and '_' (e.g. 7 * 24 * 3600)"""
    expr = expr.strip().replace('_', '')
    if not re.fullmatch(r'\d+(\s*\*\s*\d+)*', expr):
        raise ValueError(f'not a product of literals: {expr!r}')
    v = 1
    for x in expr.split('*'):
        v *= int(x)
    return v


def go_const(text, name):
    m = re.search(rf'^const {name}\s*(?:\w+\s*)?=\s*([0-9_ *]+?)\s*(?://.*)?$', text, re.M)
    if not m:
        raise ValueError(f'const {name} not found')
    return go_int_expr(m.group(1))


def go_json_fields(text, struct):
    """{json tag: Go type} of `type <struct> struct {...}` (fields with a json tag only)."""
    m = re.search(rf'type {struct} struct \{{(.*?)\n\}}', text, re.S)
    if not m:
        raise ValueError(f'struct {struct} not found')
    out = {}
    for l in m.group(1).splitlines():
        f = re.match(r'\s*\w+\s+(\S+)\s+`json:"([^",]+)', l)
        if f:
            out[f.group(2)] = f.group(1)
    return out


PY_OF_GO = {'string': str, 'int': int, 'int64': int, 'uint64': int, 'map[string]uint64': dict}


def retention_from_source(text):
    """(whitelisted, grey) seconds from p2p/peer_pool.go retention_seconds — read, not typed (R19: the r18 check had
    typed r17's numbers, and the FAIL at 10:57:45 on 2026-10-24 was the old 3600 s rule judging a 86400 s build)"""
    m = re.search(r'func retention_seconds\(v \*Peer\) uint64 \{\s*if v\.Whitelist \{\s*return ([0-9_ *]+?)\s*\}\s*return ([0-9_ *]+?)\s*\}', text)
    if not m:
        raise ValueError('retention_seconds not found in p2p/peer_pool.go')
    return go_int_expr(m.group(1)), go_int_expr(m.group(2))


def first_relay_check(table, now, forget, fields):
    """mirror of p2p/first_relay.go load_first_relay_from: which entries a restart would restore, and why not."""
    peers = table.get('peers') if isinstance(table, dict) else None
    if not isinstance(peers, dict):
        return {'schema_errors': ['no "peers" object'], 'entries': 0, 'restorable': 0, 'rejected': {}}
    bad, rej, ok, firsts = [], {}, 0, []
    for ip, s in peers.items():
        if not isinstance(s, dict) or set(s) - set(fields) or any(
                k in s and not isinstance(s[k], PY_OF_GO.get(t, object)) or isinstance(s.get(k), bool) for k, t in fields.items()):
            bad.append(ip)
            continue
        try:
            ipaddress.ip_address(ip)
            valid_ip = True
        except ValueError:
            valid_ip = False
        why = ('no firsts' if not s.get('firsts') else 'not an IP' if not valid_ip else
               'older than FIRST_RELAY_FORGET' if now - s.get('last_first', 0) > forget else
               'in the future' if s.get('last_first', 0) > now + 86400 else None)
        if why:
            rej[why] = rej.get(why, 0) + 1
        else:
            ok += 1
            firsts.append(s['firsts'])
    tot = sum(firsts)
    return {'schema_errors': bad, 'entries': len(peers), 'restorable': ok, 'rejected': rej,
            'blocks': table.get('blocks'), 'top_share': round(max(firsts) / tot, 3) if tot else None}


def v2_offences_check(m, now, forget, fields):
    """mirror of p2p/v2_offences.go load_v2_offences_from."""
    if not isinstance(m, dict):
        return {'schema_errors': ['not an object'], 'entries': 0, 'kept': 0}
    bad, kept = [], 0
    for ip, r in m.items():
        if not isinstance(r, dict) or set(r) != set(fields) or any(not isinstance(r[k], int) or isinstance(r[k], bool) for k in r):
            bad.append(ip)
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            bad.append(ip)
            continue
        if r['n'] > 0 and now - r['last'] <= forget and r['last'] <= now + 86400:
            kept += 1
    return {'schema_errors': bad, 'entries': len(m), 'kept': kept}


def rpc(method, params=None):
    body = json.dumps({'jsonrpc': '2.0', 'id': '1', 'method': method, **({'params': params} if params else {})}).encode()
    req = urllib.request.Request(RPC, data=body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read()).get('result')



def write_atomic(path, text):
    """R22 crash safety: a snapshot is written to a hidden temp file in the same directory, fsynced and renamed over
    its name, so a kill mid-write never leaves a torn newest snapshot for run_gates/mine_intel to choke on (they read
    the newest *_<ts>.json; a torn one used to crash the whole gate run). The temp name never matches a *_*.json glob."""
    import os, tempfile
    p = Path(path)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix='.' + p.name + '.', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--datadir', default=os.path.expanduser(os.environ.get('DERO_DATADIR', '~/dero-data')) + '')
    ap.add_argument('--quick', action='store_true', help='skip the full bltx_store walk')
    a = ap.parse_args()
    D = Path(a.datadir) / 'mainnet'
    C = constants()
    R = C['TOPORECORD_SIZE']
    checks = []
    running = (rpc('DERO.GetInfo') or {}).get('version', '')

    def check(name, ok, what, fixed_in=None, **num):
        # a check for a defect fixed in build `fixed_in` is KNOWN, not FAIL, while an older build is still running
        res = ('PASS' if ok else 'FAIL') if ok is not None else 'INFO'
        if res == 'FAIL' and fixed_in and fixed_in not in running:
            res = 'KNOWN'
            what += f' — expected while {running} runs; fixed in +{fixed_in}'
        checks.append({'check': name, 'result': res, 'what': what, **num})

    # ---- topo.map: read once, then ask the node; the node may append a record in between, so allow one retry
    for attempt in range(3):
        data = (D / 'topo.map').read_bytes()
        info = rpc('DERO.GetInfo') or {}
        n = len(data) // R
        c = n
        while c >= 1 and data[(c - 1) * R:c * R] == b'\0' * R:
            c -= 1                                          # trailing clean records (Count() skips them)
        last = data[(c - 1) * R:c * R]
        if c - 1 == info.get('topoheight'):
            break
        time.sleep(2)
    check('topo-records', len(data) % R == 0, f'{len(data):,} bytes = {n:,} records of {R} bytes, remainder {len(data) % R}',
          records=n, remainder=len(data) % R)
    tip_ok = (c - 1 == info.get('topoheight') and last[:32].hex() == (info.get('top_block_hash') or '').lower())
    check('topo-tip', tip_ok, f"last record topo {c - 1} vs RPC {info.get('topoheight')}; hash {last[:32].hex()[:16]} vs "
          f"{(info.get('top_block_hash') or '')[:16].lower()}", topo=c - 1, rpc_topo=info.get('topoheight'))
    first = next(i for i in range(c) if data[i * R:i * R + 32] != b'\0' * 32)
    pv = ph = -1
    dec_v = dec_h = gaps = 0
    for i in range(first, c):
        v = struct.unpack_from('<Q', data, i * R + 32)[0]
        h = struct.unpack_from('<q', data, i * R + 40)[0]
        if v < pv:
            dec_v += 1
        if ph >= 0 and h < ph:
            dec_h += 1
        if ph >= 0 and h - ph > 1:
            gaps += 1
        pv, ph = v, h
    check('topo-monotonic', dec_v == 0 and dec_h == 0 and gaps == 0,
          f'from topo {first:,}: state_version decreases {dec_v}, height decreases {dec_h}, height gaps {gaps}',
          first_block_topo=first)
    # LocatePruneTopo reports the first topo that still has a block id (records below it were cleaned to zero)
    check('topo-prune', first == info.get('prunedheight'),
          f"first topo with a block id {first:,} vs RPC prunedheight {info.get('prunedheight')}")
    newest_v = struct.unpack_from('<Q', last, 32)[0]

    # ---- graviton balances: version_root.bin holds one (findex u32, fpos u32) pointer per version
    B = D / 'balances'
    vr = (B / 'version_root.bin').read_bytes()
    nv = len(vr) // 8
    dfs = {int(p.stem): p.stat().st_size for p in (B / '0/0/0').glob('*.dfs')}
    prev, bad_mono, oob, zero = (0, 0), 0, 0, 0
    for v in range(nv):
        fi, fp = struct.unpack_from('<II', vr, v * 8)
        if (fi, fp) == (0, 0):
            zero += 1
        if (fi, fp) < prev:
            bad_mono += 1
        if fi not in dfs or fp >= dfs[fi]:
            oob += 1
        prev = (fi, fp)
    check('grav-versions', len(vr) % 8 == 0 and nv in (newest_v, newest_v + 1) and not (bad_mono or oob or zero),
          f'{nv:,} version pointers (newest topo state_version {newest_v:,}); zero {zero}, non-monotonic {bad_mono}, '
          f'out of bounds {oob}; dfs files {sorted(dfs)}', versions=nv, newest_state_version=newest_v)

    # ---- bltx_store
    bf, tf = C['block_fanout'], C['tx_fanout']
    if not a.quick:
        BRE = re.compile(r'^([0-9a-f]{64})\.block_(\d+)_(\d+)_(\d+)$')
        TRE = re.compile(r'^([0-9a-f]{64})\.tx$')
        blocks, bad_dir, tx_files, odd = {}, [], 0, []
        for d1 in os.listdir(D / 'bltx_store'):
            for d2 in os.listdir(D / 'bltx_store' / d1):
                for fn in os.listdir(D / 'bltx_store' / d1 / d2):
                    m = BRE.match(fn)
                    if m:
                        h = bytes.fromhex(m.group(1))
                        if (f'{h[bf[0]]:02x}', f'{h[bf[1]]:02x}') != (d1, d2):
                            bad_dir.append(fn)
                        blocks.setdefault(m.group(1), []).append((int(m.group(3)), int(m.group(4))))
                        continue
                    m = TRE.match(fn)
                    if m:
                        tx_files += 1
                        h = bytes.fromhex(m.group(1))
                        if (f'{h[tf[0]]:02x}', f'{h[tf[1]]:02x}') != (d1, d2) and (f'{h[0]:02x}', f'{h[1]:02x}') != (d1, d2):
                            bad_dir.append(fn)          # ReadTX also tries the legacy getpath location first
                        continue
                    odd.append(fn)
        check('bltx-fanout', not bad_dir, f'{sum(len(v) for v in blocks.values()):,} block files and {tx_files:,} tx files; '
              f'misplaced {len(bad_dir)}, unrecognised names {len(odd)}', misplaced=len(bad_dir), odd=len(odd))
        missing, hmis, vmis = 0, 0, 0
        for i in range(first, c):
            blid = data[i * R:i * R + 32].hex()
            if blid not in blocks:
                missing += 1
                continue
            v = struct.unpack_from('<Q', data, i * R + 32)[0]
            h = struct.unpack_from('<q', data, i * R + 40)[0]
            if all(x[1] != h for x in blocks[blid]):
                hmis += 1
            if max(x[0] for x in blocks[blid]) != v:
                vmis += 1
        check('bltx-topo', missing == 0 and hmis == 0 and vmis == 0,
              f'{c - first:,} topo records after the prune point: block file missing {missing}, height mismatch {hmis}, '
              f'snapshot-version mismatch {vmis}', missing=missing)

    # ---- peers.json / ban_list.json
    now = int(time.time())
    pj = json.loads((D / 'peers.json').read_text())
    pm = int((D / 'peers.json').stat().st_mtime)
    F = {'address': str, 'peerid': int, 'miner': bool, 'lastconnected': int, 'failcount': int, 'connectafter': int,
         'blacklistbefore': int, 'goodcount': int, 'version': int, 'whitelist': bool}
    bad = [k for k, v in pj.items() if set(v) != set(F) or any(type(v.get(f)) is not t for f, t in F.items())]
    keep_white, keep_grey = retention_from_source(src('p2p/peer_pool.go'))
    stale = [k for k, v in pj.items() if pm > v['lastconnected'] + (keep_white if v['whitelist'] else keep_grey)]
    check('peers-schema', not bad, f'{len(pj)} entries, schema errors {len(bad)}', entries=len(pj))
    check('peers-survive-reload', len(stale) == 0,
          f'{len(stale)} of {len(pj)} entries were saved past their retention (whitelisted {keep_white} s, grey {keep_grey} s, '
          f'from p2p/peer_pool.go retention_seconds), so the load-time clean_up would purge them', fixed_in='22102026',
          stale=len(stale), entries=len(pj))
    bj = json.loads((D / 'ban_list.json').read_text())
    badb = []
    for k in bj:
        try:
            ipaddress.ip_network(k, strict=False)
        except ValueError:
            badb.append(k)
    check('bans-schema', not badb, f'{len(bj)} ban entr(ies), invalid keys {badb}')

    # ---- r18 persistence files: first_relay.json and v2_offences.json, formats read from the Go that writes them
    fr_src, pen_src = src('p2p/first_relay.go'), src('p2p/penalty.go')
    frp = D / 'first_relay.json'
    if frp.exists():
        fr = first_relay_check(json.loads(frp.read_text()), int(frp.stat().st_mtime), go_const(fr_src, 'FIRST_RELAY_FORGET'),
                               go_json_fields(fr_src, 'RelayStat'))
        check('first-relay', not fr['schema_errors'] and fr['restorable'] > 0,
              f"{fr['entries']} entries, schema errors {len(fr['schema_errors'])}, a restart would restore {fr['restorable']} "
              f"(rejected {fr['rejected']}); blocks counter {fr['blocks']}, top peer share {fr['top_share']}",
              entries=fr['entries'], restorable=fr['restorable'])
    else:
        check('first-relay', None, 'no first_relay.json (written by r17+ every 5 minutes)')
    v2p = D / 'v2_offences.json'
    if v2p.exists():
        v2 = v2_offences_check(json.loads(v2p.read_text()), int(v2p.stat().st_mtime), go_const(pen_src, 'V2_FORGET'),
                               go_json_fields(pen_src, 'v2_record'))
        check('v2-offences', not v2['schema_errors'],
              f"{v2['entries']} entr(ies), schema errors {len(v2['schema_errors'])}, kept on reload {v2['kept']}",
              entries=v2['entries'])
    else:
        check('v2-offences', None, 'no v2_offences.json')

    # ---- what else is in the data directory
    arch = []
    for p in sorted(Path(a.datadir).iterdir()):
        if p.name in ('mainnet', '.DS_Store'):
            continue
        size = p.stat().st_size if p.is_file() else sum(f.stat().st_size for f in p.rglob('*') if f.is_file())
        arch.append({'name': p.name, 'bytes': size, 'modified': datetime.datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec='seconds')})
    check('archives', None, ', '.join(f"{x['name']} {x['bytes'] / 1e9:.2f} GB" for x in arch), items=arch)

    fails = [x for x in checks if x['result'] == 'FAIL']
    report = {'captured': datetime.datetime.now().astimezone().isoformat(timespec='seconds'), 'datadir': str(D),
              'constants': C, 'checks': checks, 'ok': not fails,
              'facts': [f"datadir {x['check']} {x['result']}: {x['what']}" for x in checks]}
    out = HARNESS / f"runtime/datadir_{datetime.datetime.now().strftime('%Y%m%dT%H%M%S')}.json"
    write_atomic(out, json.dumps(report, indent=1, ensure_ascii=False))   # verbatim UTF-8; R22: atomic
    for x in checks:
        print(f"  {x['result']:4s} {x['check']:22s} {x['what']}")
    print(f"datadir_intel: {'OK' if not fails else 'FAIL'} · {len(checks)} checks · wrote {out.relative_to(ROOT)}")
    return 0 if not fails else 6


if __name__ == '__main__':
    sys.exit(main())
