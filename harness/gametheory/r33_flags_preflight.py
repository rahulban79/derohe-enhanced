#!/usr/bin/env python3
"""R33 GT-B25 pre-flight on a PRIVATE chain: does derod accept a miniblock whose Flags field carries an 8-byte game tag (bytes 32..39: Flags + the first
nonce word), and does the tag survive into the block that a contract later verifies (GT-B24)?

  python3 -I harness/gametheory/r33_flags_preflight.py --out <dir> [--tag a1b2c3d4] [--blocks 6]

It builds gt-simulator and gt-dero-miner from this tree into <dir>/bin (the live gt bins under GT_HOME are not
touched), starts the simulator (--testnet --noautomine, loopback ports 47300/47302/47380, data dir <dir>/chain; never
under the mainnet data dir), mines to the simulator's genesis wallet with --game-tag, reads every new block with
DERO.GetBlock from the private RPC, decodes its miniblocks from the block bytes (the layout of block/block.go
serialize and block/miniblock.go Serialize), and checks: sha3-256(bytes) == block id, every non-final miniblock mined
by this miner carries Flags == tag. It stops only the processes it started. Writes <dir>/r33_flags_preflight.json.
Exit 0 PASS · 1 FAIL · 2 setup error. Never contacts mainnet ports (10100/10102/11011).
"""
import argparse, hashlib, json, os, re, signal, subprocess, sys, time, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PORTS = {'getwork': '127.0.0.1:47300', 'daemon': '127.0.0.1:47302', 'explorer': '127.0.0.1:47380'}
MAINNET_DATA = Path.home() / 'dero-data'


def rpc(method, params=None, timeout=10):
    body = {'jsonrpc': '2.0', 'id': 1, 'method': method}
    if params is not None:
        body['params'] = params
    req = urllib.request.Request(f"http://{PORTS['daemon']}/json_rpc", data=json.dumps(body).encode(),
                                 headers={'Content-Type': 'application/json'})
    d = json.load(urllib.request.urlopen(req, timeout=timeout))
    if 'error' in d:
        raise RuntimeError(f"{method}: {d['error']}")
    return d['result']


def miniblocks(blob, ntx):
    """the miniblocks of a serialized block, parsed from the end (tx hashes, tx count, miniblocks, their count)."""
    p = len(blob) - 32 * ntx - 1
    if blob[p] != ntx:
        raise ValueError(f'tx count byte {blob[p]} != {ntx}')
    # r33 KAT R33-7: a count byte can match by coincidence at a smaller m (real block 7,915,141); accept a layout only
    # when every parsed miniblock has version 1 and all share one height field (block/miniblock.go Serialize)
    for m in [10] + [k for k in range(1, 64) if k != 10]:
        q = p - 48 * m - 1
        if q > 0 and blob[q] == m:
            out, heights, okv = [], set(), True
            for i in range(m):
                mb = blob[q + 1 + 48 * i: q + 1 + 48 * (i + 1)]
                okv &= (mb[0] & 0x0f) == 1
                heights.add(int.from_bytes(mb[3:8], 'big'))
                out.append({'final': bool(mb[0] & 0x20), 'keyhash': mb[16:32].hex(), 'flags': mb[32:40].hex()})
            if okv and len(heights) == 1:
                return out
    raise ValueError('miniblock section not found')


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--tag', default='a1b2c3d4e5f60718')
    ap.add_argument('--blocks', type=int, default=6)
    a = ap.parse_args(argv)
    out = Path(a.out).resolve()
    if str(out).startswith(str(MAINNET_DATA)):
        print('refusing an output dir under the mainnet data dir'); return 2
    (out / 'bin').mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GOFLAGS='-mod=vendor')
    for name, pkg in (('gt-simulator', './cmd/simulator'), ('gt-dero-miner', './cmd/dero-miner')):
        r = subprocess.run(['nice', '-n', '15', 'go', 'build', '-o', str(out / 'bin' / name), pkg], cwd=ROOT, env=env,
                           capture_output=True, text=True)
        if r.returncode:
            print(f'build {name} failed: {r.stderr[-400:]}'); return 2
    procs = []
    res = {'tag': a.tag, 'ports': PORTS, 'blocks': [], 'verdict': 'FAIL'}
    try:
        chain = subprocess.Popen(['nice', '-n', '15', str(out / 'bin' / 'gt-simulator'), '--testnet', '--noautomine',
                                  f"--data-dir={out / 'chain'}", f"--rpc-bind={PORTS['daemon']}",
                                  f"--http-address={PORTS['explorer']}", f"--getwork-bind={PORTS['getwork']}"],
                                 cwd=out, stdout=open(out / 'chain.out', 'w'), stderr=subprocess.STDOUT, start_new_session=True)
        procs.append(chain)
        genesis = None
        for _ in range(240):
            txt = (out / 'chain.out').read_text(errors='ignore')
            m = re.search(r'genesis wallet.*?"address": "(deto1[0-9a-z]+)"', txt)
            if m:
                genesis = m.group(1)
                try:
                    rpc('DERO.GetInfo'); break
                except Exception:  # noqa: BLE001 — the RPC is still starting
                    pass
            time.sleep(0.5)
        if not genesis:
            print('the simulator did not start (no genesis wallet / RPC)'); return 2
        h0 = rpc('DERO.GetInfo')['height']
        miner = subprocess.Popen(['nice', '-n', '15', str(out / 'bin' / 'gt-dero-miner'), f'--wallet-address={genesis}',
                                  f"--daemon-rpc-address={PORTS['getwork']}", '--mining-threads=2', '--testnet',
                                  '--node-rpc-address=off', '--cpu-max=50', f'--game-tag={a.tag}'],
                                 cwd=out, stdout=open(out / 'miner.out', 'w'), stderr=subprocess.STDOUT, start_new_session=True)
        procs.append(miner)
        t0 = time.time()
        while rpc('DERO.GetInfo')['height'] < h0 + a.blocks + 1:
            if time.time() - t0 > 900:
                print('no blocks mined in 900 s'); break
            if miner.poll() is not None:
                print('the miner exited:', (out / 'miner.out').read_text(errors='ignore')[-400:]); break
            time.sleep(2)
        h1 = rpc('DERO.GetInfo')['height']
        tagged = untagged = finals = 0
        for h in range(h0 + 1, h1):
            b = rpc('DERO.GetBlock', {'height': h})
            blob = bytes.fromhex(b['blob'])
            ok_hash = hashlib.sha3_256(blob).hexdigest() == b['block_header']['hash']
            mbs = miniblocks(blob, b['block_header'].get('txcount', 0))
            row = {'height': h, 'hash_ok': ok_hash, 'miniblocks': len(mbs),
                   'flags': sorted({x['flags'] for x in mbs if not x['final']})}
            res['blocks'].append(row)
            for x in mbs:
                if x['final']:
                    finals += 1
                elif x['flags'] == a.tag:
                    tagged += 1
                else:
                    untagged += 1
        res.update(tagged=tagged, untagged=untagged, finals=finals, heights=[h0 + 1, h1 - 1])
        good = res['blocks'] and all(r['hash_ok'] for r in res['blocks']) and tagged > 0 and untagged == 0
        res['verdict'] = 'PASS' if good else 'FAIL'
        res['miner_tag_line'] = bool(re.search(r'game tag written', (out / 'miner.out').read_text(errors='ignore')))
    finally:
        for p in reversed(procs):
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGTERM)
                try:
                    p.wait(20)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGKILL)
        (out / 'r33_flags_preflight.json').write_text(json.dumps(res, indent=1))
    print(f"r33 flags preflight {res['verdict']}: blocks {len(res['blocks'])}, non-final miniblocks tagged "
          f"{res.get('tagged')}, untagged {res.get('untagged')}, final {res.get('finals')}")
    return 0 if res['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
