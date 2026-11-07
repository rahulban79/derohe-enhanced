#!/usr/bin/env python3
"""b36_payee_read.py — the B36 24 h payee read, as one reproducible command (dero-rft §7 B36; R28 glue-global).

B36's acceptance (rft §8 R28 carry, glue-global): "checkpoint payees = GetEmissionAudit payees at the same segment end".
Since r27 the live auditor writes a v2 checkpoint (payees, payees_verified, payees_explained) into the emission series
each time its segment top crosses a multiple of the interval (glue/emission/series.go), and DERO.GetEmissionAudit
answers the same three counts for the segment as it stands now. The two are only comparable when the RPC's segment_to
IS a checkpoint height of the same segment (segment_from equal); between checkpoints the RPC counts can only be >= the
last checkpoint's. Before R28 each round compared them by hand from a GetEmissionAudit read and a `tail` of the series.

What it does, read-only:
  * one DERO.GetEmissionAudit on 127.0.0.1:10102 (POST /json_rpc, Content-Type: application/json, no params: B38, lesson
    #78), repeated every --poll seconds up to --wait seconds until segment_to equals a checkpoint height of the series;
  * reads the series FILE given by --series (the live file or a copy; nothing is written to it, its directory, or the
    node); every line '<json> <crc32 8 hex>' is checked and a torn/bad line is dropped and counted; records without
    v >= 2 (written before r27) carry no payees and are never read as 0;
  * verdict per the rules below; --out FILE writes the record (the series file is named by its basename only).

Verdict (compare(); pure):
  EQUAL      a v2 checkpoint of the RPC's segment at height == segment_to: payees, payees_verified, payees_explained equal
  MISMATCH   that checkpoint exists and a count differs (a B36 failure: the series and the live auditor disagree)
  BOUND      no checkpoint at segment_to yet: the RPC counts are >= the newest checkpoint's (equality pending)
  BAD        a checkpoint whose verified/explained exceed its payees, counts that decrease along the segment, an RPC
             count below the newest checkpoint's, or a segment with alerts
  PENDING    no v2 checkpoint for the RPC's segment (pre-r27 records, a new segment, or an empty series)
  span_24h   the newest checkpoint's time - seg_start >= 86,400 s (the 24 h part of B36); 'pending' otherwise
B36 is CONFIRMED by this read only when the verdict is EQUAL and span_24h is true and alerts are 0.

  python3 -I harness/intel/b36_payee_read.py --series FILE [--wait 2400] [--poll 3] [--out FILE] [--rpc URL]
  exit 0 EQUAL (or BOUND/PENDING when --wait 0) · 3 MISMATCH or BAD · 4 no equality within --wait · 2 usage / RPC error
"""
import argparse, json, sys, time, urllib.request, zlib
from pathlib import Path

RPC = 'http://127.0.0.1:10102/json_rpc'
DAY = 86400
FIELDS = ('payees', 'payees_verified', 'payees_explained')


def parse_series(text):
    """(records, dropped): every line '<json> <crc32 8 hex>' whose checksum matches; a torn or bad line is dropped"""
    out, dropped = [], 0
    for line in text.splitlines():
        if not line.strip():
            continue
        body, _, crc = line.rpartition(' ')
        try:
            ok = len(crc) == 8 and int(crc, 16) == zlib.crc32(body.encode()) & 0xffffffff
            rec = json.loads(body) if ok else None
        except ValueError:
            ok, rec = False, None
        if ok and isinstance(rec, dict):
            out.append(rec)
        else:
            dropped += 1
    return out, dropped


def checkpoints(records, segment_from):
    """the v2 (payee-carrying) checkpoints of one segment, by height"""
    cps = [r for r in records if r.get('kind') == 'checkpoint' and int(r.get('v') or 0) >= 2
           and r.get('segment_from') == segment_from]
    return sorted(cps, key=lambda r: r.get('height', 0))


def compare(rpc, records):
    """the verdict dict for one GetEmissionAudit answer and the parsed series. Pure."""
    seg_from, seg_to = rpc.get('segment_from'), rpc.get('segment_to')
    cps = checkpoints(records, seg_from)
    res = {'segment_from': seg_from, 'segment_to': seg_to, 'rpc': {k: rpc.get(k) for k in FIELDS},
           'rpc_alerts': rpc.get('alerts'), 'checkpoints': len(cps), 'problems': []}
    if not cps:
        res.update(verdict='PENDING', span_24h='pending', why='no v2 checkpoint for this segment')
        return res
    last = cps[-1]
    span = int(last.get('time', 0)) - int(last.get('seg_start', 0))
    res['span_s'] = span
    res['span_24h'] = span >= DAY
    res['newest_checkpoint'] = {'height': last.get('height'), **{k: last.get(k) for k in FIELDS}}
    prev = None
    for c in cps:
        if c.get('payees_verified', 0) > c.get('payees', 0) or c.get('payees_explained', 0) > c.get('payees', 0):
            res['problems'].append(f"checkpoint {c.get('height')}: verified/explained above payees")
        if prev and any(c.get(k, 0) < prev.get(k, 0) for k in FIELDS):
            res['problems'].append(f"checkpoint {c.get('height')}: a count decreased after {prev.get('height')}")
        if c.get('alerts', 0):
            res['problems'].append(f"checkpoint {c.get('height')}: {c.get('alerts')} alerts")
        prev = c
    if rpc.get('alerts', 0):
        res['problems'].append(f"GetEmissionAudit alerts {rpc.get('alerts')}")
    at = next((c for c in cps if c.get('height') == seg_to), None)
    if at is not None:
        res['at_checkpoint'] = at.get('height')
        diff = {k: (rpc.get(k), at.get(k)) for k in FIELDS if rpc.get(k) != at.get(k)}
        res['verdict'] = 'MISMATCH' if diff else ('BAD' if res['problems'] else 'EQUAL')
        if diff:
            res['problems'].append(f'counts differ at {seg_to}: {diff}')
        return res
    if any(rpc.get(k, 0) < last.get(k, 0) for k in FIELDS) or (seg_to or 0) < last.get('height', 0):
        res['problems'].append('the RPC segment is behind its newest checkpoint')
    res['verdict'] = 'BAD' if res['problems'] else 'BOUND'
    return res


def confirmed(res):
    return res.get('verdict') == 'EQUAL' and res.get('span_24h') is True and not res.get('rpc_alerts')


def rpc_call(method, url=RPC, timeout=15):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method}).encode()
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        ans = json.loads(r.read())
    if 'error' in ans:
        raise RuntimeError(f"{method}: {ans['error']}")
    return ans['result']


def render(res, series_name, dropped, at):
    lines = [f'# B36 payee read (harness/intel/b36_payee_read.py), {at}: GetEmissionAudit (read-only, 127.0.0.1:10102) vs '
             f'the emission series {series_name} ({dropped} bad/torn line(s) dropped)',
             json.dumps(res, sort_keys=True),
             f"verdict {res['verdict']} · span_24h {res.get('span_24h')} · B36 24 h payee read "
             f"{'CONFIRMED' if confirmed(res) else 'not confirmed by this read'}"]
    return '\n'.join(lines) + '\n'


def main(argv):
    ap = argparse.ArgumentParser(description='B36: GetEmissionAudit payees vs the emission series checkpoints (read-only)')
    ap.add_argument('--series', required=True, help='the emission series file (live or a copy); read only')
    ap.add_argument('--wait', type=float, default=0.0, help='seconds to poll for segment_to == a checkpoint height')
    ap.add_argument('--poll', type=float, default=3.0)
    ap.add_argument('--out', help='write the record here')
    ap.add_argument('--rpc', default=RPC)
    a = ap.parse_args(argv)
    if a.poll <= 0 or a.wait < 0:
        print('--poll must be > 0 and --wait >= 0', file=sys.stderr)
        return 2
    deadline = time.monotonic() + a.wait
    while True:
        try:
            rpc = rpc_call('DERO.GetEmissionAudit', a.rpc)
            records, dropped = parse_series(Path(a.series).read_text(encoding='utf-8', errors='replace'))
        except (OSError, ValueError, RuntimeError) as e:
            print(f'read failed: {e}', file=sys.stderr)
            return 2
        res = compare(rpc, records)
        if res['verdict'] != 'BOUND' or time.monotonic() >= deadline:
            break
        time.sleep(a.poll)
    text = render(res, Path(a.series).name, dropped, time.strftime('%Y-%m-%d %H:%M:%S %z'))
    sys.stdout.write(text)
    if a.out:
        Path(a.out).write_text(text, encoding='utf-8')
    if res['verdict'] in ('MISMATCH', 'BAD'):
        return 3
    if a.wait > 0 and res['verdict'] != 'EQUAL':
        return 4
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
