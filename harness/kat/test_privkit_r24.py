#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the r24 privacy kit (harness/kit/privkit.py) and its two users outside the
observatories: miners/minelib.emit (every raw file pseudonymised) and the private-capture pruning of
intel/consensus_intel.py and intel/peer_intel.py.

  PK1 pseudonymise_obj: a LAN/peer address in a string value, in a dict key and in a logger name
      ('P2P.outgoing.<ip>:11011') becomes 'peer-' + 8 hex, the SAME pseudonym peer_intel.Pseud.peer gives it; reserved
      addresses (127.0.0.1, 0.0.0.0, RFC 5737/2544, 240/4) and values under 'file' are kept; another salt, another name
  PK2 minelib.emit in a temp tree writes a raw file with no address; the pseudonymised quote still resolves on the raw
      line it was taken from through mask(), and a quote of other text does not
  PK3 page_ip_leaks: an address before a full stop, after 'outgoing.' and with a port is found; a version string
      (a four-part version after 'v'), a pseudonym and reserved addresses are not
  PK4 prune_private: 12 runs, keep 5 → the newest 5 stay; a 3-run byte cap → 3 stay; the newest run stays even when it
      alone exceeds the cap; names that are not runs are never touched; every dir 0700, every file 0600

Synthetic inputs only (RFC 1918 10.x addresses stand in for a peer; temp dirs; a fixed test salt); no real file is
read or written.
  python3 -I harness/kat/test_privkit_r24.py   # exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught
A mutation that crashes the KAT is INVALID, not caught.
"""
import hashlib, importlib.util, json, os, shutil, stat, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
FILES = ('kit/privkit.py', 'miners/minelib.py')
SALT = 'k' * 64
LAN = '10.20.30.40'


def load(base):
    sp = importlib.util.spec_from_file_location(f'privkit_kat_{id(base)}_{os.urandom(4).hex()}', base / 'kit/privkit.py')
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


def want(ip, salt=SALT):
    """peer_intel.Pseud(salt).peer(ip), written out independently."""
    return 'peer-' + hashlib.blake2b(f'{salt}|ip|{ip}'.encode(), digest_size=16).hexdigest()[:8]


def pk1(base):
    K = load(base)
    doc = {'title': f'P2P.outgoing.{LAN}:11011 - Call failed GetObject', LAN: 1,
           'evidence': [{'file': f'harness/runtime/x_{LAN}.log', 'quote': f'peer {LAN} sent'}],
           'keep': '127.0.0.1 0.0.0.0 198.51.100.7 203.0.113.9 192.0.2.4 198.18.0.5 240.0.0.1'}
    o = K.pseudonymise_obj(doc, SALT)
    o2 = K.pseudonymise_obj(doc, 'z' * 64)
    p = want(LAN)
    ok = (o['title'] == f'P2P.outgoing.{p}:11011 - Call failed GetObject' and p in o and LAN not in json.dumps({k: v for k, v in o.items() if k != 'evidence'})
          and o['evidence'][0]['quote'] == f'peer {p} sent' and o['evidence'][0]['file'] == f'harness/runtime/x_{LAN}.log'
          and o['keep'] == doc['keep'] and want(LAN, 'z' * 64) in o2['title'] and o2['title'] != o['title'])
    return ok, f"title {o['title'][:60]} · keep {o['keep'] == doc['keep']} · other salt differs {o2['title'] != o['title']}"


def pk2(base):
    t = Path(tempfile.mkdtemp(prefix='r24pk-'))
    try:
        for f in FILES:
            (t / 'harness' / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(base / f, t / 'harness' / f)
        priv = t / 'priv'
        priv.mkdir()
        (priv / 'salt').write_text(SALT + '\n')
        log = t / 'harness/runtime/console.log'
        log.parent.mkdir(parents=True)
        line = f'07:15:37 ERROR P2P.outgoing.{LAN}:11011 Call failed GetObject'
        log.write_text('header line of the console\n' + line + '\n')
        code = ('import sys; sys.path.insert(0, sys.argv[1]); import minelib as M; '
                "a = M.anchor('harness/runtime/console.log', 'Call failed GetObject', full_line=True); "
                "M.emit('triage', [{'id': 'r1', 'title': a['quote'][:40], 'evidence': [a]}], [], 'kat')")
        env = {**os.environ, 'DERO_PEER_PRIVATE': str(priv)}
        r = subprocess.run([sys.executable, '-c', code, str(t / 'harness/miners')], capture_output=True, text=True, cwd=t, env=env, timeout=60)
        if r.returncode:
            raise RuntimeError(r.stderr[-300:])
        raw = (t / 'harness/model/raw/triage.json').read_text()
        K = load(base)
        q = json.loads(raw)['rows'][0]['evidence'][0]['quote']
        resolves = K.mask(q) in K.mask(line) and q not in line
        other = K.mask(q.replace('GetObject', 'GetBlock')) in K.mask(line)
        ok = LAN not in raw and want(LAN) in raw and resolves and not other and not K.page_ip_leaks(raw)
        return ok, f'address in raw {LAN in raw} · pseudonym {want(LAN) in raw} · masked quote resolves {resolves} · other text resolves {other}'
    finally:
        shutil.rmtree(t, ignore_errors=True)


def pk3(base):
    K = load(base)
    a = K.page_ip_leaks(f'seen {LAN}. then P2P.outgoing.10.1.2.3:11011 and <td>172.16.5.9</td>')
    ver = 'v' + '.'.join(('3', '6', '0', '153'))      # a version after 'v' (built here so export scanners do not read an address)
    b = K.page_ip_leaks(ver + ' peer-0a1b2c3d 127.0.0.1 198.51.100.7:11011 0.0.0.0 192.0.2.1')
    ok = a == sorted([LAN, '10.1.2.3', '172.16.5.9']) and b == []
    return ok, f'found {a} · false positives {b}'


def pk4(base):
    K = load(base)
    t = Path(tempfile.mkdtemp(prefix='r24pkp-'))
    try:
        def mk(d, n, size):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o755)
            for i in range(n):
                p = d / f'consensus_raw_20261103T0{i:02d}000Z.json'
                p.write_bytes(b'x' * size)
                os.chmod(p, 0o644)
            (d / 'notes.txt').write_text('not a run')
        a, b, c = t / 'a', t / 'b', t / 'c'
        pat = r'^consensus_raw_\d{8}T\d{6}Z\.json$'
        mk(a, 12, 100)
        ka, ra = K.prune_private(a, keep=5, max_bytes=10 ** 9, pattern=pat)
        mk(b, 12, 100)
        kb, rb = K.prune_private(b, keep=50, max_bytes=300, pattern=pat)
        mk(c, 3, 1000)
        kc, rc = K.prune_private(c, keep=5, max_bytes=10, pattern=pat)
        newest5 = sorted(p.name for p in a.iterdir() if p.name.startswith('consensus_raw_'))
        modes = all(stat.S_IMODE(p.stat().st_mode) == (0o700 if p.is_dir() else 0o600) for p in [a, *a.iterdir()])
        ok = (newest5 == [f'consensus_raw_20261103T0{i:02d}000Z.json' for i in range(7, 12)] and len(kb) == 3 and len(rb) == 9
              and kc == ['consensus_raw_20261103T002000Z.json'] and (a / 'notes.txt').exists() and modes)
        return ok, f'keep5 {newest5[:1]}..{len(newest5)} · cap kept {len(kb)} · oversize newest kept {kc} · modes 700/600 {modes}'
    finally:
        shutil.rmtree(t, ignore_errors=True)


KATS = [('PK1', pk1), ('PK2', pk2), ('PK3', pk3), ('PK4', pk4)]
PK, ML = 'kit/privkit.py', 'miners/minelib.py'
MUTATIONS = [
    ('PK1', PK, "    return 'peer-' + hashlib.blake2b(f'{salt}|ip|{ip}'.encode(), digest_size=16).hexdigest()[:8]",
     "    return 'peer-' + hashlib.blake2b(f'ip|{ip}'.encode(), digest_size=16).hexdigest()[:8]", 'the salt is ignored (pseudonyms are dictionary-reversible)'),
    ('PK1', PK, "        return {(pseudonymise_text(k, salt) if isinstance(k, str) else k):", "        return {k:", 'a dict key keeps the address'),
    ('PK1', PK, "    return x.is_loopback or x.is_unspecified or any(x in n for n in TEST_NETS)", "    return x.is_loopback or x.is_unspecified or x.is_private",
     'a LAN address counts as reserved'),
    ('PK2', ML, '    rows = privkit.pseudonymise_obj(rows, salt)\n', '', 'emit writes the raw rows unpseudonymised'),
    ('PK2', PK, '    return PSEUDO.sub(TOKEN, s)', '    return s', 'a pseudonymised quote no longer resolves on its raw line'),
    ('PK3', PK, "(?<![\\w])(?<!\\d\\.)", "(?<![\\w.])", "an address after 'outgoing.' is not seen"),
    ('PK3', PK, "(?![\\w]|\\.\\d)')", "(?![\\w.])')", 'an address before a full stop is not seen'),
    ('PK4', PK, "        if i == 0 or (len(kept) < keep and total + sz <= max_bytes):", "        if len(kept) < keep and total + sz <= max_bytes:",
     'the newest run is deleted when it alone exceeds the cap'),
    ('PK4', PK, "        if i == 0 or (len(kept) < keep and total + sz <= max_bytes):", "        if i == 0 or len(kept) < keep:", 'the byte cap is ignored'),
    ('PK4', PK, "                os.chmod(os.path.join(dp, f), 0o600)", "                pass", 'files keep their 0644 mode'),
    ('PK4', PK, "    runs = sorted((p for p in d.iterdir() if not p.name.startswith('.') and (rx is None or rx.search(p.name))),",
     "    runs = sorted((p for p in d.iterdir() if not p.name.startswith('.')),", 'a file that is not a run is pruned'),
]


def copy_base():
    d = Path(tempfile.mkdtemp(prefix='r24pkm-'))
    for f in FILES:
        (d / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HARNESS / f, d / f)
    return d


def main():
    fails = 0
    base = copy_base()
    for name, fn in KATS:
        try:
            ok, det_ = fn(base)
        except Exception as e:                                    # noqa: BLE001
            ok, det_ = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} {str(det_)[:300]}")
    shutil.rmtree(base, ignore_errors=True)
    missed, byname = 0, dict(KATS)
    for kat, f, find, repl, why in MUTATIONS:
        d = copy_base()
        p = d / f
        text = p.read_text()
        if text.count(find) != 1:
            print(f'  ??      {kat}: {why} — find text occurs {text.count(find)} times')
            missed += 1
            shutil.rmtree(d, ignore_errors=True)
            continue
        p.write_text(text.replace(find, repl))
        try:
            ok2, _ = byname[kat](d)
            verdict = 'MISSED ' if ok2 else 'proved '
        except Exception as e:                                     # noqa: BLE001 — a crash proves nothing: INVALID
            ok2, verdict = True, f'INVALID ({type(e).__name__})'
        print(f'  {verdict} {kat}: {why}')
        missed += ok2
        shutil.rmtree(d, ignore_errors=True)
    print(f'\nr24 privkit KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
