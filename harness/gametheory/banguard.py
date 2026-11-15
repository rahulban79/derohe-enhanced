#!/usr/bin/env python3
"""banguard.py — r32 (artifacts/dero-game-theory-rft.md D-GT-2): the user's own wallet address may never be used by a
game-theory miner, smart contract, wallet or playbook, and is never written anywhere.

The private file ~/derohe-persist/gt-private/banned_addresses.json (mode 600, never in the repo) holds only the sha256
of each banned address string. This module compares candidates by hash; it never prints, logs or returns an address.

  python3 -I harness/gametheory/banguard.py check ADDRESS...   exit 0 all allowed · 6 a banned address (not echoed)
  python3 -I harness/gametheory/banguard.py scan FILE...       exit 0 no banned address in the files · 6 found (file:line)
  python3 -I harness/gametheory/banguard.py status             the private file is present, its hash count (no hashes)
Environment GT_BANNED_FILE overrides the private file (the KATs use a temporary one).
"""
import hashlib, json, os, re, sys
from pathlib import Path

DEFAULT_FILE = Path.home() / 'derohe-persist' / 'gt-private' / 'banned_addresses.json'
ADDR_RE = re.compile(r'\b(?:dero|deto)(?:1|i)[0-9a-z]{50,}\b')


def banned_file():
    return Path(os.environ.get('GT_BANNED_FILE') or DEFAULT_FILE)


def load_hashes(path=None):
    """The set of banned sha256 hex digests; an absent or unreadable file is an error (fail closed)."""
    p = Path(path) if path else banned_file()
    d = json.loads(p.read_text())
    hs = {h.lower() for h in d.get('banned_sha256', []) if re.fullmatch(r'[0-9a-f]{64}', str(h).lower())}
    if not hs:
        raise ValueError('the banned-address file holds no hash')
    return hs


def digest(addr):
    return hashlib.sha256(addr.strip().encode()).hexdigest()


def is_banned(addr, hashes=None):
    hs = hashes if hashes is not None else load_hashes()
    return digest(addr) in hs


class BannedAddress(Exception):
    """Raised with a message that never contains the address."""


def assert_allowed(addr, what='address', hashes=None):
    if is_banned(addr, hashes):
        raise BannedAddress(f'{what}: the address is on the private ban list (D-GT-2); refused')
    return True


def scan_text(text, hashes=None):
    """Line numbers (1-based) of every banned address occurrence in text; the addresses are not returned."""
    hs = hashes if hashes is not None else load_hashes()
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        for m in ADDR_RE.finditer(line):
            if digest(m.group(0)) in hs:
                out.append(i)
    return out


def main(argv):
    if not argv or argv[0] in ('-h', '--help'):
        print(__doc__)
        return 0
    try:
        hs = load_hashes()
    except (OSError, ValueError) as e:
        print(f'banguard: the private ban list is unusable ({type(e).__name__}); fail closed')
        return 7
    cmd, rest = argv[0], argv[1:]
    if cmd == 'status':
        print(f'banguard: {len(hs)} banned hash(es) in the private file')
        return 0
    if cmd == 'check':
        bad = sum(1 for a in rest if digest(a) in hs)
        print(f'banguard: {len(rest)} checked, {bad} banned')
        return 6 if bad else 0
    if cmd == 'scan':
        found = []
        for f in rest:
            try:
                t = Path(f).read_text(errors='ignore')
            except OSError:
                continue
            found += [f'{f}:{n}' for n in scan_text(t, hs)]
        for x in found:
            print(f'banned address at {x}')
        print(f'banguard: {len(rest)} file(s) scanned, {len(found)} banned occurrence(s)')
        return 6 if found else 0
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
