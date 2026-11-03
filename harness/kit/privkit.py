#!/usr/bin/env python3
"""r24 privkit: the privacy rules shared by the consensus observatory and the miners that read the derod log.

Before r24 the console-error triage (miners/mine_triage.py), the log bridge (miners/mine_logbridge.py) and the node
intelligence rows (miners/mine_intel.py) copied the peer addresses they read from derod's console and log into
harness/model/raw/*.json, so dero-src-arch.html and harness/model/verified.json carried peer IPv4 literals (found by the
r24 consensus-network verifier). This module is the single place that decides what an address may look like in a
tracked output:

  pseudonymise_obj(doc, salt)   every non-reserved IPv4 in every string becomes 'peer-' + 8 hex of
                                blake2b(salt | 'ip' | address): the SAME pseudonym peer_intel.py gives that peer, so a
                                peer in the console triage and in the peer observatory reads the same (the salt is
                                ~/derohe-persist/peer_intel_private/salt, 0600, never in a repository)
  mask(text)                    a salt-free form for anchor matching: every non-reserved IPv4 and every peer-xxxxxxxx
                                pseudonym becomes one token, so a pseudonymised quote still resolves on the raw log
                                line it was taken from (gen_deroarch.resolve_ev / verify_deroarch fall back to it only
                                when the exact match fails)
  page_ip_leaks(text, allowed)  the IPv4 literals of a generated page that are neither reserved (loopback, unspecified,
                                RFC 5737/2544 test ranges, reserved 240/4) nor code literals of the tree (`code_literal_ips`: an
                                address written in a tracked .go file is quoted from source, not observed)
  prune_private(dir, ...)       the private raw captures: keep the newest N runs and at most max_bytes, every
                                directory 0700 and every file 0600 (the observatories call it after each capture)

Read-only on the repository; prune_private only deletes inside the private directory it is given.
"""
import hashlib, ipaddress, os, re, subprocess
from pathlib import Path

PEER_PRIVATE = Path(os.environ.get('DERO_PEER_PRIVATE') or (Path.home() / 'derohe-persist' / 'peer_intel_private'))
IPV4 = re.compile(r'(?<![\w])(?<!\d\.)((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?![\w]|\.\d)')
PSEUDO = re.compile(r'\bpeer-[0-9a-f]{8}\b')
TOKEN = '<peer>'
TEST_NETS = [ipaddress.ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '198.18.0.0/15',
                                                 '240.0.0.0/4')]   # 240/4: reserved (RFC 1112); export scanners treat 233.252/24 as global
SKIP_KEYS = ('file', 'abs', 'path', 'emitter', 'where')


def reserved(ip):
    """True for an address that names no host on the internet or LAN: loopback, unspecified, the documentation and
    benchmark ranges. A private-LAN address (192.168/16, 10/8, 172.16/12) is NOT reserved: it names the operator's LAN."""
    try:
        x = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return x.is_loopback or x.is_unspecified or any(x in n for n in TEST_NETS)


def load_salt(priv=None, create=True):
    """The peer observatory's salt (one per installation). create=False returns None when it is absent."""
    d = Path(priv or PEER_PRIVATE)
    f = d / 'salt'
    try:
        s = f.read_text().strip()
        if len(s) >= 32:
            return s
    except OSError:
        pass
    if not create:
        return None
    import secrets
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    s = secrets.token_hex(32)
    fd = os.open(str(f), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as fh:
        fh.write(s + '\n')
    return s


def pseudo_ip(ip, salt):
    """peer_intel.Pseud.peer for a bare address."""
    return 'peer-' + hashlib.blake2b(f'{salt}|ip|{ip}'.encode(), digest_size=16).hexdigest()[:8]


def pseudonymise_text(s, salt):
    return IPV4.sub(lambda m: m.group(1) if reserved(m.group(1)) else pseudo_ip(m.group(1), salt), s)


def pseudonymise_obj(o, salt, skip=SKIP_KEYS):
    """A copy of a JSON-like document with every non-reserved IPv4 in every string value (and dict key) pseudonymised;
    values under the keys in `skip` (paths) are kept."""
    if isinstance(o, str):
        return pseudonymise_text(o, salt)
    if isinstance(o, list):
        return [pseudonymise_obj(x, salt, skip) for x in o]
    if isinstance(o, dict):
        return {(pseudonymise_text(k, salt) if isinstance(k, str) else k):
                (v if k in skip else pseudonymise_obj(v, salt, skip)) for k, v in o.items()}
    return o


def mask(s):
    """salt-free matching form: every non-reserved IPv4 and every peer pseudonym -> one token."""
    s = IPV4.sub(lambda m: m.group(1) if reserved(m.group(1)) else TOKEN, str(s or ''))
    return PSEUDO.sub(TOKEN, s)


def ips_in(text):
    return [m.group(1) for m in IPV4.finditer(text)]


def code_literal_ips(root):
    """The IPv4 literals written in the tree's tracked .go files (seed nodes, test fixtures, comments): a page that
    quotes source code shows them as code, not as an observation of this node."""
    root = Path(root)
    try:
        fs = subprocess.run(['git', '-C', str(root), 'ls-files', '*.go'], capture_output=True, text=True, timeout=60).stdout.split()
    except (OSError, subprocess.SubprocessError):
        fs = []
    if not fs:
        fs = [str(p.relative_to(root)) for p in root.rglob('*.go') if 'vendor' not in p.parts]
    out = set()
    for f in fs:
        if f.startswith('vendor/'):
            continue
        try:
            out.update(ips_in((root / f).read_text(errors='replace')))
        except OSError:
            continue
    return out


def page_ip_leaks(text, allowed=()):
    """[address] of the IPv4 literals in `text` that are neither reserved nor in `allowed` (code literals)."""
    al = set(allowed)
    return sorted({ip for ip in ips_in(text) if not reserved(ip) and ip not in al})


def prune_private(d, keep=12, max_bytes=200 * 1024 * 1024, pattern=None):
    """Keep the newest `keep` runs (files or run directories directly under d, ordered by name = timestamp) and at most
    `max_bytes` in total (the newest run is always kept); chmod 0700 on every directory and 0600 on every file under d.
    Returns (kept, removed) lists of names. Only entries matching `pattern` (a regex on the name) are runs."""
    import shutil
    d = Path(d)
    if not d.is_dir():
        return [], []
    rx = re.compile(pattern) if pattern else None
    runs = sorted((p for p in d.iterdir() if not p.name.startswith('.') and (rx is None or rx.search(p.name))),
                  key=lambda p: p.name)

    def size(p):
        if p.is_file():
            return p.stat().st_size
        return sum(f.stat().st_size for f in p.rglob('*') if f.is_file())
    kept, removed, total = [], [], 0
    for i, p in enumerate(reversed(runs)):
        sz = size(p)
        if i == 0 or (len(kept) < keep and total + sz <= max_bytes):
            kept.append(p.name)
            total += sz
        else:
            (shutil.rmtree if p.is_dir() else os.remove)(p)
            removed.append(p.name)
    for dp, dn, fn in os.walk(d):
        os.chmod(dp, 0o700)
        for f in fn:
            try:
                os.chmod(os.path.join(dp, f), 0o600)
            except OSError:
                pass
    return kept, removed
