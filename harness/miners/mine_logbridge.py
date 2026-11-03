#!/usr/bin/env python3
"""mine_logbridge.py — every line the running daemon printed, joined to the Go line that printed it.

Three steps, all mechanical:
 1. mine the logger registry: `globals.Logger.WithName("X")` tells us which file owns the name derod prints,
    so the plausibility rule below is read out of the tree instead of being declared here;
 2. parse harness/runtime/*.log into (level, logger, message, kv) tuples;
 3. find the message as a Go string literal. A match COUNTS only when it sits in the package that owns that
    logger name (step 1). Anything else is recorded as a coincidence and is never drawn as a bridge.

Error strings travel in the kv payload rather than as the message, so `{"error": "..."}` is bridged too,
against `fmt.Errorf` / `errors.New` literals.
"""
import collections, json, re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import minelib as M

RUNTIME = M.HARNESS / 'runtime'
LINE = re.compile(r'^(\d\d/\d\d)\s+(\d\d:\d\d:\d\d)\s+(INFO|ERROR|WARN|DEBUG)\s+(\S+)\s+(.*?)\s*(\{.*\})?\s*$')
PKGS = [p for p in M.pkgindex()['packages']]


def logger_registry():
    """name -> [(file, line, quote)] from the WithName calls themselves."""
    reg = collections.defaultdict(list)
    for pkg in PKGS:
        for f in M.go_files(pkg):
            for ln, line in M.grep(f, r'WithName\("([^"]+)"\)'):
                for nm in re.findall(r'WithName\("([^"]+)"\)', line):
                    reg[nm].append((f, ln, line.strip()))
    return reg


def owner_pkgs(reg, name):
    """Which first-party packages may print under this logger name. Sub-loggers inherit the root's owner."""
    root = name.split('.')[0]
    out = {f.split('/')[0] if not f.startswith('cmd/') else f.rsplit('/', 1)[0] for f, _, _ in reg.get(root, [])}
    return out


def lit_hits(msg):
    """Every first-party Go line carrying this text as a string literal.

    Both sides go through minelib.norm first: the console and the source differ in typography (the KCP banner
    uses an em dash) and a transcription that normalises away is not a missing bridge.
    """
    needle = M.norm(msg.replace('\\n', ''))
    if len(needle) < M.MIN_Q:
        return []
    probe = '"' + needle
    out = []
    for pkg in PKGS:
        for f in M.go_files(pkg):
            raw, nl = M.lines(f)
            if nl is None:
                continue
            for i, nline in enumerate(nl):
                if probe in nline:
                    out.append((f, i + 1, raw[i].strip()))
    # the line may have been printed by an older binary whose source this tree has since changed;
    # harness/baseline/<ref>/ holds exact git copies of that source (verified by KAT DK27). Baseline
    # hits go after the tree's own, so a literal the tree still emits is bridged to the tree.
    for f in sorted((M.HARNESS / 'baseline').glob('*/**/*.go.base')):
        rel = str(f.relative_to(M.ROOT))
        raw, nl = M.lines(rel)
        for i, nline in enumerate(nl or []):
            if probe in nline:
                out.append((rel, i + 1, raw[i].strip()))
    return out


def main():
    reg = logger_registry()
    rows, unv = [], []
    coincidence = 0

    for nm, hits in sorted(reg.items()):
        f, ln, q = hits[0]
        rows.append({'id': f'logger-{nm.lower()}', 'section': 'loggers', 'title': nm, 'class': 'SRC',
                     'claim': f'The daemon prints under the logger name "{nm}", registered in {f}:{ln}'
                              + (f' ({len(hits)} registration sites).' if len(hits) > 1 else '.'),
                     'logger': nm, 'owner': f, 'evidence': [{'file': f, 'quote': q, 'line': ln}]})

    # Console captures overlap: a later paste usually repeats the start of the earlier one. Walk the newest first
    # and bridge each printed line once, so the same event is never counted twice.
    bridged = set()
    for log in sorted(RUNTIME.glob('*.log'), reverse=True):
        rel = str(log.relative_to(M.ROOT))
        raw, _ = M.lines(rel)
        for i, l in enumerate(raw or [], 1):
            m = LINE.match(l)
            if not m or l.strip() in bridged:
                continue
            bridged.add(l.strip())
            _, t, lvl, name, msg, kv = m.groups()
            msg = msg.strip()
            cands = []
            # the message itself, then any string value inside the kv payload (errors travel there)
            probes = [msg] + ([v for v in re.findall(r'"(?:error|errorVerbose)":\s*"([^"]{12,200})"', kv or '')] if kv else [])
            # A short message ("Min peers", "Initialized") cannot be a 12-char anchor on its own, but the Go call
            # site writes it next to its first structured key: logger.Info("Min peers", "min-peers", ...). That
            # pair is both long enough and far more specific than the message alone.
            if kv:
                k1 = re.match(r'\{\s*"([^"]+)"', kv)
                if k1:
                    probes.append(f'{msg}", "{k1.group(1)}')
            for probe in probes:
                probe = probe.split('\\n')[0].strip()
                for f, ln, q in lit_hits(probe):
                    src = re.sub(r'\.base$', '', re.sub(r'^harness/baseline/[^/]+/', '', f))   # a baseline copy owns what its original owned
                    top = src.split('/')[0] if not src.startswith('cmd/') else src.rsplit('/', 1)[0]
                    cands.append((f, ln, q, probe, top))
            if not cands:
                unv.append({'title': f'{name}: {msg[:70]}', 'why': 'no Go string literal carries this text',
                            'where': f'{rel}:{i}'})
                continue
            own = owner_pkgs(reg, name)
            good = [c for c in cands if not own or c[4] in own] or []
            coincidence += len(cands) - len(good)
            if not good:
                unv.append({'title': f'{name}: {msg[:70]}',
                            'why': f'literal found only outside the packages that own logger "{name}" '
                                   f'({sorted(own)}): {[c[0] for c in cands][:3]} — recorded as a coincidence',
                            'where': f'{rel}:{i}'})
                continue
            f, ln, q, probe, _ = good[0]
            retired = f.startswith('harness/baseline/')
            where = (f'{f}:{ln} — the source the running binary was built from; this tree no longer emits it there'
                     if retired else f'{f}:{ln}')
            rows.append({'id': f'log-{log.stem}-{i}', 'section': 'logbridge', 'title': f'{name} \u2014 {msg[:60]}',
                         'class': 'HARNESS', 'retired': retired,
                         'claim': f'At {t} the running daemon printed "{msg}" at level {lvl} '
                                  f'under logger {name}; the literal is emitted from {where}.',
                         't': t, 'level': lvl, 'logger': name, 'message': msg, 'emitter': f'{f}:{ln}',
                         'alternatives': len(good) - 1,
                         'evidence': [{'file': rel, 'quote': l.strip()[:200], 'line': i},
                                      {'file': f, 'quote': q, 'line': ln}]})
    print(f'  logger names: {len(reg)} · coincidences rejected: {coincidence}')
    M.emit('logbridge', rows, unv, 'mine_logbridge.py')


if __name__ == '__main__':
    main()
