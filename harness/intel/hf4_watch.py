#!/usr/bin/env python3
"""hf4_watch.py — r30 (rft §7 B184): the standing HF4 fork watch as a tool with an ESTIMATE date and an escalation rule.

DEROFDN `community-dev` (058889ca) carries an unreleased version-4 hard-fork row at MAJOR_HF4_HEIGHT 8,000,000
("not yet decided"). This tree's version table has no such row, so a release that ships it splits the chain from
ours at that height (rft B184). Until R29 the watch was a hand-run `git ls-remote` and a hand-written JSON record;
the r30 audit (b184-hf4-no-deadline) asked for a deadline and a rule for when to tell the user.

  * refs: `git ls-remote --heads --tags <repo>` (read-only network, no fetch, no clone write), compared with the
    baseline (the previous watch record): unchanged / moved / new / gone per ref;
  * ESTIMATE date: (MAJOR_HF4_HEIGHT - tip) x 18.52 s (the healthy node's s/block, memory `dero-network-changes`)
    from now; the tip is read read-only from DERO.GetInfo on 127.0.0.1:10102, or given with --tip;
  * escalation (exit 5, "REPORT TO THE USER"): (a) a release tag or `main`/`community-mainnet` is KNOWN to carry
    MAJOR_HF4_HEIGHT (--carriers names refs whose config was read to carry it; content is never fetched by this tool),
    (b) fewer than ESCALATE_BLOCKS (30,000, ~6.4 days) blocks remain, or (c) a tag name was added or removed (a set
    difference against the baseline's tags_all, r30 fix D1), a tag was re-pointed, or a watched head moved: its
    content is unknown until read, so the user is told to look (CHECK). Otherwise exit 0 (UNCHANGED).

  python3 -I harness/intel/hf4_watch.py [--baseline harness/runtime/r29_b184_watch_20261108.json] [--tip N]
                                        [--carriers REF ...] [--out harness/runtime/r30_b184_watch_<date>.json]
  python3 -I harness/intel/hf4_watch.py --help
Exit 0 unchanged · 4 CHECK (a ref changed: report it, read its config) · 5 ESCALATE (report to the user) · 2 no refs or bad input.
"""
import argparse, datetime, json, re, subprocess, sys, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
REPO = 'https://github.com/DEROFDN/derohe.git'
HF4_HEIGHT = 8_000_000            # community-dev config/config.go MAJOR_HF4_HEIGHT ("not yet decided", rft B184)
SECONDS_PER_BLOCK = 18.52         # healthy node, memory dero-network-changes (r30 start: averageblocktime50 18.5773)
ESCALATE_BLOCKS = 30_000          # ~6.4 days at 18.52 s: time for the user to decide before a split
WATCHED_HEADS = ('main', 'community-mainnet', 'community-testnet', 'community-dev')
RELEASE_RX = re.compile(r'^Release\d+$')
RPC = 'http://127.0.0.1:10102/json_rpc'


def parse_ls_remote(text):
    """({head: sha}, {tag: sha}) of `git ls-remote --heads --tags` output; a peeled tag (^{}) wins over the tag
    object. Pure."""
    heads, tags = {}, {}
    for line in (text or '').splitlines():
        parts = line.split('\t')
        if len(parts) != 2 or not re.match(r'^[0-9a-f]{40}$', parts[0]):
            continue
        sha, ref = parts
        if ref.startswith('refs/heads/'):
            heads[ref[len('refs/heads/'):]] = sha
        elif ref.startswith('refs/tags/'):
            name = ref[len('refs/tags/'):]
            if name.endswith('^{}'):
                tags[name[:-3]] = sha
            else:
                tags.setdefault(name, sha)
    return heads, tags


def baseline_refs(doc):
    """({head: sha}, tag count, {tag: sha prefix}) of a previous watch record (r29 hand format or this tool's). Pure."""
    heads = {}
    for k, v in (doc.get('heads') or {}).items():
        m = re.match(r'^([0-9a-f]{7,40})', str(v))
        if m:
            heads[k] = m.group(1)
    tags = doc.get('tags_all') or doc.get('newest_tags') or {}
    n = doc.get('tags') if isinstance(doc.get('tags'), int) else len(doc.get('tags_all') or {})
    return heads, n, {k: str(v)[:8] for k, v in tags.items()}


def estimate(tip, now=None, height=HF4_HEIGHT, spb=SECONDS_PER_BLOCK):
    """{'blocks_left', 'seconds', 'eta'} of the HF4 height from `tip` (an ESTIMATE: the mean block time varies). Pure
    given `now`."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    left = height - int(tip)
    secs = left * spb
    return {'tip': int(tip), 'hf4_height': height, 'blocks_left': left, 'seconds_per_block': spb, 'seconds': round(secs),
            'days': round(secs / 86400, 1), 'eta_utc': (now + datetime.timedelta(seconds=secs)).strftime('%Y-%m-%dT%H:%MZ'),
            'label': 'ESTIMATE'}


def judge(heads, tags, base_heads, base_tag_count, base_tags, est, carriers=()):
    """(verdict, reasons): 'ESCALATE' when a rule fires, 'CHECK' when a ref changed (content unknown), else 'UNCHANGED'.
    Pure."""
    reasons, check = [], []
    for c in carriers or ():
        if RELEASE_RX.match(c) or c in ('main', 'community-mainnet'):
            reasons.append(f'{c} carries MAJOR_HF4_HEIGHT (a release or main): adopting it is the user\'s decision')
    if est and est['blocks_left'] < ESCALATE_BLOCKS:
        reasons.append(f"{est['blocks_left']:,} blocks to {est['hf4_height']:,} (< {ESCALATE_BLOCKS:,}; {est['days']} days, ESTIMATE)")
    for h in WATCHED_HEADS:
        b, cur = base_heads.get(h), heads.get(h)
        if b and cur and not cur.startswith(b):
            check.append(f'head {h} moved {b[:8]} -> {cur[:8]}')
        elif b and not cur:
            check.append(f'head {h} gone')
        elif cur and not b:
            check.append(f'head {h} new at {cur[:8]}')
    # r30 fix D1: names, not the count. A removed + added pair keeps the count and read UNCHANGED; with the baseline's
    # full name list (tags_all: its names number its count) every added or removed name is a CHECK.
    complete = base_tag_count is None or len(base_tags) == base_tag_count
    if complete:
        added = sorted(set(tags) - set(base_tags))
        removed = sorted(set(base_tags) - set(tags))
        if added or removed:
            check.append(f'tags {len(base_tags)} -> {len(tags)}: added {added}, removed {removed}')
    else:                       # a partial baseline (the r29 hand record lists only its newest tags): count + names it has
        new_rel = sorted(t for t in tags if RELEASE_RX.match(t) and t not in base_tags and len(tags) > base_tag_count)
        if len(tags) != base_tag_count:
            check.append(f'tags {base_tag_count} -> {len(tags)}' + (f' (new releases {new_rel})' if new_rel else '')
                         + ' (partial baseline: names not compared)')
        gone = sorted(t for t in base_tags if t not in tags)
        if gone:
            check.append(f'tags removed {gone}')
    for t, sha in base_tags.items():
        if t in tags and not tags[t].startswith(sha):
            check.append(f'tag {t} re-pointed {sha} -> {tags[t][:8]}')
    if reasons:
        return 'ESCALATE', reasons + check
    if check:
        return 'CHECK', check
    return 'UNCHANGED', []


def newest_releases(tags, n=3):
    rel = sorted((int(t[len('Release'):]), t) for t in tags if RELEASE_RX.match(t))
    return {t: tags[t][:8] for _, t in rel[-n:]}


def read_tip(url=RPC, timeout=10):
    req = urllib.request.Request(url, data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'DERO.GetInfo'}).encode(),
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return int(json.loads(r.read())['result']['height'])


def newest_baseline(root=ROOT):
    c = sorted(Path(root).glob('harness/runtime/r*_b184_watch_*.json'), key=lambda p: p.name)
    return c[-1] if c else None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0], formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument('--baseline')
    ap.add_argument('--tip', type=int)
    ap.add_argument('--carriers', nargs='*', default=[], help='refs whose config was read to carry MAJOR_HF4_HEIGHT')
    ap.add_argument('--ls-remote-file', help='use a saved ls-remote output instead of the network (KAT, replay)')
    ap.add_argument('--out')
    ap.add_argument('--rpc', default=RPC)
    a = ap.parse_args(argv)
    if a.ls_remote_file:
        text = Path(a.ls_remote_file).read_text()
    else:
        r = subprocess.run(['git', 'ls-remote', '--heads', '--tags', REPO], capture_output=True, text=True, timeout=60)
        text = r.stdout if r.returncode == 0 else ''
    heads, tags = parse_ls_remote(text)
    if not heads:
        print('no refs read (network?)', file=sys.stderr)
        return 2
    bp = Path(a.baseline) if a.baseline else newest_baseline()
    base = json.loads(bp.read_text()) if bp else {}
    bh, bn, bt = baseline_refs(base)
    tip = a.tip if a.tip is not None else read_tip(a.rpc)
    est = estimate(tip)
    verdict, reasons = judge(heads, tags, bh, bn, bt, est, a.carriers)
    rec = {'row': 'B184 (rft §7), standing HF4 fork watch', 'tool': 'harness/intel/hf4_watch.py',
           'when': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
           'method': f'git ls-remote --heads --tags {REPO} (read-only; no fetch, no clone write); tip from DERO.GetInfo (read-only)',
           'baseline': str(bp.relative_to(ROOT)) if bp and bp.is_absolute() and ROOT in bp.parents else (str(bp) if bp else None),
           'heads': {h: heads[h] for h in sorted(heads)}, 'tags': len(tags), 'newest_tags': newest_releases(tags),
           'tags_all': {t: tags[t][:8] for t in sorted(tags)}, 'estimate': est,
           'rule': f'ESCALATE (report to the user) when a release tag or main/community-mainnet carries MAJOR_HF4_HEIGHT, or fewer than {ESCALATE_BLOCKS:,} blocks remain; CHECK when a watched head moved or a tag was added/re-pointed (read its config before saying more)',
           'result': verdict, 'reasons': reasons}
    if a.out:
        Path(a.out).write_text(json.dumps(rec, indent=1) + '\n')
    print(f"hf4_watch: {verdict}; heads {len(heads)} tags {len(tags)} newest {rec['newest_tags']}; HF4 {est['hf4_height']:,} - tip {tip:,} = "
          f"{est['blocks_left']:,} blocks x {SECONDS_PER_BLOCK} s = {est['days']} days -> {est['eta_utc']} (ESTIMATE)")
    for x in reasons:
        print('  ' + x)
    if verdict == 'ESCALATE':
        print('REPORT TO THE USER: ' + '; '.join(reasons))
    if verdict == 'CHECK':
        print('REPORT TO THE USER (a watched ref changed; read its config/config.go before saying more): ' + '; '.join(reasons))
    return {'ESCALATE': 5, 'CHECK': 4}.get(verdict, 0)


if __name__ == '__main__':
    sys.exit(main())
