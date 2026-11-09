#!/usr/bin/env python3
"""mine_evolution.py — r23c: how the tree evolved from upstream Release152 to the current round, read from git.

Git is the ground truth; nothing here is typed. The miner walks `git log --numstat --no-renames <base>..HEAD`, assigns
every commit to a round by its subject, buckets every changed path into a subsystem and a module, and writes one
deterministic snapshot, harness/runtime/evolution_git.tsv (one line per commit, round, module and top file). Each row
it emits anchors on its own line of that snapshot (HARNESS: the owner's measured system) and, for a round, on the
heading of that round's section in ARCHITECTURE.md / RUN_REPORT.md, so a round the docs never wrote up says so.

THE BASE. The branch forks from upstream tag Release152 (1d3c4b7): it is `git merge-base HEAD Release153` (the
deroproject Release153 tag is not an ancestor, ARCHITECTURE §20.1 / §21 tag skew). The miner checks that identity at
run time and refuses to emit if it no longer holds.

THE ROUND RULE (shown in the page footer). A subject that starts with `Round N[x]`, `RN[x]` or `rN[x]` belongs to
round N[x]; the one commit that ports the Release142 enhancements is R1-R3 (those rounds ran on the Release142 tree,
outside this repository); any other commit belongs to the NEXT round-marked commit after it (fixes land before the
round's docs commit: da2fd6a/3c5ffbf are Round 4b, d28c5b7/9612278 Round 6). Rounds are grouped as the Enhancement
Ledger groups them (artifacts/src/gen_ledger.py): 4/4b/4c/4d -> R4, 6/6b -> R6, 9/9b/10 -> R9, 23b and 23c separate.
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import collections, re, subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import minelib as M

BASE_TAG = 'Release152'
SNAP = 'harness/runtime/evolution_git.tsv'
# the ledger's round axis, in order; R23c stays listed so a not-yet-committed round renders as pending, never as zero
ORDER = ['R1-3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9'] + [f'R{n}' for n in range(11, 24)] + ['R23b', 'R23c', 'R24']
ORDER += ['R25', 'R26', 'R27', 'R28', 'R28d', 'R29', 'R30']  # r30 listed at the R29 open (Part A, B149: the registry's next planned round r30); r28d listed at the R28d open (Part A, D1: the community-dev merge sub-round, between R28 and R29); r29 listed at the R28 open (Part A, B149: the registry's next planned round r29); r28 listed at the R27 open loop (tools-kats: HT11 FAILED at cee1d80f, the registry's next planned round r28 was missing); r27 listed at the R26 open loop (B90 early warning: before its first 'R27' commit); r26 listed at the R25 artifacts (B90: before its first 'R26' commit); r25 plan (2026-11-03): listed before its first 'R25 plan:' commit lands, so it renders as pending, never as zero (rft §6 step 13)
# r24 (pipeline run 1): ORDER ended at R23c, so the first 'R24 ...' commit crashed this miner with KeyError: 'R24' (S7 FAIL).
# A round that git names but ORDER does not list is now refused by name (unknown_rounds); harness/kat/
# test_evolution_order_r24.py checks every non-planned harness/round.json round and every commit since the base.
LABEL = {'R1-3': 'R1–R3', 'R9': 'R9 · R10'}
SUBSYSTEMS = ['dero-miner', 'gpu-miner-poc', 'p2p', 'derod + rpc', 'glue', 'blockchain', 'walletapi',
              'other first-party Go', 'tools', 'experiments', 'harness code', 'harness data', 'artifacts', 'docs', 'other']
CODE = {'dero-miner', 'gpu-miner-poc', 'p2p', 'derod + rpc', 'glue', 'blockchain', 'walletapi', 'other first-party Go',
        'tools', 'experiments', 'harness code'}
GO_SHIPPED = {'dero-miner', 'p2p', 'derod + rpc', 'glue', 'blockchain', 'walletapi', 'other first-party Go', 'tools'}
HARNESS_DATA = ('harness/runtime/', 'harness/model/', 'harness/loop/', 'harness/corpus/', 'harness/baseline/',
                'harness/external/')
TOP_FILES = 25
# the churn leaderboard ranks SOURCE files: captured json, stamps and other generated data under harness/ are not code
SOURCE_EXT = ('.go', '.c', '.h', '.s', '.py', '.swift', '.metal', '.sh', '.js', '.m', '.mm', '.cpp')
# where each round is written up: (ARCHITECTURE heading regex, RUN_REPORT heading regex). From R11 on both docs name the
# round in the heading, so the pattern is generated; before that the headings are topical and are listed by hand.
DOC = {'R1-3': (r'^## 18\. ', r'^# ROUND 3 '), 'R4': (r'^## 20\. ', r'^# ROUND 4 '), 'R5': (r'^## 21\. ', r'^## ROUND 5 '),
       'R6': (r'^## 22\. ', r'^## ROUND 6 '), 'R7': (r'^## 24\. ', r'^## ROUND 7 '), 'R8': (r'^## 25\. ', r'^## ROUND 8 '),
       'R9': (r'^## 26\. ', r'^## Round 9b / Round 10 ')}


def planned_keys(root=None):
    """r28 (tools-kats): the ledger keys ('r29' -> 'R29') that harness/round.json marks 'planned'. ORDER lists the next
    planned round early (B90) and its row renders as pending; until R28 the same round was ALSO counted as an item 'a
    miner could not anchor' (evolution.json unverified 1 at the R28 open: 'R29: no commit ... names this round yet'), so
    the page's unverified KPI mixed a planned round with a real anchoring gap. An empty set when the registry is
    unreadable (then every commit-less round stays unverified, the old behaviour)."""
    import json
    try:
        reg = json.loads((Path(root or M.ROOT) / 'harness/round.json').read_text())
    except (OSError, ValueError):
        return set()
    return {'R' + str(r.get('id', ''))[1:] for r in reg.get('rounds') or [] if r.get('status') == 'planned'}


def commitless_unverified(k, commits, planned):
    """the unverified entry of a round with no commit, or None: a round the registry still marks planned has nothing to
    anchor yet (its row says 'pending measurement'); any other commit-less round is a real gap. Pure."""
    if commits or k in planned:
        return None
    return {'title': f'{LABEL.get(k, k)}: no commit in {BASE_TAG}..HEAD names this round yet',
            'why': 'pending measurement: the round has not been committed, so git holds nothing to count; '
                   'the page shows it as pending, never as zero'}


def git(*a):
    return subprocess.run(['git', *a], cwd=M.ROOT, capture_output=True, text=True).stdout


def round_of(subject):
    """the round a subject NAMES, or None (then it belongs to the next one that does). Pure."""
    if subject.startswith('Port Release142 local enhancements'):
        return 'R1-3'
    m = re.match(r'(?:Round|R|r)\s?(\d+)([a-z]?)\b', subject)
    if not m:
        return None
    n, x = int(m.group(1)), m.group(2)
    if n in (4, 6) or n in (9, 10):
        return {4: 'R4', 6: 'R6', 9: 'R9', 10: 'R9'}[n]
    return f'R{n}{x}' if (n, x) in ((23, 'b'), (23, 'c'), (28, 'd')) else f'R{n}'   # r28d: the community-dev merge sub-round


def assign(commits):
    """[(sha, subject)] oldest first -> {sha: round}; unmarked commits take the next marked round ('pending' at the
    tail when no marked commit follows yet). Pure, so the KAT can feed it shapes."""
    out, pend = {}, []
    for sha, subj in commits:
        r = round_of(subj)
        pend.append(sha)
        if r:
            for s in pend:
                out[s] = r
            pend = []
    for s in pend:
        out[s] = 'pending'
    return out


def unknown_rounds(rnd):
    """{sha: round} -> the sorted rounds that ORDER does not list ('pending' is always known). Pure (r24)."""
    return sorted({r for r in rnd.values() if r != 'pending' and r not in ORDER})


def subsystem(p):
    """the subsystem column of the heatmap a changed path belongs to. Pure."""
    top = p.split('/')[0]
    if p.startswith('cmd/dero-miner/'):
        return 'dero-miner'
    if p.startswith('gpu-miner-poc/'):
        return 'gpu-miner-poc'
    if p.startswith('p2p/'):
        return 'p2p'
    if p.startswith(('cmd/derod/', 'rpc/')):
        return 'derod + rpc'
    if p.startswith('glue/'):
        return 'glue'
    if p.startswith('blockchain/'):
        return 'blockchain'
    if p.startswith(('walletapi/', 'cmd/dero-wallet-cli/')):
        return 'walletapi'
    if p.startswith('tools/'):
        return 'tools'
    if re.match(r'cmd/(_|r\d)', p):
        return 'experiments'
    if p.startswith(HARNESS_DATA):
        return 'harness data'
    if p.startswith('harness/'):
        return 'harness code'
    if p.startswith('artifacts/'):
        return 'artifacts'
    if top in M_SRC_PKGS and '/' in p:
        return 'other first-party Go'
    if p.endswith(('.md', '.svg', '.html')) or p.startswith(('.skills/', 'memory-mirror/')):
        return 'docs'
    return 'other'


def module(p):
    """the module (directory) a path is drawn under in the module map, or None for data/docs/loose files. Pure."""
    sub = subsystem(p)
    if sub in ('harness data', 'docs', 'other'):
        return None
    if sub == 'experiments':
        return 'cmd/_* experiments'
    parts = p.split('/')[:-1]
    if not parts:
        return None
    depth = 3 if parts[0] == 'cmd' else (1 if parts[0] in ('gpu-miner-poc', 'artifacts') else 2)
    return '/'.join(parts[:depth])


def doc_anchor(rel, rx):
    hits = M.grep(rel, rx)
    return ({'file': rel, 'quote': hits[0][1].strip(), 'line': hits[0][0]}, hits[0][1]) if hits else (None, '')


def doc_anchors(rnd):
    if rnd in DOC:
        ra, rr = DOC[rnd]
    else:
        n = rnd[1:]
        ra, rr = rf'^## \d+\. .*\bRound {n}\b', rf'^## Round {n} \('
    a, ah = doc_anchor('ARCHITECTURE.md', ra)
    b, _ = doc_anchor('RUN_REPORT.md', rr)
    sec = re.match(r'## (\d+[A-Z]?)\.\s*(.*)', ah.strip()) if ah else None
    what = re.sub(r'^[★\s]+', '', sec.group(2)) if sec else ''
    return [e for e in (a, b) if e], (f'§{sec.group(1)}' if sec else ''), what


def base_claim(tag, base, head, n, merges):
    """the evo-base row's claim; r29: it names the merge commits left out of the count. Pure."""
    return (f'The branch forks from upstream {tag} ({base[:7]}), which is merge-base(HEAD, Release153): '
            f'{n} local commits up to HEAD {head[:7]}'
            + (f', plus {merges} merge commit(s) joining dimension branches (not counted: a merge\'s lines are its '
               f'branch commits).' if merges else ', none of them merges.'))


def walk(git, base, head='HEAD'):
    """(commits, merges) of base..head. r29: the R29 merge joined the dimension branches with --no-ff merge commits;
    the walk counted those 8 too (294 vs `git log --no-merges` 286, verify_deroarch DK35) and the page still said
    "none of them merges". A merge's own diff is the lines of its branch's commits, already counted, so merges are
    left out of the partition and counted separately (KAT test_evolution_merges_r29.py)."""
    log = git('log', '--reverse', '--no-merges', '--no-renames', '--format=@@%h\t%ad\t%s', '--date=short', '--numstat',
              f'{base}..{head}')
    commits, cur = [], None
    for l in log.splitlines():
        if l.startswith('@@'):
            sha, date, subj = l[2:].split('\t', 2)
            cur = {'sha': sha, 'date': date, 'subject': subj, 'files': []}
            commits.append(cur)
        elif '\t' in l and cur is not None:
            a, d, p = l.split('\t', 2)
            cur['files'].append((p, 0 if a == '-' else int(a), 0 if d == '-' else int(d)))
    merges = len(git('rev-list', '--merges', f'{base}..{head}').split())
    return commits, merges


def main():
    global M_SRC_PKGS
    sys.path.insert(0, str(M.HARNESS))
    import prep_corpus as PC
    M_SRC_PKGS = set(PC.SRC_PKGS)
    base = git('rev-parse', f'{BASE_TAG}^{{commit}}').strip()
    head = git('rev-parse', 'HEAD').strip()
    mb = git('merge-base', 'HEAD', 'Release153').strip()
    if not base or base != mb:
        M.emit('evolution', [], [{'title': 'evolution base', 'why': f'{BASE_TAG} ({base[:7]}) is no longer '
                                  f'merge-base(HEAD, Release153) ({mb[:7]}): the base claim does not hold, nothing drawn'}],
               'mine_evolution.py')
        return 0
    commits, merges = walk(git, base)
    rnd = assign([(c['sha'], c['subject']) for c in commits])
    unknown = unknown_rounds(rnd)
    if unknown:  # r24: name the missing round instead of a KeyError traceback
        print(f'mine_evolution: git names round(s) {unknown} that ORDER does not list: add them to ORDER', file=sys.stderr)
        return 1
    up_dirs = set(git('ls-tree', '-r', '-d', '--name-only', base).split('\n'))
    # r23c (review): the base's own files (vendor/ aside), so an 'evolved' strip can tell upstream-as-tagged from data
    up_files = sorted(f for f in git('ls-tree', '-r', '--name-only', base).split('\n') if f and not f.startswith('vendor/'))

    R = {k: {'commits': [], 'add': 0, 'del': 0, 'paths': set(), 'sub': collections.defaultdict(lambda: [0, 0, 0, set()]),
             'files': collections.defaultdict(lambda: [0, 0]), 'dates': []} for k in ORDER + ['pending']}
    MOD = collections.defaultdict(lambda: {'add': 0, 'del': 0, 'paths': set(), 'rounds': set(), 'commits': set()})
    FIL = collections.defaultdict(lambda: {'add': 0, 'del': 0, 'commits': set(), 'rounds': set()})
    # line 1 must not change with HEAD: mine_localdiff anchors a changed file by its first line and runs before this
    # miner rewrites the file, so a HEAD sha there left the localdiff row one commit stale (MISSING, refused) - r23c
    lines = [f'# evolution_git.tsv — written by harness/miners/mine_evolution.py (r23c) from git; base {BASE_TAG} '
             f'{base[:7]} = merge-base(HEAD, Release153); numstat --no-renames',
             '# round rule: a subject starting Round N / RN / rN names its round; the Release142 port is R1-3; any other '
             'commit belongs to the next round-marked commit; groups as the Enhancement Ledger: 4/4b/4c/4d=R4 6/6b=R6 9/9b/10=R9',
             f'# head {head[:7]}; {len(commits)} commits']
    for i, c in enumerate(commits, 1):
        k = rnd[c['sha']]
        g = R[k]
        g['commits'].append(c['sha'])
        g['dates'].append(c['date'])
        ca = sum(a for _, a, _ in c['files'])
        cd = sum(d for _, _, d in c['files'])
        g['add'] += ca
        g['del'] += cd
        seen_sub = set()
        for p, a, d in c['files']:
            s = subsystem(p)
            g['paths'].add(p)
            sb = g['sub'][s]
            sb[1] += a
            sb[2] += d
            sb[3].add(p)
            if s not in seen_sub:
                sb[0] += 1
                seen_sub.add(s)
            if s != 'harness data':
                g['files'][p][0] += a
                g['files'][p][1] += d
            m = module(p)
            if m:
                mm = MOD[m]
                mm['add'] += a
                mm['del'] += d
                mm['paths'].add(p)
                mm['rounds'].add(k)
                mm['commits'].add(c['sha'])
            if s in CODE and p.endswith(SOURCE_EXT):
                ff = FIL[p]
                ff['add'] += a
                ff['del'] += d
                ff['commits'].add(c['sha'])
                ff['rounds'].add(k)
        lines.append(f"C\t{i:03d}\t{c['sha']}\t{k}\t{c['date']}\tfiles={len(c['files'])}\t+{ca}\t-{cd}\t"
                     f"{c['subject'][:72].rstrip()}")   # r23c (review): no trailing blank where the cut lands on a space

    rows, unv = [], []
    planned = planned_keys()
    cum_go = cum_code = cum_all = 0
    for k in ORDER:
        g = R[k]
        go = sum(a + d for p, (a, d) in g['files'].items() if p.endswith('.go') and subsystem(p) in GO_SHIPPED)
        code = sum(v[1] + v[2] for s, v in g['sub'].items() if s in CODE)
        cum_go += go
        cum_code += code
        cum_all += g['add'] + g['del']
        subs = {s: [v[0], v[1], v[2], len(v[3])] for s, v in sorted(g['sub'].items(), key=lambda x: SUBSYSTEMS.index(x[0]))}
        sline = ' '.join(f"{s.replace(' ', '_')}={v[0]}/{v[1]}/{v[2]}" for s, v in subs.items())
        tsv = (f"R\t{k}\tcommits={len(g['commits'])}\tfiles={len(g['paths'])}\t+{g['add']}\t-{g['del']}\t"
               f"go={go}\tcode={code}\tcum_go={cum_go}\tcum_code={cum_code}\t{sline or 'no-commits'}")
        lines.append(tsv)
        docs, secno, what = doc_anchors(k)
        u = commitless_unverified(k, g['commits'], planned)        # r28: a planned round is pending, not unanchored
        if u:
            unv.append(u)
        rows.append({'id': f'evo-{k.lower()}', 'section': 'evolution', 'kind': 'evo-round', 'class': 'HARNESS',
                     'title': LABEL.get(k, k), 'round': k, 'order': ORDER.index(k),
                     'claim': (f"{LABEL.get(k, k)}: {len(g['commits'])} commit(s), {len(g['paths'])} path(s), "
                               f"+{g['add']:,} / -{g['del']:,} lines; first-party Go +/- {go:,}, code +/- {code:,}"
                               + (f" ({min(g['dates'])} to {max(g['dates'])})" if g['dates'] else ' — pending measurement')
                               + (f'. Written up in ARCHITECTURE {secno}: {what}' if secno else '')),
                     'pending': not g['commits'], 'commits': g['commits'], 'commit_n': len(g['commits']),
                     'added': g['add'], 'removed': g['del'], 'paths_n': len(g['paths']), 'go': go, 'code': code,
                     'cum_go': cum_go, 'cum_code': cum_code, 'cum_all': cum_all, 'subs': subs,
                     'files': {p: v for p, v in sorted(g['files'].items())},
                     'dates': [min(g['dates']), max(g['dates'])] if g['dates'] else [],
                     'doc_section': secno, 'doc_what': what, 'head': head[:7], 'base': base[:7],
                     'evidence': [{'file': SNAP, 'quote': tsv, 'line': len(lines)}] + docs})
    if R['pending']['commits']:
        unv.append({'title': f"{len(R['pending']['commits'])} commit(s) after the last round-marked commit",
                    'why': 'the round rule gives them the NEXT round-marked commit, and none exists yet: '
                           + ', '.join(R['pending']['commits'][:6])})

    for m in sorted(MOD, key=lambda m: (-(MOD[m]['add'] + MOD[m]['del']), m)):
        v = MOD[m]
        up = m in up_dirs
        rs = [k for k in ORDER if k in v['rounds']]
        tsv = (f"M\t{m}\tupstream={'yes' if up else 'no'}\tfirst={rs[0] if rs else '-'}\trounds={','.join(rs)}\t"
               f"files={len(v['paths'])}\t+{v['add']}\t-{v['del']}\tcommits={len(v['commits'])}")
        lines.append(tsv)
        rows.append({'id': 'evo-mod-' + re.sub(r'[^a-z0-9]+', '-', m.lower()).strip('-'), 'section': 'evo-module',
                     'kind': 'evo-module', 'class': 'HARNESS', 'title': m, 'module': m, 'upstream': up,
                     'first_round': rs[0] if rs else '', 'rounds': rs, 'files_n': len(v['paths']), 'added': v['add'],
                     'removed': v['del'], 'commit_n': len(v['commits']), 'subsystem': subsystem(sorted(v['paths'])[0] if v['paths'] else m),
                     'claim': (f"{m}: {'upstream module, modified' if up else 'new module, first added'} in "
                               f"{LABEL.get(rs[0], rs[0]) if rs else '-'}; changed in {len(rs)} round(s), {len(v['commits'])} "
                               f"commit(s), {len(v['paths'])} file(s), +{v['add']:,} / -{v['del']:,} lines"),
                     'evidence': [{'file': SNAP, 'quote': tsv, 'line': len(lines)}]})

    # upstream modules this branch never touched: top-level first-party packages and cmd/<x> as they were at the base
    # (a package one of whose sub-modules changed is drawn through that sub-module instead)
    still = sorted(d for d in up_dirs if d and ((d in M_SRC_PKGS and d not in ('cmd', 'tools'))
                                               or (d.startswith('cmd/') and d.count('/') == 1)))
    for m in still:
        if m in MOD or any(k.startswith(m + '/') for k in MOD):
            continue
        tsv = f"M\t{m}\tupstream=yes\tfirst=-\trounds=\tfiles=0\t+0\t-0\tcommits=0"
        lines.append(tsv)
        rows.append({'id': 'evo-mod-' + re.sub(r'[^a-z0-9]+', '-', m.lower()).strip('-'), 'section': 'evo-module',
                     'kind': 'evo-module', 'class': 'HARNESS', 'title': m, 'module': m, 'upstream': True,
                     'first_round': '', 'rounds': [], 'files_n': 0, 'added': 0, 'removed': 0, 'commit_n': 0,
                     'subsystem': subsystem(m + '/x.go'),
                     'claim': f'{m}: upstream module, unchanged since {BASE_TAG} (no local commit touches it)',
                     'evidence': [{'file': SNAP, 'quote': tsv, 'line': len(lines)}]})

    top = sorted(FIL, key=lambda p: (-(FIL[p]['add'] + FIL[p]['del']), p))[:TOP_FILES]
    for i, p in enumerate(top, 1):
        v = FIL[p]
        rs = [k for k in ORDER if k in v['rounds']]
        tsv = (f"F\t{i:02d}\t{p}\t+{v['add']}\t-{v['del']}\tcommits={len(v['commits'])}\trounds={','.join(rs)}")
        lines.append(tsv)
        rows.append({'id': f'evo-file-{i:02d}', 'section': 'evo-file', 'kind': 'evo-file', 'class': 'HARNESS',
                     'title': p, 'path': p, 'rank': i, 'added': v['add'], 'removed': v['del'],
                     'commit_n': len(v['commits']), 'rounds': rs, 'subsystem': subsystem(p),
                     'claim': f"#{i} by lines changed: {p}, +{v['add']:,} / -{v['del']:,} over {len(v['commits'])} "
                              f"commit(s) in {len(rs)} round(s)",
                     'evidence': [{'file': SNAP, 'quote': tsv, 'line': len(lines)}]})

    # the base itself: the documented tag line and the snapshot header that records the merge-base check
    ba = M.anchor('ARCHITECTURE.md', f'Release152 (tag `{base[:7]}`')
    rows.append({'id': 'evo-base', 'section': 'evolution', 'kind': 'evo-base', 'class': 'HARNESS',
                 'title': f'{BASE_TAG} {base[:7]}', 'base': base[:7], 'head': head[:7], 'commit_n': len(commits), 'merge_n': merges,
                 'base_paths': up_files,
                 'claim': base_claim(BASE_TAG, base, head, len(commits), merges),
                 'evidence': [{'file': SNAP, 'quote': lines[0], 'line': 1},
                              {'file': SNAP, 'quote': lines[2], 'line': 3}] + ([ba] if ba else [])})
    out = M.ROOT / SNAP
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text('\n'.join(lines) + '\n')
    M._CACHE.clear()
    rows = [r for r in rows if r['evidence']]
    M.emit('evolution', rows, unv, 'mine_evolution.py')
    return 0


M_SRC_PKGS = set()

if __name__ == '__main__':
    sys.exit(main())
