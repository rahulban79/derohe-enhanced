#!/usr/bin/env python3
"""handoff.py — r30 (rft §7 B252, §0.10, §2.22): the agent HANDOFF.md convention and its checker.

Every agent of a round keeps <scratch>/<round>/<dim>/HANDOFF.md current, and writes it last before it hands back or
when the coordinator says "checkpoint now" (round_pause.py pause). A fresh agent resumes the dim from this file alone, so
it must hold:

  Agent: <agent id>                      the Agent-tool id (round_checkpoint maps the transcript to this file by it)
  Branch <branch> head <sha>             the clone's branch and its head (e.g. "Branch r30-pause head 1a2b3c4d")
  ## Done                                bullets: what is finished (commits, KATs, records), with anchors
  ## In flight                           bullets: what was running at the hand-off (or "- none"), detached jobs with
                                         their output file
  ## Next                                the exact next command(s), each in `backticks` or a ``` block

check() reports a problem for: a missing section, an empty Done / In flight section, a Next section without a command,
no Branch/head line, and (when the clone tree is given or found beside the file) a head that is not the tree's HEAD
('stale') or not in the tree at all. The merge agent's form ("branch local-enhancements, head abd5c477" in the header,
"## Next exact commands") is accepted.

  python3 -I harness/kit/handoff.py check <HANDOFF.md> [--tree DIR] [--json]
  python3 -I harness/kit/handoff.py template --agent ID --branch B --head SHA     # a skeleton to fill
Exit 0 ok · 4 a problem · 2 unreadable. KAT: harness/kat/test_round_pause_r30.py (HF1-HF3).
"""
import json, re, subprocess, sys
from pathlib import Path

SECTIONS = (('done', r'done'), ('in_flight', r'in[ -]?flight'), ('next', r'next'))
HEAD_RX = re.compile(r'(?i)\bbranch\b\W*`?([\w./-]+)`?\W*(?:,|;)?\s*(?:head|at)\W*`?([0-9a-f]{7,40})\b')
AGENT_RX = re.compile(r'(?im)^\W*agent\W+(a[0-9a-f]{8,})')
CMD_RX = re.compile(r'`[^`\n]{3,}`|```')


def parse(text):
    """{'agent', 'branch', 'head', 'done': [..], 'in_flight': [..], 'next': [..], 'sections': [names]}. Pure."""
    out = {'agent': None, 'branch': None, 'head': None, 'done': [], 'in_flight': [], 'next': [], 'sections': []}
    m = AGENT_RX.search(text)
    out['agent'] = m.group(1) if m else None
    m = HEAD_RX.search(text)
    if m:
        out['branch'], out['head'] = m.group(1), m.group(2)
    cur = None
    for line in text.splitlines():
        h = re.match(r'^#{2,3}\s+(.*)$', line)
        if h:
            cur = next((k for k, rx in SECTIONS if re.match(rx, h.group(1).strip(), re.I)), None)
            if cur:
                out['sections'].append(cur)
            continue
        if cur and line.strip():
            out[cur].append(line.rstrip())
    return out


def git_head(tree):
    try:
        r = subprocess.run(['git', '-C', str(tree), 'rev-parse', 'HEAD'], capture_output=True, text=True, timeout=30)
        return r.stdout.strip() if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def has_commit(tree, sha):
    try:
        return subprocess.run(['git', '-C', str(tree), 'cat-file', '-e', f'{sha}^{{commit}}'], capture_output=True,
                              timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def check(path, tree=None):
    """(ok, problems, parsed) for one HANDOFF.md; tree = the dim's clone (default: <dir>/tree when it is a git tree)."""
    p = Path(path)
    try:
        d = parse(p.read_text(errors='replace'))
    except OSError as e:
        return False, [f'unreadable: {type(e).__name__}'], {}
    probs = []
    for k, _ in SECTIONS:
        if k not in d['sections']:
            probs.append(f"no '## {k.replace('_', ' ').title()}' section")
        elif k != 'next' and not d[k]:
            probs.append(f"empty '{k}' section (write '- none')")
    if 'next' in d['sections'] and not CMD_RX.search('\n'.join(d['next'])):
        probs.append('Next has no exact command (`cmd` or a ``` block)')
    if not d['head']:
        probs.append("no 'Branch <name> head <sha>' line")
    if not d['agent']:
        probs.append("no 'Agent: <id>' line (round_checkpoint cannot map the agent's transcript to this file)")
    tree = Path(tree) if tree else (p.parent / 'tree' if (p.parent / 'tree' / '.git').exists() else None)
    if tree and d['head']:
        th = git_head(tree)
        if th is None:
            probs.append(f'tree {tree} unreadable')
        elif not has_commit(tree, d['head']):
            probs.append(f"head {d['head']} is not in the tree {tree}")
        elif not th.startswith(d['head']):
            probs.append(f"stale: the tree HEAD is {th[:12]}, the file says {d['head']}")
    d['tree'] = str(tree) if tree else None
    return not probs, probs, d


def template(agent, branch, head):
    return (f'# HANDOFF\n\nAgent: {agent}\nBranch {branch} head {head}\n\n## Done\n- none\n\n## In flight\n- none\n\n'
            f'## Next\n- `<the exact next command>`\n')


def main(argv):
    if not argv or {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    if argv[0] == 'template':
        kv = dict(zip(argv[1::2], argv[2::2]))
        print(template(kv.get('--agent', '<id>'), kv.get('--branch', '<branch>'), kv.get('--head', '<sha>')), end='')
        return 0
    if argv[0] != 'check' or len(argv) < 2:
        print(__doc__)
        return 2
    tree = argv[argv.index('--tree') + 1] if '--tree' in argv else None
    if not Path(argv[1]).exists():
        print(f'{argv[1]}: no such file')
        return 2
    ok, probs, d = check(argv[1], tree)
    if '--json' in argv:
        print(json.dumps({'ok': ok, 'problems': probs, 'parsed': d}, indent=1))
    else:
        print(f"{'ok' if ok else 'PROBLEM'} {argv[1]}: agent {d.get('agent')} branch {d.get('branch')} head {d.get('head')}"
              + ''.join(f'\n  - {x}' for x in probs))
    return 0 if ok else 4


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
