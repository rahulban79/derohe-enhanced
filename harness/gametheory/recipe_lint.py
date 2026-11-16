#!/usr/bin/env python3
"""r32a: lint the LIVE stallwatch command files (<GT_HOME>/mainnet/*.cmd) — a job's DONE marker only on success.

Why (main session 2026-11-15 14:28): the running earn.cmd ended `...; touch earn.DONE`. When the driver was stopped to add
a wallet, its shell still ran `touch earn.DONE`, and the relaunched stallwatch read DONE and exited at once. KAT GT10
checked the docstring and page copies of the recipe, never the live command file the watchdog actually runs.

Rule: every `touch <x>.DONE` in a command file must be reached through `&&` (the command before it succeeded), never
through `;`, `||` or a newline. Read-only.

  python3 -I harness/gametheory/recipe_lint.py [--dir DIR]     # exit 0 clean · 5 a recipe marks DONE on failure · 2 no dir
"""
import argparse, re, sys
from pathlib import Path


def problems(text):
    """[(line_no, why)] for each `touch *.DONE` not reached through `&&`. Pure."""
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        for m in re.finditer(r'touch\s+\S*\.DONE\b', line):
            before = line[:m.start()].rstrip()
            if not before.endswith('&&'):
                sep = ('`;`' if before.endswith(';') else '`||`' if before.endswith('||') else
                       'the line start' if not before else 'no separator')
                out.append((i, f"the DONE touch follows {sep}, not `&&`: a failed or killed job is marked DONE"))
    return out


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--dir', default=None, help='the directory of *.cmd files (default <GT_HOME>/mainnet)')
    a = ap.parse_args(argv)
    if a.dir:
        d = Path(a.dir)
    else:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / 'playbooks'))
        import gtlib
        d = gtlib.GT_HOME / 'mainnet'
    if not d.is_dir():
        print(f'recipe_lint: no directory {d.name}')
        return 2
    bad = 0
    files = sorted(d.glob('*.cmd'))
    for f in files:
        for ln, why in problems(f.read_text()):
            print(f'BAD {f.name}:{ln}: {why}')
            bad += 1
    print(f'recipe_lint: {len(files)} command file(s), {bad} problem(s) · {"PASS" if not bad else "FAIL"}')
    return 0 if not bad else 5


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
