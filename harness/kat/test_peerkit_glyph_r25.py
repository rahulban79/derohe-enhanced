#!/usr/bin/env python3
"""Known-answer test + mutation proof for the peer-observatory grade chips (harness/kit/peerkit.py GRADE_ICON; r25
pipeline run 4, pipeline project-only S7 FAIL at verify_deroarch DK16: textkit found "… pending" as a cut without a
tooltip).

  PG1 every grade chip (OBSERVED, ANOMALY, NORMAL, pending) rendered with a plain chip passes textkit.audit (no visible
      '…' without a tooltip), and every grade has its own icon.

  python3 -I harness/kat/test_peerkit_glyph_r25.py
Exit 0 all ok · 3 the KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import importlib.util, sys, tempfile
from pathlib import Path

KIT = Path(__file__).resolve().parent.parent / 'kit'
SRC = KIT / 'peerkit.py'
sys.path.insert(0, str(KIT))
import textkit  # noqa: E402


def load(path):
    spec = importlib.util.spec_from_file_location(f'pg25_{abs(hash(str(path)))}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def chip(text, col):
    return f'<span class="chip" style="--c:{col}">{text}</span>'


def pg1(m):
    grades = ['OBSERVED', 'ANOMALY', 'NORMAL', 'pending']
    html = '<html><body><table><tr>' + ''.join(f'<td>{m._grade(g, chip)}</td>' for g in grades) + '</tr></table></body></html>'
    a = textkit.audit(html)
    icons = [m.GRADE_ICON.get(g) for g in grades]
    return a['ok'] and all(icons) and len(set(icons)) == 4, f"audit={a} icons={icons}"


MUTATIONS = [("'pending': '○'}", "'pending': '…'}", "the pending chip prints '…' (a cut without a tooltip)")]


def main():
    ok, det = pg1(load(SRC))
    print(f"{'ok  ' if ok else 'FAIL'} PG1 {det[:300]}")
    if not ok:
        return 3
    text, missed = SRC.read_text(), 0
    for find, repl, why in MUTATIONS:
        if text.count(find) != 1:
            print(f'  ??      {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / SRC.name
            p.write_text(text.replace(find, repl, 1))
            try:
                mm = load(p)
            except Exception as e:                                # noqa: BLE001
                print(f'  INVALID {why}: mutant does not load ({type(e).__name__})')
                missed += 1
                continue
            survived = pg1(mm)[0]
        print(f"  {'MISSED ' if survived else 'proved '} {why}")
        missed += survived
    print(f'\nr25 peerkit-glyph KATs: 1/1 ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
