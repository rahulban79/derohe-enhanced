#!/usr/bin/env python3
"""autosync.py — PostToolUse(Write|Edit) hook: keep the page, the stamp and the skill in step automatically.

Reads the hook JSON on stdin. When the edited file is a model file, the generator, a miner, the kit, a runtime
snapshot or the skill, it runs `gen_deroarch.py build` (~3 s): the page is re-projected, the stamp re-hashed and
the skill's AUTO block rewritten. Anything else is ignored. It never blocks the tool call — it prints a one-line
systemMessage with the result (or the failure) and exits 0.
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import json, subprocess, sys
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
WATCH = [HARNESS / 'model', HARNESS / 'miners', HARNESS / 'kit', HARNESS / 'runtime',
         HARNESS / 'gen_deroarch.py', HARNESS / 'prep_corpus.py', ROOT / '.skills/dero-miner-tuning']
SKIP = {HARNESS / 'model/verified.json', HARNESS / 'stamp.json'}      # the build's own output


def main():
    try:
        d = json.load(sys.stdin)
    except Exception:                                                  # noqa: BLE001
        return
    f = (d.get('tool_input') or {}).get('file_path') or (d.get('tool_response') or {}).get('filePath') or ''
    if not f:
        return
    p = Path(f).resolve()
    if p in SKIP or not any(p == w or w in p.parents for w in WATCH):
        return
    r = subprocess.run([sys.executable, str(HARNESS / 'gen_deroarch.py'), 'build'],
                       capture_output=True, text=True, timeout=300)
    if r.returncode == 0:
        st = json.loads((HARNESS / 'stamp.json').read_text())
        msg = (f"dero-arch autosync: rebuilt after {p.name} · {st['stats']['rows']} rows · "
               f"{st['stats']['anchors_ok']}/{st['stats']['anchors']} anchors · fingerprint {st['fingerprint']} "
               f"· skill AUTO block updated (run harness/run_gates.py to re-gate)")
    else:
        msg = (f"dero-arch autosync: build FAILED after {p.name} (exit {r.returncode}): "
               f"{(r.stderr or r.stdout).strip().splitlines()[-1:]}")
    print(json.dumps({'systemMessage': msg}))


if __name__ == '__main__':
    main()
