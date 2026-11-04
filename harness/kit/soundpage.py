"""soundpage.py — r25: the soundness review is a per-round page, like the ledger (artifacts/dero-rft.md §0.6, §6 step 13).

Until R25 every tool named one fixed page, artifacts/dero-soundness-r23.html. From R25 each round writes its own
review page, artifacts/dero-soundness-<round>.html, where <round> is harness/round.json `current`; earlier pages stay
unchanged as history (old ledger pages link them and must keep regenerating byte-exact). Every harness tool that needs
the soundness page asks this module, so no tool can keep pointing at a stale round:

  name(root)          'dero-soundness-<current>.html'  (raises ValueError when the registry has no current round)
  rel(root)           'artifacts/' + name(root)
  history(root)       the other dero-soundness-r*.html pages under artifacts/, oldest first (historic, not gated)
  page_round(fname)   'r25' for 'dero-soundness-r25.html', else None

Pure except the reads of harness/round.json and the artifacts/ listing. KAT: harness/kat/test_soundpage_r25.py.
"""
import json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
RX = re.compile(r'^dero-soundness-(r\d+[a-z]?)\.html$')


def current(root=ROOT):
    reg = json.loads((Path(root) / 'harness/round.json').read_text())
    cur = reg.get('current') if isinstance(reg, dict) else None
    if not isinstance(cur, str) or not re.fullmatch(r'r\d+[a-z]?', cur):
        raise ValueError(f'harness/round.json has no usable current round: {cur!r}')
    return cur


def name(root=ROOT):
    return f'dero-soundness-{current(root)}.html'


def rel(root=ROOT):
    return 'artifacts/' + name(root)


def page_round(fname):
    m = RX.match(Path(fname).name)
    return m.group(1) if m else None


def _key(r):
    m = re.match(r'r(\d+)([a-z]?)', r)
    return (int(m.group(1)), m.group(2))


def history(root=ROOT):
    cur = name(root)
    pages = [p.name for p in (Path(root) / 'artifacts').glob('dero-soundness-r*.html') if page_round(p.name) and p.name != cur]
    return sorted(pages, key=lambda n: _key(page_round(n)))
