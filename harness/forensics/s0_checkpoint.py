#!/usr/bin/env python3
"""R30 S0 offline (rft §8 "R30 audit plan" stage S0; B209, B210, B111, B203(a)): the shared reader of the R29 B182 deep
checkpoint (`~/derohe-persist/forensics_raw_r29/deep/checkpoint.log`, 73,983 batch records + 1 join record, each line
`<crc32 hex> <json>`). The checkpoint is READ-ONLY input: it is never written here, and every record that uses it pins it
by SHA-256 (rule 4: an input is named by its hash). Counts and hashes only (rule 13): no address, no amount.

  python3 -I harness/forensics/s0_checkpoint.py [--checkpoint PATH]     # print the pin and the record census
  python3 -I harness/forensics/s0_checkpoint.py --check                 # S7: re-derive the four r30 S0 records and
      # compare them with the committed harness/runtime/r30_*.json; exit 0 equal (or the checkpoint absent: the two
      # checkpoint records SKIPPED and labelled, the other two still checked) · 5 a record differs

Callers: claim_grant.py (B210), dc0_genesis.py (B209), dc2_den.py (B203 a), b111_premine.py (B111).
"""
import argparse, hashlib, importlib.util, json, os, re, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DEFAULT_CHECKPOINT = Path(os.environ.get('FORENSICS_R29_DEEP', str(Path.home() / 'derohe-persist' / 'forensics_raw_r29' / 'deep'))) / 'checkpoint.log'
CHECKPOINT_LABEL = '$FORENSICS_R29_DEEP/checkpoint.log (the R29 B182 deep stage, outside git, read-only; a label, not a path)'
# the R29 checkpoint as recorded at S0 (2026-11-08): a different file is a different input and every S0 record says so
CHECKPOINT_SHA256 = '548f31c351e7a4525ded86c2b19f6ef348b50bcaf4a5c2fde497ec55d52aec6a'


def _b182(root=ROOT):
    """the R29 tool's own record parser (unseal: CRC check, torn tail ignored); used, never edited"""
    p = Path(root) / 'harness' / 'forensics' / 'b182_deep_r29.py'
    sp = importlib.util.spec_from_file_location(f'b182_for_s0_{id(p)}', p)
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


def sha_file(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def load(path=DEFAULT_CHECKPOINT, root=ROOT):
    """{'records': [...], 'ignored_tail_lines': n, 'sha256': hex, 'pin_equal': bool, 'label': str}"""
    path = Path(path)
    with open(path, 'r', encoding='utf-8') as f:
        recs, ign = _b182(root).unseal(f.readlines())
    h = sha_file(path)
    return {'records': recs, 'ignored_tail_lines': ign, 'sha256': h, 'pin_equal': h == CHECKPOINT_SHA256,
            'label': CHECKPOINT_LABEL}


def batches(recs):
    return [r for r in recs if r.get('kind') == 'batch']


def pin(ck):
    """the input pin every S0 record carries"""
    return {'file': ck['label'], 'sha256': ck['sha256'], 'recorded_sha256': CHECKPOINT_SHA256, 'equal': ck['pin_equal'],
            'batch_records': len(batches(ck['records'])), 'ignored_tail_lines': ck['ignored_tail_lines']}


def config_heights(root=ROOT):
    """mainnet HF heights read from config/config.go (the first block of each `NAME: value,` line pair): {name: (h, line)}"""
    out = {}
    for i, l in enumerate((Path(root) / 'config' / 'config.go').read_text().splitlines(), 1):
        m = re.match(r'\s*(HF1_HEIGHT|HF2_HEIGHT|MAJOR_HF2_HEIGHT|MAJOR_HF3_HEIGHT):\s*(\d+),', l)
        if m and m.group(1) not in out:
            out[m.group(1)] = (int(m.group(2)), i)
    return out


def anchor(root, rel, line, want):
    """re-read one code anchor: {'anchor': 'file:line', 'ok': want in that line}"""
    try:
        t = (Path(root) / rel).read_text().splitlines()[line - 1]
    except (OSError, IndexError):
        t = ''
    return {'anchor': f'{rel}:{line}', 'expect': want, 'ok': want in t}


def write_record(path, obj):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(obj, indent=1, sort_keys=True) + '\n')


S0_RECORDS = {'claim_grant': 'harness/runtime/r30_claim_grant.json', 'dc0_genesis': 'harness/runtime/r30_dc0_genesis.json',
              'dc2_den': 'harness/runtime/r30_dc2_den.json', 'b111_premine': 'harness/runtime/r30_b111_premine.json'}
NEEDS_CHECKPOINT = ('claim_grant', 'dc0_genesis')


def check(root=ROOT, checkpoint=DEFAULT_CHECKPOINT, base='forensics/r28d', builders=None):
    """{record: 'equal' | 'DIFFERS' | 'SKIPPED: ...'} re-deriving every r30 S0 record from its pinned inputs"""
    root = Path(root)
    ck = load(checkpoint, root) if Path(checkpoint).exists() else None
    if builders is None:
        if str(HERE) not in sys.path:
            sys.path.insert(0, str(HERE))
        import claim_grant, dc0_genesis, dc2_den, b111_premine   # noqa: E401 (they import this module)
        builders = {'claim_grant': lambda ck: claim_grant.build(ck, root), 'dc0_genesis': lambda ck: dc0_genesis.build(ck, root),
                    'dc2_den': lambda ck: dc2_den.build(root, base), 'b111_premine': lambda ck: b111_premine.build(root, base)}
    out = {}
    for name, rel in S0_RECORDS.items():
        if name in NEEDS_CHECKPOINT and ck is None:
            out[name] = 'SKIPPED: the B182 checkpoint is not on this machine'
            continue
        if name in NEEDS_CHECKPOINT and not ck['pin_equal']:
            out[name] = f"DIFFERS: the checkpoint hashes to {ck['sha256'][:16]}, not the pinned {CHECKPOINT_SHA256[:16]}"
            continue
        new = builders[name](ck)
        try:
            old = json.loads((root / rel).read_text())
        except (OSError, ValueError):
            old = None
        out[name] = 'equal' if old == new else 'DIFFERS'
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--checkpoint', default=str(DEFAULT_CHECKPOINT))
    ap.add_argument('--check', action='store_true')
    a = ap.parse_args(argv)
    if a.check:
        r = check(ROOT, a.checkpoint)
        print('s0 records: ' + ', '.join(f'{k} {v}' for k, v in r.items()))
        return 5 if any(v.startswith('DIFFERS') for v in r.values()) else 0
    ck = load(a.checkpoint)
    print(json.dumps(pin(ck), indent=1, sort_keys=True))
    return 0 if ck['pin_equal'] else 6


if __name__ == '__main__':
    sys.exit(main())
