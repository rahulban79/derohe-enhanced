#!/usr/bin/env python3
"""katmut.py — mutation independence for the stand-alone harness KATs (r27 tools-kats; dero-rft §0.9 rule 1).

A KAT file's mutation runner applies one mutation (it undoes one fix), re-runs EVERY KAT of the file and calls the
mutation 'proved' when any KAT fails. That hid two faults (R26 measurement, harness/kat/test_harness_tooling_r26.py):
  * coupling: HT12 called the real out-of-repo scrubber through the mutant's own ROOT, so EVERY tooling_intel mutation
    also failed HT12 ([HT8,HT12], [HT10,HT12]); had HT8 stopped testing --help, HT12 would still have 'proved' it;
  * a mutation caught only by ANOTHER defect's KAT proves nothing about the KAT that claims the defect.
So each mutation names its defect (the 'B<n>' that starts its reason, or an explicit owner) and the file maps every
defect to the KAT(s) that own it. classify() then says:
  proved     a KAT that owns the defect failed (other KATs may fail too: they are listed as coupled)
  MISSED     no KAT failed
  WRONG-KAT  only KATs of OTHER defects failed: the owning KAT does not test what it claims
and the summary line 'mutations proved P/N · mutations coupled C' is what tooling_intel reads (KAT_MUT_RX,
KAT_COUPLED_RX). A coupled mutation is a finding (target 0), not a failure of the defect's own proof.

  python3 harness/kit/katmut.py --help
Library only (no command): imported by harness/kat/test_*.py.
"""
import re

DEFECT_RX = re.compile(r'^\s*(B\d+[a-z]?|r\d+[a-z]?(?:\s+[\w-]+)?)\b')


def defect_of(why):
    """the defect id a mutation reason starts with: 'B98: ...' -> 'B98', 'B119 class: ...' -> 'B119', 'r27 TK3: ...'
    -> 'r27 TK3'; None when it names none. Pure."""
    m = DEFECT_RX.match(str(why or ''))
    return m.group(1) if m else None


def classify(failed, owners):
    """(verdict, coupled) for one mutation: `failed` = the KAT ids that failed under it, `owners` = the KAT ids that own
    its defect. Pure."""
    failed, owners = set(failed or ()), set(owners or ())
    if not failed:
        return 'MISSED', []
    if not owners or not failed & owners:
        return 'WRONG-KAT', sorted(failed)
    return 'proved', sorted(failed - owners)


def summary(label, n_kats, n_mut, missed, coupled):
    """the file's last line; 'mutations proved X/Y' and 'mutations coupled C' are parsed by tooling_intel. Pure."""
    return (f'{label}: {n_kats}/{n_kats} ok · mutations proved {n_mut - missed}/{n_mut} · mutations coupled {coupled}')


if __name__ == '__main__':
    import sys
    print(__doc__)                         # '--help', '-h' or nothing: the usage; a library has no other command
    sys.exit(0 if not sys.argv[1:] or {'-h', '--help'} & set(sys.argv[1:]) else 2)
