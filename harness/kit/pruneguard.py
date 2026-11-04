#!/usr/bin/env python3
"""r25 pruneguard: refuse a harness probe's state read below the live node's prune point, and log every state read.

On 2026-11-03 08:37:44 four read-only GetEncryptedBalance calls of the R25 forensics discovery probe asked the live
derod for topoheights below its prunedheight (7,498,540). The r24 handler panicked on purpose, the recover turned it
into "internal error: file does not exist", and four ERROR lines with a stack failed gate G15 for the rest of that
derod run (rft §7 B85; harness/runtime/r25_forensics_discovery_20261103.txt lines 108-111, 183-184). r25 makes derod
answer -32031 instead, but a running older binary still panics, and a probe should never ask: the rule (rft §5) is
"never ask the live node for state below its prunedheight". This module is that rule, in one place:

  state_topo(method, params)        the topoheight a state-reading call would read, from the handler's own rule, or
                                    None for a call that reads no historical state:
                                      GetEncryptedBalance (cmd/derod/rpc/rpc_dero_getencryptedbalance.go): topoheight
                                        >= 0 is used AS IS (0 = genesis, the JSON default when the field is omitted!),
                                        < 0 = the tip; a treehash in the params selects the tip
                                      GetSC (rpc_dero_getsc.go): topoheight >= 1 is used, else the tip
  check(method, params, pruned)     raises StateBelowPrune when that topoheight is below `pruned` (> 0); pure
  guarded_call(rpc, method, params, pruned=None, call_log=...)
                                    reads GetInfo.prunedheight when not given, checks, appends one line to the call
                                    log (UTC time, method, topoheight; no address, no params), then calls rpc(method,
                                    params). The derod error census (harness/intel/error_census.py) matches recovered
                                    panics against this log to name them self-inflicted.

The call log defaults to ~/derohe-persist/probe_calls.jsonl (private, outside every repository); DERO_PROBE_CALL_LOG
overrides it. Read-only on the node; the only write is the call-log line.
"""
import datetime, json, os
from pathlib import Path

CALL_LOG = Path(os.environ.get('DERO_PROBE_CALL_LOG') or (Path.home() / 'derohe-persist' / 'probe_calls.jsonl'))

# method names as the node serves them (servicemux + historical_apis, cmd/derod/rpc/websocket_server.go)
ENCBAL = ('DERO.GetEncryptedBalance', 'getencryptedbalance')
GETSC = ('DERO.GetSC', 'getsc')


class StateBelowPrune(Exception):
    def __init__(self, method, topo, pruned):
        super().__init__(f'refused: {method} would read state at topoheight {topo}, below the node\'s prunedheight '
                         f'{pruned} (rft §5, B85)')
        self.method, self.topo, self.pruned = method, topo, pruned


def state_topo(method, params):
    """The historical topoheight the call would read (int), 'tip', or None (no state read). Pure."""
    p = params or {}
    if isinstance(p, list):
        p = p[0] if p and isinstance(p[0], dict) else {}
    if method in ENCBAL:
        if p.get('treehash'):
            return 'tip'
        t = p.get('topoheight', 0)
        t = 0 if t is None else int(t)
        return t if t >= 0 else 'tip'
    if method in GETSC:
        t = int(p.get('topoheight') or 0)
        return t if t >= 1 else 'tip'
    return None


def check(method, params, pruned):
    """Raise StateBelowPrune when the call would read pruned state. Returns the topoheight it reads (or 'tip'/None)."""
    t = state_topo(method, params)
    if isinstance(t, int) and pruned and pruned > 0 and t < pruned:
        raise StateBelowPrune(method, t, pruned)
    return t


def log_call(method, topo, call_log=None):
    path = Path(call_log or CALL_LOG)
    path.parent.mkdir(parents=True, exist_ok=True)
    rec = {'t': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds'), 'method': method,
           'topoheight': topo}
    with path.open('a', encoding='utf-8') as f:
        f.write(json.dumps(rec) + '\n')
    return rec


def guarded_call(rpc, method, params=None, pruned=None, call_log=None):
    """rpc(method, params) -> result, with the prune check first and a call-log line for state reads."""
    t = state_topo(method, params)
    if t is None:
        return rpc(method, params)
    if pruned is None:
        pruned = int((rpc('DERO.GetInfo', None) or {}).get('prunedheight') or 0)
    check(method, params, pruned)
    log_call(method, t, call_log)
    return rpc(method, params)


def read_call_log(call_log=None):
    path = Path(call_log or CALL_LOG)
    out = []
    if not path.exists():
        return out
    for l in path.read_text(encoding='utf-8', errors='replace').splitlines():
        try:
            out.append(json.loads(l))
        except ValueError:
            continue
    return out
