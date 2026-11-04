"""stateguard.py — r25 (tooling class 'probes hitting pruned state', dero-rft §7 B85, §5 Forensics data).

On 2026-11-03 a read-only discovery probe sent DERO.GetEncryptedBalance at topoheights below the live node's prune point;
the handler panicked on purpose (`cmd/derod/rpc/rpc_dero_getencryptedbalance.go:92`), the recover turned it into an
rpc_internal_error, and the node logged 4 ERROR lines with a stack, which fail G15 for the rest of that derod run. A
read-only RPC can still write to the live node's log (lesson #53).

Every harness probe that asks for STATE (a balance, an SC, a tree read) goes through `check()` first: a request whose
topoheight is below GetInfo.prunedheight is refused here, before it reaches the node. `topoheight` -1 / absent means
'the top', which every node holds. Block and transaction reads (GetBlock, GetTransaction) are not state reads: a pruned
node answers them from its block store or with an ordinary not-found error, never a panic.

Pure except `pruned_height()` (one read-only DERO.GetInfo). KAT: harness/kat/test_stateguard_r25.py (SG1-SG3).
"""
import json, urllib.request

# the read methods that open a balance / SC tree snapshot at a requested topoheight (cmd/derod/rpc)
STATE_METHODS = ('DERO.GetEncryptedBalance', 'DERO.GetSC', 'DERO.NameToAddress', 'DERO.GetRandomAddress')
TOPO_KEYS = ('topoheight', 'TopoHeight', 'topo_height')


# how each handler reads an absent / small topoheight (cmd/derod/rpc): GetEncryptedBalance takes ANY value >= 0 as a
# topoheight (`p.TopoHeight >= 0`, rpc_dero_getencryptedbalance.go:48), so an omitted field (JSON default 0) reads the
# state at topoheight 0; only a negative value means the top. GetSC reads a topoheight only when it is >= 1
# (rpc_dero_getsc.go:57). The others default to the top.
ZERO_IS_TOPO = ('DERO.GetEncryptedBalance',)


def requested_topo(params, method=None):
    """the topoheight a request asks for, or None for 'the top'. For GetEncryptedBalance an absent field is 0 and 0 is a
    real topoheight; for the other methods absent, None, 0 or a negative value is the top. Pure."""
    zero_real = method in ZERO_IS_TOPO
    if not isinstance(params, dict):
        return 0 if zero_real else None
    for k in TOPO_KEYS:
        if k in params and params[k] is not None:
            try:
                v = int(params[k])
            except (TypeError, ValueError):
                return None
            if v < 0 or (v == 0 and not zero_real):
                return None
            return v
    return 0 if zero_real else None


def check(method, params, pruned):
    """(ok, why) for one request. A state read below `pruned` (GetInfo.prunedheight) is refused; an unknown prune point
    (None) refuses every state read at an explicit topoheight, so a probe that could not read GetInfo never guesses.
    Non-state methods always pass. Pure."""
    if method not in STATE_METHODS:
        return True, 'not a state read'
    t = requested_topo(params, method)
    if t is None:
        return True, 'state read at the top'
    if pruned is None:
        return False, f'{method} at topoheight {t}: the prune point is unknown (GetInfo unread), refused'
    if t < int(pruned):
        return False, f'{method} at topoheight {t} is below prunedheight {pruned}: refused (B85)'
    return True, f'topoheight {t} >= prunedheight {pruned}'


def pruned_height(url='http://127.0.0.1:10102/json_rpc', timeout=8):
    """GetInfo.prunedheight of the node at `url` (read-only), or None when it cannot be read"""
    try:
        rq = urllib.request.Request(url, headers={'Content-Type': 'application/json'},
                                    data=json.dumps({'jsonrpc': '2.0', 'id': '1', 'method': 'DERO.GetInfo'}).encode())
        return int(json.loads(urllib.request.urlopen(rq, timeout=timeout).read())['result']['prunedheight'])
    except Exception:                                                # noqa: BLE001 — unknown = refuse explicit reads
        return None
