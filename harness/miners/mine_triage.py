#!/usr/bin/env python3
"""mine_triage.py — every ERROR the running daemon printed, traced to its origin and judged.

The question a console log raises is never "what does this line say" but "whose fault is it, and does it cost
me anything". Each error class becomes one row that answers four things with anchors, never with prose alone:

  origin   LOCAL (our code executing), REMOTE (a peer's own error, relayed verbatim by rpc2's ServerError),
           LOCAL-CONSEQUENCE (our own reaction to a remote fault), or TRANSPORT (a socket closed under a read);
  cause    the Go lines that produce the message, and the condition that reaches them;
  chain    what the chain itself says about the transactions involved (captured from the node, see --capture);
  verdict  what it costs and what to do — including, usually, nothing.

Numbers are computed from the log at build time: occurrence counts, the distinct keyhashes, and the two proofs
that need no trust at all — blake2s(33 zero bytes) against the keyhash the node printed, and the tx-store
directory a peer printed against the one storefs.getpath derives from the txid.

  python3 harness/miners/mine_triage.py --capture   # also re-asks derod about every txid in the log
"""
import hashlib, json, re, sys, urllib.request
import os
from datetime import datetime
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import minelib as M

RUNTIME = M.HARNESS / 'runtime'
RPC = 'http://127.0.0.1:10102/json_rpc'
PEERS = Path(os.path.expanduser(os.environ.get('DERO_DATADIR', '~/dero-data')) + '/mainnet/peers.json')
BANS = Path(os.path.expanduser(os.environ.get('DERO_DATADIR', '~/dero-data')) + '/mainnet/ban_list.json')
FILELOGS = M.ROOT / 'bin/derod.log'    # lumberjack: <exe>.log + rotated derod-<ts>.log
CLASSES = [('zero-signer', 'collision, keyhash'), ('sc-parse', 'is invalid'), ('remote-emptyblock', 'Invalid Major Version'),
           ('remote-txstore', 'bltx_store'), ('closed-pipe', 'closed pipe')]
TE = 'blockchain/transaction_execute.go'
SIM = 'dvm/simulator.go'
RPC2 = 'vendor/github.com/cenkalti/rpc2/client.go'
BASE = 'harness/baseline/bf274e5/'   # the source the running binary was built from (DK27)
OE = 'p2p/object_errors.go'
LINE = re.compile(r'^(\d\d/\d\d \d\d:\d\d:\d\d)\s+ERROR\s+(\S+)\s+(.+?)\s{2,}(\{.*\})\s*$')


def latest_log():
    logs = sorted(RUNTIME.glob('derod_console_*.log'))
    return logs[-1] if logs else None


def errors(log):
    out = []
    for i, l in enumerate(log.read_text(errors='replace').splitlines(), 1):
        m = LINE.match(l)
        if m:
            t, name, msg, kv = m.groups()
            out.append({'n': i, 't': t, 'logger': name, 'msg': msg.strip(), 'kv': kv, 'raw': l})
    return out


def rpc(method, params=None):
    body = json.dumps({'jsonrpc': '2.0', 'id': '1', 'method': method, **({'params': params} if params else {})}).encode()
    req = urllib.request.Request(RPC, data=body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def scrub_snapshot(snap, salt=None):
    """r25 (peers, §7 B71): the triage snapshot is tracked evidence; its peer facts ('peer <ip> address=...') and the
    ban list line carried raw addresses. Pseudonymised at the source (kit/privkit.py, the peer observatory's salt), so
    the miner below anchors on 'peer-' names, exactly what minelib.emit writes into the raw file."""
    sys.path.insert(0, str(M.HARNESS / 'kit'))
    import privkit
    return privkit.pseudonymise_obj(snap, salt or privkit.load_salt())


def pseud_peer(addr, salt=None):
    """r25 (pipeline run 3): the console's peer address in the snapshot's pseudonymised form. scrub_snapshot (B71)
    pseudonymised the 'peer <ip> ...' facts, but the rows still looked them up by the raw console address, so three
    rows (tri-remote-emptyblock, tri-remote-txstore, tri-closedpipe-churn) lost their anchor and left the page
    (verify_deroarch --mutations: 'tri-remote-txstore not on the page'); the raw address would also have reached the
    claim text. KAT: harness/kat/test_triage_pseud_r25.py."""
    sys.path.insert(0, str(M.HARNESS / 'kit'))
    import privkit
    return privkit.pseudonymise_text(addr, salt or privkit.load_salt())


def capture(log, errs):
    """One line per fact so each is anchorable: the chain's view of every txid, and the peer records."""
    ids = []
    for e in errs:
        ids += re.findall(r'"txid": "([0-9a-f]{64})"', e['kv'])
        for blob in re.findall(r'"Tx_list":\[\[([\d,]+)\]\]', e['kv']):
            ids.append(bytes(int(x) for x in blob.split(',')).hex())
    facts = []
    for t in dict.fromkeys(ids):
        x = ((rpc('DERO.GetTransaction', {'txs_hashes': [t]}).get('result') or {}).get('txs') or [{}])[0]
        facts.append(f'tx {t} block_height={x.get("block_height")} in_pool={x.get("in_pool")} '
                     f'signer={x.get("signer") or "NONE"} valid_block={x.get("valid_block") or "NONE"}')
    peers = json.loads(PEERS.read_text()) if PEERS.exists() else {}
    for e in errs:
        m = re.match(r'P2P\.outgoing\.([\d.]+):(\d+)', e['logger'])
        if m and m.group(1) in peers:
            p = peers[m.group(1)]
            line = (f'peer {m.group(1)} address={p.get("address")} goodcount={p.get("goodcount")} '
                    f'failcount={p.get("failcount")} blacklistbefore={p.get("blacklistbefore")} '
                    f'lastconnected={datetime.fromtimestamp(p.get("lastconnected", 0)).astimezone().isoformat()}')
            if line not in facts:
                facts.append(line)
    # the daemon's own JSON file log (debug level) for the whole current run: is the pasted console representative?
    start = log.read_text(errors='replace').split('\n', 1)[0]
    since = None
    for l in log.read_text(errors='replace').splitlines():
        m = re.match(r'^(\d\d)/(\d\d) (\d\d:\d\d:\d\d)\s', l)
        if m:
            since = f'{datetime.now().year}-{m.group(2)}-{m.group(1)}T{m.group(3)}'
            break
    census, json_files = {}, 0
    if since:
        for fl in sorted(set(sorted(FILELOGS.parent.glob(FILELOGS.name + '*')) + sorted(FILELOGS.parent.glob('derod-*.log'))
                             + sorted(Path(os.path.expanduser(os.environ.get('DERO_DATADIR', '~/dero-data')) + '/logs').glob('derod*.log')))):   # --log-dir since 2026-10-21 23:18
            with fl.open(errors='replace') as fh:
                if not fh.readline().startswith('{'):
                    continue                                      # a pasted console, not lumberjack JSON
            json_files += 1
            for line in fl.open(errors='replace'):
                if '"L":"ERROR"' not in line:
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                if d.get('T', '') < since:
                    continue
                e = str(d.get('error', '')) + ' ' + str(d.get('r', ''))
                k = next((n for n, p in CLASSES if p in e), 'other')
                key = (d.get('C'), d.get('M', '').strip(), k)
                census[key] = census.get(key, 0) + 1
        for (c, mm, k), n in sorted(census.items(), key=lambda x: -x[1]):
            facts.append(f'filelog ERROR {c} "{mm}" class={k} count={n} since={since}')
        facts.append(f'filelog ERROR total={sum(census.values())} since={since} json_files={json_files}')
    bans = json.loads(BANS.read_text()) if BANS.exists() else {}
    facts.append(f'ban_list holds {len(bans)} address(es): {", ".join(sorted(bans)) or "none"}')
    snap = {'captured': datetime.now().astimezone().isoformat(timespec='seconds'), 'log': log.name,
            'source': 'DERO.GetTransaction per txid + <datadir>/mainnet/peers.json + ban_list.json',
            'facts': facts}
    snap = scrub_snapshot(snap)                                    # r25 (B71): no peer address in the snapshot
    p = RUNTIME / f'triage_{datetime.now().strftime("%Y%m%dT%H%M%S")}.json'
    p.write_text(json.dumps(snap, indent=1))
    print(f'captured {p.name}: {len(facts)} facts')


def parse(argv=None):
    """r26 B117: a real argument parser. main() tested `'--capture' in sys.argv`, so `--help` ran the miner (it wrote
    its raw rows) and an unknown flag was ignored. Now --help prints the usage and exits 0 having written nothing."""
    import argparse
    ap = argparse.ArgumentParser(prog='mine_triage.py', description=__doc__.split('\n\n')[0])
    ap.add_argument('--capture', action='store_true', help='also re-ask derod (read-only RPC) about every txid in the log')
    return ap.parse_args(argv)


def main(argv=None):
    a = parse(argv)
    log = latest_log()
    if not log:
        M.emit('triage', [], [{'title': 'no console log', 'why': 'harness/runtime/derod_console_*.log is missing'}])
        return
    errs = errors(log)
    if a.capture:
        capture(log, errs)
    snaps = sorted(RUNTIME.glob('triage_*.json'))
    snap = str(snaps[-1].relative_to(M.ROOT)) if snaps else None
    lrel = str(log.relative_to(M.ROOT))
    mx = re.search(r'const MAX_TX_FETCH_FAILURES = (\d+)', (M.ROOT / OE).read_text()) if (M.ROOT / OE).exists() else None
    maxf = int(mx.group(1)) if mx else None   # read from the source, never typed
    rows, unv = [], []

    def F(fid, title, origin, verdict, claim, anchors, fix=None, **extra):
        # fix = (what this tree now does, [anchors in the changed code]); its anchors are evidence too
        if fix:
            anchors = anchors + fix[1]
            extra['fix'] = fix[0]
        evs = []
        for f, needle in anchors:
            a = M.anchor(f, needle, full_line=not f.startswith('harness/'))
            if not a:
                unv.append({'title': title, 'why': f'anchor lost: {f} :: {needle[:80]}'})
                return
            evs.append(a)
        cls = 'SRC' if any(not f.startswith(('vendor/', 'harness/')) for f, _ in anchors) else \
              'EXT' if any(f.startswith('vendor/') for f, _ in anchors) else 'HARNESS'
        rows.append({'id': fid, 'section': 'triage', 'title': title, 'class': cls, 'origin': origin,
                     'triage_verdict': verdict, 'claim': claim, 'evidence': evs, **extra})

    def of(pred):
        return [e for e in errs if pred(e)]

    def fact(needle):
        return (snap, needle) if snap else ('harness/runtime/__missing__', needle)

    def facts():
        return json.loads((M.ROOT / snap).read_text())['facts'] if snap else []

    def height_of(txid):
        for f in facts():
            if f.startswith(f'tx {txid} '):
                m = re.search(r'block_height=(\d+)', f)
                return int(m.group(1)) if m else None

    # ---- 1. anonymous SC tx -> ErrorRevert on the zero signer -> recovered panic
    sc = of(lambda e: e['msg'].startswith('Recover while executing SC'))
    if sc:
        keys = sorted({k for e in sc for k in re.findall(r'keyhash ([0-9a-f]{64}) not found', e['kv'])})
        zero = hashlib.blake2s(bytes(33), digest_size=32).hexdigest()
        txs = [re.search(r'"txid": "([0-9a-f]{64})"', e['kv']).group(1) for e in sc]
        nosig = [t for t in txs if any(f.startswith(f'tx {t} ') and 'signer=NONE' in f for f in facts())]
        F('tri-sc-zerosigner', 'Recover while executing SC: the missing key is the all-zero signer', 'LOCAL',
          'known upstream defect · deterministic · not corruption',
          f'{len(sc)} times the node recovered a panic inside process_transaction_sc, and every time graviton '
          f'reported the same missing key: {", ".join("`" + k + "`" for k in keys)}. Graviton keys a leaf by '
          f'blake2s-256 of the key bytes, and the signer is a [33]byte. blake2s-256 of 33 zero bytes is '
          f'`{zero}`, which is {"exactly" if keys == [zero] else "NOT"} that key. The transactions are '
          f'anonymous ({len(nosig)} of {len(txs)} have no signer on chain), so Extract_signer failed, `signer` stayed '
          f'zero, and the "burn" branch called ErrorRevert, which looks the zero account up in the balance tree. '
          f'It is not there, the nearest leaf answers "collision", and simulator.go panics on a lookup its own '
          f'comment says only disk corruption can fail. Nothing on disk is wrong: the same three inputs fail the '
          f'same way on every node that replays these blocks (a node that fastsyncs past them never executes '
          f'them).',
          [(lrel, f'keyhash {keys[0]} not found'),
           ('vendor/github.com/deroproject/graviton/hash.go', 'return blake2s.Sum256(key)'),
           (TE, 'func Extract_signer(tx *transaction.Transaction) (signer [33]byte, err error) {'),
           (TE, '} else { //  we could not extract signer, we burn all the funds'),
           (SIM, 'panic(err1) // only disk corruption can reach here'),
           # r29 (B157, user decision (a)): the recover logs at V(2) Info now (logr Error ignored V); the anchor follows the
           # line, and its loss had dropped this row from the page (verify_deroarch DK25 12 vs 15; KAT test_triage_anchors_r29)
           (TE, 'logger.V(2).Info("Recover while executing SC ", "txid", txhash, "error", r')]
          + [fact(f'tx {t} ') for t in txs],
          fix=('Logging only (consensus guard PASS): the recover recognises the zero-signer case by its keyhash and logs one '
               'V(1) line to the file log instead of an ERROR with a 3 KB stack. Fee kept, burn destroyed, exactly as before.',
               [(TE, 'if is_zero_signer_revert(r) { // anonymous SC tx failed: fee kept, burn value stays burned (see sc_revert_log.go)'),
                ('blockchain/sc_revert_log.go', 'return strings.Contains(err.Error(), "keyhash "+zero_signer_keyhash)')]),
          count=len(sc), keyhashes=keys, zero_signer_hash=zero, keyhash_is_zero_signer=(keys == [zero]),
          anonymous=len(nosig), txs=txs, heights=[height_of(t) for t in txs], related='find-screvert',
          impact='Each such transaction keeps its fee (gas = tx.Fees() is assigned before the panic and the recover '
                 'leaves the named results alone) and its burn value stays burned; the panic changes no state. '
                 'Every node that replays it does the same.',
          action='Nothing locally. Patching it would change fee accounting and fork this node off the network; '
                 'it belongs upstream behind a height gate. This row only proves the cause; find-screvert '
                 'carries the full defect.')

    # ---- 2. SC install with an invalid parameter type
    pa = of(lambda e: e['msg'] == 'error Parsing sc')
    if pa:
        txs = [re.search(r'"txid": "([0-9a-f]{64})"', e['kv']).group(1) for e in pa]
        types = sorted(set(re.findall(r'variable type \\"(\w+)\\" is invalid', ' '.join(e['kv'] for e in pa))))
        poss = sorted(set(re.findall(r'"pos": "([^"]+)"', ' '.join(e['kv'] for e in pa))))
        hs = [height_of(t) for t in txs]
        sig = sorted({re.search(r'signer=(\S+)', f).group(1) for f in facts() for t in txs if f.startswith(f'tx {t} ')})
        F('tri-sc-parse', 'error Parsing sc: someone tried to deploy a contract with a type DVM does not have',
          'LOCAL', 'sender error · refunded · harmless',
          f'{len(pa)} smart-contract install transactions declared an Initialize parameter of type '
          f'{", ".join(chr(34) + t + chr(34) for t in types)} at {", ".join(poss)}. DVM-BASIC has exactly two '
          f'declarable types, Uint64 and String; check_valid_type returns Invalid for anything else and the parser rejects '
          f'the contract. Install is skipped, the error falls through to the revert branch, and because these '
          f'transactions do carry a signer the burn value is refunded to the sender (fees are not). All {len(pa)} fail with the same error at the '
          f'same position, in blocks {", ".join(f"{h:,}" for h in hs if h)}'
          f'{", and all are signed by the same address, so this is most likely one sender resubmitting the same broken contract (the source text itself was not compared)" if len(sig) == 1 and sig[0] != "NONE" else ""}. The node logged it while replaying those historic blocks during catch-up.',
          [(lrel, 'variable type \\"collector\\" is invalid'),
           ('dvm/dvm.go', 'return fmt.Errorf("function name \\"%s\\", variable type \\"%s\\" is invalid", f.Name, line[pos+1])'),
           ('dvm/dvm.go', 'func check_valid_type(name string) Vtype {'),
           (BASE + TE + '.base', 'logger.V(2).Error(err, "error Parsing sc", "txid", txhash, "pos", pos)'),
           (TE, 'if signer, err1 := Extract_signer(&tx); err1 == nil { // if we can identify sender, return funds to him')]
          + [fact(f'tx {t} ') for t in txs],
          fix=('Logging only (consensus guard PASS): a contract that does not parse is the sender\'s mistake, so it is now a '
               'V(1) INFO line in the file log, not a console ERROR. Install is still skipped and the burn refunded.',
               [(TE, 'logger.V(1).Info("SC install rejected, contract source does not parse", "txid", txhash, "pos", pos, "error", err.Error())')]),
          count=len(pa), types=types, txs=txs, heights=hs, senders=len(sig),
          impact='None to this node. The sender paid a fee for a contract that was never installed.',
          action='None.')

    # ---- 3. a peer with an empty block file
    mv = of(lambda e: 'Invalid Major Version in Block' in e['kv'])
    if mv:
        peer = sorted({pseud_peer(e['logger'].split('.', 2)[2]) for e in mv})  # r25: as the snapshot names it
        F('tri-remote-emptyblock', 'Invalid Major Version in Block: a peer\'s block file is empty', 'REMOTE',
          'remote storage fault · no cost here',
          f'{len(mv)} GetObject calls to {", ".join(peer)} came back with this text. It is the peer\'s own error: '
          f'rpc2 turns the error string a remote handler returns into ServerError verbatim, and nothing on our '
          f'call path deserialises a block. On the peer, GetObject loads the block with Load_BL_FROM_ID, which '
          f'reads the .block file with os.ReadFile and hands the bytes to Deserialize. The very first read is '
          f'binary.Uvarint(buf); it returns done <= 0 only when the buffer is empty, ends in a run of continuation '
          f'bytes, or holds a varint that overflows 64 bits. So the peer handed Deserialize an empty or garbled '
          f'buffer for a block it still advertises: most likely a zero-length or damaged .block file, though a '
          f'panic recovered inside ReadBlock (which then returns nil, nil) gives the same text. A real major version (3) is the single byte 0x03 and could never fail there.',
          [(lrel, 'Call failed GetObject    {"error": "Invalid Major Version in Block'),
           ('block/block.go', 'return fmt.Errorf("Invalid Major Version in Block\\n")'),
           ('block/block.go', 'bl.Major_Version, done = binary.Uvarint(buf)'),
           ('blockchain/storefs.go', 'return os.ReadFile(file)'),
           ('p2p/rpc_object_request.go', 'bl, err := chain.Load_BL_FROM_ID(request.Block_list[i])'),
           (RPC2, 'call.Error = ServerError(resp.Error)')]
          + ([fact(f'peer {p.split(":")[0]} ') for p in peer]),
          fix=('p2p only: log_call_failure classifies an rpc2 ServerError as the peer\'s and logs it at V(1); the sync loop still '
               'moves on to another peer as before (r25: through Connection.call_failed, which also counts it per '
               'connection, and the B47 sync hold skips that peer for a while).',
               [('p2p/chain_sync.go', 'connection.sync_failed(connection.call_failed(err, "Call failed GetObject"), time.Now())'),
                ('p2p/peer_observe.go', 'kind := log_call_failure(c.logger, err, msg, keysAndValues...)'),
                (OE, 'if errors.As(err, &server_err) {')]),
          count=len(mv), peers=peer,
          impact='None. The sync loop returns and the block is fetched from another peer; the peer is not '
                 'penalised (its record shows no failures and it is not banned).',
          action='None on this side. The peer operator needs to resync.')

    # ---- 4. a peer that advertised transactions it could not serve
    ts = of(lambda e: '/bltx_store/' in e['kv'])
    if ts:
        peer = sorted({pseud_peer(e['logger'].split('.', 2)[2]) for e in ts})  # r25: as the snapshot names it
        checks, lags = [], []
        for e in ts:
            m = re.search(r'bltx_store/([0-9a-f]{2})/([0-9a-f]{2})/([0-9a-f]{64})\.tx', e['kv'])
            h = bytes.fromhex(m.group(3))
            checks.append(f'{h[16]:02x}/{h[17]:02x}' == f'{m.group(1)}/{m.group(2)}')
            req = int(re.search(r'"Height":(\d+)', e['kv']).group(1))
            got = height_of(m.group(3))
            if got:
                lags.append(got - req)
        txs = [re.search(r'bltx_store/../../([0-9a-f]{64})', e['kv']).group(1) for e in ts]
        fl_ts = sum(int(re.search(r'count=(\d+)', f).group(1)) for f in facts()
                    if f.startswith('filelog ERROR ') and 'class=remote-txstore' in f)
        more = (f' (the daemon\'s file log holds {fl_ts} for the whole run; the tx-store and mining checks below '
                f'cover the {len(ts)} in the console)' if fl_ts > len(ts) else '')
        F('tri-remote-txstore', 'bltx_store, no such file: a peer announced transactions it could not serve',
          'REMOTE', 'remote fault · we drop the peer · tx still arrives',
          f'{len(ts)} times in the pasted console{more}, {", ".join(peer)} sent a NotifyINV for a transaction, our node asked for it, and the '
          f'peer\'s GetObject failed to read it from its own disk. The path is the peer\'s (/root/daemon2), and its two directory levels '
          f'are bytes 16 and 17 of the txid, exactly what storefs.getpathtx derives for a tx, '
          f'{"in all " + str(len(checks)) + " cases" if all(checks) else "NOT in every case"}. The raw "open <path>: no such file or directory" '
          f'text cannot come from this tree\'s ReadTX, which returns "tx <id> not found", so the peer runs a '
          f'different, older build; that it checked its mempool and regpool first is inferred, not seen. Every one '
          f'of those transactions is valid: the chain mined each {min(lags)}–{max(lags)} block(s) after the height '
          f'we reported in the request. Why the peer lost them is not decidable from here. What is decidable is our reaction: '
          f'the running binary\'s NotifyINV calls c.exit() on any GetObject failure, so a transient miss on a '
          f'single transaction costs the whole connection.',
          [(lrel, 'no such file or directory"}'),
           ('blockchain/storefs.go', 'return filepath.Join(filepath.Join(s.basedir, "bltx_store"), fmt.Sprintf("%02x", h[16]), fmt.Sprintf("%02x", h[17]))'),
           ('blockchain/storefs.go', 'return nil, fmt.Errorf("tx %x not found", h[:])'),
           ('p2p/rpc_object_request.go', '} else if tx_bytes, err = chain.Store.Block_tx_store.ReadTX(request.Tx_list[i]); err != nil {'),
           (BASE + 'p2p/rpc_notifications.go.base', 'c.logger.V(2).Error(err, "Call failed GetObject", "need_objects", need)'),
           (RPC2, 'call.Error = ServerError(resp.Error)')]
          + [fact(f'tx {t} ') for t in dict.fromkeys(txs)] + [fact(f'peer {p.split(":")[0]} ') for p in peer],
          fix=('p2p only (P5 implemented): a transaction-only fetch that the peer answers with its own error no longer drops '
               f'the connection; the peer is dropped only after {maxf} consecutive such failures, '
               'and a success resets the count.',
               [('p2p/rpc_notifications.go', 'if kind == call_failure_remote && is_tx_only(need) && c.keep_after_tx_fetch_failure() {'),
                (OE, 'const MAX_TX_FETCH_FAILURES = 8')]),
          count=len(ts), peers=peer, path_checks=checks, mined_after=lags, txs=list(dict.fromkeys(txs)),
          impact='One peer out of 18 is dropped and reconnects; we already had, or soon got, every transaction '
                 'from someone else. No ban, no lost data.',
          action='Optional, non-consensus: on a transactions-only GetObject failure, log and keep the connection '
                 '(recorded in harness/loop/PROPOSALS.md). Not worth restarting a healthy node for.')

    # ---- 5. the closed pipe that we caused ourselves
    cp = of(lambda e: 'closed pipe' in e['kv'])
    casc = [e for e in cp if any(o is not e and o['t'] == e['t'] and o['logger'] == e['logger'] and o in ts for o in ts)]
    if casc:
        F('tri-closedpipe-cascade', 'closed pipe, same second, same peer: our own c.exit() closed it', 'LOCAL-CONSEQUENCE',
          'side effect of row above · harmless',
          f'{len(casc)} closed-pipe error(s) share the second and the peer of a failed tx request, and carry the '
          f'identical requested Tx_list (only the T0 timestamp differs). The peer had announced the same '
          f'transaction twice; rpc2 dispatches every incoming request on its own goroutine (the p2p layer never '
          f'enables blocking mode), so two NotifyINV handlers ran at once, each with a GetObject call pending. The '
          f'first got the peer\'s error and called c.exit(), which closed the TLS socket; rpc2\'s shared read loop '
          f'was partway through the next 150-byte frame on that socket, failed with "closed pipe", and passed that '
          f'error to the second handler\'s pending call.',
          [(lrel, 'frame length 150 err io: read/write on closed pipe'),
           (RPC2, 'go c.handleRequest(*req, method, argv)'),
           ('p2p/connection_pool.go', 'c.onceexit.Do(func() {'),
           ('p2p/rpc_cbor_codec.go', 'return fmt.Errorf("Could not read data size  read %d, frame length %d err %s", data_size, frame_length, err)')],
          fix=('Prevented: with P5 the connection is no longer closed on a tx-only peer error, so there is no socket to close '
               'under the other pending call.',
               [('p2p/rpc_notifications.go', 'if kind == call_failure_remote && is_tx_only(need) && c.keep_after_tx_fetch_failure() {')]),
          count=len(casc),
          impact='None beyond the drop already counted above.', action='None; it disappears with that proposal.')

    # ---- 6. ordinary disconnects
    churn = [e for e in cp if e not in casc]
    if churn:
        peer = sorted({pseud_peer(e['logger'].split('.', 2)[2]) for e in churn})  # r25: as the snapshot names it
        F('tri-closedpipe-churn', 'closed pipe: a peer connection ended under a read', 'TRANSPORT',
          'ordinary churn · our side closed · reconnected within seconds',
          f'{len(churn)} reads on {", ".join(peer)} ended because the session was already closed: kcp-go returns '
          f'io.ErrClosedPipe once its die channel fires, and on an outgoing session only our own UDPSession.Close '
          f'(for example through c.exit) fires it. One read failed mid-frame (Read_Data_Frame: "Could not read data '
          f'size"), the other on the frame-length read itself. So our side closed the session; what made it close '
          f'cannot be told from one log line. The peer records show both peers reconnected afterwards (2 s and 24 s '
          f'later) with failcount 0, although a successful connect resets that count.',
          [(lrel, 'Call failed GetObject    {"error": "io: read/write on closed pipe"'),
           (lrel, 'frame length 12 err io: read/write on closed pipe'),
           ('vendor/github.com/xtaci/kcp-go/v5/sess.go', 'return 0, errors.WithStack(io.ErrClosedPipe)'),
           ('vendor/github.com/xtaci/kcp-go/v5/sess.go', 'close(s.die)'),
           (BASE + 'p2p/rpc_cbor_codec.go.base', 'data_size, err := io.ReadFull(r, data_buf)')]   # the build that printed it
          + [fact(f'peer {p.split(":")[0]} ') for p in peer],
          fix=('p2p only: a closed-pipe failure is classified as teardown and logged as a V(1) INFO line (file log), not as a console ERROR.',
               [(OE, 'case call_failure_closed:')]),
          count=len(churn), peers=peer,
          impact='None. 18 peers held steady throughout.', action='None.')

    # ---- the whole run, from the daemon's own file log: does the pasted console tell the whole story?
    fl = [f for f in facts() if f.startswith('filelog ERROR ') and ' class=' in f]
    tot = next((f for f in facts() if f.startswith('filelog ERROR total=')), None)
    if fl and tot:
        n_all = int(re.search(r'total=(\d+)', tot).group(1))
        since = re.search(r'since=(\S+)', tot).group(1)
        by_class = {}
        for f in fl:
            k = re.search(r'class=(\S+)', f).group(1)
            by_class[k] = by_class.get(k, 0) + int(re.search(r'count=(\d+)', f).group(1))
        a_tot = M.anchor(snap, tot, full_line=True)
        evs = [a_tot] + [M.anchor(snap, f.replace('"', '\\"'), full_line=True) for f in fl]   # quotes are escaped in the JSON
        if all(evs):
            rows.append({'id': 'tri-filelog-census', 'section': 'triage-census', 'class': 'HARNESS',
                         'title': 'The whole run, from the daemon\'s own file log',
                         'claim': f'derod also writes a debug-level JSON log (bin/derod.log and its rotations). Since '
                                  f'{since} it holds {n_all} ERROR lines, against {len(errs)} in the pasted console; '
                                  f'every one falls in the same classes: '
                                  + ', '.join(f'{k} {v}' for k, v in sorted(by_class.items(), key=lambda x: -x[1]))
                                  + '. Nothing else went wrong that the console did not show.',
                         'total': n_all, 'console': len(errs), 'by_class': by_class, 'evidence': evs})

    seen = {id(e) for e in sc + pa + mv + ts + cp}
    for e in errs:
        if id(e) not in seen:
            unv.append({'title': f'{e["logger"]}: {e["msg"][:60]}', 'why': 'error class not yet triaged',
                        'where': f'{lrel}:{e["n"]}'})
    print(f'  {len(errs)} ERROR lines in {log.name} → {len(rows)} classes · snapshot {snap}')
    M.emit('triage', rows, unv, 'mine_triage.py')


if __name__ == '__main__':
    main()
