#!/usr/bin/env python3
"""test_detectors_r31.py — r31 dimension 0 (rft §0.12 D-20/D-21, §7 B280-B285, B287): the area detectors of
harness/intel/detectors.py find what they claim on planted Go trees, accept what is guarded, and area_intel lands each
finding as one anchored 'detector-<name>' proposal of its area.

  DT1 B280 budget-census: a derod RPC method with client-sized params and no weight is a finding, the same method with
           a remote_method_cost weight is not; a P2P handler without heavy() is a finding, one through heavy() is not
  DT2 B281 fuzz-coverage: a decoder no Fuzz* body reaches is a finding (also a same-named one in another package), one a
           target in another package reaches through a typed local is not; a target without f.Add is a no-seed-corpus
           finding, a seeded one is not
  DT3 B282 error-paths: `x, _ := strconv.Atoi(...)` and an err overwritten unread are findings, a checked err and an
           err assigned in if/else branches then checked are not; panic( in a decoder is one, in a plain func not; an
           allow entry with a reason accepts its finding, one without a reason or matching nothing is a problem
  DT4 B283 crypto-input: a compressed-point decoder whose canonical check sits behind a call whose error it drops is a
           finding missing canonical + flag; one with both checks is not
  DT5 B284 value-paths: a balance credit neither audited nor pinned is a finding; an audited coinbase line and a credit
           a test names are not
  DT6 B285 signal-coverage: an ERROR literal no census rule knows (falls to error_census's fallback) is a finding, a
           peer-answer literal (peer-caused) is not; the B269 'timestamp is too much into future' literal is classed
           (r31 d4: future_timestamp) but marks an event with no counter in its function (event-no-counter); a registry
           family no intel tool reads is a finding, one an intel tool names is not
  DT7 B287 dvm-builtins: a flat-priced builtin that hashes its string input is a disclosure-style finding, a
           length-only builtin is not; a builtin no test names is builtin-untested
  DA1 r31 detfeed: area_intel lands a detector finding as one 'detector-error-paths' proposal of the area owning the
           file (also_areas: the home area), id = pid(area, kind, finding id), stable over two runs, with the ready row
  DA2 r31 detfeed: a missing detector JSON is a 'detector-missing' proposal, a JSON whose scanned input changed a
           'detector-stale' one; the feed's 'detectors' block names each state; without detectors.py nothing changes
  DA3 r31 detfeed: a finding whose anchor no longer resolves is refused ('detector-anchor-broken', not landed), and
           feed_problems fails a landed detector proposal whose anchor stopped resolving
  DA4 r31 detstep: S7 runs `harness/intel/detectors.py --all` immediately before `area_intel.py --live`
  DA5 r31 detreg: this file is registered in the observability area that owns harness/intel/detectors.py

  python3 -I harness/kat/test_detectors_r31.py      # KATs, then the mutations; exit 0 · 3 a KAT failed · 4 missed
"""
import contextlib, importlib.util, io, json, re, shutil, sys, tempfile, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'det': 'harness/intel/detectors.py', 'ai': 'harness/intel/area_intel.py',
         'fbv': 'harness/pipeline/fix_build_verify.py', 'areas': 'harness/areas.json'}
# the tool's siblings: detectors.py loads area_intel and error_census (which loads log_intel, privkit, pruneguard)
SIBLINGS = ('harness/intel/detectors.py', 'harness/intel/area_intel.py', 'harness/intel/error_census.py',
            'harness/intel/log_intel.py', 'harness/intel/backlog_truth.py', 'harness/kit/privkit.py',
            'harness/kit/pruneguard.py', 'harness/intel/metric_registry.py')   # r31 d4: detectors reads the K8 notes
GOMOD = 'github.com/deroproject/derohe/'


def tool_root(over):
    return Path(over.get('root') or ROOT)


def load(over, key='det'):
    spec = importlib.util.spec_from_file_location(f'dt31_{key}_{uuid.uuid4().hex[:6]}', tool_root(over) / PATHS[key])
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def W(root, rel, text):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


AREAS = ('harness', 'security', 'cryptosupply', 'getworkops', 'mempool', 'chainperf', 'rpcws', 'syncp2p', 'wallet',
         'storage', 'observability', 'docs', 'disclosure', 'miner', 'tooling', 'cryptography', 'dvm')
CODE = {'harness': ['harness/'], 'security': ['p2p/controller.go'], 'syncp2p': ['p2p/'], 'rpcws': ['cmd/derod/rpc/', 'rpc/'],
        'cryptography': ['cryptography/bn256/*.go', 'cryptography/crypto/*.go'], 'dvm': ['dvm/*.go'],
        'cryptosupply': ['transaction/', 'glue/emission/'], 'chainperf': ['blockchain/'], 'observability': ['harness/intel/', 'metrics/']}


def registry(root):
    areas = []
    for a in AREAS:
        areas.append({'id': a, 'title': a, 'owner_dim': a, 'status': 'active', 'code_paths': CODE.get(a, []), 'metrics': [],
                      'kat_files': [], 'gates': [], 'gomut_prefixes': [], 'backlog': [], 'history': {}})
    W(root, 'harness/areas.json', json.dumps({'schema': 1, 'stale_rounds': 2, 'rounds': [{'id': 'r1'}], 'areas': areas}, indent=1))
    W(root, 'harness/round.json', json.dumps({'current': 'r1', 'rounds': [{'id': 'r1', 'tracks': {}}]}))


def fixture(over):
    d = Path(tempfile.mkdtemp(prefix='dt31-'))
    registry(d)
    return d


def run(over, root, name):
    D = load(over)
    return D.run(root, name, rev='fixture', allow=None)


def kinds(doc):
    return sorted((f['kind'], f['file'], f.get('why', '')[:40]) for f in doc['findings'])


# ───────────────────────────── DT1 budget-census (B280) ─────────────────────────────
def kat_dt1(over):
    r = fixture(over)
    W(r, 'cmd/derod/rpc/websocket_server.go', 'package rpc\n\nvar historical_apis = handler.Map{"getx": typed_new(GetX)}\n\n'
      'var servicemux = handler.ServiceMap{\n\t"DERO": handler.Map{\n\t\t"GetA": typed_new(GetA),\n\t\t"GetB": typed_new(GetB),\n'
      '\t\t"GetX": typed_new(GetX),\n\t},\n}\n')
    W(r, 'cmd/derod/rpc/handlers.go', 'package rpc\n\nfunc GetA(ctx context.Context, p rpc.GetA_Params) (result int, err error) {\n'
      '\tfor range p.Items {\n\t}\n\treturn\n}\n\nfunc GetB(ctx context.Context, p rpc.GetB_Params) (result int, err error) {\n'
      '\treturn\n}\n\nfunc GetX(ctx context.Context, p rpc.GetX_Params) (result int, err error) {\n\treturn\n}\n')
    W(r, 'rpc/daemon_rpc.go', 'package rpc\n\ntype (\n\tGetA_Params struct {\n\t\tItems []string `json:"items"`\n\t}\n'
      '\tGetB_Params struct {\n\t\tItems []string `json:"items"`\n\t}\n\tGetX_Params struct {\n\t\tHash string `json:"hash"`\n\t}\n)\n')
    W(r, 'cmd/derod/rpc/rpc_abuse.go', 'package rpc\n\nvar remote_method_cost = map[string]int{\n\t"DERO.GetB": 4,\n}\n')
    W(r, 'cmd/derod/rpc/ws_foreign_rate.go', 'package rpc\n\nvar foreign_method_cost = map[string]int{\n}\n')
    W(r, 'p2p/controller.go', 'package p2p\n\nfunc set_handlers(o interface{}) {\n'
      '\tset_handler(o, "Peer.Foo", func(client *rpc2.Client, args FooReq, reply *Dummy) error {\n'
      '\t\treturn getc(client).Foo(args, reply)\n\t})\n'
      '\tset_handler(o, "Peer.Bar", func(client *rpc2.Client, args BarReq, reply *Dummy) error {\n'
      '\t\tc := getc(client)\n\t\treturn heavy(c, "Peer.Bar", func() error { return c.Bar(args, reply) })\n\t})\n}\n')
    W(r, 'p2p/handlers.go', 'package p2p\n\nfunc (c *Connection) Foo(request FooReq, response *Dummy) error {\n\treturn nil\n}\n\n'
      'func (c *Connection) Bar(request BarReq, response *Dummy) error {\n\treturn nil\n}\n')
    doc = run(over, r, 'budget-census')
    got = {(f['kind'], ','.join(f.get('methods') or [])) for f in doc['findings']}
    shutil.rmtree(r, ignore_errors=True)
    want = {('rpc-no-budget', 'DERO.GetA'), ('p2p-no-budget', 'Peer.Foo')}
    return got == want, sorted(got)


# ───────────────────────────── DT2 fuzz-coverage (B281) ─────────────────────────────
def kat_dt2(over):
    r = fixture(over)
    W(r, 'transaction/tx.go', 'package transaction\n\nfunc (tx *Transaction) Deserialize(buf []byte) error {\n\treturn nil\n}\n\n'
      'func (tx *Transaction) UnmarshalHeader(buf []byte) error {\n\treturn nil\n}\n')
    W(r, 'block/block.go', 'package block\n\nfunc (bl *Block) Deserialize(buf []byte) error {\n\treturn nil\n}\n')
    W(r, 'p2p/fz_test.go', 'package p2p\n\nfunc FuzzTx(f *testing.F) {\n\tf.Add([]byte{1})\n'
      '\tf.Fuzz(func(t *testing.T, b []byte) {\n\t\tvar tx transaction.Transaction\n\t\ttx.Deserialize(b)\n\t})\n}\n\n'
      'func FuzzNoSeed(f *testing.F) {\n\tf.Fuzz(func(t *testing.T, b []byte) {\n\t\tvar tx transaction.Transaction\n\t\ttx.Deserialize(b)\n\t})\n}\n')
    doc = run(over, r, 'fuzz-coverage')
    got = {(f['kind'], f.get('decoder') or f.get('target')) for f in doc['findings']}
    shutil.rmtree(r, ignore_errors=True)
    want = {('no-fuzz-target', 'Transaction.UnmarshalHeader'), ('no-fuzz-target', 'Block.Deserialize'),
            ('no-seed-corpus', 'FuzzNoSeed')}
    return got == want, sorted(got)


# ───────────────────────────── DT3 error-paths (B282) ─────────────────────────────
EP_GO = '''package p2p

func parse_port(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func parse_checked(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func two_steps() error {
	a, err := first()
	b, err := second(a)
	if err != nil {
		return err
	}
	_ = b
	return nil
}

func branches(sim bool) error {
	var err error
	if sim {
		_, err = first()
	} else {
		_, err = first()
	}
	if err != nil {
		return err
	}
	return nil
}

func allowed_port(s string) int {
	n, _ := strconv.Atoi(s) // planted: accepted by the allow-list
	return n
}

func DecodeThing(b []byte) int {
	if len(b) == 0 {
		panic("empty")
	}
	return int(b[0])
}

func plain(b []byte) {
	panic("not a decoder")
}

func first() (int, error) { return 0, nil }

func second(a int) (int, error) { return a, nil }
'''


def kat_dt3(over):
    r = fixture(over)
    W(r, 'p2p/ep.go', EP_GO)
    D = load(over)
    allow = [{'detector': 'error-paths', 'file': 'p2p/ep.go', 'kind': 'discarded-error', 'quote': 'planted: accepted', 'reason': 'KAT'},
             {'detector': 'error-paths', 'file': 'p2p/ep.go', 'kind': 'discarded-error', 'quote': 'n, _ := strconv.Atoi(s)\n', 'reason': 'stale'},
             {'detector': 'error-paths', 'file': 'p2p/ep.go', 'kind': 'unchecked-err', 'quote': 'a, err := first()', 'reason': ''}]
    doc = D.run(r, 'error-paths', rev='fixture', allow=allow)
    got = {(f['kind'], f.get('func')) for f in doc['findings']}
    shutil.rmtree(r, ignore_errors=True)
    want = {('discarded-error', 'parse_port'), ('unchecked-err', 'two_steps'), ('panic-in-decoder', 'DecodeThing')}
    probs = doc['allow_problems']
    okp = len(probs) == 2 and any('no reason' in p for p in probs) and any('stale' in p for p in probs)
    oka = [a['func'] for a in doc['allowed']] == ['allowed_port']
    return got == want and okp and oka, (sorted(got), probs, [a['func'] for a in doc['allowed']])


# ───────────────────────────── DT4 crypto-input (B283) ─────────────────────────────
CI_BN = '''package bn256

func (e *G1) Unmarshal(m []byte) ([]byte, error) {
	if x >= 0 {
		return nil, errors.New("bn256: coordinate exceeds modulus")
	}
	if e.IsInfinity() {
		return nil, errors.New("bn256: identity")
	}
	if !e.p.IsOnCurve() {
		return nil, errors.New("bn256: malformed point")
	}
	return m, nil
}

func (e *G1) DecodeCompressed(b []byte) error {
	if b[32] > 1 {
		return errors.New("bn256: invalid flag")
	}
	if _, err := e.Unmarshal(b); err != nil {
		return err
	}
	return nil
}
'''
CI_CR = '''package crypto

func (p *Point) DecodeCompressed(b []byte) error {
	g := new(G1)
	g.Unmarshal(b)
	return nil
}
'''


def kat_dt4(over):
    r = fixture(over)
    W(r, 'cryptography/bn256/b.go', CI_BN)
    W(r, 'cryptography/crypto/c.go', CI_CR)
    doc = run(over, r, 'crypto-input')
    got = {(f.get('entry'), tuple(f.get('missing') or ())) for f in doc['findings']}
    shutil.rmtree(r, ignore_errors=True)
    want = {('Point.DecodeCompressed', ('canonical', 'flag'))}
    return got == want, sorted(got)


# ───────────────────────────── DT5 value-paths (B284) ─────────────────────────────
def kat_dt5(over):
    r = fixture(over)
    W(r, 'blockchain/transaction_execute.go', 'package blockchain\n\nfunc (c *Chain) process_miner_transaction(fees uint64) {\n'
      '\tfull_reward := base_reward + fees\n\t_ = full_reward\n}\n\nfunc (c *Chain) process_bonus_credit(nb *NonceBalance) {\n'
      '\tnb.Balance = nb.Balance.Plus(new(big.Int).SetUint64(5)) // credit\n}\n\nfunc (c *Chain) process_pinned_credit(nb *NonceBalance) {\n'
      '\tnb.Balance = nb.Balance.Plus(new(big.Int).SetUint64(6)) // credit\n}\n')
    W(r, 'blockchain/credit_test.go', 'package blockchain\n\nfunc TestPinned(t *testing.T) {\n\tprocess_pinned_credit(nil)\n}\n')
    W(r, 'glue/emission/emission.go', 'package emission\n\nfunc audit(base, fees uint64) Split {\n\tsp := SplitReward(base, fees, 10, 1)\n'
      '\treturn sp\n}\n')
    doc = run(over, r, 'value-paths')
    got = {(f['kind'], f.get('func'), f.get('value_class')) for f in doc['findings']}
    shutil.rmtree(r, ignore_errors=True)
    want = {('value-path-unchecked', 'process_bonus_credit', 'transfer')}
    return got == want, sorted(got)


# ───────────────────────────── DT6 signal-coverage (B285) ─────────────────────────────
def kat_dt6(over):
    r = fixture(over)
    W(r, 'cmd/derod/main.go', f'package main\n\nimport (\n\t"{GOMOD}blockchain"\n)\n\nfunc main() {{\n}}\n')
    W(r, 'blockchain/blockchain.go', 'package blockchain\n\nfunc (chain *Blockchain) add() {\n'
      '\tblock_logger.Error(fmt.Errorf("Rejecting Block, timestamp is too much into future, make sure that system clock is correct"), "")\n'
      '\tlogger.V(1).Error(err, "peer answered with garbage")\n\tlogger.Error(err, "widget frobnication failed")\n}\n\n'
      'var foo = metrics.NewCounter("dero_foo_total")\n'
      'var bar = metrics.NewCounter("dero_bar_total")\n')
    W(r, 'metrics/metric_registry.json', json.dumps({'families': [
        {'name': 'dero_foo_total', 'type': 'counter', 'area': 'chainperf', 'source': 'blockchain/blockchain.go'},
        {'name': 'dero_bar_total', 'type': 'counter', 'area': 'chainperf', 'source': 'blockchain/blockchain.go'},
        {'name': 'go_gc_total', 'type': 'counter', 'area': 'observability', 'source': 'vendored'}]}, indent=1))
    W(r, 'harness/intel/reader_x.py', "WANT = ('dero_bar_total',)\n")
    doc = run(over, r, 'signal-coverage')
    got = {(f['kind'], f.get('family') or f.get('text', '')[:40]) for f in doc['findings']}
    shutil.rmtree(r, ignore_errors=True)
    want = {('event-no-counter', 'Rejecting Block, timestamp is too much i'), ('log-unmapped', 'widget frobnication failed'),
            ('family-unread', 'dero_foo_total')}
    return got == want, sorted(got)


# ───────────────────────────── DT7 dvm-builtins (B287) ─────────────────────────────
DVM_TABLE = '''package dvm

func init() {
	func_table["sha256"] = []func_data{func_data{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 25000, StorageCost: 0, PtrS: dvm_sha256}}
	func_table["strlen"] = []func_data{func_data{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 20000, StorageCost: 0, PtrU: dvm_strlen}}
	func_table["blid"] = []func_data{func_data{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 2000, StorageCost: 0, PtrS: dvm_blid}}
}

func dvm_sha256(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result string) {
	checkargscount(1, len(expr.Args))
	input_eval := dvm.eval(expr.Args[0])
	if _, ok := input_eval.(string); !ok {
		panic("input argument must be valid string")
	}
	hash := sha256.Sum256([]byte(input_eval.(string)))
	return true, string(hash[:])
}

func dvm_strlen(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(1, len(expr.Args))
	asset_eval := dvm.eval(expr.Args[0])
	if _, ok := asset_eval.(string); !ok {
		panic("argument must be valid string")
	}
	return true, uint64(len([]byte(asset_eval.(string))))
}

func dvm_blid(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result string) {
	checkargscount(0, len(expr.Args))
	return true, "x"
}
'''


def kat_dt7(over):
    r = fixture(over)
    W(r, 'dvm/dvm_functions.go', DVM_TABLE)
    W(r, 'dvm/dvm.go', 'package dvm\n\nfunc RunSmartContract(SC *SmartContract) (err error) {\n\tdefer func() {\n'
      '\t\tif r := recover(); r != nil {\n\t\t\terr = fmt.Errorf("x")\n\t\t}\n\t}()\n\treturn\n}\n')
    W(r, 'dvm/b_test.go', 'package dvm\n\nvar src = `Function T() Uint64\n10 RETURN STRLEN(SHA256("a"))\nEnd Function`\n')
    doc = run(over, r, 'dvm-builtins')
    got = {(f['kind'], f.get('builtin')) for f in doc['findings']}
    shutil.rmtree(r, ignore_errors=True)
    want = {('disclosure-style', 'sha256'), ('builtin-untested', 'blid')}
    return got == want, sorted(got)


# ───────────────────────────── DA1-DA3 area_intel integration ─────────────────────────────
EP_DA = '''package p2p

func helper() error { return nil }

func caller() {
	_ = helper()
}
'''


def feed_fixture(over, with_tool=True):
    """a tree with the tool (and its siblings) copied in, one error-paths finding in p2p/ (area syncp2p), every detector
    JSON written by the tool itself, so all are fresh."""
    r = fixture(over)
    W(r, 'p2p/da.go', EP_DA)
    if with_tool:
        for rel in SIBLINGS:
            W(r, rel, (tool_root(over) / rel).read_text())
        spec = importlib.util.spec_from_file_location(f'dt31_fx_{uuid.uuid4().hex[:6]}', r / PATHS['det'])
        D = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(D)
        for n in D.DETECTORS:
            D.write(r, D.run(r, n, rev='fixture', allow=[]))
    return r


def evaluate(over, r):
    AI = load(over, 'ai')
    with contextlib.redirect_stdout(io.StringIO()):
        doc, pdoc, err = AI.evaluate(r)
    return AI, pdoc


def kat_da1(over):
    r = feed_fixture(over)
    AI, p1 = evaluate(over, r)
    _, p2 = evaluate(over, r)
    det = [p for p in p1['proposals'] if p['kind'].startswith('detector-')]
    fdoc = json.loads((r / 'harness/runtime/detector_error-paths.json').read_text())
    shutil.rmtree(r, ignore_errors=True)
    bad = []
    if len(det) != 1 or len(fdoc['findings']) != 1:
        return False, f'{len(det)} detector proposals, {len(fdoc["findings"])} findings: {[p["kind"] for p in det]}'
    p, f = det[0], fdoc['findings'][0]
    if p['kind'] != 'detector-error-paths' or p['area'] != 'syncp2p':
        bad.append(f"kind/area {p['kind']}/{p['area']}")
    if p['id'] != AI.pid('syncp2p', 'detector-error-paths', f['id']) or p['id'] not in [x['id'] for x in p2['proposals']]:
        bad.append(f"id {p['id']} not stable")
    if p.get('also_areas') != ['harness'] or p.get('finding_id') != f['id']:
        bad.append(f"also_areas {p.get('also_areas')} finding_id {p.get('finding_id')}")
    if not p.get('suggested_row', '').startswith('| B? | (B282, detector-error-paths)') or 'p2p/da.go:6' not in p['suggested_row']:
        bad.append(f"row {p.get('suggested_row')}")
    ev = p['evidence'][0]
    if (ev.get('file'), ev.get('line'), ev.get('quote')) != ('p2p/da.go', 6, '_ = helper()'):
        bad.append(f'evidence {ev}')
    return not bad, '; '.join(bad) or p['id']


def kat_da2(over):
    r = feed_fixture(over)
    (r / 'harness/runtime/detector_value-paths.json').unlink()
    W(r, 'p2p/da.go', EP_DA + '\n// an edit after the scan\n')
    AI, p = evaluate(over, r)
    ks = {(x['area'], x['kind'], x['id'].rsplit('-', 1)[0]) for x in p['proposals'] if x['kind'] in ('detector-missing', 'detector-stale')}
    st = {n: v['state'] for n, v in (p.get('detectors') or {}).items()}
    shutil.rmtree(r, ignore_errors=True)
    r0 = feed_fixture(over, with_tool=False)
    W(r0, 'harness/runtime/detector_error-paths.json', '{}')
    _, p0 = evaluate(over, r0)
    shutil.rmtree(r0, ignore_errors=True)
    stale_n = sum(1 for v in st.values() if v == 'stale')
    ok = (('cryptosupply', 'detector-missing', 'AP-cryptosupply-detector-missing') in ks and
          ('harness', 'detector-stale', 'AP-harness-detector-stale') in ks and len(ks) == 1 + stale_n and
          st.get('value-paths') == 'missing' and st.get('error-paths') == 'stale' and st.get('budget-census') == 'fresh' and
          'detectors' not in p0 and not any(x['kind'].startswith('detector-') for x in p0['proposals']))
    return ok, (sorted(ks), st, 'detectors' in p0)


def kat_da3(over):
    r = feed_fixture(over)
    W(r, 'p2p/da.go', EP_DA.replace('_ = helper()', '_ =  helper()'))   # the quote is gone: the anchor breaks
    D = load(over)
    for n in D.DETECTORS:           # fresh again: only the anchor is broken
        doc = json.loads((r / f'harness/runtime/detector_{n}.json').read_text())
        D.write(r, dict(doc, fingerprint=D.fingerprint(r, doc['input_files'])))
    AI, p = evaluate(over, r)
    ks = sorted(x['kind'] for x in p['proposals'] if x['kind'].startswith('detector-'))
    reg = json.loads((r / 'harness/areas.json').read_text())
    landed = {'id': 'AP-syncp2p-detector-error-paths-x', 'area': 'syncp2p', 'kind': 'detector-error-paths', 'severity': 'low',
              'finding_id': 'DF-x', 'evidence': [{'file': 'p2p/da.go', 'quote': '_ = helper()', 'line': 6}]}
    probs = AI.feed_problems({'proposals': [landed]}, reg, r)
    shutil.rmtree(r, ignore_errors=True)
    ok = ks == ['detector-anchor-broken'] and len(probs) == 1 and 'no longer resolves' in probs[0]
    return ok, (ks, probs)


# ───────────────────────────── DA4 / DA5 S7 step and registration ─────────────────────────────
def kat_da4(over):
    src = (tool_root(over) / PATHS['fbv']).read_text()
    m = re.search(r'def s7_project\(\):(.*?)\n    steps \+= ', src, re.S)
    body = m.group(1) if m else ''
    steps = re.findall(r"\[sys\.executable, '([^']+)'(?:, '([^']+)')?", body)
    i = next((k for k, s in enumerate(steps) if s == ('harness/intel/detectors.py', '--all')), None)
    j = next((k for k, s in enumerate(steps) if s == ('harness/intel/area_intel.py', '--live')), None)
    return i is not None and j is not None and j == i + 1, (i, j)


def kat_da5(over):
    reg = json.loads((tool_root(over) / PATHS['areas']).read_text())
    AI = load(over, 'ai')
    owner = AI.area_of(reg['areas'], 'harness/intel/detectors.py')
    reg_k = [a['id'] for a in reg['areas'] if 'harness/kat/test_detectors_r31.py' in a.get('kat_files', [])]
    return owner == 'observability' and reg_k == ['observability'], (owner, reg_k)


KATS = [('DT1', kat_dt1), ('DT2', kat_dt2), ('DT3', kat_dt3), ('DT4', kat_dt4), ('DT5', kat_dt5), ('DT6', kat_dt6),
        ('DT7', kat_dt7), ('DA1', kat_da1), ('DA2', kat_da2), ('DA3', kat_da3), ('DA4', kat_da4), ('DA5', kat_da5)]
OWNERS = {'B280': ['DT1'], 'B281': ['DT2'], 'B282': ['DT3'], 'B283': ['DT4'], 'B284': ['DT5'], 'B285': ['DT6'],
          'B287': ['DT7'], 'r31 detfeed': ['DA1', 'DA2', 'DA3'], 'r31 detstep': ['DA4'], 'r31 detreg': ['DA5']}
MUTATIONS = [
    ('det', "        if name in weights:\n", "        if False:\n", 'B280: a per-method weight is not budget evidence'),
    ('det', "        if re.search(r'\\bheavy\\(', reg.split('})', 1)[0]):", "        if False:",
     'B280: a heavy() registration is not budget evidence'),
    ('det', "        cov = [t for t in targets if (f, fn['start']) in t['reach']]", "        cov = []",
     'B281: no decoder is ever covered'),
    ('det', "            seed = 'f.Add(' in b or", "            seed = True or", 'B281: every target counts as seeded'),
    ('det', "            if t and any(g[1]['recv'] == t for g in cands):\n                cands = [g for g in cands if g[1]['recv'] == t]\n",
     "            if False:\n                cands = [g for g in cands if g[1]['recv'] == t]\n",
     'B281: a typed local is not narrowed (the call from another package is dropped)'),
    ('det', "    if any(re.fullmatch(q.replace('.', r'\\.').replace('*', r'\\w*'), f'{chain}.{name}') for q in STD_QUAL):\n        return name, True",
     "    if any(re.fullmatch(q.replace('.', r'\\.').replace('*', r'\\w*'), f'{chain}.{name}') for q in STD_QUAL):\n        return name, None",
     'B282: a discarded standard-library error is not reported'),
    ('det', "            return True                                       # overwritten unread", "            return False",
     'B282: an err overwritten unread is not reported'),
    ('det', "            left = True                                       # the block (or the switch branch) ends: `} else {`, `case`",
     "            pass", 'B282: an else branch counts as the same block (false finding)'),
    ('det', "                    and a.get('quote') and a['quote'] in f['quote'] and str(a.get('reason') or '').strip()), None)",
     "                    and a.get('quote') and a['quote'] in f['quote']), None)", 'B282: an allow entry without a reason accepts'),
    ('det', "                if DEC_NAME_RX.match(fn['name']) and re.search(r'\\bpanic\\(', s) and 'panic' not in seen_kind:",
     "                if re.search(r'\\bpanic\\(', s) and 'panic' not in seen_kind:", 'B282: a panic outside a decoder is reported'),
    ('det', "                    if bare and returns_error(gfn['sig']):    # a check whose error the caller drops does not protect it",
     "                    if False:    # a check whose error the caller drops does not protect it",
     'B283: a check behind a dropped error counts'),
    ('det', "REQUIRED = {'point-compressed': ('canonical', 'flag'),", "REQUIRED = {'point-compressed': ('canonical',),",
     'B283: the flag byte is not required of a compressed point'),
    ('det', "            a = aud.get(cls)\n", "            a = aud.get(cls) or 'any'\n", 'B284: every class counts as audited'),
    ('det', "                pin = pinned(name)\n", "                pin = None\n", 'B284: a test naming the function does not pin it'),
    ('det', "            mapped = not (cls == 'unclassified' or (cls == 'node-bug' and why == 'an ERROR no rule explains'))",
     "            mapped = True", 'B285: the census fallback counts as a class'),
    ('det', "        if rd:\n            continue\n", "        if False:\n            continue\n", 'B285: a family a tool reads is a finding'),
    ('det', "        if grows and not size_bound:", "        if not size_bound:", 'B287: a length-only builtin is disclosure-style'),
    ('det', "        pin = next((f for f, t in tests + kats if rx.search(t)), None)\n        census.append({'builtin'",
     "        pin = 'x'\n        census.append({'builtin'", 'B287: an untested builtin passes'),
    ('ai', "        found += _det_found.get(aid, [])          # r31 dimension 0: one proposal per detector finding\n", "",
     'r31 detfeed: detector findings never land'),
    ('ai', "            aid = area_of(areas_open, str(f.get('file'))) or home_eff", "            aid = home_eff",
     'r31 detfeed: a finding lands in the home area, not the file owner'),
    ('ai', "            if (aid, k, key) in _det_extra:                       # r31: a detector finding's ready §7 row, co-owners\n                p.update(_det_extra[(aid, k, key)])\n",
     "", 'r31 detfeed: no ready row, no co-owner'),
    ('ai', "        if reasons:\n            k = 'detector-missing'", "        if False:\n            k = 'detector-missing'",
     'r31 detfeed: a missing or stale detector is skipped silently'),
    ('det', "    if doc.get('fingerprint') != fp:", "    if False:", 'r31 detfeed: an input change does not make a detector stale'),
    ('ai', "            if not resolved(a):\n                st['refused'] += 1", "            if False:\n                st['refused'] += 1",
     'r31 detfeed: a broken anchor lands'),
    ('ai', "            if str(p.get('kind', '')).startswith('detector-') and p.get('finding_id'):",
     "            if False:", 'r31 detfeed: feed_problems ignores a broken detector anchor'),
    ('fbv', "             [sys.executable, 'harness/intel/detectors.py', '--all'],\n", "",
     'r31 detstep: S7 no longer runs the detectors before area_intel'),
    ('areas', ',\n    "harness/kat/test_detectors_r31.py"', '', 'r31 detreg: the KAT file is registered to no area'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_dt31', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run_kats(over):
    res = []
    for name, fn in KATS:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                ok, det = fn(over)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        res.append((name, bool(ok), str(det)))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr31 detectors KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='dt31-mut-') as d:
            for rel in set(SIBLINGS) | set(PATHS.values()):      # the mutant tool root: the tools load their siblings
                (Path(d) / rel).parent.mkdir(parents=True, exist_ok=True)
                (Path(d) / rel).write_text((ROOT / rel).read_text(encoding='utf-8'), encoding='utf-8')
            (Path(d) / PATHS[key]).write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({'root': d}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r31 detectors KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed or coupled else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
