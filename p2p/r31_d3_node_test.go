package p2p

// r31 dimension 3 (node; dero-rft §7 B269 (a)-(c), DF-error-paths-2ae6fec909): a block refused for a future timestamp
// is one attributed INFO line with the sender's skew (no console ERROR, no block hex, no stack below V(2)), counted per
// peer and in a skew histogram, never penalised; the "Incoming Block could not be added" echo names the peer by its
// pseudonym; the TLS key generator's error is checked. The 50 ms rule itself is upstream consensus and unchanged
// (consensus guard S1).

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/errormsg"
	"github.com/deroproject/derohe/globals"
	"github.com/go-logr/logr"
)

// r31_sink records Info lines (with level and kv) and Error calls (with message and error text).
type r31_sink struct {
	sync.Mutex
	infos  []r25_line
	errors []string
}

func (s *r31_sink) Init(logr.RuntimeInfo) {}
func (s *r31_sink) Enabled(int) bool      { return true }
func (s *r31_sink) Info(level int, msg string, kv ...interface{}) {
	s.Lock()
	defer s.Unlock()
	m := map[string]interface{}{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[fmt.Sprint(kv[i])] = kv[i+1]
	}
	s.infos = append(s.infos, r25_line{level, msg, m})
}
func (s *r31_sink) Error(err error, msg string, kv ...interface{}) {
	s.Lock()
	defer s.Unlock()
	s.errors = append(s.errors, msg+" | "+fmt.Sprint(err))
}
func (s *r31_sink) WithValues(kv ...interface{}) logr.LogSink { return s }
func (s *r31_sink) WithName(name string) logr.LogSink         { return s }
func (s *r31_sink) find(msg string) (out []r25_line) {
	s.Lock()
	defer s.Unlock()
	for _, l := range s.infos {
		if l.msg == msg {
			out = append(out, l)
		}
	}
	return
}

func r31_sum(prefix string) (sum float64) {
	for _, v := range r28_metric_values(prefix) {
		sum += v
	}
	return
}

// B269 (a)+(b): the attributed line carries skew_ms; the skew is counted per peer and in the histogram even when the
// line is rate-limited; no offence is scored; the series exist from the start.
func TestR31FutureSkewAttributedPerPeer(t *testing.T) {
	r25_reset(t)
	s := &r31_sink{}
	logger = logr.New(s)
	if _, ok := r28_metric_values("p2p_future_blocks_total")["p2p_future_blocks_total"]; !ok {
		t.Fatal("p2p_future_blocks_total is not registered at start")
	}
	if _, ok := r28_metric_values("p2p_future_block_skew_seconds_bucket")[`p2p_future_block_skew_seconds_bucket{le="0.05"}`]; !ok {
		t.Fatal("p2p_future_block_skew_seconds is not on /metrics before its first event")
	}
	n0, h0, pen0 := future_blocks_total.Get(), r31_sum("p2p_future_block_skew_seconds_count"), r31_sum("p2p_penalty_events_total")
	le10 := r28_metric_values("p2p_future_block_skew_seconds_bucket")[`p2p_future_block_skew_seconds_bucket{le="10"}`]
	conn_sink := &r31_sink{}
	c := &Connection{Peer_ID: 0x5ec3, logger: logr.New(conn_sink)}
	for i := 0; i < 2; i++ {
		bl := &block.Block{Height: 7888575 + uint64(i), Timestamp: uint64(globals.Time().UTC().UnixMilli()) + 5000}
		note_block_result(c, &block.Complete_Block{Bl: bl}, errormsg.ErrFutureTimestamp, false)
	}
	lines := s.find("Block rejected")
	if len(lines) != 1 || lines[0].level != 0 || lines[0].kv["reason"] != "future_timestamp" || lines[0].kv["peer_id"] != "0000000000005ec3" {
		t.Fatalf("one console-level attributed line expected (the second is rate-limited): %+v", lines)
	}
	sk, _ := lines[0].kv["skew_ms"].(int64)
	if sk < 4000 || sk > 5000 {
		t.Fatalf("skew_ms %v, want about 5000", lines[0].kv["skew_ms"])
	}
	if len(s.errors) != 0 || len(conn_sink.errors)+len(conn_sink.infos) != 0 {
		t.Fatalf("no ERROR and nothing on the address-named logger: %v / %v %v", s.errors, conn_sink.errors, conn_sink.infos)
	}
	if c.obs.future_blocks.Load() != 2 || c.obs.future_skew_max.Load() < 4000 || c.obs.future_skew_max.Load() > 5000 {
		t.Fatalf("per-peer: blocks %d max %d", c.obs.future_blocks.Load(), c.obs.future_skew_max.Load())
	}
	le10b := r28_metric_values("p2p_future_block_skew_seconds_bucket")[`p2p_future_block_skew_seconds_bucket{le="10"}`]
	if future_blocks_total.Get() != n0+2 || r31_sum("p2p_future_block_skew_seconds_count") != h0+2 || le10b != le10+2 {
		t.Fatalf("node-wide: blocks +%d histogram +%v le10 +%v", future_blocks_total.Get()-n0, r31_sum("p2p_future_block_skew_seconds_count")-h0, le10b-le10)
	}
	if r31_sum("p2p_penalty_events_total") != pen0 {
		t.Fatal("a future block must not score an offence (B269 b: never a ban for one event)")
	}
	// another reason carries no skew and touches no skew counter
	note_block_result(c, &block.Complete_Block{Bl: &block.Block{Height: 9, Timestamp: 1}}, errormsg.ErrInvalidPoW, false)
	l2 := s.find("Block rejected")
	if len(l2) != 2 || l2[1].kv["skew_ms"] != nil || c.obs.future_blocks.Load() != 2 {
		t.Fatalf("invalid_pow line %+v future %d", l2, c.obs.future_blocks.Load())
	}
	// a block whose time has passed by the verdict is booked at 0 s, not as a negative sample
	if got := note_future_skew(nil, 1000, 2000); got != -1000 {
		t.Fatalf("skew %d", got)
	}
}

// B269 (c): the "Incoming Block could not be added" echo is file-log V(2) from the package logger with the peer_id;
// nothing reaches the logger named after the peer's address, and chain_sync.go no longer prints it there.
func TestR31IncomingBlockFailureLinePseudonymous(t *testing.T) {
	r25_reset(t)
	s := &r31_sink{}
	logger = logr.New(s)
	conn_sink := &r31_sink{}
	c := &Connection{Peer_ID: 0x2801, logger: logr.New(conn_sink), Addr: &net.UDPAddr{IP: net.ParseIP("192.0.2.7"), Port: 11011}}
	log_incoming_block_failure(c, errormsg.ErrFutureTimestamp, false)
	log_incoming_block_failure(c, errormsg.ErrPastMissing, true)
	a := s.find("Incoming Block could not be added due to some error")
	b := s.find("Incoming Block could not be added due to missing past, so skipping future block")
	if len(a) != 1 || len(b) != 1 || a[0].level != 2 || a[0].kv["peer_id"] != "0000000000002801" || len(s.errors) != 0 {
		t.Fatalf("lines %+v %+v errors %v", a, b, s.errors)
	}
	for _, l := range append(a, b...) {
		for _, v := range l.kv {
			if strings.Contains(fmt.Sprint(v), "192.0.2.7") {
				t.Fatalf("address in %+v", l)
			}
		}
	}
	if len(conn_sink.errors)+len(conn_sink.infos) != 0 {
		t.Fatalf("address-named logger used: %v %v", conn_sink.errors, conn_sink.infos)
	}
	src, err := os.ReadFile("chain_sync.go")
	if err != nil {
		t.Fatal(err)
	}
	for i, l := range strings.Split(string(src), "\n") {
		if strings.Contains(l, "connection.logger") && strings.Contains(l, "Incoming Block could not be added") {
			t.Fatalf("chain_sync.go:%d still prints the line on the address-named logger: %s", i+1, strings.TrimSpace(l))
		}
	}
}

// B269 (a) end to end on a simulator chain: the chain's own rule refuses a block stamped 60 s ahead (the verdict is
// unchanged: ErrFutureTimestamp); its log is one V(1) Info with the skew, the generic "Block rejected by chain" is
// file-log only (the block hex and the stack at V(2)), and no ERROR is printed for it anywhere.
func TestR31FutureTimestampLogHygieneOnChain(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a simulator chain")
	}
	r25_reset(t)
	old_args, old_logger := globals.Arguments, globals.Logger
	globals.Arguments = map[string]interface{}{"--data-dir": t.TempDir(), "--testnet": true, "--simulator": true}
	defer func() { globals.Arguments, globals.Logger = old_args, old_logger }()
	globals.Initialize()
	core := &r31_sink{}
	globals.Logger = logr.New(core)
	ch, err := blockchain.Blockchain_Start(map[string]interface{}{"--simulator": true})
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Shutdown()
	old_chain := chain
	chain = ch
	defer func() { chain = old_chain }()
	p2p_sink := &r31_sink{}
	logger = logr.New(p2p_sink)

	miner := r25_genesis_miner(t)
	var c *Connection
	for i := 0; i < 3; i++ {
		cbl, _, err := ch.Create_new_miner_block(miner)
		if err != nil {
			t.Fatal(err)
		}
		cbl.Bl.MiniBlocks = append(cbl.Bl.MiniBlocks, blockchain.ConvertBlockToMiniblock(*cbl.Bl, miner))
		if err, ok := c.add_block(cbl); !ok {
			t.Fatalf("block %d: %v", i, err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	core.Lock()
	core.errors, core.infos = nil, nil
	core.Unlock()
	fut, _, err := ch.Create_new_miner_block(miner)
	if err != nil {
		t.Fatal(err)
	}
	fut.Bl.Timestamp = uint64(globals.Time().UTC().UnixMilli()) + 60_000
	fut.Bl.MiniBlocks = append(fut.Bl.MiniBlocks, blockchain.ConvertBlockToMiniblock(*fut.Bl, miner))
	if err, ok := c.add_block(fut); ok || !errors.Is(err, errormsg.ErrFutureTimestamp) {
		t.Fatalf("future block: %v %v (the rule must still refuse it)", err, ok)
	}
	if len(core.errors) != 0 {
		t.Fatalf("a future block must print no ERROR: %v", core.errors)
	}
	rule := core.find("Rejecting Block, timestamp is too much into future")
	if len(rule) != 1 || rule[0].level != 1 {
		t.Fatalf("rule line %+v", rule)
	}
	if sk, _ := rule[0].kv["skew_ms"].(int64); sk < 59000 || sk > 60000 || rule[0].kv["limit_ms"] != 50 {
		t.Fatalf("rule line kv %+v", rule[0].kv)
	}
	for _, l := range core.find("Block rejected by chain") {
		if (l.kv["bl"] != nil || l.kv["stack"] != nil) && l.level < 2 {
			t.Fatalf("block hex / stack below V(2): level %d", l.level)
		}
	}
	if n := len(core.find("Block rejected by chain")); n != 2 {
		t.Fatalf("generic echo lines %d, want 2 (V(1) short + V(2) detail)", n)
	}
	att := p2p_sink.find("Block rejected")
	if len(att) != 1 || att[0].kv["reason"] != "future_timestamp" || att[0].kv["skew_ms"] == nil {
		t.Fatalf("attributed line %+v", att)
	}
}

// DF-error-paths-2ae6fec909: a failing key generator panics with ITS error (it was overwritten by the next call, so
// the failure surfaced as a nil-key crash inside x509).
func TestR31TLSKeyGenErrorChecked(t *testing.T) {
	sentinel := errors.New("r31 keygen failure")
	old := tls_key_gen
	tls_key_gen = func() (*ecdsa.PrivateKey, error) { return nil, sentinel }
	defer func() { tls_key_gen = old }()
	var got interface{}
	func() {
		defer func() { got = recover() }()
		generate_random_tls_cert()
	}()
	if e, ok := got.(error); !ok || !errors.Is(e, sentinel) {
		t.Fatalf("panic value %v, want the key generator's error", got)
	}
	tls_key_gen = old
	if c := generate_random_tls_cert(); len(c.Certificate) != 1 {
		t.Fatal("a working generator yields one certificate")
	}
}

// DF-fuzz-coverage-2160264e4a: ParseIPNoError (peer-supplied address strings: ban lists, peer lists, the console) had
// no fuzz target. Properties: never panics; equals ParseIP's ip; a bare IP comes back canonical; "" exactly on error.
func FuzzR31ParseIPNoError(f *testing.F) {
	for _, s := range []string{"", "1.2.3.4", "1.2.3.4:11011", "[::1]:80", "::FFFF:1.2.3.4", "2001:DB8::1", "host:1", ":", "[", "1.2.3.4:", "999.1.1.1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := ParseIPNoError(s)
		ip, err := ParseIP(s)
		if out != ip {
			t.Fatalf("%q: ParseIPNoError %q, ParseIP %q %v", s, out, ip, err)
		}
		if err != nil && out != "" {
			t.Fatalf("%q: an error must yield \"\", got %q", s, out)
		}
		if _, _, e := net.SplitHostPort(s); e != nil {
			if p := net.ParseIP(s); p != nil && out != p.String() {
				t.Fatalf("%q: bare IP not canonical: %q, want %q", s, out, p.String())
			}
		}
	})
}
