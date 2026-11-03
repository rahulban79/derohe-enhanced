package p2p

import (
	"fmt"
	"io"
	"testing"

	"github.com/cenkalti/rpc2"
	"github.com/go-logr/logr"
	pkgerrors "github.com/pkg/errors"
)

func TestClassifyCallError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want call_failure
	}{
		// texts are the ones the node printed (harness/runtime/derod_console_20261021.log)
		{"peer has an empty block file", rpc2.ServerError("Invalid Major Version in Block\n"), call_failure_remote},
		{"peer lost a tx", rpc2.ServerError("open /root/daemon2/mainnet/bltx_store/82/39/d5bda2dde5e3a4f3831b2a353c9d584e8239f47ac130ae5b213301ddcad20d64.tx: no such file or directory"), call_failure_remote},
		{"kcp session closed", pkgerrors.WithStack(io.ErrClosedPipe), call_failure_closed},
		{"frame body never came", fmt.Errorf("Could not read data size  read %d, frame length %d err %s", 0, 150, io.ErrClosedPipe), call_failure_closed},
		{"rpc2 client shut down", rpc2.ErrShutdown, call_failure_closed},
		{"anything else", fmt.Errorf("i/o timeout"), call_failure_other},
		{"nil", nil, call_failure_other},
	}
	for _, c := range cases {
		if got := classify_call_error(c.err); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestIsTxOnly(t *testing.T) {
	var h [32]byte
	if !is_tx_only(ObjectList{Tx_list: [][32]byte{h}}) {
		t.Error("a tx-only request must be recognised")
	}
	if is_tx_only(ObjectList{Tx_list: [][32]byte{h}, Block_list: [][32]byte{h}}) {
		t.Error("a request with blocks is not tx-only")
	}
	if is_tx_only(ObjectList{Tx_list: [][32]byte{h}, Chunk_list: [][32 + 1 + 32]byte{{}}}) {
		t.Error("a request with chunks is not tx-only")
	}
	if is_tx_only(ObjectList{}) {
		t.Error("an empty request is not tx-only")
	}
}

func TestTxFetchFailureBudget(t *testing.T) {
	// the documented policy (PROPOSALS P5, ARCHITECTURE section 27, the triage row) is "dropped on the 8th consecutive
	// failure"; a test that only used the constant symbolically let it drift to any value (go_mutate gm-budget-size)
	if MAX_TX_FETCH_FAILURES != 8 {
		t.Fatalf("MAX_TX_FETCH_FAILURES = %d; the documented budget is 8 — change the docs with it", MAX_TX_FETCH_FAILURES)
	}
	c := &Connection{}
	for i := 1; i < MAX_TX_FETCH_FAILURES; i++ {
		if !c.keep_after_tx_fetch_failure() {
			t.Fatalf("connection dropped after only %d failures", i)
		}
	}
	if c.keep_after_tx_fetch_failure() {
		t.Fatalf("connection kept after %d consecutive failures", MAX_TX_FETCH_FAILURES)
	}
	c.tx_fetch_succeeded()
	if !c.keep_after_tx_fetch_failure() {
		t.Fatal("a success must reset the budget")
	}
}

func TestEmptyReplyDoesNotResetBudget(t *testing.T) {
	var h [32]byte
	need := ObjectList{Tx_list: [][32]byte{h}}
	c := &Connection{}
	for i := 1; i < MAX_TX_FETCH_FAILURES; i++ {
		c.keep_after_tx_fetch_failure()
	}
	c.note_tx_fetch_reply(need, 0, 1) // an empty reply (r22: counts as the 8th failure)
	if c.keep_after_tx_fetch_failure() {
		t.Fatal("an empty reply reset the budget; a peer could dodge it forever")
	}
	c.note_tx_fetch_reply(need, 1, 1)
	if !c.keep_after_tx_fetch_failure() {
		t.Fatal("a reply that delivered a tx must reset the budget")
	}
}

// records the V level of every Info and whether Error was used
type level_sink struct {
	infos  []int
	errors int
}

func (s *level_sink) Init(logr.RuntimeInfo)                          {}
func (s *level_sink) Enabled(int) bool                               { return true }
func (s *level_sink) Info(level int, msg string, kv ...interface{})  { s.infos = append(s.infos, level) }
func (s *level_sink) Error(err error, msg string, kv ...interface{}) { s.errors++ }
func (s *level_sink) WithValues(kv ...interface{}) logr.LogSink      { return s }
func (s *level_sink) WithName(name string) logr.LogSink              { return s }

// The default file log keeps level >= -1 (V(1)) and the console level >= 0 (globals.go). Remote and closed
// failures must land in the file log and off the console: exactly V(1). Anything else stays an ERROR.
func TestCallFailureLogLevels(t *testing.T) {
	for _, c := range []struct {
		err   error
		level int
	}{{rpc2.ServerError("Invalid Major Version in Block\n"), 1}, {pkgerrors.WithStack(io.ErrClosedPipe), 1}} {
		s := &level_sink{}
		log_call_failure(logr.New(s), c.err, "Call failed GetObject")
		if s.errors != 0 || len(s.infos) != 1 || s.infos[0] != c.level {
			t.Errorf("%v: infos %v errors %d, want one V(%d) info", c.err, s.infos, s.errors, c.level)
		}
	}
	s := &level_sink{}
	log_call_failure(logr.New(s), fmt.Errorf("i/o timeout"), "Call failed GetObject")
	if s.errors != 1 {
		t.Errorf("an unclassified failure must stay an ERROR, got infos %v errors %d", s.infos, s.errors)
	}
}
