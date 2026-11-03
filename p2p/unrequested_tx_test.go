package p2p

import (
	"net"
	"os"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/transaction"
)

func TestTxWantTakesEachAskedTxOnce(t *testing.T) {
	a, b := reg_tx(1).GetHash(), reg_tx(2).GetHash()
	w := new_tx_want([][32]byte{a, b, a})
	if w.left != 2 {
		t.Fatalf("left %d, want 2 (duplicates in the ask count once)", w.left)
	}
	if w.take(crypto.Hash{0x55}) {
		t.Fatal("an unasked txid was taken")
	}
	if !w.take(a) || w.take(a) {
		t.Fatal("an asked txid must be taken exactly once")
	}
	if !w.take(b) || w.left != 0 {
		t.Fatalf("left %d after both asked txids arrived", w.left)
	}
}

func reset_penalties() {
	penalty_mu.Lock()
	penalty_map = map[string]*misbehaviour{}
	penalty_mu.Unlock()
}

func penalty_of(ip string) float64 {
	penalty_mu.Lock()
	defer penalty_mu.Unlock()
	if m := penalty_map[ip]; m != nil {
		return m.score
	}
	return 0
}

// A GetObject answer stuffed with txs we never asked for: none reaches the chain (chain is nil here, so one that did
// would panic and be recovered without the score), each is counted, and the peer is scored once.
func TestUnrequestedTxsDroppedAndScored(t *testing.T) {
	reset_penalties()
	const ip = "198.51.100.77"
	c := &Connection{logger: globals.Logger, Addr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 11011}}
	resp := Objects{Txs: [][]byte{reg_tx(1).Serialize(), reg_tx(2).Serialize(), reg_tx(3).Serialize()}}
	before := p2p_unrequested_txs.Get()
	c.process_object_response_want(resp, 0, false, new_tx_want([][32]byte{reg_tx(9).GetHash()}))
	if got := p2p_unrequested_txs.Get() - before; got != 3 {
		t.Fatalf("dropped %d unrequested txs, want 3", got)
	}
	if s := penalty_of(ip); s != PENALTY_POINTS["malformed_request"] {
		t.Fatalf("score %.1f, want exactly one malformed_request (%.0f)", s, PENALTY_POINTS["malformed_request"])
	}
}

// Once the connection is closed (for example banned by an earlier tx of the same response), the rest of the response
// is not processed at all.
func TestTxLoopStopsAfterExit(t *testing.T) {
	reset_penalties()
	const ip = "198.51.100.78"
	c := &Connection{logger: globals.Logger, Addr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 11011}}
	c.exited.Store(1)
	before := p2p_unrequested_txs.Get()
	resp := Objects{Txs: [][]byte{reg_tx(1).Serialize(), reg_tx(2).Serialize()}}
	c.process_object_response_want(resp, 0, false, new_tx_want([][32]byte{reg_tx(9).GetHash()}))
	if p2p_unrequested_txs.Get() != before || penalty_of(ip) != 0 {
		t.Fatalf("a closed connection's response was still processed")
	}
}

// Honest-path cost of the r21 filter: one INV for one tx = one new_tx_want plus one take.
func BenchmarkTxWantHonestOneTx(b *testing.B) {
	h := reg_tx(1).GetHash()
	list := [][32]byte{h}
	for i := 0; i < b.N; i++ {
		w := new_tx_want(list)
		if !w.take(h) {
			b.Fatal("not taken")
		}
	}
}

// For scale: the tx decode every received tx already pays before the filter.
func BenchmarkTxDecodeRegistration(b *testing.B) {
	raw := reg_tx(1).Serialize()
	for i := 0; i < b.N; i++ {
		var tx transaction.Transaction
		if err := deserialize_tx(&tx, raw); err != nil {
			b.Fatal(err)
		}
		_ = tx.GetHash()
	}
}

// r21 merge (SEC21-04 verifier: reverting the NotifyINV call site to nil left every p2p test green): the INV path must
// hand process_object_response_want the asked-for txids, or unrequested txs are admitted again.
func TestNotifyINVPassesTxWant(t *testing.T) {
	src, err := os.ReadFile("rpc_notifications.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "want := new_tx_want(need.Tx_list)\n\t\t\tif err = c.process_object_response_want(oresponse, request.Sent, false, want)") {
		t.Fatal("NotifyINV no longer restricts the GetObject reply to the requested txids")
	}
}
