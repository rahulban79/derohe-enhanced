package main

import (
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/deroproject/derohe/block"
)

func testBlob(nonce uint32, final bool) string {
	mbl := block.MiniBlock{Version: 1, Height: 7799233, PastCount: 1, Final: final, HighDiff: final}
	mbl.Nonce[0] = nonce
	return hex.EncodeToString(mbl.Serialize())
}

// the miner must name a share by the same hash derod's record_submission computes (Deserialize + GetHash)
func TestLedgerHashIsDerodsHash(t *testing.T) {
	b := testBlob(7, false)
	raw, _ := hex.DecodeString(b)
	var mbl block.MiniBlock
	if err := mbl.Deserialize(raw); err != nil {
		t.Fatal(err)
	}
	h, ok := miniblockHash(raw)
	if !ok || h != mbl.GetHash().String() {
		t.Fatalf("ledger hash %q != derod hash %q", h, mbl.GetHash().String())
	}
}

func TestLedgerAttributesOrphansPerSource(t *testing.T) {
	l := shareLedger{src: map[string]byte{}, fate: map[string]string{}}
	c1, c2, g1, c3, c4 := testBlob(1, false), testBlob(2, false), testBlob(3, false), testBlob(4, true), testBlob(6, false)
	l.add(c1, 'C')
	l.add(c2, 'C')
	l.add(g1, 'G')
	l.add(c3, 'C')
	l.add(c4, 'C')
	l.add(c3, 'C')                      // a duplicate submit is one share
	l.add("zz", 'C')                    // undecodable: ignored
	l.add(testBlob(5, false)[:10], 'C') // short: ignored
	hash := func(b string) string { raw, _ := hex.DecodeString(b); h, _ := miniblockHash(raw); return h }
	l.apply([]outcomeRow{
		{Hash: hash(c1), Fate: "paid"},
		{Hash: hash(c2), Fate: "orphaned", Reason: "not_included"},
		{Hash: hash(g1), Fate: "paid"},
		{Hash: hash(c3), Fate: "pending"},
		{Hash: hash(c4), Fate: "paid"},
		{Hash: strings.Repeat("ab", 32), Fate: "orphaned"}, // another miner on the same node: not ours
	})
	got := l.tally()
	if len(l.order) != 5 {
		t.Fatalf("%d shares recorded, want 5 (a resubmit is not a new share)", len(l.order))
	}
	want := sourceTally{cpuPaid: 2, cpuOrphaned: 1, gpuPaid: 1, gpuOrphaned: 0, unresolved: 1}
	if got != want {
		t.Fatalf("tally %+v want %+v", got, want)
	}
}

func TestLedgerIsBounded(t *testing.T) {
	l := shareLedger{src: map[string]byte{}, fate: map[string]string{}}
	for i := 0; i < LEDGER_MAX+10; i++ {
		l.add(testBlob(uint32(i), false), 'C')
	}
	if len(l.src) != LEDGER_MAX || len(l.order) != LEDGER_MAX {
		t.Fatalf("ledger grew to %d/%d", len(l.src), len(l.order))
	}
}

func TestOutcomeAddress(t *testing.T) {
	cases := []struct {
		flag   interface{}
		daemon string
		want   string
	}{
		{nil, "127.0.0.1:10100", "127.0.0.1:10102"}, // the live setup
		{nil, "localhost:10100", "localhost:10102"},
		{nil, "minernode1.dero.live:10100", ""}, // a public node: never assumed
		{nil, "192.168.1.20:10100", ""},         // LAN node: say so explicitly
		{"192.168.1.20:10102", "192.168.1.20:10100", "192.168.1.20:10102"},
		{"off", "127.0.0.1:10100", ""},
		{nil, "garbage", ""},
	}
	for i, c := range cases {
		if got := outcomeAddress(c.flag, c.daemon, 10102); got != c.want {
			t.Fatalf("case %d: %q want %q", i, got, c.want)
		}
	}
}

// a response shaped like the live one at 2026-10-23 08:10:45 (15 submitted, 13 paid, 2 orphaned)
func TestFetchOutcome(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/json_rpc" || r.Method != "POST" {
			http.Error(w, "no", 404)
			return
		}
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":"1","result":{"submitted":15,"paid":13,"orphaned":{"not_included":2},"pending":0,"paid_fraction":0.8666666666666667,"work_would_be_stale":false,"recent":[{"hash":"acd926a25e1bbf893e4f446d100b97cd9b2351629383315d1339f01cb335df0b","height":7799270,"submitted_unix":1792766805,"fate":"orphaned","reason":"not_included"}]}}`)
	}))
	defer srv.Close()
	r, err := fetchOutcome(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Submitted != 15 || r.Paid != 13 || r.orphanedTotal() != 2 || len(r.Recent) != 1 || r.Recent[0].Fate != "orphaned" {
		t.Fatalf("%+v", r)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":"1","error":{"code":-32601,"message":"method not found"}}`)
	}))
	defer bad.Close()
	if _, err := fetchOutcome(strings.TrimPrefix(bad.URL, "http://")); err == nil {
		t.Fatal("an RPC error must not read as an outcome")
	}
}

// ARCHITECTURE 31.2: DERO/day = H·86400·R/(18·D). The r16 live point: H 37.5k, D 2.5M, R 0.3075 DERO.
func TestExpectation(t *testing.T) {
	got := expectedDEROPerDay(37500, 2_500_000, 30750)
	want := 37500.0 * 86400 * 0.3075 / (18 * 2_500_000)
	if math.Abs(got-want) > 1e-9 || math.Abs(got-22.14) > 0.01 {
		t.Fatalf("DERO/day %f want %f (~22.14)", got, want)
	}
	// one block's worth of network work (18·D hashes) is 10 shares
	if s := expectedShares(18*2_500_000, 2_500_000); math.Abs(s-10) > 1e-9 {
		t.Fatalf("expected shares %f want 10", s)
	}
	if expectedShares(5, 0) != 0 || expectedDEROPerDay(5, 0, 1) != 0 {
		t.Fatal("D=0 must not divide")
	}
}

// DERO_LIVE_RPC=127.0.0.1:10102 go test -run TestLiveOutcome: read-only check against a running derod
func TestLiveOutcome(t *testing.T) {
	addr := os.Getenv("DERO_LIVE_RPC")
	if addr == "" {
		t.Skip("set DERO_LIVE_RPC")
	}
	r, err := fetchOutcome(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("submitted %d paid %d orphaned %v pending %d paid_fraction %.3f recent %d", r.Submitted, r.Paid, r.Orphaned, r.Pending, r.PaidFraction, len(r.Recent))
}
