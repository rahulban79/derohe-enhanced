package rpc

// r24 verify (rpcws): a remote /json_rpc body is split per element the way jrpc2 splits it (decode_requests), and
// txids / SC keys are counted in the handler's own param type (request_items). Forged bodies that hid requests from
// the admission and the item bounds on base 04ceb55 (evidence/verify_malformed_batch_admission.txt,
// evidence/verify_smuggle_base.txt).

import (
	"strings"
	"testing"
	"time"
)

func r24v_call(id int, method, params string) string {
	s := `{"jsonrpc":"2.0","id":` + itoa_r24v(id) + `,"method":"` + method + `"`
	if params != "" {
		s += `,"params":` + params
	}
	return s + `}`
}

func itoa_r24v(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// "keysuint64":0 is ignored by GetTransaction_Params but failed the old one-struct precheck decode.
func r24v_smuggled(n int) string { return strings.TrimSuffix(r23c_hashes(n), "}") + `,"keysuint64":0}` }

func TestR24VerifyIgnoredFieldCannotHideItems(t *testing.T) {
	fresh_abuse(t)
	if _, err := remote_body_items([]byte(r24v_call(1, "DERO.GetTransaction", r24v_smuggled(MAX_REMOTE_TX_HASHES+44)))); err == nil || !strings.Contains(err.Error(), "per call") {
		t.Fatalf("300 txids + an ignored field passed the per-call bound: %v", err)
	}
	var parts []string
	for i := 0; i < 16; i++ {
		parts = append(parts, r24v_call(i, "DERO.GetTransaction", r24v_smuggled(MAX_REMOTE_TX_HASHES)))
	}
	rec := r24_post("["+strings.Join(parts, ",")+"]", "192.0.2.101:1", "application/json")
	if !strings.Contains(rec.Body.String(), "per body") {
		t.Fatalf("16 x 256 txids + ignored fields reached the bridge: %.200s", rec.Body.String())
	}
	// GetSC: a txs_hashes value that is not a list must not hide 300 keys
	keys := `{"scid":"00","txs_hashes":5,"keysstring":[` + strings.TrimSuffix(strings.Repeat(`"a",`, MAX_REMOTE_SC_KEYS+44), ",") + `]}`
	if _, err := remote_body_items([]byte(r24v_call(1, "DERO.GetSC", keys))); err == nil {
		t.Fatal("300 SC keys + an ignored non-list field passed the per-call bound")
	}
	// a params value the handler cannot decode runs nothing, so it is not counted
	if items, err := remote_body_items([]byte(r24v_call(1, "DERO.GetTransaction", `{"txs_hashes":[1,2]}`))); err != nil || items != nil {
		t.Fatalf("undecodable params counted: %v %v", items, err)
	}
}

func TestR24VerifyNonObjectElementKeepsAdmission(t *testing.T) {
	fresh_abuse(t)
	if m, err := request_methods([]byte(`[0,{"method":"a"},{"method":1},null]`)); err != nil || len(m) != 4 || m[0] != "" || m[1] != "a" || m[2] != "" || m[3] != "" {
		t.Fatalf("per-element methods: %q %v", m, err)
	}
	if _, err := request_methods([]byte(`[0,{"method":"a"}`)); err == nil {
		t.Fatal("a body that is not JSON must stay an error (the bridge runs none of it)")
	}
	// one non-object element must not let the rest of a 16 x 256-txid batch past the per-body total
	parts := []string{"0"}
	for i := 0; i < 16; i++ {
		parts = append(parts, r24v_call(i+1, "DERO.GetTransaction", r23c_hashes(MAX_REMOTE_TX_HASHES)))
	}
	if rec := r24_post("["+strings.Join(parts, ",")+"]", "192.0.2.102:1", "application/json"); !strings.Contains(rec.Body.String(), "per body") {
		t.Fatalf("[0, 16 x 256 txids] reached the bridge: %.200s", rec.Body.String())
	}
	// nor skip the call cost: 20 bodies of [0, 255 x Ping] = 5,100 calls cannot all run from a 2,000-token burst
	pings := []string{"0"}
	for i := 0; i < 255; i++ {
		pings = append(pings, r24v_call(i+1, "DERO.Ping", ""))
	}
	served, start := 0, time.Now()
	for r := 0; r < 20; r++ {
		served += strings.Count(r24_post("["+strings.Join(pings, ",")+"]", "192.0.2.103:1", "application/json").Body.String(), "Pong")
	}
	// the bucket refills while the loop runs (slow under -race): burst + rate x elapsed + one body of slack
	if limit := float64(ABUSE_DEFAULT_BURST) + float64(ABUSE_DEFAULT_RATE)*time.Since(start).Seconds() + 255; float64(served) > limit {
		t.Fatalf("%d of 5,100 batched calls served past the call cost (limit %.0f)", served, limit)
	}
	// nor reach a built-in
	for _, off := range []bool{false, true} {
		rpc_abuse.enabled = !off
		if b := r24_post(`[0,`+r24v_call(1, "rpc.serverInfo", "")+`]`, "192.0.2.104:1", "application/json").Body.String(); strings.Contains(b, "startTime") || strings.Contains(b, "DERO.GetInfo") {
			t.Fatalf("guard off=%v: [0, rpc.serverInfo] answered remotely: %.200s", off, b)
		}
	}
	rpc_abuse.enabled = true
	// loopback keeps the built-ins
	if b := r24_post(`[0,`+r24v_call(1, "rpc.serverInfo", "")+`]`, "127.0.0.1:1", "application/json").Body.String(); !strings.Contains(b, "startTime") {
		t.Fatalf("loopback lost rpc.serverInfo in a batch: %.200s", b)
	}
}
