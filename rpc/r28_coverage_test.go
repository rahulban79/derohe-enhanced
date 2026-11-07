package rpc

// r28 (rpc-metrics, tests only: rpc/ is a consensus-listed package): the 11 functions the R28 sweep found at 0.0 %
// (go test -coverprofile ./rpc/: DataType.String, Argument.String, Argument.UnmarshalJSON, Entry.String,
// Entry.ProcessPayload, the wallet_rpc FormatMoney* copies). UnmarshalJSON is how a wallet RPC client decodes the
// payload_rpc arguments of every entry it lists: each type must come back as its Go type (int64, not float64).

import (
	"encoding/json"
	"math/big"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
)

func TestR28DataTypeAndArgumentString(t *testing.T) {
	for dt, want := range map[DataType]string{DataString: "string", DataInt64: "int64", DataUint64: "uint64", DataFloat64: "float64",
		DataHash: "hash", DataAddress: "address", DataTime: "time", DataType("Z"): "unknown data type"} {
		if got := dt.String(); got != want {
			t.Fatalf("%q.String() = %q, want %q", string(dt), got, want)
		}
	}
	addr, err := NewAddress(config.Mainnet.Dev_Address)
	if err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		a    Argument
		want string
	}{
		{Argument{"c", DataString, "hi"}, "Name:c Type:string Value:'hi'"},
		{Argument{"i", DataInt64, int64(-7)}, "Name:i Type:int64 Value:'-7'"},
		{Argument{"u", DataUint64, uint64(7)}, "Name:u Type:uint64 Value:'7'"},
		{Argument{"f", DataFloat64, 1.5}, "Name:f Type:float64 Value:'1.500000'"},
		{Argument{"h", DataHash, crypto.Hash{0xab}}, "Name:h Type:hash Value:'ab000000"},
		{Argument{"a", DataAddress, *addr}, "Name:a Type:address Value:'dero1"},
		{Argument{"t", DataTime, when}, "Name:t Type:time Value:'2026-11-06 00:00:00 +0000 UTC'"},
		{Argument{"x", DataType("Z"), 1}, "unknown data type"},
	} {
		if got := c.a.String(); !strings.HasPrefix(got, c.want) {
			t.Fatalf("%s: %q, want prefix %q", c.a.Name, got, c.want)
		}
	}
}

func TestR28ArgumentUnmarshalJSON(t *testing.T) {
	addr, _ := NewAddress(config.Mainnet.Dev_Address)
	when := time.Date(2026, 11, 6, 1, 2, 3, 0, time.UTC)
	in := Arguments{{"c", DataString, "hi"}, {"i", DataInt64, int64(-1) << 62}, {"u", DataUint64, uint64(1)<<63 + 5},
		{"f", DataFloat64, 2.25}, {"h", DataHash, crypto.Hash{1, 2, 3}}, {"a", DataAddress, *addr}, {"t", DataTime, when}}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Arguments
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != len(in) {
		t.Fatalf("%d arguments back, want %d", len(out), len(in))
	}
	if out[1].Value.(int64) != int64(-1)<<62 || out[2].Value.(uint64) != uint64(1)<<63+5 || out[3].Value.(float64) != 2.25 ||
		out[0].Value.(string) != "hi" || out[4].Value.(crypto.Hash) != (crypto.Hash{1, 2, 3}) || !out[6].Value.(time.Time).Equal(when) {
		t.Fatalf("values changed type or value: %#v", out)
	}
	if a := out[5].Value.(Address); a.String() != addr.String() {
		t.Fatalf("address %s", a.String())
	}
	for _, bad := range []string{
		`{"name":"x","datatype":"Z","value":1}`,         // unknown type
		`{"name":"x","datatype":"I","value":"seven"}`,   // a string for int64
		`{"name":"x","datatype":"U","value":-1}`,        // negative uint64
		`{"name":"x","datatype":"H","value":"zz"}`,      // not a hash
		`{"name":"x","datatype":"A","value":"dero1xx"}`, // not an address
		`{"name":"x","datatype":"T","value":"monday"}`,  // not a time
		`{"name":"x","datatype":"S","value":5}`,         // a number for a string
		`{"name":"x","datatype":"F","value":"1.5"}`,     // a string for a float
		`[1]`,
	} {
		var a Argument
		if err := json.Unmarshal([]byte(bad), &a); err == nil {
			t.Fatalf("%s decoded without error: %#v", bad, a)
		}
	}
	var a Argument
	// the message prints the type through DataType.String, so the caller's letter is lost: "unknown data type unknown
	// data type" (upstream text, pinned; rpc/ takes tests only, the cosmetic fix is a §7 note)
	if err := json.Unmarshal([]byte(`{"name":"x","datatype":"Z","value":1}`), &a); err == nil || err.Error() != "unknown data type unknown data type" {
		t.Fatalf("unknown type error %v", err)
	}
}

func TestR28EntryProcessPayloadAndString(t *testing.T) {
	args := Arguments{{RPC_DESTINATION_PORT, DataUint64, uint64(0xd1)}, {RPC_SOURCE_PORT, DataUint64, uint64(0x5c)}, {RPC_COMMENT, DataString, "thanks"}}
	payload, err := args.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	e := Entry{Incoming: true, Amount: 123456789, TXID: "tx1", Payload: payload, Sender: "s1", Height: 9, TopoHeight: 10}
	got, err := e.ProcessPayload()
	if err != nil || len(got) != 3 || e.DestinationPort != 0xd1 || e.SourcePort != 0x5c || len(e.Payload_RPC) != 3 || e.PayloadError != "" {
		t.Fatalf("ProcessPayload %v %v %+v", got, err, e)
	}
	s := e.String()
	for _, want := range []string{"Type: Received\n", "Amount: 1234.56789\n", "TXID: tx1\n", "Sender: s1\n", "DestPort:  00000000000000d1\n",
		"SrcPort:  000000000000005c\n", "thanks", "Block Height: 9\n", "Block TopoHeight: 10\n"} {
		if !strings.Contains(s, want) {
			t.Fatalf("incoming entry lacks %q:\n%s", want, s)
		}
	}
	ports := Arguments{{RPC_COMMENT, DataString, "no ports"}}
	payload2, _ := ports.MarshalBinary()
	e2 := Entry{Payload: payload2}
	if _, err := e2.ProcessPayload(); err != nil || e2.DestinationPort != 0 || e2.SourcePort != 0 {
		t.Fatalf("ports must stay 0 when absent: %+v %v", e2, err)
	}
	empty := Entry{}
	if _, err := empty.ProcessPayload(); err == nil || err.Error() != "zero length payload" {
		t.Fatalf("empty payload: %v", err)
	}
	junk := Entry{Payload: []byte{0xff, 0x01}, Destination: "d1", Proof: "p1", Amount: 1}
	if _, err := junk.ProcessPayload(); err == nil || junk.PayloadError == "" {
		t.Fatalf("junk payload must set PayloadError: %+v", junk)
	}
	s = junk.String()
	for _, want := range []string{"Type: Sent Outgoing\n", "Amount: 0.00001\n", "Destination: d1\n", "Proof: p1\n", "Raw Payload:  ff01\n", "Payload error:  "} {
		if !strings.Contains(s, want) {
			t.Fatalf("outgoing entry lacks %q:\n%s", want, s)
		}
	}
	cb := Entry{Coinbase: true, Amount: 61500}
	if s = cb.String(); !strings.HasPrefix(s, "Type: Coinbase\nAmount: 0.61500\n") || strings.Contains(s, "TXID") || strings.Contains(s, "PayloadType") {
		t.Fatalf("coinbase entry:\n%s", s)
	}
}

// exact decimal text of amount/1e5 at precision p, truncated (as big.Float.Text rounds the exact quotient: rounding to
// nearest-even of the exact value), from integers only
func r28_exact(amount uint64, p int) string {
	q := new(big.Rat).SetFrac(new(big.Int).SetUint64(amount), big.NewInt(100000))
	return q.FloatString(p)
}

func TestR28WalletFormatMoney(t *testing.T) {
	for _, c := range []struct {
		f    func(uint64) string
		a    uint64
		want string
	}{
		{FormatMoney, 0, "0.00000"}, {FormatMoney, 1, "0.00001"}, {FormatMoney, 123456789, "1234.56789"},
		{FormatMoney0, 123456789, "1235"}, {FormatMoney5, 100000, "1.00000"}, {FormatMoney8, 1, "0.00001000"},
		{FormatMoney12, 7, "0.000070000000"},
	} {
		if got := c.f(c.a); got != c.want {
			t.Fatalf("%d: %q, want %q", c.a, got, c.want)
		}
	}
	if FormatMoneyPrecision(150000, 0) != "2" && FormatMoneyPrecision(150000, 0) != "1" { // half: either rounding is a legal display
		t.Fatal("precision 0")
	}
	r := rand.New(rand.NewSource(28))
	for i := 0; i < 20000; i++ { // exact below 2^53 (every amount of the 21M-DERO supply, 2.1e12 atomic units, is)
		a := uint64(r.Int63n(1 << 53))
		if got, want := FormatMoney(a), r28_exact(a, 5); got != want {
			t.Fatalf("FormatMoney(%d) = %s, want %s", a, got, want)
		}
	}
	// B144 residual (report only; rpc/ is consensus-listed and only tests may be added): the 64-bit quotient misprints the
	// 5th decimal for part of [2^63, 2^64). Measured here, so the rft row can quote a number instead of "~16 %".
	wrong := 0
	const n = 20000
	for i := 0; i < n; i++ {
		a := uint64(1)<<63 | r.Uint64()
		if FormatMoney(a) != r28_exact(a, 5) {
			wrong++
		}
	}
	t.Logf("B144 residual: rpc.FormatMoney wrong 5th decimal for %d of %d random amounts in [2^63, 2^64) (%.1f %%)", wrong, n, 100*float64(wrong)/n)
}
