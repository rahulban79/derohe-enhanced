package rpc

// r27 (rpc-metrics, tests only: rpc/ is a consensus-listed package): the Arguments lookups and the address helpers
// were 0.0 % covered (R27 sweep, go test -coverprofile ./rpc/). The integrated-address path is the one the
// integrator-address footgun runs through: an integrated address must keep its arguments through Clone, and its
// BaseAddress must drop them without touching the original.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/deroproject/derohe/config"
)

func r27_args() Arguments {
	return Arguments{
		{Name: RPC_DESTINATION_PORT, DataType: DataUint64, Value: uint64(1337)},
		{Name: RPC_COMMENT, DataType: DataString, Value: "hello"},
		{Name: "nil", DataType: DataString, Value: nil},
	}
}

func TestR27ArgumentsLookups(t *testing.T) {
	a := r27_args()
	if !a.Has(RPC_DESTINATION_PORT, DataUint64) || a.Has(RPC_DESTINATION_PORT, DataInt64) || a.Has("absent", DataString) {
		t.Fatal("Has: name and type must both match")
	}
	if !a.Has("nil", DataString) || a.HasValue("nil", DataString) || !a.HasValue(RPC_COMMENT, DataString) {
		t.Fatal("HasValue: a nil value is present but has no value")
	}
	if a.Index(RPC_COMMENT, DataString) != 1 || a.Index(RPC_COMMENT, DataUint64) != -1 || a.Index("absent", DataString) != -1 {
		t.Fatal("Index")
	}
	if v, ok := a.Value(RPC_DESTINATION_PORT, DataUint64).(uint64); !ok || v != 1337 {
		t.Fatalf("Value %v", a.Value(RPC_DESTINATION_PORT, DataUint64))
	}
	if a.Value(RPC_DESTINATION_PORT, DataString) != nil {
		t.Fatal("Value with the wrong type must be nil")
	}
}

func TestR27ArgumentsPack(t *testing.T) {
	a := r27_args()[:2]
	exact, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.CheckPack(len(exact))
	if err != nil || !bytes.Equal(p, exact) {
		t.Fatalf("CheckPack at the exact size: %x %v", p, err)
	}
	p, err = a.CheckPack(len(exact) + 40)
	if err != nil || len(p) != len(exact)+40 || !bytes.Equal(p[:len(exact)], exact) {
		t.Fatalf("CheckPack padded: %d bytes %v", len(p), err)
	}
	var back Arguments
	if err := back.UnmarshalBinary(p); err != nil || !back.Has(RPC_COMMENT, DataString) {
		t.Fatalf("padded pack does not decode: %v %v", back, err)
	}
	if _, err := a.CheckPack(len(exact) - 1); err == nil || !strings.Contains(err.Error(), "limit is") {
		t.Fatalf("CheckPack over the limit: %v", err)
	}
	if got := a.MustPack(len(exact)); !bytes.Equal(got, exact) {
		t.Fatal("MustPack")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustPack over the limit must panic")
		}
	}()
	a.MustPack(len(exact) - 1)
}

func TestR27AddressHelpers(t *testing.T) {
	// bech32_test.go sets the package-global length_check to true (BIP-173's 90-character cap) and leaves it so; an
	// integrated address is longer than 90 characters, so a later test that encodes one fails only in a full run
	old_check := length_check
	length_check = false
	defer func() { length_check = old_check }()
	base, err := NewAddress(config.Mainnet.Dev_Address)
	if err != nil {
		t.Fatal(err)
	}
	if !base.IsMainnet() || base.IsIntegratedAddress() || !base.IsDERONetwork() {
		t.Fatal("dev address: mainnet, not integrated")
	}
	integ := base.Clone()
	integ.Arguments = r27_args()[:2]
	if txt, err := integ.MarshalText(); err != nil || !integ.IsIntegratedAddress() || !strings.HasPrefix(string(txt), "deroi") {
		t.Fatalf("integrated address %q: %v", txt, err)
	}
	back, err := NewAddress(integ.String())
	if err != nil || !back.IsIntegratedAddress() || back.Arguments.Value(RPC_DESTINATION_PORT, DataUint64) != uint64(1337) {
		t.Fatalf("integrated round trip: %v %v", back, err)
	}
	// Clone copies the key and the arguments; changing the clone leaves the original alone
	cl := integ.Clone()
	if cl.String() != integ.String() || cl.PublicKey == integ.PublicKey {
		t.Fatal("Clone must copy the key, not share it")
	}
	cl.Arguments[0].Value = uint64(1)
	if integ.Arguments.Value(RPC_DESTINATION_PORT, DataUint64) != uint64(1337) {
		t.Fatal("Clone shares the arguments slice")
	}
	// BaseAddress drops the arguments, keeps the key, does not modify the integrated address
	b := integ.BaseAddress()
	if b.IsIntegratedAddress() || b.String() != base.String() || !integ.IsIntegratedAddress() {
		t.Fatalf("BaseAddress %q, want %q", b.String(), base.String())
	}
	// testnet hrp
	tn := base.Clone()
	tn.Mainnet = false
	if tn.IsMainnet() || !strings.HasPrefix(tn.String(), "deto") {
		t.Fatalf("testnet %q", tn.String())
	}
	// from the compressed key
	k, err := NewAddressFromCompressedKeys(base.Compressed())
	if err != nil || k.String() != base.String() {
		t.Fatalf("from compressed keys: %v", err)
	}
	if _, err := NewAddressFromCompressedKeys(base.Compressed()[:32]); err == nil {
		t.Fatal("32-byte key accepted")
	}
}
