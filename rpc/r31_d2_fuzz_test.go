// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package rpc

// r31 dimension 2 (rpcws fuzz-coverage, detector-fuzz-coverage DF-fuzz-coverage-480ddd1d3d and -077132f17a): the two
// rpc/ decoders no Go fuzz target reached. Characterization only: rpc/ is consensus-guarded, nothing here changes it.
// The properties never require a canonical point encoding (the bn256 x >= P / flag-byte question is dimension 1's).

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
)

// FuzzR31NewAddressFromCompressedKeys: never panics; any length but 33 is an error; an accepted key re-encodes
// (EncodeCompressed) to 33 bytes, and when those decode they give the same key.
func FuzzR31NewAddressFromCompressedKeys(f *testing.F) {
	p := new(bn256.G1).ScalarBaseMult(big.NewInt(77))
	good := (*crypto.Point)(p).EncodeCompressed()
	f.Add(good)
	f.Add(append(append([]byte{}, good...), 0x00)) // 34 bytes: a valid prefix plus one
	f.Add(good[:32])
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 33))
	f.Add(make([]byte, 33))
	f.Fuzz(func(t *testing.T, ckey []byte) {
		a, err := NewAddressFromCompressedKeys(ckey)
		if len(ckey) != 33 {
			if err == nil {
				t.Fatalf("%d bytes accepted", len(ckey))
			}
			return
		}
		if err != nil {
			return
		}
		re := a.PublicKey.EncodeCompressed()
		if len(re) != 33 || !a.Mainnet {
			t.Fatalf("%x accepted: re-encoding %d bytes, mainnet %v", ckey, len(re), a.Mainnet)
		}
		b, err := NewAddressFromCompressedKeys(re)
		if err != nil {
			// an accepted input whose re-encoding is refused (e.g. 0xff x 33 decodes to the point at infinity, which
			// encodes as 33 zero bytes): the bn256 flag-byte / x >= P acceptance of the R22 audit, owned by dimension 1
			// (dero-rft §8 R31 item 1); recorded, not asserted here
			return
		}
		if b.PublicKey.String() != a.PublicKey.String() {
			t.Fatalf("%x accepted but its re-encoding %x decodes to another key", ckey, re)
		}
	})
}

// r31_value_type_ok: an accepted Argument's Value has the Go type its DataType names.
func r31_value_type_ok(a Argument) bool {
	switch a.DataType {
	case DataString:
		_, ok := a.Value.(string)
		return ok
	case DataInt64:
		_, ok := a.Value.(int64)
		return ok
	case DataUint64:
		_, ok := a.Value.(uint64)
		return ok
	case DataFloat64:
		_, ok := a.Value.(float64)
		return ok
	case DataHash:
		_, ok := a.Value.(crypto.Hash)
		return ok
	case DataAddress:
		_, ok := a.Value.(Address)
		return ok
	case DataTime:
		_, ok := a.Value.(time.Time)
		return ok
	}
	return false
}

// FuzzR31ArgumentUnmarshalJSON: never panics; an accepted argument carries the Go type of its datatype, and one
// marshal / unmarshal round trip reaches a fixpoint (the second encoding equals the first).
func FuzzR31ArgumentUnmarshalJSON(f *testing.F) {
	for _, s := range []string{`{"name":"C","datatype":"S","value":"hi"}`, `{"name":"D","datatype":"U","value":18446744073709551615}`,
		`{"name":"x","datatype":"U","value":5}`, `{"name":"i","datatype":"I","value":-9223372036854775808}`,
		`{"name":"f","datatype":"F","value":1.5e300}`, `{"name":"h","datatype":"H","value":"` + string(bytes.Repeat([]byte("ab"), 32)) + `"}`,
		`{"name":"t","datatype":"T","value":"2026-11-13T10:00:00+01:00"}`, `{"name":"q","datatype":"Q","value":1}`,
		`{"name":"u","datatype":"U","value":-1}`, `{"datatype":"S"}`, `[]`, `null`, `{`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var a Argument
		if a.UnmarshalJSON(raw) != nil {
			return
		}
		if !r31_value_type_ok(a) {
			t.Fatalf("%q: datatype %q holds %T", raw, a.DataType, a.Value)
		}
		b1, err := json.Marshal(a)
		if err != nil {
			return // e.g. a float the encoder refuses; not a decoder property
		}
		var a2 Argument
		if err := a2.UnmarshalJSON(b1); err != nil {
			t.Fatalf("%q re-encoded as %s does not decode: %v", raw, b1, err)
		}
		b2, _ := json.Marshal(a2)
		if !bytes.Equal(b1, b2) || a2.Name != a.Name || a2.DataType != a.DataType {
			t.Fatalf("%q: no fixpoint %s != %s", raw, b1, b2)
		}
	})
}
