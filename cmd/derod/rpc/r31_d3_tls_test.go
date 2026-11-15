package rpc

// r31 dimension 3 (DF-error-paths-f5f2163409): the getwork TLS key generator's error is checked; it was overwritten by
// the next call, so a failure surfaced as a nil-key crash inside x509 instead of its own error.

import (
	"crypto/ecdsa"
	"errors"
	"testing"
)

func TestR31GetworkTLSKeyGenErrorChecked(t *testing.T) {
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
