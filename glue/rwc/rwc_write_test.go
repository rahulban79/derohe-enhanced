//go:build !wasm
// +build !wasm

package rwc

import (
	"bytes"
	"testing"
)

type short_writer struct{ bytes.Buffer }

func (s *short_writer) Write(p []byte) (int, error) { // at most 3 bytes per call
	if len(p) > 3 {
		p = p[:3]
	}
	return s.Buffer.Write(p)
}
func (s *short_writer) Close() error { return nil }

func TestWriteHandlesShortWrites(t *testing.T) {
	sw := &short_writer{}
	r := &ReadWriteCloser{w: sw}
	msg := []byte(`{"jsonrpc":"2.0","id":1,"result":"Pong "}`)
	if n, err := r.Write(msg); err != nil || n != len(msg) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if got := sw.String(); got != string(msg) {
		t.Fatalf("wrote %q, want %q", got, msg)
	}
}
