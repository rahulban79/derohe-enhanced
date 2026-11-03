package rpcserver

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Fix H (r18 merge, N5): /install_sc reads its body through http.MaxBytesReader, not an unbounded ReadAll.
func TestInstallSCBodyLimited(t *testing.T) {
	small := bytes.Repeat([]byte("a"), 1000)
	req := httptest.NewRequest("POST", "/install_sc", bytes.NewReader(small))
	b, err := read_install_sc_body(httptest.NewRecorder(), req)
	if err != nil || !bytes.Equal(b, small) {
		t.Fatalf("small body: %d bytes, %v", len(b), err)
	}
	big := make([]byte, INSTALL_SC_MAX_BODY+1)
	req = httptest.NewRequest("POST", "/install_sc", bytes.NewReader(big))
	b, err = read_install_sc_body(httptest.NewRecorder(), req)
	var tooBig *http.MaxBytesError
	if !errors.As(err, &tooBig) {
		t.Fatalf("oversized body accepted (%d bytes read, err %v)", len(b), err)
	}
	if INSTALL_SC_MAX_BODY > 32<<20 {
		t.Fatalf("limit %d above 32 MiB", INSTALL_SC_MAX_BODY)
	}
}
