// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package rpc

// r29 (live-observability, dero-rft §7 B175): the jhttp bridge answers its own errors (a body it cannot parse, the
// R28 probe `{"jsonrpc":"2.0","id":3,`) with HTTP 500 and the text "[-32700] invalid request value"
// (vendor/github.com/creachadair/jrpc2/jhttp/bridge.go ServeHTTP), outside jrpc2's LogResponse, so
// rpc_error_responses_total{code="-32700"} stayed 0 on live r28. bridge_writer holds a 500 the bridge writes, and the
// answer becomes a JSON-RPC error body with the same code and message (status 500 kept), counted once by its code; a
// 500 whose text is not "[code] message" is forwarded verbatim and counted "other". Every other answer passes through
// unbuffered.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/code"
)

var bridge_error_rx = regexp.MustCompile(`^\[(-?[0-9]+)\] (.+)$`)

// bridge_error_code parses the bridge's error text "[code] message" (pure).
func bridge_error_code(s string) (c code.Code, msg string, ok bool) {
	m := bridge_error_rx.FindStringSubmatch(strings.TrimRight(s, "\n"))
	if m == nil {
		return 0, "", false
	}
	n, err := strconv.ParseInt(m[1], 10, 32)
	if err != nil {
		return 0, "", false
	}
	return code.Code(n), m[2], true
}

type bridge_writer struct {
	http.ResponseWriter
	held bool // the bridge wrote a 500: its text is buffered until finish
	buf  bytes.Buffer
}

func (b *bridge_writer) WriteHeader(status int) {
	if status == http.StatusInternalServerError {
		b.held = true
		return
	}
	b.ResponseWriter.WriteHeader(status)
}

func (b *bridge_writer) Write(p []byte) (int, error) {
	if b.held {
		return b.buf.Write(p)
	}
	return b.ResponseWriter.Write(p)
}

// finish writes the held 500 as a JSON-RPC error body (or verbatim) and counts it.
func (b *bridge_writer) finish() {
	if !b.held {
		return
	}
	c, msg, ok := bridge_error_code(b.buf.String())
	if !ok {
		rpc_error_code_other.Inc()
		b.ResponseWriter.WriteHeader(http.StatusInternalServerError)
		b.ResponseWriter.Write(b.buf.Bytes())
		return
	}
	e := &jrpc2.Error{Code: c, Message: msg}
	count_error_code(e)
	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": nil, "error": e})
	b.ResponseWriter.Header().Set("Content-Type", "application/json")
	b.ResponseWriter.WriteHeader(http.StatusInternalServerError)
	b.ResponseWriter.Write(body)
}
