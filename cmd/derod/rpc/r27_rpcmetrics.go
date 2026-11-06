// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package rpc

// r27 (rpc-metrics): what an RPC caller is told when its parameters do not decode, and which /metrics series stand
// behind the typed answers. Nothing here is consensus-visible: it changes error texts and adds counters.
//
// B132. jrpc2's reflective handler (vendor handler/handler.go:195, :204) wraps a parameter decode failure as
//     Errorf(InvalidParams, "invalid parameters: %v", err)
// where err is itself a *jrpc2.Error ("[-32602] invalid parameters", the decoder text only in its Data). The client
// read "invalid parameters: [-32602] invalid parameters": the code doubled into the text and no field named (R26
// live probes, 08:05:57). typed_new wraps handler.New and, ONLY on that failure, decodes the same params again the
// same way (strict when the type has DisallowUnknownFields, as jrpc2 does) to recover the decoder's text:
//     -32602 invalid parameters: unknown field "start" (accepted: start_topoheight, end_topoheight)
//     -32602 invalid parameters: field start_topoheight: want int64, got string
// with data {"field": ..., "accepted": [...]}. The success path is unchanged (no second decode); if the second decode
// does not fail (it cannot, it is the same decoder) the original error is returned.
//
// Typed answers by code. rpc_request_errors_total{method} counts error responses per method without the code, so a
// claim "the typed answers -32031/-32032/-32602 are CONFIRMED live" had no series behind it (R26 confirmed them by
// probing only). rpc_error_responses_total{code} counts every error response by its JSON-RPC code; the label set is
// fixed (RPC_ERROR_CODES, "other" for anything else) and registered at start, so each series reads 0 before its first
// event instead of being absent.
//
// Absent-until-first (R26 metrics gap). The typed-refusal counters were created by their first event
// (GetOrCreateCounter at the call site), so "absent" had to be read as 0 by every consumer, and a binary without the
// feature looked the same as one where it never fired. Their fixed-label series are registered at start
// (rpc_counters_preregistered); TestR27TypedRefusalCountersPreregistered keeps the list complete against the call
// sites' literals.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/code"
	"github.com/creachadair/jrpc2/handler"

	vmetrics "github.com/VictoriaMetrics/metrics"

	"github.com/deroproject/derohe/metrics"
)

// RPC_ERROR_CODES is the label set of rpc_error_responses_total{code}: the JSON-RPC standard codes, jrpc2's
// environment codes and this node's own (-32029 rate limited, -32030 banned, -32031 state unavailable, -32032 not
// found). Any other code is counted as "other".
var RPC_ERROR_CODES = []code.Code{code.ParseError, code.InvalidRequest, code.MethodNotFound, code.InvalidParams,
	code.InternalError, code.SystemError, code.Cancelled, code.DeadlineExceeded,
	RPC_CODE_RATE_LIMITED, RPC_CODE_BANNED, RPC_CODE_STATE_UNAVAILABLE, RPC_CODE_NOT_FOUND}

var rpc_error_code_counters = func() map[code.Code]*vmetrics.Counter {
	m := map[code.Code]*vmetrics.Counter{}
	for _, c := range RPC_ERROR_CODES {
		m[c] = metrics.Set.GetOrCreateCounter(fmt.Sprintf(`rpc_error_responses_total{code="%d"}`, int32(c)))
	}
	return m
}()

var rpc_error_code_other = metrics.Set.GetOrCreateCounter(`rpc_error_responses_total{code="other"}`)

// count_error_code counts one error response by its code (nil: not an error, nothing counted).
func count_error_code(e *jrpc2.Error) {
	if e == nil {
		return
	}
	if c, ok := rpc_error_code_counters[e.Code]; ok {
		c.Inc()
		return
	}
	rpc_error_code_other.Inc()
}

// rpc_counters_preregistered: the fixed-label series this package creates inside a function (typed refusals and the
// other first-event counters), created at start so they read 0 before their first event. Method and kind values are the literals of the call sites (r25_rpcrobust.go,
// rpc_dero_explorer.go, rpc_dero_getsc.go, rpc_dero_getencryptedbalance.go, rpc_dero_getrandomaddress.go,
// rpc_dero_nametoaddress.go, rpc_dero_getblockheaderbyhash.go).
var rpc_counters_preregistered = []string{
	`rpc_name_not_found_total`,
	`rpc_tx_not_found_total`,
	`rpc_recovered_panics_total`,
	`rpc_block_not_found_total{method="GetBlockHeaderByHash"}`,
	`rpc_state_unavailable_total{method="GetBlockHeadersRange"}`,
	`rpc_state_unavailable_total{method="GetMiniBlocks"}`,
	`rpc_state_unavailable_total{method="GetDifficultyHistory"}`,
	`rpc_state_unavailable_total{method="GetEncryptedBalance"}`,
	`rpc_state_unavailable_total{method="GetSC"}`,
	`rpc_input_refused_total{method="GetEncryptedBalance",kind="address"}`,
	`rpc_input_refused_total{method="GetEncryptedBalance",kind="scid"}`,
	`rpc_input_refused_total{method="GetRandomAddress",kind="scid"}`,
	`rpc_input_refused_total{method="NameToAddress",kind="name_value"}`,
	`rpc_params_refused_total`,
	`rpc_limited_total`,                      // websocket_server.go, ws_hardening.go
	`getwork_template_refresh_resends_total`, // job_dispatch.go
	`miniblock_ours_submitted_total`,         // mining_outcome.go (miniblock_ours_orphaned_total{reason} stays lazy: open label)
	`miniblock_ours_paid_total`,
}

func init() {
	for _, name := range rpc_counters_preregistered {
		metrics.Set.GetOrCreateCounter(name)
	}
}

// rpc_params_refused counts the -32602 answers typed_new rewrote (a parameter decode failure of any method).
var rpc_params_refused = metrics.Set.GetOrCreateCounter(`rpc_params_refused_total`)

// typed_new is handler.New with the B132 message: the wrapped handler is called as before; only a jrpc2 parameter
// decode failure is rewritten.
func typed_new(fn interface{}) handler.Func {
	h := handler.New(fn)
	pt := params_type(fn)
	return func(ctx context.Context, req *jrpc2.Request) (interface{}, error) {
		res, err := h(ctx, req)
		if err != nil && pt != nil && is_param_decode_failure(err) {
			if typed := params_error(pt, []byte(req.ParamString())); typed != nil {
				rpc_params_refused.Inc()
				return nil, typed
			}
		}
		return res, err
	}
}

// params_type is the (non-pointer) type of fn's parameter argument, nil when fn takes none.
func params_type(fn interface{}) reflect.Type {
	t := reflect.TypeOf(fn)
	if t == nil || t.Kind() != reflect.Func || t.NumIn() < 2 {
		return nil
	}
	a := t.In(1)
	if a.Kind() == reflect.Ptr {
		a = a.Elem()
	}
	return a
}

// is_param_decode_failure recognises the wrapper's text: "invalid parameters: " + a *jrpc2.Error rendered as "[code] ...".
func is_param_decode_failure(err error) bool {
	var je *jrpc2.Error
	return errors.As(err, &je) && je.Code == code.InvalidParams && strings.HasPrefix(je.Message, "invalid parameters: [")
}

type strict_fields interface{ DisallowUnknownFields() }

// params_error decodes params into a new value of type t exactly as jrpc2's UnmarshalParams does (base.go:86) and
// turns the decoder's error into a typed -32602 that names the field. nil when the params decode.
func params_error(t reflect.Type, params []byte) *jrpc2.Error {
	if len(params) == 0 {
		return nil
	}
	v := reflect.New(t).Interface()
	var err error
	if _, strict := v.(strict_fields); strict {
		dec := json.NewDecoder(strings.NewReader(string(params)))
		dec.DisallowUnknownFields()
		err = dec.Decode(v)
	} else {
		err = json.Unmarshal(params, v)
	}
	if err == nil {
		return nil
	}
	accepted := json_field_names(t)
	data := map[string]interface{}{"accepted": accepted}
	var msg string
	var te *json.UnmarshalTypeError
	switch {
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		field, _ := strconv.Unquote(strings.TrimPrefix(err.Error(), "json: unknown field "))
		data["field"] = bounded(field) // the caller's own key: bounded in data as in the text
		msg = fmt.Sprintf("unknown field %q (accepted: %s)", bounded(field), strings.Join(accepted, ", "))
	case errors.As(err, &te) && te.Field == "":
		msg = fmt.Sprintf("want a JSON object, got %s (accepted fields: %s)", te.Value, strings.Join(accepted, ", "))
	case errors.As(err, &te):
		data["field"] = bounded(te.Field)
		msg = fmt.Sprintf("field %s: want %s, got %s", bounded(te.Field), te.Type.String(), te.Value)
	default:
		msg = strings.TrimPrefix(err.Error(), "json: ")
	}
	e := &jrpc2.Error{Code: code.InvalidParams, Message: "invalid parameters: " + msg}
	return e.WithData(data)
}

// bounded caps a caller-chosen name echoed back (the NAME_ECHO_MAX rule of NameToAddress, cut on a rune boundary).
func bounded(s string) string { return cap_utf8(s, NAME_ECHO_MAX) }

// json_field_names lists the JSON names a struct type accepts (exported fields, the tag name or the field name),
// in declaration order; embedded structs contribute their own fields.
func json_field_names(t reflect.Type) []string {
	var out []string
	if t.Kind() != reflect.Struct {
		return out
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if f.Anonymous && name == "" {
			ft := f.Type
			if ft.Kind() == reflect.Ptr {
				ft = ft.Elem()
			}
			out = append(out, json_field_names(ft)...)
			continue
		}
		if f.PkgPath != "" { // unexported
			continue
		}
		if name == "" {
			name = f.Name
		}
		out = append(out, name)
	}
	return out
}

// cap_utf8 returns s cut to at most max bytes on a rune boundary, with "..." when it was cut (NR26 cosmetic note: the
// 64-byte name cap of NameToAddress cut inside a multi-byte rune, and the echoed name ended in an invalid byte).
func cap_utf8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	n := max
	for n > 0 && !utf8_rune_start(s[n]) {
		n--
	}
	return s[:n] + "..."
}

func utf8_rune_start(b byte) bool { return b&0xC0 != 0x80 }
