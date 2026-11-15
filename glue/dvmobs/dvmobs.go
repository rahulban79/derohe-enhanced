// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

// Package dvmobs exports the DERO Virtual Machine's activity on /metrics (R31, dero-rft §7 B288; D-21: non-consensus
// only). Before R31 no /metrics family showed an SC install, invoke, revert or out-of-gas.
//
// How, without touching consensus code: blockchain/transaction_execute.go (process_transaction_sc) gained only logger
// statements (consensus guard S1 strips a logger call that assigns nothing): "dvm start" when an SC tx starts, "dvm
// panic recovered" in the existing recover, and "dvm outcome" in the existing deferred function, which runs at every
// return with the final named results (err) and the gas the VM reported. derod wraps the logger the chain takes at
// Blockchain_Start (Wrap); the wrapper force-enables only the chain's "CORE" logger, reads those three messages and
// increments the counters below, and forwards every line to the real sink exactly when that sink is enabled for the
// line's level, so the console and the log file print what they printed before.
//
// Nothing here can reach the chain: the handler runs synchronously inside the deferred function of
// process_transaction_sc, so it must never panic there (a panic would replace the named results). Every handler call
// recovers its own panic and counts it in sc_metrics_handler_panics_total. The counters count executions: a block that
// is executed again (a reorg, a re-validation) counts its SC txs again.
package dvmobs

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/VictoriaMetrics/metrics"
	"github.com/go-logr/logr"

	dmetrics "github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/rpc"
)

// the messages transaction_execute.go logs (a test pins them against the source)
const (
	MsgStart   = "dvm start"
	MsgPanic   = "dvm panic recovered"
	MsgOutcome = "dvm outcome"
	MsgParse   = "SC install rejected, contract source does not parse"
	CoreName   = "CORE" // blockchain.go: logger = globals.Logger.WithName("CORE")
	// DvmLevel is the only verbosity the wrapper force-enables on CORE (the V(9) lines of transaction_execute.go);
	// every other level answers exactly as the real sink does, so a `logger.V(n).Enabled()` guard in blockchain/ is unchanged
	DvmLevel = 9
)

// revert reasons, in the order they are tested by Classify
var Reasons = []string{"out_of_gas", "vm_panic", "exec_panic", "discarded", "transfer_check", "not_found", "not_installed",
	"parse", "bad_request", "other"}

var (
	// SC install transactions executed, by result (ok: Initialize ran and returned 0; error: the install failed)
	InstallOK  = dmetrics.Set.NewCounter(`sc_install_total{result="ok"}`)
	InstallErr = dmetrics.Set.NewCounter(`sc_install_total{result="error"}`)
	// SC invoke transactions executed (SC_CALL, or an unknown SC action), by result
	InvokeOK  = dmetrics.Set.NewCounter(`sc_invoke_total{result="ok"}`)
	InvokeErr = dmetrics.Set.NewCounter(`sc_invoke_total{result="error"}`)
	// SC transactions whose execution failed (state changes discarded), by reason
	Revert = func() map[string]*metrics.Counter {
		m := map[string]*metrics.Counter{}
		for _, r := range Reasons {
			m[r] = dmetrics.Set.NewCounter(fmt.Sprintf(`sc_revert_total{reason=%q}`, r))
		}
		return m
	}()
	// SC executions that ran out of compute or storage gas (a subset of sc_revert_total{reason="out_of_gas"})
	OutOfGas = dmetrics.Set.NewCounter(`sc_out_of_gas_total`)
	// panics recovered by the deferred recover of process_transaction_sc (the V(2) "Recover while executing SC" line)
	PanicRecovered = dmetrics.Set.NewCounter(`sc_panic_recovered_total`)
	// panics of this package's own log handler, recovered (must stay 0)
	HandlerPanics = dmetrics.Set.NewCounter(`sc_metrics_handler_panics_total`)
	// compute gas the VM reported per SC execution (vmrange buckets)
	GasCompute = dmetrics.Set.NewHistogram(`sc_gas_compute_used`)
	// storage gas the VM reported per SC execution (vmrange buckets)
	GasStorage = dmetrics.Set.NewHistogram(`sc_gas_storage_used`)
	// wall time of one SC execution, from "dvm start" to "dvm outcome" (vmrange buckets)
	ExecSeconds = dmetrics.Set.NewHistogram(`sc_exec_seconds`)
)

// Classify maps the final error of an SC execution to a revert reason. Pure.
func Classify(err interface{}) string {
	if err == nil {
		return "other"
	}
	s := fmt.Sprint(err)
	switch {
	case strings.Contains(s, "Insufficient Gas"), strings.Contains(s, "Insufficient Storage Gas"):
		return "out_of_gas"
	case strings.Contains(s, "Recovered in function"), strings.Contains(s, "Stack trace"):
		return "vm_panic"
	case strings.Contains(s, "Discarded knowingly"):
		return "discarded"
	case strings.Contains(s, "Balance calculation"), strings.Contains(s, "account is unregistered"):
		return "transfer_check"
	case strings.Contains(s, "SC not found"):
		return "not_found"
	case strings.Contains(s, "not installed"):
		return "not_installed"
	case strings.Contains(s, "no code provided"), strings.Contains(s, "no scid provided"),
		strings.Contains(s, "no entrypoint provided"), strings.Contains(s, "unknown action"),
		strings.Contains(s, "parameter type missing"), strings.Contains(s, "does not contain entrypoint"):
		return "bad_request"
	}
	return "other"
}

type pending struct {
	start    time.Time
	panicked bool
	parse    bool
}

// Observer turns the chain's dvm log lines into counter increments. The zero value is not usable; use New.
type Observer struct {
	mu      sync.Mutex
	pending map[string]*pending
	now     func() time.Time
}

const maxPending = 4096 // a start without an outcome (cannot happen: the outcome is deferred) never grows the map past this

func New() *Observer { return &Observer{pending: map[string]*pending{}, now: time.Now} }

// Default is the observer derod installs.
var Default = New()

func kvmap(kv []interface{}) map[string]interface{} {
	m := map[string]interface{}{}
	for i := 0; i+1 < len(kv); i += 2 {
		if k, ok := kv[i].(string); ok {
			m[k] = kv[i+1]
		}
	}
	return m
}

func (o *Observer) entry(txid string, create bool) *pending {
	p := o.pending[txid]
	if p == nil && create {
		if len(o.pending) >= maxPending {
			o.pending = map[string]*pending{}
		}
		p = &pending{}
		o.pending[txid] = p
	}
	return p
}

// Handle consumes one log line. It never panics (a recovered panic counts in sc_metrics_handler_panics_total) and
// returns whether the message was one of the dvm messages.
func (o *Observer) Handle(msg string, kv []interface{}) (mine bool) {
	switch msg {
	case MsgStart, MsgPanic, MsgOutcome, MsgParse:
	default:
		return false
	}
	defer func() {
		if r := recover(); r != nil {
			HandlerPanics.Inc()
		}
	}()
	m := kvmap(kv)
	txid := fmt.Sprint(m["txid"])
	o.mu.Lock()
	defer o.mu.Unlock()
	switch msg {
	case MsgStart:
		o.entry(txid, true).start = o.now()
	case MsgPanic:
		o.entry(txid, true).panicked = true
		PanicRecovered.Inc()
	case MsgParse:
		o.entry(txid, true).parse = true
	case MsgOutcome:
		p := o.entry(txid, false)
		delete(o.pending, txid)
		o.outcome(p, m)
	}
	return true
}

func (o *Observer) outcome(p *pending, m map[string]interface{}) {
	if p == nil {
		p = &pending{}
	}
	args, _ := m["scdata"].(rpc.Arguments)
	if !args.Has(rpc.SCACTION, rpc.DataUint64) {
		return // SCDATA without an SC action: not an SC operation (the chain returns before any execution)
	}
	install := rpc.SC_ACTION(args.Value(rpc.SCACTION, rpc.DataUint64).(uint64)) == rpc.SC_INSTALL
	err := m["error"]
	if e, ok := err.(error); ok && e == nil {
		err = nil
	}
	failed := err != nil || p.panicked || m["zero_signer"] == true
	if !p.start.IsZero() {
		ExecSeconds.Update(o.now().Sub(p.start).Seconds())
	}
	if g, ok := m["gascompute"].(uint64); ok {
		GasCompute.Update(float64(g))
	}
	if g, ok := m["gasstorage"].(uint64); ok {
		GasStorage.Update(float64(g))
	}
	switch {
	case install && failed:
		InstallErr.Inc()
	case install:
		InstallOK.Inc()
	case failed:
		InvokeErr.Inc()
	default:
		InvokeOK.Inc()
	}
	if !failed {
		return
	}
	reason := Classify(err)
	switch {
	case reason == "out_of_gas":
	case p.panicked:
		reason = "exec_panic"
	case p.parse:
		reason = "parse"
	}
	Revert[reason].Inc()
	if reason == "out_of_gas" {
		OutOfGas.Inc()
	}
}

// sink wraps the chain's log sink. Only the logger named CoreName is force-enabled (so its V(9) dvm lines reach the
// observer); every line is forwarded to the real sink only when the real sink is enabled for its level.
type sink struct {
	under logr.LogSink // nil: discard
	name  string
	obs   *Observer
}

func (s *sink) core() bool { return s.name == CoreName }

func (s *sink) Init(logr.RuntimeInfo) {} // the wrapped sink was initialised by its own logr.New

func (s *sink) Enabled(level int) bool {
	return (s.core() && level == DvmLevel) || (s.under != nil && s.under.Enabled(level))
}

func (s *sink) Info(level int, msg string, kv ...interface{}) {
	if s.core() {
		s.obs.Handle(msg, kv)
	}
	if s.under != nil && s.under.Enabled(level) {
		s.under.Info(level, msg, kv...)
	}
}

func (s *sink) Error(err error, msg string, kv ...interface{}) {
	if s.under != nil {
		s.under.Error(err, msg, kv...)
	}
}

func (s *sink) WithValues(kv ...interface{}) logr.LogSink {
	c := *s
	if s.under != nil {
		c.under = s.under.WithValues(kv...)
	}
	return &c
}

func (s *sink) WithName(name string) logr.LogSink {
	c := *s
	if s.under != nil {
		c.under = s.under.WithName(name)
	}
	if c.name == "" {
		c.name = name
	} else {
		c.name = c.name + "/" + name
	}
	return &c
}

func (s *sink) WithCallDepth(depth int) logr.LogSink {
	c := *s
	if cd, ok := s.under.(logr.CallDepthLogSink); ok {
		c.under = cd.WithCallDepth(depth)
	}
	return &c
}

// Wrap returns l with the dvm observer attached (obs nil: Default). derod calls it on globals.Logger right before
// blockchain.Blockchain_Start, which derives the chain's "CORE" logger from it.
func Wrap(l logr.Logger, obs *Observer) logr.Logger {
	if obs == nil {
		obs = Default
	}
	under := l.GetSink()
	if cd, ok := under.(logr.CallDepthLogSink); ok {
		under = cd.WithCallDepth(1) // one more frame: this wrapper
	}
	return logr.New(&sink{under: under, obs: obs})
}
