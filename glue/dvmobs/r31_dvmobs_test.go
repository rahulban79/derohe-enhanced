package dvmobs

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/deroproject/derohe/rpc"
)

// R31 (dero-rft §7 B288; D-21 non-consensus): the sc_* /metrics families fed from the chain's dvm log lines.

func args(kv ...interface{}) rpc.Arguments {
	var a rpc.Arguments
	for i := 0; i+1 < len(kv); i += 2 {
		switch v := kv[i+1].(type) {
		case uint64:
			a = append(a, rpc.Argument{Name: kv[i].(string), DataType: rpc.DataUint64, Value: v})
		case string:
			a = append(a, rpc.Argument{Name: kv[i].(string), DataType: rpc.DataString, Value: v})
		}
	}
	return a
}

var installArgs = args(rpc.SCACTION, uint64(rpc.SC_INSTALL), rpc.SCCODE, "x")
var callArgs = args(rpc.SCACTION, uint64(rpc.SC_CALL), "entrypoint", "Bump")

type snap map[string]uint64

func take() snap {
	s := snap{"install_ok": InstallOK.Get(), "install_err": InstallErr.Get(), "invoke_ok": InvokeOK.Get(),
		"invoke_err": InvokeErr.Get(), "oog": OutOfGas.Get(), "panic": PanicRecovered.Get(), "handler_panic": HandlerPanics.Get()}
	for _, r := range Reasons {
		s["revert_"+r] = Revert[r].Get()
	}
	return s
}

func (a snap) delta(b snap) map[string]uint64 {
	d := map[string]uint64{}
	for k, v := range b {
		if v != a[k] {
			d[k] = v - a[k]
		}
	}
	return d
}

func expect(t *testing.T, what string, got, want map[string]uint64) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("%s: counter deltas %v, want %v", what, got, want)
	}
}

// run one execution: start, optional extra lines, outcome
func run(o *Observer, txid string, sc rpc.Arguments, err interface{}, extra ...string) {
	o.Handle(MsgStart, []interface{}{"txid", txid})
	for _, m := range extra {
		o.Handle(m, []interface{}{"txid", txid})
	}
	o.Handle(MsgOutcome, []interface{}{"txid", txid, "scdata", sc, "error", err, "gascompute", uint64(800), "gasstorage", uint64(40)})
}

func TestR31DVMObsClassify(t *testing.T) {
	cases := map[string]string{
		"Recovered in function Insufficient Gas stack ...":         "out_of_gas",
		"Recovered in function Insufficient Storage Gas stack ...": "out_of_gas",
		"Recovered in function runtime error stack ...":            "vm_panic",
		"Stack trace  \n...":                           "vm_panic",
		"Discarded knowingly":                          "discarded",
		"Balance calculation underflow stored_value 1": "transfer_check",
		"account is unregistered":                      "transfer_check",
		"SC not found abcd":                            "not_found",
		"scid abcd not installed":                      "not_installed",
		"no code provided":                             "bad_request",
		"no scid provided":                             "bad_request",
		"no entrypoint provided":                       "bad_request",
		"unknown action what to do scid 4d":            "bad_request",
		"entrypoint 'X' parameter type missing or not yet supported": "bad_request",
		"stored SC  does not contain entrypoint 'X' scid":            "bad_request",
		"something new": "other",
	}
	for in, want := range cases {
		if got := Classify(errors.New(in)); got != want {
			t.Errorf("Classify(%q) = %s, want %s", in, got, want)
		}
	}
	if Classify(nil) != "other" {
		t.Error("Classify(nil) != other")
	}
}

// every counter family, one execution class each, exact deltas
func TestR31DVMObsCounters(t *testing.T) {
	o := New()
	steps := []struct {
		what  string
		sc    rpc.Arguments
		err   interface{}
		extra []string
		want  map[string]uint64
	}{
		{"install ok", installArgs, nil, nil, map[string]uint64{"install_ok": 1}},
		{"invoke ok", callArgs, nil, nil, map[string]uint64{"invoke_ok": 1}},
		{"invoke discarded", callArgs, errors.New("Discarded knowingly"), nil, map[string]uint64{"invoke_err": 1, "revert_discarded": 1}},
		{"invoke out of gas", callArgs, errors.New("Recovered in function Insufficient Gas stack"), nil,
			map[string]uint64{"invoke_err": 1, "revert_out_of_gas": 1, "oog": 1}},
		{"install parse", installArgs, errors.New("line 3 unexpected token"), []string{MsgParse},
			map[string]uint64{"install_err": 1, "revert_parse": 1}},
		{"install exec panic, err nil", installArgs, nil, []string{MsgPanic},
			map[string]uint64{"install_err": 1, "revert_exec_panic": 1, "panic": 1}},
		{"invoke not installed", callArgs, errors.New("scid 00aa not installed"), nil,
			map[string]uint64{"invoke_err": 1, "revert_not_installed": 1}},
		{"no SC action", args("note", uint64(1)), nil, nil, map[string]uint64{}},
		{"unknown action", args(rpc.SCACTION, uint64(77)), errors.New("unknown action what to do scid 4d"), nil,
			map[string]uint64{"invoke_err": 1, "revert_bad_request": 1}},
	}
	for i, s := range steps {
		before := take()
		run(o, fmt.Sprintf("tx%d", i), s.sc, s.err, s.extra...)
		expect(t, s.what, before.delta(take()), s.want)
	}
	// the zero-signer outcome (err already set by the SC) counts as a failed invoke
	before := take()
	o.Handle(MsgOutcome, []interface{}{"txid", "z", "scdata", callArgs, "error", errors.New("Discarded knowingly"), "zero_signer", true})
	expect(t, "zero signer", before.delta(take()), map[string]uint64{"invoke_err": 1, "revert_discarded": 1})
	if len(o.pending) != 0 {
		t.Fatalf("pending entries left: %d", len(o.pending))
	}
	// a panic flag never leaks into the next tx
	before = take()
	run(o, "p1", callArgs, nil, MsgPanic)
	run(o, "p2", callArgs, nil)
	expect(t, "panic then ok", before.delta(take()), map[string]uint64{"invoke_err": 1, "invoke_ok": 1, "revert_exec_panic": 1, "panic": 1})
}

func TestR31DVMObsHistograms(t *testing.T) {
	// r31 closed loop: the histograms are package-global, so a re-run in the same process (-count=3, S3a) sees the
	// earlier samples: judge the per-bucket DELTA of this run, never the absolute count (flaky_20261113T125726)
	snap := func() map[string]uint64 {
		m := map[string]uint64{}
		ExecSeconds.VisitNonZeroBuckets(func(r string, c uint64) { m["exec "+r] = c })
		GasCompute.VisitNonZeroBuckets(func(r string, c uint64) { m["gc "+r] = c })
		GasStorage.VisitNonZeroBuckets(func(r string, c uint64) { m["gs "+r] = c })
		return m
	}
	before := snap()
	o := New()
	clock := time.Unix(1000, 0)
	o.now = func() time.Time { return clock }
	o.Handle(MsgStart, []interface{}{"txid", "h"})
	clock = clock.Add(250 * time.Millisecond)
	o.Handle(MsgOutcome, []interface{}{"txid", "h", "scdata", callArgs, "error", nil, "gascompute", uint64(123456), "gasstorage", uint64(77)})
	after := snap()
	var w strings.Builder
	for k, v := range after {
		if d := v - before[k]; d != 0 {
			fmt.Fprintf(&w, "%s %d\n", k, d)
		}
	}
	out := w.String()
	for _, want := range []string{"exec 2.448e-01...2.783e-01 1", "gc 1.136e+05...1.292e+05 1", "gs 6.813e+01...7.743e+01 1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("histograms miss %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "\n"); n != 3 {
		t.Fatalf("one outcome moved %d buckets, want 3:\n%s", n, out)
	}
}

// the handler runs inside the deferred function of process_transaction_sc: it must never panic there
func TestR31DVMObsHandlerNeverPanics(t *testing.T) {
	o := New()
	before := HandlerPanics.Get()
	bad := rpc.Arguments{{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: "not a uint64"}} // Has() true, Value().(uint64) panics
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Handle panicked: %v", r)
			}
		}()
		o.Handle(MsgOutcome, []interface{}{"txid", "x", "scdata", bad, "error", nil})
		o.Handle(MsgOutcome, []interface{}{"txid"})               // odd kv
		o.Handle(MsgOutcome, []interface{}{42, "x", "scdata", 7}) // wrong types
	}()
	if HandlerPanics.Get() != before+1 {
		t.Fatalf("handler panics %d, want 1 (the mistyped SC action)", HandlerPanics.Get()-before)
	}
	if o.Handle("some other line", nil) {
		t.Fatal("a foreign message was claimed")
	}
}

// a recording sink
type rec struct {
	level int
	lines *[]string
	name  string
}

func (r *rec) Init(logr.RuntimeInfo)  {}
func (r *rec) Enabled(level int) bool { return level <= r.level }
func (r *rec) Info(level int, msg string, kv ...interface{}) {
	*r.lines = append(*r.lines, fmt.Sprintf("%s V%d %s", r.name, level, msg))
}
func (r *rec) Error(err error, msg string, kv ...interface{}) {
	*r.lines = append(*r.lines, fmt.Sprintf("%s E %s", r.name, msg))
}
func (r *rec) WithValues(kv ...interface{}) logr.LogSink { return r }
func (r *rec) WithName(n string) logr.LogSink            { c := *r; c.name = n; return &c }

// the wrapper prints exactly what the real sink would print; only the CORE logger is force-enabled for the observer
func TestR31DVMObsSinkForwarding(t *testing.T) {
	var lines []string
	o := New()
	l := Wrap(logr.New(&rec{level: 1, lines: &lines}), o)
	core := l.WithName(CoreName)
	other := l.WithName("P2P")
	before := take()
	core.V(9).Info(MsgStart, "txid", "f")
	core.V(9).Info(MsgOutcome, "txid", "f", "scdata", callArgs, "error", nil)
	other.V(9).Info(MsgOutcome, "txid", "g", "scdata", callArgs, "error", nil) // not CORE: not observed
	core.V(1).Info("visible", "a", 1)
	core.V(2).Info("hidden")
	other.V(2).Info("hidden too")
	core.Error(errors.New("e"), "an error")
	expect(t, "observed", before.delta(take()), map[string]uint64{"invoke_ok": 1})
	if got := strings.Join(lines, "|"); got != "CORE V1 visible|CORE E an error" {
		t.Fatalf("forwarded lines %q", got)
	}
	if other.V(9).Enabled() || !core.V(9).Enabled() {
		t.Fatal("force-enable must apply to the CORE logger only")
	}
	Wrap(logr.Discard(), o).WithName(CoreName).V(9).Info(MsgStart, "txid", "d") // a discard logger wraps without panicking
}

// the messages and the logger lines in the chain's execute path stay what this package reads
func TestR31DVMObsMessagesPinned(t *testing.T) {
	src, err := os.ReadFile("../../blockchain/transaction_execute.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, want := range []string{
		`logger.V(9).Info("` + MsgStart + `", "txid", txhash)`,
		`logger.V(9).Info("` + MsgPanic + `", "txid", txhash)`,
		`logger.V(9).Info("` + MsgOutcome + `", "txid", txhash, "scdata", tx.SCDATA, "error", err, "gascompute", gascompute, "gasstorage", gasstorage)`,
		`logger.V(9).Info("` + MsgOutcome + `", "txid", txhash, "scdata", tx.SCDATA, "error", err, "zero_signer", true, "gascompute", gascompute, "gasstorage", gasstorage)`,
		`logger.V(1).Info("` + MsgParse + `", "txid", txhash,`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("transaction_execute.go lacks %s", want)
		}
	}
	main, err := os.ReadFile("../../cmd/derod/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(main), "globals.Logger = dvmobs.Wrap(core_logger, nil)\n\tchain, err := blockchain.Blockchain_Start(params)") {
		t.Error("derod no longer wraps the logger right before Blockchain_Start")
	}
}

// r31 verify (d5 verifier): the wrapper must not change any CORE verbosity guard except DvmLevel; before the fix every
// CORE V(n).Enabled() was true, which turned on the V(1)-guarded Load_Merkle_Hash block of Add_Complete_Block
func TestR31DVMObsCoreEnabledParity(t *testing.T) {
	var lines []string
	plain := logr.New(&rec{level: 1, lines: &lines}).WithName(CoreName)
	wrapped := Wrap(logr.New(&rec{level: 1, lines: &lines}), New()).WithName(CoreName)
	for l := 0; l <= 12; l++ {
		want := plain.V(l).Enabled()
		if l == DvmLevel {
			want = true
		}
		if got := wrapped.V(l).Enabled(); got != want {
			t.Fatalf("CORE V(%d).Enabled() = %v, plain logger %v (only V(%d) may be forced)", l, got, plain.V(l).Enabled(), DvmLevel)
		}
	}
}
