package main

import (
	"bytes"
	"os"
	"strings"

	"github.com/deroproject/derohe/rpc"
	"sync/atomic"
	"testing"
	"time"

	"github.com/docopt/docopt-go"
)

func TestParsePhaseDuty(t *testing.T) {
	ok := map[string]phase_duty_cfg{
		"":         {},
		"off":      {},
		"Balanced": {on: true, balanced: true, regular: 100},
		"100:80":   {on: true, regular: 100, final: 80},
		" 90:10 ":  {on: true, regular: 90, final: 10},
	}
	for in, want := range ok {
		got, err := parse_phase_duty(in)
		if err != nil || got != want {
			t.Fatalf("%q: %+v %v, want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"90", "0:50", "101:5", "90:0", "a:b", "1:2:3", "auto"} {
		if _, err := parse_phase_duty(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestBalancedFinalDutyKeepsMean(t *testing.T) {
	// the measured prior: regular 48.9% of the wall time; --cpu-max=90 -> final 80 (0.489*100 + 0.511*80.4 = 90)
	if got := balanced_final_duty(90, 100, 0.489); got != 80 {
		t.Fatalf("balanced final = %d, want 80", got)
	}
	for _, f := range []float64{0.3, 0.489, 0.6} {
		fd := balanced_final_duty(90, 100, f)
		mean := f*100 + (1-f)*float64(fd)
		if mean < 89 || mean > 91 {
			t.Fatalf("regFrac %.3f: final %d gives mean %.2f, want ~90", f, fd, mean)
		}
	}
	if got := balanced_final_duty(40, 100, 0.6); got != 1 { // cannot keep the mean: never below 1
		t.Fatalf("infeasible mean: %d, want the floor 1", got)
	}
	if got := balanced_final_duty(90, 100, 0); got != 80 { // no data -> prior
		t.Fatalf("regFrac 0 -> %d, want the prior's 80", got)
	}
}

func TestJobIsFinal(t *testing.T) {
	// first byte: version 1 | PastCount<<6 | HighDiff 0x10 | Final 0x20 (block/miniblock.go Serialize)
	cases := map[string]bool{"41": false, "51": false, "71": true, "31": true, "": false, "z1": false, "4": false}
	for in, want := range cases {
		if got := job_is_final(in + strings.Repeat("00", 47)); in != "" && len(in) == 2 && got != want {
			t.Fatalf("%q: %v, want %v", in, got, want)
		}
		if len(in) < 2 && job_is_final(in) {
			t.Fatalf("short blob %q read as final", in)
		}
	}
}

func TestPhaseClockBooksTimeAndHashes(t *testing.T) {
	var p phase_clock
	t0 := time.Unix(1000, 0)
	if !p.observe(false, t0, 0) {
		t.Fatal("first observation must report a phase start")
	}
	if p.observe(false, t0.Add(4*time.Second), 400) { // same phase (job refresh)
		t.Fatal("a same-phase job reported a change")
	}
	if !p.observe(true, t0.Add(9*time.Second), 900) {
		t.Fatal("regular -> final not reported")
	}
	secs, hashes := p.snapshot(t0.Add(18*time.Second), 1800)
	if secs != [2]float64{9, 9} || hashes != [2]uint64{900, 900} {
		t.Fatalf("secs %v hashes %v, want [9 9] [900 900]", secs, hashes)
	}
	if !p.observe(false, t0.Add(19*time.Second), 1900) {
		t.Fatal("final -> regular not reported")
	}
	secs, hashes = p.snapshot(t0.Add(19*time.Second), 1900)
	if secs != [2]float64{9, 10} || hashes != [2]uint64{900, 1000} {
		t.Fatalf("after switch: secs %v hashes %v", secs, hashes)
	}
}

func TestRegularFractionPrior(t *testing.T) {
	if got := regular_fraction([2]float64{60, 60}); got != phase_regular_prior {
		t.Fatalf("2 min of data replaced the prior: %v", got)
	}
	if got := regular_fraction([2]float64{1200, 1800}); got != 0.4 {
		t.Fatalf("50 min of data: %v, want 0.4", got)
	}
}

func TestPhaseCaps(t *testing.T) {
	c := phase_duty_cfg{on: true, regular: 100, final: 30}
	if cpu, gpu := phase_caps(c, false, 90, 96, 0.5); cpu != 100 || gpu != 96 {
		t.Fatalf("regular: %d/%d, want 100/96 (GPU never above --gpu-max)", cpu, gpu)
	}
	if cpu, gpu := phase_caps(c, true, 90, 96, 0.5); cpu != 30 || gpu != 30 {
		t.Fatalf("final: %d/%d, want 30/30", cpu, gpu)
	}
	b := phase_duty_cfg{on: true, balanced: true, regular: 100}
	if cpu, gpu := phase_caps(b, true, 90, 96, 0.489); cpu != 80 || gpu != 96 {
		t.Fatalf("balanced final: %d/%d, want 80/96 (balanced keeps the GPU at --gpu-max)", cpu, gpu)
	}
}

// r23b merge (PAY-3 fix 1): balanced keeps the time-weighted mean CPU duty at --cpu-max and the GPU's at --gpu-max
func TestBalancedPhaseMeansHoldCaps(t *testing.T) {
	b := phase_duty_cfg{on: true, balanced: true, regular: 100}
	for _, f := range []float64{0.40, 0.489, 0.55} {
		rc, rg := phase_caps(b, false, 90, 96, f)
		fc, fg := phase_caps(b, true, 90, 96, f)
		cpu := f*float64(rc) + (1-f)*float64(fc)
		gpu := f*float64(rg) + (1-f)*float64(fg)
		if cpu < 89 || cpu > 91 {
			t.Fatalf("f=%.3f mean CPU duty %.2f, want 90+-1", f, cpu)
		}
		if gpu != 96 {
			t.Fatalf("f=%.3f mean GPU duty %.2f, want 96 (--gpu-max)", f, gpu)
		}
	}
}

// phase_note moves the caps only with --phase-duty, and only on a phase change
func TestPhaseNoteMovesCaps(t *testing.T) {
	saved_cfg, saved_cpu, saved_gpu, saved_cm, saved_gm := phase_cfg, cpu_duty_pct(), gpu_duty_pct(), cpu_max, gpu_max
	phases = phase_clock{}
	t.Cleanup(func() {
		phase_cfg, cpu_max, gpu_max, phases = saved_cfg, saved_cm, saved_gm, phase_clock{}
		set_cpu_duty(saved_cpu)
		set_gpu_duty(saved_gpu)
	})
	cpu_max, gpu_max = 90, 96
	set_cpu_duty(90)
	set_gpu_duty(96)
	reg, fin := "41"+strings.Repeat("00", 47), "71"+strings.Repeat("00", 47)
	phase_cfg = phase_duty_cfg{}
	phase_note(reg)
	phase_note(fin)
	if cpu_duty_pct() != 90 || gpu_duty_pct() != 96 {
		t.Fatalf("phase duty off moved the caps: %d/%d", cpu_duty_pct(), gpu_duty_pct())
	}
	phase_cfg = phase_duty_cfg{on: true, regular: 100, final: 20}
	phase_note(reg)
	if cpu_duty_pct() != 100 || gpu_duty_pct() != 96 {
		t.Fatalf("regular phase caps %d/%d, want 100/96", cpu_duty_pct(), gpu_duty_pct())
	}
	phase_note(fin)
	if cpu_duty_pct() != 20 || gpu_duty_pct() != 20 {
		t.Fatalf("final phase caps %d/%d, want 20/20", cpu_duty_pct(), gpu_duty_pct())
	}
}

func TestPhaseWakeSleepWakesOnlyOnLaterChange(t *testing.T) {
	var changed int64 = 1
	go func() { time.Sleep(30 * time.Millisecond); atomic.StoreInt64(&changed, time.Now().UnixNano()) }()
	if slept := phase_wake_sleep(2*time.Second, func() int64 { return atomic.LoadInt64(&changed) }); slept > 500*time.Millisecond {
		t.Fatalf("slept %v through a phase change", slept)
	}
	// a change stamped before the sleep began (during the busy window) does NOT shorten it
	past := time.Now().UnixNano()
	if slept := phase_wake_sleep(30*time.Millisecond, func() int64 { return past }); slept < 30*time.Millisecond {
		t.Fatalf("slept only %v of 30ms: an earlier change cut the sleep", slept)
	}
}

// only a final->regular change under --phase-duty stamps the wake; same-phase (keepalive) jobs never do
func TestPhaseNoteStampsWakeOnlyFinalToRegular(t *testing.T) {
	saved_cfg, saved_cpu, saved_gpu, saved_cm, saved_gm := phase_cfg, cpu_duty_pct(), gpu_duty_pct(), cpu_max, gpu_max
	phases = phase_clock{}
	t.Cleanup(func() {
		set_phase_duty(saved_cfg)
		cpu_max, gpu_max, phases = saved_cm, saved_gm, phase_clock{}
		set_cpu_duty(saved_cpu)
		set_gpu_duty(saved_gpu)
	})
	cpu_max, gpu_max = 90, 96
	reg, fin := "41"+strings.Repeat("00", 47), "71"+strings.Repeat("00", 47)
	set_phase_duty(phase_duty_cfg{on: true, regular: 100, final: 10})
	w0 := last_phase_wake()
	phase_note(reg)
	phase_note(reg)
	phase_note(fin)
	phase_note(fin)
	if last_phase_wake() != w0 {
		t.Fatal("a regular/final or same-phase job stamped the phase wake")
	}
	phase_note(reg)
	if last_phase_wake() == w0 {
		t.Fatal("final->regular did not stamp the phase wake")
	}
	if !phase_wake_enabled() {
		t.Fatal("set_phase_duty(on) did not enable the wake")
	}
	set_phase_duty(phase_duty_cfg{})
	if phase_wake_enabled() {
		t.Fatal("set_phase_duty(off) left the wake on")
	}
}

func TestUsageParsesNewFlags(t *testing.T) {
	args, err := docopt.Parse(command_line, []string{"--wallet-address=x", "--phase-duty=balanced", "--supervised"}, true, "v", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if args["--phase-duty"] != "balanced" || args["--supervised"] != true {
		t.Fatalf("parsed %v %v", args["--phase-duty"], args["--supervised"])
	}
	args, err = docopt.Parse(command_line, []string{"--wallet-address=x"}, true, "v", false, false)
	if err != nil || args["--phase-duty"] != "off" || args["--supervised"] != false {
		t.Fatalf("defaults: %v %v %v", args["--phase-duty"], args["--supervised"], err)
	}
}

func TestConsoleExitIgnoredWhenSupervised(t *testing.T) {
	if console_exit_allowed(true) {
		t.Fatal("--supervised: a typed exit must not stop the miner")
	}
	if !console_exit_allowed(false) {
		t.Fatal("interactive: a typed exit must stop the miner")
	}
	for _, w := range []string{"exit", "QUIT", " bye "} {
		if !is_console_exit_word(w) {
			t.Fatalf("%q is an exit word", w)
		}
		var out bytes.Buffer
		called := ""
		if console_exit(w, true, &out, func(r string) { called = r }) || called != "" {
			t.Fatalf("--supervised: %q called exit (%q)", w, called)
		}
		if !strings.Contains(out.String(), "console exit ignored") {
			t.Fatalf("--supervised: no message for %q: %q", w, out.String())
		}
		if !console_exit(w, false, &out, func(r string) { called = r }) || called != "console "+strings.ToLower(strings.TrimSpace(w)) {
			t.Fatalf("interactive: %q did not exit (%q)", w, called)
		}
	}
	if is_console_exit_word("exits") || is_console_exit_word("") {
		t.Fatal("non-exit words matched")
	}
}

// r23b merge (PAY-1 fix 3): the console loop routes every exit word through console_exit with the --supervised flag
func TestConsoleLoopWiresExit(t *testing.T) {
	src, err := os.ReadFile("miner.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	if !strings.Contains(s, "case is_console_exit_word(line):\n\t\t\tconsole_exit(line, supervised, os.Stdout,") {
		t.Fatal("console loop does not call console_exit(line, supervised, ...) for exit words")
	}
	for _, bad := range []string{`case strings.ToLower(line) == "exit":`, `case strings.ToLower(line) == "quit":`, `case strings.ToLower(line) == "bye":`} {
		if strings.Contains(s, bad) {
			t.Fatalf("console loop still has a direct exit case %s", bad)
		}
	}
}

// take_job is where the phase is read: a final job after a regular one is booked and stamps the job-change time
func TestTakeJobBooksPhase(t *testing.T) {
	mutex.Lock()
	saved, saved_counter := job, job_counter
	mutex.Unlock()
	phases = phase_clock{}
	defer func() { mutex.Lock(); job, job_counter = saved, saved_counter; mutex.Unlock(); phases = phase_clock{} }()
	before := time.Now().UnixNano()
	if !take_job(rpc.GetBlockTemplate_Result{JobID: "1.0", Blockhashing_blob: test_blob(false, 7), Difficulty: "1000", Height: 5}) {
		t.Fatal("valid job dropped")
	}
	if last_job_change() < before {
		t.Fatal("take_job did not stamp the job-change time")
	}
	time.Sleep(20 * time.Millisecond)
	if !take_job(rpc.GetBlockTemplate_Result{JobID: "2.0", Blockhashing_blob: test_blob(true, 7), Difficulty: "9000", Height: 5}) {
		t.Fatal("valid final job dropped")
	}
	secs, _ := phases.snapshot(time.Now(), 0)
	if secs[0] < 0.015 || !phases.final {
		t.Fatalf("phase not booked: secs %v final %v", secs, phases.final)
	}
}

// with --phase-duty the mining threads' throttle (cpu_throttle) ends a long low-duty sleep on a final->regular change
func TestCpuThrottleWakesOnPhaseChange(t *testing.T) {
	saved, saved_cfg := cpu_duty_pct(), phase_cfg
	defer func() { set_cpu_duty(saved); set_phase_duty(saved_cfg) }()
	set_phase_duty(phase_duty_cfg{on: true, regular: 100, final: 1})
	set_cpu_duty(1) // 40 ms busy -> 3.96 s sleep without the wake
	start := time.Now().Add(-cpu_throttle_window)
	go func() { time.Sleep(30 * time.Millisecond); atomic.StoreInt64(&phase_wake_ns, time.Now().UnixNano()) }()
	t0 := time.Now()
	cpu_throttle(&start)
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("cpu_throttle slept %v through a phase change", d)
	}
}

// r23b merge (PAY-3 fix 2): a job stream (keepalives every 2 s live; 50/s here) neither skips nor shortens the sleep,
// with or without --phase-duty, so a 10% cap is achieved
func TestCpuThrottleIgnoresJobStream(t *testing.T) {
	saved, saved_cfg := cpu_duty_pct(), phase_cfg
	defer func() { set_cpu_duty(saved); set_phase_duty(saved_cfg) }()
	set_cpu_duty(10)
	quit := make(chan struct{})
	defer close(quit)
	go func() {
		for {
			select {
			case <-quit:
				return
			case <-time.After(20 * time.Millisecond):
				atomic.StoreInt64(&job_change_ns, time.Now().UnixNano())
			}
		}
	}()
	for _, on := range []bool{false, true} {
		set_phase_duty(phase_duty_cfg{on: on, regular: 100, final: 10})
		start := time.Now().Add(-cpu_throttle_window)
		atomic.StoreInt64(&job_change_ns, time.Now().UnixNano()) // a job during the busy window
		s0 := atomic.LoadInt64(&cpu_throttle_sleep_ns)
		cpu_throttle(&start)
		want := int64(cpu_throttle_window) * 9 // busy*(100-10)/10 at share 1
		if d := atomic.LoadInt64(&cpu_throttle_sleep_ns) - s0; d < want*95/100 {
			t.Fatalf("phase-duty %v: slept %v of %v with a job stream: jobs shortened the duty sleep", on, time.Duration(d), time.Duration(want))
		}
	}
}

// achieved duty under cpu_throttle follows the cap the phase sets (busy-spin windows, wall clock)
func TestThrottleAchievesPhaseDuty(t *testing.T) {
	saved := cpu_duty_pct()
	defer set_cpu_duty(saved)
	measure := func(p int) float64 {
		set_cpu_duty(p)
		var busy time.Duration
		t0 := time.Now()
		start := time.Now()
		for time.Since(t0) < 800*time.Millisecond {
			b := time.Now()
			for time.Since(b) < time.Millisecond {
			}
			busy += time.Since(b)
			cpu_throttle(&start)
		}
		return busy.Seconds() / time.Since(t0).Seconds()
	}
	lo, hi := measure(25), measure(100)
	if lo < 0.12 || lo > 0.40 || hi < 0.85 {
		t.Fatalf("achieved duty %.2f at cap 25, %.2f at cap 100", lo, hi)
	}
}
