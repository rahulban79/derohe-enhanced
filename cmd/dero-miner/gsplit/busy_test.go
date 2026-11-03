package gsplit

import (
	"math/rand"
	"sort"
	"testing"
	"time"
)

// r21 splitpipe (gpukernels-8): overlapping command buffers count once; the sum of spans is what the old debt used.
func TestBusyUnionExact(t *testing.T) {
	var u busyUnion
	steps := []struct{ s, e, want int64 }{
		{100, 200, 100}, // first buffer
		{150, 260, 60},  // overlaps the tail: only 200..260 is new
		{120, 180, 0},   // nested: nothing new
		{300, 400, 100}, // disjoint
		{250, 310, 40},  // bridges the gap 260..300
		{50, 500, 150},  // covers everything: 50..100 and 400..500 are new
		{500, 510, 10},  // touching
	}
	for i, st := range steps {
		if got := u.add(st.s, st.e); got != st.want {
			t.Fatalf("step %d add(%d,%d) = %d, want %d (segs %v)", i, st.s, st.e, got, st.want, u.segs)
		}
	}
	if len(u.segs) != 1 || u.segs[0] != [2]int64{50, 510} {
		t.Fatalf("segments %v, want one [50,510)", u.segs)
	}
	if u.add(10, 10) != 0 || u.add(20, 10) != 0 {
		t.Fatal("an empty interval added busy time")
	}
}

// The total equals the measure of the union whatever order the intervals arrive in (two queues complete out of order).
func TestBusyUnionMatchesBruteForce(t *testing.T) {
	rng := rand.New(rand.NewSource(21))
	for trial := 0; trial < 200; trial++ {
		var u busyUnion
		var cover [2000]bool
		var total int64
		type iv struct{ s, e int64 }
		var ivs []iv
		for k := 0; k < 30; k++ {
			s := int64(rng.Intn(1900))
			ivs = append(ivs, iv{s, s + 1 + int64(rng.Intn(100))})
		}
		sort.Slice(ivs, func(a, b int) bool { return ivs[a].e < ivs[b].e }) // arrival order: by end
		for _, x := range ivs {
			total += u.add(x.s, x.e)
			for p := x.s; p < x.e; p++ {
				cover[p] = true
			}
		}
		var want int64
		for _, c := range cover {
			if c {
				want++
			}
		}
		if total != want {
			t.Fatalf("trial %d: union %d, brute force %d", trial, total, want)
		}
		for i := 1; i < len(u.segs); i++ {
			if u.segs[i-1][1] >= u.segs[i][0] {
				t.Fatalf("segments not disjoint/sorted: %v", u.segs)
			}
		}
	}
}

// Old segments are forgotten (bounded memory); a span reaching behind the horizon is counted in full (stricter cap).
func TestBusyUnionBounded(t *testing.T) {
	var u busyUnion
	for i := int64(0); i < 10*busyMaxSegs; i++ {
		u.add(i*1000, i*1000+10)
	}
	if len(u.segs) > busyMaxSegs {
		t.Fatalf("%d segments kept, cap %d", len(u.segs), busyMaxSegs)
	}
	var v busyUnion
	v.add(0, 100)
	if got := v.add(busyHorizonNs+200, busyHorizonNs+300); got != 100 || len(v.segs) != 1 {
		t.Fatalf("segment past the horizon kept: add=%d segs=%v", got, v.segs)
	}
}

// The engine charges the --gpu-max debt on the union: two fully overlapped 1 ms buffers owe one 1 ms share, and Stats
// report the sum (GPUus) and the union (GPUBusyUs) separately.
func TestReplyLoopDebtOnUnion(t *testing.T) {
	r := newRig(t, true, 4, 2, 0)
	e := r.e
	defer e.Close()
	e.SetGPUMax(50) // r22 duty bucket: charge = busy * 100/50 = 2 * busy (duty.go), at the cap in force (SetGPUMax)
	ch := make(chan reply, 4)
	ft := &fakeReplies{ch: ch}
	at := e.clock() + int64(time.Second)
	ch <- reply{status: 0, us: 1000, tag: 0xffff, op: 1, at: at} // unknown tag: ignored before accounting
	// op 4: an op the loop only accounts (op 3 is the r21 GPU sort, routed to sortDone)
	ch <- reply{status: 0, us: 1000, tag: 0, op: 4, at: at}            // buffer A: [at-1ms, at]
	ch <- reply{status: 0, us: 1000, tag: 1, op: 4, at: at + 1000}     // buffer B: overlaps A but for 1 us
	ch <- reply{status: 0, us: 500, tag: 0, op: 4, at: at + 3_000_000} // disjoint 0.5 ms
	close(ch)
	e.wgReply.Add(1)
	e.lifeMu.Lock()
	close(e.quit) // the loop must not respawn when its channel closes
	e.lifeMu.Unlock()
	e.replyLoop(ft)
	st := e.Stats()
	if st.GPUus != 2500 {
		t.Fatalf("GPUus = %d, want the 2500 us sum", st.GPUus)
	}
	if st.GPUBusyUs != 1501 {
		t.Fatalf("GPUBusyUs = %d, want the 1501 us union", st.GPUBusyUs)
	}
	if d := e.debt.Load(); d != 2*1501*1000 {
		t.Fatalf("debt = %d ns, want 3002000 (2 x the 1501 us union, not the 2.5 ms sum)", d)
	}
	e.quit = make(chan struct{}) // let the deferred Close run its normal path
}

type fakeReplies struct{ ch chan reply }

func (f *fakeReplies) issue(op, first, n, tag uint32) error { return nil }
func (f *fakeReplies) replies() <-chan reply                { return f.ch }
func (f *fakeReplies) close()                               {}
func (f *fakeReplies) kill()                                {}

// r21 merge: op 3 (GPU sort) buffers are charged on the same wall-clock union as op 1/op 2 (gpukernels-8), not on
// their summed spans: two overlapping 1 ms sort buffers owe one 1 ms (+1 us) share of --gpu-max debt.
func TestSortDoneDebtOnUnion(t *testing.T) {
	r := newRig(t, true, 4, 2, 0)
	e := r.e
	defer e.Close()
	e.SetGPUMax(50) // r22 duty bucket: charge = busy * 100/50 = 2 * busy (duty.go), at the cap in force (SetGPUMax)
	at := e.clock() + int64(time.Second)
	for i, b := range e.batches[:2] {
		b.sorted = true
		e.sortInflight.Add(1)
		// status 1: a failed sort hands the batch to the CPU, but its GPU time was spent and is charged
		e.sortDone(b, reply{status: 1, us: 1000, tag: uint32(i), op: 3, at: at + int64(i)*1000})
	}
	if st := e.Stats(); st.SortUs != 2000 || st.GPUBusyUs != 1001 {
		t.Fatalf("SortUs %d (want the 2000 us sum), GPUBusyUs %d (want the 1001 us union)", st.SortUs, st.GPUBusyUs)
	}
	if d := e.debt.Load(); d != 2*1001*1000 {
		t.Fatalf("debt = %d ns, want 2002000 (2 x the 1001 us union)", d)
	}
}

// r22 gpukernels: Stats split GPUus by kernel. Every successful op 1 reply adds its span to S1us and one to S1Cmds,
// every op 2 reply to SHAus/SHACmds; the two partition GPUus when the GPU sort is off, and failed replies count in
// neither (they are re-issued).
func TestReplyLoopPerKernelSpans(t *testing.T) {
	r := newRig(t, true, 8, 3, 0)
	r.g.failN.Store(2) // two failed (status 2) replies first: re-issued, never accounted
	r.e.Start()
	n := r.mine(2, 64)
	r.e.Close() // quiesced: the counters below are read as one consistent set
	if n < 64 {
		t.Fatalf("mined %d hashes, want 64", n)
	}
	st := r.e.Stats()
	if st.S1Cmds == 0 || st.SHACmds == 0 {
		t.Fatalf("per-kernel buffer counts not recorded: %+v", st)
	}
	// the soft GPU answers every command with a 7 us span
	if st.S1us != 7*st.S1Cmds || st.SHAus != 7*st.SHACmds {
		t.Fatalf("S1us %d / S1Cmds %d, SHAus %d / SHACmds %d: want 7 us per buffer", st.S1us, st.S1Cmds, st.SHAus, st.SHACmds)
	}
	if st.S1us+st.SHAus != st.GPUus {
		t.Fatalf("S1us %d + SHAus %d != GPUus %d (sort off: the two kernels are all of it)", st.S1us, st.SHAus, st.GPUus)
	}
	if st.GPURetries < 2 {
		t.Fatalf("GPURetries %d, want the 2 injected failures", st.GPURetries)
	}
	// every collected batch passed one op 1 and one op 2 (in flight ones may have finished op 1 only)
	if st.SHACmds > st.S1Cmds || st.SHACmds < st.Batches {
		t.Fatalf("SHACmds %d, S1Cmds %d, Batches %d", st.SHACmds, st.S1Cmds, st.Batches)
	}
}
