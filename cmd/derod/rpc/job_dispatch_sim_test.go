package rpc

import (
	"math/rand"
	"sort"
	"testing"
)

// A virtual-time model of job dispatch against the 100 ms template cache (blockchain/miner_block.go
// Create_new_block_template_mining), comparing the pre-r23 loop (per-miniblock SendJob + 10 ms poll + 500 ms resend)
// with run_job_dispatcher's policy (dispatch_core, the code that ships). The event trace is the live network shape:
// 9 normal miniblocks per height ~1 s apart, then the block ~9 s later (the final is 9x the difficulty).
// Measured per height: L9 = time from the 9th normal miniblock reaching this node until a job carrying a FINAL
// template is sent (normal shares found meanwhile cannot be paid), and LH = time from a block arriving until a job
// for the new height is sent.

type sim_tmpl struct {
	ts, height int64
	minis      int
	ok         bool
}

// A template build takes time: its timestamp is read after the trigger (Create_new_miner_block stamps it near the end),
// usually 1 ms or more later, sometimes in the same millisecond. p0 is the same-millisecond probability; the live
// share of refresh resends (1,452 of 12,604 jobs, 11.5%) calibrates it.
type sim_chain struct {
	height int64
	minis  int
	cache  sim_tmpl
	builds int
	r      *rand.Rand
	p0     float64
	// r24 (getworkops): key_minis models the report-only blockchain/ proposal (B39): the cache is also rebuilt when the
	// pool's normal-miniblock count for the template differs from the cached template's.
	key_minis bool
	// r24: serial makes the model dispatcher one goroutine, as run_job_dispatcher is: a kick that arrives while a send
	// is still building its template is handled when that send has left, never at the kick's own (earlier) time. The
	// r23c model (serial=false) let a send start before the previous one ended, so a 9th miniblock that landed during
	// a 1-3 ms build was answered by a template stamped AFTER it that did not contain it; refresh_due (correctly, for
	// the code) saw a newer stamp and scheduled nothing, and that flip waited for the 2 s keepalive. The code cannot do
	// that: Create_new_miner_block stamps bl.Timestamp (miner_block.go:304) BEFORE it reads the pool (:335).
	serial bool
}

// template returns the template and the time the job leaves (after the build, if there was one)
func (c *sim_chain) template(now int64) (sim_tmpl, int64) {
	m := c.minis
	if m > 9 {
		m = 9
	}
	if !c.cache.ok || c.cache.ts+100 < now || c.cache.height != c.height || (c.key_minis && c.cache.minis != m) {
		b := int64(0)
		if c.r.Float64() >= c.p0 {
			b = 1 + c.r.Int63n(3)
		}
		c.cache = sim_tmpl{ts: now + b, height: c.height, minis: m, ok: true}
		c.builds++
		return c.cache, now + b
	}
	return c.cache, now
}

type sim_send struct {
	t, height int64
	final     bool
	held      int   // r24: normal miniblocks the pool held when the job left (note_flip's held_normal)
	trigger   int64 // r24: send_job's trigger_ms
}

type sim_ev struct {
	t     int64
	block bool
}

func sim_trace(seed int64, heights int) []sim_ev {
	r := rand.New(rand.NewSource(seed))
	var ev []sim_ev
	t := int64(1000)
	for h := 0; h < heights; h++ {
		for i := 0; i < 9; i++ {
			t += 1 + int64(r.ExpFloat64()*1000)
			ev = append(ev, sim_ev{t: t})
		}
		t += 1 + int64(r.ExpFloat64()*9000)
		ev = append(ev, sim_ev{t: t, block: true})
	}
	return ev
}

type sim_out struct {
	l9, lh        []int64
	sends, builds int
	secs          float64
}

// send_job's template and refresh logic on the model chain
func sim_send_job(c *sim_chain, due *int64, now, trigger int64, sends *[]sim_send) int64 {
	tm, out := c.template(now)
	if d := refresh_due(tm.ts, trigger); d != 0 && *due == 0 {
		*due = d
	}
	*sends = append(*sends, sim_send{t: out, height: tm.height, final: tm.minis >= 9, held: c.minis, trigger: trigger})
	return out
}

var sim_old_refreshes int

func sim_old(ev []sim_ev, phase int64, p0 float64) ([]sim_send, int) {
	c := &sim_chain{height: 1, r: rand.New(rand.NewSource(7)), p0: p0}
	var sends []sim_send
	var due int64
	old_count, old_height, old_time := -1, int64(0), int64(0)
	tick := phase
	end := ev[len(ev)-1].t + 1000
	i := 0
	for tick < end {
		for i < len(ev) && ev[i].t <= tick {
			e := ev[i]
			if e.block {
				c.height++
				c.minis = 0
			} else {
				c.minis++
				sim_send_job(c, &due, e.t, e.t, &sends) // Notify_MiniBlock_Addition -> SendJob
			}
			i++
		}
		count := c.minis + int(c.height)*100 // MiniBlocks.Count() also changes on the purge at a new height
		refresh := due != 0 && tick >= due
		if refresh {
			due = 0
			sim_old_refreshes++
		}
		if old_count != count || old_height != c.height || refresh || tick-old_time > 500 {
			old_count, old_height = count, c.height
			tick = sim_send_job(c, &due, tick, tick, &sends)
			old_time = tick
		}
		tick += 10
	}
	return sends, c.builds
}

func sim_new(ev []sim_ev, keepalive int64, p0 float64) ([]sim_send, int) {
	return sim_new_chain(ev, keepalive, &sim_chain{height: 1, r: rand.New(rand.NewSource(7)), p0: p0})
}

// sim_new_chain runs the shipped dispatcher policy against a given model chain (r24: lets a test vary the cache rule).
func sim_new_chain(ev []sim_ev, keepalive int64, c *sim_chain) ([]sim_send, int) {
	var sends []sim_send
	due := new(int64)
	d := &dispatch_core{keepalive_ms: keepalive, due: due}
	var events uint64
	var busy int64 // r24 serial: when the last send left
	run := func(now int64) int64 {
		if c.serial && now < busy {
			now = busy
		}
		st := dispatch_state{height: c.height, minis: c.minis, events: events}
		if reason, trigger := d.decide(st, now); reason != "" {
			var p int64 = *due
			now = sim_send_job(c, &p, now, trigger, &sends)
			busy = now
			if *due == 0 {
				*due = p
			}
			d.sent(now, true)
		}
		return now + d.wait_ms(now, 10)
	}
	wake := run(0)
	end := ev[len(ev)-1].t + 1000
	i := 0
	for wake < end {
		if i < len(ev) && ev[i].t <= wake {
			e := ev[i]
			if e.block {
				c.height++
				c.minis = 0
				events++
			} else {
				c.minis++
			}
			i++
			wake = run(e.t) // the kick
			continue
		}
		wake = run(wake)
	}
	return sends, c.builds
}

func sim_measure(ev []sim_ev, sends []sim_send, builds int) (o sim_out) {
	o.sends, o.builds = len(sends), builds
	o.secs = float64(ev[len(ev)-1].t) / 1000
	h := int64(1)
	n := 0
	var t9 int64
	for _, e := range ev {
		if e.block {
			// LH: first send for the new height at or after the block
			j := sort.Search(len(sends), func(k int) bool { return sends[k].t >= e.t })
			for ; j < len(sends); j++ {
				if sends[j].height == h+1 {
					o.lh = append(o.lh, sends[j].t-e.t)
					break
				}
			}
			// L9: first FINAL send for this height at or after the 9th miniblock
			j = sort.Search(len(sends), func(k int) bool { return sends[k].t >= t9 })
			for ; j < len(sends) && sends[j].t < e.t; j++ {
				if sends[j].height == h && sends[j].final {
					o.l9 = append(o.l9, sends[j].t-t9)
					break
				}
			}
			h++
			n = 0
			continue
		}
		n++
		if n == 9 {
			t9 = e.t
		}
	}
	return
}

func sim_stats(v []int64) (mean float64, p50, p90, p99 int64, over int) {
	s := append([]int64(nil), v...)
	sort.Slice(s, func(a, b int) bool { return s[a] < s[b] })
	var sum int64
	for _, x := range s {
		sum += x
		if x > 10 {
			over++
		}
	}
	return float64(sum) / float64(len(s)), s[len(s)/2], s[len(s)*9/10], s[len(s)*99/100], over
}

// The shipped policy must never be slower than the old loop to put the miner on final work or on the new height,
// must send fewer jobs, and must build fewer templates.
func TestDispatchPolicySimulation(t *testing.T) {
	ev := sim_trace(23, 4000)
	p0 := 0.03
	sim_old_refreshes = 0
	so, bo := sim_old(ev, 3, p0)
	old := sim_measure(ev, so, bo)
	sn, bn := sim_new(ev, JOB_KEEPALIVE.Milliseconds(), p0)
	nw := sim_measure(ev, sn, bn)
	s5, b5 := sim_new(ev, 500, p0)
	n5 := sim_measure(ev, s5, b5)
	for _, r := range []struct {
		name string
		o    sim_out
	}{{"old (event+poll, 500 ms resend)", old}, {"new keepalive 500 ms", n5}, {"new keepalive 2 s (shipped)", nw}} {
		m9, a9, b9, c9, o9 := sim_stats(r.o.l9)
		mh, ah, bh, ch, _ := sim_stats(r.o.lh)
		t.Logf("%-32s L9 mean %.2f ms p50 %d p90 %d p99 %d (>10ms %.1f%%) | LH mean %.2f ms p50 %d p90 %d p99 %d | jobs/s %.2f builds/s %.2f",
			r.name, m9, a9, b9, c9, 100*float64(o9)/float64(len(r.o.l9)), mh, ah, bh, ch,
			float64(r.o.sends)/r.o.secs, float64(r.o.builds)/r.o.secs)
	}
	t.Logf("old loop refresh resends: %.1f%% of jobs (live r22: 1,452 of 12,604 = 11.5%%)", 100*float64(sim_old_refreshes)/float64(old.sends))
	m9o, _, _, _, _ := sim_stats(old.l9)
	m9n, _, _, _, _ := sim_stats(nw.l9)
	mho, _, _, _, _ := sim_stats(old.lh)
	mhn, _, _, _, _ := sim_stats(nw.lh)
	if m9n > m9o || mhn > mho {
		t.Fatalf("new policy slower: L9 %.2f vs %.2f, LH %.2f vs %.2f", m9n, m9o, mhn, mho)
	}
	if _, _, _, ch, _ := sim_stats(nw.lh); ch > 3 { // only the template build (1-3 ms in the model) is left
		t.Fatalf("a block must be answered by the kick at once, LH p99 %d ms", ch)
	}
	if nw.sends >= old.sends || nw.builds >= old.builds {
		t.Fatalf("no fewer sends/builds: %d/%d vs %d/%d", nw.sends, nw.builds, old.sends, old.builds)
	}
}
