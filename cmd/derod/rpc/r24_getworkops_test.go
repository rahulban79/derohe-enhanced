package rpc

// r24 (getworkops, B39): the live flip-delay histogram and the simulated L9 measure different things; the replay below
// books the simulator's own job stream through the SHIPPED flip_watch, so the live metric's definition is applied to
// the model and the two can be compared like with like.

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/metrics"
)

type flip_replay struct {
	dead, flips, closed    int
	delay_sum, delay_max   int64
	l9                     []int64
	cond_mean, per_flip_ms float64
}

// replay_flips books every sim send through a fresh flip_watch exactly as note_flip does (held only for normal jobs).
func replay_flips(sends []sim_send) (r flip_replay) {
	var f flip_watch
	for _, s := range sends {
		held := 0
		if !s.final {
			held = s.held
		}
		dead, first, closed, delay, l9 := f.note(uint64(s.height), s.final, held, s.trigger, s.t)
		if dead {
			r.dead++
		}
		if first {
			r.flips++
		}
		if closed {
			r.closed++
			r.delay_sum += delay
			if delay > r.delay_max {
				r.delay_max = delay
			}
		}
		if l9 >= 0 {
			r.l9 = append(r.l9, l9)
		}
	}
	if r.closed > 0 {
		r.cond_mean = float64(r.delay_sum) / float64(r.closed)
	}
	if r.flips > 0 {
		r.per_flip_ms = float64(r.delay_sum) / float64(r.flips)
	}
	return
}

func TestR24FlipL9Sample(t *testing.T) {
	var f flip_watch
	// clean flip: the change send observed at 1000 is final and leaves at 1002 -> L9 2 ms
	if _, first, _, _, l9 := f.note(100, true, 0, 1000, 1002); !first || l9 != 2 {
		t.Fatalf("clean flip: first %v l9 %d want 2", first, l9)
	}
	// a second final job of the same height books nothing
	if _, _, _, _, l9 := f.note(100, true, 0, 1000, 1500); l9 != -1 {
		t.Fatalf("second final job booked l9 %d", l9)
	}
	// dead window: the 9th observed at 2000 (dead job sent at 2001), the refresh's final job leaves at 2090
	if dead, _, _, _, _ := f.note(101, false, 9, 2000, 2001); !dead {
		t.Fatal("dead")
	}
	f.note(101, false, 9, 2040, 2041) // a later dead job must not move the start
	// the final job answers a later state (trigger 2040, e.g. a 10th normal miniblock): L9 still starts at 2000
	_, first, closed, delay, l9 := f.note(101, true, 0, 2040, 2090)
	if !first || !closed || delay != 89 || l9 != 90 {
		t.Fatalf("dead flip: first %v closed %v delay %d (want 89, from the first dead SEND) l9 %d (want 90, from its trigger)", first, closed, delay, l9)
	}
	// a keepalive final job (trigger 0) with no dead window has no start: nothing booked
	if _, first, _, _, l9 := f.note(102, true, 0, 0, 3000); !first || l9 != -1 {
		t.Fatalf("keepalive flip: first %v l9 %d want -1", first, l9)
	}
	// a dead window opened by a keepalive (trigger 0) starts at its send
	f.note(103, false, 9, 0, 4000)
	if _, _, _, _, l9 := f.note(103, true, 0, 4000, 4050); l9 != 50 {
		t.Fatalf("keepalive-opened window: l9 %d want 50", l9)
	}
	// a trigger after now (clock step) is not a start
	if _, _, _, _, l9 := f.note(104, true, 0, 6000, 5000); l9 != -1 {
		t.Fatalf("future trigger booked l9 %d", l9)
	}
	// a window of an ended height must not leak its start into the next height
	f.note(105, false, 9, 7000, 7000)
	if _, _, closed, _, l9 := f.note(106, true, 0, 7900, 7901); closed || l9 != 1 {
		t.Fatalf("cross-height: closed %v l9 %d want 1", closed, l9)
	}
}

// The live histogram replayed on the model: its L9 samples equal sim_measure's L9 (the definition the 10.36 ms
// number uses), while the conditional delay is several times larger by construction. The B39 "5x" is the
// definition, not the dispatcher.
func TestR24SimLiveFlipDefinitions(t *testing.T) {
	ev := sim_trace(23, 4000)
	type res struct {
		m  sim_out
		r  flip_replay
		m9 float64
	}
	run := func(name string, c *sim_chain) res {
		sn, bn := sim_new_chain(ev, JOB_KEEPALIVE.Milliseconds(), c)
		m := sim_measure(ev, sn, bn)
		r := replay_flips(sn)
		m9, _, p90, p99, _ := sim_stats(m.l9)
		r9, _, rp90, _, _ := sim_stats(r.l9)
		t.Logf("%-34s flips %d, dead jobs %d (%.3f/flip), dead windows %d (%.1f%% of flips), conditional delay mean %.2f ms max %d, sum/flips %.2f ms",
			name, r.flips, r.dead, float64(r.dead)/float64(r.flips), r.closed, 100*float64(r.closed)/float64(r.flips), r.cond_mean, r.delay_max, r.per_flip_ms)
		t.Logf("%-34s sim L9 mean %.2f ms p90 %d p99 %d (n %d) | getwork_final_flip_l9 replay mean %.2f p90 %d (n %d) | jobs/s %.2f builds/s %.2f",
			name, m9, p90, p99, len(m.l9), r9, rp90, len(r.l9), float64(m.sends)/m.secs, float64(m.builds)/m.secs)
		if len(r.l9) < len(m.l9)*99/100 || math.Abs(r9-m9) > 0.5 {
			t.Fatalf("%s: getwork_final_flip_l9 does not reproduce sim L9: %.2f ms (n %d) vs %.2f ms (n %d)", name, r9, len(r.l9), m9, len(m.l9))
		}
		if r.per_flip_ms > m9 {
			t.Fatalf("%s: dead time per flip %.2f ms exceeds L9 %.2f ms (it starts later and covers fewer flips)", name, r.per_flip_ms, m9)
		}
		return res{m, r, m9}
	}
	newc := func(key_minis, serial bool) *sim_chain {
		return &sim_chain{height: 1, r: rand.New(rand.NewSource(7)), p0: 0.03, key_minis: key_minis, serial: serial}
	}
	run("r23c model (shipped, overlapping)", newc(false, false)) // reproduces the documented 10.36 ms
	s := run("serial model (shipped)", newc(false, true))
	if s.r.closed == 0 || s.r.cond_mean < 3*s.m9 {
		t.Fatalf("conditional mean %.2f ms is not the large number it is by construction (L9 %.2f)", s.r.cond_mean, s.m9)
	}
	if s.r.delay_max > 104 { // the refresh fires at the cache expiry (template + 101 ms), plus at most a 1-3 ms build
		t.Fatalf("a dead window outlived the 100 ms cache: %d ms", s.r.delay_max)
	}
	// report-only (blockchain/ is guarded): the cache rebuilt when the pool's normal count changes
	k := run("proposal (cache keyed on count)", newc(true, true))
	if _, _, _, kp99, _ := sim_stats(k.m.l9); k.r.dead != 0 || kp99 > 3 {
		t.Fatalf("proposal leaves dead work: %d dead jobs, L9 p99 %d", k.r.dead, kp99)
	}
}

func l9_count(t *testing.T) int {
	t.Helper()
	var b bytes.Buffer
	metrics.Set.WritePrometheus(&b)
	m := regexp.MustCompile(`(?m)^getwork_final_flip_l9_seconds_count (\d+)$`).FindStringSubmatch(b.String())
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// note_flip books one L9 sample per first final job with a start, into getwork_final_flip_l9_seconds
func TestR24NoteFlipBooksL9(t *testing.T) {
	var tip crypto.Hash
	tip[0] = 0xcc
	pool := block.CreateMiniBlockCollection()
	h := uint64(9_000_001) // a height no other test books
	bl := block.Block{Height: h, Tips: []crypto.Hash{tip}}
	n0 := l9_count(t)
	note_flip(pool, &bl, true, 5000, 5003)
	note_flip(pool, &bl, true, 5000, 5400) // same height: no second sample
	if n := l9_count(t) - n0; n != 1 {
		t.Fatalf("l9 samples %d want 1", n)
	}
}

// send_job_to hands its trigger to note_flip (without it every L9 sample of a clean flip would be lost)
func TestR24SendJobPassesTrigger(t *testing.T) {
	src, err := os.ReadFile("websocket_getwork_server.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "note_flip(chain.MiniBlocks, &bl, mbl_main.Final, trigger_ms, globals.Time().UTC().UnixMilli())") {
		t.Fatal("send_job_to does not pass trigger_ms to note_flip")
	}
}

func TestR24FlipSlowThreshold(t *testing.T) {
	if flip_is_slow(104) || flip_is_slow(FLIP_SLOW_MS) || !flip_is_slow(FLIP_SLOW_MS+1) || !flip_is_slow(300) {
		t.Fatal("slow-flip threshold")
	}
	var b bytes.Buffer
	metrics.Set.WritePrometheus(&b)
	if !strings.Contains(b.String(), "getwork_final_flip_slow_total") {
		t.Fatal("getwork_final_flip_slow_total not registered")
	}
}

// note_flip counts a dead window above FLIP_SLOW_MS in getwork_final_flip_slow_total
func TestR24NoteFlipCountsSlow(t *testing.T) {
	var tip crypto.Hash
	tip[0] = 0xcd
	pool := block.CreateMiniBlockCollection()
	for i := 0; i < 9; i++ {
		var m block.MiniBlock
		m.Version, m.Height, m.PastCount = 1, 9_000_101, 1
		m.Past[0] = binary.BigEndian.Uint32(tip[:])
		m.Nonce[0], m.KeyHash[0] = uint32(i+1), byte(i+1)
		pool.InsertMiniBlock(m)
	}
	bl := block.Block{Height: 9_000_101, Tips: []crypto.Hash{tip}}
	n0 := getwork_final_flip_slow.Get()
	note_flip(pool, &bl, false, 7000, 7000) // dead
	note_flip(pool, &bl, true, 7000, 7300)  // closes after 300 ms
	if getwork_final_flip_slow.Get()-n0 != 1 {
		t.Fatal("a 300 ms dead window was not counted slow")
	}
}
