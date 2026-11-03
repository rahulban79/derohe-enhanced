package gsplit

// GPU wall-busy accounting (Round 21 splitpipe, r20 deferred gpukernels-8).
//
// The server reports each command buffer's own GPU span (gpuEndTime - gpuStartTime). Stage 1 (op 1) and the GPU SHA
// (op 2) run on two queues and Inflight command buffers overlap, so the SUM of those spans is not GPU time: live r19
// summed 32.6 us per staged hash against ~17.5 us of wall GPU time, and r20 summed 19.7 us per hash at 79.7k staged
// H/s, i.e. 157% of the wall clock. The --gpu-max duty debt was charged on that sum and over-throttled. busyUnion
// measures the UNION of the busy intervals instead: each reply is placed at [arrival - span, arrival] on one monotonic
// clock (arrival is stamped by the transport's reader as the 16 bytes come off the pipe), and only the part of it not
// already covered by earlier intervals counts. Completion order across the two queues does not matter: the union of a
// set of intervals is the same whatever order they are inserted in.

// busyHorizonNs: covered segments that ended this long before the newest arrival are forgotten. A GPU command that
// starts earlier than that is counted in full (more busy time: the cap only gets stricter).
const busyHorizonNs = int64(10e9)

// busyMaxSegs bounds the memory; when exceeded the oldest segment is forgotten (same conservative direction).
const busyMaxSegs = 256

type busyUnion struct {
	segs [][2]int64 // disjoint, sorted by start, each [start, end)
}

// add records the busy interval [s, e) and returns how many ns of it were not covered before.
func (u *busyUnion) add(s, e int64) int64 {
	if e <= s {
		return 0
	}
	// forget segments far behind this arrival (the replies' arrival stamps are monotonic)
	k := 0
	for k < len(u.segs) && u.segs[k][1] < e-busyHorizonNs {
		k++
	}
	if k > 0 {
		u.segs = append(u.segs[:0], u.segs[k:]...)
	}
	added := e - s
	ns, ne := s, e
	out := u.segs[:0:0]
	inserted := false
	for _, g := range u.segs {
		switch {
		case g[1] < ns: // entirely before
			out = append(out, g)
		case g[0] > ne: // entirely after
			if !inserted {
				out = append(out, [2]int64{ns, ne})
				inserted = true
			}
			out = append(out, g)
		default: // overlaps or touches [s, e): subtract its covered part, merge
			lo, hi := g[0], g[1]
			if lo < s {
				lo = s
			}
			if hi > e {
				hi = e
			}
			if hi > lo {
				added -= hi - lo
			}
			if g[0] < ns {
				ns = g[0]
			}
			if g[1] > ne {
				ne = g[1]
			}
		}
	}
	if !inserted {
		out = append(out, [2]int64{ns, ne})
	}
	if len(out) > busyMaxSegs {
		out = out[len(out)-busyMaxSegs:]
	}
	u.segs = out
	return added
}
