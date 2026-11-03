package main

// Compare CPU vs GPU per-iteration loop trace (tries,op,pos1,pos2,lhash,prev_lhash) to pinpoint
// whether op SELECTION (hash->lhash) or op EXECUTION diverges first.
import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
)

type row struct{ tries, op, p1, p2, lhash, prev uint64 }

func main() {
	cases := map[string][]byte{"a": []byte("a"), "abc": []byte("abc"), "abcd": []byte("abcd"), "48x00": make([]byte, 48)}
	idx := map[string]int{"a": 0, "abc": 2, "abcd": 3, "48x00": 10}
	for _, label := range []string{"abcd", "abc", "a", "48x00"} {
		var cpu []row
		astrobwtv3.GpuIterHook = func(tries, op, p1, p2, lhash, prev uint64) {
			cpu = append(cpu, row{tries, op, p1, p2, lhash, prev})
		}
		_ = astrobwtv3.AstroBWTv3(cases[label])
		astrobwtv3.GpuIterHook = nil

		raw, err := os.ReadFile(fmt.Sprintf("gpu-miner-poc/gpu_trace_%d.bin", idx[label]))
		if err != nil {
			fmt.Println("read err", err)
			continue
		}
		get := func(t, f int) uint64 { return binary.LittleEndian.Uint64(raw[(t*5+f)*8:]) }

		fmt.Printf("=== %s (cpu iters=%d) ===\n", label, len(cpu))
		found := false
		for i, c := range cpu {
			gop, gp1, gp2, glh, gpv := get(i, 0), get(i, 1), get(i, 2), get(i, 3), get(i, 4)
			if c.op != gop || c.p1 != gp1 || c.p2 != gp2 || c.lhash != glh || c.prev != gpv {
				fmt.Printf("  FIRST TRACE DIVERGENCE at iteration %d (tries=%d):\n", i+1, c.tries)
				fmt.Printf("    field      CPU                  GPU\n")
				fmt.Printf("    op         %-20d %d\n", c.op, gop)
				fmt.Printf("    pos1       %-20d %d\n", c.p1, gp1)
				fmt.Printf("    pos2       %-20d %d\n", c.p2, gp2)
				fmt.Printf("    lhash      %016x     %016x\n", c.lhash, glh)
				fmt.Printf("    prev_lhash %016x     %016x\n", c.prev, gpv)
				// also show the previous iteration's op (the one whose execution/hash produced this lhash)
				if i > 0 {
					fmt.Printf("    [prev iter %d] cpu op=%d p1=%d p2=%d lhash=%016x\n", i, cpu[i-1].op, cpu[i-1].p1, cpu[i-1].p2, cpu[i-1].lhash)
				}
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("  trace identical for all %d iterations (divergence must be in op EXECUTION not selection)\n", len(cpu))
		}
	}
}
