package main

// Measure SA-IS recursion DEPTH + reduced-problem sizes for real AstroBWTv3 hashing.
// This scopes the GPU port (shallow recursion → small fixed stack; textMax bounds the int32 alphabet).
import (
	"crypto/rand"
	"fmt"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
)

func main() {
	var hashes uint64
	var depthHist [40]uint64 // depth -> count of hashes
	var maxDepthSeen int
	var maxTextMax int
	var curDepth int
	var levelLen [40]uint64 // sum of textLen at each level
	var levelCount [40]uint64

	astrobwtv3.SaisRecurseHook = func(rec bool, numLMS, maxID int) {
		// called once per sais_8_32 = start of a new top-level hash's SAIS
		if hashes > 0 {
			if curDepth > maxDepthSeen {
				maxDepthSeen = curDepth
			}
			if curDepth < len(depthHist) {
				depthHist[curDepth]++
			}
		}
		hashes++
		curDepth = 0
	}
	astrobwtv3.SaisDepthHook = func(textLen, textMax int) {
		curDepth++
		if curDepth < len(levelLen) {
			levelLen[curDepth] += uint64(textLen)
			levelCount[curDepth]++
		}
		if textMax > maxTextMax {
			maxTextMax = textMax
		}
	}

	const N = 5000
	var buf [48]byte
	for i := 0; i < N; i++ {
		rand.Read(buf[:])
		_ = astrobwtv3.AstroBWTv3(buf[:])
	}
	// flush last
	if curDepth > maxDepthSeen {
		maxDepthSeen = curDepth
	}
	if curDepth < len(depthHist) {
		depthHist[curDepth]++
	}
	astrobwtv3.SaisRecurseHook = nil
	astrobwtv3.SaisDepthHook = nil

	fmt.Printf("hashes=%d  MAX recursion depth=%d  max textMax(int32 alphabet)=%d\n", hashes, maxDepthSeen, maxTextMax)
	fmt.Println("depth histogram (recursion levels below sais_8_32) -> #hashes:")
	for d := 0; d <= maxDepthSeen && d < len(depthHist); d++ {
		if depthHist[d] > 0 {
			fmt.Printf("  depth %2d : %d hashes\n", d, depthHist[d])
		}
	}
	fmt.Println("avg reduced-text length per recursion level:")
	for d := 1; d <= maxDepthSeen && d < len(levelLen); d++ {
		if levelCount[d] > 0 {
			fmt.Printf("  level %2d : avg len %d (n=%d)\n", d, levelLen[d]/levelCount[d], levelCount[d])
		}
	}
}
