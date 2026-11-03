package main

import (
	"encoding/hex"
	"sync"
	"time"

	"github.com/deroproject/derohe/config"
)

// session_counter turns a per-session count that restarts at 0 (derod keeps one per websocket connection,
// cmd/derod/rpc/websocket_getwork_server.go) into a total for the miner's whole run.
type session_counter struct {
	sync.Mutex
	base, last uint64
}

func (s *session_counter) observe(v uint64) uint64 {
	s.Lock()
	defer s.Unlock()
	if v < s.last { // a new session: what the old one reached is kept
		s.base += s.last
	}
	s.last = v
	return s.base + v
}

var blocks_seen, minis_seen, rejected_seen session_counter

// nw_from_job estimates the network hashrate from a job. Per block 9 normal miniblocks at difficulty D and one
// final at 9D (config.MINIBLOCK_HIGHDIFF) are found in BLOCK_TIME = 18 s: 18D hashes per 18 s, i.e. about D H/s.
// A final job carries 9D, which the prompt used to show as a 9x network jump. Byte 0 bit 4 of the hashing blob is
// the HighDiff flag (block/miniblock.go Serialize).
func nw_from_job(blob string, diff uint64) uint64 {
	var b [1]byte
	if len(blob) >= 2 {
		if _, err := hex.Decode(b[:], []byte(blob[:2])); err == nil && b[0]&0x10 != 0 {
			return diff / config.MINIBLOCK_HIGHDIFF
		}
	}
	return diff
}

type speed_sample struct {
	t time.Time
	c uint64
}

var speed_ring []speed_sample // only the status goroutine touches it

// log_path: a --bench run writes <exe>.bench.log. Both used <exe>.log, and os.Create truncates, so every benchmark
// of the installed binary (pipeline S4b, A/B runs) wiped the LIVE miner's log and left NUL holes where the running
// process kept writing at its old offset (Round 16 forensics: 27,933 of 39,638 bytes NUL).
func log_path(exe string, args []string) string {
	for _, a := range args {
		if a == "--bench" {
			return exe + ".bench.log"
		}
	}
	return exe + ".log"
}
