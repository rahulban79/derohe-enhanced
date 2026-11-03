package rpc

// r23c payouts: getwork_flip.go (dead normal jobs after the 9th miniblock, flip delay).

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/cryptography/crypto"
)

func flip_pool(t *testing.T, height uint64, tip crypto.Hash, normal, final int) *block.MiniBlocksCollection {
	t.Helper()
	pool := block.CreateMiniBlockCollection()
	for i := 0; i < normal+final; i++ {
		var m block.MiniBlock
		m.Version, m.Height, m.PastCount = 1, height, 1
		m.Past[0] = binary.BigEndian.Uint32(tip[:])
		m.Nonce[0] = uint32(i + 1)
		m.KeyHash[0] = byte(i + 1)
		if i >= normal {
			m.Final, m.HighDiff = true, true
		}
		if err, ok := pool.InsertMiniBlock(m); !ok {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	return pool
}

func TestR23cHeldNormalCountsTheTemplateKey(t *testing.T) {
	var tip, other crypto.Hash
	tip[0], other[0] = 0xaa, 0xbb
	pool := flip_pool(t, 100, tip, 9, 0) // the pool refuses finals ("Final cannot be inserted"); held_normal skips them anyway
	if n := held_normal(pool, 100, []crypto.Hash{tip}); n != 9 {
		t.Fatalf("held %d want 9", n)
	}
	if held_normal(pool, 100, []crypto.Hash{other}) != 0 || held_normal(pool, 101, []crypto.Hash{tip}) != 0 {
		t.Fatal("another tip or height must not count")
	}
	if held_normal(nil, 100, []crypto.Hash{tip}) != 0 || held_normal(pool, 100, nil) != 0 {
		t.Fatal("nil pool / no tips")
	}
}

func TestR23cFlipWatch(t *testing.T) {
	var f flip_watch
	// normal job, 8 held: live work
	if dead, first, closed, _, _ := f.note(100, false, 8, 0, 1000); dead || first || closed {
		t.Fatal("8 held is live normal work")
	}
	// the 9th landed inside the template cache: two dead normal jobs, then the final job 90 ms after the first
	if dead, _, _, _, _ := f.note(100, false, 9, 0, 1010); !dead {
		t.Fatal("9 held + normal job = dead")
	}
	if dead, _, _, _, _ := f.note(100, false, 9, 0, 1050); !dead {
		t.Fatal("still dead")
	}
	dead, first, closed, delay, _ := f.note(100, true, 0, 0, 1100)
	if dead || !first || !closed || delay != 90 {
		t.Fatalf("final: dead %v first %v closed %v delay %d (want 90 from the FIRST dead job)", dead, first, closed, delay)
	}
	// a keepalive final job at the same height is neither a new flip nor a new close
	if _, first, closed, _, _ := f.note(100, true, 0, 0, 2000); first || closed {
		t.Fatal("second final job of a height")
	}
	// a clean flip at the next height: first final, nothing to close
	if _, first, closed, _, _ := f.note(101, true, 0, 0, 3000); !first || closed {
		t.Fatal("clean flip")
	}
	// a dead window whose height ends (block arrived) is dropped, never closed by the next height's final
	f.note(102, false, 9, 0, 4000)
	if _, _, closed, _, _ := f.note(103, true, 0, 0, 4500); closed {
		t.Fatal("a window of another height must not close")
	}
}

// send_job_to books every CURRENT job with note_flip (a source check: the hook needs a live template).
func TestR23cSendJobWiresFlipWatch(t *testing.T) {
	src, err := os.ReadFile("websocket_getwork_server.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	i := strings.Index(s, "func send_job_to(")
	j := strings.Index(s, "func dispatch_targets(")
	if i < 0 || j < i {
		t.Fatal("send_job_to not found")
	}
	body := s[i:j]
	if !strings.Contains(body, "if current { // r23c payouts") || !strings.Contains(body, "note_flip(chain.MiniBlocks, &bl, mbl_main.Final,") {
		t.Fatal("send_job_to does not call note_flip for current jobs")
	}
}

// The hook's cost per send (a pool read of one key): compare with getwork_send_job_seconds (live mean ~4 ms).
func BenchmarkR23cNoteFlip(b *testing.B) {
	var tip crypto.Hash
	tip[0] = 0xaa
	pool := block.CreateMiniBlockCollection()
	for i := 0; i < 9; i++ {
		var m block.MiniBlock
		m.Version, m.Height, m.PastCount = 1, 100, 1
		m.Past[0] = binary.BigEndian.Uint32(tip[:])
		m.Nonce[0], m.KeyHash[0] = uint32(i+1), byte(i+1)
		pool.InsertMiniBlock(m)
	}
	bl := block.Block{Height: 100, Tips: []crypto.Hash{tip}}
	for i := 0; i < b.N; i++ {
		note_flip(pool, &bl, i%2 == 0, int64(i), int64(i))
	}
}
