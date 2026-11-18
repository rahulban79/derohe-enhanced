package main

// R33 GT-B25 (dero-game-theory-rft §7): --game-tag=<16 hex digits> writes an 8-byte tag into miniblock bytes 32..39:
// the Flags field and the first nonce word (version 1, timestamp 2, height 5, past 8, keyhash 16 -> flags at 32,
// nonce at 36; block/miniblock.go:140-171). The CPU loop iterates only bytes 43..46 and writes the thread id at 47
// (miner.go: nonce_buf = work[43:], work[47] = tid), so bytes 36..39 are free per job. 8 bytes, not 4: other miners
// already use constant nonzero Flags (01000000.. seen on mainnet), and a 4-byte tag can be ground in ~2^32 keys. No consensus code reads Flags (block/miniblock.go:55 "can be used as flags by special
// miners"); the PoW covers all 48 bytes, so a tag in an accepted miniblock cannot be forged without the work. A game
// contract that verifies the block's bytes (GT-B24, dvm/r33_blockproof_test.go) can then credit the miniblock to the
// game identity whose tag it carries. The stock behaviour (no flag) leaves Flags exactly as the job template set it.

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/deroproject/derohe/block"
)

const game_tag_offset = 32 // Flags: 1 + 2 + 5 + 8 + 16; the tag spans Flags and Nonce[0] (8 bytes)
const game_tag_len = 8

var game_tag_set bool
var game_tag [game_tag_len]byte

// parse_game_tag accepts exactly 16 hex digits (8 bytes, written in this order into bytes 32..39).
func parse_game_tag(v string) ([game_tag_len]byte, error) {
	var t [game_tag_len]byte
	v = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(v), "0x"))
	if len(v) != 2*game_tag_len {
		return t, fmt.Errorf("--game-tag needs exactly 16 hex digits, got %d", len(v))
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		return t, fmt.Errorf("--game-tag: %v", err)
	}
	copy(t[:], b)
	return t, nil
}

// apply_game_tag writes the tag into a work blob (no-op without --game-tag).
func apply_game_tag(work *[block.MINIBLOCK_SIZE]byte) {
	if game_tag_set {
		copy(work[game_tag_offset:game_tag_offset+game_tag_len], game_tag[:])
	}
}
