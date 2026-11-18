package main

import (
	"testing"

	"github.com/deroproject/derohe/block"
)

// R33 GT-B25: --game-tag lands in the miniblock Flags field as block.MiniBlock decodes it, and nowhere else.
func TestR33GameTagLandsInFlags(t *testing.T) {
	for _, bad := range []string{"", "abc", "a1b2c3d4", "00112233445566778", "zz11223344556677"} {
		if _, err := parse_game_tag(bad); err == nil {
			t.Fatalf("parse_game_tag(%q) accepted", bad)
		}
	}
	tag, err := parse_game_tag("0xA1b2C3d4E5f60718")
	if err != nil || tag != [8]byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18} {
		t.Fatalf("parse_game_tag: %x %v", tag, err)
	}
	mbl := block.MiniBlock{Version: 1, PastCount: 1, Past: [2]uint32{0xdeadbeef, 0}, Height: 7915141, Timestamp: 1234, Flags: 7, Nonce: [3]uint32{1, 2, 3}}
	mbl.KeyHash[0], mbl.KeyHash[15] = 0x11, 0x22
	var work [block.MINIBLOCK_SIZE]byte
	copy(work[:], mbl.Serialize())
	before := work

	game_tag_set, game_tag = false, [8]byte{}
	apply_game_tag(&work)
	if work != before {
		t.Fatalf("without --game-tag the work blob changed")
	}
	game_tag_set, game_tag = true, tag
	defer func() { game_tag_set, game_tag = false, [8]byte{} }()
	apply_game_tag(&work)
	var got block.MiniBlock
	if err := got.Deserialize(work[:]); err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.Flags != 0xa1b2c3d4 || got.Nonce[0] != 0xe5f60718 {
		t.Fatalf("Flags %x Nonce[0] %x, want a1b2c3d4 e5f60718", got.Flags, got.Nonce[0])
	}
	if got.KeyHash != mbl.KeyHash || got.Height != mbl.Height || got.Nonce[1] != mbl.Nonce[1] || got.Nonce[2] != mbl.Nonce[2] || got.Timestamp != mbl.Timestamp || got.Past != mbl.Past {
		t.Fatalf("a field other than Flags changed: %+v vs %+v", got, mbl)
	}
	for i := range work {
		if (i < game_tag_offset || i >= game_tag_offset+game_tag_len) && work[i] != before[i] {
			t.Fatalf("byte %d changed outside the tag bytes 32..39", i)
		}
	}
}
