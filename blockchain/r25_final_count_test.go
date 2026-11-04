package blockchain

// r25 (cryptodisc, backlog B22): "consensus allows >= 1 final miniblock, so F > 1 finals under-pay by share x (F - 1)".
// The coinbase split (transaction_execute.go process_miner_transaction) divides the reward by len(MiniBlocks) and
// credits every non-final miniblock plus the integrator once, so F finals would leave share x (F - 1) un-credited.
// Re-verified in code: Verify_MiniBlocks only counts finals >= 1, BUT it also requires exactly
// BLOCK_TIME - MINIBLOCK_HIGHDIFF + 1 = 10 miniblocks and, from height 399,000, a collection count of exactly
// BLOCK_TIME - MINIBLOCK_HIGHDIFF = 9, and MiniBlocksCollection.InsertMiniBlock refuses every Final miniblock. So the
// block must carry exactly 9 non-final miniblocks and therefore exactly one final: F > 1 is refused by consensus above
// 399,000 (it was not below). Live: 20,000 of 20,000 recent blocks carry F = 1 (evidence b22_finals_census.txt).
// This test pins the consensus rule (no code change): F = 2 and F = 0 are refused, F = 1 passes; below 399,000 F = 2
// passes the count rule (the historical window where the under-payment was possible), and F = 0 is refused there by
// the final_count rule alone.

import (
	"encoding/binary"
	"testing"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
)

func r25BlockWithFinals(height uint64, finals int) block.Block {
	var bl block.Block
	bl.Height = height
	var tip crypto.Hash
	copy(tip[:], []byte("r25 B22 tip hash for the test..."))
	bl.Tips = []crypto.Hash{tip}
	n := int(config.BLOCK_TIME - config.MINIBLOCK_HIGHDIFF + 1)
	for i := 0; i < n; i++ {
		var mbl block.MiniBlock
		mbl.Version = 1
		mbl.Height = height
		mbl.PastCount = 1
		mbl.Past[0] = binary.BigEndian.Uint32(tip[:])
		mbl.Nonce[0] = uint32(i + 1) // distinct, so no collision
		mbl.KeyHash[0] = byte(i + 1)
		mbl.Final = i >= n-finals // the finals at the end, the last one always final when finals >= 1
		mbl.HighDiff = mbl.Final
		bl.MiniBlocks = append(bl.MiniBlocks, mbl)
	}
	return bl
}

func TestR25ExactlyOneFinalMiniblock(t *testing.T) {
	const h = 7_800_000
	if err := Verify_MiniBlocks(r25BlockWithFinals(h, 1)); err != nil {
		t.Fatalf("F=1 must pass the miniblock rules: %v", err)
	}
	for _, f := range []int{0, 2, 3, 10} {
		if err := Verify_MiniBlocks(r25BlockWithFinals(h, f)); err == nil {
			t.Fatalf("F=%d passed Verify_MiniBlocks at height %d: the coinbase split would leave share x (F-1) un-credited", f, h)
		}
	}
	// below the soft-HF height the collection-count rule does not run: F = 2 passes (historical under-payment window)
	if err := Verify_MiniBlocks(r25BlockWithFinals(398_999, 2)); err != nil {
		t.Fatalf("below 399,000 F=2 was allowed by the rules as written; the test's premise moved: %v", err)
	}
	// there, final_count >= 1 is the only rule that refuses a block without a final (above 399,000 the count rule
	// refuses it too)
	if err := Verify_MiniBlocks(r25BlockWithFinals(398_999, 0)); err == nil {
		t.Fatalf("below 399,000 a block with no final miniblock passed")
	}
}
