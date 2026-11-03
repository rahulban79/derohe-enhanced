package rpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/rpc"
)

// job_message_old is the pre-r18 per-client goroutine body of SendJob (everything per client, fmt %x), kept as the
// reference for the byte-identity test and the benchmark.
func job_message_old(ts, height uint64, prev_hash string, diff *big.Int, lasterr string, mbl block.MiniBlock, blocks, miniblocks, rejected uint64) []byte {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	var params rpc.GetBlockTemplate_Result
	params.JobID = fmt.Sprintf("%d.%d.%s", ts, 0, "notified")
	params.Height = height
	params.Prev_Hash = prev_hash
	params.Difficultyuint64 = diff.Uint64()
	params.Difficulty = diff.String()
	params.LastError = lasterr
	params.Blockhashing_blob = fmt.Sprintf("%x", mbl.Serialize())
	params.Blocks = blocks
	params.MiniBlocks = miniblocks
	params.Rejected = rejected
	encoder.Encode(params)
	return buf.Bytes()
}

func sample_job() (uint64, uint64, string, *big.Int, block.MiniBlock) {
	var mbl block.MiniBlock
	mbl.Version = 1
	mbl.Timestamp = 0x1234
	mbl.Height = 7_600_123
	mbl.PastCount = 2
	mbl.Past = [2]uint32{0x01020304, 0xa0b0c0d0}
	for i := range mbl.KeyHash {
		mbl.KeyHash[i] = byte(i * 7)
	}
	for i := range mbl.Nonce {
		mbl.Nonce[i] = uint32(0xdeadbeef) + uint32(i)
	}
	diff, _ := new(big.Int).SetString("123456789012345678901234567890", 10)
	return 1792853213123, 7_600_123, "a1b2<&>c3" + "0000000000000000000000000000000000000000000000000000000000000000", diff, mbl
}

func base_of(ts, height uint64, prev_hash string, diff *big.Int) rpc.GetBlockTemplate_Result {
	var base rpc.GetBlockTemplate_Result // must mirror SendJob's base construction
	base.JobID = fmt.Sprintf("%d.%d.%s", ts, 0, "notified")
	base.Height = height
	base.Prev_Hash = prev_hash
	base.Difficultyuint64 = diff.Uint64()
	base.Difficulty = diff.String()
	return base
}

func TestJobMessageByteIdentical(t *testing.T) {
	ts, h, ph, diff, mbl := sample_job()
	for _, lasterr := range []string{"", "unregistered miner or you need to wait 15 mins"} {
		for _, final := range []bool{false, true} {
			mbl.Final = final
			want := job_message_old(ts, h, ph, diff, lasterr, mbl, 3, 41, 2)
			params := base_of(ts, h, ph, diff)
			params.LastError = lasterr
			got := job_message(params, &mbl, 3, 41, 2)
			if !bytes.Equal(want, got) {
				t.Fatalf("job frames differ\nwant %s\n got %s", want, got)
			}
		}
	}
}

func BenchmarkJobMessage_Old(b *testing.B) {
	ts, h, ph, diff, mbl := sample_job()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = job_message_old(ts, h, ph, diff, "", mbl, 3, 41, 2)
	}
}

// per client cost after r18: the base is built once per job, so it is outside the loop
func BenchmarkJobMessage_New(b *testing.B) {
	ts, h, ph, diff, mbl := sample_job()
	base := base_of(ts, h, ph, diff)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = job_message(base, &mbl, 3, 41, 2)
	}
}
