package blockchain

// r23c (chainperf): measurement only. Verification cost of REAL mainnet transactions and miniblock PoW, on a
// cloned datadir (never the live one). Skipped unless DERO_R23C_VERIFY_DATADIR names the clone's parent directory.
// DERO_R23C_VERIFY_OUT receives the JSON result. Runs nothing that writes consensus state: Expand/Verify load
// snapshots and discard their temporary trees, GetPoWHash is pure.

import (
	"encoding/json"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/transaction"
)

func r23c_clear_valid_cache() {
	transaction_valid_cache.Range(func(k, v interface{}) bool { transaction_valid_cache.Delete(k); return true })
}

func r23c_ms(d []time.Duration) map[string]float64 {
	if len(d) == 0 {
		return nil
	}
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	var sum time.Duration
	for _, x := range s {
		sum += x
	}
	f := func(x time.Duration) float64 { return float64(x.Microseconds()) / 1000 }
	return map[string]float64{"n": float64(len(s)), "median_ms": f(s[len(s)/2]), "p90_ms": f(s[len(s)*9/10]), "mean_ms": f(sum / time.Duration(len(s))), "min_ms": f(s[0])}
}

func TestR23cVerifyCostMainnetClone(t *testing.T) {
	dir := os.Getenv("DERO_R23C_VERIFY_DATADIR")
	if dir == "" {
		t.Skip("set DERO_R23C_VERIFY_DATADIR to a CLONED datadir")
	}
	want, _ := strconv.Atoi(os.Getenv("DERO_R23C_VERIFY_TXS"))
	if want <= 0 {
		want = 48
	}
	old := globals.Arguments
	globals.Arguments = map[string]interface{}{"--data-dir": dir}
	defer func() { globals.Arguments = old }()
	globals.Initialize()
	chain, err := Blockchain_Start(map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Shutdown()

	out := map[string]interface{}{"numcpu": runtime.NumCPU()}
	top := chain.Load_TOPO_HEIGHT()
	out["top_topo"] = top

	// corpus: the newest `want` non-registration txs mined below the clone's top
	type item struct {
		raw   []byte
		topo  int64
		ring  uint64
		pl    int
		ttype string
	}
	var corpus []item
	scanned := int64(0)
	for topo := top; topo > top-400000 && len(corpus) < want; topo-- {
		scanned++
		rec, err := chain.Store.Topo_store.Read(topo)
		if err != nil {
			continue
		}
		bl, err := chain.Load_BL_FROM_ID(rec.BLOCK_ID)
		if err != nil {
			continue
		}
		for _, h := range bl.Tx_hashes {
			raw, err := chain.Store.Block_tx_store.ReadTX(h)
			if err != nil {
				continue
			}
			var tx transaction.Transaction
			if tx.Deserialize(raw) != nil || tx.IsRegistration() {
				continue
			}
			corpus = append(corpus, item{raw: raw, topo: topo, ring: tx.Payloads[0].Statement.RingSize, pl: len(tx.Payloads), ttype: tx.TransactionType.String()})
		}
	}
	out["blocks_scanned"], out["txs"] = scanned, len(corpus)
	if len(corpus) == 0 {
		t.Fatal("no txs found")
	}
	rings := map[string]int{}
	for _, c := range corpus {
		rings[strconv.FormatUint(c.ring, 10)+"x"+strconv.Itoa(c.pl)+"/"+c.ttype]++
	}
	out["ring_x_payloads"] = rings
	out["oldest_topo"] = corpus[len(corpus)-1].topo

	decode := func(raw []byte) *transaction.Transaction {
		var tx transaction.Transaction
		if err := tx.Deserialize(raw); err != nil {
			t.Fatal(err)
		}
		return &tx
	}
	// serial: expansion only (state lookups + point decompression), then the full verify (expansion + proof)
	var expand, full []time.Duration
	failures := 0
	for rep := 0; rep < 3; rep++ {
		for _, c := range corpus {
			r23c_clear_valid_cache()
			tx := decode(c.raw)
			t0 := time.Now()
			if err := chain.Expand_Transaction_NonCoinbase(tx); err != nil {
				failures++
				continue
			}
			expand = append(expand, time.Since(t0))
			r23c_clear_valid_cache()
			tx = decode(c.raw)
			t0 = time.Now()
			if err := chain.Verify_Transaction_NonCoinbase(tx); err != nil {
				failures++
				t.Logf("verify failed topo %d: %s", c.topo, err)
				continue
			}
			full = append(full, time.Since(t0))
		}
	}
	out["serial_expand"], out["serial_full_verify"], out["failures"] = r23c_ms(expand), r23c_ms(full), failures

	// parallel throughput of full verification (the pattern Add_Complete_Block uses: one goroutine per tx)
	par := map[string]float64{}
	for _, w := range []int{1, 2, 4, 8, runtime.NumCPU()} {
		r23c_clear_valid_cache()
		txs := make([]*transaction.Transaction, 0, len(corpus)*2)
		for rep := 0; rep < 2; rep++ {
			for _, c := range corpus {
				txs = append(txs, decode(c.raw))
			}
		}
		next := make(chan *transaction.Transaction, len(txs))
		for _, tx := range txs {
			next <- tx
		}
		close(next)
		t0 := time.Now()
		var wg sync.WaitGroup
		for i := 0; i < w; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for tx := range next {
					r23c_clear_valid_cache() // each verify pays the proof
					chain.Verify_Transaction_NonCoinbase(tx)
				}
			}()
		}
		wg.Wait()
		par["workers_"+strconv.Itoa(w)+"_tx_per_s"] = float64(len(txs)) / time.Since(t0).Seconds()
	}
	out["parallel_full_verify"] = par

	// miniblock PoW (AstroBWTv3, Go SA-IS as derod runs it) and difficulty lookup, newest 30 blocks
	var pow, diff []time.Duration
	for topo := top; topo > top-30; topo-- {
		rec, _ := chain.Store.Topo_store.Read(topo)
		bl, err := chain.Load_BL_FROM_ID(rec.BLOCK_ID)
		if err != nil {
			continue
		}
		for _, mbl := range bl.MiniBlocks {
			m := mbl
			t0 := time.Now()
			_ = (&m).GetPoWHash()
			pow = append(pow, time.Since(t0))
		}
		t0 := time.Now()
		_ = Get_Difficulty_At_Tips(chain, bl.Tips)
		diff = append(diff, time.Since(t0))
	}
	out["miniblock_pow_serial"], out["difficulty_at_tips_uncached"] = r23c_ms(pow), r23c_ms(diff)
	_ = block.MiniBlock{}

	b, _ := json.MarshalIndent(out, "", " ")
	t.Logf("%s", b)
	if p := os.Getenv("DERO_R23C_VERIFY_OUT"); p != "" {
		os.WriteFile(p, b, 0600)
	}
}
