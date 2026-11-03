// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package rpc

// Round 19 read-only explorer/operator methods (no consensus state is written, nothing is accepted or rejected
// differently; every method only reads stores the node already keeps):
//
//	DERO.GetBlockHeadersRange  {start_topoheight, end_topoheight}  <= MAX_HEADERS_RANGE headers per call
//	DERO.GetMiniBlocks         {hash | topoheight}                 who mined each miniblock of a block, and when
//	DERO.GetDifficultyHistory  {count, end_topoheight}             <= MAX_DIFFICULTY_HISTORY points + summary
//	DERO.GetTxPoolDetail       {limit}                             <= MAX_TXPOOL_DETAIL pool entries with size/fee/type
//	DERO.GetPeerInfo           -                                   active peers: height, latency, first-relay score
//
// Every range method is bounded by a hard per-call limit AND by range_slots, a small semaphore shared by the range
// methods, so a client looping on 100-header ranges cannot occupy more than RANGE_CONCURRENCY handler goroutines'
// worth of store reads at a time. Each loop also checks ctx so a disconnected client stops costing reads.

import "context"
import "encoding/hex"
import "fmt"
import "math/big"
import "os"
import "sort"
import "strings"
import "sync"
import "time"

import "github.com/deroproject/derohe/block"
import "github.com/deroproject/derohe/config"
import "github.com/deroproject/derohe/cryptography/crypto"
import "github.com/deroproject/derohe/globals"
import "github.com/deroproject/derohe/p2p"
import "github.com/deroproject/derohe/rpc"
import "github.com/deroproject/derohe/transaction"

const MAX_HEADERS_RANGE = 100       // headers per GetBlockHeadersRange call (each costs a block read + a state snapshot)
const MAX_DIFFICULTY_HISTORY = 1000 // points per GetDifficultyHistory call (~5 h of blocks at 18 s)
const MAX_TXPOOL_DETAIL = 1000      // entries per GetTxPoolDetail call
const DEFAULT_TXPOOL_DETAIL = 100
const DEFAULT_DIFFICULTY_HISTORY = 100
const MAX_PEER_INFO = 256
const RANGE_CONCURRENCY = 2 // concurrent range calls node-wide; extra callers wait (or give up when their ctx ends)

var range_slots = make(chan struct{}, RANGE_CONCURRENCY)

// FOREIGN_RANGE_CONCURRENCY: range slots that cross-site (foreign Origin) websockets may hold at once, all together
// (r21, security; r20 residual R-6). One web page could keep both node-wide slots busy, so local explorers and wallets
// queued behind it; now at least RANGE_CONCURRENCY-1 slots are always left to everyone else.
const FOREIGN_RANGE_CONCURRENCY = 1

var foreign_range_slots = make(chan struct{}, FOREIGN_RANGE_CONCURRENCY)

// acquire_range_slot blocks until a range slot is free or ctx is done.
func acquire_range_slot(ctx context.Context) (release func(), err error) {
	return acquire_range_slot_as(ctx, caller_is_foreign(ctx))
}

// acquire_range_slot_as is acquire_range_slot for a caller known to be foreign or not: a foreign caller first takes
// one of the FOREIGN_RANGE_CONCURRENCY slots, then a node-wide one.
func acquire_range_slot_as(ctx context.Context, foreign bool) (release func(), err error) {
	if foreign {
		select {
		case foreign_range_slots <- struct{}{}:
		case <-ctx.Done():
			return func() {}, fmt.Errorf("busy: %d cross-site range request already running (%v)", FOREIGN_RANGE_CONCURRENCY, ctx.Err())
		}
	}
	select {
	case range_slots <- struct{}{}:
		if foreign {
			return func() { <-range_slots; <-foreign_range_slots }, nil
		}
		return func() { <-range_slots }, nil
	case <-ctx.Done():
		if foreign {
			<-foreign_range_slots
		}
		return func() {}, fmt.Errorf("busy: %d range requests already running (%v)", RANGE_CONCURRENCY, ctx.Err())
	}
}

// clamp_topo_range validates an inclusive [start,end] request against the chain top and the per-call limit. It is a
// pure function so the bounds are unit tested. end is clipped to top (a client asking past the tip gets what exists).
func clamp_topo_range(start, end, top int64, limit int64) (int64, int64, error) {
	if start < 0 || end < 0 {
		return 0, 0, fmt.Errorf("negative topoheight")
	}
	if start > top {
		return 0, 0, fmt.Errorf("start_topoheight %d is above the chain top %d", start, top)
	}
	if end > top {
		end = top
	}
	if end < start {
		return 0, 0, fmt.Errorf("end_topoheight %d is below start_topoheight %d", end, start)
	}
	if end-start+1 > limit {
		return 0, 0, fmt.Errorf("range of %d blocks exceeds the limit of %d per call", end-start+1, limit)
	}
	return start, end, nil
}

// block_id_at_topo reads the block id stored at a topoheight without the panic that
// Load_Block_Topological_order_at_index raises on a clean (unset) record.
func block_id_at_topo(topo int64) (crypto.Hash, error) {
	r, err := chain.Store.Topo_store.Read(topo)
	if err != nil {
		return crypto.Hash{}, err
	}
	if r.IsClean() {
		return crypto.Hash{}, fmt.Errorf("no block recorded at topoheight %d", topo)
	}
	return r.BLOCK_ID, nil
}

// ---------------------------------------------------------------- GetBlockHeadersRange

type GetBlockHeadersRange_Params struct {
	Start int64 `json:"start_topoheight"`
	End   int64 `json:"end_topoheight"`
}

type GetBlockHeadersRange_Result struct {
	Headers []rpc.BlockHeader_Print `json:"headers"`
	Status  string                  `json:"status"`
}

func GetBlockHeadersRange(ctx context.Context, p GetBlockHeadersRange_Params) (result GetBlockHeadersRange_Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = rpc_internal_error(r)
		}
	}()
	start, end, err := clamp_topo_range(p.Start, p.End, chain.Load_TOPO_HEIGHT(), MAX_HEADERS_RANGE)
	if err != nil {
		return
	}
	release, err := acquire_range_slot(ctx)
	defer release()
	if err != nil {
		return
	}
	result.Headers = make([]rpc.BlockHeader_Print, 0, end-start+1)
	for t := start; t <= end; t++ {
		if err = ctx.Err(); err != nil {
			return
		}
		var hash crypto.Hash
		if hash, err = block_id_at_topo(t); err != nil {
			return
		}
		var h rpc.BlockHeader_Print
		if h, err = GetBlockHeader(chain, hash); err != nil {
			err = fmt.Errorf("topoheight %d: %s", t, err)
			return
		}
		result.Headers = append(result.Headers, h)
	}
	result.Status = "OK"
	return
}

// ---------------------------------------------------------------- GetMiniBlocks

type GetMiniBlocks_Params struct {
	Hash       string `json:"hash,omitempty"`
	TopoHeight int64  `json:"topoheight"` // used when hash is empty
}

type MiniBlock_Print struct {
	Index      int      `json:"index"`
	Hash       string   `json:"hash"`
	Final      bool     `json:"final"`
	HighDiff   bool     `json:"highdiff"`
	Version    uint8    `json:"version"`
	Height     uint64   `json:"height"`
	PastCount  uint8    `json:"past_count"`
	Past       []string `json:"past"`
	Timestamp  uint16   `json:"timestamp16"`          // raw: low 16 bits of the miner's template time in ms
	TimeMs     uint64   `json:"time_ms_estimate"`     // reconstructed wall-clock ms (estimate, see mbl_time_ms)
	BeforeMs   int64    `json:"ms_before_block"`      // block timestamp minus TimeMs
	KeyHash    string   `json:"keyhash"`              // the 16 bytes a miniblock carries of the miner's key hash
	Miner      string   `json:"miner"`                // address, "unknown" if not registered in that block's state
	Integrator bool     `json:"integrator,omitempty"` // the final miniblock pays the block's integrator address
	Flags      uint32   `json:"flags"`
}

type GetMiniBlocks_Result struct {
	BlockHash      string            `json:"block_hash"`
	Height         int64             `json:"height"`
	TopoHeight     int64             `json:"topoheight"`
	BlockTimestamp uint64            `json:"block_timestamp_ms"`
	Integrator     string            `json:"integrator"`
	MiniBlocks     []MiniBlock_Print `json:"miniblocks"`
	Status         string            `json:"status"`
}

// MBL_FUTURE_SLACK_MS: a miniblock template can be stamped slightly after the block's own timestamp (the final
// template is built from a fresh clock read). Anything later than this is taken to belong to the previous 65.536 s
// window.
const MBL_FUTURE_SLACK_MS = 5000

// mbl_time_ms reconstructs a miniblock's wall-clock time from its 16-bit rolling stamp: ConvertBlockToMiniblock
// stores uint16(UnixMilli()) (blockchain/miner_block.go:356-357), so the full value is the latest time <= block
// time + slack whose low 16 bits match. Valid while the template is younger than ~60 s, which holds for a block
// whose miniblocks are all mined within one 18 s round. Pure: unit tested.
func mbl_time_ms(block_ms uint64, ts16 uint16) uint64 {
	c := (block_ms &^ 0xFFFF) | uint64(ts16)
	if c+0x10000 <= block_ms+MBL_FUTURE_SLACK_MS { // the miniblock is stamped after the block and its low 16 bits wrapped
		c += 0x10000
	} else if c > block_ms+MBL_FUTURE_SLACK_MS && c >= 0x10000 {
		c -= 0x10000
	}
	return c
}

func GetMiniBlocks(ctx context.Context, p GetMiniBlocks_Params) (result GetMiniBlocks_Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = rpc_internal_error(r)
		}
	}()
	var hash crypto.Hash
	if p.Hash != "" {
		var raw []byte
		if raw, err = hex.DecodeString(p.Hash); err != nil || len(raw) != 32 {
			return result, fmt.Errorf("hash must be 64 hex characters")
		}
		copy(hash[:], raw)
	} else {
		if p.TopoHeight < 0 || p.TopoHeight > chain.Load_TOPO_HEIGHT() {
			return result, fmt.Errorf("topoheight %d out of range 0..%d", p.TopoHeight, chain.Load_TOPO_HEIGHT())
		}
		if hash, err = block_id_at_topo(p.TopoHeight); err != nil {
			return
		}
	}
	bl, err := chain.Load_BL_FROM_ID(hash)
	if err != nil {
		return
	}
	result.BlockHash = hash.String()
	result.Height = chain.Load_Height_for_BL_ID(hash)
	result.TopoHeight = -1
	if chain.Is_Block_Topological_order(hash) {
		result.TopoHeight = chain.Load_Block_Topological_order(hash)
	}
	result.BlockTimestamp = bl.Timestamp

	// resolve miners against the state at the block's own TOPOheight (GetBlockHeader reads Topo_store at the
	// block's height, which is only the same record while topoheight == height)
	resolve := func(keyhash []byte) string { return "unknown" }
	if result.TopoHeight >= 0 {
		if toporecord, e := chain.Store.Topo_store.Read(result.TopoHeight); e == nil {
			if ss, e := chain.Store.Balance_store.LoadSnapshot(toporecord.State_Version); e == nil {
				if balance_tree, e := ss.GetTree(config.BALANCE_TREE); e == nil {
					resolve = func(keyhash []byte) string {
						bits, key, _, e := balance_tree.GetKeyValueFromHash(keyhash)
						if e != nil || bits >= 120 {
							return "unknown"
						}
						addr, e := rpc.NewAddressFromCompressedKeys(key)
						if e != nil {
							return "unknown"
						}
						addr.Mainnet = globals.IsMainnet()
						return addr.String()
					}
				}
			}
		}
	}
	if addr, e := rpc.NewAddressFromCompressedKeys(bl.Miner_TX.MinerAddress[:]); e == nil {
		addr.Mainnet = globals.IsMainnet()
		result.Integrator = addr.String()
	}

	result.MiniBlocks = make([]MiniBlock_Print, 0, len(bl.MiniBlocks))
	for i := range bl.MiniBlocks {
		result.MiniBlocks = append(result.MiniBlocks, print_miniblock(i, &bl.MiniBlocks[i], bl.Timestamp, resolve, result.Integrator))
	}
	result.Status = "OK"
	return
}

func print_miniblock(i int, mbl *block.MiniBlock, block_ms uint64, resolve func([]byte) string, integrator string) (m MiniBlock_Print) {
	m.Index = i
	m.Hash = mbl.GetHash().String()
	m.Final, m.HighDiff = mbl.Final, mbl.HighDiff
	m.Version, m.Height, m.PastCount = mbl.Version, mbl.Height, mbl.PastCount
	for j := 0; j < int(mbl.PastCount) && j < len(mbl.Past); j++ {
		m.Past = append(m.Past, fmt.Sprintf("%08x", mbl.Past[j]))
	}
	m.Timestamp = mbl.Timestamp
	m.TimeMs = mbl_time_ms(block_ms, mbl.Timestamp)
	m.BeforeMs = int64(block_ms) - int64(m.TimeMs)
	m.KeyHash = hex.EncodeToString(mbl.KeyHash[:16])
	m.Flags = mbl.Flags
	if mbl.Final {
		m.Miner, m.Integrator = integrator, true // a final miniblock carries no miner key; it pays the integrator
	} else {
		m.Miner = resolve(mbl.KeyHash[:16])
	}
	return
}

// ---------------------------------------------------------------- GetDifficultyHistory

type GetDifficultyHistory_Params struct {
	Count int64 `json:"count"`          // default DEFAULT_DIFFICULTY_HISTORY, max MAX_DIFFICULTY_HISTORY
	End   int64 `json:"end_topoheight"` // 0 = chain top
}

type DifficultyPoint struct {
	TopoHeight int64  `json:"topoheight"`
	Height     int64  `json:"height"`
	Hash       string `json:"hash"`
	Difficulty string `json:"difficulty"`
	Timestamp  uint64 `json:"timestamp_ms"`
}

type GetDifficultyHistory_Result struct {
	Points               []DifficultyPoint `json:"points"` // ascending topoheight
	MeanDifficulty       float64           `json:"mean_difficulty"`
	MeanBlockTimeSeconds float64           `json:"mean_block_time_seconds"` // (last-first timestamp) / (last-first height)
	HashrateEstimate     float64           `json:"network_hashrate_estimate"`
	HashrateNote         string            `json:"network_hashrate_note"`
	Status               string            `json:"status"`
}

// difficulty_summary is pure so the arithmetic is unit tested.
func difficulty_summary(pts []DifficultyPoint, diffs []float64) (mean_diff, mean_bt float64) {
	if len(diffs) > 0 {
		var s float64
		for _, d := range diffs {
			s += d
		}
		mean_diff = s / float64(len(diffs))
	}
	if n := len(pts); n >= 2 {
		dh := pts[n-1].Height - pts[0].Height
		if dh > 0 && pts[n-1].Timestamp > pts[0].Timestamp {
			mean_bt = float64(pts[n-1].Timestamp-pts[0].Timestamp) / 1000 / float64(dh)
		}
	}
	return
}

func GetDifficultyHistory(ctx context.Context, p GetDifficultyHistory_Params) (result GetDifficultyHistory_Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = rpc_internal_error(r)
		}
	}()
	top := chain.Load_TOPO_HEIGHT()
	count := p.Count
	if count == 0 {
		count = DEFAULT_DIFFICULTY_HISTORY
	}
	end := p.End
	if end == 0 {
		end = top
	}
	if count < 0 || count > MAX_DIFFICULTY_HISTORY {
		return result, fmt.Errorf("count must be 1..%d", MAX_DIFFICULTY_HISTORY)
	}
	start := end - count + 1
	if start < 0 {
		start = 0
	}
	if start, end, err = clamp_topo_range(start, end, top, MAX_DIFFICULTY_HISTORY); err != nil {
		return
	}
	release, err := acquire_range_slot(ctx)
	defer release()
	if err != nil {
		return
	}
	diffs := make([]float64, 0, end-start+1)
	result.Points = make([]DifficultyPoint, 0, end-start+1)
	for t := start; t <= end; t++ {
		if err = ctx.Err(); err != nil {
			return
		}
		r, e := chain.Store.Topo_store.Read(t)
		if e != nil || r.IsClean() {
			continue // a hole (e.g. a clean record) is skipped, not fatal
		}
		d := chain.Load_Block_Difficulty(crypto.Hash(r.BLOCK_ID))
		df, _ := new(big.Float).SetInt(d).Float64()
		diffs = append(diffs, df)
		result.Points = append(result.Points, DifficultyPoint{TopoHeight: t, Height: r.Height, Hash: crypto.Hash(r.BLOCK_ID).String(), Difficulty: d.String(), Timestamp: chain.Load_Block_Timestamp(crypto.Hash(r.BLOCK_ID))})
	}
	result.MeanDifficulty, result.MeanBlockTimeSeconds = difficulty_summary(result.Points, diffs)
	result.HashrateEstimate = result.MeanDifficulty
	result.HashrateNote = "estimate: mean difficulty, the same quantity GetInfo reports as network hashrate (blockchain.Get_Network_HashRate returns the difficulty)"
	result.Status = "OK"
	return
}

// ---------------------------------------------------------------- GetTxPoolDetail

type GetTxPoolDetail_Params struct {
	Limit int `json:"limit"` // default DEFAULT_TXPOOL_DETAIL, max MAX_TXPOOL_DETAIL
}

type TxPoolEntry struct {
	TXID      string `json:"txid"`
	Pool      string `json:"pool"` // mempool | regpool
	Type      string `json:"type"`
	Size      int    `json:"size"`
	Fee       uint64 `json:"fee"`
	FeePerKB  uint64 `json:"fee_per_kb"`
	Payloads  int    `json:"payloads"`
	RingSize  uint64 `json:"ring_size"`
	Height    uint64 `json:"height_built"`
	SC        bool   `json:"sc"`
	BurnValue uint64 `json:"burn_value"`
}

type GetTxPoolDetail_Result struct {
	MempoolCount int           `json:"mempool_count"`
	RegpoolCount int           `json:"regpool_count"`
	TotalBytes   int           `json:"listed_bytes"`
	Truncated    bool          `json:"truncated"`
	Txs          []TxPoolEntry `json:"txs"` // mempool by fee per KB (highest first), then regpool
	Status       string        `json:"status"`
}

// tx_pool_entry summarises a pool tx; pure so it is unit tested on a constructed transaction.
func tx_pool_entry(tx *transaction.Transaction, pool string) (e TxPoolEntry) {
	e.TXID = tx.GetHash().String()
	e.Pool = pool
	e.Type = tx.TransactionType.String()
	e.Size = len(tx.Serialize())
	e.Height = tx.Height
	e.SC = tx.IsSC()
	e.Payloads = len(tx.Payloads)
	if !tx.IsRegistration() {
		e.Fee = tx.Fees()
	}
	if e.Size > 0 {
		e.FeePerKB = e.Fee * 1024 / uint64(e.Size)
	}
	for i := range tx.Payloads {
		if tx.Payloads[i].Statement.RingSize > e.RingSize {
			e.RingSize = tx.Payloads[i].Statement.RingSize
		}
		e.BurnValue += tx.Payloads[i].BurnValue
	}
	return
}

func GetTxPoolDetail(ctx context.Context, p GetTxPoolDetail_Params) (result GetTxPoolDetail_Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = rpc_internal_error(r)
		}
	}()
	limit := p.Limit
	if limit == 0 {
		limit = DEFAULT_TXPOOL_DETAIL
	}
	if limit < 0 || limit > MAX_TXPOOL_DETAIL {
		return result, fmt.Errorf("limit must be 1..%d", MAX_TXPOOL_DETAIL)
	}
	release, err := acquire_range_slot(ctx) // one of the node-wide range slots, like the other range methods (F5)
	defer release()
	if err != nil {
		return
	}
	// Order: mempool entries sorted by fee/KB among the first MAX_TXPOOL_DETAIL listed, then regpool entries; on a
	// pool larger than that the order is local to those entries (Truncated says so).
	mem := chain.Mempool.Mempool_List_TX()
	reg := chain.Regpool.Regpool_List_TX()
	result.MempoolCount, result.RegpoolCount = len(mem), len(reg)

	var mtx []TxPoolEntry
	for _, h := range mem {
		if err = ctx.Err(); err != nil {
			return
		}
		if tx := chain.Mempool.Mempool_Get_TX(h); tx != nil { // may have left the pool since the listing
			mtx = append(mtx, tx_pool_entry(tx, "mempool"))
		}
		if len(mtx) >= MAX_TXPOOL_DETAIL {
			break
		}
	}
	sort.SliceStable(mtx, func(i, j int) bool { return mtx[i].FeePerKB > mtx[j].FeePerKB })
	for _, h := range reg {
		if len(mtx) >= MAX_TXPOOL_DETAIL {
			break
		}
		if tx := chain.Regpool.Regpool_Get_TX(h); tx != nil {
			mtx = append(mtx, tx_pool_entry(tx, "regpool"))
		}
	}
	if len(mtx) > limit {
		mtx, result.Truncated = mtx[:limit], true
	} else if len(mem)+len(reg) > len(mtx) && len(mtx) == MAX_TXPOOL_DETAIL {
		result.Truncated = true
	}
	for i := range mtx {
		result.TotalBytes += mtx[i].Size
	}
	result.Txs = mtx
	result.Status = "OK"
	return
}

// ---------------------------------------------------------------- GetPeerInfo

type GetPeerInfo_Result struct {
	Peers         []p2p.PeerInfo `json:"peers"`
	Incoming      uint64         `json:"incoming"`
	Outgoing      uint64         `json:"outgoing"`
	V2PeersSeen7d int            `json:"v2_chain_peers_seen_7d"` // distinct IPs dropped for following the v2 remnant chain
	OurHeight     int64          `json:"our_height"`
	OurTopoHeight int64          `json:"our_topoheight"`
	Status        string         `json:"status"`
}

// rpc_bind_address is the --rpc-bind the server listens on (set by RPCServer_Start; loopback until then).
var rpc_bind_address = "127.0.0.1:0"

// peerinfo_allowed: GetPeerInfo lists every peer's IP, first relays and miniblock counts, so like pprof and /metrics
// (bind_policy.go, node_metrics.go) it is served on a loopback --rpc-bind, or on a public one only with
// ENABLE_PUBLIC_PEER_INFO=1 (verifier F6).
func peerinfo_allowed(bind string, getenv func(string) string) bool {
	return bind_is_loopback(bind) || getenv("ENABLE_PUBLIC_PEER_INFO") == "1"
}

func GetPeerInfo(ctx context.Context) (result GetPeerInfo_Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = rpc_internal_error(r)
		}
	}()
	if err = refuse_foreign(ctx, "DERO.GetPeerInfo"); err != nil { // r20: peer IPs are not for web pages
		return
	}
	if !peerinfo_allowed(rpc_bind_address, os.Getenv) {
		return result, fmt.Errorf("DERO.GetPeerInfo is served on a loopback --rpc-bind only (set ENABLE_PUBLIC_PEER_INFO=1 to expose peer addresses)")
	}
	result.Peers = p2p.PeerInfos(MAX_PEER_INFO)
	result.Incoming, result.Outgoing = p2p.Peer_Direction_Count()
	result.V2PeersSeen7d = p2p.V2OffendersSeen(time.Now().Unix())
	result.OurHeight = chain.Get_Height()
	result.OurTopoHeight = chain.Load_TOPO_HEIGHT()
	result.Status = "OK"
	return
}

// ---------------------------------------------------------------- chain fingerprint (exposed by GetSyncInfo)

// The HF3 fork block (height 7,504,640, config.Mainnet.MAJOR_HF3_HEIGHT) identifies which side of the 2026-08-21
// chain split a node is on: the upgraded chain carries HF3_V3_HASH there, the non-upgraded v2 remnant a v2 block
// whose hash starts with HF3_V2_PREFIX (memory release151-hardfork-migration.md; v3 hash read from this node's RPC).
const HF3_V3_HASH = "e454090e983a3437e9b8ad4f1a45e4dbf46849832cccb3cc2b7841b94fb464d5"
const HF3_V2_PREFIX = "54219c50"

// classify_fingerprint is pure: unit tested.
func classify_fingerprint(mainnet bool, our_height, hf3_height int64, hashes []string) (verdict string, final bool) {
	switch {
	case !mainnet:
		return "n/a (not mainnet)", true
	case our_height < hf3_height:
		return "not reached (below HF3 height)", false
	}
	for _, h := range hashes {
		if h == HF3_V3_HASH {
			return "v3 (upgraded chain, fork block " + HF3_V3_HASH[:8] + ")", true
		}
	}
	for _, h := range hashes {
		if strings.HasPrefix(h, HF3_V2_PREFIX) {
			return "v2-remnant (NOT the upgraded chain, fork block " + HF3_V2_PREFIX + ")", true
		}
	}
	if len(hashes) == 0 {
		return "unknown (no block stored at HF3 height)", false
	}
	return "unknown (fork block " + hashes[0][:8] + " matches neither side)", false
}

var fingerprint_cached struct {
	sync.Mutex
	verdict string
	final   bool
}

func chain_fingerprint() string {
	fingerprint_cached.Lock()
	defer fingerprint_cached.Unlock()
	if fingerprint_cached.final {
		return fingerprint_cached.verdict
	}
	hf3 := globals.Config.MAJOR_HF3_HEIGHT
	var hashes []string
	if globals.IsMainnet() && chain.Get_Height() >= hf3 {
		for _, h := range chain.Get_Blocks_At_Height(hf3) {
			hashes = append(hashes, h.String())
		}
	}
	fingerprint_cached.verdict, fingerprint_cached.final = classify_fingerprint(globals.IsMainnet(), chain.Get_Height(), hf3, hashes)
	return fingerprint_cached.verdict
}
