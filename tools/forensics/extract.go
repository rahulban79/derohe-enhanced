// R25 forensics-extract modes of the read-only decoder (rft §0.8.3, §0.8.8). Consensus-neutral: it imports the
// node's packages unchanged and calls their exported functions; it changes no package state except the crypto
// package's Logger (a no-op logr.Discard by default, cryptography/crypto/userdata.go:28), which it points at a
// recorder so that a failed Proof.Verify names the check that failed (proof_verify.go logs one V(1) line per check).
//
// "verify" re-runs, against a COPY of a graviton balances store, exactly the steps of the current verifier
// (blockchain/transaction_verify.go, verify_Transaction_NonCoinbase_internal) that do not depend on a live chain:
// the sanity checks of :225-322, the reference state root of :327-338 (Load_Merkle_Hash, blockchain/store.go:297-327),
// the ring expansion of :358-431, and Proof.Verify of :450-461 — WITHOUT the HF3 cache entry of :232-238 and the
// cache short-circuit of :433-441, so it answers "would today's verifier accept this proof if the exemption did not
// exist". It records outcomes only (pass/fail + the name of the failed check), never proof internals.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
	"github.com/go-logr/logr"
)

// ---------------------------------------------------------------------------------------------------- block2/tx2

type block2Out struct {
	OK             bool     `json:"ok"`
	Kind           string   `json:"kind"`
	Path           string   `json:"path"`
	Error          string   `json:"error,omitempty"`
	ID             string   `json:"id,omitempty"`
	Reserialize    bool     `json:"reserialize_equal"`
	Major          uint64   `json:"major_version"`
	Minor          uint64   `json:"minor_version"`
	Height         uint64   `json:"height"`
	TimestampMs    uint64   `json:"timestamp_ms"`
	Tips           []string `json:"tips"`
	TxHashes       []string `json:"tx_hashes"`
	MiniBlocks     int      `json:"miniblocks"`
	MiniFinal      int      `json:"miniblocks_final"`
	ProofNonZero   bool     `json:"proof_field_nonzero"`
	MinerTxType    string   `json:"miner_tx_type"`
	MinerTxHeight  uint64   `json:"miner_tx_height"`
	MinerTxValue   uint64   `json:"miner_tx_value"`
	BaseReward     uint64   `json:"node_calc_block_reward"`  // blockchain/transaction_execute.go:60
	SupplyAtHeight uint64   `json:"node_calc_supply_height"` // blockchain/supply.go:5, CalcSupply(height)
	SupplyNext     uint64   `json:"node_calc_supply_next"`   // CalcSupply(height+1)
}

func decodeBlock2(path string, buf []byte) (o block2Out) {
	o.Kind, o.Path = "block2", path
	defer func() {
		if r := recover(); r != nil {
			o = block2Out{Kind: "block2", Path: path, Error: fmt.Sprintf("recovered panic: %v", r)}
		}
	}()
	var bl block.Block
	if err := bl.Deserialize(buf); err != nil {
		o.Error = err.Error()
		return
	}
	h := bl.GetHash()
	o.ID = hex.EncodeToString(h[:])
	o.Reserialize = bytes.Equal(bl.Serialize(), buf)
	o.Major, o.Minor, o.Height, o.TimestampMs = bl.Major_Version, bl.Minor_Version, bl.Height, bl.Timestamp
	o.Tips, o.TxHashes = []string{}, []string{}
	for _, t := range bl.Tips {
		o.Tips = append(o.Tips, hex.EncodeToString(t[:]))
	}
	for _, t := range bl.Tx_hashes {
		o.TxHashes = append(o.TxHashes, hex.EncodeToString(t[:]))
	}
	o.MiniBlocks = len(bl.MiniBlocks)
	for _, mb := range bl.MiniBlocks {
		if mb.Final {
			o.MiniFinal++
		}
	}
	var zero [32]byte
	o.ProofNonZero = bl.Proof != zero
	o.MinerTxType, o.MinerTxHeight, o.MinerTxValue = bl.Miner_TX.TransactionType.String(), bl.Miner_TX.Height, bl.Miner_TX.Value
	o.BaseReward = blockchain.CalcBlockReward(bl.Height)
	o.SupplyAtHeight = blockchain.CalcSupply(bl.Height)
	o.SupplyNext = blockchain.CalcSupply(bl.Height + 1)
	o.OK = true
	return
}

type payload2Out struct {
	SCIDZero      bool   `json:"scid_zero"`
	BurnValue     uint64 `json:"burn_value"`
	Fees          uint64 `json:"fees"`
	RingSize      uint64 `json:"ring_size"`
	BytesPerKey   byte   `json:"bytes_per_publickey"`
	PointerBytes  int    `json:"pointer_bytes"`
	Commitments   int    `json:"commitments"`
	Roothash      string `json:"statement_roothash"`
	RPCType       byte   `json:"rpc_type"`
	RPCPayloadLen int    `json:"rpc_payload_len"`
	HasProof      bool   `json:"has_proof"`
	ProofParity   bool   `json:"proof_parity"` // Proof.Parity(), the value transaction_execute.go:213 starts from
}

type tx2Out struct {
	OK              bool          `json:"ok"`
	Kind            string        `json:"kind"`
	Path            string        `json:"path"`
	Error           string        `json:"error,omitempty"`
	TXID            string        `json:"txid,omitempty"`
	CoreHex         string        `json:"core_hex,omitempty"` // SerializeCoreStatement (transaction/transaction.go:510); TXID = Keccak256 of it (:195)
	SerializeKeccak string        `json:"serialize_keccak256,omitempty"`
	Reserialize     bool          `json:"reserialize_equal"`
	Size            int           `json:"size"`
	Version         uint64        `json:"version"`
	TxType          string        `json:"tx_type"`
	Value           uint64        `json:"value"`
	RefHeight       uint64        `json:"ref_height"`
	RefBLID         string        `json:"ref_blid"`
	Fees            uint64        `json:"fees"`
	HasSCData       bool          `json:"has_scdata"`
	SCDataKeys      int           `json:"scdata_keys"`
	RegValid        *bool         `json:"registration_signature_valid,omitempty"`
	Payloads        []payload2Out `json:"payloads"`
}

func decodeTx2(path string, buf []byte) (o tx2Out) {
	o.Kind, o.Path = "tx2", path
	defer func() {
		if r := recover(); r != nil {
			o = tx2Out{Kind: "tx2", Path: path, Error: fmt.Sprintf("recovered panic: %v", r)}
		}
	}()
	var tx transaction.Transaction
	if err := tx.Deserialize(buf); err != nil {
		o.Error = err.Error()
		return
	}
	h := tx.GetHash()
	o.TXID = hex.EncodeToString(h[:])
	o.CoreHex = hex.EncodeToString(tx.SerializeCoreStatement())
	sk := crypto.Keccak256(tx.Serialize())
	o.SerializeKeccak = hex.EncodeToString(sk[:])
	o.Reserialize = bytes.Equal(tx.Serialize(), buf)
	o.Size = len(buf)
	o.Version, o.TxType, o.Value = tx.Version, tx.TransactionType.String(), tx.Value
	o.RefHeight, o.RefBLID = tx.Height, hex.EncodeToString(tx.BLID[:])
	o.Fees = tx.Fees()
	o.HasSCData, o.SCDataKeys = len(tx.SCDATA) > 0, len(tx.SCDATA)
	if tx.TransactionType == transaction.REGISTRATION {
		v := tx.IsRegistrationValid()
		o.RegValid = &v
	}
	var zero [32]byte
	o.Payloads = []payload2Out{}
	for i := range tx.Payloads {
		p := &tx.Payloads[i]
		po := payload2Out{SCIDZero: [32]byte(p.SCID) == zero, BurnValue: p.BurnValue, Fees: p.Statement.Fees,
			RingSize: p.Statement.RingSize, BytesPerKey: p.Statement.Bytes_per_publickey,
			PointerBytes: len(p.Statement.Publickeylist_pointers), Commitments: len(p.Statement.C),
			Roothash: hex.EncodeToString(p.Statement.Roothash[:]), RPCType: p.RPCType, RPCPayloadLen: len(p.RPCPayload),
			HasProof: p.Proof != nil}
		if p.Proof != nil && tx.TransactionType != transaction.REGISTRATION {
			po.ProofParity = p.Proof.Parity()
		}
		o.Payloads = append(o.Payloads, po)
	}
	o.OK = true
	return
}

// ---------------------------------------------------------------------------------------------------- stores

var (
	storesMu sync.Mutex
	stores   = map[string]*graviton.Store{}
)

// openCopy opens a graviton store, refusing anything that looks like a node datadir (only copies are allowed).
func openCopy(dir string) (*graviton.Store, error) {
	storesMu.Lock()
	defer storesMu.Unlock()
	if s, ok := stores[dir]; ok {
		return s, nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(abs, "version_root.bin")); err != nil {
		return nil, fmt.Errorf("not a graviton store (no version_root.bin): %w", err)
	}
	if os.Getenv("FORENSICS_STORE_COPY_OK") != abs {
		return nil, fmt.Errorf("refused: FORENSICS_STORE_COPY_OK must name this exact copy (graviton opens O_RDWR)")
	}
	s, err := graviton.NewDiskStore(abs)
	if err != nil {
		return nil, err
	}
	stores[dir] = s
	return s, nil
}

// merkle is Load_Merkle_Hash (blockchain/store.go:297-327): balance tree hash XOR SC meta tree hash.
func merkle(ss *graviton.Snapshot) (hash crypto.Hash, err error) {
	bt, err := ss.GetTree(config.BALANCE_TREE)
	if err != nil {
		return
	}
	mt, err := ss.GetTree(config.SC_META)
	if err != nil {
		return
	}
	bh, err := bt.Hash()
	if err != nil {
		return
	}
	mh, err := mt.Hash()
	if err != nil {
		return
	}
	for i := range bh {
		hash[i] = bh[i] ^ mh[i]
	}
	return
}

type rootRow struct {
	Version uint64 `json:"version"`
	Root    string `json:"root,omitempty"`
	Error   string `json:"error,omitempty"`
}

type rootsOut struct {
	OK    bool      `json:"ok"`
	Kind  string    `json:"kind"`
	Error string    `json:"error,omitempty"`
	Rows  []rootRow `json:"rows"`
}

func stateRoots(dir string, versions []uint64) (o rootsOut) {
	o.Kind, o.Rows = "roots", []rootRow{}
	s, err := openCopy(dir)
	if err != nil {
		o.Error = err.Error()
		return
	}
	for _, v := range versions {
		r := rootRow{Version: v}
		func() {
			defer func() {
				if x := recover(); x != nil {
					r.Error = fmt.Sprintf("recovered panic: %v", x)
				}
			}()
			ss, err := s.LoadSnapshot(v)
			if err != nil {
				r.Error = err.Error()
				return
			}
			h, err := merkle(ss)
			if err != nil {
				r.Error = err.Error()
				return
			}
			r.Root = hex.EncodeToString(h[:])
		}()
		o.Rows = append(o.Rows, r)
	}
	o.OK = true
	return
}

// ---------------------------------------------------------------------------------------------------- verify

type recSink struct{ msgs *[]string }

func (r recSink) Init(logr.RuntimeInfo)                    {}
func (r recSink) Enabled(int) bool                         { return true }
func (r recSink) Info(_ int, msg string, _ ...interface{}) { *r.msgs = append(*r.msgs, msg) }
func (r recSink) Error(_ error, msg string, _ ...interface{}) {
	*r.msgs = append(*r.msgs, "error: "+msg)
}
func (r recSink) WithValues(...interface{}) logr.LogSink { return r }
func (r recSink) WithName(string) logr.LogSink           { return r }

type check struct {
	Name   string `json:"name"`
	Cite   string `json:"cite"`
	Result string `json:"result"` // pass | fail | not_reached
	Detail string `json:"detail,omitempty"`
}

type payloadVerify struct {
	Index       int    `json:"payload"`
	Expanded    bool   `json:"ring_expanded"`
	ProofVerify string `json:"proof_verify"` // pass | fail | not_reached
	FailedCheck string `json:"failed_check,omitempty"`
}

type verifyOut struct {
	OK          bool            `json:"ok"`
	Kind        string          `json:"kind"`
	Path        string          `json:"path"`
	Error       string          `json:"error,omitempty"`
	TXID        string          `json:"txid,omitempty"`
	Version     uint64          `json:"state_version"`
	StateRoot   string          `json:"state_root,omitempty"`
	Checks      []check         `json:"checks"`
	Payloads    []payloadVerify `json:"payloads"`
	Verdict     string          `json:"verdict"` // pass | fail:<check> | not_decidable:<reason>
	HF3Bypassed string          `json:"hf3_cache_bypassed"`
}

var verifyMu sync.Mutex

func verifyTx(path, dir string, version uint64) (o verifyOut) {
	verifyMu.Lock()
	defer verifyMu.Unlock()
	o.Kind, o.Path, o.Version, o.Checks, o.Payloads = "verify", path, version, []check{}, []payloadVerify{}
	o.HF3Bypassed = "yes: this mode never fills or reads transaction_valid_cache (transaction_verify.go:232-238, :433-441)"
	add := func(name, cite, res, det string) { o.Checks = append(o.Checks, check{name, cite, res, det}) }
	defer func() {
		if r := recover(); r != nil {
			o.OK, o.Verdict = false, "not_decidable:recovered panic in expansion"
			o.Error = fmt.Sprintf("recovered panic: %v", r)
		}
	}()
	buf, err := os.ReadFile(path)
	if err != nil {
		o.Error = err.Error()
		return
	}
	var tx transaction.Transaction
	if err := tx.Deserialize(buf); err != nil {
		o.Error = err.Error()
		return
	}
	txid := tx.GetHash()
	o.TXID = hex.EncodeToString(txid[:])
	fail := func(name string) { o.OK, o.Verdict = true, "fail:"+name }

	// :225-227, :256-322
	if tx.Version != 1 {
		add("version", "blockchain/transaction_verify.go:225", "fail", "")
		fail("version")
		return
	}
	add("version", "blockchain/transaction_verify.go:225", "pass", "")
	if !(tx.TransactionType == transaction.NORMAL || tx.TransactionType == transaction.SC_TX || tx.TransactionType == transaction.BURN_TX) {
		o.OK, o.Verdict = true, "not_decidable:not a proof-carrying type ("+tx.TransactionType.String()+")"
		return
	}
	sane := "pass"
	if tx.TransactionType == transaction.BURN_TX && tx.Value == 0 {
		sane = "fail"
	}
	if len(tx.Payloads) < 1 {
		sane = "fail"
	}
	hasBase := false
	for i := range tx.Payloads {
		if tx.Payloads[i].SCID.IsZero() {
			hasBase = true
		}
		if tx.Payloads[i].Statement.Roothash != tx.Payloads[0].Statement.Roothash {
			sane = "fail"
		}
	}
	if !hasBase {
		sane = "fail"
	}
	for t := range tx.Payloads {
		st := &tx.Payloads[t].Statement
		bpk := int(st.Bytes_per_publickey)
		if bpk == 0 || st.RingSize != uint64(len(st.Publickeylist_pointers)/bpk) || st.RingSize < 2 || st.RingSize > 128 ||
			!crypto.IsPowerOf2(len(st.Publickeylist_pointers)/bpk) {
			sane = "fail"
			continue
		}
		km := map[string]bool{}
		for i := 0; i < int(st.RingSize); i++ {
			km[string(st.Publickeylist_pointers[i*bpk:(i+1)*bpk])] = true
		}
		if len(km) != int(st.RingSize) {
			sane = "fail"
		}
		st.CLn, st.CRn = st.CLn[:0], st.CRn[:0]
	}
	add("statement_sanity", "blockchain/transaction_verify.go:256-322", sane, "burn value, payload count, base payload, roothash equality, ring size/pointers, distinct members")
	if sane != "pass" {
		fail("statement_sanity")
		return
	}

	// :327-341 reference state and its root
	s, err := openCopy(dir)
	if err != nil {
		o.Error = err.Error()
		return
	}
	ss, err := s.LoadSnapshot(version)
	if err != nil {
		add("reference_state", "blockchain/transaction_verify.go:327-341", "fail", err.Error())
		o.OK, o.Verdict = true, "not_decidable:reference state version not readable"
		return
	}
	root, err := merkle(ss)
	if err != nil {
		add("reference_state", "blockchain/transaction_verify.go:331-334", "fail", err.Error())
		o.OK, o.Verdict = true, "not_decidable:reference state root not computable"
		return
	}
	o.StateRoot = hex.EncodeToString(root[:])
	add("reference_state", "blockchain/transaction_verify.go:327-341", "pass", "")
	if root != crypto.Hash(tx.Payloads[0].Statement.Roothash) {
		// The verifier itself returns an error here (:336-338). With a store we hold, that means the copy's state at
		// this version is not the state the tx was built against: proof result not decidable from this store.
		add("statement_roothash", "blockchain/transaction_verify.go:336-338", "fail", "store root != Statement.Roothash")
		o.OK, o.Verdict = true, "not_decidable:held state root differs from the tx's Statement.Roothash"
		return
	}
	add("statement_roothash", "blockchain/transaction_verify.go:336-338", "pass", "")

	// :341-431 ring expansion
	balanceTree, err := ss.GetTree(config.BALANCE_TREE)
	if err != nil || balanceTree == nil {
		add("ring_expansion", "blockchain/transaction_verify.go:341-354", "fail", "balance tree not found")
		o.OK, o.Verdict = true, "not_decidable:balance tree missing"
		return
	}
	trees := map[crypto.Hash]*graviton.Tree{}
	var zh crypto.Hash
	trees[zh] = balanceTree
	expandOK := true
	for t := range tx.Payloads {
		pv := payloadVerify{Index: t, ProofVerify: "not_reached"}
		st := &tx.Payloads[t].Statement
		st.Publickeylist_compressed = st.Publickeylist_compressed[:0]
		st.Publickeylist = st.Publickeylist[:0]
		tree, ok := trees[tx.Payloads[t].SCID]
		if !ok {
			tree, _ = ss.GetTree(string(tx.Payloads[t].SCID[:]))
			trees[tx.Payloads[t].SCID] = tree
		}
		bpk := int(st.Bytes_per_publickey)
		good := true
		for i := 0; i < int(st.RingSize) && good; i++ {
			kp := st.Publickeylist_pointers[i*bpk : (i+1)*bpk]
			_, kc, bs, err := tree.GetKeyValueFromHash(kp)
			needsInit := false
			if err != nil && !tx.Payloads[t].SCID.IsZero() {
				if _, kc2, _, err2 := balanceTree.GetKeyValueFromHash(kp); err2 == nil {
					kc, err, needsInit = kc2, nil, true
				}
			}
			if err != nil {
				good = false
				break
			}
			var p bn256.G1
			var pc [33]byte
			copy(pc[:], kc)
			if err = p.DecodeCompressed(kc[:]); err != nil {
				good = false
				break
			}
			st.Publickeylist_compressed = append(st.Publickeylist_compressed, pc)
			st.Publickeylist = append(st.Publickeylist, &p)
			if needsInit {
				var nb crypto.NonceBalance
				nb.Balance = crypto.ConstructElGamal(&p, crypto.ElGamal_BASE_G)
				bs = nb.Serialize()
			}
			var ll, rr bn256.G1
			nb := new(crypto.NonceBalance).Deserialize(bs)
			ll.Add(nb.Balance.Left, st.C[i])
			st.CLn = append(st.CLn, &ll)
			rr.Add(nb.Balance.Right, st.D)
			st.CRn = append(st.CRn, &rr)
			ech := crypto.ConstructElGamal(st.C[i], st.D)
			nb = new(crypto.NonceBalance).Deserialize(bs)
			nb.Balance = nb.Balance.Add(ech)
			tree.Put(kc, nb.Serialize()) // in-memory only; never committed (the store is a copy anyway)
		}
		pv.Expanded = good
		if !good {
			expandOK = false
		}
		o.Payloads = append(o.Payloads, pv)
	}
	if !expandOK {
		add("ring_expansion", "blockchain/transaction_verify.go:358-431", "fail", "a ring member's balance could not be read or decoded")
		fail("ring_expansion")
		return
	}
	add("ring_expansion", "blockchain/transaction_verify.go:358-431", "pass", "")

	// :449-459 Proof.Verify per payload, with the crypto package's V(1) check names recorded
	scidMap := map[crypto.Hash]int{}
	var msgs []string
	old := crypto.Logger
	crypto.Logger = logr.New(recSink{&msgs})
	defer func() { crypto.Logger = old }()
	allPass := true
	firstFail := ""
	for t := range tx.Payloads {
		msgs = msgs[:0]
		index := scidMap[tx.Payloads[t].SCID]
		okv := tx.Payloads[t].Proof.Verify(tx.Payloads[t].SCID, index, &tx.Payloads[t].Statement, txid, tx.Payloads[t].BurnValue)
		if okv {
			o.Payloads[t].ProofVerify = "pass"
		} else {
			allPass = false
			o.Payloads[t].ProofVerify = "fail"
			name := "Proof.Verify returned false without a named check (cryptography/crypto/proof_verify.go:103-111 precondition)"
			if len(msgs) > 0 {
				name = msgs[len(msgs)-1]
			}
			o.Payloads[t].FailedCheck = name
			if firstFail == "" {
				firstFail = name
			}
		}
		scidMap[tx.Payloads[t].SCID] = scidMap[tx.Payloads[t].SCID] + 1
	}
	if allPass {
		add("proof_verify", "blockchain/transaction_verify.go:450-461", "pass", "")
		o.OK, o.Verdict = true, "pass"
		return
	}
	add("proof_verify", "blockchain/transaction_verify.go:450-461", "fail", firstFail)
	fail("proof_verify")
	return
}
