package main

// R26 forensics-data KATs for the (a2) tool (go_mutations.json gm-a2-*). Each test has a negative control (the input
// that must be refused) and a positive control (the input that must pass), so a weakened guard fails a test.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2s"

	"github.com/deroproject/derohe/p2p"
)

func TestR26A2DatadirGuard(t *testing.T) {
	base := t.TempDir()
	good := filepath.Join(base, "seed")
	cases := []struct {
		name, dir, env string
		create, ok     bool
	}{
		{"relative", "rel/seed", "rel/seed", true, false},
		{"unclean", base + "/x/../seed", base + "/x/../seed", true, false},
		{"node store component", filepath.Join(base, "dero-data", "mainnet"), filepath.Join(base, "dero-data", "mainnet"), true, false},
		{"node store sibling", filepath.Join(base, "dero-data.bak"), filepath.Join(base, "dero-data.bak"), true, false},
		{"no confirmation", good, "", true, false},
		{"other confirmation", good, good + "x", true, false},
		{"fresh ok", good, good, true, true},
		{"open without marker", good, good, false, false},
	}
	for _, c := range cases {
		os.Setenv("FORENSICS_A2_DATADIR_OK", c.env)
		_, err := datadirGuard(c.dir, c.create)
		if (err == nil) != c.ok {
			t.Fatalf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
	// a non-empty dir is never reused by fetch-state; a seeded one (marker) opens for replay
	os.MkdirAll(good, 0700)
	os.WriteFile(filepath.Join(good, "x"), []byte("x"), 0600)
	os.Setenv("FORENSICS_A2_DATADIR_OK", good)
	if _, err := datadirGuard(good, true); err == nil {
		t.Fatal("non-empty datadir accepted for create")
	}
	os.WriteFile(filepath.Join(good, markerName), []byte("m"), 0600)
	if _, err := datadirGuard(good, false); err != nil {
		t.Fatalf("seeded datadir refused: %v", err)
	}
	os.Unsetenv("FORENSICS_A2_DATADIR_OK")
}

// keyIn returns a key whose blake2s key-hash starts with the given first bit
func keyIn(bit bool) []byte {
	for i := 0; ; i++ {
		k := []byte{byte(i), byte(i >> 8), 7}
		h := blake2s.Sum256(k)
		if (h[0]&0x80 != 0) == bit {
			return k
		}
	}
}

func TestR26A2SectionCheck(t *testing.T) {
	sec := sectionPath(1) // bit-reversed 1: first bit set
	if sec[0] != 0x80 {
		t.Fatalf("sectionPath(1)[0] = %x, want 80", sec[0])
	}
	in, out := keyIn(true), keyIn(false)
	ok := &p2p.Response_Tree_Section_Struct{Keys: [][]byte{in}, Values: [][]byte{{1}}}
	if err := sectionCheck(sec, 1, ok); err != nil {
		t.Fatalf("a key inside the section was refused: %v", err)
	}
	foreign := &p2p.Response_Tree_Section_Struct{Keys: [][]byte{in, out}, Values: [][]byte{{1}, {2}}}
	if err := sectionCheck(sec, 1, foreign); err == nil {
		t.Fatal("a key outside the requested section was accepted")
	}
	unpaired := &p2p.Response_Tree_Section_Struct{Keys: [][]byte{in}, Values: nil}
	if err := sectionCheck(sec, 1, unpaired); err == nil {
		t.Fatal("unpaired keys/values accepted")
	}
	capped := &p2p.Response_Tree_Section_Struct{}
	for i := 0; i <= maxSectionKeys; i++ {
		capped.Keys, capped.Values = append(capped.Keys, in), append(capped.Values, []byte{1})
	}
	if err := sectionCheck(sec, 1, capped); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("a reply at the handler's 10,001-key cap was accepted (err %v)", err)
	}
	if err := sectionCheck(sec, 0, &p2p.Response_Tree_Section_Struct{Keys: [][]byte{out}, Values: [][]byte{{1}}}); err != nil {
		t.Fatalf("path 0 (a whole SC tree) refused: %v", err)
	}
}

func TestR26A2ChunksFor(t *testing.T) {
	for _, c := range []struct {
		keys       int64
		chunks     int64
		pathLength int
	}{{0, 2, 1}, {640, 2, 1}, {640 * 5, 8, 3}, {2141950, 4096, 12}} {
		ch, pl := chunksFor(c.keys)
		if ch != c.chunks || pl != c.pathLength {
			t.Fatalf("chunksFor(%d) = %d,%d want %d,%d", c.keys, ch, pl, c.chunks, c.pathLength)
		}
	}
	if l := newLimiter(100); l.gap.Seconds() < 0.25 {
		t.Fatalf("limiter not capped at 4 req/s: gap %v", l.gap)
	}
}

// tier A data of dataset v1 (in git): the anchor block (no txs) and a tx-carrying block with its body
func v1Blob(t *testing.T, sha string) []byte {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "forensics", "r25", "raw", "blobs", sha))
	if err != nil {
		t.Skip("dataset v1 blobs not present: ", err)
	}
	return b
}

func TestR26A2CompleteBlockChecks(t *testing.T) {
	// the 414f79b8 carrier at 7,467,498 (dataset v1 tier A): block and body are in raw/blobs
	var prov struct {
		Tx []struct {
			ID, SHA256 string
			Carriers   []string
		} `json:"tx_objects"`
		Blocks []struct {
			ID, SHA256 string
		} `json:"tierA_blocks"`
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "forensics", "r25", "raw", "provenance.json"))
	if err != nil {
		t.Skip("dataset v1 not present")
	}
	if err := json.Unmarshal(b, &prov); err != nil {
		t.Fatal(err)
	}
	var txid, txsha, blid, blsha string
	for _, x := range prov.Tx {
		if strings.HasPrefix(x.ID, "414f79b8") {
			txid, txsha, blid = x.ID, x.SHA256, x.Carriers[0]
		}
	}
	for _, x := range prov.Blocks {
		if x.ID == blid {
			blsha = x.SHA256
		}
	}
	if blsha == "" {
		t.Skip("carrier block not in tier A")
	}
	dir := t.TempDir()
	blk, tx := v1Blob(t, blsha), v1Blob(t, txsha)
	write := func(b []byte) string {
		h := sha256.Sum256(b)
		s := hex.EncodeToString(h[:])
		os.WriteFile(filepath.Join(dir, s), b, 0600)
		return s
	}
	write(blk)
	write(tx)
	// the carrier may hold more txs than 414f79b8: take the block's own list from a decode
	cbl, err := completeBlock(planRow{BLID: blid, SHA256: blsha, Txs: [][2]string{{txid, txsha}}}, []string{dir}, []string{dir})
	if err != nil && !strings.Contains(err.Error(), "plan has") {
		t.Fatalf("positive control failed: %v", err)
	}
	if err == nil && len(cbl.Txs) != 1 {
		t.Fatalf("tx count %d", len(cbl.Txs))
	}
	if err != nil {
		t.Fatal("the 414f79b8 carrier must be a one-tx tier A block (dataset v1)")
	}
	// negative controls
	if _, err := completeBlock(planRow{BLID: strings.Repeat("0", 64), SHA256: blsha, Txs: [][2]string{{txid, txsha}}}, []string{dir}, []string{dir}); err == nil {
		t.Fatal("a wrong block id was accepted")
	}
	bad := append([]byte{}, blk...)
	bad[len(bad)/2] ^= 1
	os.WriteFile(filepath.Join(dir, blsha), bad, 0600) // content no longer matches its name
	if _, err := completeBlock(planRow{BLID: blid, SHA256: blsha, Txs: [][2]string{{txid, txsha}}}, []string{dir}, []string{dir}); err == nil {
		t.Fatal("a blob whose content does not hash to its name was accepted")
	}
	// readBlob itself: other bytes stored under a content name are refused even when they are a valid object
	os.WriteFile(filepath.Join(dir, blsha), tx, 0600)
	if _, err := readBlob([]string{dir}, blsha); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("readBlob returned bytes that do not hash to their name (err %v)", err)
	}
	os.WriteFile(filepath.Join(dir, blsha), blk, 0600)
	if b, err := readBlob([]string{dir}, blsha); err != nil || len(b) != len(blk) {
		t.Fatalf("readBlob positive control: %v", err)
	}
	if _, err := completeBlock(planRow{BLID: blid, SHA256: blsha, Txs: [][2]string{{strings.Repeat("1", 64), txsha}}}, []string{dir}, []string{dir}); err == nil {
		t.Fatal("a wrong TXID was accepted")
	}
}

func TestR26A2PlanContiguous(t *testing.T) {
	p := filepath.Join(t.TempDir(), "plan.jsonl")
	os.WriteFile(p, []byte(`{"topo":5,"blid":"a","sha256":"b","txs":[]}`+"\n"+`{"topo":7,"blid":"a","sha256":"b","txs":[]}`+"\n"), 0600)
	if _, err := readPlan(p); err == nil {
		t.Fatal("a plan with a gap was accepted")
	}
	os.WriteFile(p, []byte(`{"topo":5,"blid":"a","sha256":"b","txs":[]}`+"\n"+`{"topo":6,"blid":"a","sha256":"b","txs":[]}`+"\n"), 0600)
	if rows, err := readPlan(p); err != nil || len(rows) != 2 {
		t.Fatalf("contiguous plan refused: %v", err)
	}
}

func TestR26A2PeerFilePrivacy(t *testing.T) {
	p := filepath.Join(t.TempDir(), "peers.json")
	os.WriteFile(p, []byte(`{"src-9":{"p2p":"peer.invalid:11011"}}`), 0600)
	if _, err := loadPeer(p, "src-1"); err == nil || strings.Contains(err.Error(), "peer.invalid") {
		t.Fatalf("missing pseudonym: err %v (must fail and never print an address)", err)
	}
	if a, err := loadPeer(p, "src-9"); err != nil || a != "peer.invalid:11011" {
		t.Fatalf("loadPeer: %v %q", err, a)
	}
}
