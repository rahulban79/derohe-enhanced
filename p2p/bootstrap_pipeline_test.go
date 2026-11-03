package p2p

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/graviton"
	"golang.org/x/crypto/blake2s"
)

// a fake peer answering section i (encoded in TreeName) after delay; tracks the most requests seen at once
func fake_sections(delay time.Duration, maxin *int32, fail int) func(Request_Tree_Section_Struct, int) (Response_Tree_Section_Struct, error) {
	var cur int32
	return func(r Request_Tree_Section_Struct, _ int) (resp Response_Tree_Section_Struct, err error) {
		c := atomic.AddInt32(&cur, 1)
		defer atomic.AddInt32(&cur, -1)
		for {
			m := atomic.LoadInt32(maxin)
			if c <= m || atomic.CompareAndSwapInt32(maxin, m, c) {
				break
			}
		}
		time.Sleep(delay)
		if string(r.TreeName) == fmt.Sprint(fail) {
			return resp, errors.New("peer failed")
		}
		resp.TreeName = r.TreeName
		return
	}
}

func TestFetchSectionsOrdered(t *testing.T) {
	for _, tc := range []struct{ n, depth int }{{0, 4}, {1, 4}, {10, 1}, {10, 4}, {257, 4}, {3, 8}} {
		var maxin int32
		var got []string
		err := fetch_sections_ordered(tc.n, tc.depth, func(i int) Request_Tree_Section_Struct {
			return Request_Tree_Section_Struct{TreeName: []byte(fmt.Sprint(i))}
		}, fake_sections(time.Millisecond, &maxin, -1), func(i int, r *Response_Tree_Section_Struct) error {
			if string(r.TreeName) != fmt.Sprint(i) {
				t.Fatalf("response %q handed to process as %d", r.TreeName, i)
			}
			got = append(got, string(r.TreeName))
			return nil
		})
		if err != nil || len(got) != tc.n || int(maxin) > tc.depth {
			t.Fatalf("n=%d depth=%d: err %v processed %d maxinflight %d", tc.n, tc.depth, err, len(got), maxin)
		}
	}
}

// the point of the pipeline: with depth d the round trips overlap, so n sections take ~n/d round trips, not n
func TestFetchSectionsOverlap(t *testing.T) {
	run := func(depth int) time.Duration {
		var maxin int32
		t0 := time.Now()
		if err := fetch_sections_ordered(40, depth, func(i int) Request_Tree_Section_Struct {
			return Request_Tree_Section_Struct{TreeName: []byte(fmt.Sprint(i))}
		}, fake_sections(10*time.Millisecond, &maxin, -1), func(int, *Response_Tree_Section_Struct) error { return nil }); err != nil {
			t.Fatal(err)
		}
		return time.Since(t0)
	}
	serial, piped := run(1), run(4)
	if piped*2 > serial {
		t.Fatalf("depth 4 took %s vs serial %s: requests are not overlapping", piped, serial)
	}
}

func TestFetchSectionsStopsAtFirstError(t *testing.T) {
	var maxin int32
	processed := 0
	err := fetch_sections_ordered(20, 4, func(i int) Request_Tree_Section_Struct {
		return Request_Tree_Section_Struct{TreeName: []byte(fmt.Sprint(i))}
	}, fake_sections(0, &maxin, 5), func(i int, r *Response_Tree_Section_Struct) error {
		processed++
		return nil
	})
	if err == nil || processed != 5 {
		t.Fatalf("err %v processed %d, want an error after exactly sections 0-4", err, processed)
	}
	processed = 0
	err = fetch_sections_ordered(20, 4, func(i int) Request_Tree_Section_Struct {
		return Request_Tree_Section_Struct{TreeName: []byte(fmt.Sprint(i))}
	}, fake_sections(0, &maxin, -1), func(i int, r *Response_Tree_Section_Struct) error {
		processed++
		if i == 7 {
			return errors.New("bad section")
		}
		return nil
	})
	if err == nil || processed != 8 {
		t.Fatalf("err %v processed %d, want the process error at section 7", err, processed)
	}
	// a panicking transport is an error, not a crash
	err = fetch_sections_ordered(3, 2, func(i int) Request_Tree_Section_Struct { return Request_Tree_Section_Struct{} },
		func(Request_Tree_Section_Struct, int) (Response_Tree_Section_Struct, error) { panic("boom") },
		func(int, *Response_Tree_Section_Struct) error { return nil })
	if err == nil {
		t.Fatal("transport panic was not reported")
	}
}

// serve answers a TreeSection request from a graviton tree exactly like the server handler (rpc_treesection.go)
func serve(tree *graviton.Tree, r Request_Tree_Section_Struct) (resp Response_Tree_Section_Struct, err error) {
	cursor := tree.Cursor()
	resp.KeyCount = tree.KeyCountEstimate()
	for k, v, err := cursor.SpecialFirst(r.Section, uint(r.SectionLength)); err == nil; k, v, err = cursor.Next() {
		resp.Keys = append(resp.Keys, k)
		resp.Values = append(resp.Values, v)
		if len(resp.Keys) > 10000 {
			break
		}
	}
	return resp, nil
}

func build_tree(t *testing.T, n int) *graviton.Tree {
	store, _ := graviton.NewMemStore()
	ss, _ := store.LoadSnapshot(0)
	tree, _ := ss.GetTree("t")
	for i := 0; i < n; i++ {
		tree.Put([]byte(fmt.Sprintf("key-%d", i)), []byte(fmt.Sprintf("value-%d", i)))
	}
	if _, err := graviton.Commit(tree); err != nil {
		t.Fatal(err)
	}
	return tree
}

// End to end against real graviton trees: the bit-reversed chunk paths cover every key exactly once, section_check
// accepts every honest answer, and the rebuilt tree has the server's root hash (the property --fastsync relies on).
func TestSectionsRebuildTreeExactly(t *testing.T) {
	for _, tc := range []struct{ keys, path_length int }{{5000, 3}, {5000, 1}, {20000, 5}} {
		src := build_tree(t, tc.keys)
		want, _ := src.Hash()
		store, _ := graviton.NewMemStore()
		ss, _ := store.LoadSnapshot(0)
		dst, _ := ss.GetTree("t")
		var mu sync.Mutex
		chunks := 1 << uint(tc.path_length)
		total := 0
		err := fetch_sections_ordered(chunks, 4, func(i int) Request_Tree_Section_Struct {
			return Request_Tree_Section_Struct{Section: section_path(int64(i)), SectionLength: uint64(tc.path_length)}
		}, func(r Request_Tree_Section_Struct, _ int) (Response_Tree_Section_Struct, error) {
			mu.Lock() // graviton trees are not safe for concurrent readers
			defer mu.Unlock()
			return serve(src, r)
		}, func(i int, r *Response_Tree_Section_Struct) error {
			if err := section_check(section_path(int64(i)), uint64(tc.path_length), r); err != nil {
				return err
			}
			for j := range r.Keys {
				dst.Put(r.Keys[j], r.Values[j])
			}
			total += len(r.Keys)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := graviton.Commit(dst); err != nil {
			t.Fatal(err)
		}
		got, _ := dst.Hash()
		if total != tc.keys || got != want {
			t.Fatalf("keys=%d path=%d: rebuilt %d keys, root %x want %x", tc.keys, tc.path_length, total, got, want)
		}
	}
}

func key_in_section(want_first_bit bool) []byte {
	for i := 0; ; i++ {
		k := []byte(fmt.Sprintf("k%d", i))
		h := blake2s.Sum256(k)
		if (h[0]&0x80 != 0) == want_first_bit {
			return k
		}
	}
}

func TestSectionCheckRejectsForeignKeys(t *testing.T) {
	left, right := key_in_section(false), key_in_section(true)
	ok := Response_Tree_Section_Struct{Keys: [][]byte{left}, Values: [][]byte{{1}}}
	if err := section_check(section_path(0), 1, &ok); err != nil {
		t.Fatalf("honest answer rejected: %v", err)
	}
	foreign := Response_Tree_Section_Struct{Keys: [][]byte{left, right}, Values: [][]byte{{1}, {2}}}
	if err := section_check(section_path(0), 1, &foreign); err == nil {
		t.Fatal("a key from the other half of the tree was accepted")
	}
	if err := section_check(section_path(1), 1, &Response_Tree_Section_Struct{Keys: [][]byte{right}, Values: [][]byte{{1}}}); err != nil {
		t.Fatalf("honest answer for chunk 1 rejected: %v", err)
	}
	if err := section_check(section_path(0), 1, &Response_Tree_Section_Struct{Keys: [][]byte{left}}); err == nil {
		t.Fatal("key/value count mismatch accepted")
	}
	if err := section_check(section_path(0), 0, &foreign); err != nil {
		t.Fatalf("a whole-tree request (path 0) must accept any key: %v", err)
	}
	// a section equal to the key's own hash prefix: all 64 path bits match, so only the length check stands
	// between a 65-bit path and an out-of-range read of the 8-byte section
	h := blake2s.Sum256(left)
	if err := section_check(h[:8], 64, &ok); err != nil {
		t.Fatalf("key inside its own 64-bit section rejected: %v", err)
	}
	if err := section_check(h[:8], 65, &ok); err == nil {
		t.Fatal("a path longer than the section bytes was accepted")
	}
}

// The prefill must leave topo.map byte-for-byte as the original per-record loop does, through the chain's real
// Topo_store (blockchain/storetopo.go), including records past the end that were there before and a batch boundary.
func TestBootstrapTopoPrefillMatchesLoop(t *testing.T) {
	defer func(v bool) { BOOTSTRAP_PREFILL = v }(BOOTSTRAP_PREFILL)
	for _, last := range []int64{1, 1000, prefill_batch + 7} {
		var a, b blockchain.Blockchain
		da, db := t.TempDir(), t.TempDir()
		if err := a.Store.Topo_store.Open(da); err != nil {
			t.Fatal(err)
		}
		if err := b.Store.Topo_store.Open(db); err != nil {
			t.Fatal(err)
		}
		var junk [32]byte
		junk[0] = 9
		for _, s := range []topo_store{&a.Store.Topo_store, &b.Store.Topo_store} { // pre-existing records, incl. past last
			s.Write(last+3, junk, 5, 77)
			s.Write(0, junk, 5, 1)
		}
		BOOTSTRAP_PREFILL = false
		if write_bootstrap_topo(&a.Store.Topo_store, filepath.Join(da, "topo.map"), last, 123) {
			t.Fatal("prefill ran while disabled")
		}
		BOOTSTRAP_PREFILL = true
		if !write_bootstrap_topo(&b.Store.Topo_store, filepath.Join(db, "topo.map"), last, 123) {
			t.Fatal("prefill fell back on a healthy store")
		}
		a.Store.Topo_store.Sync()
		b.Store.Topo_store.Sync()
		fa, _ := os.ReadFile(filepath.Join(da, "topo.map"))
		fb, _ := os.ReadFile(filepath.Join(db, "topo.map"))
		if len(fa) == 0 || !bytes.Equal(fa, fb) {
			t.Fatalf("last=%d: prefilled topo.map (%d bytes) differs from the per-record loop's (%d bytes)", last, len(fb), len(fa))
		}
		if r, err := b.Store.Topo_store.Read(last); err != nil || r.State_Version != 123 || r.IsClean() {
			t.Fatalf("last record %+v %v", r, err)
		}
	}
}

// a wrong path (or a store that does not read back what was written) must fall back to the loop, not trust the file
func TestBootstrapTopoPrefillFallsBack(t *testing.T) {
	defer func(v bool) { BOOTSTRAP_PREFILL = v }(BOOTSTRAP_PREFILL)
	var a blockchain.Blockchain
	d := t.TempDir()
	if err := a.Store.Topo_store.Open(d); err != nil {
		t.Fatal(err)
	}
	BOOTSTRAP_PREFILL = true
	other := filepath.Join(t.TempDir(), "topo.map")
	os.WriteFile(other, nil, 0600)
	if write_bootstrap_topo(&a.Store.Topo_store, other, 50, 9) {
		t.Fatal("prefill of a different file was trusted")
	}
	if write_bootstrap_topo(&a.Store.Topo_store, filepath.Join(d, "missing", "topo.map"), 50, 9) {
		t.Fatal("prefill of a missing file was trusted")
	}
	for i := int64(0); i <= 50; i++ {
		if r, err := a.Store.Topo_store.Read(i); err != nil || r.State_Version != 9 {
			t.Fatalf("record %d not written by the fallback loop: %+v %v", i, r, err)
		}
	}
}

// The real in-flight count, measured: an outer pipeline at depth d refills before its process step, so while a nested
// pipeline (a huge SC tree) runs inside that step the outer one has d requests out. Together they must stay at
// MAX_HEAVY_PER_CONNECTION-1, leaving a slot for an INV-triggered GetObject (verifier SYNC-2).
func TestBootstrapDepthWithinPeerCap(t *testing.T) {
	if nested_depth(1) != 1 {
		t.Fatalf("nested_depth(1) = %d: depth 1 must be one request at a time", nested_depth(1))
	}
	for d := 1; d <= BOOTSTRAP_DEPTH_MAX; d++ {
		if d+nested_depth(d) > MAX_HEAVY_PER_CONNECTION-1 { // the bound itself, independent of timing
			t.Fatalf("depth %d: outer %d + nested %d leaves no slot below the cap of %d", d, d, nested_depth(d), MAX_HEAVY_PER_CONNECTION)
		}
		var maxin int32
		fetch := fake_sections(2*time.Millisecond, &maxin, -1)
		req := func(i int) Request_Tree_Section_Struct {
			return Request_Tree_Section_Struct{TreeName: []byte(fmt.Sprint(i))}
		}
		err := fetch_sections_ordered(3*d+3, d, req, fetch, func(i int, r *Response_Tree_Section_Struct) error {
			if i == 1 { // a huge SC tree: nested pipeline inside the outer process step
				return fetch_sections_ordered(4*d+4, nested_depth(d), req, fetch, func(int, *Response_Tree_Section_Struct) error { return nil })
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if maxin > MAX_HEAVY_PER_CONNECTION-1 || nested_depth(d) < 1 {
			t.Fatalf("depth %d: %d requests in flight at once, cap %d leaves no slot for GetObject", d, maxin, MAX_HEAVY_PER_CONNECTION)
		}
	}
	if BOOTSTRAP_DEPTH < 1 || BOOTSTRAP_DEPTH > BOOTSTRAP_DEPTH_MAX {
		t.Fatalf("BOOTSTRAP_DEPTH %d out of range", BOOTSTRAP_DEPTH)
	}
}

// After a bootstrap error the next bootstraps run at depth 1 until BOOTSTRAP_RECOVER_SECTIONS sections succeeded
// (verifier SYNC-1).
func TestBootstrapFallsBackToDepth1AfterFailure(t *testing.T) {
	defer bootstrap_recover.Store(0)
	bootstrap_recover.Store(0)
	if bootstrap_depth() != BOOTSTRAP_DEPTH {
		t.Fatalf("healthy depth %d, want %d", bootstrap_depth(), BOOTSTRAP_DEPTH)
	}
	bootstrap_failed()
	if bootstrap_depth() != 1 {
		t.Fatalf("depth %d right after a failure, want 1", bootstrap_depth())
	}
	for i := 0; i < BOOTSTRAP_RECOVER_SECTIONS-1; i++ {
		bootstrap_section_ok()
	}
	if bootstrap_depth() != 1 {
		t.Fatal("depth restored before BOOTSTRAP_RECOVER_SECTIONS successes")
	}
	bootstrap_section_ok()
	if bootstrap_depth() != BOOTSTRAP_DEPTH {
		t.Fatalf("depth %d after recovery, want %d", bootstrap_depth(), BOOTSTRAP_DEPTH)
	}
	bootstrap_section_ok() // never below zero
	if bootstrap_recover.Load() != 0 {
		t.Fatalf("recover counter %d", bootstrap_recover.Load())
	}
}

// A request issued behind k others gets (k+1) base timeouts: on a bandwidth-limited link it waits for their answers
// first, which is not the peer's fault (verifier SYNC-1).
func TestPipelinedTimeoutCoversQueue(t *testing.T) {
	var mu sync.Mutex
	seen := map[int]bool{}
	err := fetch_sections_ordered(20, 4, func(i int) Request_Tree_Section_Struct { return Request_Tree_Section_Struct{} },
		func(r Request_Tree_Section_Struct, queued int) (Response_Tree_Section_Struct, error) {
			mu.Lock()
			seen[queued] = true
			mu.Unlock()
			time.Sleep(time.Millisecond)
			return Response_Tree_Section_Struct{}, nil
		}, func(int, *Response_Tree_Section_Struct) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	for q := range seen {
		if q < 0 || q > 3 {
			t.Fatalf("queued %d with depth 4", q)
		}
	}
	if !seen[0] || !seen[3] {
		t.Fatalf("queue positions seen %v, want 0 and 3", seen)
	}
	base := call_timeout("Peer.TreeSection")
	if pipelined_timeout("Peer.TreeSection", 0) != base || pipelined_timeout("Peer.TreeSection", 3) != 4*base {
		t.Fatalf("pipelined timeouts %s / %s for base %s", pipelined_timeout("Peer.TreeSection", 0), pipelined_timeout("Peer.TreeSection", 3), base)
	}
}

// answers waiting to be processed above BOOTSTRAP_BUFFER_MAX stop new requests (the head of line is still fetched)
func TestFetchSectionsBufferBound(t *testing.T) {
	big := make([]byte, BOOTSTRAP_BUFFER_MAX/2+1)
	issued := 0
	var at0 int
	err := fetch_sections_ordered(8, 4, func(i int) Request_Tree_Section_Struct {
		issued++
		return Request_Tree_Section_Struct{TreeName: []byte(fmt.Sprint(i))}
	}, func(r Request_Tree_Section_Struct, _ int) (Response_Tree_Section_Struct, error) {
		if string(r.TreeName) == "0" {
			time.Sleep(50 * time.Millisecond) // sections 1-3 (2 big answers > the bound) arrive before the head
		}
		return Response_Tree_Section_Struct{Keys: [][]byte{big}, Values: [][]byte{nil}}, nil
	}, func(i int, _ *Response_Tree_Section_Struct) error {
		if i == 0 {
			at0 = issued
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if at0 != 4 {
		t.Fatalf("%d requests issued when the head was processed with >%d bytes buffered, want 4 (no refill)", at0, BOOTSTRAP_BUFFER_MAX)
	}
}

// apply_section refuses a foreign key before writing anything
func TestApplySectionRejectsBeforeWriting(t *testing.T) {
	left, right := key_in_section(false), key_in_section(true)
	puts := 0
	put := func(k, v []byte) { puts++ }
	if err := apply_section(section_path(0), 1, &Response_Tree_Section_Struct{Keys: [][]byte{left, right}, Values: [][]byte{{1}, {2}}}, put); err == nil || puts != 0 {
		t.Fatalf("foreign key: err %v, %d pairs written", err, puts)
	}
	if err := apply_section(section_path(0), 0, &Response_Tree_Section_Struct{Keys: [][]byte{left}}, put); err == nil || puts != 0 {
		t.Fatalf("unpaired key: err %v, %d pairs written", err, puts)
	}
	if err := apply_section(section_path(0), 1, &Response_Tree_Section_Struct{Keys: [][]byte{left}, Values: [][]byte{{1}}}, put); err != nil || puts != 1 {
		t.Fatalf("honest answer: err %v, %d pairs written", err, puts)
	}
}

// Every bootstrap write of a fetched section goes through the check (verifier SYNC-3: disabling a call site was not
// caught by any test). The call sites are pinned in the source; a weakened or removed check fails here.
func TestBootstrapCallSitesCheckSections(t *testing.T) {
	src, err := os.ReadFile("chain_bootstrap.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, site := range []string{
		"if err := apply_section(section_path(i), uint64(path_length), ts_response, func(k, v []byte) { balance_tree.Put(k, v) }); err != nil {\n\t\t\t\t\treturn err",
		"if err = section_check(section, uint64(path_length), &ts_response); err != nil {\n\t\t\t\tbootstrap_failed()\n\t\t\t\treturn err",
		"if err := apply_section(section, 0, sc_response, func(k, v []byte) { sc_data_tree.Put(k, v) }); err != nil {\n\t\t\t\t\t\treturn err",
		"return apply_section(section_path(int64(k)), uint64(sc_path_length), sc_ts_response, func(k, v []byte) { sc_data_tree.Put(k, v) })",
	} {
		if strings.Count(s, site) != 1 {
			t.Errorf("chain_bootstrap.go: checked call site missing or changed:\n%s", site)
		}
	}
	if n := strings.Count(s, ".Put("); n != 5 { // the 3 apply_section put closures, the SC_META key itself, the changeset
		t.Errorf("chain_bootstrap.go has %d .Put( calls, want 5: a write that bypasses apply_section?", n)
	}
}
