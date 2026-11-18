package dvm

import (
	"encoding/json"
	"os"
	"testing"
)

// R33 GT-B29: the member tag vector shared with playbooks/gtlib.pool_tag (address -> the first 8 bytes of SHA3-256 of
// the 33-byte key, the contract's HEX(SUBSTR(SHA3256(SIGNER()), 0, 8))). The four test wallets have fixed keys
// (gtNew), so the vector is committed in testdata/r33_tagvec.json and checked here; harness/kat/test_gt_r33.py R33-9
// checks gtlib against the same file. GT_TAGVEC_OUT=<file> rewrites it (r33 close: the opt-in form was an orphan).
func TestR33TagVector(t *testing.T) {
	w := gtNew(t, "alice", "bob", "carol", "owner")
	v := map[string]string{}
	for _, n := range []string{"alice", "bob", "carol", "owner"} {
		v[w.addr[n].String()] = w.poolTag(n)
	}
	if out := os.Getenv("GT_TAGVEC_OUT"); out != "" {
		b, _ := json.MarshalIndent(v, "", " ")
		if err := os.WriteFile(out, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile("testdata/r33_tagvec.json")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	if len(want) != len(v) {
		t.Fatalf("vector has %d entries, the wallets %d", len(want), len(v))
	}
	for a, tag := range v {
		if want[a] != tag {
			t.Fatalf("tag of %s: %s, vector %q", a, tag, want[a])
		}
	}
}
