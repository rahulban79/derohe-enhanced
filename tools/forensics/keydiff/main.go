// Command keydiff is the R31 B111 set-diff helper (rft §7 B111 residual; R30 hypothesis record
// harness/runtime/r30_b111_premine.json): it compares the KEY SET of the balance tree of one state version with a set
// of registration-key digests and reports what is left on each side. COUNTS AND DIGESTS ONLY (rft §0.8.9 rule 13): a
// key never leaves this process; each one is reduced to SHA-256(33-byte key) before it is compared or printed, the
// same digest the genesis census writes into regkeys.bin (harness/forensics/genesis_r30.py, `regkeys.bin`).
//
// It is its own package (like ./tools/forensics/classstats) so the sealed datasets' decoder pins of ./tools/forensics
// do not move. graviton opens a store O_RDWR, so it refuses any directory not named by FORENSICS_STORE_COPY_OK (a
// copy outside the node's datadir; never the live store, rft §7 B111 S4).
//
//	keydiff -balances <COPY> -version N -regkeys <regkeys.bin> [-limit K]
//
// Output: one JSON object on stdout.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/graviton"
)

type result struct {
	OK                   bool        `json:"ok"`
	Error                string      `json:"error,omitempty"`
	Version              uint64      `json:"version"`
	Root                 string      `json:"root,omitempty"` // Load_Merkle_Hash: balance tree hash XOR SC meta tree hash
	BalanceKeys          int         `json:"balance_keys"`
	BalanceKeyLens       map[int]int `json:"balance_key_lens"`
	RegDigests           int         `json:"reg_digests"`
	RegDistinct          int         `json:"reg_distinct"`
	KeysInRegs           int         `json:"keys_in_regs"`
	KeysNotInRegs        int         `json:"keys_not_in_regs"`
	KeysNotInRegsDigests []string    `json:"keys_not_in_regs_digests"` // sha256 of each 33-byte key, sorted, at most -limit
	RegsNotInKeys        int         `json:"regs_not_in_keys"`
	KeySetSHA256         string      `json:"key_digest_set_sha256"` // sha256 of the sorted key digests, concatenated
}

// readRegs returns the distinct 32-byte digests of a regkeys.bin sidecar (a flat array of SHA-256 digests).
func readRegs(path string) (all int, set map[[32]byte]struct{}, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, nil, err
	}
	if len(b)%32 != 0 {
		return 0, nil, fmt.Errorf("%s: %d bytes is not a multiple of 32", path, len(b))
	}
	set = make(map[[32]byte]struct{}, len(b)/32)
	for i := 0; i < len(b); i += 32 {
		var d [32]byte
		copy(d[:], b[i:i+32])
		set[d] = struct{}{}
	}
	return len(b) / 32, set, nil
}

// diff compares the key digests with the registration digests. Pure.
func diff(keys [][32]byte, regs map[[32]byte]struct{}, limit int) (r result) {
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })
	h := sha256.New()
	seen := make(map[[32]byte]struct{}, len(keys))
	for _, k := range keys {
		h.Write(k[:])
		seen[k] = struct{}{}
		if _, ok := regs[k]; ok {
			r.KeysInRegs++
		} else {
			r.KeysNotInRegs++
			if len(r.KeysNotInRegsDigests) < limit {
				r.KeysNotInRegsDigests = append(r.KeysNotInRegsDigests, hex.EncodeToString(k[:]))
			}
		}
	}
	for d := range regs {
		if _, ok := seen[d]; !ok {
			r.RegsNotInKeys++
		}
	}
	r.BalanceKeys, r.RegDistinct = len(keys), len(regs)
	r.KeySetSHA256 = hex.EncodeToString(h.Sum(nil))
	return
}

func openCopy(dir string) (*graviton.Store, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(abs, "version_root.bin")); err != nil {
		return nil, fmt.Errorf("not a graviton store (no version_root.bin): %w", err)
	}
	if underLiveDatadir(abs) {
		return nil, fmt.Errorf("refused: %s is inside the node's datadir (~/dero-data): work on a copy outside it", abs)
	}
	if os.Getenv("FORENSICS_STORE_COPY_OK") != abs {
		return nil, fmt.Errorf("refused: FORENSICS_STORE_COPY_OK must name this exact copy (graviton opens O_RDWR)")
	}
	return graviton.NewDiskStore(abs)
}

// underLiveDatadir: r31 verify (d6 verifier) — the copy must be OUTSIDE the live node's datadir (rft §5: never write under
// ~/dero-data; graviton opens O_RDWR). Symlinks are resolved, so a link into the datadir is refused too.
func underLiveDatadir(abs string) bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return true // fail closed: without a home the datadir cannot be ruled out
	}
	live := filepath.Join(home, "dero-data")
	if r, err := filepath.EvalSymlinks(live); err == nil {
		live = r
	}
	real := abs
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		real = r
	}
	return real == live || strings.HasPrefix(real, live+string(filepath.Separator))
}

// keyDigests walks the balance tree of one snapshot (read-only) and returns SHA-256 of every key, plus the root.
func keyDigests(ss *graviton.Snapshot) (keys [][32]byte, lens map[int]int, root string, err error) {
	bt, err := ss.GetTree(config.BALANCE_TREE)
	if err != nil {
		return nil, nil, "", err
	}
	lens = map[int]int{}
	c := bt.Cursor()
	for k, _, e := c.First(); e == nil; k, _, e = c.Next() {
		lens[len(k)]++
		keys = append(keys, sha256.Sum256(k))
	}
	mt, err := ss.GetTree(config.SC_META)
	if err != nil {
		return nil, nil, "", err
	}
	bh, err := bt.Hash()
	if err != nil {
		return nil, nil, "", err
	}
	mh, err := mt.Hash()
	if err != nil {
		return nil, nil, "", err
	}
	var x [32]byte
	for i := range x {
		x[i] = bh[i] ^ mh[i]
	}
	return keys, lens, hex.EncodeToString(x[:]), nil
}

func run(balances string, version uint64, regkeys string, limit int) (r result) {
	defer func() {
		if p := recover(); p != nil {
			r = result{Version: version, Error: fmt.Sprintf("recovered panic: %v", p)}
		}
	}()
	all, regs, err := readRegs(regkeys)
	if err != nil {
		return result{Version: version, Error: err.Error()}
	}
	s, err := openCopy(balances)
	if err != nil {
		return result{Version: version, Error: err.Error()}
	}
	ss, err := s.LoadSnapshot(version)
	if err != nil {
		return result{Version: version, Error: err.Error()}
	}
	keys, lens, root, err := keyDigests(ss)
	if err != nil {
		return result{Version: version, Error: err.Error()}
	}
	r = diff(keys, regs, limit)
	r.OK, r.Version, r.Root, r.BalanceKeyLens, r.RegDigests = true, version, root, lens, all
	return
}

func main() {
	balances := flag.String("balances", "", "a COPY of a graviton balances directory (FORENSICS_STORE_COPY_OK)")
	version := flag.Uint64("version", 0, "state version")
	regkeys := flag.String("regkeys", "", "regkeys.bin: SHA-256 digests of registration keys")
	limit := flag.Int("limit", 16, "at most this many digests of keys not in the registration set")
	flag.Parse()
	r := run(*balances, *version, *regkeys, *limit)
	b, err := json.Marshal(r)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Stdout.Write(append(b, '\n'))
	if !r.OK {
		os.Exit(1)
	}
}
