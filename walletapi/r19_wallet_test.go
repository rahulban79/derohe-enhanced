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

package walletapi

import (
	"bytes"
	"errors"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

const r19_seed = "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly"

// N5: atomic save keeps the wallet file present and 0600, keeps the previous
// version as .bak and leaves no temp files.
func Test_Save_Wallet_Atomic(t *testing.T) {
	dir := t.TempDir()
	fn := filepath.Join(dir, "w.db")
	w, err := Create_Encrypted_Wallet_From_Recovery_Words(fn, "QWER", r19_seed)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Save_Wallet(); err != nil {
		t.Fatal(err)
	}
	first, _ := ioutil.ReadFile(fn)
	w.SetRingSize(32) // changes content and saves
	if err = w.Save_Wallet(); err != nil {
		t.Fatal(err)
	}
	second, _ := ioutil.ReadFile(fn)
	bak, err := ioutil.ReadFile(fn + ".bak")
	if err != nil {
		t.Fatalf("no backup: %s", err)
	}
	if bytes.Equal(first, second) || len(second) == 0 {
		t.Fatalf("second save did not change the file")
	}
	if len(bak) == 0 {
		t.Fatalf("empty backup")
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(fn)
		if st.Mode().Perm() != 0600 {
			t.Fatalf("wallet mode %o, want 600", st.Mode().Perm())
		}
	}
	if m, _ := filepath.Glob(fn + ".tmp-*"); len(m) != 0 {
		t.Fatalf("temp files left behind: %v", m)
	}
	if _, err := Open_Encrypted_Wallet(fn, "QWER"); err != nil {
		t.Fatalf("saved wallet does not open: %s", err)
	}
}

// a failed write must leave the existing wallet untouched (the old code
// renamed it to .bak first, so a failed/crashed write left no wallet file)
func Test_Save_Wallet_Failure_Keeps_Old_File(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("needs POSIX directory permissions")
	}
	dir := t.TempDir()
	fn := filepath.Join(dir, "w.db")
	w, err := Create_Encrypted_Wallet_From_Recovery_Words(fn, "QWER", r19_seed)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Save_Wallet(); err != nil {
		t.Fatal(err)
	}
	before, _ := ioutil.ReadFile(fn)
	os.Chmod(dir, 0500) // temp file cannot be created
	defer os.Chmod(dir, 0700)
	if err = w.Save_Wallet(); err == nil {
		t.Fatalf("save into read-only directory reported success")
	}
	after, err := ioutil.ReadFile(fn)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("wallet file damaged by failed save: err=%v", err)
	}
}

func Test_Open_Removes_Stale_Temp(t *testing.T) {
	dir := t.TempDir()
	fn := filepath.Join(dir, "w.db")
	w, _ := Create_Encrypted_Wallet_From_Recovery_Words(fn, "QWER", r19_seed)
	w.Save_Wallet()
	ioutil.WriteFile(fn+".tmp-123", []byte("partial"), 0600)
	old := time.Now().Add(-time.Hour)
	os.Chtimes(fn+".tmp-123", old, old)
	ioutil.WriteFile(fn+".tmp-fresh", []byte("a save in progress"), 0600) // too young to be stale
	if _, err := Open_Encrypted_Wallet(fn, "QWER"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fn + ".tmp-123"); err == nil {
		t.Fatal("stale temp not removed")
	}
	if _, err := os.Stat(fn + ".tmp-fresh"); err != nil {
		t.Fatal("a temp file of a save that may be in progress was removed")
	}
}

// W3: a wallet name with glob metacharacters still finds its own temp files and never touches another file
func Test_Stale_Temp_Glob_Metachars(t *testing.T) {
	dir := t.TempDir()
	fn := filepath.Join(dir, "w[1].db")
	other := filepath.Join(dir, "w1.db.tmp-x") // what the glob "w[1].db.tmp-*" matched
	mine := fn + ".tmp-x"
	for _, f := range []string{other, mine} {
		ioutil.WriteFile(f, []byte("x"), 0600)
	}
	removeStaleTempFilesAt(fn, time.Now().Add(time.Hour))
	if _, err := os.Stat(mine); err == nil {
		t.Fatal("the wallet's own stale temp file was not removed")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("another file was removed")
	}
}

// W3: a failure after the temp file is written (the rename) leaves the original wallet intact and no temp behind
func Test_Save_Wallet_Rename_Failure_Keeps_Old_File(t *testing.T) {
	dir := t.TempDir()
	fn := filepath.Join(dir, "w.db")
	ioutil.WriteFile(fn, []byte("old wallet"), 0600)
	err := writeWalletFileAtomicWith(fn, []byte("new wallet"), func(from, to string) error {
		if b, _ := ioutil.ReadFile(from); string(b) != "new wallet" {
			t.Errorf("temp file holds %q before the rename", b)
		}
		return errors.New("injected rename failure")
	})
	if err == nil {
		t.Fatal("failed rename reported success")
	}
	if b, _ := ioutil.ReadFile(fn); string(b) != "old wallet" {
		t.Fatalf("wallet after failed save: %q", b)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "w.db.tmp-*")); len(m) != 0 {
		t.Fatalf("temp file left behind: %v", m)
	}
}

// STOR-2: the backup fallback must never truncate the live wallet through a .bak hard link
func Test_Backup_Copy_Never_Truncates_Linked_Wallet(t *testing.T) {
	dir := t.TempDir()
	fn := filepath.Join(dir, "w.db")
	ioutil.WriteFile(fn, []byte("live wallet"), 0600)
	if err := os.Link(fn, fn+".bak"); err != nil {
		t.Skip("no hard links:", err)
	}
	copyFileReplace(fn, fn+".bak") // .bak is the live inode: an O_TRUNC write would empty the wallet
	if b, _ := ioutil.ReadFile(fn); string(b) != "live wallet" {
		t.Fatalf("live wallet now %q", b)
	}
	if b, _ := ioutil.ReadFile(fn + ".bak"); string(b) != "live wallet" {
		t.Fatalf("backup %q", b)
	}
	a, _ := os.Stat(fn)
	b, _ := os.Stat(fn + ".bak")
	if os.SameFile(a, b) { // written in place through the link: a crash mid-write would have truncated the wallet
		t.Fatal("backup still shares the live wallet's inode: it was written in place")
	}
}

// Create_Encrypted_Wallet_Random used to return before wiring the disk
// back-pointer, so the wallet was never auto-saved
func Test_Create_Random_Wires_Disk(t *testing.T) {
	fn := filepath.Join(t.TempDir(), "r.db")
	w, err := Create_Encrypted_Wallet_Random(fn, "QWER")
	if err != nil {
		t.Fatal(err)
	}
	if w.Wallet_Memory.wallet_disk != w {
		t.Fatalf("wallet_disk back-pointer not set")
	}
	w.SetRingSize(16) // save_if_disk path
	if _, err := os.Stat(fn); err != nil {
		t.Fatalf("auto-save did not write the wallet: %s", err)
	}
}

// Close stops sync_loop (Quit was never closed and "break" left only the
// select), refuses later saves and scrubs the password-derived keys.
func Test_Close_Stops_SyncLoop_And_Scrubs(t *testing.T) {
	fn := filepath.Join(t.TempDir(), "c.db")
	w, err := Create_Encrypted_Wallet_From_Recovery_Words(fn, "QWER", r19_seed)
	if err != nil {
		t.Fatal(err)
	}
	w.Close_Encrypted_Wallet()
	var passes int32
	sync_pass_hook = func() { atomic.AddInt32(&passes, 1) }
	defer func() { sync_pass_hook = nil }()
	done := make(chan struct{})
	go func() { w.Wallet_Memory.sync_loop(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("sync_loop did not exit after close")
	}
	if n := atomic.LoadInt32(&passes); n != 0 { // the Quit check must come before any work on a closed wallet
		t.Fatalf("sync_loop ran %d pass(es) after close", n)
	}
	if err := w.Save_Wallet(); err == nil {
		t.Fatalf("save after close succeeded")
	}
	for _, b := range [][]byte{w.Wallet_Memory.pbkdf2_password, w.Wallet_Memory.master_password} {
		for _, c := range b {
			if c != 0 {
				t.Fatalf("key material not scrubbed")
			}
		}
	}
	if _, err := Open_Encrypted_Wallet(fn, "QWER"); err != nil {
		t.Fatalf("final save broken: %s", err)
	}
}

func Test_Sync_Run_State(t *testing.T) {
	var s walletSyncState
	k := syncKey{topo: 7}
	if active, _ := s.markDone(k, true); active {
		t.Fatalf("markDone active without a run")
	}
	s.begin()
	if s.isDone(k) {
		t.Fatalf("fresh run already done")
	}
	s.markDone(k, false)
	if !s.isDone(k) {
		t.Fatalf("block not recorded")
	}
	s.markDone(syncKey{topo: 8}, true)
	if !s.end() {
		t.Fatalf("run with entries not dirty")
	}
	if s.isDone(k) {
		t.Fatalf("state leaked past end of run")
	}
	s.putDecoded("x", 5)
	if v, ok := s.getDecoded("x"); !ok || v != 5 {
		t.Fatalf("decode cache miss")
	}
}

func Test_Decode_Cache_Same_Result(t *testing.T) {
	w, err := Create_Encrypted_Wallet_From_Recovery_Words_Memory("QWER", r19_seed)
	if err != nil {
		t.Fatal(err)
	}
	pub := w.account.Keys.Public.G1()
	for _, v := range []uint64{0, 1, 777777} {
		// ElGamal(v): Left = v*G + r*Pub, Right = r*G (r = 3)
		el := elgamalOf(pub, v)
		a := w.DecodeEncryptedBalance_Memory(el, 0)
		b := w.DecodeEncryptedBalance_Memory(el, 0) // cached
		if a != v || b != v {
			t.Fatalf("value %d decoded %d then %d", v, a, b)
		}
	}
}

func Test_TransferMatches(t *testing.T) {
	e := rpc.Entry{Sender: "a", Destination: "b", DestinationPort: 3, SourcePort: 4}
	cases := []struct {
		s, r   string
		dp, sp uint64
		want   bool
	}{{"", "", 0, 0, true}, {"a", "b", 3, 4, true}, {"x", "", 0, 0, false}, {"", "x", 0, 0, false}, {"", "", 9, 0, false}, {"", "", 0, 9, false}}
	for _, c := range cases {
		if got := transferMatches(&e, c.s, c.r, c.dp, c.sp); got != c.want {
			t.Fatalf("%+v: got %v", c, got)
		}
	}
}

func elgamalOf(pub *bn256.G1, v uint64) *crypto.ElGamal {
	r := big.NewInt(3)
	left := new(bn256.G1).Add(new(bn256.G1).ScalarMult(crypto.G, new(big.Int).SetUint64(v)), new(bn256.G1).ScalarMult(pub, r))
	return crypto.ConstructElGamal(left, new(bn256.G1).ScalarMult(crypto.G, r))
}

// GetTransfers' sender/receiver/port filters reach Show_Transfers
func Test_Show_Transfers_Filters(t *testing.T) {
	w, err := Create_Encrypted_Wallet_From_Recovery_Words_Memory("QWER", r19_seed)
	if err != nil {
		t.Fatal(err)
	}
	var zero crypto.Hash
	w.InsertReplace(zero, rpc.Entry{TopoHeight: 1, Height: 1, Incoming: true, Sender: "alice", DestinationPort: 7})
	w.InsertReplace(zero, rpc.Entry{TopoHeight: 2, Height: 2, Incoming: true, Sender: "bob", DestinationPort: 8})
	if got := w.Show_Transfers(zero, true, true, true, 0, 0, "", "", 0, 0); len(got) != 2 {
		t.Fatalf("unfiltered: %d entries", len(got))
	}
	if got := w.Show_Transfers(zero, true, true, true, 0, 0, "bob", "", 0, 0); len(got) != 1 || got[0].Sender != "bob" {
		t.Fatalf("sender filter: %+v", got)
	}
	if got := w.Show_Transfers(zero, true, true, true, 0, 0, "", "", 7, 0); len(got) != 1 || got[0].DestinationPort != 7 {
		t.Fatalf("dstport filter: %+v", got)
	}
}
