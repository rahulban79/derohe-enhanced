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

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrunePreflight(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "balances"), 0700)
	size := func(string) int64 { return 5 << 30 }
	plenty := func(string) uint64 { return 100 << 30 }
	if err := prune_preflight(dir, plenty, size); err != nil {
		t.Fatal("room and no leftover must pass:", err)
	}
	// not enough room for a second tree plus the margin: refused (Prune_Blockchain would delete the old tree)
	if err := prune_preflight(dir, func(string) uint64 { return 5<<30 + PRUNE_FREE_MARGIN - 1 }, size); err == nil || !strings.Contains(err.Error(), "free") {
		t.Fatal("low disk not refused:", err)
	}
	if err := prune_preflight(dir, func(string) uint64 { return 5<<30 + PRUNE_FREE_MARGIN }, size); err != nil {
		t.Fatal("exactly enough must pass:", err)
	}
	// the dirsize asked is the balance tree's
	var asked string
	prune_preflight(dir, plenty, func(p string) int64 { asked = p; return 0 })
	if asked != filepath.Join(dir, "balances") {
		t.Fatal("measured", asked)
	}
	// a leftover balances_new: refused (graviton would append to it)
	os.Mkdir(filepath.Join(dir, "balances_new"), 0700)
	if err := prune_preflight(dir, plenty, size); err == nil || !strings.Contains(err.Error(), "balances_new") {
		t.Fatal("leftover balances_new not refused:", err)
	}
}

// r22: a dangling symlink named balances_new is refused too (Stat followed it and saw nothing).
func TestPrunePreflightDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "balances"), 0700)
	if err := os.Symlink(filepath.Join(dir, "nowhere", "x"), filepath.Join(dir, "balances_new")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	plenty := func(string) uint64 { return 100 << 30 }
	if err := prune_preflight(dir, plenty, func(string) int64 { return 1 }); err == nil || !strings.Contains(err.Error(), "balances_new") {
		t.Fatal("dangling balances_new symlink not refused:", err)
	}
}
