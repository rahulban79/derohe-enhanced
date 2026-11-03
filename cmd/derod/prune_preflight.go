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

// Round 21 (storageops): a pre-flight for --prune-history. blockchain.Prune_Blockchain (a consensus-listed package,
// so it is not changed here) rewrites the balance tree into <datadir>/balances_new, then deletes blocks and the old
// tree and renames the new one into place. Two of its failure modes destroy the node's state:
//   - prune_history.go:96-99: an error from rewrite_graviton_store is only LOGGED; the function then still deletes the
//     old blocks, RemoveAll()s the old balances and renames the partial balances_new over it. Running out of disk
//     during the rewrite (it needs room for a second tree) is the obvious way to get that error.
//   - rewrite_graviton_store opens balances_new with graviton.NewDiskStore, which APPENDS to an existing store, so a
//     balances_new left by an interrupted earlier prune is silently extended rather than started fresh.
// The pre-flight refuses both before anything is touched. It cannot make the swap itself atomic (that is inside
// Prune_Blockchain): take a copy first (an APFS `cp -c -R` clone of the datadir costs ~100 s and no space).

import (
	"fmt"
	"os"
	"path/filepath"
)

const PRUNE_FREE_MARGIN = 1 << 30 // on top of a full second copy of the balance tree

// prune_preflight: free and dirsize are injected so the rules are unit-tested without a 9 GB datadir.
func prune_preflight(datadir string, free func(string) uint64, dirsize func(string) int64) error {
	// r22: Lstat, not Stat. A dangling symlink named balances_new reads as absent through Stat, and the rewrite then
	// fails to create its store there; Prune_Blockchain only logs that error and deletes the old tree anyway.
	if _, err := os.Lstat(filepath.Join(datadir, "balances_new")); err == nil {
		return fmt.Errorf("%s exists (left by an interrupted prune?): the rewrite would append to it; move it away first",
			filepath.Join(datadir, "balances_new"))
	}
	need := uint64(dirsize(filepath.Join(datadir, "balances"))) + PRUNE_FREE_MARGIN
	if have := free(datadir); have < need {
		return fmt.Errorf("pruning needs %d bytes free for the rewritten balance tree, %d available: a rewrite that runs "+
			"out of disk is ignored by Prune_Blockchain, which then deletes the old tree", need, have)
	}
	return nil
}
