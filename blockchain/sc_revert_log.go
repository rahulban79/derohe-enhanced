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

package blockchain

// Logging only. When an anonymous SC transaction fails, process_transaction_sc takes the
// "burn all the funds" branch with signer still the zero [33]byte; dvm.ErrorRevert then looks
// that account up, graviton answers "... keyhash <blake2s(33 zero bytes)> ..." (not found) and
// ErrorRevert panics. The recover in process_transaction_sc catches it with the named results
// already set (gas = tx.Fees(), err = the SC error), so the fee is kept and the burn value is
// never refunded — which is what the branch's comment promises. Every node that replays such a
// transaction takes the same path, so it is upstream behaviour, not a fault of this node.
//
// Nothing here may change that outcome: it is consensus-visible. This file only lets the
// recover recognise the case and log one line instead of an ERROR with a full stack.

import (
	"encoding/hex"
	"errors"
	"strings"

	"github.com/deroproject/graviton"
	"golang.org/x/crypto/blake2s"
)

// graviton keys a leaf by blake2s-256 of the key bytes (graviton/hash.go)
var zero_signer_keyhash = func() string {
	var zero [33]byte
	h := blake2s.Sum256(zero[:])
	return hex.EncodeToString(h[:])
}()

// is_zero_signer_revert reports whether a recovered panic value is graviton failing to find the
// all-zero signer, i.e. the anonymous-SC revert described above.
func is_zero_signer_revert(r interface{}) bool {
	err, ok := r.(error)
	if !ok || !errors.Is(err, graviton.ErrNotFound) {
		return false
	}
	// every graviton not-found error names the looked-up key as "keyhash <hex>" ("collision, keyhash
	// %x not found, ..." from a leaf, "left/right dead end at %d. keyhash %x" from an inner node);
	// the collision form's second hash is introduced as "keyhash in ram", so this matches only the
	// key that was looked up
	return strings.Contains(err.Error(), "keyhash "+zero_signer_keyhash)
}
