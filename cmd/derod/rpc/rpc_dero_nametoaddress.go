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

import "context"
import "golang.org/x/xerrors"
import "github.com/deroproject/graviton"
import "github.com/deroproject/derohe/cryptography/crypto"
import "github.com/deroproject/derohe/rpc"
import "github.com/deroproject/derohe/globals"
import "github.com/deroproject/derohe/dvm"
import "github.com/deroproject/derohe/metrics"

//import "github.com/deroproject/derosuite/blockchain"

func NameToAddress(ctx context.Context, p rpc.NameToAddress_Params) (result rpc.NameToAddress_Result, err error) {

	defer func() { // safety so if anything wrong happens, we return error
		if r := recover(); r != nil {
			err = rpc_internal_error(r)
		}
	}()

	topoheight := chain.Load_TOPO_HEIGHT()

	toporecord, err := chain.Store.Topo_store.Read(topoheight)
	if err != nil {
		panic(err) // r25 B86: store invariant (current state, fixed tree name), keeps ERROR + stack
	}
	ss, err := chain.Store.Balance_store.LoadSnapshot(toporecord.State_Version)
	if err != nil {
		panic(err) // r25 B86: store invariant (current state, fixed tree name), keeps ERROR + stack
	}

	var zerohash crypto.Hash
	zerohash[31] = 1
	treename := string(zerohash[:])

	tree, err := ss.GetTree(treename)
	if err != nil {
		panic(err) // r25 B86: store invariant (current state, fixed tree name), keeps ERROR + stack
	}

	var value_bytes []byte
	value_bytes, err = tree.Get(dvm.Variable{Type: dvm.String, ValueString: p.Name}.MarshalBinaryPanic())
	if err = name_lookup_error(p.Name, err); err == nil {

		var v dvm.Variable
		if err = v.UnmarshalBinary(value_bytes); err != nil {
			return
		}

		var addr string
		if addr, err = name_value_address(v.ValueString, globals.IsMainnet()); err != nil {
			return
		}
		result.Address = addr
		result.Name = p.Name
		result.Status = "OK"
	}
	return

}

// name_value_address turns a name-service value (the registrant's compressed key) into an address string (r25 B86:
// upstream wrote `addr, _ := NewAddressFromCompressedKeys(...)` and then tested the stale err of the unmarshal, so a
// value that is not a key dereferenced a nil address inside the recover: ERROR + stack, -32098).
func name_value_address(raw string, mainnet bool) (string, error) {
	addr, err := rpc.NewAddressFromCompressedKeys([]byte(raw))
	if err != nil {
		return "", refuse_input("NameToAddress", "name_value", err.Error())
	}
	addr.Mainnet = mainnet
	return addr.String(), nil
}

// name_lookup_error types the name-service tree's answer for a name (r26 B100): a name nobody registered was the raw
// graviton error "leaf not found", which jrpc2 sent as untyped -32098 (the code for errors of the operating
// environment), indistinguishable from a store fault. It is now -32032 "name not found: <name>" (NotFoundError, the
// r25 B80 class), counted in rpc_name_not_found_total. Any other store error is returned unchanged.
const NAME_ECHO_MAX = 64

func name_lookup_error(name string, err error) error {
	if err != nil && xerrors.Is(err, graviton.ErrNotFound) {
		metrics.Set.GetOrCreateCounter(`rpc_name_not_found_total`).Inc()
		if len(name) > NAME_ECHO_MAX { // the caller's own input, echoed back: bounded anyway
			name = name[:NAME_ECHO_MAX] + "..."
		}
		return &NotFoundError{What: "name", ID: name}
	}
	return err
}
