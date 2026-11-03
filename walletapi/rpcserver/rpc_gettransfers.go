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

package rpcserver

import (
	"context"
	"fmt"
	"runtime/debug"

	"github.com/deroproject/derohe/rpc"
)

func GetTransfers(ctx context.Context, p rpc.Get_Transfers_Params) (result rpc.Get_Transfers_Result, err error) {
	defer func() { // safety so if anything wrong happens, we return error
		if r := recover(); r != nil {
			err = fmt.Errorf("panic occured. stack trace %s", debug.Stack())
		}
	}()

	w := FromContext(ctx)

	result.Entries = w.wallet.Show_Transfers(p.SCID, p.Coinbase, p.In, p.Out, p.Min_Height, p.Max_Height, p.Sender, p.Receiver, p.DestinationPort, p.SourcePort)

	return result, nil
}

// GetTransfersPaged_Params extends GetTransfers with paging (wallet-local
// type: rpc/ is frozen). All GetTransfers filters apply first.
type GetTransfersPaged_Params struct {
	rpc.Get_Transfers_Params
	Offset      uint64 `json:"offset"`       // entries to skip after filtering
	Limit       uint64 `json:"limit"`        // 0 = GetTransfersPagedDefault, capped at GetTransfersPagedMax
	NewestFirst bool   `json:"newest_first"` // page from the newest entry backwards
}

type GetTransfersPaged_Result struct {
	Entries []rpc.Entry `json:"entries"`
	Total   uint64      `json:"total"`  // matching entries before paging
	Offset  uint64      `json:"offset"` // echo of the offset used
	More    bool        `json:"more"`   // further pages exist
}

const GetTransfersPagedDefault = 100
const GetTransfersPagedMax = 10000

// GetTransfersPaged returns one page of the filtered transfer history, so a
// long-lived (e.g. mining) wallet with tens of thousands of entries does not
// have to ship its whole history in one JSON response.
func GetTransfersPaged(ctx context.Context, p GetTransfersPaged_Params) (result GetTransfersPaged_Result, err error) {
	defer func() { // safety so if anything wrong happens, we return error
		if r := recover(); r != nil {
			err = fmt.Errorf("panic occured. stack trace %s", debug.Stack())
		}
	}()

	w := FromContext(ctx)
	all := w.wallet.Show_Transfers(p.SCID, p.Coinbase, p.In, p.Out, p.Min_Height, p.Max_Height, p.Sender, p.Receiver, p.DestinationPort, p.SourcePort)
	result.Entries, result.Total, result.More = pageEntries(all, p.Offset, p.Limit, p.NewestFirst)
	result.Offset = p.Offset
	return result, nil
}

// pageEntries cuts one page out of entries (oldest first unless newest_first)
func pageEntries(all []rpc.Entry, offset, limit uint64, newest_first bool) (page []rpc.Entry, total uint64, more bool) {
	total = uint64(len(all))
	if limit == 0 {
		limit = GetTransfersPagedDefault
	}
	if limit > GetTransfersPagedMax {
		limit = GetTransfersPagedMax
	}
	page = []rpc.Entry{}
	if offset >= total {
		return page, total, false
	}
	end := offset + limit
	if end > total || end < offset { // end < offset: overflow
		end = total
	}
	if newest_first {
		for i := offset; i < end; i++ {
			page = append(page, all[total-1-i])
		}
	} else {
		page = append(page, all[offset:end]...)
	}
	return page, total, end < total
}
