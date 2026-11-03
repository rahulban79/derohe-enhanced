// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package rpc

// r24 (verify-txpool): TemplateTxs covers exactly the templates Accept_new_block can still find.

import (
	"os"
	"strings"
	"testing"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/cryptography/crypto"
)

func reset_template_txs() {
	template_txs.Lock()
	template_txs.q, template_txs.ref, template_txs.snap = nil, nil, nil
	template_txs.Unlock()
}

func th(i int) crypto.Hash { var h crypto.Hash; h[0], h[1], h[2] = byte(i), byte(i>>8), 0xAB; return h }

func TestR24NoteTemplateBoundAndDedupe(t *testing.T) {
	reset_template_txs()
	t.Cleanup(reset_template_txs)
	first := &block.Block{Timestamp: 1, Tx_hashes: []crypto.Hash{th(0), th(1)}}
	NoteTemplate(first)
	NoteTemplate(first) // served again from the 100 ms cache
	if n := len(template_txs.q); n != 1 {
		t.Fatalf("a re-served template recorded %d times", n)
	}
	if s := TemplateTxs(); !s[th(0)] || !s[th(1)] || len(s) != 2 {
		t.Fatalf("protected set %v", s)
	}
	// th(1) is carried again by every later template: it must stay while any of them is kept
	for i := 0; i < TEMPLATE_KEEP; i++ {
		NoteTemplate(&block.Block{Timestamp: uint64(2 + i), Tx_hashes: []crypto.Hash{th(1), th(1000 + i)}})
	}
	s := TemplateTxs()
	if s[th(0)] {
		t.Fatalf("a template older than the %d Accept_new_block can find is still protected", TEMPLATE_KEEP)
	}
	if !s[th(1)] || !s[th(1000)] || !s[th(1000+TEMPLATE_KEEP-1)] {
		t.Fatalf("txs of kept templates lost protection")
	}
	if len(template_txs.q) != TEMPLATE_KEEP || len(s) != TEMPLATE_KEEP+1 {
		t.Fatalf("kept %d templates, %d txids", len(template_txs.q), len(s))
	}
}

func TestR24TemplatesNotedWhereHandedOut(t *testing.T) {
	for _, f := range []string{"websocket_getwork_server.go", "rpc_dero_getblocktemplate.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), "\tNoteTemplate(&bl) // r24 (verify-txpool)") {
			t.Fatalf("%s hands out templates without NoteTemplate", f)
		}
	}
}
