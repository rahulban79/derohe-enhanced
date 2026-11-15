// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package txpolicy

// r31 Part B dimension 4 (rft §7 B285): Add_TX_To_Pool's refusals are counted by reason at the admission wrapper.

import (
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/deroproject/derohe/transaction"
)

// every refusal text Add_TX_To_Pool returns (blockchain/blockchain.go) names a reason other than "other"; read from the
// source so an upstream rewording fails here instead of drifting into "other"
func TestR31PoolRefusalReasonsCoverAddTXToPool(t *testing.T) {
	src, err := os.ReadFile("../../blockchain/blockchain.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	i := strings.Index(s, "func (chain *Blockchain) Add_TX_To_Pool(")
	if i < 0 {
		t.Fatal("Add_TX_To_Pool not found")
	}
	body := s[i:]
	if j := strings.Index(body[1:], "\nfunc "); j > 0 {
		body = body[:j+1]
	}
	body = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(body, "") // the commented-out upstream checks
	body = regexp.MustCompile(`(?m)^\s*//.*$`).ReplaceAllString(body, "")
	rx := regexp.MustCompile(`(?:return|err =) fmt\.Errorf\("([^"]*)"`)
	verbs := regexp.MustCompile(`%[sdvx]`)
	n := 0
	for _, m := range rx.FindAllStringSubmatch(body, -1) {
		text := verbs.ReplaceAllString(m[1], "7")
		if r := pool_refusal_reason(errors.New(text)); r == pool_refusal_other {
			t.Errorf("Add_TX_To_Pool refusal %q counts as %q", m[1], r)
		}
		n++
	}
	if n < 14 {
		t.Fatalf("found only %d refusal texts in Add_TX_To_Pool", n)
	}
}

func TestR31PoolRefusedCountedByReason(t *testing.T) {
	cases := map[string]string{
		"TX rejected  Size 400000 byte Max possible 307200":                                     "oversize",
		"such transaction type cannot appear in mempool":                                        "type",
		"TX rejected  coinbase tx cannot appear in mempool":                                     "type",
		"TX doesn't solve Pow":                                                                  "registration",
		"TX ab rejected Already in MEMPOOL":                                                     "known",
		"TX ab rejected height(7) reference not found":                                          "reference",
		"TX  ab rejected due to low fees  provided fee 1 calculated fee 2":                      "low_fee",
		"Invalid SCID ID,it must not start with 0x80":                                           "scid",
		"Incoming TX ab nonce verification failed, err could not be verified":                   "nonce",
		"Incoming TX ab could not be verified, err transaction statement 0 verification failed": "proof",
		"TX ab rejected by pool by mempool":                                                     "pool",
		"leveldb: closed":                                                                       "other",
	}
	for _, attached := range []bool{false, true} {
		if attached {
			attach_test(t, new_fake_pool(), 1<<30)
		} else {
			Detach()
		}
		h := uint64(100)
		for text, want := range cases {
			before := map[string]uint64{}
			for r, c := range pool_refused {
				before[r] = c.Get()
			}
			tx, raw := forged(100, h, 3000)
			h++
			bad := errors.New(text)
			if err := Admit(raw, tx, func(*transaction.Transaction) error { return bad }); err != bad {
				t.Fatalf("attached=%v: Admit changed the verdict: %v", attached, err)
			}
			for r, c := range pool_refused {
				d := c.Get() - before[r]
				if (r == want && d != 1) || (r != want && d != 0) {
					t.Fatalf("attached=%v %q: reason %s moved by %d (want +1 on %s only)", attached, text, r, d, want)
				}
			}
		}
		// an admitted tx is not a refusal
		before := map[string]uint64{}
		for r, c := range pool_refused {
			before[r] = c.Get()
		}
		tx, raw := forged(100, h, 3000)
		if err := Admit(raw, tx, func(*transaction.Transaction) error { return nil }); err != nil {
			t.Fatalf("attached=%v: admit: %v", attached, err)
		}
		for r, c := range pool_refused {
			if c.Get() != before[r] {
				t.Fatalf("attached=%v: an admitted tx moved reason %s", attached, r)
			}
		}
		if attached {
			Detach()
		}
	}
	// every reason is a series from the start (eager registration), so /metrics shows zeros before the first event
	if len(pool_refused) != len(pool_refusal_reasons)+1 {
		t.Fatalf("%d series registered, want %d", len(pool_refused), len(pool_refusal_reasons)+1)
	}
	for _, r := range pool_refusal_reasons {
		if pool_refused[r.reason] == nil {
			t.Fatalf("reason %s not registered", r.reason)
		}
	}
}
