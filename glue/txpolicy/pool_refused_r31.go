// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package txpolicy

// r31 Part B dimension 4 (rft §7 B285, detector-signal-coverage): blockchain.Add_TX_To_Pool refuses a transaction with
// an error and, for two of its refusals, an ERROR line ("Huge TX", "coinbase tx cannot appear in mempool"), but no
// refusal was counted anywhere: a peer relaying oversized or unverifiable transactions showed only as log text. A counter inside blockchain/ is not a logger statement, so the consensus guard (S1) refuses it;
// the count lives here, at the one admission wrapper both callers use (p2p relay through txcanon.Admit, RPC
// SendRawTransaction through txprecheck.AdmitAt -> txcanon.Admit), around the add() that IS Add_TX_To_Pool.
//
// tx_pool_refused_total{reason}: one count per Add_TX_To_Pool call that returned an error, by the reason its text
// names. All reasons are registered at start, so every series reads 0 before its first event (the r29 lazy-counter
// lesson). A verdict shared by a concurrent admission of the same bytes (flight follower) or a known-invalid replay
// is not a new Add_TX_To_Pool call and is counted by tx_policy_shared_admissions_total / tx_policy_known_invalid_total.
// The text match reads only error strings: it changes no verdict.

import (
	"fmt"
	"regexp"

	"github.com/VictoriaMetrics/metrics"

	dmetrics "github.com/deroproject/derohe/metrics"
)

// pool_refusal_reasons: Add_TX_To_Pool's refusal texts (blockchain/blockchain.go func Add_TX_To_Pool), first match wins
var pool_refusal_reasons = []struct {
	reason string
	rx     *regexp.Regexp
}{
	{"oversize", regexp.MustCompile(`rejected\s+Size \d+ byte Max possible`)},
	{"type", regexp.MustCompile(`such transaction type cannot appear in mempool|coinbase tx cannot appear in mempool|premine tx not mineable`)},
	{"registration", regexp.MustCompile(`doesn't solve Pow|address already registered|registration for address is already pending`)},
	{"known", regexp.MustCompile(`rejected Already in MEMPOOL|rejected Already mined in some block`)},
	{"reference", regexp.MustCompile(`reference not found`)},
	{"low_fee", regexp.MustCompile(`rejected due to low fees`)},
	{"scid", regexp.MustCompile(`Invalid SCID ID`)},
	{"nonce", regexp.MustCompile(`nonce verification failed`)},
	{"proof", regexp.MustCompile(`could not be verified`)},
	{"pool", regexp.MustCompile(`rejected by pool by mempool`)},
}

const pool_refusal_other = "other" // a store read error or a text this table does not know

var pool_refused = func() map[string]*metrics.Counter {
	m := map[string]*metrics.Counter{}
	for _, r := range pool_refusal_reasons {
		m[r.reason] = dmetrics.Set.NewCounter(fmt.Sprintf(`tx_pool_refused_total{reason=%q}`, r.reason))
	}
	m[pool_refusal_other] = dmetrics.Set.NewCounter(fmt.Sprintf(`tx_pool_refused_total{reason=%q}`, pool_refusal_other))
	return m
}()

// pool_refusal_reason names the reason of one Add_TX_To_Pool error. Pure.
func pool_refusal_reason(err error) string {
	s := err.Error()
	for _, r := range pool_refusal_reasons {
		if r.rx.MatchString(s) {
			return r.reason
		}
	}
	return pool_refusal_other
}

// count_pool_refusal counts one Add_TX_To_Pool verdict (nil: admitted, not counted) and returns it unchanged.
func count_pool_refusal(err error) error {
	if err != nil {
		pool_refused[pool_refusal_reason(err)].Inc()
	}
	return err
}
