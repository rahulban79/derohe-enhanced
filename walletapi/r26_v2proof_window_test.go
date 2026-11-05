package walletapi

// r26 (disclosure-cryptoinfl, backlog B32 residual CD25-5): the r24 V2 receiver-proof guard (r24_v2proof.go) indexes
// only the entries the wallet holds. A wallet with TrackRecentBlocks > 0 scans from daemon_topoheight -
// TrackRecentBlocks (daemon_communication.go synchistory_internal), so an earlier V2 transfer below that window is
// never stored, and a later transfer that repeats its ephemeral key E is not seen as a repeat.
//
// R26 decision (artifacts/dero-rft.md §7 B32): ACCEPTED RESIDUAL, documented and pinned here. The only wallet-local
// closure is to withhold every V2 receiver proof of a partial-history wallet (the guard cannot tell a repeat from a
// first use without the history), which removes receiver proofs for every such user to cover a payload-privacy-only
// leak that also needs the victim to hand the proof to the repeating sender. The complete fix binds E in the proof
// format (upstream, FORK-free but format-changing for every wallet). This test pins both sides, so a change in either
// direction (a mitigation that ships, or a guard that stops covering full-history wallets) fails it and the B32 row
// must be re-decided.

import (
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
)

func TestR26V2ProofGuardWindowResidualPinned(t *testing.T) {
	sk := r24scalar(t)
	E := new(bn256.G1).ScalarMult(crypto.G, r24scalar(t))
	V2 := transaction.ENCRYPTED_DEFAULT_PAYLOAD_CBOR_V2
	var zero crypto.Hash
	earlier, repeat := r24entry(sk, E, "tx-earlier", 10, V2), r24entry(sk, E, "tx-repeat", 5000, V2)

	// full history (TrackRecentBlocks 0, the default): the earlier entry is held, the repeat is withheld (control)
	full := r24wallet()
	full.InsertReplace(zero, earlier)
	full.InsertReplace(zero, repeat)
	for _, e := range r24stored(full, zero) {
		if !r24withheld(e) {
			t.Fatalf("full-history wallet: entry %s keeps a proof whose key repeats (the r24 guard regressed)", e.TXID)
		}
	}

	// partial history: the window starts above the earlier transfer, so it is never stored; the repeat keeps its proof
	part := r24wallet()
	part.account.TrackRecentBlocks = 1000
	part.InsertReplace(zero, repeat)
	s := r24stored(part, zero)
	if len(s) != 1 {
		t.Fatalf("stored %d entries", len(s))
	}
	if r24withheld(s[0]) {
		t.Fatalf("partial-history wallet now withholds the out-of-window repeat: the B32 residual changed, re-decide B32 (rft §7)")
	}
	if part.SetTrackRecentBlocks(-1) != 1000 {
		t.Fatalf("TrackRecentBlocks not read back")
	}
}
