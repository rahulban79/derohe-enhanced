// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package txprecheck

// r28 (glue-global, docs-vs-code truth): the glue packages justify each policy by a consensus line ("refused at
// transaction_verify.go:263"). Nothing re-read those lines, and 4 of the 36 cited lines (in 5 places) had drifted when
// R28 checked them at 5a32c5b2: emission.go blockchain.go:964 -> a blank line, transaction_execute.go:250 -> '}',
// hf3.go chain_sync.go:397 (twice) -> a request-time store (the HF3 parity moved to p2p/hf3_parity.go), txpolicy.go
// transaction_verify.go:345 -> a blank line. This test reads every 'file.go:N' citation in the comments of glue/**/*.go (and the bare ':N' rule
// table of this package, which cites transaction_verify.go) and requires the cited line (or range) to still hold the
// statement it names. A new citation needs an entry below; an upstream line shift fails here instead of silently
// leaving a wrong anchor. Read-only: it opens the cited files and changes nothing.

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var r28_cited_file = map[string]string{
	"blockchain.go": "blockchain/blockchain.go", "transaction_execute.go": "blockchain/transaction_execute.go",
	"transaction_verify.go": "blockchain/transaction_verify.go", "miner_block.go": "blockchain/miner_block.go",
	"mempool.go": "blockchain/mempool/mempool.go", "hf3_parity.go": "p2p/hf3_parity.go",
	"chain_sync.go": "p2p/chain_sync.go", "proof_generate.go": "cryptography/crypto/proof_generate.go",
	"proof_innerproduct.go": "cryptography/crypto/proof_innerproduct.go", "transaction.go": "transaction/transaction.go",
}

// citation -> a fragment the cited line (or any line of a cited range) must contain
var r28_citation_holds = map[string]string{
	"blockchain.go:284": "Mempool.HouseKeeping", "blockchain.go:778": "unreferable history",
	"blockchain.go:786": "TX_VALIDITY_HEIGHT", "blockchain.go:911": "WriteTX(", "blockchain.go:958": "ReadBlockSnapshotVersion(bl.Tips[0])",
	"blockchain.go:1300": "already mined", "blockchain.go:1344": "Verify_Transaction_NonCoinbase_CheckNonce_Tips(",
	"transaction_execute.go:126-160": "CalcBlockReward", "transaction_execute.go:239": "ConstructElGamal(tx.Payloads[t].Statement.C[i], tx.Payloads[t].Statement.D)",
	"transaction_execute.go:244": "HF3_Affected_Txs", "hf3_parity.go:77": "t.Parity = (height > t.Height) == t.Tx_Parity",
	"transaction_verify.go:225-319": "tx.Version != 1", "transaction_verify.go:232": "HF3_Affected_Txs",
	"transaction_verify.go:236": "tips_string", "transaction_verify.go:336": "Roothash",
	"transaction_verify.go:466": "chain.cache_enabled", "mempool.go:106": "v.Tx.Height",
	"miner_block.go:247": "STARGATE_HE_MAX_BLOCK_SIZE", "miner_block.go:529-547": "Tx not found in pool or DB",
	"proof_generate.go:84": "func (p *Proof) Serialize(", "proof_innerproduct.go:42": "func (ip *InnerProduct) Serialize(",
	"transaction.go:321": `panic("unknown transaction type")`,
	// the rule table of txprecheck.go (bare ':N' = transaction_verify.go)
	"transaction_verify.go:140": "Proof.Parity()", "transaction_verify.go:218": "defer func()",
	"transaction_verify.go:226": "TX should be version 1", "transaction_verify.go:263": "Burn Value cannot be zero",
	"transaction_verify.go:273": "at least one payload", "transaction_verify.go:285": "does not contains base",
	"transaction_verify.go:290": "Roothash corrupted", "transaction_verify.go:297": "corrupted key pointers ringsize",
	"transaction_verify.go:301": "cannot be less than 2", "transaction_verify.go:305": "cannot be more than 128",
	"transaction_verify.go:309": "corrupted key pointers", "transaction_verify.go:319": "key_map does not contain ringsize members",
	"transaction_verify.go:419": "Statement.C[i]", "transaction_verify.go:421": "Statement.D",
}

var (
	r28_cite_rx = regexp.MustCompile(`\b([a-z_0-9]+\.go):(\d+)(?:-(\d+))?`)
	r28_bare_rx = regexp.MustCompile(`(?:^|[\s(,/]):(\d+)\b`)
)

func r28_lines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.Split(string(b), "\n")
}

// r28_citations returns {citation: "file:line where it is cited"} for every comment citation under glue/.
func r28_citations(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	files, _ := filepath.Glob(filepath.Join(root, "glue", "*", "*.go"))
	sort.Strings(files)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		rel, _ := filepath.Rel(root, f)
		table := false // inside txprecheck.go's rule table ("Rules, with the consensus line ..." up to "The decoder")
		for n := 1; sc.Scan(); n++ {
			l := strings.TrimSpace(sc.Text())
			if !strings.HasPrefix(l, "//") {
				continue
			}
			if strings.HasSuffix(rel, "txprecheck.go") {
				if strings.Contains(l, "Rules, with the consensus line") {
					table = true
				} else if strings.Contains(l, "The decoder") {
					table = false
				}
			}
			at := fmt.Sprintf("%s:%d", rel, n)
			for _, m := range r28_cite_rx.FindAllStringSubmatch(l, -1) {
				if _, known := r28_cited_file[m[1]]; !known {
					continue
				}
				c := m[1] + ":" + m[2]
				if m[3] != "" {
					c += "-" + m[3]
				}
				out[c] = at
			}
			if table { // the rule table: a bare ':N' cites transaction_verify.go
				rest := r28_cite_rx.ReplaceAllString(l, "")
				for _, m := range r28_bare_rx.FindAllStringSubmatch(rest, -1) {
					out["transaction_verify.go:"+m[1]] = at
				}
			}
		}
		fh.Close()
	}
	return out
}

func TestR28ConsensusCitationsHold(t *testing.T) {
	root := filepath.Join("..", "..")
	cites := r28_citations(t, root)
	if len(cites) < 30 {
		t.Fatalf("only %d citations found: the scanner is broken", len(cites))
	}
	var bad []string
	for c, at := range cites {
		frag, ok := r28_citation_holds[c]
		if !ok {
			bad = append(bad, fmt.Sprintf("%s cites %s: no expectation (add one to r28_citation_holds)", at, c))
			continue
		}
		name, span, _ := strings.Cut(c, ":")
		lo, hi := span, span
		if a, b, isRange := strings.Cut(span, "-"); isRange {
			lo, hi = a, b
		}
		from, _ := strconv.Atoi(lo)
		to, _ := strconv.Atoi(hi)
		lines := r28_lines(t, filepath.Join(root, r28_cited_file[name]))
		found := false
		for i := from; i <= to && i <= len(lines); i++ {
			found = found || strings.Contains(lines[i-1], frag)
		}
		if !found {
			got := ""
			if from <= len(lines) {
				got = strings.TrimSpace(lines[from-1])
			}
			bad = append(bad, fmt.Sprintf("%s cites %s for %q, the line reads %q (stale citation)", at, c, frag, got))
		}
	}
	for c := range r28_citation_holds { // an expectation nothing cites any more is dead weight
		if _, ok := cites[c]; !ok {
			bad = append(bad, fmt.Sprintf("expectation %s: no glue comment cites it", c))
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatalf("%d citation problems:\n%s", len(bad), strings.Join(bad, "\n"))
	}
	t.Logf("%d consensus citations hold", len(cites))
}
