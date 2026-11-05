// Command a2 is the R26 (a2) forensic tool (artifacts/dero-rft.md §0.8.4 option (a2), §7 B95/B76, §8 forensics-data).
//
//	a2 fetch-state --peer-file F --peer src-N --datadir D --topo T --expect-blid H [--depth 50] [--rate 2] --out S
//	a2 replay      --datadir D --plan P --blocks DIR --txs DIR --to T --roots R --out S
//	a2 roots       --datadir D --from A --to B
//
// fetch-state is a read-only TreeSection client: it opens ONE outgoing p2p session to ONE archival source, asks it
// for the changeset of topos T-depth+1..T (Peer.ChangeSet, p2p/rpc_changeset.go) and for the balance tree, the SC
// meta tree and every SC tree at topo T-depth+1 (Peer.TreeSection, p2p/rpc_treesection.go:35-43), exactly the
// requests derod's own fastsync makes (p2p/chain_bootstrap.go:53-339) but at a chosen historical topo instead of the
// peer's height. It writes them into a NEW datadir outside the live store, the same way bootstrap_chain does. The
// state it writes is EXT (the source's claim) until `replay` ends at our own treehash (the end-state check).
//
// replay opens that datadir with the node's own blockchain package and feeds our RAW blocks (forensics/r25
// headerchain, content-addressed blobs) and RAW tx bodies one topo at a time to Add_Complete_Block, the single
// entry point every block takes (blockchain/blockchain.go:376). Every check runs exactly as in derod: PoW,
// difficulty, tx verification and execution, the HF3 exemption table. After every block it records the node's
// own Load_Merkle_Hash (blockchain/store.go:297) of the new state version: the DERIVED pre/post state roots.
//
// The tool never imports or changes consensus code paths; it calls them. It never dials anything but the one
// endpoint named in a private peer file, never listens, never opens a datadir it did not create (env guard), and
// prints only the source's pseudonym.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// datadirGuard refuses a datadir that is not an absolute, explicitly confirmed path outside every node store.
// Rules (rft §5): never write under ~/dero-data; graviton opens O_RDWR, so a wrong path could damage a node.
//   - the path must be absolute and clean;
//   - no path component may be "dero-data" or start with "dero-data" (the live store and its siblings);
//   - FORENSICS_A2_DATADIR_OK must equal the exact path (a second, deliberate confirmation, as extract.go openCopy);
//   - for create=true the directory must not exist yet or be empty (fetch-state never reuses a store);
//   - for create=false it must hold the a2 marker file written by fetch-state (replay only opens our own seed).
func datadirGuard(dir string, create bool) (string, error) {
	if dir == "" || !filepath.IsAbs(dir) {
		return "", fmt.Errorf("refused: --datadir must be an absolute path")
	}
	clean := filepath.Clean(dir)
	if clean != dir {
		return "", fmt.Errorf("refused: --datadir must be a clean path (got %q, clean %q)", dir, clean)
	}
	real := clean
	if r, err := filepath.EvalSymlinks(clean); err == nil {
		real = r
	} else if r, err := filepath.EvalSymlinks(filepath.Dir(clean)); err == nil {
		real = filepath.Join(r, filepath.Base(clean))
	}
	for _, p := range []string{clean, real} {
		for _, c := range strings.Split(p, string(filepath.Separator)) {
			if strings.HasPrefix(strings.ToLower(c), "dero-data") {
				return "", fmt.Errorf("refused: --datadir lies under a node store (%q component)", c)
			}
		}
	}
	if os.Getenv("FORENSICS_A2_DATADIR_OK") != clean {
		return "", fmt.Errorf("refused: FORENSICS_A2_DATADIR_OK must name this exact datadir")
	}
	marker := filepath.Join(clean, markerName)
	if create {
		if ents, err := os.ReadDir(clean); err == nil && len(ents) > 0 {
			return "", fmt.Errorf("refused: fetch-state needs a new or empty datadir")
		}
		return clean, nil
	}
	if _, err := os.Stat(marker); err != nil {
		return "", fmt.Errorf("refused: %s has no %s marker (only a datadir seeded by fetch-state is opened)", clean, markerName)
	}
	return clean, nil
}

const markerName = "A2_FORENSIC_SEED"
