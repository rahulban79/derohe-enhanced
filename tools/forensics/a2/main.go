package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtaci/kcp-go/v5"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/globals"
)

func globalsDataDir() string { return globals.GetDataDirectory() }

// openChain sets the node globals for an offline, mainnet, own-datadir chain and starts the blockchain package.
// Nothing here listens or dials: p2p, RPC and getwork are never started by this tool.
func openChain(datadir, logPath string) (*blockchain.Blockchain, error) {
	os.Unsetenv("METRICS_SERVER") // metrics.Dump_metrics_data_directly would otherwise post to it
	globals.Arguments = map[string]interface{}{"--data-dir": datadir, "--testnet": false, "--simulator": false,
		"--debug": false, "--fastsync": false}
	globals.InitNetwork()
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	globals.InitializeLog(lf, io.Discard)
	globals.Initialize()
	if !strings.HasPrefix(globals.GetDataDirectory(), datadir+string(filepath.Separator)) {
		return nil, fmt.Errorf("data directory resolved outside --datadir")
	}
	return blockchain.Blockchain_Start(map[string]interface{}{})
}

func writeJSON(path string, v interface{}) {
	b, _ := json.MarshalIndent(v, "", " ")
	if path == "" || path == "-" {
		os.Stdout.Write(append(b, '\n'))
		return
	}
	os.WriteFile(path, append(b, '\n'), 0644)
}

func die(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "a2: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		die("usage: a2 fetch-state|replay|roots [flags] (see guard.go)")
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; atomic.StoreInt32(&stopRequested, 1) }()

	switch os.Args[1] {
	case "fetch-state":
		fs := flag.NewFlagSet("fetch-state", flag.ExitOnError)
		peerFile := fs.String("peer-file", "", "PRIVATE peer file {name: {p2p: host:port}}")
		peer := fs.String("peer", "", "pseudonym of the ONE source")
		datadir := fs.String("datadir", "", "new datadir (absolute, outside every node store)")
		topo := fs.Int64("topo", 0, "last topo of the changeset (the state before the window)")
		depth := fs.Int64("depth", 50, "changeset depth (11..50)")
		expect := fs.String("expect-blid", "", "our RAW block id at --topo")
		rate := fs.Float64("rate", 2, "requests per second (<= 4)")
		out := fs.String("out", "-", "summary JSON")
		fs.Parse(os.Args[2:])
		dir, err := datadirGuard(*datadir, true)
		if err != nil {
			die("%v", err)
		}
		if len(*expect) != 64 || *topo < 100 {
			die("--topo and --expect-blid are required")
		}
		addr, err := loadPeer(*peerFile, *peer)
		if err != nil {
			die("%v", err)
		}
		os.MkdirAll(dir, 0700)
		sum := seedSummary{Kind: "a2_fetch_state", Source: *peer, Started: time.Now().UTC().Format(time.RFC3339),
			Class: "EXT: the source's state at the tree topo plus its per-block changes, until the replay's end-state check binds it",
			Method: []string{"Peer.ChangeSet (p2p/rpc_changeset.go:29)", "Peer.TreeSection (p2p/rpc_treesection.go:22-66)",
				"written as p2p/chain_bootstrap.go:53-339 writes a fastsync bootstrap"}}
		t0 := time.Now()
		chain, err := openChain(dir, filepath.Join(dir, "a2.log"))
		if err != nil {
			die("open chain: %v", err)
		}
		pc, err := dialPeer(*peer, addr, *rate)
		if err == nil {
			err = fetchState(pc, chain, *topo, *depth, *expect, &sum)
			sum.Requests, sum.Failures = pc.requests, pc.failures
			pc.close()
		}
		if err != nil {
			sum.Error = err.Error()
		}
		sum.Finished, sum.Seconds = time.Now().UTC().Format(time.RFC3339), time.Since(t0).Seconds()
		writeJSON(*out, sum)
		chain.Shutdown()
		if err != nil {
			os.Exit(2)
		}
	case "probe": // dial + TLS + Peer.Handshake only; writes nothing
		fs := flag.NewFlagSet("probe", flag.ExitOnError)
		peerFile := fs.String("peer-file", "", "PRIVATE peer file")
		peer := fs.String("peer", "", "pseudonym of the ONE source")
		hold := fs.Duration("hold", 0, "keep the session open this long before closing (dedup control)")
		fs.Parse(os.Args[2:])
		addr, err := loadPeer(*peerFile, *peer)
		if err != nil {
			die("%v", err)
		}
		globals.Arguments = map[string]interface{}{"--testnet": false}
		globals.InitNetwork()
		t0 := time.Now()
		pc, err := dialPeer(*peer, addr, 1)
		snmp := kcp.DefaultSnmp.Copy()
		res := map[string]interface{}{"kind": "a2_probe", "source": *peer, "seconds": time.Since(t0).Seconds(),
			"kcp_out_pkts": snmp.OutPkts, "kcp_in_pkts": snmp.InPkts, "kcp_in_errs": snmp.InErrs,
			"kcp_in_csum_errs": snmp.InCsumErrors}
		if err != nil {
			res["error"] = err.Error()
		} else {
			res["handshake"] = "ok"
			res["peer_topoheight_ext"], res["peer_pruned_ext"], res["peer_version_ext"] = pc.peerTopo, pc.peerPruned, pc.peerVersion
			time.Sleep(*hold)
			pc.close()
		}
		writeJSON("-", res)
	case "seed-archive":
		fs := flag.NewFlagSet("seed-archive", flag.ExitOnError)
		archive := fs.String("archive", "", "a COPY of the replaywall archive (replaywall_balances, replaywall_bltx_store)")
		slice := fs.String("topo-slice", "", "the archive's topo.map slice file")
		first := fs.Int64("slice-first", 0, "topo of the slice's first record")
		top := fs.Int64("top", 0, "last committed topo to keep")
		expect := fs.String("expect-blid", "", "our RAW block id at --top")
		datadir := fs.String("datadir", "", "new datadir (absolute, outside every node store)")
		out := fs.String("out", "-", "summary JSON")
		fs.Parse(os.Args[2:])
		dir, err := datadirGuard(*datadir, true)
		if err != nil {
			die("%v", err)
		}
		os.MkdirAll(dir, 0700)
		sum := archiveSummary{Kind: "a2_seed_archive", Archive: "archive:replaywall-20260819 (copy, APFS-cloned)",
			Class: "DERIVED by our own node's 2026-08 replay from its fastsync base at the slice's first topo; not end-state-checked until replay"}
		err = seedArchive(*archive, *slice, *first, *top, *expect, dir, &sum)
		if err == nil {
			var chain *blockchain.Blockchain
			if chain, err = openChain(dir, filepath.Join(dir, "a2.log")); err == nil {
				sum.ChainTop = chain.Load_TOPO_HEIGHT()
				if _, _, root, e := rootAt(chain, *top); e == nil {
					sum.TopRoot = fmt.Sprintf("%x", root[:])
				} else {
					err = e
				}
				chain.Shutdown()
			}
		}
		if err != nil {
			sum.Error = err.Error()
		}
		writeJSON(*out, sum)
		if err != nil {
			os.Exit(2)
		}
	case "replay":
		fs := flag.NewFlagSet("replay", flag.ExitOnError)
		datadir := fs.String("datadir", "", "datadir seeded by fetch-state")
		plan := fs.String("plan", "", "plan JSONL (topo, blid, sha256, txs)")
		blocks := fs.String("blocks", "", "colon-separated content-addressed block blob dirs")
		txs := fs.String("txs", "", "colon-separated content-addressed tx blob dirs")
		to := fs.Int64("to", 0, "last topo to replay")
		roots := fs.String("roots", "", "roots JSONL (appended; resumable)")
		expect := fs.String("expect-root", "", "our own treehash at --to (end-state check)")
		out := fs.String("out", "-", "summary JSON")
		fs.Parse(os.Args[2:])
		dir, err := datadirGuard(*datadir, false)
		if err != nil {
			die("%v", err)
		}
		rows, err := readPlan(*plan)
		if err != nil {
			die("plan: %v", err)
		}
		chain, err := openChain(dir, filepath.Join(dir, "a2.log"))
		if err != nil {
			die("open chain: %v", err)
		}
		sum := replaySummary{Kind: "a2_replay", Started: time.Now().UTC().Format(time.RFC3339)}
		t0 := time.Now()
		err = replay(chain, rows, *to, strings.Split(*blocks, ":"), strings.Split(*txs, ":"), *roots, *expect, &sum)
		if err != nil {
			sum.Stopped, sum.FailError = "error", err.Error()
		}
		sum.Finished, sum.Seconds = time.Now().UTC().Format(time.RFC3339), time.Since(t0).Seconds()
		writeJSON(*out, sum)
		chain.Shutdown()
		if sum.Stopped != "completed" && !strings.HasPrefix(sum.Stopped, "signal") {
			os.Exit(2)
		}
	case "roots":
		fs := flag.NewFlagSet("roots", flag.ExitOnError)
		datadir := fs.String("datadir", "", "datadir seeded by fetch-state")
		from := fs.Int64("from", 0, "first topo")
		to := fs.Int64("to", 0, "last topo")
		fs.Parse(os.Args[2:])
		dir, err := datadirGuard(*datadir, false)
		if err != nil {
			die("%v", err)
		}
		chain, err := openChain(dir, filepath.Join(dir, "a2.log"))
		if err != nil {
			die("open chain: %v", err)
		}
		enc := json.NewEncoder(os.Stdout)
		for t := *from; t <= *to; t++ {
			id, v, root, err := rootAt(chain, t)
			if err != nil {
				enc.Encode(map[string]interface{}{"topo": t, "error": err.Error()})
				continue
			}
			enc.Encode(rootLine{Topo: t, BLID: fmt.Sprintf("%x", id[:]), StateVersion: v, Root: fmt.Sprintf("%x", root[:])})
		}
		chain.Shutdown()
	default:
		die("unknown subcommand %q", os.Args[1])
	}
}
