// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

// Command nodehealth is a one-shot derod health check that needs no miner (r24 getworkops, B35 ops).
//
//	go run ./tools/nodehealth                       # 127.0.0.1:10102; one line; exit 0 healthy, 1 unhealthy, 2 no answer
//	go run ./tools/nodehealth --json --rpc=127.0.0.1:10102 --max-tip-age=180 --min-peers=1
//
// It reads DERO.GetSyncInfo (r21+): the node's own sync verdict (synced/syncing/stalled/isolated), the TIP BLOCK's age,
// lag against the peers' median, peer counts, recovered panics and which side of the HF3 split it follows. A node
// without GetSyncInfo is read through DERO.GetInfo plus DERO.GetLastBlockHeader, and the tip age is computed from the
// tip block's own timestamp, never from GetInfo's averageblocktime50 or target_height: those said "OK" while a node
// was 40 days behind (memory dero-getinfo-cannot-show-lag).
//
// Every request carries Content-Type: application/json: derod answers a JSON-RPC POST without it with HTTP 415 and an
// EMPTY body (2026-11-02, backlog B38; r24 verify: curl without the header gets 415, 0 bytes), which this tool reports
// as such instead of as a JSON error.
//
// Unhealthy (exit 1) when: status is not "synced", the tip is older than --max-tip-age, fewer than --min-peers peers,
// or the chain fingerprint is not the v3 (upgraded) chain. Read-only: it never changes the node.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type sync_info struct {
	Status          string  `json:"status"`
	Reason          string  `json:"reason"`
	Height          int64   `json:"height"`
	TopoHeight      int64   `json:"topoheight"`
	TipAgeSeconds   float64 `json:"tip_age_seconds"`
	LagBlocks       int64   `json:"lag_blocks"`
	PeersIncoming   uint64  `json:"peers_incoming"`
	PeersOutgoing   uint64  `json:"peers_outgoing"`
	RecoveredPanics uint64  `json:"recovered_panics_total"`
	RPCRecovered    uint64  `json:"rpc_recovered_panics_total"`
	UptimeSeconds   int64   `json:"uptime_seconds"`
	Version         string  `json:"version"`
	Fingerprint     string  `json:"chain_fingerprint"`
	StaleWork       bool    `json:"mining_work_would_be_stale"`
}

type get_info struct {
	Height   int64  `json:"height"`
	Topo     int64  `json:"topoheight"`
	In       uint64 `json:"incoming_connections_count"`
	Out      uint64 `json:"outgoing_connections_count"`
	Uptime   int64  `json:"uptime"`
	Version  string `json:"version"`
	Testnet  bool   `json:"testnet"`
	TopBlock string `json:"top_block_hash"`
}

type last_header struct {
	BlockHeader struct {
		Height    int64  `json:"height"`
		Timestamp uint64 `json:"timestamp"` // ms
	} `json:"block_header"`
}

// Report is what the tool prints (--json) and judges.
type Report struct {
	Healthy  bool      `json:"healthy"`
	Problems []string  `json:"problems"`
	Source   string    `json:"source"` // GetSyncInfo | GetInfo+GetLastBlockHeader
	Info     sync_info `json:"node"`
	RPC      string    `json:"rpc"`
	Checked  string    `json:"checked_at"`
}

type rpc_error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ErrEmpty: derod answered with no body (the B38 symptom when Content-Type is missing is HTTP 415 with 0 bytes; r24 verify).
var ErrEmpty = fmt.Errorf("empty reply (derod answers a JSON-RPC POST without Content-Type: application/json with HTTP 415 and no body, B38)")

type caller struct {
	url    string
	client *http.Client
}

func (c caller) call(method string, out interface{}) (rerr *rpc_error, err error) {
	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": method})
	req, err := http.NewRequest("POST", c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, ErrEmpty
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *rpc_error      `json:"error"`
	}
	if err = json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("%s: not JSON-RPC (%v)", method, err)
	}
	if env.Error != nil {
		return env.Error, nil
	}
	if len(env.Result) == 0 {
		return nil, fmt.Errorf("%s: no result", method)
	}
	return nil, json.Unmarshal(env.Result, out)
}

// read gets the node's state: GetSyncInfo, or the GetInfo + tip-header fallback when the method does not exist.
func read(c caller, now time.Time) (si sync_info, source string, err error) {
	rerr, err := c.call("DERO.GetSyncInfo", &si)
	if err != nil {
		return si, "", err
	}
	if rerr == nil {
		return si, "GetSyncInfo", nil
	}
	if rerr.Code != -32601 { // anything but "no such method" is a real failure
		return si, "", fmt.Errorf("DERO.GetSyncInfo: %d %s", rerr.Code, rerr.Message)
	}
	var gi get_info
	var lh last_header
	if rerr, err = c.call("DERO.GetInfo", &gi); err != nil || rerr != nil {
		return si, "", fmt.Errorf("DERO.GetInfo: %v %v", err, rerr)
	}
	if rerr, err = c.call("DERO.GetLastBlockHeader", &lh); err != nil || rerr != nil {
		return si, "", fmt.Errorf("DERO.GetLastBlockHeader: %v %v", err, rerr)
	}
	si = sync_info{Status: "unknown", Reason: "node has no DERO.GetSyncInfo; lag against peers not available",
		Height: gi.Height, TopoHeight: gi.Topo, PeersIncoming: gi.In, PeersOutgoing: gi.Out, UptimeSeconds: gi.Uptime,
		Version: gi.Version}
	si.TipAgeSeconds = float64(now.UnixMilli()-int64(lh.BlockHeader.Timestamp)) / 1000
	return si, "GetInfo+GetLastBlockHeader", nil
}

type limits struct {
	MaxTipAge float64
	MinPeers  uint64
}

// judge lists what is wrong. A fallback read (status "unknown") is judged on tip age and peers only.
func judge(si sync_info, source string, l limits) (problems []string) {
	if source == "GetSyncInfo" && si.Status != "synced" {
		problems = append(problems, fmt.Sprintf("status %s: %s", si.Status, si.Reason))
	}
	if si.TipAgeSeconds > l.MaxTipAge {
		problems = append(problems, fmt.Sprintf("tip block is %.0f s old (limit %.0f s)", si.TipAgeSeconds, l.MaxTipAge))
	}
	if peers := si.PeersIncoming + si.PeersOutgoing; peers < l.MinPeers {
		problems = append(problems, fmt.Sprintf("%d peers (limit %d)", peers, l.MinPeers))
	}
	if si.Fingerprint != "" && !strings.HasPrefix(si.Fingerprint, "v3") {
		problems = append(problems, "chain fingerprint "+si.Fingerprint+" (not the v3 upgraded chain)")
	}
	return
}

func line(r Report) string {
	s := r.Info
	head := "OK"
	if !r.Healthy {
		head = "UNHEALTHY"
	}
	out := fmt.Sprintf("%s status=%s height=%d topo=%d tip_age=%.1fs lag=%d peers_out=%d peers_in=%d panics=%d/%d uptime=%ds version=%s source=%s",
		head, s.Status, s.Height, s.TopoHeight, s.TipAgeSeconds, s.LagBlocks, s.PeersOutgoing, s.PeersIncoming,
		s.RecoveredPanics, s.RPCRecovered, s.UptimeSeconds, s.Version, r.Source)
	if len(r.Problems) > 0 {
		out += " problems=" + fmt.Sprintf("%q", strings.Join(r.Problems, "; "))
	}
	return out
}

func run(args []string, out, errw io.Writer, now func() time.Time) int {
	fs := flag.NewFlagSet("nodehealth", flag.ContinueOnError)
	fs.SetOutput(errw)
	addr := fs.String("rpc", "127.0.0.1:10102", "derod --rpc-bind address (host:port) or a full http URL")
	var l limits
	fs.Float64Var(&l.MaxTipAge, "max-tip-age", 180, "seconds; 10 block times (a 300 s gap has probability ~e^-16.7)")
	fs.Uint64Var(&l.MinPeers, "min-peers", 1, "minimum handshaken peers (in + out)")
	timeout := fs.Duration("timeout", 5*time.Second, "per-request timeout")
	as_json := fs.Bool("json", false, "print the full report as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	url := *addr
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url + "/json_rpc"
	}
	t := now()
	si, source, err := read(caller{url: url, client: &http.Client{Timeout: *timeout}}, t)
	if err != nil {
		fmt.Fprintln(out, "DOWN", err)
		return 2
	}
	r := Report{Source: source, Info: si, RPC: *addr, Checked: t.UTC().Format(time.RFC3339)}
	r.Problems = append([]string{}, judge(si, source, l)...) // [] not null in --json
	r.Healthy = len(r.Problems) == 0
	if *as_json {
		e := json.NewEncoder(out)
		e.SetIndent("", " ")
		e.Encode(r)
	} else {
		fmt.Fprintln(out, line(r))
	}
	if !r.Healthy {
		return 1
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now)) }
