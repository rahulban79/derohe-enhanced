// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

// Command getworkprobe is a fake getwork client for derod (r24 getworkops): it connects like a miner, records every
// job derod pushes (receive time, height, normal/final), and NEVER submits a share. With the miner paused it is the
// way to exercise derod's job dispatcher end to end (getwork_* metrics move only while a session is connected).
//
//	go run ./tools/getworkprobe --daemon=127.0.0.1:10100 --address=<registered dero1...> --duration=30m --out=jobs.jsonl
//
// It prints a summary: jobs, heights, finals, and per height the client-side flip: the time from the last NORMAL job
// to the first FINAL job of that height. That is NOT the node's dead-normal window and bounds it in neither direction
// (r24 verify): with no dead window the last normal job was live work (seconds before the flip); with several dead jobs
// it starts at the LAST one while the node books from the FIRST (r24_verify_test.go). The node's own numbers are
// getwork_final_flip_delay_seconds / getwork_final_flip_l9_seconds.
package main

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/rpc"
	"github.com/gorilla/websocket"
)

// Job is one received job.
type Job struct {
	RecvMs int64  `json:"recv_ms"`
	Height uint64 `json:"height"`
	Final  bool   `json:"final"`
	JobID  string `json:"jobid"`
}

// parse decodes one getwork text frame into a Job.
func parse(msg []byte, recv_ms int64) (j Job, err error) {
	var p rpc.GetBlockTemplate_Result
	if err = json.Unmarshal(msg, &p); err != nil {
		return
	}
	b, err := hex.DecodeString(p.Blockhashing_blob)
	if err != nil {
		return
	}
	var m block.MiniBlock
	if err = m.Deserialize(b); err != nil {
		return
	}
	return Job{RecvMs: recv_ms, Height: m.Height, Final: m.Final, JobID: p.JobID}, nil
}

// Summary is the client-side view of one run.
type Summary struct {
	Jobs, Finals, Heights int
	Flips                 []int64 // per height with both kinds: first final - last normal before it (ms)
}

func summarize(jobs []Job) (s Summary) {
	type hs struct {
		last_normal, first_final int64
	}
	per := map[uint64]*hs{}
	for _, j := range jobs {
		s.Jobs++
		h := per[j.Height]
		if h == nil {
			h = &hs{}
			per[j.Height] = h
		}
		if j.Final {
			s.Finals++
			if h.first_final == 0 {
				h.first_final = j.RecvMs
			}
		} else if h.first_final == 0 {
			h.last_normal = j.RecvMs
		}
	}
	s.Heights = len(per)
	for _, h := range per {
		if h.last_normal != 0 && h.first_final != 0 {
			s.Flips = append(s.Flips, h.first_final-h.last_normal)
		}
	}
	sort.Slice(s.Flips, func(a, b int) bool { return s.Flips[a] < s.Flips[b] })
	return
}

func (s Summary) String() string {
	out := fmt.Sprintf("jobs %d finals %d heights %d flips %d", s.Jobs, s.Finals, s.Heights, len(s.Flips))
	if n := len(s.Flips); n > 0 {
		var sum int64
		for _, x := range s.Flips {
			sum += x
		}
		out += fmt.Sprintf(" | last-normal->first-final ms: mean %.1f p50 %d p90 %d max %d", float64(sum)/float64(n),
			s.Flips[n/2], s.Flips[n*9/10], s.Flips[n-1])
	}
	return out
}

func main() {
	daemon := flag.String("daemon", "127.0.0.1:10100", "derod --getwork-bind address")
	address := flag.String("address", "", "a REGISTERED dero1 address (unregistered ones get no normal jobs)")
	duration := flag.Duration("duration", 10*time.Minute, "how long to listen")
	outp := flag.String("out", "", "write every job as a JSON line here")
	flag.Parse()
	if *address == "" {
		fmt.Fprintln(os.Stderr, "getworkprobe: --address is required")
		os.Exit(2)
	}
	d := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, HandshakeTimeout: 5 * time.Second}
	c, _, err := d.Dial("wss://"+*daemon+"/ws/"+*address, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "getworkprobe: dial:", err)
		os.Exit(2)
	}
	defer c.Close()
	var w io.Writer = io.Discard
	if *outp != "" {
		f, err := os.Create(*outp)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		defer f.Close()
		w = f
	}
	enc := json.NewEncoder(w)
	var jobs []Job
	end := time.Now().Add(*duration)
	for time.Now().Before(end) {
		c.SetReadDeadline(end)
		_, msg, err := c.ReadMessage()
		if err != nil {
			if time.Now().Before(end) {
				fmt.Fprintln(os.Stderr, "getworkprobe: read:", err)
			}
			break
		}
		j, err := parse(msg, time.Now().UnixMilli())
		if err != nil {
			fmt.Fprintln(os.Stderr, "getworkprobe: bad job:", err)
			continue
		}
		jobs = append(jobs, j)
		enc.Encode(j)
	}
	fmt.Println(summarize(jobs))
}
