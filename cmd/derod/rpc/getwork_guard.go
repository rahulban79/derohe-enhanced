// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package rpc

// r23 (security): getwork protection for a node whose --getwork-bind is reachable from the network (the upstream
// default is 0.0.0.0:10100). Every submitted share with a current job id costs one full PoW verification, and all
// verifications share ONE slot (verify_slot, r19). Before r23 a remote client could
//   - open up to nbhttp's MaxLoad (10,240) sessions from one address, each receiving every job (fan-out cost) and
//     filling the slots honest remote miners need;
//   - submit well-formed garbage shares without limit: each one a PoW hash, queued in front of the LOCAL miner's
//     shares. A local share that waits behind N bogus ones reaches the network N verifications later: on DERO, where
//     the 9th/10th miniblock slot is an arrival race, that delay turns paid shares into orphans (payout loss).
//
// Now, for non-loopback sessions only (loopback miners are untouched):
//   - at most getwork_max_per_ip sessions per key (IPv4 address / IPv6 /64), env DERO_GETWORK_MAX_PER_IP (default 32);
//   - GETWORK_BAD_SHARE_LIMIT consecutive shares that fail verification for a reason that is the submitter's fault
//     (undecodable blob, invalid PoW) close the session and ban its key from getwork, 60 s doubling to 1 h. An honest
//     miner computes the PoW it submits, so it never builds such a run; stale jobs ("job not found") cost no PoW and
//     are not counted;
//   - remote shares pass a one-slot gate BEFORE the shared verify slot, so at most one remote share is ever queued
//     there: a local share waits for at most one remote verification plus the one running, whatever the flood.
// None of this is consensus-visible; a share's acceptance rules are unchanged.

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/lesismal/nbio/nbhttp/websocket"

	"github.com/deroproject/derohe/errormsg"
	dmetrics "github.com/deroproject/derohe/metrics"
)

const GETWORK_DEFAULT_MAX_PER_IP = 32
const GETWORK_BAD_SHARE_LIMIT = 8
const GETWORK_BAN_BASE = 60 * time.Second
const GETWORK_BAN_MAX = time.Hour

var getwork_max_per_ip = GETWORK_DEFAULT_MAX_PER_IP

var getwork_conn_limit = new_ip_limiter(GETWORK_DEFAULT_MAX_PER_IP)

// getwork_bans reuses the abuse table's escalating bans (its call bucket is unused here).
var getwork_bans = new_abuse_table(1, 1, ABUSE_MAX_ENTRIES)

var (
	getwork_refused_conns  = dmetrics.Set.GetOrCreateCounter(`getwork_guard_refused_total{reason="per_ip"}`)
	getwork_refused_banned = dmetrics.Set.GetOrCreateCounter(`getwork_guard_refused_total{reason="banned"}`)
	getwork_bad_shares     = dmetrics.Set.GetOrCreateCounter("getwork_guard_bad_shares_total")
	getwork_guard_bans     = dmetrics.Set.GetOrCreateCounter("getwork_guard_bans_total")
)

func configure_getwork_guard(getenv func(string) string) {
	if v, err := strconv.Atoi(getenv("DERO_GETWORK_MAX_PER_IP")); err == nil && v > 0 {
		getwork_max_per_ip = v
		getwork_conn_limit = new_ip_limiter(v)
	}
}

// getwork_remote_key returns the limit key of a getwork client and whether it is exempt (loopback).
func getwork_remote_key(remote_addr string) (key string, loopback bool) {
	host, _, err := net.SplitHostPort(remote_addr)
	if err != nil {
		host = remote_addr
	}
	p := net.ParseIP(host)
	if p != nil && p.IsLoopback() {
		return host, true
	}
	return abuse_key(host), false
}

// getwork_admit decides whether a new getwork session from remote_addr may upgrade. On success the caller owns one
// slot of key (release with getwork_conn_limit.release) unless loopback.
func getwork_admit(w http.ResponseWriter, remote_addr string) (key string, loopback bool, ok bool) {
	key, loopback = getwork_remote_key(remote_addr)
	if loopback {
		return key, true, true
	}
	if d := getwork_ban_left(key, time.Now()); d > 0 {
		getwork_refused_banned.Inc()
		w.Header().Set("Retry-After", strconv.FormatInt(int64(d/time.Second)+1, 10))
		http.Error(w, "temporarily banned", http.StatusTooManyRequests)
		return key, false, false
	}
	if !getwork_conn_limit.acquire(key) {
		getwork_refused_conns.Inc()
		http.Error(w, "too many getwork sessions from this address", http.StatusTooManyRequests)
		return key, false, false
	}
	return key, false, true
}

func getwork_ban_left(key string, now time.Time) time.Duration {
	getwork_bans.mu.Lock()
	defer getwork_bans.mu.Unlock()
	if e := getwork_bans.m[key]; e != nil && now.Before(e.banned_until) {
		return e.banned_until.Sub(now)
	}
	return 0
}

// getwork_ban bans key with escalation and returns the ban length.
func getwork_ban(key string, now time.Time) time.Duration {
	getwork_bans.mu.Lock()
	defer getwork_bans.mu.Unlock()
	e := getwork_bans.entry(key, now)
	e.last_seen = now
	if e.strikes > 0 && now.Sub(e.last_ban) > ABUSE_STRIKE_FORGET {
		e.strikes = 0
	}
	e.strikes++
	d := GETWORK_BAN_BASE
	for i := uint(1); i < e.strikes && d < GETWORK_BAN_MAX; i++ {
		d *= 2
	}
	if d > GETWORK_BAN_MAX {
		d = GETWORK_BAN_MAX
	}
	e.banned_until = now.Add(d)
	e.last_ban = now
	getwork_guard_bans.Inc()
	return d
}

// share_is_bad: a verification failure that is the submitter's fault and cost us work (or was garbage).
func share_is_bad(accepted bool, err error) bool {
	if accepted || err == nil {
		return false
	}
	return errors.Is(err, errormsg.ErrInvalidPoW) || err == errormsg.ErrInvalidPoW || err == err_share_undecodable
}

var err_share_undecodable = errors.New("share could not be decoded")

// share_guard is the per-session run of bad shares.
type share_guard struct {
	mu      sync.Mutex
	bad_run int
	closed  bool
}

// note returns true when the session must be closed and its key banned (once).
func (g *share_guard) note(bad bool) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	if !bad {
		g.bad_run = 0
		return false
	}
	getwork_bad_shares.Inc()
	g.bad_run++
	if g.bad_run >= GETWORK_BAD_SHARE_LIMIT {
		g.closed = true
		return true
	}
	return false
}

func (g *share_guard) is_closed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closed
}

// remote_verify_gate: at most one remote share waits on verify_slot (see the file comment).
var remote_verify_gate = make(chan struct{}, 1)

// verify_share_from runs f in the verify slot; remote shares first pass remote_verify_gate.
func verify_share_from(loopback bool, f func()) {
	if !loopback {
		remote_verify_gate <- struct{}{}
		defer func() { <-remote_verify_gate }()
	}
	verify_share(f)
}

// release_slot frees the session's per-IP slot (once; loopback sessions hold none).
func (s *user_session) release_slot() {
	s.slot_once.Do(func() {
		if !s.loopback {
			getwork_conn_limit.release(s.limit_key)
		}
	})
}

// getwork_note_share applies the bad-share rule to one verified (or undecodable) share of a remote session.
func getwork_note_share(c *websocket.Conn, sess *user_session, accepted bool, err error) {
	if sess.loopback {
		return
	}
	if sess.guard.note(share_is_bad(accepted, err)) {
		d := getwork_ban(sess.limit_key, time.Now())
		log_presence("banned", "remote", sess.remote, "reason", "consecutive bad shares", "ban", d.String())
		if c != nil {
			c.Close()
		}
		// r23 merge: the ban covers the key, so its other open sessions (up to getwork_max_per_ip - 1) are closed too;
		// before, each of them could still submit its own GETWORK_BAD_SHARE_LIMIT bad shares
		for _, o := range sessions_of_key(sess.limit_key, c) {
			o.Close()
		}
	}
}

// getwork_session_refused: a share from this session must not be verified, because the session was closed for bad
// shares or its key is banned (another session of the same key earned the ban) (r23 merge).
func getwork_session_refused(sess *user_session, now time.Time) bool {
	if sess.guard.is_closed() {
		return true
	}
	return !sess.loopback && getwork_ban_left(sess.limit_key, now) > 0
}

// sessions_of_key lists the registered remote connections of key other than except.
func sessions_of_key(key string, except *websocket.Conn) (out []*websocket.Conn) {
	client_list_mutex.Lock()
	defer client_list_mutex.Unlock()
	for c, s := range client_list {
		if c != except && s != nil && !s.loopback && s.limit_key == key {
			out = append(out, c)
		}
	}
	return out
}
